package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// EmergencyMessage represents an authenticated application datagram exchanged over DNS.
type EmergencyMessage struct {
	ID        string `json:"id"`
	Type      string `json:"type"`      // e.g. "ping", "bootstrap", "alert", "data"
	Payload   []byte `json:"payload"`   // Application payload bytes
	Timestamp int64  `json:"timestamp"` // Unix timestamp
}

// EmergencyResponse represents an authenticated server response returned inside a DNS TXT record.
type EmergencyResponse struct {
	ID        string `json:"id"`        // Echoes Request ID
	Status    string `json:"status"`    // e.g. "OK", "ERROR"
	Reply     []byte `json:"reply"`     // Dynamic response payload
	Timestamp int64  `json:"timestamp"` // Server Unix timestamp
}

// EmergencyDNSServerConfig configures the authoritative DNS emergency service.
type EmergencyDNSServerConfig struct {
	ListenAddr   string
	DomainSuffix string
	PSK          []byte
	Handler      func(msg *EmergencyMessage) (*EmergencyResponse, error)
}

// EmergencyDNSServer hosts the authoritative DNS endpoint, receiving recursive DNS queries,
// reassembling multipart frames, decrypting authenticated requests, and returning dynamic responses in TXT records.
type EmergencyDNSServer struct {
	cfg         EmergencyDNSServerConfig
	conn        *net.UDPConn
	reassembler *DNSReassembler
	sessions    map[uint64]*AsymmetricConn
	mu          sync.Mutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewEmergencyDNSServer creates a new authoritative emergency DNS daemon.
func NewEmergencyDNSServer(cfg EmergencyDNSServerConfig) (*EmergencyDNSServer, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("emergency dns: domain suffix required")
	}
	if len(cfg.PSK) == 0 {
		return nil, errors.New("emergency dns: PSK required")
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", cfg.ListenAddr, err)
	}

	srv := &EmergencyDNSServer{
		cfg:         cfg,
		conn:        conn,
		reassembler: NewDNSReassembler(30 * time.Second),
		sessions:    make(map[uint64]*AsymmetricConn),
		stopChan:    make(chan struct{}),
	}

	srv.wg.Add(1)
	go srv.serveLoop()
	return srv, nil
}

// Addr returns the local listening address.
func (s *EmergencyDNSServer) Addr() net.Addr {
	return s.conn.LocalAddr()
}

// Stop shuts down the authoritative DNS server.
func (s *EmergencyDNSServer) Stop() error {
	close(s.stopChan)
	err := s.conn.Close()
	s.wg.Wait()
	return err
}

func (s *EmergencyDNSServer) getOrCreateSession(sessionID uint64) (*AsymmetricConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[sessionID]; ok {
		return sess, nil
	}

	sess, err := NewServerAsymmetricSession(sessionID, s.cfg.PSK)
	if err != nil {
		return nil, err
	}
	s.sessions[sessionID] = sess
	return sess, nil
}

func (s *EmergencyDNSServer) serveLoop() {
	defer s.wg.Done()
	buf := make([]byte, 4096)

	normalizedSuffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.cfg.DomainSuffix), "."))

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, remoteAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		reqPacket := append([]byte(nil), buf[:n]...)
		go s.handlePacket(reqPacket, remoteAddr, normalizedSuffix)
	}
}

func (s *EmergencyDNSServer) handlePacket(reqPacket []byte, remoteAddr net.Addr, normalizedSuffix string) {
	if len(reqPacket) < 12 {
		return
	}

	id, qname, qtype, err := ParseDNSQuery(reqPacket)
	if err != nil {
		resp := BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}
	_ = id

	qnameLower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))

	// Security requirement: Restrict exclusively to the delegated domain suffix!
	// Reject all other domains with REFUSED (RCODE 5) so the server never operates as an open resolver.
	if !strings.HasSuffix(qnameLower, "."+normalizedSuffix) && qnameLower != normalizedSuffix {
		resp := BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	// Handle TXT Queries (Emergency channel)
	if qtype != 0x0010 /* TXT */ {
		// Non-TXT query (e.g. A, AAAA, SOA) on child zone: return NOERROR with zero answers
		resp, _ := BuildDNSTXTResponse(reqPacket, nil)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	clientID, offset, part, total, chunk, err := DecodeDNSQName(qnameLower, normalizedSuffix)
	if err != nil {
		// Non-encoded query under child zone (e.g. diagnostic ping)
		resp, _ := BuildDNSTXTResponse(reqPacket, []byte("PAQET_EMERGENCY_DNS_ZONE_ACTIVE"))
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	fullFrame, isComplete := s.reassembler.PushFragment(clientID, offset, part, total, chunk)
	if !isComplete {
		// Multipart query in progress: return intermediate empty TXT response so recursive resolver does not stall
		resp, _ := BuildDNSTXTResponse(reqPacket, nil)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	// Reassembly complete: process authenticated frame
	if len(fullFrame) < AsymmetricHeaderLen {
		resp := BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	sessionID := binary.BigEndian.Uint64(fullFrame[4:12])
	sess, err := s.getOrCreateSession(sessionID)
	if err != nil {
		resp := BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	seq, _, plaintext, err := sess.openFrame(fullFrame)
	if err != nil {
		// AEAD authentication failed or replay detected! Drop silently or refuse
		resp := BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	var reqMsg EmergencyMessage
	if err := json.Unmarshal(plaintext, &reqMsg); err != nil {
		resp := BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	// Invoke application handler to dynamically generate response
	var respMsg *EmergencyResponse
	if s.cfg.Handler != nil {
		respMsg, err = s.cfg.Handler(&reqMsg)
		if err != nil {
			respMsg = &EmergencyResponse{
				ID:        reqMsg.ID,
				Status:    "ERROR",
				Reply:     []byte(err.Error()),
				Timestamp: time.Now().Unix(),
			}
		}
	} else {
		respMsg = &EmergencyResponse{
			ID:        reqMsg.ID,
			Status:    "OK",
			Reply:     append([]byte("ACK_"), reqMsg.Payload...),
			Timestamp: time.Now().Unix(),
		}
	}

	respPlaintext, _ := json.Marshal(respMsg)
	respSeq := sess.NextSendSeq()

	respFrame, err := sess.sealFrame(respSeq, seq, respPlaintext)
	if err != nil {
		resp := BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
		if resp != nil {
			_, _ = s.conn.WriteTo(resp, remoteAddr)
		}
		return
	}

	// Embed authenticated response frame inside DNS TXT answer record
	dnsRespPacket, err := BuildDNSTXTResponse(reqPacket, respFrame)
	if err == nil && dnsRespPacket != nil {
		_, _ = s.conn.WriteTo(dnsRespPacket, remoteAddr)
	}
}

// EmergencyDNSClientConfig configures the emergency DNS client.
type EmergencyDNSClientConfig struct {
	ResolverAddr string // e.g. "8.8.8.8:53"
	DomainSuffix string // e.g. "tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir"
	ClientID     string
	PSK          []byte
	SessionID    uint64
	Timeout      time.Duration
	MaxRetries   int
}

// EmergencyDNSClient sends authenticated application messages over public recursive DNS and verifies responses.
type EmergencyDNSClient struct {
	cfg     EmergencyDNSClientConfig
	session *AsymmetricConn
}

// NewEmergencyDNSClient initializes an emergency client for a given session.
func NewEmergencyDNSClient(cfg EmergencyDNSClientConfig) (*EmergencyDNSClient, error) {
	if cfg.ResolverAddr == "" {
		cfg.ResolverAddr = "8.8.8.8:53"
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("emergency client: domain suffix required")
	}
	if len(cfg.PSK) == 0 {
		return nil, errors.New("emergency client: PSK required")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "c01"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 4000 * time.Millisecond
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 2
	}
	if cfg.SessionID == 0 {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFFFFFFFFFF))
		cfg.SessionID = uint64(nBig.Int64())
	}

	sess, err := NewClientAsymmetricSession(cfg.SessionID, cfg.PSK)
	if err != nil {
		return nil, err
	}

	return &EmergencyDNSClient{
		cfg:     cfg,
		session: sess,
	}, nil
}

// Exchange transmits an EmergencyMessage through the recursive DNS resolver and waits for an authenticated response.
func (c *EmergencyDNSClient) Exchange(ctx context.Context, msg *EmergencyMessage) (*EmergencyResponse, time.Duration, error) {
	if msg == nil {
		return nil, 0, errors.New("emergency client: nil message")
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}

	reqBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal message: %w", err)
	}

	seq := c.session.NextSendSeq()
	frame, err := c.session.sealFrame(seq, 0, reqBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("seal frame: %w", err)
	}

	// Chunk frame into 35-byte labels for RFC 1035 label length limits
	const chunkSize = 35
	totalParts := uint8((len(frame) + chunkSize - 1) / chunkSize)
	if totalParts == 0 {
		totalParts = 1
	}

	// Generate a unique 24-bit random offset so every transmission query name is globally unique,
	// bypassing any caching in intermediate recursive resolvers.
	nBig, _ := rand.Int(rand.Reader, big.NewInt(0xFFFFFF))
	curOffset := uint32(nBig.Int64() + 1)

	resolverUDP, err := net.ResolveUDPAddr("udp", c.cfg.ResolverAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve resolver addr %s: %w", c.cfg.ResolverAddr, err)
	}

	startOverall := time.Now()

	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}

		resp, err := c.attemptExchange(ctx, resolverUDP, curOffset, totalParts, frame, chunkSize, msg.ID)
		if err == nil && resp != nil {
			return resp, time.Since(startOverall), nil
		}

		time.Sleep(300 * time.Millisecond)
	}

	return nil, time.Since(startOverall), fmt.Errorf("emergency exchange timed out after %d retries", c.cfg.MaxRetries)
}

func (c *EmergencyDNSClient) attemptExchange(
	ctx context.Context,
	resolverUDP *net.UDPAddr,
	curOffset uint32,
	totalParts uint8,
	frame []byte,
	chunkSize int,
	expectedMsgID string,
) (*EmergencyResponse, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.cfg.Timeout))

	type pendingQuery struct {
		txID  uint16
		qname string
	}
	var queries []pendingQuery

	// Dispatch each fragment query
	for i := uint8(0); i < totalParts; i++ {
		start := int(i) * chunkSize
		end := start + chunkSize
		if end > len(frame) {
			end = len(frame)
		}
		chunk := frame[start:end]

		qname := EncodeDNSQName(c.cfg.DomainSuffix, c.cfg.ClientID, curOffset, i, totalParts, chunk)

		nBig, _ := rand.Int(rand.Reader, big.NewInt(65535))
		txID := uint16(nBig.Int64())

		queryPkt := BuildDNSQuery(qname, 0x0010 /* TXT */, txID)
		if _, err := conn.WriteToUDP(queryPkt, resolverUDP); err != nil {
			return nil, err
		}

		queries = append(queries, pendingQuery{txID: txID, qname: qname})
	}

	// Read responses until matching authenticated payload is recovered
	buf := make([]byte, 4096)
	deadline := time.Now().Add(c.cfg.Timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		respPkt := buf[:n]
		if len(respPkt) < 12 {
			continue
		}

		respTxID := binary.BigEndian.Uint16(respPkt[0:2])
		isMatched := false
		for _, q := range queries {
			if q.txID == respTxID {
				isMatched = true
				break
			}
		}
		if !isMatched {
			continue
		}

		txtAnswer, err := ParseDNSTXTResponse(respPkt)
		if err != nil || len(txtAnswer) < AsymmetricHeaderLen {
			continue
		}

		// Decrypt and authenticate downstream frame
		_, _, respPlaintext, err := c.session.openFrame(txtAnswer)
		if err != nil {
			continue // Unauthenticated or corrupted response
		}

		var resp EmergencyResponse
		if err := json.Unmarshal(respPlaintext, &resp); err != nil {
			continue
		}

		if resp.ID == expectedMsgID {
			return &resp, nil
		}
	}

	return nil, errors.New("timeout waiting for valid response")
}
