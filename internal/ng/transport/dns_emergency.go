package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxActiveServerSessions caps live sessions to prevent heap exhaustion.
	MaxActiveServerSessions = 1024

	// ServerSessionIdleTimeout is the duration of silence before an inactive session is purged.
	ServerSessionIdleTimeout = 10 * time.Minute

	// MaxCachedRepliesPerSession bounds memory for idempotent reply recovery.
	MaxCachedRepliesPerSession = 32

	// MaxReplyCacheBytesPerSession bounds total bytes stored in replyCache per session (32 KB).
	MaxReplyCacheBytesPerSession = 32 * 1024

	// MaxEmergencyPayloadBytes limits application payload to prevent amplification and abuse.
	MaxEmergencyPayloadBytes = 512
)

// Allowed emergency message types
const (
	MsgTypePing              = "ping"
	MsgTypeAlert             = "alert"
	MsgTypeBootstrapRequest  = "bootstrap_request"
	MsgTypeBootstrapResponse = "bootstrap_response"
	MsgTypeStatus            = "status"
	MsgTypeData              = "data"
)

// BootstrapEndpointData specifies authenticated transport coordinates for endpoint failover.
type BootstrapEndpointData struct {
	ServerIP      string `json:"server_ip"`
	TransportPort int    `json:"transport_port"`
	TransportMode string `json:"transport_mode"` // "raw-kcp", "aead-stream", "tls-outer"
	ServerPubKey  string `json:"server_pub_key,omitempty"`
	ValidUntil    int64  `json:"valid_until"`
}

// EmergencyMessage represents an authenticated application datagram exchanged over DNS.
type EmergencyMessage struct {
	ID        string `json:"id"`
	Type      string `json:"type"`      // "ping", "bootstrap_request", "bootstrap_response", "alert", "status", "data"
	Payload   []byte `json:"payload"`   // Application payload bytes (capped at MaxEmergencyPayloadBytes)
	Timestamp int64  `json:"timestamp"` // Unix timestamp
}

// Validate validates that the EmergencyMessage conforms to the strict control schema.
func (m *EmergencyMessage) Validate() error {
	if m == nil {
		return errors.New("nil emergency message")
	}
	if m.ID == "" {
		return errors.New("message ID required")
	}
	switch m.Type {
	case MsgTypePing, MsgTypeAlert, MsgTypeBootstrapRequest, MsgTypeBootstrapResponse, MsgTypeStatus, MsgTypeData:
		// Valid type
	default:
		return fmt.Errorf("unsupported message type: %q (strict schema rejection)", m.Type)
	}
	if len(m.Payload) > MaxEmergencyPayloadBytes {
		return fmt.Errorf("payload size %d exceeds max %d", len(m.Payload), MaxEmergencyPayloadBytes)
	}
	return nil
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

type cachedReplyEntry struct {
	reqSeq             uint32
	requestFingerprint [32]byte // SHA-256 digest of complete authenticated request frame
	requestID          string
	respSeq            uint32
	replyFrame         []byte
	createdAt          time.Time
}

type serverSessionEntry struct {
	mu         sync.Mutex // Serializes session replay state and reply cache
	conn       *AsymmetricConn
	lastActive time.Time
	activeOps  int32                    // Ref count of active goroutines; prevents idle eviction during in-flight processing
	inFlight   map[uint32]chan struct{} // Sequence -> channel for in-flight request single-flighting
	replyCache map[uint32]*cachedReplyEntry
	seqOrder   []uint32 // FIFO order for eviction
	cacheBytes int      // Current total bytes in replyCache
}

func (e *serverSessionEntry) addReplyCacheLocked(seq uint32, digest [32]byte, reqID string, respSeq uint32, replyFrame []byte) {
	entryLen := len(replyFrame)
	for len(e.replyCache) >= MaxCachedRepliesPerSession || (e.cacheBytes+entryLen > MaxReplyCacheBytesPerSession && len(e.seqOrder) > 0) {
		oldestSeq := e.seqOrder[0]
		e.seqOrder = e.seqOrder[1:]
		if old, ok := e.replyCache[oldestSeq]; ok {
			e.cacheBytes -= len(old.replyFrame)
			delete(e.replyCache, oldestSeq)
		}
	}
	e.replyCache[seq] = &cachedReplyEntry{
		reqSeq:             seq,
		requestFingerprint: digest,
		requestID:          reqID,
		respSeq:            respSeq,
		replyFrame:         append([]byte(nil), replyFrame...),
		createdAt:          time.Now(),
	}
	e.seqOrder = append(e.seqOrder, seq)
	e.cacheBytes += entryLen
}

// EmergencyDNSServer hosts the authoritative DNS endpoint, receiving recursive DNS queries,
// reassembling multipart frames, decrypting authenticated requests, and returning dynamic responses in TXT records.
type EmergencyDNSServer struct {
	cfg         EmergencyDNSServerConfig
	udpConn     *net.UDPConn
	tcpListener net.Listener
	reassembler *DNSReassembler
	sessions    map[uint64]*serverSessionEntry
	mu          sync.Mutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewEmergencyDNSServer creates a new authoritative emergency DNS daemon listening on UDP and TCP port 53.
func NewEmergencyDNSServer(cfg EmergencyDNSServerConfig) (*EmergencyDNSServer, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("emergency dns: domain suffix required")
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("emergency dns: PSK must be exactly 32 bytes")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen udp addr: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", cfg.ListenAddr, err)
	}

	actualPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpAddr := &net.TCPAddr{
		IP:   udpAddr.IP,
		Port: actualPort,
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("listen tcp %s: %w", tcpAddr, err)
	}

	srv := &EmergencyDNSServer{
		cfg:         cfg,
		udpConn:     udpConn,
		tcpListener: tcpListener,
		reassembler: NewDNSReassembler(30 * time.Second),
		sessions:    make(map[uint64]*serverSessionEntry),
		stopChan:    make(chan struct{}),
	}

	srv.wg.Add(3)
	go srv.serveUDP()
	go srv.serveTCP()
	go srv.cleanerLoop()
	return srv, nil
}

// Addr returns the local listening address.
func (s *EmergencyDNSServer) Addr() net.Addr {
	return s.udpConn.LocalAddr()
}

// ActiveSessionsCount returns the number of authenticated live sessions currently tracked in memory.
func (s *EmergencyDNSServer) ActiveSessionsCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Stop shuts down the authoritative DNS server cleanly.
func (s *EmergencyDNSServer) Stop() error {
	close(s.stopChan)
	errUDP := s.udpConn.Close()
	errTCP := s.tcpListener.Close()
	s.wg.Wait()
	if errUDP != nil {
		return errUDP
	}
	return errTCP
}

func (s *EmergencyDNSServer) cleanerLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.mu.Lock()
			s.evictIdleSessionsLocked(time.Now())
			s.mu.Unlock()
		}
	}
}

func (s *EmergencyDNSServer) evictIdleSessionsLocked(now time.Time) {
	for id, entry := range s.sessions {
		if atomic.LoadInt32(&entry.activeOps) == 0 && now.Sub(entry.lastActive) > ServerSessionIdleTimeout {
			delete(s.sessions, id)
		}
	}
}

func (s *EmergencyDNSServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	normalizedSuffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.cfg.DomainSuffix), "."))

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		_ = s.udpConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, remoteAddr, err := s.udpConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		reqPacket := append([]byte(nil), buf[:n]...)
		go func(pkt []byte, addr net.Addr) {
			resp := s.processQuery(pkt, normalizedSuffix)
			if resp != nil {
				_, _ = s.udpConn.WriteTo(resp, addr)
			}
		}(reqPacket, remoteAddr)
	}
}

func (s *EmergencyDNSServer) serveTCP() {
	defer s.wg.Done()
	normalizedSuffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.cfg.DomainSuffix), "."))

	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))

			// RFC 7766 TCP DNS: 2-byte prefix length
			var lenBuf [2]byte
			if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
				return
			}
			msgLen := binary.BigEndian.Uint16(lenBuf[:])
			if msgLen < 12 || msgLen > 4096 {
				return
			}

			reqBuf := make([]byte, msgLen)
			if _, err := io.ReadFull(c, reqBuf); err != nil {
				return
			}

			resp := s.processQuery(reqBuf, normalizedSuffix)
			if resp != nil && len(resp) <= 65535 {
				var outLen [2]byte
				binary.BigEndian.PutUint16(outLen[:], uint16(len(resp)))
				_, _ = c.Write(outLen[:])
				_, _ = c.Write(resp)
			}
		}(conn)
	}
}

func (s *EmergencyDNSServer) processQuery(reqPacket []byte, normalizedSuffix string) []byte {
	if len(reqPacket) < 12 {
		return nil
	}

	id, qname, qtype, err := ParseDNSQuery(reqPacket)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}
	_ = id

	qnameLower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))

	// Security Rule: Reject domains outside our authoritative child zone with REFUSED (RCODE 5)
	// Prevents the server from operating as an open resolver or DNS amplifier.
	if !strings.HasSuffix(qnameLower, "."+normalizedSuffix) && qnameLower != normalizedSuffix {
		return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
	}

	// Handle non-TXT queries (e.g. A, AAAA, SOA) with NOERROR and empty answers
	if qtype != 0x0010 /* TXT */ {
		resp, _ := BuildDNSTXTResponse(reqPacket, nil)
		return resp
	}

	clientID, offset, part, total, chunk, err := DecodeDNSQName(qnameLower, normalizedSuffix)
	if err != nil {
		// Non-encoded query under child zone (e.g. diagnostic ping)
		resp, _ := BuildDNSTXTResponse(reqPacket, []byte("PAQET_EMERGENCY_DNS_ZONE_ACTIVE"))
		return resp
	}

	fullFrame, isComplete := s.reassembler.PushFragment(clientID, offset, part, total, chunk)
	if !isComplete {
		// Intermediate fragment received: return empty response so recursor does not stall
		resp, _ := BuildDNSTXTResponse(reqPacket, nil)
		return resp
	}

	// Reassembled frame must have valid header
	if len(fullFrame) < AsymmetricHeaderLen {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	sessionID := binary.BigEndian.Uint64(fullFrame[4:12])
	reqSeq := binary.BigEndian.Uint32(fullFrame[12:16])
	reqDigest := sha256.Sum256(fullFrame)

	// Step 1: Check if session already exists
	s.mu.Lock()
	entry, exists := s.sessions[sessionID]
	if exists {
		atomic.AddInt32(&entry.activeOps, 1)
	}
	s.mu.Unlock()

	if exists {
		defer atomic.AddInt32(&entry.activeOps, -1)
		return s.processExistingSessionQuery(reqPacket, entry, fullFrame, reqSeq, reqDigest)
	}

	return s.processNewSessionQuery(reqPacket, sessionID, fullFrame, reqSeq, reqDigest)
}

func (s *EmergencyDNSServer) processExistingSessionQuery(
	reqPacket []byte,
	entry *serverSessionEntry,
	fullFrame []byte,
	reqSeq uint32,
	reqDigest [32]byte,
) []byte {
	entry.mu.Lock()

	// Wait if another goroutine is currently processing this exact sequence (single-flight)
	for {
		waitCh, inFlight := entry.inFlight[reqSeq]
		if !inFlight {
			break
		}
		entry.mu.Unlock()
		select {
		case <-waitCh:
		case <-time.After(3 * time.Second):
			return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
		}
		entry.mu.Lock()
	}

	// 1. Check replyCache
	if cached, ok := entry.replyCache[reqSeq]; ok {
		// A sequence was found in replyCache.
		// REQUIREMENT: Must cryptographically verify AEAD authentication and compare fingerprint!
		_, _, _, err := entry.conn.VerifyFrame(fullFrame)
		if err != nil {
			// Unauthenticated attacker or corrupt frame!
			entry.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}

		if reqDigest != cached.requestFingerprint {
			// Attacker or client reused seq with different ciphertext/content!
			// REJECT without invoking handler or leaking cached reply!
			entry.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
		}

		// Exact authenticated duplicate! Return cached reply
		cachedReply := append([]byte(nil), cached.replyFrame...)
		entry.lastActive = time.Now()
		entry.mu.Unlock()

		resp, err := BuildDNSTXTResponse(reqPacket, cachedReply)
		if err == nil {
			return resp
		}
		return nil
	}

	// 2. New sequence for existing session: verify AEAD and update replay window
	seq, _, plaintext, err := entry.conn.openFrame(fullFrame)
	if err != nil {
		// Replay violation (e.g. sequence already seen and evicted from cache) or AEAD failure
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
	}

	// Register in-flight operation
	doneCh := make(chan struct{})
	if entry.inFlight == nil {
		entry.inFlight = make(map[uint32]chan struct{})
	}
	entry.inFlight[reqSeq] = doneCh
	entry.lastActive = time.Now()
	entry.mu.Unlock()

	defer func() {
		entry.mu.Lock()
		delete(entry.inFlight, reqSeq)
		close(doneCh)
		entry.mu.Unlock()
	}()

	// 3. Schema validation outside lock
	var reqMsg EmergencyMessage
	if err := json.Unmarshal(plaintext, &reqMsg); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}
	if err := reqMsg.Validate(); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	// 4. Invoke handler outside lock
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
			Reply:     append([]byte("ACK_ECHO:"), reqMsg.Payload...),
			Timestamp: time.Now().Unix(),
		}
	}

	respPlaintext, _ := json.Marshal(respMsg)

	// 5. Seal response and cache it under session lock
	entry.mu.Lock()
	respSeq := entry.conn.NextSendSeq()
	respFrame, err := entry.conn.sealFrame(respSeq, seq, respPlaintext)
	if err != nil {
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	entry.addReplyCacheLocked(reqSeq, reqDigest, reqMsg.ID, respSeq, respFrame)
	entry.lastActive = time.Now()
	entry.mu.Unlock()

	dnsRespPacket, err := BuildDNSTXTResponse(reqPacket, respFrame)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}
	return dnsRespPacket
}

func (s *EmergencyDNSServer) processNewSessionQuery(
	reqPacket []byte,
	sessionID uint64,
	fullFrame []byte,
	reqSeq uint32,
	reqDigest [32]byte,
) []byte {
	// 1. Ephemeral unpersisted session for candidate validation
	candidateConn, err := NewServerAsymmetricSession(sessionID, s.cfg.PSK)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	// 2. Cryptographic authentication: openFrame validates AEAD tag, AAD headers, and anti-replay
	seq, _, plaintext, err := candidateConn.openFrame(fullFrame)
	if err != nil {
		// Authentication failed or bad magic. Drop immediately with REFUSED. Zero state persisted!
		return BuildDNSErrorResponse(reqPacket, 5 /* REFUSED */)
	}

	// 3. Validate JSON schema before committing to persistent session state
	var reqMsg EmergencyMessage
	if err := json.Unmarshal(plaintext, &reqMsg); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}
	if err := reqMsg.Validate(); err != nil {
		return BuildDNSErrorResponse(reqPacket, 1 /* FORMERR */)
	}

	// 4. Atomically commit or detect existing session
	doneCh := make(chan struct{})
	var entry *serverSessionEntry

	s.mu.Lock()
	existingEntry, alreadyCreated := s.sessions[sessionID]
	if alreadyCreated {
		// Another concurrent goroutine already committed this session while we were authenticating!
		entry = existingEntry
		atomic.AddInt32(&entry.activeOps, 1)
		s.mu.Unlock()

		// Discard candidateConn and route request through existing established session!
		defer atomic.AddInt32(&entry.activeOps, -1)
		return s.processExistingSessionQuery(reqPacket, entry, fullFrame, reqSeq, reqDigest)
	}

	// Session is genuinely new. Enforce session table bounds.
	now := time.Now()
	if len(s.sessions) >= MaxActiveServerSessions {
		s.evictIdleSessionsLocked(now)
	}
	if len(s.sessions) >= MaxActiveServerSessions {
		// Evict oldest session that has activeOps == 0
		var oldestID uint64
		var oldestTime time.Time
		found := false
		for id, e := range s.sessions {
			if atomic.LoadInt32(&e.activeOps) == 0 {
				if oldestTime.IsZero() || e.lastActive.Before(oldestTime) {
					oldestID = id
					oldestTime = e.lastActive
					found = true
				}
			}
		}
		if found {
			delete(s.sessions, oldestID)
		} else {
			// All 1024 sessions have active operations! Reject to prevent OOM
			s.mu.Unlock()
			return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
		}
	}

	entry = &serverSessionEntry{
		conn:       candidateConn,
		lastActive: now,
		activeOps:  1,
		inFlight:   map[uint32]chan struct{}{reqSeq: doneCh},
		replyCache: make(map[uint32]*cachedReplyEntry),
	}
	s.sessions[sessionID] = entry
	s.mu.Unlock()

	defer func() {
		entry.mu.Lock()
		delete(entry.inFlight, reqSeq)
		close(doneCh)
		entry.mu.Unlock()
		atomic.AddInt32(&entry.activeOps, -1)
	}()

	// 5. Invoke handler outside lock
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
			Reply:     append([]byte("ACK_ECHO:"), reqMsg.Payload...),
			Timestamp: time.Now().Unix(),
		}
	}

	respPlaintext, _ := json.Marshal(respMsg)

	// 6. Seal response and cache it
	entry.mu.Lock()
	respSeq := entry.conn.NextSendSeq()
	respFrame, err := entry.conn.sealFrame(respSeq, seq, respPlaintext)
	if err != nil {
		entry.mu.Unlock()
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}

	entry.addReplyCacheLocked(reqSeq, reqDigest, reqMsg.ID, respSeq, respFrame)
	entry.lastActive = time.Now()
	entry.mu.Unlock()

	dnsRespPacket, err := BuildDNSTXTResponse(reqPacket, respFrame)
	if err != nil {
		return BuildDNSErrorResponse(reqPacket, 2 /* SERVFAIL */)
	}
	return dnsRespPacket
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
	if len(cfg.PSK) != 32 {
		return nil, errors.New("emergency client: PSK must be exactly 32 bytes")
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
		cfg.SessionID = cryptoRandUint64()
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
	if err := msg.Validate(); err != nil {
		return nil, 0, fmt.Errorf("emergency client invalid message: %w", err)
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

	const chunkSize = 35
	totalParts := uint8((len(frame) + chunkSize - 1) / chunkSize)
	if totalParts == 0 {
		totalParts = 1
	}

	// Generate a 64-bit cryptographically secure random nonce for cache busting
	curOffset := cryptoRandUint64()

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

		if attempt < c.cfg.MaxRetries {
			// Exponential backoff with jitter: 250ms * 2^attempt + jitter
			backoff := time.Duration(250*(1<<attempt))*time.Millisecond + time.Duration(cryptoRandUint64()%50)*time.Millisecond
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return nil, time.Since(startOverall), fmt.Errorf("emergency exchange timed out after %d retries", c.cfg.MaxRetries)
}

func (c *EmergencyDNSClient) attemptExchange(
	ctx context.Context,
	resolverUDP *net.UDPAddr,
	curOffset uint64,
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

		// RFC 1035 limits validation: labels <= 63, full name <= 253
		if len(qname) > 253 {
			return nil, fmt.Errorf("emergency client: qname length %d exceeds RFC 1035 limit (253)", len(qname))
		}

		txID := uint16(cryptoRandUint64())
		queryPkt := BuildDNSQuery(qname, 0x0010 /* TXT */, txID)
		if _, err := conn.WriteToUDP(queryPkt, resolverUDP); err != nil {
			return nil, err
		}

		queries = append(queries, pendingQuery{txID: txID, qname: qname})
	}

	buf := make([]byte, 4096)
	deadline := time.Now().Add(c.cfg.Timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
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
			continue
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

// GenerateEmergencyKey produces a fresh 32-byte cryptographically secure random key.
func GenerateEmergencyKey() []byte {
	k := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, k)
	return k
}

// GenerateRandomMessageID creates a collision-resistant 16-byte hex request ID.
func GenerateRandomMessageID() string {
	b := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("msg-%s", hex.EncodeToString(b))
}

func cryptoRandUint64() uint64 {
	nBig, _ := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFFFFFFFFFF))
	return uint64(nBig.Int64())
}
