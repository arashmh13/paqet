package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"paqet/internal/ng/crypto"
	"paqet/internal/ng/replay"
)

const (
	// AsymmetricMagic identifies legacy v2 asymmetric transport frames ("PAQA").
	AsymmetricMagic uint32 = 0x50415141

	// AsymmetricMagicV3 identifies v3 asymmetric transport frames with explicit ServerID domain separation ("PAQC").
	AsymmetricMagicV3 uint32 = 0x50415143

	// AsymmetricHeaderLen is the fixed size of unencrypted v2 frame header:
	// Magic (4) + SessionID (8) + Seq (4) + Ack (4) = 20 bytes.
	AsymmetricHeaderLen = 20

	// AsymmetricHeaderV3MinLen is the minimum size of unencrypted v3 frame header:
	// Magic (4) + SessionID (8) + Seq (4) + Ack (4) + ServerIDLen (1) = 21 bytes.
	AsymmetricHeaderV3MinLen = 21

	// DefaultAsymmetricMTU is the maximum payload size per chunk (120 bytes for DNS, 1380 for UDP).
	DefaultAsymmetricMTU = 1380

	// AsymmetricSessionTimeout is the period of inactivity before tearing down an asymmetric session.
	AsymmetricSessionTimeout = 60 * time.Second

	// DefaultRTO is the retransmission timeout for unacknowledged frames over lossy channels.
	DefaultRTO = 600 * time.Millisecond

	// MaxRetries is the maximum retransmission attempts before marking frame dropped.
	MaxRetries = 8
)

var (
	ErrAsymmetricInvalidMagic   = errors.New("asymmetric: invalid magic header")
	ErrAsymmetricSessionClosed  = errors.New("asymmetric: session is closed")
	ErrAsymmetricShortFrame     = errors.New("asymmetric: frame too short")
	ErrAsymmetricWindowOverflow = errors.New("asymmetric: receive window overflow")
	ErrSequenceExhausted        = errors.New("asymmetric: sequence number space exhausted, session must terminate")
)

type unackedFrame struct {
	seq     uint32
	frame   []byte
	sentAt  time.Time
	retries int
}

// Role indicates whether the node is a client (initiator) or server (responder).
type Role uint8

const (
	RoleClient Role = 1
	RoleServer Role = 2
)

// UpstreamSender is the interface for transmitting client-to-server datagrams.
type UpstreamSender interface {
	SendUpstream(ctx context.Context, frame []byte) error
	Close() error
}

// DownstreamReceiver is the interface for receiving server-to-client datagrams.
type DownstreamReceiver interface {
	RecvDownstream(ctx context.Context) ([]byte, error)
	Close() error
}

// DownstreamSender is the server-side interface for returning datagrams to the client.
type DownstreamSender interface {
	SendDownstream(ctx context.Context, clientAddr net.Addr, frame []byte) error
	Close() error
}

// UpstreamReceiver is the server-side interface for receiving client datagrams.
type UpstreamReceiver interface {
	RecvUpstream(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}

// AsymmetricConn implements net.Conn over directionally decoupled upstream and downstream transports.
type AsymmetricConn struct {
	sessionID         uint64
	role              Role
	serverID          string          // Authoritative server ID for multi-authority domain separation
	authorizedServers map[string]bool // Optional client-side whitelist of authorized server IDs
	mtu               int
	psk               []byte
	encKey            []byte
	decKey            []byte
	sendSeq           atomic.Uint32
	lastAckRcv        atomic.Uint32
	nextRecv          atomic.Uint32

	sender       UpstreamSender
	receiver     DownstreamReceiver
	replay       *replay.Filter
	serverReplay map[string]*replay.Filter
	replayMu     sync.Mutex

	pipeR *io.PipeReader
	pipeW *io.PipeWriter

	reorderMu sync.Mutex
	reorder   map[uint32][]byte // out-of-order received payloads

	localAddr  net.Addr
	remoteAddr net.Addr

	unackedMu sync.Mutex
	unacked   map[uint32]*unackedFrame
	rto       time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	readDeadline  time.Time
	writeDeadline time.Time
}

// NewClientAsymmetricConn creates an asymmetric net.Conn from separate upstream and downstream channels.
func NewClientAsymmetricConn(
	sessionID uint64,
	psk []byte,
	mtu int,
	sender UpstreamSender,
	receiver DownstreamReceiver,
	localAddr net.Addr,
	remoteAddr net.Addr,
) (*AsymmetricConn, error) {
	if mtu <= 0 {
		mtu = DefaultAsymmetricMTU
	}

	c2s, s2c, err := crypto.DeriveServerTrafficKeys(psk, []byte(fmt.Sprintf("paqet-asym-%d", sessionID)), "default")
	if err != nil {
		return nil, fmt.Errorf("derive keys: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pipeR, pipeW := io.Pipe()

	conn := &AsymmetricConn{
		sessionID:  sessionID,
		role:       RoleClient,
		mtu:        mtu,
		psk:        psk,
		encKey:     c2s, // client encrypts with c2s
		decKey:     s2c, // client decrypts with s2c
		sender:     sender,
		receiver:   receiver,
		replay:     replay.NewFilter(30 * time.Second),
		pipeR:      pipeR,
		pipeW:      pipeW,
		reorder:    make(map[uint32][]byte),
		unacked:    make(map[uint32]*unackedFrame),
		rto:        DefaultRTO,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		ctx:        ctx,
		cancel:     cancel,
	}

	go conn.recvLoop()
	go conn.retransmitLoop()
	return conn, nil
}

// Write fragments and encrypts application data, emitting it across the upstream transport.
func (c *AsymmetricConn) Write(b []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, ErrAsymmetricSessionClosed
	default:
	}

	totalSent := 0
	offset := 0

	for offset < len(b) {
		chunkSize := len(b) - offset
		if chunkSize > c.mtu {
			chunkSize = c.mtu
		}
		chunk := b[offset : offset+chunkSize]

		if c.sendSeq.Load() >= 0xFFFFFFF0 {
			return totalSent, ErrSequenceExhausted
		}
		seq := c.sendSeq.Add(1)
		if seq == 0 || seq >= 0xFFFFFFF0 {
			return totalSent, ErrSequenceExhausted
		}
		ack := c.nextRecv.Load()

		frame, err := c.sealFrame(seq, ack, chunk)
		if err != nil {
			return totalSent, fmt.Errorf("seal frame %d: %w", seq, err)
		}

		c.unackedMu.Lock()
		if c.unacked != nil {
			c.unacked[seq] = &unackedFrame{
				seq:    seq,
				frame:  frame,
				sentAt: time.Now(),
			}
		}
		c.unackedMu.Unlock()

		if err := c.sender.SendUpstream(c.ctx, frame); err != nil {
			return totalSent, fmt.Errorf("send upstream seq %d: %w", seq, err)
		}

		offset += chunkSize
		totalSent += chunkSize
	}

	return totalSent, nil
}

// Read reads in-order application payload reassembled from the downstream transport.
func (c *AsymmetricConn) Read(b []byte) (int, error) {
	return c.pipeR.Read(b)
}

// Close terminates the asymmetric session and underlying transports.
func (c *AsymmetricConn) Close() error {
	c.cancel()
	_ = c.pipeW.Close()
	_ = c.pipeR.Close()
	var errs []error
	if c.sender != nil {
		if err := c.sender.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.receiver != nil {
		if err := c.receiver.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (c *AsymmetricConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *AsymmetricConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *AsymmetricConn) SetDeadline(t time.Time) error      { return nil }
func (c *AsymmetricConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *AsymmetricConn) SetWriteDeadline(t time.Time) error { return nil }

// SealFrame provides public access to sealFrame for emergency datagram channels.
func (c *AsymmetricConn) SealFrame(seq, ack uint32, plaintext []byte) ([]byte, error) {
	return c.sealFrame(seq, ack, plaintext)
}

// OpenFrame provides public access to openFrame for emergency datagram channels.
func (c *AsymmetricConn) OpenFrame(frame []byte) (seq, ack uint32, plaintext []byte, err error) {
	return c.openFrame(frame)
}

// SessionID returns the active session ID.
func (c *AsymmetricConn) SessionID() uint64 {
	return c.sessionID
}

// NextSendSeq advances and returns the next sequence number.
func (c *AsymmetricConn) NextSendSeq() uint32 {
	return c.sendSeq.Add(1)
}

// ServerID returns the configured server ID for this connection.
func (c *AsymmetricConn) ServerID() string {
	return c.serverID
}

// SetServerID sets the authoritative server ID.
func (c *AsymmetricConn) SetServerID(id string) {
	c.serverID = id
}

// SetAuthorizedServers sets the whitelist of authorized server IDs for client connections.
func (c *AsymmetricConn) SetAuthorizedServers(servers []string) {
	c.authorizedServers = make(map[string]bool)
	for _, s := range servers {
		c.authorizedServers[s] = true
	}
}

// NewServerAsymmetricSession creates an AsymmetricConn configured as RoleServer for a given session.
func NewServerAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	return NewServerAsymmetricSessionWithID(sessionID, psk, "default")
}

// NewServerAsymmetricSessionWithID creates an AsymmetricConn configured as RoleServer with a specific ServerID.
func NewServerAsymmetricSessionWithID(sessionID uint64, psk []byte, serverID string) (*AsymmetricConn, error) {
	if serverID == "" {
		serverID = "default"
	}
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveServerTrafficKeys(psk, salt, serverID)
	if err != nil {
		return nil, fmt.Errorf("derive server keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		serverID:  serverID,
		psk:       psk,
		encKey:    s2c, // server encrypts with s2c bound to serverID
		decKey:    c2s, // server decrypts with c2s
		replay:    replay.NewFilter(30 * time.Second),
	}, nil
}

// NewClientAsymmetricSession creates an AsymmetricConn configured as RoleClient for a given session.
func NewClientAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	return NewClientAsymmetricSessionWithServers(sessionID, psk, nil)
}

// NewClientAsymmetricSessionWithServers creates an AsymmetricConn configured as RoleClient with authorized servers.
func NewClientAsymmetricSessionWithServers(sessionID uint64, psk []byte, authorizedServers []string) (*AsymmetricConn, error) {
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveServerTrafficKeys(psk, salt, "default")
	if err != nil {
		return nil, fmt.Errorf("derive client keys: %w", err)
	}

	authMap := make(map[string]bool)
	for _, s := range authorizedServers {
		authMap[s] = true
	}

	return &AsymmetricConn{
		sessionID:         sessionID,
		role:              RoleClient,
		psk:               psk,
		encKey:            c2s, // client encrypts with c2s
		decKey:            s2c, // default s2c; dynamically derives if serverID is in v3 header
		authorizedServers: authMap,
		replay:            replay.NewFilter(30 * time.Second),
	}, nil
}

// sealFrame packs Magic, SessionID, Seq, Ack, and AEAD-encrypted payload into a wire datagram.
func (c *AsymmetricConn) sealFrame(seq, ack uint32, plaintext []byte) ([]byte, error) {
	var header []byte
	if c.serverID != "" || c.role == RoleServer {
		srvID := c.serverID
		if srvID == "" {
			srvID = "default"
		}
		if len(srvID) > 64 {
			return nil, errors.New("asymmetric: serverID exceeds 64 bytes limit")
		}
		header = make([]byte, AsymmetricHeaderV3MinLen+len(srvID))
		binary.BigEndian.PutUint32(header[0:4], AsymmetricMagicV3)
		binary.BigEndian.PutUint64(header[4:12], c.sessionID)
		binary.BigEndian.PutUint32(header[12:16], seq)
		binary.BigEndian.PutUint32(header[16:20], ack)
		header[20] = byte(len(srvID))
		copy(header[21:], srvID)
	} else {
		// Client upstream v3 frame: ServerIDLen = 0
		header = make([]byte, AsymmetricHeaderV3MinLen)
		binary.BigEndian.PutUint32(header[0:4], AsymmetricMagicV3)
		binary.BigEndian.PutUint64(header[4:12], c.sessionID)
		binary.BigEndian.PutUint32(header[12:16], seq)
		binary.BigEndian.PutUint32(header[16:20], ack)
		header[20] = 0 // No server ID in upstream
	}

	// Nonce is deterministically constructed from SessionID, Seq, and Role (12 bytes)
	nonce := make([]byte, crypto.NonceSize)
	binary.BigEndian.PutUint64(nonce[0:8], c.sessionID)
	binary.BigEndian.PutUint32(nonce[8:12], seq)
	nonce[0] ^= byte(c.role)

	aead, err := crypto.NewAEAD(c.encKey)
	if err != nil {
		return nil, err
	}

	// Encrypt plaintext with header authenticated as AAD
	ciphertext := aead.Seal(nil, nonce, plaintext, header)

	frame := make([]byte, len(header)+len(ciphertext))
	copy(frame[:len(header)], header)
	copy(frame[len(header):], ciphertext)
	return frame, nil
}

// VerifyFrameWithServerID cryptographically verifies the frame's header, magic, session ID,
// and AEAD authentication tag, returning the decrypted plaintext and authenticating ServerID.
func (c *AsymmetricConn) VerifyFrameWithServerID(frame []byte) (seq, ack uint32, plaintext []byte, serverID string, err error) {
	if len(frame) < AsymmetricHeaderLen+crypto.TagSize {
		return 0, 0, nil, "", ErrAsymmetricShortFrame
	}

	magic := binary.BigEndian.Uint32(frame[0:4])
	var headerLen int
	var sessID uint64

	switch magic {
	case AsymmetricMagicV3:
		if len(frame) < AsymmetricHeaderV3MinLen+crypto.TagSize {
			return 0, 0, nil, "", ErrAsymmetricShortFrame
		}
		sessID = binary.BigEndian.Uint64(frame[4:12])
		seq = binary.BigEndian.Uint32(frame[12:16])
		ack = binary.BigEndian.Uint32(frame[16:20])
		srvIDLen := int(frame[20])
		headerLen = AsymmetricHeaderV3MinLen + srvIDLen
		if len(frame) < headerLen+crypto.TagSize {
			return 0, 0, nil, "", ErrAsymmetricShortFrame
		}
		if srvIDLen > 0 {
			serverID = string(frame[21 : 21+srvIDLen])
		}

	case AsymmetricMagic:
		// Legacy v2 frame
		sessID = binary.BigEndian.Uint64(frame[4:12])
		seq = binary.BigEndian.Uint32(frame[12:16])
		ack = binary.BigEndian.Uint32(frame[16:20])
		headerLen = AsymmetricHeaderLen
		serverID = "legacy"

	default:
		return 0, 0, nil, "", ErrAsymmetricInvalidMagic
	}

	if sessID != c.sessionID {
		return 0, 0, nil, "", fmt.Errorf("session ID mismatch: got %d, want %d", sessID, c.sessionID)
	}

	peerRole := RoleServer
	if c.role == RoleServer {
		peerRole = RoleClient
	}
	nonce := make([]byte, crypto.NonceSize)
	binary.BigEndian.PutUint64(nonce[0:8], c.sessionID)
	binary.BigEndian.PutUint32(nonce[8:12], seq)
	nonce[0] ^= byte(peerRole)

	var decKey []byte
	if c.role == RoleClient && magic == AsymmetricMagicV3 && serverID != "" {
		// Client verifying downstream server response:
		// Check server authorization policy
		if len(c.authorizedServers) > 0 && !c.authorizedServers[serverID] {
			return 0, 0, nil, serverID, fmt.Errorf("server %q is not authorized by client policy (fail-closed)", serverID)
		}
		salt := []byte(fmt.Sprintf("paqet-asym-%d", c.sessionID))
		sKey, err := crypto.DeriveServerResponseKey(c.psk, salt, serverID)
		if err != nil {
			return 0, 0, nil, serverID, fmt.Errorf("derive server response key: %w", err)
		}
		decKey = sKey
	} else {
		decKey = c.decKey
	}

	aead, err := crypto.NewAEAD(decKey)
	if err != nil {
		return 0, 0, nil, serverID, err
	}

	header := frame[:headerLen]
	ciphertext := frame[headerLen:]

	plaintext, err = aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return 0, 0, nil, serverID, fmt.Errorf("aead open: %w", err)
	}

	return seq, ack, plaintext, serverID, nil
}

// VerifyFrame cryptographically verifies the frame's header, magic, session ID,
// and AEAD authentication tag, and returns the decrypted plaintext WITHOUT
// updating or checking the sliding replay window.
func (c *AsymmetricConn) VerifyFrame(frame []byte) (seq, ack uint32, plaintext []byte, err error) {
	seq, ack, plaintext, _, err = c.VerifyFrameWithServerID(frame)
	return seq, ack, plaintext, err
}

// openFrame parses, verifies replay, and decrypts an incoming wire datagram.
func (c *AsymmetricConn) openFrame(frame []byte) (seq, ack uint32, plaintext []byte, err error) {
	seq, ack, plaintext, _, err = c.openFrameWithServerID(frame)
	return seq, ack, plaintext, err
}

// openFrameWithServerID parses, verifies replay, and decrypts an incoming wire datagram, returning serverID.
func (c *AsymmetricConn) openFrameWithServerID(frame []byte) (seq, ack uint32, plaintext []byte, serverID string, err error) {
	seq, ack, plaintext, serverID, err = c.VerifyFrameWithServerID(frame)
	if err != nil {
		return 0, 0, nil, serverID, err
	}

	// Replay verification and recording ONLY AFTER successful authentication
	c.replayMu.Lock()
	defer c.replayMu.Unlock()

	var filter *replay.Filter
	if c.role == RoleClient && serverID != "" {
		if c.serverReplay == nil {
			c.serverReplay = make(map[string]*replay.Filter)
		}
		f, ok := c.serverReplay[serverID]
		if !ok {
			f = replay.NewFilter(30 * time.Second)
			c.serverReplay[serverID] = f
		}
		filter = f
	} else {
		filter = c.replay
	}

	if filter != nil {
		if err := filter.Validate(uint64(seq)); err != nil {
			return 0, 0, nil, serverID, fmt.Errorf("replay check seq %d for server %q: %w", seq, serverID, err)
		}
	}

	return seq, ack, plaintext, serverID, nil
}

// recvLoop processes inbound packets from the downstream receiver, reordering as needed.
func (c *AsymmetricConn) recvLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		rawFrame, err := c.receiver.RecvDownstream(c.ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		seq, ack, payload, err := c.openFrame(rawFrame)
		if err != nil {
			continue // drop invalid, replayed, or unauthenticated datagram
		}

		c.lastAckRcv.Store(ack)
		c.unackedMu.Lock()
		if c.unacked != nil {
			for s := range c.unacked {
				if s <= ack {
					delete(c.unacked, s)
				}
			}
		}
		c.unackedMu.Unlock()

		if len(payload) == 0 {
			continue // Pure ACK frame
		}

		c.reorderMu.Lock()
		expected := c.nextRecv.Load() + 1
		if seq == expected {
			// In-order packet arrived
			_, _ = c.pipeW.Write(payload)
			c.nextRecv.Store(seq)

			// Drain consecutive buffered packets
			for {
				nextExpected := c.nextRecv.Load() + 1
				nextPayload, found := c.reorder[nextExpected]
				if !found {
					break
				}
				delete(c.reorder, nextExpected)
				_, _ = c.pipeW.Write(nextPayload)
				c.nextRecv.Store(nextExpected)
			}
		} else if seq > expected {
			// Future packet (out of order)
			if len(c.reorder) < 256 {
				c.reorder[seq] = append([]byte(nil), payload...)
			}
		}
		c.reorderMu.Unlock()
	}
}

func (c *AsymmetricConn) SetRTO(d time.Duration) {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()
	if d > 0 {
		c.rto = d
	}
}

func (c *AsymmetricConn) getRTO() time.Duration {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()
	if c.rto <= 0 {
		return DefaultRTO
	}
	return c.rto
}

// retransmitLoop handles automatic retransmissions of unacknowledged frames over lossy channels.
func (c *AsymmetricConn) retransmitLoop() {
	rto := c.getRTO()
	ticker := time.NewTicker(rto / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			curRTO := c.getRTO()
			c.unackedMu.Lock()
			for _, entry := range c.unacked {
				if now.Sub(entry.sentAt) >= curRTO {
					if entry.retries < MaxRetries {
						entry.retries++
						entry.sentAt = now
						if c.sender != nil {
							_ = c.sender.SendUpstream(c.ctx, entry.frame)
						}
					}
				}
			}
			c.unackedMu.Unlock()
		}
	}
}

// MemoryPipeUpstream connects memory channels for testing and local simulation.
type MemoryPipeSender struct {
	ch chan []byte
}

func NewMemoryPipeSender(ch chan []byte) *MemoryPipeSender {
	return &MemoryPipeSender{ch: ch}
}

func (s *MemoryPipeSender) SendUpstream(ctx context.Context, frame []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.ch <- append([]byte(nil), frame...):
		return nil
	}
}

func (s *MemoryPipeSender) Close() error {
	return nil
}

type MemoryPipeReceiver struct {
	ch chan []byte
}

func NewMemoryPipeReceiver(ch chan []byte) *MemoryPipeReceiver {
	return &MemoryPipeReceiver{ch: ch}
}

func (r *MemoryPipeReceiver) RecvDownstream(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame, ok := <-r.ch:
		if !ok {
			return nil, io.EOF
		}
		return frame, nil
	}
}

func (r *MemoryPipeReceiver) Close() error {
	return nil
}
