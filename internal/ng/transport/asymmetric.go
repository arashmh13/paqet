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

	// MaxSafeSequenceNumber is the sequence number limit before terminating the session to prevent 32-bit nonce wraparound.
	MaxSafeSequenceNumber uint32 = 0xFFFFFFF0
)

var (
	ErrAsymmetricInvalidMagic   = errors.New("asymmetric: invalid magic header")
	ErrAsymmetricSessionClosed  = errors.New("asymmetric: session is closed")
	ErrAsymmetricShortFrame     = errors.New("asymmetric: frame too short")
	ErrAsymmetricWindowOverflow = errors.New("asymmetric: receive window overflow")
	ErrSequenceExhausted        = errors.New("asymmetric: sequence number space exhausted, session must terminate to prevent nonce reuse")
	ErrInvalidServerID          = errors.New("asymmetric: invalid server ID format")
	ErrEmptyServerAllowlist     = errors.New("asymmetric: authorized servers allowlist cannot be empty (fail-closed)")
	ErrLegacyProtocolDisabled   = errors.New("asymmetric: legacy v2 protocol frames are disabled by policy (v3 required)")
	ErrMissingResponseSecret    = errors.New("asymmetric: dedicated per-server response secret is required (shared PSK fallback prohibited)")
	ErrInvalidResponseSecret    = errors.New("asymmetric: response secret must be exactly 32 bytes")
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

// ValidateServerID validates that serverID is canonically formatted (3-64 chars, lowercase alphanumeric, '-', '.', or '_').
func ValidateServerID(id string) error {
	if len(id) < 3 || len(id) > 64 {
		return fmt.Errorf("%w: length %d must be between 3 and 64 characters", ErrInvalidServerID, len(id))
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '.' || b == '_') {
			return fmt.Errorf("%w: invalid character %q (must be lowercase alphanumeric, '-', '.', or '_')", ErrInvalidServerID, b)
		}
	}
	return nil
}

// AsymmetricConn implements net.Conn over directionally decoupled upstream and downstream transports.
type AsymmetricConn struct {
	sessionID            uint64
	role                 Role
	serverID             string            // Cryptographic server ID (immutable once derived)
	serverSecret         []byte            // Dedicated server response secret (immutable)
	authorizedServers    map[string][]byte // Client-side map: serverID -> 32-byte response secret (immutable)
	allowLegacyV2        bool              // If false, rejects 0x50415141 frames (fail-closed)
	isLegacySingleServer bool              // If true, operates in legacy single-server mode using PSK only
	mtu                  int
	psk                  []byte
	encKey               []byte
	decKey               []byte
	sendSeq              atomic.Uint32
	lastAckRcv           atomic.Uint32
	nextRecv             atomic.Uint32

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
	if len(psk) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}

	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveLegacySingleServerTrafficKeys(psk, salt)
	if err != nil {
		return nil, fmt.Errorf("derive keys: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pipeR, pipeW := io.Pipe()

	conn := &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		mtu:                  mtu,
		psk:                  psk,
		encKey:               c2s, // client encrypts with c2s
		decKey:               s2c, // client decrypts with s2c
		allowLegacyV2:        true,
		isLegacySingleServer: true,
		sender:               sender,
		receiver:             receiver,
		replay:               replay.NewFilter(30 * time.Second),
		pipeR:                pipeR,
		pipeW:                pipeW,
		reorder:              make(map[uint32][]byte),
		unacked:              make(map[uint32]*unackedFrame),
		rto:                  DefaultRTO,
		localAddr:            localAddr,
		remoteAddr:           remoteAddr,
		ctx:                  ctx,
		cancel:               cancel,
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

// NextSendSeq advances and returns the next sequence number, or returns ErrSequenceExhausted before wraparound.
func (c *AsymmetricConn) NextSendSeq() (uint32, error) {
	for {
		curr := c.sendSeq.Load()
		if curr >= MaxSafeSequenceNumber {
			return 0, ErrSequenceExhausted
		}
		next := curr + 1
		if next == 0 || next >= MaxSafeSequenceNumber {
			return 0, ErrSequenceExhausted
		}
		if c.sendSeq.CompareAndSwap(curr, next) {
			return next, nil
		}
	}
}

// SetSendSeqForTest allows deterministic testing of sequence boundaries without running billions of iterations.
func (c *AsymmetricConn) SetSendSeqForTest(seq uint32) {
	c.sendSeq.Store(seq)
}

// SetAllowLegacyV2ForTest allows explicitly enabling legacy v2 support for migration tests.
func (c *AsymmetricConn) SetAllowLegacyV2ForTest(allow bool) {
	c.allowLegacyV2 = allow
}

// ServerID returns the configured server ID for this connection.
func (c *AsymmetricConn) ServerID() string {
	return c.serverID
}

// NewServerAsymmetricSession creates an AsymmetricConn configured as RoleServer for explicit single-server legacy mode.
// For multi-authoritative deployments, use NewServerAsymmetricSessionWithID with dedicated credentials.
func NewServerAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	return NewServerLegacyAsymmetricSession(sessionID, psk)
}

// NewServerLegacyAsymmetricSession creates an AsymmetricConn for explicit single-server legacy operation using PSK only.
// This mode is visibly separate and cannot be selected implicitly by a multi-authoritative configuration.
func NewServerLegacyAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	if len(psk) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	pskClone := append([]byte(nil), psk...)
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveLegacySingleServerTrafficKeys(pskClone, salt)
	if err != nil {
		return nil, fmt.Errorf("derive legacy server keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleServer,
		serverID:             "legacy",
		serverSecret:         pskClone,
		psk:                  pskClone,
		encKey:               s2c,
		decKey:               c2s,
		allowLegacyV2:        true,
		isLegacySingleServer: true,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// NewServerAsymmetricSessionWithID creates an AsymmetricConn configured as RoleServer for multi-authoritative operation
// with an explicit, immutable ServerID and a mandatory dedicated 32-byte response secret.
// No fallback to PSK is permitted.
func NewServerAsymmetricSessionWithID(sessionID uint64, c2sPSK []byte, serverResponseSecret []byte, serverID string) (*AsymmetricConn, error) {
	if serverID == "" {
		return nil, fmt.Errorf("server session requires non-empty serverID")
	}
	if serverID == "default" || serverID == "legacy" {
		return nil, fmt.Errorf("server session cannot use reserved ID %q in multi-server mode", serverID)
	}
	if err := ValidateServerID(serverID); err != nil {
		return nil, err
	}
	if len(c2sPSK) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	if len(serverResponseSecret) == 0 {
		return nil, ErrMissingResponseSecret
	}
	if len(serverResponseSecret) != crypto.KeySize {
		return nil, ErrInvalidResponseSecret
	}

	// Defensive copy of secret slices to prevent caller mutations after construction
	pskClone := append([]byte(nil), c2sPSK...)
	secretClone := append([]byte(nil), serverResponseSecret...)

	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveServerTrafficKeys(pskClone, secretClone, salt, serverID)
	if err != nil {
		return nil, fmt.Errorf("derive server keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleServer,
		serverID:             serverID,
		serverSecret:         secretClone,
		psk:                  pskClone,
		encKey:               s2c, // server encrypts with s2c bound to serverResponseSecret + serverID
		decKey:               c2s, // server decrypts with c2s
		allowLegacyV2:        false,
		isLegacySingleServer: false,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// AuthorizedServerEntry describes an authorized server for the client-side verification map.
type AuthorizedServerEntry struct {
	ServerID       string
	ResponseSecret []byte // 32-byte server-specific response secret (mandatory)
}

// NewClientAsymmetricSession creates an AsymmetricConn configured as RoleClient for explicit single-server legacy mode.
// For multi-authoritative deployments, use NewClientAsymmetricSessionWithServers.
func NewClientAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	return NewClientLegacyAsymmetricSession(sessionID, psk)
}

// NewClientLegacyAsymmetricSession creates an AsymmetricConn configured as RoleClient for explicit single-server legacy operation.
func NewClientLegacyAsymmetricSession(sessionID uint64, psk []byte) (*AsymmetricConn, error) {
	if len(psk) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}
	pskClone := append([]byte(nil), psk...)
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, err := crypto.DeriveLegacySingleServerTrafficKeys(pskClone, salt)
	if err != nil {
		return nil, fmt.Errorf("derive legacy client keys: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		serverID:             "legacy",
		psk:                  pskClone,
		encKey:               c2s,
		decKey:               s2c,
		authorizedServers:    map[string][]byte{"legacy": pskClone, "default": pskClone},
		allowLegacyV2:        true,
		isLegacySingleServer: true,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// NewClientAsymmetricSessionWithServers creates an AsymmetricConn configured as RoleClient with an explicit,
// nonempty set of authorized server identities and their corresponding dedicated 32-byte response secrets.
// The client will ONLY accept v3 responses from servers in this authorized set. Legacy v2 frames are rejected.
func NewClientAsymmetricSessionWithServers(sessionID uint64, c2sPSK []byte, servers []AuthorizedServerEntry) (*AsymmetricConn, error) {
	if len(servers) == 0 {
		return nil, ErrEmptyServerAllowlist
	}
	if len(c2sPSK) != crypto.KeySize {
		return nil, crypto.ErrInvalidKey
	}

	pskClone := append([]byte(nil), c2sPSK...)
	authMap := make(map[string][]byte)
	for _, s := range servers {
		if s.ServerID == "" {
			return nil, fmt.Errorf("authorized server entry has empty serverID")
		}
		if s.ServerID == "default" || s.ServerID == "legacy" {
			return nil, fmt.Errorf("authorized server cannot use reserved ID %q", s.ServerID)
		}
		if err := ValidateServerID(s.ServerID); err != nil {
			return nil, err
		}
		if len(s.ResponseSecret) == 0 {
			return nil, fmt.Errorf("server %q: %w", s.ServerID, ErrMissingResponseSecret)
		}
		if len(s.ResponseSecret) != crypto.KeySize {
			return nil, fmt.Errorf("server %q: %w", s.ServerID, ErrInvalidResponseSecret)
		}
		if _, dup := authMap[s.ServerID]; dup {
			return nil, fmt.Errorf("duplicate authorized server ID %q (fail-closed)", s.ServerID)
		}
		// Defensive copy of secret slice to prevent caller mutations after construction
		secretClone := append([]byte(nil), s.ResponseSecret...)
		authMap[s.ServerID] = secretClone
	}

	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, _, err := crypto.DeriveServerTrafficKeys(pskClone, servers[0].ResponseSecret, salt, servers[0].ServerID)
	if err != nil {
		return nil, fmt.Errorf("derive client c2s key: %w", err)
	}

	return &AsymmetricConn{
		sessionID:            sessionID,
		role:                 RoleClient,
		psk:                  pskClone,
		encKey:               c2s,
		authorizedServers:    authMap,
		allowLegacyV2:        false,
		isLegacySingleServer: false,
		replay:               replay.NewFilter(30 * time.Second),
	}, nil
}

// sealFrame packs Magic, SessionID, Seq, Ack, and AEAD-encrypted payload into a wire datagram.
func (c *AsymmetricConn) sealFrame(seq, ack uint32, plaintext []byte) ([]byte, error) {
	if seq >= MaxSafeSequenceNumber {
		return nil, ErrSequenceExhausted
	}
	var header []byte
	if c.role == RoleServer {
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
		if !c.allowLegacyV2 {
			return 0, 0, nil, "", ErrLegacyProtocolDisabled
		}
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
	if c.role == RoleClient {
		if magic == AsymmetricMagicV3 {
			if c.isLegacySingleServer {
				// Single-server legacy client decodes using pre-shared key
				decKey = c.decKey
			} else {
				if serverID == "" {
					return 0, 0, nil, "", fmt.Errorf("%w: server response missing server ID", ErrInvalidServerID)
				}
				if err := ValidateServerID(serverID); err != nil {
					return 0, 0, nil, serverID, err
				}
				// Multi-authoritative client policy check: nonempty allowlist required
				if len(c.authorizedServers) == 0 {
					return 0, 0, nil, serverID, ErrEmptyServerAllowlist
				}
				secret, ok := c.authorizedServers[serverID]
				if !ok {
					return 0, 0, nil, serverID, fmt.Errorf("server %q is not authorized by client policy (fail-closed)", serverID)
				}
				if len(secret) != crypto.KeySize {
					return 0, 0, nil, serverID, fmt.Errorf("server %q has invalid response secret length (fail-closed)", serverID)
				}
				salt := []byte(fmt.Sprintf("paqet-asym-%d", c.sessionID))
				sKey, err := crypto.DeriveServerResponseKey(secret, salt, serverID)
				if err != nil {
					return 0, 0, nil, serverID, fmt.Errorf("derive server response key: %w", err)
				}
				decKey = sKey
			}
		} else if magic == AsymmetricMagic {
			// Legacy v2 frame: strictly rejected on multi-server clients
			if !c.allowLegacyV2 || !c.isLegacySingleServer {
				return 0, 0, nil, "", ErrLegacyProtocolDisabled
			}
			decKey = c.decKey
		}
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
