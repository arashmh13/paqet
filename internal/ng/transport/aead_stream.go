package transport

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"paqet/internal/ng/crypto"
	"paqet/internal/ng/replay"
)

const (
	SaltSize       = 16
	MaxChunkSize   = 16384
	ChunkHeaderLen = 2 // 2-byte uint16 length
)

var (
	ErrHandshakeFailed = errors.New("aead-stream: handshake authentication failed")
	ErrChunkTooLarge   = errors.New("aead-stream: chunk exceeds maximum allowed size")
)

// secureConn wraps a net.Conn with directional AEAD encryption.
type secureConn struct {
	net.Conn
	enc      cipher.AEAD
	dec      cipher.AEAD
	encNonce uint64
	decNonce uint64
	readBuf  []byte
	writeMu  sync.Mutex
	readMu   sync.Mutex
}

func newSecureConn(raw net.Conn, encKey, decKey []byte) (*secureConn, error) {
	enc, err := crypto.NewAEAD(encKey)
	if err != nil {
		return nil, err
	}
	dec, err := crypto.NewAEAD(decKey)
	if err != nil {
		return nil, err
	}
	return &secureConn{
		Conn: raw,
		enc:  enc,
		dec:  dec,
	}, nil
}

func (s *secureConn) makeNonce(counter uint64) [crypto.NonceSize]byte {
	var n [crypto.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func (s *secureConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	totalSent := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > MaxChunkSize {
			chunkSize = MaxChunkSize
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		nonce := s.makeNonce(s.encNonce)
		s.encNonce++

		ciphertext := s.enc.Seal(nil, nonce[:], chunk, nil)
		frameLen := uint16(len(ciphertext))

		var hdr [ChunkHeaderLen]byte
		binary.BigEndian.PutUint16(hdr[:], frameLen)

		if _, err := s.Conn.Write(hdr[:]); err != nil {
			return totalSent, err
		}
		if _, err := s.Conn.Write(ciphertext); err != nil {
			return totalSent, err
		}
		totalSent += chunkSize
	}
	return totalSent, nil
}

func (s *secureConn) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readBuf) > 0 {
		n := copy(b, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	var hdr [ChunkHeaderLen]byte
	if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
		return 0, err
	}

	frameLen := int(binary.BigEndian.Uint16(hdr[:]))
	if frameLen > MaxChunkSize+crypto.TagSize+512 {
		return 0, ErrChunkTooLarge
	}

	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(s.Conn, ciphertext); err != nil {
		return 0, err
	}

	nonce := s.makeNonce(s.decNonce)
	s.decNonce++

	plaintext, err := s.dec.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("aead-stream: %w", crypto.ErrDecrypt)
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		s.readBuf = append(s.readBuf[:0], plaintext[n:]...)
	}
	return n, nil
}

// AEADStreamDialer establishes secure client sessions.
type AEADStreamDialer struct {
	psk    []byte
	maxPad int
}

func NewAEADStreamDialer(psk []byte, maxPad int) *AEADStreamDialer {
	return &AEADStreamDialer{psk: psk, maxPad: maxPad}
}

func (d *AEADStreamDialer) Dial(ctx context.Context, addr string) (Session, error) {
	var netDialer net.Dialer
	rawConn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("aead-stream dial: %w", err)
	}

	// 1. Send random salt
	var salt [SaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}
	if _, err := rawConn.Write(salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}

	// 2. Derive directional keys
	c2sKey, s2cKey, err := crypto.DeriveKeys(d.psk, salt[:])
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	secConn, err := newSecureConn(rawConn, c2sKey, s2cKey)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// 3. Send initial authenticated handshake frame with timestamp and random padding
	padLen := 0
	if d.maxPad > 0 {
		var pb [1]byte
		_, _ = rand.Read(pb[:])
		padLen = int(pb[0]) % d.maxPad
	}

	initFrame := make([]byte, 4+2+padLen)
	binary.BigEndian.PutUint32(initFrame[:4], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(initFrame[4:6], uint16(padLen))
	if padLen > 0 {
		_, _ = rand.Read(initFrame[6:])
	}

	if _, err := secConn.Write(initFrame); err != nil {
		secConn.Close()
		return nil, fmt.Errorf("aead-stream: failed to send handshake: %w", err)
	}

	// 4. Initialize smux multiplexer
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	sess, err := smux.Client(secConn, smuxCfg)
	if err != nil {
		secConn.Close()
		return nil, fmt.Errorf("aead-stream: smux client init: %w", err)
	}

	return &smuxSessionWrapper{sess: sess, underlying: secConn, remote: rawConn.RemoteAddr()}, nil
}

// AEADStreamListener accepts and authenticates inbound sessions.
type AEADStreamListener struct {
	listener net.Listener
	psk      []byte
	filter   *replay.Filter
}

func NewAEADStreamListener(addr string, psk []byte) (*AEADStreamListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &AEADStreamListener{
		listener: l,
		psk:      psk,
		filter:   replay.NewFilter(30 * time.Second),
	}, nil
}

func (l *AEADStreamListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *AEADStreamListener) Close() error {
	return l.listener.Close()
}

func (l *AEADStreamListener) Accept(ctx context.Context) (Session, error) {
	for {
		rawConn, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}

		// Perform handshake with strict timeout (3 seconds)
		rawConn.SetDeadline(time.Now().Add(3 * time.Second))

		var salt [SaltSize]byte
		if _, err := io.ReadFull(rawConn, salt[:]); err != nil {
			rawConn.Close()
			continue
		}

		c2sKey, s2cKey, err := crypto.DeriveKeys(l.psk, salt[:])
		if err != nil {
			rawConn.Close()
			continue
		}

		// Server writes using s2cKey and reads using c2sKey
		secConn, err := newSecureConn(rawConn, s2cKey, c2sKey)
		if err != nil {
			rawConn.Close()
			continue
		}

		// Read and validate initial handshake frame
		initFrame := make([]byte, 512)
		n, err := secConn.Read(initFrame)
		if err != nil || n < 6 {
			// Prober or invalid authentication: terminate immediately
			rawConn.Close()
			continue
		}

		packetUnix := binary.BigEndian.Uint32(initFrame[:4])
		if err := l.filter.CheckTimestamp(packetUnix, time.Now()); err != nil {
			// Stale timestamp or replay: terminate immediately
			rawConn.Close()
			continue
		}

		rawConn.SetDeadline(time.Time{}) // Clear handshake deadline

		smuxCfg := smux.DefaultConfig()
		smuxCfg.Version = 2
		sess, err := smux.Server(secConn, smuxCfg)
		if err != nil {
			secConn.Close()
			continue
		}

		return &smuxSessionWrapper{sess: sess, underlying: secConn, remote: rawConn.RemoteAddr()}, nil
	}
}
