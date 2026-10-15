package stream

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"

	"paqet/internal/conf"
	"paqet/internal/ng/crypto"
	"paqet/internal/ng/transport"
	"paqet/internal/tnet"
)

func Dial(addr string, obfsCfg *conf.Obfs) (tnet.Conn, error) {
	key := []byte(obfsCfg.Key)
	if len(key) == 0 {
		return nil, fmt.Errorf("stream: encryption key is required")
	}

	maxPad := obfsCfg.MaxPad
	if maxPad <= 0 {
		maxPad = 64
	}

	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("stream: failed to dial %s: %w", addr, err)
	}

	// 1. Send random salt
	var salt [transport.SaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}
	if _, err := rawConn.Write(salt[:]); err != nil {
		rawConn.Close()
		return nil, err
	}

	// 2. Derive directional keys
	c2sKey, s2cKey, err := crypto.DeriveKeys(key, salt[:])
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	enc, err := crypto.NewAEAD(c2sKey)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	dec, err := crypto.NewAEAD(s2cKey)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	secConn := &secureStreamConn{
		Conn: rawConn,
		enc:  enc,
		dec:  dec,
	}

	// 3. Send initial handshake with timestamp and random padding
	padLen := 0
	if maxPad > 0 {
		var pb [1]byte
		_, _ = rand.Read(pb[:])
		padLen = int(pb[0]) % maxPad
	}

	initFrame := make([]byte, 4+2+padLen)
	binary.BigEndian.PutUint32(initFrame[:4], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint16(initFrame[4:6], uint16(padLen))
	if padLen > 0 {
		_, _ = rand.Read(initFrame[6:])
	}

	if _, err := secConn.Write(initFrame); err != nil {
		secConn.Close()
		return nil, fmt.Errorf("stream: handshake failed: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	sess, err := smux.Client(secConn, smuxCfg)
	if err != nil {
		secConn.Close()
		return nil, fmt.Errorf("stream: smux client init: %w", err)
	}

	return &Conn{
		underlying: secConn,
		session:    sess,
		rawConn:    rawConn,
	}, nil
}
