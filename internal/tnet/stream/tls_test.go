package stream

import (
	"bytes"
	"crypto/tls"
	"io"
	"testing"

	"paqet/internal/conf"
)

func TestGenuineTLSOuterTransportEndToEnd(t *testing.T) {
	tlsCfg := &conf.TLS{
		Enabled:            true,
		ServerName:         "cloudflare.com",
		InsecureSkipVerify: true,
		MinVersion:         "1.3",
		ALPN:               []string{"h2", "http/1.1"},
	}

	listener, err := ListenTLS("127.0.0.1:0", nil, tlsCfg)
	if err != nil {
		t.Fatalf("ListenTLS failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		strm, err := conn.AcceptStrm()
		if err != nil {
			errCh <- err
			return
		}
		defer strm.Close()

		buf := make([]byte, 1024)
		n, err := strm.Read(buf)
		if err != nil && err != io.EOF {
			errCh <- err
			return
		}
		_, err = strm.Write(buf[:n])
		errCh <- err
	}()

	clientConn, err := DialTLS(addr, nil, tlsCfg)
	if err != nil {
		t.Fatalf("DialTLS failed: %v", err)
	}
	defer clientConn.Close()

	// Verify that the underlying connection is an authentic *tls.Conn
	tlsStreamConn, ok := clientConn.(*Conn)
	if !ok {
		t.Fatalf("clientConn is not *Conn")
	}
	realTLSConn, ok := tlsStreamConn.underlying.(*tls.Conn)
	if !ok {
		t.Fatalf("underlying is not *tls.Conn")
	}

	state := realTLSConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Errorf("Expected TLS 1.3 (0x%04x), got 0x%04x", tls.VersionTLS13, state.Version)
	}
	if !state.HandshakeComplete {
		t.Errorf("Expected HandshakeComplete=true")
	}
	if state.ServerName != "cloudflare.com" {
		t.Errorf("Expected ServerName 'cloudflare.com', got %q", state.ServerName)
	}

	// Test stream data exchange over genuine TLS
	strm, err := clientConn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm failed: %v", err)
	}
	defer strm.Close()

	msg := []byte("Testing Authentic TLS 1.3 Outer Transport in Paqet-NG")
	if _, err := strm.Write(msg); err != nil {
		t.Fatalf("strm.Write failed: %v", err)
	}

	reply := make([]byte, 1024)
	n, err := strm.Read(reply)
	if err != nil {
		t.Fatalf("strm.Read failed: %v", err)
	}

	if !bytes.Equal(reply[:n], msg) {
		t.Fatalf("reply mismatch: got %q, want %q", reply[:n], msg)
	}

	if err := <-errCh; err != nil && err != io.EOF {
		t.Fatalf("Server error: %v", err)
	}
}
