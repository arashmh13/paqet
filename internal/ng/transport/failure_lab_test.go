package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestFailureLab_DestinationPortBlockedFallback simulates a firewall blocking port A,
// verifying that StrategySelector automatically falls back to port B without user intervention.
func TestFailureLab_DestinationPortBlockedFallback(t *testing.T) {
	psk := []byte("failure-lab-psk-32-bytes-long!")

	// 1. Create working AEAD listener on Port B
	listenerB, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("NewAEADStreamListener B failed: %v", err)
	}
	defer listenerB.Close()
	addrB := listenerB.Addr().String()

	// Server on Port B echoes data
	go func() {
		for {
			sess, err := listenerB.Accept(context.Background())
			if err != nil {
				return
			}
			go func(s Session) {
				defer s.Close()
				strm, err := s.AcceptStream()
				if err != nil {
					return
				}
				defer strm.Close()
				_, _ = io.Copy(strm, strm)
			}(sess)
		}
	}()

	// 2. Closed port A (simulating firewall blackhole/drop)
	dummyL, _ := net.Listen("tcp", "127.0.0.1:0")
	addrA := dummyL.Addr().String()
	dummyL.Close() // immediately closed

	stratA := NewAEADStreamDialer(psk, 64) // points to blocked addrA
	stratB := NewAEADStreamDialer(psk, 64) // points to working addrB

	// Create selector with stratA as preferred
	selector := NewStrategySelector(SelectorConfig{
		Candidates:          []Strategy{stratA, stratB},
		PreferredMode:       ModeAEADStream,
		CircuitFailureLimit: 1,
		CircuitCooldown:     5 * time.Second,
	})

	// Wrap stratA to dial addrA and stratB to dial addrB
	mockStratA := &targetDialer{Strategy: stratA, targetAddr: addrA}
	mockStratB := &targetDialer{Strategy: stratB, targetAddr: addrB}

	selector.cfg.Candidates = []Strategy{mockStratA, mockStratB}
	selector.current = mockStratA

	// Dial through selector: should fail on A and succeed on B
	sess, err := selector.Dial(context.Background(), addrA)
	if err != nil {
		t.Fatalf("Selector failed to fall back when port A was blocked: %v", err)
	}
	defer sess.Close()

	if selector.Current() != mockStratB {
		t.Errorf("Expected active strategy to switch to mockStratB")
	}

	report := selector.StatusReport()
	if report["last_success_mode"] != string(ModeAEADStream) {
		t.Errorf("Expected last_success_mode to be recorded")
	}
}

// targetDialer overrides the dial address for testing distinct ports.
type targetDialer struct {
	Strategy
	targetAddr string
}

func (t *targetDialer) Dial(ctx context.Context, addr string) (Session, error) {
	return t.Strategy.Dial(ctx, t.targetAddr)
}

func (t *targetDialer) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	return t.Strategy.CheckHealth(ctx, t.targetAddr)
}

// TestFailureLab_IdleConnectionResume verifies that an established session maintains
// cryptographic stream sync even after periods of silence.
func TestFailureLab_IdleConnectionResume(t *testing.T) {
	psk := []byte("failure-lab-idle-psk-32-bytes!")

	listener, err := NewAEADStreamListener("127.0.0.1:0", psk)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer sess.Close()
		strm, err := sess.AcceptStream()
		if err != nil {
			return
		}
		defer strm.Close()

		// Read burst 1
		b1 := make([]byte, 5)
		_, _ = io.ReadFull(strm, b1)
		_, _ = strm.Write(b1)

		// Wait for idle period
		time.Sleep(300 * time.Millisecond)

		// Read burst 2
		b2 := make([]byte, 5)
		_, _ = io.ReadFull(strm, b2)
		_, _ = strm.Write(b2)
	}()

	dialer := NewAEADStreamDialer(psk, 64)
	sess, err := dialer.Dial(context.Background(), listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer sess.Close()

	strm, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer strm.Close()

	// Send burst 1
	if _, err := strm.Write([]byte("PING1")); err != nil {
		t.Fatalf("Write burst 1 failed: %v", err)
	}
	resp1 := make([]byte, 5)
	if _, err := io.ReadFull(strm, resp1); err != nil {
		t.Fatalf("Read burst 1 failed: %v", err)
	}
	if string(resp1) != "PING1" {
		t.Fatalf("Burst 1 mismatch: %s", resp1)
	}

	// Idle wait
	time.Sleep(300 * time.Millisecond)

	// Send burst 2 after idle
	if _, err := strm.Write([]byte("PING2")); err != nil {
		t.Fatalf("Write burst 2 failed: %v", err)
	}
	resp2 := make([]byte, 5)
	if _, err := io.ReadFull(strm, resp2); err != nil {
		t.Fatalf("Read burst 2 failed: %v", err)
	}
	if string(resp2) != "PING2" {
		t.Fatalf("Burst 2 mismatch: %s", resp2)
	}
}

// TestFailureLab_AsymmetricCurfewSimulation simulates complete outbound TCP blockage
// where only an asymmetric channel (e.g. DNS upstream + UDP downstream) functions.
func TestFailureLab_AsymmetricCurfewSimulation(t *testing.T) {
	sessionID := uint64(0xABCDEF0123456789)
	psk := []byte("asym-curfew-lab-psk-32-bytes-ok!")

	upCh := make(chan []byte, 50)
	downCh := make(chan []byte, 50)

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		128,
		NewMemoryPipeSender(upCh),
		NewMemoryPipeReceiver(downCh),
		mockAddr("iran-client-nin"),
		mockAddr("germany-vps-edge"),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn: %v", err)
	}
	defer clientConn.Close()

	// Server echo responder operating over decoupled pipes
	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey,
		decKey:    clientConn.encKey,
	}

	// Echo server loop
	go func() {
		for frame := range upCh {
			seq, _, payload, err := serverConn.openFrame(frame)
			if err != nil {
				continue
			}
			// Echo back payload with matching seq over downstream
			replyFrame, err := serverConn.sealFrame(seq, seq, payload)
			if err == nil {
				downCh <- replyFrame
			}
		}
	}()

	// Send data through client asymmetric connection
	testMsg := []byte("SURVIVAL MESSAGE DURING NATIONAL FIREWALL OUTAGE")
	go func() {
		_, _ = clientConn.Write(testMsg)
	}()

	recvBuf := make([]byte, len(testMsg))
	_, err = io.ReadFull(clientConn, recvBuf)
	if err != nil {
		t.Fatalf("Failed to read over asymmetric curfew channel: %v", err)
	}

	if !bytes.Equal(recvBuf, testMsg) {
		t.Fatalf("Message mismatch: got %q, want %q", recvBuf, testMsg)
	}
}
