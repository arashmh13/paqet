package transport

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// mockAddr implements net.Addr for testing.
type mockAddr string

func (m mockAddr) Network() string { return "mock" }
func (m mockAddr) String() string  { return string(m) }

func TestAsymmetricConnEndToEndReassembly(t *testing.T) {
	sessionID := uint64(0x1234567890ABCDEF)
	psk := []byte("test-psk-key-32-bytes-long-12345")

	// Upstream and Downstream simulated FIFO channels
	upCh := make(chan []byte, 100)
	downCh := make(chan []byte, 100)

	clientSender := NewMemoryPipeSender(upCh)
	clientReceiver := NewMemoryPipeReceiver(downCh)

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		64, // small MTU to force multiple chunks
		clientSender,
		clientReceiver,
		mockAddr("client-local"),
		mockAddr("server-remote"),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn failed: %v", err)
	}
	defer clientConn.Close()

	// Server-side representation
	c2s, s2c, err := clientConn.encKey, clientConn.decKey, error(nil)
	_ = c2s
	_ = s2c

	// Test 1: Client writes large message, verify chunking
	msg := []byte("Hello Asymmetric World! This message exceeds small MTU and must be fragmented into several chunks.")
	go func() {
		n, err := clientConn.Write(msg)
		if err != nil {
			t.Errorf("clientConn.Write failed: %v", err)
		}
		if n != len(msg) {
			t.Errorf("clientConn.Write short write: got %d, want %d", n, len(msg))
		}
	}()

	// Server reads fragments from upCh
	var receivedUpstream [][]byte
	timer := time.After(2 * time.Second)
	for len(receivedUpstream) < 2 {
		select {
		case frame := <-upCh:
			receivedUpstream = append(receivedUpstream, frame)
		case <-timer:
			t.Fatalf("Timeout waiting for upstream frames, got %d", len(receivedUpstream))
		}
	}

	if len(receivedUpstream) < 2 {
		t.Fatalf("Expected at least 2 chunks, got %d", len(receivedUpstream))
	}

	// Test 2: Downstream reordering test
	// Server crafts 2 downstream responses with Seq 1 and Seq 2, but delivers Seq 2 FIRST, then Seq 1!
	replyPart1 := []byte("Part1-Data-")
	replyPart2 := []byte("Part2-Data-Complete!")

	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey, // server encrypts with s2c
		decKey:    clientConn.encKey, // server decrypts with c2s
	}

	frame1, err := serverConn.sealFrame(1, 1, replyPart1)
	if err != nil {
		t.Fatalf("sealFrame 1 failed: %v", err)
	}
	frame2, err := serverConn.sealFrame(2, 1, replyPart2)
	if err != nil {
		t.Fatalf("sealFrame 2 failed: %v", err)
	}

	// Inject OUT OF ORDER: frame2 first, then frame1
	downCh <- frame2
	time.Sleep(20 * time.Millisecond) // small delay to ensure frame2 sits in reorder buffer
	downCh <- frame1

	// Client Read() MUST return in-order: replyPart1 followed by replyPart2!
	buf := make([]byte, len(replyPart1)+len(replyPart2))
	_, err = io.ReadFull(clientConn, buf)
	if err != nil {
		t.Fatalf("clientConn.Read failed: %v", err)
	}

	expected := append(replyPart1, replyPart2...)
	if !bytes.Equal(buf, expected) {
		t.Fatalf("Reordered output mismatch: got %q, want %q", buf, expected)
	}
}

func TestAsymmetricReplayAndTamperRejection(t *testing.T) {
	sessionID := uint64(999999)
	psk := []byte("secret-key-32-bytes-super-safe!")

	upCh := make(chan []byte, 10)
	downCh := make(chan []byte, 10)

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		1024,
		NewMemoryPipeSender(upCh),
		NewMemoryPipeReceiver(downCh),
		mockAddr("client"),
		mockAddr("server"),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn: %v", err)
	}
	defer clientConn.Close()

	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey,
		decKey:    clientConn.encKey,
	}

	// 1. Valid frame
	frame1, err := serverConn.sealFrame(1, 1, []byte("Original Payload"))
	if err != nil {
		t.Fatalf("sealFrame: %v", err)
	}

	// 2. Tampered frame (modify ciphertext byte)
	tamperedFrame := append([]byte(nil), frame1...)
	tamperedFrame[len(tamperedFrame)-1] ^= 0xFF

	downCh <- tamperedFrame
	// Tampered frame must be discarded silently by recvLoop

	// Send valid frame1
	downCh <- frame1

	buf := make([]byte, len("Original Payload"))
	_, err = io.ReadFull(clientConn, buf)
	if err != nil {
		t.Fatalf("Read valid frame: %v", err)
	}
	if string(buf) != "Original Payload" {
		t.Fatalf("Unexpected content: %s", buf)
	}

	// Replay frame1 again -> Must be rejected by replay filter
	downCh <- frame1

	// Ensure replay was dropped: send frame2 and read it
	frame2, _ := serverConn.sealFrame(2, 1, []byte("Second Payload"))
	downCh <- frame2

	buf2 := make([]byte, len("Second Payload"))
	_, err = io.ReadFull(clientConn, buf2)
	if err != nil {
		t.Fatalf("Read frame2 failed: %v", err)
	}
	if string(buf2) != "Second Payload" {
		t.Fatalf("Unexpected content for frame2: %s", buf2)
	}
}

func TestAsymmetricHeaderTamperingRejection(t *testing.T) {
	sessionID := uint64(0x1122334455667788)
	psk := []byte("secret-key-32-bytes-tamper-test!")

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		1024,
		NewMemoryPipeSender(make(chan []byte, 10)),
		NewMemoryPipeReceiver(make(chan []byte, 10)),
		mockAddr("client"),
		mockAddr("server"),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn: %v", err)
	}
	defer clientConn.Close()

	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey,
		decKey:    clientConn.encKey,
	}

	validFrame, err := serverConn.sealFrame(1, 100, []byte("Secure Payload"))
	if err != nil {
		t.Fatalf("sealFrame failed: %v", err)
	}

	// 1. Verify valid frame parses
	_, _, _, err = clientConn.openFrame(validFrame)
	if err != nil {
		t.Fatalf("openFrame failed on valid frame: %v", err)
	}

	// 2. Tamper Magic (bytes 0..3)
	badMagic := append([]byte(nil), validFrame...)
	badMagic[0] ^= 0x01
	if _, _, _, err := clientConn.openFrame(badMagic); err != ErrAsymmetricInvalidMagic {
		t.Errorf("Expected ErrAsymmetricInvalidMagic, got %v", err)
	}

	// 3. Tamper SessionID (bytes 4..11)
	badSess := append([]byte(nil), validFrame...)
	badSess[5] ^= 0x01
	if _, _, _, err := clientConn.openFrame(badSess); err == nil {
		t.Errorf("Expected openFrame to fail on tampered session ID")
	}

	// 4. Tamper Seq (bytes 12..15) - Must fail AEAD AAD authentication!
	badSeq := append([]byte(nil), validFrame...)
	badSeq[15] ^= 0x01
	if _, _, _, err := clientConn.openFrame(badSeq); err == nil {
		t.Errorf("Expected openFrame to fail on tampered sequence number")
	}

	// 5. Tamper Ack (bytes 16..19) - Must fail AEAD AAD authentication!
	badAck := append([]byte(nil), validFrame...)
	badAck[19] ^= 0x01
	if _, _, _, err := clientConn.openFrame(badAck); err == nil {
		t.Errorf("Expected openFrame to fail on tampered ACK number")
	}
}

func TestAsymmetricSequenceExhaustion(t *testing.T) {
	sessionID := uint64(12345)
	psk := []byte("secret-key-32-bytes-exhaust-tst!")

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		1024,
		NewMemoryPipeSender(make(chan []byte, 10)),
		NewMemoryPipeReceiver(make(chan []byte, 10)),
		mockAddr("client"),
		mockAddr("server"),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn: %v", err)
	}
	defer clientConn.Close()

	// Simulate sequence reaching the maximum 32-bit threshold
	clientConn.sendSeq.Store(0xFFFFFFFE)

	_, err = clientConn.Write([]byte("Data that should be rejected due to exhaustion"))
	if err != ErrSequenceExhausted {
		t.Fatalf("Expected ErrSequenceExhausted, got %v", err)
	}
}

func TestAsymmetricLossAndAutomaticRetransmission(t *testing.T) {
	sessionID := uint64(0x99887766)
	psk := []byte("secret-key-32-bytes-loss-test!!")

	upCh := make(chan []byte, 20)
	downCh := make(chan []byte, 20)

	clientConn, err := NewClientAsymmetricConn(
		sessionID,
		psk,
		1024,
		NewMemoryPipeSender(upCh),
		NewMemoryPipeReceiver(downCh),
		mockAddr("client"),
		mockAddr("server"),
	)
	if err != nil {
		t.Fatalf("NewClientAsymmetricConn: %v", err)
	}
	defer clientConn.Close()

	// Configure small RTO for testing
	clientConn.SetRTO(100 * time.Millisecond)

	serverConn := &AsymmetricConn{
		sessionID: sessionID,
		role:      RoleServer,
		encKey:    clientConn.decKey,
		decKey:    clientConn.encKey,
	}

	// Client writes message
	go func() {
		_, _ = clientConn.Write([]byte("Crucial Data"))
	}()

	// 1. Read first frame from upCh and DROP IT (simulate packet loss)!
	select {
	case droppedFrame := <-upCh:
		t.Logf("Simulating loss: dropped frame of len %d", len(droppedFrame))
	case <-time.After(1 * time.Second):
		t.Fatalf("Timeout waiting for original frame")
	}

	// 2. Retransmission loop should re-emit the frame within ~100-200ms!
	var retransmittedFrame []byte
	select {
	case retransmittedFrame = <-upCh:
		t.Logf("Successfully captured retransmitted frame of len %d", len(retransmittedFrame))
	case <-time.After(1 * time.Second):
		t.Fatalf("Timeout waiting for retransmission")
	}

	// Server opens retransmitted frame
	seq, _, payload, err := serverConn.openFrame(retransmittedFrame)
	if err != nil {
		t.Fatalf("Server openFrame on retransmitted frame failed: %v", err)
	}
	if string(payload) != "Crucial Data" {
		t.Fatalf("Payload mismatch: got %s, want Crucial Data", payload)
	}

	// Server sends ACK back
	ackFrame, err := serverConn.sealFrame(1, seq, nil)
	if err != nil {
		t.Fatalf("sealFrame ACK failed: %v", err)
	}
	downCh <- ackFrame

	// Give client a moment to process ACK and prune unacked buffer
	time.Sleep(50 * time.Millisecond)

	clientConn.unackedMu.Lock()
	unackedLen := len(clientConn.unacked)
	clientConn.unackedMu.Unlock()

	if unackedLen != 0 {
		t.Errorf("Expected unacked buffer to be empty after ACK, got %d items", unackedLen)
	}
}
