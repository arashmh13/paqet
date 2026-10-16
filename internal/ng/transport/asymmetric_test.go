package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"time"

	"paqet/internal/ng/crypto"
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

func TestAsymmetric_SequenceExhaustionFailsSafely(t *testing.T) {
	sessionID := uint64(0x9988776655443322)
	psk := []byte("test-psk-key-32-bytes-long-12345")

	conn, err := NewServerAsymmetricSessionWithID(sessionID, psk, nil, "srv-de-01")
	if err != nil {
		t.Fatalf("NewServerAsymmetricSessionWithID failed: %v", err)
	}

	// Set sequence counter 2 steps before MaxSafeSequenceNumber
	conn.SetSendSeqForTest(MaxSafeSequenceNumber - 2)

	seq1, err := conn.NextSendSeq()
	if err != nil || seq1 != MaxSafeSequenceNumber-1 {
		t.Fatalf("expected seq1 %d, got %d (err: %v)", MaxSafeSequenceNumber-1, seq1, err)
	}

	// Reaching threshold
	seq2, err := conn.NextSendSeq()
	if err != ErrSequenceExhausted {
		t.Fatalf("expected ErrSequenceExhausted at boundary, got seq %d, err %v", seq2, err)
	}

	// Further attempts MUST continue to fail closed and NEVER wrap around to 0 or 1
	seq3, err := conn.NextSendSeq()
	if err != ErrSequenceExhausted {
		t.Fatalf("expected persistent ErrSequenceExhausted, got seq %d, err %v", seq3, err)
	}
	if conn.sendSeq.Load() == 0 {
		t.Fatalf("CRITICAL SECURITY DEFECT: sequence counter wrapped around to 0!")
	}

	// SealFrame must reject exhausted sequence
	_, err = conn.SealFrame(MaxSafeSequenceNumber, 0, []byte("danger"))
	if err != ErrSequenceExhausted {
		t.Fatalf("SealFrame must fail with ErrSequenceExhausted, got %v", err)
	}
}

func TestAsymmetric_MandatoryNonemptyAllowlist(t *testing.T) {
	sessionID := uint64(0x1122334455667788)
	psk := []byte("test-psk-key-32-bytes-long-12345")

	// Nil allowlist must fail closed
	_, err := NewClientAsymmetricSessionWithServers(sessionID, psk, nil)
	if err != ErrEmptyServerAllowlist {
		t.Fatalf("expected ErrEmptyServerAllowlist for nil servers, got: %v", err)
	}

	// Empty slice must fail closed
	_, err = NewClientAsymmetricSessionWithServers(sessionID, psk, []AuthorizedServerEntry{})
	if err != ErrEmptyServerAllowlist {
		t.Fatalf("expected ErrEmptyServerAllowlist for empty servers, got: %v", err)
	}

	// Duplicate server ID in allowlist must fail closed
	_, err = NewClientAsymmetricSessionWithServers(sessionID, psk, []AuthorizedServerEntry{
		{ServerID: "srv-de-01", ResponseSecret: []byte("secret1")},
		{ServerID: "srv-de-01", ResponseSecret: []byte("secret2")},
	})
	if err == nil {
		t.Fatalf("expected error on duplicate server ID in allowlist, got nil")
	}
}

func TestAsymmetric_DistinctServerSecretsPreventImpersonation(t *testing.T) {
	sessionID := uint64(0xAABBCCDDEEFF0011)
	sharedPSK := []byte("shared-c2s-psk-32-bytes-long-123")
	secretA := []byte("server-a-response-secret-1111111")
	secretB := []byte("server-b-response-secret-2222222")

	// Server A with secretA
	serverA, err := NewServerAsymmetricSessionWithID(sessionID, sharedPSK, secretA, "srv-de-01")
	if err != nil {
		t.Fatalf("NewServerAsymmetricSessionWithID A failed: %v", err)
	}

	// Server B with secretB
	serverB, err := NewServerAsymmetricSessionWithID(sessionID, sharedPSK, secretB, "srv-nl-01")
	if err != nil {
		t.Fatalf("NewServerAsymmetricSessionWithID B failed: %v", err)
	}

	// Client configured with both servers
	client, err := NewClientAsymmetricSessionWithServers(sessionID, sharedPSK, []AuthorizedServerEntry{
		{ServerID: "srv-de-01", ResponseSecret: secretA},
		{ServerID: "srv-nl-01", ResponseSecret: secretB},
	})
	if err != nil {
		t.Fatalf("NewClientAsymmetricSessionWithServers failed: %v", err)
	}

	// 1. Legitimate response from Server A
	payloadA := []byte("Genuine response from Server A")
	frameA, err := serverA.SealFrame(1, 0, payloadA)
	if err != nil {
		t.Fatalf("serverA SealFrame failed: %v", err)
	}

	seq, ack, decA, srvIDA, err := client.VerifyFrameWithServerID(frameA)
	if err != nil {
		t.Fatalf("client failed to verify genuine frame from Server A: %v", err)
	}
	if srvIDA != "srv-de-01" || string(decA) != string(payloadA) || seq != 1 || ack != 0 {
		t.Fatalf("verified frame A mismatch: srv=%s, dec=%s", srvIDA, decA)
	}

	// 2. Legitimate response from Server B
	payloadB := []byte("Genuine response from Server B")
	frameB, err := serverB.SealFrame(1, 0, payloadB)
	if err != nil {
		t.Fatalf("serverB SealFrame failed: %v", err)
	}

	_, _, decB, srvIDB, err := client.VerifyFrameWithServerID(frameB)
	if err != nil {
		t.Fatalf("client failed to verify genuine frame from Server B: %v", err)
	}
	if srvIDB != "srv-nl-01" || string(decB) != string(payloadB) {
		t.Fatalf("verified frame B mismatch: srv=%s, dec=%s", srvIDB, decB)
	}

	// 3. ADVERSARIAL IMPERSONATION:
	// Server A (holding secretA and sharedPSK) attempts to craft a response claiming Server B's ID ("srv-nl-01").
	// Server A only has secretA, so it creates a server session with srv-nl-01 but using secretA:
	maliciousServerA, err := NewServerAsymmetricSessionWithID(sessionID, sharedPSK, secretA, "srv-nl-01")
	if err != nil {
		t.Fatalf("malicious server creation: %v", err)
	}
	forgedFrame, err := maliciousServerA.SealFrame(2, 0, []byte("Forged payload from A pretending to be B"))
	if err != nil {
		t.Fatalf("SealFrame forged failed: %v", err)
	}

	// Client verifying forgedFrame MUST FAIL AEAD tag verification because client uses secretB for srv-nl-01!
	_, _, _, _, err = client.VerifyFrameWithServerID(forgedFrame)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY DEFECT: Client accepted forged frame from Server A claiming Server B's identity!")
	}
	t.Logf("Impersonation safely rejected fail-closed: %v", err)
}

func TestAsymmetric_LegacyV2FramesRejectedByDefault(t *testing.T) {
	sessionID := uint64(0x4455667788990011)
	psk := []byte("test-psk-key-32-bytes-long-12345")

	client, err := NewClientAsymmetricSessionWithServers(sessionID, psk, []AuthorizedServerEntry{
		{ServerID: "srv-de-01", ResponseSecret: psk},
	})
	if err != nil {
		t.Fatalf("NewClientAsymmetricSessionWithServers failed: %v", err)
	}

	// Craft a legacy v2 frame (magic 0x50415141)
	legacyConn, err := NewServerAsymmetricSession(sessionID, psk)
	if err != nil {
		t.Fatalf("NewServerAsymmetricSession failed: %v", err)
	}
	salt := []byte(fmt.Sprintf("paqet-asym-%d", sessionID))
	c2s, s2c, _ := crypto.DeriveKeys(psk, salt)
	_ = c2s

	// Header for v2: Magic(4) + SessID(8) + Seq(4) + Ack(4) = 20
	hdr := make([]byte, AsymmetricHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], AsymmetricMagic)
	binary.BigEndian.PutUint64(hdr[4:12], sessionID)
	binary.BigEndian.PutUint32(hdr[12:16], 1)
	binary.BigEndian.PutUint32(hdr[16:20], 0)

	nonce := make([]byte, crypto.NonceSize)
	binary.BigEndian.PutUint64(nonce[0:8], sessionID)
	binary.BigEndian.PutUint32(nonce[8:12], 1)
	nonce[0] ^= byte(RoleServer)

	aead, _ := crypto.NewAEAD(s2c)
	ct := aead.Seal(nil, nonce, []byte("legacy payload"), hdr)
	v2Frame := append(hdr, ct...)

	_ = legacyConn

	// Verification on v3 client MUST fail with ErrLegacyProtocolDisabled
	_, _, _, _, err = client.VerifyFrameWithServerID(v2Frame)
	if err != ErrLegacyProtocolDisabled {
		t.Fatalf("expected ErrLegacyProtocolDisabled for v2 frame, got: %v", err)
	}

	// Explicitly enable legacy support for test
	client.SetAllowLegacyV2ForTest(true)
	// Without "legacy" or "default" in allowlist, still rejected
	_, _, _, _, err = client.VerifyFrameWithServerID(v2Frame)
	if err == nil {
		t.Fatalf("expected error when legacy is not in allowlist, got nil")
	}
}

func TestAsymmetric_ServerIDValidation(t *testing.T) {
	validIDs := []string{"ns-de-01", "ns2-nl-01", "srv_01.primary", "node-1"}
	for _, id := range validIDs {
		if err := ValidateServerID(id); err != nil {
			t.Errorf("expected valid ID %q, got err: %v", id, err)
		}
	}

	invalidIDs := []string{"", "a", "ab", "UPPERCASE", "with space", "bad@char", "very-long-id-that-exceeds-sixty-four-characters-limit-which-is-strictly-invalid-and-must-fail"}
	for _, id := range invalidIDs {
		if err := ValidateServerID(id); err == nil {
			t.Errorf("expected invalid ID %q to fail validation, got nil", id)
		}
	}
}

func TestAsymmetric_TamperedServerIDInAADFails(t *testing.T) {
	sessionID := uint64(0x778899AABBCCDDEE)
	psk := []byte("test-psk-key-32-bytes-long-12345")
	secretA := []byte("secret-a-32-bytes-long-123456789")

	server, err := NewServerAsymmetricSessionWithID(sessionID, psk, secretA, "srv-de-01")
	if err != nil {
		t.Fatalf("NewServerAsymmetricSessionWithID failed: %v", err)
	}

	client, err := NewClientAsymmetricSessionWithServers(sessionID, psk, []AuthorizedServerEntry{
		{ServerID: "srv-de-01", ResponseSecret: secretA},
		{ServerID: "srv-de-02", ResponseSecret: secretA},
	})
	if err != nil {
		t.Fatalf("NewClientAsymmetricSessionWithServers failed: %v", err)
	}

	frame, err := server.SealFrame(1, 0, []byte("tamper test"))
	if err != nil {
		t.Fatalf("SealFrame failed: %v", err)
	}

	// Tamper with the last character of ServerID in the wire frame (from '1' to '2')
	// Wire frame header: Magic(4) + Sess(8) + Seq(4) + Ack(4) + SrvLen(1) + "srv-de-01"(9)
	srvIDEndIdx := 21 + 9 - 1
	tamperedFrame := make([]byte, len(frame))
	copy(tamperedFrame, frame)
	tamperedFrame[srvIDEndIdx] = '2' // Changes "srv-de-01" to "srv-de-02"

	// Even though srv-de-02 is in the client's allowlist, AEAD verification MUST fail because
	// ServerID was authenticated as AAD during Seal!
	_, _, _, _, err = client.VerifyFrameWithServerID(tamperedFrame)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY DEFECT: Tampered ServerID in AAD passed AEAD verification!")
	}
	t.Logf("Tampered ServerID correctly failed AEAD verification: %v", err)
}
