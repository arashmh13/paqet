package transport

import (
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDualAuthoritativeServerCrossServerRetriesAndReplay(t *testing.T) {
	domainSuffix := "tunnel.redundancy.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var serverAInvocations int32
	var serverBInvocations int32

	// 1. Spawn Server A with independent state
	serverA, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&serverAInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SERVER_A_ECHO:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server A failed: %v", err)
	}
	defer serverA.Stop()

	// 2. Spawn Server B with independent state (separate memory, sessions, replay windows)
	serverB, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&serverBInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SERVER_B_ECHO:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Start Server B failed: %v", err)
	}
	defer serverB.Stop()

	sessionID := uint64(0x5555666677778888)
	clientConn, err := NewClientAsymmetricSession(sessionID, psk)
	if err != nil {
		t.Fatalf("NewClientAsymmetricSession failed: %v", err)
	}

	udpAddrA, _ := net.ResolveUDPAddr("udp", serverA.Addr().String())
	udpAddrB, _ := net.ResolveUDPAddr("udp", serverB.Addr().String())

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	// Scenario 1: Request 1 sent to Server A, but client simulates losing the response
	msg1 := &EmergencyMessage{
		ID:        "msg-cross-001",
		Type:      MsgTypeAlert,
		Payload:   []byte("Cross Server Failover Alert"),
		Timestamp: time.Now().Unix(),
	}
	raw1, _ := json.Marshal(msg1)
	frame1, _ := clientConn.sealFrame(1, 0, raw1)

	qname1A := EncodeDNSQName(domainSuffix, "c01", 101, 0, 1, frame1)
	pkt1A := BuildDNSQuery(qname1A, 0x0010, 0x00A1)
	_, _ = conn.WriteToUDP(pkt1A, udpAddrA)

	// Read Server A reply
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server A response failed: %v", err)
	}
	if atomic.LoadInt32(&serverAInvocations) != 1 {
		t.Fatalf("Server A handler should have been invoked 1 time")
	}

	// Scenario 2: Client retransmits the EXACT same request 1 (seq=1) to Server B (failover)
	// Server B has never seen this session before!
	qname1B := EncodeDNSQName(domainSuffix, "c01", 102, 0, 1, frame1)
	pkt1B := BuildDNSQuery(qname1B, 0x0010, 0x00B1)
	_, _ = conn.WriteToUDP(pkt1B, udpAddrB)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server B response failed: %v", err)
	}
	ansB, err := ParseDNSTXTResponse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Server B answer failed: %v", err)
	}
	_, _, ptB, err := clientConn.VerifyFrame(ansB)
	if err != nil {
		t.Fatalf("Verify Server B reply failed: %v", err)
	}
	var respB EmergencyResponse
	_ = json.Unmarshal(ptB, &respB)
	if string(respB.Reply) != "SERVER_B_ECHO:Cross Server Failover Alert" {
		t.Fatalf("Server B reply mismatch: %s", string(respB.Reply))
	}
	if atomic.LoadInt32(&serverBInvocations) != 1 {
		t.Fatalf("Server B handler should have been invoked 1 time")
	}

	// Scenario 3: Attacker replays request 1 to Server B again.
	// Server B has already processed seq=1 and cached its reply!
	// Server B must return the cached reply without second invocation of handler.
	pkt1BReplay := BuildDNSQuery(qname1B, 0x0010, 0x00B2)
	_, _ = conn.WriteToUDP(pkt1BReplay, udpAddrB)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Read Server B replay response failed: %v", err)
	}
	if atomic.LoadInt32(&serverBInvocations) != 1 {
		t.Fatalf("Server B invoked handler on duplicate replay! Expected 1, got %d", atomic.LoadInt32(&serverBInvocations))
	}

	// Scenario 4: Request split across servers (Multipart fragment 0 sent to Server A, fragment 1 sent to Server B)
	// This simulates what happens if a public recursor sprays queries of a multipart message.
	payloadLong := make([]byte, 60)
	for i := range payloadLong {
		payloadLong[i] = byte(i)
	}
	msgMulti := &EmergencyMessage{
		ID:        "msg-multipart-split",
		Type:      MsgTypeData,
		Payload:   payloadLong,
		Timestamp: time.Now().Unix(),
	}
	rawMulti, _ := json.Marshal(msgMulti)
	frameMulti, _ := clientConn.sealFrame(2, 1, rawMulti)

	// Split into 2 chunks of 35 bytes
	chunk0 := frameMulti[:35]
	chunk1 := frameMulti[35:]

	// Part 0 -> Server A
	qnamePart0 := EncodeDNSQName(domainSuffix, "c01", 9001, 0, 2, chunk0)
	pktPart0 := BuildDNSQuery(qnamePart0, 0x0010, 0x9000)
	_, _ = conn.WriteToUDP(pktPart0, udpAddrA)

	// Part 1 -> Server B
	qnamePart1 := EncodeDNSQName(domainSuffix, "c01", 9001, 1, 2, chunk1)
	pktPart1 := BuildDNSQuery(qnamePart1, 0x0010, 0x9001)
	_, _ = conn.WriteToUDP(pktPart1, udpAddrB)

	// Server A should return intermediate empty answer (not complete)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err == nil {
		ansPart0, _ := ParseDNSTXTResponse(buf[:n])
		if len(ansPart0) > 0 {
			t.Fatalf("Server A should NOT have completed reassembly with only Part 0")
		}
	}

	// Server B should return intermediate empty answer (not complete)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err == nil {
		ansPart1, _ := ParseDNSTXTResponse(buf[:n])
		if len(ansPart1) > 0 {
			t.Fatalf("Server B should NOT have completed reassembly with only Part 1")
		}
	}

	// Conclusively proved: Multipart reassembly CANNOT succeed when fragments are split across uncoordinated servers.
	// Only single-query datagrams (total=1) are stateless and naturally resilient across independent server pools!
	_ = n
}
