package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"paqet/internal/ng/dns"
)

func TestEmergencyDNSRoundTripSmallAndFragmented(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	// 1. Start Emergency DNS Server on loopback port
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("SERVER_ECHO:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()

	// 2. Initialize Emergency DNS Client
	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr: serverAddr,
		DomainSuffix: domainSuffix,
		ClientID:     "c99",
		PSK:          psk,
		SessionID:    0x123456789ABCDEF0,
		Timeout:      2 * time.Second,
		MaxRetries:   2,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	ctx := context.Background()

	// Case A: Small single-part payload (20 bytes)
	msgSmall := &EmergencyMessage{
		ID:        "test-small-001",
		Type:      "ping",
		Payload:   []byte("Short Emergency Text"),
		Timestamp: time.Now().Unix(),
	}

	respSmall, rttSmall, err := client.Exchange(ctx, msgSmall)
	if err != nil {
		t.Fatalf("Case A Exchange failed: %v", err)
	}
	if respSmall.ID != msgSmall.ID {
		t.Fatalf("Case A ID mismatch: got %s, want %s", respSmall.ID, msgSmall.ID)
	}
	if string(respSmall.Reply) != "SERVER_ECHO:Short Emergency Text" {
		t.Fatalf("Case A Reply mismatch: got %s", respSmall.Reply)
	}
	t.Logf("Case A (Small) succeeded in %v", rttSmall)

	// Case B: Large multipart payload requiring 4 fragments (120 bytes)
	randBytes := make([]byte, 120)
	_, _ = io.ReadFull(rand.Reader, randBytes)

	msgLarge := &EmergencyMessage{
		ID:        "test-large-002",
		Type:      "data",
		Payload:   randBytes,
		Timestamp: time.Now().Unix(),
	}

	respLarge, rttLarge, err := client.Exchange(ctx, msgLarge)
	if err != nil {
		t.Fatalf("Case B Multipart Exchange failed: %v", err)
	}
	if respLarge.ID != msgLarge.ID {
		t.Fatalf("Case B ID mismatch: got %s, want %s", respLarge.ID, msgLarge.ID)
	}
	expectedLargeReply := append([]byte("SERVER_ECHO:"), randBytes...)
	if !bytes.Equal(respLarge.Reply, expectedLargeReply) {
		t.Fatalf("Case B Multipart Reply bytes mismatch")
	}
	t.Logf("Case B (Large Multipart) succeeded in %v", rttLarge)
}

func TestEmergencyDNSServerSecurityAndRefused(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()

	// 1. Query for domain outside domainSuffix (e.g. google.com) -> Must be REFUSED (RCODE 5)
	host, portStr, _ := net.SplitHostPort(serverAddr)
	port, _ := strconv.Atoi(portStr)
	resp, _, err := dns.SendQuery(context.Background(), host, port, "google.com", dns.TypeA, 0, 1*time.Second)
	if err == nil && len(resp) >= 4 {
		rcode := resp[3] & 0x0F
		if rcode != 5 {
			t.Errorf("Expected RCODE=5 REFUSED for query outside domainSuffix, got %d", rcode)
		}
	}

	// 2. Client with wrong PSK dialing server -> Must fail authentication
	badClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr: serverAddr,
		DomainSuffix: domainSuffix,
		ClientID:     "c99",
		PSK:          []byte("WRONG-KEY-32-BYTES-MUST-NOT-WORK"),
		SessionID:    0x99999999,
		Timeout:      1 * time.Second,
		MaxRetries:   0,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	msg := &EmergencyMessage{
		ID:        "test-bad-key",
		Type:      "ping",
		Payload:   []byte("Should be rejected"),
		Timestamp: time.Now().Unix(),
	}

	_, _, err = badClient.Exchange(context.Background(), msg)
	if err == nil {
		t.Errorf("Expected exchange with wrong PSK to fail, but succeeded")
	}
}

func TestUnauthenticatedSessionIDMemoryExhaustionProtection(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	srvUDP, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	// Send 50 queries with completely fabricated random session IDs and corrupted AEAD tags
	for i := 0; i < 50; i++ {
		fakeSessionID := uint64(0x2AAA000000000000) + uint64(i)
		fakeChunk := make([]byte, 35)
		// Embed fake session ID into chunk
		for b := 0; b < 8; b++ {
			fakeChunk[4+b] = byte(fakeSessionID >> (56 - b*8))
		}
		qname := EncodeDNSQName(domainSuffix, "c01", uint64(i+1), 0, 1, fakeChunk)
		pkt := BuildDNSQuery(qname, 0x0010 /* TXT */, uint16(i+1))
		_, _ = conn.WriteToUDP(pkt, srvUDP)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify that ZERO unauthenticated sessions were persisted in server memory!
	activeSessions := server.ActiveSessionsCount()
	if activeSessions != 0 {
		t.Fatalf("Memory exhaustion vulnerability detected! Expected 0 active sessions, got %d", activeSessions)
	}
}

func TestIdempotentDuplicateRetransmission(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	var handlerInvocations int32
	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			atomic.AddInt32(&handlerInvocations, 1)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     append([]byte("ACK_IDEMPOTENT:"), msg.Payload...),
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr: server.Addr().String(),
		DomainSuffix: domainSuffix,
		ClientID:     "c01",
		PSK:          psk,
		SessionID:    0xDEADBEEFCAFE0001,
		Timeout:      2 * time.Second,
		MaxRetries:   0,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	ctx := context.Background()
	msg := &EmergencyMessage{
		ID:        "test-retry-001",
		Type:      "alert",
		Payload:   []byte("Critical Payload"),
		Timestamp: time.Now().Unix(),
	}

	// 1. Initial transmission
	resp1, _, err := client.Exchange(ctx, msg)
	if err != nil {
		t.Fatalf("First exchange failed: %v", err)
	}
	if string(resp1.Reply) != "ACK_IDEMPOTENT:Critical Payload" {
		t.Fatalf("Unexpected response reply: %s", string(resp1.Reply))
	}
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Expected 1 handler invocation, got %d", atomic.LoadInt32(&handlerInvocations))
	}

	// 2. Transmit exact same frame (retransmission of duplicate sequence)
	// We craft the duplicate by dialing the server with the exact frame from the first sequence
	// Client session has advanced, so we create a duplicate client with same sequence to simulate network duplicate
	dupClient, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr: server.Addr().String(),
		DomainSuffix: domainSuffix,
		ClientID:     "c01",
		PSK:          psk,
		SessionID:    0xDEADBEEFCAFE0001,
		Timeout:      2 * time.Second,
		MaxRetries:   0,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// Duplicate sends with the same initial sequence (1)
	resp2, _, err := dupClient.Exchange(ctx, msg)
	if err != nil {
		t.Fatalf("Retransmit exchange failed: %v", err)
	}
	if string(resp2.Reply) != "ACK_IDEMPOTENT:Critical Payload" {
		t.Fatalf("Retransmit response mismatch: %s", string(resp2.Reply))
	}

	// Crucial check: handler was NOT called a second time! Reply was served from idempotent replyCache!
	if atomic.LoadInt32(&handlerInvocations) != 1 {
		t.Fatalf("Idempotency violation! Handler was invoked %d times instead of 1", atomic.LoadInt32(&handlerInvocations))
	}
}

func TestTCPPort53QueryHandling(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	server, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: domainSuffix,
		PSK:          psk,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()

	// Dial TCP to the server
	tcpConn, err := net.DialTimeout("tcp", serverAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	defer tcpConn.Close()

	// Build a diagnostic query over TCP
	queryPkt := BuildDNSQuery(domainSuffix, 0x0010 /* TXT */, 0x1234)

	// RFC 7766: 2-byte prefix length
	var lenBuf [2]byte
	lenBuf[0] = byte(len(queryPkt) >> 8)
	lenBuf[1] = byte(len(queryPkt))

	if _, err := tcpConn.Write(lenBuf[:]); err != nil {
		t.Fatalf("Write len prefix failed: %v", err)
	}
	if _, err := tcpConn.Write(queryPkt); err != nil {
		t.Fatalf("Write query failed: %v", err)
	}

	// Read response len
	var respLenBuf [2]byte
	if _, err := io.ReadFull(tcpConn, respLenBuf[:]); err != nil {
		t.Fatalf("Read resp len failed: %v", err)
	}
	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	if respLen < 12 {
		t.Fatalf("Response len too small: %d", respLen)
	}

	respPkt := make([]byte, respLen)
	if _, err := io.ReadFull(tcpConn, respPkt); err != nil {
		t.Fatalf("Read resp pkt failed: %v", err)
	}

	// Verify DNS transaction ID matches
	if respPkt[0] != 0x12 || respPkt[1] != 0x34 {
		t.Fatalf("TxID mismatch in TCP response: got %02x%02x, want 1234", respPkt[0], respPkt[1])
	}
}

func TestKeyLengthValidationAndFailClosed(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"

	invalidKeys := [][]byte{
		nil,
		{},
		[]byte("short-key"),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}

	for _, k := range invalidKeys {
		_, errSrv := NewEmergencyDNSServer(EmergencyDNSServerConfig{
			ListenAddr:   "127.0.0.1:0",
			DomainSuffix: domainSuffix,
			PSK:          k,
		})
		if errSrv == nil {
			t.Fatalf("Expected NewEmergencyDNSServer to fail for key len %d, but succeeded", len(k))
		}

		_, errCli := NewEmergencyDNSClient(EmergencyDNSClientConfig{
			ResolverAddr: "127.0.0.1:53",
			DomainSuffix: domainSuffix,
			PSK:          k,
		})
		if errCli == nil {
			t.Fatalf("Expected NewEmergencyDNSClient to fail for key len %d, but succeeded", len(k))
		}
	}
}

func TestOversizedPayloadRejection(t *testing.T) {
	domainSuffix := "tunnel.emergency.local"
	psk := []byte("emergency-psk-32-bytes-super-key")

	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr: "127.0.0.1:53",
		DomainSuffix: domainSuffix,
		PSK:          psk,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	// MaxEmergencyPayloadBytes is 512. Try 513 bytes.
	msg := &EmergencyMessage{
		ID:        "oversized-test",
		Type:      "alert",
		Payload:   make([]byte, 513),
		Timestamp: time.Now().Unix(),
	}

	_, _, err = client.Exchange(context.Background(), msg)
	if err == nil {
		t.Fatalf("Expected payload > 512 bytes to be rejected, but succeeded")
	}
}
