package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
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
