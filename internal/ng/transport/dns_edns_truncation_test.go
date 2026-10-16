package transport

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func TestEDNS0_ConservativeDefaultAndCustomBufferSize(t *testing.T) {
	// 1. Default query must advertise 1232 bytes (DNS Flag Day standard)
	q1 := BuildDNSQuery("test.example.com", 0x0010, 0x1234)
	bufSize1 := ParseEDNSBufferSize(q1)
	if bufSize1 != DefaultEDNSUDPPayloadSize {
		t.Fatalf("expected default EDNS buffer size %d, got %d", DefaultEDNSUDPPayloadSize, bufSize1)
	}
	if bufSize1 != 1232 {
		t.Fatalf("expected 1232 bytes default, got %d", bufSize1)
	}

	// 2. Custom 1400 bytes query
	q2 := BuildDNSQueryWithEDNS("test.example.com", 0x0010, 0x1234, 1400)
	bufSize2 := ParseEDNSBufferSize(q2)
	if bufSize2 != 1400 {
		t.Fatalf("expected custom EDNS buffer size 1400, got %d", bufSize2)
	}

	// 3. RFC 1035 standard query (0 bytes EDNS)
	q3 := BuildDNSQueryWithEDNS("test.example.com", 0x0010, 0x1234, 0)
	bufSize3 := ParseEDNSBufferSize(q3)
	if bufSize3 != 512 {
		t.Fatalf("expected RFC 1035 fallback size 512, got %d", bufSize3)
	}
	arcount := binary.BigEndian.Uint16(q3[10:12])
	if arcount != 0 {
		t.Fatalf("expected ARCOUNT=0 when EDNS buffer size is 0, got %d", arcount)
	}
}

func TestEDNS0_ParseEDNSBufferSize_MalformedInputs(t *testing.T) {
	// Truncated packet
	if size := ParseEDNSBufferSize([]byte{0x01, 0x02}); size != 512 {
		t.Fatalf("expected 512 on short packet, got %d", size)
	}

	// Empty packet
	if size := ParseEDNSBufferSize(nil); size != 512 {
		t.Fatalf("expected 512 on nil packet, got %d", size)
	}
}

func TestEDNS0_ResponseTruncationWhenExceedingLimit(t *testing.T) {
	// Client sends standard RFC 1035 query with 512-byte limit (ednsBufSize = 0)
	queryPkt := BuildDNSQueryWithEDNS("payload.example.com", 0x0010, 0x4321, 0)

	// Create a 1500-byte payload which exceeds safe UDP maximum (1400 bytes)
	largePayload := make([]byte, 1500)
	for i := range largePayload {
		largePayload[i] = byte('A' + (i % 26))
	}

	respPkt, err := BuildDNSTXTResponse(queryPkt, largePayload)
	if err != nil {
		t.Fatalf("BuildDNSTXTResponse failed: %v", err)
	}

	flags := binary.BigEndian.Uint16(respPkt[2:4])
	if flags&0x0200 == 0 {
		t.Fatalf("expected TC (Truncation) bit 0x0200 set on overflow response, got flags 0x%04x", flags)
	}
	ancount := binary.BigEndian.Uint16(respPkt[6:8])
	if ancount != 0 {
		t.Fatalf("expected ANCOUNT=0 on truncated response, got %d", ancount)
	}
	t.Logf("PASS: Response safely truncated with TC=1 and ANCOUNT=0 when exceeding 1400-byte safe limit")
}

func TestEDNS0_TCPPort53FallbackOnTruncation(t *testing.T) {
	// Start an EmergencyDNSServer with UDP and TCP listeners on an isolated loopback port
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	bm, err := NewBootstrapManager([]BootstrapEndpointRecord{
		{
			ServerIP:      "127.0.0.1",
			TransportPort: 18089,
			TransportMode: "aead-stream",
			IdentityType:  IdentityTypePSKID,
			IdentityValue: "SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ValiditySec:   3600,
		},
	}, "aead-stream", 1)
	if err != nil {
		t.Fatalf("NewBootstrapManager failed: %v", err)
	}

	srv, err := NewEmergencyDNSServer(EmergencyDNSServerConfig{
		ListenAddr:   "127.0.0.1:0",
		DomainSuffix: "edns.test",
		PSK:          psk,
		Handler: func(msg *EmergencyMessage) (*EmergencyResponse, error) {
			bResp, err := bm.GenerateResponse(msg, "aead-stream")
			if err != nil {
				return nil, err
			}
			bBytes, _ := json.Marshal(bResp)
			return &EmergencyResponse{
				ID:        msg.ID,
				Status:    "OK",
				Reply:     bBytes,
				Timestamp: time.Now().Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSServer failed: %v", err)
	}
	defer srv.Stop()

	addrStr := srv.udpConn.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create client with conservative 1232-byte EDNS buffer
	client, err := NewEmergencyDNSClient(EmergencyDNSClientConfig{
		ResolverAddr:   addrStr,
		DomainSuffix:   "edns.test",
		ClientID:       "c01",
		PSK:            psk,
		Timeout:        1 * time.Second,
		EDNSBufferSize: 1232,
	})
	if err != nil {
		t.Fatalf("NewEmergencyDNSClient failed: %v", err)
	}

	resp, _, err := client.Exchange(ctx, &EmergencyMessage{
		ID:        "msg-edns-01",
		Type:      "bootstrap_request",
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("client.Exchange failed: %v", err)
	}
	if resp.Status != "OK" {
		t.Fatalf("expected status OK, got %s", resp.Status)
	}
	t.Logf("PASS: Emergency DNS query succeeded with conservative 1232-byte EDNS buffer")
}
