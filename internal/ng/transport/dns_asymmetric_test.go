package transport

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestDNSAsymmetricFramingAndReassemblyDetails(t *testing.T) {
	domainSuffix := "tunnel.paqet.local"
	clientID := "c99"
	offset := uint32(1000)

	// Simulate a 100-byte payload split into 3 chunks
	payload := []byte("Emergency DNS payload for severe curfew testing. 100% authenticated chunk framing over UDP:53.")
	chunkSize := 35 // Fits comfortably in a 63-char base32 label

	var chunks [][]byte
	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[i:end])
	}

	totalParts := uint8(len(chunks))
	reassembler := NewDNSReassembler(5 * time.Second)

	// Encode and push out of order: Part 2, then Part 0, then Part 1
	order := []int{2, 0, 1}
	var complete []byte
	var ok bool

	for _, idx := range order {
		qname := EncodeDNSQName(domainSuffix, clientID, offset, uint8(idx), totalParts, chunks[idx])

		// Verify label lengths <= 63 (RFC 1035 limit)
		labels := bytes.Split([]byte(qname), []byte("."))
		for _, l := range labels {
			if len(l) > 63 {
				t.Fatalf("Label %q exceeds RFC 1035 limit (len %d > 63)", l, len(l))
			}
		}

		cID, off, p, tot, data, err := DecodeDNSQName(qname, domainSuffix)
		if err != nil {
			t.Fatalf("DecodeDNSQName failed for qname %s: %v", qname, err)
		}
		if cID != clientID || off != offset || p != uint8(idx) || tot != totalParts {
			t.Fatalf("Metadata mismatch: got (%s, %d, %d, %d), want (%s, %d, %d, %d)",
				cID, off, p, tot, clientID, offset, idx, totalParts)
		}

		res, finished := reassembler.PushFragment(cID, off, p, tot, data)
		if finished {
			complete = res
			ok = true
		}
	}

	if !ok {
		t.Fatalf("Reassembler failed to assemble all parts")
	}

	if !bytes.Equal(complete, payload) {
		t.Fatalf("Reassembled payload mismatch: got %q, want %q", complete, payload)
	}
}

func TestDNSOverheadAndThroughputBounds(t *testing.T) {
	// Calculate mathematical throughput and amplification
	rawChunkSize := 35 // bytes
	b32Len := (rawChunkSize*8 + 4) / 5
	domainSuffix := "t.paqet.ir"
	clientID := "c01"

	qname := fmt.Sprintf("p0.t1.o0.%s.%s.%s", string(make([]byte, b32Len)), clientID, domainSuffix)
	dnsQuerySize := 20 /* IPv4 */ + 8 /* UDP */ + 12 /* DNS Header */ + len(qname) + 2 + 4 /* Question */

	amplification := float64(dnsQuerySize) / float64(rawChunkSize)
	t.Logf("DNS Wire Query Size: %d bytes, Payload: %d bytes, Wire Amplification: %.2fx",
		dnsQuerySize, rawChunkSize, amplification)

	if amplification < 2.0 {
		t.Errorf("Expected wire amplification to exceed 2.0x, got %.2fx", amplification)
	}

	// At 20 queries/second (conservative resolver rate limit)
	conservativeThroughputBps := 20 * rawChunkSize * 8
	t.Logf("Conservative DNS Throughput @ 20 qps: %d bps (%.2f kbps)",
		conservativeThroughputBps, float64(conservativeThroughputBps)/1000.0)

	// At 100 queries/second (aggressive)
	aggressiveThroughputBps := 100 * rawChunkSize * 8
	t.Logf("Aggressive DNS Throughput @ 100 qps: %d bps (%.2f kbps)",
		aggressiveThroughputBps, float64(aggressiveThroughputBps)/1000.0)

	if conservativeThroughputBps > 100000 {
		t.Errorf("Conservative DNS throughput unexpectedly exceeded 100 kbps")
	}
}
