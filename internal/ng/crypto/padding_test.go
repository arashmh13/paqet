package crypto

import (
	"testing"
)

func TestSampleAdaptivePadding(t *testing.T) {
	maxFrame := 1460
	maxPad := 128

	// Test bounds across 100 trials
	for i := 0; i < 100; i++ {
		plainLen := 30 + (i * 10)
		if plainLen > 1400 {
			plainLen = 1400
		}

		padUniform := SampleAdaptivePadding(plainLen, maxPad, maxFrame, PaddingProfileUniform)
		if padUniform < 0 || padUniform > maxPad {
			t.Fatalf("Uniform padding out of bounds: %d (maxPad=%d)", padUniform, maxPad)
		}
		if plainLen+padUniform > maxFrame {
			t.Fatalf("Uniform total length exceeds maxFrame: %d > %d", plainLen+padUniform, maxFrame)
		}

		padTLS := SampleAdaptivePadding(plainLen, maxPad, maxFrame, PaddingProfileTLSBimodal)
		if padTLS < 0 || padTLS > maxPad {
			t.Fatalf("TLS padding out of bounds: %d (maxPad=%d)", padTLS, maxPad)
		}
		if plainLen+padTLS > maxFrame {
			t.Fatalf("TLS total length exceeds maxFrame: %d > %d", plainLen+padTLS, maxFrame)
		}
	}
}

func TestSampleAdaptivePaddingTLSBucketAlignment(t *testing.T) {
	// A 50-byte plain payload with maxPad=64 should pad close to 64 bytes
	plainLen := 50
	maxPad := 32
	maxFrame := 1460

	pad := SampleAdaptivePadding(plainLen, maxPad, maxFrame, PaddingProfileTLSBimodal)
	total := plainLen + pad
	if total < 64 {
		t.Errorf("Expected padded total >= 64, got %d", total)
	}
}
