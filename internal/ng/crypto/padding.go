package crypto

import (
	"crypto/rand"
	"encoding/binary"
)

// PaddingProfile represents the packet shaping profile.
type PaddingProfile string

const (
	PaddingProfileUniform   PaddingProfile = "uniform"
	PaddingProfileTLSBimodal PaddingProfile = "tls_bimodal"
)

// SampleAdaptivePadding calculates padding length according to the selected profile.
// It guarantees that 0 <= padLen <= maxPad and (plainLen + padLen) <= maxFrame.
func SampleAdaptivePadding(plainLen, maxPad, maxFrame int, profile PaddingProfile) int {
	if maxPad <= 0 || maxFrame <= plainLen {
		return 0
	}

	budget := maxFrame - plainLen
	if budget > maxPad {
		budget = maxPad
	}
	if budget <= 0 {
		return 0
	}

	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	randVal := int(binary.BigEndian.Uint16(b[:]))

	switch profile {
	case PaddingProfileTLSBimodal:
		// Target discrete TLS record size buckets: 64, 128, 256, 512, 1024, 1420
		targetBuckets := []int{64, 128, 256, 512, 1024, 1420}
		for _, bucket := range targetBuckets {
			if bucket >= plainLen {
				needed := bucket - plainLen
				if needed <= budget {
					// Add small random jitter (0 to 15 bytes) to prevent exact static length matching
					jitter := (randVal % 16)
					if needed+jitter <= budget {
						return needed + jitter
					}
					return needed
				}
				break
			}
		}
		// For larger frames, pick a small random jitter
		return randVal % (budget + 1)

	default: // Uniform random
		return randVal % (budget + 1)
	}
}
