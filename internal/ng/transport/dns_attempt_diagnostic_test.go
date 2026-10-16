package transport

import (
	"testing"
)

func TestDNSQueryAttemptRecord_Validation(t *testing.T) {
	// Case 1: Valid SUCCESS record
	validRec := DNSQueryAttemptRecord{
		AttemptIndex:      0,
		ResolverAddr:      "8.8.8.8:53",
		Protocol:          "udp",
		TxID:              1234,
		SentAtMonotonicMs: 10.0,
		RcvdAtMonotonicMs: 150.0,
		DurationMs:        140.0,
		RCode:             0,
		Truncated:         false,
		Authenticated:     true,
		ServerID:          "ns-de-01",
		Status:            DNSAttemptStatusSuccess,
		Error:             "", // must be empty
	}
	if err := validRec.Validate(); err != nil {
		t.Fatalf("Valid attempt record failed validation: %v", err)
	}

	// Case 2: Contradictory SUCCESS record with non-empty error (Phase 16 anomaly)
	badSuccessRec := validRec
	badSuccessRec.Error = "invalid txt response format"
	if err := badSuccessRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for SUCCESS attempt with non-empty error, got nil")
	}

	// Case 3: SUCCESS record missing authentication
	unauthSuccessRec := validRec
	unauthSuccessRec.Authenticated = false
	if err := unauthSuccessRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for unauthenticated SUCCESS attempt, got nil")
	}

	// Case 4: SUCCESS record missing ServerID
	noServerSuccessRec := validRec
	noServerSuccessRec.ServerID = ""
	if err := noServerSuccessRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for SUCCESS attempt missing ServerID, got nil")
	}

	// Case 5: Negative duration
	negDurationRec := validRec
	negDurationRec.DurationMs = -5.0
	if err := negDurationRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for negative duration, got nil")
	}

	// Case 6: Non-monotonic timing (rcvd < sent)
	nonMonotonicRec := validRec
	nonMonotonicRec.SentAtMonotonicMs = 150.0
	nonMonotonicRec.RcvdAtMonotonicMs = 100.0
	if err := nonMonotonicRec.Validate(); err == nil {
		t.Fatalf("Expected validation error for non-monotonic timing, got nil")
	}

	// Case 7: Valid TIMEOUT record
	validTimeoutRec := DNSQueryAttemptRecord{
		AttemptIndex:      0,
		ResolverAddr:      "1.1.1.1:53",
		Protocol:          "udp",
		TxID:              5678,
		SentAtMonotonicMs: 0.0,
		RcvdAtMonotonicMs: 1500.0,
		DurationMs:        1500.0,
		Status:            DNSAttemptStatusTimeout,
		Error:             "timeout waiting for valid response",
	}
	if err := validTimeoutRec.Validate(); err != nil {
		t.Fatalf("Valid TIMEOUT record failed validation: %v", err)
	}
}
