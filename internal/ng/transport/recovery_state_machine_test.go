package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecoveryStateMachine_SuccessfulTransition(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    3,
		DegradedTimeout:            50 * time.Millisecond,
		BootstrapValidationTimeout: 100 * time.Millisecond,
		CooldownDuration:           200 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			if endpoint.ServerIP == "77.37.65.2" && endpoint.TransportPort == 18089 {
				return nil // Handshake validated!
			}
			return errors.New("candidate handshake failed")
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected initial state PRIMARY_HEALTHY, got %s", sm.CurrentState())
	}

	// 1. Report 2 failures (below threshold 3)
	sm.ReportPrimaryFailure(errors.New("timeout 1"))
	sm.ReportPrimaryFailure(errors.New("timeout 2"))
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state to remain PRIMARY_HEALTHY, got %s", sm.CurrentState())
	}

	// 2. Report 3rd failure (reaches threshold) -> StatePrimaryDegraded
	sm.ReportPrimaryFailure(errors.New("timeout 3"))
	if sm.CurrentState() != StatePrimaryDegraded {
		t.Fatalf("Expected state PRIMARY_DEGRADED, got %s", sm.CurrentState())
	}

	// 3. Step before degraded timeout: remains in DEGRADED (hysteresis)
	state, err := sm.Step(context.Background())
	if err != nil || state != StatePrimaryDegraded {
		t.Fatalf("Expected state to remain PRIMARY_DEGRADED during hysteresis window, got %s", state)
	}

	// 4. Wait for degraded timeout to elapse
	time.Sleep(60 * time.Millisecond)

	// 5. Step: triggers emergency signaling, receives bootstrap, validates candidate, transitions to RECOVERY_READY
	state, err = sm.Step(context.Background())
	if err != nil {
		t.Fatalf("Step failed: %v", err)
	}
	if state != StateRecoveryReady {
		t.Fatalf("Expected state RECOVERY_READY, got %s", state)
	}
	if sm.ActiveEndpoint() != "77.37.65.2:18089" {
		t.Fatalf("Expected active endpoint 77.37.65.2:18089, got %s", sm.ActiveEndpoint())
	}

	// Verify transition history contains all expected phases
	history := sm.History()
	expectedStates := []RecoveryState{
		StatePrimaryHealthy,
		StatePrimaryDegraded,
		StateEmergencySignaling,
		StateBootstrapReceived,
		StateCandidateEndpointValidating,
		StateRecoveryReady,
	}
	for _, exp := range expectedStates {
		found := false
		for _, ev := range history {
			if ev.ToState == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing expected state transition to %s in history", exp)
		}
	}
}

func TestRecoveryStateMachine_HysteresisRecovery(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 2,
		DegradedTimeout:         100 * time.Millisecond,
	}
	sm := NewRecoveryStateMachine(cfg)

	sm.ReportPrimaryFailure(errors.New("error 1"))
	sm.ReportPrimaryFailure(errors.New("error 2"))
	if sm.CurrentState() != StatePrimaryDegraded {
		t.Fatalf("Expected PRIMARY_DEGRADED, got %s", sm.CurrentState())
	}

	// Primary recovers before degraded timeout!
	sm.ReportPrimarySuccess()
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state to recover to PRIMARY_HEALTHY, got %s", sm.CurrentState())
	}
}

func TestRecoveryStateMachine_StaleBootstrapRejection(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 8443,
				TransportMode: "tls-outer",
				ValidUntil:    time.Now().Add(-10 * time.Minute).Unix(), // Expired!
			}, nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("fail"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrStaleBootstrapData) {
		t.Fatalf("Expected ErrStaleBootstrapData, got err=%v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected transition to COOLDOWN, got %s", state)
	}
}

func TestRecoveryStateMachine_CandidateValidationFailure(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "192.0.2.1",
				TransportPort: 8089,
				TransportMode: "aead-stream",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return errors.New("connection refused by remote host")
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrCandidateValidation) {
		t.Fatalf("Expected ErrCandidateValidation, got err=%v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected transition to COOLDOWN after candidate validation failure, got %s", state)
	}

	// Verify rollback restores state
	sm.ResetRollback("operator initiated")
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected PRIMARY_HEALTHY after ResetRollback, got %s", sm.CurrentState())
	}
}
