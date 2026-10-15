package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRecoveryStateMachine_SuccessfulTransition(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    3,
		DegradedTimeout:            50 * time.Millisecond,
		BootstrapValidationTimeout: 100 * time.Millisecond,
		CooldownDuration:           200 * time.Millisecond,
		AllowLoopbackEndpoints:     true,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid-crypto-fingerprint-node1",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			if endpoint.ServerIP == "77.37.65.2" && endpoint.TransportPort == 18089 && endpoint.ServerPubKey != "" {
				return nil // Handshake and cryptographic identity validated!
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

func TestRecoveryStateMachine_MissingValidatorFailClosed(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: nil, // Missing validator must cause fail-closed rejection!
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrMissingCandidateValidator) {
		t.Fatalf("Expected ErrMissingCandidateValidator, got %v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected state COOLDOWN, got %s", state)
	}
	if sm.ActiveEndpoint() != "" {
		t.Fatalf("Fail-closed violation: active endpoint must remain empty on missing validator, got %q", sm.ActiveEndpoint())
	}
}

func TestRecoveryStateMachine_ZeroOrMissingExpiryFailClosed(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid",
				ValidUntil:    0, // Zero expiry must fail closed!
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData, got %v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected state COOLDOWN, got %s", state)
	}
}

func TestRecoveryStateMachine_DistantExpiryRejected(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold:    1,
		DegradedTimeout:            10 * time.Millisecond,
		MaxBootstrapValidityWindow: 2 * time.Hour,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid",
				ValidUntil:    time.Now().Add(10 * time.Hour).Unix(), // Exceeds 2h window!
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	state, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData for excessively distant expiry, got %v", err)
	}
	if state != StateCooldown {
		t.Fatalf("Expected state COOLDOWN, got %s", state)
	}
}

func TestRecoveryStateMachine_UnsupportedTransportModeRejected(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "telnet-plain", // Unsupported mode!
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	_, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData for unsupported transport mode, got %v", err)
	}
}

func TestRecoveryStateMachine_MissingCryptographicIdentityRejected(t *testing.T) {
	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 8443,
				TransportMode: "tls-outer",
				ServerPubKey:  "", // Missing certificate/key identity!
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}
	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("down"))
	time.Sleep(15 * time.Millisecond)

	_, err := sm.Step(context.Background())
	if !errors.Is(err, ErrInvalidBootstrapData) {
		t.Fatalf("Expected ErrInvalidBootstrapData for missing cryptographic identity, got %v", err)
	}
}

func TestRecoveryStateMachine_StaleAsyncDialerDiscardedOnPrimaryRecovery(t *testing.T) {
	dialerStarted := make(chan struct{})
	dialerBlock := make(chan struct{})

	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			close(dialerStarted)
			<-dialerBlock // Pause in async network call
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	var stepErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, stepErr = sm.Step(context.Background())
	}()

	<-dialerStarted // Wait until dialer is blocked mid-flight

	// Primary recovers while dialer is in-flight!
	sm.ReportPrimarySuccess()
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state PRIMARY_HEALTHY after ReportPrimarySuccess, got %s", sm.CurrentState())
	}

	// Unblock dialer
	close(dialerBlock)
	wg.Wait()

	if !errors.Is(stepErr, ErrStaleRecoveryOperation) {
		t.Fatalf("Expected ErrStaleRecoveryOperation for superseded dialer, got %v", stepErr)
	}
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("State must remain PRIMARY_HEALTHY; got %s", sm.CurrentState())
	}
	if sm.ActiveEndpoint() != "" {
		t.Fatalf("Active endpoint must remain empty on superseded dialer, got %q", sm.ActiveEndpoint())
	}
}

func TestRecoveryStateMachine_StaleCandidateValidatorDiscardedOnRollback(t *testing.T) {
	validatorStarted := make(chan struct{})
	validatorBlock := make(chan struct{})

	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			close(validatorStarted)
			<-validatorBlock // Pause in candidate validation
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	var stepErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, stepErr = sm.Step(context.Background())
	}()

	<-validatorStarted

	// Operator executes ResetRollback while validation is pending
	sm.ResetRollback("operator rollback")
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("Expected state PRIMARY_HEALTHY after ResetRollback, got %s", sm.CurrentState())
	}

	close(validatorBlock)
	wg.Wait()

	if !errors.Is(stepErr, ErrStaleRecoveryOperation) {
		t.Fatalf("Expected ErrStaleRecoveryOperation for superseded validator, got %v", stepErr)
	}
	if sm.CurrentState() != StatePrimaryHealthy {
		t.Fatalf("State must remain PRIMARY_HEALTHY; got %s", sm.CurrentState())
	}
	if sm.ActiveEndpoint() != "" {
		t.Fatalf("Active endpoint must remain empty on superseded validator, got %q", sm.ActiveEndpoint())
	}
}

func TestRecoveryStateMachine_ConcurrentStepOperations(t *testing.T) {
	dialerStarted := make(chan struct{})
	dialerBlock := make(chan struct{})

	cfg := RecoveryStateMachineConfig{
		PrimaryFailureThreshold: 1,
		DegradedTimeout:         10 * time.Millisecond,
		EmergencyDialer: func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error) {
			close(dialerStarted)
			<-dialerBlock
			return &BootstrapEndpointData{
				ServerIP:      "77.37.65.2",
				TransportPort: 18089,
				TransportMode: "aead-stream",
				ServerPubKey:  "SHA256:valid",
				ValidUntil:    time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		},
		CandidateValidator: func(ctx context.Context, endpoint *BootstrapEndpointData) error {
			return nil
		},
	}

	sm := NewRecoveryStateMachine(cfg)
	sm.ReportPrimaryFailure(errors.New("primary down"))
	time.Sleep(15 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = sm.Step(context.Background())
	}()

	<-dialerStarted

	// A concurrent Step() must be rejected as already active
	_, err := sm.Step(context.Background())
	if !errors.Is(err, ErrRecoveryOperationActive) {
		t.Fatalf("Expected ErrRecoveryOperationActive for concurrent Step, got %v", err)
	}

	close(dialerBlock)
	wg.Wait()
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
