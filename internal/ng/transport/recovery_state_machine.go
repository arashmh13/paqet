package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RecoveryState represents the explicit operational phase of the transport recovery lifecycle.
type RecoveryState string

const (
	StatePrimaryHealthy              RecoveryState = "PRIMARY_HEALTHY"
	StatePrimaryDegraded             RecoveryState = "PRIMARY_DEGRADED"
	StateEmergencySignaling          RecoveryState = "EMERGENCY_SIGNALING"
	StateBootstrapReceived           RecoveryState = "BOOTSTRAP_RECEIVED"
	StateCandidateEndpointValidating RecoveryState = "CANDIDATE_ENDPOINT_VALIDATING"
	StateRecoveryReady               RecoveryState = "RECOVERY_READY"
	StateRecoveryFailed              RecoveryState = "RECOVERY_FAILED"
	StateCooldown                    RecoveryState = "COOLDOWN"
)

const (
	// MaxRecoveryHistoryEvents bounds the circular audit trail to prevent memory leaks
	MaxRecoveryHistoryEvents = 256
	// DefaultMaxBootstrapValidityWindow limits maximum validity window into the future (24 hours)
	DefaultMaxBootstrapValidityWindow = 24 * time.Hour
)

var (
	ErrStaleBootstrapData        = errors.New("recovery: bootstrap endpoint coordinates have expired")
	ErrInvalidBootstrapData      = errors.New("recovery: invalid bootstrap endpoint fields")
	ErrCandidateValidation       = errors.New("recovery: candidate endpoint failed authenticated validation handshake")
	ErrMissingCandidateValidator = errors.New("recovery: candidate validator required for fail-closed recovery; cannot activate unvalidated endpoint")
	ErrSignalingFailed           = errors.New("recovery: emergency DNS signaling channel failed")
	ErrCooldownActive            = errors.New("recovery: recovery engine is in cooldown backoff")
	ErrRecoveryOperationActive   = errors.New("recovery: recovery operation already in progress")
	ErrStaleRecoveryOperation    = errors.New("recovery: stale asynchronous recovery operation superseded by state change or rollback")
)

// StateTransitionEvent records historical state movements for telemetry and auditability.
type StateTransitionEvent struct {
	FromState RecoveryState `json:"from_state"`
	ToState   RecoveryState `json:"to_state"`
	Reason    string        `json:"reason"`
	Timestamp time.Time     `json:"timestamp"`
}

// RecoveryStateMachineConfig configures the failure-detection and recovery parameters.
type RecoveryStateMachineConfig struct {
	PrimaryFailureThreshold    int           // Number of consecutive failures to declare DEGRADED (e.g. 3)
	DegradedTimeout            time.Duration // Time in DEGRADED before initiating EMERGENCY_SIGNALING (e.g. 2s)
	BootstrapValidationTimeout time.Duration // Time limit for independent candidate validation (e.g. 4s)
	CooldownDuration           time.Duration // Cooldown duration after failure before retrying (e.g. 15s)
	MaxBootstrapValidityWindow time.Duration // Maximum future validity window (default 24h)
	AllowLoopbackEndpoints     bool          // For local unit tests only; false in production
	EmergencyDialer            func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error)
	CandidateValidator         func(ctx context.Context, endpoint *BootstrapEndpointData) error
}

// RecoveryStateMachine implements the controlled, non-flapping, fail-closed recovery lifecycle.
type RecoveryStateMachine struct {
	cfg               RecoveryStateMachineConfig
	mu                sync.RWMutex
	state             RecoveryState
	consecutiveFails  int
	lastTransition    time.Time
	cooldownExpiry    time.Time
	activeEndpoint    string
	lastBootstrap     *BootstrapEndpointData
	history           []StateTransitionEvent
	currentGeneration uint64 // Incremented on state changes, rollback, or primary recovery to detect stale async results
	operationActive   bool   // Enforces strictly one concurrent Step() recovery attempt per machine
}

// NewRecoveryStateMachine instantiates a recovery engine starting in StatePrimaryHealthy.
func NewRecoveryStateMachine(cfg RecoveryStateMachineConfig) *RecoveryStateMachine {
	if cfg.PrimaryFailureThreshold <= 0 {
		cfg.PrimaryFailureThreshold = 3
	}
	if cfg.DegradedTimeout <= 0 {
		cfg.DegradedTimeout = 2 * time.Second
	}
	if cfg.BootstrapValidationTimeout <= 0 {
		cfg.BootstrapValidationTimeout = 4 * time.Second
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 15 * time.Second
	}
	if cfg.MaxBootstrapValidityWindow <= 0 {
		cfg.MaxBootstrapValidityWindow = DefaultMaxBootstrapValidityWindow
	}

	sm := &RecoveryStateMachine{
		cfg:            cfg,
		state:          StatePrimaryHealthy,
		lastTransition: time.Now(),
	}
	sm.recordTransitionLocked(StatePrimaryHealthy, StatePrimaryHealthy, "initialization")
	return sm
}

// CurrentState returns the active recovery state.
func (sm *RecoveryStateMachine) CurrentState() RecoveryState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// ActiveEndpoint returns the verified recovery endpoint, or empty string if using primary.
func (sm *RecoveryStateMachine) ActiveEndpoint() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeEndpoint
}

// CurrentGeneration returns the current state revision generation.
func (sm *RecoveryStateMachine) CurrentGeneration() uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentGeneration
}

// History returns a copy of state transition events for audit reporting.
func (sm *RecoveryStateMachine) History() []StateTransitionEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	copied := make([]StateTransitionEvent, len(sm.history))
	copy(copied, sm.history)
	return copied
}

func (sm *RecoveryStateMachine) recordTransitionLocked(from, to RecoveryState, reason string) {
	sm.state = to
	sm.lastTransition = time.Now()
	sm.currentGeneration++
	if len(sm.history) >= MaxRecoveryHistoryEvents {
		sm.history = sm.history[1:]
	}
	sm.history = append(sm.history, StateTransitionEvent{
		FromState: from,
		ToState:   to,
		Reason:    reason,
		Timestamp: sm.lastTransition,
	})
}

// ReportPrimarySuccess signals that the primary transport handled traffic successfully.
func (sm *RecoveryStateMachine) ReportPrimarySuccess() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.consecutiveFails = 0
	if sm.state == StatePrimaryDegraded || sm.state == StateEmergencySignaling || sm.state == StateCandidateEndpointValidating {
		sm.currentGeneration++
		sm.activeEndpoint = ""
		sm.recordTransitionLocked(sm.state, StatePrimaryHealthy, "primary traffic verified healthy; hysteresis recovered")
	}
}

// ReportPrimaryFailure registers a transport error on the primary path.
func (sm *RecoveryStateMachine) ReportPrimaryFailure(err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.consecutiveFails++
	if sm.state == StatePrimaryHealthy && sm.consecutiveFails >= sm.cfg.PrimaryFailureThreshold {
		sm.recordTransitionLocked(sm.state, StatePrimaryDegraded, fmt.Sprintf("consecutive primary failures (%d) reached threshold: %v", sm.consecutiveFails, err))
	}
}

// Step performs an autonomous evaluation cycle of the state machine.
func (sm *RecoveryStateMachine) Step(ctx context.Context) (RecoveryState, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 1. Enforce strictly one recovery operation active per machine
	if sm.operationActive {
		return sm.state, ErrRecoveryOperationActive
	}
	sm.operationActive = true
	defer func() {
		sm.operationActive = false
	}()

	now := time.Now()

	switch sm.state {
	case StatePrimaryHealthy:
		return StatePrimaryHealthy, nil

	case StatePrimaryDegraded:
		if now.Sub(sm.lastTransition) < sm.cfg.DegradedTimeout {
			// Hysteresis window: remain in DEGRADED to allow transient recovery
			return StatePrimaryDegraded, nil
		}

		// P0 FAIL-CLOSED REQUIREMENT: Candidate validator MUST be configured!
		if sm.cfg.CandidateValidator == nil {
			sm.recordTransitionLocked(StatePrimaryDegraded, StateRecoveryFailed, "fail-closed: candidate validator required for recovery but not configured")
			sm.enterCooldownLocked("missing candidate validator")
			return StateCooldown, ErrMissingCandidateValidator
		}

		// Degraded timeout elapsed: trigger emergency signaling
		sm.recordTransitionLocked(StatePrimaryDegraded, StateEmergencySignaling, "degraded timeout elapsed; requesting bootstrap failover via emergency DNS")
		fallthrough

	case StateEmergencySignaling:
		if sm.cfg.CandidateValidator == nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, "fail-closed: missing candidate validator")
			sm.enterCooldownLocked("missing candidate validator")
			return StateCooldown, ErrMissingCandidateValidator
		}
		if sm.cfg.EmergencyDialer == nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, "no emergency dialer configured")
			sm.enterCooldownLocked("missing emergency dialer")
			return StateCooldown, ErrSignalingFailed
		}

		req := &EmergencyMessage{
			ID:        GenerateRandomMessageID(),
			Type:      MsgTypeBootstrapRequest,
			Payload:   []byte("REQUEST_BOOTSTRAP_ENDPOINT"),
			Timestamp: now.Unix(),
		}

		startGen := sm.currentGeneration

		// Unlock mutex during external network signaling call
		sm.mu.Unlock()
		endpoint, err := sm.cfg.EmergencyDialer(ctx, req)
		sm.mu.Lock()

		// Stale operation check: verify generation has not advanced while network call was in flight
		if sm.currentGeneration != startGen || sm.state != StateEmergencySignaling {
			return sm.state, ErrStaleRecoveryOperation
		}

		if err != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("emergency signaling query failed: %v", err))
			sm.enterCooldownLocked("emergency signaling error")
			return StateCooldown, fmt.Errorf("%w: %v", ErrSignalingFailed, err)
		}

		// Validate received bootstrap data schema, freshness, and cryptographic identity
		maxWindow := sm.cfg.MaxBootstrapValidityWindow
		if maxWindow <= 0 {
			maxWindow = DefaultMaxBootstrapValidityWindow
		}
		if valErr := endpoint.Validate(now, maxWindow, sm.cfg.AllowLoopbackEndpoints); valErr != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("bootstrap validation failed: %v", valErr))
			sm.enterCooldownLocked(fmt.Sprintf("invalid bootstrap payload: %v", valErr))
			return StateCooldown, fmt.Errorf("%w: %v", ErrInvalidBootstrapData, valErr)
		}

		sm.lastBootstrap = endpoint
		sm.recordTransitionLocked(sm.state, StateBootstrapReceived, fmt.Sprintf("received authenticated bootstrap endpoint %s:%d (%s)", endpoint.ServerIP, endpoint.TransportPort, endpoint.TransportMode))
		sm.recordTransitionLocked(StateBootstrapReceived, StateCandidateEndpointValidating, "initiating independent authenticated handshake validation")

		valGen := sm.currentGeneration

		// Validate candidate endpoint independently
		valCtx, cancel := context.WithTimeout(ctx, sm.cfg.BootstrapValidationTimeout)
		defer cancel()

		sm.mu.Unlock()
		valErr := sm.cfg.CandidateValidator(valCtx, endpoint)
		sm.mu.Lock()

		// Stale operation check: verify generation has not advanced while candidate was validating
		if sm.currentGeneration != valGen || sm.state != StateCandidateEndpointValidating {
			return sm.state, ErrStaleRecoveryOperation
		}

		if valErr != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("candidate endpoint %s:%d failed validation handshake: %v", endpoint.ServerIP, endpoint.TransportPort, valErr))
			sm.enterCooldownLocked("candidate validation rejected")
			return StateCooldown, fmt.Errorf("%w: %v", ErrCandidateValidation, valErr)
		}

		// Validation successful! Activate recovery endpoint for new connections
		sm.activeEndpoint = fmt.Sprintf("%s:%d", endpoint.ServerIP, endpoint.TransportPort)
		sm.recordTransitionLocked(sm.state, StateRecoveryReady, fmt.Sprintf("candidate endpoint %s validated and active for new connections", sm.activeEndpoint))
		return StateRecoveryReady, nil

	case StateRecoveryReady:
		return StateRecoveryReady, nil

	case StateRecoveryFailed:
		sm.enterCooldownLocked("previous recovery failed")
		return StateCooldown, nil

	case StateCooldown:
		if now.After(sm.cooldownExpiry) {
			sm.recordTransitionLocked(StateCooldown, StatePrimaryDegraded, "cooldown duration expired; re-evaluating primary connectivity")
			return StatePrimaryDegraded, nil
		}
		return StateCooldown, ErrCooldownActive

	default:
		return sm.state, nil
	}
}

func (sm *RecoveryStateMachine) enterCooldownLocked(reason string) {
	sm.activeEndpoint = ""
	sm.cooldownExpiry = time.Now().Add(sm.cfg.CooldownDuration)
	sm.recordTransitionLocked(sm.state, StateCooldown, fmt.Sprintf("entering cooldown for %v: %s", sm.cfg.CooldownDuration, reason))
}

// ResetRollback deterministically restores the state machine to StatePrimaryHealthy and clears active recovery endpoints.
func (sm *RecoveryStateMachine) ResetRollback(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.currentGeneration++
	sm.consecutiveFails = 0
	sm.activeEndpoint = ""
	sm.lastBootstrap = nil
	sm.recordTransitionLocked(sm.state, StatePrimaryHealthy, fmt.Sprintf("manual or automated rollback: %s", reason))
}
