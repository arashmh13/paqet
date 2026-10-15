package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
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

var (
	ErrStaleBootstrapData   = errors.New("recovery: bootstrap endpoint coordinates have expired")
	ErrInvalidBootstrapData = errors.New("recovery: invalid bootstrap endpoint fields")
	ErrCandidateValidation  = errors.New("recovery: candidate endpoint failed authenticated validation handshake")
	ErrSignalingFailed      = errors.New("recovery: emergency DNS signaling channel failed")
	ErrCooldownActive       = errors.New("recovery: recovery engine is in cooldown backoff")
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
	EmergencyDialer            func(ctx context.Context, msg *EmergencyMessage) (*BootstrapEndpointData, error)
	CandidateValidator         func(ctx context.Context, endpoint *BootstrapEndpointData) error
}

// RecoveryStateMachine implements the controlled, non-flapping recovery lifecycle.
type RecoveryStateMachine struct {
	cfg              RecoveryStateMachineConfig
	mu               sync.RWMutex
	state            RecoveryState
	consecutiveFails int
	lastTransition   time.Time
	cooldownExpiry   time.Time
	activeEndpoint   string
	lastBootstrap    *BootstrapEndpointData
	history          []StateTransitionEvent
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
	if sm.state == StatePrimaryDegraded {
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

	now := time.Now()

	switch sm.state {
	case StatePrimaryHealthy:
		return StatePrimaryHealthy, nil

	case StatePrimaryDegraded:
		if now.Sub(sm.lastTransition) < sm.cfg.DegradedTimeout {
			// Hysteresis window: remain in DEGRADED to allow transient recovery
			return StatePrimaryDegraded, nil
		}
		// Degraded timeout elapsed: trigger emergency signaling
		sm.recordTransitionLocked(StatePrimaryDegraded, StateEmergencySignaling, "degraded timeout elapsed; requesting bootstrap failover via emergency DNS")
		fallthrough

	case StateEmergencySignaling:
		if sm.cfg.EmergencyDialer == nil {
			sm.recordTransitionLocked(StateEmergencySignaling, StateRecoveryFailed, "no emergency dialer configured")
			sm.enterCooldownLocked("missing emergency dialer")
			return StateCooldown, ErrSignalingFailed
		}

		req := &EmergencyMessage{
			ID:        GenerateRandomMessageID(),
			Type:      MsgTypeBootstrapRequest,
			Payload:   []byte("REQUEST_BOOTSTRAP_ENDPOINT"),
			Timestamp: now.Unix(),
		}

		// Unlock mutex during external network signaling call
		sm.mu.Unlock()
		endpoint, err := sm.cfg.EmergencyDialer(ctx, req)
		sm.mu.Lock()

		if err != nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("emergency signaling query failed: %v", err))
			sm.enterCooldownLocked("emergency signaling error")
			return StateCooldown, fmt.Errorf("%w: %v", ErrSignalingFailed, err)
		}

		// Validate received bootstrap data schema and freshness
		if endpoint == nil || endpoint.ServerIP == "" || endpoint.TransportPort <= 0 || endpoint.TransportPort > 65535 {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, "malformed bootstrap endpoint payload")
			sm.enterCooldownLocked("malformed bootstrap payload")
			return StateCooldown, ErrInvalidBootstrapData
		}
		if ip := net.ParseIP(endpoint.ServerIP); ip == nil {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("invalid server IP %q in bootstrap payload", endpoint.ServerIP))
			sm.enterCooldownLocked("invalid server IP")
			return StateCooldown, ErrInvalidBootstrapData
		}
		if endpoint.ValidUntil > 0 && endpoint.ValidUntil < now.Unix() {
			sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("bootstrap coordinates expired at %d (current %d)", endpoint.ValidUntil, now.Unix()))
			sm.enterCooldownLocked("expired bootstrap payload")
			return StateCooldown, ErrStaleBootstrapData
		}

		sm.lastBootstrap = endpoint
		sm.recordTransitionLocked(sm.state, StateBootstrapReceived, fmt.Sprintf("received authenticated bootstrap endpoint %s:%d (%s)", endpoint.ServerIP, endpoint.TransportPort, endpoint.TransportMode))
		sm.recordTransitionLocked(StateBootstrapReceived, StateCandidateEndpointValidating, "initiating independent authenticated handshake validation")

		// Validate candidate endpoint independently
		if sm.cfg.CandidateValidator != nil {
			valCtx, cancel := context.WithTimeout(ctx, sm.cfg.BootstrapValidationTimeout)
			defer cancel()

			sm.mu.Unlock()
			valErr := sm.cfg.CandidateValidator(valCtx, endpoint)
			sm.mu.Lock()

			if valErr != nil {
				sm.recordTransitionLocked(sm.state, StateRecoveryFailed, fmt.Sprintf("candidate endpoint %s:%d failed validation handshake: %v", endpoint.ServerIP, endpoint.TransportPort, valErr))
				sm.enterCooldownLocked("candidate validation rejected")
				return StateCooldown, fmt.Errorf("%w: %v", ErrCandidateValidation, valErr)
			}
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

	sm.consecutiveFails = 0
	sm.activeEndpoint = ""
	sm.lastBootstrap = nil
	sm.recordTransitionLocked(sm.state, StatePrimaryHealthy, fmt.Sprintf("manual or automated rollback: %s", reason))
}
