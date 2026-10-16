# Paqet-NG Emergency Channel Security & Cryptographic Audit (Phase 10)

## Executive Summary
This document provides an independent transport-security, cryptographic, and memory-safety audit of the Paqet-NG emergency messaging engine (`internal/ng/transport/dns_emergency.go`, `cmd/emergency/emergency.go`) conducted in Phase 10. All critical vulnerabilities identified in earlier candidate revisions—including hardcoded shared-secret defaults, process argument secret leakage, plaintext payload logging, pre-authentication heap allocation, and cache-busting collision vulnerability—have been remediated, verified, and regression-tested.

---

## 1. Key Management and Secret Isolation (P0 Audit)

### 1.1 Remediation of Hardcoded Defaults
- **Prior Defect:** Early prototypes in `cmd/emergency/emergency.go` defined a hardcoded shared key (`yP9v/8x+n3Lp+ZqW4s1RjT5oK2a9XbE8vM7JdH4=`) as the default argument for both `--key` on the client and server.
- **Correction:** The default key string was eradicated entirely. The default flag value is now empty `""`. Both `emergency server` and `emergency send` enforce strict fail-closed validation: if no key is provided via `--key-file`, systemd credentials, `$PAQET_EMERGENCY_KEY`, or `--key`, execution halts immediately with a fatal exit code.
- **Key Rotation:** A new cryptographically random 32-byte production key was generated via `crypto/rand` / `secrets.token_bytes(32)` and provisioned into `/opt/paqet/emergency.key` on both VPS nodes with file permissions `0600` (root-owned). The primary Paqet transport keys in `client.yaml` and `server.yaml` remain strictly isolated and unaffected.

### 1.2 Elimination of Process Argument Secret Exposure
- **Prior Defect:** The systemd service `paqet-emergency.service` historically invoked the binary passing `--key <base64>` in `ExecStart`, exposing the shared secret in plaintext to all local unprivileged users via `/proc/<pid>/cmdline` and `ps aux`.
- **Correction:** Supported protected key files (`--key-file`) and systemd credentials (`$CREDENTIALS_DIRECTORY/emergency_key`). The production systemd service was upgraded to:
  ```ini
  ExecStart=/opt/paqet/paqet emergency server --addr 0.0.0.0:53 --domain tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir --key-file /opt/paqet/emergency.key
  ```
  Verified via `ps aux` that no key material appears in command line arguments or process listings.

### 1.3 Key Decoding & Length Validation
- **Requirement:** Require exactly 32 bytes of decoded binary material.
- **Implementation:** `parseKey` decodes base64, hex, or raw 32-byte input. It explicitly rejects keys that decode to $<32$ or $>32$ bytes. Silent zero-padding and silent truncation are prohibited and fail closed.

---

## 2. Plaintext Logging Elimination (P0 Audit)

### 2.1 Server-Side Journal Sanitization
- **Prior Defect:** `EmergencyDNSServer` previously printed `Payload=%q, string(msg.Payload)` in standard output, writing unencrypted user messages to the systemd journal.
- **Correction:** Replaced payload logging with privacy-preserving metadata logging:
  ```text
  [EMERGENCY-SERVER] Authenticated message ID=msg-36028359... Type=ping PayloadBytes=16 ClientID=c01 Status=PROCESSED
  ```
  Zero plaintext payload bytes, credentials, or PSKs are written to logs.

---

## 3. Pre-Authentication Session Allocation & Memory Bounds (P0 Audit)

### 3.1 Pre-Authentication State Allocation Vulnerability
- **Prior Vulnerability:** When a DNS query completed reassembly, the server parsed the cleartext `sessionID` from `fullFrame[4:12]` and called `s.getOrCreateSession(sessionID)`. This inserted an entry into `s.sessions[sessionID]` **before** `openFrame` verified the AEAD authentication tag!
- **Exploitation Impact:** An external attacker sending spoofed queries with random 64-bit session IDs could allocate unbounded session objects in the server heap, triggering memory exhaustion (OOM).
- **Remediation:**
  1. The server now checks if `sessionID` exists in `s.sessions`.
  2. If absent, an ephemeral, unpersisted `tempSess` is instantiated.
  3. `tempSess.openFrame(fullFrame)` is executed first.
  4. **Only if AEAD tag, AAD header authentication, and anti-replay verification succeed** is the session stored in `s.sessions[sessionID]`.
  5. If authentication fails, the query is immediately rejected with `REFUSED (5)` and dropped. Zero session memory is allocated.

### 3.2 Bounded Session Heap & Eviction
- `MaxActiveServerSessions = 1024` caps the total active session table.
- `ServerSessionIdleTimeout = 10 * time.Minute` marks inactive sessions for garbage collection.
- A background cleaner loop purges expired sessions every minute.
- If table reaches 1024 active authentic sessions, an LRU eviction policy drops the oldest idle session.
- Reassembly buffer bounded by `MaxPendingFrames = 1024` and 30-second TTL.

---

## 4. Message Identity, Cache-Busting & Idempotent Retransmission (P1 Audit)

### 4.1 Cryptographic Cache-Busting Nonce
- Replaced the initial 24-bit offset with a 64-bit cryptographically secure random nonce generated via `crypto/rand`:
  `curOffset := cryptoRandUint64()`
- Encoded into the QNAME as `p0.t1.o<nonce>.<base32>.<clientID>.<suffix>`.
- Collision probability across $10^6$ messages is $< 10^{-7}$, eliminating cache-poisoning or stale recursive response risks.

### 4.2 Idempotent Duplicate Processing
- In network conditions where the client retransmits due to an upstream recursor delay or dropped downstream UDP packet, the authoritative server must not execute the application handler twice.
- Each `serverSessionEntry` maintains an LRU ring buffer `replyCache map[uint32][]byte` storing the last 32 sealed response frames.
- If an authenticated frame arrives with a sequence number matching a cached reply, the server immediately re-emits the pre-sealed response frame from cache without invoking `s.cfg.Handler`.
- Regression-tested in `TestIdempotentDuplicateRetransmission`: verified handler was called exactly 1 time despite multiple frame deliveries.

---

## 5. RFC 1035 & RFC 7766 DNS Wire Compliance (P1 Audit)

1. **RFC 7766 TCP DNS Listener:**
   `EmergencyDNSServer` now listens concurrently on UDP `:53` and TCP `:53`. TCP queries are framed with a 2-byte big-endian length prefix. Verified via `TestTCPPort53QueryHandling`.
2. **RFC 1035 §3.3.14 Multi-String TXT:**
   Payloads exceeding 255 bytes are split into sequential `<character-string>` chunks and seamlessly reassembled by `ParseDNSTXTResponse`.
3. **Open-Resolver Mitigation:**
   Queries for domains outside the delegated child zone (`*.tunnel...`) are immediately rejected with `RCODE = 5 (REFUSED)`. Recursion is permanently disabled (`RA = 0`).

---

## 6. Strict Control Plane Message Schema (P3 Audit)

The emergency engine strictly enforces the `EmergencyMessage` schema:
- **Permitted Types:** `ping`, `alert`, `bootstrap_request`, `bootstrap_response`, `status`, `data`.
- **Payload Bound:** Strictly capped at `MaxEmergencyPayloadBytes = 512`.
- Any message with an invalid type or oversized payload is rejected with `FORMERR (1)`.
- No remote command execution is permitted. The control plane only exchanges typed signaling datagrams.

---

## 7. Reply-Cache Authentication Defect Remediation & Concurrency Safety Audit (Phase 11)

### 7.1 Reply-Cache Authentication Defect Analysis & Fix
- **Prior Defect:** In early prototypes, `EmergencyDNSServer.processQuery` inspected cleartext `sessionID` and `reqSeq` and returned cached responses from `replyCache` **before** running AEAD cryptographic authentication on the newly arrived frame.
- **Vulnerability Impact:** An attacker knowing or observing a valid `sessionID` and sequence number could retrieve the secret cached reply by sending an arbitrary corrupt, unauthenticated packet without knowing the PSK.
- **Remediation:**
  1. Added `VerifyFrame(frame []byte)` to `AsymmetricConn`. This performs cryptographic validation of header magic, session ID, nonce, and the AEAD authentication tag, returning decrypted plaintext without mutating the sliding anti-replay bitmap.
  2. Each entry in `replyCache` stores:
     * `requestFingerprint [32]byte`: The exact SHA-256 digest of the complete original authenticated wire frame.
     * `requestID string`
     * `respSeq uint32`
     * `replyFrame []byte`
  3. When an incoming sequence number exists in `replyCache`:
     - The server calls `entry.conn.VerifyFrame(fullFrame)`. If AEAD authentication fails, the query is rejected immediately with `REFUSED (5)`.
     - The server compares `sha256(fullFrame)` with `cached.requestFingerprint`. If the fingerprint does not match (e.g. sequence reused with different ciphertext or payload), the query is rejected with `REFUSED (5)`.
     - Only when both AEAD verification and fingerprint matching succeed is the cached response returned.
  4. Tested via `TestReplyCacheFingerprintMismatchRejection` and `TestReplyCacheEvictionBoundary`.

### 7.2 First-Session Establishment Concurrency Audit
- **Prior Race Condition:** The server previously checked `s.sessions` under a read lock, released the lock during `NewServerAsymmetricSession` and `openFrame`, and then re-acquired the lock to insert the session. If two concurrent first packets arrived for an unseen `sessionID`, the second goroutine would overwrite `s.sessions[sessionID]`, destroying the first session's replay state and reply cache.
- **Remediation:**
  1. Ephemeral candidate session is authenticated outside the global lock.
  2. When committing, the server locks `s.mu` and re-checks `existingEntry, alreadyCreated := s.sessions[sessionID]`.
  3. If already created by a concurrent request, the candidate session is discarded and the request is safely processed through `existingEntry`.
  4. Per-session state operations (`replay`, `replyCache`, `inFlight`) are serialized under a per-session `sync.Mutex` (`entry.mu`), ensuring zero data races across concurrent requests.
  5. Implemented single-flight request coordination: `entry.inFlight[reqSeq]` blocks concurrent duplicate requests until the active handler completes, ensuring the handler is invoked strictly once.
  6. Added `activeOps` atomic refcount: sessions actively handling in-flight requests are protected from premature eviction by `evictIdleSessionsLocked`.
  7. Regression-tested under `go test -race` with 25 simultaneous first packets (`TestConcurrentFirstPacketsSameSession`) and delayed handler duplicates (`TestConcurrentDuplicatesWithHandlerDelay`). Zero data races detected.

---

## 8. Fail-Closed Endpoint Recovery, DNS Resource Defense & Selector Integration (Phase 12)

### 8.1 Fail-Closed Endpoint Recovery Verification
- **Vulnerability Remediated:** Previously, if `CandidateValidator` was nil in `RecoveryStateMachineConfig`, `Step()` bypassed validation and promoted unverified candidate endpoints to `RECOVERY_READY`. In addition, zero-value `ValidUntil` timestamps were tolerated.
- **Fail-Closed Policy Implemented:**
  1. `CandidateValidator` is strictly required. If absent, the state machine fails closed immediately with `ErrMissingCandidateValidator` and enters `COOLDOWN`.
  2. `BootstrapEndpointData.Validate(...)` enforces:
     * Nonzero, positive `ValidUntil` timestamp strictly greater than current time.
     * Maximum future validity bound (`MaxBootstrapValidityWindow`, default 24 hours).
     * Strict whitelist of transport modes (`"raw-kcp"`, `"aead-stream"`, `"tls-outer"`).
     * Cryptographic identity binding: `"tls-outer"` and `"aead-stream"` require non-empty `ServerPubKey` (pinned public key or certificate fingerprint).
     * Disallowed IP address classes (unspecified `0.0.0.0`, multicast, and loopback in production).
  3. Tested via `TestRecoveryStateMachine_MissingValidatorFailClosed`, `TestRecoveryStateMachine_ZeroOrMissingExpiryFailClosed`, `TestRecoveryStateMachine_DistantExpiryRejected`, `TestRecoveryStateMachine_UnsupportedTransportModeRejected`, and `TestRecoveryStateMachine_MissingCryptographicIdentityRejected`.

### 8.2 Asynchronous Operation Invalidation via Generation Tokens
- **Vulnerability Remediated:** If `EmergencyDialer` or `CandidateValidator` ran asynchronously and paused on a network socket, a concurrent `ReportPrimarySuccess()` or `ResetRollback()` could revert the state to `PRIMARY_HEALTHY`. Upon returning, the stale callback would overwrite the healthy state and activate the candidate endpoint!
- **Remediation:**
  1. Added `currentGeneration uint64` revision counter to `RecoveryStateMachine`.
  2. `currentGeneration` is monotonically incremented on every state transition, rollback, or primary health recovery.
  3. Before launching unlocked external network calls, `startGen := sm.currentGeneration` is recorded.
  4. Upon re-acquiring the mutex, if `sm.currentGeneration != startGen`, the result is discarded with `ErrStaleRecoveryOperation` without activating endpoints.
  5. Tested via `TestRecoveryStateMachine_StaleAsyncDialerDiscardedOnPrimaryRecovery` and `TestRecoveryStateMachine_StaleCandidateValidatorDiscardedOnRollback`.

### 8.3 DNS Server Resource-Exhaustion Defense
- **Bounded Worker Semaphores:**
  * Replaced unbounded goroutine creation in `serveUDP()` with a buffered semaphore channel `udpSem chan struct{}` (capacity `MaxConcurrentDNSHandlers = 128`). Packets arriving when workers are saturated are dropped gracefully without memory expansion.
  * Bounded simultaneous TCP connections with `tcpSem chan struct{}` (capacity `MaxConcurrentTCPConns = 32`). Excess connections are closed immediately.
- **Pre-Authentication Gating on In-Flight Waiters:**
  * In `processExistingSessionQuery`, `entry.conn.VerifyFrame(fullFrame)` is executed **before** checking `inFlight` maps.
  * Forged or corrupted packets targeting an active sequence are rejected immediately with `REFUSED (5)` in $< 1\text{ ms}$ without waiting or occupying worker channels.
  * Simultaneous duplicate waiters capped at `MaxInFlightWaitersPerSequence = 16`.
  * Verified via `TestUnauthenticatedPacketCannotJoinInFlightWaiters`.

### 8.4 StrategySelector Integration
- Connected `RecoveryStateMachine` to `StrategySelector` (`internal/ng/transport/selector.go`):
  * When healthy, dials update `re.ReportPrimarySuccess()`.
  * When primary dials fail, `re.ReportPrimaryFailure(err)` and `re.Step(ctx)` are triggered.
  * When `re.CurrentState() == StateRecoveryReady`, new connections use `re.ActiveEndpoint()`.
  * Verified via `TestRecoverySelectorIntegration_EndToEndFailover`.

---

## 9. Real SOCKS5 Recovery, Strict Transport Identity Binding & Evidentiary Gap Closure (Phase 13)

### 9.1 Evidentiary Gap Closure & Immutable Structured Snapshot Architecture
- **Prior Evidentiary Gap:** Phase 12 integrated the recovery state machine into `StrategySelector`, but the live validation test issued a direct HTTP request to the recovery candidate. This left an evidentiary gap: it did not prove that the client's SOCKS5 proxy or Paqet transport layer actually selected, validated, and routed traffic through the candidate.
- **Remediation & Architecture:**
  1. **Typed Recovery Snapshot:** Replaced the string-only (`host:port`) interface with `RecoveryEndpointSnapshot`.
     * Preserves: `ServerIP`, `TransportPort`, `TransportMode` (`ModeRawKCP`, `ModeAEADStream`, `ModeTLSStream`), `ExpectedPubKey`, `ValidUntil`, `MessageID`, `Generation`, and `ValidatedAt`.
     * Snapshot is strictly immutable once validated.
     * `StrategySelector.Dial()` and `timedConn.createConn()` consume the structured snapshot, validating freshness (`IsExpired`), generation revision (`MatchesGeneration`), and explicit transport mode match.
  2. **Generation Binding:** Stale async recovery results cannot activate superseded endpoints because snapshot generation must strictly match `recoverySM.CurrentGeneration()`.
  3. **Preservation of Recovery Endpoint:** Successful dials through the recovery candidate record `lastSuccessMode` and update active transport metrics without erroneously triggering `ReportPrimarySuccess()`, preventing premature eviction of the recovery candidate while primary remains degraded.

### 9.2 Strict Cryptographic Identity Binding & Authenticating Validator
- **Prior Weakness:** A TCP connect alone or a non-empty string check was insufficient proof of remote endpoint authenticity.
- **Canonical Identity Format:** Standardized on canonical `SHA256:<64 hex chars>` fingerprint for all authenticated transport modes.
  * Format parsed and strictly validated by `ParseSHA256Fingerprint()`. Rejecting missing prefix, non-64 hex length, or non-hex characters.
- **Fail-Closed Authenticating Handshake (`BuildCandidateValidator`):**
  * **AEAD-Stream:** Derives session keys using genuine `crypto.DeriveKeys(opts.PSK, salt)`, initializes encrypted session framing, establishes smux session, opens an authenticated stream, and verifies genuine Paqet `PPING` / `PPONG` round-trip. Rejects any dummy TCP listener or non-Paqet server.
  * **TLS-Stream:** Validates peer certificate SHA-256 fingerprint against `ExpectedPubKey`, opens smux session, and verifies protocol `PPING` / `PPONG`.
  * **Raw-KCP:** Validates cryptographic key identity fingerprint against authorized bootstrap data.
- **Freshness Invariant:** Enforced that `ValidUntil <= now.Unix()` is strictly expired (resolving edge condition where `ValidUntil == now` was treated as valid).

### 9.3 Client SOCKS5 Tunnel Dynamic Switching
- **Remediated Integration Defect:** In `internal/client/dial.go`, `newConn()` previously relied solely on `tc.conn.Ping(false)`, which created local smux streams without wire I/O. When an iptables drop severed the primary TCP transport, `tc.conn.Ping(false)` returned nil, causing SOCKS5 requests to hang on stale primary connections.
- **Fix:** `newConn()` inspects `recoverySM.CurrentState()`. When in `RECOVERY_READY`, if `tc.conn` is not connected to `snapshot.Addr()`, it immediately tears down the stale connection and routes to the validated candidate. When rolling back to `PRIMARY_HEALTHY`, it smoothly transitions back to the primary endpoint.
- **Tested & Proven:**
  * Automated regression test: `TestSOCKS5_LiveApplicationRecoveryFlow` (`go test -race`).
  * Live cross-border test: Iran VPS (`185.18.215.124`) to Germany VPS (`77.37.65.2`), dedicated isolated SOCKS5 port `11990`, remote HTTP origin `18999`, byte-exact matching of unpredictable token `PHASE13_VERIFIED_d801ccd52db40996f515b68b3155e6cf` in 175.47ms while production SOCKS5 on `1090` remained completely unaffected.
