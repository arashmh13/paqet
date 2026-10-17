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

---

## 10. Complete Transport Authentication, Configurable Mode-Aware Bootstrap & Connection Identity Tracking (Phase 14)

### 10.1 Explicit, Versioned Endpoint Identity Model
- **Prior Semantic Ambiguity:** Earlier bootstrap models stored key fingerprints in a field named `ServerPubKey`. This created dangerous ambiguity: symmetric PSK fingerprints were labeled as public keys, and the validator lacked explicit identity scheme tagging across `aead-stream`, `tls-outer`, and `raw-kcp`.
- **Version 2 Explicit Identity Architecture:**
  1. `EndpointIdentityType` defines three explicit types:
     * `IdentityTypePSKID` (`"psk-id"`): Identifies AEAD or Raw-KCP endpoints via the SHA-256 fingerprint of the shared symmetric key.
     * `IdentityTypeCertPin` (`"cert-pin"`): Identifies TLS endpoints via the SHA-256 fingerprint of the server's leaf X.509 certificate.
     * `IdentityTypePubKeyPin` (`"pubkey-pin"`): Identifies TLS or asymmetric endpoints via the SHA-256 fingerprint of the server's public key.
  2. Mode-Specific Enforcement:
     * `ModeTLSStream` strictly requires `IdentityTypeCertPin` or `IdentityTypePubKeyPin`. Attempting to pair TLS with `psk-id` fails closed.
     * `ModeAEADStream` and `ModeRawKCP` strictly require `IdentityTypePSKID`. Attempting to pair AEAD or Raw-KCP with `cert-pin` fails closed.
  3. `BootstrapEndpointData` and `RecoveryEndpointSnapshot` preserve `IdentityType`, `IdentityValue`, `RecoveryGen`, and `RequestID`.

### 10.2 Genuine Raw-KCP Candidate Handshake Validation
- **Prior Defect:** In early iterations, `ModeRawKCP` candidate validation merely compared the configured local key fingerprint without establishing a network connection or authenticating the remote server.
- **Remediation & Handshake Requirements:**
  1. `BuildCandidateValidator` now requires `RawKCPDialer` for `ModeRawKCP`.
  2. The validator dials the candidate address and completes an actual raw-KCP packet handshake.
  3. Establishes an smux stream over the connection.
  4. Writes `protocol.PPING` and requires `protocol.PPONG` within a strict context deadline.
  5. Deterministically closes temporary socket resources.
  6. Verified across 8 negative and positive adversarial tests (`TestRawKCPCandidateValidation_AllNegativeAndPositiveCases`): no listening server, plain TCP on port, wrong key, pin mismatch, invalid protocol response, cancellation/timeout, and post-validation failure.

### 10.3 Mode-Aware, Configurable Bootstrap Management
- **Prior Hard-Coding:** The authoritative emergency DNS server previously hard-coded the Germany server IP (`77.37.65.2`) and derived identity values solely from the emergency PSK.
- **Remediation:**
  1. Introduced `BootstrapManager` and `BootstrapEndpointRecord` in `dns_emergency.go`.
  2. Supports explicit candidate configuration via `--bootstrap-config`, `--bootstrap-ip`, `--bootstrap-cert`, `--bootstrap-key-file`, and `--bootstrap-pin`.
  3. `computeCertFingerprint` extracts genuine leaf certificate SHA-256 digests from PEM certificates at startup.
  4. Fails fast at startup if a requested mode lacks required identity credentials (e.g. TLS without certificate or pin).
  5. When responding to `bootstrap_request`, maps the requested mode to the authorized record and binds response to `RecoveryGen` and `RequestID`.
  6. Leaves `ServerPubKey` empty when `IdentityValue` is present, saving 80+ bytes and keeping DNS replies compact for single-datagram recursive DNS traversal.

### 10.4 Typed Connection Identity Tracking & Elimination of Implicit Fallback
- **Prior Defect:** `timed_conn.go` previously checked only `snapshot.Addr()`. A mode or generation change at the same IP:port was ignored. Furthermore, candidate dial errors fell through to the primary transport selection.
- **Remediation:**
  1. Added `ConnectionIdentity` tracking `RemoteAddr`, `TransportMode`, `Generation`, `IdentityType`, `IdentityValue`, and `IsRecovery`.
  2. `desiredIdentity()` dynamically computes the expected connection parameters based on recovery state and snapshot generation.
  3. `newConn()` detects any mismatch (`!currentIdentity.Matches(desired)`) and recreates the connection.
  4. Eliminated implicit fallback: candidate dial errors report failure to `RecoveryStateMachine` and immediately return an actionable error. Dials never fall through to the primary transport during `RECOVERY_READY`.
  5. Bounded `newStrm` retry loop (max 5 retries with exponential backoff) with strict context deadline handling.
  6. Audited `sendTCPF`: disabled on candidate connections and guarded against execution on dying sockets.
  7. Tested live across Iran ⇄ Germany using public recursive resolver `8.8.8.8:53` with byte-exact token match (`PHASE14_PROVEN_adc8bdad43def3706c34e7741adf37dd`). Production SOCKS5 healthy.

---

## 11. Fail-Closed Configuration, End-to-End Identity Continuity & Measured Recovery Timeline (Phase 15)

### 11.1 Complete Elimination of Implicit Bootstrap Defaults
- **Prior Defect:** In Phase 14, `setupBootstrapManager()` implicitly fell back to `77.37.65.2` if no `--bootstrap-ip` was provided.
- **Remediation & Fail-Closed Startup Invariants:**
  1. Removed all implicit IP, port, mode, and key fallbacks.
  2. A production emergency server strictly fails startup unless an explicit configuration is supplied via `--bootstrap-config <file.json>`, `--bootstrap-ip <ip>`, or explicitly set to messaging-only mode via `--disable-bootstrap`.
  3. Added deterministic JSON configuration loading and validation:
     * Disallowed IP address classes (unspecified `0.0.0.0`, multicast `224.0.0.0/4`, link-local unicast/multicast) are rejected at configuration time.
     * Ports outside 1-65535 rejected.
     * Unsupported transport modes rejected with explicit fail-closed errors.
     * Duplicate conflicting records for the same transport mode rejected.
  4. Tested via unit suite (`TestEmergencyServerStartup_*` in `cmd/emergency/emergency_test.go`): all missing configurations fail startup with explicit actionable errors.
  5. Updated systemd examples to use protected, explicit configuration paths (`example/systemd/paqet-emergency.service.example` and `example/bootstrap-candidates.json.example`).

### 11.2 Complete Separation of Emergency-Channel Identity from Data-Transport Identity
- **Prior Defect:** When neither `--bootstrap-key-file` nor `--bootstrap-pin` was provided, `setupBootstrapManager()` previously computed the `psk-id` fingerprint from `emergencyPSK`, conflating control-plane and data-plane credentials.
- **Remediation:**
  1. Removed `emergencyPSK` from `setupBootstrapManager()`.
  2. For AEAD and Raw-KCP, `--bootstrap-key-file` or `--bootstrap-pin` is strictly mandatory.
  3. For TLS, `--bootstrap-cert` or `--bootstrap-pin` is strictly mandatory.
  4. Added `Provenance` configuration metadata (e.g. `key_file:emergency.key`, `cert_file:server.crt`, `pin:SHA256:...`) to record identity origins without leaking secret key material.
  5. Verified on live Germany infrastructure: starting without explicit candidate key/cert fails startup immediately with exit code 1.

### 11.3 End-to-End Identity Continuity (Validation-to-Dial Binding)
- **Prior Defect:** After candidate validation succeeded, the client dial path dialed candidate addresses without re-verifying that local transport credentials matched the authorized snapshot fingerprint, and TLS dials did not enforce certificate pins on live application connections.
- **Remediation:**
  1. Implemented `stream.DialTLSPinned()` in `internal/tnet/stream/tls.go`: verifies leaf X.509 certificate SHA-256 fingerprint (or public-key fingerprint) directly on the live TLS connection after handshake completion. Mismatches trigger immediate socket termination and fail closed.
  2. In `timedConn.createConn()`:
     * For AEAD: verifies `sha256(obfs.Key)` matches `snapshot.GetIdentityValue()`.
     * For Raw-KCP: verifies `sha256(kcpKey)` matches `snapshot.GetIdentityValue()`.
     * For TLS: invokes `stream.DialTLSPinned()` enforcing `snapshot.GetIdentityValue()`.
     * Mismatches fail closed before any application traffic is transmitted.
  3. Snapshot Invalidation on Dial Race: In `newConn()`, re-checks `tc.desiredIdentity()`. If a rollback or generation change occurred while dialing was in flight, the newly established connection is immediately closed and rejected.
  4. Tested via adversarial unit tests: `TestTimedConn_CandidateKeyMismatchFailsClosed` and `TestTimedConn_GenerationChangeOrRollbackDuringDialRejectsConnection`.

### 11.4 Conservative EDNS0 Limits (1232 Bytes) & Measured RFC 7766 TCP Fallback
- **Prior Weakness:** The emergency DNS client previously advertised an arbitrary 4096-byte EDNS0 buffer.
- **Remediation:**
  1. Defaulted client UDP advertisement to modern DNS Flag Day recommended conservative buffer size: `DefaultEDNSUDPPayloadSize = 1232` bytes, avoiding IPv4/IPv6 fragmentation across all standard MTUs.
  2. Configurable via `EmergencyDNSClientConfig.EDNSBufferSize`.
  3. Server UDP response generation capped to `MaxSafeDNSUDPPayloadSize = 1400` bytes. If a response exceeds safe UDP size, the server sets `TC = 1` (Truncated) with `ANCOUNT = 0`.
  4. Implemented `EmergencyDNSClient.attemptTCPExchange()`: when receiving `TC = 1`, the client automatically falls back to RFC 7766 TCP port 53.
  5. Tested via `TestEDNS0_ConservativeDefaultAndCustomBufferSize`, `TestEDNS0_ParseEDNSBufferSize_MalformedInputs`, `TestEDNS0_ResponseTruncationWhenExceedingLimit`, and `TestEDNS0_TCPPort53FallbackOnTruncation`.

### 11.5 Monotonic Failover Timeline & Full Latency Telemetry
- **Prior Evidentiary Gap:** Prior reports highlighted the post-activation HTTP request latency (~179 ms) without recording the full failure-to-restored-traffic timeline.
- **Remediation & Live Empirical Validation:**
  Built monotonic timeline recording in `scripts/phase15_recovery/main.go` and verified live across Iran (`185.18.215.124`) ⇄ Germany (`77.37.65.2`) using public recursive resolver `8.8.8.8:53`:
  * T0 (Primary Failure Injected): 0.00 ms (iptables DROP on :18088)
  * T1 (Failure Threshold Crossed): 35.40 ms (State -> PRIMARY_DEGRADED)
  * T2 (Degraded Hysteresis Ended): 96.02 ms (60.62 ms hysteresis interval)
  * T3 / T4 (DNS Control-Plane Exchange): 4639.34 ms (Recursive DNS traversal via 8.8.8.8 across international borders)
  * T5 / T6 (Candidate Validation): 0.00 ms (Cached / instantaneous)
  * T7 (State Activation): 4905.79 ms (RECOVERY_READY)
  * T8 / T9 (Application Request through SOCKS5 11990): 87.94 ms
  * **Total Failover Duration (T9 - T0): 4993.79 ms**
  * Unpredictable Token Verified Byte-Exact: `PHASE15_PROVEN_fd06fd5251a6c37143e21b0489f9a5b0`
  * Raw Telemetry Artifact: `docs/research/recovery_socks5_live_audit_phase15.json`
  * Production SOCKS5 proxy on `127.0.0.1:1090` verified healthy (`pong`) throughout.

---

## 12. Recovery Telemetry Correction, DNS Sizing Enforcement & Multi-Authority Cryptographic Safety (Phase 16)

### 12.1 Root Cause & Resolution of Candidate Validation Timing Anomaly
- **Prior Telemetry Defect:** In Phase 15, `recovery_socks5_live_audit_phase15.json` reported `candidate_validation_rtt_ms` as approximately 0.001 ms, while state transition history showed 178 ms between `BOOTSTRAP_RECEIVED` and `RECOVERY_READY`.
- **Root Cause Identified:** `sm.Step(ctx)` performs both `EmergencyDialer` (DNS exchange) and `CandidateValidator` (remote handshake) before returning. In Phase 15's script, `t4` was taken after `Step()` had already finished both operations. Lines 360-363 took `t5 := t4` and `t6 := time.Now()`, measuring only CPU delta between two sequential statements rather than the handshake itself. Furthermore, `production_health` reported `"UNKNOWN"` because `http.Get("http://127.0.0.1:8999/ping")` made a direct unauthenticated loopback request rather than querying through the authenticated SOCKS5 proxy on `127.0.0.1:1090`.
- **Remediation & Exact Milestone Tracking:**
  1. Wrapped `EmergencyDialer` with monotonic timer callbacks to capture `T3` (DNS query dispatch) and `T4` (DNS response receipt).
  2. Wrapped `CandidateValidator` with monotonic timer callbacks to capture `T5` (candidate handshake start) and `T6` (candidate handshake completion).
  3. `T7` captured immediately when `Step()` commits `RECOVERY_READY`.
  4. Built and validated `ValidateAndReconcileTimeline()` (`internal/ng/transport/timeline_validator.go`): enforces strict monotonic ordering ($T_i \le T_{i+1}$) and mathematical reconciliation ($\sum \text{intervals} + \text{unaccounted\_overhead} = \text{total}$).
  5. Implemented authenticated SOCKS5 health check querying through `127.0.0.1:1090` (`arash:arash`) returning `HEALTHY` and `"pong"` in 132.24 ms.
  6. Reconciled Live Results (Phase 16):
     * DNS Exchange RTT: **160.63 ms**
     * Candidate Validation RTT: **178.12 ms** (matching wire handshake latency)
     * Total Failover Time: **505.95 ms**
     * Unaccounted Overhead: **0.000 ms** (exact mathematical identity)
     * Logged to `docs/research/recovery_socks5_live_audit_phase16.json`.

### 12.2 Strict EDNS Response Sizing & RFC 6891 Compliance
- **Prior Weakness:** `ParseEDNSBufferSize()` previously assumed the first bytes following the Question section were an OPT record, and response generation did not consistently respect valid buffer advertisements below 1232 bytes (such as the standard 512-byte limit when EDNS is absent).
- **Remediation & Strict Sizing Invariant:**
  1. Implemented complete RFC 6891 Additional Section parser in `ParseEDNSOption()`: traverses Question, Answer, Authority, and Additional sections using wire-format domain name decompression (`skipDomainName`) and record skipping (`skipResourceRecord`).
  2. Confirms that NAME is root (`0x00`), TYPE is 41 (`OPT`), and extracts the advertised buffer size.
  3. Enforced explicit sizing rule:
     $$\text{effective\_udp\_limit} = \min(\text{server\_udp\_cap}, \text{validated\_client\_advertisement})$$
     * No EDNS present: strictly 512 bytes (`ARCOUNT = 0` in response).
     * Valid EDNS (512–1400 bytes): strictly respected.
     * Advertisements > 1400 bytes: clamped to 1400 bytes.
  4. When serialized response exceeds `effective_udp_limit`, the server returns a standards-compliant truncated packet with `TC = 1` (`0x0200`) and `ANCOUNT = 0`.
  5. Verified across sizes 512, 768, 1024, 1232, 1400, and 4096 in `TestEDNS0_AllAdvertisedSizesAndSizingRule`.

### 12.3 Cryptographic Nonce & Key Separation in Multi-Authoritative Mode
- **Prior Security Hazard:** In asymmetric transport, downstream AEAD nonces were derived from `(sessionID, seq, role)`. Two independent servers sharing the same PSK answering the same request at sequence 1 derived identical `s2c` keys and constructed identical nonces. If their response payloads differed, an identical key/nonce pair was used to encrypt different plaintexts (a catastrophic AES-GCM nonce collision leaking the GHASH key).
- **Cryptographic Domain Separation Architecture (RFC 5869 HKDF):**
  1. Introduced explicit `ServerID` binding in key derivation:
     $$\text{PRK} = \text{HKDF-Extract}(\text{SHA-256}, \text{IKM}=\text{PSK}, \text{salt}=\text{sessionID})$$
     $$\text{c2sKey} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{"paqet-ng-v3-c2s"}, L=32)$$
     $$\text{s2cKey} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{"paqet-ng-v3-s2c:"} \mathbin{\Vert} \text{ServerID}, L=32)$$
  2. Client-to-server (`c2s`) keys remain shared across servers so that any authorized server can decrypt upstream queries.
  3. Server-to-client (`s2c`) response keys are cryptographically isolated per `ServerID`. Server A (`srv-de-01`) and Server B (`srv-nl-01`) derive mathematically distinct response keys, preventing cross-server key/nonce reuse even at identical sequence numbers.
  4. Frame Framing v3 (`AsymmetricMagicV3 = 0x50415143`): includes `ServerIDLen` and `ServerID` in the unencrypted authenticated header (authenticated as AAD).
  5. Per-Server Replay Filtering: The client maintains separate replay windows (`c.serverReplay[serverID]`), allowing independent servers to maintain their own sequence counters without causing false replay rejections on the client.
  6. Client Authorization Whitelist (`AuthorizedServers`): Client verifies that the answering `serverID` is authorized by its configuration policy, rejecting rogue server responses fail-closed.
  7. Adversarially verified via `TestMultiAuthoritative_CryptographicSafetyAndKeyNonceSeparation` and `TestMultiAuthoritative_FailoverAndServerRestart`.

---

## 13. Authenticated Server Identity, Fail-Closed Authorization & AEAD Lifecycle Safety (Phase 17)

### 13.1 Cryptographic Per-Server Response Secrets (Elimination of Shared-PSK Impersonation)
- **Prior Architectural Defect:** In Phase 16, server response keys were derived from HKDF context incorporating `ServerID`, but using the root shared PSK (`IKM = PSK`). Any server instance holding the shared PSK could compute the response key for *any* `ServerID` merely by passing that string into HKDF. A malicious or compromised server could thus forge responses claiming another server's identity.
- **Cryptographic Trust Model Redesign:**
  1. Decoupled upstream query decryption from downstream response authentication:
     $$\text{PRK}_{\text{c2s}} = \text{HKDF-Extract}(\text{SHA-256}, \text{IKM}=\text{c2sPSK}, \text{salt}=\text{sessionID})$$
     $$\text{c2sKey} = \text{HKDF-Expand}(\text{PRK}_{\text{c2s}}, \text{info}=\text{"paqet-ng-v3-c2s"}, L=32)$$
     $$\text{PRK}_{\text{s2c}} = \text{HKDF-Extract}(\text{SHA-256}, \text{IKM}=\text{ServerResponseSecret}, \text{salt}=\text{sessionID})$$
     $$\text{s2cKey} = \text{HKDF-Expand}(\text{PRK}_{\text{s2c}}, \text{info}=\text{"paqet-ng-v3-s2c:"} \mathbin{\Vert} \text{ServerID}, L=32)$$
  2. Each authoritative server instance is provisioned with its own distinct 32-byte response secret (`ServerSecret`), held exclusively by that node.
  3. The client maintains an authorized server map (`map[string][]byte`): `ServerID -> ResponseSecret`.
  4. Server A (holding `secretA`) cannot derive Server B's response key (`s2cKey`), even if it knows Server B's `ServerID` and the shared `c2sPSK`.
  5. Verified via `TestAsymmetric_DistinctServerSecretsPreventImpersonation`: a rogue server attempting to forge Server B's response fails AEAD message authentication tag verification on the client.

### 13.2 Immutable Server Identity & Canonical Validation
- **Prior Defect:** `AsymmetricConn.SetServerID()` allowed mutating server identity after key initialization, which could decouple header identity from the active encryption key.
- **Remediation:**
  1. Removed `SetServerID()` and `SetAuthorizedServers()` setter methods entirely.
  2. Server identity and keys are derived atomically and immutably at session construction (`NewServerAsymmetricSessionWithID`).
  3. Implemented `ValidateServerID()`: enforces canonical identity format (3–64 characters, lowercase alphanumeric, `-`, `.`, `_`). Malformed identities fail startup fail-closed.
  4. Duplicate server IDs in client authorization policies are rejected at configuration time.

### 13.3 Mandatory Nonempty Authorization Policy & Legacy v2 Fail-Closed Rejection
- **Prior Defect:** Clients with empty authorization allowlists silently accepted any server ID, and legacy v2 frames followed a separate code path that bypassed server ID validation.
- **Remediation:**
  1. Multi-authoritative clients strictly require a nonempty authorization allowlist. Empty or nil allowlists return `ErrEmptyServerAllowlist` fail-closed.
  2. Multi-authoritative sessions disable legacy v2 frames (`allowLegacyV2 = false`). Any legacy v2 frame (`0x50415141`) presented to a v3 client is rejected with `ErrLegacyProtocolDisabled`.
  3. Verified via `TestAsymmetric_MandatoryNonemptyAllowlist` and `TestAsymmetric_LegacyV2FramesRejectedByDefault`.

### 13.4 32-bit Sequence Exhaustion & AEAD Lifecycle Nonce Safety
- **Prior Hazard:** Nonces are constructed using big-endian 32-bit sequence numbers. An atomic increment (`sendSeq.Add(1)`) on an active or long-running session could overflow from $2^{32}-1$ to 0, causing catastrophic nonce reuse under the same AEAD key.
- **Remediation:**
  1. Established `MaxSafeSequenceNumber = 0xFFFFFFF0` ($2^{32} - 16$).
  2. In `NextSendSeq()`: atomically inspects sequence counter. If counter reaches or exceeds `MaxSafeSequenceNumber`, it stops cleanly and returns `ErrSequenceExhausted`. It never wraps around to 0.
  3. In `sealFrame()`: checks `seq >= MaxSafeSequenceNumber` and rejects frame sealing with `ErrSequenceExhausted`.
  4. Tested via `TestAsymmetric_SequenceExhaustionFailsSafely`: verified counter halts at boundary without overflow or wraparound.

### 13.5 DNS Attempt Instrumentation Remediation
- **Prior Telemetry Defect:** In Phase 16, `recovery_socks5_live_audit_phase16.json` recorded attempt 0 as `SUCCESS` while simultaneously retaining `error = "invalid txt response format"`.
- **Root Cause & Remediation:**
  1. A transient parsing error inside a packet reception loop populated `rec.Error`. When a valid packet was subsequently received within the same attempt, `rec.Status` was set to `SUCCESS`, but `rec.Error` was not reset to `""`.
  2. Defined distinct terminal statuses: `DNSAttemptStatusSuccess`, `DNSAttemptStatusTimeout`, `DNSAttemptStatusTruncatedTCP`, `DNSAttemptStatusProtocolFail`, `DNSAttemptStatusParseFail`, `DNSAttemptStatusAuthFail`, `DNSAttemptStatusAppValidationFail`, `DNSAttemptStatusCanceled`.
  3. In both UDP and TCP exchange loops: `rec.Error = ""` explicitly reset upon matching `expectedMsgID`.
  4. Implemented `(r *DNSQueryAttemptRecord) Validate()`: rejects contradictory SUCCESS records with non-empty error fields, missing authentication, missing ServerID, negative intervals, or non-monotonic timestamps.
  5. Tested via `TestDNSQueryAttemptRecord_Validation`.

### 13.6 Two-Authoritative Cross-Server Readiness Verification
- Verified via `TestPhase17_TwoAuthoritativeReadinessSuite`:
  * Dual independent servers Server A (`srv-de-01`) and Server B (`srv-nl-01`) running with distinct secrets.
  * Legitimate query to Server A verified.
  * Server A stopped; client automatically fails over to Server B, decrypts authenticated reply, and verifies `ServerID = srv-nl-01`.
  * Key revocation tested: removing Server B from client allowlist causes immediate fail-closed rejection.
- Live Verified Across Iran ⇄ Germany:
  * Measured monotonic failover: failure detection 38.95 ms, hysteresis 60.78 ms, signaling dispatch 0.41 ms, DNS exchange 1926.29 ms, validation dispatch 0.21 ms, candidate validation 177.03 ms, state activation 0.08 ms, post-activation app RTT 87.22 ms; total failover duration 2291.58 ms.
  * Unaccounted overhead: **0.000 ms** (exact mathematical identity).
  * Validated 2 DNS attempt records (Attempt 0: `TIMEOUT` via 8.8.8.8; Attempt 1: `SUCCESS` via 1.1.1.1 without contradictory error).
  * Production SOCKS5 on `127.0.0.1:1090`: `HEALTHY`, `"pong"` in 109.83 ms.
  * Audit Artifact: `docs/research/recovery_socks5_live_audit_phase17.json`.

## 14. Phase 18 Audit: Mandatory Server Credentials, Shared-PSK Elimination, Session-Key Uniqueness & Trust Boundary Definition

### 14.1 Complete Elimination of Shared-PSK Fallback in Multi-Authoritative Path
- **Vulnerability Identified:** In Phase 17, `crypto.DeriveServerTrafficKeys` and `transport.VerifyFrameWithServerID` allowed `serverResponseSecret` to default to `c2sPSK` when `serverSecret` was nil or empty. This allowed a named server to accidentally operate using the client-to-server root PSK for response sealing, creating an impersonation hazard where any entity holding the shared upstream PSK could forge downstream responses.
- **Architectural Remediation (Fail-Closed):**
  1. Updated `crypto.DeriveServerTrafficKeys` to strictly require `len(serverSecret) == 32`. A nil or empty secret returns `ErrMissingResponseSecret`; a malformed length returns `ErrInvalidResponseSecret`. Implicit fallback to PSK was completely removed.
  2. Isolated single-server legacy operation behind `crypto.DeriveLegacySingleServerTrafficKeys`, which is strictly confined to legacy single-server constructors (`NewServerLegacyAsymmetricSession`, `NewClientLegacyAsymmetricSession`).
  3. In `transport.VerifyFrameWithServerID`, multi-server clients strictly reject frames missing valid server IDs or possessing missing/malformed response secrets, completely removing the `resSecret = c.psk` fallback.
  4. Tested via `TestPhase18_MandatoryCredentialsAndImmutabilitySuite` and `TestDeriveServerTrafficKeys_MultiServerValidation`.

### 14.2 Fail-Closed Constructor Validation & Immutability via Defensive Slice Cloning
- **Credential Immutability:** Passing mutable byte slices to constructors creates a security hazard if the caller later modifies the slice in memory.
- **Remediation:**
  1. `NewServerAsymmetricSessionWithID` and `NewClientAsymmetricSessionWithServers` create independent byte slice clones (`append([]byte(nil), secret...)`) of all key material and server identities upon initialization.
  2. Identity metadata and derived keys are bound atomically at construction time; mutable setters are prohibited.
  3. Verified via `TestPhase18_MandatoryCredentialsAndImmutabilitySuite` Test 8: mutating caller slice memory post-construction leaves session cryptographic state unaltered.

### 14.3 Startup Contract & Deployment Audits
- **CLI Startup Hardening:**
  1. Removed default `"ns-de-01"` from `--server-id`. Named servers require explicit `--server-id` and `--server-secret-file`.
  2. Reserved server IDs (`"default"`, `"legacy"`) are rejected fail-closed for multi-server instances.
  3. Servers attempting startup without `--server-secret-file` abort with exit code 1 prior to opening DNS listener sockets.
  4. Legacy single-server operation requires explicit `--legacy-single-server` flag and logs a high-visibility warning that multi-authoritative guarantees are disabled.
  5. Verified via `TestEmergencyServerStartup_MultiServerCredentialValidation` and empirical CLI test runs.
- **Live Infrastructure Deployment Audit (Sanitized):**
  * Iran VPS (`185.18.215.124`): `paqet.service` active; production SOCKS5 on `127.0.0.1:1090` verified healthy (`pong`); `/opt/paqet/emergency.key` permissions `0600`.
  * Germany VPS (`77.37.65.2`): `paqet.service` active; `paqet-emergency.service` active running Phase 17 binary (`c950611e...`).
  * Live Security Note: The active production daemon on Germany was deployed in Phase 17 without `--server-secret-file`, confirming that the production instance relies on legacy fallback until scheduled promotion to Phase 18 `v2.5.10-credreq`. Production services remain untouched to preserve operational continuity.

### 14.4 Session Identifier & Nonce Uniqueness Invariants Across Process Lifetimes
- **Key Derivation Schedule:**
  * Upstream (c2s): `HKDF-Extract(salt="paqet-asym-<sessionID>", IKM=c2sPSK)`, Info: `"c2s"` -> `c2sKey` (32 bytes).
  * Downstream (s2c): `HKDF-Extract(salt="paqet-asym-<sessionID>", IKM=serverSecret)`, Info: `"s2c:" + serverID` -> `s2cKey` (32 bytes).
- **Nonce Domain Construction:**
  * 12-byte AES-GCM nonce: `nonce[0:8] = BigEndian.PutUint64(sessionID)`, `nonce[8:12] = BigEndian.PutUint32(seq)`.
  * Role differentiation: `nonce[0] ^= byte(role)` (`RoleClient = 1`, `RoleServer = 2`). Client and server nonce spaces are strictly disjoint.
- **Uniqueness Invariants:**
  1. *Concurrent Sessions:* 64-bit cryptographic entropy (`crypto/rand`) ensures negligible collision probability ($P \approx 2^{-32}$ birthday bound across billions of sessions).
  2. *Retransmissions:* Server idempotency cache returns identical sealed ciphertext byte-for-byte; no new nonce or plaintext is encrypted under an existing sequence number.
  3. *Cross-Server Retries:* Server A and Server B hold distinct 32-byte response secrets. Even if a retried query uses the same `sessionID` and sequence number, the derived AES-GCM keys are cryptographically disjoint, preventing multi-target nonce collisions.
  4. *Sequence Exhaustion:* Atomic counter stops permanently at `MaxSafeSequenceNumber = 0xFFFFFF00` ($2^{32} - 256$), returning `ErrSequenceExhausted` and preventing sequence wraparound.
  5. Verified via `TestPhase18_SessionUniquenessAndNonceSafety`.

### 14.5 Symmetric vs Asymmetric Server Authentication: Formal Threat Model & Boundaries
- **Scope & Trust Boundary:**
  * In the present symmetric recovery control plane, the client holds the authorized mapping `{ServerID -> ResponseSecret}` to derive the AEAD decryption key for downstream frames.
  * *Attacks Prevented by Per-Server Symmetric Secrets:*
    1. Compromised or rogue authoritative nameservers holding the shared upstream PSK cannot forge responses or impersonate other authoritative servers.
    2. Network eavesdroppers and recursive resolvers cannot decrypt requests, forge responses, or decrypt server payloads.
    3. Untrusted third parties cannot manipulate AAD headers (`ServerID`, sequence, sessionID) without triggering AEAD tag failure.
  * *Attacks Remaining In Scope for Malicious/Compromised Authorized Clients:*
    1. Because authorized clients hold the 32-byte `ResponseSecret` for each server to verify AEAD tags, a compromised client possessing `ResponseSecret` could theoretically forge responses claiming that server identity to another client, or analyze traffic offline if it captures other sessions.
    2. In the Paqet threat model, emergency recovery clients are trusted endpoints operated by the tunnel owner. For hostile multi-tenant environments where clients are untrusted, asymmetric digital signatures (e.g. Ed25519 with server private key and client-held public key verifying a canonical transcript) must be adopted. The current architecture strictly documents symmetric secrets as *per-server response credentials*, not *server-exclusive private keys*.

### 14.6 Inter-Attempt Gap Accounting & Mathematical Timeline Reconciliation
- **Telemetry Defect Resolved:** Phase 17 reported exchange durations with discrepancies between attempt totals and overall wall time due to uninstrumented inter-attempt backoff and resolver failover pauses.
- **Remediation:**
  1. Defined `DNSInterAttemptGap` tracking `StartMonotonicMs`, `EndMonotonicMs`, `DurationMs`, and `Reason`.
  2. Implemented `DNSExchangeTimeline.Reconcile(toleranceMs)`: verifies that `TotalDurationMs == sum(Attempts) + sum(Gaps)` within numerical tolerance ($\le 2.0$ ms). Unaccounted intervals are calculated and audited fail-closed.
  3. Tested via `TestDNSExchangeTimeline_ReconcileSuite`: verified single-attempt success, multi-attempt backoff reconciliation, and negative gap rejection.

## 15. Phase 19 Audit: v4 Session Nonce Lifecycle, Explicit Authorized-Server Mapping & Restart Replay Containment

### 15.1 Quantified Session-ID Collision Analysis (Honest Probabilistic Bounds)
The 64-bit session identifier is NOT a mathematical identifier. Under a fixed credential epoch (c2s PSK + per-server response secret), the birthday collision bound is:
- v3: `P ≈ n² / 2⁶⁵`. At n = 10⁶ sessions: ~5.4×10⁻¹⁴. At n = 2³² sessions: ~50%.
- v4: `P ≈ n² / 2¹²⁹` (risk shifts to the 128-bit per-session random seed). n = 10⁹ sessions: ≈ 10⁻²⁰.
Both are PROBABILISTIC upper bounds under the stated seed-generation assumptions (crypto/rand). Accidental collisions are NOT the same class as deliberate replay — see §15.3.

### 15.2 v4 Lifecycle Redesign (Per-Instance Downstream Nonce Stream Base)
- Frame format: `Magic(4)+SessionID(8)+Seq(4)+Ack(4)+SeedLen(1)+Seed(16)+ServerIDLen(1)+ServerID(+ServerID then RNBLen+RNB for server frames)`.
- AAD coverage: entire cleartext frame prefix (seeded + session + sequence).
- Server responses carry an 8-byte per-instance random "downstream nonce stream base" (RNB), regenerated at each server (re)start.
- The server-side downstream AEAD nonce is `RNB || seq` (role-XORed), NOT `SessionID || seq`.
- After a restart, a replayed captured request under the same `(sessionID, seed, serverID, long-term creds)` derives an identical s2c key but a FRESH RNB, so the (key, nonce) pair differs from any previous response — nonce reuse eliminated across restarts (empirically verified).
- Client-side replay filter is keyed by `(serverID, RNB)`, so the restarted instance uses a fresh window and the attacker cannot leverage the OLD stream base to bypass the window.
- Full spec: `docs/research/paqet_protocol_v4_spec.md`.

### 15.3 Replay-After-Restart Defect Confirmed, Then Eradicated (TDD evidence)
- First confirmed defect: `TestPhase19_V4ReplayAfterRestartNoKeyNonceReuse` on the Phase 18 v3 approach reproduced identical nonces (`5351515151515151_00000001`) with different plaintexts because the server response一致性 recreated the previous key/nonce domain — this is the exact scenario considered adversarial for a captured initial request around a restart.
- Fixed by introducing the per-instance stream base + per-instance nonce composition; the same test now enforces nonce-domain uniqueness per server instance.

### 15.4 Explicit Multi-Server Authorized-Server Mapping (CLI Loader)
- New `--authorized-servers-config <file.json>` schema v1 on the emergency client: explicit `version=1`, `protocol="v4"`, `generation`, and `authorized_servers[].{server_id, secret_file}`. Inline response secrets are rejected.
- Credential-file policy: symlink (Lstat) rejected, non-regular paths rejected, 0600/0400-style permissions enforced (group/world bits rejected), exactly 32-byte decoded secret required (parseKeyBytes: base64 / hex / raw).
- Ambiguity policy at CLI level: `--authorized-servers-config` is incompatible with legacy `--legacy-single-server` AND incompatible with the singular `--server-id`/`--server-secret-file` convenience path. All flag-mixing combinations fail-closed BEFORE any socket is opened.
- Safe metadata: the CLI prints safe, non-secret diagnostics — `[CLIENT] protocol=v4-PAQD authorized-servers=[srv-a-01 srv-b-01]`.

### 15.5 v4 Lifecycle Verification Matrix (wire-level)
| Test | Scope | Result |
| Creating sessions with same seed & different sessionIDs derives different c2s keys | v4 wire constructor | pass |
| Restarted server replays captured request under same creds → nonce does NOT equal the pre-restart nonce | deterministic crypto-layer + wire e2e | pass |
| Old response replay rejected by per-domain window | client session persistence | pass |
| Two independent servers processing a repeated request under distinct identities → distinct response keys, byte-distinct ciphertexts | cross-server wire test | pass |
| Key rotation after server restart: stale-credential client must fail closed, fresh-credential client must succeed | e2e + CLI | pass |
| Revoked server from client map rejected | CLI + plane | pass |
| Sequence exhaustion hard-stop with no wraparound | deterministic seam | pass |
| Cached ciphertext retransmission byte-identical | retransmission cache | pass |

### 15.6 Protocol Version Rejection Matrix
- v4 frames rejected on legacy and v3 sessions (explicit `ErrProtocolVersionSignature`).
- v3 frames rejected on v4 sessions (explicit).
- v2 frames rejected on v4 and v3 (explicit `ErrLegacyProtocolDisabled`).
- Frame-version-dependent / seed-length-dependent angle mismatch rejected before AEAD key derivation.

### 15.7 Staged Deployment Evidence (Run PHASE19_STAGE_RUN_001/002/003/004)
- Candidate `v2.5.11-sesssalt` built with `CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X paqet/cmd/version.Version=v2.5.11-sesssalt -X paqet/cmd/version.GitCommit=db86722"`.
- Binary SHA-256: `1cb0378201a95fe9ffad0dae8a19a8d055e41a66c3c1ee702b5aab408f316a99`.
- Gzip SHA-256: `6232af5c292bf70bc06e71a1d8865028ea2c9ed2825759c9dd6b28f680400986`.
- Isolated staging daemon at `127.0.0.1:15353` on the Germany node under a transient `paqet-phase19-stage` systemd unit with `--disable-bootstrap`, dedicated `srv-stage-01`, and a dedicated 32-byte response credential generated with `openssl rand 32` on the target host (never in source, shell history, or the report).
- Stage 6 (fail-closed probes): missing secret file rejected; short secret file rejected (invalid length 8); 0644 permissions rejected (unsafe permission policy); symlink-replaced secret rejected. All exit code 1 before any listener binding.
- Stage 7 (successful startup): active with explicit identity and dedicated credential; confirmed via `systemctl` + `ss` listener.
- Stage 8 (e2e exchange): authenticated request/reply, byte-exact echo at 1.14 ms RTT with `--authorized-servers-config` + v4-PAQD protocol.
- Stage 9 (wrong credential): stale-credential client fails exchange with ERR exit code 1; the server NEVER authenticated the response.
- Stage 10 (restart): `systemctl restart` preserves the identity; `POST_RESTART_REPLAY` e2e still yields authenticated response at 1.13 ms RTT.
- Phase 19 production state (read-only): unmodified; Germany production daemon still running the Phase 17 binary at `c950611e...` without `--server-secret-file`; no dedicated credential files on any production node.
- Cleanup: transient `paqet-phase19-stage` stopped, staging filesystem removed, temporary secrets destroyed on-node, no firewall changes, no transient artifacts left.


## 16. Phase 20 Audit: Replay-Domain Sealing, v4.1 KDF Binding, Control-Message Safety & Migration Preflight

### 16.1 Confirmed defect (P0-1): replay-domain eviction reopened accepted windows (FIXED)
Phase 19's `pruneOldestReplayDomain` evicted a map-iteration-order replay filter at the 32-domain cap. A flood of 32 distinct authenticated domains (feasible only for a real response-key holder — the trust boundary) could evict the filter that had accepted a genuine response, making that response ACCEPTABLE AGAIN (verbatim replay fully passed AEAD + replay check). Deterministic test `TestPhase20_DomainCapacity_FirstDomainAcceptedThenReplayRejected` fails on that behavior and passes on the fix.
Fix: capacity exhaustion SEALS the connection (`ErrReplayDomainCapacity`, `replayDomainSealed` atomic) — no eviction ever; a new authenticated session is required. Accepted windows are never re-opened. Concurrency test (`-race`) shows exactly 32 accepts and deterministic sealing regardless of scheduling.

### 16.2 v4.1 KDF binding (P0-2): server-session base bound into the s2c salt
The base is generated once per server-session reconstruction (single call site: `NewServerAsymmetricSessionWithIDV4`). Binding it into the s2c HKDF salt (rev 2, wire layout unchanged) makes every reconstruction's response key distinct, so `(key, nonce)` reuse requires a base collision: `n²/2⁶⁵` for n reconstructions of the SAME tuple (n=10⁶ ⇒ ~2.7×10⁻⁸; n=10⁹ ⇒ ~0.027). The 128-bit client-seed bound is NOT substituted for the deliberate-replay class — that class is handled by the client replay window + sealing, and is documented separately. Forced-base-reuse, repeated-tuple, cross-server and collision-bound tests all pass (honest probabilistic framing).

### 16.3 Control-message safety (P0-3)
Explicit per-type policy (`MessageTypeSafety`): ping/status read-only; bootstrap_request/response + alert idempotent; data ClassStateChanging (exactly-once unsupported without durable dedup); unknown types fail-closed in schema validation. The reply cache is documented and tested as a retransmission optimization: duplicate-on-live-server, cross-server duplicates, and replay-after-full-restart wire tests exercise every supported type. No exactly-once claims.

### 16.4 Production audit (read-only, 2026-10-17)
| Property | Status |
| Germany emergency daemon active | VERIFIED |
| Running exe = /opt/paqet/paqet = SHA c950611e51bf1a8fcbff804f9012a1b9a2a683b77430e70e7f7b0f20e5ef0c54 | VERIFIED (identical) |
| Effective cmdline (sanitized) | VERIFIED: `--addr 0.0.0.0:53 --key-file [REDACTED] --bootstrap-config ... --server-id ns-de-01` — NO `--protocol-v4`, NO `--server-secret-file`, NO `--legacy-single-server` |
| Actual protocol mode | VERIFIED: v3 named-server fallback (neither credentialed-v4 nor explicit legacy) |
| Dedicated response secret file | NOT VERIFIED — none present on node |
| Client authorized-servers config (Iran) | NOT VERIFIED — none present |
| Restart-failure risk if binary were replaced with credentialed build | BLOCKED (would fail closed without the secret; currently running v3 binary restarts fine) |
| Production SOCKS5 (127.0.0.1:1090, Iran) | VERIFIED healthy (`pong`) at audit time |
| Rollback artifacts | VERIFIED checksummed: paqet.prev d4043086…, paqet-ng.v259.gz 1deaddbe… |
| Approved maintenance window | NOT REGISTERED ⇒ live promotion BLOCKED (preflight-only) |
No secrets, key material, or decrypted payloads were printed or recorded.

### 16.5 Migration preflight (READY — NOT EXECUTED, criterion 8)
Candidate `v2.5.13-domainseal` built from Phase 20 sources: binary `aa49fc742cec…` (see benchmark §5.7 for full hashes). Procedure, rollback, readiness checks and SOCKS5 health verification are documented in benchmark-results §5.7 and NEXT_STEPS §1. Execution is BLOCKED pending an approved maintenance window.
