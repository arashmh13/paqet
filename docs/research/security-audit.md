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
