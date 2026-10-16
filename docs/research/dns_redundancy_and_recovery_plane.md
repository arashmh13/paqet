# Paqet-NG DNS Redundancy & Recovery Plane Architecture (Phase 10)

## 1. Problem Statement: The Single-IP / Single-NS Dependency

### 1.1 The Vulnerability
In the current deployment, the delegated child zone:
`tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`
has its NS delegation pointing to:
`ns-de...` $\longrightarrow$ `A` $\longrightarrow$ `77.37.65.2` (Hetzner, Falkenstein, Germany).

Crucially, `77.37.65.2` is the **exact same IP address** hosting the primary Paqet `raw-kcp` transport (port 8088), `aead-stream` (port 8089), and `tls-outer` (port 8443).

**Failure Mode:** If an Iranian upstream provider (TIC / TCI) or routing policy blackholes the IP prefix `77.37.65.0/24` or Hetzner AS24940, **both the conventional proxy transports AND the authoritative DNS emergency daemon will be simultaneously severed**. Even if domestic users can reach Google (`8.8.8.8`) or Cloudflare (`1.1.1.1`), the recursors will be unable to reach `77.37.65.2:53` to resolve the child zone queries.

---

## 2. Distributed Dual-Authoritative Nameserver Architecture

To achieve true survivability against IP-level and datacenter-level censorship, the emergency DNS recovery plane must operate at least two independent authoritative nameservers on distinct network prefixes and independent hosting providers.

```
                            [ Cloudflare Parent Zone ]
                                        |
           +----------------------------+----------------------------+
           |                                                         |
     NS Record 1:                                              NS Record 2:
     ns-eu.domain... -> 77.37.65.2 (Hetzner, DE)               ns-us.domain... -> 149.28.x.x (Vultr/OVH, US/FR)
           |                                                         |
           v                                                         v
   [ Authoritative Node 1 ]                                  [ Authoritative Node 2 ]
```

### 2.2 The Recursive Resolver Query-Splitting Problem
Recursive resolvers (such as Google Public DNS, Cloudflare, and Quad9) select authoritative nameservers according to internal latency scoring, SRTT (Smoothed Round Trip Time), or random spraying.

When a client transmits a multipart emergency message consisting of multiple fragments (e.g. Part 0 and Part 1):
- Query for Part 0 may be dispatched by Google to `Node 1` (`77.37.65.2`).
- Query for Part 1 may be dispatched by Google to `Node 2` (`149.28.x.x`).

If Node 1 and Node 2 maintain isolated in-memory reassembly buffers (`DNSReassembler`), neither node receives the complete frame, resulting in query timeouts and communication failure!

### 2.3 Architectural Solutions & Engineering Decision

Three design approaches solve the query-splitting problem:

#### Strategy A: Single-Query Control Datagrams (Implemented & Recommended)
- As demonstrated in Phase 10 empirical benchmarks, control plane datagrams (e.g. `bootstrap_request`, `ping`, `alert`, `status`) fit comfortably within 35 bytes of raw payload (1 single fragment label).
- When `total = 1`, no multipart reassembly is required. Either authoritative server can immediately decrypt, authenticate, process, and answer the query independently, with **zero inter-server coordination**.
- **Status:** **Operational in v2.5.2-hardened**. All control messages are formatted to fit into single-query datagrams.

#### Strategy B: Deterministic Subdomain Sharding
- Instead of delegating a single pool, delegate two distinct subdomains:
  * `*.node1.tunnel...` $\longrightarrow$ `NS` $\longrightarrow$ `ns-eu...` (`77.37.65.2`)
  * `*.node2.tunnel...` $\longrightarrow$ `NS` $\longrightarrow$ `ns-us...` (`149.28.x.x`)
- The client tries `node1` first; if unanswered, it fails over to `node2`.
- All fragments of a message are addressed to the same authoritative node, preventing split reassembly.

#### Strategy C: Inter-Daemon WireGuard State Replication
- Authoritative daemons connect over an encrypted WireGuard peer-to-peer overlay.
- Incoming intermediate fragments are mirrored over the mesh via UDP gossip or Redis/Etcd.
- Allows arbitrary multi-kilobyte transfers across split nameservers.
- Adds deployment complexity and inter-VPS dependency.

---

## 3. Strict Typed Control Schema for Endpoint Failover

The recovery plane must never execute arbitrary shell commands. It enforces a strict typed schema for bootstrap coordinates.

### 3.1 Control Message Types
```go
const (
	MsgTypePing              = "ping"               // Liveness probe
	MsgTypeAlert             = "alert"              // Firewall cutoff alert
	MsgTypeBootstrapRequest  = "bootstrap_request"  // Request updated proxy coordinates
	MsgTypeBootstrapResponse = "bootstrap_response" // Return new proxy coordinates
	MsgTypeStatus            = "status"             // Client telemetry
	MsgTypeData              = "data"               // Small encrypted text payload
)
```

### 3.2 Bootstrap Payload Schema
When conventional ports are severed, the client issues a `bootstrap_request`. The authoritative server returns authenticated `BootstrapEndpointData`:
```json
{
  "server_ip": "77.37.65.2",
  "transport_port": 8443,
  "transport_mode": "tls-outer",
  "server_pub_key": "SHA256:4a8b...cert-fingerprint",
  "valid_until": 1780000000
}
```

### 3.3 Bootstrap Validation Rules
1. **Signaling Only:** Receiving a bootstrap response signals the *intended* next transport coordinates; it does not assume reachability.
2. **Mutual Handshake Required:** The client must initiate a full cryptographic handshake (e.g. genuine TLS 1.3 handshake with certificate pinning, or AEAD stream session) before routing user SOCKS5 traffic.
3. **Graceful Failover:** New connections transition to the new endpoint; existing streams fail over gracefully on reconnect.

---

## 4. Independent Authoritative DNS Redundancy & Multi-Server Architecture

### 4.1 State Synchronization vs. Stateless Control Signaling
In Phase 11, cross-server testing proved that:
1. **Single-Datagram Control Messages ($\le 64\text{ bytes}$):** Can be processed independently by distinct authoritative server instances. A client whose query reaches Server A, or whose retransmission reaches Server B, receives an authenticated response because each request datagram carries its own AEAD header and deterministic nonce.
2. **Multipart Assembly Limitation:** Uncoordinated authoritative servers do not share in-memory reassembly buffers (`DNSReassembler`). If fragment 0 arrives at Server A and fragment 1 arrives at Server B, reassembly fails. Therefore, emergency control signaling must strictly fit within single-query frames.
3. **Session Replay Synchronization:** For continuous multi-packet streams across servers, a shared state synchronization plane (e.g. distributed cache or raft log) is required. For the emergency plane, single-flight bootstrap requests utilize fresh request nonces and timestamp verification, ensuring security without distributed locks.

### 4.2 Deployment Procedure for Secondary Nameserver (`ns2`)
When an independent second VPS is provisioned on a non-Hetzner provider:
1. **Host Hardening & Credentials:**
   - Deploy `paqet-emergency.service` on Node 2.
   - Synchronize `/opt/paqet/emergency.key` via secure channel (file permissions `0600`).
   - Configure candidate endpoint records in `/opt/paqet/bootstrap_endpoints.json`.
2. **Cloudflare DNS Configuration (STRICT PRECONDITION):**
   - **Do NOT add an NS record until Node 2 is reachable and validated.**
   - Add A record: `ns2.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir` $\longrightarrow$ `<Node2_IP>`.
   - Add delegated NS record: `tunnel.passionatepharmacist...` $\longrightarrow$ `ns2...` (in addition to `ns-de...`).
3. **End-to-End Multi-Server Verification:**
   - Query `ns-de...` directly via `paqet emergency send --resolver 77.37.65.2:53`.
   - Query `ns2...` directly via `paqet emergency send --resolver <Node2_IP>:53`.
   - Query via public recursive resolvers (`8.8.8.8`, `1.1.1.1`) and verify recursors distribute queries across both nameservers without errors.

---

## 5. Controlled Recovery State Machine Architecture (Phase 11)

To ensure reliable, non-flapping failover when primary transports degrade, Paqet-NG implements an explicit finite state machine (`RecoveryStateMachine` in `internal/ng/transport/recovery_state_machine.go`):

```
                       +-------------------+
                       |  PRIMARY_HEALTHY  |<--------------------+
                       +-------------------+                     |
                                 |                               |
                   Failure Count >= Threshold                    |
                                 v                               |
                       +-------------------+                     |
        +------------->|  PRIMARY_DEGRADED |                     |
        |              +-------------------+                     |
        |                        |                               |
        |                  Degraded Timeout                      |
        |                        v                               |
        |              +-------------------+                     |
        |              |EMERGENCY_SIGNALING|                     |
        |              +-------------------+                     |
        |                        |                               |
        |                 DNS Bootstrap OK                       |
        |                        v                               |
        |              +-------------------+                     |
        |              | BOOTSTRAP_RECEIVED|                     |
        |              +-------------------+                     |
        |                        |                               |
        |                        v                               |
        |              +-------------------+                     |
        |              | CANDIDATE_ENDPOINT|                     |
        |              |    VALIDATING     |                     |
        |              +-------------------+                     |
        |                   /             \                      |
        |          Validation Failed   Validation Passed         |
        |                 /                 \                    |
        |                v                   v                   |
        |       +-----------------+  +----------------+          |
        |       | RECOVERY_FAILED |  | RECOVERY_READY |          |
        |       +-----------------+  +----------------+          |
        |                |                   |                   |
        |                v                   |                   |
        |       +-----------------+          |                   |
        |       |    COOLDOWN     |          |                   |
        |       +-----------------+          |                   |
        |                |                   |                   |
        +----------------+                   |                   |
        Cooldown Expired                     |                   |
                                             v                   |
                                    Rollback / Restored ---------+
```

### 5.1 State Machine Design Invariants
1. **Hysteresis & Flap Prevention:**
   A single transient packet drop does not trigger emergency failover. `PrimaryFailureThreshold` (default 3) consecutive failures are required to transition from `PRIMARY_HEALTHY` to `PRIMARY_DEGRADED`.
   If primary traffic succeeds during `PRIMARY_DEGRADED`, the engine immediately reverts to `PRIMARY_HEALTHY` without initiating emergency signaling.
2. **Untrusted Candidate Validation:**
   Receiving bootstrap coordinates over DNS is treated as an untrusted recommendation. The engine does NOT activate the endpoint until `CandidateValidator` independently executes a live TCP/AEAD handshake with the target (`CANDIDATE_ENDPOINT_VALIDATING`).
3. **Graceful Connection Scoping:**
   When reaching `RECOVERY_READY`, the candidate endpoint is activated strictly for **new connections** (`ActiveEndpoint()`). Existing sessions are not forcefully severed.
4. **Deterministic Rollback:**
   `ResetRollback(reason)` clears all temporary failover routes and restores `PRIMARY_HEALTHY`.

---

## 6. Strict Transport Identity Binding & SOCKS5 Proxy Dynamic Recovery (Phase 13)

### 6.1 Immutable Structured Snapshot Model
Rather than passing an unvalidated address string (`host:port`), Phase 13 introduces `RecoveryEndpointSnapshot`:
```go
type RecoveryEndpointSnapshot struct {
    ServerIP       string        `json:"server_ip"`
    TransportPort  int           `json:"transport_port"`
    TransportMode  TransportMode `json:"transport_mode"` // ModeRawKCP, ModeAEADStream, ModeTLSStream
    ExpectedPubKey string        `json:"expected_pub_key"`
    ValidUntil     int64         `json:"valid_until"`
    MessageID      string        `json:"message_id"`
    Generation     uint64        `json:"generation"`
    ValidatedAt    time.Time     `json:"validated_at"`
}
```
**Invariants:**
1. **Mode Enforcement:** `StrategySelector.Dial()` and `timedConn.createConn()` strictly select the transport strategy matching `snapshot.TransportMode`. Attempting to dial an unauthorized or unsupported mode fails closed.
2. **Generation Pinning:** `snapshot.Generation` must match `recoverySM.CurrentGeneration()`. Any async result returning from a superseded attempt is discarded.
3. **Strict Expiry:** `snapshot.ValidUntil <= now.Unix()` is treated as expired. Expired snapshots are purged and trigger candidate failure reporting.

### 6.2 Authenticating Candidate Validator
Candidate endpoints must prove ownership of the authorized cryptographic identity prior to activation:
- **AEAD-Stream:** Derives directional keys from the configured PSK and random salt, initializes secure connection framing, completes smux version 2 handshake, opens stream, writes `protocol.PPING`, and requires `protocol.PPONG`. Plain TCP listeners are rejected.
- **TLS-Stream:** Extracts peer leaf certificate, computes SHA-256 digest, and requires byte-exact match against `SHA256:<64 hex>` `ExpectedPubKey`.
- **Raw-KCP:** Validates cryptographic identity key against authorized bootstrap fingerprint.

### 6.3 SOCKS5 Tunnel Pool Dynamic Failover
Inside `internal/client/dial.go`, `newConn()` tracks recovery engine state:
1. When `recoverySM` enters `RECOVERY_READY`, any active connection not pointing to `snapshot.Addr()` is closed and replaced with a newly established connection to the recovery candidate.
2. When `recoverySM` resets to `PRIMARY_HEALTHY`, connections return smoothly to the primary transport.
3. Verified live: SOCKS5 proxy on `127.0.0.1:11990` serves real application HTTP requests through candidate `77.37.65.2:18089` during primary outage in **175.47 ms**, matching unpredictable test tokens byte-exact while production `127.0.0.1:1090` remains unaffected.

