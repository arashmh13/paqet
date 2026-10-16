# Next Engineering Steps & Strategic Priorities: Paqet-NG Platform

## 1. Executive Status & Current State

- **Current Git Branch:** `research/hard-mode-rnd`
- **Current Version:** `v2.5.9-authid`
- **Active Binary SHA-256:** `c950611e51bf1a8fcbff804f9012a1b9a2a683b77430e70e7f7b0f20e5ef0c54`
- **Architectural Validation Status:**
  - Phase 17 Authenticated Server Identity, Fail-Closed Authorization & AEAD Lifecycle Safety: **COMPLETE & WIRE-VERIFIED** (Eliminated shared-PSK server impersonation via distinct 32-byte per-server response secrets derived via RFC 5869 HKDF; made server identity immutable after key initialization; implemented canonical `ServerID` validation; enforced mandatory nonempty client authorization allowlists fail-closed; disabled legacy v2 frames by default in multi-server configurations; implemented sequence exhaustion protection preventing 32-bit nonce wraparound at `0xFFFFFFF0`; resolved Phase 16 DNS attempt contradictory status defect via strict `rec.Error = ""` clearing and `(r *DNSQueryAttemptRecord) Validate()` schema enforcement; passed complete two-authoritative readiness suite `TestPhase17_TwoAuthoritativeReadinessSuite`; executed live Iran ⇄ Germany recovery achieving total failover in 2291.58 ms with zero unaccounted overhead; verified byte-exact token `PHASE17_PROVEN_c55043e264da662fe43b3dae4d71ade1`; verified production SOCKS5 on `1090` returning `HEALTHY` `"pong"` in 109.83 ms).
  - Phase 16 Recovery Telemetry Correction, DNS Latency Diagnosis & Multi-Authority Cryptographic Safety: **COMPLETE & WIRE-VERIFIED** (Resolved candidate validation timing anomaly, reconciling 178.12 ms handshake duration with state machine history; verified authenticated production SOCKS5 proxy on `127.0.0.1:1090` returning `HEALTHY` `"pong"`; implemented RFC 6891 Additional Section parser with strict `min(server_cap, client_advertisement)` UDP sizing; mathematically eliminated multi-authoritative AEAD nonce collisions via RFC 5869 HKDF server-specific response keys bound to `ServerID`; implemented per-server anti-replay filters and client-side server authorization whitelisting; live cross-border recovery over Google `8.8.8.8:53` achieved total failover in 505.95 ms with exact 0.000 ms reconciliation overhead; verified byte-exact token `PHASE16_PROVEN_ce3bc1913762b15a977917d8a9c25bed`).
  - Phase 15 Fail-Closed Configuration, End-to-End Identity Continuity & Measured Recovery Timeline: **COMPLETE & WIRE-VERIFIED** (Eliminated implicit bootstrap fallback to `77.37.65.2` and emergency PSK identity conflation; enforced fail-closed startup when configuration is missing or malformed; implemented `stream.DialTLSPinned()` enforcing leaf certificate / pubkey pins on candidate TLS connections; verified candidate key fingerprints before dialing in `timed_conn.createConn()`; prevented stale/raced connection pool commitment; conservative 1232-byte EDNS0 buffer limits with measured RFC 7766 TCP port 53 fallback when responses exceed safe 1400 bytes; recorded full monotonic failover timeline distinguishing 87.94 ms post-activation HTTP request from total 4993.79 ms end-to-end failover duration; verified live across Iran ⇄ Germany using Google `8.8.8.8:53` with byte-exact token match `PHASE15_PROVEN_fd06fd5251a6c37143e21b0489f9a5b0`; production SOCKS5 proxy on `1090` verified healthy throughout).
  - Phase 14 Complete Transport Authentication, Failover Consistency & Failure-Domain Resilience: **COMPLETE & VERIFIED** (Explicit, versioned endpoint identity model distinguishing `psk-id`, `cert-pin`, and `pubkey-pin`; genuine remote raw-KCP candidate handshake validation enforcing stream creation and protocol `PPING`/`PPONG` verification while deterministically closing temporary sockets; mode-aware, configurable `BootstrapManager` supporting candidate endpoint records without hardcoded IPs or shared-key leakage; client tunnel pool tracking typed `ConnectionIdentity` across address, mode, generation, and identity; elimination of implicit fallback on candidate failure; live cross-border validation over public recursive DNS `8.8.8.8:53` with byte-exact token match `PHASE14_PROVEN_adc8bdad43def3706c34e7741adf37dd`; failure-domain resilience matrix established in `docs/research/failure_domain_resilience_matrix.md`).
  - Phase 13 Real SOCKS5 Recovery & Transport Identity Binding: **COMPLETE & WIRE-VERIFIED** (Closed evidentiary gap between unit-tested recovery state machine and actual application SOCKS5 tunnel routing; immutable `RecoveryEndpointSnapshot` preserving authorized transport mode, canonical `SHA256:<64 hex>` identity, generation revision, and strict non-zero freshness; authenticating `BuildCandidateValidator` enforcing genuine Paqet AEAD/TLS handshakes and smux PPING/PPONG protocol verification while rejecting dummy TCP listeners; dynamic tunnel pool switching in `dial.go`; live cross-border validation across Iran ⇄ Germany using dedicated SOCKS5 port `11990` and remote HTTP origin `18999` with byte-exact verification of unpredictable token `PHASE13_VERIFIED_d801ccd52db40996f515b68b3155e6cf` in 175.47ms while production `1090` remained completely healthy throughout).
  - Candidate 1 (Genuine TLS 1.3 Outer Transport): **COMPLETE & WIRE-VERIFIED** (RFC 8446 standard TLS 1.3 handshake, ContentType 0x17 ApplicationData records, 90.9 ms RTT, 11.60 Mbps line rate, CA certificate validation verified).
  - Candidate 2 (Raw TCP Decoy Sequence Injection): **COMPLETE & WIRE-VERIFIED** (`wrong_seq` out-of-window packet injection, silent kernel drop on Germany VPS, 123.4 ms RTT).
  - Asymmetric Directional Decoupling (`AsymmetricConn`): **COMPLETE & HARDENED** (independent `UpstreamSender` and `DownstreamReceiver` channels, AAD header authentication, sequence exhaustion protection, RTO retransmission queue, and memory bounds).
  - DNS-Asymmetric Transport: **OPERATIONAL & PUBLICLY VERIFIED** (Live public recursive DNS TXT traversal across Iranian border via Google `8.8.8.8`, Cloudflare `1.1.1.1`, and Quad9 `9.9.9.9` to Germany authoritative daemon `77.37.65.2:53` in $136.9 - 242.4\text{ ms}$; verified arbitrary multi-payload exchange and conventional port-blockade survival).
  - Phase 12 Fail-Closed Recovery & Resource-Exhaustion Defense: **COMPLETE & LIVE-VERIFIED** (Fail-closed candidate validation requiring valid cryptographic identity and strict future validity window; generation tokens preventing stale asynchronous callbacks from overriding newer primary health or rollback states; authoritative DNS bounded worker semaphores capping concurrent handlers to 128 UDP / 32 TCP; pre-authentication gating preventing unauthenticated packets from occupying in-flight duplicate capacity; real `StrategySelector` integration for new connections; live cross-border application HTTP recovery test verified with byte-exact payload delivery).
  - Phase 11 Reply-Cache Security & Concurrency Safety: **COMPLETE & ADVERSARIALLY VERIFIED** (Eradicated unauthenticated reply-cache lookup defect; enforced `VerifyFrame` AEAD validation + 32-byte SHA-256 request fingerprint matching on cached replies; eliminated first-session race conditions via atomic candidate commit; serialized session replay/cache operations under per-session mutex; implemented single-flight duplicate request coordination; protected in-flight sessions from idle eviction with `activeOps` refcount; tested under Go race detector with zero data races).
  - Deterministic Benchmark Analysis & Statistical Reconciliation: **COMPLETE & DOCUMENTED** (`internal/ng/dns/benchmark_analysis.go` implemented and tested; Hyndman-Fan Type 7 linear interpolation reconciled Quad9 P95 metric anomaly at $1259.31\text{ ms}$; decoupled successful RTT from timeout elapsed times).
  - Dual-Authoritative Nameserver Redundancy Testing: **VERIFIED LOCALLY** (`dns_redundancy_test.go` tested cross-server retries, replays, and proved why multipart queries fail across uncoordinated server pools; single-query datagrams $\le 35\text{B}$ established as stateless protocol requirement).
  - Controlled Recovery State Machine (`RecoveryStateMachine`): **IMPLEMENTED & LIVE TESTED** (Explicit states: `PRIMARY_HEALTHY`, `PRIMARY_DEGRADED`, `EMERGENCY_SIGNALING`, `BOOTSTRAP_RECEIVED`, `CANDIDATE_ENDPOINT_VALIDATING`, `RECOVERY_READY`, `COOLDOWN`; tested cross-border over dedicated test listeners with verified state audit trail; production SOCKS5 proxy on `:1090` preserved undisturbed).
  - Clean-Room Resolver Scanner (`internal/ng/dns`): **COMPLETE & LIVE-TESTED** (Tested live from Tehran across 8 candidate resolvers; identified domestic resolver label censorship; verified 100% clean profile on public recursors; clarified CAPABILITY vs E2E PASS).
  - BCP 38 / uRPF Spoofing Feasibility: **CONCLUDED & INFEASIBLE** (probes conclusively dropped by Panel01 and Hetzner egress routers).
  - Controlled Failure Laboratory: **OPERATIONAL & EXPANDED** (`failure_lab_test.go` passing across all formal failure models: Conditions A through I; verified isolated test listener block and recovery without touching production services).
- **Active Endpoints:**
  - Iran VPS (`185.18.215.124`): Primary SOCKS5 on `127.0.0.1:1090` (`raw-kcp` with out-of-window SNI sequence injection), Genuine TLS on `127.0.0.1:1095` (`tls` on `:8443`).
  - German VPS (`77.37.65.2`): Primary server listening on `:8088` (kcp), Genuine TLS server on `:8443`, Emergency Authoritative DNS daemon on UDP+TCP `:53` (`paqet-emergency.service`, `--key-file /opt/paqet/emergency.key`).
  - In-Host Benchmark Daemon: `127.0.0.1:8999` (`/ping`, `/bytes/<N>`, `/echo`).

---

## 2. Priority 1: Automated Multi-Path Port Failover & Jitter Injection

- **Objective:** Enable dynamic transport port hopping when an active TCP stream experiences sudden packet drops or silent stalling (censor heuristic throttling).
- **Architecture:**
  - Expand client connection ticker to track per-port throughput and TCP retransmission counts.
  - If a connection on `:8089` drops below threshold while peer connection on `:8443` maintains healthy throughput, dynamically re-route streams without tearing down user SOCKS5 sessions.
- **Dependencies:** `internal/client/udp_pool.go` and `internal/client/ticker.go`.
- **Acceptance Criteria:**
  1. Controlled injection of `iptables -A INPUT -p tcp --dport 8089 -j DROP` on Germany VPS must not drop active SOCKS5 downloads on Iran VPS.
  2. Multiplexer transfers active streams to `:8443` within $< 1.5$ seconds.

---

## 3. Priority 2: TLS 1.3 REALITY / Decoy SNI Reverse Proxy Layer

- **Objective:** Eliminate high-entropy detection on port 443 by disguising the server stream listener as a genuine HTTPS web server (e.g. `www.apple.com` or `www.cloudflare.com`).
- **Architecture:**
  - Integrate `uTLS` ClientHello parser on server listener.
  - When an unauthenticated connection arrives with a valid TLS ClientHello, forward the raw connection transparently via TCP splice to the genuine external decoy server (e.g. Apple/Cloudflare).
  - The censor observing probe scans receives genuine DigiCert / Let's Encrypt certificates from the real web server.
- **Dependencies:** `internal/ng/transport/aead_stream.go` and `uTLS` / reverse proxy splice engine.
- **Acceptance Criteria:**
  1. `curl -I https://77.37.65.2:8443` from an external host returns genuine HTTP/2 200 OK and valid TLS certificate chain.
  2. Authenticated Paqet-NG client connecting to `:8443` with secret PSK establishes the tunnel instantly.

---

## 4. Priority 3: Asymmetric DNS Signaling Channel Live Demonstration

- **Objective:** Demonstrate end-to-end DNS query signaling on live nodes under simulated total TCP blocking.
- **Architecture:**
  - Bind a lightweight authoritative DNS UDP listener on Germany VPS (port 5353 or port 53).
  - Configure Iran VPS to emit Base32 QNAME frames to `8.8.8.8` / `1.1.1.1` targeting the registered test domain.
  - Reassemble emergency control commands on Germany VPS.
- **Dependencies:** `internal/ng/transport/dns_asymmetric.go`.
- **Acceptance Criteria:**
  1. 100% frame reassembly rate over 50 consecutive test datagrams.
  2. Frame reassembly survives simulated 20% packet drop on UDP port 53.

---

## 5. Priority 4: Reed-Solomon Forward Error Correction (FEC) over Stream Chunks

- **Objective:** Eliminate TCP head-of-line blocking and retransmission stalls on high-loss Iranian residential lines (FTTH / 4G).
- **Architecture:**
  - Wrap stream chunk payloads in an $(N, K)$ Reed-Solomon parity matrix using `klauspost/reedsolomon` (e.g. 10 data chunks + 3 parity chunks).
  - Receiver reconstructs dropped chunks locally without requesting TCP retransmissions across high-latency international links.
- **Dependencies:** `internal/ng/transport/aead_stream.go` and `internal/ng/protocol/`.
- **Acceptance Criteria:**
  1. Under simulated 15% random packet loss (`tc qdisc add dev eth0 root netem loss 15%`), download throughput remains within 80% of baseline.
