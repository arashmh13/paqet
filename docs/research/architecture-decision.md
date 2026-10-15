# Architectural Decision Record (ADR): Paqet-NG

## 1. Context & Problem Statement

Baseline Paqet demonstrates that raw TCP packet injection combined with KCP and an AES-256-GCM obfuscation layer can traverse certain middleboxes. However, empirical testing on the live Iran VPS to German VPS link revealed critical protocol and transport flaws:
1. **TCP Sequence & Timestamp Defects:** Advancing TCP sequence numbers by a fixed `+128` regardless of payload size and decrementing `TSecr` creates severe TCP protocol anomalies detectable by any stateful conntrack firewall.
2. **Cryptographic Replay Vulnerability:** The `internal/obfs` envelope lacks replay protection, allowing captured packets to be replayed indefinitely.
3. **Active Probing Signature:** The server completes a 3-way handshake with any IP and then completely blackholes all subsequent non-authenticated traffic, creating an obvious "silent tarpit" fingerprint.
4. **Architectural Rigidity:** The proxy logic (SOCKS5 and port forwarding) is hardcoded directly to KCP over raw pcap sockets, making it impossible to switch or benchmark alternative transports without rewriting core modules.

---

## 2. Evaluation of Architectural Candidates

### Candidate A — Hardened Raw Paqet
- **Concept:** Keep the raw Layer-2/Layer-3/Layer-4 packet injection architecture. Fix the sequence number tracking by computing actual byte-based `Seq` and `Ack` offsets from the initial handshake. Fix timestamp generation. Add a sliding-window replay filter to `internal/obfs`.
- **Pros:** Preserves the raw packet concept; retains the ability to customize TCP flags (`local_flag`, `remote_flag`).
- **Cons:**
  - Still requires root privileges (`CAP_NET_RAW`, `libpcap`).
  - Cannot function behind residential NAT routers without router DMZ or bridge mode.
  - Still suffers from pcap serialization bottlenecks and high CPU usage under heavy load.
  - Vulnerable to DPI classifiers that target raw encrypted payloads on custom ports.

### Candidate B — Pure Userspace TLS / Camouflage Transport
- **Concept:** Discard raw packet injection entirely. Use standard kernel-managed TCP sockets with TLS 1.3 masquerade or HTTP/2 encapsulation.
- **Pros:** Runs in userspace without root privileges; perfect TCP stateful conntrack compliance; operates cleanly behind any NAT; active probe resistance via web decoy fallback.
- **Cons:** Loses the custom raw TCP flag manipulation capability that is effective against certain DPI middleboxes; higher protocol overhead.

### Candidate C — Modular Multi-Transport Architecture (Paqet-NG)
- **Concept:** Architect Paqet-NG with a decoupled, modular transport subsystem:
  1. **Core Service Layer:** SOCKS5, port forwarders, and client stream manager independent of the underlying wire transport.
  2. **Pluggable Transport Interface (`Transport`):**
     - **Mode 1: `raw-hardened` (Hardened Raw Packet Transport):** Repaired raw TCP injection with strict sequence tracking, valid timestamps, sliding-window anti-replay, and bounded padding.
     - **Mode 2: `aead-stream` (Standard Secure Stream Transport):** Userspace TCP transport featuring AEAD-2022 session key derivation, monotonic timestamp headers, instant probe rejection, and zero raw socket requirements.
     - **Mode 3: `tls-camouflaged` (TLS 1.3 Chameleon):** Disguises traffic as genuine TLS 1.3 records with real SNI camouflage.
  3. **Unified Stream Multiplexer & Session Manager:** Standardized stream framing with version negotiation, keepalive, and flow control.
- **Pros:**
  - Solves the single-point-of-failure risk of a single transport.
  - Provides a direct, scientific comparison platform between raw-packet injection and kernel-managed transports on the exact same VPS link.
  - Supports non-root deployment (e.g. mobile or unprivileged containers) while retaining raw capabilities where advantageous.
  - Eliminates all identified defects (sequence tracking, anti-replay, probe blackholing).
- **Cons:** Slightly higher initial implementation scope.

---

## 3. Decision & Technical Rationale

**Selected Architecture: Candidate C (Modular Multi-Transport Paqet-NG)**

### Justification:
1. **Empirical Evidence:** Benchmark results show that raw KCP over pcap on the Iran-Germany link is capped at ~10.6 Mbps due to pcap context switches and single-socket serialization. A modular architecture allows evaluating hardened raw transport against clean AEAD stream transport under identical conditions.
2. **Robustness & Survivability:** In an active censorship event, if the raw packet signature is targeted by ISPs, users can switch the transport engine (e.g. to `aead-stream` or `tls-camouflaged`) via a single configuration flag without rebuilding or altering proxy bindings.
3. **Security Standards:** All transports in Paqet-NG will enforce:
   - Authenticated Encryption with Associated Data (AEAD) via AES-256-GCM or ChaCha20-Poly1305.
   - 30-second sliding-window replay filter with bloom/hash cache.
   - Bounded random padding with traffic-shaping options.
   - Probe-resistant server admission (immediate disconnect or fallback rather than silent tarpit).
