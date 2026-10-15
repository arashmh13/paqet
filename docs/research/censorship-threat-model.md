# Censorship-Resistance Threat Model & Vulnerability Analysis

## 1. Threat Environment & Censorship Classification Models

This research analyzes transport survivability against five progressive tiers of adversary capabilities observed in national firewalls (such as Iran TIC / GFW / Roskomnadzor).

```
+-------------------------------------------------------------------------+
| Model E: Adaptive / Multi-Signal Classification (ML, cross-layer feeds) |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Model D: Active Probing & Replay Verification (Automated scanners)      |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Model C: Statistical & Flow Analysis (Packet sizes, timing, entropy)    |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Model B: Protocol & Deep Packet Inspection (DPI, stateful conntrack)    |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Model A: Destination-Based Blocking (IP, BGP routing, Port blacklisting)|
+-------------------------------------------------------------------------+
```

---

## 2. Model A — Destination-Based Blocking

### 2.1 Censor Capabilities
- IP address blacklisting at national border gateways or autonomous system (AS) boundaries.
- Targeted port throttling (e.g. international egress ports other than 80/443).
- BGP blackholing and DNS poisoning.

### 2.2 Observable Properties of Current Paqet
- Server operates on a static destination port (`:8088`).
- Direct client-to-server IP communication without intermediate CDN fronting or relay hopping.
- Outbound traffic from Iran VPS `185.18.215.124` targets fixed foreign IP `77.37.65.2`.

### 2.3 Vulnerabilities
- Port 8088 is non-standard. Non-80/443 traffic crossing international borders is frequently targeted for bulk heuristic throttling or complete drops during elevated censorship events.
- Once the destination IP `77.37.65.2` is identified, all traffic to it can be blocked instantly regardless of protocol sophistication.

### 2.4 Empirical Testability on 2-VPS Lab
- Can test: Port flexibility (running server on port 443 vs 8088), measuring differences in packet drops or throttling.
- Cannot test: Censor IP blacklisting resilience across multi-homed residential networks without using diverse relays.

---

## 3. Model B — Protocol Inspection & Stateful DPI

### 3.1 Censor Capabilities
- In-line stateful TCP connection tracking (similar to Linux `netfilter / conntrack`).
- Protocol anomaly detection: Dropping packets with unusual flag combinations, invalid sequence numbers, or invalid TCP options.
- Deep Packet Inspection (DPI) scanning for known protocol headers (e.g. KCP headers, TLS ClientHello, HTTP methods).

### 3.2 Observable Properties of Current Paqet
- **Handshake Emulation:** Sends `SYN (len 0)` -> receives `SYN-ACK (len 0)` -> sends `ACK (len 0)`.
- **Synthetic Sequence Numbers:** Emits TCP segments where Sequence numbers advance by exactly `+128` per packet.
- **Inverted Timestamps:** Emits TCP Timestamps where `TSecr` decrements per packet.
- **Payload Obfuscation:** Payloads are encrypted with AES-256-GCM. High Shannon entropy (~7.98 bits/byte) with zero static magic bytes.

### 3.3 Vulnerabilities
- **Strict TCP Window Tracking:** If the middlebox enforces RFC 793 sequence validation, consecutive packets whose sequence numbers jump arbitrarily or overlap with mismatched payloads will be discarded as TCP anomalies.
- **Entropy Heuristics:** Completely uniform high-entropy data over a raw TCP stream is a primary fingerprint for raw encryption protocols (Shadowsocks / pure KCP). Natural TCP traffic (TLS, HTTP/2, SSH) exhibits structured plaintext framing.

### 3.4 Empirical Testability on 2-VPS Lab
- Can test: Packet capture verification of sequence continuity, handshake state transitions, middlebox conntrack state transitions on real Iran-to-Germany international link.

---

## 4. Model C — Statistical Traffic Analysis

### 4.1 Censor Capabilities
- Flow metadata aggregation: Packet size histograms, inter-packet arrival times (IAT), burst length distributions.
- Correlation analysis: Identifying tunneling signatures (e.g. regular KCP ACK pacing, packet length correlations with web browsing patterns).

### 4.2 Observable Properties of Current Paqet
- **Random Padding:** `internal/obfs` pads frames with a uniform random length `0..maxPad` (default 64).
- **Packet Length Distribution:** Frame lengths are uniformly distributed across `[len + Overhead, len + Overhead + maxPad]`.
- **Timing:** KCP emits periodic update packets and ACK flushes at regular intervals (10–30ms depending on mode).

### 4.3 Vulnerabilities
- While random padding smooths packet length distributions, uniform random padding does not mimic realistic protocol distributions (e.g. TLS record distributions or WebRTC packet sizes).
- High frequency of small packets during idle periods (KCP keepalive and ACK ticks) creates a distinct heartbeat cadence.

### 4.4 Empirical Testability on 2-VPS Lab
- Can test: Long-duration packet size distributions, inter-arrival time distributions, and bandwidth overhead under various padding policies.

---

## 5. Model D — Active Probing & Verification

### 5.1 Censor Capabilities
- Follow-up active scanning: When a suspected flow is flagged, automated probing infrastructure connects to the destination IP and port.
- Multi-protocol probing: Sends HTTP requests, TLS ClientHellos, random bytes, replay packets, and malformed handshakes.
- Observes server response: Measures whether the server replies, drops, resets, or hangs.

### 5.2 Observable Properties of Current Paqet
- **TCP SYN Response:** The server responds with `SYN-ACK` to any incoming `SYN`.
- **Post-Handshake Payload Response:** The server drops all unauthenticated payloads and remains completely silent.
- **Replay Behavior:** The server accepts and decrypts replayed ciphertext frames without rejection due to lack of replay protection in `internal/obfs`.

### 5.3 Vulnerabilities
- **Tarpit / Blackhole Fingerprint:** An open TCP port that accepts connections but never replies to standard protocols (HTTP, TLS) is trivially classified by active scanners (GFW active probing, Censys, Shodan).
- **Replay Vulnerability:** Replaying captured authenticated packets causes the server to execute AEAD verification and pass duplicate frames to KCP, consuming CPU and potentially triggering identifiable transport state responses.

### 5.4 Empirical Testability on 2-VPS Lab
- Fully verified and tested: Active probing script confirmed that German VPS completes 3-way handshake in 88ms and completely blackholes subsequent HTTP GET requests.

---

## 6. Model E — Adaptive Multi-Signal Classification

### 6.1 Censor Capabilities
- Combining flow volume, destination IP reputation, port number, packet entropy, active probing outcomes, and client location.
- Dynamic rule deployment: Escalating from throttling to partial packet dropping, and finally full IP block.

### 6.2 Vulnerabilities of Current Paqet
The combination of:
1. Non-standard port (8088),
2. High-entropy payload on raw TCP,
3. Fixed +128 sequence number anomalies,
4. Complete silence upon active HTTP/TLS probing,
provides an unmistakable signature for adaptive classifiers.

---

## 7. Threat Evaluation Matrix

| Threat Model | Censor Detection Vector | Current Paqet Resistance | Severity | Remediation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Model A** | Static Port 8088 & Direct IP | Low | High | Support standard ports (443), multi-endpoint failover, and TLS camouflage. |
| **Model B** | Stateful conntrack & +128 Seq jumps | Moderate (Bypasses basic DPI; fails strict conntrack) | Critical | Implement strictly monotonic TCP sequence tracking or use standard kernel transport. |
| **Model C** | Periodic KCP ACK pacing & uniform padding | Moderate | Medium | Adaptive traffic shaping, realistic TLS record distribution padding. |
| **Model D** | Active probing silent blackhole & replay | None (Vulnerable to active tarpit detection & replay) | Critical | Implement anti-replay window, peer authentication before state allocation, and fallback camouflage. |
| **Model E** | Combined entropy + probing heuristics | Low | High | Modular multi-transport architecture disguising traffic as genuine TLS 1.3. |
