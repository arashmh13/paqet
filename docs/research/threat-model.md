# Severe-Censorship Threat Model & Adversary Capabilities

This document formalizes the threat model for Paqet-NG under severe national-level internet censorship, specifically reflecting the empirical realities of Iran's national firewall (TIC / mobile operators MCI, Irancell, Rightel, and fixed-line ISPs Shatel, Mokhaberat, ParsOnline), as well as comparative capabilities of China's Great Firewall (GFW) and Russia's TSPU.

---

## 1. Adversary Classification Taxonomy

We evaluate transport survivability against seven distinct, escalating filtering classes:

```text
[ G. Partial Connectivity ]  (Protocol-selective shutdowns, DNS-only, asymmetric egress)
           ^
[ F. Adaptive Filtering ]    (Dynamic multi-indicator rule generation, auto-blacklisting)
           ^
[ E. Statistical Classification ] (Packet size distributions, entropy, inter-arrival timing)
           ^
[ D. Active Probing ]        (Automated scanners, protocol decoders, replay verification)
           ^
[ C. TLS/SNI-Based Filtering ] (Decoy SNI detection, ClientHello reassembly, cert snooping)
           ^
[ B. Stateful Packet Inspection ] (TCP conntrack, sequence validation, option tracking)
           ^
[ A. Address and Port Blocking ] (Static IP blacklisting, non-standard port drops, BGP drops)
```

---

## 2. Comprehensive Analysis by Filtering Class

### Class A: Address and Port Blocking
*Known endpoints, CIDR ranges, or non-standard ports are blocked or severely throttled.*

- **Observable Evidence:** Outbound TCP SYN packets to foreign IP/port receive zero response (silent drop) or receive synthetic TCP RST injected with forged IP/TCP headers; ICMP Destination Unreachable (Type 3 Code 1/3) injected by middlebox.
- **Likely Failure Mechanisms:** Server listening on static non-standard port (`:8088`, `:8089`) or single un-rotated foreign IP (`77.37.65.2`).
- **Relevant Transport Features:**
  - Multi-endpoint / multi-port listener binding (listening on port 443, 80, 8443, 8088 simultaneously).
  - Rapid endpoint rotation and connection pooling.
  - SOCKS5 fallback / strategy switching.
- **Testable Hypotheses:** Listening on standard port 443 exhibits lower packet loss and higher handshake success rates than non-standard port 8088 during peak censorship throttling.
- **Proposed Experiment:** Run parallel continuous synthetic probes from Iran VPS to German VPS on ports 443, 8088, 8089, and 29999 over 60 minutes, recording SYN-ACK latency and drop rates.
- **Limitations:** Testing between two fixed VPSs measures host-to-host path behavior, not the entire range of Iranian residential ISP edge filters.

---

### Class B: Stateful Packet Inspection (SPI & Conntrack)
*The observer tracks TCP 4-tuple flow state, validates RFC 793/9293 sequence and acknowledgment progression, and monitors TCP options (MSS, Window Scale, Timestamps).*

- **Observable Evidence:** Packet drop occurs specifically after the first data segment; mid-stream TCP resets; middleboxes dropping packets with out-of-order sequence jumps or non-monotonic timestamps.
- **Likely Failure Mechanisms:**
  - Fixed-step sequence advancement (e.g. baseline Paqet jumping `+128` regardless of payload length $L$).
  - RFC 7323 timestamp inversion (e.g. `TSecr` counting down in reverse).
  - Missing kernel TCP handshake matching raw packet injections.
- **Relevant Transport Features:**
  - Byte-accurate atomic sequence counter (`curSeq.Add(pLen)`).
  - Strictly non-decreasing RFC 7323 monotonic timestamp echo handling.
  - Standard userspace TCP stream transport (`aead-stream`), delegating conntrack compliance entirely to the kernel TCP stack.
- **Testable Hypotheses:** Correcting sequence progression to byte-accurate increments and timestamps to RFC 7323 compliance will reduce `conntrack` drop flags to 0 on international paths.
- **Proposed Experiment:** Capture bidirectional traces with `tcpdump` on both endpoints during high-concurrency transfers; inspect with Wireshark/tshark to verify zero sequence overlap, zero gap, and strictly monotonic timestamps.
- **Limitations:** Middlebox conntrack state tables are opaque; internal drop decisions must be inferred from packet delivery and latency anomalies.

---

### Class C: TLS/SNI-Based Filtering
*The observer inspects the TLS ClientHello, extracts the Server Name Indication (SNI), and resets or drops connections targeting blacklisted hostnames.*

- **Observable Evidence:** TCP 3-way handshake succeeds in ~100ms, but the connection is instantly RST'd or blackholed within 1–2 RTTs of transmitting a TLS ClientHello carrying a restricted domain.
- **Likely Failure Mechanisms:** Transmitting blocked domain names in plaintext ClientHello; relying solely on classic TCP segmentation (`tlshello` fragment) which modern Iranian DPI reassembles before inspection.
- **Relevant Transport Features:**
  - Out-of-window TCP sequence injection (`wrong_seq`), presenting a benign decoy SNI (`hcaptcha.com`, `bank.ir`) to the DPI flow cache before the real payload.
  - TLS camouflage / REALITY architecture with `uTLS` fingerprint matching.
- **Testable Hypotheses:** Injecting a decoy ClientHello with `seq = syn_seq + 1 - len(payload)` will cause stateful DPI to classify the flow as benign while the destination server ignores the out-of-window packet.
- **Proposed Experiment:** Simulate blocked SNI connections using the SNI-assisted dialer, compare against direct un-fragmented connections, and verify flow survival.
- **Limitations:** Requires raw socket capabilities on the client or specialized driver support (`WinDivert` on Windows, `AF_PACKET` on Linux).

---

### Class D: Active Probing & Verification
*When a suspicious high-entropy connection is observed, automated scanning servers dial back to the destination IP/port and send protocol probes (HTTP GET, TLS ClientHello, random fuzzing, replay packets).*

- **Observable Evidence:** Destination server logs show inbound connections from suspicious subnets (censor scanning pools) probing open ports within seconds of a client session.
- **Likely Failure Mechanisms:**
  - Silent tarpit / blackholing: Accepting TCP connections but never answering non-Paqet data.
  - Replay vulnerability: Replaying previously captured packets triggers identical responses or state allocation.
- **Relevant Transport Features:**
  - Immediate probe termination: On unauthenticated input or tag verification failure, emit an instant TCP RST/FIN ($< 0.5$s) rather than hanging silently.
  - Sliding-window anti-replay filter: Replay cache rejecting duplicate nonces and stale timestamps.
  - Strict pre-authentication: Zero state or buffer allocation before AEAD tag verification.
- **Testable Hypotheses:** Rejecting probes instantly with TCP RST prevents automated scanners from classifying the port as a silent censorship proxy tarpit.
- **Proposed Experiment:** Run an adversarial scanner suite sending HTTP GET, TLS ClientHello, random bytes, and replayed packets against the Paqet server, measuring response latency and socket behavior.
- **Limitations:** Censors may continually evolve their active probing signatures and probe from hundreds of distributed source IPs.

---

### Class E: Statistical Classification & Traffic Analysis
*The observer aggregates packet lengths, inter-arrival times (IAT), burstiness, and Shannon entropy over time to fingerprint tunnels without decrypting payloads.*

- **Observable Evidence:** Connections succeed initially but are throttled or severed after 2–5 minutes of continuous data transfer or after transferring a threshold volume.
- **Likely Failure Mechanisms:**
  - Uniform random padding creating flat, unnatural packet size distributions.
  - High Shannon entropy (~7.99 bits/byte) across raw TCP sockets.
  - Distinct KCP ACK pacing / heartbeat cadences during idle periods.
- **Relevant Transport Features:**
  - Adaptive padding matching realistic TLS record size distributions.
  - Coalesced ACK flushing and randomized keepalive intervals.
  - Stream framing disguising payload lengths.
- **Testable Hypotheses:** Adding dynamic padding distributions decreases packet-length histogram divergence against natural HTTPS traffic.
- **Proposed Experiment:** Capture 10,000 packets of Paqet traffic and 10,000 packets of genuine HTTPS video/web streaming; calculate Kolmogorov-Smirnov test statistic on packet lengths and IATs.
- **Limitations:** Sophisticated machine-learning classifiers can leverage multi-dimensional feature vectors that require extensive dataset collection to fully mimic.

---

### Class F: Adaptive Filtering & Cross-Layer Correlation
*The censor correlates signals across network layers (e.g. repeated raw packet drops + DNS lookups + foreign IP connection attempts) and dynamically generates temporary or persistent firewall rules.*

- **Observable Evidence:** After an experimental transport fails, all connections to that destination server (including SSH) become degraded or inaccessible for a cooling period (15–60 minutes).
- **Likely Failure Mechanisms:** Persistent retrying of failing protocols on the same IP/port, triggering automated IDS/IPS threshold alerts.
- **Relevant Transport Features:**
  - Strategy selector with exponential backoff and circuit-breaking.
  - Hysteresis in transport switching to avoid rapid flapping.
  - Fallback suppression when severe provider-level filtering is detected.
- **Testable Hypotheses:** Circuit breaking on transport failure preserves IP reachability compared to aggressive reconnect loops.
- **Proposed Experiment:** Simulate consecutive transport failures and verify that the client enters backoff before triggering provider rate limits.
- **Limitations:** National firewall rate limits are dynamic and non-deterministic.

---

### Class G: Partial Connectivity & Asymmetric Blackouts
*International TCP is completely severed, foreign UDP is dropped, but specific domestic or restricted outbound paths remain operational (e.g. DNS port 53, ICMP, intranet-only whitelists).*

- **Observable Evidence:** `ping` or DNS queries to 8.8.8.8 succeed, but all TCP SYN packets to foreign destinations time out completely.
- **Likely Failure Mechanisms:** Relying solely on conventional bidirectional TCP or UDP tunnels.
- **Relevant Transport Features:**
  - Asymmetric signaling / emergency channel (`dns-asymmetric`) utilizing recursive DNS lookups for upstream communication.
  - Independent return-path routing.
- **Testable Hypotheses:** Data framed into DNS queries can reach the foreign server when all foreign TCP ports are blocked.
- **Proposed Experiment:** Simulate a TCP block via local iptables drop; verify that DNS queries continue to deliver signaling frames to the German server.
- **Limitations:** Extremely low throughput ($< 1$ Mbps) and high packet loss make this suitable only for recovery, signaling, and emergency control.
