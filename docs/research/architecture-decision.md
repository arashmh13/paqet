# Architectural Decision Record (ADR): Paqet-NG Multi-Transport Platform

## 1. Context & Problem Statement

Baseline Paqet demonstrated that raw TCP packet injection combined with KCP and an AES-GCM obfuscation layer can traverse certain middleboxes. However, extensive reverse engineering, code inspection, and live network experiments on the Iran VPS (`185.18.215.124`) to German VPS (`77.37.65.2`) network path exposed fundamental limitations across four distinct transport paradigms:

1. **Raw Packet Injection (`raw-kcp`):**
   - Fixed-step sequence advancement (`+128` per packet) and decrementing timestamps violated TCP RFCs and triggered stateful firewall drops.
   - Requires root privileges (`CAP_NET_RAW`), raw interface binding, and exact router gateway MAC addresses.
   - Incompatible with standard residential NAT/CGNAT; throughput capped at ~10.6 Mbps due to userspace pcap serialization.
2. **Userspace Encrypted Streams (`aead-stream`):**
   - Achieves high throughput (~72.8 Mbps), operates without root privileges, traverses NAT seamlessly, and neutralizes active probing via instant TCP RST/FIN.
   - However, persistent high-entropy data on a single TCP port can be identified by statistical machine-learning classifiers or port-whitelisting firewalls.
3. **SNI-Spoofing & Packet Manipulation (`patterniha`, `aleskxyz`, Xray-core #5969):**
   - Out-of-window TCP sequence injection (`wrong_seq`) successfully tricks Iranian DPI into whitelisting flows, but classic TCP fragmentation is now reassembled and defeated.
   - SNI manipulation is only meaningful when applied to the outer tunnel transport handshake, not to proxied end-to-end HTTPS payload streams.
4. **Bidirectional IP Spoofing (`ParsaKSH/spoof-tunnel`):**
   - Decouples IP addresses from logical sessions, but empirical live testing proved that datacenter switches enforce BCP 38 (RFC 2827) and uRPF (RFC 3704), dropping spoofed packets at egress before they cross international borders.
5. **Asymmetric DNS Upstream (`patterniha/QS-Tunnel`):**
   - Upstream DNS queries survive full TCP blackouts, but throughput is restricted to $< 1$ Mbps and return-path spoofing suffers the same BCP 38 drop failure on cloud VPS networks.

---

## 2. Decision: A Decoupled Multi-Strategy Platform

Paqet-NG is hereby established as a **modular multi-strategy networking platform** with an **evidence-based resilience selector**.

Rather than forcing fundamentally incompatible network mechanisms into one brittle protocol, Paqet-NG decomposes the system into strictly separated subsystems:

```text
+-----------------------------------------------------------------------------------+
|                            Application Proxy Layer                                |
|  - SOCKS5 Proxy Server (User/Pass Auth, IPv4/IPv6/Domain targets)                 |
|  - Inbound TCP/UDP Port Forwarders                                                |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        Logical Stream Multiplexer (smux v2)                       |
|  - Channel Multiplexing, Stream Flow Control, Dynamic Buffer Management           |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                      Evidence-Based Strategy Selector (`auto`)                     |
|  - Real-time Latency EMA, Sliding-Window Success Rate, Circuit Breaker            |
|  - Hysteresis Switching (prevents flapping), Graceful Fallback Sequencing         |
+-----------------------------------------------------------------------------------+
                                          |
               +--------------------------+--------------------------+
               |                          |                          |
               v                          v                          v
    +--------------------+     +--------------------+     +--------------------+
    |  `aead-stream`     |     |  `sni-assisted`    |     |  `raw-kcp`         |
    |  (High Throughput) |     |  (DPI SNI Cloaking)|     |  (Hardened Raw)    |
    +--------------------+     +--------------------+     +--------------------+
               |                          |                          |
               v                          v                          v
    +--------------------+     +--------------------+     +--------------------+
    |  `asymmetric-spoof`|     |  `dns-asymmetric`  |     | Future Adaptors    |
    |  (Gated by BCP 38) |     |  (Emergency Beacon)|     | (uTLS / REALITY)   |
    +--------------------+     +--------------------+     +--------------------+
```

---

## 3. Policy & Strategy Selection Rules

### Strategy 1: `aead-stream` (Default High-Throughput Mode)
- **Role:** Primary workhorse for standard operations.
- **Characteristics:** ~72.8 Mbps, 100ms RTT, zero root requirement, fully NAT-compatible.
- **Probe Defense:** Monotonic timestamps + 30-second sliding-window anti-replay filter; instant RST/FIN ($< 0.5$s) on unauthenticated probes.

### Strategy 2: `sni-assisted` (SNI Camouflage Mode)
- **Role:** Active when national DPI enforces strict SNI blacklisting on foreign ports.
- **Characteristics:** Injects synthetic TLS 1.3 ClientHello with decoy SNI (`hcaptcha.com`, `ebanking.ir`) to prime DPI flow cache, followed by authenticated AEAD session.
- **Fallback:** Seamlessly supported on stream listener via automatic TLS record header detection.

### Strategy 3: `raw-kcp` (Hardened Packet Injection Mode)
- **Role:** Fallback when stateful middleboxes drop userspace TCP handshakes.
- **Characteristics:** Layer 2/3 raw frame injection via `libpcap`, byte-accurate sequence advancement, RFC 7323 monotonic timestamps, 16,384-entry ring-buffer anti-replay cache.

### Strategy 4: `dns-asymmetric` (Emergency Beacon / Survival Channel)
- **Role:** Survival fallback when all foreign TCP and direct UDP traffic is blocked.
- **Characteristics:** Encodes signaling data into Base32 DNS queries routed via public recursive resolvers; reassembles out-of-order chunks on destination. Throughput $< 1$ Mbps.

### Strategy 5: `asymmetric-spoof` (Gated Experimental Mode)
- **Role:** Specialized deployment on dedicated infrastructure where BCP 38 is disabled.
- **Gating Invariant:** **Must execute pre-flight BCP 38 qualification probe**. If spoofed packets are dropped at egress, mode is marked `Unavailable` and rejected by the selector.

---

## 4. Consequences & Migration Path

- **Backward Compatibility:** Existing `client.yaml` and `server.yaml` configurations using `protocol: "kcp"` or `protocol: "stream"` remain 100% compatible.
- **Reliability Guarantee:** The automated strategy selector (`protocol: "auto"`) ensures that transient packet loss or middlebox rule changes do not cause permanent disconnection.
- **Auditability:** Every transport exposes standardized `Capabilities()` and `Metrics()` reporting for real-time diagnostics.

