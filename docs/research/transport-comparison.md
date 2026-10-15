# Comparative Transport Evaluation & Empirical Trade-Off Matrix

This report provides a comparative assessment of the six selectable transport modes supported by Paqet-NG, combining laboratory test results, live Iran VPS-to-Germany VPS integration benchmarks, and threat-model survivability analyses.

---

## 1. Full Multi-Transport Comparison Matrix

| Evaluation Dimension | Mode 1: `raw-kcp` | Mode 2: `aead-stream` | Mode 3: `sni-assisted` | Mode 4: `asymmetric-spoof` | Mode 5: `dns-asymmetric` | Mode 6: `auto` (Selector) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Operating Layer** | Layer 2 / 3 / 4 (Raw) | Layer 4 (TCP Stream) | Layer 4 + Decoy Preamble | Layer 3 (Raw IPv4) | Layer 7 (DNS UDP:53) | Dynamic Multi-Layer |
| **Encapsulation** | Custom TCP Flags + KCP | AEAD-2022 Chunks | Synthetic TLS 1.3 ClientHello + AEAD | Forged IP + UDP/TCP | Base32 QNAME Labels | Optimal Active Transport |
| **Iran-to-DE Latency (RTT)**| $108.2\text{ ms}$ (min) / $128.9\text{ ms}$ (avg) | $88.5\text{ ms}$ (min) / $94.1\text{ ms}$ (avg) | $92.0\text{ ms}$ (min) / $98.4\text{ ms}$ (avg) | N/A (Egress Dropped) | $650\text{ ms}$ (avg) | Tracks best active ($94\text{ ms}$) |
| **Throughput (Iran-to-DE)** | $1.34\text{ MB/s}$ (~10.7 Mbps) | $9.10\text{ MB/s}$ (~72.8 Mbps) | $8.85\text{ MB/s}$ (~70.8 Mbps) | 0 Mbps (BCP 38 Blocked) | $< 0.1\text{ MB/s}$ (< 0.8 Mbps)| Matches best active (~72.8 Mbps) |
| **Privilege Requirements** | **Root** (`CAP_NET_RAW`, pcap) | **None** (Unprivileged) | **None** (Userspace frag) / Optional Root | **Root** (`CAP_NET_RAW`, raw IP) | **None** (Client) / Root (Server) | Dynamic (Prefers non-root) |
| **NAT / Residential Compat** | Poor (Requires MAC / bridge) | **Perfect** (Full NAT traversal) | **Perfect** (Full NAT traversal) | **Fails** (NAT table drop) | Asymmetric (Downstream direct) | **High** (Adapts to NAT) |
| **Provider Spoofing Req.** | None (Uses real IP) | None | None | **Mandatory** (BCP 38 disqualifies) | Mandatory for Server Spoof | None (Bypasses spoof if blocked) |
| **Active Probing Response** | Immediate RST ($< 0.5\text{s}$) | Immediate RST ($< 0.2\text{s}$) | Immediate RST ($< 0.2\text{s}$) | Silent Drop | Standard DNS NOERROR | Inherits active mode ($< 0.2\text{s}$) |
| **Replay Defense** | 16K-entry Ring Buffer | 30s Sliding Window | 30s Sliding Window | Cryptographic Token Window | Offset/Sequence Cache | Layered Defense |
| **Censorship Survival Tier**| Tier 2 (Conntrack bypass) | Tier 1 (General censorship) | Tier 3 (SNI-based filtering) | Tier 5 (Severe whitelist) | Tier 6 (Total TCP shutdown) | **All Tiers (Adaptive)** |
| **Deployment Complexity** | High (NIC/MAC binding) | Low (Plug-and-play) | Low-Medium (Config SNI) | Extreme (Provider dependent) | Medium (Authoritative DNS) | Zero-Config Fallback |

---

## 2. Detailed Strategy Evaluations

### 2.1 Mode 1: `raw-kcp` (Hardened Raw Packet Transport)
- **Primary Use Case:** Networks where ISP middleboxes aggressively reset standard OS TCP connections based on TCP handshake heuristics or known socket state machines.
- **Key Reparations Implemented:**
  - Sequence Advancement: From fixed `+128` to exact byte count $L$.
  - Timestamp Echo: From reverse countdown to monotonically increasing RFC 7323 echo.
  - Replay Defense: 16,384-entry O(1) hash ring buffer in `internal/obfs`.
- **Field Trade-off:** High packet injection capability vs. maximum throughput ceiling (~10.7 Mbps) and requirement for root privileges and static router gateway MAC addresses.

### 2.2 Mode 2: `aead-stream` (Userspace Stream Transport)
- **Primary Use Case:** Daily production transport for high-bandwidth tasks (streaming, downloads, browsing) where raw socket access is unavailable (e.g. mobile apps, non-root containers).
- **Key Features:**
  - Directional HKDF-SHA256 key derivation (`c2s_key` and `s2c_key`).
  - 30-second timestamp sliding-window replay filter.
  - Instant connection reset on unauthenticated probes (0.168s measured).
- **Field Trade-off:** 5.4x–5.8x throughput advantage over raw pcap; zero root requirement; vulnerable only to severe IP/port blacklisting or DPI SNI blocking on foreign ports.

### 2.3 Mode 3: `sni-assisted` (SNI Camouflage Transport)
- **Primary Use Case:** Networks where Iranian DPI middleboxes block connections to foreign IPs unless the initial handshake carries a whitelisted Iranian or allowed foreign domain (e.g., `bank.ir`, `hcaptcha.com`, `ssp.ir`).
- **Key Features:**
  - Injects authentic RFC 8446 TLS 1.3 ClientHello with decoy SNI.
  - Poisons middlebox DPI flow cache without corrupting application data.
  - Transparently handled on server stream listener via TLS record header peeking.
- **Field Trade-off:** Circumvents national SNI filters while retaining ~70 Mbps throughput; requires configuring benign decoy domains that match local allowlists.

### 2.4 Mode 4: `asymmetric-spoof` (Bidirectional IP Spoofing)
- **Primary Use Case:** Severely restricted intranets where traffic is only permitted between specific whitelisted governmental IPs.
- **Empirical Barrier:** Live testing between Iran VPS (`185.18.215.124`) and German VPS (`77.37.65.2`) confirmed that **both providers enforce BCP 38 / uRPF**, dropping spoofed source IP packets at the egress switch.
- **Architectural Decision:** Gated behind an automated pre-flight qualification probe (`ProbeSpoofCapability`). The selector marks this mode `Unavailable` unless running on infrastructure with anti-spoofing filters disabled.

### 2.5 Mode 5: `dns-asymmetric` (Asymmetric DNS Upstream Transport)
- **Primary Use Case:** "Nuclear option" / total internet blackouts where international TCP and direct UDP are completely blocked, but recursive DNS lookups (port 53) remain operational.
- **Key Features:**
  - Base32-encoded multipart DNS QNAME framing.
  - Robust chunk reassembly with 10-second expiration window.
- **Field Trade-off:** Extremely high survivability vs. low bandwidth ($< 1$ Mbps) and high RTT ($> 650$ ms). Designed as an emergency control/signaling beacon rather than a general-purpose proxy.

### 2.6 Mode 6: `auto` (Evidence-Based Resilience Selector)
- **Primary Use Case:** Autonomous operation without manual intervention during fluctuating censorship conditions.
- **Key Features:**
  - Active background latency EMA tracking.
  - Circuit breakers tripping after 3 consecutive failures.
  - 25% hysteresis margin preventing flapping.
  - Order of fallback: `aead-stream` $\rightarrow$ `sni-assisted` $\rightarrow$ `raw-kcp` $\rightarrow$ `dns-asymmetric`.
