# Known Limitations, Constraints, and Scope Boundaries

## 1. Single Path Validation Boundary

- **Path Scope:** All empirical findings and live integration benchmarks in this report were conducted strictly across the designated **Iran VPS (`185.18.215.124`) to German VPS (`77.37.65.2`)** international network link.
- **Interpretation:** While this path crosses the Iranian Telecommunication Infrastructure Company (TIC) international border gateway, **datacenter VPS traffic may experience different filtering policies from residential ISP connections** (e.g. MCI, Irancell, Shatel, or TCI FTTH).
- **Universal Claims Disavowed:** Success on this verified link does **not** constitute proof of universal resistance against all global censors or China's Great Firewall (GFW).

---

## 2. Kernel & Operating System Constraints

### 2.1 Raw-Packet Injection Requirements
- `raw-hardened` mode requires root privileges (`CAP_NET_RAW` / `CAP_NET_ADMIN`) and access to the host network interface.
- It cannot be run inside unprivileged Docker containers or standard restricted cloud functions without `network_mode: host` and elevated capabilities.
- Windows hosts require Npcap OEM drivers in WinPcap compatibility mode.
- WSL2 requires mirrored networking (`networkingMode=mirrored`) and disabled Hyper-V firewall; it cannot function over standard WSL2 NAT switches.

### 2.2 Residential NAT Limitations
- Like baseline Paqet, `raw-hardened` mode generates raw Layer-2 Ethernet frames targeting the physical gateway MAC. Behind residential home routers with stateful Linux Netfilter NAT (`nf_conntrack`), out-of-order raw frames may be marked `INVALID` and discarded unless the router is in Bridge/PPPoE mode or DMZ is configured.
- **Solution:** For residential endpoints, Paqet-NG's `aead-stream` mode operates via standard kernel sockets and traverses all consumer NAT routers seamlessly.

---

## 3. Cryptographic & Traffic Analysis Boundaries

1. **Passive Flow Correlation:** While uniform padding (`0..maxPad`) disrupts precise packet-size fingerprinting, it does not fully obscure long-term statistical burst patterns or session timing during continuous bulk transfers.
2. **Replay Window Expiry:** The anti-replay ring buffer protects against up to 16,384 replayed packets per connection. Replays arriving after the buffer rolls over and outside the 30-second clock window are rejected by the timestamp check, but require reasonably synchronized clocks ($\Delta t < 30\text{s}$).

---

## 4. IP-Spoofing & BCP 38 / uRPF Provider Constraints

1. **Egress Source-Address Filtering (RFC 2827):** Standard cloud VPS providers (including Hetzner, OVH, DigitalOcean, and Iranian datacenter providers) enforce strict BCP 38 ingress/egress filtering at the hypervisor virtual switch. Any packet with a forged source IP is dropped before leaving the physical rack.
2. **Empirical Verification (October 15, 2026 Audit):**
   - Transmitted raw UDP probes from Iran VPS (`185.18.215.124`): Genuine IP succeeded. Adjacent IP (`185.18.215.45`, same subnet) was dropped by switch-port binding. Documentation IP (`198.51.100.1`) was dropped by Panel01 upstream router.
   - Transmitted raw UDP probes from Germany VPS (`77.37.65.2`): Genuine IP succeeded. Documentation IP (`198.51.100.1`) was dropped by Hetzner vSwitch.
3. **Infrastructure Prerequisite:** The `asymmetric-spoof` mode cannot operate on generic VPS hosting. It strictly requires dedicated bare-metal servers or transit providers that explicitly allow arbitrary source IP announcements via BGP.
4. **Automated Safety Gating:** To prevent user connection failure, Paqet-NG gates spoofing behind `ProbeSpoofCapability` and returns `ErrBCP38Enforced`.

---

## 5. DNS-Asymmetric Bandwidth & Latency Constraints

1. **Bandwidth Ceiling:** Maximum Base32 payload capacity is capped at 35 bytes per DNS query label. Measured wire amplification is **$3.60\times$** (126-byte DNS query to carry 35 bytes of binary data).
2. **Throughput Bounds:**
   - Conservative (20 queries/second): **$5.60\text{ kbps}$**.
   - Aggressive (100 queries/second): **$28.00\text{ kbps}$**.
3. **Latency Inflation:** Recursive multi-hop DNS resolution inflates round-trip times to 150–600ms.
4. **Operational Scope:** `dns-asymmetric` must be deployed strictly as an emergency signaling, bootstrap, or text-terminal channel, not as an interactive browsing transport.

---

## 10. Directional Decoupling vs. Symmetric Full-Duplex Transports

1. **Simplex vs Duplex Synchronization:** Directionally decoupled transports (`AsymmetricConn`) utilize independent upstream and downstream paths. While this survives severe asymmetric egress blocks, it introduces reassembly buffering overhead and relies on piggybacked ACKs.
2. **Interactive Stream Latency:** When upstream is routed over high-latency channels (e.g. recursive DNS queries), interactive TCP handshakes and window scaling take significantly longer to converge compared to direct symmetric transports.

---

## 6. Unit Test Correctness vs. Censorship Resistance Claims

Passing self-authored unit tests, adversarial fuzz harnesses, or simulated middlebox drop scripts proves **software correctness, memory safety, and protocol specification adherence**; it does **not** prove evasion of China's Great Firewall (GFW), Russia's TSPU, or un-tested Iranian residential mobile operators (MCI / Irancell).
- **GFW vs. Iran TIC:** The GFW employs active probing with distinct TLS/QUIC probe sequences, extensive BGP-level route poisoning, and dynamic deep-learning classifiers trained on massive international egress pipes.
- **Controlled Lab Boundary:** Our live tests establish that Paqet-NG bypasses specific stateful conntrack drops and silent tarpit active-probing signatures between Panel01 (Tehran) and Hetzner (Germany). Broader claims of universal invulnerability are scientifically unverified.

---

## 7. Padding Reality vs. Genuine TLS Record Layer Mimicry

- **Scope of Payload Padding:** `SamplePadding` with `PaddingStrategyBucketed` clusters application payload lengths into standard discrete sizes (e.g. 64, 128, 256, 512, 1024, 1420 bytes) plus small random jitter.
- **What It Does NOT Do:** It operates strictly inside the encrypted AEAD datagram or stream chunk. It does **not** generate genuine TLS 1.3 `0x17` ApplicationData records, nor does it emit valid TLS record layer headers on the wire.
- **Classification Reality:** A passive DPI sensor inspecting raw packet streams will observe custom binary framing or high-entropy TCP segments, not an authentic TLS handshake and session. Claiming "HTTPS mimicry" without a full TLS record layer wrapper is inaccurate.

---

## 8. Multi-Port Pooling vs. Deep Packet Inspection

- **Scope of Multi-Port Pooling:** Distributing client connections across multiple ports (e.g. `:8089` and `:8443`) on the same destination IP address mitigates **port-specific heuristic rate-limiting** and **single-port firewall blocks**.
- **What It Does NOT Do:** It does **not** prevent DPI classification if the DPI inspects payload contents, entropy distributions, or the underlying transport framing.
- **Operational Reality:** Multi-port pooling is a traffic-distribution and availability feature; it is not a standalone DPI circumvention technique.

---

## 9. Physical Egress Bandwidth Ceiling (Panel01 Iran VPS)

- **Measured Egress Limit:** Direct un-proxied TCP curl downloads from Iran VPS (`185.18.215.124`) to German VPS (`77.37.65.2`) are physically shaped to $1.34\text{ MB/s}$ ($11.27\text{ Mbps}$).
- **Transport Utilization:** `aead-stream` achieves $1.43\text{ MB/s}$ ($11.97\text{ Mbps}$), representing 100% saturation of the allocated link capacity.
- **Throughput Reporting:** Measurements reporting 70+ Mbps reflect unthrottled local loopback or synthetic lab conditions, not the real-world egress limit of this specific virtual machine path.
