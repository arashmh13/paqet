# Reference Project Evaluation & Architectural Comparison

## 1. Scope & Investigated Transports

To establish an evidence-based foundation for Paqet-NG, five mature, widely deployed censorship-resistant transport architectures were analyzed:

1. **Xray-core REALITY (XTLS):** TLS 1.3 masquerade with server identity spoofing.
2. **Tor obfs4:** Elligator2-based asymmetric handshake with randomized packet shaping.
3. **Tor WebTunnel:** HTTP/2 and HTTP/3 reverse proxy camouflage mimicking standard web endpoints.
4. **Tor Snowflake:** WebRTC data channels with ephemeral volunteer browser proxies and domain-fronted rendezvous.
5. **Shadowsocks-2022 (AEAD-2022):** High-performance symmetric authenticated encryption with strict anti-replay and active-probe resistance.

---

## 2. In-Depth Architectural Evaluation

### 2.1 Xray-core REALITY
- **Mechanism:** Borrows real TLS certificates from legitimate websites (e.g. `www.apple.com`, `www.microsoft.com`). The client sends a genuine TLS 1.3 ClientHello containing the target SNI and a public key hidden inside the `SessionID` field.
- **Server Behavior:**
  - If the client provides a valid authentication key in `SessionID`, the REALITY server terminates the connection and enters proxy mode.
  - If the client is an active censor scanner (or regular user) sending an ordinary TLS handshake, the server proxies the connection transparently to the real destination website.
- **Active Probing Resistance:** Exceptional. Scanners see a 100% genuine TLS 1.3 handshake with legitimate certificates matching the real SNI.
- **Complexity & Trade-offs:** Requires TLS 1.3 stack customization (`uTLS`), dependency on external TLS SNI availability, and strict clock synchronization.

### 2.2 Tor obfs4
- **Mechanism:** Uses Elligator2 to transform Curve25519 public keys into bitstrings indistinguishable from uniform random noise. Handshake messages contain no static headers or magic numbers.
- **Traffic Shaping:** Employs maximum-segment-size (MSS) randomization, inter-arrival time (IAT) shaping, and dynamic padding based on a pseudo-random number generator (PRNG) seeded during the handshake.
- **Active Probing Resistance:** High. Probes with invalid keys fail the Elligator2 MAC verification and are silently dropped.
- **Complexity & Trade-offs:** High CPU overhead due to per-packet padding and IAT calculation. Throughput is significantly lower than standard TCP.

### 2.3 Tor WebTunnel
- **Mechanism:** Tunnels traffic inside standard HTTP/2 or HTTP/3 HTTPS connections to a reverse proxy. A secret URL path (e.g. `https://domain.com/secret-path`) activates the proxy WebSocket or TCP stream.
- **Server Behavior:** All requests to other paths serve a legitimate website (decoy site).
- **Active Probing Resistance:** Outstanding. Automated scanners receive ordinary HTTP 200/404 responses matching standard web servers (Nginx, Caddy).
- **Complexity & Trade-offs:** Requires domain name, valid SSL certificate, and web server infrastructure. Higher latency due to HTTP/2/3 encapsulation.

### 2.4 Tor Snowflake
- **Mechanism:** Solves endpoint blocking (Model A) by routing client traffic through short-lived WebRTC data channels hosted by temporary volunteer browser extensions.
- **Rendezvous:** Uses domain-fronted brokers to negotiate WebRTC SDP offers/answers.
- **Trade-offs:** High latency, variable bandwidth, dependency on broker accessibility. Ideal for circumvention during extreme blackouts, but unsuited for high-throughput single-user VPS setups.

### 2.5 Shadowsocks-2022 (AEAD-2022)
- **Mechanism:** Replaces legacy Shadowsocks stream/AEAD ciphers with an authenticated transport protocol.
  - Header: Contains salt, timestamp (within a 30-second window), and payload length protected by separate AEAD subkeys.
  - Replay Protection: Employs a sliding bloom filter or monotonic timestamp cache to reject replayed handshakes immediately.
  - Active Probing: Unauthenticated connections receive zero response or an immediate RST/FIN depending on configuration, leaving no observable state.
- **Throughput & Efficiency:** Near line-rate speeds; minimal CPU overhead.

---

## 3. Comprehensive Comparative Matrix

| Evaluation Dimension | Paqet (Baseline) | Xray REALITY | Tor obfs4 | Tor WebTunnel | Shadowsocks 2022 | Paqet-NG Target |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Transport Layer** | Raw TCP / libpcap | Standard TCP (TLS 1.3) | Standard TCP | Standard TCP/QUIC (H2/H3) | Standard TCP / UDP | Hybrid Modular |
| **Passive DPI Resistance** | High entropy on raw TCP | Camouflaged as genuine TLS | Random noise (Elligator2) | Indistinguishable from HTTPS | Random noise | Protocol Chameleon / AEAD |
| **Stateful Conntrack Safety** | Fragile (+128 Seq jumps) | Perfect (Kernel TCP stack) | Perfect (Kernel TCP stack) | Perfect (Kernel TCP stack) | Perfect (Kernel TCP stack) | Strict Monotonic TCP / Standard |
| **Active Probing Resistance** | Zero (Silent blackhole tarpit) | Perfect (Transparent forward) | High (Silent drop) | Perfect (Decoy website) | High (Instant drop/close) | Probe-Diverting Fallback / Anti-Replay |
| **Replay Protection** | None in obfs layer | Built-in TLS 1.3 nonces | Built-in epoch/session | Built-in TLS/HTTP | Monotonic Sliding Window | Monotonic Sliding Bloom / Nonce Cache |
| **Sustained Throughput** | ~10.6 Mbps (1.3 MB/s) | 300+ Mbps | ~20-50 Mbps | 100+ Mbps | 500+ Mbps | > 50-100 Mbps |
| **Round-Trip Latency** | ~127 ms (Iran-Germany) | ~90-110 ms | ~180-250 ms | ~130-160 ms | ~90-100 ms | < 110 ms |
| **Kernel Privilege Required** | Yes (`CAP_NET_RAW` / `root`) | No (Standard userspace socket)| No | No | No | Optional / Low-Privilege Clean Mode |
| **NAT Traversal Resilience** | Poor (Breaks behind strict NAT) | Excellent | Excellent | Excellent | Excellent | High |

---

## 4. Key Architectural Lessons for Paqet-NG

1. **Decouple Proxy Logic from Transport:**
   In baseline Paqet, SOCKS5 handling, smux multiplexing, KCP, obfs, and raw pcap are tightly coupled. Paqet-NG must introduce a clean, abstract transport interface (`TransportDialer`, `TransportListener`, `StreamSession`).
2. **Eliminate Non-Standard TCP Sequence Jumps:**
   If raw packet injection is retained as an operational mode, the sequence and acknowledgment numbers must strictly track actual byte counts or utilize kernel-managed sockets to guarantee conntrack consistency across strict middleboxes.
3. **Mandatory Cryptographic Replay Protection:**
   The transport must incorporate session timestamps, epoch markers, and a sliding-window replay filter to immediately drop replayed packets without allocating cryptographic or state resources.
4. **Active-Probe Tarpit Elimination:**
   The server must either:
   - Authenticate the client within the initial message before committing state.
   - Redirect unauthenticated connections to a legitimate decoy service rather than lingering as an identifiable silent blackhole.
