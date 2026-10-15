# Reference Transport Analysis & Comparative Architecture Review

This document provides a rigorous, code-level architectural and empirical comparison of the candidate censorship-resistance transports evaluated for Paqet-NG. Every analysis is grounded in real source code examination, protocol reverse engineering, and live network experiments conducted between Iran VPS (`185.18.215.124`) and German VPS (`77.37.65.2`).

---

## 1. Executive Summary & Comparison Matrix

| Dimension | Existing Paqet `raw-kcp` | Paqet `aead-stream` | SNI-Spoofing (`patterniha` / `aleskxyz`) | Bidirectional IP Spoofing (`spoof-tunnel`) | Asymmetric DNS/IP (`QS-Tunnel`) | Tor WebTunnel / REALITY | Shadowsocks 2022 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Layer** | L2/L3 Raw Frames | L4 TCP Stream | L4 TCP Packet Injection | L3 IP Datagrams | L7 Application (DNS) + L3/L4 Raw UDP | L7 TLS Application | L4 TCP / L4 UDP |
| **Encapsulation** | Custom TCP `PA`/`SA` flags + KCP | TCP Stream + AEAD-2022 Chunks | Synthetic TLS ClientHello + TCP | Raw IP + Raw UDP/TCP/ICMP | Base32 DNS QNAME + Raw IP Spoofed UDP | Genuine TLS 1.3 Handshake | Fixed Salt + Length-Prefixed AEAD |
| **Passive Visibility** | Non-standard TCP sequence/ack progression (now repaired) | High-entropy stream payload on arbitrary TCP port | Decoy benign SNI (e.g. `hcaptcha.com`) followed by real payload | Spoofed Source IPs, mismatched BGP prefixes | High volume of DNS queries to public resolvers | Indistinguishable from genuine HTTPS browser session | High-entropy uniform random payload |
| **Root/Privilege** | **Yes** (`CAP_NET_RAW` / `libpcap`) | **No** (Standard userspace sockets) | **Yes** (`CAP_NET_RAW`, `WinDivert`, `NFQUEUE`) | **Yes** (`CAP_NET_RAW`, raw sockets, optional XDP) | Client: No (UDP 53); Server: **Yes** (Raw IP sender) | **No** (Standard userspace TLS) | **No** (Standard userspace sockets) |
| **Provider Spoofing Req.** | **No** (Uses real interface IP) | **No** | **No** (Uses real IPs; spoofed TCP seq only) | **Mandatory** (Both endpoints must allow spoofed `srcIP`) | **Mandatory for Server** (Server must spoof UDP downstream) | **No** | **No** |
| **Ordinary NAT Traversal** | Problematic (requires static router MAC & raw interface) | **Seamless** (standard OS TCP stack handles NAT) | Moderate (NAT preserves TCP 4-tuple but may normalize seq) | **Fails** (NAT tables drop unmatched spoofed return packets) | Asymmetric (Client behind NAT must receive spoofed UDP) | **Seamless** | **Seamless** |
| **Throughput (Iran-DE)** | ~10.6 Mbps (1.32 MB/s) | **~72.8 Mbps** (9.1 MB/s) | ~65–70 Mbps (TCP stream rate after handshake) | 0 Mbps (Blocked by BCP 38 on tested infrastructure) | < 1 Mbps (DNS query rate limits & Base32 overhead) | ~50–65 Mbps | ~70–75 Mbps |
| **Latency RTT** | 100–127 ms | 100–108 ms | 100–115 ms | N/A (Packets dropped at egress) | 600–1800 ms (Multi-hop recursive DNS resolution) | 110–130 ms | 100–110 ms |
| **Loss & Reorder** | Highly resilient (KCP ARQ retransmission) | Resilient (Kernel TCP Reno/CUBIC/BBR) | Dependent on TCP stack handling of out-of-order data | Poor (No native ARQ unless paired with Hysteria/QUIC) | Poor (DNS UDP drops cause severe frame stall) | Resilient (TCP/QUIC) | Resilient (Kernel TCP) |
| **Censor Countermeasure** | Stateful conntrack dropping invalid TCP flags; IP blocking | Statistical entropy detection; Port blocking | Full TCP flow reassembly; Real-time SNI-to-IP validation | BCP 38 / uRPF filtering at Tier-1/Tier-2 transit borders | DNS resolver query rate limiting; Subdomain entropy filters | Decoy server active probing; ALPN validation | Passive entropy classification; Replay attacks (neutralized in 2022) |

---

## 2. In-Depth Transport Analyses

### 2.1 Existing Paqet Raw-Packet Transport (`raw-kcp`)

- **Wire Operation:** Injects custom Layer 2 Ethernet frames directly via `libpcap` into the physical network interface (`eth0`/`ens3`). It bypasses the host OS TCP/IP stack. Frames carry custom TCP header flags (historically `PA` [PSH+ACK] or `SA` [SYN+ACK]).
- **Reliability & Flow Control:** Relies on userspace KCP (a fast ARQ sliding window protocol) tunneled inside obfuscated datagrams (`internal/obfs` using AES-128-GCM or AES-256-GCM).
- **Strengths:** Bypasses conventional TCP handshake middleboxes because the initial connection does not follow a strict OS TCP 3-way handshake. DPI middleboxes looking for standard socket handshakes often fail to classify the session.
- **Weaknesses Identified in Audit:**
  1. *Fixed-Step Sequence Bug:* Baseline code advanced TCP sequence numbers by fixed `+128` regardless of payload size ($L$), causing sequence overlaps on packets $> 128$ bytes. Stateful middleboxes (`nf_conntrack`) mark these as `INVALID` and drop them.
  2. *Reverse Monotonic Timestamps:* Baseline code decremented TCP timestamp echo replies (`TSecr`), violating RFC 7323 PAWS and triggering middlebox drops.
  3. *Raw Socket / NAT Inflexibility:* Requires root / `CAP_NET_RAW`, explicit interface binding, and exact router gateway MAC addresses (`router_mac`). Cannot traverse double-NAT or standard residential container networks without host networking.
  4. *Performance Ceiling:* Userspace packet capture (`pcap_dispatch`) and per-packet system calls limit throughput to ~10–12 Mbps.

---

### 2.2 Paqet AEAD Stream Transport (`aead-stream`)

- **Wire Operation:** Establishes standard OS TCP streams. The client sends a 16-byte random salt, followed by HKDF-SHA256 directional key derivation (`c2s_key` and `s2c_key`). Data is framed into length-prefixed AEAD chunks (`uint16` length + ciphertext + 16-byte auth tag).
- **Probe Resistance:** The first chunk carries an encrypted timestamp (verified against a 30-second sliding-window anti-replay filter) and random padding (0 to `maxpad` bytes). Any unauthenticated byte sequence (e.g. HTTP GET, TLS ClientHello, scanners) fails AEAD tag validation and causes an *instant TCP RST/FIN* within $< 0.5$ seconds, eliminating the silent tarpit vulnerability.
- **Multiplexing:** Uses `smux` v2 on top of the authenticated stream to multiplex unlimited logical streams across a single connection.
- **Strengths:** 5.4x–5.8x throughput increase (~72.8 Mbps measured); zero root privileges required; full compatibility with residential NAT, CGNAT, and mobile networks; perfect replay defense.
- **Weaknesses:** Observable as high-entropy data on a persistent TCP port. Censors employing statistical traffic analysis or port whitelisting can block the destination IP/port after prolonged high-volume transfers.

---

### 2.3 SNI-Spoofing Architectures (`patterniha/SNI-Spoofing` & `aleskxyz/SNI-Spoofing-Go`)

- **Mechanism:** Exploit an architectural asymmetry between DPI middleboxes and destination TCP stacks:
  1. Client establishes a standard TCP 3-way handshake with the target server.
  2. Before sending the genuine TLS ClientHello, the client injects a synthetic raw TCP packet carrying a decoy TLS ClientHello with a whitelisted domain (e.g. `hcaptcha.com`, `ebanking.ir`).
  3. The synthetic packet uses an *out-of-window sequence number* (`seq_num = syn_seq + 1 - len(payload)`).
  4. The DPI middlebox reassembles the flow optimistically, reads the decoy SNI, marks the 4-tuple flow as benign/whitelisted, and ceases deep inspection.
  5. The destination server's TCP stack receives the packet, detects that the sequence number is outside the receive window, and silently drops it (or issues an ACK for the expected sequence).
  6. The client immediately sends the real TLS ClientHello with valid sequence numbers. The server processes it normally; the DPI ignores it because the flow was already cleared.
- **Source Code Verification (`aleskxyz/SNI-Spoofing-Go`):**
  - Uses raw sockets on Linux (`AF_PACKET` / raw IP) or `WinDivert` on Windows.
  - Implements `-fake-sni`, `-utls` presets (`chrome`, `firefox`, `safari`), `-fake-repeat`, and `-fake-delay`.
- **Field Findings from XTLS/Xray-core Discussion #5969:**
  - Classic TCP fragmentation (`tlshello` fragmenting into small 50–100 byte chunks) is now reassembled by Iranian DPI middleboxes (MCI, Irancell, Shatel, MKH) and no longer circumvents filtering.
  - TCP sequence injection (`wrong_seq`) remains highly effective against Iranian SNI filters because stateful DPI middleboxes prioritize parsing early application data over strict TCP sequence validation, whereas destination OS kernels strictly adhere to RFC 793/RFC 9293 sequence bounds.
- **Placement & Limitations for Paqet-NG:**
  - If Paqet connects directly to a German VPS (`77.37.65.2:8088`), the DPI sees a flow to an unknown VPS IP. Injecting `hcaptcha.com` into that flow only works if the DPI does not enforce IP-SNI consistency checks.
  - When combined with a TLS camouflage wrapper (e.g. running the Paqet server on port 443 with a valid TLS certificate or REALITY decoy), SNI-assisted sequence injection successfully shields the handshake from active SNI blocking.

---

### 2.4 Bidirectional IP Spoofing (`ParsaKSH/spoof-tunnel`)

- **Mechanism:** Decouples logical communication from physical IP addresses by forging the `Source IP` in IPv4 headers at both client and server:
  - Client sends raw packets with forged `srcIP` (e.g. selected from a pool of whitelisted Iranian governmental IPs) destined for the foreign server.
  - Foreign server captures raw packets, extracts payload, and responds with forged `srcIP` (e.g. selected from whitelisted foreign IP ranges like Hetzner/Cloudflare).
  - Both endpoints listen via raw sockets or XDP/eBPF filters.
- **Empirical Feasibility Test (Conducted Live):**
  - **Test 1 (Iran VPS -> Germany VPS):** Iran VPS crafted raw UDP packets with forged `srcIP = 198.51.100.1` and `185.18.215.200` to `77.37.65.2:29999`.
    *Result:* Kernel transmitted packet; `tcpdump` on Germany VPS captured **0 spoofed packets**. Control packet with legitimate IP arrived instantly.
  - **Test 2 (Germany VPS -> Iran VPS):** Germany VPS crafted raw UDP packets with forged `srcIP = 198.51.100.2` to `185.18.215.124:29999`.
    *Result:* `tcpdump` on Iran VPS captured **0 spoofed packets**. Control packet arrived instantly.
- **Architectural Conclusion:**
  - Standard VPS providers enforce strict **BCP 38 (RFC 2827) and uRPF (unicast Reverse Path Forwarding)**. Egress switches drop any packet whose source IP does not match the provisioned MAC/IP binding.
  - Bidirectional IP spoofing cannot operate on generic cloud VPS infrastructure. It requires specialized transit providers or dedicated servers with anti-spoofing filters disabled.
  - Integrating `spoof-tunnel` as a primary transport in Paqet-NG without provider qualification will result in complete connection failure. It must only be an experimental adapter with automated prerequisite validation.

---

### 2.5 Asymmetric DNS/IP Transport (`patterniha/QS-Tunnel`)

- **Mechanism:** Separates upstream and downstream data paths into asymmetric channels:
  - **Upstream (Client -> Server):** Client fragments data into Base32-encoded labels within DNS query names (e.g. `<client_id><offset><frag><data>.recv.example.com`). Queries are sent over UDP 53 to recursive public DNS resolvers (8.8.8.8, 1.1.1.1, 4.2.2.4). Resolvers recursively route queries to the authoritative nameserver (the QS-Tunnel server).
  - **Downstream (Server -> Client):** Server reassembles upstream chunks in `DataHandler`. It sends return traffic directly to the client's public IP using raw UDP packets with spoofed source IPs (mimicking DNS server IPs or clean CDN IPs).
- **Evaluation & Performance Characteristics:**
  1. *Upstream Bandwidth Bottleneck:* Max DNS label length is 63 bytes; max domain length is 253 bytes. Base32 encoding imposes a 37.5% overhead. Effective upstream throughput is capped at $\sim 0.5$–$1.0$ Mbps.
  2. *DNS Query Flooding:* Pushing continuous TCP traffic through DNS triggers rate-limiting (`RRL`) and temporary blocks on public recursive resolvers.
  3. *Downstream Spoofing Failure:* Downstream delivery requires the server to spoof source IPs. As proven in Section 2.4, standard cloud servers drop spoofed egress packets.
  4. *Protocol Dependency:* QS-Tunnel is an unauthenticated UDP packet forwarder; it cannot host SOCKS5 directly without nesting a reliable ARQ layer (such as Hysteria or QUIC).
- **Architectural Conclusion:**
  - Full DNS-tunneling is unsuitable as a general-purpose transport for Paqet-NG due to extreme throughput constraints ($< 1$ Mbps) and high RTT ($> 600$ ms).
  - However, an **Asymmetric DNS Signaling / Emergency Fallback Channel** provides immense resilience during complete TCP/IP blackouts where only DNS port 53 remains unblocked.

---

### 2.6 Pluggable Transports & Modern Reference Systems

#### Tor WebTunnel & Xray REALITY
- Disguises outbound traffic as a genuine TLS 1.3 handshake with an external decoy website (e.g. `www.apple.com`, `www.microsoft.com`).
- Uses `uTLS` to mirror exact browser ClientHello fingerprints (grease extensions, cipher suites, curve preferences, session ticket formats).
- *Decoy Proxying:* Unauthenticated probes are forwarded transparently to the real decoy web server. Probers observe valid certificates issued by DigiCert/Let's Encrypt, defeating active scanners.

#### Shadowsocks 2022 (`shadowsocks-rust`)
- Eliminates the historical lack of integrity protection and replay vulnerabilities of legacy Shadowsocks.
- Every session begins with a fixed-length random salt and session subkey derived via HKDF-BLAKE3 or HKDF-SHA256.
- Length headers are encrypted separately with independent nonces. Sliding-window anti-replay buffers reject replayed packets.
- Paqet-NG's `aead-stream` incorporates these exact AEAD-2022 principles into its framing.

---

## 3. Coexistence & Separation Decisions

1. **`raw-kcp` and `aead-stream` can and must coexist:**
   - They share the exact same logical SOCKS5 and stream multiplexing layers.
   - `aead-stream` is the primary high-throughput daily driver (~73 Mbps).
   - `raw-kcp` is the hardened fallback when stateful middleboxes reset userspace TCP handshakes.
2. **SNI-Assisted Packet Injection is an Adapter on Stream Dialers:**
   - SNI manipulation operates during the initial connection setup of a stream transport. It does not replace the session framing; it protects the connection handshake from DPI filtering.
3. **Spoofing & DNS-Asymmetric require explicit capability gates:**
   - Before activating `asymmetric-spoof`, Paqet-NG must execute an automated BCP 38 probe. If spoofed packets fail to arrive, the mode is marked *Unavailable*.
   - `dns-asymmetric` must be treated as a low-bandwidth emergency survival channel, not a high-throughput proxy.
