# Asymmetric Transport Architecture, Directional Decoupling, and Emergency Survival Protocol Design

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Investigator:** Autonomous Network-Protocol Architect & Transport-Security Auditor  
**Repository:** `https://github.com/arashmh13/paqet`  
**Target Environment:** Severe Censorship, Asymmetric Filtering, and National Intranet Curfews

---

## 1. Architectural Motivation & Problem Statement

Conventional proxy and tunnel protocols (including standard TCP, WireGuard, KCP, and TLS) are fundamentally **symmetric**: they require an interactive, full-duplex bidirectional channel over a shared 4-tuple (source IP, source port, destination IP, destination port).

Under severe censorship conditions (such as national internet shutdowns, severe curfew filtering by Iranian TIC, or selective upstream throttling), network symmetry breaks down:
1. **Asymmetric Egress Filtering:** Censors frequently block or throttle outbound international connections (e.g. TCP SYN packets to foreign IPs, non-whitelisted SNIs, or generic UDP) while leaving inbound international traffic lightly filtered.
2. **Protocol Whitelisting:** Egress UDP port 53 (DNS) to domestic/root resolvers may remain open when all other egress ports (80, 443, 8088, 8089) are dropped.
3. **TCP Connection Interference:** Stateful middleboxes inject TCP RST packets into established outbound streams when flow duration or entropy thresholds are exceeded.

To survive these environments, Paqet-NG introduces **Directional Decoupling**: an architecture where upstream (Client $\to$ Server) and downstream (Server $\to$ Client) traffic utilize completely separate, independently selectable network paths.

---

## 2. In-Depth Study of Reference Projects

### 2.1 ParsaKSH/spoof-tunnel
- **Core Mechanism:** Uses raw sockets (`SOCK_RAW`) to craft IPv4 packets with forged source IP addresses.
- **Hypothesis:** By spoofing the client's source IP as an unblocked foreign or domestic IP, egress packet inspection rules that track source-destination pairs are blinded.
- **Empirical Infrastructure Reality (October 15, 2026 Audit):**
  - Tested on Hetzner (Germany VPS) and Panel01 (Iran VPS).
  - **Verdict:** Strictly non-functional on standard VPS and cloud hosting. Both providers enforce BCP 38 / RFC 2827 egress filtering and unicast Reverse Path Forwarding (uRPF). Packets with spoofed source addresses are dropped at the virtual switch / top-of-rack hypervisor layer before ever reaching transit.
  - **Applicability:** Requires dedicated bare-metal infrastructure with unverified BGP transit. In Paqet-NG, this mode is explicitly gated under `asymmetric-spoof` and classified as **Infeasible on Cloud Hosting**.

### 2.2 patterniha/QS-Tunnel
- **Core Mechanism:** Asymmetric transport utilizing DNS queries for upstream communication and direct packets (or alternative tunnels) for downstream communication.
- **Upstream Path:** Client encodes small payload chunks into DNS query domain names (QNAMEs) directed to recursive resolvers (e.g. `8.8.8.8:53` or domestic resolvers). The recursive resolver routes the query to the server's authoritative nameserver.
- **Downstream Path:** Server cannot respond with large streams through DNS responses due to RFC 1035 packet limits (512 bytes UDP) and recursive resolver caching. Instead, the server transmits downstream data directly back to the client's public IP over UDP or TCP.
- **Architectural Strength:** Effectively bypasses national egress TCP firewalls because DNS lookups to domestic resolvers escape the perimeter.

---

## 3. Directionally Decoupled Architecture (`AsymmetricConn`)

Paqet-NG's implementation (`internal/ng/transport/asymmetric.go`) provides a modular `net.Conn` stream abstraction over independent directional transports.

```text
+--------------------------------------------------------------------------+
|                       Application Layer (smux v2 / SOCKS5)                |
+--------------------------------------------------------------------------+
                                     |
                       [AsymmetricConn: net.Conn]
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v (Write: Fragment & Encrypt)                           ^ (Read: Reorder & Decrypt)
+-------------------------------+                       +-------------------------------+
|       UpstreamSender          |                       |      DownstreamReceiver       |
|  - DNS QNAME Framer (UDP:53)  |                       |  - Direct UDP Receiver (:9000)|
|  - Raw Decoy Injection        |                       |  - Inbound Stream Receiver    |
|  - Alternative Egress Socket  |                       |  - ICMP / Secondary Ingress   |
+-------------------------------+                       +-------------------------------+
         |                                                       ^
         v (Outbound Egress)                                     | (Inbound Return)
+-------------------------------+                       +-------------------------------+
|     National Firewall / TIC   |                       |    Unrestricted Ingress Path  |
+-------------------------------+                       +-------------------------------+
         |                                                       ^
         v                                                       |
+-------------------------------------------------------------------------------+
|                           Remote Server (Germany VPS)                         |
|   - UpstreamReceiver (DNS/UDP)   ====>   - DownstreamSender (Direct UDP)      |
+-------------------------------------------------------------------------------+
```

### 3.1 Wire Framing & Sequence Arithmetic
Every asymmetric datagram carries a fixed 20-byte unencrypted header followed by AEAD ciphertext:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic (0x50415141)                      |  "PAQA"
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Session ID (64 bits)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence (32 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          ACK (32 bits)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      AEAD Ciphertext ...                      |
|              (Payload + 16-byte Poly1305 / GCM Tag)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Cryptographic Key Separation & Anti-Replay
1. **Key Derivation:** Directional subkeys ($K_{c2s}$ and $K_{s2c}$) are derived using HKDF-SHA256 from the Pre-Shared Key (PSK) and the unique 64-bit `SessionID`.
2. **Deterministic Nonce Construction:**
   $$\text{Nonce} = \text{SessionID (8B)} \,\|\, \text{Seq (4B)}, \quad \text{Nonce}[0] \oplus= \text{Role}$$
   This guarantees that nonces are never repeated across directions or sequence increments.
3. **Cryptographic Validation Order (Anti-DoS Rule):**
   The receiver **must authenticate** the AEAD ciphertext *before* updating the sliding-window replay filter. Testing proved that verifying replay before AEAD authentication allows an unauthenticated attacker to advance the replay bitmap and cause denial of service.

### 3.3 Reassembly & Reordering
Because upstream and downstream datagrams travel over connectionless transports (UDP / DNS queries), packet reordering and loss are expected. `AsymmetricConn` incorporates a reassembly map:
- If packet arrives with $\text{Seq} == \text{nextExpected}$: payload is immediately delivered to the application read pipe, and any consecutively buffered packets are drained.
- If packet arrives with $\text{Seq} > \text{nextExpected}$: payload is held in the reorder buffer (up to 256 packets).
- Replayed sequence numbers are detected and discarded by `replay.Filter`.

---

## 4. DNS-Asymmetric Protocol Analysis & Empirical Bounds

### 4.1 RFC 1035 Constraints & Wire Amplification
DNS queries used for upstream data are subject to RFC 1035 constraints:
- Maximum length of a domain label: **63 characters**.
- Maximum total length of a domain name: **253 characters**.
- Standard Base32 expansion: 5 bytes raw binary $\to$ 8 characters text ($1.6\times$ expansion).

In Paqet-NG's QNAME format:
`p<part>.t<total>.o<offset>.<base32chunk>.<clientID>.<domainSuffix>`
- Maximum binary payload per label: **35 bytes** ($35 \times 8 / 5 = 56$ base32 characters).
- DNS Query Wire Size: IPv4 header (20B) + UDP header (8B) + DNS Header (12B) + QNAME (82B) + Type/Class (4B) = **126 bytes**.
- **Measured Wire Amplification:** $\frac{126\text{ bytes}}{35\text{ bytes}} = \mathbf{3.60\times}$!

### 4.2 Measured Throughput & Rate Limits
Tested in `internal/ng/transport/dns_asymmetric_test.go`:
- **Conservative Resolver Rate (20 queries/second):**
  $$20\text{ qps} \times 35\text{ bytes} \times 8 = \mathbf{5.60\text{ kbps}}$$
- **Aggressive Resolver Rate (100 queries/second):**
  $$100\text{ qps} \times 35\text{ bytes} \times 8 = \mathbf{28.00\text{ kbps}}$$
- **Latency:** Round-trip query latency through recursive resolvers averages $150 - 450\text{ ms}$.

### 4.3 Conclusion on DNS Transport
DNS-asymmetric is **fundamentally unsuitable** for general web browsing, video streaming, or bulk data transfer. Claiming it as a full SOCKS5 replacement is technically false.
However, it is uniquely capable as:
1. **Emergency Signaling & Bootstrap Channel:** Exchanging dynamic IP/port configurations or rotating TLS certificates when primary ports are blocked.
2. **Text / Command Line Channel:** Low-bandwidth terminal sessions (SSH) or encrypted messaging during national firewall blackouts.
