# SlipNet Architecture Review, Transport Decomposition, and Licensing Analysis

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Investigator:** Autonomous Principal Network-Protocol Architect & Transport-Security Auditor  
**Repository Target:** `https://github.com/arashmh13/paqet`  
**Reference Repositories:**  
- `https://github.com/anonvector/SlipNet` (Client, AGPL-3.0)  
- `https://github.com/anonvector/slipgate` (Server Management, AGPL-3.0)  
- `https://www.bamsoftware.com/git/dnstt.git` (DNSTT Reference, David Fifield)

---

## 1. Executive Summary & Purpose

SlipNet and its companion server management suite `slipgate` provide an Android and Linux multi-transport proxy platform designed for censorship resistance. Unlike monolithic single-transport projects, SlipNet assembles multiple independent tunneling technologies into a unified operator dashboard and client UI.

This review analyzes the architectural decisions, wire protocols, transport lifecycle, resolver capability evaluation, and licensing constraints of SlipNet to determine:
1. Which architectural principles are appropriate for integration into Paqet-NG.
2. Which components should be independently implemented versus accessed via external adapters.
3. How to avoid legal copyleft contamination given SlipNet's **GNU Affero General Public License v3.0 (AGPL-3.0)** versus Paqet-NG's **MIT / Apache-2.0** terms.

---

## 2. Decomposition of SlipNet's Supported Transport Families

SlipNet categorizes its connectivity strategies into distinct operational niches:

| Transport | Layer / Port | Underlying Technology | Operational Role & Sensor Profile | SlipNet Implementation Model |
| :--- | :--- | :--- | :--- | :--- |
| **DNSTT** | UDP:53 / DoH | Noise protocol (Curve25519) + KCP + smux | Established encrypted DNS tunnel; Base32/Base64 in QNAME, responses in TXT/NULL records | Bundled external Go library (`app/libs/dnstt.aar`) |
| **NoizDNS** | UDP:53 / DoH | Same server as DNSTT; client adds DPI evasion | Disguises query cadence via randomized jitter, padding, and decoy queries to evade statistical length/entropy classifiers | Client-side wrapper around DNSTT engine |
| **VayDNS** | UDP:53 | Tunable KCP-based DNS tunnel | Optimized for flaky/lossy DNS paths; tunable clientid size, record types (`TXT`, `A`, `AAAA`), queue sizes | Bundled external Go library (`app/libs/vaydns.aar`) |
| **Slipstream** | UDP:53 | QUIC over DNS datagrams | High throughput on clean/unthrottled networks; low-latency multiplexing | External binary / Go daemon |
| **NaiveProxy** | TCP:443 | Chromium network stack + Caddy forwardproxy | Mimics Google Chrome browser TLS/HTTP2 stack; redirects unauthenticated probers to legitimate decoy websites | External Caddy binary with forwardproxy plugin |
| **StunTLS** | TCP:443 | SSH over TLS / SSH over WebSocket | Self-signed or CDN-friendly WebSocket tunnel; works behind Cloudflare/Fastly CDN fronting | Go wrapper over OpenSSH / WebSocket |
| **Tor Pluggable Transports** | Various | Snowflake (WebRTC), obfs4, Meek (domain fronting) | Global circumvention baseline maintained by The Tor Project | Tor PT client binaries invoked via SOCKS5 proxy |

---

## 3. Deep-Dive: SlipNet's Resolver Capability Evaluation System

A critical strength of SlipNet is its **Resolver Scanner** (`cli/scanner.go` in SlipNet CLI and `app/src/main/java/app/slipnet/tunnel/DnsResolverProber.kt` in Android). In restrictive countries like Iran, public recursive resolvers (e.g. `8.8.8.8`, `1.1.1.1`, `4.2.2.4`) are frequently poisoned, rate-limited, or blocked by national ISPs.

SlipNet's scanner evaluates candidate resolvers across 6 independent capability checks:

```text
                               [Candidate Resolver IP:Port]
                                            |
         +----------------------------------+----------------------------------+
         |                                  |                                  |
         v                                  v                                  v
 [1. Basic A Reachability]         [2. NS -> A Delegation]            [3. TXT Query Support]
 (Latency < 1500ms, RCODE!=ERR)    (Resolves zone NS, then A)         (Answers TXT records)
         |                                  |                                  |
         +----------------------------------+----------------------------------+
                                            |
         +----------------------------------+----------------------------------+
         |                                  |                                  |
         v                                  v                                  v
 [4. Random Subdomain Support]      [5. Tunnel Realism (DPI)]         [6. NXDOMAIN Non-Hijack]
 (Resolves dynamic subdomains)     (Long Base32 query labels <= 57)   (RCODE=3 on .invalid query;
                                                                       detects ISP landing pages)
                                            |
                                            v
                             [7. EDNS0 Buffer Size Probe]
                             (Probes OPT RR: 512, 900, 1232B)
```

### 3.1 Scoring and Metric Breakdown:
- **`NSSupport`:** Verifies that the resolver queries the zone's authoritative nameserver and returns the A-record glue.
- **`TXTSupport`:** Verifies that TXT records (which carry downstream payload chunks) are delivered without stripping.
- **`TunnelRealism`:** Emulates full-length Base32 tunnel queries (57 characters per label). If middleboxes drop long labels, this check fails.
- **`NXDOMAINCorrect`:** Queries `<random>.invalid`. If the resolver returns `NOERROR` with an IP address (common in Iran where ISPs redirect failed lookups to government landing pages or advertisements), `NXDOMAINCorrect` fails, as hijacked NXDOMAIN corrupts tunnel signaling.
- **`EDNS0MaxPayload`:** Probes whether the resolver supports EDNS0 extension (RFC 6891) for payloads up to 1,232 bytes, which enables $2.4\times$ higher throughput than standard 512-byte UDP.

---

## 4. Software Licensing Audit & Legal Compatibility Analysis

### 4.1 License Conflict Identification
- **SlipNet License:** `GNU Affero General Public License v3.0 (AGPL-3.0)`.
- **Slipgate License:** `GNU Affero General Public License v3.0 (AGPL-3.0)`.
- **Paqet-NG License:** `MIT License` / `Apache-2.0`.

### 4.2 AGPL-3.0 Legal Implications
Section 13 of the AGPL-3.0 states:
> *"Notwithstanding any other provision of this License, if you modify the Program, your modified version must prominently offer all users interacting with it remotely through a computer network ... an opportunity to receive the Corresponding Source of your version..."*

Copying any source code, structs, or functions from SlipNet directly into Paqet-NG would create a **derivative work**, legally forcing Paqet-NG to relicense its entire repository under AGPL-3.0. This would destroy Paqet-NG's permissive MIT downstream usability.

### 4.3 Mandatory Architectural Decision: Clean-Room Implementation
1. **Zero Source Code Ingestion:** Paqet-NG **must not** copy or translate source code from `anonvector/SlipNet` or `anonvector/slipgate`.
2. **Open Standards Implementation:** All Paqet-NG features (including the resolver capability scanner and DNS tunneling engines) must be implemented clean-room using Go standard library packages (`net`, `crypto`, `encoding/binary`) based exclusively on open IETF specifications (RFC 1035, RFC 6891, RFC 2181, RFC 8446).
3. **Pluggable Adapter Interfaces:** Where third-party binaries (such as `dnstt-client`, `naiveproxy`, or Tor PTs) are utilized, Paqet-NG will interact with them strictly through **decoupled process boundaries** (SOCKS5 forwarding on `127.0.0.1`, stdin/stdout pipes, or standard CLI arguments), preserving license isolation.

---

## 5. Architectural Comparison: SlipNet vs. Paqet-NG

| Dimension | SlipNet / Slipgate Architecture | Paqet-NG Architecture | Strategic Decision for Paqet-NG |
| :--- | :--- | :--- | :--- |
| **Primary Philosophy** | Aggregation of external tunnels via bash/Android wrapper | Unified Go networking library with modular internal transports | Retain Go-native core; expose clean Go `Strategy` interfaces |
| **Low-Level Packet Control** | None (relies on standard userspace UDP/TCP sockets) | Deep Layer 2/3/4 packet crafting (`libpcap`, raw sockets, `wrong_seq`) | **Preserve Paqet-NG advantage:** Low-level packet desync defeats stateful conntrack |
| **DNS Tunneling** | External binaries (`dnstt`, `vaydns`, `slipstream`) | Internal native `AsymmetricConn` + QNAME/TXT framing | Maintain native Go framing; add public NS delegation support |
| **Resolver Intelligence** | High: Comprehensive 6-point capability scanner & scorer | Previously None: Hardcoded resolver IP (`8.8.8.8`) | **Adopt Strategy:** Implement native Go clean-room resolver scanner |
| **NAT Traversal** | Uses symmetric DoH / DNS / HTTPS tunnels | Dual: `raw-kcp` for server-to-server; `aead-stream` for residential NAT | Preserve dual capability; route users to `aead-stream` or `tls` |
| **Failover Control** | User manually selects profile in Android app | Automated `StrategySelector` with candidate cooldowns & hysteresis | **Expand Paqet-NG Controller:** Autonomous failure detection and recovery |

---

## 6. Actionable Recommendations for Paqet-NG

1. **Build a Native Resolver Scanner (`internal/ng/dns/scanner.go`):**  
   Implement a clean-room Go package evaluating candidate resolvers on reachability, RTT, EDNS0 max buffer size, NXDOMAIN preservation, and tunnel responsiveness.
2. **Support Public Recursive Delegation:**  
   Configure dedicated child zone delegation (`tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`) using Cloudflare API to validate public recursive DNS tunneling live.
3. **Enhance Transport Controller:**  
   Integrate the resolver scanner into `StrategySelector`, allowing automatic discovery and failover to healthy public or local resolvers when primary resolvers are throttled.
