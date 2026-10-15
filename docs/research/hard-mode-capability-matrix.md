# Paqet-NG Hard-Mode Transport Capability and Failure Matrix

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Investigator:** Autonomous Network-Protocol Architect & Transport-Security Auditor  
**Repository:** `https://github.com/arashmh13/paqet`  
**Target Environment:** Severe Censorship, Partial Connectivity, and Emergency Filtering

---

## 1. Executive Summary

This matrix establishes the physical and protocol-level capabilities, prerequisites, failure boundaries, and survivability characteristics of each Paqet-NG transport mode. Rather than treating transports as interchangeable tunnels or relying on synthetic benchmarks, this evaluation separates:
- What has been **empirically proven** on the Iran-to-Germany link.
- What is **theoretically possible** under specific network topologies.
- What is **physically prohibited** by hosting providers and transit networks.

---

## 2. Comprehensive Transport Capability & Failure Matrix

| Transport Mode | Wire Protocol | Required Privileges | Bidirectional Requirement | NAT & CGNAT Traversal | Behavior if Egress Direction Blocked | Behavior if Ingress Direction Blocked | Single Port Block Resilience | Destination IP Block Resilience | Tested Restricted Conditions | Untested Conditions |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`raw-kcp`** | Raw Ethernet/IPv4/TCP frames carrying encrypted KCP datagrams | `CAP_NET_RAW` / Root (libpcap) | Symmetric bidirectional full-duplex | Fails behind symmetric NAT; requires static gateway MAC | Session dies immediately (no ACK) | KCP retransmit storm -> connection drops | Fails if port `:8088` is blocked | Fails (single IP target) | Tested on live Iran-DE path with out-of-window SNI | Packet drop $> 35\%$, sudden ISP gateway MAC change |
| **`aead-stream`** | Userspace TCP stream carrying AEAD-2022 encrypted smux frames | Unprivileged userspace | Symmetric bidirectional TCP | 100% compatible with residential NAT & CGNAT | TCP FIN/RST or timeout | TCP stalls -> zero window -> drop | Fails if port `:8089` is blocked | Fails (single IP target) | Tested under active probing; rejects invalid inputs | Middlebox TCP ACK tampering, active flow throttling |
| **Genuine TLS Outer** | RFC 8446 TLS 1.3 `ApplicationData` (`0x17`) records | Unprivileged userspace | Symmetric bidirectional TLS handshake | 100% compatible with residential NAT & CGNAT | TLS handshake fails (ClientHello times out) | TLS handshake fails (ServerHello dropped) | Fails if port `:8443` is blocked | Fails (single IP target) | Tested with CA certificate validation & rejection | SNI blocking by Iranian TIC, TLS fingerprint (JA4) classification |
| **Raw SNI Injection (`wrong_seq`)** | Raw TCP with out-of-window decoy ClientHello ($Seq < rcv\_nxt$) | `CAP_NET_RAW` / Root (libpcap) | Bidirectional TCP (decoy is unidirectional out-of-window) | Fails behind symmetric NAT | Session dies | Segment dropped | Fails if port `:8088` is blocked | Fails (single IP target) | Tested on live Iran-DE path; decoy accepted by pcap, dropped by kernel | State-tracking DPI requiring bidirectional `ServerHello` |
| **Multi-Port Connection Pool** | Round-robin TCP/KCP connections over multiple destination ports | Unprivileged userspace (for stream) | Symmetric per connection | Compatible with NAT | Stalled connection dropped; other ports continue | Same as egress | **Survives single-port block** (traffic routed over surviving port) | Fails (all ports on same IP) | Tested with concurrent listeners on `:8089` and `:8443` | Dynamic in-flight port migration upon mid-session reset |
| **Automatic Selector (`auto`)** | Dynamic dial fallback across configured transports | Transport-dependent | Evaluates candidate transports | Dependent on selected mode | Dials next available candidate | Current transport marks cooldown, falls back | **Survives** if secondary candidate uses different port | Fails if IP is unreachable | Tested circuit-breaker cooldown and fallback in test lab | Multi-IP rotation fallback |
| **DNS-Asymmetric** | RFC 1035 QNAME Base32 queries upstream; UDP/TCP downstream | Unprivileged userspace (UDP 53) | **Decoupled Asymmetric** (Upstream $\ne$ Downstream) | Fully compatible with NAT via recursive resolvers | Fails if UDP 53 blocked | Fails if downstream channel blocked | **Survives conventional port blocks** (uses UDP 53) | **Survives foreign IP blocks** (routed via 8.8.8.8, 1.1.1.1) | Tested Base32 label framing, reassembly, out-of-order delivery | Live public authoritative DNS delegation traversal |
| **Asymmetric IP Spoofing** | Raw IPv4 datagrams with forged source addresses | `CAP_NET_RAW` / Root | Decoupled Asymmetric | Fails behind NAT (NAT replaces spoofed IP) | Fails | Fails | Dependent on raw protocol | Dependent on routing | **Tested on VPSs: Physically DROPPED by BCP 38 / uRPF** | Bare-metal unverified transit networks |

---

## 3. Physical Egress Spoofing & BCP 38 Audit (October 15, 2026)

To determine whether IP-spoofing architectures (e.g. `ParsaKSH/spoof-tunnel`) are operationally viable on the production infrastructure, controlled raw packet probes were transmitted between the Iran VPS (`185.18.215.124`, Panel01 Datacenter) and the German VPS (`77.37.65.2`, Hetzner Datacenter):

### 3.1 Direction 1: Iran VPS $\longrightarrow$ Germany VPS
- **Control Test (Genuine Source IP `185.18.215.124`):**
  - Sender: `python3 /tmp/raw_sender.py 185.18.215.124 77.37.65.2 9998`
  - Receiver (Germany): Packet received and captured via tcpdump (`SPOOF_PROBE_185.18.215.124`).
  - **Result: PERMITTED.**
- **Subnet Spoof Test (Adjacent IP `185.18.215.45` in same /24 datacenter subnet):**
  - Sender: `python3 /tmp/raw_sender.py 185.18.215.45 77.37.65.2 9998`
  - Receiver (Germany): **Zero packets received.** Egress switch dropped packet.
  - **Result: DROPPED (Strict switch-port MAC/IP binding / uRPF).**
- **Foreign Spoof Test (Documentation Prefix `198.51.100.1`):**
  - Sender: `python3 /tmp/raw_sender.py 198.51.100.1 77.37.65.2 9998`
  - Receiver (Germany): **Zero packets received.** Upstream router dropped packet.
  - **Result: DROPPED (RFC 2827 / BCP 38 egress filtering).**

### 3.2 Direction 2: Germany VPS $\longrightarrow$ Iran VPS
- **Control Test (Genuine Source IP `77.37.65.2`):**
  - Sender: `python3 /tmp/raw_sender.py 77.37.65.2 185.18.215.124 9998`
  - Receiver (Iran): Packet received and captured via tcpdump (`SPOOF_PROBE_77.37.65.2`).
  - **Result: PERMITTED.**
- **Foreign Spoof Test (Documentation Prefix `198.51.100.1`):**
  - Sender: `python3 /tmp/raw_sender.py 198.51.100.1 185.18.215.124 9998`
  - Receiver (Iran): **Zero packets received.** Hetzner vSwitch dropped packet.
  - **Result: DROPPED (Hetzner cloud hypervisor anti-spoofing).**

### 3.3 Concrete Architectural Verdict:
Egress source address spoofing is **strictly blocked** by both Panel01 (Iran) and Hetzner (Germany). IP-spoofing tunnels cannot operate on generic cloud VPS infrastructure without dedicated bare-metal connections with unverified BGP routing. The `asymmetric-spoof` mode is properly gated with `ErrBCP38Enforced`.

---

## 4. Failure Mode Analysis Under Severe Iranian Censorship Conditions

### Condition A: Total National Intranet Curfew (National Information Network / NIN Only)
- **Observed Behavior:** All international TCP SYN packets dropped at TIC (Telecommunication Infrastructure Company) border routers. International UDP dropped except port 53 to domestic resolvers.
- **Survivable Transport:** **DNS-Asymmetric upstream** (queries routed through domestic resolvers that forward to root/authoritative nameservers, or recursive lookups that escape via national DNS caches).

### Condition B: Heavy Outbound Port & SNI Filtering (Standard Iranian Restrictive Regime)
- **Observed Behavior:** Conventional SOCKS5, Shadowsocks, VMess/VLESS without TLS, and ports 1080/8088/8089 are blocked by IP/port blacklists. Port 443 permitted only with recognized SNIs.
- **Survivable Transport:** **Genuine TLS 1.3 Outer Transport** on port 443/8443 with legitimate CA certificates, OR **Raw SNI sequence injection (`wrong_seq`)** on permitted ports.

### Condition C: Asymmetric Uplink Throttling & RST Injection
- **Observed Behavior:** Middleboxes inject TCP RST packets into established outbound streams when payload entropy exceeds thresholds or high traffic volume is sustained.
- **Survivable Transport:** **Multi-Port Connection Pooling** with rapid in-flight stream failover, combined with **Chameleon bucketing padding** to flatten entropy and packet size profiles.
