# DNS-Asymmetric Protocol: End-to-End Validation, Empirical Firewall Probing, and Operational Boundary Analysis

**Document Version:** 2.0.0  
**Date:** October 15, 2026  
**Investigator:** Autonomous Principal Network-Protocol Architect, Transport-Security Auditor & Go Systems Engineer  
**Repository:** `https://github.com/arashmh13/paqet`  
**Classification:** **OPERATIONAL & PUBLICLY VALIDATED (Candidate B via Recursive DNS TXT)**

---

## 1. Executive Summary & Status Classification

Following the explicit directives of the milestone audit, this report reconciles the operational status of Paqet-NG's DNS-asymmetric transport with live public validation.

### Definitive Status:
- **Unit & Local Socket Implementation:** **COMPLETE & TESTED.** Real OS network UDP socket implementations (`RealSocketDNSUpstreamSender`, `RealSocketDirectUDPReceiver`, `BuildDNSQuery`, `BuildDNSTXTResponse`) pass 100% of end-to-end tests for both Candidate A (direct return) and Candidate B (DNS-mediated return).
- **Public End-to-End Live Status:** **OPERATIONAL & PUBLICLY VERIFIED.** Tested live across the Iranian national border gateway using authorized public domain delegation on `passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`.
- **Live Empirical Evidence (October 15, 2026):**
  * Client on Iran VPS (`185.18.215.124`) dispatched DNS TXT query to Google Public DNS (`8.8.8.8:53`).
  * Google recursive resolvers traversed public NS delegation and reached the authoritative Paqet daemon on Germany VPS (`77.37.65.2:53`) from Google egress node `172.253.228.151`.
  * Authoritative server processed the request and emitted an authenticated TXT response.
  * Google returned the response back to Iran VPS in **$140.98\text{ ms}$** with `ancount = 1` and authenticated payload `AUTHENTICATED_PAQET_DNS_RECURSIVE_TRAVERSAL_OK`.

---

## 2. Empirical Firewall Probing on Live Iran-to-Germany Link (October 15, 2026)

To understand the real-world filtering environment governing DNS traffic out of Iran, active UDP probes were executed from the Iran VPS (`185.18.215.124`, Panel01 Datacenter, Tehran):

### 2.1 Arbitrary International UDP Ports
- Tested destination ports on Germany VPS (`77.37.65.2`): `5353`, `8999`, `9000`, `9998`.
- **Result:** **100% BLOCKED / TIMED OUT.**
- **Finding:** Iranian TIC border routers enforce a strict default-deny policy on outbound international UDP traffic for arbitrary non-whitelisted ports.

### 2.2 Direct UDP to Foreign VPS on Port 53
- Transmitted minimal DNS queries directly from Iran VPS to Germany VPS IP on port 53 (`77.37.65.2:53`).
- **Result:** **BLOCKED / TIMED OUT.**
- **Finding:** TIC border firewalls inspect the destination IP of outbound UDP port 53 datagrams. Packets directed to arbitrary foreign IP addresses are discarded, even when using port 53.

### 2.3 Recursive Resolver UDP to Public DNS (8.8.8.8:53)
- Transmitted standard DNS A-record query for `example.com` to Google Public DNS (`8.8.8.8:53`).
- **Result:** **PERMITTED (Received 61-byte authentic DNS response in $< 90\text{ ms}$).**
- **Finding:** Only outbound UDP port 53 traffic targeting recognized, whitelisted recursive DNS resolvers is permitted to exit the national network perimeter.

### 2.4 Core Architectural Conclusion:
Direct point-to-point UDP DNS tunneling (Client $\to$ Server VPS) **cannot survive** in Iran. A viable DNS tunnel **strictly requires** recursive delegation through public resolvers:
$$\text{Client} \xrightarrow[\text{UDP:53}]{\text{Whitelisted}} \text{Recursive Resolver (8.8.8.8)} \xrightarrow[\text{NS Lookup}]{\text{Global Internet}} \text{Authoritative Server (Germany VPS)}$$

---

## 3. Comparative Architecture: Candidate A vs. Candidate B

Paqet-NG evaluated two distinct asymmetric return-path architectures:

### 3.1 Candidate A: DNS Upstream with Direct UDP Return
- **Upstream Path:** Client encodes authenticated application chunks into DNS QNAME queries (RFC 1035 Base32) targeting a recursive resolver.
- **Downstream Path:** Server reassembles chunks and transmits authenticated response frames directly back to the client's public IP over a raw UDP socket.
- **Empirical Socket Test (`TestRealSocketDNSAsymmetricCandidateAEndToEnd`):**
  - Executed over real OS UDP sockets (`net.ListenUDP`).
  - Successfully fragmented, transmitted via DNS query packets, decoded, reassembled, and echoed back over direct UDP in **$30\text{ ms}$**.
- **Critical Real-World Limitation:**
  Candidate A **fails behind residential NAT and CGNAT**. Consumer routers and 4G/LTE mobile networks do not forward unsolicited inbound UDP packets to internal hosts unless stateful NAT hole punching or UPnP is established. Candidate A is strictly viable only when the client possesses an externally accessible public IP or port forwarding.

### 3.2 Candidate B: DNS-Mediated Return (TXT Answer Records)
- **Upstream Path:** Client sends standard DNS TXT queries.
- **Downstream Path:** Authoritative server encodes downstream authenticated response frames into the `RDATA` of DNS TXT answer records (`BuildDNSTXTResponse`). The recursive resolver forwards the response back to the client's original socket.
- **Empirical Socket Test (`TestRealSocketDNSAsymmetricCandidateBEndToEnd`):**
  - Executed over real OS UDP sockets with bidirectional request/response correlation.
  - Successfully transmitted, encapsulated in TXT records, and reassembled in **$20\text{ ms}$**.
- **Critical Real-World Limitation:**
  - **Caching Constraints:** Responses must set `TTL = 0` to prevent recursive resolvers from caching and serving stale data.
  - **Response Size Ceiling:** Standard UDP DNS responses without EDNS0 are capped at **512 bytes**. Larger responses require EDNS0 (up to 1232–1420 bytes) or trigger TCP fallback (`TC=1`), which is blocked by TIC.
  - **Throughput:** Halves upstream bandwidth due to synchronous query-response turnarounds.

---

## 4. Defined Emergency Use Case & Performance Bounds

| Performance Parameter | Measured Empirical Value | Impact on Application Suitability |
| :--- | :--- | :--- |
| **Max Payload per Label** | $35\text{ bytes}$ (56 Base32 characters) | RFC 1035 label limit (63 chars) |
| **Wire Amplification** | **$3.60\times$** (126B query for 35B payload) | High bandwidth overhead |
| **Conservative Rate (20 qps)** | **$5.60\text{ kbps}$** ($0.70\text{ KB/s}$) | Below minimum web browsing threshold |
| **Aggressive Rate (100 qps)** | **$28.00\text{ kbps}$** ($3.50\text{ KB/s}$) | Triggers resolver rate limiting (RRL) |
| **Median RTT** | $150\text{ ms} - 450\text{ ms}$ | High latency for interactive streams |

### Explicit Use-Case Boundaries:
- **UNSUITABLE:** General SOCKS5 web browsing, media streaming, bulk downloads, and interactive GUI applications.
- **APPROPRIATE EMERGENCY ROLES:**
  1. **Dynamic Bootstrap & Signaling:** Transmitting new server IP addresses, ports, or rotated TLS certificates when primary ports are blocked.
  2. **Encrypted Emergency Messaging:** Low-bandwidth asynchronous text communication during total national internet curfews.
  3. **Terminal Access:** Low-rate CLI/SSH command execution.

---

## 5. Live Public Domain Delegation & Verification Results

The public DNS delegation was established on Cloudflare for the operator's verified domain `passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`:

### 5.1 Configured Zone Records (Cloudflare API)
1. **Authoritative Nameserver Glue (`A` Record):**
   - Hostname: `ns-de.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`
   - Content: `77.37.65.2` (German VPS)
   - TTL: `300` (Proxied: `false`)
2. **Child Zone Delegation (`NS` Record):**
   - Hostname: `tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`
   - Content: `ns-de.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`
   - TTL: `300` (Proxied: `false`)

### 5.2 Live End-to-End Execution Trace (October 15, 2026)
```text
[CLIENT - IRAN VPS 185.18.215.124]
Query: TXT test3.tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir
Target: 8.8.8.8:53 (Google Public DNS)
Time Emitted: 19:40:12 UTC

[RECURSIVE TRAVERSAL]
Google Public DNS (8.8.8.8) resolves parent zone -> receives NS delegation -> queries 77.37.65.2:53

[AUTHORITATIVE SERVER - GERMANY VPS 77.37.65.2:53]
Received UDP query from Google resolver node: 172.253.228.151:45704 (len=118 bytes)
Normalized QNAME: test3.tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir
Emitted authenticated DNS TXT response to 172.253.228.151

[CLIENT - IRAN VPS 185.18.215.124]
Received DNS Response from 8.8.8.8: len=155 bytes, ancount=1
End-to-End Elapsed RTT: 140.98 ms
Authenticated Payload: "AUTHENTICATED_PAQET_DNS_RECURSIVE_TRAVERSAL_OK"
```
**Conclusion:** Recursive DNS-asymmetric transport (Candidate B) is **100% operational, wire-verified across international borders, and capable of surviving complete TCP blockades**.

---

## 6. Phase 3: Multi-Payload Application Message Exchange Acceptance Results

To prove that the channel carries arbitrary authenticated application data (rather than static markers), 5 distinct payloads spanning single-part and multipart frames were exchanged live from Iran VPS to Germany VPS via Google Public DNS (`8.8.8.8`):

| Test Identifier | Payload Description | Payload Size | Multipart Parts | Measured RTT | Client Verification | Server Decryption Verified |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TEST-01-TINY** | Diagnostic Ping Text | $16\text{ bytes}$ | 1 | $142.64\text{ ms}$ | `ACK_ECHO:PING_16_BYTES_OK` | `msg-60389` decrypted |
| **TEST-02-BOOTSTRAP** | Target IP/Port & Obfs Key | $63\text{ bytes}$ | 2 | $198.88\text{ ms}$ | `ACK_ECHO:BOOTSTRAP_ENDPOINT:...` | `msg-499251` decrypted |
| **TEST-03-ALERT** | Port 8088 Down Failover Notice | $69\text{ bytes}$ | 2 | $211.20\text{ ms}$ | `ACK_ECHO:ALERT_FIREWALL_BLOCK...` | `msg-10845` decrypted |
| **TEST-04-MULTIPART-100B** | Cryptographic Random Hex String | $100\text{ bytes}$ | 4 | $202.76\text{ ms}$ | Exact byte echo matching | `msg-485065` decrypted |
| **TEST-05-MULTIPART-140B** | Cryptographic Random Hex String | $140\text{ bytes}$ | 5 | $206.47\text{ ms}$ | Exact byte echo matching | `msg-333343` decrypted |

*Artifact Preserved:* `docs/research/emergency_dns_test_records.json`

---

## 7. Phase 6: Controlled Conventional-Transport Failure & Recovery Experiment

To definitively establish survivability when conventional proxy transports are severed:

1. **Baseline Verification:** SOCKS5 proxy on `:1090` verified active ($146.5\text{ ms}$, HTTP 200).
2. **Controlled Failure Injection:** On Germany VPS, dropped all incoming TCP traffic from Iran VPS targeting conventional Paqet ports (`:8088`, `:8089`, `:8443`):
   ```bash
   iptables -A INPUT -p tcp -s 185.18.215.124 --dport 8088 -j DROP
   iptables -A INPUT -p tcp -s 185.18.215.124 --dport 8089 -j DROP
   iptables -A INPUT -p tcp -s 185.18.215.124 --dport 8443 -j DROP
   ```
3. **Conventional Failure Confirmed:** Client curl on `:1090` timed out and failed completely (`CONVENTIONAL_TRANSPORT_FAILED_AS_EXPECTED`).
4. **Emergency DNS Exchange Executed:**
   - Message: `ALERT_CONVENTIONAL_PORT_8088_DOWN_EMERGENCY_CHANNEL_ACTIVE`
   - Client dispatched via Google Public DNS (`8.8.8.8:53`).
   - German server received and decrypted payload (`msg-781467`), logged it in systemd journal, and generated authenticated echo response.
   - Client verified authentic reply in $1.11\text{s}$ (including initial resolver cache-miss traversal).
5. **Restoration:** Firewall rules removed. Conventional SOCKS5 immediately restored ($143.7\text{ ms}$, HTTP 200).

---

## 8. Resolver Diversity & Capability Evaluation (Phase 8 Live Results)

Executed live from Iran VPS across 8 candidate resolvers using `paqet emergency scan`:

```text
RESOLVER           STATUS   PROFILE            SCORE  LATENCY    EDNS0    NXDOMAIN TUNNEL  
-----------------------------------------------------------------------------------------------
8.8.8.8            WORKING  TUNNEL_COMPATIBLE  6/6    80.2ms     1400B    CLEAN    PASS    
9.9.9.9            WORKING  TUNNEL_COMPATIBLE  6/6    85.3ms     1400B    CLEAN    PASS    
4.2.2.4            WORKING  TUNNEL_COMPATIBLE  6/6    89.5ms     1400B    CLEAN    PASS    
8.8.4.4            WORKING  TUNNEL_COMPATIBLE  6/6    90.1ms     1400B    CLEAN    PASS    
1.1.1.1            WORKING  TUNNEL_COMPATIBLE  6/6    105.5ms    1400B    CLEAN    PASS    
1.0.0.1            WORKING  TUNNEL_COMPATIBLE  6/6    121.1ms    1400B    CLEAN    PASS    
45.9.252.80        WORKING  TUNNEL_COMPATIBLE  5/6    0.9ms      1400B    CLEAN    FAIL    
10.10.34.34        TIMEOUT  DISCOVERED         0/6    0.0ms      NONE     HIJACKED FAIL    
```

### Empirical Discovery on Domestic Resolvers:
- Iranian domestic datacenter resolver `45.9.252.80` answered with $< 1\text{ ms}$ latency, but **FAILED the tunnel realism check** (dropping long Base32 labels).
- Public resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`) passed 100% of tunnel capability checks, including EDNS0 1400B buffers and clean unhijacked NXDOMAIN preservation.
- Live test confirmed successful emergency messaging over all 3 major public resolvers:
  * Google (`8.8.8.8`): $142.6\text{ ms}$
  * Cloudflare (`1.1.1.1`): $136.9\text{ ms}$
  * Quad9 (`9.9.9.9`): $299.4\text{ ms}$

---

## 9. Single Point of Failure (SPOF) Disclaimer

The current public DNS delegation relies on a single authoritative nameserver IP (`77.37.65.2`).
- **Limitation:** If German VPS IP `77.37.65.2` is blocked at the IP level, public recursive resolvers cannot reach the authoritative server, disabling the DNS emergency channel.
- **Future Roadmap:** To eliminate this SPOF, configure secondary authoritative nameservers on independent IP addresses across multiple cloud providers.

---

## 9. Phase 10 Hardened Security & Reliability Enhancements

1. **Secret Key Isolation & Process Protection:**
   - Production secrets are provisioned into protected key files (`/opt/paqet/emergency.key`, 0600 root-owned).
   - Removed `--key` defaults and process command-line arguments, eliminating leakage via `ps aux`.
   - Emergency key rotated to an independent 32-byte secret; primary transport keys remain completely decoupled.
2. **Pre-Authentication Heap Allocation Elimination:**
   - Frames are cryptographically authenticated via `openFrame` before allocating or persisting sessions in `s.sessions`. Unauthenticated probers are rejected with `REFUSED (5)` with zero persistent memory allocated.
   - Live session map capped at `MaxActiveServerSessions = 1024` with 10-minute idle eviction.
3. **Idempotent Reply Caching:**
   - Server caches recent sealed response frames per session. Retransmissions of the same sequence number recover the cached reply without re-executing application handlers.
4. **RFC 7766 TCP Port 53 Support:**
   - Authoritative daemon listens concurrently on UDP and TCP `:53`.
5. **Empirical Operating Boundary:**
   - Bounded to $\le 64\text{ bytes}$ for deterministic 100% single-round-trip delivery ($< 152\text{ ms}$). Payloads $> 140\text{ bytes}$ incur recursor packet fragmentation drops.


