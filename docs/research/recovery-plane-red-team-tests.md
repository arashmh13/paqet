# Paqet-NG Recovery Plane Red-Team & Adversarial Testing Report

## Executive Summary
This document records the adverse-condition validation, red-team simulation, and isolated failure testing executed during Phase 10 against the Paqet-NG recovery plane. Tests were performed locally in WSL using Go's race-enabled test harness and live across the cross-border Iran-to-Germany network link.

---

## 1. Adversarial Automated Unit & Race Test Suite

The automated adverse-condition test suite in `internal/ng/transport/dns_emergency_test.go` exercises boundary failures, resource exhaustion attacks, and protocol violations.

| Test Case | Attack / Adverse Condition Modeled | Expected Security Behavior | Test Result |
| :--- | :--- | :--- | :--- |
| `TestUnauthenticatedSessionIDMemoryExhaustionProtection` | Attacker floods 50 queries with randomized unauthenticated session IDs and corrupted AEAD tags | Zero sessions persisted in `s.sessions`; unauthenticated queries rejected with `REFUSED (5)` or dropped; memory remains flat | **PASS (0.12s, 0 races)** |
| `TestIdempotentDuplicateRetransmission` | Downstream packet loss causes client to retransmit authenticated query with identical `(sessionID, seq)` | Server serves cached sealed reply from `replyCache`; handler invocation count equals exactly 1 | **PASS (0.03s, 0 races)** |
| `TestTCPPort53QueryHandling` | Recursive resolver falls back to TCP port 53 (RFC 7766) due to truncation or policy | Server accepts TCP connection, parses 2-byte length prefix, processes query, and returns 2-byte length-prefixed response | **PASS (0.03s, 0 races)** |
| `TestKeyLengthValidationAndFailClosed` | Missing key, empty key, truncated key (31B), or oversized key (33B, 64B) | Server and Client fail closed with explicit validation error; silent truncation or padding is rejected | **PASS (0.00s, 0 races)** |
| `TestOversizedPayloadRejection` | Attacker submits payload exceeding `MaxEmergencyPayloadBytes = 512` (513 bytes) | Client and Server reject message with schema error; query not transmitted/processed | **PASS (0.00s, 0 races)** |
| `TestEmergencyDNSServerSecurityAndRefused` | Query for foreign domain (e.g. `google.com`) or client with invalid PSK | Non-child-zone query returns `RCODE = 5 (REFUSED)`; invalid PSK query fails AEAD decryption | **PASS (4.43s, 0 races)** |
| `TestEmergencyDNSRoundTripSmallAndFragmented` | Legitimate single-part (20B) and multipart (120B, 4 parts) payloads | Successful reassembly, decryption, echo verification, and round-trip completion | **PASS (0.03s, 0 races)** |

---

## 2. Live Cross-Border Isolated Conventional Transport Severance

To rigorously validate emergency messaging during a severe network restriction without interrupting the primary production SOCKS5 proxy on `:1090`:

### 2.1 Experimental Architecture
- **Dedicated Test Listener:** A secondary TCP listener was spawned on Germany VPS port `18089` (`systemd-run --unit=paqet-test-tcp-listener nc -l -k -p 18089`).
- **Baseline Reachability:** Iran VPS dialed `77.37.65.2:18089` via TCP and confirmed `REACHABLE`.
- **Targeted Severance:** Iran VPS applied an isolated egress firewall drop on port `18089` only:
  ```bash
  iptables -I OUTPUT 1 -p tcp -d 77.37.65.2 --dport 18089 -j DROP
  ```
- **Failure Verification:** Dialing `77.37.65.2:18089` timed out (`BLOCKED`).
- **Emergency Signaling:** Dispatched an authenticated emergency message through Google Public DNS (`8.8.8.8:53`):
  ```bash
  /opt/paqet/paqet emergency send --resolver 8.8.8.8:53 --key-file /opt/paqet/emergency.key \
    --message 'ALERT_FAILOVER_PORT_18089_SEVERED_ed3c25353883'
  ```
- **Delivery Verification:**
  - Emergency message delivered and processed by authoritative server in Germany.
  - Authenticated response `ACK_ECHO:ALERT_FAILOVER_PORT_18089_SEVERED_ed3c25353883` returned to Iran in $162.6\text{ ms}$.
  - Server journal logged:
    `[EMERGENCY-SERVER] Authenticated message ID=msg-819bb7... Type=alert PayloadBytes=46 ClientID=c01 Status=PROCESSED`
- **Deterministic Cleanup:** Removed the temporary firewall drop (`iptables -D OUTPUT ...`). Port 18089 immediately returned to `REACHABLE`. Stopped test listener.
- **Production Isolation:** The primary production SOCKS5 proxy on `185.18.215.124:1090` remained active and unaffected throughout the test ($0.228\text{ s}$, HTTP 200).

---

## 3. Rate-Limited Multi-Resolver Soak Benchmark Results

Conducted a 45-trial empirical soak test across Google (`8.8.8.8`), Cloudflare (`1.1.1.1`), and Quad9 (`9.9.9.9`), testing 16B, 64B, and 140B cryptographic random hex payloads at 0.8s intervals.

### 3.1 Empirical Summary Table
| Resolver | Trials | Success Rate | Byte-Exact Echo Rate | Min RTT | Median RTT | Mean RTT | P95 RTT | Max RTT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Public DNS (`8.8.8.8:53`)** | 15 | 66.7% | 66.7% | $99.08\text{ ms}$ | $146.77\text{ ms}$ | $142.09\text{ ms}$ | $157.71\text{ ms}$ | $166.73\text{ ms}$ |
| **Cloudflare DNS (`1.1.1.1:53`)** | 15 | 66.7% | 66.7% | $132.78\text{ ms}$ | $147.77\text{ ms}$ | $154.79\text{ ms}$ | $177.46\text{ ms}$ | $180.35\text{ ms}$ |
| **Quad9 DNS (`9.9.9.9:53`)** | 15 | 80.0% | 80.0% | $126.84\text{ ms}$ | $150.82\text{ ms}$ | $351.44\text{ ms}$ | $196.34\text{ ms}$ | $2,558.48\text{ ms}$ |

### 3.2 Breakdown by Payload Size
- **16-byte payloads (1 fragment):** 15/15 SUCCESS (**100.0%**), median RTT $144.5\text{ ms}$, 100% byte-exact echo across all resolvers.
- **64-byte payloads (2 fragments):** 15/15 SUCCESS (**100.0%**), median RTT $151.8\text{ ms}$, 100% byte-exact echo across all resolvers.
- **140-byte payloads (6 fragments):** Higher drop probability across recursors; when retransmissions completed, latency rose to $\approx 2.5 - 4.2\text{ s}$.

### 3.3 Engineering Conclusion
Emergency control-plane messages (status reporting, endpoint bootstrap, port failover alerts) should be bounded to $\le 64\text{ bytes}$ ($\le 2$ fragments). At this size, the emergency channel delivers **100% reliability with median latency $< 152\text{ ms}$** across all major public recursive resolvers.
