# Next-Generation Architecture: Paqet-NG Multi-Strategy Platform

## 1. Architectural Overview

Paqet-NG decomposes censorship-circumvention into a multi-layered, modular system where logical application traffic is completely separated from wire transport mechanics.

```text
+-----------------------------------------------------------------------------------+
|                            1. Application Forwarding                              |
|   - SOCKS5 Inbound Listener (0.0.0.0:1090)                                        |
|   - TCP / UDP Port Forwarders (Transparent Redirection)                           |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        2. Multiplexed Stream Management                           |
|   - smux v2 Multiplexer (Stream opening, window sizing, keepalive)                |
|   - Logical Channel Framing (protocol.Proto: TCP Connect, UDP Associate)          |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     3. Evidence-Based Resilience Selector                         |
|   - Strategy Engine (`auto` mode)                                                 |
|   - Metric Collectors (EMA Latency, Sliding-Window Success Rate, Failure Streaks) |
|   - Circuit Breakers & Hysteresis Dampening (anti-flapping)                       |
+-----------------------------------------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+-----------------------+     +-----------------------+     +-----------------------+
|  4A. `aead-stream`    |     |  4B. `sni-assisted`   |     |  4C. `raw-kcp`        |
|  - Userspace TCP      |     |  - Decoy SNI Hello    |     |  - L2/L3 Raw Injection|
|  - Salt (16B)         |     |  - Out-of-window Seq  |     |  - Monotonic RFC 7323 |
|  - HKDF-SHA256        |     |  - Middlebox Cache    |     |  - Exact Seq Advance  |
|  - AEAD-2022 Framing  |     |    Poisoning          |     |  - Anti-Replay Ring   |
+-----------------------+     +-----------------------+     +-----------------------+
        |                                 |                                 |
        v                                 v                                 v
+-----------------------+     +-----------------------+     +-----------------------+
| 4D. `dns-asymmetric`  |     | 4E. `asymmetric-spoof`|     | 4F. Decoy Handlers    |
| - Base32 QNAME Up     |     | - Forged IPv4 Header  |     | - Instant TCP RST     |
| - UDP:53 Multi-hop    |     | - BCP 38 Auto-Probe   |     | - Zero Silent Tarpit  |
| - Frame Reassembler   |     | - Provider Gatekeeper |     | - HTTP / TLS Probing  |
+-----------------------+     +-----------------------+     +-----------------------+
```

---

## 2. Core Subsystems

### 2.1 Subsystem 1: Application Proxy & SOCKS5
- **Implementation:** `internal/socks` and `internal/forward`.
- Accepts standard SOCKS5 connections with user/password authentication.
- Forwards `CONNECT` (TCP stream) and `UDP ASSOCIATE` (UDP packets over multiplexed streams).
- Zero protocol dependency: SOCKS5 knows nothing about whether packets travel over raw Ethernet, TCP streams, or DNS queries.

### 2.2 Subsystem 2: Stream Multiplexing & Logical Framing
- **Implementation:** `internal/tnet` and `internal/ng/protocol`.
- Employs `smux` v2 on top of secure bidirectional byte streams (`transport.Session`).
- Stream framing (`protocol.Proto`) encodes:
  - Command: `0x01` (TCP Connect), `0x02` (UDP Associate), `0x03` (Ping), `0x04` (Pong), `0x05` (Terminate).
  - Target Address: FQDN or IPv4/IPv6 address + port.
  - Payload length and stream payload.

### 2.3 Subsystem 3: Evidence-Based Resilience Selector
- **Implementation:** `internal/ng/transport/selector.go`.
- Tracks telemetry per candidate:
  $$\text{EMA}_{t} = \alpha \cdot \text{RTT}_{t} + (1 - \alpha) \cdot \text{EMA}_{t-1} \quad (\alpha = 0.2)$$
  $$\text{SuccessRate} = \frac{\text{Successes}}{\text{Total Attempts}}$$
- **Circuit Breaker:**
  - `Closed`: Normal operation.
  - `Open`: Tripped after 3 consecutive connection failures; enters 45-second cooldown.
  - `HalfOpen`: Probes single connection after cooldown; closes on success, re-opens on failure.
- **Hysteresis:** A candidate must offer at least a 25% lower latency score than the active transport before a switch is initiated, preventing oscillatory flapping under jitter.

---

## 3. Wire Framing Specifications

### 3.1 AEAD Stream Framing (`aead-stream`)
1. **Initial Handshake:**
   - Client sends 16-byte random salt $S$.
   - Directional keys derived via HKDF-SHA256:
     $$\text{c2s\_key}, \text{s2c\_key} = \text{HKDF-Expand}(\text{HKDF-Extract}(S, \text{PSK}), \text{"paqet-ng-directional-v2"}, 64)$$
2. **Encrypted Handshake Header:**
   - 2-byte chunk length + Ciphertext(Timestamp [4B] + PadLen [2B] + RandomPad [$0..\text{maxPad}$] + Tag [16B]).
   - Verified against sliding-window anti-replay filter (30-second window).
3. **Data Chunks:**
   - `[Length: uint16 (2B)][Ciphertext: N bytes][AEAD Tag: 16B]`.
   - Nonce: 12 bytes with 64-bit monotonic sequence counter.

### 3.2 SNI-Assisted Decoy Framing (`sni-assisted`)
1. **Decoy Injection:**
   - Client emits an authentic RFC 8446 TLS 1.3 ClientHello record carrying a benign SNI (e.g. `hcaptcha.com`, `ebanking.ir`).
   - On raw interfaces: Injected with `seq = syn_seq + 1 - len(payload)` (out-of-window).
   - On userspace streams: Injected as an explicit preamble record.
2. **Listener Adaptation:**
   - Server inspects initial 3 bytes: if `0x16, 0x03` (TLS Handshake), reads 2-byte record length, consumes the decoy record, and proceeds immediately to the AEAD salt.
   - If initial bytes are non-TLS, proceeds directly to AEAD salt (100% backward compatibility).

### 3.3 Asymmetric DNS Framing (`dns-asymmetric`)
- **QNAME Structure:**
  `p<part>.t<total>.o<offset>.<base32chunk>.<clientID>.<domainSuffix>`
- **Constraints:**
  - Base32 chunk length $\le 45$ bytes per label.
  - Label length $\le 63$ characters.
  - Total QNAME $\le 253$ bytes.
- **Reassembly:**
  - Destination nameserver collects fragments in memory.
  - Reassembles in exact order when all parts $0..(\text{total}-1)$ are present.
  - Incomplete frames pruned after 10-second timeout.

---

## 4. Lifecycle & Resource Management

1. **Pre-Authentication Resource Cap:**
   - Unauthenticated connections are strictly bounded: maximum 3-second deadline, maximum 4KB read buffer.
   - Any bad salt, corrupt tag, or active scanner probe immediately triggers `rawConn.Close()` (instant TCP RST/FIN).
2. **Graceful Connection Teardown:**
   - `smux.Session.Close()` terminates all child streams.
   - Timed connections automatically recycle every 30 minutes to prevent long-lived connection tracking.
3. **Rollback & Safety:**
   - All legacy baseline modes (`kcp`, `stream`) remain intact and runnable via their original YAML configuration keys.
