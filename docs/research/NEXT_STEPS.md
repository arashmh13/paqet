# Next Engineering Steps & Strategic Priorities: Paqet-NG Platform

## 1. Executive Status & Current State

- **Current Git Branch:** `research/hard-mode-rnd`
- **Current Version:** `v2.4.2-verified`
- **Active Binary SHA-256:** `0ee0d399a559a9b92ee8348b61473b8413ae62c232320f07c26c763019f6ee93`
- **Architectural Validation Status:**
  - Candidate 1 (Genuine TLS 1.3 Outer Transport): **COMPLETE & WIRE-VERIFIED** (RFC 8446 standard TLS 1.3 handshake, ContentType 0x17 ApplicationData records, 90.9 ms RTT, 11.60 Mbps line rate, CA certificate validation verified).
  - Candidate 2 (Raw TCP Decoy Sequence Injection): **COMPLETE & WIRE-VERIFIED** (`wrong_seq` out-of-window packet injection, silent kernel drop on Germany VPS, 123.4 ms RTT).
  - Asymmetric Directional Decoupling (`AsymmetricConn`): **COMPLETE & TESTED** (independent `UpstreamSender` and `DownstreamReceiver` channels, AEAD framing, reassembly sliding window, and anti-replay DoS protection).
  - BCP 38 / uRPF Spoofing Feasibility: **CONCLUDED & INFEASIBLE** (probes conclusively dropped by Panel01 and Hetzner egress routers).
  - Controlled Failure Laboratory: **OPERATIONAL** (`failure_lab_test.go` passing 100% across port drops, idle resumptions, and national curfew simulations).
- **Active Endpoints:**
  - Iran VPS (`185.18.215.124`): Primary SOCKS5 on `127.0.0.1:1090` (`raw-kcp` with out-of-window SNI sequence injection), Genuine TLS on `127.0.0.1:1095` (`tls` on `:8443`).
  - German VPS (`77.37.65.2`): Primary server listening on `:8088` (kcp), Genuine TLS server on `:8443`.
  - In-Host Benchmark Daemon: `127.0.0.1:8999` (`/ping`, `/bytes/<N>`, `/echo`).

---

## 2. Priority 1: Automated Multi-Path Port Failover & Jitter Injection

- **Objective:** Enable dynamic transport port hopping when an active TCP stream experiences sudden packet drops or silent stalling (censor heuristic throttling).
- **Architecture:**
  - Expand client connection ticker to track per-port throughput and TCP retransmission counts.
  - If a connection on `:8089` drops below threshold while peer connection on `:8443` maintains healthy throughput, dynamically re-route streams without tearing down user SOCKS5 sessions.
- **Dependencies:** `internal/client/udp_pool.go` and `internal/client/ticker.go`.
- **Acceptance Criteria:**
  1. Controlled injection of `iptables -A INPUT -p tcp --dport 8089 -j DROP` on Germany VPS must not drop active SOCKS5 downloads on Iran VPS.
  2. Multiplexer transfers active streams to `:8443` within $< 1.5$ seconds.

---

## 3. Priority 2: TLS 1.3 REALITY / Decoy SNI Reverse Proxy Layer

- **Objective:** Eliminate high-entropy detection on port 443 by disguising the server stream listener as a genuine HTTPS web server (e.g. `www.apple.com` or `www.cloudflare.com`).
- **Architecture:**
  - Integrate `uTLS` ClientHello parser on server listener.
  - When an unauthenticated connection arrives with a valid TLS ClientHello, forward the raw connection transparently via TCP splice to the genuine external decoy server (e.g. Apple/Cloudflare).
  - The censor observing probe scans receives genuine DigiCert / Let's Encrypt certificates from the real web server.
- **Dependencies:** `internal/ng/transport/aead_stream.go` and `uTLS` / reverse proxy splice engine.
- **Acceptance Criteria:**
  1. `curl -I https://77.37.65.2:8443` from an external host returns genuine HTTP/2 200 OK and valid TLS certificate chain.
  2. Authenticated Paqet-NG client connecting to `:8443` with secret PSK establishes the tunnel instantly.

---

## 4. Priority 3: Asymmetric DNS Signaling Channel Live Demonstration

- **Objective:** Demonstrate end-to-end DNS query signaling on live nodes under simulated total TCP blocking.
- **Architecture:**
  - Bind a lightweight authoritative DNS UDP listener on Germany VPS (port 5353 or port 53).
  - Configure Iran VPS to emit Base32 QNAME frames to `8.8.8.8` / `1.1.1.1` targeting the registered test domain.
  - Reassemble emergency control commands on Germany VPS.
- **Dependencies:** `internal/ng/transport/dns_asymmetric.go`.
- **Acceptance Criteria:**
  1. 100% frame reassembly rate over 50 consecutive test datagrams.
  2. Frame reassembly survives simulated 20% packet drop on UDP port 53.

---

## 5. Priority 4: Reed-Solomon Forward Error Correction (FEC) over Stream Chunks

- **Objective:** Eliminate TCP head-of-line blocking and retransmission stalls on high-loss Iranian residential lines (FTTH / 4G).
- **Architecture:**
  - Wrap stream chunk payloads in an $(N, K)$ Reed-Solomon parity matrix using `klauspost/reedsolomon` (e.g. 10 data chunks + 3 parity chunks).
  - Receiver reconstructs dropped chunks locally without requesting TCP retransmissions across high-latency international links.
- **Dependencies:** `internal/ng/transport/aead_stream.go` and `internal/ng/protocol/`.
- **Acceptance Criteria:**
  1. Under simulated 15% random packet loss (`tc qdisc add dev eth0 root netem loss 15%`), download throughput remains within 80% of baseline.
