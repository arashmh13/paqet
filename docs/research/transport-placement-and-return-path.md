# Transport Placement, Network Path Mechanics, and Return-Path Engineering

## 1. The Fundamental Distinction: Where Techniques Act

A critical flaw in many censorship-circumvention tools is conflating **transport-layer camouflage** with **application-layer evasion**. To design a resilient multi-strategy platform, we must formally map the physical and logical placement of each technique across the network topology.

```text
[ Client Application ]  (e.g., Browser, curl, Telegram)
        |
        | (1) Local Inbound Socket (SOCKS5 / HTTP Proxy on 127.0.0.1:1090)
        v
[ Paqet-NG Client ]
        |
        | (2) Transport Encapsulation & Obfuscation
        |     (raw-kcp, aead-stream, sni-assisted, dns-asymmetric)
        |
    [ Local OS Stack / Raw NIC (eth0) ]
        |
        | (3) National / ISP Egress Path (Iran DPI Middleboxes, conntrack, BCP 38)
        v
    [ International Transit & Filtering Border ]
        |
        | (4) German Network Ingress (Hetzner / Provider BCP 38 / Transit)
        v
    [ German OS Stack / Raw NIC (ens3) ]
        |
[ Paqet-NG Server ] (:8088 / :8089)
        |
        | (5) Application Outbound Forwarding
        v
[ Target Internet Host ] (e.g., Cloudflare, YouTube, Wikipedia)
```

---

## 2. Paqet's Tunnel Transport vs. Outbound TLS Connections

### 2.1 The Observable Tunnel Path (Position 3)
When an Iranian client connects to the German Paqet-NG server, the censor on the Iranian transit path observes traffic strictly between:
$$\text{Iran VPS } (185.18.215.124) \longleftrightarrow \text{German VPS } (77.37.65.2)$$

- **In `raw-kcp` mode:** The censor observes custom Layer 2 Ethernet frames carrying raw TCP packets with non-standard sequence increments or custom TCP flags (`PA`, `SA`) and high-entropy payloads.
- **In `aead-stream` mode:** The censor observes a standard TCP 3-way handshake followed by an initial 16-byte random salt and encrypted AEAD binary frames on port 8089.

### 2.2 The Fallacy of Direct SNI Spoofing on Tunnels
If an application requests `https://www.youtube.com`:
- The client sends a SOCKS5 `CONNECT youtube.com:443` command to Paqet-NG over the local loopback (Position 1).
- Paqet-NG encrypts this request inside the tunnel multiplexer (Position 2).
- The outer packets traversing the Iranian network (Position 3) contain **zero plaintext references to `youtube.com`**.
- Therefore, applying SNI spoofing to `youtube.com` at the tunnel level is meaningless: the censor never sees `youtube.com` anyway.

---

## 3. SNI-Spoofing Placement Analysis

SNI-spoofing techniques (such as those in `patterniha/SNI-Spoofing` and `aleskxyz/SNI-Spoofing-Go`) operate by injecting a decoy TLS ClientHello into a TCP stream. Where does this provide genuine value?

### Option A: Applied to Outbound Connections Created by Proxy Applications
- **Mechanism:** When an application connects directly without a tunnel, or when Paqet acts as a local transparent redirector.
- **Censor View:** The censor sees a connection from the client to the foreign web server. The decoy SNI (e.g. `ssp.ir` or `hcaptcha.com`) tricks the DPI into permitting the flow to the blocked destination.
- **Limitation:** Fails when the destination IP itself is blocked at Layer 3 (IP blacklisting), which is ubiquitous in Iran during elevated filtering.

### Option B: Applied to Paqet's Own Tunnel Stream Connection
- **Mechanism:** Paqet-NG disguises its outer tunnel connection as a TLS flow to the German VPS:
  1. Client dials TCP to `77.37.65.2:443` (or `:8089`).
  2. Before the application handshake, the client injects a synthetic raw TCP packet carrying a decoy TLS ClientHello with an out-of-window sequence number (`wrong_seq`) pointing to an allowed domain (e.g., `bank.ir` or `hcaptcha.com`).
  3. The Iranian DPI inspects the packet, classifies the flow as whitelisted, and bypasses further inspection.
  4. The German Paqet-NG server discards the out-of-window packet, accepts the real stream handshake, and establishes the AEAD session.
- **Packet-Level Trace:**
  - Packet 1: Client -> Server `[SYN]` seq=1000
  - Packet 2: Server -> Client `[SYN, ACK]` seq=5000, ack=1001
  - Packet 3: Client -> Server `[ACK]` seq=1001, ack=5001
  - Packet 4 (Injected Decoy): Client -> Server `[PSH, ACK]` **seq=850** (out of window: $1001 - 151$), payload = TLS ClientHello with SNI `hcaptcha.com`
  - Packet 5 (Real Payload): Client -> Server `[PSH, ACK]` seq=1001, ack=5001, payload = Paqet AEAD Salt + Handshake
- **Architectural Placement in Paqet-NG:**
  Implemented as a **Dialer Adapter** (`SNIAssistedDialer`) that decorates the underlying stream transport during connection establishment.

---

## 4. IP-Spoofing Placement and Feasibility Analysis

### 4.1 Theoretical Operation (`ParsaKSH/spoof-tunnel`)
Bidirectional IP spoofing requires:
1. Client sends packet to Server: Header contains `SrcIP = Spoofed_Iran_IP`, `DstIP = Server_IP`.
2. Server captures packet, matches session via encrypted token or port tuple, and responds: Header contains `SrcIP = Spoofed_Foreign_IP`, `DstIP = Client_Real_IP` (or asymmetric spoofed return).

### 4.2 Empirical Reality: BCP 38 / uRPF Verification
In Phase Two, we executed controlled raw-socket injection tests between our live nodes:

| Test Case | Origin Node | Injected `SrcIP` | Destination | Border Filter Result | Packet Arrived? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Control** | Iran (`185.18.215.124`) | `185.18.215.124` | Germany (`77.37.65.2:29999`) | Permitted (Standard Egress) | **YES** (RTT 100ms) |
| **Test 1** | Iran (`185.18.215.124`) | `198.51.100.1` (Bogus) | Germany (`77.37.65.2:29999`) | **Dropped at Iran DC Border** | **NO** (0 packets) |
| **Test 2** | Iran (`185.18.215.124`) | `185.18.215.200` (Subnet) | Germany (`77.37.65.2:29999`) | **Dropped at Iran DC Border** | **NO** (0 packets) |
| **Test 3** | Germany (`77.37.65.2`) | `198.51.100.2` (Bogus) | Iran (`185.18.215.124:29999`) | **Dropped at Hetzner Border** | **NO** (0 packets) |

### 4.3 Why Spoofing Fails on Generic Infrastructure
- **BCP 38 (RFC 2827):** Network Ingress Filtering for Multihomed Networks. Modern data centers verify that the source address of every outgoing packet matches the subnet allocated to that specific virtual switch port.
- **uRPF (RFC 3704):** Unicast Reverse Path Forwarding. If a router receives a packet on an interface from which it has no valid reverse route back to that source IP, the packet is silently discarded.
- **Conclusion:** Bidirectional IP spoofing cannot be relied upon as a production transport for ordinary cloud deployments. In Paqet-NG, it is encapsulated as an experimental adapter with an active pre-flight validator that aborts before causing service outages.

---

## 5. QS-Style Asymmetric DNS/IP Transport Architecture

### 5.1 Asymmetry Breakdown
QS-Tunnel splits communication into two completely disconnected network paths:

```text
[ Client (Iran) ] -----( Base32 DNS Queries via UDP:53 )-----> [ Recursive Public DNS ]
                                                                       |
                                                               ( Authoritative Query )
                                                                       v
                                                               [ Server (Germany) ]
                                                                       |
[ Client (Iran) ] <----( Raw Spoofed UDP / Direct UDP )----------------+
```

### 5.2 Framing & Reassembly Mechanics
1. **Upstream (DNS):**
   - The payload is chunked into small fragments ($M \le 35$ bytes).
   - Each fragment is encoded into DNS subdomain labels:
     `{client_id:7B}.{offset:3B}.{part:1B}.{base32_data}.tunnel.example.com`
   - Client sends standard `A` or `TXT` queries to recursive resolvers (8.8.8.8, 1.1.1.1).
   - Server acts as the authoritative nameserver for `tunnel.example.com`.
   - The server extracts the labels, decodes Base32, and reassembles fragments in an in-memory buffer (`DataHandler`) with a 13-second reassembly window.
2. **Downstream (Return Path):**
   - The server transmits responses directly to the client's public IP address.
   - If the server attempts to spoof the source IP (e.g. forging 8.8.8.8 as the source), BCP 38 drops the packet on generic hosting.
   - If the server uses its real IP (`77.37.65.2`), the return path is a direct foreign-to-domestic UDP stream. If foreign UDP is blocked by the national firewall, the return path collapses.

### 5.3 Limitations & SOCKS5 Compatibility
- **Extreme Asymmetry:** Upstream is capped at $\sim 50$–$100$ KB/s due to DNS query serialization and resolver rate limits. Downstream can reach standard UDP throughput.
- **Packet Loss Vulnerability:** Losing a single DNS query fragment causes the entire reassembly frame to expire, stalling TCP sessions.
- **Role in Paqet-NG:**
  An asymmetric DNS transport cannot support interactive web browsing or video streaming. However, it serves as a **Resilience Beacon / Emergency Command Channel** to signal the server, exchange updated endpoint IP lists, or recover configuration during total IP blackouts.
