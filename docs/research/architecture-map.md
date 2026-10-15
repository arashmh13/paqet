# Paqet Architecture Map & Baseline Source Audit

## 1. Executive Summary & Repository Baseline

This document maps the complete source tree, component responsibilities, dependency graph, concurrency model, and system interactions of the Paqet transport system.

- **Target Repository (Fork):** `https://github.com/arashmh13/paqet`
- **Upstream Repository:** `https://github.com/hanselime/paqet`
- **Baseline Commit:** `d23e5e32b89a66491d6e9ebf46484f0a8414aed2` (`feat(socket): add raw TCP 3-way handshake to defeat stateful DPI conntrack`)
- **Baseline Branch:** `repair/iran-connectivity`
- **Active Research Branch:** `research/paqet-ng`
- **Upstream Tracking Commit:** `b9fa0bd` (`build(deps): bump golang.org/x/crypto from 0.55.0 to 0.57.0 (#169)`)
- **Runtime Toolchain:** Go 1.27.2 linux/amd64, CGO enabled (`libpcap-dev 1.10.4-4.1ubuntu3.1`), Linux Kernel 6.8.0.
- **Deployed Test Systems:**
  - **Client (Iran VPS):** `185.18.215.124`, Ubuntu 24.04 (kernel `6.8.0-31-generic`), Interface `eth0`, Gateway `185.18.215.1`.
  - **Server (Germany VPS):** `77.37.65.2`, Ubuntu 24.04 (kernel `6.8.0-146-generic`), Interface `ens3`, Gateway `77.37.65.1`.
- **Baseline Binary SHA-256 (identical on both VPS endpoints):**
  `b359a7132fa7a212bda07f55c5507b6788f47ea69b6f4252f67aac507d8c0fb8`
- **Backup Locations:**
  - Iran VPS: `/opt/paqet/backup-baseline/`
  - German VPS: `/opt/paqet/backup-baseline/`

---

## 2. Component Responsibility Map

```
                  +-----------------------------------+
                  |         cmd/main.go (Cobra)       |
                  +-----------------+-----------------+
                                    |
                  +-----------------v-----------------+
                  |        cmd/run/run.go             |
                  +--------+-----------------+--------+
                           |                 |
                (role: "client")       (role: "server")
                           |                 |
          +----------------v------+   +------v----------------+
          | internal/client       |   | internal/server       |
          | - client.go           |   | - server.go           |
          | - timed_conn.go       |   | - handle.go           |
          | - tcp.go / udp.go     |   | - tcp.go / udp.go     |
          | - udp_pool.go         |   +-----------+-----------+
          +-------+---------------+               |
                  |                               |
    +-------------v-------------+                 |
    | internal/socks & forward  |                 |
    | - SOCKS5 listener (:1090) |                 |
    | - Port forwarding engine  |                 |
    +-------------+-------------+                 |
                  |                               |
                  +---------------+---------------+
                                  |
                   +--------------v--------------+
                   |     internal/protocol       |
                   | - Framing: MAGIC(0x50), V01 |
                   | - Types: PING, TCPF, TCP,   |
                   |   UDP payload streams       |
                   +--------------+--------------+
                                  |
                   +--------------v--------------+
                   |     internal/tnet/kcp       |
                   | - smux.Session (v2 mux)     |
                   | - kcp.UDPSession / Listener |
                   | - FEC (Reed-Solomon)        |
                   +--------------+--------------+
                                  |
                   +--------------v--------------+
                   |     internal/obfs           |
                   | - AES-256-GCM AEAD          |
                   | - 12B Random Nonce          |
                   | - Random Padding (0..maxPad)|
                   +--------------+--------------+
                                  |
                   +--------------v--------------+
                   |     internal/socket         |
                   | - SendHandle (raw inject)   |
                   | - RecvHandle (pcap capture) |
                   | - 3-Way Handshake Engine    |
                   +--------------+--------------+
                                  |
                   +--------------v--------------+
                   |      OS Kernel & Network    |
                   | - libpcap / AF_PACKET       |
                   | - iptables RST Drop         |
                   | - Raw Ethernet/IP/TCP wire  |
                   +-----------------------------+
```

### 2.1 Entry Points & CLI (`cmd/`)
- `cmd/main.go`: Initializes the root Cobra command (`paqet`). Configures subcommands: `run`, `ping`, `dump`, `secret`, `version`.
- `cmd/run/run.go`: Loads configuration YAML via `internal/conf`, configures logging level, and branches into `startClient` or `startServer`.
- `cmd/run/client.go`: Spawns client instance, launches configured SOCKS5 listeners (`internal/socks`) and port forwarders (`internal/forward`). Listens for OS shutdown signals (`SIGINT`, `SIGTERM`).
- `cmd/run/server.go`: Initializes server instance, binds transport listener, launches stream accept loop, and handles graceful shutdown.

### 2.2 Configuration Management (`internal/conf/`)
- `conf.go`: Root struct (`Conf`) holding role (`client` | `server`), logging settings, network configuration, server target, transport options, SOCKS5 list, and port forwarding rules.
- `network.go`: Interface binding, IPv4/IPv6 address parsing, router gateway MAC address resolution, and custom TCP flag configurations (`local_flag`, `remote_flag`).
- `kcp.go`: KCP engine parameters: mode (`normal`, `fast`, `fast2`, `fast3`, `manual`), window sizes (`sndwnd`, `rcvwnd`), MTU, FEC parameters (`dshard`, `pshard`), smux buffer limits, and keepalive intervals.
- `obfs.go`: Obfuscation envelope settings: `enabled` (boolean), `key` (base64 or plaintext shared secret), and `maxpad` (random padding ceiling).
- `tcp.go`: Parses custom TCP flag strings (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`, `NS`, or abbreviations like `PA`, `SA`).

### 2.3 Obfuscation Envelope (`internal/obfs/`)
- `obfs.go`: Transparent `net.PacketConn` wrapper.
  - Derives a 32-byte AES key via PBKDF2 with SHA-256, salt `"paqet-obfs-v1"`, and 100,000 iterations.
  - Enforces AES-256-GCM authenticated encryption.
  - Prepends a 12-byte cryptographically secure random nonce (`crypto/rand`).
  - Prepends a 2-byte BigEndian length prefix to the plaintext payload.
  - Appends uniform random padding up to `maxPad` bytes, bounded by `MaxFrame` (1460 bytes).
  - Unconditionally drops packets failing GCM authentication or with truncated/invalid length fields.

### 2.4 Low-Level Raw Packet Engine (`internal/socket/`)
- `socket.go`: Defines `PacketConn` implementing `net.PacketConn`.
  - Coordinates `SendHandle` (outbound injection) and `RecvHandle` (inbound pcap capture).
  - Manages `handshakeCh` and intercepts control packets (SYN, SYN-ACK, ACK) during connection setup.
- `send_handle.go`: Constructs raw Layer-2 Ethernet, Layer-3 IPv4/IPv6, and Layer-4 TCP packets.
  - Injects frames directly into the physical network interface using `pcap.WritePacketData()`.
  - Synthesizes TCP headers with configured flags, simulated TCP options (MSS, WindowScale, SACKPermitted, Timestamps).
  - Calculates TCP checksums against the pseudo-IP header.
  - Manages `tsCounter` and synthetic `Seq` / `Ack` values.
- `recv_handle.go`: Captures incoming raw packets via `libpcap` with BPF filter `tcp and dst port <Port>`.
  - Decodes Ethernet, IPv4/IPv6, and TCP layers using `gopacket.DecodingLayerParser`.
  - Extracts TCP payload and filters out packets without data unless intercepted as control/handshake frames.

### 2.5 Transport & Stream Multiplexing (`internal/tnet/kcp/`)
- `dial.go`: Client transport dialer.
  - Instantiates `socket.PacketConn`.
  - Executes raw TCP 3-way handshake (`packetConn.Handshake(addr)`).
  - Wraps connection in `obfs.Conn`.
  - Establishes a reliable `kcp.UDPSession` over the obfuscated packet connection.
  - Initializes `smux.Session` (version 2) over the KCP session for stream multiplexing.
- `listen.go`: Server transport listener.
  - Creates `socket.PacketConn` bound to physical interface and capture port.
  - Wraps in `obfs.Conn`.
  - Starts `kcp.Listener` (`kcp.ServeConn`).
  - Accepts inbound KCP sessions and wraps each in an `smux.Session`.
- `kcp.go`: Configures KCP congestion control parameters (`NoDelay`, `Interval`, `Resend`, `NoCongestion`), MTU, stream mode, and DSCP.

### 2.6 Application Protocol Framing (`internal/protocol/`)
- `protocol.go`: Binary framing over smux streams:
  - Header: 5 bytes `[MAGIC(0x50), VERSION(0x01), TYPE(1B), BODY_LEN(2B BigEndian)]`.
  - Types:
    - `0x01` (`PPING`): Heartbeat probe (body empty).
    - `0x02` (`PPONG`): Heartbeat response (body empty).
    - `0x03` (`PTCPF`): Remote TCP flags sync (`[1B count] [count * 2B flags]`).
    - `0x04` (`PTCP`): TCP dial request (`[1B host_len] [host bytes] [2B port]`).
    - `0x05` (`PUDP`): UDP dial request (`[1B host_len] [host bytes] [2B port]`).
- Body payload: Transmitted directly over the smux stream following the protocol header frame.

### 2.7 Proxy & Ingress Engines (`internal/socks/` & `internal/forward/`)
- `socks/socks.go`: Local SOCKS5 server listening on TCP (e.g. `0.0.0.0:1090`). Supports RFC 1928 `NO_AUTH` (0x00) and `USER_PASS` (0x02).
- `socks/connect.go`: Handles `CONNECT` (0x01). Calls `client.TCP()` to create a multiplexed stream to the target host and bidirectionally copies data.
- `socks/associate.go`: Handles `UDP_ASSOCIATE` (0x03). Listens on local UDP port, wraps datagrams into `client.UDP()` streams.
- `forward/tcp.go`: Transparent local TCP port forwarding to remote destination.

---

## 3. Goroutine Lifecycle, Buffer Ownership & Concurrency Model

1. **Packet Capture Goroutine:**
   - On the server, `kcp.ServeConn` runs an internal goroutine calling `PacketConn.ReadFrom()`, which locks `RecvHandle.mu` and blocks on `pcap.ZeroCopyReadPacketData()`.
   - On the client, during `Handshake()`, a temporary background goroutine pumps `recvHandle.Read()` to capture incoming SYN-ACKs until the handshake completes.
2. **KCP Update & Retransmission Loop:**
   - KCP maintains an internal update ticker running every 10–30ms to process retransmissions, FEC matrix calculations, sliding window updates, and ACK flushes.
3. **smux Stream Handlers:**
   - Server: `server.listen()` accepts incoming KCP connections in an infinite loop. For each connection, `server.handleConn()` spawns a goroutine. That goroutine loops accepting `smux.Stream`s via `conn.AcceptStrm()`. For every accepted stream, `server.handleStrm()` runs in a new detached goroutine.
   - Stream data copying: Two goroutines per connection are created by `buffer.CopyT()` for bidirectional copying between the remote `net.Conn` and the local `smux.Stream`.
4. **Buffer Ownership:**
   - `SendHandle` uses a `sync.Pool` (`ePool`) for `encoder` structs, each containing a `gopacket.SerializeBuffer`. Buffer memory is reused across packet transmissions.
   - `RecvHandle` uses a `sync.Pool` (`dPool`) for `decoder` structs.
   - `obfs.Conn` uses `sync.Pool` (`recvPool`) allocating 1460-byte buffers for decrypted payloads.

---

## 4. Fork vs Upstream Commit Differentiation

| Commit Hash | Author | Description | Impact / Security Evaluation |
| :--- | :--- | :--- | :--- |
| `upstream/b9fa0bd` | Dependabot | Bump `golang.org/x/crypto` from 0.55.0 to 0.57.0 | Clean dependency security patch. |
| `fe2c4b1` | arashmh13 / cline | `feat(transport): add obfs layer to defeat DPI fingerprinting` | Wraps raw datagrams in AES-256-GCM + random padding. Crucial for packet-length obfuscation and active-probe resistance. |
| `642dec7` | arashmh13 | `fix(tnet/kcp): remove duplicate imports in conn.go` | Build fix. |
| `d23e5e3` | arashmh13 | `feat(socket): add raw TCP 3-way handshake to defeat stateful DPI conntrack` | Implements SYN -> SYN-ACK -> ACK exchange prior to KCP data flow to prevent stateful conntrack drops. |

---

## 5. Linux Kernel, Routing, and Firewall Interactions

1. **Kernel TCP Stack Bypass:**
   - Both client and server inject packets below the Linux TCP/IP stack using `libpcap` / `AF_PACKET` raw socket interfaces.
   - Because the host kernel does not have a listening TCP socket matching the raw 4-tuple, incoming packets received by the host interface trigger automatic kernel TCP RST generation.
   - **Mandatory Firewall Rule:**
     ```bash
     # Iran VPS (Client):
     iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP

     # German VPS (Server):
     iptables -A OUTPUT -p tcp -m tcp --sport 8088 --tcp-flags RST RST -j DROP
     ```
     Failure to maintain this rule causes the kernel to immediately reset any connection initiated or received by the raw engine.
2. **Physical Gateway MAC Resolution:**
   - Raw packet transmission requires explicit Layer-2 Ethernet framing.
   - `client.yaml` requires `network.ipv4.router_mac: "cc:46:d6:21:67:45"` (resolved from `ip route show default` and `ip neigh show`).
   - `server.yaml` requires `network.ipv4.router_mac: "98:5d:82:48:1a:25"`.
3. **BPF Packet Filtering:**
   - Client BPF filter: `tcp and dst port <dynamic_client_port>`.
   - Server BPF filter: `tcp and dst port 8088`.
