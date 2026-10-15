# Iran VPS to German VPS Live Integration Laboratory

## 1. Network Topology & Infrastructure

The live integration and verification testbed comprises two physical Ubuntu VPS nodes spanning an international censorship-enforced boundary:

```text
+-------------------------------------------------------------------------+
| Endpoint A: Iran VPS (Client / Test Origin)                             |
|   - Provider: Panel01 Datacenter, Tehran, Iran                          |
|   - Public IPv4: 185.18.215.124                                         |
|   - Network Interface: eth0 (MTU: 1500)                                 |
|   - Default Gateway: 185.18.215.1 (MAC: cc:46:d6:21:67:45)             |
|   - Operating System: Ubuntu 24.04 LTS (Kernel: 6.8.0-31-generic)       |
|   - Firewall State: OUTPUT RST Drop (-A OUTPUT -p tcp --tcp-flags RST)  |
|   - Local Ingress Service: SOCKS5 Server on 0.0.0.0:1090                |
+-------------------------------------------------------------------------+
                                    |
                                    | International Transit Path
                                    | RTT: ~83.5 ms ICMP
                                    | Stateful DPI conntrack (TIC border)
                                    v
+-------------------------------------------------------------------------+
| Endpoint B: Germany VPS (Server / Destination)                          |
|   - Provider: Hetzner / European Hosting, Germany                       |
|   - Public IPv4: 77.37.65.2                                             |
|   - Network Interface: ens3 (MTU: 1500)                                 |
|   - Default Gateway: 77.37.65.1 (MAC: 98:5d:82:48:1a:25)               |
|   - Operating System: Ubuntu 24.04 LTS (Kernel: 6.8.0-146-generic)      |
|   - Firewall State: OUTPUT RST Drop (-A OUTPUT -p tcp --sport 8088 RST) |
|   - Listening Transport Port: :8088                                     |
|   - Controlled In-Host Target: Python Echo/Benchmark Server on :8999    |
+-------------------------------------------------------------------------+
```

---

## 2. Ingress & Egress Interface Verification

### 2.1 Iran VPS (`185.18.215.124`)
- **IP & Route Details:**
  ```text
  eth0: inet 185.18.215.124/24 scope global eth0
  default via 185.18.215.1 dev eth0 onlink
  ```
- **Gateway ARP Resolution:**
  ```text
  185.18.215.1 dev eth0 lladdr cc:46:d6:21:67:45 REACHABLE
  ```
- **Packet Capture Permissions:** Full raw packet capture and transmission privileges via `CAP_NET_RAW` / `CAP_NET_ADMIN`.

### 2.2 German VPS (`77.37.65.2`)
- **IP & Route Details:**
  ```text
  ens3: inet 77.37.65.2/24 scope global ens3
  default via 77.37.65.1 dev ens3 proto static
  ```
- **Gateway ARP Resolution:**
  ```text
  77.37.65.1 dev ens3 lladdr 98:5d:82:48:1a:25 REACHABLE
  ```

---

## 3. Controlled In-Host Destination Service

To eliminate the variance and unreliability of third-party public web servers, a dedicated HTTP/echo daemon (`/opt/paqet/echo_server.py`) is deployed on the German VPS listening on `0.0.0.0:8999`.
- **Endpoints:**
  - `GET /ping`: Immediate 200 response with `"pong\n"`. Measures pure round-trip latency across the proxy tunnel.
  - `GET /bytes/<N>`: Generates exactly $N$ bytes of data chunked in 64KB blocks. Measures sustained bulk download throughput (1MB, 5MB, 10MB).
  - `POST /echo`: Returns the exact POST body received. Validates upload integrity and bi-directional stream flow.

---

## 4. Verification Protocols & Test Execution Flow

Every integration test follows a deterministic protocol:
1. **Endpoint Sanity:** Verify that both VPS nodes are reachable and that iptables RST drop rules are intact.
2. **Binary Verification:** Confirm SHA-256 hash compatibility between client and server binaries.
3. **Capture Daemon Launch:** Launch background `tcpdump` with packet filters matching the test ports.
4. **Controlled Traffic Injection:** Execute parameterized requests (latency pings, bulk throughput transfers, active probes).
5. **Packet Trace Collection:** Extract `.pcap` files from both nodes and verify TCP sequence tracking, timestamp monotonicity, and padding randomness.
