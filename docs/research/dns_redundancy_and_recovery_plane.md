# Paqet-NG DNS Redundancy & Recovery Plane Architecture (Phase 10)

## 1. Problem Statement: The Single-IP / Single-NS Dependency

### 1.1 The Vulnerability
In the current deployment, the delegated child zone:
`tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir`
has its NS delegation pointing to:
`ns-de...` $\longrightarrow$ `A` $\longrightarrow$ `77.37.65.2` (Hetzner, Falkenstein, Germany).

Crucially, `77.37.65.2` is the **exact same IP address** hosting the primary Paqet `raw-kcp` transport (port 8088), `aead-stream` (port 8089), and `tls-outer` (port 8443).

**Failure Mode:** If an Iranian upstream provider (TIC / TCI) or routing policy blackholes the IP prefix `77.37.65.0/24` or Hetzner AS24940, **both the conventional proxy transports AND the authoritative DNS emergency daemon will be simultaneously severed**. Even if domestic users can reach Google (`8.8.8.8`) or Cloudflare (`1.1.1.1`), the recursors will be unable to reach `77.37.65.2:53` to resolve the child zone queries.

---

## 2. Distributed Dual-Authoritative Nameserver Architecture

To achieve true survivability against IP-level and datacenter-level censorship, the emergency DNS recovery plane must operate at least two independent authoritative nameservers on distinct network prefixes and independent hosting providers.

```
                            [ Cloudflare Parent Zone ]
                                        |
           +----------------------------+----------------------------+
           |                                                         |
     NS Record 1:                                              NS Record 2:
     ns-eu.domain... -> 77.37.65.2 (Hetzner, DE)               ns-us.domain... -> 149.28.x.x (Vultr/OVH, US/FR)
           |                                                         |
           v                                                         v
   [ Authoritative Node 1 ]                                  [ Authoritative Node 2 ]
```

### 2.2 The Recursive Resolver Query-Splitting Problem
Recursive resolvers (such as Google Public DNS, Cloudflare, and Quad9) select authoritative nameservers according to internal latency scoring, SRTT (Smoothed Round Trip Time), or random spraying.

When a client transmits a multipart emergency message consisting of multiple fragments (e.g. Part 0 and Part 1):
- Query for Part 0 may be dispatched by Google to `Node 1` (`77.37.65.2`).
- Query for Part 1 may be dispatched by Google to `Node 2` (`149.28.x.x`).

If Node 1 and Node 2 maintain isolated in-memory reassembly buffers (`DNSReassembler`), neither node receives the complete frame, resulting in query timeouts and communication failure!

### 2.3 Architectural Solutions & Engineering Decision

Three design approaches solve the query-splitting problem:

#### Strategy A: Single-Query Control Datagrams (Implemented & Recommended)
- As demonstrated in Phase 10 empirical benchmarks, control plane datagrams (e.g. `bootstrap_request`, `ping`, `alert`, `status`) fit comfortably within 35 bytes of raw payload (1 single fragment label).
- When `total = 1`, no multipart reassembly is required. Either authoritative server can immediately decrypt, authenticate, process, and answer the query independently, with **zero inter-server coordination**.
- **Status:** **Operational in v2.5.2-hardened**. All control messages are formatted to fit into single-query datagrams.

#### Strategy B: Deterministic Subdomain Sharding
- Instead of delegating a single pool, delegate two distinct subdomains:
  * `*.node1.tunnel...` $\longrightarrow$ `NS` $\longrightarrow$ `ns-eu...` (`77.37.65.2`)
  * `*.node2.tunnel...` $\longrightarrow$ `NS` $\longrightarrow$ `ns-us...` (`149.28.x.x`)
- The client tries `node1` first; if unanswered, it fails over to `node2`.
- All fragments of a message are addressed to the same authoritative node, preventing split reassembly.

#### Strategy C: Inter-Daemon WireGuard State Replication
- Authoritative daemons connect over an encrypted WireGuard peer-to-peer overlay.
- Incoming intermediate fragments are mirrored over the mesh via UDP gossip or Redis/Etcd.
- Allows arbitrary multi-kilobyte transfers across split nameservers.
- Adds deployment complexity and inter-VPS dependency.

---

## 3. Strict Typed Control Schema for Endpoint Failover

The recovery plane must never execute arbitrary shell commands. It enforces a strict typed schema for bootstrap coordinates.

### 3.1 Control Message Types
```go
const (
	MsgTypePing              = "ping"               // Liveness probe
	MsgTypeAlert             = "alert"              // Firewall cutoff alert
	MsgTypeBootstrapRequest  = "bootstrap_request"  // Request updated proxy coordinates
	MsgTypeBootstrapResponse = "bootstrap_response" // Return new proxy coordinates
	MsgTypeStatus            = "status"             // Client telemetry
	MsgTypeData              = "data"               // Small encrypted text payload
)
```

### 3.2 Bootstrap Payload Schema
When conventional ports are severed, the client issues a `bootstrap_request`. The authoritative server returns authenticated `BootstrapEndpointData`:
```json
{
  "server_ip": "77.37.65.2",
  "transport_port": 8443,
  "transport_mode": "tls-outer",
  "server_pub_key": "SHA256:4a8b...cert-fingerprint",
  "valid_until": 1780000000
}
```

### 3.3 Bootstrap Validation Rules
1. **Signaling Only:** Receiving a bootstrap response signals the *intended* next transport coordinates; it does not assume reachability.
2. **Mutual Handshake Required:** The client must initiate a full cryptographic handshake (e.g. genuine TLS 1.3 handshake with certificate pinning, or AEAD stream session) before routing user SOCKS5 traffic.
3. **Graceful Failover:** New connections transition to the new endpoint; existing streams fail over gracefully on reconnect.

---

## 4. Current External Dependency & Deployment Guide

- **Current Status:** Dual-authoritative nameserver code-level architecture and single-datagram stateless processing are implemented and verified in `v2.5.2-hardened`.
- **External Blocker:** The second independent authoritative endpoint requires an active second VPS instance on a non-Hetzner provider (e.g. Vultr, OVH, DigitalOcean, or an independent datacenter).
- **Deployment Procedure When Second VPS is Acquired:**
  1. Provision `paqet-emergency.service` and copy `/opt/paqet/emergency.key` to `Node 2`.
  2. In Cloudflare DNS:
     - Add `ns2.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir` `A` $\longrightarrow$ `<Node2_IP>`.
     - Add `tunnel...` `NS` $\longrightarrow$ `ns2...` alongside `ns-de...`.
  3. Verify delegation via `dig +trace` and `paqet emergency scan`.
