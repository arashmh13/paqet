# Known Limitations, Constraints, and Scope Boundaries

## 1. Single Path Validation Boundary

- **Path Scope:** All empirical findings and live integration benchmarks in this report were conducted strictly across the designated **Iran VPS (`185.18.215.124`) to German VPS (`77.37.65.2`)** international network link.
- **Interpretation:** While this path crosses the Iranian Telecommunication Infrastructure Company (TIC) international border gateway, **datacenter VPS traffic may experience different filtering policies from residential ISP connections** (e.g. MCI, Irancell, Shatel, or TCI FTTH).
- **Universal Claims Disavowed:** Success on this verified link does **not** constitute proof of universal resistance against all global censors or China's Great Firewall (GFW).

---

## 2. Kernel & Operating System Constraints

### 2.1 Raw-Packet Injection Requirements
- `raw-hardened` mode requires root privileges (`CAP_NET_RAW` / `CAP_NET_ADMIN`) and access to the host network interface.
- It cannot be run inside unprivileged Docker containers or standard restricted cloud functions without `network_mode: host` and elevated capabilities.
- Windows hosts require Npcap OEM drivers in WinPcap compatibility mode.
- WSL2 requires mirrored networking (`networkingMode=mirrored`) and disabled Hyper-V firewall; it cannot function over standard WSL2 NAT switches.

### 2.2 Residential NAT Limitations
- Like baseline Paqet, `raw-hardened` mode generates raw Layer-2 Ethernet frames targeting the physical gateway MAC. Behind residential home routers with stateful Linux Netfilter NAT (`nf_conntrack`), out-of-order raw frames may be marked `INVALID` and discarded unless the router is in Bridge/PPPoE mode or DMZ is configured.
- **Solution:** For residential endpoints, Paqet-NG's `aead-stream` mode operates via standard kernel sockets and traverses all consumer NAT routers seamlessly.

---

## 3. Cryptographic & Traffic Analysis Boundaries

1. **Passive Flow Correlation:** While uniform padding (`0..maxPad`) disrupts precise packet-size fingerprinting, it does not fully obscure long-term statistical burst patterns or session timing during continuous bulk transfers.
2. **Replay Window Expiry:** The anti-replay ring buffer protects against up to 16,384 replayed packets per connection. Replays arriving after the buffer rolls over and outside the 30-second clock window are rejected by the timestamp check, but require reasonably synchronized clocks ($\Delta t < 30\text{s}$).
