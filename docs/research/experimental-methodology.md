# Experimental Methodology & Measurement Standards

## 1. Principles of Scientific Rigor

To prevent confirmation bias and ensure high standards of empirical investigation, the Paqet-NG project adheres to four core research principles:
1. **Verifiable Artifacts Over Recommendations:** Every architectural decision is backed by executed code, packet captures, and quantitative benchmark data.
2. **Deterministic Control Environments:** Application transport testing is decoupled from external Internet variance by using an in-host controlled benchmark daemon (`echo_server.py`) on the German VPS.
3. **Dual-Endpoint Packet Auditing:** Every protocol claim is verified using synchronized `tcpdump` traces captured at both the Iranian egress interface (`eth0`) and the German ingress interface (`ens3`).
4. **Zero-Fabrication Reporting:** Unexecuted checks, unresolved hypotheses, and environmental boundaries are explicitly disclosed rather than masked.

---

## 2. Benchmark Measurement Specifications

### 2.1 Latency Measurements
- **Tool:** `curl` using high-resolution connection timing variables:
  - `time_connect`: Duration to establish local SOCKS5 TCP connection.
  - `time_starttransfer`: Duration from request initiation until the first response byte is received from the destination (measures tunnel round-trip time + remote processing).
  - `time_total`: Full duration of the transaction.
- **Sample Size:** Bounded runs of 10 consecutive executions with 100ms pacing between trials.

### 2.2 Throughput Measurements
- **Payload Sizes:** Exact powers-of-two and decimal benchmarks: 1 MB ($1,048,576\text{ bytes}$), 5 MB ($5,242,880\text{ bytes}$), and 10 MB ($10,485,760\text{ bytes}$).
- **Validation:** Byte count verified via `size_download` to ensure zero payload truncation.
- **Metric:** Sustained byte transfer rate ($\text{Bytes/sec}$) calculated over the full transfer duration.

### 2.3 Packet Trace Auditing
- **Tool:** `tcpdump` capturing full packets (`snapshot-length 262144`).
- **Filters:** Bounded capture on physical interfaces: `host 185.18.215.124 and port 8088`.
- **Validation Criteria:**
  - $\text{Seq}_{i+1} = \text{Seq}_i + \text{PayloadLen}_i$.
  - $\text{Ack}_i$ matches remote peer sequence space.
  - $\text{TSval}_i \le \text{TSval}_{i+1}$ (monotonic progression).
  - $\text{TSecr}_i \le \text{TSecr}_{i+1}$ (non-decreasing echo).
