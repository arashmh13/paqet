# Compatibility, Interoperability, and Migration Guide

## 1. Backward Compatibility Strategy

Paqet-NG is designed with complete backward compatibility for existing deployments:
1. **Wire Format Parity:** The hardened raw packet engine maintains 100% wire framing compatibility with baseline Paqet (`v1.0.0-alpha.21`). Existing client and server configuration files (`client.yaml` and `server.yaml`) operate without modification.
2. **Obfuscation Envelope Coexistence:** The anti-replay ring buffer added to `internal/obfs` operates entirely on the 12-byte random nonce, requiring zero changes to on-wire frame structure. A Paqet-NG client can communicate with an existing baseline server, and vice versa.
3. **Graceful Fallback:** If an unsupported protocol version or legacy KCP block cipher is encountered, the server routes the stream to the appropriate legacy engine.

---

## 2. Configuration Schema & Options

Paqet-NG introduces optional configuration keys under the `transport` block:

```yaml
role: "client" # or "server"
log:
  level: "info"

transport:
  # Transport engine selector:
  # "kcp"          - Legacy KCP over raw TCP (default for 100% backward compatibility)
  # "raw-hardened" - Hardened raw TCP with strict sequence tracking and anti-replay
  # "aead-stream"  - High-throughput userspace TCP stream with instant probe rejection
  type: "raw-hardened"
  conn: 1
  obfs:
    enabled: true
    key: "yP9v/8x+n3Lp+ZqW4s1RjT5oK2a9XbE8vM7JdH4="
    maxpad: 64
  replay:
    window_seconds: 30
    ring_size: 16384
```

---

## 3. Step-by-Step Migration & Rollback Procedures

### 3.1 Upgrading from Baseline Paqet to Paqet-NG
1. **Preserve Baseline:** Verify `/opt/paqet/backup-baseline/` contains original binary and config.
2. **Stop Daemons:**
   ```bash
   systemctl stop paqet
   ```
3. **Deploy New Binary:**
   ```bash
   cp /tmp/paqet-ng /opt/paqet/paqet
   chmod +x /opt/paqet/paqet
   ```
4. **Start Server Node (Germany) First:**
   ```bash
   systemctl start paqet
   systemctl status paqet
   ```
5. **Start Client Node (Iran):**
   ```bash
   systemctl start paqet
   systemctl status paqet
   ```
6. **Verify End-to-End Flow:**
   ```bash
   curl -x socks5://arash:arash@127.0.0.1:1090 -s http://127.0.0.1:8999/ping
   ```

### 3.2 Rollback Procedure (Emergency Reversion)
If unexpected network degradation occurs:
```bash
systemctl stop paqet
cp /opt/paqet/backup-baseline/paqet /opt/paqet/paqet
systemctl start paqet
```
Rollback takes under 2 seconds and restores exact baseline state.
