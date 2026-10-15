# Paqet-NG Cryptographic Architecture & Security Specification

## 1. Cryptographic Objectives & Threat Model

The cryptographic subsystem of Paqet-NG is designed to provide:
1. **Confidentiality & Integrity:** Authenticated Encryption with Associated Data (AEAD) ensuring that no observer can inspect, alter, or inject traffic.
2. **Replay Attack Resistance:** Deterministic sliding-window verification and timestamp validation preventing eavesdropped packet replay.
3. **Active Probing Resistance:** Immediate detection and silent rejection or instant termination of invalid handshakes, preventing fingerprinting by automated censors.
4. **Indistinguishability from Random Noise (or Legitimate TLS):** Elimination of static magic bytes, identifiable framing patterns, or protocol indicators in the initial segment.
5. **Nonce Safety & Key Derivation:** Cryptographically sound derivation of distinct encryption, authentication, and subkeys using standard KDFs (HKDF / PBKDF2).

---

## 2. Key Derivation & Hierarchy

### 2.1 Master Key Derivation
The pre-shared secret (PSK) configured by the user is expanded into subkeys using **HKDF-SHA256** (RFC 5869) or **PBKDF2-SHA256**:

```
Pre-Shared Secret (PSK, 32+ bytes)
                |
                v
    HKDF-Extract(salt = "paqet-ng-v2-salt", PSK)
                |
                v
             PRK (32 bytes)
                |
       +--------+--------+
       |                 |
       v                 v
HKDF-Expand("c2s")   HKDF-Expand("s2c")
       |                 |
       v                 v
Client-to-Server     Server-to-Client
Key (32 bytes)       Key (32 bytes)
```

- **Salt:** Fixed domain-separation salt `"paqet-ng-v2-salt"`.
- **Directional Separation:** Separate keys are derived for Client-to-Server (`c2s`) and Server-to-Client (`s2c`) traffic, preventing reflection attacks where an adversary intercepts a client packet and reflects it back to the client.

---

## 3. Anti-Replay Architecture: Sliding Window & Timestamp Filter

To resolve the vulnerability discovered in baseline Paqet (`internal/obfs` accepting replayed packets indefinitely), Paqet-NG introduces a dual-layer anti-replay engine:

```
[Incoming Packet]
       |
       v
Layer 1: Timestamp Window Filter (30-second window)
       |--> |t_packet - t_local| > 30s ? --> DROP IMMEDIATELY
       v
Layer 2: Sliding-Window Nonce/Sequence Filter (1024-packet bitmap)
       |--> Sequence already seen in window? --> DROP IMMEDIATELY
       |--> Sequence older than window bottom? --> DROP IMMEDIATELY
       v
Layer 3: AEAD Authenticated Decryption
       |--> MAC verification fails? --> DROP / TERMINATE
       v
[Accept & Process Payload]
```

### 3.1 Layer 1: Epoch / Monotonic Timestamp Window
- Each packet header carries a 4-byte Unix timestamp (seconds since epoch) or relative session counter encrypted under the AEAD header key.
- The receiver compares the timestamp against its local clock:
  $$\Delta t = |t_{\text{packet}} - t_{\text{local}}|$$
- If $\Delta t > 30\text{ seconds}$, the packet is dropped immediately before allocating any decryption buffers.

### 3.2 Layer 2: 1024-Packet Sliding Window Bitmap
- For packets within the timestamp window, a 1024-bit sliding window tracks observed sequence numbers:
  - If a sequence number has already been seen in the bitmap, it is dropped as a duplicate.
  - If the sequence number is new and advances the window, the bitmap slides forward and sets the corresponding bit.

---

## 4. Authenticated Encryption Construction

Paqet-NG employs **AES-256-GCM** (or **ChaCha20-Poly1305** where hardware AES is absent):

### 4.1 Packet Construction (Datagram / Hardened Mode)
```text
+-------------------+--------------------+------------------------+-------------------+
| Nonce (12 Bytes)  | Timestamp (4 Bytes)| Encrypted Data + Pad   | AEAD Tag (16 Bytes|
+-------------------+--------------------+------------------------+-------------------+
```
1. **Nonce:** 12 bytes generated via `crypto/rand` per packet, guaranteeing nonce uniqueness ($2^{96}$ space).
2. **Additional Authenticated Data (AAD):** The 12-byte nonce and 4-byte timestamp are passed as AAD to the AEAD cipher, binding the metadata cryptographically to the ciphertext.
3. **Payload:** Sized `[2B Length] + [Payload] + [Padding]`.
4. **Padding:** Randomly padded up to `maxPad` bytes to prevent traffic size correlation.

### 4.2 Stream Framing Construction (Stream Mode)
For TCP-based stream connections, Paqet-NG uses chunked AEAD framing:
```text
+------------------------------------+---------------------------------------------+
| Header (2B Length + 16B Tag)       | Body (Payload + Pad + 16B Tag)              |
+------------------------------------+---------------------------------------------+
```
- Each chunk is individually authenticated.
- Subkey rotation: Every $2^{24}$ records or 1 hour, a subkey is automatically rotated using HKDF.

---

## 5. Active Probing Defense & Fallback

In baseline Paqet, active probes completed a 3-way handshake and were met with silence. In Paqet-NG:
1. **Probe Identification:** Any packet that fails AEAD authentication or timestamp validation is classified as an unauthorized probe.
2. **Immediate Connection Termination:** Rather than keeping the socket open in a tarpit state, the server immediately sends a TCP RST or cleanly closes the connection (`TCP FIN`), matching standard closed or non-listening port behavior.
3. **Camouflage Fallback Option:** In stream mode, unauthenticated connections can optionally be forwarded to a local decoy HTTP/HTTPS service (such as Nginx on port 80/443), presenting authentic HTTP responses to port scanners.
