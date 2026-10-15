# Asymmetric Transport Protocol Security Audit, Cryptographic Verification, and Reliability Hardening

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Investigator:** Autonomous Network-Protocol Architect, Transport-Security Auditor & Go Systems Engineer  
**Repository:** `https://github.com/arashmh13/paqet`  
**Target Architecture:** `AsymmetricConn` & `internal/ng/transport/asymmetric.go`

---

## 1. Executive Summary & Audit Scope

This audit evaluates the complete cryptographic security, header integrity, replay resistance, session lifecycle, and packet-loss recovery mechanisms of Paqet-NG's directionally decoupled transport (`AsymmetricConn`).

### Key Findings & Hardened Safeguards:
1. **Header Authenticated Data (AAD):** The entire 20-byte unencrypted wire header (`Magic`, `SessionID`, `Seq`, `Ack`) is bound to the ciphertext as Additional Authenticated Data (AAD). Unit tests (`TestAsymmetricHeaderTamperingRejection`) confirm that tampering with any individual header field causes immediate AEAD authentication failure.
2. **Nonce Collision & Sequence Wraparound:** In 12-byte AEAD nonces, reusing a nonce with the same key is catastrophic (leaks the GHASH key in AES-GCM). `AsymmetricConn` now strictly enforces sequence exhaustion gating (`ErrSequenceExhausted`) at $2^{32}-16$ frames, preventing wraparound nonce collisions.
3. **Anti-DoS Ordering Enforcement:** Verification confirms that the sliding-window replay filter (`replay.Filter`) is updated **only after** successful AEAD authentication. Unauthenticated attackers cannot forge sequence numbers to advance the sliding window or induce DoS.
4. **Reliability & Automatic Retransmissions:** A retransmission buffer (`unackedFrame`) and RTO ticker (default 600ms) were implemented. Unacknowledged frames are automatically retransmitted on loss and pruned upon receipt of cumulative peer ACKs (`TestAsymmetricLossAndAutomaticRetransmission`).
5. **Memory Allocation & Flooding Bounds:** `DNSReassembler` was hardened with a strict cap of `MaxPendingFrames = 1024` and `totalParts <= 64` to prevent heap exhaustion attacks via spoofed fragment floods.

---

## 2. Wire Header Architecture & AEAD Integrity Proof

### 2.1 Wire Format Breakdown
Every asymmetric frame transmitted on the wire consists of a fixed 20-byte header followed by AEAD ciphertext:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic (0x50415141)                      |  "PAQA"
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Session ID (64 bits)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence (32 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          ACK (32 bits)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      AEAD Ciphertext ...                      |
|              (Payload + 16-byte Poly1305 / GCM Tag)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Header Tampering Audit & Empirical Tests
In `sealFrame`:
```go
header := make([]byte, AsymmetricHeaderLen)
binary.BigEndian.PutUint32(header[0:4], AsymmetricMagic)
binary.BigEndian.PutUint64(header[4:12], c.sessionID)
binary.BigEndian.PutUint32(header[12:16], seq)
binary.BigEndian.PutUint32(header[16:20], ack)

ciphertext := aead.Seal(nil, nonce, plaintext, header)
```
In `openFrame`:
```go
header := frame[:AsymmetricHeaderLen]
ciphertext := frame[AsymmetricHeaderLen:]
plaintext, err = aead.Open(nil, nonce, ciphertext, header)
```

**Empirical Verification (`TestAsymmetricHeaderTamperingRejection`):**
- **Tampered Magic:** Rejected with `ErrAsymmetricInvalidMagic` before cryptographic processing.
- **Tampered SessionID:** Rejected because extracted `sessionID` does not match active session.
- **Tampered Seq:** The modified sequence alters the AAD. `aead.Open` fails with `crypto: decryption failed or authentication tag mismatch`.
- **Tampered Ack:** The modified ACK alters the AAD. `aead.Open` fails with tag mismatch.

**Conclusion:** Zero header fields can be modified by an on-path attacker without invalidating the cryptographic authentication tag.

---

## 3. Cryptographic Key Derivation & Nonce Construction

### 3.1 Directional Key Separation
Subkeys are derived using HKDF-SHA256 from the master Pre-Shared Key (PSK) and unique `SessionID`:
- Client-to-Server Encryption Key ($K_{c2s}$): 32 bytes.
- Server-to-Client Encryption Key ($K_{s2c}$): 32 bytes.
Because $K_{c2s} \ne K_{s2c}$, reflection attacks (replaying client frames back to the client) fail decryption immediately.

### 3.2 Nonce Uniqueness & Sequence Wraparound Gating
Nonces are 12 bytes:
$$\text{Nonce} = \text{SessionID}[0..7] \,\|\, \text{Seq}[0..3], \quad \text{Nonce}[0] \oplus= \text{Role}$$
- **Role Separation:** Client uses `RoleClient (1)`; server uses `RoleServer (2)`. This ensures nonces never collide across directions even if `SessionID` and `Seq` match.
- **Wraparound Gating:** If `c.sendSeq.Load() >= 0xFFFFFFF0` ($4,294,967,280$), `Write()` refuses to encrypt and returns `ErrSequenceExhausted`. This eliminates the risk of nonce reuse in long-lived sessions.

---

## 4. Replay-Window Validation & DoS Protection

### 4.1 Anti-DoS Validation Ordering
In naive implementations, sequence numbers are marked in the replay filter before payload decryption. An unauthenticated attacker sending forged frames with high sequence numbers could advance the sliding window, causing subsequent legitimate frames to be discarded as "window overflow."
- **Hardened Order in `openFrame`:**
  1. Parse header length and magic.
  2. Decrypt and verify AEAD authentication tag (`aead.Open(nil, nonce, ciphertext, header)`).
  3. **Only upon successful tag verification:** Invoke `c.replay.Validate(uint64(seq))`.

---

## 5. Reliability & Loss Recovery Architecture

Because asymmetric transports travel over unreliable channels (e.g. UDP datagrams or DNS QNAME queries), packet drops stall stream reassembly unless retransmitted.

### 5.1 Retransmission Queue (`unackedFrame`)
- When `Write()` seals a frame, it stores a copy in `c.unacked[seq] = &unackedFrame{seq, frame, sentAt, retries}`.
- A background goroutine (`retransmitLoop`) checks unacknowledged frames every $RTO/2$. If $\text{now} - \text{sentAt} \ge RTO$ (default 600ms), the frame is retransmitted up to `MaxRetries` (8 attempts).
- When an authenticated frame with `Ack = A` arrives, all unacknowledged frames with $\text{Seq} \le A$ are purged from memory.

---

## 6. Memory Allocation & Resource Exhaustion Bounds

To defend against memory exhaustion (heap spray / fragment flooding attacks):
1. **`AsymmetricConn` Out-of-Order Map:** Capped at 256 frames ($256 \times 1.4\text{ KB} \approx 360\text{ KB}$ max overhead per connection).
2. **`DNSReassembler` Pending Frames:** Capped at `MaxPendingFrames = 1024`. If pending fragmented sessions exceed 1,024, new fragments are dropped until the cleaner loop prunes expired sessions.
3. **Max Total Parts:** `totalParts` in QNAME headers is capped at $\le 64$ parts. Queries specifying $> 64$ parts are rejected with `ErrDNSInvalidQuery`.
