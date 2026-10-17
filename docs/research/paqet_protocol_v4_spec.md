# PAQET-NG Protocol v4 ("PAQD") Specification

Status: draft (Phase 19). Supersedes the v3 ("PAQC") deterministic-session keying scheme for multi-authoritative emergency exchanges.

## Framing

All fields are big-endian.

### v4 server-downstream frame (server → client)

```
Magic          4 bytes   0x50415144 ("PAQD")
SessionID      8 bytes   client-chosen 64-bit session identifier
Seq            4 bytes   strictly increasing 32-bit sequence
Ack            4 bytes   highest in-order client sequence acknowledged
SeedLen        1 byte    constant 0x10 (16)
SessionSeed   16 bytes   client-generated per-session random seed (HKDF salt component)
ServerIDLen    1 byte    length of ServerID
ServerID       N bytes   immutable canonical server identity (lowercase [a-z0-9._-], 3..64)
RNBLen         1 byte    constant 0x08
RNB            8 bytes   per-server-instance random downstream nonce stream base
AEAD Payload   16-byte AES-256-GCM tag appended after ciphertext payload
```

Minimum frame length before payload: 4+8+4+4+1+16+1+64..1+1+8 = 47 bytes (with 1-byte ServerID).

### v4 client-upstream frame (client → server)

```
Magic          4 bytes   0x50415144 ("PAQD")
SessionID      8 bytes   client-chosen 64-bit session identifier
Seq            4 bytes   strictly increasing 32-bit sequence
Ack            4 bytes   highest in-order server sequence acknowledged
SeedLen        1 byte    constant 0x10 (16)
SessionSeed   16 bytes   client-generated per-session random seed
ServerIDLen    1 byte    constant 0x00 (upstream carries no server identity)
AEAD Payload   . AES-256-GCM tag appended after ciphertext payload
```

Minimum frame length before payload: 4+8+4+4+1+16+1 = 38 bytes.

### AAD

The entire cleartext frame prefix (magic, sessionID, seq, ack, seedLen, seed, serverIDLen, serverID, [rnbLen, rnb]) is authenticated associated data. Any tampering with ServerID, sequence, ack, or session identifiers fails the AEAD tag.

## Key derivation

- Upstream key (`c2s`): `HKDF-SHA256(ikm=c2sPSK, salt="paqet-v4-" || seed(16) || sessionID(8BE), info="paqet-v4-c2s")`.
- Downstream key (`s2c`): `HKDF-SHA256(ikm=serverSecret, salt=V4Salt(seed, sessionID), info="paqet-v4-s2c:" + serverID)`.
- The v3 info strings differ (`paqet-ng-v3-c2s` / `paqet-ng-v3-s2c:<serverID>`), so v3 and v4 keys are cryptographically disjoint even when the underlying long-term credentials match.

## AEAD

AES-256-GCM. The 12-byte nonce is constructed as:

- **Server→client (v4)**: `[rnb(8) || seq(4)]` with `nonce[0] ^= byte(RoleServer)`.
- **Client→server / v2/v3 frames**: `[sessionID(8 BE) || seq(4)]` with `nonce[0] ^= byte(sender role)`.

Downstream nonces are unique per server instance because the per-instance `rnb` is regenerated from crypto/rand on each server (re)start, even when a replayer resubmits the exact captured request under identical (`sessionID`, `seed`, `serverID`, long-term credentials). Residual risk of accidental `(rnb, seq)` overlap across two independent server instances is bounded by ~n²/2⁶⁵ (8-byte RNB) — a *probabilistic* upper bound, not a mathematical guarantee.

Upstream client frames retain the deterministic SessionID‖Seq nonce domain: an upstream rekey would break deterministic server-side candidate reconstruction, and upstream GCM operations are all decrypts (no new encrypts reuse a nonce for a different plaintext).

## Session lifecycle

- The client selects a 64-bit `sessionID` (full-entropy crypto/rand) and a 128-bit random `sessionSeed`. Both travel in the cleartext frame prefix.
- Clients regenerate `sessionID` on every client restart. A constant `sessionID` is not itself identity-bearing; it only discriminates *within* a specific key epoch (`c2sPSK` + per-server response secret).
- A server seeing an unknown `sessionID` establishes an ephemeral in-memory session bound to the frame seed, the configured ServerID, and its current per-instance `rnb`, then decrypts and responds.
- A server restart flushes sessions, reply caches, and anti-replay filters; replays are therefore answered by a fresh session carrying a fresh `rnb`.
- The server enforces sequence exhaustion hard-stop at `MaxSafeSequenceNumber = 0xFFFFFFF0` and never wraps to 0.

## Protocol-version policy

Older v2/"PAQA" and v3/"PAQC" frames are explicitly rejected on v4 sessions (AEAD tag will never validate because the v4 seed field does not exist in the older header). v4 frames are explicitly rejected on v2 and v3 sessions. There is no silent reinterpretation across framing generations.

## Authorized-server verification

The response key for ServerID is derived from that server's dedicated 32-byte response secret; the client only carries credentials for authorized server IDs. A response frame from an unauthorized ServerID is rejected fail-closed WITHOUT attempting key derivation. Malformed or oversized ServerID/seed/RNB lengths are rejected BEFORE allocation or key derivation, so a truncated or malformed frame bypasses decryption entirely.

## Duplicate/replay semantics

诚实分层模型：

| Mechanism | Scope | Lifetime |
| --- | --- | --- |
| Server replay filter (client seq, per client conn) | per client session conn | server lifetime |
| Server in-flight request fingerprint | same seq + same auth-ciphertext | request lifetime |
| Server reply cache | same seq + same fingerprint | reply-cache window, in-memory until eviction/restart |
| Client per-server response nonce-domain replay window | serverID + per-instance rnb | client process lifetime, up to 32 domains |
| Client's `msg.ID` | one random 128-bit request identity | single Exchange call |

Handler operations in this protocol version are read-only and idempotent (bootstrap response generation, ACK_ECHO). A replayed authenticated request may produce a NEW response with the SAME semantics but a FRESH validity-window generation. Future handlers that mutate state (for example, key-rotation ACTION) must add their own durable deduplication layer or persist `(sessionID, requestDigest)` before executing anything that is not naturally idempotent. Plaintext handlers are NOT protected against replay-side-effects out of the box.

## Trust boundary (documented, unchanged from Phase 18)

Because the response key is a symmetric secret also held by the client, any client that knows the authorized `secret_A` can itself forge frames claiming ServerID A to another client. This design protects against *differential* unauthorized servers (servers holding A's ID but not A's secret) but does NOT protect against a compromised authorized client. Asymmetric server authentication is an explicit future phase.

## Session collision bounds (honest)

- v3: `P_collision ≈ n² / 2⁶⁵` birthday bound on the 64-bit SessionID under a fixed credential epoch. n = 10⁶ ⇒ ≈ 5.4×10⁻¹⁴; n = 2³² ⇒ ≈ 50%. This is a PROBABILISTIC statement.
- v4: `P ≈ n² / 2¹²⁹` birthday bound on the 128-bit seed-salt component. n = 10⁹ ⇒ ≈ 10⁻²⁰. Also PROBABILISTIC. Both collision estimates are reported only as bounds against ACCIDENTAL random collisions; adversarial replay is treated separately (see duplicate/replay semantics).


---

## Rev 2 Addendum (Phase 20): Server-Session Nonce/Key Base, Domain Sealing & Control-Message Safety

Status naming correction: the previous "per-instance RNB" term is renamed the **server-session nonce/key base**. It is generated exactly once inside `NewServerAsymmetricSessionWithIDV4` (the single call site of `crypto.GenerateDownstreamNonceBase()`), i.e. per reconstructed SERVER SESSION — not per process, and not per TCP/UDP connection. Normal reconnects and session evictions create NEW sessions (fresh base); process restart destroys sessions so the next request reconstructs every session with a fresh base; server restart is the same mechanism at process scale.

### v4.1 Key-derivation change (KDF-context only; wire layout unchanged)
- `s2c` response-key HKDF salt becomes `V4Salt(seed, sessionID) || serverSessionBase` (both `DeriveServerTrafficKeysV4` and `DeriveServerResponseKeyV4`). The `c2s` salt is UNCHANGED (must stay derivable from the cleartext request alone).
- Consequence: every reconstruction of the same `(sessionID, seed, serverID, secret)` tuple produces a DIFFERENT response key. Cross-instance ciphertexts are key-disjoint; `(key, nonce)` reuse now additionally requires a base collision.
- v4.1 is mandated before any production promotion; the Phase 19 candidate's KDF differed and was never deployed to production. Explicit change note, not a silent modification.

### Residual collision bound (PROBABILISTIC, not an invariant)
- Accidental base collision across `n` reconstructions of the SAME session tuple: `P ≈ n²/2⁶⁵` — n=10⁶ ⇒ ~2.7×10⁻⁸; n=10⁹ ⇒ ~0.027. Accidental collision of client seeds remains the n²/2¹²⁹ bound.
- Deliberate replay of an existing session tuple is NOT a collision question: the attacker replays the exact captured frame. That class is covered by the per-domain client replay window, domain-capacity sealing (below), and the response AEAD binding — not by entropy bounds.

### Replay-domain capacity (Phase 20 fix)
- Client replay-window domains (`serverID#base`, per-connection) are capped at `MaxServerReplayDomainsPerConn = 32`.
- On a 33rd DISTINCT AUTHENTICATED domain the connection is SEALED: `ErrReplayDomainCapacity`, `replayDomainSealed` set permanently, every further downstream frame fails closed. Domains are NEVER evicted — eviction would silently re-open an accepted replay window (Acceptance Criterion 1).
- Capacity is consumed ONLY by AEAD-authenticated frames: malformed frames, unknown server IDs, corrupted ciphertexts and all-zero bases are rejected before the replay stage and cannot consume capacity (verified by flood tests).
- Memory bound: ≤32 × window filter per connection, exhausted state is one atomic bit.
- A sealed session requires a new authenticated session (new client session construction); this is explicit, not implicit.

### Control-message safety policy (explicit, table-driven)
| Type | Class | Duplicate/replay semantics |
| --- | --- | --- |
| `ping` | read-only | safe to answer any number of times; no state |
| `status` | read-only | safe; state report only |
| `bootstrap_request` | idempotent | duplicate re-generates a fresh validity window; same semantics |
| `bootstrap_response` | idempotent | client-side last-writer-wins endpoint apply |
| `alert` | idempotent | duplicates re-notify; no durable state mutation |
| `data` | state-changing | UNSUPPORTED for exactly-once without a durable dedup layer; transport class `ClassStateChanging`; never claim exactly-once from in-memory state |
| unknown | unsupported | rejected by `Validate()` before any handler (FORMERR); payloads are opaque bytes, never interpreted as commands |

- The server reply cache / retransmission fingerprint is a RETRANSMISSION OPTIMIZATION, never replay protection: a duplicate may re-run the handler after cache eviction or server restart, and the SAME handler must be safe to run twice. Verified by wire tests for every supported type (duplicate on live server, the same request to two independent servers, and replay after a full server restart with all in-memory state lost).
- No exactly-once semantics are claimed anywhere. Future state-changing operations require durable `(sessionID, requestDigest)` dedup with bounded storage before execution.

### Trust model (unchanged, restated)
Symmetric per-server response secrets protect against foreign servers (an ID-holder without the secret cannot authenticate) but NOT against a compromised authorized client, who can forge frames for that identity. Asymmetric server authentication remains a separate future phase.
