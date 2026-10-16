# Paqet-NG Failure-Domain Resilience Matrix

**Document Version:** 1.0.0  
**Phase:** 14  
**Date:** October 2026  
**Scope:** Technical demarcation between port-level failover, transport mode switching, destination-IP blocking, and autonomous-system/provider-level censorship.

---

## 1. Executive Summary & Purpose

Earlier test phases demonstrated that Paqet-NG's integrated `RecoveryStateMachine`, `StrategySelector`, and SOCKS5 connection pool can successfully detect port outages and route traffic through authenticated candidate endpoints. However, because both the primary transport (`:18088`), the recovery candidate (`:18089`), and the authoritative emergency DNS daemon (`:53`) reside on the same Hetzner Germany VPS (`77.37.65.2`), survival of destination-IP blocking, routing drops, or hosting-provider blackholing **cannot be claimed**.

This document defines an explicit, empirically grounded resilience matrix classifying:
1. **Proven & Verified:** Conditions tested and demonstrated with real traffic.
2. **Fail-Closed Safe:** Conditions where failure prevents unauthenticated compromise and deterministically stops traffic.
3. **Untested / Externally Blocked:** Conditions requiring independent multi-cloud infrastructure before empirical claims can be made.

---

## 2. Failure Domain Resilience Matrix

| Failure Domain ID | Scenario Description | Tested Condition | Expected Behavior | Observed Runtime Outcome | Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FD-01** | **Primary Transport Process Failure** | Process crashed or killed (`SIGKILL`) | Failure detector reports error; triggers degraded hysteresis | SOCKS5 proxy transparently recreates connection to candidate upon failover | **PROVEN & VERIFIED** |
| **FD-02** | **Primary Port Blocked** | Targeted firewall drop (`iptables -I OUTPUT -p tcp --dport 18088 -j DROP`) | Connection fails; DNS signaling initiates candidate validation | Verified live (Iran ⇄ Germany): HTTP request routed via candidate in 175.47ms | **PROVEN & VERIFIED** |
| **FD-03** | **Primary Mode Unavailable** | Strategy prerequisites not met or mode unsupported | Selector skips unavailable strategy; uses eligible candidates | Tested via `TestRecoverySelectorIntegration_UnauthorizedModeFailClosed` | **PROVEN & VERIFIED** |
| **FD-04** | **Candidate Port Blocked / Unreachable** | Candidate endpoint unreachable or port closed | Candidate dial fails; reports failure; enters cooldown | Tested via `TestTimedConn_EliminateImplicitFallbackOnCandidateFailure` | **FAIL-CLOSED SAFE** |
| **FD-05** | **Recursive Resolver Outage** | Configured recursive DNS resolver unresponsive | DNS client retries alternate resolvers in pool | Tested in Phase 10 (Google, Cloudflare, Quad9 resolver pool scan) | **PROVEN & VERIFIED** |
| **FD-06** | **Authoritative DNS Daemon Outage** | Daemon on `:53` stopped or unreachable | Emergency signaling times out; recovery fails closed | State machine enters `COOLDOWN`; no unauthenticated endpoints activated | **FAIL-CLOSED SAFE** |
| **FD-07** | **DNS Tampering / Poisoning** | Attacker or middlebox modifies DNS TXT responses | AEAD tag verification fails in `openFrame`; frame dropped | Tampered responses rejected with `REFUSED (5)` or authentication failure | **FAIL-CLOSED SAFE** |
| **FD-08** | **Same-IP Transport Mode Transition** | Candidate is on same IP, but mode changes (e.g. `aead` -> `tls`) | Client detects mode mismatch via `ConnectionIdentity`; recreates | Verified via `TestTimedConn_SameAddressModeChangeRecreates` | **PROVEN & VERIFIED** |
| **FD-09** | **Same-IP Generation Transition** | Candidate is on same IP, but recovery generation increments | Client detects generation revision mismatch; closes stale conn | Verified via `TestConnectionIdentity_Matches` & `dial.go` | **PROVEN & VERIFIED** |
| **FD-10** | **Destination IP Blocked (Single Host)** | Censor drops all traffic to `77.37.65.2` (IP-level blackhole) | Control plane and data plane both severed | **Cannot survive**: Both transports and authoritative NS share single IP | **UNTESTED / SPOF** |
| **FD-11** | **Candidate on Independent IP** | Candidate hosted on distinct IPv4 address | Candidate validated via independent handshake | Blocked pending second cloud VPS acquisition | **EXTERNALLY BLOCKED** |
| **FD-12** | **Candidate on Distinct Provider / ASN** | Candidate hosted on non-Hetzner autonomous system | Candidate accessible even if Hetzner AS24940 is blocked | Blocked pending second cloud VPS acquisition | **EXTERNALLY BLOCKED** |
| **FD-13** | **Multi-Server Uncoordinated Replay** | Same query sent across two independent authoritative daemons | Single-datagram queries succeed; multipart reassembly fails | Proven in Phase 11 (`TestDualAuthoritativeServerCrossServerRetriesAndReplay`) | **DOCUMENTED BOUNDARY** |
| **FD-14** | **Candidate Key Mismatch During Dial** | Client key does not match snapshot identity pin | Key checked before network dial; fails closed | Tested via `TestTimedConn_CandidateKeyMismatchFailsClosed` | **FAIL-CLOSED SAFE** |
| **FD-15** | **Rollback / Generation Race During Dial** | Rollback or generation increments while dial in flight | Identity verified before pool insertion; socket closed | Tested via `TestTimedConn_GenerationChangeOrRollbackDuringDialRejectsConnection` | **FAIL-CLOSED SAFE** |
| **FD-16** | **DNS Response Exceeding Safe UDP Limit** | Server response exceeds 1400 bytes | Server sets TC=1; client retries via RFC 7766 TCP :53 | Tested via `TestEDNS0_ResponseTruncationWhenExceedingLimit` & `TestEDNS0_TCPPort53FallbackOnTruncation` | **PROVEN & VERIFIED** |
| **FD-17** | **Emergency PSK Conflation** | Emergency server started without candidate identity flags | Implicit fallback removed; daemon fails startup | Tested via `TestEmergencyServerStartup_AEADWithoutKeyOrPinFails` & live CLI verification | **FAIL-CLOSED SAFE** |
| **FD-18** | **Cross-Server Nonce Reuse in Multi-Authoritative** | Two independent authoritative servers answer same session/seq | Server-specific HKDF response keys (`s2cKey` bound to `ServerID`) prevent key/nonce collision | Tested via `TestMultiAuthoritative_CryptographicSafetyAndKeyNonceSeparation` | **PROVEN & VERIFIED** |
| **FD-19** | **Unauthorized Rogue Server Injection** | Unlisted server sharing root PSK attempts to serve bootstrap | Client enforces `AuthorizedServers` whitelist in `VerifyFrameWithServerID`; rejects rogue reply | Tested via `TestMultiAuthoritative_CryptographicSafetyAndKeyNonceSeparation` | **FAIL-CLOSED SAFE** |
| **FD-20** | **Shared-PSK Server Impersonation** | Server A (holding `secretA`) attempts to forge Server B's response | Distinct 32-byte response secrets per server; client AEAD authentication tag verification fails | Tested via `TestAsymmetric_DistinctServerSecretsPreventImpersonation` & `TestPhase17_TwoAuthoritativeReadinessSuite` | **FAIL-CLOSED SAFE** |
| **FD-21** | **32-Bit Sequence Overflow Nonce Lifecycle** | Long-running session approaches $2^{32}-1$ sequence counter | Counter halted at `MaxSafeSequenceNumber` (`0xFFFFFFF0`); halts session cleanly with `ErrSequenceExhausted` | Tested via `TestAsymmetric_SequenceExhaustionFailsSafely`; zero overflow/wraparound | **FAIL-CLOSED SAFE** |

---

## 3. Analysis of Critical Boundaries

### 3.1 Port Outage vs. IP Outage
- **Port Outage:** Middleboxes often throttle or reset specific destination ports (e.g. `:443`, `:8088`, `:8089`) while leaving UDP `:53` or other port ranges unmolested. Paqet-NG's demonstrated ability to recover over port-level blocks provides high resilience against heuristic port throttling.
- **IP Outage:** If the censor injects BGP null-routes or drops all IP packets targeting `77.37.65.2`, neither the primary transport, the candidate transport, nor the authoritative DNS nameserver can be reached.

### 3.2 Single Authoritative NS Single Point of Failure (SPOF)
The delegated child zone `tunnel.passionatepharmacistwithdeepaffectionfortechnologyanditscience.ir` has a single `NS` record pointing to `ns-de...` (`77.37.65.2`).
- To survive destination IP or hosting provider failure, a secondary authoritative nameserver (`ns2...`) must be provisioned on an independent hosting provider (e.g. Vultr, OVH, or an independent datacenter).
- As established in Phase 11, uncoordinated authoritative pools cannot reassemble multipart frames. Therefore, emergency bootstrap queries must strictly remain single-datagram payloads ($\le 64\text{ bytes}$).

---

## 4. Operational Recommendations
1. **Never advertise IP-level censorship resistance** until a second server on a distinct autonomous system is provisioned and verified.
2. **Maintain strict fail-closed guarantees**: If recovery fails or the candidate endpoint is unreachable, client connections must return actionable errors and enter cooldown, rather than silently falling through to an unvalidated transport.
