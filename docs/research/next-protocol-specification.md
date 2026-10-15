# Paqet-NG Wire Protocol Specification (Version 2)

## 1. Protocol Architecture & Identity

- **Protocol Name:** Paqet Next-Generation (Paqet-NG)
- **Protocol Version:** `0x02`
- **Transport Abstraction:** Modular (supports `raw-hardened` and `aead-stream` modes)
- **Multiplexing Engine:** smux v2 over secure authenticated channel
- **Framing Model:** Explicit length-prefixed binary framing with authenticated integrity verification

---

## 2. Hardened Raw Packet Transport Specification (`raw-hardened`)

### 2.1 Stateful 3-Way Handshake & Sequence Initialization
Unlike baseline Paqet which discarded ISNs and emitted synthetic `+128` sequence jumps, `raw-hardened` implements true TCP sequence tracking:

```text
 Client                                                   Server
   |                                                         |
   | 1. SYN (len 0, Client_ISN, standard TCP options)        |
   |-------------------------------------------------------->|
   |                                                         |
   | 2. SYN-ACK (len 0, Server_ISN, Ack = Client_ISN + 1)    |
   |<--------------------------------------------------------|
   |                                                         |
   | 3. ACK (len 0, Seq = Client_ISN + 1,                    |
   |         Ack = Server_ISN + 1)                           |
   |-------------------------------------------------------->|
   |                                                         |
   | [Client State: ESTABLISHED]           [Server State: ESTABLISHED]
   | Seq_Client = Client_ISN + 1           Seq_Server = Server_ISN + 1
   | Ack_Client = Server_ISN + 1           Ack_Server = Client_ISN + 1
```

### 2.2 Sequence & Acknowledgment Advancement Rule
For every subsequent data packet containing $L$ bytes of payload:
- **Transmitter Sequence Number:** $\text{Seq}_{\text{out}} = \text{Seq}_{\text{current}}$
- **Transmitter Advancement:** $\text{Seq}_{\text{next}} = \text{Seq}_{\text{current}} + L$
- **Transmitter Acknowledgment Number:** $\text{Ack}_{\text{out}} = \text{Last Received Peer Seq} + \text{Peer Payload Length}$
- **Timestamp Generation:** $\text{TSval} = \text{Current Milliseconds}$, strictly monotonically increasing ($\Delta \text{TSval} \ge 0$). $\text{TSecr} = \text{Last Seen Peer TSval}$, non-decreasing.

### 2.3 On-Wire Packet Layout (Raw Hardened)
```text
+--------------------------------------------------------------------------+
| Ethernet Header (14 Bytes): Dst MAC, Src MAC, EtherType (0x0800 / 0x86DD) |
+--------------------------------------------------------------------------+
| IPv4 Header (20 Bytes): DF=1, TOS=0, TTL=64, Proto=6                     |
+--------------------------------------------------------------------------+
| TCP Header (20 Bytes + 12B Options):                                     |
|   - Real Ports: Client Port <-> Server Port                              |
|   - Strictly tracked Seq and Ack                                         |
|   - Flags: PSH, ACK (0x018) for data packets                             |
|   - Options: NOP, NOP, Timestamps (TSval monotonic, TSecr echoing)       |
+--------------------------------------------------------------------------+
| Paqet-NG Envelope:                                                       |
|   - Nonce (12 Bytes)                                                     |
|   - Unix Timestamp (4 Bytes BigEndian)                                   |
|   - Encrypted Data + Padding (Variable)                                  |
|   - Poly1305 / GCM Tag (16 Bytes)                                        |
+--------------------------------------------------------------------------+
```

---

## 3. High-Throughput AEAD Stream Transport (`aead-stream`)

For environments where raw socket injection is either blocked by strict ISP routing or unprivileged execution (non-root) is required, `aead-stream` provides a standard TCP stream transport with authenticated framing:

### 3.1 Initial Handshake Request (Client -> Server)
```text
+-----------------------+-----------------------+--------------------------+
|  Client Nonce (16B)   | Encrypted Header (16B)| Header AEAD Tag (16B)    |
+-----------------------+-----------------------+--------------------------+
```
- **Plaintext Header (16B):**
  - Bytes 0-1: Protocol Version (`0x0002`)
  - Bytes 2-5: Timestamp (uint32 BigEndian)
  - Bytes 6-7: Padding Length ($0 \le P \le 256$)
  - Bytes 8-15: Reserved (Random bytes)
- **Authentication:** If header tag or timestamp fails verification, connection is closed instantly with TCP RST/FIN.

### 3.2 Data Record Framing
Following handshake, all communication is framed into discrete AEAD chunks:
```text
+-----------------------------+---------------------------------------------+
| Chunk Length (2B) + Tag(16B)| Encrypted Chunk Payload + Padding + Tag(16B)|
+-----------------------------+---------------------------------------------+
```
- Maximum chunk payload: 16,384 bytes.
- Frame boundary: Length prefix indicates exact payload size. Receiver reads full chunk before decrypting.

---

## 4. Application Protocol Framing (Inside Multiplexed Streams)

Within each `smux` stream, Paqet-NG employs Version 2 application framing:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  MAGIC (0x50) | VERSION (0x02)|   CMD (1B)    |   FLAGS (1B)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       BODY LENGTH (4B)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        BODY PAYLOAD                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.1 Header Fields
- `MAGIC`: `0x50` (`'P'`).
- `VERSION`: `0x02` (distinguishes Paqet-NG from baseline `0x01`).
- `CMD`:
  - `0x01` (`CMD_PING`): Heartbeat request.
  - `0x02` (`CMD_PONG`): Heartbeat response.
  - `0x03` (`CMD_TCP_CONNECT`): Request TCP stream connection to target host and port.
  - `0x04` (`CMD_UDP_ASSOCIATE`): Request UDP forward stream.
  - `0x05` (`CMD_TERMINATE`): Explicit stream termination with error code.
- `FLAGS`: Bitfield for options (e.g. `0x01` = compressed, `0x02` = urgent).
- `BODY LENGTH`: uint32 BigEndian. Maximum body length: 65,536 bytes.

---

## 5. State Machine & Lifecycle Transitions

```
[IDLE / DISCONNECTED]
       |
       | Client dials transport (Raw 3-way or AEAD Stream)
       v
[TRANSPORT_CONNECTING]
       |
       | Handshake & Timestamp exchange
       |---> Invalid credentials / Timestamp delta > 30s --> [ABORT & RESET]
       v
[AUTHENTICATED]
       |
       | Initialize smux v2 session
       v
[SESSION_ACTIVE]
       |
       | SOCKS5 CONNECT / Port Forward --> Open stream
       v
[STREAM_ESTABLISHED]
       |
       | Bidirectional Data Transfer (AEAD Framed)
       |---> Local/Remote EOF --> Send CMD_TERMINATE --> Close stream
       |---> Transport Timeout --> [RECONNECT]
       v
[STREAM_CLOSED]
```

---

## 6. Backward Compatibility & Migration Strategy

1. **Side-by-Side Coexistence:**
   - Paqet-NG introduces a configurable protocol version (`version: 2`) and transport selector (`transport.type: "raw-hardened" | "aead-stream" | "kcp"`).
   - If `transport.type: "kcp"` is configured, the legacy wire protocol (Version 1) is used, ensuring 100% backward compatibility with existing configurations.
2. **Version Negotiation:**
   - Server inspects initial message framing. If header begins with `MAGIC(0x50), VERSION(0x01)`, it routes to legacy handler; if `VERSION(0x02)` or AEAD-2022 header, it routes to Paqet-NG handler.
