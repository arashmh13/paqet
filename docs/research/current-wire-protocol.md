# Current Wire Protocol Specification & Reverse-Engineering Analysis

## 1. Protocol Overview & Layering Architecture

The current implementation of Paqet utilizes a multi-layered encapsulation pipeline designed to disguise tunneled traffic as regular TCP traffic:

```
+--------------------------------------------------------------------------+
| Layer 1: Physical / Data Link (Ethernet Frame)                           |
|   - Destination MAC (Gateway Router MAC, e.g. cc:46:d6:21:67:45)         |
|   - Source MAC (Host Interface MAC)                                      |
|   - EtherType (0x0800 IPv4 / 0x86DD IPv6)                                |
+--------------------------------------------------------------------------+
| Layer 2: Network (IPv4 / IPv6 Header)                                    |
|   - Protocol: 6 (TCP), TTL: 64, TOS/DSCP: 0, Flags: DF (Don't Fragment) |
|   - Source IP: Egress Host IP, Destination IP: Remote Peer IP            |
+--------------------------------------------------------------------------+
| Layer 3: Transport (Custom Synthetic TCP Segment)                        |
|   - Source Port: Dynamic/Configured, Destination Port: 8088              |
|   - TCP Flags: PSH, ACK (0x018) for data segments                        |
|   - Sequence Number: h.time + (counter << 7) [INCREMENTS BY +128]       |
|   - Acknowledgment Number: seq - (counter & 0x3FF) + 1400                |
|   - Window Size: 65535, Options: NOP, NOP, Timestamps (TSval, TSecr)     |
+--------------------------------------------------------------------------+
| Layer 4: Obfuscation Envelope (internal/obfs - AES-256-GCM)              |
|   - Nonce: 12 Bytes (crypto/rand)                                        |
|   - Ciphertext: [2B Plaintext Length] + [Payload] + [Random Padding]     |
|   - AEAD Tag: 16 Bytes (Poly1305 / GCM Tag)                              |
+--------------------------------------------------------------------------+
| Layer 5: Reliable Transport (KCP Protocol Frame - RFC-like)              |
|   - Conv (4B), Cmd (1B), Frg (1B), Wnd (2B), Ts (4B), Sn (4B), Una (4B)  |
|   - Length (4B), Optional Inner Block Encryption (aes-128-gcm)           |
+--------------------------------------------------------------------------+
| Layer 6: Stream Multiplexing (smux v2 Frame)                             |
|   - Version: 2, Cmd (SYN/FIN/PUSH/NOP), Length (2B), StreamID (4B)       |
+--------------------------------------------------------------------------+
| Layer 7: Application Protocol Framing (internal/protocol)                |
|   - MAGIC: 0x50 ('P'), VERSION: 0x01, TYPE: 1B, LENGTH: 2B (BigEndian)  |
|   - Type-specific Body (PTCP / PUDP / PTCPF / PPING)                     |
+--------------------------------------------------------------------------+
```

---

## 2. Low-Level Wire Framing & Packet Layouts

### 2.1 The Raw TCP Envelope

Data segments emitted on the wire adhere to standard TCP framing but carry synthetic, non-standard state:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|  0x8  |           |G|K|H|T|N|N|            65535              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  NOP (0x01)   |  NOP (0x01)   | Kind=8 (TS)   |  Length = 10  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     TS Value (Timestamp)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  TS Echo Reply (Timestamp)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|             Obfuscated Payload (Layer 4)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.2 Obfuscation Wire Layout (`internal/obfs`)

Every packet payload delivered to `socket.WriteTo` is formatted as follows:

```text
+-------------------+------------------------------------------+--------------------+
|  Nonce (12 Bytes) | Encrypted Plaintext + Padding (Variable) | AEAD Tag (16 Bytes)|
+-------------------+------------------------------------------+--------------------+
| Offset: 0..11     | Offset: 12 .. (12 + len(plain) - 1)      | Offset: N-16 .. N  |
+-------------------+------------------------------------------+--------------------+
```

The decrypted plaintext structure inside AES-256-GCM:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Payload Length (2 Bytes)    |  Payload Data (1..N bytes)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Cryptographically Random Padding (0..maxPad Bytes)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Payload Length:** BigEndian uint16, strictly defining the valid data bytes belonging to the inner KCP frame.
- **Random Padding:** Sized randomly between `0` and `min(maxPad, 1460 - Overhead - payloadLen)`. Filled with `crypto/rand` bytes.
- **Overhead:** `12 (Nonce) + 2 (Length) + 16 (Tag) = 30 Bytes` minimum per packet.

### 2.3 Application Protocol Frame (`internal/protocol`)

Once decrypted and stripped of KCP/smux headers, logical streams convey protocol messages with a fixed 5-byte header:

```text
+--------------+-----------------+---------------+-----------------------+
|  MAGIC (1B)  |   VERSION (1B)  |   TYPE (1B)   |   BODY LENGTH (2B)    |
|    0x50      |      0x01       |  0x01 .. 0x05 |  0x0000 .. 0x1000     |
+--------------+-----------------+---------------+-----------------------+
```

- **Header Offset 0 (MAGIC):** ASCII `'P'` (`0x50`).
- **Header Offset 1 (VERSION):** Protocol version `0x01`.
- **Header Offset 2 (TYPE):**
  - `0x01` (`PPING`): Zero-length body.
  - `0x02` (`PPONG`): Zero-length body.
  - `0x03` (`PTCPF`): Remote TCP flags sync. Body: `[1B count] + count * [2B bitmask]`.
  - `0x04` (`PTCP`): TCP target connection. Body: `[1B host_len] + [host ASCII] + [2B port BigEndian]`.
  - `0x05` (`PUDP`): UDP target datagram. Body: `[1B host_len] + [host ASCII] + [2B port BigEndian]`.
- **Header Offset 3-4 (BODY LENGTH):** uint16 BigEndian, capped at 4096 bytes.

---

## 3. Connection Setup & Handshake Sequence

The protocol attempts to mimic a normal TCP handshake before initiating KCP reliable streaming:

```text
 Client (Iran VPS)                                       Server (German VPS)
 185.18.215.124:51555                                        77.37.65.2:8088
       |                                                           |
       |  1. TCP SYN (len: 0, clientISN, opts: MSS, SACK, TS, WS)  |
       |---------------------------------------------------------->|
       |                                                           |
       |  2. TCP SYN-ACK (len: 0, serverISN, ack: clientISN+1)     |
       |<----------------------------------------------------------|
       |                                                           |
       |  3. TCP ACK (len: 0, ack: serverISN+1)                    |
       |---------------------------------------------------------->|
       |                                                           |
       |  === Middlebox conntrack state transitions to ESTABLISHED ===
       |                                                           |
       |  4. KCP Session Init: Data Packet 1 (Flags: PSH, ACK)     |
       |     Seq: synthetic (+128), Ack: synthetic, len: 147 bytes |
       |     [12B Nonce][AES-GCM (KCP Conv Init + Pad)][16B Tag]   |
       |---------------------------------------------------------->|
       |                                                           |
       |  5. KCP ACK / Response (Flags: PSH, ACK)                  |
       |     Seq: synthetic (+128), Ack: synthetic, len: 178 bytes |
       |<----------------------------------------------------------|
```

---

## 4. Empirical Protocol Defects & Fingerprints Discovered

Direct packet-level analysis over the live Iran VPS to German VPS link revealed four structural defects in the current protocol:

### Defect 1: The "+128 Sequence Number" Artifact
In `internal/socket/send_handle.go`:
```go
counter := h.tsCounter.Add(1)
seq := h.time + (counter << 7)
e.tcp.Seq = seq
```
Because `counter << 7` multiplies the packet index by 128, **every single packet transmitted by the client or server advances its TCP sequence number by exactly 128**, regardless of whether the packet payload is 95 bytes, 274 bytes, or 1400 bytes.
- When payload is > 128 bytes, consecutive packets overlap on the wire.
- When payload is < 128 bytes, gaps appear in the sequence space.
- A standard TCP window tracking engine (e.g. Linux `nf_conntrack` with `nf_conntrack_tcp_be_liberal=0` or Palo Alto Networks / Fortinet DPI firewalls) marks such traffic as corrupted and drops out-of-window packets.

### Defect 2: Inverted Timestamp Echo Reply (`TSecr` Countdown)
In `internal/socket/send_handle.go`:
```go
tsEcr := tsVal - (counter%200 + 50)
```
As `counter` increases by 1 on each packet, `tsEcr` decreases monotonically. RFC 7323 dictates that `TSecr` must reflect monotonically increasing timestamps sent by the peer. Middleboxes inspecting TCP timestamp validity flag decreasing `TSecr` as anomalous or spoofed.

### Defect 3: Lack of Replay Protection in Obfuscation Layer
In `internal/obfs/obfs.go`:
- Nonce is randomly generated per packet: `rand.Read(nonce)`.
- The receiver passes `nonce` directly into `cipher.AEAD.Open(ciphertext, nonce, ...)` without checking against a timestamp window, sliding bitmap, or replay cache.
- **Vulnerability:** An eavesdropper who captures an authentic obfuscated packet can replay it indefinitely. `aead.Open()` will succeed each time, forcing the CPU to decrypt and passing replayed frames into KCP.

### Defect 4: Unconditional SYN-ACK Generation (Active Probing Tarpit)
In `internal/socket/socket.go`:
```go
recvHandle.onHandshake = func(p *HandshakePacket) {
    if p.SYN && !p.ACK {
        serverISN := rand.Uint32()
        _ = sendHandle.WriteControl(p.Addr, conf.TCPF{SYN: true, ACK: true}, serverISN, p.Seq+1, true)
    }
}
```
- The server responds with `SYN-ACK` to **any** IP in the world that transmits a `SYN` packet to port 8088.
- However, if the client sends an HTTP GET, TLS ClientHello, or arbitrary data after the handshake, the server ignores it completely (`internal/obfs` silently drops any payload that does not authenticate with the pre-shared AES key).
- Result: An active scanner observes an open TCP port that completes a 3-way handshake and then becomes a 100% silent blackhole. This behavior uniquely identifies the server as an unauthorized proxy endpoint.
