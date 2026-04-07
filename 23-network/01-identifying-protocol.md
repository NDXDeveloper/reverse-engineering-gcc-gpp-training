🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 23.1 — Identifying the custom protocol with `strace` + Wireshark

> 🎯 **Objective of this section**: before even opening a disassembler, obtain a first mapping of the network protocol by observing traffic in real time. By the end of this section, you will have identified the port used, the sequence of exchanges, message sizes, and spotted the first recurring patterns (magic bytes, fixed headers).

---

## Why start with observation

When you receive two binaries — a client and a server — the natural reflex is to open Ghidra immediately. This is a strategic mistake. Disassembling a network parser without context is thankless work: you end up facing dozens of `recv()` calls and byte comparisons without knowing what you're looking for.

The opposite approach is far more productive: **launch both binaries, observe what happens on the network and in the system calls, then only afterwards open the disassembler with hypotheses to verify.** It's the difference between exploring a maze blindly and entering it with a rough map.

This observation phase relies on two complementary tools:

- **`strace`** observes the program **from the inside**: which system calls it makes, in what order, with what arguments and what data.  
- **Wireshark** observes the traffic **from the outside**: what actually transits on the network, byte by byte, with the timing of each packet.

Cross-referencing both views gives a rapid understanding of the protocol before any static analysis.

---

## Phase 1 — Quick triage of both binaries

Before launching anything, we apply the triage workflow from Chapter 5 to both binaries. This takes two minutes and already yields valuable information.

### `file` — binary characteristics

```bash
$ file server
server: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped  

$ file client
client: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped  
```

We confirm: two 64-bit ELFs, dynamically linked, PIE enabled. The fact that they are `not stripped` (in the `-O0 -g` variant) will make analysis easier. In real-world conditions, we always start with the easiest variant before tackling stripped versions.

### `strings` — textual clues

```bash
$ strings server | grep -iE "port|listen|bind|auth|error|welcome|password|key|secret"
```

Character strings often reveal the protocol's vocabulary: error messages, command names, authentication prompts. We look in particular for:

- **Error messages** like `"Invalid command"`, `"Auth failed"`, `"Bad magic"` — they betray the parser's validation logic.  
- **Hardcoded port numbers** in format strings (`"Listening on port %d"`).  
- **Command names** in cleartext (`"HELLO"`, `"AUTH"`, `"DATA"`, `"QUIT"`) if the protocol uses textual or mixed commands.  
- **Welcome strings** or handshake messages (`"Welcome"`, `"Server ready"`).

We do the same on the client side:

```bash
$ strings client | grep -iE "connect|send|recv|server|auth|login|user|pass"
```

> 💡 **Tip**: `strings -t x` displays the hexadecimal offset of each string. Note the interesting offsets: they will be valuable entry points in Ghidra via cross-references (Chapter 8, Section 8.7).

### `checksec` — active protections

```bash
$ checksec --file=server
$ checksec --file=client
```

We note the protections (PIE, RELRO, canary, NX) to anticipate the constraints of dynamic analysis. For this chapter, the main interest is checking whether PIE is enabled — which will affect breakpoint addresses in GDB later.

### `ldd` — dependencies

```bash
$ ldd server
$ ldd client
```

We look for particular network or crypto libraries. A dependency on `libssl` or `libcrypto` would indicate TLS encryption, which would considerably complicate network capture. A dependency on `libz` could indicate compression. For our training binary, we expect to see only libc — the protocol is implemented directly with POSIX sockets.

---

## Phase 2 — Network capture with `strace`

### Launching the server under `strace`

We start the server while tracing network-related and I/O system calls:

```bash
$ strace -f -e trace=network,read,write -x -s 256 -o server_trace.log ./server
```

Let's break down the options:

- **`-f`**: follows child processes. Essential if the server uses `fork()` to handle connections (classic concurrent server model).  
- **`-e trace=network,read,write`**: filters only network system calls (`socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `shutdown`, `close`...) and read/write operations (`read`, `write`, often used instead of `send`/`recv` on TCP sockets).  
- **`-x`**: displays binary data in hexadecimal rather than escaped ASCII. Crucial for a binary protocol.  
- **`-s 256`**: increases the maximum displayed string size (default: 32). For network packets, 256 is a good compromise; increase to 1024 if messages are long.  
- **`-o server_trace.log`**: redirects output to a file for later analysis.

### Launching the client under `strace`

In a second terminal:

```bash
$ strace -f -e trace=network,read,write -x -s 256 -o client_trace.log ./client 127.0.0.1
```

The client connects to the server and performs its complete sequence (handshake, authentication, commands). Once finished, we have two complete trace files.

### Reading the server trace

Here is an annotated example of what we might observe in `server_trace.log`:

```
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3  
setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0  
bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0  
listen(3, 5)                            = 0  
accept(3, {sa_family=AF_INET, sin_port=htons(54321), sin_addr=inet_addr("127.0.0.1")}, [16]) = 4  
```

These first five lines are the classic TCP server sequence. We immediately extract:

- **The listening port**: `4444` (visible in the `bind`).  
- **The transport protocol**: TCP (`SOCK_STREAM`).  
- **The connection model**: the server performs an `accept`, so it's a single-connection or concurrent server (check for the presence of `fork` next).

The next part is the interesting section — the data exchanges:

```
recv(4, "\xc0\x01\x00\x08", 4, 0)                             = 4  
recv(4, "HELLO\x00\x00\x00", 8, 0)                            = 8  
send(4, "\xc0\x81\x00\x0f", 4, 0)                             = 4  
send(4, "WELCOME\xa3\x7b\x01\xf9\x8c\x22\xd4\x5e", 15, 0)   = 15  
recv(4, "\xc0\x02\x00\x12", 4, 0)                             = 4  
recv(4, "\x05admin\x0b\xd0\x48\x62\x8c\xfe\x11\x84\x1e\xd0\x08\x20", 18, 0) = 18  
send(4, "\xc0\x82\x00\x02", 4, 0)                             = 4  
send(4, "\x00\x01", 2, 0)                                      = 2  
```

The first pattern that jumps out: **each exchange begins with a `recv` (or `send`) of exactly 4 bytes**, followed by a second call whose size varies. The server thus reads a **fixed 4-byte header**, then a **variable-length payload** determined by the header. This is the classic pattern of a TLV (Type-Length-Value) protocol.

Examining the 4-byte headers, we see:

- The first byte is always **`\xc0`** — this is probably the **magic byte**.  
- The second byte varies: `\x01`, `\x81`, `\x02`, `\x82` — the `\x8x` values seem to be responses (bit 7 set to 1 = response?).  
- Bytes 3–4 (`\x00\x08`, `\x00\x0f`, `\x00\x12`, `\x00\x02`) look like a **length field** in big-endian. Let's verify: `\x00\x08` = 8, and the following `recv` reads exactly 8 bytes. `\x00\x0f` = 15, and the following `send` sends 15 bytes. The match is perfect.  
- The payloads contain readable strings (`HELLO`, `WELCOME`, `admin`) interspersed with opaque binary data.

> 📝 **Note**: at this stage, these are only **hypotheses**. We will carefully note them to confirm or invalidate them during disassembly (Section 23.2).

### Reading the client trace

The client trace shows the same exchange seen from the other side. The interest is to **correlate the client's `write` calls with the server's `read` calls** (and vice versa) to verify that there is no fragmentation or buffering that would shift the data.

```
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3  
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16) = 0  
send(3, "\xc0\x01\x00\x08", 4, 0)                             = 4  
send(3, "HELLO\x00\x00\x00", 8, 0)                            = 8  
recv(3, "\xc0\x81\x00\x0f", 4, 0)                             = 4  
recv(3, "WELCOME\xa3\x7b\x01\xf9\x8c\x22\xd4\x5e", 15, 0)   = 15  
send(3, "\xc0\x02\x00\x12", 4, 0)                             = 4  
send(3, "\x05admin\x0b\xd0\x48\x62\x8c\xfe\x11\x84\x1e\xd0\x08\x20", 18, 0) = 18  
recv(3, "\xc0\x82\x00\x02", 4, 0)                             = 4  
recv(3, "\x00\x01", 2, 0)                                      = 2  
```

We find the same header/payload pattern. The correspondence with the server trace is direct: the client's `send` of 4+8 bytes corresponds to the server's two `recv` calls of 4 then 8 bytes. We confirm that the protocol is **synchronous request/response**: the client sends a message, waits for the response, then sends the next message.

### Extracting an exchange diagram

From both traces, we can already construct a protocol exchange diagram:

```
Client                          Server
  |                                |
  |--- [C0 01 ...] HELLO --------->|     Handshake request
  |<-- [C0 81 ...] WELCOME --------|     Handshake response
  |                                |
  |--- [C0 02 ...] AUTH ---------->|     Authentication request
  |<-- [C0 82 ...] OK -------------|     Authentication response
  |                                |
  |--- [C0 03 ...] CMD ----------->|     Command request
  |<-- [C0 83 ...] DATA -----------|     Command response
  |                                |
  |--- [C0 04 ...] QUIT ---------->|     Disconnect
  |<-- [C0 84 ...] BYE ------------|     Disconnect ack
  |                                |
```

This diagram, however approximate, will be an invaluable guide for disassembly.

---

## Phase 3 — Network capture with Wireshark

### Capturing on the loopback interface

Since the client and server run on the same machine, the traffic goes through the **loopback** interface (`lo`). We launch Wireshark (or `tcpdump`) on this interface:

```bash
# With tcpdump (raw capture for later analysis in Wireshark):
$ sudo tcpdump -i lo -w ch23_capture.pcap port 4444

# Or directly in Wireshark:
# Menu Capture → choose the "Loopback: lo" interface → capture filter: "port 4444"
```

We then relaunch the client to generate traffic, then stop the capture.

### First reading in Wireshark

Upon opening the capture, we see the classic TCP sequence:

1. **Three-way handshake**: `SYN` → `SYN-ACK` → `ACK` (Wireshark displays them in grey/black).  
2. **Data exchanges**: the `PSH-ACK` packets contain the application data — this is what interests us.  
3. **Teardown**: `FIN-ACK` → `FIN-ACK` → `ACK`.

We apply a display filter to keep only the application data:

```
tcp.port == 4444 && tcp.len > 0
```

### Identifying patterns in the payload

By clicking on each `PSH-ACK` packet, Wireshark's lower panel displays the hexadecimal payload. We find the same bytes as in the `strace` trace — which is reassuring and confirms that there is no intermediate layer (TLS, compression) between the application and the network.

The advantages of Wireshark over `strace` for this phase:

- **Temporal view**: the `Time` column shows the delay between each packet. A significant delay between the authentication request and the response could indicate expensive server-side processing (password hashing, file access...).  
- **Flow view**: the menu `Analyze → Follow → TCP Stream` reconstructs the entire conversation continuously, alternating client data (in red) and server data (in blue). This is the most readable view for understanding the protocol at a glance.  
- **Statistics**: the menu `Statistics → Conversations` gives the total number of bytes exchanged in each direction, and `Statistics → I/O Graphs` shows the temporal traffic profile.  
- **Automatic detection**: if the protocol resembles a known protocol (HTTP, DNS, TLS...), Wireshark will automatically decode it. The absence of decoding confirms that we are indeed dealing with a custom protocol.

### Follow TCP Stream — the view that summarizes everything

The `Follow TCP Stream` feature is particularly useful. By switching the display to **"Hex Dump"**, we get the complete conversation with the client/server alternation clearly marked:

```
→ 00000000  c0 01 00 08 48 45 4c 4c  4f 00 00 00             ....HELL O...
← 00000000  c0 81 00 0f 57 45 4c 43  4f 4d 45 a3 7b 01 f9 8c ....WELC OME.{...
← 00000010  22 d4 5e                                          ".^
→ 0000000C  c0 02 00 12 05 61 64 6d  69 6e 0b d0 48 62 8c fe .....adm in..Hb..
→ 0000001C  11 84 1e d0 08 20                                 ..... 
← 00000013  c0 82 00 02 00 01                                 ......
```

The `→` arrows indicate data sent by the client, `←` those sent by the server. We note that the username `"admin"` is visible in cleartext in the AUTH payload, but the password that follows (after byte `\x0b`) is a sequence of opaque bytes — a clue that the password undergoes a transformation before being sent. This view is ideal for visually spotting packet structures.

> 💡 **Tip**: you can save this raw stream from Wireshark (`Show data as: Raw`, then `Save as...`) to then open it in ImHex and apply a `.hexpat` pattern to it (Section 23.3).

---

## Phase 4 — Synthesis of observations

### Building a hypothesis table

At this stage, without having opened a single disassembler, we can formulate a set of structured hypotheses about the protocol:

**Header structure (4 bytes) — hypothesis:**

| Offset | Size | Hypothesis | Observed values |  
|--------|------|------------|-----------------|  
| 0 | 1 byte | Magic byte | Always `0xC0` |  
| 1 | 1 byte | Command type | `0x01`=HELLO, `0x02`=AUTH, `0x03`=CMD, `0x04`=QUIT |  
| 2–3 | 2 bytes | Payload length (big-endian) | Consistent with observed sizes |

**Message types — hypothesis:**

| Type | Direction | Assumed name | Observed payload |  
|------|-----------|--------------|------------------|  
| `0x01` | Client → Server | Handshake request | String `"HELLO"` + padding |  
| `0x81` | Server → Client | Handshake response | String `"WELCOME"` + 8 bytes (challenge?) |  
| `0x02` | Client → Server | Auth request | Length + username + length + password |  
| `0x82` | Server → Client | Auth response | 2 bytes (status code?) |  
| `0x03` | Client → Server | Command request | To be determined |  
| `0x83` | Server → Client | Command response | To be determined |  
| `0x04` | Client → Server | Disconnect | Empty or minimal payload |  
| `0x84` | Server → Client | Disconnect ack | Empty or minimal payload |

**Additional observations:**

- Bit 7 of the type field appears to distinguish requests (`0x0_`) from responses (`0x8_`). This is a common pattern in binary protocols (found in RADIUS, ASN.1 BER, and others).  
- The authentication payload contains the string `"admin"` in cleartext (readable in the strace output), preceded by byte `\x05` (5 — the length of `"admin"`). This suggests a **length-prefixed strings** format: a length byte followed by the string. The rest of the AUTH payload consists of opaque binary bytes — probably the password, but in a transformed form (encrypted? hashed? XOR'd?). No cleartext password is visible.  
- The 8 bytes after `"WELCOME"` in the handshake response could be a **challenge** or a **nonce** used in authentication — which would explain why the password is not readable. We will need to check whether these bytes change from one session to another.

### Verifying challenge variability

To test the challenge/nonce hypothesis, we relaunch the client several times and compare the handshake responses:

```bash
# Relaunch 3 times, capturing each time
for i in 1 2 3; do
    strace -e trace=read -x -s 256 ./client 127.0.0.1 2>&1 | grep "WELCOME"
done
```

If the 8 bytes after `"WELCOME"` change with each connection, it is indeed a nonce or challenge. If they are identical, it is a fixed value (session identifier, protocol version, or simply padding). This distinction matters: a variable challenge means that authentication is not a simple cleartext password submission, and that a naive replay of the authentication sequence could fail.

---

## Phase 5 — Preparing for what comes next

The observations from this section produced three concrete deliverables:

1. **The `strace` trace files** (`server_trace.log`, `client_trace.log`) — they will serve as reference throughout the analysis.  
2. **The Wireshark capture** (`ch23_capture.pcap`) — it will be reopened in the following sections to validate hypotheses and, in Section 23.3, exported as raw for analysis in ImHex.  
3. **The hypothesis table** on the protocol structure — this is the map with which we will enter the disassembler in Section 23.2.

The next step is to open the server binary in Ghidra and locate the packet parser to confirm (or invalidate) each of these hypotheses. We now know exactly what to look for: a function that reads 4 header bytes, checks the magic byte `0xC0`, extracts the type and length, then dispatches based on type. This is a much more precise entry point than "disassemble the binary and see what happens".

---

## Common pitfalls

### TCP fragmentation

TCP is a stream protocol, not a message protocol. There is no guarantee that a 22-byte `send()` on the client side arrives as a single 22-byte `recv()` on the server side. The kernel may fragment or coalesce the data. In practice, on `localhost` with small messages, fragmentation is rare. But in real-world conditions (slow network, large packets), a single application message may arrive in multiple `recv()` calls. You need to be aware of this when reading traces: if a `read()` returns fewer bytes than expected, it's not a protocol bug, it's TCP doing its job.

### `send`/`recv` vs `read`/`write`

On a TCP socket under Linux, `read()` and `recv()` (without flags) are functionally identical, as are `write()` and `send()`. Don't be surprised to see one or the other in `strace` traces — it's a choice made by the program's author, not a behavioral difference. The `strace` filter `-e trace=network,read,write` covers both cases.

### Encrypted or compressed protocol

If the payload in Wireshark is totally opaque (high entropy, no readable strings, no visible patterns), the protocol likely uses encryption or compression. In this case, `strace` remains useful (data is encrypted *before* `send()` and decrypted *after* `recv()`, so you can potentially intercept cleartext data by setting breakpoints on encryption functions). But the network capture alone will not suffice.

For our training binary, the protocol is in cleartext — the strings `"HELLO"`, `"WELCOME"`, `"admin"` are directly visible. In real-world conditions, this is not always the case.

### Multi-process or multi-threaded servers

If the server uses `fork()` for each connection, the `-f` flag of `strace` is essential: without it, you only see the parent process (which only does `accept`) and miss all the connection handling in the child process. If the server uses threads, `-f` follows them as well (threads are LWPs under Linux). The trace will indicate the PID/TID of each call, which allows distinguishing the flows.

---

## Section summary

| Step | Tool | What we obtain |  
|------|------|----------------|  
| Binary triage | `file`, `strings`, `checksec`, `ldd` | Binary characteristics, textual clues, protections, dependencies |  
| Server-side system trace | `strace -f -e trace=network,read,write` | Call sequence, hex buffers, message sizes |  
| Client-side system trace | `strace` (same options) | Mirror view, exchange correlation |  
| Network capture | Wireshark / `tcpdump` on loopback | Raw packets, timing, Follow TCP Stream |  
| Synthesis | Manual analysis | Hypothesis table: magic byte, types, lengths, sequence |

At the end of this phase, we have a **macroscopic understanding of the protocol**: how many messages are exchanged, in what order, what their approximate size is, and what structural patterns can be identified. The next section (**23.2**) will dive into disassembly to precisely reconstruct the packet parser's state machine.

⏭️ [RE of the packet parser (state machine, fields, magic bytes)](/23-network/02-re-packet-parser.md)
