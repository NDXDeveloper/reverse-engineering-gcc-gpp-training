🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 28.3 — RE of the Custom C2 Protocol (Commands, Encoding, Handshake)

> 📍 **Objective** — Consolidate all observations from sections 28.1 and 28.2 into a **formal and complete protocol specification**. By the end of this section, you will have a reference document sufficient to write a compatible client or server — which is precisely the goal of this chapter's checkpoint.

---

## From observation to specification

Up to this point, our approach has been **bottom-up**: we captured bytes on the network (`strace`, Wireshark), then observed their interpretation within the process (Frida). We accumulated isolated facts — a magic byte here, a XOR there, a handshake followed by an ACK.

This section shifts perspective. We switch to **top-down** mode: we gather all facts, organize them, fill in the gaps with static disassembly (Ghidra), and produce a coherent specification document. This is exactly the work of a malware analyst writing the "Protocol Analysis" section of a technical report.

The methodology follows five steps:

1. **Formalize the frame format** — Header structure, field encoding, size constraints.  
2. **Document the handshake** — Initial exchange sequence, content of each message.  
3. **Catalog the commands** — For each message type, document the body format, encoding, and expected behavior.  
4. **Reconstruct the state machine** — Which transitions are valid? What happens on error?  
5. **Verify through disassembly** — Confirm in Ghidra that the specification is complete and no hidden command has escaped dynamic analysis.

---

## Step 1 — Frame format

### Protocol header

Every protocol message begins with a fixed **4-byte** header:

```
 Byte 0       Byte 1       Bytes 2–3
┌────────────┬────────────┬────────────────────────┐
│   magic    │    type    │     body_length        │
│   (0xDE)   │   (uint8)  │ (uint16, little-endian)│
└────────────┴────────────┴────────────────────────┘
```

| Field | Offset | Size | Type | Description |  
|---|---|---|---|---|  
| `magic` | 0 | 1 byte | `uint8` | Constant `0xDE`. Used to validate that a byte stream belongs to this protocol. If the received byte is not `0xDE`, the message is rejected. |  
| `type` | 1 | 1 byte | `uint8` | Message type identifier. The range `0x01–0x0F` is reserved for server → client commands; the range `0x10–0x1F` for client → server responses. |  
| `body_length` | 2 | 2 bytes | `uint16` | Body size in bytes, encoded in **little-endian** (least significant byte first). Maximum observed value: 4096 (`0x1000`). A message with no body has `body_length = 0`. |

The body immediately follows the header, for a total message size of `4 + body_length` bytes.

### Observations about the format

**No checksum, no sequence number.** The protocol relies entirely on TCP for reliability and ordering. This is a common choice in simple C2 protocols: reduce complexity (and detection surface) by delegating these aspects to the transport layer.

**No end-of-message delimiter.** The explicit length in the header makes delimiters unnecessary. The receiver first reads 4 bytes (the header), extracts `body_length`, then reads exactly that many additional bytes. This is a *length-prefixed* protocol, as opposed to *delimiter-based* protocols like HTTP/1.1 (which uses `\r\n\r\n`).

**Little-endian for `body_length`.** This is the native endianness of x86-64. The dropper's code uses `memcpy` directly to write and read this field, without `htons`/`ntohs` conversion. This is a detail that's immediately visible in the disassembly: the absence of endianness conversion function calls on this field (whereas `sin_port` in `sockaddr_in` does use `htons`).

---

## Step 2 — The handshake

### Sequence diagram

The handshake occurs immediately after TCP connection establishment. It's a simple two-message exchange:

```
     Dropper                                C2 Server
        │                                      │
        │──── TCP SYN ────────────────────────►│
        │◄─── TCP SYN-ACK ───────────────────  │
        │──── TCP ACK ────────────────────────►│
        │                                      │
        │   ┌─────────────────────────────┐    │
        │   │ MSG_HANDSHAKE (0x10)        │    │
        │──►│ body: hostname\0 PID\0 ver\0│───►│
        │   └─────────────────────────────┘    │
        │                                      │
        │   ┌─────────────────────────────┐    │
        │   │ MSG_ACK (0x13)              │    │
        │◄──│ body: (optional)            │◄───│
        │   └─────────────────────────────┘    │
        │                                      │
        │   ══ Session established ══          │
        │   The dropper enters the             │
        │   command loop (command_loop)        │
```

### MSG_HANDSHAKE (0x10) — Client → Server

The first message is **always** a `MSG_HANDSHAKE`. The body contains three concatenated null-terminated ASCII strings:

```
┌───────────────────┬───┬──────────────┬───┬─────────────────┬───┐
│    hostname       │\0 │   pid_str    │\0 │    version      │\0 │
│  (variable len)   │   │ (ASCII dec.) │   │ (e.g. "DRP-1.0")│   │
└───────────────────┴───┴──────────────┴───┴─────────────────┴───┘
```

| Field | Format | Example | Source |  
|---|---|---|---|  
| `hostname` | Null-terminated ASCII string | `"analysis-vm"` | `gethostname()` |  
| `pid_str` | PID as decimal ASCII, null-terminated | `"1287"` | `getpid()` converted by `snprintf` |  
| `version` | Version identifier, null-terminated | `"DRP-1.0"` | Hardcoded constant `DROPPER_VERSION` |

**body_length** = `strlen(hostname) + 1 + strlen(pid_str) + 1 + strlen(version) + 1`

> 💡 **RE note** — The choice of null-terminated strings rather than a TLV (Type-Length-Value) format makes parsing trivial in C (`strchr` or simple iteration), but fragile: a hostname containing a null byte would break the protocol. This kind of fragility is typical of hastily written C2 protocols — and can be a disruption vector (sending a malformed hostname to crash the attacker's C2 server).

### MSG_ACK (0x13) — Server → Client

The server responds with a `MSG_ACK`. The body is **optional** — it can contain a text message (e.g., `"welcome"`) or be empty (`body_length = 0`). The dropper doesn't check the ACK body content, only the type (`0x13`).

**If the server doesn't respond** — The dropper remains blocked on `recv_all()` indefinitely. There is no application-level timeout (no `SO_RCVTIMEO` set on the socket). Only a TCP disconnection will cause an error return.

**If the server responds with a type ≠ 0x13** — The dropper considers the handshake failed, closes the socket, and attempts a reconnection.

---

## Step 3 — Command catalog

### Overview

The protocol defines two categories of messages:

**Server → Client commands (range `0x01–0x0F`):**

| Type | Name | Body | XOR encoding | Expected response |  
|---|---|---|---|---|  
| `0x01` | `CMD_PING` | Empty | No | `MSG_PONG` (0x11) |  
| `0x02` | `CMD_EXEC` | Shell command | **Yes** | `MSG_RESULT` (0x12) |  
| `0x03` | `CMD_DROP` | File to drop | **Yes** | `MSG_ACK` (0x13) |  
| `0x04` | `CMD_SLEEP` | Interval (uint32) | No | `MSG_ACK` (0x13) |  
| `0x05` | `CMD_EXIT` | Empty | No | `MSG_ACK` (0x13) |

**Client → Server responses (range `0x10–0x1F`):**

| Type | Name | Body | XOR encoding | Sent in response to |  
|---|---|---|---|---|  
| `0x10` | `MSG_HANDSHAKE` | Identification | No | (initiative) |  
| `0x11` | `MSG_PONG` | Empty | No | `CMD_PING` |  
| `0x12` | `MSG_RESULT` | Command output | **Yes** | `CMD_EXEC` |  
| `0x13` | `MSG_ACK` | Optional text | No | `CMD_DROP`, `CMD_SLEEP`, `CMD_EXIT` |  
| `0x14` | `MSG_ERROR` | Error message | No | Any failed command |  
| `0x15` | `MSG_BEACON` | Counter + timestamp | No | (periodic, initiative) |

### CMD_PING (0x01) — Keepalive

The simplest message in the protocol. The header alone suffices, the body is empty (`body_length = 0`).

```
Server → Client:  DE 01 00 00  
Client → Server:  DE 11 00 00     (MSG_PONG)  
```

The PING serves as a *heartbeat* from the server. It verifies that the dropper is still alive and that the TCP connection is functional. The dropper responds immediately with a PONG, which is also bodyless.

### CMD_EXEC (0x02) — Shell command execution

This is the most dangerous command in the protocol: it allows arbitrary command execution on the infected machine.

**Body format (server → client):**

```
┌───────────────────────────────────────┐
│  shell command (XOR-encoded, 0x5A)    │
│  NOT null-terminated                  │
│  length = body_length                 │
└───────────────────────────────────────┘
```

The body contains the shell command encoded byte-by-byte with XOR key `0x5A`. The size is given by `body_length` in the header — there is no null terminator in the encoded body (the dropper adds the `\0` after decoding).

**Example** — To send the command `id` (2 bytes):

```
Plaintext:  69 64          ("id")  
XOR 0x5A:   33 3E          (0x69⊕0x5A=0x33, 0x64⊕0x5A=0x3E)  

Complete message:  DE 02 02 00 33 3E
                   ── ── ───── ─────
                   │  │    │     └─ XOR-encoded body
                   │  │    └─ body_length = 2 (LE)
                   │  └─ type = CMD_EXEC
                   └─ magic
```

**MSG_RESULT (0x12) response format:**

```
┌───────────────────────────────────────┐
│  command output                       │
│  (XOR-encoded, 0x5A)                  │
│  length = body_length                 │
└───────────────────────────────────────┘
```

The result (stdout from the command executed via `popen`) is also XOR-encoded before sending. The maximum size is limited to `MAX_BODY_SIZE` (4096 bytes); any longer output is truncated.

**On error** (nonexistent command, `popen` fails), the dropper sends a `MSG_ERROR` (0x14) with a plaintext error string (not XOR-encoded): `"exec_failed"`.

### CMD_DROP (0x03) — File drop and execution

This command allows the C2 to drop a file on the target system and execute it. This is the dropper's *staging* mechanism — the malware's reason for existing.

**Body format (server → client, XOR-encoded):**

After XOR decoding, the body has the following structure:

```
┌──────────────┬──────────────────────┬──────────────────────────┐
│ fname_len(1) │   filename           │      payload_data        │
│   uint8      │ (fname_len bytes)    │ (body_len-1-fname_len)   │
│              │ NOT null-terminated  │                          │
└──────────────┴──────────────────────┴──────────────────────────┘
```

| Field | Offset (after XOR) | Size | Description |  
|---|---|---|---|  
| `fname_len` | 0 | 1 byte | Filename length |  
| `filename` | 1 | `fname_len` bytes | Filename (without path) |  
| `payload_data` | `1 + fname_len` | remainder | Raw file content to write |

The dropper:
1. Decodes the entire body with XOR `0x5A`.  
2. Extracts the filename.  
3. Writes `payload_data` to `/tmp/<filename>`.  
4. Applies `chmod 0755` to the dropped file.  
5. Executes the file via `system()`.  
6. Sends back a `MSG_ACK` with body `"drop_ok:<exit_code>"`.

**Example** — Dropping a script named `test.sh` containing `#!/bin/sh\necho hello\n`:

```
Plaintext data (before XOR):
  07                              ← fname_len = 7
  74 65 73 74 2e 73 68            ← "test.sh"
  23 21 2f 62 69 6e 2f 73 68 0a  ← "#!/bin/sh\n"
  65 63 68 6f 20 68 65 6c 6c 6f  ← "echo hello"
  0a                              ← "\n"

After XOR 0x5A on the whole body:
  5d 2e 3f 29 2e 74 29 32 79 7b 75 ...
```

**Validations** — The dropper checks that `body_length ≥ 2` and that `fname_len + 1 < body_length`. If these conditions are not met, it sends `MSG_ERROR` with `"too_short"` or `"bad_fname"`. On write failure, it sends `"write_fail"`.

> ⚠️ **Security note** — The filename is **not** sanitized. A path injection (`../../../etc/cron.d/backdoor`) is theoretically possible. In real malware, this would be intentional; in our educational sample, this realistic behavior is deliberately preserved for the analysis exercise.

### CMD_SLEEP (0x04) — Modify beacon interval

Allows the C2 to adjust the dropper's beacon frequency, typically to reduce network noise once the implant is installed.

**Body format (no XOR):**

```
┌──────────────────────────────────────┐
│  new_interval (uint32, little-endian)│
│  in seconds                          │
└──────────────────────────────────────┘
```

The dropper clamps the value between 1 and 3600 seconds. Any value outside this range is silently clamped (no error).

```
Example: interval = 30 seconds
  DE 04 04 00    1E 00 00 00
  ── ── ─────    ───────────
  │  │    │         └─ 30 as uint32 LE
  │  │    └─ body_length = 4
  │  └─ CMD_SLEEP
  └─ magic
```

Response: `MSG_ACK` with body `"sleep_ok"`.

### CMD_EXIT (0x05) — Termination

Orders the dropper to terminate cleanly.

```
Server → Client:  DE 05 00 00  
Client → Server:  DE 13 03 00 62 79 65     (MSG_ACK, body="bye")  
```

After sending the ACK, the dropper sets `state.running = 0`, exits the `command_loop`, closes the socket, and terminates with `return 0` from `main`. No reconnection attempt.

### MSG_BEACON (0x15) — Periodic heartbeat (client → server)

The dropper sends a beacon at regular intervals when it hasn't received a command for `beacon_interval` seconds. The beacon is **client-initiated** (sent without solicitation) and doesn't expect a response.

**Body format (no XOR):**

```
┌───────────────────────┬────────────────────────┐
│  cmd_count (uint32 LE)│  timestamp (uint32 LE) │
│  commands processed   │  Unix epoch (sec)      │
└───────────────────────┴────────────────────────┘
```

The `cmd_count` lets the C2 track the dropper's activity. The `timestamp` confirms the dropper is alive and gives the infected machine's local time.

```
Example: 5 commands processed, timestamp 1714500000
  DE 15 08 00    05 00 00 00    A0 3E 33 66
  ── ── ─────    ───────────    ───────────
  │  │    │         │               └─ timestamp (LE)
  │  │    │         └─ cmd_count = 5 (LE)
  │  │    └─ body_length = 8
  │  └─ MSG_BEACON
  └─ magic
```

---

## Step 4 — XOR encoding

### Encoding scope

XOR encoding is **not** uniformly applied to all messages. It only affects the bodies of commands whose content is "sensitive" — shell commands and dropped files:

| Message | Body XOR-encoded? |  
|---|---|  
| `MSG_HANDSHAKE` (0x10) | No — hostname and PID travel in plaintext |  
| `CMD_EXEC` (0x02) | **Yes** — the shell command is encoded |  
| `MSG_RESULT` (0x12) | **Yes** — the command output is encoded |  
| `CMD_DROP` (0x03) | **Yes** — filename and payload are encoded |  
| All others | No — ACK, PONG, BEACON, SLEEP, PING, EXIT travel in plaintext |

> 💡 **RE note** — This inconsistency is typical of real malware: encoding is added opportunistically on the "noisiest" channels (commands and results), but metadata (handshake, beacons) is left in plaintext. This is a boon for the analyst: plaintext beacons make detection via network signatures (IDS/IPS) easier.

### The XOR algorithm

The encoding is a **single-byte XOR** with the fixed key `0x5A`, applied to the entire body:

```
for each byte b[i] in the body:
    b[i] = b[i] ⊕ 0x5A
```

Since XOR is its own inverse, the same function serves for both encoding and decoding. There is no initialization vector, no counter, no block cipher. This is **obfuscation**, not encryption — an analyst with access to network traffic and knowledge of the key can instantly decode all content.

### Identifying the key in the disassembly

In Ghidra, the `xor_encode` function is recognizable by a characteristic pattern:

```
; XOR loop in xor_encode (Ghidra view, simplified syntax)
LOOP:
    movzx  eax, byte [rdi + rcx]     ; load current byte
    xor    eax, 0x5a                  ; XOR with the constant
    mov    byte [rdi + rcx], al       ; write back the byte
    inc    rcx                        ; increment counter
    cmp    rcx, rsi                   ; compare with length
    jb     LOOP                       ; loop if not done
```

Elements that reveal XOR encoding:

- **An `xor` instruction with an immediate constant** (`0x5A`) inside a loop. This is the strongest signal.  
- **A counter incremented by 1** at each iteration — processing byte by byte.  
- **The same buffer used for reading and writing** (`rdi` appears as both source and destination) — the operation is *in-place*.  
- **The constant `0x5A` appears in the `.rodata` section or as an immediate** — searchable via `Search > For Scalars` in Ghidra.

> 💡 **RE note** — In real-world scenarios, the XOR key could be derived dynamically (timestamp hash, registry key portion, etc.). Searching for `xor reg, imm8` inside a loop remains the most reliable detection pattern, regardless of the key's source.

---

## Step 5 — Dropper state machine

### State diagram

The dropper implements a simple state machine with four states:

```
                    ┌──────────────────────────────────┐
                    │                                  │
                    ▼                                  │
             ┌─────────────┐                           │
             │ DISCONNECTED│                           │
             └──────┬──────┘                           │
                    │ connect() succeeds               │
                    ▼                                  │
           ┌────────────────┐                          │
           │  HANDSHAKING   │                          │
           └───────┬────────┘                          │
                   │ Send HANDSHAKE                    │
                   │ Receive ACK                       │
                   ▼                                   │
           ┌────────────────┐     timeout              │
           │    COMMAND     │────────────┐             │
           │     LOOP       │            │             │
           └───┬──────┬─────┘            │             │
               │      │                  │             │
     CMD recv  │      │ CMD_EXIT         ▼             │
               │      │           ┌────────────┐       │
               ▼      │           │  BEACONING │       │
       ┌────────────┐ │           │  (send     │       │
       │  HANDLING  │ │           │   beacon)  │       │
       │  COMMAND   │ │           └─────┬──────┘       │
       └─────┬──────┘ │                 │              │
             │        │                 │ return to    │
             │ return │                 │ command_loop │
             │ to     │                 │              │
             │ loop   ▼                 │              │
             │   ┌──────────┐           │              │
             │   │TERMINATED│           │              │
             │   └──────────┘           │              │
             │                          │              │
             └──────────────────────────┘              │
                                                       │
              Network error / Handshake rejected       │
              ─────────────────────────────────────────┘
              (reconnect if retries < MAX_RETRIES)
```

### Detailed transitions

| Source state | Event | Action | Destination state |  
|---|---|---|---|  
| `DISCONNECTED` | `connect()` succeeds | — | `HANDSHAKING` |  
| `DISCONNECTED` | `connect()` fails | `sleep(BEACON_INTERVAL)`, `retries++` | `DISCONNECTED` (if `retries < MAX_RETRIES`) |  
| `DISCONNECTED` | `retries >= MAX_RETRIES` | — | `TERMINATED` |  
| `HANDSHAKING` | Send `MSG_HANDSHAKE` + receive `MSG_ACK` | `retries = 0` | `COMMAND_LOOP` |  
| `HANDSHAKING` | Receive type ≠ `MSG_ACK` | `close()`, `retries++` | `DISCONNECTED` |  
| `HANDSHAKING` | Network error | `close()`, `retries++` | `DISCONNECTED` |  
| `COMMAND_LOOP` | `select()` timeout | Send `MSG_BEACON` | `COMMAND_LOOP` |  
| `COMMAND_LOOP` | Receive `CMD_PING` | Send `MSG_PONG` | `COMMAND_LOOP` |  
| `COMMAND_LOOP` | Receive `CMD_EXEC` | XOR decode, `popen()`, send `MSG_RESULT` | `COMMAND_LOOP` |  
| `COMMAND_LOOP` | Receive `CMD_DROP` | XOR decode, write file, `system()`, send `MSG_ACK` | `COMMAND_LOOP` |  
| `COMMAND_LOOP` | Receive `CMD_SLEEP` | Update `beacon_interval`, send `MSG_ACK` | `COMMAND_LOOP` |  
| `COMMAND_LOOP` | Receive `CMD_EXIT` | Send `MSG_ACK("bye")`, `running = 0` | `TERMINATED` |  
| `COMMAND_LOOP` | Receive unknown type | Send `MSG_ERROR("unknown_cmd")` | `COMMAND_LOOP` |  
| `COMMAND_LOOP` | Network error | `close()` | `DISCONNECTED` |

### Timing

The command loop relies on `select()` with a timeout equal to `beacon_interval` (5 seconds by default). The dropper doesn't actively poll — it sleeps between commands, which is more stealthy than a pure blocking `recv` loop because the beacon keeps the connection alive even in the absence of commands.

---

## Step 6 — Verification in Ghidra

Dynamic analysis (sections 28.1 and 28.2) allowed us to reconstruct most of the protocol, but a risk remains: **untested commands could exist**. Dynamic analysis only covers paths that were actually taken. If the C2 never sends a certain command type during our tests, we won't see it.

To ensure completeness, we examine `dispatch_command` in Ghidra.

### Locating the dispatcher

Two complementary approaches:

**With symbols (`dropper_O0`)** — Search for `dispatch_command` in the Symbol Tree. Double-click to navigate to the function.

**Without symbols (`dropper_O2_strip`)** — Look for the `switch/case` pattern. In the disassembled code, a `switch` on `msg->header.type` typically compiles into a jump table or a cascade of `cmp` / `je`. You can locate this structure by looking for cross-references to the handlers — for example, find the string `"unknown_cmd"` (which survives stripping because it's in `.rodata`), trace back via XREF to the `switch`'s `default` branch, then examine the other branches.

### Reading the switch in the decompiler

Ghidra's decompiler produces pseudo-code like:

```c
int dispatch_command(dropper_state_t *state, proto_message_t *msg)
{
    state->cmd_count++;

    switch (msg->header.type) {
    case 1:     // CMD_PING
        return handle_ping(state);
    case 2:     // CMD_EXEC
        return handle_exec(state, msg->body, msg->header.length);
    case 3:     // CMD_DROP
        return handle_drop(state, msg->body, msg->header.length);
    case 4:     // CMD_SLEEP
        return handle_sleep(state, msg->body, msg->header.length);
    case 5:     // CMD_EXIT
        return handle_exit(state);
    default:
        return send_message(state->sockfd, 0x14, "unknown_cmd", 11);
    }
}
```

We verify that the `case` values correspond exactly to the documented types (`0x01` through `0x05`). If there were an unknown `case 6` or `case 7`, we would see it here. The absence of additional cases confirms that our command catalog is complete.

> 💡 **RE note** — In real malware, the dispatcher could contain "dormant" commands — implemented in the code but never invoked during the observation period. Static analysis is the only way to discover them. This is why the combination of static + dynamic analysis is fundamental.

### Verifying individual handlers

For each handler (`handle_exec`, `handle_drop`, etc.), we verify in Ghidra:

- **The expected body format** — Does it match our documentation?  
- **The validations performed** — Which conditions trigger a `MSG_ERROR`?  
- **The side effects** — Which files are written? Which system commands are executed?  
- **The error paths** — Can the handler crash? (e.g., buffer overflow if `body_length > MAX_BODY_SIZE` — verify the bound is correctly enforced.)

This systematic verification work transforms our "observed" specification into a "verified" specification.

---

## Protocol specification summary

### One-page summary

```
Protocol: Custom TCP, little-endian, length-prefixed  
Transport: TCP, port 4444  
Encoding:  Single-byte XOR (key 0x5A) on selected bodies  

Header (4 bytes):
  [0]     uint8   magic = 0xDE
  [1]     uint8   type
  [2..3]  uint16  body_length (little-endian)

Initialization sequence:
  Client → Server: MSG_HANDSHAKE (0x10)
  Server → Client: MSG_ACK (0x13)

Server → client commands:
  0x01  PING    body=∅           response=PONG(0x11)
  0x02  EXEC    body=cmd^XOR     response=RESULT(0x12, output^XOR)
  0x03  DROP    body=file^XOR    response=ACK(0x13, "drop_ok:N")
  0x04  SLEEP   body=uint32(sec) response=ACK(0x13, "sleep_ok")
  0x05  EXIT    body=∅           response=ACK(0x13, "bye")

Client → server messages (initiative):
  0x10  HANDSHAKE  body=hostname\0+pid\0+version\0  (at connection)
  0x15  BEACON     body=uint32(count)+uint32(timestamp)  (periodic)

Errors:
  0x14  ERROR   body=plaintext string (not XOR)

XOR value: 0x5A, applied byte-by-byte, in-place  
Scope:     bodies of EXEC(0x02), DROP(0x03), RESULT(0x12)  
```

### ImHex format (`.hexpat`)

For readers who wish to visualize captured frames in ImHex, the pattern `hexpat/ch23_protocol.hexpat` ([Chapter 23](/23-network/README.md) protocol) can serve as a starting point. The header structure is similar (magic + type + length), but values differ: magic `0xDE` instead of Chapter 23's, command types `0x01–0x05` / `0x10–0x15`, and XOR encoding on selected bodies. Adapting it into a dedicated `ch28_protocol.hexpat` makes a good complementary exercise.

---

## Correlation with IOCs

At this point, we can formalize the network indicators of compromise extracted from the analysis:

| IOC | Type | Value | Confidence |  
|---|---|---|---|  
| C2 address | IP | `127.0.0.1` | High (hardcoded) |  
| C2 port | TCP port | `4444` | High (hardcoded) |  
| Magic byte | Network signature | First byte of TCP payload = `0xDE` | High |  
| Beacon pattern | Network signature | `DE 15 08 00` followed by 8 bytes, every ~5s | High |  
| Handshake pattern | Network signature | `DE 10` followed by null-terminated strings containing `DRP-` | Medium (version may change) |  
| XOR key | Crypto parameter | `0x5A` | High (hardcoded) |

These IOCs allow writing detection rules (Snort, Suricata, network YARA) without even needing to understand the dropper's internal logic. A minimal Suricata rule could detect the beacon:

```
alert tcp any any -> any 4444 (msg:"Dropper beacon detected";
    content:"|DE 15 08 00|"; offset:0; depth:4;
    sid:1000001; rev:1;)
```

---

> **Up next** — In section 28.4, we put this specification into practice by writing a **complete fake C2 server** in Python. We'll send each command from the catalog to the dropper and observe its behavior in real time, definitively validating our understanding of the protocol.

⏭️ [Simulating a C2 server to observe complete behavior](/28-dropper/04-simulating-c2-server.md)
