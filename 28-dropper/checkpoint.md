🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 28

## Write a Fake C2 Server that Controls the Dropper

> **Target binary**: `dropper_O2_strip` (optimized, no symbols)  
> **Estimated time**: 2 to 3 hours  
> **Deliverables**: a Python script `fake_c2.py`, a capture `session.pcap`, a report `report_ch28.md`

---

## Problem statement

You are an analyst on an incident response team. A suspicious ELF binary named `dropper_O2_strip` was extracted from a compromised machine. The network team observed outbound TCP connections to `127.0.0.1:4444` (the address was modified by the SOC to point to localhost). No source code is available. No protocol documentation exists.

Your mission is to **take control of the dropper** by writing a fake C2 server capable of:

1. **Accepting the connection** from the dropper and completing the handshake.  
2. **Sending each of the 5 commands** of the protocol (PING, EXEC, DROP, SLEEP, EXIT) and correctly receiving the responses.  
3. **Decoding all exchanged data**, including data protected by XOR encoding.  
4. **Capturing the complete network session** in a pcap file.  
5. **Documenting your findings** in a structured analysis report.

> ⚠️ **Difficulty condition** — You must work on the **stripped** variant (`dropper_O2_strip`). Debug symbols are not available. The `_O0` and `_O2` variants can be used to aid understanding, but the final deliverable must work with the stripped binary.

---

## Validation criteria

### 1. The fake C2 works (`fake_c2.py`)

| Criterion | Required | Bonus |  
|---|---|---|  
| The handshake succeeds (the dropper doesn't disconnect) | ✅ | — |  
| `CMD_PING` → the dropper responds with `MSG_PONG` | ✅ | — |  
| `CMD_EXEC` → the command is executed, the decoded result is readable | ✅ | — |  
| `CMD_DROP` → a file is created in `/tmp/`, executed, ACK received | ✅ | — |  
| `CMD_SLEEP` → the dropper modifies its beacon interval | ✅ | — |  
| `CMD_EXIT` → the dropper terminates cleanly | ✅ | — |  
| Periodic beacons are correctly received and parsed | ✅ | — |  
| The C2 handles connection errors without crashing | — | ✅ |  
| The C2 offers an interactive mode (menu) | — | ✅ |  
| The C2 offers a script mode (automated sequence) | — | ✅ |  
| The C2 displays a readable hexdump of raw and decoded messages | — | ✅ |

### 2. The network capture is complete (`session.pcap`)

| Criterion | Required |  
|---|---|  
| The capture contains the TCP handshake (SYN/SYN-ACK/ACK) | ✅ |  
| The application handshake (HANDSHAKE → ACK) is visible | ✅ |  
| At least one exchange of each command type is present | ✅ |  
| At least one beacon is visible in the capture | ✅ |  
| The clean connection teardown (FIN/ACK) is captured | ✅ |

### 3. The analysis report is complete (`report_ch28.md`)

The report must contain the following sections:

| Section | Expected content |  
|---|---|  
| **Executive summary** | 5-line description of the binary, its behavior, and the threat |  
| **Network IOCs** | IP address, port, transport protocol, magic byte, XOR key, version string |  
| **Protocol specification** | Header format, message type table (commands and responses), encoding |  
| **Per-command behavior** | Description of each command, body format, observed effects |  
| **Sequence diagram** | ASCII or Mermaid diagram showing a complete session flow |  
| **Resilience mechanisms** | Automatic reconnection, retry count, interval |  
| **Detection recommendations** | At least one network detection rule (Snort, Suricata, or custom signature) |

---

## Methodological guidance

### Where to start

The recommended approach is the one followed throughout the chapter. Apply it **from scratch** on `dropper_O2_strip`, as if you hadn't read the previous sections:

1. **Triage** — `file`, `strings`, `checksec`, `ldd`. Note every clue.  
2. **Passive observation** — `strace` + `tcpdump` with an `nc` listener. Identify the address, port, magic byte, first message size.  
3. **Instrumentation** — Frida hooks on `connect`, `send`, `recv`. Identify message types, XOR encoding, body format.  
4. **Static analysis** — Open the binary in Ghidra to confirm constants (`0xDE`, `0x5A`), identify the dispatcher's `switch/case`, reconstruct the handshake structure.  
5. **Build the C2** — Implement the protocol layer by layer: transport → messages → commands → interface.  
6. **Validation** — Launch the C2, connect the dropper, exercise each command, capture everything.

### Key pointers for the stripped binary

Without symbols, function names are not available in Ghidra (you'll see `FUN_001XXXXX`). Here are landmarks for finding key functions:

- **`main`** — Entry point referenced by `__libc_start_main` in the `.init` section. Contains the reconnection loop (`while` + `connect` + `sleep`).  
- **The handshake function** — Look for calls to `gethostname` and `getpid` followed by a `send`. The string `"DRP-1.0"` in `.rodata` is a reliable anchor.  
- **The dispatcher** — Look for a `switch`/`case` pattern with constants `0x01` through `0x05`. At `-O2`, GCC often generates a jump table rather than a cascade of `cmp`/`jz`.  
- **The XOR function** — Look for a loop containing `xor` with an immediate operand `0x5A` (or a register loaded with `0x5A`). At `-O2`, the loop may be unrolled or vectorized.  
- **`send_message` / `recv_message`** — Look for functions that write or read the magic byte `0xDE` (`0xDE` = 222 in decimal). These functions call `libc`'s `send`/`recv`.

### Common pitfalls

- **Endianness of the `length` field** — The header's length field is in **native little-endian** (no `htons`). On x86-64, `struct.pack("<H", ...)` is correct. Using `"!H"` (big-endian) will break the protocol.  
- **Selective XOR** — XOR is **not** applied to all messages. Only `CMD_EXEC`, `CMD_DROP`, and `MSG_RESULT` have their body encoded. `CMD_SLEEP`, `MSG_HANDSHAKE`, `MSG_BEACON`, `MSG_ACK`, `MSG_PONG`, and `MSG_ERROR` are in plaintext.  
- **The handshake expects an ACK** — If you send anything other than `MSG_ACK` (type `0x13`) in response to the handshake, the dropper considers the connection rejected and disconnects.  
- **Beacons arrive between commands** — The dropper sends a beacon every `BEACON_INTERVAL` seconds via `select()`. Your C2 must consume them so as not to confuse a beacon with a command response.  
- **`recv` doesn't necessarily return everything at once** — Implement a `recv_all` that loops until the exact number of requested bytes is received.

---

## Provided files

| File | Location | Description |  
|---|---|---|  
| `dropper_O0` | `binaries/ch28-dropper/` | Debug variant (aids understanding) |  
| `dropper_O2` | `binaries/ch28-dropper/` | Optimized variant with symbols |  
| `dropper_O2_strip` | `binaries/ch28-dropper/` | **Target variant** (stripped) |  
| `dropper_sample.c` | `binaries/ch28-dropper/` | Source code (⚠️ do not consult before completing) |  
| `Makefile` | `binaries/ch28-dropper/` | To recompile the variants |

---

## Self-assessment checklist

Before consulting the solution, verify each point:

| # | Check | ✅ / ❌ |  
|---|---|---|  
| 1 | My C2 accepts the connection and completes the handshake without errors | |  
| 2 | I correctly identified the magic byte, types, and endianness | |  
| 3 | The PING command produces a PONG | |  
| 4 | The EXEC command returns a readable result (XOR-decoded) | |  
| 5 | The DROP command creates a file in `/tmp/` and executes it | |  
| 6 | The SLEEP command effectively modifies the beacon interval | |  
| 7 | The EXIT command terminates the dropper cleanly | |  
| 8 | Beacons are received and parsed (cmd_count + timestamp) | |  
| 9 | My pcap capture contains at least one exchange of each type | |  
| 10 | My report contains IOCs, protocol specification, and a diagram | |  
| 11 | Everything works with `dropper_O2_strip` (not just `_O0`) | |  
| 12 | My C2 doesn't crash if the dropper disconnects unexpectedly | |

**Score:**  
- **10–12** ✅ — Excellent. You have mastered C2 protocol analysis and server emulation.  
- **7–9** ✅ — Solid. Review the missed points, often related to edge cases.  
- **4–6** ✅ — The basics are there. Revisit sections 28.2 and 28.3 to consolidate protocol understanding.  
- **< 4** ✅ — Start the chapter over from 28.1. The sequential analysis is essential.

---

## Solution

The complete solution is available in [`solutions/ch28-checkpoint-fake-c2.py`](/solutions/ch28-checkpoint-fake-c2.py).

> ⚠️ **Advice** — Only consult the solution after making a serious attempt. The pedagogical value of this checkpoint lies in the **process**: reconstructing an unknown protocol from a stripped binary and proving your understanding by writing a functional tool. Reading the solution without having tried is like learning the recipe without ever having cooked.

⏭️ [Chapter 29 — Packing Detection, Unpacking and Reconstruction](/29-unpacking/README.md)
