🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 13

## Write a Frida script that logs all calls to `send()` with their buffers

> 📦 **Target binary**: `binaries/ch13-network/server_O0` and `binaries/ch13-network/client_O0`  
> 🧰 **Required tools**: `frida`, Python 3 + `frida` module  
> 📖 **Sections mobilized**: 13.1 to 13.7 (entire chapter)  
> ⏱️ **Estimated duration**: 45 minutes to 1 hour  
> 📄 **Solution**: `solutions/ch13-checkpoint-solution.js`

---

## Context

The `client_O0` binary is a network client that connects to `server_O0`, authenticates via a custom protocol, then exchanges a series of messages. You have neither the source code nor the protocol documentation. Your mission is to write a complete Frida script that captures and logs all data sent by the client via the `send()` function, so you can reconstruct the protocol in a later chapter (Chapter 23).

This checkpoint validates your ability to combine the chapter's fundamental techniques:

- Choose the right injection mode (section 13.2).  
- Hook a library function (section 13.3).  
- Correctly read arguments of different types — integer, pointer to buffer, size (section 13.4).  
- Transmit raw binary data to the Python client (section 13.4).  
- Filter noise to keep only relevant calls (section 13.3).  
- Enrich the trace with contextual metadata (section 13.6).

---

## Requirements

The Frida script to produce must satisfy the following requirements.

### Functional requirements

**FR-1 — `send()` interception.** Each call to libc's `send()` function made by the client must be intercepted. Recall the signature:

```c
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
```

**FR-2 — Structured logging.** For each intercepted call, the script must send the Python client a JSON message containing at minimum:

- The file descriptor number (`sockfd`).  
- The requested size (`len`).  
- The number of bytes actually sent (return value).  
- A timestamp (milliseconds since tracing began).  
- An incremental sequence number (1st call = 1, 2nd = 2, etc.).

**FR-3 — Raw buffer transmission.** The binary content of the buffer must be transmitted to the Python client via the second parameter of `send()` on the JavaScript side (the binary channel), and not encoded in the JSON. The Python client must be able to exploit these bytes directly.

**FR-4 — Hexadecimal display.** The script must display in the Frida console a `hexdump` of the buffer for each call, limited to the first 128 bytes if the buffer is larger.

**FR-5 — `connect()` interception.** Additionally, the script must hook `connect()` to log the destination IP address and port (parsing `sockaddr_in`), to contextualize subsequent `send()` calls.

### Technical requirements

**TR-1 — Spawn mode.** The script must launch the client in spawn mode (`frida -f` or `frida.spawn`) to capture `send()` calls from the very first byte, including those of the authentication handshake.

**TR-2 — Robustness.** The `onEnter` and `onLeave` callbacks must be protected by `try/catch` blocks. An invalid buffer or unexpected call must not crash the script.

**TR-3 — Optional filtering.** The script must be able to filter `send()` by file descriptor (only log a specific socket), activatable via a configuration variable at the top of the script.

**TR-4 — Data export.** The Python client must save captured buffers in a `capture.bin` file (concatenated raw bytes) and a `capture.json` file (metadata for each call), exploitable for later analysis.

---

## Expected structure

The deliverable consists of two files:

```
checkpoint-ch13/
├── agent.js          ← Frida agent JavaScript code
└── capture.py        ← Python client script (orchestration + export)
```

### `agent.js` skeleton

The agent JavaScript script must contain at minimum:

- An initialization section (start timestamp, sequence counter, filtering configuration).  
- A hook on `connect()` with `sockaddr_in` parsing (AF_INET family, IP and port extraction).  
- A hook on `send()` with reading of file descriptor, buffer, size, and structured sending to Python.  
- A `hexdump` display in the console for each call.

### `capture.py` skeleton

The Python script must:

- Spawn the `client_O0` process via `frida.spawn()`.  
- Load the agent, register the `on_message` callback.  
- Receive JSON messages and binary buffers.  
- Display a formatted summary in the terminal.  
- Save results in `capture.bin` and `capture.json`.  
- Cleanly handle process end (`detached`, Ctrl+C).

---

## Hints and reminders

The following points can guide your thinking without giving the solution:

**Reading the buffer in the right callback.** The buffer passed to `send()` already contains the data to send at the time of the call. So it can be read as early as `onEnter`. However, the number of bytes actually sent is only known at function return (`retval` in `onLeave`). The two callbacks must be coordinated via `this`.

**`readByteArray` size.** Read `Math.min(len, retval)` bytes — no more than what the program asks to send, and no more than what was actually transmitted. If `send()` returns `-1` (error), don't attempt to read the buffer.

**`sockaddr_in` parsing.** Review section 13.4. The address family is on 2 bytes, the port on 2 bytes in big-endian, the IP address on 4 bytes. Each field's offset in the structure is fixed.

**Binary transmission.** The second argument of JavaScript-side `send()` accepts an object returned by `.readByteArray()`. On the Python side, this buffer arrives in the `on_message` callback's `data` parameter as `bytes`.

**`sendall` and `write`.** Depending on the client's implementation, data may be sent via `send()`, `sendto()`, `sendmsg()`, or even `write()` on a socket. For complete coverage, consider also hooking `write()` filtering by file descriptor (sockets and regular files share the file-descriptor space).

---

## Validation criteria

Your checkpoint is successful if:

| # | Criterion | Checked? |  
|---|---|---|  
| 1 | The script captures the initial `connect()` and displays the destination IP and port | ☐ |  
| 2 | Each `send()` call is logged with fd, size, and number of bytes sent | ☐ |  
| 3 | The `hexdump` of each buffer is displayed in the Frida console | ☐ |  
| 4 | Raw binary buffers are transmitted to the Python client via the binary channel | ☐ |  
| 5 | The `capture.json` file contains metadata for each call (fd, size, sequence, timestamp) | ☐ |  
| 6 | The `capture.bin` file contains the concatenation of raw buffers and is exploitable by a parser | ☐ |  
| 7 | The script doesn't crash on `send()` error (return `-1`) or invalid buffer | ☐ |  
| 8 | Filtering by file descriptor works when activated | ☐ |

---

## Going further

If you finish before the allotted time, here are extensions that reinforce mastery:

- **Also intercept `recv()`** and produce a chronological bidirectional trace (interleaved sends and receives), with a direction marker (`>>>` for `send`, `<<<` for `recv`).  
- **Add a backtrace** to each `send()` to identify which binary function originates each send.  
- **Compute an MD5 hash** of each buffer on the Python side and store it in the JSON, to detect retransmissions or duplicate messages.  
- **Produce a reconstructed PCAP file** from the captures, importable into Wireshark for visual protocol analysis.

---

## Skills validated

Success on this checkpoint confirms you master:

| Skill | Sections |  
|---|---|  
| Choose between attach and spawn according to need | 13.2 |  
| Hook a library function by name | 13.3 |  
| Read arguments of heterogeneous types (int, pointer, size) | 13.3, 13.4 |  
| Parse a C structure in memory (`sockaddr_in`) | 13.4 |  
| Transmit binary data from the JS agent to the Python client | 13.4 |  
| Coordinate `onEnter` and `onLeave` via `this` | 13.3 |  
| Protect hooks against runtime errors | 13.3 |  
| Orchestrate a complete Frida session in Python (spawn → attach → load → resume) | 13.2 |

You are ready to tackle Chapter 14 — Analysis with Valgrind and sanitizers, and to apply Frida on the practical cases of Part V, where network (Chapter 23), crypto (Chapter 24), and malware (Chapters 27–28) binaries will intensively mobilize these interception techniques.

⏭️ [Chapter 14 — Analysis with Valgrind and sanitizers](/14-valgrind-sanitizers/README.md)
