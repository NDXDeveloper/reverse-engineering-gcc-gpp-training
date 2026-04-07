🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 28.2 — Hooking Sockets with Frida (Intercepting `connect`, `send`, `recv`)

> 📍 **Objective** — Move from passive observation (`strace` + Wireshark) to **active instrumentation**. With Frida, we inject JavaScript code into the dropper's process to intercept every call to `libc` network functions. We see the buffers in their entirety, we can decode them on the fly, and we can even modify arguments or return values — all without patching or recompiling the binary.

---

## Why Frida rather than `strace`?

`strace` is excellent for a first overview, but it has several limitations for in-depth protocol analysis:

- **Level of abstraction** — `strace` operates at the syscall level (`sendto`, `recvfrom`). You don't see the higher-level calls (`connect`, `send`, `recv` from the `libc`) with their typed arguments. More importantly, you cannot intercept the binary's internal functions.  
- **Truncated buffers** — Even with `-s 4096`, `strace` imposes a limit on displayed buffer sizes. Frida has no such limitation: you have access to the process's entire memory.  
- **No modification** — `strace` is read-only. It cannot modify an argument before the call or spoof a return value. Frida can do both.  
- **No contextual decoding** — If data is encoded (XOR, base64, compression), `strace` shows raw bytes. With Frida, you can call the binary's own decoding function, or implement decoding in the JavaScript script.  
- **Correlation with code** — Frida can hook not only `libc` functions, but also the binary's internal functions (by address). You can thus hook `xor_encode`, `dispatch_command`, `perform_handshake` — points that `strace` doesn't see at all.

In summary, `strace` answers "*what's happening on the network?*"; Frida answers "*what's happening inside the program when it communicates?*".

---

## Recap: Frida architecture

> This section assumes you have mastered the Frida basics covered in [Chapter 13](/13-frida/README.md). We'll recap the essential principles applied to the network context here.

Frida works by injecting a **JavaScript agent** into the target process's memory space. This agent runs in an embedded V8 (or QuickJS) runtime and communicates with the controlling Python script via a message channel.

The core interception API is **`Interceptor.attach(target, callbacks)`**:

- **`target`** — The address of the function to hook. For `libc` functions, we use `Module.getExportByName(null, "connect")` which resolves the symbol across all loaded libraries.  
- **`callbacks.onEnter(args)`** — Called **before** the original function executes. Arguments are accessible via `args[0]`, `args[1]`, etc.  
- **`callbacks.onLeave(retval)`** — Called **after** execution. The return value is accessible and can be modified.

For network functions, arguments follow standard POSIX signatures. We decode them using Frida's `NativePointer` types and memory reading methods (`readByteArray`, `readUtf8String`, `readU16`, etc.).

---

## Setup: the listener and the dropper

For the dropper to get past the connection phase, a server needs to accept the connection and respond to the handshake. We use a minimal Python script that speaks just enough of the protocol to keep the conversation going:

```python
#!/usr/bin/env python3
"""mini_c2.py — Minimal C2 server for testing Frida hooks.
Accepts the connection, acknowledges the handshake, then sends a PING."""

import socket, struct, time

MAGIC = 0xDE  
MSG_ACK   = 0x13  
CMD_PING  = 0x01  
CMD_EXIT  = 0x05  

def make_msg(msg_type, body=b""):
    hdr = struct.pack("<BBH", MAGIC, msg_type, len(body))
    return hdr + body

def recv_msg(sock):
    hdr = sock.recv(4)
    if len(hdr) < 4:
        return None, None, None
    magic, mtype, length = struct.unpack("<BBH", hdr)
    body = sock.recv(length) if length > 0 else b""
    return magic, mtype, body

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 4444))
    srv.listen(1)
    print("[C2] Listening on 127.0.0.1:4444")
    conn, addr = srv.accept()
    print(f"[C2] Connection from {addr}")

    # Receive handshake
    magic, mtype, body = recv_msg(conn)
    print(f"[C2] Handshake: magic=0x{magic:02X} type=0x{mtype:02X} "
          f"body={body}")

    # Acknowledge
    conn.sendall(make_msg(MSG_ACK, b"welcome"))
    print("[C2] Sent ACK")

    time.sleep(1)

    # Send a PING
    conn.sendall(make_msg(CMD_PING))
    print("[C2] Sent PING")

    # Wait for PONG
    magic, mtype, body = recv_msg(conn)
    print(f"[C2] Response: type=0x{mtype:02X}")

    time.sleep(2)

    # Clean termination
    conn.sendall(make_msg(CMD_EXIT))
    print("[C2] Sent EXIT")
    time.sleep(1)
    conn.close()
```

This mini-C2 will be replaced by a more complete server in section 28.4. For now, it's enough to generate bidirectional traffic that Frida can intercept.

**Launch workflow (three terminals):**

```
Terminal 1:  python3 mini_c2.py  
Terminal 2:  frida -l hook_network.js -f ./dropper_O0  
Terminal 3:  (optional) sudo tcpdump -i lo -w cap.pcap port 4444  
```

---

## Hook 1 — `connect`: where does the dropper connect?

The first hook targets the `libc` `connect()` function. Its POSIX signature is:

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

The `addr` argument points to a `sockaddr_in` structure (for IPv4) with the following memory layout:

```
Offset  Size    Field
0x00    2       sa_family  (AF_INET = 2)
0x02    2       sin_port   (big-endian, network order)
0x04    4       sin_addr   (big-endian, network order)
```

The Frida script to hook `connect` and extract the destination address:

```javascript
// hook_connect.js — Intercepts connect() and displays the target address

Interceptor.attach(Module.getExportByName(null, "connect"), {
    onEnter(args) {
        this.sockfd = args[0].toInt32();
        const sockaddr = args[1];
        const family = sockaddr.readU16();

        if (family === 2) { // AF_INET
            // sin_port is in network byte order (big-endian)
            const portRaw = sockaddr.add(2).readU16();
            const port = ((portRaw & 0xFF) << 8) | ((portRaw >> 8) & 0xFF);

            // sin_addr: 4 bytes in network byte order
            const addrRaw = sockaddr.add(4).readU32();
            const ip = [
                addrRaw & 0xFF,
                (addrRaw >> 8) & 0xFF,
                (addrRaw >> 16) & 0xFF,
                (addrRaw >> 24) & 0xFF
            ].join(".");

            this.target = `${ip}:${port}`;
            console.log(`[connect] fd=${this.sockfd} → ${this.target}`);
        }
    },

    onLeave(retval) {
        const ret = retval.toInt32();
        const status = ret === 0 ? "SUCCESS" : `FAILED (${ret})`;
        console.log(`[connect] fd=${this.sockfd} → ${this.target} : ${status}`);
    }
});
```

**Expected output:**

```
[connect] fd=3 → 127.0.0.1:4444
[connect] fd=3 ��� 127.0.0.1:4444 : SUCCESS
```

> 💡 **RE note** — Manually parsing `sockaddr_in` in Frida is an exercise that reinforces understanding of network structure memory layout. In real-world scenarios, you'll find exactly this parsing in Ghidra when reconstructing types in [Chapter 20](/20-decompilation/04-reconstructing-header.md).

---

## Hook 2 — `send`: what does the dropper tell the C2?

The `libc` `send()` function has the following signature:

```c
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
```

The hook captures the sent buffer and breaks it down according to the protocol format identified in section 28.1:

```javascript
// hook_send.js — Intercepts send() and decodes the protocol header

const PROTO_MAGIC = 0xDE;  
const MSG_TYPES = {  
    0x10: "HANDSHAKE", 0x11: "PONG",  0x12: "RESULT",
    0x13: "ACK",       0x14: "ERROR", 0x15: "BEACON"
};

Interceptor.attach(Module.getExportByName(null, "send"), {
    onEnter(args) {
        this.sockfd = args[0].toInt32();
        this.buf    = args[1];
        this.len    = args[2].toInt32();
        this.flags  = args[3].toInt32();

        if (this.len < 4) return;

        const magic = this.buf.readU8();
        if (magic !== PROTO_MAGIC) {
            console.log(`[send] fd=${this.sockfd} len=${this.len} (non-protocol data)`);
            return;
        }

        const msgType  = this.buf.add(1).readU8();
        const bodyLen  = this.buf.add(2).readU16(); // little-endian (native x86-64)
        const typeName = MSG_TYPES[msgType] || `UNKNOWN(0x${msgType.toString(16)})`;

        console.log(`[send] fd=${this.sockfd} | magic=0xDE | type=${typeName} (0x${msgType.toString(16)}) | body_len=${bodyLen}`);

        // Hex dump of the body
        if (bodyLen > 0 && this.len >= 4 + bodyLen) {
            const body = this.buf.add(4).readByteArray(bodyLen);
            console.log("  body (hex): " + hexdump(body, { header: false, ansi: true }));
        }
    },

    onLeave(retval) {
        const sent = retval.toInt32();
        if (sent < 0) {
            console.log(`[send] fd=${this.sockfd} FAILED (returned ${sent})`);
        }
    }
});
```

**Expected output during handshake:**

```
[send] fd=3 | magic=0xDE | type=HANDSHAKE (0x10) | body_len=20
  body (hex):           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
             00000000  6d 79 68 6f 73 74 00 31  32 33 34 00 44 52 50 2d  myhost.1234.DRP-
             00000010  31 2e 30 00                                        1.0.
```

We can clearly see the hostname (`myhost`), the PID (`1234`), and the version (`DRP-1.0`), separated by null bytes. These are the three handshake fields, readable in plaintext because the handshake is **not** XOR-encoded (only the `CMD_EXEC` and `CMD_DROP` commands are).

---

## Hook 3 — `recv`: what does the C2 tell the dropper?

The `recv()` signature:

```c
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
```

For `recv`, the buffer is filled **after** the call. So we must read the data in `onLeave`, once the kernel has written to the buffer:

```javascript
// hook_recv.js �� Intercepts recv() and decodes C2 commands

const CMD_TYPES = {
    0x01: "PING", 0x02: "EXEC", 0x03: "DROP",
    0x04: "SLEEP", 0x05: "EXIT"
};
const XOR_KEY = 0x5A;

function xorDecode(bytes) {
    const decoded = new Uint8Array(bytes);
    for (let i = 0; i < decoded.length; i++) {
        decoded[i] ^= XOR_KEY;
    }
    return decoded.buffer;
}

Interceptor.attach(Module.getExportByName(null, "recv"), {
    onEnter(args) {
        this.sockfd = args[0].toInt32();
        this.buf    = args[1];
        this.size   = args[2].toInt32();
    },

    onLeave(retval) {
        const received = retval.toInt32();
        if (received <= 0) return;

        // Only decode if we have at least a complete header
        if (received < 4) {
            console.log(`[recv] fd=${this.sockfd} ${received} bytes (partial header)`);
            return;
        }

        const magic = this.buf.readU8();
        if (magic !== 0xDE) {
            console.log(`[recv] fd=${this.sockfd} ${received} bytes (non-protocol)`);
            return;
        }

        const msgType = this.buf.add(1).readU8();
        const bodyLen = this.buf.add(2).readU16();
        const typeName = CMD_TYPES[msgType] || `RESP(0x${msgType.toString(16)})`;

        console.log(`[recv] fd=${this.sockfd} | magic=0xDE | type=${typeName} (0x${msgType.toString(16)}) | body_len=${bodyLen}`);

        if (bodyLen > 0 && received >= 4 + bodyLen) {
            const bodyRaw = this.buf.add(4).readByteArray(bodyLen);
            console.log("  body (raw hex):");
            console.log(hexdump(bodyRaw, { header: false, ansi: true }));

            // Attempt XOR decoding for EXEC and DROP commands
            if (msgType === 0x02 || msgType === 0x03) {
                const decoded = xorDecode(bodyRaw);
                console.log("  body (XOR-decoded):");
                console.log(hexdump(decoded, { header: false, ansi: true }));
            }
        }
    }
});
```

**Key points in this hook:**

- Reading is done in **`onLeave`** — this is the fundamental difference from the `send` hook where we read in `onEnter`. The `recv` buffer is empty when the function is entered; it's the kernel that fills it during execution.  
- **XOR decoding** is implemented directly in the hook. For `CMD_EXEC` (type `0x02`) and `CMD_DROP` (type `0x03`), the body is encoded with the key `0x5A`. The hook displays both the raw version and the decoded version, allowing you to immediately verify whether our encoding hypothesis is correct.  
- The **magic byte** check (`0xDE`) filters out non-protocol data (for example, stray network traffic if the dropper opened other sockets).

---

## Complete script: putting it all together

In practice, we combine all three hooks into a single JavaScript file. Here is the unified script, enhanced with a few additional features:

```javascript
// hook_network.js — Complete Frida script for dropper network analysis
// Usage: frida -l hook_network.js -f ./dropper_O0

"use strict";

const PROTO_MAGIC = 0xDE;  
const XOR_KEY     = 0x5A;  

// Type-to-readable-name lookup tables
const CLIENT_MSG = {
    0x10: "HANDSHAKE", 0x11: "PONG",   0x12: "RESULT",
    0x13: "ACK",       0x14: "ERROR",  0x15: "BEACON"
};
const SERVER_CMD = {
    0x01: "PING",  0x02: "EXEC",  0x03: "DROP",
    0x04: "SLEEP", 0x05: "EXIT"
};
// Merge for generic lookup
const ALL_TYPES = Object.assign({}, CLIENT_MSG, SERVER_CMD);

// ─── Utilities ──────────────────────────────────────────────

function xorBuf(arrayBuf) {
    const u8 = new Uint8Array(arrayBuf);
    const out = new Uint8Array(u8.length);
    for (let i = 0; i < u8.length; i++) out[i] = u8[i] ^ XOR_KEY;
    return out.buffer;
}

function parseAddr(sockaddrPtr) {
    const family = sockaddrPtr.readU16();
    if (family !== 2) return null; // AF_INET only
    const portRaw = sockaddrPtr.add(2).readU16();
    const port = ((portRaw & 0xFF) << 8) | ((portRaw >> 8) & 0xFF);
    const raw = sockaddrPtr.add(4).readU32();
    const ip = [raw & 0xFF, (raw >> 8) & 0xFF,
                (raw >> 16) & 0xFF, (raw >> 24) & 0xFF].join(".");
    return { ip, port };
}

function decodeProtoHeader(ptr, len) {
    if (len < 4) return null;
    const magic   = ptr.readU8();
    if (magic !== PROTO_MAGIC) return null;
    const msgType = ptr.add(1).readU8();
    const bodyLen = ptr.add(2).readU16();
    const name    = ALL_TYPES[msgType] || `0x${msgType.toString(16)}`;
    return { magic, msgType, bodyLen, name };
}

function logBody(ptr, hdr, direction) {
    if (hdr.bodyLen === 0) return;
    const body = ptr.add(4).readByteArray(hdr.bodyLen);
    console.log(`  [${direction}] body (raw):`);
    console.log(hexdump(body, { header: false, ansi: true }));

    // XOR decoding for EXEC, DROP, and RESULT
    if (hdr.msgType === 0x02 || hdr.msgType === 0x03 ||
        hdr.msgType === 0x12) {
        const decoded = xorBuf(body);
        console.log(`  [${direction}] body (XOR 0x5A decoded):`);
        console.log(hexdump(decoded, { header: false, ansi: true }));
    }
}

// ─── Hook: connect() ────���──────────────────────────────────

Interceptor.attach(Module.getExportByName(null, "connect"), {
    onEnter(args) {
        this.fd   = args[0].toInt32();
        this.addr = parseAddr(args[1]);
    },
    onLeave(retval) {
        if (!this.addr) return;
        const ok = retval.toInt32() === 0 ? "OK" : "FAIL";
        console.log(`\n[connect] fd=${this.fd} → ${this.addr.ip}:${this.addr.port} [${ok}]`);
    }
});

// ─── Hook: send() ──��───────────────────────────────────────

Interceptor.attach(Module.getExportByName(null, "send"), {
    onEnter(args) {
        const fd  = args[0].toInt32();
        const buf = args[1];
        const len = args[2].toInt32();

        const hdr = decodeProtoHeader(buf, len);
        if (hdr) {
            console.log(`\n[send >>>] fd=${fd} | ${hdr.name} (0x${hdr.msgType.toString(16)}) | body=${hdr.bodyLen}B | total=${len}B`);
            logBody(buf, hdr, "send");
        } else {
            console.log(`\n[send >>>] fd=${fd} | raw ${len}B`);
        }
    }
});

// ─── Hook: recv() ───────��────────────────────────────��─────

Interceptor.attach(Module.getExportByName(null, "recv"), {
    onEnter(args) {
        this.fd  = args[0].toInt32();
        this.buf = args[1];
    },
    onLeave(retval) {
        const received = retval.toInt32();
        if (received <= 0) return;

        const hdr = decodeProtoHeader(this.buf, received);
        if (hdr) {
            console.log(`\n[recv <<<] fd=${this.fd} | ${hdr.name} (0x${hdr.msgType.toString(16)}) | body=${hdr.bodyLen}B | total=${received}B`);
            logBody(this.buf, hdr, "recv");
        } else {
            console.log(`\n[recv <<<] fd=${this.fd} | raw ${received}B`);
        }
    }
});

// ─── Hook: close() ─────────────────────────────────────────

Interceptor.attach(Module.getExportByName(null, "close"), {
    onEnter(args) {
        const fd = args[0].toInt32();
        if (fd > 2) { // ignore stdin/stdout/stderr
            console.log(`\n[close] fd=${fd}`);
        }
    }
});

console.log("=== hook_network.js loaded ===");  
console.log("Hooks active: connect, send, recv, close");  
```

### Launching

```bash
$ frida -l hook_network.js -f ./dropper_O0 --no-pause
```

The **`-f`** option launches the binary via Frida (*spawn mode*), which guarantees that hooks are in place **before** the first call to `connect`. Without this option (*attach* mode), you might miss the initial connection and handshake.

The **`--no-pause`** option immediately resumes process execution after agent injection. Without it, Frida pauses the process at the entry point, and you need to type `%resume` in the Frida console to continue.

---

## Reading the output: annotated complete session

Here is a typical session with `mini_c2.py` listening, annotated for reference:

```
=== hook_network.js loaded ===
Hooks active: connect, send, recv, close

[connect] fd=3 → 127.0.0.1:4444 [OK]              ← TCP connection established

[send >>>] fd=3 | HANDSHAKE (0x10) | body=20B | total=24B
  [send] body (raw):                                ← handshake in plaintext
             00000000  6d 79 68 6f 73 74 00 31  32 33 34 00 44 52 50 2d  myhost.1234.DRP-
             00000010  31 2e 30 00                                        1.0.

[recv <<<] fd=3 | ACK (0x13) | body=7B | total=11B  ← C2 acknowledges
  [recv] body (raw):
             00000000  77 65 6c 63 6f 6d 65                               welcome

[recv <<<] fd=3 | PING (0x01) | body=0B | total=4B  ← PING with no body

[send >>>] fd=3 | PONG (0x11) | body=0B | total=4B  ← PONG response

[recv <<<] fd=3 | EXIT (0x05) | body=0B | total=4B  ← termination order

[send >>>] fd=3 | ACK (0x13) | body=3B | total=7B   ← "bye" acknowledgment
  [send] body (raw):
             00000000  62 79 65                                            bye

[close] fd=3                                         ← socket closed
```

Each line corresponds exactly to what `strace` showed, but with incomparably better readability: message types are named, bodies are decoded, and direction (send/receive) is explicit.

> ⚠️ **Note** — The `[send >>>]` lines faithfully reflect what the hook sees (one `send()` per message, thanks to `send_message`'s unified buffer). The `[recv <<<]` lines are a **simplified view**: in reality, for messages with a body (like ACK/7B), the `recv` hook fires twice (4B header + 7B body separately). Messages without a body (PING, EXIT, PONG) only require one `recv` and display correctly. To get the unified view shown here, you need to hook the internal `recv_message()` function rather than the libc `recv` — see the "Common pitfalls" section below.

---

## Going further: hooks on internal functions

The major advantage of Frida over `strace` is the ability to hook the binary's **internal** functions, not just `libc` ones. If the binary has symbols (`_O0` variant), you can resolve functions by name:

### Hooking `xor_encode` — observing encoding in action

> ⚠️ **Caution** — In the dropper's source code, `xor_encode` is declared `static`. `static` functions are **not** dynamic exports: they don't appear in `.dynsym` and `Module.getExportByName()` won't find them, even on a binary compiled with `-g`. However, DWARF debug symbols reference them in `.symtab`. Frida exposes this table via **`DebugSymbol.getFunctionByName()`**, which works on non-stripped binaries.

```javascript
// hook_xor.js — Intercepts the dropper's internal xor_encode() function
//
// xor_encode is `static` → not in .dynsym → we use DebugSymbol
// which reads .symtab / DWARF (available on _O0 and _O2, not on _strip)

const xorEncode = DebugSymbol.getFunctionByName("xor_encode");

if (!xorEncode.isNull()) {
    Interceptor.attach(xorEncode, {
        onEnter(args) {
            this.buf = args[0];
            this.len = args[1].toInt32();

            // Read buffer BEFORE XOR
            console.log(`\n[xor_encode] BEFORE — ${this.len} bytes:`);
            console.log(hexdump(this.buf.readByteArray(this.len),
                        { header: false, ansi: true }));
        },
        onLeave(retval) {
            // Read buffer AFTER XOR
            console.log(`[xor_encode] AFTER  — ${this.len} bytes:`);
            console.log(hexdump(this.buf.readByteArray(this.len),
                        { header: false, ansi: true }));
        }
    });
    console.log("[+] Hooked xor_encode at " + xorEncode);
} else {
    console.log("[-] xor_encode not found in debug symbols (stripped binary?)");
    console.log("    → Use Ghidra to find the offset, then hook by address.");
}
```

This hook shows the buffer **before** and **after** XOR application, definitively confirming the key used and the scope of encoding. You see the received shell command in plaintext (before XOR) then its encoded version (after XOR, just before sending).

> 💡 **RE note** — When you switch to the stripped variant (`_O2_strip`), debug symbols (`.symtab`, DWARF) have been removed by `strip`. `DebugSymbol.getFunctionByName()` will return a null pointer for internal functions (`xor_encode`, `dispatch_command`, `perform_handshake`...). You'll first need to identify the address of `xor_encode` in Ghidra (e.g., via the `0x5A` constant in the disassembly), then provide this address directly to Frida:  
>  
> ```javascript  
> const base = Module.getBaseAddress("dropper_O2_strip");  
> const xorEncode = base.add(0x1a30); // offset found in Ghidra  
> Interceptor.attach(xorEncode, { ... });  
> ```

### Hooking `dispatch_command` — observing the state machine

Same caveat as for `xor_encode`: `dispatch_command` is `static`, so we use `DebugSymbol`:

```javascript
// hook_dispatch.js — Intercepts dispatch_command() to log each command

const dispatch = DebugSymbol.getFunctionByName("dispatch_command");

if (!dispatch.isNull()) {
    Interceptor.attach(dispatch, {
        onEnter(args) {
            // args[0] = dropper_state_t*, args[1] = proto_message_t*
            const msgPtr = args[1];
            const msgType = msgPtr.add(1).readU8();    // type field offset
            const bodyLen = msgPtr.add(2).readU16();   // length field offset
            const typeName = {
                0x01: "PING", 0x02: "EXEC", 0x03: "DROP",
                0x04: "SLEEP", 0x05: "EXIT"
            }[msgType] || "??";

            console.log(`\n[dispatch] command=${typeName} (0x${msgType.toString(16)}) body_len=${bodyLen}`);
        },
        onLeave(retval) {
            console.log(`[dispatch] returned ${retval.toInt32()}`);
        }
    });
    console.log("[+] Hooked dispatch_command at " + dispatch);
}
```

By hooking the dispatcher, you observe the dropper's **state machine** from the inside: each incoming command, the handler's return value, and the command sequencing. It's an ideal complement to network hooks: you correlate "what arrives on the socket" with "what the dropper does with it."

---

## Handling the stripped binary case

On the `dropper_O2_strip` variant, debug symbols (`.symtab`, DWARF) have been removed by `strip`. `DebugSymbol.getFunctionByName()` returns a null pointer for internal functions (`xor_encode`, `dispatch_command`, `perform_handshake`...). Hooks on `libc` functions (`connect`, `send`, `recv`) continue to work normally since those symbols reside in shared libraries, not in the binary.

To hook internal functions of a stripped binary, the procedure is:

1. **Identify the function in Ghidra** — Look for the XOR constant `0x5A`, format strings, the dispatcher's `switch/case` patterns. Ghidra will assign automatic names like `FUN_00101a30`.

2. **Calculate the offset from the module base** — In Ghidra, the displayed address is the *image* address (before relocation). The offset is `ghidra_address - ghidra_image_base`. For a PIE binary, the image base in Ghidra is typically `0x00100000`.

3. **Apply the offset to the actual base in memory** — In Frida, `Module.getBaseAddress("dropper_O2_strip")` returns the actual base (after ASLR). Add the offset.

```javascript
// Example for a stripped PIE binary
const mod  = Process.getModuleByName("dropper_O2_strip");  
const base = mod.base;  

// Offsets found in Ghidra (image base = 0x100000)
const OFF_XOR_ENCODE = 0x1a30;      // FUN_00101a30  
const OFF_DISPATCH   = 0x1d80;      // FUN_00101d80  

Interceptor.attach(base.add(OFF_XOR_ENCODE), {
    onEnter(args) {
        console.log("[xor_encode] called");
        // ... same logic as above
    }
});
```

> ���� **RE note** — This "Ghidra → Frida bridge via offset" technique is fundamental in malware analysis. You identify interesting functions statically, then instrument them dynamically. The two approaches reinforce each other.

---

## Common pitfalls and solutions

### The dropper uses `sendto`/`recvfrom` instead of `send`/`recv`

Depending on the `libc` version and optimization level, the C calls `send()` and `recv()` may be internally implemented as `sendto()` and `recvfrom()` with address arguments set to `NULL`. If your `send`/`recv` hooks aren't triggering, add hooks on `sendto` and `recvfrom`:

```javascript
Interceptor.attach(Module.getExportByName(null, "sendto"), {
    onEnter(args) {
        // args: sockfd, buf, len, flags, dest_addr, addrlen
        // For TCP, dest_addr is NULL — same logic as send()
        // ...
    }
});
```

The reverse problem can also occur (your `sendto` hooks don't trigger because the `libc` uses `send` directly). The robust solution is to **hook both** and deduplicate in your logic if necessary.

### The `recv` hook fires twice per protocol message

The dropper's internal `recv_message()` function calls `recv_all()` **twice** for each message: once for the **header** (4 bytes) to determine the body size, then a second time for the **body** (N bytes). Each `recv_all()` calls `recv()` in a loop, which means the Frida hook on `recv` fires **at least twice** per protocol message.

In practice on a local socket (`127.0.0.1`), each `recv_all()` typically completes in a single `recv()` call (the kernel has enough data buffered). So the hook sees:

1. **First `recv`** → 4 bytes (header) — the hook parses the magic, type, and length, but the body isn't in the buffer yet.  
2. **Second `recv`** → N bytes (body) — the hook sees raw data without a magic byte and displays it as "non-protocol."

This is why the annotated output example in this section (and the unified `hook_network.js` script) corresponds to a **simplified** scenario. In reality, received messages appear in two fragments in the hook output.

To reassemble complete messages, three approaches:

- **Hook `recv_message()` directly** — This is the dropper's internal function that returns a complete message (header + body) in a contiguous `proto_message_t` structure. Using `DebugSymbol.getFunctionByName("recv_message")` on the `_O0` variant, or by offset on the stripped variant. This is the most reliable approach.  
- **Accumulate in the hook** — Maintain an accumulation buffer in the JavaScript script and progressively reassemble messages by parsing headers. More complex but works on any binary.  
- **Accept fragments** — The libc `send`/`recv` hooks remain useful for confirming sizes and timestamps, even if they don't give you the "one message = one line" view.

> 💡 **Why the `send` hook doesn't have this problem** — The dropper's `send_message()` function assembles the header and body into a **single buffer** before calling `send_all()`. So there's only one `send()` call per protocol message, and the Frida hook sees the entire message at once.

### Frida crashes with `Process.getModuleByName` not found

If the binary is launched in spawn mode (`-f`) and the agent tries to access the module before the loader has loaded it, you get an error. Using `--no-pause` and placing hooks in the script's main body (not in an asynchronous callback) generally solves the problem. If the issue persists, you can wrap the initialization in a `setTimeout`:

```javascript
setTimeout(function() {
    // hooks here
}, 100);
```

---

## What we know after this phase

The Frida hooks have allowed us to confirm and enrich the observations from section 28.1:

| Element | Source 28.1 (strace/Wireshark) | Confirmed/Enriched by Frida (28.2) |  
|---|---|---|  
| C2 address | `127.0.0.1:4444` | Confirmed via `connect` hook |  
| Magic byte | `0xDE` (raw byte in packets) | Confirmed — consistent across all messages |  
| Header format | `[magic][type][length][body]` | Confirmed — `packed` structure of 4 bytes |  
| Handshake | Body = hostname + PID + version | Confirmed — visible in plaintext in `send` hook |  
| XOR encoding | Hypothesis based on `strings` | **Confirmed**: key `0x5A`, applied to EXEC and DROP only |  
| State machine | Unknown | **Identified** via `dispatch_command` hook: 5 commands |

The next section (28.3) will use all this data to **formalize the C2 protocol**: exact format of each command, sequence diagram, complete state machine, and a specification sufficient to write a compatible client or server.

---

> **Up next** — In section 28.3, we consolidate all our observations into a **complete C2 protocol specification**: message format, handshake sequence diagram, command table, and dropper state machine.

⏭️ [RE of the custom C2 protocol (commands, encoding, handshake)](/28-dropper/03-re-c2-protocol.md)
