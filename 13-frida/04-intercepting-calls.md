🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.4 — Intercepting calls to `malloc`, `free`, `open`, custom functions

> 🧰 **Tools used**: `frida`, Python 3 + `frida` module  
> 📦 **Binaries used**: `binaries/ch13-keygenme/keygenme_O0`, `binaries/ch14-crypto/crypto_O0`, `binaries/ch23-network/server_O0`  
> 📖 **Prerequisites**: [13.3 — Hooking C and C++ functions](/13-frida/03-hooking-c-cpp-functions.md)

---

## From theory to fieldwork

Section 13.3 laid the foundations: `Interceptor.attach`, symbol resolution, argument reading, filtering. This section applies them to three families of functions the reverse engineer constantly intercepts — memory allocations (`malloc`/`free`), file and network operations (`open`, `read`, `write`, `send`, `recv`), and application-specific functions unique to the analyzed binary. Each family presents specific challenges and proven hooking patterns.

---

## Intercepting memory allocations: `malloc` and `free`

### Why trace allocations?

In RE, tracing memory allocations answers several fundamental questions. How much memory does the program use, and how does this consumption evolve over time? Are buffers allocated to store sensitive data (crypto keys, decrypted passwords, tokens)? Are there memory leaks that could reveal flawed internal logic? What is a data structure's lifecycle — when is it created, filled, consumed, freed?

With GDB, answering these questions requires conditional breakpoints on `malloc` and `free`, manual register inspection at each stop, and considerable patience. With Frida, you automate everything and observe the allocation flow in real time, without interrupting the program.

### Basic hook on `malloc`

Recall the signature:

```c
void *malloc(size_t size);
```

A single argument (`size`, passed in `rdi`), and the return value is the pointer to the allocated zone.

```javascript
Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter(args) {
        this.size = args[0].toInt32();
    },
    onLeave(retval) {
        if (this.size > 0) {
            console.log(`malloc(${this.size}) = ${retval}`);
        }
    }
});
```

> ⚠️ **Watch the volume.** A typical program makes thousands of `malloc` calls per second — each `printf`, each `std::string` manipulation, each internal libc operation triggers allocations. Without filtering, the output is unusable. The following sections show how to reduce the noise.

### Filter by size

Often, interesting allocations have characteristic sizes. An AES-256 buffer is 32 bytes. A network read buffer is typically 1024, 4096, or 8192 bytes. You can filter by size:

```javascript
Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter(args) {
        this.size = args[0].toInt32();
    },
    onLeave(retval) {
        // Only log allocations between 16 and 256 bytes
        // (typical range for crypto keys, tokens, small structures)
        if (this.size >= 16 && this.size <= 256) {
            console.log(`malloc(${this.size}) = ${retval}`);
        }
    }
});
```

### Filter by caller

More powerful technique: only capture `malloc` calls from the main binary, ignoring internal libc and library allocations.

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter(args) {
        this.size = args[0].toInt32();
        this.fromMain = this.returnAddress.compare(modBase) >= 0 &&
                        this.returnAddress.compare(modEnd) < 0;
    },
    onLeave(retval) {
        if (this.fromMain) {
            console.log(`[main] malloc(${this.size}) = ${retval}`);
            console.log(`  called from ${DebugSymbol.fromAddress(this.returnAddress)}`);
        }
    }
});
```

This pattern drastically reduces noise. You only see allocations initiated by the analyzed binary's code — those reflecting its internal logic.

### Hook on `free` and correlation

```c
void free(void *ptr);
```

```javascript
Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter(args) {
        const ptr = args[0];
        if (!ptr.isNull()) {
            console.log(`free(${ptr})`);
        }
    }
});
```

Hooking `free` alone has limited interest. The power appears when you **correlate** allocations and frees to track buffer lifecycles:

```javascript
const allocations = new Map();

Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter(args) {
        this.size = args[0].toInt32();
    },
    onLeave(retval) {
        if (this.size >= 16 && !retval.isNull()) {
            allocations.set(retval.toString(), {
                size: this.size,
                caller: DebugSymbol.fromAddress(this.returnAddress).toString(),
                time: Date.now()
            });
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "free"), {
    onEnter(args) {
        const key = args[0].toString();
        if (allocations.has(key)) {
            const info = allocations.get(key);
            const lifetime = Date.now() - info.time;
            console.log(`free(${key}) — was malloc(${info.size}) `
                      + `from ${info.caller}, alive ${lifetime}ms`);
            allocations.delete(key);
        }
    }
});

// Periodically display unfreed allocations
setInterval(() => {
    if (allocations.size > 0) {
        console.log(`\n[*] ${allocations.size} in-flight allocations:`);
        allocations.forEach((info, ptr) => {
            console.log(`  ${ptr} : ${info.size} bytes from ${info.caller}`);
        });
    }
}, 5000);
```

This script builds a real-time allocation tracker. Each `malloc` records the returned pointer, size, caller, and timestamp. Each `free` finds the corresponding allocation and displays its lifetime. Allocations that are never freed (leaks, or persistent buffers) remain in the map and are displayed periodically.

In crypto RE context (Chapter 24), this tracker reveals buffers allocated to store keys and IVs — they have a characteristic size (16, 24, or 32 bytes for AES) and are often allocated by an identifiable function (`init_cipher`, `generate_key`…).

### `calloc` and `realloc`

For complete coverage, also hook `calloc` and `realloc`:

```c
void *calloc(size_t nmemb, size_t size);  
void *realloc(void *ptr, size_t size);  
```

```javascript
Interceptor.attach(Module.findExportByName(null, "calloc"), {
    onEnter(args) {
        this.nmemb = args[0].toInt32();
        this.size = args[1].toInt32();
    },
    onLeave(retval) {
        const total = this.nmemb * this.size;
        console.log(`calloc(${this.nmemb}, ${this.size}) [${total} bytes] = ${retval}`);
    }
});

Interceptor.attach(Module.findExportByName(null, "realloc"), {
    onEnter(args) {
        this.oldPtr = args[0];
        this.newSize = args[1].toInt32();
    },
    onLeave(retval) {
        console.log(`realloc(${this.oldPtr}, ${this.newSize}) = ${retval}`);
    }
});
```

### Reading a buffer's content after allocation

`malloc` returns a pointer to uninitialized memory. Interesting content will only be written there later, by application code. Reading the buffer in `malloc`'s `onLeave` thus gives nothing useful.

The strategy is to note the address and size during `malloc`, then read the content at the opportune moment — in the `onEnter` of a function that consumes this buffer (for example `send`, `write`, or a crypto function), or at a more advanced logical breakpoint in the execution. We'll see this technique in detail in the examples that follow.

---

## Intercepting file operations: `open`, `read`, `write`, `close`

### Tracing file access

Observing which files a program opens, reads, and writes is one of the reverse engineer's first reflexes. `strace` does it passively (Chapter 5, section 5.5), but Frida allows going further: filter, modify arguments, read buffers, correlate operations.

### Hook on `open` / `openat`

On modern Linux, `openat` is the actual system call for nearly all file openings. Libc's `open` function is often a wrapper around `openat`. For exhaustiveness, hook both:

```javascript
// open(const char *pathname, int flags, mode_t mode)
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter(args) {
        this.path = args[0].readUtf8String();
        this.flags = args[1].toInt32();
    },
    onLeave(retval) {
        const fd = retval.toInt32();
        console.log(`open("${this.path}", 0x${this.flags.toString(16)}) = fd ${fd}`);
    }
});

// openat(int dirfd, const char *pathname, int flags, mode_t mode)
Interceptor.attach(Module.findExportByName(null, "openat"), {
    onEnter(args) {
        this.dirfd = args[0].toInt32();
        this.path = args[1].readUtf8String();
        this.flags = args[2].toInt32();
    },
    onLeave(retval) {
        const fd = retval.toInt32();
        console.log(`openat(${this.dirfd}, "${this.path}", 0x${this.flags.toString(16)}) = fd ${fd}`);
    }
});
```

### Correlating file descriptors

The most powerful pattern for file tracing consists of maintaining a correspondence table between file descriptors and paths, then using this table in `read`/`write` hooks:

```javascript
const fdMap = new Map();

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave(retval) {
        const fd = retval.toInt32();
        if (fd >= 0) {
            fdMap.set(fd, this.path);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "close"), {
    onEnter(args) {
        const fd = args[0].toInt32();
        if (fdMap.has(fd)) {
            console.log(`close(fd ${fd}) → "${fdMap.get(fd)}"`);
            fdMap.delete(fd);
        }
    }
});

// read(int fd, void *buf, size_t count)
Interceptor.attach(Module.findExportByName(null, "read"), {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
    },
    onLeave(retval) {
        const bytesRead = retval.toInt32();
        if (bytesRead > 0 && fdMap.has(this.fd)) {
            const path = fdMap.get(this.fd);
            console.log(`read(fd ${this.fd} → "${path}", ${bytesRead} bytes)`);
            // Dump the first bytes read
            const preview = this.buf.readByteArray(Math.min(bytesRead, 64));
            console.log("  data:", preview);
        }
    }
});

// write(int fd, const void *buf, size_t count)
Interceptor.attach(Module.findExportByName(null, "write"), {
    onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
    },
    onLeave(retval) {
        const bytesWritten = retval.toInt32();
        if (bytesWritten > 0 && fdMap.has(this.fd)) {
            const path = fdMap.get(this.fd);
            console.log(`write(fd ${this.fd} → "${path}", ${bytesWritten} bytes)`);
            const preview = this.buf.readByteArray(Math.min(bytesWritten, 64));
            console.log("  data:", preview);
        }
    }
});
```

This script builds a complete view of the program's file I/O: which file is opened, what data is read or written to it, and when it's closed. In crypto RE context (Chapter 24), you see the encrypted-file reads and decrypted-file writes appear — with their content.

Note that for `read`, the buffer is read in `onLeave` (after the function filled it), while for `write`, the buffer can be read as early as `onEnter` (it already contains the data to write). Here, we read in `onLeave` in both cases to have access to the actual number of bytes transferred via `retval`.

### Decoding `open` flags

The flags of `open` are bitmasks. To make them readable:

```javascript
function decodeOpenFlags(flags) {
    const names = [];
    const O_RDONLY = 0x0, O_WRONLY = 0x1, O_RDWR = 0x2;
    const O_CREAT = 0x40, O_TRUNC = 0x200, O_APPEND = 0x400;

    const access = flags & 0x3;
    if (access === O_RDONLY) names.push("O_RDONLY");
    else if (access === O_WRONLY) names.push("O_WRONLY");
    else if (access === O_RDWR) names.push("O_RDWR");

    if (flags & O_CREAT) names.push("O_CREAT");
    if (flags & O_TRUNC) names.push("O_TRUNC");
    if (flags & O_APPEND) names.push("O_APPEND");

    return names.join(" | ");
}
```

---

## Intercepting network operations: `connect`, `send`, `recv`

Network tracing is central for protocol reversing (Chapter 23). `strace` shows raw system calls, but Frida allows decoding structures and correlating exchanges.

### Hook on `connect`

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

The difficulty here is parsing the `sockaddr` structure, which varies by address family (IPv4, IPv6, Unix):

```javascript
Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter(args) {
        this.sockfd = args[0].toInt32();
        const sockaddr = args[1];
        const family = sockaddr.readU16();  // sa_family, first 2 bytes

        if (family === 2) { // AF_INET (IPv4)
            // struct sockaddr_in: family(2) + port(2) + addr(4) + zero(8)
            const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            const ip = [
                sockaddr.add(4).readU8(),
                sockaddr.add(5).readU8(),
                sockaddr.add(6).readU8(),
                sockaddr.add(7).readU8()
            ].join('.');

            this.target = `${ip}:${port}`;
        } else if (family === 1) { // AF_UNIX
            this.target = sockaddr.add(2).readUtf8String();
        } else {
            this.target = `family=${family}`;
        }
    },
    onLeave(retval) {
        const result = retval.toInt32();
        console.log(`connect(fd ${this.sockfd}, ${this.target}) = ${result}`);
    }
});
```

Note the manual network-port parsing: `sockaddr_in.sin_port` is in **network byte order** (big-endian), while x86-64 is little-endian. We read both bytes individually and recombine them in the right order.

### Hook on `send` and `recv`

```c
ssize_t send(int sockfd, const void *buf, size_t len, int flags);  
ssize_t recv(int sockfd, void *buf, size_t len, int flags);  
```

```javascript
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        this.sockfd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        const sent = retval.toInt32();
        if (sent > 0) {
            console.log(`\n>>> send(fd ${this.sockfd}, ${sent} bytes)`);
            console.log(hexdump(this.buf, { length: Math.min(sent, 128) }));
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "recv"), {
    onEnter(args) {
        this.sockfd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        const received = retval.toInt32();
        if (received > 0) {
            console.log(`\n<<< recv(fd ${this.sockfd}, ${received} bytes)`);
            console.log(hexdump(this.buf, { length: Math.min(received, 128) }));
        }
    }
});
```

The `hexdump` function is a built-in Frida utility that produces a classic hexadecimal display with offsets and ASCII representation — exactly the format of `xxd` (Chapter 5, section 5.1):

```
              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  48 45 4c 4c 4f 00 01 02 03 04 05 06 07 08 09 0a  HELLO...........
00000010  6b 65 79 3d 41 42 43 44 45 46                    key=ABCDEF
```

### Sending binary data to the Python client

For binary protocols (Chapter 23), captured data often needs to be analyzed on the Python side rather than displayed in the console. The second parameter of `send()` allows transmitting a raw binary buffer:

```javascript
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        const sent = retval.toInt32();
        if (sent > 0) {
            // Send JSON + raw binary buffer
            send(
                { event: "send", fd: this.sockfd, length: sent },
                this.buf.readByteArray(sent)
            );
        }
    }
});
```

Python side:

```python
def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('event') == 'send':
            print(f"[>>>] {payload['length']} bytes on fd {payload['fd']}")
            # data contains raw bytes (type bytes)
            with open("capture_send.bin", "ab") as f:
                f.write(data)
            # Or analyze the protocol directly
            parse_protocol(data)
```

The `data` parameter in the Python callback is a `bytes` object containing exactly the bytes sent by the second argument of `send()` on the JavaScript side. This mechanism avoids base64-encoding the buffer in JSON, which is crucial for large transfers.

---

## Intercepting application functions (customs)

Beyond standard library functions, the most interesting targets in RE are the binary's own functions — a `validate_license`, `decrypt_buffer`, `parse_packet`, or `authenticate` function. These are the ones encapsulating business logic.

### Finding candidate functions

The first step is identifying the functions to hook. Several approaches combine:

**From static analysis (Ghidra, objdump).** You identified in Ghidra a function at offset `0x11a9` that takes a string argument and returns an `int`. The decompiler suggests it performs a verification.

```javascript
const base = Process.enumerateModules()[0].base;  
const validate_addr = base.add(0x11a9);  

Interceptor.attach(validate_addr, {
    onEnter(args) {
        console.log("validate() called");
        console.log("  arg0 (rdi):", args[0].readUtf8String());
        console.log("  arg1 (rsi):", args[1].toInt32());
    },
    onLeave(retval) {
        console.log("  return:", retval.toInt32());
    }
});
```

**From the binary's imports.** Imports (section 13.3) reveal called library functions, but internal functions don't appear there. However, you can start from an import and work back: "who calls `strcmp` from the main binary?" The backtrace (section 13.3) gives the answer, and the return address identifies the calling function.

**From `frida-trace` with exhaustive enumeration.** You can trace all functions of the main binary at once:

```bash
frida-trace -f ./keygenme_O0 -I "keygenme_O0"
```

The `-I` (uppercase) option includes all functions of the specified module. The output shows the call order and allows quickly identifying functions called during a specific action (password input, for example).

### Hooking a function with unknown signature

In RE, you don't always know the target function's exact signature. Ghidra's decompiler gives an estimate, but it may be incorrect — especially with optimizations. The strategy is to hook first in exploratory mode, inspecting raw registers:

```javascript
const base = Process.enumerateModules()[0].base;  
const mystery_func = base.add(0x1250);  

Interceptor.attach(mystery_func, {
    onEnter(args) {
        console.log("mystery_func() called");
        console.log("  rdi:", args[0]);
        console.log("  rsi:", args[1]);
        console.log("  rdx:", args[2]);
        console.log("  rcx:", args[3]);

        // Try reading each argument as different types
        try { console.log("  rdi as string:", args[0].readUtf8String()); } catch(e) {}
        try { console.log("  rdi as int   :", args[0].toInt32()); } catch(e) {}
        try { console.log("  rsi as string:", args[1].readUtf8String()); } catch(e) {}
        try { console.log("  rsi as int   :", args[1].toInt32()); } catch(e) {}

        // Memory dump around the first argument (if it's a pointer)
        try {
            console.log("  memory @ rdi:");
            console.log(hexdump(args[0], { length: 64 }));
        } catch(e) {}
    },
    onLeave(retval) {
        console.log("  return:", retval);
        console.log("  return as int:", retval.toInt32());
        try { console.log("  return as string:", retval.readUtf8String()); } catch(e) {}
    }
});
```

The multiple `try/catch` blocks seem inelegant, but it's an effective probing technique. If `args[0]` is an integer (for example a file descriptor), `readUtf8String()` will throw an exception (address `0x3` isn't a valid pointer), but `toInt32()` will work. If it's a pointer to a string, `readUtf8String()` will return the string. By observing results, you progressively deduce the signature.

### Hooking a function that manipulates structures

When an argument is a pointer to a structure, you must read individual fields knowing the memory layout (reconstructed via Ghidra, Chapter 8 section 8.6):

```c
// Structure reconstructed from Ghidra
typedef struct {
    uint32_t magic;      // offset 0x00
    uint16_t version;    // offset 0x04
    uint16_t flags;      // offset 0x06
    uint32_t data_size;  // offset 0x08
    char     name[32];   // offset 0x0c
} PacketHeader;
```

```javascript
Interceptor.attach(parse_packet_addr, {
    onEnter(args) {
        const hdr = args[0];  // pointer to PacketHeader

        const magic     = hdr.readU32();
        const version   = hdr.add(0x04).readU16();
        const flags     = hdr.add(0x06).readU16();
        const dataSize  = hdr.add(0x08).readU32();
        const name      = hdr.add(0x0c).readUtf8String();

        console.log(`parse_packet():`);
        console.log(`  magic    : 0x${magic.toString(16)}`);
        console.log(`  version  : ${version}`);
        console.log(`  flags    : 0x${flags.toString(16)}`);
        console.log(`  dataSize : ${dataSize}`);
        console.log(`  name     : "${name}"`);

        // If we also want to see raw data after the header
        if (dataSize > 0 && dataSize < 4096) {
            const dataPtr = hdr.add(0x2c); // 0x0c + 32 (name size)
            console.log("  data:");
            console.log(hexdump(dataPtr, { length: Math.min(dataSize, 128) }));
        }
    }
});
```

This field-by-field reading is the dynamic equivalent of writing a `.hexpat` pattern for ImHex (Chapter 6). The difference is that here, you see the real values at runtime, with effective memory addresses and dynamic content.

### Combining multiple hooks to reconstruct a flow

A frequent RE case: you want to understand data flow across several functions — for example, how user input is transformed, encrypted, then sent over the network. The strategy consists of placing hooks at each step and correlating data via common identifiers (pointers, file descriptors, buffer sizes):

```javascript
// Step 1: user enters a password
Interceptor.attach(Module.findExportByName(null, "fgets"), {
    onEnter(args) {
        this.buf = args[0];
    },
    onLeave(retval) {
        if (!retval.isNull()) {
            const input = this.buf.readUtf8String().trim();
            console.log(`[1] User input: "${input}"`);
        }
    }
});

// Step 2: program transforms the input (custom function)
const transform_addr = Process.enumerateModules()[0].base.add(0x1340);  
Interceptor.attach(transform_addr, {  
    onEnter(args) {
        this.inputBuf = args[0];
        this.outputBuf = args[1];
        this.len = args[2].toInt32();
        console.log(`[2] transform(): input of ${this.len} bytes`);
        console.log(hexdump(this.inputBuf, { length: this.len }));
    },
    onLeave(retval) {
        console.log(`[2] transform(): output`);
        console.log(hexdump(this.outputBuf, { length: this.len }));
    }
});

// Step 3: result is sent over the network
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        const len = args[2].toInt32();
        console.log(`[3] send(): ${len} bytes`);
        console.log(hexdump(args[1], { length: Math.min(len, 128) }));
    }
});
```

This setup of successive hooks is the fundamental technique of dynamic analysis with Frida. You place probes at each data-transformation point, and observe how bytes evolve from one step to the next. It's the dynamic analog of following cross-references in Ghidra (Chapter 8, section 8.7), but with the real data.

---

## `Memory.scan`: searching for patterns in memory

As a complement to function hooks, Frida allows scanning the process's memory looking for byte patterns. It's particularly useful for locating crypto constants (Chapter 24), strings decrypted in memory, or specific data structures.

```javascript
// Search for the AES S-box constant (first bytes: 63 7c 77 7b)
const sboxSignature = "63 7c 77 7b f2 6b 6f c5";

Process.enumerateRanges('r--').forEach(range => {
    Memory.scan(range.base, range.size, sboxSignature, {
        onMatch(address, size) {
            console.log(`[!] AES S-box found @ ${address}`);
            console.log(hexdump(address, { length: 64 }));
        },
        onComplete() {}
    });
});
```

`Process.enumerateRanges('r--')` returns all readable memory ranges. The pattern is expressed in hexadecimal with spaces between bytes. You can use wildcards with `??` for variable bytes:

```javascript
// Search for a magic number followed by 2 arbitrary bytes then a flag
const pattern = "de ad ?? ?? 01";
```

---

## Best practices and common pitfalls

### Reentrancy

A hook on `malloc` that calls `console.log` potentially triggers an internal `malloc` (to format the string), which triggers the hook again, and so on — infinite recursion. In practice, Frida handles this case by detecting reentrancy and disabling the hook during callback execution. But in some complex scenarios (hooks on multiple functions that call each other), reentrancy can cause unexpected behavior.

If you observe strange results or crashes with hooks on very low-level functions (`malloc`, `free`, `mmap`), an explicit reentrancy guard can help:

```javascript
let insideHook = false;

Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter(args) {
        if (insideHook) return;
        insideHook = true;

        this.size = args[0].toInt32();
        this.active = true;

        insideHook = false;
    },
    onLeave(retval) {
        if (!this.active) return;
        console.log(`malloc(${this.size}) = ${retval}`);
    }
});
```

> ⚠️ This guard is not thread-safe in a multi-threaded program. For robust protection, you'd need a per-thread guard (via `Process.getCurrentThreadId()`). In practice, for our single-threaded training binaries, the simple guard suffices.

### Performance

Each hook adds overhead. For very frequently called functions (`malloc`, `free`, `strlen`), this overhead can noticeably slow the program. A few rules:

- **Filter early.** Check the filtering criteria (size, caller, content) as early as possible in `onEnter`, and use a fast `return` for uninteresting cases.  
- **Minimize work in the hook.** Send raw data to the Python client via `send()` and do heavy analysis on the Python side rather than in the agent's JavaScript.  
- **Use `console.log` sparingly.** `send()` with a Python callback is more performant than `console.log` for large volumes.  
- **Detach hooks no longer needed.** If you've captured the sought information, call `listener.detach()` to remove the hook and restore normal performance.

---

## What to remember

- **`malloc`/`free`**: hooking both and correlating pointers allows tracking the allocation lifecycle. Filtering by size and caller eliminates noise from libc's internal allocations.  
- **`open`/`read`/`write`**: maintaining an `fd → path` map gives a complete view of file I/O. Read buffers in `read`'s `onLeave` (after filling) and in `write`'s `onEnter` (before sending).  
- **`connect`/`send`/`recv`**: manually parse `sockaddr` for IP and port, use `hexdump` to visualize network data, and `send()` with a binary buffer to transmit captures to the Python client.  
- **Application functions**: combine static analysis (Ghidra) to find offsets, exploratory probing (`try/catch` on types) to guess the signature, and field-by-field structure reading for complex arguments.  
- **`Memory.scan`**: byte-pattern searching in memory to locate constants, keys, or structures.  
- **Reentrancy and performance**: beware of hooks on very frequent functions, filter early, send raw data to the Python client for heavy analysis.

---

> **Next section**: 13.5 — Modifying arguments and return values live — we'll move from observation to intervention, learning to rewrite data during program execution.

⏭️ [Modifying arguments and return values live](/13-frida/05-modifying-arguments-returns.md)
