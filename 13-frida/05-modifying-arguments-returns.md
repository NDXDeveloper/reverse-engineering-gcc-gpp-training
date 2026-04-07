🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.5 — Modifying arguments and return values live

> 🧰 **Tools used**: `frida`, Python 3 + `frida` module  
> 📦 **Binaries used**: `binaries/ch13-keygenme/keygenme_O0`, `binaries/ch14-crypto/crypto_O0`, `binaries/ch13-network/client_O0`  
> 📖 **Prerequisites**: [13.3 — Hooking C and C++ functions](/13-frida/03-hooking-c-cpp-functions.md), [13.4 — Intercepting calls](/13-frida/04-intercepting-calls.md)

---

## Moving from observation to intervention

Until now, our Frida hooks were **passive sensors**: we read arguments, inspected return values, logged data — without ever changing the program's behavior. That's already extremely powerful for understanding a binary, but reverse engineering doesn't stop at understanding. You often want to **test hypotheses** by modifying behavior on the fly.

A verification function returns `0` (failure)? You want to force `1` to see what happens next in the program. A `connect` call points to an unreachable remote server? You want to redirect to `127.0.0.1`. The program reads a configuration file with limits? You want to rewrite the values in memory before they're processed.

With GDB, these modifications are possible but manual: you set a breakpoint, modify a register with `set $rax = 1`, continue. With Frida, they're **scriptable and automatic** — each function invocation is intercepted and modified without human intervention, for the entire duration of execution.

---

## Modifying a return value with `retval.replace`

### The mechanism

In the `onLeave` callback, the `retval` parameter is a `NativePointer` representing the function's return value (the content of `rax` after the `ret`). Frida exposes a `.replace()` method that replaces this value before it's transmitted to the caller:

```javascript
Interceptor.attach(addr, {
    onLeave(retval) {
        retval.replace(new_value);
    }
});
```

The original function executes normally, produces its return value, then the exit trampoline calls `onLeave`, where `retval.replace()` overwrites `rax` with the new value. The caller receives the modified value without knowing it was altered.

> ⚠️ **`retval.replace()`, not assignment.** Writing `retval = ptr(1)` doesn't work — it reassigns the local JavaScript variable without affecting the register. You must use the `.replace()` method which modifies the value in the target process's CPU context.

### Forcing a verification function's return

The most classic RE scenario: a `check_password` function returns `0` (failure) or `1` (success). We force the return to `1` to bypass the verification.

```javascript
const base = Process.enumerateModules()[0].base;  
const check_addr = base.add(0x11a9);  // offset from Ghidra  

Interceptor.attach(check_addr, {
    onEnter(args) {
        this.input = args[0].readUtf8String();
    },
    onLeave(retval) {
        const original = retval.toInt32();
        if (original === 0) {
            console.log(`check_password("${this.input}") = ${original} → forced to 1`);
            retval.replace(ptr(1));
        } else {
            console.log(`check_password("${this.input}") = ${original} (already OK)`);
        }
    }
});
```

This hook is the dynamic equivalent of the binary patching seen in Chapter 21 (section 21.6), where we inverted a `jz` to `jnz` in ImHex. The fundamental difference: here, the on-disk binary is not modified, and the modification is conditional — you could force the return only for certain inputs, or alternate between original and modified behavior to observe consequences.

### Forcing library function returns

The same pattern works on libc functions. Example: make the program believe that `strcmp` always returns `0` (equality):

```javascript
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        this.s1 = args[0].readUtf8String();
        this.s2 = args[1].readUtf8String();
    },
    onLeave(retval) {
        console.log(`strcmp("${this.s1}", "${this.s2}") = ${retval.toInt32()} → forced to 0`);
        retval.replace(ptr(0));
    }
});
```

> ⚠️ **Massive side effect.** Forcing `strcmp` to always return `0` affects **all** `strcmp` calls in the program, including libc's own internal ones (locale resolution, internal configuration parsing, etc.). The program may crash or behave erratically. You must always filter to modify only the relevant calls.

### Selective modification with filtering

```javascript
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        this.s1 = args[0].readUtf8String();
        this.s2 = args[1].readUtf8String();
        // Only modify if one of the arguments looks like a key or password
        this.shouldPatch = (this.s1 && this.s1.length > 4 && this.s1.length < 64) &&
                           (this.s2 && this.s2.length > 4 && this.s2.length < 64);
    },
    onLeave(retval) {
        if (this.shouldPatch && retval.toInt32() !== 0) {
            console.log(`[PATCH] strcmp("${this.s1}", "${this.s2}") → forced to 0`);
            retval.replace(ptr(0));
        }
    }
});
```

Or better still, filter by caller to only target `strcmp` invoked by the verification function:

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        this.fromMain = this.returnAddress.compare(modBase) >= 0 &&
                        this.returnAddress.compare(modEnd) < 0;
        if (this.fromMain) {
            this.s1 = args[0].readUtf8String();
            this.s2 = args[1].readUtf8String();
        }
    },
    onLeave(retval) {
        if (this.fromMain) {
            console.log(`[main] strcmp("${this.s1}", "${this.s2}") → forced to 0`);
            retval.replace(ptr(0));
        }
        // strcmp calls from libc remain intact
    }
});
```

---

## Modifying arguments in `onEnter`

### Rewriting an argument passed by value

Integer and pointer arguments passed by value can be modified directly in the `args` array:

```javascript
// open(const char *pathname, int flags, mode_t mode)
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter(args) {
        const path = args[0].readUtf8String();

        // Redirect reading of a license file to our custom file
        if (path === "/opt/app/license.dat") {
            const fakePath = Memory.allocUtf8String("/tmp/fake_license.dat");
            args[0] = fakePath;
            console.log(`[REDIRECT] open(): "${path}" → "/tmp/fake_license.dat"`);
        }
    }
});
```

`Memory.allocUtf8String` allocates a new string in the target process's heap and returns a `NativePointer` to this allocation. By assigning this pointer to `args[0]`, we replace the `pathname` argument before `open` uses it. The `open` function will open `/tmp/fake_license.dat` instead of `/opt/app/license.dat`.

> 💡 **Allocation lifetime.** `Memory.allocUtf8String` allocates in a zone managed by Frida. The memory remains valid as long as the script is loaded. For hooks called a very large number of times, these allocations accumulate. If it's a problem, you can reuse a pre-allocated buffer.

### Rewriting an integer argument

For arguments passed by value (integers, flags, sizes), direct assignment in `args` works with `ptr()`:

```javascript
// Force the O_RDONLY flag on every open call
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter(args) {
        const path = args[0].readUtf8String();
        const flags = args[1].toInt32();

        if (flags & 0x1) {  // O_WRONLY or O_RDWR
            console.log(`[PATCH] open("${path}"): flags 0x${flags.toString(16)} → O_RDONLY`);
            args[1] = ptr(0x0);  // O_RDONLY
        }
    }
});
```

This hook prevents the program from writing to files — any attempt to open in write mode is downgraded to read-only. Useful in a sandbox context or to observe malware without letting it modify the filesystem.

### Modifying a pointed buffer's content

When an argument is a pointer to a buffer, modifying `args[i]` changes the pointer itself (which buffer the function will read from). But you can also modify the **content** of the original buffer, without changing the pointer:

```javascript
// send(int sockfd, const void *buf, size_t len, int flags)
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        const len = args[2].toInt32();
        const buf = args[1];

        console.log(`send() original (${len} bytes):`);
        console.log(hexdump(buf, { length: Math.min(len, 64) }));

        // Rewrite the first 4 bytes of the buffer
        buf.writeU8(0x41);          // offset 0: 'A'
        buf.add(1).writeU8(0x42);   // offset 1: 'B'
        buf.add(2).writeU8(0x43);   // offset 2: 'C'
        buf.add(3).writeU8(0x44);   // offset 3: 'D'

        console.log(`send() modified:`);
        console.log(hexdump(buf, { length: Math.min(len, 64) }));
    }
});
```

The distinction is important:

- **`args[1] = otherPtr`** — changes the pointer: the function will read a completely different buffer.  
- **`args[1].writeU8(0x41)`** — changes the content at the original address: the function will read the same buffer, but its content has been altered.

The first approach is safer (original buffer stays intact), the second is simpler when you want to modify a few bytes.

### Replacing an entire buffer

To replace a buffer's complete content with arbitrary data:

```javascript
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        const originalLen = args[2].toInt32();

        // Prepare a new buffer with our content
        const payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        const newBuf = Memory.alloc(payload.length);
        newBuf.writeByteArray(payload);

        // Replace the pointer and the size
        args[1] = newBuf;
        args[2] = ptr(payload.length);

        console.log(`[PATCH] send(): buffer replaced (${payload.length} bytes)`);
    }
});
```

We allocate a new buffer with `Memory.alloc`, write the desired content with `writeByteArray`, then redirect pointer `args[1]` and adjust size `args[2]`. The `send` function will send our payload instead of the original data.

---

## Modifying process memory: `Memory.write*` methods

Beyond modifying arguments in hooks, Frida allows writing directly to the process's memory at any time. It's the equivalent of GDB's `set` command, but scriptable.

### Writing primitive types

```javascript
const addr = ptr("0x7f3a8c001000");

// Write a byte
addr.writeU8(0xFF);

// Write a 32-bit integer
addr.writeS32(-1);          // signed  
addr.add(4).writeU32(42);   // unsigned  

// Write a 64-bit integer
addr.writeU64(uint64("0xDEADBEEFCAFEBABE"));

// Write a float
addr.writeFloat(3.14);  
addr.writeDouble(2.718281828);  

// Write a pointer
addr.writePointer(ptr("0x401000"));
```

### Writing strings and buffers

```javascript
// Write a UTF-8 string (with null terminator)
addr.writeUtf8String("Hello from Frida");

// Write a byte array
addr.writeByteArray([0x90, 0x90, 0x90, 0x90]);  // 4 x NOP
```

### Memory protections

Any write requires the target memory page to have write permission (`w`). The `.text` (code) and `.rodata` (constants) sections are normally read-only. Attempting to write there directly causes a crash (`SIGSEGV`).

Frida provides `Memory.protect` to modify permissions:

```javascript
const codeAddr = ptr("0x555555555189");

// Make the page readable + writable + executable
Memory.protect(codeAddr, 4096, 'rwx');

// Now we can write to the code
codeAddr.writeByteArray([0x90, 0x90]);  // replace 2 bytes with NOPs

// Restore original permissions
Memory.protect(codeAddr, 4096, 'r-x');
```

> ⚠️ `Memory.protect` granularity is the page (4096 bytes on x86-64). Changing permissions of one address affects the entire page containing it. Restore permissions after modification to minimize the attack surface.

---

## In-memory binary patching

Memory modification opens the door to **in-memory patching** — rewriting machine instructions directly in the `.text` section, without touching the on-disk file. It's the live equivalent of hexadecimal patching in ImHex (Chapter 21, section 21.6).

### Replacing a conditional jump

Classic crackme scenario: a `jz` instruction (jump if zero, opcode `0x74`) must be transformed into `jnz` (jump if not zero, opcode `0x75`), or vice versa.

```javascript
const base = Process.enumerateModules()[0].base;

// Address of the jz to patch (offset found in Ghidra)
const jzAddr = base.add(0x1205);

// Check the current opcode
const currentOpcode = jzAddr.readU8();  
console.log(`Current opcode @ ${jzAddr}: 0x${currentOpcode.toString(16)}`);  

if (currentOpcode === 0x74) {  // jz (short)
    Memory.protect(jzAddr, 4096, 'rwx');
    jzAddr.writeU8(0x75);  // jnz (short)
    Memory.protect(jzAddr, 4096, 'r-x');
    console.log("[PATCH] jz → jnz");
} else {
    console.log("[!] Unexpected opcode, aborting patch");
}
```

Verifying the opcode before writing is an essential precaution. If ASLR shifted addresses differently than expected, or if the binary was updated, you'd write at the wrong place. Always validate before modifying.

### NOPing an instruction or a block

Replacing instructions with `NOP` (`0x90`) is a classic technique for disabling a code block — a license check, a call to `exit`, a delay loop:

```javascript
const base = Process.enumerateModules()[0].base;

// NOP a 5-byte call (opcode E8 + 4 offset bytes)
// For example a call to an anti-debug function
const callAddr = base.add(0x120a);

Memory.protect(callAddr, 4096, 'rwx');  
callAddr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);  // 5 NOPs  
Memory.protect(callAddr, 4096, 'r-x');  

console.log("[PATCH] anti_debug call NOP'd");
```

A `call rel32` on x86-64 is 5 bytes (1 for opcode `0xE8`, 4 for relative displacement). We replace all 5 bytes with 5 `NOP`s so the processor passes through without doing anything. Execution flow continues normally after the vanished `call` location.

### `Memory.patchCode`: the clean method

For code patching, Frida offers `Memory.patchCode`, which automatically handles memory permissions and instruction cache flushing (necessary on some architectures):

```javascript
const base = Process.enumerateModules()[0].base;  
const target = base.add(0x1205);  

Memory.patchCode(target, 1, code => {
    code.putU8(0x75);  // jnz
});
```

`Memory.patchCode` takes the target address, the zone size to modify, and a callback that receives a writer. The writer offers methods like `putU8`, `putBytes`, etc. This approach is more robust than manual modification because it handles low-level details (instruction cache flush, modification atomicity).

---

## Network flow redirection

A frequent use case in network binary RE (Chapter 23): redirecting connections to a server you control.

### Modifying the IP address in `connect`

```javascript
Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter(args) {
        const sockaddr = args[1];
        const family = sockaddr.readU16();

        if (family === 2) {  // AF_INET
            const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            const origIp = [
                sockaddr.add(4).readU8(),
                sockaddr.add(5).readU8(),
                sockaddr.add(6).readU8(),
                sockaddr.add(7).readU8()
            ].join('.');

            console.log(`[*] connect() original: ${origIp}:${port}`);

            // Redirect to 127.0.0.1
            sockaddr.add(4).writeU8(127);
            sockaddr.add(5).writeU8(0);
            sockaddr.add(6).writeU8(0);
            sockaddr.add(7).writeU8(1);

            console.log(`[REDIRECT] → 127.0.0.1:${port}`);
        }
    }
});
```

Here, we directly modify the `sockaddr_in` structure in memory, in the buffer the program prepared. When `connect` executes, it uses the modified address. The program believes it's connecting to the remote server, but the connection lands on `127.0.0.1`.

### Modifying the port

You can also redirect to a different port:

```javascript
// Redirect port 443 to 8080
if (port === 443) {
    // sin_port is in network byte order (big-endian)
    const newPort = 8080;
    sockaddr.add(2).writeU8((newPort >> 8) & 0xFF);  // high byte
    sockaddr.add(3).writeU8(newPort & 0xFF);          // low byte
    console.log(`[REDIRECT] port 443 → 8080`);
}
```

Watch the byte order: `sin_port` is stored in big-endian (network byte order), while x86-64 is little-endian. We write both bytes separately in the right order.

### Application: simulating a C2 server

This redirection pattern is fundamental for malware analysis (Chapter 28). The dropper attempts to contact a remote C2 server. By redirecting `connect` to `127.0.0.1`, you can run your own fake C2 server there and observe the communication protocol without ever contacting the real malicious infrastructure.

---

## Modifying environment variables and system function returns

### Making `getenv` lie

```c
char *getenv(const char *name);
```

```javascript
Interceptor.attach(Module.findExportByName(null, "getenv"), {
    onEnter(args) {
        this.name = args[0].readUtf8String();
    },
    onLeave(retval) {
        if (this.name === "LICENSE_KEY") {
            const fakeValue = Memory.allocUtf8String("VALID-KEY-12345");
            retval.replace(fakeValue);
            console.log(`[PATCH] getenv("LICENSE_KEY") → "VALID-KEY-12345"`);
        }
    }
});
```

The program calls `getenv("LICENSE_KEY")` to read an environment variable. Our hook intercepts the return and replaces it with a key of our choice, without needing to actually define the variable.

### Making `time` and `gettimeofday` lie

Some programs check an expiration date or use time as a seed for a pseudo-random generator. Controlling the time perceived by the program is a powerful lever:

```javascript
// time(time_t *tloc)
Interceptor.attach(Module.findExportByName(null, "time"), {
    onLeave(retval) {
        // Freeze time to January 1, 2024 00:00:00 UTC
        const fakeTime = 1704067200;
        retval.replace(ptr(fakeTime));
        console.log(`[PATCH] time() → ${fakeTime} (2024-01-01)`);
    }
});
```

This allows bypassing time-based license-expiration checks, or making reproducible a behavior that depends on `time()` as a PRNG seed.

### Disabling `ptrace` (anti-anti-debug)

As seen in section 13.1, some programs call `ptrace(PTRACE_TRACEME, ...)` to detect a debugger. You can neutralize this check:

```javascript
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter(args) {
        this.request = args[0].toInt32();
    },
    onLeave(retval) {
        if (this.request === 0) {  // PTRACE_TRACEME
            retval.replace(ptr(0));  // Simulate success
            console.log("[PATCH] ptrace(PTRACE_TRACEME) → 0 (simulated success)");
        }
    }
});
```

The program believes `ptrace(PTRACE_TRACEME)` succeeded (return `0`), meaning no debugger is attached. In reality, Frida already released `ptrace` after injection (section 13.1), so this check would fail if we didn't neutralize it. This technique is deepened in Chapter 19 (section 19.7).

---

## Directly modifying the CPU context

For cases where modifying arguments and return values isn't enough, Frida gives access to the **complete CPU context** — all registers — via `this.context` in hook callbacks.

### Reading registers

```javascript
Interceptor.attach(addr, {
    onEnter(args) {
        const ctx = this.context;

        console.log("Registers:");
        console.log(`  rax = ${ctx.rax}`);
        console.log(`  rbx = ${ctx.rbx}`);
        console.log(`  rcx = ${ctx.rcx}`);
        console.log(`  rdx = ${ctx.rdx}`);
        console.log(`  rdi = ${ctx.rdi}`);
        console.log(`  rsi = ${ctx.rsi}`);
        console.log(`  rsp = ${ctx.rsp}`);
        console.log(`  rbp = ${ctx.rbp}`);
        console.log(`  rip = ${ctx.rip}`);
        console.log(`  r8  = ${ctx.r8}`);
        console.log(`  r9  = ${ctx.r9}`);
    }
});
```

### Modifying registers

Registers are read-write. You can modify any register, including the instruction pointer (`rip`) — though modifying `rip` is extremely dangerous and rarely necessary:

```javascript
Interceptor.attach(addr, {
    onEnter(args) {
        // Modify rax (for example to change a counter)
        this.context.rax = ptr(42);

        // Modify a flag via a register
        this.context.rdx = ptr(0);
    }
});
```

Modifying `this.context` in `onEnter` takes effect **before** the function executes. In `onLeave`, it takes effect at the moment of return to the caller. Modifying `rax` in `onLeave` is functionally equivalent to `retval.replace()`.

### Use case: jumping over a code block

You can modify `rip` in a hook placed at the beginning of an undesirable block to jump directly to the end:

```javascript
const base = Process.enumerateModules()[0].base;  
const antiDebugStart = base.add(0x1300);  // anti-debug block start  
const antiDebugEnd = base.add(0x1350);    // instruction after the block  

Interceptor.attach(antiDebugStart, {
    onEnter(args) {
        console.log("[SKIP] Anti-debug block skipped");
        this.context.rip = antiDebugEnd;
    }
});
```

> ⚠️ Modifying `rip` is a delicate operation. If the destination address isn't a valid instruction, or if the stack state doesn't match what the destination code expects, the program will crash. This technique requires precise understanding of the assembly code at both ends of the jump.

---

## Orchestrating modifications from Python

Previous examples show unconditional modifications (force to `1`, always redirect). In practice, you often want to dynamically decide — from the Python script — which modifications to apply. The `send()`/`on_message` channel is bidirectional: the JavaScript agent can receive messages from the Python client via `recv()`.

### Bidirectional communication

```javascript
// Agent side (JavaScript)
Interceptor.attach(check_addr, {
    onLeave(retval) {
        const original = retval.toInt32();

        // Ask the Python client if we should patch
        send({ event: "check_result", value: original });

        // Wait for the client's response
        const op = recv('patch_decision', value => {
            if (value.payload.patch === true) {
                retval.replace(ptr(1));
                console.log("[PATCH] Return forced to 1 by Python decision");
            }
        });
        op.wait();  // Blocks until response is received
    }
});
```

```python
# Client side (Python)
def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('event') == 'check_result':
            original = payload['value']
            # Decision logic on Python side
            should_patch = (original == 0)
            script.post({'type': 'patch_decision', 'patch': should_patch})

script.on('message', on_message)
```

`recv()` on the JavaScript side blocks hook execution until the Python client sends a message via `script.post()`. This enables an interactive loop: the agent signals an event, Python decides the action, the agent executes it.

> ⚠️ `recv().wait()` blocks the target process's thread. If the Python response is slow to arrive, the program is frozen. For frequently called functions, prefer an asynchronous approach where patching decisions are sent in advance, stored in a JavaScript variable, and consulted non-blockingly.

### Non-blocking approach with pre-sent configuration

```javascript
// Agent side: configuration modifiable on the fly
let patchConfig = {
    forceReturn: false,
    returnValue: 0
};

// Listen for configuration updates without blocking
recv('update_config', msg => {
    patchConfig = msg.payload;
    console.log("[*] Config updated:", JSON.stringify(patchConfig));
});

Interceptor.attach(check_addr, {
    onLeave(retval) {
        if (patchConfig.forceReturn) {
            retval.replace(ptr(patchConfig.returnValue));
        }
    }
});
```

```python
# Python side: send a new config at any time
script.post({'type': 'update_config', 'forceReturn': True, 'returnValue': 1})

# Later, disable patching
script.post({'type': 'update_config', 'forceReturn': False, 'returnValue': 0})
```

This approach is non-blocking: the hook consults the `patchConfig` variable without waiting for a response. The Python client can update the configuration at any time, and the modification takes effect on the next call to the hooked function.

---

## Modification methods summary

| What you want to modify | Where to do it | Method |  
|---|---|---|  
| Function's return value | `onLeave` | `retval.replace(ptr(value))` |  
| Argument passed by value (int, pointer) | `onEnter` | `args[i] = ptr(value)` |  
| Content of a buffer pointed to by an argument | `onEnter` | `args[i].writeU8(...)`, `.writeByteArray(...)` |  
| Replace an entire buffer | `onEnter` | `args[i] = Memory.alloc(...)` + fill |  
| Arbitrary CPU register | `onEnter` or `onLeave` | `this.context.reg = ptr(value)` |  
| Machine instruction in `.text` | Any time | `Memory.patchCode(addr, size, writer)` |  
| Arbitrary memory (data, heap, stack) | Any time | `ptr(addr).writeU32(...)`, etc. |  
| Entire function (replace its logic) | Initialization | `Interceptor.replace(addr, NativeCallback(...))` |

---

## What to remember

- **`retval.replace()`** is the method for modifying the return value — not direct assignment. It's the most used technique for bypassing checks (license, anti-debug, validation).  
- **`args[i] = ptr()`** replaces an argument by value or a pointer. **`args[i].write*()`** modifies the pointed buffer's content.  
- **Always filter** modifications to target only relevant calls (by caller, by argument content). An unfiltered modification on `strcmp` or `malloc` causes unpredictable behavior.  
- **`Memory.patchCode`** allows in-memory instruction patching (jz→jnz, NOP) without modifying the on-disk file.  
- **`this.context`** gives read-write access to all CPU registers, including `rip` — handle with care.  
- **Bidirectional** Python↔JavaScript communication (via `send`/`recv`/`post`) allows dynamically driving modifications from the Python client, in blocking or non-blocking mode.

---

> **Next section**: 13.6 — Stalker: tracing all executed instructions (dynamic code coverage) — we'll cover Frida's instruction-by-instruction tracing engine, a unique tool for exhaustive mapping of executed code.

⏭️ [Stalker: tracing all executed instructions (dynamic code coverage)](/13-frida/06-stalker-code-coverage.md)
