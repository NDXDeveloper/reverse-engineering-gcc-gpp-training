🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.7 — Practical case: bypassing a license check

> 🧰 **Tools used**: `frida`, `frida-trace`, Python 3 + `frida` module, Ghidra (static analysis results)  
> 📦 **Binary used**: `binaries/ch13-keygenme/keygenme_O0`  
> 📖 **Prerequisites**: All previous sections of Chapter 13

---

## Objective

This practical case mobilizes all the Frida techniques seen in this chapter — from reconnaissance with `frida-trace` to automated bypassing in Python, through code coverage with Stalker. The objective is not just to bypass the verification: it's to demonstrate a **reproducible methodology** applicable to any protected binary.

The `keygenme_O0` binary is a crackme compiled with GCC without optimizations (`-O0`) and with debug symbols. It asks the user for a key and displays a success or failure message. We'll treat it as if we only had the binary — without looking at the source code.

The journey unfolds in five phases, reflecting the reverse engineer's natural methodology facing software protection:

1. **Reconnaissance** — identify functions involved in verification.  
2. **Localization** — precisely target the decision routine.  
3. **Understanding** — analyze the verification logic.  
4. **Bypass** — modify behavior to accept any key.  
5. **Extraction** — recover the valid key without modifying the program.

---

## Phase 1 — Reconnaissance with `frida-trace`

The first question facing an unknown binary is always: *which library functions does it use, and in what order?* `frida-trace` gives the answer in seconds.

### Tracing string and I/O functions

A crackme that verifies a key necessarily uses comparison functions (`strcmp`, `strncmp`, `memcmp`) and I/O functions (`printf`, `puts`, `scanf`, `fgets`). Let's start by tracing this family:

```bash
frida-trace -f ./keygenme_O0 -i "strcmp" -i "strncmp" -i "memcmp" \
            -i "printf" -i "puts" -i "scanf" -i "fgets" -i "strlen"
```

The program starts, displays its prompt, and waits for input. Let's type an arbitrary key — `AAAA`:

```
Instrumenting...
           /* TID 0x7a3b */
   142 ms  puts("=== KeyGenMe v1.0 ===")
   142 ms  puts("Enter the license key:")
   142 ms  scanf()
  3891 ms  strlen("AAAA")
  3891 ms  strcmp("AAAA", "GCC-RE-2024-XPRO")
  3891 ms  puts("Invalid key. Access denied.")
```

In a single command, without breakpoints, without Ghidra, without a single line of JavaScript, the trace reveals:

- The expected key: `"GCC-RE-2024-XPRO"` (second argument of `strcmp`).  
- The verification flow: `scanf` reads input, `strlen` checks its length, `strcmp` compares with the hardcoded key.  
- The failure message: `"Invalid key. Access denied."`.

For a `-O0` binary with symbols, the work is already done. But in reality, things are rarely this simple — the key can be dynamically computed, the comparison can be custom, the binary can be stripped and optimized. Let's continue the methodology as if the key hadn't been directly visible.

### Broadening the reconnaissance

Let's now trace all functions of the main binary to see the structure of internal calls:

```bash
frida-trace -f ./keygenme_O0 -I "keygenme_O0"
```

```
           /* TID 0x7a3b */
   142 ms  main()
   142 ms     | print_banner()
   142 ms     | read_input()
  3891 ms     | validate_key()
  3891 ms     |    | compute_hash()
  3891 ms     |    | check_hash()
  3891 ms     | print_result()
```

The hierarchy is clear: `main` calls `validate_key`, which calls `compute_hash` then `check_hash`. It's `validate_key` that encapsulates the decision logic.

---

## Phase 2 — Locating the decision routine

Reconnaissance identified `validate_key` as the pivot function. Let's confirm with a Frida hook that observes its behavior:

```javascript
// recon_validate.js
'use strict';

const validate = Module.findExportByName(null, "validate_key");

if (validate) {
    Interceptor.attach(validate, {
        onEnter(args) {
            try {
                this.input = args[0].readUtf8String();
                console.log(`\n[*] validate_key("${this.input}")`);
            } catch (e) {
                console.log(`\n[*] validate_key(${args[0]})`);
            }
        },
        onLeave(retval) {
            const result = retval.toInt32();
            console.log(`[*] validate_key() → ${result}`);
            console.log(`    Interpretation: ${result === 1 ? 'VALID' : 'INVALID'}`);
        }
    });
} else {
    console.log("[!] validate_key symbol not found — stripped binary?");
}
```

```bash
frida -f ./keygenme_O0 -l recon_validate.js --no-pause
```

Result with input `test123`:

```
[*] validate_key("test123")
[*] validate_key() → 0
    Interpretation: INVALID
```

Confirmation: `validate_key` returns `0` for an incorrect input. The natural hypothesis is that `1` corresponds to a valid input. The next step is to verify this hypothesis by forcing the return value.

### Phase 2b — If the binary were stripped

On a stripped binary (`keygenme_O2_strip`), the `validate_key` symbol doesn't exist. You must find the address by other means. Here's the combined Stalker + caller-filtering approach:

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        if (this.returnAddress.compare(modBase) >= 0 &&
            this.returnAddress.compare(modEnd) < 0) {

            const caller = this.returnAddress;
            const offset = caller.sub(modBase);
            console.log(`[*] strcmp() called from the main binary`);
            console.log(`    Return address: ${caller} (offset 0x${offset.toString(16)})`);
            console.log(`    Backtrace:`);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n    '));
        }
    }
});
```

The backtrace reveals the call chain leading to `strcmp`, and therefore the verification function's offset. You then use it with `base.add(offset)` as seen in section 13.3.

---

## Phase 3 — Understanding with Stalker

Before bypassing, let's try to understand the verification logic. Let's activate Stalker during `validate_key`'s execution to see which code blocks are traversed, and compare two executions.

### Comparative coverage

```javascript
// coverage_compare.js
'use strict';

const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  
const validate = Module.findExportByName(null, "validate_key");  
const covered = new Set();  

Interceptor.attach(validate, {
    onEnter(args) {
        this.input = args[0].readUtf8String();
        this.tid = Process.getCurrentThreadId();

        Stalker.follow(this.tid, {
            transform(iterator) {
                let insn = iterator.next();
                const addr = insn.address;
                if (addr.compare(modBase) >= 0 && addr.compare(modEnd) < 0) {
                    covered.add(addr.sub(modBase).toInt32());
                }
                do { iterator.keep(); } while ((insn = iterator.next()) !== null);
            }
        });
    },
    onLeave(retval) {
        Stalker.unfollow(this.tid);
        Stalker.flush();
        Stalker.garbageCollect();

        send({
            input: this.input,
            result: retval.toInt32(),
            blocks: Array.from(covered)
        });
        covered.clear();
    }
});
```

The Python script collects both traces and compares them:

```python
import frida, sys, time, json

results = []

def on_message(msg, data):
    if msg['type'] == 'send':
        results.append(msg['payload'])

def run_with_input(binary, user_input):
    pid = frida.spawn([binary])
    session = frida.attach(pid)
    with open("coverage_compare.js") as f:
        code = f.read()
    script = session.create_script(code)
    script.on('message', on_message)
    script.load()
    frida.resume(pid)
    time.sleep(1)
    time.sleep(2)
    session.detach()

# Compare results
if len(results) >= 2:
    blocks_a = set(results[0]['blocks'])
    blocks_b = set(results[1]['blocks'])

    only_a = blocks_a - blocks_b
    only_b = blocks_b - blocks_a

    print(f"\nInput A ('{results[0]['input']}'): {len(blocks_a)} blocks, "
          f"return={results[0]['result']}")
    print(f"Input B ('{results[1]['input']}'): {len(blocks_b)} blocks, "
          f"return={results[1]['result']}")
    print(f"\nBlocks specific to A: {len(only_a)}")
    for off in sorted(only_a):
        print(f"  0x{off:x}")
    print(f"Blocks specific to B: {len(only_b)}")
    for off in sorted(only_b):
        print(f"  0x{off:x}")
```

Blocks specific to the valid execution correspond to the verification's "success" branch. Those specific to the invalid execution correspond to the "failure" branch. Examining these offsets in Ghidra reveals exactly the `if/else` structure that decides the outcome.

### What coverage reveals

For `keygenme_O0`, comparative coverage typically shows:

- A common block that calls `compute_hash` and `strcmp` — the verification core.  
- A block specific to the valid input that calls `puts("Valid key! Access granted.")`.  
- A block specific to the invalid input that calls `puts("Invalid key. Access denied.")`.  
- The difference lies at a single conditional jump — exactly the `jz`/`jnz` you'd patch in ImHex (Chapter 21, section 21.6).

---

## Phase 4 — Bypass

We now have a complete understanding of the verification. Three bypass approaches present themselves, from simplest to most elegant.

### Approach 1: force `validate_key`'s return value

The most direct method — force `validate_key` to return `1` regardless of input:

```javascript
// bypass_v1.js — force the return
'use strict';

const validate = Module.findExportByName(null, "validate_key");

Interceptor.attach(validate, {
    onEnter(args) {
        this.input = args[0].readUtf8String();
    },
    onLeave(retval) {
        const original = retval.toInt32();
        if (original !== 1) {
            retval.replace(ptr(1));
            console.log(`[BYPASS] validate_key("${this.input}"): ${original} → 1`);
        }
    }
});

console.log("[*] Bypass v1 active — validate_key() forced to 1");
```

```bash
frida -f ./keygenme_O0 -l bypass_v1.js --no-pause
```

Result:

```
[*] Bypass v1 active — validate_key() forced to 1
=== KeyGenMe v1.0 ===
Enter the license key:  
anythingatall  
[BYPASS] validate_key("anythingatall"): 0 → 1
Valid key! Access granted.
```

The program accepts any key. It's the fastest bypass, but it has a limitation: it teaches us nothing about the valid key. The program thinks the key is correct, but we don't know which key would be legitimately accepted.

### Approach 2: force `strcmp`'s return

If verification relies on a `strcmp`, we can target this specific function rather than the wrapper:

```javascript
// bypass_v2.js — force strcmp to return 0 (equality)
'use strict';

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
        if (this.fromMain && retval.toInt32() !== 0) {
            console.log(`[BYPASS] strcmp("${this.s1}", "${this.s2}") → forced to 0`);
            retval.replace(ptr(0));
        }
    }
});

console.log("[*] Bypass v2 active — strcmp forced to 0 (from main module)");
```

This approach is more precise: it only modifies `strcmp` calls initiated by the binary, not libc's. And it has a major advantage — the `strcmp` arguments are logged, giving us the expected key for free.

### Approach 3: memory patching of the conditional jump

For a persistent bypass throughout the session (without an active hook at each call), you can patch the branch instruction in memory:

```javascript
// bypass_v3.js — patch jz to jnz
'use strict';

const mod = Process.enumerateModules()[0];  
const base = mod.base;  

// jz offset identified by Ghidra or by comparative coverage
const jzOffset = 0x1234;  // Adapt to the actual binary  
const jzAddr = base.add(jzOffset);  

const opcode = jzAddr.readU8();  
console.log(`[*] Opcode @ offset 0x${jzOffset.toString(16)}: 0x${opcode.toString(16)}`);  

if (opcode === 0x74) {       // jz short
    Memory.patchCode(jzAddr, 1, code => { code.putU8(0x75); });
    console.log("[PATCH] jz (0x74) → jnz (0x75)");
} else if (opcode === 0x0F) {  // jz near (0F 84)
    const secondByte = jzAddr.add(1).readU8();
    if (secondByte === 0x84) {
        Memory.patchCode(jzAddr.add(1), 1, code => { code.putU8(0x85); });
        console.log("[PATCH] jz near (0F 84) → jnz near (0F 85)");
    }
} else {
    console.log(`[!] Unexpected opcode 0x${opcode.toString(16)}, aborting`);
}
```

This patch needs no active hook — once the opcode is modified in memory, the verification is permanently inverted (for this execution session). The overhead is zero.

> 💡 **Finding the jump offset.** The comparative coverage from phase 3 identifies blocks that differ between valid and invalid input. The last common block before the divergence ends with the target conditional jump. In Ghidra, this information is visible in the Function Graph.

---

## Phase 5 — Key extraction

Bypassing verification is useful for understanding what happens "behind the wall". But the ultimate goal is often to **recover the valid key** — to write a keygen (Chapter 21, section 21.8) or to understand the generation algorithm.

### Passive extraction via `strcmp`

The simplest method — already illustrated in phase 1 — consists of reading `strcmp`'s arguments:

```javascript
// extract_key.js
'use strict';

const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        if (this.returnAddress.compare(modBase) >= 0 &&
            this.returnAddress.compare(modEnd) < 0) {

            const s1 = args[0].readUtf8String();
            const s2 = args[1].readUtf8String();

            send({
                event: 'strcmp',
                user_input: s1,
                expected_key: s2,
                caller_offset: '0x' + this.returnAddress.sub(modBase).toString(16)
            });
        }
    }
});
```

```python
def on_message(message, data):
    if message['type'] == 'send':
        p = message['payload']
        if p.get('event') == 'strcmp':
            print(f"\n{'='*50}")
            print(f"  User input    : {p['user_input']}")
            print(f"  Expected key  : {p['expected_key']}")
            print(f"  Called from   : {p['caller_offset']}")
            print(f"{'='*50}")
```

Output:

```
==================================================
  User input    : test123
  Expected key  : GCC-RE-2024-XPRO
  Called from   : 0x1234
==================================================
```

### Extraction when the comparison is custom

If the binary doesn't use `strcmp` but a custom comparison function (byte-by-byte `for` loop, XOR, hash), direct extraction doesn't work. You must then intercept data upstream of the comparison.

Strategy: hook the `compute_hash` function (identified in phase 1) to capture the transformation applied to user input and the reference value:

```javascript
const compute_hash = Module.findExportByName(null, "compute_hash");

Interceptor.attach(compute_hash, {
    onEnter(args) {
        this.inputBuf = args[0];
        this.outputBuf = args[1];
        this.len = args[2].toInt32();

        console.log(`[*] compute_hash() — input (${this.len} bytes):`);
        console.log(hexdump(this.inputBuf, { length: this.len }));
    },
    onLeave(retval) {
        console.log(`[*] compute_hash() — output:`);
        console.log(hexdump(this.outputBuf, { length: 32 }));  // hash size
    }
});
```

You thus observe the transformation: what hash is produced from the input. By also hooking `check_hash`, you see the reference value against which the hash is compared. With both pieces of information, you can either invert the transformation (if it's simple), or use symbolic execution (Chapter 18) to find an input that produces the expected hash.

### Extraction via Stalker: observing byte-by-byte comparison

For custom comparisons that proceed byte by byte in a loop, Stalker with a callout on `cmp` instructions is the most direct approach:

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  
const validate = Module.findExportByName(null, "validate_key");  

const comparedBytes = [];

Interceptor.attach(validate, {
    onEnter(args) {
        this.tid = Process.getCurrentThreadId();

        Stalker.follow(this.tid, {
            transform(iterator) {
                let insn = iterator.next();
                do {
                    const addr = insn.address;
                    if (insn.mnemonic === 'cmp' &&
                        addr.compare(modBase) >= 0 &&
                        addr.compare(modEnd) < 0) {

                        iterator.putCallout((context) => {
                            const a = context.rax.toInt32() & 0xFF;
                            const b = context.rbx.toInt32() & 0xFF;
                            if (a >= 0x20 && a <= 0x7E && b >= 0x20 && b <= 0x7E) {
                                comparedBytes.push({
                                    user: String.fromCharCode(a),
                                    expected: String.fromCharCode(b)
                                });
                            }
                        });
                    }
                    iterator.keep();
                } while ((insn = iterator.next()) !== null);
            }
        });
    },
    onLeave(retval) {
        Stalker.unfollow(this.tid);
        Stalker.flush();
        Stalker.garbageCollect();

        if (comparedBytes.length > 0) {
            const expectedKey = comparedBytes.map(b => b.expected).join('');
            console.log(`\n[*] Compared bytes:`);
            comparedBytes.forEach((b, i) =>
                console.log(`  [${i}] user='${b.user}' vs expected='${b.expected}'`)
            );
            console.log(`\n[KEY] Reconstructed key: "${expectedKey}"`);
        }
        comparedBytes.length = 0;
    }
});
```

> ⚠️ The registers involved in the `cmp` depend on the actual assembly code. The script above assumes `cmp al, bl` — in practice, you must examine the instruction's operands in Ghidra to know which registers to read. The `insn.opStr` attribute in the `transform` callback gives operands in textual form (`"al, bl"`, `"byte ptr [rdi+rcx], dl"`, etc.) to guide this choice.

---

## Complete script: reconnaissance → automated extraction

Here is a single Python script that orchestrates the entire methodology — from reconnaissance to extraction — in an automated way:

```python
#!/usr/bin/env python3
"""
Frida automation — keygenme license bypass & key extraction.  
Usage: python3 solve_keygenme.py ./keygenme_O0  
"""
import frida  
import sys  
import time  

AGENT = r"""
'use strict';

const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

// Phase 1: Reconnaissance — which comparison functions are called?
const compareFuncs = ["strcmp", "strncmp", "memcmp"];  
const foundKeys = [];  

compareFuncs.forEach(name => {
    const addr = Module.findExportByName(null, name);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            this.fromMain = this.returnAddress.compare(modBase) >= 0 &&
                            this.returnAddress.compare(modEnd) < 0;
            if (this.fromMain) {
                try {
                    this.s1 = args[0].readUtf8String();
                    this.s2 = args[1].readUtf8String();
                } catch(e) {
                    this.fromMain = false;
                }
            }
        },
        onLeave(retval) {
            if (this.fromMain) {
                send({
                    phase: 'recon',
                    func: name,
                    s1: this.s1,
                    s2: this.s2,
                    result: retval.toInt32(),
                    caller: this.returnAddress.sub(modBase).toString(16)
                });
            }
        }
    });
});

// Phase 2: Bypass — force validate_key if it exists
const validate = Module.findExportByName(null, "validate_key");  
if (validate) {  
    Interceptor.attach(validate, {
        onLeave(retval) {
            const orig = retval.toInt32();
            if (orig !== 1) {
                retval.replace(ptr(1));
                send({ phase: 'bypass', original: orig, patched: 1 });
            }
        }
    });
    send({ phase: 'info', message: 'validate_key found and hooked' });
} else {
    send({ phase: 'info', message: 'validate_key not found — stripped binary' });
}
"""

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)

    binary = sys.argv[1]
    extracted_keys = set()

    def on_message(msg, data):
        if msg['type'] == 'send':
            p = msg['payload']
            phase = p.get('phase')

            if phase == 'info':
                print(f"[INFO] {p['message']}")

            elif phase == 'recon':
                func = p['func']
                s1, s2 = p['s1'], p['s2']
                result = p['result']
                print(f"\n[RECON] {func}(\"{s1}\", \"{s2}\") = {result}")
                print(f"        called from offset 0x{p['caller']}")

                for candidate in [s1, s2]:
                    if candidate and len(candidate) > 2:
                        extracted_keys.add(candidate)

                if result == 0:
                    print(f"  → MATCH! Key found in arguments.")

            elif phase == 'bypass':
                print(f"\n[BYPASS] validate_key: {p['original']} → {p['patched']}")

        elif msg['type'] == 'error':
            print(f"[ERROR] {msg['stack']}")

    print(f"[*] Launching {binary} with Frida...")
    pid = frida.spawn([binary])
    session = frida.attach(pid)

    script = session.create_script(AGENT)
    script.on('message', on_message)
    script.load()

    frida.resume(pid)
    print("[*] Hooks active. Interact with the program.")
    print("[*] Ctrl+C to stop.\n")

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass

    print(f"\n{'='*50}")
    print(f"[RESULT] Candidate keys extracted:")
    for key in extracted_keys:
        print(f"  → \"{key}\"")
    print(f"{'='*50}")

    session.detach()

if __name__ == '__main__':
    main()
```

Execution:

```bash
python3 solve_keygenme.py ./keygenme_O0
```

```
[*] Launching ./keygenme_O0 with Frida...
[INFO] validate_key found and hooked
[*] Hooks active. Interact with the program.

=== KeyGenMe v1.0 ===
Enter the license key:  
anythingatall  

[RECON] strcmp("anythingatall", "GCC-RE-2024-XPRO") = -7
        called from offset 0x1256

[BYPASS] validate_key: 0 → 1
Valid key! Access granted.

^C
==================================================
[RESULT] Candidate keys extracted:
  → "anythingatall"
  → "GCC-RE-2024-XPRO"
==================================================
```

The script simultaneously bypassed the verification (the program displays "Valid key") and extracted the expected key (`GCC-RE-2024-XPRO`). All in a single launch, without any manual interaction beyond entering an arbitrary input.

---

## Methodological synthesis

This practical case illustrates a five-phase workflow applicable to a wide range of protected binaries:

| Phase | Frida tool | What you get |  
|---|---|---|  
| **Reconnaissance** | `frida-trace -i "str*"` | List of called functions, execution flow |  
| **Localization** | `Interceptor.attach` + backtrace | Address and signature of the decision function |  
| **Understanding** | `Stalker` (comparative coverage) | Map of executed blocks, identification of the critical branch |  
| **Bypass** | `retval.replace` or `Memory.patchCode` | Program that accepts any input |  
| **Extraction** | Hook on `strcmp`/`memcmp` + argument reading | Valid key or reference data |

The three bypass approaches correspond to three levels of understanding:

- **Force `validate_key`** — black box, you don't understand the internal mechanism but you bypass the result.  
- **Force `strcmp`** — gray box, you know verification relies on a string comparison.  
- **Patch the `jz`** — white box, you identified the exact instruction making the decision.

In real RE, you often progress from black box to white box through the analysis. Frida lets you test each hypothesis instantly, without a recompilation cycle, and move to the next hypothesis in seconds.

---

## Limits and more complex cases

The `keygenme_O0` binary is deliberately simple — it's a learning exercise. Real-world protections present additional challenges:

**Multiple verifications.** Some programs perform several successive checks (key format, checksum, cryptographic signature). Bypassing the first isn't enough — you must identify and handle each one.

**Environment-derived key.** The valid key may depend on a hardware identifier, a username, or a timestamp. In that case, passive extraction only gives the key for this specific execution — a keygen must reproduce the derivation algorithm.

**Obfuscation.** The binary may use control flow flattening (Chapter 19, section 19.3), opaque predicates, or self-modifying code to make analysis harder. Stalker remains effective (it follows actually executed code, regardless of static obfuscation), but the volume of blocks to analyze explodes.

**Frida detection.** The program may scan `/proc/self/maps` for `frida-agent`, check thread count, or use timing checks. Chapter 19 (section 19.7) details these techniques and their countermeasures.

The following chapters of Part V (21 to 25) apply this methodology to progressively more complex scenarios — from simple string comparison to AES encryption with a derived key.

---

## What to remember

- The **reconnaissance → localization → understanding → bypass → extraction** methodology is a reproducible framework applicable to any protected binary.  
- `frida-trace` is the first-line tool: in one command, it reveals called functions and their arguments.  
- **Comparative coverage** with Stalker automatically identifies the code blocks responsible for the valid/invalid decision.  
- Three bypass levels: **verification function return** (fastest), **comparison function return** (more precise, reveals the key), **conditional jump patching** (most surgical).  
- A single Python script can combine reconnaissance, bypass, and extraction in a fully automated workflow.  
- Limitations (multiple checks, derived key, obfuscation, Frida detection) motivate the advanced techniques of following chapters.

---

> **Next step**: 🎯 Chapter 13 Checkpoint — write a Frida script that logs all calls to `send()` with their buffers, putting into practice the interception techniques seen throughout the chapter.

⏭️ [🎯 Checkpoint: write a Frida script that logs all calls to `send()` with their buffers](/13-frida/checkpoint.md)
