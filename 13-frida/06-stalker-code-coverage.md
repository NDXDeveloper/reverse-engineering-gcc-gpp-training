🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.6 — Stalker: tracing all executed instructions (dynamic code coverage)

> 🧰 **Tools used**: `frida`, Python 3 + `frida` module  
> 📦 **Binaries used**: `binaries/ch13-keygenme/keygenme_O0`, `binaries/ch25-fileformat/fileformat_O0`  
> 📖 **Prerequisites**: [13.3 — Hooking functions](/13-frida/03-hooking-c-cpp-functions.md), [13.5 — Modifying arguments and returns](/13-frida/05-modifying-arguments-returns.md), [Chapter 3 — x86-64 assembly](/03-x86-64-assembly/README.md)

---

## Beyond function hooking

With `Interceptor`, you place probes at the entry and exit of specific functions. It's surgical lighting — you illuminate exactly the points you chose, and the rest of the program remains in shadow. But some RE questions demand an overview: which instructions were executed? Which basic blocks were traversed? Which branch paths were taken — and which were never reached?

This is the domain of **dynamic code coverage**, and Frida answers it with a dedicated engine: **Stalker**.

Stalker follows a thread instruction by instruction, in real time, while it executes. It doesn't set breakpoints. It doesn't permanently modify the original code. Instead, it uses a technique called **dynamic binary translation**: the process's machine code is copied, instrumented on the fly, then executed from this copy. The target thread never traverses the original code — it permanently executes code translated by Stalker, which contains calls to your callbacks between each instruction, call, or branch.

The result: a complete execution trace, at the granularity you choose — instruction by instruction, basic block by basic block, or call by call.

---

## Operating principles

### Dynamic binary translation

When Stalker starts following a thread, it intercepts the execution flow and proceeds as follows:

1. **Reading the current basic block** — Stalker reads the machine instructions at the thread's current address, up to the next branch (a `jmp`, `jcc`, `call`, `ret`, or any instruction that modifies `rip`).

2. **Copying and instrumentation** — The block is copied into a memory zone managed by Stalker (the "slab"). Additional instructions are inserted in the copy — calls to your callbacks, counters, writes to an event buffer.

3. **Executing the copy** — The thread is redirected to the instrumented copy. It executes the translated block instead of the original.

4. **Branch following** — When the translated block ends (branch, call, ret), Stalker intercepts the destination, translates the next block, and the cycle repeats.

This process is transparent to the program: executed instructions produce exactly the same result as the originals, registers and memory evolve identically. The only observable difference is a slowdown — translated code is bulkier and callbacks add overhead.

### Difference with Interceptor

The distinction is fundamental and conditions tool choice:

| Criterion | Interceptor | Stalker |  
|---|---|---|  
| **Granularity** | Function entry/exit point | Each instruction, block, or call |  
| **Scope** | Explicitly chosen functions | All code executed by a thread |  
| **Overhead** | Minimal (one trampoline per hook) | Significant (all code translated) |  
| **Data produced** | Arguments and returns of targeted functions | Complete execution trace |  
| **Use case** | Observe/modify specific functions | Map executed code, analyze paths |

In practice, you use Stalker when you don't yet know which functions are interesting — when you want an overview before zooming in. Once zones are identified, switch back to Interceptor for targeted, performant hooking.

---

## Basic API: `Stalker.follow` and `Stalker.unfollow`

### Following a thread

```javascript
const threadId = Process.getCurrentThreadId();

Stalker.follow(threadId, {
    events: {
        call: true,    // trace CALL instructions
        ret: false,    // don't trace RETs
        exec: false,   // don't trace each instruction individually
        block: false,  // don't trace basic blocks
        compile: false // don't signal block compilation
    },
    onReceive(events) {
        // Called periodically with a batch of events
        const parsed = Stalker.parse(events);
        console.log(JSON.stringify(parsed, null, 2));
    }
});
```

`Stalker.follow` takes a thread ID and a configuration object. The `events` field is a mask controlling which event types are generated. The `onReceive` callback is invoked periodically (not at each event — events are buffered for performance) with a compact binary buffer that `Stalker.parse` decodes into a JavaScript array.

### Stopping the trace

```javascript
Stalker.unfollow(threadId);
```

Or to stop tracing the current thread:

```javascript
Stalker.unfollow();
```

After `unfollow`, the thread resumes normal execution on the original code, without any residual instrumentation.

### Following the main thread at spawn

The most common case is following the main thread from program launch:

```javascript
// In spawn mode, the main thread is the one executing main()
Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true, ret: true },
    onReceive(events) {
        // ...
    }
});
```

Combined with Frida's spawn mode (section 13.2), you get the complete execution trace from the very first instruction.

---

## Event types

### `call` — function calls

Each `call` instruction generates an event containing the address of the `call` instruction itself and the target address (the called function). It's the most used event for the overview.

```javascript
Stalker.follow(threadId, {
    events: { call: true },
    onReceive(events) {
        const parsed = Stalker.parse(events, { annotate: true, stringify: true });
        parsed.forEach(ev => {
            if (ev[0] === 'call') {
                const from = ev[1];    // call address
                const target = ev[2];  // target address
                const fromSym = DebugSymbol.fromAddress(ptr(from));
                const targetSym = DebugSymbol.fromAddress(ptr(target));
                console.log(`CALL ${fromSym} → ${targetSym}`);
            }
        });
    }
});
```

### `ret` — function returns

Each `ret` instruction generates an event with the `ret` address and the return address (where control goes back). Combined with `call`, you get a complete dynamic call graph.

### `exec` — each executed instruction

This is the finest and most expensive mode. Each individual instruction generates an event. The data volume is colossal — a program can execute millions of instructions per second. This mode is only usable on short execution sequences or with aggressive filtering.

### `block` — basic blocks

A basic block is a linear sequence of instructions without internal branching — it starts at a jump or call target, and ends with a branch. It's the natural granularity for code coverage: knowing which basic blocks were executed gives a precise map of traversed code, without the overhead of per-instruction tracing.

### `compile` — block compilation

This event is emitted when Stalker translates a new basic block for the first time. It's an indirect indicator of "new code reached" — if a block is compiled, it hadn't been executed yet in this Stalker session. This mode is very lightweight and useful for coverage-guided fuzzing.

---

## `transform`: instrumenting translated code

The `transform` callback is Stalker's most powerful feature. It's called when Stalker translates a basic block, and gives you access to the block's instructions **before they're emitted** into the copy. You can inspect each instruction, add extra instructions, or even remove instructions.

### Observing each instruction

```javascript
Stalker.follow(threadId, {
    transform(iterator) {
        let instruction = iterator.next();

        do {
            // Display each instruction
            console.log(`${instruction.address}: ${instruction.mnemonic} ${instruction.opStr}`);

            // Emit the instruction into the copy (mandatory)
            iterator.keep();

        } while ((instruction = iterator.next()) !== null);
    }
});
```

The pattern is always the same: `iterator.next()` advances to the block's next instruction, and `iterator.keep()` emits it into the translated copy. If you call `iterator.next()` without calling `iterator.keep()`, the instruction is **removed** from the copy — it won't be executed. It's an extremely powerful dynamic patching mechanism.

> ⚠️ Never forget `iterator.keep()`. If an instruction is read with `next()` but not emitted with `keep()`, it disappears from execution. Accidentally removing a critical instruction (like a `ret` or `push rbp`) causes an immediate crash.

### Filtering by module

In practice, you don't want to instrument libc, loader, or other library code — only the analyzed binary's code. `transform` is called for **all** code blocks executed by the thread, all libraries included. Address-range filtering is indispensable:

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

Stalker.follow(threadId, {
    transform(iterator) {
        let instruction = iterator.next();
        const isMainModule = instruction.address.compare(modBase) >= 0 &&
                             instruction.address.compare(modEnd) < 0;

        do {
            if (isMainModule) {
                console.log(`${instruction.address}: ${instruction.mnemonic} ${instruction.opStr}`);
            }
            iterator.keep();
        } while ((instruction = iterator.next()) !== null);
    }
});
```

We check the first instruction's address in the block (all instructions of a basic block are in the same module, by definition). If the block is in the main module, we log; otherwise, we emit instructions silently.

### Injecting callouts

Rather than logging in `transform` (which is called only once during block compilation), you can inject a **callout** — a JavaScript callback that will be called each time the instruction is executed:

```javascript
Stalker.follow(threadId, {
    transform(iterator) {
        let instruction = iterator.next();

        do {
            // If it's a CMP followed by a conditional jump, inject a callout
            if (instruction.mnemonic === 'cmp') {
                iterator.putCallout((context) => {
                    console.log(`CMP executed @ ${context.pc}`);
                    console.log(`  rax=${context.rax} rbx=${context.rbx}`);
                    console.log(`  rdi=${context.rdi} rsi=${context.rsi}`);
                });
            }

            iterator.keep();
        } while ((instruction = iterator.next()) !== null);
    }
});
```

`iterator.putCallout(callback)` inserts a call to `callback` just before the current instruction in the translated code. The callback receives a `context` object identical to `this.context` in Interceptor — all registers are readable and writable.

Callouts are the ideal tool for instrumenting specific instructions (comparisons, memory accesses, jumps) without the overhead of systematic per-instruction logging.

---

## Building a code-coverage map

Stalker's most direct application in RE is building a coverage map: which basic blocks of the binary were executed for a given input?

### Collecting block addresses

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

const coveredBlocks = new Set();

Stalker.follow(Process.getCurrentThreadId(), {
    transform(iterator) {
        let instruction = iterator.next();
        const blockAddr = instruction.address;

        const isMainModule = blockAddr.compare(modBase) >= 0 &&
                             blockAddr.compare(modEnd) < 0;

        if (isMainModule) {
            // Record the block address (offset relative to base)
            const offset = blockAddr.sub(modBase).toInt32();
            coveredBlocks.add(offset);
        }

        do {
            iterator.keep();
        } while ((instruction = iterator.next()) !== null);
    }
});
```

The `transform` callback is called once per basic block, on its first execution. It's exactly what we need for coverage: each block is recorded once, and overhead is minimal since the callback doesn't fire on subsequent executions of the same block.

### Exporting coverage to Python

```javascript
// When the program terminates or on demand
recv('dump_coverage', () => {
    const offsets = Array.from(coveredBlocks).sort((a, b) => a - b);
    send({
        event: 'coverage',
        module: mod.name,
        base: modBase.toString(),
        blocks: offsets,
        count: offsets.length
    });
});
```

```python
def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('event') == 'coverage':
            blocks = payload['blocks']
            print(f"[*] Coverage: {payload['count']} basic blocks reached")

            # Save in a format compatible with other tools
            with open("coverage.txt", "w") as f:
                for offset in blocks:
                    f.write(f"0x{offset:x}\n")

# Request the dump
script.post({'type': 'dump_coverage'})
```

### Exploiting coverage in Ghidra

The exported offset list can be imported into Ghidra to colorize executed blocks. A simple Ghidra Python script walks the list and applies a color:

```python
# Ghidra script (Jython) — execute in the Script Manager
from ghidra.app.plugin.core.colorizer import ColorizingService  
from java.awt import Color  

service = state.getTool().getService(ColorizingService)  
base = currentProgram.getImageBase()  

with open("/tmp/coverage.txt") as f:
    for line in f:
        offset = int(line.strip(), 16)
        addr = base.add(offset)
        service.setBackgroundColor(addr, addr.add(1), Color.GREEN)
```

Green blocks are those that were executed. Uncolored blocks represent dead code for this input — untaken branches, untriggered error handlers, unexplored conditional paths. It's precious information for guiding analysis: uncovered blocks are often those containing the most interesting logic (error handling, secret paths, debug code).

### drcov format for compatibility

For integration with standard coverage tools (notably the `lighthouse` plugin for IDA/Ghidra and Binary Ninja), you can export in **drcov** (DynamoRIO coverage) format:

```javascript
const coveredBlocksInfo = [];

Stalker.follow(Process.getCurrentThreadId(), {
    transform(iterator) {
        let instruction = iterator.next();
        const blockStart = instruction.address;
        let blockSize = 0;

        const isMainModule = blockStart.compare(modBase) >= 0 &&
                             blockStart.compare(modEnd) < 0;

        do {
            if (isMainModule) {
                blockSize += instruction.size;
            }
            iterator.keep();
        } while ((instruction = iterator.next()) !== null);

        if (isMainModule && blockSize > 0) {
            coveredBlocksInfo.push({
                start: blockStart.sub(modBase).toInt32(),
                size: blockSize
            });
        }
    }
});
```

We collect not only each block's start address, but also its size (sum of the block's instruction sizes). The drcov format needs both pieces of information.

```python
# Export in drcov format
def export_drcov(module_name, module_base, module_size, blocks, filename):
    with open(filename, 'wb') as f:
        f.write(b"DRCOV VERSION: 2\n")
        f.write(b"DRCOV FLAVOR: frida\n")
        f.write(f"Module Table: version 2, count 1\n".encode())
        f.write(b"Columns: id, base, end, entry, path\n")
        f.write(f"  0, {module_base}, {hex(int(module_base, 16) + module_size)}, 0x0, {module_name}\n".encode())
        f.write(f"BB Table: {len(blocks)} bbs\n".encode())

        import struct
        for block in blocks:
            # drcov format: start(uint32), size(uint16), mod_id(uint16)
            f.write(struct.pack('<IHH', block['start'], block['size'], 0))

    print(f"[*] drcov exported: {filename} ({len(blocks)} blocks)")
```

This file can be directly opened in lighthouse (Ghidra/IDA) or Binary Ninja for interactive coverage visualization, with per-function coverage statistics and automatically applied color coding.

---

## Comparative coverage: two inputs, two traces

A powerful RE technique consists of comparing coverage between two executions — one with a valid input and one with an invalid input. The blocks that differ between both traces are exactly those implementing the validation logic.

### Approach with Python

```python
import frida  
import sys  

AGENT_CODE = """
'use strict';

const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  
const covered = new Set();  

Stalker.follow(Process.getCurrentThreadId(), {
    transform(iterator) {
        let insn = iterator.next();
        const addr = insn.address;
        if (addr.compare(modBase) >= 0 && addr.compare(modEnd) < 0) {
            covered.add(addr.sub(modBase).toInt32());
        }
        do { iterator.keep(); } while ((insn = iterator.next()) !== null);
    }
});

recv('dump', () => {
    send({ blocks: Array.from(covered) });
    Stalker.unfollow();
    Stalker.garbageCollect();
});
"""

def get_coverage(binary, input_data):
    """Launch the binary with input_data and return covered blocks."""
    blocks = []

    def on_msg(msg, data):
        nonlocal blocks
        if msg['type'] == 'send':
            blocks = set(msg['payload']['blocks'])

    pid = frida.spawn([binary], stdin=input_data.encode())
    session = frida.attach(pid)
    script = session.create_script(AGENT_CODE)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)

    import time
    time.sleep(2)  # Let the program execute
    script.post({'type': 'dump'})
    time.sleep(1)
    session.detach()

    return blocks

# Execute with two different inputs
cov_valid = get_coverage("./keygenme_O0", "CORRECT_KEY")  
cov_invalid = get_coverage("./keygenme_O0", "wrong_input")  

# Blocks executed only with the valid input
only_valid = cov_valid - cov_invalid
# Blocks executed only with the invalid input
only_invalid = cov_invalid - cov_valid
# Common blocks
common = cov_valid & cov_invalid

print(f"Common blocks          : {len(common)}")  
print(f"Valid input only       : {len(only_valid)}")  
print(f"Invalid input only     : {len(only_invalid)}")  

print("\nBlocks specific to the valid input (offsets):")  
for offset in sorted(only_valid):  
    print(f"  0x{offset:x}")
```

The offsets listed in `only_valid` point directly to the code that executes when the key is correct — the "success" path. Examining them in Ghidra identifies the validation branch and reveals the verification logic.

---

## Stalker on targeted portions

Following an entire thread throughout the program's execution is expensive. Often, you want to activate Stalker only during a specific phase — for example, during a specific function's execution. The Interceptor + Stalker combination allows exactly that.

### Activating Stalker during a function's execution

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  
const targetFunc = modBase.add(0x11a9);  // check_password  

const coveredInFunc = new Set();

Interceptor.attach(targetFunc, {
    onEnter(args) {
        this.tid = Process.getCurrentThreadId();

        Stalker.follow(this.tid, {
            transform(iterator) {
                let insn = iterator.next();
                const addr = insn.address;
                if (addr.compare(modBase) >= 0 && addr.compare(modEnd) < 0) {
                    coveredInFunc.add(addr.sub(modBase).toInt32());
                }
                do { iterator.keep(); } while ((insn = iterator.next()) !== null);
            }
        });

        console.log("[Stalker] Activated for check_password()");
    },
    onLeave(retval) {
        Stalker.unfollow(this.tid);
        Stalker.garbageCollect();

        console.log(`[Stalker] Deactivated. ${coveredInFunc.size} blocks traced.`);
        send({ event: 'func_coverage', blocks: Array.from(coveredInFunc) });
    }
});
```

Stalker activates when `check_password` starts and deactivates when it returns. You only trace code executed during this function — including sub-functions it calls. Stalker's overhead applies only during this window.

---

## Tracing function calls (dynamic call graph)

By combining `call` and `ret` events, you can reconstruct the dynamic call graph — the tree of functions actually called during execution.

```javascript
const mod = Process.enumerateModules()[0];  
const modBase = mod.base;  
const modEnd = modBase.add(mod.size);  

let depth = 0;

Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true, ret: true },
    onReceive(events) {
        const parsed = Stalker.parse(events, { annotate: true, stringify: true });
        parsed.forEach(ev => {
            const type = ev[0];

            if (type === 'call') {
                const target = ptr(ev[2]);
                if (target.compare(modBase) >= 0 && target.compare(modEnd) < 0) {
                    const sym = DebugSymbol.fromAddress(target);
                    const indent = '  '.repeat(depth);
                    console.log(`${indent}→ ${sym.name || target}`);
                    depth++;
                }
            } else if (type === 'ret') {
                const from = ptr(ev[1]);
                if (from.compare(modBase) >= 0 && from.compare(modEnd) < 0) {
                    depth = Math.max(0, depth - 1);
                }
            }
        });
    }
});
```

Typical output:

```
→ main
  → init_config
    → read_file
    → parse_config
  → check_password
    → hash_input
    → compare_hash
  → print_result
```

This hierarchical view is the dynamic equivalent of Ghidra's call graph (Chapter 8, section 8.7) or the Callgrind/KCachegrind graph (Chapter 14, section 14.2), but with real execution paths instead of all static possibilities.

---

## Performance and best practices

Stalker is Frida's most resource-hungry component. A few rules to maintain acceptable performance:

**Limit temporal scope.** Activate Stalker only during the interesting execution phase, not for the program's entire lifetime. Use Interceptor to trigger and stop Stalker at the right moment.

**Filter by module.** Only log blocks from the main binary. Libc, loader, and library code generates an enormous volume of blocks that generally don't interest the analysis.

**Prefer `transform` to `events: { exec: true }`.** The `exec` mode generates one event per instruction and buffers them for `onReceive`. The `transform` callback is called only once per block during compilation. For coverage, `transform` is infinitely more efficient.

**Call `Stalker.garbageCollect()`.** After an `unfollow`, translated code stays in memory. `garbageCollect()` frees translated blocks that are no longer needed. Call it after each follow/unfollow cycle to avoid memory accumulation.

**Watch for threads.** Stalker follows one thread at a time. If the program is multi-threaded, you must call `Stalker.follow` on each thread of interest, or enumerate threads and follow them all:

```javascript
Process.enumerateThreads().forEach(thread => {
    Stalker.follow(thread.id, { /* ... */ });
});
```

**The `flush`.** By default, events are buffered. To force immediate sending:

```javascript
Stalker.flush();
```

Useful just before an `unfollow` to ensure all events have been transmitted.

---

## Stalker and fuzzing: the bridge to Chapter 15

The coverage map produced by Stalker is exactly the information a coverage-guided fuzzer needs to decide if an input is "interesting" (it reached new code). It's the conceptual bridge between this chapter and Chapter 15 (Fuzzing).

Indeed, you can build a mini-fuzzer with Frida:

1. Generate an input.  
2. Launch the program with this input under Stalker.  
3. Collect coverage.  
4. If new blocks were reached, keep the input in the corpus.  
5. Mutate the input and repeat.

This artisanal approach doesn't reach AFL++'s performance (Chapter 15, section 15.2), which uses much lighter compile-time instrumentation. But it works on closed binaries, without recompilation — precisely the reverse-engineering context.

---

## What to remember

- **Stalker** uses dynamic binary translation to follow a thread's execution instruction by instruction, without breakpoints.  
- Event types (`call`, `ret`, `exec`, `block`, `compile`) offer different granularity and overhead levels.  
- The **`transform`** callback is the most powerful mechanism: it allows inspecting, modifying, or removing instructions during translation, and injecting **callouts** executed at each passage.  
- Building a **coverage map** (offsets of executed basic blocks) is the main RE application — it reveals live code vs dead code for a given input.  
- Export in **drcov** format enables integration with lighthouse (Ghidra, IDA, Binary Ninja) for interactive visualization.  
- **Comparative coverage** between two inputs identifies the code blocks implementing validation logic — a devastatingly effective localization technique.  
- Combining **Interceptor + Stalker** allows limiting tracing to a precise execution window (during a function), maintaining acceptable performance.  
- `Stalker.garbageCollect()` and `Stalker.flush()` are essential for memory management and data reliability.

---

> **Next section**: 13.7 — Practical case: bypassing a license check — we'll put into practice all the techniques seen in this chapter (Interceptor, return modification, Stalker) on a complete software-protection bypass scenario.

⏭️ [Practical case: bypassing a license check](/13-frida/07-practical-license-bypass.md)
