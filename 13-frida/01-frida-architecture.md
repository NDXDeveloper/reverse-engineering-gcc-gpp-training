🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.1 — Frida's architecture — JS agent injected into the target process

> 🧰 **Tools used**: `frida`, `frida-ps`, `frida-trace`, Python 3 + `frida` module  
> 📖 **Prerequisites**: [Chapter 2 — The GNU compilation chain](/02-gnu-compilation-chain/README.md) (sections on the loader and dynamic libraries), [Chapter 5 — Inspection tools](/05-basic-inspection-tools/README.md) (`strace`, `ltrace`, `/proc`)

---

## Overview: the fundamental idea

To understand Frida, you first have to understand the problem it solves.

When using GDB, the debugger is an **external process** that controls the target via the `ptrace` system call. This parent–child relationship is visible to the kernel, to the process itself (via `/proc/self/status`), and imposes a structural cost: each breakpoint triggers a `SIGTRAP` signal, a context switch to GDB, a wait, then a resumption. The program is alternately frozen and restarted.

Frida adopts a radically different strategy. Instead of controlling the program from the outside, Frida **places an agent inside the target process**. This agent is a shared library (`.so` on Linux) that embeds a complete JavaScript engine. Once injected, the agent executes in the same address space as the program, with the same memory permissions, and can manipulate code and data as if it were part of it — because it is.

That's the essential distinction: **GDB observes from the outside, Frida operates from the inside.**

---

## The architectural components

Frida's architecture relies on four components that communicate with each other. Understanding their role and interactions is indispensable for using the tool effectively and diagnosing problems when they arise.

### The client (your Python script or the CLI)

It's the entry point for the user. The client runs in a separate process — typically a terminal where you launch `frida`, `frida-trace`, or a Python script using the `frida` module. Its role is to drive everything: select the target process, send the agent's JavaScript code, receive messages in return, and orchestrate the instrumentation lifecycle.

The client never directly touches the target process's memory. It communicates exclusively with the following component.

```
┌─────────────────────────────┐
│   Client (Python / CLI)     │
│   - Piloting                │
│   - Sending JS script       │
│   - Receiving messages      │
└──────────┬──────────────────┘
           │  inter-process communication
           ▼
```

### The `frida-server` service (or direct injection)

On local Linux, Frida most often uses **direct injection** via `ptrace` to load its library into the target process. This use of `ptrace` is brief and one-time: it only serves to inject the agent's code, then Frida releases `ptrace` control. This contrasts with GDB, which maintains the `ptrace` attachment throughout the debugging session.

In other configurations (remote debugging, instrumentation on Android or iOS), a `frida-server` daemon runs on the target machine and manages injection on demand. The client then communicates with `frida-server` via a network socket (TCP by default, on port 27042).

```
           │
           ▼
┌─────────────────────────────────────┐
│   Injection (ptrace or frida-server)│
│   - Loads frida-agent.so            │
│   - Releases ptrace after injection │
└──────────┬──────────────────────────┘
           │
           ▼
```

### The agent (`frida-agent.so`)

This is Frida's heart. The agent is a shared library that, once loaded into the target process, starts a **JavaScript engine** (based on Google's V8 or on Duktape depending on the configuration). This engine executes the script you sent from the client.

The agent exposes to JavaScript a rich API that allows:

- **Reading and writing process memory** (`Memory.read*`, `Memory.write*`, `Memory.scan`).  
- **Resolving symbols** by name (`Module.findExportByName`, `Module.enumerateExports`).  
- **Intercepting functions** at entry and exit (`Interceptor.attach`).  
- **Replacing functions** entirely (`Interceptor.replace`).  
- **Allocating memory** and writing native code to it (`Memory.alloc`, `NativeFunction`, `NativeCallback`).  
- **Tracing execution instruction by instruction** (`Stalker`).

The agent lives in one or more dedicated threads inside the target process. The JavaScript code executes in the context of these threads, but the hooks it installs are triggered in the context of the program's original threads — a crucial point we'll deepen in the following sections.

```
           │
           ▼
┌──────────────────────────────────────────────┐
│   Target process                             │
│                                              │
│   ┌────────────────────────────────────┐     │
│   │  frida-agent.so                    │     │
│   │  ┌──────────────────────────┐      │     │
│   │  │  JS engine (V8/Duktape)  │      │     │
│   │  │  - Your script           │      │     │
│   │  │  - Frida API             │      │     │
│   │  └──────────────────────────┘      │     │
│   │  Interceptor, Stalker, Memory...   │     │
│   └────────────────────────────────────┘     │
│                                              │
│   ┌────────────────────────────────────┐     │
│   │  Program's original code           │     │
│   │  (.text, .data, heap, stack...)    │     │
│   └────────────────────────────────────┘     │
│                                              │
└──────────────────────────────────────────────┘
```

### The communication channel

The client and agent communicate via a bidirectional message channel. On the agent side (JavaScript), you send data to the client with the `send()` function. On the client side (Python), you receive these messages via an `on_message` callback. This channel carries JSON, which allows sending arbitrary data structures — intercepted function arguments, encoded memory dumps, counters, logs.

```python
# Client side (Python)
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])

session = frida.attach("target")  
script = session.create_script("""  
    // Agent side (JavaScript, executed in the target process)
    send({event: "hello", pid: Process.id});
""")
script.on('message', on_message)  
script.load()  
```

The Python callback's `data` parameter allows receiving raw binary data (a memory buffer, a structure dump) alongside the JSON message, without going through a costly base64 encoding.

---

## The injection mechanism in detail

Understanding how the agent arrives in the target process illuminates both Frida's capabilities and limits.

### Injection via `ptrace` (default mode on Linux)

When you execute `frida -p <PID>` or `frida.attach(pid)` in Python, here's the sequence that unfolds:

1. **`ptrace` attachment** — Frida briefly attaches to the target process via `PTRACE_ATTACH`. The process is suspended.

2. **Bootstrapper injection** — Frida allocates a small memory zone in the process (via an `mmap` call constrained by `ptrace`) and writes a machine-code stub there. This stub calls `dlopen()` to load `frida-agent.so`.

3. **Bootstrapper execution** — Frida modifies the main thread's instruction pointer (`rip`) to execute the stub. The process briefly resumes, `dlopen` loads the agent, and the agent's constructor (`__attribute__((constructor))`) initializes the JavaScript engine.

4. **`ptrace` detachment** — Once the agent is loaded and operational, Frida restores the original register context and detaches via `PTRACE_DETACH`. The process resumes normal execution, with the agent included.

From this point, all instrumentation goes through the internal agent — no more `ptrace` is used. That's why Frida is compatible with programs that detect `ptrace`: the attachment is so brief that many anti-debug checks miss it (though the most robust protections can still detect it, as we'll see in Chapter 19).

### Spawn mode (`frida -f ./program`)

Instead of attaching to an existing process, Frida can **launch** the program itself. In this mode:

1. Frida creates the process via `fork` + `exec`, but suspends it before the program's first instruction executes (using `ptrace` or an equivalent mechanism).  
2. The agent is injected into this suspended process.  
3. The program is resumed, with the agent already in place.

This mode is essential when you want to instrument code that executes very early — a C++ global constructor, an initialization routine, or an anti-debug check executed at startup. In attach mode, these routines would have already been executed before you could intervene.

### Permission implications

Injection via `ptrace` requires the Frida process to have the necessary privileges to attach to the target process. On Linux, this means:

- Either running Frida as `root`.  
- Or having `/proc/sys/kernel/yama/ptrace_scope` allow attachment (value `0` allows free attachment, `1` restricts to child processes).

In our lab environment (dedicated VM, Chapter 4), working as `root` or adjusting `ptrace_scope` is risk-free and simplifies practice.

---

## Frida-agent in memory: what the process sees

Once injection is complete, the target process carries traces of Frida's presence. It's useful to know how to recognize them — both to understand what's happening and to anticipate detection mechanisms.

### Loaded libraries

The agent appears in the process's memory map. A `cat /proc/<PID>/maps` reveals Frida-related entries:

```
7f3a8c000000-7f3a8c400000 rwxp 00000000 00:00 0    frida-agent-64.so
```

The presence of `frida-agent` in `/proc/self/maps` is the simplest detection vector. A malicious or protected program can read its own memory map and look for the string `"frida"`. We'll see in section 13.7 and Chapter 19 how some techniques attempt to mask this signature.

### Additional threads

The agent creates one or more threads for the JavaScript engine and the communication channel. An `ls /proc/<PID>/task/` will show additional TIDs (Thread IDs) that didn't exist before injection. A program monitoring its own thread count can see this as an anomaly.

### File descriptors and sockets

The communication channel between agent and client goes through a socket (often a Unix pipe or a local TCP connection). These file descriptors appear in `/proc/<PID>/fd/` and constitute another indication of Frida's presence.

---

## The JavaScript engine: V8 vs Duktape

Frida embeds two JavaScript engines, and the choice between them has practical implications.

**V8** (Chrome and Node.js's engine) is the default choice. It offers a complete JIT compiler, excellent JavaScript performance, and ES6+ support (classes, arrow functions, async/await, destructuring). It's the engine you'll use in 99% of cases on x86-64.

**Duktape** is a minimalist JavaScript engine, interpreted (no JIT), with a much smaller memory footprint. Frida uses it on platforms where V8 isn't available or is too heavy (some embedded devices, very constrained environments). Its language support is limited to ES5 — no `let`/`const`, no arrow functions, no `class`.

In this training, we'll systematically use V8 and modern JavaScript syntax. All scripts presented use `const`, `let`, arrow functions, and `async/await`.

To check which engine is active, execute from an agent script:

```javascript
send({runtime: Script.runtime});  // "V8" or "DUK"
```

---

## How Interceptor works under the hood

The `Interceptor` API is Frida's most used feature. Before learning to use it in detail (sections 13.3 to 13.5), it's useful to understand what happens under the hood when you write:

```javascript
Interceptor.attach(ptr("0x401234"), {
    onEnter(args) { /* ... */ },
    onLeave(retval) { /* ... */ }
});
```

### The trampoline

When you attach a hook to an address, Frida doesn't set a software breakpoint (no `0xCC` byte like GDB). Instead, it rewrites the **first instructions of the target function** to replace them with a jump (`jmp`) to a **trampoline** — a small block of code dynamically generated by Frida.

This trampoline performs the following sequence:

1. **Context save** — All registers are pushed onto the stack.  
2. **`onEnter` callback call** — The JavaScript engine is invoked with the function's arguments (read from the `rdi`, `rsi`, `rdx`… registers per the System V AMD64 convention seen in Chapter 3).  
3. **Original instruction execution** — The instructions that were overwritten by the `jmp` are executed from a copy (the "relocated prologue").  
4. **Jump to continuation** — Control returns to the target function, right after the displaced instructions. The function executes normally.  
5. **Return interception** — To capture the return value, Frida replaces the return address on the stack with the address of a second trampoline that calls `onLeave` before returning to the real caller.

### Why it matters for RE

This mechanism has several practical consequences:

- **No `SIGTRAP`** — Unlike GDB breakpoints, Frida hooks generate no signal. The process doesn't know it's instrumented (as long as it doesn't actively search).  
- **Performance** — A hook's overhead is that of an extra `jmp` plus JavaScript execution. For functions called millions of times, this cost can become significant, but it remains negligible for targeted hooking.  
- **Relocation** — Frida must "understand" the function's first instructions to move them correctly. If these instructions contain `rip`-relative references (PC-relative addressing, common in PIE code compiled with `-fPIC`), Frida must adjust them. This process is robust in the vast majority of cases, but can occasionally fail on very atypical or heavily obfuscated code.

---

## Frida in the ecosystem: positioning relative to other tools

To situate Frida in your reverse engineer's toolbox, here's how it compares to other dynamic-analysis approaches encountered in this training:

| Criterion | `strace`/`ltrace` | GDB | Frida |  
|---|---|---|---|  
| **Granularity** | System / library calls | Instruction by instruction | Function by function (or instruction via Stalker) |  
| **Intrusiveness** | Low (passive observation) | High (halt at each BP) | Medium (injection, but no halt) |  
| **Live modification** | No | Yes (but manual, register by register) | Yes (scriptable, automated) |  
| **Scripting language** | None | Python (GDB API) | JavaScript (agent) + Python (client) |  
| **Detectable** | Yes (permanent `ptrace`) | Yes (permanent `ptrace`) | Yes (but brief `ptrace`, agent in memory) |  
| **`ptrace` usage** | Permanent | Permanent | Brief (injection only) |

The key point: Frida doesn't replace GDB. Both tools are complementary. You use GDB when you need to inspect the program's state at a precise moment, instruction by instruction, with total control. You use Frida when you want to observe or modify the behavior of specific functions over time, without interrupting execution flow. In a typical RE session, it's common to alternate between the two.

---

## Architecture summary

```
  Your machine (or control machine)
  ┌────────────────────────────────┐
  │  Client Python / CLI frida     │
  │  ┌──────────────────────────┐  │
  │  │  frida.attach(pid)       │  │
  │  │  session.create_script() │  │
  │  │  script.on('message')    │  │
  │  └──────────┬───────────────┘  │
  └─────────────┼──────────────────┘
                │ message channel (JSON + binary)
                │
  Target machine (or same machine)
  ┌─────────────┼────────────────────────────────────┐
  │  Process    ▼  target (PID 1234)                 │
  │                                                  │
  │  ┌────────────────────────────────────────────┐  │
  │  │  frida-agent.so                            │  │
  │  │                                            │  │
  │  │  ┌──────────────┐   ┌───────────────────┐  │  │
  │  │  │  V8 engine   │   │  Interceptor      │  │  │
  │  │  │  (your JS)   │◄─►│  Stalker          │  │  │
  │  │  │              │   │  Memory API       │  │  │
  │  │  └──────────────┘   └───────┬───────────┘  │  │
  │  │                             │              │  │
  │  └─────────────────────────────┼──────────────┘  │
  │                                │                 │
  │  ┌─────────────────────────────▼──────────────┐  │
  │  │  Original code (.text)                     │  │
  │  │  ┌─────────┐  ┌─────────┐  ┌────────────┐  │  │
  │  │  │ main()  │  │ check() │  │ libc.so    │  │  │
  │  │  │ ┌─jmp──►│  │ ┌─jmp──►│  │ malloc()   │  │  │
  │  │  │ │tramp. │  │ │tramp. │  │ free()     │  │  │
  │  │  └─┼───────┘  └─┼───────┘  └────────────┘  │  │
  │  │    │ hooks      │ hooks                    │  │
  │  └────┼────────────┼──────────────────────────┘  │
  │       └────────────┘                             │
  └──────────────────────────────────────────────────┘
```

The agent lives **inside** the process. The client lives **outside**. Hooks are trampolines inserted **into the target's code**. The JavaScript engine orchestrates everything from the inside, and communicates results outward via the message channel.

---

## What to remember

- Frida injects a shared library (`frida-agent.so`) into the target process, which embeds a complete JavaScript engine (V8 by default).  
- Injection uses `ptrace` briefly on Linux, then releases it — unlike GDB which maintains the attachment.  
- **Attach** mode instruments an already-running process; **spawn** mode launches the program and injects the agent before the first instruction.  
- Hooks are implemented by **trampolines** (rewriting a function's first instructions), not by software breakpoints.  
- The client (Python) and agent (JavaScript) communicate via a bidirectional JSON message channel.  
- The agent is detectable in memory (libraries, threads, file descriptors) — a point to keep in mind facing protected binaries.

---

> **Next section**: 13.2 — Injection modes: `frida`, `frida-trace`, spawn vs attach — we'll move from theory to practice by exploring the different ways to launch Frida on our training binaries.

⏭️ [Injection modes: `frida`, `frida-trace`, spawn vs attach](/13-frida/02-injection-modes.md)
