🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 34.1 — Go Runtime Specifics: Goroutines, Scheduler, GC

> 🐹 *Before analyzing Go code, you need to understand the invisible machine running in the background. The Go runtime is not an external library — it is an integral part of every binary. In RE, you will see it everywhere: in function prologues, in the thousands of `runtime.*` symbols, and in the process's memory behavior. This section teaches you to recognize it so you can better ignore it when it's not relevant — and better exploit it when it is.*

---

## Overview of the Go Runtime

In C, the runtime is virtually nonexistent: `_start` calls `__libc_start_main`, which calls your `main()`, and the rest is delegated to the kernel via libc. In Go, it is radically different. The binary embeds a complete runtime that initializes well before your `main.main()` executes. This runtime includes:

- a **cooperative scheduler** that multiplexes thousands of goroutines onto a few OS threads,  
- a **concurrent tri-color garbage collector** that automatically manages memory,  
- a **memory allocator** with arenas inspired by TCMalloc,  
- a **growable stack** system (segmented stacks, then contiguous stacks since Go 1.4),  
- handling of **POSIX signals**, **timers**, **networking** (built-in netpoller),  
- mechanisms for **reflection**, **interfaces**, and **type assertion**.

When you open a Go binary in Ghidra and launch auto-analysis, you will see thousands of functions prefixed with `runtime.`. This is normal. A "Hello, World!" in Go typically contains between 1,500 and 2,500 functions — fewer than ten of which belong to your business logic. Knowing how to filter this noise is the first skill to acquire.

---

## The Startup Sequence: From `_rt0` to `main.main`

Understanding the execution path between the ELF entry point and your code is essential to avoid getting lost during dynamic analysis. Here is the simplified call chain on Linux/amd64:

```
_rt0_amd64_linux          ← ELF entry point (equivalent of _start)
  → runtime.rt0_go        ← low-level initialization (TLS, stack, argc/argv)
    → runtime.schedinit    ← initialization of the scheduler, GC, memory
    → runtime.newproc      ← creates the first goroutine for runtime.main
    → runtime.mstart       ← starts thread M0 (first OS thread)
      → runtime.main       ← package initialization (init()), then…
        → main.main        ← your code
```

### What You Will See in Ghidra / objdump

The ELF entry point (`readelf -h`) points to `_rt0_amd64_linux`, a function of just a few assembly instructions that simply places `argc` and `argv` into registers, then jumps to `runtime.rt0_go`.

`runtime.rt0_go` is a long assembly function (hand-written in `src/runtime/asm_amd64.s` in the Go source code) that:

1. configures the initial thread stack,  
2. initializes TLS (Thread Local Storage) to store the `g` pointer (the current goroutine),  
3. detects CPU capabilities (CPUID) to enable SIMD optimizations,  
4. calls `runtime.schedinit` to initialize the scheduler,  
5. creates an initial goroutine with `runtime.newproc` pointing to `runtime.main`,  
6. calls `runtime.mstart` to start the scheduler loop.

> 💡 **RE tip**: if you are looking for `main.main` in a Go binary, do not set your breakpoint on the ELF entry point. Search directly for the `main.main` symbol (or its address via `gopclntab` if the binary is stripped). You will avoid traversing hundreds of runtime initialization instructions.

### Finding `main.main` in a Stripped Binary

Even without symbols, the string `main.main` is often recoverable via `gopclntab` (section 34.4). But a quick method during dynamic analysis:

1. Set a breakpoint on `runtime.main` (recoverable via `gopclntab`).  
2. Step through: `runtime.main` calls the `init()` functions of each imported package, then performs a `call` to `main.main`. It is the last significant call before the exit loop.

---

## Goroutines as Seen from the Disassembler

### The M:N Model

Go implements an **M:N** concurrency model — M goroutines multiplexed onto N OS threads. Three internal structures orchestrate this mechanism:

- **G** (goroutine): the `runtime.g` structure — contains the execution context, stack state, stack pointer, status (idle, runnable, running, syscall, waiting…).  
- **M** (machine): the `runtime.m` structure — represents an OS thread. Each M executes one goroutine at a time.  
- **P** (processor): the `runtime.p` structure — a logical processor that holds a local goroutine run queue. The number of P's is set by `GOMAXPROCS`.

The scheduler assigns G's to M's via P's. When a goroutine blocks (I/O, channel, mutex), the scheduler detaches the G from the M and executes another one — without a `clone()` syscall or kernel context switch.

### What This Looks Like in Assembly

When you see in your Go source code:

```go
go myFunction(arg1, arg2)
```

The compiler generates a call to `runtime.newproc`. In assembly (Intel syntax, recent Go with register-based ABI):

```asm
; Preparing arguments for runtime.newproc
LEA     RAX, [main.myFunction·f]   ; pointer to the closure/function
; ... arguments pushed or placed in registers depending on ABI ...
CALL    runtime.newproc
```

`runtime.newproc` allocates a `runtime.g` structure (approximately 400 bytes on Go 1.21+), copies the goroutine's arguments onto its initial stack (2 KB by default since Go 1.4, dynamically growable), and places the new G in the current P's local run queue.

> 💡 **RE tip**: each `CALL runtime.newproc` in the disassembly corresponds to a `go func()` in the source code. By counting these calls and identifying the target function (the first argument, often a `LEA` to a `main.xxx·f` symbol), you can reconstruct the map of goroutines launched by the program.

### `runtime.g` Structure in Memory

The `g` structure is large and changes between Go versions, but the important fields for RE remain stable:

| Offset (Go 1.21, amd64) | Field | Description |  
|---|---|---|  
| `+0x00` | `stack.lo` | Bottom of the goroutine's stack |  
| `+0x08` | `stack.hi` | Top of the stack |  
| `+0x10` | `stackguard0` | Sentinel for stack overflow detection |  
| `+0x18` | `stackguard1` | Secondary sentinel (used by the runtime) |  
| `+0x???` | `goid` | Unique goroutine ID (incremental integer) |  
| `+0x???` | `atomicstatus` | Current state (idle=0, runnable=1, running=2…) |  
| `+0x???` | `sched` | `gobuf` — saved registers (SP, PC, ctxt…) |

The exact offsets vary depending on the compiler version. To determine them for your binary, look for recurring memory accesses in the functions `runtime.gogo`, `runtime.gosave`, and `runtime.mcall` — they directly manipulate the fields of `g`.

> 💡 **RE tip**: in GDB, the `R14` register (since Go 1.17 on amd64) permanently points to the `g` structure of the currently running goroutine. Before Go 1.17, this pointer was stored in TLS. The command `info registers r14` followed by `x/20gx $r14` gives you a raw dump of the current `g` structure.

---

## Growable Stacks and Stack Splitting

### The Problem

Each goroutine starts with a stack of only 2 to 8 KB (depending on the Go version). With potentially thousands of active goroutines, allocating 1 MB per stack as with POSIX threads would be prohibitive. Go solves this problem with growable stacks: when the stack runs out of space, the runtime allocates a larger one, copies the contents, then updates all pointers.

### The Stack Check Preamble

Here is the most visible direct consequence in RE: **virtually every Go function begins with a stack check preamble**. It is an extremely recognizable pattern:

```asm
; Typical Go function prologue (amd64)
; R14 = pointer to g (current goroutine)
MOV     RAX, [R14+0x10]        ; RAX = g.stackguard0  
CMP     RSP, RAX               ; does the current stack exceed the sentinel?  
JBE     _morestack             ; if so → grow the stack  
; --- function body ---
...
; At the end of the file, or just after:
_morestack:
    CALL    runtime.morestack_noctxt
    JMP     _début_de_la_fonction   ; retry after growing
```

This pattern repeats in virtually all functions in the binary. In RE:

- **Do not confuse it with a stack canary.** The mechanism is fundamentally different: it does not protect against buffer overflows; it manages dynamic stack growth.  
- **Use it as a signature.** If you see this pattern in an unknown binary, it is very likely compiled Go.  
- **Mentally ignore it.** When analyzing business logic, jump directly past the `JBE` to reach the real start of the function.

The function `runtime.morestack_noctxt` (or `runtime.morestack`) is the growth mechanism: it allocates a larger new stack, copies the old one, updates the pointers, then restarts the function from the beginning.

> 💡 **RE tip**: in Ghidra, you can write a simple script that identifies all functions containing the pattern `CMP RSP, [R14+0x10]` followed by a `JBE`. This gives you a reliable inventory of Go functions in the binary, even without symbols.

---

## The Scheduler as Seen from RE

### Key Scheduler Functions

When browsing a Go binary, you will frequently encounter these scheduler functions. Knowing their role will save you from wasting time analyzing them:

| Function | Role |  
|---|---|  
| `runtime.schedule` | Main scheduler loop — chooses the next G to execute |  
| `runtime.findRunnable` | Looks for a ready goroutine (local queue, global queue, work stealing) |  
| `runtime.execute` | Switches context to a selected G |  
| `runtime.gogo` | Restores registers from `g.sched` and jumps to the saved PC |  
| `runtime.gosave` | Saves the current G's registers into `g.sched` |  
| `runtime.mcall` | Switches to the M's system stack to execute a runtime function |  
| `runtime.park_m` | Puts a G to sleep (blocking on channel, mutex, I/O…) |  
| `runtime.gopark` | High-level interface for `park_m` — called by channels |  
| `runtime.goready` | Wakes a parked G and puts it back in the runnable queue |  
| `runtime.newproc` | Creates a new G (corresponds to `go func()`) |  
| `runtime.Goexit` | Cleanly terminates the current goroutine |

### Preemption Points

Since Go 1.14, the scheduler supports **asynchronous preemption** via signals (SIGURG on Linux). Before that, preemption was only cooperative — at stack check points and function calls. In RE, this translates to:

- signal handlers `runtime.sighandler` that check whether the signal is a preemption SIGURG,  
- fields in the `g` structure (`preempt`, `preemptStop`) that control when the G can be interrupted.

For the analyst, the key point is that goroutines are **not** OS threads. An `strace` will only show you the few OS threads (the M's), not the individual goroutines. To trace the execution of a specific goroutine, you will need to set breakpoints on the goroutine's code itself, not on the scheduler mechanisms.

---

## The Garbage Collector as Seen from RE

### Concurrent Tri-Color Architecture

Go's GC uses a tri-color (white/gray/black), concurrent, non-generational mark algorithm. The algorithmic details are beyond the scope of RE, but the impacts on analysis are concrete.

### Frequently Encountered GC Functions

| Function | Role |  
|---|---|  
| `runtime.gcStart` | Triggers a GC cycle |  
| `runtime.gcMarkDone` | End of the marking phase |  
| `runtime.gcSweep` | Sweep phase — frees unmarked objects |  
| `runtime.gcBgMarkWorker` | Background marking worker (dedicated goroutine) |  
| `runtime.mallocgc` | Main allocation entry point — **every `make`, `new`, or implicit allocation goes through here** |  
| `runtime.newobject` | Wrapper around `mallocgc` for simple allocations |

### Write Barriers

The concurrent GC requires **write barriers** — code injected by the compiler at every pointer write. In assembly, you will frequently see:

```asm
; Writing a pointer with write barrier
LEA     RDI, [destination]  
MOV     RSI, [source_pointeur]  
CALL    runtime.gcWriteBarrier  
```

Or, in recent versions, a faster inline sequence that tests a flag of the current P before deciding whether the barrier is active.

These write barriers appear in **all** functions that manipulate pointers, including your business logic. They add significant noise to the disassembly. Learn to recognize them to mentally filter them out:

- A `CALL runtime.gcWriteBarrier` (or `runtime.gcWriteBarrierN` for variants) in the middle of a function is almost always a GC write barrier.  
- The variants `runtime.gcWriteBarrier1` through `runtime.gcWriteBarrier8` handle different buffer sizes.

> 💡 **RE tip**: if you see a Ghidra function whose pseudo-code appears abnormally complex with many `runtime.gcWriteBarrier*` calls, do not worry. The actual underlying code is often much simpler — these calls are just GC instrumentation.

### The Memory Allocator

Go does not use libc's `malloc`/`free`. Its allocator is built into the runtime and organized in three levels:

1. **mheap** — the global arena, manages memory pages obtained via `mmap`.  
2. **mcentral** — shared cache by size class.  
3. **mcache** — local cache per P (logical processor), lock-free.

For small allocations (≤ 32 KB), the fast path goes through `mcache` without any lock, making allocation very fast. In RE, the consequence is that you will almost never see `mmap` or `brk` in `strace` during normal execution — the runtime pre-allocates large arenas and slices them internally.

The main entry point is `runtime.mallocgc`. **Everything** goes through this function: `make([]byte, n)`, `new(MyStruct)`, implicit allocations during interface conversions, closures escaping the local scope.

> 💡 **RE tip**: setting a conditional breakpoint on `runtime.mallocgc` and filtering by allocation size is an effective way to spot important data structure allocations in a Go program. The first argument (in `RAX` with the register ABI) is the size of the object to allocate.

---

## Impact on Dynamic Analysis

### Threads vs Goroutines in GDB

When you run a Go binary under GDB, `info threads` will show you a few threads (typically 4 to 8, corresponding to the M's). But the program may have hundreds of active goroutines. GDB has no native knowledge of goroutines.

To list goroutines, you have several options:

- **Delve** (`dlv`), Go's native debugger, which understands goroutines (`goroutines`, `goroutine <id>` to switch context). But Delve assumes access to Go symbols and is not really designed for RE of stripped binaries.  
- **GDB with a custom script** that traverses the linked list `runtime.allgs` (slice of all G's) and displays the state and PC of each goroutine.  
- **GEF / pwndbg** do not have native Go support, but you can inspect `R14` (pointer to the current G) and manually navigate the structures.

### Signals and Interference

The Go runtime intercepts many signals for its own needs:

- `SIGURG` for asynchronous preemption,  
- `SIGSEGV` and `SIGBUS` for stack guard page detection,  
- `SIGPROF` for built-in CPU profiling (`pprof`).

During a GDB session, this can cause unexpected stops. Remember to configure GDB to ignore these signals:

```
handle SIGURG nostop noprint  
handle SIGPIPE nostop noprint  
```

---

## Recognizing a Go Binary Without Symbols

Even when facing a stripped and unknown binary, several clues betray a Go binary:

1. **The size** — an executable of several megabytes for simple functionality is suspicious.  
2. **Characteristic strings** — `runtime.`, `GOROOT`, `gopclntab`, `go.buildid`, `go1.` appear in `strings` even after stripping. Look especially for `go.buildid` and `runtime.main`.  
3. **The stack preamble** — the pattern `CMP RSP, [R14+0x10]; JBE` repeated in the majority of functions.  
4. **The ELF sections** — the presence of sections `.gopclntab`, `.go.buildid`, `.noptrdata`, `.noptrbss` is a strong indicator. Check with `readelf -S`.  
5. **The absence of dynamic dependencies** — `ldd` returns `not a dynamic executable` or lists only a few minimal dependencies.  
6. **The entry point** — `readelf -h` will display an entry point named `_rt0_amd64_linux` (or the equivalent for the target architecture).  
7. **The section entropy** — the `.rodata` section of a Go binary is often abnormally large (it contains all strings, type tables, and runtime metadata).

> 💡 **RE tip**: the quick command `strings binaire | grep -c 'runtime\.'` gives a good indicator. A typical C binary will return 0. A Go binary will return several hundred, even thousands of occurrences.

---

## Key Takeaways for What Follows

The Go runtime is omnipresent in the binary, but you must not let it overwhelm you. The effective approach in RE:

1. **Identify the runtime and ignore it.** Filter out `runtime.*`, `internal/*`, `sync.*`, etc. functions to focus on application packages (`main.*` and business packages).  
2. **Recognize recurring patterns.** The stack check preamble, GC write barriers, and scheduler calls are noise: learn to mentally skip them.  
3. **Exploit the runtime structures.** The `g` pointer in `R14`, the `gopclntab` table, and the type structures provide valuable information that the C runtime never offers.  
4. **Adapt your tools.** GDB alone is not ideal for Go. Delve, custom GDB scripts, or specific Ghidra plugins (section 34.4) will radically change your efficiency.

The following sections build on this understanding of the runtime to address calling conventions (34.2), data structures in memory (34.3), and symbol recovery (34.4).

⏭️ [Go Calling Convention (stack-based then register-based since Go 1.17)](/34-re-go/02-calling-convention.md)
