🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 1.4 — Difference between static RE and dynamic RE

> **Chapter 1 — Introduction to Reverse Engineering**  
> 📦 No technical prerequisites — reading section.  
> 📖 The concepts introduced here will be developed in depth in Parts II (static analysis) and III (dynamic analysis).

---

## Two families of approaches, a single goal

Faced with an unknown binary, the reverse engineer has two major families of techniques at their disposal to understand how it works. These two approaches differ by a simple criterion: **is the program executed during the analysis, or not?**

**Static analysis** consists of examining the binary *without executing it*. You work on the file as it is stored on disk: its structure, its hexadecimal content, its disassembled code, its decompiled pseudo-code, its strings, its metadata.

**Dynamic analysis** consists of observing the program *during its execution*. You launch it (in a controlled environment) and observe what it does: which instructions it executes, which values pass through the registers, which files it opens, which network connections it establishes, how it reacts to different inputs.

These two approaches are not competitors — they are **complementary**. Each reveals information the other cannot easily provide. A competent reverse engineer masters both and moves seamlessly between them throughout a single analysis.

---

## Static analysis

### The principle

Static analysis treats the binary as a document to be read. You open it, examine its structure, disassemble the machine code into readable assembly instructions, and try to reconstruct the program's logic through reading and reasoning.

The most direct analogy would be that of a mechanic studying the blueprints of an engine — or, lacking blueprints, disassembling the engine piece by piece and examining each component — without ever running it.

### What static analysis lets you do

**Get an overview of the binary** — Before even reading a single assembly instruction, basic inspection tools reveal a considerable amount of information: the file format (ELF, PE, Mach-O), the target architecture (x86-64, ARM, MIPS), the sections and segments of the binary, the dynamically linked libraries, the exported and imported symbols, the embedded strings, the enabled protections (PIE, NX, canary, RELRO). This is the **triage** phase — the first five minutes in front of an unknown binary.

**Disassemble the machine code** — Disassembly transforms the raw bytes of the `.text` section into readable assembly instructions. A tool like `objdump` produces a linear listing; more sophisticated disassemblers like Ghidra, IDA, or Radare2 perform a recursive analysis that reconstructs the control flow graph (CFG), identifies functions, resolves cross-references, and recognizes certain compiler patterns.

**Decompile to high-level pseudo-code** — Decompilers (Ghidra Decompiler, Hex-Rays in IDA, RetDec) go one step further than disassembly: they try to reconstruct C-like pseudo-code from the assembly instructions. The result is never perfect (variable names are lost, types are approximate, control structures are sometimes poorly reconstructed), but it considerably accelerates understanding of the overall logic.

**Analyze the embedded data** — A binary contains more than just code. The `.data`, `.rodata`, and `.bss` sections contain constants, strings, value tables, initialized structures. Hexadecimal analysis with a tool like ImHex makes it possible to visualize these data, apply decoding patterns to them, and identify significant elements: cryptographic constants (AES S-box, SHA-256 IV), dispatch tables, message formats, hardcoded keys.

**Compare two versions of a binary** — *Binary diffing* is a purely static technique that consists of comparing two versions of the same program to identify modified, added, or removed functions. It is a central tool for analyzing security patches.

**Search for known patterns** — YARA rules make it possible to scan a binary for byte sequences, strings, or structural conditions that correspond to known signatures: malware families, embedded cryptographic libraries, packers, compiler signatures.

### The limits of static analysis

Static analysis is powerful but hits several obstacles:

**Self-modifying code and packing** — If a program modifies its own code in memory at runtime (unpacking, section decryption), static analysis only sees the encrypted or compressed code on disk — not the actual code that will be executed. The binary as it appears on disk is then only an envelope that hides the real program.

**Values known only at runtime** — Static analysis cannot determine the concrete value of a variable that depends on user input, a configuration file, a network response, the system time, or any other external data. It can identify that "this function compares the user input against a value derived from a computation on `rdx`", but it cannot always determine what value `rdx` will actually contain.

**Indirect calls and dynamic dispatch** — When code executes a `call rax` (indirect call) or resolves a C++ virtual method via a vtable, static analysis must reason about all possible values of `rax` or all classes that could be pointed to. In practice, resolving these indirections exhaustively is often impossible without running the program.

**Control flow obfuscation** — Obfuscation techniques like *control flow flattening* or *bogus control flow* transform a readable flow graph into a maze of basic blocks connected by a central dispatcher. Static analysis remains technically possible, but the time required explodes.

**Combinatorial explosion** — A real-sized program contains thousands of functions, millions of instructions, and countless execution paths. Exhaustive static analysis of such a program is a job of several weeks or months. In practice, the analyst must target areas of interest — and it is often dynamic analysis that indicates *where* to focus the effort.

### The tools of this training for static analysis

| Tool | Role | Chapters |  
|---|---|---|  
| `file`, `strings`, `xxd` | Quick triage | 5 |  
| `readelf`, `objdump`, `nm` | Inspecting the ELF structure | 5, 7 |  
| `checksec` | Protection inventory | 5 |  
| ImHex | Advanced hex analysis, `.hexpat` patterns | 6 |  
| Ghidra | Disassembly, decompilation, structure analysis | 8 |  
| IDA Free, Radare2, Binary Ninja | Alternative disassembly and decompilation | 9 |  
| BinDiff, Diaphora, `radiff2` | Binary diffing | 10 |  
| YARA | Pattern and signature detection | 6, 35 |

---

## Dynamic analysis

### The principle

Dynamic analysis consists of executing the program and observing its behavior in real time. You work with the live program: you launch it, provide it with inputs, set breakpoints, inspect memory, intercept system calls, modify values on the fly.

Returning to the engine analogy: this time, the mechanic runs the engine and observes its operation — listening to sounds, measuring temperatures, checking pressures, testing reactions at different RPMs.

### What dynamic analysis lets you do

**Observe the program's actual behavior** — Dynamic analysis shows what the program *actually* does for a given set of inputs, without ambiguity. It does not show what the program *could* do under other circumstances (that is a limitation), but what it shows is certain.

**Resolve concrete values** — Registers, in-memory variables, function arguments, return values — everything is observable during execution. What was an abstract `mov rdi, [rbp-0x18]` in static analysis becomes "`rdi` is `0x7fffffffde30`, which points to the string `"admin123"`". This concrete resolution is often the decisive moment of an analysis.

**Trace system calls and library calls** — The `strace` and `ltrace` tools make it possible to capture all system calls and calls to shared libraries made by the program. Without reading a single assembly instruction, you can know that the program opens the `/etc/shadow` file, sends a UDP packet to address `192.168.1.42:4444`, or allocates 65,536 bytes of memory.

**Debug step by step** — A debugger like GDB makes it possible to execute the program instruction by instruction, inspect the complete machine state (registers, stack, heap, flags) at each step, and set sophisticated stop conditions (conditional breakpoints, watchpoints on memory regions, catchpoints on system events).

**Modify execution in progress** — Dynamic analysis is not limited to passive observation. With GDB, you can modify the value of a register or of a variable in memory to force the program to take a different branch. With Frida, you can intercept a function call, modify its arguments or return value, and inject JavaScript code into the target process — all without modifying the binary on disk.

**Analyze code actually executed after unpacking** — When a binary is packed or encrypted, dynamic analysis makes it possible to wait for the code to be decompressed or decrypted in memory, then capture (dump) it in its decrypted state for static analysis. This is the standard technique for dealing with packed binaries.

**Explore execution paths through fuzzing** — Fuzzing consists of bombarding the program with randomly generated or mutated inputs, guided by code coverage. This is not a manual analysis, but it is a form of automated dynamic analysis that explores execution paths the analyst might never have taken manually, and that reveals unexpected behaviors (crashes, hangs, abnormal memory consumption).

### The limits of dynamic analysis

**Partial coverage** — Dynamic analysis only observes the execution paths actually taken during the test. If the program contains a backdoor activated only when the input is `"xK9#mZ$2"` on a Tuesday at 3 a.m., dynamic analysis will probably not find it — unless the fuzzer gets lucky or the analyst knows what to look for.

**The execution environment** — The program has to be run, which presupposes a compatible environment: the right operating system, the right libraries, the right hardware (or an emulator). Dynamically analyzing an ARM binary on an x86-64 machine requires an emulator like QEMU, which adds complexity and limitations.

**Execution risk** — Executing an unknown binary carries risks. If the binary is malware, it can damage the system, exfiltrate data, or propagate over the network. That is why dynamic analysis of potentially malicious code must **always** take place in an isolated environment (sandboxed VM, disconnected network). Chapter 26 details how to set up such a lab.

**Detection of analysis** — Some programs integrate techniques for detecting a debugger or analysis environment: checking for `ptrace`, timing measurements to detect single-stepping, inspection of `/proc/self/status`, virtual-machine detection. These techniques complicate dynamic analysis and require specific countermeasures (covered in Chapter 19).

**Time cost for complex programs** — Debugging a program step by step is a slow process. A program that runs a million iterations before reaching the area of interest makes single-stepping impractical. The analyst must then combine intelligent breakpoints, stop conditions, and prior knowledge of the code (obtained through static analysis) to directly target the relevant areas.

### The tools of this training for dynamic analysis

| Tool | Role | Chapters |  
|---|---|---|  
| `strace`, `ltrace` | Tracing system and library calls | 5 |  
| GDB | Step-by-step debugging, memory inspection | 11 |  
| GEF / pwndbg / PEDA | GDB extensions (visualization, heap, ROP gadgets) | 12 |  
| Frida | Dynamic instrumentation, function hooking | 13 |  
| Valgrind, sanitizers | Memory bug detection, profiling | 14 |  
| AFL++, libFuzzer | Coverage-guided fuzzing | 15 |  
| angr | Symbolic execution (hybrid static/dynamic) | 18 |

---

## Complementarity in practice

The strength of reverse engineering lies in the ability to combine the two approaches fluidly. In practice, an analysis rarely follows a purely static or purely dynamic path. The typical workflow looks more like an iterative loop:

### The static → dynamic → static cycle

**1. Static triage** — First reflexes when facing the binary: `file` to identify the format, `strings` to spot revealing strings, `readelf` to understand the structure, `checksec` to inventory protections. In a few minutes, you have a first idea of what you are dealing with.

**2. Targeted static analysis** — You open the binary in Ghidra or another disassembler. You locate `main`, identify the key functions, read the decompiled pseudo-code. You form hypotheses: "this function appears to verify a password by comparing it against a SHA-256 hash", "this block seems to decrypt a buffer with XOR".

**3. Dynamic validation** — You launch the program in GDB to verify your hypotheses. You set a breakpoint on the suspicious function, run the program with a known input, and observe the concrete values. The hypothesis is confirmed, refined, or collapses.

**4. Back to static analysis** — Dynamic observations guide the rest of the static analysis. You now know that the function at address `0x401280` is the verification routine — you can focus your reading on this function and its callers, trace cross-references, and understand how user input reaches the comparison.

**5. Dynamic deepening** — You return to GDB or Frida to explore a specific aspect: intercept the arguments of `strcmp`, modify a return value to force a branch, dump a decrypted buffer from memory.

This cycle repeats as many times as necessary. Each iteration brings new information that refines the understanding of the program.

### A concrete example

Imagine a program that asks for a password and displays "Access Granted" or "Access Denied".

**Static analysis** lets you locate the strings `"Access Granted"` and `"Access Denied"` in the `.rodata` section, follow cross-references back to the function that uses them, and read the disassembled code of that function to identify the comparison logic. You see a `call` to an internal function, a `test eax, eax`, then a `jnz` that jumps to the error message. You have identified the structure of the verification, but you do not yet know what password is expected — the comparison value may be computed dynamically.

**Dynamic analysis** lets you set a breakpoint just before the comparison, launch the program with any password, and inspect the registers and memory at that precise point. You see the expected value in plaintext in a register or on the stack. The password is found.

Neither of the two approaches would have been optimal on its own. Static analysis alone could have worked, but would have required understanding the key derivation algorithm in detail — potentially a long job. Dynamic analysis alone could have worked too, but without knowing where to set the breakpoint, the analyst would have fumbled. It is the combination of the two that produces a fast, reliable result.

---

## The special case of symbolic execution

**Symbolic execution** (Chapter 18) deserves a special mention, because it sits at the border between the two approaches. The principle is to "simulate" the execution of the program by replacing concrete inputs with **symbolic variables** — mathematical unknowns. Instead of computing `x + 5 = 12` with `x = 7`, symbolic execution propagates the symbol `x` through the program and accumulates **constraints** at each conditional branch.

When an execution path reaches a point of interest (the "Access Granted" branch, for example), the tool passes the accumulated constraints to a **constraint solver** (Z3, typically) which computes a concrete input value satisfying all the constraints — that is, a valid password.

Symbolic execution does not execute the program in the classical sense (it does not produce real system calls), but it is not content with statically reading the code either (it explores execution paths). It is a **hybrid** technique that combines static reasoning about the code with systematic path exploration — and it is formidably effective on certain types of problems, notably crackmes and license checks.

> 🔬 **Deep dive** — Symbolic execution has well-known limits, notably **path explosion** (the number of possible paths grows exponentially with the size of the program) and the difficulty of modeling system calls and interactions with the environment. Chapter 18 details these limits and the strategies for working around them.

---

## Summary

| | Static analysis | Dynamic analysis |  
|---|---|---|  
| **Executes the binary** | No | Yes |  
| **What it observes** | The binary on disk: code, data, structure | The running program: registers, memory, behavior |  
| **Coverage** | Total in theory (all code is visible) | Partial (only the paths taken are observed) |  
| **Variable values** | Unknown or to be deduced by reasoning | Concrete, directly observable |  
| **Packed/encrypted code** | Invisible (seen in encrypted form) | Visible after decompression in memory |  
| **Execution risk** | None | Real (malware, side effects) — requires a sandbox |  
| **Indirect calls** | Difficult to resolve | Naturally resolved through execution |  
| **Anti-analysis** | Flow obfuscation, bogus graphs | Debugger detection, timing checks |  
| **Main tools (this training)** | `readelf`, Ghidra, ImHex, YARA | GDB, Frida, `strace`, AFL++ |

---

> 📖 **Takeaway** — Static analysis and dynamic analysis are the two complementary pillars of reverse engineering. Static analysis offers an exhaustive but abstract view of the binary. Dynamic analysis offers concrete but partial observations. The effective reverse engineer combines both in an iterative cycle: statically observe to formulate hypotheses, dynamically execute to validate them, then return to static analysis with the information obtained. This back-and-forth is what this training teaches.

---


⏭️ [Overview of the methodology and tools used in this tutorial](/01-introduction-re/05-methodology-tools.md)
