🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 1.5 — Overview of the methodology and tools used in this tutorial

> **Chapter 1 — Introduction to Reverse Engineering**  
> 📦 No technical prerequisites — reading section.  
> 📖 This section presents the overall workflow and the tools. Installation and configuration are covered in [Chapter 4](/04-work-environment/README.md).

---

## A methodology before tools

One of the most frequent mistakes among reverse engineering beginners is to rush into a tool — opening Ghidra, loading the binary, and starting to read decompiled pseudo-code — without first establishing a strategy. The result is often erratic navigation across an ocean of functions, with no idea what to look for or how to prioritize information.

Effective RE rests on a **structured methodology**: a sequence of phases, each with its objectives and tools, that makes it possible to move progressively from total ignorance to a sufficient understanding of the binary to reach the stated goal (understand an algorithm, find a vulnerability, extract a protocol, etc.).

This training teaches a methodology in **five phases**, which forms the guiding thread of all the practical analyses in Parts II through VI. These phases are not rigidly sequential — as seen in section 1.4, RE is an iterative process — but they provide a working framework that keeps you from going in circles.

---

## The five phases of analysis

### Phase 1 — Triage and reconnaissance

**Goal**: in under five minutes, obtain a profile of the binary without reading a single assembly instruction.

This is the first-contact phase. You have just received a binary file — perhaps as part of a CTF, an audit, or a malware analysis. Before anything else, you must answer a set of fundamental questions:

- **What type of file?** ELF, PE, Mach-O, script, archive? The `file` command answers in one second.  
- **Which architecture?** x86-64, x86-32, ARM, MIPS? `file` or `readelf -h` tells you.  
- **Statically or dynamically linked?** `ldd` lists the dynamic dependencies. A binary with no dependency is probably statically linked — which significantly changes the analysis approach.  
- **Stripped or not?** `file` indicates "not stripped" or "stripped". `nm` confirms the presence or absence of symbols.  
- **Which strings are embedded?** `strings` extracts sequences of printable characters. Error messages, URLs, file paths, library function names, and text constants are often the first clues about the program's functionality.  
- **Which protections are enabled?** `checksec` provides a quick inventory: PIE, NX, canary, RELRO (partial or full), ASLR. This information shapes the dynamic analysis strategy.  
- **What is the internal structure?** `readelf -S` lists the ELF sections. The presence or absence of certain sections (`.debug_info`, `.plt`, `.got`, `.eh_frame`) gives indications about the compilation mode and the program's features.

At the end of triage, you have an **identity card** of the binary. You do not yet know what it does, but you know what you are dealing with, and you have identified the first leads to explore.

**Main tools**: `file`, `strings`, `readelf`, `objdump -f`, `nm`, `ldd`, `checksec`, `xxd`/`hexdump`.

**Reference chapter**: [5 — Basic binary inspection tools](/05-basic-inspection-tools/README.md), and in particular [5.7 — Quick triage workflow](/05-basic-inspection-tools/07-quick-triage-workflow.md).

---

### Phase 2 — In-depth static analysis

**Goal**: understand the structure and logic of the program through examining the disassembled and decompiled code, without executing it.

This is the longest and most intellectually demanding phase. You load the binary into a disassembler/decompiler and start reconstructing its logic.

Work generally proceeds from the general to the specific:

**Identify the entry points** — The `main` function is the natural starting point for a C program. In a C++ binary, the global constructor (`__libc_csu_init`) may also deserve examination. For a stripped binary, the ELF entry point (`_start`) leads to `__libc_start_main`, whose first argument is the address of `main`. Disassemblers like Ghidra generally identify `main` automatically, even on a stripped binary.

**Map the functions** — Scan through the list of functions identified by the disassembler, spot those with meaningful names (if the binary is not stripped), identify functions imported from shared libraries (`printf`, `strcmp`, `malloc`, `send`, `recv`, `AES_encrypt`…). Imports are major clues about the program's capabilities.

**Follow the control flow** — Starting from `main`, follow function calls in depth. Control flow graphs (CFG) and cross-references (XREF) are your main navigation tools. Ghidra, IDA, and Radare2 all offer graphical views of the CFG that make it easier to understand conditional branches and loops.

**Rename and annotate** — As understanding grows, rename functions, variables, and types in the disassembler. `FUN_00401280` becomes `verify_password`. `DAT_00404060` becomes `expected_hash`. This step is crucial: it transforms an opaque listing into a readable document, and it capitalizes your work for the next analysis sessions.

**Analyze the data** — Examine data sections with ImHex. Apply `.hexpat` patterns to visualize binary structures: custom file headers, configuration tables, encrypted buffers. Identify the magic constants that betray the use of known algorithms (the AES S-box constants, the initial values of SHA-256, etc.).

**Main tools**: Ghidra (disassembly, decompilation, XREF, scripting), IDA Free, Radare2/Cutter, Binary Ninja Cloud, ImHex, `objdump -d -M intel`, `c++filt`, BinDiff/Diaphora (diffing).

**Reference chapters**: [6 — ImHex](/06-imhex/README.md), [7 — objdump and Binutils](/07-objdump-binutils/README.md), [8 — Ghidra](/08-ghidra/README.md), [9 — IDA, Radare2, Binary Ninja](/09-ida-radare2-binja/README.md), [10 — Binary diffing](/10-binary-diffing/README.md).

---

### Phase 3 — Targeted dynamic analysis

**Goal**: validate the hypotheses formed during static analysis by observing the running program, and obtain the concrete values inaccessible to static analysis.

Dynamic analysis is not blind exploration — it is **guided by static analysis**. You already know, thanks to phase 2, which functions interest you, which branches are critical, which memory regions contain sensitive data. Phase 3 consists of verifying and completing this understanding through direct observation.

**Trace the overall behavior** — Before pulling out GDB, a first execution supervised by `strace` and `ltrace` gives an overview of the runtime behavior: files opened, sockets created, child processes launched, signals received, library calls made. It is a quick complement to static triage.

**Debug the areas of interest** — Set breakpoints on the functions identified in phase 2, run the program, inspect registers and memory at the critical points. GDB extensions like GEF or pwndbg make this step much more visual by constantly displaying the state of registers, stack, and surrounding code.

**Instrument without modifying the binary** — Frida makes it possible to intercept function calls, read and modify arguments and return values, and trace execution flow — all via JavaScript scripts injected into the process, without touching the binary on disk. It is a particularly powerful tool for RE of network protocols and encryption schemes.

**Explore via fuzzing** — When the program's input surface is large or poorly understood, fuzzing with AFL++ or libFuzzer makes it possible to discover unexpected execution paths, revealing crashes, and boundary behaviors that shed light on parsing logic.

**Main tools**: GDB (with GEF, pwndbg, or PEDA), `strace`, `ltrace`, Frida, Valgrind/Memcheck, AFL++, libFuzzer, `pwntools`.

**Reference chapters**: [11 — GDB](/11-gdb/README.md), [12 — Enhanced GDB](/12-gdb-extensions/README.md), [13 — Frida](/13-frida/README.md), [14 — Valgrind and sanitizers](/14-valgrind-sanitizers/README.md), [15 — Fuzzing](/15-fuzzing/README.md).

---

### Phase 4 — Advanced techniques (if necessary)

**Goal**: overcome the obstacles that phases 2 and 3 cannot resolve — aggressive optimizations, complex C++ constructs, anti-RE protections, symbolic execution.

Not all binaries require this phase. A program compiled with `-O0` and symbols can be analyzed comfortably with the techniques of phases 2 and 3. But a binary compiled with `-O3`, stripped, obfuscated, or packed puts up resistance that demands additional techniques.

**Recognize the effects of optimizations** — The compiler reorganizes code in sometimes radical ways: inlining, loop unrolling, tail call optimization, SIMD vectorization. Recognizing these transformations avoids wasting time analyzing code that has no direct equivalent in the original source.

**Analyze C++ at the binary level** — C++ constructs (vtables, RTTI, exceptions, templates, smart pointers, STL) generate specific assembly patterns that the analyst must learn to recognize. Without this knowledge, an optimized C++ binary is an opaque wall.

**Bypass anti-RE protections** — Stripping, packing (UPX and custom packers), control flow obfuscation (control flow flattening), debugger detection (`ptrace`, timing checks), breakpoint countermeasures. Each protection has its bypass techniques.

**Resort to symbolic execution** — For certain problems (crackme solving, systematic branch exploration), symbolic execution with angr or manual constraint modeling with Z3 makes it possible to obtain results that manual analysis would take hours to produce.

**Main tools**: Ghidra (C++ type reconstruction), angr, Z3, `checksec`, UPX (unpacking), GDB (anti-debug bypass).

**Reference chapters**: [16 — Compiler optimizations](/16-compiler-optimizations/README.md), [17 — C++ RE with GCC](/17-re-cpp-gcc/README.md), [18 — Symbolic execution](/18-symbolic-execution/README.md), [19 — Anti-reversing](/19-anti-reversing/README.md), [20 — Decompilation and reconstruction](/20-decompilation/README.md).

---

### Phase 5 — Leveraging the results

**Goal**: produce a concrete deliverable from the acquired understanding — keygen, replacement client, decryptor, analysis report, format specification, patch.

RE is only complete when understanding is **materialized** into something usable. Depending on the initial goal of the analysis, this deliverable can take different forms:

- **A keygen** — A Python script that generates valid keys by reproducing the verification algorithm identified (Chapter 21).  
- **A replacement client or server** — A program that implements the reversed network protocol, able to communicate with the original binary (Chapter 23).  
- **A decryptor** — A tool that reproduces the identified encryption scheme to decrypt protected data (Chapter 24).  
- **A format parser** — A program that reads and writes files in the identified proprietary format (Chapter 25).  
- **An analysis report** — A structured document describing the capabilities, IOCs, C2 protocol, and recommendations, in the case of malware analysis (Chapter 27).  
- **A specification** — A technical document describing an identified protocol or file format, reusable by other developers (Chapter 25).  
- **A binary patch** — A direct modification of the binary to fix a behavior or bypass a verification (Chapter 21).  
- **A compatible plugin** — A `.so` module developed from understanding an application's plugin interface (Chapter 22).

**Main tools**: Python, `pwntools`, ImHex (patching), `lief`/`pyelftools` (ELF modification), YARA (detection), Ghidra headless scripts (automation).

**Reference chapters**: [21–25 — Practical cases](/part-5-practical-cases.md), [27–28 — Malware analysis](/part-6-malware.md), [35 — Automation and scripting](/35-automation-scripting/README.md).

---

## Workflow overview

The five phases form a funnel: you start from a broad, coarse view (triage), progressively refine understanding (static analysis, then dynamic), mobilize specialized techniques if necessary (phase 4), and materialize the result (phase 5). The whole process is iterative — phases 2 and 3, in particular, feed each other in a loop.

```
 ┌─────────────────────────────────────┐
 │  Phase 1 — Triage & reconnaissance  │  file, strings, readelf, checksec
 └──────────────────┬──────────────────┘
                    ▼
 ┌─────────────────────────────────────┐
 │  Phase 2 — Static analysis          │  Ghidra, ImHex, objdump, YARA
 └──────────────────┬──────────────────┘
                    ▼
            ┌───────────────┐
            │  Hypotheses   │
            └───────┬───────┘
                    ▼
 ┌─────────────────────────────────────┐
 │  Phase 3 — Dynamic analysis         │  GDB, Frida, strace, AFL++
 └──────────────────┬──────────────────┘
                    │
          ┌─────────┴─────────┐
          │  Validation /     │
          │  New leads        │
          └─────────┬─────────┘
                    │
         ┌──── Sufficient? ────┐
         │                     │
         No                   Yes
         │                     │
         ▼                     ▼
 ┌──────────────────┐  ┌──────────────────────────┐
 │  Phase 4 —       │  │  Phase 5 — Leveraging    │
 │  Advanced        │  │  the results             │
 │  (anti-RE, C++,  │  │  (keygen, report,        │
 │   symex, optim.) │  │   parser, patch…)        │
 └────────┬─────────┘  └──────────────────────────┘
          │
          └──────► Back to Phase 2 or 3
```

> 💡 **This diagram is a guide, not a straitjacket.** In practice, an experienced analyst can skip phases, backtrack, or run several phases in parallel. The important thing is to have a mental framework that structures the approach and keeps you from getting lost.

---

## Overview of this training's tools

The table below summarizes all the tools used in this training, classified by category. Each tool is introduced in a dedicated chapter with installation and getting-started instructions. No installation is required at this stage — Chapter 4 and the `check_env.sh` script take care of it.

### Inspection and triage

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| `file` | File type identification | GPL | CLI | 5 |  
| `strings` | String extraction | GPL | CLI | 5 |  
| `xxd` / `hexdump` | Raw hexadecimal dump | GPL | CLI | 5 |  
| `readelf` | Inspection of ELF headers and sections | GPL | CLI | 5 |  
| `objdump` | Disassembly and binary inspection | GPL | CLI | 5, 7 |  
| `nm` | Symbol listing | GPL | CLI | 5 |  
| `ldd` | Dynamic dependencies | GPL | CLI | 5 |  
| `checksec` | Binary protection inventory | GPL | CLI | 5 |  
| `c++filt` | C++ symbol demangling | GPL | CLI | 7 |  
| `binwalk` | Analysis of firmwares and composite files | MIT | CLI | 25 |

### Hexadecimal analysis

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| ImHex | Advanced hex editor with `.hexpat` patterns, YARA, diff | GPL-2.0 | GUI | 6 |

### Disassembly and decompilation

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| Ghidra | Full RE framework (NSA): disassembly, decompilation, scripting | Apache 2.0 | GUI + headless | 8 |  
| IDA Free | Interactive disassembler (free version) | Freeware | GUI | 9 |  
| Radare2 / Cutter | Command-line RE framework (+ Cutter GUI) | LGPL-3.0 | CLI + GUI | 9 |  
| Binary Ninja Cloud | Online disassembler/decompiler (free version) | Freeware | Web | 9 |  
| RetDec | Offline static decompiler (Avast) | MIT | CLI | 20 |

### Binary diffing

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| BinDiff | Binary comparison (Google) | Apache 2.0 | GUI (Ghidra/IDA plugin) | 10 |  
| Diaphora | Open source diffing plugin for Ghidra/IDA | GPL | Plugin | 10 |  
| `radiff2` | Command-line diffing (Radare2) | LGPL-3.0 | CLI | 10 |

### Debugging

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| GDB | GNU debugger — the fundamental tool | GPL | CLI | 11 |  
| GEF | GDB extension: visualization, exploitation | MIT | CLI (GDB plugin) | 12 |  
| pwndbg | GDB extension: heap analysis, exploitation | MIT | CLI (GDB plugin) | 12 |  
| PEDA | GDB extension: exploitation | BSD | CLI (GDB plugin) | 12 |  
| `gdbserver` | Remote debugging | GPL | CLI | 11 |

### Dynamic instrumentation

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| Frida | Dynamic instrumentation via JS injection | wxWindows | CLI + scripting | 13 |  
| `strace` | System call tracing | BSD | CLI | 5 |  
| `ltrace` | Library call tracing | GPL | CLI | 5 |

### Memory analysis and profiling

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| Valgrind (Memcheck) | Memory leak and error detection | GPL | CLI | 14 |  
| Callgrind + KCachegrind | Profiling and call graph | GPL | CLI + GUI | 14 |  
| ASan / UBSan / MSan | GCC/Clang sanitizers (compile with `-fsanitize`) | Apache 2.0 | Built-in | 14 |

### Fuzzing

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| AFL++ | Coverage-guided fuzzer (mutation + instrumentation) | Apache 2.0 | CLI | 15 |  
| libFuzzer | In-process fuzzer integrated with Clang | Apache 2.0 | Built-in | 15 |

### Symbolic execution and solvers

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| angr | Python symbolic execution framework | BSD | Python API | 18 |  
| Z3 | SMT solver (Microsoft Research) | MIT | Python API | 18 |

### Scripting and automation

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| `pwntools` | Python framework for CTF and exploitation | MIT | Python | 11, 21, 23 |  
| `pyelftools` | ELF parsing in Python | Public domain | Python | 35 |  
| `lief` | Parsing and modification of binaries (ELF, PE, Mach-O) | Apache 2.0 | Python / C++ | 35 |  
| YARA | Pattern detection via rules | BSD | CLI + Python | 6, 27, 35 |  
| Ghidra headless | Automated batch-mode analysis | Apache 2.0 | CLI + Java/Python | 8, 35 |  
| r2pipe | Radare2 scripting via Python pipe | LGPL-3.0 | Python | 9 |  
| GDB Python API | GDB scripting in Python | GPL | Python | 11 |

### .NET tools (Part VII — bonus)

| Tool | Description | License | Interface | Chapter |  
|---|---|---|---|---|  
| ILSpy | Open source C# decompiler | MIT | GUI | 31 |  
| dnSpy / dnSpyEx | .NET decompiler + debugger | GPL | GUI | 31, 32 |  
| dotPeek | .NET decompiler (JetBrains) | Freeware | GUI | 31 |  
| de4dot | .NET deobfuscator | GPL | CLI | 31 |

---

## Why these tools and not others?

The selection of tools for this training follows three criteria:

**Accessibility** — Almost all of the tools are free and open source. The few exceptions (IDA Free, Binary Ninja Cloud, dotPeek) are available in a free version. The goal is that no financial barrier should block learning.

**Complementarity** — Each tool has a precise role in the workflow. There is no unnecessary redundancy, but there is deliberate coverage of several disassemblers (Ghidra, IDA, Radare2, Binary Ninja) so that you can choose the one best suited to your workflow once the training is over. Chapter 9 provides a detailed comparison.

**Professional relevance** — These are the tools used by RE professionals in the industry. Ghidra has become a de facto standard since its release by the NSA in 2019. GDB with GEF/pwndbg is the dominant debugging environment under Linux. Frida is the reference dynamic instrumentation tool. AFL++ is the most widely used fuzzer. Mastering these tools means being immediately operational in a professional context.

> 💡 **You do not need to master all these tools.** The training presents them all, but in practice most analysts develop an affinity with a subset of tools they use daily, only reaching for others when a specific problem demands it. What matters is to know that each tool exists, what it does, and when it is relevant to bring it out.

---

> 📖 **Takeaway** — RE follows a five-phase methodology: triage, static analysis, dynamic analysis, advanced techniques (if necessary), and leveraging the results. This workflow is iterative — phases 2 and 3 feed each other in a loop. Each phase has its dedicated tools, all free or open source, covered by a specific chapter of the training. Installation and configuration of these tools are covered in Chapter 4.

---


⏭️ [Target taxonomy: native binary, bytecode, firmware — where this tutorial fits](/01-introduction-re/06-target-taxonomy.md)
