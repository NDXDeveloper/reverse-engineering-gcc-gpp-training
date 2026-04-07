🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part III — Dynamic Analysis

Static analysis gives you a view of the binary as it sits on disk — dynamic analysis shows you what it **actually does** when it runs. By setting breakpoints, hooking functions, tracing memory allocations, or bombarding a parser with malformed inputs, you observe the program's concrete behavior: which branches are taken, which data flows, which buffers overflow. The two approaches are complementary — static analysis formulates hypotheses, dynamic analysis confirms or invalidates them.

---

## 🎯 Objectives of this part

By the end of these five chapters, you will be able to:

1. **Debug any ELF binary with GDB** — including stripped and symbol-less ones — using conditional breakpoints, watchpoints, catchpoints, and the Python API to automate your sessions.  
2. **Leverage GDB extensions (GEF, pwndbg, PEDA)** to visualize the stack, registers, and heap in real time, and search for ROP gadgets directly from the debugger.  
3. **Instrument a running process with Frida**: hook C/C++ functions, intercept and modify arguments or return values on the fly, and trace code coverage with Stalker.  
4. **Detect memory bugs and profile execution** with Valgrind (Memcheck, Callgrind) and GCC sanitizers (`-fsanitize=address,undefined,memory`), then leverage these reports to understand the internal logic of the program.  
5. **Fuzz a binary compiled with GCC** via AFL++ or libFuzzer, analyze the crashes obtained, and use coverage maps to chart the program's execution paths.  
6. **Combine static and dynamic analysis** in an iterative workflow: identify a suspicious function in Ghidra, set a targeted breakpoint in GDB, hook its inputs/outputs with Frida, then validate with fuzzing.

---

## 📋 Chapters

| # | Title | Description | Link |  
|----|-------|-------------|------|  
| 11 | Debugging with GDB | Compilation with DWARF symbols, fundamental commands, inspecting stack/registers/memory, stripped binary, conditional breakpoints, watchpoints, catchpoints, `gdbserver`, GDB Python API, introduction to `pwntools`. | [Chapter 11](/11-gdb/README.md) |  
| 12 | Enhanced GDB: PEDA, GEF, pwndbg | Installation and comparison of the three extensions, real-time stack/register visualization, ROP gadget search, heap analysis with `vis_heap_chunks`. | [Chapter 12](/12-gdb-extensions/README.md) |  
| 13 | Dynamic instrumentation with Frida | JS agent architecture, injection modes (spawn vs attach), hooking C/C++ functions, intercepting `malloc`/`free`/`open`/custom, modifying arguments and returns live, Stalker for code coverage. | [Chapter 13](/13-frida/README.md) |  
| 14 | Analysis with Valgrind and sanitizers | Memcheck (leaks and invalid accesses), Callgrind + KCachegrind (profiling and call graph), ASan, UBSan, MSan — leveraging reports to understand internal logic. | [Chapter 14](/14-valgrind-sanitizers/README.md) |  
| 15 | Fuzzing for Reverse Engineering | AFL++ (instrumentation and first run), libFuzzer (in-process fuzzing), coverage-guided fuzzing, corpus and dictionary management, crash analysis to understand parsing logic. | [Chapter 15](/15-fuzzing/README.md) |

---

## 🛠️ Tools covered

- **GDB** — GNU debugger, the central tool of dynamic analysis under Linux.  
- **GEF** (GDB Enhanced Features) — exploitation and RE-oriented GDB extension, the most actively maintained.  
- **pwndbg** — GDB extension specialized in heap/exploitation, commands `vis_heap_chunks`, `bins`, `arena`.  
- **PEDA** (Python Exploit Development Assistance) — historical GDB extension, pattern and gadget search.  
- **`gdbserver`** — remote debugging (target on one machine, GDB on another).  
- **`pwntools`** — Python framework for automated interaction with binaries (I/O, patching, exploitation).  
- **Frida** — cross-platform dynamic instrumentation by injecting a JavaScript agent into the target process.  
- **`frida-trace`** — quick function tracing without writing a full script.  
- **Valgrind / Memcheck** — detection of memory leaks, uninitialized reads, out-of-bounds accesses.  
- **Callgrind + KCachegrind** — execution profiling and call graph visualization.  
- **AddressSanitizer (ASan)** — detects buffer overflows and use-after-free at compile time (`-fsanitize=address`).  
- **UndefinedBehaviorSanitizer (UBSan)** — detects undefined behavior (`-fsanitize=undefined`).  
- **MemorySanitizer (MSan)** — detects reads of uninitialized memory (`-fsanitize=memory`).  
- **AFL++** — reference coverage-guided fuzzer, enhanced fork of AFL.  
- **libFuzzer** — in-process fuzzer integrated with LLVM/Clang, compatible with sanitizers.  
- **`afl-cov` / `lcov`** — visualization of the code coverage reached by fuzzing.

---

## ⚠️ Precautions

Dynamic analysis requires **executing the binary**. If you are working on a program whose behavior you do not control — which is the case for any binary being reversed — systematically apply these rules:

- Work **exclusively in an isolated VM** (configured in Chapter 4). Never on your host machine.  
- Set the VM's network to **host-only or disconnected**. A binary that opens sockets should not reach the Internet.  
- Take a **snapshot before each execution**. If the binary alters the filesystem, you can roll back in one click.  
- The binaries of chapters 27-29 (educational malware) require reinforced isolation — Part VI details the setup of a dedicated secure lab.

---

## ⏱️ Estimated duration

**~20-28 hours** for a developer who has completed Parts I and II.

Chapter 11 (GDB) is the longest in this part (~6-8h): it is the tool you will use most in your daily RE practice, and mastering the Python API takes time. Chapter 12 (GDB extensions) is a quicker complement (~2-3h). Chapter 13 (Frida) requires familiarization with the Frida JavaScript API (~4-5h). Chapters 14 (Valgrind/sanitizers, ~3h) and 15 (fuzzing, ~4-5h) are more self-contained and can be tackled in the order that suits you.

---

## 📌 Prerequisites

Having completed **[Part I — Fundamentals & Environment](/part-1-fundamentals.md)** and **[Part II — Static Analysis](/part-2-static-analysis.md)**, or having the equivalent knowledge:

- Read an x86-64 disassembly and identify control structures (loops, conditions, function calls).  
- Navigate an ELF binary with `readelf`, `objdump`, or Ghidra.  
- Know the key ELF sections and the PLT/GOT mechanism.  
- Have an operational work VM with the tools installed.

Dynamic analysis constantly relies on what static analysis has revealed: you will set your breakpoints on functions identified in Ghidra, you will hook with Frida the calls spotted in `objdump`, you will fuzz the parsers whose code you read in the decompiler.

---

## ⬅️ Previous part

← [**Part II — Static Analysis**](/part-2-static-analysis.md)

## ➡️ Next part

With static and dynamic analysis under your belt, you will tackle advanced techniques: understanding compiler optimizations, reversing C++ (vtables, STL, templates), solving crackmes with symbolic execution, and bypassing anti-reversing protections.

→ [**Part IV — Advanced RE Techniques**](/part-4-advanced-techniques.md)

⏭️ [Chapter 11 — Debugging with GDB](/11-gdb/README.md)
