🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part II — Static Analysis

Static analysis consists of examining a binary **without ever executing it**: you work on the file as it sits on disk, reading its headers, sections, strings, and disassembled code. It is the first step of any Reverse Engineering effort — the one that lets you form solid hypotheses before setting a single breakpoint. This part takes you from the raw first contact with an unknown binary (`file`, `strings`) all the way to reconstructing complex structures in Ghidra, via fine-grained hexadecimal analysis with ImHex and version comparison with BinDiff.

---

## 🎯 Objectives of this part

By the end of these six chapters, you will be able to:

1. **Perform a complete triage of an unknown binary in under 5 minutes** — identify its format, dependencies, protections, readable strings, and likely system calls.  
2. **Write ImHex patterns (`.hexpat`)** to visualize and annotate arbitrary binary structures: ELF headers, custom protocols, proprietary file formats.  
3. **Disassemble and read the machine code** produced by GCC at different optimization levels, in Intel as well as AT&T syntax, and untangle C++ name mangling with `c++filt`.  
4. **Navigate Ghidra efficiently**: use the decompiler, trace cross-references, reconstruct C/C++ structures (vtables, structs, enums), and automate tasks with Java or Python scripts.  
5. **Use at least two disassemblers** among Ghidra, IDA Free, Radare2, and Binary Ninja, and choose the right tool depending on the context.  
6. **Compare two versions of the same binary** to precisely identify the modified functions — a skill directly applicable to security patch analysis.

---

## 📋 Chapters

| # | Title | Description | Link |  
|----|-------|-------------|------|  
| 5 | Basic binary inspection tools | `file`, `strings`, `xxd`, `readelf`, `objdump`, `nm`, `ldd`, `strace`, `ltrace`, `checksec` — quick triage and first reflexes when facing an unknown binary. | [Chapter 5](/05-basic-inspection-tools/README.md) |  
| 6 | ImHex: advanced hexadecimal analysis | Next-generation hex editor: `.hexpat` pattern language, parsing ELF headers and custom structures, colorization, binary diff, YARA rules. | [Chapter 6](/06-imhex/README.md) |  
| 7 | Disassembly with objdump and Binutils | Command-line disassembly, AT&T vs Intel syntax, impact of GCC optimizations, prologues/epilogues, C++ name mangling and `c++filt`. | [Chapter 7](/07-objdump-binutils/README.md) |  
| 8 | Advanced disassembly with Ghidra | ELF import, CodeBrowser, decompiler, renaming and typing, GCC vtables and RTTI, cross-references, Java/Python scripts, headless mode. | [Chapter 8](/08-ghidra/README.md) |  
| 9 | IDA Free, Radare2, and Binary Ninja | Alternative workflows: IDA Free on a GCC binary, Radare2/Cutter in CLI and GUI, r2pipe scripting, Binary Ninja Cloud, detailed comparison of the four tools. | [Chapter 9](/09-ida-radare2-binja/README.md) |  
| 10 | Binary diffing | Comparing two versions of a binary: BinDiff (Google), Diaphora (open source), `radiff2` in CLI. Practical case of identifying a vulnerability patch. | [Chapter 10](/10-binary-diffing/README.md) |

---

## 🛠️ Tools covered

- **`file`** — identifies the file type (ELF, PE, script, data).  
- **`strings`** — extracts readable ASCII/Unicode strings from a binary.  
- **`xxd` / `hexdump`** — raw hexadecimal dump at the command line.  
- **`readelf`** — detailed inspection of ELF headers, sections, and segments.  
- **`objdump`** — disassembly and display of symbol tables.  
- **`nm`** — listing of symbols (functions, global variables) of a binary or `.o`.  
- **`ldd`** — displays dynamic dependencies (shared libraries).  
- **`strace`** — traces system calls (syscalls) at runtime.  
- **`ltrace`** — traces dynamic library calls (libc, etc.).  
- **`checksec`** — inventory of binary protections (PIE, NX, canary, RELRO, ASLR).  
- **`c++filt`** — demangling of C++ symbols (Itanium ABI).  
- **ImHex** — advanced hex editor with pattern language, YARA, diff, and integrated disassembler.  
- **Ghidra** — NSA RE suite: disassembler, decompiler, type analysis, scripting.  
- **IDA Free** — reference interactive disassembler (free version).  
- **Radare2 / Cutter** — RE framework in CLI (r2) and GUI (Cutter), scriptable via r2pipe.  
- **Binary Ninja** — modern disassembler with intermediate IL (free Cloud version).  
- **BinDiff** — binary diffing by Google, integrated with Ghidra and IDA.  
- **Diaphora** — open source diffing plugin for Ghidra and IDA.  
- **`radiff2`** — command-line diffing via Radare2.

---

## ⏱️ Estimated duration

**~18-25 hours** for a developer who has completed Part I.

Chapter 5 (CLI tools) can be covered quickly if you are used to the terminal (~2h). Chapter 6 (ImHex) requires practice with `.hexpat` patterns (~3-4h). Chapters 7 through 9 form the core of this part: count ~4h for `objdump`/Binutils, ~5-6h for Ghidra (the most comprehensive tool to master), and ~3h for the IDA/r2/BinJa overview. Chapter 10 (diffing) is shorter (~2h) but very concrete.

---

## 📌 Prerequisites

Having completed **[Part I — Fundamentals & Environment](/part-1-fundamentals.md)**, or having the equivalent knowledge:

- Understand the structure of an ELF binary (headers, sections `.text`/`.data`/`.rodata`/`.plt`/`.got`).  
- Be able to read a basic x86-64 assembly listing (registers, `mov`, `call`, `cmp`, `jz`, prologue/epilogue).  
- Know the System V AMD64 calling convention (argument passing in `rdi`, `rsi`, `rdx`…).  
- Have a functional work environment with all tools installed (`check_env.sh` all green).

---

## ⬅️ Previous part

← [**Part I — Fundamentals & Environment**](/part-1-fundamentals.md)

## ➡️ Next part

Once static analysis is mastered, you will move on to dynamic analysis: running the binary under control with GDB, instrumenting its functions with Frida, detecting its flaws with Valgrind and AFL++.

→ [**Part III — Dynamic Analysis**](/part-3-dynamic-analysis.md)

⏭️ [Chapter 5 — Basic binary inspection tools](/05-basic-inspection-tools/README.md)
