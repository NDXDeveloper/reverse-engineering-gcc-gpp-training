🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 11 — Debugging with GDB

> **Part III — Dynamic Analysis**

---

## Introduction

Previous chapters taught us to read a binary without ever executing it: disassembly, inspection of ELF sections, hexadecimal analysis, cross-references in Ghidra. This static approach is powerful, but it reaches its limits as soon as the program's behavior depends on data computed at runtime — a value derived from user input, a dynamically resolved pointer, an internal state modified across calls. To understand what *really* happens, you have to observe the program while it's running. That's the role of dynamic analysis, and its fundamental tool on Linux is **GDB** (GNU Debugger).

GDB has existed since 1986. It's an integral part of the GNU chain we studied in Chapter 2, and it is installed by default on nearly all Linux distributions. Behind its austere command-line interface lies a debugger of remarkable depth: it allows setting breakpoints at any address, inspecting memory byte by byte, modifying registers on the fly, tracing system calls, and even being fully scripted in Python. For the reverse engineer, GDB is the equivalent of a microscope: where Ghidra shows the overall structure, GDB reveals the exact state of the program at a given instant.

## Why GDB is indispensable in RE

In static analysis, you reason about what the code *might* do. In dynamic analysis with GDB, you observe what it *actually* does, with concrete values in registers and memory. This difference is fundamental in several common situations:

- **Values computed at runtime.** A key-verification algorithm can combine user input with constants, cascading XOR operations, bit rotations. In static analysis, you must mentally reconstruct each step. With GDB, you set a breakpoint just before the final comparison and directly read the expected value from a register.

- **Pointer and address resolution.** In a PIE binary with ASLR enabled, absolute addresses change at each execution. GDB resolves all of this automatically: it displays effective addresses, follows indirections through C++ vtables, and lets you navigate the heap just like the stack.

- **Obfuscated or self-modifying code.** Some binaries modify their own code in memory before executing it, or decrypt code portions on the fly. Static analysis only sees the encrypted code. GDB lets you wait until decryption is complete, then examine the real code.

- **Exploring third-party libraries.** When a binary calls functions from shared libraries (OpenSSL, zlib, etc.), GDB allows following execution into these libraries, inspecting the arguments passed and the values returned, without needing to read their source code.

## What this chapter covers

This chapter is the densest of Part III, because GDB will be our constant companion for the rest of the training. We'll build skills progressively:

We'll start with **compilation with debug symbols** (`-g` and the DWARF format), to understand what GDB knows — or doesn't know — about the binary it analyzes. We'll then see the **fundamental commands**: setting breakpoints, stepping instruction by instruction, inspecting registers and memory. With these basics acquired, we'll tackle the realistic case of a **stripped binary** — without any symbols — and techniques to navigate despite that.

The second half of the chapter ramps up with **conditional breakpoints and watchpoints**, which allow stopping only when a specific condition is met (a variable reaches a certain value, a memory zone is modified). We'll see **catchpoints**, which intercept system events like `fork`, `exec`, or signals. We'll cover **remote debugging** with `gdbserver`, indispensable for analyzing a binary in a sandboxed VM from the comfort of our host machine.

Finally, we'll discover two major GDB extensions: its **Python API**, which allows automating complex analysis tasks via scripts, and **pwntools**, the reference Python library for programmatically interacting with a binary — sending inputs, reading outputs, and driving GDB in parallel.

## Prerequisites for this chapter

This chapter relies directly on knowledge built in previous chapters:

- **Chapter 2** — The GNU compilation chain: understanding how a source file becomes an ELF binary, and the role of `.text`, `.data`, `.plt`/`.got` sections.  
- **Chapter 3** — x86-64 assembly: reading instructions, knowing registers (`rax`, `rdi`, `rsp`, `rbp`, `rip`), understanding the stack and System V AMD64 calling conventions.  
- **Chapter 5** — Inspection tools: `file`, `readelf`, `checksec` for initial triage before launching GDB.  
- **Chapter 7 or 8** — Disassembly with `objdump` or Ghidra: knowing how to locate a function of interest in the static disassembly before setting a breakpoint.

If reading a 20-line assembly listing still makes you uncomfortable, take the time to review section 3.7 (*Reading an assembly listing without panicking*) before continuing.

## Required tools

All these tools must be functional in your environment. If you followed Chapter 4 and `check_env.sh` is green, everything is in place.

| Tool | Minimum version | Role in this chapter |  
|---|---|---|  
| `gdb` | 12.x+ | Main debugger |  
| `gcc` / `g++` | 12.x+ | Compilation of training binaries with `-g` |  
| `gdbserver` | (included with GDB) | Remote debugging (section 11.7) |  
| Python 3 | 3.10+ | GDB Python scripts (section 11.8) and pwntools (section 11.9) |  
| `pwntools` | 4.x+ | Interaction automation (section 11.9) |

## Reading advice

GDB is learned by practicing it. Each section of this chapter contains commands to type and outputs to observe. Keep a terminal open with GDB alongside your reading: reproduce each example on the binaries provided in `binaries/ch11-keygenme/`. The `keygenme_O0` binary (compiled without optimization, with symbols) is the ideal companion for the first sections; we'll move to stripped and optimized variants as we progress.

---

## Chapter outline

- 11.1 [Compilation with debug symbols (`-g`, DWARF)](/11-gdb/01-debug-symbols-compilation.md)  
- 11.2 [Fundamental GDB commands: `break`, `run`, `next`, `step`, `info`, `x`, `print`](/11-gdb/02-fundamental-commands.md)  
- 11.3 [Inspecting the stack, registers, memory (format and sizes)](/11-gdb/03-inspecting-stack-registers-memory.md)  
- 11.4 [GDB on a stripped binary — working without symbols](/11-gdb/04-gdb-stripped-binary.md)  
- 11.5 [Conditional breakpoints and watchpoints (memory and registers)](/11-gdb/05-conditional-breakpoints-watchpoints.md)  
- 11.6 [Catchpoints: intercepting `fork`, `exec`, `syscall`, signals](/11-gdb/06-catchpoints.md)  
- 11.7 [Remote debugging with `gdbserver` (debugging on a remote target)](/11-gdb/07-remote-debugging-gdbserver.md)  
- 11.8 [GDB Python API — scripting and automation](/11-gdb/08-gdb-python-api.md)  
- 11.9 [Introduction to `pwntools` to automate interactions with a binary](/11-gdb/09-introduction-pwntools.md)  
- 🎯 [Checkpoint: write a GDB Python script that automatically dumps the arguments of each call to `strcmp`](/11-gdb/checkpoint.md)

⏭️ [Compilation with debug symbols (`-g`, DWARF)](/11-gdb/01-debug-symbols-compilation.md)
