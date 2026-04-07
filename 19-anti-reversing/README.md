🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 19 — Anti-reversing and compiler protections

> 🔒 **Objective**: Understand, identify, and bypass mechanisms that make reverse engineering more difficult — whether intentionally applied by the developer, automatically by the compiler, or added by a third-party tool.

---

## Why this chapter exists

Until now, the binaries we've analyzed were relatively cooperative. Even compiled with high optimizations, they didn't actively try to prevent us from understanding them. In reality, this is rarely the case.

Commercial software developers, malware authors, and CTF challenge designers all employ — for very different reasons — techniques designed to slow down, deceive, or block the analyst. These techniques fall into several categories:

- **Information removal**: stripping symbols, debug information, anything that makes the binary easier to read. This is the first barrier, the simplest and most widespread.  
- **Compression and packing**: transforming the binary into a compressed wrapper that decompresses in memory at runtime. The file on disk no longer looks anything like the actual code.  
- **Control flow obfuscation**: rewriting the program's logical structure so the control graph becomes an incomprehensible maze, without modifying functional behavior.  
- **Compiler and system memory protections**: stack canaries, ASLR, PIE, NX, RELRO — mechanisms that don't directly target the reverse engineer but significantly complicate exploitation and dynamic analysis.  
- **Active analyst detection**: anti-debugger checks, breakpoint detection, integrity controls — the binary defends itself in real time against any observation attempt.

Understanding these protections is a fundamental skill. Not only to bypass them when analysis warrants it (security audit, malware analysis, interoperability), but also to recognize them immediately during triage and adapt your strategy accordingly. An analyst who can't identify a packed binary will waste hours trying to disassemble compressed code. An analyst who doesn't recognize an anti-`ptrace` check will wonder why GDB refuses to attach to the process.

## What you will learn

This chapter covers the protections you'll encounter most frequently on ELF binaries compiled with GCC/G++, in progressive order:

1. **Stripping** — Symbol removal with `strip`, how to detect it, and what you lose (and what you don't).  
2. **Packing with UPX** — The most common packer, how it works, how to detect it, and how to decompress the original binary.  
3. **Control flow obfuscation** — Control Flow Flattening, bogus control flow, and transformations that make the function graph unreadable.  
4. **LLVM-based obfuscation** — Obfuscation passes like Hikari and O-LLVM, operating at the compiler level and producing recognizable patterns.  
5. **Compiler and system protections** — Stack canaries (`-fstack-protector`), ASLR, PIE, NX: their internal workings and concrete impact on analysis.  
6. **RELRO** — The distinction between Partial and Full RELRO, and what it implies for the GOT/PLT table and dynamic patching possibilities.  
7. **Debugger detection** — Classic techniques (`ptrace`, timing checks, reading `/proc/self/status`) and how to neutralize them.  
8. **Breakpoint countermeasures** — Self-modifying code, `int3` instruction scanning, and protections directly targeting dynamic analysis tools.  
9. **Complete audit with `checksec`** — The systematic approach to inventorying all binary protections before starting analysis.

## Prerequisites

This chapter builds on all skills acquired in previous parts. Before starting, you must be comfortable with:

- Disassembly and reading x86-64 assembly code (Part I, Chapter 3)  
- Binary inspection tools: `readelf`, `objdump`, `checksec`, `file`, `strings` (Chapter 5)  
- Static analysis with Ghidra (Chapter 8)  
- Debugging with GDB and its extensions (Chapters 11–12)  
- Dynamic instrumentation with Frida (Chapter 13)  
- ELF binary structure: sections, segments, PLT/GOT (Chapter 2)

## Approach philosophy

Each section follows the same three-part pattern:

1. **Understand** — How the protection works technically, what it modifies in the binary or execution environment.  
2. **Detect** — The signatures, indicators, and tools that quickly identify the protection's presence.  
3. **Bypass** — The techniques and tools to neutralize the protection and continue analysis.

This approach is not an encouragement to piracy. Recall that the legal and ethical framework for reverse engineering was established in Chapter 1 (Section 1.2). The techniques presented here are those used daily by security analysts, vulnerability researchers, and CTF participants.

## Training binaries

The sources and Makefile for this chapter are in `binaries/ch19-anti-reversing/`. The Makefile produces **22 variants** in `binaries/ch19-anti-reversing/build/`, each isolating a specific protection:

- **`anti_reverse.c`** — A crackme protected by multiple anti-debug layers (ptrace, timing, /proc, int3 scan, checksum), individually activatable via compilation macros. The password is stored XOR-encoded.  
- **`vuln_demo.c`** — An intentionally vulnerable program (buffer overflow) compiled with different compiler protection combinations (canary, PIE, NX, RELRO) to observe their concrete effect.

```bash
cd binaries/ch19-anti-reversing/  
make all        # compile all 22 variants  
make list       # display description of each target  
make checksec   # run checksec on all variants  
```

The final checkpoint will ask you to identify all protections of the `anti_reverse_all_checks` binary and bypass them one by one to recover the password.

## Chapter outline

| Section | Topic |  
|---|---|  
| 19.1 | Stripping (`strip`) and detection |  
| 19.2 | Packing with UPX — detecting and decompressing |  
| 19.3 | Control flow obfuscation (Control Flow Flattening, bogus control flow) |  
| 19.4 | LLVM-based obfuscation (Hikari, O-LLVM) — recognizing patterns |  
| 19.5 | Stack canaries (`-fstack-protector`), ASLR, PIE, NX |  
| 19.6 | RELRO: Partial vs Full and impact on GOT/PLT table |  
| 19.7 | Debugger detection techniques (`ptrace`, timing checks, `/proc/self/status`) |  
| 19.8 | Breakpoint countermeasures (self-modifying code, int3 scanning) |  
| 19.9 | Inspecting all protections with `checksec` before any analysis |

---


⏭️ [Stripping (`strip`) and detection](/19-anti-reversing/01-stripping-detection.md)
