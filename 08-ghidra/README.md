🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 8 — Advanced disassembly with Ghidra

> **Part II — Static Analysis**

---

## Why this chapter?

The previous chapters allowed you to have a first contact with disassembly using `objdump` and the Binutils tools. You learned how to read an assembly listing, distinguish AT&T from Intel syntax, and spot basic structures like function prologues or C++ name mangling. But you also noted the limits of these command-line tools: no interactive navigation, no decompilation, no automatic typing, no control-flow graphs. To go further in static analysis, you need a real reverse-engineering environment.

That is exactly what **Ghidra** offers.

## Ghidra in a few words

Ghidra is a binary analysis framework developed by the NSA (National Security Agency), made public and open source in 2019 under the Apache 2.0 license. Its release profoundly transformed the reverse-engineering landscape by offering for free a set of features that were previously reserved for expensive commercial tools like IDA Pro.

Ghidra is not a simple disassembler. It's a complete suite that integrates:

- a multi-architecture **disassembler** (x86, x86-64, ARM, MIPS, PowerPC, and many more);  
- a **decompiler** capable of producing C pseudo-code from machine code, without needing an additional plugin;  
- a **typing system** that lets you define and apply structures, enumerations, and custom types;  
- a **cross-references** engine (XREF) to track the use of each function, variable, or constant across the binary;  
- a **graph editor** that visualizes a function's control flow as basic blocks connected by edges;  
- a **scripting system** in Java and Python (via Jython) to automate repetitive tasks;  
- a **headless mode** to run batch analyses on many binaries without a graphical interface.

## What you will learn

This chapter guides you step by step in mastering Ghidra applied to ELF binaries produced by GCC/G++. You will learn to:

1. **Install Ghidra** and configure your working environment, including managing Java versions and the structure of Ghidra projects.  
2. **Import and analyze an ELF binary**, understanding the automatic analysis options offered by Ghidra and their impact on results.  
3. **Navigate efficiently in the CodeBrowser**, Ghidra's central interface, exploiting its different views: assembly listing, decompiler, symbol tree, and function graph.  
4. **Annotate a binary** by renaming functions and variables, adding comments, and creating custom types to make the disassembly readable and maintainable.  
5. **Recognize GCC-specific structures** in a C++ binary: vtables, RTTI (Run-Time Type Information), and exception tables.  
6. **Reconstruct data structures** (`struct`, `class`, `enum`) from disassembled code, using Ghidra's Data Type Manager.  
7. **Exploit cross-references** (XREF) to trace call chains and understand how a piece of data or a function is used throughout the program.  
8. **Write Ghidra scripts** in Java or Python to automate common analysis tasks: bulk-rename functions, extract strings, apply signatures.  
9. **Use headless mode** to integrate Ghidra into an automated analysis workflow or to process a batch of binaries without manual interaction.

## Positioning in the learning path

This chapter assumes you master the notions covered in the preceding chapters:

- **Chapter 2** — The GNU compilation chain: you must understand how a source file becomes an ELF binary, what sections (`.text`, `.data`, `.rodata`, `.plt`, `.got`) are, and what a binary compiled with or without symbols means.  
- **Chapter 3** — x86-64 assembly: you must know how to read basic instructions, understand registers, System V AMD64 calling conventions, and interpret function prologues/epilogues.  
- **Chapter 5** — Basic inspection tools: the triage tools (`file`, `strings`, `readelf`, `nm`, `checksec`) must be part of your routine.  
- **Chapter 7** — Disassembly with `objdump`: you must have practiced command-line disassembly and felt the limitations that motivate moving to a graphical tool.

The skills acquired here will be directly reused in:

- **Chapter 9** — where you will compare Ghidra with IDA Free, Radare2, and Binary Ninja;  
- **Chapter 10** — for binary diffing with BinDiff and Diaphora, which integrate with Ghidra;  
- **Chapter 17** — for deep reverse engineering of C++ compiled with GCC;  
- **Chapter 20** — for decompilation and source-code reconstruction;  
- **Part V** (Chapters 21 to 25) — where Ghidra will be your main static-analysis tool for each practical case.

## Training binaries

The binaries used in this chapter are found in the `binaries/` directory of the repository. This chapter relies mainly on the `ch08-oop` binary (object-oriented C++ application), provided in several variants:

| Variant | Optimization | Symbols | Use in this chapter |  
|---|---|---|---|  
| `ch08-oop_O0` | `-O0` | Yes | Interface discovery, first analysis |  
| `ch08-oop_O0_strip` | `-O0` | No (`-s`) | Working without symbols |  
| `ch08-oop_O2` | `-O2` | Yes | Observing optimization impact on the decompiler |  
| `ch08-oop_O2_strip` | `-O2` | No (`-s`) | Realistic analysis conditions |

To compile these binaries:

```bash
cd binaries/ch08-oop/  
make all  
```

You will also use the `ch21-keygenme` binary for some simpler examples in pure C, as well as the `mystery_bin` binary from Chapter 5 if you wish to resume your initial triage in Ghidra.

## Chapter organization

| Section | Title | Goal |  
|---|---|---|  
| 8.1 | Installation and getting started with Ghidra | Install, configure, create a first project |  
| 8.2 | Importing an ELF binary — automatic analysis and options | Understand what auto-analysis does |  
| 8.3 | Navigation in the CodeBrowser | Master the Listing, Decompiler, Symbol Tree, Function Graph views |  
| 8.4 | Renaming, comments, and types | Annotate a binary to make it readable |  
| 8.5 | GCC structures: vtables, RTTI, exceptions | Recognize GCC's C++ artifacts |  
| 8.6 | Reconstructing data structures | Create `struct`, `class`, `enum` in Ghidra |  
| 8.7 | Cross-references (XREF) | Trace the use of functions and data |  
| 8.8 | Ghidra scripts (Java/Python) | Automate analysis |  
| 8.9 | Headless mode and batch processing | Ghidra without the graphical interface |  
| 🎯 Checkpoint | Import `ch20-oop`, reconstruct the class hierarchy | Validate the chapter's learning |

---

> **💡 Tip** — Ghidra is a rich tool whose interface may seem intimidating at first. Don't try to master everything at once. This chapter is designed for incremental progression: each section builds on the previous one. Take the time to handle the tool alongside your reading. Reverse engineering is above all a practical discipline.

---


⏭️ [Installation and getting started with Ghidra (NSA)](/08-ghidra/01-installation-getting-started.md)
