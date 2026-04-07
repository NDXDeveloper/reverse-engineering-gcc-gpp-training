🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg

> **Part III — Dynamic Analysis**

---

## Why enhance GDB?

The previous chapter laid the foundations of debugging with GDB: setting breakpoints, inspecting memory, stepping through code. These fundamentals are indispensable, but anyone who has spent more than ten minutes in vanilla GDB knows it: the default interface is spartan. After a `stepi`, the debugger returns to the prompt without showing register state, stack contents, or surrounding disassembly. You must manually chain `info registers`, `x/20i $rip`, `x/32gx $rsp` at every instruction — a slow, repetitive workflow prone to oversight.

This observation gave rise to three major extensions, all written in Python via the GDB API we covered in section 11.8. They share a common goal — making debugging interactive, visual, and productive — but differ in their philosophy, functional scope, and community.

## The three extensions at a glance

**PEDA** (*Python Exploit Development Assistance for GDB*) is the pioneer. Created by Long Le Dinh in 2012, it was the first to automatically display registers, stack, and disassembled code after each instruction. PEDA established the visual conventions that the other two adopted and extended. It remains functional today, but its development has considerably slowed, and it doesn't support some modern features like advanced glibc heap analysis.

**GEF** (*GDB Enhanced Features*, pronounced "jeff") was designed by Hugsy as an alternative with no external dependencies. Where PEDA and pwndbg sometimes require third-party Python libraries, GEF fits in a single Python file. This portability makes it an excellent choice for constrained environments: remote servers, Docker containers, CTF machines where you can't install much. GEF offers a good balance between feature richness and lightness, with particularly polished multi-architecture support (ARM, MIPS, RISC-V…).

**pwndbg** (pronounced "pone-dee-bug") is the richest of the three in terms of features. Actively maintained by a large community, it offers specialized commands for heap analysis (`vis_heap_chunks`, `bins`, `tcachebins`), ROP gadget searching, memory allocation tracking, and much more. It's the extension of choice for vulnerability exploitation and complex binary analysis. The trade-off is a somewhat heavier installation, with several Python dependencies.

## What these extensions concretely change

The most immediate change is the **automatic context**. At each program stop — breakpoint, `stepi`, `nexti`, watchpoint — the extension displays a complete dashboard: register state with coloring of modified values, stack portion with intelligent pointer dereferencing, disassembly around the current instruction, and often source code if debug symbols are present. This context eliminates the need to manually type inspection commands after each step.

Beyond the display, the three extensions add dozens of commands absent from vanilla GDB. Cyclic pattern searching to compute buffer-overflow offsets, De Bruijn pattern generation and identification, recursive pointer dereferencing ("telescope"), automatic detection of the debugged binary's protections, or extracting the GOT table and PLT entries in a single command are all tasks that would take several chained commands in bare GDB.

## Positioning in the training

This chapter is deliberately placed after mastering vanilla GDB (Chapter 11). Understanding what the extensions do "under the hood" — that is, calls to GDB's Python API, formatted memory reads, heuristics on glibc structures — is essential not to become dependent on a tool without understanding its limits. Extensions are accelerators, not substitutes for understanding.

In the rest of the training, we'll mainly use **GEF** and **pwndbg** for the practical cases of Parts V and VI. GEF will be preferred for its portability during remote debugging (Chapter 11, `gdbserver` section), while pwndbg will be our tool of choice for heap analysis and exploitation scenarios in Chapters 27 to 29.

## Chapter outline

- **12.1** — Installation and comparison of the three extensions  
- **12.2** — Real-time stack and register visualization  
- **12.3** — ROP gadget searching from GDB  
- **12.4** — Heap analysis with pwndbg (`vis_heap_chunks`, `bins`)  
- **12.5** — Useful commands specific to each extension  
- **🎯 Checkpoint** — Trace the complete execution of `keygenme_O0` with GEF, capture the comparison moment

## Prerequisites for this chapter

This chapter assumes all of Chapter 11 on GDB is mastered, in particular:

- Setting breakpoints and stepping (`stepi`, `nexti`, `finish`)  
- Inspecting registers (`info registers`) and memory (`x/`)  
- Conditional breakpoints and watchpoints (section 11.5)  
- Basics of Python scripting for GDB (section 11.8)

Familiarity with System V AMD64 calling conventions (Chapter 3, sections 3.5 and 3.6) is also necessary to fully benefit from the stack and register displays offered by these extensions.

## Binaries used

This chapter's training binaries are in the `binaries/ch12-keygenme/` directory. The checkpoint uses `keygenme_O0` (compiled without optimization, with symbols), which allows focusing on getting started with the extensions without being hindered by compiler transformations. Optimized and stripped variants will be exploited in later chapters once the extensions are mastered.

To recompile the binaries if needed:

```bash
cd binaries/ch12-keygenme/  
make clean && make all  
```

---


⏭️ [Installation and comparison of the three extensions](/12-gdb-extensions/01-installation-comparison.md)
