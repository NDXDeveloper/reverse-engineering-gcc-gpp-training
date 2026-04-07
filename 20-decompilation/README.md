🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 20 — Decompilation and Source Code Reconstruction

> 📘 **Part IV — Advanced RE Techniques**  
>  
> **Prerequisites**: Chapters 7–9 (disassembly with objdump, Ghidra, IDA/Radare2/Binary Ninja), Chapter 16 (compiler optimizations), Chapter 17 (RE of C++ with GCC).

---

## Why this chapter?

Disassembly produces an instruction-by-instruction representation of machine code. It is faithful, but difficult to reason about: a 30-line C function can generate over 200 lines of assembly, not counting compiler-introduced artifacts — prologues, epilogues, intermediate registers, arithmetic optimizations. Decompilation takes this a step further by attempting to reconstruct high-level pseudo-code from this instruction stream. Instead of reading `mov`, `cmp`, and `jnz`, you see `if` statements, `while` loops, and function calls with named parameters.

This transition from disassembly to decompilation radically changes an analyst's productivity. A binary with thousands of functions becomes navigable. Control structures become readable again. Data types can be guessed, then manually refined. But this readability comes at a cost: the decompiler makes choices, assumptions, and sometimes mistakes. Understanding what it produces — and especially what it *cannot* produce — is a fundamental skill in reverse engineering.

## What this chapter covers

This chapter approaches decompilation from a resolutely practical angle, applied to ELF binaries compiled with GCC/G++.

We start by examining **the intrinsic limits of automatic decompilation**: why the generated pseudo-code is never strictly equivalent to the original source code, what information is irrecoverably lost during compilation, and how the optimization level influences the quality of the result. This awareness is essential to avoid treating a decompiler's output as absolute truth.

We then move to **hands-on practice with Ghidra's decompiler**, the central tool in this training. We analyze the quality of pseudo-code produced at different optimization levels (`-O0` to `-O3`), and learn to guide the decompiler by renaming, retyping, and restructuring data to obtain usable results. We also cover **RetDec**, Avast's open source decompiler, as an offline static alternative.

The second half of the chapter focuses on **concrete reconstruction of usable artifacts** from pseudo-code. We learn to produce a synthetic `.h` file that captures the types, structures, and function signatures discovered in the binary — a tangible deliverable that documents the RE work and can serve as a foundation for writing code that interacts with the analyzed binary. We then cover **identifying embedded third-party libraries** via FLIRT signatures and Ghidra's Function ID, a technique that eliminates hundreds of functions from the analysis at once by recognizing them as belonging to a known library. Finally, we address **exporting and cleaning pseudo-code** to produce recompilable code — a goal rarely achieved at 100%, but whose pursuit structures the analysis.

## Position in the learning path

This chapter closes Part IV on advanced techniques. It builds on everything that came before: disassembly (chapters 7–9), understanding optimizations (chapter 16), reverse engineering C++ constructs (chapter 17), and knowledge of anti-reversing protections (chapter 19). It directly prepares Part V, where we will apply decompilation to complete practical cases — the keygenme (chapter 21), the object-oriented application (chapter 22), the network binary (chapter 23), and the encrypted binary (chapter 24).

## Tools used in this chapter

| Tool | Role in this chapter |  
|---|---|  
| **Ghidra** (Decompiler) | Interactive decompilation, renaming, retyping, pseudo-code export |  
| **RetDec** | Offline static decompilation, comparison with Ghidra |  
| **FLIRT / Function ID** | Identifying embedded third-party libraries (signatures) |  
| **GCC/G++** | Compiling training binaries at different optimization levels |  
| **c++filt** | Demangling C++ symbols in pseudo-code |  
| **diff** | Comparing decompiled pseudo-code with original source |

## Training binaries

The binaries used in this chapter come from the `binaries/` directory and are compiled at multiple optimization levels via the dedicated `Makefile`:

- `ch20-keygenme` — a simple C program, ideal for observing the impact of optimizations on decompilation.  
- `ch20-oop` — a C++ application with classes, vtables, and inheritance, for testing the reconstruction of complex structures.  
- `ch20-network` — a client/server binary, for practicing `.h` file production from decompilation.

Each binary is available in `-O0`, `-O2`, `-O3` variants, with and without symbols (`-g` / `-s`), allowing direct comparison of each configuration's effect on the decompiler output.

## Chapter outline

- **20.1** — Limits of automatic decompilation (why the result is never perfect)  
- **20.2** — Ghidra Decompiler — quality depending on optimization level  
- **20.3** — RetDec (Avast) — offline static decompilation  
- **20.4** — Reconstructing a `.h` file from a binary (types, structs, API)  
- **20.5** — Identifying embedded third-party libraries (FLIRT / Ghidra signatures)  
- **20.6** — Exporting and cleaning pseudo-code to produce recompilable code

> **🎯 Checkpoint**: produce a complete `.h` for the `ch20-network` binary (the stripped network server).

---


⏭️ [Limits of automatic decompilation (why the result is never perfect)](/20-decompilation/01-decompilation-limits.md)
