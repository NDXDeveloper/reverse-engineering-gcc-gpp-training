🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 2 — The GNU Compilation Chain

> 🎯 **Chapter goal**: Understand the complete journey of a C/C++ source file from source to the ELF executable binary loaded in memory, and master the impact of each step on what you will observe in reverse engineering.

---

## Why this chapter is essential

Reverse engineering a binary compiled with GCC or G++ means swimming upstream. The compiler has transformed your readable source code into a sequence of bytes optimized for the machine — not for the human. Understanding *how* this transformation takes place, step by step, gives you a decisive advantage: you will know **what the compiler did and why**, instead of being blindsided by an opaque disassembly.

This chapter lays the foundations on which all the following parts of this training rest. When you look for a function in Ghidra, set a breakpoint in GDB on a call to `printf`, or try to understand why a loop has disappeared from the `-O2` binary, you will mentally come back here.

Concretely, by the end of this chapter you will be able to:

- Describe the four main compilation phases (preprocessor, compilation, assembly, linking) and identify the intermediate files produced at each step.  
- Distinguish the main binary formats (ELF, PE, Mach-O) and explain why this training focuses on ELF.  
- Name the key sections of an ELF binary (`.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`…) and know what kind of information each one contains.  
- Predict the effect of common compilation flags (`-O0` through `-O3`, `-g`, `-s`, `-fPIC`, `-pie`) on the ease or difficulty of an RE analysis.  
- Explain the role of DWARF debug information and know how to exploit it when present.  
- Describe how an ELF is loaded into memory by the Linux loader (`ld.so`), segment mapping, and the ASLR mechanism.  
- Understand dynamic symbol resolution via PLT/GOT and the principle of lazy binding.

## Prerequisites

Before tackling this chapter, make sure you are comfortable with:

- The concepts seen in **Chapter 1** (static/dynamic analysis distinction, basic RE vocabulary).  
- The **basics of the C language**: compiling a simple program with `gcc`, concept of source file, object file, and executable.  
- Elementary use of a **Linux terminal**: navigating the directory tree, running commands, reading text output.

No prior knowledge of assembly is required — that is the subject of Chapter 3.

## Chapter outline

| Section | Title | Central theme |  
|---------|-------|---------------|  
| 2.1 | GCC/G++ architecture | The 4 phases: preprocessor → compiler → assembler → linker |  
| 2.2 | Compilation phases and intermediate files | `.i`, `.s`, `.o` files — observing each step |  
| 2.3 | Binary formats | ELF (Linux), PE (Windows), Mach-O (macOS) |  
| 2.4 | Key ELF sections | `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.init`, `.fini` |  
| 2.5 | Compilation flags and impact on RE | `-O0` through `-O3`, `-g`, `-s`, `-fPIC`, `-pie` |  
| 2.6 | DWARF symbol files | Debug information and its exploitation |  
| 2.7 | The Linux Loader (`ld.so`) | From ELF file to process in memory |  
| 2.8 | Segments, ASLR, and virtual addresses | Why addresses move from one execution to the next |  
| 2.9 | Dynamic resolution: PLT/GOT | Lazy binding and calls to shared libraries |

## Running thread

Throughout this chapter, we will use the same minimalist `hello.c` program as a running example. By compiling it in different ways and observing the result at each step, you will see the theory take concrete shape. This file is located in the repository at `binaries/ch02-hello/`.

```c
/* hello.c — running example of Chapter 2 */
#include <stdio.h>
#include <string.h>

#define SECRET "RE-101"

int check(const char *input) {
    return strcmp(input, SECRET) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    if (check(argv[1])) {
        printf("Access granted.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
```

This program is deliberately simple, but rich enough to illustrate every concept: the preprocessor will substitute the `SECRET` macro, the compiler will transform `check()` into machine instructions, the linker will resolve `strcmp` and `printf` from libc, and the loader will place everything into memory at execution time. In section 2.5, we will compile it with different flags to directly observe their impact.

## Position in the training

```
Chapter 1 (Introduction to RE)
        │
        ▼
  ┌─────────────┐
  │  CHAPTER 2  │ ◄── You are here
  │  The GNU    │
  │ compilation │
  │    chain    │
  └─────┬───────┘
        │
        ▼
Chapter 3 (x86-64 Assembly)
        │
        ▼
Chapter 4 (Work environment)
        │
        ▼
Part II — Static Analysis
```

The concepts seen here will be used constantly in what follows:

- **Chapter 3** will rely on your understanding of `.s` files and calling conventions to approach x86-64 assembly.  
- **Chapter 5** will use `readelf` and `objdump` to inspect the ELF sections and headers you will have learned to identify here.  
- **Chapter 7** will compare disassembly at different optimization levels — you will already know what `-O0` and `-O2` change under the hood.  
- **Chapter 8** (Ghidra) and **Chapter 11** (GDB) will assume you understand the PLT/GOT mechanism and the role of the loader.  
- **Chapter 19** (anti-reversing) will dig deeper into the protections (PIE, ASLR, RELRO) whose basics are laid down here.

---

> 📖 **Ready?** Let's start by opening GCC's hood and observing the four main phases that transform C code into an executable.  
>  
> → 2.1 — GCC/G++ architecture: preprocessor → compiler → assembler → linker

⏭️ [GCC/G++ architecture: preprocessor → compiler → assembler → linker](/02-gnu-compilation-chain/01-gcc-architecture.md)
