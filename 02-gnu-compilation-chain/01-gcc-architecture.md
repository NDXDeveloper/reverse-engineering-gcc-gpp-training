🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.1 — GCC/G++ architecture: preprocessor → compiler → assembler → linker

> 🎯 **Goal of this section**: Identify the four main phases of the GNU compilation chain, understand the role of each one, and know at which point information useful to the reverse engineer is produced — or lost.

---

## Compilation is not an atomic operation

When you type `gcc hello.c -o hello`, it looks as though a single command transforms your source code into an executable. In reality, GCC orchestrates **four separate programs**, executed sequentially, each consuming the output of the previous one:

```
                    Source code (.c / .cpp)
                            │
                            ▼
                 ┌──────────────────────┐
                 │   1. PREPROCESSOR    │    cpp / cc1 -E
                 │      (cpp)           │
                 └──────────┬───────────┘
                            │  Preprocessed file (.i / .ii)
                            ▼
                 ┌──────────────────────┐
                 │   2. COMPILER        │    cc1 / cc1plus
                 │      (cc1)           │
                 └──────────┬───────────┘
                            │  Assembly file (.s)
                            ▼
                 ┌──────────────────────┐
                 │   3. ASSEMBLER       │    as
                 │      (as)            │
                 └──────────┬───────────┘
                            │  Object file (.o)
                            ▼
                 ┌──────────────────────┐
                 │  4. LINKER           │    ld / collect2
                 │     (linker)         │
                 └──────────┬───────────┘
                            │
                            ▼
                     Executable (ELF)
```

The `gcc` program (or `g++` for C++) is therefore not the compiler strictly speaking: it is a **driver** — a conductor that invokes the right tools in the right order, with the right flags. Understanding this pipeline architecture is fundamental to RE, because each step transforms information in an irreversible way. The further you advance in the pipeline, the further you move away from the original source code — and this is precisely the path the reverse engineer must walk backwards.

## Phase 1 — The preprocessor (`cpp`)

### What it does

The preprocessor is a **textual transformation** tool that operates before any syntactic analysis of the code. It processes directives starting with `#`:

- **`#include`**: inserts the full content of the designated header file at the location of the directive. A simple `#include <stdio.h>` can inject thousands of lines from system headers.  
- **`#define` / `#undef`**: defines or removes macros. Macros are then substituted everywhere they appear in the code.  
- **`#ifdef` / `#ifndef` / `#if` / `#else` / `#endif`**: conditional compilation — certain portions of code are included or excluded depending on the defined macros.  
- **`#pragma`**: compiler-specific directives (memory alignment, warning suppression, etc.).  
- Removal of **comments** (`//` and `/* */`).  
- Insertion of **line markers** (`# 1 "hello.c"`) that allow the compiler to report errors with the correct line numbers from the original file.

### In practice on our running example

Taking the chapter's `hello.c`:

```c
#include <stdio.h>
#include <string.h>

#define SECRET "RE-101"

int check(const char *input) {
    return strcmp(input, SECRET) == 0;
}
```

Run the preprocessor alone with the `-E` flag:

```bash
gcc -E hello.c -o hello.i
```

The produced `hello.i` file typically has **several hundred lines** — whereas the source had only about twenty. Opening it, you will find that:

- All the content of `stdio.h`, `string.h`, and their transitive dependencies has been injected at the top of the file.  
- The `SECRET` macro has disappeared: every occurrence has been textually replaced with `"RE-101"`.  
- Comments have been removed.  
- Markers such as `# 1 "hello.c"` and `# 1 "/usr/include/stdio.h"` are scattered throughout the file.

The line of the `check()` function in the `.i` now looks like:

```c
int check(const char *input) {
    return strcmp(input, "RE-101") == 0;
}
```

### Relevance for RE

The preprocessor has two direct consequences for the reverse engineer:

1. **Macro names disappear.** In the final binary, you will never see `SECRET` — only the literal string `"RE-101"` in the `.rodata` section. That is why the `strings` tool (Chapter 5) is so valuable: it makes it possible to recover these substituted values.

2. **Headers are absorbed.** There is no longer a trace of which headers were included. In the binary, you will not be able to distinguish what comes from the author's code and what comes from the standard library — except by recognizing libc functions from their known signatures (FLIRT, Ghidra signatures — Chapter 20).

> 💡 **RE tip**: When you find an interesting string with `strings` in a binary, consider that it may come from a `#define` in the original source. The value is there, but the macro's *name* has been erased by the preprocessor.

## Phase 2 — The compiler itself (`cc1` / `cc1plus`)

### What it does

This is the heart of the process. The compiler takes the preprocessed file (`.i` or `.ii`) and transforms it into **assembly code** (`.s`). This phase is itself broken down into several internal steps:

1. **Lexical analysis (lexing)**: source code is split into *tokens* — keywords, identifiers, operators, literals.  
2. **Syntactic analysis (parsing)**: tokens are organized into an *abstract syntax tree* (AST) according to the grammar of the language.  
3. **Semantic analysis**: type checking, name resolution, detection of semantic errors.  
4. **Generation of the intermediate representation**: GCC uses several levels of internal representation (GENERIC → GIMPLE → RTL). It is on these representations that the optimization passes operate.  
5. **Optimization**: depending on the requested level (`-O0` through `-O3`), dozens of passes transform the code — dead code elimination, constant propagation, function inlining, loop unrolling, vectorization… We will dig deeper into this in section 2.5 and in Chapter 16.  
6. **Assembly code generation**: the optimized internal representation is translated into assembly instructions for the target architecture (x86-64 in our case).

### In practice

To stop compilation just after this phase and obtain the assembly file:

```bash
gcc -S hello.c -o hello.s
```

The `hello.s` file contains readable assembly code (AT&T syntax by default under GCC). For our `check()` function compiled without optimization (`-O0`), you will get something like:

```asm
check:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $16, %rsp
        movq    %rdi, -8(%rbp)
        movq    -8(%rbp), %rax
        leaq    .LC0(%rip), %rdx
        movq    %rdx, %rsi
        movq    %rax, %rdi
        call    strcmp@PLT
        testl   %eax, %eax
        sete    %al
        movzbl  %al, %eax
        leave
        ret
```

With `-O2`, the same code could be considerably transformed, or even inlined directly into `main()`.

### Relevance for RE

This phase is **the most information-destroying** from the reverse engineer's point of view:

- **Local variable names disappear** (unless `-g` is used to generate DWARF information — section 2.6).  
- **Types are reduced to sizes and alignments.** An `int` simply becomes "4 bytes in a 32-bit register"; a `struct` becomes a block of memory at a certain offset.  
- **Control structures are flattened** into sequences of instructions and jumps. An `if/else` becomes a `cmp` followed by a `jz` or `jnz`. A `for` loop becomes a label, a body, an increment, and a conditional `jmp`.  
- **Optimizations reorder, merge, and remove code.** A function can be inlined (integrated into its caller), a variable can be kept solely in a register without ever touching memory, an `else` branch can be removed if the compiler proves it is unreachable.

For all these reasons, analyzing a binary compiled with `-O0` (without optimization) is dramatically simpler than analyzing the same program compiled with `-O2` or `-O3`. At `-O0`, the correspondence between source code and assembly is nearly direct. At `-O2`, the compiler has sometimes rewritten the logic beyond recognition.

> 💡 **RE tip**: When you have access to the source code or suspect the use of an open source library, recompile that library yourself at different optimization levels and compare the result with the target binary. This allows you to calibrate the optimization level used and to recognize the compiler's patterns.

## Phase 3 — The assembler (`as`)

### What it does

The assembler (GNU `as`, also called GAS — GNU Assembler) translates the textual assembly file (`.s`) into an **object file** (`.o`). This object file is already in ELF binary format, but it is **incomplete**:

- It contains the machine code corresponding to the assembly instructions.  
- It contains the data defined in the source (literal strings, initialized global variables…).  
- It contains a **symbol table** that lists the functions and variables defined or referenced.  
- It contains **relocation entries**: places in the machine code where an address must be filled in later by the linker because it is not yet known (for example the address of `strcmp`).

On the other hand, final addresses are not fixed. The `.o` file is a fragment — it cannot be executed on its own.

### In practice

To produce only the object file without invoking the linker:

```bash
gcc -c hello.c -o hello.o
```

You can inspect this object file with `readelf` and `objdump` (tools we will cover in detail in Chapter 5):

```bash
# See the sections of the object file
readelf -S hello.o

# See the symbol table
readelf -s hello.o

# See the relocation entries
readelf -r hello.o

# Disassemble the .text section
objdump -d hello.o
```

In the symbol table, you will see `check` and `main` marked as defined (`DEF`), whereas `strcmp`, `printf`, and `puts` will appear as undefined (`UND`). In the relocations, each `call strcmp@PLT` generates an entry saying: "at this offset in the code, the address of `strcmp` must be inserted once it is known."

### Relevance for RE

From the reverse engineer's point of view, the transformation performed by the assembler is essentially **an encoding** — moving from a textual representation to a binary representation of the same instructions. Unlike phase 2, this step loses almost no structural information. That is also why **disassembly** (the inverse operation) works so well: it is about decoding binary opcodes to recover the assembly mnemonics.

The `.o` file is interesting for RE for another reason: it contains the **local symbols** and the **relocation information** that are sometimes removed or resolved in the final executable. If you have access to a project's `.o` files (before linking), you have richer information than in the final binary.

## Phase 4 — The linker (`ld` / `collect2`)

### What it does

The linker is the final phase. It takes one or more object files (`.o`) as well as libraries (`.a` for static libraries, `.so` for dynamic libraries) and assembles them into a **single executable file** or into a shared library. Its responsibilities are:

**Symbol resolution.** Every symbol marked as undefined in an `.o` must be found in another `.o` or in a library. If `hello.o` references `strcmp` without defining it, the linker must find that definition — here in the libc (`libc.so`). If a symbol remains unresolved, the linker produces an `undefined reference` error.

**Relocation resolution.** Once the address of each symbol is known (or at least its dynamic resolution mechanism via PLT/GOT), the linker fills in the places left empty by the assembler. This is the final "wiring up".

**Section merging.** Each `.o` file has its own `.text`, `.data`, `.rodata` sections, etc. The linker merges all the `.text` sections into a single one, all the `.data` sections into a single one, and so on. It organizes these sections into **segments** that will be loaded into memory by the loader (section 2.7).

**Adding bootstrap code (CRT — C Runtime).** The linker automatically adds the startup code (`crt0.o`, `crti.o`, `crtn.o`, `crtbegin.o`, `crtend.o`) provided by the toolchain. This code is responsible for initializing the C runtime environment: setting up the stack, calling global constructors (C++), passing `argc` and `argv` to `main()`, and handling the return value of `main()` to call `exit()`. Concretely, the actual entry point of an ELF binary is not `main()` but `_start`, which calls `__libc_start_main`, which eventually calls your `main()`.

**Creating the PLT/GOT structures.** For dynamic libraries, the linker generates the `.plt` (Procedure Linkage Table) and `.got` (Global Offset Table) sections that will allow symbol resolution at execution time. We will detail this mechanism in section 2.9.

### In practice

When you run `gcc hello.c -o hello`, GCC invokes the linker transparently. To observe what happens, add the `-v` (verbose) flag:

```bash
gcc -v hello.c -o hello
```

The output reveals the call to `collect2` (GCC's wrapper around `ld`) with a long list of arguments: the CRT files, libc, library paths, relocation options, etc.

You can also invoke the linker manually, but the list of required files and options is long — this is one of the reasons `gcc` exists as a driver.

To examine the result:

```bash
# Entry point and type of the executable
readelf -h hello

# Segments (loader's view)
readelf -l hello

# Full sections
readelf -S hello

# Dynamic symbols (those linked to .so files)
readelf --dyn-syms hello

# Check the required dynamic libraries
ldd hello
```

### Static vs dynamic linking

The linker can operate in two modes, and this distinction has a major impact on RE:

**Dynamic linking** (the default under Linux): libc functions and those of other shared libraries are **not** copied into the executable. The binary contains only references (via PLT/GOT) that will be resolved at load time by the `ld.so` loader. The executable is compact, but depends on the `.so` files present on the system.

```bash
gcc hello.c -o hello          # Dynamic linking (default)  
ldd hello                     # Displays the required .so files  
```

**Static linking**: all the code from the required libraries is **copied** directly into the executable. The binary is self-contained but much larger.

```bash
gcc -static hello.c -o hello_static  
ldd hello_static              # "not a dynamic executable"  
```

For the reverse engineer, a statically linked binary is paradoxically harder to analyze: libc code is mixed with the application code, and without signatures (like FLIRT for IDA or Ghidra signatures — Chapter 20), it is difficult to distinguish the standard functions from the author's functions. Conversely, a dynamically linked binary offers a valuable landmark: every call through the PLT is a call to a library function identifiable by its name.

### Relevance for RE

Linking is the last moment when you can lose information:

- **Stripping** (`gcc -s` or `strip` after compilation) removes the non-dynamic symbol table. The names of your internal functions (`check`, `validate_input`, etc.) disappear from the binary. Only dynamic symbols (those of the `.so` files) are preserved because they are required at runtime.  
- **Intermediate object files are merged.** You can no longer distinguish what comes from which `.o` — everything is fused into the sections of the final binary.  
- **CRT code adds complexity.** When you open a binary in Ghidra or IDA, the `_start` entry point and the libc initialization code can be confusing. Knowing that `main()` is called *from* `__libc_start_main` lets you quickly locate the application logic.

## Overview: what is preserved, what is lost

The table below summarizes, for each phase, the information that survives and what is irretrievably lost (under standard compilation without `-g`):

| Information | After CPP | After CC1 | After AS | After LD |  
|---|---|---|---|---|  
| Macro names (`#define`) | ❌ Lost | — | — | — |  
| Comments | ❌ Lost | — | — | — |  
| Local variable names | ✅ | ❌ Lost | — | — |  
| Precise types (struct, enum…) | ✅ | ❌ Reduced to sizes | — | — |  
| Control structures (if, for…) | ✅ | ❌ Flattened into jumps | — | — |  
| Internal function names | ✅ | ✅ | ✅ Labels | ⚠️ Lost if stripped |  
| Machine code | — | — | ✅ | ✅ |  
| Unresolved relocations | — | — | ✅ | ❌ Resolved |  
| Dynamic function names | — | — | — | ✅ Always present |

> 💡 **Key point**: Most of what the reverse engineer must reconstruct — names, types, control structures — is lost in phase 2 (compilation). That is why the decompiler (Ghidra, IDA, RetDec — Chapter 20) works so hard: it tries to **reinvent** what the compiler destroyed.

## How GCC orchestrates everything

To fix ideas, here are the internal commands GCC runs when you type `gcc hello.c -o hello` (simplified):

```bash
# Phase 1 — Preprocessor
cc1 -E hello.c -o /tmp/hello.i

# Phase 2 — Compilation (implicitly includes the preprocessor)
cc1 /tmp/hello.i -o /tmp/hello.s

# Phase 3 — Assembly
as /tmp/hello.s -o /tmp/hello.o

# Phase 4 — Linking
collect2 (ld) /usr/lib/crt1.o /usr/lib/crti.o /tmp/hello.o \
    -lc /usr/lib/crtn.o -o hello
```

In practice, GCC often combines phases 1 and 2 in a single call to `cc1`, and goes directly from source to `.s` or `.o`. But the four-step conceptual model remains the right mental picture.

You can observe all the commands executed with:

```bash
gcc -v hello.c -o hello        # Verbose: displays each command  
gcc -### hello.c -o hello      # Displays commands without running them  
```

The `-save-temps` flag is particularly useful for learning: it keeps all intermediate files in the current directory.

```bash
gcc -save-temps hello.c -o hello  
ls hello.*  
# hello.c  hello.i  hello.s  hello.o  hello
```

You thus obtain the `.i`, `.s`, and `.o` files in addition to the final executable — a snapshot of each stage of the pipeline. We will exploit this in section 2.2.

## The C++ case (`g++`)

When you compile C++ with `g++`, the pipeline is identical but a few points differ:

- The preprocessor recognizes C++ directives and the preprocessed file has the `.ii` extension.  
- The compiler is `cc1plus` instead of `cc1`. It handles C++ syntax: classes, templates, exceptions, operator overloading, etc.  
- **Name mangling** comes into play: C++ function names are encoded to include their parameter types (for overloading), the namespace, and the class they belong to. For example, a method `MyClass::check(std::string)` will be encoded into a symbol like `_ZN7MyClass5checkENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE`. Demangling is covered in detail in Chapter 7 (section 7.6, `c++filt`) and in Chapter 17 (section 17.1, Itanium ABI rules).  
- The linker must resolve additional symbols related to the C++ runtime: `libstdc++.so`, the exception-handling functions (`__cxa_throw`, `__cxa_begin_catch`…), RTTI support, etc.

---

> 📖 **In the next section**, we are going to get our hands dirty: using `-save-temps`, we will produce and inspect each intermediate file to concretely observe the transformations described here.  
>  
> → 2.2 — Compilation phases and intermediate files (`.i`, `.s`, `.o`)

⏭️ [Compilation phases and intermediate files (`.i`, `.s`, `.o`)](/02-gnu-compilation-chain/02-compilation-phases.md)
