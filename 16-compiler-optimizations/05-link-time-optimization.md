🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 16.5 — Link-Time Optimizations (`-flto`) and their effects on the call graph

> **Associated source files**: `binaries/ch16-optimisations/lto_main.c`, `lto_math.c`, `lto_utils.c` (+ headers)  
> **Compilation**: `make s16_5` (produces 12 variants: 6 without LTO, 6 with `-flto`)  
> **Quick comparison**: `make lto_compare`

---

## Introduction

Until now, all the optimizations we've studied operated within a single **compilation unit** — a `.c` file compiled into a `.o` file. When GCC compiles `lto_main.c`, it doesn't see the code of `lto_math.c`. It knows that `math_square()` exists (thanks to the declaration in the header), but it doesn't know its body. It therefore can't inline it, propagate its constants, or eliminate its dead branches.

This is a fundamental limitation of the separate compilation model inherited from 1970s C: each `.c` file is compiled independently, then the linker assembles the `.o` files into a final executable. The classic linker (`ld`) only resolves symbol addresses — it doesn't touch the machine code itself.

**Link-Time Optimization** (`-flto`) radically changes this model. With `-flto`, GCC doesn't produce machine code in `.o` files: it stores an intermediate representation (GIMPLE) of the program. At link time, all GIMPLE files are merged and GCC applies its optimization passes on the **entire program**, as if all `.c` files had been concatenated into one.

The consequences for the reverse engineer are considerable:

- Functions defined in separate files can be **inlined cross-module** — they disappear from the binary whereas they would have survived without LTO.  
- **Constants propagate** across file boundaries: a value passed as a parameter in `main.c` can be substituted directly into the body of a function defined in `math.c`.  
- **Inter-module dead code** is eliminated: if a function exported in `utils.c` is never called by any other file, it's removed.  
- The binary's **call graph** is radically simplified — or rather flattened, as entire levels of indirection disappear.

This section explores these transformations with side-by-side comparisons of binaries compiled with and without `-flto`.

---

## How LTO works internally

To understand LTO's effects on the final binary, it's helpful to know what happens in the compilation chain.

### Classic compilation (without LTO)

```
lto_main.c  ──→  gcc -O2 -c  ──→  lto_main.o   (x86-64 machine code)  
lto_math.c  ──→  gcc -O2 -c  ──→  lto_math.o   (x86-64 machine code)  
lto_utils.c ──→  gcc -O2 -c  ──→  lto_utils.o  (x86-64 machine code)  

lto_main.o + lto_math.o + lto_utils.o  ──→  ld  ──→  lto_demo_O2
                                              ↑
                                         Symbol resolution only.
                                         Machine code is not modified.
```

Each `.o` contains final machine code. The linker glues the `.text` sections together and resolves symbol addresses (`math_square`, `utils_clamp`, etc.) but doesn't modify instructions.

### Compilation with LTO (`-flto`)

```
lto_main.c  ──→  gcc -O2 -flto -c  ──→  lto_main.o   (GIMPLE IR + bytecode)  
lto_math.c  ──→  gcc -O2 -flto -c  ──→  lto_math.o   (GIMPLE IR + bytecode)  
lto_utils.c ──→  gcc -O2 -flto -c  ──→  lto_utils.o  (GIMPLE IR + bytecode)  

lto_main.o + lto_math.o + lto_utils.o  ──→  gcc -flto (lto1 + ld)  ──→  lto_demo_O2_flto
                                              ↑
                                         1. Merge GIMPLE from all .o files
                                         2. Global optimization (inlining,
                                            propagation, DCE, devirtualization)
                                         3. Final machine code generation
                                         4. Classic linkage
```

The `.o` files produced with `-flto` contain the GIMPLE representation — GCC's IR (Intermediate Representation), a simplified syntax tree that preserves all program semantics. At link time, the compiler (`lto1`) merges the IR from all files, applies optimization passes on the whole, then generates the final machine code.

The result is a binary that was optimized as if all code had been written in a single file — but with the modularity of separate compilation on the development side.

### Checking for LTO in a `.o` file

A `.o` file compiled with `-flto` contains special sections:

```bash
$ readelf -S lto_math.o | grep lto
  [3] .gnu.lto_.decls   PROGBITS  ...
  [4] .gnu.lto_.symtab  PROGBITS  ...
  [5] .gnu.lto_main.0   PROGBITS  ...
```

The `.gnu.lto_*` sections contain the serialized GIMPLE IR. This is a clue for RE: if you find these sections in a provided `.o` (for example in an SDK), the developer uses LTO.

---

## Effect 1 — Cross-module inlining

This is LTO's most spectacular effect: functions defined in a separate file can be inlined in the caller, exactly like `static` functions in the same file.

### Trivial functions disappear

In `lto_math.c`:

```c
int math_square(int x)
{
    return x * x;
}

int math_cube(int x)
{
    return x * x * x;
}
```

In `lto_main.c`:

```c
int sq = math_square(input);  
int cb = math_cube(input);  
```

#### Without LTO (`-O2`)

`math_square` and `math_cube` are in a separate `.o` file. GCC doesn't see their bodies when compiling `lto_main.c`. The calls generate explicit `call`s:

```asm
    ; in main()
    mov    edi, ebx                     ; input
    call   math_square                  ; call via PLT or direct
    mov    r12d, eax                    ; sq = result

    mov    edi, ebx
    call   math_cube
    mov    r13d, eax                    ; cb = result
```

Both functions exist as symbols in the binary:

```bash
$ nm build/lto_demo_O2 | grep ' T '
0000000000401190 T main
0000000000401350 T math_cube
0000000000401340 T math_square
0000000000401380 T math_complex_transform
...
```

#### With LTO (`-O2 -flto`)

GCC merges the IR from all three files and inlines `math_square` and `math_cube` into `main()`:

```asm
    ; in main() — math_square inlined
    imul   r12d, ebx, ebx              ; sq = input * input

    ; math_cube inlined
    mov    eax, ebx
    imul   eax, ebx
    imul   r13d, eax, ebx              ; cb = input * input * input
    ; (or a lea/imul combination depending on GCC version)
```

The symbols `math_square` and `math_cube` have disappeared:

```bash
$ nm build/lto_demo_O2_flto | grep -E 'math_square|math_cube'
# (nothing)
```

### Call graph comparison in Ghidra

This is a crucial point for RE. If you open both binaries in Ghidra:

**Without LTO** — the call graph of `main()` shows XREFs to `math_square`, `math_cube`, `math_sum_of_powers`, `math_hash`, `math_divide_sum`, `math_complex_transform`, `utils_fill_sequence`, `utils_array_max`, `utils_clamp`, `utils_int_to_hex`, `utils_print_array`. The graph is complete and reflects the modular architecture of the source.

**With LTO** — the graph of `main()` shows only the functions that weren't inlined (those that were too large: `math_complex_transform`, `utils_print_array`) plus libc calls (`printf`, `sqrt`). Trivial and medium-sized functions were absorbed. The graph is flattened.

Verify for yourself with the Makefile's `lto_compare` target:

```bash
$ make lto_compare
```

---

## Effect 2 — Cross-module constant propagation

Without LTO, when `main()` calls `math_divide_sum(data, 32, 7)`, the compiler of `lto_math.c` doesn't know that `divisor` equals `7` — it's an arbitrary parameter. It can't apply the magic number optimization (cf. Section 16.6) when compiling `lto_math.c` because the divisor is a variable.

In practice, the compiler can still optimize the division if `divisor` isn't known: it uses `idiv`. But if the divisor were known, it could use the much more efficient magic number.

### Without LTO

In `math_divide_sum` compiled separately:

```c
int math_divide_sum(const int *data, int n, int divisor)
{
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += data[i] / divisor;
    }
    return sum;
}
```

```asm
math_divide_sum:
    ; divisor is in edx — value unknown at compile time
    ; ...
.L_loop:
    mov    eax, DWORD PTR [rdi+rcx*4]
    cdq
    idiv   esi                          ; division by variable → idiv
    add    r8d, eax
    add    rcx, 1
    cmp    ecx, edx
    jl     .L_loop
```

The compiler is forced to use `idiv` (20–90 cycles per iteration) because it doesn't know the divisor's value.

### With LTO

GCC sees that `main()` calls `math_divide_sum(data, 32, 7)` — the third argument is the constant `7`. It propagates this constant into the function body and applies the magic number replacement:

```asm
    ; math_divide_sum inlined in main(), divisor = 7 propagated
.L_loop:
    mov    eax, DWORD PTR [rdi+rcx*4]
    ; Division by 7 via magic number
    mov    edx, 0x92492493
    imul   edx                          ; multiplication by magic number
    add    edx, eax
    sar    edx, 2
    mov    eax, edx
    shr    eax, 31
    add    edx, eax                     ; edx = data[i] / 7
    add    r8d, edx
    add    rcx, 1
    cmp    ecx, 32                      ; n = 32 propagated too!
    jl     .L_loop
```

Two constants were propagated cross-module:

1. `divisor = 7` → the `idiv` is replaced by the magic number `0x92492493`.  
2. `n = 32` → the loop bound is an immediate, opening the door to unrolling and vectorization.

### What RE should remember

When you see a division magic number in the body of `main()` (or a high-level function) of an LTO binary, it may come from a function defined in an entirely different module. Without LTO, this same magic number would be in a separate function with a `call` to access it. With LTO, it appears "out of nowhere" in the middle of `main()`.

This is disorienting, but the recognition technique remains the same: identify the magic number, recover the divisor (cf. Section 16.6), and deduce the original logic.

---

## Effect 3 — Inter-module dead code elimination

Without LTO, the linker can't know if an exported function will be used by another `.o` file — it keeps it as a precaution. With LTO, the compiler sees the entire program and can determine that a function is never called.

### Example

Imagine that `utils_int_to_hex()` is called nowhere (or that the call is in an `if (0)` branch eliminated by constant propagation). Without LTO, it remains in the binary. With LTO, it's removed.

This effect can be observed by comparing symbols:

```bash
# Without LTO — all public functions are present
$ nm build/lto_demo_O2 | grep ' T ' | wc -l
12

# With LTO — only actually called functions survive
$ nm build/lto_demo_O2_flto | grep ' T ' | wc -l
5
```

The 7 missing functions were either inlined (their code merged into `main()`) or eliminated as dead code.

### What RE should remember

An LTO binary is often **smaller** than a non-LTO binary (despite inlining, which duplicates code) thanks to dead code elimination. If you're analyzing a binary and find surprisingly few functions for a program that seems complex, LTO is a hypothesis to consider.

---

## Effect 4 — Displaced magic constants

One of LTO's most disorienting effects for RE is the **displacement of recognizable constants** from one function to another.

### The `math_hash` case

```c
unsigned int math_hash(const char *str)
{
    unsigned int hash = 0x5F3759DF;  /* Recognizable constant */

    while (*str) {
        hash = hash * 31 + (unsigned char)(*str);
        str++;
    }

    hash ^= (hash >> 16);
    hash *= 0x45D9F3B;
    hash ^= (hash >> 16);

    return hash;
}
```

#### Without LTO

The constant `0x5F3759DF` and the multiplier `31` are in the body of `math_hash`, a function clearly identifiable by its symbol. An analyst who spots these constants in Ghidra can immediately identify a polynomial hash with murmurhash-type finalization.

```bash
$ objdump -d build/lto_demo_O2 | grep '5f3759df'
  401360:   mov    eax, 0x5f3759df       ← in math_hash
```

#### With LTO

`math_hash` is inlined into `main()`. Its constants appear in the middle of `main()`'s code, without obvious context:

```bash
$ objdump -d build/lto_demo_O2_flto | grep '5f3759df'
  401234:   mov    eax, 0x5f3759df       ← in main(), amid other code
```

The analyst browsing `main()` in Ghidra sees `0x5F3759DF` in the middle of a long instruction flow. Without knowing this constant, there's no immediate indication it's a hash. And even if they recognize it, they don't know it came from a separate function — it appears to be part of `main()`.

### Crypto constants are particularly affected

This phenomenon is critical when analyzing binaries using cryptography. Typical magic constants (AES S-box, SHA-256 initialization vectors, round constants) are normally grouped in an identifiable function (`aes_encrypt`, `sha256_update`). With LTO, they can end up scattered in the calling functions.

The tutorial's Appendix J lists common crypto constants. Keep it handy: constant recognition remains the best tool for identifying algorithms, even when LTO has scattered the code.

### What RE should remember

Facing an LTO binary, the strategy of "find the function then understand its body" no longer works for inlined functions. You need to invert the approach: **search for constants first** (hash magic numbers, crypto constants, division magic numbers), then reconstruct the logical boundaries of "ghost functions" around these constants.

---

## Effect 5 — Large functions: they survive LTO

Not everything is inlined with LTO. The same size heuristics as for intra-file inlining apply. Large functions remain explicit `call`s.

```c
long math_complex_transform(const int *data, int n)
{
    /* Three loops, branches, statistical calculations...
     * ~50 gimple statements → too large for inlining */
    // ...
}
```

### With LTO

```bash
$ nm build/lto_demo_O2_flto | grep math_complex_transform
0000000000401280 T math_complex_transform
```

The function survives. In `main()`, you still see a `call math_complex_transform`. However, LTO can still optimize it "from the inside" — for example by propagating constants known in `main()` as function arguments.

### What RE should remember

The presence of a function as a symbol in an LTO binary is a clue to its size and complexity. Functions visible in an LTO binary are the program's "large" functions — those that deserve in-depth analysis.

---

## Effect 6 — Inter-module devirtualization

LTO can resolve certain indirect calls (function pointers) when the target is determinable at compile time. This is **devirtualization** — an optimization particularly important for C++ (virtual calls via vtable) but that also applies to C.

### C example

```c
/* In lto_main.c */
unsigned int h1 = math_hash("hello");
```

Without LTO, if `math_hash` were called via a function pointer (which isn't the case here but illustrates the principle), the compiler of `lto_main.c` couldn't resolve the target. With LTO, it sees the entire program and can determine that the pointer always points to `math_hash`.

In C++, the effect is much more pronounced. A virtual call `obj->method()` goes through the vtable (a `call [rax+offset]`). If LTO can prove that `obj`'s dynamic type is always the same (for example because the object is constructed locally and never passed to polymorphic code), it replaces the indirect call with a direct call — or even inlines the method.

### What RE should remember

If you compare a C++ binary with and without LTO, you can observe that some `call [rax+offset]` (vtable calls) are replaced by `call direct_function` or even inlined code. This is devirtualization. For RE, this means the LTO binary contains **fewer indirect calls** — which facilitates analysis (targets are explicit) but masks the polymorphic nature of the source code.

---

## Identifying an LTO binary

How do you know if a binary you're analyzing was compiled with LTO? There's no explicit indicator in the final binary (`.gnu.lto_*` sections only exist in intermediate `.o` files), but several clues converge:

### Clue 1 — Few functions despite a complex program

An LTO binary typically has fewer functions than its non-LTO equivalent. If a program that should have dozens of modules shows only 5–10 functions in `nm` or Ghidra, LTO is likely.

### Clue 2 — Abnormally long `main()`

With LTO, functions from all modules can be inlined into `main()`. A `main()` function that spans 500 lines of decompilation in Ghidra, with heterogeneous constants (hash, crypto, parsing) mixed together, is characteristic of an LTO binary.

### Clue 3 — Absence of certain utility functions

In a multi-file program without LTO, utility functions (clamp, min, max, wrappers) exist as symbols even if they're trivial — because the caller's compiler couldn't inline them. If these functions are absent while the logic using them is present in the binary, it's a sign of LTO.

### Clue 4 — "Orphan" magic numbers

Recognizable constants (hash, crypto, CRC) appearing in the middle of `main()` or a high-level function, without being in a dedicated function, suggest cross-module inlining made possible by LTO.

### Clue 5 — Comments in debug information

If the binary isn't stripped and contains DWARF information, `DW_TAG_inlined_subroutine` entries may reference functions defined in other source files. This cross-file inlining is only possible with LTO (or with inline functions in headers):

```bash
$ readelf --debug-dump=info build/lto_demo_O2_flto | grep -B2 'DW_AT_abstract_origin'
# May show functions from lto_math.c inlined in lto_main.c
```

---

## LTO and binary size

LTO's effect on binary size is counterintuitive: it can **increase or decrease** size depending on the case.

**Reduction factors:**  
- Inter-module dead code elimination (never-called functions removed).  
- Elimination of prologues/epilogues of inlined functions.  
- Constant propagation → code simplification (e.g., `idiv` replaced by shorter magic number, dead branches eliminated).

**Increase factors:**  
- Cross-module inlining → body duplication at each call site.  
- More aggressive unrolling and vectorization thanks to constant propagation (known loop bounds).

In practice, LTO often reduces size by a few percent for medium-sized programs. For large programs with lots of dead code, the reduction can be significant (5–15%).

```bash
$ make lto_compare
=== Size difference ===
  Without LTO : 21456 bytes
  With LTO    : 19832 bytes
```

---

## Single-pass compilation vs LTO: what's the difference?

A legitimate question: if LTO amounts to optimizing the whole program at once, why not simply compile all `.c` files together?

```bash
# "Poor man's LTO" — everything in a single command
gcc -O2 -g -o lto_demo_single lto_main.c lto_math.c lto_utils.c -lm
```

In practice, this command **produces a very similar result to LTO** for a small project. GCC concatenates the IR from all three files and optimizes them together.

The difference appears in real projects with hundreds of files:

- Single-pass compilation recompiles **everything** on each modification — no incremental compilation.  
- LTO allows incremental compilation: only modified `.o` files are recompiled, but the link step redoes the global optimization.  
- LTO has specific optimization passes (call graph partitioning, interprocedural summaries) that aren't activated in monolithic compilation.

For RE, both approaches produce binaries that look very similar — the same functions are inlined, the same constants propagated. The distinction is transparent in the final binary.

---

## Summary: with and without LTO from the RE perspective

| Aspect | Without LTO (`-O2`) | With LTO (`-O2 -flto`) |  
|---|---|---|  
| Trivial cross-module functions | Explicit `call` (visible symbol) | Inlined, gone |  
| Medium cross-module functions | Explicit `call` | Inlined if few call sites |  
| Large functions | Explicit `call` | Explicit `call` (survive) |  
| Call graph in Ghidra | Complete, reflects architecture | Flattened, few XREFs |  
| Division by constant parameter | `idiv` (divisor unknown at compile) | Magic number (constant propagated) |  
| Magic constants (hash, crypto) | In the dedicated function | Scattered in the caller |  
| Inter-module dead code | Kept by linker | Eliminated |  
| Binary size | Reference | Often slightly smaller |  
| Indirect calls (C++ vtable) | `call [reg+offset]` | Potentially devirtualized |  
| RE identification | "Normal" number of functions | Few functions, long `main()` |

---

## Analysis strategy for LTO binaries

When you suspect a binary was compiled with LTO, here's a methodical approach:

**1. Start with functions that survived.** These are the large functions — they contain the program's complex logic. Analyze them first: they have clear boundaries, exploitable XREFs, and their decompilation in Ghidra is generally good quality.

**2. Search for recognizable constants in `main()`.** Hash magic numbers, crypto constants, divisors transformed into multiplicative magic numbers — these are your landmarks for identifying "ghost functions" inlined in `main()`.

**3. Segment `main()` into logical blocks.** In Ghidra, use comments and renames to annotate regions of `main()` that correspond to an inlined function. Name them `/* inlined: math_hash */` or similar.

**4. Look for duplicated patterns.** If the same sequence of constants and instructions appears multiple times in `main()`, it's a function inlined at multiple sites. Each occurrence is a copy of the same body.

**5. Use Compiler Explorer to validate.** If you've identified a library or algorithm, compile it on [godbolt.org](https://godbolt.org) with `-O2 -flto` and compare the assembly pattern with what you see in the binary.

**6. Compare with a non-LTO build if possible.** If you have access to sources or a debug binary, the `nm` comparison with and without LTO immediately reveals which functions were inlined.

---


⏭️ [Recognizing typical GCC patterns (compiler idioms)](/16-compiler-optimizations/06-gcc-patterns-idioms.md)
