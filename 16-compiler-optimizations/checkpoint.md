🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 16

## Objective

Identify **at least 3 optimizations** applied by GCC on the provided `opt_levels_demo_O2` binary, by comparing its disassembly with the `opt_levels_demo_O0` version.

This checkpoint validates your ability to recognize compiler transformations in a real binary — the central skill of this chapter.

---

## Context

You have two variants of the same program, compiled from the same source code (`opt_levels_demo.c`):

| Binary | Flags | Characteristics |  
|---|---|---|  
| `build/opt_levels_demo_O0` | `-O0 -g` | Non-optimized reference, DWARF symbols |  
| `build/opt_levels_demo_O2` | `-O2 -g` | Standard optimizations, DWARF symbols |

If the binaries aren't yet compiled:

```bash
cd binaries/ch16-optimisations/  
make s16_1  
```

---

## Instructions

Analyze the `opt_levels_demo_O2` binary by comparing it with `opt_levels_demo_O0`. For each identified optimization, document:

1. **The optimization's name** (inlining, magic number, cmov, unrolling, tail call, etc.).  
2. **Where it's located** in the disassembly (address or affected function).  
3. **What the code did in `-O0`** (the "naive" pattern).  
4. **What the code does in `-O2`** (the optimized pattern).  
5. **How you recognized it** (which visual clue put you on the trail).

You must identify **at least 3**. The binary contains far more — an experienced analyst can find 8 to 10 without effort.

---

## Suggested methodology

### Step 1 — Compare the number of functions

```bash
echo "=== Functions in O0 ==="  
nm build/opt_levels_demo_O0 | grep ' t \| T ' | sort  

echo ""  
echo "=== Functions in O2 ==="  
nm build/opt_levels_demo_O2 | grep ' t \| T ' | sort  
```

Note the functions that **disappeared** between `-O0` and `-O2`. Each disappearance is an optimization (inlining or dead code elimination).

### Step 2 — Compare the disassembly of `main()`

```bash
# Quick method with the Makefile
make disasm_compare BIN=opt_levels_demo

# Or manually
objdump -d -M intel build/opt_levels_demo_O0 | sed -n '/<main>:/,/^$/p' > /tmp/main_O0.asm  
objdump -d -M intel build/opt_levels_demo_O2 | sed -n '/<main>:/,/^$/p' > /tmp/main_O2.asm  
diff --color /tmp/main_O0.asm /tmp/main_O2.asm | less  
```

Browse `main()` in `-O2` and look for the patterns described in this chapter:

- An `imul` by a large hexadecimal constant → magic number (Section 16.6, Idiom 1).  
- A `cmp` + `cmovCC` → eliminated branch (Section 16.6, Idiom 5).  
- The absence of `call square` or `call clamp` → inlining (Section 16.2).  
- A `lea` with scale factor → multiplication by constant (Section 16.6, Idiom 4).  
- A counter incremented by 2+ in a loop → unrolling (Section 16.3).  
- A `jmp` at end of function instead of `call` + `ret` → tail call (Section 16.4).  
- A `lea` + `movsxd` + `jmp rax` → jump table (Section 16.6, Idiom 8).

### Step 3 — Examine a specific function

If `main()` is too dense, examine a function that survived inlining (if one exists) or compare a specific function between the two versions:

```bash
# Look for a specific function
objdump -d -M intel build/opt_levels_demo_O0 | grep -A 30 '<classify_grade>:'  
objdump -d -M intel build/opt_levels_demo_O2 | grep -A 30 '<classify_grade>:'  
```

### Step 4 (optional) — Verify with Ghidra

Import both binaries into Ghidra and compare the call graphs. The `main()` graph in `-O2` should be noticeably poorer in XREFs than the one in `-O0`.

---

## What you should find

Without revealing exact answers, here are the optimization categories present in this binary. You must document at least 3 from among these:

- **Inlining** of trivial and medium-sized `static` functions.  
- **Division replaced by magic number** (at least one division by constant in the source code).  
- **Conditional move** instead of branch for a simple if/else.  
- **Jump table** for a dense switch.  
- **Register allocation** — variables in registers instead of on the stack.  
- **Constant propagation** — values computed at compile time.  
- **Multiplication by constant via `lea`** instead of `imul`.  
- **`strlen` resolved at compile time** for string literals.  
- **`printf` replaced by `puts`** (if applicable to your GCC version).

---

## Deliverable format

Write a short document (1–2 pages) structured as follows:

```
# Checkpoint Report — Chapter 16

## Environment
- GCC version: ...
- OS: ...
- Compilation command: make s16_1

## Optimization 1: [name]
- Location: [function or address]
- In O0: [description of the naive pattern]
- In O2: [description of the optimized pattern]
- Recognition clue: [what put you on the trail]

## Optimization 2: [name]
...

## Optimization 3: [name]
...

## Additional observations (optional)
...
```

---

## Validation criteria

| Criterion | Expected |  
|---|---|  
| Number of optimizations identified | ≥ 3 |  
| Each optimization is correctly named | Yes |  
| The `-O0` pattern is described | Yes |  
| The `-O2` pattern is described | Yes |  
| The recognition clue is relevant | Yes |

If you've identified 3 optimizations with correct descriptions, you can move on to Chapter 17. If you found 5 or more, you've mastered the subject.

---

## Going further

If you finished quickly, apply the same analysis to the other chapter binaries:

- Compare `inlining_demo_O0` and `inlining_demo_O2` — count the disappeared functions.  
- Compare `loop_unroll_vec_O2` and `loop_unroll_vec_O3` — look for SIMD instructions.  
- Compare `loop_unroll_vec_O3` and `loop_unroll_vec_O3_avx2` — look for `ymm` registers.  
- Compare `lto_demo_O2` and `lto_demo_O2_flto` — use `make lto_compare`.  
- Compare `gcc_idioms_O2` and `gcc_idioms_clang_O2` (if `clang` is installed) — look for the compiler markers from Section 16.7.

---


⏭️ [Chapter 17 — Reverse Engineering C++ with GCC](/17-re-cpp-gcc/README.md)
