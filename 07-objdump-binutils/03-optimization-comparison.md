🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 7.3 — Comparison with/without GCC optimizations (`-O0` vs `-O2` vs `-O3`)

> 🔧 **Tools used**: `objdump`, `gcc`, `wc`, `diff`  
> 📦 **Binaries**: `keygenme_O0`, `keygenme_O2`, `keygenme_O3` (`binaries/ch07-keygenme/` directory)  
> 📝 **Syntax**: Intel (via `-M intel`), in line with the choice made in 7.2.

---

## Why this comparison is fundamental for RE

When you do reverse engineering on a "wild" binary, you do not choose the optimization level — the developer chose it at compile time. Now, the vast majority of production binaries are compiled with `-O2` or `-O3`. `-O0` debug builds are rarely distributed.

That means the assembly code you'll encounter in real conditions does **not** look like a naive translation of C. The compiler reorganized instructions, eliminated variables, merged operations, removed dead code, and sometimes transformed loops to the point of making them unrecognizable. If you have never seen these transformations, you risk wasting hours understanding an instruction sequence that, in reality, corresponds to three trivial lines of C.

The goal of this section is to show you these transformations on a concrete example, so that you know how to recognize them when you encounter them. We won't make an exhaustive catalog of every GCC optimization (Chapter 16 is devoted to that) — we'll focus here on what a RE beginner absolutely must know to recognize when reading an `objdump` listing.

---

## Preparation: compile the three variants

If you haven't already compiled the variants via the `Makefile`, here are the manual commands:

```bash
gcc -O0 -o keygenme_O0 keygenme.c  
gcc -O2 -o keygenme_O2 keygenme.c  
gcc -O3 -o keygenme_O3 keygenme.c  
```

Let's start with a quick measurement:

```bash
$ ls -l keygenme_O0 keygenme_O2 keygenme_O3
-rwxr-xr-x 1 user user  16696  keygenme_O0
-rwxr-xr-x 1 user user  16432  keygenme_O2
-rwxr-xr-x 1 user user  16464  keygenme_O3
```

The `-O0` version is slightly larger. The full executable size is not a very reliable indicator (it includes ELF headers, symbol tables, etc.), but it gives a first intuition. Let's look instead at the size of the `.text` section alone:

```bash
$ for f in keygenme_O0 keygenme_O2 keygenme_O3; do
    echo -n "$f .text: "
    readelf -S $f | grep '\.text' | awk '{print $6}' 
  done
keygenme_O0 .text: 0x...  
keygenme_O2 .text: 0x...  
keygenme_O3 .text: 0x...  
```

And let's count the number of instruction lines in the `.text` section:

```bash
$ for f in keygenme_O0 keygenme_O2 keygenme_O3; do
    echo -n "$f : "
    objdump -d -M intel -j .text $f | grep '^ ' | wc -l
  done
```

You'll typically find that `-O2` produces **fewer** instructions than `-O0`, and `-O3` may produce slightly **more** than `-O2`. That's counterintuitive at first: `-O3` optimizes more aggressively, but some of its transformations (loop unrolling, vectorization) *increase* code size in favor of speed. Optimizing does not always mean "produce less code" — it means "produce faster code".

---

## `-O0`: the faithful translation of C

The `-O0` level asks GCC to do **no optimization**. The assembly code produced is a near-literal translation of the C source code, instruction by instruction. It's the easiest level to understand in RE, because every local variable has a dedicated place on the stack, every operation corresponds to a visible instruction, and the control flow matches the source exactly.

Here are the dominant characteristics of code compiled at `-O0`:

### Everything goes through the stack

Every local variable is stored at a fixed position on the stack (relative to `rbp`). Even when a value has just been computed in a register, GCC immediately stores it to memory, then reloads it from memory to use it in the next operation. This produces systematic *store-load* sequences:

```asm
; hash += (int)input[i];
mov    eax, DWORD PTR [rbp-0x8]       ; load 'i' from the stack  
cdqe                                    ; sign extension eax → rax  
add    rax, QWORD PTR [rbp-0x18]      ; add the 'input' pointer  
movzx  eax, BYTE PTR [rax]            ; load input[i] (1 byte)  
movsx  eax, al                         ; sign extension → 32 bits  
add    DWORD PTR [rbp-0x4], eax        ; hash += ... (directly in memory)  
```

Six instructions for a simple addition in a loop. At `-O2`, this sequence will be reduced to two or three instructions by keeping values in registers.

### Systematic prologue/epilogue with frame pointer

Every function starts with `push rbp` / `mov rbp, rsp` and ends with `leave` / `ret`. The *frame pointer* (`rbp`) is always maintained, making it easy to navigate the stack with GDB. Every local variable is accessible via `[rbp-N]`.

### No inlining, no reordering

Every function call in the C code produces a `call` in the assembly. The instructions appear in the same order as the source code. `if/else` branches translate to a `cmp` followed by a conditional jump (`jz`, `jne`…) that directly reflects the `if` condition.

### Loops are literal

A `for` loop produces exactly the expected pattern: initialization, jump to the test, body, increment, test, conditional jump to the body.

```asm
; for (int i = 0; input[i] != '\0'; i++)
    mov    DWORD PTR [rbp-0x8], 0x0    ; i = 0
    jmp    test_label                   ; jump to the test
body_label:
    ; ... loop body ...
    add    DWORD PTR [rbp-0x8], 0x1    ; i++
test_label:
    ; ... load input[i], compare with 0 ...
    jne    body_label                   ; if != 0, continue
```

It's almost structured pseudocode — and that's exactly why `-O0` binaries are ideal for learning RE.

---

## `-O2`: the standard production optimization

The `-O2` level is the one you'll most often encounter on production binaries. GCC enables a broad battery of optimizations: register allocation, common subexpression elimination, constant propagation, *strength reduction*, instruction reordering, and many more.

Let's disassemble the same `compute_hash` function at `-O2` and observe the transformations:

```bash
objdump -d -M intel keygenme_O2 | less
```

### Variables live in registers

The most visible transformation: local variables are no longer stored on the stack. The compiler uses the processor's registers (there are 16 of them in x86-64, which is generous) to keep values in flight. The result: far fewer memory accesses, shorter instructions, and a more compact listing.

Where `-O0` did:

```asm
; Load i, use it, store the result
mov    eax, DWORD PTR [rbp-0x8]       ; load i from the stack
...
mov    DWORD PTR [rbp-0x4], eax        ; store hash on the stack
```

At `-O2`, you'll see something like:

```asm
; i stays in ecx, hash stays in edx — all in registers
movsx  eax, BYTE PTR [rdi+rcx]        ; load input[i] directly  
add    edx, eax                        ; hash += input[i]  
```

Two instructions instead of six. No `[rbp-...]` accesses. Variable names have disappeared — they are just registers.

> 💡 **RE consequence**: at `-O2`, you must **track registers** instead of tracking stack positions. It's harder because the same register can be reused for different variables throughout the function. A good reflex: annotate in the margin which register corresponds to which "logical variable" as you read.

### The frame pointer disappears (often)

With `-O2`, GCC enables `-fomit-frame-pointer` by default. The `push rbp` / `mov rbp, rsp` prologue disappears. The function starts directly with its useful code, and `rbp` is used as an additional general-purpose register. Accesses to local variables (if any remain on the stack) go through `rsp` instead of `rbp`.

```asm
; -O0: classic prologue
push   rbp  
mov    rbp, rsp  
sub    rsp, 0x20  

; -O2: minimal prologue (or absent)
sub    rsp, 0x8          ; only alignment if needed
; ... or nothing at all if the function has no need for stack
```

This absence of prologue breaks the function-boundary detection method via `push rbp` that we saw in 7.1. On a stripped binary compiled at `-O2`, you have to lean more on `call` targets and `ret` instructions to delimit functions.

### Instruction reordering

GCC reorders instructions to maximize parallelism at the processor pipeline level. The result: the code no longer follows the source order. An instruction that initializes a variable may appear several lines before the place you would expect it, because the compiler "advanced" it to hide the latency of a memory access.

It's destabilizing at first. At `-O0`, you could read the listing top to bottom and follow the C thread. At `-O2`, you sometimes have to reconstruct the logical flow by following data dependencies ("this register was written here, read there") rather than the sequential order.

### Replacing idioms: strength reduction

Some "expensive" operations are replaced by faster equivalents. The classic example is multiplication by a constant, replaced by combinations of shifts and additions:

```asm
; hash = hash * 8  at -O0
imul   eax, DWORD PTR [rbp-0x4], 0x8

; hash = hash * 8  at -O2  (strength reduction)
shl    edx, 3                          ; left shift by 3 = ×8
```

Similarly, division by a constant can be replaced by a multiplication by the modular inverse followed by a shift — a sequence that seems totally opaque if you don't know the pattern:

```asm
; x / 10  at -O2 (magic number division)
mov    eax, edi  
mov    edx, 0xcccccccd  
mul    edx  
shr    edx, 3  
```

These transformations will be studied in detail in Chapter 16. For now, simply remember that if you encounter a weird multiplication followed by a shift, it's probably a division by a constant optimized by GCC.

### Dead-code elimination and constant propagation

If GCC can determine at compile time that a branch will never be taken, it removes it entirely. If a variable is always equal to a constant, it replaces the variable with the constant everywhere. The resulting assembly code can contain significantly fewer branches than the C source suggested.

---

## `-O3`: aggressive optimization

The `-O3` level includes everything `-O2` does, plus additional transformations that can significantly modify the code structure:

### Loop unrolling

Instead of executing the body of a loop once per iteration with a continuation test, GCC duplicates the body several times to reduce the number of jumps:

```asm
; Original loop in C: for (i=0; i<4; i++) hash += input[i];

; At -O2: classic loop with test
.loop:
    movsx  eax, BYTE PTR [rdi+rcx]
    add    edx, eax
    inc    rcx
    cmp    rcx, r8
    jl     .loop

; At -O3: unrolled loop (the compiler can process 2 or 4 elements per iteration)
    movsx  eax, BYTE PTR [rdi+rcx]
    movsx  r9d, BYTE PTR [rdi+rcx+1]
    add    edx, eax
    add    edx, r9d
    add    rcx, 2
    cmp    rcx, r8
    jl     .loop
```

The result is more code (the body is duplicated), but fewer jumps (the test is evaluated only once for two iterations). In RE, an unrolled loop can look like "copy-pasted" sequential code — if you see very similar sequences repeated two or four times, it's probably unrolling.

### SIMD vectorization

GCC can transform a scalar loop into SIMD operations using `xmm` or `ymm` registers (SSE/AVX). Code that used to process array elements one by one starts to process them in batches of 4 (SSE, 128 bits) or 8 (AVX, 256 bits):

```asm
; Vectorized processing at -O3
movdqu xmm0, XMMWORD PTR [rdi+rcx]    ; load 16 bytes at once  
paddb  xmm1, xmm0                      ; parallel addition on 16 bytes  
add    rcx, 16  
cmp    rcx, rax  
jb     .loop_vec  
```

If you've never seen SIMD instructions, these mnemonics (`movdqu`, `paddb`, `pxor`, `pmaddwd`…) seem to belong to another language. Chapter 3 (section 3.9) briefly introduces them, and Chapter 16 covers them in depth. For now, remember that if you see `xmm`/`ymm` registers and instructions starting with `p` or `v`, it's vectorization — and the original loop was probably scalar.

### More aggressive inlining

At `-O3`, GCC is more inclined to integrate (*inline*) small functions directly into their caller. A function that existed as a distinct `call` at `-O2` may disappear completely at `-O3`: its code is copied at each call site. The result: fewer `call`s, longer functions, and "ghost" functions that no longer appear in the listing but whose code is scattered in other functions.

---

## Visual comparison: the same logic, three faces

To summarize the differences, here is what you can observe by disassembling the three variants of the same program:

| Characteristic | `-O0` | `-O2` | `-O3` |  
|---|---|---|---|  
| Local variables | On the stack (`[rbp-N]`) | In registers | In registers (+ SIMD) |  
| Frame pointer (`rbp`) | Always present | Often omitted | Often omitted |  
| Prologue `push rbp`/`mov rbp,rsp` | Systematic | Rare | Rare |  
| Number of instructions | High (many load/stores) | Reduced | Variable (unrolling ↑, vectorization ↑) |  
| Correspondence with C source | Near-direct | Recognizable but reorganized | Sometimes very remote |  
| Conditional jumps | Reflect `if`/`else` in C | May be inverted, reordered | Same + branchless (`cmov`) |  
| Function calls | All visible as `call` | Small functions possibly inlined | Aggressive inlining |  
| Loops | Recognizable for/while structure | Compact, sometimes inverted | Unrolled, vectorized |  
| Multiplication/division by constant | Literal `imul`/`idiv` | Strength reduction (shifts, magic numbers) | Same |  
| `xmm`/`ymm` registers | Absent (except float calculations) | Possible | Frequent (vectorization) |  
| RE difficulty | ★☆☆ Easy | ★★☆ Intermediate | ★★★ Difficult |

---

## `-Os`: the special case of size optimization

Although the `Makefile` doesn't produce an `-Os` variant, this level deserves mention. `-Os` enables the same optimizations as `-O2`, **except** those that increase code size. No loop unrolling, no extensive vectorization, limited inlining. The resulting code is compact and looks a lot like `-O2`, but without the duplications of `-O3`.

`-Os` is found in firmwares, embedded systems, and binaries distributed over the network (installers, updates) where size matters. In RE, it reads like "sedate" `-O2`.

---

## Practical method: comparing two listings with `diff`

To concretely see the differences between two optimization levels, generate the listings then compare them:

```bash
# Generate listings (only .text, Intel syntax)
objdump -d -M intel -j .text keygenme_O0 > /tmp/O0.asm  
objdump -d -M intel -j .text keygenme_O2 > /tmp/O2.asm  

# Visual comparison
diff --color /tmp/O0.asm /tmp/O2.asm | less

# Or side by side
diff -y --width=160 /tmp/O0.asm /tmp/O2.asm | less
```

This direct comparison is extremely instructive. You'll see functions shrink (fewer lines), `[rbp-N]` accesses disappear in favor of registers, prologues simplify, and loops change structure.

An even more telling alternative: use the `-S` output (interleaved source) with debug symbols, by compiling both versions with `-g`:

```bash
gcc -O0 -g -o keygenme_O0g keygenme.c  
gcc -O2 -g -o keygenme_O2g keygenme.c  

objdump -d -S -M intel keygenme_O0g > /tmp/O0_src.asm  
objdump -d -S -M intel keygenme_O2g > /tmp/O2_src.asm  
```

With `-O2 -g`, GCC keeps DWARF information even while optimizing. The interleaved listing then shows the same C lines associated with very different assembly — it's the most striking demonstration of optimization impact.

> 💡 **Complementary tool**: the [Compiler Explorer (godbolt.org)](https://godbolt.org) site lets you visualize in real time the assembly code produced by GCC at different optimization levels, with source/assembly correspondence coloring. It's an ideal complement to `objdump` for exploring compiler transformations.

---

## Implications for RE strategy

This comparison has direct consequences for your approach in reverse engineering:

**Always start by identifying the probable optimization level.** If the binary contains systematic `push rbp`/`mov rbp,rsp` prologues and omnipresent `[rbp-N]` accesses, it's `-O0` (or `-O1`) — you're on easy ground. If the frame pointer is absent and variables live in registers, it's at least `-O2`. If you see loop unrolling, `xmm` registers, and *magic numbers* for divisions, it's `-O3` or equivalent.

**Adapt your reading granularity.** On `-O0`, you can almost read instruction by instruction and translate to C on the fly. On `-O2`/`-O3`, it's better to first identify logical blocks (prologue, loop, function calls, return) then understand each block as a whole, rather than clinging to each individual instruction.

**Don't look for 1:1 mapping with the source.** On an optimized binary, a single line of C can produce zero instructions (optimized away) or ten instructions (unrolling + vectorization). Conversely, three lines of C can be fused into two assembly instructions. Look for **logic** rather than syntactic correspondence.

**Exploit the training binaries provided.** This tutorial provides each binary at multiple optimization levels precisely so you can practice this comparison. Analyze the `-O0` version first to understand the logic, then attack the `-O2` version already knowing what to look for. It's a luxury you won't have in real conditions, so take advantage of it during the training.

---

## Summary

GCC's optimization level radically transforms the produced assembly. At `-O0`, the code is a faithful translation of C: variables on the stack, full prologues, literal loops. At `-O2`, variables migrate to registers, the frame pointer disappears, instructions are reordered, and compiler idioms (strength reduction, constant propagation) replace naive operations. At `-O3`, loop unrolling, SIMD vectorization, and aggressive inlining can make the assembly code very far from the original source. Recognizing these transformations is an essential skill: it lets you quickly identify the optimization level of an unknown binary and adapt your analysis strategy accordingly.

---


⏭️ [Reading function prologues/epilogues in practice](/07-objdump-binutils/04-prologue-epilogue.md)
