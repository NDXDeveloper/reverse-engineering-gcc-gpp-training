🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 16.3 — Loop unrolling and vectorization (SIMD/SSE/AVX)

> **Associated source file**: `binaries/ch16-optimisations/loop_unroll_vec.c`  
> **Compilation**: `make s16_3` (produces 7 variants in `build/`, including `_O3_avx2`)

---

## Introduction

Loops are the heart of most programs: array traversals, accumulations, data transformations, sorting algorithms, protocol parsers. They're also the prime target of GCC's most aggressive optimizations, because that's where execution time is concentrated.

Two families of transformations apply to loops starting from `-O2`:

- **Unrolling** (*loop unrolling*): replicating the loop body N times to reduce the number of iterations and the cost of comparisons/jumps.  
- **Vectorization** (*auto-vectorization*): grouping multiple scalar iterations into a single SIMD operation, leveraging the processor's 128-bit (SSE, `xmm0`–`xmm15`) or 256-bit (AVX, `ymm0`–`ymm15`) registers.

These two transformations produce assembly that no longer resembles the original C loop at all. The loop body can be multiplied by 4 or 8, instructions you've never seen in `-O0` code appear (`paddd`, `vpmulld`, `vmovdqu`…), and the control structure fragments into three sub-loops (prologue, vectorized main body, epilogue).

For the reverse engineer, understanding these transformations is essential for analyzing any binary compiled at `-O2` or `-O3` that manipulates arrays — meaning virtually all real-world programs.

---

## Refresher: SIMD registers

Before diving into disassembly, a brief refresher on x86-64 SIMD architecture is needed. Chapter 3 (Section 3.9) introduces them; here we'll encounter them in context.

### SSE (Streaming SIMD Extensions)

SSE uses registers `xmm0` through `xmm15`, each being 128 bits wide. An `xmm` register can simultaneously hold 4 32-bit integers (or 2 64-bit integers, 4 single-precision floats, 2 double-precision). SSE instructions operate on all 4 values in parallel.

The most frequent SSE instructions in RE of loops on 32-bit integers:

| Instruction | Meaning | Scalar equivalent |  
|---|---|---|  
| `movdqa xmm0, [mem]` | Load 4 aligned ints | `mov eax, [mem]` × 4 |  
| `movdqu xmm0, [mem]` | Load 4 unaligned ints | same, no alignment constraint |  
| `paddd xmm0, xmm1` | Parallel addition 4 × 32-bit | `add eax, ecx` × 4 |  
| `psubd xmm0, xmm1` | Parallel subtraction | `sub eax, ecx` × 4 |  
| `pmulld xmm0, xmm1` | Parallel multiplication (SSE4.1) | `imul eax, ecx` × 4 |  
| `pxor xmm0, xmm1` | Parallel XOR | `xor eax, ecx` × 4 |  
| `pcmpgtd xmm0, xmm1` | Parallel > comparison (mask) | `cmp eax, ecx` × 4 |  
| `movdqa [mem], xmm0` | Store 4 aligned ints | `mov [mem], eax` × 4 |

### AVX / AVX2

AVX extends registers to 256 bits (`ymm0`–`ymm15`), allowing processing of 8 32-bit integers simultaneously. AVX instructions are prefixed with `v`: `vpaddd`, `vpmulld`, `vmovdqu`, etc.

AVX2 (introduced with Haswell in 2013) adds support for 256-bit integer operations. Without AVX2, `ymm` registers only serve for floats.

For RE, the presence of `vmov...`, `vpadd...`, `vpmul...` instructions with `ymm` registers indicates a binary compiled with `-mavx2` (or `-march=native` on a compatible CPU). It's a clue about the compilation environment.

---

## Loop unrolling

Unrolling is the simplest transformation to understand: instead of executing the loop body once per iteration with a `cmp` + `jmp` at each turn, GCC replicates the body N times and only performs the test once every N turns.

### Why unroll?

Each loop iteration has an incompressible fixed cost:

1. Increment the counter (`add edx, 1`).  
2. Compare with the bound (`cmp edx, ecx`).  
3. Perform the conditional jump (`jle .L_loop`).

On a modern CPU, these three instructions take ~1 cycle, but the conditional branch can cause a *branch misprediction* (~15 cycle penalty). By unrolling by 4, the number of branches is divided by 4.

Additionally, unrolling opens opportunities for other optimizations: the CPU can execute instructions from two iterations in parallel (instruction-level parallelism), and the compiler can reuse common values between adjacent iterations.

### Anatomy of an unrolled loop

Let's take the `vec_add` function from our source file:

```c
static void vec_add(int *dst, const int *a, const int *b, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = a[i] + b[i];
    }
}
```

#### In `-O0` — the literal loop

```asm
vec_add:
    push   rbp
    mov    rbp, rsp
    mov    QWORD PTR [rbp-0x8], rdi      ; dst
    mov    QWORD PTR [rbp-0x10], rsi     ; a
    mov    QWORD PTR [rbp-0x18], rdx     ; b
    mov    DWORD PTR [rbp-0x1c], ecx     ; n

    mov    DWORD PTR [rbp-0x20], 0       ; i = 0

.L_check:
    mov    eax, DWORD PTR [rbp-0x20]
    cmp    eax, DWORD PTR [rbp-0x1c]
    jge    .L_end

    ; Body: dst[i] = a[i] + b[i]
    mov    eax, DWORD PTR [rbp-0x20]     ; load i
    cdqe
    lea    rdx, [rax*4]
    mov    rax, QWORD PTR [rbp-0x10]     ; load a
    add    rax, rdx
    mov    ecx, DWORD PTR [rax]          ; ecx = a[i]

    mov    eax, DWORD PTR [rbp-0x20]     ; load i (again!)
    cdqe
    lea    rdx, [rax*4]
    mov    rax, QWORD PTR [rbp-0x18]     ; load b
    add    rax, rdx
    mov    eax, DWORD PTR [rax]          ; eax = b[i]

    add    ecx, eax                       ; ecx = a[i] + b[i]

    mov    eax, DWORD PTR [rbp-0x20]     ; load i (a 3rd time!)
    cdqe
    lea    rdx, [rax*4]
    mov    rax, QWORD PTR [rbp-0x8]      ; load dst
    add    rax, rdx
    mov    DWORD PTR [rax], ecx          ; dst[i] = result

    add    DWORD PTR [rbp-0x20], 1       ; i++
    jmp    .L_check

.L_end:
    pop    rbp
    ret
```

The counter `i` is reloaded from the stack **three times** per iteration (to compute `a[i]`, `b[i]`, `dst[i]`). This is the "worst case" in terms of performance, but it's perfectly readable for RE: you immediately see the loop structure and the computation performed.

#### In `-O2` — unrolling without vectorization

In `-O2`, GCC optimizes the loop with registers and may partially unroll it (typically by 2 or 4), but vectorization isn't always activated (it depends on `-ftree-vectorize`, active by default in `-O2` since GCC 12, but not in earlier versions):

```asm
    ; Loop unrolled by 2
    ; rdi = dst, rsi = a, rdx = b, ecx = n
    xor    eax, eax                       ; i = 0
    test   ecx, ecx
    jle    .L_done

.L_loop:
    ; Iteration i
    mov    r8d, DWORD PTR [rsi+rax*4]    ; r8d = a[i]
    add    r8d, DWORD PTR [rdx+rax*4]    ; r8d += b[i]
    mov    DWORD PTR [rdi+rax*4], r8d    ; dst[i] = result

    ; Iteration i+1 (unrolled)
    mov    r8d, DWORD PTR [rsi+rax*4+4]  ; r8d = a[i+1]
    add    r8d, DWORD PTR [rdx+rax*4+4]  ; r8d += b[i+1]
    mov    DWORD PTR [rdi+rax*4+4], r8d  ; dst[i+1] = result

    add    rax, 2                         ; i += 2
    cmp    eax, ecx
    jl     .L_loop

    ; Epilogue: if n is odd, process the last element
    ; ...

.L_done:
```

The unrolling signature is clear: the counter `rax` is incremented by 2 instead of 1, and the body contains two identical instruction groups with offsets shifted by 4 bytes (`+0` and `+4`).

Note the **epilogue**: when `n` isn't a multiple of the unrolling factor, a small loop or linear sequence processes the remaining elements. In `-O0`, there's no epilogue — the scalar loop processes every element one by one.

---

## Automatic vectorization

Vectorization is a level above unrolling: instead of processing iterations sequentially (even unrolled), the compiler executes them **in parallel** using SIMD registers.

### Conditions for vectorization

GCC only vectorizes a loop if **all** these conditions are met:

**1. No inter-iteration dependency.** If iteration `i` depends on the result of iteration `i-1`, the iterations can't be executed in parallel. This is the most common reason for vectorization failure.

**2. Operations supported by the SIMD instruction set.** The operation in the loop body must have a SIMD equivalent. Addition, subtraction, multiplication, XOR, comparisons are supported. Integer division, arbitrary function calls, non-sequential memory accesses are not (or only with difficulty).

**3. Sequential memory accesses.** Data must be accessed contiguously (`a[i]`, `a[i+1]`, `a[i+2]`, ...). A strided access (`a[i*stride]`) complicates vectorization, and an indirect access (`a[index[i]]`) prevents it.

**4. No unresolved aliasing.** The compiler must be sure that read and write memory regions don't overlap. The `restrict` keyword (C99) provides this guarantee to the compiler.

### `vec_add` in `-O3` — SSE vectorization

Let's revisit `vec_add` compiled at `-O3` (or `-O2` with `-ftree-vectorize`):

```asm
vec_add:                                  ; inlined in main() in practice
    ; Check: n >= 4 ?
    cmp    ecx, 3
    jle    .L_scalar                      ; too small → scalar loop

    ; Vectorized loop — 4 ints per iteration (SSE 128-bit)
    xor    eax, eax                       ; i = 0

.L_vec_loop:
    movdqu xmm0, XMMWORD PTR [rsi+rax]   ; xmm0 = a[i..i+3]  (4 integers)
    movdqu xmm1, XMMWORD PTR [rdx+rax]   ; xmm1 = b[i..i+3]
    paddd  xmm0, xmm1                    ; xmm0 = a[i..i+3] + b[i..i+3]
    movdqu XMMWORD PTR [rdi+rax], xmm0   ; dst[i..i+3] = result
    add    rax, 16                        ; i += 4 (4 ints × 4 bytes = 16)
    cmp    eax, r8d                       ; r8d = n rounded to multiple of 4
    jl     .L_vec_loop

    ; Epilogue: process remaining 0–3 elements (scalar)
.L_epilogue:
    ; ... scalar loop for the rest ...

.L_scalar:
    ; Classic scalar loop for n < 4
    ; ...
```

This is where the disassembly radically changes appearance. Let's break down the key elements.

**`movdqu xmm0, [rsi+rax]`** — Loads 128 bits (4 32-bit integers) from array `a` into register `xmm0`. The `movdqu` instruction (Move Double Quadword Unaligned) works even if the address isn't 16-byte aligned. If GCC can prove alignment, it uses `movdqa` (Aligned), which is slightly faster on older CPUs.

**`paddd xmm0, xmm1`** — Parallel addition of 4 32-bit integers: `xmm0[0] += xmm1[0]`, `xmm0[1] += xmm1[1]`, `xmm0[2] += xmm1[2]`, `xmm0[3] += xmm1[3]`. A single instruction replaces 4 scalar `add`s.

**`add rax, 16`** — The counter advances by 16 bytes (= 4 integers × 4 bytes/integer) each turn.

**The epilogue** — If `n` isn't a multiple of 4, the remaining 1 to 3 elements are processed by a small scalar loop. This is often the most confusing part of the disassembly, as it creates a second code path after the main loop.

### `vec_add` in `-O3 -mavx2` — AVX vectorization

With `-mavx2`, registers expand to 256 bits (`ymm`), processing 8 integers per iteration:

```asm
.L_vec_loop_avx:
    vmovdqu ymm0, YMMWORD PTR [rsi+rax]  ; ymm0 = a[i..i+7]  (8 integers)
    vpaddd  ymm0, ymm0, [rdx+rax]        ; ymm0 += b[i..i+7]
    vmovdqu YMMWORD PTR [rdi+rax], ymm0  ; dst[i..i+7] = result
    add     rax, 32                       ; i += 8 (8 ints × 4 bytes = 32)
    cmp     eax, r8d
    jl      .L_vec_loop_avx
```

The pattern is identical to SSE, but with `ymm` instead of `xmm`, `vmovdqu` instead of `movdqu`, `vpaddd` instead of `paddd`, and a step of 32 instead of 16.

For RE, the SSE vs AVX difference is immediately recognizable by the prefixes (`v` for AVX) and register names (`ymm` vs `xmm`). It's a clue about the target CPU and compilation flags.

---

## The three-part structure of a vectorized loop

A recurring pattern in `-O3` vectorized loop disassembly is the three-part structure. It's one of the most important patterns to recognize in RE.

### 1. The prologue (alignment)

If data isn't aligned to the SIMD register size (16 bytes for SSE, 32 for AVX), GCC may add a prologue loop that processes the first elements in scalar mode until reaching an aligned address.

```asm
    ; Prologue — process elements until alignment
    test   rdi, 0xF                      ; dst aligned to 16 bytes?
    jz     .L_main_loop                  ; yes → skip prologue
.L_prologue:
    mov    eax, DWORD PTR [rsi+rcx*4]
    add    eax, DWORD PTR [rdx+rcx*4]
    mov    DWORD PTR [rdi+rcx*4], eax
    add    rcx, 1
    test   rdi, 0xF                      ; retest alignment
    jnz    .L_prologue
```

In practice, the prologue is often absent if GCC uses `movdqu` (unaligned), which is the common case on modern CPUs (Haswell and later) where the cost of an unaligned access is negligible.

### 2. The main body (vectorized)

This is the SIMD loop we saw above: `movdqu` + SIMD operation + `movdqu` + increment by 16/32.

### 3. The epilogue (remainder)

After the main loop, remaining elements (when `n` isn't a multiple of the vectorization factor) are processed in scalar:

```asm
    ; Epilogue — remaining elements
    cmp    eax, ecx                      ; elements remaining?
    jge    .L_done
.L_epilogue:
    mov    r8d, DWORD PTR [rsi+rax*4]
    add    r8d, DWORD PTR [rdx+rax*4]
    mov    DWORD PTR [rdi+rax*4], r8d
    add    eax, 1
    cmp    eax, ecx
    jl     .L_epilogue
.L_done:
```

This prologue/body/epilogue structure is often what makes the disassembly of an `-O3` loop intimidating at first: a 3-line C loop transforms into 30–50 lines of assembly with three sub-loops and branches between them. But once the pattern is recognized, reading becomes systematic: identify the main loop (the one with `xmm`/`ymm`), understand the SIMD operation, ignore the prologue and epilogue.

---

## Reduction (accumulation): the dot product case

Loops with a single accumulator (sum, product, min, max) pose a particular challenge for vectorization: iterations aren't independent since each reads and writes the same accumulator.

```c
static long dot_product(const int *a, const int *b, int n)
{
    long sum = 0;
    for (int i = 0; i < n; i++) {
        sum += (long)a[i] * (long)b[i];
    }
    return sum;
}
```

### The solution: vector accumulator + horizontal reduction

GCC vectorizes this loop using a **vector accumulator** — an `xmm` register that contains 2 (or 4) partial sums in parallel. At the end of the loop, the partial sums are added into a single value by a **horizontal reduction**.

```asm
    ; Vectorized body (simplified)
    pxor     xmm2, xmm2                  ; vector accumulator = {0, 0}

.L_vec_loop:
    movdqu   xmm0, XMMWORD PTR [rsi+rax] ; load a[i..i+3]
    movdqu   xmm1, XMMWORD PTR [rdx+rax] ; load b[i..i+3]

    ; Multiplication with 32→64 bit extension
    ; (exact operations depend on GCC version)
    pmuludq  xmm0, xmm1                  ; 32×32→64 multiplication (2 results)
    paddq    xmm2, xmm0                  ; accumulator += results

    add      rax, 16
    cmp      eax, r8d
    jl       .L_vec_loop

    ; Horizontal reduction — sum the 2 elements of xmm2
    movhlps  xmm0, xmm2                  ; xmm0 = high part of xmm2
    paddq    xmm2, xmm0                  ; xmm2[0] = total sum
    movq     rax, xmm2                   ; scalar result in rax
```

Horizontal reduction instructions vary by data type. For 32-bit integers, you often see a `pshufd` + `paddd` sequence (or `phaddd` if SSSE3 is available). For 64-bit, `movhlps` + `paddq`.

### What RE should remember

If you see an `xmm` register initialized to zero (`pxor xmm, xmm`), then accumulated in a loop (`paddq` or `paddd`), followed by a `pshufd`/`movhlps` + additions sequence, it's a **vectorized reduction**. The original C code contains an accumulator (`sum += ...`).

---

## Complete unrolling of a constant-bound loop

When the number of iterations is known at compile time and is small, GCC can **completely unroll** the loop — no control instructions (`cmp`, `jmp`) remain.

```c
static void fixed_size_init(int arr[16])
{
    for (int i = 0; i < 16; i++) {
        arr[i] = i * i + 1;
    }
}
```

### In `-O0`

Classic loop with counter on the stack, 16 iterations with `cmp`/`jge`/`jmp`.

### In `-O2` / `-O3`

GCC evaluates `i * i + 1` for each `i` from 0 to 15 at compile time and produces a sequence of immediate stores:

```asm
    ; Complete unrolling — no loop
    mov    DWORD PTR [rdi],    1         ; arr[0]  = 0*0+1 = 1
    mov    DWORD PTR [rdi+4],  2         ; arr[1]  = 1*1+1 = 2
    mov    DWORD PTR [rdi+8],  5         ; arr[2]  = 2*2+1 = 5
    mov    DWORD PTR [rdi+12], 10        ; arr[3]  = 3*3+1 = 10
    mov    DWORD PTR [rdi+16], 17        ; arr[4]  = 4*4+1 = 17
    mov    DWORD PTR [rdi+20], 26        ; arr[5]  = 5*5+1 = 26
    ; ... etc. up to arr[15]
    mov    DWORD PTR [rdi+60], 226       ; arr[15] = 15*15+1 = 226
```

Or, if the values fit in a SIMD register, GCC can load a constant vector from `.rodata` and do a single `movdqa` for 4 values at a time:

```asm
    ; Vectorized variant of complete unrolling
    movdqa xmm0, XMMWORD PTR [rip+.LC0] ; {1, 2, 5, 10}
    movdqa XMMWORD PTR [rdi], xmm0
    movdqa xmm0, XMMWORD PTR [rip+.LC1] ; {17, 26, 37, 50}
    movdqa XMMWORD PTR [rdi+16], xmm0
    ; ... etc. (4 movdqa for 16 integers)
```

### What RE should remember

When you see a long sequence of `mov DWORD PTR [reg+offset], constant` without any loop around it, you're looking at a complete unrolling. The stored constants are pre-computed values — they often hold the key to understanding what the original loop did. Try to find the formula linking the constants to their index: here, the sequence `1, 2, 5, 10, 17, 26, 37, 50, ...` corresponds to `i² + 1`.

---

## Non-vectorizable loop: inter-iteration dependency

```c
static void dependent_loop(int *data, int n)
{
    for (int i = 1; i < n; i++) {
        data[i] = data[i - 1] * 3 + data[i];
    }
}
```

Here, `data[i]` depends on `data[i-1]` — the previous iteration's result is needed to compute the current one. Iterations cannot be executed in parallel.

### In `-O2` and `-O3`

GCC detects the dependency and **gives up on vectorization**. It can still partially unroll the loop, but each iteration remains sequential:

```asm
.L_loop:
    mov    eax, DWORD PTR [rdi+rcx*4-4]  ; eax = data[i-1]
    lea    eax, [rax+rax*2]              ; eax = data[i-1] * 3
    add    eax, DWORD PTR [rdi+rcx*4]    ; eax += data[i]
    mov    DWORD PTR [rdi+rcx*4], eax    ; data[i] = result
    add    rcx, 1
    cmp    rcx, rdx
    jl     .L_loop
```

Notice: no `xmm`/`ymm` instructions, despite `-O3`. The loop is scalar, with a single iteration per turn.

The multiplication by 3 is expressed with `lea eax, [rax+rax*2]` instead of `imul eax, eax, 3` — this is a common GCC idiom (cf. Section 16.6).

### What RE should remember

If a loop in `-O3` uses only scalar registers (`eax`, `ecx`, etc.) without any SIMD registers, it's a strong hint that the compiler detected an **inter-iteration dependency**. Look for the pattern: the value computed at iteration `i` is immediately used as a source at iteration `i+1`, typically via an offset shift (`[rdi+rcx*4-4]` for `data[i-1]` vs `[rdi+rcx*4]` for `data[i]`).

---

## The aliasing problem and the `restrict` keyword

Aliasing is the situation where two pointers may designate the same memory region. When GCC can't prove the absence of aliasing, it must be conservative.

```c
/* Without restrict — aliasing possible */
static void vec_add_alias(int *dst, const int *src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = dst[i] + src[i];
    }
}

/* With restrict — no aliasing guaranteed */
static void vec_add_noalias(int * restrict dst, const int * restrict src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = dst[i] + src[i];
    }
}
```

### Without `restrict` — runtime aliasing test

GCC doesn't know if `dst` and `src` overlap. If the regions overlap (for example `dst = src + 1`), vectorization would give an incorrect result. GCC therefore generates **two versions** of the loop: a vectorized version and a scalar version, with a runtime test to choose:

```asm
vec_add_alias:
    ; Runtime aliasing test
    lea    rax, [rdi+rcx*4]              ; end of dst
    cmp    rax, rsi                       ; dst_end > src ?
    jbe    .L_vectorized                  ; no overlap → vectorize

    lea    rax, [rsi+rcx*4]              ; end of src
    cmp    rax, rdi                       ; src_end > dst ?
    jbe    .L_vectorized                  ; no overlap → vectorize

    jmp    .L_scalar                      ; overlap → scalar

.L_vectorized:
    ; SIMD loop (movdqu + paddd + movdqu)
    ; ...

.L_scalar:
    ; Classic loop one element at a time
    ; ...
```

This aliasing test is a recognizable pattern: two `lea` instructions computing end addresses, followed by cross-`cmp` between the two memory regions, with a branch to the vectorized or scalar version.

### With `restrict` — direct vectorization

```asm
vec_add_noalias:
    ; No aliasing test — restrict guarantees non-interference
    ; Directly the SIMD loop
.L_vec_loop:
    movdqu xmm0, XMMWORD PTR [rdi+rax]
    movdqu xmm1, XMMWORD PTR [rsi+rax]
    paddd  xmm0, xmm1
    movdqu XMMWORD PTR [rdi+rax], xmm0
    add    rax, 16
    cmp    eax, edx
    jl     .L_vec_loop
```

The test has disappeared — the compiler trusts the `restrict`.

### What RE should remember

If you see a "dual path" in a function (two versions of the same loop, one with `xmm` and one without, preceded by an address test), it's a **runtime aliasing test**. It's a clue that the source code didn't use `restrict` and the compiler had to handle both cases.

---

## Floats and `-ffast-math`

Vectorization of floating-point reductions is an interesting special case.

```c
static float float_sum(const float *data, int n)
{
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        sum += data[i];
    }
    return sum;
}
```

### Without `-ffast-math`: no reduction vectorization

IEEE 754 floating-point addition is **not associative**: `(a + b) + c` can give a different result from `a + (b + c)` due to rounding. However, vectorizing a sum amounts to changing the evaluation order: instead of `sum += a[0]; sum += a[1]; sum += a[2]; sum += a[3];`, we compute `sum0 += a[0]; sum1 += a[1]; sum2 += a[2]; sum3 += a[3]; sum = sum0+sum1+sum2+sum3;`.

By default, GCC strictly respects IEEE 754 semantics and doesn't vectorize this loop. The result in `-O3` is a scalar loop using `addss` (Add Scalar Single):

```asm
.L_loop:
    addss  xmm0, DWORD PTR [rdi+rax*4]  ; scalar float addition
    add    rax, 1
    cmp    eax, ecx
    jl     .L_loop
```

`addss` operates on a single float in the low corner of register `xmm0`. The upper 96 bits are ignored — it's wasted SIMD.

### With `-ffast-math`: vectorization authorized

With `-ffast-math`, GCC has permission to reassociate floating-point additions:

```asm
    ; Vector accumulator — 4 partial sums
    xorps  xmm1, xmm1                   ; {0, 0, 0, 0}

.L_vec_loop:
    movups xmm0, XMMWORD PTR [rdi+rax]  ; 4 floats
    addps  xmm1, xmm0                   ; 4 parallel additions
    add    rax, 16
    cmp    eax, edx
    jl     .L_vec_loop

    ; Horizontal reduction
    movhlps xmm0, xmm1                  ; swap high and low
    addps   xmm1, xmm0                  ; cross sum
    movss   xmm0, xmm1
    shufps  xmm1, xmm1, 0x55
    addss   xmm0, xmm1                  ; final sum
```

The instructions `addps` (Add Packed Single) and `movups` (Move Unaligned Packed Single) are the float equivalents of `paddd` and `movdqu`. The horizontal reduction uses `movhlps` + `addps` + `shufps` + `addss` to sum the register's 4 elements.

### What RE should remember

If a loop on floats in `-O3` uses `addss` (scalar) instead of `addps` (parallel), the binary was probably compiled **without** `-ffast-math`. This is useful information: the developer cared about IEEE 754 numerical precision. Conversely, `addps` in a reduction indicates `-ffast-math` — the result may differ slightly from the sequential version.

---

## memset/memcpy recognition by the compiler

GCC recognizes certain loop patterns as being functionally equivalent to `memset` or `memcpy` and replaces them with calls to these optimized libc functions (or with inline `rep stosb` / `rep movsb` instructions).

```c
static void zero_fill(int *arr, int n)
{
    for (int i = 0; i < n; i++) {
        arr[i] = 0;
    }
}

static void copy_array(int *dst, const int *src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}
```

### In `-O0`

Explicit loops with `mov DWORD PTR [rdi+rax*4], 0` per iteration.

### In `-O2`

```asm
zero_fill:
    ; GCC replaces the loop with a call to memset
    movsxd rdx, esi                      ; rdx = n
    shl    rdx, 2                        ; rdx = n * 4 (size in bytes)
    xor    esi, esi                      ; value = 0
    jmp    memset@plt                    ; tail call to memset

copy_array:
    ; GCC replaces the loop with a call to memcpy
    movsxd rdx, edx                      ; rdx = n
    shl    rdx, 2                        ; rdx = n * 4
    mov    rax, rdi                      ; save dst for return
    jmp    memcpy@plt                    ; tail call to memcpy
```

The entire loop has been replaced by a single `jmp` (tail call) to `memset` or `memcpy`. The size calculation `n * 4` (an `int` is 4 bytes) is the only vestige of the original loop.

### What RE should remember

When you see a `call memset` or `call memcpy` in an optimized binary, it's possible that there's **no explicit call** to `memset`/`memcpy` in the source code. GCC recognized the loop pattern and replaced it automatically. Conversely, if you're reconstructing source code, you can choose to write a direct `memset` — the compiled result will be identical.

This phenomenon also explains why some optimized binaries make more calls to `memset`/`memcpy` than the source would suggest.

---

## Strength reduction in loops

*Strength reduction* replaces an expensive operation that depends on the loop counter with a less expensive incremental operation.

```c
static void strided_write(int *data, int n, int stride, int value)
{
    for (int i = 0; i < n; i++) {
        data[i * stride] = value + i;
    }
}
```

### In `-O0`

The index `i * stride` is computed by an `imul` at each iteration:

```asm
.L_loop:
    mov    eax, DWORD PTR [rbp-0x24]     ; i
    imul   eax, DWORD PTR [rbp-0x1c]     ; i * stride
    cdqe
    lea    rdx, [rax*4]
    mov    rax, QWORD PTR [rbp-0x8]      ; data
    add    rax, rdx
    ; ...
    mov    DWORD PTR [rax], ecx          ; data[i*stride] = value + i
```

### In `-O2`

GCC transforms the multiplication into a cumulative addition. Instead of recalculating `i * stride` each turn, it maintains a pointer that advances by `stride * 4` bytes each iteration:

```asm
    ; Pre-compute: stride_bytes = stride * 4
    movsxd rax, ecx                      ; rax = stride
    shl    rax, 2                        ; rax = stride * 4 (in bytes)

.L_loop:
    mov    DWORD PTR [rdi], esi          ; *ptr = value + i
    add    esi, 1                        ; value + i → value + i + 1
    add    rdi, rax                      ; ptr += stride_bytes
    cmp    esi, edx
    jl     .L_loop
```

The `imul` has disappeared, replaced by `add rdi, rax`. The multiplication (expensive: 3 cycles) is replaced by an addition (1 cycle). This is strength reduction.

### What RE should remember

When you see a pointer advancing by fixed steps in a loop (`add rdi, constant` or `add rdi, register`), without any visible multiplication, it's probably a strided indexed access whose multiplication was reduced to an addition. The advancement step (`rax` in the example) corresponds to `stride * sizeof(element)`.

---

## Summary: recognizing loop transformations in RE

| What you see in the disassembly | GCC transformation | What was in the source |  
|---|---|---|  
| `add rcx, 2` (or 4, 8) instead of `add rcx, 1` in the loop | Partial unrolling | `for(i=0; i<n; i++)` loop with duplicated body |  
| Loop body duplicated N times, counter incremented by N | Partial unrolling (factor N) | Same |  
| Sequence of `mov [reg+off], constant` without loop | Complete unrolling | Loop with constant and small bounds |  
| `movdqu xmm + paddd xmm + movdqu xmm`, counter += 16 | SSE vectorization (4 × int32) | Loop over an integer array |  
| `vmovdqu ymm + vpaddd ymm`, counter += 32 | AVX vectorization (8 × int32) | Same, with `-mavx2` |  
| `pxor xmm, xmm` + SIMD accumulation + `pshufd`/`phaddd` reduction | Vectorized reduction | `sum += ...` loop |  
| Three sub-loops (scalar prologue + SIMD body + scalar epilogue) | Vectorized loop with remainder handling | Simple loop where n isn't a multiple of the SIMD factor |  
| `lea`/`cmp` test on two addresses before the loop, two versions | Runtime aliasing test | Loop on two pointers without `restrict` |  
| `addss` instead of `addps` in a float reduction loop | No `-ffast-math` | `sum += float_array[i]` |  
| `call memset@plt` or `jmp memcpy@plt` | Pattern recognition | Zero-fill or copy loop |  
| `add rdi, reg` without `imul` in a loop | Strength reduction | `data[i * stride]` |  
| No SIMD registers despite `-O3` | Inter-iteration dependency | `data[i] = f(data[i-1])` |

---

## Practical tip: using `-fopt-info` to understand what GCC does

If you have access to the source code (or if you're experimenting), GCC provides a very useful flag for understanding its decisions:

```bash
gcc -O3 -fopt-info-vec-optimized -o test loop_unroll_vec.c
```

GCC displays the loops it vectorized:

```
loop_unroll_vec.c:42:5: optimized: loop vectorized using 16 byte vectors  
loop_unroll_vec.c:62:5: optimized: loop vectorized using 16 byte vectors  
```

And with `-fopt-info-vec-missed`, it explains why certain loops were **not** vectorized:

```
loop_unroll_vec.c:95:5: missed: not vectorized: complicated access pattern  
loop_unroll_vec.c:115:5: missed: not vectorized: possible dependence  
```

These messages are valuable for understanding the compiler's internal logic — even though in an RE situation, you obviously don't have access to them. The goal is to build your intuition about what's vectorizable and what's not.

---


⏭️ [Tail call optimization and its impact on the stack](/16-compiler-optimizations/04-tail-call-optimization.md)
