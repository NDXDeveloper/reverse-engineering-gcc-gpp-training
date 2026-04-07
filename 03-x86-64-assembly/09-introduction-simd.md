🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.9 — Introduction to SIMD instructions (SSE/AVX) — recognizing them without fear

> 🎯 **Goal of this section**: know how to identify SIMD instructions when they appear in disassembly, understand why they are there, and be able to navigate through them without getting stuck during analysis. It is not about mastering SIMD programming — only about not panicking when GCC generates them.

---

## Why this section exists

You are analyzing a binary compiled with `-O2`. Everything is going well — `mov`, `cmp`, `jne`, `call` — and suddenly you hit this:

```asm
movdqu  xmm0, xmmword [rdi]  
movdqu  xmm1, xmmword [rsi]  
pcmpeqb xmm0, xmm1  
pmovmskb eax, xmm0  
cmp     eax, 0xffff  
jne     .not_equal  
```

First reaction: these mnemonics are incomprehensible. Second reaction: panic.

This section is here so that the second reaction does not happen. SIMD instructions are not rare in modern binaries — GCC generates them liberally from `-O2` onward, and libc itself is full of them (the optimized implementations of `memcpy`, `strcmp`, `strlen`…). You need to know how to recognize them, skim through them intelligently, and only dig in when necessary.

---

## SIMD in one sentence

**SIMD** (*Single Instruction, Multiple Data*) makes it possible to apply the same operation to **multiple data elements in parallel** with a single instruction. Instead of adding two integers one at a time, a SIMD instruction adds 4, 8, or 16 pairs of integers simultaneously.

```
Scalar (one operation at a time):          SIMD (4 parallel operations):

  a₁ + b₁ = c₁                              ┌ a₁ ┐   ┌ b₁ ┐   ┌ c₁ ┐
  a₂ + b₂ = c₂                              │ a₂ │ + │ b₂ │ = │ c₂ │
  a₃ + b₃ = c₃                              │ a₃ │   │ b₃ │   │ c₃ │
  a₄ + b₄ = c₄                              └ a₄ ┘   └ b₄ ┘   └ c₄ ┘

  4 instructions                              1 instruction
```

It is the mechanism that makes operations on arrays, strings, buffers, and numerical computations much faster.

---

## SIMD generations on x86-64

The x86-64 architecture has accumulated several generations of SIMD extensions over the decades. Each generation adds wider registers and new instructions:

| Extension | Year | Register width | Registers | Introduced by |  
|---|---|---|---|---|  
| **SSE** | 1999 | 128 bits | `xmm0`–`xmm7` | Intel Pentium III |  
| **SSE2** | 2001 | 128 bits | `xmm0`–`xmm7` | Intel Pentium 4 |  
| **SSE3/SSSE3** | 2004/2006 | 128 bits | `xmm0`–`xmm7` | Intel Prescott / Core 2 |  
| **SSE4.1/4.2** | 2008 | 128 bits | `xmm0`–`xmm7` | Intel Penryn / Nehalem |  
| **AVX** | 2011 | 256 bits | `ymm0`–`ymm15` | Intel Sandy Bridge |  
| **AVX2** | 2013 | 256 bits | `ymm0`–`ymm15` | Intel Haswell |  
| **AVX-512** | 2016 | 512 bits | `zmm0`–`zmm31` | Intel Xeon Phi / Skylake-X |

In x86-64 mode, **SSE2 is guaranteed** — it is part of the baseline AMD64 specification. This means any x86-64 binary can use the `xmm0`–`xmm15` registers and SSE2 instructions without a prior check. That is why GCC uses SSE2 as the default baseline, even without a specific flag.

> 💡 **For RE**: the vast majority of SIMD you will encounter in standard binaries is **SSE/SSE2**, sometimes SSE4.2 (for string operations). AVX and AVX-512 appear in scientific code, multimedia processing, or numerical libraries (BLAS, FFT, codecs…).

---

## SIMD registers

### `xmm` registers (128 bits — SSE)

The `xmm0` through `xmm15` registers are 128 bits wide (16 bytes). The same register can hold different data interpretations:

```
xmm0 (128 bits) can be viewed as:
┌────────────────────────────────────────────────────────────┐
│                   1 × 128-bit value                        │  (128-bit integer)
├─────────────────────────────┬──────────────────────────────┤
│       double (64 bits)      │       double (64 bits)       │  (2 × double)
├──────────────┬──────────────┬──────────────┬───────────────┤
│  float 32b   │  float 32b   │  float 32b   │  float 32b    │  (4 × float)
├───────┬──────┬───────┬──────┬───────┬──────┬───────┬───────┤
│ int32 │ int32│ int32 │ int32│  ...  │      │       │       │  (4 × int32)
├──┬──┬─┴─┬──┬─┴─┬──┬──┴──┬───┴──┬──┬─┴─┬──┬─┴─┬──┬──┴──┬────┤
│b │b │ b │b │ b │b │  b  │ b    │b │ b │b │ b │b │  b  │ b  │  (16 × byte)
└──┴──┴───┴──┴───┴──┴─────┴──────┴──┴───┴──┴───┴──┴─────┴────┘
```

It is the instruction's chosen interpretation that determines how the 128 bits are split. The register itself does not "know" whether it contains 2 doubles or 16 bytes.

### `ymm` registers (256 bits — AVX)

The `ymm0` through `ymm15` registers are the 256-bit extensions of the `xmm`s. The low half of a `ymm` **is** the corresponding `xmm`:

```
ymm0:  [ 256 bits                                                    ]
        [ high half (128 bits)    ][ low half = xmm0 (128 bits)     ]
```

### `zmm` registers (512 bits — AVX-512)

The same principle extended to 512 bits. Rare in everyday code.

### Role in the System V AMD64 convention

As seen in section 3.5, the `xmm0`–`xmm7` registers are used to **pass floating-point arguments**, and `xmm0` for the **floating-point return value**. These usages are scalar SSE (a single value per register), not vectorial SIMD — but they use the same physical registers.

---

## Recognizing SIMD instructions in the disassembly

### The naming system

SIMD mnemonics follow naming conventions that, once understood, let you guess the role of an instruction without knowing it by heart:

**Data-type prefixes/suffixes:**

| Prefix / Suffix | Meaning | Example |  
|---|---|---|  
| `ss` | *Scalar Single* — 1 × 32-bit float | `addss`, `movss` |  
| `sd` | *Scalar Double* — 1 × 64-bit double | `addsd`, `movsd` |  
| `ps` | *Packed Single* — 4 × 32-bit floats in parallel | `addps`, `mulps` |  
| `pd` | *Packed Double* — 2 × 64-bit doubles in parallel | `addpd`, `mulpd` |  
| `b` | Bytes (8-bit) | `paddb`, `pcmpeqb` |  
| `w` | Words (16-bit) | `paddw`, `pcmpeqw` |  
| `d` | Doublewords (32-bit) | `paddd`, `pcmpeqd` |  
| `q` | Quadwords (64-bit) | `paddq` |  
| `dq` / `dqu` | Double-quadword (128-bit) | `movdqa`, `movdqu` |

**Operation prefixes:**

| Prefix | Meaning | Examples |  
|---|---|---|  
| `p` | *Packed integer* | `paddb`, `pcmpeqb`, `pmovmskb` |  
| `v` | *VEX encoding* (AVX) | `vaddps`, `vmovdqu`, `vpxor` |

The `v` prefix is the immediate signal of an AVX (or higher) instruction. AVX instructions have the same semantics as their SSE equivalents, but with a VEX encoding that allows 3-register operands and the use of 256-bit `ymm` registers:

```asm
addps   xmm0, xmm1           ; SSE: xmm0 = xmm0 + xmm1 (2 operands)  
vaddps  ymm0, ymm1, ymm2     ; AVX: ymm0 = ymm1 + ymm2 (3 operands, 256 bits)  
```

### Categories of SIMD instructions

Without aiming for exhaustiveness, SIMD instructions are grouped into recognizable families:

**Data movement:**

```asm
movaps  xmm0, [rdi]          ; loads 128 aligned bits (packed float)  
movups  xmm0, [rdi]          ; loads 128 unaligned bits (packed float)  
movdqa  xmm0, [rdi]          ; loads 128 aligned bits (integers)  
movdqu  xmm0, [rdi]          ; loads 128 unaligned bits (integers)  
movss   xmm0, [rdi]          ; loads a single float (32-bit)  
movsd   xmm0, [rdi]          ; loads a single double (64-bit)  
```

The **aligned** (`a` = *aligned*) vs **unaligned** (`u` = *unaligned*) distinction is historically important: the aligned versions require the memory address to be a multiple of 16 bytes, otherwise they trigger a crash (`SIGSEGV`). The unaligned versions are more tolerant but were slower on older processors. On modern processors (since Nehalem/Sandy Bridge), the performance difference is negligible, and GCC increasingly uses the unaligned versions.

**Arithmetic:**

```asm
addps   xmm0, xmm1       ; 4 float additions in parallel  
mulpd   xmm0, xmm1       ; 2 double multiplications in parallel  
paddb   xmm0, xmm1       ; 16 byte additions in parallel  
psubd   xmm0, xmm1       ; 4 subtractions of 32-bit integers in parallel  
```

**Comparison:**

```asm
pcmpeqb xmm0, xmm1       ; compares 16 byte pairs → 0xFF if equal, 0x00 otherwise  
cmpps   xmm0, xmm1, 0    ; compares 4 float pairs (0 = equal)  
```

**Logic:**

```asm
pxor    xmm0, xmm0       ; zeroing of an xmm register (SSE idiom)  
pand    xmm0, xmm1       ; 128-bit AND  
por     xmm0, xmm1       ; 128-bit OR  
```

> 💡 **For RE**: `pxor xmm0, xmm0` is the SIMD equivalent of `xor eax, eax` — it is the standard zeroing of an SSE register. You will see it constantly.

**Rearrangement and extraction:**

```asm
pshufd  xmm0, xmm1, 0xff    ; redistributes the 4 doublewords according to a mask  
punpcklbw xmm0, xmm1        ; interleaves the bytes of two registers  
pmovmskb eax, xmm0           ; extracts the high-order bit of each byte → 16-bit mask  
```

**Conversion:**

```asm
cvtsi2sd  xmm0, eax        ; converts int → double  
cvttsd2si eax, xmm0        ; converts double → int (truncation)  
cvtss2sd  xmm0, xmm0       ; converts float → double  
```

These conversion instructions appear in mixed arithmetic code (computations involving both integers and floats).

---

## Why GCC generates SIMD in your code

Even if your C code uses no explicit SIMD function, GCC generates SIMD in four common situations:

### 1. Scalar floating-point arithmetic

In x86-64, **all floating-point arithmetic** goes through SSE registers. The old x87 unit (`st0`–`st7`) is almost never used. A simple `a + b` on `double`s generates:

```c
double add(double a, double b) {
    return a + b;
}
```

```asm
addsd   xmm0, xmm1       ; a in xmm0, b in xmm1, result in xmm0  
ret  
```

This is not SIMD in the "parallel operations" sense — it is scalar SSE. But the instructions and registers are the same. It is the most frequent case in ordinary code.

### 2. Auto-vectorization of loops (`-O2` / `-O3`)

GCC analyzes loops and, when possible, replaces scalar operations with vector operations. That is **auto-vectorization**:

```c
void add_arrays(float *a, const float *b, int n) {
    for (int i = 0; i < n; i++)
        a[i] += b[i];
}
```

At `-O3`, GCC may generate:

```asm
; Vectorized loop — processes 4 floats per iteration
.loop:
    movups  xmm0, [rdi+rax]     ; loads 4 floats of a[]
    movups  xmm1, [rsi+rax]     ; loads 4 floats of b[]
    addps   xmm0, xmm1           ; 4 additions in parallel
    movups  [rdi+rax], xmm0      ; stores the 4 results
    add     rax, 16               ; advances by 16 bytes (4 × 4)
    cmp     rax, rcx
    jl      .loop

; Cleanup loop — processes the remaining elements one by one
.cleanup:
    movss   xmm0, [rdi+rax]
    addss   xmm0, [rsi+rax]
    movss   [rdi+rax], xmm0
    add     rax, 4
    ; ...
```

The typical pattern is a **main loop** with `ps`/`pd` instructions (packed, parallel) that advances in blocks of 16 bytes (or 32 with AVX), followed by a **cleanup loop** (*epilog*) that processes the remaining elements in scalar (`ss`/`sd`).

> 💡 **For RE**: if you see a loop with `movups`/`addps`/`movups` that advances by 16-byte steps, followed by a small loop with `movss`/`addss` that advances by 4-byte steps, it is an auto-vectorized loop. The logic is the same as the scalar version — it just runs 4× faster.

### 3. String and buffer operations (libc)

Optimized implementations of `memcpy`, `memset`, `strcmp`, `strlen` in glibc use SIMD instructions extensively to process 16 or 32 bytes at a time. If you enter the code of these functions (in dynamic analysis with GDB, or in a static binary), you will see intensive SIMD.

An optimized `strcmp`, for example, loads 16 bytes of each string into `xmm` registers, compares them in bulk with `pcmpeqb`, and uses `pmovmskb` to extract a bitmask indicating the differing positions.

### 4. SSE4.2 instructions for strings

SSE4.2 introduced instructions specially designed for string processing, which glibc uses when the processor supports them:

```asm
pcmpistri xmm0, [rdi], 0x18    ; compares NUL-terminated strings implicitly  
pcmpistrm xmm0, [rdi], 0x40    ; same but returns a mask in xmm0  
```

These instructions are powerful but complex (the immediate byte encodes multiple options). In RE, just know they appear in optimized string-handling functions.

---

## SIMD reading strategy in RE

Most of the time, you do **not need** to understand every SIMD instruction in detail. Here is the recommended strategy:

### Level 1 — Identify and skim (enough in 80% of cases)

When you encounter a SIMD block:

1. **Identify the context**: is it in a computation loop, in a libc function, in a `memcpy`?  
2. **Look for the scalar version**: often, right after the vectorized loop, there is a scalar cleanup loop that does the same thing instruction by instruction — it is much easier to read.  
3. **Summarize the block** with a high-level comment: `// vectorized copy of 16 bytes`, `// parallel string comparison`, `// addition of 4 floats`.  
4. **Move on to the next block** — SIMD is rarely the interesting logic in application RE.

### Level 2 — Understand the vector logic (when necessary)

If SIMD **is** the interesting logic (vectorized crypto, SIMD parser, image processing), you need to decode it:

1. **Identify the data type** via the suffixes (`ps` = float, `pd` = double, `b` = bytes, `d` = int32…).  
2. **Follow the data register by register** — imagine each `xmm` register as a small array.  
3. **Use a scratch pad**: draw the registers as boxes split into elements and trace the operations.  
4. **Consult the Intel reference**: the *Intel Intrinsics Guide* (online) gives a visual description of each instruction with diagrams.

### Level 3 — Identify known algorithms

Some algorithms have recognizable SIMD implementations thanks to their constants and instruction sequences:

- **AES-NI**: `aesenc`, `aesdec`, `aeskeygenassist` — instructions dedicated to AES encryption, integrated into the processor since 2010. If you see these mnemonics, the code does hardware AES.  
- **CRC32**: `crc32` — dedicated SSE4.2 instruction.  
- **SHA**: `sha256rnds2`, `sha256msg1` — SHA Extensions instructions.  
- **CLMUL**: `pclmulqdq` — carry-less multiplication, used in GCM (authenticated encryption mode).

> 💡 **For crypto RE**: the presence of AES-NI instructions (`aesenc`, `aesdec`) immediately identifies the encryption algorithm — no need to recognize the S-box constants manually. It is a major shortcut over reversing purely software AES implementations. Chapter 24 covers crypto routine identification in detail.

---

## Common SIMD idioms generated by GCC

A few patterns you will frequently encounter and their meaning:

### Zeroing an SSE register

```asm
pxor    xmm0, xmm0           ; SSE: xmm0 = 0  
vpxor   xmm0, xmm0, xmm0    ; AVX: xmm0 = 0 (VEX encoding)  
vxorps  ymm0, ymm0, ymm0    ; AVX: ymm0 = 0 (256 bits)  
```

Equivalent of `xor eax, eax` for scalar registers.

### Integer ↔ floating-point conversion

```asm
cvtsi2sd  xmm0, eax          ; (int)eax → (double)xmm0  
cvttsd2si eax, xmm0          ; (double)xmm0 → (int)eax (truncation)  
```

Appears whenever C code mixes `int` and `double` in an expression.

### Memory block copy (inlined memcpy/memset)

```asm
; GCC inlines a small memcpy with SSE instructions
movdqu  xmm0, [rsi]  
movdqu  [rdi], xmm0          ; copies 16 bytes  
movdqu  xmm0, [rsi+0x10]  
movdqu  [rdi+0x10], xmm0     ; copies 16 more bytes  
```

When the size is known at compile time and small enough, GCC replaces the call to `memcpy` with a series of inline `movdqu`s. It is faster than a function call for small copies.

### Broadcasting a value (AVX)

```asm
vbroadcastss ymm0, [rdi]     ; copies a float into the 8 positions of the ymm  
vpbroadcastd ymm0, xmm0      ; copies an int32 into the 8 positions of the ymm  
```

Prepares a register where all positions hold the same value, typically before a parallel operation (comparing an array to a constant, filling a buffer…).

### Optimized string comparison

```asm
; Optimized strcmp (simplified pattern)
movdqu  xmm0, [rdi]              ; loads 16 bytes of string 1  
movdqu  xmm1, [rsi]              ; loads 16 bytes of string 2  
pcmpeqb xmm0, xmm1               ; compares byte by byte: 0xFF if equal, 0x00 otherwise  
pmovmskb eax, xmm0                ; extracts 1 bit per byte → 16-bit mask in eax  
cmp     eax, 0xffff               ; 0xFFFF = all 16 bytes are equal  
jne     .differ                    ; if not, there is a difference  
```

`pmovmskb` (*Packed Move Mask Byte*) is the key instruction: it extracts the high-order bit of each byte of the `xmm` register and concatenates them into a 32-bit register. It is the bridge between the SIMD world (128 bits) and the scalar world (conditions, jumps).

---

## SIMD and decompilers

Modern decompilers handle SIMD variably:

- **Ghidra**: recognizes basic SIMD instructions and shows them in the decompiler, but the result is often hard to read — it uses unfamiliar vector types and complex casts. The assembly view is sometimes clearer for SIMD.  
- **IDA + Hex-Rays**: better handling with intrinsic types (`__m128i`, `_mm_add_ps`…), but the result remains verbose.  
- **Binary Ninja**: support comparable to Ghidra.

In practice, for SIMD, the manually annotated assembly view remains the most productive approach. The decompiler is useful for the scalar code around the SIMD, but the vector blocks themselves deserve direct reading.

---

## What to remember going forward

1. **SIMD is normal in modern binaries** — GCC generates it for floating-point arithmetic, loop auto-vectorization, and optimized memory copies. It is not exotic.  
2. **The `xmm0`–`xmm15` registers** (128-bit) are ubiquitous: for scalar floats (calling convention) and for SIMD. The `ymm` registers (256-bit AVX) and `zmm` (512-bit AVX-512) are rarer.  
3. **The suffixes reveal the type**: `ss` = 1 float, `sd` = 1 double, `ps` = 4 parallel floats, `pd` = 2 parallel doubles, `b`/`w`/`d`/`q` = integers of varying size.  
4. **The `v` prefix** = AVX encoding. `addps` is SSE, `vaddps` is AVX — the semantics are the same.  
5. **`pxor xmm, xmm`** = zeroing. **`pmovmskb`** = bridge between SIMD and scalar. **`cvtsi2sd`/`cvttsd2si`** = int↔double conversion.  
6. **RE strategy**: in 80% of cases, identify the context, summarize the SIMD block in a high-level comment, and move on to the next block. Only decode instruction by instruction if the SIMD *is* the logic you are interested in.  
7. **AES-NI** (`aesenc`, `aesdec`) and **CRC32** instantly identify the algorithm — it is a powerful shortcut in crypto RE.

---


⏭️ [🎯 Checkpoint: manually annotate a real (provided) disassembly](/03-x86-64-assembly/checkpoint.md)
