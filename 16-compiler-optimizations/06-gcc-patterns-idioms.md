🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 16.6 — Recognizing typical GCC patterns (compiler idioms)

> **Associated source file**: `binaries/ch16-optimisations/gcc_idioms.c`  
> **Compilation**: `make s16_6` (produces 6 variants in `build/`)

---

## Introduction

Every compiler has its "tics" — characteristic instruction sequences it systematically emits to translate certain C constructs. These sequences are called **compiler idioms**. Recognizing them instantly is one of the most valuable skills in reverse engineering: instead of dissecting each instruction one by one, you identify the pattern at a glance and reconstruct the original C operation.

The previous sections already showed some of these idioms in context (the division magic number in 16.1, `cmov` in 16.1, unrolling in 16.3). This section gathers them all in a systematic catalog, enriched with additional patterns you'll encounter frequently in RE.

Each idiom is presented with the original C code, the `-O0` assembly (for reference), and the `-O2` assembly (the pattern to recognize). Examples are drawn from `gcc_idioms.c`.

---

## Idiom 1 — Division by constant: the magic number

This is the most famous and most disorienting idiom the first time you encounter it. GCC replaces any division by a known constant with a multiplication followed by a shift.

### Why

The `idiv` instruction (signed division) is one of the slowest in the x86-64 instruction set: between 20 and 90 cycles depending on the CPU and operand size. By comparison, an `imul` takes 3 cycles. Replacing a division with a multiplication is therefore a considerable gain.

### The mathematical principle

To compute `x / N` with N known at compile time, we use the identity:

```
x / N  ≈  (x * M) >> S
```

where `M` (the *magic number*) and `S` (the *shift*) are precomputed by the compiler. `M` is the multiplicative inverse of `N` modulo 2^32 (or 2^64), adjusted so the shift compensates for rounding error.

The reference for these calculations is Chapter 10 of *Hacker's Delight* (Henry S. Warren Jr.).

### Example: signed division by 7

```c
int idiom_div_by_constant(int x)
{
    int a = x / 3;
    int b = x / 7;
    int c = x / 10;
    int d = x / 100;
    int e = x / 127;
    return a + b + c + d + e;
}
```

#### In `-O0`

```asm
    ; x / 7
    mov    eax, DWORD PTR [rbp-0x4]
    cdq                                  ; sign extension → edx:eax
    mov    ecx, 7
    idiv   ecx                           ; eax = quotient, edx = remainder
```

Simple and readable: `idiv` with the divisor in a register.

#### In `-O2`

```asm
    ; x / 7 — magic number
    mov    eax, edi                      ; eax = x
    mov    edx, 0x92492493               ; magic number M for /7
    imul   edx                           ; edx:eax = x * M (64-bit)
    add    edx, edi                      ; correction: edx += x
    sar    edx, 2                        ; arithmetic shift by 2
    mov    eax, edx
    shr    eax, 31                       ; extract sign bit
    add    edx, eax                      ; correction for negatives
    ; edx = x / 7
```

The pattern breaks down into steps:

1. **`imul edx` by the magic number** — 32×32→64-bit multiplication. The useful result is in `edx` (the high 32 bits of the 64-bit product).  
2. **Additive correction** (`add edx, edi`) — necessary for some divisors, not all.  
3. **`sar edx, S`** — arithmetic right shift, which completes the "division."  
4. **Sign correction** (`shr eax, 31` + `add`) — so the result is correct for negative numbers (arithmetic shift rounds toward -∞, while C division rounds toward zero).

### Table of common magic numbers

| Divisor | Magic number (signed, 32-bit) | Shift | Additive correction |  
|---|---|---|---|  
| 3 | `0x55555556` | 0 | No |  
| 5 | `0x66666667` | 1 | No |  
| 7 | `0x92492493` | 2 | Yes (`add edx, edi`) |  
| 9 | `0x38E38E39` | 1 | No |  
| 10 | `0x66666667` | 2 | No |  
| 12 | `0x2AAAAAAB` | 1 | No |  
| 100 | `0x51EB851F` | 5 | No |  
| 127 | `0x02040811` | varies | Depends on GCC |  
| 1000 | `0x10624DD3` | 6 | No |

> 💡 You don't need to memorize this table. What matters is recognizing the **pattern**: an `imul` by a large hexadecimal constant followed by `sar` = division by constant. To recover the divisor, you can use the inverse formula or simply test: `0x66666667 * 42` >> 34 indeed gives `42 / 10 = 4`.

### Unsigned division

For `unsigned int`, the pattern is slightly different: no sign correction, and the magic number may differ.

```c
unsigned int idiom_udiv_by_constant(unsigned int x)
{
    return x / 10;
}
```

```asm
    ; unsigned x / 10
    mov    eax, edi
    mov    edx, 0xCCCCCCCD               ; unsigned magic number for /10
    mul    edx                           ; mul (unsigned) instead of imul
    shr    edx, 3                        ; shr (unsigned) instead of sar
    ; edx = x / 10
```

Key differences: `mul` instead of `imul`, `shr` instead of `sar`, and no sign correction. The magic number is also different (`0xCCCCCCCD` vs `0x66666667`).

### How to recover the divisor in RE

Facing an unknown magic number in a binary, two approaches:

**Empirical approach** — Test a few values. If `(x * MAGIC) >> S` gives `x / N` for several `x`, you've found `N`.

**Computational approach** — The divisor N satisfies: `N ≈ 2^(32 + S) / M` (for unsigned) or a similar formula with correction for signed.

**Tool** — Ghidra's plugin automatically recognizes division magic numbers and displays `x / N` in the decompiler. This is one of the reasons the decompiler is so useful in RE.

---

## Idiom 2 — Modulo by power of 2: AND bitmask

```c
unsigned int idiom_umod_power_of_2(unsigned int x)
{
    return x % 8;
}
```

### In `-O2` (unsigned)

```asm
    ; unsigned x % 8
    and    eax, 7                        ; mask the 3 least significant bits
    ; eax = x % 8
```

For an unsigned integer, `x % 2^n` is strictly equivalent to `x & (2^n - 1)`. GCC applies this substitution systematically. It's the simplest idiom to recognize: an `and` by `0x7`, `0xF`, `0x1F`, `0x3F`, `0xFF`, etc.

### In `-O2` (signed)

```c
int idiom_mod_power_of_2(int x)
{
    return x % 8;
}
```

For signed integers, C modulo has the sign of the dividend (`-13 % 8 = -5`), which requires a correction:

```asm
    ; signed x % 8
    mov    eax, edi
    cdq                                  ; edx = 0 if x >= 0, 0xFFFFFFFF if x < 0
    ; Alternative: sar eax, 31 → same effect
    and    edx, 7                        ; mask = 7 if x < 0, 0 if x >= 0
    add    eax, edx                      ; adjust for negatives
    and    eax, 7                        ; final mask
    sub    eax, edx                      ; restore sign
    ; eax = x % 8 (signed)
```

The signed pattern is longer but remains recognizable by the presence of two `and` by the same constant with a `cdq` or `sar eax, 31` in between.

---

## Idiom 3 — Modulo by non-power-of-2 constant

```c
int idiom_mod_non_pow2(int x)
{
    return x % 7;
}
```

GCC computes the modulo in two steps: first the division `x / 7` by magic number (Idiom 1), then the subtraction `x - (x/7) * 7`.

### In `-O2`

```asm
    ; x % 7
    ; Step 1: compute x / 7 (magic number)
    mov    eax, edi
    mov    edx, 0x92492493
    imul   edx
    add    edx, edi
    sar    edx, 2
    mov    eax, edx
    shr    eax, 31
    add    edx, eax                      ; edx = x / 7

    ; Step 2: x - (x/7) * 7
    lea    eax, [rdx+rdx*2]             ; eax = (x/7) * 3
    lea    eax, [rdx+rax*2]             ; eax = (x/7) + (x/7)*3*2 = (x/7) * 7
    ; (GCC uses lea to multiply by 7 without imul)
    sub    edi, eax                      ; edi = x - (x/7) * 7 = x % 7
```

Modulo thus produces the magic number pattern **plus** a multiplication by the divisor (often via `lea`) and a final subtraction.

---

## Idiom 4 — Multiplication by constant: lea / shl / add

GCC avoids the `imul` instruction when it can express the multiplication through combinations of `lea`, `shl`, and `add`, which are faster on some CPUs.

```c
int idiom_mul_by_constant(int x)
{
    int a = x * 2;
    int b = x * 3;
    int c = x * 5;
    int d = x * 7;
    int e = x * 9;
    int f = x * 10;
    int g = x * 15;
    int h = x * 100;
    return a + b + c + d + e + f + g + h;
}
```

### Patterns in `-O2`

The `lea` (Load Effective Address) instruction can compute `base + index * {1, 2, 4, 8}` in a single cycle. GCC exploits this for small multipliers:

```asm
    ; x * 2
    add    eax, eax                      ; or: shl eax, 1
                                         ; or: lea eax, [rdi+rdi]

    ; x * 3
    lea    eax, [rdi+rdi*2]             ; eax = x + x*2 = x*3

    ; x * 5
    lea    eax, [rdi+rdi*4]             ; eax = x + x*4 = x*5

    ; x * 7
    lea    eax, [rdi+rdi*2]             ; eax = x*3
    lea    eax, [rdi+rax*2]             ; eax = x + x*3*2 = x*7
    ; Variant: lea eax, [rdi*8] ; sub eax, edi  → x*8 - x = x*7

    ; x * 9
    lea    eax, [rdi+rdi*8]             ; eax = x + x*8 = x*9

    ; x * 10
    lea    eax, [rdi+rdi*4]             ; eax = x*5
    add    eax, eax                      ; eax = x*10

    ; x * 15
    lea    eax, [rdi+rdi*4]             ; eax = x*5
    lea    eax, [rax+rax*2]             ; eax = x*5 * 3 = x*15

    ; x * 100
    lea    eax, [rdi+rdi*4]             ; eax = x*5
    lea    eax, [rax+rax*4]             ; eax = x*25
    shl    eax, 2                        ; eax = x*100
```

### Table of common multipliers

| Multiplier | GCC pattern | Logic |  
|---|---|---|  
| 2 | `add eax, eax` or `shl eax, 1` | x + x or x << 1 |  
| 3 | `lea [rdi+rdi*2]` | x + 2x |  
| 4 | `shl eax, 2` | x << 2 |  
| 5 | `lea [rdi+rdi*4]` | x + 4x |  
| 6 | `lea [rdi+rdi*2]` + `add eax, eax` | 3x × 2 |  
| 7 | `lea [rdi*8]` + `sub eax, edi` | 8x − x |  
| 8 | `shl eax, 3` | x << 3 |  
| 9 | `lea [rdi+rdi*8]` | x + 8x |  
| 10 | `lea [rdi+rdi*4]` + `add eax, eax` | 5x × 2 |

For larger multipliers or those that don't decompose easily, GCC uses `imul eax, edi, constant` — a direct `imul` with immediate, which remains fast (3 cycles).

### What RE should remember

When you see a `lea` with a scale factor (1, 2, 4, 8) followed by another `lea` or an `add`/`shl`, it's a constant multiplication decomposed. Mentally recombine the factors: `lea [rdi+rdi*4]` = ×5, `lea [rax+rax*2]` = previous result × 3, etc.

---

## Idiom 5 — Conditional move (cmov): the eliminated branch

```c
int idiom_cmov_max(int a, int b)
{
    return (a > b) ? a : b;
}

int idiom_cmov_abs(int x)
{
    return (x < 0) ? -x : x;
}
```

### In `-O2`

```asm
idiom_cmov_max:
    cmp    edi, esi                      ; compare a and b
    mov    eax, esi                      ; eax = b (default value)
    cmovg  eax, edi                     ; if a > b: eax = a
    ret

idiom_cmov_abs:
    mov    eax, edi                      ; eax = x
    neg    eax                           ; eax = -x
    cmovs  eax, edi                     ; if -x is negative (x was positive): eax = x
    ret
    ; Variant: test edi, edi ; cmovns instead of neg+cmovs
```

The `cmov` (Conditional MOVe) performs a conditional `mov` without branching. The CPU evaluates **both** possible values, then chooses which to assign to the destination register based on the flags.

### cmov variants

| Instruction | Condition | Typical usage |  
|---|---|---|  
| `cmovg` / `cmovl` | > / < (signed) | Signed `max(a, b)`, `min(a, b)` |  
| `cmova` / `cmovb` | > / < (unsigned) | Unsigned `max(a, b)`, `min(a, b)` |  
| `cmove` / `cmovne` | == / != | Equality-based selection |  
| `cmovs` / `cmovns` | positive/negative sign | `abs(x)` |  
| `cmovge` / `cmovle` | >= / <= | Clamp, saturation |

### What RE should remember

A `cmp` + `cmovCC` is a simple if/else without branching. The `cmov`'s destination operand is the value chosen if the condition is true; the destination register before the `cmov` contains the "else" value. Reconstruct the ternary: `result = (condition) ? cmov_value : previous_value`.

---

## Idiom 6 — Bit test: `test` + `setcc` / `jcc`

```c
int idiom_test_bit(int flags)
{
    int result = 0;
    if (flags & 0x01) result += 1;
    if (flags & 0x04) result += 10;
    if (flags & 0x80) result += 100;
    return result;
}
```

### In `-O2`

```asm
    xor    eax, eax                      ; result = 0
    test   dil, 1                        ; test bit 0
    jz     .L_skip1
    mov    eax, 1                        ; result = 1
.L_skip1:
    test   dil, 4                        ; test bit 2
    jz     .L_skip2
    add    eax, 10                       ; result += 10
.L_skip2:
    test   dil, 0x80                     ; test bit 7
    jz     .L_skip3
    add    eax, 100                      ; result += 100
.L_skip3:
    ret
```

The `test` instruction performs a logical AND without storing the result — it only modifies the flags. `test reg, mask` followed by `jz` is the standard pattern for "if bit N is set."

Variant with `setcc` when the result is boolean:

```asm
    ; flag = (x & 4) != 0
    test   edi, 4
    setnz  al                            ; al = 1 if bit 2 is set, 0 otherwise
    movzx  eax, al                       ; 8→32-bit extension
```

### What RE should remember

The pattern `test reg, power_of_2_constant` followed by `jz`/`jnz` or `setz`/`setnz` corresponds to a bit test in the source code. The `test`'s constant indicates which bit is being tested: `1` = bit 0, `2` = bit 1, `4` = bit 2, `0x80` = bit 7, `0x100` = bit 8, etc. This pattern is ubiquitous in code that manipulates flags, bitmasks, hardware registers, or permissions.

---

## Idiom 7 — Boolean normalization: `!!x`

```c
int idiom_bool_normalize(int x)
{
    return !!x;    /* Converts any non-zero value to 1 */
}

int idiom_bool_from_compare(int a, int b)
{
    return (a == b);
}
```

### In `-O2`

```asm
idiom_bool_normalize:
    test   edi, edi                      ; x == 0 ?
    setne  al                            ; al = 1 if x != 0, 0 otherwise
    movzx  eax, al                       ; 8→32-bit extension
    ret

idiom_bool_from_compare:
    cmp    edi, esi                      ; a == b ?
    sete   al                            ; al = 1 if a == b
    movzx  eax, al                       ; 8→32-bit extension
    ret
```

The `test`/`cmp` + `setCC` + `movzx` pattern is GCC's standard way of producing a boolean 0 or 1 result from a condition. Common variants:

| C code | Instructions |  
|---|---|  
| `!!x` | `test edi, edi` + `setne al` + `movzx` |  
| `x == 0` | `test edi, edi` + `sete al` + `movzx` |  
| `a == b` | `cmp edi, esi` + `sete al` + `movzx` |  
| `a < b` | `cmp edi, esi` + `setl al` + `movzx` |  
| `a >= b` | `cmp edi, esi` + `setge al` + `movzx` |

---

## Idiom 8 — Dense switch: the jump table

```c
const char *idiom_switch_dense(int day)
{
    switch (day) {
        case 0: return "Monday";
        case 1: return "Tuesday";
        case 2: return "Wednesday";
        case 3: return "Thursday";
        case 4: return "Friday";
        case 5: return "Saturday";
        case 6: return "Sunday";
        default: return "Unknown";
    }
}
```

### In `-O2`

```asm
idiom_switch_dense:
    cmp    edi, 6
    ja     .L_default                    ; if day > 6 → "Unknown"

    ; Jump table
    lea    rax, [rip+.L_jumptable]
    movsxd rdx, DWORD PTR [rax+rdi*4]   ; load relative offset
    add    rax, rdx
    jmp    rax                           ; jump to corresponding case

.L_case_0:
    lea    rax, [rip+.LC_monday]         ; "Monday"
    ret
.L_case_1:
    lea    rax, [rip+.LC_tuesday]        ; "Tuesday"
    ret
; ... etc.

.L_default:
    lea    rax, [rip+.LC_unknown]
    ret

; In .rodata:
.L_jumptable:
    .long  .L_case_0 - .L_jumptable     ; relative offset to case 0
    .long  .L_case_1 - .L_jumptable     ; relative offset to case 1
    .long  .L_case_2 - .L_jumptable
    ; ... etc.
```

The jump table is an array of relative offsets stored in `.rodata`. The recognition pattern is as follows, in this order:

1. `cmp edi, N` + `ja .L_default` — bounds check.  
2. `lea rax, [rip+.L_jumptable]` — load the table's base.  
3. `movsxd rdx, [rax+rdi*4]` — read the offset indexed by the switch value.  
4. `add rax, rdx` — compute the target address.  
5. `jmp rax` — indirect jump.

GCC generates a jump table when case values are **dense** (few gaps between them). The threshold depends on the GCC version, but in general, if more than ~75% of values in the min–max range have a case, GCC prefers the jump table.

---

## Idiom 9 — Sparse switch: comparison tree

```c
const char *idiom_switch_sparse(int code)
{
    switch (code) {
        case 1:    return "START";
        case 7:    return "PAUSE";
        case 42:   return "ANSWER";
        case 100:  return "PERCENT";
        case 255:  return "MAX_BYTE";
        case 1000: return "KILO";
        default:   return "UNKNOWN";
    }
}
```

Case values are far apart — a 1000-entry jump table for 6 cases would be wasteful.

### In `-O2`

GCC generates a **binary comparison tree** — a sort of binary search:

```asm
idiom_switch_sparse:
    cmp    edi, 42
    je     .L_answer                     ; case 42
    jg     .L_upper_half                 ; code > 42 → search in {100, 255, 1000}

    ; code < 42
    cmp    edi, 1
    je     .L_start                      ; case 1
    cmp    edi, 7
    je     .L_pause                      ; case 7
    jmp    .L_unknown                    ; default

.L_upper_half:
    cmp    edi, 100
    je     .L_percent                    ; case 100
    cmp    edi, 255
    je     .L_max_byte                   ; case 255
    cmp    edi, 1000
    je     .L_kilo                       ; case 1000
    jmp    .L_unknown                    ; default
```

GCC chooses a pivot value (here 42) and divides the cases into two groups. Each group can be subdivided recursively if needed. The number of comparisons is O(log N) instead of O(N) for a linear cascade.

### What RE should remember

If you see a `cmp`/`je` cascade organized as a tree (with an initial `jg` or `jl` separating two groups), it's a sparse switch. If you see a `lea` + `movsxd` + `jmp rax`, it's a dense switch (jump table). The boundary between the two depends on case density.

Ghidra reconstructs both patterns as switch/case in the decompiler.

---

## Idiom 10 — Bit rotation: `rol` / `ror`

The C language has no bit rotation operator. Developers write the classic pattern:

```c
unsigned int idiom_rotate_left(unsigned int x, int n)
{
    return (x << n) | (x >> (32 - n));
}

unsigned int idiom_rotate_left_13(unsigned int x)
{
    return (x << 13) | (x >> 19);
}
```

### In `-O0`

The pattern is translated literally — two shifts and an OR:

```asm
    ; (x << n) | (x >> (32 - n))
    mov    eax, DWORD PTR [rbp-0x4]
    mov    ecx, DWORD PTR [rbp-0x8]
    shl    eax, cl                       ; x << n
    mov    edx, 32
    sub    edx, DWORD PTR [rbp-0x8]
    mov    ecx, edx
    mov    edx, DWORD PTR [rbp-0x4]
    shr    edx, cl                       ; x >> (32-n)
    or     eax, edx                      ; result
```

### In `-O2`

GCC **recognizes the pattern** and replaces it with a single `rol` instruction:

```asm
idiom_rotate_left:
    mov    eax, edi
    mov    ecx, esi
    rol    eax, cl                       ; left rotate by n bits
    ret

idiom_rotate_left_13:
    mov    eax, edi
    rol    eax, 13                       ; left rotate by 13 bits (immediate)
    ret
```

Two shifts and an OR become a single `rol`. For right rotation, `(x >> n) | (x << (32 - n))` is recognized as `ror`.

### What RE should remember

Rotations are ubiquitous in cryptographic algorithms (SHA-256, ChaCha20, RC5, MD5…) and hash functions. If you see a `rol` or `ror` in a binary, it's almost certainly an algorithm using bit rotations — check Appendix J for known rotation constants to identify the algorithm.

If you're analyzing a binary compiled in `-O0` and see the `shl` + `shr` + `or` pattern, recognize it as a rotation even without the `rol`.

---

## Idiom 11 — Branchless absolute value

```c
int idiom_cmov_abs(int x)
{
    return (x < 0) ? -x : x;
}
```

### In `-O2`

GCC typically produces one of two variants.

**`neg` + `cmov` variant** (most common in recent GCC):

```asm
    mov    eax, edi                      ; eax = x
    neg    eax                           ; eax = -x (sets SF if x > 0)
    cmovs  eax, edi                     ; if -x < 0 (i.e. x > 0): eax = x
    ret
```

**Arithmetic variant** `sar` + `xor` + `sub` (seen in older GCC or when writing the pattern manually):

```c
int idiom_abs_manual(int x)
{
    int mask = x >> 31;
    return (x ^ mask) - mask;
}
```

```asm
    mov    eax, edi
    sar    eax, 31                       ; eax = 0x00000000 if x >= 0
                                         ;      = 0xFFFFFFFF if x < 0
    xor    edi, eax                      ; if x < 0: invert all bits (ones' complement)
    sub    edi, eax                      ; if x < 0: add 1 (two's complement = -x)
                                         ; if x >= 0: no effect (xor 0, sub 0)
    mov    eax, edi
    ret
```

The `sar eax, 31` produces a mask: all zeros if positive, all ones if negative. The `xor` + `sub` with this mask is the branchless equivalent of conditional negation.

### What RE should remember

Both patterns (`neg` + `cmovs` and `sar 31` + `xor` + `sub`) compute `abs(x)`. The first is more readable; the second often appears in cryptographic or DSP code where branches are prohibited.

---

## Idiom 12 — Branchless Min / Max

```c
int idiom_min(int a, int b) { return (a < b) ? a : b; }  
int idiom_max(int a, int b) { return (a > b) ? a : b; }  
unsigned int idiom_umin(unsigned int a, unsigned int b) { return (a < b) ? a : b; }  
```

### In `-O2`

```asm
idiom_min:
    cmp    edi, esi
    mov    eax, esi
    cmovl  eax, edi                     ; if a < b: eax = a, else eax = b
    ret

idiom_max:
    cmp    edi, esi
    mov    eax, esi
    cmovg  eax, edi                     ; if a > b: eax = a, else eax = b
    ret

idiom_umin:
    cmp    edi, esi
    mov    eax, esi
    cmovb  eax, edi                     ; cmovb = "below" (unsigned comparison)
    ret
```

The difference between `cmovl` (signed) and `cmovb` (unsigned) is a valuable clue in RE: it reveals whether variables are treated as `int` or `unsigned int` in the source code.

---

## Idiom 13 — Structure initialization: `rep stosq` or `mov` sequence

```c
Record r;  
memset(&r, 0, sizeof(r));  
r.id = id;  
r.type = 1;  
r.value = 3.14159;  
r.flags = 0x0F;  
```

### In `-O2`

For moderately sized structures, GCC emits a sequence of immediate `mov`s:

```asm
    ; Zeroing + field initialization
    mov    DWORD PTR [rsp],    edi       ; r.id = id
    mov    DWORD PTR [rsp+4],  1         ; r.type = 1
    movsd  xmm0, QWORD PTR [rip+.LC_pi] ; load 3.14159 from .rodata
    movsd  QWORD PTR [rsp+8], xmm0      ; r.value = 3.14159
    ; ... zeroing of name[32] fields ...
    mov    DWORD PTR [rsp+48], 0x0F      ; r.flags = 0x0F
    mov    DWORD PTR [rsp+52], 0         ; r.padding = 0
```

For larger structures (> ~128 bytes), GCC uses `rep stosq` — an instruction that fills a memory block by writing the value in `rax` `rcx` times:

```asm
    ; Zeroing a large structure (or array)
    lea    rdi, [rsp+offset]             ; destination address
    xor    eax, eax                      ; value = 0
    mov    ecx, N                        ; number of qwords (8 bytes)
    rep    stosq                          ; fill N × 8 bytes with 0
```

### What RE should remember

A sequence of `mov DWORD/QWORD PTR [rsp+offsets], constants` is a structure initialization. The offsets reveal the field layout: `[rsp+0]` is the first field, `[rsp+4]` the second if the first is 4 bytes, etc. You can reconstruct the structure by noting the offsets and sizes of stores.

The `rep stosq` indicates a `memset` (often to zero). It may come from an explicit `memset()` call or from a zero-fill loop recognized by the compiler (cf. Section 16.3).

---

## Idiom 14 — Short inline string comparison

```c
int idiom_strcmp_known(const char *input)
{
    if (strcmp(input, "OK") == 0)     return 1;
    if (strcmp(input, "FAIL") == 0)   return 2;
    if (strcmp(input, "ERROR") == 0)  return 3;
    return 0;
}
```

### In `-O2`

When the comparison string is short and known at compile time, GCC can inline the `strcmp` by loading the string as an integer and doing a numeric comparison:

```asm
    ; strcmp(input, "OK") == 0
    ; "OK" = 0x4B4F in little-endian (2 bytes + null)
    movzx  eax, WORD PTR [rdi]          ; load 2 bytes from input
    cmp    ax, 0x4B4F                    ; compare with "OK"
    jne    .L_not_ok
    cmp    BYTE PTR [rdi+2], 0          ; verify null terminator
    je     .L_return_1

.L_not_ok:
    ; strcmp(input, "FAIL") == 0
    ; "FAIL" = 0x4C494146 in little-endian (4 bytes)
    mov    eax, DWORD PTR [rdi]          ; load 4 bytes
    cmp    eax, 0x4C494146               ; compare with "FAIL"
    jne    .L_not_fail
    cmp    BYTE PTR [rdi+4], 0          ; null terminator
    je     .L_return_2
```

Instead of calling `strcmp@plt` (which loops byte by byte), GCC loads 2 or 4 bytes at once and compares them as an integer. The `cmp BYTE PTR [rdi+N], 0` verifies the string actually ends there (no continuation after the match).

### What RE should remember

When you see a `cmp eax, 0x4C494146` in a binary, don't look for a division or hash magic number — it's probably an inline string comparison. Convert the constant to ASCII (watch out for little-endian byte order): `0x4C494146` → bytes `46 41 49 4C` → "FAIL".

This pattern is very common in command parsers, simple password checkers, and network protocol state machines.

---

## Idiom 15 — Population count (popcount): `popcnt`

```c
int idiom_popcount(unsigned int x)
{
    return __builtin_popcount(x);
}
```

### With `-mpopcnt` (modern CPU)

```asm
    popcnt eax, edi                      ; count the number of 1-bits
    ret
```

A single instruction. `popcnt` has been available since Nehalem (2008) on Intel and Barcelona (2007) on AMD.

### Without `-mpopcnt` (software fallback)

GCC emits the Hamming weight calculation with characteristic magic constants:

```asm
    ; Hamming weight — recognizable constants
    mov    eax, edi
    shr    eax, 1
    and    eax, 0x55555555               ; mask: even bits
    sub    edi, eax
    mov    eax, edi
    shr    eax, 2
    and    eax, 0x33333333               ; mask: bit pairs
    and    edi, 0x33333333
    add    edi, eax
    mov    eax, edi
    shr    eax, 4
    add    eax, edi
    and    eax, 0x0F0F0F0F               ; mask: nibbles
    imul   eax, eax, 0x01010101          ; horizontal sum via multiplication
    shr    eax, 24                       ; result in top 8 bits
```

The constants `0x55555555`, `0x33333333`, `0x0F0F0F0F`, and `0x01010101` are the Hamming weight signature. If you see them together in a binary, it's a bit count.

### What RE should remember

The `popcnt` instruction or the constant sequence `0x55555555` / `0x33333333` / `0x0F0F0F0F` identify a bit count. This pattern appears in bitmap set implementations, Hamming distance calculations, compression algorithms, and certain hash functions.

---

## Idiom 16 — Sign and zero extension: `movsx` / `movzx`

```c
int idiom_sign_extend(char c) { return (int)c; }  
int idiom_zero_extend(unsigned char c) { return (int)c; }  
```

### In `-O2`

```asm
idiom_sign_extend:
    movsx  eax, dil                      ; sign-extend 8→32 bits
    ret                                   ; 0xFE → 0xFFFFFFFE (-2)

idiom_zero_extend:
    movzx  eax, dil                      ; zero-extend 8→32 bits
    ret                                   ; 0xFE → 0x000000FE (254)
```

| Instruction | Meaning | Use case |  
|---|---|---|  
| `movsx eax, dil` | Sign-extend 8→32 | Cast `char` → `int` |  
| `movsx eax, di` | Sign-extend 16→32 | Cast `short` → `int` |  
| `movsxd rax, edi` | Sign-extend 32→64 | Cast `int` → `long` |  
| `movzx eax, dil` | Zero-extend 8→32 | Cast `unsigned char` → `int` |  
| `movzx eax, di` | Zero-extend 16→32 | Cast `unsigned short` → `int` |

The choice between `movsx` and `movzx` reveals whether the source type is signed or unsigned in the C code — this is valuable typing information in RE.

### What RE should remember

`movsx` = signed source type (`char`, `short`, `int`). `movzx` = unsigned source type (`unsigned char`, `unsigned short`). A `movsxd rax, edi` indicates an `int` → `long` conversion (32→64 bits), often seen before an indexed access to a 64-bit array.

---

## Recap: quick reference card

| Assembly pattern | Idiom | Corresponding C code |  
|---|---|---|  
| `imul edx, MAGIC` + `sar edx, S` + sign correction | Division by constant | `x / N` |  
| `and eax, (2^n - 1)` | Power-of-2 modulo | `x % 2^n` (unsigned) |  
| magic number + `imul` + `sub` | Non-power-of-2 modulo | `x % N` |  
| `lea [rdi+rdi*{2,4,8}]` | Small constant multiplication | `x * {3,5,9}` |  
| `cmp` + `cmovCC` | Eliminated branch | `(cond) ? a : b`, `min`, `max`, `abs` |  
| `test reg, mask` + `jz`/`setnz` | Bit test | `if (flags & BIT)` |  
| `test`/`cmp` + `setCC` + `movzx` | Boolean normalization | `!!x`, `a == b`, `a < b` |  
| `lea` + `movsxd [table+idx*4]` + `jmp rax` | Jump table (dense switch) | `switch (x) { case 0..N: }` |  
| Tree of `cmp`/`je`/`jg` | Sparse switch | `switch (x) { case 1, 42, 1000: }` |  
| `rol eax, N` / `ror eax, N` | Bit rotation | `(x << n) \| (x >> (32-n))` |  
| `neg` + `cmovs` or `sar 31` + `xor` + `sub` | Absolute value | `abs(x)` |  
| `cmp` + `cmovl`/`cmovg` | Min / Max | `min(a,b)`, `max(a,b)` |  
| `mov [rsp+off], imm` sequence | Structure initialization | `struct s = {...}` |  
| `cmp eax, 0xASCII` + `cmp byte [rdi+N], 0` | Inline strcmp | `strcmp(s, "short")` |  
| `popcnt` or `0x55555555`/`0x33333333` | Bit count | `__builtin_popcount(x)` |  
| `movsx` / `movzx` | Type extension | Cast `char→int`, `short→int` |

---

## Tips for daily RE practice

**Build your muscle memory.** The more binaries you analyze, the more automatic these patterns become. The first `0x92492493` you encounter is mysterious; after seeing ten, you identify them instantly as a division by 7.

**Let the decompiler do the work when possible.** Ghidra recognizes most of these idioms and translates them into readable C in the decompiler. But the decompiler can be wrong — direct disassembly reading remains the fundamental skill.

**Watch out for GCC version.** Exact patterns vary between GCC versions. An `abs()` might be `neg` + `cmovs` on GCC 12 and `sar` + `xor` + `sub` on GCC 8. The source code is the same, but the assembly differs. Compiler Explorer ([godbolt.org](https://godbolt.org)) lets you verify the pattern for a specific version.

**Document your discoveries.** The tutorial's Appendix I provides an extended reference table of GCC patterns. Enrich it with your own observations as you analyze.

---


⏭️ [GCC vs Clang comparison: assembly pattern differences](/16-compiler-optimizations/07-gcc-vs-clang.md)
