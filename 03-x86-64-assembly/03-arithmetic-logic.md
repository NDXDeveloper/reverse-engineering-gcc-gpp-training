🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.3 — Arithmetic and logic: `add`, `sub`, `imul`, `xor`, `shl`/`shr`, `test`, `cmp`

> 🎯 **Goal of this section**: know how to recognize and interpret arithmetic and logic operations in disassembled code, including GCC's common idioms that use these instructions in unexpected ways (multiplication disguised as a shift, `xor` to zero out, `test` to check for nullity…).

---

## The common principle

All the instructions in this section share two fundamental characteristics:

1. **They operate on one or two operands** in the form `op destination, source`, where the result replaces the destination (except for `cmp` and `test`, which store nothing).  
2. **They update the `RFLAGS` register** — that is what allows conditional jumps (section 3.4) to make their decisions right afterwards.

This link between arithmetic/logic instruction and flags is the central mechanism of all control flow in x86-64 assembly. Every `if`, every loop, every condition of the C code goes through this pair: an instruction that sets the flags, followed by a jump that reads them.

---

## Arithmetic instructions

### `add` — addition

```
add  destination, source      ; destination = destination + source
```

`add` adds the source to the destination and stores the result in the destination. The ZF, SF, CF, and OF flags are updated.

```asm
add     eax, 1                ; eax = eax + 1  (increment)  
add     eax, esi              ; eax = eax + esi  
add     dword [rbp-0x4], 1    ; directly increments a variable in memory  
add     rsp, 0x30             ; frees 48 bytes of stack (epilogue)  
```

C correspondence:

```c
x += 1;       // →  add  dword [rbp-0x4], 1  
total += val;  // →  add  eax, ecx  
```

> 💡 **For RE**: `add rsp, N` at the end of a function is the counterpart of `sub rsp, N` in the prologue — it frees the space reserved for local variables. If you see `add rsp, 0x28` in an epilogue, the function had reserved 40 bytes of stack.

### `sub` — subtraction

```
sub  destination, source      ; destination = destination - source
```

Same principle as `add`, but for subtraction. Flags are updated, and that is exactly what makes `sub` and `cmp` so close (more on that below).

```asm
sub     eax, 1                ; eax = eax - 1  (decrement)  
sub     eax, ecx              ; eax = eax - ecx  
sub     rsp, 0x20             ; reserves 32 bytes on the stack (prologue)  
```

C correspondence:

```c
count--;          // →  sub  dword [rbp-0x4], 1  
diff = a - b;     // →  mov eax, edi  /  sub eax, esi  
```

### `inc` and `dec` — increment and decrement

```asm
inc     eax               ; eax = eax + 1  
dec     dword [rbp-0x4]   ; local_variable -= 1  
```

`inc` and `dec` are shortcuts for `add X, 1` and `sub X, 1`. They update ZF, SF, and OF but **not CF** — a subtlety that has no impact in day-to-day RE, but explains why GCC sometimes prefers `add reg, 1` to `inc reg` when the carry flag is needed.

In practice, modern GCC uses `add`/`sub` rather than `inc`/`dec` in most cases, but you will encounter both forms.

### `neg` — negation (two's complement)

```asm
neg     eax               ; eax = -eax
```

`neg` computes the two's complement of the operand — it is the translation of C's unary `-` operator. You see it in expressions like `result = -value` or in certain optimizations where GCC turns a subtraction into a negation followed by an addition.

### `imul` — signed multiplication

Multiplication is more complex than addition because the result of multiplying two 32-bit values can require 64 bits. The x86-64 architecture offers several forms of `imul`:

**Two-operand form** (the most common in GCC code):

```asm
imul    eax, ecx           ; eax = eax * ecx   (32-bit × 32-bit, result truncated to 32-bit)  
imul    rax, rdx           ; rax = rax * rdx   (64-bit × 64-bit, truncated to 64-bit)  
```

**Three-operand form** (multiplication with immediate):

```asm
imul    eax, ecx, 0xc      ; eax = ecx * 12  
imul    eax, edi, 0x64     ; eax = edi * 100  
```

This form is the direct translation of `result = value * constant` in C.

**One-operand form** (full multiplication):

```asm
imul    ecx                ; edx:eax = eax * ecx (full 64 bits in edx:eax)
```

This form stores the high 32 bits in `edx` and the low 32 bits in `eax`. You rarely see it in application code, but it appears when the compiler needs the full result (for example for a subsequent division or computation on wide integers).

C correspondence:

```c
area = width * height;     // →  imul  eax, ecx  
cost = qty * 12;           // →  imul  eax, edi, 0xc  
```

> 💡 **For RE**: `imul` is the *signed* multiplication. For *unsigned* multiplication, the processor uses `mul`, but GCC uses almost exclusively `imul` in its two- or three-operand form, because the truncated result is identical for both (the signed/unsigned distinction only matters for the upper bits of the full result).

### `div` and `idiv` — division

x86-64 division is the most "exotic" operation for a C developer used to a simple `/`. It uses a rigid protocol involving the `rax` and `rdx` registers:

**Unsigned division (`div`)**:

```asm
; 32-bit division: edx:eax / ecx → quotient in eax, remainder in edx
xor     edx, edx           ; sets edx to 0 (unsigned extension)  
div     ecx                 ; eax = edx:eax / ecx, edx = edx:eax % ecx  
```

**Signed division (`idiv`)**:

```asm
; 32-bit signed division: edx:eax / ecx → quotient in eax, remainder in edx
cdq                          ; sign-extends eax into edx  
idiv    ecx                  ; eax = quotient, edx = remainder  
```

The `cdq` (*Convert Doubleword to Quadword*) instruction is the signal of an imminent signed division — it propagates the sign bit of `eax` into all the bits of `edx`. Its 64-bit equivalent is `cqo` (extends `rax` into `rdx`).

C correspondence:

```c
int q = a / b;     // →  cdq  /  idiv ecx     → result in eax  
int r = a % b;     // →  same sequence         → remainder in edx  
```

> 💡 **For RE**: when you see `cdq` or `cqo` followed by an `idiv`, it is a signed division. When you see `xor edx, edx` followed by `div`, it is an unsigned division. The quotient is in `eax`/`rax`, the remainder in `edx`/`rdx` — so if the code uses `edx` after the `div`/`idiv`, it is C's `%` (modulo) operator.

### When GCC avoids `div`: magic multiplication

Division is the processor's slowest instruction (dozens of cycles). GCC systematically avoids it when the divisor is a **compile-time constant**, by replacing it with a sequence of multiplication and shifts. It is an extremely frequent idiom at `-O1` and above:

```c
// C code
int f(int x) {
    return x / 3;
}
```

```asm
; GCC -O2 — no div in sight!
mov     eax, edi  
mov     edx, 0x55555556       ; magic constant ≈ (2^32 + 2) / 3  
imul    edx                    ; edx:eax = eax * 0x55555556  
mov     eax, edx               ; eax = high bits of result  
shr     eax, 0x1f              ; extracts the sign bit (adjustment for negatives)  
add     eax, edx               ; final adjustment  
```

This pattern is confusing the first time, but it is mechanical. The "magic constant" is the modular multiplicative inverse of the divisor. Chapter 16 details these optimizations — for now, remember the following rule:

> ⚠️ **Recognition rule**: if you see an `imul` with a large hexadecimal constant (like `0x55555556`, `0xAAAAAAAB`, `0xCCCCCCCD`…) followed by shifts (`shr`, `sar`) and possibly adjustments, it is almost certainly a **division by a constant** that GCC has optimized. The absence of `div`/`idiv` is normal — it is the compiler's default behavior in optimized mode.

---

## Bitwise logical instructions

### `and` — logical AND

```asm
and     eax, 0xff          ; eax = eax & 0xFF (mask: keeps the low byte)  
and     eax, ecx           ; eax = eax & ecx  
```

The AND operation sets each bit of the result to 1 only if both corresponding bits of the operands are 1.

C correspondence:

```c
masked = value & 0xFF;    // →  and  eax, 0xff  
flags &= MASK;            // →  and  eax, ecx  
```

Common uses in GCC code:

- **Bit masking**: `and eax, 0xff` isolates the low byte (equivalent to a cast to `unsigned char`).  
- **Alignment**: `and rsp, 0xfffffffffffffff0` aligns `rsp` on 16 bytes — very frequent in `main()`'s prologue or in functions using SSE instructions that require alignment.  
- **Bit parity test**: `and eax, 1` tests whether a number is even or odd (optimized `n % 2`).

### `or` — logical OR

```asm
or      eax, 0x1           ; sets bit 0 to 1  (eax |= 1)  
or      eax, ecx           ; eax = eax | ecx  
```

Each bit of the result is 1 if at least one of the two corresponding bits is 1.

C correspondence:

```c
flags |= FLAG_ACTIVE;     // →  or  eax, 0x4
```

One special case to note: `or reg, reg` does not change the register's value but updates the flags — it is a (rare) alternative to `test reg, reg` for testing nullity.

### `xor` — exclusive OR

```asm
xor     eax, eax           ; eax = 0  (the most famous x86 idiom)  
xor     eax, ecx           ; eax = eax ^ ecx  
xor     byte [rdi], 0x42   ; byte-by-byte XOR decryption  
```

XOR sets each bit to 1 if the two corresponding bits are **different**, and to 0 if they are identical. Fundamental property: `A XOR A = 0` for any value A.

**The `xor reg, reg` idiom** is GCC's standard method for zeroing a register. It is preferred over `mov reg, 0` because the encoding is shorter (2 bytes versus 5 for `mov eax, 0`) and modern processors recognize this pattern as a *zeroing idiom* that breaks data dependencies.

```asm
xor     eax, eax       ; 2 bytes, breaks dependencies — GCC's preference  
mov     eax, 0          ; 5 bytes, functionally identical but longer  
```

> 💡 **For RE**: when you see `xor eax, eax` at the start of a function or before a `call`, it is simply a zeroing. Do not look for cryptographic XOR. In contrast, an `xor` with a *different* register or a non-zero constant is a real logical operation — potentially a simple XOR cipher (Chapter 24) or a hash computation.

**XOR in the crypto context**:

```asm
; Typical XOR decryption loop
.loop:
    xor     byte [rdi+rcx], 0x42    ; decrypts the current byte with key 0x42
    inc     rcx
    cmp     rcx, rax
    jl      .loop
```

This pattern — a loop that XORs each byte of a buffer with a constant — is the most basic form of encryption/obfuscation. It shows up in simple malware and CTFs (Chapters 24 and 27).

### `not` — bitwise complement

```asm
not     eax               ; eax = ~eax (inverts all bits)
```

It is the translation of C's `~` operator. Less frequent than the other logical operations, but you encounter it in mask calculations and in certain optimizations.

---

## Shift instructions

Shifts move the bits of a register to the left or right. They are omnipresent in optimized code because **a left shift by N positions is equivalent to a multiplication by 2ᴺ**, and **a right shift by N positions is equivalent to a division by 2ᴺ** — infinitely faster operations than `imul` or `div`.

### `shl` / `sal` — left shift (*Shift Left*)

```asm
shl     eax, 1            ; eax = eax << 1   (× 2)  
shl     eax, 3            ; eax = eax << 3   (× 8)  
shl     eax, cl           ; eax = eax << cl  (variable shift)  
```

The bits leaving on the left are lost (the last bit out goes into CF). Zeros are inserted on the right. `shl` and `sal` are synonyms — behavior is identical.

C correspondence:

```c
x <<= 3;           // →  shl  eax, 3  
x *= 8;            // →  shl  eax, 3    (GCC optimizes automatically)  
```

### `shr` — logical right shift (*Shift Right*)

```asm
shr     eax, 1            ; eax = eax >> 1  (÷ 2, unsigned)  
shr     eax, 4            ; eax = eax >> 4  (÷ 16, unsigned)  
```

Zeros are inserted on the left. This is the shift for **unsigned** values.

### `sar` — arithmetic right shift (*Shift Arithmetic Right*)

```asm
sar     eax, 1            ; eax = eax >> 1  (÷ 2, signed — preserves sign)  
sar     eax, 0x1f         ; extracts the sign bit (0 if positive, -1 if negative)  
```

The sign bit (most significant bit) is replicated on the left. This is the shift for **signed** values — it preserves the number's sign.

> 💡 **For RE**: the `shr` vs `sar` distinction reveals the variable's signedness. If GCC uses `shr`, the variable is `unsigned`. If it uses `sar`, it is `signed` (or the compiler treats the value as signed in this context). It is a precious clue for reconstructing types.

### The `shr reg, 0x1f` (or `sar reg, 0x1f`) pattern

This pattern extracts the sign bit of a 32-bit value:

```asm
sar     eax, 0x1f          ; eax = 0x00000000 if positive, 0xFFFFFFFF if negative
```

You see it in division-by-constant sequences (adjustment for negative numbers) and in absolute-value calculations. Do not mistake it for a division by 2³¹.

### Multiplications and divisions by powers of 2

GCC systematically replaces multiplications and divisions by powers of 2 with shifts:

| C operation | GCC instruction | Equivalent |  
|---|---|---|  
| `x * 2` | `shl eax, 1` or `add eax, eax` | Left shift by 1 |  
| `x * 4` | `shl eax, 2` | Left shift by 2 |  
| `x * 8` | `shl eax, 3` | Left shift by 3 |  
| `x / 2` (unsigned) | `shr eax, 1` | Logical right shift by 1 |  
| `x / 4` (signed) | `sar eax, 2` (+ adjustment) | Arithmetic right shift |  
| `x % 4` (unsigned) | `and eax, 3` | Low bits mask |

Replacing `x % power_of_2` with `and eax, (power - 1)` is particularly common. For example, `n % 16` becomes `and eax, 0xf` — it is instantaneous whereas `div` would cost dozens of cycles.

> ⚠️ **Pitfall**: signed division by a power of 2 is not a simple `sar`. For negative numbers, C rounds toward zero, whereas `sar` rounds toward -∞. GCC therefore inserts an adjustment:  
>  
> ```asm  
> ; x / 4 (signed)  
> mov     eax, edi  
> sar     eax, 0x1f        ; eax = sign bit extended (0 or -1)  
> shr     eax, 0x1e        ; eax = 0 if positive, 3 if negative (adjustment)  
> add     eax, edi          ; adds the adjustment to x  
> sar     eax, 2            ; arithmetic shift of 2  
> ```  
>  
> This pattern is mechanical and recognizable once you've seen it once.

---

## Comparison instructions

### `cmp` — comparison (subtraction without a result)

```
cmp  operand1, operand2     ; computes operand1 - operand2, updates flags, discards result
```

`cmp` is fundamentally identical to `sub`, with one difference: **the subtraction result is discarded**. Only the flags are affected. It is the instruction that almost always precedes a conditional jump.

```asm
cmp     eax, 0x2a              ; compares eax with 42  
jz      .equal                  ; jumps if eax == 42 (ZF = 1)  

cmp     dword [rbp-0x4], 0     ; compares a local variable with 0  
jle     .negative_or_zero       ; jumps if var <= 0  

cmp     rdi, rsi               ; compares two pointers  
je      .same_pointer           ; jumps if they are equal  
```

The `cmp` + conditional-jump pair reads naturally as an `if` in C:

| Assembly | C condition |  
|---|---|  
| `cmp eax, ebx` / `je .L` | `if (a == b)` |  
| `cmp eax, ebx` / `jne .L` | `if (a != b)` |  
| `cmp eax, ebx` / `jl .L` | `if (a < b)` — signed |  
| `cmp eax, ebx` / `jge .L` | `if (a >= b)` — signed |  
| `cmp eax, ebx` / `jb .L` | `if (a < b)` — unsigned |  
| `cmp eax, ebx` / `jae .L` | `if (a >= b)` — unsigned |

The full table of conditional jumps is in section 3.4.

### `test` — logical AND without result

```
test  operand1, operand2    ; computes operand1 AND operand2, updates flags, discards result
```

`test` is to `and` what `cmp` is to `sub`: it performs a logical AND, updates the flags, but does not store the result. Its two dominant uses:

**Use 1 — Testing whether a register is zero**

```asm
test    rax, rax           ; rax AND rax = rax → ZF = 1 if rax == 0  
jz      .is_null            ; jumps if rax is NULL  
```

It is GCC's standard idiom for `if (ptr == NULL)` or `if (value == 0)`. You also see it as `test eax, eax` for 32-bit values.

Why `test rax, rax` rather than `cmp rax, 0`? Both give the same result on ZF, but `test` has a shorter encoding (no immediate to encode) and the processor handles it more efficiently.

**Use 2 — Testing a specific bit**

```asm
test    eax, 0x1           ; tests bit 0 (parity)  
jnz     .is_odd             ; jumps if bit 0 is 1 → odd number  

test    eax, 0x4           ; tests bit 2  
jz      .flag_not_set       ; jumps if bit 2 is 0  
```

C correspondence:

```c
if (n % 2 != 0)        // →  test eax, 0x1  /  jnz  
if (flags & FLAG_X)    // →  test eax, FLAG_X  /  jnz  
```

> 💡 **For RE**: distinguishing `cmp` and `test` is important for understanding the nature of the comparison. `cmp` compares *values* (equality, ordering…). `test` checks *bits* (nullity, flag presence, parity). Both precede conditional jumps, but the semantics differ.

---

## Summary: the flags modified by each instruction

All arithmetic and logic instructions modify the flags, but not all in the same way. This table summarizes the behavior for the instructions in this section:

| Instruction | ZF | SF | CF | OF | Note |  
|---|---|---|---|---|---|  
| `add`, `sub` | ✓ | ✓ | ✓ | ✓ | All arithmetic flags |  
| `inc`, `dec` | ✓ | ✓ | — | ✓ | CF **not modified** |  
| `imul` (2/3 op.) | — | — | ✓ | ✓ | ZF and SF undefined |  
| `div`, `idiv` | — | — | — | — | All flags **undefined** |  
| `and`, `or`, `xor` | ✓ | ✓ | 0 | 0 | CF and OF always cleared |  
| `shl`, `shr`, `sar` | ✓ | ✓ | ✓ | * | OF defined only for shift of 1 |  
| `cmp` | ✓ | ✓ | ✓ | ✓ | Identical to `sub` |  
| `test` | ✓ | ✓ | 0 | 0 | Identical to `and` |  
| `neg` | ✓ | ✓ | ✓ | ✓ | CF = 1 unless operand = 0 |  
| `not` | — | — | — | — | **No** flag modified |

In everyday RE, you do not need to memorize this table. Just remember that **`cmp` and `test` are the two "official" instructions for setting flags before a jump**, and that standard arithmetic operations (`add`, `sub`) do it too — which explains why GCC sometimes omits the `cmp` when a preceding `sub` has already set the right flags.

---

## GCC idioms to recognize

GCC produces recurring sequences that, out of context, may seem cryptic. Here are the most frequent ones involving the instructions in this section:

### Zeroing

```asm
xor     eax, eax               ; eax = 0 (and rax = 0 by extension)
```

Always preferred over `mov eax, 0`. It is *the* most common x86 pattern.

### Nullity test

```asm
test    rax, rax                ; sets ZF depending on whether rax is zero
```

Always preferred over `cmp rax, 0`.

### Multiplication by small constant (without `imul`)

GCC combines `lea`, `add`, and `shl` for small multipliers:

| C operation | Typical GCC code |  
|---|---|  
| `x * 2` | `add eax, eax` or `shl eax, 1` |  
| `x * 3` | `lea eax, [rdi+rdi*2]` |  
| `x * 5` | `lea eax, [rdi+rdi*4]` |  
| `x * 9` | `lea eax, [rdi+rdi*8]` |  
| `x * 6` | `lea eax, [rdi+rdi*2]` then `add eax, eax` |  
| `x * 7` | `lea eax, [rdi*8]` then `sub eax, edi` |  
| `x * 10` | `lea eax, [rdi+rdi*4]` then `add eax, eax` |

These combinations exploit the `lea` with scale (×2, ×4, ×8) seen in section 3.2, chained with additions or shifts. GCC prefers them over `imul` because they avoid using the multiplication unit, and modern processors execute `lea` and `add` with a 1-cycle latency.

### Division by constant (the "magic multiplication")

Summary of the pattern seen above — the most frequent magic constants:

| Divisor | Magic constant (`imul`) | Shift after |  
|---|---|---|  
| 3 | `0x55555556` | `shr 0` or sign adjustment |  
| 5 | `0x66666667` | `sar 1` |  
| 7 | `0x92492493` | `sar 2` + adjustment |  
| 10 | `0x66666667` | `sar 2` |  
| 100 | `0x51EB851F` | `sar 5` |

When you spot one of these constants in an `imul`, you can directly deduce the original divisor.

### Branchless absolute value

```asm
; abs(eax)
mov     edx, eax  
sar     edx, 0x1f        ; edx = 0 if positive, -1 if negative  
xor     eax, edx          ; inverts all bits if negative  
sub     eax, edx          ; +1 if negative (completes the two's complement)  
```

This pattern computes `abs(x)` without any branching, exploiting the properties of two's complement and XOR. If `x` is positive, `edx` is 0, `xor` and `sub` do nothing. If `x` is negative, `edx` is -1 (`0xFFFFFFFF`), `xor` inverts all the bits, and `sub` adds 1 — which gives exactly `-x`.

---

## What to remember going forward

1. **`add`/`sub`** are the basic operations — they modify the flags and also implicitly serve as comparisons.  
2. **`imul`** in two- or three-operand form is GCC's standard multiplication form — `mul` is rare.  
3. **`div`/`idiv`** are slow, and GCC replaces them with "magic multiplications" starting at `-O1` — recognizing the magic constants is an essential RE skill.  
4. **`xor eax, eax`** = zeroing, **`test reg, reg`** = nullity test — these are idioms, not cryptographic logic.  
5. **`shl`/`shr`/`sar`** replace multiplications and divisions by powers of 2 — `shr` indicates an unsigned type, `sar` a signed type.  
6. **`cmp`** sets flags for a value comparison, **`test`** for bit checking — both precede conditional jumps (section 3.4).  
7. **GCC's instruction choice reveals the type**: `shr` vs `sar` → unsigned vs signed, `movzx` vs `movsx` → unsigned vs signed, `jb`/`ja` vs `jl`/`jg` → unsigned vs signed comparison.

---


⏭️ [Conditional and unconditional jumps: `jmp`, `jz`/`jnz`, `jl`, `jge`, `jle`, `ja`…](/03-x86-64-assembly/04-conditional-jumps.md)
