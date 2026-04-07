🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.4 — Understanding Conditional Jumps (`jz`/`jnz`) in the Crackme Context

> 📖 **Reminder**: x86-64 conditional and unconditional jumps were presented in chapter 3 (section 3.4). This section focuses on their specific role in a crackme and on the reading pitfalls they pose to the reverse engineer.

---

## Introduction

Section 21.3 located two critical conditional jumps: a `JZ` in `main` (after the call to `check_license`) and a `JNE` in `check_license` (after the call to `strcmp`). These few-byte instructions are the central mechanism of any crackme: they materialize, in machine language, the question "is the key valid?"

Understanding precisely *why* the processor takes or does not take a jump means understanding the program's logic. This section dissects the mechanics of conditional jumps in the concrete context of our keygenme, tracing from C code down to processor flags.

---

## From C to flags: the complete chain

To grasp how a conditional jump works, you need to understand the three links in the chain:

```
C code (logical condition)
    ↓  GCC compilation
Test instruction (TEST, CMP)  →  sets flags in RFLAGS
    ↓  immediately after
Jump instruction (Jcc)        →  reads one or more flags to decide
```

The processor does not "understand" C conditions. It does not know what an `if` or `==` is. It only knows **flags** — individual bits in the `RFLAGS` register — that are set by certain arithmetic and logical instructions, then read by conditional jump instructions.

### The relevant flags

Among the roughly twenty flags in `RFLAGS`, three are ubiquitous in crackme analysis:

| Flag | Name | Set to 1 when... |  
|---|---|---|  
| **ZF** | Zero Flag | The result of the last operation is zero |  
| **SF** | Sign Flag | The result of the last operation is negative (most significant bit = 1) |  
| **CF** | Carry Flag | A carry occurred (unsigned overflow) |

For our keygenme, only the **Zero Flag (ZF)** is involved. The `JZ` and `JNZ` jumps (and their aliases `JE`/`JNE`) exclusively test this flag.

---

## First decision point: `strcmp` in `check_license`

### The original C code

```c
if (strcmp(expected, user_key) == 0) {
    return 1;
}
return 0;
```

The `strcmp` function returns:
- **0** if the two strings are identical.  
- A **positive** value if the first string is lexicographically greater.  
- A **negative** value if the first string is lexicographically lesser.

The `== 0` in the C code tests string equality. Let's see how GCC translates this.

### The assembly translation

```nasm
CALL    strcmp@plt          ; return in EAX  
TEST    EAX, EAX           ; EAX AND EAX → sets ZF  
JNE     .return_zero        ; if ZF = 0 (EAX ≠ 0) → jump to failure  
```

#### `CALL strcmp@plt`

The call to `strcmp` places its result in `EAX` (System V AMD64 convention: the integer return value is in `RAX`/`EAX`). After this call:
- If the strings are identical: `EAX = 0`.  
- Otherwise: `EAX ≠ 0` (positive or negative value).

#### `TEST EAX, EAX`

The `TEST` instruction performs a **logical AND** between its two operands without storing the result — it only modifies the flags. When both operands are the same register (`TEST EAX, EAX`), the operation amounts to `EAX & EAX`, which gives... `EAX` itself. The interest is not in the result (which is discarded) but in the effect on flags:

- If `EAX = 0`: the AND result is 0 → **ZF = 1**.  
- If `EAX ≠ 0`: the AND result is non-zero → **ZF = 0**.

`TEST EAX, EAX` is GCC's standard idiom for testing whether a register is zero. It is encountered in virtually every GCC-compiled binary. It is the machine equivalent of the question "is this value zero?"

> 💡 **Why `TEST` and not `CMP EAX, 0`?** Both would set the flags in the same way. But `TEST EAX, EAX` is encoded in 2 bytes (`85 C0`) while `CMP EAX, 0` requires 5 (`83 F8 00` or more). GCC always prefers the most compact form. The reverse engineer must recognize both forms as semantically identical.

#### `JNE .return_zero`

`JNE` (Jump if Not Equal) is an alias for `JNZ` (Jump if Not Zero). Both mnemonics designate the same opcode (`0x75` for the short form). The instruction jumps if **ZF = 0**.

Combining:

| `EAX` (`strcmp` return) | Meaning | `TEST EAX, EAX` → ZF | `JNE` taken? | Consequence |  
|---|---|---|---|---|  
| `0` | Strings identical | ZF = 1 | **No** (continues) | → `return 1` (success) |  
| `≠ 0` | Strings different | ZF = 0 | **Yes** (jumps) | → `return 0` (failure) |

The jump is taken when the key is **wrong**. When the key is **correct**, execution falls through sequentially into the success path.

---

## Second decision point: `check_license` in `main`

### The original C code

```c
if (check_license(username, user_key)) {
    printf(MSG_OK, username);
    return EXIT_SUCCESS;
} else {
    printf(MSG_FAIL);
    return EXIT_FAILURE;
}
```

In C, the condition `if (check_license(...))` is true when the return value is **non-zero** (C convention: any non-zero integer is "true").

### The assembly translation

```nasm
CALL    check_license       ; return in EAX  
TEST    EAX, EAX            ; sets ZF  
JZ      .label_fail          ; if ZF = 1 (EAX = 0) → jump to failure  
```

Here, it is a `JZ` (Jump if Zero, alias `JE`) — the opposite of the `JNE` in `check_license`. The jump is taken when `EAX = 0`, i.e., when `check_license` returned 0 (invalid key).

| `EAX` (`check_license` return) | Meaning | `TEST EAX, EAX` → ZF | `JZ` taken? | Consequence |  
|---|---|---|---|---|  
| `1` | Valid key | ZF = 0 | **No** (continues) | → `printf(MSG_OK)` |  
| `0` | Invalid key | ZF = 1 | **Yes** (jumps) | → `printf(MSG_FAIL)` |

---

## The two jumps face to face

Let's place the two decision points side by side to clearly visualize their articulation:

```
┌──────────────────────────────────────────────────────────┐
│                    check_license()                       │
│                                                          │
│    CALL strcmp@plt                                       │
│    TEST EAX, EAX                                         │
│    JNE  .return_zero     ←── jump taken if key is WRONG  │
│    MOV  EAX, 1           ←── key correct: return 1       │
│    JMP  .epilogue                                        │
│  .return_zero:                                           │
│    MOV  EAX, 0           ←── key wrong: return 0         │
│  .epilogue:                                              │
│    ... (canary check)                                    │
│    RET                                                   │
└──────────────────────────────────────────────────────────┘
                          │
                    return to main
                          ▼
┌──────────────────────────────────────────────────────────┐
│                        main()                            │
│                                                          │
│    CALL check_license                                    │
│    TEST EAX, EAX                                         │
│    JZ   .label_fail      ←── jump taken if EAX = 0       │
│    ... printf(MSG_OK)    ←── success path                │
│    JMP  .end                                             │
│  .label_fail:                                            │
│    ... printf(MSG_FAIL)  ←── failure path                │
│  .end:                                                   │
│    ...                                                   │
│    RET                                                   │
└──────────────────────────────────────────────────────────┘
```

The sequence is crystal clear:
1. `strcmp` returns 0 → `JNE` is **not** taken → `check_license` returns 1.  
2. `check_license` returns 1 → `JZ` is **not** taken → the success message is displayed.

In both cases, the **success** path is the **sequential** path (no jump). The **failure** path is where the jump is taken. This is an extremely common pattern in GCC binaries: the compiler places the "normal" or "expected" case in sequential flow and the "exceptional" case as the jump target. Knowing this convention facilitates quick reading of disassembly.

---

## The `JE`/`JNE` vs `JZ`/`JNZ` aliases

Browsing different tools, you will encounter `JZ` or `JE`, `JNZ` or `JNE` interchangeably. These are **exact aliases** for the same opcode:

| Opcode | Alias 1 | Alias 2 | Condition | Flag tested |  
|---|---|---|---|---|  
| `0x74` (short) / `0x0F 0x84` (near) | `JZ` (Jump if Zero) | `JE` (Jump if Equal) | ZF = 1 | ZF |  
| `0x75` (short) / `0x0F 0x85` (near) | `JNZ` (Jump if Not Zero) | `JNE` (Jump if Not Equal) | ZF = 0 | ZF |

The alias choice depends on the disassembler:
- **`objdump`** uses `je`/`jne` by default.  
- **Ghidra** uses `JZ`/`JNZ` in some versions and `JE`/`JNE` in others.  
- **IDA** uses `jz`/`jnz`.  
- **Radare2** uses `je`/`jne`.

Regardless of the spelling, the behavior is identical. The reverse engineer must mentally associate both forms without hesitation.

---

## `CMP` vs `TEST`: two ways to prepare a jump

Our keygenme uses `TEST EAX, EAX` before jumps, but `CMP` is frequently encountered in other binaries. Both instructions set flags, but not in the same way.

### `TEST A, B` — logical AND without storage

```nasm
TEST    EAX, EAX     ; computes EAX & EAX, sets ZF, discards result
```

Primary use: **testing whether a register is zero** (when A = B).

### `CMP A, B` — subtraction without storage

```nasm
CMP     EAX, 0x5     ; computes EAX - 5, sets ZF/SF/CF, discards result
```

Primary use: **comparing two values**. After `CMP A, B`:
- `JE` / `JZ`: jump if A = B (subtraction result = 0 → ZF = 1).  
- `JNE` / `JNZ`: jump if A ≠ B.  
- `JL` / `JNGE`: jump if A < B (signed comparison).  
- `JG` / `JNLE`: jump if A > B (signed comparison).  
- `JB` / `JNAE`: jump if A < B (unsigned comparison).  
- `JA` / `JNBE`: jump if A > B (unsigned comparison).

### In our keygenme

GCC uses `TEST EAX, EAX` because the C condition is a simple zero test (`== 0` or boolean value). If the C code contained a comparison against a non-zero constant (for example `if (result == 42)`), GCC would use `CMP EAX, 0x2A` followed by `JE`/`JNE`.

> 💡 **Rule of thumb**: when you see `TEST reg, reg` → the C code tests whether the variable is zero or non-zero. When you see `CMP reg, imm` → the C code compares against a specific value. This correspondence allows mentally reconstructing the original `if`.

---

## Variants depending on optimization level

The `TEST`/`Jcc` pair we analyzed is typical of `-O0`. At higher optimization levels, GCC may reorganize the code significantly.

### At `-O2`: fusion and inversion

GCC at `-O2` may fuse the `strcmp` call and the test into more compact code:

```nasm
CALL    strcmp@plt  
TEST    EAX, EAX  
SETE    AL              ; AL = 1 if ZF=1 (strings equal), 0 otherwise  
MOVZX   EAX, AL         ; zero-extend to 32 bits  
RET  
```

Here, the compiler has replaced the `JNE` branch + two paths `MOV EAX, 1`/`MOV EAX, 0` with a `SETE` instruction (Set byte if Equal) that directly produces the 0 or 1 result without a jump. The code is shorter, branchless, and therefore faster — but less readable for the RE beginner.

The `SETE` instruction (and its variants `SETNE`, `SETL`, `SETG`...) is a frequent pattern at `-O2`/`-O3`. It replaces a conditional branch with a conditional assignment. The reverse engineer must recognize it as the equivalent of:

```c
return (strcmp(expected, user_key) == 0) ? 1 : 0;
// or simply:
return strcmp(expected, user_key) == 0;
```

### At `-O2`: inlining of `check_license`

If GCC decides to inline `check_license` into `main`, the boundary between the two functions disappears. You end up with a single code block in `main` that chains `compute_hash` → `derive_key` → `format_key` → `strcmp` → `TEST`/`JZ`. The logic is the same, but there is no longer a `CALL check_license` to spot. You must then rely on the remaining calls (`strcmp@plt` is not inlinable since it is part of libc) and character strings to locate the decision point.

### At `-O3`: CMOV (conditional move)

At aggressive optimization levels, GCC may use `CMOVZ`/`CMOVNZ` (Conditional Move) to completely avoid branches:

```nasm
CALL    strcmp@plt  
XOR     ECX, ECX         ; ECX = 0  
TEST    EAX, EAX  
MOV     EAX, 0x1  
CMOVNE  EAX, ECX         ; if strcmp ≠ 0, EAX ← 0  
RET  
```

There is no conditional jump in this code — the return value is computed linearly. This is more performant (no branch misprediction), but there is no longer a `JZ`/`JNE` to invert for a patch. You would need to patch the `CMOVNE` to `NOP` or modify the logic otherwise. We will see adapted patching techniques in section 21.6.

---

## Classic pitfall: confusing the jump direction

The most frequent pitfall for beginners is **confusing "the jump leads to success" with "the jump leads to failure"**. The only way to avoid mistakes is to read the complete context:

1. Identify what happens **if the jump is taken** (the jump target).  
2. Identify what happens **if the jump is not taken** (the next instruction, sequential execution).  
3. Determine which of these two paths displays the success message.

Never reason on the mnemonic alone. A `JNZ` can lead to success or failure — it all depends on how the compiler arranged the code. Here are two possible arrangements for the same C condition:

**Arrangement A** (most common with GCC):
```nasm
TEST    EAX, EAX  
JZ      .fail           ; jump → failure  
; ... success code ...
.fail:
; ... failure code ...
```

**Arrangement B** (possible with another compiler or with `-O2`):
```nasm
TEST    EAX, EAX  
JNZ     .success        ; jump → success  
; ... failure code ...
JMP     .end
.success:
; ... success code ...
.end:
```

Both represent the same `if (check_license()) { success } else { failure }`, but with inverted jumps. Only reading the context (the instructions after the jump and at the jump target) resolves the ambiguity.

---

## Summary: opcodes to know

To prepare for the following sections (patching in 21.6, GDB observation in 21.5), here are the opcodes of the conditional jumps appearing in our keygenme:

| Mnemonic | Opcode (short, rel8) | Opcode (near, rel32) | Condition | Typical use |  
|---|---|---|---|---|  
| `JZ` / `JE` | `74 xx` | `0F 84 xx xx xx xx` | ZF = 1 | Zero test, equality |  
| `JNZ` / `JNE` | `75 xx` | `0F 85 xx xx xx xx` | ZF = 0 | Non-zero test, inequality |  
| `JMP` | `EB xx` | `E9 xx xx xx xx` | Unconditional | Always taken |  
| `NOP` | `90` | — | — | No-operation instruction |

The short form (`74 xx`, `75 xx`) encodes a relative displacement on 1 signed byte (range: -128 to +127 bytes). The near form encodes a displacement on 4 signed bytes (range: ±2 GB). GCC uses the short form when the jump target is close and the near form when it is distant.

For patching (section 21.6), remember that:
- Changing `74` to `75` (or vice versa) **inverts** the jump condition.  
- Changing `74 xx` to `EB xx` transforms the conditional jump into an **unconditional jump** (always taken).  
- Changing `74 xx` to `90 90` replaces the jump with two **NOPs** (never taken — execution continues sequentially).

These one or two-byte modifications are the foundation of crackme patching, and they flow directly from the mechanical understanding of conditional jumps developed in this section.

---

## Summary

Conditional jumps are the tipping point of any crackme. Here is what to remember:

- `TEST reg, reg` sets ZF = 1 if the register is zero, ZF = 0 otherwise. This is GCC's idiom for testing a boolean value or function return.  
- `JZ`/`JE` jumps when ZF = 1 (zero value, equal strings). `JNZ`/`JNE` jumps when ZF = 0 (non-zero value, different strings).  
- The **direction** of the jump (success or failure) depends on code arrangement, not the mnemonic. Always read the jump target and the sequential path to determine which is which.  
- At `-O2`/`-O3`, conditional jumps may be replaced by `SETcc` or `CMOVcc`, eliminating explicit branching. The reverse engineer must recognize these patterns as optimized forms of the same `if`.  
- Opcodes `74`/`75`/`EB`/`90` are the keys to patching — we will encounter them again in section 21.6.

The mechanics are understood. The next section (21.5) will confirm them in real time: we will set a breakpoint on `strcmp` in GDB and directly observe the values in registers at the moment of comparison.

⏭️ [Dynamic analysis: tracing the comparison with GDB](/21-keygenme/05-dynamic-analysis-gdb.md)
