🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 3

## Manually annotate a real disassembly

> **Goal**: validate that you master what you have learned in Chapter 3 by applying the 5-step reading method (section 3.7) to a real assembly listing. This checkpoint covers registers, essential instructions, arithmetic, conditional jumps, prologue/epilogue, parameter passing, and reconstruction into C pseudo-code.

---

## Instructions

The listing below is the disassembly of an unknown function, compiled by GCC with `-O0` for x86-64 Linux (Intel syntax). The binary has been stripped — you have no function or variable names.

Your task is to:

1. **Delimit** the function (prologue, epilogue, number of arguments).  
2. **Structure** the control flow (identify blocks, jumps, loops, branches).  
3. **Characterize** the notable operations (calls, constants, known patterns).  
4. **Annotate** each instruction or group of instructions with a comment explaining its role.  
5. **Rewrite** the logic as C pseudo-code.

---

## Listing to analyze

```asm
; Unknown function — GCC -O0, x86-64 Linux, Intel syntax, non-PIE

0x401176:  push    rbp
0x401177:  mov     rbp, rsp
0x40117a:  mov     qword [rbp-0x18], rdi
0x40117e:  mov     dword [rbp-0x1c], esi
0x401181:  mov     dword [rbp-0x8], 0x0
0x401188:  mov     dword [rbp-0x4], 0x0
0x40118f:  jmp     0x4011c1
0x401191:  mov     eax, dword [rbp-0x4]
0x401194:  movsxd  rdx, eax
0x401197:  mov     rax, qword [rbp-0x18]
0x40119b:  add     rax, rdx
0x40119e:  movzx   eax, byte [rax]
0x4011a1:  cmp     al, 0x60
0x4011a3:  jle     0x4011bd
0x4011a5:  mov     eax, dword [rbp-0x4]
0x4011a8:  movsxd  rdx, eax
0x4011ab:  mov     rax, qword [rbp-0x18]
0x4011af:  add     rax, rdx
0x4011b2:  movzx   eax, byte [rax]
0x4011b5:  cmp     al, 0x7a
0x4011b7:  jg      0x4011bd
0x4011b9:  add     dword [rbp-0x8], 0x1
0x4011bd:  add     dword [rbp-0x4], 0x1
0x4011c1:  mov     eax, dword [rbp-0x4]
0x4011c4:  cmp     eax, dword [rbp-0x1c]
0x4011c7:  jl      0x401191
0x4011c9:  mov     eax, dword [rbp-0x8]
0x4011cc:  pop     rbp
0x4011cd:  ret
```

---

## Self-assessment grid

Before consulting the solution, verify that you have identified each of the following elements:

| Element | Question | ✓ |  
|---|---|---|  
| **Prologue** | Which instructions make up the prologue? Is there a frame pointer? | ☐ |  
| **Arguments** | How many parameters does the function receive? What are their probable types? | ☐ |  
| **Local variables** | How many local variables are declared? At which `rbp` offsets? | ☐ |  
| **Loop** | Is there a loop? What type (for, while, do…while)? What is its bound? | ☐ |  
| **Inner condition** | What condition is tested in the body of the loop? What does it guard? | ☐ |  
| **Constants** | Which constants appear? What do they mean? | ☐ |  
| **Return value** | What does the function return? In which register? | ☐ |  
| **Pseudo-code** | Can you rewrite the full logic in C? | ☐ |

---

## Detailed solution

> ⚠️ **Try the exercise before reading on.** The solution is here to validate your analysis, not replace it.

### Step 1 — Delimit

**Prologue** (lines `0x401176`–`0x401177`):

```asm
0x401176:  push    rbp                 ; saves the old base pointer
0x401177:  mov     rbp, rsp            ; establishes the frame pointer
```

Classic prologue with frame pointer, no `sub rsp` — local variables fit in the red zone or the space above `rbp`. No callee-saved register saving (no `push rbx`, `push r12`…) → simple function. No stack canary (no `mov rax, [fs:0x28]`).

**Epilogue** (lines `0x4011cc`–`0x4011cd`):

```asm
0x4011cc:  pop     rbp                 ; restores the old base pointer
0x4011cd:  ret                          ; returns to the caller
```

No `leave` here, just a simple `pop rbp` (equivalent since there was no `sub rsp`).

**Arguments** — the spills at the start of the function reveal the parameters:

```asm
0x40117a:  mov     qword [rbp-0x18], rdi    ; 1st arg, 64-bit → pointer
0x40117e:  mov     dword [rbp-0x1c], esi    ; 2nd arg, 32-bit → int
```

Two parameters: a pointer (64-bit, in `rdi`) and an integer (32-bit, in `esi`).

### Step 2 — Structure

Let's identify the jumps:

| Address | Instruction | Target | Direction |  
|---|---|---|---|  
| `0x40118f` | `jmp 0x4011c1` | `0x4011c1` | Downward → jump to the loop test |  
| `0x4011a3` | `jle 0x4011bd` | `0x4011bd` | Downward → skip (condition false) |  
| `0x4011b7` | `jg 0x4011bd` | `0x4011bd` | Downward → skip (condition false) |  
| `0x4011c7` | `jl 0x401191` | `0x401191` | **Upward** → **loop** |

The upward `jl` at `0x4011c7` confirms a loop. The initial `jmp 0x4011c1` jumps straight to the loop test → that is the pattern of a **`for`/`while` loop with the test at the bottom** (cf. section 3.4).

Identified blocks:

```
Block A [0x401176–0x40118f]: prologue + spill arguments + init variables + jmp to test  
Block B [0x401191–0x4011b9]: loop body (loading str[i] + double condition)  
Block C [0x4011bd–0x4011c1]: increment of the loop counter i  
Block D [0x4011c1–0x4011c7]: loop test (cmp + jl back to the body)  
Block E [0x4011c9–0x4011cd]: loading of the result + epilogue + ret  
```

Flow diagram:

```
        ┌──────────┐
        │ Block A  │  prologue + init
        └────┬─────┘
             │ jmp
             ▼
        ┌─────────────┐
  ┌────►│  Block D    │  test: i < len?
  │     └──┬───────┬──┘
  │   true │       │ false
  │        ▼       │
  │  ┌──────────┐  │
  │  │ Block B  │  │
  │  │   body   │  │
  │  └────┬─────┘  │
  │       ▼        │
  │  ┌──────────┐  │
  │  │ Block C  │  │
  │  │   i++    │  │
  │  └────┬─────┘  │
  │       │        │
  └───────┘        │
                   ▼
            ┌──────────┐
            │ Block E  │  return result
            └──────────┘
```

### Step 3 — Characterize

**No `call`** → the function calls nothing, it is standalone.

**Notable constants**:

| Hex value | Decimal | ASCII | Meaning |  
|---|---|---|---|  
| `0x60` | 96 | `` ` `` | Character just before `'a'` (97) in the ASCII table |  
| `0x7a` | 122 | `z` | Lowercase letter `'z'` |  
| `0x0` | 0 | — | Zero initialization |  
| `0x1` | 1 | — | Increment |

The `0x60` and `0x7a` constants bound the **lowercase letters** range in the ASCII table: a character `c` is a lowercase letter if `c > 0x60 && c <= 0x7a`, that is, `c >= 'a' && c <= 'z'`. Note that the comparison uses `jle` (less or equal) with `0x60`, which means "jump if `al <= 0x60`", i.e., "continue if `al > 0x60`". Combined with `jg` on `0x7a` ("jump if `al > 0x7a`"), the condition to NOT jump is `0x60 < al <= 0x7a`, i.e., `'a' <= al <= 'z'`.

**Operations**:

- `movsxd rdx, eax` → sign-extension of an `int` index to 64 bits (for pointer arithmetic).  
- `movzx eax, byte [rax]` → reading of an **unsigned byte** (character) from a pointed-to buffer.  
- `add dword [rbp-0x8], 0x1` → increment of a counter (the variable that will be returned).

**Hypothesis**: the function counts the number of lowercase letters in a string (or buffer of given length).

### Step 4 — Annotate

```asm
; === PROLOGUE ===
0x401176:  push    rbp                          ; saves the frame pointer
0x401177:  mov     rbp, rsp                     ; establishes the new frame pointer

; === ARGUMENT SPILL ===
0x40117a:  mov     qword [rbp-0x18], rdi        ; arg1 → str (pointer, char*)
0x40117e:  mov     dword [rbp-0x1c], esi        ; arg2 → len (integer, int)

; === LOCAL VARIABLE INITIALIZATION ===
0x401181:  mov     dword [rbp-0x8], 0x0         ; count = 0 (lowercase counter)
0x401188:  mov     dword [rbp-0x4], 0x0         ; i = 0 (loop index)
0x40118f:  jmp     0x4011c1                     ; jump to the loop test

; === LOOP BODY — 1st condition (str[i] >= 'a') ===
0x401191:  mov     eax, dword [rbp-0x4]         ; eax = i
0x401194:  movsxd  rdx, eax                     ; rdx = (long)i (sign-extension)
0x401197:  mov     rax, qword [rbp-0x18]        ; rax = str
0x40119b:  add     rax, rdx                     ; rax = str + i  (address of str[i])
0x40119e:  movzx   eax, byte [rax]              ; eax = (unsigned char)str[i]
0x4011a1:  cmp     al, 0x60                     ; compare str[i] with 96 ('a' - 1)
0x4011a3:  jle     0x4011bd                     ; if str[i] <= 96 → not lowercase, skip

; === LOOP BODY — 2nd condition (str[i] <= 'z') ===
; GCC -O0 reloads str[i] entirely (no register reuse)
0x4011a5:  mov     eax, dword [rbp-0x4]         ; eax = i (reloaded from stack)
0x4011a8:  movsxd  rdx, eax                     ; rdx = (long)i
0x4011ab:  mov     rax, qword [rbp-0x18]        ; rax = str (reloaded from stack)
0x4011af:  add     rax, rdx                     ; rax = str + i
0x4011b2:  movzx   eax, byte [rax]              ; eax = (unsigned char)str[i]
0x4011b5:  cmp     al, 0x7a                     ; compare str[i] with 122 ('z')
0x4011b7:  jg      0x4011bd                     ; if str[i] > 'z' → not lowercase, skip

; --- both conditions are true: it is a lowercase letter ---
0x4011b9:  add     dword [rbp-0x8], 0x1         ; count++

; === INCREMENT ===
0x4011bd:  add     dword [rbp-0x4], 0x1         ; i++

; === LOOP TEST ===
0x4011c1:  mov     eax, dword [rbp-0x4]         ; eax = i
0x4011c4:  cmp     eax, dword [rbp-0x1c]        ; compare i with len
0x4011c7:  jl      0x401191                     ; if i < len → back to body

; === RETURN ===
0x4011c9:  mov     eax, dword [rbp-0x8]         ; eax = count (return value)
0x4011cc:  pop     rbp                           ; restores the frame pointer
0x4011cd:  ret                                    ; returns count
```

**Variable map:**

| Offset | Size | Source register | Name | Type | Role |  
|---|---|---|---|---|---|  
| `[rbp-0x18]` | 8 bytes | `rdi` | `str` | `const char *` | Pointer to the buffer to analyze |  
| `[rbp-0x1c]` | 4 bytes | `esi` | `len` | `int` | Length of the buffer |  
| `[rbp-0x08]` | 4 bytes | — | `count` | `int` | Lowercase-letter counter |  
| `[rbp-0x04]` | 4 bytes | — | `i` | `int` | Loop index |

### Step 5 — Rewrite as C pseudo-code

```c
int count_lowercase(const char *str, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] > 0x60 && str[i] <= 0x7a) {  // 'a' <= str[i] <= 'z'
            count++;
        }
    }
    return count;
}
```

Or, in a more idiomatic version:

```c
int count_lowercase(const char *str, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            count++;
        }
    }
    return count;
}
```

### Points of attention in this listing

**The double condition as a translation of `&&`** (section 3.4): `if (c >= 'a' && c <= 'z')` in C produces two consecutive `cmp`/`jXX` pairs that both jump to the **same target** (`0x4011bd`). As soon as one of the conditions is false, you short-circuit — that is the signature of logical AND.

**GCC's inverted conditions**: in C you write `>= 'a'`, but GCC compares with `0x60` (= `'a' - 1`) and uses `jle` (jump if less or equal). The "continue" condition is `al > 0x60`, which is equivalent to `al >= 0x61`, i.e., `al >= 'a'`. Likewise, `jg 0x7a` jumps if `al > 'z'`, so the "continue" condition is `al <= 'z'`.

**The `movzx` (section 3.2)**: `movzx eax, byte [rax]` reads a byte and zero-extends it to 32 bits. That is the reading of an `unsigned char` (or of a `char` treated as unsigned for range comparison). The fact that GCC uses `movzx` (and not `movsx`) combined with `jle`/`jg` (signed jumps) tells us the compared values are in the 0–127 range (standard ASCII), where the signed/unsigned distinction has no impact.

**Full reload of `str[i]` for the 2nd condition** (lines `0x4011a5`–`0x4011b2`): GCC at `-O0` entirely recomputes `str[i]` from the stack — reloads `i`, extends to 64 bits, reloads `str`, recomputes `str + i`, re-reads the byte — instead of reusing the value already present in `eax`. This is typical `-O0` behavior: each C subexpression is compiled independently, without reusing values in registers. With `-O1` or above, this entire sequence would be eliminated in favor of a simple comparison on the already-loaded register.

---

## Validation criteria

You can consider this checkpoint successful if you have:

- ☑ Correctly identified the prologue, epilogue, and the two arguments (`char *` + `int`).  
- ☑ Spotted the `for` loop with test at the bottom and the backward `jl` at `0x4011c7`.  
- ☑ Understood that the two internal `cmp`/`jXX` pairs form a `&&` (short-circuit to the same target).  
- ☑ Translated the constants `0x60` and `0x7a` into the bounds of the ASCII lowercase alphabet.  
- ☑ Produced functionally correct C pseudo-code (even if the names differ).

If some points gave you trouble, re-read the corresponding section of the chapter before moving on.

---

> ✅ **Chapter 3 complete.** You now have the x86-64 assembly basics needed to tackle the RE tools of Parts II and III.  
>  
> 

⏭️ [Chapter 4 — Setting Up the Work Environment](/04-work-environment/README.md)
