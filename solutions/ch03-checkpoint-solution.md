🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Checkpoint Solution — Chapter 3

> **Exercise**: Manually annotate the disassembly of an unknown function compiled by GCC at `-O0` (Intel syntax, x86-64 Linux) by applying the 5-step method from section 3.7.

---

## Original Source (not given to the student)

The listing corresponds to the `count_lowercase` function from `binaries/ch03-checkpoint/count_lowercase.c`:

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

To reproduce the listing: `cd binaries/ch03-checkpoint && make all && make disass`

---

## Step 1 — Delimit

- **Prologue**: `push rbp / mov rbp, rsp` — classic frame pointer, no `sub rsp`  
- **Epilogue**: `pop rbp / ret`  
- **Arguments**: 2 parameters — `rdi` (64-bit pointer = `const char *`) and `esi` (32-bit integer = `int`)  
- **Local variables**: 4 (2 spilled arguments + 2 locals)

---

## Step 2 — Structure

| Jump | Target | Direction | Role |  
|---|---|---|---|  
| `jmp 0x4011c1` | Loop test | Downward | Initial jump to the test (`for` pattern) |  
| `jle 0x4011bd` | Increment | Downward | `&&` short-circuit (1st condition false) |  
| `jg 0x4011bd` | Increment | Downward | `&&` short-circuit (2nd condition false) |  
| `jl 0x401191` | Loop body | **Upward** | **Loop** — return to body if `i < len` |

Structure: `for` loop with bottom test, body containing an `if` with dual condition (`&&` pattern).

---

## Step 3 — Characterize

- **No `call`** → standalone function, no external calls  
- **Key constants**: `0x60` (96 = `'a' - 1`) and `0x7a` (122 = `'z'`) → ASCII lowercase bounds  
- **`&&` pattern**: both `jle`/`jg` jump to the **same target** (`0x4011bd`) → logical AND short-circuit  
- **Full reload**: GCC `-O0` fully reloads `str[i]` for the 2nd condition (5 instructions instead of reusing the register)

---

## Step 4 — Variable Map

| Offset | Size | Source register | Name | Type | Role |  
|---|---|---|---|---|---|  
| `[rbp-0x18]` | 8 bytes | `rdi` | `str` | `const char *` | Pointer to the buffer |  
| `[rbp-0x1c]` | 4 bytes | `esi` | `len` | `int` | Buffer length |  
| `[rbp-0x08]` | 4 bytes | — | `count` | `int` | Lowercase counter |  
| `[rbp-0x04]` | 4 bytes | — | `i` | `int` | Loop index |

---

## Step 5 — Reconstructed C Pseudo-code

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

---

## Pedagogical Points of Attention

1. **`&&` in assembly**: two consecutive `cmp`/`jXX` jumping to the same target. As soon as one condition is false, it short-circuits — classic signature of logical AND.

2. **Condition inversion**: `if (c >= 'a')` in C produces `cmp al, 0x60 / jle skip` in assembly. GCC compares with `'a' - 1` and jumps if `<=` (inverse of `>=`). The jump goes to the code that skips `count++`, not to the code that executes it.

3. **`-O0` reload**: each C sub-expression is compiled independently. `str[i]` is fully recalculated for the second comparison. At `-O2`, the 5 reload instructions disappear.

4. **`movzx` vs `movsx`**: `movzx eax, byte [rax]` reads an unsigned byte (zero-extend). For ASCII characters (0–127), the distinction with `movsx` (sign-extend) has no impact, but `movzx` confirms that GCC treats `char` as potentially unsigned for range comparison.

5. **`movsxd rdx, eax`**: sign-extension of `int i` (32 bits) to 64 bits for pointer arithmetic. Necessary because `str + i` is a computation on a 64-bit pointer.

---

⏭️ [Chapter 4 — Setting Up the Work Environment](/04-work-environment/README.md)
