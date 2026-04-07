🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 10 Checkpoint: Binary Diffing

> **Spoiler** — Only consult this solution after producing your own report.  
>  
> Binaries: `binaries/ch10-keygenme/keygenme_v1` and `binaries/ch10-keygenme/keygenme_v2`

---

## 1. Initial Triage with `radiff2`

### Similarity Score

```bash
$ radiff2 -s keygenme_v1 keygenme_v2
similarity: 0.992  
distance: 28  
```

**Interpretation**: the two binaries are nearly identical — 99.2% similarity, only 28 bytes of difference. The patch is very targeted. We expect to find a localized modification in a single function, or even a single basic block.

### Raw Location of Modified Bytes

```bash
$ radiff2 keygenme_v1 keygenme_v2
0x00001182 4883ec20 => 4883ec30
0x0000118e 48897de8 => 48897dd8
0x00001193 488b7de8 => 488b7dd8
0x00001197 e8a4ffffff => e870ffffff
0x0000119c 89...     => 4889...
...
```

The modified offsets are all concentrated in the `0x1180`–`0x11d0` range, confirming that a single area of the binary is affected. Offset `0x1180` corresponds to the beginning of a function.

### Target Function Identification

```bash
$ radiff2 -AC keygenme_v1 keygenme_v2
```

Filtered result (functions with similarity < 1.00):

```
sym.check_serial  0x00001180 | sym.check_serial  0x00001180  (MATCH 0.82)
```

All other functions are at 1.00:

```
sym.main          0x00001060 | sym.main          0x00001060  (MATCH 1.00)  
sym.transform     0x00001140 | sym.transform     0x00001140  (MATCH 1.00)  
sym.usage         0x00001230 | sym.usage         0x00001230  (MATCH 1.00)  
```

**Triage conclusion**: only one function is modified — `check_serial` — with a score of 0.82. The patch is surgical. Elapsed time: less than one minute.

---

## 2. Overview with BinDiff

### Export and Comparison

After importing and auto-analyzing both binaries in Ghidra, export in BinExport format:

```bash
# Exports done from Ghidra: File → Export BinExport2…
$ ls *.BinExport
keygenme_v1.BinExport  keygenme_v2.BinExport

$ bindiff keygenme_v1.BinExport keygenme_v2.BinExport
```

### Global Statistics

| Metric | Value |  
|--------|-------|  
| Functions in v1 | 4 (+libc functions) |  
| Functions in v2 | 4 (+libc functions) |  
| Matched identical functions | 3 (+ libc) |  
| Matched modified functions | 1 |  
| Unmatched functions | 0 |  
| Overall similarity | 0.99 |

### Modified Function Detail

| Field | v1 | v2 |  
|-------|----|----|  
| Name | `check_serial` | `check_serial` |  
| Address | `0x00001180` | `0x00001180` |  
| Similarity | 0.82 | — |  
| Basic blocks | 6 | 8 |  
| CFG edges | 6 | 9 |  
| Matching algorithm | name hash matching | — |

### CFG Analysis in BinDiff

The side-by-side control flow graph view shows:

- **4 green blocks** (identical): the function prologue, the `transform()` call block, the block displaying `"Access granted!"` and the block displaying `"Access denied."`.  
- **1 yellow block** (modified): the block between the prologue and the `transform()` call. In v1, this block chained directly to `transform()`. In v2, it was modified to include a `strlen()` call and store the result.  
- **2 red blocks** (added in v2): two new test blocks. The first compares the length to 3 (`cmp`/`jbe`) and branches to the failure path if the length is insufficient. The second compares to 32 (`cmp`/`ja`) and branches to failure if the length is excessive.  
- **1 additional yellow block**: the final branch block that existed in both versions but whose jump offsets were recalculated to accommodate the new blocks.

The patch structure is clear: two validation blocks were inserted between the prologue and the `transform()` call, creating a new early failure path (*early exit*).

---

## 3. Detailed Analysis with Diaphora

### Pseudo-code Diff

After exporting both binaries in SQLite format from Ghidra and launching the comparison, `check_serial` appears in the **Partial matches** tab (ratio 0.82).

The side-by-side pseudo-code diff shows:

**Version v1:**

```c
int check_serial(char *input) {
    int transformed = transform(input);
    if (transformed == 0x5a42) {
        puts("Access granted!");
        return 1;
    }
    puts("Access denied.");
    return 0;
}
```

**Version v2 (added lines marked +):**

```c
int check_serial(char *input) {
+   size_t len = strlen(input);
+   if (len < 4 || len > 32) {
+       puts("Access denied.");
+       return 0;
+   }
    int transformed = transform(input);
    if (transformed == 0x5a42) {
        puts("Access granted!");
        return 1;
    }
    puts("Access denied.");
    return 0;
}
```

The diff is unambiguous: three lines of code were added at the beginning of the function, before any processing logic. These lines compute the input length and immediately reject any input whose size is not between 4 and 32 characters inclusive.

---

## 4. Assembly-level Verification

### Version v1 — beginning of `check_serial`

```asm
0x00001180  push   rbp
0x00001181  mov    rbp, rsp
0x00001184  sub    rsp, 0x20              ; 32-byte frame
0x00001188  mov    qword [rbp-0x18], rdi  ; save input
0x0000118c  mov    rdi, qword [rbp-0x18]
0x00001190  call   sym.transform          ; DIRECT call, no validation
0x00001195  mov    dword [rbp-0x4], eax
0x00001198  cmp    dword [rbp-0x4], 0x5a42
0x0000119f  jne    0x11b5                 ; if != 0x5a42 → "denied"
```

### Version v2 — beginning of `check_serial`

```asm
0x00001180  push   rbp
0x00001181  mov    rbp, rsp
0x00001184  sub    rsp, 0x30              ; frame enlarged to 48 bytes (+16)
0x00001188  mov    qword [rbp-0x28], rdi  ; save input (shifted offset)
0x0000118c  mov    rdi, qword [rbp-0x28]
0x00001190  call   strlen                 ; NEW: length computation
0x00001195  mov    qword [rbp-0x10], rax  ; NEW: store len
0x00001199  cmp    qword [rbp-0x10], 0x3
0x0000119e  jbe    0x11d0                 ; NEW: len <= 3 → denied
0x000011a0  cmp    qword [rbp-0x10], 0x20
0x000011a5  ja     0x11d0                 ; NEW: len > 32 → denied
0x000011a7  mov    rdi, qword [rbp-0x28]
0x000011ab  call   sym.transform          ; call PROTECTED by validation
0x000011b0  mov    dword [rbp-0x4], eax
0x000011b3  cmp    dword [rbp-0x4], 0x5a42
0x000011ba  jne    0x11d0                 ; if != 0x5a42 → "denied"
```

### Instruction-by-instruction Changes Observed

| Element | v1 | v2 | Meaning |  
|---------|----|----|---------|  
| Frame size | `sub rsp, 0x20` (32) | `sub rsp, 0x30` (48) | +16 bytes for the `len` variable (8-byte `size_t` + alignment) |  
| `input` offset | `[rbp-0x18]` | `[rbp-0x28]` | Shift due to frame enlargement |  
| Instruction after save | `call sym.transform` | `call strlen` | Replacement: validation before processing |  
| `strlen` result storage | — | `mov qword [rbp-0x10], rax` | New local variable `len` |  
| Lower bound test | — | `cmp [rbp-0x10], 0x3` + `jbe` | Reject if length ≤ 3 (< 4 characters) |  
| Upper bound test | — | `cmp [rbp-0x10], 0x20` + `ja` | Reject if length > 32 characters |  
| `transform` call | Unprotected | After both tests | Only executes if 4 ≤ len ≤ 32 |

The assembly fully confirms the pseudo-code interpretation.

---

## 5. Vulnerability Characterization

### Flaw Nature

In version v1, the `check_serial` function passes user input directly to `transform()` without any length validation. If `transform()` works with a fixed-size internal buffer (common for serial transformation routines), an input of arbitrary length — excessively long or too short — can cause:

- **Input too long**: a *buffer overflow* in `transform()`, with potential overwriting of the stack return address and possibility of arbitrary code execution.  
- **Input too short**: an *out-of-bounds read* if `transform()` accesses indices beyond the actual string length, with potential stack information leakage or crash.

### CWE Classification

- **CWE-20** — *Improper Input Validation*: the root cause. User input is not validated before being passed to a processing function.  
- **CWE-120** — *Buffer Copy without Checking Size of Input*: the likely consequence if `transform()` copies input into a fixed-size buffer.

### Potential Impact

An attacker can provide specially crafted input to trigger the buffer overflow in `transform()`. Depending on the binary's protection configuration (canary, NX, ASLR — verifiable with `checksec`), this can lead to:

- A program crash (denial of service).  
- Authentication verification bypass.  
- Arbitrary code execution in the most severe case.

---

## 6. Summary Table

| Element | Detail |  
|---------|--------|  
| **Binary** | `keygenme` (v1 vulnerable → v2 fixed) |  
| **Overall similarity** | 0.992 (`radiff2`) / 0.99 (BinDiff) |  
| **Modified function** | `check_serial` @ `0x00001180` |  
| **Function similarity score** | 0.82 |  
| **Basic blocks** | 6 (v1) → 8 (v2), +2 validation blocks |  
| **Nature of change** | Added `strlen()` + double bounds check [4, 32] before `transform()` call |  
| **Fixed vulnerability** | Missing input length validation (CWE-20 / CWE-120) |  
| **Potential impact** | Buffer overflow → authentication bypass / code execution |  
| **Unmodified functions** | `main` (1.00), `transform` (1.00), `usage` (1.00) |

---

## Applied Workflow Summary

| Step | Tool | Time | Result obtained |  
|------|------|------|-----------------|  
| Triage | `radiff2 -s` / `-AC` | ~30 sec | Similarity 0.992, target = `check_serial` |  
| CFG overview | BinDiff | ~5 min | 4 green, 2 yellow, 2 red blocks — patch structure |  
| Pseudo-code diff | Diaphora | ~5 min | 3 lines added: `strlen` + bounds tests |  
| ASM verification | Ghidra | ~5 min | Confirmation: `call strlen`, `cmp`+`jbe`, `cmp`+`ja` |  
| Documentation | — | ~5 min | Complete report with summary table |  
| **Total** | | **~20 min** | |

---

⏭️
