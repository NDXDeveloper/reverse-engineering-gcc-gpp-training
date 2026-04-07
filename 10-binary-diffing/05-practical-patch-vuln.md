🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 10.5 — Practical case: identify a vulnerability fix between two versions of a binary

> **Chapter 10 — Binary diffing**  
> **Part II — Static Analysis**  
>  
> 📦 Binaries used: `binaries/ch10-keygenme/keygenme_v1` and `binaries/ch10-keygenme/keygenme_v2`  
> 🧰 Tools: `radiff2`, BinDiff, Diaphora, Ghidra

---

## Scenario context

This practical case simulates a 1-day analysis scenario as encountered in the security industry. Here is the situation:

You are a security analyst. A software vendor has released an update accompanied by a laconic security bulletin: *"Fix for an input-validation vulnerability in the authentication module, which could lead to a verification bypass. Severity: high."* No additional technical details are provided — no CVE, no description of the flaw, no credit to the researcher.

You have both versions of the binary: `keygenme_v1` (vulnerable version) and `keygenme_v2` (fixed version). Your mission is to precisely identify the modified function, understand the nature of the fixed vulnerability, and document your conclusions.

We'll unroll the analysis step by step, combining the three tools seen in this chapter according to the recommended workflow: quick triage with `radiff2`, overview with BinDiff, detailed analysis with Diaphora.

---

## Step 1 — Triage with `radiff2`

Before launching a disassembler, let's measure the change. A few seconds suffice.

### Quantify the difference

```bash
radiff2 -s keygenme_v1 keygenme_v2
```

Typical output:

```
similarity: 0.992  
distance: 28  
```

A similarity score of 0.992 confirms what the security bulletin suggested: the patch is surgical. Out of the entire binary, only 28 bytes differ. It's not a major refactoring — it's a targeted fix, probably localized in one or two functions.

### Locate modified zones

```bash
radiff2 keygenme_v1 keygenme_v2
```

The hexadecimal output shows the exact offsets of modified bytes. Observe the distribution of these offsets: if they're concentrated in a narrow range, the change probably touches a single function. If they're scattered, the patch is more extensive.

In our case, differences concentrate in a restricted zone — let's say around `0x1180`–`0x11d0` — which suggests a modification in a single function.

### First glimpse of modified code

```bash
radiff2 -AC keygenme_v1 keygenme_v2
```

This mode launches function analysis on both binaries and produces the list of matches. By filtering functions that are not at 1.00 similarity, you quickly identify the touched function(s):

```
sym.check_serial  0x00001180 | sym.check_serial  0x00001180  (MATCH 0.82)  
sym.main          0x00001060 | sym.main          0x00001060  (MATCH 1.00)  
sym.usage         0x00001230 | sym.usage         0x00001230  (MATCH 1.00)  
sym.transform     0x00001140 | sym.transform     0x00001140  (MATCH 1.00)  
```

The table is unambiguous: only `check_serial` has a score below 1.00 (0.82). All other functions are identical. We have our target.

> 💡 **Observation** — The name `check_serial` is visible here because our training binaries are not stripped. In a real situation, facing a stripped binary, you would see `fcn.00001180` or `sub_1180`. The process remains the same — it's the address and score that guide the analysis, not the name.

**Triage summary**: in less than a minute and three commands, we know that the patch modifies a single function (`check_serial` at `0x1180`), that the change is moderate (similarity of 0.82), and that the rest of the binary is intact. We can now focus the analysis.

---

## Step 2 — Overview with BinDiff

`radiff2` gave us the target. BinDiff will show us the change's structure.

### Export and comparison

If not already done, import both binaries into Ghidra, launch auto-analysis, and export each to BinExport format (cf. section 10.2):

```bash
# After exports from Ghidra
bindiff keygenme_v1.BinExport keygenme_v2.BinExport
```

Open the result in the BinDiff interface:

```bash
bindiff --ui keygenme_v1_vs_keygenme_v2.BinDiff
```

### Reading the overview

The statistical summary confirms `radiff2`'s observations: very high global similarity score, a single function marked as modified. Sort the matched-functions table by ascending similarity: `check_serial` appears at the top with the lowest score.

### CFG inspection

Double-click the `check_serial` pair. BinDiff opens the side-by-side view of the control-flow graphs. Here is what we typically observe in this kind of patch:

**v1 version (vulnerable):**
The CFG of `check_serial` has, let's say, 6 basic blocks. Flow is linear: the serial is transformed, then compared to an expected value via a single test followed by a branch to "success" or "failure".

**v2 version (fixed):**
The CFG now has 8 basic blocks — two more than v1. BinDiff's color code reveals:

- **Green blocks** (identical) — the function's entry blocks (prologue), the serial-transformation computation, and the exit blocks (epilogue) have not changed.  
- **Yellow blocks** (modified) — the block containing the final comparison has been modified. Examining the instructions, you can observe for example that a `je` (jump if equal) was replaced by a more complex sequence.  
- **Red blocks** (added) — two new blocks appear in v2. These are the blocks that didn't exist in v1: typically, an additional check of input length and a branch to the failure path if this check fails.

This visualization gives us the patch's structure: the fix adds a validation that didn't exist in the original version. Before diving into instruction details, let's move to Diaphora for the pseudo-code diff.

---

## Step 3 — Detailed analysis with Diaphora

### Export and comparison

From Ghidra, export both binaries to Diaphora format (`.sqlite` files), then launch the comparison as described in section 10.3.

### Locating in the results

In Diaphora's results, `check_serial` appears in the **Partial matches** tab — it was recognized as corresponding but with a similarity score below the "best matches" threshold. This is consistent with what `radiff2` and BinDiff showed us.

### The pseudo-code diff

Select the `check_serial` pair and open the pseudo-code diff. This is where Diaphora reveals all its value. Here is a representative example of what you might observe (simplified for clarity):

**v1 version (decompiled pseudo-code):**

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

**v2 version (decompiled pseudo-code):**

```c
int check_serial(char *input) {
    size_t len = strlen(input);
    if (len < 4 || len > 32) {
        puts("Access denied.");
        return 0;
    }
    int transformed = transform(input);
    if (transformed == 0x5a42) {
        puts("Access granted!");
        return 1;
    }
    puts("Access denied.");
    return 0;
}
```

Diaphora's diff highlights the added lines (in green in the interface): the call to `strlen`, the `len < 4 || len > 32` check, and the branch to the failure path. The rest of the function is identical (in white).

### Interpreting the vulnerability

The pseudo-code diff makes the analysis crystal clear. In v1, the `check_serial` function passes user input directly to `transform()` without verifying its length. The vulnerability depends on what `transform()` does — if this function works with a fixed-size buffer internally, a too-long input causes a buffer overflow. A too-short input can also cause problems (out-of-bounds access if `transform` expects a minimum number of characters).

Version v2 fixes this by adding a length check **before** calling `transform()`. The input must be between 4 and 32 characters, otherwise the function immediately returns in failure without ever reaching the vulnerable code.

> 📝 **Note** — In this pedagogical scenario, the vulnerability is voluntarily simple to understand. In real situations, patches are sometimes more subtle: changing `<` to `<=` (off-by-one fix), adding a `NULL` check, replacing a `strcpy` with a `strncpy`, or modifying an index calculation. The methodology remains identical — only the interpretation complexity changes.

---

## Step 4 — Verification at the assembly level

Pseudo-code gave us the semantic understanding. Let's verify at the assembly level to be certain of the interpretation. From Ghidra (with `keygenme_v1` open), navigate to the `check_serial` function and examine the listing.

**v1 version — start of `check_serial`:**

```asm
check_serial:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 0x20
    mov    qword [rbp-0x18], rdi      ; save input
    mov    rdi, qword [rbp-0x18]
    call   transform                   ; direct call without verification
    ...
```

**v2 version — start of `check_serial`:**

```asm
check_serial:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 0x30
    mov    qword [rbp-0x28], rdi      ; save input
    mov    rdi, qword [rbp-0x28]
    call   strlen                      ; NEW: length computation
    mov    qword [rbp-0x10], rax       ; store len
    cmp    qword [rbp-0x10], 0x3
    jbe    .Ldenied                    ; NEW: len <= 3 → failure
    cmp    qword [rbp-0x10], 0x20
    ja     .Ldenied                    ; NEW: len > 32 → failure
    mov    rdi, qword [rbp-0x28]
    call   transform                   ; call protected by the check
    ...
```

Assembly confirms the pseudo-code: three new instructions (`call strlen`, `cmp`+`jbe`, `cmp`+`ja`) and a branch to the failure path frame the call to `transform`. The stack frame has been enlarged (`0x20` → `0x30`) to accommodate the `len` local variable.

These are exactly the yellow and red blocks that BinDiff showed us in the CFG view.

---

## Step 5 — Documenting conclusions

The analysis is complete. Let's synthesize the results in an exploitable form — it's a step often neglected but essential in a professional context.

### Patch-analysis summary

| Element | Detail |  
|---------|--------|  
| **Analyzed binary** | `keygenme` (v1 → v2) |  
| **Modified function** | `check_serial` (address `0x1180`) |  
| **Change nature** | Addition of a user-input length check |  
| **Vulnerability fixed** | Missing input size validation before processing by `transform()` |  
| **Vulnerability type** | Improper input validation (CWE-20), potentially leading to a buffer overflow (CWE-120) |  
| **Potential impact** | Authentication-verification bypass, potential code execution |  
| **Applied fix** | `strlen(input)` check with bounds [4, 32] before calling `transform()` |  
| **Unchanged functions** | `main`, `usage`, `transform` — identical between v1 and v2 |

### CWE classification

Referencing CWE identifiers (*Common Weakness Enumeration*) is good practice in an analysis report. It allows classifying the vulnerability in a recognized taxonomy and facilitates communication with development and risk-management teams. In our case:

- **CWE-20** (*Improper Input Validation*) — the root cause. User input is not validated before processing.  
- **CWE-120** (*Buffer Copy without Checking Size of Input*) — the likely consequence, if `transform()` copies the input into a fixed-size buffer.

---

## Reflection on the methodology

This practical case illustrates the funnel workflow we built throughout the chapter:

1. **`radiff2`** — 30 seconds — answered "how many functions changed?" and gave us the target (`check_serial`).  
2. **BinDiff** — 5 minutes — confirmed the target and showed the change's structure (added blocks, modified blocks) via CFG visualization.  
3. **Diaphora** — 5 minutes — provided the pseudo-code diff that makes the change immediately understandable without having to decode assembly instruction by instruction.  
4. **Ghidra (assembly)** — 5 minutes — allowed verifying the interpretation at the lowest level and confirming technical details (frame size, exact opcodes of conditional jumps).

In total, the complete identification of the fixed vulnerability took about 15 minutes. On a stripped, larger binary, or with a more subtle patch, the process would be longer, but the methodology remains the same: triage, overview, detailed analysis, verification, documentation.

What is remarkable is that we didn't need to understand the entire binary. We didn't analyze `main`, nor `transform`, nor `usage`. Diffing allowed us to ignore 100% of the unchanged code and concentrate effort on the few lines that matter. That's the whole point of this technique.

---


⏭️ [🎯 Checkpoint: compare `keygenme_v1` and `keygenme_v2`, identify the modified function](/10-binary-diffing/checkpoint.md)
