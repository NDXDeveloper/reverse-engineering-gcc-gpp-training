🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 21

## Objective

Produce a **working Python keygen** capable of generating valid license keys for any username, and **automatically validate** these keys against the three main binary variants: `keygenme_O0`, `keygenme_O2`, and `keygenme_O2_strip`.

This checkpoint verifies that the entire RE cycle presented in this chapter has been assimilated, from initial static analysis to algorithm reconstruction.

---

## Validation criteria

The checkpoint is considered passed when the following **five criteria** are all met simultaneously:

### 1. The keygen is standalone

The Python script works without depending on the binary at runtime. It takes a username as input and produces a key as output, reproducing the algorithm extracted from the disassembly. It calls neither GDB, nor angr, nor the binary itself to compute the key.

### 2. Keys are valid on `keygenme_O0`

For at least 10 distinct usernames (of varying lengths, between 3 and 31 characters), the generated key is accepted by `keygenme_O0` with the message `[+] Valid license!`.

### 3. Keys are valid on `keygenme_O2`

The same keys, for the same usernames, are accepted by `keygenme_O2`. This criterion verifies that the keygen reproduces the program's semantic algorithm and not an artifact related to the `-O0` optimization level.

### 4. Keys are valid on `keygenme_O2_strip`

The same keys are accepted by `keygenme_O2_strip`. This criterion verifies that the keygen works independently of the presence or absence of symbols — it is the same algorithm, only the binary envelope differs.

### 5. Validation is automated

A validation script (using `pwntools` or `subprocess`) automatically submits the generated keys to all three binaries and displays a success/failure report. No manual copy-paste.

---

## Expected deliverable

The checkpoint produces **two files**:

| File | Role |  
|---|---|  
| `keygen_keygenme.py` | The standalone keygen. Takes a username as argument and displays the key. |  
| `validate_checkpoint.py` | The automated validation script. Tests the keygen against the 3 variants for N usernames and displays a report. |

### Expected output format of the validation script

```
══════════════════════════════════════════════════
  Checkpoint 21 — Keygen validation
══════════════════════════════════════════════════

  Username            Generated key         O0    O2    O2s
  ──────────────────────────────────────────────────────────
  Alice               DCEB-0DFC-B51F-3428   ✅    ✅    ✅
  Bob                 679E-0910-0F9D-94B5   ✅    ✅    ✅
  X1z                 B818-3F1B-CC86-5274   ✅    ✅    ✅
  ReverseEngineer     6865-6B66-F22C-F8FB   ✅    ✅    ✅
  ...

  Result: 30/30 validations passed.
  ✅ Checkpoint passed.
```

---

## Methodological reminder

The complete path to the keygen was covered in the chapter's sections. Here is the correspondence between each criterion and the section providing the tools to fulfill it:

| Criterion | Required skill | Reference section |  
|---|---|---|  
| Standalone keygen | Algorithm reconstruction in Python | 21.8 |  
| Valid on `_O0` | Correct translation of Ghidra pseudo-C | 21.3, 21.8 |  
| Valid on `_O2` | Understanding that optimization does not change semantics | 21.4, 21.8 |  
| Valid on `_O2_strip` | Ability to analyze a binary without symbols | 21.1, 21.3, 21.5 |  
| Automated validation | Using `pwntools` (`process`, `sendline`, `recvuntil`) | 21.8 |

### Intermediate verification points

If the keygen fails, the following diagnostic steps help isolate the problem:

**Is the hash correct?** — Compare the output of `compute_hash(b"Alice")` in Python with the value observed in GDB (section 21.5). Set a breakpoint after the call to `compute_hash` in `check_license` and read `EAX`. If the two values diverge, the error is in the `compute_hash` translation — check the `& 0xFFFFFFFF` masks, the rotation when count equals 0, and the order of operations in the loop.

**Are the groups correct?** — Compare the four groups produced by `derive_key` in Python with the values in the `groups[4]` array in memory (readable via `x/4hx $rsp+offset` in GDB after the call to `derive_key`). If the hash is correct but the groups diverge, the error is in the XOR constants or in `derive_key`'s rotations.

**Is the formatting correct?** — Compare the string produced by `format_key` in Python with the `expected` string captured in GDB just before `strcmp` (section 21.5, `x/s $rdi`). If the groups are correct but the string differs, check the format (`%04X` = uppercase hexadecimal padded to 4 digits, `{:04X}` in Python).

**Is the submission correct?** — If the key displayed by the keygen matches the one captured in GDB but the binary rejects it, the problem is in the `pwntools` interaction: stray end-of-line character (`\r\n` vs `\n`), key truncation, or read timing. Verify with `p.recvall()` what the binary actually returns.

---

## Variants to go further

Once the checkpoint is validated, the following extensions allow deepening the work:

- **Test on `keygenme_O3` and `keygenme_strip`** in addition to the three required variants. The keygen should work without modification (5/5 variants).  
- **Compare the key produced by the keygen with the one found by angr** (section 21.7) for the same username. Both must be identical — this is double validation by independent methods.  
- **Measure the execution time** of the keygen vs angr. The keygen should be nearly instantaneous (milliseconds), while angr takes several seconds per execution. This difference illustrates the cost of symbolic execution compared to direct algorithm reproduction.  
- **Adapt the keygen to C** instead of Python, using exactly the same types (`uint32_t`, `uint16_t`) as the original binary. Compare the produced binary with the keygenme via `objdump` to observe the similarities in machine code.

---

## Solution

The complete solution is available in `solutions/ch21-checkpoint-keygen.py`. Consult it only after attempting to produce your own version — the pedagogical value of the checkpoint lies in the reconstruction process, not in the final result.

⏭️ [Chapter 22 — Reversing an Object-Oriented C++ Application](/22-oop/README.md)
