🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 14

## Objective

Run Valgrind on the `ch14-crypto` binary, identify key buffers in memory, and produce a structured synthesis document following the ACRF method covered in Section 14.4.

This checkpoint validates your ability to **leverage memory analysis tools not as debugging tools, but as reverse engineering instruments** — extracting from raw reports the structural information needed to understand an unknown binary.

---

## Target binary

```
binaries/ch14-crypto/
```

Use the `-O0` version with symbols for the first pass (most readable reports), then the `-O2` stripped version to verify that your conclusions hold on a realistic binary.

Prepare a reasonably sized test file (a few hundred bytes) as encryption input. Any password will serve as the second argument.

---

## What you must produce

### 1. Allocation map (ACRF method — step A)

A table listing **all dynamic blocks** allocated by the binary during the encryption operation, obtained via Memcheck (`--leak-check=full --show-leak-kinds=all`) and/or ASan. For each block, document:

- Its exact size.  
- The address of the function that allocates it.  
- The address of the function that frees it (if applicable).  
- Its Memcheck category (definitely lost, still reachable, normally freed).  
- Your hypothesis about its nature (key, IV, I/O buffer, crypto context, etc.).

**Validation criterion**: you must identify at least **two blocks whose size corresponds to standard cryptographic primitives** (symmetric key, IV, hash block, expanded key…). Justify the link between the observed size and the assumed primitive.

### 2. Key buffer identification

This is the core of the checkpoint. From the Memcheck and/or MSan reports, you must precisely identify:

- **The buffer containing the key** — its size, allocation address, the function that writes the derived key into it, and the function that reads it for encryption.  
- **The buffer containing the IV** (if it exists) — same information. Note whether the IV is correctly initialized or whether Memcheck/MSan reports uninitialized bytes.  
- **The crypto context** (if it exists) — a persistent block containing the expanded key or other state data. Propose a partial layout of this structure based on access offsets observed in the reports.

**Validation criterion**: for each identified key buffer, you must provide at least **two independent sources** that confirm your hypothesis (for example: Memcheck size + ASan offset, or Memcheck size + Callgrind access count).

### 3. Functional graph of the crypto chain (ACRF method — step C)

An annotated call graph — textual or visual — showing the functions involved in the encryption flow, obtained via Callgrind. For each function, indicate:

- Its address.  
- Its Callgrind cost (percentage of total).  
- Its hypothesized role.  
- The memory blocks it manipulates (reference to your allocation map).

**Validation criterion**: your graph must clearly distinguish the **initialization** phases (buffer allocation, key derivation), **processing** (block-by-block encryption), and **finalization** (writing, cleanup). The computational hotspot (encryption routine) must be identified with its relative cost.

### 4. Draft of at least one reconstructed C structure (ACRF method — step R)

Propose at minimum one C `struct` corresponding to one of the identified blocks (preferably the crypto context). Each field must be justified by a tool report:

```c
struct cipher_ctx {
    // offset 0, size X — source: [tool, error type]
    // offset X, size Y — source: [tool, error type]
    // ...
};
```

**Validation criterion**: the structure must have at minimum two documented fields with their sources. The sum of field sizes (plus any padding) must match the observed allocation size.

---

## Hints and points of attention

- Remember to disable ASLR if the binary is compiled as PIE, to get stable addresses between runs:
  ```bash
  setarch x86_64 -R valgrind [options] ./ch14-crypto [args]
  ```

- Common cryptographic sizes to keep in mind: 16 bytes (128 bits — AES block, IV), 32 bytes (256 bits — AES-256 key, SHA-256 hash), 20 bytes (160 bits — SHA-1), 48 bytes (384 bits — SHA-384), 64 bytes (512 bits — SHA-512, SHA-256 block).

- If you use sanitizers (ASan, UBSan, MSan), remember to recompile from the sources provided in `binaries/ch14-crypto/`. The combined ASan + UBSan version is the most productive in a single run.

- A Memcheck suppression file filtering out errors from libc and system crypto libraries will save you time in isolating errors from the target binary.

- Run Callgrind **with a small input** (a few dozen bytes) to get a readable profile. An input that's too large drowns the initialization functions under the volume of encryption iterations.

- The call count on Callgrind graph edges is your best ally for identifying the encryption algorithm. Cross-reference it with Appendix J (crypto magic constants).

---

## Self-assessment

Before consulting the answer key, verify that your document answers these questions:

- [ ] Have you identified at least two blocks whose size corresponds to a crypto primitive?  
- [ ] Can you trace the key's path from user input to its use in encryption (flow F)?  
- [ ] Does your functional graph clearly distinguish init / processing / finalization?  
- [ ] Is each field in your reconstructed structures justified by at least one source?  
- [ ] Have you tested with at least two different inputs to confirm which blocks are fixed-size and which vary?  
- [ ] Would you be able to open Ghidra and immediately rename key functions based on your analysis?

If you check all boxes, you have mastered leveraging Valgrind and sanitizer tools in a reverse engineering context. You are ready for Chapter 15 (Fuzzing), where these same tools will be coupled with automatic input generation to systematically explore a binary's code paths.

---

📂 **Answer key**: [`/solutions/ch14-checkpoint-solution.md`](/solutions/ch14-checkpoint-solution.md)


⏭️ [Chapter 15 — Fuzzing for Reverse Engineering](/15-fuzzing/README.md)
