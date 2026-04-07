🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 24

## Decrypt the Provided `secret.enc` File by Extracting the Key from the Binary

> **Target binary**: `binaries/ch24-crypto/crypto_O2_strip` (optimized, stripped)  
> **File to decrypt**: `binaries/ch24-crypto/secret.enc`  
> **Reference file**: `binaries/ch24-crypto/secret.txt` (for final validation only)  
> **Solution**: `solutions/ch24-checkpoint-decrypt.py`

---

## Context

You have the `crypto_O2_strip` binary and the `secret.enc` file it produced. The binary is optimized (`-O2`) and stripped — local symbols have been removed. Your objective is to produce a Python script capable of decrypting `secret.enc` and restoring the original content.

This checkpoint validates all the skills from chapter 24: algorithm identification, library identification, secret extraction, file format understanding, and scheme reproduction in Python.

---

## Validation criteria

The checkpoint is considered passed when the following **four conditions** are met.

### 1. Documented identification of algorithm and library

You must be able to answer, with supporting evidence, the following questions:

- What encryption algorithm is used, and in what mode of operation?  
- What hashing algorithm is involved in key derivation?  
- Do the crypto routines come from an external library or a custom implementation?  
- How did you obtain these answers? (which tools, which commands, which results)

**Expected methods**: magic constant search (section 24.1), dynamic symbol and/or internal string inspection (section 24.2).

### 2. Extraction of key and IV

You must have captured:

- The encryption key (32 bytes for AES-256) — either directly from memory or by reproducing the derivation.  
- The IV (16 bytes) — either from memory or from the `.enc` file itself.  
- Bonus: the source passphrase and the complete derivation logic (passphrase → hash → transformation → final key).

**Expected methods**: GDB breakpoints and/or Frida hooks on crypto functions (section 24.3).

### 3. Understanding of the file format

You must produce a map of the `secret.enc` format indicating:

- The offset, size, and meaning of each header field.  
- The exact offset where the ciphertext begins.  
- The padding scheme used.

**Expected methods**: inspection in ImHex, entropy analysis, ideally a functional `.hexpat` pattern (section 24.4).

### 4. Functional decryption script

You must produce a Python script (`decrypt.py`) that:

- Takes as argument the path to a `.enc` file in CRYPT24 format.  
- Parses the header to extract the IV, original size, and ciphertext.  
- Derives (or uses) the AES-256 key.  
- Decrypts in AES-256-CBC with padding removal.  
- Writes the decrypted result to an output file.

**Final validation**:

```bash
$ python3 decrypt.py secret.enc decrypted.txt
$ diff secret.txt decrypted.txt
# (no output = identical files = success)
```

---

## Suggested difficulty levels

This checkpoint can be approached at three levels, depending on your proficiency and the time you wish to invest.

### Level 1 — Standard

Work on `crypto_O0` (non-optimized, non-stripped, dynamically linked). All symbols are visible, breakpoints are set by function name, and `ldd` + `nm` give immediate identification.

### Level 2 — Intermediate

Work on `crypto_O2_strip` (optimized, stripped, dynamically linked). Local symbols are gone, but dynamic imports (`EVP_*`) remain visible. The `-O2` optimization rearranges code and inlines some functions — the Ghidra decompiler is less readable than at `-O0`.

### Level 3 — Advanced

Work on `crypto_static` after manually stripping it (`strip crypto_static`). No symbols, no visible dynamic library. You must identify the algorithm by constants, find functions by XREF in Ghidra, and set breakpoints by address. This is the scenario closest to a real case (malware, firmware).

---

## Expected deliverables

| Deliverable | Format | Description |  
|---|---|---|  
| `decrypt.py` | Python script | Decrypts a `.enc` file in CRYPT24 format |  
| `decrypted.txt` | Text file | Result of decrypting `secret.enc` |  
| `crypt24.hexpat` | ImHex pattern | Map of the CRYPT24 format (optional but recommended) |  
| Analysis notes | Free-form text | Commands used, observations, screenshots (optional) |

---

## Quick checklist

Check off each step as you go:

- [ ] Initial triage of the binary (`file`, `checksec`, `strings`, `readelf`)  
- [ ] Algorithm identified (AES-256-CBC + SHA-256)  
- [ ] Library identified (OpenSSL)  
- [ ] AES-256 key extracted (32 bytes)  
- [ ] IV extracted (16 bytes, from memory or the `.enc` file)  
- [ ] Passphrase recovered  
- [ ] Derivation logic reconstructed (SHA-256 → XOR mask)  
- [ ] `secret.enc` format mapped (offsets, fields, sizes)  
- [ ] `decrypt.py` script written and functional  
- [ ] `diff secret.txt decrypted.txt` returns no differences  
- [ ] (Bonus) Functional `.hexpat` pattern  
- [ ] (Bonus) Script capable of *encrypting* a file in CRYPT24 format

---

## Progressive hints

If you are stuck, these hints are ordered from vaguest to most precise. Try to read only one at a time before retrying.

> **Hint 1** — The binary is dynamically linked. Even stripped, some symbols remain accessible. Which `nm` command lets you see them?

> **Hint 2** — The passphrase does not appear in `strings` because it is built in pieces in memory. But it exists in cleartext at a specific moment. Which function builds it?

> **Hint 3** — The 32-byte XOR mask is a global variable in `.rodata`. Its first bytes are `0xDE 0xAD 0xBE 0xEF`. Search for this sequence in Ghidra.

> **Hint 4** — The System V calling convention places the 4th argument in `rcx` and the 5th in `r8`. For `EVP_EncryptInit_ex`, the 4th argument is the key and the 5th is the IV.

> **Hint 5** — The ciphertext starts at offset `0x20` in the `.enc` file. Everything before that is cleartext header.

---

## What this checkpoint demonstrates

By completing this checkpoint, you have proven your ability to conduct an end-to-end crypto RE analysis on a binary compiled with GCC. You combined static analysis (constants, signatures, structures) and dynamic analysis (breakpoints, hooks, memory inspection) to extract information that neither approach alone would have been sufficient to obtain. And you translated this understanding into a functional tool — the decryption script — which is the concrete and indisputable validation of the work accomplished.

These skills are directly transferable to real-world scenarios: ransomware analysis (chapter 27), encrypted protocol auditing (chapter 23), and more generally any context where a binary manipulates protected data.

---


⏭️ [Chapter 25 — Reversing a Custom File Format](/25-fileformat/README.md)
