🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 27: Decrypt the Files and Produce a Complete Report

> **Target variant**: `ransomware_O2_strip` (optimized, without symbols).  
> This is the variant that simulates a realistic scenario. If you worked on `ransomware_O0` during the previous sections to familiarize yourself with the sample, now is the time to start from scratch on the stripped variant.  
>  
> 📁 The solution is available in `solutions/ch27-checkpoint-decryptor.py` and `solutions/ch27-checkpoint-solution.md`. Consult it **only** after completing your own analysis.

---

## Validation criteria

This checkpoint is passed when the following **four deliverables** are produced and functional:

### Deliverable 1 — Functional Python decryptor

Your script must:

- Correctly parse the `.locked` file header (magic `RWARE27\0` + original size `uint64_t` LE).  
- Decrypt the payload using AES-256-CBC with the key and IV extracted through your analysis.  
- Remove PKCS#7 padding and restore files to their exact original size.  
- Recursively process an entire directory.  
- Cleanly reject files that don't carry the correct magic header.

**Validation test**:

```bash
# 1. Prepare a clean environment
make reset

# 2. Calculate hashes of original files
find /tmp/test -type f -exec sha256sum {} \; | sort > /tmp/before.txt

# 3. Run the ransomware
./ransomware_O2_strip

# 4. Verify files are encrypted
ls /tmp/test/*.locked

# 5. Run YOUR decryptor
python3 your_decryptor.py /tmp/test/

# 6. Recalculate hashes
find /tmp/test -type f ! -name "*.locked" ! -name "README_LOCKED.txt" \
    -exec sha256sum {} \; | sort > /tmp/after.txt

# 7. Compare — no differences = success
diff /tmp/before.txt /tmp/after.txt
```

If `diff` produces no output, the restoration is bit-perfect. This is the objective success criterion for this deliverable.

### Deliverable 2 — Operational YARA rules

Your `.yar` file must contain at least two rules:

- A rule targeting the **binary** (the sample itself).  
- A rule targeting the **`.locked` files** produced.

**Validation test**:

```bash
# The binary rule must match the sample
yara your_file.yar ransomware_O2_strip
# Expected: at least one match

# The binary rule must NOT match a legitimate binary
yara your_file.yar /usr/bin/openssl
# Expected: no match

# The file rule must match .locked files
yara -r your_file.yar /tmp/test/
# Expected: one match per .locked file
```

### Deliverable 3 — Structured analysis report

Your report must contain at minimum the following sections:

- **Executive summary** — Nature of the sample, data recoverability, sophistication level.  
- **Identification** — Hashes (SHA-256 at minimum), type, dependencies.  
- **IOCs** — At least 5 indicators of compromise classified by category (file-based, behavioral).  
- **Behavioral analysis** — Description of the encryption flow, cryptographic parameters (algorithm, key, IV), produced file format.  
- **Recommendations** — At least 3 actionable recommendations.

The report must be written so that a third-party analyst, without access to your environment, can understand the sample, deploy the IOCs, and use the decryptor from reading the document alone.

### Deliverable 4 — ImHex pattern for the `.locked` format

Your `.hexpat` file must:

- Identify and colorize the magic header.  
- Extract and display the original size as a 64-bit integer.  
- Visually delimit the encrypted payload.  
- Load without errors in ImHex on any `.locked` file produced by the sample.

---

## Self-assessment checklist

This checklist lets you measure the completeness of your work before consulting the solution.

### Static analysis

| Checkpoint | ✅ / ❌ |  
|---|---|  
| I identified the encryption algorithm (AES-256-CBC) without executing the binary | |  
| I located the key in the binary (address in `.rodata` + complete hex value) | |  
| I located the IV in the binary | |  
| I reconstructed the call graph from `main` down to the EVP functions | |  
| I renamed at least 5 functions in Ghidra with meaningful names | |  
| I mapped the `.locked` format (offsets, types, sizes of each field) | |

### Dynamic analysis

| Checkpoint | ✅ / ❌ |  
|---|---|  
| I set a breakpoint on `EVP_EncryptInit_ex` and captured the key from a register | |  
| I set a breakpoint on `EVP_EncryptInit_ex` and captured the IV from a register | |  
| I verified that the key and IV are identical for each encrypted file | |  
| I confirmed the absence of network communication (via `strace` or absence of network symbols) | |  
| I used at least two different tools (GDB, Frida, ltrace, strace) | |

### Decryptor

| Checkpoint | ✅ / ❌ |  
|---|---|  
| My script parses the `.locked` header and validates the magic | |  
| My script correctly decrypts with AES-256-CBC | |  
| My script handles PKCS#7 padding | |  
| My script recursively processes a directory | |  
| Restored files are bit-for-bit identical to the originals (hash validation) | |  
| My script handles errors cleanly (corrupted file, wrong magic, empty file) | |

### YARA rules

| Checkpoint | ✅ / ❌ |  
|---|---|  
| My rule detects the sample binary | |  
| My rule does not produce false positives on `/usr/bin/openssl` | |  
| My rule detects `.locked` files | |  
| I tested my rules with the `yara` command | |

### Report

| Checkpoint | ✅ / ❌ |  
|---|---|  
| The executive summary fits in one paragraph and answers "is the data recoverable?" | |  
| SHA-256 hashes of the sample are included | |  
| At least 5 IOCs are listed and classified | |  
| Cryptographic parameters are documented with their confirmation source | |  
| The `.locked` format is described (offsets, types, sizes) | |  
| At least 3 actionable recommendations are formulated | |  
| The report is understandable by someone who didn't follow my process | |

---

## Indicative grading scale

| Level | Criteria |  
|---|---|  
| **Essential** | Functional decryptor (hash validation passed) + crypto parameters documented |  
| **Complete** | Essential + tested YARA rules + report with IOCs and recommendations |  
| **Excellent** | Complete + analysis conducted entirely on the stripped variant + ImHex pattern + automated GDB or Frida extraction script + ATT&CK matrix in the report |

---

## Common mistakes to watch for

**Forgetting the endianness of the original size.** The `original_size` field is stored in little-endian (`uint64_t` on x86-64). A `struct.unpack(">Q", ...)` (big-endian) will produce an absurd value and the decryption will "seem to work" but files will be incorrectly truncated or extended. Use `<Q`.

**Confusing block size in bits vs. bytes.** AES has a 16-byte block = 128 bits. Python's `cryptography` library expects the block size in **bits** in `padding.PKCS7(128)`. Writing `PKCS7(16)` will cause a silent error or incorrect padding removal.

**Neglecting the 16-byte header.** If you pass the entire `.locked` file (including the 16-byte header) to the AES decryption routine, the result will be incoherent. The ciphertext starts at offset `0x10`, not `0x00`.

**Setting a breakpoint on the wrong function.** On the stripped variant, `break main` may not work (symbol absent). However, `break EVP_EncryptInit_ex` always works because it's a dynamic symbol. If GDB asks to make the breakpoint *pending*, answer `y` — it will be resolved when `libcrypto.so` is loaded.

**Writing a purely descriptive report.** A report that says "the malware encrypts files with AES" without specifying the key, the IV, the extraction method, and without providing a decryptor is not actionable. The value of a malware report lies in its **concrete deliverables**: deployable IOCs, YARA rules, remediation tool.

---

## Going further

If you have completed this checkpoint and want to go deeper, here are extension paths that don't require a new chapter:

**Modify the sample and start over.** Change the key and IV in the source code, recompile, and redo the complete analysis on the new binary without looking at the sources. Verify that your generic YARA rules still detect the modified variant.

**Add packing.** Compress the binary with UPX (`upx ransomware_O2_strip`), then attempt the analysis. Which steps are blocked? How do you unpack before analyzing? This scenario directly connects to [Chapter 29 — Unpacking](/29-unpacking/README.md).

**Compare with a real public report.** Consult reports published by threat intelligence teams (Mandiant, CrowdStrike, Kaspersky GReAT, CISA) on real ransomware. Compare their structure with your report: what sections do they add? What level of detail do they provide on cryptography? How do they present IOCs?

**Automate the complete pipeline.** Write a single script that takes a suspicious binary as input and automatically produces: the triage (`file`, `strings`, `checksec`), extraction of interesting strings, a structured JSON report. This automation work prepares for [Chapter 35 — Automation and Scripting](/35-automation-scripting/README.md).

⏭️ [Chapter 28 — Analysis of an ELF Dropper with Network Communication](/28-dropper/README.md)
