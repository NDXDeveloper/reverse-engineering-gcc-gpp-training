🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.7 — Writing a Standard Analysis Report (IOC, Behavior, Recommendations)

> 🎯 **Goal of this section**: formalize the entirety of the analysis conducted since section 27.2 into a **structured report**, such as an incident response analyst would produce for their team, management, or a client. The report is the final deliverable of any malware analysis — it's what transforms individual technical work into actionable information for an organization.  
>  
> This section first presents the principles of writing an analysis report, then provides a **complete template** filled with the results of our Ch27 sample analysis.

---

## Why write a report

The most brilliant technical analysis has no value if it stays in the analyst's head or scattered across informal notes. The report serves three distinct functions depending on its audience:

**For the technical team (SOC, CERT, IR)** — The report provides the IOCs needed to detect the sample on other machines, immediately deployable YARA rules, and the decryptor to restore files. It's an operational tool.

**For management and decision makers** — The executive summary translates the technical analysis into business impact: how many files affected, is the data recoverable, what is the attacker's sophistication level, should the ransom be paid. It's a decision-making tool.

**For the community (national CERTs, sector partners, threat intelligence databases)** — The IOCs, YARA rules, and behavioral description feed shared signature databases. It's a collective defense tool.

A good report must serve all three audiences within a single document, through a layered structure: executive summary (non-technical) at the top, technical details in the body, technical annexes at the end.

---

## Writing principles

### Clarity and precision

Every statement in the report must be backed by an identifiable piece of evidence. Avoid vague formulations like "the malware seems to use encryption." Prefer "the binary calls `EVP_aes_256_cbc()` (XREF at offset `0x001013c5`), confirmed by capturing register `rcx` during the GDB breakpoint on `EVP_EncryptInit_ex`." Precision allows a peer to **reproduce** each conclusion.

### Separating facts from interpretations

Always distinguish what you **observed** (fact) from what you **infer** (interpretation). For example: "The binary contains no calls to `socket`, `connect`, or `send` in its dynamic symbol table (fact). This suggests the absence of network communication (interpretation), confirmed by a silent `strace` trace on network syscalls (supporting fact)." This rigor protects the report against challenges and guides the reader's own reasoning.

### Confidence levels

Assign a confidence level to each conclusion. Standardized terminology in threat intelligence uses a scale like this:

| Level | Meaning | Example in our analysis |  
|---|---|---|  
| **Confirmed** | Directly observed, reproducible | "The AES key is `REVERSE_ENGINEERING_IS_FUN_2025!`" |  
| **Highly likely** | Multiple converging indicators, no direct observation of an alternative | "The sample does not communicate over the network" |  
| **Likely** | Solid indicators but alternative scenarios possible | "The sample only targets `/tmp/test/`" (an alternative mode could exist) |  
| **Possible** | Plausible hypothesis, limited indicators | "The author is a security student (pedagogical context)" |

### Progressive structure

The report reads top to bottom, from most synthetic to most detailed. A busy reader stops at the executive summary. A technical analyst goes down to the annexes. Nobody should have to read everything to find the information they need.

---

## Report template — filled with our analysis

What follows is a complete report, written as if we were an analyst reporting on a real incident. Students can use it as a template for their own future analyses by replacing the Ch27-specific content with their own results.

---

> # MALWARE ANALYSIS REPORT  
>  
> | Field | Value |  
> |---|---|  
> | **Reference** | MAL-2025-CH27-001 |  
> | **Classification** | TLP:WHITE — Unrestricted distribution |  
> | **Analysis date** | [Today's date] |  
> | **Analyst** | [Your name / handle] |  
> | **Primary tools** | Ghidra 11.x, GDB 14.x, Frida 16.x, ImHex 1.3x |  
> | **Environment** | Ubuntu 24.04 LTS, isolated QEMU/KVM VM, network disconnected |  
> | **Revision** | 1.0 |

---

> ## 1. Executive Summary  
>  
> The analyzed sample is a **Linux ELF ransomware** targeting the `/tmp/test/` directory. It recursively encrypts files using the **AES-256-CBC** algorithm via the OpenSSL library, replaces the originals with files bearing the `.locked` extension, then drops a ransom note.  
>  
> **Key finding: files are fully recoverable.** The encryption key is hardcoded in the binary and was extracted through static and dynamic analysis. A functional decryption tool has been produced and validated.  
>  
> The sample exhibits no network communication, no persistence mechanism, and no evasion or anti-analysis techniques. Its sophistication is **low**. It does not constitute an advanced threat, but its destructive encryption behavior makes it dangerous for unbackup data within the targeted scope.  
>  
> **Immediate recommendation**: deploy the decryptor (Annex C) on affected systems and scan the infrastructure with the provided YARA rules (Annex D) to identify any other compromised machines.

---

> ## 2. Sample Identification  
>  
> | Property | Value |  
> |---|---|  
> | **Filename** | `ransomware_O2_strip` |  
> | **Type** | ELF 64-bit LSB PIE executable, x86-64, dynamically linked, stripped |  
> | **SHA-256** | `[insert hash — sha256sum ransomware_O2_strip]` |  
> | **SHA-1** | `[insert]` |  
> | **MD5** | `[insert]` |  
> | **Size** | [insert] bytes |  
> | **Compiler** | GCC (GNU Compiler Collection), standard Linux toolchain |  
> | **Dependencies** | `libssl.so.3`, `libcrypto.so.3`, `libc.so.6` |  
> | **Binary protections** | PIE enabled, NX enabled, Stack canary present, Partial RELRO |  
> | **First VT submission** | N/A (pedagogical sample, not submitted) |

---

> ## 3. Indicators of Compromise (IOC)  
>  
> ### 3.1 File-based IOCs  
>  
> | Type | Value | Context |  
> |---|---|---|  
> | SHA-256 | `[binary hash]` | Hash of the analyzed sample |  
> | Filename | `README_LOCKED.txt` | Ransom note dropped by the sample |  
> | Extension | `.locked` | Extension appended to encrypted files |  
> | Magic bytes (binary) | `7F 45 4C 46` (ELF) | Sample header |  
> | Magic bytes (produced files) | `52 57 41 52 45 32 37 00` (`RWARE27\0`) | Encrypted file header |  
> | Characteristic string | `REVERSE_ENGINEERING_IS_FUN_2025!` | AES key in `.rodata` |  
> | Characteristic string | `YOUR FILES HAVE BEEN ENCRYPTED` | Ransom note fragment |  
>  
> ### 3.2 Behavioral IOCs  
>  
> | Type | Value | Context |  
> |---|---|---|  
> | Targeted directory | `/tmp/test/` | Only directory traversed |  
> | File operation | Recursive traversal (`opendir`/`readdir`/`stat`) | Directory tree enumeration |  
> | File operation | Full read (`fopen`/`fread`) → write `.locked` → delete original (`unlink`) | Encryption/replacement cycle |  
> | Crypto API | `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex` | AES-256-CBC encryption via OpenSSL |  
> | No network | No `socket`/`connect`/`send`/`recv` calls | No exfiltration, no C2 |  
> | No persistence | No writes to crontab, systemd, `.bashrc`, `/etc/init.d` | Single execution |  
>  
> ### 3.3 Network-based IOCs  
>  
> None. The sample performs no network communication. This absence was confirmed by static analysis (no network symbols in `.dynsym`) and dynamic analysis (silent `strace -e trace=network`).

---

> ## 4. Detailed Behavioral Analysis  
>  
> ### 4.1 Execution Flow  
>  
> The program follows a linear flow in five phases:  
>  
> **Phase 1 — Initialization.** The sample displays a banner on `stdout` then verifies the existence of the `/tmp/test/` directory via a `stat()` call. If the directory does not exist, the program stops with an error message. This check constitutes an unintentional safeguard: the sample cannot encrypt files outside this directory tree.  
>  
> **Phase 2 — Enumeration.** The recursive traversal function (`traverse_directory`) uses `opendir`/`readdir` to list the contents of `/tmp/test/` and its subdirectories. Each entry is filtered: `.locked` files (already encrypted) and `README_LOCKED.txt` (ransom note) are skipped. Directories trigger a recursive call. Regular files are passed to the encryption routine.  
>  
> **Phase 3 — Encryption.** For each targeted file, the `encrypt_file` function executes the following sequence:  
>  
> 1. Full file read into memory (`fopen` / `fseek` / `ftell` / `fread`).  
> 2. Allocation of an output buffer of size `file_size + 16` (AES padding).  
> 3. Encryption via the OpenSSL EVP API: `EVP_EncryptInit_ex` (AES-256-CBC with static key and IV) → `EVP_EncryptUpdate` → `EVP_EncryptFinal_ex`.  
> 4. Writing the `.locked` file: 16-byte header (magic `RWARE27\0` + original size as `uint64_t` LE) followed by the ciphertext.  
> 5. Deletion of the original file via `unlink()`.  
>  
> **Phase 4 — Ransom note.** After encrypting all files, the `drop_ransom_note` function writes `README_LOCKED.txt` at the root of `/tmp/test/`. The text mentions the algorithm used (AES-256-CBC) and provides a hint about the key's location.  
>  
> **Phase 5 — Termination.** The sample displays the number of encrypted files and terminates normally (`exit(0)`). No persistence mechanism is established.  
>  
> ### 4.2 Cryptographic Analysis  
>  
> | Parameter | Value | Confirmation method |  
> |---|---|---|  
> | Algorithm | AES-256-CBC | XREF to `EVP_aes_256_cbc()` (Ghidra) + call observed (GDB/Frida) |  
> | Key | `52455645...30323521` (ASCII: `REVERSE_ENGINEERING_IS_FUN_2025!`) | `rcx` argument of `EVP_EncryptInit_ex` (GDB/Frida) |  
> | IV | `DEADBEEFCAFEBABE13374242FEEDFACE` | `r8` argument of `EVP_EncryptInit_ex` (GDB/Frida) |  
> | Padding | PKCS#7 (OpenSSL default) | Ciphertext size = ⌈plaintext_size / 16⌉ × 16 |  
> | Key rotation | None | 6 calls captured, key and IV identical at each call |  
> | Key derivation | None | Key used raw from `.rodata`, no call to PBKDF2/scrypt |  
>  
> **Cryptographic robustness assessment: LOW.** The key is static, in cleartext in the binary, and identical for all potential victims. The IV is static and reused for each file, allowing pattern analysis on the first encrypted blocks. Data recovery is trivial for anyone possessing the binary.  
>  
> ### 4.3 Encrypted File Format  
>  
> ```  
> Offset    Size      Type           Content  
> ─────────────────────────────────────────────────────  
> 0x00      8         char[8]        Magic: "RWARE27\0"  
> 0x08      8         uint64_t LE    Original file size  
> 0x10      variable  byte[]         AES-256-CBC ciphertext (PKCS#7 padding included)  
> ```  
>  
> An ImHex pattern (`.hexpat`) and a YARA detection rule are provided in the annexes.  
>  
> ### 4.4 Evasion and Anti-Analysis Techniques  
>  
> **No evasion techniques were identified.** The sample does not detect debuggers (`ptrace`, timing checks), does not check its execution environment (VM detection), does not use packing or control flow obfuscation. The binary is stripped (internal symbols removed), but dynamic symbols remain intact, which constitutes minimal protection.

---

> ## 5. Threat Assessment  
>  
> ### 5.1 Classification  
>  
> | Criterion | Assessment |  
> |---|---|  
> | **Type** | Ransomware — file encryption |  
> | **Family** | Unknown (unique sample, pedagogical context) |  
> | **Target** | Linux x86-64, `/tmp/test/` directory |  
> | **Sophistication** | Low |  
> | **Potential impact** | Moderate (data destruction within targeted scope) |  
> | **Recoverability** | Full (key extracted, functional decryptor) |  
>  
> ### 5.2 ATT&CK Matrix  
>  
> | Tactic | Technique | ID | Details |  
> |---|---|---|---|  
> | Execution | User Execution | T1204 | Sample must be manually executed |  
> | Discovery | File and Directory Discovery | T1083 | Recursive traversal of `/tmp/test/` |  
> | Impact | Data Encrypted for Impact | T1486 | AES-256-CBC file encryption |  
> | Impact | Data Destruction | T1485 | Deletion of original files (`unlink`) |  
>  
> The small number of techniques employed confirms the sample's limited sophistication. Notable absences include Defense Evasion techniques (T1027 Obfuscated Files, T1140 Deobfuscate/Decode), Persistence (T1053 Scheduled Task, T1543 Create System Service), and Command and Control.

---

> ## 6. Recommendations  
>  
> ### 6.1 Immediate Actions (incident response)  
>  
> **R1 — Deploy the decryptor.** Run `decryptor.py` (Annex C) on all affected systems to restore files. Validate integrity through SHA-256 hash comparison with available backups.  
>  
> **R2 — Scan the infrastructure.** Deploy the YARA rules (Annex D) on endpoints via the existing EDR to identify any other compromised machines. Scan with the `ransomware_ch27_locked_file` rule to inventory encrypted files, and with `ransomware_ch27_exact` to locate the binary.  
>  
> **R3 — Preserve evidence.** Before any restoration, capture a forensic image of affected systems (disk + memory). Retain the binary, `.locked` files, and ransom note as evidence.  
>  
> **R4 — Identify the infection vector.** The sample analysis does not reveal how it was deposited on the system. Examine SSH access logs, bash histories, authentication journals, and any recent downloads to reconstruct the initial attack chain.  
>  
> ### 6.2 Remediation Actions (short term)  
>  
> **R5 — Reset access credentials.** Change passwords and SSH keys for accounts with access to affected systems. Revoke any suspicious active sessions.  
>  
> **R6 — Audit permissions.** Verify that sensitive directories are not writable by unprivileged accounts. Apply the principle of least privilege.  
>  
> **R7 — Update signatures.** Integrate the IOCs (section 3) and YARA rules (Annex D) into the organization's detection tools (EDR, SIEM, antivirus).  
>  
> ### 6.3 Hardening Actions (long term)  
>  
> **R8 — Backups.** Verify that offline (air-gapped) backups exist for critical data. Regularly test the restoration procedure. An untested backup is not a backup.  
>  
> **R9 — Filesystem monitoring.** Deploy monitoring for abnormal mass file operations: rapid creation of numerous files with an unusual extension, serial deletion, CPU usage spikes related to encryption. Tools like `auditd`, `inotifywait`, or Sysmon rules (on Windows/Linux endpoints) can detect this pattern.  
>  
> **R10 — Segmentation.** Isolate sensitive data partitions with read-only mounts when writing is not necessary. Restrict directory access with granular ACLs.

---

> ## 7. Annexes  
>  
> ### Annex A — Call Graph  
>  
> *(Insert the call graph reconstructed in Ghidra — section 27.3)*  
>  
> ### Annex B — ImHex Pattern for the `.locked` Format  
>  
> *(Insert the complete `.hexpat` pattern — section 27.3, Part B)*  
>  
> ### Annex C — Python Decryptor  
>  
> *(Insert or reference `solutions/ch27-checkpoint-decryptor.py` — section 27.6)*  
>  
> Usage:  
> ```bash  
> pip install cryptography  
> python3 decryptor.py /tmp/test/          # decrypt the entire directory  
> python3 decryptor.py file.txt.locked     # decrypt a single file  
> python3 decryptor.py --dry-run           # simulate without writing  
> ```  
>  
> ### Annex D — YARA Rules  
>  
> *(Insert the file `yara-rules/ransomware_ch27.yar` — section 27.4)*  
>  
> Three rules:  
> - `ransomware_ch27_exact` — Exact sample detection  
> - `ransomware_ch27_generic` — Variant detection by behavioral pattern  
> - `ransomware_ch27_locked_file` — Detection of produced encrypted files  
>  
> ### Annex E — Execution Traces  
>  
> *(Insert relevant excerpts from GDB, Frida, and strace logs — section 27.5)*  
>  
> ### Annex F — Analysis Timeline  
>  
> | Step | Estimated duration | Tools | Key result |  
> |---|---|---|---|  
> | Quick triage | 10 min | `file`, `strings`, `checksec`, `ldd`, `readelf` | Hypotheses H1–H8 formulated |  
> | Static analysis | 45 min | Ghidra, ImHex | Complete call graph, key/IV located, `.locked` format mapped |  
> | YARA rules | 20 min | ImHex, YARA | 3 operational detection rules |  
> | Dynamic analysis | 30 min | GDB, Frida, `strace` | Definitive confirmation of key/IV/behavior |  
> | Decryptor | 30 min | Python, `cryptography` | Functional script, hash-validated |  
> | Report | 30 min | — | This document |  
> | **Total** | **~2h45** | | |

---

## Tips for your future reports

### Adapt the level of detail to the audience

The template above is intentionally comprehensive. In practice, adapt the granularity to the context. An internal report for a company's IR team can be more technical and less formal. A report intended for a national CERT or sector sharing (ISAC) will be more structured and follow community conventions (STIX/TAXII for IOCs, TLP for classification, MITRE ATT&CK for taxonomy).

### Use a consistent referencing system

Number your IOCs, recommendations, and annexes. When the report is discussed in a meeting, being able to say "see IOC-3" or "apply R7" is infinitely more effective than "the YARA rule I was talking about earlier."

### Include limitations and open questions

An honest report mentions what it doesn't know. In our case: the initial infection vector is unknown (R4), and we cannot rule out the existence of variants with different keys (the generic YARA rule covers this risk, but without certainty). Mentioning these blind spots strengthens the report's credibility rather than weakening it.

### Version the report

Use a revision number and date. The analysis may evolve: a sample variant could appear, a new infection vector could be identified, or an error could be corrected. A versioned report allows tracking these evolutions without ambiguity.

### Archive the complete case file

The report alone is not sufficient. Archive the entire analysis case file in a structured directory:

```
analysis-MAL-2025-CH27-001/
├── report.md                      ← The final report
├── sample/
│   ├── ransomware_O2_strip        ← The analyzed binary
│   └── sha256sums.txt             ← Reference hashes
├── ghidra/
│   └── Ch27-Ransomware.gpr        ← Ghidra project with renames
├── imhex/
│   ├── locked_format.hexpat        ← .locked format pattern
│   └── crypto_constants.hexpat     ← Constants pattern in the ELF
├── yara/
│   └── ransomware_ch27.yar         ← YARA rules
├── scripts/
│   ├── decryptor.py                ← Decryptor
│   ├── extract_crypto_params.py    ← GDB Python script
│   ├── hook_evp.js                 ← Frida script
│   └── hook_evp_full.js            ← Extended Frida script
├── traces/
│   ├── strace_output.txt           ← Complete strace trace
│   ├── frida_log.txt               ← Frida output
│   └── crypto_params.json          ← GDB export of crypto parameters
└── locked_samples/
    ├── document.txt.locked         ← Encrypted file samples
    └── budget.csv.locked
```

This directory structure allows an analyst to pick up the case file months later, or a peer to reproduce and verify each conclusion in the report.

---

## What this report teaches you about the discipline

Beyond the technical content, writing this report illustrates several fundamental aspects of the analyst profession:

**Traceability is non-negotiable.** Every statement refers to evidence. Every piece of evidence is reproducible. Every tool and its version are documented. This rigor protects the analyst and the organization — legally in case of dispute, technically in case of challenge.

**The analysis is not finished until the report is written.** The temptation is strong to stop once the decryptor works. But without a report, IOCs are not shared, recommendations are not issued, and knowledge remains individual. The report is what transforms technical skill into organizational value.

**The report is a living deliverable.** It will be reread, critiqued, supplemented, updated. Write it for your future self as much as for your immediate readers. In six months, when a variant appears, you'll be grateful you documented every decision and observation.

⏭️ [Checkpoint: decrypt the files and produce a complete report](/27-ransomware/checkpoint.md)
