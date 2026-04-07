🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 27 — Analysis of a Linux ELF Ransomware (self-compiled with GCC)

> ⚠️ **Warning — Controlled environment required**  
>  
> The binary studied in this chapter is an **educational sample created by us**, compiled with GCC, whose source code is provided and auditable. It is in no way real malware. Nevertheless, its behavior — encrypting files on disk — is destructive by nature.  
>  
> **Never run it outside the sandboxed VM configured in [Chapter 26](/26-secure-lab/README.md).** Always restore a clean snapshot after each execution.

---

## Why analyze a ransomware?

Ransomware is one of the most widespread and costly threats in today's cyber landscape. For a reverse engineering analyst, being able to dissect a ransomware sample means being able to answer three critical questions during an incident:

1. **What encryption algorithm is used, and how?** — Identifying the crypto routine determines whether decryption is feasible without paying the ransom.  
2. **Is the key recoverable?** — A hardcoded key, a poorly seeded random number generator, or a key transmitted in cleartext over the network are all exploitable weaknesses.  
3. **What is the scope of impact?** — Which directories are targeted, which extensions, which volumes? This information is essential for assessing damage and guiding incident response.

This chapter puts you in the shoes of an analyst who receives a suspicious ELF binary and must produce a complete report along with a decryption tool, leveraging all the techniques acquired since the beginning of this training.

---

## Introducing the `ch27-ransomware` sample

The binary we will study is intentionally realistic in its logic while remaining simple in its implementation, in order to stay pedagogically accessible. Here are its general characteristics (which you will discover for yourself throughout the analysis):

- **Language**: C, compiled with GCC.  
- **Target**: files located in `/tmp/test/` only (limited scope for lab safety).  
- **Algorithm**: AES symmetric encryption (the exact variant — mode, key size — is part of the analysis).  
- **Key management**: the key is hardcoded in the binary (intentionally, to allow its recovery).  
- **Post-encryption behavior**: original files are replaced by their encrypted version, with an appended extension.

The source code (`binaries/ch27-ransomware/ransomware_sample.c`) and associated `Makefile` are provided in the repository. Several binary variants are available:

| Variant | Optimization | Symbols | File |  
|---|---|---|---|  
| Debug | `-O0` | Yes (`-g`) | `ransomware_O0` |  
| Optimized | `-O2` | Yes | `ransomware_O2` |  
| Stripped | `-O2` | No (`strip`) | `ransomware_O2_strip` |

We recommend starting the analysis on the debug variant (`ransomware_O0`) to establish a reference understanding, then comparing it against the stripped variant to practice analysis without a safety net.

---

## What this chapter draws upon

This chapter is designed as an integration exercise. It draws on skills and tools from previous parts:

- **Quick triage** ([Chapter 5](/05-basic-inspection-tools/README.md)) — `file`, `strings`, `checksec` for initial hypotheses.  
- **Hexadecimal analysis** ([Chapter 6](/06-imhex/README.md)) — ImHex to spot cryptographic constants and visualize internal structures.  
- **Disassembly and decompilation** ([Chapters 7–9](/07-objdump-binutils/README.md)) — Ghidra to reconstruct the encryption flow.  
- **Crypto pattern detection** ([Chapter 24](/24-crypto/README.md)) — identification of magic constants (AES S-box, IV…) and associated routines.  
- **YARA rules** ([Chapter 35](/35-automation-scripting/README.md)) — writing signatures to detect this type of sample in a binary collection.  
- **Dynamic analysis with GDB and Frida** ([Chapters 11–13](/11-gdb/README.md)) — extracting the key and IV from memory at runtime.  
- **Python scripting** — writing a functional decryptor.  
- **Report writing** — producing a structured deliverable including IOCs (Indicators of Compromise), observed behavior, and recommendations.

---

## Methodology followed in this chapter

The analysis unfolds in seven sequential steps, each corresponding to a section of the chapter:

```
27.1  Sample design
 │    Understand what we're analyzing and why it's built this way.
 ▼
27.2  Quick triage
 │    file, strings, checksec → initial hypotheses.
 ▼
27.3  Static analysis (Ghidra + ImHex)
 │    Spot AES constants, reconstruct the encryption flow.
 ▼
27.4  YARA rules
 │    Write detection signatures from ImHex.
 ▼
27.5  Dynamic analysis (GDB + Frida)
 │    Confirm hypotheses, extract the key from memory.
 ▼
27.6  Writing the Python decryptor
 │    Reproduce the crypto scheme in reverse.
 ▼
27.7  Analysis report
      Formalize the results into a professional deliverable.
```

This progression reflects a realistic malware analysis workflow: you always start with the least risky triage (static, without execution), formulate hypotheses, then confirm them dynamically in a controlled environment.

---

## Prerequisites

Before tackling this chapter, make sure:

- You have configured and validated your **secure analysis lab** ([Chapter 26](/26-secure-lab/README.md)) — isolated VM, working snapshots, network disconnected.  
- You are comfortable with **Ghidra** ([Chapter 8](/08-ghidra/README.md)) and **GDB** ([Chapter 11](/11-gdb/README.md)).  
- You have gone through **Chapter 24** (reversing encrypted binaries), particularly identifying cryptographic constants and extracting keys.  
- You have compiled the chapter binaries: from the `binaries/ch27-ransomware/` directory, run `make all`.

---

## Chapter outline

- 27.1 [Sample design: AES encryption on `/tmp/test`, hardcoded key](/27-ransomware/01-sample-design.md)  
- 27.2 [Quick triage: `file`, `strings`, `checksec`, initial hypotheses](/27-ransomware/02-quick-triage.md)  
- 27.3 [Static analysis: Ghidra + ImHex (spotting AES constants, encryption flow)](/27-ransomware/03-static-analysis-ghidra-imhex.md)  
- 27.4 [Identifying corresponding YARA rules from ImHex](/27-ransomware/04-yara-rules.md)  
- 27.5 [Dynamic analysis: GDB + Frida (extracting the key from memory)](/27-ransomware/05-dynamic-analysis-gdb-frida.md)  
- 27.6 [Writing the Python decryptor](/27-ransomware/06-python-decryptor.md)  
- 27.7 [Writing a standard analysis report (IOC, behavior, recommendations)](/27-ransomware/07-analysis-report.md)  
- 🎯 **Checkpoint**: [decrypt the files and produce a complete report](/27-ransomware/checkpoint.md)

⏭️ [Sample design: AES encryption on `/tmp/test`, hardcoded key](/27-ransomware/01-sample-design.md)
