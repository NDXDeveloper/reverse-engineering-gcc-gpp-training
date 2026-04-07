# Reverse Engineering Training — GNU Toolchain (GCC/G++)

> **This content is strictly educational and ethical.**  
> See [LICENSE](/LICENSE) for the full terms of use.

Comprehensive training on the **Reverse Engineering** of native binaries compiled with the GNU toolchain (GCC/G++), enriched with bonus modules on **.NET/C#**, **Rust**, and **Go** binaries.

**36 chapters** · **9 parts** · **~120 hours** of content · **20+ training binaries** · **Checkpoints with solutions**

---

## 🎯 Objectives

By the end of this training, you will be able to:

- Understand the internal structure of an ELF binary produced by GCC/G++  
- Conduct a complete static analysis (disassembly, decompilation, hex inspection, diffing)  
- Conduct dynamic analysis (GDB debugging, Frida hooking, AFL++ fuzzing, angr/Z3 symbolic execution)  
- Reverse complex C++ (vtables, RTTI, name mangling, STL, templates, smart pointers)  
- Identify and bypass common protections (ASLR, PIE, canaries, RELRO, UPX, obfuscation)  
- Analyze malicious code in an isolated environment (ransomware, dropper, packing)  
- Apply these techniques to .NET/C# binaries (dnSpy, ILSpy, Frida-CLR)  
- Approach the RE of Rust and Go binaries (name mangling, runtime, specific structures)  
- Automate your RE workflows (Python scripts, Ghidra headless, YARA rules, CI/CD pipelines)

---

## 👥 Target audience

| Profile | Prerequisites |  
|:---|:---|  
| C/C++ developer wanting to understand their binaries | C/C++ basics |  
| .NET/C# developer curious about RE | C# basics + notions of compilation |  
| Rust/Go developer facing RE | Language basics + ELF notions |  
| Cybersecurity student | Linux basics + command line |  
| Beginner/intermediate CTF participant | No RE prerequisites |

---

## 📦 Repository structure

```
reverse-engineering-gcc-gpp-training/
├── README.md                        ← This file
├── TABLE-OF-CONTENTS.md             ← Detailed table of contents (36 chapters)
├── LICENSE                          ← MIT + ethical disclaimer
├── check_env.sh                     ← Environment verification script
│
├── preface.md                       ← Tutorial preface
├── part-1-fundamentals.md           ← Part I introduction
├── part-2-static-analysis.md        ← Part II introduction
├── ...                              ← (one intro page per part)
├── part-9-resources.md              ← Part IX introduction
│
├── 01-introduction-re/              ← Chapter 1 — Introduction to RE
│   ├── README.md
│   ├── 01-definition-objectives.md
│   ├── ...
│   └── checkpoint.md
├── 02-gnu-compilation-chain/        ← Chapter 2 — GNU Compilation Chain
├── ...                              ← Chapters 3 through 36 (same structure)
├── 36-resources-further-learning/   ← Chapter 36 — Resources for further learning
│
├── appendices/                      ← Appendices A through K
│   ├── README.md
│   └── ...
│
├── binaries/                        ← All training binaries
│   ├── Makefile                     ← `make all` to recompile everything
│   ├── ch05-keygenme/               ← Chapters 5–6 (triage, ImHex)
│   ├── ch06-fileformat/
│   ├── ch08-oop/
│   ├── ch16-optimisations/          ← Chapter 16 (GCC optimizations)
│   ├── ch17-oop/                    ← Chapter 17 (C++ RE)
│   ├── ch20-keygenme/               ← Chapter 20 (decompilation)
│   ├── ch20-network/
│   ├── ch20-oop/
│   ├── ch21-keygenme/               ← Chapter 21 (keygenme practical case)
│   ├── ch22-oop/                    ← Chapter 22 (OOP + plugins practical case)
│   ├── ch23-network/                ← Chapter 23 (network practical case)
│   ├── ch24-crypto/                 ← Chapter 24 (crypto practical case)
│   ├── ch25-fileformat/             ← Chapter 25 (file format practical case)
│   ├── ch27-ransomware/             ← ⚠️ Sandbox only
│   ├── ch28-dropper/                ← ⚠️ Sandbox only
│   ├── ch29-packed/                 ← Chapter 29 (packing/unpacking)
│   ├── ch32-dotnet/                 ← Chapter 32 (.NET LicenseChecker)
│   ├── ch33-rust/                   ← Chapter 33 (Rust crackme)
│   └── ch34-go/                     ← Chapter 34 (Go crackme)
│
├── scripts/                         ← Python utility scripts
│   ├── triage.py                    ← Automatic binary triage
│   ├── keygen_template.py           ← pwntools keygen template
│   └── batch_analyze.py             ← Ghidra headless batch analysis
│
├── hexpat/                          ← ImHex patterns (.hexpat)
│   ├── elf_header.hexpat            ← Generic ELF header
│   ├── ch06_fileformat.hexpat       ← CDB format (chapter 6)
│   ├── ch23_protocol.hexpat         ← ch23 network protocol
│   ├── ch24_crypt24.hexpat          ← CRYPT24 format (chapter 24)
│   └── ch25_fileformat.hexpat       ← CFR format (chapter 25)
│
├── yara-rules/                      ← YARA rules
│   ├── crypto_constants.yar         ← Crypto constants detection (AES, SHA, MD5…)
│   └── packer_signatures.yar        ← Packer signatures (UPX…)
│
└── solutions/                       ← Checkpoint solutions (⚠️ spoilers)
    ├── ch01-checkpoint-solution.md
    ├── ch02-checkpoint-solution.md
    ├── ...
    ├── ch21-checkpoint-keygen.py
    ├── ch22-checkpoint-plugin.cpp
    ├── ch23-checkpoint-client.py
    ├── ch24-checkpoint-decrypt.py
    ├── ch25-checkpoint-parser.py
    ├── ch25-checkpoint-solution.hexpat
    ├── ch27-checkpoint-decryptor.py
    ├── ch28-checkpoint-fake-c2.py
    ├── ch34-checkpoint-solution.md
    └── ch35-checkpoint-batch.py
```

---

## 🛠️ Tools used

### Static analysis

| Tool | Role | Free |  
|:---|:---|:---:|  
| `readelf`, `objdump`, `nm` | ELF / Binutils inspection | ✅ |  
| `checksec` | Protection inventory | ✅ |  
| `strace` / `ltrace` | System and library calls | ✅ |  
| **ImHex** | Advanced hex editor + `.hexpat` patterns + YARA | ✅ |  
| **Ghidra** | Disassembler / decompiler (NSA) | ✅ |  
| **Radare2 / Cutter** | CLI + GUI analysis (based on Rizin) | ✅ |  
| IDA Free | Reference disassembler (free version) | ✅ |  
| Binary Ninja Cloud | Modern disassembler (free cloud version) | ✅ |  
| **BinDiff** / Diaphora | Binary diffing | ✅ |  
| **RetDec** | Offline static decompiler (CLI) | ✅ |

### Dynamic analysis

| Tool | Role | Free |  
|:---|:---|:---:|  
| **GDB** + GEF / pwndbg / PEDA | Enhanced native debugging | ✅ |  
| **Frida** | Dynamic instrumentation + hooking | ✅ |  
| `pwntools` | Scripting interactions with a binary | ✅ |  
| Valgrind / ASan / UBSan / MSan | Memory and runtime behavior analysis | ✅ |  
| **AFL++** / libFuzzer | Coverage-guided fuzzing | ✅ |  
| **angr** | Symbolic execution | ✅ |  
| **Z3** | Constraint solver (SMT) | ✅ |

### .NET / C# reversing

| Tool | Role | Free |  
|:---|:---|:---:|  
| **dnSpy / dnSpyEx** | Integrated .NET decompilation + debugging | ✅ |  
| **ILSpy** | Open source C# decompilation | ✅ |  
| dotPeek | JetBrains decompilation | ✅ |  
| de4dot | .NET assembly deobfuscation | ✅ |  
| Frida-CLR | .NET method hooking | ✅ |

---

## 🚀 Quick start

### 1. Clone the repository

```bash
git clone https://github.com/NDXDeveloper/reverse-engineering-gcc-gpp-training.git  
cd reverse-engineering-gcc-gpp-training  
```

### 2. Install essential dependencies (Debian/Ubuntu/Kali)

```bash
sudo apt update && sudo apt install -y \
    gcc g++ make gdb ltrace strace binutils \
    bsdextrautils checksec valgrind python3-pip binwalk

pip3 install pwntools pyelftools lief frida-tools angr

# AFL++
sudo apt install -y afl++
```

> 💡 For Ghidra, ImHex, and GUI tools, see **[Chapter 4](/04-work-environment/README.md)**, which details the installation step by step.

### 3. Verify the environment

```bash
chmod +x check_env.sh
./check_env.sh
```

This script verifies that all required tools are installed and functional.

### 4. Compile all training binaries

```bash
cd binaries/  
make all  
```

Each chapter's `Makefile` produces several variants:

```
*_O0          ← no optimization, with symbols (-O0 -g)
*_O2          ← -O2 optimized, with symbols
*_O3          ← -O3 optimized, with symbols
*_strip       ← stripped (no symbols, -O0 -s)
*_O2_strip    ← optimized + stripped (most realistic case)
```

### 5. Start the training

```bash
# Open the detailed table of contents
xdg-open TABLE-OF-CONTENTS.md
```

Or start directly with **[Chapter 1 — What is RE?](/01-introduction-re/README.md)**

---

## ⚠️ Warning — Part VI (Malware)

The binaries of chapters 27 and 28 (`ch27-ransomware/`, `ch28-dropper/`) are **intentionally limited educational prototypes**:

- The ransomware encrypts only `/tmp/test/` with a hardcoded AES key  
- The dropper only communicates with `127.0.0.1:4444`, without persistence  
- **Never compile or run them outside a snapshotted VM isolated from the network**

**[Chapter 26](/26-secure-lab/README.md)** details the setup of the secure lab — it must be completed before any work on chapters 27-29.

---

## 📚 Table of contents

| Part | Content | Chapters |  
|:---|:---|:---:|  
| **[I](/part-1-fundamentals.md)** — Fundamentals | Intro RE, GNU toolchain, x86-64 assembly, environment | 1 – 4 |  
| **[II](/part-2-static-analysis.md)** — Static Analysis | Binutils, ImHex, objdump, Ghidra, IDA, Radare2, Binary Ninja, diffing | 5 – 10 |  
| **[III](/part-3-dynamic-analysis.md)** — Dynamic Analysis | GDB, GEF/pwndbg, Frida, Valgrind/Sanitizers, AFL++/libFuzzer | 11 – 15 |  
| **[IV](/part-4-advanced-techniques.md)** — Advanced Techniques | GCC optimizations, C++ RE, symbolic execution, anti-reversing, decompilation | 16 – 20 |  
| **[V](/part-5-practical-cases.md)** — Practical Cases | Keygenme, OOP + plugins, network, crypto, custom format | 21 – 25 |  
| **[VI](/part-6-malware.md)** — Malware (sandbox) | Secure lab, ransomware, dropper, unpacking | 26 – 29 |  
| **[VII](/part-7-dotnet.md)** — Bonus .NET/C# | .NET RE, ILSpy, dnSpy, Frida-CLR | 30 – 32 |  
| **[VIII](/part-8-rust-go.md)** — Bonus Rust & Go | Rust RE specifics, Go RE specifics | 33 – 34 |  
| **[IX](/part-9-resources.md)** — Resources | Scripting, automation, CTF, readings, certifications | 35 – 36 |

➡️ **[Detailed table of contents (TABLE-OF-CONTENTS.md)](/TABLE-OF-CONTENTS.md)**

---

## 🧭 Recommended paths

Depending on your profile, you can follow the training linearly or in a targeted way:

| Goal | Suggested path |  
|:---|:---|  
| **Complete training** | Parts I → IX in order |  
| **Get started in RE quickly** | Chapters 1–5, then 11, then 21 (keygenme) |  
| **Prepare for CTFs** | Chapters 3, 5, 8, 11, 13, 18, 21 |  
| **Malware analysis** | Parts I–III, then Part VI directly |  
| **.NET / C# RE only** | Chapter 1, then Part VII |  
| **Rust / Go RE** | Chapters 1–5, 8, 11, then Part VIII |

---

## 🎯 Checkpoints

Each chapter (or group of chapters) ends with a **checkpoint**: a practical exercise that validates what you have learned before moving on. Solutions are in `solutions/`.

> ⚠️ Always try to solve the checkpoint by yourself before consulting the solution.

---

## 🤝 Contributing

Contributions are welcome:

- Correcting technical or typographical errors  
- Adding variants of training binaries  
- Adding `.hexpat` patterns or YARA rules

Please open an **issue** before any major pull request.

---

## 📄 License

[MIT](/LICENSE) — © 2025-2026 [Nicolas DEOUX / NDXDeveloper]  
This content is strictly educational and ethical. See the [full disclaimer](/LICENSE).
