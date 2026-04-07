🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part V — Practical Cases on Our Applications

You have the tools, you have the techniques — it is time to use them for real. This part plunges you into five complete end-to-end exercises, each targeting a different type of application: a classic C crackme, an object-oriented C++ application with plugins, a network binary with a custom protocol, a program using encryption, and a parser for a proprietary file format. The binaries are yours — you compile them from the provided sources, then analyze them as if you had never seen them before.

---

## 🎯 Objectives of this part

By the end of these five chapters, you will be able to:

1. **Conduct a complete analysis of a C binary** end to end: from the initial triage to writing a working keygen, via binary patching and automatic solving with angr.  
2. **Reconstruct the class hierarchy of a C++ application** from disassembly alone, understand its dynamic plugin system, and write a compatible `.so` plugin without having the sources.  
3. **Reverse a custom network protocol**: identify the fields and the parser's state machine, visualize frames with ImHex, and produce a replacement client capable of authenticating to the server.  
4. **Extract cryptographic keys** from a running binary (GDB, Frida), identify the algorithms used from their magic constants, and reproduce the encryption scheme in Python.  
5. **Fully document a proprietary file format**: map its structure with ImHex, validate the interpretation through fuzzing, and produce a standalone Python parser accompanied by a specification.  
6. **Adapt your approach to the level of difficulty**: solve the same challenge on a `-O0` binary with symbols, then on its stripped `-O2` variant, adjusting your techniques.

---

## 📋 Chapters

| # | Title | Target | Techniques used | Link |  
|----|-------|-------|----------------------|------|  
| 21 | Reversing a simple C program (keygenme) | Crackme with key verification | `strings`, `checksec`, Ghidra, GDB, ImHex patching, angr, `pwntools` keygen | [Chapter 21](/21-keygenme/README.md) |  
| 22 | Reversing an object-oriented C++ application | Application with class hierarchy and `.so` plugins | Ghidra (vtables, RTTI), `c++filt`, `dlopen`/`dlsym`, `LD_PRELOAD`, plugin writing | [Chapter 22](/22-oop/README.md) |  
| 23 | Reversing a network binary (client/server) | Custom protocol over TCP | `strace`, Wireshark, ImHex (protocol `.hexpat`), replay attack, `pwntools` client | [Chapter 23](/23-network/README.md) |  
| 24 | Reversing a binary with encryption | Program encrypting files | Magic constants (AES S-box, SHA IV), GDB, Frida, ImHex, crypto reproduction in Python | [Chapter 24](/24-crypto/README.md) |  
| 25 | Reversing a custom file format | Proprietary format parser | `file`, `binwalk`, ImHex (iterative `.hexpat`), AFL++ (parser fuzzing), Python parser, spec writing | [Chapter 25](/25-fileformat/README.md) |

---

## 📦 Provided binaries

Each chapter has its directory in `binaries/` with the sources and a dedicated `Makefile`:

```
binaries/
├── ch21-keygenme/    ← keygenme.c + Makefile
├── ch22-oop/         ← oop.cpp, processor.h, plugin_alpha.cpp, plugin_beta.cpp + Makefile
├── ch23-network/     ← client.c, server.c + Makefile
├── ch24-crypto/      ← crypto.c + Makefile
└── ch25-fileformat/  ← fileformat.c + Makefile
```

Each `Makefile` produces **several variants** of the same binary:

- `*_O0` — no optimization, with symbols (`-O0 -g`): the most readable version, ideal for a first pass.  
- `*_O2` — optimized (`-O2 -g`): the compiler reorganizes the code, some functions are inlined.  
- `*_O3` — aggressive optimization (`-O3 -g`): vectorization, loop unrolling.  
- `*_strip` — stripped (`-O0 -s`): symbols removed, function names absent.  
- `*_O2_strip` — optimized and stripped (`-O2 -s`): the configuration closest to a production binary.

Compile everything with a single command from the repository root:

```bash
cd binaries && make all
```

---

## 🧭 Recommended approach

For each chapter, proceed by increasing difficulty:

1. **Start with the `-O0` variant with symbols.** Function names are visible, the disassembled code follows the structure of the source, the Ghidra decompiler produces very readable pseudo-code. This is your training ground for understanding the program's logic.

2. **Move on to the `-O2` variant with symbols.** Names are still there, but the code is reorganized by the compiler. Here you apply the techniques from Chapter 16 (recognizing optimizations).

3. **Tackle the stripped variant (`-O0 -s` then `-O2 -s`).** No more function names, no more types — you have to reconstruct everything. This is the most formative exercise and the closest to real conditions.

Only move to the next variant once you have completed the checkpoint for the current one. The progression is designed to consolidate your reflexes at each step.

---

## ⏱️ Estimated duration

**~25-35 hours** for a practitioner who has completed Parts I through IV.

Each chapter represents a complete mini-project. Count ~5-7h per practical case if you work on at least two variants of the binary (typically `-O0` then `-O2 -s`). Chapter 21 (keygenme) is the most guided and serves as an on-ramp — the following chapters progressively leave more autonomy. Chapter 25 (file format) is the most open-ended: writing the specification requires an additional synthesis effort.

---

## 📌 Prerequisites

Having completed **[Part I](/part-1-fundamentals.md)**, **[Part II](/part-2-static-analysis.md)**, **[Part III](/part-3-dynamic-analysis.md)**, and **[Part IV](/part-4-advanced-techniques.md)**.

Concretely, each practical case mobilizes a specific subset of skills:

- **Chapter 21** — Ghidra, GDB, ImHex (patching), angr, `pwntools`.  
- **Chapter 22** — Ghidra (vtables, RTTI), `c++filt`, understanding of virtual dispatch and `dlopen`.  
- **Chapter 23** — `strace`, Wireshark, ImHex (`.hexpat`), `pwntools` (sockets).  
- **Chapter 24** — Crypto constants (Appendix J), GDB, Frida, Python (`pycryptodome` or equivalent).  
- **Chapter 25** — `binwalk`, ImHex, AFL++, Python (binary parsing with `struct`).

If you already master some of these tools, you can tackle the chapters in any order — they are independent of each other.

---

## ⬅️ Previous part

← [**Part IV — Advanced RE Techniques**](/part-4-advanced-techniques.md)

## ➡️ Next part

Practical cases done, you will move on to malicious code analysis in a controlled environment: Linux ransomware, dropper with C2 communication, and unpacking techniques.

→ [**Part VI — Malicious Code Analysis (Controlled Environment)**](/part-6-malware.md)

⏭️ [Chapter 21 — Reversing a simple C program (keygenme)](/21-keygenme/README.md)
