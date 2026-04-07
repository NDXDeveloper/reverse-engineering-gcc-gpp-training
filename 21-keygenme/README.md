🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 21 — Reversing a Simple C Program (keygenme)

> 🎯 **Chapter objective**: carry out the complete reverse engineering of a crackme written in pure C, compiled with GCC at different optimization levels. By the end of this chapter, you will be able to locate a verification routine, understand its logic, bypass it through binary patching, solve it automatically via symbolic execution, and produce a working keygen.

---

## Context

This chapter is the first of the practical cases in **Part V**. It mobilizes all the skills acquired in previous parts — static analysis (Part II), dynamic analysis (Part III), and advanced techniques (Part IV) — on a deliberately accessible target: a simple C program that asks the user for a license key and verifies its validity.

The `keygenme` binary is a classic scenario from the world of CTFs and RE learning. The user launches the program, enters a character string, and the program responds with a success or failure message. Behind this seemingly trivial mechanic lies a rich learning opportunity: each step of the reverse — from initial triage to writing the keygen — illustrates a fundamental skill that you will encounter on much more complex targets.

## Why start with a keygenme?

The keygenme is to the reverse engineer what "Hello, World!" is to the developer: a canonical exercise that validates the fundamentals in a controlled setting. Its apparent simplicity is deceptive, because it forces you to methodically chain together all phases of a complete analysis:

- **Reconnaissance**: what does this binary contain? What compiler, what protections, what revealing strings?  
- **Static analysis**: where is the verification logic? What transformations does the user input undergo? What is the success predicate?  
- **Dynamic analysis**: can we observe the comparison in real time? What values pass through the registers at the critical moment?  
- **Exploitation**: can we bypass the verification (patching) or solve it (keygen, symbolic execution)?

An analyst who masters this workflow on a keygenme at `-O0` with symbols is ready to face the same binary at `-O2` stripped, then targets of increasing complexity.

## The target binary

The `binaries/ch21-keygenme/` directory contains the source `keygenme.c` and a `Makefile` that produces **five variants** of the same program:

| Variant | Optimization | Symbols | Difficulty |  
|---|---|---|---|  
| `keygenme_O0` | `-O0` | yes | ⭐ |  
| `keygenme_O2` | `-O2` | yes | ⭐⭐ |  
| `keygenme_O3` | `-O3` | yes | ⭐⭐⭐ |  
| `keygenme_strip` | `-O0` | no (`strip`) | ⭐⭐ |  
| `keygenme_O2_strip` | `-O2` | no (`strip`) | ⭐⭐⭐⭐ |

This progression allows you to concretely observe the impact of the compilation flags studied in chapter 2 (`-O0` to `-O3`, `-g`, `-s`) and the anti-reversing techniques seen in chapter 19 (stripping). We recommend starting the analysis with `keygenme_O0` to gain understanding of the logic, then verifying that you reach the same conclusions on the optimized and stripped variants.

## What you will learn

This chapter covers the entire reverse engineering cycle applied to a C target compiled with GCC:

- **Section 21.1** — Quick triage of the binary: `file`, `strings`, `readelf`, section inspection. You will apply the first 5 minutes workflow seen in chapter 5.  
- **Section 21.2** — Protection inventory with `checksec`: PIE, NX, canary, RELRO. You will know what the compiler has enabled and what this implies for the analysis.  
- **Section 21.3** — Locating the verification routine via a top-down approach in Ghidra, starting from `main()` and following cross-references to the critical function.  
- **Section 21.4** — Understanding conditional jumps (`jz`/`jnz`) that separate the "valid key" path from the "invalid key" path. This is the heart of any crackme.  
- **Section 21.5** — Dynamic analysis with GDB: setting a breakpoint on the comparison, observing registers, capturing the expected key in memory.  
- **Section 21.6** — Binary patching with ImHex: flipping a conditional jump byte so the program accepts any key. A surgical modification of one or two bytes.  
- **Section 21.7** — Automatic solving with angr: writing a symbolic execution script that finds the correct key without manually understanding the algorithm.  
- **Section 21.8** — Writing a keygen in Python with `pwntools`: reproducing the validation algorithm to generate valid keys on demand.

## Prerequisites

Before tackling this chapter, make sure you are comfortable with:

- **Quick triage** of an ELF binary (chapter 5)  
- **Reading x86-64 disassembly** and System V calling conventions (chapter 3)  
- **Ghidra basics**: navigating the CodeBrowser, renaming, XREF (chapter 8)  
- **Fundamental GDB commands**: `break`, `run`, `x`, `info registers` (chapter 11)  
- The concept of **binary patching** and using ImHex (chapter 6)  
- The **principles of symbolic execution** with angr (chapter 18)  
- Using **pwntools** to interact with a binary (chapter 11, section 9)

If any of these points seems unclear, do not hesitate to revisit the corresponding chapter. Each section of this chapter 21 will indicate the necessary refreshers.

## Methodology followed

The analysis in this chapter follows a deliberately linear path, from the most passive to the most intrusive:

```
Triage (passive)
  └─→ Protections (passive)
        └─→ Static analysis in Ghidra (passive)
              └─→ Dynamic analysis in GDB (active, non-destructive)
                    └─→ Binary patching (active, destructive)
                          └─→ Automatic solving with angr (active)
                                └─→ Keygen (final product)
```

This progression is not arbitrary. In RE, you always start with what does not modify the target and does not risk skewing the analysis. Triage and static analysis allow formulating hypotheses; dynamic analysis confirms them; patching and the keygen exploit the acquired understanding.

## Conventions for this chapter

- Shell commands are prefixed with `$`, GDB commands with `(gdb)`.  
- Unless otherwise stated, examples use the `keygenme_O0` variant (the most readable).  
- Assembly syntax is **Intel** (`-M intel` for `objdump`, default option in Ghidra).  
- Displayed addresses may differ from yours if PIE is enabled and ASLR not disabled — this is normal, relative offsets remain identical.

---

## Chapter outline

- 21.1 — [Complete static analysis of the binary (triage, strings, sections)](/21-keygenme/01-static-analysis.md)  
- 21.2 — [Protection inventory with `checksec`](/21-keygenme/02-checksec-protections.md)  
- 21.3 — [Locating the verification routine (top-down approach)](/21-keygenme/03-routine-localization.md)  
- 21.4 — [Understanding conditional jumps (`jz`/`jnz`) in the crackme context](/21-keygenme/04-conditional-jumps-crackme.md)  
- 21.5 — [Dynamic analysis: tracing the comparison with GDB](/21-keygenme/05-dynamic-analysis-gdb.md)  
- 21.6 — [Binary patching: flipping a jump directly in the binary (with ImHex)](/21-keygenme/06-patching-imhex.md)  
- 21.7 — [Automatic solving with angr](/21-keygenme/07-angr-solving.md)  
- 21.8 — [Writing a keygen in Python with `pwntools`](/21-keygenme/08-keygen-pwntools.md)  
- 🎯 Checkpoint — [Produce a working keygen for all 3 binary variants](/21-keygenme/checkpoint.md)

⏭️ [Complete static analysis of the binary (triage, strings, sections)](/21-keygenme/01-static-analysis.md)
