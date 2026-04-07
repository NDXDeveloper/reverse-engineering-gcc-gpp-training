🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja

> 📘 **Part II — Static Analysis**  
> Prerequisites: [Chapter 7 — objdump and Binutils](/07-objdump-binutils/README.md), [Chapter 8 — Ghidra](/08-ghidra/README.md)

---

## Why multiple disassemblers?

Chapter 7 showed us the limits of `objdump`: no flow graph, no decompilation, a linear analysis that gets things wrong as soon as it encounters data mixed with code. Chapter 8 presented Ghidra as a complete and free solution to these problems. So why dedicate an entire chapter to other tools?

The answer is one word: **complementarity**. In reverse-engineering practice, no tool systematically dominates all others on every aspect. IDA remains the historical industry reference and its initial binary analysis is often formidably precise. Radare2 offers unparalleled command-line power, ideal for scripting and automation. Binary Ninja offers a modern interface and a particularly well-designed API for programmatic analysis. Each has its strengths, weaknesses, and situations where it excels.

An experienced reverse engineer does not swear by a single tool. They know each tool's peculiarities and choose the one best suited to the task at hand — or combine them. It's not uncommon to start an analysis in Ghidra to benefit from the decompiler, verify a specific point in IDA whose function-recognition heuristic is more reliable on some stripped binaries, then script a mass extraction with Radare2.

## What this chapter covers

This chapter gives you the keys to get started with three major tools complementing Ghidra, all applied to ELF binaries produced by GCC/G++:

- **IDA Free** — the free version of the most used disassembler in the industry. We'll see how to import a binary, navigate the interface, and exploit its automatic analysis features on an x86-64 ELF. IDA Free has important limitations compared to the Pro version (no decompiler for x86-64 in the classic free version, no full IDAPython scripting), but its analysis engine and function recognition make it a valuable tool even in its free version.

- **Radare2 and Cutter** — the Swiss army knife of open-source RE. Radare2 (`r2`) is an entirely command-line framework, renowned for its steep learning curve but also for its exceptional flexibility. Cutter is its official graphical interface, built on top of `r2`, which makes the tool accessible without sacrificing the power of the underlying engine. We'll cover essential commands, navigation, visual mode, and above all scripting via `r2pipe` which allows controlling `r2` from Python.

- **Binary Ninja Cloud** — the free online version of Binary Ninja, a more recent disassembler that has established itself through the quality of its "Intermediate Language" (BNIL) and its API. We'll see how to use it for a quick start and how its approach differs from the previous tools.

The chapter concludes with a **structured comparison** between Ghidra, IDA, Radare2, and Binary Ninja, covering features, license model, preferred use cases, and selection criteria.

## Positioning relative to Chapter 8

This chapter does not aim to replace Ghidra in your workflow. It aims to **broaden your toolbox** and give you enough ease with each alternative to be able to:

- Validate a Ghidra analysis with a second opinion (cross-checking between decompilers).  
- Choose the most suitable tool according to context: quick CLI script, collaborative analysis, exotic binary, enterprise licensing constraint.  
- Read and understand CTF write-ups and analysis reports that use IDA or Radare2, as a large part of the existing literature relies on these tools.

## Tools and versions used

| Tool | Recommended version | License | Installation |  
|---|---|---|---|  
| IDA Free | 8.x+ | Free (proprietary, non-commercial use) | [hex-rays.com/ida-free](https://hex-rays.com/ida-free) |  
| Radare2 | 5.9+ | LGPL v3 | `git clone` + `sys/install.sh` or package manager |  
| Cutter | 2.3+ | GPL v3 | AppImage / package manager |  
| Binary Ninja Cloud | — | Free (browser) | [cloud.binary.ninja](https://cloud.binary.ninja) |

> 💡 The exact versions used for captures and examples in this chapter are documented in the [`04-work-environment/02-tools-installation.md`](/04-work-environment/02-tools-installation.md) file. If you followed Chapter 4 and ran `check_env.sh`, Radare2 and Cutter should already be installed.

## Running-thread binary

Throughout this chapter, we'll work mainly on the `keygenme_O2_strip` binary from the `binaries/ch09-keygenme/` folder. It's a binary compiled with `-O2` then stripped with `strip`: no symbols, inlined functions, optimized code. It's precisely the type of target where the differences between disassemblers become visible and instructive. We'll occasionally use the version with symbols (`keygenme_O0`) as a reference to verify our hypotheses.

## Chapter outline

- 9.1 — [IDA Free — base workflow on GCC binary](/09-ida-radare2-binja/01-ida-free-workflow.md)  
- 9.2 — [Radare2 / Cutter — command-line analysis and GUI](/09-ida-radare2-binja/02-radare2-cutter.md)  
- 9.3 — [`r2`: essential commands (`aaa`, `pdf`, `afl`, `iz`, `iS`, `VV`)](/09-ida-radare2-binja/03-r2-essential-commands.md)  
- 9.4 — [Scripting with r2pipe (Python)](/09-ida-radare2-binja/04-scripting-r2pipe.md)  
- 9.5 — [Binary Ninja Cloud (free version) — quick start](/09-ida-radare2-binja/05-binary-ninja-cloud.md)  
- 9.6 — [Ghidra vs IDA vs Radare2 vs Binary Ninja comparison](/09-ida-radare2-binja/06-tools-comparison.md)  
- 🎯 Checkpoint — [Analyze the same binary in 2 different tools, compare results](/09-ida-radare2-binja/checkpoint.md)

---


⏭️ [IDA Free — base workflow on GCC binary](/09-ida-radare2-binja/01-ida-free-workflow.md)
