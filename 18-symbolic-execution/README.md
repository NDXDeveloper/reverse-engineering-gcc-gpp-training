🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 18 — Symbolic execution and constraint solvers

> **Part IV — Advanced RE Techniques**

---

## Why this chapter?

In the previous chapters, you learned to read disassembly, navigate a decompiler, set breakpoints, and trace a binary's execution instruction by instruction. These approaches — static and dynamic — rest on a common denominator: **you are the one reasoning** about possible execution paths, input constraints, and branching conditions. Faced with a crackme with a 15-line verification routine, this is perfectly doable by hand. Faced with a cascade of nested arithmetic transformations across 200 lines of optimized assembly, it's no longer feasible.

Symbolic execution reverses the problem: instead of providing a concrete input and observing what happens, you leave the inputs **undetermined** — treating them as mathematical variables — and ask an exploration engine to traverse the program's paths while accumulating **constraints** on these variables. At the end, a constraint solver (typically an SMT solver like Z3) answers the question: *"Does an input value exist that satisfies all these constraints and leads to this point in the program?"*

In other words, symbolic execution transforms a reverse engineering problem into a **constraint satisfaction problem**, and delegates the resolution to a machine.

---

## What you will learn

This chapter covers the theoretical foundations and practical application of symbolic execution applied to reverse engineering of binaries compiled with GCC. You'll discover:

- The **fundamental principles** of symbolic execution: symbolic variables, symbolic states, path tree exploration, and constraint collection along each branch.

- **angr**, the Python binary analysis framework most used in the RE and CTF community. You'll learn its internal architecture (`SimState`, `SimulationManager`, exploration strategies) and how to use it to automatically solve a crackme compiled with GCC — from raw binary to solution, without ever reading a line of assembly.

- **Z3**, the SMT solver developed by Microsoft Research, used as a backend by angr but also usable standalone. You'll see how to manually model constraints extracted during static analysis and ask Z3 to solve them.

- The **fundamental limits** of the approach: combinatorial path explosion, difficulty modeling unbounded loops, system calls, and environment interactions.

- When and how to **combine** symbolic execution with manual reverse engineering to get the best of both worlds.

---

## Positioning in the training

This chapter sits at the crossroads of static and dynamic analysis. It assumes you're comfortable with:

- **Reading x86-64 disassembly** and understanding conditional branches (Chapters 3 and 7).  
- Using a **decompiler** like Ghidra to understand a binary's logic (Chapter 8).  
- The basics of **debugging with GDB** to validate hypotheses on a running binary (Chapter 11).  
- Notions of **binary protections** (stripping, PIE, ASLR) that influence angr's configuration (Chapter 19, but the basics covered in Chapter 5 with `checksec` suffice here).

The techniques learned in this chapter will be directly employed in the Part V practical cases, notably in **Chapter 21** (automatic keygenme solving with angr) and **Chapter 24** (constraint extraction on cryptographic routines).

---

## Tools used in this chapter

| Tool | Role | Installation |  
|------|------|-------------|  
| **angr** | Symbolic execution framework on binaries | `pip install angr` |  
| **Z3** (z3-solver) | Standalone SMT solver, also angr's backend | `pip install z3-solver` |  
| **Python 3.10+** | Scripting language for angr and Z3 | Pre-installed on the Chapter 4 VM |  
| **Ghidra** | Decompiler for manual constraint extraction | Installed in Chapter 8 |  
| **GDB + GEF** | Dynamic validation of found solutions | Installed in Chapters 11–12 |

> 💡 **Note on versions:** angr evolves rapidly. This chapter was written and tested with angr **9.2.x**. If you're using a newer version, consult the [official documentation](https://docs.angr.io/) for any API changes. Installation in a **dedicated virtualenv** is strongly recommended, as angr bundles many dependencies that can conflict with other Python packages.

---

## Training binaries

The binaries used in this chapter are located in the repository's `binaries/` directory. You'll primarily work with the keygenme variants:

```
binaries/ch18-keygenme/
├── keygenme.c          ← Source (don't look before trying!)
├── Makefile
├── keygenme_O0         ← -O0, with symbols  (learning)
├── keygenme_O0_strip   ← -O0, without symbols  (RE without symbols)
├── keygenme_O2         ← -O2, with symbols  (optimizations)
├── keygenme_O2_strip   ← -O2, without symbols  (ch.18 checkpoint)
├── keygenme_O3         ← -O3, with symbols  (vectorization)
└── keygenme_O3_strip   ← -O3, without symbols  (advanced challenge)
```

The 6 variants are produced by `make all`. The progression within the chapter follows increasing difficulty: we start by solving `keygenme_O0` (the most readable), then tackle optimized and stripped versions to see how angr handles — or doesn't — the additional complexity.

---

## Chapter outline

- **18.1** — Symbolic execution principles: treating inputs as symbols  
- **18.2** — angr — installation and architecture (SimState, SimManager, exploration)  
- **18.3** — Automatically solving a crackme with angr  
- **18.4** — Z3 Theorem Prover — modeling manually extracted constraints  
- **18.5** — Limits: path explosion, loops, system calls  
- **18.6** — Combining with manual RE: when to use symbolic execution  
- **🎯 Checkpoint** — Solve `keygenme_O2_strip` with angr in under 30 lines of Python

---

> **Ready?** Let's start by understanding what it concretely means to "treat an input as a symbol" in Section 18.1.

⏭️ [Symbolic execution principles: treating inputs as symbols](/18-symbolic-execution/01-symbolic-execution-principles.md)
