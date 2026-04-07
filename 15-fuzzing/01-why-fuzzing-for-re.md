🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.1 — Why fuzzing is a full-fledged RE tool

> 🔗 **Prerequisites**: Chapter 1 (static vs dynamic RE difference), Chapter 5 (triage workflow), Chapter 14 (sanitizers)

---

## The problem: the analyst's blind spot

Let's revisit the methodology we've been building since the beginning of this training. When facing an unknown binary, the classic approach follows two complementary axes:

**Static analysis** (Parts II and IV) consists of reading the binary without executing it. We inspect ELF sections, browse the disassembly in Ghidra, reconstruct data structures, rename functions. It's a reading exercise — methodical, precise, but entirely guided by the reverse engineer's intuition and experience. We choose to look at `main()`, then follow the calls, spot a `strcmp`, trace back to the verification routine. The risk? **Missing an execution path we didn't think to explore.** A parser with 47 conditional branches doesn't reveal its secrets through reading alone — especially when compiled at `-O2` with inlined functions.

**Dynamic analysis** (Chapters 11 through 14) executes the binary and observes its behavior. We set breakpoints in GDB, hook functions with Frida, trace system calls with `strace`. It's more concrete than static reading, but it remains **analyst-directed**: we choose which inputs to provide, where to set breakpoints, which functions to hook. If we don't guess the right input, we don't reach the right path. We observe a subset of the program's behavior — the one we managed to trigger.

Between these two approaches lies a considerable blind spot: **all the execution paths the analyst has neither read nor triggered**. It's precisely in this blind spot that the most complex parsing logic hides, along with rarely reached error handlers, undocumented features, and — in a security context — vulnerabilities.

---

## Fuzzing as automated exploration

Fuzzing fills this blind spot by inverting the logic: instead of the analyst choosing inputs, **the program itself guides the exploration**, through a feedback mechanism called *coverage feedback*.

The principle is simple in concept:

1. You provide the fuzzer with one or more **initial inputs** (the *seed corpus*).  
2. The fuzzer **mutates** these inputs — it changes bytes, inserts some, deletes some, recombines them.  
3. Each mutated input is sent to the target program.  
4. The fuzzer observes whether this input **triggered a new path** in the code (a branch never taken, a basic block never reached).  
5. If so, the input is **kept** in the corpus and will serve as a basis for future mutations.  
6. If the program **crashes**, the input is saved separately for analysis.  
7. The cycle repeats, thousands of times per second.

This *coverage-guided fuzzing* mechanism means the fuzzer **progressively learns** the structure expected by the program. Without any prior knowledge of the input format, it eventually produces inputs that pass the initial validations, reach deeper parsing layers, and reveal behaviors the analyst wouldn't have suspected.

> 💡 **Analogy** — Imagine a maze whose layout you don't know. Static analysis is looking at the maze from above without entering — useful, but some corridors are hidden. Dynamic analysis is entering with a flashlight and choosing which turns to take — you explore what you decide to explore. Fuzzing is sending thousands of robots that each take different paths and report back what they found.

---

## What fuzzing reveals to a reverse engineer

Fuzzing isn't just a bug detection tool. For a reverse engineer, each result produced by the fuzzer is a **source of information** about the binary:

### Crashes as structural clues

A crash isn't just a bug to fix — it's an **open window into the program's internal logic**. When the fuzzer produces an input that triggers a segfault in a function at offset `0x4012a0`, we learn several things at once:

- That function is **reachable** from the program's entry point (which may not have been obvious from reading the call graph).  
- The input that caused the crash tells us **which parsing path** leads to that function.  
- The nature of the crash (out-of-bounds read, null dereference, stack overflow) tells us about **how that function manipulates data**.

By combining this information with Ghidra or GDB, we can reconstruct the complete chain: from the program's entry point to the crash point, through every validation, every branch, every data transformation. A single well-analyzed crash can unlock the understanding of an entire module.

### Coverage as a map of the binary

Modern fuzzers like AFL++ maintain a **coverage map** (*coverage bitmap*) that records which basic blocks have been executed and which transitions between blocks have been observed. This map is a gold mine for RE:

- **Covered areas** correspond to paths the fuzzer managed to reach. They can be overlaid on the function graph in Ghidra to visualize which parts of the code are actually used for input processing.  
- **Uncovered areas** are equally interesting: they indicate either dead code, or paths protected by conditions the fuzzer couldn't satisfy — which directs manual analysis toward those specific conditions.

We'll see in Section 15.5 how to extract and visualize these coverage maps with `afl-cov` and `lcov`.

### Surviving inputs as implicit specification

The corpus the fuzzer accumulates over time constitutes, in effect, a **collection of valid** (or nearly valid) **inputs** that exercise different paths in the program. By examining these inputs, you can reconstruct fragments of the input format specification:

- What *magic bytes* are expected at the beginning of the file?  
- Which fields have size or value constraints?  
- Which flag combinations activate which branches?

This "from the outside" approach is particularly valuable when the format is proprietary and undocumented — exactly the scenario in Chapter 25.

---

## Complementarity with other approaches

Fuzzing replaces neither static nor dynamic analysis. It **feeds** them. Here's how the three approaches fit together in a complete RE methodology:

**Static → Fuzzing.** Static analysis in Ghidra identifies parsing functions, validation routines, and expected formats. This information is used to build a **relevant initial corpus** and a **dictionary** of tokens for the fuzzer (Section 15.6). The closer the seed corpus is to the real format, the faster the fuzzer will reach the parser's deeper layers.

**Fuzzing → Static.** Crashes and the coverage map produced by the fuzzer guide the return to static analysis. Instead of reading the binary linearly, you now know **which functions deserve particular attention** — those that crash, those that handle rarely reached branches, those that weren't covered at all.

**Fuzzing → Dynamic.** Each crash produces a **reproducible input** that can be replayed in GDB to observe exactly what happens at the time of the bug. The typical workflow is: the fuzzer finds the crash, GDB (with GEF or pwndbg) allows analyzing it instruction by instruction, and Frida can hook the traversed functions to capture data transformations live.

**Dynamic → Fuzzing.** Observations made under GDB or Frida allow refining the fuzzing strategy. If you discover that a certain checksum value is expected at offset 8 of the file, you can modify the fuzzing harness to calculate this checksum automatically — which unlocks access to parsing layers the fuzzer alone would never have reached.

```
                    ┌──────────────────────┐
                    │   Static Analysis    │
                    │  (Ghidra, objdump)   │
                    └──────┬───────▲───────┘
                           │       │
          initial corpus,  │       │ functions to
                dictionary │       │ examine
                           │       │
                    ┌──────▼───────┴───────┐
                    │       Fuzzing        │
                    │   (AFL++, libFuzzer) │
                    └──────┬───────▲───────┘
                           │       │
              crashes,     │       │ refined harness,
              inputs       │       │ fixed checksum
                           │       │
                    ┌──────▼───────┴───────┐
                    │  Dynamic Analysis    │
                    │  (GDB, Frida, strace)│
                    └──────────────────────┘
```

This iterative cycle — static, fuzzing, dynamic, then back again — is at the heart of the modern reverse engineering methodology for complex binaries.

---

## Black-box vs grey-box vs white-box fuzzing

It's useful to distinguish three levels of fuzzing, as the RE context determines which one is applicable:

**Black-box fuzzing.** You have no instrumentation of the binary. You send it inputs and observe only whether it crashes or not — via the return code, `strace`, or external monitoring. It's the most limited approach, but sometimes the only option when you don't have the sources and can't instrument the binary (embedded firmware, protected binary). Discovery is slow because the fuzzer has no feedback on internal coverage.

**Grey-box fuzzing.** You instrument the binary at compilation time (with `afl-gcc` or `afl-clang-fast`) or at runtime (via QEMU, Frida, DynamoRIO) to get coverage feedback. The fuzzer knows which paths each input explores, and adapts its mutations accordingly. This is the dominant mode today — AFL++ and libFuzzer work this way. This is **the approach we'll use throughout this chapter**, since the training binaries come with their sources and can be recompiled with instrumentation.

**White-box fuzzing.** You use symbolic execution (cf. Chapter 18 — angr, Z3) to generate inputs that exactly satisfy each branch's constraints. It's theoretically optimal, but the combinatorial explosion of paths makes it impractical on real-world binaries — except for isolated functions. In practice, it's often combined with grey-box: the fuzzer explores broadly, and symbolic execution solves blocking constraints on a case-by-case basis.

> 💡 **In an RE context** — When you have the sources (or can recompile), always prefer grey-box with compile-time instrumentation: it's by far the most efficient. If you're working on a binary you can't recompile, AFL++ offers a QEMU mode (`-Q`) that instruments at runtime — slower, but functional.

---

## When to use fuzzing in an RE workflow

Fuzzing isn't always the right answer. Here are the situations where it provides the most value:

**Fuzzing excels when:**

- The binary **processes structured inputs** (files, network packets, serialized messages). Parsers are ideal targets because they contain many conditional branches the fuzzer can explore.  
- The parsing logic is **complex or obscure** — too many branches to read them all manually, too many combinations to test by hand.  
- You want to **quickly map the input surface** of an unknown binary before diving into detailed analysis.  
- You want to **validate hypotheses** from static analysis: "this function seems to handle type X inputs — does the fuzzer confirm this?"

**Fuzzing is less relevant when:**

- The binary is **purely interactive** (GUI without file input) — GUI fuzzing is a separate domain, outside the scope of this chapter.  
- The target logic depends on **complex external state** (database, multi-party network, system clock) that's difficult to reproduce in a fuzzing harness.  
- The program has a **very long startup time** — fuzzing relies on executing thousands of inputs per second; if each execution takes several seconds, throughput will be low.  
- You already understand the binary well and are looking for a specific detail — in that case, GDB or Frida are more suited than the fuzzer's broad sweep.

---

## Summary

Fuzzing transforms reverse engineering from a purely human exercise into a **collaboration between the analyst and automation**. The reverse engineer brings structural understanding, intuition, and interpretive capability. The fuzzer brings exhaustiveness, exploration speed, and the ability to reach paths the human wouldn't have considered. Together, they cover far more ground than either one separately.

In the following sections, we move to practice: installing AFL++ (15.2), writing a libFuzzer harness (15.3), then leveraging the results to advance our understanding of the target binary.

---


⏭️ [AFL++ — installation, instrumentation, and first run on a GCC application](/15-fuzzing/02-afl-plus-plus.md)
