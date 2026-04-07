🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 15 — Fuzzing for Reverse Engineering

> 📦 **Binaries used in this chapter**: `binaries/ch15-keygenme/` (first AFL++ run, Sections 15.2–15.4), `binaries/ch15-fileformat/` (complete practical case, Section 15.7)  
> 🛠️ **Main tools**: AFL++, libFuzzer, `afl-cov`, `lcov`, GCC with `-fsanitize`, `afl-tmin`, `afl-cmin`  
> ⏱️ **Estimated duration**: 4 to 5 hours (reading + experimentation)

---

## Why this chapter?

In the previous chapters, we analyzed binaries by reading them (static analysis) or by executing them step by step (dynamic analysis with GDB, Frida, Valgrind). Both approaches rest on the same premise: **it's the reverse engineer who decides what to look at and what to test**. This works well when you have a precise hypothesis — tracing a call to `strcmp`, setting a breakpoint on a verification routine, inspecting a buffer in memory.

But what do you do when you don't yet know *where* to look? When the binary exposes a complex parser with dozens of conditional branches, and you don't know which inputs trigger which paths? This is exactly the problem that **fuzzing** solves.

Fuzzing consists of bombarding a program with automatically generated inputs — often random or semi-random — and observing what happens. A crash? You've just discovered an interesting execution path. A new branch covered? The fuzzer adapts its mutations to explore it further. In a few hours of fuzzing, you can map entire portions of a binary's internal logic that days of manual analysis wouldn't have revealed.

This chapter positions fuzzing not as a quality testing or vulnerability research tool (even though it excels in those roles), but as a **full-fledged reverse engineering tool** — a way to explore a binary from the outside to understand its logic from the inside.

---

## What you will learn

By the end of this chapter, you will be able to:

- Explain how fuzzing complements static and dynamic analysis in an RE workflow.  
- Install and configure **AFL++** to instrument a binary compiled with GCC.  
- Use **libFuzzer** for in-process fuzzing coupled with sanitizers (ASan, UBSan).  
- Analyze crashes produced by a fuzzer to extract information about the program's internal logic (parsing paths, input validation, error handling).  
- Read and interpret a **coverage map** to identify which areas of the binary have been reached and which remain unexplored.  
- Manage an input **corpus** and create custom **dictionaries** tailored to the target format to accelerate discovery.  
- Apply these techniques on a concrete case: the custom file format parser provided in `binaries/ch25-fileformat/`.

---

## Prerequisites

This chapter builds on concepts covered in previous chapters:

- **Chapter 2** — GNU compilation chain: you must be comfortable with GCC flags (`-O0`, `-O2`, `-g`, `-fsanitize`) and know how to recompile a binary from the provided sources.  
- **Chapter 5** — Basic inspection tools: the quick triage workflow (`file`, `strings`, `checksec`) is the starting point before any fuzzing session.  
- **Chapter 14** — Valgrind and sanitizers: understanding AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) is essential, as modern fuzzers rely heavily on these sanitizers to detect bugs beyond simple crashes.

Familiarity with the Linux command line and a working environment (cf. Chapter 4) are essential. Fuzzing sessions can be resource-intensive — plan for at least 2 CPU cores and 4 GB of available RAM for your VM.

---

## Chapter outline

| Section | Title | Content |  
|---------|-------|---------|  
| 15.1 | Why fuzzing is a full-fledged RE tool | Positioning fuzzing in the RE methodology, complementarity with static/dynamic |  
| 15.2 | AFL++ — installation, instrumentation, and first run | Instrumented compilation with `afl-gcc`/`afl-clang-fast`, configuration, first run on `ch15-keygenme` |  
| 15.3 | libFuzzer — in-process fuzzing with sanitizers | Writing a harness, compilation with `-fsanitize=fuzzer`, ASan/UBSan coupling |  
| 15.4 | Analyzing crashes to understand parsing logic | Sorting crashes, reproducing them, interpreting them as clues about internal structure; leveraging the corpus beyond crashes |  
| 15.5 | Coverage-guided fuzzing: reading coverage maps | Using `afl-cov` and `lcov` to visualize coverage and guide analysis |  
| 15.6 | Corpus management and custom dictionaries | `afl-cmin`, `afl-tmin`, creating dictionaries from `strings` and static analysis |  
| 15.7 | Practical case: discovering hidden paths in a binary parser | Complete application on `ch25-fileformat`: from initial corpus to coverage report |

---

## Positioning in the training

```
Part III — Dynamic Analysis

  Chapter 11 — GDB                           ← Controlled execution, step by step
  Chapter 12 — Enhanced GDB (GEF/pwndbg)     ← Enriched visualization
  Chapter 13 — Frida                          ← Live instrumentation and hooking
  Chapter 14 — Valgrind & sanitizers          ← Memory bug detection
  ▶ Chapter 15 — Fuzzing                      ← Automated exploration    ◀ YOU ARE HERE
```

Fuzzing closes the dynamic analysis loop. Where GDB and Frida give you a **microscope** to examine a specific execution path, the fuzzer gives you a **radar** that sweeps the program's entire input surface. The crashes it discovers then become entry points for targeted analysis with the tools from Chapters 11 through 14.

---

## Conventions used in this chapter

Shell commands are prefixed with `$` (normal user) or `#` (root). Long fuzzing sessions are represented by excerpts from AFL++ output with annotations. Crash files are referenced by their path in AFL++'s standard output directory (`out/crashes/`).

> 💡 **Tip** — Green callout: practical advice to save time or avoid a common pitfall.

> ⚠️ **Warning** — Orange callout: point of vigilance (system resources, false positives, misinterpretation).

> 🔗 **Link** — Reference to another chapter or training appendix.

⏭️ [Why fuzzing is a full-fledged RE tool](/15-fuzzing/01-why-fuzzing-for-re.md)
