🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 14 — Analysis with Valgrind and sanitizers

> 🎯 **Chapter goal**: Leverage memory instrumentation tools and compiler sanitizers to observe a binary's runtime behavior, detect its internal errors, and deduce its operating logic — all without access to the source code.

---

## Why this chapter in a Reverse Engineering training?

At first glance, Valgrind and sanitizers (ASan, UBSan, MSan) are **development** tools: they're associated with debugging, hunting memory leaks, detecting undefined behavior. So why devote an entire chapter to them in an RE curriculum?

The answer fits in one sentence: **a program's errors reveal its internal structure**.

When Valgrind reports an uninitialized read of 16 bytes at address `0x5204a0`, it implicitly tells us that a buffer of this size exists at that location, that it's allocated but not yet filled at this execution stage, and that the code attempts to use it as valid data. This type of information is gold for the reverse engineer:

- **Memory leak reports map out allocations** — each unfreed `malloc` reveals a structure's size, lifetime, and the function that created it.  
- **Out-of-bounds accesses betray buffer sizes** — a 4-byte overflow on a 64-byte block tells us the program probably manipulates a 64-byte structure and the indexing is erroneous.  
- **Reads of uninitialized memory point to keys, IVs, and ephemeral secrets** — cryptographic data is often allocated then filled in stages, and Valgrind precisely captures this in-between.  
- **Callgrind's call graphs expose the functional architecture** — without symbols, without a decompiler, you get a complete map of who calls whom, how many times, and at what cost.

In other words, these tools offer us a **complementary dynamic analysis angle** to GDB and Frida. Where GDB asks us to know *where* to set a breakpoint and Frida to know *which function* to hook, Valgrind and sanitizers work **passively and exhaustively**: they instrument the entirety of the execution and report everything abnormal. The reverse engineer only has to read the report to extract structural hypotheses about the binary.

---

## Positioning in the dynamic RE toolbox

To clearly position these tools relative to what we've already covered:

| Tool | Action mode | What you observe | Prerequisites |  
|---|---|---|---|  
| **GDB** (ch. 11-12) | Breakpoints, stepping | Registers, stack, memory at a point in time | Know *where* to stop |  
| **Frida** (ch. 13) | JS agent injection | Function calls, arguments, returns | Know the target functions |  
| **Valgrind** | Complete binary instrumentation | Allocations, memory accesses, leaks, call graph | None — total instrumented execution |  
| **Sanitizers** | Compile-time instrumentation | Overflows, UB, uninitialized reads | Ability to recompile (or have an instrumented build) |

Valgrind requires **no recompilation** of the target binary. It works on any ELF executable, stripped or not, optimized or not. It's a considerable advantage in an RE context where you generally don't have the sources.

Sanitizers, on the other hand, require recompiling with specific flags (`-fsanitize=address`, etc.). In this training, we have the sources for all training binaries, which allows us to explore both approaches. In real situations, you'll mainly use Valgrind on third-party binaries, and sanitizers when rebuilding a modified binary or when you have a development build.

---

## What we will cover

This chapter breaks down into four sections:

**14.1 — Valgrind / Memcheck**: the flagship tool of the Valgrind suite. We'll see how to run a binary under Memcheck, read and interpret error reports (invalid reads, leaks, use of uninitialized memory), and above all how to **translate these reports into exploitable RE information** — structure sizes, buffer lifetimes, sensitive data flows.

**14.2 — Callgrind + KCachegrind**: Valgrind's call profiler. Without symbols or a decompiler, Callgrind produces a complete call graph with the execution count of each instruction. Coupled with KCachegrind for visualization, it's a formidable way to **map the functional architecture** of an unknown binary and identify its hotspots (crypto loops, parsers, validation routines).

**14.3 — AddressSanitizer (ASan), UBSan, MSan**: sanitizers built into GCC and Clang. We'll see how to recompile our training binaries with `-fsanitize=address,undefined` and interpret the produced reports. The emphasis will be on what these reports reveal about the program's internal logic, beyond simple bug diagnosis.

**14.4 — Leveraging sanitizer reports to understand internal logic**: a synthesis section where we'll apply a systematic methodology to transform Valgrind and sanitizer outputs into verifiable RE hypotheses — structure reconstruction, key buffer identification, understanding a program's memory management.

---

## Prerequisites for this chapter

Before starting, make sure you're comfortable with:

- **GDB and dynamic debugging** (Chapters 11–12) — we'll regularly link addresses reported by Valgrind to their inspection in GDB.  
- **C/C++ memory management basics** — `malloc`/`free`, stack vs heap, notion of buffer overflow and out-of-bounds read.  
- **Compilation with GCC** (Chapter 2) — we'll recompile some binaries with specific flags.

Valgrind and sanitizer installation was covered in Chapter 4. If not already done, verify that `valgrind --version` returns a recent version (3.20+) and that your GCC supports `-fsanitize=address` (GCC 4.8+ for ASan, but prefer GCC 12+ for full support of all sanitizers).

---

## Training binaries used

In this chapter, we'll primarily work with:

- **`ch14-crypto`** (`binaries/ch14-crypto/`) — an encryption binary that manipulates keys and IVs in memory. It's an ideal Valgrind target: cryptographic buffer allocations leave very readable traces in Memcheck reports.  
- **`ch14-keygenme`** (`binaries/ch14-keygenme/`) — our usual crackme, used here to illustrate Callgrind and functional mapping.  
- **`ch14-fileformat`** (`binaries/ch14-fileformat/`) — the custom format parser, useful for demonstrating how sanitizers reveal parsing logic through memory accesses.

Each binary is available at multiple optimization levels. For this chapter, we'll mainly use **`-O0`** versions (more readable in Valgrind reports) and **`-O2`** (to observe the impact of optimizations on diagnostics).

---

## Conventions used in this chapter

> 💡 **RE tip** — Callouts that translate a Valgrind or sanitizer diagnostic into exploitable information for reverse engineering.

> ⚠️ **Warning** — Points of vigilance on false positives, interpretation limits, or common pitfalls.

> 🔧 **Command** — Shell commands to execute, with options explained.

Valgrind and sanitizer outputs are reproduced as-is in code blocks, with `←` annotations to point out key information to extract.

---

*Let's now move to our first tool: Valgrind and its Memcheck module.*


⏭️ [Valgrind / Memcheck — memory leaks and runtime behavior](/14-valgrind-sanitizers/01-valgrind-memcheck.md)
