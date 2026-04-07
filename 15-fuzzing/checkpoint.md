🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 15: Fuzzing for Reverse Engineering

> **Objective**: fuzz the `ch15-fileformat` binary with AFL++, find at least 2 crashes and analyze them.  
> 📦 **Binary**: `binaries/ch15-fileformat/`  
> ⏱️ **Estimated duration**: 1h30 to 2h (compilation + fuzzing + analysis)  
> 📄 **Answer key**: `solutions/ch15-checkpoint-solution.md`

---

## Context

This checkpoint validates your mastery of the entire RE-oriented fuzzing pipeline presented in this chapter. You're working on the custom format parser `ch15-fileformat` — the same binary as in the practical case (Section 15.7). If you followed the practical case alongside, you can build on your existing results; otherwise, you start from scratch.

The checkpoint is considered passed when the **five deliverables** below are produced.

---

## Expected deliverables

### 1. Instrumented and functional binary

Compile `ch15-fileformat` with `afl-gcc` (or `afl-clang-fast`) and verify that instrumentation is active. Also compile a build with ASan for crash triage.

**Validation criterion**: `afl-showmap` produces non-empty output when running the instrumented binary with a valid seed.

### 2. Initial corpus and dictionary

Build an initial corpus of at least **3 seeds** targeting different parser branches, and a dictionary of at least **10 relevant tokens** extracted from triage (`strings`, constants, boundary values).

**Validation criterion**: each seed reaches at least one distinct parser branch (verifiable with `afl-showmap` — the seeds' bitmaps must differ).

### 3. Productive AFL++ fuzzing campaign

Launch `afl-fuzz` with the corpus and dictionary. Let it run until obtaining at minimum:

- **20 inputs** in the corpus (`corpus count ≥ 20`)  
- **2 saved crashes** (`saved crashes ≥ 2`)

**Validation criterion**: the `out/default/queue/` directory contains at least 20 files and `out/default/crashes/` contains at least 2 files.

### 4. Detailed analysis of 2 crashes

For each of the 2 crashes (at minimum):

- **Reproduce** the crash on the ASan build and note the bug type (heap-buffer-overflow, SEGV, stack-buffer-overflow, etc.) and the affected function.  
- **Minimize** the crash input with `afl-tmin`.  
- **Examine** the minimized input with `xxd` and propose a field interpretation (which bytes correspond to the magic, version, section type, length, etc.).  
- **Trace** the crash in GDB (or GEF/pwndbg) to identify the condition path taken from the parser's entry to the crash point.

**Validation criterion**: for each crash, a paragraph describing the bug type, the faulty function, the execution path, and the format fields involved.

### 5. Format mapping draft

From analyzed crashes and corpus examination, produce a table (even partial) describing the identified fields of the input format:

```
Offset  Size    Field              Known values
──────  ──────  ─────────────────  ──────────────────────
0x00    ?       ...                ...
...
```

**Validation criterion**: at least 4 identified fields with their offset, size, and a description of their role.

---

## Self-assessment rubric

| Criterion | Insufficient | Proficient | Mastered |  
|-----------|-------------|------------|----------|  
| **Instrumented compilation** | Binary not instrumented or `afl-showmap` fails | Functional AFL++ build, `afl-showmap` produces a bitmap | AFL++ build + ASan build + gcov build for coverage |  
| **Corpus and dictionary** | Empty or generic corpus (single `\x00`), no dictionary | 3+ targeted seeds, dictionary of 10+ tokens from triage | Seeds built per identified branch, dictionary enriched after first pass |  
| **Fuzzing campaign** | Fewer than 20 inputs or 0 crashes | 20+ inputs, 2+ crashes, stable campaign | 50+ inputs, 3+ crashes, parallel fuzzing, iterated dictionary |  
| **Crash analysis** | Crashes listed but not analyzed | 2 crashes reproduced with ASan, inputs examined with `xxd` | Crashes minimized, traced in GDB, condition path documented |  
| **Format mapping** | No structural information extracted | 4+ fields identified with offset and size | Field table + parser decision tree |

---

## Tips before getting started

**Start with triage.** The first 5 minutes with `file`, `strings`, and `checksec` save hours of blind fuzzing. Every string found is a potential clue for the dictionary or corpus.

**Test your seeds before launching the fuzzer.** Run each seed manually on the binary and verify it doesn't cause an immediate rejection ("file too small," "invalid magic"). A seed that passes at least the first validation is infinitely more useful than one rejected at the entry.

**Don't let it run indefinitely.** If `last new find` in the AFL++ dashboard hasn't moved for 15 minutes, move on to analyzing results or enrich the corpus/dictionary. The reverse engineer's time is more valuable than CPU time.

**Minimize before analyzing.** A 200-byte crash is hard to interpret. The same crash minimized to 18 bytes is often directly readable — every byte matters.

**Document as you go.** Note your observations at each step: what `strings` revealed, why you chose a particular seed, what the crash taught you. These notes constitute your final deliverable and will be reused in Chapter 25.

---

## Bridge to what's next

This checkpoint closes Part III (Dynamic Analysis). The `ch15-fileformat` binary will be revisited in Chapter 25 with a complete analysis: ImHex for hexadecimal mapping, Ghidra for in-depth static analysis, and a complete Python parser. The corpus, dictionary, and structural knowledge produced here will be directly reused.

Part IV (Advanced Techniques) begins with Chapter 16 on compiler optimizations — a topic that radically changes the appearance of disassembled code and directly impacts fuzzing results (an `-O2` binary doesn't crash at the same places as an `-O0` binary).

---


⏭️ [Part IV — Advanced RE Techniques](/part-4-advanced-techniques.md)
