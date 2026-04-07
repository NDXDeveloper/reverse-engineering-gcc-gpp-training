🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 10.1 — Why compare two versions of the same binary (patch analysis, vuln detection)

> **Chapter 10 — Binary diffing**  
> **Part II — Static Analysis**

---

## The fundamental problem

When reversing an isolated binary, you try to understand **what it does**. But in many professional scenarios, the question is different: **what has changed?** Between two versions of a firmware, between a Tuesday security patch and the Monday binary, between a development build and a production one — the difference is often more telling than the complete code.

The problem is that you can't simply run `diff` on two binaries. A textual or byte-by-byte `diff` is unusable in practice: the slightest change in one function shifts the addresses of all the following functions, jump offsets are recomputed, relocation tables change, and the result is a wall of meaningless differences. Even two successive compilations of the **same source code** with the same compiler can produce slightly different binaries (timestamps, build paths embedded in DWARF metadata, randomization of some internal layouts).

**Binary diffing** solves this problem by working at a higher abstraction level: instead of comparing bytes, you compare **functions**, **basic blocks**, and **control-flow graphs** (CFG). Diffing tools match functions between two binaries by relying on structural heuristics — CFG signatures, constants used, symbol names when they exist, decompiled pseudo-code hashes — then, for each matched function pair, identify the blocks that were modified, added, or removed.

---

## Concrete diffing scenarios

### Patch diffing (1-day analysis)

This is the most emblematic use case. When a vendor releases a security fix — whether Microsoft on Patch Tuesday, Adobe for a Reader, or an open-source project that only provides an updated binary — the associated security bulletin rarely gives more than a vague description: "memory corruption vulnerability in the PDF parsing module, allowing arbitrary code execution". Sometimes even less.

The patched binary, however, contains **all** the information. By comparing the vulnerable version (before the patch) and the fixed version (after the patch), you can:

1. **Locate the modified function** — on a binary with thousands of functions, the diff reduces the investigation scope to a handful of functions, often one or two.  
2. **Understand the nature of the vulnerability** — the diff shows exactly what has changed. Adding a size check before a `memcpy` suggests a buffer overflow. A new null-check points to a null-pointer dereference. A change in a loop condition indicates an off-by-one.  
3. **Evaluate real criticality** — the bulletin says "critical", but what does that mean concretely? The diff lets you judge whether the vulnerability is actually exploitable in a given context.  
4. **Develop a proof of concept** — for offensive researchers or red-team members, the diff considerably speeds up the understanding needed to write an exploit (this is called **1-day** analysis, as opposed to **0-day** where the vulnerability is found without prior knowledge of the patch).

> ⚠️ **Ethical note** — 1-day analysis is a legitimate and common practice in the security industry. It's used by defensive teams to evaluate patch-deployment urgency, by security-solution vendors to create detection signatures, and by researchers to understand vulnerability classes. As always, it's intent and legal framework that determine the legitimacy of the use (cf. Chapter 1, section 1.2).

### Binary regression analysis

In a development context, diffing allows verifying that modifications to source code do translate into the expected changes — and only those — in the final binary. It's particularly useful in the following cases:

- **Compiler version change** — moving from GCC 12 to GCC 14 can subtly change the generated code. Diffing lets you precisely identify functions whose code generation has changed and verify that no performance or behavior regression has been introduced.  
- **Compilation flag change** — enabling `-O2` instead of `-O0`, adding `-fstack-protector-strong`, switching to `-fPIC` for a shared library… each flag has visible consequences in the binary. Diffing quantifies and locates these consequences.  
- **Build-chain audit** — in environments where software supply-chain security is critical (embedded, aerospace, defense), diffing lets you verify that a delivered binary matches the audited source code, by comparing the result of a controlled recompilation to the production binary.

### Reproducible builds

The *reproducible builds* movement aims to guarantee that anyone can recompile software from its sources and obtain a **bit-for-bit identical** binary to the distributed one. The goal is to allow independent verification: if the distributed binary differs from the recompilation result, it has been tampered with (backdoor, build-chain compromise).

In practice, achieving perfect reproducibility is difficult — timestamps, file paths, the compiler's file-processing order introduce variations. Diffing then intervenes to distinguish **cosmetic** differences (a different timestamp in an ELF header) from **semantic** differences (a function whose code has changed). It's a precious tool for projects tending towards reproducibility without having fully achieved it yet.

### Tracking the evolution of proprietary software

When working on interoperability with proprietary software — a network protocol, a file format, a driver — each new version can modify the behavior you carefully documented. Diffing allows tracking these evolutions in a targeted way: instead of re-reversing the entire binary at each release, you compare both versions and concentrate effort on functions that changed. It's a considerable time saving on multi-megabyte binaries with thousands of functions.

### Malware analysis: tracking variants

Malware families evolve through iterations. A ransomware version 2.1 shares most of its code with version 2.0, but may have modified its encryption algorithm, added an evasion mechanism, or changed its C2 protocol. Diffing allows malware analysts to immediately focus on what's new instead of starting over, and to maintain a chronology of modifications across variants.

---

## What diffing reveals — and what it doesn't

### What diffing does well

Diffing excels at answering structural and quantitative questions:

- **Which functions changed?** — with a confidence score on the match.  
- **Which functions are new?** — present in version B but absent from version A.  
- **Which functions were removed?** — present in A, absent from B.  
- **What is the extent of the change?** — a modification of a single basic block in a 50-block function, or a complete rewrite?  
- **Where exactly in the function is the change?** — at the basic-block level, with side-by-side visualization.

### What diffing does not do by itself

Diffing locates changes but doesn't **explain** them. Knowing that a `jl` (jump if less) was replaced by a `jle` (jump if less or equal) in the `parse_header` function is valuable information, but understanding that this fixes an off-by-one that allowed a heap overflow still requires the reverse engineer's expertise. Diffing is an **orientation tool**: it reduces a 10,000-function binary to 3 modified functions, and that's where classic RE work resumes.

Similarly, diffing doesn't handle massive structural changes well. If a binary was entirely recompiled with a different compiler, or if a major refactoring reorganized the code, matching algorithms can fail to recognize the corresponding functions. In these cases, tools will signal a large number of "unmatched" functions, and the analysis will have to be completed manually.

---

## Anatomy of a binary diff

To understand what tools will show us in the following sections, it's useful to set the vocabulary and concepts. A binary-diff result typically presents itself in the form of three categories of functions:

### Matched identical functions (*matched, identical*)

These functions exist in both binaries and are considered identical by the algorithm. They were not modified between the two versions. It's generally the vast majority of functions — a security patch rarely modifies more than a few functions out of several thousand.

### Matched changed functions (*matched, changed*)

These functions exist in both binaries and have been recognized as corresponding, but their content differs. That's where the most interesting information lies. For each pair, the tool provides:

- A **similarity score** (typically between 0.0 and 1.0) — a function with a score of 0.95 has only undergone a minor change, while a score of 0.3 indicates a substantial rewrite.  
- A **basic-block-level diff** — side-by-side visualization of basic blocks, with coloring of modified, added, and removed blocks.  
- The **modified instructions** within each block.

### Unmatched functions (*unmatched*)

These functions only exist in one of the two binaries. In version A but not in B: the function was removed (or renamed/refactored to the point of being unrecognizable). In B but not in A: it's a new function. However, beware: an "unmatched" function is not necessarily new — it happens that the algorithm fails to recognize a significantly modified function and mistakenly classes it in this category.

---

## Matching algorithms: the intuition

Without going into mathematical details (each tool has its own heuristics), here are the main families of criteria used to match functions between two binaries:

- **Name matching** — if both binaries are not stripped, function names are the most reliable criterion. Two functions bearing the same symbol are matched in priority.  
- **Structural CFG hash** — the control-flow graph (number of blocks, number of edges, branch structure) is converted into a hash. Two functions with the same structural hash are very probably the same.  
- **Referenced constants and strings** — if a function references the string `"Invalid header size"` and a call to `malloc(0x200)` in both versions, it's a strong matching hint.  
- **Pseudo-code hash** — some tools (notably Diaphora) compare the pseudo-code produced by the decompiler. It's more resistant to cosmetic changes (register reordering, address changes) than comparison at the assembly level.  
- **Position in the call graph** — a function called by the same callers and calling the same callees in both versions is probably the same, even if its internal code changed.  
- **Propagation** — once some functions are matched with high confidence, their neighbors in the call graph can be matched by propagation (if A calls B and C in version 1, and A' calls B' and C' in version 2, and we already know A↔A' and B↔B', then C↔C' is likely).

Tools combine these criteria in multiple passes, from the most reliable (exact name or hash match) to the most heuristic (call-graph propagation), to maximize the number of matched functions.

---

## In summary

Binary diffing is a productivity multiplier for the reverse engineer. Rather than drowning the analyst under a program's entire code, it surgically isolates changes and allows concentrating human effort where it has the most value. It's an unavoidable tool in the security professional's toolbox, whether working on defense (patch evaluation, variant analysis) or research (vulnerability understanding, interoperability).

In the following sections, we'll put these concepts into practice with the three main tools of the ecosystem: BinDiff, Diaphora, and `radiff2`.

---


⏭️ [BinDiff (Google) — installation, import from Ghidra/IDA, reading the result](/10-binary-diffing/02-bindiff.md)
