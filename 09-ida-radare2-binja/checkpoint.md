🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 9

## Analyze the same binary in 2 different tools, compare decompiler results

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [9.6 — Ghidra vs IDA vs Radare2 vs Binary Ninja comparison](/09-ida-radare2-binja/06-tools-comparison.md)

---

## Goal

This checkpoint validates your ability to use at least two disassemblers autonomously on the same binary, and to take a critical look at the differences in results between tools. It mobilizes all the chapter's skills: navigation, annotation, decompilation, and cross-references.

The deliverable is a **short comparative report** (1 to 2 pages) documenting your analysis and observations.

## Target binary

The binary to analyze is `keygenme_O2_strip`, located in `binaries/ch09-keygenme/`. It's the running-thread binary used throughout the chapter: compiled with `-O2`, stripped, ELF x86-64. If you followed sections 9.1 to 9.5, you've already opened it in several tools — this checkpoint asks you to formalize the comparison.

## Choice of tools

Choose **two tools among the four** covered in Chapters 8 and 9:

- Ghidra (Chapter 8)  
- IDA Free (section 9.1)  
- Radare2 / Cutter (sections 9.2–9.4)  
- Binary Ninja Cloud (section 9.5)

The recommended combination for a first checkpoint is **Ghidra + another tool of your choice**. Since Ghidra is the training's main tool, comparing it with a second tool anchors the cross-checking practice that will be useful throughout the following parts.

## Expected elements in the report

The comparative report must cover the following points.

### 1 — Function recognition

Indicate for each tool the total number of functions detected after complete automatic analysis. Identify any divergences: did one tool detect functions the other missed? If so, at what addresses, and why in your opinion (different detection heuristic, code confused with data, function too short to be detected)?

Also note whether both tools automatically identified `main`, and by what mechanism (recognition of the `__libc_start_main` pattern, residual symbols, name heuristic).

### 2 — Decompiled-code quality on the main function

Focus on the serial-verification function (the one containing the `strcmp` calls and branches to the "Access granted" / "Wrong key" strings). Export or capture the pseudo-code produced by each of the two tools for this same function.

Compare the results along the following axes:

- **Readability** — which of the two pseudo-codes is most immediately understandable? Are variable names more explicit in one or the other?  
- **Fidelity** — do both decompilers rebuild the same control structure (same `if/else`s, same conditions)? Are there `goto`s in one but not the other?  
- **Types** — are variable and parameter types inferred the same way? Did one tool better propagate types (for example, recognize a `char *` where the other displays an `undefined *` or an `int64_t`)?  
- **Errors or artifacts** — does one of the decompilers produce manifestly incorrect or misleading code (phantom variable, inverted condition, wrongly resolved function call)?

### 3 — Cross-references and navigation

For the "Access granted" string (or "Wrong key"), document the navigation path in each tool: how did you locate the string, how did you trace back XREFs, and how did you reach the verification function. Note ergonomic differences: number of clicks or commands needed, clarity of XREF display, ease of going back.

### 4 — Annotations and renamings

In each of the two tools, rename the verification function and at least two local variables with meaningful names. Document the ease of the operation: keyboard shortcut or menu, immediate or non-immediate propagation in disassembly and decompiled code, persistence after closing and reopening the project.

### 5 — Synthesis and argued preference

Conclude the report with a personal synthesis. On this specific binary and with the tasks performed, which tool did you find most effective and why? Are there tasks where one clearly surpassed the other? Which tool would you use first on a next similar binary, and in what case would you switch to the second?

There's no "right answer" to this synthesis — the goal is to build your own informed decision grid, not to reproduce the one from section 9.6.

## Validation criteria

The checkpoint is validated if the report:

- Covers the five points above with concrete observations (addresses, function names, pseudo-code excerpts, counts).  
- Contains at least one specific example of divergence between the two tools (even minor).  
- Shows that you actually manipulated both tools (and not just described their theoretical features).  
- Formulates an argued synthesis based on your direct experience.

## Report format

The report can be written in Markdown, plain text, or the format of your choice. It's intended for your personal use — it's a working document, not a formal deliverable. Screenshots or pseudo-code copy-pastes are welcome to illustrate comparison points.

A minimalist template:

```
# Checkpoint Ch.9 — [Tool A] vs [Tool B] comparison
Binary: keygenme_O2_strip

## 1. Function recognition
[Tool A]: XX functions detected
[Tool B]: XX functions detected
Divergences: ...

## 2. Decompiled verification function
### [Tool A]
(pseudo-code or capture)
### [Tool B]
(pseudo-code or capture)
### Comparison
...

## 3. Navigation and XREFs
...

## 4. Annotations
...

## 5. Synthesis
...
```

## Going further

If you wish to deepen the exercise, you can extend the comparison along two additional axes:

- **Compare three tools** instead of two, which makes divergences more visible and allows deciding cases where two tools agree against a third.  
- **Repeat the analysis on `keygenme_O0`** (with symbols, no optimization) then on `keygenme_O2_strip` to observe how binary difficulty affects the relative quality of tools. A tool may excel on a `-O0` binary and fall behind on a stripped `-O2`, or vice versa.

---

> ✅ **Checkpoint completed?** You now master the basics of four major disassemblers and know how to compare them critically. The rest of the training (Part III — Dynamic Analysis) will introduce GDB and debugging tools, which will complete your arsenal with the dynamic dimension of reverse engineering.  
>  
> 

⏭️ [Chapter 10 — Binary diffing](/10-binary-diffing/README.md)
