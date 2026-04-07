🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 10 — Binary diffing

> **Part II — Static Analysis**  
>  
> 📦 Binaries used: `binaries/ch10-keygenme/` (variants `keygenme_v1` and `keygenme_v2`)  
> 🧰 Tools: BinDiff, Diaphora, `radiff2`, Ghidra, IDA Free

---

## Chapter overview

Throughout previous chapters, we learned to disassemble a binary, navigate its code with Ghidra or Radare2, and understand what it does. But in practice, the question is not always "what does this binary do?" — it's often **"what has changed between these two versions?"**.

**Binary diffing** consists of comparing two versions of the same compiled program to precisely identify the functions, blocks, or instructions that were added, removed, or modified. It's a discipline in its own right, at the intersection of reverse engineering and vulnerability analysis.

### Why it's indispensable

When a vendor releases a security fix, they don't generally provide the exact details of the corrected vulnerability — and that's understandable. But the binary patch itself contains all the information: by comparing the vulnerable version and the fixed version, you can locate the modified function, understand the nature of the flaw, and in some cases, write an exploit for systems not yet updated. This is the technique known as **patch diffing** (or *1-day analysis*), used by both defensive security teams and offensive researchers.

Beyond security, diffing also serves to understand the evolution of proprietary software between two releases, to verify that a recompilation produces an identical result (*reproducible builds*), or to analyze behavior differences introduced by a change of compilation flags.

### What you will learn

This chapter covers the most used diffing tools and methodologies in the RE ecosystem:

- **BinDiff** (Google) — the historical reference tool, which works from bases exported by Ghidra or IDA. It compares control-flow graphs (CFG) to match functions between two binaries and assign a similarity score to each pair.

- **Diaphora** — an open-source alternative in the form of a Ghidra/IDA plugin, which offers similar capabilities to BinDiff with increased flexibility thanks to its approach via multiple heuristics (pseudo-code hashes, symbol names, constants, call graphs).

- **`radiff2`** — the diffing tool integrated into the Radare2 suite, usable entirely on the command line. Less graphically rich, but perfectly suited to automation and scripting in an analysis pipeline.

- **Concrete application** — a complete practical case where you will compare two versions of the same binary to identify a vulnerability fix, combining the tools seen in the chapter.

### Prerequisites

This chapter relies directly on skills acquired in previous chapters:

- **Chapter 7** — Disassembly with `objdump` and Binutils (reading disassembled code, Intel syntax)  
- **Chapter 8** — Ghidra (navigation in the CodeBrowser, cross-references, decompiler)  
- **Chapter 9** — IDA Free and Radare2 (base workflow, essential `r2` commands)

Familiarity with the concept of control-flow graph (CFG) — seen in Ghidra's Function Graph in Chapter 8 — is particularly useful here, because it's the representation on which most diffing algorithms rely.

### Pedagogical approach

The chapter follows a four-phase progression:

1. **The why** — understand the motivations and concrete scenarios that justify binary diffing.  
2. **Graphical tools** — BinDiff then Diaphora, with import from Ghidra, reading results, and interpreting similarity scores.  
3. **Command line** — `radiff2` for automated workflows and integration into scripts.  
4. **Hands-on practice** — a realistic patch-diffing case on two versions of a provided binary.

Each section includes annotated screenshots and reproducible commands on the repository's binaries.

---

## Chapter sections

- 10.1 [Why compare two versions of the same binary (patch analysis, vuln detection)](/10-binary-diffing/01-why-diffing.md)  
- 10.2 [BinDiff (Google) — installation, import from Ghidra/IDA, reading the result](/10-binary-diffing/02-bindiff.md)  
- 10.3 [Diaphora — open-source Ghidra/IDA plugin for diffing](/10-binary-diffing/03-diaphora.md)  
- 10.4 [`radiff2` — command-line diffing with Radare2](/10-binary-diffing/04-radiff2.md)  
- 10.5 [Practical case: identify a vulnerability fix between two versions of a binary](/10-binary-diffing/05-practical-patch-vuln.md)  
- [**🎯 Checkpoint**: compare `keygenme_v1` and `keygenme_v2`, identify the modified function](/10-binary-diffing/checkpoint.md)

---

> **💡 Tip** — If you haven't installed Radare2 yet, go back to Chapter 4 (section 4.2) for the installation procedure. BinDiff and Diaphora will be installed in their respective sections.

⏭️ [Why compare two versions of the same binary (patch analysis, vuln detection)](/10-binary-diffing/01-why-diffing.md)
