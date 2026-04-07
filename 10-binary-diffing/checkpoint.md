🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 10: Binary diffing

> **Goal**: validate your mastery of the diffing workflow by comparing two versions of a binary and identifying the modified function.  
>  
> 📦 Binaries: `binaries/ch10-keygenme/keygenme_v1` and `binaries/ch10-keygenme/keygenme_v2`  
> 📄 Solution: `solutions/ch10-checkpoint-solution.md`

---

## Statement

You receive two versions of the same binary compiled with GCC: `keygenme_v1` and `keygenme_v2`. A security bulletin indicates that an input-validation vulnerability was fixed in version v2, without further details.

Your mission is to produce a **patch-diffing report** that precisely documents the modifications made between the two versions.

---

## Expected deliverable

A Markdown (or text) report containing the following elements:

### 1. Initial triage

- The global similarity score between both binaries (obtained with `radiff2 -s`).  
- The number of bytes that differ.  
- Your conclusion at this stage: is the patch targeted or extensive?

### 2. Inventory of modified functions

- The complete list of matched functions and their similarity score, obtained with at least one of the three chapter's tools (`radiff2 -AC`, BinDiff, or Diaphora).  
- Clear identification of the function(s) whose score is below 1.0.  
- For each unmodified function, a simple mention confirming that it's identical between the two versions.

### 3. Analysis of the modified function

- The name (or address, if the binary is stripped) of the modified function.  
- A description of the observed changes at the control-flow graph level: how many basic blocks in v1, how many in v2, which blocks were added/modified/removed.  
- The pseudo-code diff (obtained with Diaphora) or, failing that, the side-by-side assembly diff showing the added or modified instructions.  
- Your interpretation of the change: what does the added code do? What check was missing in v1?

### 4. Characterization of the vulnerability

- The nature of the fixed vulnerability, described in one or two sentences.  
- The vulnerability type according to CWE taxonomy (identifier and name).  
- The potential impact if the vulnerability were exploited.

### 5. Summary table

A summary table following this model:

| Element | Detail |  
|---------|--------|  
| Modified function | *(name or address)* |  
| Change nature | *(short description)* |  
| Vulnerability type | *(CWE-XX)* |  
| Potential impact | *(short description)* |  
| Applied fix | *(short description)* |

---

## Tools to use

The report must demonstrate the use of **at least two** of the following three tools:

- `radiff2` (mandatory triage — it's the first step of the workflow)  
- BinDiff (BinExport from Ghidra or IDA, comparison, CFG reading)  
- Diaphora (SQLite export from Ghidra or IDA, pseudo-code diff)

Use of all three tools is encouraged but not mandatory. What matters is showing that you know how to choose the right tool for each step of the analysis.

---

## Validation criteria

Your checkpoint is validated if your report:

- ✅ Correctly identifies the function modified by the patch.  
- ✅ Describes the changes at the CFG level (number of blocks, added blocks).  
- ✅ Explains the nature of the fixed vulnerability with coherent interpretation.  
- ✅ Includes a similarity score from `radiff2` or BinDiff.  
- ✅ Presents a diff (pseudo-code or assembly) of the modified function.  
- ✅ Contains an exploitable summary table.

---

## Tips before starting

- Follow the funnel workflow presented in the chapter: **triage** (`radiff2`) → **overview** (BinDiff) → **detailed analysis** (Diaphora) → **assembly verification** (Ghidra). Each step reduces the investigation scope.  
- Don't try to understand the entire binary. Diffing serves precisely to avoid that — concentrate on what has changed.  
- If you're stuck on installing a tool, don't hesitate to skip to the next one. Two tools out of three suffice to produce a complete report.  
- Take screenshots of CFG views and pseudo-code diffs to enrich your report. A good patch-diffing report is as visual as textual.

---

> 📄 **Solution available**: `solutions/ch10-checkpoint-solution.md` — consult it only after producing your own report.  
>  
> 

⏭️ [Part III — Dynamic Analysis](/part-3-dynamic-analysis.md)
