🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 35 — Automation and Scripting

> 📂 `35-automation-scripting/`  
> 🎯 **Objective**: transform the manual techniques covered throughout the training into reproducible, scriptable workflows that can be integrated into analysis pipelines.

---

## Why automate Reverse Engineering?

Throughout the previous chapters, each analysis followed a recurring pattern: initial triage, section and symbol inspection, disassembly, dynamic analysis, data extraction, report writing. Performed manually, these steps are reliable on an isolated binary, but they become a bottleneck as volume increases — whether comparing twenty variants of the same firmware, monitoring updates to a third-party library, or scanning a fleet of binaries for suspicious cryptographic constants.

Automation doesn't replace the analyst's judgment. It handles repetitive and deterministic tasks so the analyst can focus attention where it has the most value: understanding business logic, identifying subtle anomalies, and making decisions in the face of ambiguity. A good RE script doesn't do the analysis *for you* — it frees you from everything that doesn't require your brain.

## What this chapter covers

This chapter gathers the scripting tools and methods we've encountered sporadically in previous parts, and organizes them into a coherent toolkit:

**Parsing and modifying ELF binaries** — with `pyelftools` for read-only inspection and `lief` for structural transformations (adding sections, modifying headers, patching entry points). These two Python libraries form the programmatic foundation of any automation on ELF binaries.

**Batch analysis with Ghidra headless** — Ghidra exposes a GUI-less mode (`analyzeHeadless`) that allows launching auto-analysis and executing Java or Python scripts on one or more binaries, from the command line. This is the key to processing entire corpora without manually opening each project.

**RE scripting with `pwntools`** — beyond its exploitation use, `pwntools` offers a complete framework for interacting with binaries (process launching, sending/receiving data, in-memory patching), making it a versatile tool for automating dynamic tests and hypothesis validation.

**Pattern detection with YARA** — writing YARA rules allows searching for signatures (crypto constants, characteristic strings, opcode sequences) across a collection of binaries. It's the natural bridge between unit analysis and large-scale scanning.

**CI/CD integration** — analysis scripts can be inserted into a continuous integration pipeline to automatically audit each build, detect binary regressions (debug symbols left in production, disabled protections, unexpected dependencies), and produce reports usable by the entire team.

**Building a personal toolkit** — the last section covers the practical organization: how to structure scripts, manage dependencies, document tools, and progressively build an RE toolkit adapted to your needs.

## Prerequisites for this chapter

This chapter builds on all skills acquired in previous parts. In particular:

- **Intermediate Python** — the scripts presented use third-party libraries, manipulate binary structures, and interact with processes. Comfort with `pip`, virtual environments, and byte manipulation in Python is necessary.  
- **Familiarity with the tutorial's tools** — Ghidra (Chapter 8), GDB (Chapter 11), `pwntools` (Chapter 11, section 9), ImHex and YARA (Chapter 6), `readelf`/`objdump` (Chapters 5 and 7). You don't need to master them perfectly, but you should know what they do and have launched each of them at least once.  
- **Basic Linux shell knowledge** — CI/CD pipelines and script orchestration assume comfort with Bash, redirections, and classic tools (`find`, `xargs`, `jq`).

## Approach philosophy

Throughout this chapter, we follow three guiding principles:

**Start small, iterate fast.** A 20-line script that does one thing well is better than a 2,000-line framework never finished. Each section starts from a minimal concrete case before generalizing.

**Structured output, always.** A script's results must be usable by another script. This means JSON output rather than free text, consistent return codes, and logs separated from the result. A human-readable report can always be generated *from* structured output — the reverse is rarely true.

**Reproduce before optimizing.** Automation only has value if it produces reliable and reproducible results. Before speeding up a workflow, ensure it gives the same result on each execution with the same input, in the same environment.

## Chapter structure

| Section | Content | Primary tools |  
|---|---|---|  
| 35.1 | ELF parsing and modification in Python | `pyelftools`, `lief` |  
| 35.2 | Batch analysis with Ghidra headless | `analyzeHeadless`, Ghidra scripts |  
| 35.3 | RE scripting with `pwntools` | `pwntools` |  
| 35.4 | Pattern detection with YARA | `yara-python`, `.yar` rules |  
| 35.5 | Integration into a CI/CD pipeline | GitHub Actions, shell scripts |  
| 35.6 | Building a personal RE toolkit | organization, documentation |  
| **Checkpoint** | Batch analysis script → JSON report | all chapter tools |

---

> 💡 **Tip**: keep a terminal open with the `binaries/` repository within reach. This chapter's examples directly rely on binaries compiled in previous chapters — particularly `ch21-keygenme/`, `ch24-crypto/`, and `ch25-fileformat/`. If you haven't compiled them yet, a simple `make all` from `binaries/` is sufficient.

---


⏭️ [Python scripts with `pyelftools` and `lief` (ELF parsing and modification)](/35-automation-scripting/01-pyelftools-lief.md)
