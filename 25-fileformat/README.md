🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 25 — Reversing a Custom File Format

> 📦 **Training binary**: `binaries/ch25-fileformat/`  
> Compilable via `make` at different optimization levels. The binary reads and writes files in a proprietary format invented for this chapter.

---

## Why reverse a file format?

In Reverse Engineering practice, the target is not always an executable binary whose internal logic needs to be understood. Very often, the real objective is to understand **the data that these binaries produce and consume**. Proprietary software that saves projects in an undocumented `.xyz` format, firmware that stores its configuration in a binary blob, a video game that packs its assets in a custom archive — all situations where the reverse target is not the code itself, but the **file format** it manipulates.

Reversing a file format means answering a seemingly simple question: **"how are these bytes organized, and what do they mean?"** In practice, this requires simultaneously mobilizing static binary analysis (to understand how the parser reads the file), hexadecimal analysis (to directly observe the data structure), and sometimes dynamic analysis (to see the parser in action and confirm hypotheses).

This type of work leads to concrete and immediately useful results:

- **Interoperability** — being able to read or write a proprietary format from a third-party tool, without depending on the original software.  
- **Data migration** — converting files from an obsolete or closed format to an open format.  
- **Security auditing** — understanding how a parser processes data allows identifying vulnerabilities (buffer overflows on size fields, integer overflows on counters, missing magic byte validation...).  
- **Forensics and investigation** — extracting information from a file whose format is not publicly documented.  
- **Documentation** — producing a specification usable by other developers or researchers.

## What we will do in this chapter

The `ch25-fileformat` binary implements a custom file format specifically designed for this exercise. This format has the typical characteristics found in real proprietary formats: a header with magic bytes and metadata, variable-length fields, repeated records, and a few subtleties intentionally introduced to make the analysis more interesting.

Our goal is to start from zero — with no format documentation — and arrive at three complete deliverables:

1. **An ImHex pattern (`.hexpat`)** capable of parsing and colorizing any valid file in this format, making its structure immediately readable.  
2. **A standalone Python parser/serializer**, capable of reading a file in this format, extracting its content, and producing new conforming files.  
3. **A documented specification** of the format, precise enough that a third-party developer could implement their own parser without ever touching the original binary.

## General methodology

Reversing a file format follows an iterative methodology that alternates between direct data observation and analysis of the code that processes it. The process is not purely linear: each discovery in the hex viewer can guide the disassembly analysis, and conversely, each structure identified in the parser code is confirmed (or corrected) by observing the raw bytes.

The approach we will follow in this chapter breaks down into major steps:

**Initial reconnaissance.** Before launching a disassembler, start with the simplest tools: `file` to attempt automatic identification, `strings` to spot readable strings, and `binwalk` to detect known sub-structures or high-entropy zones. This step gives a rough first overview — magic bytes, presence or absence of compression, block sizes.

**Hexadecimal mapping.** Next, open the file in ImHex and begin annotating what you observe: the first bytes (probable header), repetitive patterns (records), padding zones, values that look like sizes or offsets. Progressively build a `.hexpat` pattern that evolves with your discoveries. This is an iterative process: write a first draft, apply it, observe what fits and what doesn't, refine.

**Validation through fuzzing.** Once you have a reasonable hypothesis about the format structure, use AFL++ to fuzz the binary's parser. Crashes reveal code paths that your understanding had not yet covered: a field you thought was ignored but is actually checked, an implicit maximum size, an edge case in record handling. Fuzzing does not replace manual analysis, but it complements it by mechanically exploring the parser's corners.

**Python implementation.** When the format understanding is solid enough, write a Python parser capable of reading existing files. Validate by comparing the Python parser's output with the original binary's behavior. Then add writing capability: generate a file in the format, have the original binary read it, and verify it is accepted. This round-trip step (read → write → re-read) is the ultimate test of our understanding.

**Documentation.** Finally, formalize everything discovered into a structured specification. A good format specification document describes each field with its offset, size, type, possible values, and constraints. It includes structure diagrams and annotated examples.

## Prerequisites for this chapter

This chapter mobilizes skills and tools introduced in previous parts. In particular:

- **ImHex and the `.hexpat` language** (chapter 6) — we will write patterns of real complexity, not just pedagogical examples.  
- **Ghidra or an equivalent disassembler** (chapters 8-9) — to analyze the parser code in the binary when hexadecimal observation is not enough.  
- **AFL++** (chapter 15) — to validate our format understanding by having the fuzzer explore the parser's paths.  
- **Python** — for the final parser. No exotic libraries are needed; `struct`, `io`, and basic types suffice.  
- **Triage tools** (chapter 5) — `file`, `strings`, `binwalk`, `xxd` for initial reconnaissance.

## Section organization

| Section | Content |  
|---|---|  
| 25.1 | Initial reconnaissance with `file`, `strings`, and `binwalk` |  
| 25.2 | Iterative mapping with ImHex and writing the `.hexpat` |  
| 25.3 | Structure validation through fuzzing with AFL++ |  
| 25.4 | Writing an independent Python parser/serializer |  
| 25.5 | Writing the documented format specification |

## 🎯 Chapter checkpoint

> Produce the three deliverables for the `ch25-fileformat` format:  
> - a functional `.hexpat` pattern,  
> - a Python parser capable of reading and writing the format,  
> - a documented format specification.  
>  
> The Python parser must pass the round-trip test: a file generated by the parser must be accepted and correctly read by the original binary.

---


⏭️ [Identifying the overall structure with `file`, `strings`, and `binwalk`](/25-fileformat/01-identifying-structure.md)
