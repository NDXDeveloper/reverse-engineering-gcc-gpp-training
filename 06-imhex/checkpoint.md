🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Chapter 6 Checkpoint — Writing a complete `.hexpat` for the `ch23-fileformat` format

> **Goal**: Validate the full set of skills acquired in this chapter by autonomously producing a complete `.hexpat` pattern for a file format you have not yet analyzed.

---

## Context

The `binaries/ch06-fileformat/fileformat_O0` binary produces a second type of data file that we did not explore in the practical case of section 6.11. This file, with the `.pkt` extension and located in the same directory under the name `sample.pkt`, uses a proprietary format tied to the network protocol we will reverse in Chapter 23.

You have neither the source code nor documentation of this format. Your only information source is the file itself and the ImHex tools seen in this chapter.

---

## Expected deliverable

A `hexpat/ch06_pkt_format.hexpat` file that, once evaluated in ImHex on `sample.pkt`:

1. **Parses the entire file** — no byte zone should remain uncovered by the pattern (except any padding zones explicitly identified as such).

2. **Names each field descriptively** — variable names must reflect the probable function of the field (`packet_type`, `payload_length`, `sequence_number`…), not generic labels (`field1`, `field2`).

3. **Uses appropriate types** — signed/unsigned integers of the right size, `char[]` for strings, `enum` for fields with symbolic values, `bitfield` if bit-flags are identified.

4. **Leverages `.hexpat` attributes** — at minimum `[[comment(...)]]` on fields whose interpretation deserves explanation, and `[[format("hex")]]` on offsets and addresses.

5. **Handles variable-size structures** — if the format contains arrays whose size depends on a field (which is likely for a network packet format), the pattern must parse them dynamically.

---

## Validation criteria

Your pattern is considered successful if it meets the following conditions:

| Criterion | Validation |  
|---|---|  
| The pattern evaluates without error | No error message in the Pattern Editor |  
| The Pattern Data tree covers the entire file | The sum of sizes of instantiated variables matches the file size |  
| The parsed values are coherent | Counters contain small plausible integers, strings are readable, offsets point to existing zones |  
| Enums display symbolic names | At least one field uses a typed `enum` |  
| Colorization distinguishes regions | Header, metadata, and payload data are visually separated in the hex view |  
| The pattern is documented | Each structure carries at least one explanatory `[[comment(...)]]` |

---

## Starting hints

These hints guide you without giving the solution. Follow the methodology of section 6.11.

**Hint 1 — The magic number.** Like most structured formats, the file begins with an identifiable magic number. The command `xxd sample.pkt | head -1` reveals it in seconds.

**Hint 2 — Endianness.** The format is tied to a network protocol. Some fields may follow the network convention (big-endian) rather than the x86 convention (little-endian). ImHex's Data Inspector shows both interpretations simultaneously — if the big-endian value of a field is more plausible than the little-endian value, that's a hint.

**Hint 3 — The structure is hierarchical.** The file probably contains a global header followed by multiple packets, each with its own sub-header and payload. Look for a repeating pattern in the data after the global header.

**Hint 4 — File size.** Compare the total file size with counters and sizes read in the header. If `header.total_length` matches the file size, that's a strong validation of your interpretation.

**Hint 5 — Entropy.** The entropy profile (**View → Information**) tells you whether there are encrypted, compressed, or uniform zones. This information guides the analysis strategy before you even read a single byte manually.

---

## Recommended approach

The approach followed in section 6.11 remains the reference:

1. Initial CLI triage (`file`, `strings`, `xxd | head`).  
2. Opening in ImHex, entropy analysis, exploratory bookmarks.  
3. Header exploration with the Data Inspector, first hypothesis, first pattern.  
4. Identification of intermediate structures (descriptor table, index, metadata).  
5. Parsing data (packets, records, payload).  
6. Full-file-coverage verification, discovery of any end structures.  
7. Assembling the complete pattern, documentation with `[[comment]]`, saving the project.

Don't try to understand everything at once. Start with the header, validate it, then progress to following structures. Each confirmed field reduces the uncertainty on neighboring fields.

---

## Allowed resources

- Every section of this chapter (6.1 to 6.11).  
- The `hexpat/elf_header.hexpat` pattern as a syntax reference.  
- The CLI tools of Chapter 5 (`file`, `strings`, `xxd`, `readelf`).  
- The `.hexpat` language documentation integrated into ImHex (**Help → Pattern Language Documentation**).  
- The Data Inspector, bookmarks, search, entropy analysis, built-in disassembler, and YARA engine of ImHex.

You must **not** use the disassembly of the `fileformat_O0` binary to solve this checkpoint. The goal is to map the format from the data file alone, exactly as in section 6.11. Cross-referencing with disassembly will be the subject of Chapter 25.

---

## Solution

The solution is available in `solutions/ch06-checkpoint-solution.hexpat`. Consult it only after producing your own version and attempting to validate the criteria above. Comparing your pattern with the solution is an exercise in itself: field names, chosen types, and interpretation hypotheses may differ while being equally valid.

---


⏭️ [Chapter 7 — Disassembly with objdump and Binutils](/07-objdump-binutils/README.md)
