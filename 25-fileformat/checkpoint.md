🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 25

> **Objective**: produce the three chapter deliverables for the `ch25-fileformat` format — a `.hexpat` pattern, a Python parser/serializer, and a documented specification — and validate their conformity with the original binary.

---

## The three expected deliverables

### Deliverable 1 — ImHex pattern (`.hexpat`)

The pattern must be applicable to the three provided archives (`demo.cfr`, `packed_noxor.cfr`, `packed_xor.cfr`) and cover the entirety of each file's bytes with no unattributed zone.

**Validation criteria**:

| # | Criterion | How to verify |  
|---|---------|-----------------|  
| H1 | The header (32 bytes) is fully colorized with explicit field names. | Open each archive in ImHex, apply the pattern, verify in the *Pattern Data* panel that the 8 header fields are named and their values are consistent. |  
| H2 | Flags are decomposed into named bits (`xor_enabled`, `has_footer`). | The bitfield must display individual bits, not just the raw numeric value. |  
| H3 | Records are parsed as an array of size `num_records`, each with its sub-fields (type, flags, name_len, data_len, name, data, crc16). | Expand the `records` array in the *Pattern Data* panel. Each record must display its readable name and dimensions. |  
| H4 | Each record's type uses a named `enum` (TEXT, BINARY, META). | The type column must display the symbolic name, not the numeric value. |  
| H5 | The conditional footer is correctly placed at the end of the file when the `has_footer` flag is active. | The footer must appear with the magic `CRFE`, the `total_size` matching the file size, and the `global_crc`. |  
| H6 | The pattern produces no errors on the three archives. | No error messages in the *Pattern Editor* console. |  
| H7 | No uncolorized bytes remain between the start of the header and the end of the footer. | Visually, the hex view must be entirely colorized. |

### Deliverable 2 — Python parser/serializer

The Python module must be able to read, validate, write, and recreate CFR archives. The decisive test is the round-trip validated by the original binary.

**Validation criteria**:

| # | Criterion | How to verify |  
|---|---------|-----------------|  
| P1 | The parser reads all three provided archives without errors and displays each record's content. | `python3 cfr_parser.py parse samples/demo.cfr` must display the 4 records with their names, types, and contents. Same for the other two archives. |  
| P2 | The parser detects and reports invalid CRCs (header, records, global). | Manually corrupt a byte in an archive copy, verify the parser raises an explicit error identifying the affected CRC. |  
| P3 | The parser correctly handles de-XOR of obfuscated archives. | The textual content of records in `packed_xor.cfr` must be readable after parsing, identical to that of `packed_noxor.cfr`. |  
| P4 | The serializer produces XOR archives that the binary accepts. | Generate an archive with `xor_enabled=True`, validate it with `./fileformat_O0 validate`. |  
| P5 | The serializer produces non-XOR archives that the binary accepts. | Generate an archive with `xor_enabled=False`, validate it with `./fileformat_O0 validate`. |  
| P6 | The serializer produces footer-less archives that the binary accepts. | Generate an archive with `include_footer=False`, verify with `./fileformat_O0 list`. |  
| P7 | **Read → write round-trip**: read each of the three archives, rewrite it, have the original binary validate it. | All three `./fileformat_O0 validate <roundtrip.cfr>` commands must return 0 errors. |  
| P8 | **Ex nihilo generation**: create an archive from scratch (without reading an existing file), have the binary accept it. | `./fileformat_O0 read <generated.cfr>` must display the records with the expected content. |  
| P9 | The parser rejects a file whose magic is not `CFRM`. | Create a 32-byte file with magic `XXXX`, verify the parser refuses to read it. |

### Deliverable 3 — Documented specification

The specification must be a standalone Markdown document, comprehensible without access to the binary or the Python code.

**Validation criteria**:

| # | Criterion | How to verify |  
|---|---------|-----------------|  
| S1 | The document describes the complete header structure with the offset, size, type, and semantics of each field. | A reader must be able to manually read the first 32 bytes of a CFR archive using only `xxd` and the spec. |  
| S2 | The document describes the record structure, including the header, name, data, and CRC-16. | A reader must be able to locate and delimit each record in a hex dump. |  
| S3 | The document describes the footer (structure, presence condition, global CRC scope). | — |  
| S4 | The three algorithms (CRC-32, CRC-16, XOR) are specified with their exact parameters (polynomial, initial value, key). | An implementer must be able to reproduce the CRCs on known data by following only the spec's pseudo-code. |  
| S5 | The CRC/XOR operation order is explicitly documented, from both the producer's AND the parser's perspective. | The spec must remove all ambiguity about the fact that CRC-16 is computed on data before XOR. |  
| S6 | Edge cases are documented (empty records, empty names, unknown types, absent footer). | — |  
| S7 | Validation constraints are listed (magic, max num_records, CRC, data_len_xor, footer). | An implementer knows exactly which invariants to check and in what order. |  
| S8 | An annotated hexadecimal example is included. | At least the first 48 bytes of an archive must be annotated field by field. |

---

## Cross-validation grid

The strongest test consists of verifying that the three deliverables are consistent with each other, not just individually valid:

| Cross-check | Method |  
|----------------------|---------|  
| The `.hexpat` and the Python parser produce the same interpretation of each field. | Compare the values displayed by ImHex (via the pattern) and those displayed by the Python parser for the same archive. Names, sizes, types, and CRCs must be identical. |  
| The spec allows recreating the parser. | Give the specification alone to a peer (or re-read it yourself after a few days). Verify that it is possible to write a functional parser based solely on the document, without consulting the Python code or the `.hexpat`. |  
| The Python parser produces files that the `.hexpat` parses correctly. | Open an archive generated by the Python serializer in ImHex with the pattern. All fields must be colorized and consistent. |

---

## What is beyond the checkpoint's scope

The following elements are possible extensions but are not part of the minimum validation:

- Optimizing the Python parser for very large archives (streaming instead of full in-memory reading).  
- Handling a hypothetical version 3 of the format.  
- Adding compression (zlib, lz4) as a new flag — the current format only supports XOR.  
- Writing a parser in another language (C, Rust) from the specification.  
- Integrating the `.hexpat` into ImHex's official pattern library.

These avenues are left to the reader's curiosity.

---


⏭️ [Part VI — Malicious Code Analysis (Controlled Environment)](/part-6-malware.md)
