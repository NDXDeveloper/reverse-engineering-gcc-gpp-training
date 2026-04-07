🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 25.5 — Documenting the Format (Producing a Specification)

> 🎯 **Objective of this section**: transform all the knowledge accumulated throughout the chapter into a standalone specification document. This document must allow a third-party developer to implement a complete CFR parser/serializer without ever touching the original binary or reading our Python code.

---

## Why a Formal Specification?

We already have a commented `.hexpat` pattern and a working Python parser. Why invest additional time in a text document?

Because code and patterns describe *how* to process the format, not *what it is*. A developer reading our `cfr_parser.py` would have to mentally reconstruct the specification from `struct.unpack` calls, scattered constants, and control logic. That is exactly the reverse engineering work we want to spare the next person.

A good specification is **declarative**: it describes the data structure independently of any implementation. It answers questions that code does not explicitly ask — "what happens if this field is zero?", "is this alignment guaranteed?", "which version of the format does this spec cover?". It is also the most useful deliverable in a professional context: a format audit report, interoperability documentation, or a contribution to a digital archival project takes the form of a document, not a script.

---

## Anatomy of a Good Format Specification

The most respected binary format specifications (PNG, ELF, ZIP, Protocol Buffers encoding...) share a common structure. We will draw inspiration from them to produce a complete document, even though our CFR format is infinitely simpler.

The essential sections are:

1. **Summary and scope** — what the format does, what the document covers, the version number.  
2. **Conventions and notations** — endianness, units, size notation, terminology.  
3. **Structure overview** — a diagram or schema showing the overall layout (header → records → footer).  
4. **Field-by-field description** — each structure detailed with offset, size, type, possible values, constraints.  
5. **Algorithms** — the CRCs, the XOR transformation, and any non-trivial process.  
6. **Validation constraints** — the invariants that a conforming file must satisfy.  
7. **Edge cases and optional behaviors** — missing footer, empty records, unknown types.  
8. **Version history** — if multiple format versions exist.  
9. **Appendices** — annotated hexadecimal examples, reference implementation.

---

## Writing Conventions

Before writing, let us establish a few conventions that will make the document unambiguous.

### RFC 2119 Vocabulary

Technical specifications conventionally use the keywords defined by RFC 2119 to express levels of obligation:

- **MUST** / **MUST** — absolute obligation. A file that violates this rule is non-conforming.  
- **SHOULD** / **SHOULD** — strong recommendation. Violation is possible but must be justified.  
- **MAY** / **MAY** — optional behavior. A conforming parser must tolerate the presence or absence of this feature.

For example: "The `magic` field MUST contain the value `0x4346524D`." leaves no room for interpretation. "The `record.flags` field SHOULD be set to zero by producers" means that a parser must tolerate non-zero values.

### Byte Notation

We adopt the following conventions:

- Offsets are in hexadecimal, prefixed with `0x`: `0x00`, `0x10`, `0x1C`.  
- Constant values are in hexadecimal: `0x4346524D`, `0xEDB88320`.  
- Sizes are in bytes unless otherwise stated.  
- Integer types follow the notation `uint16_le` (unsigned integer, 16 bits, little-endian).  
- Strings are encoded in ASCII, **not** null-terminated unless otherwise stated.

---

## The CFR Specification

What follows is the complete specification document as we would produce it as the final reverse engineering deliverable. In a real-world context, this document would be a separate file (e.g., `CFR_FORMAT_SPEC.md`), versioned and maintained independently from the code.

---

### 1. Summary

The CFR format (*Custom Format Records*) is a binary archive format for storing multiple named records in a single file. Each record has a type (text, binary, or metadata), a variable-length name, and a variable-length payload. The format optionally supports XOR obfuscation of the data and includes integrity mechanisms at three levels (header, record, global).

This document describes version **2** (`0x0002`) of the format.

### 2. Conventions

| Element | Convention |  
|---------|------------|  
| Byte order | Little-endian for all multi-byte fields |  
| String encoding | ASCII, not null-terminated (length is explicit) |  
| Alignment | None. Fields are contiguous with no padding between structures |  
| Offsets | Hexadecimal, relative to the start of the described structure |  
| Keywords | MUST, SHOULD, MAY — as defined in RFC 2119 |

### 3. Overview

A CFR file is composed of three consecutive parts:

```
┌─────────────────────────────────┐  offset 0x00
│           HEADER (32 bytes)     │
├─────────────────────────────────┤  offset 0x20
│         RECORD 0                │
│  ┌────────────────────────────┐ │
│  │ Record Header   (8 bytes)  │ │
│  │ Name     (name_len bytes)  │ │
│  │ Data     (data_len bytes)  │ │
│  │ CRC-16          (2 bytes)  │ │
│  └────────────────────────────┘ │
├─────────────────────────────────┤
│         RECORD 1                │
│             ...                 │
├─────────────────────────────────┤
│         RECORD N-1              │
├─────────────────────────────────┤
│     FOOTER (12 bytes)           │  ← optional
│     (present if flags.bit1 = 1) │
└─────────────────────────────────┘
```

Records follow one another with no padding between them. The footer, if present, immediately follows the last record.

### 4. Header

**Fixed size**: 32 bytes.

| Offset | Size | Type | Name | Description |  
|--------|------|------|------|-------------|  
| `0x00` | 4 | `char[4]` | `magic` | MUST equal `"CFRM"` (`0x43 0x46 0x52 0x4D`). Identifies the format. |  
| `0x04` | 2 | `uint16_le` | `version` | Format version. This document describes version `0x0002`. |  
| `0x06` | 2 | `uint16_le` | `flags` | Bit field (see section 4.1). |  
| `0x08` | 4 | `uint32_le` | `num_records` | Number of records in the archive. MUST be ≤ 1024. |  
| `0x0C` | 4 | `uint32_le` | `timestamp` | Archive creation date, in seconds since the UNIX epoch (January 1, 1970 00:00:00 UTC). |  
| `0x10` | 4 | `uint32_le` | `header_crc` | CRC-32 of bytes `[0x00..0x0F]` (the first 16 bytes of the header). See section 7.1. |  
| `0x14` | 8 | `char[8]` | `author` | Author identifier. Right-padded with null bytes (`0x00`) if shorter than 8 characters. |  
| `0x1C` | 4 | `uint32_le` | `data_len_xor` | XOR of all `data_len` fields from the archive's records. See section 7.4. |

#### 4.1 `flags` Field

| Bit | Name | Description |  
|-----|------|-------------|  
| 0 | `XOR_ENABLED` | If set (1), the data of each record is obfuscated by rotating XOR (see section 7.3). Names are NOT transformed. |  
| 1 | `HAS_FOOTER` | If set (1), a 12-byte footer is present at the end of the file (see section 6). |  
| 2–15 | Reserved | MUST be set to zero by producers. Parsers SHOULD ignore them. |

### 5. Record

Each record consists of four consecutive parts:

#### 5.1 Record Header

**Fixed size**: 8 bytes.

| Offset | Size | Type | Name | Description |  
|--------|------|------|------|-------------|  
| `0x00` | 1 | `uint8` | `type` | Content type (see section 5.2). |  
| `0x01` | 1 | `uint8` | `flags` | Reserved. SHOULD be `0x00`. Parsers MUST ignore it. |  
| `0x02` | 2 | `uint16_le` | `name_len` | Name length in bytes. MAY be zero. |  
| `0x04` | 4 | `uint32_le` | `data_len` | Payload length in bytes. MAY be zero. |

#### 5.2 Record Types

| Value | Name | Semantics |  
|-------|------|-----------|  
| `0x01` | `TEXT` | Textual content (UTF-8 or ASCII). |  
| `0x02` | `BINARY` | Arbitrary binary data. |  
| `0x03` | `META` | Metadata in `key=value` format, one pair per line (`\n`). |

Parsers SHOULD accept unknown type values without error and treat the payload as opaque binary data.

#### 5.3 Name

- Size: `name_len` bytes.  
- Encoding: ASCII.  
- Is NOT null-terminated.  
- Is NEVER subject to XOR transformation, even if the `XOR_ENABLED` flag is set.  
- MAY be empty (`name_len = 0`).

#### 5.4 Data

- Size: `data_len` bytes.  
- If the header's `XOR_ENABLED` flag is set and `data_len > 0`, the stored bytes are the result of the XOR transformation (see section 7.3) applied to the original data.  
- If the `XOR_ENABLED` flag is not set, the data is stored in plaintext.  
- MAY be empty (`data_len = 0`), in which case no transformation is applied.

#### 5.5 Record CRC-16

- Size: 2 bytes (`uint16_le`).  
- Algorithm: CRC-16/CCITT (see section 7.2).  
- Calculation input: concatenation `name || data_original`, where `data_original` refers to the data **before** the XOR transformation.  
- This CRC protects both the name and the content of the record.

**Order of operations for a producer**:

1. Compute `crc16 = CRC-16(name || data_original)`.  
2. If `XOR_ENABLED`: transform `data_stored = XOR(data_original)`.  
3. Write: `record_header || name || data_stored || crc16`.

**Order of operations for a parser**:

1. Read `record_header`, `name`, `data_stored`, `crc16`.  
2. If `XOR_ENABLED`: restore `data_original = XOR(data_stored)`.  
3. Verify: `CRC-16(name || data_original) == crc16`.

### 6. Footer

**Presence**: only if `flags.HAS_FOOTER = 1`.

**Fixed size**: 12 bytes.

**Position**: immediately after the last record.

| Offset | Size | Type | Name | Description |  
|--------|------|------|------|-------------|  
| `0x00` | 4 | `char[4]` | `magic` | MUST equal `"CRFE"` (`0x43 0x52 0x46 0x45`). |  
| `0x04` | 4 | `uint32_le` | `total_size` | Total file size in bytes (header + records + footer). |  
| `0x08` | 4 | `uint32_le` | `global_crc` | CRC-32 of all bytes preceding the footer (offsets `[0x00..total_size - 13]`). See section 7.1. |

The footer enables detection of truncated files (via `total_size`) and global corruption (via `global_crc`).

### 7. Algorithms

#### 7.1 CRC-32

Used for `header_crc` and `global_crc`.

| Parameter | Value |  
|-----------|-------|  
| Polynomial | `0xEDB88320` (reflected form of `0x04C11DB7`) |  
| Initial value | `0xFFFFFFFF` |  
| Final XOR | `0xFFFFFFFF` |  
| Input bit reflection | Yes |  
| Final CRC reflection | Yes |

This is the CRC-32/ISO-HDLC variant, identical to the one used by `zlib`, `gzip`, `binascii.crc32()` in Python, and Ethernet FCS.

**Pseudo-code**:

```
function crc32(data):
    crc ← 0xFFFFFFFF
    for each byte b in data:
        crc ← crc XOR b
        repeat 8 times:
            if crc AND 1:
                crc ← (crc >> 1) XOR 0xEDB88320
            else:
                crc ← crc >> 1
    return crc XOR 0xFFFFFFFF
```

**Scope per field**:

| Field | Covered bytes |  
|-------|---------------|  
| `header_crc` | Bytes `[0x00..0x0F]` of the header (first 16 bytes: magic, version, flags, num_records, timestamp) |  
| `global_crc` | All file bytes preceding the footer (header + all records) |

#### 7.2 CRC-16

Used for the `crc16` of each record.

| Parameter | Value |  
|-----------|-------|  
| Polynomial | `0x1021` |  
| Initial value | `0x1D0F` |  
| Final XOR | `0x0000` (no final XOR) |  
| Input bit reflection | No |  
| Final CRC reflection | No |

This variant differs from the standard CRC-16/CCITT-FALSE only by its initial value (`0x1D0F` instead of `0xFFFF`). It corresponds to CRC-16/AUG-CCITT as defined in Greg Cook's catalogue.

**Pseudo-code**:

```
function crc16(data):
    crc ← 0x1D0F
    for each byte b in data:
        crc ← crc XOR (b << 8)
        repeat 8 times:
            if crc AND 0x8000:
                crc ← (crc << 1) XOR 0x1021
            else:
                crc ← crc << 1
            crc ← crc AND 0xFFFF
    return crc
```

#### 7.3 XOR Transformation

Applied to record data when `flags.XOR_ENABLED = 1`.

| Parameter | Value |  
|-----------|-------|  
| Key | `0x5A 0x3C 0x96 0xF1` (4 bytes, fixed) |  
| Mode | Rotating (byte `data[i]` is XOR-ed with `key[i mod 4]`) |

The transformation is involutory: applying the function twice produces the original data.

**Pseudo-code**:

```
KEY = [0x5A, 0x3C, 0x96, 0xF1]

function xor_transform(data):
    result ← copy of data
    for i from 0 to length(data) - 1:
        result[i] ← data[i] XOR KEY[i mod 4]
    return result
```

**Remarks**:

- The transformation is NOT applied to record names.  
- If `data_len = 0`, no transformation is necessary.  
- The XOR index is reset to zero at the beginning of each record (the key does not "carry over" from one record to the next).

#### 7.4 `data_len_xor` Verification

The header's `data_len_xor` field is the XOR of all `data_len` fields from the archive's records:

```
data_len_xor = record[0].data_len XOR record[1].data_len XOR ... XOR record[N-1].data_len
```

This field provides a quick size consistency check without requiring a full read of the data. If a single `data_len` is corrupted, the global XOR will be invalid.

### 8. Validation Constraints

A CFR file MUST satisfy the following invariants to be considered conforming:

| # | Invariant | Consequence of violation |  
|---|-----------|------------------------|  
| V1 | `header.magic == "CFRM"` | Immediate rejection (not a CFR file). |  
| V2 | `header.num_records ≤ 1024` | Rejection (protection against excessive allocation). |  
| V3 | `header.header_crc == CRC-32(header[0x00..0x0F])` | The header is corrupted. |  
| V4 | For each record: `name_len + data_len` MUST NOT exceed the remaining file size. | Truncated record. |  
| V5 | For each record: `CRC-16(name \|\| data_original) == stored_crc16` | The record data is corrupted. |  
| V6 | `header.data_len_xor == XOR(data_len[0], ..., data_len[N-1])` | Record size inconsistency. |  
| V7 | If `HAS_FOOTER`: `footer.magic == "CRFE"` | Footer missing or corrupted. |  
| V8 | If `HAS_FOOTER`: `footer.total_size == actual file size` | File truncated or extended. |  
| V9 | If `HAS_FOOTER`: `footer.global_crc == CRC-32(file[0..total_size - 13])` | Global corruption. |

A strict parser MUST verify all these invariants. A tolerant parser MAY ignore violations V3, V6, and V9 with a warning.

### 9. Edge Cases

| Case | Expected behavior |  
|------|-------------------|  
| `num_records = 0` | Empty archive. The file contains only the header (and optionally the footer). Valid. |  
| `name_len = 0` | Record with an empty name. The `name` field is absent (0 bytes). The CRC-16 is computed on the data alone. Valid. |  
| `data_len = 0` | Record with no data. The `data` field is absent (0 bytes). No XOR transformation. The CRC-16 is computed on the name alone. Valid. |  
| `name_len = 0` AND `data_len = 0` | Entirely empty record. The CRC-16 is computed on a 0-byte buffer: `CRC-16("") = 0x1D0F`. Valid. |  
| Unknown `type` (> `0x03`) | The parser SHOULD accept the record and treat the payload as opaque binary. |  
| `flags.HAS_FOOTER = 0` | The file ends after the last record. No footer is present or expected. |  
| `flags.HAS_FOOTER = 1` but file truncated | The parser MUST report an error. |  
| `header.version ≠ 0x0002` | The parser MAY attempt to read the file but SHOULD emit a warning. |

### 10. Version History

| Version | Identifier | Changes |  
|---------|------------|---------|  
| 1 | `0x0001` | Initial version (undocumented, assumed obsolete). |  
| 2 | `0x0002` | Version described in this document. Added optional footer, the `data_len_xor` field, and the XOR transformation. |

### 11. Appendix — Annotated Example

Here are the first 48 bytes of the `demo.cfr` archive, annotated field by field:

```
Offset   Hex                                      Field
───────  ───────────────────────────────────────   ─────────────────────────
                          HEADER
0x00     43 46 52 4D                               magic = "CFRM"
0x04     02 00                                     version = 2
0x06     02 00                                     flags = 0x0002
                                                     bit 0 (XOR_ENABLED) = 0
                                                     bit 1 (HAS_FOOTER)  = 1
0x08     04 00 00 00                               num_records = 4
0x0C     XX XX XX XX                               timestamp (variable)
0x10     XX XX XX XX                               header_crc
0x14     XX XX XX XX XX XX XX XX                   author (8 bytes)
0x1C     XX XX XX XX                               data_len_xor

                       RECORD 0
0x20     01                                        type = TEXT (0x01)
0x21     00                                        flags = 0x00
0x22     0C 00                                     name_len = 12
0x24     40 00 00 00                               data_len = 64
0x28     67 72 65 65 74 69 6E 67 2E 74 78 74      name = "greeting.txt"
0x34     [64 bytes of plaintext data]              data (XOR inactive in demo.cfr)
0x74     XX XX                                     crc16
                                                   (over "greeting.txt" || data)

                       RECORD 1
0x76     02                                        type = BINARY (0x02)
0x77     00                                        flags = 0x00
0x78     08 00                                     name_len = 8
0x7A     18 00 00 00                               data_len = 24
0x7E     64 61 74 61 2E 62 69 6E                   name = "data.bin"
0x86     [24 bytes of binary data]                 data
0x9E     XX XX                                     crc16
         ...
```

---

## Best Practices for Writing Specifications

A few reflections drawn from this documentation work, applicable to any format reverse engineering.

**Specify what is left unsaid.** Silence in a specification is ambiguous. If names are not null-terminated, state it explicitly — a reader accustomed to C might assume otherwise. If alignment is absent, state that too. The "Notes" and "Remarks" in italics within algorithm sections serve to resolve these ambiguities.

**Separate structure from algorithms.** Section 5.5 describes *where* the CRC-16 is located and *what* it covers. Section 7.2 describes *how* to compute it. This separation allows a reader in a hurry to understand the structure without drowning in algorithmic details, and allows an implementer to quickly find the pseudo-code they need.

**Document the order of operations.** For the CRC-16 and XOR, order is critical and counterintuitive (the CRC covers the data *before* XOR, not after). Section 5.5 details the order for the producer *and* for the parser, because the two perspectives are not symmetric and an error in either one produces different results.

**Include edge cases.** Section 9 is often the most useful for an implementer. That is where the bugs hide: a `data_len = 0` that turns an XOR into a no-op, a `name_len = 0` that produces a CRC computed on an empty buffer. These cases are rarely covered by examples but systematically encountered in production.

**Version the document.** The format may evolve. Clearly indicating which version is described (here: version 2, identifier `0x0002`) allows maintaining multiple versions of the spec without confusion.

**Provide an annotated example.** An annotated hex dump is worth a thousand words. It allows the reader to verify their understanding by following the bytes by hand. It is also the first test for a new implementer: parsing the example by hand and verifying that each field is read correctly.

---

## The Three Chapter Deliverables

With this specification, the three chapter deliverables are complete:

| Deliverable | File | Role |  
|-------------|------|------|  
| ImHex Pattern | `hexpat/ch25_fileformat.hexpat` | Visualization and interactive inspection of CFR archives in ImHex. Colorization of each field, annotations and comments. |  
| Python Parser | `scripts/cfr_parser.py` | Programmatic reading, writing, validation, and round-trip. Standalone CLI. |  
| Specification | `docs/CFR_FORMAT_SPEC.md` | Standalone document describing the format independently of any implementation. Allows a third party to create their own parser without access to the binary. |

These three deliverables complement each other: the pattern enables visual exploration, the parser proves understanding through code, and the specification preserves the knowledge. If the original binary disappears tomorrow, the specification and the parser are sufficient to recreate a compatible tool.

---


⏭️ [🎯 Checkpoint: produce a Python parser + a `.hexpat` + a format spec](/25-fileformat/checkpoint.md)
