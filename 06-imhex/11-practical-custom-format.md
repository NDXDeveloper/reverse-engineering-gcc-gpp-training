🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.11 — Practical case: mapping a custom file format with `.hexpat`

> 🎯 **Goal of this section**: Apply the full set of skills acquired in this chapter — visual exploration, Data Inspector, bookmarks, `.hexpat` patterns, search, entropy, disassembler, and YARA — in a realistic reverse-engineering scenario of a proprietary file format for which no documentation exists.

> 📦 **Test binary**: `binaries/ch06-fileformat/fileformat_O0`  
> 📁 **Data file**: a `.cdb` (custom database) file produced by this binary  
> 📁 **Pattern produced**: `hexpat/ch06_fileformat.hexpat`

---

## The scenario

You are tasked with analyzing a GCC-compiled application that stores its data in a proprietary file format with the `.cdb` (custom database) extension. You have the binary (`fileformat_O0`) and a data file (`sample.cdb`) produced by this program. You have neither the source code nor documentation of the format. Your goal is to **understand the structure of the `.cdb` file** enough to be able to read it, modify it, and possibly write an independent parser in Python (which we will do in Chapter 25).

This scenario is common in reverse engineering: a proprietary software uses an undocumented storage format, and you have to understand it — for interoperability, security audit, data migration, or simply technical curiosity.

In this section, we will unroll the full analysis, step by step, using only ImHex and the techniques seen in this chapter. It's an integrative exercise that mobilizes sections 6.1 to 6.10.

---

## Phase 1 — Initial reconnaissance

### CLI triage

Before opening ImHex, let's apply Chapter 5's quick triage workflow on the data file:

```bash
file sample.cdb
# sample.cdb: data

strings sample.cdb
# (a few readable strings appear: names, descriptions...)

xxd sample.cdb | head -5
# 00000000: 4344 4232 0200 0100 0500 0000 8000 0000  CDB2............
# 00000010: 0100 0000 0300 0000 0000 0000 0000 0000  ................
# 00000020: ...
```

First lessons. The `file` command does not recognize the format — expected for a proprietary format. The `strings` command reveals readable strings, which means the file is not entirely encrypted or compressed. And `xxd` shows us the first bytes: `43 44 42 32` — the ASCII string `CDB2`. That is our **magic number**.

### Opening in ImHex and first look

Let's open `sample.cdb` in ImHex. Here is what we observe in the hex view:

- The first 4 bytes are `43 44 42 32` (`CDB2`). Magic number confirmed.  
- The following bytes show small integers interspersed with zeros — probable header structure with short fields and padding or counters.  
- Further into the file, we glimpse readable text blocks (the strings seen by `strings`) interspersed with structured binary data.  
- No zone appears to be pure randomness — no obvious encrypted block at first glance.

### Entropy analysis

Let's open **View → Information** to see the entropy profile. The graph shows moderate and relatively uniform entropy (around 4–5 bits/byte) throughout the file, with a few local dips. This profile is characteristic of a structured data file containing text and integers — no compression or encryption. This observation confirms that the file is analyzable directly, without a prior decompression or decryption step.

### Exploratory bookmarks

Let's place our first bookmarks before going further:

- **Offset 0x00, 4 bytes** → bookmark `Magic number "CDB2"` (orange color).  
- **Offset 0x04, ~28 bytes** → bookmark `Header (unknown structure)` (orange color). We'll adjust the size once we understand the header.  
- The first readable text zones → bookmark `Textual data zone` (yellow color).

These exploratory bookmarks are temporary. They capture our initial understanding and will serve as navigation points during the rest of the analysis.

---

## Phase 2 — Decrypting the header

### Exploration with the Data Inspector

Let's place the cursor on each group of bytes at the start of the file and watch the Data Inspector.

**Offset 0x00** — `43 44 42 32`: the Data Inspector shows `char[4] = "CDB2"`. Magic number, 4 bytes.

**Offset 0x04** — `02 00`: `uint16_t = 2`. Probably a version number (the magic says "CDB2", this field says version 2 — coherent).

**Offset 0x06** — `01 00`: `uint16_t = 1`. Too early to say what it is. Let's note "unknown field, value 1".

**Offset 0x08** — `05 00 00 00`: `uint32_t = 5`. A counter? The file may contain 5 records. Hypothesis to verify.

**Offset 0x0C** — `80 00 00 00`: `uint32_t = 128` (0x80). A size? An offset? If it's an offset, data would start at offset 128 in the file. If it's a size, the data block is 128 bytes. Let's note both hypotheses.

**Offset 0x10** — `01 00 00 00`: `uint32_t = 1`. A value or a flag.

**Offset 0x14** — `03 00 00 00`: `uint32_t = 3`. Another counter?

**Offset 0x18** — 8 null bytes. End-of-header padding, or reserved fields.

At this stage, we formulate a first header hypothesis:

```
Offset  Size    Hypothesis
0x00    4       Magic "CDB2"
0x04    2       Version (2)
0x06    2       Unknown (1) — sub-version? flags?
0x08    4       Number of records (5)
0x0C    4       Offset or size (128)
0x10    4       Unknown (1)
0x14    4       Unknown (3) — number of fields per record?
0x18    8       Reserved / padding (zeros)
Total: 32 bytes (0x20)
```

### First `.hexpat` pattern

Let's translate this hypothesis into a pattern:

```cpp
struct CDB_Header {
    char magic[4]       [[comment("Must equal 'CDB2'")]];
    u16  version        [[comment("Format version")]];
    u16  unknown_06     [[comment("Sub-version or flags?")]];
    u32  record_count   [[comment("Number of records")]];
    u32  data_offset    [[comment("Offset to data zone?")]];
    u32  unknown_10     [[comment("To be determined")]];
    u32  field_count    [[comment("Number of fields per record?")]];
    padding[8]          [[comment("Reserved")]];
};

CDB_Header header @ 0x00;
```

Let's evaluate (`F5`). The Pattern Data tree shows:

```
header
├── magic        = "CDB2"
├── version      = 2
├── unknown_06   = 1
├── record_count = 5
├── data_offset  = 128
├── unknown_10   = 1
└── field_count  = 3
```

The values are plausible. The `data_offset = 128` hypothesis is testable: let's navigate to offset `0x80` (128) in the hex view. If we find the beginning of structured data there (and not the middle of a block), the hypothesis is reinforced.

---

## Phase 3 — The zone between the header and the data

### Identify the intermediate table

Between the header (32 bytes, offsets 0x00–0x1F) and offset 0x80 (supposed start of data), there are 96 bytes (offsets 0x20–0x7F). What do they contain?

Let's explore this zone with the Data Inspector by moving the cursor. We observe a repeating pattern: apparently fixed-size blocks following each other. Each block seems to contain a small integer followed by a short string then null padding bytes.

Let's place a bookmark `Intermediate table (0x20–0x9F, 128 bytes)` (green color) and examine more closely.

Observing the blocks, we identify a regular 24-byte structure:

```
Offset 0x20 : 01 00  "name\0"  (padding)  01 00 00 00  
Offset 0x38 : 02 00  "description\0"  (padding)  02 00 00 00  
Offset 0x50 : 03 00  "value\0"  (padding)  03 00 00 00  
```

Three 24-byte blocks = 72 bytes. But the zone is 128 bytes. 56 bytes remain. Maybe our blocks have a different size, or the zone contains something else after the three descriptors.

Let's go back to the header: `field_count = 3`. We hypothesized this was the number of fields per record. And here we find exactly 3 blocks that look like **field descriptors** (an identifier, a name, a type). The hypothesis reinforces.

Let's refine our observation. Counting precisely with ImHex (selecting a block, reading the size in the status bar), we measure that each descriptor is actually 32 bytes, not 24. With the Data Inspector:

```
Offset  Size    Content
+0x00   2       Field ID (u16)
+0x02   2       Field type (u16) — 1=string, 2=string, 3=integer?
+0x04   20      Field name (char[20], null-terminated, zero-padded)
+0x18   4       Max field size in bytes (u32)
+0x1C   4       Flags or reserved (u32)
Total: 32 bytes
```

Three 32-byte descriptors = 96 bytes (0x60). From 0x20 to 0x80, that's 96 bytes. The remaining bytes from 0x80 to 0x9F (32 bytes) could be another block or padding up to `data_offset`.

The descriptors occupy exactly 96 bytes (3 × 32), which lands directly at offset 0x80 (32 + 96 = 128). Since 128 is already a multiple of 32, no alignment padding is necessary: `data_offset = 0x80` falls right after the last descriptor.

### Updated pattern

```cpp
enum FieldType : u16 {
    STRING  = 0x0001,
    TEXT    = 0x0002,
    INTEGER = 0x0003
};

struct FieldDescriptor {
    u16       field_id      [[comment("Unique field identifier")]];
    FieldType field_type    [[comment("Data type")]];
    char      field_name[20] [[comment("Field name, null-terminated")]];
    u32       max_size      [[comment("Max size in bytes")]];
    u32       flags         [[format("hex")]];
};

struct CDB_Header {
    char magic[4]       [[color("FF8844"), comment("Magic 'CDB2'")]];
    u16  version;
    u16  sub_version;
    u32  record_count   [[comment("Number of records")]];
    u32  data_offset    [[format("hex"), comment("Offset to data zone")]];
    u32  unknown_10;
    u32  field_count    [[comment("Number of field descriptors")]];
    padding[8];
};

CDB_Header header @ 0x00;  
FieldDescriptor fields[header.field_count] @ 0x20;  
```

Let's evaluate. The tree now shows the header **and** the three field descriptors with their names (`name`, `description`, `value`), their types, and their max sizes. The hex view is colorized on the first 32 bytes (header) and the next 96 (descriptors). The padding zone 0x80–0x9F remains uncolorized — that's normal, we identified it as padding.

Let's update our bookmarks: replace the `Intermediate table` bookmark with a more precise `Field descriptors (3 × 32 bytes)` bookmark, and add an `Alignment padding (0x80–0x9F)` bookmark in gray.

---

## Phase 4 — The data zone (the records)

### Exploring the records

Let's navigate to offset `0x80` (the `data_offset` value). This is where records should start. The header tells us there are 5 of them (`record_count`), and the descriptors tell us each record has 3 fields: `name` (string), `description` (text), and `value` (integer).

Let's observe the bytes from 0x80 with the Data Inspector:

**Offset 0x80** — The first bytes look like a small record header: an integer followed by data. Sweeping with the cursor, we identify a pattern:

```
Offset  Observation
0x80    u32 = 1 (record identifier?)
0xA4    Readable string "Alpha\0" followed by padding
0xB8    Longer string "First entry in the database\0"
0xE0    u32 = 42 (an integer value)
0xE4    u32 = 2 (start of next record?)
```

The record seems to have a fixed size. Let's measure: from 0x80 (start of record 1) to 0xC4 (supposed start of record 2), there are 68 bytes. Let's verify by looking for the third record: if records are 68 bytes, record 3 should start at `0x80 + 2×68 = 0x80 + 0x88 = 0x108`. Let's navigate to 0x108 and check whether a record identifier (value 3) is there.

If the check fails, we adjust. If it succeeds, we've found the size of records. In this case, suppose verification confirms a 68-byte size per record.

### Deducing the structure of a record

Let's cross-reference with the field descriptors:

- Field `name`: type STRING, `max_size = 20`. → Probably `char[20]`.  
- Field `description`: type TEXT, `max_size = 40`. → Probably `char[40]`.  
- Field `value`: type INTEGER, `max_size = 4`. → Probably `u32`.

Total data: 20 + 40 + 4 = 64 bytes. Plus a 4-byte identifier at the head = 68 bytes. The size matches.

### Pattern for records

```cpp
struct CDB_Record {
    u32  record_id   [[comment("Sequential identifier")]];
    char name[20]    [[color("FFEE55"), comment("'name' field")]];
    char description[40] [[color("FFEE55"), comment("'description' field")]];
    u32  value       [[comment("'value' field")]];
};
```

Let's instantiate the record array:

```cpp
CDB_Record records[header.record_count] @ header.data_offset;
```

Let's evaluate. The tree shows 5 records, each with its identifier, name, description, and value. The strings are readable, the identifiers are sequential (1, 2, 3, 4, 5), the integer values are plausible. The hex view is now colorized over almost the entire file.

---

## Phase 5 — Verification and discovering the footer

### Checking coverage

Let's check whether our pattern covers the entire file. The header is 32 bytes, descriptors 96, padding 32, and 5 records are 5 × 68 = 340 bytes. Total: 32 + 96 + 32 + 340 = 500 bytes (0x1F4).

What is the file size? ImHex displays it in the status bar or in **View → Information**. Suppose the file is 512 bytes (0x200). 12 bytes remain uncovered (offsets 0x1F4–0x1FF).

Let's navigate to 0x1F4. The Data Inspector shows:

```
Offset 0x1F4: u32 = 0x4F454643  → char[4] = "CFEO" → reversed: "OEFC"
```

Interesting — it looks like a **footer magic**. In little-endian, the bytes `43 46 45 4F` read as the string `CFEO`. Let's verify: if the start magic is `CDB2`, the end magic could be `2BDC` reversed, or a distinct identifier. Whatever the case, an end-of-file magic is a classic pattern that lets you check file integrity (the file wasn't truncated).

The following bytes:

```
Offset 0x1F8: u32 = 5           → record_count (verification redundancy)  
Offset 0x1FC: u32 = 0x1F4       → data size or footer offset  
```

It's a 12-byte **footer**:

```cpp
struct CDB_Footer {
    char magic[4]        [[color("FF8844"), comment("End magic")]];
    u32  record_count    [[comment("Copy of record count (verification)")]];
    u32  data_end_offset [[format("hex"), comment("End-of-data offset")]];
};

CDB_Footer footer @ 0x1F4;
```

The file is now entirely covered by our pattern.

---

## Phase 6 — The full assembled pattern

Let's regroup everything into a single file:

```cpp
// ============================================================
// ch06_fileformat.hexpat — Custom .cdb file format
// Reverse Engineering Training — Chapter 6 (practical case)
// ============================================================

#include <std/io.pat>

// ─── Enums ───

enum FieldType : u16 {
    STRING  = 0x0001,
    TEXT    = 0x0002,
    INTEGER = 0x0003
};

// ─── Structures ───

struct CDB_Header {
    char magic[4]       [[color("FF8844"), comment("Magic 'CDB2'")]];
    u16  version        [[comment("Major version")]];
    u16  sub_version    [[comment("Minor version")]];
    u32  record_count   [[comment("Number of records")]];
    u32  data_offset    [[format("hex"), comment("Offset to data zone")]];
    u32  unknown_10     [[comment("To be determined (always 1?)")]];
    u32  field_count    [[comment("Number of field descriptors")]];
    padding[8]          [[comment("Reserved")]];
};

struct FieldDescriptor {
    u16       field_id    [[comment("Field identifier")]];
    FieldType field_type  [[comment("Data type")]];
    char      field_name[20] [[comment("Field name")]];
    u32       max_size    [[comment("Max size in bytes")]];
    u32       flags       [[format("hex"), comment("Flags")]];
};

struct CDB_Record {
    u32  record_id      [[comment("Sequential ID")]];
    char name[20]       [[color("FFEE55"), comment("'name' field")]];
    char description[40][[color("AADDFF"), comment("'description' field")]];
    u32  value          [[comment("'value' field")]];
};

struct CDB_Footer {
    char magic[4]        [[color("FF8844"), comment("End magic")]];
    u32  record_count    [[comment("Record count verification")]];
    u32  data_end_offset [[format("hex"), comment("End-of-data offset")]];
};

// ─── Instantiation ───

CDB_Header      header  @ 0x00;  
FieldDescriptor fields[header.field_count] @ 0x20;  
CDB_Record      records[header.record_count] @ header.data_offset;  
CDB_Footer      footer  @ addressof(records) + sizeof(records);  
```

A few points to note about the last lines.

The footer's position is computed dynamically: `addressof(records)` gives the start offset of the records array, and `sizeof(records)` gives its total size. The footer is therefore placed just after the last record. This approach is more robust than hardcoding the offset `0x1F4` — if the file contains a different number of records, the footer will still be found.

The `unknown_10` field of the header remains unresolved. That's normal — in RE, it's frequent to end an analysis with a few fields that resist interpretation. We documented them with a `[[comment]]` that flags the uncertainty. Dynamic analysis of the binary with GDB (Chapter 11) or Frida (Chapter 13) may eventually lift the ambiguity by observing how the program reads and uses this field.

---

## Phase 7 — Final documentation

### Final bookmarks

Let's update our bookmarks to reflect final understanding:

| Bookmark | Offset | Size | Color | Comment |  
|---|---|---|---|---|  
| Header CDB2 | 0x00 | 32 | Orange | Version 2.1, 5 records, 3 fields |  
| Field descriptors | 0x20 | 96 | Green | 3 descriptors × 32 bytes |  
| Alignment padding | 0x80 | 32 | Gray | Zeros up to data_offset |  
| Data zone (records) | 0x80 | 340 | Yellow | 5 records × 68 bytes |  
| Footer CDB2 | 0x1F4 | 12 | Orange | Magic + integrity check |

### Saving the project

Let's save everything via **File → Save Project** under the name `sample_cdb_analysis.hexproj`. The project contains the loaded pattern, bookmarks, and interface layout. Let's also save the pattern in `hexpat/ch06_fileformat.hexpat`.

### YARA scan

As a complement, let's run a quick YARA scan with `crypto_constants.yar` to verify that no crypto constants are hiding in the file. Result: no match. The `.cdb` format contains no encryption — coherent with the entropy profile observed in phase 1.

---

## Methodological assessment

Let's recap the approach we followed and the ImHex tools mobilized at each step:

| Phase | Action | ImHex tools |  
|---|---|---|  
| 1 — Reconnaissance | CLI triage, first look, entropy | Hex view, View → Information |  
| 2 — Header | Byte-by-byte exploration, structure hypothesis | Data Inspector, first `.hexpat` |  
| 3 — Intermediate table | Identification of a repeating pattern, size measurement | Data Inspector, selection + status bar |  
| 4 — Records | Descriptors/data cross-reference, size validation | `.hexpat` pattern with dynamic array |  
| 5 — Footer | File coverage, discovery of an unexpected structure | Navigation, Data Inspector |  
| 6 — Assembly | Complete pattern, dynamic placement | Pattern Editor, evaluation |  
| 7 — Documentation | Bookmarks, saving, YARA scan | Bookmarks, Project, YARA |

This approach is **transferable** to any unknown file format. The steps and their order may vary — sometimes you'll identify the records before the header, sometimes the footer will be your first clue — but the fundamental cycle remains the same: observe, formulate a hypothesis, encode it in `.hexpat`, evaluate, adjust, document.

The fact that we carried out this analysis **without ever opening the `fileformat_O0` binary in a disassembler** is significant. To understand a file format, the data file itself is often the best source of information. The binary that produces it will be useful in a second step — in Chapter 25, we will cross-reference our `.hexpat` pattern with the disassembly of the parser in Ghidra to confirm the fields that remain ambiguous and understand the serialization/deserialization logic.

---

## Summary

This practical case demonstrated the complete workflow of mapping an unknown file format in ImHex: initial reconnaissance (entropy, magic bytes, exploratory bookmarks), progressive exploration with the Data Inspector, iterative construction of a `.hexpat` pattern starting with the header then following pointers to internal structures, full-file-coverage verification, and final documentation with bookmarks and saving as a project. The resulting pattern — about sixty lines — turns an opaque hex blob into a navigable, colorized, documented structure. This pattern will serve as the basis in Chapter 25 to write an independent Python parser and produce a formal specification of the format.

---


⏭️ [🎯 Checkpoint: write a complete `.hexpat` for the `ch23-fileformat` format](/06-imhex/checkpoint.md)
