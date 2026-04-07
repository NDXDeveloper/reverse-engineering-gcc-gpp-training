🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 25.2 — Mapping Fields with ImHex and an Iterative `.hexpat` Pattern

> 🎯 **Objective of this section**: build a complete `.hexpat` pattern for the CFR format step by step, alternating between hexadecimal observation and structural hypotheses. By the end, every byte of the archive will be identified and colorized in ImHex.

---

## The Iterative Approach

Writing a `.hexpat` pattern for an unknown format is never done in a single pass. It is a back-and-forth process between three activities:

1. **Observe** the raw bytes in the hexadecimal view.  
2. **Formulate a hypothesis** about the meaning of a group of bytes.  
3. **Write the corresponding pattern fragment**, apply it, and check whether the resulting colorization is consistent with the rest of the file.

If the pattern correctly colors a region, the hypothesis is validated — move on to the next region. If the colorization overflows or does not match the visible data, the hypothesis is wrong — correct it. This is exactly the same scientific method as in the rest of RE, but applied to data rather than code.

Let's open `demo.cfr` in ImHex and begin.

---

## Pass 1 — The Header

### Raw Observation

In section 25.1, we determined that the header starts at offset `0x00` and is probably 32 bytes long. Let's observe them in ImHex with the Data Inspector enabled (the side panel that displays the value of the selected byte or group in various types: `uint8`, `uint16 LE`, `uint32 LE`, `float`, `char[]`…).

```
Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  43 46 52 4D 02 00 02 00 04 00 00 00 XX XX XX XX
00000010  XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
```

Let's break down what we see, reading from left to right:

| Offset | Bytes | Data Inspector (LE) | Likely Interpretation |  
|--------|-------|---------------------|----------------------|  
| `0x00` | `43 46 52 4D` | ASCII `"CFRM"` | Magic bytes — confirmed |  
| `0x04` | `02 00` | `uint16 = 2` | Version number? |  
| `0x06` | `02 00` | `uint16 = 2` | Flags? (value 2 = bit 1 set) |  
| `0x08` | `04 00 00 00` | `uint32 = 4` | Number of records? (demo.cfr contains 4) |  
| `0x0C` | `XX XX XX XX` | `uint32` = large number | UNIX timestamp? |  
| `0x10` | `XX XX XX XX` | `uint32` | Unknown — checksum? |  
| `0x14` | ASCII text | Readable string | Author name? |  
| `0x1C` | `XX XX XX XX` | `uint32` | Unknown — "reserved"? |

Several clues already converge. The value `4` at offset `0x08` matches the number of records we counted with `strings` in section 25.1 (four filenames). The value `2` at offset `0x04` matches the `version=2` we had seen in the metadata. The value `2` at offset `0x06` can be interpreted as a flags field with one bit set (bit 1).

The field at `0x0C`: if we convert the value to a date (`date -d @<value>`), we get a recent date consistent with the file's generation time. It's a UNIX timestamp.

The field at `0x14`: we can read the system username there (8 characters, padded with zeros). This is the `author` field we had guessed via `strings`.

### First Pattern Fragment

We can now write a first draft of the header:

```hexpat
#pragma endian little

import std.io;

struct CFRHeader {
    char magic[4];        // 0x00 — "CFRM"
    u16  version;         // 0x04 — format version
    u16  flags;           // 0x06 — bitfield
    u32  num_records;     // 0x08 — number of records
    u32  timestamp;       // 0x0C — UNIX timestamp
    u32  header_crc;      // 0x10 — CRC (to be identified)
    char author[8];       // 0x14 — author, null-padded
    u8   reserved[4];     // 0x1C — unknown purpose
};

CFRHeader header @ 0x00;
```

Let's apply this pattern in ImHex (*Pattern Editor → paste → run*). If everything goes well, the first 32 bytes become colorized and the field names appear in the *Pattern Data* panel. We can then verify that the displayed values are consistent:

- `magic` = `"CFRM"` ✓  
- `version` = `2` ✓  
- `flags` = `2` (binary: `0b10` → bit 1 set) ✓  
- `num_records` = `4` ✓  
- `timestamp` = plausible UNIX value ✓  
- `author` = username ✓

### Validating Against Other Archives

Let's open `packed_noxor.cfr` with the same pattern. We should observe:

- `flags` = `2` (binary: `0b10` → only bit 1 set, like `demo.cfr`)  
- `num_records` = `3`

And for `packed_xor.cfr`:

- `flags` = `3` (binary: `0b11` → bits 0 and 1 set)  
- `num_records` = `3`

Bit 0 is set **only** in `packed_xor.cfr` — the archive where text data is unreadable with `strings` (section 25.1). So this is the **XOR flag**. Bit 1 is set in all three archives — it is probably the **footer flag** (since we identified the magic `CRFE` at the end of each file).

Let's enrich our pattern with named constants:

```hexpat
bitfield Flags {
    xor_enabled : 1;     // bit 0 — XOR-obfuscated data
    has_footer  : 1;     // bit 1 — footer present at end of file
    padding     : 14;
};
```

And replace `u16 flags;` with `Flags flags;` in the structure.

### The Mystery of the `reserved` Field

The field at offset `0x1C` (4 bytes) contains a non-zero value, but its role is not yet clear. We keep it as is with a comment `// unknown purpose` and will come back to it later. In the iterative process, it is normal to temporarily leave zones annotated as "unknown" — they often become clear when we better understand the rest of the format.

> 💡 **ImHex tip**: use the *Bookmarks* feature to mark zones whose meaning remains uncertain. Create a bookmark "reserved — to investigate" on bytes `0x1C–0x1F`. When you come back to it, the bookmark will be there to remind you of the open question.

---

## Pass 2 — The First Record

### Observation

At offset `0x20` (just after the 32-byte header), we observe:

```
Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000020  01 00 0C 00 40 00 00 00 67 72 65 65 74 69 6E 67  ....@...greeting
00000030  2E 74 78 74 48 65 6C 6C 6F 20 66 72 6F 6D 20 74  .txtHello from t
00000040  68 65 20 43 46 52 20 61 72 63 68 69 76 65 20 66  he CFR archive f
```

Let's break down the record header:

| Offset | Bytes | LE Value | Hypothesis |  
|--------|-------|----------|------------|  
| `0x20` | `01` | `uint8 = 1` | Record type? (1 = TEXT?) |  
| `0x21` | `00` | `uint8 = 0` | Per-record flags? Padding? |  
| `0x22` | `0C 00` | `uint16 = 12` | Name length? (`"greeting.txt"` is 12 characters) |  
| `0x24` | `40 00 00 00` | `uint32 = 64` | Data length? |  
| `0x28` | `67 72 65 65…` | ASCII | The name: `"greeting.txt"` |

The `uint16 = 12` field at `0x22` matches exactly the length of `"greeting.txt"`. The string starts right after, at offset `0x28`. This is consistent with a record header of **8 bytes** (1 + 1 + 2 + 4), followed by the variable-length name.

After the name (`0x28` + 12 = `0x34`), we find the data. Here, `demo.cfr` does not have the XOR flag set (bit 0 = 0), so the data is in plaintext — we can directly read `"Hello from t"` starting at offset `0x34` in the hex dump above. If the data length is 64 bytes, they extend from `0x34` to `0x73` inclusive.

Let's look beyond the data area, at offset `0x74`: we should find either the record's CRC-16 (2 bytes) or the start of the next record.

```
00000074  XX XX 02 00 08 00 18 00 00 00 64 61 74 61 2E 62  ..........data.b
```

We read `02` at offset `0x76` — a new type byte (`2` = BINARY?), preceded by 2 bytes (`XX XX` at `0x74–0x75`) that could be the CRC-16 of the previous record. Then `00` (flags), `08 00` (uint16 = 8, name length for `"data.bin"`), `18 00 00 00` (uint32 = 24, data length).

The pattern is confirmed: each record is structured as **header (8 bytes) + name (variable) + data (variable) + CRC-16 (2 bytes)**.

> 📝 **Note**: if we opened `packed_xor.cfr` at this point, we would see the same record headers (same names, same lengths), but the data areas would contain unreadable bytes — since the XOR flag is active in this archive. We will return to this transformation in pass 4.

### Second Pattern Fragment

```hexpat
enum RecordType : u8 {
    TEXT   = 0x01,
    BINARY = 0x02,
    META   = 0x03
};

struct RecordHeader {
    RecordType type;      // 0x00 — content type
    u8         flags;     // 0x01 — per-record flags
    u16        name_len;  // 0x02 — name length
    u32        data_len;  // 0x04 — data length
};

struct Record {
    RecordHeader rh;
    char  name[rh.name_len];
    u8    data[rh.data_len];
    u16   crc16;
};
```

Let's add this to the main pattern:

```hexpat
CFRHeader header @ 0x00;  
Record records[header.num_records] @ 0x20;  
```

When applying this pattern, ImHex should colorize all the records. If the `records` array deploys correctly and the last record ends just before the `CRFE` magic, we have validated the record structure.

### Verification Through Type Consistency

Let's browse the 4 records of `demo.cfr` in the *Pattern Data* panel:

| # | `type` | `name_len` | `name` | `data_len` |  
|---|--------|------------|--------|------------|  
| 0 | TEXT (1) | 12 | `greeting.txt` | 64 |  
| 1 | BINARY (2) | 8 | `data.bin` | 24 |  
| 2 | META (3) | 12 | `version.meta` | 35 |  
| 3 | TEXT (1) | 9 | `notes.txt` | 116 |

Four records, three different types, name lengths matching the visible strings — everything is consistent. Since the XOR flag is not set in `demo.cfr`, the data of TEXT and META records is directly readable in the hexadecimal view.

---

## Pass 3 — The Footer

### Observation

The `CRFE` magic is located at the end of the file. The size of `demo.cfr` is 364 bytes, so the footer starts at offset `364 - 12 = 352` (`0x160`) if our 12-byte estimate is correct. Let's verify:

```
Offset           Bytes
0x160       43 52 46 45 XX XX XX XX YY YY YY YY
            C  R  F  E  ........    ........
```

| Relative Offset | Bytes | LE Value | Hypothesis |  
|---|---|---|---|  
| `+0x00` | `43 52 46 45` | ASCII `"CRFE"` | Footer magic |  
| `+0x04` | `XX XX XX XX` | `uint32` | Total file size? |  
| `+0x08` | `YY YY YY YY` | `uint32` | Global CRC-32? |

The field at `+0x04`: let's convert the value. If we get exactly 364, the "total size" hypothesis is confirmed. This is a classic pattern in archive formats — storing the total size in the footer allows detection of truncated files.

The field at `+0x08` is probably a global CRC-32 computed over the entire file *before* the footer (i.e., over the first `364 - 12 = 352` bytes).

### Pattern Fragment

```hexpat
struct CFRFooter {
    char magic[4];        // "CRFE"
    u32  total_size;      // total file size
    u32  global_crc;      // CRC-32 of everything preceding
};
```

To place the footer correctly, it must be positioned right after the last record. In `.hexpat`, we can use the implicit cursor (the pattern is placed sequentially after the previous structures):

```hexpat
CFRHeader header @ 0x00;  
Record records[header.num_records] @ 0x20;  
// The footer immediately follows the records if the flag is set
```

Or place it explicitly at the end:

```hexpat
// Placement at the end of the file (size - 12 bytes)
CFRFooter footer @ (std::mem::size() - 12);
```

The second approach is more robust: it works even if our record size calculation is slightly off. If the footer colorizes correctly at this position (readable `CRFE` magic, `total_size` = file size), it provides double validation: the footer is indeed there **and** our sequential record calculation is correct.

### Cross-Verification

If the footer is at offset `F`, then the records occupy bytes from `0x20` to `F - 1`. We can verify that the sum `32 (header) + record sizes + 12 (footer) = file size`. If the equality holds, our mapping is complete — every byte of the file is assigned to a structure.

---

## Pass 4 — Understanding the XOR Transformation

Let's now open `packed_noxor.cfr` and `packed_xor.cfr` side by side in ImHex (*Diff View* feature or simply two tabs). Let's apply the same pattern to both files.

The record headers are identical in both files (same names, same lengths). Only the `data[]` areas differ. Let's compare the data area of the first record byte by byte:

```
packed_noxor.cfr (data) : 54 68 69 73 20 69 73 20 61 20 70 6C ...  
packed_xor.cfr   (data) : 0E 54 FF 82 7A 55 EB D1 3B 0C E6 9D ...  
```

The first line is readable ASCII text (`"This is a "…`). The second is transformed. Let's compute the XOR between the two:

```
0x54 ^ 0x0E = 0x5A
0x68 ^ 0x54 = 0x3C
0x69 ^ 0xFF = 0x96
0x73 ^ 0x82 = 0xF1
0x20 ^ 0x7A = 0x5A    ← the pattern repeats
0x69 ^ 0x55 = 0x3C
0x73 ^ 0xEB = 0x96    (note the detail of the actual calculation)
0x20 ^ 0xD1 = 0xF1
```

The XOR key is `5A 3C 96 F1`, and it repeats every 4 bytes. This is a **rotating XOR with a fixed 4-byte key**. We can verify it over the entire data: each byte `data_xor[i]` equals `data_plain[i] ^ key[i % 4]`.

We also confirm what we had observed in section 25.1: `demo.cfr` (flags = `0x0002`, bit 0 = 0) stores data in plaintext, while `packed_xor.cfr` (flags = `0x0003`, bit 0 = 1) transforms it. Bit 0 of the header indeed controls XOR activation.

> 💡 **ImHex tip**: ImHex has a built-in XOR tool in the *Data Processor* (data processing panel). You can select a region, apply a XOR with the key `5A3C96F1`, and verify that the result matches the plaintext.

Let's enrich our pattern to handle the transformation:

```hexpat
// We cannot "decrypt" in a standard .hexpat,
// but we can annotate the area and document the key.

struct Record {
    RecordHeader rh;
    char  name[rh.name_len];

    // If the header's XOR flag is set, these bytes are
    // XORed with the rotating key {0x5A, 0x3C, 0x96, 0xF1}
    u8    data[rh.data_len] [[comment("XOR key: 5A 3C 96 F1 if flag bit 0")]];

    u16   crc16;
};
```

> 📝 **Important note**: is the CRC-16 following the data computed on the data *before* or *after* XOR? This is a crucial question. We can determine it empirically: compute the CRC-16 on the plaintext data (in the non-XOR archive) and check whether the value matches the CRC-16 stored in the XOR archive for the same record. If the CRCs are identical between the two archives for the same record, then the CRC is computed on the data **before** XOR (original data). Otherwise, it is computed on the data **after** XOR (data as stored).  
>  
> This distinction is fundamental for writing a correct parser — it determines the order of operations during validation.

---

## Pass 5 — Identifying the CRC-16

We know that a 2-byte CRC-16 terminates each record. But which CRC-16 exactly? There are many variants (CRC-16/CCITT, CRC-16/XMODEM, CRC-16/IBM, CRC-16/ARC…), which differ by polynomial, initial value, and bit reflection.

### Empirical Approach

Let's take the simplest record in `packed_noxor.cfr` (no XOR to deal with). We know the name bytes and the plaintext data. We extract the stored CRC-16. We could equally use `demo.cfr`, which also does not have the XOR flag set.

Then, we try common CRC-16 variants on the concatenation `name + data` with a tool like `reveng` (CRC RevEng) or a Python script:

```python
# Brute-force script for known CRC-16 variants
import crcmod

data = nom_bytes + payload_bytes  
stored_crc = 0xXXXX  # value read from the file  

# Test CRC-16/CCITT with init=0x1D0F
crc_func = crcmod.mkCrcFun(0x11021, initCrc=0x1D0F, xorOut=0x0000)  
computed = crc_func(data)  
print(f"CCITT init=0x1D0F : {computed:#06x}  {'MATCH' if computed == stored_crc else ''}")  
```

> 💡 **ImHex's Data Inspector can also help.** If you select exactly the bytes on which the CRC should be computed (name + data), some ImHex versions display checksums in the side panel. This does not cover all variants, but can quickly confirm a hypothesis.

When the variant is identified (here: CRC-16/CCITT with polynomial `0x1021` and initial value `0x1D0F`), let's add a comment in the pattern:

```hexpat
u16 crc16 [[comment("CRC-16/CCITT poly=0x1021 init=0x1D0F on name+data")]];
```

---

## Pass 6 — Back to the Header: CRC and `reserved`

### The Header CRC-32

The `header_crc` field at offset `0x10` is a CRC-32. But over which bytes is it computed? It cannot cover itself (chicken-and-egg problem). The standard approach is to set this field to zero before computing the CRC.

Hypothesis: the CRC-32 is computed over the first 16 bytes of the header (offsets `0x00` to `0x0F`), i.e., `magic + version + flags + num_records + timestamp`, with the `header_crc` field excluded from the computation since it comes right after.

Verification: extract the first 16 bytes, compute the standard CRC-32 (polynomial `0xEDB88320`, init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`), and compare with the stored value.

```bash
$ python3 -c "
import struct, binascii  
with open('demo.cfr', 'rb') as f:  
    data = f.read(32)
# CRC-32 of the first 16 bytes
crc = binascii.crc32(data[:16]) & 0xFFFFFFFF  
stored = struct.unpack_from('<I', data, 0x10)[0]  
print(f'Computed: {crc:#010x}')  
print(f'Stored:   {stored:#010x}')  
print('MATCH' if crc == stored else 'MISMATCH')  
"
```

If it doesn't match directly, we need to test a variant: perhaps the CRC is computed over the first 16 bytes with `header_crc` set to zero. This is a classic trial-and-error exercise in format reversing.

### The `reserved` Field

Let's return to the 4-byte field at `0x1C`. We can now formulate a hypothesis by cross-referencing information from our three archives. Let's compute the `reserved` value and the `data_len` of each record:

For `demo.cfr`: data_len of the 4 records = 64, 24, 35, 116.

Let's try a few operations:
- Sum: 64 + 24 + 35 + 116 = 239 → compare with `reserved`  
- XOR: 64 ^ 24 ^ 35 ^ 116 → compare with `reserved`

If the XOR of all `data_len` values matches the stored value, we've found it: it's a **lightweight checksum** that allows quickly verifying size consistency without recomputing all CRCs. Let's verify across all three archives to confirm.

Let's update the pattern:

```hexpat
struct CFRHeader {
    char   magic[4];
    u16    version;
    Flags  flags;
    u32    num_records;
    u32    timestamp;
    u32    header_crc;      // CRC-32 of the first 16 bytes
    char   author[8];       // null-padded
    u32    data_len_xor;    // XOR of all data_len values (verification)
};
```

---

## Complete `.hexpat` Pattern

Here is the consolidated pattern after our six passes. It can be applied to any CFR archive:

```hexpat
#pragma endian little
#pragma pattern_limit 65536

import std.io;  
import std.mem;  

// ───────────────────────────────────────
//  Constants
// ───────────────────────────────────────

#define HEADER_MAGIC "CFRM"
#define FOOTER_MAGIC "CRFE"

// ───────────────────────────────────────
//  Enums & Bitfields
// ───────────────────────────────────────

enum RecordType : u8 {
    TEXT   = 0x01,
    BINARY = 0x02,
    META   = 0x03
};

bitfield HeaderFlags {
    xor_enabled : 1;     // bit 0 — data XORed with key {5A, 3C, 96, F1}
    has_footer  : 1;     // bit 1 — CRFE footer present
    padding     : 14;
};

// ───────────────────────────────────────
//  Header (32 bytes)
// ───────────────────────────────────────

struct CFRHeader {
    char        magic[4];       // 0x00 — "CFRM"
    u16         version;        // 0x04 — format version (expected: 2)
    HeaderFlags flags;          // 0x06 — bitfield
    u32         num_records;    // 0x08 — number of records
    u32         timestamp;      // 0x0C — creation date (UNIX epoch)
    u32         header_crc;     // 0x10 — CRC-32 of bytes [0x00..0x0F]
    char        author[8];      // 0x14 — author, null-padded
    u32         data_len_xor;   // 0x1C — XOR of all data_len values
};

// ───────────────────────────────────────
//  Record (variable size)
//
//  Layout:
//    RecordHeader  (8 bytes)
//    name          (name_len bytes, ASCII, not transformed)
//    data          (data_len bytes, XORed if flag is set)
//    crc16         (2 bytes, CRC-16/CCITT init=0x1D0F
//                   computed on name + data BEFORE XOR)
// ───────────────────────────────────────

struct RecordHeader {
    RecordType type;        // 0x00
    u8         flags;       // 0x01 — reserved (always 0)
    u16        name_len;    // 0x02
    u32        data_len;    // 0x04
};

struct Record {
    RecordHeader rh;
    char name[rh.name_len];
    u8   data[rh.data_len]
        [[comment("Rotating XOR key {5A,3C,96,F1} if header.flags.xor_enabled")]];
    u16  crc16
        [[comment("CRC-16/CCITT poly=0x1021 init=0x1D0F on name||original_data")]];
};

// ───────────────────────────────────────
//  Footer (12 bytes, optional)
// ───────────────────────────────────────

struct CFRFooter {
    char magic[4];       // "CRFE"
    u32  total_size;     // total file size in bytes
    u32  global_crc;     // CRC-32 of everything preceding the footer
};

// ───────────────────────────────────────
//  Instantiation
// ───────────────────────────────────────

CFRHeader header @ 0x00;  
Record    records[header.num_records] @ 0x20;  

// Conditional footer at end of file
if (header.flags.has_footer) {
    CFRFooter footer @ (std::mem::size() - 12);
}
```

### Result in ImHex

Once applied, this pattern produces a complete colorization of the file:

- The **header** (32 bytes) is colorized as a single block, with each field identifiable in the *Pattern Data* panel.  
- Each **record** is individually colorized with its subfields (type, flags, name_len, data_len, name, data, CRC).  
- The **footer** (12 bytes) is colorized at the end of the file.

No byte remains unassigned between the header and the footer — this is the best proof that our mapping is correct.

---

## Methodological Lessons

This six-pass process illustrates several general principles of format reversing:

**Start with what you can see.** Magic bytes and ASCII strings are free anchor points. They allow segmenting the file before even understanding the numeric fields. In `demo.cfr`, the plaintext data allowed us to visually verify the delimitation of each record.

**Validate across multiple files.** A single example file is never enough. Fixed values (magic, version) are confirmed by their consistency across files. Variable values (timestamps, CRC) are confirmed by their coherent variation. It was the comparison between `packed_noxor.cfr` and `packed_xor.cfr` that allowed us to understand the XOR, and the comparison of flags across the three archives that revealed the meaning of each bit.

**Leave unknowns.** It is tempting to want to understand everything before moving forward, but this is counterproductive. The `reserved` field was only elucidated in pass 6, once we had all the `data_len` values. Accepting temporary blind spots and revisiting them with more context is the hallmark of an effective reverse engineer.

**Verify CRCs on known data.** To identify a CRC variant, you need both the plaintext data and the stored CRC. Archives without XOR (`demo.cfr` and `packed_noxor.cfr`) are valuable for this — they eliminate one variable from the equation.

**The `.hexpat` pattern is a living document.** It does not freeze at the end of this section. Fuzzing (section 25.3) may reveal edge cases (zero-length record, empty name, non-zero flags on a record) that require adjustments to the pattern. Writing the Python parser (section 25.4) may also highlight ambiguities that the pattern did not cover.

---



⏭️ [Confirming the interpretation with AFL++ (parser fuzzing)](/25-fileformat/03-confirming-afl-fuzzing.md)
