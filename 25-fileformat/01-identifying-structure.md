🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 25.1 — Identifying the General Structure with `file`, `strings`, and `binwalk`

> 🎯 **Objective of this section**: establish an initial portrait of the unknown file format in under ten minutes, without opening a disassembler. By the end, you will have identified the magic bytes, visible strings, entropy zones, and formulated your first hypotheses about the data organization.

---

## Setting the Context

Let's imagine the following situation: we have the binary `fileformat_O2_strip` (compiled with `-O2`, stripped) and three `.cfr` files produced by this binary — `demo.cfr`, `packed_noxor.cfr`, and `packed_xor.cfr`. We know nothing about the format. The `.cfr` extension doesn't match any known format. Our mission begins.

The temptation is strong to immediately open Ghidra to analyze the parser. Resist. Reversing a file format is **more effective when you start with the data itself** rather than the code. Observing the raw bytes with simple tools allows you to formulate concrete hypotheses *before* diving into the disassembly. You then enter Ghidra with precise questions rather than a blind exploration.

The three tools of this first pass — `file`, `strings`, and `binwalk` — are intentionally primitive. That's their strength: they don't need to understand the format to reveal useful information.

---

## Step 1 — `file`: Attempting Automatic Identification

The `file` command identifies a file by examining its first bytes and comparing them against a signature database (the "magic patterns" defined in `/usr/share/misc/magic`). For an unknown custom format, `file` won't find anything relevant — and that in itself is information.

```bash
$ file demo.cfr
demo.cfr: data
```

The `data` verdict means that `file` didn't recognize any known signature. This is the expected result for a proprietary format. If `file` had returned something more specific (a PNG, a ZIP, an ELF…), it would have meant either that the format encapsulates a known format, or that the file isn't what we think it is.

Let's also check the other two archives:

```bash
$ file packed_noxor.cfr packed_xor.cfr
packed_noxor.cfr: data  
packed_xor.cfr:   data  
```

Same result. Note in passing that the three files share the same extension but could have internal variations. Let's keep that in mind.

> 💡 **Useful reflex**: also run `file` on the binary itself to confirm its nature.  
>  
> ```bash  
> $ file fileformat_O2_strip  
> fileformat_O2_strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
>                      dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
>                      BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped  
> ```  
>  
> We confirm a dynamically linked, stripped x86-64 ELF — consistent with our compilation parameters.

---

## Step 2 — `xxd`: Observing the First Bytes

Before moving on to `strings`, let's get into the habit of looking at the very first bytes of the file. This is almost always where a format's magic bytes are found.

```bash
$ xxd demo.cfr | head -4
00000000: 4346 524d 0200 0200 0400 0000 xxxx xxxx  CFRM............
00000010: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  ................
00000020: 01xx xxxx xxxx xxxx xxxx xxxx 6772 6565  ............gree
00000030: 7469 6e67 2e74 7874 xxxx xxxx xxxx xxxx  ting.txt........
```

*(The `xx` represent variable bytes — timestamps, CRC, etc.)*

In the very first four bytes, we can read the ASCII characters **`CFRM`**. This is our first major discovery: the format uses a 4-byte magic number at the beginning of the file. Let's note this immediately.

We also observe that around offset `0x20`, we start seeing readable file names (`greeting.txt`). This suggests that the header is relatively short (about thirty bytes?) and that the useful data begins quickly after it.

Let's also look at the end of the file:

```bash
$ xxd demo.cfr | tail -4
```

If the format has a footer, we should find a second magic there. Let's search:

```bash
$ xxd demo.cfr | grep -i "crfe\|cfrm"
```

If we spot the string `CRFE` toward the end of the file, it's a strong indication of a footer with its own magic.

---

## Step 3 — `strings`: Extracting Readable Strings

The `strings` command extracts all sequences of printable bytes of a minimum length (4 by default). On a file format, it reveals names, textual metadata, and sometimes structural clues.

### On the Data Files

```bash
$ strings demo.cfr
CFRM  
greeting.txt  
Hello from the CFR archive format!  
This is a sample text record.  
data.bin  
version.meta  
format=CFR  
version=2  
author=student  
notes.txt  
This archive was generated for Chapter 25 of the RE training.  
Your mission: reverse-engineer this format completely.  
CRFE  
```

This output is a goldmine. We learn that:

- **`CFRM`** appears at the beginning of the file (header magic confirmed).  
- **`CRFE`** appears at the end of the file (probable footer magic).  
- The format contains **file names** (`greeting.txt`, `data.bin`, `version.meta`, `notes.txt`), which confirms it is an archive format.  
- Textual contents are readable in plaintext — at least for some records.  
- Key-value pairs appear (`format=CFR`, `version=2`, `author=student`), suggesting a distinct metadata record type.

Now let's compare with the XOR archive:

```bash
$ strings packed_xor.cfr
CFRM  
test.txt  
info.meta  
fake.bin  
CRFE  
```

Important observation: the **file names** remain readable, but the **contents** have disappeared from the `strings` output. This means that the data (payload) is transformed in a way that breaks ASCII strings, while the names are not. Hypothesis: some form of obfuscation or compression is selectively applied to the data, but not to the names.

Let's verify with the non-XOR archive:

```bash
$ strings packed_noxor.cfr
CFRM  
test.txt  
This is a plain text test file for packing.  
info.meta  
chapter=25  
topic=fileformat  
fake.bin  
CRFE  
```

Here the textual contents are readable. The difference between `packed_xor.cfr` and `packed_noxor.cfr` confirms the hypothesis: an optional transformation is applied to the data. The fact that it is "optional" suggests the existence of a flag in the header that controls this behavior.

### On the Binary Itself

Running `strings` on the executable binary is equally revealing:

```bash
$ strings fileformat_O2_strip | head -60
```

We'll typically find:

- Error and usage strings: `"Usage:"`, `"generate"`, `"pack"`, `"list"`, `"read"`, `"unpack"`, `"validate"` — which reveals the subcommands supported by the binary.  
- Format strings: `"CFRM"`, `"CRFE"`, `"TEXT"`, `"BINARY"`, `"META"` — which confirms our observations about the magics and reveals the record types.  
- Diagnostic messages: `"Invalid magic"`, `"Header CRC"`, `"Record %u"`, `"CRC-16"` — which betray the presence of integrity verification mechanisms (CRC-32 for the header, CRC-16 per record).  
- Field-related strings: `"Author"`, `"Flags"`, `"Version"`, `"Records"` — hints about the header structure.

Let's filter the most interesting strings:

```bash
$ strings fileformat_O2_strip | grep -iE "crc|magic|record|header|footer|flag|xor"
```

Each string found here is a thread to pull during the Ghidra analysis. The message `"Invalid magic: expected CFRM"`, for example, once located in the disassembly, will lead us directly to the header parsing function.

> 📝 **Key takeaway**: `strings` on the binary is often *more* informative than `strings` on the data itself, because the binary contains the error messages that describe the format's constraints.

---

## Step 4 — `binwalk`: Scanning for Known Structures and Entropy

`binwalk` is a firmware analysis tool that excels at detecting nested formats (archives within archives, filesystems, compressed images) and computing entropy by blocks. Even when it doesn't recognize anything, its entropy analysis remains valuable.

### Signature Scan

```bash
$ binwalk demo.cfr

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------
```

No recognized signature — this is expected for an entirely custom format. If `binwalk` had detected a gzip header, a JFFS2 filesystem, or a PNG image at a certain offset, it would have meant that the format encapsulates data in a standard format.

### Entropy Analysis

This is where `binwalk` becomes truly useful for format reversing:

```bash
$ binwalk -E demo.cfr
```

This command produces a graph (or text output) of entropy by blocks. Entropy measures the "disorder" of bytes on a scale from 0 (perfectly uniform, e.g., all zeros) to 1 (pure random, e.g., encrypted or compressed data).

For our `demo.cfr` archive:
- The **header** (first ~32 bytes) will have moderate entropy — a mix of structured bytes (ASCII magic, counters, CRC) and padding.  
- The **text records** will have typical ASCII text entropy (~0.4–0.6).  
- The **binary record** (`data.bin`) will have higher entropy.

Now let's compare the three archives:

```bash
$ binwalk -E packed_noxor.cfr
$ binwalk -E packed_xor.cfr
```

The difference between these two files will be visually striking. The XOR archive will show significantly higher entropy in the data zones, while the name zones (not transformed) will keep the same entropy. This entropy difference between names and data is yet another clue that the transformation only applies to the payloads.

> 💡 **Interpreting entropy**:  
>  
> | Entropy      | Typical interpretation |  
> |---|---|  
> | 0.0 – 0.2    | Padding, zero zones, highly structured data |  
> | 0.3 – 0.6    | ASCII text, executable code, structured data |  
> | 0.7 – 0.85   | Transformed data (simple XOR, basic encoding) |  
> | 0.85 – 1.0   | Encrypted or compressed data (AES, gzip, zlib…) |  
>  
> Short-key XOR (4 bytes in our case) raises text entropy but generally doesn't bring it to the level of strong encryption. Observing entropy around 0.7–0.8 in a zone that should contain text is a classic indicator of XOR.

### Raw String Scan with Offset

`binwalk` can also extract strings with their offsets, similarly to `strings` but with analysis-oriented formatting:

```bash
$ binwalk -R "CFRM" demo.cfr
$ binwalk -R "CRFE" demo.cfr
```

These raw pattern searches confirm the exact positions of the magic bytes in the file. We thus verify that `CFRM` appears only once (at offset 0) and that `CRFE` appears only at the end of the file (footer).

---

## Step 5 — Initial Size Calculations

Before wrapping up this reconnaissance phase, let's note the file sizes:

```bash
$ ls -la samples/*.cfr
-rw-r--r-- 1 user user  364 ... demo.cfr
-rw-r--r-- 1 user user  204 ... packed_noxor.cfr
-rw-r--r-- 1 user user  204 ... packed_xor.cfr
```

The two `packed_*.cfr` archives have the same size — logical, since they contain the same files and only the data transformation differs. XOR doesn't change the size (it's a byte-by-byte transformation), which rules out compression as an explanation for the transformation.

We can also start estimating the header size. If the magic is 4 bytes and the first readable data appears around offset `0x20` (32 in decimal), the header is probably 32 bytes. That's a round and typical size for a binary format header.

Similarly, if `CRFE` is followed by a few bytes before the end of the file, we can estimate the footer size.

---

## Summary: What We Know After 10 Minutes

Let's recap the hypotheses formulated at this stage, without having touched a disassembler:

| Discovery | Source | Confidence |  
|---|---|---|  
| Header magic: `CFRM` (4 bytes at offset 0) | `xxd`, `strings` | Certain |  
| Footer magic: `CRFE` (end of file) | `strings`, `binwalk -R` | Strong |  
| The format is an archive (contains named files) | `strings` | Certain |  
| Probable header size: ~32 bytes | `xxd` | Hypothesis |  
| At least 3 content types: text, binary, metadata | `strings` on the binary | Strong |  
| Optional data transformation (likely XOR) | `strings` comparison + entropy | Strong |  
| The transformation doesn't change the size | `ls -la` | Certain |  
| Names are not transformed | `strings` on the XOR archive | Certain |  
| Integrity mechanisms: CRC-32 (header) + CRC-16 (records) | `strings` on the binary | Strong |  
| A flag in the header controls the transformation | Existence of two variants | Hypothesis |

This is a solid starting point. We know what we're looking for, we have keywords to navigate the disassembly (`CFRM`, `Invalid magic`, `CRC`), and we have testable hypotheses.

---

## Creating a Structured Notebook

Before moving on to the hexadecimal mapping (section 25.2), open a dedicated notes file. A good working format:

```markdown
# Reverse CFR Format — Notes

## Magic bytes
- Header: 0x4346524D ("CFRM") @ offset 0x00
- Footer: 0x43524645 ("CRFE") @ end of file

## Estimated sizes
- Header: ~32 bytes (to be confirmed)
- Footer: ~12 bytes (to be confirmed)

## Record types
- TEXT, BINARY, META (strings from the binary)

## Transformation
- Optional (flag), probably XOR
- Applies to data, not to names
- Doesn't change the size → no compression

## Integrity
- CRC-32 for the header
- CRC-16 per record
- Possible global CRC (footer?)

## Open questions
- [ ] Exact header structure (which fields, in what order?)
- [ ] Where is the XOR flag in the header?
- [ ] How is a record structured? (header + name + data + CRC?)
- [ ] Which CRC-16 variant? (polynomial, initial value)
- [ ] What is the XOR key?
- [ ] What exactly does the footer contain?
- [ ] Does the "reserved" field visible in the binary's messages serve any purpose?
```

This notebook will evolve throughout the following sections. Each hypothesis will be confirmed or corrected, each question resolved and checked off.

---


⏭️ [Mapping fields with ImHex and an iterative `.hexpat` pattern](/25-fileformat/02-mapping-imhex-hexpat.md)
