🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 29.1 — Identifying UPX and Custom Packers with `checksec` + ImHex + Entropy

> 🎯 **Section objective** — Before attempting any unpacking, you first need to **confirm** that the binary is packed and, if possible, **identify the packer** used. This section presents a systematic methodology based on five converging indicators, which we'll apply to the `packed_sample` variants compiled for this chapter.

---

## The problem: how do you know a binary is packed?

A packed binary carries no label saying "I'm compressed." It remains a perfectly valid ELF file: the Linux kernel can load and execute it without issue. The decompression stub is perfectly normal machine code. It's only by examining the file's **statistical properties**, the **structure of its sections**, and the **behavior of its metadata** that you can deduce the visible code is not the real code.

Identification relies on the convergence of multiple indicators. No single indicator taken in isolation is sufficient — a legitimate binary can have a high-entropy section (embedded compressed data), unusual section names (custom linker), or few readable strings (Rust or Go binary). It's the **combination** of these signals that allows you to conclude with confidence.

---

## Indicator 1 — Quick triage with `file` and `strings`

The first command to run on any unknown binary remains `file`. On a UPX-packed binary, the output is often revealing:

```
$ file packed_sample_upx
packed_sample_upx: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),  
statically linked, no section header  
```

Two elements should catch your attention. First, the mention **`statically linked`** when the original program uses libc functions (`printf`, `fgets`, `strcmp`...) — a standard GCC binary is almost always dynamically linked. UPX produces a standalone executable that embeds the stub and compressed data, with no external dependencies. Second, the mention **`no section header`** (or an abnormally low section count): UPX removes the section table, which isn't needed for kernel loading but is essential for disassemblers.

Let's immediately follow up with `strings`:

```
$ strings packed_sample_O2_strip | wc -l
87

$ strings packed_sample_upx | wc -l
9
```

The unpacked binary contains dozens of readable strings: the banner, the flag, error messages, libc function names. The packed binary contains almost none — the only visible strings are those from the UPX stub itself. If `strings` returns only a handful of results on a binary that's supposed to interact with the user (text display, input reading), that's a strong packing signal.

> 💡 **Watch out for the reverse trap** — A stripped Go or Rust binary can also produce very few strings with `strings`, without being packed. This is why you should never stop at a single indicator.

---

## Indicator 2 — Section and segment analysis with `readelf`

The internal structure of a packed ELF differs radically from that of a standard binary. Let's examine the **program headers** (segments) and the **section headers**:

```
$ readelf -l packed_sample_upx
```

On a typical UPX binary, you generally observe two or three `LOAD` segments with unusual characteristics:

- A first `LOAD` segment with **`RWE`** (Read-Write-Execute) flags. In a normal binary, code segments are `RE` (Read-Execute) and data segments are `RW` (Read-Write). A segment that is simultaneously writable and executable is an almost certain marker of packing or self-modifying code: the stub needs to write decompressed code into a memory area that it will then execute.  
- An abnormal **size ratio** between the on-disk size (`FileSiz`) and the in-memory size (`MemSiz`). A segment whose `MemSiz` is much larger than its `FileSiz` indicates the loader will need to allocate much more memory than what's present in the file — this is exactly what happens when the stub decompresses the original code into it.

On the sections side:

```
$ readelf -S packed_sample_upx
```

If the section table still exists (UPX often removes it, but some packers keep it), you can observe **non-standard section names**. UPX historically uses `UPX0`, `UPX1`, `UPX2` as section names. On our `packed_sample_upx_tampered` variant, these names have been altered to `XP_0`, `XP_1`, `XP_2` — but the very fact that the names don't match any standard ELF convention (`.text`, `.data`, `.rodata`...) remains an indicator.

For comparison, the unpacked binary has a perfectly standard section structure:

```
$ readelf -S packed_sample_O2_strip | grep -c "\."
27
```

Twenty-seven sections with standard names (`.text`, `.rodata`, `.data`, `.bss`, `.plt`, `.got`, `.init`, `.fini`...) versus two or three sections with exotic names in the packed binary.

---

## Indicator 3 — `checksec` and binary protections

The `checksec` tool (included in `pwntools` and available standalone) displays a binary's security protections. On a packed binary, the result is often characteristic:

```
$ checksec --file=packed_sample_O2_strip
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE

$ checksec --file=packed_sample_upx
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

The simultaneous disappearance of all protections is an alarm signal. Here's why each change is significant:

- **NX disabled** — The NX (No-eXecute) bit prevents code execution in data segments. UPX needs to decompress code into a memory area initially marked as data, then execute it. For this to work, NX protection must be disabled (or the stub must use `mprotect` to change permissions, which some more sophisticated packers do).  
- **No canary found** — Stack canaries are inserted by GCC at compile time (`-fstack-protector`). Since the visible binary is the packer's stub (not the GCC-compiled code), the original code's canaries are not detectable.  
- **No RELRO** — RELRO (Relocation Read-Only) protection concerns the GOT table. Since the packed binary doesn't have a conventional GOT (the stub handles import resolution itself after decompression), RELRO is absent.

In summary: a binary that was compiled with GCC's standard protections and suddenly loses all of them has most likely been through a packer.

---

## Indicator 4 — Entropy analysis

Entropy is the most reliable measure for detecting packing. The concept is simple: Shannon entropy measures the degree of "disorder" in a byte sequence, on a scale from 0.0 (perfectly uniform sequence, e.g., all zeros) to 8.0 (sequence statistically indistinguishable from random data).

x86-64 machine code typically has entropy between **5.0 and 6.5**: it contains repetitive patterns (function prologues, common instructions) but enough variety to not be trivial. Compressed (and even more so encrypted) data has entropy between **7.5 and 8.0**: compression eliminates all redundancy, making the data resemble random noise.

### Method 1 — `binwalk -E`

The `binwalk` tool with the `-E` (entropy) option produces a per-block entropy graph across the entire file:

```
$ binwalk -E packed_sample_O2_strip
```

On an unpacked binary, the graph shows variations: average entropy on `.text`, lower on `.rodata` (readable character strings), very low on `.bss` (zeros). On a packed binary, the graph shows a **nearly uniform plateau at entropy above 7.5** across most of the file, with possibly a small lower-entropy zone corresponding to the decompression stub.

### Method 2 — Python script with `math.log2`

For finer analysis (per section or per segment), you can compute entropy manually:

```python
import math  
from collections import Counter  

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )
```

By applying this function to each `LOAD` segment's data (extracted with `readelf` + `dd` or with `pyelftools`), you get precise numerical values. The empirical thresholds to remember are: below 6.0, the data is probably machine code or plaintext data; between 6.0 and 7.0, it may be optimized code or structured data; above 7.5, it is almost certainly compressed or encrypted data.

### Method 3 — ImHex (visual analysis)

ImHex offers a built-in entropy view accessible via **View → Data Information**. This view displays a byte distribution histogram and a per-block entropy curve directly overlaid on the hex view. This is the most intuitive approach: you literally **see** compressed zones (uniform color, flat byte distribution) standing out from code or data zones (irregular distribution, peaks on certain byte values).

In ImHex, an unpacked binary's byte distribution shows characteristic peaks: `0x00` (padding, string terminators) dominates heavily, followed by a few frequent opcodes. On a packed binary, the distribution is almost flat — every byte value from `0x00` to `0xFF` appears with nearly identical frequency. This "flatness" is the most immediate visual sign of packing.

---

## Indicator 5 — Packer-specific signatures

Some packers leave identifiable signatures in the binary, even without analyzing the stub's code.

### UPX signatures

UPX is the most common and easiest packer to identify. It leaves several markers:

- The ASCII string **`UPX!`** (magic bytes `0x55 0x50 0x58 0x21`) present in the compression metadata, usually toward the end of the file. You can search for it with `grep` in binary mode or in ImHex with a hex search.  
- The section names **`UPX0`**, **`UPX1`**, **`UPX2`** if the section table is preserved.  
- The string **`$Info: This file is packed with the UPX executable packer`** sometimes present in UPX versions that weren't invoked with `--no-banner`.  
- The **UPX compression header** structure at a fixed offset from the end of the file (`p_info`, `l_info`, `p_blocksize`), documented in UPX's source code.

```
$ grep -c "UPX!" packed_sample_upx
1

$ grep -c "UPX!" packed_sample_upx_tampered
0
```

On our `packed_sample_upx_tampered` variant, signatures have been deliberately replaced (`UPX!` → `FKP!`, `UPX0` → `XP_0`...). This is a common technique in malware that uses UPX but wants to prevent automatic decompression with `upx -d`. However, the **stub's code** remains UPX's: the decompression instruction sequences (copy loop, zero-run handling) are recognizable when analyzing the entry point.

### Signatures of other ELF packers

Beyond UPX, other packers leave identifiable traces:

- **Ezuri** — A Go packer targeting Linux ELF binaries, widespread in IoT botnets. The stub is a statically compiled Go program, which produces a large binary (several MB) with Go internal structures (`gopclntab`, runtime). The presence of a Go runtime in a binary that's not supposed to be written in Go is a strong signal.  
- **Midgetpack** — Uses ELF sections with random names and an assembly-written stub. Entropy remains the best indicator.  
- **Custom packers** — No known signature. Identification relies solely on structural indicators (entropy, RWE segments, `FileSiz`/`MemSiz` ratio, absence of standard sections) and on code analysis at the entry point.

### YARA rules for automated detection

Packer detection can be formalized as YARA rules, as seen in Chapter 6 (section 6.10). A simple rule for standard UPX could target the `UPX!` magic combined with the presence of `RWE` segments. For custom packers, rules will rely on statistical criteria (entropy calculated by YARA's `math` module) rather than exact signatures.

The file `yara-rules/packer_signatures.yar` in the repository contains a ready-to-use rule set for the most common packers.

---

## Summary: the detection grid

To conclude this section, here is the decision grid that we'll systematically apply when facing a suspicious binary. We consider the binary is probably packed if **three or more indicators** converge:

| # | Indicator | Tool | Threshold / Signal |  
|---|--------|-------|----------------|  
| 1 | Very few readable strings | `strings \| wc -l` | Fewer than ~15 for an interactive binary |  
| 2 | Missing sections or non-standard names | `readelf -S` | Names outside ELF conventions (`.text`, `.data`...) |  
| 3 | LOAD segment with RWE flags | `readelf -l` | Simultaneous Read+Write+Execute flags |  
| 4 | `MemSiz` ≫ `FileSiz` ratio on a segment | `readelf -l` | Ratio greater than ~3× |  
| 5 | Missing protections (NX off, no canary, no RELRO) | `checksec` | Loss of all GCC protections |  
| 6 | Overall entropy > 7.5 | `binwalk -E` / ImHex | High entropy plateau across the file |  
| 7 | Nearly uniform byte distribution | ImHex (Data Information) | Flat histogram from `0x00` to `0xFF` |  
| 8 | Known packer signature | `strings` / ImHex / YARA | `UPX!`, section names, magic bytes |

When convergence is established and the packer identified (or not), we move to the next step: actually decompressing the binary, which will be covered in section 29.2.

---

> 📌 **Key takeaway** — Packing identification is a differential diagnosis: you accumulate independent indicators and conclude by convergence. A single indicator is never sufficient. Entropy is the most reliable indicator, but it must always be corroborated by structural analysis (sections, segments, protections) to avoid false positives.

⏭️ [Static unpacking (UPX) and dynamic unpacking (memory dump with GDB)](/29-unpacking/02-static-dynamic-unpacking.md)
