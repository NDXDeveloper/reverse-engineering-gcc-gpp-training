🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.2 — Packing with UPX — detecting and decompressing

> 🎯 **Objective**: Understand a packer's internal workings, know how to identify a binary packed with UPX (and recognize general packing indicators), master static and dynamic decompression techniques.

---

## What is a packer?

A packer is a tool that transforms an executable binary into another executable binary. The produced binary contains a compressed (and sometimes encrypted) version of the original code, accompanied by a small decompression "stub." At runtime, the stub executes first, decompresses the original code in memory, then transfers control to it.

From the user's perspective, the program works normally. From the analyst's perspective, the file on disk no longer contains the actual code — only compressed noise and a minimalist stub. Disassembly of the packed file shows only the decompression routine, not the program's logic.

Packers are used for two distinct reasons:

- **Size reduction** — The historical use. UPX was designed in the 1990s when disk space and bandwidth were limited. A UPX-packed binary typically weighs 40 to 60% of its original size.  
- **Analysis obstruction** — The use that interests us here. Even though UPX is trivial to decompress, more sophisticated packers (Themida, VMProtect, custom packers) add encryption, anti-debug, and code virtualization to actively resist analysis.

## UPX: the reference packer

UPX (Ultimate Packer for eXecutables) is the most widespread open-source packer. It supports many formats (ELF, PE, Mach-O, etc.) and works on GCC-compiled binaries without source code modification.

### How UPX transforms an ELF

The process of packing an ELF binary with UPX follows these steps:

1. **Reading the original binary** — UPX parses the ELF headers, identifies loadable segments (PT_LOAD) and sections.

2. **Segment compression** — Segment contents (`.text` code, `.data`, `.rodata` data, etc.) are compressed with an NRV (Not Really Vanished) or LZMA-type algorithm. The original code disappears from the file.

3. **Stub construction** — UPX generates a small assembly program (a few hundred bytes) that becomes the new entry point. This stub knows how to decompress data and rebuild the original memory image.

4. **ELF rewriting** — UPX produces a new ELF file with a simplified structure: original segments are replaced by compressed data and the decompression stub. Headers are rewritten to point to the new entry point.

5. **Marking** — UPX writes its signature into the binary (`UPX!` strings and associated magic bytes) so it can later be decompressed with `upx -d`.

### What happens at runtime

When the Linux loader loads the packed binary:

1. The kernel loads the packed file's segments into memory (like any ELF).  
2. Execution starts at the entry point, which is the UPX stub.  
3. The stub decompresses the compressed data into the appropriate memory areas, reconstructing the original segments.  
4. The stub corrects memory page permissions (code = RX, data = RW).  
5. The stub jumps to the original entry point (`_start` or `__libc_start_main`), and the real program execution begins.

This entire process takes a few milliseconds. The user notices nothing.

## Detecting a UPX-packed binary

Detection occurs at multiple levels, from the most obvious to the most subtle. An experienced analyst spots a packed binary in seconds during the initial triage (Chapter 5 workflow).

### The `file` command

`file` often recognizes UPX directly:

```bash
$ file anti_reverse_upx
anti_reverse_upx: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),  
statically linked, no section header at file offset 0,  
missing section headers at 8408 with 0 entries  
```

Multiple clues here. The binary appears as `statically linked` when the original was dynamic. Section headers are absent (`no section header at file offset 0`). For a binary that should be a simple crackme, this is abnormal.

### The `strings` command

This is often the quickest test:

```bash
$ strings anti_reverse_upx | grep -i upx
$Info: This file is packed with the UPX executable packer $
$Id: UPX 4.2.2 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
UPX!
```

UPX leaves its signature in plaintext in the binary. The `$Info:` and `UPX!` strings are characteristic. Note that this signature can be manually removed (we'll revisit this), but in its standard form, UPX identifies itself.

Beyond the UPX signature, compare `strings` output between the original and packed binary:

```bash
$ strings anti_reverse_stripped | wc -l
87

$ strings anti_reverse_upx | wc -l
12
```

A sharp drop in the number of readable strings is a strong packing indicator. The original strings (`"Password"`, `"Access authorized"`, error messages) were compressed and are no longer visible.

### Entropy

Entropy measures the degree of "disorder" in a file's bytes. Compiled machine code has typical entropy between 5.0 and 6.5 (on a scale of 0 to 8). Compressed or encrypted data has entropy close to 7.5 to 8.0 — the bytes are quasi-random.

You can measure entropy with `binwalk`:

```bash
$ binwalk -E anti_reverse_stripped

DECIMAL       HEXADECIMAL     ENTROPY
---------------------------------------------
0             0x0             Rising entropy edge (0.5 -> 6.1)

$ binwalk -E anti_reverse_upx

DECIMAL       HEXADECIMAL     ENTROPY
---------------------------------------------
0             0x0             Rising entropy edge (0.5 -> 7.8)
```

An overall entropy above 7.0 on the majority of the file almost certainly indicates compression or encryption.

ImHex also offers a graphical entropy view that lets you visualize compressed zones at a glance: normal code produces an irregular entropy profile with dips (`.rodata` sections, padding), while a packed binary presents a uniformly high plateau.

### ELF sections

A normal GCC-compiled ELF binary has many sections with familiar names: `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.eh_frame`, etc. A UPX-packed binary presents a radically different structure:

```bash
$ readelf -S anti_reverse_stripped | head -20
  [Nr] Name              Type             ...
  [ 1] .interp           PROGBITS         ...
  [ 2] .note.gnu.build-id NOTE            ...
  [ 3] .gnu.hash         GNU_HASH         ...
  [ 4] .dynsym           DYNSYM           ...
  ...
  [14] .text             PROGBITS         ...
  [15] .rodata           PROGBITS         ...
  ...
  (27 sections total)

$ readelf -S anti_reverse_upx
There are no sections in this file.
```

The total absence of section headers is characteristic of UPX packing on ELF. UPX removes the section table because it's not necessary for execution (the loader uses program headers, not section headers). This makes tools like `objdump` unusable on the packed file.

### Program headers (segments)

In the absence of sections, we examine segments:

```bash
$ readelf -l anti_reverse_upx

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg
  LOAD           0x000000 0x0000000000400000 0x0000000000400000 0x...    0x...    R E
  LOAD           0x...    0x0000000000600000 0x0000000000600000 0x...    0x...    RW
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW
```

Two things to note. First, the number of segments is minimal (2 LOAD + GNU_STACK). Second, the `FileSiz / MemSiz` ratio is very unbalanced on the first LOAD segment: the memory size (`MemSiz`) is much larger than the disk size (`FileSiz`). This makes sense — compressed data on disk must decompress into a larger memory space.

### `checksec`

The `checksec` tool also reveals anomalies:

```bash
$ checksec --file=anti_reverse_upx
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

A binary showing `No RELRO`, `No canary`, `NX disabled`, and `No PIE` simultaneously is suspicious. UPX needs to disable certain protections to write decompressed code into memory (it requires an executable and writable segment during decompression). The Makefile actually compiles with `-no-pie` before packing, since UPX handles PIE binaries poorly in some versions.

### Packing indicator summary

| Indicator | Normal binary | UPX-packed binary |  
|---|---|---|  
| `file` | `dynamically linked, not stripped` | `statically linked, missing section headers` |  
| `strings` | Many readable strings | Almost no strings + `UPX!` signature |  
| Entropy | 5.0 – 6.5 | 7.5 – 8.0 |  
| ELF sections | 25–30 named sections | No sections |  
| `MemSiz / FileSiz` | Ratio close to 1 | High ratio (×2 to ×4) |  
| `checksec` | Various protections | Everything disabled |

## Decompressing a UPX binary

### Static decompression: `upx -d`

UPX being reversible by design, decompression is trivial when the signature is intact:

```bash
$ upx -d anti_reverse_upx -o anti_reverse_unpacked
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reese

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     14832 <-      6480   43.69%   linux/amd64   anti_reverse_unpacked

Unpacked 1 file.
```

The decompressed binary is functionally identical to the original. You can now disassemble it, load it into Ghidra, set breakpoints — analysis resumes normally.

### When `upx -d` fails: altered signature

A malware author or developer seeking to complicate analysis can modify the UPX signature in the packed binary. The `UPX!` magic bytes are replaced by arbitrary values, and the `$Info:` string is erased. In this case, `upx -d` refuses to decompress:

```bash
$ upx -d modified_binary
upx: modified_binary: NotPackedException: not packed by UPX
```

To work around this, two approaches are possible.

**Restore the signature** — UPX magic bytes are at known offsets in the file. You can restore them with a hex editor (ImHex) by finding the characteristic UPX stub patterns and rewriting the 4 bytes `UPX!` (`55 50 58 21`) at the right locations. There are typically three occurrences of the signature in a UPX binary.

**Dynamic decompression** — Instead of trying to decompress the file, let it decompress itself by running it, then recover the code from memory. This is the approach described in the next section.

### Dynamic decompression: memory dump with GDB

Dynamic decompression consists of letting the stub execute, waiting until it has finished decompressing the code, then recovering the memory image containing the original program.

**Step 1 — Find the jump point to the original code**

The UPX stub ends with a jump (often an indirect `jmp` or `call`) to the decompressed program's entry point. You can spot it by disassembling the stub:

```bash
$ objdump -d -M intel anti_reverse_upx | tail -20
```

The stub is short (a few hundred instructions). The last unconditional jump at the end of the stub is generally the control transfer to the original code.

**Step 2 — Set a breakpoint and execute**

```
$ gdb ./anti_reverse_upx
(gdb) starti
(gdb) info proc mappings
```

We examine memory mappings. After identifying the stub's end, we set a breakpoint just after decompression:

```
(gdb) break *0x<final_jmp_address>
(gdb) continue
```

The stub executes, decompresses everything, and stops just before jumping to the original code.

**Step 3 — Dump memory**

We use `dump memory` to extract decompressed segments:

```
(gdb) info proc mappings
(gdb) dump memory code_dump.bin 0x400000 0x402000
(gdb) dump memory data_dump.bin 0x600000 0x601000
```

Chapter 29 details reconstructing a functional ELF from these memory dumps.

**Alternative with `/proc/pid/mem`**

Without GDB, you can also directly read process memory via `/proc/<pid>/mem` combined with `/proc/<pid>/maps`:

```bash
# In a terminal, launch the binary and suspend it
$ ./anti_reverse_upx &
$ PID=$!
$ kill -STOP $PID

# Read mappings
$ cat /proc/$PID/maps

# Dump a segment
$ dd if=/proc/$PID/mem bs=1 skip=$((0x400000)) count=$((0x2000)) \
     of=segment_dump.bin
```

## Beyond UPX: recognizing other packers

UPX is the most common packer and the easiest to handle. Other packers exist and are significantly more resistant to analysis. They'll be covered in Chapter 29, but here are the general indicators that betray packing, regardless of the packer:

- **High entropy** (> 7.0) on the majority of the file  
- **Very few readable strings** relative to the binary's size  
- **Unusual section names** — Some packers rename sections (`.UPX0`, `.UPX1` for UPX on PE, random names for other packers)  
- **Entry point pointing to an unusual section** — For example in `.data` or an unknown section rather than `.text`  
- **Abnormal `MemSiz / FileSiz` ratio** in program headers  
- **Signature-based detection** — YARA rules (Chapter 6, Section 6.10 and Chapter 35) can detect known packers by their characteristic byte patterns

The fundamental distinction to remember: packing is a reversible transformation of the on-disk binary. Once in memory, the original code is always there, in plaintext, ready to be analyzed. This is why dynamic decompression (memory dump) works universally, even when static decompression fails.

---


⏭️ [Control flow obfuscation (Control Flow Flattening, bogus control flow)](/19-anti-reversing/03-control-flow-obfuscation.md)
