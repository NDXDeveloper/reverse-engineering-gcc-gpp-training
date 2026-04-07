🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 5.1 — `file`, `strings`, `xxd` / `hexdump` — first contact with an unknown binary

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

You just received a binary file. Maybe a suspicious executable flagged by a SOC team, maybe a CTF challenge, maybe a legacy binary whose sources are lost. Whatever the situation, the first question is always the same: **what is it?**

The file's extension is worthless — it can be missing, misleading, or deliberately forged. The filename is not much better. The only source of truth is the **content of the file itself**.

The three tools presented in this section — `file`, `strings`, and `xxd`/`hexdump` — form the very first reflex of the reverse engineer. They require no knowledge of the binary's internal format, never execute the file, and deliver a surprising amount of information in seconds. Together, they answer three fundamental questions:

1. **What type of file is it?** → `file`  
2. **Which readable texts does it contain?** → `strings`  
3. **What does its raw content look like?** → `xxd` / `hexdump`

---

## `file` — identifying a file's nature

### How it works

The `file` command identifies a file's type by examining its content, not its extension. It relies on a signature database called the **magic database** (usually `/usr/share/misc/magic` or `/usr/share/file/magic`). This database contains thousands of rules that associate byte sequences located at precise positions in the file — the **magic bytes** or **magic numbers** — with a known file type.

For example, every ELF file starts with the four bytes `7f 45 4c 46` (the DEL character followed by the ASCII letters `E`, `L`, `F`). A PDF file starts with `%PDF`, a PNG with `89 50 4e 47`. The `file` command reads these first bytes, compares them to its database, and derives the type.

For an ELF binary, `file` goes well beyond the simple magic number: it parses the ELF headers to extract the target architecture, the binary type (executable, shared library, relocatable object), the endianness, the target OS, and other metadata.

### Basic usage

```bash
$ file keygenme_O0
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a3f5...c4e2, for GNU/Linux 3.2.0, not stripped
```

This single line already tells us a lot. Let's break down each element:

| Fragment | Meaning |  
|---|---|  
| `ELF` | The file format is ELF (Executable and Linkable Format), the Linux standard. |  
| `64-bit` | The binary targets a 64-bit architecture. Registers, pointers, and addresses are 8 bytes. |  
| `LSB` | Little-endian (Least Significant Byte first). The low-order byte is stored first in memory. This is the norm on x86/x86-64. |  
| `pie executable` | The binary is a **PIE** (Position-Independent Executable). It can be loaded at any memory address, which lets ASLR work fully. |  
| `x86-64` | The instruction set architecture is x86-64 (also called AMD64 or Intel 64). |  
| `version 1 (SYSV)` | ELF ABI version. `SYSV` means System V, the standard Linux ABI. |  
| `dynamically linked` | The binary depends on shared libraries (`.so`) that will be loaded at runtime by the dynamic loader. |  
| `interpreter /lib64/ld-linux-x86-64.so.2` | The path of the dynamic loader (also called *dynamic linker* or *RTLD*). It is what resolves dependencies at launch. |  
| `BuildID[sha1]=a3f5...c4e2` | A unique build identifier, useful to correlate a binary with its debug symbols. |  
| `for GNU/Linux 3.2.0` | The minimum Linux kernel version required to run this binary. |  
| `not stripped` | Debug symbols **have not been removed**. Function and variable names will therefore be found in the symbol tables. That is valuable information for RE. |

### Comparison with a stripped binary

```bash
$ file keygenme_O2_strip
keygenme_O2_strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d8b1...7f3a, for GNU/Linux 3.2.0, stripped
```

The difference is obvious: `stripped` instead of `not stripped`. This means symbols have been removed with the `strip` command. Function names will no longer be in the symbol tables — the reversing work will be harder. Note that `file` tells us nothing about the optimization level (`-O0`, `-O2`…): this information is not stored explicitly in the ELF headers.

### Useful options for RE

```bash
# Display the MIME type instead of the textual description
$ file -i keygenme_O0
keygenme_O0: application/x-executable; charset=binary

# Follow symbolic links
$ file -L /usr/bin/python3
/usr/bin/python3: ELF 64-bit LSB pie executable, x86-64, ...

# Do not display the filename (useful in scripts)
$ file -b keygenme_O0
ELF 64-bit LSB pie executable, x86-64, ...

# Process several files at once
$ file binaries/ch05-keygenme/*
```

### What `file` does not tell you

`file` is a **classification** tool, not an analysis tool. It will tell you a file is an x86-64 ELF, but it will not tell you which functions it contains, which libraries it calls, nor what it does. It does not reliably detect packers either: a UPX-packed binary will often be identified as a plain ELF, even if its content is compressed. To go further, you need to inspect the sections and the entropy — which we will do with other tools.

---

## `strings` — extracting readable strings

### How it works

A compiled binary is not made solely of machine instructions. It also contains **textual data**: error messages, user prompts, filenames, URLs, configuration keys, `printf` format strings, library function names, and sometimes information the developer did not intend to leave visible.

The `strings` command scans a file and extracts every sequence of bytes that corresponds to printable ASCII characters (by default, sequences of at least 4 consecutive characters). It does not understand the file's structure — it simply looks for text patterns in a raw byte stream.

### Basic usage

```bash
$ strings keygenme_O0
/lib64/ld-linux-x86-64.so.2
libc.so.6  
puts  
printf  
strcmp  
strlen  
__cxa_finalize
__libc_start_main
GLIBC_2.2.5  
GLIBC_2.34  
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
[...]
Enter your license key:  
Invalid key format. Expected: XXXX-XXXX-XXXX-XXXX  
Checking key...  
Access granted! Welcome.  
Access denied. Invalid key.  
SuperSecret123  
[...]
GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0
[...]
```

In a few seconds and without any code analysis, `strings` gives us a remarkable set of clues:

- **libc dependencies**: `puts`, `printf`, `strcmp`, `strlen` — we know the program prints text and compares strings. The presence of `strcmp` in a crackme is a major clue: it is probably the function comparing the entered password to the expected value.  
- **User messages**: `Enter your license key:`, `Access granted!`, `Access denied.` — we immediately understand the program's flow: it asks for a key, checks it, and displays a result.  
- **Expected format**: `Expected: XXXX-XXXX-XXXX-XXXX` — we now know the key format without reading a single instruction.  
- **Suspicious data**: `SuperSecret123` — a string that looks a lot like a hardcoded password or key. In a real binary, finding something like this would be a major security flaw.  
- **Compilation information**: `GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0` — GCC embeds its version in a `.comment` section of the binary. We now know which compiler and version were used.

### Essential options for RE

```bash
# Change the minimum string length (default: 4)
# A higher value reduces the noise
$ strings -n 8 keygenme_O0

# Display the offset (position in the file) of each string
# Essential for finding the string in a hex editor
$ strings -t x keygenme_O0
   2a8 /lib64/ld-linux-x86-64.so.2
   [...]
   2048 Enter your license key:
   2060 Invalid key format. Expected: XXXX-XXXX-XXXX-XXXX
   [...]

# Also look for strings encoded as UTF-16 little-endian
# (frequent in Windows or cross-platform binaries)
$ strings -e l keygenme_O0

# Scan all file sections (not only data sections)
$ strings -a keygenme_O0
```

The `-t x` option is particularly useful: it displays the hexadecimal offset of each string in the file. That offset lets you locate the string precisely in `xxd` or ImHex, and trace it back to the code that references it via cross-references in a disassembler (chapters 7 and 8).

### Filtering the output smartly

The raw output of `strings` is often large and noisy. In practice, you almost always combine it with `grep` or other filtering tools:

```bash
# Look for URLs or network paths
$ strings keygenme_O0 | grep -iE '(http|ftp|/tmp/|/etc/|\.conf)'

# Look for printf format strings (reveals the display logic)
$ strings keygenme_O0 | grep '%'

# Look for error messages (often very telling)
$ strings keygenme_O0 | grep -iE '(error|fail|denied|invalid|success|grant)'

# Look for crypto function names (hints about the encryption used)
$ strings keygenme_O0 | grep -iE '(aes|sha|md5|rsa|encrypt|decrypt|key|iv)'

# Count the number of strings to estimate the binary's "richness"
$ strings keygenme_O0 | wc -l
```

### `strings` on a stripped binary

On a stripped binary, local function names disappear from the symbol tables, but **data strings** remain intact. Error messages, prompts, `printf` format strings — all of it survives stripping, because these strings are stored in the `.rodata` section (read-only data), not in the symbol tables.

```bash
$ strings keygenme_O2_strip | grep -i key
Enter your license key:  
Invalid key format. Expected: XXXX-XXXX-XXXX-XXXX  
```

That is why `strings` remains effective even on binaries without symbols. On the other hand, internal function names (`check_license`, `validate_key`…) will have disappeared. You will only see the names of functions imported from shared libraries (stored in `.dynstr`), such as `strcmp` or `printf`.

### Limits of `strings`

`strings` has important blind spots to keep in mind:

- **Obfuscated strings**: if the developer encrypted or encoded their strings (XOR, Base64, building characters one at a time at runtime), `strings` will not find them. This is a common anti-RE technique.  
- **Strings built dynamically**: a string assembled at runtime by concatenation (`strcat`, `snprintf`) does not exist as a contiguous sequence in the binary.  
- **False positives**: random sequences of machine-code bytes can look like ASCII text. The shorter the minimum length (under 6-7 characters), the more noise you get.  
- **Non-ASCII encodings**: by default, `strings` only searches for ASCII. UTF-8 multi-byte strings, UTF-16, or other encodings require the `-e` option.

Despite these limitations, `strings` remains one of the most cost-effective tools in terms of effort-to-information ratio. A few seconds of execution can reveal the essentials of a program's behavior.

---

## `xxd` and `hexdump` — inspecting raw content byte by byte

### Why look at raw bytes?

`file` tells you *what* it is. `strings` shows you *the texts* it contains. But sometimes you need to see exactly **what is at a specific position** in the file — a magic number, a header, an opcode sequence, a numeric value encoded in binary, suspicious padding. That is where **hex dumps** come in.

A hex dump displays the file's content as bytes in hexadecimal, accompanied by their ASCII representation. It is the most "raw" view possible of a file, with no structure interpretation.

### `xxd` — a versatile hex dumper

`xxd` ships with `vim` and is available on virtually every system. It produces a readable, compact dump.

```bash
$ xxd keygenme_O0 | head -20
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 c010 0000 0000 0000  ..>.............
00000020: 4000 0000 0000 0000 d839 0000 0000 0000  @........9......
00000030: 0000 0000 4000 3800 0d00 4000 1f00 1e00  ....@.8...@.....
00000040: 0600 0000 0400 0000 4000 0000 0000 0000  ........@.......
[...]
```

Each line has three parts:

- **Left column** (`00000000:`): the offset in the file, in hexadecimal. That is the byte's address from the start of the file.  
- **Central part** (`7f45 4c46 0201 0100...`): the bytes in hexadecimal, grouped in pairs. Each pair represents one byte (two hex digits = 8 bits = values from `00` to `ff`).  
- **Right column** (`.ELF............`): the ASCII representation of the same bytes. Non-printable bytes are shown as a dot `.`.

On the first line, we immediately recognize the **ELF magic number**: `7f 45 4c 46`. The `7f` is the DEL character (non-printable, shown as `.`), followed by the ASCII codes for `E` (`45`), `L` (`4c`), and `F` (`46`).

### Essential `xxd` options

```bash
# Limit the amount of data shown (here: 64 bytes)
$ xxd -l 64 keygenme_O0

# Start at a specific offset (here: from byte 0x2048)
# Useful when strings -t x gave you the offset of an interesting string
$ xxd -s 0x2048 -l 64 keygenme_O0

# Display bytes individually instead of in groups of 2
$ xxd -g 1 -l 32 keygenme_O0
00000000: 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010: 03 00 3e 00 01 00 00 00 c0 10 00 00 00 00 00 00  ..>.............

# Display in binary only (useful for bit-level operations)
$ xxd -b -l 8 keygenme_O0
00000000: 01111111 01000101 01001100 01000110 00000010 00000001 00000001 00000000  .ELF....

# "Plain" mode: only hex bytes, no offset or ASCII
# Useful for scripting and piping
$ xxd -p -l 16 keygenme_O0
7f454c4602010100000000000000000
```

### Combining `strings -t x` and `xxd`: a common workflow

Suppose `strings -t x` revealed a suspicious string at offset `0x2048`. We can examine it in context with `xxd`:

```bash
# 1. Spot the string with strings
$ strings -t x keygenme_O0 | grep "SuperSecret"
  20a5 SuperSecret123

# 2. Examine the bytes around that position
$ xxd -s 0x2090 -l 48 keygenme_O0
000020a0: 0053 7570 6572 5365 6372 6574 3132 3300  .SuperSecret123.
000020b0: 4163 6365 7373 2067 7261 6e74 6564 2120  Access granted! 
```

This workflow — spot with `strings`, locate with `xxd` — is a fundamental reflex. The offset will then let you find cross-references in Ghidra or IDA (Chapter 8) to identify which code uses that string.

### `hexdump` — an alternative with flexible formatting

`hexdump` is another hex-dumping tool, available in the `bsdmainutils` (or `util-linux` depending on the distribution) package. Its syntax differs from `xxd` and its default output format is less readable, but it offers a very powerful customizable formatting system.

```bash
# Default format (not very readable, 2-byte groups in little-endian)
$ hexdump keygenme_O0 | head -5
0000000 457f 464c 0102 0001 0000 0000 0000 0000
0000010 0003 003e 0001 0000 10c0 0000 0000 0000
[...]
```

> ⚠️ **Beware of the pitfall**: `hexdump`'s default format displays bytes in **little-endian order within 2-byte groups**. On the first line, you read `457f` instead of `7f45`. This is not an error — it is `hexdump` swapping the bytes within each 16-bit group. It is confusing and error-prone. That is why, in RE, we usually prefer `xxd` or `hexdump`'s canonical mode.

```bash
# Canonical mode (-C): same format as xxd, much more readable
$ hexdump -C keygenme_O0 | head -5
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  c0 10 00 00 00 00 00 00  |..>.............|
[...]

# Limit the output and start at an offset
$ hexdump -C -s 0x2048 -n 64 keygenme_O0
```

In practice, `hexdump -C` and `xxd` produce a very similar result. The choice between the two is essentially a matter of personal preference. `xxd` has the advantage of being installed everywhere `vim` is present, and its reverse mode (`xxd -r`) lets you convert a hex dump back to a binary file — a useful feature for quick patching.

### Reading the ELF header by hand with `xxd`

To illustrate the power of a hex dump, let's walk through the first bytes of a 64-bit ELF and interpret them manually. This reading relies on the `Elf64_Ehdr` structure defined in the ELF specification (see Chapter 2, section 2.4):

```bash
$ xxd -l 64 -g 1 keygenme_O0
00000000: 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010: 03 00 3e 00 01 00 00 00 c0 10 00 00 00 00 00 00  ..>.............
00000020: 40 00 00 00 00 00 00 00 d8 39 00 00 00 00 00 00  @........9......
00000030: 00 00 00 00 40 00 38 00 0d 00 40 00 1f 00 1e 00  ....@.8...@.....
```

| Offset | Bytes | Field | Interpretation |  
|---|---|---|---|  
| `0x00` | `7f 45 4c 46` | `e_ident[EI_MAG]` | Magic number: `\x7fELF` |  
| `0x04` | `02` | `e_ident[EI_CLASS]` | Class 2 = 64-bit ELF |  
| `0x05` | `01` | `e_ident[EI_DATA]` | Data 1 = little-endian (LSB) |  
| `0x06` | `01` | `e_ident[EI_VERSION]` | ELF version = 1 (current) |  
| `0x07` | `00` | `e_ident[EI_OSABI]` | OS/ABI = ELFOSABI_NONE (System V) |  
| `0x10` | `03 00` | `e_type` | Type 3 = `ET_DYN` (shared object / PIE executable) |  
| `0x12` | `3e 00` | `e_machine` | Machine `0x3e` = 62 = EM_X86_64 |  
| `0x18` | `c0 10 00 00 00 00 00 00` | `e_entry` | Entry point = `0x10c0` |  
| `0x20` | `40 00 00 00 00 00 00 00` | `e_phoff` | Program header table offset = `0x40` (64 bytes) |  
| `0x34` | `38 00` | `e_phentsize` | Program header entry size = 56 bytes |  
| `0x36` | `0d 00` | `e_phnum` | Number of program headers = 13 |

> 💡 **Reminder**: in little-endian, bytes are read "backward". `03 00` at offset `0x10` reads as the value `0x0003` = 3. Similarly, `c0 10 00 00 00 00 00 00` at offset `0x18` reads as `0x00000000000010c0` = `0x10c0`.

This ability to read a header directly in raw bytes may seem tedious — and it is. That is exactly why tools like `readelf` (section 5.2) and ImHex (Chapter 6) exist. But understanding the link between raw bytes and the structures they represent is a fundamental RE skill. When an automatic tool fails or produces a suspicious result, going back to the bytes is how you find the truth.

---

## Summary: when to use which tool

| Tool | Question it answers | Runtime | Complexity |  
|---|---|---|---|  
| `file` | What type of file is it? Which architecture? Stripped or not? | < 1 second | None |  
| `strings` | Which readable texts does this binary contain? | < 1 second | None |  
| `strings -t x` + `grep` | Where is this specific string in the file? | < 1 second | Minimal |  
| `xxd` / `hexdump -C` | What do the bytes at this position contain? | Instant | Requires knowledge of structures |

These three tools are always the **first step** — before `readelf`, before `objdump`, before Ghidra. They form the foundation of the quick triage workflow that we will formalize in section 5.7.

---

## What to remember going forward

- **Always start with `file`**. It is reflex number one. It will keep you from opening an ARM binary in an x86 disassembler, or treating a Python script as a native executable.  
- **`strings` is your best ally on stripped binaries**. When symbols are gone, data strings remain. A single error message can be enough to identify a function or an execution path.  
- **`strings -t x` + `xxd`** form a location duo. Spot an interesting string, note its offset, then examine the surrounding bytes. These offsets will serve as entry points into more advanced analysis tools.  
- **The hex dump is the absolute truth**. When a tool gives you a surprising result, check the raw bytes. No abstraction layer can lie about the file's actual content.

---


⏭️ [`readelf` and `objdump` — anatomy of an ELF (headers, sections, segments)](/05-basic-inspection-tools/02-readelf-objdump.md)
