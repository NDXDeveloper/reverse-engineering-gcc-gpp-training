🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 5.2 — `readelf` and `objdump` — anatomy of an ELF (headers, sections, segments)

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

In the previous section, `file` told us our binary was a 64-bit x86-64 ELF, and `xxd` let us manually read the first bytes of the header. But parsing an ELF by hand, byte by byte, would be an unreasonable exercise in patience. That is where `readelf` and `objdump` come in — two tools from the GNU Binutils that know how to **parse an ELF's internal structure** and present its content in a readable way.

These two tools overlap partially, but have different philosophies:

- **`readelf`** is a **structural dissection** tool. It displays headers, sections, segments, symbol tables, relocations, notes, DWARF information — in short, all the **metadata** of an ELF. It does not disassemble code.  
- **`objdump`** is a more versatile tool that can **both** display ELF metadata and **disassemble** machine code. Its disassembly side will be covered in depth in Chapter 7; here, we focus on its structural inspection capabilities, as a complement to `readelf`.

Before diving into the commands, let's briefly recall the architecture of an ELF file, introduced in Chapter 2.

---

## Reminder: the dual view of an ELF file

An ELF file can be read from two complementary perspectives, each serving a different purpose:

**The "linking" view (sections)** is used by the linker (`ld`) at compile time. It splits the file into named **sections** (`.text`, `.data`, `.rodata`, `.bss`, `.symtab`, `.strtab`…), each with a precise role. This view is described by the **Section Header Table** (SHT), located at the end of the file.

**The "execution" view (segments)** is used by the loader (`ld.so`) when the file is loaded into memory. It groups sections into **segments** (also called *program headers*) that define the regions to map into memory with their permissions (read, write, execute). This view is described by the **Program Header Table** (PHT), located right after the ELF header.

A segment generally contains several sections. For example, a `LOAD` segment with `R+X` permissions (readable and executable) will typically contain the `.text`, `.plt`, `.init`, and `.fini` sections. A `LOAD` segment with `R+W` permissions (readable and writable) will contain `.data`, `.bss`, and `.got`.

The **ELF header** is the absolute starting point. Located in the first 64 bytes of the file (in 64-bit ELF), it contains fundamental information and offsets to the two header tables (PHT and SHT).

`readelf` and `objdump` let you explore these three levels: ELF header, program headers (segments), and section headers (sections).

---

## `readelf` — the scalpel of ELF analysis

`readelf` is part of the GNU Binutils. Unlike `objdump`, it does not depend on the BFD (*Binary File Descriptor*) library and parses the ELF format directly. This makes it more reliable on malformed or non-standard ELFs.

### The ELF header: `-h`

```bash
$ readelf -h keygenme_O0
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x10c0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14808 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

This is exactly the information we extracted manually with `xxd` in section 5.1, but presented readably. Let's review the most important fields for RE:

**`Entry point address: 0x10c0`** — this is the address of the first instruction executed by the program. On a GCC-compiled binary, this is **not** `main()`. It is `_start`, a small stub provided by the libc (via `crt1.o`) that initializes the environment, then calls `__libc_start_main`, which in turn calls `main()`. Knowing the entry point lets you set an initial breakpoint in GDB even before you have identified `main`.

**`Type: DYN`** — the `DYN` type (shared object) is used both for shared `.so` libraries and PIE executables. The distinction comes from the presence of a non-zero entry point and an `INTERP` segment. Before GCC 8/9, classic executables had the `EXEC` type; today, `-pie` is enabled by default and the type is `DYN`.

**`Start of program headers: 64`** and **`Start of section headers: 14808`** — file offsets to the two header tables. The PHT starts right after the ELF header (64 bytes = size of the 64-bit ELF header). The SHT is at the end of the file.

**`Number of section headers: 31`** — the binary contains 31 sections. A stripped binary will have far fewer (the `.symtab`, `.strtab`, `.debug_*` sections will be absent).

**`Section header string table index: 30`** — the index of the section that contains the section names themselves (`.shstrtab`). It is thanks to this section that `readelf` can display `.text` instead of "section number 14".

### Sections: `-S`

```bash
$ readelf -S keygenme_O0
There are 31 section headers, starting at offset 0x39d8:

Section Headers:
  [Nr] Name              Type             Address           Offset    Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000  0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000318  00000318  000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.pr[...] NOTE             0000000000000338  00000338  0000000000000030  0000000000000000   A       0     0     8
  [ 3] .note.gnu.bu[...] NOTE             0000000000000368  00000368  0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             000000000000038c  0000038c  0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000000003b0  000003b0  0000000000000024  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000000003d8  000003d8  00000000000000f0  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           00000000000004c8  000004c8  00000000000000ad  0000000000000000   A       0     0     1
  [...]
  [14] .text             PROGBITS         00000000000010c0  000010c0  0000000000000225  0000000000000000  AX       0     0    16
  [15] .fini             PROGBITS         00000000000012e8  000012e8  000000000000000d  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000002000  00002000  00000000000000f5  0000000000000000   A       0     0     8
  [...]
  [23] .data             PROGBITS         0000000000004000  00003000  0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000004010  00003010  0000000000000008  0000000000000000  WA       0     0     1
  [25] .comment          PROGBITS         0000000000000000  00003010  000000000000002c  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00003040  0000000000000408  0000000000000018          27    18     8
  [27] .strtab           STRTAB           0000000000000000  00003448  0000000000000242  0000000000000000           0     0     1
  [...]
```

The output is dense, but each column has a precise meaning:

**`Name`** — the section's name. The sections essential for RE were introduced in Chapter 2 (section 2.4). Let's recall the most important ones:

| Section | Content | Interest for RE |  
|---|---|---|  
| `.text` | Executable machine code | This is where the instructions to disassemble live. |  
| `.rodata` | Read-only data (strings, constants) | The strings found by `strings` live mostly here. |  
| `.data` | Initialized global and static variables | May contain keys, lookup tables, configurations. |  
| `.bss` | Uninitialized global variables | Reserved in memory but takes no space in the file. |  
| `.plt` / `.got` | Procedure Linkage Table / Global Offset Table | Mechanism for resolving calls to shared-library functions (see Chapter 2, section 2.9). |  
| `.symtab` | Full symbol table | Names of all functions and variables — disappears after `strip`. |  
| `.dynsym` | Dynamic symbol table | Names of imported/exported functions — survives `strip`. |  
| `.dynstr` | Dynamic string table | Names referenced by `.dynsym`. |  
| `.strtab` | Symbol string table | Names referenced by `.symtab` — disappears after `strip`. |  
| `.comment` | Compiler comments | Contains the GCC version (the one `strings` had found). |

**`Type`** — the type of the section. `PROGBITS` means the section contains data defined by the program (code or data). `NOBITS` means the section occupies memory space but no file space (typical of `.bss`). `DYNSYM` and `SYMTAB` are symbol tables. `STRTAB` is a string table.

**`Address`** — the virtual address at which the section will be loaded into memory. For a PIE binary, these addresses are relative and will be shifted by ASLR at load time.

**`Offset`** — the section's position in the on-disk file. It is this offset you would use with `xxd -s` to examine the raw content of the section.

**`Size`** — the section's size in bytes.

**`Flags`** — the section's attributes. The most common flags are:

| Flag | Meaning |  
|---|---|  
| `A` | **Alloc** — the section occupies memory space at runtime. |  
| `X` | **eXecute** — the section contains executable code. |  
| `W` | **Write** — the section is writable in memory. |  
| `S` | **Strings** — the section contains null-terminated strings. |  
| `M` | **Merge** — the section can be merged to remove duplicates. |

The combination of flags reveals the section's nature. `AX` (alloc + execute) = executable code (`.text`). `A` alone = read-only data (`.rodata`). `WA` (write + alloc) = writable data (`.data`, `.bss`, `.got`).

### Comparing the sections of a normal binary and a stripped binary

```bash
$ readelf -S keygenme_O0 | grep -c '\['
32
$ readelf -S keygenme_O2_strip | grep -c '\['
29
```

The stripped binary has fewer sections. The removed sections are mainly `.symtab` and `.strtab` — the non-dynamic symbol tables. We can confirm:

```bash
$ readelf -S keygenme_O0 | grep -E '\.symtab|\.strtab'
  [26] .symtab           SYMTAB           [...]
  [27] .strtab           STRTAB           [...]

$ readelf -S keygenme_O2_strip | grep -E '\.symtab|\.strtab'
(no result)
```

This is the structural confirmation of what `file` told us with `stripped` vs `not stripped`. On the other hand, `.dynsym` and `.dynstr` are still present, because they are needed at runtime for the resolution of shared libraries. That is why, even on a stripped binary, you can still see the names of imported functions like `printf` or `strcmp`.

### Segments (program headers): `-l`

```bash
$ readelf -l keygenme_O0

Elf file type is DYN (Position-Independent Executable file)  
Entry point 0x10c0  
There are 13 program headers, starting at offset 64  

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000000628 0x0000000000000628  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000 0x00000000000002f5 0x00000000000002f5  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000 0x0000000000000174 0x0000000000000174  R      0x1000
  LOAD           0x0000000000002db8 0x0000000000003db8 0x0000000000003db8 0x0000000000000258 0x0000000000000260  RW     0x1000
  DYNAMIC        0x0000000000002dc8 0x0000000000003dc8 0x0000000000003dc8 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000338 0x0000000000000338 0x0000000000000338 0x0000000000000030 0x0000000000000030  R      0x8
  [...]
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002db8 0x0000000000003db8 0x0000000000003db8 0x0000000000000248 0x0000000000000248  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
   03     .init .plt .plt.got .plt.sec .text .fini
   04     .rodata .eh_frame_hdr .eh_frame
   05     .init_array .fini_array .dynamic .got .data .bss
   06     .dynamic
   [...]
```

The output splits into two parts. The first lists the **program headers** (segments), the second shows the **sections → segments mapping**.

The most important segment types:

**`PHDR`** — describes the program header table itself. Required so the loader knows where to find the other segments.

**`INTERP`** — contains the path of the dynamic loader (`/lib64/ld-linux-x86-64.so.2`). This segment only exists in dynamically linked executables. Its absence would indicate a statically linked binary.

**`LOAD`** — these are the segments actually loaded into memory by the loader. Here the **Flags** column is crucial:

| Flags | Permissions | Typical content |  
|---|---|---|  
| `R` | Read-only | ELF headers, metadata |  
| `R E` | Read + execute | Code (`.text`, `.plt`, `.init`, `.fini`) |  
| `R` (second) | Read-only | Constant data (`.rodata`, `.eh_frame`) |  
| `RW` | Read + write | Modifiable data (`.data`, `.bss`, `.got`) |

Notice that no segment is both writable **and** executable (`RWE`). This is the **NX** (No-eXecute) protection in action: code is not modifiable, data is not executable. This separation considerably complicates the exploitation of vulnerabilities like buffer overflows (see Chapter 19).

**`DYNAMIC`** — contains the `dynamic` structure that lists the required shared libraries, the offsets of dynamic symbol tables, relocation information, etc. It is the "table of contents" for the dynamic loader.

**`GNU_STACK`** — indicates the stack permissions. The `RW` flag (no `E`) confirms the stack is not executable, another layer of NX protection.

**`GNU_RELRO`** — marks a memory region that will be made read-only after initial relocations. This is the RELRO (Relocation Read-Only) mechanism. We will come back to it in section 5.6 with `checksec`.

The **sections → segments mapping** at the bottom of the output is particularly instructive. It shows how sections are grouped. Segment 03, with flags `R E`, contains `.init`, `.plt`, `.plt.got`, `.plt.sec`, `.text`, and `.fini` — all executable code. Segment 05, with `RW` flags, contains `.init_array`, `.fini_array`, `.dynamic`, `.got`, `.data`, and `.bss` — all writable data.

### Dynamic information: `-d`

```bash
$ readelf -d keygenme_O0

Dynamic section at offset 0x2dc8 contains 27 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x1000
 0x000000000000000d (FINI)               0x12e8
 0x0000000000000019 (INIT_ARRAY)         0x3db8
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x3dc0
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x3b0
 0x0000000000000005 (STRTAB)             0x4c8
 0x0000000000000006 (SYMTAB)             0x3d8
 0x000000000000000a (STRSZ)              173 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x3fb8
 0x0000000000000002 (PLTRELSZ)           72 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x5d8
 [...]
 0x000000006ffffff0 (VERSYM)             0x576
 0x000000006ffffffe (VERNEED)            0x598
 0x000000006fffffff (VERNEEDNUM)         1
 0x0000000000000000 (NULL)               0x0
```

The most important entry here is **`NEEDED`**: it indicates the binary depends on `libc.so.6`. That is the standard C library. A binary with many `NEEDED` entries uses several shared libraries — each one is a clue about the program's functionality (network, crypto, GUI, etc.).

The `PLTGOT`, `JMPREL`, and `PLTRELSZ` entries give the addresses and sizes of the PLT/GOT tables, essential for understanding the dynamic resolution mechanism (Chapter 2, section 2.9).

### ELF notes: `-n`

```bash
$ readelf -n keygenme_O0

Displaying notes found in: .note.gnu.property
  Owner                Data size    Description
  GNU                  0x00000020   NT_GNU_PROPERTY_TYPE_0
      Properties: x86 feature: IBT, SHSTK

Displaying notes found in: .note.gnu.build-id
  Owner                Data size    Description
  GNU                  0x00000014   NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: a3f5...c4e2

Displaying notes found in: .note.ABI-tag
  Owner                Data size    Description
  GNU                  0x00000010   NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0
```

Notes contain useful metadata. The **Build ID** is a unique hash identifying this precise build — it lets you retrieve the corresponding debug symbols from a debug-symbol server. The **x86 properties** (`IBT`, `SHSTK`) indicate the binary was compiled with support for Intel CET (Control-flow Enforcement Technology), a hardware protection against ROP attacks.

### Summary of essential `readelf` options

| Option | Displays | Typical usage |  
|---|---|---|  
| `-h` | ELF header | Architecture, type, entry point, header sizes |  
| `-S` | Section headers | List of sections, their flags, offsets, and sizes |  
| `-l` | Program headers (segments) | Memory mapping, permissions, loader's view |  
| `-s` | Symbol tables | Function and variable names (see section 5.3) |  
| `-d` | `.dynamic` section | Dependencies, PLT/GOT addresses |  
| `-r` | Relocations | Relocation entries (helpful to understand PLT/GOT) |  
| `-n` | Notes | Build ID, ABI tag, hardware properties |  
| `-a` | Everything | Equivalent of all options combined |  
| `-W` | Wide mode | Prevents truncation of long lines |  
| `-x <section>` | Hex dump of a section | Examine the raw content of a specific section |

The `-W` option deserves special mention: without it, `readelf` truncates long lines to fit an 80-column terminal, which makes the output unreadable on 64-bit address fields. Get into the habit of always using `-W`:

```bash
$ readelf -SW keygenme_O0
```

### Dumping a section's raw content

`readelf -x` lets you dump a specific section in hexadecimal, a targeted alternative to `xxd`:

```bash
$ readelf -x .rodata keygenme_O0

Hex dump of section '.rodata':
  0x00002000 01000200 00000000 456e7465 7220796f ........Enter yo
  0x00002010 7572206c 6963656e 7365206b 65793a20 ur license key:
  0x00002020 00496e76 616c6964 206b6579 20666f72 .Invalid key for
  0x00002030 6d61742e 20457870 65637465 643a2058 mat. Expected: X
  [...]
```

We find in `.rodata` the strings that `strings` had detected. This time, we see them **in their structural context** — they belong to the read-only data section, which confirms they are compiled-in constants, not random artifacts.

---

## `objdump` — the complementary perspective

`objdump` can display a large part of the information `readelf` provides, but with sometimes different presentation and granularity. Its strong point is **disassembly** (Chapter 7), but its structural-inspection capabilities are worth knowing.

### File headers: `-f`

```bash
$ objdump -f keygenme_O0

keygenme_O0:     file format elf64-x86-64  
architecture: i386:x86-64, flags 0x00000150:  
HAS_SYMS, DYNAMIC, D_PAGED  
start address 0x00000000000010c0  
```

The output is more compact than `readelf -h`. The key information is in the **BFD flags**:

- `HAS_SYMS` — the binary contains symbols (it is not stripped).  
- `DYNAMIC` — the binary is dynamically linked.  
- `D_PAGED` — the binary uses memory paging (standard for executables).

On a stripped binary, `HAS_SYMS` will be replaced by its absence, which confirms the symbols have been lost.

### Section headers: `-h`

```bash
$ objdump -h keygenme_O0

keygenme_O0:     file format elf64-x86-64

Sections:  
Idx Name          Size      VMA               LMA               File off  Algn  
  0 .interp       0000001c  0000000000000318  0000000000000318  00000318  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  [...]
 13 .text         00000225  00000000000010c0  00000000000010c0  000010c0  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
 15 .rodata       000000f5  0000000000002000  0000000000002000  00002000  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 [...]
 22 .data         00000010  0000000000004000  0000000000004000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .bss          00000008  0000000000004010  0000000000004010  00003010  2**0
                  ALLOC
```

Compared to `readelf -S`, `objdump -h` presents attributes as descriptive keywords instead of single-letter flags. `CONTENTS, ALLOC, LOAD, READONLY, CODE` is more readable than `AX` once you know the correspondence. That said, `readelf -S` shows additional fields (like `EntSize`, `Link`, `Info`) that can be useful for in-depth analysis of symbol and relocation tables.

### Content of a section: `-s -j`

```bash
$ objdump -s -j .rodata keygenme_O0

keygenme_O0:     file format elf64-x86-64

Contents of section .rodata:
 2000 01000200 00000000 456e7465 7220796f  ........Enter yo
 2010 7572206c 6963656e 7365206b 65793a20  ur license key:
 [...]
```

Functionally equivalent to `readelf -x .rodata`, with a slightly different output format. The `-j` option selects the section, `-s` enables dump mode.

### Private (ELF-specific) headers: `-p`

```bash
$ objdump -p keygenme_O0
```

This command displays program headers and the `.dynamic` section — a mix of `readelf -l` and `readelf -d`. The information is the same, but the format differs. In practice, `readelf` is usually preferred for pure structural inspection, because its output is more easily parsable and more detailed.

---

## `readelf` vs `objdump`: when to use which?

The two tools overlap heavily, and the choice is sometimes a matter of preference. Here are a few guiding principles:

**Prefer `readelf`** for pure structural inspection: headers, sections, segments, symbol tables, relocations, notes, DWARF information. Its output is more complete, more predictable, and does not depend on the BFD library. It handles malformed or non-standard ELFs better — an important advantage for malware analysis.

**Prefer `objdump`** when you need to **disassemble** code (Chapter 7) or when you want a quick, compact view of the headers (`-f`). `objdump` is also the tool of choice for comparing assembly listings between different optimization levels, thanks to its disassembly formatting options.

**Use both** when a tool gives an ambiguous result. Having two independent sources that parse the same file with different implementations strengthens confidence in the results. On an intentionally malformed ELF (an anti-RE technique, see Chapter 19), divergences between `readelf` and `objdump` are themselves a source of information.

---

## Quick reading: the reflexes to adopt

In practice, during a triage (section 5.7), you do not run every `readelf` option in sequence. Here are the commands the reverse engineer launches as a priority, and in which order:

```bash
# 1. Quick overview: type, architecture, entry point
$ readelf -h keygenme_O0

# 2. Section list: is the binary stripped?
#    Are there unusual sections?
$ readelf -SW keygenme_O0

# 3. Dependencies: which libraries are linked?
$ readelf -d keygenme_O0 | grep NEEDED

# 4. Segments: what memory permissions?
#    Is NX active? (no RWE segment)
$ readelf -lW keygenme_O0

# 5. If not stripped: symbols (section 5.3)
$ readelf -s keygenme_O0
```

This sequence takes less than 30 seconds and provides a complete structural portrait of the binary. Combined with the results of `file` and `strings` (section 5.1), it constitutes the majority of first-level static triage.

---

## What to remember going forward

- **`readelf -h`** is your first reflex after `file`. It confirms and details the base information: entry point, binary type, number of sections.  
- **`readelf -S`** reveals the internal structure of the binary. The presence or absence of `.symtab` confirms whether the binary is stripped. Non-standard section names may indicate a packer or obfuscator.  
- **`readelf -l`** shows how the binary will be loaded into memory. The segment permissions (`R`, `RE`, `RW`) are directly tied to security protections (NX, RELRO).  
- **`readelf -d | grep NEEDED`** lists the required shared libraries — each entry is a functional clue (network? crypto? GUI?).  
- **`objdump`** complements `readelf` and excels at disassembly, which we will cover in Chapter 7.  
- The distinction between **sections** (linking view) and **segments** (execution view) is fundamental to understanding how the on-disk code becomes an in-memory process.

---


⏭️ [`nm` and `objdump -t` — inspecting symbol tables](/05-basic-inspection-tools/03-nm-symbols.md)
