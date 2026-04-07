🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.4 — Writing a pattern to visualize an ELF header from scratch

> 🎯 **Goal of this section**: Build, step by step, a `.hexpat` pattern that parses the main header of a 64-bit ELF file, the Program Headers, and the Section Headers, drawing on the ELF specification and Chapter 2's concepts. The final pattern will be reusable in later chapters.

> 📁 **File produced**: `hexpat/elf_header.hexpat`  
> 📦 **Test binary**: any 64-bit ELF from `binaries/` — for example `binaries/ch21-keygenme/keygenme_O0`

---

## Why build this pattern by hand?

ImHex already provides an ELF pattern in its Content Store. So why write one ourselves? For three reasons.

First, the ELF format is an **ideal training ground** for the `.hexpat` language. It contains varied primitive types (8- to 64-bit integers), enumerations (file type, architecture, endianness), dynamic-size arrays (Program Headers, Section Headers), and pointers to other regions of the file (section offsets, string table). It is a condensed form of everything we saw in section 6.3.

Second, writing the pattern forces us to **re-read the ELF specification** with fresh eyes. In Chapter 2, we looked at ELF sections from the angle of their role (`.text` for code, `.data` for data…). Here, we look at them from the angle of their **binary encoding** — which bytes, at which offsets, with which endianness. This is exactly the perspective shift RE demands.

Third, the pattern we will produce will be **tailored to our needs**. The Content Store pattern is generic and covers every case (32- and 64-bit ELF, every architecture). Ours will target the x86-64 64-bit ELFs we manipulate in this training, with English comments and formatting attributes adapted to our workflow.

---

## Reminder: structure of a 64-bit ELF file

Before writing a single line of `.hexpat`, let's recall the general organization of an ELF file as seen in Chapter 2. An ELF is composed of three layers of metadata:

**The ELF Header** (`Elf64_Ehdr`) — 64 fixed bytes at offset 0 of the file. It is the entry point: it identifies the file as ELF, specifies the architecture, endianness, type (executable, shared object, relocatable…), and contains the offsets to the following two tables.

**The Program Header Table** — an array of `Elf64_Phdr` (56 bytes each) describing the **segments** the loader (`ld.so`) must load into memory. The offset of this table and the number of entries are given by the ELF Header.

**The Section Header Table** — an array of `Elf64_Shdr` (64 bytes each) describing the **sections** of the file (`.text`, `.data`, `.rodata`, `.bss`, etc.). Again, the offset and the number of entries come from the ELF Header.

Our pattern will parse these three layers in this order, following the chain of pointers from the ELF Header to the two tables.

---

## Step 1: the magic number and identification

Open an ELF file in ImHex and look at the first 16 bytes at offset `0x00`. This block is called `e_ident` — the ELF identification field. It is a 16-byte array containing the magic number and the fundamental parameters of the file.

Start our pattern with this block:

```cpp
#include <std/io.pat>

// === e_ident: the first 16 bytes ===

enum EI_CLASS : u8 {
    ELFCLASSNONE = 0,
    ELFCLASS32   = 1,    // 32-bit ELF
    ELFCLASS64   = 2     // 64-bit ELF
};

enum EI_DATA : u8 {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1,     // Little-endian
    ELFDATA2MSB = 2      // Big-endian
};

enum EI_OSABI : u8 {
    ELFOSABI_NONE    = 0x00,   // UNIX System V
    ELFOSABI_HPUX    = 0x01,
    ELFOSABI_NETBSD  = 0x02,
    ELFOSABI_GNU     = 0x03,   // alias ELFOSABI_LINUX
    ELFOSABI_SOLARIS = 0x06,
    ELFOSABI_FREEBSD = 0x09
};

struct ElfIdent {
    char     magic[4]         [[comment("Must equal 0x7f 'E' 'L' 'F'")]];
    EI_CLASS file_class       [[comment("32 or 64 bits")]];
    EI_DATA  data_encoding    [[comment("Endianness")]];
    u8       version          [[comment("Always 1 for EV_CURRENT")]];
    EI_OSABI os_abi           [[comment("Target OS/ABI")]];
    u8       abi_version;
    padding[7]                [[comment("Reserved padding bytes")]];
};
```

A few points to note.

The magic number is declared as `char[4]` rather than `u32`. That is a deliberate choice: the 4 bytes `7f 45 4c 46` are better read as the characters `\x7f`, `E`, `L`, `F` than as an integer. ImHex will display the string in the tree, which is immediately readable.

The fields `file_class` and `data_encoding` use enums typed on `u8`. In the Pattern Data tree, instead of seeing `2` and `1`, you will see `ELFCLASS64` and `ELFDATA2LSB` — a considerable readability gain.

The last 7 bytes of `e_ident` are padding reserved by the specification. We use `padding[7]` to cleanly skip them without cluttering the tree.

Evaluate this pattern with `F5`. You should see an expandable `ElfIdent` node in Pattern Data, with each field named and interpreted. In the hex view, the first 16 bytes are colorized. That is a good start.

---

## Step 2: the full ELF Header (`Elf64_Ehdr`)

The following 48 bytes (offsets `0x10` to `0x3F`) form the rest of the ELF Header. They specify the file type, architecture, entry point, and pointers to the header tables. Add the necessary enums then the complete structure:

```cpp
enum ET_Type : u16 {
    ET_NONE   = 0x0000,   // None
    ET_REL    = 0x0001,   // Relocatable (.o)
    ET_EXEC   = 0x0002,   // Executable
    ET_DYN    = 0x0003,   // Shared object (.so) or PIE
    ET_CORE   = 0x0004    // Core dump
};

enum EM_Machine : u16 {
    EM_NONE    = 0,
    EM_386     = 3,       // Intel 80386
    EM_ARM     = 40,      // ARM
    EM_X86_64  = 62,      // AMD x86-64
    EM_AARCH64 = 183,     // ARM AARCH64
    EM_RISCV   = 243      // RISC-V
};

struct Elf64_Ehdr {
    ElfIdent  e_ident                [[comment("ELF identification (16 bytes)")]];
    ET_Type   e_type                 [[comment("ELF file type")]];
    EM_Machine e_machine             [[comment("Target architecture")]];
    u32       e_version              [[comment("ELF version (1 = current)")]];
    u64       e_entry                [[format("hex"), comment("Entry point (virtual address)")]];
    u64       e_phoff                [[format("hex"), comment("Program Header Table offset")]];
    u64       e_shoff                [[format("hex"), comment("Section Header Table offset")]];
    u32       e_flags                [[format("hex"), comment("Processor-specific flags")]];
    u16       e_ehsize               [[comment("Size of this header (64 bytes for ELF64)")]];
    u16       e_phentsize            [[comment("Size of a Program Header entry")]];
    u16       e_phnum                [[comment("Number of Program Header entries")]];
    u16       e_shentsize            [[comment("Size of a Section Header entry")]];
    u16       e_shnum                [[comment("Number of Section Header entries")]];
    u16       e_shstrndx             [[comment("Index of .shstrtab section")]];
};

Elf64_Ehdr elf_header @ 0x00;
```

Evaluate again. The tree now shows the entire ELF Header over the first 64 bytes. Let's check a few values by comparing with the output of `readelf`:

```bash
readelf -h binaries/ch21-keygenme/keygenme_O0
```

The `e_entry` field in ImHex should match `readelf`'s "Entry point address". The `e_phoff` field should match "Start of program headers". The `e_shoff` field should match "Start of section headers". If the values match, your pattern is correct.

Note the use of `[[format("hex")]]` on address and offset fields. Without this attribute, ImHex would display these values in decimal, which is unnatural for memory addresses and file offsets. In hexadecimal, an address like `0x401040` is immediately recognizable.

---

## Step 3: the Program Header Table (`Elf64_Phdr`)

The ELF Header gives us the offset of the Program Header Table (`e_phoff`) and the number of entries (`e_phnum`). We can now parse this table. Each entry is an `Elf64_Phdr` of 56 bytes:

```cpp
enum PT_Type : u32 {
    PT_NULL    = 0,        // Unused entry
    PT_LOAD    = 1,        // Segment loadable into memory
    PT_DYNAMIC = 2,        // Dynamic linking information
    PT_INTERP  = 3,        // Path to the interpreter (ld.so)
    PT_NOTE    = 4,        // Auxiliary information
    PT_SHLIB   = 5,        // Reserved
    PT_PHDR    = 6,        // Entry for the table itself
    PT_TLS     = 7,        // Thread-Local Storage
    PT_GNU_EH_FRAME = 0x6474E550,
    PT_GNU_STACK    = 0x6474E551,
    PT_GNU_RELRO    = 0x6474E552,
    PT_GNU_PROPERTY = 0x6474E553
};

bitfield PF_Flags {
    execute : 1;
    write   : 1;
    read    : 1;
    padding : 29;
};

struct Elf64_Phdr {
    PT_Type   p_type     [[comment("Segment type")]];
    PF_Flags  p_flags    [[comment("Permissions: RWX")]];
    u64       p_offset   [[format("hex"), comment("Segment offset in the file")]];
    u64       p_vaddr    [[format("hex"), comment("Virtual address in memory")]];
    u64       p_paddr    [[format("hex"), comment("Physical address (often = vaddr)")]];
    u64       p_filesz   [[format("hex"), comment("Segment size in the file")]];
    u64       p_memsz    [[format("hex"), comment("Segment size in memory")]];
    u64       p_align    [[format("hex"), comment("Required alignment")]];
};
```

Here we introduce a new construction: the **bitfield**. The `p_flags` field is a 32-bit bitmask where bit 0 indicates execution, bit 1 write, and bit 2 read. Rather than declaring a simple `u32` and leaving the reader to mentally decode the mask, the `bitfield` breaks down the bits individually. In the Pattern Data tree, ImHex will display `execute = 1`, `write = 0`, `read = 1` — you immediately see that the segment is `R-X` (readable and executable, not writable), typical of a `.text` segment.

To instantiate the table, we use the offset and the counter read in the ELF Header:

```cpp
Elf64_Phdr program_headers[elf_header.e_phnum] @ elf_header.e_phoff;
```

This line says: "parse `e_phnum` consecutive `Elf64_Phdr` structures, starting at offset `e_phoff` in the file". That is the power of dynamic placement with `@` combined with variable-size arrays — in a single line, we parse the entire Program Header Table.

Evaluate and compare with `readelf -l` (which displays Program Headers). The number of segments, their types, and their permissions must match.

---

## Step 4: the Section Header Table (`Elf64_Shdr`)

Proceed the same way for the Section Header Table. Each entry is an `Elf64_Shdr` of 64 bytes:

```cpp
enum SHT_Type : u32 {
    SHT_NULL          = 0,
    SHT_PROGBITS      = 1,     // Program code or data
    SHT_SYMTAB        = 2,     // Symbol table
    SHT_STRTAB        = 3,     // String table
    SHT_RELA          = 4,     // Relocations with addend
    SHT_HASH          = 5,     // Symbol hash table
    SHT_DYNAMIC       = 6,     // Dynamic linking information
    SHT_NOTE          = 7,     // Notes
    SHT_NOBITS        = 8,     // Section with no data in the file (.bss)
    SHT_REL           = 9,     // Relocations without addend
    SHT_DYNSYM        = 11,    // Dynamic symbol table
    SHT_INIT_ARRAY    = 14,    // Constructor array
    SHT_FINI_ARRAY    = 15,    // Destructor array
    SHT_GNU_HASH      = 0x6FFFFFF6,
    SHT_GNU_VERSYM    = 0x6FFFFFFF,
    SHT_GNU_VERNEED   = 0x6FFFFFFE
};

bitfield SHF_Flags {
    write     : 1;
    alloc     : 1;
    execinstr : 1;
    padding   : 1;
    merge     : 1;
    strings   : 1;
    info_link : 1;
    link_order: 1;
    padding2  : 24;
};

struct Elf64_Shdr {
    u32       sh_name       [[comment("Index in .shstrtab (section name)")]];
    SHT_Type  sh_type       [[comment("Section type")]];
    SHF_Flags sh_flags      [[comment("Flags: Write, Alloc, Exec...")]];
    u64       sh_addr       [[format("hex"), comment("Virtual address if loaded")]];
    u64       sh_offset     [[format("hex"), comment("Offset in the file")]];
    u64       sh_size       [[format("hex"), comment("Section size")]];
    u32       sh_link       [[comment("Linked section index (depends on type)")]];
    u32       sh_info       [[comment("Additional information (depends on type)")]];
    u64       sh_addralign  [[comment("Alignment constraint")]];
    u64       sh_entsize    [[comment("Entry size if the section is a table")]];
};

Elf64_Shdr section_headers[elf_header.e_shnum] @ elf_header.e_shoff;
```

Evaluate and compare with `readelf -S`. The number of sections, their types, and their sizes must match. You will notice that the `sh_name` field shows an integer rather than a readable section name. That is normal: `sh_name` is an **index into the `.shstrtab` string table**, not the name itself. Resolving these names requires following the `e_shstrndx` pointer of the ELF Header to the `.shstrtab` section and reading the string at the indicated offset. That is doable in `.hexpat` with advanced functions, but it exceeds the scope of this introductory section. For now, `readelf -S` remains the best tool for seeing section names — our pattern focuses on the raw binary structure.

---

## The full assembled pattern

Let's regroup everything into a single, coherent file. This is the file you will save in `hexpat/elf_header.hexpat`:

```cpp
// ============================================================
// elf_header.hexpat — 64-bit ELF pattern for ImHex
// Reverse Engineering Training — Chapter 6
// ============================================================

#include <std/io.pat>

// ────────────────────────────────────────────
//  Enums: e_ident
// ────────────────────────────────────────────

enum EI_CLASS : u8 {
    ELFCLASSNONE = 0,
    ELFCLASS32   = 1,
    ELFCLASS64   = 2
};

enum EI_DATA : u8 {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2
};

enum EI_OSABI : u8 {
    ELFOSABI_NONE    = 0x00,
    ELFOSABI_HPUX    = 0x01,
    ELFOSABI_NETBSD  = 0x02,
    ELFOSABI_GNU     = 0x03,
    ELFOSABI_SOLARIS = 0x06,
    ELFOSABI_FREEBSD = 0x09
};

// ────────────────────────────────────────────
//  Enums: ELF Header
// ────────────────────────────────────────────

enum ET_Type : u16 {
    ET_NONE = 0x0000,
    ET_REL  = 0x0001,
    ET_EXEC = 0x0002,
    ET_DYN  = 0x0003,
    ET_CORE = 0x0004
};

enum EM_Machine : u16 {
    EM_NONE    = 0,
    EM_386     = 3,
    EM_ARM     = 40,
    EM_X86_64  = 62,
    EM_AARCH64 = 183,
    EM_RISCV   = 243
};

// ────────────────────────────────────────────
//  Enums & bitfields: Program Headers
// ────────────────────────────────────────────

enum PT_Type : u32 {
    PT_NULL         = 0,
    PT_LOAD         = 1,
    PT_DYNAMIC      = 2,
    PT_INTERP       = 3,
    PT_NOTE         = 4,
    PT_SHLIB        = 5,
    PT_PHDR         = 6,
    PT_TLS          = 7,
    PT_GNU_EH_FRAME = 0x6474E550,
    PT_GNU_STACK    = 0x6474E551,
    PT_GNU_RELRO    = 0x6474E552,
    PT_GNU_PROPERTY = 0x6474E553
};

bitfield PF_Flags {
    execute : 1;
    write   : 1;
    read    : 1;
    padding : 29;
};

// ────────────────────────────────────────────
//  Enums & bitfields: Section Headers
// ────────────────────────────────────────────

enum SHT_Type : u32 {
    SHT_NULL       = 0,
    SHT_PROGBITS   = 1,
    SHT_SYMTAB     = 2,
    SHT_STRTAB     = 3,
    SHT_RELA       = 4,
    SHT_HASH       = 5,
    SHT_DYNAMIC    = 6,
    SHT_NOTE       = 7,
    SHT_NOBITS     = 8,
    SHT_REL        = 9,
    SHT_DYNSYM     = 11,
    SHT_INIT_ARRAY = 14,
    SHT_FINI_ARRAY = 15,
    SHT_GNU_HASH    = 0x6FFFFFF6,
    SHT_GNU_VERSYM  = 0x6FFFFFFF,
    SHT_GNU_VERNEED = 0x6FFFFFFE
};

bitfield SHF_Flags {
    write      : 1;
    alloc      : 1;
    execinstr  : 1;
    padding    : 1;
    merge      : 1;
    strings    : 1;
    info_link  : 1;
    link_order : 1;
    padding2   : 24;
};

// ────────────────────────────────────────────
//  Structures
// ────────────────────────────────────────────

struct ElfIdent {
    char     magic[4]      [[comment("0x7f 'E' 'L' 'F'")]];
    EI_CLASS file_class    [[comment("32 or 64 bits")]];
    EI_DATA  data_encoding [[comment("Endianness")]];
    u8       version       [[comment("EV_CURRENT = 1")]];
    EI_OSABI os_abi;
    u8       abi_version;
    padding[7];
};

struct Elf64_Ehdr {
    ElfIdent   e_ident;
    ET_Type    e_type        [[comment("ELF file type")]];
    EM_Machine e_machine     [[comment("Target architecture")]];
    u32        e_version     [[comment("ELF version")]];
    u64        e_entry       [[format("hex"), comment("Entry point")]];
    u64        e_phoff       [[format("hex"), comment("Program Header Table offset")]];
    u64        e_shoff       [[format("hex"), comment("Section Header Table offset")]];
    u32        e_flags       [[format("hex")]];
    u16        e_ehsize      [[comment("Size of this header")]];
    u16        e_phentsize   [[comment("Size of a Program Header")]];
    u16        e_phnum       [[comment("Number of Program Headers")]];
    u16        e_shentsize   [[comment("Size of a Section Header")]];
    u16        e_shnum       [[comment("Number of Section Headers")]];
    u16        e_shstrndx    [[comment("Index of .shstrtab")]];
};

struct Elf64_Phdr {
    PT_Type  p_type    [[comment("Segment type")]];
    PF_Flags p_flags   [[comment("RWX permissions")]];
    u64      p_offset  [[format("hex"), comment("Offset in the file")]];
    u64      p_vaddr   [[format("hex"), comment("Virtual address")]];
    u64      p_paddr   [[format("hex"), comment("Physical address")]];
    u64      p_filesz  [[format("hex"), comment("Size in the file")]];
    u64      p_memsz   [[format("hex"), comment("Size in memory")]];
    u64      p_align   [[format("hex"), comment("Alignment")]];
};

struct Elf64_Shdr {
    u32       sh_name      [[comment("Index in .shstrtab")]];
    SHT_Type  sh_type      [[comment("Section type")]];
    SHF_Flags sh_flags     [[comment("Flags: W, A, X...")]];
    u64       sh_addr      [[format("hex"), comment("Virtual address")]];
    u64       sh_offset    [[format("hex"), comment("Offset in the file")]];
    u64       sh_size      [[format("hex"), comment("Size")]];
    u32       sh_link;
    u32       sh_info;
    u64       sh_addralign [[comment("Alignment")]];
    u64       sh_entsize   [[comment("Entry size if table")]];
};

// ────────────────────────────────────────────
//  Instantiation on the file
// ────────────────────────────────────────────

Elf64_Ehdr elf_header @ 0x00;

Elf64_Phdr program_headers[elf_header.e_phnum] @ elf_header.e_phoff;

Elf64_Shdr section_headers[elf_header.e_shnum] @ elf_header.e_shoff;
```

Three instantiation lines suffice to parse the entirety of an ELF's structural metadata. The ELF Header is placed at offset 0 (it always is, by specification), then the two tables are placed at the offsets the header itself provides. The whole weighs about 150 lines, comments included.

---

## Cross-checking with `readelf`

Once the pattern is evaluated in ImHex, get in the habit of **systematically verifying** parsed values against a reference tool. This discipline will prevent you from building incorrect patterns that seem to "work" by coincidence.

Here are the three `readelf` commands to run in parallel and the fields to compare:

**ELF Header** — `readelf -h <binary>`:

- "Class" must match `e_ident.file_class`  
- "Type" must match `e_type`  
- "Machine" must match `e_machine`  
- "Entry point address" must match `e_entry`  
- "Number of program headers" must match `e_phnum`  
- "Number of section headers" must match `e_shnum`

**Program Headers** — `readelf -l <binary>`:

- The number of segments must match the size of the `program_headers` array  
- The types (LOAD, DYNAMIC, INTERP…) must match the parsed `p_type`  
- Offsets and sizes must match `p_offset` and `p_filesz`

**Section Headers** — `readelf -S <binary>`:

- The number of sections must match the size of the `section_headers` array  
- The types (PROGBITS, STRTAB, SYMTAB…) must match the parsed `sh_type`  
- Offsets and sizes must match `sh_offset` and `sh_size`

If a value does not match, the problem almost always comes from an **alignment shift** in your pattern — a forgotten field or one of wrong size that shifts all following fields. Go back to the ELF specification and count the bytes.

---

## What we did not parse (and why)

Our pattern covers the three layers of structural metadata of an ELF, but it does not parse the **content** of the sections themselves. We have not, for example, parsed the entries of the symbol table (`.symtab`), relocation entries (`.rela.text`), nor the content of the `.dynamic` section.

That is a deliberate choice. Each of these structures would merit its own development, and some (the symbol table, relocations) are better explored with dedicated tools like `readelf -s` or Ghidra. Our pattern has a precise goal: provide a structured, navigable view of an ELF's **high-level metadata**, the ones that answer the questions "what kind of file is this?", "which segments will be loaded into memory?", and "which sections does it contain?".

To go further, you could enrich this pattern by parsing the `.shstrtab` string table to resolve section names, or by adding conditional structures to parse the content of sections according to their type. The ELF pattern from ImHex's Content Store illustrates these advanced techniques and is a good reference if you want to extend your pattern.

---

## What this construction teaches us about RE

Beyond the pattern itself, this exercise illustrates a fundamental approach of reverse engineering: **following the chain of pointers**. The ELF Header is the entry point. It contains offsets (`e_phoff`, `e_shoff`) and counters (`e_phnum`, `e_shnum`) that point us to the following tables. Each Section Header in turn contains an offset (`sh_offset`) and a size (`sh_size`) that point to the actual content of the section.

This "header → pointer → data → sub-pointer → sub-data" logic is found in practically every binary format. A network protocol has a header with a length field that indicates the payload size. A PE executable has a DOS Header that points to a PE Header that points to Section Headers. A proprietary file format has a magic number followed by a table of contents that points to data blocks.

When you reverse an unknown format in Chapters 23 and 25, you will look for exactly this same schema: identify the entry point, find the pointers, follow the chains. The ELF pattern we just built is a template you can adapt to any format.

---

## Summary

We built a complete `.hexpat` pattern for the 64-bit ELF format in four steps: identification (`e_ident`), ELF Header (`Elf64_Ehdr`), Program Headers (`Elf64_Phdr`), and Section Headers (`Elf64_Shdr`). The pattern uses enums for symbolic values, bitfields for permission masks, `[[format("hex")]]` and `[[comment(...)]]` attributes for readability, and dynamic placement with `@` to follow pointers from the header to the tables. The result is a 150-line file that turns a hexadecimal blob into a navigable, documented map — exactly the kind of tool we will build for every binary format encountered in the rest of this training.

---


⏭️ [Parsing a homemade C/C++ structure directly in the binary](/06-imhex/05-custom-structure-parser.md)
