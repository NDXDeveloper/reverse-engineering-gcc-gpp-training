// ============================================================
// elf_header.hexpat — 64-bit ELF Pattern for ImHex
// Reverse Engineering Training — Chapter 6
//
// Parses the three layers of structural metadata in a
// 64-bit ELF file:
//   1. ELF Header (Elf64_Ehdr) — 64 bytes at offset 0
//   2. Program Header Table (Elf64_Phdr[]) — segments
//   3. Section Header Table (Elf64_Shdr[]) — sections
//
// Reference: ELF specification (Tool Interface Standard),
//            System V ABI AMD64 Architecture Supplement
//
// Cross-checking:
//   readelf -h <binary>   → compare with elf_header
//   readelf -l <binary>   → compare with program_headers
//   readelf -S <binary>   → compare with section_headers
//
// Limitations:
//   - 64-bit ELF only (no 32-bit ELF support)
//   - Does not parse section contents (.symtab,
//     .strtab, .rela, .dynamic, etc.)
//   - Does not resolve section names (sh_name remains a
//     numeric index into .shstrtab)
// ============================================================

#include <std/io.pat>

// ────────────────────────────────────────────
//  Enums: e_ident (first 16 bytes)
// ────────────────────────────────────────────

enum EI_CLASS : u8 {
    ELFCLASSNONE = 0,        // Invalid
    ELFCLASS32   = 1,        // 32-bit ELF
    ELFCLASS64   = 2         // 64-bit ELF
};

enum EI_DATA : u8 {
    ELFDATANONE = 0,         // Invalid
    ELFDATA2LSB = 1,         // Little-endian
    ELFDATA2MSB = 2          // Big-endian
};

enum EI_OSABI : u8 {
    ELFOSABI_NONE    = 0x00, // UNIX System V (default value)
    ELFOSABI_HPUX    = 0x01, // HP-UX
    ELFOSABI_NETBSD  = 0x02, // NetBSD
    ELFOSABI_GNU     = 0x03, // GNU/Linux (alias ELFOSABI_LINUX)
    ELFOSABI_SOLARIS = 0x06, // Solaris
    ELFOSABI_FREEBSD = 0x09  // FreeBSD
};

// ────────────────────────────────────────────
//  Enums: ELF Header
// ────────────────────────────────────────────

enum ET_Type : u16 {
    ET_NONE = 0x0000,        // No type
    ET_REL  = 0x0001,        // Relocatable file (.o)
    ET_EXEC = 0x0002,        // Executable (fixed addresses)
    ET_DYN  = 0x0003,        // Shared object (.so) or PIE
    ET_CORE = 0x0004         // Core dump
};

enum EM_Machine : u16 {
    EM_NONE    = 0,          // No architecture
    EM_386     = 3,          // Intel 80386
    EM_ARM     = 40,         // ARM
    EM_X86_64  = 62,         // AMD x86-64
    EM_AARCH64 = 183,        // ARM AARCH64
    EM_RISCV   = 243         // RISC-V
};

// ────────────────────────────────────────────
//  Enums: Program Headers (segments)
// ────────────────────────────────────────────

enum PT_Type : u32 {
    PT_NULL         = 0,           // Unused entry
    PT_LOAD         = 1,           // Loadable segment in memory
    PT_DYNAMIC      = 2,           // Dynamic linking information
    PT_INTERP       = 3,           // Path to interpreter (ld.so)
    PT_NOTE         = 4,           // Auxiliary information
    PT_SHLIB        = 5,           // Reserved (unused)
    PT_PHDR         = 6,           // Entry describing the table itself
    PT_TLS          = 7,           // Thread-Local Storage
    PT_GNU_EH_FRAME = 0x6474E550,  // GNU exception frame
    PT_GNU_STACK    = 0x6474E551,  // GNU stack permissions
    PT_GNU_RELRO    = 0x6474E552,  // Read-only after relocation
    PT_GNU_PROPERTY = 0x6474E553   // GNU properties
};

// Segment permissions — 32-bit bitmask.
// Bit 0 = Execute, Bit 1 = Write, Bit 2 = Read.
// Common examples:
//   R-X (5) = executable code (.text)
//   RW- (6) = writable data (.data, .bss)
//   R-- (4) = read-only data (.rodata)
bitfield PF_Flags {
    execute : 1;
    write   : 1;
    read    : 1;
    padding : 29;
};

// ────────────────────────────────────────────
//  Enums: Section Headers (sections)
// ────────────────────────────────────────────

enum SHT_Type : u32 {
    SHT_NULL       = 0,            // Unused entry (index 0)
    SHT_PROGBITS   = 1,            // Program code or data
    SHT_SYMTAB     = 2,            // Symbol table (complete)
    SHT_STRTAB     = 3,            // String table
    SHT_RELA       = 4,            // Relocations with explicit addend
    SHT_HASH       = 5,            // Symbol hash table
    SHT_DYNAMIC    = 6,            // Dynamic linking information
    SHT_NOTE       = 7,            // Notes (build-id, ABI, etc.)
    SHT_NOBITS     = 8,            // Section with no data in file (.bss)
    SHT_REL        = 9,            // Relocations without addend
    SHT_DYNSYM     = 11,           // Dynamic symbol table
    SHT_INIT_ARRAY = 14,           // Array of constructor pointers
    SHT_FINI_ARRAY = 15,           // Array of destructor pointers
    SHT_GNU_HASH    = 0x6FFFFFF6,  // GNU hash table (faster than SHT_HASH)
    SHT_GNU_VERSYM  = 0x6FFFFFFF,  // Version symbols
    SHT_GNU_VERNEED = 0x6FFFFFFE   // Required version dependencies
};

// Section flags — 32-bit bitmask.
// The first three bits are the most common:
//   SHF_WRITE (1)     = writable section in memory
//   SHF_ALLOC (2)     = section loaded in memory at runtime
//   SHF_EXECINSTR (4) = section containing executable code
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
//  Structure: ELF Identification (e_ident)
// ────────────────────────────────────────────
// The first 16 bytes of any ELF file. Contains the
// magic number (7f 45 4c 46 = "\x7fELF"), class (32/64),
// endianness, version and target OS/ABI.

struct ElfIdent {
    char     magic[4]      [[color("FF4444"),
                             comment("ELF Magic: 0x7F 'E' 'L' 'F'")]];
    EI_CLASS file_class    [[comment("Class: ELFCLASS32 (1) or ELFCLASS64 (2)")]];
    EI_DATA  data_encoding [[comment("Endianness: LSB (1) = little, MSB (2) = big")]];
    u8       version       [[comment("ELF version: always EV_CURRENT (1)")]];
    EI_OSABI os_abi        [[comment("Target OS/ABI (NONE = generic System V)")]];
    u8       abi_version   [[comment("ABI version (usually 0)")]];
    padding[7]             [[comment("Reserved padding (EI_PAD, 7 null bytes)")]];
};

// ────────────────────────────────────────────
//  Structure: ELF Header (Elf64_Ehdr)
// ────────────────────────────────────────────
// 64 bytes at file offset 0. Entry point for the
// entire ELF metadata tree.
//
// Fields e_phoff / e_phnum point to the Program
// Header Table (segments). Fields e_shoff / e_shnum
// point to the Section Header Table (sections).

struct Elf64_Ehdr {
    ElfIdent   e_ident     [[comment("ELF identification block (16 bytes)")]];
    ET_Type    e_type      [[comment("ELF file type")]];
    EM_Machine e_machine   [[comment("Target processor architecture")]];
    u32        e_version   [[comment("ELF version (1 = EV_CURRENT)")]];
    u64        e_entry     [[format("hex"),
                             comment("Virtual address of entry point (_start)")]];
    u64        e_phoff     [[format("hex"),
                             comment("File offset of the Program Header Table")]];
    u64        e_shoff     [[format("hex"),
                             comment("File offset of the Section Header Table")]];
    u32        e_flags     [[format("hex"),
                             comment("Processor-specific flags (often 0 on x86-64)")]];
    u16        e_ehsize    [[comment("Size of this ELF header (64 bytes for ELF64)")]];
    u16        e_phentsize [[comment("Size of one Program Header entry (56 bytes)")]];
    u16        e_phnum     [[comment("Number of entries in the Program Header Table")]];
    u16        e_shentsize [[comment("Size of one Section Header entry (64 bytes)")]];
    u16        e_shnum     [[comment("Number of entries in the Section Header Table")]];
    u16        e_shstrndx  [[comment("Section Header index of .shstrtab (section name table)")]];
};

// ────────────────────────────────────────────
//  Structure: Program Header (Elf64_Phdr)
// ────────────────────────────────────────────
// 56 bytes per entry. Describes a segment that the
// loader (ld.so) must load into memory.
//
// Key fields for RE:
//   p_type   — segment type (LOAD, DYNAMIC, INTERP...)
//   p_flags  — RWX permissions
//   p_vaddr  — virtual load address
//   p_offset — segment offset in the file
//   p_filesz — size in file (can be < p_memsz)
//   p_memsz  — size in memory (if > filesz, the delta is .bss)

struct Elf64_Phdr {
    PT_Type  p_type   [[comment("Segment type")]];
    PF_Flags p_flags  [[comment("Permissions: bits R(4) W(2) X(1)")]];
    u64      p_offset [[format("hex"),
                        comment("Offset of segment start in the file")]];
    u64      p_vaddr  [[format("hex"),
                        comment("Virtual load address in memory")]];
    u64      p_paddr  [[format("hex"),
                        comment("Physical address (= vaddr on most systems)")]];
    u64      p_filesz [[format("hex"),
                        comment("Segment size in the file")]];
    u64      p_memsz  [[format("hex"),
                        comment("Segment size in memory (>= filesz)")]];
    u64      p_align  [[format("hex"),
                        comment("Alignment constraint (power of 2)")]];
};

// ────────────────────────────────────────────
//  Structure: Section Header (Elf64_Shdr)
// ────────────────────────────────────────────
// 64 bytes per entry. Describes a section of the ELF file.
//
// Note: the sh_name field is an index (in bytes) into the
// .shstrtab string table, NOT the section name itself.
// To resolve names, one would need to parse .shstrtab and
// read the string at offset sh_name — which this pattern
// does not do (see "Limitations" in the header).
//
// Use `readelf -S` to see resolved names.

struct Elf64_Shdr {
    u32       sh_name      [[comment("Index into .shstrtab (use readelf -S for the name)")]];
    SHT_Type  sh_type      [[comment("Section type")]];
    SHF_Flags sh_flags     [[comment("Flags: W(rite), A(lloc), X(ecinstr)")]];
    u64       sh_addr      [[format("hex"),
                             comment("Virtual address if section is loaded (otherwise 0)")]];
    u64       sh_offset    [[format("hex"),
                             comment("Section offset in the file")]];
    u64       sh_size      [[format("hex"),
                             comment("Section size in bytes")]];
    u32       sh_link      [[comment("Linked section index (semantics depend on type)")]];
    u32       sh_info      [[comment("Additional info (semantics depend on type)")]];
    u64       sh_addralign [[comment("Alignment constraint (0 or 1 = no constraint)")]];
    u64       sh_entsize   [[comment("Entry size if section is a table (otherwise 0)")]];
};

// ────────────────────────────────────────────
//  File instantiation
// ────────────────────────────────────────────
// Three lines are enough to parse all the structural
// metadata of a 64-bit ELF:
//
//   1. The ELF Header is always at offset 0.
//   2. The Program Header Table is at offset e_phoff,
//      with e_phnum entries.
//   3. The Section Header Table is at offset e_shoff,
//      with e_shnum entries.

Elf64_Ehdr elf_header @ 0x00;

Elf64_Phdr program_headers[elf_header.e_phnum] @ elf_header.e_phoff;

Elf64_Shdr section_headers[elf_header.e_shnum] @ elf_header.e_shoff;

// ────────────────────────────────────────────
//  Debug information
// ────────────────────────────────────────────

std::print("=== ELF Header Summary ===");
std::print("  Class       : {}", elf_header.e_ident.file_class);
std::print("  Encoding    : {}", elf_header.e_ident.data_encoding);
std::print("  Type        : {}", elf_header.e_type);
std::print("  Machine     : {}", elf_header.e_machine);
std::print("  Entry point : 0x{:X}", elf_header.e_entry);
std::print("  PH count    : {}", elf_header.e_phnum);
std::print("  SH count    : {}", elf_header.e_shnum);
std::print("  File size   : 0x{:X} ({} bytes)", std::mem::size(), std::mem::size());
