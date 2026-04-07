🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.3 — Binary formats: ELF (Linux), PE (Windows via MinGW), Mach-O (macOS)

> 🎯 **Goal of this section**: Understand what an executable binary format is, know the three major formats used by desktop systems, and understand why this training focuses on ELF while being able to recognize the others.

---

## What is a binary format?

The machine code produced by the compiler and assembler cannot be delivered "raw" to the operating system. The kernel needs metadata to know *how* to load that code into memory: where executable code starts, where data is located, which libraries are required, what the program's entry point is, which permissions to apply to each memory region, etc.

The **binary format** is the container that wraps machine code and all this metadata in a standardized structure. It is the equivalent of a file format (such as PNG for images or ZIP for archives) but for executable programs.

Each operating system family has adopted its own format:

| Format | Systems | Magic bytes | Specification |  
|---|---|---|---|  
| **ELF** (Executable and Linkable Format) | Linux, BSD, Solaris, Android, PlayStation, Nintendo Switch… | `7f 45 4c 46` (`\x7fELF`) | System V ABI / Linux extensions |  
| **PE** (Portable Executable) | Windows (all versions) | `4d 5a` (`MZ`) | Microsoft PE/COFF specification |  
| **Mach-O** (Mach Object) | macOS, iOS, watchOS, tvOS | `fe ed fa ce` / `fe ed fa cf` / `ca fe ba be` (universal) | Apple Mach-O Reference |

> 💡 **Magic bytes**: the first bytes of a binary file constitute its "magic signature". It is the first thing the kernel checks before attempting to load an executable. It is also the first thing the `file` tool examines (Chapter 5, section 5.1).

## ELF — The format of this training

### Origin and ubiquity

ELF was designed in the early 1990s as part of the System V ABI specification and progressively replaced older formats (a.out, COFF). Today, it is used by almost all Unix-like systems and far beyond: Linux, the BSD variants (FreeBSD, OpenBSD, NetBSD), Solaris/illumos, Android (APKs contain ELF `.so` files for native code), game consoles (PlayStation, Nintendo Switch), and many embedded systems.

### General structure

An ELF file offers **two complementary views** of the same binary content, designed for two different consumers:

**The section view** (*section header table*) is intended for the **linker** and analysis tools (objdump, readelf, Ghidra…). It splits the file into named sections (`.text`, `.data`, `.rodata`, `.bss`, `.plt`, `.got`, etc.), each with a type, flags, and a precise role. This is the view we explored in section 2.2 and will detail in section 2.4.

**The segment view** (*program header table*) is intended for the **loader** (`ld.so`) which loads the program into memory to execute it. It groups sections into contiguous segments with associated memory permissions (read, write, execute). This is the view we will dig into in sections 2.7 and 2.8.

```
                        ELF file
    ┌──────────────────────────────────────────┐
    │              ELF Header                  │ ← Magic, architecture, entry point
    ├──────────────────────────────────────────┤
    │         Program Header Table             │ ← Segment view (for the loader)
    │  ┌────────────────────────────────────┐  │
    │  │  LOAD segment (R-X) ───────────────┼──┼── .text, .rodata, .plt
    │  │  LOAD segment (RW-) ───────────────┼──┼── .data, .bss, .got
    │  │  DYNAMIC segment ──────────────────┼──┼── .dynamic
    │  │  INTERP segment ───────────────────┼──┼── .interp
    │  │  ...                               │  │
    │  └────────────────────────────────────┘  │
    ├──────────────────────────────────────────┤
    │         Section Header Table             │ ← Section view (for the linker / RE)
    │  ┌────────────────────────────────────┐  │
    │  │  .text   .rodata   .data   .bss    │  │
    │  │  .plt    .got      .dynamic        │  │
    │  │  .symtab .strtab   .shstrtab       │  │
    │  │  .eh_frame   .comment   ...        │  │
    │  └────────────────────────────────────┘  │
    └──────────────────────────────────────────┘
```

The sections/segments duality is an important particularity of ELF. A stripped executable may have its *section header table* removed (this is rare but possible, notably in malware) while remaining perfectly executable, because the loader uses only the *program header table*. For the reverse engineer, this means the section view is a **luxury** — valuable when available, but not guaranteed.

### ELF file types

The ELF header contains an `e_type` field that indicates the nature of the file:

| Type | Value | Description | Example |  
|---|---|---|---|  
| `ET_REL` | 1 | Relocatable object file | `hello.o` |  
| `ET_EXEC` | 2 | Fixed-address executable | Binary compiled without `-pie` |  
| `ET_DYN` | 3 | Shared object / PIE | `libc.so.6`, or executable compiled with `-pie` |  
| `ET_CORE` | 4 | Core dump file | Memory dump after a crash |

A point that is often a source of confusion: for several years now, GCC has produced **PIE** (Position-Independent Executable) executables by default, which are technically of type `ET_DYN` — the same type as shared `.so` libraries. This does not mean your program is a library; it simply means the format is the same to enable loading at a randomized address (ASLR, section 2.8). The `file` command distinguishes the two by displaying "shared object" for a `.so` and "pie executable" or "Position-Independent Executable" for a PIE executable.

### Why this training focuses on ELF

The choice of ELF as the central format of this training rests on several converging reasons:

- **Openness of the specification.** The ELF specification is public, free, and well documented. No NDA, no partial documentation.  
- **Native GNU tooling.** The GNU toolchain tools (`readelf`, `objdump`, `nm`, `ld`) are designed for ELF. They are free, open source, and available everywhere.  
- **Rich RE ecosystem.** Ghidra, Radare2, IDA Free, GDB, Frida, angr, AFL++ — all these tools natively support ELF and are often primarily developed for Linux.  
- **Pedagogical coherence.** Working on a single format allows depth rather than a surface overview of three different formats. The concepts (sections, segments, symbols, relocations, dynamic linking) then transfer naturally to the other formats.  
- **Practical relevance.** The vast majority of servers, Docker containers, Android devices, connected objects, and cloud infrastructure run ELF code.

## PE — The Windows format

### Context

The PE (Portable Executable) format is the native format of Windows for executables (`.exe`), dynamic libraries (`.dll`), drivers (`.sys`), and object files (`.obj`). It derives from the COFF (Common Object File Format) format and was introduced with Windows NT in 1993.

The GNU toolchain can produce PE binaries via the **MinGW** (Minimalist GNU for Windows) cross-compiler:

```bash
# Cross-compilation from Linux to Windows
x86_64-w64-mingw32-gcc hello.c -o hello.exe
```

The produced binary is a valid PE, executable under Windows, even though it was compiled on Linux with GCC.

### General structure

A PE file always begins with a **DOS stub** inherited from MS-DOS (the famous `MZ` header), followed by the PE header proper. This historical layered structure is characteristic:

```
    ┌──────────────────────────┐
    │   DOS Header (MZ)        │ ← MS-DOS heritage, contains an offset to the PE header
    │   DOS Stub               │ ← Mini DOS program ("This program cannot be run in DOS mode")
    ├──────────────────────────┤
    │   PE Signature ("PE\0\0")│
    │   COFF Header            │ ← Architecture, number of sections, timestamp
    │   Optional Header        │ ← Entry point, image size, base address, subsystem
    │     Data Directories     │ ← Import Table, Export Table, Resource Table, Relocation Table…
    ├──────────────────────────┤
    │   Section Table          │
    │   .text                  │ ← Executable code
    │   .rdata                 │ ← Read-only data (equivalent of .rodata)
    │   .data                  │ ← Initialized data
    │   .bss                   │ ← Uninitialized data
    │   .idata                 │ ← Import Address Table (functional equivalent of PLT/GOT)
    │   .edata                 │ ← Export Table (for DLLs)
    │   .rsrc                  │ ← Resources (icons, menus, dialogs, version info)
    │   .reloc                 │ ← Relocation table (for ASLR)
    └──────────────────────────┘
```

### Key differences from ELF (RE perspective)

| Aspect | ELF | PE |  
|---|---|---|  
| Magic bytes | `\x7fELF` | `MZ` (DOS) then `PE\0\0` |  
| Dynamic linking | PLT/GOT + `ld.so` | Import Address Table (IAT) + `ntdll.dll` / `kernel32.dll` |  
| Shared libraries | `.so` (shared ELF) | `.dll` (PE with exports) |  
| Symbol resolution | By name via `.dynsym` | By name or by **ordinal** (number) |  
| Embedded resources | No standard mechanism | `.rsrc` section (icons, strings, dialogs…) |  
| Position-independent code | PIE / `-fPIC` | ASLR via `.reloc` + DLL characteristics flag |  
| Debug information | DWARF (embedded or separate) | PDB (separate `.pdb` file) |  
| Two views (sections/segments) | Yes (section headers + program headers) | No — a single section table |

The most notable difference for daily RE is the handling of imports. In ELF, calls to shared libraries go through the PLT/GOT pair (section 2.9). In PE, they go through the **Import Address Table** (IAT): the Windows loader fills a table of function pointers at load time, and the code calls these functions via `call [IAT_entry]` indirections. The principle is similar (a table of addresses filled at runtime) but the mechanics and the data structures differ.

Another important difference: PE **debug information** is not embedded in the binary in the DWARF format. Windows uses separate **PDB** (Program Database) files. In RE on a Windows binary, having the corresponding `.pdb` is a considerable advantage — it is the equivalent of having an ELF binary compiled with `-g`. Without a PDB, you are in the same situation as with a stripped ELF.

### RE tools for PE

If you ever have to analyze a PE binary, the same multi-format tools work: Ghidra, IDA, and Radare2 natively support PE. Tools specific to the Windows world add themselves to the mix: PE-bear, CFF Explorer, x64dbg (debugger), API Monitor, and Process Monitor (Sysinternals). The Python framework `pefile` plays a role similar to `pyelftools` for programmatic analysis.

## Mach-O — The Apple format

### Context

Mach-O (Mach Object) is the native format of the Apple ecosystem: macOS, iOS, watchOS, tvOS, and visionOS. Its name comes from the Mach microkernel that forms the foundation of XNU, the macOS kernel. GCC was long the default compiler on macOS, but Apple moved to **Clang/LLVM** starting in 2012 (Xcode 5). The `gcc` command still exists on macOS, but it is an alias for Clang.

### General structure

Mach-O adopts an architecture based on **load commands** — a sequence of loading instructions that the XNU kernel loader (`dyld`) executes sequentially:

```
    ┌───────────────────────────┐
    │   Mach-O Header           │ ← Magic, CPU type, number of load commands
    ├───────────────────────────┤
    │   Load Commands           │
    │   LC_SEGMENT_64 __TEXT    │ ← Code segment (contains sections __text, __stubs, __cstring…)
    │   LC_SEGMENT_64 __DATA    │ ← Data segment (__data, __bss, __la_symbol_ptr…)
    │   LC_SEGMENT_64 __LINKEDIT│ ← Linking metadata (symbols, relocations, signatures)
    │   LC_DYLD_INFO_ONLY       │ ← Information for the dyld dynamic loader
    │   LC_SYMTAB               │ ← Symbol table
    │   LC_LOAD_DYLIB           │ ← Required dynamic library (one per .dylib)
    │   LC_CODE_SIGNATURE       │ ← Code signature (required on iOS, common on macOS)
    │   ...                     │
    ├───────────────────────────┤
    │   Section Data            │
    │   __TEXT,__text           │ ← Executable code
    │   __TEXT,__cstring        │ ← C strings (equivalent of .rodata)
    │   __TEXT,__stubs          │ ← Dynamic call stubs (equivalent of .plt)
    │   __DATA,__la_symbol_ptr  │ ← Lazy pointers (equivalent of .got.plt)
    │   __DATA,__data           │ ← Initialized data
    │   ...                     │
    └───────────────────────────┘
```

### Notable particularities for RE

**The naming convention** uses double underscores: segments are in uppercase (`__TEXT`, `__DATA`), sections in lowercase (`__text`, `__cstring`). The `segment,section` pair is the canonical reference: `__TEXT,__text` designates the `__text` section within the `__TEXT` segment.

**Universal Binaries** (or *fat binaries*) are an Apple-specific mechanism that allows packaging binaries for several architectures (x86-64 + ARM64, for example) in a single file. The `ca fe ba be` magic bytes identify a fat binary, which contains a header listing the available architectures followed by the individual Mach-O binaries concatenated. With Apple's transition to Apple Silicon (ARM64), universal binaries have become common again.

**Code signing** is ubiquitous in the Apple ecosystem. On iOS, every binary must be signed. On macOS, signing is increasingly required (Gatekeeper, notarization). For RE, this means that a modified (patched) Mach-O binary will no longer pass signature verification — an additional obstacle compared to ELF, where code signing is not a standard mechanism of the format.

**The `dyld` loader** (dynamic link editor) is Apple's equivalent of `ld.so` under Linux. Its operation is similar in principle (symbol resolution, dynamic linking at load time) but the internal mechanisms differ. Apple publishes the `dyld` source code, which is a valuable resource for RE on macOS/iOS.

### RE tools for Mach-O

Ghidra, IDA, and Radare2 natively support Mach-O. Specific tools include `otool` (macOS equivalent of `objdump`/`readelf`), `install_name_tool`, `codesign`, and the `lldb` debugger (the LLVM counterpart to GDB). Hopper Disassembler is a popular commercial tool specialized in macOS/iOS RE. The Python library `lief` supports all three formats (ELF, PE, Mach-O) and allows unified programmatic analysis.

## Synthesis comparison

| Characteristic | ELF | PE | Mach-O |  
|---|---|---|---|  
| **Systems** | Linux, BSD, Android… | Windows | macOS, iOS |  
| **Magic bytes** | `7f 45 4c 46` | `4d 5a` | `fe ed fa ce/cf` or `ca fe ba be` |  
| **Common extensions** | (none), `.so`, `.o` | `.exe`, `.dll`, `.sys`, `.obj` | (none), `.dylib`, `.o`, `.app` |  
| **Executable code** | `.text` | `.text` | `__TEXT,__text` |  
| **Read-only data** | `.rodata` | `.rdata` | `__TEXT,__cstring` |  
| **Initialized data** | `.data` | `.data` | `__DATA,__data` |  
| **Uninitialized data** | `.bss` | `.bss` | `__DATA,__bss` |  
| **Dynamic imports** | PLT + GOT | IAT (Import Address Table) | `__stubs` + `__la_symbol_ptr` |  
| **Debug info** | DWARF (embedded) | PDB (separate file) | DWARF (embedded or separate dSYM) |  
| **Loader** | `ld.so` (`ld-linux-x86-64.so.2`) | `ntdll.dll` | `dyld` |  
| **Multi-architecture** | No (one file = one arch) | No | Yes (Universal / fat binary) |  
| **Code signing** | Optional (rare) | Authenticode (optional) | Mandatory (iOS), common (macOS) |  
| **Native inspection tool** | `readelf`, `objdump` | `dumpbin` (MSVC) | `otool`, `pagestuff` |  
| **Python library** | `pyelftools`, `lief` | `pefile`, `lief` | `macholib`, `lief` |

## Recognizing a format at a glance

In an RE situation, the first step when facing an unknown binary is to identify its format. Three complementary methods:

**The `file` command** analyzes the magic bytes and headers to identify the format, architecture, and other characteristics:

```bash
file hello
# hello: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
#        dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
#        for GNU/Linux 3.2.0, not stripped

file hello.exe
# hello.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections

file hello_macos
# hello_macos: Mach-O 64-bit x86_64 executable
```

**The magic bytes** visible with `xxd` or `hexdump`:

```bash
xxd -l 16 hello
# 00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............

xxd -l 16 hello.exe
# 00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............

xxd -l 16 hello_macos
# 00000000: cffa edfe 0c00 0001 0000 0000 0200 0000  ................
```

**ImHex** (Chapter 6) lets you visualize these headers in a structured way thanks to its `.hexpat` patterns — we will come back to it.

## What this section changes for the rest of the training

Although this training focuses on ELF, the fundamental concepts are cross-cutting. Once you master the code/data/metadata distinction, the dynamic imports mechanism, and the role of debug information on ELF, you can approach a PE or Mach-O binary by looking for the equivalents in the target format. The major tools (Ghidra, IDA, Radare2) abstract away a large part of these format differences and present you with a unified view.

---

> 📖 **Now that we know which container the machine code is delivered in**, let's dive into the details of the ELF sections — the compartments that organize the binary's content and that you will handle daily in static analysis.  
>  
> → 2.4 — Key ELF sections: `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.init`, `.fini`

⏭️ [Key ELF sections: `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.init`, `.fini`](/02-gnu-compilation-chain/04-elf-sections.md)
