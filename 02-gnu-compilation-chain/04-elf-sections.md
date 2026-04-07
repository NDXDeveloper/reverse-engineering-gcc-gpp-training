🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.4 — Key ELF sections: `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.init`, `.fini`

> 🎯 **Goal of this section**: Know the role of each important section of an ELF binary, know what kind of information to look for in it during an RE analysis, and understand how the linker organizes these sections into segments loadable into memory.

---

## The concept of a section in ELF

In section 2.3, we saw that an ELF file offers two views: the **section** view (for the linker and analysis tools) and the **segment** view (for the loader). Here, we focus on sections — these are the ones you will handle daily in Ghidra, objdump, readelf, or Radare2.

A section is a **contiguous zone of the file** identified by a name, a type, flags, and a size. Each section has a precise role: containing executable code, read-only data, modifiable data, linking metadata, debug information, etc. The name of a section is a convention (nothing technically prevents renaming `.text` into `.mycode`), but the tools and the loader rely on these conventions.

To list the sections of our `hello`:

```bash
readelf -S hello
```

Typical output (simplified — a common dynamic ELF binary contains between 25 and 35 sections):

| Nr | Name | Type | Flags | Summary role |  
|---|---|---|---|---|  
| 0 | *(null)* | NULL | — | Mandatory entry at index 0 |  
| 1 | `.interp` | PROGBITS | A | Path to the dynamic loader |  
| 2 | `.note.gnu.build-id` | NOTE | A | Unique build identifier |  
| 3 | `.gnu.hash` | GNU_HASH | A | Hash table for dynamic symbols |  
| 4 | `.dynsym` | DYNSYM | A | Dynamic symbol table |  
| 5 | `.dynstr` | STRTAB | A | Names of dynamic symbols |  
| 6 | `.rela.dyn` | RELA | A | Relocations for data |  
| 7 | `.rela.plt` | RELA | AI | Relocations for PLT calls |  
| 8 | `.init` | PROGBITS | AX | Initialization code |  
| 9 | `.plt` | PROGBITS | AX | Procedure Linkage Table |  
| 10 | `.text` | PROGBITS | AX | Main executable code |  
| 11 | `.fini` | PROGBITS | AX | Finalization code |  
| 12 | `.rodata` | PROGBITS | A | Read-only data |  
| 13 | `.eh_frame_hdr` | PROGBITS | A | Index of exception frames |  
| 14 | `.eh_frame` | PROGBITS | A | Stack-unwinding information |  
| 15 | `.init_array` | INIT_ARRAY | WA | Pointers to constructors |  
| 16 | `.fini_array` | FINI_ARRAY | WA | Pointers to destructors |  
| 17 | `.dynamic` | DYNAMIC | WA | Information table for the loader |  
| 18 | `.got` | PROGBITS | WA | Global Offset Table (data) |  
| 19 | `.got.plt` | PROGBITS | WA | Global Offset Table (PLT functions) |  
| 20 | `.data` | PROGBITS | WA | Modifiable initialized data |  
| 21 | `.bss` | NOBITS | WA | Uninitialized data |  
| 22 | `.comment` | PROGBITS | MS | Compiler version |  
| 23 | `.symtab` | SYMTAB | — | Complete symbol table |  
| 24 | `.strtab` | STRTAB | — | Names of the symbol table |  
| 25 | `.shstrtab` | STRTAB | — | Section names |

The **flags** describe the properties of each section:

| Flag | Letter | Meaning |  
|---|---|---|  
| `SHF_ALLOC` | `A` | The section occupies memory at runtime |  
| `SHF_WRITE` | `W` | The section is modifiable in memory |  
| `SHF_EXECINSTR` | `X` | The section contains executable code |  
| `SHF_MERGE` | `M` | Entries can be merged (deduplication) |  
| `SHF_STRINGS` | `S` | The section contains `\0`-terminated strings |  
| `SHF_INFO_LINK` | `I` | The `sh_info` field references another section |

The combination of flags directly translates into the **memory permissions** that the loader will apply. For example, `AX` (alloc + exec) means the zone will be loaded into memory with read + execute rights, but **not** write. This is the **W⊕X** (*Write XOR Execute*) principle: a memory zone is either writable or executable, never both — a fundamental protection against code injection (section 2.8 and Chapter 19).

## Code sections

### `.text` — Executable code

This is the most important section for the reverse engineer. It contains the entire **machine code** of the program: all compiled functions, including `main()`, user functions, and inlined functions.

**Flags**: `AX` (Alloc + Exec) — loaded into memory, executable, not writable.

When you open a binary in a disassembler, the content of `.text` is displayed first. The program's entry point (`e_entry` in the ELF header) points to an address in `.text` — generally the `_start` function of the CRT code, and not directly to `main()`.

```bash
# Disassemble only the .text section
objdump -d -j .text hello
```

> 💡 **In RE**: If a binary is stripped, the boundaries between functions in `.text` are no longer marked by symbols. The disassembler must then resort to heuristics to identify function starts (looking for `push rbp; mov rbp, rsp` prologues, analyzing the control flow graph…). This is one of the reasons why a tool like Ghidra is superior to `objdump` for analyzing stripped binaries (Chapter 7, section 7.7).

### `.plt` — Procedure Linkage Table

The PLT contains small pieces of code (*stubs*) that serve as trampolines for calls to dynamic library functions. Each imported function (for example `strcmp`, `printf`, `puts`) has a dedicated PLT stub.

**Flags**: `AX` (Alloc + Exec).

When your code calls `strcmp`, the `call` actually points to `strcmp@plt` in the `.plt` section. This stub performs an indirect jump through the GOT (`.got.plt`) to reach the real implementation of `strcmp` in `libc.so`. This double-indirection mechanism is the foundation of **lazy binding** — we will detail it in section 2.9.

```bash
# See the content of the PLT
objdump -d -j .plt hello
```

Typical output for the `strcmp` stub:

```
Disassembly of section .plt:

0000000000001020 <strcmp@plt>:
    1020:   ff 25 e2 2f 00 00    jmp    *0x2fe2(%rip)    # 4008 <strcmp@GLIBC_2.2.5>
    1026:   68 00 00 00 00       push   $0x0
    102b:   e9 e0 ff ff ff       jmp    1010 <_init+0x10>
```

> 💡 **In RE**: The PLT is a gold mine. Even in a stripped binary, the names of imported functions are preserved in the dynamic symbols (`.dynsym`). When you see `call 0x1020` in `.text` and `0x1020` corresponds to `strcmp@plt`, you immediately know the code is calling `strcmp`. It is often the first reliable landmark in an unknown binary.

### `.init` and `.fini` — Initialization and finalization

These two sections contain code executed respectively **before** and **after** `main()`:

- **`.init`**: initialization code executed by the dynamic loader before `main()` is called. It is generated by the linker from the CRT (C Runtime).  
- **`.fini`**: finalization code executed after `main()` returns (or after a call to `exit()`).

**Flags**: `AX` (Alloc + Exec).

Two complementary sections, **`.init_array`** and **`.fini_array`**, contain arrays of function pointers. Each pointer in `.init_array` designates a constructor function to be called before `main()`, and each pointer in `.fini_array` designates a destructor to be called after `main()`. In C, you can declare such functions with the GCC attributes `__attribute__((constructor))` and `__attribute__((destructor))`. In C++, global variables' constructors are registered in `.init_array`.

```bash
# See the content of .init_array (array of pointers)
objdump -s -j .init_array hello
```

> 💡 **In RE**: The `.init_array` and `.fini_array` sections are targets of interest in malware analysis. Malicious code can register a constructor function to execute code *before* `main()`, which can go unnoticed if the analyst focuses only on `main()`. Systematically check these sections (Chapters 27–28).

## Data sections

### `.rodata` — Read-only data

This section contains all the program's constant data: literal strings, numeric constants, lookup tables (`switch/case` compiled as jump tables), and any data marked `const` in C/C++.

**Flags**: `A` (Alloc, without Write or Exec) — loaded into memory, read-only.

For our `hello.c`, this section contains the strings `"RE-101"`, `"Usage: %s <password>\n"`, `"Access granted."`, and `"Access denied."`:

```bash
# Display the raw content of .rodata
objdump -s -j .rodata hello
```

> 💡 **In RE**: The `.rodata` section is the first one to examine after `.text`. The literal strings it contains are often the best clues about the program's behavior: error messages, filenames, URLs, registry keys, `printf` format strings, log messages… The `strings` tool (Chapter 5) extracts precisely this data. Cross-references (XREF) in Ghidra then allow you to trace back from each string to the code that references it (Chapter 8, section 8.7).

### `.data` — Modifiable initialized data

This section contains **global and static variables initialized** with a non-zero value. For example:

```c
int counter = 42;                   // → .data  
static char key[] = "secret123";    // → .data  
```

**Flags**: `WA` (Write + Alloc) — loaded into memory, writable.

The `.data` section occupies space both in the file and in memory, because the initial values must be stored somewhere.

> 💡 **In RE**: Global variables in `.data` are often indicators of the program's state (flags, counters, pointers to buffers). In a binary with symbols, they bear a name. In a stripped binary, they appear as raw addresses in the memory range corresponding to `.data`. GDB watchpoints (Chapter 11, section 11.5) are particularly useful for monitoring modifications of these variables during execution.

### `.bss` — Uninitialized data (or zero-initialized)

The name `.bss` is historical (*Block Started by Symbol*, from a 1950s assembler). This section contains **global and static variables initialized to zero** or not explicitly initialized:

```c
int buffer[1024];           // → .bss (implicitly zero)  
static int state = 0;       // → .bss (explicitly zero)  
```

**Flags**: `WA` (Write + Alloc).

**Type**: `NOBITS` — this is the peculiarity of `.bss`. Unlike `.data`, this section **occupies no space in the file** on disk. Its `NOBITS` type tells the loader that it must allocate the corresponding memory zone and fill it with zeros at load time. This saves disk space: a 1 MB array initialized to zero costs only a few bytes of metadata in the ELF file.

```bash
# Check that .bss is of type NOBITS and takes no space in the file
readelf -S hello | grep bss
#  [21] .bss     NOBITS    0000000000004020  00003020  00000008  ...  WA  0  0  1
#                                                      ^^^^^^^^
#                                            Size in memory (8 bytes here)
# But the file offset and file size show that it consumes nothing on disk.
```

> 💡 **In RE**: The size of `.bss` can reveal the presence of important buffers (communication buffers, decryption zones, caches). An abnormally large `.bss` in a small binary warrants investigation.

## Dynamic linking sections

### `.got` and `.got.plt` — Global Offset Table

The GOT is an array of addresses located in a **writable** memory zone. Each entry corresponds to an external symbol (function or variable) whose real address is only known at load time.

- **`.got`** contains the addresses of global variables imported from shared libraries.  
- **`.got.plt`** contains the addresses of imported functions, filled in progressively by the lazy binding mechanism.

**Flags**: `WA` (Write + Alloc) — it is this writable nature that makes the GOT strategic in exploitation (GOT overwrite — Chapter 19, section 19.6).

At startup, the entries in `.got.plt` do not contain the real addresses of the functions. They initially point to the corresponding PLT stub, which triggers resolution via the dynamic loader on the first call. After resolution, the real address is written into the GOT and subsequent calls are direct. This is **lazy binding**, detailed in section 2.9.

```bash
# Display the entries of the GOT
objdump -R hello
# or
readelf -r hello
```

> 💡 **In RE**: Reading the GOT during execution with GDB lets you see which library functions have already been resolved and to what addresses. The command `x/10gx <got_address>` (Chapter 11) displays the contents of the table. In exploitation, overwriting a GOT entry to redirect a call to arbitrary code is a classic technique — which is why the Full RELRO protection (section 2.9 and Chapter 19) makes the GOT read-only after initial resolution.

### `.dynsym` and `.dynstr` — Dynamic symbols

These sections form the symbol table needed at **runtime** for dynamic resolution:

- **`.dynsym`** contains the symbol entries (name, type, binding, section, value).  
- **`.dynstr`** contains the strings (symbol names) referenced by `.dynsym`.

**Flags**: `A` (Alloc) — they must be in memory because the loader needs them.

The difference with `.symtab`/`.strtab` (see below) is fundamental: **`.dynsym` survives stripping**. When you run `strip` on a binary, `.symtab` and `.strtab` are removed, but `.dynsym` and `.dynstr` are preserved because they are essential to the program's operation. That is why, even in a stripped binary, you can still see the names of functions imported from shared libraries.

```bash
# Dynamic symbols (survive stripping)
readelf --dyn-syms hello

# Complete table (disappears after strip)
readelf -s hello
```

### `.dynamic` — Dynamic table

This section contains an array of key-value pairs (`tag` + `value`) that provides the loader with all the information needed for dynamic linking: names of required shared libraries (`NEEDED`), addresses of symbol and hash tables, linking flags, etc.

```bash
readelf -d hello
```

Simplified output:

| Tag | Value | Meaning |  
|---|---|---|  
| `NEEDED` | `libc.so.6` | Required library |  
| `INIT` | `0x1000` | Address of `.init` |  
| `FINI` | `0x1234` | Address of `.fini` |  
| `PLTGOT` | `0x3fe8` | Address of `.got.plt` |  
| `SYMTAB` | `0x3c8` | Address of `.dynsym` |  
| `STRTAB` | `0x488` | Address of `.dynstr` |  
| `BIND_NOW` | — | Disables lazy binding (Full RELRO) |

> 💡 **In RE**: Consulting `.dynamic` is one of the first reflexes of quick triage (Chapter 5, section 5.7). The `NEEDED` entry lists the required shared libraries, which reveals the program's dependencies. The presence of `BIND_NOW` or `FLAGS_1` with `NOW` indicates Full RELRO — a clue about the binary's hardening level.

### `.interp` — Loader path

This small section contains a single string: the absolute path of the dynamic interpreter (the loader). On a standard x86-64 system:

```bash
readelf -p .interp hello
#   /lib64/ld-linux-x86-64.so.2
```

The Linux kernel reads this section to know which program to load first. It is not your program that is executed directly — it is the loader that is launched, and it is the loader that loads and prepares your program (section 2.7).

## Metadata and debug sections

### `.symtab` and `.strtab` — Complete symbol table

These sections make up the "complete" symbol table of the binary — the one that contains the names of **all** functions and variables, including internal (`static`) functions, labels, source files, etc.

**Flags**: none (`A` absent) — these sections are **not** loaded into memory. They only exist in the file on disk for analysis and debug tools.

It is precisely for this reason that `strip` can remove them without affecting program execution. The difference between a "not stripped" binary and a "stripped" binary essentially lies in the presence or absence of `.symtab` and `.strtab`:

```bash
# Before stripping
file hello
# hello: ELF 64-bit ... not stripped
readelf -s hello | wc -l
# 65 (for example)

strip hello

# After stripping
file hello
# hello: ELF 64-bit ... stripped
readelf -s hello
# (no output — .symtab has disappeared)

# But dynamic symbols are still there:
readelf --dyn-syms hello
# strcmp, printf, puts... still visible
```

### `.eh_frame` and `.eh_frame_hdr` — Stack unwinding

These sections contain the **stack unwinding** information in DWARF format (even in C, even without `-g`). They allow the runtime to "unwind" the call stack, which is necessary for C++ exception handling (`throw`/`catch`), profiling tools, and debuggers (`backtrace` in GDB).

**Flags**: `A` (Alloc) — they must be in memory because the runtime needs them for *stack unwinding*.

> 💡 **In RE**: The information in `.eh_frame` is usable to recover function boundaries in a stripped binary. Some analysis tools (including Ghidra) use it to improve function detection. The `.eh_frame` section is also tied to C++ exception handling, which we will cover in Chapter 17, section 17.4.

### `.comment` — Compiler version

This section contains a string identifying the compiler and its version:

```bash
readelf -p .comment hello
#   GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0
```

**Flags**: `MS` (Merge + Strings) — not loaded into memory.

> 💡 **In RE**: Knowing the exact compiler version lets you look up patterns and idioms specific to that version (Chapter 16), reproduce the compilation in similar conditions, and identify any known vulnerabilities of the compiler itself.

### `.note.gnu.build-id` — Build identifier

This section contains a unique hash (generally SHA1) computed from the binary's content. It acts as a "fingerprint":

```bash
readelf -n hello
#   Build ID: 3a1b...f42c (hex SHA1)
```

This build ID makes it possible to tie a binary to its separate debug files (`.debug` or `debuginfod`), which is useful when DWARF information is provided in a separate package (common in Linux distributions).

## Mental map: sections and memory permissions

When the loader loads a binary, it groups sections into **segments** according to their permissions. The correspondence sections → permissions → segment forms an essential mental model:

| Memory permissions | Sections concerned | Segment |  
|---|---|---|  
| **R-X** (read + execute) | `.text`, `.plt`, `.init`, `.fini`, `.rodata`, `.eh_frame` | `LOAD` #1 (text) |  
| **RW-** (read + write) | `.data`, `.bss`, `.got`, `.got.plt`, `.dynamic`, `.init_array`, `.fini_array` | `LOAD` #2 (data) |  
| **Not loaded** | `.symtab`, `.strtab`, `.shstrtab`, `.comment` | No segment |

> ⚠️ **Note**: The exact boundary between segments and the sections they contain can vary depending on the linker version and compilation options. The scheme above is the common case. Use `readelf -l` to see the actual mapping (section 2.7).

Note that `.rodata` is placed in the executable segment (R-X) along with `.text`. This may seem surprising — read-only data in an executable segment? It is a consequence of the fact that the linker groups by minimum permissions: `.rodata` only needs read access, and the R-X segment provides that. Some modern linker configurations (with the `-z separate-code` option) create a dedicated R-- segment (read-only, non-executable) for `.rodata`, thereby improving security.

## Inspecting sections in practice

Here are the most useful commands, summarized for quick reference:

| Goal | Command |  
|---|---|  
| List all sections | `readelf -S hello` |  
| Hex content of a section | `objdump -s -j .rodata hello` |  
| Disassemble a code section | `objdump -d -j .text hello` |  
| Display the strings of a section | `readelf -p .rodata hello` |  
| See the dynamic symbols | `readelf --dyn-syms hello` |  
| See the relocations | `readelf -r hello` |  
| See the dynamic table | `readelf -d hello` |  
| Build information | `readelf -p .comment hello` |  
| Build ID | `readelf -n hello` |  
| Sections → segments mapping | `readelf -l hello` |

> 💡 **Tip**: In Chapter 5, we will formalize these commands into a **quick triage workflow** — a systematic routine for the first 5 minutes facing an unknown binary. The sections you just learned to identify will form the backbone of this workflow.

---

> 📖 **We now know what an ELF binary contains, section by section.** The next question is: how do you influence this content at compile time? In the next section, we will examine the most important GCC flags for RE and their concrete impact on the sections and the code produced.  
>  
> → 2.5 — Compilation flags and their impact on RE (`-O0` through `-O3`, `-g`, `-s`, `-fPIC`, `-pie`)

⏭️ [Compilation flags and their impact on RE (`-O0` through `-O3`, `-g`, `-s`, `-fPIC`, `-pie`)](/02-gnu-compilation-chain/05-compilation-flags.md)
