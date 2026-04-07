🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix F — ELF Section Table and Their Roles

> 📎 **Reference Sheet** — This appendix provides a comprehensive list of sections you may encounter in an x86-64 ELF binary produced by GCC/G++. For each section, it indicates its content, flags, role in the execution process, and its specific relevance to reverse engineering. It directly complements Chapter 2 (section 2.4) and serves as a permanent reference for all static analysis.

---

## Reminder: sections vs segments

Before diving into the table, it is essential to clarify the distinction between **sections** and **segments**, two concepts often confused in the ELF format.

**Sections** are the view of the *linker* and the *reverse engineer*. They divide the binary into named logical units (`.text` for code, `.data` for initialized data, etc.). Each section has a name, a type, flags, and a size. This is the granularity at which `readelf -S`, `objdump`, Ghidra, and all static analysis tools operate. A stripped binary may have its sections removed or renamed, but this does not prevent it from running.

**Segments** (or *program headers*) are the view of the kernel *loader*. They group one or more sections into contiguous memory zones with common permissions (read, write, execute). This is the granularity at which the Linux kernel operates when it maps the binary into memory via `mmap`. A `PT_LOAD` segment with `R+X` flags will typically contain `.text`, `.plt`, `.rodata`, and other read-only and executable sections.

In summary: sections are for analysis, segments are for execution. A binary can function without a section table (packers often remove it) but not without a segment table.

```
            Linker / RE view                 Loader view
         ┌──────────────────────┐        ┌──────────────────────┐
         │  Section .text       │        │                      │
         │  Section .rodata     │───────▶│  Segment LOAD (R+X)  │
         │  Section .plt        │        │                      │
         ├──────────────────────┤        ├──────────────────────┤
         │  Section .data       │        │                      │
         │  Section .bss        │───────▶│  Segment LOAD (R+W)  │
         │  Section .got        │        │                      │
         └──────────────────────┘        └──────────────────────┘
```

---

## Section flags

Each section has flags (`sh_flags`) that indicate its memory properties. The three main flags are:

| Flag | `readelf` letter | Meaning |  
|------|-------------------|---------------|  
| `SHF_WRITE` | `W` | The section is writable at runtime |  
| `SHF_ALLOC` | `A` | The section occupies memory at runtime (mapped into memory) |  
| `SHF_EXECINSTR` | `X` | The section contains executable code |

Other less common flags exist:

| Flag | Letter | Meaning |  
|------|--------|---------------|  
| `SHF_MERGE` | `M` | Section elements can be merged (deduplication) |  
| `SHF_STRINGS` | `S` | The section contains null-terminated strings (combined with `M` for deduplication) |  
| `SHF_INFO_LINK` | `I` | The `sh_info` field contains a section index |  
| `SHF_GROUP` | `G` | The section is part of a group (COMDAT, C++ templates) |  
| `SHF_TLS` | `T` | The section contains Thread-Local Storage data |

Typical combinations encountered in RE:

| Flags | Practical meaning | Typical sections |  
|-------|------------------------|-------------------|  
| `AX` | Read-only executable code | `.text`, `.plt`, `.init`, `.fini` |  
| `A` | Read-only data | `.rodata`, `.eh_frame`, `.dynsym` |  
| `WA` | Read-write data | `.data`, `.bss`, `.got`, `.got.plt` |  
| `AMS` | Mergeable read-only strings | `.rodata` (when the compiler merges identical strings) |  
| (none) | Not mapped into memory (metadata) | `.symtab`, `.strtab`, `.shstrtab`, `.comment` |

---

## Complete ELF section table

### Code sections

#### `.text`

| Property | Value |  
|-----------|--------|  
| **Flags** | `AX` (Alloc + Exec) |  
| **Content** | Compiled machine code — the body of all program functions |  
| **RE relevance** | This is **the** main analysis section. All disassembly of `main()`, user functions, and static functions from statically linked libraries is found here. |

The `.text` section is the largest executable section in the binary. It contains all compiled code, except for PLT trampolines (in `.plt`) and initialization/finalization code (in `.init`/`.fini`). GCC aligns functions on 16-byte boundaries by default, which produces NOP padding between functions — do not confuse them with meaningful code.

#### `.plt` (Procedure Linkage Table)

| Property | Value |  
|-----------|--------|  
| **Flags** | `AX` |  
| **Content** | Indirect jump trampolines for calls to shared library functions |  
| **RE relevance** | Each entry corresponds to an imported function. A `call printf@plt` jumps into this section, which redirects via the GOT to the actual address of `printf` in the libc. |

The PLT implements the *lazy binding* mechanism: on the first call, the trampoline invokes the dynamic resolver (`ld.so`) to find the actual address of the function and store it in the GOT. Subsequent calls jump directly to the resolved address. In RE, PLT entries are easily recognizable by their uniform structure (an indirect `jmp` via the GOT, followed by an index `push` and a `jmp` to the resolver).

#### `.plt.got`

| Property | Value |  
|-----------|--------|  
| **Flags** | `AX` |  
| **Content** | PLT variant for functions resolved in an *eager* (non-lazy) manner |  
| **RE relevance** | Present in binaries compiled with `-z now` (Full RELRO). Entries are simple indirect `jmp` instructions without a lazy resolution mechanism. |

#### `.plt.sec`

| Property | Value |  
|-----------|--------|  
| **Flags** | `AX` |  
| **Content** | Secure PLT with CET protection (Intel Control-flow Enforcement) |  
| **RE relevance** | Present in binaries compiled with `-fcf-protection`. Each entry starts with `endbr64` followed by an indirect `jmp`. Structure identical to `.plt.got` but with the CET marker. |

#### `.init`

| Property | Value |  
|-----------|--------|  
| **Flags** | `AX` |  
| **Content** | Initialization code executed **before** `main()` |  
| **RE relevance** | Generally contains a call to `__gmon_start__` (profiling) and the invocation of functions listed in `.init_array`. Useful for spotting code that runs before `main()` (C++ global constructors, anti-debugging). |

#### `.fini`

| Property | Value |  
|-----------|--------|  
| **Flags** | `AX` |  
| **Content** | Finalization code executed **after** `main()` returns |  
| **RE relevance** | Executes the functions listed in `.fini_array`. C++ global destructors and functions registered by `atexit()` go through this mechanism. Malware can hide trace-cleanup code here. |

---

### Read-only data sections

#### `.rodata`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` (or `AMS` if strings are merged) |  
| **Content** | Constant data: string literals, `const` constants, value tables, `switch` jump tables |  
| **RE relevance** | This is the **gold mine** for strings. `strings` and `iz` (r2) primarily target this section. Error messages, filenames, URLs, hardcoded keys, and format strings are found here. Jump tables for `switch` statements compiled by GCC also reside here. |

When GCC compiles a `switch` with many consecutive `case` values, it generates a jump table in `.rodata`: an array of relative offsets, indexed by the `switch` value. Recognizing this pattern (a series of dwords in `.rodata` referenced by a `lea` + `movsxd` + `add` + indirect `jmp`) allows you to reconstruct the original `switch`.

#### `.rodata1`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Additional constant data (overflow from `.rodata`) |  
| **RE relevance** | Rare in common GCC binaries. Same usage as `.rodata`. |

---

### Writable data sections

#### `.data`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` (Write + Alloc) |  
| **Content** | Global and static variables initialized with a non-zero value |  
| **RE relevance** | Contains the initial values of global variables. If a binary contains a hardcoded password in a global variable (and not a `const` constant), it will be here rather than in `.rodata`. Function-local static variables (`static int count = 42;`) are also in `.data`. |

#### `.data1`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Additional initialized data |  
| **RE relevance** | Rare. Same usage as `.data`. |

#### `.bss` (Block Started by Symbol)

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Global and static variables initialized to zero (or uninitialized) |  
| **RE relevance** | `.bss` **does not occupy space in the file** — it is entirely made up of zeros allocated by the loader in memory. Its size indicates the amount of "blank" memory the program uses at startup. Large global buffers (`static char buffer[65536];`) end up here. |

The distinction between `.data` and `.bss` is a file size optimization: why store 64 KB of zeros in the file when the loader can simply allocate the memory and fill it with zeros? In RE, variables in `.bss` have no interesting value to read in the file itself — their value only becomes meaningful at runtime (dynamic analysis).

---

### Dynamic linking sections

#### `.dynamic`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Table of `Elf64_Dyn` structures — metadata for the dynamic linker (`ld.so`) |  
| **RE relevance** | Contains critical information for dynamic resolution: paths of required libraries (`DT_NEEDED`), GOT addresses, PLT, dynamic symbol tables, RELRO flags, etc. `readelf -d` displays this section in a readable format. |

#### `.dynsym`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Dynamic symbol table (imported/exported functions and variables) |  
| **RE relevance** | Unlike `.symtab`, this table **survives stripping** (`strip`). It contains the names of imported functions (libc, libcrypto, etc.) and exported ones. This is the table that `nm -D` displays. On a stripped binary, it is often the only source of function names. |

#### `.dynstr`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | String table associated with dynamic symbols |  
| **RE relevance** | Contains the names of functions and libraries referenced by `.dynsym` and `.dynamic`. Survives stripping. |

#### `.gnu.hash`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | GNU hash table for fast dynamic symbol resolution |  
| **RE relevance** | Replaces the old `.hash` (SysV). Used by `ld.so` to quickly find a symbol by name. Its internal structure (bloom filter + buckets + chains) can be exploited to enumerate symbols even if other tables are corrupted. |

#### `.hash`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | SysV hash table (old format) for symbol resolution |  
| **RE relevance** | Sometimes present alongside `.gnu.hash` for compatibility. Same role, different hashing algorithm. |

#### `.gnu.version` / `.gnu.version_r`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Symbol versioning information (which symbol belongs to which libc version) |  
| **RE relevance** | Allows determining which glibc version the binary was compiled against. For example, `GLIBC_2.34` indicates that the binary requires at minimum glibc 2.34. |

---

### GOT (Global Offset Table) sections

#### `.got`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Global offset table for global variables in PIC/PIE code |  
| **RE relevance** | Contains the resolved addresses of global variables and certain functions. In Full RELRO, this section is remapped as read-only after initial resolution. |

#### `.got.plt`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | GOT sub-table dedicated to PLT entries (library functions) |  
| **RE relevance** | Each entry corresponds to an imported function. Before lazy resolution, entries point to the PLT resolution stub. After resolution, they contain the actual address of the function in the shared library. In dynamic RE, reading `.got.plt` with GDB (`x/gx 0x...`) allows you to see which functions have already been resolved. |

The distinction between `.got` and `.got.plt` is related to RELRO. In Partial RELRO (GCC default), `.got` is read-only but `.got.plt` remains writable (required for lazy binding). In Full RELRO (`-z now`), both are read-only after loading, which blocks GOT overwrite attacks.

---

### Initialization and finalization sections

#### `.init_array`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Array of function pointers executed before `main()` |  
| **RE relevance** | C++ global constructors (constructors of static objects), functions marked with `__attribute__((constructor))`, and shared library initializers are listed here. Malware can register malicious code in this table so that it runs automatically. |

#### `.fini_array`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Array of function pointers executed after `main()` returns |  
| **RE relevance** | C++ global destructors and functions marked with `__attribute__((destructor))`. Same security consideration as `.init_array`. |

#### `.preinit_array`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Functions executed before the constructors in `.init_array` |  
| **RE relevance** | Very rare. Only in executables (not shared libraries). |

---

### Symbol and debugging sections

#### `.symtab`

| Property | Value |  
|-----------|--------|  
| **Flags** | (none — not mapped into memory) |  
| **Content** | Complete symbol table (all functions, variables, labels) |  
| **RE relevance** | Contains the names of **all** functions, including static functions (`static`) and local variables. This is the most information-rich table. **Removed by `strip`** — if present, the binary is not stripped and your RE work is considerably easier. |

#### `.strtab`

| Property | Value |  
|-----------|--------|  
| **Flags** | (none) |  
| **Content** | String table associated with `.symtab` |  
| **RE relevance** | Contains the names of all symbols in `.symtab`. Removed by `strip` along with `.symtab`. |

#### `.shstrtab`

| Property | Value |  
|-----------|--------|  
| **Flags** | (none) |  
| **Content** | String table for section names (`.text`, `.data`, etc.) |  
| **RE relevance** | Provides a name for each section. Generally survives stripping (unless the binary is packed or deliberately altered). If section names are absent, `readelf` displays numeric indices instead. |

#### `.debug_info`, `.debug_abbrev`, `.debug_line`, `.debug_str`, `.debug_ranges`, etc.

| Property | Value |  
|-----------|--------|  
| **Flags** | (none) |  
| **Content** | Debugging information in DWARF format (types, source lines, variables, scopes) |  
| **RE relevance** | Present only if the binary was compiled with `-g`. This is a treasure for RE: instruction-to-source-line correspondence, complete variable types, parameter names, scope hierarchy. **Removed by `strip` or `-s`**. If present, exploit them immediately. |

#### `.note.gnu.build-id`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Unique hash identifying this specific build (SHA-1 or UUID) |  
| **RE relevance** | Allows uniquely identifying a build. Useful for associating a stripped binary with its separate debug symbol files (`.debug` files). Symbol servers (debuginfod) use the build-id as a lookup key. |

#### `.note.ABI-tag`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | ABI tag indicating the target system (Linux, GNU, minimum kernel version) |  
| **RE relevance** | Confirms that the binary targets Linux and indicates the minimum required kernel version. |

---

### Exception handling sections

#### `.eh_frame`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Stack unwinding tables in DWARF CFI (Call Frame Information) format |  
| **RE relevance** | Used by the C++ exception mechanism and by profiling/debugging tools to reconstruct the call stack (stack unwinding). Even in pure C binaries, this section is present because GCC generates it by default. It survives stripping and can be exploited to reconstruct function boundaries in a stripped binary. |

The `.eh_frame` section is an underestimated source of information in RE. Each entry (FDE — Frame Description Entry) describes how to unwind the stack for a given function, which implies that it implicitly contains the start and end addresses of each function. Tools like `dwarfdump --eh-frame` or the Ghidra plugin can exploit this information to improve function detection in stripped binaries.

#### `.eh_frame_hdr`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Binary index (lookup table) for quickly accessing `.eh_frame` entries |  
| **RE relevance** | Speeds up stack unwinding. Contains an array sorted by function start address, making it a mini function table exploitable for RE. |

#### `.gcc_except_table`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | LSDA (Language Specific Data Area) tables for C++ exceptions |  
| **RE relevance** | Describes code regions covered by `try`/`catch` blocks, the types of caught exceptions, and cleanup actions. Present only in C++ binaries that use exceptions. Helps reconstruct `try`/`catch` logic during decompilation. |

---

### Relocation sections

#### `.rela.dyn`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Relocation table for data (global variables, addresses in `.got`) |  
| **RE relevance** | Indicates which addresses in the binary must be adjusted by the loader at load time. In PIE/PIC, nearly all absolute references require a relocation. `readelf -r` displays this table. |

#### `.rela.plt`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Relocation table for PLT entries (imported functions) |  
| **RE relevance** | Each entry associates a `.got.plt` slot with an imported function symbol. This table is what tells you that GOT entry #5 corresponds to `printf`, #6 to `malloc`, etc. Essential for naming PLT calls in the disassembly. |

---

### TLS (Thread-Local Storage) sections

#### `.tdata`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WAT` (Write + Alloc + TLS) |  
| **Content** | Initialized thread-local variables (`__thread int x = 42;` or `thread_local int x = 42;`) |  
| **RE relevance** | Each thread receives its own copy of these variables. Access goes through the `fs` segment register (or `gs` depending on the ABI). In RE, an access to `fs:[offset]` or a pattern `mov rax, qword ptr fs:[0x28]` followed by comparisons indicates either TLS or the **stack canary** (the canary is stored in TLS at `fs:0x28` on the x86-64 glibc). |

#### `.tbss`

| Property | Value |  
|-----------|--------|  
| **Flags** | `WAT` |  
| **Content** | Uninitialized (or zero-initialized) thread-local variables |  
| **RE relevance** | TLS equivalent of `.bss`. Does not occupy space in the file. |

---

### Special GCC/GNU sections

#### `.comment`

| Property | Value |  
|-----------|--------|  
| **Flags** | (none) |  
| **Content** | String identifying the compiler and its version |  
| **RE relevance** | Typically contains `GCC: (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0` or similar. Allows precisely identifying the compiler version, distribution, and sometimes the compilation options. Valuable information for choosing the right signatures in Ghidra or for reproducing the build. |

#### `.note.gnu.property`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | GNU properties of the binary (CET support, BTI for ARM, etc.) |  
| **RE relevance** | Indicates whether the binary was compiled with control-flow protections (CET/IBT). Survives stripping. |

#### `.gnu.warning.*`

| Property | Value |  
|-----------|--------|  
| **Flags** | (variable) |  
| **Content** | Warnings emitted by the linker when a specific symbol is used |  
| **RE relevance** | Rare. Warnings like "this function is dangerous, use X instead" for `gets()` go through this mechanism. |

#### `.interp`

| Property | Value |  
|-----------|--------|  
| **Flags** | `A` |  
| **Content** | Path to the dynamic linker (typically `/lib64/ld-linux-x86-64.so.2`) |  
| **RE relevance** | Indicates which ELF interpreter is used to load the binary. An unusual path may indicate a cross-compiled binary, a chroot environment, or an exploit chain that replaces the loader. Static binaries do not have this section. |

---

### Security and control-flow sections

#### `.rela.dyn` / `.rela.plt` and RELRO

The interaction between relocation sections and RELRO protection deserves a specific mention:

| RELRO mode | `.got` | `.got.plt` | RE impact |  
|------------|--------|------------|-----------|  
| **No RELRO** | `WA` (writable) | `WA` (writable) | The entire GOT is writable → vulnerable to GOT overwrite |  
| **Partial RELRO** (GCC default) | Read-only after loading | `WA` (writable, lazy binding) | `.got.plt` remains the target of GOT overwrite attacks |  
| **Full RELRO** (`-z now`) | Read-only | Read-only | The entire GOT is protected. No more lazy binding. More secure but slower startup |

---

### Rarely encountered but worth knowing sections

#### `.ctors` / `.dtors` (obsolete)

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Old constructor/destructor tables (replaced by `.init_array`/`.fini_array`) |  
| **RE relevance** | May still be present in old binaries or binaries compiled with old GCC versions. Same role as `.init_array`/`.fini_array`. |

#### `.jcr` (Java Class Registration — obsolete)

| Property | Value |  
|-----------|--------|  
| **Flags** | `WA` |  
| **Content** | Java class registration table for GCJ (GNU Compiler for Java, abandoned) |  
| **RE relevance** | Obsolete. May appear in very old binaries. |

#### `.stab` / `.stabstr`

| Property | Value |  
|-----------|--------|  
| **Flags** | (none) |  
| **Content** | Debugging information in STABS format (old format, replaced by DWARF) |  
| **RE relevance** | Very rare on modern systems. If you encounter them, the binary is probably very old or cross-compiled from a BSD/Solaris system. |

---

## Commands for inspecting sections

| Tool | Command | Description |  
|-------|----------|-------------|  
| `readelf` | `readelf -S ./binary` | Lists all sections with flags, offsets, and sizes |  
| `readelf` | `readelf -l ./binary` | Lists segments (program headers) and the sections they contain |  
| `readelf` | `readelf -d ./binary` | Displays the `.dynamic` section |  
| `readelf` | `readelf -r ./binary` | Displays the relocation tables (`.rela.dyn`, `.rela.plt`) |  
| `readelf` | `readelf -s ./binary` | Displays the symbol table (`.symtab` and `.dynsym`) |  
| `readelf` | `readelf -p .comment ./binary` | Displays the content of the `.comment` section |  
| `readelf` | `readelf -n ./binary` | Displays the notes (`.note.*`) |  
| `readelf` | `readelf --debug-dump=info ./binary` | Dumps DWARF information |  
| `objdump` | `objdump -h ./binary` | Lists sections with their VMAs and sizes |  
| `objdump` | `objdump -j .rodata -s ./binary` | Hexadecimal dump of `.rodata` contents |  
| r2 | `iS` | Lists sections |  
| r2 | `iSS` | Lists segments |  
| GDB | `maintenance info sections` | Sections with flags and addresses |  
| GDB (GEF) | `xfiles` | Sections with in-memory addresses |

---

## Typical sections of a GCC binary — overview

The following table shows the sections you will find in a typical x86-64 ELF binary compiled by GCC, in the approximate order they appear in the file:

| Section | Flags | Segment | Summary content | Survives `strip`? |  
|---------|-------|---------|----------------|---------------------|  
| `.interp` | `A` | `INTERP` | Loader path | Yes |  
| `.note.gnu.build-id` | `A` | `NOTE` | Unique build ID | Yes |  
| `.note.ABI-tag` | `A` | `NOTE` | Linux ABI tag | Yes |  
| `.gnu.hash` | `A` | `LOAD R` | Symbol hash table | Yes |  
| `.dynsym` | `A` | `LOAD R` | Dynamic symbols | Yes |  
| `.dynstr` | `A` | `LOAD R` | Dynamic symbol names | Yes |  
| `.gnu.version` | `A` | `LOAD R` | Symbol versioning | Yes |  
| `.gnu.version_r` | `A` | `LOAD R` | Required versioning | Yes |  
| `.rela.dyn` | `A` | `LOAD R` | Data relocations | Yes |  
| `.rela.plt` | `A` | `LOAD R` | PLT relocations | Yes |  
| `.init` | `AX` | `LOAD RX` | Initialization code | Yes |  
| `.plt` | `AX` | `LOAD RX` | PLT trampolines | Yes |  
| `.text` | `AX` | `LOAD RX` | **Main code** | Yes |  
| `.fini` | `AX` | `LOAD RX` | Finalization code | Yes |  
| `.rodata` | `A` | `LOAD R` | **Constant data, strings** | Yes |  
| `.eh_frame_hdr` | `A` | `LOAD R` | Exception frame index | Yes |  
| `.eh_frame` | `A` | `LOAD R` | Stack unwinding tables | Yes |  
| `.init_array` | `WA` | `LOAD RW` | Constructor pointers | Yes |  
| `.fini_array` | `WA` | `LOAD RW` | Destructor pointers | Yes |  
| `.dynamic` | `WA` | `DYNAMIC` | Dynamic linker metadata | Yes |  
| `.got` | `WA` | `LOAD RW` | GOT (variables) | Yes |  
| `.got.plt` | `WA` | `LOAD RW` | GOT (PLT functions) | Yes |  
| `.data` | `WA` | `LOAD RW` | **Initialized variables** | Yes |  
| `.bss` | `WA` | `LOAD RW` | Zero-initialized variables | Yes |  
| `.comment` | — | — | Compiler version | Sometimes |  
| `.symtab` | — | — | Complete symbol table | **No** |  
| `.strtab` | — | — | Symbol names | **No** |  
| `.shstrtab` | — | — | Section names | Yes |  
| `.debug_*` | — | — | DWARF information | **No** |

The "Survives `strip`?" column indicates whether the section is present after a `strip --strip-all`. Sections that survive are those necessary for execution (flags `A`) or for identifying the binary. Debug sections and the complete symbol table are removed.

---

> 📚 **Further reading**:  
> - **Chapter 2, section 2.4** — [Key ELF Sections](/02-gnu-compilation-chain/04-elf-sections.md) — pedagogical coverage with concrete examples.  
> - **Chapter 2, section 2.9** — [PLT/GOT in Detail](/02-gnu-compilation-chain/09-plt-got-lazy-binding.md) — detailed operation of lazy binding.  
> - **Appendix A** — [x86-64 Opcode Quick Reference](/appendices/appendix-a-opcodes-x86-64.md) — the instructions you will find in `.text`.  
> - **Appendix B** — [System V AMD64 ABI Calling Conventions](/appendices/appendix-b-system-v-abi.md) — the convention governing `.text` code.  
> - **Appendix E** — [ImHex Cheat Sheet](/appendices/appendix-e-cheatsheet-imhex.md) — writing a `.hexpat` to visualize an ELF header.  
> - **ELF Specification** — *Tool Interface Standard (TIS) Executable and Linking Format (ELF) Specification* — the official reference document.  
> - **`man 5 elf`** — the Linux man page documenting ELF structures.

⏭️ [Comparison of native tools (tool / usage / free / CLI or GUI)](/appendices/appendix-g-native-tools-comparison.md)
