🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.1 — Compilation with debug symbols (`-g`, DWARF)

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## The fundamental problem: the source ↔ binary gap

When GCC transforms a `.c` file into an executable binary, it performs a series of irreversible transformations. Local variable names disappear — they have no use for the processor. Source code line numbers are lost. Data types (`int`, `char *`, `struct Player`) are reduced to mere sizes and memory offsets. Function parameters become values in registers. At the end of the process, the binary contains only machine code and raw data: the processor needs nothing else.

This gap between source code and binary is precisely what makes reverse engineering difficult — and it's also what makes debugging painful without additional information. If you set a breakpoint at address `0x401156` and GDB shows you a `cmp eax, 0x2a` instruction, you don't know that this instruction corresponds to line 47 of `main.c`, that `eax` contains the `user_input` variable, and that `0x2a` is the `EXPECTED_VALUE` constant defined in a `#define`.

**Debug symbols** exist to bridge this gap. They are metadata added to the binary that allow the debugger to make the link between the machine-code world and the source-code world. They don't change the executed code — the same instructions are generated with or without symbols — but they provide GDB with the map it's missing to navigate.

## The `-g` flag: asking GCC to generate symbols

Debug symbol generation is done at compilation with the `-g` flag:

```bash
# Without debug symbols
gcc -o program program.c

# With debug symbols
gcc -g -o program_debug program.c
```

This flag asks GCC to include in the ELF binary additional sections containing debug information. The generated machine code remains identical — `-g` affects neither instructions, nor optimizations, nor runtime performance. It only increases the file size on disk.

This is easily verified:

```bash
$ gcc -O0 -o keygenme keygenme.c
$ gcc -O0 -g -o keygenme_debug keygenme.c
$ ls -lh keygenme keygenme_debug
-rwxr-xr-x 1 user user  17K  keygenme
-rwxr-xr-x 1 user user  51K  keygenme_debug
```

The binary with symbols is about three times larger, but the `.text` (code) and `.data` (data) sections are strictly identical. The size difference comes entirely from the added debug sections.

### Detail levels: `-g`, `-g1`, `-g2`, `-g3`

The `-g` flag alone is equivalent to `-g2`, the default level. GCC offers several detail levels:

| Flag | Generated content |  
|---|---|  
| `-g0` | No symbols (equivalent to not using `-g`) |  
| `-g1` | Minimal information: function names and external functions, sufficient for stack traces but without local variables or line numbers |  
| `-g2` (`-g`) | Standard level: function names and types, local variables and parameters, line numbers, source ↔ address correspondence |  
| `-g3` | Maximum level: everything from `-g2` plus macro definitions (`#define`), allowing macro evaluation in GDB |

In an RE context, `-g2` (or `-g`) is the reference level. Level `-g3` is useful when debugging your own code with many macros, but binaries you'll encounter in real situations will never have been compiled with it.

### Combining `-g` with optimizations

A crucial point: **`-g` is compatible with all optimization levels**. You can perfectly write:

```bash
gcc -O2 -g -o program program.c
```

The binary will be optimized exactly as with `-O2` alone, but will additionally contain debug symbols. However, the debugging experience degrades significantly with optimizations, for several reasons:

- **"Optimized out" variables.** The compiler can decide that a variable doesn't need to exist in memory: its value is kept in a register, or it's completely eliminated by constant propagation. GDB will display `<optimized out>` when attempting to read it.

- **Reordered instructions.** Execution no longer follows the order of source lines. A `step` in GDB can jump from line 12 to line 18, then return to line 14. DWARF symbols try to track these rearrangements, but the result is often confusing.

- **Inlined functions.** If the compiler inlines a function, it no longer exists as a separate entity in the binary. GDB can report being "inside" the inlined function thanks to DWARF information, but you can't set a breakpoint on its entry in the usual way.

That's why, for the training binaries of this course, we work first with `-O0 -g` (no optimization, complete symbols) before moving to optimized variants.

## The DWARF format

Debug symbols are not stored in an improvised format. GCC uses the standard **DWARF** format (*Debugging With Attributed Record Formats*), which is the reference debugging format for ELF binaries under Linux. DWARF is currently at version 5 (DWARF5, published in 2017), but GCC generates DWARF4 or DWARF5 by default depending on the compiler version.

You can force a specific version:

```bash
gcc -g -gdwarf-4 -o program program.c   # Force DWARF version 4  
gcc -g -gdwarf-5 -o program program.c   # Force DWARF version 5  
```

### What DWARF contains

DWARF is a rich and structured format. It organizes information as a tree of entries called **DIE** (*Debugging Information Entry*). Each DIE describes a source program element and possesses a **tag** (its type) and **attributes** (its properties). Here are the main categories of information DWARF encodes:

**Address ↔ source-line correspondence.** For each address in `.text`, DWARF can indicate the corresponding source file, line number, and column. This is what allows GDB to display source code during debugging and to set breakpoints on line numbers (`break main.c:42`).

**Function descriptions.** For each function, DWARF records its name, start and end address, parameters (names, types, locations — register or stack), local variables (same information), and calling convention.

**Type descriptions.** DWARF encodes the program's entire type system: base types (`int`, `char`, `float`), pointers, arrays, structures (`struct`), unions, enumerations, and in C++ classes with their methods, inheritance, and access qualifiers. It's thanks to this information that GDB can display a complete structure when you type `print *player` instead of showing a raw block of bytes.

**Scope information.** DWARF describes lexical blocks (the `{}` in C), allowing GDB to know that a variable `i` declared in a `for` is only visible in that loop.

**Variable locations (location expressions).** This is one of DWARF's most sophisticated aspects. A variable's location can change during a function's execution: it might be in register `rdi` at the function's entry, then be saved on the stack at offset `rbp-0x10`, then be moved to `rax` to serve as a return value. DWARF uses a stack-based mini-language (*DWARF expressions*) to describe these variable locations, and it's this language that GDB interprets to find the right value at the right time.

### ELF sections generated by DWARF

DWARF information is stored in dedicated ELF sections, all prefixed with `.debug_`. You can list them with `readelf`:

```bash
$ readelf -S keygenme_debug | grep debug
  [27] .debug_aranges    PROGBITS     0000000000000000  00003041  00000030
  [28] .debug_info       PROGBITS     0000000000000000  00003071  00000198
  [29] .debug_abbrev     PROGBITS     0000000000000000  00003209  000000c7
  [30] .debug_line       PROGBITS     0000000000000000  000032d0  0000008e
  [31] .debug_str        PROGBITS     0000000000000000  0000335e  000000fb
  [32] .debug_line_str   PROGBITS     0000000000000000  00003459  00000032
```

Here is the role of each main section:

| Section | Content |  
|---|---|  
| `.debug_info` | The heart of DWARF: the DIE tree describing functions, variables, types, scopes |  
| `.debug_abbrev` | Abbreviation table that compacts `.debug_info` (frequent tags and attributes are encoded by a number) |  
| `.debug_line` | The address → source-line correspondence table (the "line number program") |  
| `.debug_str` | String pool referenced by `.debug_info` (function names, variables, files) |  
| `.debug_aranges` | Quick index: address ranges → compilation units, to speed up lookups |  
| `.debug_loc` | Location lists for variables whose location changes |  
| `.debug_ranges` | Non-contiguous address ranges for functions and scopes (useful with optimizations) |  
| `.debug_frame` | Stack-unwinding information (*call frame information*), used to reconstruct the call stack |

> 💡 **Note:** The `.debug_frame` section is distinct from `.eh_frame` (seen in Chapter 2). Both contain stack-unwinding information, but `.eh_frame` is used by the C++ exception mechanism at runtime and is always present, even without `-g`. The `.debug_frame` section is more detailed and reserved for the debugger.

### Inspecting DWARF information

Several tools allow reading the DWARF content of a binary. The most common is `readelf` with the `--debug-dump` flag (or its abbreviated form `-w`):

```bash
# Display the DIE of .debug_info
$ readelf --debug-dump=info keygenme_debug
```

The output is verbose. Here is a simplified excerpt showing the description of a `check_key` function:

```
 <1><8f>: Abbrev Number: 5 (DW_TAG_subprogram)
    <90>   DW_AT_name        : check_key
    <9a>   DW_AT_decl_file   : 1
    <9b>   DW_AT_decl_line   : 23
    <9c>   DW_AT_type        : <0x62>
    <a0>   DW_AT_low_pc      : 0x401156
    <a8>   DW_AT_high_pc     : 0x4d
    <ac>   DW_AT_frame_base  : 1 byte block: 56    (DW_OP_reg6 (rbp))
 <2><ae>: Abbrev Number: 6 (DW_TAG_formal_parameter)
    <af>   DW_AT_name        : input
    <b5>   DW_AT_decl_line   : 23
    <b6>   DW_AT_type        : <0x7b>
    <ba>   DW_AT_location    : 2 byte block: 91 68  (DW_OP_fbreg: -24)
```

Let's break down this output:

- `DW_TAG_subprogram` indicates a function. Its name (`DW_AT_name`) is `check_key`, declared at line 23 (`DW_AT_decl_line`) of the first source file.  
- `DW_AT_low_pc` and `DW_AT_high_pc` give the function's address range: it starts at `0x401156` and spans `0x4d` bytes (77 bytes).  
- `DW_AT_frame_base` indicates the frame pointer is in `rbp` (`DW_OP_reg6`).  
- The `DW_TAG_formal_parameter` describes the `input` parameter. Its location (`DW_AT_location`) is `DW_OP_fbreg: -24`, meaning "at offset -24 relative to the frame base (`rbp`)", i.e., `rbp - 0x18`.

For the line/address correspondence table:

```bash
$ readelf --debug-dump=decodedline keygenme_debug

File name         Line number    Starting address    View    Stmt  
keygenme.c                 23          0x401156               x  
keygenme.c                 24          0x40116a               x  
keygenme.c                 25          0x401172               x  
keygenme.c                 28          0x401183               x  
keygenme.c                 29          0x401190               x  
```

Each entry associates a file, a line number, and a memory address. This is exactly what GDB uses when you type `break keygenme.c:25` — it consults this table to find address `0x401172` and set the breakpoint there.

The `objdump` tool offers an alternative view with the `-WL` flag (or `--dwarf=decodedline`), and the dedicated `dwarfdump` utility (`libdwarf-tools` or `dwarfdump` package depending on the distribution) provides even more detailed output.

## The impact of stripping on symbols

Let's recall the distinction between two types of "symbols" that are often confused:

**The ELF symbol table** (`.symtab` / `.dynsym`) contains the names of functions and global variables. It's what `nm` displays and what `strip` removes. These symbols allow GDB to resolve `break check_key` to an address, but they contain neither types, nor local variables, nor line numbers.

**The DWARF sections** (`.debug_*`) contain the complete debug information described above. They are much richer than the symbol table.

The `strip` command removes **both**:

```bash
$ strip keygenme_debug -o keygenme_stripped
$ readelf -S keygenme_stripped | grep -E "symtab|debug"
# (no output — everything has been removed)
```

You can also remove only the debug symbols while keeping the symbol table:

```bash
$ strip --strip-debug keygenme_debug -o keygenme_nodebug
$ nm keygenme_nodebug | head
0000000000401156 T check_key    # ← the symbol table is preserved
```

In practice, the binaries you'll encounter in RE are in one of these three states:

| State | `.symtab` | `.debug_*` | Compilation command |  
|---|---|---|---|  
| Full debug | ✅ | ✅ | `gcc -g -O0` |  
| Standard release | ✅ | ❌ | `gcc -O2` |  
| Stripped | ❌ | ❌ | `gcc -O2 -s` or `strip` after compilation |

The majority of binaries "in the wild" (distributed software, malware, firmware) are stripped. It's the most common and most difficult situation — we'll see how to handle it in section 11.4.

## Separate debug symbols

A common practice in Linux distributions exists: debug symbols are distributed in **separate packages** (often suffixed with `-dbg` or `-dbgsym`). The installed binary is stripped to save space, and symbols are available on demand.

```bash
# Example on Debian/Ubuntu
sudo apt install libc6-dbg       # Debug symbols for glibc
```

GDB knows how to automatically load these symbols if they're installed. It searches in standardized paths like `/usr/lib/debug/`. You can also manually load a symbol file:

```bash
(gdb) symbol-file /path/to/program.debug
```

Or use a separate symbol file created with `objcopy`:

```bash
# Extract symbols into a separate file
$ objcopy --only-keep-debug program program.debug

# Strip the binary
$ strip program

# Add a link to the symbol file
$ objcopy --add-gnu-debuglink=program.debug program
```

With this configuration, GDB will automatically load `program.debug` when it opens `program`, provided the file is in the same directory or in the symbol search path.

> 💡 **For RE:** this technique is useful the other way around. If you analyze a binary from a Linux distribution (for example a system daemon), installing the corresponding `-dbgsym` package gives you full access to debug symbols, transforming a painful GDB session into a comfortable experience. Systematically think of it before starting analysis.

## Checking a binary's state before launching GDB

Before opening GDB, get in the habit of quickly checking what the binary contains in terms of symbols. Here is the routine:

```bash
# 1. Does the binary have a symbol table?
$ nm program 2>&1 | head -3
# If "no symbols" → stripped

# 2. Does the binary contain DWARF sections?
$ readelf -S program | grep debug
# If no line → no debug symbols

# 3. Which DWARF format and version?
$ readelf --debug-dump=info program 2>/dev/null | head -5
# Displays "Compilation Unit @ offset 0x0:" with the DWARF version

# 4. Quick summary with file
$ file program
program: ELF 64-bit LSB pie executable, x86-64, [...], not stripped
# "not stripped" = symbol table present
# "stripped" = symbol table absent
# (file says nothing about DWARF — you need readelf for that)
```

This four-command check takes a few seconds and conditions your approach in GDB: with DWARF symbols, you'll work comfortably with function names, line numbers, and types. Without symbols, you'll work with raw addresses and registers — which is perfectly doable, but requires a different methodology (section 11.4).

## What GDB does with DWARF information

To conclude this section and connect to what follows, here is concretely how GDB exploits each category of DWARF information on a daily basis:

| You type in GDB... | GDB uses... |  
|---|---|  
| `break check_key` | `.symtab` to resolve the name to an address |  
| `break keygenme.c:25` | `.debug_line` to find the address matching line 25 |  
| `next` (advance one source line) | `.debug_line` to compute how far to advance |  
| `print input` | `.debug_info` to find the variable's type and location |  
| `print *player` | `.debug_info` to know the structure of the pointed type and its fields |  
| `backtrace` | `.debug_frame` + `.debug_info` to reconstruct and name the call stack |  
| `list` (display source) | `.debug_line` for address → file:line correspondence, then reads the source file from disk |

This last point is important: GDB does not include the source code in the binary. The `.debug_line` section contains paths to source files as they existed at compilation time. If these files are not present at the same location on your machine, the `list` command will fail — but all other features (breakpoints by line, variable display, backtrace) will continue to work normally, because they only depend on DWARF metadata embedded in the binary.

---

> **Takeaway:** DWARF debug symbols are the map that connects machine code to source code. They don't modify program execution, but they radically transform the debugging experience. In RE, checking their presence is the first thing to do before opening GDB — and when they're absent, you must adapt your method, not give up.

⏭️ [Fundamental GDB commands: `break`, `run`, `next`, `step`, `info`, `x`, `print`](/11-gdb/02-fundamental-commands.md)
