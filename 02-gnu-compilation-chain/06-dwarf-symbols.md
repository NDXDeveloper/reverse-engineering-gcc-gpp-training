🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.6 — Understanding DWARF symbol files

> 🎯 **Goal of this section**: Understand the structure and content of the DWARF format, know how to extract and exploit debug information when it is available, and be aware of the situations where a reverse engineer can benefit from it even on a production binary.

---

## What is DWARF?

DWARF (*Debugging With Attributed Record Formats*) is the standard format for debug information on Unix-like systems. It is produced by GCC (and Clang) when the `-g` flag is used, and consumed by debuggers (GDB), profilers (`perf`, `valgrind`), stack-unwinding tools, and disassemblers/decompilers (Ghidra, IDA).

The name DWARF is a nod to ELF (elves and dwarves of fantasy mythology). The format is currently at version 5 (DWARF5, published in 2017), but GCC produces DWARF4 or DWARF5 by default depending on the version. You can force a version with `-gdwarf-4` or `-gdwarf-5`.

DWARF answers a fundamental question: **how do you relate machine code (addresses, registers, stack offsets) to source code (files, lines, functions, variables, types)?** This correspondence is exactly the reverse of the reverse engineer's work — which is why DWARF information, when present, is an extraordinary shortcut.

## Where is DWARF information stored?

DWARF information is spread across several sections of the ELF file, all prefixed with `.debug_`. In section 2.5, we listed them briefly. Let's now detail the role of each:

| Section | Role | Primary consumer |  
|---|---|---|  
| `.debug_info` | Structured descriptions of the whole program: functions, variables, types, scopes, parameters | GDB, Ghidra, IDA |  
| `.debug_abbrev` | Definitions of the "forms" used in `.debug_info` (compression system) | Internal DWARF parser |  
| `.debug_line` | Machine address ↔ source file + line number correspondence table | GDB (`list`), profilers |  
| `.debug_str` | String pool (names of functions, variables, types, files) | Referenced by `.debug_info` |  
| `.debug_loc` | Location lists: where a variable is at each point of the program | GDB (`print variable`) |  
| `.debug_ranges` | Discontinuous address ranges associated with an entity (optimized functions, scopes) | GDB, analyzers |  
| `.debug_frame` | Stack-unwinding information (CFA — Call Frame Address) | GDB (`backtrace`), unwinders |  
| `.debug_aranges` | Accelerated index: address ranges → compilation units | Fast lookup |  
| `.debug_types` | Type descriptions (DWARF4, merged into `.debug_info` in DWARF5) | GDB, Ghidra |  
| `.debug_macro` | Preprocessor macro definitions (if `-g3` is used) | GDB (`macro expand`) |  
| `.debug_str_offsets` | Offset table into `.debug_str` (DWARF5, access optimization) | Internal DWARF parser |  
| `.debug_line_str` | String pool specific to `.debug_line` (DWARF5) | Internal DWARF parser |  
| `.debug_addr` | Shared address table (DWARF5, redundancy reduction) | Internal DWARF parser |

All these sections have the `A` flag absent — they are **not loaded into memory** at runtime. They only exist in the file on disk. That is why removing them (with `strip` or `-s`) in no way changes the program's behavior.

To quickly check for DWARF information:

```bash
readelf -S hello_debug | grep debug
```

If no `.debug_*` section appears, the binary was compiled without `-g` or has been stripped.

## The structure of `.debug_info`: DIEs

The heart of DWARF is the `.debug_info` section, organized as a hierarchy of entries called **DIEs** (*Debugging Information Entry*). Each DIE represents an entity of the source program and has a **tag** (its type) and a list of **attributes** (its properties).

### Common tags

| Tag | Represents | Example |  
|---|---|---|  
| `DW_TAG_compile_unit` | A compilation unit (a `.c` file) | `hello.c` |  
| `DW_TAG_subprogram` | A function | `check`, `main` |  
| `DW_TAG_formal_parameter` | A function parameter | `input`, `argc`, `argv` |  
| `DW_TAG_variable` | A variable (local or global) | `counter` |  
| `DW_TAG_base_type` | A primitive type | `int`, `char`, `long` |  
| `DW_TAG_pointer_type` | A pointer type | `const char *` |  
| `DW_TAG_structure_type` | A structure (`struct`) | `struct sockaddr` |  
| `DW_TAG_class_type` | A C++ class | `class MyClass` |  
| `DW_TAG_enumeration_type` | An enumerated type | `enum Color` |  
| `DW_TAG_typedef` | A type alias | `typedef unsigned int uint32_t` |  
| `DW_TAG_array_type` | An array type | `int buffer[1024]` |  
| `DW_TAG_lexical_block` | A scope block (`{ ... }`) | Inner block of an `if` |  
| `DW_TAG_inlined_subroutine` | A function that has been inlined | `check` inlined into `main` |

### Common attributes

| Attribute | Meaning | Example value |  
|---|---|---|  
| `DW_AT_name` | Name of the entity | `"check"` |  
| `DW_AT_type` | Reference to the DIE describing the type | `→ DIE #0x4a (int)` |  
| `DW_AT_low_pc` | Start address in memory | `0x1149` |  
| `DW_AT_high_pc` | End address (or size) | `0x1172` (or size: `41`) |  
| `DW_AT_decl_file` | Source file of declaration | `hello.c` |  
| `DW_AT_decl_line` | Line of declaration | `6` |  
| `DW_AT_location` | Variable location (register, stack, expression) | `DW_OP_fbreg -24` (stack, rbp-24) |  
| `DW_AT_encoding` | Encoding of a primitive type | `DW_ATE_signed` (signed integer) |  
| `DW_AT_byte_size` | Size in bytes | `4` (for an `int`) |  
| `DW_AT_comp_dir` | Compilation directory | `/home/user/project` |  
| `DW_AT_producer` | Compiler used | `GNU C17 13.2.0 -O0 -g` |  
| `DW_AT_inline` | Inlining indication | `DW_INL_inlined` |

### DIE hierarchy

DIEs are organized as a tree. Each DIE can contain child DIEs, forming a structure that reflects the nesting of the source code:

```
DW_TAG_compile_unit ("hello.c")
├── DW_TAG_base_type ("int", 4 bytes, signed)
├── DW_TAG_base_type ("char", 1 byte, signed)
├── DW_TAG_pointer_type (→ const char)
├── DW_TAG_subprogram ("check")
│   ├── DW_TAG_formal_parameter ("input", type: const char *)
│   │       DW_AT_location: DW_OP_fbreg -24   ← on the stack, rbp-24
│   └── DW_TAG_variable (temporary variable for strcmp's return)
├── DW_TAG_subprogram ("main")
│   ├── DW_TAG_formal_parameter ("argc", type: int)
│   │       DW_AT_location: DW_OP_fbreg -20   ← on the stack, rbp-20
│   ├── DW_TAG_formal_parameter ("argv", type: char **)
│   │       DW_AT_location: DW_OP_fbreg -32   ← on the stack, rbp-32
│   └── DW_TAG_lexical_block
│       └── ...
```

This hierarchy is exactly what Ghidra and GDB leverage to display function names, parameter types, and variable values during debugging.

## Exploring DWARF data in practice

### With `readelf`

The `readelf` tool provides several options to explore DWARF sections:

```bash
# Complete view of .debug_info (verbose — can be very long)
readelf --debug-dump=info hello_debug

# Line ↔ address correspondence table (decoded)
readelf --debug-dump=decodedline hello_debug

# Frame information (stack unwinding)
readelf --debug-dump=frames hello_debug

# Address ranges
readelf --debug-dump=aranges hello_debug
```

The output of `--debug-dump=info` for our `check()` function looks like this (simplified):

```
 <1><0x80>: Abbrev Number: 5 (DW_TAG_subprogram)
    <0x81>   DW_AT_external    : 1
    <0x82>   DW_AT_name        : check
    <0x87>   DW_AT_decl_file   : 1 (hello.c)
    <0x88>   DW_AT_decl_line   : 6
    <0x89>   DW_AT_type        : <0x4a> (int)
    <0x8d>   DW_AT_low_pc      : 0x1149
    <0x95>   DW_AT_high_pc     : 0x29 (size)
    <0x99>   DW_AT_frame_base  : 1 byte block: 56 (DW_OP_reg6 (rbp))
 <2><0x9b>: Abbrev Number: 6 (DW_TAG_formal_parameter)
    <0x9c>   DW_AT_name        : input
    <0x a2>  DW_AT_decl_line   : 6
    <0xa3>   DW_AT_type        : <0x3b> (const char *)
    <0xa7>   DW_AT_location    : 2 byte block: 91 58 (DW_OP_fbreg -24)
```

You can read directly that the `check` function is defined at line 6 of `hello.c`, starts at address `0x1149`, is `0x29` (41) bytes long, returns an `int`, and its `input` parameter (of type `const char *`) is stored on the stack at `rbp - 24`.

### With `objdump`

The `objdump` tool can mix source code with disassembly when DWARF information is present:

```bash
objdump -d -S hello_debug
```

The `-S` flag interleaves lines of source code among the assembly instructions:

```
0000000000001149 <check>:
int check(const char *input) {
    1149:   55                      push   %rbp
    114a:   48 89 e5                mov    %rsp,%rbp
    114d:   48 83 ec 10             sub    $0x10,%rsp
    1151:   48 89 7d f8             mov    %rdi,-0x8(%rbp)
    return strcmp(input, SECRET) == 0;
    1155:   48 8b 45 f8             mov    -0x8(%rbp),%rax
    1159:   48 8d 15 a4 0e 00 00    lea    0xea4(%rip),%rdx
    1160:   48 89 d6                mov    %rdx,%rsi
    1163:   48 89 c7                mov    %rax,%rdi
    1166:   e8 c5 fe ff ff          call   1030 <strcmp@plt>
    116b:   85 c0                   test   %eax,%eax
    116d:   0f 94 c0                sete   %al
    1170:   0f b6 c0                movzbl %al,%eax
}
    1173:   c9                      leave
    1174:   c3                      ret
```

This interleaved view is a valuable learning tool for understanding the C → assembly correspondence. It is also a shortcut for analyzing a binary when you have both the source and the binary (security audit, build verification).

### With `dwarfdump` and `eu-readelf`

For more advanced explorations, two specialized tools complement `readelf`:

- **`dwarfdump`** (package `libdwarf-tools` or `dwarfdump`): tool dedicated to DWARF analysis, with filtering options and a more readable output format than `readelf`.  
- **`eu-readelf`** (package `elfutils`): alternative version of `readelf` developed by Red Hat, often more performant on large DWARF files and with better support for DWARF5.

```bash
# With dwarfdump
dwarfdump --name=check hello_debug      # Search everything about "check"  
dwarfdump --print-lines hello_debug     # Line table  

# With eu-readelf (elfutils)
eu-readelf --debug-dump=info hello_debug
```

## The line table (`.debug_line`)

The line table is one of the most directly useful DWARF sections. It establishes a bidirectional correspondence between each machine address and the source file + line number that generated that instruction.

```bash
readelf --debug-dump=decodedline hello_debug
```

Simplified output:

| Address | File | Line | Column | Flags |  
|---|---|---|---|---|  
| `0x1149` | `hello.c` | 6 | 0 | `is_stmt` |  
| `0x1155` | `hello.c` | 7 | 0 | `is_stmt` |  
| `0x1175` | `hello.c` | 10 | 0 | `is_stmt` |  
| `0x1188` | `hello.c` | 11 | 0 | `is_stmt` |  
| `0x1197` | `hello.c` | 13 | 0 | `is_stmt` |  
| `0x11a3` | `hello.c` | 14 | 0 | `is_stmt` |  
| `0x11a8` | `hello.c` | 16 | 0 | `is_stmt` |

The `is_stmt` (*is statement*) flag indicates that the address corresponds to the start of a source statement (as opposed to intermediate code generated by the compiler). Debuggers use this flag to place breakpoints meaningfully when the user asks "break at line 7".

With optimizations (`-O2 -g`), this table becomes more complex: the same source line can correspond to non-contiguous addresses (the compiler reordered instructions), and the same address can be associated with several lines (merged code).

## Location expressions (`DW_AT_location`)

One of the most sophisticated aspects of DWARF is the system of **variable location**. At each point of the program, a variable can be in different places: in a register, on the stack, in a memory zone, or even exist only partially.

### Simple location

For a binary compiled with `-O0`, locations are stable and simple:

```
DW_AT_location: DW_OP_fbreg -24    → Variable at rbp - 24 (on the stack)  
DW_AT_location: DW_OP_reg0         → Variable in rax  
DW_AT_location: DW_OP_addr 0x4020  → Variable at global address 0x4020  
```

The `DW_OP_*` operations form a small stack machine language that allows arbitrarily complex locations to be described. The most common cases are `DW_OP_fbreg` (offset from the frame base, generally `rbp`) and `DW_OP_reg*` (in a register).

### Location lists (optimized code)

With optimizations, a variable can change location during the execution of a function. DWARF then uses **location lists** in the `.debug_loc` section:

```
Variable "input":
  [0x1149, 0x1151) → DW_OP_reg5 (rdi)        ← in register rdi at entry
  [0x1151, 0x1166) → DW_OP_fbreg -24          ← then saved onto the stack
  [0x1166, 0x1174) → <optimized out>          ← no longer accessible after the call
```

This list reads as: between addresses `0x1149` and `0x1151`, the `input` variable is in register `rdi` (it is the first parameter, according to the System V AMD64 convention). Then it is copied onto the stack. After the call to `strcmp`, it is no longer needed and the compiler has reused its location.

This is the reason for the famous GDB message "`<optimized out>`": the debugger consults the location list and finds that at the current program address, the variable no longer has a defined location.

> 💡 **In RE**: Location lists are an advanced but powerful tool. They reveal exactly which register or stack offset holds each variable at each point in the program. If you are analyzing a `-O2 -g` binary, this information lets you follow values through the compiler's optimizations.

## DWARF and RE tools

### GDB

GDB is the main consumer of DWARF information. In the presence of DWARF, GDB can:

- Display the source code (`list`), set breakpoints by function name or line number (`break check`, `break hello.c:7`).  
- Display variables by their name (`print input`, `info locals`).  
- Display complete types (`ptype struct sockaddr`, `whatis variable`).  
- Produce a readable backtrace with function names and line numbers.  
- Navigate call frames (`frame`, `up`, `down`) with source context.

Without DWARF, GDB still works but in "raw" mode: no names, no types, no source — only addresses, registers, and machine code. Chapter 11 covers both modes of work.

### Ghidra

Ghidra imports DWARF information during the initial analysis of a binary. If DWARF is present, Ghidra automatically applies function names, parameter types, local variable names, and structure definitions to the decompiled code. The result is pseudo-code remarkably close to the original source.

Even in the absence of DWARF in the target binary, you can exploit DWARF indirectly: if the binary uses an open source library (for example OpenSSL), you can compile that library with `-g`, extract the type information (structures, enums, typedefs), and import it into your Ghidra project as type files. This workflow is covered in Chapter 8.

### Valgrind and the sanitizers

Valgrind (Chapter 14) and sanitizers like AddressSanitizer (`-fsanitize=address`) use DWARF information to display readable error messages: name of the corrupted variable, source line of the allocation, call stack with function names. Without DWARF, reports contain only hexadecimal addresses.

## Separate DWARF information

DWARF information is voluminous — it can multiply the binary's size by 3 to 10. For production builds, it is common to **separate** the debug information from the executable binary.

### Separate debug files

GCC and the GNU tools make it possible to extract DWARF information into a separate file:

```bash
# 1. Compile with -g
gcc -O2 -g -o hello hello.c

# 2. Extract the debug info into a separate file
objcopy --only-keep-debug hello hello.debug

# 3. Strip the main binary
strip hello

# 4. Add a link to the debug file (via build-id or .gnu_debuglink section)
objcopy --add-gnu-debuglink=hello.debug hello
```

After this operation, `hello` is stripped (compact) but GDB will automatically find `hello.debug` and load the DWARF information. The link is made either via the **build-id** (`.note.gnu.build-id` section), or via the `.gnu_debuglink` section which contains the name of the debug file and a verification CRC.

### Debug packages of Linux distributions

Linux distributions use exactly this mechanism. For each binary package, a separate `-dbgsym` or `-debuginfo` package contains the `.debug` files:

```bash
# Debian/Ubuntu — install the libc debug symbols
sudo apt install libc6-dbg

# Fedora/RHEL — install the debuginfo
sudo dnf debuginfo-install glibc
```

The files are installed in `/usr/lib/debug/` with a mirrored directory structure. GDB finds them automatically.

### `debuginfod` — On-demand debug server

The `debuginfod` project (integrated with `elfutils`) goes further: instead of installing packages, GDB downloads debug information **on the fly** from an HTTP server using the build-id as a lookup key. Several distributions (Fedora, Ubuntu, Arch, Debian) operate public `debuginfod` servers.

```bash
# Enable debuginfod in GDB (often enabled by default)
export DEBUGINFOD_URLS="https://debuginfod.ubuntu.com"

# GDB will automatically download missing symbols
gdb ./hello
```

> 💡 **In RE**: `debuginfod` servers are an often-overlooked resource. If your target binary uses standard system libraries, `debuginfod` can provide you with the debug information for those libraries for free and automatically. This considerably helps with understanding library calls in GDB. Remember to check whether a `debuginfod` server is available for the target distribution.

## Detail levels with `-g`

The `-g` flag accepts detail levels that control the amount of DWARF information generated:

| Flag | Information generated | Use case |  
|---|---|---|  
| `-g0` | No debug information | Equivalent to not using `-g` |  
| `-g1` | Minimal: line tables and backtrace information, no local variables or types | Production builds with readable backtraces |  
| `-g` or `-g2` | Standard: everything except macros | Normal development and debugging |  
| `-g3` | Complete: adds definitions of preprocessor macros (`#define`) | Advanced debugging, macro analysis |

The `-g3` level is particularly interesting for RE: it preserves the names and values of preprocessor macros, which are normally lost from the preprocessing phase (section 2.1). In GDB, the `macro expand MACRO_NAME` command then displays the value of the macro.

```bash
gcc -O0 -g3 -o hello_g3 hello.c
```

In practice, `-g3` is rarely used in production. But if you have access to the build system (internal audit), requesting a recompilation with `-g3` can save you considerable time.

## `-gsplit-dwarf` — Debug info in `.dwo` files

For large projects, GCC offers the `-gsplit-dwarf` option which separates the DWARF information as early as compilation into `.dwo` (*DWARF Object*) files:

```bash
gcc -O0 -g -gsplit-dwarf -o hello hello.c  
ls hello*.dwo  
# hello.dwo
```

The main binary contains only a DWARF skeleton (minimal `.debug_info` section with references to the `.dwo`), while the bulk of the data is in the `.dwo` file. This speeds up linking on large projects because the linker does not have to process gigabytes of DWARF data.

GDB finds `.dwo` files automatically thanks to the path recorded in the `DW_AT_GNU_dwo_name` attribute.

## Summary: what DWARF brings to the reverse engineer

| DWARF information | What it replaces | RE gain |  
|---|---|---|  
| Function names (`DW_TAG_subprogram`) | Prologue analysis and XREF | Instant identification |  
| Parameter and variable names | Manual tracking of registers/offsets | Direct reading |  
| Complete types (struct, class, enum) | Manual reconstruction of memory layouts | Hours saved |  
| Line-address correspondence | Deducing logic by reading assembly | Source ↔ machine navigation |  
| Variable locations | Dynamic tracing with GDB | `print variable` instead of `x/gx $rbp-0x18` |  
| Inlining information | Guessing which functions were inlined | Complete code map |  
| Compilation path, flags | Inspecting `.comment` and heuristics | Exact build context |  
| Macros (`-g3`) | Unrecoverable without source | Recovering named constants |

**The golden rule**: always check whether DWARF information is available before starting a manual analysis. A few seconds of verification can save you hours of work:

```bash
# Quick check in one command
readelf -S binary | grep -c '\.debug_'
# If > 0: jackpot — DWARF is present
# If 0: check whether a .debug file or a -dbgsym package exists
```

---

> 📖 **We now know what the compiler puts in the binary and how debug information can help RE.** But a binary is useless until it is loaded into memory to be executed. That is the work of the Linux loader, which we will discover in the next section.  
>  
> → 2.7 — The Linux Loader (`ld.so`): from ELF file to process in memory

⏭️ [The Linux Loader (`ld.so`): from ELF file to process in memory](/02-gnu-compilation-chain/07-linux-loader.md)
