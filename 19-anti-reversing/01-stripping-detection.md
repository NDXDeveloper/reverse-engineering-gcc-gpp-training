🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.1 — Stripping (`strip`) and detection

> 🎯 **Objective**: Understand what `strip` removes from an ELF binary, what it leaves intact, how to detect a stripped binary, and what strategies to adopt for analysis despite it.

---

## Stripping, the first line of defense

Stripping is the simplest, quickest-to-apply, and most universally deployed anti-RE technique. Nearly all binaries distributed in production are stripped. It's not a sophisticated technique — it's a standard GNU tool (`strip`, provided with Binutils) — but its impact on the analyst's comfort is considerable.

The principle is straightforward: remove from the ELF file all information not necessary for execution. The binary works exactly the same way, but the analyst loses the landmarks that facilitate code comprehension.

## What `strip` removes

To fully understand stripping's impact, you must distinguish what disappears from what survives.

### The `.symtab` symbol table

This is the most visible loss. The `.symtab` section contains the static symbol table: function names, global variable names, source file names. After stripping, this entire section is deleted.

Concretely, where `objdump -d` displayed:

```
0000000000401156 <verify_password>:
  401156:  55                    push   rbp
  401157:  48 89 e5              mov    rbp,rsp
```

It will now show:

```
  401156:  55                    push   rbp
  401157:  48 89 e5              mov    rbp,rsp
```

The function still exists at the same location, with the same code — but it no longer has a name. In Ghidra, it will appear as `FUN_00401156`. The analyst must name it manually by understanding what it does.

### DWARF debug information

The `.debug_info`, `.debug_abbrev`, `.debug_line`, `.debug_str`, `.debug_ranges` sections and other DWARF sections are entirely removed. These sections contained:

- The correspondence between addresses and source code lines  
- Names and types of local variables  
- Definitions of structures, unions, and enumerations  
- Information about each function's parameters  
- The scope tree (lexical scopes)

This is a massive loss for debugging. Without DWARF, GDB can no longer display variables by name or show the corresponding source line. The analyst works exclusively with registers, memory addresses, and assembly code.

### The `.comment` section

This section generally contains the compiler version used (e.g., `GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0`). Useful for the analyst, useless for execution — `strip` removes it.

### The `.note.*` note sections

Some note sections (`.note.gnu.build-id` may survive depending on options) are removed. The Build ID is sometimes preserved as the loader may use it.

## What `strip` does NOT remove

This is where the analyst regains hope. Several categories of information survive stripping because they're necessary for execution.

### The dynamic symbol table `.dynsym`

This is the crucial point. Dynamic symbols — those needed by the dynamic linker (`ld.so`) to resolve shared library calls — are **not** touched by `strip`. These symbols live in the `.dynsym` section, not in `.symtab`.

This means that after stripping, you still see:

- Names of all functions imported from shared libraries (`printf`, `strcmp`, `malloc`, `ptrace`, `fopen`…)  
- Names of functions exported by the binary (if it exports any)  
- Associated PLT/GOT entries

This is a gold mine. Seeing a call to `ptrace` in `.dynsym` immediately reveals an anti-debug technique. Seeing `AES_encrypt` betrays encryption usage. Dynamic symbols tell the binary's story even when static symbols have been erased.

### The `.rodata` string constants

The `.rodata` (read-only data) section contains the program's literal strings: error messages, prompts, `printf` format strings, file paths. `strip` doesn't touch `.rodata` because these data are referenced by the code.

This is why `strings` remains useful after stripping. A message like `"Error: non-conforming environment."` in our training binary immediately hints at the presence of an anti-debug check.

### The `.text` executable code

Obviously, the machine code itself is intact. Instructions, jump addresses, program logic — everything is there. Stripping doesn't modify a single instruction. The analyst can still disassemble, set breakpoints, trace execution.

### The `.plt`, `.got`, `.init`, `.fini` sections

All dynamic linking machinery remains in place. PLT stubs, the GOT table, constructors and destructors — everything needed at runtime survives.

### ELF headers and remaining section table

ELF headers (ELF header, program headers) are intact. The section header table is reduced — entries for removed sections disappear — but remaining sections keep their names.

## `strip` variants

The `strip` tool accepts several levels of aggressiveness:

### `strip` (default)

Removes `.symtab`, DWARF debug sections, `.comment`, and non-essential note sections. This is the standard stripping you'll encounter most often.

```bash
strip anti_reverse_debug -o anti_reverse_stripped
```

### `strip --strip-all` (`-s`)

Equivalent to the default option in most cases, but explicit. Removes everything not necessary for execution.

### `strip --strip-debug` (`-g`)

Removes only DWARF debug sections, but preserves the `.symtab` table. You lose the source code correspondence but keep function names. This is a compromise sometimes used for binaries distributed with minimal debug support.

### `strip --strip-unneeded`

Removes symbols not needed for relocation processing. More selective than `--strip-all`: it may preserve certain necessary global symbols.

### GCC's `-s` flag

You can also strip directly at compilation:

```bash
gcc -s -o program program.c
```

This is equivalent to compiling then calling `strip` on the result. The `-s` flag is passed to the linker (`ld`), which removes symbols at the linking stage.

## Detecting a stripped binary

Identifying a stripped binary is quick. Several complementary methods ensure certainty.

### With `file`

The `file` command explicitly indicates whether a binary is stripped:

```bash
$ file anti_reverse_debug
anti_reverse_debug: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
for GNU/Linux 3.2.0, with debug_info, not stripped  

$ file anti_reverse_stripped
anti_reverse_stripped: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
for GNU/Linux 3.2.0, stripped  
```

The key mentions are `not stripped`, `stripped`, and `with debug_info`. A binary can be `not stripped` without having debug information (compiled without `-g` but without being stripped).

### With `readelf -S`

Check for the presence or absence of revealing sections:

```bash
$ readelf -S anti_reverse_debug | grep -E '\.symtab|\.debug|\.comment'
  [29] .comment          PROGBITS  ...
  [30] .symtab           SYMTAB    ...
  [31] .strtab           STRTAB    ...
  [32] .debug_info       PROGBITS  ...
  [33] .debug_abbrev     PROGBITS  ...
  ...

$ readelf -S anti_reverse_stripped | grep -E '\.symtab|\.debug|\.comment'
  (no results)
```

The total absence of `.symtab` and `.debug_*` sections confirms stripping.

### With `nm`

The `nm` tool displays symbols. On a stripped binary, it says so clearly:

```bash
$ nm anti_reverse_stripped
nm: anti_reverse_stripped: no symbols
```

However, `nm -D` (dynamic symbols) still works. Let's compare the variant without anti-debug protections and the one with all protections:

```bash
$ nm -D anti_reverse_stripped
                 U explicit_bzero@GLIBC_2.25
                 U fgets@GLIBC_2.2.5
                 U fprintf@GLIBC_2.2.5
                 U fflush@GLIBC_2.2.5
                 U printf@GLIBC_2.2.5
                 U signal@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
                 U __stack_chk_fail@GLIBC_2.4

$ nm -D anti_reverse_all_checks
                 U clock_gettime@GLIBC_2.17
                 U explicit_bzero@GLIBC_2.25
                 U fgets@GLIBC_2.2.5
                 U fopen@GLIBC_2.2.5
                 U fprintf@GLIBC_2.2.5
                 U fflush@GLIBC_2.2.5
                 U printf@GLIBC_2.2.5
                 U ptrace@GLIBC_2.2.5
                 U signal@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
                 U strncmp@GLIBC_2.2.5
                 U strtol@GLIBC_2.2.5
                 U __stack_chk_fail@GLIBC_2.4
```

The difference is striking. The variant with anti-debug protections imports `ptrace`, `fopen`, `clock_gettime`, `strncmp`, `strtol` — functions absent from the clean variant. The presence of `ptrace` in dynamic imports is a major clue, even on a stripped binary.

### With file size

A simple but often overlooked indicator. The size difference between a binary with symbols and its stripped version is significant:

```bash
$ ls -la anti_reverse_debug anti_reverse_stripped
-rwxr-xr-x 1 user user  23456  anti_reverse_debug
-rwxr-xr-x 1 user user  14832  anti_reverse_stripped
```

A binary that weighs noticeably less than expected for its apparent complexity has probably been stripped. If it also contained DWARF information (`-g`), the difference can reach a factor of 3 to 5.

## Analysis strategies for a stripped binary

Stripping makes analysis slower, but not impossible. Here are the approaches to adopt.

### Exploit dynamic symbols

As seen above, `.dynsym` survives. PLT calls remain named in the disassembly. A call to `call printf@plt` is still readable. The analyst can trace back from known library functions to understand the logic: if a function calls `fopen`, `fread` then `fclose`, it's probably a file reading routine.

### Exploit string constants

The `strings` tool combined with cross-references in Ghidra allows finding interesting functions. If you're looking for the password verification routine, search for the string `"Password"` in `.rodata`, then find which function references it via XREF.

### Progressive renaming in the disassembler

In Ghidra, IDA, or Cutter, rename each function as you understand its role. Start from functions you identify with certainty (those calling known library functions with recognizable strings) and work up the call graph.

### Library function signatures

Tools like FLIRT (IDA) or Ghidra signatures allow automatically identifying standard library functions that may have been statically linked. If the binary is dynamically linked, libc functions are already named via PLT. If the binary is static, these signatures become essential to avoid wasting time reversing `memcpy` or `strlen`.

### Recovering symbols from a separate debug file

Some Linux distributions provide `*-dbg` or `*-dbgsym` packages containing debug information in a separate file (`.debug`). GDB can load these files automatically via the Build ID. If the target binary is packaged software whose version is identifiable, this approach can restore all symbols.

```bash
# Find the Build ID
readelf -n target_binary | grep "Build ID"

# GDB automatically searches in /usr/lib/debug/
gdb ./target_binary
```

## Impact of stripping on our training binaries

The chapter's Makefile produces two variants directly related to this section:

- **`anti_reverse_debug`** — Compiled with `-O0 -g`, not stripped. Contains symbols, DWARF, all analyst comforts. This is the reference version.  
- **`anti_reverse_stripped`** — Compiled with `-O2`, stripped. Anti-debug protections are disabled to isolate the stripping effect alone.

Comparing these two variants with `readelf -S`, `nm`, `file`, and `checksec` is the natural starting point for internalizing what `strip` changes — and especially what it doesn't change.

---


⏭️ [Packing with UPX — detecting and decompressing](/19-anti-reversing/02-packing-upx.md)
