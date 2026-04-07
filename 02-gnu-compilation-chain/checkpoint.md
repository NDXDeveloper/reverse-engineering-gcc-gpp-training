🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Chapter 2 Checkpoint — Compile, compare, understand

> **Goal**: Validate your understanding of the GNU compilation chain by compiling the same program under two extreme configurations and concretely analyzing the differences with `readelf`.

---

## Context

Throughout this chapter, we have seen how compilation flags transform the produced binary: the sections present, the amount of information available, the readability of the machine code. This checkpoint asks you to verify it yourself by comparing two diametrically opposed builds:

| Variant | Flags | Philosophy |  
|---|---|---|  
| **Debug build** | `-O0 -g` | Maximum information, no optimization — the reverse engineer's dream |  
| **Release build** | `-O2 -s` | Optimized and stripped — the daily reality of RE |

## Source

Use the `hello.c` running example of the chapter (available in `binaries/ch02-hello/`):

```c
/* hello.c — running example of Chapter 2 */
#include <stdio.h>
#include <string.h>

#define SECRET "RE-101"

int check(const char *input) {
    return strcmp(input, SECRET) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    if (check(argv[1])) {
        printf("Access granted.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
```

## Step 1 — Compile both variants

```bash
gcc -O0 -g -o hello_debug hello.c  
gcc -O2 -s -o hello_release hello.c  
```

Check that both binaries work:

```bash
./hello_debug RE-101
# Access granted.

./hello_release RE-101
# Access granted.
```

Behavior is identical. It is the **metadata and internal structure** that differ.

## Step 2 — Compare sizes

```bash
ls -lh hello_debug hello_release
```

**What you should observe**: the debug binary is significantly larger than the release binary — often 2 to 4 times bigger. Most of this difference comes from the `.debug_*` sections (DWARF information) present in the debug build and absent from the release build.

Also measure with `size`, which displays the sizes of code and data sections:

```bash
size hello_debug hello_release
```

The `size` command shows the sizes of `.text`, `.data`, and `.bss` — the sections that count for the effective code and data. You will notice that the release build's `.text` section is slightly smaller (optimized, more compact code) despite an overall smaller binary thanks to the absence of debug info and symbols.

## Step 3 — Compare the sections

List the sections of both binaries:

```bash
readelf -S hello_debug > sections_debug.txt  
readelf -S hello_release > sections_release.txt  
diff sections_debug.txt sections_release.txt  
```

**What you should observe:**

The debug build contains sections absent from the release build. Count the sections in each binary:

```bash
readelf -S hello_debug | grep -c '\['  
readelf -S hello_release | grep -c '\['  
```

The debug build typically has 30 to 40 sections, the release build between 25 and 30. The sections missing from the release are mainly:

- **The `.debug_*` sections** (`.debug_info`, `.debug_abbrev`, `.debug_line`, `.debug_str`, `.debug_aranges`, `.debug_frame`, `.debug_loc`, `.debug_ranges`…) — absent because `-g` was not used.  
- **`.symtab` and `.strtab`** — removed by the `-s` flag (stripping). These are the non-dynamic symbol tables.

Verify explicitly:

```bash
# Debug sections
readelf -S hello_debug | grep debug
# Should list 6-10 .debug_* sections

readelf -S hello_release | grep debug
# No result

# Symbol tables
readelf -S hello_debug | grep -E 'symtab|strtab'
# .symtab and .strtab present

readelf -S hello_release | grep -E 'symtab|strtab'
# Only .dynstr and .shstrtab — no .symtab
```

## Step 4 — Compare the symbols

```bash
# Debug build: complete symbols
readelf -s hello_debug | grep FUNC
# You should see: check, main, and CRT/libc functions

# Release build: symbols removed
readelf -s hello_release
# No output (no .symtab)

# But dynamic symbols survive in both cases:
readelf --dyn-syms hello_debug | grep FUNC  
readelf --dyn-syms hello_release | grep FUNC  
# strcmp, printf, puts... visible in both binaries
```

**Key point to remember**: stripping (`-s`) removes `.symtab` (names of your internal functions) but preserves `.dynsym` (names of functions imported from `.so` files). This is the principle seen in section 2.5.

## Step 5 — Compare type and protections

```bash
file hello_debug  
file hello_release  
```

Both binaries should be of type `PIE executable` (that is the modern GCC default). The visible difference in `file` is the `not stripped` (debug) vs `stripped` (release) mention.

If `checksec` is installed:

```bash
checksec --file=hello_debug  
checksec --file=hello_release  
```

The protections (PIE, NX, RELRO, canary) are identical — they do not depend on `-O` or on `-g`/`-s` but on dedicated flags (`-pie`, `-fstack-protector`, `-Wl,-z,relro,-z,now`).

## Step 6 — Compare the disassembly

```bash
# Debug build: the check function is identifiable by its name
objdump -d hello_debug | grep -A 20 '<check>'
# Classic prologue push rbp / mov rbp,rsp, variables on the stack

# Release build: is check still visible?
objdump -d hello_release | grep '<check>'
```

**What you should observe**: in the release build, the `check` function may have disappeared as a named symbol (because stripped), but above all it may have been **inlined** into `main` by the `-O2` optimizer. If that is the case, the code of `check` (the call to `strcmp` and the comparison) is found directly in the body of `main`, without a dedicated `call`.

To compare the size of `main`'s code in both variants:

```bash
# Number of instructions in main (debug)
objdump -d hello_debug | sed -n '/<main>/,/^$/p' | grep -cE '^\s+[0-9a-f]+:'

# In release, main has no named label (stripped).
# We can count the total instructions of .text:
objdump -d -j .text hello_debug | grep -cE '^\s+[0-9a-f]+:'  
objdump -d -j .text hello_release | grep -cE '^\s+[0-9a-f]+:'  
```

The release build typically contains fewer instructions overall — the code is more compact thanks to optimizations.

## Step 7 — Compare DWARF information

```bash
# Debug build: complete DWARF
readelf --debug-dump=info hello_debug | head -40
# You see the DIEs: DW_TAG_compile_unit, DW_TAG_subprogram "check", types, lines...

readelf --debug-dump=decodedline hello_debug | head -20
# Address → source line correspondence table

# Release build: nothing
readelf --debug-dump=info hello_release 2>&1
# readelf: Error: Section '.debug_info' was not dumped because it does not exist!
```

The debug build contains the complete correspondence between each machine instruction and the matching source line. The release build has no trace of it.

## Step 8 — Check what remains exploitable in the release build

Even in the stripped and optimized binary, some information remains and is exploitable in RE:

```bash
# Literal strings in .rodata
strings hello_release | grep -E 'RE-101|Usage|granted|denied'
# RE-101, the usage and access messages are still there!

# The .comment section (compiler version)
readelf -p .comment hello_release
# GCC: (Ubuntu XX.X.X) XX.X.X

# The required libraries
readelf -d hello_release | grep NEEDED
# libc.so.6

# The RELRO level
readelf -d hello_release | grep -E 'BIND_NOW|FLAGS'
```

The password `RE-101` is still visible in clear via `strings` — stripping removes function and variable names, but does not encrypt or mask the constant data in `.rodata`. That is why `strings` is one of the first tools of the quick triage workflow (Chapter 5).

## Expected synthesis

At the end of this checkpoint, you should be able to fill in this table from memory:

| Criterion | `hello_debug` (`-O0 -g`) | `hello_release` (`-O2 -s`) |  
|---|---|---|  
| Binary size | __ KB | __ KB |  
| Number of sections | __ | __ |  
| `.debug_*` sections | ✅ Present (__ sections) | ❌ Absent |  
| `.symtab` / `.strtab` | ✅ Present | ❌ Removed (strip) |  
| `.dynsym` / `.dynstr` | ✅ Present | ✅ Present |  
| `file` says | `not stripped` | `stripped` |  
| `check` function visible by name | ✅ Yes | ❌ No |  
| `check` exists as a function | ✅ Yes (not inlined) | ⚠️ Probably inlined |  
| `"RE-101"` string visible with `strings` | ✅ Yes | ✅ Yes |  
| Import names (`strcmp`, `puts`…) | ✅ Yes | ✅ Yes |

Fill it in with your own measured values. If your observations match the expected pattern, you master the fundamentals of this chapter.

## What this checkpoint demonstrates

This simple comparison exercise illustrates the full spectrum seen in this chapter:

1. **The compilation chain** (section 2.1) produces a different binary depending on the flags, even though the source is identical.  
2. **Intermediate files** (section 2.2) — if you add `-save-temps`, you can compare the `.s` files of both builds and observe the optimizer's transformations.  
3. **The ELF format** (sections 2.3–2.4) organizes the content into sections whose presence depends on the compilation options.  
4. **Compilation flags** (section 2.5) are the main lever that determines the difficulty of an RE analysis.  
5. **DWARF** (section 2.6) is the richest source of information — and the first to disappear in a production build.  
6. **Dynamic mechanisms** (sections 2.7–2.9) — PLT/GOT, dynamic symbols — survive stripping because they are essential at runtime.

---

> ✅ **Checkpoint validated?** You are ready to tackle Chapter 3, where we will learn to read the x86-64 assembly code you saw in the disassemblies of this chapter.  
>  
> → Chapter 3 — x86-64 Assembly Basics for RE

⏭️ [Chapter 3 — x86-64 Assembly Basics for RE](/03-x86-64-assembly/README.md)
