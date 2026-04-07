🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Checkpoint Solution — Chapter 2

> **Exercise**: Compile `hello.c` with `-O0 -g` (debug) and `-O2 -s` (release), then compare sizes, sections and symbols with `readelf`.

---

## Compilation

```bash
cd binaries/ch02-hello  
gcc -O0 -g -o hello_debug hello.c  
gcc -O2 -s -o hello_release hello.c  
```

Functional verification:

```bash
./hello_debug RE-101    # → Access granted.
./hello_release RE-101  # → Access granted.
```

---

## Step 1 — Sizes

```bash
ls -lh hello_debug hello_release
```

| Variant | Size |  
|---------|------|  
| `hello_debug` | ~18 KB |  
| `hello_release` | ~15 KB |

The debug binary is about 20% larger, mainly due to `.debug_*` sections and complete symbol tables (`.symtab`, `.strtab`).

```bash
size hello_debug hello_release
```

| Variant | `.text` | `.data` | `.bss` |  
|---------|---------|---------|--------|  
| `hello_debug` | 1789 | 616 | 8 |  
| `hello_release` | 1775 | 616 | 8 |

The release `.text` section is slightly smaller (more compact optimized code). The `.data` and `.bss` sections are identical since global data doesn't change.

---

## Step 2 — Number of Sections

```bash
readelf -S hello_debug | grep -c '\['    # → 38  
readelf -S hello_release | grep -c '\['  # → 30  
```

The debug build has **38 sections**, the release **30**. The difference of 8 sections corresponds to `.debug_*` sections and non-dynamic symbol tables.

---

## Step 3 — `.debug_*` Sections

```bash
readelf -S hello_debug | grep debug
```

The debug build contains **6 DWARF sections**:
- `.debug_aranges` — address ranges per compilation unit  
- `.debug_info` — main debugging information (types, functions, variables)  
- `.debug_abbrev` — abbreviations used in `.debug_info`  
- `.debug_line` — address → source line correspondence  
- `.debug_str` — strings used in DIEs  
- `.debug_line_str` — additional strings for file names

```bash
readelf -S hello_release | grep debug
# No output
```

The release build contains **no debug sections** — they were never generated (no `-g` flag).

---

## Step 4 — Symbol Tables

```bash
readelf -S hello_debug | grep -E 'symtab|strtab'
```

| Section | Debug | Release |  
|---------|-------|---------|  
| `.symtab` | ✅ Present | ❌ Removed by `-s` |  
| `.strtab` | ✅ Present | ❌ Removed by `-s` |  
| `.shstrtab` | ✅ Present | ✅ Present (section names, always needed) |

```bash
readelf -s hello_debug | grep -w check
#    34: 0000000000001189    48 FUNC    GLOBAL DEFAULT   16 check
```

The `check` function is visible by name in the debug build.

```bash
readelf -s hello_release
# No output (no .symtab)
```

The `check` function is no longer identifiable by name in the release build.

**But dynamic symbols survive in both cases:**

```bash
readelf --dyn-syms hello_release | grep FUNC
# puts, strcmp, printf (imports from libc) — still visible
```

This is the key point: `-s` removes `.symtab` (your internal functions) but **preserves** `.dynsym` (functions imported from `.so` files). Import names like `strcmp`, `puts`, `printf` remain available for RE even on a stripped binary.

---

## Step 5 — Type and Protections

```bash
file hello_debug
# ELF 64-bit LSB pie executable, x86-64, [...], with debug_info, not stripped

file hello_release
# ELF 64-bit LSB pie executable, x86-64, [...], stripped
```

Both binaries are **PIE executables** (modern GCC default). The visible difference: `not stripped` vs `stripped`, and `with debug_info` in the debug build.

Protections (PIE, NX, RELRO) are identical — they don't depend on `-O` or `-g`/`-s`.

---

## Step 6 — Disassembly

```bash
objdump -d hello_debug | grep '<check>'
# 0000000000001189 <check>:
# (48 bytes, classic push rbp / mov rbp,rsp prologue)
```

The `check` function is present as a separate function in the debug build.

```bash
objdump -d hello_release | grep 'check'
# (no results)
```

In the release build (`-O2`), the `check` function was **inlined** into `main` by the optimizer. The `strcmp` call ends up directly in `main`'s body, without a dedicated `call check`. Additionally, since symbols were removed by `-s`, no `<check>` label appears.

---

## Step 7 — DWARF Information

```bash
readelf --debug-dump=info hello_debug | head -20
# Compile Unit, DW_TAG_subprogram "check", types, lines...

readelf --debug-dump=decodedline hello_debug | head -10
# Correspondence table: address → hello.c line 22, 23, 26...
```

The debug build contains the complete correspondence between each machine instruction and the corresponding source line.

```bash
readelf --debug-dump=info hello_release 2>&1
# Error: Section '.debug_info' was not dumped because it does not exist!
```

The release build has no DWARF information.

---

## Step 8 — What Remains Exploitable in the Release

```bash
strings hello_release | grep -E 'RE-101|Usage|granted|denied'
# RE-101
# Usage: %s <password>
```

The password `RE-101` is **still visible in plaintext** via `strings`. Stripping removes function and variable names but does not hide constant data in `.rodata`.

```bash
readelf -p .comment hello_release
# GCC: (Ubuntu ...) ...
```

The compiler version remains available in `.comment`.

```bash
readelf -d hello_release | grep NEEDED
# [NEEDED] libc.so.6
```

Dependencies are still readable.

---

## Completed Summary Table

| Criterion | `hello_debug` (`-O0 -g`) | `hello_release` (`-O2 -s`) |  
|---|---|---|  
| Binary size | ~18 KB | ~15 KB |  
| Number of sections | 38 | 30 |  
| `.debug_*` sections | ✅ Present (6 sections) | ❌ Absent |  
| `.symtab` / `.strtab` | ✅ Present | ❌ Removed (strip) |  
| `.dynsym` / `.dynstr` | ✅ Present | ✅ Present |  
| `file` says | `not stripped`, `with debug_info` | `stripped` |  
| `check` function visible by name | ✅ Yes (`readelf -s`) | ❌ No |  
| `check` function exists as a function | ✅ Yes (not inlined at `-O0`) | ❌ Inlined into `main` by `-O2` |  
| `"RE-101"` string visible with `strings` | ✅ Yes | ✅ Yes |  
| Import names (`strcmp`, `puts`...) | ✅ Yes (`.dynsym`) | ✅ Yes (`.dynsym`) |  
| Compiler version (`.comment`) | ✅ Yes | ✅ Yes |

---

## What This Checkpoint Demonstrates

1. **Compilation flags** radically determine what is available to the reverse engineer, even from identical source code.  
2. **DWARF** (flag `-g`) is the richest source of information — and the first to disappear in production.  
3. **Stripping** (flag `-s`) removes `.symtab` but preserves `.dynsym` — imported function names remain accessible.  
4. **Optimization** (flag `-O2`) can eliminate entire functions through inlining, modifying the visible code structure.  
5. **Constant data** (`.rodata`) survives all transformations — `strings` remains a first-resort tool.  
6. **Dynamic mechanisms** (PLT/GOT, dynamic symbols) are essential at runtime and cannot be removed.

---

⏭️ [Chapter 3 — x86-64 Assembly Basics for RE](/03-x86-64-assembly/README.md)
