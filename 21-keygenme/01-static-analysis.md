🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.1 — Complete Static Analysis of the Binary (Triage, Strings, Sections)

> 📖 **Reminder**: this section applies the "5-minute quick triage" workflow presented in chapter 5 (section 5.7). If the approach seems unclear, reread it before continuing.

---

## Introduction

When facing an unknown binary, the temptation to immediately open it in Ghidra is strong. This is a common mistake among beginners. A methodical triage of a few minutes provides an indispensable mental framework: you know *what you are analyzing* before diving into the *how*. This first phase is entirely passive — the binary is never launched, never modified, only observed.

In this section, we apply this triage to the `keygenme_O0` variant (compiled with `-O0 -g`, symbols present). The results will serve as a reference for comparison with the optimized and stripped variants in the following sections.

---

## Step 1 — `file`: format identification

The very first command to run on an unknown binary is `file`. It identifies the file format by analyzing its magic bytes and headers, without ever executing it.

```bash
$ file keygenme_O0
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, with debug_info, not stripped  
```

Each element of this output is exploitable information:

| Fragment | Significance for RE |  
|---|---|  
| `ELF 64-bit LSB` | ELF format, 64-bit architecture, little-endian. We are working in x86-64 with 64-bit registers (`rax`, `rdi`...) and the System V AMD64 calling convention. |  
| `pie executable` | Position-Independent Executable — addresses in the disassembly are relative offsets. In dynamic analysis (GDB), absolute addresses will change on each execution if ASLR is active. |  
| `dynamically linked` | The binary depends on shared libraries (at minimum libc). We expect to find a `.plt`/`.got` section and calls via `call xxx@plt`. |  
| `interpreter /lib64/ld-linux-x86-64.so.2` | The standard Linux dynamic linker. Confirms a classic GNU/Linux binary. |  
| `with debug_info` | DWARF information is present — Ghidra and GDB will be able to display original function names, variables, and types. |  
| `not stripped` | The symbol table (`.symtab`) is intact. `nm` will list all functions. |

> 💡 **Key takeaway**: the mention `with debug_info, not stripped` is a luxury in RE. On a real target, this information is almost always absent. Here, it serves as a reference point. We will see in section 21.3 how to work without it on `keygenme_strip`.

### Quick comparison with the stripped variant

To measure the difference, let's apply the same command to `keygenme_strip`:

```bash
$ file keygenme_strip
keygenme_strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped  
```

The `with debug_info` mention has disappeared and `stripped` replaces `not stripped`. The format, architecture, and linking are identical — only the amount of information available to the analyst has changed. This is exactly the role of stripping seen in chapter 19.

---

## Step 2 — `strings`: extracting readable strings

The `strings` command extracts all printable ASCII character sequences of a minimum length (default 4). This is often the most revealing triage step: error messages, prompts, function names, constants, file paths — everything the developer left in plaintext.

```bash
$ strings keygenme_O0
```

Among the hundreds of returned strings (many of which come from libc and ELF metadata), some stand out:

```
=== KeyGenMe v1.0 — RE Training ===
Enter username:  
Enter license key (XXXX-XXXX-XXXX-XXXX):  
[+] Valid license! Welcome, %s.
[-] Invalid license. Try again.
[-] Username must be between 3 and 31 characters.
%04X-%04X-%04X-%04X
```

### Analysis of each string

**`=== KeyGenMe v1.0 — RE Training ===`** — The program banner. It confirms we are facing a crackme/keygenme. The name and version can be useful for open source searches on a real target.

**`Enter username:` and `Enter license key (XXXX-XXXX-XXXX-XXXX):`** — User prompts. They reveal the expected key format: four groups of four characters separated by dashes. This is crucial information: the key is 19 characters in hexadecimal format.

**`[+] Valid license! Welcome, %s.`** — The success message. The `%s` indicates a call to `printf` (or `sprintf`) with the username as parameter. In static analysis in Ghidra, we can search for the cross-reference to this string to go directly to the "success" branch of the code.

**`[-] Invalid license. Try again.`** — The failure message. Same strategy: its cross-reference leads to the "failure" branch. The fork between the two branches is the conditional jump we seek to identify (section 21.4).

**`[-] Username must be between 3 and 31 characters.`** — A length check on the username. We deduce that the program validates the input before proceeding to key verification. In RE, this information helps understand the flow: username validation → key computation/verification → result.

**`%04X-%04X-%04X-%04X`** — A `printf`/`snprintf` format. Four hexadecimal values of 4 digits (`04X` means: unsigned integer in uppercase hexadecimal, padded to 4 characters with zeros). This string is a major clue: it reveals that the program internally *builds* a string in `XXXX-XXXX-XXXX-XXXX` format, probably the expected key, before comparing it to the user input.

### Filtering noise

The raw output of `strings` contains a great deal of noise (section names, linker paths, DWARF symbols...). Some tips for filtering:

```bash
# Strings of 8 characters minimum (eliminates short noise)
$ strings -n 8 keygenme_O0

# Search for specific patterns
$ strings keygenme_O0 | grep -i "license\|key\|valid\|invalid\|password\|serial"

# Strings in the .rodata section only (read-only data)
$ strings -t x keygenme_O0 | head -40
```

The `-t x` option adds the hexadecimal offset of each string in the file. This offset is valuable: it can be found in ImHex or in the disassembly to identify exactly which function references this string.

### What `strings` does not show

It is important to keep in mind the limitations of `strings`:

- **Encoded or encrypted** strings will not appear (simple XOR, base64, AES encryption...). We will see this issue in chapter 24.  
- **Dynamically built** strings (character by character on the stack) escape `strings`. This is a lightweight but effective obfuscation technique.  
- **Unicode** strings (UTF-16) require the `-e l` option (16-bit little-endian) to be detected.

On our keygenme, all strings are in plaintext ASCII — this is intentional for learning purposes.

---

## Step 3 — `readelf`: anatomy of the ELF binary

After identification with `file` and string extraction, we examine the internal structure of the ELF binary. The `readelf` command allows inspecting headers, sections, and segments without disassembling.

### ELF header

```bash
$ readelf -h keygenme_O0
```

Essential fields to note:

- **Type**: `DYN (Position-Independent Executable)` — confirms PIE, consistent with `file`.  
- **Entry point address**: the entry point address (`_start`, not `main`). In PIE, this is a relative offset (typically `0x1080` or similar). Useful for finding the start of execution in a stripped binary.  
- **Number of section headers**: the number of sections. A non-stripped binary typically has between 25 and 35; a stripped binary loses several.

### Section table

```bash
$ readelf -S keygenme_O0
```

This command displays all sections of the binary. On a keygenme compiled with GCC, the sections relevant to RE are:

| Section | Role | RE interest |  
|---|---|---|  
| `.text` | Executable code (machine instructions) | This is where all the program logic lives: `main`, `check_license`, `compute_hash`... |  
| `.rodata` | Read-only data (constants, strings) | The strings found by `strings` reside here. Numeric constants too (hash seeds, XOR masks). |  
| `.data` | Initialized global variables | Rarely interesting on a small program, but can contain tables or keys on a more complex target. |  
| `.bss` | Uninitialized global variables | Allocated in memory but absent from the file (zero size on disk). |  
| `.plt` / `.plt.sec` | Procedure Linkage Table | Redirection stubs to library functions (`printf`, `strcmp`, `strlen`...). Each `call xxx@plt` goes through here. |  
| `.got` / `.got.plt` | Global Offset Table | Table of dynamically resolved addresses. In Full RELRO, it is read-only after loading. |  
| `.symtab` | Symbol table | Names of all functions and variables. Absent after `strip`. |  
| `.strtab` | Symbol string table | Names referenced by `.symtab`. |  
| `.debug_info` | DWARF information | Types, local variables, line numbers. Present only with `-g`. |

> 💡 **Key point**: the size of `.text` gives an idea of code complexity. Compare:  
> ```  
> keygenme_O0        .text: ~0x50B bytes  
> keygenme_O2        .text: ~0x31C bytes  (more compact code after optimization)  
> keygenme_O3        .text: ~0x31C bytes  (same size as -O2 here; on more complex loops, -O3 can be larger due to unrolling)  
> ```  
> Exact sizes depend on the GCC version, but the trend is consistent: `-O2` compacts the code, `-O3` can inflate it due to loop unrolling and vectorization (chapter 16).

### Segments (Program Headers)

```bash
$ readelf -l keygenme_O0
```

Segments describe how the loader maps the file into memory. The most important ones:

- **LOAD (R-X)**: the executable segment (contains `.text`, `.plt`). Permissions: read + execute, no write. NX is active.  
- **LOAD (RW-)**: the data segment (contains `.data`, `.bss`, `.got`). Permissions: read + write, no execute.  
- **INTERP**: dynamic linker path (`/lib64/ld-linux-x86-64.so.2`).  
- **GNU_RELRO**: indicates the segment that becomes read-only after relocation (partial or full RELRO).  
- **GNU_STACK**: stack permissions. If `RWE` is absent (no `E` flag), NX protects the stack.

The strict separation between executable segments (no write) and writable segments (no execute) is the foundation of NX protection. We will confirm this with `checksec` in section 21.2.

---

## Step 4 — `nm`: symbol inventory

On a non-stripped binary, `nm` lists all functions and global variables with their addresses and types.

```bash
$ nm keygenme_O0 | grep ' [Tt] '
```

The `[Tt]` filter selects "text" type symbols (functions). We expect to find:

```
0000000000001209 t rotate_left
0000000000001229 t compute_hash
00000000000012d8 t derive_key
0000000000001358 t format_key
00000000000013d1 t check_license
0000000000001460 t read_line
00000000000014e1 T main
```

The lowercase `t` indicates a `static` function (local file visibility), while the uppercase `T` of `main` indicates a global symbol. All internal functions (`rotate_left`, `compute_hash`, `derive_key`, `format_key`, `check_license`, `read_line`) are static — a common choice in C that limits symbol exposure.

> ⚠️ **Note**: on `keygenme_strip`, this command returns nothing:  
> ```bash  
> $ nm keygenme_strip  
> nm: keygenme_strip: no symbols  
> ```  
> The `.symtab` table has been removed by `strip`. However, dynamic symbols in `.dynsym` remain (needed for dynamic linking):  
> ```bash  
> $ nm -D keygenme_strip  
> ```  
> These contain only functions imported from libc (`printf`, `strcmp`, `strlen`, `fgets`...), not the program's internal functions. This is exactly what makes RE of a stripped binary more difficult.

### Deduced call hierarchy

From the function names, we can already sketch a probable call hierarchy:

```
main
 ├── read_line       (input reading)
 ├── check_license   (verification — primary target)
 │    ├── compute_hash    (username transformation)
 │    ├── derive_key      (expected key derivation)
 │    └── format_key      (XXXX-XXXX-... formatting)
 └── printf          (result display)
```

This sketch is a *hypothesis* to confirm in Ghidra via cross-references (section 21.3). But it already guides the analysis: we know that `check_license` is the critical point.

---

## Step 5 — `objdump`: disassembly overview

Without opening Ghidra, we can get a first look at the machine code with `objdump`. This step is optional in a triage, but useful for verifying a quick hypothesis.

```bash
# Disassemble only the check_license function
$ objdump -d -M intel --no-show-raw-insn keygenme_O0 | \
    sed -n '/<check_license>:/,/^$/p'
```

We observe the classic pattern of a function at `-O0`:

1. **Prologue**: `push rbp` / `mov rbp, rsp` / `sub rsp, N` — setting up the stack frame.  
2. **Body**: successive calls to `compute_hash`, `derive_key`, `format_key` via `call`, then the call to `strcmp@plt`.  
3. **Decision point**: a `test eax, eax` followed by a `jne` (or `jnz`) after the return from `strcmp`. This is the conditional jump that separates the "valid key" path from the "invalid key" path.  
4. **Epilogue**: `leave` / `ret`.

At `-O0`, the code is verbose but very readable: each local variable is on the stack, each function call is explicit. At `-O2`, the compiler might inline some functions, use registers instead of the stack, and reorder instructions — making reading more difficult (chapter 16).

---

## Step 6 — `ldd`: dynamic dependencies

```bash
$ ldd keygenme_O0
    linux-vdso.so.1 (0x...)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
    /lib64/ld-linux-x86-64.so.2 (0x...)
```

The binary depends only on the standard libc — no external crypto library, no network framework. This means all verification logic is **internally implemented** in the binary. There is no `libssl`, no `libcrypto` — the hashing algorithm is custom, which we had anticipated from seeing the names `compute_hash` and `derive_key` in `nm`.

> ⚠️ **Security reminder**: `ldd` partially executes the binary via the dynamic linker. On a potentially malicious binary, prefer `objdump -p` or `readelf -d` which are purely static:  
> ```bash  
> $ readelf -d keygenme_O0 | grep NEEDED  
>  0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]  
> ```

---

## Triage summary

After these few minutes of inspection, here is what we know without having executed the binary or opened a graphical disassembler:

| Information | Value | Source |  
|---|---|---|  
| Format | ELF 64-bit, x86-64, little-endian | `file` |  
| Linking | Dynamic (libc only) | `file`, `ldd` |  
| PIE | Yes | `file` |  
| Symbols | Present (debug + symtab) | `file`, `nm` |  
| Internal functions | `main`, `check_license`, `compute_hash`, `derive_key`, `format_key`, `rotate_left`, `read_line` | `nm` |  
| Key format | `XXXX-XXXX-XXXX-XXXX` (hex, 19 characters) | `strings` |  
| Username validation | 3 to 31 characters | `strings` |  
| Key algorithm | Custom hash → derivation → formatting → `strcmp` | `strings` + `nm` + `objdump` |  
| Crypto libraries | None (internal algorithm) | `ldd` |  
| Success message | `[+] Valid license! Welcome, %s.` | `strings` |  
| Failure message | `[-] Invalid license. Try again.` | `strings` |

This table constitutes the **triage report** for the binary. In a professional analysis, it would be the first section of a formal report. For our training, it serves as a roadmap: we know exactly where and what to look for in the following steps.

The next section (21.2) will complete this triage by inventorying active protections with `checksec`, before diving into Ghidra to precisely locate the verification routine (21.3).

⏭️ [Protection inventory with `checksec`](/21-keygenme/02-checksec-protections.md)
