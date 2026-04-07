🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 5.3 — `nm` and `objdump -t` — inspecting symbol tables

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

In the previous section, `readelf -S` showed us the existence of sections named `.symtab` and `.dynsym`. These sections are the binary's **symbol tables** — data structures that associate human-readable names (function names, global variable names, labels) with memory addresses.

Symbols are the bridge between the world of source code (where you think in terms of `main`, `check_license`, `user_input`) and the world of the binary (where there are only addresses like `0x1189` or `0x11f5`). When symbols are present, the reverse engineering work is considerably eased: you immediately know which functions exist, how they are called, and where they are located.

This section presents the tools to extract and interpret these symbol tables: `nm`, the specialized tool from the GNU Binutils, and `objdump -t` / `readelf -s`, its complementary alternatives.

---

## The two symbol tables of an ELF

A dynamically linked ELF binary potentially contains **two** distinct symbol tables, serving different purposes:

### `.symtab` — the full symbol table

This table contains **all** the symbols known at link time: local functions, global functions, imported functions, global variables, static variables, section-start labels, and even some internal compiler symbols. It is the richest and most useful table for the reverse engineer.

It is stored in the `.symtab` section, accompanied by its string table `.strtab` that holds the names as C strings (null-terminated).

**Crucial point**: `.symtab` is **not required at runtime**. It is there solely for debugging and analysis. That is why the `strip` command removes it without affecting the binary's operation. On a stripped binary, `.symtab` and `.strtab` are absent.

### `.dynsym` — the dynamic symbol table

This table contains only the symbols required for **dynamic linking** at runtime: functions imported from shared libraries (like `printf`, `strcmp`, `malloc`) and functions exported by the binary (if it is a shared `.so` library).

It is stored in the `.dynsym` section, accompanied by `.dynstr` for the names.

**Crucial point**: `.dynsym` is **essential at runtime**. Without it, the dynamic loader would not know which functions to resolve. That is why it **survives `strip`**. Even on a fully stripped binary, you can still read the names of functions imported from shared libraries.

### Summary of the two tables

| Table | Section | Content | Survives `strip`? | Required at runtime? |  
|---|---|---|---|---|  
| `.symtab` | `.symtab` + `.strtab` | All symbols (local/global functions, variables…) | No | No |  
| `.dynsym` | `.dynsym` + `.dynstr` | Dynamic symbols (imports/exports) only | Yes | Yes |

---

## `nm` — listing the symbols of a binary

### Basic usage

`nm` is the canonical tool for listing the symbols of an ELF binary. By default, it displays the content of `.symtab`:

```bash
$ nm keygenme_O0
                 U __cxa_finalize@GLIBC_2.2.5
                 U __libc_start_main@GLIBC_2.34
                 U printf@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
                 U strcmp@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
0000000000004010 B __bss_start
0000000000004010 b completed.0
0000000000004000 D __data_start
0000000000004000 W data_start
00000000000010c0 T _start
0000000000001189 T main
00000000000011f5 T check_license
0000000000001280 T generate_expected_key
0000000000002000 R _IO_stdin_used
[...]
```

Each line follows the format: **address — type — name**. Symbols with no address (marked by spaces) are **undefined** symbols — they will be resolved at runtime by the dynamic loader.

### Symbol types: decoding the middle letter

The letter between the address and the name encodes the symbol's **type**. It is the densest and most important piece of information in `nm`'s output. Here are the types you will encounter most often:

| Letter | Meaning | Typical section | RE interpretation |  
|---|---|---|---|  
| `T` | **Text** (code) — global symbol | `.text` | Global function defined in the binary. This is what you look for first. |  
| `t` | **Text** (code) — local symbol | `.text` | Static function (`static` in C) or internal function. Visible only in the originating object file. |  
| `U` | **Undefined** | *(none)* | Imported symbol, not defined in the binary. Will be resolved by the dynamic loader. |  
| `D` | **Data** — initialized variable, global | `.data` | Global variable with an initial value. |  
| `d` | **Data** — initialized variable, local | `.data` | Initialized static variable. |  
| `B` | **BSS** — uninitialized variable, global | `.bss` | Global variable with no initial value (zeroed at load time). |  
| `b` | **BSS** — uninitialized variable, local | `.bss` | Uninitialized static variable. |  
| `R` | **Read-only data** — global | `.rodata` | Global constant (string, lookup table…). |  
| `r` | **Read-only data** — local | `.rodata` | Local or static constant. |  
| `W` / `w` | **Weak** symbol | varies | Weak symbol — can be replaced by a strong symbol with the same name. Frequent with C++ constructors/destructors and initializers. |  
| `A` | **Absolute** | *(none)* | Fixed value, not tied to a section. Rare in user binaries. |

The uppercase/lowercase convention encodes **visibility**: an uppercase letter (`T`, `D`, `B`, `R`) indicates a **global** symbol (visible from outside), a lowercase letter (`t`, `d`, `b`, `r`) indicates a **local** symbol (visible only in the originating compilation unit).

### Interpreting the output: what symbols teach us

Let's revisit the `nm` output on our crackme and see what we can deduce, without having read a single line of code:

```
                 U strcmp@GLIBC_2.2.5       # The program compares strings
                 U strlen@GLIBC_2.2.5       # It measures string length
                 U printf@GLIBC_2.2.5       # It prints formatted text
                 U puts@GLIBC_2.2.5         # It prints lines of text
0000000000001189 T main                     # The program's logical entry point
00000000000011f5 T check_license            # ← A license-checking function!
0000000000001280 T generate_expected_key    # ← A function that generates the expected key!
```

Without any disassembly, we already know:

1. The program has a `main` function at address `0x1189`.  
2. It contains a `check_license` function — probably the verification routine to analyze.  
3. It contains a `generate_expected_key` function — it probably computes the correct key.  
4. It uses `strcmp` — comparing the entered key to the expected one probably goes through this function.  
5. It uses `strlen` — it probably verifies the input's length.

We have essentially reconstructed the program's architecture purely from symbol names. That is the power of symbols — and it is also why developers who want to protect their binaries strip them.

### Essential `nm` options

```bash
# Display dynamic symbols (.dynsym) instead of .symtab
# Essential on a stripped binary
$ nm -D keygenme_O2_strip
                 U __cxa_finalize@GLIBC_2.2.5
                 U __libc_start_main@GLIBC_2.34
                 U printf@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
                 U strcmp@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
```

On the stripped binary, `nm` without options fails (or displays "no symbols"), because `.symtab` has been removed. With `-D`, we query `.dynsym` and recover the imported functions. The local functions (`main`, `check_license`, `generate_expected_key`) have disappeared — you will need to find them by other means (disassembly, call-graph analysis).

```bash
# Sort by address (instead of the default alphabetical order)
# Useful to visualize the in-memory layout of functions
$ nm -n keygenme_O0
[...]
0000000000001189 T main
00000000000011f5 T check_license
0000000000001280 T generate_expected_key
00000000000012c0 T __libc_csu_init
[...]
```

Sorting by address (`-n` or `--numeric-sort`) reveals **the physical order of functions** in the `.text` section. We see that `main` is at `0x1189`, `check_license` starts right after at `0x11f5`, and `generate_expected_key` follows at `0x1280`. Subtracting addresses lets you estimate each function's size: `check_license` is about `0x1280 - 0x11f5 = 0x8B` = 139 bytes, which corresponds to a relatively short function.

```bash
# Display symbol sizes
$ nm -S keygenme_O0 | grep ' T '
0000000000001189 000000000000006c T main
00000000000011f5 000000000000008b T check_license
0000000000001280 0000000000000035 T generate_expected_key
```

The `-S` option (or `--print-size`) displays each symbol's size in the second column. `main` is `0x6c` = 108 bytes, `check_license` is `0x8b` = 139 bytes, `generate_expected_key` is `0x35` = 53 bytes. These sizes are useful indicators: a 53-byte function is very short (perhaps a simple computation or transformation), while a function of several hundred bytes probably contains complex logic with branching.

```bash
# Filter only undefined symbols (imports)
$ nm -u keygenme_O0
                 U __cxa_finalize@GLIBC_2.2.5
                 U __libc_start_main@GLIBC_2.34
                 U printf@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
                 U strcmp@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5

# Filter only defined symbols (local functions and data)
$ nm --defined-only keygenme_O0

# Filter only global (exported) symbols
$ nm -g keygenme_O0

# Demangle C++ names (see Chapter 7, section 7.6)
$ nm -C cpp_program
```

The `-C` option (or `--demangle`) is essential for C++ binaries. C++ names are **mangled** by the compiler to encode the full signature (namespace, class, parameter types) into a single identifier. For example, `_ZN7MyClass10processKeyENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE` becomes, after demangling, `MyClass::processKey(std::string)`. Without `-C`, C++ symbol tables are practically unreadable.

### Summary of `nm` options

| Option | Effect | Use case |  
|---|---|---|  
| *(none)* | Displays `.symtab` | First reflex on a non-stripped binary |  
| `-D` | Displays `.dynsym` | Only option on a stripped binary |  
| `-n` | Sort by address | Visualize the in-memory order of functions |  
| `-S` | Display sizes | Estimate function complexity |  
| `-u` | Undefined symbols only | List imports (library functions) |  
| `--defined-only` | Defined symbols only | List local functions and data |  
| `-g` | Global symbols only | List exported functions and variables |  
| `-C` | C++ demangling | Make mangled C++ names readable |

---

## `objdump -t` and `readelf -s` — symbol inspection alternatives

### `objdump -t` — the full symbol table

```bash
$ objdump -t keygenme_O0

keygenme_O0:     file format elf64-x86-64

SYMBOL TABLE:
0000000000000000 l    df *ABS*  0000000000000000 Scrt1.o
000000000000038c l     O .note.ABI-tag  0000000000000020 __abi_tag
0000000000000000 l    df *ABS*  0000000000000000 crtstuff.c
00000000000010f0 l     F .text  0000000000000000 deregister_tm_clones
0000000000001120 l     F .text  0000000000000000 register_tm_clones
0000000000001160 l     F .text  0000000000000000 __do_global_dtors_aux
0000000000004010 l     O .bss   0000000000000001 completed.0
[...]
0000000000000000 l    df *ABS*  0000000000000000 keygenme.c
0000000000000000       F *UND*  0000000000000000 __cxa_finalize@GLIBC_2.2.5
0000000000000000       F *UND*  0000000000000000 printf@GLIBC_2.2.5
0000000000000000       F *UND*  0000000000000000 strcmp@GLIBC_2.2.5
0000000000000000       F *UND*  0000000000000000 strlen@GLIBC_2.2.5
0000000000000000       F *UND*  0000000000000000 puts@GLIBC_2.2.5
0000000000001189 g     F .text  000000000000006c main
00000000000011f5 g     F .text  000000000000008b check_license
0000000000001280 g     F .text  0000000000000035 generate_expected_key
[...]
```

`objdump -t` displays more details than `nm`: the format includes columns for flags (`l` = local, `g` = global, `F` = function, `O` = object, `df` = debug/filename), the section of affiliation, and the size.

A particularly interesting element appears here: lines with the `df` flag and the `*ABS*` section carry the **source file names**. You can read `Scrt1.o`, `crtstuff.c`, and `keygenme.c` — the name of the original source file. This detail may seem innocuous, but in a real RE case, knowing the source file name helps understanding the code organization, especially in a multi-file project.

```bash
# Equivalent of nm -D: dynamic symbols only
$ objdump -T keygenme_O0

keygenme_O0:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*  0000000000000000 GLIBC_2.2.5  __cxa_finalize
0000000000000000      DF *UND*  0000000000000000 GLIBC_2.34   __libc_start_main
0000000000000000      DF *UND*  0000000000000000 GLIBC_2.2.5  printf
0000000000000000      DF *UND*  0000000000000000 GLIBC_2.2.5  puts
0000000000000000      DF *UND*  0000000000000000 GLIBC_2.2.5  strcmp
0000000000000000      DF *UND*  0000000000000000 GLIBC_2.2.5  strlen
```

`objdump -T` (uppercase) is the equivalent of `nm -D`. The output additionally includes the **GLIBC version** required for each symbol. We see that most functions need `GLIBC_2.2.5` (very old), but `__libc_start_main` requires `GLIBC_2.34` — a much more recent version. This information can be relevant to determine the binary's compatibility with a given target system.

### `readelf -s` — the most detailed output

```bash
$ readelf -s keygenme_O0

Symbol table '.dynsym' contains 10 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __cxa_finalize@GLIBC_2.2.5
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strcmp@GLIBC_2.2.5
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.2.5
     [...]

Symbol table '.symtab' contains 43 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     [...]
    26: 0000000000001189   108 FUNC    GLOBAL DEFAULT   14 main
    27: 00000000000011f5   139 FUNC    GLOBAL DEFAULT   14 check_license
    28: 0000000000001280    53 FUNC    GLOBAL DEFAULT   14 generate_expected_key
     [...]
```

`readelf -s` is the most explicit command. Each field is named in the column header, which makes it self-documenting. It displays `.dynsym` and `.symtab` separately, with the following information:

**`Type`** — `FUNC` (function), `OBJECT` (variable/data), `NOTYPE` (no defined type), `SECTION` (section start), `FILE` (source file name).

**`Bind`** — `LOCAL` (visible only in the originating object file), `GLOBAL` (visible everywhere), `WEAK` (can be replaced by a global symbol of the same name).

**`Vis`** — the ELF visibility: `DEFAULT` (visible normally), `HIDDEN` (not exported by a shared library even if global), `PROTECTED`, `INTERNAL`. In most cases, it is `DEFAULT`.

**`Ndx`** — the index of the section containing the symbol. `UND` means undefined (imported symbol). A number such as `14` refers to a section — in our case, section 14 is `.text`, which confirms that `main`, `check_license`, and `generate_expected_key` are indeed executable code.

### Comparison of the three symbol tools

| Aspect | `nm` | `objdump -t` / `-T` | `readelf -s` |  
|---|---|---|---|  
| Output format | Compact (3 columns) | Detailed (flags, section, size) | Very detailed (named columns) |  
| `.symtab` | By default | `-t` | `-s` (displays both tables) |  
| `.dynsym` | `-D` | `-T` | `-s` (displays both tables) |  
| Symbol size | `-S` | Included by default | Included by default |  
| Source filenames | Not shown | Shown (flag `df`) | Shown (type `FILE`) |  
| C++ demangling | `-C` | `-C` | Not built-in (pipe to `c++filt`) |  
| Scriptability | Excellent (simple output) | Good | Good (fixed columns) |  
| Handling of malformed ELFs | Via BFD | Via BFD | Direct ELF parsing (more robust) |

---

## Practical techniques with symbols

### Listing only the program's functions

Combining `nm` with `grep`, you can quickly isolate the functions belonging to the program's code, eliminating the noise of internal compiler and runtime symbols:

```bash
# All global functions defined in .text
$ nm -n keygenme_O0 | grep ' T '
00000000000010c0 T _start
0000000000001189 T main
00000000000011f5 T check_license
0000000000001280 T generate_expected_key
00000000000012c0 T __libc_csu_init
0000000000001330 T __libc_csu_fini

# Same, excluding C runtime functions
$ nm -n keygenme_O0 | grep ' T ' | grep -v -E '(_start|_init|_fini|__libc|_IO_)'
0000000000001189 T main
00000000000011f5 T check_license
0000000000001280 T generate_expected_key
```

In two commands, we have isolated the three functions that make up the program's business logic. On a more complex binary with dozens or hundreds of functions, this filtering is essential to avoid drowning in noise.

### Searching for a specific symbol

When you suspect a binary uses a particular function — for example an encryption function — you can search directly:

```bash
# Look for encryption-related functions
$ nm keygenme_O0 | grep -iE '(crypt|aes|sha|md5|encrypt|decrypt)'

# Look for network functions
$ nm keygenme_O0 | grep -iE '(socket|connect|send|recv|bind|listen|accept)'

# Look for file-handling functions
$ nm keygenme_O0 | grep -iE '(fopen|fread|fwrite|open|read|write|mmap)'
```

The absence of results is itself information: if no network symbol appears, the binary probably does no network communication (or does it through direct system calls, which `strace` will reveal in section 5.5).

### Comparing symbols between two versions of a binary

Combining `nm` with `diff` or `comm`, you can quickly identify the functions added, removed, or modified between two versions:

```bash
# Extract the functions of each version
$ nm --defined-only -n keygenme_v1 | grep ' T ' > /tmp/syms_v1.txt
$ nm --defined-only -n keygenme_v2 | grep ' T ' > /tmp/syms_v2.txt

# Compare
$ diff /tmp/syms_v1.txt /tmp/syms_v2.txt
```

This technique is a first level of binary diffing, well before using specialized tools like BinDiff (Chapter 10).

---

## What happens on a stripped binary

Summary of the situation on a stripped binary, a scenario you will encounter very frequently in real conditions:

```bash
$ nm keygenme_O2_strip
nm: keygenme_O2_strip: no symbols

$ nm -D keygenme_O2_strip
                 U __cxa_finalize@GLIBC_2.2.5
                 U __libc_start_main@GLIBC_2.34
                 U printf@GLIBC_2.2.5
                 U puts@GLIBC_2.2.5
                 U strcmp@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
```

`.symtab` is absent: `nm` with no option finds nothing. With `-D`, we access `.dynsym` and see the imported functions, but local functions (`main`, `check_license`, `generate_expected_key`) have entirely disappeared. We know the program uses `strcmp` and `strlen`, but we no longer know where or how.

This is where the reverse engineering work truly begins: finding these functions through machine-code analysis, naming them manually in a disassembler, and reconstructing the program's logic. The remaining dynamic symbols are valuable clues — they tell you what to look for, even if they no longer tell you where.

To locate `main` in a stripped binary, a classic technique is to look for the call to `__libc_start_main` in the `_start` code: the third argument passed to `__libc_start_main` is the address of `main`. We will see this technique in detail in Chapter 7 (section 7.5).

---

## What to remember going forward

- **`nm` is the first functional reconnaissance tool**. Before disassembling, list the symbols. Function names are the best clue about a program's architecture.  
- **Uppercase = global, lowercase = local** in `nm` types. `T` = global function in `.text`, `U` = undefined (import), `B`/`D`/`R` = data in `.bss`/`.data`/`.rodata`.  
- **`nm -D` is your plan B** on a stripped binary. Dynamic symbols survive `strip` and reveal the libraries used.  
- **`nm -n`** sorts by address and shows the physical layout of functions — useful to estimate their sizes and understand the code layout.  
- **`nm -C`** is essential in C++ — without demangling, C++ symbols are unreadable.  
- **Imported symbols** (`U`) are functional clues: `strcmp` = string comparison, `socket` = network, `EVP_EncryptInit` = OpenSSL encryption. Learn to recognize them.  
- On a stripped binary, the loss of `.symtab` means all the richness of local function names has disappeared. What remains is `.dynsym` and the strings in `.rodata` — the two Ariadne's threads we will exploit with the disassembler.

---


⏭️ [`ldd` and `ldconfig` — dynamic dependencies and resolution](/05-basic-inspection-tools/04-ldd-ldconfig.md)
