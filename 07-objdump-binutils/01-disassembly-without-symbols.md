🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 7.1 — Disassembling a binary compiled without symbols (`-s`)

> 🔧 **Tools used**: `objdump`, `strip`, `readelf`, `nm`, `file`  
> 📦 **Binaries**: `keygenme_O0` and `keygenme_strip` (`binaries/ch07-keygenme/` directory)

---

## The realistic scenario: no symbols

When you retrieve a binary "in the wild" — a commercial executable, an extracted firmware, a suspect sample — chances are high that it has been **stripped**. Debug symbols (`-g`) are obviously not there, and even the standard symbol table (`.symtab`) has been removed with `strip`. Only the strict minimum needed for execution remains: machine code, data, and dynamic symbols (`.dynsym`) if the binary is dynamically linked.

That is the situation we'll tackle in this section. We'll start by understanding what `strip` removes concretely, then we'll see how `objdump` behaves against a stripped binary, and finally how to navigate in the produced listing nonetheless.

---

## What `strip` removes (and what it leaves)

Before disassembling a stripped binary, let's understand exactly what has disappeared. Take our working binary and create both versions if not already done:

```bash
# Compile with debug symbols
gcc -O0 -g -o keygenme_O0 keygenme.c

# Stripped version
cp keygenme_O0 keygenme_strip  
strip keygenme_strip  
```

Let's immediately compare the sizes of the two files:

```bash
$ ls -l keygenme_O0 keygenme_strip
-rwxr-xr-x 1 user user  20536  keygenme_O0
-rwxr-xr-x 1 user user  14472  keygenme_strip
```

The stripped version is significantly smaller. The difference corresponds to the symbol and debug sections that were removed. To see exactly what changed, let's compare the sections present in each binary:

```bash
$ readelf -S keygenme_O0 | grep -c '\['
31

$ readelf -S keygenme_strip | grep -c '\['
27
```

Sections that typically disappear after a `strip` are:

| Removed section | Lost content |  
|---|---|  
| `.symtab` | Full symbol table (local function names, global variables…) |  
| `.strtab` | Strings associated with `.symtab` (the names themselves) |  
| `.debug_info` | DWARF information: types, variables, line numbers |  
| `.debug_abbrev` | DWARF abbreviations |  
| `.debug_line` | Address → source line correspondence |  
| `.debug_str` | Strings used by DWARF |  
| `.debug_aranges` | DWARF address-range index |

What **remains** after stripping, and this is crucial:

| Kept section | Why it survives |  
|---|---|  
| `.dynsym` | Needed by the *dynamic linker* to resolve imported/exported symbols at runtime |  
| `.dynstr` | Strings associated with `.dynsym` |  
| `.plt` / `.got` / `.got.plt` | Mechanism for calling shared-library functions (dynamic resolution) |  
| `.text` | Executable code — what we disassemble |  
| `.rodata` | Constants: string literals, value tables… |  
| `.data` / `.bss` | Initialized / uninitialized global variables |

The `file` command confirms the difference:

```bash
$ file keygenme_O0
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
for GNU/Linux 3.2.0, with debug_info, not stripped  

$ file keygenme_strip
keygenme_strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
for GNU/Linux 3.2.0, stripped  
```

Notice the two key indications at the end of the line: `with debug_info, not stripped` versus simply `stripped`. The `file` command gives you this information instantly — it's one of the very first triage reflexes (Chapter 5).

---

## Checking the presence or absence of symbols with `nm`

Before disassembling, it's useful to confirm symbol state with `nm`:

```bash
$ nm keygenme_O0
0000000000001189 T check_serial
0000000000001139 T compute_hash
00000000000011e2 T main
                 U printf@@GLIBC_2.2.5
                 U puts@@GLIBC_2.2.5
                 U strcmp@@GLIBC_2.2.5
...
```

We see here the functions defined in the binary (`T` = `.text` section) and imported functions (`U` = *undefined*, dynamically resolved). Each symbol is associated with its virtual address. It's a gold mine for RE: we immediately know which functions exist and where they are located.

On the stripped binary:

```bash
$ nm keygenme_strip
nm: keygenme_strip: no symbols
```

The `.symtab` table has disappeared. But **dynamic** symbols are still there:

```bash
$ nm -D keygenme_strip
                 w __cxa_finalize
                 w __gmon_start__
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
                 U printf
                 U puts
                 U strcmp
...
```

The `-D` option queries `.dynsym` instead of `.symtab`. We recover the names of libc functions called by the program (`printf`, `puts`, `strcmp`), but **no local function names** — `main`, `check_serial`, `compute_hash` all disappeared. Those are the names the reverse engineer will have to reconstruct manually.

> 💡 **Key point**: even on a stripped binary, calls to shared libraries remain identifiable thanks to `.dynsym` and the PLT/GOT mechanism. It's a major anchor point for RE. When you see a `call` to `strcmp@plt`, you immediately know what that instruction does, and you can work back through the surrounding logic.

---

## Disassembling with `objdump -d`

Let's move on to the disassembly itself. The basic command is:

```bash
objdump -d keygenme_O0
```

The `-d` option (*disassemble*) decodes every section marked as containing executable code — in practice, `.text`, `.init`, `.fini`, and `.plt`. The resulting listing looks like this (simplified excerpt):

```
keygenme_O0:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:       f3 0f 1e fa             endbr64
    1004:       48 83 ec 08             sub    $0x8,%rsp
    ...

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:       ff 35 e2 2f 00 00       pushq  0x2fe2(%rip)
    ...

0000000000001030 <puts@plt>:
    1030:       ff 25 e2 2f 00 00       jmpq   *0x2fe2(%rip)
    ...

0000000000001040 <printf@plt>:
    1040:       ff 25 da 2f 00 00       jmpq   *0x2fda(%rip)
    ...

Disassembly of section .text:

0000000000001060 <_start>:
    1060:       f3 0f 1e fa             endbr64
    1064:       31 ed                   xor    %ebp,%ebp
    ...

0000000000001139 <compute_hash>:
    1139:       55                      push   %rbp
    113a:       48 89 e5                mov    %rsp,%rbp
    ...

0000000000001189 <check_serial>:
    1189:       55                      push   %rbp
    118a:       48 89 e5                mov    %rsp,%rbp
    ...

00000000000011e2 <main>:
    11e2:       55                      push   %rbp
    11e3:       48 89 e5                mov    %rsp,%rbp
    ...
```

### Anatomy of a line

Each line of the listing follows the format:

```
    11e2:       55                      push   %rbp
    ^^^^        ^^                      ^^^^^^^^^^^^^^^^
    │           │                       └─ Decoded instruction (mnemonic + operands)
    │           └─ Machine bytes (raw opcodes in hexadecimal)
    └─ Virtual address (offset in the binary)
```

The three columns are always present. The address lets you locate yourself, the raw bytes are useful for patching (Chapter 21), and the mnemonic is what you read first.

### Labels between angle brackets

When symbols are available, `objdump` displays the name of each function as a **label** between angle brackets (`<compute_hash>:`, `<main>:`…). These labels are priceless: they segment the listing into logical blocks and immediately give each function's name.

Inside the code, references to functions also use these labels:

```
    11f5:       e8 3f ff ff ff          callq  1139 <compute_hash>
```

Here, the `call` points to address `0x1139`, and `objdump` indicates between angle brackets that it is `compute_hash`. Without symbols, you would only have seen:

```
    11f5:       e8 3f ff ff ff          callq  1139
```

The address is always there, but the name has disappeared. It is up to you to determine what the function at `0x1139` does.

---

## Disassembling a stripped binary

Now let's run the same command on the stripped binary:

```bash
objdump -d keygenme_strip
```

The listing changes significantly:

```
Disassembly of section .text:

0000000000001060 <.text>:
    1060:       f3 0f 1e fa             endbr64
    1064:       31 ed                   xor    %ebp,%ebp
    1066:       49 89 d1                mov    %rdx,%r9
    ...
    1139:       55                      push   %rbp
    113a:       48 89 e5                mov    %rsp,%rbp
    113d:       48 89 7d e8             mov    %rdi,-0x18(%rbp)
    ...
    1189:       55                      push   %rbp
    118a:       48 89 e5                mov    %rsp,%rbp
    ...
    11e2:       55                      push   %rbp
    11e3:       48 89 e5                mov    %rsp,%rbp
    ...
```

Several differences stand out:

**A single label for the whole `.text` section.** Instead of seeing `<compute_hash>:`, `<check_serial>:`, `<main>:`, we only see a unique `<.text>:` at the beginning. The whole section is treated as a monolithic block. The boundaries between functions are no longer marked.

**Internal `call`s lose their annotation.** Where we saw `callq 1139 <compute_hash>`, we now see simply `callq 1139`. The target address is still correct, but it's up to you to note that `0x1139` is the start of a function and give it a name.

**PLT calls remain annotated.** Good news: `call`s to dynamic-library functions keep their labels because `.dynsym` has not been removed:

```
    1205:       e8 36 fe ff ff          callq  1040 <printf@plt>
```

It's one of the few landmarks that survive and they are precious. If you see a `call` to `strcmp@plt`, you know that the code just before prepares two strings in `rdi` and `rsi` to compare them. That is a solid starting point to understand the program's logic.

---

## Essential `objdump` options for disassembly

Here are the options you will use most frequently, beyond the simple `-d`:

### `-d` vs `-D`: executable code vs disassemble everything

The `-d` option only disassembles sections containing code (those with the `SHF_EXECINSTR` flag). The `-D` option (uppercase) disassembles **every** section, including `.data`, `.rodata`, `.got`, etc.

```bash
objdump -D keygenme_strip | head -100
```

In practice, `-D` is rarely what you want: decoding `.rodata` as x86 instructions produces noise. But it's sometimes useful for examining the contents of `.got.plt` or for spotting code hidden in a data section (an obfuscation technique).

Prefer `-d` for daily work.

### `-M intel`: switch to Intel syntax

By default, `objdump` uses AT&T syntax, inherited from Unix. Section 7.2 covers this subject in detail, but here's the preview:

```bash
# AT&T syntax (default)
objdump -d keygenme_strip
    113a:       48 89 e5                mov    %rsp,%rbp

# Intel syntax
objdump -d -M intel keygenme_strip
    113a:       48 89 e5                mov    rbp,rsp
```

Intel syntax swaps operand order (destination first) and removes the `%` and `$` prefixes. The majority of RE documentation, courses, and tools (IDA, Ghidra by default) use Intel syntax. We'll adopt it in the rest of this training.

> 💡 **Tip**: to avoid typing `-M intel` every time, you can create an alias in your `~/.bashrc`:  
> ```bash  
> alias objdump='objdump -M intel'  
> ```

### `-j <section>`: disassemble a specific section

If you only want to see `.text` without the noise of `.init`, `.fini`, and `.plt`:

```bash
objdump -d -j .text keygenme_strip
```

You can also target `.plt` to study the dynamic-resolution mechanism:

```bash
objdump -d -j .plt keygenme_strip
```

### `--start-address` / `--stop-address`: address window

To zoom on a precise area of the binary — for example, the function that starts at `0x1189` and seems to end around `0x11e1`:

```bash
objdump -d -M intel --start-address=0x1189 --stop-address=0x11e2 keygenme_strip
```

It's the equivalent of a "zoom": instead of searching through a listing of several thousand lines, you isolate exactly the portion that interests you.

### `-S`: interleave source code and assembly

If the binary contains DWARF debug information (compiled with `-g`, not stripped), the `-S` option shows the original C source code interleaved with assembly instructions:

```bash
objdump -d -S -M intel keygenme_O0
```

The result looks like this:

```
int compute_hash(const char *input) {
    1139:       55                      push   rbp
    113a:       48 89 e5                mov    rbp,rsp
    113d:       48 89 7d e8             mov    QWORD PTR [rbp-0x18],rdi
    int hash = 0;
    1141:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
    for (int i = 0; input[i] != '\0'; i++) {
    1148:       c7 45 f8 00 00 00 00    mov    DWORD PTR [rbp-0x8],0x0
    114f:       eb 1d                   jmp    116e
```

This view is **extremely** valuable for learning. It shows you exactly which instruction corresponds to which line of C. It's the best way to build your intuition on GCC compiler patterns. Of course, this option only works on a non-stripped binary containing DWARF info — on a stripped binary, `-S` behaves exactly like `-d`.

> 💡 **Recommended method**: when studying a binary provided with this tutorial, open **two terminals side by side**. In the first one, disassemble the version with symbols and debug info (`objdump -d -S -M intel keygenme_O0`). In the second one, disassemble the stripped version (`objdump -d -M intel keygenme_strip`). Compare the two listings. You'll see exactly what stripping makes disappear, and you'll learn to recognize patterns without the help of annotations.

### `-r` and `-R`: relocations

The `-r` option displays relocations of object files (`.o`), and `-R` those of the final binary. It's less used in daily RE, but can be useful to understand how the linker resolved addresses. We won't go deeper into them in this section, but know that they exist.

---

## Strategy facing a stripped binary: spotting function boundaries

The main challenge of a stripped binary is that functions are no longer delimited by labels. The listing is a continuous flow of instructions. How to find your way?

### 1. Look for prologues

In `x86-64`, the vast majority of functions compiled by GCC at `-O0` start with the same prologue:

```asm
push   rbp  
mov    rbp, rsp  
sub    rsp, <N>       ; optional, allocation of local variables  
```

Searching for every occurrence of `push rbp` followed by `mov rbp, rsp` in the listing gives you a reliable approximation of function starts. With `grep`:

```bash
objdump -d -M intel keygenme_strip | grep -n "push   rbp"
```

Every line found is potentially the start of a function. It is not foolproof (a `push rbp` may appear in another context, and optimized functions can omit the *frame pointer*), but at `-O0`, it is remarkably reliable.

### 2. Look for epilogues

Symmetrically, functions end with:

```asm
leave              ; equivalent to  mov rsp, rbp  +  pop rbp  
ret  
```

or sometimes:

```asm
pop    rbp  
ret  
```

A `ret` followed by a `push rbp` is a very strong signal of a boundary between two functions.

### 3. Follow the `call`s

Each `call <address>` instruction tells you that a function exists at the target address. Collect all `call` targets:

```bash
objdump -d -M intel keygenme_strip | grep "call" | grep -v plt
```

This gives you the list of internal functions called. By combining this list with the prologues found in point 1, you can quickly reconstruct a directory of functions, even without symbols.

### 4. Lean on PLT calls

Calls to `printf@plt`, `strcmp@plt`, `malloc@plt` and friends are strong semantic hints. If you see:

```asm
lea    rdi, [rip+0x...]    ; loads the address of a string into rdi  
call   printf@plt  
```

You know the current function uses `printf`, and that the first argument (in `rdi`, System V convention) is probably a pointer to a formatted string. Go to `.rodata` to find this string:

```bash
objdump -s -j .rodata keygenme_strip
```

Or more simply:

```bash
strings keygenme_strip
```

Linking strings to the points in code where they are referenced is a fundamental RE technique on stripped binaries. If you find a string `"Invalid serial!\n"`, you know that the function that loads it is probably the serial-verification routine — and you just located your target without needing a single symbol name.

---

## The `-t` and `--syms` options: when symbols are partial

There is an intermediate situation: the binary was not compiled with `-g` (no DWARF), but was not stripped either. That's the default case when compiling simply with `gcc -o binary source.c` without any specific option. The `.symtab` table is present, but debug information (types, line numbers, local variables) is not.

In this case, `objdump -d` does display function labels, but `-S` cannot interleave source code. It's a common middle ground, and `objdump` handles it very well: the disassembly is clear, functions are named, `call`s are annotated.

To quickly check the symbol state of a binary before disassembling it:

```bash
# .symtab present?
readelf -S keygenme_O0 | grep symtab

# DWARF sections present?
readelf -S keygenme_O0 | grep debug

# Quick summary
file keygenme_O0
```

These three commands take a few seconds and immediately inform you about what `objdump` will be able to show.

---

## Redirecting and filtering the listing

On a reasonably sized binary, the `objdump` listing runs to a few hundred to a few thousand lines. On a real binary (a web browser, a server…), it can exceed one million lines. A few techniques to avoid drowning:

**Redirect to a file** so you can search at leisure:

```bash
objdump -d -M intel keygenme_strip > keygenme_strip.asm
```

You can then open this file in your favorite text editor and use the built-in search.

**Combine with `less`** for interactive navigation:

```bash
objdump -d -M intel keygenme_strip | less
```

In `less`, type `/` followed by a search term (for example `/call` or `/strcmp`) to jump directly to occurrences.

**`grep` with context** to extract interesting zones:

```bash
# See 10 lines before and 20 lines after each call to strcmp
objdump -d -M intel keygenme_strip | grep -B10 -A20 "strcmp"
```

**Count functions** (approximation via prologues):

```bash
objdump -d -M intel keygenme_strip | grep -c "push   rbp"
```

These techniques seem rudimentary compared to Ghidra's interface, but they are fast, scriptable, and perfectly suited for a first look at the binary.

---

## Summary

Stripping removes local function names and debug information, but leaves intact the machine code, data, and dynamic symbols. Faced with a stripped binary, `objdump -d` produces a linear listing without function labels, but PLT calls remain annotated. To reconstruct the program structure, you lean on prologues/epilogues to delimit functions, on `call` targets to build their inventory, and on PLT calls combined with `.rodata` strings to give meaning to each function. These manual techniques form the basis of any RE work on an unknown binary, and remain relevant even with more sophisticated tools.

---


⏭️ [AT&T vs Intel syntax — switching from one to the other (`-M intel`)](/07-objdump-binutils/02-att-vs-intel.md)
