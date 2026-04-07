🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 9.3 — `r2`: essential commands (`aaa`, `pdf`, `afl`, `iz`, `iS`, `VV`)

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [9.2 — Radare2 / Cutter — command-line analysis and GUI](/09-ida-radare2-binja/02-radare2-cutter.md)

---

Section 9.2 presented Radare2's architecture and the mnemonic logic of its commands. This section moves into practice: we'll go through, command by command, the essential gestures for conducting a complete static analysis in `r2`. Each command is illustrated on our running-thread binary `keygenme_O2_strip`.

> 💡 **Convention.** In the examples below, the prompt `[0x...]>` represents `r2`'s interactive shell. Lines without a prompt are the output produced by the command. Explanatory comments are preceded by `#`.

## Opening a binary and launching analysis

### Simple opening

```
$ r2 keygenme_O2_strip
[0x00401050]>
```

The binary is loaded into memory, the seek is positioned on the entry point. No analysis is launched: `r2` waits for your instructions.

### Opening with automatic analysis

```
$ r2 -A keygenme_O2_strip
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] ...
[0x00401050]>
```

The `-A` flag automatically runs `aaa` at loading. It's the most common option to start an analysis session.

### Opening in write mode (for patching)

```
$ r2 -w keygenme_O2_strip
```

The `-w` flag opens the binary in write mode. The `w*` (write) commands will directly modify the file on disk. To be handled with caution — always work on a copy.

### Non-interactive execution (one-liner)

```
$ r2 -qc 'aaa; afl' keygenme_O2_strip
```

The `-q` (*quiet*) flag suppresses the banner, and `-c` executes the command string then quits. It's the ideal mode for shell scripting: you can chain `r2` commands in a Unix pipeline like any CLI tool.

## Analysis commands (`a`)

The `a` family groups everything concerning the binary's static analysis. It's the first thing to run after loading.

### `aa` — basic analysis

```
[0x00401050]> aa
```

Performs an initial analysis pass: function detection from known entry points, direct call resolution, basic-block identification. It's fast but can miss functions not reachable through a direct call path from `_start`.

### `aaa` — deep analysis

```
[0x00401050]> aaa
```

Chains several more aggressive analysis passes than `aa`. In addition to basic analysis, `aaa` performs indirect call resolution, stack analysis (local variables and arguments), auto-naming of functions based on glibc conventions, and type propagation. It's the recommended analysis level for most use cases.

### `aaaa` — experimental analysis

```
[0x00401050]> aaaa
```

Adds additional, more time-consuming heuristics: attempt to recover "orphan" functions (dead code, never-called functions), ESIL emulation analysis to resolve dynamic values, and other exploratory passes. Useful on stripped or obfuscated binaries, but can be slow on large binaries and may also produce false positives.

### `af` — analyze a specific function

```
[0x00401160]> af
```

Analyzes only the function at the current seek address. Useful if you prefer targeted analysis rather than global, or if you want to force `r2` to recognize a function it did not detect automatically.

### `afr` — analyze recursively from a function

```
[0x00401160]> afr
```

Analyzes the function at the current seek and all functions it calls, recursively. A good compromise between `af` (one function) and `aaa` (the whole binary).

## Information commands (`i`)

The `i` (*info*) family displays binary metadata. These commands don't require prior analysis — they directly read the ELF format's headers and tables.

### `iI` — general information

```
[0x00401050]> iI
arch     x86  
baddr    0x400000  
binsz    14328  
bintype  elf  
bits     64  
canary   false  
class    ELF64  
endian   little  
machine  AMD x86-64 architecture  
nx       true  
os       linux  
pic      false  
relro    partial  
stripped true  
```

Overview at a glance: architecture, size, security protections (canary, NX, PIE, RELRO), and confirmation that the binary is stripped. It's the equivalent of `file` + `checksec` combined.

### `iS` — sections

```
[0x00401050]> iS
[Sections]

nth paddr        size vaddr       vsize perm type     name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- NULL
1   0x00000318   0x1c 0x00400318   0x1c -r-- NOTE     .note.gnu.build-id
2   0x00000338   0x24 0x00400338   0x24 -r-- NOTE     .note.ABI-tag
3   0x00000360   0x28 0x00400360   0x28 -r-- GNU_HASH .gnu.hash
...
```

Lists all ELF sections with their physical address in the file (`paddr`), virtual address in memory (`vaddr`), size, permissions, and name. It's the same result as `readelf -S`, presented in `r2`'s tabular format.

The most relevant sections for RE are `.text` (executable code), `.rodata` (read-only data, notably strings), `.data` and `.bss` (modifiable data), `.plt` and `.got` (dynamic import resolution).

### `iS~.text` — filter a section

```
[0x00401050]> iS~.text
7   0x00001050  0x1a2 0x00401050  0x1a2 -r-x PROGBITS .text
```

The `~` operator is `r2`'s **internal grep**. It filters the output of any command by a text expression. `iS~.text` displays only the line of the `.text` section. This filtering mechanism is omnipresent in `r2` workflows and allows quickly extracting relevant information from verbose output.

A few useful variants of the internal grep:

- `~word` — filters lines containing "word"  
- `~!word` — filters lines NOT containing "word"  
- `~word[2]` — extracts the 3rd column (index 0) from lines containing "word"  
- `~..` — displays the output in an interactive pager (less scrolling lost)

### `ii` — imports

```
[0x00401050]> ii
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――――
1   0x00401030 GLOBAL FUNC       puts
2   0x00401040 GLOBAL FUNC       strcmp
3   0x00000000 WEAK   NOTYPE     __gmon_start__
```

Lists functions imported from shared libraries. On a dynamically linked binary, this list reveals the high-level system calls the program uses. Seeing `strcmp` in a crackme's imports is an immediate clue that the comparison of user input is probably a simple `strcmp`.

### `ie` — entry point

```
[0x00401050]> ie
[Entrypoints]
vaddr=0x00401050 paddr=0x00001050 haddr=0x00000018 type=program
```

Displays the binary's entry point (`e_entry` field of the ELF header). It's the address of `_start`, not `main` — the distinction is important as explained in chapter 2.7.

### `iz` — strings in data sections

```
[0x00401050]> iz
[Strings]
nth paddr      vaddr      len  size section type  string
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002000 0x00402000 13   14   .rodata ascii Enter key:
1   0x0000200e 0x0040200e 14   15   .rodata ascii Access granted
2   0x0000201d 0x0040201d 9    10   .rodata ascii Wrong key
```

Extracts strings from data sections (`.rodata`, `.data`). Each string is displayed with its physical address, virtual address, size, owning section, and encoding. It's the enriched equivalent of the `strings` command.

### `izz` — strings in the entire binary

```
[0x00401050]> izz
```

More aggressive variant that looks for strings in the **entire** file, including headers, code sections, and unmapped zones. Produces more results (including noise), but can reveal strings hidden in atypical sections.

### `iz~granted` — search for a specific string

```
[0x00401050]> iz~granted
1   0x0000200e 0x0040200e 14   15   .rodata ascii Access granted
```

The internal grep combined with `iz` allows instantly locating a string of interest.

## Movement commands (`s`)

### `s addr` — move the seek

```
[0x00401050]> s 0x00401160
[0x00401160]>
```

Moves the cursor to the specified address. Accepts numeric addresses, function names (`s main`, `s sym.check_serial`), flags (`s entry0`), or expressions (`s $$+0x10` to advance 16 bytes from the current position).

### `s-` and `s+` — navigation history

```
[0x00401160]> s-
[0x00401050]>
[0x00401050]> s+
[0x00401160]>
```

Navigate the history of previous and next positions, like the "back" and "forward" buttons of a web browser. Indispensable when following `call` chains and wanting to return to the starting point.

### `sr` — seek to a register (debug mode)

```
[0x00401160]> sr rip
```

In debug mode, moves the seek to a register's value. Useful to synchronize the disassembly view with the current instruction counter.

## Display commands (`p`)

The `p` (*print*) family is the Swiss army knife of display. It allows visualizing the binary's content in every possible form from the current seek.

### `pdf` — disassemble the current function

```
[0x00401160]> pdf
            ; DATA XREF from entry0 @ 0x40106d(r)
┌ 78: int main (int argc, char **argv, char **envp);
│           0x00401160      4883ec18       sub rsp, 0x18
│           0x00401164      488d3e95e0..   lea rdi, str.Enter_key:
│           0x0040116b      e8c0feffff     call sym.imp.puts
│           0x00401170      488d7424..     lea rsi, [rsp + 4]
│           0x00401175      488d3d84..     lea rdi, str._25s
│           0x0040117c      b800000000     mov eax, 0
│           0x00401181      e8cafeffff     call sym.imp.__isoc99_scanf
│           ...
│       ┌─< 0x0040119a      7512           jne 0x4011ae
│       │   0x0040119c      488d3d6b..     lea rdi, str.Access_granted
│       │   0x004011a3      e888feffff     call sym.imp.puts
│      ┌──< 0x004011a8      eb0e           jmp 0x4011b8
│      │└─> 0x004011ae      488d3d68..     lea rdi, str.Wrong_key
│      │    0x004011b5      e876feffff     call sym.imp.puts
│      └──> 0x004011b8      b800000000     mov eax, 0
│           0x004011bd      4883c418       add rsp, 0x18
└           0x004011c1      c3             ret
```

This is the most used `r2` command. `pdf` stands for **p**rint **d**isassembly **f**unction. It displays the complete disassembly of the function in which the seek is located, with:

- Virtual addresses in the left column.  
- Raw bytes of each instruction.  
- Mnemonics and operands in Intel syntax (default in recent versions).  
- Automatic annotations: string names (`str.Enter_key:`), imported function names (`sym.imp.puts`), cross-references (`; DATA XREF` comments).  
- ASCII arrows (`┌─<`, `└─>`) that visually trace conditional and unconditional jumps. It's a simplified graph mode directly in the text listing.

### `pd N` — disassemble N instructions

```
[0x00401160]> pd 5
            0x00401160      4883ec18       sub rsp, 0x18
            0x00401164      488d3e95e0..   lea rdi, str.Enter_key:
            0x0040116b      e8c0feffff     call sym.imp.puts
            0x00401170      488d7424..     lea rsi, [rsp + 4]
            0x00401175      488d3d84..     lea rdi, str._25s
```

Disassembles exactly N instructions from the current seek, independently of function bounds. Useful when the seek is not in a recognized function, or when you want to examine a specific fragment.

### `pds` — function summary (calls and strings)

```
[0x00401160]> pds
0x0040116b call sym.imp.puts           ; "Enter key: "
0x00401181 call sym.imp.__isoc99_scanf
0x00401193 call sym.imp.strcmp
0x004011a3 call sym.imp.puts           ; "Access granted"
0x004011b5 call sym.imp.puts           ; "Wrong key"
```

Displays an ultra-condensed summary of the function: only function calls and referenced strings, without the intermediate code. It's a remarkably effective triage command. In three seconds, you know this function reads input (`scanf`), compares it (`strcmp`), and displays a conditional result. You have the essence of the crackme's logic.

### `pdc` — pseudo-code (simplified decompilation)

```
[0x00401160]> pdc
```

Produces a rudimentary decompilation into C pseudo-code. Quality is inferior to the integrated Ghidra decompiler via `pdg` (see below), but `pdc` is always available without an external plugin. Useful for a quick first overview.

### `pdg` — Ghidra decompiler (if installed)

```
[0x00401160]> pdg
```

If the `r2ghidra` plugin is installed (via `r2pm -i r2ghidra`), this command invokes the Ghidra decompiler on the current function and displays the resulting pseudo-code. Quality is comparable to that obtained in Ghidra or Cutter. It's a major asset of `r2`: the most powerful decompiler in the open-source world, accessible from the command line.

### `px N` — hex dump

```
[0x00402000]> px 32
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00402000  456e 7465 7220 6b65 793a 2000 4163 6365  Enter key: .Acce
0x00402010  7373 2067 7261 6e74 6564 0057 726f 6e67  ss granted.Wrong
```

Displays N bytes in hexadecimal with the matching ASCII view, from the current seek. It's the classic view of a hex editor.

### `ps` — display as string

```
[0x00402000]> ps
Enter key:
```

Interprets the bytes at the current seek as a character string and displays it. Variants: `psz` for null-terminated strings, `psw` for wide strings (UTF-16).

## Function commands (`af`)

### `afl` — list all functions

```
[0x00401050]> afl
0x00401050    1     46 entry0
0x00401080    4     31 sym.deregister_tm_clones
0x004010b0    4     49 sym.register_tm_clones
0x004010f0    3     28 sym.__do_global_dtors_aux
0x00401110    1      6 sym.frame_dummy
0x00401120    3     63 sym.transform_key
0x00401160    4     98 main
0x004011d0    1      5 sym.__libc_csu_fini
0x004011e0    4    101 sym.__libc_csu_init
```

Lists all functions detected by the analysis with their address, number of basic blocks, size in bytes, and name. It's the equivalent of IDA's "Functions" window. We find the GCC infrastructure functions (`deregister_tm_clones`, `register_tm_clones`, `frame_dummy`, `__libc_csu_init`, `__libc_csu_fini`) and the application functions (`main`, `transform_key`).

### `afl~transform` — filter functions

```
[0x00401050]> afl~transform
0x00401120    3     63 sym.transform_key
```

Combined with the internal grep, `afl` allows quickly locating a function by name fragment.

### `aflj` — JSON output

```
[0x00401050]> aflj
```

The `j` suffix produces output in JSON format. It's essential for scripting: JSON output is cleanly parseable from Python, unlike tabular text output. Nearly all `r2` commands support the `j` suffix.

### `afn new_name` — rename the current function

```
[0x00401120]> afn check_serial
[0x00401120]> afl~check
0x00401120    3     63 check_serial
```

Renames the function at the current seek. The new name propagates throughout the disassembly. Equivalent to the `N` key in IDA.

### `afvn old new` — rename a local variable

```
[0x00401160]> afvn var_ch user_input
```

Renames a local variable of the current function. Local variables are identified by stack analysis (`afv` to list them).

### `afv` — list local variables

```
[0x00401160]> afv
var char *user_input @ rsp+0x4
```

Displays the detected local variables and arguments for the current function, with their estimated type and location (offset relative to the stack pointer or base pointer).

## Search commands (`/`)

### `/s string` — search for a string

```
[0x00401050]> / Access
Searching 6 bytes in [0x00400000-0x00402040]  
hits: 1  
0x0040200e hit0_0 "Access granted"
```

Searches for a byte sequence interpreted as an ASCII string in the binary's mapped segments. Displays the addresses of matches.

### `/x DEADBEEF` — search for a hexadecimal sequence

```
[0x00401050]> /x 7512
```

Searches for an exact byte sequence. Useful for finding specific opcode patterns — for example, `7512` matches `jne +0x12`, the conditional jump that decides between the two paths in a crackme.

### `/R` — search for ROP gadgets

```
[0x00401050]> /R ret
```

Searches for instruction sequences ending in `ret` — the ROP gadgets used in exploitation techniques. This feature, native in `r2`, is covered in more detail in chapter 12.3 on GDB extensions.

## Cross-references (`ax`)

### `axt addr` — who references this address?

```
[0x0040200e]> axt
main 0x40119c [DATA:r--] lea rdi, str.Access_granted
```

Displays all cross-references **to** the current address (*to*). In this example, the string "Access granted" is referenced by a `lea` in `main` at address `0x40119c`. It's the equivalent of the `X` key in IDA.

### `axf addr` — what does this address reference?

```
[0x0040116b]> axf
sym.imp.puts 0x401030 [CODE:--x] call sym.imp.puts
```

Displays cross-references **from** the current address (*from*). Here, the instruction at `0x40116b` is a `call` to `puts`.

### Combining XREF + strings: the base workflow

The following command sequence illustrates the classic crackme-triage workflow:

```
[0x00401050]> iz~granted           # 1. Find the success string
1   0x0040200e 0x0040200e 14   15   .rodata ascii Access granted

[0x00401050]> s 0x0040200e         # 2. Move to this string

[0x0040200e]> axt                  # 3. Who uses this string?
main 0x40119c [DATA:r--] lea rdi, str.Access_granted

[0x0040200e]> s main               # 4. Go into main

[0x00401160]> pdf                  # 5. Disassemble the function
```

In five commands, you've located the verification routine. That's the power of the CLI workflow: each command produces information that feeds the next.

## Visual modes

Visual modes were introduced in section 9.2. Here are the practical details of each.

### `V` — visual mode

```
[0x00401160]> V
```

Switches to a full-screen mode with the disassembly centered on the current seek. Keyboard shortcuts in visual mode:

| Key | Action |  
|---|---|  
| `p` / `P` | Cycle between views (hex, disassembly, debug, etc.) |  
| `j` / `k` | Down / up one instruction |  
| `J` / `K` | Down / up one page |  
| `Enter` | Follow a call or jump |  
| `u` | Go back |  
| `x` / `X` | Display XREFs to / from the current instruction |  
| `d` | Define menu (change the type: code, data, string, etc.) |  
| `:` | Open the command prompt (execute a one-off `r2` command) |  
| `n` / `N` | Rename the symbol under the cursor / Go to the next flag |  
| `;` | Add a comment |  
| `q` | Quit visual mode |

Visual mode is a good compromise between CLI speed and the navigation comfort of a graphical interface. It's particularly useful over SSH, where Cutter isn't available.

### `VV` — graph mode

```
[0x00401160]> VV
```

Displays the current function's control-flow graph (CFG) in ASCII art. Each basic block is a text rectangle containing instructions, connected to successor blocks by lines.

Shortcuts specific to graph mode:

| Key | Action |  
|---|---|  
| `tab` | Move to the next block |  
| `Tab` (Shift+Tab) | Move to the previous block |  
| `t` / `f` | Follow the *true* / *false* branch |  
| `g` + letter | Jump to the labeled block (labels appear when you press `g`) |  
| `R` | Change colors |  
| `+` / `-` | Zoom in / out (adjusts the number of columns) |  
| `hjkl` or arrows | Move the view |  
| `p` | Toggle between graph view and mini-graph (overview) |

### `V!` — panel mode

```
[0x00401160]> V!
```

Panel mode divides the terminal into several configurable windows. By default, you get the disassembly, registers, and stack side by side. You can add, remove, and resize panels with the `Tab` (change active panel), `w` (panel-management menu), and `e` (in some versions) keys.

This mode approaches the experience offered by GDB extensions like GEF or pwndbg (Chapter 12), but for static analysis.

## Flags and comments

### Flags

Flags in `r2` are named labels associated with addresses. Function names (`main`, `sym.imp.puts`), strings (`str.Enter_key:`), sections (`section..text`) are all flags. You can create your own flags:

```
[0x0040119a]> f cmp_branch @ 0x0040119a
[0x0040119a]> f~cmp
0x0040119a 1 cmp_branch
```

The `f name @ address` command creates a flag. `f` without arguments lists all flags, filterable with `~`.

### Comments

```
[0x0040119a]> CC Success/failure branch based on strcmp
[0x0040119a]> pdf~CC
│           ; Success/failure branch based on strcmp
│       ┌─< 0x0040119a      7512           jne 0x4011ae
```

`CC text` adds a comment at the current seek address. The comment appears in the disassembly (`pdf`) and in visual modes.

## JSON output and composition

One of `r2`'s design principles is that every command should be able to produce output usable by a program. The `j` suffix enables JSON output on the vast majority of commands:

```
[0x00401050]> aflj    # Function list in JSON
[0x00401050]> iIj     # Binary info in JSON
[0x00401050]> izj     # Strings in JSON
[0x00401050]> axtj    # Cross-references in JSON
```

Combined with non-interactive mode (`r2 -qc '...'`), this allows building analysis pipelines:

```bash
# Extract the names of all functions in JSON, process with jq
r2 -qc 'aaa; aflj' keygenme_O2_strip | jq '.[].name'
```

This capability is the cornerstone of scripting with `r2pipe`, which we'll cover in detail in section 9.4.

## Recap of essential commands

| Command | Mnemonic | Function |  
|---|---|---|  
| `aaa` | **a**nalyze **a**ll **a**dvanced | Deep analysis of the binary |  
| `afl` | **a**nalyze **f**unctions **l**ist | List detected functions |  
| `afn name` | **a**nalyze **f**unction **n**ame | Rename a function |  
| `pdf` | **p**rint **d**isasm **f**unction | Disassemble the current function |  
| `pd N` | **p**rint **d**isasm N | Disassemble N instructions |  
| `pds` | **p**rint **d**isasm **s**ummary | Summary: calls and strings only |  
| `pdc` | **p**rint **d**ecompile | Pseudo-decompilation |  
| `pdg` | **p**rint **d**ecompile **g**hidra | Ghidra decompiler (plugin) |  
| `px N` | **p**rint he**x** | Hex dump of N bytes |  
| `iI` | **i**nfo **I**nfo | Binary metadata |  
| `iS` | **i**nfo **S**ections | ELF sections |  
| `ii` | **i**nfo **i**mports | Imported functions |  
| `ie` | **i**nfo **e**ntrypoint | Entry point |  
| `iz` | **i**nfo string**z** | Strings in data sections |  
| `s addr` | **s**eek | Move the cursor |  
| `s-` / `s+` | **s**eek back / forward | Navigation history |  
| `axt` | **a**nalyze **x**ref **t**o | XREFs to the current address |  
| `axf` | **a**nalyze **x**ref **f**rom | XREFs from the current address |  
| `/ text` | search | Search for a string |  
| `/x hex` | search hex | Search for bytes |  
| `CC text` | **C**omment **C**omment | Add a comment |  
| `f name` | **f**lag | Create a flag (label) |  
| `V` | **V**isual | Full-screen visual mode |  
| `VV` | **V**isual **V**isual | ASCII graph mode |  
| `V!` | **V**isual panels | Panel mode |  
| `q` | **q**uit | Quit |

---


⏭️ [Scripting with r2pipe (Python)](/09-ida-radare2-binja/04-scripting-r2pipe.md)
