🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix D — Cheat sheet Radare2 / Cutter

> 📎 **Reference sheet** — This appendix gathers the most useful Radare2 (`r2`) commands for reverse engineering ELF x86-64 binaries compiled with GCC. It covers the native console mode as well as the Cutter graphical interface. Commands are organized by task for quick access during an analysis session.

---

## Understanding the Radare2 philosophy

Radare2 is a command-line RE framework whose interface relies on **short and composable commands**. The learning curve is steep, but the underlying logic is consistent: each command is a letter or group of letters, and variants are obtained through suffixes. For example, `p` = *print*, `pd` = *print disassembly*, `pdf` = *print disassembly of function*, `pdfj` = same in JSON.

The recurring suffixes are:

| Suffix | Meaning | Example |  
|--------|---------|---------|  
| `j` | JSON output | `ij` = `i` in JSON |  
| `q` | *Quiet* mode (minimal output) | `aflq` = compact function list |  
| `*` | Output as replayable `r2` commands | `afl*` = function list in script format |  
| `~` | Internal grep (filters output) | `afl~main` = filters functions containing "main" |  
| `~:N` | Grep + Nth column selection | `afl~:0` = first column only (addresses) |  
| `?` | Command help | `pd?` = help on `pd` |

> 💡 **Golden rule**: when you don't know how to use a command, append `?` at the end. `a?`, `p?`, `s?`, `w?` — each command family has its own built-in help page.

---

## 1 — Launch and opening modes

### 1.1 — Opening a binary

| Shell command | Description |  
|---------------|-------------|  
| `r2 ./binary` | Opens a binary in read-only mode (no automatic analysis) |  
| `r2 -A ./binary` | Opens and runs automatic analysis (`aaa`) |  
| `r2 -AA ./binary` | Opens with deep analysis (`aaaa`) |  
| `r2 -d ./binary` | Opens in debug mode (launches the program) |  
| `r2 -d ./binary arg1 arg2` | Debug mode with arguments |  
| `r2 -d -A ./binary` | Debug mode with automatic analysis |  
| `r2 -w ./binary` | Opens in write mode (for patching the binary) |  
| `r2 -n ./binary` | Opens without any analysis or metadata loading |  
| `r2 -B 0x400000 ./binary` | Opens with a specified base address (rebased binary) |  
| `r2 -e bin.cache=true ./binary` | Enables binary cache (speeds up analysis of large files) |  
| `r2 -i script.r2 ./binary` | Executes a command script at launch |  
| `r2 malloc://512` | Opens a 512-byte memory block (write sandbox) |

### 1.2 — Session commands

| r2 command | Description |  
|------------|-------------|  
| `o ./other_binary` | Opens another file in the same session |  
| `o` | Lists open files |  
| `oo+` | Reopens the current file in write mode |  
| `oo` | Reopens the current file (reloads) |  
| `q` | Quits r2 |  
| `q!` | Quits without confirmation |  
| `?` | General help |  
| `?v $$ ` | Displays the current address in hexadecimal |  
| `?v $$ - sym.main` | Calculates an address difference |  
| `? 0xff + 1` | Built-in calculator |

---

## 2 — Analysis

Analysis is the step that allows r2 to recognize functions, basic blocks, cross-references, and structures in the binary. Without analysis, r2 only shows raw bytes.

### 2.1 — Analysis commands

| Command | Description |  
|---------|-------------|  
| `aa` | Basic analysis (functions identified by symbols and entries) |  
| `aaa` | Deep analysis (function detection heuristics, xrefs) |  
| `aaaa` | Experimental analysis (even more heuristics, slower) |  
| `aab` | Basic block analysis |  
| `aac` | Call analysis (`call` → function detection) |  
| `aap` | Function detection by prologue (searches for `push rbp; mov rbp, rsp` prologues) |  
| `aar` | Reference analysis (data references) |  
| `aav` | Value and constant analysis (searches for pointers in data) |  
| `aan` | Auto-naming of functions (heuristics based on strings and calls) |  
| `afr` | Re-analyzes the current function |  
| `af` | Analyzes the function at the current address (if not automatically detected) |  
| `af+ <addr> <size> <name>` | Manually creates a function |  
| `af- <addr>` | Removes the function at the specified address |

The `aaa` command is the right trade-off between speed and thoroughness for most binaries. For very large binaries (several MB), `aa` may suffice for initial triage, followed by targeted analysis with `af` on functions of interest.

### 2.2 — Function information

| Command | Description |  
|---------|-------------|  
| `afl` | Lists all detected functions (address, size, name) |  
| `aflq` | Compact list (addresses only) |  
| `afl~main` | Filters functions containing "main" in their name |  
| `afl~:1` | Displays only the size column |  
| `afll` | Detailed list (number of blocks, calls, xrefs, cyclomatic complexity) |  
| `aflt` | List with the number of instructions per function |  
| `afi` | Information about the current function (address, size, variables, arguments) |  
| `afi.` | Information about the function containing the current address |  
| `afn <name>` | Renames the current function |  
| `afn <name> <addr>` | Renames the function at the specified address |  
| `afvn <old> <new>` | Renames a local variable |  
| `afvt <name> <type>` | Changes the type of a local variable |  
| `afv` | Lists local variables and arguments of the current function |

---

## 3 — Navigation and movement

### 3.1 — The `s` (seek) command

In r2, the current position is a **cursor** (*seek*) that you move through the file. All commands that display content (disassembly, hexdump, etc.) operate from this position.

| Command | Description |  
|---------|-------------|  
| `s main` | Moves to the beginning of the `main` function |  
| `s sym.main` | Same (explicit `sym.` prefix) |  
| `s 0x401234` | Moves to an absolute address |  
| `s entry0` | Moves to the binary's entry point |  
| `s $s` | Moves to the beginning of the current section |  
| `s+10` | Advances by 10 bytes |  
| `s-10` | Goes back by 10 bytes |  
| `s++` | Advances to the next function |  
| `s--` | Goes back to the previous function |  
| `s-` | Returns to the previous position (history, like the "Back" button) |  
| `s*` | Displays the position history |  
| `sf` | Moves to the beginning of the current function |  
| `sf.` | Moves to the beginning of the function containing the current position |

### 3.2 — Variables and special addresses

| Variable | Meaning |  
|----------|---------|  
| `$$` | Current address (seek position) |  
| `$s` | Start of the current section |  
| `$S` | Size of the current section |  
| `$b` | Size of the current block |  
| `$l` | Size of the opcode at the current position |  
| `$e` | Start of the stack (if in debug mode) |  
| `$f` | Start of the current function |  
| `$j` | Jump destination at the current position |

---

## 4 — Binary information

### 4.1 — Metadata and headers

| Command | Description |  
|---------|-------------|  
| `i` | Binary summary (format, architecture, endianness, size) |  
| `ia` | Architecture and bits |  
| `ie` | Entry point (entrypoints) |  
| `iI` | Detailed binary information (type, OS, machine, class) |  
| `ih` | Binary headers |  
| `iH` | Detailed headers (ELF program headers and section headers) |  
| `il` | Dynamically linked libraries (equivalent of `ldd`) |  
| `ii` | Import table (functions imported from libraries) |  
| `iE` | Export table (exported functions) |  
| `iS` | Binary sections (name, size, permissions, address) |  
| `iSS` | Binary segments (ELF program headers) |  
| `iS~.text` | Filter on the `.text` section |  
| `is` | Symbol table |  
| `is~FUNC` | Filters function-type symbols |

### 4.2 — Strings

| Command | Description |  
|---------|-------------|  
| `iz` | Strings found in data sections (`.rodata`, `.data`) |  
| `izz` | Strings found in the entire binary (including non-standard sections) |  
| `iz~password` | Filters strings containing "password" |  
| `izj` | Strings in JSON format (useful for scripting) |  
| `izzq` | Compact strings (address + content only) |

### 4.3 — Cross-references (XREF)

| Command | Description |  
|---------|-------------|  
| `axt <addr>` | Xrefs **to** the address (who calls or references this address) |  
| `axt @ sym.strcmp` | Who calls `strcmp`? |  
| `axt @ str.password` | Who uses the string "password"? |  
| `axf <addr>` | Xrefs **from** the address (what does this address call or reference) |  
| `axf @ sym.main` | What functions are called by `main`? |  
| `ax` | Lists all cross-references |  
| `axtj <addr>` | Xrefs to the address in JSON |

Cross-references are one of the most powerful RE tools. The `axt` command in particular is essential for tracing the usage of a string, function, or constant across the entire binary. The typical workflow is: find an interesting string with `iz`, then `axt @ str.xxx` to find the code that uses it.

### 4.4 — Protections and security

| Command | Description |  
|---------|-------------|  
| `ik~canary` | Checks for the presence of the stack canary |  
| `ik~nx` | Checks NX (non-executable stack) |  
| `ik~pic` | Checks PIC/PIE |  
| `ik~relro` | Checks RELRO |  
| `rabin2 -I ./binary` | Protection summary from the shell (companion tool) |

> 💡 For a complete protection audit, the `checksec` tool (see Chapter 5.6) or the `checksec` command from GEF/pwndbg remains more readable. But `rabin2 -I` is handy when you are working exclusively with the r2 suite.

---

## 5 — Display and disassembly

### 5.1 — Disassembly (`p` = print)

| Command | Description |  
|---------|-------------|  
| `pd 20` | Disassembles 20 instructions from the current position |  
| `pd -10` | Disassembles 10 instructions **before** the current position |  
| `pdf` | Disassembles the current function (print disassembly function) |  
| `pdf @ main` | Disassembles the `main` function |  
| `pdr` | Recursive disassembly of the function (follows internal jumps) |  
| `pds` | Function summary (only calls and strings used) |  
| `pds @ main` | Summary of `main`: which functions are called, with which strings |  
| `pdc` | C pseudo-code (basic built-in decompilation) |  
| `pdc @ main` | Pseudo-code of `main` |  
| `pdg` | Ghidra decompilation (requires the `r2ghidra` plugin) |  
| `pdg @ main` | Ghidra decompilation of `main` |  
| `pdi 20` | Disassembles 20 instructions (simplified format: opcode only) |  
| `pid 20` | Instructions with raw opcodes (bytes + mnemonic) |  
| `pif` | Instructions of the current function (simplified format) |

### 5.2 — Hexadecimal display

| Command | Description |  
|---------|-------------|  
| `px 64` | Hexadecimal dump of 64 bytes (`xxd`-like format) |  
| `px 64 @ main` | Dump of 64 bytes from the beginning of `main` |  
| `pxw 32` | Dump in dwords (4 bytes per element) |  
| `pxq 32` | Dump in qwords (8 bytes per element) |  
| `pxr 64` | Dump with recursive dereferencing (follows pointers) |  
| `p8 16` | Displays 16 raw bytes in hexadecimal (compact, no offset) |  
| `pc 32` | Dump in C array format (`unsigned char buf[] = {0x...}`) |  
| `pcp 32` | Dump in Python format (`buf = b"\x..."`) |  
| `pcj 32` | Dump in JSON format |

### 5.3 — String and data display

| Command | Description |  
|---------|-------------|  
| `ps @ <addr>` | Displays the C string (null-terminated) at the address |  
| `psz @ <addr>` | Same (zero-terminated string) |  
| `psw @ <addr>` | Wide string (UTF-16) |  
| `psp @ <addr>` | Pascal string (length-prefixed) |  
| `pf x` | Displays a hexadecimal dword at the current position |  
| `pf xxxx` | Displays 4 consecutive dwords |  
| `pf s` | Displays a C string |  
| `pf d` | Displays a signed integer |  
| `pf q` | Displays a qword |  
| `pf.elf_header @ 0` | Applies a named structure format (if defined) |

### 5.4 — Display configuration

| Command | Description |  
|---------|-------------|  
| `e asm.syntax = intel` | Switches to Intel syntax (recommended for RE) |  
| `e asm.syntax = att` | AT&T syntax |  
| `e asm.bytes = true` | Displays raw opcodes alongside the disassembly |  
| `e asm.bytes = false` | Hides opcodes (more readable) |  
| `e asm.comments = true` | Displays automatic comments |  
| `e asm.describe = true` | Adds a short description of each instruction |  
| `e asm.lines = true` | Displays connection lines between jumps |  
| `e asm.xrefs = true` | Displays inline xrefs in the disassembly |  
| `e scr.color = 3` | Maximum color level (0 = no color) |  
| `e scr.utf8 = true` | Enables UTF-8 characters (arrows, borders) |  
| `e asm.cmt.col = 50` | Comment column (adjusts alignment) |

To make the configuration permanent, add these commands to `~/.radare2rc`:

```
e asm.syntax = intel  
e scr.color = 3  
e scr.utf8 = true  
e asm.bytes = false  
e asm.describe = false  
```

---

## 6 — Visual graphs and interactive modes

### 6.1 — Visual mode (`V`)

Visual mode is a full-screen interactive display, navigable by keyboard. It is the most comfortable way to explore a binary in r2 from the console.

| Command / Key | Description |  
|---------------|-------------|  
| `V` | Enters visual mode (scrollable disassembly) |  
| `V!` | Enters "panels" visual mode (configurable layout) |  
| `p` / `P` | Cycles between views: hex → disassembly → debug → summary |  
| `j` / `k` | Scrolls down / up one line |  
| `J` / `K` | Scrolls down / up one page |  
| `Enter` | Follows a `call` or `jmp` (enters the target) |  
| `u` | Goes back (undo seek, like the "Back" button) |  
| `U` | Goes forward in history (redo seek) |  
| `o` | Go to an address or symbol (input prompt) |  
| `/` | Search for a string or value |  
| `;` | Add a comment at the current address |  
| `d` | Definition menu: function (`df`), data, string, etc. |  
| `n` | Rename the symbol at the current address |  
| `x` | Display xrefs to the current address |  
| `X` | Display xrefs from the current address |  
| `c` | Display the hex editing cursor (patch mode) |  
| `q` | Quit visual mode and return to the prompt |  
| `:` | Open the r2 command prompt without leaving visual mode |

### 6.2 — Graph mode (`VV`)

Graph mode displays the control flow graph (CFG) of the current function, with basic blocks connected by arrows.

| Command / Key | Description |  
|---------------|-------------|  
| `VV` | Enters graph mode for the current function |  
| `VV @ main` | Graph mode for the `main` function |  
| `h` / `j` / `k` / `l` | Directional navigation in the graph |  
| `H` / `J` / `K` / `L` | Moves the graph faster |  
| `tab` | Switches between basic blocks (cycle) |  
| `t` / `f` | Follows the true / false branch of a conditional jump |  
| `g` | Jump to a specific block |  
| `+` / `-` | Zoom in / out |  
| `0` | Resets zoom and recenters |  
| `p` | Cycles block display mode (asm, mini-blocks, summary) |  
| `R` | Randomizes block colors (helps distinguish paths) |  
| `;` | Add a comment |  
| `x` | Display xrefs |  
| `q` | Quit graph mode |

### 6.3 — Panels mode (`V!`)

Panels mode allows splitting the screen into multiple simultaneous zones (disassembly, registers, stack, hexdump) similar to GEF/pwndbg.

| Key | Description |  
|-----|-------------|  
| `V!` | Enters panels mode |  
| `tab` | Switches between panels |  
| `w` | Panel management menu |  
| `e` | Change the content of the selected panel |  
| `|` | Vertical split |  
| `-` | Horizontal split |  
| `X` | Close the selected panel |  
| `m` | Select a predefined layout |  
| `?` | Panels mode help |  
| `q` | Quit |

---

## 7 — Flags, comments, and annotations

### 7.1 — Flags (named markers)

Flags are named labels attached to addresses. Binary symbols, function names, and strings are all represented as flags internally.

| Command | Description |  
|---------|-------------|  
| `f` | Lists all flags |  
| `f flag_name @ 0x401234` | Creates a named flag at address `0x401234` |  
| `f- flag_name` | Removes a flag |  
| `fs` | Lists flag spaces (categories: `symbols`, `strings`, `imports`, etc.) |  
| `fs strings` | Selects the "strings" flag space |  
| `f~pattern` | Filters flags matching the pattern |  
| `fl` | Total number of flags |

### 7.2 — Comments

| Command | Description |  
|---------|-------------|  
| `CC comment text` | Adds a comment at the current address |  
| `CC comment text @ 0x401234` | Adds a comment at a specific address |  
| `CC-` | Removes the comment at the current address |  
| `CC` | Displays the comment at the current address |  
| `CCl` | Lists all comments |

### 7.3 — Types and structures

| Command | Description |  
|---------|-------------|  
| `t` | Lists loaded types |  
| `to file.h` | Loads types from a C header file |  
| `ts` | Lists structures |  
| `ts struct_name` | Displays a structure definition |  
| `tp struct_name @ addr` | Displays memory at `addr` interpreted according to the structure |  
| `tl struct_name @ addr` | Links a structure to an address (the display becomes permanent) |

---

## 8 — Search

### 8.1 — Searching in the binary

| Command | Description |  
|---------|-------------|  
| `/ string` | Searches for the ASCII string "string" |  
| `/x 9090` | Searches for a hex byte sequence (`0x90 0x90`) |  
| `/x 4889..24` | Searches with wildcard bytes (`.` = any nibble) |  
| `/w string` | Searches for a wide string (UTF-16) |  
| `/a jmp rax` | Searches for an assembly instruction |  
| `/A push rbp; mov rbp, rsp` | Searches for a multi-instruction assembly pattern |  
| `/r sym.strcmp` | Searches for references (xrefs) to `strcmp` |  
| `/R pop rdi` | Searches for ROP gadgets containing `pop rdi` |  
| `/R/ pop r..;ret` | Searches for gadgets by regular expression |  
| `/c jmp` | Searches for `jmp`-type instructions |  
| `/v 0xdeadbeef` | Searches for a numeric value (handles endianness) |  
| `/i password` | Searches for a case-insensitive string |

### 8.2 — Search results

| Command | Description |  
|---------|-------------|  
| `fs searches` | Selects the search results flag space |  
| `f~hit` | Lists the results (each match creates a `hit0_N` flag) |

---

## 9 — Debugging

### 9.1 — Execution control

| Command | Description |  
|---------|-------------|  
| `dc` | Continues execution |  
| `ds` | Step into (executes one instruction, enters `call`s) |  
| `dso` | Step over (executes one instruction, steps over `call`s) |  
| `dsf` | Step until end of function (executes until `ret`) |  
| `dsu <addr>` | Continues until the specified address |  
| `dsu sym.main` | Continues until `main` |  
| `dcr` | Continue until return (executes until function return) |  
| `dcu <addr>` | Continue until address |  
| `dcu sym.main` | Continue until `main` |  
| `dk 9` | Sends signal 9 (SIGKILL) to the process |  
| `dk` | Lists pending signals |

### 9.2 — Breakpoints

| Command | Description |  
|---------|-------------|  
| `db <addr>` | Sets a breakpoint at the address |  
| `db sym.main` | Breakpoint at the beginning of `main` |  
| `db-*` | Removes all breakpoints |  
| `db- <addr>` | Removes the breakpoint at the address |  
| `dbi` | Lists all breakpoints with their index |  
| `dbe <index>` | Enables breakpoint #`<index>` |  
| `dbd <index>` | Disables the breakpoint |  
| `dbH <addr>` | Sets a hardware breakpoint |  
| `dbc <addr> <cmd>` | Executes a command when the breakpoint is hit |  
| `dbw <addr> <rw>` | Watchpoint: `r` (read), `w` (write), `rw` (both) |

### 9.3 — Register inspection

| Command | Description |  
|---------|-------------|  
| `dr` | Displays all registers |  
| `dr rax` | Displays the value of `rax` |  
| `dr rax=0x42` | Modifies the value of `rax` |  
| `dr=` | Displays registers in compact format with progress bars |  
| `drt` | Displays registers by type (general, fpu, mmx, xmm) |  
| `drt xmm` | Displays only XMM registers |  
| `drr` | Recursive dereferencing of each register (follows pointers) |

### 9.4 — Stack and memory inspection

| Command | Description |  
|---------|-------------|  
| `dbt` | Backtrace (call stack) |  
| `dbt.` | Backtrace from the current frame |  
| `dm` | Process memory mapping (equivalent of `/proc/pid/maps`) |  
| `dm.` | Memory section containing the current address |  
| `dm libc` | Filters the mapping for libc |  
| `dmh` | Heap information |  
| `dmhg` | Graphical display of heap chunks |  
| `dmhb` | Displays heap bins (fastbin, unsorted, etc.) |  
| `dmp <addr> <size> <perms>` | Changes memory permissions of a page |

### 9.5 — Traces and profiling

| Command | Description |  
|---------|-------------|  
| `dt` | Displays collected traces |  
| `dts+` | Creates a new timestamp (time marker) for profiling |  
| `dte` | Enables system call (syscall) tracing |  
| `e dbg.trace = true` | Enables global tracing (logs all executed instructions) |

---

## 10 — Writing and patching

r2 can modify a binary directly if the file is opened in write mode (`r2 -w` or `oo+`).

| Command | Description |  
|---------|-------------|  
| `wa nop` | Assembles and writes a `nop` at the current position |  
| `wa jmp 0x401250` | Assembles and writes a `jmp` to the specified address |  
| `wa nop @ 0x401234` | Writes a `nop` at address `0x401234` |  
| `"wa nop;nop;nop"` | Writes multiple instructions (separated by `;`) |  
| `wx 90` | Writes byte `0x90` (nop) at the current position |  
| `wx 9090909090` | Writes 5 bytes |  
| `wx 9090 @ 0x401234` | Writes at a specific address |  
| `wv 0x41414141` | Writes a 4-byte value (little-endian) |  
| `wv8 0x4141414141414141` | Writes an 8-byte value |  
| `wz "hello"` | Writes a null-terminated string |  
| `wo` | Byte operation submenu (xor, add, etc.) |  
| `wox 0xff` | XORs all bytes in the current block with `0xFF` |  
| `woa 1` | Adds 1 to each byte in the current block |

**Patching conditional jumps** — The most common RE operation: inverting a `jz` to `jnz` or vice versa.

| Desired patch | Command |  
|---------------|---------|  
| `jz` → `jnz` | `wx 75 @ <addr>` (changes opcode `0x74` to `0x75`) |  
| `jnz` → `jz` | `wx 74 @ <addr>` (changes `0x75` to `0x74`) |  
| NOP-out an instruction (2 bytes) | `wx 9090 @ <addr>` |  
| NOP-out a `call` (5 bytes) | `wx 9090909090 @ <addr>` |  
| Force a jump (replace `jz` with `jmp` short) | `wx eb @ <addr>` (changes to `jmp rel8`) |

> ⚠️ After any modification, verify the result with `pd 5 @ <addr>` to confirm that the disassembly is correct. One byte too many or too few can misalign all subsequent instructions.

---

## 11 — Companion tools (r2 suite)

Radare2 ships with several command-line tools that can be used independently from the interactive session.

| Tool | Description |  
|------|-------------|  
| `rabin2` | Binary header and metadata analysis (equivalent of `readelf` + `file` + `strings`) |  
| `rasm2` | Command-line assembler/disassembler |  
| `rahash2` | Hash and checksum computation |  
| `radiff2` | Binary diffing |  
| `rafind2` | Pattern searching in files |  
| `ragg2` | Shellcode and pattern generator |  
| `rarun2` | Program launcher with controlled environment |  
| `rax2` | Base converter and calculator |

### 11.1 — `rabin2` — Quick analysis

| Command | Description |  
|---------|-------------|  
| `rabin2 -I ./binary` | General information (arch, bits, protections, endian) |  
| `rabin2 -z ./binary` | Strings in data sections |  
| `rabin2 -zz ./binary` | Strings in the entire binary |  
| `rabin2 -i ./binary` | Imports |  
| `rabin2 -E ./binary` | Exports |  
| `rabin2 -S ./binary` | Sections |  
| `rabin2 -s ./binary` | Symbols |  
| `rabin2 -l ./binary` | Linked libraries |  
| `rabin2 -e ./binary` | Entrypoints |  
| `rabin2 -H ./binary` | ELF headers |

### 11.2 — `rasm2` — Assemble/disassemble

| Command | Description |  
|---------|-------------|  
| `rasm2 -a x86 -b 64 "nop"` | Assembles `nop` → outputs `90` |  
| `rasm2 -a x86 -b 64 "push rbp; mov rbp, rsp"` | Assembles a prologue |  
| `rasm2 -a x86 -b 64 -d "554889e5"` | Disassembles the bytes → `push rbp; mov rbp, rsp` |  
| `rasm2 -a x86 -b 64 -D "554889e5"` | Disassembles with addresses and sizes |

### 11.3 — `radiff2` — Diffing

| Command | Description |  
|---------|-------------|  
| `radiff2 binary_v1 binary_v2` | Byte-by-byte diff |  
| `radiff2 -g main binary_v1 binary_v2` | Graphical diff of the `main` function blocks |  
| `radiff2 -AC binary_v1 binary_v2` | Function-level diff with code analysis |  
| `radiff2 -ss binary_v1 binary_v2` | Diff based on function similarity |

### 11.4 — `rax2` — Conversions and calculator

| Command | Description |  
|---------|-------------|  
| `rax2 0x41` | Hex → decimal → ASCII (`65 0x41 A`) |  
| `rax2 65` | Decimal → hex |  
| `rax2 -s 414243` | Hex → ASCII string (`ABC`) |  
| `rax2 -S "ABC"` | String → hex (`414243`) |  
| `rax2 -e 0x41424344` | Swap endianness |  
| `rax2 -b 0xff` | Hex → binary |  
| `rax2 -k 1024` | Human-readable size (1K) |  
| `rax2 '0x100+0x50'` | Hexadecimal calculator (`0x150`) |

### 11.5 — `rahash2` — Hashes and checksums

| Command | Description |  
|---------|-------------|  
| `rahash2 -a md5 ./binary` | Computes the MD5 hash of the file |  
| `rahash2 -a sha256 ./binary` | SHA-256 hash |  
| `rahash2 -a all ./binary` | All hash algorithms |  
| `rahash2 -a crc32 ./binary` | CRC32 |  
| `rahash2 -a entropy -b 256 ./binary` | Entropy per 256-byte blocks (useful for detecting packing) |  
| `rahash2 -D base64 < encoded.txt` | Decodes Base64 |  
| `rahash2 -E base64 < plain.txt` | Encodes in Base64 |

### 11.6 — `rafind2` — Searching in files

| Command | Description |  
|---------|-------------|  
| `rafind2 -ZS "password" ./binary` | Searches for the string "password" |  
| `rafind2 -x 7f454c46 ./binary` | Searches for the hex sequence (here: ELF magic `\x7fELF`) |  
| `rafind2 -X ./binary` | Displays printable strings (similar to `strings`) |

### 11.7 — `ragg2` — Pattern and shellcode generator

| Command | Description |  
|---------|-------------|  
| `ragg2 -P 200` | Generates a 200-byte De Bruijn pattern |  
| `ragg2 -q 0x41416241` | Calculates the corresponding offset in a De Bruijn pattern |  
| `ragg2 -a x86 -b 64 -i exec` | Generates an `execve` x86-64 shellcode |

### 11.8 — `rarun2` — Controlled execution launcher

`rarun2` allows you to define an execution profile for a program (stdin, stdout, arguments, environment variables, limits) without writing a shell script. It is used via a `.rr2` file:

```ini
# profile.rr2
program=./binary  
arg1=AAAA  
arg2=test  
stdin=input.txt  
timeout=5  
setenv=DEBUG=1  
```

Launch:

```bash
r2 -d -e dbg.profile=profile.rr2 ./binary
# or directly:
rarun2 profile.rr2
```

This is particularly useful for fuzzing and test automation in RE, when you need to provide reproducible input to the target binary from r2.

---

## 12 — Scripting with r2pipe

r2pipe is the official Python library for interacting with r2 programmatically. It opens an r2 session and sends commands via a pipe.

### 12.1 — Basic usage

```python
import r2pipe

r2 = r2pipe.open("./binary")  
r2.cmd("aaa")                      # Analysis  

# Binary information
info = r2.cmdj("ij")               # 'j' = JSON → returns a Python dict  
print(f"Architecture: {info['bin']['arch']}")  
print(f"Bits: {info['bin']['bits']}")  

# List functions
functions = r2.cmdj("aflj")        # Function list in JSON  
for f in functions:  
    print(f"0x{f['offset']:08x}  {f['size']:5d}  {f['name']}")

# Disassemble main
r2.cmd("s main")  
disasm = r2.cmd("pdf")  
print(disasm)  

# Search for strings
strings = r2.cmdj("izj")  
for s in strings:  
    if "password" in s.get("string", "").lower():
        print(f"0x{s['vaddr']:08x}: {s['string']}")

# Xrefs to strcmp
xrefs = r2.cmdj("axtj @ sym.imp.strcmp")  
for x in xrefs:  
    print(f"strcmp called from 0x{x['from']:08x} in {x.get('fcn_name', '?')}")

r2.quit()
```

### 12.2 — Common r2pipe commands

| Python method | Description |  
|---------------|-------------|  
| `r2.cmd("command")` | Executes a command and returns the result as text |  
| `r2.cmdj("commandj")` | Executes a JSON command and returns a Python object (dict/list) |  
| `r2.quit()` | Closes the r2 session |

The standard pattern is to use `cmdj` with the `j` suffix of the r2 command whenever you want to process results programmatically, and `cmd` when you simply want to display text.

### 12.3 — Advanced example: batch analysis of multiple binaries

```python
import r2pipe  
import os  
import json  

def analyze_binary(path):
    """Analyzes a binary and returns a structured summary."""
    r2 = r2pipe.open(path)
    r2.cmd("aaa")

    info = r2.cmdj("ij")
    functions = r2.cmdj("aflj") or []
    imports = r2.cmdj("iij") or []
    strings = r2.cmdj("izj") or []

    summary = {
        "file": path,
        "arch": info.get("bin", {}).get("arch", "?"),
        "bits": info.get("bin", {}).get("bits", 0),
        "language": info.get("bin", {}).get("lang", "?"),
        "num_functions": len(functions),
        "num_imports": len(imports),
        "num_strings": len(strings),
        "interesting_imports": [
            i["name"] for i in imports
            if any(kw in i.get("name", "").lower()
                   for kw in ["crypt", "strcmp", "exec", "system",
                              "socket", "connect", "send", "recv"])
        ],
        "interesting_strings": [
            s["string"] for s in strings
            if any(kw in s.get("string", "").lower()
                   for kw in ["password", "key", "flag", "secret",
                              "admin", "login", "http", "token"])
        ][:20]  # Limit to 20 strings
    }

    r2.quit()
    return summary

# Analyze all binaries in a directory
results = []  
for fname in os.listdir("./binaries"):  
    fpath = os.path.join("./binaries", fname)
    if os.path.isfile(fpath):
        try:
            result = analyze_binary(fpath)
            results.append(result)
            print(f"[OK] {fname}: {result['num_functions']} functions")
        except Exception as e:
            print(f"[ERR] {fname}: {e}")

with open("analysis_report.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"\nReport written to analysis_report.json ({len(results)} binaries)")
```

This type of script illustrates the power of r2pipe for automation: the entire r2 API is accessible from Python, and the `j` suffix makes parsing results trivial.

---

## 13 — Cutter — Radare2 graphical interface

Cutter is the official graphical front-end for r2. It exposes the same functionalities as the r2 console in a Qt interface with movable widgets.

### 13.1 — Main panels

| Panel | r2 equivalent | Description |  
|-------|---------------|-------------|  
| **Disassembly** | `pd` / `pdf` | Linear or function-based disassembly |  
| **Graph** | `VV` | Interactive control flow graph |  
| **Decompiler** | `pdc` / `pdg` | C pseudo-code (built-in decompiler or r2ghidra) |  
| **Hexdump** | `px` | Hexadecimal view |  
| **Functions** | `afl` | Function list with search and filtering |  
| **Strings** | `iz` / `izz` | String list with double-click to navigate |  
| **Imports** | `ii` | Import table |  
| **Exports** | `iE` | Export table |  
| **Sections** | `iS` | Binary sections |  
| **Symbols** | `is` | Symbol table |  
| **XRefs** | `axt` / `axf` | Cross-references (accessible via right-click) |  
| **Registers** | `dr` | Registers (in debug mode) |  
| **Stack** | `pxr @ rsp` | Stack (in debug mode) |  
| **Console** | (r2 prompt) | Built-in r2 terminal for manual commands |  
| **Dashboard** | `i` | Binary summary |

### 13.2 — Cutter keyboard shortcuts

| Shortcut | Description |  
|----------|-------------|  
| `Space` | Toggles between linear view and graph view |  
| `g` | Go to an address or symbol |  
| `n` | Rename the selected function or symbol |  
| `;` | Add a comment |  
| `x` | Display xrefs to the selected element |  
| `Ctrl+Shift+F` | Search the entire binary |  
| `Tab` | Switch between disassembly and decompiler |  
| `Escape` | Go back in navigation history |  
| `Ctrl+F5` | Start debugging |  
| `F2` | Set/remove a breakpoint |  
| `F5` | Continue execution (debug) |  
| `F7` | Step into (debug) |  
| `F8` | Step over (debug) |  
| `F9` | Continue (debug) |  
| `Ctrl+R` | Open the built-in r2 console |

### 13.3 — Cutter plugins

| Plugin | Description |  
|--------|-------------|  
| **r2ghidra** | Integrates the Ghidra decompiler into Cutter (decompilation quality significantly better than native `pdc`) |  
| **r2dec** | Alternative built-in decompiler |  
| **r2yara** | YARA pattern searching |  
| **cutterref** | Built-in command reference sheet |

To install r2ghidra (recommended):

```bash
r2pm -ci r2ghidra
```

Once installed, the Decompiler panel in Cutter automatically uses the Ghidra engine, and the `pdg` command becomes available in the r2 console.

---

## 14 — Recommended `~/.radare2rc` file

The `~/.radare2rc` file is automatically read at every r2 launch. It allows you to define persistent preferences without having to retype them each session.

```bash
# ─── Display ──────────────────────────────────
e asm.syntax = intel          # Intel syntax (essential for RE)  
e scr.color = 3               # Maximum coloring  
e scr.utf8 = true             # Unicode characters (arrows, borders)  
e scr.wheel = true            # Mouse wheel support in the terminal  

# ─── Disassembly ──────────────────────────────
e asm.bytes = false           # Hides raw opcodes (more readable)  
e asm.describe = false        # No instruction descriptions (too verbose)  
e asm.lines = true            # Connection lines between jumps  
e asm.lines.call = true       # Lines for calls too  
e asm.xrefs = true            # Displays inline xrefs  
e asm.cmt.col = 55            # Comment column  
e asm.var = true              # Displays local variable names  

# ─── Analysis ────────────────────────────────
e anal.jmp.ref = true         # Follows jump references during analysis  
e anal.jmp.cref = true        # Follows call references  
e anal.hasnext = true         # Detects functions that immediately follow  

# ─── Debugging ───────────────────────────────
e dbg.follow.child = false    # Follows the parent by default after fork  
e dbg.btalgo = fuzzy          # More tolerant backtrace algorithm  

# ─── Performance ────────────────────────────
e bin.cache = true            # Caches binary analysis results  
e io.cache = true             # Caches I/O reads (faster)  
```

---

## 15 — r2 ↔ GDB ↔ Cutter correspondence

This table establishes equivalences between the three environments for the most common operations. Useful if you are used to GDB and are switching to r2, or vice versa.

| Operation | GDB | r2 (console) | Cutter |  
|-----------|-----|--------------|--------|  
| Run the program | `run` | `dc` (in `-d` mode) | `Ctrl+F5` |  
| Continue | `continue` | `dc` | `F9` |  
| Step into | `stepi` | `ds` | `F7` |  
| Step over | `nexti` | `dso` | `F8` |  
| Finish (until ret) | `finish` | `dsf` / `dcr` | — |  
| Breakpoint | `break *0x401234` | `db 0x401234` | `F2` |  
| List breakpoints | `info breakpoints` | `dbi` | Breakpoints panel |  
| View registers | `info registers` | `dr` | Registers panel |  
| Modify register | `set $rax = 42` | `dr rax=42` | Double-click on the value |  
| Backtrace | `backtrace` | `dbt` | Stack panel |  
| Examine memory (hex) | `x/20gx $rsp` | `pxq 160 @ rsp` | Hexdump panel |  
| Examine memory (instructions) | `x/10i $rip` | `pd 10 @ rip` | Disassembly panel |  
| String at an address | `x/s $rdi` | `ps @ rdi` | — |  
| Memory map | `info proc mappings` | `dm` | — |  
| Disassemble a function | `disas main` | `pdf @ main` | Double-click in Functions |  
| Search for a string | `find 0x400000, 0x500000, "str"` | `/ str` | `Ctrl+Shift+F` |  
| List functions | `info functions` | `afl` | Functions panel |  
| List strings | — | `iz` | Strings panel |  
| Imports | — | `ii` | Imports panel |  
| Sections | `maintenance info sections` | `iS` | Sections panel |  
| Xrefs to | — | `axt <addr>` | Right-click → Xrefs to |  
| Xrefs from | — | `axf <addr>` | Right-click → Xrefs from |  
| Add comment | — | `CC text` | `;` |  
| Rename | — | `afn name` | `n` |  
| Patch (nop) | `set *(char*)0x...=0x90` | `wx 90 @ 0x...` | Right-click → Edit → NOP |  
| Function graph | — | `VV` | `Space` |  
| Decompile | — | `pdc` / `pdg` | `Tab` |  
| Quit | `quit` | `q` | Close the window |

---

## 16 — Typical r2 workflows

### 16.1 — Quick triage of an unknown binary (5 minutes)

```bash
r2 -A ./mystery_bin
```

```
i                        # Format, arch, bits, endianness  
iI                       # Protections (canary, NX, PIE, RELRO)  
ie                       # Entry point  
il                       # Linked libraries  
iS                       # Sections (check sizes, unusual sections)  
iz                       # Strings in .rodata/.data  
iz~pass                  # Search for keywords: pass, key, flag, secret, admin  
iz~key  
iz~flag  
ii                       # Imports → which library functions are used?  
ii~crypt                 # Imported crypto functions?  
ii~strcmp                # String comparisons?  
ii~socket                # Network activity?  
afl                      # List of detected functions  
afl~main                 # The main function  
pdf @ main               # Disassemble main for an overview  
pds @ main               # Summary of main: calls and strings used  
```

This workflow corresponds to the "quick triage" from Chapter 5.7 transposed to r2 commands. In less than 5 minutes, you have an overview of what the binary does, its dependencies, its interesting strings, and its function structure.

### 16.2 — Tracing a suspicious string to the code

```
iz~password              # Find the string
                         # Result: 0x00402010 "Enter password:"
axt @ 0x00402010         # Who uses this string?
                         # Result: called from 0x00401185 in sym.check_auth
s sym.check_auth         # Move to the function  
pdf                      # Disassemble the complete function  
VV                       # Control flow graph to see the branches  
```

### 16.3 — Analyzing a crackme in debug mode

```bash
r2 -d -A ./crackme
```

```
db sym.main              # Breakpoint at main  
dc                       # Run  
pdf                      # See where we are  
afl~check                # Search for a verification function  
db sym.check_password    # Breakpoint on the verification  
dc                       # Continue (the program waits for input)  
                         # → Type a dummy password in the terminal
dr                       # Inspect registers at the comparison point  
ps @ rdi                 # View the string in the first argument (our input?)  
ps @ rsi                 # View the string in the second argument (the password?)  
```

### 16.4 — Patching a binary to bypass a check

```bash
r2 -w ./crackme          # Open in write mode
```

```
aaa                      # Analysis  
afl~check                # Find the verification function  
pdf @ sym.check_password # Disassemble  
                         # Identify the critical jnz/jz
                         # Suppose it is at 0x00401234
wx 75 @ 0x00401234       # Invert jz (0x74) to jnz (0x75)
                         # OR
wx eb @ 0x00401234       # Force an unconditional jmp  
pd 5 @ 0x00401234        # Verify the patch  
q                        # Quit (modifications are saved)  
```

---

## 17 — Quick reference: the 30 essential commands

For daily RE sessions, this table condenses the must-know commands. If you can only remember one page from this appendix, this is it.

| # | Command | What it does |  
|---|---------|--------------|  
| 1 | `r2 -A ./bin` | Opens + automatic analysis |  
| 2 | `aaa` | Deep analysis |  
| 3 | `i` | General binary info |  
| 4 | `iS` | Sections |  
| 5 | `ii` | Imports |  
| 6 | `iz` | Strings |  
| 7 | `afl` | Function list |  
| 8 | `s <addr/sym>` | Move (seek) |  
| 9 | `s-` | Go back |  
| 10 | `pdf` | Disassemble the current function |  
| 11 | `pd 20` | Disassemble 20 instructions |  
| 12 | `pds` | Function summary (calls + strings) |  
| 13 | `pdc` / `pdg` | Decompile |  
| 14 | `px 64` | Hex dump |  
| 15 | `ps @ <addr>` | Display a C string |  
| 16 | `axt <addr>` | Xrefs to (who uses this address?) |  
| 17 | `axf <addr>` | Xrefs from (what does this address call?) |  
| 18 | `/ string` | Search for a string |  
| 19 | `/R pop rdi` | Search for a ROP gadget |  
| 20 | `V` | Visual mode |  
| 21 | `VV` | Graph mode |  
| 22 | `afn <name>` | Rename a function |  
| 23 | `CC <text>` | Add a comment |  
| 24 | `db <addr>` | Breakpoint (debug mode) |  
| 25 | `dc` | Continue (debug mode) |  
| 26 | `ds` / `dso` | Step into / step over |  
| 27 | `dr` | Registers |  
| 28 | `dm` | Memory map |  
| 29 | `wx <hex>` | Write bytes (patch) |  
| 30 | `q` | Quit |

---

> 📚 **To go further**:  
> - **Appendix C** — [GDB / GEF / pwndbg Cheat sheet](/appendices/appendix-c-cheatsheet-gdb.md) — the reference sheet for the complementary debugger.  
> - **Appendix E** — [ImHex Cheat sheet: `.hexpat` syntax](/appendices/appendix-e-cheatsheet-imhex.md) — reference for advanced hexadecimal analysis.  
> - **Chapter 9, sections 9.2–9.4** — [Radare2 / Cutter and r2pipe scripting](/09-ida-radare2-binja/02-radare2-cutter.md) — pedagogical coverage of r2 with progressive use cases.  
> - **Radare2 Book** — [https://book.rada.re/](https://book.rada.re/) — the complete official r2 manual.  
> - **Cutter** — [https://cutter.re/](https://cutter.re/) — documentation and download for the graphical interface.  
> - **r2pipe** — `pip install r2pipe` — documentation on [GitHub](https://github.com/radareorg/radare2-r2pipe).

⏭️ [ImHex Cheat sheet: `.hexpat` reference syntax](/appendices/appendix-e-cheatsheet-imhex.md)
