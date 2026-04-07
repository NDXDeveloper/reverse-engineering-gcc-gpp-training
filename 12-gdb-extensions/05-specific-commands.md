🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 12.5 — Useful commands specific to each extension

> **Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg**  
> **Part III — Dynamic Analysis**

---

## Overview

Previous sections covered the flagship features of GDB extensions: contextual display (12.2), ROP gadget searching (12.3), and heap analysis (12.4). But each extension carries dozens of additional commands that accelerate the reverse engineer's daily work. This section reviews the most useful commands not yet covered, organized by extension then by cross-cutting theme.

---

## PEDA-specific commands

Despite its slowed development, PEDA remains relevant for some simple and well-thought-out commands.

### `checksec` — protection verification

```
gdb-peda$ checksec  
CANARY    : ENABLED  
FORTIFY   : disabled  
NX        : ENABLED  
PIE       : ENABLED  
RELRO     : FULL  
```

PEDA popularized this command that displays the debugged binary's security protections. It's the GDB equivalent of the `checksec` command-line tool (section 5.6), with the advantage of operating on the process loaded in memory rather than on the static file. GEF and pwndbg each offer their own `checksec` implementation, but PEDA introduced it first in the GDB context.

### `searchmem` / `find` — pattern searching in memory

```
gdb-peda$ searchmem "password"  
Searching for 'password' in: binary ranges  
Found 2 results, display max 2 items:  
keygenme_O0 : 0x555555556008 ("password_expected")  
[stack]     : 0x7fffffffe0b4 ("password_user_input")
```

`searchmem` scans the process's memory looking for an ASCII string, hex value, or byte pattern. You can restrict the search to a specific region:

```
gdb-peda$ searchmem 0xdeadbeef stack  
gdb-peda$ searchmem "/bin/sh" libc  
```

Recognized search targets are `binary`, `stack`, `heap`, `libc`, `all`, or an explicit address range `start-end`.

### `xormem` — XOR a memory region

```
gdb-peda$ xormem 0x555555559290 0x5555555592b0 0x42
```

This command applies XOR with a given key on a memory range. It's a niche but precious utility when analyzing binaries that use simple XOR encoding to mask strings or data — a frequent pattern in simple malware (Chapters 27–28). `xormem` decodes a zone directly in the process's memory without an external script.

### `procinfo` — process information

```
gdb-peda$ procinfo  
exe: /home/user/binaries/ch12-keygenme/keygenme_O0  
pid: 12345  
ppid: 12300  
uid: [1000, 1000, 1000, 1000]  
gid: [1000, 1000, 1000, 1000]  
```

`procinfo` gathers information extracted from `/proc/pid/` in a single command: executable path, PID, UID/GID, and other process metadata. It's a handy shortcut to confirm the right binary is loaded.

### `elfheader` and `elfsymbol` — ELF structures from the debugger

```
gdb-peda$ elfheader
.interp    = 0x555555554318
.note.gnu.property = 0x555555554338
.gnu.hash  = 0x555555554368
.dynsym    = 0x555555554390
.dynstr    = 0x555555554438
.text      = 0x555555555060
.rodata    = 0x555555556000
...

gdb-peda$ elfsymbol printf  
printf@plt = 0x555555555030  
```

These commands extract information from ELF tables from the process's memory. `elfheader` lists sections with their effective addresses (after relocation), and `elfsymbol` searches for a symbol by name. This avoids switching to `readelf` or `objdump` in another terminal during a debugging session.

---

## GEF-specific commands

### `xinfo` — know everything about an address

```
gef➤ xinfo 0x7ffff7e15a80
──────────────────── xinfo: 0x7ffff7e15a80 ────────────────────
Page: 0x7ffff7dd5000 → 0x7ffff7f5d000 (size=0x188000)  
Permissions: r-x  
Pathname: /lib/x86_64-linux-gnu/libc.so.6  
Offset (from page): 0x40a80  
Inode: 1835041  
Segment: .text (libc.so.6)  
Symbol: __libc_start_call_main+128  
```

`xinfo` is one of GEF's most valuable commands. It takes any address as argument and returns everything GEF knows about it: the memory page containing it, permissions, mapped file, file offset, ELF section, and nearest symbol. It's a universal investigation tool. When you see an unknown address in a register or on the stack, `xinfo` immediately answers the question "what is this address?".

### `vmmap` — enriched memory map

```
gef➤ vmmap
[ Legend: Code | Heap | Stack | Writable | ReadOnly ]
Start              End                Size               Offset  Perm  Path
0x555555554000     0x555555555000     0x1000             0x0     r--   /home/user/keygenme_O0
0x555555555000     0x555555556000     0x1000             0x1000  r-x   /home/user/keygenme_O0
0x555555556000     0x555555557000     0x1000             0x2000  r--   /home/user/keygenme_O0
0x555555557000     0x555555559000     0x2000             0x2000  rw-   /home/user/keygenme_O0
0x555555559000     0x55555557a000     0x21000            0x0     rw-   [heap]
0x7ffff7dd5000     0x7ffff7f5d000     0x188000           0x0     r-x   /lib/.../libc.so.6
...
0x7ffffffde000     0x7ffffffff000     0x21000            0x0     rw-   [stack]
```

`vmmap` exists in all three extensions, but GEF enriches the output with a colored legend that visually distinguishes code, heap, stack, and writable regions. pwndbg offers a similar display. The command accepts an optional filter:

```
gef➤ vmmap libc  
gef➤ vmmap heap  
gef➤ vmmap stack  
```

### `pattern create` / `pattern search` — De Bruijn patterns

These commands serve to calculate the exact offset of a buffer overflow. You generate a unique cyclic pattern, send it as input to the program, and identify which portion of the pattern overwrote a register or return address.

```
gef➤ pattern create 200  
aaaaaaaabaaaaaaacaaaaaaadaaaa...  

gef➤ run  
Enter password: aaaaaaaabaaaaaaacaaaaaaadaaaa...  
Program received signal SIGSEGV  

gef➤ pattern search $rsp
[+] Found at offset 72 (little-endian search) likely
```

GEF generates a De Bruijn pattern where each 8-character subsequence (on x86-64) is unique. After the crash, `pattern search` takes the corrupted value of a register or address and finds its position in the pattern, directly giving the offset in bytes between the buffer's start and the overwrite point.

pwndbg offers equivalent commands named `cyclic` and `cyclic -l`:

```
pwndbg> cyclic 200  
pwndbg> cyclic -l 0x6161616161616166  
```

PEDA uses `pattern_create` and `pattern_search` with underscores.

### `got` — GOT table at a glance

```
gef➤ got  
GOT protection: Full RELRO | GOT functions: 5  

[0x555555557fd8] puts@GLIBC_2.2.5  →  0x7ffff7e52420
[0x555555557fe0] printf@GLIBC_2.2.5  →  0x7ffff7e37e50
[0x555555557fe8] strcmp@GLIBC_2.2.5  →  0x7ffff7e6db70
[0x555555557ff0] malloc@GLIBC_2.2.5  →  0x7ffff7e92070
[0x555555557ff8] free@GLIBC_2.2.5  →  0x7ffff7e92460
```

The `got` command displays the Global Offset Table with the resolved addresses of each imported function. This shows at once all library functions used by the program and their effective addresses in memory. It's a shortcut for `x/gx address` on each GOT entry, and a quick way to check whether lazy binding has occurred (if an entry points to the PLT stub, resolution hasn't happened yet).

pwndbg offers the same `got` command. PEDA uses `got` or `elfgot` depending on versions.

### `highlight` — dynamic pattern coloring

```
gef➤ highlight add "0xdeadbeef" yellow  
gef➤ highlight add "strcmp" red  
```

`highlight` adds a persistent coloring rule: any occurrence of the specified pattern in GDB's output will be automatically colorized. It's useful for visually tracking a sentinel value across successive contexts, or highlighting calls to a function of interest without setting a breakpoint.

```
gef➤ highlight list                    # list active rules  
gef➤ highlight remove "0xdeadbeef"     # remove a rule  
```

### `edit-flags` — modify CPU flags

```
gef➤ edit-flags +zero       # enable the Zero Flag  
gef➤ edit-flags -carry       # disable the Carry Flag  
```

This command allows directly modifying individual flags of the `RFLAGS` register by name. In vanilla GDB, you'd have to compute the complete numeric value of `RFLAGS` and patch it with `set $eflags = ...`. With `edit-flags`, you manipulate each flag individually by its readable name. It's particularly useful for forcing a conditional jump: if the program is on a `jz` and you want to take the jump, enable `ZF` with `edit-flags +zero` before `stepi`.

### `aliases` — custom shortcuts

GEF allows defining aliases for frequently used commands:

```
gef➤ aliases add "ctx" "context"  
gef➤ aliases add "tele" "dereference"  
```

These aliases are saved in `~/.gef.rc` via `gef save` and persist between sessions.

---

## pwndbg-specific commands

### `nextcall` / `nextjmp` / `nextret` — semantic navigation

These commands advance execution to the next instruction of a given type:

```
pwndbg> nextcall          # continue until the next `call`  
pwndbg> nextjmp           # continue until the next jump (conditional or not)  
pwndbg> nextret           # continue until the next `ret`  
pwndbg> nextsyscall       # continue until the next `syscall`  
```

In vanilla GDB, achieving the same result requires setting a temporary breakpoint on each instruction of the desired type, or looping `stepi`. These pwndbg commands transform code traversal into navigation by semantic points of interest. `nextret` is particularly useful for quickly exiting a function without knowing its exact epilogue. `nextcall` lets you walk through a program stopping only on function calls, giving a high-level view of execution flow.

### `search` — polymorphic memory search

```
pwndbg> search --string "password"  
pwndbg> search --dword 0xdeadbeef  
pwndbg> search --qword 0x00007ffff7e52420  
pwndbg> search --bytes "48 89 e5"  
pwndbg> search --string "/bin/sh" --executable  
```

pwndbg's `search` command is more expressive than equivalents in PEDA and GEF. It accepts an explicit type (`--string`, `--byte`, `--word`, `--dword`, `--qword`, `--bytes` for arbitrary byte sequences) and a permission filter (`--executable`, `--writable`). The permission filter is precious: `--executable` restricts the search to executable pages (useful for finding gadgets or opcode sequences), while `--writable` targets modifiable data regions (useful for finding where to write during exploitation).

### `regs` — register filtering

```
pwndbg> regs  
pwndbg> regs --all            # includes SIMD, segment registers, detailed flags  
```

Without arguments, `regs` displays general registers with the same formatting as the context section. With `--all`, it includes segment registers (`cs`, `ds`, `ss`, etc.), SIMD registers (`xmm0`–`xmm15`), and a detailed flag-by-flag decoding of `RFLAGS`. It's a shortcut for vanilla GDB's `info all-registers`, but with pwndbg's recursive dereferencing and coloring.

### `procinfo` — detailed process information

```
pwndbg> procinfo  
exe     /home/user/binaries/ch12-keygenme/keygenme_O0  
pid     12345  
tid     12345  
ppid    12300  
uid     1000  
gid     1000  
groups  [1000, 27, 110]  
fd[0]   /dev/pts/3  
fd[1]   /dev/pts/3  
fd[2]   /dev/pts/3  
fd[3]   socket:[54321]  
```

pwndbg's `procinfo` version is more detailed than PEDA's: it includes open file descriptors, which is extremely useful for understanding a network binary's communications (Chapter 23). An `fd[3]` of type `socket` immediately indicates an active network connection.

### `plt` — PLT table

```
pwndbg> plt  
Section .plt 0x555555555020-0x555555555060:  
  0x555555555030: puts@plt
  0x555555555040: printf@plt
  0x555555555050: strcmp@plt
```

The `plt` command lists Procedure Linkage Table entries with imported function names. Combined with `got`, it gives a complete view of the dynamic-resolution mechanism seen in Chapter 2 (section 2.9).

### `distance` — offset calculation between two addresses

```
pwndbg> distance $rsp $rbp
0x7fffffffe090->0x7fffffffe0c0 is 0x30 bytes (0x6 words)
```

`distance` computes the difference between two addresses and expresses it in bytes and machine words. It's a simple shortcut that avoids mental hexadecimal calculations when determining a stack frame's size or the distance between two buffers.

### `canary` — stack canary value

```
pwndbg> canary  
AT_RANDOM = 0x7fffffffe2c9  
Found valid canaries on the stacks:  
00:0000│  0x7fffffffe0b8 ◂— 0xa3f2e1d0c9b8a7f6
```

This command locates and displays the program's stack canary value. It searches in TLS (Thread-Local Storage) and on the stack to find the original value and check if it's been corrupted. Knowing the canary value is useful during an audit: it allows building a test exploit that preserves the canary, or verifying that a detected overflow actually reaches the canary.

### `patchelf` and `dumpargs`

`dumpargs` displays the arguments of the function about to be called by interpreting the System V AMD64 calling convention:

```
pwndbg> dumpargs
        rdi = 0x7fffffffe0b0 → "user_input"
        rsi = 0x555555556004 → "expected_key"
```

This command is implicitly active in pwndbg's context (arguments are annotated near `call`s), but it can be invoked manually when on a `call` instruction and you want a clean argument display without the rest of the context.

---

## Cross-cutting commands: same needs, different syntaxes

Some operations are available in all three extensions but with different names or syntaxes. The following table serves as a quick reference for translating between the three.

| Need | PEDA | GEF | pwndbg |  
|---|---|---|---|  
| String search in memory | `searchmem "str"` | `grep memory "str"` | `search --string "str"` |  
| Byte search in memory | `searchmem 0xDEAD` | `scan section 0xDE 0xAD` | `search --bytes "DE AD"` |  
| Recursive stack dereferencing | `telescope 20` (basic) | `dereference $rsp 20` | `telescope $rsp 20` |  
| Memory mapping | `vmmap` | `vmmap` | `vmmap` |  
| Binary protections | `checksec` | `checksec` | `checksec` |  
| GOT table | `elfgot` / `got` | `got` | `got` |  
| PLT table | — | — | `plt` |  
| Information about an address | `xinfo addr` (limited) | `xinfo addr` | `xinfo addr` |  
| De Bruijn pattern (creation) | `pattern_create 200` | `pattern create 200` | `cyclic 200` |  
| De Bruijn pattern (search) | `pattern_search` | `pattern search $reg` | `cyclic -l val` |  
| Execute until next `call` | — | — | `nextcall` |  
| Execute until next `ret` | — | — | `nextret` |  
| Modify a CPU flag | `set $eflags \|= 0x40` | `edit-flags +zero` | `set $eflags \|= 0x40` |  
| Canary value | — | `canary` | `canary` |  
| Distance between two addresses | — | — | `distance a b` |  
| Display context on demand | — | `context` | `context` |

Empty cells indicate the command doesn't exist natively in the concerned extension. In most cases, the same result can be obtained with more verbose vanilla GDB commands — extensions simply offer an ergonomic shortcut.

---

## Writing your own commands

Since all three extensions are written in Python, they also serve as models for creating your own custom GDB commands via the Python API seen in section 11.8.

In GEF, the class architecture facilitates adding a command. Each command is a class inheriting from `GenericCommand`:

```python
# ~/.gef-custom.py — custom GEF command
@register
class MyCustomCommand(GenericCommand):
    """My command description."""
    _cmdline_ = "mycommand"
    _syntax_ = f"{_cmdline_} [args]"

    def do_invoke(self, argv):
        gef_print(f"RSP = {gef.arch.register('$rsp'):#x}")
        gef_print(f"RIP = {gef.arch.register('$rip'):#x}")
```

For this command to be automatically loaded, add `source ~/.gef-custom.py` in `~/.gdbinit` after loading GEF.

In pwndbg, the mechanism is similar but relies on pwndbg's internal framework. For a simple command, direct use of the GDB Python API (section 11.8) is more portable:

```python
# ~/.gdb-custom.py — standard GDB Python command (compatible with any extension)
import gdb

class DumpStrcmpArgs(gdb.Command):
    """Display strcmp arguments at the current breakpoint."""

    def __init__(self):
        super().__init__("dump-strcmp", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rdi = gdb.parse_and_eval("$rdi")
        rsi = gdb.parse_and_eval("$rsi")
        s1 = gdb.execute(f"x/s {int(rdi)}", to_string=True)
        s2 = gdb.execute(f"x/s {int(rsi)}", to_string=True)
        gdb.write(f"strcmp arg1: {s1}strcmp arg2: {s2}")

DumpStrcmpArgs()
```

This command, loaded via `source ~/.gdb-custom.py`, works with any extension and in vanilla GDB. The idea is to progressively build a custom-command file that complements the chosen extension for recurring analysis needs — it's the "personal toolkit" logic developed in Chapter 35.

---

## Summary: which extension for which use

After going through all the commands in this chapter, the extension choice can be summarized as follows.

**PEDA** remains a good learning tool. Its code is readable, its commands are simple, and it works everywhere without dependencies. For daily use in 2024+, it's superseded by GEF and pwndbg on all fronts except installation simplicity and source-code readability.

**GEF** is the portable Swiss army knife. Its single file, absence of mandatory dependencies, multi-architecture support, and granular configurability make it the ideal extension for remote debugging, embedded work, and general use. The `xinfo`, `pattern create/search`, `edit-flags`, `got`, and `highlight` commands make it a complete tool for everyday reverse engineering.

**pwndbg** is the specialized arsenal. Its heap commands (`vis_heap_chunks`, `bins`, `tcachebins`), semantic navigation (`nextcall`, `nextret`), polymorphic memory search (`search`), and contextual annotations (libc function arguments, jump prediction) make it the most productive extension for complex binary analysis and vulnerability exploitation.

The alias mechanism described in section 12.1 allows switching between the three in one command. The best approach is to choose a default extension for routine work and switch on demand when a specific feature of the other is needed.

---


⏭️ [🎯 Checkpoint: trace the complete execution of `keygenme_O0` with GEF, capture the comparison moment](/12-gdb-extensions/checkpoint.md)
