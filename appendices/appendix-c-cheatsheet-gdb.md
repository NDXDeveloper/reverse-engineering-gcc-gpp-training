🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix C — Cheat sheet GDB / GEF / pwndbg

> 📎 **Reference card** — This appendix gathers the most useful commands from native GDB as well as those added by the GEF and pwndbg extensions. It is organized by task rather than alphabetical order, so you can quickly find what you need during a debugging session. Commands specific to an extension are marked with the **[GEF]** and **[pwndbg]** badges.

---

## 1 — Launching and attaching

### 1.1 — Starting GDB

| Shell command | Description |  
|----------------|-------------|  
| `gdb ./binary` | Launches GDB on a binary |  
| `gdb -q ./binary` | Launches GDB in quiet mode (suppresses the banner) |  
| `gdb -q -nx ./binary` | Launches without loading initialization files (`.gdbinit`) |  
| `gdb -q --args ./binary arg1 arg2` | Launches with arguments for the program |  
| `gdb -q -p <pid>` | Attaches GDB to a running process |  
| `gdb -q -c core ./binary` | Analyzes a core dump |

### 1.2 — Session commands inside GDB

| GDB command | Abbreviation | Description |  
|-------------|-------------|-------------|  
| `file ./binary` | — | Loads a binary into an already open GDB session |  
| `attach <pid>` | — | Attaches to a running process |  
| `detach` | — | Detaches from the process without killing it |  
| `set args arg1 arg2` | — | Sets the program arguments |  
| `show args` | — | Displays the current arguments |  
| `set env VAR=value` | — | Sets an environment variable for the program |  
| `unset env VAR` | — | Removes an environment variable |  
| `set follow-fork-mode child` | — | Follows the child process after a `fork()` |  
| `set follow-fork-mode parent` | — | Follows the parent process after a `fork()` (default) |  
| `set disable-randomization off` | — | Enables ASLR in GDB (disabled by default) |  
| `quit` | `q` | Quits GDB |

> 💡 GDB **disables ASLR** by default to facilitate reproducible debugging. If you are testing an exploit or analyzing a PIE binary with ASLR, remember to re-enable it with `set disable-randomization off`.

---

## 2 — Execution and navigation

### 2.1 — Launching and controlling execution

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `run` | `r` | Starts the program from the beginning |  
| `run < input.txt` | `r < input.txt` | Starts with input redirected from a file |  
| `start` | — | Starts and automatically stops at `main()` |  
| `starti` | — | Starts and stops at the very first instruction (before the loader) |  
| `continue` | `c` | Resumes execution until the next breakpoint or end |  
| `kill` | `k` | Kills the program being debugged |

### 2.2 — Stepping

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `next` | `n` | Executes the next source line (steps over calls) |  
| `step` | `s` | Executes the next source line (steps into calls) |  
| `nexti` | `ni` | Executes the next assembly instruction (steps over `call`) |  
| `stepi` | `si` | Executes the next assembly instruction (steps into `call`) |  
| `finish` | `fin` | Executes until the current function returns |  
| `until <addr>` | `u <addr>` | Executes until the specified address or line is reached |  
| `advance <location>` | — | Executes until the location is reached (like a temporary breakpoint) |

The `next`/`nexti` vs `step`/`stepi` distinction is fundamental. In RE on a stripped binary, you will work almost exclusively with `ni` and `si` (instruction level) because source line information is not available.

### 2.3 — Going backwards (Reverse Debugging)

| Command | Description |  
|----------|-------------|  
| `target record-full` | Enables recording for reverse debugging |  
| `reverse-continue` | `rc` — Continues backwards until the previous breakpoint |  
| `reverse-nexti` | `rni` — Steps back one instruction (without entering `call`) |  
| `reverse-stepi` | `rsi` — Steps back one instruction (enters `call`) |  
| `reverse-finish` | Steps back to the call of the current function |

> ⚠️ Reverse debugging is very slow (factor of ×10,000 or more). It is useful for short sequences when you have gone past a critical point, but not for navigating globally through a program.

---

## 3 — Breakpoints

### 3.1 — Standard breakpoints

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `break main` | `b main` | Breakpoint on the `main` function |  
| `break *0x401234` | `b *0x401234` | Breakpoint at an exact address |  
| `break *main+42` | `b *main+42` | Breakpoint at an offset from the beginning of a function |  
| `break file.c:25` | `b file.c:25` | Breakpoint at line 25 of `file.c` (requires symbols) |  
| `tbreak *0x401234` | `tb *0x401234` | Temporary breakpoint (automatically removed after the first hit) |  
| `rbreak regex` | — | Breakpoint on all functions matching the regular expression |

### 3.2 — Conditional breakpoints

| Command | Description |  
|----------|-------------|  
| `break *0x401234 if $rax == 0x42` | Stops only if `rax` equals `0x42` |  
| `break *0x401234 if *(int*)($rsp+8) > 100` | Condition on a memory value |  
| `break *0x401234 if strcmp($rdi, "admin") == 0` | Condition with a function call (if available) |  
| `condition <num> $rcx < 10` | Adds/modifies the condition of breakpoint #`<num>` |  
| `condition <num>` | Removes the condition (the breakpoint becomes unconditional again) |  
| `ignore <num> 50` | Ignores the first 50 hits of breakpoint `<num>` |

### 3.3 — Managing breakpoints

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `info breakpoints` | `i b` | Lists all breakpoints with their status |  
| `delete <num>` | `d <num>` | Deletes breakpoint #`<num>` |  
| `delete` | `d` | Deletes all breakpoints (asks for confirmation) |  
| `disable <num>` | `dis <num>` | Disables the breakpoint without deleting it |  
| `enable <num>` | `en <num>` | Re-enables a disabled breakpoint |  
| `enable once <num>` | — | Enables the breakpoint for a single hit |  
| `commands <num>` | — | Executes commands automatically when the breakpoint is hit |

The `commands` command is extremely powerful for automated RE. For example, to log all `strcmp` arguments without stopping:

```
break strcmp  
commands  
  silent
  printf "strcmp(%s, %s)\n", (char*)$rdi, (char*)$rsi
  continue
end
```

### 3.4 — Watchpoints (data breakpoints)

| Command | Description |  
|----------|-------------|  
| `watch *0x7fffffffe000` | Stops when the value at this memory address **changes** (write) |  
| `watch $rax` | Stops when the value of `rax` changes |  
| `watch *(int*)0x404060` | Stops when the `int` at address `0x404060` is modified |  
| `rwatch *0x404060` | Stops when the address is **read** (hardware watchpoint) |  
| `awatch *0x404060` | Stops on read **or** write |  
| `info watchpoints` | Lists all active watchpoints |

Hardware watchpoints (implemented by the processor debug registers DR0–DR3) are limited to 4 simultaneous ones and to sizes of 1, 2, 4, or 8 bytes. Software watchpoints (fallback) are much slower because GDB must execute instruction by instruction and check memory.

### 3.5 — Catchpoints

| Command | Description |  
|----------|-------------|  
| `catch syscall` | Stops on any system call |  
| `catch syscall write` | Stops on the `write` syscall only |  
| `catch syscall 1` | Stops on syscall number 1 (`write` on x86-64) |  
| `catch fork` | Stops when the program executes `fork()` |  
| `catch exec` | Stops when the program executes `execve()` |  
| `catch signal SIGSEGV` | Stops on reception of `SIGSEGV` |  
| `catch throw` | Stops on every C++ `throw` |  
| `catch catch` | Stops on every C++ `catch` |  
| `catch load libcrypto` | Stops when `libcrypto.so` is dynamically loaded |

---

## 4 — Register inspection

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `info registers` | `i r` | Displays all general-purpose registers |  
| `info all-registers` | `i r a` | Displays all registers including SSE, FPU, etc. |  
| `print $rax` | `p $rax` | Displays the value of `rax` in decimal |  
| `print/x $rax` | `p/x $rax` | Displays `rax` in hexadecimal |  
| `print/t $rax` | `p/t $rax` | Displays `rax` in binary |  
| `print/d $rax` | `p/d $rax` | Displays `rax` in signed decimal |  
| `print/u $rax` | `p/u $rax` | Displays `rax` in unsigned decimal |  
| `print (char*)$rdi` | — | Displays the string pointed to by `rdi` |  
| `set $rax = 0x42` | — | Modifies the value of a register |  
| `set $rip = 0x401234` | — | Moves the instruction pointer (jumps to an address) |  
| `set $eflags \|= (1 << 6)` | — | Sets the Zero Flag (ZF, bit 6 of EFLAGS) |  
| `set $eflags &= ~(1 << 6)` | — | Clears the Zero Flag |

**RE Tip**: modifying `$eflags` to force or prevent a conditional jump is a quick technique to explore a branch without patching the binary. For example, inverting ZF just before a `jz` to take or skip the jump.

### Display formats for `print`

| Suffix | Format | Example with `$rax = 0x41` |  
|---------|--------|---------------------------|  
| `/x` | Hexadecimal | `0x41` |  
| `/d` | Signed decimal | `65` |  
| `/u` | Unsigned decimal | `65` |  
| `/t` | Binary | `1000001` |  
| `/o` | Octal | `0101` |  
| `/c` | Character | `'A'` |  
| `/f` | Float | `9.10844e-44` |  
| `/a` | Address (nearest symbol) | `0x41` |  
| `/s` | C string (if the register is a pointer) | `"ABC..."` |

---

## 5 — Memory inspection

### 5.1 — The `x` (examine) command

The `x` command is the most commonly used command in RE for inspecting memory. Its full syntax is `x/NFS addr` where N = number of elements, F = format, S = size.

| Parameter | Values | Meaning |  
|-----------|---------|---------------|  
| **N** (count) | Positive integer | Number of elements to display |  
| **F** (format) | `x`, `d`, `u`, `o`, `t`, `c`, `s`, `i`, `a`, `f` | Same codes as `print` + `i` (instruction) and `s` (string) |  
| **S** (size) | `b` (1 byte), `h` (2), `w` (4), `g` (8) | Size of each element |

### 5.2 — Practical examples

| Command | Description |  
|----------|-------------|  
| `x/10gx $rsp` | 10 qwords in hex from the top of the stack |  
| `x/20wx $rsp` | 20 dwords in hex from the top of the stack |  
| `x/s $rdi` | C string pointed to by `rdi` |  
| `x/10s 0x402000` | 10 consecutive strings from address `0x402000` |  
| `x/5i $rip` | 5 instructions starting from the current instruction |  
| `x/20i main` | 20 instructions from the beginning of `main` |  
| `x/10i $rip-20` | Instructions around the current instruction (context before) |  
| `x/40bx $rsp` | 40 raw bytes in hex from the top of the stack |  
| `x/gx $rbp-0x8` | One qword at `[rbp-8]` (typical local variable) |  
| `x/4gx $rdi` | 4 qwords from the address pointed to by `rdi` (start of an object/struct) |  
| `x/wx 0x404060` | One dword at a fixed address (global variable, GOT entry) |

### 5.3 — Memory dump to file

| Command | Description |  
|----------|-------------|  
| `dump binary memory out.bin 0x400000 0x401000` | Dumps a memory range to a binary file |  
| `dump binary value out.bin $rdi` | Dumps the value of an expression to a file |  
| `dump ihex memory out.hex 0x400000 0x401000` | Dumps in Intel HEX format |  
| `restore out.bin binary 0x400000` | Restores a binary dump to a memory address |

### 5.4 — Memory search

| Command | Description |  
|----------|-------------|  
| `find 0x400000, 0x500000, "FLAG{"` | Searches for a string in a memory range |  
| `find /b 0x400000, 0x500000, 0x90, 0x90, 0x90` | Searches for a byte sequence (here: 3 × `nop`) |  
| `find /w 0x400000, +0x1000, 0xDEAD` | Searches for a word (2 bytes) in a relative range |

---

## 6 — Stack and frame inspection

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `backtrace` | `bt` | Displays the call stack |  
| `backtrace full` | `bt full` | Call stack with local variables for each frame |  
| `backtrace 5` | `bt 5` | Only the 5 most recent frames |  
| `frame <num>` | `f <num>` | Selects frame #`<num>` for inspection |  
| `up` | — | Moves up one frame (toward the caller) |  
| `down` | — | Moves down one frame (toward the callee) |  
| `info frame` | `i f` | Details of the current frame (addresses, saved registers) |  
| `info locals` | `i lo` | Local variables of the current frame (requires symbols) |  
| `info args` | `i ar` | Arguments of the current frame (requires symbols) |

On a stripped binary, `bt` will show raw addresses without function names. GEF and pwndbg significantly improve this display (see §11 and §12).

---

## 7 — Disassembly and source

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `disassemble` | `disas` | Disassembles the current function |  
| `disassemble main` | `disas main` | Disassembles the `main` function |  
| `disassemble 0x401100,0x401180` | — | Disassembles an address range |  
| `disassemble /r main` | — | Disassembles with raw bytes (opcodes) |  
| `disassemble /m main` | — | Disassembles with interleaved source lines (if available) |  
| `disassemble /s main` | — | Like `/m` but with better formatting (GDB ≥ 7.11) |  
| `set disassembly-flavor intel` | — | Switches to Intel syntax (recommended for RE) |  
| `set disassembly-flavor att` | — | Switches back to AT&T syntax (GDB default) |  
| `list` | `l` | Displays source code around the current position (if available) |  
| `list main` | `l main` | Displays the source of `main` |

> 💡 Add `set disassembly-flavor intel` to your `~/.gdbinit` so you never have to type it again. GEF and pwndbg use Intel by default.

---

## 8 — Symbol and process memory inspection

### 8.1 — Symbols and functions

| Command | Abbreviation | Description |  
|----------|-------------|-------------|  
| `info functions` | `i fu` | Lists all known functions |  
| `info functions regex` | — | Filters functions by regular expression |  
| `info variables` | `i va` | Lists all global/static variables |  
| `info symbol 0x401234` | — | Displays the symbol nearest to the address |  
| `info address main` | — | Displays the address of the `main` symbol |  
| `info sharedlibrary` | `i shl` | Lists loaded shared libraries |  
| `info target` | — | Information about the target binary (entry point, sections) |  
| `info files` | `i fi` | Details of the binary's sections and memory ranges |  
| `maintenance info sections` | — | Exhaustive list of ELF sections with flags |

### 8.2 — Process memory mapping

| Command | Description |  
|----------|-------------|  
| `info proc mappings` | Displays the memory mapping (`/proc/<pid>/maps`) |  
| `!cat /proc/<pid>/maps` | Direct access to the maps file (if PID is known) |  
| `info proc status` | Process information (PID, PPID, state) |

---

## 9 — Data modification and patching

| Command | Description |  
|----------|-------------|  
| `set *(int*)0x404060 = 42` | Writes the value `42` (4 bytes) at address `0x404060` |  
| `set *(char*)0x401234 = 0x90` | Writes one byte `0x90` (`nop`) at address `0x401234` |  
| `set *(short*)$rsp = 0x1337` | Writes a word at `[rsp]` |  
| `set {int}0x404060 = 42` | Alternative syntax for writing an `int` |  
| `set $rdi = 0x402000` | Modifies the value of a register |  
| `set $rip = 0x401250` | Forces a jump to a specific address |  
| `set variable x = 10` | Modifies a named C variable (requires symbols) |  
| `call (int)puts("hello")` | Calls a function in the program's context |

**Inline patching in RE**: to invert a conditional jump on the fly during debugging, you can overwrite the opcode directly. For example, to change a `jz` (`0x74`) to a `jnz` (`0x75`):

```
set *(char*)0x401234 = 0x75
```

This is a temporary in-memory patch. For a permanent patch, use ImHex or a Python script with `lief`/`pwntools` (see chapters 21.6 and 35.1).

---

## 10 — GDB Python scripting

GDB includes a full Python interpreter accessible via the `python` or `py` command.

### 10.1 — Basic commands

| Command | Description |  
|----------|-------------|  
| `python print(gdb.execute("info registers", to_string=True))` | Executes a GDB command and captures the output |  
| `python print(hex(gdb.parse_and_eval("$rax")))` | Reads the value of a register as a Python integer |  
| `python gdb.execute("set $rax = 0x42")` | Executes a GDB command from Python |  
| `source mon_script.py` | Loads and executes a GDB Python script |

### 10.2 — Useful Python objects

| Python expression | Description |  
|-------------------|-------------|  
| `gdb.parse_and_eval("$rip")` | Evaluates a GDB expression and returns a `gdb.Value` object |  
| `int(gdb.parse_and_eval("$rax"))` | Converts a register to a Python integer |  
| `gdb.inferiors()[0].read_memory(addr, size)` | Reads `size` bytes at address `addr` |  
| `gdb.inferiors()[0].write_memory(addr, data)` | Writes bytes at an address |  
| `gdb.breakpoints()` | Lists breakpoints as Python objects |  
| `gdb.selected_frame()` | Currently selected stack frame |  
| `gdb.selected_frame().read_register("rax")` | Reads a register via the frame object |  
| `gdb.events.stop.connect(callback)` | Registers a callback called at each stop |

### 10.3 — Example: logging `strcmp` calls

```python
import gdb

class StrcmpLogger(gdb.Breakpoint):
    def __init__(self):
        super().__init__("strcmp", internal=True)
        self.silent = True

    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi"))
        rsi = int(gdb.parse_and_eval("$rsi"))
        s1 = gdb.inferiors()[0].read_memory(rdi, 64).tobytes().split(b'\x00')[0]
        s2 = gdb.inferiors()[0].read_memory(rsi, 64).tobytes().split(b'\x00')[0]
        print(f"strcmp({s1.decode(errors='replace')}, {s2.decode(errors='replace')})")
        return False  # False = do not stop, continue execution

StrcmpLogger()
```

---

## 11 — GEF commands

GEF (*GDB Enhanced Features*) is a single-file extension that enriches GDB with high-level commands oriented toward exploitation and RE. It is installed by adding a single line to `~/.gdbinit`.

### 11.1 — Context display

GEF automatically displays a "context" at each stop: registers, stack, disassembled code, and source code (if available). This display is controlled by the following commands:

| Command | Description |  
|----------|-------------|  
| `context` | Forces the context to be redisplayed |  
| `gef config context.layout` | Displays/modifies the panels shown (`regs`, `stack`, `code`, `source`, `threads`, `extra`) |  
| `gef config context.nb_lines_code 15` | Number of disassembly lines displayed |  
| `gef config context.nb_lines_stack 10` | Number of stack lines displayed |  
| `gef config context.show_registers_raw true` | Displays raw register values |

### 11.2 — Binary and process information

| Command | Description |  
|----------|-------------|  
| `checksec` | Displays binary protections (PIE, NX, canary, RELRO, Fortify) |  
| `vmmap` | Displays the process memory mapping with permissions and file names |  
| `vmmap stack` | Filters vmmap on the stack |  
| `vmmap libc` | Filters on libc |  
| `xfiles` | Lists the binary's sections with their memory addresses |  
| `entry-break` | Places a breakpoint on the binary's actual entry point |  
| `got` | Displays the GOT table with resolved addresses |  
| `canary` | Displays the current stack canary value |  
| `elf-info` | Displays ELF header information |

### 11.3 — Memory search and exploration

| Command | Description |  
|----------|-------------|  
| `search-pattern "FLAG{"` | Searches for a string in the entire process memory |  
| `search-pattern 0xdeadbeef` | Searches for a hexadecimal value |  
| `search-pattern "FLAG{" stack` | Searches only in the stack |  
| `search-pattern "FLAG{" heap` | Searches only in the heap |  
| `xinfo 0x7fff12345678` | Displays information about an address (which mapping it belongs to) |  
| `dereference $rsp 20` | Recursively dereferences 20 entries from `rsp` (follows pointers) |  
| `hexdump byte $rsp 64` | Hex dump of 64 bytes from `rsp` |  
| `hexdump qword $rsp 8` | Dump of 8 qwords from `rsp` |

### 11.4 — Heap analysis

| Command | Description |  
|----------|-------------|  
| `heap chunks` | Lists all allocated chunks on the heap |  
| `heap bins` | Displays the state of allocator bins (fastbins, unsorted, small, large) |  
| `heap arenas` | Displays malloc arenas |  
| `heap chunk <addr>` | Details a specific chunk (size, flags, contents) |

### 11.5 — Exploitation and gadgets

| Command | Description |  
|----------|-------------|  
| `rop --search "pop rdi"` | Searches for ROP gadgets in the binary |  
| `rop --search "pop rdi" --range 0x400000-0x500000` | Searches in a specific address range |  
| `format-string-helper` | Helps build format strings for format string vulnerabilities |  
| `pattern create 200` | Creates a 200-byte De Bruijn pattern (to find the offset of an overflow) |  
| `pattern offset 0x41416141` | Computes the offset corresponding to a value found in a register |

### 11.6 — Miscellaneous

| Command | Description |  
|----------|-------------|  
| `gef save` | Saves the current GEF configuration to `~/.gef.rc` |  
| `gef restore` | Restores the saved configuration |  
| `gef install <plugin>` | Installs an additional GEF plugin |  
| `pcustom` | Manages custom structures for memory visualization |  
| `highlight add "keyword" "color"` | Colors a keyword in the output |  
| `aliases add <alias> <command>` | Creates a command alias |

---

## 12 — pwndbg commands

pwndbg is an exploitation-oriented extension with rich display and numerous commands for heap analysis, RE, and exploit development. Its commands are more numerous than GEF's and their naming sometimes differs.

### 12.1 — Context display

pwndbg automatically displays a rich context at each stop, similar to GEF but with different formatting.

| Command | Description |  
|----------|-------------|  
| `context` | Forces the context to be redisplayed |  
| `contextoutput <section> <cmd>` | Redirects a context section to a separate terminal |  
| `set context-sections regs disasm code stack backtrace` | Configures the displayed sections |  
| `set context-code-lines 15` | Number of disassembled code lines |  
| `set context-stack-lines 10` | Number of stack lines |

### 12.2 — Binary and process information

| Command | Description |  
|----------|-------------|  
| `checksec` | Binary protections (identical to GEF) |  
| `vmmap` | Process memory mapping |  
| `vmmap libc` | Filters vmmap |  
| `aslr` | Displays the ASLR state |  
| `got` | GOT table with resolved addresses |  
| `plt` | PLT table |  
| `gotplt` | GOT and PLT combined |  
| `canary` | Stack canary value |  
| `piebase` | Base address of the PIE binary |  
| `libs` | Lists loaded libraries |  
| `entry` | Entry point address |

### 12.3 — Memory search and exploration

| Command | Description |  
|----------|-------------|  
| `search --string "FLAG{"` | Searches for a string in memory |  
| `search --dword 0xdeadbeef` | Searches for a dword |  
| `search --qword 0xdeadbeefcafebabe` | Searches for a qword |  
| `search --string "FLAG{" --writable` | Searches only in writable pages |  
| `search --string "FLAG{" --executable` | Searches only in executable pages |  
| `xinfo <addr>` | Detailed information about an address |  
| `telescope $rsp 20` | Recursive dereference of 20 entries (follows pointer chains) |  
| `hexdump $rsp 64` | Hex dump |  
| `dq $rsp 10` | 10 qwords from `rsp` (compact format) |  
| `dd $rsp 10` | 10 dwords from `rsp` |  
| `db $rsp 40` | 40 bytes from `rsp` |  
| `dc $rsp 80` | Dump with ASCII characters (like `xxd`) |

### 12.4 — Heap analysis (glibc ptmalloc2)

pwndbg excels at glibc heap analysis. These commands are among the most advanced in the extension.

| Command | Description |  
|----------|-------------|  
| `vis_heap_chunks` | Colorful graphical visualization of heap chunks |  
| `vis_heap_chunks 0x555555559000 10` | Visualizes 10 chunks starting from an address |  
| `heap` | Heap overview (arenas, top chunk) |  
| `bins` | State of all bins (fastbins, tcache, unsorted, small, large) |  
| `fastbins` | Fastbins only |  
| `unsortedbin` | Unsorted bin only |  
| `smallbins` | Small bins only |  
| `largebins` | Large bins only |  
| `tcachebins` | Tcache bins only |  
| `tcache` | Full tcache details |  
| `mp_` | Displays the malloc `mp_` structure (global parameters) |  
| `malloc_chunk <addr>` | Details a specific chunk |  
| `top_chunk` | Displays the top chunk (wilderness) |  
| `arena` | Displays the current arena |  
| `arenas` | Lists all arenas |  
| `find_fake_fast <addr>` | Searches for fake fast chunks usable for a fastbin attack |

### 12.5 — Enhanced disassembly

| Command | Description |  
|----------|-------------|  
| `nearpc` | Disassembles around `rip` with syntax highlighting |  
| `nearpc 30` | 30 instructions around `rip` |  
| `u <addr>` | Disassembles from an address (alias for `nearpc`) |  
| `emulate 20` | Emulates the next 20 instructions (predicts the execution path) |  
| `pdisass` | Enhanced disassembly with annotations |  
| `nextcall` | Continues until the next `call` |  
| `nextjmp` | Continues until the next jump |  
| `nextret` | Continues until the next `ret` |  
| `nextsyscall` | Continues until the next `syscall` |  
| `stepret` | Steps until the `ret` of the current function |

### 12.6 — Exploitation and gadgets

| Command | Description |  
|----------|-------------|  
| `rop` | Searches for all ROP gadgets |  
| `rop --grep "pop rdi"` | Filters gadgets |  
| `ropper --search "pop rdi"` | Interface to the Ropper tool |  
| `cyclic 200` | Generates a 200-byte De Bruijn pattern |  
| `cyclic -l 0x6161616b` | Computes the offset corresponding to a value |  
| `cyclic -l aaak` | Computes the offset from the ASCII string |

### 12.7 — Miscellaneous

| Command | Description |  
|----------|-------------|  
| `distance <addr1> <addr2>` | Computes the distance between two addresses |  
| `plist <addr>` | Displays a linked list in memory |  
| `errno` | Displays the current value of `errno` with its meaning |  
| `mprotect <addr> <size> <perms>` | Changes memory permissions (requires the program to call `mprotect`) |  
| `procinfo` | Complete process information |  
| `regs` | Compact and colored display of all registers |

---

## 13 — GEF vs pwndbg comparison: equivalences

| Feature | GEF | pwndbg |  
|----------------|-----|--------|  
| Memory mapping | `vmmap` | `vmmap` |  
| Binary protections | `checksec` | `checksec` |  
| Recursive dereference | `dereference $rsp 20` | `telescope $rsp 20` |  
| Memory search | `search-pattern "str"` | `search --string "str"` |  
| Address info | `xinfo <addr>` | `xinfo <addr>` |  
| Stack canary | `canary` | `canary` |  
| GOT table | `got` | `got` / `gotplt` |  
| Hex dump | `hexdump byte $rsp 64` | `hexdump $rsp 64` / `db $rsp 64` |  
| Heap bins | `heap bins` | `bins` |  
| Visual heap chunks | `heap chunks` | `vis_heap_chunks` |  
| ROP gadgets | `rop --search "..."` | `rop --grep "..."` |  
| De Bruijn pattern (create) | `pattern create 200` | `cyclic 200` |  
| De Bruijn pattern (lookup) | `pattern offset 0x...` | `cyclic -l 0x...` |  
| Execute until next call | — | `nextcall` |  
| Execute until next ret | — | `stepret` / `nextret` |  
| Code emulation | — | `emulate 20` |  
| PIE base | — | `piebase` |

---

## 14 — Recommended `~/.gdbinit` file

Here is a minimal `.gdbinit` recommended for RE. Adapt it to your extension (GEF or pwndbg — only enable one at a time).

```
# ─── Native GDB ──────────────────────────────────
set disassembly-flavor intel  
set pagination off  
set confirm off  
set print pretty on  
set print array on  
set print elements 256  

# ─── Command history ─────────────────────────────
set history save on  
set history filename ~/.gdb_history  
set history size 10000  

# ─── Fork following ──────────────────────────────
set follow-fork-mode parent  
set detach-on-fork on  

# ─── Extension (uncomment ONE line only) ─────────
# source ~/.gdbinit-gef.py        # GEF
# source ~/pwndbg/gdbinit.py      # pwndbg
# source ~/peda/peda.py           # PEDA
```

---

## 15 — Keyboard shortcuts and productivity tips

| Shortcut / Tip | Description |  
|---------------------|-------------|  
| `Enter` (no command) | Repeats the last command (very useful with `ni`, `si`, `x`) |  
| `Ctrl+C` | Interrupts the running program (like `kill -INT`) |  
| `Ctrl+L` | Clears the screen |  
| `Ctrl+R` | Searches command history |  
| `!command` | Executes a shell command from GDB |  
| `shell command` | Identical to `!command` |  
| `define mycommand` ... `end` | Creates a macro (custom command) |  
| `pipe <cmd> \| grep pattern` | Pipes the output of a GDB command to grep (GDB ≥ 10) |

---

> 📚 **Further reading**:  
> - **Appendix D** — [Cheat sheet Radare2 / Cutter](/appendices/appendix-d-cheatsheet-radare2.md) — the reference card for the other major debugger/disassembler.  
> - **Chapter 11** — [Debugging with GDB](/11-gdb/README.md) — comprehensive pedagogical coverage of GDB commands for RE.  
> - **Chapter 12** — [Enhanced GDB: PEDA, GEF, pwndbg](/12-gdb-extensions/README.md) — installation, comparison, and use cases for the extensions.  
> - **GDB Documentation** — `help <command>` in GDB, or the [official manual](https://sourceware.org/gdb/current/onlinedocs/gdb/).  
> - **GEF** — [https://hugsy.github.io/gef/](https://hugsy.github.io/gef/) — official documentation.  
> - **pwndbg** — [https://pwndbg.re/](https://pwndbg.re/) — official documentation.

⏭️ [Cheat sheet Radare2 / Cutter](/appendices/appendix-d-cheatsheet-radare2.md)
