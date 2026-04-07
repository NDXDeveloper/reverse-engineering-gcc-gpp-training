🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.2 — Fundamental GDB commands: `break`, `run`, `next`, `step`, `info`, `x`, `print`

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## Launching GDB

GDB is invoked by passing the binary to analyze as an argument:

```bash
$ gdb ./keygenme_O0
```

GDB displays its welcome message (version, license) then presents its `(gdb)` prompt. The program is **not yet running** — GDB has simply loaded it into memory and read its ELF sections, symbols, and any DWARF information. We're in a waiting state, ready to configure the analysis before starting execution.

To suppress the welcome message and license information:

```bash
$ gdb -q ./keygenme_O0
(gdb)
```

The `-q` (or `--quiet`) flag will quickly become a reflex. You can also pass arguments to the target program at launch:

```bash
$ gdb -q --args ./keygenme_O0 my_argument
```

Without `--args`, GDB would interpret `my_argument` as a core dump to load. With `--args`, everything following the binary name is passed to the program when launched.

### The `.gdbinit` file

At each startup, GDB executes the commands contained in two files if they exist:

- `~/.gdbinit` — global configuration, applied to all sessions.  
- `.gdbinit` in the current directory — project-specific configuration.

You can place frequent settings there:

```
# ~/.gdbinit — example global configuration
set disassembly-flavor intel  
set pagination off  
set print pretty on  
```

The first line is particularly important for RE: it switches the assembly display to **Intel syntax** instead of the default AT&T syntax. If you followed Chapter 7 and worked with `objdump -M intel`, you'll recognize your landmarks. This preference can also be set during a session:

```
(gdb) set disassembly-flavor intel
```

> ⚠️ **Security:** by default, GDB refuses to execute a local `.gdbinit` to prevent malicious code in an untrusted directory. You must explicitly authorize it in `~/.gdbinit` with the line:  
> ```  
> set auto-load safe-path /  
> ```  
> Or, more specifically, indicate your working directory path.

## Execution control

### `run` — launch the program

The `run` command (abbreviated `r`) starts program execution from its entry point:

```
(gdb) run
Starting program: /home/user/binaries/ch11-keygenme/keygenme_O0  
Enter your key: _  
```

The program executes normally and waits for user input. If the program expects command-line arguments, pass them directly to `run`:

```
(gdb) run ABCD-1234-EFGH
```

Or, if you already specified them with `--args` at launch, `run` uses them automatically. To modify arguments between two executions:

```
(gdb) set args XXXX-9999-YYYY
(gdb) run
```

You can also redirect standard input from a file — very useful when the program expects interactive input you want to automate:

```
(gdb) run < input.txt
```

### `start` — launch and stop at `main()`

If you want to start debugging right at `main()` entry without manually setting a breakpoint:

```
(gdb) start
Temporary breakpoint 1 at 0x401196: file keygenme.c, line 35.  
Starting program: /home/user/binaries/ch11-keygenme/keygenme_O0  

Temporary breakpoint 1, main () at keygenme.c:35
35      int main(int argc, char *argv[]) {
```

GDB sets a temporary breakpoint on `main`, launches the program, and stops immediately. It's a convenient shortcut at the start of an analysis. Note that `start` requires the `main` symbol to be present — on a stripped binary, you'll need another approach (section 11.4).

### `continue` — resume execution

When the program is stopped at a breakpoint, `continue` (abbreviated `c`) resumes normal execution until the next breakpoint or end of program:

```
(gdb) continue
Continuing.  
Enter your key: TEST-KEY  
Wrong key!  
[Inferior 1 (process 12345) exited with code 01]
```

### `next` and `step` — step by step

These are the two step-by-step progression commands, and their difference is fundamental:

**`next`** (abbreviated `n`) executes the current source line entirely. If this line contains a function call, the function is executed in full and GDB stops at the next line in the current function. `next` does not "descend" into called functions.

**`step`** (abbreviated `s`) executes the current source line, but if it contains a function call, GDB enters that function and stops at its first line.

Let's take a concrete example with this code:

```c
35: int main(int argc, char *argv[]) {
36:     char input[64];
37:     printf("Enter your key: ");
38:     fgets(input, sizeof(input), stdin);
39:     if (check_key(input)) {
40:         printf("Correct!\n");
```

If stopped at line 39:

```
(gdb) next
# → Executes check_key(input) entirely, stops at line 40 (or at the else)

(gdb) step
# → Enters check_key(), stops at the first line of check_key()
```

In RE, `step` is what you'll use most often: you want to descend into functions to understand their internal logic. `next` is useful for "stepping over" library calls you don't wish to explore (like `printf` or `fgets`).

### `nexti` and `stepi` — step instruction by instruction

The `next` and `step` commands work at the **source line** level. Their equivalents at the **assembly instruction** level are:

- **`nexti`** (abbreviated `ni`) — executes a single machine instruction. If it's a `call`, the called function is executed in full.  
- **`stepi`** (abbreviated `si`) — executes a single machine instruction. If it's a `call`, GDB enters the called function.

These commands are indispensable in RE, particularly on binaries without symbols where source-level commands don't work. They provide absolute control, instruction by instruction:

```
(gdb) stepi
0x0000000000401162 in check_key ()
(gdb) stepi
0x0000000000401165 in check_key ()
```

An extremely practical shortcut: after a first `stepi` or `nexti`, pressing **Enter** without typing a command repeats the last executed command. You can thus advance instruction by instruction by simply pressing Enter repeatedly.

### `finish` — finish the current function

If you entered a function with `step` and have seen what you wanted, `finish` (abbreviated `fin`) executes the rest of the function and stops just after the `ret`, back in the calling function:

```
(gdb) finish
Run till exit from #0  check_key (input=0x7fffffffe100 "TEST-KEY\n") at keygenme.c:24
0x00000000004011a5 in main () at keygenme.c:39
39          if (check_key(input)) {
Value returned is $1 = 0
```

GDB displays the return value (`Value returned is $1 = 0`), which is often exactly the information you're looking for — for example, knowing whether `check_key` returned 0 (failure) or 1 (success).

### `until` — advance to a line or address

`until` (abbreviated `u`) continues execution until reaching a line higher than the current line in the same function. It's particularly useful for exiting a loop without setting a breakpoint:

```
(gdb) until 45
# → Continues until line 45
```

You can also give an address:

```
(gdb) until *0x401190
```

## Breakpoints: `break`

### Breakpoints by function name

The simplest form sets a breakpoint at a function's entry:

```
(gdb) break main
Breakpoint 1 at 0x401196: file keygenme.c, line 35.
(gdb) break check_key
Breakpoint 2 at 0x401156: file keygenme.c, line 24.
```

GDB indicates the resolved address and, if DWARF symbols are present, the corresponding file and line.

### Breakpoints by line number

With DWARF symbols, you can set a breakpoint directly on a line number:

```
(gdb) break keygenme.c:39
Breakpoint 3 at 0x40119e: file keygenme.c, line 39.
```

If the current source file is unambiguous, the file name is optional:

```
(gdb) break 39
```

### Breakpoints by address

This is the universal method, which works even without any symbols. Prefix the address with `*`:

```
(gdb) break *0x401156
Breakpoint 4 at 0x401156
```

In RE on a stripped binary, it's the primary method. You spot the address of interest in Ghidra or `objdump`, then set the breakpoint in GDB.

### Breakpoints on library calls

You can set a breakpoint on a shared-library function:

```
(gdb) break strcmp
Breakpoint 5 at 0x7ffff7e42a40
(gdb) break printf
Breakpoint 6 at 0x7ffff7e12e10
```

This is a fundamental RE technique: rather than searching for where the program compares a key, you set a breakpoint on `strcmp` (or `memcmp`, `strncmp`) and examine the arguments at each call. GDB resolves the name via the PLT/GOT (Chapter 2, section 2.9).

### Managing breakpoints

```
(gdb) info breakpoints
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401196 in main at keygenme.c:35
2       breakpoint     keep y   0x0000000000401156 in check_key at keygenme.c:24
3       breakpoint     keep y   0x000000000040119e in main at keygenme.c:39
```

Key columns: `Num` is the breakpoint identifier, `Enb` indicates whether it's enabled (`y`) or disabled (`n`), `Address` is the memory address.

Management commands:

```
(gdb) disable 2         # Disables breakpoint 2 (stays in place but no longer triggers)
(gdb) enable 2          # Re-enables breakpoint 2
(gdb) delete 2          # Permanently deletes breakpoint 2
(gdb) delete            # Deletes ALL breakpoints (asks confirmation)
```

### Temporary breakpoints

A temporary breakpoint automatically removes itself after the first trigger:

```
(gdb) tbreak check_key
Temporary breakpoint 7 at 0x401156: file keygenme.c, line 24.
```

This is exactly what `start` uses internally. Temporary breakpoints are useful when you want to stop only once at a location (for example, the first time an initialization function is called).

## Displaying information: `print`, `x`, `info`, `display`

### `print` — evaluate and display an expression

`print` (abbreviated `p`) is GDB's most versatile command. It evaluates a C expression and displays the result:

```
(gdb) print argc
$1 = 1
(gdb) print argv[0]
$2 = 0x7fffffffe3a0 "/home/user/keygenme_O0"
(gdb) print input
$3 = "TEST-KEY\n\000\000\000..."
```

Each result is stored in a numbered variable (`$1`, `$2`, `$3`...) reusable in subsequent expressions:

```
(gdb) print $1 + 5
$4 = 6
```

#### Formatting `print` output

You can force the display format with a `/` suffix:

```
(gdb) print/x argc       # Hexadecimal
$5 = 0x1
(gdb) print/t argc       # Binary
$6 = 1
(gdb) print/c 0x41       # Character
$7 = 65 'A'
(gdb) print/d 0xff       # Signed decimal
$8 = -1
(gdb) print/u 0xff       # Unsigned decimal
$9 = 255
```

Available formats:

| Suffix | Format |  
|---|---|  
| `/x` | Hexadecimal |  
| `/d` | Signed decimal |  
| `/u` | Unsigned decimal |  
| `/t` | Binary |  
| `/o` | Octal |  
| `/c` | Character |  
| `/f` | Floating point |  
| `/a` | Address (symbolic if possible) |  
| `/s` | String (null-terminated) |

#### `print` on registers

Access registers by prefixing them with `$`:

```
(gdb) print $rax
$10 = 0
(gdb) print/x $rdi
$11 = 0x7fffffffe100
(gdb) print (char *)$rdi
$12 = 0x7fffffffe100 "TEST-KEY\n"
```

The last form is extremely useful: you cast a register's content to a C type so GDB interprets it correctly. Here, `$rdi` contains a pointer to a string — by casting it to `char *`, GDB displays the pointed string.

#### `print` with complex expressions

`print` accepts arbitrary C expressions, including pointer dereferences, structure member accesses, and arithmetic:

```
(gdb) print *player               # Dereference a pointer to a structure
(gdb) print player->health        # Field access
(gdb) print input[5]              # Array element access
(gdb) print strlen(input)         # Function call (!)
```

The last form is remarkable: GDB can **call functions** from the program or loaded libraries. This means you can call `strlen`, `strcmp`, `printf`, or even program functions directly from the GDB prompt. It's a powerful tool, but use it with caution — the call modifies the process state (stack, registers, side effects).

### `x` — examine raw memory

Where `print` interprets C expressions, `x` (*examine*) reads raw memory at a given address. Its syntax is:

```
x/NFS address
```

Where `N` is the number of units to display, `F` is the format, and `S` is the size of each unit.

**Formats** (`F`) — same as for `print`: `x` (hex), `d` (decimal), `s` (string), `i` (assembly instruction), `c` (character), `t` (binary), `a` (address), `f` (float).

**Sizes** (`S`):

| Letter | Size | Name |  
|---|---|---|  
| `b` | 1 byte | byte |  
| `h` | 2 bytes | halfword |  
| `w` | 4 bytes | word |  
| `g` | 8 bytes | giant (quad word) |

A few concrete examples covering the most common RE use cases:

```
(gdb) x/s 0x402010
0x402010: "Enter your key: "
```

Displays the null-terminated string at address `0x402010`. Useful for verifying string contents in `.rodata`.

```
(gdb) x/20bx 0x7fffffffe100
0x7fffffffe100: 0x54 0x45 0x53 0x54 0x2d 0x4b 0x45 0x59
0x7fffffffe108: 0x0a 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x7fffffffe110: 0x00 0x00 0x00 0x00
```

Displays 20 bytes in hexadecimal starting from the given address. We recognize "TEST-KEY\n" (0x54='T', 0x45='E', etc.). It's the most common "hex dump" view.

```
(gdb) x/4gx $rsp
0x7fffffffe0f0: 0x0000000000000001  0x00007fffffffe3a0
0x7fffffffe100: 0x59454b2d54534554  0x000000000000000a
```

Displays 4 words of 8 bytes (giant) in hexadecimal starting from the top of the stack. Essential for inspecting arguments and local variables on the stack.

```
(gdb) x/10i $rip
=> 0x401156 <check_key>:     push   rbp
   0x401157 <check_key+1>:   mov    rbp,rsp
   0x40115a <check_key+4>:   sub    rsp,0x30
   0x40115e <check_key+8>:   mov    QWORD PTR [rbp-0x28],rdi
   0x401162 <check_key+12>:  mov    rax,QWORD PTR [rbp-0x28]
   ...
```

The `i` format is for **disassembly**. `x/10i $rip` displays the next 10 instructions from the current instruction pointer. It's the reference command for seeing assembly code around the current execution point, and it works even without symbols. The `=>` arrow indicates the instruction that will be executed at the next `stepi`.

### `display` — automatic display at each stop

If you want to see the same information after each `step`, `next`, or breakpoint, `display` avoids retyping `print` or `x` in a loop:

```
(gdb) display/x $rax
1: /x $rax = 0x0
(gdb) display/i $rip
2: x/i $rip
=> 0x40115e <check_key+8>:  mov    QWORD PTR [rbp-0x28],rdi
(gdb) display/s $rdi
3: x/s $rdi
0x7fffffffe100: "TEST-KEY\n"
```

After each stop, GDB will automatically display these three pieces of information. To manage displays:

```
(gdb) info display        # List active displays
(gdb) undisplay 2         # Remove display number 2
(gdb) disable display 1   # Temporarily disable display 1
```

A well-chosen set of `display`s transforms the GDB session into a real-time dashboard. A classic setup for assembly RE:

```
(gdb) display/x $rax
(gdb) display/x $rdi
(gdb) display/x $rsi
(gdb) display/6i $rip
```

You thus see, at each step, the return value / accumulator (`rax`), the two first function arguments (`rdi`, `rsi`), and the next instructions to execute.

### `info` — query GDB and program state

`info` is a prefix that opens access to a wide variety of information. The most useful subcommands in RE:

```
(gdb) info registers
```

Displays the value of all general registers. It's the complete snapshot of the processor state:

```
rax    0x0                 0  
rbx    0x0                 0  
rcx    0x7ffff7f14a80      140737353030272  
rdx    0x7fffffffe218      140737488347672  
rsi    0x7fffffffe208      140737488347656  
rdi    0x1                 1  
rbp    0x7fffffffe0f0      0x7fffffffe0f0  
rsp    0x7fffffffe0f0      0x7fffffffe0f0  
rip    0x401196            0x401196 <main>  
eflags 0x246               [ PF ZF IF ]  
...
```

For floating-point and SIMD registers:

```
(gdb) info all-registers    # All registers, including SSE/AVX
```

Other essential subcommands:

```
(gdb) info breakpoints      # List of breakpoints (seen above)
(gdb) info functions         # List of all known functions
(gdb) info locals            # Local variables of the current frame (requires DWARF)
(gdb) info args              # Arguments of the current function (requires DWARF)
(gdb) info frame             # Details about the current stack frame
(gdb) info proc mappings     # Process memory map (sections, libraries)
(gdb) info sharedlibrary     # Loaded shared libraries
(gdb) info threads           # Thread list
```

The `info proc mappings` command deserves particular attention — it displays the process's virtual address ranges, equivalent of `/proc/<pid>/maps`:

```
(gdb) info proc mappings
  Start Addr           End Addr       Size     Offset  Perms  objfile
  0x00400000         0x00401000     0x1000        0x0  r--p   keygenme_O0
  0x00401000         0x00402000     0x1000     0x1000  r-xp   keygenme_O0
  0x00402000         0x00403000     0x1000     0x2000  r--p   keygenme_O0
  0x7ffff7dc0000     0x7ffff7de8000 0x28000        0x0  r--p   libc.so.6
  ...
```

You see the binary's segments (code in `r-xp`, read-only data in `r--p`), shared libraries, stack, heap. It's indispensable for understanding the process memory layout at analysis time.

## Disassembly in GDB: `disassemble`

The `disassemble` command (abbreviated `disas`) complements `x/i`. It disassembles an entire function:

```
(gdb) disassemble check_key
Dump of assembler code for function check_key:
   0x0000000000401156 <+0>:     push   rbp
   0x0000000000401157 <+1>:     mov    rbp,rsp
   0x000000000040115a <+4>:     sub    rsp,0x30
   0x000000000040115e <+8>:     mov    QWORD PTR [rbp-0x28],rdi
   ...
   0x00000000004011a2 <+76>:    leave
   0x00000000004011a3 <+77>:    ret
End of assembler dump.
```

The offsets between angle brackets (`<+0>`, `<+1>`, `<+4>`...) indicate the distance in bytes from the function's start, which facilitates navigation.

If stopped in the middle of a function, you can use:

```
(gdb) disassemble $rip-20, $rip+40
```

This disassembles an address range around the current execution point. It's the technique to use on stripped binaries where GDB doesn't know function boundaries.

To mix source code and assembly (requires DWARF):

```
(gdb) disassemble /m check_key
```

Or its improved variant `/s` which handles optimizations better:

```
(gdb) disassemble /s check_key
```

## Modifying program state: `set`

GDB does not just observe — it can modify the running program's state. It's a fundamental tool in RE.

### Modifying a register

```
(gdb) set $rax = 1
(gdb) set $rip = 0x4011a0
```

The first command forces `rax`'s value to 1 — for example, to simulate a "success" return from a verification function. The second modifies the instruction pointer, making execution jump to another address. It's the dynamic equivalent of binary patching seen in chapter 21.6.

### Modifying memory

```
(gdb) set {int}0x7fffffffe100 = 0x41414141
(gdb) set {char}0x402010 = 'X'
```

The `{type}address` syntax writes to memory with the specified type. You can also use variables if symbols are available:

```
(gdb) set variable result = 1
```

### Modifying execution flow: `jump`

```
(gdb) jump *0x4011a0
(gdb) jump keygenme.c:40
```

`jump` is similar to `set $rip = ...` but also triggers execution resumption. Warning: jumping to an arbitrary location without adjusting the stack can cause a crash. It's nonetheless useful for bypassing a conditional branch — for example, jumping over an `if` that checks a license.

## Essential commands summary

For quick reference, here are the commands covered in this section with their abbreviations:

| Command | Abbrev. | Action |  
|---|---|---|  
| `run [args]` | `r` | Launch the program |  
| `start` | — | Launch and stop at `main()` |  
| `continue` | `c` | Resume execution |  
| `next` | `n` | Advance one line (without entering functions) |  
| `step` | `s` | Advance one line (entering functions) |  
| `nexti` | `ni` | Advance one instruction (without entering `call`s) |  
| `stepi` | `si` | Advance one instruction (entering `call`s) |  
| `finish` | `fin` | Finish the current function |  
| `until [loc]` | `u` | Continue until a line/address |  
| `break [loc]` | `b` | Set a breakpoint |  
| `tbreak [loc]` | `tb` | Temporary breakpoint |  
| `delete [n]` | `d` | Delete a breakpoint |  
| `disable [n]` | `dis` | Disable a breakpoint |  
| `enable [n]` | `en` | Re-enable a breakpoint |  
| `print[/fmt] expr` | `p` | Display an expression |  
| `x/NFS addr` | — | Examine raw memory |  
| `display[/fmt] expr` | — | Automatic display at each stop |  
| `info registers` | `i r` | Display registers |  
| `info breakpoints` | `i b` | List breakpoints |  
| `info locals` | — | Local variables |  
| `info proc mappings` | — | Process memory map |  
| `disassemble` | `disas` | Disassemble a function |  
| `set $reg = val` | — | Modify a register |  
| `set {type}addr = val` | — | Modify memory |  
| `jump loc` | `j` | Jump to an address and continue |  
| `quit` | `q` | Quit GDB |

> 💡 **Mnemonic tip:** the progression commands form a natural hierarchy. At the highest level, `continue` executes everything until the next breakpoint. Below, `next` and `step` advance line by line. Even below, `nexti` and `stepi` advance instruction by instruction. At each level, the variant without `i` stays in the current function, and the variant with `i` (or `step`) descends into calls.

---

> **Takeaway:** These commands form the basic vocabulary of any GDB session. In RE, the typical work loop is: set a breakpoint on a function of interest (identified in static analysis), launch the program, inspect registers and memory at the breakpoint, then step by step to observe the behavior. Mastering `break`, `run`, `stepi`, `x`, and `print` suffices to conduct the majority of dynamic analyses — the following sections will add finer capabilities, but the core is here.

⏭️ [Inspecting the stack, registers, memory (format and sizes)](/11-gdb/03-inspecting-stack-registers-memory.md)
