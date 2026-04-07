🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 12.2 — Real-time stack and register visualization

> **Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg**  
> **Part III — Dynamic Analysis**

---

## The automatic context: the heart of the experience

The feature that alone justifies installing a GDB extension is the automatic display of the **context** at each breakpoint. In vanilla GDB, after a `stepi`, the debugger displays a single line — the current instruction — and returns to the prompt. The analyst must mentally reconstruct the machine's state by chaining inspection commands. With an extension, each stop produces a complete dashboard simultaneously presenting registers, stack, surrounding disassembly, and sometimes the corresponding source code.

This dashboard is triggered by a **GDB hook**: extensions register a Python function on the `stop` event, which executes automatically every time the program stops, regardless of the reason (breakpoint, watchpoint, signal, end of `stepi` or `nexti`). No manual intervention is needed — the context appears, the analyst reads, then types their next command.

---

## Context anatomy in each extension

### PEDA's context

PEDA displays three blocks separated by colored dash lines.

The first block, **registers**, lists the 64-bit general registers (`RAX` to `R15`), the instruction pointer `RIP`, the stack pointer `RSP`, and the base pointer `RBP`. Each value is followed by a first level of dereferencing: if `RAX` contains a valid address, PEDA displays the value stored at that address. If that value is itself a pointer to a readable ASCII string, the string is displayed in quotes. This single-level dereferencing is sufficient to quickly spot a `char *` argument in `RDI` before a `call`, but it doesn't follow deeper pointer chains.

The second block, **code**, shows the disassembly around the current instruction. The instruction about to be executed is highlighted by an `=>` arrow and distinct coloring. A few instructions before and after are shown to provide control-flow context.

The third block, **stack**, displays the first stack entries starting from `RSP`. Each 8-byte slot (on x86-64) is presented with its address, raw value, and one-level dereferencing, identical to the registers.

```
[----------------------------------registers-----------------------------------]
RAX: 0x0  
RBX: 0x0  
RCX: 0x7ffff7e15a80 (<__libc_start_call_main+128>: mov edi,eax)  
RDX: 0x0  
RSI: 0x7fffffffe1a8 --> 0x7fffffffe47a ("./keygenme_O0")  
RDI: 0x1  
...
[-------------------------------------code-------------------------------------]
   0x555555555169 <main>:       push   rbp
   0x55555555516a <main+1>:     mov    rbp,rsp
   0x55555555516d <main+4>:     sub    rsp,0x30
=> 0x555555555171 <main+8>:     mov    DWORD PTR [rbp-0x24],edi
   0x555555555174 <main+11>:    mov    QWORD PTR [rbp-0x30],rsi
...
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe090 --> 0x7fffffffe1a8 --> 0x7fffffffe47a ("./keygenme_O0")
0008| 0x7fffffffe098 --> 0x100000000
0016| 0x7fffffffe0a0 --> 0x0
...
```

The display is functional and readable, but lacks granularity: you can't easily see which registers changed since the last stop, and the limited dereferencing forces additional commands to follow data structures in memory.

### GEF's context

GEF organizes its context in **modular sections**, each identified by a colored banner. By default, the displayed sections are (in this order): `registers`, `stack`, `code`, `threads`, and `trace`.

GEF's **registers** section brings two improvements over PEDA. First, registers whose value changed since the last stop are displayed in a different color (typically red or yellow depending on the theme), allowing you to immediately spot the effect of the instruction that just executed. Second, dereferencing is recursive: GEF follows pointer chains until reaching a scalar value, a string, or an unmapped address. This gives lines like:

```
$rdi   : 0x00007fffffffe1a8  →  0x00007fffffffe47a  →  "./keygenme_O0"
```

Here, `RDI` points to an `argv` entry that itself points to the program-name string. Both levels of indirection are visible without additional commands.

GEF's **stack** section uses the same recursive-dereferencing logic. Each stack entry is followed by a chain of arrows (`→`) to the final value. Addresses belonging to known regions (stack, heap, shared libraries, binary sections) are annotated with the region name in brackets, helping to immediately distinguish a heap pointer from a code pointer.

The **code** section displays disassembly with syntax coloring. The current instruction is marked with a green `→` arrow. If DWARF symbols are present, GEF can interleave the corresponding C/C++ source-code lines above the assembly block, facilitating correlation between high-level logic and machine instructions.

The **trace** section shows the compact backtrace (call stack), equivalent to a `bt` but integrated into the context. This section is precious for permanently keeping an overview of call depth without typing a command.

### pwndbg's context

pwndbg pushes contextual display even further. Its default sections are `REGISTERS`, `DISASM`, `STACK`, and `BACKTRACE`, but several additional behaviors activate automatically depending on the situation.

pwndbg's **REGISTERS** section is the most informative of the three. Each modified register is highlighted, and the old value appears alongside in gray or muted color, allowing you to see both the current state and the transition. Recursive dereferencing is present, plus contextual detection: if `RDI` contains an address matching the first expected argument of the libc function about to be called, pwndbg annotates it. For example, just before a `call strcmp@plt`, you might see:

```
 RAX  0x0
 RBX  0x0
*RDI  0x7fffffffe0b0 ◂— 'user_input'
*RSI  0x555555556020 ◂— 'expected_key'
```

The asterisk before `RDI` and `RSI` indicates these registers were modified. The pointed strings are directly readable — the analyst sees both `strcmp` arguments without any additional command.

pwndbg's **DISASM** section goes beyond simple linear disassembly. When a `call` instruction is encountered, pwndbg resolves the target and displays the function name. For conditional jumps, it indicates whether the jump will be taken or not by analyzing the current state of flags in `RFLAGS`. This predictive annotation (`TAKEN` / `NOT TAKEN`) spares the analyst the mental calculation of checking the `ZF`, `CF`, or `SF` flag to determine the next execution path.

```
 ► 0x5555555551c2 <main+89>    je     0x5555555551d8 <main+111>    NOT TAKEN
```

The **STACK** section uses the built-in `telescope` command. The term "telescope" aptly describes the principle: each stack entry is followed by a dereferencing chain that "zooms" through successive indirections. The number of levels is configurable. By default, pwndbg displays 8 stack entries, each with complete dereferencing.

---

## The `telescope` command in detail

The `telescope` command (available in GEF and pwndbg, absent from PEDA) is one of the most useful tools for understanding memory state. It takes an address as argument and displays a series of memory slots, each followed by the complete dereferencing chain.

In pwndbg:

```
pwndbg> telescope $rsp 12
```

This command displays the first 12 slots of 8 bytes starting from the top of the stack. Each line shows the offset relative to `RSP`, the absolute address, the raw value, and the dereferencing chain:

```
00:0000│ rsp 0x7fffffffe090 —▸ 0x7fffffffe1a8 —▸ 0x7fffffffe47a ◂— './keygenme_O0'
01:0008│     0x7fffffffe098 ◂— 0x100000000
02:0010│ rbp 0x7fffffffe0a0 ◂— 0x0
03:0018│     0x7fffffffe0a8 —▸ 0x7ffff7e15a80 ◂— mov edi, eax
04:0020│     0x7fffffffe0b0 ◂— 'user_input'
...
```

The left column indicates the offset. When a register points to a given slot, its name is displayed (here `rsp` for slot `00` and `rbp` for slot `02`). The `—▸` symbols indicate a valid pointer to a mapped address, while `◂—` marks the final value (either a constant, a string, or a disassembled instruction).

In GEF, the equivalent command is called `dereference`:

```
gef➤ dereference $rsp 12
```

The output format is slightly different but the principle is identical: recursive dereferencing with memory-region annotation.

`telescope` is particularly valuable for inspecting stack frames during function-call analysis. By pointing at `RBP` rather than `RSP`, you visualize in one shot the saved `RBP`, the return address, and the calling frame's local variables:

```
pwndbg> telescope $rbp 4
00:0000│ rbp 0x7fffffffe0c0 —▸ 0x7fffffffe0e0 ◂— 0x0        # saved RBP
01:0008│     0x7fffffffe0c8 —▸ 0x555555555210 <main+200>     # return address
02:0010│     0x7fffffffe0d0 ◂— 0x41414141                    # local variable
03:0018│     0x7fffffffe0d8 ◂— 0x0
```

---

## Configuring and customizing the display

### Configuration in GEF

GEF offers the most granular configuration system. Every aspect of the display is controlled by a variable accessible via `gef config`.

To list all configuration variables related to the context:

```
gef➤ gef config context
```

A few frequently adjusted parameters:

```
gef➤ gef config context.nb_lines_code 12  
gef➤ gef config context.nb_lines_stack 10  
gef➤ gef config context.nb_lines_code_prev 5  
```

The first parameter controls the number of disassembly lines displayed *after* the current instruction, the second the number of stack entries, and the third the number of lines *before* the current instruction. Increasing these values gives more context but consumes more vertical space in the terminal — a trade-off to adjust according to screen size.

To choose which sections to display and in what order:

```
gef➤ gef config context.layout "regs code stack trace extra"
```

You can remove a section by omitting it from the list. For example, for a stripped binary without DWARF symbols, the `extra` section (source code) is useless and can be removed to save space:

```
gef➤ gef config context.layout "regs code stack"
```

To make these changes permanent, GEF offers to save the configuration:

```
gef➤ gef save
```

This writes a `~/.gef.rc` file that will be automatically reloaded in future sessions.

### Configuration in pwndbg

pwndbg uses a similar system. The `config` (or `configfile`) command modifies parameters:

```
pwndbg> config context-stack-lines 12  
pwndbg> config context-code-lines 14  
```

To disable an entire context section:

```
pwndbg> config context-sections "regs disasm stack backtrace"
```

Modifications are persisted in the `~/.pwndbg` file (created automatically). pwndbg also supports a theme file (`~/.pwndbg-theme`) to adjust colors independently of display logic.

### Configuration in PEDA

PEDA offers less flexibility. Configuration is done by modifying Python variables in `peda.py` or via the `pset` command:

```
gdb-peda$ pset option context "register,code,stack"  
gdb-peda$ pset option context_code_lines 12  
```

Options are fewer and less well documented than in GEF or pwndbg. It's one of the reasons PEDA is less suited to prolonged use than its two successors.

---

## Conditional display: adapting context to the situation

A common pitfall with GDB extensions is **information overload**. When debugging a complex program with many threads, or when executing hundreds of `stepi` in a loop, the constant scrolling of context can drown useful information.

All three extensions allow temporarily disabling the context:

```
# GEF
gef➤ gef config context.enable false
# ... execute several commands without context ...
gef➤ gef config context.enable true

# pwndbg
pwndbg> set context-output /dev/null
# ... or more simply:
pwndbg> ctx off  
pwndbg> ctx on  

# PEDA
gdb-peda$ pset option context "none"  
gdb-peda$ pset option context "register,code,stack"  
```

In GEF and pwndbg, you can also force a context redisplay without executing an instruction, which is useful after manually modifying a register or memory zone:

```
# GEF
gef➤ context

# pwndbg
pwndbg> context
```

---

## Monitoring specific registers and addresses

Beyond the global context, it's frequent to want to monitor a particular address or register throughout execution. Extensions offer mechanisms complementary to vanilla GDB's watchpoints.

### GDB's `display` command (always available)

Before using extension commands, recall that vanilla GDB has the `display` command, which automatically displays an expression at each stop:

```
(gdb) display/x $rax
(gdb) display/s (char*)$rdi
(gdb) display/4gx $rsp
```

These expressions add to the extension's context and appear in the output at each stop. It's a simple way to track a local variable or register that doesn't appear prominently enough in the standard context.

### Monitoring commands in GEF

GEF offers the `registers` command to display registers on demand with a custom format, but more importantly the `memory watch` command to continuously monitor a memory zone:

```
gef➤ memory watch 0x555555558040 16 byte
```

This command adds an additional section to the context, displaying the 16 bytes starting from the specified address at each stop. You can stack multiple monitoring zones:

```
gef➤ memory watch $rbp-0x10 8 qword  
gef➤ memory watch 0x555555556020 32 byte  
```

To remove a monitoring zone:

```
gef➤ memory unwatch 0x555555558040
```

### Monitoring commands in pwndbg

pwndbg doesn't have a direct equivalent to GEF's `memory watch`, but it fluently integrates GDB's `display` command into its context. Additionally, the `hexdump` command allows quick formatted inspection:

```
pwndbg> hexdump $rsp 64
```

For continuous monitoring, the recommended approach with pwndbg is to combine `display` with GDB formatting expressions:

```
pwndbg> display/4gx $rsp  
pwndbg> display/s *(char**)($rbp-0x18)  
```

---

## Application to reverse engineering: reading the stack like a book

Real-time visualization takes its full meaning during concrete binary analysis. Take a typical scenario: you want to understand how a program processes a password entered by the user.

With GEF or pwndbg active, set a breakpoint on the comparison function:

```
gef➤ break strcmp  
gef➤ run  
Enter password: test123  
```

When `strcmp` is reached, the context displays automatically. The registers section immediately shows both arguments — the System V AMD64 convention places the first two arguments in `RDI` and `RSI`:

```
$rdi : 0x00007fffffffe0b0  →  "test123"
$rsi : 0x0000555555556004  →  "s3cr3t_p4ss"
```

Without an extension, getting this information would have required:

```
(gdb) info registers rdi rsi
(gdb) x/s $rdi
(gdb) x/s $rsi
```

Three commands instead of zero. Over a debugging session of several hours with hundreds of breakpoints, this difference translates into considerable time savings and above all a reduction in cognitive load: the information is there, visible, without effort from the analyst.

The stack, visible simultaneously in the `stack` section, shows the return address and the caller's context. At a glance, you identify from which function `strcmp` was invoked, which helps trace back to the verification routine without manually navigating the call graph.

When stepping through the comparison function with `nexti`, each register modification is highlighted in the next context. You see the bytes compared one by one, the flags modified, and the exact moment the comparison fails (the conditional jump marked `TAKEN` or `NOT TAKEN` by pwndbg). This immediate visibility on control flow turns debugging from a memory exercise into a reading exercise.

---

## Best practices

**Adjust the terminal size.** The contexts of all three extensions are designed for wide terminals. A terminal of 80 columns will produce a truncated and hard-to-read display. Use at minimum 120 columns and 40 lines. A screen dedicated to the GDB terminal, or a multiplexer like `tmux` with a wide pane, considerably improves comfort.

**Reduce context when not using it.** During execution of long loops with `continue` between distant breakpoints, the context displaying at each intermediate stop (watchpoint, frequent conditional breakpoint) can slow the session. Temporarily disabling context speeds execution in these cases.

**Combine `telescope` with `display`.** Rather than retyping `telescope $rsp 8` after each instruction, add a permanent `display` that shows the first 4 stack slots. This creates a custom mini-context that complements the extension's context.

**Don't neglect flags.** Registers and stack naturally attract attention in the context, but flags (`EFLAGS` / `RFLAGS`) are equally important. GEF and pwndbg display individual flags (`ZF`, `CF`, `SF`, `OF`) readably. Getting into the habit of consulting them at each conditional jump prevents getting lost in control flow.

---


⏭️ [ROP gadget searching from GDB](/12-gdb-extensions/03-rop-gadget-search.md)
