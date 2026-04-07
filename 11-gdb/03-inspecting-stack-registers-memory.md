🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.3 — Inspecting the stack, registers, memory (format and sizes)

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

The previous section introduced `print`, `x`, and `info registers` as display tools. This section goes further: it explains **how to read and interpret** what these commands show. Knowing how to type `x/10gx $rsp` isn't enough — you need to understand what the 10 displayed values represent, where a stack frame begins, which register holds which argument, and how to navigate through the different memory regions of a process. It's this interpretive ability that distinguishes a GDB user from an effective reverse engineer.

## Anatomy of x86-64 registers in GDB

Chapter 3 presented registers from the architecture's perspective. Here, we approach them from the practical perspective: what they contain at a given moment during debugging and how to exploit them.

### Registers and their sub-registers

Each 64-bit register has aliases to access its sub-parts. GDB knows them all:

```
(gdb) print/x $rax        # Full 64 bits
$1 = 0x00000000deadbeef
(gdb) print/x $eax        # Lower 32 bits
$2 = 0xdeadbeef
(gdb) print/x $ax         # Lower 16 bits
$3 = 0xbeef
(gdb) print/x $al         # Lower 8 bits
$4 = 0xef
(gdb) print/x $ah         # Upper 8 bits of the low word (rax[15:8])
$5 = 0xbe
```

This is important in RE because compilers frequently use sub-registers. A comparison on a `char` will use `al` or `dil`, an operation on an `int` will use `eax` or `edi`. Reading the wrong register (64 bits instead of 32) will give a value that seems absurd when the lower 32 bits contain exactly the expected value.

> 💡 **Classic pitfall:** when GCC operates on an `int` (32 bits), it uses `eax` and not `rax`. The `mov eax, 5` instruction implicitly zeros the upper 32 bits of `rax`. But the `mov al, 5` instruction does **not** touch the upper bits. If `rax` was `0xFFFFFFFF00000000` before `mov al, 5`, it will be `0xFFFFFFFF00000005` after — not `0x05`. When inspecting a register in GDB, always check which width the code actually uses.

### Registers to watch depending on context

Rather than listing all 16 registers at each stop, an effective reverse engineer knows which registers to observe depending on the situation:

**At a function's entry** (just after the `call`, on the first instruction):

| Register | Content (System V AMD64 convention) |  
|---|---|  
| `rdi` | 1st integer/pointer argument |  
| `rsi` | 2nd argument |  
| `rdx` | 3rd argument |  
| `rcx` | 4th argument |  
| `r8` | 5th argument |  
| `r9` | 6th argument |  
| `rsp` | Points to the return address on the stack |

If the function has more than 6 integer arguments, the following ones are on the stack, at `rsp+8`, `rsp+16`, etc. (the return address occupies `rsp+0`).

**At a function's return** (just after the `ret`, back in the caller):

| Register | Content |  
|---|---|  
| `rax` | Integer / pointer return value |  
| `xmm0` | Floating-point return value (if applicable) |

**During a `strcmp` / `memcmp` call**:

| Register | Content |  
|---|---|  
| `rdi` | Pointer to the first string |  
| `rsi` | Pointer to the second string |  
| `rdx` | Size (for `memcmp` / `strncmp`) |

You can immediately read both compared strings:

```
(gdb) x/s $rdi
0x7fffffffe100: "USER_INPUT"
(gdb) x/s $rsi
0x402020: "EXPECTED_KEY"
```

It's one of the most direct techniques to extract an expected key from a crackme.

**During a system call (`syscall`)**:

| Register | Content |  
|---|---|  
| `rax` | Syscall number |  
| `rdi` | 1st argument |  
| `rsi` | 2nd argument |  
| `rdx` | 3rd argument |  
| `r10` | 4th argument |  
| `r8` | 5th argument |  
| `r9` | 6th argument |

Notice that the syscall convention uses `r10` instead of `rcx` for the 4th argument (because `rcx` is overwritten by the `syscall` instruction itself, which saves `rip` there).

### The RFLAGS register

The flags register doesn't contain a "value" in the usual sense, but a set of individual bits. GDB displays them readably:

```
(gdb) print $eflags
$1 = [ CF PF ZF IF ]
```

The flags you'll encounter most in RE:

| Flag | Name | Set to 1 when... |  
|---|---|---|  
| `ZF` | Zero Flag | The result of the last operation is zero |  
| `CF` | Carry Flag | An unsigned overflow occurred |  
| `SF` | Sign Flag | The result is negative (most significant bit is 1) |  
| `OF` | Overflow Flag | A signed overflow occurred |

After a `cmp rax, rbx` instruction (which performs `rax - rbx` without storing the result), the flags indicate the comparison result:

- `ZF = 1` → `rax == rbx`  
- `ZF = 0` and `SF == OF` → `rax > rbx` (signed)  
- `ZF = 0` and `CF = 0` → `rax > rbx` (unsigned)

When stopped just before a conditional jump (`jz`, `jne`, `jl`...), inspecting the flags immediately indicates which path will be taken:

```
(gdb) print $eflags
$2 = [ PF IF ]          # ZF absent → jz will NOT jump, jnz will jump
```

## The stack: structure and navigation

### Anatomy of a stack frame

At each function call, a new **frame** (*stack frame*) is created on the stack. Recall the System V AMD64 convention seen in Chapter 3: after the standard prologue `push rbp ; mov rbp, rsp`, the frame has the following structure (addresses increasing downward):

```
High addresses (bottom of stack)
┌──────────────────────────────┐
│  Caller's 7+ arguments       │  [rbp+24], [rbp+16] ...
├──────────────────────────────┤
│  Return address               │  [rbp+8]
├──────────────────────────────┤
│  Old rbp (saved)              │  [rbp+0]   ← rbp points here
├──────────────────────────────┤
│  Local variables              │  [rbp-8], [rbp-16] ...
├──────────────────────────────┤
│  Alignment / padding zone     │
├──────────────────────────────┤
│  (space for calls)            │  ← rsp points here (top of stack)
└──────────────────────────────┘
Low addresses (top of stack)
```

In GDB, you can reconstruct this structure manually:

```
(gdb) x/gx $rbp          # Old rbp (caller's frame)
0x7fffffffe0f0: 0x00007fffffffe130

(gdb) x/gx $rbp+8        # Return address
0x7fffffffe0f8: 0x00000000004011a5

(gdb) x/a $rbp+8         # Same thing, "address" format (symbolic resolution)
0x7fffffffe0f8: 0x4011a5 <main+47>
```

The `/a` format is precious: it displays not only the address but also the matching symbol, if available. We see here that the return address points to `main+47`, meaning we're in a function called from `main`.

### `backtrace` — the call stack

The `backtrace` command (abbreviated `bt`) reconstructs the complete chain of function calls by walking back through frames:

```
(gdb) backtrace
#0  check_key (input=0x7fffffffe100 "TEST-KEY\n") at keygenme.c:24
#1  0x00000000004011a5 in main (argc=1, argv=0x7fffffffe208) at keygenme.c:39
```

Each line is a numbered frame. Frame `#0` is the current (most recent) function, `#1` is the caller, and so on down to `_start` or `__libc_start_main` at the bottom.

With DWARF symbols, GDB displays function names, arguments with their values, and line numbers. Without symbols, the output is more spartan but remains exploitable:

```
(gdb) backtrace
#0  0x0000000000401162 in ?? ()
#1  0x00000000004011a5 in ?? ()
#2  0x00007ffff7de0b6a in __libc_start_call_main () from /lib/x86_64-linux-gnu/libc.so.6
```

The `?? ()` indicate that GDB doesn't know the function name. Addresses remain present and can be correlated with static disassembly.

To limit trace depth:

```
(gdb) backtrace 5        # The 5 most recent frames
(gdb) backtrace -3       # The 3 oldest frames
(gdb) backtrace full     # With local variables of each frame
```

`backtrace full` is particularly useful: it displays the local variables of each frame, offering a complete snapshot of the program's state across the entire call chain.

### Navigating between frames: `frame`, `up`, `down`

By default, `print`, `info locals`, and `info args` operate on the current frame (frame `#0`). You can change context:

```
(gdb) frame 1            # Switch to main()'s frame
#1  0x00000000004011a5 in main (argc=1, argv=0x7fffffffe208) at keygenme.c:39
(gdb) info locals        # Local variables of main(), not check_key()
input = "TEST-KEY\n\000..."
(gdb) info args          # Arguments of main()
argc = 1  
argv = 0x7fffffffe208  
```

The `up` and `down` commands move up or down one frame:

```
(gdb) up                 # Move up one frame (toward the caller)
(gdb) down               # Move down one frame (toward the callee)
```

Frame navigation does not modify execution — it only changes the inspection context. When you resume execution with `continue` or `step`, you always restart from frame `#0`.

### Inspecting the raw stack

Beyond structured commands (`backtrace`, `info frame`), it's often necessary to examine the stack as a raw memory zone. This is particularly true on stripped binaries where `backtrace` can be incomplete or incorrect.

Display stack contents from the top:

```
(gdb) x/20gx $rsp
0x7fffffffe0c0: 0x0000000000000000  0x00007fffffffe100
0x7fffffffe0d0: 0x00007fffffffe208  0x0000000100000000
0x7fffffffe0e0: 0x0000000000000000  0x0000000000000000
0x7fffffffe0f0: 0x00007fffffffe130  0x00000000004011a5
0x7fffffffe100: 0x59454b2d54534554  0x000000000000000a
...
```

Let's interpret this output based on what we know about frame structure:

- `0x7fffffffe0f0` contains `0x00007fffffffe130` — this is the saved `rbp` (old frame pointer).  
- `0x7fffffffe0f8` contains `0x00000000004011a5` — this is the return address, pointing to `main+47`.  
- `0x7fffffffe100` contains `0x59454b2d54534554` — reading the bytes in little-endian, this gives `54 53 54 2d 4b 45 59` → "TEST-KEY". It's the `input` buffer on the stack.

To display the stack with symbolic address resolution:

```
(gdb) x/20ag $rsp
0x7fffffffe0c0: 0x0                 0x7fffffffe100
0x7fffffffe0d0: 0x7fffffffe208      0x100000000
0x7fffffffe0e0: 0x0                 0x0
0x7fffffffe0f0: 0x7fffffffe130      0x4011a5 <main+47>
```

The `a` (address) format makes `<main+47>` appear next to the return address — it's an immediate landmark for identifying return addresses in a raw stack dump.

### `info frame` — details about a frame

The `info frame` command gives a structured view of the current frame:

```
(gdb) info frame
Stack level 0, frame at 0x7fffffffe0f8:
 rip = 0x401162 in check_key (keygenme.c:24); saved rip = 0x4011a5
 called by frame at 0x7fffffffe138
 source language c.
 Arglist at 0x7fffffffe0e8, args: input=0x7fffffffe100 "TEST-KEY\n"
 Locals at 0x7fffffffe0e8, Locals list:
  result = 0
 Saved registers:
  rbp at 0x7fffffffe0e8, rip at 0x7fffffffe0f0
```

You find the saved return address (`saved rip`), the calling frame, arguments, local variables, and the location of saved registers. It's an excellent starting point for understanding a frame's layout before diving into raw addresses.

## Inspecting memory: methodology and use cases

The `x` command was presented in the previous section. Here, we address **inspection strategies** that constantly recur in RE.

### Identifying memory regions

Before examining an address, it's useful to know which region it falls in:

```
(gdb) info proc mappings
  Start Addr           End Addr       Size     Offset  Perms  objfile
  0x00400000         0x00401000     0x1000        0x0  r--p   keygenme_O0
  0x00401000         0x00402000     0x1000     0x1000  r-xp   keygenme_O0
  0x00402000         0x00403000     0x1000     0x2000  r--p   keygenme_O0
  0x00403000         0x00404000     0x1000     0x2000  rw-p   keygenme_O0
  0x00007ffff7dc0000 0x00007ffff7de8000 0x28000  0x0  r--p   libc.so.6
  0x00007ffff7de8000 0x00007ffff7f5d000 0x175000 0x28000 r-xp libc.so.6
  ...
  0x00007ffffffde000 0x00007ffffffff000 0x21000  0x0  rw-p   [stack]
```

Permissions indicate the type of content:

| Permissions | Typical region | Content |  
|---|---|---|  
| `r-xp` | `.text` | Executable code |  
| `r--p` | `.rodata`, headers | Read-only data (constant strings, tables) |  
| `rw-p` | `.data`, `.bss`, heap, stack | Modifiable data |  
| `r-xp` + libc | libc code | Library functions |

When you examine a pointer whose value is `0x7fffffffe100`, the `0x7fffff...` prefix immediately indicates the stack. An `0x402xxx` address points to the binary's data. An `0x7ffff7...` address points to a shared library. With experience, this identification becomes instantaneous.

### Reading strings

Strings are omnipresent in RE: error messages, encryption keys, URLs, file names. Several approaches depending on the situation:

```
(gdb) x/s 0x402010
0x402010: "Enter your key: "
```

Classic C string (null-terminated) in `.rodata`.

```
(gdb) x/s $rdi
0x7fffffffe100: "TEST-KEY\n"
```

String pointed to by a register — typically a function argument.

If the string is not null-terminated (frequent with fixed-size buffers or network protocols), examine the raw bytes:

```
(gdb) x/32bx 0x7fffffffe100
0x7fffffffe100: 0x54 0x45 0x53 0x54 0x2d 0x4b 0x45 0x59
0x7fffffffe108: 0x0a 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x7fffffffe110: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x7fffffffe118: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
```

And to visualize printable characters:

```
(gdb) x/32bc 0x7fffffffe100
0x7fffffffe100: 84 'T'  69 'E'  83 'S'  84 'T'  45 '-'  75 'K'  69 'E'  89 'Y'
0x7fffffffe108: 10 '\n' 0 '\000' 0 '\000' 0 '\000' ...
```

### Reading structures in memory

When DWARF symbols are present and the type is known, GDB can display a structure readably:

```
(gdb) print *player
$1 = {
  name = "Alice\000...",
  health = 100,
  x = 15.5,
  y = -3.2000000000000002,
  inventory = {0, 3, 0, 1, 0, 0, 0, 0, 0, 0}
}
```

The `set print pretty on` option (generally put in `.gdbinit`) enables indentation, making nested structures much more readable.

Without symbols, you must reconstruct manually. If static analysis in Ghidra revealed that a structure starts at the address contained in `rdi` and its fields are laid out as follows: a 32-character array, an `int`, two `double`s — you can verify:

```
(gdb) x/s $rdi                 # name field (offset 0, 32 chars)
0x555555558040: "Alice"

(gdb) x/dw $rdi+32             # health field (offset 32, int = 4 bytes)
0x555555558060: 100

(gdb) x/fg $rdi+40             # x field (offset 40, double = 8 bytes)
0x555555558068: 15.5

(gdb) x/fg $rdi+48             # y field (offset 48, double = 8 bytes)
0x555555558070: -3.2000000000000002
```

The `/f` format with `g` size (8 bytes) displays a `double`. With `w` size (4 bytes), it would display a `float`. The `/d` format with `w` size displays a signed `int`.

### Endianness in memory dumps

x86-64 is a **little-endian** architecture: the least significant byte is stored at the lowest address. It's a recurring pitfall when reading hexadecimal dumps.

Consider the value `0x0000000000402010` stored in memory at address `0x7fffffffe0d0`:

```
(gdb) x/gx 0x7fffffffe0d0        # Read as 8-byte word
0x7fffffffe0d0: 0x0000000000402010   # GDB reconstructs the value correctly

(gdb) x/8bx 0x7fffffffe0d0       # Read byte by byte
0x7fffffffe0d0: 0x10  0x20  0x40  0x00  0x00  0x00  0x00  0x00
```

Reading byte by byte, you see `10 20 40 00...` — the bytes are in **reversed** order compared to the value `0x0000000000402010`. It's the little-endian order: `0x10` (least significant byte) is at the lowest address.

When using `x/gx` or `x/wx`, GDB automatically performs the conversion and displays the value in natural order (big-endian for human reading). But when reading byte by byte with `x/bx` — or when examining a dump in ImHex — you must mentally reverse the bytes to reconstruct multi-byte values.

This also affects reading strings in word dumps:

```
(gdb) x/2gx 0x7fffffffe100
0x7fffffffe100: 0x59454b2d54534554  0x000000000000000a
```

The value `0x59454b2d54534554` corresponds, in little-endian, to the bytes `54 53 54 2d 4b 45 59` → `T S T - K E Y`. You read the string "backwards" in the displayed word.

### Monitoring library calls by their arguments

A powerful technique consists of setting a breakpoint on a library function and systematically inspecting its arguments. Here are the most revealing functions and what to look for:

**`strcmp` / `strncmp` / `memcmp`** — data comparison:
```
(gdb) break strcmp
(gdb) commands
  silent
  printf "strcmp(%s, %s)\n", (char *)$rdi, (char *)$rsi
  continue
end
```

The `commands` block executes automatically when the breakpoint is hit. `silent` suppresses GDB's standard message. You get a continuous log of all string comparisons:

```
strcmp(TEST-KEY, VALID-KEY-2025)  
strcmp(en_US.UTF-8, C)  
...
```

**`malloc` / `free`** — memory allocations:
```
(gdb) break malloc
(gdb) commands
  silent
  printf "malloc(%d)\n", $rdi
  continue
end
```

**`open` / `fopen`** — files accessed:
```
(gdb) break open
(gdb) commands
  silent
  printf "open(\"%s\", %d)\n", (char *)$rdi, $rsi
  continue
end
```

**`send` / `recv`** — network data:
```
(gdb) break send
(gdb) commands
  silent
  printf "send(fd=%d, buf=%p, len=%d)\n", $rdi, $rsi, $rdx
  x/s $rsi
  continue
end
```

This approach transforms GDB into a targeted tracing tool: instead of `strace` or `ltrace` which show everything, you only capture the calls that interest you, with the display format you've chosen.

## The heap

The heap is the memory zone dynamically allocated via `malloc`, `calloc`, `realloc` (or `new` in C++). Unlike the stack whose structure is regular and predictable, the heap is managed by the glibc allocator (`ptmalloc2`) which maintains its own metadata.

### Locating the heap

```
(gdb) info proc mappings | grep heap
  0x0000555555559000 0x000055555557a000 0x21000  0x0  rw-p   [heap]
```

You can also find the heap's start via the glibc's internal symbol:

```
(gdb) print (void *)&__malloc_hook
```

### Inspecting an allocation

If you know the address returned by `malloc` (for example by breaking on `malloc` and noting `$rax` on return), you can examine the allocated zone:

```
(gdb) x/8gx 0x555555559260
0x555555559260: 0x0000000000000000  0x0000000000000031  ← chunk header
0x555555559270: 0x4141414141414141  0x4242424242424242  ← user data
0x555555559280: 0x0000000000000000  0x0000000000000000
0x555555559290: 0x0000000000000000  0x0000000000020d71  ← top chunk
```

The word preceding user data (`0x31` here) is the allocator's **chunk header**. In `ptmalloc2`, it encodes the chunk size (most significant bits) and flags in the least significant bits. The value `0x31` means: size = `0x30` (48 bytes), `PREV_INUSE` bit set to 1 (the previous chunk is occupied).

Detailed heap analysis is an advanced topic covered in section 12.4 with pwndbg, but knowing how to read basic chunk headers is useful right now.

## Mapped memory and files: `/proc` and `info`

GDB gives access to additional process information via the `/proc` pseudo-filesystem:

```
(gdb) shell cat /proc/$(pidof keygenme_O0)/maps
```

It's the equivalent of `info proc mappings`, but directly from the kernel. You can also consult:

```
(gdb) shell cat /proc/$(pidof keygenme_O0)/status     # Process state
(gdb) shell cat /proc/$(pidof keygenme_O0)/fd/         # Open file descriptors
(gdb) shell ls -la /proc/$(pidof keygenme_O0)/fd/      # Symbolic links to files
```

The `shell` command in GDB executes any shell command without leaving the debugging session. It's a quick way to access system information during analysis.

Alternatively, `info files` (or `info target`) lists the loaded binary's sections with their addresses:

```
(gdb) info files
Symbols from "/home/user/keygenme_O0".  
Local exec file:  
  Entry point: 0x401060
  0x00400318 - 0x00400334 is .interp
  0x00400338 - 0x00400358 is .note.gnu.build-id
  ...
  0x00401000 - 0x004011b4 is .text
  0x00402000 - 0x00402038 is .rodata
  0x00403e00 - 0x00404030 is .got.plt
  ...
```

## Memory dumps: save and restore

During analysis, you may need to save a memory region to examine it in an external tool (ImHex, a Python script, etc.):

```
(gdb) dump binary memory /tmp/stack_dump.bin 0x7fffffffe000 0x7fffffffe200
(gdb) dump binary memory /tmp/heap_dump.bin 0x555555559000 0x55555555a000
```

These raw binary files can then be opened in ImHex (Chapter 6) for comfortable hexadecimal analysis, or read by a Python script:

```python
with open("/tmp/stack_dump.bin", "rb") as f:
    data = f.read()
```

You can also save the value of an expression:

```
(gdb) dump binary value /tmp/buffer.bin input
```

And to load data into memory (useful for modifying a buffer on the fly):

```
(gdb) restore /tmp/patched_data.bin binary 0x7fffffffe100
```

## Synthesis: inspection workflow in RE

To conclude, here is the typical workflow when stopped at a breakpoint and wanting to understand what's happening:

**1. Situate — where am I?**
```
(gdb) backtrace 3          # Recent call stack
(gdb) x/5i $rip            # Instructions around the current point
```

**2. Observe — what is the state?**
```
(gdb) info registers       # Register overview
(gdb) x/8gx $rsp           # Top of stack
```

**3. Interpret — what do these values mean?**
```
(gdb) x/s $rdi             # If rdi is a pointer to a string
(gdb) x/a $rbp+8           # Return address
(gdb) print/x $rax         # Return value / accumulator
```

**4. Decide — what to do next?**
```
(gdb) stepi                # Advance one instruction
(gdb) finish               # Exit the function
(gdb) continue             # Go to the next breakpoint
```

This cycle of situate → observe → interpret → decide repeats at each stop. With practice, it becomes a reflex and each iteration takes only a few seconds.

---

> **Takeaway:** Inspecting memory in GDB is not just knowing the syntax of `x` and `print` — it's knowing where to look and how to interpret what you see. The stack has a predictable structure you can read manually when `backtrace` fails. Registers have conventional roles that change with context (function entry, syscall, return). And the addresses themselves — through their prefix — betray the memory region they belong to. This reading ability is what makes dynamic analysis operational.

⏭️ [GDB on a stripped binary — working without symbols](/11-gdb/04-gdb-stripped-binary.md)
