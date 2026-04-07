🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.5 — Conditional breakpoints and watchpoints (memory and registers)

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## The problem: too much noise, not enough signal

A classic breakpoint on `strcmp` stops at **every** call — including the dozens of internal libc calls during initialization, locale comparisons, environment-variable checks. On a real-sized program, setting a breakpoint on `malloc` can trigger hundreds of stops before reaching the code that interests us. Advancing instruction by instruction through a 10,000-iteration loop to reach iteration 9,999 is out of the question.

**Conditional breakpoints** solve the first problem: GDB evaluates a condition at each trigger and only stops if it's true. **Watchpoints** solve a different but complementary problem: instead of monitoring the execution of an instruction, they monitor a **memory zone** and stop when it's read or modified, regardless of the responsible instruction. Together, these two mechanisms turn GDB into an intelligent filter that only signals relevant events.

## Conditional breakpoints

### Basic syntax

You add a condition to a breakpoint with the `if` keyword:

```
(gdb) break strcmp if strcmp((char *)$rdi, "VALID-KEY") == 0
```

But this form is problematic: it calls `strcmp` *inside* a condition of a breakpoint *on* `strcmp`, creating recursion. In practice, you use simpler conditions on registers or memory:

```
(gdb) break strcmp if (char)*(char *)$rdi == 'V'
```

This breakpoint only stops when the first character of the string pointed to by `rdi` (first argument of `strcmp`) is `'V'`. You thus filter out calls unrelated to the key you're looking for.

Another classic example — stop only when a function receives a specific value:

```
(gdb) break *0x401140 if $rdi > 0x7fffffffe000
```

This breakpoint on the function at `0x401140` only triggers if the first argument (`rdi`) is a stack address. This filters out calls where the argument is a `.rodata` or heap address.

### Adding a condition to an existing breakpoint

You can condition a breakpoint after creation with the `condition` command:

```
(gdb) break malloc
Breakpoint 1 at 0x7ffff7e5b0a0
(gdb) condition 1 $rdi > 1024
```

Breakpoint 1 (on `malloc`) will now only stop for allocations of more than 1024 bytes. It's handy to ignore routine small allocations and only capture large buffers — often the most interesting in RE.

To remove the condition without deleting the breakpoint:

```
(gdb) condition 1
```

Without an expression after the number, GDB removes the condition and the breakpoint becomes unconditional again.

### Condition expressions: what's allowed

Conditions accept any valid C expression that GDB can evaluate. Here are the most useful forms in RE:

**Register comparisons:**
```
(gdb) break *0x40117a if $rax == 0x42
(gdb) break *0x40117a if $rax != $rbx
(gdb) break *0x40117a if ($rax & 0xff) == 0x41    # Mask on the low byte
```

**Memory value comparisons:**
```
(gdb) break *0x401180 if *(int *)($rbp - 0x10) == 42
(gdb) break *0x401180 if *(char *)0x404050 == 'Y'
```

The `*(type *)address` syntax dereferences the address as a pointer to the given type. It's the GDB equivalent of a C cast followed by a dereference.

**Partial string comparisons:**
```
(gdb) break strcmp if *(int *)$rdi == 0x494c4156    # "VALI" in little-endian
```

Here, you read the first 4 bytes of the string pointed to by `rdi` as an integer and compare to `0x494c4156`, which corresponds to the characters `V`, `A`, `L`, `I` encoded in little-endian. It's a trick to filter `strcmp` calls by prefix without calling a function in the condition.

**Iteration counter:**
```
(gdb) break *0x401160 if $rcx == 9999
```

To stop only at the 10,000th iteration of a loop whose counter is in `rcx`.

**Logical combinations:**
```
(gdb) break *0x401180 if $rax > 0 && $rdi != 0
(gdb) break *0x401180 if $rax == 0 || $rbx == 0
```

### Ignoring the first N triggers: `ignore`

Complementary to conditions, the `ignore` command tells GDB to let a given number of triggers pass before stopping:

```
(gdb) break strcmp
Breakpoint 1 at 0x401030
(gdb) ignore 1 50
Will ignore next 50 crossings of breakpoint 1.
```

Breakpoint 1 will let the first 50 `strcmp` calls pass and only stop at the 51st. It's useful when you know the first N calls are uninteresting initialization routine.

To check the current counter:

```
(gdb) info breakpoints
Num  Type           Disp Enb Address            What
1    breakpoint     keep y   0x0000000000401030 <strcmp@plt>
     ignore next 42 hits
```

### Breakpoints with automatic commands

Combining a conditional breakpoint with a `commands` block allows creating "probes" that collect information without interrupting execution:

```
(gdb) break strcmp
Breakpoint 1 at 0x401030
(gdb) commands 1
  silent
  if *(char *)$rdi != 0
    printf "strcmp(\"%s\", \"%s\")\n", (char *)$rdi, (char *)$rsi
  end
  continue
end
```

This breakpoint intercepts all `strcmp` calls, displays both arguments if the first isn't an empty string, then automatically resumes execution. The program runs "normally" from the user's perspective, but GDB prints a log of all string comparisons in the background.

You can go further by combining condition, commands, and logic:

```
(gdb) break *0x401180
Breakpoint 2 at 0x401180
(gdb) commands 2
  silent
  set $count = $count + 1
  if $rax == 1
    printf ">>> Iteration %d: rax=1, match found!\n", $count
  end
  continue
end
(gdb) set $count = 0
```

This breakpoint maintains an iteration counter in a convenience variable `$count`, and only displays a message when `rax` equals 1. You get a targeted log without ever interrupting execution.

### Conditional breakpoint performance

An important point to understand: a conditional breakpoint is **not** more efficient than an unconditional one from the processor's perspective. GDB uses the same hardware mechanism (replacing the instruction with `int3`). At each trigger, the process is interrupted, control passes to GDB, the condition is evaluated, and if false, execution resumes. This back-and-forth between the process and GDB has a cost.

For a breakpoint in a tight loop executed millions of times, this can considerably slow down execution. In that case, it's sometimes preferable to use `ignore` (which short-circuits condition evaluation), to set the breakpoint further in the code (after a preliminary test), or to use hardware conditional breakpoints when the processor supports them.

## Watchpoints: monitoring memory

Watchpoints are a fundamentally different mechanism from breakpoints. Instead of monitoring the execution of an instruction at a given address, a watchpoint monitors a **memory zone** and interrupts the program when that zone is modified (or read, depending on the watchpoint type).

It's the ideal tool for answering the question: "*Which instruction modifies this variable?*" — a very frequent question in RE, where you spot an interesting value in memory without knowing what code is responsible.

### Write watchpoints: `watch`

The `watch` command monitors an expression and stops when its value changes:

```
(gdb) watch *(int *)0x404050
Hardware watchpoint 3: *(int *)0x404050
```

GDB will stop each time the 4 bytes at address `0x404050` are modified, and display the old and new values:

```
Hardware watchpoint 3: *(int *)0x404050

Old value = 0  
New value = 42  
0x0000000000401168 in ?? ()
```

You immediately see that the instruction at `0x401168` wrote the value 42 to this address. You can inspect this instruction:

```
(gdb) x/i 0x401168
   0x401168:  mov    DWORD PTR [rip+0x2ede],eax    # 0x404050
```

With DWARF symbols, you can directly use the variable name:

```
(gdb) watch result
Hardware watchpoint 4: result
```

GDB will monitor the memory location of the `result` variable and stop at each modification.

#### Monitoring zones of variable size

The expression passed to `watch` determines the monitored zone size:

```
(gdb) watch *(char *)0x404050         # Monitors 1 byte
(gdb) watch *(short *)0x404050        # Monitors 2 bytes
(gdb) watch *(int *)0x404050          # Monitors 4 bytes
(gdb) watch *(long *)0x404050         # Monitors 8 bytes
```

To monitor a larger buffer, you can use a cast to an array:

```
(gdb) watch *(char[32] *)0x7fffffffe100
```

This creates a watchpoint on 32 consecutive bytes. However, hardware watchpoint size is limited by the processor (see the section on hardware watchpoints below), and a software watchpoint on a large zone will be very slow.

### Read watchpoints: `rwatch`

`rwatch` (*read watch*) stops when the memory zone is **read**:

```
(gdb) rwatch *(char *)0x402010
Hardware read watchpoint 5: *(char *)0x402010
```

This answers the question: "*Which instruction reads this data?*" It's useful for tracing the use of a constant, an encryption key stored in memory, or a configuration.

```
Hardware read watchpoint 5: *(char *)0x402010

Value = 69 'E'
0x000000000040116c in ?? ()
```

The instruction at `0x40116c` read the byte at `0x402010`.

### Read and write watchpoints: `awatch`

`awatch` (*access watch*) combines both: it stops on any access — read or write — to the memory zone:

```
(gdb) awatch *(int *)0x404050
Hardware access (read/write) watchpoint 6: *(int *)0x404050
```

It's the widest net: you capture any interaction with the memory zone, regardless of access type.

### Hardware vs software watchpoints

GDB uses two watchpoint implementations, and the distinction has a major impact on performance.

**Hardware watchpoints.** The x86-64 processor has 4 debug registers (`DR0`–`DR3`) that allow monitoring up to 4 addresses simultaneously, with sizes of 1, 2, 4, or 8 bytes. When GDB uses these registers, monitoring is performed by hardware without any program slowdown. GDB displays `Hardware watchpoint` to indicate this mode.

Hardware limitations are strict:

| Constraint | Value on x86-64 |  
|---|---|  
| Maximum simultaneous | 4 watchpoints |  
| Supported sizes | 1, 2, 4, or 8 bytes |  
| Required alignment | Address must be aligned on the size |  
| Supported types | Write, read, read+write (depending on CPU) |

If you try to exceed these limits:

```
(gdb) watch *(int *)0x404050
Hardware watchpoint 1: *(int *)0x404050
(gdb) watch *(int *)0x404054
Hardware watchpoint 2: *(int *)0x404054
(gdb) watch *(int *)0x404058
Hardware watchpoint 3: *(int *)0x404058
(gdb) watch *(int *)0x40405c
Hardware watchpoint 4: *(int *)0x40405c
(gdb) watch *(int *)0x404060
# GDB falls back to a software watchpoint (or refuses)
```

**Software watchpoints.** When hardware registers are exhausted or the zone to monitor exceeds the supported size, GDB falls back to software mode: it executes the program **instruction by instruction** and checks memory after each instruction. It's extremely slow — the program can run 100 to 1000 times slower.

GDB indicates the watchpoint type at creation:

```
(gdb) watch *(char[128] *)0x7fffffffe100
Watchpoint 5: *(char[128] *)0x7fffffffe100    # No "Hardware" → software
```

> 💡 **Practical tip:** keep your watchpoints as small and few as possible. If you need to monitor a large zone, first set an 8-byte watchpoint on the part most likely to be modified, identify the responsible code, then refine.

### Conditional watchpoints

Watchpoints accept the same conditions as breakpoints:

```
(gdb) watch *(int *)0x404050 if *(int *)0x404050 > 100
```

This watchpoint only stops when the value at `0x404050` changes **and** the new value is greater than 100. Without the condition, it would stop at every modification, including initializations to 0 or intermediate increments.

Another useful example — monitor a pointer and stop when it becomes `NULL`:

```
(gdb) watch *(void **)0x404060 if *(void **)0x404060 == 0
```

### Watchpoints on registers

Despite what this section's title might suggest, GDB **does not directly support watchpoints on registers**. The `watch $rax` command doesn't work as one might hope: registers are not memory locations and the processor's debug registers cannot monitor other registers.

To achieve a similar effect — stop when a register reaches a given value — use a **conditional breakpoint**:

```
(gdb) break *0x401160 if $rax == 42
```

Or, to monitor a register at each instruction (very slow but sometimes necessary):

```
(gdb) display $rax
(gdb) stepi
# Repeat with Enter and observe visually
```

In practice, the question "*when does `rax` become 42?*" is better solved by setting conditional breakpoints at locations likely to modify `rax`, identified via static analysis.

## Reverse Engineering use cases

### Finding who modifies a global variable

Scenario: while analyzing a binary in Ghidra, you spot a global variable at `0x404050` that seems to control access to a feature (0 = locked, 1 = unlocked). You want to know what code modifies it.

```
(gdb) watch *(int *)0x404050
Hardware watchpoint 1: *(int *)0x404050
(gdb) run

Hardware watchpoint 1: *(int *)0x404050  
Old value = 0  
New value = 1  
0x00000000004011b2 in ?? ()

(gdb) x/3i 0x4011ac
   0x4011ac:  call   0x401140         # Call to check_key
   0x4011b1:  test   eax,eax
   0x4011b3:  ...
```

You found that the instruction at `0x4011b2` modifies the variable. Going back a few instructions, you understand the context: it's the result of `check_key` that updates this variable.

### Detecting a buffer overflow

Scenario: you suspect that an `fgets` writes beyond the allocated buffer. You set a watchpoint just after the buffer's end.

```
# Buffer 'input' is at rbp-0x40, size 64 bytes
# The canary or next variable is at rbp-0x08
(gdb) break *0x401190          # Just before fgets
(gdb) run
Breakpoint 1, 0x0000000000401190 in ?? ()

(gdb) watch *(long *)($rbp - 0x08)
Hardware watchpoint 2: *(long *)($rbp - 0x08)
(gdb) continue

# If fgets overflows...
Hardware watchpoint 2: *(long *)($rbp - 0x08)  
Old value = 0x00000000deadbeef       # Original canary value  
New value = 0x4141414141414141       # Overwritten by "AAAA..."  
0x00007ffff7e62123 in __GI__IO_fgets () from libc.so.6
```

The watchpoint captures the exact moment the canary is overwritten, and the faulting address points into `fgets` — confirmation of the overflow.

### Tracing buffer decryption

Scenario: an encrypted binary decrypts code or data in memory before using them. You want to capture the moment the encrypted buffer is transformed to cleartext.

```
# Encrypted buffer loaded at 0x555555559300 (identified via static analysis)
(gdb) watch *(long *)0x555555559300
Hardware watchpoint 1: *(long *)0x555555559300
(gdb) run

Hardware watchpoint 1: *(long *)0x555555559300  
Old value = 0x8a3c7f12e5d0b641       # Encrypted data  
New value = 0x0068732f6e69622f       # /bin/sh\0 in little-endian!  
0x00000000004010e8 in ?? ()
```

The watchpoint captures the decryption instruction. You can now inspect the full buffer:

```
(gdb) x/s 0x555555559300
0x555555559300: "/bin/sh"
```

And examine the decryption code around `0x4010e8` to understand the algorithm.

### Tracking C++ vtable modifications

Scenario: while analyzing a C++ binary (Chapter 17), you identified a vtable at a given address. An exploit could replace a vtable pointer with the address of a malicious function.

```
# The first object's vtable is pointed to by the field at offset 0 of the object
# The object is at 0x555555559260
(gdb) watch *(void **)0x555555559260
Hardware watchpoint 1: *(void **)0x555555559260
(gdb) commands 1
  silent
  printf "vptr modified! New vtable: %p\n", *(void **)0x555555559260
  x/4ag *(void **)0x555555559260
  continue
end
(gdb) run
```

You get a log of all vtable-pointer modifications, with the content of the pointed vtable at each change.

## Listing and managing watchpoints

Watchpoints appear in the same list as breakpoints:

```
(gdb) info breakpoints
Num  Type            Disp Enb Address            What
1    breakpoint      keep y   0x0000000000401190 
2    hw watchpoint   keep y                      *(int *)0x404050
3    hw watchpoint   keep y                      *(long *)($rbp - 0x08)
     stop only if *(long *)($rbp - 0x08) == 0
4    read watchpoint keep y                      *(char *)0x402010
```

The type (`hw watchpoint`, `read watchpoint`) indicates the mode. Management commands are identical to breakpoints:

```
(gdb) delete 3          # Delete watchpoint 3
(gdb) disable 2         # Disable watchpoint 2
(gdb) enable 2          # Re-enable
```

> ⚠️ **Watchpoint lifetime.** A watchpoint on a local variable (for example `watch *(int *)($rbp - 0x10)`) uses an address relative to the current frame. When the function returns and the frame is destroyed, the watchpoint is automatically deleted by GDB with the message:  
> ```  
> Watchpoint 3 deleted because the program has left the block in  
> which its expression is valid.  
> ```  
> To monitor a memory zone beyond a function's lifetime, use an absolute address rather than an expression relative to `$rbp`.

## Commands summary

| Command | Action |  
|---|---|  
| `break <loc> if <expr>` | Conditional breakpoint |  
| `condition <n> <expr>` | Add/modify the condition of breakpoint n |  
| `condition <n>` | Remove the condition of breakpoint n |  
| `ignore <n> <count>` | Ignore the next `count` triggers |  
| `watch <expr>` | Write watchpoint (stops when value changes) |  
| `rwatch <expr>` | Read watchpoint (stops when value is read) |  
| `awatch <expr>` | Access watchpoint (read or write) |  
| `commands <n>` | Attach automatic commands to breakpoint/watchpoint n |  
| `info watchpoints` | List active watchpoints (alias of `info breakpoints`) |

---

> **Takeaway:** Conditional breakpoints and watchpoints transform GDB from a "stop-everywhere" tool into a targeted monitoring tool. Conditional breakpoints filter noise by stopping only when a precise condition is met. Watchpoints invert the search logic: instead of searching for what code acts on data, you monitor the data and let GDB identify the code. In RE, this combination is particularly effective for tracing global-variable modifications, capturing decryption moments, and isolating significant iterations in massive loops.

⏭️ [Catchpoints: intercepting `fork`, `exec`, `syscall`, signals](/11-gdb/06-catchpoints.md)
