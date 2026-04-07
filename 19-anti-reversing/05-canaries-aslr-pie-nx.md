🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.5 — Stack canaries (`-fstack-protector`), ASLR, PIE, NX

> 🎯 **Objective**: Understand the internal workings of the four most common memory protections on Linux — stack canaries, ASLR, PIE, and NX — their concrete impact on static and dynamic analysis, how to detect them with `checksec` and `readelf`, and in which cases they complicate (or don't) the reverse engineer's work.

---

## Memory protections: a different category

The previous sections covered techniques specifically designed to hinder the analyst: stripping, packing, obfuscation. The protections in this section have a different objective. They don't target the reverse engineer — they target the **attacker** attempting to exploit a memory vulnerability (buffer overflow, use-after-free, ROP chain, etc.).

That said, these protections have a direct impact on dynamic analysis. An analyst trying to follow execution in GDB, predict memory addresses, or patch a binary in memory runs into these mechanisms. Understanding them is essential to avoid confusing a protection artifact with intentional program behavior.

The four protections covered here operate at different levels:

| Protection | Level | Protects against |  
|---|---|---|  
| Stack canary | Compiler | Return address overwrite (stack buffer overflow) |  
| NX | OS + hardware | Injected code execution on stack or heap |  
| ASLR | OS (kernel) | Memory address prediction |  
| PIE | Compiler + OS | Binary base address prediction |

## Stack canaries (`-fstack-protector`)

### The problem solved

A classic stack buffer overflow overwrites data beyond the buffer, potentially including the return address saved by the function prologue. If the attacker controls this return address, they redirect execution to arbitrary code at the `ret` moment.

### The mechanism

The stack canary (sometimes called "stack cookie") is a sentinel value placed between local variables and the saved return address. If a buffer overflow overwrites the buffer and continues toward the return address, it inevitably overwrites the canary along the way. The compiler inserts code in the function epilogue to check that the canary value hasn't changed. If it has, the program calls `__stack_chk_fail` and terminates immediately.

### What it looks like in assembly

Here's the prologue and epilogue of a canary-protected function, compiled with GCC and `-fstack-protector`:

**Prologue — canary setup:**

```nasm
push   rbp  
mov    rbp, rsp  
sub    rsp, 0x60                    ; local variable allocation  
mov    rax, qword [fs:0x28]        ; read canary from TLS  
mov    qword [rbp-0x8], rax        ; store on stack, just before saved rbp  
xor    eax, eax                    ; clear register  
```

**Epilogue — canary verification:**

```nasm
mov    rax, qword [rbp-0x8]        ; reload canary from stack  
cmp    rax, qword [fs:0x28]        ; compare with reference value  
jne    .canary_fail                 ; if different → overflow detected  
leave  
ret  

.canary_fail:
call   __stack_chk_fail            ; terminates the program, never returns
```

Several elements are noteworthy in this code.

**The `fs:0x28` access** — The canary reference value is stored in Thread Local Storage (TLS), accessible via the `fs` segment register. Offset `0x28` is standard on Linux x86-64 for the canary in glibc's `tcbhead_t` structure. This value is randomly initialized by the kernel at process startup and remains constant throughout execution. Each thread has its own canary.

**The canary position on the stack** — The canary is placed at `[rbp-0x8]`, immediately before the saved `rbp` and return address. It's the last line of defense before the stack's critical data.

**The `__stack_chk_fail` call** — This function is provided by glibc. It displays an error message (`*** stack smashing detected ***`), logs the event, and calls `abort()`. The program cannot survive a corrupted canary.

### `-fstack-protector` variants

GCC offers four canary protection levels:

**`-fstack-protector`** — Standard mode. Only inserts a canary in functions containing a character buffer of 8 bytes or more, or calling `alloca`. It's a compromise between protection and performance. This is the default on most modern distributions.

**`-fstack-protector-strong`** — More conservative. Protects functions containing arrays of any size, variables whose address is taken (`&var`), or local variables used in function calls. Covers more cases than `-fstack-protector` without the cost of protecting *every* function.

**`-fstack-protector-all`** — Inserts a canary in **every** function, without exception. Higher performance cost (one TLS access + one comparison per function call), but maximum coverage.

**`-fno-stack-protector`** — Explicitly disables protection. No canary is inserted.

### Impact on reverse engineering

For the static analyst, the canary is a recognizable but harmless artifact. The `fs:0x28` access in the prologue and `call __stack_chk_fail` in the epilogue are patterns you learn to mentally ignore — they're not part of the program's logic.

For the dynamic analyst, the canary has two implications:

- **It forbids naive stack patching** — If you try to modify data on the stack in GDB beyond the buffer (e.g., to change a protected local variable's value), you risk overwriting the canary and triggering `__stack_chk_fail`.  
- **It reveals stack layout** — The canary's position precisely indicates where local variables end and where the critical zone begins (saved rbp, return address). This is useful information for understanding stack layout.

### Detecting the canary

```bash
$ checksec --file=build/vuln_canary
    Stack:    Canary found

$ checksec --file=build/vuln_no_canary
    Stack:    No canary found
```

You can also check in the dynamic symbol table:

```bash
$ nm -D build/vuln_canary | grep stack_chk
                 U __stack_chk_fail@GLIBC_2.4
```

The presence of `__stack_chk_fail` in dynamic imports confirms canary usage.

### Observing the canary in GDB

GDB extensions (GEF, pwndbg) display the canary directly:

```
gef> canary
[+] The canary of process 12345 is at 0x7ffff7d8a768, value is 0xd84f2c91a7e3b100
```

Note that the canary's last byte is always `0x00` (null byte). This is intentional: if an overflow uses `strcpy` (which stops at the null byte), the canary's null byte will prevent the overflow from copying data beyond the canary. This is a design subtlety often mentioned in CTFs.

## NX (No-eXecute)

### The problem solved

In classic buffer overflow attacks, the attacker injects shellcode (machine code) into a stack buffer, then redirects execution to that buffer. The injected code runs with the victim process's privileges.

### The mechanism

NX (also called DEP — Data Execution Prevention, or W^X — Write XOR eXecute) is a hardware and software protection that marks memory pages as either writable or executable, but **never both simultaneously**. The stack and heap are marked RW (read-write) but not X (execute). The `.text` section is marked RX (read-execute) but not W (write).

If the processor attempts to execute an instruction on a non-executable page, the hardware generates an exception (page fault), and the kernel kills the process.

On x86-64, NX is implemented via the NX bit (bit 63) of page table entries. All x86-64 processors support this bit. On older 32-bit x86, hardware support didn't always exist, and NX was emulated by the kernel (or absent).

### Impact on reverse engineering

NX has virtually no impact on static analysis. For dynamic analysis, it prevents one specific technique: injecting code into memory and executing it. For example, if an analyst wanted to write a small assembly stub on the stack with GDB and execute it via `set $rip`, NX would block this attempt.

In practice, this limitation is rarely an obstacle for pure RE. It's much more relevant for vulnerability exploitation, where it forces the attacker to use techniques like ROP (Return-Oriented Programming) instead of direct shellcode.

### Detecting NX

```bash
$ checksec --file=build/vuln_no_canary
    NX:       NX enabled

$ checksec --file=build/vuln_execstack
    NX:       NX disabled
```

You can also verify with `readelf` by looking for the `GNU_STACK` segment:

```bash
$ readelf -l build/vuln_no_canary | grep GNU_STACK
  GNU_STACK      0x000000 0x0000000000000000 ... 0x000000 RW  0x10

$ readelf -l build/vuln_execstack | grep GNU_STACK
  GNU_STACK      0x000000 0x0000000000000000 ... 0x000000 RWE 0x10
```

The `RW` flag means NX enabled (the stack is read-write, not executable). The `RWE` flag means NX disabled (the stack is read-write-execute).

To compile without NX, pass `-z execstack` to the linker:

```bash
gcc -z execstack -o vuln_execstack vuln_demo.c
```

NX is enabled by default on all modern distributions. A binary with `NX disabled` is either very old or explicitly compiled with `-z execstack` — which immediately deserves your attention.

## ASLR (Address Space Layout Randomization)

### The problem solved

Many attacks rely on knowing memory addresses: a function's address, a ROP gadget's address, a buffer's address. If addresses are predictable, the attacker can hardcode them in their payload.

### The mechanism

ASLR is a **Linux kernel** feature, not a compiler feature. At each program execution, the kernel randomizes the base addresses of several memory regions:

- **The stack** — The stack's starting address is randomly offset.  
- **The heap** — The heap's base address (`brk`) is randomized.  
- **Shared libraries** — The load address of each `.so` (libc, libpthread, etc.) changes at each execution.  
- **The `mmap` mapping** — `mmap` allocations (used among other things for large `malloc` allocations) are randomized.  
- **The binary itself** — Only if the binary is compiled as PIE (see next section).

ASLR is controlled by the kernel parameter `/proc/sys/kernel/randomize_va_space`:

- `0` — ASLR disabled. Identical addresses at each execution.  
- `1` — Partial randomization: stack, libraries, mmap. The main binary and heap are not randomized.  
- `2` — Full randomization: all of the above + the heap. This is the default on modern distributions.

### Observing ASLR in action

Our `vuln_demo` binary displays its memory region addresses. Running it twice:

```bash
$ ./build/vuln_pie
--- Addressing information ---
  main()       @ 0x55d3a4401290  (.text)
  stack_var    @ 0x7ffd8b234a5c  (stack)
  heap_var     @ 0x55d3a5e2b2a0  (heap)

$ ./build/vuln_pie
--- Addressing information ---
  main()       @ 0x563e1c801290  (.text)
  stack_var    @ 0x7ffcc3f19a1c  (stack)
  heap_var     @ 0x563e1da1c2a0  (heap)
```

All addresses changed. Compare with the same binary compiled without PIE:

```bash
$ ./build/vuln_no_pie
--- Addressing information ---
  main()       @ 0x401290        (.text)
  stack_var    @ 0x7ffc92d1aa2c  (stack)
  heap_var     @ 0x1c3a2a0       (heap)

$ ./build/vuln_no_pie
--- Addressing information ---
  main()       @ 0x401290        (.text)
  stack_var    @ 0x7fff5a88c91c  (stack)
  heap_var     @ 0x24432a0       (heap)
```

Without PIE, `main()`'s address is fixed (`0x401290`). The stack and heap change (kernel ASLR), but the binary's code stays at the same address.

### Impact on reverse engineering

ASLR has a direct impact on dynamic analysis:

- **Addresses are not reproducible** — If you note a variable's address during a GDB session, that address will be different in the next session. You must reason in relative offsets, not absolute addresses.  
- **Breakpoints on absolute addresses only work once** — Under GDB, if you set `break *0x55d3a4401290`, that breakpoint will only be valid for this execution. Prefer breakpoints on function names (`break main`) or on offsets from base (`break *($base + 0x1290)`).  
- **Scripts must calculate addresses** — Any GDB or Frida script manipulating addresses must first determine the binary and library base addresses, then calculate target addresses.

### Disabling ASLR for analysis

To simplify an analysis session, ASLR can be temporarily disabled:

```bash
# For a single process (via setarch)
$ setarch $(uname -m) -R ./target_binary

# Globally (requires root, restore afterward)
# echo 0 > /proc/sys/kernel/randomize_va_space

# In GDB (disables ASLR for the debugged process)
(gdb) set disable-randomization on    # enabled by default in GDB
```

GDB disables ASLR by default for the process it launches. This is a classic trap: an analyst develops an exploit that works under GDB (ASLR off) but fails outside GDB (ASLR on).

## PIE (Position Independent Executable)

### The relationship with ASLR

PIE is ASLR's complement on the compiler side. ASLR randomizes the stack, heap, and shared libraries — but it can only randomize the main binary's base address if it was compiled as PIE.

A PIE binary is one whose code is entirely position-independent: it uses no absolute addresses, all references are relative (via `rip`-relative addressing). Technically, a PIE is a shared object (`ET_DYN` in the ELF header) that the loader can load at any address.

A non-PIE binary is of type `ET_EXEC` and is loaded at a fixed address (typically `0x400000` on x86-64). ASLR cannot relocate an `ET_EXEC`.

### What PIE changes in assembly

The most visible difference between a PIE and non-PIE binary manifests in global data and function addressing:

**Non-PIE — absolute addressing:**

```nasm
; Loading a string from .rodata
mov    edi, 0x402010        ; absolute address of the string  
call   0x401030             ; absolute address of puts@plt  
```

**PIE — rip-relative addressing:**

```nasm
; Loading a string from .rodata
lea    rdi, [rip+0x2e3f]   ; offset relative to current instruction  
call   printf@plt           ; resolved via PLT, itself relative  
```

The `lea rdi, [rip+0x2e3f]` instruction is PIE's signature pattern. The effective address is calculated by adding offset `0x2e3f` to the current `rip` value. No matter where the binary is loaded in memory, this offset remains correct.

### Impact on reverse engineering

**Static analysis** — PIE slightly complicates disassembly reading because displayed addresses are relative offsets (often starting at `0x0` or `0x1000`), not absolute addresses. Ghidra handles PIE binaries well and displays consistent base addresses, but `objdump` on a PIE may display low addresses that don't match the actual load address.

**Dynamic analysis** — PIE combined with ASLR means the binary's base address changes at each execution. Modern tools (GEF, pwndbg) automatically display the base address:

```
gef> vmmap  
Start              End                Offset             Perm Path  
0x55555555400      0x555555556000     0x0000000000000000 r-x /path/to/binary
```

The base address is `0x555555554000` in this example. Each address in the binary is this base + the offset seen in the disassembler.

### Detecting PIE

```bash
$ checksec --file=build/vuln_pie
    PIE:      PIE enabled

$ checksec --file=build/vuln_no_pie
    PIE:      No PIE
```

With `readelf`:

```bash
$ readelf -h build/vuln_pie | grep Type
  Type:                              DYN (Position-Independent Executable)

$ readelf -h build/vuln_no_pie | grep Type
  Type:                              EXEC (Executable file)
```

`DYN` = PIE. `EXEC` = non-PIE.

And with `file`:

```bash
$ file build/vuln_pie
vuln_pie: ELF 64-bit LSB pie executable, ...

$ file build/vuln_no_pie
vuln_no_pie: ELF 64-bit LSB executable, ...
```

The `pie executable` vs `executable` mention is the direct indicator.

PIE is enabled by default on GCC since recent versions (≥ 8) on most distributions. To explicitly disable it:

```bash
gcc -no-pie -fno-pie -o vuln_no_pie vuln_demo.c
```

The `-no-pie` flag is for the linker and `-fno-pie` is for the compiler (non-position-independent code generation). Both are necessary.

## Interaction between the four protections

These protections are not independent. They complement each other and their combination determines the residual attack surface:

**ASLR + PIE** — This is the combination that makes all addresses unpredictable. ASLR alone without PIE leaves the main binary's code at a fixed address. PIE without ASLR produces a relocatable binary but always loaded at the same place. Both together are necessary for complete randomization.

**NX + canary** — NX prevents injected shellcode execution. The canary prevents return address overwriting. Together, they force the attacker toward advanced techniques (ROP + information leak to bypass ASLR + canary).

**All protections combined** — This is the state of our `vuln_max_protection` variant. A binary with canary + PIE + NX + Full RELRO (next section) offers a minimal attack surface. Dynamic analysis remains possible, but naive patching and address prediction techniques don't work.

### Global verification with `checksec`

Our Makefile produces two extreme variants illustrating the contrast:

```bash
$ checksec --file=build/vuln_max_protection
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

$ checksec --file=build/vuln_min_protection
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

The first binary is hardened to the maximum. The second is intentionally left without any protection — it's a pedagogical binary, not a production model.

## For the reverse engineer: what really matters

In summary, here's each protection's practical impact on a typical RE session:

| Protection | Impact on static analysis | Impact on dynamic analysis |  
|---|---|---|  
| Stack canary | Recognizable `fs:0x28` pattern, mentally ignore | Prevents stack patching beyond the buffer |  
| NX | None | Prevents injection and execution of custom code in memory |  
| ASLR | None | Non-reproducible addresses between sessions |  
| PIE | Relative offset addresses, `lea [rip+...]` ubiquitous | Binary base address not predictable |

The good news: none of these protections make the code unreadable. Unlike obfuscation (Sections 19.3–19.4), they don't transform the program's logic. The assembly code is the same with or without canary — there are just a few extra instructions in the prologue and epilogue. The code is the same with or without PIE — the `lea [rip+offset]` instructions are slightly less readable than absolute addresses, but Ghidra resolves them automatically.

These protections are obstacles for exploitation, not for understanding. The RE analyst notes them during triage (with `checksec`), adapts tools accordingly, and continues the work.

---


⏭️ [RELRO: Partial vs Full and impact on GOT/PLT table](/19-anti-reversing/06-relro-got-plt.md)
