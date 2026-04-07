🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.8 — Segment mapping, ASLR, and virtual addresses: why addresses move

> 🎯 **Goal of this section**: Understand the virtual-memory mechanism that underlies the loading of an ELF binary, master how ASLR works and its consequences on reverse engineering, and know how to work with addresses that change at every execution.

---

## Virtual addresses vs physical addresses

When you read `0x55a3c4001149` in GDB or in `/proc/<pid>/maps`, that address does not exist as such in physical RAM. It is a **virtual address** — an abstraction provided by the processor (via the MMU — *Memory Management Unit*) and managed by the kernel.

Each process has its own **virtual address space**: a 2⁴⁸-byte (256 TB) space on x86-64, of which only a fraction is actually mapped. Two different processes can use the same virtual address `0x7ffff7e00000` — it will point to different physical pages in RAM. This is the foundation of isolation between processes.

The kernel maintains a **page table** for each process, which translates virtual addresses into physical addresses. The unit of mapping is the **page** — typically 4 KB on x86-64. When the processor accesses a virtual address, the MMU consults the page table to find the corresponding physical page. If the page is not mapped, the processor triggers a **page fault** that the kernel handles (either by loading the page from the file, or by sending a `SIGSEGV` if the access is illegitimate).

For the reverse engineer, the practical consequence is the following: **all the addresses you manipulate are virtual**. The addresses in the disassembly, the addresses in GDB, the addresses in `/proc/<pid>/maps` — everything is virtual. The translation to physical RAM is transparent and outside your control (except in kernel exploitation scenarios).

## Segments and mapping: from ELF file to memory

### The program header table revisited

In section 2.7, we saw that the kernel uses the **program header table** (segment view) to know what to load into memory. Let's now detail the mapping mechanism itself.

Each `PT_LOAD` entry in the program header table specifies:

| Field | Meaning |  
|---|---|  
| `p_offset` | Starting offset in the ELF file |  
| `p_vaddr` | Desired virtual address in memory |  
| `p_filesz` | Number of bytes to read from the file |  
| `p_memsz` | Size of the memory zone to allocate |  
| `p_flags` | Permissions (`PF_R`, `PF_W`, `PF_X`) |  
| `p_align` | Required alignment (generally page size: `0x1000`) |

The kernel calls `mmap` for each `PT_LOAD` segment, projecting the `[p_offset, p_offset + p_filesz)` portion of the file to virtual addresses `[p_vaddr, p_vaddr + p_memsz)`. If `p_memsz > p_filesz`, the extra bytes are filled with zeros — this is the mechanism that implements the `.bss` section in memory.

### Non-PIE binary: fixed addresses

For a binary compiled without PIE (`gcc -no-pie`), the ELF type is `ET_EXEC` and the virtual addresses in the program header table are **absolute**. The kernel maps the segments exactly at the requested addresses:

```bash
gcc -no-pie -o hello_nopie hello.c  
readelf -l hello_nopie | grep LOAD  
# LOAD  0x000000 0x0000000000400000 ... R   0x1000
# LOAD  0x001000 0x0000000000401000 ... R E 0x1000
# LOAD  0x002000 0x0000000000402000 ... R   0x1000
# LOAD  0x002e10 0x0000000000403e10 ... RW  0x1000
```

The code segment is always at `0x401000`, data at `0x403e10`, from one execution to the next. The entry point is a fixed address like `0x401050`.

It is simple and predictable — and that is exactly the problem from a security point of view.

### PIE binary: relative addresses

For a PIE binary (`ET_DYN`, the modern default), the virtual addresses in the program header table are **offsets relative to a load base** that will be chosen at runtime:

```bash
gcc -o hello_pie hello.c    # PIE by default  
readelf -l hello_pie | grep LOAD  
# LOAD  0x000000 0x0000000000000000 ... R   0x1000
# LOAD  0x001000 0x0000000000001000 ... R E 0x1000
# LOAD  0x002000 0x0000000000002000 ... R   0x1000
# LOAD  0x002db8 0x0000000000003db8 ... RW  0x1000
```

The `p_vaddr` values start at `0x0` — these are not actual addresses but offsets. At load time, the kernel chooses a base address (for example `0x55a3c4000000`) and adds this base to each offset:

```
Address in memory = load_base + p_vaddr
                  = 0x55a3c4000000     + 0x1000
                  = 0x55a3c4001000
```

It is this base that changes at every execution when ASLR is active.

## ASLR — Address Space Layout Randomization

### Principle

ASLR is a security technique that **randomizes the base address** at which each component is loaded into memory. At every execution, the stack, the heap, shared libraries, and the main binary (if it is PIE) are placed at different addresses.

The goal is to make the exploitation of memory vulnerabilities (buffer overflows, use-after-free, etc.) much more difficult. An attacker who knows a vulnerability must also know the addresses of the functions or gadgets they want to target — if these addresses change at every execution, a reliable attack first requires an **address leak**.

### ASLR levels under Linux

The Linux kernel controls ASLR via the `/proc/sys/kernel/randomize_va_space` parameter:

| Value | Behavior |  
|---|---|  
| `0` | ASLR disabled — everything at a fixed address |  
| `1` | Partial ASLR — stack, libraries, vDSO, and mmap randomized. The main binary and heap are not |  
| `2` | Full ASLR (default) — stack, libraries, vDSO, mmap, **and heap** (via `brk`) randomized. The main binary is randomized only if it is PIE |

```bash
# Check the current ASLR level
cat /proc/sys/kernel/randomize_va_space
# 2  (default on most distributions)
```

### What is randomized, what is not

| Component | Non-PIE (`ET_EXEC`) | PIE (`ET_DYN`) |  
|---|---|---|  
| Main binary (`.text`, `.data`, `.got`…) | ❌ Fixed | ✅ Randomized |  
| Shared libraries (`libc.so`, etc.) | ✅ Randomized | ✅ Randomized |  
| Stack | ✅ Randomized | ✅ Randomized |  
| Heap (`brk`/`mmap`) | ✅ Randomized (level 2) | ✅ Randomized |  
| vDSO | ✅ Randomized | ✅ Randomized |  
| Loader `ld.so` | ✅ Randomized | ✅ Randomized |

This table reveals a crucial point: **a non-PIE binary with ASLR enabled offers incomplete protection**. The code and data of the main binary remain at fixed addresses — only the libraries and stack move. That is why modern distributions compile everything as PIE by default.

### Observing ASLR in action

Let's run our program twice and compare the addresses:

```bash
# With ASLR enabled (default)
cat /proc/sys/kernel/randomize_va_space
# 2

# First execution
LD_SHOW_AUXV=1 ./hello RE-101 2>&1 | grep AT_ENTRY
# AT_ENTRY: 0x5603a4001060

# Second execution
LD_SHOW_AUXV=1 ./hello RE-101 2>&1 | grep AT_ENTRY
# AT_ENTRY: 0x55b7e8c01060

# The base addresses differ: 0x5603a4000000 vs 0x55b7e8c00000
# But the offset is the same: 0x1060
```

We see that the high part of the address changes (`0x5603a4` → `0x55b7e8c`) but the **offset** (`0x1060`) remains identical. That is the key: RE tools work with offsets, which are stable.

### ASLR entropy

ASLR's security depends on the number of random bits in the base address — its **entropy**. On x86-64 with Linux, typical entropy is:

| Component | Entropy bits (approx.) | Possible positions |  
|---|---|---|  
| PIE binary | 28 bits | ~268 million |  
| Shared libraries (`mmap`) | 28 bits | ~268 million |  
| Stack | 22 bits | ~4 million |  
| Heap (`brk`) | 13 bits | ~8,000 |

The entropy of the stack and especially the heap is much lower. That is why some exploitation techniques brute-force the heap — with only 8,000 possible positions, a few thousand attempts are statistically enough.

On x86 32-bit, entropy is much lower (often 8 bits for libraries — 256 positions), making brute-force trivial. This is one of the reasons 64-bit systems are significantly more resistant to this kind of attack.

## Working with ASLR in RE

### Disabling ASLR for debugging

During dynamic analysis, ASLR can be inconvenient: addresses change at every execution, breakpoints on absolute addresses do not work from one session to the next. Several methods allow it to be temporarily disabled:

**Globally** (discouraged outside a lab):

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# Restore afterwards:
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

**For a single process** (recommended method):

```bash
# With setarch
setarch x86_64 -R ./hello RE-101

# With GDB's personality flag
# GDB disables ASLR by default for the debugged process!
gdb ./hello
(gdb) show disable-randomization
# Disable randomization of debuggee's virtual address space is on.
(gdb) run RE-101
```

GDB disables ASLR by default for the process it launches (via the `ADDR_NO_RANDOMIZE` flag of the `personality` system call). That is why addresses are reproducible between two GDB sessions. If you need to test with ASLR active inside GDB:

```bash
(gdb) set disable-randomization off
(gdb) run
```

### Computing offsets

The fundamental strategy for working with ASLR is to reason in **offsets** rather than in absolute addresses:

```
offset = runtime_address - load_base
```

The offset of a function or piece of data is identical in the ELF file on disk and in memory (it is the `p_vaddr` from the program header table). It is this value that tools like Ghidra and IDA display by default for PIE binaries.

To retrieve the load base at runtime:

```bash
# In GDB (with GEF or pwndbg)
gef> vmmap
# or
pwndbg> vmmap

# From /proc
grep hello /proc/$(pidof hello)/maps | head -1
# 55a3c4000000-55a3c4001000 r--p 00000000 ...  /home/user/hello
# ^^^^^^^^^^^^ load base
```

To convert a Ghidra offset into a runtime address:

```
runtime_address = load_base + ghidra_offset
```

For example, if Ghidra shows the `check` function at offset `0x1149` and the load base in GDB is `0x55a3c4000000`:

```bash
(gdb) break *0x55a3c4001149
# or more simply, if symbols are available:
(gdb) break check
```

GDB extensions like GEF and pwndbg automate these calculations with commands like `pie breakpoint` and `pie run` (Chapter 12).

### The case of shared libraries

Shared libraries are always loaded at random addresses, whether the main binary is PIE or not. To find the base address of a library:

```bash
# In GDB
(gdb) info sharedlibrary
# From                To                  Syms Read   Shared Object Library
# 0x00007f8c3a228000  0x00007f8c3a3bd000  Yes         /lib/.../libc.so.6

# From /proc
grep libc /proc/$(pidof hello)/maps | head -1
# 7f8c3a200000-7f8c3a228000 r--p ...  /lib/.../libc.so.6
```

To set a breakpoint on a library function (for example `strcmp` in libc), simply use its name — GDB resolves the address automatically thanks to dynamic symbols:

```bash
(gdb) break strcmp
# Breakpoint 1 at 0x7f8c3a2xxxx
```

## Segment memory protections

Segment mapping is not only about addresses — **permissions** are just as important. The kernel configures the MMU to apply each page's permissions:

| Permission | Meaning | Violation → signal |  
|---|---|---|  
| `R` (Read) | Memory can be read | Reading a non-R page → `SIGSEGV` |  
| `W` (Write) | Memory can be written | Writing to a non-W page → `SIGSEGV` |  
| `X` (Execute) | Memory can be executed as code | Executing a non-X page → `SIGSEGV` |

### The W⊕X principle (NX bit)

The **W⊕X** principle (*Write XOR Execute*, also called **NX** — *No eXecute*, or **DEP** — *Data Execution Prevention* on Windows) states that a memory page should never be both writable **and** executable. In practice:

- Code (`.text`) is `R-X`: executable but not writable. Impossible to inject code by writing to `.text`.  
- Data (`.data`, `.bss`, stack, heap) is `RW-`: writable but not executable. Impossible to execute code injected into a buffer.  
- Read-only data (`.rodata`) is `R--`: neither writable nor executable.

This protection is implemented in hardware via the **NX bit** (No eXecute) of the processor, present on all modern x86-64 processors. The Linux kernel enables it by default.

```bash
# Check NX with checksec
checksec --file=hello
# NX:  NX enabled
```

### Consequences in RE and exploitation

W⊕X prevents classical **shellcode injection** attacks: even if an attacker manages to write machine code into a buffer on the stack or heap, that code cannot be executed because the memory zone does not have `X` permission.

That is why modern exploitation techniques bypass W⊕X through **code reuse** approaches: instead of injecting new code, they reuse fragments of code already existing in `R-X` zones — this is the principle of **ROP** (*Return-Oriented Programming*, Chapter 12, section 12.3) and **ret2libc**.

The GOT (`.got.plt`) is in a `RW-` segment — writable but not executable. That is what makes **GOT overwrite** attacks possible: you overwrite a function pointer in the GOT (allowed write) to redirect an existing call via the PLT (execution of the code at the written address). The **Full RELRO** protection (section 2.9, Chapter 19) counters this attack by making the GOT `R--` after initial resolution.

## The zero page — The NULL trap

The address `0x0` (and generally the entire first page, `0x0`–`0xFFF`) is **never mapped**. Any access to this zone triggers a `SIGSEGV`. It is an intentional protection: dereferencing a NULL pointer produces an immediate, detectable crash, instead of silently corrupting data.

```bash
# Check that the zero page is not mapped
head -1 /proc/$(pidof hello)/maps
# The start address is well above 0x0
```

This protection is configurable via `/proc/sys/vm/mmap_min_addr` (generally `65536` — the first 64 KB are forbidden). Historically, some kernel vulnerabilities exploited mapping of the zero page; this restriction prevents *NULL pointer dereference* type exploits.

## Summary of typical addresses on x86-64

To give you a mental landmark, here are the address ranges you will frequently encounter in RE on Linux x86-64. These values are indicative and vary with ASLR:

| Component | Typical range (with ASLR) | Typical range (without ASLR / non-PIE) |  
|---|---|---|  
| PIE binary | `0x55XX_XXXX_X000` – … | — |  
| Non-PIE binary | `0x0040_0000` – `0x004X_XXXX` | Fixed |  
| Heap (brk) | Right after the binary | Right after the binary |  
| `.so` libraries | `0x7fXX_XXXX_X000` – … | `0x7fXX_XXXX_X000` – … |  
| Loader `ld.so` | `0x7fXX_XXXX_X000` – … | `0x7fXX_XXXX_X000` – … |  
| Stack | `0x7fXX_XXXX_X000` (top of stack) | `0x7fff_XXXX_XXXX` |  
| vDSO | Near the stack | Near the stack |  
| Kernel (inaccessible in user mode) | `0xFFFF_8XXX_XXXX_XXXX` | `0xFFFF_8XXX_XXXX_XXXX` |

A useful reflex: when you see an address starting with `0x55`, it is probably the PIE binary. An address starting with `0x7f` is probably a shared library, the loader, or the stack. An address starting with `0x40` is a non-PIE binary.

## Impact on the RE workflow

The combination PIE + ASLR influences your workflow at every stage:

**Static analysis** (Ghidra, IDA, objdump): tools display offsets relative to the base `0x0` for PIE binaries. These offsets are stable and correspond exactly to what you will find in memory (modulo adding the base). No negative impact — static analysis is independent of ASLR.

**Dynamic analysis** (GDB, Frida, strace): actual addresses depend on the load base, which changes at every execution (unless you disable ASLR or use GDB, which does it by default). You must either work with symbol names or compute runtime addresses from known offsets.

**Scripting and automation** (pwntools, angr): exploitation frameworks like `pwntools` handle ASLR explicitly. You work with offsets until exploitation time, when you inject a runtime address computed from a leaked address. The `ELF` module of pwntools eases these computations:

```python
from pwn import *  
elf = ELF('./hello')  
# elf.symbols['check'] → offset of check (e.g.: 0x1149)
# At runtime, address = base + elf.symbols['check']
```

> 💡 **Golden rule**: In RE, always think in offsets. Record offsets in your Ghidra annotations, scripts, and reports. Absolute addresses are only valid for a given execution; offsets are permanent.

---

> 📖 **We now understand how segments are mapped into memory and why addresses move.** One last essential mechanism remains to be understood: how calls to shared-library functions are resolved through the PLT/GOT pair. That is the subject of the last section of this chapter.  
>  
> → 2.9 — Dynamic symbol resolution: PLT/GOT in detail (lazy binding)

⏭️ [Dynamic symbol resolution: PLT/GOT in detail (lazy binding)](/02-gnu-compilation-chain/09-plt-got-lazy-binding.md)
