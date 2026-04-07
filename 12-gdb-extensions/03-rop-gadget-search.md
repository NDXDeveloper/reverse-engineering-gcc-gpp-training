🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 12.3 — ROP gadget searching from GDB

> **Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg**  
> **Part III — Dynamic Analysis**

---

## What is a ROP gadget and why search for it in RE?

Return-Oriented Programming (ROP) is a technique that reuses code fragments already present in a binary or its libraries — called **gadgets** — to build an arbitrary execution flow without injecting new code. Each gadget is a short sequence of machine instructions ending with a `ret` (or sometimes a `jmp reg` / `call reg`). By chaining the addresses of these gadgets on the stack, an attacker can bypass the NX (No eXecute) protection that prevents executing injected code on the stack or heap.

From the reverse engineer's perspective, ROP gadget searching is relevant in several legitimate contexts. During a **security audit**, identifying available gadgets in a binary allows evaluating its residual attack surface even in the presence of NX. In a **CTF**, solving exploitation challenges almost systematically involves building ROP chains. For **understanding an existing exploit**, knowing how to read and search for gadgets is indispensable for analyzing vulnerability reports and published proofs of concept.

GDB extensions integrate gadget search commands directly in the debugger, which offers an advantage over external tools: the search is performed on the **effective process memory** at execution time, including dynamically loaded libraries and accounting for ASLR resolution.

---

## Reminder: anatomy of a gadget

A gadget is a sequence of consecutive instructions in the `.text` segment (or any executable segment) that ends with a control-transfer instruction. The most common terminating instruction is `ret`, which pops an address from the stack and jumps to it. Here are some typical gadget examples:

```nasm
; Gadget "pop rdi ; ret" — loads a value from the stack into RDI
pop rdi  
ret  

; Gadget "pop rsi ; pop r15 ; ret" — loads two values, one useful (RSI), one sacrificed (R15)
pop rsi  
pop r15  
ret  

; Gadget "xor eax, eax ; ret" — sets RAX to zero
xor eax, eax  
ret  

; Gadget "syscall ; ret" — triggers a system call
syscall  
ret  
```

The `pop rdi ; ret` gadget is probably the most sought-after on x86-64: it allows placing a controlled value in `RDI`, the first function argument in the System V AMD64 convention. Combined with the address of `system@plt` and a pointer to the string `"/bin/sh"`, it suffices to obtain a shell — the classic `ret2libc` scenario.

A crucial point is that gadgets don't necessarily correspond to legitimate instruction boundaries of the original program. The linear disassembler of `objdump` splits bytes from the beginning of each function, but the x86-64 instruction set is variable-length. Starting decoding in the middle of a multi-byte instruction can produce an entirely different valid instruction sequence, ending with a `ret`, that constitutes an exploitable gadget. These are called **unaligned gadgets**, and it's one of the reasons why gadget search tools scan bytes one by one rather than relying on official disassembly.

---

## Gadget searching with PEDA

PEDA was the first extension to integrate a gadget search command. The `ropgadget` command scans the process's executable memory:

```
gdb-peda$ ropgadget
```

Without arguments, `ropgadget` searches in the main binary and displays all found gadgets, sorted by address. The output can be voluminous — a modestly-sized dynamically linked binary easily contains hundreds of gadgets, and if shared libraries are included, the count reaches thousands.

To filter the search on a specific pattern:

```
gdb-peda$ ropgadget "pop rdi"
```

This command searches for all gadgets containing the `pop rdi` sequence. PEDA displays the address and complete disassembly of the gadget:

```
0x00005555555551a3 : pop rdi ; ret
0x00007ffff7e1b2a1 : pop rdi ; pop rbp ; ret
```

PEDA also offers the `ropsearch` command for more targeted searching by regular expression on the disassembly:

```
gdb-peda$ ropsearch "pop r?i" binary  
gdb-peda$ ropsearch "pop rdi" libc  
```

The second argument specifies the search target: `binary` for the main binary, `libc` for the C library, or an explicit address range.

PEDA's `dumprop` command goes further by listing the most useful gadgets in a format organized by function (register-control gadgets, memory-write gadgets, jump gadgets):

```
gdb-peda$ dumprop
```

PEDA's limitations in this area are mainly related to search depth (maximum number of instructions per gadget) and the absence of advanced automatic classification.

---

## Gadget searching with GEF

GEF doesn't contain a built-in gadget search engine in its base code. It delegates this functionality to the external tool **ropper**, which it invokes transparently from the GDB prompt.

If ropper is installed (see section 12.1), the `ropper` command is available directly in GEF:

```
gef➤ ropper --search "pop rdi"
```

GEF automatically passes the context of the binary being debugged to ropper, which performs the search and displays results in the GDB terminal:

```
[INFO] Searching for gadgets: pop rdi
0x00005555555551a3: pop rdi; ret;
```

The advantage of this integration is benefiting from all of ropper's power (unaligned gadget searching, multiple format support, advanced filtering) without leaving the debugger. Accepted arguments are the same as ropper's command-line ones.

To search in a specific library loaded by the process:

```
gef➤ ropper --file /lib/x86_64-linux-gnu/libc.so.6 --search "pop rdi"
```

GEF also offers the `scan` command to search for arbitrary byte sequences in the process's executable segments, which can serve to manually locate a specific opcode:

```
gef➤ scan executable 0x5f 0xc3
```

This example searches for the byte sequence `5f c3` (i.e., `pop rdi ; ret` in x86-64 encoding). The command returns all addresses where this sequence appears in executable memory. It's a lower-level approach than disassembly-based searching, but useful for confirming a gadget's existence or searching for exotic encodings.

---

## Gadget searching with pwndbg

pwndbg integrates its own `rop` command:

```
pwndbg> rop --grep "pop rdi"
```

This command scans the process's executable memory, disassembles sequences ending with `ret` (and optionally `jmp` or `call`), and filters results according to the provided pattern.

Without a filter, `rop` produces the complete list of found gadgets. Results are paginated to avoid flooding the terminal:

```
pwndbg> rop
```

pwndbg allows restricting the search to a specific module via the `rop` command combined with memory-mapping information:

```
pwndbg> rop --module-name keygenme  
pwndbg> rop --module-name libc  
```

### Searching by target register

A frequent need is finding all gadgets that control a given register. pwndbg doesn't offer a native semantic filter for this, but grep filtering covers most cases:

```
pwndbg> rop --grep "pop rdi"  
pwndbg> rop --grep "mov rdi"  
pwndbg> rop --grep "xchg .*, rdi"  
```

By chaining these searches, you progressively build an inventory of means to control each argument register (`rdi`, `rsi`, `rdx`, `rcx`).

### The `ropper` command in pwndbg

In addition to its native `rop` command, pwndbg can also invoke ropper if installed, the same way as GEF:

```
pwndbg> ropper -- --search "pop rdi; ret"
```

The double dash separates pwndbg's arguments from those passed to ropper. This redundancy gives the choice between the internal engine (faster, fewer features) and ropper (slower, more complete).

---

## Searching in effective memory vs static searching

A fundamental advantage of gadget searching from GDB compared to static tools (`ROPgadget`, standalone `ropper`, `r2` with `/R`) is access to the **running process's memory**.

When the binary is compiled with PIE (Position Independent Executable) — which is the default with recent GCC — addresses displayed by a static tool are relative offsets. To obtain absolute addresses usable in an exploit, you need to know the base address at which the binary was loaded, which depends on ASLR. From GDB, gadgets are directly displayed with their effective addresses after relocation, ready to use.

Similarly, shared libraries (libc, libpthread, etc.) are only present in memory after dynamic loading. A static tool can analyze the `.so` file separately, but only a runtime tool sees the entire address space — main binary, libraries, vDSO, stack — as one.

To visualize the memory mapping and understand which region a gadget is in:

```
# GEF
gef➤ vmmap

# pwndbg
pwndbg> vmmap

# PEDA
gdb-peda$ vmmap
```

This command displays memory regions with their permissions (rwx). Gadgets can only be found in regions marked with the `x` (executable) flag. If a binary is compiled with Full RELRO and PIE, executable segments are reduced to the binary's `.text` and the libraries' `.text` — the number of available gadgets is limited by this surface.

---

## Complementary external tools

Commands built into GDB extensions are convenient for quick searching during a debugging session, but for exhaustive analysis of available gadgets, dedicated tools remain more performant.

**ROPgadget** is a standalone Python tool that performs deep searching, including unaligned gadgets, automatic chaining, and generation of complete ropchains for common scenarios (`execve`, `mprotect`):

```bash
ROPgadget --binary ./keygenme_O0 --ropchain
```

**ropper** offers similar features with an emphasis on performance and support for varied formats (ELF, PE, Mach-O, raw):

```bash
ropper --file ./keygenme_O0 --search "pop rdi"  
ropper --file /lib/x86_64-linux-gnu/libc.so.6 --search "pop rdi"  
```

**Radare2** offers the `/R` command for gadget searching in its own context, which we saw in Chapter 9:

```bash
r2 -q -c '/R pop rdi' ./keygenme_O0
```

The recommended strategy is to use built-in GDB commands for point and contextual searches during debugging, and switch to external tools for complete analysis or automatic ROP chain generation.

---

## Interaction between ROP gadgets and binary protections

Gadget searching doesn't happen in a vacuum — it must account for protections compiled into the binary. Let's recall the relevant protections (seen with `checksec`, section 5.6, and deepened in Chapter 19):

**NX (No eXecute)** is the protection that makes ROP necessary in the first place. Without NX, an attacker could simply inject shellcode on the stack and execute it. With NX enabled, stack and heap are non-executable, which forces resorting to reuse of existing code via ROP.

**ASLR (Address Space Layout Randomization)** randomizes the base addresses of libraries and, if PIE is enabled, of the main binary. Gadgets have different addresses at each execution. ROP exploitation in the presence of ASLR requires either an address leak (*information leak*) to compute the base, or exclusive use of gadgets in the main binary if PIE is disabled (since it's then loaded at a fixed address).

**PIE (Position Independent Executable)** subjects the main binary itself to ASLR. When PIE is active, even gadgets in the main binary have random addresses. Checking PIE status is therefore the first step before building a ROP chain:

```
gef➤ checksec
```

**Stack canaries** don't block ROP per se, but they protect against the buffer overflow that is the usual vector for overwriting the return address and triggering the ROP chain. A corrupted canary causes a call to `__stack_chk_fail` before the `ret` reaches the first gadget. Bypassing a canary requires either leaking it, or finding a write vector that doesn't overwrite the canary (arbitrary write outside a linear buffer, format string, etc.).

GDB extensions allow visualizing these protections and understanding their impact on the feasibility of a ROP chain, all without leaving the debugger — which connects gadget searching to the global analysis of the binary.

---

## Practical search methodology

Rather than searching for gadgets randomly, a methodical approach starts from the objective to achieve and works back to the necessary gadgets.

**Step 1 — Identify the objective.** What do you want to do? Call `system("/bin/sh")`? Invoke `execve` via a syscall? Call `mprotect` to make a page executable then jump to it? The objective determines which registers must be controlled and with what values.

**Step 2 — List the registers to control.** For `system("/bin/sh")`, you need `RDI = address of "/bin/sh"`. For an `execve` syscall, you need `RAX = 0x3b`, `RDI = address of "/bin/sh"`, `RSI = 0`, `RDX = 0`. Each register requires a `pop reg ; ret` type gadget or equivalent.

**Step 3 — Search for corresponding gadgets.**

```
pwndbg> rop --grep "pop rdi"  
pwndbg> rop --grep "pop rsi"  
pwndbg> rop --grep "pop rdx"  
pwndbg> rop --grep "pop rax"  
pwndbg> rop --grep "syscall"  
```

**Step 4 — Check side effects.** A `pop rsi ; pop r15 ; ret` gadget controls `RSI` but consumes an extra stack slot for `R15`. It's not a problem — just place any value at that location — but it must be accounted for in chain construction. Carefully read the complete disassembly of each gadget, not just the filtered part.

**Step 5 — Locate data.** The `"/bin/sh"` string is often present in libc itself. To find it from GDB:

```
# GEF
gef➤ grep "/bin/sh"

# pwndbg
pwndbg> search --string "/bin/sh"

# PEDA
gdb-peda$ searchmem "/bin/sh"
```

These commands search the string in the entire process memory and return the found addresses.

**Step 6 — Assemble the chain.** This assembly is outside the scope of this chapter (it belongs to exploitation proper), but the information collected in previous steps — gadget addresses, data addresses, memory mapping — constitute the necessary building blocks. The `pwntools` tool, introduced in section 11.9, allows automating this construction in Python.

---


⏭️ [Heap analysis with pwndbg (`vis_heap_chunks`, `bins`)](/12-gdb-extensions/04-heap-analysis-pwndbg.md)
