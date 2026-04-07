🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 5.6 — `checksec` — binary protection inventory (ASLR, PIE, NX, canary, RELRO)

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

Throughout the previous sections, we already met several security protections without explicitly naming them. With `readelf -l`, we saw that no segment was simultaneously writable and executable (`RWE`) — that is the NX protection. With `readelf -l`, we saw the `GNU_RELRO` segment — that is the RELRO mechanism. With `file`, we read `pie executable` — that is the PIE protection that enables full ASLR.

These protections are **defense mechanisms** integrated by the compiler, linker, and kernel to make the exploitation of vulnerabilities (buffer overflow, format string, use-after-free…) harder. In reverse engineering, knowing them is essential for two reasons:

- **In security auditing**: inventorying the protections lets you assess the defensive posture of a binary and identify exploitable weaknesses.  
- **In pure RE**: some protections modify the binary's behavior in ways that are visible in the disassembly. Stack canaries add code in every function's prologue/epilogue. PIE changes the addressing scheme. RELRO affects the GOT. Knowing which protections are active lets you understand patterns that would otherwise be puzzling.

`checksec` is a script that automates checking all these protections in one command. It queries the ELF headers, sections, and binary properties to produce a synthetic report.

---

## Installing `checksec`

`checksec` exists in several forms. The most widespread is the standalone shell script, but the version integrated with `pwntools` (the Python exploitation framework) is just as common in practice.

```bash
# Standalone version (shell script)
# Available on most distributions
$ sudo apt install checksec       # Debian/Ubuntu
$ checksec --file=keygenme_O0

# pwntools version (Python)
$ pip install pwntools
$ checksec keygenme_O0

# From a pwntools Python script
from pwn import *  
elf = ELF('./keygenme_O0')  
# Protections are displayed automatically on import
```

Both versions produce identical results. Below, we use the standalone version's syntax.

---

## Reading the `checksec` output

### Example on our crackme

```bash
$ checksec --file=keygenme_O0
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable  FILE  
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   72 Symbols      No      0           2           keygenme_O0  
```

In a single line, `checksec` summarizes the state of each protection. Let's review them one by one, explaining what each one means, how it works, and how it shows up in the binary.

---

## NX (No-eXecute) — the stack and data are not executable

### Principle

NX (also called DEP — *Data Execution Prevention* — on Windows, or W^X — *Write XOR Execute*) is the principle that a memory region should never be simultaneously **writable and executable**. Code is executable but not modifiable; data is modifiable but not executable.

Without NX, an attacker who manages to inject code on the stack (via a classic buffer overflow) can execute it immediately, because the stack is both writable (for local variables) and executable. With NX enabled, any attempt to execute code from the stack triggers a `SIGSEGV` (segmentation fault).

### How `checksec` checks for it

`checksec` inspects the `GNU_STACK` segment in the program headers:

```bash
$ readelf -lW keygenme_O0 | grep GNU_STACK
  GNU_STACK      0x000000 0x000000 0x000000 0x000000 0x000000 RW  0x10
```

The flag is `RW` (readable and writable, **without** `E` for executable). The stack is therefore not executable: **NX is enabled**.

If NX were disabled, you would see `RWE`:

```bash
# Compilation deliberately without NX (for testing only)
$ gcc -z execstack -o vuln vuln.c
$ readelf -lW vuln | grep GNU_STACK
  GNU_STACK      0x000000 0x000000 0x000000 0x000000 0x000000 RWE 0x10
```

### RE impact

NX has been enabled by default in GCC for years. Its absence in a modern binary is a strong signal: either the binary was intentionally compiled with `-z execstack` (JIT compilers, some educational exploits), or it is a very old binary, or it is self-modifying code.

In the disassembly, NX produces no visible code — it is a property of the segments, not of the machine code. But if you see an `mprotect` call with flags `PROT_READ|PROT_WRITE|PROT_EXEC` in `strace` or the disassembly, it means the program is bypassing NX dynamically by making a memory region executable on the fly. That is typical behavior of packers and malware (Chapter 29).

---

## PIE (Position-Independent Executable) — the executable can be loaded anywhere

### Principle

A PIE binary is compiled so that all of its code uses **relative addressing** — no absolute address is hardcoded. This lets the loader load the binary at a random base address on every execution, thanks to the kernel's ASLR (Address Space Layout Randomization).

Without PIE, the binary is loaded at a fixed address (typically `0x400000` for a 64-bit non-PIE ELF). An attacker then knows exactly the addresses of all functions and all ROP gadgets. With PIE, the base address changes at every execution, which makes code-reuse attacks much harder.

### How `checksec` checks for it

`checksec` looks at the `e_type` field of the ELF header:

```bash
$ readelf -h keygenme_O0 | grep Type
  Type:                              DYN (Position-Independent Executable file)
```

The `DYN` type indicates a PIE binary (or a shared library). A non-PIE binary would have the `EXEC` type:

```bash
# Compilation deliberately without PIE
$ gcc -no-pie -o nopie nopie.c
$ readelf -h nopie | grep Type
  Type:                              EXEC (Executable file)
```

### RE impact

PIE significantly affects reverse-engineering work:

**In static disassembly**: every address displayed by `objdump`, Ghidra, or IDA is relative to the load base (offsets). The `0x1189` address for `main` is not the actual address in memory — it is an offset that will be added to the (random) base address at load time.

**In dynamic debugging**: effective addresses change at every execution. To set a breakpoint on `main` in GDB, you either use the symbolic name (`break main`) or compute the real address by adding the offset to the current base. GDB handles this automatically in most cases, but it is a frequent source of confusion for beginners.

**On non-PIE binaries**: addresses are fixed and identical between the static disassembly and dynamic execution. It is simpler to analyze, but also less secure.

### ASLR — the kernel counterpart of PIE

PIE is a property of the **binary**. ASLR is a **kernel** feature that randomizes load addresses. Both are complementary:

| PIE | Kernel ASLR | Result |  
|---|---|---|  
| Yes | Enabled | Binary address random on every execution (maximum protection) |  
| Yes | Disabled | The binary is PIE but loaded at a fixed address (ASLR off) |  
| No | Enabled | Stack, heap, and libraries are randomized, but the binary itself is at a fixed address |  
| No | Disabled | No randomization (no protection) |

To check ASLR state on the system:

```bash
$ cat /proc/sys/kernel/randomize_va_space
2
```

The value `2` means full ASLR (stack, heap, mmap, libraries). `1` = partial ASLR (no heap). `0` = ASLR disabled. For dynamic RE, you sometimes temporarily disable ASLR to get reproducible addresses:

```bash
# Disable ASLR for the current session (requires root)
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Or for a single command (no root needed)
$ setarch $(uname -m) -R ./keygenme_O0
```

---

## Stack Canary — detecting stack buffer overflows

### Principle

A *stack canary* (also called *stack guard* or *stack cookie*) is a random value placed between a function's local variables and the saved return address on the stack. Before returning, the function verifies that this value has not been modified. If a buffer overflow wrote past the buffer, it will also have overwritten the canary, and the check will fail, immediately aborting the program (`__stack_chk_fail`).

The name "canary" references the birds coal miners carried into tunnels to detect toxic gases: if the canary died, the miners knew to evacuate. Likewise, if the stack canary is corrupted, the program knows an overflow occurred.

### How `checksec` checks for it

`checksec` looks for the `__stack_chk_fail` symbol in the symbol tables:

```bash
$ readelf -s keygenme_O0 | grep stack_chk
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4

$ nm -D keygenme_O0 | grep stack_chk
                 U __stack_chk_fail@GLIBC_2.4
```

The presence of this symbol indicates the binary contains canary-checking code — hence **Canary found**.

### RE impact

Stack canaries are visible in the disassembly of every protected function. GCC inserts a **prologue** that reads the canary value from the TLS (Thread-Local Storage) segment and places it on the stack, and an **epilogue** that verifies it before the `ret`:

```asm
; Prologue — canary setup
push   rbp  
mov    rbp, rsp  
sub    rsp, 0x30  
mov    rax, QWORD PTR fs:[0x28]     ; ← Read canary from fs:[0x28]  
mov    QWORD PTR [rbp-0x8], rax     ; ← Store it on the stack  
xor    eax, eax  

; ... function body ...

; Epilogue — canary verification
mov    rax, QWORD PTR [rbp-0x8]     ; ← Re-read the canary from the stack  
cmp    rax, QWORD PTR fs:[0x28]     ; ← Compare with the original value  
jne    .Lfail                        ; ← If different: overflow detected!  
leave  
ret  
.Lfail:
call   __stack_chk_fail              ; ← Terminates the program
```

This pattern `fs:[0x28]` → store → ... → reload → compare → `__stack_chk_fail` is a **GCC idiom** you will find in virtually every function of a binary compiled with `-fstack-protector`. Learn to recognize it immediately — it is not part of the program's logic, it is protection code injected by the compiler.

The access via `fs:[0x28]` uses the `fs` segment register, which points to the current thread's TLS structure. The `0x28` offset is the location of the canary in that structure on x86-64 Linux. The canary's value is randomly generated at process startup.

### Protection levels

GCC offers several canary protection levels:

| Compile flag | Behavior |  
|---|---|  
| `-fstack-protector` | Only protects functions using character arrays (GCC heuristic). |  
| `-fstack-protector-strong` | Protects functions using arrays, local variables whose address is taken, or `alloca` calls. It is the default on modern distributions. |  
| `-fstack-protector-all` | Protects **every** function, no exception. Safer but more costly in performance. |  
| `-fno-stack-protector` | Fully disables canaries. |

`checksec` does not distinguish these levels — it simply indicates whether canaries are present or not.

---

## RELRO (Relocation Read-Only) — protecting the GOT

### Principle

The GOT (Global Offset Table) is an in-memory table containing the resolved addresses of shared-library functions (see Chapter 2, section 2.9). By default, this table is writable because the dynamic loader writes addresses into it as functions are called for the first time (lazy binding).

A writable GOT is a prime target for attackers: by overwriting a GOT entry (via a buffer overflow or arbitrary write), you can redirect a function call to arbitrary code. For example, replacing `printf`'s address in the GOT with `system`'s address lets you execute shell commands the next time the program calls `printf`.

RELRO (Relocation Read-Only) counters this attack by making the GOT read-only after symbol resolution.

### Partial RELRO vs Full RELRO

There are two RELRO levels, offering very different protections:

**Partial RELRO** (`-Wl,-z,relro`) — the linker reorganizes ELF sections to place the GOT after the writable data sections, and marks certain regions (`.init_array`, `.fini_array`, `.dynamic`) as read-only after loading. However, **the part of the GOT used by the PLT** (`.got.plt`) remains writable, because lazy binding needs it.

**Full RELRO** (`-Wl,-z,relro,-z,now`) — in addition to Partial RELRO's reorganization, the `-z now` flag forces the loader to resolve **all** symbols immediately at load time (eager binding), instead of resolving them lazily on first use. Once every address has been written into the GOT, the **entire** GOT is made read-only via `mprotect`. The GOT cannot be modified at all after initialization.

### How `checksec` checks for it

`checksec` examines the presence of the `GNU_RELRO` segment and the `BIND_NOW` entry in the `.dynamic` section:

```bash
# Check the GNU_RELRO segment
$ readelf -lW keygenme_O0 | grep GNU_RELRO
  GNU_RELRO      0x002db8 0x003db8 0x003db8 0x000248 0x000248 R   0x1

# Check BIND_NOW (distinguishes Partial from Full)
$ readelf -d keygenme_O0 | grep -E 'BIND_NOW|FLAGS'
 0x0000000000000018 (BIND_NOW)
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
```

The logic is as follows:

| `GNU_RELRO` present? | `BIND_NOW` present? | Result |  
|---|---|---|  
| No | — | No RELRO |  
| Yes | No | Partial RELRO |  
| Yes | Yes | Full RELRO |

### RE impact

**No RELRO**: the GOT is fully writable. Classic exploitation technique: GOT overwrite.

**Partial RELRO**: the PLT's GOT remains writable. Lazy binding is active — in the disassembly, the first call to a function goes through the PLT stub that invokes the resolver, and subsequent calls jump directly to the resolved address in the GOT.

**Full RELRO**: the GOT is read-only after initialization. Lazy binding is disabled — all addresses are resolved at load time. In `strace`, you observe an `mprotect` making the GOT region read-only during the initialization phase. Exploitation techniques based on GOT overwrite no longer work.

---

## FORTIFY_SOURCE — hardening libc functions

### Principle

`FORTIFY_SOURCE` is a compilation mechanism (`-D_FORTIFY_SOURCE=2` or `=3`) that replaces some dangerous libc functions with secured versions that check buffer sizes at compile time and/or runtime. For example, `memcpy(dst, src, n)` is replaced with `__memcpy_chk(dst, src, n, dst_size)` which checks that `n` does not exceed `dst_size`.

### How `checksec` checks for it

`checksec` counts the "fortified" functions (`_chk` suffix) in dynamic symbols and compares them to the number of "fortifiable" functions:

```
FORTIFY   Fortified   Fortifiable  
No        0           2  
```

Here, `checksec` indicates 2 functions *could* be fortified, but 0 are. It means the binary was not compiled with `-D_FORTIFY_SOURCE`.

If the protection were active, you would see symbols like `__printf_chk` and `__read_chk` instead of `printf` and `read`:

```bash
$ nm -D fortified_binary | grep _chk
                 U __printf_chk@GLIBC_2.3.4
                 U __read_chk@GLIBC_2.4
```

### RE impact

Fortified functions (`__printf_chk`, `__memcpy_chk`, `__strcpy_chk`…) take an extra argument (the destination buffer size). In the disassembly, this manifests as an extra parameter passed in a register and a call to the `_chk` version instead of the standard one. It is a minor pattern but good to know so you are not thrown off by these unusual function names.

---

## RPATH / RUNPATH — library search paths

`checksec` also reports the presence of `RPATH` and `RUNPATH` — library search paths encoded in the binary (see section 5.4). From a security standpoint, an `RPATH` or `RUNPATH` pointing to a directory writable by an unprivileged user is a vulnerability: an attacker could place a malicious library there that would be loaded instead of the legitimate one.

```bash
# No RPATH/RUNPATH (normal, safe situation)
RPATH      RUNPATH  
No RPATH   No RUNPATH  

# RPATH pointing to a potentially dangerous directory
RPATH      RUNPATH
/tmp/libs  No RUNPATH    # ← Alert: /tmp is writable by everyone!
```

---

## Comparing protections of several binaries

`checksec` can analyze several binaries in one command, which lets you quickly compare protections:

```bash
$ checksec --dir=binaries/ch05-keygenme/
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable  FILE  
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   72 Symbols      No      0           2           keygenme_O0  
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   72 Symbols      No      0           2           keygenme_O2  
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols      No      0           2           keygenme_O2_strip  
```

We see that the protections are identical across the three versions — security flags do not depend on the optimization level (`-O0` vs `-O2`), but on linking and compile flags. The only difference is the `Symbols` column: the stripped binary shows `No Symbols`.

---

## Checking protections manually (without `checksec`)

`checksec` is a convenience tool, not a black box. Everything it does can be reproduced with `readelf`. Here is the correspondence:

| Protection | Manual command | Presence indicator |  
|---|---|---|  
| NX | `readelf -lW binary \| grep GNU_STACK` | Flags `RW` (without `E`) |  
| PIE | `readelf -h binary \| grep Type` | `DYN` = PIE, `EXEC` = non-PIE |  
| Canary | `readelf -s binary \| grep __stack_chk_fail` | Symbol present = canary enabled |  
| RELRO | `readelf -lW binary \| grep GNU_RELRO` | Segment present = at least Partial |  
| Full RELRO | `readelf -d binary \| grep BIND_NOW` | Entry present = Full RELRO |  
| FORTIFY | `readelf -s binary \| grep _chk@` | `_chk` symbols = fortified |  
| RPATH | `readelf -d binary \| grep RPATH` | Entry present = RPATH defined |  
| RUNPATH | `readelf -d binary \| grep RUNPATH` | Entry present = RUNPATH defined |

Knowing how to reproduce these checks manually matters: on the one hand, `checksec` is not always available (minimal environment, restricted target machine); on the other hand, understanding *how* protections are encoded in the ELF reinforces your mastery of the format.

---

## Protection summary

| Protection | Protects against | Enabled by | Disabled by |  
|---|---|---|---|  
| **NX** | Execution of injected code (stack, heap) | GCC default | `-z execstack` |  
| **PIE** | Prediction of binary addresses | Modern GCC default | `-no-pie` |  
| **ASLR** | Prediction of addresses (stack, heap, libs) | Kernel default | `echo 0 > /proc/sys/kernel/randomize_va_space` |  
| **Stack Canary** | Buffer overflow overwriting the return address | `-fstack-protector-strong` (default) | `-fno-stack-protector` |  
| **Partial RELRO** | Reorganization of sensitive sections | GCC default | `-Wl,-z,norelro` |  
| **Full RELRO** | GOT overwrite (makes the GOT read-only) | `-Wl,-z,now` | Absence of `-z now` |  
| **FORTIFY** | Overflows on libc functions (`memcpy`, `printf`…) | `-D_FORTIFY_SOURCE=2` | Absence of the define |

---

## What to remember going forward

- **`checksec` is the first reflex of binary security auditing**. In a single command, you know the state of every protection. It is also an RE triage reflex: protections directly influence your analysis strategy.  
- **NX enabled** means direct shellcode injection and execution is impossible without a bypass. Its disabling is a red flag.  
- **PIE enabled** means the binary's addresses are relative and randomized by ASLR. In debug, temporarily disable ASLR to get stable addresses.  
- **Stack canaries** add a recognizable pattern in disassembly (`fs:[0x28]` → comparison → `__stack_chk_fail`). Learn to recognize it to tell it apart from application logic.  
- **Full RELRO** makes the GOT read-only — PLT/GOT entries are resolved at load time, not lazily.  
- **Everything `checksec` does is reproducible with `readelf`**. Knowing the corresponding manual commands makes you autonomous on any system.  
- Chapter 19 will dig deeper into each of these protections and the techniques to bypass them in an advanced-analysis context.

---


⏭️ [Quick triage workflow: the first-5-minutes routine when facing a binary](/05-basic-inspection-tools/07-quick-triage-workflow.md)
