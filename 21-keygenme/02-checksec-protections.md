🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.2 — Protection Inventory with `checksec`

> 📖 **Reminder**: binary protections (ASLR, PIE, NX, canary, RELRO) were presented in detail in chapter 19. This section applies them concretely to our keygenme. If the terms seem unclear, revisit sections 19.5 and 19.6 before continuing.

---

## Introduction

The triage in section 21.1 revealed the nature of the binary (ELF x86-64, PIE, dynamically linked) and its content (internal functions, plaintext strings). Before diving into disassembly, one essential question remains: **what protections did the compiler and linker enable?**

The answer directly conditions the analysis strategy. A binary with Full RELRO and a stack canary is not patched the same way as a binary with no protection. A PIE binary with active ASLR requires working with relative offsets in GDB. Knowing the protections *before* analyzing means avoiding wasted time on approaches doomed to fail.

The `checksec` tool automates this inventory in a single command.

---

## `checksec`: quick overview

`checksec` is a shell script (historically) or a Python module (via `pwntools`) that inspects an ELF binary and lists its security protections. It does nothing magical: it reads the ELF headers, sections, and program flags — exactly what `readelf` allows, but synthesizing the information in an immediately readable format.

Two ways to invoke it:

```bash
# Via the standalone checksec script
$ checksec --file=keygenme_O0

# Via pwntools (Python)
$ pwn checksec keygenme_O0
```

Both produce an equivalent result. We will use the `pwntools` syntax throughout the rest of the chapter, as it integrates naturally into the Python scripts in sections 21.7 and 21.8.

---

## Result on `keygenme_O0`

```bash
$ pwn checksec keygenme_O0
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    DEBUGINFO:  Yes
```

Six lines, six pieces of information. Let's break down each one in the context of our analysis.

---

## Detailed analysis of each protection

### Arch: `amd64-64-little`

The architecture confirms what `file` had already indicated: x86-64 in little-endian. This is not a "protection" per se, but the information is critical for everything that follows: we work with 64-bit registers, the System V AMD64 calling convention (parameters in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`), and little-endian encoding of addresses in memory.

### RELRO: `Full RELRO`

RELRO (RELocation Read-Only) controls the permissions of the `.got.plt` section after the binary is loaded.

In **Full RELRO**, all relocations are resolved at startup (eager binding) and the GOT is then marked read-only. Concretely:

- The GOT cannot be overwritten at runtime. "GOT overwrite" exploitation techniques are neutralized.  
- Calls to libc functions (`printf`, `strcmp`...) no longer go through the lazy binding mechanism — the real address is written into the GOT as soon as `ld.so` loads it.

**Impact on our analysis**: for the keygenme, Full RELRO means we cannot modify the GOT to hijack a call (for example, replacing the address of `strcmp` with that of a function that always returns 0). This is not a problem here — our approach will be direct patching of the conditional jump (section 21.6) or writing a keygen (section 21.8). But on a target where we would seek to exploit a vulnerability, Full RELRO would close a classic attack vector.

> 💡 **How GCC enables Full RELRO**: this is the default behavior on modern distributions (since Debian 11, Ubuntu 22.04, Fedora 33+). The explicit flag is `-Wl,-z,relro,-z,now` passed to the linker. The `-z,now` option is what transforms Partial RELRO into Full RELRO by forcing eager binding.

### Stack: `Canary found`

A stack canary (or stack protector) is a sentinel value placed between local variables and the return address on the stack. At the end of each protected function, the program checks that the canary has not been altered. If it has, it calls `__stack_chk_fail` and terminates immediately — preventing exploitation of a stack buffer overflow.

In assembly, the canary is recognized in two places:

**In the function prologue**:
```nasm
mov    rax, QWORD PTR fs:0x28    ; read canary from TLS  
mov    QWORD PTR [rbp-0x8], rax  ; copy onto stack  
```

**In the epilogue**, just before `ret`:
```nasm
mov    rax, QWORD PTR [rbp-0x8]  ; re-read canary from stack  
xor    rax, QWORD PTR fs:0x28    ; compare with original value  
jne    .canary_fail               ; if different → stack smashing detected  
```

The canary value is read from `fs:0x28` (Thread Local Storage). It is random and changes with each program execution.

**Impact on our analysis**: the canary adds a few instructions in the prologue and epilogue of each function. They must not be confused with the program's business logic. When reading the disassembly of `check_license` in Ghidra or GDB, the canary-related instructions (access to `fs:0x28`, the final `xor`, the `jne` to `__stack_chk_fail`) are "protection noise" that can be mentally ignored. They are easily recognized by the `fs:0x28` pattern.

> 💡 **How GCC enables the canary**: the flag `-fstack-protector-strong` (default on modern distributions) protects functions that contain local arrays or calls to `alloca`. The flag `-fstack-protector-all` protects *all* functions. The flag `-fno-stack-protector` disables the protection.

### NX: `NX enabled`

NX (No eXecute), also called DEP (Data Execution Prevention) or W^X, forbids code execution in data segments (stack, heap, `.data`, `.bss`). The processor refuses to execute an instruction located in a memory page marked "non-executable."

We had already deduced this protection in section 21.1 by examining segments with `readelf -l`: the stack segment (`GNU_STACK`) did not have the `E` (executable) flag.

**Impact on our analysis**: NX prevents classic shellcode injection (writing code on the stack then jumping to it). For a keygenme, this protection has no consequence — we are not seeking to execute arbitrary code, but to understand the verification algorithm. NX is nevertheless important to note because it conditions exploitation techniques (ROP, ret2libc) if we needed to exploit a vulnerability in the binary.

### PIE: `PIE enabled`

PIE (Position-Independent Executable) means the binary is compiled entirely as position-independent code. Combined with ASLR (at the OS level), the binary's base address changes with each execution.

**Impact on our analysis**: this is the protection that most affects the reverse engineer's daily workflow.

In **static analysis** (Ghidra, objdump), displayed addresses are offsets relative to the binary's base. Ghidra uses a default fictitious base (`0x00100000`) and all addresses are consistent with each other — no problem.

In **dynamic analysis** (GDB), absolute addresses change with each launch. To set a breakpoint on `check_license` in GDB:

```bash
# With symbols: no problem, GDB resolves the name
(gdb) break check_license

# Without symbols (stripped binary): the address must be calculated
# Method: Ghidra offset - Ghidra base + actual base
(gdb) info proc mappings
# ... locate the binary's load base
(gdb) break *0x<actual_base + offset>
```

You can also disable ASLR to simplify debugging:

```bash
# Disable ASLR globally (temporary, requires root)
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Or only for GDB
(gdb) set disable-randomization on
```

The second method is preferable: it only affects the current GDB session and does not reduce host system security.

### DEBUGINFO: `Yes`

Indicates the presence of DWARF debug information (compiled with `-g`). This is not a protection — it is the opposite: their presence greatly facilitates RE by providing function names, variable types, line numbers, and source-to-assembly correspondence.

On the stripped variants (`keygenme_strip`, `keygenme_O2_strip`), this line will display `No`.

---

## Comparison of the 5 variants

For an overview, let's run `checksec` on all five variants:

```bash
$ for bin in keygenme_O0 keygenme_O2 keygenme_O3 keygenme_strip keygenme_O2_strip; do
    echo "── $bin ──"
    pwn checksec $bin 2>/dev/null | tail -6
    echo ""
done
```

The expected result (with a recent GCC on a modern distribution):

| Protection | `_O0` | `_O2` | `_O3` | `_strip` | `_O2_strip` |  
|---|---|---|---|---|---|  
| RELRO | Full | Full | Full | Full | Full |  
| Stack Canary | ✅ | ✅ | ✅ | ✅ | ✅ |  
| NX | ✅ | ✅ | ✅ | ✅ | ✅ |  
| PIE | ✅ | ✅ | ✅ | ✅ | ✅ |  
| Debug info | ✅ | ✅ | ✅ | ❌ | ❌ |  
| Symbols | ✅ | ✅ | ✅ | ❌ | ❌ |

The protections are **identical** across all five variants. This is logical: RELRO, canary, NX, and PIE are compiler and linker options, not optimization level options. Stripping removes symbols and debug information, but does not touch security protections.

This table confirms an important point: **the increasing difficulty between variants does not come from protections** (they are the same), but from two factors:

1. **Optimization** (`-O0` → `-O2` → `-O3`): the assembly code becomes more compact, functions may be inlined, loops unrolled, variables kept in registers instead of the stack. The algorithm is the same, but its expression in assembly is harder to read.

2. **Stripping**: without symbols, we lose function names (`check_license` becomes `FUN_XXXXXXXX` in Ghidra), variable types, and source correspondence. This information must be reconstructed manually.

---

## What `checksec` does not tell you

`checksec` covers the standard protections of a modern ELF binary, but does not detect:

- **Packing** (UPX, custom packers) — section entropy must be checked and known packer signatures searched for. See chapter 29.  
- **Control flow obfuscation** (control flow flattening, bogus control flow) — visible only in disassembly. See chapter 19, section 3.  
- **Anti-debugger techniques** (`ptrace` detection, timing checks, `/proc/self/status`) — detectable via static analysis or by running under `strace`. See chapter 19, section 7.  
- **String or section encryption** — detectable via entropy analysis or the absence of readable strings in `strings`.  
- **Fortify Source** (`_FORTIFY_SOURCE`) — the replacement of dangerous functions (`strcpy` → `__strcpy_chk`) is visible in symbols but not always reported by `checksec`.

Our keygenme uses none of these additional techniques — protections are limited to the standard defenses enabled by default by GCC.

---

## Summary and implications for what follows

The protection inventory completes the triage from section 21.1. We can now summarize our knowledge of the binary in two categories:

**What facilitates the analysis:**  
- Symbols and DWARF information present (on the `_O0` variant)  
- No packing or obfuscation  
- No anti-debugger technique  
- Plaintext strings

**What constrains the analysis:**  
- **PIE + ASLR** → work with relative offsets in GDB, or disable ASLR  
- **Full RELRO** → no GOT overwrite possible  
- **Stack canary** → additional noise in prologue/epilogue (`fs:0x28` instructions to ignore)  
- **NX** → no shellcode injection (not relevant for a keygen, but good to know)

None of these constraints prevent us from achieving our objective: understanding the verification algorithm and writing a keygen. They simply add a few methodological precautions when using GDB (section 21.5) and close certain exploitation paths that are not our approach here anyway.

The ground is mapped. The next section (21.3) dives into Ghidra to locate the verification routine via a top-down approach, starting from `main()` and following cross-references to the decisive `strcmp`.

⏭️ [Locating the verification routine (top-down approach)](/21-keygenme/03-routine-localization.md)
