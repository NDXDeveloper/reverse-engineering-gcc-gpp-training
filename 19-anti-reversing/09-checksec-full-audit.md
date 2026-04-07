🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.9 — Inspecting all protections with `checksec` before any analysis

> 🎯 **Objective**: Integrate `checksec` into a systematic triage workflow, know how to interpret each line of its output in light of the previous sections, and build a "protection sheet" reflex that guides the analysis strategy before even opening the disassembler.

---

## Why `checksec` is the first reflex

Sections 19.1 through 19.8 covered protections one by one. In reality, a binary combines several — sometimes all. An analyst who opens Ghidra directly without characterizing the protections risks wasting time on false leads: attempting a GOT overwrite on a Full RELRO binary, searching for strings in a packed binary, setting software breakpoints on a binary that scans for `int3`.

`checksec` is the tool that answers in one second the question: *what am I dealing with?* It inspects an ELF binary's headers, segments, sections, and flags and produces a summary of active protections. It's the first tool to launch, before `file`, before `strings`, before everything else.

## Installation

`checksec` exists in two main forms:

**Shell script version (pwntools/checksec.sh)** — The historical Bash script, often available in repositories:

```bash
# Debian / Ubuntu
sudo apt install checksec

# Or directly from the repository
git clone https://github.com/slimm609/checksec.sh
```

**Python version (pwntools)** — Integrated in the `pwntools` framework, usable from command line or scripts:

```bash
pip install pwntools  
checksec ./binary  
# or from Python:
# from pwn import ELF
# elf = ELF('./binary')
# print(elf.checksec())
```

Both versions produce equivalent results. The `pwntools` version is often more up-to-date and integrates better into automation scripts.

## Anatomy of a `checksec` output

Let's run `checksec` on our two extreme chapter variants:

```bash
$ checksec --file=build/vuln_max_protection
[*] 'build/vuln_max_protection'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

$ checksec --file=build/vuln_min_protection
[*] 'build/vuln_min_protection'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
    FORTIFY:  Disabled
```

Each line corresponds to a protection analyzed in this chapter. Let's detail what `checksec` checks for each and how it reaches its conclusion.

### `Arch` line

The binary's architecture, determined from the ELF header (`e_machine` and `e_ident[EI_DATA]`). `amd64-64-little` means x86-64 in little-endian. This line isn't a "protection" but essential context information: it determines which instruction set to expect in disassembly and which calling conventions apply.

### `RELRO` line (Section 19.6)

`checksec` inspects two elements:

1. The `GNU_RELRO` segment's presence in program headers (`readelf -l`). If absent → `No RELRO`.  
2. The `BIND_NOW` flag's presence in the `.dynamic` section (`readelf -d`). If `GNU_RELRO` is present but not `BIND_NOW` → `Partial RELRO`. If both are present → `Full RELRO`.

| checksec output | GNU_RELRO segment | BIND_NOW flag | GOT writable |  
|---|---|---|---|  
| No RELRO | Absent | Absent | Yes (entire GOT) |  
| Partial RELRO | Present | Absent | Yes (`.got.plt` only) |  
| Full RELRO | Present | Present | No |

### `Stack` line (Section 19.5)

`checksec` looks for the `__stack_chk_fail` symbol in the dynamic symbol table (`.dynsym`). If this symbol is imported, the binary uses stack canaries. `checksec` doesn't distinguish between `-fstack-protector`, `-fstack-protector-strong`, and `-fstack-protector-all` — all three import `__stack_chk_fail`.

To determine the precise protection level, you must inspect the disassembly: if every function has an `fs:0x28` access, it's `-fstack-protector-all`. If only functions with buffers have one, it's `-fstack-protector` or `-strong`.

### `NX` line (Section 19.5)

`checksec` reads the `GNU_STACK` segment's flags in program headers:

- Flags `RW` (no `E`) → `NX enabled` — the stack is not executable.  
- Flags `RWE` (with `E`) → `NX disabled` — the stack is executable.  
- `GNU_STACK` segment absent → behavior depends on kernel (generally NX enabled on modern systems).

### `PIE` line (Section 19.5)

`checksec` checks the ELF type in the header (`e_type`):

- `ET_DYN` (type 3) → `PIE enabled` — the binary is position-independent.  
- `ET_EXEC` (type 2) → `No PIE` — the binary is loaded at a fixed address.

Technically, a shared library (`.so`) is also of type `ET_DYN`. `checksec` and `file` distinguish PIEs from `.so`s by the presence of a non-zero entry point (`e_entry`) and an interpreter (`PT_INTERP`).

### `FORTIFY` line (bonus)

`FORTIFY_SOURCE` is a GCC protection that replaces certain libc functions (`memcpy`, `sprintf`, `strcpy`…) with verified versions that check buffer sizes at runtime. `checksec` detects its presence by looking for `__*_chk` symbols (e.g., `__printf_chk`, `__memcpy_chk`) in dynamic imports.

`FORTIFY_SOURCE` wasn't covered in detail in this chapter because its RE impact is minimal — it adds calls to `_chk` variants instead of standard functions, which is transparent to the analyst. But its presence in `checksec` indicates a binary compiled with a high hardening level.

To enable it:

```bash
gcc -D_FORTIFY_SOURCE=2 -O2 -o binary source.c
```

The flag requires at least `-O1` to work (the compiler needs optimization to insert size checks).

## What `checksec` does NOT detect

`checksec` is a compiler and system protection inspection tool. It doesn't cover the application-level protections covered in this chapter:

| Protection | Detected by checksec? | How to detect |  
|---|---|---|  
| RELRO / Canary / NX / PIE | Yes | `checksec` |  
| Stripping | No | `file` (`stripped` / `not stripped`) |  
| Packing (UPX, etc.) | No | `strings`, entropy, `file`, missing sections |  
| CFF/BCF obfuscation | No | Function Graph in Ghidra, cyclomatic complexity |  
| LLVM obfuscation (Hikari) | No | `.comment`, dispatcher patterns, encrypted strings |  
| ptrace detection | No | `nm -D` (look for `ptrace`), `strings` (`/proc/self/status`) |  
| Timing checks | No | `nm -D` (look for `clock_gettime`, `gettimeofday`) |  
| int3 scanning / checksum | No | Static analysis in Ghidra |  
| Self-modifying code | No | `nm -D` (look for `mprotect`), CFG analysis |

This is why `checksec` is the *first* tool, not the *only* one. It's part of a broader triage workflow.

## The complete triage workflow integrating `checksec`

Here's the recommended systematic routine when facing an unknown binary. It integrates `checksec` into the Chapter 5 triage workflow (Section 5.7) while adding this chapter's anti-RE dimension.

### Step 1 — Basic identification (10 seconds)

```bash
file target_binary
```

What we're looking for: the format (ELF, PE, Mach-O), architecture (x86-64, ARM…), linkage (dynamic, static), stripping (`stripped` / `not stripped`), debug info presence (`with debug_info`). If `file` mentions missing section headers or unexpected static linkage, suspect packing.

### Step 2 — Compiler protections (5 seconds)

```bash
checksec --file=target_binary
```

What we're looking for: RELRO level, canary presence, NX, PIE, FORTIFY. This result conditions dynamic analysis strategies (fixed addresses or not, modifiable GOT or not, executable stack or not).

### Step 3 — Dynamic imports (10 seconds)

```bash
nm -D target_binary | grep -iE 'ptrace|proc|time|mprotect|signal|dlopen'
```

What we're looking for: suspicious functions in imports. Each import tells a story:

- `ptrace` → debugger detection (Section 19.7)  
- `clock_gettime`, `gettimeofday` → potential timing check (Section 19.7)  
- `mprotect` → self-modifying code or permission manipulation (Section 19.8)  
- `signal` → potential SIGTRAP handler for anti-debug (Section 19.7)  
- `dlopen`, `dlsym` → dynamic plugin or code loading (Chapter 22)

### Step 4 — Strings and signatures (15 seconds)

```bash
strings target_binary | head -50  
strings target_binary | grep -iE 'upx|pack|proc/self|TracerPid|password|flag|key'  
strings target_binary | wc -l  
```

What we're looking for: packer signatures (`UPX!`, `$Info:`), procfs paths (`/proc/self/status`), strings revealing business logic, and total string count (a sharp drop indicates packing or string encryption).

### Step 5 — Entropy and structure (15 seconds)

```bash
readelf -S target_binary | head -30  
binwalk -E target_binary  
```

What we're looking for: normal or absent ELF sections (packing), unusual section names (obfuscation), abnormally high entropy (compression or encryption).

### Step 6 — Summary: the protection sheet

After these five steps (about one minute total), the analyst has enough information to fill a protection sheet that will guide the entire rest of the analysis:

```
╔══════════════════════════════════════════════════╗
║         PROTECTION SHEET — target_binary         ║
╠══════════════════════════════════════════════════╣
║ Format     : ELF 64-bit x86-64, dynamic          ║
║ Stripping  : stripped (no symbols)               ║
║ Packing    : not detected                        ║
║ RELRO      : Full RELRO                          ║
║ Canary     : present                             ║
║ NX         : enabled                             ║
║ PIE        : enabled                             ║
║ FORTIFY    : enabled                             ║
║ Anti-debug : ptrace + /proc/self/status detected ║
║ Timing     : clock_gettime imported (suspect)    ║
║ SMC        : mprotect not imported (unlikely)    ║
║ Obfuscation: to confirm in Ghidra                ║
╠══════════════════════════════════════════════════╣
║ RECOMMENDED STRATEGY:                            ║
║ • Hardware breakpoints (anti int3 probable)      ║
║ • Frida to bypass ptrace + timing                ║
║ • Addresses in relative offsets (PIE)            ║
║ • GOT not modifiable (Full RELRO)                ║
║ • LD_PRELOAD viable for hooks                    ║
╚══════════════════════════════════════════════════╝
```

This sheet doesn't need to be formal — a notepad, a comment at the top of a Python script, or a text file in the working directory suffices. The important thing is having it laid out before starting in-depth analysis.

## Batch audit with `checksec`

When working with a binary directory (like our chapter variants), `checksec` can be run in batch. Our Makefile provides a dedicated target:

```bash
$ make checksec
```

This command runs `checksec` on each binary in the `build/` directory and displays results. It's the ideal opportunity to observe differences between variants and visually anchor the correspondence between compilation flags and `checksec` output.

You can also use `checksec` in process mode to inspect a running binary:

```bash
$ checksec --proc=12345
```

This variant inspects protections of the process with the given PID, reading `/proc/<pid>/maps` and ELF information. It's useful for verifying the effective protections of a binary that was unpacked in memory.

## Automation with `pwntools`

For repetitive analyses or automated pipelines, `pwntools` exposes `checksec` results in Python:

```python
from pwn import ELF, context

context.log_level = 'warn'  # reduce noise

import os, json

results = []  
for fname in os.listdir('build'):  
    path = os.path.join('build', fname)
    if not os.path.isfile(path):
        continue
    try:
        elf = ELF(path)
        results.append({
            'name': fname,
            'arch': elf.arch,
            'relro': elf.relro or 'No RELRO',
            'canary': elf.canary,
            'nx': elf.nx,
            'pie': elf.pie,
        })
    except Exception:
        pass

# Tabular display
print(f"{'Binary':<35} {'RELRO':<15} {'Canary':<8} {'NX':<8} {'PIE':<8}")  
print("=" * 74)  
for r in sorted(results, key=lambda x: x['name']):  
    print(f"{r['name']:<35} {r['relro']:<15} "
          f"{'Yes' if r['canary'] else 'No':<8} "
          f"{'Yes' if r['nx'] else 'No':<8} "
          f"{'Yes' if r['pie'] else 'No':<8}")
```

This script produces a summary table of all variants, directly usable in an analysis report or CI/CD pipeline (Chapter 35, Section 35.5).

## Connecting `checksec` to analysis strategy

The `checksec` result doesn't just say "which protections are active." It guides tool and technique choices for the entire rest of the analysis. Here are the key decisions:

### RELRO → hooking method choice

- `No RELRO` or `Partial RELRO` → GOT overwrite possible. Useful for quick instrumentation.  
- `Full RELRO` → GOT locked. Use `LD_PRELOAD` or Frida `Interceptor.attach` (inline hooking).

### Canary → expected behavior under GDB

- `Canary found` → Functions with buffers will have the `fs:0x28` pattern. Don't overwrite the canary zone during memory manipulations. If the program crashes with `*** stack smashing detected ***`, it's the canary, not an analysis bug.  
- `No canary found` → No constraints on stack manipulations.

### NX → possible injection techniques

- `NX enabled` → Impossible to execute injected code on stack or heap. Custom stubs must be placed in already-executable pages.  
- `NX disabled` → Code injection possible. Rare on a modern binary — its presence is suspicious (old binary, CTF challenge, or special compilation).

### PIE → address management

- `PIE enabled` → Reason in relative offsets. Calculate addresses as `base + offset`. Scripts must determine the base at runtime. GDB with GEF/pwndbg displays the base automatically.  
- `No PIE` → Stable absolute addresses (excluding ASLR on stack/heap/libs). Address breakpoints are reproducible between sessions.

### Full combination → overall difficulty level

The protection combination gives an indication of the binary's sophistication level and required analysis effort:

- **Everything disabled** (`No RELRO`, `No canary`, `NX disabled`, `No PIE`) → Pedagogical, old, or intentionally vulnerable binary. Direct analysis, all techniques work.  
- **Modern defaults** (`Partial RELRO`, `Canary`, `NX`, `PIE`) → Standard production binary. Normal analysis with modern tools, no particular difficulty.  
- **Everything enabled + stripped** (`Full RELRO`, `Canary`, `NX`, `PIE`, `FORTIFY`, stripped) → Hardened binary. Analysis works but requires up-to-date tools and scripts that calculate addresses dynamically.  
- **Everything enabled + application protections** (anti-debug, obfuscation, packing) → Actively protected binary. Complete triage (not just `checksec`) is essential to plan strategy before diving in.

---


⏭️ [Checkpoint: identify all protections of the `ch27-packed` binary, bypass them one by one](/19-anti-reversing/checkpoint.md)
