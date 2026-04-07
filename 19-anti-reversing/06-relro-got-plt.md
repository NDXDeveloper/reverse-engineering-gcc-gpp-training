🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.6 — RELRO: Partial vs Full and impact on GOT/PLT table

> 🎯 **Objective**: Understand the two RELRO levels (Partial and Full), their internal mechanism at the ELF segment and memory permission level, their impact on dynamic symbol resolution (lazy binding vs immediate binding), and the concrete consequences for the analyst — particularly regarding hooking and patching possibilities via the GOT.

---

## Refresher: PLT and GOT in dynamic resolution

Before addressing RELRO, a quick refresher on the PLT/GOT mechanism is needed. This topic was covered in detail in Chapter 2 (Section 2.9), but the key points are essential for understanding what RELRO protects.

When a dynamically linked ELF binary calls a shared library function (e.g., `printf`), the call doesn't go directly to libc. It passes through two intermediate structures:

- **PLT (Procedure Linkage Table)** — A table of small stubs in `.text` (executable code, read-only). Each stub contains an indirect jump to an address stored in the GOT.  
- **GOT (Global Offset Table)** — A table of pointers in `.got.plt` (data, initially read-write). Each entry contains the target function's actual memory address.

The flow of a `printf` call looks like this:

```
user code               PLT                     GOT                libc
      │                    │                       │                  │
      ├─ call printf@plt ─►│                       │                  │
      │                    ├── jmp [GOT+offset] ──►│                  │
      │                    │                       ├── 0x7f...4520 ──►│ printf()
      │                    │                       │                  │
```

### Lazy binding: the default behavior

By default, the GOT isn't filled at program loading. At the first call to `printf`, the corresponding GOT entry doesn't yet contain `printf`'s address in libc — it contains the address of a dynamic resolver routine (`_dl_runtime_resolve`). This resolver looks up `printf`'s real address, writes it into the GOT, then jumps to `printf`. Subsequent calls find the correct address directly in the GOT and no longer go through the resolver.

This is **lazy binding**: resolution is deferred to the first call. The advantage is faster startup (only actually called functions are resolved). The disadvantage is that the GOT must remain **writable** during the entire program execution, since the resolver must be able to write addresses as calls happen.

And it's precisely this writable GOT that constitutes an attack surface.

## The GOT overwrite attack

If an attacker has an arbitrary write primitive (via a buffer overflow, format string, use-after-free…), they can overwrite a GOT entry. For example, replace `printf`'s address in the GOT with `system`'s address. At the next call to `printf("ls")` in the code, `system("ls")` actually executes.

This is a classic, elegant, and powerful exploitation technique. RELRO was designed to neutralize it.

## Partial RELRO

### The mechanism

Partial RELRO is the default protection level on most modern Linux distributions. It's enabled by the linker flag `-z relro` (often passed automatically by GCC).

Partial RELRO applies two modifications to the binary:

**1. ELF section reorganization** — The linker reorders sections so the GOT (`.got`) and other critical dynamic linker data structures (`.dynamic`, `.init_array`, `.fini_array`) are placed **before** program data (`.data`, `.bss`) in the memory layout. The goal is that if a buffer overflow in `.bss` or `.data` overflows toward lower addresses, it won't reach the linker structures.

**2. Marking non-PLT sections as read-only** — After loading and initial relocation, the loader marks certain sections as read-only via `mprotect`. This includes the `.got` section (containing pointers to library global variables) and the `.dynamic` section headers. But — and this is the crucial point — the `.got.plt` section remains writable.

The `.got.plt` section contains the addresses of functions resolved by lazy binding. Partial RELRO leaves it writable because the dynamic resolver must be able to write addresses as calls are made.

### What Partial RELRO protects and doesn't protect

| Protected (read-only after loading) | Not protected (remains writable) |  
|---|---|  
| `.got` (global variables) | `.got.plt` (lazy-bound functions) |  
| `.dynamic` | |  
| `.init_array` / `.fini_array` | |  
| Relocated ELF headers | |

In summary: Partial RELRO prevents overwriting linker metadata but leaves the door open to classic GOT overwrite on function pointers.

### Observing Partial RELRO

```bash
$ readelf -l build/vuln_partial_relro | grep GNU_RELRO
  GNU_RELRO      0x002e00 0x0000000000403e00 0x0000000000403e00
                 0x000200 0x000200  R    0x1
```

The `GNU_RELRO` segment's presence in program headers confirms RELRO is active. This segment defines the address range the loader will mark read-only.

You can verify `.got.plt` is outside this range:

```bash
$ readelf -S build/vuln_partial_relro | grep -E '\.got|\.dynamic'
  [21] .dynamic          DYNAMIC   0000000000403e00  ...
  [22] .got              PROGBITS  0000000000403fe0  ...
  [23] .got.plt          PROGBITS  0000000000404000  ...
```

The `.dynamic` and `.got` sections are at `0x403e00` and `0x403fe0`, covered by the `GNU_RELRO` segment starting at `0x403e00`. But `.got.plt` at `0x404000` is beyond the protected range — it remains writable.

## Full RELRO

### The mechanism

Full RELRO is enabled by the linker flags `-z relro -z now`. The `-z now` flag is the key: it asks the loader to resolve **all** symbols immediately at loading, instead of using lazy binding.

The process at loading becomes:

1. The loader (`ld.so`) loads the binary and its libraries into memory.  
2. **All** imported functions are resolved immediately: the loader traverses the `.dynsym` table, looks up each symbol in the libraries, and writes the real address into the GOT.  
3. Once all resolutions are complete, the loader calls `mprotect` on the **entirety** of the GOT (including `.got.plt`) to mark it read-only.  
4. Program execution begins with a fully populated and fully locked GOT.

After this initialization, no writing to the GOT is possible. Any attempt (by the program, an attacker, or an analysis tool) causes a segmentation fault.

### What changes compared to Partial RELRO

| Aspect | Partial RELRO | Full RELRO |  
|---|---|---|  
| Symbol resolution | Lazy binding (on demand) | Immediate binding (at loading) |  
| `.got.plt` after init | Read-Write | Read-Only |  
| GOT overwrite possible | Yes | No |  
| Startup time | Faster (deferred resolution) | Slower (everything resolved at once) |  
| GNU_RELRO segment | Covers `.got`, `.dynamic` | Covers `.got`, `.got.plt`, `.dynamic` |

### Observing Full RELRO

```bash
$ readelf -l build/vuln_full_relro | grep GNU_RELRO
  GNU_RELRO      0x002de0 0x0000000000403de0 0x0000000000403de0
                 0x000220 0x000220  R    0x1
```

The range covered by `GNU_RELRO` is larger than in Partial RELRO — it now encompasses `.got.plt`.

You can also verify the `BIND_NOW` flag in the `.dynamic` section:

```bash
$ readelf -d build/vuln_full_relro | grep -E 'BIND_NOW|FLAGS'
 0x0000000000000018 (BIND_NOW)
 0x000000006ffffffb (FLAGS_1)            Flags: NOW
```

The presence of `BIND_NOW` or the `NOW` flag in `FLAGS_1` confirms immediate binding. This is the reliable Full RELRO indicator, as this flag triggers complete lockdown by the loader.

### Detection with `checksec`

```bash
$ checksec --file=build/vuln_no_relro
    RELRO:    No RELRO

$ checksec --file=build/vuln_partial_relro
    RELRO:    Partial RELRO

$ checksec --file=build/vuln_full_relro
    RELRO:    Full RELRO
```

The three levels are clearly distinguished by `checksec`.

## No RELRO

For reference, it's possible to compile without any RELRO:

```bash
gcc -Wl,-z,norelro -o vuln_no_relro vuln_demo.c
```

Without RELRO, all data sections — `.got`, `.got.plt`, `.dynamic`, `.init_array`, `.fini_array` — remain read-write during the entire execution. The `GNU_RELRO` segment is absent from program headers. This is the least secure configuration and should never be used in production.

For the analyst, a binary without RELRO is the easiest to manipulate dynamically: all tables are modifiable in memory.

## Impact on reverse engineering

RELRO has different implications depending on whether you're doing static analysis, dynamic analysis, or hooking.

### Static analysis: no impact

RELRO doesn't modify machine code or the program's logical structure. Instructions are the same, functions are the same, strings are the same. An analyst working exclusively in Ghidra will see no difference between a Partial RELRO and Full RELRO binary.

The only nuance is that Full RELRO eliminates the lazy binding mechanism, meaning PLT stubs are slightly simplified: they no longer contain the fallback code to the dynamic resolver. But this difference is minor in disassembly.

### Dynamic analysis: moderate impact

The main consequence of Full RELRO for the dynamic analyst is the inability to patch the GOT in memory. Several techniques are affected.

**GOT hooking impossible under Full RELRO** — A classic instrumentation technique consists of replacing a GOT entry with a custom function's address (a hook). For example, replacing `strcmp`'s GOT entry with a wrapper that logs arguments before calling the real `strcmp`. Under Full RELRO, writing to the GOT causes a crash.

**`LD_PRELOAD` still works** — The `LD_PRELOAD` mechanism (Chapter 22, Section 22.4) doesn't use the GOT for hooking. It acts at the symbol resolver level, injecting a priority library in the resolution order. `LD_PRELOAD` works identically regardless of RELRO level.

**Frida still works** — Frida (Chapter 13) uses several interception mechanisms that don't depend on GOT writing. The `Interceptor.attach` mode rewrites the first instructions of the target function (inline hooking), not the GOT. RELRO doesn't block Frida.

**GDB can bypass permissions** — GDB can write to read-only pages via `ptrace(PTRACE_POKEDATA)`, which bypasses the target process's memory protections. An analyst using GDB can therefore modify the GOT even under Full RELRO, though this isn't a common technique for pure RE.

### Summary for the analyst

| Technique | No RELRO | Partial RELRO | Full RELRO |  
|---|---|---|---|  
| GOT overwrite in memory | Possible | Possible (`.got.plt`) | Blocked (`SIGSEGV`) |  
| `LD_PRELOAD` hooking | Works | Works | Works |  
| Frida `Interceptor.attach` | Works | Works | Works |  
| GDB `set` on GOT | Works | Works | Possible via `ptrace` |  
| `.dynamic` writing | Possible | Blocked | Blocked |  
| `.init_array` writing | Possible | Blocked | Blocked |

## RELRO and the distribution ecosystem

For several years, major Linux distributions have converged on default settings that activate at least Partial RELRO:

- **Debian / Ubuntu** — Partial RELRO by default. Full RELRO enabled on sensitive packages (network daemons, setuid binaries).  
- **Fedora / RHEL** — Full RELRO by default (`-Wl,-z,relro,-z,now` in package compilation flags).  
- **Arch Linux** — Full RELRO by default via `makepkg.conf`.  
- **Hardened Gentoo** — Systematic Full RELRO.

Consequently, the majority of binaries you'll encounter "in the wild" will have at least Partial RELRO. Full RELRO binaries are increasingly common. Binaries without RELRO are rare and warrant attention — it's either an old binary or a deliberate choice (embedded binary, packed binary, CTF challenge).

## Connecting RELRO to other protections

RELRO completes the protection triad covered in the previous section:

- **Canary** prevents return address overwriting on the stack.  
- **NX** prevents injected code execution.  
- **ASLR + PIE** prevent address prediction.  
- **Full RELRO** prevents GOT modification.

Together, these protections close classic exploitation vectors one by one. For the RE analyst, the essential thing is knowing how to identify them quickly (a single `checksec` suffices) and understanding which ones affect the analysis strategy — without confusing them with anti-RE protections per se.

---


⏭️ [Debugger detection techniques (`ptrace`, timing checks, `/proc/self/status`)](/19-anti-reversing/07-debugger-detection.md)
