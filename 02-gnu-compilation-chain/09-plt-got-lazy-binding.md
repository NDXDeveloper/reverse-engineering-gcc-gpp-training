🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.9 — Dynamic symbol resolution: PLT/GOT in detail (lazy binding)

> 🎯 **Goal of this section**: Understand in detail the PLT/GOT mechanism that allows dynamically linked binaries to call functions from shared libraries, master how lazy binding works, and know how to leverage this knowledge in both static and dynamic analysis.

---

## The problem to solve

When our `hello.c` calls `strcmp`, the code of `strcmp` is not in the binary — it is in `libc.so.6`, a shared library loaded at an address unknown at compile time. Worse, with ASLR (section 2.8), this address changes at every execution.

The compiler therefore cannot insert a `call 0x7f8c3a2XXXXX` directly into the machine code — this address is not known. An **indirection** mechanism is needed: the code calls a fixed location (known at compile time), and that location contains — or will eventually contain — the real address of `strcmp` in memory.

This mechanism rests on two complementary structures:

- The **PLT** (*Procedure Linkage Table*): a series of small pieces of code (*stubs*) in the `.plt` section, in `R-X` zone (executable, non-writable).  
- The **GOT** (*Global Offset Table*): an array of pointers in the `.got.plt` section, in `RW-` zone (writable, non-executable).

## General architecture

Here is the complete diagram of the mechanism for a call to `strcmp`:

```
     Your code (.text)               PLT (.plt)                  GOT (.got.plt)
    ┌─────────────────┐         ┌──────────────────┐         ┌──────────────────┐
    │                 │         │                  │         │                  │
    │ call strcmp@plt ├────────►│ strcmp@plt:      │    ┌───►│ GOT[3]:          │
    │                 │         │   jmp *GOT[3]    ├────┘    │  (real address   │
    └─────────────────┘         │                  │         │   of strcmp in   │
                                │   push 0x0       │         │   libc.so.6)     │
                                │   jmp PLT[0]     │         │                  │
                                ├──────────────────┤         ├──────────────────┤
                                │ PLT[0]:          │         │ GOT[0]:          │
                                │   push GOT[1]    │         │  (address of     │
                                │   jmp  *GOT[2]   ├────────►│   link_map)      │
                                │                  │         │ GOT[1]:          │
                                └──────────────────┘         │  (link_map)      │
                                                             │ GOT[2]:          │
                                                             │  (address of     │
                                         ┌───────────────────┤   _dl_runtime_   │
                                         │                   │   resolve)       │
                                         ▼                   └──────────────────┘
                                ┌──────────────────┐
                                │ ld.so:           │
                                │ _dl_runtime_     │
                                │   resolve()      │
                                │ → looks up strcmp│
                                │ → writes address │
                                │   into GOT[3]    │
                                │ → jumps to strcmp│
                                └──────────────────┘
```

## The three reserved GOT entries

The first three entries of `.got.plt` have a special, reserved role, dedicated to the resolution mechanism:

| Entry | Content | Role |  
|---|---|---|  
| `GOT[0]` | Address of the `.dynamic` section | Lets the resolver find the symbol and relocation tables |  
| `GOT[1]` | Pointer to the `link_map` structure | Identifies the binary or `.so` for which resolution is requested |  
| `GOT[2]` | Address of `_dl_runtime_resolve` | Entry point of the resolver in `ld.so` |

These three entries are filled in by the `ld.so` loader at program startup, before any user instruction runs. Subsequent entries (`GOT[3]`, `GOT[4]`, etc.) each correspond to an imported function.

## The PLT stub in detail

Let's disassemble the PLT of our `hello` to see the real stubs:

```bash
objdump -d -j .plt --no-show-raw-insn hello
```

Typical output (AT&T syntax):

```asm
Disassembly of section .plt:

0000000000001020 <.plt>:                          ; ← PLT[0]: the resolver
    1020:   push   0x2fe2(%rip)                   ; push GOT[1] (link_map)
    1026:   jmp    *0x2fe4(%rip)                  ; jmp  GOT[2] (_dl_runtime_resolve)
    102c:   nopl   0x0(%rax)                      ; alignment padding

0000000000001030 <strcmp@plt>:                     ; ← stub for strcmp
    1030:   jmp    *0x2fd2(%rip)                  ; jmp *GOT[3]
    1036:   push   $0x0                            ; relocation index = 0
    103b:   jmp    1020 <.plt>                    ; jump to PLT[0]

0000000000001040 <printf@plt>:                     ; ← stub for printf
    1040:   jmp    *0x2fca(%rip)                  ; jmp *GOT[4]
    1046:   push   $0x1                            ; relocation index = 1
    104b:   jmp    1020 <.plt>                    ; jump to PLT[0]

0000000000001050 <puts@plt>:                       ; ← stub for puts
    1050:   jmp    *0x2fc2(%rip)                  ; jmp *GOT[5]
    1056:   push   $0x2                            ; relocation index = 2
    105b:   jmp    1020 <.plt>                    ; jump to PLT[0]
```

Each stub is exactly 16 bytes and follows the same three-instruction scheme:

1. **`jmp *GOT[n]`** — indirect jump through the GOT. If the address in `GOT[n]` is already the real address of the function, the jump reaches it directly. Otherwise, the address points to the following instruction (the `push`), which triggers resolution.  
2. **`push $index`** — pushes the relocation index of this symbol in the `.rela.plt` table. The resolver needs it to know which function to resolve.  
3. **`jmp PLT[0]`** — jumps to the common resolver stub.

## Lazy binding step by step

Let's trace a call to `strcmp` through both scenarios: the first call (resolution needed) and subsequent calls (resolution already done).

### First call — Lazy resolution

```
1. main() executes: call strcmp@plt
   → rip jumps to 0x1030 (strcmp stub in .plt)

2. The stub executes: jmp *GOT[3]
   → GOT[3] contains 0x1036 (address of the push instruction just below)
   → The jump "falls through" to the next instruction in the stub

3. The stub executes: push $0x0
   → Pushes strcmp's relocation index (0)

4. The stub executes: jmp PLT[0]
   → Jumps to the common resolver stub at 0x1020

5. PLT[0] executes: push GOT[1]
   → Pushes the link_map pointer (identifies the binary)

6. PLT[0] executes: jmp *GOT[2]
   → Jumps to _dl_runtime_resolve in ld.so

7. _dl_runtime_resolve:
   a. Reads the relocation index (0) from the stack
   b. Looks up entry 0 in .rela.plt → symbol "strcmp"
   c. Searches for "strcmp" in the symbol tables of loaded .so files
   d. Finds strcmp in libc.so.6 at address 0x7f8c3a2XXXXX
   e. WRITES this address into GOT[3]         ← key modification
   f. Jumps to strcmp (0x7f8c3a2XXXXX) to execute the initial call
```

The crucial point is step 7e: the resolver **writes** the real address of `strcmp` into the corresponding GOT entry. This write is permanent (for the lifetime of the process).

### Subsequent calls — Resolution already done

```
1. main() executes: call strcmp@plt
   → rip jumps to 0x1030 (strcmp stub in .plt)

2. The stub executes: jmp *GOT[3]
   → GOT[3] now contains 0x7f8c3a2XXXXX (real address of strcmp)
   → The jump reaches strcmp DIRECTLY in libc.so.6

   (the push and jmp PLT[0] instructions are never executed)
```

After the first resolution, the call costs only **one indirection**: the `jmp` through the GOT. The PLT stub acts as the initial trampoline but is short-circuited as soon as the GOT is filled in. That is the "lazy" of lazy binding: resolution is **deferred** to the time of the first actual call.

## Observing lazy binding in action

### With GDB

You can observe the GOT before and after the first call:

```bash
gdb -q ./hello
(gdb) break main
(gdb) run RE-101
# Stopped at the start of main

# Find the GOT address for strcmp
(gdb) got             # GEF/pwndbg command
# or manually:
(gdb) x/gx 0x555555557fd8    # address of GOT[3] (from readelf -r)
# 0x555555557fd8: 0x0000555555555036
#                 ^^^^^^^^^^^^^^^^ points to the push in the PLT stub
#                                  → strcmp NOT YET RESOLVED

# Continue until after the call to strcmp
(gdb) break *0x555555555166    # address just after call strcmp@plt
(gdb) continue

# Re-read the GOT
(gdb) x/gx 0x555555557fd8
# 0x555555557fd8: 0x00007ffff7e5a420
#                 ^^^^^^^^^^^^^^^^ real address of strcmp in libc
#                                  → strcmp RESOLVED

# Verify
(gdb) info symbol 0x00007ffff7e5a420
# strcmp in section .text of /lib/x86_64-linux-gnu/libc.so.6
```

### With `LD_DEBUG`

The loader can trace resolutions in real time:

```bash
LD_DEBUG=bindings ./hello RE-101 2>&1 | grep strcmp
# binding file ./hello [0] to /lib/.../libc.so.6 [0]:
#   normal symbol `strcmp' [GLIBC_2.2.5]
```

### With ELF relocations

The `.rela.plt` entries precisely describe the GOT locations to patch:

```bash
readelf -r hello | grep plt
```

| Offset | Type | Sym. Name |  
|---|---|---|  
| `0x3fd8` | `R_X86_64_JUMP_SLOT` | `strcmp@GLIBC_2.2.5` |  
| `0x3fe0` | `R_X86_64_JUMP_SLOT` | `printf@GLIBC_2.2.5` |  
| `0x3fe8` | `R_X86_64_JUMP_SLOT` | `puts@GLIBC_2.2.5` |

The `R_X86_64_JUMP_SLOT` type is the relocation type specific to the PLT/GOT mechanism: it indicates that the entry at the given offset in `.got.plt` must be filled in with the address of the indicated symbol. The `0x3fd8` offset corresponds to `GOT[3]` in our example.

## Immediate binding and Full RELRO

### Lazy binding's security flaw

Lazy binding has an inherent flaw: the GOT must remain **writable** throughout the lifetime of the process, because entries can be resolved at any moment (at the first call of each function). A writable GOT is a prime target for attackers:

**GOT overwrite**: if an attacker finds a vulnerability allowing arbitrary-address write (buffer overflow, format string, use-after-free…), they can overwrite a GOT entry to redirect a function call to an address of their choice. For example, overwriting the GOT entry of `puts` with the address of `system` — the next `puts("/bin/sh")` will execute `system("/bin/sh")`.

### Immediate binding (`LD_BIND_NOW`)

Immediate binding resolves **all** GOT entries at load time, before any user code runs. It is activated through the `LD_BIND_NOW=1` environment variable or through the `DT_BIND_NOW` flag in the binary's `.dynamic` section:

```bash
# At runtime
LD_BIND_NOW=1 ./hello RE-101

# At compile time (writes the flag into .dynamic)
gcc -Wl,-z,now -o hello_bindnow hello.c  
readelf -d hello_bindnow | grep BIND_NOW  
# 0x0000000000000018 (BIND_NOW)
```

Advantage: all resolutions are done at startup, eliminating the cost of the first hot resolution. Disadvantage: startup is slower if the binary imports many functions, because all of them are resolved even if some are never called.

### RELRO — Relocation Read-Only

RELRO is a protection mechanism that makes certain sections read-only after relocations. It exists in two levels:

**Partial RELRO** (default with GCC): after loading, the `.init_array`, `.fini_array`, `.dynamic`, and `.got` sections (excluding `.got.plt`) are made read-only via `mprotect`. The `.got.plt` section remains writable because lazy binding needs it.

```bash
gcc -o hello_partial hello.c    # Partial RELRO by default  
checksec --file=hello_partial  
# RELRO: Partial RELRO
```

**Full RELRO**: combines immediate binding (`-z now`) with RELRO protection (`-z relro`). All GOT entries are resolved at load time, then the **entire** `.got.plt` is made read-only with `mprotect`. Any write attempt into the GOT causes a `SIGSEGV`.

```bash
gcc -Wl,-z,relro,-z,now -o hello_fullrelro hello.c  
checksec --file=hello_fullrelro  
# RELRO: Full RELRO
```

Summary comparison:

| Aspect | No RELRO | Partial RELRO | Full RELRO |  
|---|---|---|---|  
| `.got` (data) | `RW-` | `R--` after init | `R--` after init |  
| `.got.plt` (functions) | `RW-` | `RW-` (lazy binding) | `R--` after resolution |  
| Lazy binding | ✅ Active | ✅ Active | ❌ Disabled |  
| GOT overwrite possible | ✅ Yes | ⚠️ Only `.got.plt` | ❌ No |  
| Startup cost | Minimal | Minimal | Higher |  
| GCC flag | `-Wl,-z,norelro` | (default) | `-Wl,-z,relro,-z,now` |

> 💡 **In RE**: `checksec` (Chapter 5, section 5.6) tells you the RELRO level immediately. A Full RELRO binary is more resistant to GOT-overwrite exploitation, which pushes the attacker toward other techniques (pure ROP, hooks on `__malloc_hook`/`__free_hook` — also removed in recent glibc, stack attacks, etc.). For the defensive reverse engineer, Full RELRO is a clue that the developer took security seriously.

## PLT/GOT and RE tools

### Ghidra

Ghidra natively recognizes and displays the PLT/GOT mechanism. In the *Symbol Tree* window, imported functions appear with the `@PLT` suffix (for example `strcmp@PLT`). The decompiler resolves the PLT/GOT indirections and directly displays `strcmp(input, "RE-101")` in the pseudo-code — the analyst does not need to understand the mechanism to read the result.

However, understanding PLT/GOT becomes essential when:
- You want to hook or patch a specific call (you need to know whether you are modifying the PLT stub, the GOT entry, or the `call` in `.text`).  
- You are analyzing an exploit that targets the GOT.  
- The decompiler fails to resolve an indirect call (obfuscation, C++ vtable, function pointers).

### GDB and extensions

GDB extensions (GEF, pwndbg) provide dedicated commands to inspect the GOT:

```bash
# GEF
gef> got
# Displays each GOT entry with the resolved address (or not)

# pwndbg
pwndbg> gotplt
# Similar, with coloring based on resolution state
```

These commands are valuable for checking whether a function has already been called (GOT resolved) or not (GOT still points to the PLT stub).

### Frida

Dynamic instrumentation with Frida (Chapter 13) can intercept calls at the PLT level by hooking the stubs, or at the GOT level by modifying the table entries. Modifying the GOT is a particularly clean hooking technique: it is enough to replace the address in the GOT with the address of your replacement function.

```javascript
// Frida: replace strcmp's GOT entry with a hook
var strcmpGotEntry = Module.findExportByName(null, "strcmp");  
Interceptor.attach(strcmpGotEntry, {  
    onEnter: function(args) {
        console.log("strcmp(" + args[0].readUtf8String() +
                    ", " + args[1].readUtf8String() + ")");
    }
});
```

## PLT/GOT for external global variables

The PLT/GOT mechanism is not only about functions. **Global variables imported** from shared libraries (for example `errno`, `stdin`, `stdout`, `stderr`) use the `.got` section (not `.got.plt`) with `R_X86_64_GLOB_DAT` type relocations:

```bash
readelf -r hello | grep GLOB_DAT
```

| Offset | Type | Sym. Name |  
|---|---|---|  
| `0x3fc0` | `R_X86_64_GLOB_DAT` | `__libc_start_main@GLIBC_2.34` |  
| `0x3fc8` | `R_X86_64_GLOB_DAT` | `__gmon_start__` |

Unlike functions (lazy binding), global variables are **always resolved immediately** at load time — there is no lazy binding for data. That is why `.got` (for data) is made read-only even with Partial RELRO, while `.got.plt` (for functions) is only read-only with Full RELRO.

## The secondary PLT: `.plt.got` and `.plt.sec`

On recent binaries (GCC 8+, Binutils 2.29+), you may encounter additional PLT sections:

**`.plt.got`**: contains stubs for functions resolved through `.got` (not `.got.plt`). These stubs are used when the linker knows a function will be resolved immediately (for example with Full RELRO) and therefore does not need the full lazy mechanism. The stub is simpler — a single `jmp *GOT[n]` without the `push` or the jump to PLT[0].

**`.plt.sec`**: introduced with processors supporting **IBT** (*Indirect Branch Tracking*, part of Intel CET technology). Each stub starts with an `endbr64` (*End Branch*) instruction that validates that the indirect jump is legitimate. The PLT/GOT mechanism remains the same, but the stubs contain this additional guard instruction.

```asm
; Classic PLT stub
strcmp@plt:
    jmp    *GOT[3](%rip)
    push   $0x0
    jmp    PLT[0]

; PLT stub with CET/IBT (.plt.sec)
strcmp@plt:
    endbr64                     ; ← IBT guard instruction
    jmp    *GOT[3](%rip)
    nop    ...                  ; padding
```

In RE, these variants do not fundamentally change the logic — the principle of indirection through the GOT remains the same. But it is useful to recognize them so as not to be disoriented by an unexpected `endbr64` instruction at the start of each PLT stub.

## Summary of the PLT/GOT mechanism

| Component | Section | Permissions | Role |  
|---|---|---|---|  
| Calling code | `.text` | `R-X` | Contains `call function@plt` |  
| PLT stub | `.plt` | `R-X` | Trampoline: `jmp *GOT[n]`, otherwise triggers resolution |  
| PLT[0] (resolver) | `.plt` | `R-X` | Entry point into `_dl_runtime_resolve` in `ld.so` |  
| GOT entry | `.got.plt` | `RW-` (or `R--` if Full RELRO) | Contains the resolved address (or the address of the `push` in the stub) |  
| Relocations | `.rela.plt` | Not loaded | Describes which symbol corresponds to which GOT entry |  
| Resolver | `ld.so` | `R-X` | `_dl_runtime_resolve`: looks up the symbol, writes the address into the GOT |

The flow for each imported function call:

```
.text                .plt               .got.plt            libc.so.6
  │                    │                    │                    │
  │  call strcmp@plt   │                    │                    │
  ├───────────────────►│  jmp *GOT[3]       │                    │
  │                    ├───────────────────►│                    │
  │                    │                    │──── if resolved ──►│ strcmp()
  │                    │                    │                    │
  │                    │◄── if not resolved │                    │
  │                    │  push index        │                    │
  │                    │  jmp PLT[0]        │                    │
  │                    │  → _dl_runtime_    │                    │
  │                    │    resolve()       │                    │
  │                    │    writes GOT[3] ──►│ (real address)    │
  │                    │    jmp strcmp ─────────────────────────►│ strcmp()
```

---

> 📖 **This chapter comes to an end.** You now have a complete understanding of the GNU compilation chain, from the source file to the process in memory with its dynamic calls resolved via PLT/GOT. These foundations are the bedrock on which all the RE techniques we will tackle starting from Chapter 3 rest.  
>  
> Before moving on, validate what you have learned with the checkpoint below.  
>  
> → 🎯 Chapter 2 Checkpoint: compile the same `hello.c` with `-O0 -g` then `-O2 -s`, compare sizes and sections with `readelf`.

⏭️ [🎯 Checkpoint: compile the same `hello.c` with `-O0 -g` then `-O2 -s`, compare sizes and sections with `readelf`](/02-gnu-compilation-chain/checkpoint.md)
