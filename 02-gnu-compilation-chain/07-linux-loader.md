🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.7 — The Linux Loader (`ld.so`): from ELF file to process in memory

> 🎯 **Goal of this section**: Understand the complete sequence that turns an ELF file on disk into a running process, identify the role of the dynamic loader `ld.so`, and know how to exploit this knowledge during the dynamic analysis of a binary.

---

## The problem: a file is not a process

When you type `./hello` in a terminal, far more happens than a simple "file execution". The ELF file on disk is a static description — an architect's blueprint. The process in memory is the actual construction: code loaded at precise addresses, memory zones allocated with specific permissions, shared libraries mapped, pointer tables filled in, and a program counter (`rip`) positioned on the first instruction to execute.

Transforming the blueprint into the construction is ensured by two complementary actors: the **Linux kernel** and the **dynamic loader** (`ld.so`, also called *dynamic linker* or *ELF interpreter*).

## Overview: from `./hello` to the execution of `main()`

Here is the complete sequence, which we will detail step by step:

```
Terminal: ./hello RE-101
        │
        ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │  1. The shell calls execve("./hello", ["hello","RE-101"], env)     │
   └──────────────────────────┬─────────────────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │  2. The Linux KERNEL:                                              │
   │     a. Opens the file, reads the ELF header                        │
   │     b. Reads the program header table (segments)                   │
   │     c. Finds the .interp section → "/lib64/ld-linux-x86-64.so.2"   │
   │     d. Maps the binary's LOAD segments into memory                 │
   │     e. Maps the ld.so loader into memory                           │
   │     f. Prepares the initial stack (argc, argv, envp, auxv)         │
   │     g. Transfers control to ld.so (not to your code)               │
   └──────────────────────────┬─────────────────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │  3. THE ld.so LOADER:                                              │
   │     a. Reads the binary's .dynamic section                         │
   │     b. Identifies required libraries (NEEDED)                      │
   │     c. Searches for and maps each .so (libc.so.6, etc.)            │
   │     d. Recursively resolves the .so dependencies                   │
   │     e. Performs relocations (fills the GOT, etc.)                  │
   │     f. Runs initialization functions (.init, .init_array)          │
   │     g. Transfers control to the binary's _start                    │
   └──────────────────────────┬─────────────────────────────────────────┘
                              │
                              ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │  4. THE CRT CODE (_start):                                         │
   │     a. Calls __libc_start_main(main, argc, argv, ...)              │
   │     b. __libc_start_main initializes the libc                      │
   │     c. Calls the constructors (.init_array)                        │
   │     d. Calls main(argc, argv)                                      │
   └──────────────────────────┬─────────────────────────────────────────┘
                              │
                              ▼
                    Your main() function finally runs
```

## Step 1 — The `execve` system call

When the shell interprets `./hello RE-101`, it performs a `fork()` to create a child process, then calls `execve()` in that child:

```c
execve("./hello", ["hello", "RE-101"], environ);
```

The `execve` system call is the entry point into the kernel. It entirely replaces the memory image of the current process (the child shell) with the new program. After a successful `execve`, there is no return — the shell's code no longer exists in this process.

> 💡 **In RE**: The `execve` call is interceptable with `strace` (Chapter 5) and with GDB catchpoints (`catch exec` — Chapter 11, section 11.6). If a binary launches another program (dropper, malware loader), you will see the `execve` call in the trace. The arguments passed (the `argv` array) are visible in clear.

## Step 2 — The kernel prepares the ground

### Reading and validating the ELF file

The kernel opens the file, reads the first bytes, and identifies the format thanks to the magic number `\x7fELF`. It then parses the *ELF header* to determine the architecture (x86-64), the type (`ET_EXEC` or `ET_DYN`), and locate the **program header table** — the segment view.

If the magic number does not match a recognized format (ELF, `#!` script, etc.), `execve` fails with `ENOEXEC` (*Exec format error*).

### Reading the program header table

The kernel walks through the program header table looking for two critical entry types:

**The `PT_LOAD` segments**: these are the zones of the file that must be mapped into memory. A typical binary has two:

| Segment | Permissions | Typical content |  
|---|---|---|  
| `LOAD` #1 | `R-X` (read + execute) | `.text`, `.plt`, `.rodata`, `.init`, `.fini`, `.eh_frame` |  
| `LOAD` #2 | `RW-` (read + write) | `.data`, `.bss`, `.got`, `.got.plt`, `.dynamic` |

**The `PT_INTERP` segment**: it contains the path of the dynamic loader. The kernel reads the string (typically `/lib64/ld-linux-x86-64.so.2`) and knows it will also have to load that program.

```bash
# See the program header table
readelf -l hello
```

Simplified output:

```
Program Headers:
  Type           Offset   VirtAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0002d8 0x0002d8 R   0x8
  INTERP         0x000318 0x0000000000000318 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000000000 0x000628 0x000628 R   0x1000
  LOAD           0x001000 0x0000000000001000 0x0001d5 0x0001d5 R E 0x1000
  LOAD           0x002000 0x0000000000002000 0x000150 0x000150 R   0x1000
  LOAD           0x002db8 0x0000000000003db8 0x000260 0x000268 RW  0x1000
  DYNAMIC        0x002dc8 0x0000000000003dc8 0x0001f0 0x0001f0 RW  0x8
  ...
```

Each `LOAD` segment has a **file offset** (`Offset`), a **virtual address** (`VirtAddr`), a **file size** (`FileSiz`), a **memory size** (`MemSiz`), and **permissions** (`Flg`). When `MemSiz` is greater than `FileSiz`, the difference is filled with zeros — that is how the `.bss` section (type `NOBITS` in the file) is allocated in memory.

### Memory mapping (`mmap`)

For each `LOAD` segment, the kernel uses the `mmap` system call to project the corresponding portion of the file into the process's address space. The mapping's permissions (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`) correspond to the segment's flags.

For a PIE (`ET_DYN`) binary, the kernel chooses a **random** base address (ASLR — section 2.8) and adds this base to all virtual addresses of the segments. For a non-PIE (`ET_EXEC`) binary, addresses are fixed (typically base `0x400000` on x86-64).

### Preparing the initial stack

The kernel allocates the process's stack (at the top of the address space, growing downwards) and deposits a well-defined structure there that `_start` and `__libc_start_main` expect to find:

```
        Top of stack (high addresses)
    ┌──────────────────────────────┐
    │  Environment strings         │ ← "PATH=/usr/bin:...", "HOME=/home/user", ...
    │  Argument strings            │ ← "./hello\0", "RE-101\0"
    ├──────────────────────────────┤
    │  Auxiliary Vector (auxv)     │ ← Key-value pairs for the loader
    │    AT_PHDR   = 0x...         │    (address of the program header table)
    │    AT_PHNUM  = 13            │    (number of entries)
    │    AT_ENTRY  = 0x...         │    (entry point _start)
    │    AT_BASE   = 0x...         │    (base address of ld.so)
    │    AT_RANDOM = 0x...         │    (16 random bytes for the canary)
    │    AT_NULL   = 0             │    (end of vector)
    ├──────────────────────────────┤
    │  envp[n] = NULL              │
    │  envp[1] = ptr → "HOME=..."  │
    │  envp[0] = ptr → "PATH=..."  │
    ├──────────────────────────────┤
    │  argv[2] = NULL              │
    │  argv[1] = ptr → "RE-101"    │
    │  argv[0] = ptr → "./hello"   │
    ├──────────────────────────────┤
    │  argc = 2                    │ ← rsp points here at startup
    └──────────────────────────────┘
        Bottom of stack (low addresses, stack grows toward here)
```

The **Auxiliary Vector** (`auxv`) is a kernel → loader communication mechanism. It contains information the kernel transmits to the loader and libc: the address of the program header table in memory, the program's entry point, the base address of the loader itself, a pointer to 16 random bytes (used by libc to initialize the stack canary), the memory page size, etc.

```bash
# See the auxiliary vector of a running process
LD_SHOW_AUXV=1 ./hello RE-101
```

> 💡 **In RE**: The Auxiliary Vector is exploitable in dynamic analysis. The `AT_RANDOM` value serves as a seed for the stack canary — if you can read it (for example via `/proc/<pid>/auxv` or via GDB), you know the canary's value without needing to leak it. The `AT_BASE` value reveals the load address of `ld.so`, which is useful for bypassing ASLR in some exploitation scenarios.

### Transfer to the loader

The kernel does **not** transfer control to the program's entry point (`_start`). It positions `rip` on the entry point of the **loader** (`ld.so`). It is the loader that will take over.

For a statically linked binary (`-static`), there is no `PT_INTERP` segment and therefore no loader. The kernel transfers control directly to `_start`.

## Step 3 — The dynamic loader (`ld.so`)

### Identity and location

The dynamic loader is itself a shared ELF binary, installed on the system. Its full name depends on the architecture and distribution:

| Architecture | Typical path |  
|---|---|  
| x86-64 | `/lib64/ld-linux-x86-64.so.2` |  
| x86 (32 bits) | `/lib/ld-linux.so.2` |  
| ARM64 (AArch64) | `/lib/ld-linux-aarch64.so.1` |

This path is the one recorded in the binary's `.interp` section. The loader is a special program: it is designed to work without dynamic dependencies (it cannot load itself). All of its code is statically resolved.

### Dependency resolution

The loader reads the binary's `.dynamic` section and walks through the `DT_NEEDED` entries to identify required shared libraries:

```bash
readelf -d hello | grep NEEDED
#  0x0000000000000001 (NEEDED)   Shared library: [libc.so.6]
```

For each required library, the loader must find it on the filesystem. The search order is:

1. **`DT_RPATH`** (deprecated) or **`DT_RUNPATH`**: paths hardcoded in the binary by the linker (`-rpath` option).  
2. **`LD_LIBRARY_PATH`**: environment variable (ignored for setuid/setgid binaries for security reasons).  
3. **`ldconfig` cache**: the `/etc/ld.so.cache` file, a pre-computed index of libraries available in the directories configured in `/etc/ld.so.conf`.  
4. **Default paths**: `/lib`, `/usr/lib` (and their 64-bit variants).

Once a `.so` is found, the loader maps it into memory with `mmap` (exactly as the kernel did for the main binary) and parses its own `.dynamic` section to find its dependencies — the process is **recursive**. The set of loaded libraries forms a dependency graph.

```bash
# See the search order and libraries found
LD_DEBUG=libs ./hello RE-101

# List resolved dependencies
ldd hello
#   linux-vdso.so.1 (0x00007ffd3abfe000)
#   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8c3a200000)
#   /lib64/ld-linux-x86-64.so.2 (0x00007f8c3a5f0000)
```

> ⚠️ **Security**: `ldd` may execute the binary to resolve dependencies. On an untrusted binary, prefer `readelf -d binary | grep NEEDED` or `objdump -p binary | grep NEEDED`, which are purely static analyses.

### Relocations

After mapping all the libraries, the loader must **fix up the addresses** in the code and data of the binary and its dependencies. This is the relocation phase.

Relocations are stored in the `.rela.dyn` sections (for data, typically GOT entries) and `.rela.plt` (for function calls through the PLT). For each relocation entry, the loader computes the real address of the referenced symbol and writes it at the indicated location.

Two relocation modes exist for PLT functions, controlled by the `LD_BIND_NOW` environment variable or the `DT_BIND_NOW` flag in `.dynamic`:

- **Lazy binding** (default): `.got.plt` entries are not resolved immediately. Each entry initially points to the PLT stub, which calls the loader to resolve the symbol on the first call. This mechanism is detailed in section 2.9.  
- **Immediate binding** (`LD_BIND_NOW=1` or Full RELRO): all GOT entries are resolved at load time, before any user code is executed. Slower at startup, but safer (the GOT can be made read-only — section 2.9 and Chapter 19).

### Initialization

Once relocations have been performed, the loader executes the **initialization functions** in order:

1. The `.init` and `.init_array` functions of each shared library, in dependency order (deepest libraries first).  
2. The `.init` and `.init_array` functions of the main binary.

In C++, this is when the constructors of global and static variables are executed. In C, functions marked `__attribute__((constructor))` are called here.

### Transfer to the program

The loader finally transfers control to the binary's **entry point**, indicated by the `e_entry` field of the ELF header. This entry point is `_start`, the first function of the CRT (C Runtime).

## Step 4 — CRT code and the path to `main()`

The `_start` entry point is not your code — it is code provided by the toolchain (`crt1.o`, `crti.o`, `crtn.o` files automatically linked by GCC). Its task is to prepare the call to `main()`:

```asm
; Simplified _start (crt1.o, x86-64)
_start:
    xor     ebp, ebp              ; Mark the bottom of the stack (rbp = 0)
    mov     rdi, [rsp]            ; argc
    lea     rsi, [rsp+8]         ; argv
    call    __libc_start_main     ; Initialize libc and call main
    hlt                           ; Should never be reached
```

The `__libc_start_main` function (defined in glibc) is the true orchestrator:

1. Records pointers to the `.init`, `.fini`, `__libc_csu_init`, and `__libc_csu_fini` functions.  
2. Initializes the libc's internal structures (memory allocator, threads, signals, standard I/O streams).  
3. Calls the remaining initialization functions (that would not have been called by the loader).  
4. Calls **`main(argc, argv, envp)`**.  
5. On return from `main()`, calls `exit()` with the return value, which triggers the destructors (`.fini_array`, `.fini`), flushes the I/O buffers, and terminates the process.

> 💡 **In RE**: When you open a binary in Ghidra or IDA, the displayed entry point is `_start`, not `main`. To quickly find `main` in a stripped binary, look for the first argument passed to `__libc_start_main` — it is the address of `main`. In x86-64, this argument is in `rdi`:  
>  
> ```asm  
> lea    rdi, [rip + 0x1234]    ; ← Address of main!  
> call   __libc_start_main  
> ```  
>  
> This technique works on nearly every ELF binary dynamically linked with glibc.

## The process memory space after loading

Once all the steps are finished, the process's virtual address space looks like this:

```
    High addresses (0x7fff...)
    ┌──────────────────────────────────────┐
    │            STACK                     │ ← Grows downward
    │  argc, argv, envp, auxv              │    rsp points here
    │  Local variables, call frames        │
    │            ↓ ↓ ↓                     │
    ├──────────────────────────────────────┤
    │                                      │
    │        (unmapped space)              │
    │                                      │
    ├──────────────────────────────────────┤
    │            ↑ ↑ ↑                     │
    │            HEAP                      │ ← Grows upward
    │  malloc(), new, brk/mmap             │    program break here
    ├──────────────────────────────────────┤
    │                                      │
    │   Shared libraries (.so)             │
    │   libc.so.6      (R-X / RW-)         │ ← Mapped by ld.so
    │   ld-linux-x86-64.so.2               │
    │   linux-vdso.so.1                    │
    │                                      │
    ├──────────────────────────────────────┤
    │                                      │
    │   Main binary                        │
    │   LOAD segment R-X (.text, .rodata)  │ ← Mapped by the kernel
    │   LOAD segment RW- (.data, .bss,     │
    │                      .got, .got.plt) │
    │                                      │
    ├──────────────────────────────────────┤
    │   [vdso] / [vvar]                    │ ← Special kernel page
    └──────────────────────────────────────┘
    Low addresses (0x0000...)
    (zero page not mapped — access = SIGSEGV)
```

Each zone is a **memory mapping** visible in `/proc/<pid>/maps`:

```bash
# See the memory map of a process
cat /proc/$(pidof hello)/maps
```

Typical output:

```
55a3c4000000-55a3c4001000 r--p 00000000 08:01 12345  /home/user/hello
55a3c4001000-55a3c4002000 r-xp 00001000 08:01 12345  /home/user/hello
55a3c4002000-55a3c4003000 r--p 00002000 08:01 12345  /home/user/hello
55a3c4003000-55a3c4005000 rw-p 00002db8 08:01 12345  /home/user/hello
7f8c3a200000-7f8c3a228000 r--p 00000000 08:01 67890  /lib/.../libc.so.6
7f8c3a228000-7f8c3a3bd000 r-xp 00028000 08:01 67890  /lib/.../libc.so.6
...
7ffd3ab80000-7ffd3aba1000 rw-p 00000000 00:00 0      [stack]
7ffd3abfe000-7ffd3ac00000 r-xp 00000000 00:00 0      [vdso]
```

Each line shows the address range, permissions (`r`ead / `w`rite / e`x`ecute / `p`rivate), offset in the file, device, inode, and name of the mapped file. Entries without a filename are anonymous mappings (stack, heap).

> 💡 **In RE**: The `/proc/<pid>/maps` map is a fundamental tool in dynamic analysis. It tells you exactly where each component is loaded in memory, what its permissions are, and which file it corresponds to. In GDB, the `info proc mappings` command (or `vmmap` in GEF/pwndbg) displays the same information. Knowing how to read this map is a prerequisite for Chapter 11 (GDB) and Chapter 12 (GDB extensions).

## Controlling and observing the loader

The `ld.so` loader offers several control and diagnostic mechanisms via environment variables:

### Diagnostic variables

| Variable | Effect |  
|---|---|  
| `LD_DEBUG=all` | Enables loader verbose mode — displays each step of resolution |  
| `LD_DEBUG=libs` | Displays only the search for libraries |  
| `LD_DEBUG=bindings` | Displays each symbol → address binding |  
| `LD_DEBUG=reloc` | Displays the relocations performed |  
| `LD_DEBUG=symbols` | Displays the search for each symbol |  
| `LD_DEBUG=versions` | Displays symbol versioning |  
| `LD_DEBUG_OUTPUT=file` | Redirects debug output to a file |

```bash
# Observe symbols resolved by the loader
LD_DEBUG=bindings ./hello RE-101 2>&1 | grep strcmp
# binding file ./hello [0] to /lib/.../libc.so.6 [0]: normal symbol `strcmp'
```

### Control variables

| Variable | Effect |  
|---|---|  
| `LD_LIBRARY_PATH=/path` | Adds a search directory for `.so` files |  
| `LD_PRELOAD=libhook.so` | Forces loading of a `.so` before all others |  
| `LD_BIND_NOW=1` | Disables lazy binding (resolves everything at load time) |  
| `LD_SHOW_AUXV=1` | Displays the Auxiliary Vector |  
| `LD_TRACE_LOADED_OBJECTS=1` | Simulates `ldd` (lists `.so` files without executing the program) |

### `LD_PRELOAD` — The reverse engineer's tool

The `LD_PRELOAD` variable is particularly powerful for RE. It forces the loader to load a shared library **first**, before all others. Symbols defined in this library then take priority over those of normal libraries (including libc).

This makes it possible to **replace any library function** without modifying the binary:

```c
// hook_strcmp.c — intercepts strcmp to display arguments
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

int strcmp(const char *s1, const char *s2) {
    // Display the arguments
    fprintf(stderr, "[HOOK] strcmp(\"%s\", \"%s\")\n", s1, s2);

    // Call the real strcmp
    int (*real_strcmp)(const char *, const char *) = dlsym(RTLD_NEXT, "strcmp");
    return real_strcmp(s1, s2);
}
```

```bash
gcc -shared -fPIC -o hook_strcmp.so hook_strcmp.c -ldl  
LD_PRELOAD=./hook_strcmp.so ./hello test123  
# [HOOK] strcmp("test123", "RE-101")
# Access denied.
```

In a single command, you have intercepted the `strcmp` call and revealed the expected password — without disassembling anything. We will dig deeper into this technique in Chapter 22, section 22.4.

> ⚠️ **Limitation**: `LD_PRELOAD` is ignored for **setuid/setgid** binaries (for obvious security reasons). It also does not work on statically linked binaries (no dynamic loader). And it can only intercept calls going through PLT/GOT — not direct calls within the same binary.

## Special case: statically linked binaries

A binary compiled with `-static` has no `.interp` section, no `PT_INTERP` segment, and no `.dynamic` section. The kernel notices the absence of a loader and transfers control directly to `_start`. There is no dynamic resolution, no PLT/GOT, no shared libraries — all required code is inside the binary.

```bash
gcc -static -o hello_static hello.c  
readelf -l hello_static | grep INTERP  
# (no output)
ldd hello_static
# not a dynamic executable
```

For the reverse engineer, the absence of a loader simplifies startup (no dynamic resolution to understand) but complicates the overall analysis: thousands of libc functions are directly inside the binary, mixed with the application code, and without the handy names the PLT provides in a dynamically linked binary.

## The vDSO — The kernel's invisible optimization

In the memory map, you may have noticed the `[vdso]` (*virtual Dynamic Shared Object*) entry. It is a small shared library **injected by the kernel** into every process's address space, without any file being mapped from disk.

The vDSO contains optimized implementations of some frequent system calls (`gettimeofday`, `clock_gettime`, `getcpu`) that can be run in userland without the cost of a transition into the kernel (no `syscall`). It is a transparent performance optimization.

In RE, the vDSO explains why some calls to `gettimeofday()` in an `strace` do not appear as a `syscall` — they are resolved directly in userland via the vDSO.

---

> 📖 **The loader has loaded our binary into memory, but the addresses chosen are not fixed.** ASLR deliberately scrambles the maps between executions. In the next section, we will see how segment mapping, ASLR, and virtual addresses interact — and what this changes for the reverse engineer.  
>  
> → 2.8 — Segment mapping, ASLR, and virtual addresses: why addresses move

⏭️ [Segment mapping, ASLR, and virtual addresses: why addresses move](/02-gnu-compilation-chain/08-segments-aslr.md)
