🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.8 — Difference between library call (`call printf@plt`) and direct syscall (`syscall`)

> 🎯 **Goal of this section**: understand the two mechanisms by which a program interacts with the outside world (libraries and kernel), know how to distinguish them in disassembly, and know the implications of each for reverse engineering.

---

## Two doors to the outside

A program compiled by GCC does almost nothing on its own. To display text, read a file, allocate memory, or communicate over the network, it must call external code. Two distinct mechanisms exist for this:

1. **Library call** (`call printf@plt`) — the program calls a function from libc (or from another shared `.so` library), which itself eventually invokes the kernel if necessary.  
2. **Direct system call** (`syscall`) — the program switches directly from user mode to kernel mode, without going through libc.

```
User program
│
├── call printf@plt ──→ libc (printf) ──→ libc (write) ──→ syscall ──→ Kernel
│                        userland code    wrapper             transition
│
└── syscall ──────────────────────────────────────────────────→ Kernel
     direct transition (no libc)
```

The vast majority of code compiled by GCC uses the first mechanism. The second appears in low-level code (inline assembly, shellcode, statically linked binaries, minimalist programs, certain malware).

---

## Library call via the PLT

### What you see in the disassembly

```asm
lea     rdi, [rip+0x2e5a]        ; argument: address of the string  
call    puts@plt                   ; call via the PLT  
```

The `@plt` suffix indicates that the call goes through the **PLT** (*Procedure Linkage Table*), a redirection mechanism that allows the program to resolve the real address of the function in the shared library at execution time.

### The PLT/GOT mechanism in brief

Chapter 2 (section 2.9) covers PLT/GOT in detail. Here is the summary needed for this section:

**PLT** (*Procedure Linkage Table*) — `.plt` section: a table of small trampolines, one per external function. Each entry does an indirect jump through the GOT.

**GOT** (*Global Offset Table*) — `.got.plt` section: a table of pointers. Initially, each pointer points to the dynamic linker's resolution code. After the first call (*lazy binding*), it is replaced with the real address of the function in libc.

The flow of a `call puts@plt`:

```
1. call puts@plt
       │
       ▼
2. PLT stub: jmp [GOT entry for puts]
       │
       ├── First call: GOT points to the resolver
       │         │
       │         ▼
       │   3. Dynamic resolver (ld.so): looks up puts in libc
       │         │
       │         ▼
       │   4. Writes the real address of puts into the GOT
       │         │
       │         ▼
       │   5. Jumps to puts (real address in libc)
       │
       └── Subsequent calls: GOT points directly to puts
                 │
                 ▼
           puts runs (no resolution, a single indirect jmp)
```

### What the PLT stub looks like in the disassembly

If you examine the code at address `puts@plt`, you typically see:

```asm
; .plt section
puts@plt:
    jmp     qword [rip+0x200a12]    ; indirect jump through the GOT
    push    0x0                      ; index in the relocation table
    jmp     0x401020                 ; jump to the common PLT resolver
```

The last two instructions (`push` + `jmp` to the resolver) are only executed on the **first call** — afterwards, the `jmp` through the GOT goes directly to the real function.

### Calling convention for library functions

Functions called via the PLT follow exactly the standard **System V AMD64** convention (sections 3.5–3.6). Nothing changes from the caller's viewpoint:

- Arguments in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`.  
- Return in `rax` (or `xmm0` for floats).  
- Caller-saved registers potentially clobbered.

This is the key point: **from the RE point of view, a `call puts@plt` reads exactly like any other `call`**. Arguments are prepared in the same registers, the return value is in the same place.

### Which functions go through the PLT?

All functions coming from **shared libraries** (`.so`) that are dynamically linked:

- libc: `printf`, `malloc`, `strcmp`, `open`, `read`, `write`…  
- libm: `sin`, `cos`, `sqrt`…  
- libpthread: `pthread_create`, `pthread_mutex_lock`…  
- OpenSSL, libcrypto, zlib, and any other dynamic library.

Functions that are **internal** to the binary (defined in the program's source code) do **not** go through the PLT — they are called directly by address:

```asm
call    0x401250              ; direct call to an internal function  
call    my_internal_func      ; same, with symbol if available  
```

> 💡 **For RE**: the distinction `call func@plt` (external) vs `call 0x4xxxxx` (internal) is a first triage filter. PLT calls tell you the program's external dependencies. Direct calls show you the program's own logic. Focus on internal functions — they contain the logic you need to reverse.

---

## Direct system call: the `syscall` instruction

### What you see in the disassembly

```asm
mov     eax, 1              ; syscall number: sys_write (1)  
mov     edi, 1              ; 1st argument: fd = 1 (stdout)  
lea     rsi, [rip+0x1234]  ; 2nd argument: buffer  
mov     edx, 14             ; 3rd argument: count = 14  
syscall                      ; transition to the kernel  
```

The `syscall` instruction is a special hardware instruction that causes an **immediate transition from user mode to kernel mode**. The processor changes privilege level, jumps to the kernel's entry point (`entry_SYSCALL_64` under Linux), and the kernel executes the requested service.

### Calling convention for Linux x86-64 syscalls

The syscall convention is **different** from the System V AMD64 convention for normal functions:

| Aspect | Function convention (System V) | Syscall convention (Linux x86-64) |  
|---|---|---|  
| Call number | N/A (function address) | `rax` |  
| 1st argument | `rdi` | `rdi` |  
| 2nd argument | `rsi` | `rsi` |  
| 3rd argument | `rdx` | `rdx` |  
| 4th argument | `rcx` | **`r10`** (not `rcx`!) |  
| 5th argument | `r8` | `r8` |  
| 6th argument | `r9` | `r9` |  
| Return value | `rax` | `rax` |  
| Clobbered registers | standard caller-saved | **`rcx`** and **`r11`** (clobbered by the CPU) |

Two major differences:

1. **The 4th argument uses `r10` instead of `rcx`**. The reason is hardware: the `syscall` instruction automatically clobbers `rcx` (it saves `rip` there for the return) and `r11` (it saves `RFLAGS` there). The kernel therefore cannot retrieve the 4th argument from `rcx`.

2. **The syscall number is in `rax`**, not in a dedicated register. Each kernel service has a fixed number (defined in the Linux headers).

### The most common syscalls

Here are the numbers you will most often encounter on x86-64 Linux:

| Number (`rax`) | Name | Signature | Role |  
|---|---|---|---|  
| 0 | `sys_read` | `read(fd, buf, count)` | Read from a descriptor |  
| 1 | `sys_write` | `write(fd, buf, count)` | Write to a descriptor |  
| 2 | `sys_open` | `open(path, flags, mode)` | Open a file |  
| 3 | `sys_close` | `close(fd)` | Close a descriptor |  
| 9 | `sys_mmap` | `mmap(addr, len, prot, flags, fd, off)` | Map memory |  
| 10 | `sys_mprotect` | `mprotect(addr, len, prot)` | Change memory permissions |  
| 12 | `sys_brk` | `brk(addr)` | Extend the data segment |  
| 21 | `sys_access` | `access(path, mode)` | Check file permissions |  
| 39 | `sys_getpid` | `getpid()` | Get the process PID |  
| 57 | `sys_fork` | `fork()` | Create a child process |  
| 59 | `sys_execve` | `execve(path, argv, envp)` | Execute a program |  
| 60 | `sys_exit` | `exit(status)` | Terminate the process |  
| 62 | `sys_kill` | `kill(pid, sig)` | Send a signal |  
| 101 | `sys_ptrace` | `ptrace(request, pid, ...)` | Trace a process (anti-debug!) |  
| 231 | `sys_exit_group` | `exit_group(status)` | Terminate all threads |  
| 257 | `sys_openat` | `openat(dirfd, path, flags, mode)` | Open relative to a directory |  
| 318 | `sys_getrandom` | `getrandom(buf, count, flags)` | Get random bytes |

> 💡 **For RE**: the number in `rax` just before `syscall` immediately identifies the requested service. Keep a syscall-number reference handy — the full table is available in `/usr/include/asm/unistd_64.h` or online on sites like `filippo.io/linux-syscall-table`.

### Syscall return value

The kernel returns the result in `rax`. On success, it is the normal value (file descriptor for `open`, byte count for `read`/`write`, etc.). On error, `rax` contains a negative value corresponding to the negated error code (for example `-2` for `ENOENT`, `-13` for `EACCES`).

libc converts this convention into the return/`errno` pair the C developer knows:

```asm
; After a syscall
cmp     rax, -4096           ; error test: values from -1 to -4095 = error  
ja      .error               ; unsigned: -1 (=0xFFFF...FFFF) > -4096 (=0xFFFF...F000)  
```

This `cmp rax, -4096` / `ja` pattern is libc's standard error check after a syscall. If you see it, you are in a syscall wrapper.

---

## libc as an intermediate layer

In practice, almost all code compiled by GCC never invokes `syscall` directly. C code calls libc functions, which themselves invoke syscalls:

```c
// User C code
write(1, "Hello\n", 6);
```

```
C call           →  libc wrapper  →  kernel syscall  
write(fd,buf,n)     write() in       mov eax, 1    (sys_write)  
                    glibc            mov edi, fd
                                     mov rsi, buf
                                     mov edx, n
                                     syscall
```

libc adds a layer of logic on top of the raw syscall:

- **Buffering**: `printf` accumulates data in a buffer and only calls `write` when the buffer is full or a `\n` is encountered (in line-buffered mode).  
- **Error handling**: libc converts the negative return value into `-1` + `errno`.  
- **Portability**: libc adapts syscall numbers (which vary across architectures) behind a stable API.  
- **Enriched features**: `malloc` uses `mmap` and `brk` but adds a complex allocator (ptmalloc) on top. `fopen` adds buffering and mode parsing (`"r"`, `"w"`, `"a"`).

### Example: what actually happens during a `printf`

```
printf("Hello %s\n", name)
   │
   ▼
vfprintf()          ← formats the string into an internal buffer
   │
   ▼
__overflow()        ← the stdio buffer is full, it needs to be flushed
   │
   ▼
write()             ← libc wrapper around the syscall
   │
   ▼
syscall (eax=1)     ← transition to the kernel
   │
   ▼
sys_write()         ← kernel code that writes to terminal/file
```

In RE, when you trace with `strace`, you only see the last level (the syscalls). When you trace with `ltrace`, you see library calls (the first level). Both perspectives are complementary (cf. Chapter 5, section 5.5).

---

## When do you encounter direct `syscall`s?

In a standard GCC-compiled binary with dynamic linking, you will **never** see the `syscall` instruction in the application code — it is hidden inside libc. But several contexts make it appear:

### Statically linked binaries (`gcc -static`)

When libc is statically linked, its code is embedded in the binary. Analyzing the binary, you see the code of libc's wrappers, including the `syscall` instructions.

```asm
; write() in a statically linked glibc
__write:
    mov     eax, 1              ; sys_write
    syscall
    cmp     rax, -4096
    ja      __syscall_error
    ret
```

### Shellcode and exploitation code

Shellcode — code injected during a vulnerability exploit — uses direct syscalls to be **independent of libc** (which may not be loaded at a known address, or whose functions may be hooked). A classic `execve("/bin/sh")` shellcode:

```asm
; execve("/bin/sh", NULL, NULL)
xor     esi, esi              ; argv = NULL  
xor     edx, edx              ; envp = NULL  
lea     rdi, [rip+binsh]     ; pathname = "/bin/sh"  
mov     eax, 59               ; sys_execve  
syscall  

binsh: .string "/bin/sh"
```

### Minimalist programs

Certain programs written directly in assembly or with ultra-light frameworks (like binary-size contest entries) avoid libc entirely:

```asm
; Complete program: prints "Hi\n" and exits
_start:
    mov     eax, 1              ; sys_write
    mov     edi, 1              ; stdout
    lea     rsi, [rip+msg]
    mov     edx, 3              ; 3 bytes
    syscall
    
    mov     eax, 60             ; sys_exit
    xor     edi, edi            ; status = 0
    syscall

msg: .ascii "Hi\n"
```

### Malware and anti-analysis

Some malware invokes syscalls directly to **bypass libc hooking**. If a security tool has hooked `open()` in libc (by modifying the GOT or via `LD_PRELOAD`), a direct `syscall` with `eax = 2` (`sys_open`) completely bypasses the hook.

```asm
; Stealth opening — bypasses libc hooks
mov     eax, 2                  ; sys_open (directly, not via libc)  
lea     rdi, [rip+filepath]  
xor     esi, esi                ; O_RDONLY  
syscall  
; The hook on open@plt was never triggered
```

This is also why some dynamic analysis tools (like Frida and `strace`) operate at the syscall level rather than at the libc level — they cannot be bypassed by a simple direct call.

> 💡 **For malware RE**: the presence of direct `syscall`s in application code (which should normally use libc) is a **red flag**. It suggests a deliberate effort to evade detection, bypass hooks, or operate without dependencies. Chapters 27 and 28 explore this subject in depth.

---

## `int 0x80` — the old mechanism (32-bit)

Before the `syscall` instruction (introduced with AMD64), Linux x86 32-bit used the `int 0x80` software interrupt to enter the kernel. You can still encounter it in:

- 32-bit code (i386 binaries analyzed on a 64-bit system).  
- Old 32-bit shellcode.  
- Legacy assembly code that has not been updated.

```asm
; Old 32-bit mechanism
mov     eax, 4           ; sys_write (32-bit number ≠ 64-bit number!)  
mov     ebx, 1           ; fd = stdout  
mov     ecx, msg         ; buffer  
mov     edx, 14          ; count  
int     0x80             ; interrupt → kernel  
```

The convention is entirely different: arguments go through `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp` (not `rdi`/`rsi`/`rdx`), and the syscall numbers are not the same as in 64-bit.

> ⚠️ **Warning**: `int 0x80` technically works in 64-bit mode (for compatibility), but with the **32-bit syscall table** and **registers truncated to 32 bits**. It is a source of bugs and confusion. If you see `int 0x80` in a 64-bit binary, it is either legacy code or a deliberate obfuscation technique.

---

## `sysenter` and `vDSO` — for completeness

Two other mechanisms deserve a quick mention:

**`sysenter`**: an Intel instruction that is an alternative to `int 0x80` for 32-bit mode, faster. You see it in 32-bit glibc on Intel processors. In 64-bit, it is `syscall` that is used.

**vDSO** (*Virtual Dynamic Shared Object*): a Linux kernel mechanism that exposes some simple syscalls (`gettimeofday`, `clock_gettime`, `getcpu`) directly in user space, without transitioning to the kernel. libc calls these functions via the vDSO rather than via `syscall`, which is much faster.

In disassembly, vDSO calls look like normal library calls (via the PLT or a pointer). You will see them if you analyze glibc's code itself, but rarely in application code.

---

## Quick recognition guide

| What you see | What it is | Calling convention |  
|---|---|---|  
| `call func@plt` | Dynamic library call | Standard System V AMD64 |  
| `call 0x4xxxxx` | Internal function call | Standard System V AMD64 |  
| `call qword [rax+0x...]` | Indirect call (vtable, function pointer) | Standard System V AMD64 |  
| `syscall` | Direct system call (64-bit) | `rax` = number, `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` |  
| `int 0x80` | Old system call (32-bit) | `eax` = number, `ebx`/`ecx`/`edx`/`esi`/`edi`/`ebp` |

The key RE question:

- **`call func@plt`** → consult the function's documentation (man pages, headers) to know the prototype and understand the arguments.  
- **`syscall`** → consult the Linux syscall table for the number in `rax`, then read the arguments from `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`.

---

## What to remember going forward

1. **`call func@plt`** goes through PLT/GOT to reach dynamic libraries — the calling convention is the standard System V AMD64, identical to internal functions.  
2. **`syscall`** is a direct transition to the kernel — the convention is almost identical to System V but the 4th argument is in **`r10`** (not `rcx`), and the service number is in **`rax`**.  
3. **Standard GCC application code** uses `call @plt` exclusively — `syscall`s are hidden in libc.  
4. **Direct `syscall`s** in application code are a red flag in malware analysis: the program is trying to bypass libc hooks.  
5. **`strace` traces syscalls**, **`ltrace` traces library calls** — both levels are complementary for dynamic RE (Chapter 5).  
6. **`int 0x80`** is the legacy 32-bit mechanism — different numbers and registers. If you see it in a 64-bit binary, it is suspicious.

---


⏭️ [Introduction to SIMD instructions (SSE/AVX) — recognizing them without fear](/03-x86-64-assembly/09-introduction-simd.md)
