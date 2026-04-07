🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.7 — Remote debugging with `gdbserver` (debugging on a remote target)

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## Why debug remotely

Until now, GDB and the analyzed binary ran on the same machine. It's the simplest configuration, but it doesn't always match the reality of RE. Several situations impose — or strongly recommend — separating the debugger from the target:

**Malware analysis in a sandbox.** The fundamental principle of malicious-code analysis (Part VI) is isolation: the suspect binary runs in a sandboxed VM, disconnected from the real network. You don't want to install a full GDB environment in this VM, nor transfer your scripts and analysis notes there. Remote debugging lets you drive execution from the host machine, safely, with all our tool comfort.

**Resource-limited targets.** An embedded system, a router, an IoT device generally lacks the memory or disk space to host GDB (which weighs several tens of MB with its dependencies). `gdbserver`, on the other hand, is a minimalist executable — a few hundred KB, no heavy dependencies — designed to run on constrained targets.

**Privilege separation.** You may want to execute the binary as root in the VM (because it requires privileges) while driving the analysis from an unprivileged user on the host. Remote debugging decouples the debugger's privileges from those of the debugged process.

**Work comfort.** The analysis VM has a limited screen, no graphical interface, a different keyboard. Working from our host machine with our configured terminal, our scripts, our `.gdb` files, and our Ghidra open next to it is incomparably more productive.

The protocol that makes all of this possible is the **GDB Remote Serial Protocol** (RSP), a simple text protocol over TCP that GDB speaks natively. On the target side, `gdbserver` is the server that speaks this protocol and controls the debugged process.

## Remote debugging architecture

The schema is as follows:

```
┌──────────────────────────┐         TCP/IP           ┌─────────────────────────┐
│      HOST MACHINE        │                          │     TARGET (VM / device)│
│                          │                          │                         │
│  ┌────────────────────┐  │    GDB Remote Protocol   │  ┌──────────────────┐   │
│  │       GDB          │◄─┼──────────────────────────┼─►│   gdbserver      │   │
│  │  (full client)     │  │       port 1234          │  │  (minimal stub)  │   │
│  └────────────────────┘  │                          │  └────────┬─────────┘   │
│                          │                          │           │ ptrace      │
│  - Symbols / DWARF       │                          │  ┌────────▼─────────┐   │
│  - .gdb scripts          │                          │  │  Target binary   │   │
│  - Ghidra alongside      │                          │  │  (process)       │   │
│                          │                          │  └──────────────────┘   │
└──────────────────────────┘                          └─────────────────────────┘
```

The essential point: **the binary does not need to be present on the host machine to be debugged**. Only `gdbserver` and the binary need to be on the target. However, for GDB to display symbols, function names, and source code, you must provide it a local copy of the binary (or at minimum a symbol file).

`gdbserver` is a lightweight program that:
- Launches the target binary (or attaches to an existing process).  
- Controls its execution via `ptrace` (as GDB would locally).  
- Translates GDB commands received via TCP into `ptrace` operations.  
- Sends results (register state, memory content) back to the GDB client.

It does no analysis, reads no symbols, disassembles nothing. All intelligence is on the GDB client side.

## Setup: the standard case

### Target side: launch `gdbserver`

`gdbserver` is used in two ways: launch a new process or attach to an existing process.

**Launch a new process:**

```bash
# On the target (VM)
$ gdbserver :1234 ./keygenme_O2_strip
Process ./keygenme_O2_strip created; pid = 4567  
Listening on port 1234  
```

`gdbserver` launches the binary, immediately pauses it (before even executing `_start`), and listens for GDB connections on TCP port 1234. The `:1234` is shorthand for `0.0.0.0:1234` — listen on all interfaces.

You can pass arguments to the program:

```bash
$ gdbserver :1234 ./keygenme_O2_strip "MY-TEST-KEY"
```

And redirect standard input:

```bash
$ gdbserver :1234 ./keygenme_O2_strip < input.txt
```

**Attach to an existing process:**

```bash
# The program is already running with PID 4567
$ gdbserver --attach :1234 4567
Attached; pid = 4567  
Listening on port 1234  
```

The process is immediately paused. It's useful for debugging a daemon or a program already running without restarting it.

### Host side: connect from GDB

```bash
# On the host
$ gdb -q ./keygenme_O2_strip
(gdb) target remote 192.168.56.10:1234
Remote debugging using 192.168.56.10:1234
0x00007ffff7fe4c40 in _start () from /lib64/ld-linux-x86-64.so.2
```

The `target remote` command establishes the connection. The address `192.168.56.10` is the target VM's IP (typically a host-only interface, see Chapter 4, section 4.4). GDB displays the initial breakpoint — the program is paused on the loader's first instruction.

You pass the local binary (`./keygenme_O2_strip`) to GDB so it reads its symbols and sections. If the local binary contains DWARF symbols (debug version) while the target runs the stripped version, you benefit from the best of both worlds: the debug version's symbols applied to the stripped version's execution.

```bash
# Local debug version, stripped version on the target
$ gdb -q ./keygenme_O2_debug
(gdb) target remote 192.168.56.10:1234
```

### `target remote` vs `target extended-remote`

GDB offers two connection modes:

| Mode | Behavior |  
|---|---|  
| `target remote` | Simple connection. When the program ends (or you `kill`), the session closes. You must relaunch `gdbserver` on the target to restart. |  
| `target extended-remote` | Persistent connection. You can relaunch the program with `run` without relaunching `gdbserver`. The server stays active between executions. |

For iterative RE (you often relaunch the binary with different inputs), `extended-remote` is far more practical:

```bash
# Target side
$ gdbserver --multi :1234
Listening on port 1234

# Host side
$ gdb -q ./keygenme_O2_strip
(gdb) target extended-remote 192.168.56.10:1234
(gdb) set remote exec-file /home/user/keygenme_O2_strip
(gdb) run
...
(gdb) run "OTHER-KEY"    # Can relaunch without touching the target
```

The `--multi` flag on `gdbserver` enables multi-session mode. The `set remote exec-file` command indicates the binary's path **on the target** (which may differ from the local path).

## Network configuration for RE

### Recommended topology

The ideal network configuration for remote debugging in an RE context (especially for malware analysis) uses a **host-only** network:

```
┌─────────────────┐     host-only (192.168.56.0/24)    ┌─────────────────┐
│   Host machine  │◄──────────────────────────────────►│   Sandbox VM    │
│  192.168.56.1   │    (no Internet access)            │  192.168.56.10  │
│                 │                                    │                 │
│  GDB client     │                                    │  gdbserver      │
│  Ghidra         │                                    │  target binary  │
└─────────────────┘                                    └─────────────────┘
```

The host-only network allows communication between host and VM without giving the VM Internet access. It's the strict minimum connectivity needed for remote debugging, and it prevents an analyzed malware from communicating with the outside.

Setting up this network is detailed in Chapter 4 (section 4.4) and Chapter 26 for malware analysis labs.

### Securing the connection

The GDB RSP protocol offers **no encryption or authentication**. Anyone who can connect to `gdbserver`'s port gets full control over the debugged process. On an isolated host-only network, it's not a problem. On any other network, you must tunnel the connection:

```bash
# On the host: SSH tunnel to the target
$ ssh -L 1234:localhost:1234 user@192.168.56.10

# Then in GDB, connect to the local tunnel
(gdb) target remote localhost:1234
```

Local port 1234 is forwarded via SSH to the target's port 1234. The connection is encrypted and authenticated.

Alternatively, you can limit `gdbserver` to listening only on localhost and use SSH to access it:

```bash
# On the target
$ gdbserver localhost:1234 ./binary

# From the host, via SSH
$ ssh -L 1234:localhost:1234 user@target
```

### Connection via pipe (without network)

For cases where even a host-only network isn't desirable, GDB can connect via a stdin/stdout pipe through SSH:

```
(gdb) target remote | ssh user@192.168.56.10 gdbserver - ./binary
```

The `-` as address tells `gdbserver` to communicate via stdin/stdout instead of a TCP socket. GDB pipes its communication through SSH. No network port is opened on the target.

## Commands specific to remote mode

Most GDB commands work transparently in remote mode. A few commands and settings are specific:

### Loading shared-library symbols

In remote mode, GDB doesn't automatically find the target's shared libraries (they're on the VM's filesystem, not on the host). If the target's libraries differ from the host's (different glibc version, for example), symbols will be incorrect.

Configure a local directory containing copies of the target's libraries:

```
(gdb) set sysroot /home/user/target-sysroot/
```

The `target-sysroot/` directory reproduces the target's structure:

```
target-sysroot/
├── lib/
│   └── x86_64-linux-gnu/
│       ├── libc.so.6
│       ├── libpthread.so.0
│       └── ld-linux-x86-64.so.2
└── usr/
    └── lib/
        └── ...
```

If libraries are identical between host and target (same distribution, same version), `set sysroot /` uses local libraries directly. To completely ignore shared libraries:

```
(gdb) set sysroot
(gdb) set auto-solib-add off
```

### Transferring files

GDB can download files from the target via the remote protocol:

```
(gdb) remote get /proc/self/maps /tmp/target_maps.txt
(gdb) remote get /etc/passwd /tmp/target_passwd.txt
```

And send files to the target:

```
(gdb) remote put /home/user/payload.bin /tmp/payload.bin
```

It's useful for retrieving memory dumps, configuration files, or any artifact produced by the binary during analysis.

### Detach and reconnect

To detach from the target without killing the process:

```
(gdb) detach
Detaching from program: /home/user/keygenme, process 4567
```

The process continues running on the target. In `extended-remote` mode, you can reattach:

```
(gdb) target extended-remote 192.168.56.10:1234
(gdb) attach 4567
```

To kill the remote process:

```
(gdb) kill
```

And to disconnect GDB from the server without affecting the process:

```
(gdb) disconnect
```

### Redirecting program input/output

By default, the debugged program's standard input and output go through `gdbserver`'s terminal on the target, not through GDB's terminal on the host. If the program expects keyboard input, you must type it **in the target's terminal**.

To redirect I/O to the host, use GDB's remote file protocol:

```
(gdb) set remote exec-file /home/user/keygenme
(gdb) set inferior-tty /dev/pts/3
```

In practice, the simplest solution is to prepare inputs in a file and redirect stdin on the target:

```bash
# On the target
$ echo "TEST-KEY" > /tmp/input.txt
$ gdbserver :1234 ./keygenme < /tmp/input.txt
```

Or use `pwntools` on the host side to programmatically interact with the remote process (section 11.9).

## Remote debugging of multi-threaded processes

Multi-threaded programs work in remote mode, but with some specifics:

```
(gdb) info threads
  Id   Target Id                    Frame
* 1    Thread 4567.4567 "keygenme"  0x00007ffff7e62123 in read ()
  2    Thread 4567.4568 "keygenme"  0x00007ffff7e63456 in nanosleep ()
  3    Thread 4567.4569 "keygenme"  0x00007ffff7e62789 in poll ()
```

You switch between threads as locally:

```
(gdb) thread 2
[Switching to thread 2 (Thread 4567.4568)]
(gdb) backtrace
...
```

An important setting for multi-threaded programs in remote mode:

```
(gdb) set non-stop on
```

In **non-stop** mode, when a thread hits a breakpoint, only that thread is stopped — the others continue running. It's more faithful to real behavior and avoids artificial deadlocks caused by stopping all threads simultaneously. The default mode (`set non-stop off`) stops all threads when one of them hits a breakpoint.

## Automating with a command file

For an iterative RE workflow, gather all the configuration in a file:

```bash
# remote_analysis.gdb — remote debugging session

# Connection
target extended-remote 192.168.56.10:1234  
set remote exec-file /home/user/keygenme_O2_strip  

# Symbols
set sysroot /home/user/target-sysroot/

# Configuration
set disassembly-flavor intel  
set pagination off  
set follow-fork-mode child  
set detach-on-fork off  

# Annotations (addresses identified in Ghidra)
set $main       = 0x401190  
set $check_key  = 0x401140  

# Breakpoints
break *$main  
break *$check_key  
break strcmp  

# Displays
display/x $rax  
display/x $rdi  
display/6i $rip  

# Anti-anti-debug: neutralize ptrace
catch syscall ptrace  
commands  
  silent
  set $rax = 0
  continue
end

# Launch
run
```

Launch:

```bash
$ gdb -q -x remote_analysis.gdb ./keygenme_O2_strip
```

This single file contains the connection, symbols, annotations, breakpoints, anti-debugging bypasses, and launch. You can version it, share it with a colleague, and reproduce exactly the same analysis session.

## Alternatives and special cases

### Debugging via QEMU user-mode

For binaries of a different architecture (ARM, MIPS, RISC-V), QEMU in user mode (*user-mode emulation*) can emulate the binary and expose a GDB stub:

```bash
# Emulate an ARM binary and listen on port 1234
$ qemu-arm -g 1234 ./arm_binary
```

On the host side, use a multiarch GDB:

```bash
$ gdb-multiarch ./arm_binary
(gdb) target remote localhost:1234
```

It's the main way to debug binaries of exotic architectures without having the physical hardware. The binary executes instruction by instruction in the emulator, with full access to registers and memory.

### Debugging via QEMU system-mode

To debug a complete kernel or firmware, QEMU in system mode also exposes a GDB stub:

```bash
$ qemu-system-x86_64 -s -S -hda disk.img
# -s: listen for GDB on port 1234
# -S: start paused (wait for GDB connection)
```

```
(gdb) target remote localhost:1234
```

You then debug the **kernel** or bare-metal code, not a user process. It's an advanced use, outside the scope of this tutorial, but the connection mechanism is identical.

### `gdbserver` without installation

If the target doesn't have `gdbserver` installed and you can't (or don't want to) install it, you can transfer a statically compiled prebuilt binary:

```bash
# Compile gdbserver statically (on a build machine)
$ apt source gdb
$ cd gdb-*/gdb/gdbserver/
$ ./configure --host=x86_64-linux-gnu --enable-static
$ make LDFLAGS=-static
$ file gdbserver
gdbserver: ELF 64-bit LSB executable, statically linked, ...

# Transfer to the target
$ scp gdbserver user@target:/tmp/
```

The static binary has no dependencies and works on any Linux distribution of the same architecture.

On common distributions, `gdbserver` is often available in a separate package:

```bash
$ sudo apt install gdbserver          # Debian/Ubuntu
$ sudo dnf install gdb-gdbserver      # Fedora/RHEL
```

## Common problem diagnosis

| Symptom | Probable cause | Solution |  
|---|---|---|  
| `Connection refused` | `gdbserver` not launched or listening on another port | Check the process and port on the target (`ss -tlnp`) |  
| `Connection timed out` | Firewall, wrong IP, unconfigured network | Test connectivity with `ping` and `nc -z <ip> <port>` |  
| `Remote 'g' packet reply is too long` | 32/64-bit architecture mismatch between GDB and target | Use `set architecture i386` or the right GDB (multiarch) |  
| Missing or incorrect symbols | Sysroot not configured or different libraries | Configure `set sysroot` with the target's libraries |  
| Program seems stuck | I/O is on the target's terminal, not the host's | Redirect stdin from a file or use the target's terminal |  
| `Cannot access memory` | ASLR addresses differ from expected | Recalculate the base (section 11.4) or disable ASLR on target |

To enable protocol logs in case of communication problems:

```
(gdb) set debug remote 1
```

GDB will display each packet sent and received, allowing you to diagnose failing exchanges.

---

> **Takeaway:** Remote debugging with `gdbserver` separates analysis comfort (host side) from binary execution (target side). It's a necessity for malware analysis in a sandbox and for embedded targets, but it's also a productivity gain for any analysis where you want to keep your tools, scripts, and notes on the main machine. Setup is simple — `gdbserver :1234 ./binary` on one side, `target remote <ip>:1234` on the other — and 95% of GDB commands work transparently. The only extra effort is managing symbols and shared libraries via `set sysroot`.

⏭️ [GDB Python API — scripting and automation](/11-gdb/08-gdb-python-api.md)
