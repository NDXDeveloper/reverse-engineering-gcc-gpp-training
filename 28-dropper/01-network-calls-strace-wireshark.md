🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 28.1 — Identifying Network Calls with `strace` + Wireshark

> 📍 **Objective** — Before diving into the disassembler, we start with **passive observation**: what is this binary doing on the network? This initial dynamic triage step lets you answer critical questions in just a few minutes — what address is the dropper trying to connect to? On which port? What transport protocol? How much data is flowing? — all without ever touching the binary's code.

---

## Why start here?

When an analyst receives a suspicious binary exhibiting network activity, the priority is not to understand the internal algorithm: it's to **identify network indicators of compromise** (IOCs) as quickly as possible. An IP address, a port, a recurring pattern in packets — these elements allow you to immediately block the threat at the firewall or proxy level, even before the full analysis is complete.

The approach is therefore twofold and complementary:

- **`strace`** observes the binary **from the inside** — it intercepts every system call made by the process, including `socket`, `connect`, `send`, `recv`, `select`, `close`. You see exactly what the program *asks* the kernel to do.  
- **Wireshark** (or `tcpdump`) observes the network **from the outside** — it captures packets as they actually travel across the interface. You see what *actually goes over the wire*, including TCP handshakes, retransmissions, and data in their protocol context.

Used together, these two tools allow you to correlate the program's intentions (syscalls) with their observable effects (network packets). A `connect()` that fails with `ECONNREFUSED` in `strace` corresponds to a SYN followed by a RST in Wireshark. A `send()` of 47 bytes in `strace` corresponds to a TCP segment containing those same 47 bytes in the capture. This cross-correlation is a fundamental reflex of dynamic analysis.

---

## Environment preparation

### Reminder: mandatory network isolation

This entire section takes place **inside the sandboxed VM** set up in [Chapter 26](/26-secure-lab/README.md). The network must be in **host-only** mode or on a dedicated isolated bridge. The dropper is configured to connect to `127.0.0.1:4444`, which limits the risk, but the discipline of isolation must remain systematic.

### Take a snapshot

Before running the dropper for the first time, take a snapshot of your VM. If the binary modifies the system state unexpectedly (writing files, changing configuration), you can instantly revert to a clean state.

### Which binary to use?

For this initial observation phase, the choice of variant (`_O0`, `_O2`, `_O2_strip`) **doesn't matter**: all three variants produce exactly the same system calls and the same network packets. The behavior observable from `strace` and Wireshark is identical, because compiler optimization doesn't change the logic of network calls — only their internal assembly implementation.

Use `dropper_O0` for convenience; debug messages (`printf`) will be visible on standard output and will help you correlate what you see in `strace`.

---

## Phase 1 — Quick triage before execution

Before launching anything, we apply the triage workflow from [Chapter 5](/05-basic-inspection-tools/07-quick-triage-workflow.md). Even though we know this binary is our educational sample, we maintain discipline.

### `file` — Binary type

```bash
$ file dropper_O0
dropper_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, with debug_info, not stripped  
```

We confirm it's a 64-bit PIE ELF, dynamically linked. The mention `with debug_info, not stripped` tells us that DWARF symbols are present — this is the `_O0` variant.

### `strings` — First suspicious strings

```bash
$ strings dropper_O0 | grep -iE '(127\.|connect|send|recv|socket|c2|drop|/tmp|beacon|handshake|cmd|0x)'
```

We look for indicators of network activity and suspicious behavior. Among the strings we expect to find:

- **`127.0.0.1`** — The C2 IP address (hardcoded).  
- **`4444`** — Visible as an integer, sometimes as a string in debug messages.  
- **`DRP-1.0`** — The version string sent in the handshake.  
- **`/tmp/`** — The payload drop directory.  
- Strings like `Connecting to C2`, `Sending handshake`, `EXEC command`, `DROP`, `beacon` — debug messages that reveal the program's logic.  
- Error handling strings: `exec_failed`, `write_fail`, `bad_len`, `unknown_cmd`.

> 💡 **RE note** — In real malware, these strings would be absent, encrypted, or obfuscated. Here, they are in plaintext because the sample is educational. In a real-world scenario, `strings` would return far fewer clues, and you would need to rely more on dynamic analysis and disassembly. Nevertheless, even sophisticated malware can leak standard library strings (libc error messages, system file paths).

### `checksec` — Binary protections

```bash
$ checksec --file=dropper_O0
```

The `Makefile` compiles with `-fstack-protector-strong`, `-pie`, `-Wl,-z,relro,-z,now`, and `-D_FORTIFY_SOURCE=2`. We expect to see:

- **RELRO**: Full — the GOT is read-only after loading.  
- **Stack canary**: Enabled — protection against stack overflows.  
- **NX**: Enabled — the stack is not executable.  
- **PIE**: Enabled — the binary has a randomized base address.

These protections are typical of a binary compiled with a modern toolchain. They don't prevent analysis, but they should be noted in the report.

### `ldd` — Dynamic dependencies

```bash
$ ldd dropper_O0
```

We check the linked libraries. The dropper only uses the standard `libc` — no specialized network library like `libcurl` or `libssl`. This means all communication goes through raw POSIX sockets (`socket`, `connect`, `send`, `recv`), which is consistent with a custom unencrypted protocol.

> 💡 **RE note** — The absence of `libssl`/`libcrypto` in the dependencies is valuable information: it indicates that network traffic is likely **not TLS-encrypted**. Data travels in the clear (or with a homegrown encoding), which will make the Wireshark capture directly readable.

---

## Phase 2 — Tracing system calls with `strace`

### Running the dropper without a C2 server

The simplest way to start is to run the dropper **without any server listening** on port 4444. The dropper will try to connect, fail, retry, then give up. This failure scenario is already rich in information.

```bash
$ strace -f -e trace=network,write -o dropper_trace.log ./dropper_O0
```

Let's break down the options:

- **`-f`** — Follows child processes. If the dropper uses `fork()` or `system()`, we won't lose the system calls from children.  
- **`-e trace=network,write`** — Filters to only show network system calls (`socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`, `setsockopt`, `getsockopt`...) and `write` (to see writes to `stdout`/`stderr`). Without this filter, the output would be flooded with hundreds of `mmap`, `brk`, `fstat` calls, etc.  
- **`-o dropper_trace.log`** — Redirects `strace` output to a file for later analysis. `strace` output goes to stderr and the program output to stdout; separating them makes reading easier.

### Reading the trace: failed connection

Here is what you typically observe in `dropper_trace.log` when no server is listening:

```
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3  
connect(3, {sa_family=AF_INET, sin_port=htons(4444),  
        sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
close(3)
```

This three-line sequence already tells us a lot:

1. **`socket(AF_INET, SOCK_STREAM, IPPROTO_IP)`** — The dropper creates a **TCP** socket (`SOCK_STREAM`) over IPv4 (`AF_INET`). The returned descriptor is `3` (descriptors 0, 1, 2 are stdin, stdout, stderr).

2. **`connect(3, {..., sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16)`** — It attempts to connect to **127.0.0.1:4444**. The address and port are our first **network IOCs**.

3. **`= -1 ECONNREFUSED`** — The connection fails because nothing is listening on that port. The kernel sent back a RST.

If the dropper is configured to retry (which is the case for our sample with `MAX_RETRIES = 3`), you'll see this sequence repeat, interspersed with calls to `nanosleep` or `clock_nanosleep` corresponding to pauses between attempts.

### Running the dropper with a dummy server

To go further, we need the connection to **succeed**. The simplest approach is to open a `netcat` listener on port 4444:

```bash
# Terminal 1: minimal listener
$ nc -lvnp 4444
```

```bash
# Terminal 2: dropper under strace
$ strace -f -e trace=network -tt -o dropper_trace_connected.log ./dropper_O0
```

The **`-tt`** option adds microsecond timestamps to each system call, which will be valuable for correlating with the Wireshark capture.

This time, the trace shows a successful connection:

```
14:23:05.123456 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
14:23:05.123789 connect(3, {sa_family=AF_INET, sin_port=htons(4444),
                sin_addr=inet_addr("127.0.0.1")}, 16) = 0
```

The `= 0` at the end of `connect` confirms success. Immediately after, we observe the **handshake**:

```
14:23:05.124012 sendto(3, "\336\20\24\0myhost\0...", 24, 0, NULL, 0) = 24
```

Here, `\336` is `0xDE` in octal — this is the protocol's **magic byte**. The type `\20` is `0x10` = `MSG_HANDSHAKE`. The next two bytes `\24\0` encode the body length in little-endian (`0x0014` = 20 bytes). The body contains the hostname, PID, and version, separated by null bytes.

> 💡 **RE note** — `strace` displays buffers in C escape notation (octal or hexadecimal depending on the characters). Non-printable bytes appear as `\xNN` or `\NNN`. For long buffers, `strace` truncates to 32 bytes by default. The **`-s 4096`** option increases this limit and lets you see the entirety of exchanged messages.

### Tracing with complete buffers

To capture all exchanged data in full, increase the displayed buffer size:

```bash
$ strace -f -e trace=network -tt -s 4096 -x \
    -o dropper_trace_full.log ./dropper_O0
```

The **`-x`** option forces hexadecimal display (`\xde` instead of `\336`), which is more readable for binary protocol analysis.

### Filtering specifically for `send` and `recv`

If the trace is too verbose, you can narrow it down further:

```bash
$ strace -f -e trace=sendto,recvfrom,send,recv,read,write \
    -tt -s 4096 -x -o dropper_io.log ./dropper_O0
```

> 💡 **Subtlety** — Depending on the `libc` version and compilation flags, the C code's `send()` and `recv()` functions may be internally implemented by the `sendto()` and `recvfrom()` syscalls (with address arguments set to `NULL`). That's why we include both variants in the filter. Check your trace to see which one actually appears.

---

## Phase 3 — Capturing traffic with Wireshark

### Capture on the loopback interface

Since the dropper connects to `127.0.0.1`, traffic goes through the **loopback** interface (`lo`). This is a point beginners often forget: Wireshark only captures on physical interfaces by default.

To capture with `tcpdump` (command-line, lighter in a VM):

```bash
# Terminal 3: capture loopback traffic on the C2 port
$ sudo tcpdump -i lo -w dropper_capture.pcap port 4444
```

The **`-w`** option writes raw packets to a `.pcap` file, which can be opened in Wireshark later for graphical analysis. The **`port 4444`** filter avoids capturing all the parasitic loopback traffic.

With Wireshark in graphical mode, select the `Loopback: lo` interface and apply the capture filter `port 4444`.

### Timeline of a complete session

By simultaneously running `tcpdump` (or Wireshark), the `nc` listener, then the dropper under `strace`, you get a capture containing the entire session. Here's what you observe in order:

**1. TCP handshake (3-way handshake)**

The first three packets are the classic TCP handshake:

```
SYN        →  dropper → 127.0.0.1:4444  
SYN-ACK    ←  127.0.0.1:4444 → dropper  
ACK        →  dropper → 127.0.0.1:4444  
```

This corresponds to the `connect()` seen in `strace`. The SYN timestamp in Wireshark should match (within a few microseconds) the `connect()` timestamp in the trace.

**2. Application handshake**

Immediately after TCP establishment, the dropper sends its first application message. In Wireshark, you see a TCP segment with a payload starting with the byte `0xDE`:

```
PSH-ACK    →  Payload: de 10 14 00 6d 79 68 6f 73 74 00 ...
```

Breaking it down:

| Offset | Bytes | Meaning |  
|---|---|---|  
| `0x00` | `DE` | Magic byte (`PROTO_MAGIC`) |  
| `0x01` | `10` | Type = `0x10` (`MSG_HANDSHAKE`) |  
| `0x02–0x03` | `14 00` | Body length = 20 bytes (little-endian: `0x0014`) |  
| `0x04+` | `6D 79 68 6F 73 74 00 ...` | Body: `"myhost\0"` + PID + version |

This is exactly what `strace` showed on the syscall side. The correlation is immediate.

**3. Silence or timeout**

Since `nc` doesn't speak the dropper's protocol, the dummy server doesn't send a response. The dropper remains blocked on its `recv()`, waiting for the handshake ACK. On the `strace` side, you see:

```
14:23:05.124500 recvfrom(3, ^C  <-- blocked here
```

The `recvfrom` never returns. The dropper is passively waiting. This is typical behavior of a client waiting for a server response.

> 💡 **RE note** — This observation teaches us something important about the protocol: the dropper **expects a response** after the handshake. The protocol is therefore **request/response** style, not a unidirectional stream. This information will guide the protocol reconstruction in section 28.3.

---

## Phase 4 — `strace` / Wireshark correlation

The power of this approach lies in the **correlation between the two sources**. Here's how to proceed systematically.

### Aligning timestamps

`strace` with `-tt` gives timestamps in `HH:MM:SS.µµµµµµ` format. Wireshark displays relative or absolute timestamps (configurable in `View > Time Display Format > Time of Day`). By aligning both, each `sendto()` in `strace` corresponds to a TCP PSH-ACK segment in Wireshark, and each `recvfrom()` corresponds to receiving a segment containing data.

### Verifying buffer sizes

`strace` shows the return value of `sendto()` — the number of bytes actually sent. Wireshark shows the TCP payload size. The two must match. If `strace` shows `sendto(...) = 33` and Wireshark shows a TCP payload of 33 bytes, everything is consistent.

A discrepancy could indicate that the `libc` is performing buffering (rare for TCP sockets in `SOCK_STREAM` mode without explicit `setvbuf`), or that the kernel fragmented the send into multiple TCP segments. In that case, the sum of TCP payloads in Wireshark must equal the `sendto` return value.

### Building the correspondence table

A table like this is the expected deliverable at the end of this phase:

| # | Timestamp | Syscall (`strace`) | Direction | Wireshark packet | Size | Observations |  
|---|---|---|---|---|---|---|  
| 1 | 14:23:05.123 | `socket(AF_INET, SOCK_STREAM, 0) = 3` | — | — | — | TCP socket creation |  
| 2 | 14:23:05.123 | `connect(3, {127.0.0.1:4444}) = 0` | → | SYN → SYN-ACK → ACK | — | TCP connection established |  
| 3 | 14:23:05.124 | `sendto(3, "\xde\x10...", 24) = 24` | → | PSH-ACK, 24-byte payload | 24 | Handshake (magic=0xDE, type=0x10) |  
| 4 | 14:23:05.124 | `recvfrom(3, ...)` blocked | ← | (no response) | — | Waiting for server ACK |

This table forms the basis for the protocol analysis that will be deepened in section 28.3.

---

## Going further: advanced `strace`

### Tracing file accesses in parallel

The dropper doesn't just do networking — it can write files (`CMD_DROP` command). You can capture **everything** in a single trace:

```bash
$ strace -f -e trace=network,open,openat,write,close,execve,chmod \
    -tt -s 4096 -x -o dropper_full_trace.log ./dropper_O0
```

The `openat`, `write`, `chmod`, and `execve` calls will let you see the dropper depositing a file in `/tmp/` and executing it — this will be visible when you send it a `CMD_DROP` command from a real fake C2 (section 28.4).

### Counting system calls

To get a statistical summary rather than a detailed trace:

```bash
$ strace -c ./dropper_O0
```

The `-c` flag produces a summary table at the end of execution, showing how many times each syscall was invoked, total time spent in each, and the percentage of time. This is useful for quickly spotting whether a binary spends most of its time in network calls (suspicious), in file `read`/`write` operations, or in `nanosleep` (waiting between attempts).

### `ltrace` as a complement

While `strace` traces *system* calls (kernel interface), `ltrace` traces *library* calls (`libc` functions). For a network binary, `ltrace` will show calls to `inet_pton`, `htons`, `gethostname`, `popen`, `fwrite`, `chmod` — a slightly higher level of abstraction than syscalls.

```bash
$ ltrace -e 'inet_pton+connect+send+recv+popen+fwrite+chmod' \
    ./dropper_O0
```

> ⚠️ **Limitation** — `ltrace` doesn't work on fully static binaries, and its support can be inconsistent on PIE binaries with Full RELRO depending on the distribution. If `ltrace` produces no output, it's not a bug in your installation — it's a known limitation. `strace` remains the reference tool for this phase.

---

## What we know after this first phase

At this point, without having opened a single disassembler, we already have the following information:

**Identified network IOCs:**  
- C2 address: `127.0.0.1` (localhost — in production, this would be an external IP or domain)  
- Port: `4444/tcp`  
- Transport: TCP (`SOCK_STREAM`)  
- No TLS encryption (absence of `libssl` in `ldd`)

**Observed behavior:**  
- The dropper initiates the connection (it is a **client**, not a server)  
- It sends a first message immediately after connection (handshake)  
- The message starts with `0xDE` (magic byte) followed by a type and a length  
- It then waits for a server response (request/response protocol)  
- On connection failure, it retries with an interval of a few seconds  
- It gives up after a finite number of attempts

**Hypotheses to verify in the following sections:**  
- The `[magic][type][length][body]` format seems constant — to be confirmed across more messages.  
- The XOR encoding visible in the `strings` output (`0x5A`) likely applies to the body of certain messages — to be verified by intercepting buffers with Frida (section 28.2).  
- The supported command set and complete state machine remain to be reconstructed (section 28.3).

---

## Key command summary

| Command | Purpose |  
|---|---|  
| `strace -f -e trace=network -tt -s 4096 -x -o trace.log ./binary` | Full trace of network calls with timestamps and hex buffers |  
| `strace -c ./binary` | Summary statistics of syscalls |  
| `ltrace -e 'connect+send+recv' ./binary` | Trace of libc network calls |  
| `sudo tcpdump -i lo -w capture.pcap port 4444` | Capture loopback traffic on the C2 port |  
| `nc -lvnp 4444` | Minimal TCP listener to accept the connection |

---

> **Up next** — In section 28.2, we'll move from passive observation to **active instrumentation**: Frida will allow us to hook `connect`, `send`, and `recv` to intercept buffers *before* and *after* XOR encoding, directly in the process's memory space.

⏭️ [Hooking sockets with Frida (intercepting `connect`, `send`, `recv`)](/28-dropper/02-hooking-sockets-frida.md)
