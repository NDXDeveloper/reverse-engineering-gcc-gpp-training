🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.9 — Introduction to `pwntools` to automate interactions with a binary

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## The missing link between analysis and action

Previous sections showed how to observe a program with GDB: set breakpoints, inspect registers, read memory, automate information collection with the Python API. But observing is not always enough. At some point, you need to **interact** with the binary: send it precise inputs, read its outputs, adapt the next input based on the response, and all of this in a reproducible and programmable way.

Let's take a concrete scenario. The analysis of `keygenme_O0` in GDB revealed that the `check_key` function compares user input with a string derived from a calculation. We now know the algorithm. We want to write a program that:

1. Launches the binary.  
2. Reads the `"Enter your key: "` prompt.  
3. Computes the correct key.  
4. Sends it to the program.  
5. Verifies that the response is `"Correct!"`.

We could do this with a shell script and pipes, or with `subprocess` in Python. But these approaches quickly run into problems with buffering, timing, interactive I/O management, and GDB integration. **pwntools** solves all of this in a single Python library, specifically designed for interacting with binaries.

## What is pwntools

pwntools is a Python library developed by the Gallopsled team, initially for CTF (*Capture The Flag*) competitions, but which has become a reference tool in reverse engineering and vulnerability research. It provides:

- A unified abstraction for interacting with local processes, remote binaries (via network), and GDB.  
- Data send and receive primitives with fine-grained buffering and timing management.  
- Payload construction tools: integer packing/unpacking, cyclic pattern generation, shellcode manipulation.  
- Native GDB integration: launch a process under GDB from the Python script, set breakpoints, resume execution.  
- ELF analysis utilities: reading sections, symbols, GOT/PLT, offset computation.

In the context of this chapter, we focus on the first two aspects: interaction with a process and GDB integration. The exploitation aspects (shellcode, ROP) are outside the scope of this training.

## Installation

pwntools installs via pip:

```bash
$ pip install pwntools
```

Dependencies include `capstone` (disassembler), `pyelftools` (ELF parsing), `unicorn` (emulation), and several others. Installation is heavier than a typical library, but everything is automatic.

Verification:

```python
$ python3 -c "from pwn import *; print(pwnlib.version)"
```

> ⚠️ **Import convention:** pwntools is conventionally imported with `from pwn import *`, which injects a large number of names into the global namespace. It's unusual for a Python library, but it's the standard pwntools style, optimized for rapid script writing. For cleaner code, you can import selectively: `from pwnlib.tubes.process import process`.

## Interacting with a local process

### Launching a process

```python
from pwn import *

# Launch a binary
p = process("./keygenme_O0")
```

The `p` object is a **tube** — pwntools' central abstraction for any bidirectional communication channel. A tube can be a local process, a network connection, a serial port, or even an SSH session. The interface is identical regardless of the transport.

The process is launched immediately and runs in the background. It waits for its inputs via tube `p`.

To pass arguments or environment variables:

```python
p = process(["./keygenme_O0", "arg1", "arg2"])  
p = process("./keygenme_O0", env={"LD_PRELOAD": "./hook.so"})  
```

### Receiving data

```python
# Read until a specific string
prompt = p.recvuntil(b"Enter your key: ")  
print(prompt)    # b'Enter your key: '  

# Read a full line (until \n)
line = p.recvline()  
print(line)      # b'Some output\n'  

# Read exactly N bytes
data = p.recv(16)

# Read all available data (non-blocking with timeout)
data = p.recv(timeout=1)

# Read until end of process
all_output = p.recvall()
```

The most important method is `recvuntil()`: it blocks until the specified string appears in the output, then returns everything received including the delimiter. It's the standard way to synchronize with an interactive program — wait for the prompt before sending the response.

The `timeout` parameter (in seconds) is available on all receive methods. If the timeout expires without the condition being met, an `EOFError` exception is raised (or partial data is returned, depending on the method).

### Sending data

```python
# Send raw bytes
p.send(b"TEST-KEY")

# Send with a newline (\n) automatically appended
p.sendline(b"TEST-KEY")

# Wait for a prompt, then send
p.sendlineafter(b"Enter your key: ", b"TEST-KEY")
```

`sendlineafter()` combines `recvuntil()` and `sendline()` in a single call — it's the most frequent pattern for prompt/response interactions. The method waits for the prompt, then sends the response followed by a newline.

Its variant `sendafter()` does the same without adding a newline.

### Complete example: interacting with the keygenme

```python
from pwn import *

# Configure log level
context.log_level = 'info'    # 'debug' to see all traffic

# Launch the binary
p = process("./keygenme_O0")

# Wait for the prompt and send a key
p.sendlineafter(b"Enter your key: ", b"TEST-KEY")

# Read the response
response = p.recvline()  
print(f"Response: {response}")  

if b"Correct" in response:
    log.success("Key accepted!")
else:
    log.failure("Key refused.")

p.close()
```

The `log` object is pwntools' built-in logger, with colored levels: `log.info()`, `log.success()`, `log.failure()`, `log.warning()`. The `context.log_level = 'debug'` setting shows all raw traffic sent and received — indispensable for diagnosing synchronization problems.

## GDB integration

This is the feature that justifies pwntools' presence in this chapter on GDB. pwntools can launch a process **directly under GDB**, allowing you to interact with the binary from the Python script while setting breakpoints and inspecting state in GDB.

### Launching a process under GDB

```python
from pwn import *

# Launch under GDB with a dedicated terminal
p = gdb.debug("./keygenme_O0", '''
    break check_key
    continue
''')
```

This command:

1. Launches the binary under `gdbserver`.  
2. Opens a **new terminal** with a GDB session connected to the server.  
3. Executes the GDB commands passed as the second argument (here, set a breakpoint and continue).  
4. Returns a tube `p` that allows interacting with the binary's stdin/stdout from the Python script.

You end up with two windows: the GDB terminal where you can interactively inspect, and the Python script that controls inputs/outputs. Both operate on the same process.

### Configuring the terminal

pwntools must open a new terminal for GDB. By default, it tries `tmux` (if in a tmux session), then `gnome-terminal`, `xterm`, etc. You can force the choice:

```python
context.terminal = ['tmux', 'splitw', '-h']     # Horizontal split in tmux  
context.terminal = ['gnome-terminal', '--', 'sh', '-c']  
context.terminal = ['xterm', '-e']  
```

The tmux configuration is the most practical: GDB opens in a pane next to the script, in the same terminal.

### Combined workflow: script + interactive GDB

Here is a realistic workflow. The script sends data to the binary, and GDB is positioned to observe the state at the critical moment:

```python
from pwn import *

context.arch = 'amd64'  
context.terminal = ['tmux', 'splitw', '-h']  

# Launch under GDB, breakpoint just before the comparison
p = gdb.debug("./keygenme_O0", '''
    set disassembly-flavor intel
    break *check_key+30
    continue
''')

# The script waits until GDB has reached the 'continue'
# then sends the input
p.sendlineafter(b"Enter your key: ", b"REVERSE-2025")

# GDB is now stopped on the breakpoint in check_key
# → You can interactively inspect registers in the GDB terminal
# → The script waits for execution to resume (when you type 'continue' in GDB)

# Read the result
p.interactive()
```

The `p.interactive()` method at the end switches the tube to interactive mode: the terminal's stdin is connected to the process's stdin, and its output is displayed directly. It's useful for phases where you want to interact manually after an automated phase.

### Attaching GDB to an existing process

You can also launch the process normally and attach GDB afterwards:

```python
from pwn import *

p = process("./keygenme_O0")

# Perform part of the interaction
p.recvuntil(b"Enter your key: ")

# Attach GDB now (the process is paused)
gdb.attach(p, '''
    break *check_key+30
    continue
''')

# Send the input (GDB is attached and breakpoint is in place)
p.sendline(b"REVERSE-2025")

p.interactive()
```

`gdb.attach()` opens a GDB terminal attached to `p`'s process. The second argument contains GDB commands to execute after attachment. The process is briefly paused during attachment, then resumes when GDB executes `continue`.

## Packing and data utilities

pwntools provides functions for converting between integers and bytes, a constant operation in RE.

### Packing and unpacking

```python
from pwn import *

context.arch = 'amd64'     # Determines default endianness and size

# Pack: integer → bytes (little-endian by default on x86-64)
p64(0xdeadbeef)              # b'\xef\xbe\xad\xde\x00\x00\x00\x00'  
p32(0xdeadbeef)              # b'\xef\xbe\xad\xde'  
p16(0x4141)                  # b'AA'  
p8(0x41)                     # b'A'  

# Unpack: bytes → integer
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')    # 0xdeadbeef  
u32(b'\xef\xbe\xad\xde')                      # 0xdeadbeef  
u16(b'AA')                                     # 0x4141  

# Unpack with automatic padding (when you don't have exactly 8 bytes)
u64(b'\xef\xbe\xad\xde\x00\x00'.ljust(8, b'\x00'))
```

These functions replace `struct.pack("<Q", val)` and `struct.unpack("<Q", data)[0]` with a much more concise syntax. The endianness convention is determined by `context.arch`.

### String and pattern manipulation

```python
# Cyclic pattern to identify offsets in a crash
pattern = cyclic(200)          # b'aaaabaaacaaadaaa...'
# If the program crashes with rip = 0x6161616c:
offset = cyclic_find(0x6161616c)  
print(f"Crash offset: {offset}")    # ex: 44  

# Hex encode/decode
enhex(b"TEST")                 # '54455354'  
unhex('54455354')              # b'TEST'  

# XOR
xor(b"SECRET", 0x42)          # XOR each byte with 0x42  
xor(b"CIPHER", b"KEYKEY")     # XOR with a repeated key  
```

The `cyclic()` function generates a De Bruijn pattern where each N-byte subsequence is unique. By sending this pattern as input to a vulnerable binary, the value found in `rip` (or `rsp`) after the crash identifies the exact overflow offset. It's a classic exploitation tool, but also useful in RE for mapping buffers.

## ELF binary analysis

pwntools includes a complete ELF parser that complements the tools seen in Chapter 5:

```python
from pwn import *

elf = ELF("./keygenme_O0")

# Basic information
print(f"Architecture: {elf.arch}")        # 'amd64'  
print(f"Entry point : {elf.entry:#x}")    # 0x401060  
print(f"PIE         : {elf.pie}")         # False  
print(f"NX          : {elf.nx}")          # True (or False)  
print(f"Canary      : {elf.canary}")      # False  

# Function addresses (if not stripped)
print(f"main        : {elf.symbols['main']:#x}")  
print(f"check_key   : {elf.symbols['check_key']:#x}")  

# PLT table (imported functions)
print(f"strcmp@plt   : {elf.plt['strcmp']:#x}")  
print(f"printf@plt  : {elf.plt['printf']:#x}")  

# GOT table
print(f"strcmp@got   : {elf.got['strcmp']:#x}")

# Sections
print(f".text        : {elf.sections['.text'].header.sh_addr:#x}")  
print(f".rodata      : {elf.sections['.rodata'].header.sh_addr:#x}")  

# Search for a string in the binary
addr = next(elf.search(b"Correct!"))  
print(f"'Correct!' found at {addr:#x}")  

# Search for a byte pattern
for addr in elf.search(b"\x48\x89\xe5"):     # mov rbp, rsp
    print(f"Prologue found at {addr:#x}")
```

The `ELF` object is particularly useful for scripts that must adapt to different compilations of the same binary. Instead of hardcoding addresses, you resolve them dynamically:

```python
elf = ELF("./keygenme_O0")

# Address is resolved dynamically
p = process(elf.path)  
gdb.attach(p, f'''  
    break *{elf.symbols['check_key']:#x}
    continue
''')
```

If you recompile the binary and addresses change, the script adapts automatically.

## Network connection

The same tube paradigm applies to network connections — this will be exploited in detail in Chapter 23 for reversing a client/server protocol:

```python
from pwn import *

# Connect to a remote service
r = remote("192.168.56.10", 4444)

# The interface is identical to process()
r.sendlineafter(b"login: ", b"admin")  
r.sendlineafter(b"password: ", b"s3cr3t")  
response = r.recvline()  
print(response)  

r.close()
```

The abstraction is transparent: a script written for a local process (`process()`) can be converted to a network client (`remote()`) by changing a single line. It's exactly what you do when writing a replacement client for a protocol you've reverse-engineered.

## Context and architecture

The global `context` object configures pwntools' behavior:

```python
from pwn import *

# Target architecture
context.arch = 'amd64'        # Also: 'i386', 'arm', 'aarch64', 'mips'  
context.bits = 64  
context.endian = 'little'  

# Log level
context.log_level = 'debug'   # Show everything (sends, receives, hex dumps)  
context.log_level = 'info'    # Normal information  
context.log_level = 'warn'    # Warnings only  
context.log_level = 'error'   # Errors only  

# Automatic configuration from an ELF binary
context.binary = ELF("./keygenme_O0")
# → context.arch, bits, endian are deduced automatically
```

`context.log_level = 'debug'` is pwntools' most useful diagnostic tool: it shows every byte sent and received, with hex dumps. When a script doesn't synchronize correctly with the binary, debug mode immediately reveals where the mismatch lies.

## Complete script: automated keygen

To conclude, here is the skeleton of a complete keygen combining everything we've seen — pwntools for interaction, GDB integration for verification, ELF analysis for address resolution:

```python
#!/usr/bin/env python3
"""
Automated keygen for keygenme_O0.  
Uses pwntools for interaction and GDB for verification.  
"""
from pwn import *

# Configuration
context.arch = 'amd64'  
context.log_level = 'info'  
elf = ELF("./keygenme_O0")  

def compute_key(username):
    """Key generation algorithm, reconstructed by RE."""
    key = 0
    for i, c in enumerate(username):
        key ^= ord(c) << (i % 8)
        key = (key * 0x5DEECE66D + 0xB) & 0xFFFFFFFF
    return f"KEY-{key:08X}"

def verify_key(binary_path, key):
    """Verify the key by sending it to the binary."""
    p = process(binary_path)
    p.sendlineafter(b"Enter your key: ", key.encode())
    response = p.recvline(timeout=3)
    p.close()
    return b"Correct" in response

def verify_with_gdb(binary_path, key):
    """Verify by observing check_key's return in GDB."""
    p = process(binary_path)
    gdb.attach(p, f'''
        break *{elf.symbols.get("check_key", 0):#x}
        commands
          silent
          finish
          printf "check_key returned %d\\n", $rax
          continue
        end
        continue
    ''')
    
    p.sendlineafter(b"Enter your key: ", key.encode())
    p.interactive()

# Generate and test
key = compute_key("user123")  
log.info(f"Generated key: {key}")  

if verify_key(elf.path, key):
    log.success(f"Verification succeeded: {key}")
else:
    log.failure("Failed — launching debug mode")
    verify_with_gdb(elf.path, key)
```

This script illustrates the complete workflow:

1. `ELF()` resolves addresses dynamically.  
2. `compute_key()` implements the algorithm reconstructed by static and dynamic analysis.  
3. `verify_key()` tests the key via `process()` + `sendlineafter()` — fully automated.  
4. `verify_with_gdb()` relaunches with GDB attached if verification fails, for diagnosis.

This is exactly the type of script we'll develop in Chapter 21 for the complete keygenme.

## Summary of essential pwntools API

| Function / Method | Role |  
|---|---|  
| `process(binary)` | Launch a local process |  
| `remote(host, port)` | Connect to a network service |  
| `gdb.debug(binary, script)` | Launch under GDB with commands |  
| `gdb.attach(proc, script)` | Attach GDB to an existing process |  
| `p.send(data)` | Send raw bytes |  
| `p.sendline(data)` | Send bytes + newline |  
| `p.sendlineafter(delim, data)` | Wait for a prompt, then send |  
| `p.recv(n)` | Receive n bytes |  
| `p.recvline()` | Receive a line |  
| `p.recvuntil(delim)` | Receive until a delimiter |  
| `p.recvall()` | Receive everything until end |  
| `p.interactive()` | Switch to interactive mode |  
| `p.close()` | Close the tube |  
| `p64()` / `u64()` | Pack / unpack 64 bits |  
| `p32()` / `u32()` | Pack / unpack 32 bits |  
| `ELF(path)` | Parse an ELF binary |  
| `elf.symbols[name]` | Address of a symbol |  
| `elf.plt[name]` / `elf.got[name]` | PLT / GOT addresses |  
| `elf.search(bytes)` | Search for bytes in the binary |  
| `cyclic(n)` / `cyclic_find(val)` | De Bruijn pattern |  
| `xor(data, key)` | XOR data |  
| `context.arch` | Target architecture |  
| `context.log_level` | Log verbosity |

---

> **Takeaway:** pwntools is the natural complement to GDB for RE: where GDB observes, pwntools acts. Its tube abstraction (`process`, `remote`) allows interacting with any binary programmatically, and its GDB integration (`gdb.debug`, `gdb.attach`) allows combining Python automation with the debugger's interactive inspection. The trio ELF + process + GDB in a single Python script forms a complete, reproducible, and shareable analysis workflow — exactly what's needed to move from analysis to producing a keygen or a replacement client.

⏭️ [🎯 Checkpoint: write a GDB Python script that automatically dumps the arguments of each call to `strcmp`](/11-gdb/checkpoint.md)
