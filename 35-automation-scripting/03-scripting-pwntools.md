🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 35.3 — RE Scripting with `pwntools` (Interactions, Patching, Exploitation)

> 📦 **Library**: `pwntools` 4.x (Python 3)  
> 🐍 **Installation**: `pip install pwntools`  
> 📁 **Example binaries**: `keygenme_O0`, `crypto_O0`, `fileformat_O0`, network binaries from Chapter 23

---

## `pwntools` beyond exploitation

In Chapter 11 (section 9), we introduced `pwntools` as a tool for interacting with binaries — launching a process, sending data, receiving output. In Chapter 21 (section 8), we used it to write a keygen. These uses represent only a fraction of what the library offers.

`pwntools` is a complete framework for offensive security scripting, but its primitives are equally useful in a defensive reverse engineering and automation context. Its strengths for RE are the following: programmatic interaction with local and remote processes (via uniform tubes), fine-grained binary data manipulation (packing/unpacking, pattern searching), patching of ELF binaries on disk, integration with GDB for scriptable debugging, and on-the-fly assembly/disassembly.

This section organizes these capabilities around three axes: interacting with a binary, patching it, and combining both in an automated analysis workflow.

---

## Configuration and context

Before any `pwntools` script, you configure the global context that determines the target architecture, endianness, and verbosity level:

```python
from pwn import *

# Configuration for our x86-64 Linux binaries
context.arch = 'amd64'  
context.os = 'linux'  
context.log_level = 'info'   # 'debug' to see all exchanges  
```

The context influences the behavior of all packing functions (`p32`, `p64`, `u32`, `u64`), assembly (`asm`), and shellcode generation. For our binaries compiled with GCC on Linux x86-64, the above configuration will be the same in all scripts in this section.

---

## Part A — Interacting with a Process

### Launching a binary and communicating

The `process` class creates a tube connected to the stdin/stdout streams of a local process. The `sendline()`, `recvuntil()`, `recvline()` methods enable structured communication:

```python
from pwn import *

def test_key(username, key):
    """Launch keygenme_O0 and test a username/key pair."""
    p = process("./keygenme_O0")

    # Wait for the prompt and send the username
    p.recvuntil(b"Enter username: ")
    p.sendline(username.encode())

    # Wait for the prompt and send the key
    p.recvuntil(b"XXXX-XXXX-XXXX-XXXX): ")
    p.sendline(key.encode())

    # Read the response
    response = p.recvall(timeout=2)
    p.close()

    return b"Valid license" in response

# Quick test
if test_key("alice", "0000-0000-0000-0000"):
    print("Key accepted!")
else:
    print("Key rejected (expected).")
```

This pattern is the foundation of any automated validation script. You can use it to verify that a keygen produces accepted keys, or to fuzz inputs and observe the binary's behavior.

### Network interactions

For the network binaries from Chapter 23, `pwntools` offers the `remote` class which provides exactly the same interface as `process`, but over a TCP connection:

```python
from pwn import *

# Connect to the Chapter 23 server
r = remote("127.0.0.1", 4444)

# The communication is identical to a local process
r.recvuntil(b"Welcome")  
r.sendline(b"AUTH user pass")  
response = r.recvline()  
print(f"Server response: {response}")  

r.close()
```

The uniformity of the interface is a considerable advantage. A script developed locally with `process` can be switched to a remote server by replacing a single line — which is exactly what is done in CTFs and in network protocol analysis.

### Interchangeable tubes

To make a script target-agnostic, a common pattern is used: an argument that selects the connection mode.

```python
from pwn import *  
import sys  

def get_tube():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return remote("target.example.com", 4444)
    else:
        return process("./keygenme_O0")

io = get_tube()
# ... the rest of the script is identical regardless of mode
io.close()
```

---

## Part B — Binary Data Manipulation

### Packing and unpacking

`pwntools` provides conversion functions between numeric values and binary representations, in the endianness configured in the context. These functions are ubiquitous in RE scripts:

```python
from pwn import *  
context.arch = 'amd64'  

# Pack a 32-bit integer in little-endian
packed = p32(0x5A3C6E2D)    # HASH_SEED from keygenme  
print(packed)                # b'\x2d\x6e\x3c\x5a'  

# Unpack bytes read from a binary
value = u32(b'\xef\xbe\xad\xde')  
print(f"0x{value:08x}")     # 0xdeadbeef — HASH_XOR from keygenme  

# 64 bits
entry = p64(0x401060)  
addr = u64(b'\x60\x10\x40\x00\x00\x00\x00\x00')  

# Signed packing
neg = p32(-1, signed=True)  # b'\xff\xff\xff\xff'

# Force big-endian on the fly
be = p32(0xDEADBEEF, endian='big')  # b'\xde\xad\xbe\xef'
```

Compared to the standard library's `struct.pack` / `struct.unpack`, these functions are more concise and context-aware — `p32(x)` replaces `struct.pack("<I", x)`, which reduces noise in scripts that manipulate lots of binary data.

### Searching for patterns in a binary

The `ELF` class from `pwntools` loads a binary and exposes its sections, symbols, and a search engine:

```python
from pwn import *

elf = ELF("./keygenme_O0")

# Basic information
print(f"Arch :  {elf.arch}")  
print(f"Entry : {hex(elf.entry)}")  
print(f"PIE :   {elf.pie}")  

# Access symbols (non-stripped binary)
if 'check_license' in elf.symbols:
    addr = elf.symbols['check_license']
    print(f"check_license @ {hex(addr)}")

if 'main' in elf.symbols:
    print(f"main @ {hex(elf.symbols['main'])}")

# Imports (PLT)
if 'strcmp' in elf.plt:
    print(f"strcmp@plt : {hex(elf.plt['strcmp'])}")

# GOT
if 'strcmp' in elf.got:
    print(f"strcmp@got : {hex(elf.got['strcmp'])}")
```

The `search()` method scans the raw binary data for a byte sequence:

```python
from pwn import *

elf = ELF("./keygenme_O0")

# Search for the HASH_SEED constant (0x5A3C6E2D) in little-endian
seed_bytes = p32(0x5A3C6E2D)  
for addr in elf.search(seed_bytes):  
    print(f"HASH_SEED found at {hex(addr)}")

# Search for a string
for addr in elf.search(b"KeyGenMe"):
    print(f"Banner found at {hex(addr)}")

# Search for the HASH_XOR constant (0xDEADBEEF)
for addr in elf.search(p32(0xDEADBEEF)):
    print(f"HASH_XOR found at {hex(addr)}")
```

On `keygenme_O0`, this script will locate `HASH_SEED` in `.text` (as an immediate operand of a `mov` instruction) and possibly in the DWARF information, as well as the banner in `.rodata`. On `crypto_O0`, be careful: `KEY_MASK` is a byte array (`unsigned char[]`), not a `uint32_t` — the bytes `DE AD BE EF` are stored in that order in memory. You must therefore search for the raw sequence `b"\xDE\xAD\xBE\xEF"`, and not `p32(0xDEADBEEF)` which would produce `EF BE AD DE` (little-endian). In contrast, `HASH_XOR` in `keygenme.c` is a `uint32_t` used as an immediate operand — the compiler encodes it in LE, and `p32` finds it correctly.

### Building and parsing binary structures

For custom formats like the one from Chapter 25 (CFR archive), `pwntools` offers a concise way to build and parse binary packets. Combined with `struct` or the `flat()` method, you can reproduce the format in a few lines:

```python
from pwn import *  
import struct  
import time  

def build_cfr_header(num_records, flags=0x02, author=b"analyst"):
    """Build a 32-byte CFR header conforming to the ch25 format."""
    magic = b"CFRM"
    version = 0x0002
    timestamp = int(time.time())

    # Pack the first 16 bytes (for CRC)
    first_16 = struct.pack("<4sHHII",
                           magic, version, flags,
                           num_records, timestamp)

    # CRC-32 of the first 16 bytes (simplified here)
    import zlib
    header_crc = zlib.crc32(first_16) & 0xFFFFFFFF

    # Complete: CRC(4) + author(8) + reserved(4) = 16 bytes
    author_padded = author.ljust(8, b'\x00')[:8]
    reserved = p32(0)  # will be recalculated based on data_len

    header = first_16 + p32(header_crc) + author_padded + reserved
    assert len(header) == 32
    return header

hdr = build_cfr_header(num_records=2, flags=0x03)  
print(f"CFR Header: {hdr.hex()}")  
print(f"Size: {len(hdr)} bytes")  
```

This pattern is exactly the one used in Chapter 25, section 4 to write an independent Python parser/serializer. `pwntools` does not replace `struct`, but its packing functions shorten the code when manipulating many values of varying sizes.

---

## Part C — Patching ELF Binaries

### Patching with the `ELF` class

The `ELF` class from `pwntools` allows you to modify a binary in memory and then write it to disk. It is simpler than `lief` for one-off patches and well integrated into the `pwntools` workflow:

```python
from pwn import *

elf = ELF("./keygenme_O0")

# Read the byte at the check_license address
check_addr = elf.symbols['check_license']  
print(f"check_license @ {hex(check_addr)}")  

# Search for the first JNZ (0x75) after the strcmp call in check_license
# Read a block of bytes around the function
func_bytes = elf.read(check_addr, 200)

# Locate the strcmp@plt call (opcode E8 + relative offset)
strcmp_plt = elf.plt['strcmp']
# Search for the JNZ (0x75) pattern following the strcmp return test
# In check_license compiled with -O0, the typical sequence is:
#   call strcmp@plt
#   test eax, eax      (85 C0)
#   jne  .Lfail        (75 xx)
pattern = b'\x85\xc0\x75'  
offset = func_bytes.find(pattern)  

if offset >= 0:
    # The 0x75 byte is at check_addr + offset + 2
    jnz_addr = check_addr + offset + 2
    print(f"JNZ found at {hex(jnz_addr)}")

    # Replace JNZ (0x75) with JZ (0x74)
    elf.write(jnz_addr, b'\x74')
    elf.save("./keygenme_O0_cracked")
    print("[+] Patched binary saved")
else:
    print("[-] Pattern not found")
```

This script automates exactly the manual patching performed with ImHex in Chapter 21, section 6. Searching for the pattern `test eax, eax` followed by `jnz` is more robust than an isolated search for `0x75` — the triplet `\x85\xc0\x75` is characteristic of the `strcmp` return test in non-optimized code.

### Verifying the patch

After patching the binary, we automatically verify that it accepts any key:

```python
from pwn import *

def verify_crack(binary_path, username, fake_key):
    """Verify that a patched binary accepts an arbitrary key."""
    p = process(binary_path)
    p.recvuntil(b"Enter username: ")
    p.sendline(username.encode())
    p.recvuntil(b"XXXX-XXXX-XXXX-XXXX): ")
    p.sendline(fake_key.encode())
    response = p.recvall(timeout=2)
    p.close()
    return b"Valid license" in response

# The key is intentionally wrong
assert verify_crack("./keygenme_O0_cracked", "test_user", "AAAA-BBBB-CCCC-DDDD")  
print("[+] Crack verified: any key is accepted")  
```

The patch -> verification chain in a single script is a fundamental pattern in RE automation. It guarantees that the transformation had the expected effect and documents the result in a reproducible manner.

---

## Part D — On-the-fly Assembly and Disassembly

`pwntools` integrates an assembler and a disassembler that require no external tools (they use `keystone` and `capstone` under the hood when available, with a fallback to GNU binutils).

### Assembling instructions

```python
from pwn import *  
context.arch = 'amd64'  

# Assemble a single instruction
nop = asm('nop')  
print(f"nop = {nop.hex()}")  # 90  

# Assemble a block
code = asm('''
    xor rdi, rdi
    mov rax, 60
    syscall
''')
print(f"exit(0) = {code.hex()}")

# Useful for patching: generate the correct opcode
jz_short = asm('jz $+0x10')  
print(f"jz +16 = {jz_short.hex()}")  
```

In an RE context, on-the-fly assembly is used to generate the replacement bytes during a patch, without having to remember opcode encodings. If you want to replace a `jnz` with an unconditional jump to a specific address, `asm()` produces the correct bytes automatically.

### Disassembling bytes

```python
from pwn import *  
context.arch = 'amd64'  

# Disassemble bytes read from a binary
raw = bytes.fromhex("554889e54883ec10897dfc")  
print(disasm(raw))  
```

Output:

```
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp, rsp
   4:   48 83 ec 10             sub    rsp, 0x10
   8:   89 7d fc                mov    DWORD PTR [rbp-0x4], edi
```

You immediately recognize the classic prologue of a GCC function compiled with `-O0`: saving `rbp`, setting up the frame, allocating local space, saving the first argument (`edi`) into a local variable.

### Disassembling an entire function

By combining the `ELF` class and `disasm`, you can extract and disassemble any function from a non-stripped binary:

```python
from pwn import *  
context.arch = 'amd64'  

elf = ELF("./keygenme_O0", checksec=False)

# Read the bytes of compute_hash
func_addr = elf.symbols['compute_hash']
# Read a reasonable block (the exact size is in the DWARF symbols,
# but 512 bytes is enough for a function of this size)
func_bytes = elf.read(func_addr, 512)

print(f"=== compute_hash @ {hex(func_addr)} ===")  
print(disasm(func_bytes, vma=func_addr))  
```

The `vma` (Virtual Memory Address) parameter adjusts the displayed addresses so they correspond to the actual addresses in the binary — jumps and calls will show their correct targets rather than offsets relative to zero.

---

## Part E — GDB Integration

`pwntools` can launch a process attached to GDB, which allows scripting complex debugging sessions. This is the bridge between automation and fine-grained dynamic analysis.

### Launching a process under GDB

```python
from pwn import *  
context.arch = 'amd64'  

# Launch keygenme_O0 under GDB with automated commands
p = gdb.debug("./keygenme_O0", '''
    break check_license
    continue
''')

# Send the inputs
p.recvuntil(b"Enter username: ")  
p.sendline(b"alice")  
p.recvuntil(b"XXXX-XXXX-XXXX-XXXX): ")  
p.sendline(b"AAAA-BBBB-CCCC-DDDD")  

# At this point, GDB is stopped on the breakpoint in check_license.
# The analyst can interact manually with GDB in the terminal,
# or the script can continue automatically.
p.interactive()
```

The `gdb.debug()` call opens a separate GDB terminal, attached to the process. The Python script continues to control stdin/stdout while GDB controls execution. This is extremely powerful for reproducing a specific scenario — for example, automatically navigating to the key comparison point, then manually inspecting registers.

### Automated GDB script

For full automation without manual interaction, you can pass a more elaborate GDB script that dumps the desired information:

```python
from pwn import *  
context.arch = 'amd64'  

# GDB script that dumps strcmp arguments
gdb_script = '''
    set pagination off
    break strcmp
    commands
        silent
        printf "strcmp(\\"%s\\", \\"%s\\")\\n", (char*)$rdi, (char*)$rsi
        continue
    end
    continue
'''

p = gdb.debug("./keygenme_O0", gdb_script)

p.recvuntil(b"Enter username: ")  
p.sendline(b"alice")  
p.recvuntil(b"XXXX-XXXX-XXXX-XXXX): ")  
p.sendline(b"AAAA-BBBB-CCCC-DDDD")  

# Let the program finish
response = p.recvall(timeout=3)  
p.close()  
```

In the GDB terminal, you will see the line `strcmp("XXXX-XXXX-XXXX-XXXX", "AAAA-BBBB-CCCC-DDDD")` — the first argument is the expected key, computed by `check_license`. This script automates exactly the Chapter 11 checkpoint (write a GDB script that dumps the arguments of each `strcmp` call), but driven from Python rather than from a `.gdb` file.

---

## Part F — Complete Automated Keygen

By combining everything above, here is a complete keygen for `keygenme_O0` that works in two steps: extracting the expected key via GDB, then automatic verification.

```python
#!/usr/bin/env python3
"""
keygen_auto.py — Automated keygen for keygenme (all variants)

Strategy:
  1. Launch the binary under GDB
  2. Set a breakpoint on strcmp
  3. Send a username and a dummy key
  4. Read the expected key from RDI at the strcmp call
  5. Relaunch the binary cleanly with the correct key
  6. Verify that the license is accepted

Usage: python3 keygen_auto.py <binary> <username>
"""

from pwn import *  
import sys  
import re  

context.arch = 'amd64'  
context.log_level = 'warn'  # Reduce noise  

def extract_expected_key(binary, username):
    """Launch the binary under GDB and extract the expected key."""

    # GDB script: breakpoint on strcmp, print RDI (1st argument)
    gdb_script = '''
        set pagination off
        break strcmp
        commands
            silent
            printf "KEYDUMP:%s\\n", (char*)$rdi
            continue
        end
        continue
    '''

    p = gdb.debug(binary, gdb_script, level='warn')

    p.recvuntil(b"Enter username: ")
    p.sendline(username.encode())
    p.recvuntil(b"XXXX-XXXX-XXXX-XXXX): ")
    p.sendline(b"AAAA-BBBB-CCCC-DDDD")

    # Read all output (GDB + program)
    try:
        output = p.recvall(timeout=5).decode(errors='replace')
    except Exception:
        output = ""
    p.close()

    # Extract the key from KEYDUMP:XXXX-XXXX-XXXX-XXXX format
    match = re.search(r'KEYDUMP:([0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4})',
                      output)
    if match:
        return match.group(1)
    return None

def verify_key(binary, username, key):
    """Verify that the username/key pair is accepted."""
    p = process(binary)
    p.recvuntil(b"Enter username: ")
    p.sendline(username.encode())
    p.recvuntil(b"XXXX-XXXX-XXXX-XXXX): ")
    p.sendline(key.encode())
    response = p.recvall(timeout=2)
    p.close()
    return b"Valid license" in response

if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else "./keygenme_O0"
    username = sys.argv[2] if len(sys.argv) > 2 else "student"

    print(f"[*] Target   : {binary}")
    print(f"[*] Username : {username}")

    key = extract_expected_key(binary, username)
    if key:
        print(f"[+] Extracted key: {key}")
        if verify_key(binary, username, key):
            print(f"[+] Verification succeeded")
        else:
            print(f"[-] Verification failed (extraction bug?)")
    else:
        print("[-] Unable to extract the key")
```

This script works on all keygenme variants — including stripped versions — because it does not depend on the target binary's symbols: `strcmp` is a dynamic import whose symbol is always present in `.dynsym`, even after `strip --strip-all`. This is a crucial point: PLT symbols survive stripping.

---

## Part G — Automating CFR Format Analysis

For the `fileformat_O0` binary from Chapter 25, `pwntools` serves both to interact with the program and to validate an independent Python parser. Here is a script that generates a CFR archive, inspects it with the official binary, then compares the result with direct parsing:

```python
from pwn import *  
import struct  
import tempfile  
import os  

context.log_level = 'warn'

def cfr_list_via_binary(binary, archive_path):
    """Use the official binary to list the contents of an archive."""
    p = process([binary, "list", archive_path])
    output = p.recvall(timeout=5).decode()
    p.close()
    return output

def cfr_validate_via_binary(binary, archive_path):
    """Run the binary's built-in validation."""
    p = process([binary, "validate", archive_path])
    output = p.recvall(timeout=5).decode()
    ret = p.poll()
    p.close()
    return ret == 0, output

# Generate a test archive
with tempfile.TemporaryDirectory() as tmpdir:
    archive = os.path.join(tmpdir, "test.cfr")
    p = process(["./fileformat_O0", "generate", archive])
    p.recvall(timeout=5)
    p.close()

    # List contents via the binary
    listing = cfr_list_via_binary("./fileformat_O0", archive)
    print("=== Listing via binary ===")
    print(listing)

    # Validate integrity
    ok, details = cfr_validate_via_binary("./fileformat_O0", archive)
    print(f"=== Validation: {'PASS' if ok else 'FAIL'} ===")
    print(details)

    # Parse the archive directly in Python for comparison
    with open(archive, "rb") as f:
        magic = f.read(4)
        version, flags, num_rec, timestamp = struct.unpack("<HHII", f.read(12))
        print(f"\n=== Direct Python parsing ===")
        print(f"Magic   : {magic}")
        print(f"Version : 0x{version:04x}")
        print(f"Flags   : 0x{flags:04x}")
        print(f"Records : {num_rec}")
```

This double-verification pattern — official binary result vs independent parsing — is characteristic of the RE approach: you use the binary as an oracle to validate your understanding of the format, and divergences reveal errors in your parser or subtleties of the format you have not yet understood.

---

## Summary of `pwntools` primitives for RE

| Primitive | RE usage | Example |  
|---|---|---|  
| `process()` | Launch and communicate with a local binary | Test a keygen, fuzz inputs |  
| `remote()` | TCP connection to a remote service | Network protocol analysis (ch23) |  
| `ELF()` | Load a binary, access symbols | Locate `check_license`, `strcmp@plt` |  
| `elf.search()` | Search for bytes in the binary | Find magic constants |  
| `elf.write()` / `elf.save()` | Patch bytes and save | Invert a conditional jump |  
| `p32()` / `u32()` / `p64()` / `u64()` | Integer <-> bytes conversion | Parse binary headers |  
| `asm()` | Assemble instructions | Generate patch bytes |  
| `disasm()` | Disassemble bytes | Inspect a function |  
| `gdb.debug()` | Launch a process under GDB | Extract the key at the comparison point |  
| `flat()` | Build a structured binary buffer | Forge packets or headers |  
| `context.arch` | Configure the target architecture | `amd64`, `i386`, `arm`, `mips` |

The strength of `pwntools` is the unification of these primitives within a single coherent framework. A script that starts by loading an ELF, locates a function, disassembles it, identifies the patch point, modifies the binary, relaunches it, interacts with it, and verifies the result — all of this fits in a single Python file of a few dozen lines, with no external tools.

---


⏭️ [Writing YARA rules to detect patterns across a collection of binaries](/35-automation-scripting/04-yara-rules.md)
