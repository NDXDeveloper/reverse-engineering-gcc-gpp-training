🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 29 Checkpoint

> **Spoilers** — This document contains the complete solution for the chapter 29 checkpoint. Only consult it after producing your own deliverables.

---

## Deliverable 1 — Detection Report

### 1.1 — `file`

```
$ file packed_sample_upx_tampered
packed_sample_upx_tampered: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),  
statically linked, no section header  
```

**Interpretation:**

- `statically linked` — Abnormal for a GCC program using `printf`, `fgets`, `strcmp`, etc., which are normally resolved dynamically via libc. The binary was made self-contained by the packer.  
- `no section header` — The section table has been removed. The file remains executable (the kernel only uses program headers), but static analysis tools lose all visibility into the internal structure.

→ **Indicator 1 ✓** (abnormal structure for a standard GCC binary)

### 1.2 — `strings`

```
$ strings packed_sample_upx_tampered | wc -l
9

$ strings packed_sample_O2_strip | wc -l
87
```

The target binary contains only 9 readable strings (essentially those from the stub) versus 87 for the unpacked version. No functional program strings (banner, messages, flag) are visible.

Examination of the few present strings:

```
$ strings packed_sample_upx_tampered
FKP!  
XP_0  
XP_1  
linux/x86  
...
```

Note `FKP!` and the names `XP_0`, `XP_1` — artifacts of UPX signature tampering (`UPX!` → `FKP!`, `UPX0` → `XP_0`, `UPX1` → `XP_1`).

→ **Indicator 2 ✓** (near-absence of strings)  
→ **Indicator 8 ✓** (tampered signatures recognizable as UPX-derived)

### 1.3 — `checksec`

```
$ checksec --file=packed_sample_upx_tampered
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

All standard GCC protections have disappeared. By comparison, the original binary (before packing) had at minimum Partial RELRO and a stack canary. The simultaneous disappearance of NX, canary, and RELRO is characteristic of compiled code being replaced by a packer stub.

→ **Indicator 5 ✓** (protections absent)

### 1.4 — `readelf -l` (program headers)

```
$ readelf -l packed_sample_upx_tampered

Elf file type is EXEC (Executable file)  
Entry point 0x4013e8  
There are 3 program headers, starting at offset 64  

Program Headers:
  Type    Offset             VirtAddr           PhysAddr
          FileSiz            MemSiz              Flags  Align
  LOAD    0x0000000000000000 0x0000000000400000 0x0000000000400000
          0x0000000000000000 0x0000000000004000  RW     0x1000
  LOAD    0x0000000000000000 0x0000000000404000 0x0000000000404000
          0x0000000000001bf4 0x0000000000001bf4  RWE    0x1000
  LOAD    0x0000000000001794 0x0000000000607794 0x0000000000607794
          0x0000000000000000 0x0000000000000000  RW     0x1000
```

Two major anomalies:

- The second segment has **`RWE`** flags (Read-Write-Execute). A normal binary never has a segment that is simultaneously writable and executable: code is `R-X`, data is `RW-`. The `RWE` flag is necessary for the stub to write the decompressed code and then execute it.  
- The first segment has a `FileSiz` of **0** but a `MemSiz` of `0x4000` (16 KB). The loader will allocate 16 KB of memory but copy nothing from the file — this is the destination zone where the stub will decompress the original code. The `MemSiz`/`FileSiz` ratio is infinite.

→ **Indicator 3 ✓** (RWE segment)  
→ **Indicator 4 ✓** (MemSiz ≫ FileSiz ratio)

### 1.5 — `readelf -S` (section headers)

```
$ readelf -S packed_sample_upx_tampered
There are no sections in this file.
```

The section table is completely absent.

→ **Indicator 2b ✓** (sections absent)

### 1.6 — Entropy

```
$ python3 -c "
import math, sys  
from collections import Counter  

data = open('packed_sample_upx_tampered', 'rb').read()  
counts = Counter(data)  
length = len(data)  
ent = -sum((c/length) * math.log2(c/length) for c in counts.values())  
print(f'Size    : {length} bytes')  
print(f'Entropy : {ent:.4f} bits/byte')  
"
Size    : 7152 bytes  
Entropy : 7.6823 bits/byte  
```

The overall entropy is **7.68**, well above the 7.5 threshold that indicates compressed or encrypted data. For comparison, the unpacked binary has an entropy of approximately 5.8.

→ **Indicator 6 ✓** (entropy > 7.5)

You can also verify visually in ImHex (View → Data Information): the byte distribution histogram is nearly flat.

→ **Indicator 7 ✓** (uniform distribution)

### 1.7 — Detection Report Conclusion

**7 out of 8 indicators** converge toward a packing diagnosis:

| # | Indicator | Result |  
|---|-----------|--------|  
| 1 | Few readable strings | ✓ — 9 strings vs 87 |  
| 2 | Sections absent | ✓ — `no section header` |  
| 3 | RWE segment | ✓ — second LOAD with RWE flags |  
| 4 | MemSiz ≫ FileSiz | ✓ — 0x4000 vs 0x0000 |  
| 5 | Protections absent | ✓ — NX off, no canary, no RELRO |  
| 6 | Entropy > 7.5 | ✓ — 7.68 bits/byte |  
| 7 | Uniform distribution | ✓ — flat ImHex histogram |  
| 8 | Packer signature | ✓ partial — `FKP!`, `XP_0`, `XP_1` (tampered UPX) |

**Packer identified: UPX with tampered signatures** (`UPX!` → `FKP!`, `UPX0` → `XP_0`, `UPX1` → `XP_1`). The `upx -d` command will fail; an approach via magic byte restoration or dynamic memory dump is required.

---

## Deliverable 2 — Decompressed Binary

Two approaches are presented below. Both are valid.

### Approach A — Signature Restoration + `upx -d`

Restore the magic bytes in a copy of the binary:

```python
#!/usr/bin/env python3
# restore_upx_magic.py

import sys, shutil

src = "packed_sample_upx_tampered"  
dst = "packed_sample_upx_fixed"  

shutil.copy2(src, dst)

data = open(dst, "rb").read()  
data = data.replace(b"FKP!", b"UPX!")  
data = data.replace(b"XP_0", b"UPX0")  
data = data.replace(b"XP_1", b"UPX1")  
data = data.replace(b"XP_2", b"UPX2")  
open(dst, "wb").write(data)  

n = data.count(b"UPX!")  
print(f"[+] Signatures restored ({n} occurrence(s) of UPX!)")  
print(f"[+] File: {dst}")  
```

```
$ python3 restore_upx_magic.py
[+] Signatures restored (1 occurrence(s) of UPX!)
[+] File: packed_sample_upx_fixed

$ upx -d packed_sample_upx_fixed
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     18472 <-      7152   38.72%   linux/amd64   packed_sample_upx_fixed

Unpacked 1 file.

$ file packed_sample_upx_fixed
packed_sample_upx_fixed: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ...  

$ strings packed_sample_upx_fixed | grep FLAG
FLAG{unp4ck3d_and_r3c0nstruct3d}
```

The ELF is complete: `upx -d` restores sections, program headers, and the original entry point. This is the cleanest method.

### Approach B — Memory Dump with GDB + LIEF Reconstruction

This approach is more general and works even when magic byte restoration is not possible.

#### B.1 — Finding the OEP

```
$ gdb -q ./packed_sample_upx_tampered

gef➤ info file  
Entry point: 0x4013e8  

gef➤ # The first LOAD segment has vaddr=0x400000, memsz=0x4000  
gef➤ # The decompressed code will be written starting at 0x400000  
gef➤ # Set a hardware breakpoint at the probable start of .text  
gef➤ hbreak *0x401000  
Hardware assisted breakpoint 1 at 0x401000  

gef➤ run  
Starting program: ./packed_sample_upx_tampered  

Breakpoint 1, 0x0000000000401000 in ?? ()
```

The OEP is **`0x401000`**. We verify that the code at this address looks like legitimate code:

```
gef➤ x/5i $rip
=> 0x401000:  endbr64
   0x401004:  xor    ebp,ebp
   0x401006:  mov    r9,rdx
   0x401009:  pop    rsi
   0x40100a:  mov    rdx,rsp
```

This is the classic `_start` prologue (GCC CRT code). The stub has finished its work.

#### B.2 — Mapping and Dumping

```
gef➤ vmmap  
Start              End                Perm  Path  
0x0000000000400000 0x0000000000401000 r--p  packed_sample_upx_tampered
0x0000000000401000 0x0000000000404000 r-xp  packed_sample_upx_tampered
0x0000000000404000 0x0000000000405000 r--p  packed_sample_upx_tampered
0x0000000000405000 0x0000000000406000 rw-p  packed_sample_upx_tampered
...

gef➤ dump binary memory /tmp/hdr.bin  0x400000 0x401000  
gef➤ dump binary memory /tmp/text.bin 0x401000 0x404000  
gef➤ dump binary memory /tmp/ro.bin   0x404000 0x405000  
gef➤ dump binary memory /tmp/rw.bin   0x405000 0x406000  
```

#### B.3 — Reconstructing with LIEF

```python
#!/usr/bin/env python3
# reconstruct_elf.py

import lief

OEP = 0x401000

regions = [
    ("/tmp/hdr.bin",  0x400000, "r--", None),
    ("/tmp/text.bin", 0x401000, "r-x", ".text"),
    ("/tmp/ro.bin",   0x404000, "r--", ".rodata"),
    ("/tmp/rw.bin",   0x405000, "rw-", ".data"),
]

elf = lief.ELF.Binary("reconstructed", lief.ELF.ELF_CLASS.CLASS64)  
elf.header.entrypoint = OEP  
elf.header.file_type  = lief.ELF.E_TYPE.EXECUTABLE  

for path, vaddr, perms, name in regions:
    data = list(open(path, "rb").read())

    seg = lief.ELF.Segment()
    seg.type             = lief.ELF.SEGMENT_TYPES.LOAD
    seg.flags            = 0
    if "r" in perms: seg.flags |= lief.ELF.SEGMENT_FLAGS.R
    if "w" in perms: seg.flags |= lief.ELF.SEGMENT_FLAGS.W
    if "x" in perms: seg.flags |= lief.ELF.SEGMENT_FLAGS.X
    seg.virtual_address  = vaddr
    seg.physical_address = vaddr
    seg.alignment        = 0x1000
    seg.content          = data
    elf.add(seg)

    if name:
        sec = lief.ELF.Section(name)
        sec.content         = data
        sec.virtual_address = vaddr
        sec.alignment       = 0x10
        if "x" in perms:
            sec.type  = lief.ELF.SECTION_TYPES.PROGBITS
            sec.flags = (lief.ELF.SECTION_FLAGS.ALLOC |
                         lief.ELF.SECTION_FLAGS.EXECINSTR)
        elif "w" in perms:
            sec.type  = lief.ELF.SECTION_TYPES.PROGBITS
            sec.flags = (lief.ELF.SECTION_FLAGS.ALLOC |
                         lief.ELF.SECTION_FLAGS.WRITE)
        else:
            sec.type  = lief.ELF.SECTION_TYPES.PROGBITS
            sec.flags = lief.ELF.SECTION_FLAGS.ALLOC
        elf.add(sec, loaded=True)

elf.write("packed_sample_reconstructed")  
print("[+] ELF reconstructed: packed_sample_reconstructed")  
```

```
$ python3 reconstruct_elf.py
[+] ELF reconstructed: packed_sample_reconstructed

$ readelf -h packed_sample_reconstructed | grep "Entry point"
  Entry point address:               0x401000

$ readelf -S packed_sample_reconstructed | grep -E "text|rodata|data"
  [ 1] .text             PROGBITS         0000000000401000  ...
  [ 2] .rodata           PROGBITS         0000000000404000  ...
  [ 3] .data             PROGBITS         0000000000405000  ...

$ strings packed_sample_reconstructed | grep FLAG
FLAG{unp4ck3d_and_r3c0nstruct3d}
```

The binary is ready for analysis.

---

## Deliverable 3 — Logic Analysis

### 3.1 — Functions Identified in Ghidra

After importing into Ghidra and running auto-analysis, the following functions are identified (names manually assigned by the analyst, as the binary is stripped):

| Address (approx.) | Assigned name | Role |  
|--------------------|---------------|------|  
| `0x401000` | `_start` | CRT entry point, calls `__libc_start_main` |  
| `0x401150` | `main` | Main function: displays banner, reads input, calls verification |  
| `0x401290` | `check_license_key` | Verifies the format and validity of the entered key |  
| `0x401320` | `compute_checksum` | Computes a weighted checksum on a buffer |  
| `0x401360` | `xor_decode` | Decrypts a buffer via cyclic XOR with a key |  
| `0x4013a0` | `print_debug_info` | Displays internal metadata (`--debug` mode) |

> **Note** — Exact addresses vary depending on optimization level and GCC version. The addresses above are indicative for an `-O2` compilation.

### 3.2 — `check_license_key` Pseudo-code

Extracted from the Ghidra decompile, renamed and annotated:

```c
int check_license_key(char *key)
{
    /* Expected format is exactly 9 characters */
    if (strlen(key) != 9)
        return 0;

    /* The first 5 characters must be "RE29-" */
    if (strncmp(key, "RE29-", 5) != 0)
        return 0;

    /* The last 4 characters are interpreted as a hexadecimal number */
    char *endptr;
    unsigned long user_val = strtoul(key + 5, &endptr, 16);
    if (*endptr != '\0')
        return 0;

    /* The number must match the prefix's checksum */
    uint32_t expected = compute_checksum("RE29-", 5);
    return (user_val == expected);
}
```

### 3.3 — Checksum Algorithm

The `compute_checksum` decompile reveals the algorithm:

```c
uint32_t compute_checksum(char *buf, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += (uint32_t)buf[i] * (uint32_t)(i + 1);
    }
    return sum & 0xFFFF;
}
```

This is a **weighted sum** of ASCII codes, where each character's weight is its position (1-indexed), reduced modulo `0xFFFF` (16-bit mask).

### 3.4 — Computing the Valid Key

Applying `compute_checksum` to the prefix `"RE29-"`:

| Position (i) | Character | ASCII (decimal) | Weight (i+1) | Contribution |  
|--------------|-----------|-----------------|-------------|--------------|  
| 0            | `R`       | 82              | 1           | 82           |  
| 1            | `E`       | 69              | 2           | 138          |  
| 2            | `2`       | 50              | 3           | 150          |  
| 3            | `9`       | 57              | 4           | 228          |  
| 4            | `-`       | 45              | 5           | 225          |

```
sum = 82 + 138 + 150 + 228 + 225 = 823  
expected = 823 & 0xFFFF = 823 = 0x0337  
```

The valid key is therefore: **`RE29-0337`**

Quick verification in Python:

```python
>>> prefix = "RE29-"
>>> checksum = sum(ord(c) * (i+1) for i, c in enumerate(prefix)) & 0xFFFF
>>> f"RE29-{checksum:04X}"
'RE29-0337'
```

### 3.5 — XOR Routine

The `xor_decode` function performs a cyclic XOR between an encrypted message and an 8-byte key:

**XOR Key** (extracted from `.rodata` in Ghidra or ImHex):

```
DE AD BE EF CA FE BA BE
```

**Encrypted message** (8 bytes):

```
8D F8 FD AC 8F AD E9 9F
```

**Decryption**:

| Index | Encrypted | Key   | XOR   | ASCII |  
|-------|-----------|-------|-------|-------|  
| 0     | `0x8D`    | `0xDE`| `0x53`| `S`   |  
| 1     | `0xF8`    | `0xAD`| `0x55`| `U`   |  
| 2     | `0xFD`    | `0xBE`| `0x43`| `C`   |  
| 3     | `0xAC`    | `0xEF`| `0x43`| `C`   |  
| 4     | `0x8F`    | `0xCA`| `0x45`| `E`   |  
| 5     | `0xAD`    | `0xFE`| `0x53`| `S`   |  
| 6     | `0xE9`    | `0xBA`| `0x53`| `S`   |  
| 7     | `0x9F`    | `0xBE`| `0x21`| `!`   |

**Decrypted message: `SUCCESS!`**

### 3.6 — Crypto Constants (bonus)

In `.rodata`, at the address corresponding to `g_fake_sbox`, we identify the first 16 bytes of the AES S-box (appendix J):

```
63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
```

These constants are a classic marker of AES usage in a binary. In our program, they are present for educational purposes (variable `g_fake_sbox` not functionally used), but the identification technique is the same as on a real binary using AES.

---

## Deliverable 4 — Proof of Resolution

### Direct Execution (sandbox VM)

```
$ ./packed_sample_upx_tampered
╔══════════════════════════════════════╗
║   Ch29 — PackedSample v1.0           ║
║   RE Training — GNU Toolchain         ║
╚══════════════════════════════════════╝

[*] Enter your license key (format RE29-XXXX): RE29-0337

[+] Valid key! Decrypted message: SUCCESS!
[+] Flag: FLAG{unp4ck3d_and_r3c0nstruct3d}
[+] Congratulations, you recovered the logic after unpacking!
```

### GDB Proof (alternative)

```
$ gdb -q ./packed_sample_upx_tampered

gef➤ hbreak *0x401000  
gef➤ run  
Breakpoint 1, 0x0000000000401000 in ?? ()  

gef➤ # Set a breakpoint on check_license_key  
gef➤ break *0x401290  
gef➤ continue  

[*] Enter your license key (format RE29-XXXX): RE29-0337

Breakpoint 2, 0x0000000000401290 in ?? ()

gef➤ x/s $rdi
0x7fffffffe0a0: "RE29-0337"

gef➤ finish  
Value returned is $1 = 1  

gef➤ # return = 1 → valid key ✓
```

### pwntools Script (alternative)

```python
#!/usr/bin/env python3
# solve_ch29.py

from pwn import *

p = process("./packed_sample_upx_tampered")  
p.recvuntil(b"RE29-XXXX) : ")  
p.sendline(b"RE29-0337")  

response = p.recvall(timeout=2).decode()  
print(response)  

assert "FLAG{unp4ck3d_and_r3c0nstruct3d}" in response  
log.success("Checkpoint passed!")  
```

```
$ python3 solve_ch29.py
[+] Starting local process './packed_sample_upx_tampered': pid 12345

[+] Valid key! Decrypted message: SUCCESS!
[+] Flag: FLAG{unp4ck3d_and_r3c0nstruct3d}
[+] Congratulations, you recovered the logic after unpacking!

[+] Checkpoint passed!
```

---

## Self-Assessment Grid

| Criterion | Status |  
|-----------|--------|  
| Report cites ≥ 4 converging indicators | ✅ 7/8 indicators documented |  
| Packer identified as tampered UPX | ✅ `FKP!` / `XP_0` signatures identified |  
| Reconstructed ELF passes `readelf` without error | ✅ (approach A: complete / approach B: minimal but valid) |  
| Ghidra produces coherent disassembly | ✅ Functions identified, readable decompile |  
| Verification algorithm correctly described | ✅ Weighted checksum + 16-bit mask |  
| Key `RE29-0337` found and validated | ✅ Detailed calculation + execution proof |  
| SHT with `.text` and `.rodata` (recommended) | ✅ Approach B: 3 sections created |  
| `SUCCESS!` message recovered (recommended) | ✅ XOR decrypted byte by byte |  
| AES S-box constants spotted (bonus) | ✅ 16 bytes identified in `.rodata` |  
| Automated reconstruction script (bonus) | ✅ `reconstruct_elf.py` with LIEF |

---

⏭️
