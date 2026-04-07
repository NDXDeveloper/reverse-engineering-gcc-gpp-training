🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.8 — Writing a Keygen in Python with `pwntools`

> 📖 **Reminder**: using `pwntools` to interact with a binary (tubes, `process`, `send`/`recv`) is introduced in chapter 11, section 11.9. This section assumes the module is installed (`pip install pwntools`) and that you have already run a basic script.

---

## Introduction

The previous sections progressed from passive to intrusive: triage, static analysis, dynamic analysis, patching, symbolic execution. Each technique produced a result — but none required *understanding* the verification algorithm in its entirety.

Writing a keygen is the culmination of reverse engineering a crackme. A keygen (key generator) is a standalone program that, for any given username, computes and produces a valid license key. It does not bypass the verification — it **satisfies** it. To achieve this, you must have reconstructed the complete algorithm: the username hashing, the group derivation, and the key formatting.

This is the most demanding exercise of the chapter, but also the most rewarding: the keygen proves that you understood the binary end to end, to the point of being able to reproduce its logic in another language.

---

## Recap of the algorithm to reproduce

Static analysis in Ghidra (section 21.3) and dynamic confirmation in GDB (section 21.5) revealed the following processing chain inside `check_license`:

```
username (string)
    │
    ▼
compute_hash(username) → hash (uint32)
    │
    ▼
derive_key(hash, groups) → groups[4] (uint16 × 4)
    │
    ▼
format_key(groups, expected) → "XXXX-XXXX-XXXX-XXXX"
    │
    ▼
strcmp(expected, user_key) → 0 if match
```

The keygen must reproduce the first three steps. The fourth (`strcmp`) is the verification itself — the keygen does not need to compare, it directly produces the expected key.

---

## Step 1 — Reconstructing `compute_hash`

### Ghidra pseudo-C

Ghidra's decompiler produces pseudo-C similar to this for `compute_hash`:

```c
uint32_t compute_hash(char *username)
{
    uint32_t h = 0x5A3C6E2D;
    size_t len = strlen(username);

    for (size_t i = 0; i < len; i++) {
        h += (uint32_t)username[i];
        h *= 0x1003F;
        h = (h << (username[i] & 0xF)) | (h >> (32 - (username[i] & 0xF)));
        h ^= 0xDEADBEEF;
    }

    h ^= (h >> 16);
    h *= 0x45D9F3B;
    h ^= (h >> 16);

    return h;
}
```

Several elements must be identified and translated:

**Constants** — `0x5A3C6E2D` (initial seed), `0x1003F` (multiplier), `0xDEADBEEF` (XOR mask), `0x45D9F3B` (avalanche multiplier). These constants are visible directly in the disassembly as immediate operands (`mov reg, 0x5A3C6E2D`). They are the first landmark for identifying the hash function in an unknown binary.

**Left rotation** — The expression `(h << n) | (h >> (32 - n))` is the classic pattern for 32-bit left rotation. In the disassembly, GCC may emit a direct `ROL` (if the count is in `CL`) or the `SHL`/`SHR`/`OR` pair. Ghidra's decompiler often recognizes this pattern and presents it in compact form — but not always. If the pseudo-C shows two shifts and an OR, it is a rotation.

**32-bit truncation** — In C, operations on `uint32_t` automatically truncate to 32 bits. In Python, integers have no fixed size — you must manually mask with `& 0xFFFFFFFF` after each operation that can overflow.

### Translation to Python

```python
import struct

def rotate_left_32(value, count):
    """32-bit left rotation."""
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

def compute_hash(username: bytes) -> int:
    """Reproduces the keygenme's compute_hash function."""
    SEED = 0x5A3C6E2D
    MUL  = 0x1003F
    XOR  = 0xDEADBEEF

    h = SEED

    for byte in username:
        h = (h + byte) & 0xFFFFFFFF
        h = (h * MUL) & 0xFFFFFFFF
        h = rotate_left_32(h, byte & 0x0F)
        h ^= XOR

    # Final avalanche
    h ^= (h >> 16)
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)

    return h
```

### Cross-verification

The first thing to do after translating a function is to **verify** that it produces the same result as the binary. We use the key captured in GDB (section 21.5) as reference:

```python
h = compute_hash(b"Alice")  
print(f"Hash of 'Alice': 0x{h:08X}")  
```

If the hash is correct, the subsequent steps (`derive_key`, `format_key`) will produce the correct key. If the hash differs, the error is in the translation — the disassembly must be re-read instruction by instruction.

> 💡 **Debugging technique**: in case of divergence, intermediate values can be compared. In GDB, set a breakpoint at the beginning of the loop in `compute_hash` and display `h` at each iteration with an automated conditional breakpoint. In Python, add a `print(f"i={i} h=0x{h:08X}")` in the loop. The first diverging iteration points to the incorrectly translated instruction.

### Common translation pitfalls

**Integer signedness** — In C, `uint32_t` is unsigned. In Python, integers are signed and of arbitrary size. The `& 0xFFFFFFFF` mask is essential after each multiplication and addition to simulate unsigned 32-bit overflow. Forgetting a single mask can produce a completely different hash due to the cascade effect.

**Byte order** — `username[i]` in C accesses the i-th byte of the string. In Python, iterating over `bytes` (`for byte in username`) produces integers 0-255 — this is the correct behavior. Be careful not to iterate over a Python `str`, which would produce Unicode characters (code points potentially > 255).

**Rotation with count = 0** — When `username[i] & 0x0F` equals 0, the rotation does nothing. The expression `h >> (32 - 0)` is a 32-bit shift, which is undefined behavior in C on 32-bit types. In practice, GCC often compiles it as a 0-bit shift (no change), but in Python `h >> 32` gives 0. The guard `count &= 31` in `rotate_left_32` protects against this case: if `count` is 0, both shifts are 0 bits and the result is `h` unchanged.

---

## Step 2 — Reconstructing `derive_key`

### Ghidra pseudo-C

```c
void derive_key(uint32_t hash, uint16_t groups[4])
{
    groups[0] = (uint16_t)((hash & 0xFFFF) ^ 0xA5A5);
    groups[1] = (uint16_t)(((hash >> 16) & 0xFFFF) ^ 0x5A5A);
    groups[2] = (uint16_t)((rotate_left(hash, 7) & 0xFFFF) ^ 0x1234);
    groups[3] = (uint16_t)((rotate_left(hash, 13) & 0xFFFF) ^ 0xFEDC);
}
```

The four groups are independent transformations of the hash, each combining a 16-bit extraction (masking or rotation + masking) with an XOR by a constant.

### Translation to Python

```python
def derive_key(hash_val: int) -> list[int]:
    """Derives 4 16-bit groups from the hash."""
    groups = [
        (hash_val & 0xFFFF) ^ 0xA5A5,
        ((hash_val >> 16) & 0xFFFF) ^ 0x5A5A,
        (rotate_left_32(hash_val, 7) & 0xFFFF) ^ 0x1234,
        (rotate_left_32(hash_val, 13) & 0xFFFF) ^ 0xFEDC,
    ]
    return groups
```

The constants `0xA5A5`, `0x5A5A`, `0x1234`, `0xFEDC` are visible directly in the disassembly as immediate operands of `XOR` instructions. They are a reliable landmark for identifying this function, even in a stripped binary.

---

## Step 3 — Reconstructing `format_key`

### Ghidra pseudo-C

```c
void format_key(uint16_t groups[4], char *out)
{
    snprintf(out, 20, "%04X-%04X-%04X-%04X",
             groups[0], groups[1], groups[2], groups[3]);
}
```

The format string `"%04X-%04X-%04X-%04X"` was spotted during triage by `strings` (section 21.1). Each 16-bit group is displayed in uppercase hexadecimal, padded to 4 digits.

### Translation to Python

```python
def format_key(groups: list[int]) -> str:
    """Formats the 4 groups as a XXXX-XXXX-XXXX-XXXX key."""
    return "{:04X}-{:04X}-{:04X}-{:04X}".format(*groups)
```

---

## Step 4 — Assembling the keygen

### Standalone version

Combining the three functions, we get a minimal keygen:

```python
#!/usr/bin/env python3
"""
keygen_keygenme.py — Key generator for the keygenme (chapter 21).

Usage: python3 keygen_keygenme.py <username>
"""

import sys

# ── Functions reconstructed from disassembly ────────────────

def rotate_left_32(value, count):
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

def compute_hash(username: bytes) -> int:
    SEED = 0x5A3C6E2D
    MUL  = 0x1003F
    XOR  = 0xDEADBEEF

    h = SEED
    for byte in username:
        h = (h + byte) & 0xFFFFFFFF
        h = (h * MUL) & 0xFFFFFFFF
        h = rotate_left_32(h, byte & 0x0F)
        h ^= XOR

    h ^= (h >> 16)
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h

def derive_key(hash_val: int) -> list[int]:
    return [
        (hash_val & 0xFFFF) ^ 0xA5A5,
        ((hash_val >> 16) & 0xFFFF) ^ 0x5A5A,
        (rotate_left_32(hash_val, 7) & 0xFFFF) ^ 0x1234,
        (rotate_left_32(hash_val, 13) & 0xFFFF) ^ 0xFEDC,
    ]

def format_key(groups: list[int]) -> str:
    return "{:04X}-{:04X}-{:04X}-{:04X}".format(*groups)

def keygen(username: str) -> str:
    """Generates a valid key for the given username."""
    h = compute_hash(username.encode())
    groups = derive_key(h)
    return format_key(groups)

# ── Entry point ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <username>")
        print(f"  Username must be between 3 and 31 characters.")
        sys.exit(1)

    username = sys.argv[1]

    if len(username) < 3 or len(username) > 31:
        print("[-] Username must be between 3 and 31 characters.")
        sys.exit(1)

    key = keygen(username)
    print(f"[+] Username: {username}")
    print(f"[+] License : {key}")
```

### Execution

```bash
$ python3 keygen_keygenme.py Alice
[+] Username: Alice
[+] License : DCEB-0DFC-B51F-3428

$ python3 keygen_keygenme.py Bob
[+] Username: Bob
[+] License : 679E-0910-0F9D-94B5

$ python3 keygen_keygenme.py ReverseEngineer
[+] Username: ReverseEngineer
[+] License : 6865-6B66-F22C-F8FB
```

The keygen instantly produces a key for any username.

---

## Step 5 — Automated validation with `pwntools`

The standalone keygen generates keys, but validation remains manual: the key must be copied and pasted into the program. With `pwntools`, we can automate the entire process — generate the key *and* submit it to the binary for verification.

### Validation script

```python
#!/usr/bin/env python3
"""
validate_keygen.py — Generates a key and automatically submits it  
to the binary for validation.  

Usage: python3 validate_keygen.py [username]
"""

from pwn import *  
import sys  

# Import the keygen (same directory)
from keygen_keygenme import keygen

# ── Configuration ────────────────────────────────────────────
BINARY = "./keygenme_O0"  
USERNAME = sys.argv[1] if len(sys.argv) > 1 else "Alice"  

# ── Key generation ──────────────────────────────────────────
key = keygen(USERNAME)  
log.info(f"Username: {USERNAME}")  
log.info(f"Generated key: {key}")  

# ── Binary interaction ──────────────────────────────────────
p = process(BINARY)

# Wait for username prompt
p.recvuntil(b"Enter username: ")  
p.sendline(USERNAME.encode())  

# Wait for key prompt
p.recvuntil(b"Enter license key")  
p.recvuntil(b": ")  
p.sendline(key.encode())  

# Read response
response = p.recvall(timeout=2).decode().strip()  
p.close()  

# ── Verification ────────────────────────────────────────────
if "Valid license" in response:
    log.success(f"Validation successful: {response}")
else:
    log.failure(f"Validation failed: {response}")
    sys.exit(1)
```

### Execution

```bash
$ python3 validate_keygen.py Alice
[*] Username: Alice
[*] Generated key: DCEB-0DFC-B51F-3428
[+] Starting local process './keygenme_O0'
[+] Receiving all data: Done (36B)
[*] Stopped process './keygenme_O0' (pid 12345)
[+] Validation successful: [+] Valid license! Welcome, Alice.
```

### Mass testing

To validate the keygen exhaustively, we can automatically test hundreds of usernames:

```python
#!/usr/bin/env python3
"""
batch_validate.py — Mass test of keygen on N random usernames.
"""

from pwn import *  
import random  
import string  

from keygen_keygenme import keygen

BINARY = "./keygenme_O0"  
NUM_TESTS = 50  

context.log_level = "error"  # Silence pwntools for batch

def random_username(min_len=3, max_len=20):
    length = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

passed = 0  
failed = 0  

for i in range(NUM_TESTS):
    username = random_username()
    key = keygen(username)

    p = process(BINARY)
    p.recvuntil(b"Enter username: ")
    p.sendline(username.encode())
    p.recvuntil(b": ")
    p.sendline(key.encode())

    response = p.recvall(timeout=2).decode()
    p.close()

    if "Valid license" in response:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL: username='{username}' key='{key}'")
        print(f"        response: {response.strip()}")

print(f"\nResult: {passed}/{NUM_TESTS} validated, {failed} failures.")
```

```bash
$ python3 batch_validate.py
Result: 50/50 validated, 0 failures.
```

A 100% score on 50 random usernames confirms the keygen is correct. If a single test fails, there is an error in the translation — the failing username is a valuable test case for debugging.

---

## Step 6 — Testing on optimized variants

The keygen reproduces the source code algorithm — it does not depend on the binary's optimization level. The same key is valid for `keygenme_O0`, `keygenme_O2`, `keygenme_O3`, `keygenme_strip`, and `keygenme_O2_strip`, because the algorithm is identical in all five variants. Only the assembly representation changes.

This can be easily verified:

```python
for binary in ["./keygenme_O0", "./keygenme_O2", "./keygenme_O3",
               "./keygenme_strip", "./keygenme_O2_strip"]:
    p = process(binary)
    p.recvuntil(b"Enter username: ")
    p.sendline(b"Alice")
    p.recvuntil(b": ")
    p.sendline(keygen("Alice").encode())
    response = p.recvall(timeout=2).decode()
    p.close()

    status = "OK" if "Valid license" in response else "FAIL"
    print(f"  [{status}] {binary}")
```

```
  [OK] ./keygenme_O0
  [OK] ./keygenme_O2
  [OK] ./keygenme_O3
  [OK] ./keygenme_strip
  [OK] ./keygenme_O2_strip
```

This test confirms a fundamental principle: **optimization and stripping do not modify the program's semantics**. They make RE harder for the human analyst, but the observable behavior (inputs/outputs) remains identical.

---

## Anatomy of the reconstruction: from disassembly to Python

To summarize the translation methodology underlying this entire keygen, here is the general process applicable to any function:

### 1. Read Ghidra's pseudo-C

The decompiler provides a C skeleton. This skeleton is often imperfect: generic variable names, approximate types (`undefined4` instead of `uint32_t`), superfluous casts. But the structure (loops, conditions, calls) is correct in the vast majority of cases.

### 2. Cross-reference with the disassembly

When the pseudo-C is ambiguous, return to the assembly Listing. Assembly does not lie — it is the binary's truth. Pseudo-C is an *interpretation* by the decompiler, susceptible to decompilation errors.

Typical cases where the disassembly settles things:
- **Operand size**: the pseudo-C shows `int`, but the disassembly shows `EAX` (32-bit) vs `RAX` (64-bit) vs `AX` (16-bit). The exact size matters for masking and overflow.  
- **Signedness**: the pseudo-C may hesitate between `int` and `uint`. The choice between `IMUL` (signed) and `MUL` (unsigned), or between `SAR` (arithmetic shift) and `SHR` (logical shift), settles the question.  
- **Rotations**: the decompiler does not always recognize the pattern `(x << n) | (x >> (32-n))` as a rotation. It may display two separate operations.

### 3. Translate to Python

The translation is mechanical once the C is correct:
- `uint32_t` → Python `int` + `& 0xFFFFFFFF` mask after each operation.  
- `uint16_t` → Python `int` + `& 0xFFFF` mask.  
- `for (size_t i = 0; i < len; i++)` → `for byte in username:` (iteration over `bytes`).  
- `h << n | h >> (32-n)` → dedicated `rotate_left_32` function.  
- `snprintf(buf, 20, "%04X-...", ...)` → `"{:04X}-...".format(...)`.

### 4. Validate by comparison

Generate a key for a known username and compare with the value captured in GDB (section 21.5). If the values match, the translation is correct. Otherwise, debug by comparing intermediate values (hash before and after each loop iteration).

---

## When direct translation fails

On more complex binaries than our pedagogical keygenme, algorithm reconstruction may encounter several obstacles:

### Functions inlined at `-O2`/`-O3`

If `compute_hash` was inlined into `check_license`, you no longer see a separate function — just a code block in the middle of `check_license`. The logic is the same, but the boundaries are blurred. The reverse engineer's job is to recognize the patterns (loop, constants, rotation) and mentally isolate them.

### Standard crypto libraries

If the binary uses OpenSSL or libsodium for hashing (instead of a custom algorithm), there is no point in reconstructing the function — just identify which function from which library is used (chapter 24) and call the same function in Python:

```python
import hashlib  
h = hashlib.sha256(username).hexdigest()  
```

Detection is done via magic constants (Appendix J) or FLIRT/Ghidra signatures (chapter 20, section 5).

### Irreversible algorithms

Sometimes, the verification does not compare the key to an expected value, but checks a *property* of the key (for example: "the CRC32 of the key XORed with the username hash must equal zero"). In this case, the keygen must solve an equation rather than reproduce a computation. This is the domain of the Z3 solver used manually (chapter 18, section 4), or angr as seen in section 21.7.

---

## Summary

The keygen is the synthesis of the entire chapter. Each section contributed a piece of the puzzle:

| Section | Contribution to the keygen |  
|---|---|  
| 21.1 — Triage | Key format (`XXXX-XXXX-XXXX-XXXX`), `%04X` string, no external crypto |  
| 21.2 — checksec | Confirmation that no protection blocks the analysis |  
| 21.3 — Ghidra | Pseudo-C of `compute_hash`, `derive_key`, `format_key` — algorithm skeleton |  
| 21.4 — Jumps | Understanding the success predicate (`strcmp == 0`) |  
| 21.5 — GDB | Expected key capture → reference value to validate the translation |  
| 21.6 — Patching | Not used directly, but confirmation of the decision point |  
| 21.7 — angr | Independent validation (the key found by angr must match) |  
| **21.8 — Keygen** | **Complete algorithm reconstruction in Python** |

The keygen construction workflow is reusable on any crackme:

```
1. Identify the verification function (Ghidra, XREF)
         ↓
2. Read the pseudo-C of each subfunction
         ↓
3. Cross-reference with the disassembly in case of ambiguity
         ↓
4. Translate to Python, function by function
         ↓
5. Validate each function individually (GDB as oracle)
         ↓
6. Assemble the complete keygen
         ↓
7. Mass test with pwntools
```

This chapter 21 has traversed the complete reverse engineering cycle of a simple C program. The acquired skill — conducting an analysis end to end, from initial triage to working keygen — is the foundation upon which the following chapters build. Targets will be more complex (object-oriented C++ in chapter 22, network binary in chapter 23, encryption in chapter 24), but the methodology remains the same: observe, understand, reproduce.

⏭️ [🎯 Checkpoint: produce a working keygen for all 3 binary variants](/21-keygenme/checkpoint.md)
