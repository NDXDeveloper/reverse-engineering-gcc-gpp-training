🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.6 — Writing the Python Decryptor

> 🎯 **Goal of this section**: leverage the cryptographic parameters extracted during the analysis (key, IV, algorithm, file format) to write a Python script capable of restoring files encrypted by the sample. This decryptor is the most concrete technical deliverable of the analysis — in a real incident context, it's the tool that allows victims to recover their data without paying a ransom.  
>  
> 📁 The final script is archived in `solutions/ch27-checkpoint-decryptor.py`.

---

## Inventory of what we know

Before writing a single line of code, let's gather the facts confirmed by static analysis (27.3) and dynamic analysis (27.5):

| Parameter | Value | Confirmation source |  
|---|---|---|  
| Algorithm | AES-256-CBC | XREF to `EVP_aes_256_cbc()` in Ghidra + call observed dynamically |  
| Key (32 bytes) | `52 45 56 45 ... 32 35 21` (`REVERSE_ENGINEERING_IS_FUN_2025!`) | `rcx` argument of `EVP_EncryptInit_ex` captured by GDB and Frida |  
| IV (16 bytes) | `DE AD BE EF CA FE BA BE 13 37 42 42 FE ED FA CE` | `r8` argument of `EVP_EncryptInit_ex` captured by GDB and Frida |  
| Padding | PKCS#7 (default in OpenSSL EVP) | Ciphertext size = next multiple of 16 ≥ plaintext size |  
| Key rotation | None — key and IV identical for each file | GDB script: 6 calls, same values |  
| `.locked` format | `[magic 8B][orig_size 8B][ciphertext NB]` | ImHex pattern + `fwrite` in Ghidra |  
| Magic header | `RWARE27\0` (8 bytes) | Offset 0x00 of the `.locked` file |  
| Original size | `uint64_t` little-endian at offset 0x08 | ImHex pattern + `fwrite(&orig_size, 8, 1, fp)` in Ghidra |  
| Encrypted data | From offset 0x10 to EOF | ImHex analysis |

Each of these pieces of information will translate directly into a constant or step in the decryptor.

---

## Technical choices

### Cryptographic library

We will use Python's `cryptography` module, which provides a high-level API for AES-CBC. It's the community-recommended Python library for cryptography — it relies on OpenSSL internally, which guarantees perfect compatibility with the encryption produced by our sample.

```bash
pip install cryptography
```

An alternative would be `pycryptodome` (`from Crypto.Cipher import AES`), equally valid. We prefer `cryptography` for its consistency with the underlying OpenSSL ecosystem.

### Truncation strategy

AES-CBC mode with PKCS#7 padding adds between 1 and 16 bytes to the plaintext. After decryption, this padding must be removed to obtain the exact original file. Two approaches are possible:

1. **Let the library handle unpadding** — `cryptography` automatically removes PKCS#7 padding when using the `finalize()` mechanism with an `unpadder`. This is the canonical method.  
2. **Truncate to the original size** — The `.locked` file header stores the original size at offset 0x08. We can simply decrypt then truncate the result to that size.

We will implement both approaches. The first is cryptographic best practice; the second is a safety net that exploits the information redundancy left by the sample's author.

---

## Building the decryptor, step by step

### Step 1 — Define constants extracted from the analysis

The first direct translation of our RE results into Python code:

```python
#!/usr/bin/env python3
"""
Decryptor for the Chapter 27 pedagogical ransomware.  
Restores .locked files encrypted with AES-256-CBC.  

Cryptographic parameters extracted by static analysis (Ghidra/ImHex)  
and confirmed by dynamic analysis (GDB/Frida).  

Usage:
    python3 decryptor.py                      # decrypt all of /tmp/test/
    python3 decryptor.py file.txt.locked      # decrypt a specific file
    python3 decryptor.py --dry-run            # simulate without writing
"""

import sys  
import os  
import struct  
import argparse  

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.primitives import padding  
from cryptography.hazmat.backends import default_backend  

# ── Constants extracted by RE ────────────────────────────────────────────────

# AES-256 key (32 bytes) — extracted from .rodata, confirmed via $rcx on
# EVP_EncryptInit_ex (GDB breakpoint + Frida hook)
AES_KEY = bytes([
    0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x45, 0x5F,  # REVERSE_
    0x45, 0x4E, 0x47, 0x49, 0x4E, 0x45, 0x45, 0x52,  # ENGINEER
    0x49, 0x4E, 0x47, 0x5F, 0x49, 0x53, 0x5F, 0x46,  # ING_IS_F
    0x55, 0x4E, 0x5F, 0x32, 0x30, 0x32, 0x35, 0x21,  # UN_2025!
])

# AES-CBC IV (16 bytes) — extracted from .rodata, confirmed via $r8 on
# EVP_EncryptInit_ex (GDB breakpoint + Frida hook)
AES_IV = bytes([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE,
])

# .locked file format — mapped with ImHex (section 27.3)
MAGIC_HEADER = b"RWARE27\x00"      # 8 bytes at offset 0x00  
HEADER_SIZE  = 16                   # 8 (magic) + 8 (orig_size)  
LOCKED_EXT   = ".locked"  
```

Each constant is accompanied by a comment tracing its origin. This traceability is essential: if a colleague picks up the script, they must be able to verify each value against the analysis report.

### Step 2 — Parse the `.locked` file header

The header is 16 bytes. We need to extract the magic (for validation) and the original size (for truncation):

```python
def parse_locked_header(filepath):
    """
    Reads and validates the header of a .locked file.
    
    Format (little-endian):
        [0x00 - 0x07]  Magic: "RWARE27\0"
        [0x08 - 0x0F]  Original size: uint64_t LE
    
    Returns (original_size, ciphertext_bytes) or raises an exception.
    """
    with open(filepath, "rb") as f:
        header = f.read(HEADER_SIZE)
        
        if len(header) < HEADER_SIZE:
            raise ValueError(f"File too small ({len(header)} bytes): {filepath}")
        
        # Verify the magic
        magic = header[0:8]
        if magic != MAGIC_HEADER:
            raise ValueError(
                f"Invalid magic header: expected {MAGIC_HEADER!r}, "
                f"got {magic!r} in {filepath}"
            )
        
        # Extract the original size (uint64_t little-endian)
        original_size = struct.unpack("<Q", header[8:16])[0]
        
        # Read the rest = encrypted data
        ciphertext = f.read()
    
    return original_size, ciphertext
```

The `struct.unpack("<Q", ...)` decodes an 8-byte unsigned integer in little-endian — exactly what the sample writes with `fwrite(&orig_size, sizeof(uint64_t), 1, fp)` on an x86-64 architecture.

The magic validation is a safety measure: if the user passes a file that was not encrypted by our sample, the decryptor refuses to process it rather than producing corrupted output.

### Step 3 — Decrypt the AES-256-CBC payload

```python
def decrypt_aes256cbc(ciphertext, key, iv):
    """
    Decrypts an AES-256-CBC buffer and removes PKCS#7 padding.
    
    Reproduces the exact inverse of the sequence:
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)
        EVP_EncryptUpdate(ctx, out, &len, in, in_len)
        EVP_EncryptFinal_ex(ctx, out + len, &len)
    """
    # Consistency checks
    if len(key) != 32:
        raise ValueError(f"Invalid key: {len(key)} bytes (expected 32)")
    if len(iv) != 16:
        raise ValueError(f"Invalid IV: {len(iv)} bytes (expected 16)")
    if len(ciphertext) == 0:
        raise ValueError("Empty ciphertext")
    if len(ciphertext) % 16 != 0:
        raise ValueError(
            f"Ciphertext size ({len(ciphertext)}) not a multiple of 16 — "
            "probable corruption"
        )
    
    # AES-256-CBC decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()  # 128 = AES block size in bits
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
```

A few points deserve attention:

**`len(ciphertext) % 16 != 0` check** — An AES-CBC ciphertext must always be a multiple of the block size (16 bytes). If not, the file is corrupted or has been truncated. Better to fail cleanly than to pass an invalid buffer to the crypto library.

**`padding.PKCS7(128).unpadder()`** — The `128` parameter is the block size in **bits** (not bytes). This is a classic source of error: AES has a 16-byte block = 128 bits.

**Why `decryptor.update()` + `decryptor.finalize()`?** — This two-step sequence is the exact mirror of `EVP_DecryptUpdate` + `EVP_DecryptFinal_ex` on the OpenSSL side. The `finalize()` verifies padding integrity; if the data is corrupted or the key is wrong, it will raise a `ValueError`.

### Step 4 — Decrypt a file and restore the original

```python
def decrypt_file(locked_path, dry_run=False):
    """
    Decrypts a .locked file and restores the original file.
    
    Steps:
        1. Parse the header (magic + original size)
        2. Decrypt the AES-256-CBC payload
        3. Verify consistency between decrypted size and announced size
        4. Write the restored file (without the .locked extension)
    
    Returns the restored file path.
    """
    print(f"[*] Processing: {locked_path}")
    
    # 1. Parse the header
    original_size, ciphertext = parse_locked_header(locked_path)
    print(f"    Announced original size: {original_size} bytes")
    print(f"    Ciphertext size:         {len(ciphertext)} bytes")
    
    # 2. Decrypt
    try:
        plaintext = decrypt_aes256cbc(ciphertext, AES_KEY, AES_IV)
    except Exception as e:
        print(f"    [!] Decryption failed: {e}")
        return None
    
    # 3. Verify consistency
    #    PKCS#7 unpadding should already give the correct size.
    #    The size announced in the header is a cross-check.
    if len(plaintext) != original_size:
        print(f"    [!] Size inconsistency: decrypted={len(plaintext)}, "
              f"announced={original_size}")
        print(f"    [!] Truncating to announced size.")
        plaintext = plaintext[:original_size]
    
    # 4. Determine output path: remove .locked
    if locked_path.endswith(LOCKED_EXT):
        output_path = locked_path[:-len(LOCKED_EXT)]
    else:
        output_path = locked_path + ".decrypted"
    
    if dry_run:
        print(f"    [DRY-RUN] Would restore: {output_path} "
              f"({len(plaintext)} bytes)")
        return output_path
    
    # Write the restored file
    with open(output_path, "wb") as f:
        f.write(plaintext)
    
    print(f"    [+] Restored: {output_path} ({len(plaintext)} bytes)")
    return output_path
```

**Cross-check on size** — In theory, removing PKCS#7 padding is sufficient to recover the original size. But the header stores this size independently, giving us a double verification mechanism. If the two sizes diverge, it's a red flag: either the key is incorrect (unpadding will produce random output), or the file is corrupted, or the header has been tampered with. The script reports the inconsistency and conservatively truncates to the announced size.

**`dry_run` mode** — Essential during development: you can validate that parsing and decryption work without writing to disk. This avoids accidentally overwriting data in an already complex lab.

### Step 5 — Traverse a directory

To process all `.locked` files in a directory tree at once:

```python
def scan_and_decrypt(directory, dry_run=False):
    """
    Recursively traverses a directory and decrypts all .locked files.
    Returns the number of successfully restored files.
    """
    success = 0
    errors  = 0
    skipped = 0
    
    for root, dirs, files in os.walk(directory):
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            
            if not filename.endswith(LOCKED_EXT):
                skipped += 1
                continue
            
            try:
                result = decrypt_file(filepath, dry_run=dry_run)
                if result:
                    success += 1
                else:
                    errors += 1
            except Exception as e:
                print(f"    [!] Unexpected error on {filepath}: {e}")
                errors += 1
    
    print(f"\n{'=' * 50}")
    print(f"Result: {success} restored, {errors} error(s), "
          f"{skipped} skipped")
    print(f"{'=' * 50}")
    
    return success
```

### Step 6 — CLI entry point

```python
def main():
    parser = argparse.ArgumentParser(
        description="Decryptor for Ch27 ransomware (AES-256-CBC)",
        epilog="Reverse Engineering Training — Chapter 27"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="/tmp/test",
        help="A .locked file or directory to process (default: /tmp/test)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate decryption without writing files"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After decryption, display the first bytes of the result"
    )
    args = parser.parse_args()
    
    print("=" * 50)
    print("  Decryptor — Chapter 27")
    print(f"  Algorithm: AES-256-CBC")
    print(f"  Key:       {AES_KEY.decode('ascii')}")
    print(f"  IV:        {AES_IV.hex()}")
    print("=" * 50)
    print()
    
    target = args.target
    
    if os.path.isfile(target):
        # Single file mode
        result = decrypt_file(target, dry_run=args.dry_run)
        
        if result and args.verify and not args.dry_run:
            with open(result, "rb") as f:
                preview = f.read(128)
            print(f"\n    Preview (first {min(128, len(preview))} bytes):")
            try:
                print(f"    {preview.decode('utf-8', errors='replace')}")
            except Exception:
                print(f"    {preview.hex()}")
    
    elif os.path.isdir(target):
        # Directory mode
        scan_and_decrypt(target, dry_run=args.dry_run)
    
    else:
        print(f"[!] Target not found: {target}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## Complete assembled script

The six steps above, assembled in order, form the complete `decryptor.py` script. Let's recap its structure:

```
decryptor.py
│
├── Constants (AES_KEY, AES_IV, MAGIC_HEADER, HEADER_SIZE)
│
├── parse_locked_header(filepath)
│     → Reads magic + original size, returns (size, ciphertext)
│
├── decrypt_aes256cbc(ciphertext, key, iv)
│     → Decrypts AES-256-CBC + removes PKCS#7 padding
│
├── decrypt_file(locked_path, dry_run)
│     → Orchestrates: parse → decrypt → verify → write
│
├── scan_and_decrypt(directory, dry_run)
│     → Recursive os.walk on .locked files
│
└── main()
      → CLI argparse: target, --dry-run, --verify
```

---

## Execution and validation

### Test on a single file

```bash
$ python3 decryptor.py /tmp/test/document.txt.locked --verify
==================================================
  Decryptor — Chapter 27
  Algorithm: AES-256-CBC
  Key:       REVERSE_ENGINEERING_IS_FUN_2025!
  IV:        deadbeefcafebabe13374242feedface
==================================================

[*] Processing: /tmp/test/document.txt.locked
    Announced original size: 47 bytes
    Ciphertext size:         48 bytes
    [+] Restored: /tmp/test/document.txt (47 bytes)

    Preview (first 47 bytes):
    This is a strictly confidential document.
```

The restored content matches exactly the original file created by `make testenv`. The decryption works.

### Test in full directory mode

```bash
$ python3 decryptor.py /tmp/test/
[*] Processing: /tmp/test/budget.csv.locked
    Announced original size: 58 bytes
    Ciphertext size:         64 bytes
    [+] Restored: /tmp/test/budget.csv (58 bytes)
[*] Processing: /tmp/test/document.txt.locked
    Announced original size: 47 bytes
    Ciphertext size:         48 bytes
    [+] Restored: /tmp/test/document.txt (47 bytes)
[*] Processing: /tmp/test/notes.md.locked
    ...
[*] Processing: /tmp/test/subfolder/nested.txt.locked
    ...

==================================================
Result: 6 restored, 0 error(s), 1 skipped
==================================================
```

The skipped file is `README_LOCKED.txt` — the ransom note, which doesn't have the `.locked` extension.

### Hash-based integrity validation

For rigorous validation, let's compare the SHA-256 hashes of the original files (before encryption) with those of the restored files:

```bash
# Before encryption (run BEFORE the ransomware, or after make reset)
$ find /tmp/test -type f -exec sha256sum {} \; | sort > /tmp/hashes_before.txt

# Run the ransomware
$ ./ransomware_O0

# Run the decryptor
$ python3 decryptor.py /tmp/test/

# After restoration
$ find /tmp/test -type f ! -name "*.locked" ! -name "README_LOCKED.txt" \
    -exec sha256sum {} \; | sort > /tmp/hashes_after.txt

# Compare
$ diff /tmp/hashes_before.txt /tmp/hashes_after.txt
# (no differences = perfect restoration)
```

If `diff` produces no output, the restored files are **bit-for-bit identical** to the originals. This is the ultimate proof that the decryption is correct.

---

## Error case handling

A robust decryptor must handle degraded situations that arise in real-world contexts:

### Wrong key

If the extracted key were incorrect (unconfirmed hypothesis, decoy in `.rodata`), the `cryptography` library would raise a `ValueError` when removing PKCS#7 padding. Indeed, after decryption with the wrong key, the last block contains pseudo-random bytes that don't constitute valid PKCS#7 padding.

The error message would look like:

```
[!] Decryption failed: Invalid padding bytes.
```

This is an immediate signal that the key or IV is incorrect. In that case, you would need to go back to the dynamic analysis step to recapture the parameters.

### Truncated or corrupted file

If a `.locked` file has been partially overwritten or truncated (disk crash, interrupted copy), the upstream checks detect the problem:
- Header less than 16 bytes → `parse_locked_header` refuses the file.  
- Ciphertext not a multiple of 16 → `decrypt_aes256cbc` refuses to decrypt.  
- Inconsistent decrypted size → the script reports the discrepancy.

### File that is not a `.locked`

The `RWARE27\0` magic check rejects any file that was not produced by our sample, even if it coincidentally has the `.locked` extension.

---

## Minimalist variant with `pwntools`

For students familiar with `pwntools` ([Chapter 11, section 11.9](/11-gdb/09-introduction-pwntools.md)), here is a condensed version using `pwnlib.util` for formatting, combined with `pycryptodome`:

```python
#!/usr/bin/env python3
"""Minimal Ch27 decryptor — pwntools + pycryptodome version."""

from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad  
from pwn import *  
import struct, os, sys  

KEY   = b"REVERSE_ENGINEERING_IS_FUN_2025!"  
IV    = bytes.fromhex("deadbeefcafebabe13374242feedface")  
MAGIC = b"RWARE27\x00"  

def decrypt(path):
    data = read(path)                              # pwntools read()
    assert data[:8] == MAGIC, f"Bad magic: {path}"
    orig_size = struct.unpack("<Q", data[8:16])[0]
    ct = data[16:]

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    out = path.replace(".locked", "")
    write(out, pt[:orig_size])                     # pwntools write()
    log.success(f"{path} → {out} ({orig_size} B)")

target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test"  
if os.path.isfile(target):  
    decrypt(target)
else:
    for root, _, files in os.walk(target):
        for f in sorted(files):
            if f.endswith(".locked"):
                decrypt(os.path.join(root, f))
```

This version fits in 25 lines. It sacrifices error handling and verbosity for conciseness, but the result is identical. The choice between the complete and minimalist versions depends on context: the complete version is a professional deliverable, the minimalist version is a CTF tool.

---

## What the decryptor reveals about the sample's weaknesses

The simple fact that a decryptor exists and works exposes the sample's cryptographic design weaknesses:

**Static key** — The same key is compiled into the binary and used for every file, on every machine. Anyone who possesses the binary (or reverses it) possesses the key. By comparison, robust ransomware generates a random AES key per execution (or even per file), then encrypts it with an embedded RSA-2048/4096 public key whose private key only the attacker holds.

**Static IV** — The same IV is reused for every file. Direct consequence: if two files begin with the same first 16 bytes, the first blocks of ciphertext will be identical. An analyst could infer information about the original content without even decrypting (pattern analysis attack). Robust ransomware generates a random IV per file and stores it in the encrypted file's header.

**No key derivation** — The key is used raw, without passing through a key derivation function (PBKDF2, scrypt, Argon2). This isn't a problem here (the key already has 256 bits of structural entropy), but in a real scheme based on a password, the absence of derivation would be a critical vulnerability.

**Key in cleartext in memory** — The key is stored in `.rodata` and referenced directly. No attempt at in-memory obfuscation (XOR with a runtime value, fragmented loading, erasure after use). Tools like Frida capture it trivially.

These weaknesses are deliberate pedagogical choices (see section 27.1). But explicitly identifying them in the analysis report (section 27.7) is important: it's what differentiates a descriptive report ("here's what the malware does") from an analytical report ("here's what the malware does, here's why it's breakable, here's how to break it").

---

## Deliverables summary

At the end of this section, you have:

1. **`decryptor.py`** — Complete script with header parsing, AES-256-CBC decryption, PKCS#7 removal, cross-check on size, dry-run mode, recursive traversal, and CLI argparse.  
2. **Hash-based validation** — SHA-256 comparison procedure proving bit-for-bit restoration.  
3. **Minimalist variant** — 25-line version with `pwntools` + `pycryptodome` for CTF contexts.  
4. **Weakness analysis** — Identification of the cryptographic flaws exploited by the decryptor, ready to be integrated into the report.

These elements constitute the technical proof that files are recoverable without paying a ransom — the most critical information an analyst can provide during a ransomware incident.

⏭️ [Writing a standard analysis report (IOC, behavior, recommendations)](/27-ransomware/07-analysis-report.md)
