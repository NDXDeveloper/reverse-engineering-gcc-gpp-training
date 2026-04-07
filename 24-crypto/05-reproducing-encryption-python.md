🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 24.5 — Reproducing the Encryption Scheme in Python

> 🎯 **Objective of this section**: assemble all the pieces collected in the previous sections to write a standalone Python script capable of decrypting `secret.enc`, then validate the result. This is the concrete culmination of the entire chapter.

---

## Inventory: what we know

Before writing a single line of code, let's take stock of the information accumulated throughout the sections.

**From section 24.1** (identification by constants): the binary uses AES and SHA-256.

**From section 24.2** (library identification): the routines come from OpenSSL, via the EVP API. The cipher is AES-256-CBC.

**From section 24.3** (memory extraction): we captured three decisive elements:  
- The passphrase: `r3vers3_m3_1f_y0u_c4n!`  
- The XOR mask applied after the SHA-256 hash (32 bytes in `.rodata`):
  `DE AD BE EF CA FE BA BE 13 37 42 42 FE ED FA CE 0B AD F0 0D DE AD C0 DE 8B AD F0 0D 0D 15 EA 5E`
- The derivation logic: `key = SHA-256(passphrase) XOR mask`  
- The IV and the final key (captured at the breakpoint on `EVP_EncryptInit_ex`)

**From section 24.4** (file format): the complete structure of `secret.enc`:

| Offset | Size | Field | Format |  
|---|---|---|---|  
| 0x00 | 8 | Magic | `"CRYPT24\0"` |  
| 0x08 | 1 | Major version | uint8 |  
| 0x09 | 1 | Minor version | uint8 |  
| 0x0A | 2 | IV length | uint16 LE |  
| 0x0C | 16 | IV | raw bytes |  
| 0x1C | 4 | Original size | uint32 LE |  
| 0x20 | … | Ciphertext | AES-256-CBC, PKCS7 |

We have everything. Let's move on to the code.

---

## Approach 1: decryption with the raw key

This is the most straightforward approach. We use the key and IV captured by GDB or Frida (section 24.3), without worrying about the derivation. We parse the `.enc` file according to the format documented in section 24.4, and we decrypt.

### Installing the dependency

```bash
$ pip install pycryptodome
```

`pycryptodome` is the reference Python crypto library. It provides `AES`, `SHA256`, and all standard modes of operation. It is the Python counterpart of OpenSSL.

### The script

```python
#!/usr/bin/env python3
"""
decrypt_raw.py — Decryption of secret.enc with the raw key.

"Memory brute force" approach: we directly use the key  
captured by GDB/Frida, without reproducing the derivation.  

Usage: python3 decrypt_raw.py secret.enc [output.txt]
"""

import sys  
import struct  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad  

# ── Raw key captured by GDB/Frida (section 24.3) ─────────────
# Replace with the actual bytes captured during YOUR execution.
# These are deterministic (same passphrase + same mask = same key),
# so they will be identical on every execution of the binary.
RAW_KEY = bytes.fromhex(
    "a31f4b728ed05519c73a6188f20dae43"
    "5be9176cd482f03ea156c87d09bb4fe2"
)  # 32 bytes — AES-256


def parse_crypt24(filepath):
    """Parse a CRYPT24-format file and return its components."""

    with open(filepath, "rb") as f:
        data = f.read()

    # ── Magic (8 bytes) ─────────────────────────────────────────
    magic = data[0x00:0x08]
    if magic != b"CRYPT24\x00":
        raise ValueError(f"Invalid magic: {magic!r} (expected b'CRYPT24\\x00')")

    # ── Version (2 bytes) ───────────────────────────────────────
    version_major = data[0x08]
    version_minor = data[0x09]
    if version_major != 1:
        raise ValueError(f"Unsupported major version: {version_major}")

    # ── IV length (uint16 LE) ──────────────────────────────────
    iv_length = struct.unpack_from("<H", data, 0x0A)[0]
    if iv_length not in (8, 12, 16):
        raise ValueError(f"Unexpected IV length: {iv_length}")

    # ── IV ──────────────────────────────────────────────────────
    iv = data[0x0C : 0x0C + iv_length]

    # ── Original size (uint32 LE) ──────────────────────────────
    header_end = 0x0C + iv_length
    original_size = struct.unpack_from("<I", data, header_end)[0]

    # ── Ciphertext ──────────────────────────────────────────────
    ciphertext_offset = header_end + 4
    ciphertext = data[ciphertext_offset:]

    return {
        "version": (version_major, version_minor),
        "iv_length": iv_length,
        "iv": iv,
        "original_size": original_size,
        "ciphertext": ciphertext,
    }


def decrypt_aes256_cbc(ciphertext, key, iv):
    """Decrypt an AES-256-CBC buffer with PKCS7 padding removal."""

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.enc> [output]")
        sys.exit(1)

    enc_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    # 1. Parse the file
    print(f"[*] Parsing {enc_path}...")
    parts = parse_crypt24(enc_path)

    print(f"    Version:       {parts['version'][0]}.{parts['version'][1]}")
    print(f"    IV length:     {parts['iv_length']} bytes")
    print(f"    IV:            {parts['iv'].hex()}")
    print(f"    Original size: {parts['original_size']} bytes")
    print(f"    Ciphertext:    {len(parts['ciphertext'])} bytes")

    # 2. Decrypt
    print(f"[*] Decrypting with raw key...")
    plaintext = decrypt_aes256_cbc(parts["ciphertext"], RAW_KEY, parts["iv"])

    # 3. Validate the size
    if len(plaintext) != parts["original_size"]:
        print(f"[!] Warning: decrypted size ({len(plaintext)}) "
              f"!= original_size ({parts['original_size']})")
    else:
        print(f"[+] Size matches: {len(plaintext)} bytes")

    # 4. Display or save
    if out_path:
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print(f"[+] Decrypted content written to {out_path}")
    else:
        print(f"\n{'='*60}")
        print(f"Decrypted content:")
        print(f"{'='*60}")
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"(binary data, {len(plaintext)} bytes)")
            print(plaintext[:256].hex())


if __name__ == "__main__":
    main()
```

### Execution

```bash
$ python3 decrypt_raw.py secret.enc
[*] Parsing secret.enc...
    Version:       1.0
    IV length:     16 bytes
    IV:            9c712eb538f4a06d1c83e752bf4906da
    Original size: 342 bytes
    Ciphertext:    352 bytes
[*] Decrypting with raw key...
[+] Size matches: 342 bytes

============================================================
Decrypted content:
============================================================
=== FICHIER CONFIDENTIEL ===

Projet : Operation Midnight Sun  
Classification : TOP SECRET  
...
```

The contents of `secret.txt` are fully recovered. The file has been successfully decrypted.

---

## Approach 2: reproducing the complete derivation

Approach 1 works, but it depends on a key captured for a specific execution. If we want a generic tool — capable of decrypting any file produced by the binary, without needing to relaunch GDB each time — we must reproduce the key derivation in the Python script.

Reminder of the logic reconstructed in section 24.3:

```
1. Build the passphrase: "r3vers3_m3_1f_y0u_c4n!"
2. Compute hash = SHA-256(passphrase)
3. For i from 0 to 31: key[i] = hash[i] XOR mask[i]
```

### The script with derivation

```python
#!/usr/bin/env python3
"""
decrypt_full.py — Decryption of secret.enc with complete
                   reproduction of the key derivation.

This script is standalone: it does not depend on any data captured  
by GDB/Frida. All the logic is reconstructed from the RE.  

Usage: python3 decrypt_full.py secret.enc [output.txt]
"""

import sys  
import struct  
import hashlib  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad  

# ── Hardcoded passphrase (reconstructed in section 24.3) ─────
# Found via breakpoint on build_passphrase() in GDB.
# Built in 3 pieces in the binary to evade `strings`.
PASSPHRASE = b"r3vers3_m3_1f_y0u_c4n!"

# ── XOR mask (extracted from .rodata, section 24.3) ──────────
# Visible in Ghidra as global variable KEY_MASK[32].
KEY_MASK = bytes([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE,
    0x0B, 0xAD, 0xF0, 0x0D, 0xDE, 0xAD, 0xC0, 0xDE,
    0x8B, 0xAD, 0xF0, 0x0D, 0x0D, 0x15, 0xEA, 0x5E,
])


def derive_key(passphrase, mask):
    """Reproduce the key derivation from the crypto.c binary."""

    # Step 1: SHA-256 of the passphrase
    sha_hash = hashlib.sha256(passphrase).digest()

    # Step 2: XOR with the mask
    key = bytes(h ^ m for h, m in zip(sha_hash, mask))

    return key


def parse_crypt24(filepath):
    """Parse a CRYPT24-format file."""

    with open(filepath, "rb") as f:
        data = f.read()

    magic = data[0x00:0x08]
    if magic != b"CRYPT24\x00":
        raise ValueError(f"Invalid magic: {magic!r}")

    version_major = data[0x08]
    version_minor = data[0x09]
    if version_major != 1:
        raise ValueError(f"Unsupported major version: {version_major}")

    iv_length = struct.unpack_from("<H", data, 0x0A)[0]
    iv = data[0x0C : 0x0C + iv_length]

    header_end = 0x0C + iv_length
    original_size = struct.unpack_from("<I", data, header_end)[0]

    ciphertext_offset = header_end + 4
    ciphertext = data[ciphertext_offset:]

    return {
        "version": (version_major, version_minor),
        "iv": iv,
        "original_size": original_size,
        "ciphertext": ciphertext,
    }


def decrypt_aes256_cbc(ciphertext, key, iv):
    """Decrypt in AES-256-CBC with PKCS7 padding removal."""

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.enc> [output]")
        sys.exit(1)

    enc_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    # 1. Derive the key (reproduces derive_key() from the binary)
    print("[*] Deriving key...")
    key = derive_key(PASSPHRASE, KEY_MASK)
    print(f"    Passphrase:  {PASSPHRASE.decode()}")
    print(f"    SHA-256:     {hashlib.sha256(PASSPHRASE).hexdigest()}")
    print(f"    Key (after XOR mask): {key.hex()}")

    # 2. Parse the .enc file
    print(f"[*] Parsing {enc_path}...")
    parts = parse_crypt24(enc_path)
    print(f"    IV:            {parts['iv'].hex()}")
    print(f"    Original size: {parts['original_size']} bytes")
    print(f"    Ciphertext:    {len(parts['ciphertext'])} bytes")

    # 3. Decrypt
    print("[*] Decrypting...")
    plaintext = decrypt_aes256_cbc(parts["ciphertext"], key, parts["iv"])

    # 4. Validate
    if len(plaintext) != parts["original_size"]:
        print(f"[!] Warning: size mismatch "
              f"({len(plaintext)} vs {parts['original_size']})")
    else:
        print(f"[+] Size validated: {len(plaintext)} bytes")

    # 5. Result
    if out_path:
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print(f"[+] Written to {out_path}")
    else:
        print(f"\n{'='*60}")
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"(binary content, {len(plaintext)} bytes)")
        print(f"{'='*60}")

    # 6. Final verification: re-encrypt and compare
    print("\n[*] Verification: re-encrypting and comparing...")
    cipher_check = AES.new(key, AES.MODE_CBC, iv=parts["iv"])
    from Crypto.Util.Padding import pad
    re_encrypted = cipher_check.encrypt(pad(plaintext, AES.block_size))
    if re_encrypted == parts["ciphertext"]:
        print("[+] Re-encryption matches — decryption is correct.")
    else:
        print("[!] Re-encryption mismatch — something is wrong.")


if __name__ == "__main__":
    main()
```

### Execution

```bash
$ python3 decrypt_full.py secret.enc decrypted.txt
[*] Deriving key...
    Passphrase:  r3vers3_m3_1f_y0u_c4n!
    SHA-256:     7db2f59d...  (raw hash of the passphrase)
    Key (after XOR mask): a31f4b728ed05519...
[*] Parsing secret.enc...
    IV:            9c712eb538f4a06d1c83e752bf4906da
    Original size: 342 bytes
    Ciphertext:    352 bytes
[*] Decrypting...
[+] Size validated: 342 bytes
[+] Written to decrypted.txt

[*] Verification: re-encrypting and comparing...
[+] Re-encryption matches — decryption is correct.
```

The key derived by Python matches exactly the one captured by GDB. The file is decrypted. The re-encrypted output matches the original ciphertext byte for byte. The scheme is fully reproduced.

---

## Cross-validation: comparison with the original file

The final verification, and the most satisfying one, is to compare the decrypted file with the original:

```bash
$ diff secret.txt decrypted.txt && echo "Identical!" || echo "Different!"
Identical!

$ sha256sum secret.txt decrypted.txt
a1b2c3d4...  secret.txt  
a1b2c3d4...  decrypted.txt  
```

The hashes are identical. The reverse engineering is complete.

---

## Methodology review: the two approaches and when to use them

The two scripts illustrate two complementary philosophies of crypto RE.

### "Raw key" approach (decrypt_raw.py)

We capture the key from memory and decrypt directly. It is fast, reliable, and does not require understanding the derivation.

**When to use it**: emergencies (security incident, ransomware to decrypt immediately), binary too obfuscated to understand the derivation within a reasonable timeframe, or cases where the key comes from outside (user input, received over the network) and cannot be re-derived from the binary alone.

**Limitation**: the captured key is valid for *one* execution. If the binary derives a different key each time (based on a timestamp, a machine identifier, a random salt...), you need to capture the key every time. It is not a standalone tool.

### "Reproduced derivation" approach (decrypt_full.py)

We fully reconstruct the key generation logic. The script is standalone: it can decrypt any file produced by the binary, without manual intervention.

**When to use it**: in-depth analysis, report writing, creation of a distributable decryption tool (for ransomware victims for example), or when you also want to be able to *encrypt* (for testing, creating test files, or writing an interoperability tool).

**Limitation**: requires understanding the entire derivation chain, which can be very time-consuming if it is complex or obfuscated.

### In practice

You almost always start with the raw key approach (to get a quick result and confirm that your understanding of the algorithm and format is correct), then invest in the reproduced derivation if the context warrants it.

---

## Common pitfalls and troubleshooting

### "The decryption produces noise"

Probable causes, in order of frequency:

1. **Wrong ciphertext offset.** You are decrypting part of the header or skipping ciphertext bytes. Verify that the start offset matches the format map exactly (section 24.4).

2. **Wrong mode of operation.** CBC, CTR, GCM, and ECB are not interchangeable. If the binary uses CTR and you decrypt in CBC, the result is noise. Re-check the call to `EVP_EncryptInit_ex` (section 24.3): the second argument identifies the mode.

3. **Incorrect key or IV.** A single wrong byte is enough to produce complete noise. Compare the values used in Python byte by byte with those captured from memory.

4. **Endianness.** If the key is derived from a hash stored as an array of `uint32_t`, the system's endianness affects the byte order. Python and x86-64 are both little-endian for integers, but hash functions return bytes in big-endian order (digest order). Verify that the conversions are consistent.

### "The padding is invalid"

`unpad()` raises a `ValueError` exception if the last bytes of the decrypted plaintext do not form valid PKCS7 padding. This generally means the key, IV, or mode is wrong — the decryption "worked" mathematically but produced noise, and the noise does not look like valid padding.

Debugging tip: temporarily replace `unpad(...)` with direct access to the raw buffer and inspect the last 16 bytes. If they are random, the problem is upstream (key/IV/mode). If they look like padding but with an unexpected value, the problem might be a non-standard padding scheme (zeros, ANSI X.923, ISO 10126).

### "The first block is correct but the rest is noise"

In CBC mode, if the IV is wrong but the key is correct, only the first 16-byte block is corrupted — the rest decrypts normally (because each subsequent block depends on the previous ciphertext block, not the IV). This is a very characteristic symptom that points directly to an IV problem.

Conversely, if the first block is correct but all subsequent blocks are noise, this may indicate that you accidentally used ECB mode (each block is independent) instead of CBC, and the first block matches by coincidence.

---

## Going further: writing an encryption tool

If we wanted to produce `.enc` files compatible with the binary (for fuzzing, testing, or interoperability), we simply reverse the process:

```python
def encrypt_file(input_path, output_path):
    """Encrypt a file in CRYPT24 format (compatible with the binary)."""

    import os
    from Crypto.Util.Padding import pad

    # Read the plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Derive the key
    key = derive_key(PASSPHRASE, KEY_MASK)

    # Generate a random IV
    iv = os.urandom(16)

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Write the .enc file
    with open(output_path, "wb") as f:
        f.write(b"CRYPT24\x00")                          # Magic
        f.write(struct.pack("BB", 1, 0))                  # Version 1.0
        f.write(struct.pack("<H", len(iv)))                # IV length
        f.write(iv)                                        # IV
        f.write(struct.pack("<I", len(plaintext)))         # Original size
        f.write(ciphertext)                                # Ciphertext
```

A file produced by this function is structurally identical to those produced by the C binary. This is the ultimate proof that the RE is complete: we have not only understood the scheme, but reproduced it in an interchangeable manner.

---

## Chapter summary

This chapter followed a single thread — decrypting `secret.enc` — through five steps that form a general methodology applicable to any binary using cryptography:

| Step | Section | Question | Result |  
|---|---|---|---|  
| 1 | 24.1 | What algorithm? | AES-256 + SHA-256 (magic constants) |  
| 2 | 24.2 | What implementation? | OpenSSL, EVP API (ldd, nm, signatures) |  
| 3 | 24.3 | Where are the secrets? | Key, IV, passphrase (GDB, Frida) |  
| 4 | 24.4 | How is the data packaged? | Documented CRYPT24 format (ImHex, .hexpat) |  
| 5 | 24.5 | Can we reproduce the scheme? | Standalone Python script, cross-validation |

Each step feeds into the next. Skipping a step means risking wasted time on the following one. Applying them in order turns an opaque binary into a methodically solved problem.

> 🎯 **Chapter checkpoint**: decrypt the provided `secret.enc` file by extracting the key from the binary. You now have two approaches (raw key and reproduced derivation). To validate the checkpoint, produce a working `decrypt.py` script and verify that `diff secret.txt decrypted.txt` returns no differences.

---


⏭️ [🎯 Checkpoint: decrypt the provided `secret.enc` file by extracting the key from the binary](/24-crypto/checkpoint.md)
