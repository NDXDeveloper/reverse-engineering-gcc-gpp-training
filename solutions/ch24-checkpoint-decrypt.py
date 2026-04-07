#!/usr/bin/env python3
"""
ch24-checkpoint-decrypt.py — Chapter 24 Checkpoint Solution
Reverse Engineering Training — Applications compiled with the GNU toolchain

Decrypts a file in CRYPT24 format produced by the ch24-crypto binary.

This script fully reproduces the binary's key derivation logic:
    1. Hardcoded passphrase: "r3vers3_m3_1f_y0u_c4n!"
       (built in pieces in build_passphrase() to evade `strings`)
    2. SHA-256 hash of the passphrase
    3. XOR of the hash with a 32-byte mask (KEY_MASK, stored in .rodata)
    4. Result = AES-256 key

The .enc file is structured according to the CRYPT24 format:
    [0x00..0x07]  Magic         "CRYPT24\0"           (8 bytes)
    [0x08]        Version maj.  0x01                   (1 byte)
    [0x09]        Version min.  0x00                   (1 byte)
    [0x0A..0x0B]  IV length     0x0010 (16)            (uint16 LE)
    [0x0C..0x1B]  IV            (16 random bytes)
    [0x1C..0x1F]  Orig. size    (plaintext size)       (uint32 LE)
    [0x20..EOF]   Ciphertext    (AES-256-CBC, PKCS7)

Prerequisites: pip install pycryptodome

Usage:
    python3 ch24-checkpoint-decrypt.py <file.enc> [output_file]

Examples:
    python3 ch24-checkpoint-decrypt.py secret.enc
    python3 ch24-checkpoint-decrypt.py secret.enc decrypted.txt

Validation:
    diff secret.txt decrypted.txt   # no output = success

MIT License — Strictly educational and ethical use.
"""

import sys
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ============================================================================
# Data reconstructed by Reverse Engineering
# ============================================================================

# Passphrase — Section 24.3
# Found via: GDB breakpoint on build_passphrase(), then x/s on the output
# buffer upon function return.
# In the binary, it is built in 3 pieces (part1 + part2 + part3)
# concatenated by strcat() to avoid appearing in plaintext in `strings`.
PASSPHRASE = b"r3vers3_m3_1f_y0u_c4n!"

# XOR Mask — Section 24.3
# Found via: KEY_MASK global variable in .rodata, located in Ghidra
# via XREF from the XOR loop in derive_key().
# First recognizable bytes: 0xDEADBEEF 0xCAFEBABE (classic sentinel values,
# likely chosen by the developer for debugging).
KEY_MASK = bytes([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE,
    0x0B, 0xAD, 0xF0, 0x0D, 0xDE, 0xAD, 0xC0, 0xDE,
    0x8B, 0xAD, 0xF0, 0x0D, 0x0D, 0x15, 0xEA, 0x5E,
])

# Identified algorithm — Sections 24.1 and 24.2
# - AES-256-CBC: confirmed by EVP_aes_256_cbc in nm -D, and by the
#   AES S-box found in crypto_static via magic constant scanning.
# - SHA-256: confirmed by the SHA256 symbol in nm -D, and by the
#   SHA-256 IVs (0x6A09E667...) found in crypto_static.
# - OpenSSL: confirmed by ldd (libcrypto.so.3) and strings ("OpenSSL ...").
ALGORITHM = "AES-256-CBC"
HASH_ALGO = "SHA-256"
KEY_LEN = 32   # AES-256
IV_LEN = 16    # AES block size
BLOCK_SIZE = 16


# ============================================================================
# Key derivation — reproduces derive_key() from the binary
# ============================================================================

def derive_key(passphrase: bytes, mask: bytes) -> bytes:
    """
    Reproduces the derive_key() function from crypto.c:
        1. sha_hash = SHA-256(passphrase)
        2. key[i] = sha_hash[i] ^ mask[i]  for i in 0..31

    Identified via:
        - GDB: break derive_key (on crypto_O0), step through
        - Ghidra: XREF from SHA-256 constants → calling function
          → XOR loop with KEY_MASK
    """
    sha_hash = hashlib.sha256(passphrase).digest()
    key = bytes(h ^ m for h, m in zip(sha_hash, mask))
    return key


# ============================================================================
# CRYPT24 format parsing — reconstructed in section 24.4
# ============================================================================

MAGIC = b"CRYPT24\x00"

def parse_crypt24(filepath: str) -> dict:
    """
    Parse a file in CRYPT24 format.

    Structure identified via:
        - ImHex: visual inspection of the first bytes
        - Data Inspector: uint16 LE confirmation for iv_length,
          uint32 LE for original_size
        - Entropy analysis: sharp transition at offset 0x20
        - .hexpat pattern: automatic assertion validation

    Returns a dict with header fields and the ciphertext.
    """
    with open(filepath, "rb") as f:
        data = f.read()

    # Minimal size checks
    if len(data) < 0x20:
        raise ValueError(
            f"File too short ({len(data)} bytes, minimum 32 for the header)"
        )

    # ── Magic (0x00, 8 bytes) ──────────────────────────────────
    magic = data[0x00:0x08]
    if magic != MAGIC:
        raise ValueError(
            f"Invalid magic: {magic!r} (expected {MAGIC!r})\n"
            f"This file is not in CRYPT24 format."
        )

    # ── Version (0x08, 2 bytes) ────────────────────────────────
    version_major = data[0x08]
    version_minor = data[0x09]
    if version_major != 1:
        raise ValueError(
            f"Major version {version_major} not supported "
            f"(this script only supports version 1.x)"
        )

    # ── IV length (0x0A, uint16 LE) ───────────────────────────
    iv_length = struct.unpack_from("<H", data, 0x0A)[0]
    if iv_length not in (8, 12, 16):
        raise ValueError(
            f"Unexpected IV length: {iv_length} "
            f"(expected 8, 12, or 16 bytes)"
        )

    # ── IV (0x0C, iv_length bytes) ─────────────────────────────
    iv_start = 0x0C
    iv_end = iv_start + iv_length
    iv = data[iv_start:iv_end]

    # ── Original size (after IV, uint32 LE) ────────────────────
    orig_size_offset = iv_end
    original_size = struct.unpack_from("<I", data, orig_size_offset)[0]

    # ── Ciphertext (after original_size, until EOF) ────────────
    ct_offset = orig_size_offset + 4
    ciphertext = data[ct_offset:]

    # Validation: ciphertext must be a multiple of BLOCK_SIZE
    if len(ciphertext) == 0:
        raise ValueError("Empty ciphertext")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext size ({len(ciphertext)}) is not a "
            f"multiple of {BLOCK_SIZE} — corrupted file or wrong format"
        )

    return {
        "version": (version_major, version_minor),
        "iv_length": iv_length,
        "iv": iv,
        "original_size": original_size,
        "ciphertext": ciphertext,
        "ct_offset": ct_offset,
    }


# ============================================================================
# AES-256-CBC decryption
# ============================================================================

def decrypt_aes256_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts an AES-256-CBC buffer and removes PKCS7 padding.

    Raises Crypto.Util.Padding.PaddingError if padding is invalid,
    which generally indicates an incorrect key or IV.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, BLOCK_SIZE)
    return plaintext


# ============================================================================
# Re-encryption verification (round-trip)
# ============================================================================

def verify_roundtrip(plaintext: bytes, key: bytes, iv: bytes,
                     expected_ct: bytes) -> bool:
    """
    Re-encrypts the plaintext with the same parameters and verifies that
    the resulting ciphertext is identical to the original.

    This is the strongest proof that the RE is correct: if the
    round-trip works, we have exactly reproduced the binary's behavior.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    re_encrypted = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return re_encrypted == expected_ct


# ============================================================================
# Entry point
# ============================================================================

def main():
    # ── Arguments ───────────────────────────────────────────────
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.enc> [output_file]")
        print()
        print("Decrypts a file in CRYPT24 format produced by ch24-crypto.")
        print("If no output file is specified, displays the content.")
        sys.exit(1)

    enc_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"[*] Chapter 24 Checkpoint — Decrypting {enc_path}")
    print(f"    Algorithm  : {ALGORITHM}")
    print(f"    Hash KDF   : {HASH_ALGO}")
    print()

    # ── Step 1: Derive the key ─────────────────────────────────
    print("[1/5] Key derivation...")
    key = derive_key(PASSPHRASE, KEY_MASK)
    sha_hex = hashlib.sha256(PASSPHRASE).hexdigest()

    print(f"      Passphrase      : {PASSPHRASE.decode()}")
    print(f"      SHA-256(phrase) : {sha_hex}")
    print(f"      XOR mask        : {KEY_MASK.hex()}")
    print(f"      Derived key     : {key.hex()}")
    print()

    # ── Step 2: Parse the .enc file ───────────────────────────
    print(f"[2/5] Parsing {enc_path}...")
    try:
        parts = parse_crypt24(enc_path)
    except (ValueError, FileNotFoundError) as e:
        print(f"      ERROR: {e}")
        sys.exit(1)

    print(f"      Version         : "
          f"{parts['version'][0]}.{parts['version'][1]}")
    print(f"      IV ({parts['iv_length']} bytes)    : {parts['iv'].hex()}")
    print(f"      Original size   : {parts['original_size']} bytes")
    print(f"      Ciphertext      : {len(parts['ciphertext'])} bytes "
          f"(starts at offset 0x{parts['ct_offset']:02X})")
    padding_size = len(parts["ciphertext"]) - parts["original_size"]
    print(f"      Expected padding: {padding_size} bytes (PKCS7)")
    print()

    # ── Step 3: Decrypt ───────────────────────────────────────
    print("[3/5] AES-256-CBC decryption...")
    try:
        plaintext = decrypt_aes256_cbc(
            parts["ciphertext"], key, parts["iv"]
        )
    except ValueError as e:
        print(f"      Padding ERROR: {e}")
        print()
        print("      Probable causes:")
        print("        - Incorrect key (check passphrase and mask)")
        print("        - Incorrect IV (check header parsing)")
        print("        - Wrong mode (verify it's indeed CBC)")
        print("        - Corrupted file")
        sys.exit(1)

    print(f"      Decrypted: {len(plaintext)} bytes")
    print()

    # ── Step 4: Validate ──────────────────────────────────────
    print("[4/5] Validation...")

    # 4a. Check size
    size_ok = len(plaintext) == parts["original_size"]
    if size_ok:
        print(f"      [OK] Size: {len(plaintext)} bytes "
              f"== original_size ({parts['original_size']})")
    else:
        print(f"      [!!] Size: {len(plaintext)} bytes "
              f"!= original_size ({parts['original_size']})")

    # 4b. Check round-trip
    roundtrip_ok = verify_roundtrip(
        plaintext, key, parts["iv"], parts["ciphertext"]
    )
    if roundtrip_ok:
        print(f"      [OK] Round-trip: re-encryption matches ciphertext")
    else:
        print(f"      [!!] Round-trip: re-encryption does not match")

    print()

    # ── Step 5: Result ────────────────────────────────────────
    print("[5/5] Result")

    if out_path:
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print(f"      Written to: {out_path}")
        print()
        print(f"      Final validation:")
        print(f"        $ diff secret.txt {out_path}")
        print(f"        (no output = success)")
    else:
        print()
        print("=" * 64)
        try:
            print(plaintext.decode("utf-8"), end="")
        except UnicodeDecodeError:
            print(f"(binary data, {len(plaintext)} bytes)")
            # Display first 256 bytes in hex
            preview = plaintext[:256]
            for i in range(0, len(preview), 16):
                chunk = preview[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in chunk
                )
                print(f"  {i:04x}  {hex_part:<48s}  {ascii_part}")
            if len(plaintext) > 256:
                print(f"  ... ({len(plaintext) - 256} bytes remaining)")
        print("=" * 64)

    # ── Summary ──────────────────────────────────────────────
    print()
    all_ok = size_ok and roundtrip_ok
    if all_ok:
        print("[+] CHECKPOINT PASSED")
        print("    The file was successfully decrypted.")
        print("    Key derivation and format are correctly reproduced.")
    else:
        print("[-] CHECKPOINT INCOMPLETE")
        print("    Decryption produced a result but validations failed.")
        print("    Recheck the key, IV, and format parsing.")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
