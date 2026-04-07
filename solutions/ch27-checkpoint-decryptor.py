#!/usr/bin/env python3
"""
============================================================================
 Reverse Engineering Training — Chapter 27
 SOLUTION: Decryptor for the Ch27 pedagogical ransomware
============================================================================

 Cryptographic parameters extracted by:
   - Static analysis (Ghidra): XREF to EVP_EncryptInit_ex,
     key and IV in .rodata
   - Dynamic analysis (GDB/Frida): capture of $rcx (key) and $r8 (IV)
     at the EVP_EncryptInit_ex call

 .locked file format (mapped with ImHex):
   [0x00 - 0x07]  Magic: "RWARE27\0"
   [0x08 - 0x0F]  Original size: uint64_t little-endian
   [0x10 - EOF ]  AES-256-CBC ciphertext (PKCS#7 padding included)

 Dependency:
   pip install cryptography

 Usage:
   python3 ch27-checkpoint-decryptor.py                        # /tmp/test/
   python3 ch27-checkpoint-decryptor.py /path/to/directory
   python3 ch27-checkpoint-decryptor.py file.txt.locked
   python3 ch27-checkpoint-decryptor.py --dry-run
   python3 ch27-checkpoint-decryptor.py --verify

 License: MIT — educational use only
============================================================================
"""

import sys
import os
import struct
import hashlib
import argparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ═══════════════════════════════════════════════════════════════════════════
#  Constants Extracted by Reverse Engineering
# ═══════════════════════════════════════════════════════════════════════════

# AES-256 key (32 bytes)
# Source: binary's .rodata, confirmed via $rcx register on
#         EVP_EncryptInit_ex (GDB breakpoint + Frida hook)
# ASCII value: REVERSE_ENGINEERING_IS_FUN_2025!
AES_KEY = bytes([
    0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x45, 0x5F,  # REVERSE_
    0x45, 0x4E, 0x47, 0x49, 0x4E, 0x45, 0x45, 0x52,  # ENGINEER
    0x49, 0x4E, 0x47, 0x5F, 0x49, 0x53, 0x5F, 0x46,  # ING_IS_F
    0x55, 0x4E, 0x5F, 0x32, 0x30, 0x32, 0x35, 0x21,  # UN_2025!
])

# AES-CBC IV (16 bytes)
# Source: binary's .rodata, confirmed via $r8 register on
#         EVP_EncryptInit_ex (GDB breakpoint + Frida hook)
AES_IV = bytes([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE,
])

# .locked file format (mapped with ImHex)
MAGIC_HEADER = b"RWARE27\x00"   # 8 bytes, offset 0x00
HEADER_SIZE  = 16                # 8 (magic) + 8 (orig_size)
LOCKED_EXT   = ".locked"


# ═══════════════════════════════════════════════════════════════════════════
#  .locked Header Parsing
# ═══════════════════════════════════════════════════════════════════════════

def parse_locked_header(filepath):
    """
    Reads and validates the header of a .locked file.

    Returns:
        (original_size, ciphertext) — original size and encrypted data

    Raises ValueError if:
        - The file is too small (< 16 bytes)
        - The magic header doesn't match
        - The announced size is inconsistent
    """
    with open(filepath, "rb") as f:
        header = f.read(HEADER_SIZE)

        if len(header) < HEADER_SIZE:
            raise ValueError(
                f"File too small ({len(header)} bytes, "
                f"minimum {HEADER_SIZE}): {filepath}"
            )

        # Check magic (first 8 bytes)
        magic = header[0:8]
        if magic != MAGIC_HEADER:
            raise ValueError(
                f"Invalid magic header in {filepath}: "
                f"expected {MAGIC_HEADER!r}, got {magic!r}"
            )

        # Extract original size (uint64_t little-endian, offset 0x08)
        original_size = struct.unpack("<Q", header[8:16])[0]

        # Basic consistency check
        if original_size == 0:
            raise ValueError(f"Zero original size in {filepath}")

        # Read the ciphertext (everything after the header)
        ciphertext = f.read()

    # Ciphertext must be a multiple of 16 (AES block size)
    if len(ciphertext) == 0:
        raise ValueError(f"No encrypted data in {filepath}")

    if len(ciphertext) % 16 != 0:
        raise ValueError(
            f"Ciphertext size ({len(ciphertext)} bytes) not a multiple "
            f"of 16 in {filepath} — file probably corrupted"
        )

    return original_size, ciphertext


# ═══════════════════════════════════════════════════════════════════════════
#  AES-256-CBC Decryption
# ═══════════════════════════════════════════════════════════════════════════

def decrypt_aes256cbc(ciphertext, key, iv):
    """
    Decrypts an AES-256-CBC buffer and removes PKCS#7 padding.

    This is the inverse of the OpenSSL sequence observed in the sample:
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)
        EVP_EncryptUpdate(ctx, out, &len, in, in_len)
        EVP_EncryptFinal_ex(ctx, out + len, &len)

    Returns the plaintext without padding.
    Raises ValueError if the key/IV is incorrect (invalid padding).
    """
    # Decryption
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    # 128 = AES block size in BITS (not bytes)
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


# ═══════════════════════════════════════════════════════════════════════════
#  Complete File Decryption
# ═══════════════════════════════════════════════════════════════════════════

def decrypt_file(locked_path, dry_run=False, verify=False):
    """
    Decrypts a .locked file and restores the original file.

    Steps:
        1. Parse the header (magic + original size)
        2. Decrypt the AES-256-CBC payload
        3. Verify consistency between decrypted size and announced size
        4. Write the restored file (without the .locked extension)

    Returns the restored file path, or None on failure.
    """
    print(f"[*] {locked_path}")

    # ── 1. Parse the header ──
    try:
        original_size, ciphertext = parse_locked_header(locked_path)
    except ValueError as e:
        print(f"    [!] Invalid header: {e}")
        return None

    print(f"    Original size: {original_size} bytes")
    print(f"    Ciphertext:    {len(ciphertext)} bytes")

    # ── 2. Decrypt ──
    try:
        plaintext = decrypt_aes256cbc(ciphertext, AES_KEY, AES_IV)
    except ValueError as e:
        print(f"    [!] Decryption failed: {e}")
        print(f"    [!] The key or IV is probably incorrect.")
        return None
    except Exception as e:
        print(f"    [!] Unexpected error: {e}")
        return None

    # ── 3. Cross-check size ──
    if len(plaintext) != original_size:
        print(
            f"    [!] Size inconsistency: "
            f"decrypted={len(plaintext)}, announced={original_size}"
        )
        # Truncate to announced size as safety net
        plaintext = plaintext[:original_size]
        print(f"    [!] Truncated to {original_size} bytes")

    # ── 4. Determine output path ──
    if locked_path.endswith(LOCKED_EXT):
        output_path = locked_path[:-len(LOCKED_EXT)]
    else:
        output_path = locked_path + ".decrypted"

    # ── Dry-run mode: don't write ──
    if dry_run:
        print(f"    [DRY-RUN] → {output_path} ({len(plaintext)} bytes)")
        return output_path

    # ── Write the restored file ──
    with open(output_path, "wb") as f:
        f.write(plaintext)

    # ── SHA-256 hash of the restored file ──
    sha256 = hashlib.sha256(plaintext).hexdigest()
    print(f"    [✓] → {output_path} ({len(plaintext)} bytes)")
    print(f"        SHA-256: {sha256}")

    # ── Preview if requested ──
    if verify:
        preview_len = min(80, len(plaintext))
        try:
            preview = plaintext[:preview_len].decode("utf-8", errors="replace")
            print(f"        Preview: {preview!r}")
        except Exception:
            print(f"        Preview: {plaintext[:preview_len].hex()}")

    return output_path


# ═══════════════════════════════════════════════════════════════════════════
#  Recursive Directory Traversal
# ═══════════════════════════════════════════════════════════════════════════

def scan_and_decrypt(directory, dry_run=False, verify=False):
    """
    Recursively traverses a directory and decrypts all .locked files.
    Returns (success_count, error_count).
    """
    success = 0
    errors  = 0
    skipped = 0

    for root, _dirs, files in os.walk(directory):
        for filename in sorted(files):
            filepath = os.path.join(root, filename)

            if not filename.endswith(LOCKED_EXT):
                skipped += 1
                continue

            result = decrypt_file(filepath, dry_run=dry_run, verify=verify)
            if result:
                success += 1
            else:
                errors += 1

    print()
    print("=" * 55)
    print(f"  Result: {success} restored, "
          f"{errors} error(s), {skipped} skipped")
    print("=" * 55)

    return success, errors


# ═══════════════════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Decryptor for the Ch27 ransomware (AES-256-CBC)",
        epilog="Reverse Engineering Training — Chapter 27 — Solution"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="/tmp/test",
        help=".locked file or directory to process (default: /tmp/test)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate without writing files"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Display a preview of decrypted content"
    )
    args = parser.parse_args()

    # Banner
    print()
    print("=" * 55)
    print("  Ch27 Decryptor — Checkpoint Solution")
    print(f"  Algorithm: AES-256-CBC")
    print(f"  Key: {AES_KEY.decode('ascii')}")
    print(f"  IV:  {AES_IV.hex()}")
    print("=" * 55)
    print()

    target = args.target

    if os.path.isfile(target):
        result = decrypt_file(target, dry_run=args.dry_run, verify=args.verify)
        sys.exit(0 if result else 1)

    elif os.path.isdir(target):
        success, errors = scan_and_decrypt(
            target, dry_run=args.dry_run, verify=args.verify
        )
        sys.exit(0 if errors == 0 else 1)

    else:
        print(f"[!] Target not found: {target}")
        sys.exit(1)


if __name__ == "__main__":
    main()
