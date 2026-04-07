#!/usr/bin/env python3
"""
ch21-checkpoint-keygen.py — Chapter 21 checkpoint solution.

This script fulfills the 5 checkpoint criteria:
  1. Standalone keygen (doesn't depend on the binary to compute the key)
  2. Valid keys on keygenme_O0
  3. Valid keys on keygenme_O2
  4. Valid keys on keygenme_O2_strip
  5. Automated validation via pwntools

Usage:
  Generate a key:
    python3 ch21-checkpoint-keygen.py Alice

  Validate the keygen against the 3 variants:
    python3 ch21-checkpoint-keygen.py --validate

  Validate against all 5 variants:
    python3 ch21-checkpoint-keygen.py --validate-all

MIT License — Strictly educational use.
"""

import sys
import os
import random
import string

# ═══════════════════════════════════════════════════════════════
# PART 1 — STANDALONE KEYGEN
#
# Functions reconstructed from the keygenme disassembly.
# Each function corresponds to its equivalent in the binary,
# identified via static analysis in Ghidra (section 21.3)
# and dynamically verified in GDB (section 21.5).
# ═══════════════════════════════════════════════════════════════

def rotate_left_32(value: int, count: int) -> int:
    """
    32-bit left rotation.

    Corresponds to the `rotate_left` function in the binary.
    In x86-64 assembly, GCC emits either a direct ROL or the
    classic pattern: SHL + SHR + OR.

    The count &= 31 masking protects against the count == 0 case
    (which would cause a 32-bit shift — undefined behavior
    in C on a uint32_t, but handled correctly here).
    """
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def compute_hash(username: bytes) -> int:
    """
    Reproduces the keygenme's compute_hash function.

    Constants identified in the disassembly:
      - SEED  = 0x5A3C6E2D  (initial value of h, MOV imm32)
      - MUL   = 0x1003F     (multiplier, IMUL imm32)
      - XOR   = 0xDEADBEEF  (XOR mask, XOR imm32)
      - 0x45D9F3B           (final avalanche multiplier)

    Key points for translation:
      - Each arithmetic operation is masked to 32 bits
        (& 0xFFFFFFFF) to simulate C's uint32_t behavior.
      - The rotation uses (byte & 0x0F) as the count,
        extracting the 4 least significant bits of the current character.
    """
    SEED = 0x5A3C6E2D
    MUL  = 0x1003F
    XOR  = 0xDEADBEEF

    h = SEED

    for byte in username:
        h = (h + byte) & 0xFFFFFFFF
        h = (h * MUL) & 0xFFFFFFFF
        h = rotate_left_32(h, byte & 0x0F)
        h ^= XOR

    # Final avalanche — diffuses high-order bits into low-order
    # bits to improve distribution.
    # Recognizable pattern: XOR-shift + multiplication + XOR-shift.
    h ^= (h >> 16)
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)

    return h


def derive_key(hash_val: int) -> list:
    """
    Derives 4 groups of 16 bits from the hash.

    Corresponds to the `derive_key` function in the binary.
    Each group combines a 16-bit extraction (direct masking
    or rotation + masking) with an XOR by a constant.

    XOR constants identified in the disassembly:
      - groups[0] : 0xA5A5
      - groups[1] : 0x5A5A
      - groups[2] : 0x1234
      - groups[3] : 0xFEDC

    The 7-bit and 13-bit rotations for groups 2 and 3
    are visible as ROL imm8 or SHL/SHR/OR pairs
    with constants 7 and 13 as immediate operands.
    """
    groups = [
        (hash_val & 0xFFFF) ^ 0xA5A5,
        ((hash_val >> 16) & 0xFFFF) ^ 0x5A5A,
        (rotate_left_32(hash_val, 7) & 0xFFFF) ^ 0x1234,
        (rotate_left_32(hash_val, 13) & 0xFFFF) ^ 0xFEDC,
    ]
    return groups


def format_key(groups: list) -> str:
    """
    Formats the 4 groups as a XXXX-XXXX-XXXX-XXXX key.

    Corresponds to the `format_key` function in the binary,
    which calls snprintf with the format "%04X-%04X-%04X-%04X"
    (string identified during triage with strings, section 21.1).
    """
    return "{:04X}-{:04X}-{:04X}-{:04X}".format(*groups)


def keygen(username: str) -> str:
    """
    Generates a valid license key for the given username.

    Reproduces the complete chain:
      compute_hash(username) → derive_key(hash) → format_key(groups)

    This is exactly what check_license does in the binary,
    except for the final strcmp (the keygen produces the expected
    key, it doesn't need to compare).
    """
    h = compute_hash(username.encode("ascii"))
    groups = derive_key(h)
    return format_key(groups)


# ═══════════════════════════════════════════════════════════════
# PART 2 — AUTOMATED VALIDATION WITH PWNTOOLS
#
# Submits generated keys to the binaries and verifies they
# are accepted. Uses pwntools for interaction.
# ═══════════════════════════════════════════════════════════════

def find_binaries_dir() -> str:
    """
    Searches for the directory containing the keygenme binaries.
    Tries several common relative paths.
    """
    candidates = [
        ".",
        "./binaries/ch21-keygenme",
        "../binaries/ch21-keygenme",
        "../../binaries/ch21-keygenme",
    ]
    for d in candidates:
        if os.path.isfile(os.path.join(d, "keygenme_O0")):
            return d
    return "."


def validate_single(binary_path: str, username: str, key: str) -> bool:
    """
    Submits a username and key to the binary, returns True if
    the success message is detected in the output.
    """
    from pwn import process, context
    context.log_level = "error"

    try:
        p = process(binary_path)
        p.recvuntil(b"Enter username: ")
        p.sendline(username.encode())
        p.recvuntil(b": ")  # end of key prompt
        p.sendline(key.encode())
        response = p.recvall(timeout=3).decode(errors="replace")
        p.close()
        return "Valid license" in response
    except Exception as e:
        print(f"    [!] Error on {binary_path}: {e}")
        return False


def generate_test_usernames(count: int = 10) -> list:
    """
    Generates a list of varied test usernames.
    Includes edge cases (min/max length) and normal cases.
    """
    # Fixed cases covering different lengths and characters
    fixed = [
        "Alice",
        "Bob",
        "X1z",                       # minimum length (3)
        "ReverseEngineer",
        "user_2024",
        "AAAAAAA",                   # repeated characters
        "aZ9",                       # mix lower/upper/digit, length 3
        "ThisIsALongerUsername12345", # 25 characters
    ]

    # Random cases to supplement
    rand_count = max(0, count - len(fixed))
    charset = string.ascii_letters + string.digits
    for _ in range(rand_count):
        length = random.randint(3, 31)
        name = "".join(random.choices(charset, k=length))
        fixed.append(name)

    return fixed[:count]


def run_validation(binaries: dict, num_tests: int = 10):
    """
    Runs the complete keygen validation.

    Args:
        binaries: dict {label: path} of binaries to test.
        num_tests: number of usernames to test.
    """
    usernames = generate_test_usernames(num_tests)
    labels = list(binaries.keys())

    # ── Header ──────────────────────────────────────────────
    print()
    print("══════════════════════════════════════════════════════════════")
    print("  Checkpoint 21 — Keygen Validation")
    print("══════════════════════════════════════════════════════════════")
    print()

    # Check that binaries exist
    missing = [l for l, p in binaries.items() if not os.path.isfile(p)]
    if missing:
        print(f"  [!] Binaries not found: {', '.join(missing)}")
        print(f"      Check the path or compile with 'make'.")
        sys.exit(1)

    # ── Columns ─────────────────────────────────────────────
    col_user = 22
    col_key  = 24
    col_bin  = 6

    header_bins = "".join(f"{l:>{col_bin}}" for l in labels)
    print(f"  {'Username':<{col_user}}{'Generated Key':<{col_key}}{header_bins}")
    print(f"  {'─' * (col_user + col_key + col_bin * len(labels))}")

    # ── Tests ────────────────────────────────────────────────
    total = 0
    passed = 0
    failures = []

    for username in usernames:
        key = keygen(username)
        results = {}

        for label, path in binaries.items():
            ok = validate_single(path, username, key)
            results[label] = ok
            total += 1
            if ok:
                passed += 1
            else:
                failures.append((username, key, label))

        icons = "".join(
            f"{'  ✅' if results[l] else '  ❌':>{col_bin}}" for l in labels
        )

        # Truncate username and key for display
        udisp = username if len(username) <= col_user - 2 else username[:col_user - 4] + "…"
        print(f"  {udisp:<{col_user}}{key:<{col_key}}{icons}")

    # ── Summary ─────────────────────────────────────────────
    print()
    print(f"  Result: {passed}/{total} validations passed.")

    if failures:
        print()
        print("  Detailed failures:")
        for username, key, label in failures:
            print(f"    - username='{username}' key='{key}' binary={label}")
        print()
        print("  ❌ Checkpoint failed.")
        print()
        print("  Diagnostic hints:")
        print("    1. Check compute_hash: compare with GDB (break after compute_hash, print $eax)")
        print("    2. Check derive_key: compare the 4 groups with GDB (x/4hx on the array)")
        print("    3. Check format_key: compare with GDB (x/s $rdi before strcmp)")
        print("    4. Check pwntools interaction: does sendline send a spurious \\n?")
        sys.exit(1)
    else:
        print()
        print("  ✅ Checkpoint passed.")
        print()


# ═══════════════════════════════════════════════════════════════
# PART 3 — ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def print_usage():
    print(f"Usage:")
    print(f"  {sys.argv[0]} <username>          Generate a key")
    print(f"  {sys.argv[0]} --validate          Validate against O0, O2, O2_strip")
    print(f"  {sys.argv[0]} --validate-all      Validate against all 5 variants")
    print(f"  {sys.argv[0]} --hash <username>   Display the intermediate hash (debug)")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    arg = sys.argv[1]

    # ── Validation mode (3 variants required by the checkpoint) ──
    if arg == "--validate":
        d = find_binaries_dir()
        binaries = {
            "O0":  os.path.join(d, "keygenme_O0"),
            "O2":  os.path.join(d, "keygenme_O2"),
            "O2s": os.path.join(d, "keygenme_O2_strip"),
        }
        run_validation(binaries, num_tests=10)

    # ── Validation mode (5 variants, for going further) ─────────
    elif arg == "--validate-all":
        d = find_binaries_dir()
        binaries = {
            "O0":    os.path.join(d, "keygenme_O0"),
            "O2":    os.path.join(d, "keygenme_O2"),
            "O3":    os.path.join(d, "keygenme_O3"),
            "strip": os.path.join(d, "keygenme_strip"),
            "O2s":   os.path.join(d, "keygenme_O2_strip"),
        }
        run_validation(binaries, num_tests=10)

    # ── Debug mode: display the intermediate hash ───────────────
    elif arg == "--hash":
        if len(sys.argv) < 3:
            print("Usage: --hash <username>")
            sys.exit(1)
        username = sys.argv[2]
        h = compute_hash(username.encode("ascii"))
        groups = derive_key(h)
        key = format_key(groups)
        print(f"  Username  : {username}")
        print(f"  Hash      : 0x{h:08X}")
        print(f"  Groups    : [0x{groups[0]:04X}, 0x{groups[1]:04X}, "
              f"0x{groups[2]:04X}, 0x{groups[3]:04X}]")
        print(f"  License   : {key}")

    # ── Simple keygen mode ──────────────────────────────────────
    else:
        username = arg

        if len(username) < 3 or len(username) > 31:
            print("[-] Username must be between 3 and 31 characters.")
            sys.exit(1)

        key = keygen(username)
        print(f"[+] Username : {username}")
        print(f"[+] License  : {key}")


if __name__ == "__main__":
    main()
