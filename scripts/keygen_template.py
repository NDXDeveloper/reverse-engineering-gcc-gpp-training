#!/usr/bin/env python3
"""
keygen_template.py — Reusable pwntools keygen template
Reverse Engineering Training — Applications compiled with the GNU toolchain

Template to copy and adapt for each new crackme.
Two-phase strategy:
  Phase 1 — Extraction: launch the binary under GDB, set a breakpoint
            on the comparison function (strcmp, memcmp, etc.),
            send a dummy input, and read the expected value from the
            registers at comparison time.
  Phase 2 — Verification: re-launch the binary normally with the
            extracted value and confirm that the input is accepted.

This template is pre-filled for keygenme_O0 (chapter 21) as an
example. Sections marked "ADAPT" must be modified for each new
target binary.

Usage:
  python3 keygen_template.py                          # default: keygenme_O0
  python3 keygen_template.py ./keygenme_O2_strip alice
  python3 keygen_template.py --remote 127.0.0.1 4444  # network mode

Dependencies:
  pip install pwntools

MIT License — Strictly educational use.
"""

from pwn import *
import re
import sys

# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION — ADAPT for each crackme
# ═══════════════════════════════════════════════════════════════

# Path to the target binary
BINARY = "./keygenme_O0"

# Architecture (affects p32/p64, asm, etc.)
context.arch = "amd64"
context.os = "linux"

# Pwntools log level ('debug' to see raw exchanges)
context.log_level = "warn"

# ── Binary prompts (strings to wait for before sending) ──
# Found via `strings` or during initial triage.
PROMPT_USERNAME = b"Enter username: "
PROMPT_KEY      = b"XXXX-XXXX-XXXX-XXXX): "

# ── Success / failure markers in the output ──
SUCCESS_MARKER = b"Valid license"
FAILURE_MARKER = b"Invalid license"

# ── Comparison function to intercept ──
# This is where the binary compares user input to the expected value.
# For strcmp: arg1 (RDI) = expected, arg2 (RSI) = user input.
# For memcmp: same, with arg3 (RDX) = length.
COMPARE_FUNC = "strcmp"

# ── Register containing the expected value ──
# System V AMD64 ABI: RDI = 1st argument, RSI = 2nd.
# In check_license() of keygenme.c: strcmp(expected, user_key)
# → RDI contains expected (the computed key).
EXPECTED_REG = "$rdi"

# ── Expected key format (regex) ──
# Used to extract the value from GDB output.
# keygenme: XXXX-XXXX-XXXX-XXXX (uppercase hex)
KEY_REGEX = r'([0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4})'

# ── Dummy input sent during extraction ──
DUMMY_KEY = "AAAA-BBBB-CCCC-DDDD"


# ═══════════════════════════════════════════════════════════════
#  Phase 1 — Extraction via GDB
# ═══════════════════════════════════════════════════════════════

def extract_key(binary, username):
    """Launch the binary under GDB and extract the expected value.

    Returns the key (str) or None if extraction fails.
    """
    # GDB script injected at launch:
    # 1. Breakpoint on the comparison function
    # 2. When hit: print the register containing the expected value
    # 3. Continue (the binary terminates normally)
    gdb_script = f'''
        set pagination off
        set confirm off
        break {COMPARE_FUNC}
        commands
            silent
            printf "KEYDUMP:%s\\n", (char*){EXPECTED_REG}
            continue
        end
        continue
    '''

    log.info(f"Extraction for username='{username}'")

    io = gdb.debug(binary, gdb_script, level='warn')

    try:
        io.recvuntil(PROMPT_USERNAME, timeout=10)
        io.sendline(username.encode())

        io.recvuntil(PROMPT_KEY, timeout=10)
        io.sendline(DUMMY_KEY.encode())

        # Read all output (program + GDB)
        output = io.recvall(timeout=10).decode(errors='replace')
    except EOFError:
        output = ""
    finally:
        io.close()

    # Extract the key from the KEYDUMP: prefix
    match = re.search(r'KEYDUMP:' + KEY_REGEX, output)
    if match:
        key = match.group(1)
        log.success(f"Extracted key: {key}")
        return key

    log.error("Extraction failed — key not found in GDB output")
    log.debug(f"Raw output:\n{output}")
    return None


# ═══════════════════════════════════════════════════════════════
#  Phase 2 — Verification
# ═══════════════════════════════════════════════════════════════

def verify_key(target, username, key):
    """Verify that a username/key pair is accepted by the binary.

    `target` is either a path (str) for a local process,
    or a tuple (host, port) for a network connection.

    Returns True if the key is accepted, False otherwise.
    """
    if isinstance(target, tuple):
        host, port = target
        io = remote(host, port)
    else:
        io = process(target)

    try:
        io.recvuntil(PROMPT_USERNAME, timeout=10)
        io.sendline(username.encode())

        io.recvuntil(PROMPT_KEY, timeout=10)
        io.sendline(key.encode())

        response = io.recvall(timeout=5)
    except EOFError:
        response = b""
    finally:
        io.close()

    if SUCCESS_MARKER in response:
        log.success("Key ACCEPTED")
        return True
    elif FAILURE_MARKER in response:
        log.error("Key REJECTED")
        return False
    else:
        log.warning("Unexpected response — neither success nor failure detected")
        log.debug(f"Raw response: {response}")
        return False


# ═══════════════════════════════════════════════════════════════
#  Complete keygen (extraction + verification)
# ═══════════════════════════════════════════════════════════════

def keygen(binary, username):
    """Complete workflow: extract the key then verify it.

    Returns the key (str) if the keygen works, None otherwise.
    """
    key = extract_key(binary, username)
    if key is None:
        return None

    if verify_key(binary, username, key):
        return key
    else:
        log.error("Extracted key was rejected — check the logic")
        return None


# ═══════════════════════════════════════════════════════════════
#  Batch mode: generate keys for multiple usernames
# ═══════════════════════════════════════════════════════════════

def batch_keygen(binary, usernames):
    """Generate keys for a list of usernames."""
    results = {}
    for username in usernames:
        log.info(f"--- {username} ---")
        key = keygen(binary, username)
        results[username] = key
        if key:
            print(f"{username} : {key}")
        else:
            print(f"{username} : FAILED")
    return results


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

def main():
    # Simple argument parsing (without argparse to keep it lightweight)
    args = sys.argv[1:]

    # Network mode: --remote HOST PORT
    if "--remote" in args:
        idx = args.index("--remote")
        host = args[idx + 1]
        port = int(args[idx + 2])
        username = args[idx + 3] if len(args) > idx + 3 else "student"
        # In network mode, GDB extraction is not available
        # The user must provide the key or adapt the script
        log.error("Network mode: GDB extraction not available.")
        log.info("Adapt extract_key() for your protocol, "
                 "or provide the key manually.")
        return

    # Local mode
    binary = args[0] if len(args) >= 1 else BINARY
    username = args[1] if len(args) >= 2 else "student"

    # Batch mode if multiple usernames provided
    if len(args) > 2:
        usernames = args[1:]
        batch_keygen(binary, usernames)
    else:
        key = keygen(binary, username)
        if key:
            print(f"\n{'='*40}")
            print(f"  Username : {username}")
            print(f"  Key      : {key}")
            print(f"{'='*40}\n")
            sys.exit(0)
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
