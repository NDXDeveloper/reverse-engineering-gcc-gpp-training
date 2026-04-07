#!/usr/bin/env python3
"""
solutions/ch23-checkpoint-client.py
Chapter 23 checkpoint solution

Replacement client for the ch23-network protocol,
fully reconstructed through reverse engineering from
the stripped binaries server_O2_strip and client_O2_strip.

⚠️  SPOILER — Only consult after attempting the checkpoint yourself.

Methodology followed:
  1. Triage: file, strings, checksec, ldd on both binaries.
  2. Observation: strace + Wireshark on a client/server session.
  3. Hypotheses: magic byte 0xC0, 4-byte header, types 0x01-0x04
     (requests) and 0x81-0x84 (responses), payload_len big-endian.
  4. Disassembly: Ghidra on server_O2_strip — locating the parser
     via XREF on recv/read, reconstructing handlers, identifying
     the XOR challenge in handle_auth.
  5. ImHex validation: .hexpat pattern on raw TCP export.
  6. Replay: naive replay (AUTH fails), XOR inversion to recover
     the password, adaptive replay (success).
  7. Standalone client: this file.

Credentials discovered (strings + GDB breakpoint on memcmp):
  admin    / s3cur3P@ss!
  analyst  / r3v3rs3M3
  guest    / guest123

Usage:
  python3 ch23-checkpoint-client.py [host] [-p PORT] [-u USER] [-P PASS]
  python3 ch23-checkpoint-client.py 127.0.0.1 -p 4444
  python3 ch23-checkpoint-client.py 127.0.0.1 -u guest -P guest123
  python3 ch23-checkpoint-client.py 127.0.0.1 -v          # debug mode

MIT License — Strictly educational use.
"""

from pwn import *
import argparse
import sys

# ═══════════════════════════════════════════════════════════════
#  Protocol Constants (reconstructed by RE)
# ═══════════════════════════════════════════════════════════════
#
#  Header (4 bytes):
#    [magic:1] [msg_type:1] [payload_len:2 big-endian]
#
#  msg_type field convention:
#    bit 7 = 0 → request (client → server)
#    bit 7 = 1 → response (server → client)
#    0xFF      → server error
#
#  State machine:
#    CONNECTED ──HELLO──▶ HELLO_DONE ──AUTH──▶ AUTHENTICATED
#    AUTHENTICATED ──CMD──▶ AUTHENTICATED (loop)
#    * ──QUIT──▶ DISCONNECTED
#
#  Authentication:
#    The password is XOR'd with the challenge (8 bytes) received
#    in the HELLO response, before being sent in the AUTH payload.
#    Cyclic XOR: password[i] ^= challenge[i % 8]
# ═══════════════════════════════════════════════════════════════

PROTO_MAGIC    = 0xC0
HEADER_SIZE    = 4
CHALLENGE_LEN  = 8

# Message types
MSG_HELLO_REQ  = 0x01
MSG_AUTH_REQ   = 0x02
MSG_CMD_REQ    = 0x03
MSG_QUIT_REQ   = 0x04
MSG_HELLO_RESP = 0x81
MSG_AUTH_RESP  = 0x82
MSG_CMD_RESP   = 0x83
MSG_QUIT_RESP  = 0x84
MSG_ERROR      = 0xFF

# Commands (CMD_REQ payload[0])
CMD_PING  = 0x01
CMD_LIST  = 0x02
CMD_READ  = 0x03
CMD_INFO  = 0x04

# Response status
STATUS_OK   = 0x01
STATUS_FAIL = 0x00

# Names for logging
MSG_NAMES = {
    0x01: "HELLO_REQ",  0x81: "HELLO_RESP",
    0x02: "AUTH_REQ",   0x82: "AUTH_RESP",
    0x03: "CMD_REQ",    0x83: "CMD_RESP",
    0x04: "QUIT_REQ",   0x84: "QUIT_RESP",
    0xFF: "ERROR",
}

CMD_NAMES = {
    0x01: "PING", 0x02: "LIST", 0x03: "READ", 0x04: "INFO",
}

ERR_NAMES = {
    0x01: "BAD_MAGIC",
    0x02: "BAD_TYPE",
    0x03: "WRONG_STATE",
    0x04: "AUTH_FAIL",
    0x05: "BAD_CMD",
    0x06: "PAYLOAD_TOO_LARGE",
}


# ═══════════════════════════════════════════════════════════════
#  Layer 1 — Transport
#
#  Packet serialization/deserialization.
#  Unaware of message semantics.
# ═══════════════════════════════════════════════════════════════

def proto_send(r, msg_type, payload=b""):
    """
    Build and send a protocol message.

    Wire format:
        [0xC0] [msg_type:1] [payload_len:2 BE] [payload:N]
    """
    plen = len(payload)
    header = bytes([
        PROTO_MAGIC,
        msg_type,
        (plen >> 8) & 0xFF,
        plen & 0xFF,
    ])
    r.send(header + payload)
    log.debug(f"TX → {MSG_NAMES.get(msg_type, f'0x{msg_type:02X}')}"
              f" | {plen} bytes payload"
              f" | {(header + payload[:16]).hex()}"
              f"{'...' if plen > 16 else ''}")


def proto_recv(r):
    """
    Receive and parse a protocol message.

    Returns:
        (msg_type, payload)

    Raises:
        EOFError      — connection closed
        ProtocolError — invalid magic byte
    """
    header = r.recvn(HEADER_SIZE)

    magic    = header[0]
    msg_type = header[1]
    plen     = (header[2] << 8) | header[3]

    if magic != PROTO_MAGIC:
        raise ProtocolError(
            f"Bad magic: 0x{magic:02X} (expected 0x{PROTO_MAGIC:02X})"
        )

    payload = r.recvn(plen) if plen > 0 else b""

    log.debug(f"RX ← {MSG_NAMES.get(msg_type, f'0x{msg_type:02X}')}"
              f" | {plen} bytes payload"
              f" | {(header + payload[:16]).hex()}"
              f"{'...' if plen > 16 else ''}")

    return msg_type, payload


class ProtocolError(Exception):
    """Protocol-level error (invalid magic, desync…)."""
    pass


class ServerError(Exception):
    """Error explicitly returned by the server (MSG_ERROR)."""
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(
            f"Server error [{ERR_NAMES.get(code, f'0x{code:02X}')}]: "
            f"{message}"
        )


def check_server_error(msg_type, payload):
    """
    Check if the response is a MSG_ERROR and raise an exception
    if so. Called by layer 2 functions.
    """
    if msg_type == MSG_ERROR:
        code = payload[0] if payload else 0x00
        text = payload[1:].decode("utf-8", errors="replace") \
               if len(payload) > 1 else "(no message)"
        raise ServerError(code, text)


# ═══════════════════════════════════════════════════════════════
#  Layer 2 — Protocol Operations
#
#  One function per protocol phase.
#  Builds payloads, interprets responses.
# ═══════════════════════════════════════════════════════════════

def xor_with_challenge(data, challenge):
    """
    Cyclic XOR of data with the 8-byte challenge.

    Discovered by RE in the server's authentication function:
    a loop that iterates over each byte of the password and XORs it
    with challenge[i % CHALLENGE_LEN]. The same code is present on
    both client side (to encode) and server side (to decode).
    """
    return bytes(d ^ challenge[i % CHALLENGE_LEN]
                 for i, d in enumerate(data))


def do_handshake(r):
    """
    Phase 1: HELLO handshake.

    Sends:    [HELLO_REQ] "HELLO" + 3 padding bytes (total 8)
    Receives: [HELLO_RESP] "WELCOME" (7) + challenge (8)

    The server verifies:
      - state == CONNECTED (otherwise ERR_WRONG_STATE)
      - payload starts with "HELLO" (otherwise ERR_BAD_TYPE)

    The challenge is an 8-byte random nonce generated by
    getrandom() server-side. It changes with each connection.

    Returns:
        bytes — the 8-byte challenge.
    """
    payload = b"HELLO" + b"\x00" * 3
    proto_send(r, MSG_HELLO_REQ, payload)

    msg_type, resp = proto_recv(r)
    check_server_error(msg_type, resp)

    if msg_type != MSG_HELLO_RESP:
        raise ProtocolError(
            f"Expected HELLO_RESP (0x{MSG_HELLO_RESP:02X}), "
            f"got 0x{msg_type:02X}"
        )

    if len(resp) < 7 + CHALLENGE_LEN:
        raise ProtocolError(
            f"HELLO_RESP payload too short: {len(resp)} bytes "
            f"(need {7 + CHALLENGE_LEN})"
        )

    banner    = resp[:7]
    challenge = resp[7:7 + CHALLENGE_LEN]

    if banner != b"WELCOME":
        log.warning(f"Unexpected banner: {banner!r} (expected b'WELCOME')")

    log.success(f"Handshake OK — challenge: {challenge.hex()}")
    return challenge


def do_auth(r, username, password, challenge):
    """
    Phase 2: Authentication.

    The password is XOR'd with the challenge before sending.
    This is the protection that prevents naive replay of the
    AUTH sequence (the challenge changes with each session).

    AUTH payload (length-prefixed strings):
        [user_len:1] [username:N] [pass_len:1] [password_xored:M]

    AUTH response:
        [reserved:1] [status:1]
        status = 0x01 (OK) or 0x00 (FAIL)

    The server verifies:
      - state == HELLO_DONE (otherwise ERR_WRONG_STATE)
      - Payload format (consistent lengths)
      - Credentials: XOR-decodes the password, compares with the
        internal database (3 hardcoded accounts).
      - Max 3 attempts per session (counter in session state).

    Returns:
        True if authenticated, False otherwise.
    """
    user_bytes  = username.encode("utf-8")
    pass_bytes  = password.encode("utf-8")
    pass_xored  = xor_with_challenge(pass_bytes, challenge)

    payload = (
        bytes([len(user_bytes)]) + user_bytes +
        bytes([len(pass_xored)]) + pass_xored
    )

    proto_send(r, MSG_AUTH_REQ, payload)

    msg_type, resp = proto_recv(r)

    # Handle MSG_ERROR (e.g., too many attempts)
    if msg_type == MSG_ERROR:
        code = resp[0] if resp else 0
        text = resp[1:].decode("utf-8", errors="replace") \
               if len(resp) > 1 else ""
        log.failure(f"Auth error [{ERR_NAMES.get(code, hex(code))}]: {text}")
        return False

    if msg_type != MSG_AUTH_RESP or len(resp) < 2:
        raise ProtocolError(
            f"Unexpected AUTH response: type=0x{msg_type:02X} "
            f"len={len(resp)}"
        )

    status = resp[1]

    if status == STATUS_OK:
        log.success(f"Authenticated as '{username}'")
        return True
    else:
        log.failure(f"Authentication failed for '{username}' "
                    f"(status=0x{status:02X})")
        return False


def do_command(r, cmd_id, args=b""):
    """
    Phase 3: Send a command.

    CMD_REQ payload:
        [command_id:1] [args:N]

    CMD_RESP payload:
        [status:1] [data:N]

    The server verifies:
      - state == AUTHENTICATED (otherwise ERR_WRONG_STATE)
      - valid command_id (otherwise ERR_BAD_CMD, non-fatal)

    Returns:
        (status, data) — status code and raw data.
    """
    payload = bytes([cmd_id]) + args
    proto_send(r, MSG_CMD_REQ, payload)

    msg_type, resp = proto_recv(r)
    check_server_error(msg_type, resp)

    if msg_type != MSG_CMD_RESP or len(resp) < 1:
        raise ProtocolError(
            f"Unexpected CMD response: type=0x{msg_type:02X}"
        )

    return resp[0], resp[1:]


def do_ping(r):
    """CMD PING → expect PONG."""
    status, data = do_command(r, CMD_PING)
    ok = (status == STATUS_OK and data == b"PONG")
    if ok:
        log.success("PING → PONG")
    else:
        log.warning(f"PING unexpected: status={status:#x} data={data!r}")
    return ok


def do_info(r):
    """CMD INFO → server information (text)."""
    status, data = do_command(r, CMD_INFO)
    if status == STATUS_OK:
        return data.decode("utf-8", errors="replace")
    return None


def do_list(r):
    """
    CMD LIST → list of available files.

    Response format (after status byte):
        [count:1]
        then for each file:
        [index:1] [name_len:1] [name:N]

    Returns:
        List of tuples (index, filename).
    """
    status, data = do_command(r, CMD_LIST)

    if status != STATUS_OK or len(data) < 1:
        return []

    count  = data[0]
    files  = []
    offset = 1

    for _ in range(count):
        if offset + 2 > len(data):
            break

        file_idx = data[offset]
        name_len = data[offset + 1]
        offset  += 2

        if offset + name_len > len(data):
            break

        name = data[offset:offset + name_len].decode(
            "utf-8", errors="replace"
        )
        offset += name_len
        files.append((file_idx, name))

    return files


def do_read(r, file_index):
    """
    CMD READ → read a file's content by its index.

    CMD_REQ payload: [CMD_READ] [file_index:1]
    Response: [STATUS_OK] [content:N]

    Returns:
        File content (str), or None on error.
    """
    status, data = do_command(r, CMD_READ, bytes([file_index]))
    if status == STATUS_OK and data:
        return data.decode("utf-8", errors="replace")
    return None


def do_quit(r):
    """
    Phase 4: Clean disconnect.

    Sends:    [QUIT_REQ] (empty payload)
    Receives: [QUIT_RESP] "BYE"

    Returns:
        True if the server acknowledged with BYE.
    """
    proto_send(r, MSG_QUIT_REQ)

    msg_type, resp = proto_recv(r)

    if msg_type == MSG_QUIT_RESP and resp[:3] == b"BYE":
        log.info("Disconnected (server sent BYE)")
        return True

    log.warning(f"Unexpected QUIT response: type=0x{msg_type:02X} "
                f"data={resp!r}")
    return False


# ═══════════════════════════════════════════════════════════════
#  Layer 3 — Scenarios
# ═══════════════════════════════════════════════════════════════

def full_session(host, port, username, password):
    """
    Complete session: handshake → auth → info → ping →
    list → read all files → quit.

    This is the scenario required by the checkpoint.
    """
    r = remote(host, port)

    try:
        # ── Phase 1: Handshake ──
        log.info("═" * 50)
        log.info("Phase 1 — Handshake")
        log.info("═" * 50)
        challenge = do_handshake(r)

        # ── Phase 2: Authentication ──
        log.info("═" * 50)
        log.info("Phase 2 — Authentication")
        log.info("═" * 50)
        if not do_auth(r, username, password, challenge):
            log.error("Authentication failed. Aborting.")
            r.close()
            return False

        # ── Phase 3: Commands ──
        log.info("═" * 50)
        log.info("Phase 3 — Commands")
        log.info("═" * 50)

        # PING
        do_ping(r)

        # INFO
        info = do_info(r)
        if info:
            log.info("Server info:")
            for line in info.strip().split("\n"):
                log.info(f"  {line}")

        # LIST
        files = do_list(r)
        if files:
            log.success(f"Available files ({len(files)}):")
            for idx, name in files:
                log.info(f"  [{idx}] {name}")
        else:
            log.warning("No files returned by LIST.")

        # READ all files
        log.info("═" * 50)
        log.info("Phase 4 — Reading all files")
        log.info("═" * 50)

        flag_found = False
        for idx, name in files:
            content = do_read(r, idx)
            if content:
                log.success(f"── {name} ──")
                for line in content.strip().split("\n"):
                    print(f"    {line}")

                    # Detect the flag
                    if "FLAG{" in line:
                        flag_found = True
                        log.success(f"🚩 FLAG FOUND: {line.strip()}")
            else:
                log.warning(f"Could not read file [{idx}] {name}")

        if not flag_found:
            log.warning("No FLAG{...} found in any file.")

        # ── Phase 5: Disconnect ──
        log.info("═" * 50)
        log.info("Phase 5 — Disconnect")
        log.info("═" * 50)
        do_quit(r)

        log.success("Session completed successfully.")
        return True

    except ServerError as e:
        log.error(f"Server error: {e}")
        return False
    except ProtocolError as e:
        log.error(f"Protocol error: {e}")
        return False
    except EOFError:
        log.error("Connection closed unexpectedly.")
        return False
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        return False
    finally:
        r.close()


def test_all_credentials(host, port):
    """
    Bonus: test the 3 accounts discovered by RE.
    Verifies that each can authenticate and execute commands.
    """
    # Credentials extracted by:
    #   1. strings server_O2_strip | grep -i pass
    #   2. GDB breakpoint on memcmp in handle_auth
    #   3. Reading adjacent strings in memory
    credentials = [
        ("admin",   "s3cur3P@ss!"),
        ("analyst", "r3v3rs3M3"),
        ("guest",   "guest123"),
    ]

    log.info("Testing all discovered credentials...")
    results = []

    for username, password in credentials:
        try:
            r = remote(host, port, level="error")
            challenge = do_handshake(r)
            success = do_auth(r, username, password, challenge)

            if success:
                # Verify we can execute a command
                status, _ = do_command(r, CMD_PING)
                cmd_ok = (status == STATUS_OK)
                do_quit(r)
            else:
                cmd_ok = False

            r.close()
            results.append((username, password, success, cmd_ok))

        except Exception as e:
            results.append((username, password, False, False))

    # Display summary
    print()
    log.info("Credentials test results:")
    log.info(f"  {'User':<12} {'Password':<16} {'Auth':<8} {'CMD':<8}")
    log.info(f"  {'─'*12} {'─'*16} {'─'*8} {'─'*8}")
    for user, pwd, auth_ok, cmd_ok in results:
        auth_str = "✓ OK" if auth_ok else "✗ FAIL"
        cmd_str  = "✓ OK" if cmd_ok else "✗ FAIL"
        log.info(f"  {user:<12} {pwd:<16} {auth_str:<8} {cmd_str:<8}")

    all_ok = all(auth and cmd for _, _, auth, cmd in results)
    if all_ok:
        log.success("All credentials validated.")
    else:
        log.failure("Some credentials failed.")

    return all_ok


# ═══════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=(
            "ch23-network checkpoint solution — "
            "Replacement client reconstructed by RE"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s 127.0.0.1
              %(prog)s 127.0.0.1 -p 4444 -u admin -P 's3cur3P@ss!'
              %(prog)s 127.0.0.1 -u guest -P guest123
              %(prog)s 127.0.0.1 --test-all
              %(prog)s 127.0.0.1 -v          # debug mode
        """)
    )

    parser.add_argument(
        "host", nargs="?", default="127.0.0.1",
        help="Server address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=4444,
        help="TCP port (default: 4444)"
    )
    parser.add_argument(
        "-u", "--user", default="admin",
        help="Username (default: admin)"
    )
    parser.add_argument(
        "-P", "--password", default="s3cur3P@ss!",
        help="Password (default: s3cur3P@ss!)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable DEBUG logging (displays each packet)"
    )
    parser.add_argument(
        "--test-all", action="store_true",
        help="Bonus: test the 3 accounts discovered by RE"
    )

    args = parser.parse_args()

    context.log_level = "debug" if args.verbose else "info"

    print()
    log.info("╔══════════════════════════════════════════╗")
    log.info("║  ch23-network — Checkpoint Solution      ║")
    log.info("║  Client reconstructed by RE              ║")
    log.info(f"║  Target: {args.host}:{args.port:<25}║")
    log.info("╚══════════════════════════════════════════╝")
    print()

    if args.test_all:
        success = test_all_credentials(args.host, args.port)
    else:
        success = full_session(
            args.host, args.port,
            args.user, args.password
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    import textwrap
    main()
