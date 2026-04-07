🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 23.5 — Writing a Complete Replacement Client with `pwntools`

> 🎯 **Objective of this section**: transform all the knowledge accumulated since section 23.1 into a standalone Python client capable of communicating with the server without the original client binary. This client implements the protocol from scratch based on the specification reconstructed through reverse engineering. By the end of this section, you will have a reusable, scriptable, and extensible tool that fully replaces the original C client.

---

## From replay to standalone client

In section 23.4, the adaptive replay proved that our understanding of the protocol is complete. But a replay script remains dependent on the captured messages: it replays them (possibly adapting them), without being able to send new commands or interact freely with the server.

A **replacement client** goes further. It implements the protocol as a library: each message type is a Python function that builds the packet from scratch, sends it, reads the response, and returns the result in a usable form. These functions can then be composed to write arbitrary scenarios — automated tests, targeted fuzzing, exploration of undocumented commands, or data extraction.

We use `pwntools` for several reasons:

- **Robust TCP socket management**: the `remote()` class handles connections, timeouts, and errors concisely.  
- **Binary packing/unpacking**: the `p16()`, `u16()`, `p8()` etc. functions with endianness control simplify packet construction and parsing.  
- **Built-in logging**: `log.info()`, `log.success()`, `log.error()` produce structured and colored output that facilitates debugging.  
- **GDB integration**: if needed, `pwntools` can attach GDB to the remote process via `gdb.attach()`.  
- **CTF familiarity**: `pwntools` is the standard tool in the RE/CTF community, the code produced here will be directly reusable in other contexts.

---

## Client architecture

We structure the client in three layers, from lowest to highest level:

```
┌─────────────────────────────────────────────┐
│  Layer 3 — Scenarios (main, scripts)        │
│  Composes operations for complete           │
│  workflows: interactive session, file       │
│  extraction, bruteforce, fuzzing...         │
├─────────────────────────────────────────────┤
│  Layer 2 — Protocol operations              │
│  do_handshake(), do_auth(), do_command(),   │
│  do_quit() — one function per protocol      │
│  phase                                      │
├─────────────────────────────────────────────┤
│  Layer 1 — Transport (binary send/recv)     │
│  proto_send(), proto_recv() — serialization │
│  and deserialization of packets             │
└─────────────────────────────────────────────┘
```

This layer separation is a good general practice when writing an RE client: it makes the code testable, readable, and easily adaptable if the protocol evolves (for example between two versions of the binary).

---

## Layer 1 — Transport

The transport layer encapsulates packet serialization. It does not know the semantics of messages (HELLO, AUTH, CMD...) — it only knows how to build a packet with a 4-byte header and a variable-length payload, and parse the reverse on reception.

```python
#!/usr/bin/env python3
"""
ch23_client.py  
Replacement client for the ch23-network protocol.  
Reconstructed by reverse engineering — RE Training, Chapter 23.  
"""

from pwn import *

# ═══════════════════════════════════════════
#  Protocol constants
# ═══════════════════════════════════════════

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

# Commands
CMD_PING       = 0x01  
CMD_LIST       = 0x02  
CMD_READ       = 0x03  
CMD_INFO       = 0x04  

# Status
STATUS_OK      = 0x01  
STATUS_FAIL    = 0x00  

# Error codes
ERR_BAD_MAGIC      = 0x01  
ERR_BAD_TYPE       = 0x02  
ERR_WRONG_STATE    = 0x03  
ERR_AUTH_FAIL      = 0x04  
ERR_BAD_CMD        = 0x05  

# Human-readable names for logging
MSG_NAMES = {
    0x01: "HELLO_REQ",   0x81: "HELLO_RESP",
    0x02: "AUTH_REQ",    0x82: "AUTH_RESP",
    0x03: "CMD_REQ",     0x83: "CMD_RESP",
    0x04: "QUIT_REQ",    0x84: "QUIT_RESP",
    0xFF: "ERROR",
}

CMD_NAMES = {
    0x01: "PING", 0x02: "LIST", 0x03: "READ", 0x04: "INFO",
}
```

The constants are extracted directly from the disassembly (section 23.2). They are grouped at the top of the file to facilitate updates if a new version of the binary modifies the values.

### Transport functions

```python
# ═══════════════════════════════════════════
#  Layer 1 — Transport
# ═══════════════════════════════════════════

def proto_send(r, msg_type, payload=b""):
    """
    Send a protocol message.
    
    Wire format:
        [0xC0][msg_type:1][payload_len:2 BE][payload:N]
    
    Args:
        r:        pwntools connection (remote)
        msg_type: message type (uint8)
        payload:  payload data (bytes)
    """
    payload_len = len(payload)
    header = bytes([
        PROTO_MAGIC,
        msg_type,
        (payload_len >> 8) & 0xFF,   # big-endian high byte
        payload_len & 0xFF,           # big-endian low byte
    ])
    
    pkt = header + payload
    
    log.debug(f"TX [{MSG_NAMES.get(msg_type, hex(msg_type))}] "
              f"{payload_len} bytes payload")
    
    r.send(pkt)


def proto_recv(r):
    """
    Receive a protocol message.
    
    Returns:
        (msg_type, payload) — the message type and raw data.
        
    Raises:
        EOFError if the connection is closed.
        Exception if the magic byte is invalid.
    """
    header = r.recvn(HEADER_SIZE)
    
    magic     = header[0]
    msg_type  = header[1]
    payload_len = (header[2] << 8) | header[3]
    
    if magic != PROTO_MAGIC:
        log.error(f"Bad magic byte: 0x{magic:02X} (expected 0x{PROTO_MAGIC:02X})")
        raise Exception("Protocol desync — bad magic byte")
    
    payload = r.recvn(payload_len) if payload_len > 0 else b""
    
    log.debug(f"RX [{MSG_NAMES.get(msg_type, hex(msg_type))}] "
              f"{payload_len} bytes payload")
    
    return msg_type, payload
```

A few important points about this implementation:

- **`r.recvn(n)`** reads exactly `n` bytes, looping if necessary. It is the `pwntools` equivalent of the `recv_exact()` function we saw in the server's C code. Unlike `r.recv(n)` which returns *up to* `n` bytes, `recvn` guarantees that the buffer is complete. This is essential for a binary protocol where every byte counts.

- **Big-endian is handled manually** with shifts and masks, exactly as in the server's C code. One could also use `struct.pack(">H", payload_len)` or `p16(payload_len, endian='big')` from `pwntools` — both approaches are equivalent.

- **The magic byte is verified client-side.** Even though we are the ones writing the client, validating the magic byte on reception protects against stream misalignment (a byte lost or duplicated by a network bug would cause the entire parsing to drift). This is good defensive programming practice.

---

## Layer 2 — Protocol operations

Each phase of the protocol (handshake, authentication, command, disconnection) becomes a Python function that encapsulates sending the request, receiving the response, and interpreting the result.

### Handshake

```python
# ═══════════════════════════════════════════
#  Layer 2 — Protocol operations
# ═══════════════════════════════════════════

def do_handshake(r):
    """
    Perform the HELLO handshake.
    
    Sends:  [HELLO_REQ] "HELLO" + 3 padding bytes
    Expects: [HELLO_RESP] "WELCOME" + challenge (8 bytes)
    
    Returns:
        The 8-byte challenge (bytes), required for authentication.
    """
    # Build the HELLO payload
    payload = b"HELLO" + b"\x00" * 3
    
    proto_send(r, MSG_HELLO_REQ, payload)
    
    msg_type, resp = proto_recv(r)
    
    # Handle errors
    if msg_type == MSG_ERROR:
        err_code = resp[0] if resp else 0
        err_msg  = resp[1:].decode("utf-8", errors="replace") if len(resp) > 1 else ""
        log.error(f"Server error on HELLO: [{err_code:#x}] {err_msg}")
        raise Exception("Handshake failed")
    
    if msg_type != MSG_HELLO_RESP:
        log.error(f"Unexpected response type: {msg_type:#x}")
        raise Exception("Handshake failed — unexpected response")
    
    # Parse the response: "WELCOME" (7 bytes) + challenge (8 bytes)
    if len(resp) < 7 + CHALLENGE_LEN:
        log.error(f"HELLO response too short: {len(resp)} bytes")
        raise Exception("Handshake failed — truncated response")
    
    banner    = resp[:7]
    challenge = resp[7:7 + CHALLENGE_LEN]
    
    if banner != b"WELCOME":
        log.warning(f"Unexpected banner: {banner}")
    
    log.success(f"Handshake OK — challenge: {challenge.hex()}")
    
    return challenge
```

### Authentication

```python
def xor_with_challenge(data, challenge):
    """Cyclic XOR of data with the 8-byte challenge."""
    return bytes(
        d ^ challenge[i % CHALLENGE_LEN]
        for i, d in enumerate(data)
    )


def do_auth(r, username, password, challenge):
    """
    Perform authentication.
    
    The password is XOR-ed with the challenge before sending.
    
    AUTH payload:
        [user_len:1][username:N][pass_len:1][password_xored:M]
    
    Args:
        r:         pwntools connection
        username:  identifier (str)
        password:  plaintext password (str)
        challenge: challenge received during handshake (bytes, 8 bytes)
    
    Returns:
        True if authentication succeeded, False otherwise.
    """
    user_bytes = username.encode("utf-8")
    pass_bytes = password.encode("utf-8")
    
    # XOR the password with the challenge
    pass_xored = xor_with_challenge(pass_bytes, challenge)
    
    # Build the payload: length-prefixed strings
    payload = (
        bytes([len(user_bytes)]) +
        user_bytes +
        bytes([len(pass_xored)]) +
        pass_xored
    )
    
    proto_send(r, MSG_AUTH_REQ, payload)
    
    msg_type, resp = proto_recv(r)
    
    if msg_type == MSG_ERROR:
        err_code = resp[0] if resp else 0
        err_msg  = resp[1:].decode("utf-8", errors="replace") if len(resp) > 1 else ""
        log.error(f"Server error on AUTH: [{err_code:#x}] {err_msg}")
        return False
    
    if msg_type != MSG_AUTH_RESP or len(resp) < 2:
        log.error(f"Unexpected AUTH response: type={msg_type:#x} len={len(resp)}")
        return False
    
    reserved = resp[0]
    status   = resp[1]
    
    if status == STATUS_OK:
        log.success(f"Authenticated as '{username}'")
        return True
    else:
        log.failure(f"Authentication failed (status={status:#x})")
        return False
```

The XOR with the challenge is implemented exactly as in the client's C code (section 23.2). The byte-for-byte correspondence between our Python implementation and the original C code can be verified by capturing both with Wireshark and comparing the packets.

### Commands

```python
def do_command(r, cmd_id, args=b""):
    """
    Send a command and receive the response.
    
    CMD_REQ payload:
        [command_id:1][args:N]
    
    CMD_RESP payload:
        [status:1][data:N]
    
    Args:
        r:      pwntools connection
        cmd_id: command identifier (CMD_PING, CMD_LIST, etc.)
        args:   command arguments (bytes)
    
    Returns:
        (status, data) — the status code and response data.
    """
    cmd_name = CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}")
    
    payload = bytes([cmd_id]) + args
    proto_send(r, MSG_CMD_REQ, payload)
    
    msg_type, resp = proto_recv(r)
    
    if msg_type == MSG_ERROR:
        err_code = resp[0] if resp else 0
        err_msg  = resp[1:].decode("utf-8", errors="replace") if len(resp) > 1 else ""
        log.error(f"Server error on CMD {cmd_name}: [{err_code:#x}] {err_msg}")
        return STATUS_FAIL, b""
    
    if msg_type != MSG_CMD_RESP or len(resp) < 1:
        log.error(f"Unexpected CMD response: type={msg_type:#x}")
        return STATUS_FAIL, b""
    
    status = resp[0]
    data   = resp[1:] if len(resp) > 1 else b""
    
    if status == STATUS_OK:
        log.debug(f"CMD {cmd_name} OK — {len(data)} bytes data")
    else:
        log.warning(f"CMD {cmd_name} failed — status={status:#x}")
    
    return status, data


def do_ping(r):
    """Send a PING and verify the PONG."""
    status, data = do_command(r, CMD_PING)
    if status == STATUS_OK and data == b"PONG":
        log.success("PING → PONG")
        return True
    return False


def do_list(r):
    """
    List available files.
    
    LIST response format:
        [count:1] then for each file:
        [index:1][name_len:1][name:N]
    
    Returns:
        List of tuples (index, file_name).
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
        
        file_index = data[offset]
        name_len   = data[offset + 1]
        offset += 2
        
        if offset + name_len > len(data):
            break
        
        name = data[offset : offset + name_len].decode("utf-8", errors="replace")
        offset += name_len
        
        files.append((file_index, name))
    
    return files


def do_read(r, file_index):
    """
    Read the contents of a file by its index.
    
    Returns:
        The file contents (str), or None on error.
    """
    status, data = do_command(r, CMD_READ, bytes([file_index]))
    
    if status == STATUS_OK and data:
        return data.decode("utf-8", errors="replace")
    return None


def do_info(r):
    """
    Retrieve server information.
    
    Returns:
        Information string (str), or None on error.
    """
    status, data = do_command(r, CMD_INFO)
    
    if status == STATUS_OK and data:
        return data.decode("utf-8", errors="replace")
    return None


def do_quit(r):
    """
    Send the QUIT command and receive the acknowledgment.
    
    Returns:
        True if the server responded with BYE.
    """
    proto_send(r, MSG_QUIT_REQ)
    
    msg_type, resp = proto_recv(r)
    
    if msg_type == MSG_QUIT_RESP and resp[:3] == b"BYE":
        log.info("Server acknowledged disconnect (BYE)")
        return True
    
    return False
```

Each Layer 2 function follows the same pattern: build the payload, call `proto_send`, call `proto_recv`, interpret the response, return a clean result. The specialized functions (`do_ping`, `do_list`, `do_read`, `do_info`) are shortcuts that call `do_command` with the appropriate `cmd_id` and parse the response format specific to each command.

---

## Layer 3 — Scenarios

Layer 3 composes protocol operations into complete workflows. This is where the high-level logic lives: establishing a complete session, extracting all files, or performing specific actions.

### Complete session with file extraction

```python
# ═══════════════════════════════════════════
#  Layer 3 — Scenarios
# ═══════════════════════════════════════════

def full_session(host, port, username, password):
    """
    Execute a complete session:
    handshake → auth → list → read all → quit.
    """
    r = remote(host, port)
    
    try:
        # ── Handshake ──
        log.info("Phase 1: Handshake")
        challenge = do_handshake(r)
        
        # ── Authentication ──
        log.info("Phase 2: Authentication")
        if not do_auth(r, username, password, challenge):
            log.error("Authentication failed — aborting.")
            r.close()
            return False
        
        # ── Server information ──
        log.info("Phase 3: Server info")
        info = do_info(r)
        if info:
            log.info(f"Server info:\n{info}")
        
        # ── Ping ──
        do_ping(r)
        
        # ── File listing ──
        log.info("Phase 4: File listing")
        files = do_list(r)
        
        if files:
            log.success(f"Found {len(files)} files:")
            for idx, name in files:
                log.info(f"  [{idx}] {name}")
            
            # ── Read each file ──
            log.info("Phase 5: Reading all files")
            for idx, name in files:
                content = do_read(r, idx)
                if content:
                    log.success(f"── {name} ──")
                    print(content, end="")
                    if not content.endswith("\n"):
                        print()
        
        # ── Disconnect ──
        log.info("Phase 6: Disconnect")
        do_quit(r)
        
        log.success("Session completed successfully.")
        return True
    
    except EOFError:
        log.error("Connection closed unexpectedly.")
        return False
    except Exception as e:
        log.error(f"Session error: {e}")
        return False
    finally:
        r.close()
```

### Entry point

```python
# ═══════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ch23-network — Replacement client (pwntools)",
        epilog="Reconstructed by RE — Reverse Engineering Training, Ch.23"
    )
    parser.add_argument("host", nargs="?", default="127.0.0.1",
                        help="Server address (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=4444,
                        help="TCP port (default: 4444)")
    parser.add_argument("-u", "--user", default="admin",
                        help="Username (default: admin)")
    parser.add_argument("-P", "--password", default="s3cur3P@ss!",
                        help="Password (default: s3cur3P@ss!)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable DEBUG logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        context.log_level = "debug"
    else:
        context.log_level = "info"
    
    full_session(args.host, args.port, args.user, args.password)
```

---

## Execution and validation

### Nominal test

```bash
# Terminal 1: start the server
$ ./build/server_O0

# Terminal 2: start the Python client
$ python3 ch23_client.py 127.0.0.1 -p 4444 -u admin -P 's3cur3P@ss!'
[+] Opening connection to 127.0.0.1 on port 4444: Done
[*] Phase 1: Handshake
[+] Handshake OK — challenge: b73a9e21f0884c17
[*] Phase 2: Authentication
[+] Authenticated as 'admin'
[*] Phase 3: Server info
[*] Server info:
    ch23-network server v1.0
    Protocol: custom binary
    Build: GCC 13.2.0
[+] PING → PONG
[*] Phase 4: File listing
[+] Found 4 files:
[*]   [0] readme.txt
[*]   [1] notes.txt
[*]   [2] config.dat
[*]   [3] flag.txt
[*] Phase 5: Reading all files
[+] ── readme.txt ──
Welcome to the secret server.  
Access level: CLASSIFIED  
[+] ── notes.txt ──
TODO: rotate encryption keys  
TODO: fix auth bypass in v2.1  
[+] ── config.dat ──
port=4444  
max_conn=16  
log_level=2  
[+] ── flag.txt ──
FLAG{pr0t0c0l_r3v3rs3d_succ3ssfully}
[*] Phase 6: Disconnect
[*] Server acknowledged disconnect (BYE)
[+] Session completed successfully.
[*] Closed connection to 127.0.0.1 port 4444
```

The Python client produces exactly the same result as the original C client. The flag is extracted.

### Cross-validation with Wireshark

To prove that our client is protocolically identical to the original client, we capture both sessions with Wireshark and compare:

```bash
# Capture the C client session
$ sudo tcpdump -i lo -w session_c.pcap port 4444 &
$ ./build/client_O0 127.0.0.1
$ kill %1

# Capture the Python client session
$ sudo tcpdump -i lo -w session_py.pcap port 4444 &
$ python3 ch23_client.py
$ kill %1
```

By opening both captures in Wireshark and comparing the "Follow TCP Stream", we verify that:

- The headers are identical (same magic, same types, same lengths).  
- The HELLO payload is identical (`"HELLO"` + 3 padding bytes).  
- The AUTH payload has the same structure (same username/password lengths), only the XOR differs (because the challenge differs between the two sessions).  
- The CMD payloads are identical.  
- The QUIT is identical.

If a byte differs unexpectedly, it means there is a remaining misunderstanding in the specification. We then go back to the disassembly (section 23.2) to correct it.

---

## Advanced usage of the client as a library

The layered architecture of the client allows importing it as a Python module in other scripts. Instead of running it via `main()`, we use the functions directly.

### Example: targeted file extraction

```python
from ch23_client import *

context.log_level = "warning"   # reduce noise

r = remote("127.0.0.1", 4444)

challenge = do_handshake(r)  
do_auth(r, "analyst", "r3v3rs3M3", challenge)  

# Read only flag.txt (index 3)
content = do_read(r, 3)  
print(content)  

do_quit(r)  
r.close()  
```

### Example: testing all known accounts

```python
from ch23_client import *

context.log_level = "error"

credentials = [
    ("admin",   "s3cur3P@ss!"),
    ("analyst", "r3v3rs3M3"),
    ("guest",   "guest123"),
    ("root",    "toor"),          # should fail
    ("admin",   "wrongpass"),     # should fail
]

for username, password in credentials:
    try:
        r = remote("127.0.0.1", 4444)
        challenge = do_handshake(r)
        success = do_auth(r, username, password, challenge)
        
        status = "✓" if success else "✗"
        print(f"  {status}  {username}:{password}")
        
        if success:
            do_quit(r)
        r.close()
    except Exception:
        print(f"  ✗  {username}:{password} (connection error)")
```

```
  ✓  admin:s3cur3P@ss!
  ✓  analyst:r3v3rs3M3
  ✓  guest:guest123
  ✗  root:toor
  ✗  admin:wrongpass
```

### Example: password bruteforce

The challenge changes with each connection, but our client handles it natively. We can therefore write a bruteforce that tests passwords from a wordlist:

```python
from ch23_client import *

context.log_level = "error"

def try_login(host, port, username, password):
    """Attempt a connection and return True if AUTH succeeds."""
    try:
        r = remote(host, port)
        challenge = do_handshake(r)
        result = do_auth(r, username, password, challenge)
        r.close()
        return result
    except Exception:
        return False

# Load a wordlist
with open("/usr/share/wordlists/rockyou.txt", "r",
          errors="ignore") as f:
    passwords = [line.strip() for line in f][:1000]  # limit for testing

target_user = "admin"  
log.info(f"Bruteforcing '{target_user}' with {len(passwords)} passwords...")  

for i, pwd in enumerate(passwords):
    if try_login("127.0.0.1", 4444, target_user, pwd):
        log.success(f"Found password: {target_user}:{pwd}")
        break
    if (i + 1) % 100 == 0:
        log.info(f"  Tested {i+1}/{len(passwords)}...")
else:
    log.failure("Password not found in wordlist.")
```

> ⚠️ **Note**: the server implements a limit of 3 attempts per session (`MAX_AUTH_RETRIES`). Our bruteforce creates a **new connection** for each attempt, which bypasses this protection since the counter is tied to the session. In real-world conditions, a server could implement IP-based rate-limiting or increasing delays between attempts — which our educational server intentionally does not.

### Example: exploring undocumented commands

During disassembly, we saw that the dispatch uses a `switch` with commands `0x01` through `0x04`. What happens if we send an undocumented `cmd_id`? Our client makes it easy to test:

```python
from ch23_client import *

r = remote("127.0.0.1", 4444)  
challenge = do_handshake(r)  
do_auth(r, "admin", "s3cur3P@ss!", challenge)  

# Test undocumented commands
for cmd_id in range(0x00, 0x10):
    try:
        status, data = do_command(r, cmd_id, b"\x00")
        result = data.decode("utf-8", errors="replace") if data else "(empty)"
        print(f"  CMD 0x{cmd_id:02X}: status={status:#x} data={result[:40]}")
    except Exception as e:
        print(f"  CMD 0x{cmd_id:02X}: error — {e}")
        # Reconnect if the session was terminated
        r.close()
        r = remote("127.0.0.1", 4444)
        challenge = do_handshake(r)
        do_auth(r, "admin", "s3cur3P@ss!", challenge)

r.close()
```

This type of exploration is a classic RE technique: we test the parser's limits to discover hidden features, edge case handling errors, or unexpected behaviors that could constitute vulnerabilities.

---

## Debugging the client with Wireshark and GDB

### When the client does not work

If a command fails unexpectedly, the debugging methodology is as follows:

1. **Enable verbose mode** (`-v` or `context.log_level = "debug"`) to see each packet sent and received.

2. **Capture with Wireshark** during the Python client's execution, then compare the traffic with a capture from the original C client. The difference is almost always found in a poorly constructed payload field.

3. **Set a GDB breakpoint on the server-side handler.** For example, if AUTH fails, we launch the server under GDB with a breakpoint on `handle_auth` (or at the equivalent address if stripped), then execute the Python client. At the breakpoint, we inspect the `payload` buffer to verify that the received data matches what the client sent:

```bash
$ gdb ./build/server_O0
(gdb) break handle_auth
(gdb) run
# ... in another terminal, start the Python client
# ... GDB stops at handle_auth
(gdb) x/32bx payload      # examine the first 32 bytes of the payload
(gdb) p payload_len        # verify the length
(gdb) p sess->challenge    # verify the challenge
```

4. **Compare byte by byte** the payload received by the server with what the Python client claims to have sent. If a misalignment appears, it is generally a payload construction issue: a length field calculated with or without the null terminator, missing padding, or reversed endianness.

### Common mistake: forgetting the HELLO padding

The original C client's HELLO payload is 8 bytes: `"HELLO"` (5 bytes) + 3 padding bytes (`\x00\x00\x00`). If the Python client sends only `b"HELLO"` (5 bytes) with a `payload_len` of 5, the server may not check the exact size and accept it anyway — or may reject the packet if the handler tests `payload_len < 8`. This type of detail is only visible in the disassembly, not in the network capture (where padding blends in with null bytes).

### Common mistake: length field endianness

If the `payload_len` is encoded in little-endian by mistake in `proto_send`, a payload of 8 bytes will be announced as `0x0800` (2048) instead of `0x0008` (8). The server will try to read 2048 bytes of payload, will never receive them, and the connection will remain stuck until timeout. This bug is immediately visible in Wireshark: bytes 2 and 3 of the header are reversed compared to the reference capture.

---

## Section summary

| Layer | Contents | Role |  
|-------|----------|------|  
| 1 — Transport | `proto_send()`, `proto_recv()` | Serialize/deserialize packets (magic, type, length, payload) |  
| 2 — Operations | `do_handshake()`, `do_auth()`, `do_command()`, `do_quit()` + specializations | Encapsulate each protocol phase |  
| 3 — Scenarios | `full_session()`, exploration scripts, bruteforce... | Compose operations into complete workflows |

The replacement client produced in this section is the **final deliverable of the chapter**. It proves that the protocol has been fully understood: every field, every mechanism (challenge XOR), every state transition is implemented in Python, validated by a complete session with the server, and verified by Wireshark capture. The `ch23_client.py` file is also a **usable operational tool** for exploration, testing, and automating interactions with the server.

The chapter checkpoint will require using these techniques to write a client capable of authenticating with the server and extracting the flag — exactly what this script accomplishes.

⏭️ [🎯 Checkpoint: write a Python client capable of authenticating with the server without knowing the source code](/23-network/checkpoint.md)
