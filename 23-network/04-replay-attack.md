🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 23.4 — Replay Attack: replaying a captured request

> 🎯 **Objective of this section**: validate our understanding of the protocol by replaying a captured communication to the real server, observe what works and what fails, then understand *why* certain sequences are not replayable. By the end of this section, you will know how to distinguish a protocol vulnerable to replay from one that protects against it, and you will have highlighted the exact role of the challenge in the authentication mechanism.

---

## Principle of the replay attack

A replay attack consists of **capturing a legitimate communication between a client and a server, then resending it as-is** to the server at a later time, hoping the server will accept it as if it were a new authentic session.

This is the most direct validation test one can perform after capturing and documenting a protocol. If the replay works entirely, it means the protocol has no protection against replayability — which is a vulnerability in most contexts. If the replay fails at a specific point, it reveals the existence of an anti-replay mechanism (nonce, timestamp, sequence counter…) that must be understood and bypassed to write a functional client.

In our pedagogical context, the replay is primarily a **diagnostic tool**: it allows testing the hypotheses formulated in sections 23.1–23.3 under real conditions, without writing any code yet. We replay, observe the server's reaction, and adjust our understanding of the protocol.

---

## Preparing the replay material

### What we have available

At this stage, we have accumulated several exploitable sources:

- **`ch23_capture.pcap`** — the complete Wireshark capture of a successful client-server session.  
- **`ch23_stream.bin`** — the raw TCP stream exported via "Follow TCP Stream".  
- **`server_trace.log` / `client_trace.log`** — the `strace` traces with hexadecimal buffers of each `send`/`recv`.  
- **The protocol specification** — reconstructed in 23.2 and visually validated in 23.3.

For the replay, we need to extract the **client-sent messages only**, in order, as raw data ready to be resent to the server.

### Extracting client messages from Wireshark

In Wireshark, we isolate the client → server traffic:

```
tcp.port == 4444 && tcp.len > 0 && ip.src == 127.0.0.1 && tcp.srcport != 4444
```

This filter keeps only the packets sent *by the client* (source port different from 4444, since 4444 is the server port). In practice, on loopback, both IP addresses are `127.0.0.1`, so we filter by source or destination port.

A more reliable approach: use "Follow TCP Stream" and select **a single direction** from the dropdown menu at the bottom of the window. We choose the client → server direction (displayed in red by default), switch to **"Raw"**, and export the file:

```
ch23_client_only.bin
```

This file contains the concatenation of all messages sent by the client during the captured session, in order: HELLO, AUTH, CMD (PING, INFO, LIST, READ×4), QUIT.

### Extracting messages from `strace`

Alternatively, we can extract the messages from the client's `strace` traces with a targeted Python script:

```python
#!/usr/bin/env python3
"""
extract_client_messages.py  
Extracts messages sent by the client from an strace log.  
Produces one binary file per message + a concatenated file.  
"""

import re  
import sys  
import os  

def extract_buffers(trace_file):
    """Parse write/send calls and return raw buffers."""
    messages = []
    
    with open(trace_file) as f:
        for line in f:
            # Look for write(fd, "...", N) or send(fd, "...", N, flags)
            m = re.search(
                r'(?:write|send)\((\d+),\s*"((?:[^"\\]|\\.)*)"\s*,\s*(\d+)',
                line
            )
            if not m:
                continue
            
            fd = int(m.group(1))
            raw = m.group(2)
            length = int(m.group(3))
            
            # Ignore writes to stdout/stderr (fd 1, 2)
            if fd <= 2:
                continue
            
            # Convert \xHH sequences to bytes
            data = b""
            i = 0
            while i < len(raw):
                if raw[i] == '\\' and i + 1 < len(raw):
                    if raw[i+1] == 'x' and i + 3 < len(raw):
                        data += bytes.fromhex(raw[i+2:i+4])
                        i += 4
                    elif raw[i+1] == '0':
                        data += b'\x00'
                        i += 2
                    elif raw[i+1] == 'n':
                        data += b'\n'
                        i += 2
                    elif raw[i+1] == 't':
                        data += b'\t'
                        i += 2
                    elif raw[i+1] == '\\':
                        data += b'\\'
                        i += 2
                    else:
                        data += raw[i].encode()
                        i += 1
                else:
                    data += raw[i].encode()
                    i += 1
            
            messages.append(data)
    
    return messages

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <strace_log> [output_dir]")
        sys.exit(1)
    
    trace_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "replay_data"
    
    os.makedirs(output_dir, exist_ok=True)
    
    messages = extract_buffers(trace_file)
    
    print(f"[+] Extracted {len(messages)} messages from {trace_file}")
    
    # Save each message individually
    for i, msg in enumerate(messages):
        path = os.path.join(output_dir, f"msg_{i:02d}.bin")
        with open(path, 'wb') as f:
            f.write(msg)
        
        # Display a summary
        msg_type = msg[1] if len(msg) > 1 else 0
        print(f"    [{i:02d}] type=0x{msg_type:02X}  "
              f"len={len(msg)} bytes  → {path}")
    
    # Save the complete concatenation
    concat_path = os.path.join(output_dir, "all_client_messages.bin")
    with open(concat_path, 'wb') as f:
        for msg in messages:
            f.write(msg)
    
    print(f"\n[+] Concatenated stream: {concat_path}")

if __name__ == "__main__":
    main()
```

```bash
$ python3 extract_client_messages.py client_trace.log replay_data/
[+] Extracted 10 messages from client_trace.log
    [00] type=0x01  len=12 bytes  → replay_data/msg_00.bin
    [01] type=0x02  len=22 bytes  → replay_data/msg_01.bin
    [02] type=0x03  len=5  bytes  → replay_data/msg_02.bin
    [03] type=0x03  len=5  bytes  → replay_data/msg_03.bin
    [04] type=0x03  len=5  bytes  → replay_data/msg_04.bin
    [05] type=0x03  len=6  bytes  → replay_data/msg_05.bin
    [06] type=0x03  len=6  bytes  → replay_data/msg_06.bin
    [07] type=0x03  len=6  bytes  → replay_data/msg_07.bin
    [08] type=0x03  len=6  bytes  → replay_data/msg_08.bin
    [09] type=0x04  len=4  bytes  → replay_data/msg_09.bin

[+] Concatenated stream: replay_data/all_client_messages.bin
```

We now have each client message as an individual binary file, plus a concatenated file. The 10 messages correspond to the complete sequence: HELLO, AUTH, then 7 commands (PING, INFO, LIST, READ×4), and finally QUIT. This granularity is important: we will first attempt a full replay, then a message-by-message replay to isolate the point of failure.

---

## Naive replay — all at once

### With `ncat` (netcat)

The most brute-force approach consists of sending the complete client stream all at once with `ncat`:

```bash
# Launch the server in a terminal
$ ./build/server_O0

# In a second terminal, send the captured stream
$ ncat 127.0.0.1 4444 < replay_data/all_client_messages.bin | xxd | head -40
```

`ncat` opens a TCP connection, sends the file contents, and displays the server response in hexadecimal via `xxd`.

### Observing the server response

The typical result is the following:

```
00000000: c081 000f 5745 4c43 4f4d 4500 .... ....  ....WELCOME.....
00000010: c082 0002 0000                           ......
```

We observe:

1. **The HELLO (`0x81`) worked**: the server responded with `WELCOME` and a new challenge. This is expected — the HELLO does not depend on any dynamic data.  
2. **The AUTH (`0x82`) failed**: the status is `0x00` (FAIL) instead of `0x01` (OK). The server rejected the authentication.  
3. **No response to the commands**: the server did not process the CMD and QUIT messages because the session never reached the `AUTHENTICATED` state.

The naive replay failed. But the failure is informative.

### Understanding the failure

The authentication failed because the **challenge is different**. Let us recall the mechanism discovered in section 23.2:

1. The server generates a random 8-byte challenge for each new connection.  
2. The client XORs the password with this challenge before sending it.  
3. The server XORs the received password with *its* challenge to recover the cleartext password.

The captured AUTH message contains the password XOR'd with the **old** challenge (from the original session). When we replay it, the server XORs it with the **new** challenge (the one it just generated for this new connection). The result is not the correct password, so authentication fails.

This is exactly the role of the challenge/nonce: **preventing replay of the authentication**. Even if an attacker captures the entire traffic, they cannot replay the AUTH sequence because it is bound to an ephemeral challenge.

> 💡 **Key RE point**: this observation confirms that the 8-byte field in the HELLO response is not decorative — it is an active component of the authentication mechanism. Without the disassembly from section 23.2, one might have thought these bytes were a session identifier or padding. The replay proves their functional role.

---

## Selective replay — message by message

Since the full replay failed because of the challenge, we move to a finer approach: sending messages one by one with a Python script that **reads the server responses** between each send. This allows observing exactly when the session diverges.

### Interactive replay script

```python
#!/usr/bin/env python3
"""
replay_interactive.py  
Replays captured messages one by one, reading the server  
response between each send.  

Usage: python3 replay_interactive.py <host> <port> <message_dir>
"""

import socket  
import struct  
import sys  
import os  
import glob  

PROTO_MAGIC = 0xC0  
HEADER_SIZE = 4  

MSG_TYPE_NAMES = {
    0x01: "HELLO_REQ",   0x81: "HELLO_RESP",
    0x02: "AUTH_REQ",    0x82: "AUTH_RESP",
    0x03: "CMD_REQ",     0x83: "CMD_RESP",
    0x04: "QUIT_REQ",    0x84: "QUIT_RESP",
    0xFF: "ERROR",
}

def recv_message(sock):
    """Receive a complete protocol message."""
    header = b""
    while len(header) < HEADER_SIZE:
        chunk = sock.recv(HEADER_SIZE - len(header))
        if not chunk:
            return None, None, None
        header += chunk
    
    magic = header[0]
    msg_type = header[1]
    payload_len = struct.unpack(">H", header[2:4])[0]
    
    payload = b""
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            return msg_type, b"", payload_len
        payload += chunk
    
    return msg_type, payload, payload_len

def hexdump_line(data, max_bytes=32):
    """Compact display of a buffer in hex + ASCII."""
    hex_part = " ".join(f"{b:02X}" for b in data[:max_bytes])
    ascii_part = "".join(
        chr(b) if 32 <= b < 127 else "." for b in data[:max_bytes]
    )
    suffix = "..." if len(data) > max_bytes else ""
    return f"{hex_part}{suffix}  |{ascii_part}{suffix}|"

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <host> <port> <message_dir>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    msg_dir = sys.argv[3]
    
    # Load messages in order
    msg_files = sorted(glob.glob(os.path.join(msg_dir, "msg_*.bin")))
    if not msg_files:
        print(f"[!] No message files found in {msg_dir}/")
        sys.exit(1)
    
    messages = []
    for path in msg_files:
        with open(path, "rb") as f:
            messages.append(f.read())
    
    print(f"[+] Loaded {len(messages)} messages from {msg_dir}/")
    print(f"[*] Connecting to {host}:{port}...\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    
    for i, msg in enumerate(messages):
        msg_type = msg[1] if len(msg) > 1 else 0
        type_name = MSG_TYPE_NAMES.get(msg_type, f"UNKNOWN(0x{msg_type:02X})")
        
        print(f"{'='*60}")
        print(f"  Message {i}: {type_name} ({len(msg)} bytes)")
        print(f"{'='*60}")
        print(f"  TX → {hexdump_line(msg)}")
        
        # Send the captured message
        sock.sendall(msg)
        
        # Receive the response
        try:
            resp_type, resp_payload, resp_len = recv_message(sock)
            
            if resp_type is None:
                print(f"  RX ← [connection closed by server]")
                print(f"\n[!] Server closed connection after message {i}.")
                break
            
            resp_name = MSG_TYPE_NAMES.get(
                resp_type, f"UNKNOWN(0x{resp_type:02X})"
            )
            
            full_resp = bytes([PROTO_MAGIC, resp_type]) + \
                        struct.pack(">H", resp_len) + resp_payload
            
            print(f"  RX ← {resp_name} ({resp_len} bytes payload)")
            print(f"       {hexdump_line(full_resp)}")
            
            # Specific analysis depending on response type
            if resp_type == 0xFF:  # ERROR
                error_code = resp_payload[0] if resp_payload else 0
                error_msg = resp_payload[1:].decode("utf-8", errors="replace")
                print(f"  ⚠  ERROR code=0x{error_code:02X}: {error_msg}")
                print(f"\n[!] Server returned error. Stopping replay.")
                break
            
            if resp_type == 0x82:  # AUTH_RESP
                status = resp_payload[1] if len(resp_payload) > 1 else 0
                if status == 0x01:
                    print(f"  ✓  AUTH SUCCESS")
                else:
                    print(f"  ✗  AUTH FAILED (status=0x{status:02X})")
                    print(f"\n[!] Authentication failed — "
                          f"challenge mismatch expected.")
                    print(f"    The captured AUTH payload was XOR'd with")
                    print(f"    the original challenge, not the current one.")
                    # We continue anyway to observe what follows
            
            if resp_type == 0x81:  # HELLO_RESP
                if len(resp_payload) >= 15:
                    challenge = resp_payload[7:15]
                    print(f"  ℹ  New challenge: "
                          f"{challenge.hex().upper()}")
                    print(f"     (differs from captured session)")
        
        except socket.timeout:
            print(f"  RX ← [timeout — no response]")
        
        print()
    
    sock.close()
    print("[*] Replay complete.")

if __name__ == "__main__":
    main()
```

### Execution and output analysis

```bash
$ python3 replay_interactive.py 127.0.0.1 4444 replay_data/
[+] Loaded 8 messages from replay_data/
[*] Connecting to 127.0.0.1:4444...

============================================================
  Message 0: HELLO_REQ (12 bytes)
============================================================
  TX → C0 01 00 08 48 45 4C 4C 4F 00 00 00  |....HELLO...|
  RX ← HELLO_RESP (15 bytes payload)
       C0 81 00 0F 57 45 4C 43 4F 4D 45 00 B7 3A 9E 21 ...  |....WELCOME..:!...|
  ℹ  New challenge: B73A9E21F0884C17
     (differs from captured session)

============================================================
  Message 1: AUTH_REQ (26 bytes)
============================================================
  TX → C0 02 00 16 05 61 64 6D 69 6E 0B 72 ...  |.....admin.r...|
  RX ← AUTH_RESP (2 bytes payload)
       C0 82 00 02 00 00  |......|
  ✗  AUTH FAILED (status=0x00)

  [!] Authentication failed — challenge mismatch expected.
      The captured AUTH payload was XOR'd with
      the original challenge, not the current one.

============================================================
  Message 2: CMD_REQ (5 bytes)
============================================================
  TX → C0 03 00 01 01  |.....|
  RX ← ERROR (19 bytes payload)
       C0 FF 00 13 03 41 75 74 68 65 6E 74 69 ...  |.....Authenti...|
  ⚠  ERROR code=0x03: Authenticate first

[!] Server returned error. Stopping replay.
[*] Replay complete.
```

The output confirms point by point what we expected:

1. **Message 0 (HELLO)**: the replay works. The server accepts the HELLO and responds with a new challenge (`B73A9E21F0884C17`), different from the one in the captured session.

2. **Message 1 (AUTH)**: the replay fails. The password XOR'd with the old challenge does not produce the correct cleartext when the server XORs it with the new challenge. Status `0x00` = failure.

3. **Message 2 (CMD)**: the server rejects the command with the error `ERR_WRONG_STATE` (code `0x03`) and the text `"Authenticate first"`. The session remained stuck in the `HELLO_DONE` state, it never reached `AUTHENTICATED`.

---

## Adaptive replay — bypassing the challenge

The naive replay fails at the AUTH step because of the challenge. But we now know the exact mechanism (XOR of the password with the challenge, discovered in 23.2). We can therefore build an **adaptive replay** that:

1. Sends the captured HELLO as-is (it works).  
2. Reads the **new challenge** from the HELLO response.  
3. **Recomputes** the AUTH payload by XOR-ing the password with the new challenge.  
4. Sends the corrected AUTH.  
5. Continues with the captured commands as-is (they do not depend on the challenge).

### Recovering the password from the capture

We have the captured AUTH message and the challenge from the original session. We can therefore **reverse the XOR** to recover the cleartext password:

```python
# Data extracted from the original capture (section 23.1)
original_challenge = bytes.fromhex("A37B01F98C22D45E")  # from the captured HELLO_RESP

# Captured AUTH payload (after the 4-byte header)
auth_payload = bytes.fromhex(
    "05"                          # user_len = 5
    "61646D696E"                  # "admin"
    "0B"                          # pass_len = 11
    "D048628CFE11841ED00820"      # password XOR'd with challenge
)

# Extract the XOR'd password
user_len = auth_payload[0]  
pass_offset = 1 + user_len  
pass_len = auth_payload[pass_offset]  
pass_xored = bytearray(auth_payload[pass_offset + 1 : pass_offset + 1 + pass_len])  

# Reverse the XOR: password_clear = password_xored XOR original_challenge
password_clear = bytearray(pass_len)  
for i in range(pass_len):  
    password_clear[i] = pass_xored[i] ^ original_challenge[i % len(original_challenge)]

print(f"Username : {'admin'}")  
print(f"Password : {password_clear.decode('utf-8')}")  
```

```
Username : admin  
Password : s3cur3P@ss!  
```

We have recovered the cleartext password. This is critical information: it allows not only building an adaptive replay, but also writing a complete replacement client (section 23.5).

> 📝 **Note**: in a real-world scenario, recovering the cleartext password from a network capture is a major protocol vulnerability. XOR with a nonce is **not** a secure authentication mechanism — it protects against naive replay but not against an attacker who has captured the complete handshake (challenge + response). A robust protocol would use an HMAC or a hash-based challenge-response, where the server could not (and would not need to) recover the cleartext password.

### Adaptive replay script

```python
#!/usr/bin/env python3
"""
replay_adaptive.py  
Adaptive replay: recomputes the AUTH payload with the new challenge.  

Usage: python3 replay_adaptive.py <host> <port> <message_dir>
"""

import socket  
import struct  
import sys  
import os  
import glob  

PROTO_MAGIC    = 0xC0  
HEADER_SIZE    = 4  
CHALLENGE_LEN  = 8  

def recv_message(sock):
    """Receive a complete protocol message."""
    header = b""
    while len(header) < HEADER_SIZE:
        chunk = sock.recv(HEADER_SIZE - len(header))
        if not chunk:
            return None, None
        header += chunk
    
    msg_type = header[1]
    payload_len = struct.unpack(">H", header[2:4])[0]
    
    payload = b""
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            break
        payload += chunk
    
    return msg_type, payload

def send_message(sock, msg_type, payload):
    """Send a protocol message."""
    header = struct.pack(">BBH", PROTO_MAGIC, msg_type, len(payload))
    sock.sendall(header + payload)

def xor_bytes(data, key):
    """Cyclic XOR of data with key."""
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def rebuild_auth(original_auth_payload, original_challenge, new_challenge):
    """
    Recompute the AUTH payload for a new challenge.
    
    1. Extract the password XOR'd with the old challenge.
    2. Reverse the XOR to obtain the cleartext password.
    3. Re-apply the XOR with the new challenge.
    4. Reconstruct the complete payload.
    """
    user_len = original_auth_payload[0]
    username = original_auth_payload[1 : 1 + user_len]
    
    pass_offset = 1 + user_len
    pass_len = original_auth_payload[pass_offset]
    pass_xored_old = original_auth_payload[
        pass_offset + 1 : pass_offset + 1 + pass_len
    ]
    
    # Key step: old_xor XOR old_challenge = cleartext
    #           cleartext XOR new_challenge = new_xor
    # Shortcut: new_xor = old_xor XOR old_challenge XOR new_challenge
    password_clear = xor_bytes(pass_xored_old, original_challenge)
    pass_xored_new = xor_bytes(password_clear, new_challenge)
    
    # Reconstruct the payload
    new_payload = (
        bytes([user_len]) +
        username +
        bytes([pass_len]) +
        pass_xored_new
    )
    
    return new_payload, password_clear.decode("utf-8", errors="replace")

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <host> <port> <message_dir>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    msg_dir = sys.argv[3]
    
    # Load captured messages
    msg_files = sorted(glob.glob(os.path.join(msg_dir, "msg_*.bin")))
    messages = []
    for path in msg_files:
        with open(path, "rb") as f:
            messages.append(f.read())
    
    print(f"[+] Loaded {len(messages)} captured messages")
    
    # ── Phase 1: extract the original challenge from the data ──
    # We need the original challenge to reverse the XOR.
    # In practice, we would also need to have captured the server's
    # HELLO response. Here, we pass it as an argument or read it
    # from a file.
    #
    # Alternative: if we have the complete pcap, we can extract the
    # challenge from the original HELLO_RESP with a script or from
    # Wireshark.
    
    original_challenge_hex = input(
        "[?] Enter original challenge (hex, from captured HELLO_RESP): "
    ).strip()
    original_challenge = bytes.fromhex(original_challenge_hex)
    assert len(original_challenge) == CHALLENGE_LEN
    
    # ── Phase 2: connection and adaptive replay ──
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    print(f"[+] Connected to {host}:{port}\n")
    
    new_challenge = None
    
    for i, msg in enumerate(messages):
        msg_type = msg[1]
        payload = msg[HEADER_SIZE:]  # everything after the 4-byte header
        
        # ── Adapt the AUTH message ──
        if msg_type == 0x02 and new_challenge is not None:
            print(f"[*] Message {i}: AUTH_REQ — adapting to new challenge...")
            
            new_payload, password = rebuild_auth(
                payload, original_challenge, new_challenge
            )
            print(f"    Recovered password: '{password}'")
            print(f"    Old XOR: {payload[1+payload[0]+1:][:8].hex().upper()}")
            print(f"    New XOR: {new_payload[1+new_payload[0]+1:][:8].hex().upper()}")
            
            send_message(sock, msg_type, new_payload)
        else:
            # Send as-is
            print(f"[*] Message {i}: type=0x{msg_type:02X} — "
                  f"replaying as-is ({len(msg)} bytes)")
            sock.sendall(msg)
        
        # ── Receive the response ──
        try:
            resp_type, resp_payload = recv_message(sock)
            
            if resp_type is None:
                print(f"    ← [connection closed]\n")
                break
            
            print(f"    ← Response: type=0x{resp_type:02X} "
                  f"({len(resp_payload)} bytes)")
            
            # Extract the challenge from the HELLO_RESP
            if resp_type == 0x81 and len(resp_payload) >= 15:
                new_challenge = resp_payload[7:15]
                print(f"    ℹ  New challenge: {new_challenge.hex().upper()}")
            
            # Check the AUTH result
            if resp_type == 0x82 and len(resp_payload) >= 2:
                if resp_payload[1] == 0x01:
                    print(f"    ✓  AUTH SUCCESS — adaptive replay succeeded!")
                else:
                    print(f"    ✗  AUTH FAILED")
            
            # Display CMD_RESP data
            if resp_type == 0x83 and len(resp_payload) > 1:
                if resp_payload[0] == 0x01:
                    text = resp_payload[1:].decode("utf-8", errors="replace")
                    preview = text[:60].replace("\n", " ↵ ")
                    print(f"    ✓  CMD OK: {preview}...")
            
            # Server error
            if resp_type == 0xFF:
                err = resp_payload[1:].decode("utf-8", errors="replace")
                print(f"    ⚠  ERROR: {err}")
                break
        
        except socket.timeout:
            print(f"    ← [timeout]")
        
        print()
    
    sock.close()
    print("[+] Adaptive replay complete.")

if __name__ == "__main__":
    main()
```

### Executing the adaptive replay

```
$ python3 replay_adaptive.py 127.0.0.1 4444 replay_data/
[+] Loaded 8 captured messages
[?] Enter original challenge (hex, from captured HELLO_RESP): A37B01F98C22D45E
[+] Connected to 127.0.0.1:4444

[*] Message 0: type=0x01 — replaying as-is (12 bytes)
    ← Response: type=0x81 (15 bytes)
    ℹ  New challenge: B73A9E21F0884C17

[*] Message 1: AUTH_REQ — adapting to new challenge...
    Recovered password: 's3cur3P@ss!'
    Old XOR: D048628CFE11841E
    New XOR: C409FD5482BB1C57
    ← Response: type=0x82 (2 bytes)
    ✓  AUTH SUCCESS — adaptive replay succeeded!

[*] Message 2: type=0x03 — replaying as-is (5 bytes)
    ← Response: type=0x83 (5 bytes)
    ✓  CMD OK: PONG...

[*] Message 3: type=0x03 — replaying as-is (5 bytes)
    ← Response: type=0x83 (68 bytes)
    ✓  CMD OK: ch23-network server v1.0 ↵ Protocol: custom binary ↵ ...

[*] Message 4: type=0x03 — replaying as-is (5 bytes)
    ← Response: type=0x83 (52 bytes)
    ✓  CMD OK: ...

[*] Message 5: type=0x03 — replaying as-is (6 bytes)
    ← Response: type=0x83 (56 bytes)
    ✓  CMD OK: Welcome to the secret server. ↵ Access level: CLA...

[*] Message 6: type=0x03 — replaying as-is (6 bytes)
    ← Response: type=0x83 (41 bytes)
    ✓  CMD OK: FLAG{pr0t0c0l_r3v3rs3d_succ3ssfully} ↵ ...

[*] Message 7: type=0x04 — replaying as-is (4 bytes)
    ← Response: type=0x84 (3 bytes)

[+] Adaptive replay complete.
```

The adaptive replay works entirely. By adjusting only the AUTH message (recomputing the XOR with the new challenge), the entire session proceeds normally. The CMD and QUIT commands do not depend on the challenge and are replayable as-is.

---

## What the replay teaches us

### Protocol protection summary

| Property | Protected? | Mechanism | Bypassable? |  
|----------|-----------|-----------|-------------|  
| Full session replay | Yes | Random challenge per session | Yes, if the complete handshake is captured |  
| Password confidentiality | Partial | XOR with the challenge | Yes — XOR is reversible with the challenge |  
| Post-AUTH command replay | No | None (no per-message nonce) | Directly replayable |  
| Message integrity | No | No checksum/HMAC | Modifiable without detection |

### Identified vulnerabilities

1. **XOR is not a secure authentication mechanism.** An attacker who captures the handshake (challenge in cleartext) and the AUTH response (XOR'd password) can recover the cleartext password by simple XOR reversal. An HMAC-SHA256 with the challenge as salt would be resistant to this attack.

2. **No protection against command replay.** Once the session is established, each CMD message can be replayed in another authenticated session. There is no sequence number, timestamp, or per-message MAC.

3. **No channel encryption.** All traffic is in cleartext (except for the XOR on the password). A network observer sees the commands, responses, and exchanged data.

These observations are typical of a proprietary protocol not designed by a cryptographer — exactly the type of target encountered when reverse engineering industrial, embedded, or legacy software.

---

## Replay with other tools

### With `pwntools`

For readers already familiar with `pwntools` (chapter 11, section 11.9), the replay is more concise:

```python
from pwn import *

r = remote("127.0.0.1", 4444)

# Send the captured HELLO
r.send(open("replay_data/msg_00.bin", "rb").read())

# Read the HELLO response
resp = r.recv(1024)  
new_challenge = resp[4+7 : 4+7+8]  
log.info(f"New challenge: {new_challenge.hex()}")  

# ... adapt and send AUTH, then the commands

r.close()
```

### With `socat`

For a raw replay without a script, `socat` allows connecting a file directly to a TCP socket with a slight delay between writes:

```bash
$ socat -d TCP:127.0.0.1:4444 FILE:replay_data/all_client_messages.bin
```

Like `ncat`, this does not allow reading responses interactively or adapting messages. It is useful only for a quick naive replay.

---

## Section summary

| Step | Result | What we learn |  
|------|--------|---------------|  
| Client message extraction | Files `msg_00.bin` to `msg_07.bin` | Data ready for replay |  
| Naive replay (all at once) | HELLO OK, AUTH FAIL | The challenge prevents authentication replay |  
| Interactive replay (message by message) | Precise failure identified at AUTH message | Confirmation of the challenge's role |  
| XOR reversal | Cleartext password recovered | XOR is reversible — protocol vulnerability |  
| Adaptive replay | Complete session succeeded | Full validation of the protocol specification |

The adaptive replay is the ultimate proof that our understanding of the protocol is correct. Every field, every mechanism, every state transition has been verified under real conditions. We are now ready for the last step of the chapter: writing a **standalone replacement client** in Python with `pwntools`, which does not replay a capture but **generates its own messages** from the specification (section 23.5).

⏭️ [Writing a complete replacement client with `pwntools`](/23-network/05-client-pwntools.md)
