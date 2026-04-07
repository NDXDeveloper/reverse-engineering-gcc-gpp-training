🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 23

## Write a Python Client Capable of Authenticating to the Server Without Knowing the Source Code

> **Context**: you are provided only the binaries `server_O2_strip` and `client_O2_strip` (optimized `-O2`, stripped, without symbols). You have no access to the sources, nor to the `-O0 -g` variants, nor to the previous sections of the chapter. The server listens on TCP port 4444. Somewhere on the server, a file contains a flag in the format `FLAG{...}`.

---

## Objective

Produce a standalone Python script (`checkpoint_client.py`) capable of:

1. Connecting to the server.  
2. Completing the initial handshake.  
3. Authenticating with valid credentials.  
4. Listing the files available on the server.  
5. Reading and displaying the content of each file.  
6. Extracting the flag.  
7. Disconnecting cleanly.

The script must work reproducibly: running it ten times in a row must produce ten successful sessions with flag extraction each time.

---

## Expected deliverables

### 1. Triage report (free-form text, ~1 page)

A short document summarizing the results of your initial observation phase:

- Results of `file`, `strings`, `checksec` on both binaries.  
- Annotated `strace` capture showing the exchange sequence.  
- Wireshark capture (`.pcap` file) of a complete session between the original client and server.  
- Your initial hypotheses about the protocol format: magic byte, header fields, observed message types, exchange sequence.

### 2. Protocol specification

A structured document describing the protocol as you reconstructed it:

- Header format (size of each field, endianness, role).  
- List of message types with their numeric values and direction (client → server or server → client).  
- Payload format for each message type.  
- State machine: which messages are accepted in which state, and what transitions each message triggers.  
- Authentication mechanism: how the password is protected, what role the handshake challenge plays.

### 3. ImHex pattern (`checkpoint_protocol.hexpat`)

A `.hexpat` file that, applied to a raw "Follow TCP Stream" export of a captured session, decodes and colorizes each protocol message: headers, types, lengths, typed payloads (HELLO, AUTH, CMD, QUIT and their responses).

### 4. Python client (`checkpoint_client.py`)

The final Python script. Validation criteria:

- Uses `pwntools` (or standard Python sockets — your choice).  
- Implements the protocol from scratch (no replay of captured data).  
- Handles the challenge: reads the handshake nonce and uses it correctly in authentication.  
- Works against `server_O2_strip` without any modification to the server binary.  
- Displays the flag in the output.

---

## Success criteria

| Criterion | Required | Bonus |  
|---------|--------|-------|  
| The client connects and completes the handshake | ✅ | — |  
| The client authenticates successfully | ✅ | — |  
| The client executes at least one command (LIST or READ) | ✅ | — |  
| The client extracts and displays the flag | ✅ | — |  
| The client disconnects cleanly (QUIT + BYE response) | ✅ | — |  
| The script works 10 times in a row without failure | ✅ | — |  
| The `.hexpat` correctly decodes a complete capture | ✅ | — |  
| The triage report documents the methodology | ✅ | — |  
| The protocol specification is complete and accurate | ✅ | — |  
| The client works with each of the 3 user accounts | — | ⭐ |  
| The client properly detects and displays server errors | — | ⭐ |  
| The client accepts host/port/credentials as CLI arguments | — | ⭐ |  
| The `.hexpat` colorizes requests and responses differently | — | ⭐ |

---

## Constraints

- **No access to sources.** The work must start from the stripped and optimized binaries only. The `-O0 -g` variants are only allowed to verify your conclusions *after* having reconstructed the protocol from the stripped variants.  
- **No patching the server.** The `server_O2_strip` binary must be run as-is, without modification.  
- **No copy-pasting from the chapter sections.** The goal is to reproduce the approach independently. Sections 23.1 to 23.5 describe the methodology — the checkpoint asks you to apply it yourself.

---

## Progressive hints

The hints below should be consulted **only if you are stuck**. Each level reveals a bit more information. Try to go as far as possible before consulting them.

<details>
<summary><strong>Hint 1 — Where to start</strong></summary>

Run `server_O2_strip` in one terminal, then `client_O2_strip 127.0.0.1` in a second terminal, with `strace -e trace=network,read,write -x -s 512` on both. Look for a recurring byte at the beginning of each exchange — this is the magic byte.

</details>

<details>
<summary><strong>Hint 2 — Header structure</strong></summary>

The header is 4 bytes. The first is constant (magic), the second varies (message type), the last two form a 16-bit big-endian integer (length of the following payload).

</details>

<details>
<summary><strong>Hint 3 — Requests vs responses</strong></summary>

Compare the types of messages sent by the client (`0x01`, `0x02`, `0x03`, `0x04`) with those sent by the server (`0x81`, `0x82`, `0x83`, `0x84`). Which bit distinguishes them?

</details>

<details>
<summary><strong>Hint 4 — The handshake</strong></summary>

The client sends a fixed 5-character ASCII string that is recognizable (visible with `strings` on the capture). The server responds with a 7-character ASCII string followed by 8 bytes that change with each connection.

</details>

<details>
<summary><strong>Hint 5 — Authentication</strong></summary>

The authentication payload uses length-prefixed strings (1 length byte + N data bytes). There are two: the username and the password. The username is in cleartext. The password is not — compare it between two sessions to see what changes.

</details>

<details>
<summary><strong>Hint 6 — Password protection</strong></summary>

The password is transformed by a reversible operation with the 8 variable bytes from the handshake. Look in Ghidra for a loop that iterates over the password and combines it with these bytes. The operation is a cyclic XOR.

</details>

<details>
<summary><strong>Hint 7 — Finding credentials</strong></summary>

Run `strings` on the server binary and look for strings that resemble identifiers or passwords. There are several pairs. Alternatively, set a breakpoint on `memcmp` in GDB and observe the arguments during an authentication attempt.

</details>

---

## Verification

To verify that your client works, launch the server and your script:

```bash
# Terminal 1
$ ./build/server_O2_strip

# Terminal 2
$ python3 checkpoint_client.py 127.0.0.1 -p 4444
```

The expected output must contain at minimum:

- A successful handshake confirmation.  
- A successful authentication confirmation.  
- The contents of the server's files.  
- A line containing `FLAG{...}`.  
- A clean disconnection.

For thorough verification, capture the Wireshark session of your Python client and compare it with a session from the original C client. The headers must be structurally identical (same magic, same types, same lengths). Only the challenge-dependent payloads (AUTH) will differ from one session to another.

---

## Skills validated by this checkpoint

This checkpoint mobilizes and validates the following skills, acquired throughout the chapter:

| Section | Skill |  
|---------|------------|  
| 23.1 | Binary triage, network capture with `strace` and Wireshark, hypothesis formulation about an unknown protocol |  
| 23.2 | Targeted disassembly in Ghidra, packet parser reconstruction, state machine and authentication mechanism identification |  
| 23.3 | Writing a `.hexpat` pattern to decode and visualize protocol frames in ImHex |  
| 23.4 | Understanding replay attacks, identifying anti-replay protections, extracting credentials from a capture |  
| 23.5 | Implementing a standalone network client in Python with `pwntools`, structured in transport / operations / scenarios layers |

⏭️ [Chapter 24 — Reversing an Encrypted Binary](/24-crypto/README.md)
