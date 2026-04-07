🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 23.2 — RE of the Packet Parser (state machine, fields, magic bytes)

> 🎯 **Objective of this section**: open the server binary in Ghidra and fully reconstruct the packet parser — the function that reads incoming bytes, validates the magic byte, extracts the type and length, then dispatches to each command's handler. By the end of this section, you will have a precise understanding of the format of each message type and the protocol's state machine.

---

## Analysis Strategy

In section 23.1, we formulated hypotheses about the protocol by observing the traffic. We now enter the disassembler with a clear objective: **locate the packet parser and confirm (or correct) each hypothesis**.

The approach is top-down in three phases:

1. **Find the network entry point** — locate the calls to `recv()`/`read()` in the server binary.  
2. **Trace back to the parser** — identify the function that processes the received data, by following the buffer from `recv()` to the decision logic.  
3. **Reconstruct the state machine** — understand the sequence of protocol states (handshake → authentication → commands → disconnection) and the exact format of each message.

We work on the server binary rather than the client, because the server is the one that **validates** the protocol. The client constructs the messages, but the server verifies them — and it is in the verification that we find the exact format rules.

---

## Step 1 — Locating Network Functions in Ghidra

### Import and automatic analysis

We import the `server` binary (`-O0 -g` variant to start) into Ghidra and run the automatic analysis with default options. If the binary is not stripped, the Symbol Tree immediately populates with function names.

### Searching for network calls via imports

In the Symbol Tree, we open the **Imports** category (or **External Functions**) and look for libc functions related to sockets:

- `socket`  
- `bind`  
- `listen`  
- `accept`  
- `recv` / `read`  
- `send` / `write`  
- `close`

Each of these functions appears as an external symbol resolved via the PLT. By double-clicking on `recv` (or `read`), Ghidra displays the PLT thunk. The point of interest is not the thunk itself, but its **cross-references** (XREF).

### Tracing back via cross-references

We right-click on `recv` → **References → Find references to** (or shortcut `Ctrl+Shift+F` in Ghidra). The XREF list shows all functions that call `recv`. In a simple server, we typically find two or three:

- A call in the **main receive loop** — this is the one we're interested in.  
- Possibly a call in a utility function like `recv_all` or `recv_exact` that loops until `n` bytes have been received.  
- Sometimes a call in the initial handshake, separate from the main loop.

We navigate to each XREF and identify the one located within a loop — this is the protocol processing loop.

### Alternative: searching by strings

If the binary is stripped and we don't have import function names directly visible, we use the strings identified in section 23.1. For example, if `strings` had revealed `"Bad magic"` or `"Invalid command"`, we search for that string in Ghidra (**Search → For Strings** or **Defined Strings** in the window), then trace back to the functions that reference it. An error message `"Bad magic byte"` will necessarily be close to the code that checks the magic byte — this is a very effective shortcut to the parser.

---

## Step 2 — Anatomy of the Packet Parser

Once the parsing function is located, we decompile it in Ghidra. The raw pseudo-code is often verbose and uses generic variable names (`iVar1`, `local_28`, `param_1`…). The work consists of making it readable by progressively renaming and retyping.

### Typical structure of a network parser

Before diving into the specific code, here is the skeleton found in the vast majority of binary TCP protocol parsers:

```
┌─────────────────────────────────────────────┐
│  1. Read N bytes (fixed header)             │
│     → recv(fd, header_buf, HEADER_SIZE, 0)  │
├─────────────────────────────────────────────┤
│  2. Validate the magic byte                 │
│     → if (header_buf[0] != MAGIC) → error   │
├─────────────────────────────────────────────┤
│  3. Extract the command type                │
│     → cmd_type = header_buf[1]              │
├─────────────────────────────────────────────┤
│  4. Extract the payload length              │
│     → payload_len = (header_buf[2] << 8)    │
│                    | header_buf[3]          │
├─────────────────────────────────────────────┤
│  5. Read the payload                        │
│     → recv(fd, payload_buf, payload_len, 0) │
├─────────────────────────────────────────────┤
│  6. Dispatch based on type                  │
│     → switch(cmd_type) {                    │
│         case 0x01: handle_hello(...)        │
│         case 0x02: handle_auth(...)         │
│         case 0x03: handle_cmd(...)          │
│         case 0x04: handle_quit(...)         │
│       }                                     │
└─────────────────────────────────────────────┘
```

This is the skeleton we will find — in a more or less direct form depending on the optimization level — in the disassembly.

### Identifying the magic byte in the disassembly

The magic byte verification is generally the first conditional test after reading the header. In x86-64 assembly, it looks like this:

```asm
; Read the first byte of the buffer into a register
movzx  eax, BYTE PTR [rbp-0x28]      ; header_buf[0]  
cmp    al, 0xC0                        ; compare with the magic byte  
jne    .bad_magic                      ; if different → error  
```

In the Ghidra decompiler, this gives something like:

```c
if (header_buf[0] != 0xc0) {
    puts("Bad magic byte");
    return -1;
}
```

We confirm the hypothesis from section 23.1: the magic byte is indeed `0xC0`. We rename the constant in Ghidra by creating a `#define` or an `enum`:

```
Right-click on 0xc0 → Set Equate → "PROTO_MAGIC"
```

> 💡 **Ghidra tip**: equates allow you to replace numeric constants with symbolic names throughout the listing. This is a considerable readability improvement when the same magic byte appears in multiple places (sending and receiving).

### Extracting the type field

Right after the magic byte validation, the parser extracts the command type. At `-O0`, it's straightforward:

```c
cmd_type = header_buf[1];
```

We verify that the values match our observations: `0x01`, `0x02`, `0x03`, `0x04` for client requests. The dispatch is typically done via a `switch` or a cascade of `if/else if`.

In the Ghidra decompiler at `-O0`, a `switch` appears clearly:

```c
switch (cmd_type) {  
case 1:  
    handle_hello(client_fd, payload_buf, payload_len);
    break;
case 2:
    handle_auth(client_fd, payload_buf, payload_len);
    break;
case 3:
    handle_command(client_fd, payload_buf, payload_len);
    break;
case 4:
    handle_quit(client_fd);
    break;
default:
    send_error(client_fd, 0xff);
    break;
}
```

The names `handle_hello`, `handle_auth`, etc. will only be visible if the binary has its symbols. On a stripped binary, Ghidra will display `FUN_00401a30`, `FUN_00401b80`, etc. — we will rename them manually as the analysis progresses.

> 📝 **Renaming convention**: adopt a consistent prefix from the start. For example `proto_handle_hello`, `proto_handle_auth`, `proto_parse_header`, `proto_send_response`. This makes the Function Call Graph much more readable.

### Extracting the length field

The length field is two bytes. The way it is read reveals the **endianness** of the protocol. Two common assembly patterns:

**Big-endian (network byte order)** — the most common in network protocols:

```c
payload_len = (header_buf[2] << 8) | header_buf[3];
```

In assembly, we recognize the `shl` by 8 bits followed by an `or`:

```asm
movzx  eax, BYTE PTR [rbp-0x26]      ; header_buf[2]  
shl    eax, 8  
movzx  edx, BYTE PTR [rbp-0x25]      ; header_buf[3]  
or     eax, edx  
```

**With `ntohs()`** — if the author used the standard macro:

```c
payload_len = ntohs(*(uint16_t *)(header_buf + 2));
```

In assembly, `ntohs` translates to a `bswap` instruction (on 32 bits followed by a shift) or `ror`/`xchg` on the two bytes. Ghidra often recognizes this pattern and displays `ntohs()` or `__bswap_16()` directly in the decompiler.

**Little-endian** — rarer in network protocols, but possible:

```c
payload_len = *(uint16_t *)(header_buf + 2);  // direct read, x86 native LE
```

We verify with our captures: if the HELLO packet contained `\x00\x08` at bytes 2–3 and the payload was 8 bytes, then it is indeed big-endian (`0x0008` = 8). In little-endian, `\x00\x08` would be read as `0x0800` = 2048, which would be inconsistent with the observed sizes.

---

## Step 3 — Reconstructing Each Handler

With the dispatch identified, we descend into each handler to reconstruct the exact payload format of each message type.

### HELLO Handler (`0x01` / `0x81`)

The handshake handler is generally simple. On the server side, it:

1. Optionally verifies the payload content (the string `"HELLO"` or a protocol version identifier).  
2. Generates a response containing a welcome message and, potentially, a **challenge** (random nonce).

In the decompiler, we look for:

- A call to `memcmp()` or `strcmp()` comparing the payload with a fixed string.  
- A call to `rand()`, `random()`, `/dev/urandom` or `getrandom()` to generate the challenge.  
- The construction of the response packet: header with magic `0xC0`, type `0x81`, length, then payload.

```c
// Reconstructed pseudo-code (after renaming)
void proto_handle_hello(int client_fd, uint8_t *payload, uint16_t len) {
    if (memcmp(payload, "HELLO", 5) != 0) {
        proto_send_error(client_fd, ERR_BAD_HELLO);
        return;
    }
    
    uint8_t challenge[8];
    getrandom(challenge, 8, 0);               // generate an 8-byte nonce
    memcpy(session->challenge, challenge, 8);  // store for future verification
    
    uint8_t response[4 + 7 + 8];              // header + "WELCOME" + challenge
    response[0] = PROTO_MAGIC;                 // 0xC0
    response[1] = MSG_HELLO_RESP;              // 0x81
    response[2] = 0x00;                        // length high byte
    response[3] = 0x0F;                        // length low byte (15)
    memcpy(response + 4, "WELCOME", 7);
    memcpy(response + 11, challenge, 8);
    
    send(client_fd, response, sizeof(response), 0);
    session->state = STATE_HELLO_DONE;
}
```

Several crucial pieces of information emerge:

- The challenge is indeed **random** (call to `getrandom`), which confirms it changes with each session.  
- The session has a **state** (`session->state`), updated after each successful step. This is the core of the state machine.  
- The response payload format is: 7 bytes of text `"WELCOME"` + 8 bytes of challenge, for a total of 15 (`0x0F`) bytes.

### AUTH Handler (`0x02` / `0x82`)

The authentication handler is the richest in logic. We look for:

- How the **username** and **password** are extracted from the payload.  
- Whether the handshake challenge is used (hash of the password with the nonce?).  
- How the success/failure response is constructed.

The extraction format for length-prefixed strings is recognized in the disassembly by a recurring pattern:

```asm
; Extract the username length
movzx  eax, BYTE PTR [rdi]           ; first byte = username length  
movzx  ecx, al                        ; ecx = username_len  
lea    rsi, [rdi+1]                   ; rsi points to the start of the username  

; Advance in the buffer
add    rdi, rcx                       ; skip the username  
inc    rdi                            ; skip the next length byte  

; Extract the password length
movzx  eax, BYTE PTR [rdi]           ; password length
```

As reconstructed pseudo-code:

```c
void proto_handle_auth(int client_fd, uint8_t *payload, uint16_t len) {
    // Check the session state
    if (session->state != STATE_HELLO_DONE) {
        proto_send_error(client_fd, ERR_WRONG_STATE);
        return;
    }
    
    // Extract username (length-prefixed)
    uint8_t user_len = payload[0];
    char *username = (char *)(payload + 1);
    
    // Extract password (length-prefixed)
    uint8_t pass_len = payload[1 + user_len];
    
    // Copy the password and de-XOR it with the challenge
    uint8_t password[256];
    memcpy(password, payload + 2 + user_len, pass_len);
    xor_with_challenge(password, pass_len, session->challenge);
    
    // Verify the credentials
    uint8_t status;
    if (check_credentials(username, user_len, password, pass_len)) {
        status = AUTH_OK;                 // 0x01
        session->state = STATE_AUTHENTICATED;
    } else {
        status = AUTH_FAIL;               // 0x00
    }
    
    // Build and send the response
    uint8_t response[6] = { PROTO_MAGIC, MSG_AUTH_RESP, 0x00, 0x02, 
                            0x00, status };
    send(client_fd, response, 6, 0);
}
```

The AUTH payload format is now clear:

```
[user_len: 1 byte][username: user_len bytes][pass_len: 1 byte][password: pass_len bytes]
```

We also note that the AUTH response is 6 bytes: 4 header + 2 payload (an unknown byte `0x00` and a status byte `0x01` for success). The unknown byte could be a detailed error code, a remaining attempts counter, or padding — we will need to test with incorrect credentials to observe whether these values change.

> 💡 **Method**: for each field whose role is unclear, we vary the inputs and observe the output. It is the combination of static analysis + dynamic analysis that yields the most reliable answers.

### The `xor_with_challenge` function — discovering the password protection

The pseudo-code above contains a call to `xor_with_challenge` before the credential comparison. In the disassembly, this function is easily spotted: it is a **small loop** that iterates over each byte of the password and combines it with the challenge.

In x86-64 assembly, the typical pattern of a cyclic XOR looks like this:

```asm
; xor_with_challenge(password, pass_len, challenge)
; rdi = password, rsi = pass_len, rdx = challenge
    xor    ecx, ecx                    ; i = 0
.loop:
    cmp    rcx, rsi                    ; i < pass_len ?
    jge    .done
    mov    rax, rcx
    xor    edx, edx
    div    r8                          ; i % CHALLENGE_LEN (or AND 0x7 if len=8)
    movzx  eax, BYTE PTR [rdx+rax]    ; challenge[i % 8]
    xor    BYTE PTR [rdi+rcx], al      ; password[i] ^= challenge[i % 8]
    inc    rcx
    jmp    .loop
.done:
```

> 💡 **Recognizable pattern**: a loop with a byte-by-byte `xor` and a modulo (or an `and` with a power of 2 minus 1) on the index is the classic sign of a cyclic XOR with a key. If the key size is a power of 2 (here 8 = 2^3), GCC optimizes the `div` into `and reg, 0x7`, which is even more characteristic.

In the Ghidra decompiler, the loop appears in a more readable form:

```c
void xor_with_challenge(uint8_t *data, size_t len, uint8_t *challenge) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= challenge[i % 8];
    }
}
```

This is the central mechanism for password protection:

1. During the handshake, the server generates a **random challenge** of 8 bytes.  
2. The client **XORs the password** with this challenge before sending it.  
3. The server **applies the same XOR** to recover the plaintext password, then compares it with the internal database.

This mechanism prevents naive replay of the authentication (since the challenge changes with each session), but it is **cryptographically weak**: an attacker who captures the complete handshake (plaintext challenge + XOR-ed password) can recover the password by simple reverse XOR. We will exploit this weakness in section 23.4.

### The `check_credentials` function — plaintext comparison

After the XOR decoding, the password is in plaintext in memory. The credential verification is then a simple comparison:

```c
int check_credentials(char *user, uint8_t ulen, char *pass, uint8_t plen) {
    for (int i = 0; user_db[i].username != NULL; i++) {
        if (ulen == strlen(user_db[i].username) &&
            memcmp(user, user_db[i].username, ulen) == 0 &&
            plen == strlen(user_db[i].password) &&
            memcmp(pass, user_db[i].password, plen) == 0)
        {
            return 1;
        }
    }
    return 0;
}
```

The `for` loop with a structure array terminated by a NULL pointer is a classic GCC pattern for static data tables. The calls to `memcmp` and `strlen` are easily identifiable in the disassembly (they are functions imported from libc, visible in the XREFs).

> 💡 **Credential extraction**: by setting a GDB breakpoint on `memcmp` during an authentication attempt, we can observe the arguments of each comparison and thus read the usernames and passwords stored in plaintext in the binary. Alternatively, `strings` on the binary may reveal adjacent strings that look like credentials — the passwords are stored in plaintext in the `.rodata` section.

### COMMAND Handler (`0x03` / `0x83`) and QUIT Handler (`0x04` / `0x84`)

We apply the same method for each remaining handler. The COMMAND handler is often the one containing the business logic (file reading, action execution, data queries). The QUIT handler is generally trivial (clean up the session, send an acknowledgment, close the socket).

For each handler, we document:

- The **exact payload format** (field by field, with sizes and encoding).  
- The **validation conditions** (length checks, allowed value checks).  
- The **corresponding response format**.  
- The **state transitions** of the state machine.

---

## Step 4 — Reconstructing the State Machine

### Identifying the state variable

Most protocol servers maintain a **session state** that determines which commands are accepted at any given time. You cannot send a command without having authenticated, nor authenticate without having completed the handshake.

In the disassembly, this state manifests as:

- A **session structure** allocated for each connection (on the stack or on the heap via `malloc`).  
- An **integer field** in this structure, compared at the beginning of each handler.  
- **Checks of the form** `if (session->state != EXPECTED_STATE) → error`.

By going through the handlers, we can reconstruct all the states and transitions:

```
               ┌──────────────┐
               │  CONNECTED   │  (initial state after accept)
               └──────┬───────┘
                      │ recv HELLO (0x01)
                      ▼
               ┌──────────────┐
               │ HELLO_DONE   │  (handshake completed)
               └──────┬───────┘
                      │ recv AUTH (0x02) + valid credentials
                      ▼
               ┌──────────────┐
          ┌───▶│AUTHENTICATED │◀───┐  (ready for commands)
          │    └──────┬───────┘    │
          │           │            │
          │    recv CMD (0x03)     │
          │           │            │
          │           ▼            │
          │    processing +        │
          │    send response ──────┘
          │
          │    recv QUIT (0x04)
          │           │
          │           ▼
          │    ┌──────────────┐
          │    │ DISCONNECTED │  (session terminated)
          │    └──────────────┘
          │
          │    AUTH failed → remains in HELLO_DONE
          │    (possibility to retry)
          └────────────────────────────────────
```

### Verifying with GDB

To confirm the state machine, we can set a **watchpoint** on the session's state field in GDB:

```bash
$ gdb ./server
(gdb) break accept
(gdb) run
# ... accept returns with fd = 4
(gdb) # Identify the address of the session structure
(gdb) # (visible in the code after accept, often allocated on the stack or via malloc)
(gdb) watch *((int*)0x7ffff...)    # address of the state field
(gdb) continue
```

Each time the state changes, GDB interrupts execution and displays the old and new values. We thus see the transitions unfold in real time while running the client in another terminal.

With GEF or pwndbg, the `watch` command is enhanced with a visual context that shows registers and the stack at each transition — which allows immediately correlating the transition with the command that triggered it.

---

## Step 5 — Reconstructing Data Structures

### Defining the protocol header in Ghidra

Now that the header format is confirmed, we formalize it by creating a structured type in Ghidra's Data Type Manager:

```c
struct proto_header {
    uint8_t  magic;        // offset 0 — always 0xC0
    uint8_t  msg_type;     // offset 1 — command type
    uint16_t payload_len;  // offset 2 — payload length (big-endian)
};
```

To create this structure in Ghidra: **Data Type Manager → right-click → New → Structure**, then add the fields one by one with the correct types and sizes.

Once the structure is created, we reapply it in the decompiler. Instead of:

```c
if (local_28[0] != 0xc0) { ... }  
iVar1 = (int)local_28[1];  
uVar2 = ((uint)local_28[2] << 8) | (uint)local_28[3];  
```

We get, after retyping the buffer as `struct proto_header *`:

```c
if (hdr->magic != PROTO_MAGIC) { ... }  
cmd_type = hdr->msg_type;  
payload_len = ntohs(hdr->payload_len);  
```

The readability is transformed. We do the same for the session structure:

```c
struct client_session {
    int      socket_fd;
    int      state;           // 0=CONNECTED, 1=HELLO_DONE, 2=AUTHENTICATED
    uint8_t  challenge[8];    // handshake nonce
    char     username[64];    // authenticated username
};
```

### Defining constants as an `enum`

The message type and state values are more readable as enums:

```c
enum msg_type : uint8_t {
    MSG_HELLO_REQ    = 0x01,
    MSG_AUTH_REQ     = 0x02,
    MSG_CMD_REQ      = 0x03,
    MSG_QUIT_REQ     = 0x04,
    MSG_HELLO_RESP   = 0x81,
    MSG_AUTH_RESP    = 0x82,
    MSG_CMD_RESP     = 0x83,
    MSG_QUIT_RESP    = 0x84,
    MSG_ERROR        = 0xFF
};

enum session_state : int {
    STATE_CONNECTED     = 0,
    STATE_HELLO_DONE    = 1,
    STATE_AUTHENTICATED = 2,
    STATE_DISCONNECTED  = 3
};
```

In Ghidra, we create these enums via **Data Type Manager → New → Enum**, then apply them to the corresponding variables and constants in the decompiler. Each `0x01` becomes `MSG_HELLO_REQ`, each `2` becomes `STATE_AUTHENTICATED` — the pseudo-code becomes virtually readable source code.

---

## Step 6 — Documenting the Protocol Format

At this stage, we have all the information to produce an **informal specification** of the protocol. This document will be the reference for writing the ImHex pattern (section 23.3) and the Python client (section 23.5).

### Header format (common to all messages)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic     |   Msg Type    |         Payload Length        |
|     (0xC0)    |               |         (big-endian)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Payload (variable)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Msg Type field convention

Bit 7 encodes the direction:

- **Bit 7 = 0** (`0x01`–`0x7F`): client → server request.  
- **Bit 7 = 1** (`0x81`–`0xFF`): server → client response.  
- The response type is always `request_type | 0x80`.  
- The special value `0xFF` is reserved for errors.

### Payloads by message type

**HELLO Request (`0x01`)**:

```
+-------+-------+-------+-------+-------+-------+-------+-------+
| 'H'   | 'E'   | 'L'   | 'L'   | 'O'   | 0x00  | 0x00  | 0x00  |
+-------+-------+-------+-------+-------+-------+-------+-------+
  Fixed identifier "HELLO"              Padding / reserved
```

**HELLO Response (`0x81`)**:

```
+-------+-------+-------+-------+-------+-------+-------+
| 'W'   | 'E'   | 'L'   | 'C'   | 'O'   | 'M'   | 'E'   |
+-------+-------+-------+-------+-------+-------+-------+
|          Challenge (8 bytes, random)                  |
+-------+-------+-------+-------+-------+-------+-------+
```

**AUTH Request (`0x02`)**:

```
+----------+-------------------+----------+-------------------+
| user_len | username          | pass_len | password          |
| (1 byte) | (user_len bytes)  | (1 byte) | (pass_len bytes)  |
+----------+-------------------+----------+-------------------+
```

**AUTH Response (`0x82`)**:

```
+----------+----------+
| reserved | status   |
| (1 byte) | (1 byte) |
+----------+----------+
  0x00       0x01 = OK, 0x00 = FAIL
```

### Complete protocol sequence

```
1. Client → Server : HELLO Request
2. Server → Client : HELLO Response (+ challenge)
3. Client → Server : AUTH Request (username + password/hash)
4. Server → Client : AUTH Response (status)
   - If AUTH_FAIL → back to step 3 (retry) or disconnection
   - If AUTH_OK → switch to command mode
5. Client → Server : CMD Request (N times)
6. Server → Client : CMD Response (N times)
7. Client → Server : QUIT Request
8. Server → Client : QUIT Response
9. TCP close
```

---

## The Case of Optimized and Stripped Binaries

Everything above assumes a `-O0` binary with symbols, where the correspondence between source code and disassembly is nearly direct. In practice, the training binaries are also provided in `-O2` and stripped. Here are the main differences:

### Effect of `-O2` on the parser

- **Inlining**: small handlers may be inlined into the main loop. Instead of seeing `call handle_hello`, we see the handler code directly in the `switch`. The dispatch remains visible, but the "functions" disappear from the Function Call Graph.  
- **Branch reorganization**: GCC places the most frequent cases first and may transform the `switch` into a jump table or a binary tree of comparisons. The `cmp/je` cascade pattern is replaced by a `jmp [rax*8 + table]` — more efficient but less readable.  
- **Read optimization**: instead of reading the header byte by byte, the compiler may do a `mov eax, DWORD PTR [rdi]` that reads all 4 bytes at once, then extracts each field by masking (`and`, `shr`). The result is functionally identical but the correspondence with the structure fields is less obvious.

### Effect of stripping

Without symbols, function names disappear. We end up with `FUN_00401230` instead of `proto_handle_auth`. The analysis strategy remains the same — we enter through character strings and calls to `recv`/`send` — but the renaming work falls entirely on the analyst.

The recommended approach is to start with the `-O0 -g` variant, thoroughly understand the protocol, then verify that the same structures are found in the optimized variant. This trains the eye to recognize GCC optimization patterns (Chapter 16) applied to the network context.

---

## Section Summary

| Step | Action | Result |  
|------|--------|--------|  
| 1. Locate network functions | XREF on `recv`/`read` in Ghidra | Identification of the main receive loop |  
| 2. Parser anatomy | Decompilation + renaming | Header structure confirmed: magic, type, length |  
| 3. Reconstruct handlers | Descent into each `case` of the dispatch | Exact payload format for each message type |  
| 4. State machine | Identification of the state variable + GDB watchpoint | Transition diagram CONNECTED → HELLO_DONE → AUTHENTICATED |  
| 5. Data structures | Creation of `struct` and `enum` in Ghidra | Readable pseudo-code, close to the original source code |  
| 6. Documentation | Informal protocol specification | Reference for ImHex (23.3) and the Python client (23.5) |

We now have a complete understanding of the protocol: header format, format of each payload, state machine, and authentication mechanism. The next section (**23.3**) will visually formalize this understanding by writing a `.hexpat` pattern for ImHex, capable of automatically decoding captured frames.

⏭️ [Visualize binary frames with ImHex and write a `.hexpat` for the protocol](/23-network/03-frames-imhex-hexpat.md)
