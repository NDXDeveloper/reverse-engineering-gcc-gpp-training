🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 20

## Produce a Complete `.h` for the `ch20-network` Binary

> **Target binary**: `binaries/ch20-network/server_O2_strip`  
> **Estimated time**: 2 to 3 hours  
> **Required tools**: Ghidra, RetDec (optional), GCC, a text editor  
> **Prerequisites**: having read sections 20.1 through 20.6

---

## Objective

This checkpoint validates all the skills acquired in chapter 20. The goal is to produce a complete C header file (`ch20_network_reconstructed.h`) from the stripped network server binary, **without consulting the source code** provided in `binaries/ch20-network/`.

The reconstructed header must fully capture the binary protocol implemented by the server: constants, message structures, enumerations, and main function signatures. It must be correct and complete enough that a third-party developer could write a compatible client using only this header.

---

## The target binary

The network server is compiled with `-O2 -s` — optimized and stripped. It contains neither debug symbols nor local function names. The only available names are dynamic symbols imported from libc (PLT functions: `socket`, `bind`, `listen`, `accept`, `send`, `recv`, `memcmp`, `strncmp`, `printf`, etc.).

The server listens on a TCP port, accepts connections, authenticates clients via a binary exchange, then processes commands. The entire protocol is to be discovered through decompilation.

---

## What the header must contain

### 1. Protocol constants

All immediate values with an identifiable role in the protocol must be formalized as `#define`. This includes at minimum:

- The protocol header magic bytes  
- The protocol version number  
- The maximum payload size  
- The protocol header size  
- The session token size  
- The authentication hash size  
- The default listening port

### 2. Enumerations

Discrete values used in `switch` statements or `if/else` chains must be formalized as `typedef enum`. This includes:

- Protocol message types (identified in the server's main dispatcher)  
- Command identifiers (identified in the command handler)

Each value must be accompanied by a comment indicating its deduced role.

### 3. Data structures

All structures of messages exchanged over the network must be reconstructed with the correct types, correct offsets, and the `packed` attribute if necessary. This includes at minimum:

- The protocol header structure (the first bytes of each frame)  
- The authentication payload structure (client request)  
- The authentication response structure (server response)  
- The command header structure (client request)

Each field must be commented with its offset and semantics.

### 4. Function signatures

The server's main functions must be declared with their parameter and return types. This includes:

- The checksum computation function  
- Endianness conversion utility functions (if not inlined)  
- The message send function  
- The message receive function  
- The authentication handler  
- The command handler  
- The token generation function

Each signature must be annotated with the function's address in the binary (`FUN_XXXXXXXX` or hexadecimal address).

---

## Validation criteria

The header is considered complete and correct if it satisfies the following five criteria.

### Criterion 1: compilation without errors

```bash
echo '#include "ch20_network_reconstructed.h"' > test_header.c  
gcc -Wall -Wextra -Wpedantic -std=c11 -c test_header.c  
```

Compilation must produce **no errors and no warnings**. Required system `#include`s (`<stdint.h>`, `<stddef.h>`, etc.) must be present in the header.

### Criterion 2: correct structure sizes

Structure sizes and offsets must match what is observed in the binary. A verification program must confirm:

```c
#include <stdio.h>
#include <stddef.h>
#include "ch20_network_reconstructed.h"

int main(void) {
    int ok = 1;

    /* Verify protocol header size */
    if (sizeof(proto_header_t) != 6) {
        printf("FAIL: sizeof(proto_header_t) = %zu, expected 6\n",
               sizeof(proto_header_t));
        ok = 0;
    }

    /* Verify type field offset */
    if (offsetof(proto_header_t, type) != 3) {
        printf("FAIL: offsetof(proto_header_t, type) = %zu, expected 3\n",
               offsetof(proto_header_t, type));
        ok = 0;
    }

    /* Verify payload_len field offset */
    if (offsetof(proto_header_t, payload_len) != 4) {
        printf("FAIL: offsetof(proto_header_t, payload_len) = %zu, expected 4\n",
               offsetof(proto_header_t, payload_len));
        ok = 0;
    }

    /* Add similar checks for other structures:
     * auth_req_payload_t, auth_resp_payload_t, cmd_req_header_t */

    if (ok) printf("ALL CHECKS PASSED\n");
    return ok ? 0 : 1;
}
```

All checks must pass.

### Criterion 3: message type exhaustiveness

The message type enumeration must cover all values handled by the server's dispatcher. No branch of the main `switch` should correspond to a value absent from the enumeration.

### Criterion 4: command exhaustiveness

The command enumeration must cover all values handled by the command handler. Undocumented commands (those falling into the `switch`'s `default`) do not count — only explicitly handled commands need to be listed.

### Criterion 5: practical usability

A developer reading only the header (without access to the binary or Ghidra) must be able to understand the protocol well enough to sketch a client. This means that comments explain the semantics of each field, that the endianness of multi-byte fields is documented, and that the exchange flow is described at minimum in a header comment.

---

## Methodological hints

These hints do not give the solution but orient the approach. Consult them progressively if needed.

### Hint 1 — Starting point

Import `server_O2_strip` into Ghidra and run the full automatic analysis (all options checked, including Decompiler Parameter ID and Aggressive Instruction Finder). Locate `main` via the entry point `_start` → `__libc_start_main`. The `main` function contains calls to `socket`, `bind`, `listen`, and `accept` — it is easy to identify even without symbols.

### Hint 2 — The dispatcher

The function called after `accept` is the client handler. It contains a loop with a `switch` on a byte — this is the message type dispatcher. The `switch` values are the types for the enumeration to reconstruct.

### Hint 3 — The magic bytes

The message receive function starts by reading 6 bytes (the header), then compares the first two bytes to constants. These constants are the protocol's magic bytes. The size of this first `recv` gives the header size.

### Hint 4 — Authentication structures

The authentication handler calls `strncmp` and `memcmp` on the received payload. The offsets of these calls within the payload buffer reveal the authentication message structure: where the username is located, where the hash is located, and what the size of each field is.

### Hint 5 — The authentication response

After a successful authentication, the server sends a response message. The handler's pseudo-code shows the bytes written into the response buffer: a status byte (0 or 1) followed by a block of bytes (the session token). The size of this block gives `PROTO_TOKEN_LEN`.

### Hint 6 — Hardcoded credentials

The authentication handler compares the received hash with a 32-byte array stored in `.rodata`. This array and the reference username (also a string in `.rodata`) are the hardcoded credentials. They are not strictly part of the header, but documenting them in a comment is a useful bonus.

### Hint 7 — Cross-reference with RetDec

If a function is particularly difficult to read in Ghidra (for example the token generation function or the checksum computation), run RetDec on the same binary and compare the pseudo-code from both tools. RetDec may reconstruct the checksum loop more compactly.

---

## Common mistakes to avoid

- **Forgetting `__attribute__((packed))`** on network structures. Without this attribute, GCC inserts padding and sizes no longer match.  
- **Confusing endianness.** The `payload_len` field is stored in big-endian in the network frame. The header must clearly document this, and utility functions `read_be16`/`write_be16` must be included or declared.  
- **Assigning the wrong type to the `success` field** of the authentication response. It is a `uint8_t` (1 byte), not an `int` (4 bytes). This error shifts all subsequent fields in the structure.  
- **Missing a message type.** The `DISCONNECT` message (`0xFF`) is easy to miss because it may appear as a separate case in the dispatcher rather than in the main `switch`.  
- **Declaring inlined functions as regular functions.** Utility functions like checksum or endianness conversions are often inlined by GCC at `-O2`. They do not have their own address in the binary — declare them as `static inline` in the header.

---

## Expected deliverable

A single file `ch20_network_reconstructed.h` following the recommended structure from section 20.4:

```
ch20_network_reconstructed.h
├── Header comment (source binary, hash, tools, date)
├── Include guards
├── System #includes (<stdint.h>, <stddef.h>)
├── Section 1: Constants (#define)
├── Section 2: Enumerations (typedef enum)
├── Section 3: Structures (typedef struct)
├── Section 4: Inline utility functions
└── Section 5: Main function signatures
```

---

## Solution

The complete solution is available in `solutions/ch20-checkpoint-solution.h`. Consult it only after producing your own version and verifying the validation criteria. Compare the two versions to identify divergences and understand alternative choices.


⏭️ [Part V — Practical Cases on Our Applications](/part-5-practical-cases.md)
