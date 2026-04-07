🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 20.4 — Reconstructing a `.h` File from a Binary (Types, Structs, API)

> 📘 **Chapter 20 — Decompilation and Source Code Reconstruction**  
> **Part IV — Advanced RE Techniques**

---

## The header as an RE deliverable

In the previous sections, we learned how to obtain pseudo-code from a binary with Ghidra and RetDec. This pseudo-code is useful for understanding logic, but it remains locked inside the decompilation tool. The natural question that follows is: **what do we concretely produce at the end of an analysis?**

One of the most useful reverse engineering deliverables is a `.h` file — a C/C++ header that captures everything the analyst has discovered about the binary's interfaces. This file documents data structures, function signatures, constants, and enumerations reconstructed from disassembly and decompilation. It is a tangible artifact that serves several purposes:

**Documenting the analysis.** The header is a structured, readable summary of all the retyping and renaming work done in Ghidra. It can be reviewed by a colleague, versioned in a Git repository, and serve as a reference for future analyses of later versions of the same binary.

**Writing code that interacts with the binary.** If the goal is to write a client compatible with the analyzed server (chapter 23), a plugin for the C++ application (chapter 22), or a keygen (chapter 21), the header provides the definitions needed for that code to compile and be compatible with the binary's structures.

**Feeding Ghidra itself.** The reconstructed header can be reimported into Ghidra via *File → Parse C Source* to enrich the Data Type Manager, which in turn improves pseudo-code quality throughout the project.

This section details the method for building this header step by step, using our three training binaries as examples.

---

## General methodology

Reconstructing a header from a binary is not an automatic process — it is iterative work that builds up over the course of the analysis. You do not sit down in front of a binary thinking "I will now produce the header." You build it progressively, extracting and formalizing discoveries made in Ghidra.

The method follows a natural order: first constants and enumerations (the simplest elements to identify), then data structures (which require memory access analysis), then function signatures (which depend on previously defined types), and finally the relationships between these elements (call graph, structure dependencies).

### Phase 1: constants and magic numbers

Constants are the first exploitable information in a binary, because they appear in plain sight in machine code — they are immediate values in instructions or data in `.rodata`.

**Where to find them.** In Ghidra, the scalar search (*Search → For Scalars*) lists all immediate values in the binary. Recurring or recognizable values are worth naming. The `strings` command and Ghidra's *Defined Strings* view reveal character strings, some of which are protocol identifiers, error messages, or configuration names.

**How to extract them.** Look for the following patterns in pseudo-code and disassembly:

**Magic numbers** appear in comparisons and initializations. In `keygenme_O2_strip`, the pseudo-code of the derivation function contains the value `0xdeadbeef` used as an initial seed. In `server_O2_strip`, the bytes `0xc0` and `0xfe` appear in the receive function as a header validity check. These values become `#define`s in the header.

**Sizes and limits** appear as loop bounds, `malloc` arguments, or `memcmp`/`memcpy` parameters. A `memcmp(buf, expected, 0x20)` indicates a 32-byte comparison — probably a hash size. A `recv(fd, buf, 0x400, 0)` indicates a 1024-byte buffer. These values also become `#define`s.

**Enumeration values** appear in `switch` statements and `if/else` chains. In the network server, the pseudo-code of the main dispatcher tests `type == 1`, `type == 2`, etc. By cross-referencing with error message strings and sent responses, you can deduce the semantics of each value.

**What this looks like in the header.** After analyzing `server_O2_strip`, you might write:

```c
/* Protocol constants — extracted from server_O2_strip */
#define PROTO_MAGIC_0       0xC0
#define PROTO_MAGIC_1       0xFE
#define PROTO_VERSION       0x01
#define PROTO_MAX_PAYLOAD   1024    /* 0x400 */
#define PROTO_HEADER_SIZE   6
#define PROTO_TOKEN_LEN     16     /* 0x10 */
#define PROTO_HASH_LEN      32     /* 0x20 */
#define DEFAULT_PORT        4337   /* 0x10F1 */
```

At this stage, we do not yet know what these constants were called in the original source. The chosen names are reasonable deductions based on usage context. This is perfectly normal — the reconstructed header documents the analyst's understanding, not the exact source code.

### Phase 2: data structures

Structures are at the heart of the reconstructed header. This is also the most technical part, because structures no longer exist explicitly in the binary — they manifest only through memory access patterns.

**Identifying a structure.** The main signal is a pointer used with several different offsets. When pseudo-code shows:

```c
*(uint8_t *)(param_1 + 0)  = 0xc0;
*(uint8_t *)(param_1 + 1)  = 0xfe;
*(uint8_t *)(param_1 + 2)  = 0x01;
*(uint8_t *)(param_1 + 3)  = type;
*(uint16_t *)(param_1 + 4) = payload_len;
```

You recognize sequential access to contiguous fields. The offsets `0, 1, 2, 3, 4` and access sizes (`uint8_t` for the first four, `uint16_t` for the last) map out the structure in memory.

**Determining field types.** Each field's type is deduced from how it is used:

A field compared with a known constant (`== 0xC0`) is probably a magic byte `uint8_t`. A field passed to `strlen` or `printf("%s", ...)` is a `char[]` or `char *`. A field used as a size argument in `memcpy` or `malloc` is an integer (its width depends on the access instruction size). A field passed to `memcmp` with a length of 32 is probably a `uint8_t[32]` hash.

**Determining alignment and packing.** GCC aligns structure fields by default according to ABI rules. A `uint32_t` at offset 5 (not aligned to 4) would indicate a `__attribute__((packed))` structure. You can verify by checking whether the compiler uses unaligned memory accesses (byte-by-byte load/store) or direct accesses (32-bit load/store).

**Handling holes (padding).** If a `uint8_t` field is at offset 3 and the next `uint32_t` field is at offset 8, there is a 4-byte padding gap between them (offsets 4–7). GCC inserts this padding to align the `uint32_t` on a 4-byte boundary. The header must either add an explicit padding field or use `__attribute__((packed))` if the original structure was packed.

**What this looks like in the header.** By analyzing the `recv_message` function of `server_O2_strip`, we reconstruct:

```c
/* Network protocol header — 6 bytes, packed */
typedef struct __attribute__((packed)) {
    uint8_t  magic[2];       /* offset 0x00 — expected: {0xC0, 0xFE} */
    uint8_t  version;        /* offset 0x02 — expected: 0x01 */
    uint8_t  type;           /* offset 0x03 — message type */
    uint16_t payload_len;    /* offset 0x04 — big-endian */
} proto_header_t;
```

The offset comments are essential: they allow verifying the structure's consistency with the disassembly and facilitate review.

### Phase 3: enumerations

Enumerations emerge naturally from analyzing `switch` statements and discrete value tests. In the server's dispatcher, we observe a `switch` on the header's `type` field, with cases for values `1`, `2`, `3`, `4`, `5`, `6`, and `0xff`. By cross-referencing with the behavior of each case (sending a hash, sending a token, processing a command, etc.), we reconstruct the semantics:

```c
/* Message types — deduced from switch in handle_client() */
typedef enum {
    MSG_AUTH_REQ    = 0x01,   /* client -> server: authentication */
    MSG_AUTH_RESP   = 0x02,   /* server -> client: auth response */
    MSG_CMD_REQ     = 0x03,   /* client -> server: command */
    MSG_CMD_RESP    = 0x04,   /* server -> client: command response */
    MSG_PING        = 0x05,   /* keepalive */
    MSG_PONG        = 0x06,   /* keepalive response */
    MSG_DISCONNECT  = 0xFF    /* end of session */
} msg_type_t;
```

The names are conjectures based on observed behavior. If the binary contains debug strings like `"Auth OK"` or `"Unknown command"`, they confirm the hypotheses. Otherwise, the names remain analyst conventions — the header documents them with explanatory comments.

### Phase 4: function signatures

Once types and structures are defined, function signatures become expressible cleanly. They are extracted from Ghidra's pseudo-code by combining several sources of information:

**Number of parameters.** Determined by the registers used at function entry according to the System V AMD64 convention: `rdi` (1st), `rsi` (2nd), `rdx` (3rd), `rcx` (4th), `r8` (5th), `r9` (6th). Beyond that, parameters go on the stack. Ghidra detects this automatically in most cases.

**Parameter types.** Deduced from usage in the function body. A parameter passed to `strlen` is a `const char *`. A parameter used as a file descriptor in `send`/`recv` is an `int`. A parameter accessed with `proto_header_t` offsets is a `proto_header_t *` (or `uint8_t *` if the structure has not yet been reconstructed).

**Return type.** Determined by the use of `rax`/`eax` after the call. If the return value is tested with `test eax, eax` followed by a conditional jump, it is an `int` used as a boolean or error code. If it is passed to `free` or used as a pointer, it is a `void *` or specific pointer type.

**Calling convention and qualifiers.** For functions that are not exported (no dynamic symbol), `static` can be added. For parameters that are not modified in the function body, `const` is appropriate.

**What this looks like in the header:**

```c
/* ============================================================
 * Protocol API — signatures reconstructed from
 * server_O2_strip, functions identified via Ghidra analysis
 * ============================================================ */

/* XOR checksum computation on a buffer — FUN_00401120 */
static inline uint8_t proto_checksum(const uint8_t *data, size_t len);

/* 16-bit big-endian read — inlined, not present as symbol */
static inline uint16_t read_be16(const uint8_t *p);

/* 16-bit big-endian write — inlined, not present as symbol */
static inline void write_be16(uint8_t *p, uint16_t val);

/* Send a complete message (header + payload + checksum)
 * Returns 0 on success, -1 on error.
 * FUN_00401250 */
static int send_message(int fd, uint8_t type,
                        const uint8_t *payload, uint16_t payload_len);

/* Receive a complete message with checksum verification.
 * Returns 0 on success, -1 on error.
 * type, payload and payload_len are output parameters.
 * FUN_00401340 */
static int recv_message(int fd, uint8_t *type,
                        uint8_t *payload, uint16_t *payload_len);

/* Server-side authentication handling — FUN_00401500 */
static void handle_auth(int fd, const uint8_t *payload,
                        uint16_t payload_len);

/* Command dispatch after authentication — FUN_00401620 */
static void handle_cmd(int fd, const uint8_t *payload,
                       uint16_t payload_len);
```

Each signature is annotated with the function's address in the binary (`FUN_XXXXXXXX`). This traceability allows finding the source of each declaration back in Ghidra.

### Phase 5: assembly and organization of the header

The final header must be structured for readability and usability. Here is the recommended convention:

```c
/*
 * ch20_network_reconstructed.h
 *
 * Header reconstructed by analysis of the server_O2_strip binary
 * RE Training — Chapter 20, decompilation exercise
 *
 * This file documents the structures and API of the custom
 * network protocol identified in the TCP server on port 4337.
 *
 * Primary tool: Ghidra 11.x
 * Secondary tool: RetDec 5.0
 * Source binary: server_O2_strip (SHA256: ...)
 */

#ifndef CH20_NETWORK_RECONSTRUCTED_H
#define CH20_NETWORK_RECONSTRUCTED_H

#include <stdint.h>
#include <stddef.h>

/* ---- Section 1: Constants ---- */
/* ... #define ... */

/* ---- Section 2: Enumerations ---- */
/* ... typedef enum ... */

/* ---- Section 3: Structures ---- */
/* ... typedef struct ... */

/* ---- Section 4: Function signatures ---- */
/* ... prototypes ... */

#endif /* CH20_NETWORK_RECONSTRUCTED_H */
```

The file header contains analysis metadata: which binary was analyzed (with a hash for unambiguous identification), which tools were used, and the date of analysis. Include guards and system includes make the header directly usable in C code.

---

## Practical case: the keygenme_O2_strip binary

Let's apply the method on a binary that provides no help — no symbols, no DWARF. Here are the concrete steps.

### Identifying constants

After the initial triage (`strings`, `file`, `checksec`) and import into Ghidra, navigate to the `main` function (identified via the entry point `_start` → `__libc_start_main`). The pseudo-code reveals:

- The value `0xdeadbeef` assigned to a field before a computation call. This is a seed.  
- The literal `3` in a string length comparison. This is the minimum username length.  
- The literal `0x10` (16) in a comparison loop. This is the key size.  
- The literal `4` as a loop bound in the derivation function. This is the round count.  
- The value `0x01000193` in the hashing loop. This is the FNV prime constant, an important clue about the algorithm used.

```c
#define MAGIC_SEED    0xDEADBEEF
#define KEY_LEN       16
#define MAX_USER      64    /* deduced from fgets buffer size */
#define ROUND_COUNT   4
#define FNV_PRIME     0x01000193
```

### Reconstructing the main structure

The `main` function allocates a block on the stack whose different offsets are used to store the username (offset 0x00, accessed by `fgets` with a size of 64), the expected key (offset 0x40, written by the derivation function, 16 bytes) and the seed (offset 0x50, initialized to `0xdeadbeef`). We deduce:

```c
/* License context structure — reconstructed from main()
 * Total size: 0x54 (84 bytes) */
typedef struct {
    char     username[64];     /* offset 0x00 — fgets buffer */
    uint8_t  expected_key[16]; /* offset 0x40 — derived key */
    uint32_t seed;             /* offset 0x50 — initialized to 0xDEADBEEF */
} license_ctx_t;
```

To validate this reconstruction, verify that `sizeof(license_ctx_t)` matches the size allocated on the stack (visible in the `main` prologue via the `sub rsp, ...` instruction), accounting for alignment.

### Extracting signatures

The internal functions of `keygenme_O2_strip` have no names. We identify them by their role and assign a name in the header:

```c
/* Key derivation from username and seed.
 * Iterates ROUND_COUNT times a custom hash (XOR + rotation + FNV).
 * FUN_00401200 — called from main() after username input */
void derive_key(const char *username, uint32_t seed, uint8_t *out_key);

/* User input parsing in XXXXXXXX-XXXXXXXX-... format
 * Returns 0 if format is valid, -1 otherwise.
 * FUN_00401350 — called from main() after key input */
int parse_key_input(const char *input, uint8_t *out_key);

/* Constant-time comparison of two KEY_LEN-byte buffers.
 * Returns 1 if identical, 0 otherwise.
 * FUN_00401400 — called from main() for final verification */
int verify_key(const uint8_t *expected, const uint8_t *provided);
```

---

## Specific case: C++ and oop_O2_strip

The C++ binary adds complexities specific to header reconstruction. The very notion of a "`.h` file" takes on a slightly different meaning: we reconstruct class declarations with their virtual methods, rather than simple C structures and free functions.

### Reconstructing a class from the vtable

In Ghidra, after identifying the `Device` vtable (a series of function pointers in `.rodata`, referenced by the constructor), we can reconstruct the class declaration. The order of pointers in the vtable gives the order of virtual methods:

```cpp
/* Abstract base class — reconstructed from vtable
 * at address 0x404a00 in oop_O2_strip
 *
 * Vtable layout (offsets from object's vptr):
 *   +0x00  -> ~Device() D1 (complete object destructor)
 *   +0x08  -> ~Device() D0 (deleting destructor)
 *   +0x10  -> type_name() const -> std::string
 *   +0x18  -> initialize()
 *   +0x20  -> process()
 *   +0x28  -> status_report() const -> std::string
 */
class Device {  
public:  
    virtual ~Device();
    virtual std::string type_name() const = 0;
    virtual void        initialize()       = 0;
    virtual void        process()          = 0;
    virtual std::string status_report() const;

    /* Non-virtual accessors — identified by direct calls (not vtable) */
    const std::string &name() const;
    uint32_t           id()   const;
    bool               is_active() const;

protected:
    void set_active(bool state);

private:
    /* Object memory layout (excluding vptr):
     * +0x08  std::string name_    (size depends on implementation)
     * +0x28  uint32_t    id_      (offset verified by accessor access)
     * +0x2c  bool        active_  (1 byte + padding) */
    std::string name_;
    uint32_t    id_;
    bool        active_;
};
```

Member offsets are obtained by analyzing non-virtual accessors (functions that read a field at a fixed offset from `this`). The `id()` accessor does `return *(uint32_t *)(this + 0x28)`, which places `id_` at offset 0x28. The size of `std::string` before this field (0x28 - 0x08 = 0x20 = 32 bytes) is consistent with the libstdc++ implementation where `std::string` contains a pointer, a size, and an SSO buffer.

### Derived classes

For `Sensor` and `Actuator`, we repeat the process: identify their respective vtables, compare with `Device`'s to find overridden methods, and analyze their constructors to deduce additional members.

```cpp
/* Sensor class — inherits from Device
 * Vtable at 0x404a40
 * Additional members from offset 0x30:
 *   +0x30  double   min_range_
 *   +0x38  double   max_range_
 *   +0x40  double   last_value_
 *   +0x48  uint32_t read_count_
 */
class Sensor : public Device {  
public:  
    Sensor(const std::string &name, uint32_t id,
           double min_range, double max_range);

    std::string type_name() const override;
    void        initialize() override;
    void        process() override;
    std::string status_report() const override;

    double last_value() const;

private:
    double   min_range_;
    double   max_range_;
    double   last_value_;
    uint32_t read_count_;
};
```

### The plugin interface

The plugin system uses `dlopen`/`dlsym` to load functions exported with C calling convention. Analyzing the `load_plugin` function (identifiable by its calls to `dlopen`, `dlsym`, `dlerror`) reveals the symbol names being searched: the strings `"plugin_name"` and `"plugin_run"` in `.rodata`. The header documents this interface:

```cpp
/* Plugin interface — C convention for dynamic loading.
 * A valid .so plugin must export these two symbols. */
extern "C" {
    /* Returns the plugin name (static string) */
    const char *plugin_name(void);

    /* Plugin entry point — receives a pointer to the DeviceManager */
    void plugin_run(DeviceManager *mgr);
}
```

This header is directly usable to write a compatible plugin without having the application's source code — which is exactly the goal of chapter 22's checkpoint.

---

## Validating the reconstructed header

A reconstructed header has value only if it is correct. Several validation techniques are possible.

### Compilation test

The header must compile without errors when included in an empty C/C++ file:

```bash
echo '#include "ch20_network_reconstructed.h"' > test.c  
gcc -c -Wall -Wextra -std=c11 test.c  
```

If the compiler issues warnings or errors, the header contains type inconsistencies or missing dependencies.

### Structure size test

You can write a small program that verifies that sizes and offsets match what is observed in the binary:

```c
#include <stdio.h>
#include <stddef.h>
#include "ch20_network_reconstructed.h"

int main(void) {
    printf("sizeof(proto_header_t) = %zu (expected: 6)\n",
           sizeof(proto_header_t));
    printf("offsetof(proto_header_t, type) = %zu (expected: 3)\n",
           offsetof(proto_header_t, type));
    printf("offsetof(proto_header_t, payload_len) = %zu (expected: 4)\n",
           offsetof(proto_header_t, payload_len));
    printf("sizeof(auth_req_payload_t) = %zu (expected: 64)\n",
           sizeof(auth_req_payload_t));
    return 0;
}
```

If sizes do not match, a field is incorrectly typed, padding is missing, or the `packed` attribute is absent.

### Functional test

The strongest validation is writing code that uses the header to interact with the binary. For the network binary, writing a minimal client that uses the header's structures and constants to authenticate with the server proves the reconstruction is correct. If the server accepts the connection and responds correctly, the structures are accurate.

---

## Common mistakes and how to avoid them

### Confusing field order with access order

Ghidra's pseudo-code shows memory accesses in execution order, not necessarily in the order of the structure's fields. If a function fills the field at offset 0x10 first, then the one at offset 0x00, the analyst may be tempted to place the first written field first in the structure. Always rely on **numeric offsets**, not on the order of appearance in pseudo-code.

### Ignoring alignment padding

On x86-64, GCC aligns `uint32_t` on 4-byte boundaries and `uint64_t`/`double`/pointers on 8-byte boundaries by default. Forgetting this padding leads to shifted offsets for all subsequent fields. When in doubt, verify each field's offset individually in the disassembly rather than relying on cumulative calculation.

### Confusing type size with access size

A `bool` field (1 byte) may be read by a `movzx eax, byte ptr [...]` instruction but also by a `mov eax, [...]` that loads 4 bytes (the upper 3 bytes being ignored or padding). The actual type is determined by usage semantics, not by the access instruction width.

### Forgetting endianness of network fields

For network protocol structures, multi-byte fields are often in big-endian (network byte order), while x86-64 is little-endian. The pseudo-code shows calls to `htons`/`ntohs` (or equivalent manual shifts) which signal endianness conversion. The header must clearly document which convention is used for each field, as we did with `/* big-endian */` in `proto_header_t`.

### Not documenting the confidence level

Not all reconstructions are equal. A field whose type is confirmed by three different accesses and a known library call is near-certain. A field deduced from a single ambiguous access is hypothetical. The header benefits from annotating the confidence level:

```c
    uint32_t seed;             /* offset 0x50 — CONFIRMED: init 0xDEADBEEF,
                                  passed as param_2 to derive_key */
    uint8_t  unknown_0x54[4];  /* offset 0x54 — UNCERTAIN: accessed only
                                  once, role undetermined */
```

---

## Reimporting the header into Ghidra

Once the header is finalized, it can be reimported into Ghidra to close the loop and improve pseudo-code throughout the project.

The procedure is as follows: in the Data Type Manager, right-click → *Open/Create* → select *Parse C Source*. In the window that appears, add the `.h` file to the source file list, configure the parsing options (standard C11 or C++17 as appropriate), and launch the parsing. The types defined in the header are imported into the Data Type Manager and can be applied to variables and parameters in the pseudo-code.

The effect is immediate: accesses with numeric offsets transform into named field accesses, `undefined4` becomes `uint32_t`, and pseudo-code gains considerably in readability. This is the virtuous cycle of decompilation: the more types are formalized, the more readable the pseudo-code becomes, the more types can be refined.

---


⏭️ [Identifying embedded third-party libraries (FLIRT / Ghidra signatures)](/20-decompilation/05-flirt-signatures.md)
