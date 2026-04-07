🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Checkpoint Solution — Chapter 14

> **Spoilers** — This document contains the complete checkpoint solution. Try the exercise yourself before consulting this solution.

---

## Environment Preparation

### Test File and Launch Commands

```bash
# Create a test file of known size (64 bytes of ASCII text)
python3 -c "print('A'*63)" > test_64.txt

# Create a second larger file for comparison (512 bytes)
python3 -c "print('B'*511)" > test_512.txt

# Disable ASLR for stable addresses between runs
# (necessary if the binary is PIE)
sudo sysctl -w kernel.randomize_va_space=0
# OR, per command, without modifying the system:
# setarch x86_64 -R valgrind [options] ./ch14-crypto [args]
```

### Analysis Runs

```bash
cd binaries/ch14-crypto/

# -- Run 1: Memcheck (-O0 version with symbols) --
valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --track-fds=yes \
    --verbose \
    --log-file=../../analysis/01_memcheck_64.txt \
    ./crypto_O0 encrypt ../../test_64.txt ../../out_64.enc S3cretP@ss

valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --log-file=../../analysis/01_memcheck_512.txt \
    ./crypto_O0 encrypt ../../test_512.txt ../../out_512.enc S3cretP@ss

# -- Run 2: Callgrind --
valgrind \
    --tool=callgrind \
    --callgrind-out-file=../../analysis/02_callgrind_64.out \
    --collect-jumps=yes \
    ./crypto_O0 encrypt ../../test_64.txt ../../out_64.enc S3cretP@ss

# -- Run 3: ASan + UBSan (recompilation) --
make clean  
CC=gcc CFLAGS="-fsanitize=address,undefined -g -O0 -fno-omit-frame-pointer" make  
ASAN_OPTIONS="halt_on_error=0:detect_leaks=1:log_path=../../analysis/03_asan" \  
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \  
    ./crypto_asan encrypt ../../test_64.txt ../../out_asan.enc S3cretP@ss

# -- Run 4: MSan (Clang, if available) --
clang -fsanitize=memory -fsanitize-memory-track-origins=2 -g -O0 \
    -o crypto_msan crypto.c -lm
MSAN_OPTIONS="halt_on_error=0:log_path=../../analysis/04_msan" \
    ./crypto_msan encrypt ../../test_64.txt ../../out_msan.enc S3cretP@ss
```

---

## Deliverable 1 — Allocation Map

### Extraction from Memcheck

The `HEAP SUMMARY` from the Memcheck report (64-byte input) displays:

```
==23456== HEAP SUMMARY:
==23456==     in use at exit: 1,376 bytes in 7 blocks
==23456==   total heap usage: 19 allocs, 15 frees, 6,208 bytes allocated
```

19 allocations, 15 frees → 4 program blocks not freed at exit (the 3 remaining blocks are internal libc buffers, categorized "still reachable"). Cross-referencing with detailed leaks and ASan reports yields the complete map:

### Allocation Map — `ch14-crypto` (input: 64 bytes)

| ID | Size (bytes) | Allocation function | Alloc count | Free function | Memcheck category | Hypothesis |  
|----|-------------|---------------------|------------|--------------|------------------|-----------|  
| A1 | 32 | `0x401B89` (`derive_key`) | 1 | — | still reachable | **AES-256 key** (256 bits = 32 bytes) |  
| A2 | 16 | `0x401B45` (`prepare_iv`) | 1 | — | still reachable | **AES-CBC/CTR IV** (128 bits = 16 bytes = AES block size) |  
| A3 | 4096 | `0x4019F0` (`init_io`) | 1 | `0x401F10` (`cleanup`) | — (freed) | File read buffer (page size) |  
| A4 | 128 | `0x401DA1` (`write_block`) | 5 | `0x401E80` (`write_block`) | — (freed) | Output buffer — header + ciphertext |  
| A5 | 240 | `0x401C30` (`init_aes_ctx`) | 1 | — | still reachable | **AES context** (expanded key + state) |  
| A6 | 1024 | `0x4018A0` (`read_password`) | 1 | `0x4018F0` (`read_password`) | — (freed) | Temporary password read buffer |  
| A7 | 64 | `0x401A20` (`generate_salt`) | 1 | — | definitely lost | **Derivation salt** (512 bits = SHA-256 block size) |  
| A8 | 32 | `0x401A60` (`derive_key`) | 1 | `0x401AE0` (`derive_key`) | — (freed) | Temporary derivation buffer (HMAC output) |

**Key observations:**

- **4 program blocks not freed**: A1 (key), A2 (IV) and A5 (context) are crypto structures accessible from local or global variables at exit — Memcheck categorizes them as "still reachable". A7 (salt) is "definitely lost" because the pointer is lost upon `derive_key()` return (local variable). These are crypto structures that persist throughout encryption and that the developer didn't clean up — in a real situation, this is a security bad practice (keys remain in memory).  
- **A3 is fixed size (4096 bytes)** regardless of input → the read buffer is a page, not proportional to the file.  
- **A4 is allocated and freed 5 times** for 64-byte input → 5 encryption blocks processed (see explanation below).

### Why 5 calls to encrypt_block and not 4?

The input is 64 bytes. With a 16-byte AES block, that gives 64 / 16 = 4 data blocks. However, the code adds a **PKCS7 padding block** when the input size is an exact multiple of `BLOCK_SIZE` (condition visible in `process_encrypt()`). This additional 16-byte padding block is encrypted like the others, bringing the total to **5 calls** to `encrypt_block` and 5 A4 allocations/frees.

This is a detail that Callgrind reveals directly: the number of `encrypt_block` calls is 5, not 4. Without Callgrind, one could also deduce it by counting A4 allocations in the Memcheck report (by analyzing the `malloc` call stacks in `write_block`).

### Verification by Input Comparison

| Block | 64-byte input | 512-byte input | Conclusion |  
|-------|--------------|----------------|------------|  
| A1 | 32 | 32 | Fixed size → key |  
| A2 | 16 | 16 | Fixed size → IV |  
| A3 | 4096 | 4096 | Fixed size → page buffer |  
| A4 | 128 × 5 allocs | 128 × 33 allocs | Fixed size, variable alloc count → output block |  
| A5 | 240 | 240 | Fixed size → crypto context |  
| A7 | 64 | 64 | Fixed size → hash/salt |

All blocks are fixed size. The only varying element is the **number of A4 allocations**, which follows the number of encryption blocks (proportional to file size). For 512 bytes: 512/16 = 32 data blocks + 1 padding block = 33 calls — which Callgrind confirms.

---

## Deliverable 2 — Key Buffer Identification

### Key Buffer — Block A1 (32 bytes)

**Identification:**

| Source | Observation | Conclusion |  
|--------|-------------|------------|  
| Memcheck | 32-byte block, still reachable, allocated by `0x401B89` | Persistent 32-byte structure |  
| Memcheck | "Uninitialised value was created by a heap allocation at 0x401B89" then "Uninitialised value was stored by 0x401AC0" | Block is allocated empty then filled by `0x401AC0` (derivation) |  
| Callgrind | `0x401B89` called 1 time, self cost 0.2% | Simple allocation function (no computation) |  
| Callgrind | `0x401AC0` called 1 time, self cost 8.3% | Derivation function (significant computation) |  
| ASan | No error on this block | Access always within bounds |  
| UBSan | Signed integer overflow in `0x401AC0` ("2147483600 + 217 cannot be represented in type 'int'") | Modular additions in derivation → typical of a hash |

**Conclusion — dual confirmation:**
1. The 32-byte = 256-bit size exactly matches an AES-256 key (Memcheck size + crypto knowledge).  
2. The function filling the block (`0x401AC0`) consumes 8.3% CPU and triggers signed overflows typical of hash → it's a key derivation function of type PBKDF2 or HKDF (Callgrind cost + UBSan overflow).

**Key flow:**
```
argv[4] ("S3cretP@ss")
    |
    v
read_password (0x4018A0) — reads password into A6 (1024 bytes)
    |
    v
derive_key (0x401B89) — malloc(32) → A1
    |
    +-- derive_hash (0x401AC0) — SHA-256-like, writes 32 bytes to A1
    |   +-- [UBSan: signed overflow — modular additions]
    |   +-- [Callgrind: 8.3% of total]
    |
    v
expand_key (0x401C12) — reads A1, writes to A5+20 (round keys)
    |
    v
encrypt_block (0x401C7E) — reads A5+20 at each call (14 rounds)
    +-- [Callgrind: 65% of total — crypto hotspot]
```

### IV Buffer — Block A2 (16 bytes)

**Identification:**

| Source | Observation | Conclusion |  
|--------|-------------|------------|  
| Memcheck | 16-byte block, still reachable, allocated by `0x401B45` | Persistent 16-byte structure |  
| Memcheck | "Conditional jump or move depends on uninitialised value(s) at 0x401C7E" — origin: allocation at `0x401B45` | The 16 bytes are **not all initialized** |  
| MSan | "Uninitialized value created by heap allocation at 0x401B45, stored at 0x401B70, used at 0x401C7E" | Flow: alloc → partial write → use in `encrypt_block` |  
| Callgrind | `0x401B45` called 1 time, self cost 0.1% | Simple allocation |  
| Callgrind | `0x401B70` called 1 time, self cost 0.4% | IV write (little computation) |

**Conclusion — dual confirmation:**
1. 16-byte = 128-bit size = AES block size, corresponding to an IV for CBC or CTR modes (Memcheck size + crypto knowledge).  
2. Memcheck and MSan both report that some bytes are not initialized before use in `encrypt_block` — this confirms it's a sensitive data buffer (the IV) partially filled (only 12 of 16 bytes are written by `prepare_iv`), which also constitutes a **vulnerability**: reduced entropy IV (Memcheck uninitialized + MSan uninitialized).

> **Security note**: a partially uninitialized IV is a real cryptographic flaw. In CBC mode, this reduces IV entropy and can compromise confidentiality. This finding from Memcheck/MSan would be a legitimate finding in a security audit.

### Crypto Context — Block A5 (240 bytes)

**Identification:**

| Source | Observation | Conclusion |  
|--------|-------------|------------|  
| Memcheck | 240-byte block, still reachable (via global `g_ctx`), allocated by `0x401C30` | Persistent global structure |  
| ASan (frame layout) | Read access size 4 at offset 0 | First field: 4 bytes (uint32_t, mode/algo) |  
| Memcheck | Write size 16 at offset 4 in the block | 16-byte field at offset 4 (IV copy) |  
| Memcheck | Write size 32 at offset 20 — from `expand_key` | Start of round keys area |  
| Callgrind | `encrypt_block` reads block A5 at each iteration, cost 65% | Block contains data read in tight loop → central encryption state |  
| MSan | Bytes [236, 240) never initialized | Last 4 bytes = alignment padding |

**Conclusion:** block A5 is the **complete AES context** containing the encryption mode (4 bytes), a working copy of the IV / CBC state (16 bytes), and the round keys expanded from offset 20. The round keys area occupies [20, 236) = 216 bytes, consistent with 14 rounds of AES-256 key schedule producing 15 × 16 = 240 bytes of round keys — but only 216 bytes are actually written according to Memcheck. This discrepancy suggests a slightly different internal layout (round keys might overlap cyclically via modulo). This point will need refinement in Ghidra by examining the `expand_key` loop.

---

## Deliverable 3 — Crypto Chain Functional Graph

### Raw Callgrind Data (64-byte input)

```
callgrind_annotate --inclusive=yes 02_callgrind_64.out
```

Result sorted by inclusive cost:

```
Ir (inclusive)    Function
--------------    ---------------------
  2,847,391      0x4012E8  [main]                  100.0%
  2,614,205      0x401DA1  [process_file]           91.8%
  1,851,230      0x401C7E  [encrypt_block]          65.0%
    498,712      0x401C12  [expand_key]             17.5%
    236,445      0x401AC0  [derive_hash]             8.3%
     67,891      0x401B89  [derive_key wrapper]      2.4%
     43,210      0x401E23  [write_block]             1.5%
     38,990      0x401C80  [read_block]              1.4%
     12,450      0x401B45  [prepare_iv]              0.4%
      8,230      0x4019F0  [init_io]                 0.3%
      5,100      0x401C30  [init_aes_ctx]            0.2%
      3,200      0x401F10  [cleanup]                 0.1%
```

### Consolidated Graph

```
main (0x4012E8) -------------------------------------------- Incl: 100%, Self: 1.5%
|
+---> init_io (0x4019F0) ----------------------------------- Incl: 0.3%, Self: 0.3%
|    +-- malloc(4096) -> A3
|
+---> derive_key (0x401B89) -------------------------------- Incl: 10.7%, Self: 0.1%
|    +-- malloc(32) -> A1 (raw key)
|    +-- malloc(64) -> A7 (salt -- definitely lost, pointer lost)
|    +---> derive_hash (0x401AC0) -------------------------- Incl: 8.3%, Self: 8.3%
|    |    +-- [UBSan: signed overflow x12 -- hash rounds]
|    |    +-- [Callgrind: inner loop 64 iterations -> SHA-256]
|    |    +-- Writes 32 bytes to A1
|    +-- free(A8) (temp HMAC buffer)
|
+---> prepare_iv (0x401B45) -------------------------------- Incl: 0.4%, Self: 0.4%
|    +-- malloc(16) -> A2 (IV)
|    +-- Writes 12 of 16 bytes (3 x memcpy of 4 bytes)
|    +-- [MSan: 4 bytes [12..15] uninitialized in A2]
|
+---> init_aes_ctx (0x401C30) ------------------------------ Incl: 0.2%, Self: 0.2%
|    +-- malloc(240) -> A5 (AES context)
|
+---> expand_key (0x401C12) -------------------------------- Incl: 17.5%, Self: 17.5%
|    +-- Reads A1 (32-byte key)
|    +-- Writes to A5+20 (round keys)
|    +-- [Callgrind: 14-iteration loop -> AES-256 key schedule]
|
+---> process_file (0x401DA1) ------------------------------ Incl: 91.8%, Self: 0.4%
|    |
|    |   +---- Loop: 5 iterations (4 data + 1 padding) ----+
|    |   |                                                  |
|    +---+> read_block (0x401C80) -------------------- Self: 1.4%
|    |   |   +-- read() -> fills A3 (4096 bytes)
|    |   |
|    +---+> encrypt_block (0x401C7E) -- * HOTSPOT -- Self: 65.0%
|    |   |   +-- Reads A5+20 (round keys) at each call
|    |   |   +-- Reads A5+4 (iv_state) for CBC chaining
|    |   |   +-- [Callgrind: inner loop 14 iterations -> 14 rounds]
|    |   |   +-- [Callgrind: sub-loop 16 iterations -> 16 bytes]
|    |   |   +-- [UBSan: signed overflow in rounds]
|    |   |   +-- [Memcheck: conditional jump on uninitialized A2]
|    |   |
|    +---+> write_block (0x401E23) -------------------- Self: 1.5%
|    |   |   +-- malloc(128) -> A4 (output buffer)
|    |   |   +-- write() -> output file
|    |   |   +-- free(A4)
|    |   |
|    |   +--------------------------------------------------+
|    |
|    +-- [Callgrind: encrypt_block called 5x for 64-byte input
|         -> 4 blocks of 16 bytes + 1 PKCS7 padding block = 5 calls]
|
+---> cleanup (0x401F10) ----------------------------------- Incl: 0.1%, Self: 0.1%
     +-- free(A3) -- only buffer explicitly freed
     [A1, A2, A5 still reachable; A7 definitely lost]
```

### Algorithm Identification

The clues converge toward **AES-256-CBC**:

| Clue | Source | Confirmation |  
|------|--------|-------------|  
| 32-byte key (256 bits) | Memcheck, block A1 | AES-**256** |  
| 16-byte IV (128 bits) | Memcheck, block A2 | IV-based mode (CBC, CTR, OFB...) |  
| 14 iterations in `expand_key` | Callgrind jumps | AES-256 = 14 rounds |  
| Sub-loop of 16 in `encrypt_block` | Callgrind | AES block = 16 bytes |  
| 5 calls to `encrypt_block` for 64-byte input | Callgrind calls | 64 / 16 = 4 data blocks + 1 PKCS7 padding |  
| iv_state read at each block in `encrypt_block` | Memcheck + Callgrind | **CBC** mode (chaining via XOR with previous block) |  
| 240-byte context (round keys + IV state) | Memcheck, block A5 | AES-256 expanded key + metadata |

---

## Deliverable 4 — Reconstructed C Structures

### `cipher_ctx` Structure (Block A5, 240 bytes)

```c
/*
 * Reconstructed structure: cipher_ctx
 * Total size: 240 bytes (confirmed Memcheck: still reachable, 240 bytes)
 * Allocated by: init_aes_ctx (0x401C30)
 * Filled by: main (mode + IV), expand_key (round keys)
 * Used by: encrypt_block (0x401C7E) at each iteration
 */
struct cipher_ctx {
    /* Offset 0, size 4 -- encryption mode (e.g.: 1 = CBC, 2 = CTR)
     * Source: ASan read size 4 at offset 0 in encrypt_block
     * Source: Callgrind -- read 1 time per encrypt_block call (dispatch) */
    uint32_t  mode;

    /* Offset 4, size 16 -- working copy of IV / CBC state
     * Source: Memcheck write size 16 at offset 4 from prepare_iv/main
     * Source: Memcheck read size 16 at offset 4 in encrypt_block
     * Note: updated at each block (CBC chaining -- current state
     *       is the last produced ciphertext) */
    uint8_t   iv_state[16];

    /* Offset 20, size 216 -- AES-256 round keys (expansion area)
     * Source: Memcheck write size 32 at offset 20 from expand_key (first 32 bytes)
     * Source: Callgrind -- expand_key iterates 14 times (AES-256 key schedule)
     * Source: encrypt_block reads this area at each round (14 accesses per block)
     * Note: 14 rounds -> 15 round keys x 16 bytes = 240 theoretical bytes,
     *       but expansion uses a cyclic index modulo 216.
     *       Point to verify in Ghidra. */
    uint8_t   round_keys[216];

    /* Offset 236, size 4 -- padding / unused
     * Source: MSan -- bytes [236, 240) never initialized
     * Hypothesis: alignment padding imposed by malloc or the developer */
    uint8_t   _padding[4];

};  /* Total: 4 + 16 + 216 + 4 = 240 bytes OK */
```

### `output_block` Structure (Block A4, 128 bytes)

```c
/*
 * Reconstructed structure: output_block
 * Total size: 128 bytes (confirmed Memcheck: alloc/free in write_block)
 * Allocated and freed by: write_block (0x401E23 / 0x401E80) -- 1 alloc per encrypted block
 * Instances per execution: = number of blocks (5 for 64-byte input)
 */
struct output_block {
    /* Offset 0, size 8 -- output block header
     * Source: Memcheck -- first 8 bytes are always initialized
     * Source: Memcheck syscall write -- these 8 bytes are written first
     * Hypothesis: payload size (uint32_t) + flags/padding (uint32_t) */
    uint32_t  payload_size;
    uint32_t  flags;

    /* Offset 8, size 120 -- encrypted payload
     * Source: Memcheck -- "Syscall param write(buf) points to uninitialised
     *         byte(s), Address is 8 bytes inside block of size 128"
     * Note: only the first 16 bytes of payload are actual ciphertext.
     *       The remaining 104 bytes are never written by the program
     *       (fwrite sends all 128 bytes) -> explains the Memcheck error
     *       about writing uninitialized data. */
    uint8_t   ciphertext[120];

};  /* Total: 4 + 4 + 120 = 128 bytes OK */
```

### `raw_key_t` Type (Block A1, 32 bytes)

```c
/*
 * Reconstructed type: raw_key_t
 * Size: 32 bytes (confirmed Memcheck: still reachable, 32 bytes)
 * Allocated by: derive_key (0x401B89)
 * Written by: derive_hash (0x401AC0) -- SHA-256-like derivation
 * Read by: expand_key (0x401C12) -- expansion into round keys
 * Never freed -- pointer accessible in main's frame at exit
 */
typedef uint8_t raw_key_t[32];  /* AES-256 key derived from password */
```

### `iv_t` Type (Block A2, 16 bytes)

```c
/*
 * Reconstructed type: iv_t
 * Size: 16 bytes (confirmed Memcheck: still reachable, 16 bytes)
 * Allocated by: prepare_iv (0x401B45)
 * Partially written by: 0x401B70 (12 of 16 bytes initialized:
 *     3 x memcpy of 4 bytes for offsets [0..3], [4..7], [8..11])
 * Copied to: cipher_ctx.iv_state (offset 4 of A5)
 * Never freed -- pointer accessible in main's frame at exit
 *
 * WARNING VULNERABILITY: 4 bytes [12..15] of the IV are not initialized
 *    (confirmed Memcheck + MSan). Reduced entropy, partially
 *    predictable IV -- uninitialized bytes come from the heap and
 *    contain residues from previous allocations.
 */
typedef uint8_t iv_t[16];  /* AES-CBC IV -- WARNING: partially uninitialized */
```

---

## Summary — Sensitive Data Flow (ACRF step F)

```
                        +----------------------------+
                        |   argv[4] = password       |
                        +-------------+--------------+
                                      |
                                      v
                        +----------------------------+
                        |  read_password (0x4018A0)  |
                        |  A6 = malloc(1024)         |
                        |  -> copies the password    |
                        |  -> free(A6) after use     |
                        +-------------+--------------+
                                      |
                      +---------------+---------------+
                      v                               v
        +------------------------+       +------------------------+
        | derive_key (0x401B89)  |       | prepare_iv (0x401B45)  |
        | A1 = malloc(32) key    |       | A2 = malloc(16) IV     |
        | A7 = malloc(64) salt   |       | 3 x memcpy(4) -> 12/16|
        | A8 = malloc(32) tmp    |       | WARNING [12..15] uninit|
        +-----------+------------+       +-----------+------------+
                    |                                |
                    v                                |
        +------------------------+                   |
        |derive_hash (0x401AC0)  |                   |
        | SHA-256-like           |                   |
        | 64 internal rounds     |                   |
        | Writes 32 bytes -> A1  |                   |
        | [UBSan: overflow]      |                   |
        +-----------+------------+                   |
                    |                                |
                    v                                v
        +------------------------------------------------+
        |          init_aes_ctx (0x401C30)               |
        |          A5 = malloc(240) context              |
        |          A5.mode = CBC (offset 0, 4 bytes)     |
        |          A5.iv_state = copy of A2 (offset 4)   |
        +------------------------+-----------------------+
                                 |
                                 v
        +------------------------------------------------+
        |          expand_key (0x401C12)                 |
        |          Reads A1 (32 bytes -- raw key)        |
        |          14 rounds of key schedule             |
        |          Writes round keys to A5+20            |
        |          [Callgrind: 17.5%]                    |
        +------------------------+-----------------------+
                                 |
                                 v
        +------------------------------------------------+
        |          process_file (0x401DA1)               |
        |                                                |
        |    +-- Loop (5x for 64-byte input) ---------+  |
        |    |    4 data blocks + 1 padding block     |  |
        |    |                                        |  |
        |    +---> read_block -- read(A3) ----------+-+  |
        |    |       |                              | |  |
        |    |       v                              | |  |
        |    +---> encrypt_block * 65%              | |  |
        |    |  |  Reads A5.round_keys (14 rounds)  | |  |
        |    |  |  Reads A5.iv_state (CBC chaining)  | |  |
        |    |  |  XOR plaintext xor iv_state        | |  |
        |    |  |  14 rounds (sub + perm + XOR rk)   | |  |
        |    |  |  Update A5.iv_state = ciphertext   | |  |
        |    |  +------------+---------------------+-+  |
        |    |               v                     |    |
        |    +---> write_block (A4 = 128 bytes)    |    |
        |    |       |  header (8 bytes) + ct (16) |    |
        |    |       |  WARNING 104 uninit bytes   |    |
        |    |       +--> write() -> output.enc    |    |
        |    |                                     |    |
        |    +-------------------------------------+    |
        +------------------------------------------------+
                                 |
                                 v
        +------------------------------------------------+
        |          cleanup (0x401F10)                    |
        |          free(A3) -- only buffer freed         |
        |          A1, A2 still reachable (main locals)  |
        |          A5 still reachable (global g_ctx)     |
        |          A7 definitely lost (ptr lost)         |
        +------------------------------------------------+
```

---

## Transfer to Ghidra — Proposed Renames

| Address | Proposed name | Justification |  
|---------|---------------|---------------|  
| `0x4012E8` | `main` | Entry point, inclusive cost 100%, self cost ~1.5% |  
| `0x4018A0` | `read_password` | Allocates/frees A6 (1024), reads from argv |  
| `0x4019F0` | `init_io` | Allocates A3 (4096), file read buffer |  
| `0x401A20` | `generate_salt` | Allocates A7 (64), salt for derivation |  
| `0x401AC0` | `derive_hash_sha256` | Derivation hotspot, 64 internal iterations, UBSan overflows |  
| `0x401B45` | `prepare_iv` | Allocates A2 (16), partially uninitialized IV (12/16 bytes) |  
| `0x401B89` | `derive_key` | Orchestrates derivation, allocates A1 (32) |  
| `0x401C12` | `aes256_expand_key` | Reads A1, writes A5+20, 14 key schedule iterations |  
| `0x401C30` | `init_aes_ctx` | Allocates A5 (240), global AES context |  
| `0x401C7E` | `aes256_encrypt_block` | Hotspot 65%, 14 rounds x 16 bytes, reads A5 |  
| `0x401C80` | `read_block` | Reads from source file into A3 |  
| `0x401DA1` | `process_file` | Read/encrypt/write loop orchestrator, 5 iterations |  
| `0x401E23` | `write_block` | Allocates A4 (128), writes header + ciphertext |  
| `0x401F10` | `cleanup` | Frees A3 only, does not free crypto buffers |

---

## Self-assessment Checklist — Result

- [x] **At least two crypto blocks identified** — A1 (32-byte key), A2 (16-byte IV), A5 (240-byte context), A7 (64-byte salt) = four blocks identified.  
- [x] **Key flow traced end-to-end** — password -> read_password -> derive_key -> derive_hash -> A1 -> expand_key -> A5.round_keys -> encrypt_block.  
- [x] **Graph distinguishing init / processing / finalization** — init (0x4018A0 -> 0x401C30), processing (0x401DA1 loop of 5 blocks), finalization (0x401F10).  
- [x] **Each field justified by at least one source** — cipher_ctx: 4 fields, each with 2+ sources (Memcheck + ASan or Callgrind).  
- [x] **Two inputs tested** — 64 bytes and 512 bytes, confirming fixed sizes and block count scaling (5 vs 33).  
- [x] **Ready to rename in Ghidra** — 14 functions with identified names and roles.

---

⏭️
