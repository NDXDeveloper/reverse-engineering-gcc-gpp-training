🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)


# 14.4 — Leveraging sanitizer reports to understand internal logic

> 🎯 **Goal of this section**: Formalize a systematic methodology to transform raw outputs from Valgrind and sanitizers into verifiable reverse-engineering hypotheses — structure reconstruction, sensitive buffer identification, data-flow mapping, and understanding an unknown program's memory management.

---

## From tool to intelligence: changing perspective

In the three previous sections, we learned to use Memcheck, Callgrind, ASan, UBSan, and MSan. Each tool produces its own reports, in its own format, with its own error categories. Taken individually, each report is a list of technical problems — invalid reads, leaks, overflows, UB.

This section's objective is to go beyond this fragmented reading to adopt a **systemic approach**: each report is not an end in itself, it's a piece of a puzzle. By cross-referencing reports from multiple tools on the same binary, with different inputs, you progressively build a **mental model of the program** — its data structures, execution flow, business logic.

The reverse engineer doesn't seek to fix the bugs reported by sanitizers. They **exploit** them as windows open to the program's interior.

---

## The ACRF method: four steps to exploit a report

To structure report exploitation, we propose the **ACRF** method — Allocations, Channels, Relations, Flows. Each letter corresponds to a category of information to systematically extract.

### A — Allocations: build the memory inventory

The first pass over reports consists of **inventorying all dynamic allocations** revealed by the tools. Each Memcheck or ASan report mentions allocated blocks with their size, address, and call stack at allocation time. Compile this information into a working table.

**Information sources:**

- Memcheck `HEAP SUMMARY` and leak reports (`--leak-check=full --show-leak-kinds=all`)  
- ASan error reports (each error mentions the concerned block with its size and allocator)  
- Callgrind (calls to `malloc`/`calloc`/`realloc` with their invocation counts)

**What you build:**

A table like this one, called the **allocation map**:

| ID | Size | Allocation function | Alloc count | Free function | Memcheck category | Hypothesis |  
|----|------|---------------------|-------------|--------------|-------------------|-----------|  
| A1 | 32 | `0x401B89` | 1 | — (leak) | definitely lost | AES-256 key |  
| A2 | 16 | `0x401B45` | 1 | — (leak) | definitely lost | AES IV (128 bits) |  
| A3 | 1024 | `0x4019F0` | 1 | `0x401F10` | — (freed) | File read buffer |  
| A4 | 128 | `0x401DA1` | N (= num blocks) | `0x401E80` | — (freed) | Encrypted output buffer |  
| A5 | 48 | `0x401C30` | 1 | — (leak) | still reachable | Global crypto context |

Each row is a **data structure** of the program. The size is the structure's exact size. The allocation function is probably a constructor or initialization function. The free function is a destructor or cleanup function. The Memcheck category (definitely lost, still reachable) tells us about lifetime: "still reachable" blocks are persistent global structures, "definitely lost" blocks are temporary structures whose pointer was lost.

> 💡 **RE tip** — The allocation count for a block of a given size is a strong structural indicator. If a 128-byte block is allocated N times (where N matches the number of blocks in the input file), you're probably looking at a per-block processing buffer. If a 48-byte block is allocated once, it's a global context initialized at startup.

### C — Channels: trace execution routes

The second pass exploits Callgrind and error-report call stacks to reconstruct the program's **execution paths**.

**Information sources:**

- Callgrind call graph (KCachegrind or `callgrind_annotate`)  
- Call stacks (stack traces) from each Memcheck, ASan, UBSan, MSan report  
- Callgrind with `--collect-jumps=yes` (conditional jumps taken/not taken)

**What you build:**

An **annotated call graph** combining Callgrind information (costs, call counts) with addresses from error reports (allocation functions, faulting functions). This graph isn't a simple call tree — it's an enriched functional map.

Let's take our `ch14-crypto` example. By combining call stacks from all reports:

```
main (0x4012E8)
│
├──► init_cipher_ctx (0x4019F0)
│    ├── malloc(1024) → A3 (file buffer)
│    ├── malloc(48)   → A5 (crypto context)
│    └── malloc(32)   → A1 (key)
│
├──► prepare_iv (0x401B45)
│    ├── malloc(16)   → A2 (IV)
│    └── [MSan: partially writes to A2]
│
├──► process_file (0x401DA1)        ← called 1x, Callgrind cost: 78%
│    ├── read_block (0x401C80)      ← called N times
│    │   └── read() syscall
│    ├── encrypt_block (0x401C7E)   ← called N times, hotspot: 65%
│    │   ├── [UBSan: signed overflow in round loop]
│    │   └── [Memcheck: conditional jump on uninitialised A2]
│    └── write_block (0x401E23)
│        ├── malloc(128) → A4 (output buffer)
│        ├── write() syscall
│        │   └── [Memcheck: uninitialised bytes in write buffer]
│        └── free(A4)
│
└──► cleanup (0x401F10)
     └── free(A3)
     [A1, A2, A5 never freed → leaks]
```

This graph is the result of **fusing** five information sources: Callgrind for structure and costs, Memcheck for leaks and uninitialized reads, ASan for overflows and frame sizes, UBSan for arithmetic overflows, MSan for uninitialized-data propagation. No single tool gives this overview. It's their combination that produces an exploitable map.

### R — Relations: identify data structures

The third pass crosses allocation sizes with offsets reported in error reports to **reconstruct the internal layout of structures**.

**Information sources:**

- ASan: "Address is N bytes inside a block of size M" → offset N in a size-M structure  
- ASan: stack frame object layout → size and position of each local variable  
- Memcheck: "Address is N bytes after a block of size M" → out-of-bounds access, confirms block size  
- MSan: "Uninitialized value was stored to memory at offset N" → uninitialized field at offset N

**What you build:**

**Structure sketches** you can later transpose into Ghidra as custom types.

Take block A5 (240 bytes, crypto context, `still reachable`). If reports give us:

- ASan reports a size-4 read at offset 0 of the block → first 4-byte field (a `uint32_t`, probably a mode identifier).  
- Memcheck reports a size-16 write at offset 4 → 16-byte field starting at offset 4 (IV copy into the context).  
- Memcheck reports a size-32 write at offset 20 from `expand_key` → start of the round-keys zone.  
- MSan reports bytes [236, 240) are never initialized → the last 4 bytes of the block aren't used (alignment padding).

We reconstruct:

```c
// Hypothetical structure for block A5 (240 bytes)
struct cipher_ctx {              // total size: 240 bytes
    uint32_t  mode;              // offset 0,   size 4  — encryption mode (CBC, CTR…)
    uint8_t   iv_state[16];     // offset 4,   size 16 — working copy of IV / CBC state
    uint8_t   round_keys[216];  // offset 20,  size 216 — AES-256 expanded key
    uint8_t   _padding[4];      // offset 236, size 4  — never initialized (padding)
};
```

This structure is a **hypothesis**. It must be verified in Ghidra by examining the code that accesses the block at the known address. But it's an *informed* hypothesis — you don't start from scratch, you start from concrete constraints imposed by reports.

> 💡 **RE tip** — When reconstructing a structure, note the constraints that define it: "offset 8, size 32: confirmed by Memcheck write size 32, confirmed by ASan block layout". When you transpose this structure into Ghidra, these notes let you distinguish confirmed fields from assumed ones.

### F — Flows: follow data propagation

The fourth pass reconstitutes **data flows** through the program — how data is created, transformed, transmitted, and consumed.

**Information sources:**

- MSan: three-level reports (creation → storage → use) = taint analysis  
- Memcheck: correlation between the function that allocates a block and the one that reads/writes it  
- UBSan: concrete values in overflow reports (ex: "2147483647 + 1") reveal manipulated data  
- Callgrind: the function call order gives the temporal sequence of the flow

**What you build:**

A **data-flow diagram** showing a sensitive datum's path through the program. For a crypto binary, we're particularly interested in the key's flow:

```
Key flow (block A1, 32 bytes):

  init_cipher_ctx (0x4019F0)
       │
       │  malloc(32) → A1 allocated but uninitialized
       │  [MSan: uninitialized value created]
       ▼
  derive_key (0x401B89)
       │
       │  Reads the password from argv[2]
       │  Writes 32 bytes to A1 (PBKDF2 derivation?)
       │  [MSan: uninitialized value stored → now initialized]
       ▼
  expand_key (0x401C12)
       │
       │  Reads A1 (32 bytes)
       │  Writes to A5+8 (expanded_key, 32 bytes)
       │  [Callgrind: this function costs 12% of total]
       ▼
  encrypt_block (0x401C7E)  ← called N times
       │
       │  Reads A5+8 (expanded_key) at each call
       │  Reads the source block from A3 (file buffer)
       │  Writes the encrypted block to A4 (output buffer)
       │  [UBSan: signed overflow in rounds]
       │  [Callgrind: 65% of total cost]
       ▼
  write_block (0x401E23)
       │
       │  Writes A4 to the file descriptor
       │  free(A4)
```

This diagram shows the **key's complete lifecycle**: allocation, derivation from the password, expansion, use in each block, and — notably — absence of freeing at the end (Memcheck leak). In RE, this view allows understanding the program's crypto architecture without ever reading a single assembly instruction.

---

## Integrated application: reconstructing `ch24-crypto`

Let's put the ACRF method into end-to-end practice on our encryption binary. This section describes the complete workflow, from the first Valgrind command to reconstructing a model exploitable in Ghidra.

### Phase 1 — Raw collection

Run all four tools on the same input:

```bash
# Prepare input
echo "The quick brown fox jumps over the lazy dog" > test_input.txt

# 1. Memcheck
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
    --track-fds=yes --log-file=01_memcheck.txt \
    ./ch24-crypto encrypt test_input.txt output.enc MyP@ssw0rd

# 2. Callgrind
valgrind --tool=callgrind --callgrind-out-file=02_callgrind.out \
    --collect-jumps=yes \
    ./ch24-crypto encrypt test_input.txt output.enc MyP@ssw0rd

# 3. ASan + UBSan (requires recompilation)
cd binaries/ch24-crypto/  
make clean  
CFLAGS="-fsanitize=address,undefined -g -O0" make  
ASAN_OPTIONS="halt_on_error=0:log_path=03_asan" \  
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \  
    ./crypto_asan encrypt ../../test_input.txt ../../output_asan.enc MyP@ssw0rd

# 4. MSan (Clang, if available)
clang -fsanitize=memory -fsanitize-memory-track-origins=2 -g -O0 \
    -o crypto_msan crypto.c
MSAN_OPTIONS="halt_on_error=0:log_path=04_msan" \
    ./crypto_msan encrypt ../../test_input.txt ../../output_msan.enc MyP@ssw0rd
```

After this phase, you have four report files plus a Callgrind file.

### Phase 2 — ACRF extraction

Open each report and fill in the method's four tables.

**A — Allocations**: browse `01_memcheck.txt` (`HEAP SUMMARY` section and leaks) and ASan reports. Note each block with its size, allocator, and status.

**C — Channels**: open `02_callgrind.out` in KCachegrind. Identify the high-level functional structure (main → init → process → cleanup). Annotate functions with addresses from error reports.

**R — Relations**: cross access offsets (ASan, Memcheck) with allocation sizes to sketch data structures. Focus on blocks appearing in multiple reports — they're the program's central structures.

**F — Flows**: use MSan reports (if available) to trace uninitialized-data propagation. Complete with Callgrind call order and Memcheck correlations (who allocates, who reads, who writes, who frees).

### Phase 3 — Consolidation

Produce a **synthesis document** summarizing hypotheses, organized in three sections:

**1. Data structure map** — For each identified block, propose a C `struct` with known fields (confirmed by at least two sources) and hypothetical fields (deduced from a single source).

```c
// ============================================
// Reconstructed structures for ch24-crypto
// Sources: Memcheck, ASan, MSan, Callgrind
// ============================================

// Block A1 — 32 bytes — raw key
// Confirmed: size 32 (Memcheck leak + ASan block size)
// Confirmed: allocated by 0x401B89, never freed
// Hypothesis: AES-256 key (32 bytes = 256 bits)
typedef uint8_t raw_key_t[32];

// Block A2 — 16 bytes — IV
// Confirmed: size 16 (Memcheck leak)
// Confirmed: partially uninitialized (MSan)
// Hypothesis: AES-CBC IV (16 bytes = 128 bits = AES block size)
typedef uint8_t iv_t[16];

// Block A5 — 48 bytes — crypto context
// Confirmed: size 48 (Memcheck still reachable)
// Confirmed: 8-byte field at offset 0 (ASan read size 8)
// Confirmed: 32-byte field at offset 8 (Memcheck write size 32)
// Confirmed: bytes [40,48) uninitialized (MSan)
struct cipher_ctx {
    uint64_t  mode;             // offset 0  — confirmed
    uint8_t   expanded_key[32]; // offset 8  — confirmed
    uint8_t   _padding[8];     // offset 40 — uninitialized (MSan)
};

// Block A3 — 1024 bytes — I/O buffer
// Confirmed: size 1024, allocated 1x, freed 1x
// Hypothesis: sequential read buffer for the source file

// Block A4 — 128 bytes — per-block output buffer
// Confirmed: size 128, allocated Nx, freed Nx
// Confirmed: first 8 bytes initialized, rest variable (Memcheck)
// Hypothesis: 8-byte header (block size + flags?) + encrypted payload
struct output_block {
    uint64_t  header;           // offset 0  — always initialized
    uint8_t   ciphertext[120];  // offset 8  — encrypted payload
};
```

**2. Annotated functional graph** — The consolidated call graph (as built in step C), with for each function:

- Its address.  
- Its hypothetical role.  
- Its Callgrind cost (% of total).  
- The blocks it manipulates (reference to table A).  
- Errors reported by sanitizers.

**3. Sensitive data flows** — The flow diagram for each critical datum (key, IV, plaintext, ciphertext), showing how it circulates through the program.

### Phase 4 — Transfer to Ghidra

Open the original binary (non-instrumented) in Ghidra and apply the synthesis results:

**Function renaming** — Navigate to each identified address and rename:

- `0x4019F0` → `init_cipher_ctx`  
- `0x401B89` → `derive_key`  
- `0x401B45` → `prepare_iv`  
- `0x401C12` → `expand_key`  
- `0x401C7E` → `encrypt_block`  
- `0x401DA1` → `process_file`  
- `0x401E23` → `write_block`  
- `0x401F10` → `cleanup`

**Type creation** — In Ghidra's Data Type Manager, create the reconstructed structures (`cipher_ctx`, `output_block`, `raw_key_t`, `iv_t`). Apply them to local variables and parameters of the corresponding functions.

**Comment annotation** — For each function, add a comment summarizing information from dynamic analysis: sizes of manipulated buffers, detected errors, data flows.

The result: when you open the decompiled view of `encrypt_block` in Ghidra, instead of seeing accesses to anonymous numeric offsets (`*(param_1 + 8)`), you see named and typed accesses (`ctx->expanded_key`). Understanding the code goes from a number puzzle to almost natural reading.

---

## Advanced cross-referencing strategies

### Multiple inputs: mapping conditional branches

Analysis with a single input shows only one execution path. To map the program's conditional branches, repeat the analysis with varied inputs and compare results.

**Contrasted-inputs strategy:**

| Input | Objective | What you observe |  
|-------|----------|-----------------|  
| Short valid input | Nominal path | Base graph, base allocations |  
| Long valid input | Volume behavior | Iteration count, allocation scaling |  
| Invalid input (format) | Rejection path | Validation functions, error messages |  
| Empty input | Edge case | Degenerate-case handling, always-called vs conditional functions |  
| Random binary input | Parser robustness | Deep error paths, recovery buffers |  
| Correct vs incorrect password | Authentication branching | Comparison function, decision point |

For each input, run Callgrind and note the **total instruction cost** and **exercised functions**. The comparison is revealing:

```
Valid input:           1,247,893 Ir — functions: A, B, C, D, E, F  
Invalid format input:  45,231 Ir    — functions: A, B, G  
Empty input:           12,108 Ir    — functions: A, H  
```

Functions A and B are called in all cases — they're initialization and initial-parsing functions. Functions C, D, E, F are only called for a valid input — that's the main processing path. G is the format-error handling function. H is the "no input" handling.

This differential approach is the dynamic equivalent of static control-flow analysis — but it only shows actually exercised paths, eliminating noise from dead code and theoretical branches.

### Temporal correlation: error appearance order

Memcheck and ASan reports (with `halt_on_error=0`) list errors in **chronological order of appearance**. This order is information in itself: it reflects the program's execution sequence.

If we observe the following sequence:

1. Allocation of 32 bytes (block A1) — `init_cipher_ctx`  
2. Allocation of 16 bytes (block A2) — `prepare_iv`  
3. Conditional jump on uninitialised A2 — `encrypt_block`  
4. Invalid read, 4 bytes after block A1 — `encrypt_block`  
5. Syscall write with uninitialised bytes — `write_block`

This sequence tells us the program first allocates the key, then the IV, then goes straight to encryption (where both errors on A1 and A2 appear), then writes the result. The encryption phase uses both buffers in an interleaved manner, and the write error propagates uninitialized data from A2 to the output.

> 💡 **RE tip** — Number errors in their order of appearance. This order constitutes a **partial execution trace** of the program. Each error is a confirmed passage point, and the interval between two errors is an execution segment without anomalies (or without detectable anomalies).

---

## Common pitfalls and how to avoid them

### Pitfall 1 — Confusing allocation size with structure size

A `malloc(32)` doesn't necessarily mean the structure is 32 bytes. It could be a 32-byte array, a 28-byte structure with 4 bytes of alignment padding, or an over-allocated buffer.

**Reflex**: cross the allocation size with actual observed accesses. If Memcheck never sees access beyond offset 24 in a 32-byte block, the last 8 bytes are probably padding.

### Pitfall 2 — Over-interpreting false positives

Memcheck and MSan produce false positives, notably uninitialized reads in the libc (optimized `strlen`, `memcpy` reading full machine words).

**Reflex**: use a Memcheck suppression file for known libc errors. Always verify in the disassembly before drawing conclusions.

### Pitfall 3 — Neglecting input impact

The most common error is drawing structural conclusions from a single input.

**Reflex**: always run at least three inputs of different sizes and compare allocation sizes. Fixed-size blocks (key, IV, context) keep the same size regardless of input. Variable-size blocks (read buffers, output buffers) change.

### Pitfall 4 — Ignoring library errors

Some library errors are caused **by the target binary** — a `memcpy` call with an erroneous size, an invalid pointer passed to `printf`, etc.

**Reflex**: before suppressing a library error, look at the complete call stack. If the immediate caller is a target-binary function, the error is relevant.

### Pitfall 5 — Believing absence of errors means absence of bugs

Memcheck only sees exercised paths. ASan doesn't detect intra-block overflows. UBSan doesn't cover all UB types.

**Reflex**: treat clean reports as "no additional information" rather than "no problem". Complement with fuzzing (Chapter 15) to exercise additional paths.

---

## Synthesis document template

To conclude the chapter, here's a document template that structures Valgrind/sanitizer analysis results into an exploitable deliverable for the rest of RE.

```markdown
# Dynamic Analysis Report — [Binary name]

## 1. Identification
- Binary: [path, SHA-256 hash]
- Type: [ELF 64-bit, stripped/non-stripped, PIE/non-PIE]
- Tested inputs: [list of inputs with their objective]
- Tools used: [Memcheck, Callgrind, ASan, UBSan, MSan]

## 2. Allocation map
[Table A — ID, size, allocator, freer, category, hypothesis]

## 3. Functional graph
[Graph C — functions, addresses, Callgrind costs, hypothetical roles]

## 4. Reconstructed structures
[C code of structures R — fields, offsets, confirmation sources]

## 5. Sensitive data flows
[Diagrams F — key flow, plaintext flow, ciphertext flow]

## 6. Anomalies and points of attention
[Unresolved errors, suspect false positives, unexercised paths]

## 7. Recommendations for next steps
[Functions to analyze in priority in Ghidra, suggested fuzzing inputs,
hypotheses to verify by static analysis]
```

This document becomes the **entry point for static analysis**. Rather than opening Ghidra facing anonymous disassembly of thousands of functions, you arrive with a map, names, structures, and targeted hypotheses. The time savings are considerable.

---

## Chapter 14 summary

This chapter covered using Valgrind and sanitizers as dynamic reverse-engineering tools. Let's recap each tool's contributions and the method that unifies them:

| Tool | Main RE contribution |  
|---|---|  
| **Memcheck** | Structure sizes, allocation/free functions, buffer lifecycle, uninitialized reads |  
| **Callgrind** | Call graph, hotspots, iteration counts, algorithm identification by profile |  
| **ASan** | Precise stack-frame layout, overflows with exact offset, complete lifecycle (alloc → free → use-after-free) |  
| **UBSan** | Arithmetic logic (overflows, shifts), clues about data types and algorithms |  
| **MSan** | Complete data flow (taint analysis), uninitialized-value propagation |  
| **ACRF method** | Fusing reports into a structural model exploitable in Ghidra |

The central idea of this chapter is that **a program's errors are windows into its internal structure**. A developer sees a bug report; a reverse engineer sees a treasure map.

---


⏭️ [🎯 Checkpoint: run Valgrind on `ch22-crypto`, identify the key buffers in memory](/14-valgrind-sanitizers/checkpoint.md)
