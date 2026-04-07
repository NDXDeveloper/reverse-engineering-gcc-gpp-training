🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 34 Checkpoint

## Analyze a stripped Go binary, recover functions and reconstruct the logic

> **Spoilers** — Only consult this document after attempting the checkpoint yourself.

---

## Objective 1 — Triage and Identification

### Compiler Version

```bash
$ strings crackme_go_strip | grep -oP 'go1\.\d+\.\d+'
go1.22.1
```

The exact version depends on your installation. The important thing is to confirm ≥ 1.17, which means register-based ABI (section 34.2).

### Binary Characteristics

```bash
$ file crackme_go_strip
crackme_go_strip: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),  
statically linked, Go BuildID=..., stripped  

$ ls -lh crackme_go_strip
-rwxr-xr-x 1 user user 1.8M ... crackme_go_strip

$ ldd crackme_go_strip
        not a dynamic executable

$ checksec --file=crackme_go_strip
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE
```

**Triage summary**: 64-bit ELF binary, statically linked (typical of Go), stripped (no `.symtab` or DWARF), about 1.8 MB for a simple program (embedded Go runtime). NX enabled, no PIE or canary — minimal protections. Go compilation ≥ 1.17 implies the register-based ABI.

### Relevant Strings

```bash
$ strings -n 6 crackme_go_strip | grep -v '/usr/local/go' \
    | grep -v 'runtime\.' | grep -v 'internal/' \
    | grep -iE 'valid|check|bravo|usage|format|key|order'
```

Strings are merged in `.rodata` (section 34.5), but filtering reveals fragments like `checksum`, `Bravo, reverser`, `invalid format`, `XXXX-XXXX`, confirming a key validation program. We also spot `order constraint` and `cross verification`, suggesting multiple validation steps.

---

## Objective 2 — Symbol Recovery

### Extraction with GoReSym

```bash
$ GoReSym -t -d -p crackme_go_strip > metadata.json

$ jq '.TabMeta' metadata.json
{
  "VA": ...,
  "Version": "1.20",
  "Endian": "LittleEndian",
  "CpuQuantum": 1,
  "CpuWordSize": 8
}

$ jq '.UserFunctions | length' metadata.json
11

$ jq '[.UserFunctions[], .StdFunctions[]] | length' metadata.json
2341
```

11 user functions out of approximately 2,300 total functions — the runtime and stdlib represent over 99% of the binary.

### `main` Package Functions

```bash
$ jq -r '.UserFunctions[] | select(.PackageName=="main")
    | "\(.FullName)\t0x\(.Start | tostring)"' metadata.json
```

| Function | Address (example) |  
|---|---|  
| `main.main` | `0x497A00` |  
| `main.parseKey` | `0x497520` |  
| `main.hexVal` | `0x4976E0` |  
| `main.validateGroups` | `0x497740` |  
| `main.validateGroups.func1` | `0x497880` |  
| `main.validateGroups.func2` | `0x4978E0` |  
| `main.validateCross` | `0x497900` |  
| `main.validateOrder` | `0x497960` |  
| `main.(*ChecksumValidator).Validate` | `0x4979C0` |

Addresses vary depending on compiler version and environment. The `.func1` and `.func2` functions are anonymous closures launched as goroutines in `validateGroups` (section 34.2): `.func1` executes a group's validation, `.func2` waits for all goroutines to finish then closes the channel.

---

## Objective 3 — Import into Ghidra and ABI Identification

### Symbol Import

Run the `apply_goresym.py` script (section 34.4) in Ghidra. After execution, the Symbol Tree shows Go names in the Listing.

### ABI Identification

Let's examine the prologue of `main.hexVal` (small function, easy to read):

```asm
main.hexVal:
    CMP     RSP, [R14+0x10]        ; stack check (g.stackguard0)
    JBE     .morestack
    SUB     RSP, 0x10
    MOV     [RSP+0x08], RBP
    LEA     RBP, [RSP+0x08]
    ; The first argument is in RAX (not on the stack)
    MOVZX   ECX, AL                ; uses AL = low byte of RAX
    CMP     ECX, 0x30              ; compare with '0'
    ...
```

**Evidence of register-based ABI**:

1. `R14` is used as goroutine pointer `g` → Go ≥ 1.17.  
2. The first argument is read from `RAX` (`AL`), not from `[RSP+offset]` → register convention.  
3. The preamble `CMP RSP, [R14+0x10]; JBE` is the characteristic Go stack growth check.

**Conclusion**: register-based ABI, argument registers `RAX`, `RBX`, `RCX`, `RDI`, `RSI`, `R8`–`R11` (section 34.2).

---

## Objective 4 — Type Reconstruction

### Type Extraction with GoReSym

```bash
$ jq '.Types[] | select(.PackageName=="main")' metadata.json
```

Reconstructed types:

```go
// --- Interface ---
type Validator interface {
    Validate(group []byte, index int) bool
}

// --- Structs ---
type ChecksumValidator struct {
    ExpectedSums map[int]uint16    // offset +0x00, 8 bytes (pointer to hmap)
}

type validationResult struct {
    Index int                      // offset +0x00, 8 bytes
    OK    bool                     // offset +0x08, 1 byte
    // padding 7 bytes → total size: 16 bytes
}
```

`ChecksumValidator` is the only type implementing the `Validator` interface. The corresponding itab binds `*ChecksumValidator` to `Validator`, with `fun[0]` pointing to `main.(*ChecksumValidator).Validate`.

### Identified Dynamic Data Structures

By searching for runtime calls in `main.*` function code:

| Runtime call | Location | Data structure |  
|---|---|---|  
| `runtime.makemap` | `main.main` | `map[int]uint16` (expectedSums) |  
| `runtime.makechan` | `main.validateGroups` | `chan validationResult` (buffered, cap=4) |  
| `runtime.chansend1` | `main.validateGroups.func1` | send on channel |  
| `runtime.chanrecv1` | `main.validateGroups` | receive from channel |  
| `runtime.newproc` | `main.validateGroups` | goroutine launch (×4, plus the closing goroutine) |  
| `runtime.growslice` | `main.parseKey` | construction of `[][2]byte` slice |

---

## Objective 5 — Validation Logic Analysis

### Call Graph from `main.main`

```
main.main
 ├─► main.parseKey            (key parsing)
 ├─► runtime.makemap          (expectedSums construction)
 ├─► main.validateGroups      (step 1: per-group checksum)
 │    ├─► runtime.makechan    (buffered channel of capacity 4)
 │    ├─► runtime.newproc ×4  (launch 4 validation goroutines)
 │    │    └─► main.(*ChecksumValidator).Validate  (via itab dispatch)
 │    ├─► runtime.newproc     (channel-closing goroutine)
 │    └─► runtime.chanrecv1   (result collection loop)
 ├─► main.validateOrder       (step 2: ascending order)
 └─► main.validateCross       (step 3: global XOR)
```

### Step 1 — Per-Group Checksum (`validateGroups` → `ChecksumValidator.Validate`)

Decompiling `main.(*ChecksumValidator).Validate`:

```
For each byte b in the group (2 bytes):
    xored = b XOR magic[i % 4]
    sum += xored

Compare sum with ExpectedSums[group_index]
```

**Extracted constants:**

The `magic` array can be found in `.rodata` or by setting a breakpoint on the Validate function:

```bash
# In GDB — breakpoint on Validate, inspect memory accesses
break main.(*ChecksumValidator).Validate  
run 1111-2222-3333-4444  
# Step through, observe bytes read for XOR
```

```
magic = { 0xDE, 0xAD, 0xC0, 0xDE }
```

Since each group is 2 bytes, only `magic[0] = 0xDE` and `magic[1] = 0xAD` are used.

The `expectedSums` map is constructed in `main.main` with calls to `runtime.mapassign`. By setting a breakpoint on `runtime.mapassign_fast64` and inspecting the arguments:

```
expectedSums = {
    0: 0x010E   (270)
    1: 0x0122   (290)
    2: 0x0136   (310)
    3: 0x013E   (318)
}
```

**Formula**: for group `i` with bytes `(g0, g1)`:

```
(g0 XOR 0xDE) + (g1 XOR 0xAD) == expectedSums[i]
```

### Step 2 — Ascending Order (`validateOrder`)

Decompilation of `main.validateOrder`:

```
For each group (i=0 to 3):
    val = g[0]  (first byte of group)
    If val <= prev: return false
    prev = val

Return true
```

**Constraint**: the first byte of each group must be strictly ascending.

```
g0[0] < g1[0] < g2[0] < g3[0]
```

### Step 3 — Cross XOR (`validateCross`)

Decompilation of `main.validateCross`:

```
globalXOR = 0  
For each group:  
    For each byte b in the group:
        globalXOR ^= b

Return globalXOR == 0x42
```

**Constraint**: the XOR of all 8 key bytes must equal `0x42`.

---

## Objective 6 — Produce a Valid Key

### Manual Resolution

We seek 4 groups of 2 bytes `(g0, g1)` simultaneously satisfying:

**Constraint C1** (checksum) — for each group `i`:

```
(gi[0] ⊕ 0xDE) + (gi[1] ⊕ 0xAD) = T[i]
with T = {270, 290, 310, 318}
```

**Constraint C2** (order):

```
g0[0] < g1[0] < g2[0] < g3[0]
```

**Constraint C3** (global XOR):

```
g0[0] ⊕ g0[1] ⊕ g1[0] ⊕ g1[1] ⊕ g2[0] ⊕ g2[1] ⊕ g3[0] ⊕ g3[1] = 0x42
```

**Approach**: for each group, set `a = gi[0] ⊕ 0xDE` and `b = gi[1] ⊕ 0xAD`, with `a + b = T[i]`. Choose `a` freely (0 ≤ a ≤ min(T[i], 255), and `b = T[i] − a` ≤ 255), then compute `gi[0] = a ⊕ 0xDE` and `gi[1] = b ⊕ 0xAD`.

First solve C1 + C2 by choosing `a` values that produce ascending first bytes, then adjust a single byte to satisfy C3.

| Group | T | chosen a | b = T−a | g[0] = a⊕0xDE | g[1] = b⊕0xAD | g[0] decimal |  
|---|---|---|---|---|---|---|  
| 0 | 270 | 200 | 70 | 0x16 | 0xEB | 22 |  
| 1 | 290 | 230 | 60 | 0x38 | 0x91 | 56 |  
| 2 | 310 | 135 | 175 | 0x59 | 0x02 | 89 |  
| 3 | 318 | 160 | 158 | 0x7E | 0x33 | 126 |

**C2 check**: 22 < 56 < 89 < 126 ✓

**C3 check**:

```
0x16 ⊕ 0xEB = 0xFD
0xFD ⊕ 0x38 = 0xC5
0xC5 ⊕ 0x91 = 0x54
0x54 ⊕ 0x59 = 0x0D
0x0D ⊕ 0x02 = 0x0F
0x0F ⊕ 0x7E = 0x71
0x71 ⊕ 0x33 = 0x42 ✓
```

### Valid Key

```
16EB-3891-5902-7E33
```

```bash
$ ./crackme_go_strip 16EB-3891-5902-7E33

   ╔══════════════════════════════════════════╗
   ║   crackme_go — Chapter 34                ║
   ║   RE Training — GNU Toolchain            ║
   ╚══════════════════════════════════════════╝

[*] Verifying key: 16EB-3891-5902-7E33
[✓] Group checksums valid.
[✓] Order constraint satisfied.
[✓] Cross verification OK.

══════════════════════════════════════
  🎉  Valid key! Congratulations, reverser!
══════════════════════════════════════
```

### Python Keygen

```python
#!/usr/bin/env python3
"""
Keygen for crackme_go — Chapter 34  
Solves the three constraints via exhaustive search on degrees  
of freedom (one 'a' parameter per group).  
"""

import random

MAGIC_0 = 0xDE  
MAGIC_1 = 0xAD  
TARGETS = {0: 270, 1: 290, 2: 310, 3: 318}  
CROSS_XOR = 0x42  

def solve():
    # For each group, enumerate valid (g0, g1) pairs for C1
    candidates = {}
    for idx, target in TARGETS.items():
        candidates[idx] = []
        for a in range(max(0, target - 255), min(target, 255) + 1):
            b = target - a
            g0 = a ^ MAGIC_0
            g1 = b ^ MAGIC_1
            candidates[idx].append((g0, g1))

    # Search for a combination satisfying C2 (order) and C3 (global XOR)
    solutions = []
    for c0 in candidates[0]:
        for c1 in candidates[1]:
            if c1[0] <= c0[0]:        # C2: ascending first byte
                continue
            for c2 in candidates[2]:
                if c2[0] <= c1[0]:
                    continue
                for c3 in candidates[3]:
                    if c3[0] <= c2[0]:
                        continue
                    # C3: global XOR
                    xor = 0
                    for g0, g1 in [c0, c1, c2, c3]:
                        xor ^= g0
                        xor ^= g1
                    if xor == CROSS_XOR:
                        solutions.append((c0, c1, c2, c3))

    return solutions

def format_key(groups):
    parts = []
    for g0, g1 in groups:
        parts.append(f"{g0:02X}{g1:02X}")
    return "-".join(parts)

if __name__ == "__main__":
    solutions = solve()
    print(f"[*] {len(solutions)} valid key(s) found.\n")

    if solutions:
        # Display a few examples
        shown = random.sample(solutions, min(5, len(solutions)))
        for groups in shown:
            print(f"    {format_key(groups)}")

        print(f"\n[*] Reference key: {format_key(solutions[0])}")
```

This brute-force keygen is nearly instant: the effective search space is very small thanks to C2 pruning (ascending first bytes).

---

## Validated Skills Summary

| Objective | Sections used | Key skill |  
|---|---|---|  
| 1 — Triage | 34.1, 34.5 | Identify a stripped Go binary and filter noise |  
| 2 — Symbols | 34.4 | Extract functions via `gopclntab` / GoReSym |  
| 3 — Ghidra + ABI | 34.2, 34.4 | Distinguish Go ABI from System V, spot R14 and stack check |  
| 4 — Types | 34.3, 34.6 | Reconstruct structs, interfaces and identify runtime structures |  
| 5 — Logic | 34.1–34.5 | Trace call graph, identify goroutines and constraints |  
| 6 — Keygen | Synthesis | Model constraints and produce a valid key |

---

⏭️
