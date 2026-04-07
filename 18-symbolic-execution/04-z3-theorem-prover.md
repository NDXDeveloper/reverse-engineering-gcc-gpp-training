🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 18.4 — Z3 Theorem Prover — modeling manually extracted constraints

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## Why use Z3 directly?

In Section 18.3, angr did all the work: loading the binary, propagating symbolic expressions, forking at branches, and querying the solver. You never touched Z3 directly — angr handled it via claripy.

But angr isn't always the right answer. There are situations where automatic symbolic execution fails or simply isn't suited:

- The binary is **too large** or too branching for angr to explore in reasonable time.  
- The code of interest represents only a **small fraction** of the program, buried in thousands of unrelated functions.  
- You've already **understood the logic** through static analysis in Ghidra (Chapter 8) and simply want to solve the equation system you extracted.  
- The binary uses **anti-reversing** (Chapter 19) that disrupts angr: self-modifying code, debugger detection, control flow obfuscation.  
- You're working on an **isolated code fragment** — a crypto routine, a license verification algorithm — not a complete program.

In all these cases, the approach is different: you analyze the binary manually (or with a decompiler), **extract the constraints** as mathematical equations, then submit them directly to Z3. It's a hybrid work — half classic reverse engineering, half mathematical modeling — and it's often the most efficient method for complex binaries.

---

## Z3 in brief

Z3 is an **SMT solver** (Satisfiability Modulo Theories) developed by Microsoft Research. "SMT" means it can verify the satisfiability of logical formulas within specific mathematical theories: bounded integer arithmetic (bitvectors), arrays, real numbers, etc.

In simple terms: you describe a constraint system ("`x` XOR `y` must equal `0x1337`, and `x` multiplied by 3 must be less than `0xFFFF`"), and it tells you whether a solution exists. If yes, it gives it to you.

### Installation

Z3 is already installed if you installed angr (it's pulled as a dependency). Otherwise:

```bash
pip install z3-solver
```

> ⚠️ The PyPI package is called `z3-solver`, not `z3`. A package named `z3` exists but it's a different, unrelated project.

### First contact

```python
from z3 import *

# Declare two symbolic integers
x = Int("x")  
y = Int("y")  

# Create a solver
s = Solver()

# Add constraints
s.add(x + y == 42)  
s.add(x - y == 10)  

# Solve
if s.check() == sat:
    m = s.model()
    print(f"x = {m[x]}")   # x = 26
    print(f"y = {m[y]}")   # y = 16
else:
    print("No solution")
```

This is elementary algebra, but the mechanism is exactly the same for constraints on 64-bit bitvectors with XOR, shift, and multiplication operations — except you couldn't solve those by hand.

---

## Bitvectors: the fundamental type for RE

In reverse engineering, you almost never work with abstract mathematical integers (`Int`). You work with fixed-size registers — 8, 16, 32, or 64 bits — where arithmetic **wraps around**. A `uint32_t` equal to `0xFFFFFFFF` plus `1` gives `0x00000000`, not `0x100000000`.

Z3 models this behavior with **bitvectors** (`BitVec`), which reproduce processor arithmetic exactly:

```python
from z3 import *

# 32-bit bitvector named "x"
x = BitVec("x", 32)

# Constant bitvector
magic = BitVecVal(0xDEADBEEF, 32)

# Modular arithmetic (mod 2^32 implicit)
expr = x + BitVecVal(1, 32)   # Overflow handled as on the CPU

# Bitwise operations
expr2 = x ^ magic              # XOR  
expr3 = LShR(x, 16)           # Logical Shift Right  
expr4 = x << 3                 # Shift Left  
expr5 = x & 0xFF              # AND (masking)  
```

### Signed vs unsigned

In x86-64 assembly, the same bit sequence can be interpreted as signed or unsigned — it's the instruction that determines the interpretation (`ja` vs `jg`, `shr` vs `sar`…). Z3 reproduces this distinction:

```python
x = BitVec("x", 32)

# Unsigned comparisons (by default)
UGT(x, 100)    # Unsigned Greater Than  
ULT(x, 100)    # Unsigned Less Than  
UGE(x, 100)    # Unsigned Greater or Equal  
ULE(x, 100)    # Unsigned Less or Equal  

# Signed comparisons
x > 100         # Signed (native Python operator)  
x < 100         # Signed  

# Shift
LShR(x, 4)     # Logical Shift Right (unsigned, inserts 0s)  
x >> 4          # Arithmetic Shift Right (signed, propagates sign bit)  
```

The `LShR` (logical) vs `>>` (arithmetic) distinction is a classic trap. In C, `>>` on an `unsigned` is logical, on a `signed` is arithmetic. In Z3, `>>` is **always arithmetic**. When translating from disassembly, check whether the instruction is `shr` (logical → `LShR`) or `sar` (arithmetic → `>>`).

---

## Workflow: from disassembly to Z3 constraints

The complete process breaks down into four steps:

```
  ELF Binary
       │
       ▼
  ┌───────────────────────┐
  │  Static analysis      │    Ghidra, objdump, IDA...
  │  (decompilation)      │    → Understand the logic
  └──────────┬────────────┘
             │
             ▼
  ┌───────────────────────┐
  │  Constraint           │    Identify operations on
  │  extraction           │    inputs and the final condition
  └──────────┬────────────┘
             │
             ▼
  ┌───────────────────────┐
  │  Z3 modeling          │    Translate each operation into
  │  (Python script)      │    Z3 expression on BitVec
  └──────────┬────────────┘
             │
             ▼
  ┌───────────────────────┐
  │  Resolution           │    s.check() → s.model()
  │  + Verification       │    Test the solution on the binary
  └───────────────────────┘
```

Let's apply this to our keygenme. Suppose you opened `keygenme_O2_strip` in Ghidra and the decompiler shows you something like this (variable names manually adjusted after renaming in Ghidra):

```c
// Ghidra pseudo-code (cleaned up)
uint32_t high = parse_hex_8chars(serial);  
uint32_t low  = parse_hex_8chars(serial + 8);  

// Round 1
uint32_t tmp = low;  
uint32_t v = low ^ 0x5a3ce7f1;  
v = ((v >> 16) ^ v) * 0x45d9f3b;  
v = ((v >> 16) ^ v) * 0x45d9f3b;  
v = (v >> 16) ^ v;  
low = high ^ v;  
high = tmp;  

// Round 2
tmp = low;  
v = low ^ 0x1f4b8c2d;  
v = ((v >> 16) ^ v) * 0x45d9f3b;  
v = ((v >> 16) ^ v) * 0x45d9f3b;  
v = (v >> 16) ^ v;  
low = high ^ v;  
high = tmp;  

// Round 3 (same pattern, seed = 0xdead1337)
// Round 4 (same pattern, seed = 0x8badf00d)

if (high == 0xa11c3514 && low == 0xf00dcafe) {
    puts("Access Granted!");
}
```

You don't need the source code to arrive at this pseudo-code — it's exactly what Ghidra produces (Chapter 8), with some renaming and cleanup.

---

## Complete keygenme modeling in Z3

Let's translate this pseudo-code into Z3 constraints. Each C operation becomes its Z3 equivalent, scrupulously respecting bitvector sizes and shift types:

```python
#!/usr/bin/env python3
"""
solve_keygenme_z3.py — Keygenme resolution with Z3 alone  
Chapter 18.4  

Constraints manually extracted from the pseudo-code  
produced by Ghidra (or any other decompiler).  
"""

from z3 import *

# ================================================================
# 1. Declare unknowns: the two 32-bit halves of the serial
# ================================================================

# high and low BEFORE the Feistel network (= input values)
high_in = BitVec("high_in", 32)  
low_in  = BitVec("low_in", 32)  

# ================================================================
# 2. Model the mix32 function
# ================================================================

def mix32(v, seed):
    """Exact reproduction of mix32 in Z3."""
    v = v ^ seed
    v = (LShR(v, 16) ^ v) * BitVecVal(0x45d9f3b, 32)
    v = (LShR(v, 16) ^ v) * BitVecVal(0x45d9f3b, 32)
    v = LShR(v, 16) ^ v
    return v

# ================================================================
# 3. Model the 4-round Feistel network
# ================================================================

MAGIC_A = BitVecVal(0x5a3ce7f1, 32)  
MAGIC_B = BitVecVal(0x1f4b8c2d, 32)  
MAGIC_C = BitVecVal(0xdead1337, 32)  
MAGIC_D = BitVecVal(0x8badf00d, 32)  

def feistel4(high, low):
    """4 Feistel rounds — translated instruction by instruction."""

    # Round 1
    tmp = low
    low = high ^ mix32(low, MAGIC_A)
    high = tmp

    # Round 2
    tmp = low
    low = high ^ mix32(low, MAGIC_B)
    high = tmp

    # Round 3
    tmp = low
    low = high ^ mix32(low, MAGIC_C)
    high = tmp

    # Round 4
    tmp = low
    low = high ^ mix32(low, MAGIC_D)
    high = tmp

    return high, low

# ================================================================
# 4. Apply the transformation and set the final constraint
# ================================================================

high_out, low_out = feistel4(high_in, low_in)

s = Solver()

# The success condition extracted from the binary
s.add(high_out == BitVecVal(0xa11c3514, 32))  
s.add(low_out  == BitVecVal(0xf00dcafe, 32))  

# ================================================================
# 5. Solve
# ================================================================

if s.check() == sat:
    m = s.model()
    h = m[high_in].as_long()
    l = m[low_in].as_long()
    serial = f"{h:08x}{l:08x}"
    print(f"[+] high_in = 0x{h:08x}")
    print(f"[+] low_in  = 0x{l:08x}")
    print(f"[+] Serial  = {serial}")
else:
    print("[-] No solution (UNSAT)")
```

### Execution

```bash
$ python3 solve_keygenme_z3.py
[+] high_in = 0x7f3a1b9e
[+] low_in  = 0x5c82d046
[+] Serial  = 7f3a1b9e5c82d046

$ ./keygenme_O2_strip 7f3a1b9e5c82d046
Access Granted!
```

The result is identical to that obtained with angr — and that's logical since the constraints are the same. But the resolution is **nearly instantaneous** (a few milliseconds versus several tens of seconds for angr), because Z3 didn't have to load the binary, simulate execution, or manage SimProcedures. It directly solved the equation system.

---

## Comparing the two approaches

| Criterion | angr (Section 18.3) | Z3 direct (this section) |  
|---|---|---|  
| **Human effort** | Minimal — just need to know success/failure strings | Significant — must understand and translate the logic |  
| **Resolution time** | Seconds to minutes | Milliseconds |  
| **Binary knowledge required** | Almost none | Good understanding of the target routine |  
| **Robustness with large binaries** | Can explode in paths | Not affected by binary size |  
| **Error risk** | Low (angr faithfully translates the binary) | Real (human translation error possible) |  
| **Reusability** | Same script works on similar crackmes | Script is specific to this binary |

In practice, both approaches are **complementary**. angr is ideal for a quick first attempt. If angr fails or is too slow, switch to Z3 by extracting constraints manually from the decompiler.

---

## Common modeling techniques

Beyond the keygenme, here are the Z3 patterns you'll encounter most often in RE.

### Modeling a lookup table (S-box, substitution)

Many crypto algorithms use substitution tables. In assembly, this translates to an indexed memory access (`movzx eax, byte [rsi + rax]`). In Z3, use an `Array` or a cascade of `If`:

```python
# Substitution table (extracted from binary with Ghidra or a script)
sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        # ... 256 entries total
       ]

def lookup_sbox(index):
    """Models sbox[index] for a symbolic 8-bit index."""
    result = BitVecVal(sbox[0], 8)
    for i in range(1, 256):
        result = If(index == i, BitVecVal(sbox[i], 8), result)
    return result

x = BitVec("x", 8)  
y = lookup_sbox(x)  
```

The `If` cascade is verbose but the solver optimizes it efficiently. For larger tables, Z3's `Array` approach is more suitable:

```python
# With a Z3 Array
SBox = Array("SBox", BitVecSort(8), BitVecSort(8))

s = Solver()
# Constrain each table entry
for i in range(256):
    s.add(Select(SBox, BitVecVal(i, 8)) == BitVecVal(sbox[i], 8))

# Use the table
x = BitVec("x", 8)  
y = Select(SBox, x)  
```

### Modeling a loop with known bounds

If a loop iterates a fixed number of times (common in crypto algorithms — fixed round count), simply **unroll** it in Z3:

```python
# Loop: for (int i = 0; i < 4; i++) { state ^= keys[i]; state = rotate(state); }
state = BitVec("input", 32)  
keys = [0x11111111, 0x22222222, 0x33333333, 0x44444444]  

for i in range(4):
    state = state ^ BitVecVal(keys[i], 32)
    state = RotateLeft(state, 7)

# state now contains a symbolic expression as a function of "input"
```

Unrolling is trivial in Python — it's a Python loop that builds an increasingly complex Z3 expression. The solver has no problem with expression depth.

### Modeling string constraints

If the serial is an ASCII string with format constraints (letters only, digits only, alphanumeric…), create one 8-bit bitvector per character:

```python
# 8-character alphanumeric serial
serial = [BitVec(f"c{i}", 8) for i in range(8)]

s = Solver()  
for c in serial:  
    is_digit = And(c >= 0x30, c <= 0x39)       # '0'-'9'
    is_upper = And(c >= 0x41, c <= 0x5a)       # 'A'-'Z'
    is_lower = And(c >= 0x61, c <= 0x7a)       # 'a'-'z'
    s.add(Or(is_digit, is_upper, is_lower))
```

### Modeling a `strcmp` / `memcmp` comparison

When the binary compares a transformation result with a fixed string, it's a byte-by-byte equality constraint:

```python
# The binary compares the transformed result with "VALID_KEY"
expected = b"VALID_KEY"  
transformed = [some_function(serial[i]) for i in range(len(expected))]  

for i, byte_val in enumerate(expected):
    s.add(transformed[i] == byte_val)
```

### Modeling a CRC or checksum

Checksums are common in verification routines. A classic CRC-32 is modeled by unrolling the bit-by-bit loop, using the polynomial as a constant:

```python
POLY = BitVecVal(0xEDB88320, 32)

def crc32_z3(data_bytes, length):
    """Symbolic CRC-32 on a list of BitVec(8)."""
    crc = BitVecVal(0xFFFFFFFF, 32)
    for i in range(length):
        crc = crc ^ ZeroExt(24, data_bytes[i])  # Extend 8 bits → 32 bits
        for _ in range(8):
            mask = If(crc & 1 == BitVecVal(1, 32),
                      BitVecVal(0xFFFFFFFF, 32),
                      BitVecVal(0, 32))
            crc = LShR(crc, 1) ^ (POLY & mask)
    return crc ^ BitVecVal(0xFFFFFFFF, 32)
```

> ⚠️ This symbolic CRC-32 works but can be slow to solve for long inputs. Each bit of each byte adds a nested `If` level. On a 16-byte input (128 bits × 8 internal iterations = 1024 nested `If`s), Z3 manages in seconds. On a 1024-byte input, it might timeout.

---

## Common traps and how to avoid them

### Trap #1: forgetting bitvector sizes

Each `BitVec` has a fixed size. Operations between bitvectors of different sizes cause an immediate error:

```python
a = BitVec("a", 32)  
b = BitVec("b", 16)  

# ERROR: incompatible sizes
# result = a + b

# Correct: extend b to 32 bits before the operation
result = a + ZeroExt(16, b)    # Unsigned extension (adds 0s)  
result = a + SignExt(16, b)    # Signed extension (propagates sign bit)  
```

In x86-64 assembly, instructions like `movzx` (zero-extend) and `movsx` (sign-extend) do exactly this. When you see `movzx eax, byte [rbx]` in the disassembly, it's a `ZeroExt(24, byte_value)` in Z3.

### Trap #2: confusing logical and arithmetic shift

This is the most frequent and most silent trap — the script runs, the solver returns a solution, but it's wrong:

```python
x = BitVec("x", 32)

# In C: (unsigned)x >> 16  →  shr in assembly
result_unsigned = LShR(x, 16)      # ✓ Correct

# In C: (signed)x >> 16    →  sar in assembly
result_signed = x >> 16              # ✓ Correct

# SILENT ERROR: using >> for an unsigned shift
# If x = 0x80000000, LShR gives 0x00008000
# but >> gives 0xFFFF8000 (propagates sign bit)
```

**Simple rule**: when the disassembly shows `shr`, use `LShR`. When it shows `sar`, use `>>`.

### Trap #3: forgetting modular multiplication semantics

In C, multiplying two `uint32_t` values truncates the result to 32 bits (the high 32 bits are lost). Z3 does the same with bitvectors — it's the default behavior, which is correct. But if the binary uses `mul` (extended multiplication, producing a 64-bit result in `rdx:rax`), you need to model the extension:

```python
a = BitVec("a", 32)  
b = BitVec("b", 32)  

# Truncated multiplication (32-bit) — imul reg32, reg32
result_low = a * b

# Extended multiplication (64-bit) — mul reg32 → rdx:rax
a_ext = ZeroExt(32, a)   # 32 → 64 bits  
b_ext = ZeroExt(32, b)  
full = a_ext * b_ext  
result_rdx = Extract(63, 32, full)   # High 32 bits  
result_rax = Extract(31, 0, full)    # Low 32 bits  
```

### Trap #4: not verifying the solution

Z3 solves the constraints **you gave it**. If your modeling is incorrect (a shift in the wrong direction, a miscopied constant, a forgotten loop round), Z3 will produce a solution satisfying your erroneous model but failing on the real binary.

Verification is trivial and non-negotiable:

```bash
$ ./keygenme_O2_strip <z3_solution>
```

If the result is `"Access Denied."`, your model contains an error. Compare it instruction by instruction with the disassembly.

---

## Z3 in interactive mode for exploratory RE

You don't have to write a complete script from the start. Z3 works very well interactively in a Python shell, alongside a Ghidra session. The typical workflow:

1. Open the binary in Ghidra.  
2. Open a Python terminal with Z3.  
3. Read the Ghidra decompiler block by block.  
4. Translate each block to Z3 in the terminal.  
5. Test hypotheses as you go.

```python
>>> from z3 import *
>>> x = BitVec("x", 32)

# "Hmm, Ghidra shows v = ((v >> 16) ^ v) * 0x45d9f3b..."
# Let's try with a known value to verify my translation

>>> concrete = BitVecVal(0x12345678, 32)
>>> v = concrete
>>> v = (LShR(v, 16) ^ v) * BitVecVal(0x45d9f3b, 32)
>>> simplify(v)
2494104013

>>> hex(2494104013)
'0x94a2b2cd'
```

You can validate this value by comparing it to what GDB shows when you run the binary with input `0x12345678`. If both match, your translation is correct. Otherwise, there's an error to find.

This back-and-forth between Ghidra, Z3, and GDB is the heart of the hybrid workflow we recommend in Section 18.6.

---

## Going further with Z3: advanced features

### Optimization: finding the minimum or maximum

Z3 can not only find **a** solution, but also **optimize** a variable under constraints. This can help find the smallest valid serial, or determine parameter bounds:

```python
from z3 import *

x = BitVec("x", 32)  
o = Optimize()    # Instead of Solver()  

o.add(x * 3 + 7 > 100)  
o.add(x % 2 == 0)  

# Minimize x
o.minimize(x)

if o.check() == sat:
    print(f"Smallest x: {o.model()[x]}")
```

### Enumerating all solutions

To get **all** solutions (useful when you want all valid serials):

```python
s = Solver()  
s.add(high_out == BitVecVal(0xa11c3514, 32))  
s.add(low_out  == BitVecVal(0xf00dcafe, 32))  

solutions = []  
while s.check() == sat:  
    m = s.model()
    h = m[high_in].as_long()
    l = m[low_in].as_long()
    solutions.append((h, l))
    # Exclude this solution
    s.add(Or(high_in != m[high_in], low_in != m[low_in]))

print(f"{len(solutions)} solution(s) found")  
for h, l in solutions:  
    print(f"  {h:08x}{l:08x}")
```

On our keygenme, there's only one solution because the Feistel network is a bijection on 32-bit integers.

### Proving there's no solution

Sometimes the goal isn't finding a solution but **proving** that no input can satisfy certain conditions — for example, proving a code path is dead. If `s.check()` returns `unsat`, it's a formal proof that no input can reach that path:

```python
s = Solver()  
s.add(path_constraints)  

if s.check() == unsat:
    print("This path is impossible — dead code confirmed.")
```

This is an advanced but powerful use for vulnerability analysis (Chapter 10 — binary diffing).

---

## Summary: when to use Z3 vs angr

```
                    Know the logic?
                    ┌───── Yes ──────┐
                    │                │
                    ▼                │
            ┌──────────────┐         │
            │  Z3 direct   │         │
            │  (fast,      │         │
            │   precise)   │         │
            └──────────────┘         │
                                     │
                    ┌──── No ────────┘
                    │
                    ▼
            ┌──────────────┐     Timeout?
            │  angr        │────── Yes ──→ Extract constraints
            │  (automatic  │                manually → Z3
            │   complete)  │
            └──────────────┘
                    │
                    No
                    │
                    ▼
                Solution ✓
```

The empirical rule is simple: start with angr. If it succeeds, you're done in 5 minutes. If it fails (timeout, path explosion), open Ghidra, understand the logic, and model the constraints in Z3. It's more human work, but the solver will answer in milliseconds.

---

## Key points to remember

- Z3 is an **SMT solver** that resolves constraint systems on bitvectors — exactly the type of operations found in a compiled binary.

- The direct Z3 approach requires **manually extracting** constraints from the decompiler, which demands good understanding of the binary's logic.

- **Bitvectors** (`BitVec`) are the fundamental type: they reproduce the processor's modular arithmetic, with overflow handling, shifts, and bitwise operations.

- The main traps are confusions between **logical and arithmetic shifts** (`LShR` vs `>>`), **incompatible bitvector sizes**, and **translation errors** from disassembly.

- Z3 solves constraints in **milliseconds** where angr may take minutes, but at the cost of human modeling work.

- Always **verify the solution** on the real binary — Z3 solves your model, not the program.

- Z3 and angr are **complementary**: angr for automation, Z3 for surgical precision.

---

> In the next section (18.5), we'll examine the **fundamental limits** of symbolic execution: path explosion, loops depending on symbolic inputs, system calls, and strategies to push these limits further.

⏭️ [Limits: path explosion, loops, system calls](/18-symbolic-execution/05-limits-path-explosion.md)
