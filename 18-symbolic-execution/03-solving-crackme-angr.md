🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 18.3 — Automatically solving a crackme with angr

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## Section objective

We're going to solve the keygenme compiled with GCC using only angr — without reading the source code, without understanding the Feistel network, without manually inverting a single operation. The final script will be about twenty lines.

We'll proceed in three successive passes on the same binary, each illustrating a different approach:

1. **Pass 1** — Solving `keygenme_O0` (with symbols) using addresses found in Ghidra.  
2. **Pass 2** — Solving the same binary using stdout output as a criterion (without even opening a disassembler).  
3. **Pass 3** — Solving `keygenme_O2_strip` (optimized, stripped) to show the method works under realistic conditions as well.

---

## Pass 1 — Resolution by addresses (keygenme_O0)

### Preliminary step: finding target addresses

Before writing the angr script, you need to know two addresses:

- The address of the instruction leading to the success message (`"Access Granted!"`).  
- The address of the instruction leading to the failure message (`"Access Denied."`).

Several methods are possible. The quickest with tools covered in previous chapters:

```bash
$ objdump -d keygenme_O0 -M intel | grep -A2 "Access"
```

Or with `strings` combined with `objdump` to locate references:

```bash
# Find the offset of the "Access Granted" string
$ strings -t x keygenme_O0 | grep "Access"
  2004 Access Granted!
  2014 Access Denied.

# Find references to these strings in the disassembly
$ objdump -d keygenme_O0 -M intel | grep "2004"
```

You can also open the binary in Ghidra (Chapter 8). Locate the `main` function, identify the final `if/else` branch, and note the addresses of both `puts` calls.

> 💡 **Exact addresses depend on your compilation.** The values used in this section are examples. You must replace them with those from **your** binary. This is a fundamental RE reflex: never assume an address is fixed from one build to another.

Let's assume the analysis gives:

- `0x40125a` — address of `call puts` for `"Access Granted!"`.  
- `0x40126e` — address of `call puts` for `"Access Denied."`.

### The complete script

```python
#!/usr/bin/env python3
"""
solve_keygenme_v1.py — Keygenme resolution by addresses  
Chapter 18.3 — Pass 1  
"""

import angr  
import claripy  

# ---------- 1. Load the binary ----------
proj = angr.Project("./keygenme_O0", auto_load_libs=False)

# ---------- 2. Create symbolic input ----------
# The serial is a string of 16 hexadecimal characters.
# We create 16 symbolic 8-bit bitvectors (one per character).
SERIAL_LEN = 16  
serial_chars = [claripy.BVS(f"c{i}", 8) for i in range(SERIAL_LEN)]  
serial_bvs = claripy.Concat(*serial_chars)  

# ---------- 3. Create initial state ----------
state = proj.factory.entry_state(
    args=["./keygenme_O0", serial_bvs]
)

# ---------- 4. Constrain characters ----------
# Each character must be a valid hexadecimal digit [0-9A-Fa-f].
for c in serial_chars:
    digit = claripy.And(c >= ord('0'), c <= ord('9'))
    upper = claripy.And(c >= ord('A'), c <= ord('F'))
    lower = claripy.And(c >= ord('a'), c <= ord('f'))
    state.solver.add(claripy.Or(digit, upper, lower))

# ---------- 5. Launch exploration ----------
simgr = proj.factory.simgr(state)  
simgr.explore(  
    find=0x40125a,      # puts("Access Granted!")
    avoid=0x40126e       # puts("Access Denied.")
)

# ---------- 6. Extract the solution ----------
if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(serial_bvs, cast_to=bytes)
    print(f"Serial found: {solution.decode()}")
else:
    print("No solution found.")
```

### Execution

```bash
$ source ~/angr-env/bin/activate
$ python3 solve_keygenme_v1.py
Serial found: 7f3a1b9e5c82d046
```

The displayed serial is a valid solution. Let's verify immediately:

```bash
$ ./keygenme_O0 7f3a1b9e5c82d046
Access Granted!
```

The solver found **one** solution among potentially multiple valid ones. If you rerun the script, Z3 might return a different solution — this is normal, the solver is non-deterministic in its choice when multiple solutions exist.

### What happened behind the scenes

Let's detail the internal flow, as it's essential for diagnosing a script that doesn't work:

**Loading (CLE)** — The ELF binary is loaded into virtual memory. The `.text`, `.data`, `.rodata` sections are mapped at their addresses. Imported functions (`puts`, `strlen`, `strtoul`, `memcpy`…) are replaced by SimProcedures.

**State creation** — `entry_state()` positions execution at `_start` and prepares the stack with `argc=2`, `argv[0]="./keygenme_O0"` (concrete) and `argv[1]=serial_bvs` (symbolic). The 16 symbolic characters are written in memory at the address pointed to by `argv[1]`, followed by a null byte.

**Exploration** — The `SimulationManager` advances the state through `_start`, then `__libc_start_main` (SimProcedure), then `main`. In `main`, the program checks `argc`, calls `check_serial` with `argv[1]`, which in turn calls `strlen`, `strtoul`, performs the Feistel operations, and reaches the final branch.

At each arithmetic instruction, angr doesn't compute a number — it builds a symbolic expression. When `feistel4` performs `v ^= seed; v = ((v >> 16) ^ v) * 0x45D9F3B; ...`, the engine produces a nested expression of the form:

```
(((((α ⊕ 0x5A3CE7F1) >> 16) ⊕ (α ⊕ 0x5A3CE7F1)) × 0x45D9F3B) >> 16) ⊕ ...
```

…as a function of the symbolic input characters.

**Final branch** — When execution reaches `cmp` followed by `jne`, the engine forks:

- One state takes the "equal" branch with the constraint `expression_high == 0xA11C3514`.  
- The other takes the "not equal" branch with the constraint `expression_high != 0xA11C3514`.

The second state inherits an `avoid` address — it's immediately discarded. The first continues to the second comparison (`expression_low == 0xF00DCAFE`), splits again, and the surviving state reaches the `find` address.

**Resolution** — The Z3 solver receives all accumulated constraints (hexadecimal constraints on each character + path constraints from branches) and finds an assignment of the 16 characters that satisfies everything.

---

## Pass 2 — Resolution by stdout (without disassembler)

Pass 1 required finding target addresses in the binary. We can skip this entirely by using **standard output** as the criterion.

### The script

```python
#!/usr/bin/env python3
"""
solve_keygenme_v2.py — Resolution by stdout content  
Chapter 18.3 — Pass 2  
"""

import angr  
import claripy  

proj = angr.Project("./keygenme_O0", auto_load_libs=False)

SERIAL_LEN = 16  
serial_chars = [claripy.BVS(f"c{i}", 8) for i in range(SERIAL_LEN)]  
serial_bvs = claripy.Concat(*serial_chars)  

state = proj.factory.entry_state(
    args=["./keygenme_O0", serial_bvs]
)

for c in serial_chars:
    digit = claripy.And(c >= ord('0'), c <= ord('9'))
    upper = claripy.And(c >= ord('A'), c <= ord('F'))
    lower = claripy.And(c >= ord('a'), c <= ord('f'))
    state.solver.add(claripy.Or(digit, upper, lower))

simgr = proj.factory.simgr(state)

# Criteria based on stdout instead of addresses
simgr.explore(
    find=lambda s: b"Access Granted" in s.posix.dumps(1),
    avoid=lambda s: b"Access Denied" in s.posix.dumps(1)
)

if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(serial_bvs, cast_to=bytes)
    print(f"Serial found: {solution.decode()}")
else:
    print("No solution found.")
```

The only difference is in the `explore()` call: numeric addresses are replaced by lambda functions that inspect stdout content via `s.posix.dumps(1)`.

### Advantages and disadvantages of this approach

**Advantages:**

- No need to open a disassembler. You only need to know the displayed strings, which `strings` reveals in seconds.  
- Works regardless of optimization level or symbol state.  
- More robust against address changes between compilations.

**Disadvantages:**

- Slower. At each `step()`, angr must check stdout content for **each** active state, which involves additional solver calls.  
- The lambda criterion is evaluated after each basic block, adding overhead compared to a simple address comparison.  
- Doesn't work if the program displays nothing distinctive (e.g., a program that just returns a different exit code).

In practice, on our keygenme, the time difference is negligible (a few extra seconds). On more complex binaries, the address-based approach will often be preferable.

---

## Pass 3 — Optimized and stripped binary (keygenme_O2_strip)

This is the real test. The `keygenme_O2_strip` binary is compiled with `-O2` (aggressive optimizations) and stripped (no symbols). This is the scenario you'll encounter most often in real-world RE.

### What changes with -O2

Before writing the script, let's understand what GCC did to the code (Chapter 16):

- **Inlining** — The `mix32`, `feistel4`, and potentially `check_serial` functions are inlined into `main`. They no longer exist as separate functions in the binary.  
- **Instruction reordering** — The order of operations may differ from the source code.  
- **Register optimization** — Fewer memory accesses, more values kept in registers.  
- **Partial unrolling** — The 4 Feistel rounds may be unrolled.

For a human analyst, all this makes the binary significantly harder to read. For angr, **it changes almost nothing** — the symbolic engine executes instructions one by one, regardless of their organization. Inlining doesn't change semantics, it only changes code structure.

### What changes with stripping

Without symbols, angr can't resolve `main` by name. Two options:

**Option A** — Find `main`'s address manually. The quickest method on an x86-64 ELF binary is to look at the argument passed to `__libc_start_main` by `_start`:

```bash
$ objdump -d keygenme_O2_strip -M intel | head -30
```

The `lea rdi, [rip+0x...]` instruction just before `call __libc_start_main` loads `main`'s address into `rdi`. Note this address.

**Option B** — Don't look for `main` at all and start from the entry point. This is what `entry_state()` does by default, and it's sufficient for our case.

### The script

```python
#!/usr/bin/env python3
"""
solve_keygenme_v3.py — Solving the stripped -O2 binary  
Chapter 18.3 — Pass 3  
"""

import angr  
import claripy  

proj = angr.Project("./keygenme_O2_strip", auto_load_libs=False)

SERIAL_LEN = 16  
serial_chars = [claripy.BVS(f"c{i}", 8) for i in range(SERIAL_LEN)]  
serial_bvs = claripy.Concat(*serial_chars)  

state = proj.factory.entry_state(
    args=["./keygenme_O2_strip", serial_bvs]
)

for c in serial_chars:
    digit = claripy.And(c >= ord('0'), c <= ord('9'))
    upper = claripy.And(c >= ord('A'), c <= ord('F'))
    lower = claripy.And(c >= ord('a'), c <= ord('f'))
    state.solver.add(claripy.Or(digit, upper, lower))

simgr = proj.factory.simgr(state)

simgr.explore(
    find=lambda s: b"Access Granted" in s.posix.dumps(1),
    avoid=lambda s: b"Access Denied" in s.posix.dumps(1)
)

if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(serial_bvs, cast_to=bytes)
    print(f"Serial found: {solution.decode()}")
else:
    print("No solution found.")
```

You'll notice the script is **virtually identical** to pass 2. Only the binary filename changes. This is precisely the point: symbolic execution is largely indifferent to optimization level and the presence or absence of symbols. The solver resolves the same constraints, simply encoded differently in the binary.

### Verification

```bash
$ python3 solve_keygenme_v3.py
Serial found: 7f3a1b9e5c82d046

$ ./keygenme_O2_strip 7f3a1b9e5c82d046
Access Granted!
```

The same serial works on all variants — which is logical since the program's semantics are identical regardless of optimization level.

---

## Obtaining multiple solutions

Z3 returns **one** solution by default. But there potentially exist others. To get several, you can ask the solver to evaluate the symbolic expression repeatedly while excluding already-found solutions:

```python
if simgr.found:
    s = simgr.found[0]

    print("Solutions found:")
    for i in range(5):
        try:
            sol = s.solver.eval(serial_bvs, cast_to=bytes)
            print(f"  [{i+1}] {sol.decode()}")
            # Exclude this solution to find another
            s.solver.add(serial_bvs != s.solver.BVV(sol, SERIAL_LEN * 8))
        except angr.errors.SimUnsatError:
            print(f"  Only {i} solution(s) exist.")
            break
```

On our keygenme, the Feistel network is a bijection (each `(high, low)` input pair produces a unique output pair). The pair `(EXPECTED_HIGH, EXPECTED_LOW)` thus has only one possible preimage over each half's 32 bits. However, the mapping from hexadecimal characters to numeric values isn't injective (`'a'` and `'A'` represent the same hex digit), which can produce multiple valid serials if the binary accepts both cases.

---

## When angr can't manage: unblocking techniques

Things don't always go this smoothly. Here are the most frequent situations and how to respond.

### Exploration doesn't terminate

Symptom: the script has been running for 10 minutes, memory is climbing, and `simgr.active` contains thousands of states.

**Probable causes and remedies:**

**Unbounded loops** — If the binary contains a loop whose exit condition depends on a symbolic value, angr may unroll it indefinitely. Solution: limit iterations with `LoopSeer`:

```python
simgr.use_technique(angr.exploration_techniques.LoopSeer(
    cfg=proj.analyses.CFGFast(),
    bound=5   # max 5 iterations per loop
))
```

**Too many branches** — The number of states explodes exponentially. Solution: add more constraints on inputs to prune the space, or use `avoid` more aggressively to discard irrelevant paths.

**Problematic library functions** — Some libc functions are poorly modeled by SimProcedures. `strtoul` in particular can cause issues as it handles many cases (different bases, leading spaces, error handling). Solution: hook the function with a simplified SimProcedure:

```python
class SimpleStrtoul(angr.SimProcedure):
    """Simplified strtoul version for symbolic execution."""
    def run(self, str_ptr, endptr, base):
        # Read 8 characters from the pointer
        str_data = self.state.memory.load(str_ptr, 8)
        # Return an unconstrained 32-bit symbolic value
        result = self.state.solver.BVS("strtoul_result", 64)
        return result

proj.hook_symbol("strtoul", SimpleStrtoul())
```

> ⚠️ Hooking a function with a simplified version loses precision: the solver will have fewer constraints and might propose invalid solutions. It's a trade-off between completeness and performance. Always test the found solution on the real binary.

### angr finds a solution but it doesn't work

Symptom: the script displays a serial, but `./keygenme <serial>` gives `"Access Denied."`.

**Probable causes:**

- **Imprecise SimProcedure** — The simplified model of a libc function doesn't exactly capture its real behavior. For example, symbolic `strtoul` may not correctly model hexadecimal conversion. Solution: check constraints with `found_state.solver.constraints` and compare with real behavior observed in GDB.

- **Missing input constraints** — If you didn't constrain characters to be hexadecimal, the solver may propose non-hex characters that pass symbolic verification but fail in real conversion.

- **Encoding or null byte issue** — The serial may contain a null byte (`\x00`) that truncates the C string. Solution: add `state.solver.add(c != 0)` for each character.

### angr crashes or raises an exception

angr error messages can be obscure. The most common:

- **`SimUnsatError`** — Constraints became unsatisfiable. One of the paths is impossible. This generally isn't a problem — the state is simply discarded.  
- **`AngrError: ... unsupported syscall`** — The binary makes a system call angr can't model. Solution: hook the relevant code area.  
- **`ClaripyZeroDivisionError`** — The program performs a division by a value that could symbolically be zero. Solution: add a constraint to exclude zero.

---

## Starting exploration midway

Sometimes executing the binary from `_start` is too costly: libc initialization, argument parsing, serial format checks — all generate useless paths before reaching the interesting part.

A powerful technique is to start exploration directly at the verification function's entry, injecting symbolic inputs into registers or memory:

```python
# Suppose check_serial starts at 0x401180
# and expects a pointer to the serial in rdi (System V convention)

import angr  
import claripy  

proj = angr.Project("./keygenme_O0", auto_load_libs=False)

# Create a state at check_serial's entry
state = proj.factory.blank_state(addr=0x401180)

# Allocate a buffer for the serial in symbolic memory
SERIAL_ADDR = 0x500000  # Arbitrary address in free space  
SERIAL_LEN = 16  

serial_chars = [claripy.BVS(f"c{i}", 8) for i in range(SERIAL_LEN)]  
for i, c in enumerate(serial_chars):  
    state.memory.store(SERIAL_ADDR + i, c)
# Null terminator
state.memory.store(SERIAL_ADDR + SERIAL_LEN, claripy.BVV(0, 8))

# Pass the pointer in rdi (first argument, System V convention)
state.regs.rdi = SERIAL_ADDR

# Hexadecimal constraints
for c in serial_chars:
    digit = claripy.And(c >= ord('0'), c <= ord('9'))
    upper = claripy.And(c >= ord('A'), c <= ord('F'))
    lower = claripy.And(c >= ord('a'), c <= ord('f'))
    state.solver.add(claripy.Or(digit, upper, lower))

simgr = proj.factory.simgr(state)

# Here, find/avoid are addresses WITHIN check_serial
# (the return 1 vs return 0)
simgr.explore(
    find=0x4011f5,    # address of `mov eax, 1` (return 1)
    avoid=0x4011e0     # address of `xor eax, eax`  (return 0)
)

if simgr.found:
    s = simgr.found[0]
    serial = bytes(s.solver.eval(c) for c in serial_chars)
    print(f"Serial found: {serial.decode()}")
```

This approach is **much faster** because it eliminates all exploration of code before `check_serial`. It does require prior static analysis to determine the function's address, its arguments, and the calling convention — exactly the kind of work done with Ghidra in Chapter 8.

---

## Comparing resolution times

The table below gives order-of-magnitude resolution times on a typical machine (4 cores, 16 GB RAM). Exact values depend on your hardware and angr version:

| Variant | Method | Approximate time |  
|---|---|---|  
| `keygenme_O0` | By addresses, from `entry_state` | ~15–30 seconds |  
| `keygenme_O0` | By stdout, from `entry_state` | ~20–45 seconds |  
| `keygenme_O0` | From `check_serial` (`blank_state`) | ~3–8 seconds |  
| `keygenme_O2_strip` | By stdout, from `entry_state` | ~20–60 seconds |  
| `keygenme_O3_strip` | By stdout, from `entry_state` | ~25–90 seconds |

Observations:

- Starting midway (`blank_state` at the target function's entry) divides time by a factor of 3 to 10.  
- Going from `-O0` to `-O2`/`-O3` has only moderate impact on resolution time. Inlining produces a longer path but not a more branching one.  
- The stdout method is slightly slower due to lambda evaluation at each step, but the difference remains small on a binary of this size.

---

## Anatomy of a robust angr script

In summary, here's the template you can reuse and adapt for any crackme:

```python
#!/usr/bin/env python3
"""
Crackme solving template with angr.  
To adapt: binary name, input size, constraints, addresses.  
"""

import angr  
import claripy  
import sys  
import logging  

# Reduce angr verbosity (uncomment to debug)
# logging.getLogger("angr").setLevel(logging.DEBUG)
logging.getLogger("angr").setLevel(logging.WARNING)

# ========== PARAMETERS TO ADAPT ==========
BINARY    = "./keygenme_O2_strip"  
INPUT_LEN = 16                       # Input length in characters  

# Exploration criteria (choose ONE of two methods):
# Method A — by addresses:
# FIND_ADDR  = 0x40125a
# AVOID_ADDR = 0x40126e
# Method B — by stdout:
FIND_STR  = b"Access Granted"  
AVOID_STR = b"Access Denied"  
# ===========================================

def main():
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Symbolic input
    chars = [claripy.BVS(f"c{i}", 8) for i in range(INPUT_LEN)]
    sym_input = claripy.Concat(*chars)

    state = proj.factory.entry_state(args=[BINARY, sym_input])

    # Character constraints (adapt to expected format)
    for c in chars:
        # Here: hexadecimal [0-9A-Fa-f]
        state.solver.add(claripy.Or(
            claripy.And(c >= ord('0'), c <= ord('9')),
            claripy.And(c >= ord('A'), c <= ord('F')),
            claripy.And(c >= ord('a'), c <= ord('f'))
        ))

    simgr = proj.factory.simgr(state)

    # Exploration
    simgr.explore(
        find=lambda s: FIND_STR in s.posix.dumps(1),
        avoid=lambda s: AVOID_STR in s.posix.dumps(1)
    )

    # Result
    if simgr.found:
        s = simgr.found[0]
        solution = s.solver.eval(sym_input, cast_to=bytes)
        print(f"[+] Solution: {solution.decode()}")
        print(f"[*] stdout  : {s.posix.dumps(1).decode().strip()}")
    else:
        print("[-] No solution found.")
        print(f"    active={len(simgr.active)} "
              f"deadended={len(simgr.deadended)} "
              f"avoided={len(simgr.avoided)} "
              f"errored={len(simgr.errored)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

The final block displaying stash states on failure is an essential diagnostic reflex. If `active` is empty and `found` too, it means all paths were explored without finding the target — probably a criterion or constraint problem. If `active` contains thousands of states, it's path explosion — you need to prune more or use a different exploration strategy.

---

## Key points to remember

- An angr crackme-solving script always follows the same 6-step skeleton: load → symbolize → constrain → explore → extract → verify.

- Two targeting methods: by **addresses** (faster, requires a disassembler) or by **stdout content** (more portable, slightly slower).

- The script is **virtually identical** for a `-O0` binary with symbols and a `-O3` stripped binary. Symbolic execution is largely indifferent to compiler optimizations.

- Starting **midway** (`blank_state` at the target function's entry) considerably accelerates resolution by eliminating initialization code.

- Always **verify the solution** on the real binary. SimProcedures are approximations, and the solver only guarantees correctness within angr's model, not in the real world.

- On failure, examine the **stashes** (`active`, `deadended`, `avoided`, `errored`) to diagnose the problem.

---

> In the next section (18.4), we'll leave angr to work directly with **Z3**: manually modeling constraints extracted during static analysis and solving them without a symbolic execution engine.

⏭️ [Z3 Theorem Prover — modeling manually extracted constraints](/18-symbolic-execution/04-z3-theorem-prover.md)
