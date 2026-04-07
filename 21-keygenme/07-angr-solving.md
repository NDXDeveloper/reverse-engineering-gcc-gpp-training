🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.7 — Automatic Solving with angr

> 📖 **Reminder**: the principles of symbolic execution, angr's architecture (SimState, SimManager, exploration), and its limits are presented in chapter 18. This section assumes you have already installed angr and run at least one simple script. If not, refer to sections 18.1 to 18.3.

---

## Introduction

The previous sections followed a manual path: static analysis to understand the structure, dynamic analysis to observe execution, patching to bypass the verification. At each step, the reverse engineer is the one driving, deducing, deciding.

Symbolic execution reverses the perspective. Instead of understanding the algorithm to find the key, we let a **constraint solver** explore all possible program paths and automatically discover the input that leads to the success path. The tool does not need to know what `compute_hash` does or how `derive_key` transforms the hash — it models machine instructions one by one and builds a system of equations that the solver (Z3) resolves.

angr is the most widely used symbolic execution framework in RE. It combines a symbolic execution engine (VEX IR, based on Valgrind), an SMT solver (Z3 from Microsoft Research), and a suite of binary analysis tools (ELF loader, syscall simulation, libc models).

In this section, we will write a Python script that automatically finds the valid key for a given username, without understanding the hashing algorithm. We will start with the `keygenme_O0` variant (with symbols), then adapt the script for `keygenme_O2_strip` (optimized and stripped).

---

## The principle: find and avoid

Using angr on a crackme relies on a simple concept:

- **find**: the address (or condition) corresponding to the success path. We want angr to find an input that leads the program to this address.  
- **avoid**: the addresses corresponding to failure paths. We want angr to abandon any path that reaches these addresses, to avoid wasting exploration time.

On our keygenme, from sections 21.1 and 21.3:

- **find** → the address of `printf(MSG_OK)` (the message `"[+] Valid license!"`)  
- **avoid** → the address of `printf(MSG_FAIL)` (the message `"[-] Invalid license."`) and the address of `printf(MSG_ERR_LEN)` (the username length error message)

angr explores the program's state space: at each conditional branch, it creates two states (one for each branch), propagates symbolic constraints, and eliminates states that reach an `avoid` address. When a state reaches a `find` address, angr asks Z3 to solve the accumulated constraints — the result is a concrete value of the symbolic inputs that satisfies all conditions.

---

## Step 1 — Identify target addresses

### With symbols (`keygenme_O0`)

We retrieve addresses directly from `objdump` or Ghidra. We search for instructions that reference the success and failure strings:

```bash
$ objdump -d -M intel keygenme_O0 | grep -n "lea.*Valid\|lea.*Invalid\|lea.*must be"
```

This command does not work directly (strings are referenced by address, not content). We use the string approach in the binary instead:

```bash
# Find the address of the success string in .rodata
$ strings -t x keygenme_O0 | grep "Valid license"
   20c0 [+] Valid license! Welcome, %s.

# Find XREFs to this address in the code
$ objdump -d -M intel keygenme_O0 | grep "20c0"
    15e6:   48 8d 05 d3 0a 00 00    lea    rax,[rip+0xad3]  # 20c0
```

The address `0x15e6` is the `LEA` that loads the success string in `main`. This is our **find** address.

Similarly, we identify the **avoid** addresses:

```bash
# Failure message
$ strings -t x keygenme_O0 | grep "Invalid license"
   21c8 [-] Invalid license. Try again.

$ objdump -d -M intel keygenme_O0 | grep "21c8"
    1601:   48 8d 05 c0 0b 00 00    lea    rax,[rip+0xbc0]  # 21c8

# Length error message
$ strings -t x keygenme_O0 | grep "must be between"
   2140 [-] Username must be between 3 and 31 characters.

$ objdump -d -M intel keygenme_O0 | grep "2190"
    1575:   48 8d 05 14 0c 00 00    lea    rax,[rip+0xc14]  # 2190
```

Summary:

| Role | Address (offset) | Instruction |  
|---|---|---|  
| **find** (success) | `0x15e6` | `LEA RAX, [MSG_OK]` |  
| **avoid** (failure) | `0x1601` | `LEA RAX, [MSG_FAIL]` |  
| **avoid** (length error) | `0x1575` | `LEA RAX, [MSG_ERR_LEN]` |

> 💡 **PIE addresses**: angr loads PIE binaries with a default base of `0x400000`. The offsets found by `objdump` must be added to this base. Thus `0x15e6` becomes `0x4015e6` in angr. Alternatively, you can use angr's string search features to not worry about addresses at all (see below).

---

## Step 2 — Write the angr script (basic version)

Here is a first script, intentionally simple and commented, that solves the keygenme for a fixed username:

```python
#!/usr/bin/env python3
"""
solve_keygenme.py — Automatic keygenme solving with angr.

Usage: python3 solve_keygenme.py
"""

import angr  
import claripy  
import sys  

# ── Configuration ────────────────────────────────────────────
BINARY = "./keygenme_O0"  
USERNAME = b"Alice"  

# Target addresses (file offset + angr base 0x400000 for PIE)
BASE = 0x400000  
ADDR_SUCCESS = BASE + 0x15e6   # LEA RAX, [MSG_OK]  
ADDR_FAIL    = BASE + 0x1601   # LEA RAX, [MSG_FAIL]  
ADDR_ERR_LEN = BASE + 0x1575   # LEA RAX, [MSG_ERR_LEN]  

# ── Binary loading ──────────────────────────────────────────
proj = angr.Project(BINARY, auto_load_libs=False)

# ── Initial state ───────────────────────────────────────────
# Create a state at the program's entry point.
state = proj.factory.entry_state(
    stdin=angr.SimFile("/dev/stdin", content=angr.SimFileBase.ALL_BYTES),
)

# ── Prepare simulated input (stdin) ─────────────────────────
# The program first reads the username, then the key.
# We provide the username concretely and the key symbolically.
#
# stdin format: "Alice\nXXXX-XXXX-XXXX-XXXX\n"
#
# The key is 19 characters (XXXX-XXXX-XXXX-XXXX) + newline.

KEY_LEN = 19  
key_chars = [claripy.BVS(f"key_{i}", 8) for i in range(KEY_LEN)]  

# Constrain each character to be an uppercase hexadecimal
# character or a dash, depending on its position in the format.
for i, c in enumerate(key_chars):
    if i in (4, 9, 14):
        # Dash positions
        state.solver.add(c == ord('-'))
    else:
        # Uppercase hexadecimal characters: 0-9 or A-F
        state.solver.add(claripy.Or(
            claripy.And(c >= ord('0'), c <= ord('9')),
            claripy.And(c >= ord('A'), c <= ord('F')),
        ))

# Build stdin content
stdin_content = claripy.Concat(
    claripy.BVV(USERNAME + b"\n"),   # username (concrete)
    *key_chars,                       # key (symbolic)
    claripy.BVV(b"\n"),              # final newline
)

state = proj.factory.entry_state(
    stdin=angr.SimFile("/dev/stdin", content=stdin_content),
)

# Reapply constraints on the new state
for i, c in enumerate(key_chars):
    if i in (4, 9, 14):
        state.solver.add(c == ord('-'))
    else:
        state.solver.add(claripy.Or(
            claripy.And(c >= ord('0'), c <= ord('9')),
            claripy.And(c >= ord('A'), c <= ord('F')),
        ))

# ── Exploration ─────────────────────────────────────────────
simgr = proj.factory.simulation_manager(state)

print(f"[*] Exploring for username = '{USERNAME.decode()}'...")  
simgr.explore(  
    find=ADDR_SUCCESS,
    avoid=[ADDR_FAIL, ADDR_ERR_LEN],
)

# ── Result ──────────────────────────────────────────────────
if simgr.found:
    found_state = simgr.found[0]
    # Extract the concrete value of each key byte
    solution = bytes(
        found_state.solver.eval(c, cast_to=int) for c in key_chars
    )
    print(f"[+] Key found: {solution.decode()}")
else:
    print("[-] No solution found.")
    sys.exit(1)
```

### Execution

```bash
$ python3 solve_keygenme.py
[*] Exploring for username = 'Alice'...
[+] Key found: DCEB-0DFC-B51F-3428
```

angr found the valid key without us having to understand the hashing algorithm.

---

## Script anatomy

Let's dissect the technical choices of the script to understand why each element is necessary.

### `angr.Project(BINARY, auto_load_libs=False)`

The `Project` is angr's entry point. It loads the ELF binary, disassembles it, and builds its internal representation (VEX IR).

The `auto_load_libs=False` parameter tells angr to **not load the real libc**. Instead, angr uses its own models (SimProcedures) to simulate standard functions (`printf`, `strcmp`, `strlen`, `fgets`...). These models are simplified implementations that understand symbolic semantics — for example, the `strcmp` SimProcedure knows how to compare two strings where one is symbolic and produce the corresponding constraints.

Loading the real libc (`auto_load_libs=True`) would considerably increase exploration complexity without benefit, as angr would have to explore libc's internal code (thousands of functions, complex loops) instead of simulating them directly.

### Symbolic variables with `claripy.BVS`

`claripy` is angr's module for manipulating symbolic expressions. `BVS("name", 8)` creates a **symbolic variable** of 8 bits (one byte) — a placeholder representing "any possible 8-bit value."

Each key character is an independent symbolic variable. angr will propagate these variables through all program instructions: when `compute_hash` adds a character to the accumulator, angr records the symbolic addition; when `strcmp` compares the formatted key with the user input, angr records the equality as a constraint.

### Format constraints

We add manual constraints to restrict the search space:

```python
state.solver.add(c == ord('-'))          # dashes at positions 4, 9, 14  
state.solver.add(claripy.And(c >= ord('0'), c <= ord('9')))  # digits  
state.solver.add(claripy.And(c >= ord('A'), c <= ord('F')))  # hex letters  
```

Without these constraints, angr would also explore keys containing non-hexadecimal characters. The solver would eventually find a solution, but exploration time would be much longer. Constraining the format is an optimization that leverages our triage knowledge (section 21.1: the format is `XXXX-XXXX-XXXX-XXXX` with hexadecimal characters).

### `simgr.explore(find=..., avoid=...)`

The Simulation Manager manages the collection of active states. The `explore` method:

1. Takes the initial state and symbolically executes instructions one by one.  
2. At each conditional branch (like our `JNE` after `strcmp`), it creates two copies of the state: one for each branch, with the corresponding constraints added.  
3. States that reach an `avoid` address are moved to the `avoided` stash and no longer explored.  
4. When a state reaches a `find` address, it is moved to the `found` stash and exploration stops.

### Extracting the solution

```python
found_state.solver.eval(c, cast_to=int)
```

The found state (`found_state`) contains all constraints accumulated along the success path. The `solver.eval(variable)` method asks Z3 to find a concrete value for the symbolic variable that satisfies all constraints. The result is the valid key.

---

## Step 3 — Improved version with string search

The basic version uses hardcoded addresses, making it fragile (addresses change if the binary is recompiled). A more robust version uses string search in the binary to automatically find target addresses:

```python
#!/usr/bin/env python3
"""
solve_keygenme_robust.py — Robust version with automatic  
address detection via binary strings.  
"""

import angr  
import claripy  
import sys  

BINARY = "./keygenme_O0"  
USERNAME = b"Alice"  
KEY_LEN = 19  

# ── Loading ─────────────────────────────────────────────────
proj = angr.Project(BINARY, auto_load_libs=False)

# ── Automatic address search ────────────────────────────────
# Scan the binary to find references to success and failure
# strings, without hardcoding addresses.

cfg = proj.analyses.CFGFast()

def find_addr_referencing(string_needle):
    """Find the address of an instruction that references
    a string containing string_needle."""
    for addr, func in proj.kb.functions.items():
        try:
            block_addrs = list(func.block_addrs)
            for baddr in block_addrs:
                block = proj.factory.block(baddr)
                for const in block.vex.all_constants:
                    val = const.value
                    try:
                        mem = proj.loader.memory.load(val, 60)
                        if string_needle in mem:
                            return baddr
                    except Exception:
                        continue
        except Exception:
            continue
    return None

addr_success = find_addr_referencing(b"Valid license")  
addr_fail    = find_addr_referencing(b"Invalid license")  
addr_err_len = find_addr_referencing(b"must be between")  

if not addr_success or not addr_fail:
    print("[-] Unable to find target addresses.")
    sys.exit(1)

avoid_addrs = [addr_fail]  
if addr_err_len:  
    avoid_addrs.append(addr_err_len)

print(f"[*] find  = {hex(addr_success)}")  
print(f"[*] avoid = {[hex(a) for a in avoid_addrs]}")  

# ── Symbolic variables ──────────────────────────────────────
key_chars = [claripy.BVS(f"k{i}", 8) for i in range(KEY_LEN)]

stdin_content = claripy.Concat(
    claripy.BVV(USERNAME + b"\n"),
    *key_chars,
    claripy.BVV(b"\n"),
)

state = proj.factory.entry_state(
    stdin=angr.SimFile("/dev/stdin", content=stdin_content),
)

for i, c in enumerate(key_chars):
    if i in (4, 9, 14):
        state.solver.add(c == ord('-'))
    else:
        state.solver.add(claripy.Or(
            claripy.And(c >= ord('0'), c <= ord('9')),
            claripy.And(c >= ord('A'), c <= ord('F')),
        ))

# ── Exploration ─────────────────────────────────────────────
simgr = proj.factory.simulation_manager(state)  
print(f"[*] Exploring for '{USERNAME.decode()}'...")  

simgr.explore(find=addr_success, avoid=avoid_addrs)

if simgr.found:
    solution = bytes(
        simgr.found[0].solver.eval(c, cast_to=int) for c in key_chars
    )
    print(f"[+] Key: {solution.decode()}")
else:
    print("[-] No solution.")
    sys.exit(1)
```

This version works on all keygenme variants (including stripped ones) as long as the success/failure strings are present in plaintext in the binary.

---

## Step 4 — Adapting for the stripped and optimized variant

### `keygenme_O2_strip`

The robust script works directly: angr does not care about symbols (it works on machine code) and strings in `.rodata` survive stripping. Simply change the `BINARY` variable:

```python
BINARY = "./keygenme_O2_strip"
```

Exploration takes slightly longer because `-O2` optimized code produces more compact paths with fewer intermediate variables on the stack, which modifies the state graph structure. But the Z3 solver finds the solution the same way.

### Points of attention on optimized binaries

At `-O2`/`-O3`, the compiler may:

- **Inline `check_license`** into `main`. For angr, this is transparent — it explores the instruction flow without caring about function boundaries.  
- **Replace `strcmp` with an optimized comparison** (for example, inlined `memcmp`, or an unrolled comparison loop). If angr does not recognize the pattern as a `strcmp` call, it will execute it symbolically instruction by instruction. This is slower but works.  
- **Use SIMD registers** for string copy or comparison operations. angr supports a subset of SSE/AVX instructions, but some may cause errors. If so, you can ask angr to use a simplified model with the option `add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}`.

---

## Step 5 — Alternative approach: start in the middle

If exploration from `entry_state` is too slow (which happens on more complex binaries), you can start symbolic execution halfway — directly at the entry of `check_license`, bypassing the entire input reading phase.

```python
#!/usr/bin/env python3
"""
solve_keygenme_targeted.py — Targeted exploration from  
the entry of check_license.  
"""

import angr  
import claripy  
import sys  

BINARY = "./keygenme_O0"  
USERNAME = b"Alice"  
KEY_LEN = 19  

proj = angr.Project(BINARY, auto_load_libs=False)

# ── Addresses (offsets + base 0x400000) ─────────────────────
BASE = 0x400000  
ADDR_CHECK_LICENSE = BASE + 0x13d1  
ADDR_STRCMP_RET_1  = BASE + 0x143e   # MOV EAX, 1 (success)  
ADDR_STRCMP_RET_0  = BASE + 0x1445   # MOV EAX, 0 (failure)  

# ── Symbolic variables for the key ──────────────────────────
key_chars = [claripy.BVS(f"k{i}", 8) for i in range(KEY_LEN)]  
key_bvv = claripy.Concat(*key_chars, claripy.BVV(b"\0"))  

# ── Build a state at the entry of check_license ────────────
state = proj.factory.call_state(
    ADDR_CHECK_LICENSE,
    angr.PointerWrapper(USERNAME + b"\0"),  # RDI = username
    angr.PointerWrapper(key_bvv),           # RSI = user_key
)

# Format constraints
for i, c in enumerate(key_chars):
    if i in (4, 9, 14):
        state.solver.add(c == ord('-'))
    else:
        state.solver.add(claripy.Or(
            claripy.And(c >= ord('0'), c <= ord('9')),
            claripy.And(c >= ord('A'), c <= ord('F')),
        ))

# ── Exploration ─────────────────────────────────────────────
simgr = proj.factory.simulation_manager(state)  
print("[*] Targeted exploration from check_license...")  

simgr.explore(
    find=ADDR_STRCMP_RET_1,
    avoid=[ADDR_STRCMP_RET_0],
)

if simgr.found:
    solution = bytes(
        simgr.found[0].solver.eval(c, cast_to=int) for c in key_chars
    )
    print(f"[+] Key: {solution.decode()}")
else:
    print("[-] No solution.")
    sys.exit(1)
```

### `call_state` vs `entry_state`

The difference is fundamental:

| Method | Starting point | Inputs | Usage |  
|---|---|---|---|  
| `entry_state()` | Program entry point (`_start`) | Simulated stdin | Complete exploration, close to real behavior |  
| `call_state(addr, arg1, arg2, ...)` | Arbitrary address | Arguments passed directly in registers | Targeted exploration, faster, but requires knowing the target function's signature |

`call_state` is much faster because angr does not have to traverse the entire initialization phase (CRT, `main` before `check_license`, stdin reads). In return, arguments must be manually provided in the correct format — which requires having understood the target function's signature through static analysis (section 21.3).

---

## Understanding what angr does internally

To demystify symbolic execution, let's mentally trace what angr does on our keygenme. The exploration from `check_license` traverses the following steps:

**1. `compute_hash(username)`** — The username is concrete (`"Alice"`), so angr computes the hash concretely, without symbols. The result is a concrete 32-bit integer.

**2. `derive_key(hash, groups)`** — The hash is concrete, so the 4 16-bit groups are computed concretely. No symbols here either.

**3. `format_key(groups, expected)`** — `snprintf` (via angr's SimProcedure) writes the formatted string. The `expected` buffer now contains a concrete string (for example `"DCEB-0DFC-B51F-3428"`).

**4. `strcmp(expected, user_key)`** — This is where the magic happens. `expected` is concrete, but `user_key` is **symbolic** (composed of our `key_chars`). The `strcmp` SimProcedure compares the two strings character by character and generates constraints:

```
key_chars[0]  == 'D'  
key_chars[1]  == 'C'  
key_chars[2]  == 'E'  
key_chars[3]  == 'B'  
key_chars[4]  == '-'  
...
key_chars[18] == '8'
```

**5. Branching** — After `strcmp`, the `TEST`/`JNE` creates two branches. The "success" branch (find) carries the equality constraints above. The "failure" branch (avoid) carries the negation. angr keeps the success branch and evaluates it with Z3.

**6. Z3 solves** — The constraints are trivial (each character is fixed to a concrete value). Z3 returns the solution instantly.

### Why it is so fast here

Our keygenme is a favorable case for symbolic execution:

- The username is concrete → no combinatorial explosion in `compute_hash`.  
- The hashing operations do not depend on the symbolic input (the key).  
- The only point where the symbolic key intervenes is the final `strcmp`.  
- The `strcmp` generates linear constraints (character-by-character equality).

On a keygenme where the key would be transformed *before* comparison (for example, an XOR between the entered key and a mask, followed by a `strcmp` on the result), angr would need to propagate symbols through the transformation, generating more complex constraints — but Z3 can solve them efficiently as long as the operations remain arithmetic/logical.

---

## Limits and when angr fails

Symbolic execution is not a silver bullet. It has structural limits that are important to know:

### Path explosion

Each conditional branch that depends on a symbolic value doubles the number of states. A loop of N iterations over a symbolic buffer can create 2^N states. On our keygenme, this is not a problem (the hashing loop iterates over the concrete username, not the symbolic key), but on a binary where the key is traversed in a loop with conditions depending on each character, the explosion is real.

**Workaround**: use `call_state` to start after problematic loops, or add constraints to reduce the search space.

### System calls and I/O

angr simulates a subset of Linux syscalls. Programs that use files, network sockets, threads, or complex IPC mechanisms may cause simulation errors.

**Workaround**: hook problematic functions with custom SimProcedures, or use `call_state` to bypass the I/O phase.

### Complex crypto functions

Modern encryption functions (AES, SHA-256...) involve S-boxes (substitution tables) indexed by symbolic values. Each table access generates 256 possible branches — path explosion is immediate.

**Workaround**: extract the key by other means (GDB, Frida — chapter 24) or model the crypto function as a black box by providing its specification to Z3 manually (chapter 18, section 4).

### Exploration time

Even without path explosion, symbolic execution is inherently slow because each instruction is interpreted (not executed natively). On our small keygenme, exploration takes a few seconds. On a 10 MB binary, it can take hours.

---

## Summary

Symbolic execution with angr offers a complementary approach to manual RE:

| Approach | Understands algorithm? | Produces a key? | Human effort | Machine time |  
|---|---|---|---|---|  
| Patching (21.6) | No | No (bypass) | Medium | None |  
| angr (21.7) | No | **Yes** | Low (script) | Seconds to minutes |  
| Manual keygen (21.8) | **Yes** | **Yes** | High | None |

angr is particularly powerful when:
- You want a valid key quickly without understanding the algorithm in detail.  
- The algorithm is complex and difficult to reconstruct manually.  
- You have multiple variants of the same binary to solve (the script is reusable).

But angr does not replace understanding. To write a **keygen** — a program that generates valid keys for any username on demand — you need to understand and reproduce the algorithm. This is the objective of the next section (21.8).

⏭️ [Writing a keygen in Python with `pwntools`](/21-keygenme/08-keygen-pwntools.md)
