#!/usr/bin/env python3
"""
solutions/ch18-checkpoint-solution.py
=====================================
Reference solution — Chapter 18 Checkpoint

Solves keygenme_O2_strip with angr in ≤ 30 useful lines of code.

Usage:
    cd binaries/ch18-keygenme/
    python3 ../../solutions/ch18-checkpoint-solution.py

Prerequisites:
    - angr installed in a virtualenv  (pip install angr)
    - keygenme_O2_strip compiled       (make keygenme_O2_strip)

Verification:
    ./keygenme_O2_strip <displayed_serial>
    → should display "Access Granted!"

MIT License — Strictly educational use.
"""

# ============================================================================
#  MAIN SOLUTION — 20 useful lines of code
# ============================================================================

import angr
import claripy
import sys
import os

# --- Configuration -----------------------------------------------------------

BINARY = os.path.join(
    os.path.dirname(__file__), "..", "binaries", "ch18-keygenme", "keygenme_O2_strip"
)
# Fallback: if launched directly from the binary's directory
if not os.path.isfile(BINARY):
    BINARY = "./keygenme_O2_strip"

SERIAL_LEN = 16  # 16 hexadecimal characters = 64 bits

# --- Solving -----------------------------------------------------------------

# 1. Load the binary (without libc to avoid path explosion)
proj = angr.Project(BINARY, auto_load_libs=False)                          #  1

# 2. Create 16 symbolic characters of 8 bits each
chars = [claripy.BVS(f"c{i}", 8) for i in range(SERIAL_LEN)]              #  2

# 3. Concatenate them into a single 128-bit bitvector
serial = claripy.Concat(*chars)                                            #  3

# 4. Create the initial state: the binary receives the serial as argv[1]
state = proj.factory.entry_state(args=[BINARY, serial])                    #  4

# 5. Constrain each character to the hexadecimal charset [0-9A-Fa-f]
for c in chars:                                                            #  5
    state.solver.add(claripy.Or(                                           #  6
        claripy.And(c >= ord('0'), c <= ord('9')),                         #  7
        claripy.And(c >= ord('A'), c <= ord('F')),                         #  8
        claripy.And(c >= ord('a'), c <= ord('f'))                          #  9
    ))                                                                     # 10

# 6. Create the SimulationManager and launch exploration
simgr = proj.factory.simgr(state)                                         # 11
simgr.explore(                                                             # 12
    find=lambda s: b"Access Granted" in s.posix.dumps(1),                  # 13
    avoid=lambda s: b"Access Denied" in s.posix.dumps(1)                   # 14
)                                                                          # 15

# 7. Extract and display the solution
if simgr.found:                                                            # 16
    found_state = simgr.found[0]                                           # 17
    solution = found_state.solver.eval(serial, cast_to=bytes)              # 18
    print(f"[+] Serial found: {solution.decode()}")                        # 19
else:                                                                      # 20
    print("[-] No solution found.")                                        # 21
    print(f"    active={len(simgr.active)} "                               # 22
          f"deadended={len(simgr.deadended)} "                             # 23
          f"avoided={len(simgr.avoided)} "                                 # 24
          f"errored={len(simgr.errored)}")                                 # 25
    sys.exit(1)                                                            # 26

# ============================================================================
#  AUTOMATIC VERIFICATION (bonus — not counted in the 30 lines)
# ============================================================================

import subprocess

serial_str = solution.decode()
result = subprocess.run(
    [BINARY, serial_str],
    capture_output=True, text=True, timeout=5
)

if "Access Granted" in result.stdout:
    print(f"[✓] Verified: ./keygenme_O2_strip {serial_str}")
    print(f"    stdout → {result.stdout.strip()}")
else:
    print(f"[✗] FAILED: the serial does not work on the real binary.")
    print(f"    stdout → {result.stdout.strip()}")
    sys.exit(1)

# ============================================================================
#  BONUS: alternative solving with Z3 alone (not counted)
#
#  Shows that the same result can be obtained without angr, by modeling
#  the constraints manually extracted from the Ghidra decompiler.
# ============================================================================

print("\n--- Alternative solving with Z3 ---\n")

from z3 import BitVec, BitVecVal, Solver, sat, LShR

def mix32_z3(v, seed):
    """Reproduction of mix32() in Z3 — extracted from Ghidra pseudo-code."""
    v = v ^ seed
    v = (LShR(v, 16) ^ v) * BitVecVal(0x45d9f3b, 32)
    v = (LShR(v, 16) ^ v) * BitVecVal(0x45d9f3b, 32)
    v = LShR(v, 16) ^ v
    return v

def feistel4_z3(high, low):
    """4 Feistel rounds — translated from disassembly."""
    seeds = [0x5a3ce7f1, 0x1f4b8c2d, 0xdead1337, 0x8badf00d]
    for seed in seeds:
        tmp = low
        low = high ^ mix32_z3(low, BitVecVal(seed, 32))
        high = tmp
    return high, low

# Unknowns: the two 32-bit halves of the serial BEFORE transformation
high_in = BitVec("high_in", 32)
low_in  = BitVec("low_in", 32)

# Apply the transformation
high_out, low_out = feistel4_z3(high_in, low_in)

# Success condition extracted from the binary
z3_solver = Solver()
z3_solver.add(high_out == BitVecVal(0xa11c3514, 32))
z3_solver.add(low_out  == BitVecVal(0xf00dcafe, 32))

if z3_solver.check() == sat:
    m = z3_solver.model()
    h = m[high_in].as_long()
    l = m[low_in].as_long()
    z3_serial = f"{h:08x}{l:08x}"
    print(f"[+] Serial found (Z3): {z3_serial}")

    # Verification
    result_z3 = subprocess.run(
        [BINARY, z3_serial],
        capture_output=True, text=True, timeout=5
    )
    if "Access Granted" in result_z3.stdout:
        print(f"[✓] Verified: ./keygenme_O2_strip {z3_serial}")
    else:
        print(f"[✗] Z3 FAILED: the serial does not work.")
else:
    print("[-] Z3: no solution (UNSAT)")
