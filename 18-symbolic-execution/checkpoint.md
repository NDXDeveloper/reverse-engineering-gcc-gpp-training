🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Solve `keygenme_O2_strip` with angr in under 30 lines of Python

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## Objective

Write a self-contained Python script that uses angr to automatically find a valid serial for the `keygenme_O2_strip` binary — compiled with `-O2` and without symbols. The script must be **30 lines of useful code or fewer** (blank lines, comments, and imports don't count).

This checkpoint validates your ability to:

- Load a stripped binary into angr.  
- Create symbolic inputs of the right size with the right constraints.  
- Configure and launch an exploration.  
- Extract and display the solution.

---

## Target binary

```
binaries/ch18-keygenme/keygenme_O2_strip
```

If you haven't compiled it yet:

```bash
cd binaries/ch18-keygenme/  
make keygenme_O2_strip  
```

### Characteristics reminder

| Property | Value |  
|---|---|  
| Compiler | GCC, `-O2` |  
| Symbols | No (stripped with `-s`) |  
| Architecture | x86-64 |  
| Input | `argv[1]`, 16 hexadecimal characters |  
| Success | Displays `Access Granted!` on stdout |  
| Failure | Displays `Access Denied.` on stdout |

---

## Checkpoint constraints

1. **30 lines of useful code maximum.** Excluded from the count: blank lines, pure comment lines (`# ...`), import lines, and the final `if __name__`. Each logic line (variable creation, angr calls, loops, conditions, print) counts.

2. **The script must be self-contained.** It must be runnable with `python3 solve.py` without additional arguments and display the valid serial.

3. **The displayed serial must work.** The verification `./keygenme_O2_strip <serial>` must display `Access Granted!`.

4. **No hardcoding the solution.** The script must actually use symbolic execution to find the serial, not simply print it.

5. **No consulting the source code.** The script must work as if you only had the binary. Using stdout strings as criteria is authorized (and recommended).

---

## What you need to draw upon

All necessary building blocks were covered in this chapter:

| Concept | Section |  
|---|---|  
| Create a `Project` with `auto_load_libs=False` | 18.2 |  
| Create symbolic bitvectors with `claripy.BVS` | 18.2 |  
| Concatenate symbolic characters | 18.2 |  
| Constrain characters to a value set (hex) | 18.2 |  
| Create an `entry_state` with symbolic arguments | 18.2 |  
| Launch `explore()` with stdout criteria | 18.3 |  
| Extract the solution with `solver.eval()` | 18.3 |

---

## Progressive hints

Only open hints if you're stuck. Try without first.

<details>
<summary><strong>Hint 1 — General structure</strong></summary>

The script follows the 7-step skeleton seen in Section 18.2:  
load → symbolize → initial state → constrain → explore → verify → display.  

Each step takes 1 to 5 lines.

</details>

<details>
<summary><strong>Hint 2 — Symbolic input</strong></summary>

The serial is 16 characters. Create a list of 16 `BVS` of 8 bits each, then concatenate them with `claripy.Concat`. Pass the result as the second element of `args` in `entry_state`.

</details>

<details>
<summary><strong>Hint 3 — Constraints</strong></summary>

Each character must be a hexadecimal digit. Three ranges: `'0'–'9'` (0x30–0x39), `'A'–'F'` (0x41–0x46), `'a'–'f'` (0x61–0x66). Use `claripy.Or` and `claripy.And` in a loop over the 16 characters.

</details>

<details>
<summary><strong>Hint 4 — Exploration criteria</strong></summary>

Use lambda functions on `s.posix.dumps(1)` to detect `b"Access Granted"` (find) and `b"Access Denied"` (avoid). This saves you from finding addresses in a stripped binary.

</details>

<details>
<summary><strong>Hint 5 — Solution extraction</strong></summary>

After `explore()`, check `simgr.found`. On the first found state, call `s.solver.eval(serial_bvs, cast_to=bytes)` where `serial_bvs` is the concatenated 128-bit bitvector (16 × 8). Decode the result with `.decode()`.

</details>

---

## Validation criteria

| Criterion | Expected |  
|---|---|  
| The script launches without error | `python3 solve.py` executes without exception |  
| The script displays a serial | A 16-character hexadecimal string appears on stdout |  
| The serial is valid | `./keygenme_O2_strip <serial>` displays `Access Granted!` |  
| The code is ≤ 30 useful lines | Count excluding blank lines, comments, and imports |  
| No hardcoding | The serial is found by symbolic execution, not hardcoded |  
| Reasonable execution time | Resolution in under 5 minutes on a standard machine |

---

## Verification

Once your script is written, run it and verify:

```bash
# 1. Activate the angr environment
source ~/angr-env/bin/activate

# 2. Run the script
python3 solve.py
# Expected output: something like
#   [+] Serial found: 7f3a1b9e5c82d046

# 3. Verify the solution
./keygenme_O2_strip 7f3a1b9e5c82d046
# Expected output: Access Granted!
```

> ⚠️ The exact serial may vary between runs and between builds. What matters is that `./keygenme_O2_strip <your_serial>` displays `Access Granted!`.

---

## Reference solution

> ⚠️ **Spoiler** — Only open the solution file after attempting the checkpoint yourself.

The complete answer key is in:

```
solutions/ch18-checkpoint-solution.py
```

This file contains the main solution (26 useful lines, commented line by line), an automatic verification of the serial on the real binary, and an alternative Z3-only resolution for comparison.

---

## Going further

If the checkpoint seemed easy, try these variants (ungraded):

- **Variant A** — Solve `keygenme_O3_strip` instead of `O2`. The script should work without modification, but verify.  
- **Variant B** — Modify the script to start exploration at the verification function's entry (`blank_state`) instead of `entry_state`. You'll need to find this function's address in the stripped binary with `objdump`.  
- **Variant C** — Rewrite the resolution entirely in Z3 (without angr), extracting constraints from Ghidra pseudo-code.  
- **Variant D** — Modify the script to find **all** valid solutions (if multiple exist due to hex case).

---

> ✅ **Checkpoint validated?** You've mastered the basics of symbolic execution with angr. You're ready for the **Part V** practical cases, notably Chapter 21 (complete keygenme reverse with all approaches) and Chapter 24 (cryptographic key extraction).

⏭️ [Chapter 19 — Anti-reversing and compiler protections](/19-anti-reversing/README.md)
