🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 14.2 — Callgrind + KCachegrind — profiling and call graph

> 🎯 **Goal of this section**: Use Callgrind to produce a complete call graph and an instruction-by-instruction execution profile of an unknown binary, then exploit KCachegrind to visualize the program's functional architecture — identification of hotspots, critical loops, and the call hierarchy — all without source code or symbols.

---

## Callgrind in the RE toolbox

In section 14.1, we saw how Memcheck reveals a program's internal structure through its memory errors. Callgrind takes a complementary approach: instead of looking for errors, it **counts**. It counts each executed instruction, each function call, each caller → callee relationship, and produces an exhaustive execution profile.

In development, Callgrind serves to optimize performance — you identify the most expensive functions to rewrite them. In reverse engineering, the same data serves an entirely different purpose: **mapping the functional architecture of an unknown binary**.

Concretely, Callgrind gives us:

- **The complete call graph** — which function calls which other, how many times, and in what context. It's the dynamic equivalent of Ghidra's cross-references (XREF), but with the advantage of showing only the paths actually executed for a given input.  
- **The instruction cost of each function** — a function executing 50,000 instructions out of a total of 200,000 represents 25% of execution. If it's an encryption program, this function is probably the main crypto routine.  
- **Loop localization** — a function called once but executing millions of instructions necessarily contains internal loops. The cost distribution between the lines (or rather addresses) of this function reveals these loops' structure.  
- **Involved libraries** — Callgrind also profiles calls to shared libraries. You directly see if the program spends 80% of its time in `libcrypto.so` (OpenSSL encryption), `libz.so` (zlib compression), or in its own code.

---

## How Callgrind works

Like Memcheck, Callgrind relies on Valgrind's instrumentation engine. But instead of maintaining shadow memory, it inserts counters at each instruction and each call site (`call`/`ret`).

### What Callgrind measures

Callgrind primarily measures **instruction execution events** (Ir — *Instruction reads*). By default, each executed x86-64 instruction increments a counter. The result is an exact count of instructions executed by the program, broken down by:

- **Function** — the total instructions executed in the function body (self cost) and the total including functions it calls (inclusive cost).  
- **Source line / address** — if debug symbols are available, cost is broken down by source line. Otherwise, it's broken down by instruction address — which is perfectly exploitable in RE.  
- **Call arc** — for each (caller, callee) pair, the number of calls and total transferred cost.

Optionally, Callgrind can also simulate cache behavior (L1, L2, LL) and branch predictor, which adds cache miss and misprediction events. In RE, these extra metrics are rarely needed — instruction counting is more than sufficient for our purposes.

### Execution cost

Callgrind is **heavier than Memcheck**: the slowdown is approximately **20 to 100x**, versus 10–50x for Memcheck. Instruction-by-instruction counting is inherently expensive because it requires finer-grained instrumentation. For an encryption program of a few seconds, the analysis will take a few minutes — that's acceptable.

---

## Launching a Callgrind analysis

### Basic command

```bash
valgrind --tool=callgrind ./my_binary arg1 arg2
```

Callgrind produces an output file named `callgrind.out.<pid>` in the current directory, where `<pid>` is the analyzed process's PID.

### Recommended options for RE

```bash
valgrind \
    --tool=callgrind \
    --callgrind-out-file=callgrind_ch21.out \
    --collect-jumps=yes \
    --collect-systime=nsec \
    ./ch14-keygenme_O0 ABCD-1234-EFGH
```

Let's detail each option:

**`--callgrind-out-file=callgrind_ch21.out`** — Explicitly names the output file. Without this option, the name includes the PID which changes at each execution, complicating comparisons between runs.

**`--collect-jumps=yes`** — Enables collection of conditional and unconditional jumps. For each branch, Callgrind records how many times it was taken and how many times it wasn't. This is precious information in RE: a branch taken 0 times out of 1000 executions is probably an error path or a rarely reached edge case. A branch taken exactly 16 times in a loop tells us the size of a processed block (16 bytes = AES block, for example).

**`--collect-systime=nsec`** — Measures time spent in system calls in nanoseconds. This allows distinguishing real CPU time from time spent waiting for I/O (file reading, network communication). In RE, a program spending 95% of its time in `read()` and `write()` has a very different profile from one spending 95% in internal computation.

### Additional useful options

**`--separate-callers=N`** — By default, Callgrind aggregates costs by function, regardless of call path. With `--separate-callers=3`, it distinguishes call contexts over 3 depth levels. If the function `process_block` is called by both `encrypt` and `decrypt`, you'll see two separate entries with their respective costs. In RE, this helps understand in what context a function is used.

```bash
valgrind --tool=callgrind --separate-callers=3 ./my_binary
```

**`--toggle-collect=<function>`** — Limits profiling collection to a specific function and its descendants. If you've already identified that a function at address `0x401B00` is interesting (for example via Memcheck), you can focus the analysis on it:

```bash
valgrind --tool=callgrind \
    --collect-atstart=no \
    --toggle-collect=0x401B00 \
    ./my_binary
```

With `--collect-atstart=no`, collection is disabled at startup. It only activates when execution enters function `0x401B00`, and deactivates when it exits. The resulting profile contains only this function's activity and everything it calls.

> 💡 **RE tip** — `--toggle-collect` is extremely useful when the program does lots of initialization (library loading, config parsing) before reaching the interesting part. You isolate the target routine and get a clean, readable profile.

---

## Dynamic collection control with `callgrind_control`

Callgrind offers a companion tool, `callgrind_control`, that allows controlling collection **during program execution**, without stopping it.

### Main commands

```bash
# List running Callgrind processes
callgrind_control -l

# Enable/disable collection
callgrind_control -i on      # enable instrumentation  
callgrind_control -i off     # disable instrumentation  

# Force profile write (intermediate dump)
callgrind_control -d

# Reset counters to zero
callgrind_control -z
```

### Typical RE scenario

Suppose we're analyzing an interactive binary that waits for user input, then performs processing:

```bash
# Terminal 1: launch the program under Callgrind, instrumentation disabled
valgrind --tool=callgrind --collect-atstart=no --callgrind-out-file=profile.out ./ch21-keygenme_O0
```

```bash
# Terminal 2: when the program is waiting for input
callgrind_control -i on         # enable collection just before entering input
```

Then enter the input in terminal 1 (for example the key `ABCD-1234-EFGH`). The program processes the input.

```bash
# Terminal 2: after processing
callgrind_control -d             # dump the profile  
callgrind_control -i off         # disable collection  
```

The `profile.out` file now contains only the profile of the key-verification phase, without initialization or display noise. It's a surgical profile of the routine that interests us.

---

## Reading the Callgrind file on the command line

Before moving to KCachegrind (graphical interface), let's see how to exploit the Callgrind file on the command line. This is useful on a remote server without a graphical environment, or for scripted analyses.

### `callgrind_annotate` — the basic reader

```bash
callgrind_annotate callgrind_ch21.out
```

This tool produces a textual report sorted by decreasing cost:

```
--------------------------------------------------------------------------------
Profile data file 'callgrind_ch21.out' (creator: callgrind-3.22.0)
--------------------------------------------------------------------------------
I refs:      1,247,893

--------------------------------------------------------------------------------
         Ir
--------------------------------------------------------------------------------
    487,231  ???:0x00401080 [/path/to/ch21-keygenme_O0]    ← 39% of total
    312,456  ???:0x004010E0 [/path/to/ch21-keygenme_O0]    ← 25% of total
    198,712  /build/glibc/.../strcmp.S:strcmp [/usr/lib/libc.so.6]
     87,334  ???:0x00401150 [/path/to/ch21-keygenme_O0]
     52,891  /build/glibc/.../printf.c:printf [/usr/lib/libc.so.6]
    ...
```

What this report immediately tells us:

- The program executed **1,247,893 instructions** total for this input.  
- The function at address `0x00401080` consumes **39%** of execution (487,231 instructions). It's the main hotspot — probably the key transformation/hashing routine.  
- The function at `0x004010E0` consumes **25%** — potentially the verification loop or a derivation routine.  
- libc's `strcmp` is called and consumes **16%** — it's the final comparison between the derived key and the expected value.  
- `printf` is present but only consumes **4%** — result display (success/failure).

> 💡 **RE tip** — The presence of `strcmp` in a crackme's profile is a strong signal: verification is done by string comparison. The address of `strcmp`'s caller (visible in the call graph) is the main verification function. This single clue can suffice to locate the patching point.

### Per-address annotation

For a binary without symbols, you can request annotation at the individual address level:

```bash
callgrind_annotate --auto=yes --inclusive=yes callgrind_ch21.out
```

The `--inclusive=yes` option displays the inclusive cost (function + everything it calls) in addition to the self cost. The difference between the two is revealing:

- If self cost ≈ inclusive cost → the function does its work itself, it doesn't delegate. Typical of a computation loop (hashing, encryption).  
- If self cost << inclusive cost → the function is a dispatcher or orchestrator. It calls other functions that do the real work. Typical of a `main()` or a flow-control function.

### Filter by object (binary vs libraries)

```bash
callgrind_annotate --include=./ch21-keygenme_O0 callgrind_ch21.out
```

This command limits the display to the target binary's functions, excluding libc, libstdc++, and other libraries. You get a profile focused on the application code.

---

## Visualization with KCachegrind

KCachegrind is the graphical visualization tool for Callgrind files. This is where analysis takes its full dimension for RE: the call graph becomes visual, navigable, and hotspots jump out at you.

### Installation

```bash
# Debian / Ubuntu
sudo apt install kcachegrind

# Qt alternative (without KDE dependencies)
sudo apt install qcachegrind
```

`qcachegrind` is a version using only Qt, without KDE desktop dependencies. Functionally identical for our needs.

### Opening a file

```bash
kcachegrind callgrind_ch21.out
```

The interface divides into several panels. Let's see the most useful ones in an RE context.

### The Flat Profile panel (function list)

The left panel lists all functions sorted by cost. For a stripped binary, names appear as `0x00401080` — raw addresses. Two main columns:

- **Self** — the function's own cost (instructions executed in its body only).  
- **Incl.** — the inclusive cost (instructions in its body + in all functions it calls).

Clicking a function updates the other panels to show its details.

> 💡 **RE tip** — In KCachegrind, right-click a function and select "Rename Function". You can rename it to something readable (`check_key`, `derive_hash`, `main`). These renamings are kept in the session and make the call graph immediately comprehensible. It's the same reflex as renaming in Ghidra, but applied to the dynamic profile.

### The Call Graph

It's the most precious panel for RE. Accessible via the **Call Graph** tab in the right panel, it displays a graphical representation of caller → callee relationships.

Each node is a function, with:

- Its name (or address).  
- Its inclusive cost as a percentage.  
- The node's color reflects its relative cost (red = hot, blue = cold).

Each arc (arrow) between two nodes indicates:

- The call direction (from caller to callee).  
- The number of calls.  
- The transferred cost.

For a typical crackme, the call graph will look something like:

```
[0x4012E8]  ──(1x)──►  [0x401080]  ──(256x)──►  [0x4011A0]
  main?                  check_key?               transform_char?
  Incl: 100%             Incl: 64%                Self: 39%
     │
     └──(1x)──►  [0x4010E0]  ──(1x)──►  [strcmp@plt]
                  compare?                 Self: 16%
                  Incl: 41%
```

This graph immediately reveals the program's structure:

- `0x4012E8` is the orchestrator (main or equivalent) — low self cost, 100% inclusive cost.  
- `0x401080` is called once and calls `0x4011A0` exactly **256 times** — it's a loop processing each character or each byte of a block. The number 256 is characteristic of a substitution table (S-box) or character-by-character processing.  
- `0x4011A0` is the computational hotspot — it does the real calculation (transformation, hashing).  
- `0x4010E0` calls `strcmp` — it's the final comparison.

> 💡 **RE tip** — The **call counts** on graph arcs are major structural clues. 256 calls = probably iterating over 256 values (table, charset). 16 calls = potentially 16 rounds (AES). 64 calls = iterating over 64-byte blocks (SHA-256). These numbers don't lie — they come from exact execution counting.

### The Callers / Callees panel

By selecting a function in the list, the **Callers** and **Callees** tabs respectively show who calls it and who it calls, with associated costs. It's the dynamic equivalent of Ghidra's XREFs.

The fundamental difference: Ghidra's XREFs show all **possible** calls in the code, while Callgrind shows calls **actually made** for a given input. A function call that exists in the code but is behind a never-taken `if` won't appear in the Callgrind profile.

This property is double-edged:

- **Advantage**: the graph is simpler and more readable, containing only exercised paths.  
- **Disadvantage**: an important code path (error handling, alternative branch) can be invisible if the chosen input doesn't trigger it.

That's why you often run Callgrind **multiple times** with different inputs: a valid input, an invalid input, an empty input, a very long input. Comparing profiles reveals the program's conditional branches.

### The Source / Assembly panel

If the binary contains debug symbols (compiled with `-g`), KCachegrind displays the source code annotated with per-instruction counters. For a stripped binary, it shows the annotated disassembly — each instruction with its execution counter.

It's an extremely powerful view in RE: you see not only the disassembly, but also **how many times each instruction was executed**. A `jnz` instruction executed 255 times with the jump taken, and 1 time without, tells us the loop does 256 iterations and the exit condition is reached on the 256th.

---

## RE analysis methodology with Callgrind

Here's a structured method for exploiting Callgrind in a reverse-engineering workflow.

### Step 1 — Profile with a "normal" input

Run a first execution with a typical input:

```bash
valgrind --tool=callgrind \
    --callgrind-out-file=profile_normal.out \
    --collect-jumps=yes \
    ./ch21-keygenme_O0 ABCD-1234-EFGH
```

Open the result in KCachegrind and note:

- The global call graph.  
- The 5 most expensive functions (addresses + percentages).  
- The call counts on significant arcs.

### Step 2 — Profile with a "different" input

Rerun with a different input to observe variations:

```bash
valgrind --tool=callgrind \
    --callgrind-out-file=profile_alt.out \
    --collect-jumps=yes \
    ./ch21-keygenme_O0 XXXX-0000-YYYY
```

Compare both profiles. Questions to ask:

- **Does the call graph have the same shape?** If yes, the program follows the same path regardless of the key → validation is probably sequential. If no, there are input-dependent conditional branches.  
- **Did call counts change?** If `0x4011A0` is called 256 times in both cases, the iteration count is fixed. If it changes, it depends on input length or content.  
- **Did the total cost change?** A nearly identical total cost for two inputs means the program always does the same work (no short-circuit on the first characters).

### Step 3 — Profile with a "limit" input

Test an extreme case — empty input, very long input, special characters:

```bash
valgrind --tool=callgrind \
    --callgrind-out-file=profile_empty.out \
    --collect-jumps=yes \
    ./ch21-keygenme_O0 ""
```

This profile reveals the error-handling path: which functions are called when the input is invalid from the start, and which functions are *absent* compared to the normal profile. The absent functions are those that actually process the input — they weren't reached because the program rejected the input upstream.

### Step 4 — Comparison in KCachegrind

KCachegrind allows loading multiple profiles simultaneously via **File → Add**. The interface then displays each profile's costs side by side for each function, facilitating visual comparison.

You can also compare on the command line:

```bash
callgrind_annotate profile_normal.out > annotated_normal.txt  
callgrind_annotate profile_alt.out > annotated_alt.txt  
diff annotated_normal.txt annotated_alt.txt  
```

### Step 5 — Report to Ghidra

Addresses identified as interesting in Callgrind are directly usable in Ghidra. Establish a correspondence:

| Callgrind address | Cost | Hypothetical role | Proposed Ghidra name |  
|---|---|---|---|  
| `0x4012E8` | Incl: 100%, Self: 2% | Entry point / main | `main` |  
| `0x401080` | Incl: 64%, Self: 25% | Hashing routine | `hash_key` |  
| `0x4011A0` | Self: 39% | Unit transformation | `transform_byte` |  
| `0x4010E0` | Incl: 41%, Self: 25% | Comparison | `verify_result` |

Open Ghidra, navigate to each address (`G` → address), and rename functions with the hypothetical names. The subsequent static analysis is considerably accelerated: instead of starting from anonymous disassembly, you already have an annotated functional map.

---

## Analysis case: identifying a crypto routine by its profile

Cryptographic routines have characteristic **profiling signatures** that Callgrind reveals unambiguously. Here are the most common patterns.

### AES (Advanced Encryption Standard)

- A function called exactly **10, 12, or 14 times** in a loop → AES rounds (10 for AES-128, 12 for AES-192, 14 for AES-256).  
- Inside each round, sub-functions called **16 times** (16 bytes = AES block size) or **4 times** (4 columns in the state).  
- A hotspot containing intensive memory accesses to a 256-entry table → the substitution S-box.

### SHA-256

- A compression function called **N times** where N depends on input size (one call per 64-byte block).  
- Inside each call, a loop executed exactly **64 times** → the 64 rounds of SHA-256.  
- A cost dominated by arithmetic operations (rotations, XOR, additions) and accesses to a table of 64 constants.

### RC4

- An initialization phase with a loop of exactly **256 iterations** → the Key Scheduling Algorithm (KSA).  
- An encryption phase with a loop of **N iterations** (N = plaintext size) → the Pseudo-Random Generation Algorithm (PRGA).  
- Very few sub-function calls — RC4 is a compact algorithm that fits in a single function.

### bcrypt / PBKDF2

- A hashing function called a **very large number of times** (thousands to hundreds of thousands) → the cost factor / number of iterations.  
- A total cost disproportionate relative to input size → sign of a deliberately slow key derivation.

> 💡 **RE tip** — When you see a loop with a fixed and "round" iteration count (10, 16, 64, 256, 1024, 4096...), note it down. These numbers are rarely arbitrary: they almost always correspond to constants of a known algorithm. Cross-reference them with Appendix J (crypto magic constants) to identify the algorithm.

---

## Callgrind on a stripped and optimized binary

So far, our examples used `-O0` binaries for readability. In practice, binaries encountered in RE are often compiled with `-O2` or `-O3`, and stripped. Callgrind still works, but interpretation differs.

### The impact of inlining

With `-O2`, GCC can inline small functions. A `transform_byte` function called 256 times in `-O0` will potentially be integrated into `hash_key`'s body in `-O2`. Consequence in Callgrind:

- In `-O0`: you see two distinct functions, with a 256-call arc.  
- In `-O2`: you see only one function, with a much higher self cost. The 256 iterations are still there (visible in the loop counter), but the call arc has disappeared.

The call graph is therefore **flatter** with optimizations. Fewer nodes, but each node is bigger. It's a disadvantage for understanding functional hierarchy, but an advantage for identifying computational hotspots: everything is concentrated in few functions.

### Tail call optimization

With `-O2`, GCC sometimes replaces a `call` + `ret` by a simple `jmp` (tail call optimization, cf. Chapter 16). Callgrind doesn't see a `call` in this case and doesn't create a call arc. The called function appears as being part of the caller.

To detect this situation, compare the Callgrind graph with Ghidra's XREFs: if Ghidra shows a call (`call`) that Callgrind doesn't see, it's probably an inlining or tail call.

### The multi-optimization strategy

When possible (this training's practice binaries, CTFs where sources are reconstructed), the most effective strategy is to **profile both versions**:

```bash
# -O0 version: detailed call graph
valgrind --tool=callgrind --callgrind-out-file=profile_O0.out ./keygenme_O0 ABCD

# -O2 version: realistic profile
valgrind --tool=callgrind --callgrind-out-file=profile_O2.out ./keygenme_O2 ABCD
```

Use the `-O0` profile to understand the functional structure (rich call graph), then the `-O2` profile to identify hotspots in the binary as actually distributed. The `-O0` addresses don't directly correspond to `-O2` addresses, but cost patterns (proportions, iteration counts) are transferable.

---

## Callgrind file format and scripted exploitation

The file produced by Callgrind is a text file with a documented format, exploitable by Python scripts.

### Format structure

```
# callgrind format
version: 1  
creator: callgrind-3.22.0  
pid: 12345  
cmd: ./ch21-keygenme_O0 ABCD-1234-EFGH  

positions: line  
events: Ir  
summary: 1247893  

ob=./ch21-keygenme_O0  
fl=(1) ???  
fn=(1) 0x00401080  

0x00401080 3
0x00401084 256
0x00401088 256
0x0040108c 512
...

cfn=(2) 0x004011A0  
calls=256 0x004011A0  
0x00401094 256
```

Key fields:

- **`ob=`** — the object (binary or library).  
- **`fn=`** — the current function.  
- **`0x... N`** — the instruction address and its execution count.  
- **`cfn=`** — the called function (callee function).  
- **`calls=N`** — the number of calls to this function.

### Python extraction script

Here's an example script that extracts functions sorted by cost from a Callgrind file:

```python
#!/usr/bin/env python3
"""Function extractor from a Callgrind file."""

import re  
import sys  
from collections import defaultdict  

def parse_callgrind(filepath):
    functions = defaultdict(int)
    current_fn = None

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            # New function
            m = re.match(r'fn=\(\d+\)\s+(.*)', line)
            if m:
                current_fn = m.group(1)
                continue
            # Cost line: address + counter
            m = re.match(r'(0x[0-9a-fA-F]+|\d+)\s+(\d+)', line)
            if m and current_fn:
                functions[current_fn] += int(m.group(2))

    return functions

if __name__ == '__main__':
    funcs = parse_callgrind(sys.argv[1])
    total = sum(funcs.values())

    print(f"{'Function':<30} {'Cost':>12} {'%':>8}")
    print("-" * 52)
    for fn, cost in sorted(funcs.items(), key=lambda x: -x[1])[:20]:
        pct = (cost / total) * 100 if total > 0 else 0
        print(f"{fn:<30} {cost:>12,} {pct:>7.1f}%")
```

This script produces a sorted table of the 20 most expensive functions, with their addresses and percentages. It can be connected to other tools (Ghidra headless, r2pipe) to automate function renaming.

---

## Callgrind limits in an RE context

**Input-dependent coverage.** Like any dynamic analysis tool, Callgrind only sees paths exercised by the provided input. A function never called is invisible. That's why the multi-input strategy (steps 1–3 of the methodology) is important.

**No data distinction.** Callgrind counts instructions, not data. It doesn't know if a 256-iteration loop iterates over a key, a message, or a substitution table. For this information, you must cross-reference with Memcheck (section 14.1) or GDB (Chapter 11).

**No real-time measurement.** Instruction counting is deterministic (same result at each execution), which is an advantage for reproducibility. But a `div` instruction costs many more CPU cycles than a `mov`, and Callgrind counts them the same way. The profile reflects algorithmic complexity, not real time.

**Multi-threaded programs.** Callgrind handles threads but serializes them — only one thread executes at a time. The profile is valid in terms of instruction counting, but concurrency issues and real performance of parallel programs are not reflected.

---

## Summary: what Callgrind + KCachegrind teach us in RE

| Callgrind information | RE utility |  
|---|---|  
| Complete call graph | Program's functional architecture |  
| Self vs inclusive cost | Distinction between computation code vs orchestrator |  
| Call counts on arcs | Number of iterations → algorithm identification |  
| Hotspots (most expensive functions) | Crypto / parsing routine localization |  
| Conditional jump counters | Loop conditions, taken/not-taken branches |  
| Multi-input comparison | Input-dependent branches, error paths |  
| Binary vs libraries breakdown | Own code vs third-party code share |

Callgrind and KCachegrind are the **functional mapping** tools of dynamic RE. Where Memcheck gives us the "what" (which buffers, what sizes), Callgrind gives us the "how" (which functions, in what order, how many times). Combined, they provide a structural vision of the program that rivals static analysis — and complements it by showing only the actually executed paths.

---


⏭️ [AddressSanitizer (ASan), UBSan, MSan — compiling with `-fsanitize`](/14-valgrind-sanitizers/03-asan-ubsan-msan.md)
