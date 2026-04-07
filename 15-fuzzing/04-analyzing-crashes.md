🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.4 — Analyzing crashes to understand parsing logic

> 🔗 **Prerequisites**: Section 15.2 (AFL++, output directory structure), Section 15.3 (libFuzzer, sanitizer reports), Chapter 11 (GDB), Chapter 14 (sanitizers)  
> 📦 **Demo binary**: the examples in this section use the `ch15-fileformat` parser (rich in crashes). The `ch15-keygenme` keygenme, used in Section 15.2 for the first run, rarely produces crashes but its corpus is useful for understanding validation logic (see the end of this section).

---

## Changing our perspective on crashes

In a software development or vulnerability research context, a crash is a **problem to fix** or a **flaw to exploit**. In reverse engineering, a crash is above all a **source of information**. This is one of fuzzing's most valuable contributions: each crash teaches us something about the program's internal logic, about its author's assumptions, about the formats it expects, and about the paths it takes to process them.

A crash tells us, in essence: "here is an input that traversed such a sequence of validations, took such a branch, reached such a function, and triggered such an invalid memory operation at such a precise location in the code." By decomposing this sentence, we reconstruct a complete slice of the program's behavior — from the entry point to the crash point.

This section presents a systematic methodology for transforming raw crashes produced by AFL++ or libFuzzer into **actionable knowledge** about the binary's logic.

---

## Step 1 — Inventory and sorting of crashes

After a fuzzing campaign, the crash directory can contain dozens, even hundreds of files. The first step is to sort them to avoid spending time on duplicates or superficial crashes.

### Listing crashes

For AFL++:

```bash
$ ls -la out/default/crashes/
total 48
-rw------- 1 user user   24 Mar 15 14:23 id:000000,sig:11,src:000007,time:1842,...
-rw------- 1 user user   19 Mar 15 14:25 id:000001,sig:06,src:000012,time:3107,...
-rw------- 1 user user   31 Mar 15 14:31 id:000002,sig:11,src:000007,time:5891,...
-rw------- 1 user user   22 Mar 15 14:38 id:000003,sig:08,src:000019,time:8204,...
-rw------- 1 user user  142 Mar 15 14:52 id:000004,sig:06,src:000031,time:14320,...
```

For libFuzzer, crash files are in the current directory:

```bash
$ ls crash-* oom-* timeout-*
crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc  
crash-e7f6c011776e8db7cd330b54174fd76f7d0216b4  
oom-b3f2c8a901e43f2b7854da2608b1a210c67d907e  
```

### Decoding AFL++ filenames

AFL++ filenames encode valuable metadata:

| Field | Example | Meaning |  
|-------|---------|---------|  
| `id` | `000002` | Sequential crash identifier |  
| `sig` | `11` | Signal that killed the process |  
| `src` | `000007` | ID of the parent input (in `queue/`) that was mutated to produce this crash |  
| `time` | `5891` | Milliseconds elapsed since the start of the campaign |  
| `op` | `havoc` | Mutation strategy that produced this crash |

The most frequent signals and their meaning:

| Signal | Number | Typical cause | RE interest |  
|--------|--------|---------------|-------------|  
| `SIGSEGV` | 11 | Invalid memory access (null dereference, out-of-bounds read/write) | Reveals accesses to data controlled by the input — often a clue about internal buffer structure |  
| `SIGABRT` | 6 | Call to `abort()` — typically triggered by ASan, UBSan, an `assert()`, or a `free()` on an invalid pointer | ASan: precise memory bug. `assert`: violation of an internal program invariant |  
| `SIGFPE` | 8 | Division by zero or trapped arithmetic overflow | Reveals a calculation dependent on input — often a size field or counter |  
| `SIGBUS` | 7 | Unaligned memory access (rare on x86-64, more frequent on ARM) | Indicates a cast to an aligned type on unaligned data |  
| `SIGILL` | 4 | Illegal instruction — executing data as code | Severe corruption of the execution flow — most often a stack buffer overflow that overwrote the return address |

### First sort by signal

A quick sort by signal allows prioritizing the analysis:

```bash
# Count crashes by signal
$ for f in out/default/crashes/id:*; do
    echo "$f" | grep -oP 'sig:\K[0-9]+'
  done | sort | uniq -c | sort -rn
     12 11
      5 06
      2 08
      1 04
```

The `sig:04` crashes (SIGILL) are the rarest and often the most interesting — they indicate deep corruption of the execution flow. The `sig:11` crashes are the most common and deserve to be sub-sorted by crash address (see step 2).

### Manual deduplication

AFL++ already deduplicates crashes by execution path (two inputs that crash at the same place via the same path are saved only once). But crashes with slightly different paths can lead to the same fundamental bug. For more aggressive deduplication, you can group by crash address:

```bash
# Get the crash address for each input (requires an ASan build)
$ for f in out/default/crashes/id:*; do
    ./target_asan "$f" 2>&1 | grep "pc 0x" | head -1
  done
```

Crashes that share the same `pc` address are probably variants of the same bug. You can focus on one representative from each group.

---

## Step 2 — Reproducing and characterizing a crash

Once a crash is selected, the goal is to understand **exactly what happened** between the program's entry and the moment of the crash.

### Reproducing with the instrumented binary

```bash
$ ./simple_parser_asan out/default/crashes/id:000000,sig:11,src:000007,time:1842,execs:52341,op:havoc,rep:8
```

If the binary was compiled with ASan, the report is detailed and self-explanatory. If it's a binary without a sanitizer, you simply get a `Segmentation fault` — less informative, but reproducible.

> ⚠️ **Warning** — A crash found by AFL++ in normal mode (without ASan) may **not** crash when replayed on an ASan build, and vice versa. The reason: ASan modifies memory layout (adding *redzones* around allocations, *quarantine* for freed blocks). A 1-byte out-of-bounds access may land in a valid zone without ASan but in a redzone with ASan. **Always compile a triage build with ASan** for reliable detection, and replay crashes found without ASan on it.

### Examining the crash input with xxd

Before even launching GDB, examining the raw input often reveals clues:

```bash
$ xxd out/default/crashes/id:000000,sig:11,...
00000000: 5245 02ff 00ff ffff ffff ffff ffff ffff  RE..............
00000010: ffff ffff ffff ff00                      ........
```

What we can immediately deduce from this hexdump:

- The first two bytes are `52 45` → `RE` in ASCII. The magic number is correct — the input passed the first validation.  
- The third byte is `02` → version 2. The parser took the v2 branch.  
- The fourth byte is `ff` — possibly a size field or a flag.  
- The following bytes are mostly `ff` — extreme values, typical of fuzzer mutations seeking to trigger overflows.

This quick read already gives us a hypothesis: the crash is probably related to processing the v2 branch with extreme field values.

### Examining with ImHex

For a more structured examination, open the input in ImHex (cf. Chapter 6) and apply the format's `.hexpat` pattern, if one already exists. If the pattern is under construction (which is the case during RE), the crash input is an excellent data point to refine it:

- Bytes that correspond to known fields are colorized correctly.  
- Bytes that trigger the crash are those the pattern doesn't cover yet, or whose values fall outside expected bounds.

---

## Step 3 — Analysis in GDB

Reproduction with GDB is the heart of crash analysis. The goal is to trace back the causal chain: from the crashing instruction to the decision that led the program down this path.

### Loading the crash into GDB

```bash
$ gdb -q ./simple_parser_asan
(gdb) run out/default/crashes/id:000000,sig:11,...
```

The program stops at the crash point. If you're using GEF or pwndbg (Chapter 12), the display is immediately rich: registers, stack, disassembled code around the crash point.

### Examining the crash point

```
Program received signal SIGSEGV, Segmentation fault.
0x000000000040128a in parse_input (data=0x6020000000a0, len=24) at parse_input.c:22
22          char c = data[(unsigned char)data[5]];
```

If debug symbols are present (`-g`), GDB shows the exact source line. Without symbols, you get the address and disassembly:

```
Program received signal SIGSEGV, Segmentation fault.
0x000000000040128a in ?? ()
(gdb) x/5i $rip-8
   0x401282:    movzx  eax, BYTE PTR [rbp-0x1]
   0x401286:    cdqe
=> 0x40128a:    movzx  eax, BYTE PTR [rdi+rax*1]
   0x40128e:    mov    BYTE PTR [rbp-0x2], al
   0x401291:    nop
```

The faulting instruction is `movzx eax, BYTE PTR [rdi+rax*1]` — an indexed read into the `data` buffer (pointed to by `rdi`), with an index coming from `rax`. If `rax` exceeds the buffer size, the access is out of bounds.

### Inspecting registers and memory

```
(gdb) info registers rdi rax
rdi    0x6020000000a0   # Address of the data buffer  
rax    0xff             # Index = 255 (comes from data[5] = 0xff)  

(gdb) print len
$1 = 24
```

The index is 255, but the buffer is only 24 bytes. The program accesses `data[255]` — well beyond the allocated area. The byte `data[5]` is `0xff` in the crash input, and the code uses it directly as an index without checking that it's less than `len`.

### Tracing back the stack trace

```
(gdb) backtrace
#0  0x000000000040128a in parse_input (data=0x6020000000a0, len=24) at parse_input.c:22
#1  0x00000000004013b7 in LLVMFuzzerTestOneInput (data=0x6020000000a0, size=24) at fuzz_parse_input.c:7
#2  0x000000000043d0a1 in fuzzer::Fuzzer::ExecuteCallback (...) at FuzzerLoop.cpp:611
```

The stack trace confirms the path: libFuzzer → harness → `parse_input`, line 22. No surprising intermediate calls — the crash is directly in the target function.

### Examining upstream branching conditions

The crash taught us *where* the program fails. Now we need to understand *how* it got there — that is, which conditions were satisfied to reach this line.

We set a breakpoint at the beginning of `parse_input` and rerun:

```
(gdb) break parse_input
(gdb) run out/default/crashes/id:000000,sig:11,...

Breakpoint 1, parse_input (data=0x6020000000a0, len=24) at parse_input.c:4
(gdb) next    # if (len < 4) → passed (len=24)
(gdb) next    # if (data[0] != 'R') → passed (data[0]='R')
(gdb) next    # if (data[1] != 'E') → passed (data[1]='E')
(gdb) next    # version = data[2] → version = 2
(gdb) next    # if (version == 1) → not taken
(gdb) next    # else if (version == 2) → taken
(gdb) next    # if (len < 16) → passed (len=24)
(gdb) next    # if (data[4] == 0x00 && len > 20) → data[4]=0x00, len=24 → taken
(gdb) next    # char c = data[(unsigned char)data[5]] → CRASH
```

We now have the complete path:

```
Entry
  → len ≥ 4         ✓
  → data[0] == 'R'  ✓
  → data[1] == 'E'  ✓
  → version == 2     ✓  (data[2] == 0x02)
  → len ≥ 16        ✓
  → data[4] == 0x00 ✓
  → len > 20        ✓
  → access data[data[5]] without bounds check → CRASH if data[5] ≥ len
```

This path is a **partial specification** of the parser's v2 branch. Each condition is a field of the input format with its constraints. Thanks to a single crash, we've just documented the header structure and the activation conditions for a specific processing path.

---

## Step 4 — Extracting RE information from each crash

Each analyzed crash produces knowledge that directly feeds the reverse engineering process. Here's how to organize it.

### Documenting the execution path

For each significant crash, note:

- **The offset and nature of the bug** — "buffer over-read at `parse_input+0x48`, index controlled by `data[5]`"  
- **The condition path** — the sequence of tests passed to reach the crash (as above)  
- **The format fields involved** — "bytes 0-1: magic 'RE', byte 2: version, byte 4: mode flag, byte 5: index/length"  
- **The minimum input size** — here 21 bytes (len > 20 is a condition)

### Reconstructing the format structure

As crashes accumulate, a picture of the input format emerges. Each crash adds pieces to the puzzle:

```
Offset  Size    Field               Known constraints
──────  ──────  ──────────────────  ─────────────────────────────
0x00    2       Magic               "RE" (0x52 0x45)
0x02    1       Version             1 or 2 (other values = rejected)
0x03    1       (unknown)           not yet observed in crashes
0x04    1       Mode flag           0x00 activates the extended path (v2)
0x05    1       Index/Length        used as index into data[]
0x06    2       (unknown)           ...
0x08    8       Payload v1          accessed if version==1, len≥8
0x08    ?       Payload v2          accessed if version==2, len≥16
```

This table is exactly the type of information that will later be injected into an ImHex pattern (`.hexpat`), into a Python parsing script, or into Ghidra comments to rename variables and structure fields.

### Mapping the parser's branches

By accumulating crashes and corpus inputs (not just crashes), you can build a **decision tree** of the parser:

```
parse_input()
│
├─ len < 4 ? → return -1 (reject)
│
├─ data[0:2] != "RE" ? → return -1 (reject)
│
├─ version == 1
│   ���─ len < 8 ? → return -1
│   └─ value > 1000 ? → extended mode v1
│
├─ version == 2
│   ├─ len < 16 ? → return -1
│   └─ data[4] == 0x00 && len > 20 ?
│       └─ access data[data[5]]  ← BUG if data[5] >= len
│
└─ other version → return 0 (silently accepted)
```

This tree is a **reconstruction of the parser's control logic**, obtained without reading a single line of source code or disassembly. In practice, you'll verify and complete this tree by comparing it to the disassembly in Ghidra — but fuzzing provided the skeleton.

---

## Step 5 — Minimizing crash inputs

Raw crashes produced by the fuzzer often contain superfluous bytes — mutation residues that have no impact on the crash. A 142-byte input that crashes could be reduced to 22 essential bytes. Minimization produces a **minimal** input that triggers exactly the same crash, making analysis easier.

### With `afl-tmin` (AFL++)

```bash
$ afl-tmin -i out/default/crashes/id:000000,sig:11,... \
           -o crash_minimized.bin \
           -- ./simple_parser_afl @@
```

`afl-tmin` progressively tries to remove bytes, replace sequences with zeros, and shorten the input, verifying at each step that the crash is still reproduced. The result is the smallest possible input that causes the same crash.

The minimized input is often spectacularly shorter than the original:

```bash
$ wc -c out/default/crashes/id:000000,sig:11,...
142
$ wc -c crash_minimized.bin
22
```

### With libFuzzer (`-minimize_crash`)

```bash
$ ./fuzz_parse_input -minimize_crash=1 -runs=10000 crash-adc83b19e...
```

libFuzzer attempts to reduce the input by performing mutations that preserve the crash. The minimized input is saved with the `minimized-from-` prefix.

### Why minimization is crucial for RE

A minimized 22-byte input is **directly interpretable**: every byte has a role, every modification of a byte changes the behavior. You can then proceed by systematic substitution to identify the role of each position:

```bash
# The minimized input:
$ xxd crash_minimized.bin
00000000: 5245 0200 00ff 0000 0000 0000 0000 0000  RE..............
00000010: 0000 0000 0000                           ......

# Change byte 2 (version) from 0x02 to 0x01:
$ printf '\x52\x45\x01...' > test_v1.bin
$ ./simple_parser_asan test_v1.bin
# → no crash: the v1 path is different

# Change byte 5 (index) from 0xff to 0x05:
$ printf '\x52\x45\x02\x00\x00\x05...' > test_safe_index.bin
$ ./simple_parser_asan test_safe_index.bin
# → no crash: index 5 is within bounds
```

This **one-byte-at-a-time perturbation** method transforms a crash into a precise map of the input format fields. It's a direct complement to static analysis in Ghidra.

---

## Step 6 — Sorting crashes by bug class

When the campaign produces many crashes, it's useful to group them by **bug class** rather than by raw signal. Each class corresponds to a type of weakness in the parser's logic and guides the analysis differently.

### Out-of-bounds read access (heap/stack-buffer-overflow READ)

This is the most common class for parsers. The program reads beyond a buffer's bounds, typically because an input field is used as an index or length without validation.

**What it reveals**: an input field directly controls a memory access. By identifying which byte of the input corresponds to the index or length, you document a key field of the format.

### Out-of-bounds write access (heap/stack-buffer-overflow WRITE)

Rarer and more severe. The program writes beyond a buffer, potentially corrupting adjacent data or the control flow.

**What it reveals**: a copy or decoding operation whose size is controlled by the input. Often linked to an unvalidated "payload length" field.

### Use-after-free

The program accesses a memory block that has already been freed. Typically, a structure is deallocated in an error path but a pointer to it persists in another.

**What it reveals**: the parser's error handling logic — which objects are created and destroyed at which moments. Useful for understanding the lifecycle of internal structures.

### Read of uninitialized memory (MSan)

The program reads a byte that was never written. No visible crash under normal conditions, but MSan reports it.

**What it reveals**: a field of the internal structure that isn't initialized before being used. Indicates an implicit assumption of the parser about field processing order.

### Division by zero / arithmetic overflow (SIGFPE, UBSan)

The program performs a division whose divisor comes from the input, or an arithmetic calculation whose result exceeds type limits.

**What it reveals**: a numeric input field used in a calculation — often a counter, block size, or scaling factor.

---

## Automating triage with a script

When the number of crashes is significant, an automatic triage script allows characterizing them quickly. Here's the general logic of such a script (the complete implementation is available in `scripts/triage.py`):

```bash
# For each crash, extract:
# 1. The signal (from the AFL++ filename or from execution)
# 2. The crash address (from ASan output or GDB)
# 3. The ASan bug type (from the report)
# 4. The input size

$ for crash in out/default/crashes/id:*; do
    echo "=== $crash ==="
    echo "Size: $(wc -c < "$crash") bytes"

    # Extract the ASan bug type
    ./simple_parser_asan "$crash" 2>&1 | grep "^SUMMARY:" || echo "No ASan report"

    echo ""
  done > triage_report.txt
```

The result is a triage file that looks like:

```
=== out/default/crashes/id:000000,sig:11,... ===
Size: 24 bytes  
SUMMARY: AddressSanitizer: heap-buffer-overflow parse_input.c:22:20 in parse_input  

=== out/default/crashes/id:000001,sig:06,... ===
Size: 19 bytes  
SUMMARY: AddressSanitizer: heap-use-after-free parse_input.c:45:12 in cleanup_context  

=== out/default/crashes/id:000002,sig:11,... ===
Size: 31 bytes  
SUMMARY: AddressSanitizer: heap-buffer-overflow parse_input.c:22:20 in parse_input  
```

We can immediately see that crashes 000000 and 000002 are variants of the same bug (same location), while 000001 is a different bug in another function. We prioritize: analyze in detail one representative from each group, starting with the rarest or deepest in the code.

---

## Back to static analysis: enriching Ghidra

The knowledge extracted from crashes directly feeds work in Ghidra (Chapter 8). Here are the concrete actions to take after analyzing a crash:

**Rename functions.** If the crash revealed that a function at address `0x4012a0` is a v2 payload decoding routine, rename it `decode_payload_v2` in Ghidra.

**Create data types.** The field table reconstructed in step 4 translates to a structure in Ghidra:

```c
struct FileHeader {
    char magic[2];        // "RE"
    uint8_t version;      // 1 or 2
    uint8_t reserved;     // not yet understood
    uint8_t mode_flag;    // 0x00 = extended mode
    uint8_t data_index;   // index into payload
    uint8_t unknown[2];   // to be explored
};
```

**Annotate branching conditions.** In the assembly listing, add comments on the identified conditions: `/* version == 2: v2 branch */`, `/* data[4] == 0x00: activates extended mode */`.

**Mark bugs.** If a bug was identified (out-of-bounds access without validation), flag it in Ghidra with a bookmark or comment `BUG: no bounds check on data[5]`. These annotations will be useful if the ultimate goal of the RE is a security audit.

---

## Summary

Crash analysis follows a six-step pipeline:

1. **Inventory and sorting** — list, count by signal, deduplicate by address.  
2. **Reproduction** — rerun the crash input on an ASan build, examine the report.  
3. **GDB analysis** — trace back the causal chain, identify the condition path.  
4. **RE information extraction** — document format fields, reconstruct the decision tree.  
5. **Minimization** — reduce the input to the bare minimum to isolate each field.  
6. **Classification** — group by bug class to prioritize and avoid duplicates.

Each analyzed crash is a slice of understanding of the binary. Accumulated and cross-referenced, they produce a detailed map of the parsing logic — which code coverage, seen in the next section, will complement by revealing the areas crashes haven't reached.

---

## Note: when the fuzzer doesn't crash (keygenme case)

Not all binaries produce crashes. The `ch21-keygenme` keygenme, fuzzed in Section 15.2, is a simple program that compares strings and returns "valid" or "invalid" — it doesn't manipulate buffers dangerously and generally doesn't crash.

In this case, the RE information is in the **corpus**, not in the crashes. Each corpus input represents a string that takes a distinct path through the verification routine. By examining them:

- The shortest inputs that reach deep branches reveal the **prefixes and delimiters** expected by the routine (for example, if all inputs with more than 10 edges start with `"KEY-"`, the prefix is identified).  
- Inputs that produce a different return code (0 vs 1) allow distinguishing **success and failure paths**.  
- The progression of the corpus over time (via timestamps in AFL++ filenames) shows in which order the fuzzer "unlocked" the validation layers.

This corpus analysis is a natural complement to crash analysis — and in some cases, it's the only source of dynamic information available.

---


⏭️ [Coverage-guided fuzzing: reading coverage maps (`afl-cov`, `lcov`)](/15-fuzzing/05-coverage-guided.md)
