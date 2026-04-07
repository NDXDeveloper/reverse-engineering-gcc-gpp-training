🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.3 — libFuzzer: in-process fuzzing with sanitizers

> 🔗 **Prerequisites**: Section 15.2 (AFL++, instrumentation and corpus concepts), Chapter 14 (ASan/UBSan/MSan sanitizers), Chapter 2 (GCC/Clang compilation flags)

---

## AFL++ vs libFuzzer: two philosophies

In Section 15.2, we saw AFL++ fuzz an **entire program**: at each iteration, AFL++ launches a new process, provides it an input via a file or stdin, waits for it to terminate, then analyzes the result. This *fork-exec* model is universal — it works with any program that accepts input — but it has a cost: creating a process at each execution consumes time (even with AFL++'s optimized *forkserver*).

libFuzzer takes a radically different approach: **in-process fuzzing**. Instead of launching the entire program at each iteration, libFuzzer directly calls a **target function** inside the same process, in a loop, without ever forking. The program is launched only once; it's the parsing function that's called millions of times with different inputs.

The consequences are immediate:

- **Speed** — Without the fork cost, libFuzzer can reach tens of thousands to hundreds of thousands of executions per second on fast functions. This is typically 5 to 50 times faster than AFL++ on the same target.  
- **Targeting precision** — You fuzz exactly the function you're interested in, not the entire program. In an RE context, this means you can directly target the parsing routine identified in Ghidra, without worrying about initialization logic, file reading, or argument handling.  
- **Native sanitizer coupling** — libFuzzer is part of the LLVM project, just like ASan, UBSan, and MSan. Their integration is native and optimized.

The tradeoff is that you need to write a small piece of code — the **harness** (or *fuzz target*) — that bridges libFuzzer and the function to fuzz. It's a minimal investment that pays off enormously in speed and precision.

> 💡 **For RE** — libFuzzer is the ideal tool when you've identified a specific parsing function in the binary and want to exhaustively explore its internal paths. AFL++ is preferable when you want to fuzz the program "black box," without knowing exactly which function to target.

---

## Prerequisite: Clang required

libFuzzer is a component of the LLVM/Clang toolchain. Unlike AFL++ which works equally well with GCC and Clang, **libFuzzer requires Clang**. This is a constraint to accept in the context of this training centered on the GNU chain: we'll use GCC for everything else, but Clang for libFuzzer fuzzing.

In practice, this poses no compatibility issues. Binaries produced by Clang and GCC are interoperable at the ABI level (they use the same System V AMD64 calling conventions, the same ELF formats, the same linker). A harness compiled with Clang can perfectly call code compiled separately with GCC, as long as the linkage is correct.

### Installing Clang and fuzzing runtimes

On Debian 12+ / Ubuntu 22.04+:

```bash
$ sudo apt install -y clang llvm lld
```

Verify that the `-fsanitize=fuzzer` flag is recognized:

```bash
$ echo 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }' > /tmp/test_fuzz.cc
$ clang++ -fsanitize=fuzzer /tmp/test_fuzz.cc -o /tmp/test_fuzz
$ /tmp/test_fuzz -runs=10
```

If compilation and the 10 test executions pass without errors, libFuzzer is operational.

> ⚠️ **Warning** — On older versions of Clang (< 6.0), libFuzzer was distributed as a separate library (`libFuzzer.a`) that had to be linked manually. Since Clang 6.0, the `-fsanitize=fuzzer` flag is sufficient — it activates both coverage instrumentation and libFuzzer runtime linking. Always use a recent version of Clang (11+, ideally 14+).

---

## Anatomy of a libFuzzer harness

The harness is a C function with a mandatory signature:

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Call the target function with the data provided by libFuzzer
    // ...
    return 0;
}
```

That's it. No `main()` — libFuzzer provides its own. No file reading — libFuzzer provides the data directly in memory via the `data` pointer and `size`. No loop — libFuzzer calls this function in a loop with mutated inputs at each iteration.

The return value must always be `0`. A non-zero value is reserved for advanced use (signaling the fuzzer not to add this input to the corpus).

### Essential rules for a good harness

A libFuzzer harness must respect a few constraints for fuzzing to be efficient and reliable:

**No mutable global state between calls.** Each call to `LLVMFuzzerTestOneInput` must be independent of previous ones. If the target function modifies global variables or persistent structures, they must be reinitialized at the beginning of each call. Otherwise, the program's behavior depends on the order of inputs, making crashes non-reproducible and skewing coverage.

**No calls to `exit()` or `abort()` in normal code.** If the target function calls `exit()` on invalid input, the entire process stops and fuzzing is over. You must either modify the code to return an error code instead of calling `exit()`, or isolate the parsing logic from the termination logic.

**No `fork()`.** In-process fuzzing relies on execution within a single process. A `fork()` in the target code would disrupt the coverage mechanism.

**Free allocated memory.** Since the same process executes millions of iterations, any memory leak accumulates and eventually exhausts RAM. Make sure every `malloc` has its corresponding `free` in the harness.

---

## Complete example: fuzzing a parsing function

Let's take the `simple_parser.c` from Section 15.2 and write a libFuzzer harness for its `parse_input` function.

### The target code (reminder)

Suppose the `parse_input` function is declared in a header or directly accessible:

```c
// parse_input.h
#ifndef PARSE_INPUT_H
#define PARSE_INPUT_H

#include <stddef.h>

int parse_input(const char *data, size_t len);

#endif
```

And its implementation in `parse_input.c`:

```c
// parse_input.c
#include "parse_input.h"
#include <stdio.h>
#include <string.h>

int parse_input(const char *data, size_t len) {
    if (len < 4) return -1;

    if (data[0] != 'R' || data[1] != 'E') return -1;

    unsigned char version = data[2];
    if (version == 1) {
        if (len < 8) return -1;
        int value = *(int *)(data + 4);
        if (value > 1000) {
            printf("Extended mode activated\n");
        }
    } else if (version == 2) {
        if (len < 16) return -1;
        // v2 logic...
        if (data[4] == 0x00 && len > 20) {
            // Intentional bug: out-of-bounds access if data[5] > len
            char c = data[(unsigned char)data[5]];
            (void)c;
        }
    }

    return 0;
}
```

### The harness

```c
// fuzz_parse_input.c — libFuzzer harness
#include <stdint.h>
#include <stddef.h>
#include "parse_input.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Direct call to the target function
    // The cast to (const char *) is safe here — same memory representation
    parse_input((const char *)data, size);
    return 0;
}
```

It's minimalist — and that's intentional. The harness only passes libFuzzer's data to the target function. All the complexity is in `parse_input`, and that's exactly what we want to explore.

### Compilation

We compile the harness and target code together with Clang, enabling libFuzzer and sanitizers:

```bash
$ clang -fsanitize=fuzzer,address,undefined -g -O1 \
    -o fuzz_parse_input \
    fuzz_parse_input.c parse_input.c
```

Let's break down the flags:

| Flag | Role |  
|------|------|  
| `-fsanitize=fuzzer` | Enables libFuzzer (coverage instrumentation + runtime + `main()`) |  
| `-fsanitize=address` | Enables AddressSanitizer (invalid memory access detection) |  
| `-fsanitize=undefined` | Enables UndefinedBehaviorSanitizer (undefined behavior detection) |  
| `-g` | Includes debug symbols (for readable crash reports) |  
| `-O1` | Moderate optimization level (recommended for fuzzing — see below) |

> 💡 **Why `-O1` and not `-O0`?** — ASan works better with a minimum of optimization. The `-O1` level is the compromise recommended by libFuzzer maintainers: it allows the sanitizer to work correctly while keeping the code readable enough for debugging. `-O0` also works, but `-O2` or `-O3` can mask certain bugs through optimization (eliminated variables, reordered code).

### Launch

```bash
$ mkdir corpus_parse
$ echo -ne 'RE\x01\x00AAAA' > corpus_parse/seed1.bin
$ ./fuzz_parse_input corpus_parse/
```

libFuzzer starts immediately and displays its progress:

```
INFO: Running with entropic power schedule (0xFF, 100).  
INFO: Seed: 3847291056  
INFO: Loaded 1 modules   (47 inline 8-bit counters): 47 [0x5a3e40, 0x5a3e6f),  
INFO: Loaded 1 PC tables (47 PCs): 47 [0x5a3e70,0x5a4160),  
INFO:        1 files found in corpus_parse/  
INFO: seed corpus: files: 1 min: 8b max: 8b total: 8b  
#2	INITED cov: 7 ft: 7 corp: 1/8b exec/s: 0 rss: 30Mb
#16	NEW    cov: 9 ft: 9 corp: 2/13b lim: 4 exec/s: 0 rss: 30Mb
#128	NEW    cov: 12 ft: 14 corp: 4/38b lim: 4 exec/s: 0 rss: 30Mb
#1024	NEW    cov: 15 ft: 19 corp: 7/89b lim: 11 exec/s: 0 rss: 31Mb
#8192	NEW    cov: 17 ft: 23 corp: 9/142b lim: 80 exec/s: 0 rss: 31Mb
...
```

---

## Reading libFuzzer output

libFuzzer's output is more compact than AFL++'s dashboard, but equally informative. Each line prefixed by `#` corresponds to an event:

```
#8192   NEW    cov: 17 ft: 23 corp: 9/142b lim: 80 exec/s: 45230 rss: 31Mb
```

| Field | Meaning |  
|-------|---------|  
| `#8192` | Execution number (input number 8192) |  
| `NEW` | Event type: a new input was added to the corpus |  
| `cov: 17` | Number of *edges* (transitions between basic blocks) covered |  
| `ft: 23` | Number of distinct *features* observed (finer metric than `cov`) |  
| `corp: 9/142b` | Corpus size: 9 inputs totaling 142 bytes |  
| `lim: 80` | Current size limit of generated inputs (increases progressively) |  
| `exec/s: 45230` | Number of executions per second |  
| `rss: 31Mb` | Resident memory consumption of the process |

Possible event types:

| Event | Meaning |  
|-------|---------|  
| `INITED` | Initialization complete, initial corpus loaded |  
| `NEW` | New input added to the corpus (new coverage discovered) |  
| `REDUCE` | An existing input was replaced by a shorter version covering the same paths |  
| `pulse` | Periodic heartbeat (no discovery, the fuzzer is still active) |  
| `DONE` | Maximum iteration count reached (if `-runs=N` was specified) |

For RE, the key moments are `NEW` events: each new corpus entry represents an execution path the fuzzer managed to reach in the target function. If `NEW` events come in rapid succession, the fuzzer is actively exploring new branches. If only `pulse` events appear for long periods, the fuzzer has probably converged — it's time to enrich the corpus or dictionary, or move on to analyzing results.

---

## When libFuzzer detects a bug

When a sanitizer detects a problem (or the program crashes), libFuzzer stops and displays a detailed report. Here's an example with ASan detecting an out-of-bounds access:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000098
    at pc 0x00000051a2f3 bp 0x7ffc12345678 sp 0x7ffc12345670
READ of size 1 at 0x602000000098 thread T0
    #0 0x51a2f2 in parse_input parse_input.c:22:20
    #1 0x51a3b7 in LLVMFuzzerTestOneInput fuzz_parse_input.c:7:5
    #2 0x43d0a1 in fuzzer::Fuzzer::ExecuteCallback(...) FuzzerLoop.cpp:611:15
    ...

0x602000000098 is located 0 bytes after 24-byte region [0x602000000080,0x602000000098)
allocated by thread T0 here:
    ...

SUMMARY: AddressSanitizer: heap-buffer-overflow parse_input.c:22:20 in parse_input

artifact_prefix='./'; Test unit written to ./crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
```

The crucial information for RE:

- **Bug type** — `heap-buffer-overflow`, `stack-buffer-overflow`, `use-after-free`, `null-deref`… Each type indicates different behavior in the internal logic.  
- **Precise location** — `parse_input.c:22:20` tells us exactly which line and column are responsible. In an RE context on a binary without sources, the address (`pc 0x00000051a2f3`) allows locating the instruction in Ghidra.  
- **Stack trace** — The call chain shows the path taken to reach the bug.  
- **Crash file** — `crash-adc83b19e...` is the input that triggered the bug. It's automatically saved for reproduction.

To reproduce the crash:

```bash
$ ./fuzz_parse_input crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
```

Or to examine it in a debugger:

```bash
$ gdb -q ./fuzz_parse_input
(gdb) run crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
```

> 💡 **RE interpretation** — This crash tells us that the `parse_input` function, when it receives a version 2 input with `data[4] == 0x00` and a `data[5]` value greater than the buffer size, performs an out-of-bounds memory access. By inspecting the crash input with `xxd`, we can reconstruct exactly which fields of the input format triggered this path — this is direct information about the parser's internal structure.

---

## Useful command-line options

libFuzzer accepts its options directly on the command line (after the binary, before the corpus):

### Duration and iteration control

```bash
# Limit to 60 seconds
$ ./fuzz_parse_input -max_total_time=60 corpus_parse/

# Limit to 100,000 iterations
$ ./fuzz_parse_input -runs=100000 corpus_parse/
```

Without a limit, libFuzzer runs indefinitely until `Ctrl+C` or a crash.

### Input size control

```bash
# Limit inputs to 256 bytes maximum
$ ./fuzz_parse_input -max_len=256 corpus_parse/
```

By default, libFuzzer progressively increases the maximum input size. If you know the target format has a limited size (for example a 64-byte header), setting `-max_len` significantly accelerates convergence: the fuzzer doesn't waste time generating multi-kilobyte inputs that will never be processed beyond the first few bytes.

### Using a dictionary

Like AFL++, libFuzzer supports token dictionaries:

```bash
$ ./fuzz_parse_input -dict=my_dict.txt corpus_parse/
```

The dictionary format is identical to AFL++'s (one token per line, cf. Section 15.6).

### Corpus merging and minimization

After a long session, the corpus may contain redundant inputs. libFuzzer can minimize it:

```bash
# Merge: keep only inputs that contribute unique coverage
$ mkdir corpus_minimized
$ ./fuzz_parse_input -merge=1 corpus_minimized/ corpus_parse/
```

This command reads all inputs from `corpus_parse/`, identifies those that contribute unique coverage, and copies them to `corpus_minimized/`. It's the equivalent of `afl-cmin` for AFL++.

### Parallelism

libFuzzer supports parallel fuzzing via jobs and workers:

```bash
# Launch 4 workers in parallel
$ ./fuzz_parse_input -jobs=4 -workers=4 corpus_parse/
```

Each worker is a separate process sharing the same corpus directory. Each worker's discoveries are automatically visible to the others through the filesystem. This mechanism is simpler than AFL++'s main/secondary mode, but equally effective.

---

## Mixed compilation: Clang harness + GCC target code

In this training, the sources are intended to be compiled with GCC. How can we use libFuzzer (which requires Clang) without recompiling everything?

The strategy is to compile **separately**:

1. The target code (the library or `.o` file) with GCC, adding Clang-compatible coverage instrumentation.  
2. The harness with Clang and `-fsanitize=fuzzer`.  
3. Link everything together.

### Approach 1: compile everything with Clang (simplest)

If the sources compile without modification with Clang (which is the case for standard C and the vast majority of C++), simply replace `gcc` with `clang`:

```bash
$ clang -fsanitize=fuzzer,address -g -O1 \
    -o fuzz_target \
    fuzz_harness.c source1.c source2.c
```

This is the recommended approach when possible. The training binaries in this course all compile correctly with Clang.

### Approach 2: compile target code as object with GCC, link with Clang

If the target code depends on GCC-specific features or if you want to minimize changes:

```bash
# Step 1: compile the target code with GCC as an object file
$ gcc -c -g -O1 -fsanitize=address -o parse_input.o parse_input.c

# Step 2: compile the harness and link with Clang
$ clang -fsanitize=fuzzer,address -g -O1 \
    -o fuzz_parse_input \
    fuzz_harness.c parse_input.o
```

> ⚠️ **Warning** — In this configuration, the target code (`parse_input.o`) is compiled with ASan (thanks to GCC's `-fsanitize=address`) but **without libFuzzer's coverage instrumentation**. The fuzzer will still detect crashes and memory bugs, but coverage feedback will be limited to the code compiled with Clang. For full coverage, prefer approach 1.

### Approach 3: GCC-compatible coverage instrumentation

GCC supports its own coverage instrumentation flags (`-fsanitize-coverage=trace-pc-guard`) since GCC 8+. In theory, this allows combining GCC coverage with the libFuzzer runtime. In practice, this combination is fragile and poorly documented. Unless you have a specific need, prefer approaches 1 or 2.

---

## Advanced harnesses: common techniques in RE

### Handling functions that expect a file, not a buffer

Many programs don't directly process a memory buffer but read a file. The harness must then write the data to a temporary file:

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

// Declaration of the target function that reads a file
int process_file(const char *filename);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Write the data to a temporary file
    char tmpfile[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return 0;

    write(fd, data, size);
    close(fd);

    // Call the target function with the temporary file
    process_file(tmpfile);

    // Clean up
    unlink(tmpfile);

    return 0;
}
```

This approach is slower than direct buffer fuzzing (due to disk I/O), but it's sometimes unavoidable. To mitigate the impact, you can use a tmpfs mounted in RAM:

```bash
$ sudo mount -t tmpfs -o size=100M tmpfs /tmp/fuzz_tmp
```

### Limiting the fuzzed surface with guards

If the target function is too large and you want to focus fuzzing on a subset of its logic, you can add conditions in the harness:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Only fuzz version 2 inputs (to target this specific path)
    if (size < 4) return 0;
    if (data[0] != 'R' || data[1] != 'E' || data[2] != 0x02) return 0;

    parse_input((const char *)data, size);
    return 0;
}
```

This pre-harness filtering saves considerable time when you already know, thanks to static analysis in Ghidra, which parser branch you want to explore.

### One-time initialization with `LLVMFuzzerInitialize`

If the target function requires expensive initialization (loading tables, allocating structures), libFuzzer offers an initialization hook called only once at startup:

```c
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // One-time initialization: load tables, prepare context
    init_parser_tables();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_input_with_context(global_context, (const char *)data, size);
    return 0;
}
```

This hook is optional. If defined, libFuzzer calls it before the first fuzzing iteration. It receives the program's `argc` and `argv`, which allows passing custom options to the harness.

---

## Choosing sanitizers based on the objective

The sanitizer combination to enable depends on what you're trying to discover about the binary:

| Combination | Command | What it detects | RE use |  
|-------------|---------|-----------------|--------|  
| ASan + UBSan | `-fsanitize=fuzzer,address,undefined` | Overflows, use-after-free, null accesses, arithmetic UB, invalid shifts | General use, first choice |  
| MSan | `-fsanitize=fuzzer,memory` | Reads of uninitialized memory | Understanding which fields are actually read/used |  
| ASan only | `-fsanitize=fuzzer,address` | Memory bugs only | When UBSan generates too many false positives |  
| No sanitizer | `-fsanitize=fuzzer` | Crashes only (fatal signals) | Maximum speed, initial triage |

> ⚠️ **Warning** — ASan and MSan are **mutually exclusive**: they cannot be enabled at the same time. If you want both types of detection, run two separate campaigns with two different builds.

MemorySanitizer (MSan) is particularly interesting in an RE context: it reports every read of an uninitialized byte. If the parser reads the 12th byte of an 8-byte input, MSan detects it immediately — even if that access lands in a valid memory region (allocated but not written). This reveals the parser's implicit assumptions about minimum input sizes.

---

## libFuzzer workflow for RE: step-by-step summary

1. **Identify the target function** in Ghidra or through static analysis — typically the parsing function that receives input data.

2. **Isolate the target code** — extract the function and its dependencies into separately compilable files. If the code has too many dependencies, consider *stubbing* non-essential functions (replacing them with empty functions that return default values).

3. **Write the harness** — a minimalist `LLVMFuzzerTestOneInput` that calls the target function.

4. **Compile with Clang** — enable `-fsanitize=fuzzer,address,undefined` and `-g -O1`.

5. **Prepare the initial corpus** — a few basic inputs built from magic bytes and constants identified through static analysis.

6. **Launch fuzzing** — observe the progression of `cov` and `ft`. Let it run as long as `NEW` events appear.

7. **Analyze crashes** — each ASan/UBSan report is a piece of the internal logic puzzle (cf. Section 15.4).

8. **Minimize the corpus** — use `-merge=1` to keep only essential inputs, then examine them to reconstruct the input format specification.

---

## AFL++ or libFuzzer: which to choose?

The two tools don't oppose each other — they complement each other. Here's a quick decision guide:

| Criterion | AFL++ | libFuzzer |  
|-----------|-------|-----------|  
| Sources available | Yes or no (QEMU mode) | Yes (Clang required) |  
| Target | Entire program (via file/stdin) | Specific function (via harness) |  
| Speed | Good (hundreds to thousands exec/s) | Excellent (tens of thousands exec/s) |  
| Setup effort | Minimal (just recompile) | Moderate (write a harness) |  
| Interface | Rich real-time dashboard | Compact text output |  
| Binaries without sources | Yes (QEMU / Frida) | No |  
| Ideal for | Broad exploration, first approach | Precise targeting, deep parsing |

In practice, in a complete RE workflow, you often start with AFL++ for broad program exploration (like our first run on `ch15-keygenme` in Section 15.2), then switch to libFuzzer on specific functions identified as interesting (like the `ch15-fileformat` parser in the practical case in Section 15.7). One's crashes feed the other's corpus.

---


⏭️ [Analyzing crashes to understand parsing logic](/15-fuzzing/04-analyzing-crashes.md)
