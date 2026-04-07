🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.5 — Coverage-guided fuzzing: reading coverage maps (`afl-cov`, `lcov`)

> 🔗 **Prerequisites**: Section 15.2 (AFL++, coverage bitmap), Section 15.4 (crash analysis), Chapter 8 (navigating in Ghidra)

---

## Coverage as an RE tool

In the previous sections, we leveraged the **crashes** produced by the fuzzer to understand execution paths that fail. But the majority of inputs don't crash — they traverse the parser, take branches, and terminate normally. These "silent" executions are just as informative as crashes, provided we can observe **which paths they traversed**.

This is exactly what code coverage measures. During fuzzing, each input triggers the execution of certain basic blocks and certain transitions between blocks. By accumulating these observations across the entire campaign, we get a **map** of the binary that distinguishes:

- **Covered code** — the portions actually executed by at least one corpus input. These are the paths the fuzzer managed to reach.  
- **Uncovered code** — the portions never executed. Either dead code (never reachable), or paths protected by conditions the fuzzer hasn't satisfied.

For a reverse engineer, this distinction is a compass. Covered code is "understood" — we know which inputs trigger it, we can trace it in GDB. Uncovered code is the terra incognita that deserves manual attention: why didn't the fuzzer get there? What condition is blocking? Is it a checksum, a signature, a temporal dependency?

This section explains how to extract, visualize, and interpret coverage data produced by AFL++ and libFuzzer, using `afl-cov`, `lcov`, `genhtml`, and `afl-showmap`.

---

## The two levels of coverage

Before diving into the tools, let's distinguish two coverage metrics that don't provide the same information:

### Line coverage

The most intuitive metric: which lines of source code were executed? This is what `gcov` and `lcov` produce from GCC's coverage instrumentation (`-fprofile-arcs -ftest-coverage` or `--coverage`). The result is an HTML report where each source line is annotated in green (executed) or red (never executed), with an execution counter.

**Advantage**: immediately readable, direct correlation with source code.  
**Limitation**: requires sources. In pure RE on a binary without sources, this metric isn't directly available (but it can be approximated by overlaying binary coverage onto Ghidra pseudo-code).  

### Edge coverage

This is AFL++ and libFuzzer's native metric. An *edge* is a transition from one basic block to another — for example, the jump from the `if (version == 2)` condition to the block that handles version 2. AFL++'s bitmap (cf. Section 15.2) records exactly these edges.

**Advantage**: available even without sources, finer than line coverage (two paths that pass through the same lines but in a different order generate distinct edges).  
**Limitation**: less readable raw — edges are address pairs, not source lines.  

In practice, we use **both**: edge coverage during fuzzing (it's what guides AFL++'s mutations), and line coverage after the campaign (to visualize the result in a readable HTML report).

---

## `afl-showmap`: the raw bitmap

The lowest-level tool for examining coverage is `afl-showmap`. It runs the instrumented binary with a given input and displays the resulting bitmap — the list of edges traversed.

### Visualizing coverage for a single input

```bash
$ afl-showmap -o /dev/stdout -- ./simple_parser_afl out/default/queue/id:000003,...
```

Output (excerpt):

```
000247:1
003891:1
007142:1
012088:3
018923:1
024510:1
031847:2
```

Each line is an `edge_id:hit_count` pair. The edge identifier is a hash of the two connected basic blocks (cf. the `hash(previous_block XOR current_block)` formula explained in Section 15.2). The counter indicates how many times this transition was taken during execution.

### Comparing coverage between two inputs

```bash
$ afl-showmap -o map_seed1.txt -- ./simple_parser_afl out/default/queue/id:000000,...
$ afl-showmap -o map_seed3.txt -- ./simple_parser_afl out/default/queue/id:000003,...
$ diff map_seed1.txt map_seed3.txt
```

The diff shows edges present in one input but not the other. If `id:000003` covers edges that `id:000000` doesn't, it means the mutation that produced `id:000003` opened a new path — and we can examine both inputs with `xxd` to identify which modified byte caused this path change.

### Cumulative coverage of the entire corpus

To get the total campaign coverage (the union of all edges reached by all inputs):

```bash
$ afl-showmap -C -i out/default/queue/ -o total_coverage.txt \
    -- ./simple_parser_afl @@
```

The `-C` flag enables cumulative mode: `afl-showmap` runs each corpus input and merges the bitmaps. The `total_coverage.txt` file contains all edges reached during the entire campaign, with cumulative counters.

The number of lines in this file is the total number of covered edges:

```bash
$ wc -l total_coverage.txt
47
```

This number, compared to the total number of edges in the program (estimable with `afl-showmap` on a corpus exercising all paths, or via the instrumentation counter displayed at compilation), gives a **binary-level coverage percentage**.

---

## `gcov` and `lcov`: source-level coverage

To get a readable coverage report, line by line, on the source code, we use the `gcov` → `lcov` → `genhtml` chain. This chain is independent of AFL++ — it relies on GCC's coverage instrumentation (`--coverage`).

### Principle

1. Compile the binary with `--coverage` (in addition to AFL++ instrumentation if you want to combine both).  
2. Run the binary with each input from the corpus produced by the fuzzer.  
3. GCC generates `.gcda` files containing per-line execution counters.  
4. `lcov` aggregates these counters into an `.info` file.  
5. `genhtml` transforms the `.info` into a navigable HTML report.

### Compilation with GCC coverage

```bash
$ gcc --coverage -O0 -g -o simple_parser_gcov simple_parser.c
```

The `--coverage` flag is a shortcut for `-fprofile-arcs -ftest-coverage`. It adds line-counting instrumentation and generates a `.gcno` file (static coverage notes) alongside each object file.

> ⚠️ **Warning** — This binary is **not** instrumented for AFL++ (not compiled with `afl-gcc`). It's a separate binary, dedicated to coverage measurement. It's used *after* the fuzzing campaign to replay inputs discovered by AFL++ and measure what fraction of the source code they cover. Both compilations (AFL++ and gcov) coexist without issue.

> 💡 **Why `-O0`?** — Optimizations reorder and merge lines of code, making line coverage difficult to interpret. An `lcov` report on an `-O2` binary will show "uncovered" lines that were actually inlined or eliminated by the optimizer. For readable coverage, always compile with `-O0`.

### Replaying the corpus on the gcov binary

```bash
# Reset counters (important if relaunching)
$ lcov --directory . --zerocounters

# Replay each input from the AFL++ corpus
$ for input in out/default/queue/id:*; do
    ./simple_parser_gcov "$input" 2>/dev/null
  done

# You can also replay crashes to see which lines they traverse
$ for crash in out/default/crashes/id:*; do
    ./simple_parser_gcov "$crash" 2>/dev/null
  done
```

Each execution updates the corresponding `.gcda` file, accumulating coverage counters. After replaying the entire corpus, the `.gcda` files contain the total campaign coverage.

### Generating the report with lcov and genhtml

```bash
# Capture coverage data
$ lcov --directory . --capture --output-file coverage.info

# (Optional) Filter system files and headers
$ lcov --remove coverage.info '/usr/*' --output-file coverage_filtered.info

# Generate the HTML report
$ genhtml coverage_filtered.info --output-directory coverage_report/
```

The report is now viewable in a browser:

```bash
$ firefox coverage_report/index.html
```

### Reading the lcov report

The `genhtml` HTML report has three navigation levels:

**Overview (index).** A table listing each source file with its line and function coverage percentages. For example:

```
Filename                      Lines     Functions
─────────────────────────────────────────────────
simple_parser.c               78.3%     100.0%
```

78.3% of lines were executed at least once, and all functions were reached (but not necessarily in their entirety).

**File view.** Clicking on a file shows the source code with color coding:

- **Green** (with counter) — executed line. The counter indicates how many times.  
- **Red** — never executed line.  
- **White/gray** — non-executable line (comments, braces, declarations).

**Line view.** The counter in the left margin identifies "hot lines" (executed thousands of times, typically the body of a parsing loop) and "cold lines" (executed once or never).

### Interpreting coverage for RE

The red (uncovered) lines are the most interesting. Each red zone is a question to ask:

**Red zone in a rarely-true `if`.** The fuzzer hasn't found an input that satisfies this condition. Look at the condition in Ghidra: is it a checksum? A secondary magic number? A size field with a precise constraint? It's a candidate for manual analysis with Z3 or angr (Chapter 18).

**Red zone in an error handler.** Error handling code is often uncovered because the fuzzer produces inputs that either pass validations or fail very early. Intermediate error handlers (decoding error in the middle of a payload, for example) are harder to reach.

**Red zone in an unknown version branch.** If the parser supports versions 1, 2, and 3, but the fuzzer only produced v1 and v2 inputs, the v3 code is red. Add a seed `RE\x03...` to the corpus and relaunch fuzzing.

**Large green zone with a red island.** A covered code block containing an uncovered line indicates a micro-condition inside a globally reached path. The fuzzer passes through this zone but doesn't trigger this specific condition — often an extreme value check or edge case.

---

## `afl-cov`: automating the coverage pipeline

`afl-cov` is a dedicated tool that automates the `gcov` → `lcov` → `genhtml` pipeline by integrating directly with AFL++'s output. It can run in real time during fuzzing or in post-processing.

### Installation

```bash
$ git clone https://github.com/mrash/afl-cov.git
$ cd afl-cov
# afl-cov is a Python script, no compilation needed
$ ./afl-cov --help
```

Dependencies: `lcov`, `genhtml`, `gcov` (installed via `sudo apt install lcov`).

### Post-processing usage

After a completed AFL++ campaign:

```bash
$ ./afl-cov/afl-cov \
    -d out/default \
    -e "./simple_parser_gcov AFL_FILE" \
    -c . \
    --coverage-cmd "lcov --directory . --capture --output-file cov.info" \
    --genhtml-cmd "genhtml cov.info --output-directory cov_html" \
    --overwrite
```

Main options:

| Option | Role |  
|--------|------|  
| `-d out/default` | AFL++ output directory to analyze |  
| `-e "./simple_parser_gcov AFL_FILE"` | Execution command for the gcov binary; `AFL_FILE` is replaced by each input |  
| `-c .` | Directory containing source code (for line/coverage correlation) |  
| `--overwrite` | Overwrite previous results |

`afl-cov` automatically replays each corpus input and each crash on the gcov binary, accumulates coverage, and produces the final HTML report.

### Real-time usage (live mode)

To monitor coverage while the fuzzer runs:

```bash
# Terminal 1: launch AFL++
$ afl-fuzz -i in -o out -- ./simple_parser_afl @@

# Terminal 2: launch afl-cov in live mode
$ ./afl-cov/afl-cov \
    -d out/default \
    -e "./simple_parser_gcov AFL_FILE" \
    -c . \
    --live
```

The `--live` flag runs `afl-cov` in a loop: it detects new inputs added by AFL++ to the corpus and updates the coverage report incrementally. You can refresh the HTML page in the browser to see coverage evolve in real time.

### `afl-cov` output

`afl-cov` produces several files in the output directory:

```
out/default/cov/
├── web/                    ← genhtml HTML report (navigable)
│   ├── index.html
│   └── ...
├── id-delta-cov/           ← Incremental coverage per input
│   ├── id:000003,...       ← New lines covered by this input
│   └── ...
├── zero-cov/               ← Functions with 0% coverage
└── cov-final.info          ← Aggregated lcov data
```

The `id-delta-cov/` directory is particularly useful: for each corpus input, it lists the source lines **newly covered** by that input (compared to previous inputs). By browsing it in chronological order, you can observe how the fuzzer progressively "unlocked" new code areas.

The `zero-cov/` file lists functions **never reached**. In an RE context, this is a direct guide: these functions deserve manual analysis — why doesn't the fuzzer reach them? Are they called only via a path the fuzzer couldn't take?

---

## libFuzzer coverage: `-print_coverage` and SanitizerCoverage

libFuzzer has its own coverage mechanisms, independent of `gcov`.

### Built-in coverage report

```bash
$ ./fuzz_parse_input -print_coverage=1 -runs=100000 corpus_parse/
```

At the end of execution, libFuzzer displays a summary of covered functions and edges:

```
COVERAGE:
  COVERED_FUNC: parse_input         (7/12 edges)
  COVERED_FUNC: validate_header     (4/4 edges)
  UNCOVERED_FUNC: decode_payload_v3
```

This summary is less detailed than an `lcov` report, but it immediately gives uncovered functions — directly usable for guiding analysis.

### Exporting coverage with SanitizerCoverage

For finer coverage, you can compile with Clang's SanitizerCoverage flags and export data in raw format:

```bash
$ clang -fsanitize=fuzzer,address -fsanitize-coverage=trace-pc-guard,pc-table \
    -g -O1 -o fuzz_parse_input fuzz_parse_input.c parse_input.c
```

Raw coverage data (covered PC addresses) can then be converted to `lcov` reports via scripts like `sancov`:

```bash
# After fuzzing, .sancov files are generated
$ sancov -symbolize fuzz_parse_input *.sancov > coverage_symbolized.txt
```

In practice, for a complete source-level visualization, the `gcov` + `lcov` + `genhtml` chain described above remains more ergonomic. SanitizerCoverage is mostly useful for programmatic analyses (triage scripts, CI/CD integration).

---

## Overlaying coverage on Ghidra disassembly

When sources aren't available (or when you want to correlate coverage with disassembly rather than sources), you can overlay binary coverage data on the function graph in Ghidra.

### Exporting covered addresses

From the AFL++ bitmap or `afl-showmap` output, you can extract the addresses of covered basic blocks. The most direct approach uses `afl-showmap` with verbose mode:

```bash
$ AFL_DEBUG=1 afl-showmap -o /dev/null -- ./simple_parser_afl some_input.bin 2>&1 \
    | grep "edge" > edges_covered.txt
```

Alternatively, with a SanitizerCoverage build, PC addresses are directly available in `.sancov` files.

### Ghidra script to colorize coverage

A Ghidra script (Java or Python) can read the list of covered addresses and colorize the corresponding blocks in the listing or Function Graph. The basic logic:

```python
# Ghidra Python script (simplified)
# Load the list of covered addresses
covered = set()  
with open("/path/to/covered_addresses.txt") as f:  
    for line in f:
        addr = int(line.strip(), 16)
        covered.add(addr)

# Colorize covered blocks in green, uncovered in red
from ghidra.program.model.address import AddressSet  
from java.awt import Color  

listing = currentProgram.getListing()  
for func in currentProgram.getFunctionManager().getFunctions(True):  
    for block in func.getBody().getAddressRanges():
        start = block.getMinAddress().getOffset()
        if start in covered:
            setBackgroundColor(block.getMinAddress(), Color.GREEN)
        else:
            setBackgroundColor(block.getMinAddress(), Color.RED)
```

> 💡 **In practice** — More sophisticated Ghidra scripts exist in the community (for example `lighthouse` for IDA/Binja, or adaptations for Ghidra). The important thing is the principle: the fuzzer's coverage becomes a **visual overlay** on the disassembly, transforming Ghidra into a data-driven navigation tool.

The visual result is striking: in Ghidra's Function Graph, green blocks are those the fuzzer reached, red blocks are the unexplored zones. You can identify at a glance:

- Parser branches the fuzzer managed to take.  
- Blocked branches — often guarded by a precise condition (checksum, signature, secondary magic value).  
- Dead code — blocks that aren't reachable through any path from the entry point.

---

## Interpreting uncovered zones: action strategies

Coverage isn't a goal in itself — it's a **diagnostic**. Each uncovered zone is a question, and the answer determines the next action.

### Identifiable blocking condition

If the uncovered block is guarded by a condition that can be read in Ghidra (for example `if (checksum(data) == data[offset_X])`), the options are:

- **Add a valid seed**: if you understand the calculation, manually craft an input that satisfies the condition and add it to the corpus.  
- **Write a smart harness**: modify the libFuzzer harness to automatically calculate the checksum before calling the target function (cf. Section 15.3, advanced harnesses).  
- **Use symbolic execution**: feed angr or Z3 with the extracted constraint and ask it to generate a satisfying input (cf. Chapter 18).

### External state dependency

If the uncovered block depends on state the fuzzer doesn't control (system clock, environment variable, external configuration file), the options are:

- **Stub the dependency**: in the harness, replace the call to `time()` or `getenv()` with a fixed or input-controlled value.  
- **Use `LD_PRELOAD`**: interpose a library that intercepts system calls and returns deterministic values (cf. Chapter 22, Section 22.4).

### Truly dead code

If no path leads to the uncovered block (no XREF in Ghidra), it's dead code — residue from a previous version, code conditioned on a different platform, or disabled debug functionality. Note it as such and move on.

### Entirely uncovered functions

If an entire function was never reached, check in Ghidra where it's called from (XREF). If it's called only from another function that's itself uncovered, trace back up the chain until you find the blocking point. Often, a single upstream blocking condition "closes" access to an entire function sub-tree.

---

## Measuring progress: when to stop fuzzing

Coverage allows making a rational decision about fuzzing duration. The key indicators:

**Coverage stagnates.** If `afl-cov` in live mode shows no more newly covered lines for 30 minutes (or several hours on a complex program), the fuzzer has likely exhausted the paths reachable with its current strategy. Options: enrich the dictionary (Section 15.6), add manual seeds based on red zones, or modify the harness.

**The coverage percentage is satisfactory.** This threshold depends on context. For a simple parser, 80-90% line coverage is achievable. For a complex program with many conditional branches, 50-60% is already a good result for the fuzzer alone. The remaining 20-40% typically falls to manual analysis or symbolic execution.

**The uncovered zones are identified and understood.** If all red zones have been examined in Ghidra and classified (known blocking condition, dead code, external dependency), you know exactly what the fuzzer can't reach and why. The campaign has fulfilled its role.

**The crash / new coverage ratio decreases.** If the last percentage points of coverage no longer produce crashes, the marginal return of fuzzing diminishes. This doesn't mean there are no more bugs — just that the remaining bugs are in uncovered zones, which require a different approach.

---

## Summary

Code coverage is the bridge between automated fuzzing and manual analysis:

- **`afl-showmap`** gives the raw edge bitmap — useful for comparing individual inputs and measuring binary-level coverage.  
- **`gcov` + `lcov` + `genhtml`** produce a line-by-line HTML report — the most readable format for identifying covered and uncovered zones in source code.  
- **`afl-cov`** automates the pipeline and can run in real time during fuzzing.  
- **Overlay in Ghidra** transforms coverage data into a visual overlay on disassembly — indispensable when sources aren't available.  
- **Interpreting uncovered zones** directly guides next actions: manual seeds, smart harness, symbolic execution, or dead code classification.

Coverage tells us *where* the fuzzer went and *where* it didn't go. The next section covers how to help it go further, by optimizing the **corpus** and providing it with **dictionaries** tailored to the target format.

---


⏭️ [Corpus management and custom dictionaries](/15-fuzzing/06-corpus-dictionaries.md)
