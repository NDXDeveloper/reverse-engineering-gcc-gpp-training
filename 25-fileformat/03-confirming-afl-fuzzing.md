🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 25.3 — Confirming the Interpretation with AFL++ (Parser Fuzzing)

> 🎯 **Objective of this section**: use coverage-guided fuzzing to validate and supplement our understanding of the CFR format. The crashes and code paths discovered by AFL++ reveal parser constraints that hexadecimal analysis alone could not highlight — maximum sizes, forbidden values, validation order, edge cases.

---

## Why Fuzz Now?

At this point, we have a `.hexpat` pattern that covers every byte of a valid CFR archive. We know the structure of the header, records, and footer. But this understanding was built exclusively from **well-formed** files — those that the binary itself produced. We have no idea what happens when the parser encounters invalid data.

Yet the parser's validation constraints are an integral part of a format's specification. A `num_records` field that cannot exceed a certain value, a `name_len` of zero that triggers different behavior, an incorrect CRC that causes rejection — all of this defines what a valid CFR file is just as much as the field layout does.

Fuzzing is the ideal tool for exploring these constraints. AFL++ will mutate our reference archives, submit the variants to the parser, and observe which ones cause crashes, timeouts, or new code paths. Each crash is a window into an aspect of the parser we had not yet mapped.

It is also a robustness test for our understanding. If the parser accepts files that our `.hexpat` pattern would consider invalid, then our model is too restrictive. If the parser rejects files that our model considers valid, then there are additional constraints to document.

---

## Preparing the Fuzzing

### Recompiling with AFL++ Instrumentation

AFL++ needs a version of the binary compiled with its own instrumented compiler (`afl-gcc` or `afl-clang-fast`). The instrumentation inserts probes at every code branch, which allows AFL++ to measure code coverage on each execution.

```bash
$ cd binaries/ch25-fileformat/
$ CC=afl-gcc make clean fileformat_O0
```

Or, if `afl-clang-fast` is available (recommended for better performance):

```bash
$ CC=afl-clang-fast make clean fileformat_O0
```

We compile with `-O0` for fuzzing: optimizations reduce the number of instrumented branches and can hide interesting paths. The resulting binary is slower but offers more granular coverage.

> 💡 **Why `-O0` for fuzzing?** With `-O2` or `-O3`, the compiler merges branches, eliminates dead code, and inlines functions. From the fuzzer's perspective, this reduces the number of visible "forks" and thus the ability to distinguish different execution paths. For bug and path discovery, `-O0` is preferable. For performance fuzzing (throughput), one would favor `-O2` with `afl-clang-lto`.

### Choosing the Target Subcommand

Our binary supports several subcommands (`list`, `read`, `validate`, `unpack`). Each one traverses the parser differently:

- **`validate`** is the most natural choice: it is the subcommand that checks the most constraints (header CRC, per-record CRC, reserved, footer). It traverses the entire file and validates every invariant. It is the one that will expose the most validation logic.  
- **`read`** traverses the full parser and displays the contents — useful for detecting bugs in XOR decoding.  
- **`list`** only traverses the metadata — lower coverage but faster execution.

We will fuzz `validate` first, then potentially `read` in a second pass.

### Building the Initial Corpus

AFL++ needs a corpus of starting files (seed corpus) that will be mutated. The quality of the initial corpus directly influences the speed of discovery. We will use our three existing archives plus a few minimal variants:

```bash
$ mkdir -p fuzz/input fuzz/output

# Main corpus: our generated archives
$ cp samples/demo.cfr          fuzz/input/seed_demo.cfr
$ cp samples/packed_noxor.cfr  fuzz/input/seed_noxor.cfr
$ cp samples/packed_xor.cfr    fuzz/input/seed_xor.cfr
```

It is also useful to create a **minimal** file — an archive with a single record containing empty or very short content. The smaller the base file, the more likely AFL++ mutations are to hit structural fields rather than data:

```bash
# Minimal archive: a single text record, no XOR, short content
$ echo -n "A" > /tmp/tiny.txt
$ ./fileformat_O0 pack /tmp/minimal.cfr /tmp/tiny.txt
$ cp /tmp/minimal.cfr fuzz/input/seed_minimal.cfr
```

### Writing a Dictionary

An AFL++ dictionary is a text file that lists tokens relevant to the format. The fuzzer will use these tokens as building blocks during mutations, which significantly accelerates path discovery in binary parsers.

Let's create `fuzz/cfr.dict` based on what we know about the format:

```
# fuzz/cfr.dict — Tokens for the CFR format

# Magic bytes
"CFRM"
"CRFE"

# Record types
"\x01"
"\x02"
"\x03"

# Common flags
"\x00\x00"
"\x01\x00"
"\x02\x00"
"\x03\x00"

# Known versions
"\x02\x00"

# Frequent sizes (little-endian)
"\x00\x00\x00\x00"
"\x01\x00\x00\x00"
"\x04\x00\x00\x00"
"\xff\xff\xff\xff"

# XOR key (may appear in data)
"\x5a\x3c\x96\xf1"

# Null padding
"\x00\x00\x00\x00\x00\x00\x00\x00"
```

The dictionary contains the magic bytes, known type values, flags, and limit sizes (`0` and `0xFFFFFFFF`). Extreme values are particularly interesting: they often trigger integer overflows or failed allocations in the parser.

---

## Launching AFL++

### Basic Command

AFL++ needs to know how to invoke the binary with an input file. The `@@` symbol will be replaced by the path to the mutated file:

```bash
$ afl-fuzz -i fuzz/input \
           -o fuzz/output \
           -x fuzz/cfr.dict \
           -- ./fileformat_O0 validate @@
```

Option breakdown:

| Option | Role |  
|--------|------|  
| `-i fuzz/input` | Initial corpus directory |  
| `-o fuzz/output` | Output directory (queues, crashes, hangs) |  
| `-x fuzz/cfr.dict` | Token dictionary |  
| `--` | Separator between AFL++ options and the target command |  
| `./fileformat_O0 validate @@` | Command to execute; `@@` = mutated file |

### Reading the Dashboard

After a few seconds, AFL++ displays its dashboard:

```
       american fuzzy lop ++4.09a {default} (./fileformat_O0)
┌─ process timing ────────────────────────────────────┐
│        run time : 0 days, 0 hrs, 2 min, 34 sec      │
│   last new find : 0 days, 0 hrs, 0 min, 12 sec      │
│   last uniq crash : 0 days, 0 hrs, 1 min, 47 sec    │
├─ overall results ───────────────────────────────────┤
│  cycles done : 3                                    │
│ corpus count : 47       (initially: 4)              │
│  saved crashes : 5                                  │
│  saved hangs : 0                                    │
├─ map coverage ──────────────────────────────────────┤
│    map density : 4.21% / 6.83%                      │
│ count coverage : 2.18 bits/tuple                    │
└─────────────────────────────────────────────────────┘
```

Key metrics to monitor:

**`corpus count`** — the number of files in the queue. Each entry represents a file that triggered a new code path. Going from 4 (our seeds) to 47 means AFL++ found 43 mutations that cover previously unseen branches of the parser.

**`saved crashes`** — the number of files that crash the binary. Each crash is an entry in `fuzz/output/default/crashes/`.

**`saved hangs`** — files that cause a timeout. A hang in a parser can indicate an infinite loop triggered by a malformed size field.

**`map density`** — the percentage of the coverage map that is filled. The higher it is, the more branches of the binary AFL++ has explored.

**`last new find`** — the time elapsed since the last discovery of a new path. When this value stagnates for a long time (several hours), the fuzzer has likely reached a plateau.

### How Long Should It Run?

For a parser of this size, a few minutes to an hour is enough to obtain usable results. Reasonable stopping criteria:

- The `cycles done` counter has exceeded 5–10 (AFL++ has traversed the corpus multiple times).  
- The `last new find` exceeds 15–20 minutes without a new path.  
- Several crashes have been found.

For format reverse engineering, we are not seeking the exhaustiveness of security fuzzing. We are looking for representative crashes that reveal the validation logic.

---

## Analyzing the Crashes

### Sorting and Reproducing

Each crash is found in `fuzz/output/default/crashes/` as a binary file. Let's reproduce them:

```bash
$ ls fuzz/output/default/crashes/
id:000000,sig:06,src:000001,time:12345,execs:67890,op:havoc,rep:4  
id:000001,sig:11,src:000003,time:23456,execs:98765,op:flip1,rep:2  
...
```

The filename contains useful metadata: `sig:06` = signal 6 (SIGABRT, often an `assert` or an `abort`), `sig:11` = signal 11 (SIGSEGV, invalid memory access), `op:havoc` / `op:flip1` = the mutation strategy that produced the crash.

Let's reproduce each crash:

```bash
$ for crash in fuzz/output/default/crashes/id:*; do
    echo "=== $crash ==="
    ./fileformat_O0 validate "$crash" 2>&1 | head -5
    echo "---"
done
```

### Classifying the Crashes

After reproduction, we classify the crashes by category. Here are the common types for a format parser:

**Size-related crashes** — an absurd `name_len` or `data_len` (e.g., `0xFFFFFFFF`) causes a massive allocation or a buffer overflow. This tells us that the parser does not check (or insufficiently checks) sizes before using them.

```bash
# Examine a crash in ImHex or xxd
$ xxd fuzz/output/default/crashes/id:000000 | head -8
```

If we observe a `data_len` of `0xFFFF0000` in the crash, this confirms that the parser uses this value directly in a `malloc` or `fread` without bounds checking.

**Record count-related crashes** — a very large `num_records` causes the parser to read beyond the allocated space. This tells us whether there is a maximum (the `MAX_RECORDS` constant in the source code, which we do not yet know at this stage).

**Magic-related crashes** — a corrupted magic can trigger an interesting error path. If the parser cleanly rejects an invalid magic (error message, non-zero return code) rather than crashing, it is a "non-crash" path that remains informative: it confirms that magic validation is the first step of parsing.

**Footer-related crashes** — a file truncated before the footer, or a footer with an inconsistent `total_size`, can reveal the order in which the parser checks invariants.

### Examining a Crash in Detail

Let's take a concrete crash. The crashing file has a `num_records` mutated to a high value (for example `0x00010000` = 65536). The parser allocates an array accordingly, then tries to read 65536 record headers from a file that only contains 4. Result: reading past the end of the file, memory corruption, SIGSEGV.

This crash teaches us two things about the format:

1. **The parser trusts `num_records` to size its structures** — there is no dynamic discovery mechanism (the parser does not scan the file up to the footer to count the records).  
2. **There is probably a `MAX_RECORDS` in the code** — by mutating `num_records` progressively, we can find the threshold value beyond which the parser refuses the file (before even crashing).

Let's test:

```bash
# Create a file with num_records = 1025 (copy of demo.cfr, manual mutation)
$ python3 -c "
import struct  
with open('samples/demo.cfr', 'rb') as f:  
    data = bytearray(f.read())
# num_records is at offset 0x08, little-endian u32
struct.pack_into('<I', data, 0x08, 1025)  
with open('/tmp/test_1025.cfr', 'wb') as f:  
    f.write(data)
"
$ ./fileformat_O0 validate /tmp/test_1025.cfr
```

If 1025 is rejected with a message `"Too many records"` but 1024 is not, we have found the constant `MAX_RECORDS = 1024` (the parser accepts values ≤ 1024 and rejects beyond). This information enriches our specification.

---

## Exploiting the Queue (Non-Crashes)

Crashes are not the only interesting results. The directory `fuzz/output/default/queue/` contains all the files that triggered a new code path *without* crashing. These are files that the parser processed differently from our initial seeds.

```bash
$ ls fuzz/output/default/queue/ | wc -l
47
```

Some of these files are archives with unusual characteristics that the parser handles silently:

- A record with `data_len = 0` (empty content).  
- A `name_len = 0` (empty name).  
- An unknown type (e.g., `type = 0xFF`) that the parser accepts without error.  
- The `has_footer` flag disabled (bit 1 set to 0) — the parser stops after the last record.  
- A non-zero `record.flags` — the parser ignores it, but the field exists.

Each queue entry can be examined in ImHex with our pattern to verify whether it remains structurally consistent. Entries that are parsed without crashing but whose structure deviates from our model are the most instructive: they reveal parser tolerances we had not anticipated.

```bash
# List queue files sorted by size (the smallest ones
# are often the most structurally interesting)
$ ls -lS fuzz/output/default/queue/ | tail -20
```

---

## Measuring Coverage

To know which parts of the parser were explored by the fuzzer (and especially which were not), we can generate a code coverage report.

### Recompiling with Coverage Profiling

```bash
$ make clean
$ CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage" make fileformat_O0
```

### Replaying the Corpus

```bash
# Replay all files from the queue and crashes
$ for f in fuzz/output/default/queue/id:* fuzz/output/default/crashes/id:*; do
    ./fileformat_O0 validate "$f" 2>/dev/null
done
```

Each execution increments the counters in the `.gcda` files generated by `gcc`.

### Generating the Report

```bash
$ lcov --capture --directory . --output-file coverage.info
$ genhtml coverage.info --output-directory coverage_report/
$ xdg-open coverage_report/index.html
```

The HTML report shows line by line which parts of the source code were executed. Uncovered areas are clues to paths the fuzzer was unable to reach — perhaps branches protected by complex CRC conditions, or paths related to non-fuzzed subcommands (`unpack`, `read`).

> 📝 **Note**: this step requires having the source code, which assumes a context such as an audit or CTF where the source is available for verification purposes. In a pure reverse engineering scenario without source, coverage is not directly measurable, but the crashes and queue paths remain equally informative.

---

## Summary: What Fuzzing Revealed

After a fuzzing session, our understanding of the CFR format has been enriched with validation constraints that were not visible in the hexadecimal analysis. Let's update the notebook:

```markdown
## Constraints Discovered Through Fuzzing

### Size Limits
- num_records: maximum 1024 (rejected beyond)
- name_len: accepted at 0 (empty name, no crash)
- data_len: very large values → crash (no explicit bound
  in the parser, potential vulnerability)

### Parser Validation Order
1. Read and verify the magic "CFRM"
2. Verify num_records ≤ MAX_RECORDS
3. Sequential reading of records (trusts num_records)
4. For each record: read name_len, name, data_len, data, crc16
5. If footer flag: read and verify the footer

### Tolerances
- record.flags: ignored by the parser (always read, never checked)
- record.type: unknown values accepted without error
- header.version: not checked (a version 0xFFFF is parsed normally)
- If the header CRC is wrong: the parser displays a warning
  but continues parsing (non-blocking in "read"/"list" mode,
  blocking in "validate" mode)

### Footer Behavior
- If has_footer is 0: the parser stops after the last record
- If has_footer is 1 but the footer is absent/truncated:
  warning in validate mode, ignored otherwise
```

### Updating the `.hexpat` Pattern

The fuzzing discoveries may require adjustments to the pattern. For example, if we confirmed that `name_len = 0` is valid, we make sure our pattern handles it (a `char name[0]` in `.hexpat` is not a problem). If we discovered that types beyond `0x03` are accepted, we can add an `UNKNOWN` case to the enum:

```hexpat
enum RecordType : u8 {
    TEXT    = 0x01,
    BINARY  = 0x02,
    META    = 0x03
    // Values > 0x03 accepted by the parser without error
};
```

### What Remains to Be Confirmed

Fuzzing does not solve everything. Some questions remain open and will be addressed in the following sections:

- **CRC-16 precision** — fuzzing showed that incorrect CRCs are rejected in `validate` mode, but we have not yet implemented the exact calculation to verify it ourselves.  
- **XOR behavior on edge cases** — is a record with `data_len = 0` and the XOR flag active handled without error?  
- **Contents of the `reserved` field** — fuzzing showed that an inconsistent value is detected in `validate` mode, which confirms that it is not simple padding.

These points will be addressed in section 25.4 (Python parser), where the complete implementation will serve as a definitive test for each constraint.

---


⏭️ [Writing an Independent Python Parser/Serializer](/25-fileformat/04-parser-python.md)
