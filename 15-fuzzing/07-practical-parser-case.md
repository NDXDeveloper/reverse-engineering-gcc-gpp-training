🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.7 — Practical case: discovering hidden paths in a binary parser

> 🔗 **Prerequisites**: Sections 15.1 through 15.6 (all techniques covered in this chapter), Chapter 5 (quick triage), Chapter 8 (Ghidra)  
> 📦 **Binary used**: `binaries/ch15-fileformat/` — custom file format parser compiled with GCC  
> 🛠️ **Tools**: AFL++, libFuzzer (Clang), GDB/GEF, `afl-cmin`, `afl-tmin`, `afl-cov`, `lcov`, `strings`, `xxd`, Ghidra, ImHex

---

## Objective

This practical case applies, end to end, the RE-oriented fuzzing methodology built throughout this chapter. The target binary is the custom format parser provided in `binaries/ch15-fileformat/` — the same one that will be analyzed in detail in Chapter 25. Here, we approach it from the fuzzing angle: the goal is not to produce a complete format specification (that's Chapter 25's job), but to **discover as many execution paths as possible** and extract the structural knowledge that the fuzzer reveals.

By the end of this practical case, we will have:

- A minimized corpus that exercises all reachable branches of the parser.  
- A dictionary built from binary analysis.  
- A coverage report identifying covered and uncovered zones.  
- A partial map of the input format, reconstructed solely from fuzzing results.  
- A list of precise questions to take to the in-depth static analysis of Chapter 25.

---

## Phase 1 — Quick triage of the binary

Before fuzzing, we apply the Chapter 5 triage workflow to collect basic information.

### Identification

```bash
$ cd binaries/ch15-fileformat/
$ file fileformat_O0
fileformat_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped  
```

Notable points: 64-bit ELF binary, dynamically linked, PIE enabled, **not stripped** — symbols are present, which will make coverage/function correlation easier.

### Protections

```bash
$ checksec --file=fileformat_O0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All protections are active. For fuzzing, this has no direct impact — we're not trying to exploit but to explore. The canary will trigger a `SIGABRT` (sig:06) on stack buffer overflow, which the fuzzer detects.

### String extraction

```bash
$ strings fileformat_O0 | head -40
```

Among the extracted strings (typical result):

```
Usage: %s <input_file>  
Error: cannot open file  
Error: file too small  
CSTM  
Error: invalid magic  
Error: unsupported version %d  
Parsing header...  
Section type: DATA  
Section type: INDEX  
Section type: META  
Error: unknown section type 0x%02x  
Decoding section at offset %d, length %d  
Error: section length exceeds file size  
Checksum mismatch: expected 0x%08x, got 0x%08x  
Processing complete: %d sections parsed  
```

These strings are an information treasure for the fuzzer:

- Magic bytes: `CSTM` (4 bytes).  
- The format has a version field.  
- Three section types: `DATA`, `INDEX`, `META`.  
- Sections have an offset, a length, and a type encoded on one byte (format `0x%02x`).  
- A **checksum** is verified — this is potentially a major obstacle for the fuzzer.  
- The parser processes sections sequentially.

### Test execution

```bash
$ echo "test" > /tmp/test_input.bin
$ ./fileformat_O0 /tmp/test_input.bin
Error: file too small

$ printf 'CSTM\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > /tmp/test_magic.bin
$ ./fileformat_O0 /tmp/test_magic.bin
Parsing header...  
Error: unsupported version 0  
```

The `CSTM` magic is validated, and the version field is located right after. We're already making progress in understanding the format.

---

## Phase 2 — Building the initial corpus and dictionary

### Initial corpus

From the triage, we build one seed per structural hypothesis:

```bash
$ mkdir corpus_ff

# Seed 1: magic + version 1 + minimal padding (16 bytes)
$ printf 'CSTM\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_ff/v1_minimal.bin

# Seed 2: magic + version 2 + padding
$ printf 'CSTM\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_ff/v2_minimal.bin

# Seed 3: magic + version 1 + larger size (32 bytes)
#   to potentially reach section parsing
$ python3 -c "
import sys  
header = b'CSTM\x01\x00\x00\x00'  
padding = b'\x00' * 24  
sys.stdout.buffer.write(header + padding)  
" > corpus_ff/v1_padded.bin

# Seed 4: attempt with a DATA section type (hypothetical 0x01)
$ python3 -c "
import sys  
header = b'CSTM\x01\x00\x01\x00'  # magic, version 1, 1 section?  
section = b'\x01\x00\x00\x00\x08\x00\x00\x00'  # type=1, length=8?  
data = b'AAAAAAAA'  
sys.stdout.buffer.write(header + section + data)  
" > corpus_ff/v1_one_section.bin
```

These seeds are hypotheses — we don't yet know the exact header structure beyond the magic and version. This is normal: the fuzzer will explore combinations and show us what passes validations.

### Dictionary

```bash
$ cat > dict_fileformat.txt << 'EOF'
# Magic bytes
magic="CSTM"

# Probable versions
v1="\x01"  
v2="\x02"  
v3="\x03"  

# Section types (hypotheses from strings)
# DATA, INDEX, META — numeric values remain to be discovered
type_01="\x01"  
type_02="\x02"  
type_03="\x03"  

# Keywords found in strings
kw_data="DATA"  
kw_index="INDEX"  
kw_meta="META"  

# Boundary values for numeric fields
zero_32="\x00\x00\x00\x00"  
ff_32="\xff\xff\xff\xff"  
one_32="\x01\x00\x00\x00"  
max_short="\xff\xff"  
one_short="\x01\x00"  

# Interesting sizes (small values)
len_8="\x08\x00\x00\x00"  
len_16="\x10\x00\x00\x00"  
len_64="\x40\x00\x00\x00"  
len_256="\x00\x01\x00\x00"  
EOF  
```

This 20-token dictionary combines triage information (`strings`, test execution) and structural hypotheses (32-bit little-endian fields for sizes). It will be enriched after the first results.

---

## Phase 3 — Instrumented compilation

We prepare three builds of the binary:

```bash
# Build 1: AFL++ instrumented (for main fuzzing)
# Build 2: AFL++ instrumented + ASan (for crash triage)
$ cd binaries/ch15-fileformat/
$ make clean
$ make fuzz

# Build 3: GCC with coverage (for lcov report)
$ make coverage
```

The `fuzz` target produces `fileformat_afl` and `fileformat_afl_asan`. The `coverage` target produces `fileformat_gcov`. You can also compile directly without the Makefile:

```bash
$ afl-gcc -O0 -g -o fileformat_afl fileformat.c
$ AFL_USE_ASAN=1 afl-gcc -O0 -g -o fileformat_afl_asan fileformat.c
$ gcc --coverage -O0 -g -o fileformat_gcov fileformat.c
```

Instrumentation verification:

```bash
$ afl-showmap -o /dev/stdout -- ./fileformat_afl corpus_ff/v1_minimal.bin 2>/dev/null | wc -l
12
```

12 edges covered by the first seed — the binary is correctly instrumented and the seed reaches at least a few parser branches.

### libFuzzer build (optional)

If you also want to fuzz with libFuzzer, you need to isolate the parsing function and write a harness. By quickly examining the source (or the disassembly in Ghidra), we identify the main parsing function — let's call it `parse_file`:

```c
// fuzz_fileformat.c — libFuzzer harness
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

// Parsing function prototype (extracted from header or deduced)
int parse_file(const char *filename);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char tmpfile[] = "/dev/shm/fuzz_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return 0;
    write(fd, data, size);
    close(fd);

    parse_file(tmpfile);

    unlink(tmpfile);
    return 0;
}
```

We use `/dev/shm/` (tmpfs in RAM) to avoid disk I/O. Compilation:

```bash
$ clang -fsanitize=fuzzer,address,undefined -g -O1 \
    -o fuzz_fileformat fuzz_fileformat.c fileformat.c
```

---

## Phase 4 — AFL++ fuzzing campaign

### System configuration

```bash
$ echo core | sudo tee /proc/sys/kernel/core_pattern
$ echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null
```

### Launch

```bash
$ afl-fuzz -i corpus_ff -o out_ff -x dict_fileformat.txt \
    -m none -- ./fileformat_afl @@
```

The `-m none` anticipates potential ASan usage in later phases (and doesn't interfere without ASan).

### Observations during fuzzing

After a few minutes, the AFL++ dashboard typically shows:

```
        run time : 0 days, 0 hrs, 5 min, 12 sec
   last new find : 0 days, 0 hrs, 0 min, 8 sec
 corpus count    : 47
 saved crashes   : 5
 map density     : 3.21% / 5.88%
 exec speed      : 4823/sec
```

**What we observe:**

- **47 inputs in the corpus** in 5 minutes — the fuzzer is actively discovering new paths. The dictionary accelerated passing the initial validations (magic, version).  
- **5 crashes** — paths leading to memory errors. To be analyzed in phase 5.  
- **3.21% bitmap coverage** — a relatively small fraction, which is normal for a parser with many branches. There's still space to explore.  
- **4823 exec/s** — good speed for a binary that reads a file from disk.

Let the fuzzer run for 30 minutes to 1 hour. If `last new find` exceeds 10-15 minutes without moving, the fuzzer has probably converged in its current configuration.

### Launch a parallel instance (optional)

In a second terminal:

```bash
$ afl-fuzz -i corpus_ff -o out_ff -x dict_fileformat.txt \
    -S secondary01 -- ./fileformat_afl @@
```

> 💡 **Key observation** — Watch the `corpus count` increase. Each new input in the corpus is a path the fuzzer had never taken before. The first few minutes show rapid growth (the fuzzer passes basic validations), then progress slows down (deeper branches are harder to reach). This slowdown is the signal that the dictionary and corpus could benefit from enrichment.

---

## Phase 5 — Crash analysis

### Inventory

```bash
$ ls out_ff/default/crashes/
README.txt  
id:000000,sig:06,src:000012,time:4231,execs:20147,op:havoc,rep:4  
id:000001,sig:11,src:000023,time:8920,execs:43021,op:havoc,rep:8  
id:000002,sig:06,src:000031,time:12847,execs:62109,op:havoc,rep:2  
id:000003,sig:11,src:000023,time:15203,execs:73488,op:splice,rep:4  
id:000004,sig:06,src:000041,time:22519,execs:108744,op:havoc,rep:16  
```

Two signals present: SIGABRT (sig:06, probably the canary or an `assert`) and SIGSEGV (sig:11, invalid memory access).

### Quick triage with ASan

```bash
$ for crash in out_ff/default/crashes/id:*; do
    echo "=== $(basename $crash) ==="
    ./fileformat_afl_asan "$crash" 2>&1 | grep "^SUMMARY:" || echo "No ASan report"
    echo ""
  done
```

Typical result:

```
=== id:000000,sig:06,... ===
SUMMARY: AddressSanitizer: heap-buffer-overflow fileformat.c:87 in decode_section

=== id:000001,sig:11,... ===
SUMMARY: AddressSanitizer: SEGV fileformat.c:142 in process_index_section

=== id:000002,sig:06,... ===
SUMMARY: AddressSanitizer: heap-buffer-overflow fileformat.c:87 in decode_section

=== id:000003,sig:11,... ===
SUMMARY: AddressSanitizer: SEGV fileformat.c:142 in process_index_section

=== id:000004,sig:06,... ===
SUMMARY: AddressSanitizer: stack-buffer-overflow fileformat.c:201 in validate_checksum
```

We identify **three distinct bugs**:

| Group | Crashes | Function | Type | Line |  
|-------|---------|----------|------|------|  
| A | 000000, 000002 | `decode_section` | heap-buffer-overflow | 87 |  
| B | 000001, 000003 | `process_index_section` | SEGV | 142 |  
| C | 000004 | `validate_checksum` | stack-buffer-overflow | 201 |

### Detailed analysis of crash A

We choose crash 000000 (the smallest in group A) and minimize it:

```bash
$ afl-tmin -i out_ff/default/crashes/id:000000,sig:06,... \
           -o crash_A_min.bin \
           -- ./fileformat_afl @@
```

Examination of the minimized input:

```bash
$ xxd crash_A_min.bin
00000000: 4353 544d 0100 0100 0100 0000 2000 0000  CSTM........  ..
00000010: 4141 4141 4141 4141                      AAAAAAAA
```

Hypothetical interpretation (to verify in GDB):

```
Offset 0x00-0x03 : "CSTM"         — magic (validated)  
Offset 0x04      : 0x01           — version 1 (validated)  
Offset 0x05      : 0x00           — (flags? padding?)  
Offset 0x06-0x07 : 0x01 0x00      — section count = 1 (LE 16-bit)  
Offset 0x08      : 0x01           — section type (DATA = 0x01?)  
Offset 0x09-0x0b : 0x00 0x00 0x00 — (padding? offset?)  
Offset 0x0c-0x0f : 0x20 0x00 0x00 0x00 — declared length = 32 (0x20)  
Offset 0x10-0x17 : "AAAAAAAA"     — payload start (8 actual bytes)  
```

The bug is clear: the section declares a length of 32 bytes (`0x20`), but the file only contains 8 bytes of payload after the section header. The `decode_section` function reads 32 bytes from the payload offset and exceeds the end of the allocated buffer.

### Verification in GDB

```bash
$ gdb -q ./fileformat_afl_asan
(gdb) run crash_A_min.bin
```

The ASan report confirms:

```
READ of size 32 at 0x602000000030
0x602000000030 is located 8 bytes after 24-byte region [0x602000000010,0x602000000028)
```

The 32-byte read starts 8 bytes before the end of the 24-byte buffer — exactly what our interpretation predicted.

### RE knowledge extracted from crash A

This single crash taught us:

- The header structure: magic (4 bytes), version (1 byte), flags/padding (1 byte), section count (2 bytes, LE).  
- The format of a section descriptor: type (1 byte), padding (3 bytes), length (4 bytes, LE).  
- The `decode_section` function reads the payload according to the declared length, without checking that it doesn't exceed the actual file size.  
- Type `0x01` probably corresponds to DATA.

### Quick analysis of crashes B and C

**Crash B** (`process_index_section`, SEGV line 142) — by examining the minimized input, we discover that section type `0x02` (INDEX) triggers different processing that dereferences a pointer calculated from the section's data. An out-of-bounds index in the payload causes the SEGV.

**Crash C** (`validate_checksum`, stack-buffer-overflow line 201) — this crash is particularly interesting: it proves that the parser **calculates and verifies a checksum**. The fuzzer managed to reach the validation function despite the incorrect checksum — probably because the verification happens *after* decoding, not before. The buffer overflow in `validate_checksum` indicates that the working buffer is sized for a fixed number of sections (256), but the header's `section_count` field is not capped — a value greater than 256 causes an out-of-bounds write on the stack.

---

## Phase 6 — Coverage report

### Generating the report

```bash
# Reset counters
$ lcov --directory . --zerocounters

# Replay entire corpus (queue + crashes) on the gcov binary
$ for f in out_ff/default/queue/id:*; do
    ./fileformat_gcov "$f" 2>/dev/null
  done
$ for f in out_ff/default/crashes/id:*; do
    ./fileformat_gcov "$f" 2>/dev/null
  done

# Capture and generate report
$ lcov --directory . --capture --output-file cov_ff.info
$ lcov --remove cov_ff.info '/usr/*' --output-file cov_ff_filtered.info
$ genhtml cov_ff_filtered.info --output-directory cov_report/
$ firefox cov_report/index.html &
```

### Reading the report

Typical result after 30 minutes of fuzzing with targeted corpus and dictionary:

```
Overall coverage rate:
  Lines:     67.3% (148 of 220 lines)
  Functions: 85.7% (12 of 14 functions)
```

**Covered functions (12/14):**

- `main` — 100%  
- `parse_header` — 95% (one unreached version branch)  
- `decode_section` — 88%  
- `process_data_section` — 72%  
- `process_index_section` — 81%  
- `process_meta_section` — 63%  
- `validate_checksum` — 45%  
- ... and a few utility functions at 100%

**Uncovered functions (2/14):**

- `decompress_section` — 0%  
- `verify_signature` — 0%

### Interpreting uncovered zones

**`validate_checksum` at 45%.** The fuzzer reaches the function but doesn't cover all its branches. The uncovered half probably corresponds to the "correct checksum" path — the fuzzer produces inputs with random checksums, so validation systematically fails and the "checksum OK, continue processing" path is never taken. This is the classic obstacle described in Section 15.5.

**`decompress_section` at 0%.** Never called. Checking XREFs in Ghidra, we discover it's called from `decode_section` only when a compression flag is set in the section descriptor. The fuzzer didn't discover this flag — we can add a seed with this flag enabled.

**`verify_signature` at 0%.** Never called. The XREF shows it's called from `parse_header` only for format version 3. The fuzzer explored versions 1 and 2 but didn't generate a valid input for version 3 — or version 3 has additional prerequisites. To explore manually in Ghidra.

---

## Phase 7 — Enrichment and second cycle

Phase 6's results directly guide the next actions.

### Enriching the corpus

```bash
# Seed for version 3 (unlock verify_signature)
$ printf 'CSTM\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_ff/v3_explore.bin

# Seed with compression flag enabled (unlock decompress_section)
# Hypothesis: the flag is bit 7 of the section type field
$ python3 -c "
import sys  
header = b'CSTM\x01\x00\x01\x00'  
section = b'\x81\x00\x00\x00\x10\x00\x00\x00'  # type=0x81 (DATA+compressed?), len=16  
data = b'\x00' * 16  
sys.stdout.buffer.write(header + section + data)  
" > corpus_ff/v1_compressed.bin
```

### Enriching the dictionary

```bash
$ cat >> dict_fileformat.txt << 'EOF'

# Additions after phases 5-6
v3="\x03"  
compressed_flag="\x80"  
type_data_compressed="\x81"  
type_index_compressed="\x82"  
type_meta_compressed="\x83"  
EOF  
```

### Minimize and relaunch

```bash
# Minimize the accumulated corpus
$ afl-cmin -i out_ff/default/queue/ -o corpus_ff_min -- ./fileformat_afl @@

# Add the new seeds
$ cp corpus_ff/v3_explore.bin corpus_ff/v1_compressed.bin corpus_ff_min/

# Relaunch fuzzing with the enriched corpus
$ rm -rf out_ff_v2
$ afl-fuzz -i corpus_ff_min -o out_ff_v2 -x dict_fileformat.txt \
    -m none -- ./fileformat_afl @@
```

After this second cycle, we expect coverage to increase — particularly in `decompress_section` and `verify_signature` if our hypotheses about the compression flag and version 3 are correct.

If `validate_checksum` coverage still stagnates, that's the signal that a libFuzzer harness with automatic checksum calculation is needed — or that symbolic execution (Chapter 18) must be brought in to solve the constraint.

---

## Summary of acquired knowledge

After two fuzzing cycles totaling approximately 1 to 2 hours, here's what the fuzzer revealed about the `ch15-fileformat` format — **without having read a single line of source code or in-depth disassembly**:

### Format structure (reconstructed)

```
┌─────────────────────────────────────────────────────┐
│                    FILE HEADER                      │
├──────────┬──────────┬────────────┬──────────────────┤
│  Magic   │ Version  │   Flags    │  Section Count   │
│  4 bytes │  1 byte  │   1 byte   │   2 bytes (LE)   │
│  "CSTM"  │  1,2,3   │   (TBD)    │                  │
├──────────┴──────────┴────────────┴──────────────────┤
│                                                     │
│              SECTION DESCRIPTOR (×N)                │
├──────────┬──────────────────┬───────────────────────┤
│   Type   │    Padding (3B)  │   Length (4B, LE)     │
│  1 byte  │                  │                       │
│  0x01=DATA  0x02=INDEX  0x03=META                   │
│  bit 7 = compression flag (hypothesis)              │
├──────────┴──────────────────┴───────────────────────┤
│                                                     │
│                 SECTION PAYLOAD                     │
│            (Length bytes per section)               │
│                                                     │
├─────────────────────────────────────────────────────┤
│                    CHECKSUM                         │
│        (position and algorithm to be determined)    │
└─────────────────────────────────────────────────────┘
```

### Identified bugs

| ID | Function | Type | Cause |  
|----|----------|------|-------|  
| A | `decode_section` | heap overflow read | Section length not validated vs file size |  
| B | `process_index_section` | null/OOB deref | Index in payload used without verification |  
| C | `validate_checksum` | stack overflow write | 1024-byte buffer indexed by section_count (max 65535) without bound |

### Open questions (to take to Chapter 25)

The following questions were not resolved by fuzzing and require in-depth static analysis:

1. **Checksum algorithm** — which function is used (CRC32? simple sum? custom?) and at which offset is the checksum field in the file?  
2. **Version 3 format** — what additional fields are expected? What does `verify_signature` do exactly?  
3. **Compression algorithm** — does `decompress_section` use zlib, LZ4, or a custom algorithm?  
4. **Internal structure of INDEX and META sections** — crashes showed they have specific processing, but the format of their payload remains to be documented.  
5. **Exact role of the flags field (offset 0x05)** — no crash directly involved this field.

These questions are targeted entry points for Ghidra: instead of reading the binary end to end, you know exactly which functions to examine and what data to look for.

---

## Methodological recap

This practical case followed the complete RE-oriented fuzzing cycle:

```
Phase 1 — Quick triage
    │   file, strings, checksec, test execution
    ▼
Phase 2 — Initial corpus + dictionary
    │   Targeted seeds per branch, tokens from strings and Ghidra
    ▼
Phase 3 — Instrumented compilation
    │   afl-gcc, afl-gcc+ASan, gcc --coverage
    ▼
Phase 4 — Fuzzing campaign
    │   afl-fuzz with dictionary, dashboard monitoring
    ▼
Phase 5 — Crash analysis
    │   ASan triage, minimization, GDB analysis, RE info extraction
    ▼
Phase 6 — Coverage report
    │   lcov + genhtml, identification of uncovered zones
    ▼
Phase 7 — Enrichment and second cycle
    │   New seeds, tokens, relaunch — iterate until convergence
    ▼
Summary — Reconstructed format, documented bugs, targeted questions
```

Each phase feeds the next. Phase 5 crashes produce knowledge injected into the phase 7 corpus. Phase 6 coverage identifies blocked branches that guide new seeds. The process is iterative and converges toward an increasingly complete understanding of the binary.

Fuzzing didn't produce a complete format specification — that's not its role. But in 1 to 2 hours, it provided a structural skeleton, three analyzable bugs, and five precise questions to resolve. The analyst who opens Ghidra after this campaign knows exactly where to look and why. That's the value fuzzing adds to a reverse engineering workflow.

---


⏭️ [Checkpoint: fuzz `ch23-fileformat` with AFL++, find at least 2 crashes and analyze them](/15-fuzzing/checkpoint.md)
