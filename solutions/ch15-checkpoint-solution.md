🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 15 Checkpoint: Fuzzing for Reverse Engineering

> **Spoilers** — This file contains the complete checkpoint solution. Try the checkpoint yourself before consulting this solution.  
> **Binary**: `binaries/ch15-fileformat/`

---

## Deliverable 1 — Instrumented Compilation

### AFL++ Build (main fuzzing)

```bash
$ cd binaries/ch15-fileformat/
$ make clean
$ make fuzz
```

This produces `fileformat_afl` (standard instrumentation) and `fileformat_afl_asan` (instrumentation + ASan). If `afl-gcc` is not found, you can override with `make fuzz AFL_CC=/path/to/afl-gcc`, or compile directly:

```bash
$ afl-gcc -O0 -g -o fileformat_afl fileformat.c
```

Expected output during compilation:

```
[+] Instrumented X locations (non-hardened mode, ratio 100%).
```

The exact number of locations varies by code, but must be greater than 0.

### ASan Build (crash triage)

If the `make fuzz` target was already run, `fileformat_afl_asan` is already available. Otherwise:

```bash
$ AFL_USE_ASAN=1 afl-gcc -O0 -g -o fileformat_afl_asan fileformat.c
```

### gcov Build (coverage — optional but recommended)

```bash
$ make coverage
```

Or directly:

```bash
$ gcc --coverage -O0 -g -o fileformat_gcov fileformat.c
```

### Verification

```bash
$ echo -ne 'CSTM\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > /tmp/test_seed.bin
$ afl-showmap -o /dev/stdout -- ./fileformat_afl /tmp/test_seed.bin 2>/dev/null | head -5
```

The output should display several lines in `NNNNN:N` format — these are the edges covered by this seed. If the output is empty, instrumentation failed (verify that `afl-gcc` is in the PATH and that compilation produced the `Instrumented X locations` message).

---

## Deliverable 2 — Initial Corpus and Dictionary

### Preliminary Triage

```bash
$ file fileformat_afl
fileformat_afl: ELF 64-bit LSB pie executable, x86-64, ...

$ strings fileformat_afl | grep -iE "error|invalid|usage|section|magic|version|checksum"
```

Typically found relevant strings:

```
Usage: %s <input_file>  
Error: file too small  
CSTM  
Error: invalid magic  
Error: unsupported version %d  
Section type: DATA  
Section type: INDEX  
Section type: META  
Error: unknown section type 0x%02x  
Decoding section at offset %d, length %d  
Error: section length exceeds file size  
Checksum mismatch: expected 0x%08x, got 0x%08x  
Processing complete: %d sections parsed  
```

Quick verification by execution:

```bash
$ echo "AAAA" | ./fileformat_afl /dev/stdin
Error: file too small

$ echo -ne 'CSTM\x01\x00\x00\x00' | ./fileformat_afl /dev/stdin
Parsing header...
```

The `CSTM` magic is confirmed, and version `\x01` passes the first validation.

### Initial Corpus (5 seeds)

```bash
$ mkdir corpus_initial

# Seed 1: version 1, minimal size (16 bytes)
$ printf 'CSTM\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    > corpus_initial/s01_v1_minimal.bin

# Seed 2: version 2, minimal size
$ printf 'CSTM\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    > corpus_initial/s02_v2_minimal.bin

# Seed 3: version 1, 1 DATA section (0x01), length 8
$ python3 -c "
import sys  
header  = b'CSTM'          # magic  
header += b'\x01'           # version 1  
header += b'\x00'           # flags  
header += b'\x01\x00'       # section_count = 1 (LE 16-bit)  
section = b'\x01'           # type = DATA  
section += b'\x00\x00\x00'  # padding  
section += b'\x08\x00\x00\x00'  # length = 8 (LE 32-bit)  
payload = b'AAAAAAAA'       # 8 bytes of data  
sys.stdout.buffer.write(header + section + payload)  
" > corpus_initial/s03_v1_data_section.bin

# Seed 4: version 1, 1 INDEX section (0x02), length 16
$ python3 -c "
import sys  
header  = b'CSTM\x01\x00\x01\x00'  
section = b'\x02\x00\x00\x00\x10\x00\x00\x00'  # type=INDEX, length=16  
payload = b'\x00' * 16  
sys.stdout.buffer.write(header + section + payload)  
" > corpus_initial/s04_v1_index_section.bin

# Seed 5: version 1, 1 META section (0x03), length 8
$ python3 -c "
import sys  
header  = b'CSTM\x01\x00\x01\x00'  
section = b'\x03\x00\x00\x00\x08\x00\x00\x00'  # type=META, length=8  
payload = b'METADATA'  
sys.stdout.buffer.write(header + section + payload)  
" > corpus_initial/s05_v1_meta_section.bin
```

Verification that seeds take different paths:

```bash
$ afl-showmap -o map_s01.txt -- ./fileformat_afl corpus_initial/s01_v1_minimal.bin 2>/dev/null
$ afl-showmap -o map_s03.txt -- ./fileformat_afl corpus_initial/s03_v1_data_section.bin 2>/dev/null
$ afl-showmap -o map_s04.txt -- ./fileformat_afl corpus_initial/s04_v1_index_section.bin 2>/dev/null

$ wc -l map_s01.txt map_s03.txt map_s04.txt
  12 map_s01.txt
  23 map_s03.txt
  27 map_s04.txt
```

Bitmaps have different sizes — each seed covers a distinct number of edges, confirming they take different paths through the parser.

### Dictionary (18 tokens)

```bash
$ cat > dict_ch25.txt << 'EOF'
# === Magic ===
magic="CSTM"

# === Versions ===
v1="\x01"  
v2="\x02"  
v3="\x03"  

# === Section types ===
type_data="\x01"  
type_index="\x02"  
type_meta="\x03"  

# === Keywords (in case the parser handles text) ===
kw_data="DATA"  
kw_index="INDEX"  
kw_meta="META"  

# === Boundary numeric values (32-bit LE fields) ===
zero_32="\x00\x00\x00\x00"  
one_32="\x01\x00\x00\x00"  
ff_32="\xff\xff\xff\xff"  
max_short="\xff\xff"  

# === Typical sizes ===
len_16="\x10\x00\x00\x00"  
len_256="\x00\x01\x00\x00"  
EOF  
```

---

## Deliverable 3 — Fuzzing Campaign

### System Configuration

```bash
$ echo core | sudo tee /proc/sys/kernel/core_pattern
```

### Launch

```bash
$ afl-fuzz -i corpus_initial -o out_ch15 -x dict_ch25.txt \
    -m none -- ./fileformat_afl @@
```

### Expected Result After 15-30 Minutes

The AFL++ dashboard should display values in these orders of magnitude:

```
        run time : 0 days, 0 hrs, 20 min, ...
   last new find : 0 days, 0 hrs, 0-5 min, ...
 corpus count    : 30-80
 saved crashes   : 2-10
 map density     : 2-6%
 exec speed      : 1000-8000/sec
```

Exact values depend on the machine and binary. The key is to exceed the checkpoint thresholds: `corpus count >= 20` and `saved crashes >= 2`.

If after 10 minutes `corpus count` stagnates below 10 and there are 0 crashes, check:

- Are the seeds correctly constructed? (Run them manually on the non-instrumented binary to see if the parser accepts them.)  
- Is the dictionary loaded? (AFL++ displays `Loaded N tokens from dict_ch25.txt` at startup.)  
- Is the binary properly instrumented? (The `Instrumented X locations` message appeared during compilation.)

### Stopping the Campaign

Stop with `Ctrl+C` once thresholds are reached. The campaign can also be left running longer to accumulate more crashes and coverage.

### Threshold Verification

```bash
$ ls out_ch15/default/queue/id:* | wc -l
47

$ ls out_ch15/default/crashes/id:* 2>/dev/null | wc -l
5
```

47 inputs in the corpus and 5 crashes — thresholds are well exceeded.

---

## Deliverable 4 — Detailed Analysis of 2 Crashes

### Inventory and Triage

```bash
$ for crash in out_ch15/default/crashes/id:*; do
    echo "=== $(basename "$crash") ($(wc -c < "$crash") bytes) ==="
    ./fileformat_afl_asan "$crash" 2>&1 | grep "^SUMMARY:" || echo "No ASan report"
    echo ""
  done
```

Typical output:

```
=== id:000000,sig:06,src:000008,time:3241,... (28 bytes) ===
SUMMARY: AddressSanitizer: heap-buffer-overflow fileformat.c:87 in decode_section

=== id:000001,sig:11,src:000019,time:7830,... (34 bytes) ===
SUMMARY: AddressSanitizer: SEGV fileformat.c:142 in process_index_section

=== id:000002,sig:06,src:000024,time:11205,... (26 bytes) ===
SUMMARY: AddressSanitizer: heap-buffer-overflow fileformat.c:87 in decode_section

=== id:000003,sig:11,src:000019,time:14782,... (41 bytes) ===
SUMMARY: AddressSanitizer: SEGV fileformat.c:142 in process_index_section

=== id:000004,sig:06,src:000037,time:21490,... (52 bytes) ===
SUMMARY: AddressSanitizer: stack-buffer-overflow fileformat.c:201 in validate_checksum
```

Three distinct bug groups:

| Group | Crashes | Function | Type |  
|-------|---------|----------|------|  
| A | 000000, 000002 | `decode_section` | heap-buffer-overflow |  
| B | 000001, 000003 | `process_index_section` | SEGV |  
| C | 000004 | `validate_checksum` | stack-buffer-overflow |

We analyze in detail one representative from group A and one from group B (the two most frequent).

---

### Crash A — `decode_section`: heap-buffer-overflow

#### Minimization

```bash
$ afl-tmin -i out_ch15/default/crashes/id:000000,sig:06,... \
           -o crash_A_min.bin \
           -- ./fileformat_afl @@
```

```bash
$ wc -c out_ch15/default/crashes/id:000000,sig:06,...
28
$ wc -c crash_A_min.bin
18
```

The input goes from 28 to 18 bytes.

#### Hexadecimal Examination

```bash
$ xxd crash_A_min.bin
00000000: 4353 544d 0100 0100 0100 0000 2000 0000  CSTM........  ..
00000010: 4100                                     A.
```

#### Field Interpretation

```
Offset  Hex             Interpretation
------  --------------  -----------------------------------------
0x00    43 53 54 4d     Magic "CSTM" — validated by parse_header
0x04    01              Version = 1 — v1 branch
0x05    00              Flags = 0 (no special flag)
0x06    01 00           Section count = 1 (uint16_t LE)
0x08    01              Section type = 0x01 (DATA)
0x09    00 00 00        Padding / reserved
0x0c    20 00 00 00     Declared length = 32 (uint32_t LE)
0x10    41 00           Actual payload: only 2 bytes
```

The bug: the declared length (32 bytes) far exceeds the actual payload (2 bytes). The `decode_section` function attempts to read 32 bytes from offset 0x10, causing an out-of-bounds access on the heap buffer.

#### GDB Trace

```bash
$ gdb -q ./fileformat_afl_asan
(gdb) run crash_A_min.bin
```

ASan report:

```
==XXXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000XX
READ of size 32 at 0x6020000000XX thread T0
    #0 0xXXXXXX in decode_section fileformat.c:87
    #1 0xXXXXXX in parse_sections fileformat.c:113
    #2 0xXXXXXX in main fileformat.c:178
```

Relaunch with a breakpoint at the beginning of `decode_section` to trace the path:

```
(gdb) break decode_section
(gdb) run crash_A_min.bin

Breakpoint 1, decode_section (...)
(gdb) backtrace
#0  decode_section (data=..., offset=16, length=32, type=1) at fileformat.c:80
#1  parse_sections (file_data=..., file_size=18, header=...) at fileformat.c:113
#2  main (argc=2, argv=...) at fileformat.c:178
```

The `decode_section` function is called with `offset=16`, `length=32`, and `type=1`. The total `file_size` is 18. Reading 32 bytes at offset 16 exceeds the file end (16 + 32 = 48 > 18).

#### Reconstructed Condition Path

```
main()
  -> file opened, read into memory (18 bytes)
  -> parse_header()
      -> file_size >= 8            Y (18 >= 8)
      -> magic == "CSTM"          Y
      -> version == 1              Y
      -> section_count = 1         (read at offset 0x06, uint16_t LE)
  -> parse_sections()
      -> for each section (i=0..0):
          -> type = data[8] = 0x01 (DATA)
          -> length = *(uint32_t*)(data+12) = 32
          -> decode_section(data, offset=16, length=32, type=1)
              -> memcpy(buf, data+16, 32)   <- CRASH: 16+32 > 18
```

#### RE Knowledge Extracted

- The header is 8 bytes: magic (4) + version (1) + flags (1) + section_count (2).  
- Each section descriptor is 8 bytes: type (1) + padding (3) + length (4).  
- The payload begins immediately after the descriptor.  
- The `decode_section` function does not check that `offset + length <= file_size`.

---

### Crash B — `process_index_section`: SEGV

#### Minimization

```bash
$ afl-tmin -i out_ch15/default/crashes/id:000001,sig:11,... \
           -o crash_B_min.bin \
           -- ./fileformat_afl @@
```

```bash
$ wc -c crash_B_min.bin
24
```

#### Hexadecimal Examination

```bash
$ xxd crash_B_min.bin
00000000: 4353 544d 0100 0100 0200 0000 0800 0000  CSTM............
00000010: ff00 0000 0000 0000                      ........
```

#### Field Interpretation

```
Offset  Hex             Interpretation
------  --------------  -----------------------------------------
0x00    43 53 54 4d     Magic "CSTM"
0x04    01              Version = 1
0x05    00              Flags = 0
0x06    01 00           Section count = 1
0x08    02              Section type = 0x02 (INDEX)
0x09    00 00 00        Padding
0x0c    08 00 00 00     Length = 8 (this time consistent with the payload)
0x10    ff 00 00 00     INDEX payload: first field = 0xff (255)
0x14    00 00 00 00     INDEX payload: second field = 0
```

The INDEX type (0x02) triggers a different processing than DATA. The payload seems to contain index entries. The value `0xff` (255) is likely used as an index into an array or offset into data — an out-of-bounds value that causes the SEGV.

#### GDB Trace

```bash
$ gdb -q ./fileformat_afl_asan
(gdb) run crash_B_min.bin
```

```
==XXXXX==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000XX
    #0 0xXXXXXX in process_index_section fileformat.c:142
    #1 0xXXXXXX in decode_section fileformat.c:95
    #2 0xXXXXXX in parse_sections fileformat.c:113
    #3 0xXXXXXX in main fileformat.c:178
```

Crash point analysis:

```
(gdb) break process_index_section
(gdb) run crash_B_min.bin

Breakpoint 1, process_index_section (section_data=..., section_len=8)
(gdb) x/8bx section_data
0x...: 0xff  0x00  0x00  0x00  0x00  0x00  0x00  0x00

(gdb) next
(gdb) next
(gdb) info locals
index_entry = 255
```

The function reads the first uint32_t from the payload (value 255) and uses it as an index to access an internal array. The array doesn't contain 256 entries — hence the SEGV.

#### Reconstructed Condition Path

```
main()
  -> parse_header()  — identical to crash A
  -> parse_sections()
      -> type = 0x02 (INDEX)
      -> length = 8
      -> decode_section() dispatches to process_index_section()
          -> index_entry = *(uint32_t*)(section_data+0) = 255
          -> table[255] access   <- CRASH: index out of bounds
```

#### RE Knowledge Extracted

- Type 0x02 (INDEX) has specific processing in `process_index_section`.  
- INDEX payload contains uint32_t entries used as indices.  
- No bounds checking is performed on these indices.  
- INDEX payload structure: uint32_t array, each entry is an index into an internal table (probably the section table or a data table).

---

## Deliverable 5 — Format Cartography

### Identified Fields Table

```
Offset  Size    Field               Values / Constraints
------  ------  ------------------  ----------------------------------------
0x00    4       Magic               "CSTM" (0x43 0x53 0x54 0x4d) — required
0x04    1       Version             0x01, 0x02 confirmed; 0x03 probable (untested)
0x05    1       Flags               0x00 observed; exact role unknown
0x06    2       Section Count       uint16_t LE — number of sections in the file
0x08    1       Section Type        0x01=DATA, 0x02=INDEX, 0x03=META
0x09    3       Section Reserved    Always 0x00 in observed inputs
0x0c    4       Section Length      uint32_t LE — payload size in bytes
0x10    N       Section Payload     Variable content depending on section type
```

For multi-section files, descriptors (type + reserved + length) and payloads follow sequentially from offset 0x08.

### Visual Structure

```
+----------------------- FILE HEADER (8 bytes) -----------------------+
|  Magic (4B)  |  Version (1B)   |  Flags (1B)  |  Section Count (2B) |
|   "CSTM"     |    0x01-0x03    |    0x00 ?    |     uint16_t LE     |
+------------------- SECTION 0 — DESCRIPTOR (8 bytes) ----------------+
|  Type (1B)   |  Reserved (3B)  |         Length (4B, LE)            |
|  01/02/03    |   00 00 00      |         uint32_t                   |
+------------------- SECTION 0 — PAYLOAD (Length bytes) ---------------+
|                    Content depends on type                          |
|  DATA  (0x01) : raw data                                            |
|  INDEX (0x02) : uint32_t array (index into internal table)          |
|  META  (0x03) : format TBD                                          |
+------------------- SECTION 1 — DESCRIPTOR --------------------------+
|  ...                                                                |
+------------------- SECTION 1 — PAYLOAD -----------------------------+
|  ...                                                                |
+------------------- CHECKSUM (position and format TBD) --------------+
|  Mentioned in strings ("Checksum mismatch: expected 0x%08x")        |
|  Probably uint32_t — algorithm and offset not determined            |
+---------------------------------------------------------------------+
```

### Documented Bugs

| ID | Function | Type | Description | Involved fields |  
|----|----------|------|-------------|-----------------|  
| A | `decode_section` (l.87) | heap-buffer-overflow READ | Reads `length` bytes without checking `offset + length <= file_size` | Section Length (0x0c) |  
| B | `process_index_section` (l.142) | SEGV (index OOB) | Payload uint32_t value used as array index without validation | INDEX Payload (0x10+) |  
| C | `validate_checksum` (l.201) | stack-buffer-overflow WRITE | 1024-byte work buffer (for 256 sections max) indexed by `section_count` without bounds checking | Section Count (0x06) |

### Open Questions for Chapter 25

1. **Checksum** — Algorithm (CRC32? sum? XOR?), position in file (end of file? in header?), and which bytes does it cover?  
2. **Version 3** — What additional fields? Link with `verify_signature`?  
3. **Compression** — `decompress_section` was never reached. Which flag activates it? Which algorithm?  
4. **META Payload** — What internal structure? Is the C crash in `validate_checksum` related?  
5. **Flags field (0x05)** — No crash or branch observed when varying this field. What is its actual role?

---

## Summary Commands

For reference, here is the complete command sequence for this checkpoint:

```bash
# === COMPILATION ===
cd binaries/ch15-fileformat/  
make clean  
make fuzz          # produces fileformat_afl and fileformat_afl_asan  
make coverage      # produces fileformat_gcov  

# === CORPUS & DICTIONARY ===
mkdir corpus_initial  
printf 'CSTM\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_initial/s01.bin  
printf 'CSTM\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_initial/s02.bin  
# (+ seeds s03, s04, s05 with DATA, INDEX, META sections — see above)
# (+ dict_ch25.txt — see above)

# === SEED VERIFICATION ===
afl-showmap -o /dev/stdout -- ./fileformat_afl corpus_initial/s01.bin 2>/dev/null | wc -l

# === SYSTEM CONFIGURATION ===
echo core | sudo tee /proc/sys/kernel/core_pattern

# === FUZZING ===
afl-fuzz -i corpus_initial -o out_ch15 -x dict_ch25.txt -m none -- ./fileformat_afl @@
# (Ctrl+C after 15-30 min or when corpus >= 20 and crashes >= 2)

# === CRASH TRIAGE ===
for crash in out_ch15/default/crashes/id:*; do
    echo "=== $(basename "$crash") ==="
    ./fileformat_afl_asan "$crash" 2>&1 | grep "^SUMMARY:"
done

# === MINIMIZATION ===
afl-tmin -i out_ch15/default/crashes/id:000000,... -o crash_A_min.bin -- ./fileformat_afl @@  
afl-tmin -i out_ch15/default/crashes/id:000001,... -o crash_B_min.bin -- ./fileformat_afl @@  

# === ANALYSIS ===
xxd crash_A_min.bin  
xxd crash_B_min.bin  
gdb -q ./fileformat_afl_asan -ex "run crash_A_min.bin"  
gdb -q ./fileformat_afl_asan -ex "run crash_B_min.bin"  

# === COVERAGE (optional) ===
lcov --directory . --zerocounters  
for f in out_ch15/default/queue/id:*; do ./fileformat_gcov "$f" 2>/dev/null; done  
for f in out_ch15/default/crashes/id:*; do ./fileformat_gcov "$f" 2>/dev/null; done  
lcov --directory . --capture --output-file cov.info  
lcov --remove cov.info '/usr/*' --output-file cov_filtered.info  
genhtml cov_filtered.info --output-directory cov_html/  
```

---

## Self-assessment

| Criterion | Your result | Level |  
|-----------|------------|-------|  
| AFL++ + ASan builds functional, `afl-showmap` OK | | ☐ Acquired ☐ Mastered |  
| 3+ targeted seeds, 10+ tokens in dictionary | | ☐ Acquired ☐ Mastered |  
| corpus >= 20, crashes >= 2 | | ☐ Acquired ☐ Mastered |  
| 2 crashes reproduced, minimized, traced in GDB | | ☐ Acquired ☐ Mastered |  
| 4+ format fields identified | | ☐ Acquired ☐ Mastered |

If you've reached the "Acquired" level on all 5 criteria, you've mastered the fundamentals of RE-oriented fuzzing. If you also produced an `lcov` coverage report and identified uncovered functions with hypotheses about blocking conditions, you're at the "Mastered" level.

---

⏭️
