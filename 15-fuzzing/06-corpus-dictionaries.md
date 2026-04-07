🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.6 — Corpus management and custom dictionaries

> 🔗 **Prerequisites**: Section 15.2 (AFL++, initial corpus and launch), Section 15.3 (libFuzzer, `-dict` and `-merge` options), Section 15.5 (coverage and uncovered zones), Chapter 5 (triage tools: `strings`, `file`)

---

## The corpus and the dictionary: two speed levers

The fuzzer is an exploration engine. Its coverage bitmap tells it *where* to go, its mutation algorithms tell it *how* to transform inputs. But two factors determine how fast it progresses into the deeper layers of the target code:

- **The corpus** — the set of inputs from which the fuzzer generates its mutations. A quality corpus places the fuzzer halfway to interesting paths; an empty or unsuitable corpus forces it to discover everything from scratch, byte by byte.  
- **The dictionary** — a list of tokens (byte sequences) that the fuzzer can insert into its mutations. Without a dictionary, the fuzzer must discover magic bytes, keywords, and delimiters through random mutation — which can take hours. With an appropriate dictionary, it finds them in seconds.

In a reverse engineering context, building the corpus and dictionary is an act of analysis in itself. It's the moment where knowledge accumulated during triage (Chapter 5), string inspection (Section 5.1), and static analysis in Ghidra (Chapter 8) transforms into **concrete fuel** for the fuzzer.

---

## Building an effective initial corpus

### Input sources for the corpus

The ideal initial corpus contains inputs that are **valid**, **varied**, and **minimal**. Valid because they pass the parser's initial validations and reach deeper layers. Varied because they exercise different branches. Minimal because mutations are more effective on short inputs — each mutated byte has a higher probability of causing a behavior change.

In practice, input sources depend on the type of binary being analyzed:

**File parser.** If the binary processes a file format (our case with `ch15-fileformat`), the best seeds are real files in that format. If the format is proprietary and you have no example files, build them by hand from static analysis information: magic bytes, version fields, header sizes. A minimal file that passes the initial validations is worth more than a hundred random files.

**Network protocol.** If the binary is a network server or client (cf. Chapter 23), Wireshark/tcpdump captures provide real frames. Export the raw payloads (without TCP/IP headers) and use them as seeds. Each protocol message type should be represented at least once.

**Command-line arguments or stdin.** If the binary reads from stdin or processes text arguments, the seeds are representative text strings. Error messages found with `strings` often give clues about expected inputs (for example, `"Invalid command: use GET, SET, or DEL"` indicates three valid commands).

**No information available.** In the worst case, a corpus containing a single one-byte file (`\x00`) is enough to start. The fuzzer will eventually discover the expected format, but convergence will be much slower. Even a hastily built minimal corpus is preferable.

### Building seeds by hand

Let's revisit our parser example with the `RE` format. Static analysis revealed:

- Magic bytes: `RE` (0x52 0x45)  
- Version field at offset 2: values 1, 2, and possibly 3  
- Minimum size varies by version

We build one seed per identified branch:

```bash
$ mkdir corpus_initial

# Version 1 — minimum size 8 bytes
$ printf 'RE\x01\x00\x00\x00\x00\x00' > corpus_initial/v1_minimal.bin

# Version 1 — value > 1000 to reach extended mode
$ printf 'RE\x01\x00\xe9\x03\x00\x00' > corpus_initial/v1_extended.bin
# (0x03e9 = 1001 in little-endian)

# Version 2 — minimum size 16 bytes
$ printf 'RE\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_initial/v2_minimal.bin

# Version 2 — mode flag at data[4]=0x00, size > 20
$ printf 'RE\x02\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_initial/v2_mode.bin

# Version 3 — hypothetical, to explore a potential branch
$ printf 'RE\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_initial/v3_guess.bin
```

Each seed is targeted: it's designed to reach a specific branch identified in Ghidra. The fuzzer only needs to mutate the remaining fields to explore sub-branches.

> 💡 **Tip** — The `printf` command with `\x` sequences is the most direct tool for creating binary seeds. For more complex formats, a Python script with `struct.pack()` is more readable. For the `ch15-fileformat` format, the script `scripts/keygen_template.py` illustrates this approach.

### Retrieving existing inputs

When the format is known or semi-known, existing inputs are often available:

- **Project test files** — if the sources contain a `tests/` or `testdata/` directory, the files found there are ideal seeds.  
- **Public corpora** — for standard formats, fuzzing corpora already exist. For example, the Google OSS-Fuzz project maintains corpora for hundreds of open-source parsers. The `google/fuzzing` repository also contains reusable dictionaries.  
- **Files generated by the program itself** — if the binary can *write* in the format it reads (serializer/deserializer), generate a few files and use them as seeds.

---

## Minimizing the corpus: `afl-cmin` and `afl-tmin`

Over the course of fuzzing, the corpus grows: AFL++ adds every input that discovers a new path. After hours of fuzzing, the corpus can contain hundreds of inputs, many of which are redundant — they cover the same paths as other inputs already present.

Corpus minimization reduces this set to the **minimal subset** that preserves the same total coverage. Fewer inputs means faster fuzzing cycles and a corpus that's easier to analyze manually.

### `afl-cmin`: minimizing the number of inputs

`afl-cmin` identifies the smallest subset of inputs that covers all edges reached by the full corpus:

```bash
$ afl-cmin -i out/default/queue/ -o corpus_minimized/ \
    -- ./simple_parser_afl @@
```

Typical result:

```
[*] Testing the target binary...
[+] OK, 247 tuples recorded.
[*] Obtaining traces for 89 input files in 'out/default/queue/'.
[*] Narrowing to 23 files with unique tuples...
[+] Narrowed down to 23 files, saved in 'corpus_minimized/'.
```

From 89 inputs, we go down to 23 — a 74% reduction with no coverage loss. This minimized corpus is the ideal starting point for a new fuzzing campaign (for example with an enriched dictionary) or for manual input analysis.

### `afl-tmin`: minimizing the size of each input

Where `afl-cmin` reduces the *number* of inputs, `afl-tmin` reduces the *size* of each individual input by removing non-essential bytes:

```bash
$ afl-tmin -i corpus_minimized/id:000003,... \
           -o corpus_minimized/id:000003_min \
           -- ./simple_parser_afl @@
```

`afl-tmin` iteratively tries to remove blocks of bytes, replace sequences with zeros, and shorten the input, verifying at each step that coverage is preserved.

To process the entire minimized corpus:

```bash
$ mkdir corpus_tmin
$ for f in corpus_minimized/*; do
    name=$(basename "$f")
    afl-tmin -i "$f" -o "corpus_tmin/${name}_tmin" \
        -- ./simple_parser_afl @@
  done
```

> ⚠️ **Warning** — `afl-tmin` is slow: it runs the binary hundreds of times per input to test each deletion. On a corpus of 23 inputs, expect a few minutes. On a corpus of 500 inputs, run it overnight. This is why you apply `afl-cmin` first (fast, reduces the count) then `afl-tmin` (slow, reduces each one's size).

### Minimization with libFuzzer

libFuzzer integrates minimization via the `-merge` flag:

```bash
$ mkdir corpus_merged
$ ./fuzz_parse_input -merge=1 corpus_merged/ corpus_parse/
```

This command is the equivalent of `afl-cmin`: it keeps only inputs contributing unique coverage. libFuzzer doesn't offer a direct equivalent of `afl-tmin`, but you can use `-reduce_inputs=1` during fuzzing so that libFuzzer progressively replaces inputs with shorter versions covering the same edges.

---

## Dictionaries: accelerating structure discovery

### The multi-byte token problem

The mutation engine of AFL++ and libFuzzer operates primarily at the byte level: it flips bits, replaces bytes with interesting values (0, 1, 0xff, 0x7f, etc.), inserts or deletes blocks. This approach works well for discovering numeric values, but it's very slow for discovering significant **multi-byte sequences**.

Let's take a concrete example. If the parser starts by checking a 4-byte magic number `\x89PNG`, the fuzzer must produce exactly these 4 bytes in the right order. By random byte-at-a-time mutation, the probability is (1/256)⁴ = 1 chance in 4 billion. Even at 10,000 executions per second, it would take an average of 5 days to stumble upon it by chance.

With a dictionary containing the token `"\x89PNG"`, the fuzzer can **directly insert** this sequence into its mutations. It finds it within the first few seconds.

### Dictionary format

The format is identical for AFL++ and libFuzzer — a text file with one token per line:

```
# Dictionary for the RE format
# Each line: "optional_name" = "value" or just "value"

# Magic bytes
magic_re="RE"

# Known versions
version_1="\x01"  
version_2="\x02"  
version_3="\x03"  

# Interesting values for numeric fields
val_0="\x00"  
val_ff="\xff"  
val_1000="\xe8\x03"  
val_1001="\xe9\x03"  

# Observed delimiters and markers
null_word="\x00\x00\x00\x00"
```

The syntax:

- Lines starting with `#` are comments.  
- Each token is a string in double quotes.  
- `\xNN` sequences represent hexadecimal bytes.  
- The `name=` prefix before the token is optional (it serves only as documentation).  
- Tokens can be of any length, but short tokens (1 to 8 bytes) are most effective.

### Building a dictionary from RE analysis

The dictionary is where the reverse engineer's knowledge transforms most directly into fuzzing acceleration. Each piece of information gathered during static analysis can translate into a token:

**From `strings` on the binary.** Strings extracted from the binary often contain keywords, command names, error messages that reveal tokens expected by the parser:

```bash
$ strings simple_parser | grep -i "error\|invalid\|expected\|unknown"
Error: invalid magic  
Error: unknown version  
Expected payload length >= 16  
```

These messages indicate that the parser expects a field called "magic," a "version" field, and a "payload" of at least 16 bytes. The words `GET`, `SET`, `DEL` found in a network binary are protocol commands — to be injected directly into the dictionary.

```bash
# Automatic extraction of all strings as tokens
$ strings -n 3 simple_parser | sort -u | \
    awk '{printf "\"%s\"\n", $0}' > dict_from_strings.txt
```

> ⚠️ **Warning** — A dictionary that's too large (hundreds of tokens) can slow down the fuzzer: at each mutation, it can choose from all tokens, diluting the probability of choosing the right ones. Filter the extracted strings to keep only those that appear to be format keywords (not complete error messages, just structural tokens).

**From constants in Ghidra.** Values compared in the parser's branching conditions are direct candidates:

```
; Ghidra decompile, parse_header function:
if (*(int *)data == 0x45520001) {    // "RE" + version 1 in little-endian
    ...
}
if (data[8] == 0x7f) {               // Section marker
    ...
}
```

The corresponding dictionary:

```
magic_v1="\x52\x45\x01\x00"  
magic_v2="\x52\x45\x02\x00"  
section_marker="\x7f"  
```

**From analyzed crashes (Section 15.4).** Each minimized crash contains significant bytes. Critical positions identified during crash analysis become tokens:

```
# Sequence that triggered the extended v2 mode
mode_trigger="\x00\xff"
```

**From known specifications.** If the format is partially documented or if an embedded library has been identified (cf. Chapter 20, FLIRT/signatures), that library's constants enrich the dictionary. For example, for a binary using JSON:

```
brace_open="{"  
brace_close="}"  
bracket_open="["  
bracket_close="]"  
colon=":"  
comma=","  
quote="\""  
kw_null="null"  
kw_true="true"  
kw_false="false"  
```

**Community dictionaries.** The AFL++ repository and the `google/fuzzing` repository contain pre-built dictionaries for dozens of formats: PNG, JPEG, PDF, XML, HTML, ELF, JSON, SQL, HTTP, TLS, and many more. If the binary being analyzed processes one of these formats, using the existing dictionary is a considerable time saver:

```bash
$ ls AFLplusplus/dictionaries/
elf.dict  gif.dict  html.dict  jpeg.dict  json.dict  pdf.dict  png.dict  ...
```

### Using a dictionary

With AFL++:

```bash
$ afl-fuzz -i corpus_minimized -o out -x my_dict.txt -- ./simple_parser_afl @@
```

With libFuzzer:

```bash
$ ./fuzz_parse_input -dict=my_dict.txt corpus_parse/
```

The fuzzer integrates dictionary tokens into its mutation strategies: it inserts them at random positions, replaces existing sequences with tokens, and combines tokens together. The dictionary doesn't replace classic mutations — it complements them.

---

## Advanced corpus management strategies

### Rotational corpus between AFL++ and libFuzzer

The two fuzzers use different mutation strategies and discover complementary paths. An effective technique is to circulate the corpus between the two:

```bash
# Phase 1: AFL++ fuzzing (broad exploration)
$ afl-fuzz -i corpus_initial -o out_afl -x dict.txt -- ./simple_parser_afl @@
# (let it run for a few hours, then Ctrl+C)

# Phase 2: minimize the AFL++ corpus
$ afl-cmin -i out_afl/default/queue/ -o corpus_after_afl -- ./simple_parser_afl @@

# Phase 3: libFuzzer fuzzing (deep targeting)
$ ./fuzz_parse_input -dict=dict.txt -max_total_time=3600 corpus_after_afl/

# Phase 4: merge the corpora
$ mkdir corpus_combined
$ ./fuzz_parse_input -merge=1 corpus_combined/ corpus_after_afl/ out_afl/default/crashes/

# Phase 5: relaunch AFL++ with the enriched corpus
$ afl-fuzz -i corpus_combined -o out_afl_v2 -x dict.txt -- ./simple_parser_afl @@
```

At each rotation, the corpus is enriched by both fuzzers' discoveries. Paths found by AFL++ through its deterministic mutations feed libFuzzer, and libFuzzer's deep explorations feed AFL++ in the next cycle.

### Manually enriching the corpus after analysis

Crash analysis (Section 15.4) and coverage analysis (Section 15.5) reveal uncovered zones guarded by precise conditions. When you understand the blocking condition, you can build a seed that satisfies it and inject it into the corpus:

```bash
# Coverage shows that the "version == 3, subtype == 0x42" branch isn't reached
# Build a seed that satisfies these conditions
$ printf 'RE\x03\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > corpus_minimized/v3_sub42.bin

# Relaunch fuzzing with this added seed
$ afl-fuzz -i corpus_minimized -o out_v2 -x dict.txt -- ./simple_parser_afl @@
```

This seed unlocks access to an entire branch that the fuzzer wasn't reaching. From there, its mutations can explore the sub-branches of this new zone.

### Regression corpus

Once the fuzzing campaign is complete and results analyzed, the minimized corpus constitutes a **regression test suite** for the parser. If the binary evolves (new version, security patch), replaying this corpus verifies that previously reached paths are still present and that fixed crashes don't reappear:

```bash
# Verify that no corpus input crashes on the patched binary
$ for f in corpus_minimized/*; do
    ./parser_v2_asan "$f" 2>&1 | grep -q "ERROR:" && echo "REGRESSION: $f"
  done
```

This workflow is particularly relevant in the context of binary diffing (Chapter 10): when comparing two versions of a binary, the fuzzer's corpus serves as a test base to identify behavioral changes.

---

## Dictionaries and corpus: measurable impact

To illustrate the concrete impact of these techniques, here are typical orders of magnitude observed on a medium-complexity binary format parser:

| Configuration | Time to reach 50% coverage | Crashes found in 1h |  
|---|---|---|  
| Empty corpus (single `\x00`), no dictionary | > 8 hours | 0–1 |  
| Minimal corpus (3 valid seeds), no dictionary | ~45 minutes | 2–4 |  
| Minimal corpus, with basic dictionary (10 tokens) | ~10 minutes | 4–8 |  
| Targeted corpus (one seed per branch), with enriched dictionary | ~2 minutes | 8–15 |

These numbers are indicative and vary depending on parser complexity, branch depth, and binary execution speed. But the ratio between configurations is typically in this range: **going from "empty corpus" to "targeted corpus + dictionary" accelerates discovery by a factor of 50 to 200**.

This 15-to-30-minute preparation investment (building seeds, extracting tokens) is the best time/result ratio in the entire fuzzing chain.

---

## Summary

The corpus and dictionary are the two channels through which the reverse engineer injects knowledge into the fuzzer:

- **The initial corpus** is built from magic bytes, field values, and size constraints identified during triage and static analysis. One seed per identified branch is the basic rule.  
- **`afl-cmin`** reduces the corpus to the minimal subset preserving coverage (fast, run first). **`afl-tmin`** then reduces each individual input's size (slow, run second). For libFuzzer, `-merge=1` fills the same role.  
- **The dictionary** contains the target format's structural tokens: magic bytes, keywords, delimiters, Ghidra constants, critical crash values. Community dictionaries exist for standard formats.  
- **Corpus rotation** between AFL++ and libFuzzer, supplemented by manual seed injection based on coverage, is the most effective strategy for maximizing exploration.

With a targeted corpus and tailored dictionary, the fuzzer no longer starts from zero — it starts from where static analysis left off. The next section puts this entire methodology into practice on a concrete case: the custom format parser of `ch15-fileformat`.

---


⏭️ [Practical case: discovering hidden paths in a binary parser](/15-fuzzing/07-practical-parser-case.md)
