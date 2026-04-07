🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 10.4 — `radiff2` — command-line diffing with Radare2

> **Chapter 10 — Binary diffing**  
> **Part II — Static Analysis**

---

## Introducing `radiff2`

`radiff2` is the diffing tool integrated into the Radare2 suite, which we discovered in Chapter 9. Unlike BinDiff and Diaphora, which rely on a graphical interface within a disassembler, `radiff2` is a **purely command-line** tool. No window, no colored CFG, no click: commands, flags, and text output.

This apparent austerity is actually its strength. `radiff2` excels in three situations where graphical tools are less at ease:

- **Automation** — a `radiff2` in a Bash or Python script integrates naturally into an analysis pipeline. Comparing 50 pairs of binaries in a loop only requires a `for` loop.  
- **Quick triage** — when you want an immediate answer ("are these two binaries identical?", "how many functions changed?") without launching a full disassembler and waiting for auto-analysis.  
- **GUI-less environments** — remote servers, Docker containers, CI/CD machines. Anywhere a terminal suffices.

`radiff2` offers several comparison levels, from the most raw byte-by-byte diff to the function diff with structural matching. This gradation makes it versatile.

---

## Prerequisites

`radiff2` is installed automatically with Radare2. If you followed Chapter 4 (section 4.2) or Chapter 9, Radare2 is already in place. Verify:

```bash
radiff2 -h
```

If the command displays the help, everything is ready. Otherwise, install Radare2:

```bash
# From packages (stable version)
sudo apt install radare2

# Or from source (most recent version)
git clone https://github.com/radareorg/radare2.git  
cd radare2  
sys/install.sh  
```

---

## Level 1 — Byte-by-byte diff

`radiff2`'s most basic mode compares the two files byte by byte, without any knowledge of the binary format. It's the equivalent of an enhanced `cmp`, with difference display in hexadecimal.

```bash
radiff2 keygenme_v1 keygenme_v2
```

The output looks like this:

```
0x00001234 48 => 49
0x00001235 83fb05 => 83fb06
0x00002010 7406 => 750e
```

Each line indicates an address (offset in the file) followed by the bytes in version 1 and their replacement in version 2. This mode is useful for quickly detecting whether two files are identical or not, and for locating raw differences. But it provides no interpretation: a `74` becoming `75` is not identified as a `jz` becoming `jnz` — it's just a byte change.

### Useful options in byte mode

```bash
# Side-by-side column display
radiff2 -d keygenme_v1 keygenme_v2

# Simply count the number of differences
radiff2 -s keygenme_v1 keygenme_v2
```

The `-s` (*distance*) flag computes the distance between both files. It's a quick metric to quantify the extent of changes: low distance on a large binary indicates a targeted patch.

```bash
# Typical result
$ radiff2 -s keygenme_v1 keygenme_v2
similarity: 0.987  
distance: 42  
```

The `similarity` field is a ratio between 0.0 (totally different files) and 1.0 (identical files). The `distance` field counts the number of bytes that differ. For a first triage, these two values often suffice to guide the analysis.

---

## Level 2 — Diff with disassembly

Byte mode doesn't understand the binary's structure. For a diff that speaks in assembly rather than hexadecimal, switch to code mode with the `-c` flag:

```bash
radiff2 -c keygenme_v1 keygenme_v2
```

In this mode, `radiff2` disassembles zones that differ and displays instructions side by side. Instead of seeing `7406 => 750e`, you get something like:

```
  0x00001234   jz  0x123c    |   0x00001234   jnz 0x1244
```

It's immediately more readable. You see that a conditional jump was inverted — a classic modification in crackmes and verification patches. This mode remains limited to code zones that differ at the binary level; it doesn't match functions.

### Intel syntax

By default, `radiff2` uses Radare2's syntax (close to Intel but with some peculiarities). To force a standard Intel syntax, add the appropriate option via the environment variable:

```bash
R2_ARCH=x86 R2_BITS=64 radiff2 -c keygenme_v1 keygenme_v2
```

Or configure it globally in your `~/.radare2rc` (cf. Chapter 9, section 9.3).

---

## Level 3 — Function diff with analysis

This is `radiff2`'s most powerful mode, and the one closest to what BinDiff and Diaphora do. The `-A` flag asks `radiff2` to perform a complete analysis of both binaries (function identification, CFG construction) before comparing:

```bash
radiff2 -A keygenme_v1 keygenme_v2
```

> ⚠️ **Execution time** — The `-A` flag triggers the equivalent of Radare2's `aaa` command on each binary (full automatic analysis, seen in Chapter 9). On a small binary, it's almost instantaneous. On a large binary, it can take a while. For even deeper analysis, `-AA` exists but is rarely necessary.

The output lists matched functions with their similarity score:

```
  sym.main   0x00001149 |   sym.main   0x00001149   (MATCH 0.95)
  sym.check  0x000011a0 |   sym.check  0x000011a0   (MATCH 0.72)
  sym.usage  0x00001230 |   sym.usage  0x00001230   (MATCH 1.00)
```

Functions with a score of 1.00 are identical. Those with a lower score have been modified. Unmatched functions are listed separately.

### Combining with code diff

To have both function matching and modified-instruction details, combine the flags:

```bash
radiff2 -AC keygenme_v1 keygenme_v2
```

This mode first displays the list of matched functions with their scores, then, for each modified function, the instruction-by-instruction diff. It's the most informative mode in a single command.

---

## Specialized comparison modes

`radiff2` offers several additional modes, activated by flags, that cover specific needs.

### Graph diff (`-g`)

The `-g` flag compares the control-flow graphs of two specific functions. You must provide the address of the function to compare in each binary:

```bash
radiff2 -g sym.check keygenme_v1 keygenme_v2
```

The output is a textual description of the graph: number of nodes (basic blocks), number of edges, and structural differences. It's less visual than BinDiff's colored CFGs, but it's parseable by a script.

For a graphical visualization, you can generate a diff in DOT format and convert it to an image with Graphviz:

```bash
radiff2 -g sym.check keygenme_v1 keygenme_v2 > diff.dot  
dot -Tpng diff.dot -o diff.png  
```

The result is a graph where common, modified, and added/removed blocks are represented with different colors. It's not as ergonomic as BinDiff's interface, but it's a visualization that can be generated automatically in a script and integrated into a report.

### Raw binary diff (`-x`)

The `-x` flag displays a hexadecimal diff in columns, with both files side by side. It's useful for inspecting differences in non-code zones (headers, data, relocation tables):

```bash
radiff2 -x keygenme_v1 keygenme_v2
```

### Comparing specific sections

It's sometimes useful to compare only a portion of the binaries — for example, only the `.text` section (code) while ignoring headers and data. Combined with `rabin2` (the Radare2 suite's binary-inspection tool), you can extract section offsets and pass address ranges to `radiff2`:

```bash
# Find the offset and size of .text in each binary
rabin2 -S keygenme_v1 | grep .text  
rabin2 -S keygenme_v2 | grep .text  

# Compare only the .text section (example with fictitious offsets)
radiff2 -r 0x1000:0x3000 keygenme_v1 keygenme_v2
```

This approach reduces noise due to differences in metadata, symbol tables, or data sections that are not relevant for code analysis.

---

## Script integration

`radiff2`'s real power is revealed in automation. Here are some common usage patterns.

### Triaging a directory of binaries

Compare each binary in a directory to a reference version and produce a summary:

```bash
#!/bin/bash
REFERENCE="keygenme_v1"

for binary in builds/*; do
    sim=$(radiff2 -s "$REFERENCE" "$binary" 2>/dev/null | grep similarity | awk '{print $2}')
    echo "$binary : similarity = $sim"
done
```

This script produces a list of similarity scores. Binaries with a score below 1.0 deserve deeper investigation.

### Extracting modified functions in JSON

For programmatic processing, `radiff2`'s output can be parsed. Combined with Radare2's JSON capabilities (`r2 -qc '...' -j`), you can build structured reports:

```bash
#!/bin/bash
# List modified functions between two versions
radiff2 -A keygenme_v1 keygenme_v2 2>/dev/null \
    | grep -v "MATCH 1.00" \
    | grep "MATCH"
```

For finer processing, go through `r2pipe` in Python (seen in Chapter 9, section 9.4), which gives complete programmatic access to all of Radare2's features, including `radiff2`:

```python
import r2pipe

r1 = r2pipe.open("keygenme_v1")  
r1.cmd("aaa")  # full analysis  
funcs_v1 = r1.cmdj("aflj")  # function list in JSON  

r2 = r2pipe.open("keygenme_v2")  
r2.cmd("aaa")  
funcs_v2 = r2.cmdj("aflj")  

# Programmatic comparison of functions
# (names, sizes, number of blocks...)
```

### CI/CD integration

In a continuous-integration pipeline, `radiff2` can serve as a guardrail: at each build, the produced binary is compared to the previous version and an alert is raised if critical functions were modified unexpectedly.

```bash
# In a CI script
SIMILARITY=$(radiff2 -s build/app_current build/app_previous \
    | grep similarity | awk '{print $2}')

if (( $(echo "$SIMILARITY < 0.95" | bc -l) )); then
    echo "WARNING: significant binary changes detected (similarity: $SIMILARITY)"
    radiff2 -AC build/app_current build/app_previous > diff_report.txt
    # Send the report by mail or Slack...
fi
```

---

## `radiff2` vs BinDiff / Diaphora

It's important to position `radiff2` correctly relative to the tools seen in the previous sections. They are not direct competitors — they operate at different levels.

### What `radiff2` does better

- **Triage speed** — launching `radiff2 -s` takes a fraction of a second, without any prior analysis. To answer "are these two files different and by how much?", nothing is faster.  
- **Scriptability** — everything goes through the command line, everything produces parseable text. Integration into scripts, pipelines, and automated tools is trivial.  
- **Lightness** — no need to launch a graphical disassembler, no project to create, no intermediate export. A terminal and a command suffice.  
- **Granularity** — `radiff2` allows comparing at all levels, from raw byte to function, through instruction and graph. You choose the level of detail adapted to the need.

### What BinDiff / Diaphora do better

- **Matching quality** — on complex binaries with thousands of functions, BinDiff's multi-pass algorithms and Diaphora's pseudo-code heuristics produce more reliable matches than `radiff2`'s.  
- **Visualization** — colored CFGs side by side, Diaphora's pseudo-code diff, integrated navigation in Ghidra — all this considerably facilitates understanding changes. `radiff2`'s text output is functional but requires more cognitive effort.  
- **Context** — in Ghidra or IDA, you can immediately move from the diff to a function's complete analysis (XREF, decompilation, types). With `radiff2`, you have to manually switch to `r2` to dig deeper.

### In practice

An efficient workflow uses `radiff2` as a first filter — a triage in a few seconds to quantify changes and identify zones of interest — then switches to BinDiff or Diaphora for detailed analysis of modified functions. Both approaches are complementary: the terminal for speed and automation, the graphical interface for in-depth understanding.

---

## Essential flags recap

| Flag | Mode | Usage |  
|------|------|-------|  
| *(none)* | Byte-by-byte diff | Raw differences in hexadecimal |  
| `-s` | Similarity | Similarity score and distance — quick triage |  
| `-d` | Column diff | Side-by-side hex display |  
| `-x` | Hex dump | Comparative hex dump |  
| `-c` | Code diff | Disassembly of modified zones |  
| `-A` | Analysis + functions | Function matching with scores |  
| `-AC` | Analysis + code | Function matching + instruction diff |  
| `-g addr` | Graph diff | CFG comparison of a specific function |

---

## In summary

`radiff2` doesn't have BinDiff's analysis power or Diaphora's richness of pseudo-code diff, and it doesn't claim to replace them. Its role is different: it's the tool you launch first, in a few seconds, to quantify and locate changes before bringing out the heavy artillery. Its purely CLI nature makes it an indispensable companion for automation, scripting, and GUI-less environments.

The reflex to develop: before launching Ghidra for a diff, start with a `radiff2 -s` to know what to expect, then a `radiff2 -AC` to get a first overview of touched functions. You'll know exactly where to focus your deep analysis.

---


⏭️ [Practical case: identify a vulnerability fix between two versions of a binary](/10-binary-diffing/05-practical-patch-vuln.md)
