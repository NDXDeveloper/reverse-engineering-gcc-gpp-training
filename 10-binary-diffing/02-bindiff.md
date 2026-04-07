🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 10.2 — BinDiff (Google) — installation, import from Ghidra/IDA, reading the result

> **Chapter 10 — Binary diffing**  
> **Part II — Static Analysis**

---

## Introducing BinDiff

BinDiff is the historical reference tool for binary comparison. Originally developed by Zynamics, it was acquired by Google in 2011 and has been distributed for free since 2016. Its role is simple: take two binaries analyzed by a disassembler (Ghidra or IDA), compare their functions, and produce a detailed report of similarities and differences.

BinDiff does not disassemble binaries itself. It works from export files produced by the disassembler — these are `.BinExport` files that contain the binary's structural representation (functions, basic blocks, CFG edges, mnemonics, operands). This two-phase architecture — export then comparison — lets it remain independent of the disassembler used.

BinDiff's core relies on a multi-pass matching algorithm, ranging from the most reliable correspondences (identical function names, exact CFG hash) to softer heuristics (call-graph propagation, partial block matching). For each matched function pair, it computes a similarity score and can go down to block-by-block diffing.

---

## Installation

### Download

BinDiff is distributed on Google's official GitHub repository:

```
https://github.com/google/bindiff/releases
```

Download the package matching your distribution. For Ubuntu/Debian:

```bash
wget https://github.com/google/bindiff/releases/download/v8/bindiff_8_amd64.deb  
sudo dpkg -i bindiff_8_amd64.deb  
sudo apt-get install -f   # resolves missing dependencies if needed  
```

> 💡 **Note** — Check the latest version available on the releases page. Version numbers and URLs evolve. At the time of writing, version 8 is the most recent.

The installation places several components:

- **`bindiff`** — the main graphical interface (Java).  
- **`binexport2dump`** — command-line utility for inspecting `.BinExport` files.  
- **BinExport plugins** — extensions for Ghidra and IDA that allow exporting analyses in `.BinExport` format.

### Installing the BinExport plugin for Ghidra

The BinExport plugin for Ghidra is included in the BinDiff package. To install it:

1. Launch Ghidra.  
2. Open the **File → Install Extensions…** menu.  
3. Click **+** (Add Extension) and navigate to the BinDiff installation directory. The plugin file is typically in `/opt/bindiff/extra/ghidra/` and has a name like `ghidra_BinExport.zip`.  
4. Select it, confirm, and restart Ghidra.

After restart, a new **BinExport** menu appears in the CodeBrowser. You can verify the installation by opening any already-analyzed binary and looking for the **File → Export BinExport2…** option (the exact label may vary by version).

### Installing the BinExport plugin for IDA Free

If you use IDA Free (seen in Chapter 9), the BinExport plugin is in `/opt/bindiff/extra/ida/`. Copy the `.so` (Linux) or `.dll` (Windows) file matching your IDA version to the `plugins/` directory of your IDA installation:

```bash
cp /opt/bindiff/extra/ida/binexport12_ida.so ~/.idapro/plugins/
```

> ⚠️ **Attention** — The number in the filename (`binexport12`) corresponds to the supported IDA API version. Make sure to copy the one that matches your IDA version. An incompatible plugin will simply be ignored at load.

### Verifying the installation

To verify everything works:

```bash
# Verify the BinDiff binary is accessible
bindiff --version

# Verify binexport2dump is available
binexport2dump --help
```

---

## Complete workflow: from analysis to comparison

The diffing process with BinDiff always follows the same three-step chain: analyze each binary separately in the disassembler, export the analyses to BinExport format, then launch the comparison.

### Step 1 — Analyze both binaries in Ghidra

Start by importing and analyzing the two versions of the binary you want to compare. Take the example of our training binaries `keygenme_v1` and `keygenme_v2`:

1. Create a dedicated Ghidra project (for example `ch10-diffing`).  
2. Import `keygenme_v1`: **File → Import File…**, select the binary, accept the default options, then launch auto-analysis when Ghidra offers it (**Yes** on the analysis dialog). Wait for analysis to finish (the progress bar at the bottom right of the CodeBrowser must be inactive).  
3. Repeat the operation for `keygenme_v2`.

> 💡 **Tip** — The diff's quality directly depends on the disassembler's analysis quality. If you renamed functions or created types during a previous analysis, these annotations will be taken into account by BinExport and improve matching. For a first diff, the default auto-analysis is largely sufficient.

### Step 2 — Export to BinExport format

For each binary, from Ghidra's CodeBrowser:

1. Open the analyzed binary (double-click in the project).  
2. Go to **File → Export BinExport2…** (or **File → Export Program…** then select the BinExport2 format from the list).  
3. Choose a location and filename. By convention, keep the binary name with the `.BinExport` extension:  
   - `keygenme_v1.BinExport`  
   - `keygenme_v2.BinExport`  
4. Confirm. Export takes a few seconds on a small binary.

Repeat the operation for the second binary.

> 📝 **From IDA** — The workflow is similar. Open the binary in IDA, wait for auto-analysis to finish, then use **File → BinExport2…** (the plugin adds this entry to the menu). The produced `.BinExport` file is in the same format, compatible with BinDiff regardless of the source disassembler.

### Step 3 — Launch the comparison with BinDiff

Two options are available: the graphical interface or the command line.

**Via the graphical interface:**

```bash
bindiff
```

BinDiff's Java interface opens. Use **Diffs → New Diff…** and select the two `.BinExport` files (primary = old version, secondary = new version, by convention). BinDiff launches the comparison and displays the results.

**Via the command line:**

```bash
bindiff keygenme_v1.BinExport keygenme_v2.BinExport
```

This command produces a `.BinDiff` results file (a SQLite database) in the current directory, which you can then open in the graphical interface:

```bash
bindiff --ui keygenme_v1_vs_keygenme_v2.BinDiff
```

The command line is particularly useful for automating comparisons in a script or pipeline.

---

## Reading BinDiff results

BinDiff's interface organizes results into several complementary views. Let's take the time to go through them.

### Overview (*Statistics*)

The first thing BinDiff displays is a statistical summary of the comparison:

- **Total number of functions** in each binary.  
- **Matched functions** — with the percentage relative to the total.  
- **Unmatched functions** — those that only exist in one of the two binaries.  
- **Global similarity score** — a number between 0.0 (completely different binaries) and 1.0 (identical binaries). For a security patch on a large binary, this score is typically greater than 0.95.

This summary allows a first quick evaluation: if the global score is 0.99 and only 2 out of 500 functions are marked as modified, you immediately know the patch is surgical and your investigation will focus on those 2 functions.

### Matched functions table (*Matched Functions*)

It's the heart of the interface. This table lists all pairs of matched functions between the two binaries, with for each:

- **Address in the primary and secondary binary** — addresses almost systematically differ between two compilations, which is normal.  
- **Function name** — if binaries are not stripped. Otherwise, BinDiff displays `sub_XXXX` like Ghidra or IDA.  
- **Similarity score** (0.0 to 1.0) — it's the most important column. Sort by this column in ascending order to bring the most modified functions to the top of the list.  
- **Confidence score** — indicates the reliability of the match itself. A low confidence score means BinDiff is not certain that these two functions are actually the same function.  
- **Matching algorithm used** — BinDiff indicates which heuristic enabled the match (exact hash, call-graph propagation, name matching, etc.). This information is useful for evaluating the result's reliability.  
- **Number of basic blocks and edges** in each version.

**The reading strategy** is simple: sort by ascending similarity. Functions with a score of 1.0 are identical — ignore them. Functions with a score below 1.0 are those that changed, and the lowest scores correspond to the largest changes. In the case of a security patch, the fixed function(s) are typically among those with the lowest score (but not necessarily the lowest of all — a function massively refactored for cosmetic reasons may have a lower score than a security fix of a single instruction).

### Unmatched functions table (*Unmatched Functions*)

Two sub-tables: functions present only in the primary binary, and those present only in the secondary. An "unmatched" function can mean:

- **Really new or removed function** — addition of a feature, removal of dead code.  
- **Matching failure** — the function exists in both binaries but changed so much that BinDiff didn't recognize it. This happens notably with inlined functions or deeply reorganized functions.  
- **Compiler artifact** — functions generated by the compiler (trampolines, thunks, initialization functions) can vary between two compilations without having functional meaning.

Always examine this table, especially unmatched functions on the secondary side (new binary): a function added by a patch may contain interesting mitigation code.

### CFG comparison view (*Flow Graphs*)

It's the most spectacular and useful view for understanding a change. When you double-click a pair of modified functions in the table, BinDiff opens a side-by-side view of both control-flow graphs, with a color code:

- **Green** — basic blocks identical in both versions.  
- **Yellow** — basic blocks matched but whose content was modified (instructions added, removed, or changed).  
- **Red** — basic blocks present only in one version (added or removed).  
- **Gray** — unmatched blocks.

Edges (transitions between blocks) are also colored to indicate whether the flow structure changed. This visualization lets you immediately locate the change within a function.

For example, if a patch adds a size check before a `memcpy` call, you'll see:

- A yellow block where the `memcpy` call was in the original version — the block still exists but its content was modified.  
- One or two red blocks representing the new verification path (the size test and the branch to error code in case of overflow).  
- Surrounding green blocks, unchanged, providing context.

### Instruction comparison view (*Instruction Diff*)

By zooming on a yellow (modified) block, BinDiff can display a diff at the assembly-instruction level, line by line. This view shows exactly which instructions were added, removed, or modified within the block. It's the finest level of detail, useful for precisely understanding the nature of a change — for example, a `jl` replaced by a `jle` (off-by-one fix) or a `cmp` whose immediate operand changed (modification of a size limit).

---

## Integrated Ghidra + BinDiff workflow

BinDiff can also be used directly from Ghidra without going through the separate graphical interface. If the plugin is correctly installed, you can access the comparison from the CodeBrowser via the BinDiff menu. This integrated mode lets you navigate diff results while benefiting from Ghidra's full context (decompiler, cross-references, annotations).

The integrated workflow is:

1. Open the **primary** binary in the CodeBrowser.  
2. Export it to BinExport (as described previously).  
3. Open the **secondary** binary in the CodeBrowser.  
4. Export it to BinExport.  
5. From the CodeBrowser (with one of the two binaries open), launch the comparison via the BinDiff menu.  
6. Results appear in windows integrated into the CodeBrowser.

The main advantage of this mode is being able to click on a modified function in the diff result and be immediately positioned in Ghidra's Listing and Decompiler, with full context (XREF, types, comments) at hand.

---

## Command-line use for automation

For repetitive workflows or integration in scripts, BinDiff is used entirely on the command line. Here are the most useful commands:

```bash
# Simple comparison
bindiff primary.BinExport secondary.BinExport

# The results file is created in the current directory
# Its name is derived from the input file names
ls *.BinDiff
```

The `.BinDiff` file is a SQLite database. You can query it directly with `sqlite3` to extract results programmatically:

```bash
# Open the results database
sqlite3 primary_vs_secondary.BinDiff

# List modified functions (similarity < 1.0)
sqlite3 primary_vs_secondary.BinDiff \
  "SELECT address1, address2, similarity, name 
   FROM function 
   WHERE similarity < 1.0 
   ORDER BY similarity ASC;"
```

This approach is precious for integrating diffing into an automated analysis pipeline — for example, a script that compares each new build to a reference version and alerts if critical functions were modified.

> 💡 **Tip** — The `binexport2dump` utility allows inspecting the content of a `.BinExport` file without opening BinDiff, which is useful for debugging or verifying that an export went well:  
> ```bash  
> binexport2dump keygenme_v1.BinExport  
> ```

---

## Limits of BinDiff

BinDiff is a mature and reliable tool, but it has limits you must know:

- **No integrated decompilation** — BinDiff compares at the assembly and basic-block level. To see pseudo-code, you must return to Ghidra or IDA. It's a navigation and localization tool, not a full-fledged analysis tool.  
- **Dependence on the disassembler** — diff quality depends on initial analysis quality. If Ghidra did not correctly identify a function's bounds, BinDiff will not be able to match it correctly. Disassembly errors propagate into the diff.  
- **Heavily obfuscated binaries** — control-flow obfuscation techniques (control flow flattening, seen in Chapter 19) considerably disrupt BinDiff's matching algorithms, because they radically transform the CFG structure.  
- **Massive compiler changes** — switching from GCC to Clang, or changing major compiler version with different optimization levels, can modify the generated code's structure enough to degrade matching quality.  
- **Dated graphical interface** — BinDiff's Java interface is functional but spartan by current standards. For a more comfortable experience, the integrated Ghidra mode or the Diaphora alternative (section 10.3) may be preferable.

---

## In summary

BinDiff is the most established diffing tool in the ecosystem. Its three-phase workflow — analyze, export, compare — naturally integrates into an existing RE process based on Ghidra or IDA. Its strength lies in the robustness of its matching algorithms, the clarity of its CFG visualization, and the ability to automate comparisons via command line and SQLite access to results.

The reflex to develop: faced with two versions of a binary, **export and diff before reversing**. The few minutes spent configuring the diff will save you hours of manual analysis by pointing you directly to the functions that matter.

---


⏭️ [Diaphora — open-source Ghidra/IDA plugin for diffing](/10-binary-diffing/03-diaphora.md)
