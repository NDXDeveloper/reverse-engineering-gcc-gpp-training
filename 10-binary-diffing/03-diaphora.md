🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 10.3 — Diaphora — open-source Ghidra/IDA plugin for diffing

> **Chapter 10 — Binary diffing**  
> **Part II — Static Analysis**

---

## Introducing Diaphora

Diaphora (from the Greek *διαφορά*, "difference") is an open-source binary-diffing tool created by Joxean Koret, a Spanish security researcher recognized in the RE community. Distributed under the GPL license, it takes the form of a plugin for IDA and, more recently, for Ghidra. It's the most complete open-source alternative to BinDiff.

What distinguishes Diaphora from BinDiff is not so much the purpose — both tools serve to compare binaries — as the technical approach and the richness of heuristics. Where BinDiff relies mainly on control-flow graph structure, Diaphora combines a much broader number of comparison criteria. Among the most notable:

- **Pseudo-code hash** — Diaphora exploits the integrated decompiler (Ghidra's or IDA's Hex-Rays) to produce a pseudo-code hash of each function. Two functions whose pseudo-code is identical are matched with very high confidence, even if the underlying assembly code differs (register changes, instruction reordering by the optimizer).  
- **ASM hash and partial hash** — beyond pseudo-code, Diaphora computes hashes on assembly mnemonics, constants, and subsets of these elements, which allows partial matching when code has been slightly modified.  
- **Constants and strings matching** — numeric constants (magic numbers, buffer sizes) and referenced strings are used as fingerprints.  
- **Call-graph topology** — like BinDiff, Diaphora uses a function's position in the global call graph (who calls it, who it calls) to strengthen or invalidate a match.  
- **Specialized heuristics** — Diaphora has dedicated passes for particular cases such as small functions (wrappers, thunks), functions that differ only by their constants, or functions whose only change is error handling.

The result of this combination is a tool often more precise than BinDiff on heavily optimized or partially obfuscated binaries, at the cost of slightly longer analysis time.

---

## Installation

### For Ghidra

Diaphora for Ghidra is distributed via the project's official GitHub repository:

```
https://github.com/joxeankoret/diaphora
```

Installation is done as a Ghidra script (and not as a packaged extension):

1. Clone the repository:
   ```bash
   cd ~/tools
   git clone https://github.com/joxeankoret/diaphora.git
   ```

2. In Ghidra, open the **Script Manager**: from the CodeBrowser, **Window → Script Manager** menu.

3. Add the cloned repository directory to the script paths: click the **Manage Script Directories** icon (the folder with a key), then add the path to the `diaphora/` directory you just cloned.

4. In the Script Manager, search for `diaphora`. You should see the script `Diaphora.java` (or `diaphora_ghidra.py` depending on the version) appear. Double-click to execute it, or assign it a keyboard shortcut for quick access.

> 💡 **Dependencies** — Diaphora uses SQLite to store its results. On most Linux distributions, the SQLite library is already present. If you encounter errors, verify that the `sqlite3` package is installed (`sudo apt install sqlite3`).

### For IDA

Installation for IDA is more direct. Diaphora was initially designed for IDA and it's the most mature platform:

1. Clone the same repository (or download the ZIP archive from GitHub).  
2. Copy the `diaphora.py` file and the associated directory into IDA's `plugins/` folder, or execute it as a script via **File → Script File…**  
3. Diaphora then appears in the **Edit → Plugins → Diaphora** menu.

### Verification

Regardless of the disassembler, the simplest way to verify the installation is to open a small analyzed binary and launch a Diaphora export (described in the next section). If the export produces a `.sqlite` file without error, the installation is functional.

---

## Comparison workflow

Diaphora's workflow is conceptually similar to BinDiff's — export both binaries, then compare the exports — but the process takes place entirely inside the disassembler, without a separate application.

### Step 1 — Export the primary binary

1. Open `keygenme_v1` in Ghidra and wait for auto-analysis to finish.  
2. Launch the Diaphora script from the Script Manager.  
3. Diaphora displays a dialog asking for the output file path. Choose a location and an explicit name:
   ```
   /home/user/diffing/keygenme_v1.sqlite
   ```
4. A series of options appears. For a first use, the default options are suitable. Among the notable options:  
   - **Use decompiler** — enable this option (checked by default in most versions). It asks Diaphora to decompile each function and store its pseudo-code in the database. It's slower but produces much better results.  
   - **Exclude library functions** — allows ignoring functions identified as coming from standard libraries (libc, libstdc++…), which reduces noise in results.  
5. Confirm. Diaphora goes through all functions of the binary, computes hashes, decompiles if requested, and stores everything in the SQLite file. A progress bar indicates progress.

### Step 2 — Export the secondary binary

Close `keygenme_v1` in Ghidra (or open a new CodeBrowser instance), open `keygenme_v2`, and repeat the same export operation:

```
/home/user/diffing/keygenme_v2.sqlite
```

> 💡 **Practical tip** — Always export to files whose name clearly identifies the version. When exports accumulate over time, names like `export1.sqlite` quickly become unusable.

### Step 3 — Launch the comparison

1. Open one of the two binaries in Ghidra (the choice doesn't matter, but by convention we open the secondary — the patched version).  
2. Launch the Diaphora script.  
3. This time, instead of simply exporting, indicate the SQLite file of the **other** version as a comparison base. Diaphora detects it's a diff and not a simple export.  
4. The comparison runs. Depending on binary size and the number of enabled heuristics, this can take from a few seconds (small binary) to several minutes (multi-megabyte binary with decompilation enabled).

The result is displayed directly in an interface integrated into the disassembler.

---

## Reading the results

Diaphora's results interface is organized into tabs, each matching a category of correspondences. This organization is one of the tool's strengths: instead of a single list of functions sorted by similarity, Diaphora separates results by confidence level.

### *Best matches* tab

These are function pairs matched with the highest confidence. Functions in this tab were recognized by reliable heuristics — identical pseudo-code hash, identical assembly hash, exact name matching. In practice, nearly all these correspondences are correct.

For each pair, Diaphora displays:

- Addresses in both binaries.  
- Function name (if available).  
- **Similarity ratio** — a number between 0.0 and 1.0, computed from the combination of heuristics.  
- **Description of the heuristic** that produced the match — for example "pseudo-code hash", "bytes hash", "same name".

Functions with a ratio of 1.0 are identical. Those with a ratio slightly below 1.0 deserve inspection: they were recognized as corresponding but present differences.

### *Partial matches* tab

Here are found pairs matched with medium confidence. The heuristic found enough points in common to propose a match, but the similarity score is significantly below 1.0. This is often the tab where the most interesting functions during a patch analysis are found: functions fixed by the patch present enough points in common with their original version to be matched, but enough differences to not be classed as "best match".

### *Unreliable matches* tab

Matches in this tab are the most speculative. Diaphora found some matching clues, but not enough to guarantee the match. Consult this tab with a critical eye: some correspondences are correct, others are false positives. Information on the heuristic used is precious here — a match by propagation in the call graph is more reliable than a match based solely on the number of basic blocks.

### *Unmatched* tab

As in BinDiff, this tab lists functions that could not be matched. Two sub-categories: functions present only in the primary binary and those only in the secondary. The same warnings as in section 10.2 apply: an unmatched function is not necessarily new — it may simply have changed too much to be recognized.

### Pseudo-code diff view

This is Diaphora's flagship feature and its clearest advantage over BinDiff. When you select a function pair in any tab, Diaphora can display a **side-by-side diff of the decompiled pseudo-code** — not just of the assembly. This view uses a format similar to a classic text diff (added lines in green, removed in red, modified in yellow), but applied to C pseudo-code produced by the decompiler.

The interest is considerable. Comparing assembly block by block requires significant mental effort to reconstruct the semantics of the change. Pseudo-code diff directly shows modifications expressed in a high-level language — for example, adding a `if (size > MAX_BUFFER)` condition is immediately readable in pseudo-code, whereas in assembly, you have to identify a `cmp` followed by a `ja` or `jbe` and mentally reconstruct the logic.

> ⚠️ **Reminder** — Pseudo-code produced by a decompiler is never perfect (cf. Chapter 20). It can contain typing errors, poorly named variables, or control structures reconstructed differently from the original. The pseudo-code diff is a navigation and quick-understanding tool, not an absolute truth. In case of doubt, always descend to the assembly level to verify.

### Assembly diff view

Diaphora also offers a diff at the assembly level, similar to BinDiff's. Instructions are presented side by side, with difference coloring. This view complements the pseudo-code diff: pseudo-code gives the semantic overview, assembly gives the exact detail.

### Control-flow graph view

For pairs of modified functions, Diaphora can display both CFGs side by side with the same color code as BinDiff (identical, modified, added, removed blocks). This view is particularly useful for functions whose control structure has changed — addition of a new branch, removal of an execution path, reorganization of a loop.

---

## Diaphora vs BinDiff: when to choose one or the other

Both tools cover the same need, but their respective strengths make them complementary rather than competitors.

### Diaphora's strengths

- **Pseudo-code diff** — it's its decisive advantage. Being able to compare decompiled code rather than assembly alone considerably speeds up understanding of changes, especially on long or complex functions.  
- **Open source** — the code is available, modifiable, extensible. If you need a matching heuristic specific to your use case (for example, signatures specific to a particular SDK or framework), you can add it.  
- **Result categorization** — the separation into best/partial/unreliable matches is more informative than a simple list sorted by score. It naturally guides the analyst towards the most relevant results.  
- **Direct integration** — everything happens in the disassembler, without an external application to launch. Full context (XREF, types, comments) is always available.

### BinDiff's strengths

- **Maturity and robustness** — BinDiff has been developed and maintained by Google for more than a decade. Its matching algorithms are extremely battle-tested on millions of comparisons.  
- **Performance** — on very large binaries (tens of megabytes, tens of thousands of functions), BinDiff is generally faster than Diaphora with decompilation enabled.  
- **Standardized export format** — BinExport format is a de facto standard. `.BinExport` files can be shared between analysts without each needing the same disassembler.  
- **SQL automation** — the SQLite results database of BinDiff is well documented and easy to query programmatically.  
- **Disassembler independence** — you can compare an export made from Ghidra with an export made from IDA. Diaphora requires both exports to be made from the same tool.

### In practice

Many analysts use both. A common workflow consists of first launching BinDiff to get a quick and reliable overview, then using Diaphora on functions of interest to benefit from pseudo-code diff. On small binaries or for quick analysis, Diaphora alone largely suffices. On large binaries or in an automated pipeline, BinDiff is often preferred for its speed and the ease of extracting results.

---

## Diaphora's advanced options

A few options deserve mention for more demanding analyses:

### Similarity thresholds

Diaphora allows configuring the thresholds below which a match is classed as "partial" or "unreliable". Lowering these thresholds increases the number of correspondences found, but at the cost of a higher false-positive rate. For targeted patch diffing, default values are generally appropriate.

### Function exclusion

You can exclude functions from analysis by their size (number of basic blocks) or by their name (regular expressions). It's useful to ignore trivial functions generated by the compiler (PLT thunks, trampolines) that clutter results without providing useful information.

### Incremental export

If you've already exported a binary and then enriched the analysis in Ghidra (function renaming, type creation), Diaphora allows updating the existing export without recomputing everything from scratch. It's an appreciable time saving on large binaries.

### Batch mode

Diaphora can be executed in non-interactive mode from Ghidra's command line (via `analyzeHeadless`), which allows integrating diffing into an automated pipeline. The result is stored in the SQLite database and can be exploited by a Python script without ever opening the graphical interface.

---

## In summary

Diaphora is a powerful and flexible tool that naturally complements BinDiff in the reverse engineer's toolbox. Its pseudo-code diff is a unique feature that changes the game for analyzing complex patches, and its open-source nature makes it adaptable to specific needs. The fact that it runs entirely inside Ghidra (or IDA) simplifies the workflow and avoids going back and forth between applications.

The reflex to develop: when BinDiff has shown you *which* functions changed, switch to Diaphora to understand *how* they changed, thanks to pseudo-code diff.

---


⏭️ [`radiff2` — command-line diffing with Radare2](/10-binary-diffing/04-radiff2.md)
