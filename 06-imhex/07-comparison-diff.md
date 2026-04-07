🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.7 — Comparing two versions of the same GCC binary (diff)

> 🎯 **Goal of this section**: Use ImHex's Diff view to visually compare two ELF binaries built from the same C/C++ source but compiled differently, understand the nature of the observed differences, and know in which RE scenarios this technique brings value that structural diffing tools (BinDiff, Diaphora) do not cover.

> 📦 **Test binaries**: `binaries/ch21-keygenme/keygenme_O0` and `binaries/ch21-keygenme/keygenme_O2`, or any pair of binaries compiled from the same source with different GCC flags.

---

## Why compare binaries at the hex level?

Chapter 10 is entirely devoted to binary diffing with structural tools like BinDiff, Diaphora, and `radiff2`. These tools compare at the **function** level: they identify which functions changed, which instructions were added or removed, and produce correspondence graphs between the two versions. It is the ideal approach to understand the impact of a security patch or the evolution of an algorithm between two releases.

But there are scenarios where structural diffing does not suffice, and where a **byte-by-byte** comparison in ImHex is more appropriate.

**Verifying a localized binary patch.** You modified a single byte in a binary (flipping a `jz` to a `jnz`, for example — Chapter 21). Before testing, you want to visually confirm that your modification touches exactly the intended byte and nothing else. A hex diff is immediate; importing both versions into BinDiff would be disproportionate.

**Comparing the impact of compilation flags.** You compile the same `hello.c` with `-O0` then with `-O2`. The two binaries are structurally very different (inlined functions, unrolled loops, reordered code), but you want to observe differences at the raw level: what is the size difference? Which sections grew or shrunk? Did the ELF header change? The hex diff answers these questions quickly.

**Comparing before and after stripping.** You run `strip` on a binary. Which sections were removed? Have the machine code bytes in `.text` changed? The hex diff immediately shows that `.text` is identical but that the `.symtab`, `.strtab` sections and DWARF information have disappeared.

**Analyzing embedded data.** Two versions of a binary contain different configurations hardcoded in `.rodata` or `.data`. Structural diff (function-level) sees no code differences — only data changes. The hex diff reveals them directly.

**Detecting stealthy modifications.** In a malware analysis context (Part VI), you compare a clean binary with a potentially trojanized one. Modifications may touch a few bytes in a data section or a hijacked jump. The hex diff misses nothing — every modified byte is highlighted.

---

## Using ImHex's Diff view

### Opening two files

ImHex supports **multiple tabs**. Open the first binary via **File → Open File**, then open the second in a new tab via **File → Open File** again (or `Ctrl+O`). You should see two tabs in the top bar of the hex view, each bearing the file name.

### Activating the Diff view

Access the Diff view via **View → Diff**. A panel opens asking you to select the two data "providers" to compare. Choose your two files in the dropdown menus — the first as "Provider A" and the second as "Provider B".

ImHex then displays the two files **side by side** in the Diff panel. The columns are synchronized: each line shows the same offsets in both files. The color code is:

- **Neutral background** — bytes are identical in both files.  
- **Colored background (highlight)** — bytes differ. The exact color depends on your ImHex theme, but it is designed to immediately attract attention.

### Navigating between differences

The Diff view provides navigation buttons (up/down arrows or a summary of differing regions) that let you **jump from one difference to the next**. When both files are largely identical with a few divergence zones (typical case of a patch or recompilation with similar flags), this navigation is far more efficient than manually scrolling through hundreds of kilobytes of identical bytes.

Scrolling is synchronized between the two views: if you manually scroll in Provider A, Provider B follows at the same offset. This lets you visually sweep the file while spotting divergent zones by their color.

---

## Case study 1: `-O0` vs `-O2` on the same source

Let's compile the keygenme with two optimization levels and compare the results:

```bash
cd binaries/ch21-keygenme/  
make keygenme_O0 keygenme_O2  
```

Open `keygenme_O0` and `keygenme_O2` in ImHex and activate the Diff view.

### What you observe

**The ELF Header (offsets 0x00–0x3F).** Most fields are identical: same magic number, same architecture, same type. But `e_entry` (the entry point) may differ if the linker placed `_start` at a different address. `e_shoff` (the offset of the Section Header Table) almost certainly differs, because the code size changed and sections are shifted.

**The `.text` section.** This is where differences are most massive. Code compiled in `-O0` is verbose: each variable is stored on the stack, each access goes through a `mov` to memory, functions are not inlined. `-O2` code is compact: variables live in registers, short functions are inlined, loops are unrolled. The hex diff shows an almost entirely divergent block over the entire length of `.text`.

**The `.rodata` and `.data` sections.** If the program contains string constants or initialized data, these sections are often identical between `-O0` and `-O2` — optimizations act on code, not on data. The diff confirms this hypothesis: the `.rodata` bytes are neutral (no highlighting).

**Debug sections.** The `-O0` binary compiled with `-g` contains bulky DWARF sections (`.debug_info`, `.debug_abbrev`, `.debug_line`, etc.) that are absent from the `-O2` binary compiled without `-g`. If both binaries were compiled without `-g`, these sections exist in neither and this difference does not apply.

**Global size.** The `-O2` binary is generally smaller than `-O0` for code, but may be bigger if inlining duplicated code. The diff's scrollbar gives you an immediate visual indication of the size difference — if Provider A is longer than Provider B, the area past the end of B appears as entirely different.

### What you take away

This diff does not serve to understand optimizations in detail — Chapter 16 covers that with adapted tools (disassembly comparison, flow graphs). On the other hand, it gives you a **structural overview** in seconds: which regions of the file are impacted by optimizations, how large the change is, and which sections stay stable. This information guides your analysis strategy: if you're looking for cryptographic constants, you know `.rodata` is stable ground between optimization levels.

---

## Case study 2: before and after `strip`

```bash
cp keygenme_O0 keygenme_O0_stripped  
strip keygenme_O0_stripped  
```

Open both versions in ImHex and activate the diff.

### What you observe

**The code is identical.** The `.text`, `.rodata`, `.data`, and `.plt` sections are byte-for-byte identical between the original and stripped binaries. That is an important confirmation: `strip` does not modify the executable code, it only touches metadata.

**Symbol sections have disappeared.** The stripped binary is significantly shorter. The `.symtab` (symbol table), `.strtab` (symbol string table) sections, and DWARF sections (if present) were removed. In the diff, these regions appear in the original file but have no match in the stripped file.

**The Section Header Table has changed.** The number of Section Headers (`e_shnum`) is reduced in the stripped binary. Entries corresponding to removed sections no longer exist. The offset of the table (`e_shoff`) probably changed as well.

### What you take away

This diff visually confirms a theoretical fact we saw in Chapter 2: stripping removes metadata without touching the code. But it also reveals a subtle detail — the order of remaining sections and their offsets in the file can be modified by `strip`, even for sections whose content did not change. That is because `strip` rewrites the ELF file without the removed sections, which can shift the offsets of following sections.

---

## Case study 3: verifying a binary patch

You flipped a conditional jump in the binary: replaced a `jz` (opcode `74`) with a `jnz` (opcode `75`) at a precise offset. Before testing the patched binary, you want to confirm the modification is correct.

Open the original and patched binaries in the ImHex diff. Difference-navigation should bring you to **exactly one modified byte**. Check:

- The offset is the one you targeted.  
- The original byte is `74` and the patched byte is `75`.  
- No other difference appears in the file.

If you see extra differences you did not expect, your patching tool probably touched other bytes by mistake (some editors modify timestamps or checksums on save). The ImHex diff makes this kind of problem immediately visible.

This scenario will be put into practice in Chapter 21 when we patch the keygenme.

---

## Hex diff vs structural diff: positioning

To close this section, let's clarify the complementarity between ImHex's hex diff and the structural diffing tools we will see in Chapter 10.

| Criterion | Hex diff (ImHex) | Structural diff (BinDiff, Diaphora) |  
|---|---|---|  
| Granularity | Byte by byte | Function by function |  
| What it shows | Which bytes changed, where and how many | Which functions changed, added, or removed |  
| Speed | Immediate, no prior analysis | Requires full analysis of both binaries |  
| Semantic context | None — raw bytes | High — function correspondence, flow graphs |  
| Main use case | Localized patch, flag impact, verification, data | Security patch analysis, code evolution |  
| Very differently sized files | Handles well (shows unmatched zones) | Can mispair functions if the delta is too large |

Both approaches are not in competition. The hex diff is your **first look** — fast, exhaustive, no assumption. The structural diff is your **deep analysis** — slow but semantically rich. In a typical workflow, you start with an ImHex diff to gauge the scope of changes and locate impacted zones, then move to BinDiff or Diaphora to understand the meaning of those changes at the code level.

---

## Limits of the Diff view

ImHex's Diff view is a **linear** comparison tool: it compares bytes at the same offset in both files. It cannot detect **insertions** and **deletions** — if a block of data was inserted in the middle of the file, everything after it appears different because the bytes are shifted, even if their content is identical at an offset.

This limitation is inherent to raw hex diffing. To correctly handle insertions and deletions in a binary, the structural tools (BinDiff, Diaphora) that reason on functions and basic blocks rather than on offsets are much better suited.

In practice, this limitation is rarely bothersome for the three use cases we described — localized patch, flag impact on the same source, before/after stripping — because in these scenarios differences are either punctual or at the end of the file (added or removed sections), and linear diff works correctly.

---

## Summary

ImHex's Diff view compares two files side by side, byte by byte, with highlighting of divergences and navigation between differing zones. It excels in three scenarios: verifying a localized binary patch (only one modified byte should appear), observing the impact of compilation flags on the binary's structure (which sections change, which stay stable), and confirming the effects of stripping (code is intact, only metadata disappears). The hex diff is complementary to the structural diff of Chapter 10: the first is immediate and exhaustive at the byte level, the second is slower but semantically rich at the function level. For Part V's analyses, both will be used in tandem.

---


⏭️ [Searching for magic bytes, encoded strings, and opcode sequences](/06-imhex/08-magic-bytes-search.md)
