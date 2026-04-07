🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.6 — Colorization, annotations, and bookmarks of binary regions

> 🎯 **Goal of this section**: Leverage ImHex's colorization, annotation, and bookmark mechanisms to progressively document the analysis of a binary, produce readable and shareable visual maps, and maintain cumulative context between work sessions.

---

## The analyst's memory problem

Reverse engineering is a long-haul job. You do not understand a binary in a single session. You explore one area, identify a few fields, move to another region of the file, come back to the first with new information gained in the meantime from disassembly or debugging. This back-and-forth can span hours, days, sometimes weeks for complex targets.

The main risk of this iterative process is **loss of context**. You identify that at offset `0x2040` begins a table of 12 entries of 32 bytes each, that the field at offset `+0x08` of each entry is a pointer to `.rodata`, and that the first 4 bytes seem to be a numeric identifier. You move on to something else. Two days later, you come back to this area and have forgotten everything. The bytes are still there, silent, identical — it is your understanding that has evaporated.

`.hexpat` patterns solve part of this problem by formalizing data structure. But a pattern is a **structural** description: it says which types occupy which bytes. It does not capture reasoning, provisional hypotheses, open questions, nor the high-level map of the file. That is exactly the role of bookmarks, annotations, and manual colorization.

---

## Bookmarks: marking and naming regions

### Creating a bookmark

Creating a bookmark follows a simple gesture: select a byte range in the hex view, then use one of these methods:

- Right-click on the selection → **Create Bookmark**  
- Shortcut `Ctrl+B`

ImHex opens a dialog box with four fields:

- **Name** — the bookmark's name, shown in the list and in the hex view on hover. Pick a descriptive and concise name: `Configuration entry table`, `Hardcoded AES key`, `Start of encrypted payload`.  
- **Color** — the highlight color in the hex view. ImHex offers a full color picker. We'll see below how to choose colors consistently.  
- **Comment** — free-form text of arbitrary length. This is where you document your reasoning: why you identified this zone, what hypotheses you formed, which questions remain open.  
- **Region** — start offset and size, pre-filled from your selection. You can adjust them manually if needed.

### The Bookmarks panel

All created bookmarks appear in the **Bookmarks** panel (toggle via **View → Bookmarks** if not already visible). This panel shows a list ordered by offset with the name, color, start offset, size, and start of the comment of each bookmark.

Clicking a bookmark in the list **jumps the hex view** to the matching offset and selects the region. It is a far more ergonomic navigation means than memorizing hex addresses or noting them in a separate text file.

### Modifying and deleting bookmarks

A double-click on a bookmark in the list opens the edit dialog. You can modify the name, color, comment, and region at any time. To delete a bookmark, right-click → **Delete** in the list.

### Bookmarks as an analysis journal

Beyond their navigation function, bookmarks constitute an **analysis journal integrated into the file**. The comment field can contain detailed observations:

```
Name: Serial verification routine  
Offset: 0x1240  
Size: 86 bytes  
Comment:  
  This function compares the user-entered serial
  with a value derived from the username.
  - XOR with 0x5A is applied byte by byte (cf. offset 0x1258)
  - The result is compared with strcmp at offset 0x1280
  - Hypothesis: the derivation key could also depend
    on the name length (to verify with GDB, Chapter 11)
  Status: HYPOTHESIS — not dynamically confirmed
```

This level of documentation turns your ImHex file into an analysis deliverable, not just a working tool. A colleague who opens the project can retrace your reasoning without asking you for explanations.

---

## Colorization: making structure visible

### Automatic pattern colors

When you evaluate a `.hexpat` pattern, ImHex automatically assigns distinct colors to different structures and their fields in the hex view. This default behavior is often sufficient: structures are visually separated from each other, and fields within the same structure are differentiated by shades.

You can influence these colors from the pattern itself with the `[[color(...)]]` attribute seen in section 6.3:

```cpp
u32 magic [[color("FF4444")]];           // bright red — attract attention  
u32 checksum [[color("44FF44")]];        // green — control value  
u8  encrypted_data[256] [[color("4444FF")]]; // blue — encrypted data  
```

### Manual colors via bookmarks

Independently of patterns, bookmarks add a **manual colorization layer** on top of the hex view. Both systems coexist: pattern colors show granular structure (field by field), while bookmark colors show the **functional regions** at a high level ("this area is the header", "this area is the encrypted payload", "this area is padding").

### Choosing a consistent palette

Colorization is only useful if it is readable. When you mark regions manually, adopt a consistent color convention and stick to it throughout the analysis. Here is a palette we will use in the practical cases of this training:

| Color | Hex code | Usage |  
|---|---|---|  
| Red | `#FF6666` | Critical data: crypto keys, passwords, secrets |  
| Orange | `#FFaa44` | Headers and structure metadata |  
| Yellow | `#FFEE55` | Strings, names, textual identifiers |  
| Green | `#66DD66` | Checksums, CRC, integrity check values |  
| Blue | `#6699FF` | Executable code, opcodes |  
| Purple | `#CC88FF` | Encrypted or compressed data |  
| Gray | `#AAAAAA` | Padding, reserved zones, non-significant bytes |

This convention is arbitrary — the key is **consistency** within a single project. If you work in a team, document your palette in a `CONVENTIONS.md` file at the project root.

> 💡 **Contrast and readability**: ImHex displays hex text over the background color. Avoid colors too dark that make bytes unreadable, and colors too saturated that tire the eye. Pastels (high values with a bit of white) work better for prolonged use.

---

## Annotations in patterns: `[[comment]]` and `[[name]]`

Bookmarks document **regions** of the file. Pattern attributes document **individual fields**. The two complement each other.

### `[[comment]]` for technical context

The `[[comment(...)]]` attribute adds explanatory text visible on hover of a field in the Pattern Data tree. Use it for technical information that helps interpret the value:

```cpp
struct NetworkPacket {
    be u16 total_length  [[comment("Total packet size, header included, big-endian")]];
    u8     ttl           [[comment("Time To Live — decremented at each hop")]];
    u8     protocol      [[comment("6 = TCP, 17 = UDP, 1 = ICMP")]];
    be u32 src_addr      [[comment("Source IP address, big-endian")]];
    be u32 dst_addr      [[comment("Destination IP address, big-endian")]];
};
```

Each field carries its explanation. A reader who expands this structure in Pattern Data immediately understands each value's meaning without consulting external documentation.

### `[[name]]` for readability

The `[[name(...)]]` attribute replaces the variable's technical name with a more readable label in the tree:

```cpp
u16 e_shstrndx [[name("Index of .shstrtab section")]];
```

In the tree, instead of seeing `e_shstrndx = 29`, you see `Index of .shstrtab section = 29`. This is particularly useful when variable names follow a technical naming convention (like the ELF field names) that is not immediately meaningful.

### `[[format]]` for alternative representations

We already used it in section 6.4, but let's mention it in this annotation context: `[[format("hex")]]` displays a value in hexadecimal rather than decimal. It is a form of annotation that improves readability of addresses, offsets, bitmasks, and magic numbers.

A few useful formats:

```cpp
u32 address   [[format("hex")]];      // 0x00401000 instead of 4198400  
u32 perms     [[format("octal")]];    // 0755 instead of 493  
u8  flags     [[format("binary")]];   // 0b10110001 instead of 177  
```

---

## Combining patterns and bookmarks: a two-level strategy

In practice, patterns and bookmarks are not used the same way or at the same time of the analysis. Here is how to combine them efficiently.

### Exploratory phase: bookmarks first

When you open an unknown binary for the first time, you do not yet know what structures it contains. The exploratory phase consists of traversing the file, spotting interesting areas, and marking them. Bookmarks are the tool for this phase:

- You spot a magic number at offset `0x00` → bookmark "Magic number / header".  
- You find an ASCII strings zone at offset `0x3000` → bookmark "String table".  
- You observe a high-entropy zone at offset `0x5000` → bookmark "Encrypted data?".  
- You identify recognizable opcode sequences at offset `0x1000` → bookmark "Start of code".

In a few minutes, you have a **rough map** of the file, materialized by colored blocks in the hex view and a navigable list in the Bookmarks panel.

### Structural phase: patterns afterwards

Once areas of interest are identified, you start writing `.hexpat` patterns to parse them structurally. The header pattern gradually replaces the bookmark "Magic number / header" with a field-by-field description. The string-table pattern replaces the matching bookmark with a parsing that shows each string individually.

Bookmarks do not disappear. They evolve: exploratory bookmarks become **documentation** bookmarks capturing the high-level reasoning, while patterns take over low-level structural documentation.

### The result: a self-documented file

At the end of the analysis, the ImHex file (saved as a project) contains:

- **Patterns** that parse and colorize the identified data structures.  
- **Bookmarks** that name the large functional regions and document reasoning.  
- **Comments** in patterns that explain each field.

Together, these three layers form **living documentation** of the binary — far richer than a static text report, because it is interactive, navigable, and directly verifiable on the bytes.

---

## ImHex projects: persisting the analysis between sessions

All this documentation (bookmarks, loaded patterns, panel layout) would be lost when closing ImHex if not saved. That is the role of **projects**.

### Saving a project

**File → Save Project** (or `Ctrl+Shift+S`) saves the complete state of your session to a `.hexproj` file. This file contains:

- The reference to the analyzed binary file (path).  
- All created bookmarks (names, colors, regions, comments).  
- The `.hexpat` pattern currently loaded in the Pattern Editor.  
- The panel layout of the interface.  
- The Diff view's data if it is active.

### Reopening a project

**File → Open Project** restores the entirety of the saved state. You recover your bookmarks, your pattern, your window layout — exactly where you left off.

### Naming best practices

Adopt a naming convention for your projects. One suggestion:

```
<binary>_analysis_<date>.hexproj
```

For example: `keygenme_O0_analysis_2025-03-15.hexproj`. If you work on multiple aspects of the same binary (structure, crypto, protocol), you can create separate projects, each with its specialized bookmarks and patterns.

> 💡 **Versioning**: `.hexproj` files are structured text (JSON). You can version them in a Git repo alongside your `.hexpat` patterns and analysis scripts. The `hexpat/` folder of our training is made for this.

---

## Exporting the map

ImHex does not natively produce a "PDF report" of your analysis, but you can **export** documentation information in several ways.

**Annotated screenshots.** The colorized hex view with visible bookmarks produces very telling visual captures for a report or presentation. On Linux, a tool like `flameshot` or simply `Ctrl+PrintScreen` does the job.

**Bookmark list export.** The Bookmarks panel does not have a dedicated "Export" button, but the data is saved in the `.hexproj` file (JSON format) and can be extracted by a Python script if you need a summary table for a report.

**The pattern as documentation.** A well-commented `.hexpat` file (with `[[comment]]`, `[[name]]`, and `//` comments) is itself technical documentation of the analyzed format. You can share it independently of the ImHex project — anyone with ImHex and the binary can evaluate your pattern and recover your analysis.

---

## Summary

Bookmarks, colorization, and annotations transform ImHex from a simple inspection tool into a **documented analysis environment**. Bookmarks capture high-level reasoning and enable navigation by points of interest. Colorization — automatic via patterns or manual via bookmarks — makes the file structure visible at a glance. The `[[comment]]`, `[[name]]`, and `[[format]]` attributes in patterns document each field individually. The optimal strategy combines both levels: exploratory bookmarks first to map the file, structural patterns afterwards to formalize understanding. The whole is persisted in a `.hexproj` project that preserves the entire analysis between sessions and can be versioned in a Git repo.

---


⏭️ [Comparing two versions of the same GCC binary (diff)](/06-imhex/07-comparison-diff.md)
