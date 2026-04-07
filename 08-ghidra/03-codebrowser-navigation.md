🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.3 — Navigation in the CodeBrowser: Listing, Decompiler, Symbol Tree, Function Graph

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## The CodeBrowser: your reverse-engineering workshop

The CodeBrowser is Ghidra's central tool — it's here you'll spend most of your analysis time. If the Project Manager is the entrance hall, the CodeBrowser is the workshop. It opens automatically when you double-click an imported binary in the Project Manager, or manually by dragging the binary onto the green dragon icon in the Tool Chest.

The CodeBrowser is composed of **panels** (windows) arranged in a default layout you can fully customize. Each panel offers a different view on the same binary, and these views are **synchronized**: navigating in one updates the others. This synchronization is what makes the tool powerful — you observe simultaneously the machine code, the C pseudo-code, the symbols, and the flow graph of the same function.

This section describes each panel in detail, explains how to use them efficiently, and how to make them collaborate.

---

## The Listing panel (assembly view)

### Role

The Listing is the central and historically most important panel. It displays the **linear disassembly** of the binary: each line corresponds to an address and shows the assembly instruction decoded at that address, accompanied by its annotations.

It's the graphical and interactive equivalent of `objdump -d`'s output, but with a fundamental difference: the Listing is not a read-only view. You can interact with each element — rename, retype, comment, navigate by click, create manual references.

### Anatomy of a Listing line

A typical Listing line in an x86-64 ELF binary with symbols looks like this:

```
00401156  48 89 e5        MOV    RBP,RSP
```

From left to right:

- **The virtual address** (`00401156`) — the instruction's location in the process's address space. It's the address as it would appear in `rip` at execution (modulo ASLR for a PIE binary).  
- **Raw bytes** (`48 89 e5`) — the instruction's machine encoding. This column is hideable via **Edit → Tool Options → Listing Fields → Bytes Field**. It's useful for binary patching (Chapter 21) and for recognizing specific opcodes.  
- **The mnemonic** (`MOV`) — the name of the assembly instruction.  
- **Operands** (`RBP,RSP`) — the instruction's arguments, in the default syntax (Ghidra uses a format close to Intel syntax).

Around this basic structure, Ghidra adds several layers of contextual information:

- **Labels** — above the first instruction of a function, Ghidra displays the function's name (for example `main`, `check_key`, `FUN_004011a0`). These labels serve as anchor points for navigation.  
- **Automatic comments** — Ghidra adds end-of-line comments for resolved references. For example, a `LEA RDI,[.rodata:s_Enter_key:_]` will be annotated with the string's content. Calls to known functions are annotated with the target's name.  
- **Cross-references (XREF)** — above a function label or a data item, Ghidra lists the addresses that reference this location. For example, `XREF[2]: main:00401203(c), FUN_00401300:00401345(c)` indicates that two locations call this function. The `(c)` suffix means *call*, `(j)` means *jump*, and `(*)` means *data reference* (pointer).  
- **Function separators** — horizontal lines visually separate functions from each other, facilitating boundary spotting.

### Navigation in the Listing

Navigation is at the heart of the experience. Here are the essential mechanisms:

**Click navigation** — Double-click an operand that is an address or function name to jump directly to it. For example, double-clicking `check_key` in a `CALL check_key` instruction takes you to that function's start. Double-clicking a reference to `.rodata` takes you to the matching data.

**Navigation history** — Ghidra maintains a history of your movements, like a web browser. Use the arrow buttons of the toolbar (or `Alt+←` / `Alt+→`) to go back or forward. It's indispensable when exploring nested call chains and wanting to find your starting point.

**Go To Address (`G`)** — Opens an input field to jump to a precise address, function name, or label. Accepts hexadecimal addresses (with or without `0x` prefix), symbol names, and simple arithmetic expressions.

**Text search (`Ctrl+Shift+E`)** — Searches in the Listing's displayed text (mnemonics, operands, comments). Useful for looking for all occurrences of a particular register or constant.

**Function navigation** — Toolbar keys allow jumping to the next or previous function in the address space. More practical: use the Symbol Tree (described below) to navigate directly by function name.

### The field header bar (Field Header)

The Listing is actually composed of **fields** individually configurable. By activating the field header via **Edit → Tool Options → Listing Fields**, you can:

- show or hide columns (raw bytes, addresses, XREFs, platform comments);  
- reorder columns;  
- adjust the width of each field.

The default configuration suits in most cases, but you might want to hide raw bytes to gain horizontal space, or display offsets relative to the function's start to facilitate correlation with `objdump` outputs.

---

## The Decompiler panel (C pseudo-code)

### Role

The Decompiler is probably the feature that most distinguishes Ghidra from a simple disassembler. It transforms machine code into human-readable **C pseudo-code**, by rebuilding control structures (`if`, `while`, `for`, `switch`), arithmetic expressions, function calls with their arguments, and accesses to local variables.

The Decompiler panel displays the pseudo-code of **the function currently selected in the Listing**. Every time you navigate to a new function in the Listing, the Decompiler updates to show the matching pseudo-code.

### Bidirectional synchronization

Synchronization between Listing and Decompiler is **bidirectional**:

- Clicking an instruction in the Listing highlights the matching line in the Decompiler.  
- Clicking a line or variable in the Decompiler highlights the matching assembly instructions in the Listing.

This correspondence is not always bijective. A single line of pseudo-code may correspond to multiple assembly instructions (for example, a complex expression), and conversely, an assembly instruction may contribute to multiple pseudo-code lines (rare cases, but possible with optimizations).

The highlighting uses a color code to show which pseudo-code elements correspond to which instructions. Get into the habit of clicking alternately in both panels to develop your intuition for the correspondence between C and assembly — it's one of the best exercises for progressing in reverse engineering.

### Reading the pseudo-code

The pseudo-code produced by Ghidra looks like C, but it is not compilable C. It's a **structural approximation** of the machine code's behavior. Here are the conventions to know:

**Generic types** — When Ghidra doesn't know a variable's exact type, it uses size-based generic types:

- `undefined1` — one byte of unknown type;  
- `undefined4` — 4 bytes (often an `int` or `float`);  
- `undefined8` — 8 bytes (often a `long`, `double`, or pointer);  
- `long` — Ghidra sometimes uses `long` when it detects an 8-byte integer via flow analysis.

As you annotate the binary (section 8.4), these generic types will be replaced with precise types.

**Local variables** — Variables are automatically named according to a predictable scheme:

- `local_XX` — local variable at offset `XX` (hexadecimal) relative to the frame pointer or stack pointer;  
- `param_1`, `param_2`, etc. — function parameters, in calling-convention order;  
- `iVar1`, `lVar2`, `uVar3` — temporary variables created by the decompiler. The prefix indicates the inferred type: `i` for `int`, `l` for `long`, `u` for `uint`, `p` for pointer, `c` for `char`, `b` for `bool`.

**Explicit casts** — The decompiler inserts `(type)` casts when it detects implicit type conversions in machine code. These casts are often verbose but faithfully reflect the binary's behavior.

**Variable quality** — The pseudo-code of a `-O0` binary with DWARF symbols can be nearly identical to the original source code. The pseudo-code of a stripped `-O3` binary will be functionally correct but structurally unrecognizable: unrolled loops, inlined functions, variables fused into registers. Don't expect to recover the original source — expect to understand the behavior.

### Interactions in the Decompiler

The Decompiler panel is not just a passive view. You can interact directly with the pseudo-code:

- **Rename a variable or parameter** — Right-click → **Rename Variable** (or `L` key). The new name propagates throughout the function's pseudo-code and is reflected in the Listing.  
- **Change a variable's type** — Right-click → **Retype Variable** (or `T` key). Particularly useful for transforming an `undefined8 *` into `struct player_t *` once you've reconstructed the structure.  
- **Navigate to a called function** — Double-click a function name in the pseudo-code to jump to it, exactly like in the Listing.  
- **Display cross-references** — Right-click on an identifier → **References to** to see all places that access this variable or call this function.  
- **Modify the function's signature** — Right-click on the function name at the top of the pseudo-code → **Edit Function Signature**. You can correct the return type, parameter types and names, and calling convention. The decompiler updates immediately.

> 💡 **Productivity tip** — When you analyze a function, start by identifying and renaming parameters in the Decompiler. That single action often makes the rest of the pseudo-code immediately understandable, because the names propagate in all expressions that use these parameters.

---

## The Symbol Tree panel

### Role

The Symbol Tree is the **directory** of everything Ghidra has identified in the binary: functions, labels, namespaces, classes, imports, exports, and global variables. It's your main navigation tool at the binary's scale — rather than moving address by address in the Listing, you browse the Symbol Tree to directly reach the function or data item you're interested in.

### Tree structure

The Symbol Tree is organized in hierarchical categories:

**Imports** — Functions imported from shared libraries. In an ELF binary dynamically linked to libc, you'll find here functions like `printf`, `malloc`, `strcmp`, `open`, `read`, etc. These names come from the `.dynsym` table and are always available, even in a stripped binary (because the dynamic linker needs them to resolve symbols at execution).

Imports are grouped by source library. You'll see for example:

```
Imports
├── libc.so.6
│   ├── printf
│   ├── malloc
│   ├── strcmp
│   ├── exit
│   └── ...
├── libstdc++.so.6
│   ├── __cxa_throw
│   ├── operator new(unsigned long)
│   └── ...
└── libm.so.6
    ├── sqrt
    └── ...
```

This organization immediately gives you an overview of the program's capabilities: a binary importing network functions (`socket`, `connect`, `send`, `recv`) is probably a client or server; a binary importing `dlopen`/`dlsym` dynamically loads plugins; a binary importing crypto functions (`EVP_EncryptInit`, `AES_encrypt`) performs encryption.

**Exports** — Functions and data exported by the binary. For a classic executable, there are few (essentially `_start` and symbols linked to C runtime initialization). For a shared library (`.so`), exports constitute the library's public API.

**Functions** — The list of all functions identified in the binary, whether they come from symbols or heuristic analysis. In a binary with symbols, you find real names (`main`, `check_key`, `process_input`). In a stripped binary, you find auto-generated names (`FUN_00401156`, `FUN_004012a0`).

If the binary is C++ with symbols, functions are organized in **namespaces** and **classes**, reflecting the source code's hierarchy:

```
Functions
├── main
├── Animal
│   ├── Animal(void)
│   ├── ~Animal(void)
│   └── speak(void)
├── Dog
│   ├── Dog(char const *)
│   └── speak(void)
└── ...
```

This hierarchical organization is one of Ghidra's major strengths for C++ analysis — it survives partially even in a stripped binary if RTTI is present (section 8.5).

**Labels** — Named labels that are not functions: block entry points, jump targets, named addresses in data.

**Classes** — Specific to C++: classes detected via vtables, RTTI, or DWARF information. This node can be empty for a pure C binary.

**Namespaces** — C++ namespaces and logical symbol groupings.

### Search and filtering

The Symbol Tree integrates a **filter field** at the bottom of the panel. Type a few characters to dynamically filter entries. It's extremely efficient for quickly locating a function by partial name.

For example, in a C++ game binary, typing `player` will filter all functions and classes whose name contains "player": `Player::update`, `Player::getHealth`, `process_player_input`, etc.

The filter also accepts the `*` wildcard character for pattern searches.

### Navigation from the Symbol Tree

Double-click any Symbol Tree element to navigate directly to its address in the Listing (and via synchronization, in the Decompiler). It's the fastest way to reach a specific function.

Right-clicking an element opens a context menu that allows, among other things, renaming it, viewing its references (who calls it, who accesses it), editing it (for a function: modifying the signature), or searching it in other views.

---

## The Function Graph panel

### Role

The Function Graph (or graph view) transforms a function's linear disassembly into a **diagram of basic blocks** connected by edges. Each basic block is a sequence of instructions that always execute linearly (no internal branching); edges represent conditional and unconditional jumps between blocks.

This view is indispensable for understanding a function's **control logic**: which execution paths are possible, where conditional branches are located, what are the loops, and how the different cases of a `switch` are organized.

### Accessing the Function Graph

From the Listing, place the cursor in the function you wish to visualize, then:

- press **`Space`** to toggle between the linear Listing view and the graph view (and vice versa);  
- or use the **Window → Function Graph** menu.

The graph displays in the central panel, temporarily replacing the linear Listing (if you use `Space`) or in a separate window (if you use the menu).

### Reading the graph

The graph reads top to bottom. The function's entry block (containing the prologue) is at the top. The exit block(s) (containing `RET`) are at the bottom.

**Edge color code** — Ghidra colors edges to indicate the type of branch:

- **Green** — the branch taken when the condition is **true** (for example, the path taken by `JZ` when ZF=1, that is when the comparison is equal).  
- **Red** — the branch taken when the condition is **false** (the *fall-through*, when the conditional jump is not taken).  
- **Blue** — an unconditional jump (`JMP`).

> ⚠️ **Beware of interpretation** — The convention green=true/red=false concerns the assembly test result, not the business logic. A `JNZ` (Jump if Not Zero) after a `CMP` jumps (green) when values are **different**. If the code compares a password, the green branch of `JNZ` corresponds to the case "incorrect password" (strings differ), which can be counterintuitive. Always take the time to read the comparison instruction and the jump type before interpreting colors.

**Block content** — Each block displays the same information as the linear Listing: addresses, instructions, operands, comments. You can click any element inside a block for the same interactions as in the Listing (renaming, retyping, navigation).

### Common visual patterns

With practice, you'll learn to visually recognize classic control structures directly in the graph, without even reading instructions:

**An `if`/`else`** — The test block has two outgoing edges (green and red) that lead to two distinct blocks, which then converge to a common block (the code after the `if`/`else`). The shape is a diamond.

**An `if` without `else`** — The test block has two edges: one leads to a processing block that then rejoins the main flow, the other goes directly to the main flow. The shape is a triangle.

**A `while` or `for` loop** — A test block has an edge that goes back up to a block located higher in the graph (back edge). The loop condition is in the test block, and the loop body is in the blocks between the test and the back edge.

**A `switch`/`case`** — A single block has many outgoing edges (one per case), creating a fan of parallel blocks that converge to a common point after the `switch`. Ghidra often detects jump tables and annotates them in the listing.

**Linear functions** — A vertical sequence of blocks without branching. Typical of initialization functions or wrappers.

### Zoom and navigation in the graph

Graphs of complex functions can become very large (dozens of blocks for a function with lots of conditional logic). Ghidra offers several mechanisms to find your way:

- **Mouse wheel** — zoom in/out.  
- **Click-drag on the background** — move the view.  
- **Minimap** — a minimap of the complete graph appears in a corner. The white rectangle indicates the currently visible portion. Click-drag in the minimap to navigate quickly.  
- **Right-click → Reset Layout** — reorganizes the graph if the automatic layout produced a confused result.

### Function Graph limits

The Function Graph only shows **one function at a time**. It doesn't show calls to other functions as sub-graphs — a `CALL` appears as an instruction in a block, not as an edge to another graph. To explore called functions, double-click the `CALL` to navigate to the target, then press `Space` to see its graph.

For very large functions (hundreds of blocks), the graph can become hard to read. In this case, the linear Listing combined with the Decompiler is often more effective, and you can return to the graph for specific portions.

---

## Secondary panels

Beyond the four main panels described above, the CodeBrowser offers several complementary panels accessible via the **Window** menu. Here are the most useful in the context of this tutorial.

### Program Trees

Located by default at the top left (in a tab with the Symbol Tree), the Program Trees displays the binary's structure in terms of **memory segments and sections**. You find there the ELF sections studied in Chapter 2: `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.init`, `.fini`, etc.

Double-clicking a section navigates to its start in the Listing. It's useful when you specifically search for read-only data (`.rodata`), global variables (`.data`/`.bss`), or PLT/GOT entries (`.plt`/`.got`).

### Data Type Manager

Accessible via **Window → Data Type Manager**, this panel is Ghidra's type manager. It displays available types, organized into categories:

- **BuiltInTypes** — primitive C/C++ types (`int`, `long`, `char`, `void *`, `float`, `double`, etc.);  
- **Type archives** — Ghidra embeds type archives (`.gdt`) for common libraries. The `generic_clib` archive contains libc function signatures; `windows_vs12` contains Windows API types. These archives are loaded automatically depending on context.  
- **Program types** — types specific to the binary currently being analyzed, including automatically detected structures and those you'll create manually (section 8.6).

The Data Type Manager will be covered in detail in sections 8.4 and 8.6. Remember for now that it exists and that it's the central access point for everything related to typing.

### Defined Strings

Accessible via **Window → Defined Strings**, this panel lists all character strings identified in the binary. It's the interactive equivalent of `strings`, but with the advantage of a direct link to the usage context: double-clicking a string navigates to its location in the Listing, and from there, you can use cross-references (`X`) to see which code references it.

This panel is one of the first you'll consult during the triage of a binary in Ghidra. Character strings often reveal a program's functionality: error messages, file names, URLs, protocol commands, license messages.

### Console

The Console panel at the bottom of the CodeBrowser displays log messages: analysis results, errors, script outputs. When you run Ghidra scripts (section 8.8), it's here their `println` and error messages will appear.

### Bookmarks

Ghidra lets you place **bookmarks** at any address via right-click → **Bookmark…** or `Ctrl+D`. Bookmarks appear in the **Window → Bookmarks** panel. It's a note-taking tool integrated into the binary: mark interesting functions, critical decision points, areas to revisit later.

Automatic analysis also creates automatic bookmarks to flag anomalies: unresolved code, invalid references, disassembly errors. Go through them after the initial analysis to identify problem areas.

---

## Typical navigation workflow

To illustrate how these panels collaborate, here is a typical workflow during the initial analysis of a binary:

**Step 1 — Orientation via the Symbol Tree.** Open the Symbol Tree and browse the **Functions** category. If the binary has symbols, spot `main` and functions with evocative names. If the binary is stripped, look at **Imports** to understand the program's capabilities, then find the entry point via **Exports → _start** or via **Navigation → Go To → Entry Point**.

**Step 2 — Reading the Decompiler.** Double-click `main` (or the identified entry point). The Decompiler displays the pseudo-code. Read it to understand the overall structure: which functions are called, in what order, with what arguments. Note the names of interesting functions to explore.

**Step 3 — Dive into a target function.** Double-click a function call in the Decompiler to navigate to it. Read the pseudo-code of this new function. If the control logic is complex, switch to graph view with `Space` to visualize the branching structure.

**Step 4 — Listing ↔ Decompiler correlation.** When a line of pseudo-code is obscure, click on it to see the matching assembly instructions in the Listing. Analyze the machine code to understand what the decompiler is trying to express.

**Step 5 — Verification via strings.** Open **Defined Strings** to look for revealing strings. Double-click an interesting string, then use `X` (Show References) to work back to the code that uses it.

**Step 6 — Progressive annotation.** As you understand, rename functions and variables (`L`), add comments (`;`), and modify types (`T`). Each annotation improves the readability of caller and callee functions thanks to automatic propagation.

This workflow isn't a rigid recipe — it's a framework you'll adapt to each binary. The key is to understand that analysis is an **iterative** process: every annotation you add enriches the context for what follows.

---

## Customizing the layout

The CodeBrowser's default arrangement is a reasonable starting point, but you'll quickly develop your preferences. A few popular configurations:

**"Intensive analysis" layout** — Listing and Decompiler side by side in maximum occupation, Symbol Tree in a reduced tab on the left. Maximizes reading space for the two main views.

**"Exploration" layout** — Symbol Tree widely open on the left, Decompiler alone on the right (Listing hidden or in a tab). Favors symbol navigation and pseudo-code reading. Suited to the orientation phase on a large binary.

**"Graph" layout** — Function Graph in full central screen, Decompiler in a right side panel. Used occasionally for analyzing a complex function's control logic.

To save a layout, use **Window → Save Tool**. You can create multiple configurations and switch between them depending on the analysis phase.

---

## Summary

The CodeBrowser is the environment where most of the analysis work takes place. Its four main panels — Listing, Decompiler, Symbol Tree, and Function Graph — each offer a complementary perspective on the binary, and their synchronization allows fluid navigation between machine code and a high-level view. Secondary panels (Program Trees, Data Type Manager, Defined Strings, Bookmarks) enrich this setup with specialized views.

Mastery of this interface is progressive. First focus on the Listing–Decompiler–Symbol Tree triangle, which covers 90% of common analysis needs, then integrate the Function Graph when tackling functions with complex control logic.

The next section will show you how to turn an anonymous disassembly into a readable document via renaming, comments, and the creation of custom types.

---


⏭️ [Renaming functions and variables, adding comments, creating types](/08-ghidra/04-renaming-comments-types.md)
