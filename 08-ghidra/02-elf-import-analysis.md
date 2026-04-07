🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.2 — Importing an ELF binary — automatic analysis and options

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## What happens when you import a binary

Importing into Ghidra is not a simple copy operation. It's a two-phase process that transforms a raw file on disk into a structured database ready to be explored:

1. **Loading** — Ghidra reads the file, identifies its format (ELF, PE, Mach-O, raw…), parses the headers, maps sections in virtual memory, resolves available symbols, and rebuilds the import/export table. At the end of this phase, you have a virtual address space populated with raw bytes, with the format's structural metadata.

2. **Automatic analysis** — Ghidra runs a battery of analyzers that transform these raw bytes into annotated disassembled code. It's this phase that identifies functions, detects strings, resolves cross-references, rebuilds function signatures, and feeds the decompiler. The quality of this analysis directly conditions the readability of the result.

Understanding these two phases is essential, because each offers configuration options that significantly influence the quality of the final analysis.

---

## Phase 1: the import dialog

When you import a file via **File → Import File…** (or by drag-and-drop into the Project Manager), Ghidra displays an import dialog with several configurable fields.

### Format

Ghidra automatically detects the file's format thanks to its magic bytes. For an ELF binary produced by GCC, it displays **Executable and Linking Format (ELF)**. This field is a dropdown that proposes other loaders if automatic detection fails or if you wish to force a particular format.

The formats you'll encounter in this tutorial are mainly:

- **ELF** — native Linux binaries produced by GCC/G++, the largely majority case of this training;  
- **PE** — Windows binaries, which you might come across if you compile with MinGW (mentioned in Chapter 2);  
- **Raw Binary** — useful when the file has no recognized headers (firmware, memory dump, shellcode). Ghidra then loads raw bytes without structural interpretation.

In nearly all cases of this tutorial, automatic detection is correct and you have nothing to modify.

### Language / Architecture

This field determines the **processor** and the **instruction set** Ghidra will use for disassembly. For an x86-64 ELF binary, Ghidra automatically proposes:

```
x86:LE:64:default (gcc)
```

Let's decompose this notation:

- `x86` — Intel/AMD processor family;  
- `LE` — Little Endian (byte order in memory, standard on x86);  
- `64` — word size (64 bits, that is the AMD64/x86-64 architecture);  
- `default` — variant of the machine language (Ghidra sometimes supports multiple variants for the same architecture);  
- `(gcc)` — the *compiler spec*, that is the calling convention. `gcc` corresponds to the System V AMD64 ABI convention we studied in Chapter 3.

This last point deserves particular attention. The *compiler spec* tells Ghidra how to interpret parameter passing and return values. If the binary was compiled with GCC under Linux, `gcc` is the right choice — and that's what Ghidra selects by default when detecting the ELF format. For a Windows PE binary compiled with MSVC, the compiler spec would be `windows`, which matches Microsoft's x64 calling convention.

> ⚠️ **Classic pitfall** — If you analyze a 32-bit binary (compiled with `gcc -m32`), Ghidra must detect `x86:LE:32:default`. If by mistake you force 64-bit mode on a 32-bit binary, the disassembly will be incoherent: instructions will be misdecoded, registers will have incorrect names, and the decompiler will produce absurd pseudo-code. Always verify consistency with the output of `file`:  
> ```bash  
> file keygenme_O0  
> # keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), ...  
> ```

### Destination Folder

The folder in the Ghidra project tree where the imported binary will be placed. By default, it is placed at the project root. You can create subfolders to organize your binaries by chapter or optimization variant.

### Import options ("Options…" button)

The **Options…** button at the bottom of the import dialog gives access to advanced settings specific to the ELF loader. The most useful for our context are as follows.

#### Image Base

The base address at which the binary will be mapped in memory in Ghidra's address space. For a non-PIE ELF binary, this address is fixed by the linker (typically `0x400000` for a classic x86-64 executable). For a PIE (Position Independent Executable) binary, Ghidra's ELF loader chooses a default base address (often `0x100000`).

In most cases, leave the default value. You might want to change it if you analyze a memory dump and know the real load address, or if you compare two binaries and want them mapped at the same base.

#### Load External Libraries

This option controls whether Ghidra attempts to load shared libraries referenced by the binary (such as `libc.so.6`, `libstdc++.so`, `libm.so`). By default, it is **disabled**, and that's generally the right choice for our exercises.

Loading external libraries has the advantage of resolving imported symbols and allowing the decompiler to know the exact signatures of libc functions. But it considerably weighs down the project (libc alone contains thousands of functions) and increases analysis time. For our training binaries, Ghidra already has built-in signatures for common libc functions (`printf`, `malloc`, `strcmp`, etc.) via its type files (Data Type Archives), which generally makes external loading superfluous.

#### Apply Processor/Loader-Defined Labels

Enables applying labels from ELF symbol tables (`.symtab`, `.dynsym`). This option should remain **enabled** — it's what allows Ghidra to name functions with their real names when the binary is not stripped.

---

## Phase 2: automatic analysis

Once the import is finished, Ghidra displays a summary (number of loaded sections, address ranges, detected symbols) then offers to launch **Auto Analysis**. It's here that the raw binary transforms into a structured, navigable disassembly.

### The "Analysis Options" dialog

Clicking **Yes** to launch analysis, Ghidra opens a window listing all available **analyzers**, each with a checkbox and sometimes its own configuration options. The list is long — Ghidra 11.x offers several dozen analyzers. You don't need to understand each one to be effective. Let's focus on those that have the most impact on the analysis of x86-64 ELF binaries compiled with GCC.

### Key analyzers

#### ASCII Strings

Scans the entire address space looking for byte sequences that look like ASCII (and UTF-8/UTF-16) character strings. Each detected string is typed as `string` in the listing and becomes consultable via **Window → Defined Strings**.

This analyzer is the automated equivalent of the `strings` command you used in Chapter 5, but integrated in the disassembly context: strings are directly linked to the instructions that reference them.

This analyzer's configuration options let you tune the minimum length of strings (5 characters by default), the character set to detect, and whether the analyzer should create strings only in data sections or also in code sections.

> 💡 **Tip** — For a first triage, the default options suit. If you find after analysis that short but significant strings (like 3-4 character command names in a network protocol) were not detected, you can rerun this analyzer alone with a lower threshold (see "Relaunching a targeted analysis" below).

#### Decompiler Parameter ID

This analyzer uses Ghidra's decompiler to deduce the **parameter types** of each function and propagate this information in the listing. It's one of the most powerful analyzers: it allows the decompiler to produce pseudo-code with typed function signatures rather than a flow of operations on anonymous registers.

By default, this analyzer is **enabled** in recent Ghidra versions. Verify it is checked. Its execution noticeably lengthens the analysis time (it invokes the decompiler on each detected function), but the readability gain is considerable.

#### ELF Scalar Operand References

Specific to ELF binaries. This analyzer tries to resolve scalar operands (numeric constants in instructions) into references to known addresses. For example, if a `mov` instruction loads a constant that matches the address of a string in `.rodata`, this analyzer will create an explicit reference, making the listing much more readable.

#### Function Start Search

Searches for function starts that the main analyzer missed. It uses heuristics based on typical prologue patterns (`push rbp ; mov rbp, rsp` at `-O0`, `endbr64` with CET enabled, etc.) and on function alignments.

This analyzer is particularly useful on **stripped** binaries, where the symbol table provides no information about function boundaries. Ghidra must then rely entirely on control-flow analysis and these heuristics to delimit functions.

#### GCC Exception Handlers

Parses the `.eh_frame` and `.gcc_except_table` sections produced by GCC for C++ exception handling. This analyzer is crucial if you analyze a C++ binary: it rebuilds the relationships between `try`/`catch` blocks and cleanup functions (destructors called during stack unwinding).

If you analyze a pure C binary (like `keygenme`), this analyzer is harmless — it simply won't find anything to process.

#### Stack

Analyzes function prologues and epilogues to rebuild the **stack layout** (stack frame) of each function: local variables, stacked parameters, register-save zones. The result appears as variables named `local_XX` and `param_X` in the decompiler.

It's one of the most critical analyzers for readability. Without it, the decompiler would only show raw accesses to `RSP+offset`.

#### Demangler GNU

Applies the demangling of C++ symbols according to the Itanium ABI conventions used by GCC/G++ (the same rules as `c++filt`, covered in Chapter 7). Transforms for example `_ZN6Animal5speakEv` into `Animal::speak(void)`.

Without this analyzer, C++ function names would remain in their mangled form, making navigation in the Symbol Tree laborious.

### Analyzers of less immediate impact

Some analyzers are useful in specific contexts but less critical for a first analysis:

- **Aggressive Instruction Finder** — searches for code in unreferenced zones. Useful for detecting dead or obfuscated code (Chapter 19), but can generate noise by creating false functions from data interpreted as instructions. Disabled by default, and that's generally the right choice for a first pass.  
- **DWARF** — parses DWARF debug information if the binary was compiled with `-g`. Recovers local variable names, line numbers, structure types, and parameter types as defined in the source code. Extremely valuable when available — it's like having part of the source code integrated into the binary. This analyzer is active by default and runs automatically when DWARF sections are detected.  
- **Condense Filler Bytes** — groups `NOP` sequences (alignment padding between functions) into annotated blocks rather than listing them instruction by instruction. Purely cosmetic but improves readability.  
- **Non-Returning Functions** — identifies functions that never return (`exit`, `abort`, `__stack_chk_fail`, `__cxa_throw`…). Important for the accuracy of the control-flow graph: without this information, Ghidra might believe code follows a call to `exit()` and try to disassemble it.

---

## The analysis process in detail

### Execution order and dependencies

Analyzers don't run in parallel in a disordered way. Ghidra orchestrates them via a system of **priorities** and **dependencies**. For example:

1. The ELF loader first resolves symbols and maps sections.  
2. The string analyzer identifies strings in `.rodata`.  
3. Control-flow analysis identifies functions.  
4. The Demangler GNU transforms mangled names.  
5. The Stack analyzer rebuilds frames.  
6. The Decompiler Parameter ID refines types.

You don't need to know the exact order, but this sequence explains why some information only appears after analysis fully finishes. If you navigate the binary while analysis runs (this is possible — the CodeBrowser is usable during analysis), you'll find that function names, types, and cross-references enrich progressively.

### Progress indicator

During analysis, a progress bar appears at the bottom right of the CodeBrowser, along with the name of the analyzer currently executing. On a small binary like `keygenme_O0` (~15 KB), complete analysis takes a few seconds. On a substantial C++ binary with STL and templates (~1-5 MB), count a few minutes. On a very large binary (full server, video game, firmware), analysis can last long minutes or even tens of minutes.

You can interrupt the running analysis via the cancel button next to the progress bar. Partial analysis is preserved — you don't lose the work already done.

### Relaunching a targeted analysis

It's frequent to want to rerun one or more analyzers after initial analysis, for example:

- after renaming functions and adding types (the Decompiler Parameter ID can then produce better results in a second pass);  
- after modifying options of an analyzer (for example, lowering the minimum string length);  
- after manually identifying new functions that the initial analysis missed.

To rerun analysis, use **Analysis → Auto Analyze…** from the CodeBrowser. The same options dialog appears. You can uncheck all analyzers except the one you wish to relaunch, then click **Analyze**.

> 💡 **Practical tip** — If you have substantially annotated the binary (renaming dozens of functions, creating structure types), relaunch the **Decompiler Parameter ID** alone. It will benefit from your annotations to propagate types more precisely in caller and callee functions.

---

## Impact of the optimization level on analysis

The behavior of automatic analysis varies notably depending on the optimization level with which the binary was compiled. Understanding these differences will save you frustration.

### `-O0` binary (no optimization)

This is the most favorable case for analysis. The code generated by GCC faithfully follows the structure of the source code: each local variable has its place on the stack, each function is present as a distinct entity, branches clearly correspond to the `if`/`else`/`for`/`while` structures of the original code.

Ghidra's automatic analysis produces a very readable result:

- functions are correctly delimited;  
- local variables are identified with regular stack offsets;  
- the decompiler produces pseudo-code close to the original source;  
- parameters are correctly associated with calling-convention registers.

### `-O2` / `-O3` binary (with optimizations)

Optimization profoundly transforms the code structure (we'll devote all of Chapter 16 to this). The most visible effects on Ghidra analysis are:

- **Inlined functions** — short functions disappear from the binary, their code being integrated directly into the caller. The Symbol Tree contains fewer entries, and the decompiler shows denser but less modular code.  
- **Variables in registers** — the optimizer avoids using the stack when registers suffice. The Stack analyzer has less material, and the decompiler may show "phantom" variables that exist only in a register.  
- **Instruction reordering** — instructions no longer follow the source code order. Conditional jumps are reorganized. The control flow may seem counterintuitive.  
- **Tail call optimization** — a `call` + `ret` is replaced by a simple `jmp`. Ghidra can interpret this as an internal jump rather than a function call, visually merging two distinct functions.

The decompiler produces a functionally correct result but structurally remote from the original source. That's normal and expected.

### Stripped binary (`-s` or post-processing `strip`)

Stripping removes symbol tables (`.symtab`) and debug information (DWARF sections). The impact on Ghidra analysis is significant:

- **Lost function names** — all non-exported functions appear as `FUN_00401234` (`FUN_` prefix followed by the address). Only dynamically imported functions keep their names (because they're necessary to the dynamic linker and remain in `.dynsym`).  
- **Uncertain function boundaries** — without symbols, Ghidra relies on flow analysis and prologue-detection heuristics. In a stripped `-O0` binary, `push rbp ; mov rbp, rsp` prologues are reliable. In a stripped `-O2` binary, functions without a classic prologue (*leaf* functions that don't use the stack) can be missed.  
- **Lost types** — structures, variable names, and function signatures defined in the source code disappear. The decompiler produces pseudo-code with generic types (`undefined8`, `long`, `int`).

It's the **`-O2` + strip** combination that represents the most common case in real conditions (release builds, distributed binaries) and the most demanding for the analyst.

---

## Import summary and expected result

After completing the loading and automatic-analysis phases, the CodeBrowser presents you with:

- an **assembly listing** in which each address is annotated: decoded instructions, function labels, references to strings and data, automatic comments;  
- a **Symbol Tree** populated with detected functions (named if symbols are available, `FUN_XXXXXX` otherwise), imports (`printf`, `malloc`, `strcmp`…), exports, and labels;  
- an operational **decompiler** that displays the C pseudo-code of any selected function;  
- a **control-flow graph** accessible by the `Space` key from the listing, showing basic blocks and edges of each function.

It's on this basis that you'll work in the following sections. The result of automatic analysis is only a **starting point** — it's your annotation, renaming, and type-reconstruction work that will turn an anonymous disassembly into a real understanding of the program.

---


⏭️ [Navigation in the CodeBrowser: Listing, Decompiler, Symbol Tree, Function Graph](/08-ghidra/03-codebrowser-navigation.md)
