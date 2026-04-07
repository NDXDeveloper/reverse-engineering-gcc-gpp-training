🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 9.1 — IDA Free — base workflow on GCC binary

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [README — Chapter introduction](/09-ida-radare2-binja/README.md)

---

## IDA in a few words

IDA (Interactive DisAssembler) is the commercial disassembler developed by Hex-Rays since the early 1990s. For over two decades, it has been *the* de facto standard in professional reverse engineering — malware analysis, vulnerability research, forensics, firmware auditing. Nearly all academic and industrial RE literature, from CTF write-ups to threat-intelligence reports, uses IDA as a reference. Understanding its interface and terminology is therefore indispensable, if only to read other people's work.

IDA exists in several variants. IDA Pro is the full version, sold for several thousand euros, which includes the Hex-Rays decompiler for many architectures. IDA Home is a personal license at reduced price. **IDA Free** is the free version we'll use here. It's limited but remains a powerful analysis tool for x86-64 binaries.

## IDA Free's capabilities and limitations

Before starting, it's important to know exactly what the free version does and does not allow, to avoid mid-analysis frustration.

**What IDA Free offers:**

IDA's automatic analysis engine is available in the free version. It's the heart of the tool: its ability to identify functions, resolve cross-references, recognize function prologues and epilogues, and distinguish code from data is historically one of the best in the industry. On a stripped binary produced by GCC, IDA often identifies more functions correctly than `objdump` in linear-disassembly mode. IDA Free supports x86-64 ELF binaries, which matches our context exactly. The full graphical interface is present: disassembly view (text and graph), hex view, cross-references, function and variable renaming, comment adding, and code navigation.

**What IDA Free does not offer:**

The most significant limitation concerns the decompiler. IDA Free includes a cloud decompiler for x86-64 since recent versions (8.x+), but it requires an internet connection and has usage quotas. IDAPython scripting is available but may be restricted depending on the version. Multi-architecture support is absent: only x86/x64 is supported, whereas IDA Pro covers ARM, MIPS, PowerPC, and dozens of other processors. Finally, the license prohibits commercial use.

> 💡 For the context of this training (x86-64 ELF, educational use), IDA Free is perfectly suited. The absent features are covered by Ghidra (Chapter 8) which you already have in hand.

## Installation

IDA Free is downloaded from the official Hex-Rays site at `hex-rays.com/ida-free`. Installation requires creating an account and accepting the non-commercial-use license.

On Linux, the program is distributed as a `.run` installer or an archive. After extraction, the main binary is `ida64` (to analyze 64-bit binaries). On recent distributions, some Qt graphical dependencies may be needed — the `check_env.sh` script from Chapter 4 verifies their presence.

```bash
# Launch IDA Free (64 bits) from the installation directory
./ida64
```

On first launch, IDA displays a welcome screen offering either to create a new analysis ("New") or open an existing database ("Previous"). IDA databases have the `.i64` extension (for 64-bit binaries) and preserve all your analysis work: renamings, comments, defined types, etc.

## Importing and initial analysis of an ELF binary

### Loading the binary

Let's open our running-thread binary `keygenme_O2_strip`:

1. Click on **New** (or *File → Open*).  
2. Navigate to the `binaries/ch09-keygenme/keygenme_O2_strip` file.  
3. IDA displays a load dialog ("Load a new file").

This dialog is the first important decision point. IDA automatically detects the file format — here `ELF64 for x86-64` — and proposes the matching processor. In the vast majority of cases, the default values are correct and you only need to confirm.

A few options deserve your attention, however:

- **Loading segment and loading offset** — leave the default values unless you know the binary must be loaded at a specific address (firmware or memory dump case).  
- **Manual load** — checking this box allows fine control over which segments are loaded. It's useful for atypical or corrupted binaries, but unnecessary for a standard ELF.  
- **Analysis options** — the "Kernel options" or "Analysis options" button gives access to the analysis-engine parameters. The default configuration is suitable to start.

Confirm with **OK**. IDA loads the binary and immediately launches its automatic analysis.

### Auto-analysis: what does IDA do in the background?

From loading, the status bar at the bottom of the window displays a progress bar and the "Autoanalysis" message. It's IDA's engine scanning the binary to:

- **Identify functions** — IDA uses recursive-descent analysis, starting from known entry points (the `_start` symbol, entries of the `.init_array` table, etc.) and following branches. This is fundamentally different from `objdump`'s linear sweep, and that's what allows IDA to distinguish code from data even in a stripped binary.  
- **Recognize library signatures** — thanks to its **FLIRT** (*Fast Library Identification and Recognition Technology*) technology, IDA compares byte sequences at the start of each detected function with a base of known signatures. That's how it can automatically name libc or other standard-library functions, even in a statically linked and stripped binary.  
- **Propagate types** — when IDA recognizes a call to `printf`, it knows the first argument is a `const char *` format and propagates this information in its analysis.  
- **Resolve cross-references** — every referenced address (by a `call`, `jmp`, `lea`, memory access…) is recorded. This XREF network is one of IDA's most powerful tools for navigating a binary.

> ⏳ Wait for the auto-analysis to finish (the "idle" mention appears in the status bar) before starting your exploration. Working during analysis can give incomplete results.

## Discovering the main interface

Once analysis is finished, IDA displays its interface organized around several views. Let's take the time to identify them, because they constitute your permanent workspace.

### The IDA View (disassembly)

It's the central view. It displays the disassembled code of the current function. IDA offers two visualization modes, accessible via the space bar:

- **Text mode** — the classic linear listing, similar to what `objdump` produces but enriched by IDA's annotations (recognized function names, automatic comments, propagated types). Each line displays the virtual address, raw bytes (optional), mnemonic, and operands.

- **Graph mode** — IDA splits the function into *basic blocks* connected by colored arrows. Green arrows indicate a taken conditional branch (true condition), red ones a non-taken branch (false condition), and blue ones an unconditional jump. This view is extremely useful for understanding a function's control logic: loops form visible cycles, `if/else`s appear as decision diamonds, and `switch/case`s appear as branch stars.

To switch between the two modes, press **Space** in the IDA View.

### The Functions window

Accessible via *View → Open Subviews → Functions* (or the shortcut depending on the version), this window lists all functions identified by auto-analysis. For each function, IDA displays its start address, size, and name — which will be either a recognized symbol (like `_start` or `__libc_csu_init`) or an auto-generated name in the form `sub_XXXXXXXX` for functions without symbols.

In the case of `keygenme_O2_strip`, most functions bear `sub_*` names. That's normal: the binary was stripped. The quantity of identified functions and the relevance of their bounds (start and end addresses) are a good indicator of analysis quality. Compare this number with the one obtained under Ghidra in Chapter 8 — results can diverge, particularly for small or non-aligned functions.

### The Strings window

*View → Open Subviews → Strings* (or shortcut **Shift+F12**) opens a window listing all character strings detected in the binary, with their address, length, and encoding. It's the enhanced equivalent of the `strings` command: IDA does not just look for ASCII sequences, it also identifies strings referenced by code and those in UTF-8/UTF-16.

Double-clicking a string takes you to its location in the data segment (`.rodata` typically). From there, you can use cross-references (key **X**) to know which functions use this string — a classic entry point in analyzing an unknown binary.

### The Hex View

The hex view displays the binary's raw content. It's synchronized with the disassembly view: navigating in one moves the cursor in the other. This view is useful for verifying the real bytes of an instruction, examining binary data, or spotting patterns the disassembler did not interpret.

### Other useful views

- **Imports** (*View → Open Subviews → Imports*) — lists functions imported from dynamic libraries (via the PLT/GOT). On a dynamically linked binary, it's a gold mine: `strcmp`, `printf`, `malloc`, `open`, `send`… each import tells part of what the program does.  
- **Exports** — lists exported symbols. On a classic executable, there are few (often just `_start`). On a `.so` library, it's the public API.  
- **Segments** — displays the binary's segments (`.text`, `.data`, `.rodata`, `.bss`, `.plt`, `.got`, etc.) with their attributes (read, write, execute). Corresponds to what `readelf -S` displays.

## Navigating the code

Efficient navigation in IDA relies on a set of keyboard shortcuts and mechanisms you must know to be productive.

### Go to an address or symbol

The shortcut **G** opens a "Jump to address" dialog. You can enter a virtual address (for example `0x401230`), a function name (`sub_401230`, `main`, `_start`), or an expression. It's the most direct way to navigate.

### Follow a call or reference

Placing the cursor on an operand (a target address of a `call`, `jmp`, or `lea`) and pressing **Enter** takes you to the target. It's the equivalent of "clicking a hyperlink". To go back, use **Escape** — IDA maintains a navigation history.

### Cross-references (XREF)

It's one of IDA's most powerful mechanisms. Placing the cursor on an address, function name, or variable, then pressing **X** opens the cross-references window. It lists all places in the binary that reference this element: all `call`s to this function, all accesses to this variable, all jumps to this address.

XREFs break down into several types:

- `p` — *code reference (procedure call)*: a `call` to this address.  
- `j` — *code reference (jump)*: a `jmp` (conditional or not) to this address.  
- `r` — *data reference (read)*: an instruction that reads this memory address.  
- `w` — *data reference (write)*: an instruction that writes to this address.  
- `o` — *data reference (offset)*: an instruction that takes the address itself as a value (typically a `lea`).

In analyzing an unknown binary, XREFs are your compass. For example, to find the `keygenme`'s verification routine, a classic approach is to spot the strings `"Access granted"` or `"Wrong key"` in the Strings window, then trace back the XREFs to identify the function that uses them.

## Annotating the binary: renaming and comments

Binary analysis is an incremental process. As you understand the role of each function or variable, you must capture that understanding in the IDA database. IDA preserves all your annotations in the `.i64` file, which lets you resume your work where you left off.

### Rename a function or variable

Selecting a name (for example `sub_40117A`) and pressing **N** opens the rename dialog. Replace `sub_40117A` with a descriptive name like `check_serial` or `validate_key`. This new name will be immediately propagated everywhere in the database: every `call sub_40117A` will become `call check_serial`, every XREF will be updated.

Renaming is probably the most frequent and useful action during an analysis. A stripped binary full of `sub_*` is unreadable. After an hour of methodical renaming, the same binary becomes understandable.

### Add comments

IDA offers two types of comments:

- **Regular comment** (key **:**) — displayed to the right of the instruction, on the same line. Used to annotate a specific instruction ("compare the serial with the expected value", "XOR decryption loop").  
- **Repeatable comment** (key **;**) — similar to the regular comment, but it is automatically displayed wherever the commented address is referenced. If you put a repeatable comment on a global variable, this comment will appear in each instruction that accesses this variable. Extremely useful for constants and global variables.

### Define a type

The shortcut **Y** on a function name lets you modify its signature (prototype). If you've identified that a function `sub_401230` takes a `char *` as first argument and returns an `int`, you can specify `int sub_401230(char *input)`. IDA will then propagate these types in the analysis: the `rdi` registers at the call point will be annotated as `input`, and the return `eax` as an `int`.

## Peculiarities of GCC binaries in IDA

Binaries compiled with GCC present characteristics that IDA handles well overall, but which you must know not to be thrown off.

### Initialization and termination functions

An ELF binary compiled with GCC does not start directly at `main()`. The real entry point is `_start`, which calls `__libc_start_main` with `main` as argument. IDA generally identifies this sequence and correctly names `main`, even in a stripped binary, by recognizing the `__libc_start_main` call pattern. If it doesn't, look for `__libc_start_main` in the imports: its first argument (passed in `rdi` per the System V convention) is `main`'s address.

You'll also find functions like `__libc_csu_init`, `__libc_csu_fini`, `_init`, `_fini`, `frame_dummy`, `register_tm_clones`, and `deregister_tm_clones`. These are infrastructure functions inserted by GCC and glibc. They have nothing to do with your program's logic. It's good to recognize them to ignore them and focus your attention on the application code.

### PLT calls

On a dynamically linked binary, calls to library functions go through the PLT (*Procedure Linkage Table*), as detailed in chapter 2.9. IDA automatically resolves these indirections: a `call` to a PLT stub is displayed with the name of the imported function (for example `call _strcmp` or `call _printf`). It's a considerable advantage over `objdump` which shows the raw stub address.

### Optimization levels

GCC's optimization level has a direct impact on readability in IDA:

- **`-O0`** — the code is near-literal compared to the source. Local variables are on the stack, each operation is a distinct instruction, and functions are rarely inlined. IDA produces a very readable result.  
- **`-O2` / `-O3`** — variables live in registers, short functions are inlined (they disappear from the function list), loops are unrolled, and control flow can be reorganized. IDA's analysis remains correct, but the code is noticeably denser and harder for a human to read.

That's why we work on `keygenme_O2_strip`: it represents the realistic case of a "wild" binary, and that's where analysis-tool quality makes a difference.

### FLIRT and library recognition

IDA's FLIRT technology compares the first bytes of each function with pre-computed signatures of known libraries. On a statically linked binary (compiled with `gcc -static`), FLIRT can recognize and automatically name hundreds of glibc functions — `strlen`, `memcpy`, `malloc`, etc. — that would otherwise be anonymous `sub_*`.

IDA Free ships with a set of FLIRT signatures, but it is more restricted than IDA Pro's. If you frequently work on statically linked binaries, note that Ghidra offers an equivalent feature via its Function ID databases (FID), covered in chapter 20.5.

## Typical workflow on `keygenme_O2_strip`

Here is the typical sequence of actions when opening a new binary in IDA Free, applied to our running thread.

**1 — Load and wait for auto-analysis.** Open `keygenme_O2_strip`, accept the default options, and wait for the status bar to display "idle".

**2 — Explore strings.** Open the Strings window (**Shift+F12**) and look for interesting strings. In a crackme, you look for success or failure messages. Double-clicking a promising string takes you to its location in `.rodata`.

**3 — Trace back XREFs.** From the identified string, press **X** to see which function(s) reference it. Navigate to that function.

**4 — Switch to graph mode.** Press **Space** to toggle to graph view. Identify the control structure: where is the branch that decides between the "success" and "failure" paths?

**5 — Rename and annotate.** Rename the function (`check_serial`, `validate_input`…), rename local variables if possible, add comments on key instructions.

**6 — Explore the neighborhood.** Use XREFs to go up to caller functions (`main`?), down to called sub-functions. Rename as you go.

**7 — Save.** IDA automatically saves in the `.i64`, but an explicit *File → Save* after a significant work session is a good habit.

This workflow is fundamentally the same as the one presented with Ghidra in Chapter 8. Reverse-engineering methodology is independent of the tool — only the keyboard shortcuts and specific capabilities change.

## Essential keyboard shortcuts

| Action | Shortcut |  
|---|---|  
| Toggle text / graph | `Space` |  
| Go to address | `G` |  
| Rename | `N` |  
| Cross-references | `X` |  
| Regular comment | `:` |  
| Repeatable comment | `;` |  
| Modify type/prototype | `Y` |  
| Strings window | `Shift+F12` |  
| Back (navigation) | `Escape` |  
| Convert to code | `C` |  
| Convert to data | `D` |  
| Undo last action | `Ctrl+Z` |

## When IDA Free surpasses Ghidra (and vice versa)

It's not about declaring an absolute winner, but knowing the situations where one shines more than the other.

**IDA Free has the advantage when:**

- Initial function recognition is critical — on some stripped or obfuscated binaries, IDA identifies function bounds more correctly than Ghidra.  
- You need fast and fluid navigation — IDA's interface is optimized for speed, shortcuts are consistent, and responsiveness on large binaries is generally better.  
- The binary is statically linked and FLIRT can identify library functions.  
- You read a write-up or report written with IDA and you need to reproduce the analysis in the same environment.

**Ghidra has the advantage when:**

- You need a full decompiler without restriction — Ghidra's decompiler is included, free, without quota, and works offline.  
- You work on non-x86 architectures (ARM, MIPS…) — IDA Free does not support them.  
- You need advanced scripting — Ghidra's Java/Python API is rich and well documented.  
- The license must allow commercial or professional use — IDA Free prohibits it, Ghidra is Apache 2.0.  
- You work in a team — Ghidra Server enables collaborative analysis, a feature absent from IDA Free.

Section 9.6 will provide a detailed comparison including Radare2 and Binary Ninja.

---


⏭️ [Radare2 / Cutter — command-line analysis and GUI](/09-ida-radare2-binja/02-radare2-cutter.md)
