🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 9.2 — Radare2 / Cutter — command-line analysis and GUI

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [9.1 — IDA Free — base workflow on GCC binary](/09-ida-radare2-binja/01-ida-free-workflow.md)

---

## Radare2: a framework, not just a disassembler

Radare2 (often abbreviated `r2`) is an open-source project fundamentally different from the tools seen so far. Where IDA and Ghidra are graphical applications centered on a visual navigation interface, Radare2 is first and foremost a **command-line framework**. Its modular architecture covers disassembly, debugging, binary analysis, patching, diffing, emulation, ROP gadget searching, and much more — all controllable from a terminal.

This CLI-first approach often disorients on first contact. The interface is austere, commands are cryptic (often two or three letters), and there is no graph view from the opening. But it's precisely this philosophy that makes the tool powerful: every command produces a composable, filterable, and scriptable text output. An analyst who masters `r2` can chain dozens of complex operations at a speed no graphical interface allows.

Radare2 was born in 2006 as a command-line hex editor. It evolved over the years into a complete ecosystem, entirely free and open source (LGPL v3 license). It's available on Linux, macOS, Windows, and even more exotic platforms like Android or iOS. Its community is active, and the tool evolves quickly — sometimes at the cost of interface changes between versions.

## Radare2's architecture

Understanding `r2`'s internal architecture helps grasp its usage logic. The framework is composed of several specialized libraries and binaries.

### The main components

The framework's core is the `libr` library, divided into modules:

- **r_bin** — parsing of binary formats (ELF, PE, Mach-O, DEX, etc.). It's the module that reads headers, sections, symbols, imports, relocations. It plays the same role as `readelf` and `objdump -h` combined, but programmatically.  
- **r_asm** — disassembly and assembly. Supports an impressive number of architectures: x86, ARM (32 and 64), MIPS, PowerPC, SPARC, RISC-V, 6502, Z80, and dozens of others. Each architecture is a plugin, which makes the system extensible.  
- **r_anal** — static code analysis. It's the engine that identifies functions, builds flow graphs, resolves cross-references, and computes local variables. Equivalent to IDA's auto-analysis engine.  
- **r_core** — the interactive shell that binds all modules together. When you type a command in `r2`, it's `r_core` that interprets it and dispatches to the appropriate module.  
- **r_debug** — the integrated debugger. It supports `ptrace` under Linux, native process debugging, and can connect to `gdbserver` in remote mode.  
- **r_io** — the abstract input/output layer. It allows working on files, running processes, memory dumps, network connections, or even remote resources via protocols like `gdb://` or `http://`.

### Companion binaries

Radare2 installs with a suite of command-line tools, each standalone:

| Binary | Role |  
|---|---|  
| `r2` / `radare2` | Main interactive shell — it's the tool you'll use 90% of the time |  
| `rabin2` | Binary inspection (headers, symbols, imports, strings, sections) — lightweight equivalent of `readelf` + `nm` + `strings` |  
| `rasm2` | Command-line assembler / disassembler — converts between mnemonics and bytes |  
| `rahash2` | Hash computation (MD5, SHA1, SHA256, CRC32…) on files or byte ranges |  
| `radiff2` | Binary diffing — comparison between two files or two functions (covered in chapter 10.4) |  
| `rafind2` | Pattern search in a file (strings, byte sequences, regular expressions) |  
| `ragg2` | Shellcode and small-binary generator |  
| `rarun2` | Program launcher with fine control over the environment (stdin, environment variables, redirections) |  
| `r2pm` | Package manager to install plugins, scripts, and `r2` extensions |

These tools are usable independently, without launching the `r2` shell. For example, `rabin2 -I keygenme_O2_strip` displays the binary's general information (format, architecture, endianness, protections) in a single command, comparable to `file` + `checksec`.

## Installing Radare2

### From source (recommended)

The recommended method is source compilation, because the versions in distribution package managers are often several months behind, and `r2` evolves quickly.

```bash
git clone https://github.com/radareorg/radare2.git  
cd radare2  
sys/install.sh  
```

The `sys/install.sh` script compiles and installs `r2` and all its companion tools. On a modern machine, compilation takes a few minutes. To update:

```bash
cd radare2  
git pull  
sys/install.sh  
```

### From the package manager

If you prefer simplicity at the cost of a potentially old version:

```bash
# Debian / Ubuntu
sudo apt install radare2

# Arch Linux
sudo pacman -S radare2

# macOS (Homebrew)
brew install radare2
```

### Verification

```bash
r2 -v
# Displays the version and build date

rabin2 -I /bin/ls
# Displays information about the /bin/ls binary — if it works, the installation is correct
```

## First contact with the `r2` shell

Let's open our running-thread binary in `r2`:

```bash
r2 keygenme_O2_strip
```

The terminal displays a prompt of the form:

```
[0x00401050]>
```

The address between brackets is the current **seek** — the position in the binary where you are. Here, `0x00401050` is the entry point (`_start`). Any command you type executes relative to this position, unless you specify another address.

### The seek concept

Seek is `r2`'s central concept. Think of it as a cursor in a text editor: it indicates where you are. Many commands operate on the "current address" — disassemble the function at the seek, display the bytes at the seek, set a breakpoint at the seek. To move the seek:

```
[0x00401050]> s main
[0x00401160]>
```

The command `s` (*seek*) moves the cursor to the address of the `main` symbol (if the binary has symbols) or to a numeric address (`s 0x401160`). The prompt immediately reflects the new position.

### Launching analysis

By default, `r2` does not automatically analyze the binary at loading. It's a deliberate design choice: unlike IDA or Ghidra which launch a full analysis on import, `r2` leaves you in control. This allows opening a 500 MB binary without waiting 10 minutes — you analyze only what you need.

To launch analysis, you use the `a` (*analyze*) family of commands:

```
[0x00401050]> aaa
```

The `aaa` command is shorthand for "deep-analyze everything". It chains several analysis passes: function identification, cross-reference computation, resolution of imported function names, type propagation, and recursive call analysis. It's equivalent to IDA's auto-analysis.

> 💡 You can also launch analysis as soon as you open with the `-A` flag: `r2 -A keygenme_O2_strip`. It's the most common usage.

Section 9.3 will detail analysis commands and all essential `r2` commands.

### The mnemonic logic of commands

`r2` commands follow a hierarchical system that may seem chaotic at first but obeys a coherent logic. Each command is built from a root letter indicating the domain, followed by modifiers:

- `a` — **a**nalyze (static analysis)  
- `p` — **p**rint (display content)  
- `i` — **i**nfo (information about the binary)  
- `s` — **s**eek (movement)  
- `w` — **w**rite (writing / patching)  
- `d` — **d**ebug (debugging)  
- `/` — search  
- `V` — **V**isual mode

The fundamental principle for discovering commands is to add `?` to any letter to get help:

```
[0x00401050]> a?
Usage: a  [abdefFghoprxstc] [...]
| a                  alias for aai - analysis information
| aa[?]              analyze all (fcns + bbs) (aa0 to avoid sub renaming)
| aaa[?]             autoname functions after aa (see afna)
| ...
```

Then `aa?` to refine, `aaa?` for even more detail, and so on. This tree exploration is the natural way to learn `r2`. It's not necessary (or possible) to memorize everything: experienced analysts consult the built-in help constantly.

### Exiting `r2`

```
[0x00401050]> q
```

The `q` (*quit*) command closes the session. If you've modified the binary (patching), `r2` will ask for confirmation.

## `r2`'s visual modes

Although `r2` is fundamentally a CLI tool, it offers several full-screen visual modes in the terminal, which provide an experience closer to a graphical disassembler.

### Basic visual mode (`V`)

The `V` command activates visual mode. The screen splits into panels displaying disassembly, registers, stack, etc. You navigate with the arrow keys, and switch between different views by pressing `p` (cycles between hex, disassembly, debugging, etc.).

In visual mode, the cursor moves instruction by instruction with the up/down arrows. Pressing **Enter** on a `call` or `jmp` follows the reference (as in IDA). Pressing `u` goes back.

| Key | Action in visual mode |  
|---|---|  
| `p` / `P` | Next / previous view (hex, disassembly, debug…) |  
| `Enter` | Follow a call or jump |  
| `u` | Go back |  
| `j` / `k` | Down / up one line |  
| `:` | Open the command prompt (type an `r2` command without leaving visual mode) |  
| `q` | Quit visual mode (return to prompt) |

### Graph mode (`VV`)

The `VV` command (or `V` then `V` from visual mode) displays the **flow graph of the current function** in ASCII art, directly in the terminal. Each basic block is a text rectangle, connected to the next ones by lines and arrows. It's the terminal equivalent of IDA's graph mode.

```
[0x00401160]> VV
```

Navigation in the graph is done with arrows, `tab` to move to the next block, and the same shortcuts as visual mode. The rendering is naturally more spartan than in a graphical interface, but it's functional and available everywhere — including via SSH on a remote server without a graphical environment, which is a considerable advantage.

### Panels (`V!`)

Panel mode (`V!` or `v` depending on versions) offers an even richer interface, with resizable and configurable windows: disassembly, registers, stack, strings, functions, graph… This mode gets close to an IDE and can be configured to display exactly the information you need side by side.

## Cutter: Radare2's graphical interface

### Why Cutter?

`r2`'s command-line power is undeniable, but the learning curve is steep. For analysts who prefer a graphical interface or who are starting with the framework, the Radare2 project offers **Cutter** — a complete graphical interface built on top of the `r2` engine.

Cutter is not a separate tool that reimplements `r2`'s features. It's a Qt/C++ graphical layer that directly calls `r2` commands in the background. That means all of `r2`'s analysis power is available, with graphical navigation on top. You can even open an integrated `r2` console in Cutter to type CLI commands when the graphical interface is not enough — the best of both worlds.

### Installation

Cutter is distributed as an AppImage on Linux, which makes installation trivial:

```bash
# Download the AppImage from the official site or GitHub
# https://cutter.re or https://github.com/rizinorg/cutter/releases
chmod +x Cutter-*.AppImage
./Cutter-*.AppImage
```

On other systems, native packages are available. The `check_env.sh` script from Chapter 4 verifies Cutter's presence.

> ⚠️ **Note on Rizin and Cutter.** The Cutter project was historically based on Radare2, but in 2020, a fork named **Rizin** was created from the `r2` code. Cutter now uses Rizin as its default engine. In practice, differences between Rizin and Radare2 are minor for the usage covered in this chapter — the concepts, command logic, and interface are the same. If you install Cutter from recent official releases, the underlying engine will be Rizin, but the commands you type there remain largely compatible with `r2`. We use `r2` (original Radare2) in this chapter's CLI examples, and Cutter for GUI examples.

### Cutter's interface

At launch, Cutter asks you to select a binary, then offers analysis options similar to those of IDA and Ghidra. After validation, the binary is loaded and analyzed.

The interface consists of arrangeable and dockable widgets around a central view:

**The Disassembly view** occupies the center of the screen. As in IDA, it offers a text mode (linear listing) and a graph mode (interconnected basic blocks). Cutter's graph mode is visually more pleasant than `VV`'s ASCII art in the terminal: blocks are colored rectangles, edges are drawn cleanly, and conditional branches are color-coded (green for "taken", red for "not taken").

**The Functions widget** (left side panel, typically) lists all detected functions, with the ability to filter, sort, and search by name or address. A double-click navigates to the function.

**The Strings widget** displays strings extracted from the binary. Double-click navigates to the string in the data view, and XREFs are accessible via right-click.

**The Decompiler widget** is one of Cutter's strong points. It integrates the **Ghidra** decompiler (via the `r2ghidra` / `rz-ghidra` plugin) directly in the interface. That means you can have a decompiled view of quality comparable to Ghidra's, synchronized with the disassembly, in Cutter's interface. This decompiler is available at no additional cost — it's a significant advantage over IDA Free.

**The Console widget** gives access to the `r2` / Rizin prompt. You can type any `r2` command there and see the result. It's the bridge between the graphical interface and CLI power.

**Other available widgets:**

- **Hex View** — integrated hex editor.  
- **Imports / Exports** — lists of imported and exported symbols.  
- **Sections / Segments** — ELF section mapping.  
- **XREF** — cross-references of the selected element.  
- **Dashboard** — overview with the binary's metadata (format, architecture, entropy, hashes).  
- **Call graph** — visualization of the global call graph.

### Renaming and annotating in Cutter

Cutter offers the same annotation capabilities as other disassemblers:

- **Rename** — right-click on a function or variable name → *Rename*. The new name propagates throughout the analysis.  
- **Comment** — right-click on an instruction → *Add comment*. The comment appears in the disassembly margin.  
- **Modify a type** — right-click on a function → *Edit function* to modify the signature.

These annotations are stored in the Cutter "project" (which is actually a serialized `r2` project). You can save and reopen your analysis later.

### Cutter workflow on `keygenme_O2_strip`

The workflow in Cutter strongly resembles the one described for IDA Free in section 9.1, with interface adjustments:

**1 — Open and analyze.** Select the binary, let Cutter launch analysis (the "aaaa" option in analysis parameters is the equivalent of a deep analysis).

**2 — Inspect the Dashboard.** The Dashboard widget gives an immediate overview: architecture, format, protections (canary, NX, PIE, RELRO), entropy. It's the equivalent of `checksec` + `file` at a glance.

**3 — Explore strings.** Open the Strings widget, look for revealing messages. Double-click to navigate.

**4 — Trace back XREFs.** Right-click on the string → *Show X-Refs* (or key `X`). Navigate to the function that uses this string.

**5 — Switch to graph mode.** Toggle the disassembly view to graph mode to visualize control flow.

**6 — Consult the decompiler.** Open the decompiler widget to see the C pseudo-code of the current function. Compare with the disassembly to verify consistency.

**7 — Annotate.** Rename functions and variables, add comments, save the project.

## Radare2 CLI vs Cutter: which to choose?

Both access the same analysis engine. The choice depends on context.

**Prefer CLI (`r2`) when:**

- You work on a remote server via SSH without a graphical environment — `r2` works in any terminal.  
- You need to script an analysis (with `r2pipe`, covered in section 9.4) or chain commands quickly.  
- You analyze a large number of binaries in batch — `r2`'s non-interactive mode (`r2 -qc 'commands' binary`) allows executing command sequences without interaction.  
- You're comfortable with CLI and you want raw speed: no graphical-rendering latency, no menus to navigate.

**Prefer Cutter when:**

- You're starting with the Radare2 framework and want to explore the interface visually before memorizing commands.  
- You need the integrated Ghidra decompiler synchronized with the disassembly.  
- You're doing a deep analysis of a single target and want to see simultaneously the graph, pseudo-code, strings, and registers.  
- You're preparing screenshots or a presentation of your analysis.

In practice, many analysts use both complementarily: Cutter for visual exploration and decompilation, then the `r2` terminal (or the integrated console in Cutter) as soon as a repetitive task or precise filtering is needed.

## Radare2's strengths in the ecosystem

To conclude this presentation, here are the domains where `r2` particularly stands out compared to the other tools of the chapter:

- **Architecture support** — `r2` supports more architectures than any other free tool. If you work on embedded firmware (ARM Cortex-M, MIPS, AVR, 8051…), it's often the only open-source tool that covers your target.  
- **Lightweight** — `r2` fits in a few megabytes and installs without heavy dependencies. It works on modest machines and in Docker containers.  
- **Composability** — each command produces text output usable in a Unix pipe, exportable in JSON (`~{}` suffixed to the command, or the `j` flag on many commands), or processable in a script. It's the Unix spirit pushed to the extreme.  
- **Integrated patching** — `r2` can write to the binary directly (`r2 -w binary`), which makes it a quick binary-patching tool without external tools.  
- **Emulation** — via the ESIL plugin (*Evaluable Strings Intermediate Language*), `r2` can emulate instructions without executing the binary. This allows tracing register and memory evolution purely statically.  
- **CTF community** — `r2` is very popular in the CTF community, where analysis speed and scripting are decisive advantages. Many write-ups are written with `r2`, and knowing it will let you follow them.

---


⏭️ [`r2`: essential commands (`aaa`, `pdf`, `afl`, `iz`, `iS`, `VV`)](/09-ida-radare2-binja/03-r2-essential-commands.md)
