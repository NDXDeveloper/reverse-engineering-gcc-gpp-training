🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 12.1 — Installation and comparison of the three extensions

> **Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg**  
> **Part III — Dynamic Analysis**

---

## The common mechanism: GDB initialization files

Before installing anything, it's useful to understand how these extensions graft onto GDB. The principle is the same for all three: GDB, at startup, automatically executes the commands present in the `~/.gdbinit` file. This file acts as a configuration script. Extensions add a `source` directive that loads their Python code, which registers new commands, replaces some default behaviors, and installs hooks that execute at each program stop.

```bash
# Typical example of a ~/.gdbinit after installing an extension
source /opt/pwndbg/gdbinit.py
```

This mechanism implies an important constraint: **only one extension can be active at a time**. If the `~/.gdbinit` file sources both GEF and pwndbg, homonymous commands will conflict and behavior will be unpredictable. We'll see at the end of this section how to cleanly switch between the three.

---

## Installing PEDA

PEDA is the simplest to install. The repository is cloned, then a line is added to GDB's initialization file.

```bash
git clone https://github.com/longld/peda.git ~/peda  
echo "source ~/peda/peda.py" >> ~/.gdbinit  
```

No external Python dependency is required: PEDA only uses Python's standard library and the built-in GDB API. It's actually one of its historical strengths — it works on minimalist systems without pip or virtualenv.

To verify the installation, simply launch GDB:

```bash
gdb -q
```

The prompt should display `gdb-peda$` instead of the usual `(gdb)`. If not, verify that the path in `~/.gdbinit` correctly points to the `peda.py` file and that the Python version embedded in GDB is compatible (Python 3 in recent GDB versions).

PEDA no longer receives frequent updates. The last significant commit on the main repository dates back several years. Community forks exist (notably `peda-arm` for the ARM architecture), but for use on x86-64 with modern features, GEF and pwndbg are now preferable.

---

## Installing GEF

GEF distinguishes itself by its distribution as a single Python file. The canonical installation goes through a script that downloads this file and configures `~/.gdbinit`:

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

For those who prefer a manual installation (which is always a good habit in security — inspect a script before executing it):

```bash
curl -fsSL https://gef.blah.cat/py -o ~/.gdbinit-gef.py  
echo "source ~/.gdbinit-gef.py" >> ~/.gdbinit  
```

GEF has no mandatory dependency beyond GDB compiled with Python 3 support. However, some optional commands gain functionality with additional packages. GEF provides a built-in command to check and install these extras:

```bash
# From the GEF prompt in GDB:
gef➤ pip install ropper keystone-engine
```

Or directly from the shell, with the system package manager for external tools:

```bash
# Optional dependencies for advanced commands
sudo apt install ropper  
pip install capstone unicorn keystone-engine  
```

These packages respectively enable ROP gadget searching (ropper), advanced disassembly (capstone), instruction emulation (unicorn), and inline assembly (keystone). Without them, GEF works perfectly for daily debugging — these extras are only needed for specific uses like exploitation.

At GDB launch, the prompt displays `gef➤` and a banner indicating the GEF version and the number of loaded commands.

---

## Installing pwndbg

pwndbg has the heaviest installation of the three, but the process remains automated:

```bash
git clone https://github.com/pwndbg/pwndbg.git ~/pwndbg  
cd ~/pwndbg  
./setup.sh
```

The `setup.sh` script creates a Python virtual environment, installs dependencies (including `capstone`, `unicorn`, `pycparser`, `psutil`, and others), then adds the appropriate `source` line in `~/.gdbinit`. On Debian/Ubuntu-based distributions, it also installs necessary system packages via `apt`.

Installation takes noticeably more time than the other two extensions, and the disk footprint is larger due to the virtual environment and compiled libraries. It's the price to pay for pwndbg's feature richness, notably its heap-analysis capabilities that rely on fine parsing of glibc's internal structures.

After installation, launching GDB displays the `pwndbg>` prompt with a colored banner.

> 💡 **Note for Arch Linux, Fedora, or other distribution users**: the `setup.sh` script detects the distribution and adapts package-installation commands. In case of problems, consult the `README.md` of the pwndbg repo which documents special cases.

---

## Switching between extensions

Since only one extension can be loaded at a time via `~/.gdbinit`, a mechanism to switch is needed. The cleanest approach consists of creating a dedicated initialization file per extension, then using shell aliases.

Start by creating three separate files:

```bash
# ~/.gdbinit-peda
source ~/peda/peda.py

# ~/.gdbinit-gef
source ~/.gdbinit-gef.py

# ~/.gdbinit-pwndbg
source ~/pwndbg/gdbinit.py
```

Then define aliases in `~/.bashrc` or `~/.zshrc`:

```bash
alias gdb-peda='gdb -ix ~/.gdbinit-peda'  
alias gdb-gef='gdb -ix ~/.gdbinit-gef'  
alias gdb-pwndbg='gdb -ix ~/.gdbinit-pwndbg'  
```

The `-ix` flag tells GDB to use the specified file as the initialization file *instead of* the default `~/.gdbinit`. After a `source ~/.bashrc`, all three commands are available:

```bash
gdb-gef -q ./keygenme_O0       # Launch GDB with GEF  
gdb-pwndbg -q ./keygenme_O0    # Launch GDB with pwndbg  
gdb-peda -q ./keygenme_O0      # Launch GDB with PEDA  
```

The main `~/.gdbinit` file can then contain the extension you use most often by default (for example GEF for its lightness), while leaving the ability to switch on demand via aliases.

> 💡 **Tip**: if the training's `check_env.sh` script checks for a GDB extension's presence, it will test the existence of these initialization files. Ensure all three are in place after this step.

---

## Comparison of the three extensions

### Philosophy and architecture

PEDA paved the way with a simple principle: display a rich context at every stop. Its code is monolithic — a single Python file of about 4,000 lines that registers all commands. This architecture makes the code easy to read for understanding how to extend GDB, but difficult to maintain and evolve.

GEF took this single-file philosophy further: the code is more modular internally (each command is a distinct Python class), but everything is distributed in a single file. The guiding idea is "zero mandatory dependencies" — you can `scp` the file to a remote machine and immediately have an enhanced GDB. GEF also emphasizes multi-architecture support: ARM, AArch64, MIPS, SPARC, PowerPC, and RISC-V are natively supported, making it valuable for firmware or embedded reverse engineering.

pwndbg adopts a split architecture with many Python modules organized in packages. This structure encourages community contribution and the addition of complex features, like the glibc heap parsing that alone requires several hundred lines of structured code. The trade-off is the impossibility of working without its dependencies — you can't copy pwndbg to a remote server as easily as GEF.

### Context display

All three extensions display a similar context at each stop, but with differences in presentation and content.

PEDA displays three panels: registers, disassembled code, and stack. Coloring is functional but basic. Pointers are dereferenced one level — you see the pointed value, but not deep dereference chains.

GEF structures its context in configurable sections: `registers`, `stack`, `code`, `threads`, `trace`, and optionally `extra` (which can display C source if DWARF symbols are present). Each section can be enabled, disabled, or reordered via the `gef config` command. Pointer dereferencing is recursive, and detected strings are displayed in clear text next to addresses.

pwndbg offers the richest display by default. Its context includes registers with highlighting of changes since the last stop (the previous value is shown in gray, the new one in bright color), disassembly with advanced syntax coloring, the stack with recursive dereferencing (built-in `telescope` command), and a backtrace panel. pwndbg also detects and displays libc function arguments at a `call`: for example, at a `call malloc`, it shows the requested size extracted from the `rdi` register.

### Notable specific commands

Some commands exist only in one extension or are significantly more developed there.

pwndbg excels in heap analysis with `vis_heap_chunks` (visual representation of malloc chunks), `bins` (state of glibc bins: fastbins, tcache, unsorted, small, large), `top_chunk`, `arena`, and `mp_`. These commands are absent from PEDA and present in a more limited form in GEF (via the `heap` command and its subcommands).

GEF offers `pattern create` / `pattern search` for De Bruijn pattern generation and searching (useful for computing offsets during buffer overflows), `xinfo` to get all information about an address (section, permissions, mapping), and `highlight` to dynamically colorize patterns in GDB output. GEF also has a `gef config` command system that allows fine-tuning every aspect of the display without modifying source code.

PEDA provides `checksec` (checking protections of the binary being debugged), `procinfo` (process information), and `elfheader` / `elfsymbol` to inspect ELF structures from the debugger. These commands also exist in GEF and pwndbg, but PEDA popularized them.

### Summary table

| Criterion | PEDA | GEF | pwndbg |  
|---|---|---|---|  
| **Single file** | Yes | Yes | No (multi-module) |  
| **Mandatory dependencies** | None | None | Several (capstone, unicorn…) |  
| **Multi-architecture** | x86, x86-64 | x86, x86-64, ARM, AArch64, MIPS, SPARC, PPC, RISC-V | x86, x86-64, ARM, AArch64, MIPS |  
| **Glibc heap analysis** | Basic | Intermediate | Advanced (vis_heap_chunks, bins, tcache…) |  
| **ROP gadget searching** | `ropgadget` | Via integrated ropper | Built-in `rop` |  
| **Recursive dereferencing** | 1 level | Recursive | Recursive (telescope) |  
| **Register modification coloring** | No | Yes | Yes (with previous value) |  
| **Fine configuration** | Limited | `gef config` (very granular) | `config` / `themefile` |  
| **Remote deployment ease** | Excellent | Excellent | Medium |  
| **Active maintenance (2024+)** | Low | Active | Very active |  
| **Community / contributors** | Small | Medium | Large |

### Which tool to choose?

The choice depends on the usage context.

For **daily debugging on a local machine** with a focus on reverse engineering x86-64 ELF binaries, pwndbg offers the most complete experience. Its heap commands and active community make it the reference extension for anyone working on exploitation or malware analysis.

For **remote debugging** via `gdbserver` on a target accessed by SSH, or for an **embedded / multi-architecture environment**, GEF is the pragmatic choice. A single `scp` of the Python file suffices, and native support for varied architectures avoids juggling additional plugins.

For **learning how extensions work internally**, PEDA's code remains the most readable and pedagogical. Its simple architecture makes it a good starting point for anyone wanting to write their own GDB commands in Python.

In practice, many reverse engineers install all three and switch via the aliases described above, depending on the task at hand. That's the approach we'll adopt in this training: GEF as the default extension for its versatility, pwndbg when heap analysis or ROP gadget searching requires it.

---

## Verifying the installation

To confirm that all three extensions are correctly installed and that the switching mechanism works, run the following commands:

```bash
# Verify GEF
gdb-gef -q -batch -ex "gef help" 2>/dev/null | head -5

# Verify pwndbg
gdb-pwndbg -q -batch -ex "pwndbg" 2>/dev/null | head -5

# Verify PEDA
gdb-peda -q -batch -ex "peda help" 2>/dev/null | head -5
```

Each command should display the list of commands specific to the corresponding extension without Python errors. If a `ModuleNotFoundError` appears for pwndbg, rerun `~/pwndbg/setup.sh` to reinstall missing dependencies. If GDB displays `No module named 'gef'`, verify that the path in `~/.gdbinit-gef` correctly points to the downloaded file.

The `check_env.sh` script provided with the training includes these verifications. After this section, run:

```bash
./check_env.sh --chapter 12
```

All three extensions should appear in green.

---


⏭️ [Real-time stack and register visualization](/12-gdb-extensions/02-stack-registers-visualization.md)
