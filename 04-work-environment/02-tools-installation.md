🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.2 — Installation and configuration of essential tools (versioned list)

> 🎯 **Goal of this section**: install and configure all the tools required for the training, in an ordered and verifiable way. By the end of this section, your VM will contain everything needed to tackle any chapter.

---

## Installation strategy

We proceed in **five waves**, from the foundations to specialized tools. This order is not arbitrary: each wave can depend on the previous one. For example, angr requires Python 3 and pip (wave 1), and GEF requires GDB (wave 2).

| Wave | Category | Examples |  
|---|---|---|  
| 1 | System foundations and languages | GCC, G++, Make, Python 3, pip, Java, Git |  
| 2 | Command-line inspection and debugging tools | binutils, GDB, strace, ltrace, Valgrind, checksec, YARA |  
| 3 | Disassemblers and graphical editors | Ghidra, Radare2, Cutter, ImHex, IDA Free |  
| 4 | Instrumentation, fuzzing, and symbolic-execution frameworks | Frida, AFL++, angr, Z3, pwntools |  
| 5 | Complementary and optional tools | BinDiff, Wireshark, UPX, binwalk, .NET/Rust/Go tools |

> 💡 **Snapshot before starting.** If you have already created your VM (section 4.3), take a snapshot named `pre-install` before launching the installs. If something goes wrong, you can return to a clean state without reinstalling the whole system.

---

## Prerequisites: system update

Before any installation, update the repositories and existing packages:

```bash
[vm] sudo apt update && sudo apt upgrade -y
```

Then install the base dependencies common to many tools:

```bash
[vm] sudo apt install -y \
    build-essential \
    curl \
    wget \
    git \
    unzip \
    pkg-config \
    libssl-dev \
    libffi-dev \
    zlib1g-dev \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg
```

---

## Wave 1 — System foundations and languages

### GCC / G++ / Make / Binutils

The `build-essential` package installed above already provides GCC, G++, Make, and the GNU binutils (including `as`, `ld`, `objdump`, `readelf`, `nm`, `strings`, `strip`, `objcopy`, `c++filt`). Verify:

```bash
[vm] gcc --version        # expected: 13.x on Ubuntu 24.04
[vm] g++ --version
[vm] make --version
[vm] objdump --version
[vm] readelf --version
```

> 📌 **Chapter concerned**: 2 (GNU compilation chain), then throughout the training for compiling the training binaries.

### Python 3 and pip

Python is the ubiquitous scripting language in RE. We use it for angr, pwntools, Frida, pyelftools, lief, r2pipe, and custom scripts.

```bash
[vm] sudo apt install -y python3 python3-pip python3-venv python3-dev
```

Create a **dedicated virtual environment** for the training. This isolates Python packages from those of the system and avoids version conflicts:

```bash
[vm] python3 -m venv ~/re-venv
[vm] echo 'source ~/re-venv/bin/activate' >> ~/.bashrc
[vm] source ~/re-venv/bin/activate
```

From now on, all `pip install` commands will run inside this virtual environment.

```bash
[vm] python3 --version    # expected: 3.12.x on Ubuntu 24.04
[vm] pip --version
```

> 📌 **Chapters concerned**: 11 (GDB Python scripts), 13 (Frida), 15 (fuzzing), 18 (angr/Z3), 21–28 (practical cases), 35 (automation).

### Java (JDK) — required by Ghidra

Ghidra requires JDK 17 or higher. OpenJDK works:

```bash
[vm] sudo apt install -y openjdk-21-jdk
[vm] java -version        # expected: openjdk 21.x
```

> 📌 **Chapters concerned**: 8 (Ghidra), 9 (disassembler comparison), 10 (BinDiff/Diaphora), 20 (decompilation).

### Git

Already installed via the base dependencies. Verify:

```bash
[vm] git --version
```

Git will be used to clone the training repository and, when applicable, to fetch the sources of some tools.

---

## Wave 2 — CLI inspection and debugging tools

### GDB (GNU Debugger)

```bash
[vm] sudo apt install -y gdb
[vm] gdb --version        # expected: 15.x on Ubuntu 24.04
```

GDB will be enhanced with extensions (GEF, pwndbg) a bit further down. For now, we install the base version.

> 📌 **Chapters concerned**: 11 (fundamental GDB), 12 (extensions), 21–29 (practical cases).

### strace / ltrace

```bash
[vm] sudo apt install -y strace ltrace
[vm] strace --version
[vm] ltrace --version
```

> 📌 **Chapters concerned**: 5 (basic inspection tools), 23 (network binary), 26–28 (malware analysis).

### Valgrind

```bash
[vm] sudo apt install -y valgrind kcachegrind
[vm] valgrind --version   # expected: 3.22.x+
```

`kcachegrind` is the graphical frontend for visualizing Callgrind profiles.

> 📌 **Chapters concerned**: 14 (Valgrind and sanitizers), 24 (extracting crypto keys from memory).

### checksec

`checksec` is a script that inventories the security protections of a binary (PIE, NX, canary, RELRO, ASLR).

```bash
[vm] sudo apt install -y checksec
[vm] checksec --version
```

If the package is not available or too old, install the upstream version:

```bash
[vm] pip install checksec.py
```

> 📌 **Chapters concerned**: 5 (quick triage), 19 (anti-reversing), 21 (keygenme), 27–29 (malware).

### YARA

YARA lets you write pattern-matching rules on binary files.

```bash
[vm] sudo apt install -y yara
[vm] yara --version       # expected: 4.3.x+
```

For use from Python:

```bash
[vm] pip install yara-python
```

> 📌 **Chapters concerned**: 6 (ImHex + YARA), 27 (ransomware), 35 (automation).

### Complementary system utilities

These tools are often already present but it is worth making sure:

```bash
[vm] sudo apt install -y \
    file \
    xxd \
    bsdextrautils \
    binwalk \
    tree \
    tmux \
    nasm
```

- `file`: file type identification (Chapter 5).  
- `xxd` / `hexdump`: quick hexadecimal dumps (Chapter 5). `hexdump` is provided by the `bsdextrautils` package.  
- `binwalk`: firmware analysis and extraction of embedded formats (Chapter 25).  
- `nasm`: x86-64 assembler, useful for the Chapter 3 experiments.  
- `tmux`: terminal multiplexer — essential for long GDB sessions.

---

## Wave 3 — Disassemblers and graphical editors

### Ghidra

Ghidra is not in the apt repositories. Download it from the NSA's official GitHub repo:

```bash
[vm] GHIDRA_VERSION="11.3"
[vm] wget "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20250108.zip" \
     -O /tmp/ghidra.zip
[vm] sudo unzip /tmp/ghidra.zip -d /opt/
[vm] sudo ln -sf /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra
[vm] rm /tmp/ghidra.zip
```

> ⚠️ **Check the version number and build date** on the [GitHub releases page](https://github.com/NationalSecurityAgency/ghidra/releases) before copying this command. URLs change with every release.

Create an alias or a launcher:

```bash
[vm] echo 'alias ghidra="/opt/ghidra/ghidraRun"' >> ~/.bashrc
[vm] source ~/.bashrc
[vm] ghidra    # should launch the graphical interface
```

> 📌 **Chapters concerned**: 8 (getting started), 9 (comparison), 10 (diffing), 17 (C++ RE), 20 (decompilation), 22 (OOP), 27 (ransomware).

### Radare2 and Cutter

Radare2 is the Swiss-army knife on the command line. Cutter is a graphical interface based on Rizin (a fork of Radare2), but remains compatible with the concepts and most `r2` commands. It is the most polished GUI for working visually with an analysis engine from the Radare family.

Install Radare2 from source to get the latest version:

```bash
[vm] git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2
[vm] cd /tmp/radare2
[vm] sys/install.sh
[vm] r2 -v               # expected: radare2 5.9.x+
```

For Cutter:

```bash
[vm] sudo apt install -y cutter
```

If the package is not available or too old, download the AppImage from [cutter.re](https://cutter.re/):

```bash
[vm] wget "https://github.com/rizinorg/cutter/releases/download/v2.4.0/Cutter-v2.4.0-Linux-x86_64.AppImage" \
     -O ~/tools/Cutter.AppImage
[vm] chmod +x ~/tools/Cutter.AppImage
```

> 📌 **Chapters concerned**: 9 (Radare2/Cutter), 10 (radiff2 for diffing).

### ImHex

ImHex is an advanced hex editor with support for `.hexpat` patterns, structure coloring, integrated disassembler, and YARA rules.

There is no official PPA for ImHex. Download the `.deb` from the [GitHub releases page](https://github.com/WerWolv/ImHex/releases):

```bash
[vm] IMHEX_VERSION="1.37.4"
[vm] wget "https://github.com/WerWolv/ImHex/releases/download/v${IMHEX_VERSION}/imhex-${IMHEX_VERSION}-Ubuntu-24.04-x86_64.deb" \
     -O /tmp/imhex.deb
[vm] sudo dpkg -i /tmp/imhex.deb
[vm] sudo apt install -f -y    # resolves missing dependencies
[vm] rm /tmp/imhex.deb
```

> ⚠️ Verify the version and exact filename of the `.deb` on the releases page. Naming conventions change between versions.

> 📌 **Chapters concerned**: 6 (ImHex chapter), 21 (patching), 23 (network protocol), 24 (encrypted format), 25 (custom format), 27 (ransomware), 29 (unpacking).

### IDA Free (optional)

IDA Free is the free version of the commercial IDA Pro disassembler. It is limited (x86-64 only, no decompiler in older versions, one target at a time), but remains useful for Chapter 9 (tool comparison).

Download the installer from [hex-rays.com/ida-free](https://hex-rays.com/ida-free/) and follow the instructions:

```bash
[vm] chmod +x ida-free-*.run
[vm] ./ida-free-*.run
```

> 📌 **Chapter concerned**: 9 (IDA Free workflow), 10 (BinDiff from IDA).

---

## Wave 4 — Instrumentation, fuzzing, and symbolic-execution frameworks

> ⚠️ All the `pip install` commands that follow assume the `re-venv` virtual environment is activated.

### GDB Extensions: GEF, pwndbg, PEDA

These three extensions enrich GDB with an improved interface, real-time display of registers and the stack, and specialized commands for RE and exploitation. **You only need to install one at a time** — they all modify the `~/.gdbinit` file and are mutually exclusive.

Our recommendation for this training is **GEF** (GDB Enhanced Features), for its lightness and broad compatibility:

```bash
[vm] bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
[vm] gdb -q -ex "gef help" -ex quit    # verifies GEF loads
```

If you prefer **pwndbg** (better for heap analysis):

```bash
[vm] git clone https://github.com/pwndbg/pwndbg ~/tools/pwndbg
[vm] cd ~/tools/pwndbg
[vm] ./setup.sh
```

And for **PEDA**:

```bash
[vm] git clone https://github.com/longld/peda.git ~/tools/peda
[vm] echo "source ~/tools/peda/peda.py" > ~/.gdbinit
```

> 💡 **Tip**: you can install all three and switch between them by modifying `~/.gdbinit`. Some users maintain separate files (`~/.gdbinit-gef`, `~/.gdbinit-pwndbg`, `~/.gdbinit-peda`) and use an alias to load the desired one. Chapter 12 details this multi-extension setup.

> 📌 **Chapters concerned**: 12 (GDB extensions chapter), 21–29 (practical cases).

### Frida

Frida is a dynamic instrumentation framework. It is installed via pip (host side) and requires a server on the target (here the same machine):

```bash
[vm] pip install frida-tools frida
[vm] frida --version      # expected: 16.x+
```

Verify that Frida can attach to a process:

```bash
[vm] frida-trace -i "open" /bin/ls    # should trace calls to open()
```

> 📌 **Chapters concerned**: 13 (Frida chapter), 24 (key extraction), 27–28 (malware).

### pwntools

pwntools is a Python library for scripting interactions with binaries (I/O, patching, ROP, network).

```bash
[vm] pip install pwntools
[vm] python3 -c "from pwn import *; print(pwnlib.version)"
```

> 📌 **Chapters concerned**: 11 (pwntools introduction), 21 (keygen), 23 (network client), 35 (automation).

### AFL++

AFL++ is the reference coverage-guided fuzzer:

```bash
[vm] sudo apt install -y afl++
[vm] afl-fuzz --version
```

If the package is not available, compile from source:

```bash
[vm] git clone https://github.com/AFLplusplus/AFLplusplus.git ~/tools/AFLplusplus
[vm] cd ~/tools/AFLplusplus
[vm] make distrib
[vm] sudo make install
```

> 📌 **Chapters concerned**: 15 (fuzzing chapter), 25 (fuzzing the custom-format parser).

### angr and Z3

angr is a symbolic-execution framework. Z3 is the SMT solver it uses as a backend (installed automatically as a dependency).

```bash
[vm] pip install angr
[vm] python3 -c "import angr; print(angr.__version__)"    # expected: 9.2.x+
```

To use Z3 directly (section 18.4):

```bash
[vm] pip install z3-solver
[vm] python3 -c "import z3; print(z3.get_version_string())"
```

> ⚠️ angr installs many dependencies and can be slow to compile on a modest VM. Count 5 to 15 minutes.

> 📌 **Chapters concerned**: 18 (dedicated chapter), 21 (automatic keygenme solving).

### pyelftools and LIEF

Two Python libraries for parsing and manipulating ELF binaries:

```bash
[vm] pip install pyelftools lief
[vm] python3 -c "import elftools; print('pyelftools OK')"
[vm] python3 -c "import lief; print(lief.__version__)"
```

> 📌 **Chapter concerned**: 35 (automation and scripting).

### r2pipe

Python interface to drive Radare2 from a script:

```bash
[vm] pip install r2pipe
```

> 📌 **Chapter concerned**: 9 (r2pipe scripting).

---

## Wave 5 — Complementary and optional tools

The tools below are not required from the first chapter but come into play in specific parts. You can install them now or when needed.

### Wireshark and tcpdump

For network analysis (Chapter 23, Part VI):

```bash
[vm] sudo apt install -y wireshark tcpdump
```

During installation, answer "Yes" to the question about non-root access to captures, then add your user to the `wireshark` group:

```bash
[vm] sudo usermod -aG wireshark $USER
```

> 📌 **Chapters concerned**: 23 (network protocol), 26 (secure lab), 28 (dropper).

### UPX

UPX is a binary packer/unpacker:

```bash
[vm] sudo apt install -y upx-ucl
[vm] upx --version
```

> 📌 **Chapters concerned**: 19 (UPX packing), 29 (unpacking).

### BinDiff (optional)

BinDiff is Google's binary diffing tool. It integrates with Ghidra or IDA. Download it from [github.com/google/bindiff/releases](https://github.com/google/bindiff/releases):

```bash
[vm] wget "https://github.com/google/bindiff/releases/download/v8/bindiff_8_amd64.deb" \
     -O /tmp/bindiff.deb
[vm] sudo dpkg -i /tmp/bindiff.deb
[vm] sudo apt install -f -y
```

> 📌 **Chapter concerned**: 10 (binary diffing).

### Monitoring tools for the malware lab (Part VI)

```bash
[vm] sudo apt install -y auditd inotify-tools sysdig
```

- `auditd`: audits system calls at the kernel level.  
- `inotify-tools`: monitors filesystem modifications (`inotifywait`).  
- `sysdig`: system event capture and analysis.

> 📌 **Chapters concerned**: 26 (setting up the lab), 27–28 (malware analysis).

### Clang and sanitizers (Parts III–IV)

Clang provides the AddressSanitizer, UBSan, and MSan sanitizers, as well as libFuzzer:

```bash
[vm] sudo apt install -y clang llvm
[vm] clang --version
```

> 📌 **Chapters concerned**: 14 (sanitizers), 15 (libFuzzer), 16 (GCC vs Clang comparison).

### .NET tools — Part VII (optional)

If you plan to tackle chapters 30 through 32 on .NET RE:

```bash
[vm] sudo apt install -y dotnet-sdk-8.0
```

For ILSpy (on the Linux command line):

```bash
[vm] dotnet tool install --global ilspycmd
```

> 📌 **Chapters concerned**: 30–32 (.NET RE).

### Rust and Go toolchains — Part VIII (optional)

To compile the Rust and Go training binaries of chapters 33 and 34:

```bash
# Rust
[vm] curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
[vm] source ~/.cargo/env
[vm] rustc --version

# Go
[vm] sudo apt install -y golang
[vm] go version
```

> 📌 **Chapters concerned**: 33 (Rust RE), 34 (Go RE).

---

## Summary of tested versions

The table below lists the versions with which this training has been tested. More recent versions will work in the vast majority of cases.

| Tool | Tested version | Installation |  
|---|---|---|  
| GCC / G++ | 13.2 | `apt` (via `build-essential`) |  
| Python 3 | 3.12 | `apt` |  
| Java (OpenJDK) | 21 | `apt` |  
| GDB | 15.0 | `apt` |  
| GEF | 2024.01+ | Installation script |  
| pwndbg | 2024.02+ | Git + setup.sh |  
| Ghidra | 11.3 | GitHub download |  
| Radare2 | 5.9 | Compile from source |  
| Cutter | 2.4 | `apt` or AppImage |  
| ImHex | 1.37 | `.deb` from GitHub |  
| IDA Free | 9.0 | hex-rays.com download |  
| Frida | 16.x | `pip` |  
| pwntools | 4.13 | `pip` |  
| AFL++ | 4.21c | `apt` or compilation |  
| angr | 9.2 | `pip` |  
| Z3 | 4.13 | `pip` (via `z3-solver`) |  
| Valgrind | 3.22 | `apt` |  
| YARA | 4.3 | `apt` + `pip` (yara-python) |  
| Wireshark | 4.2 | `apt` |  
| UPX | 4.2 | `apt` |  
| BinDiff | 8 | `.deb` from GitHub |  
| pyelftools | 0.31 | `pip` |  
| LIEF | 0.15 | `pip` |  
| Clang / LLVM | 18.x | `apt` |  
| binwalk | 2.3 | `apt` |

---

## Disk layout

After all these installations, here is the recommended directory tree in your user home:

```
~/
├── re-venv/                  ← Python virtual environment
├── tools/                    ← Manually installed tools
│   ├── pwndbg/               
│   ├── AFLplusplus/          (if compiled from source)
│   └── Cutter.AppImage       (if AppImage)
├── formation-re/             ← Cloned training repository
│   ├── binaries/
│   ├── scripts/
│   ├── hexpat/
│   ├── yara-rules/
│   └── ...
└── .gdbinit                  ← Loads GEF (or pwndbg/PEDA)
```

Tools installed via `apt` end up in `/usr/bin/` or `/usr/local/bin/`. Tools installed into `/opt/` (such as Ghidra) are accessible via aliases in `~/.bashrc`.

---

## In case of problems

A few diagnostic reflexes:

- **`command not found`** — Check that the package is installed (`which <tool>` or `dpkg -l | grep <tool>`), that the `PATH` is correct, and that the Python virtual environment is activated if the tool is a pip package.  
- **pip dependency conflict** — Make sure you are in `re-venv`. If the conflict persists, try `pip install --force-reinstall <package>`.  
- **Ghidra won't launch** — Check the Java version (`java -version`). Ghidra 11.x requires JDK 17+.  
- **GEF / pwndbg does not load in GDB** — Check the contents of `~/.gdbinit`. Only one extension should be sourced.  
- **Frida fails with "Failed to spawn"** — Verify you have access rights to the target process (run with `sudo` if needed, or adjust `ptrace_scope`).  
- **AFL++: "Hmm, your system is configured to send core dump notifications to an external utility"** — Run `echo core | sudo tee /proc/sys/kernel/core_pattern` before launching the fuzzer.

---

## Summary

By the end of this section, your VM contains:

- the **compilation base** (GCC, G++, Make, Clang) to produce and recompile the training binaries;  
- the **inspection tools** on the command line (binutils, strace, ltrace, checksec, YARA, binwalk) for quick triage;  
- the **graphical disassemblers and editors** (Ghidra, Radare2/Cutter, ImHex) for in-depth static analysis;  
- the **dynamic frameworks** (GDB + GEF, Frida, pwntools, Valgrind) for runtime analysis;  
- the **advanced analysis engines** (AFL++, angr, Z3) for fuzzing and symbolic execution;  
- an **isolated Python environment** (`re-venv`) containing all the required libraries.

The `check_env.sh` script (section 4.7) will automatically validate that everything is in place.

---


⏭️ [Creating a sandboxed VM (VirtualBox / QEMU / UTM for macOS)](/04-work-environment/03-vm-creation.md)
