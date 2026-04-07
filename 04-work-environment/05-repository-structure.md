🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.5 — Repository structure: organization of `binaries/` and per-chapter `Makefile`s

> 🎯 **Goal of this section**: understand the organization of the training repository — where the sources, binaries, scripts, patterns, and solutions live — in order to navigate the material efficiently throughout the 36 chapters.

---

## Repository overview

The `reverse-engineering-gcc-gpp-training/` repository is organized around a simple principle: **every type of content has its dedicated place**, and every chapter is self-contained in its own folder.

```
reverse-engineering-gcc-gpp-training/
│
├── README.md                    ← General overview + links to the parts
├── LICENSE                      ← MIT + ethical disclaimer
├── check_env.sh                 ← Environment verification script
├── preface.md                   ← Tutorial preface
│
├── part-1-fundamentals.md       ← Part I introduction
├── part-2-static-analysis.md    ← Part II introduction
├── ...                          ← One introduction per part (9 files)
│
├── 01-introduction-re/            ┐
├── 02-gnu-compilation-chain/      │
├── ...                            ├─ One folder per chapter (36 folders)
├── 35-automation-scripting/       │
├── 36-resources-further-learning/ ┘
│
├── binaries/                    ← C/C++/Rust/Go sources + Makefile → training binaries
├── scripts/                     ← Python utility scripts
├── hexpat/                      ← ImHex patterns (.hexpat)
├── yara-rules/                  ← YARA rules
├── appendices/                  ← Appendices A–K (references, cheat sheets, glossary)
│
└── solutions/                   ← Checkpoint solutions (⚠️ spoilers)
```

Four major content categories coexist:

1. **The course** — the 36 chapter folders, each containing Markdown files (`.md`) and a `checkpoint.md`.  
2. **The training binaries** — the `binaries/` directory, the practical core of the training.  
3. **Cross-cutting resources** — Python scripts, ImHex patterns, YARA rules, appendices.  
4. **The solutions** — the `solutions/` directory, to be consulted only after attempting the checkpoints.

---

## The chapter folders

Each chapter follows the same internal structure:

```
XX-chapter-name/
├── README.md               ← Chapter introduction and outline
├── 01-first-section.md     ← Numbered sections
├── 02-second-section.md
├── ...
└── checkpoint.md           ← Mini-exercise to validate learning
```

The `README.md` of each chapter acts as a landing page: it introduces the subject, lists the prerequisites, summarizes the outline, and links to the sections. It is the entry point if you jump into a chapter directly, without going through the previous ones.

Sections are numbered in the recommended reading order. Each file is self-contained — it holds the text, code excerpts, commands, and references to the relevant binaries.

The `checkpoint.md` closes the chapter with a practical exercise that exercises the skills covered. The corresponding solution is in `solutions/`.

> 💡 The chapters do not contain compiled binaries. The sources live in `binaries/`, and it is up to you to compile them (section 4.6). This separation is intentional: it ensures the binaries are compiled for *your* system, with *your* version of GCC, exactly as in a real RE context.

---

## The `binaries/` directory — the practical core

This is the most important directory in the repository. It contains the **sources** of the training applications and the **Makefiles** that compile them into several variants.

### Directory tree

```
binaries/
├── Makefile                   ← Root Makefile: `make all` compiles everything
│
├── ch21-keygenme/
│   ├── keygenme.c             ← C source of the crackme
│   └── Makefile               ← Produces the binary variants
│
├── ch22-oop/
│   ├── oop.cpp                ← Object-oriented C++ source
│   └── Makefile
│
├── ch23-network/
│   ├── client.c               ← Network client
│   ├── server.c               ← Network server
│   └── Makefile
│
├── ch24-crypto/
│   ├── crypto.c               ← Application with encryption
│   └── Makefile
│
├── ch25-fileformat/
│   ├── fileformat.c           ← Custom-format parser
│   └── Makefile
│
├── ch27-ransomware/           ← ⚠️ Sandbox only
│   ├── ransomware_sample.c
│   └── Makefile
│
├── ch28-dropper/              ← ⚠️ Sandbox only
│   ├── dropper_sample.c
│   └── Makefile
│
├── ch29-packed/
│   ├── packed_sample.c
│   └── Makefile
│
├── ch33-rust/
│   ├── crackme_rust/
│   │   ├── src/
│   │   │   └── main.rs
│   │   └── Cargo.toml
│   └── Makefile
│
└── ch34-go/
    ├── crackme_go/
    │   └── main.go
    └── Makefile
```

### Sub-folder naming convention

Each sub-folder is prefixed with the **number of the chapter** that uses it primarily: `ch21-keygenme`, `ch23-network`, etc. This prefix makes it possible to immediately link a binary to the chapter documenting it.

Some binaries are reused in several chapters. For example, `ch21-keygenme` appears in Chapter 21 (main practical case), but also in Chapters 7 (optimization comparison with `objdump`), 12 (tracing with GEF), 18 (solving with angr), and others. The folder name indicates the *introducing* chapter of the binary, not the only chapter that uses it.

### What each sub-folder contains

A typical sub-folder contains:

- **One or several source files** (`.c`, `.cpp`, `.rs`, `.go`) — the code you compile.  
- **A dedicated `Makefile`** — that knows how to produce all the required variants of the binary.

The **compiled binaries** are not versioned in the repository. They are generated locally by `make` and appear in the same directory as the sources after compilation. This is a deliberate choice: binaries depend on the compiler, its version, and the system, and should not be shared as static files.

---

## Anatomy of a chapter Makefile

Each sub-folder Makefile follows the same model. Let's take the example of `ch21-keygenme/Makefile`:

```makefile
CC      = gcc  
CFLAGS  = -Wall -Wextra  
SRC     = keygenme.c  
NAME    = keygenme  

all: $(NAME)_O0 $(NAME)_O2 $(NAME)_O3 $(NAME)_O0_strip $(NAME)_O2_strip

# --- Variants by optimization level ---

$(NAME)_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

$(NAME)_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

$(NAME)_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

# --- Stripped variants (no symbols) ---

$(NAME)_O0_strip: $(NAME)_O0
	cp $< $@
	strip $@

$(NAME)_O2_strip: $(NAME)_O2
	cp $< $@
	strip $@

clean:
	rm -f $(NAME)_O0 $(NAME)_O2 $(NAME)_O3 $(NAME)_O0_strip $(NAME)_O2_strip

.PHONY: all clean
```

This Makefile produces **five binaries** from a single source file:

| Binary | Optimization | Debug symbols | Stripped |  
|---|---|---|---|  
| `keygenme_O0` | `-O0` (none) | Yes (`-g`) | No |  
| `keygenme_O2` | `-O2` (standard) | Yes (`-g`) | No |  
| `keygenme_O3` | `-O3` (aggressive) | Yes (`-g`) | No |  
| `keygenme_O0_strip` | `-O0` | No | Yes |  
| `keygenme_O2_strip` | `-O2` | No | Yes |

### Why these variants?

This multi-variant approach is at the core of the training's pedagogy:

**Optimization levels** (`-O0` through `-O3`) let you see how the same source code transforms radically at the assembly level depending on compiler options. Chapter 7 compares `objdump` listings of `keygenme_O0` and `keygenme_O2`. Chapter 16 analyzes in depth the optimizations applied by GCC. Having the variants side by side makes these differences tangible.

**Variants with symbols** (`-g`) make learning easier: function names, line numbers, and variable names are present in the DWARF information. It is a safety net when you are starting out — you can check your deductions against the symbols.

**Stripped variants** simulate real RE conditions. A commercial binary, a piece of malware, a firmware — none of them will give you debug symbols. Working on stripped variants is harder, but it is the skill you are building.

> 💡 **Recommended progression**: for each practical case, start with the `_O0` variant (the most readable at the assembly level), then move to `_O2` (more realistic), and finally try the `_O2_strip` variant (real conditions). This is a natural difficulty ramp that consolidates what you have learned.

---

## The root Makefile

The `binaries/Makefile` file (at the root of the `binaries/` directory) orchestrates the compilation of all sub-folders:

```makefile
SUBDIRS = ch21-keygenme ch22-oop ch23-network ch24-crypto ch25-fileformat \
          ch27-ransomware ch28-dropper ch29-packed ch33-rust ch34-go

all:
	@for dir in $(SUBDIRS); do \
		echo "=== Compiling $$dir ==="; \
		$(MAKE) -C $$dir all; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

.PHONY: all clean
```

A simple `make all` from `binaries/` compiles all variants of all chapters. A `make clean` removes all generated binaries. Section 4.6 details this operation.

> ⚠️ **Prerequisites**: compiling the `ch33-rust` and `ch34-go` sub-folders respectively requires the Rust (`rustc`/`cargo`) and Go (`go`) toolchains. If they are not installed, these two targets will fail without affecting the others. These toolchains are marked as optional in section 4.2.

---

## The `scripts/` directory

```
scripts/
├── triage.py             ← Automatic binary triage
├── keygen_template.py    ← Keygen template with pwntools
└── batch_analyze.py      ← Batch analysis script for Ghidra headless
```

These Python scripts are **utility tools** used and detailed in the following chapters:

**`triage.py`** (Chapter 5) — automates the "quick triage" workflow seen in section 5.7. It runs `file`, `strings`, `readelf`, `checksec`, and `ldd` on a given binary and produces a structured report. It is a starting point you will enrich throughout the training.

**`keygen_template.py`** (Chapter 21) — keygen skeleton based on pwntools. Chapter 21 guides you to complete it in order to generate valid keys for the `keygenme` crackme.

**`batch_analyze.py`** (Chapter 35) — batch-analysis script using Ghidra in headless mode. It imports a directory of binaries, launches automatic analysis on each one, and produces a JSON report. It is the Chapter 35 checkpoint.

> 💡 These scripts are starting points, not turnkey solutions. They contain `TODO`s and incomplete functions that you will fill in during the exercises.

---

## The `hexpat/` directory

```
hexpat/
├── elf_header.hexpat          ← Pattern to visualize an ELF header
├── ch25_fileformat.hexpat     ← Pattern for the custom format of Chapter 25
└── ch23_protocol.hexpat       ← Pattern for the network protocol of Chapter 23
```

The `.hexpat` files are **ImHex patterns** written in ImHex's structure-description language. They make it possible to overlay a structured grammar on a raw binary file, turning a sequence of bytes into named, typed, colorized fields.

**`elf_header.hexpat`** (Chapter 6) — reference pattern that parses and colors the headers of an ELF file (magic bytes, type, architecture, entry point, program headers, section headers). It is a pedagogical tool to understand the ELF structure visually, and a complete example of `.hexpat` syntax.

**`ch25_fileformat.hexpat`** (Chapter 25) — pattern for the custom file format created for the Chapter 25 practical case. The Chapter 6 checkpoint asks you to write it yourself before looking at this version.

**`ch23_protocol.hexpat`** (Chapter 23) — pattern to decode frames of the custom network protocol used by the client/server in Chapter 23. Lets you load a `.pcap` file (or a raw dump) into ImHex and visualize each packet's fields.

---

## The `yara-rules/` directory

```
yara-rules/
├── crypto_constants.yar      ← Detection of cryptographic constants
└── packer_signatures.yar     ← Detection of common packers (UPX, etc.)
```

The `.yar` files contain **YARA rules** — pattern-matching signatures applied to binary files.

**`crypto_constants.yar`** (Chapters 24, 27) — detects the presence of known cryptographic constants: AES S-box, SHA-256 initialization vectors, MD5 constants, RC4 tables. When this rule matches on a binary, it is a strong hint that the binary uses cryptography — and a starting point for identifying the corresponding routines in the disassembler.

**`packer_signatures.yar`** (Chapter 29) — detects signatures of common packers: UPX headers, sections with characteristic names, entropy patterns. Useful in the triage workflow to know whether a binary is compressed or obfuscated before trying to disassemble it.

> 📌 Chapter 35 guides you in writing your own YARA rules and integrating them into an automated analysis pipeline.

---

## The `appendices/` directory

```
appendices/
├── README.md
├── appendix-a-opcodes-x86-64.md
├── appendix-b-system-v-abi.md
├── appendix-c-cheatsheet-gdb.md
├── appendix-d-cheatsheet-radare2.md
├── appendix-e-cheatsheet-imhex.md
├── appendix-f-elf-sections.md
├── appendix-g-native-tools-comparison.md
├── appendix-h-dotnet-tools-comparison.md
├── appendix-i-gcc-patterns.md
├── appendix-j-crypto-constants.md
└── appendix-k-glossary.md
```

The appendices are **reference documents** you will consult regularly during the training and beyond. They are not chapters to be read end to end, but cheat sheets to keep at hand:

- **Appendix A** — The most frequent x86-64 opcodes in RE, with their effect on registers and flags.  
- **Appendices C, D, E** — Cheat sheets for GDB/GEF/pwndbg, Radare2/Cutter, and ImHex. Print them or keep them in a tab.  
- **Appendix F** — Table of ELF sections and their roles — companion to Chapter 2.  
- **Appendix I** — Assembly patterns characteristic of GCC — companion to Chapter 16.  
- **Appendix J** — Cryptographic magic constants — companion to Chapter 24.  
- **Appendix K** — Complete reverse engineering glossary, from "ABI" to "zero-day".

---

## The `solutions/` directory

```
solutions/
├── ch01-checkpoint-solution.md
├── ch02-checkpoint-solution.md
├── ...
├── ch21-checkpoint-keygen.py
├── ch22-checkpoint-plugin.cpp
├── ch23-checkpoint-client.py
├── ...
└── ch35-checkpoint-batch.py
```

Each file corresponds to the solution of a chapter's checkpoint. Formats vary by exercise nature: Markdown for written analyses, Python for scripts, C++ for the Chapter 22 plugin, `.hexpat` for the Chapter 6 ImHex checkpoint.

> ⚠️ **Spoilers.** Consult the solutions only after trying the checkpoint yourself. RE is a discipline acquired through practice — reading a solution without searching does not build the reflexes needed.

---

## Files at the root

Three files at the root of the repository deserve mention:

**`README.md`** — the general overview of the training. It is the main entry point, with links to every part, every chapter, and every section. If you are lost, come back here.

**`LICENSE`** — MIT license with an ethical disclaimer. It reminds that the content is strictly educational and that using the taught techniques on software without authorization is illegal.

**`check_env.sh`** — the environment verification script detailed in section 4.7. It walks through all expected tools, checks their versions, and verifies that the training binaries are compiled.

---

## Cloning the repository

If not already done, clone the repository into your VM:

```bash
[vm] git clone https://github.com/NDXDeveloper/reverse-engineering-gcc-gpp-training.git ~/formation-re
[vm] cd ~/formation-re
[vm] ls
```

You should see the structure described above. The `binaries/` directory contains only sources and Makefiles — no compiled binaries yet. That is the subject of the next section.

---

## Summary

- The repository is organized by **content type**: chapters (course), `binaries/` (practice), `scripts/`/`hexpat/`/`yara-rules/` (resources), `solutions/` (solutions), `appendices/` (references).  
- Each chapter is a self-contained folder with its Markdown sections and a checkpoint.  
- The `binaries/` directory contains the **sources** and **Makefiles**, not compiled binaries. Each Makefile produces several variants (optimization levels, with/without symbols) to enable progressive learning.  
- The root Makefile of `binaries/` compiles everything with a single command (`make all`).  
- Cross-cutting resources (`.hexpat` patterns, YARA rules, Python scripts) are centralized in dedicated directories and referenced from the relevant chapters.

---


⏭️ [Compile all training binaries in one command (`make all`)](/04-work-environment/06-compiling-binaries.md)
