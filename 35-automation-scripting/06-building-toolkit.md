🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 35.6 — Building Your Own RE Toolkit: Organizing Your Scripts and Snippets

> 🎯 **Objective**: structure the scripts developed throughout this training (and those you will write later) into a coherent, documented, versioned, and reusable personal toolkit from one analysis to the next.

---

## The throwaway script problem

Every RE analyst accumulates scripts. A `pyelftools` one-liner to list functions. A Frida snippet to hook `strcmp`. A `pwntools` keygen template. A GDB script that dumps memory around a breakpoint. A YARA rule written at 2 AM during a CTF.

These scripts are born in temporary directories, with names like `test.py`, `solve2_final_v3.py`, or directly in the terminal history. Three weeks later, facing a similar binary, the analyst rewrites the same script from scratch because they can no longer find the original — or they find it, but can no longer understand what it does.

The cost of this disorganization is real. This is not a matter of personal discipline — it is an engineering problem. The same principles that make a software project work (directory structure, documentation, dependency management, version control) apply to an RE toolkit. This section lays the practical foundations.

---

## Directory structure

An RE toolkit is not a conventional software project. It does not produce a single deliverable — it is a collection of independent tools that share common utilities. The structure must reflect this reality: each script is self-contained, but reusable building blocks are factored out.

```
re-toolkit/
│
├── README.md                  <- Toolkit description, installation, index
├── requirements.txt           <- Python dependencies (lief, yara-python, pwntools...)
├── setup.sh                   <- Automated environment installation
│
├── triage/                    <- First-contact scripts for a binary
│   ├── triage_elf.py          <- Complete triage (lief + checksec + YARA)
│   ├── quick_strings.py       <- String extraction with context (section, offset)
│   └── compare_builds.py      <- Diff between two binary versions
│
├── static/                    <- Automated static analysis
│   ├── list_functions.py      <- pyelftools: list functions
│   ├── find_crypto.py         <- Crypto constant search (lief + patterns)
│   ├── extract_rodata.py      <- Dump .rodata with annotations
│   └── ghidra/                <- Ghidra headless scripts
│       ├── list_functions.py
│       ├── decompile_all.py
│       ├── find_callers.py
│       └── scan_crypto.py
│
├── dynamic/                   <- Dynamic analysis and instrumentation
│   ├── gdb/
│   │   ├── dump_strcmp.py      <- GDB Python script: log strcmp args
│   │   ├── dump_malloc.py      <- GDB Python script: log malloc/free
│   │   └── break_on_crypto.gdb <- Breakpoints on common crypto functions
│   └── frida/
│       ├── hook_strcmp.js       <- Hook strcmp with argument logging
│       ├── hook_network.js     <- Hook send/recv/connect
│       └── hook_crypto.js      <- Hook EVP_*, SHA256, etc.
│
├── patching/                  <- Binary modification
│   ├── flip_jump.py           <- Invert a conditional jump (lief/pwntools)
│   ├── nop_range.py           <- NOP-out an address range
│   └── add_section.py         <- Add a custom section to an ELF
│
├── keygen/                    <- Keygen and solver templates
│   ├── keygen_template.py     <- pwntools template (process + GDB extract)
│   ├── angr_template.py       <- angr template (find/avoid)
│   └── z3_template.py         <- Z3 template (manual constraints)
│
├── formats/                   <- Custom format parsers
│   ├── parse_cfr.py           <- CFR format parser (ch25)
│   ├── parse_crypt24.py       <- CRYPT24 format parser (ch24)
│   └── hexpat/
│       ├── elf_header.hexpat
│       ├── cfr_format.hexpat
│       └── crypt24_format.hexpat
│
├── yara/                      <- YARA rules
│   ├── crypto_constants.yar
│   ├── packer_signatures.yar
│   └── custom/                <- Rules specific to your analyses
│       └── .gitkeep
│
├── ci/                        <- CI/CD integration
│   ├── audit_binary.py
│   ├── diff_audits.py
│   └── policies/
│       └── default_policy.json
│
├── lib/                       <- Shared utilities
│   ├── __init__.py
│   ├── elf_helpers.py         <- Common pyelftools/lief functions
│   ├── format_utils.py        <- Packing, unpacking, hex dump
│   ├── report.py              <- JSON/Markdown report generation
│   └── constants.py           <- Known crypto constants, signatures
│
└── docs/                      <- Toolkit documentation
    ├── INSTALL.md             <- Detailed installation guide
    ├── CONVENTIONS.md         <- Code and naming conventions
    └── CATALOG.md             <- Script index with description and usage
```

### Principles behind this structure

**One directory per analysis phase.** `triage/`, `static/`, `dynamic/`, `patching/` follow the natural RE workflow. When starting an analysis, you know which directory to look in.

**Ghidra scripts kept separate.** Ghidra headless scripts live in `static/ghidra/` because they run in Ghidra's Jython interpreter, not in the toolkit's Python environment. They cannot import `lib/` — this physical separation avoids confusion.

**Templates in `keygen/`.** A template is not a finished script — it is a skeleton with sections to fill in (`# TODO: insert the find address`, `# TODO: model the constraints`). It saves the first ten minutes of each new challenge.

**`lib/` for shared code.** Functions used by multiple scripts (ELF parsing, hexadecimal formatting, report generation) are factored out here. The `__init__.py` makes it an importable package:

```python
# From any script in the toolkit:
from lib.elf_helpers import list_functions, get_imports  
from lib.report import generate_json_report  
```

---

## The `lib/` module: shared utilities

The `lib/` module is the glue of the toolkit. Rather than copy-pasting the same ten lines of ELF parsing into every script, you write them once here.

### `lib/elf_helpers.py`

```python
"""Utility functions for ELF inspection with lief and pyelftools."""

import lief  
from elftools.elf.elffile import ELFFile  
from elftools.elf.sections import SymbolTableSection  

def quick_info(path):
    """Return a dict with essential properties of a binary."""
    b = lief.parse(str(path))
    if b is None:
        return None
    return {
        "path": str(path),
        "pie": b.is_pie,
        "nx": b.has_nx,
        "stripped": len(list(b.static_symbols)) == 0,
        "libraries": list(b.libraries),
        "imports": sorted(s.name for s in b.imported_symbols if s.name),
        "sections": {s.name: {"size": s.size, "entropy": round(s.entropy, 2)}
                     for s in b.sections if s.name},
    }

def list_functions(path):
    """List functions via pyelftools (non-stripped binary)."""
    functions = []
    with open(str(path), "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value']:
                    functions.append({
                        "name": sym.name,
                        "addr": sym['st_value'],
                        "size": sym['st_size'],
                    })
    return sorted(functions, key=lambda f: f["addr"])

def get_imports(path):
    """Return the set of imported symbols."""
    b = lief.parse(str(path))
    return {s.name for s in b.imported_symbols if s.name} if b else set()

def find_bytes(path, pattern, section_name=None):
    """Search for a byte sequence, optionally restricted to a section."""
    b = lief.parse(str(path))
    if b is None:
        return []
    results = []
    if section_name:
        s = b.get_section(section_name)
        if s:
            content = bytes(s.content)
            offset = 0
            while True:
                idx = content.find(pattern, offset)
                if idx < 0:
                    break
                results.append(s.virtual_address + idx)
                offset = idx + 1
    else:
        for addr in b.elf.search(pattern) if hasattr(b, 'elf') else []:
            results.append(addr)
    return results
```

### `lib/format_utils.py`

```python
"""Formatting and binary data manipulation utilities."""

import struct

def hexdump(data, base_addr=0, width=16):
    """Produce a formatted hexdump of a buffer."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base_addr + offset:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)

def u8(data, offset):
    return struct.unpack_from("<B", data, offset)[0]

def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]

def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]

def p32(value):
    return struct.pack("<I", value & 0xFFFFFFFF)

def find_all(data, pattern):
    """Return all offsets of a pattern in a buffer."""
    results = []
    offset = 0
    while True:
        idx = data.find(pattern, offset)
        if idx < 0:
            break
        results.append(idx)
        offset = idx + 1
    return results
```

### `lib/report.py`

```python
"""Structured report generation."""

import json  
import time  
from pathlib import Path  

def generate_json_report(binary_path, data, output_path=None):
    """Wrap a result dict in a timestamped report."""
    report = {
        "metadata": {
            "binary": str(binary_path),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "toolkit_version": "1.0.0",
        },
        "results": data,
    }
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
    return report

def generate_markdown_report(binary_path, data):
    """Produce a human-readable Markdown report."""
    lines = [
        f"# Analysis Report — `{Path(binary_path).name}`",
        f"",
        f"**Date**: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        f"**Binary**: `{binary_path}`",
        f"",
    ]
    for section_name, section_data in data.items():
        lines.append(f"## {section_name}")
        lines.append("")
        if isinstance(section_data, dict):
            for k, v in section_data.items():
                lines.append(f"- **{k}**: {v}")
        elif isinstance(section_data, list):
            for item in section_data:
                lines.append(f"- {item}")
        else:
            lines.append(str(section_data))
        lines.append("")
    return "\n".join(lines)
```

---

## Dependency management

A toolkit unusable because of a `ModuleNotFoundError` is a dead toolkit. Explicit dependency management is the first thing to set up.

### `requirements.txt`

```
# re-toolkit/requirements.txt
# Python dependencies for the RE toolkit
# Installation: pip install -r requirements.txt

# ELF parsing and modification (section 35.1)
pyelftools>=0.29  
lief>=0.13.0  

# Binary interaction (section 35.3)
pwntools>=4.11.0

# Pattern scanning (section 35.4)
yara-python>=4.3.0

# Symbolic execution (Chapter 18)
angr>=9.2.0  
z3-solver>=4.12.0  

# Utilities
capstone>=5.0.0        # disassembly  
keystone-engine>=0.9.2 # assembly  
```

### `setup.sh`

```bash
#!/bin/bash
# setup.sh — RE toolkit environment installation
set -e

echo "=== RE toolkit installation ==="

# Python virtual environment
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "[+] Virtual environment created"
fi  
source .venv/bin/activate  

# Python dependencies
pip install --upgrade pip  
pip install -r requirements.txt  
echo "[+] Python dependencies installed"  

# System dependencies (Debian/Ubuntu)
if command -v apt-get &>/dev/null; then
    sudo apt-get install -y yara gdb gcc g++ make binutils \
        libssl-dev strace ltrace
    echo "[+] System dependencies installed"
fi

# Verification
echo ""  
echo "=== Verification ==="  
python3 -c "import lief; print(f'  lief {lief.__version__}')"  
python3 -c "import yara; print(f'  yara-python OK')"  
python3 -c "import pwn; print(f'  pwntools {pwn.__version__}')"  
python3 -c "from elftools import __version__; print(f'  pyelftools {__version__}')"  
yara --version 2>/dev/null && echo "  yara CLI OK"  
gdb --version 2>/dev/null | head -1  

echo ""  
echo "[+] Toolkit ready. Activate the environment: source .venv/bin/activate"  
```

The Python virtual environment (`.venv`) isolates the toolkit's dependencies from the system's. This is essential for reproducibility — the same `requirements.txt` produces the same environment on any machine.

---

## Documentation

A toolkit without documentation is a collection of files. Three documents are enough to make the toolkit usable by someone else (including yourself in six months).

### `README.md`

The README is the entry point. It answers three questions: what is it, how to install it, and how to use it. It does not need to be long — an introductory paragraph, installation commands, and a usage example are sufficient.

### `docs/CONVENTIONS.md`

Code conventions ensure consistency across scripts. Decisions are made once and for all here, instead of being rediscovered with each new script:

```markdown
# RE Toolkit Conventions

## Naming
- Scripts: `snake_case.py` (e.g.: `find_crypto.py`)
- Functions: `snake_case` (e.g.: `list_functions()`)
- Constants: `UPPER_CASE` (e.g.: `HASH_SEED`)

## Inputs/Outputs
- The first positional argument is always the path to the target binary
- `--output` to specify an output file (JSON by default)
- Without `--output`, results go to stdout (JSON or human-readable text)
- Return code: 0 = success, 1 = problem detected, 2 = execution error

## Output format
- Structured JSON for any result consumable by another script
- Each JSON report contains a `metadata` field (see lib/report.py)
- Addresses are formatted in hexadecimal with the 0x prefix

## Ghidra scripts (static/ghidra/)
- Python 2 syntax (Jython) — no f-strings, no type hints
- Output via file (GHIDRA_OUTPUT) — never to stdout (polluted by Ghidra)
- `args` variable for arguments, `currentProgram` for the binary
```

### `docs/CATALOG.md`

The catalog is an index of all scripts, with a one-line description and an invocation example for each. It is the document you consult when wondering "do I already have a script that does this?":

```markdown
# Script Catalog

## Triage
| Script | Description | Usage |
|---|---|---|
| `triage/triage_elf.py` | Complete ELF binary triage | `python3 triage/triage_elf.py ./binary` |
| `triage/quick_strings.py` | Strings with section and offset | `python3 triage/quick_strings.py ./binary` |
| `triage/compare_builds.py` | Diff between two builds | `python3 triage/compare_builds.py v1 v2` |

## Static Analysis
| Script | Description | Usage |
|---|---|---|
| `static/list_functions.py` | List functions (pyelftools) | `python3 static/list_functions.py ./binary` |
| `static/find_crypto.py` | Search for crypto constants | `python3 static/find_crypto.py ./binary` |
...
```

This catalog is maintained manually — each time you add a script, you add a line. It is a thirty-second investment that saves hours of searching.

---

## Version control with Git

The toolkit lives in a Git repository. Each script added or modified gets a commit with a message that explains *why*, not just *what*.

### `.gitignore`

```gitignore
# Python environment
.venv/
__pycache__/
*.pyc
*.egg-info/

# Analysis artifacts (do not version results)
reports/
*.json
!policies/*.json
!docs/*.json

# Binaries (too large, recompilable from source)
*.o
*.elf
*.bin

# Ghidra projects (large and machine-specific)
*.gpr
*.rep/

# Compiled YARA rules (recompilable)
*.yarc
```

JSON reports and analyzed binaries are not versioned — they are the result of running the toolkit, not the toolkit itself. Policy files (`policies/*.json`) and YARA rules (`yara/*.yar`) are versioned because they are part of the configuration.

### Branch strategy

For a personal toolkit, a stable `main` branch is sufficient. Experiments (new script under development, testing a different approach) live in temporary branches. The criterion for merging into `main`: the script works on at least one real binary and is documented in the catalog.

---

## Evolving the toolkit

An RE toolkit is never finished. It grows at the pace of your analyses. Here are the natural moments when it gets enriched.

**After each analysis.** The question to ask yourself at the end of an analysis: "What script would I have liked to have at the start?" If a snippet was written during the analysis, cleaning it up and integrating it into the toolkit takes ten minutes. Postponing it to later means never doing it.

**After each CTF.** CTFs are high-frequency script generators. Many are throwaway, but certain patterns recur: angr solver, Frida hook for a type of protection, parser for an exotic format. Extracting the generic pattern and adding it as a template in `keygen/` is a worthwhile investment.

**When a script is used twice.** The first use of a snippet in a context different from the one where it was written is the signal that it deserves to be promoted to `lib/` or to the appropriate directory.

**When an external tool evolves.** A new version of Ghidra, `lief`, or `pwntools` can break existing scripts or offer new capabilities. Updating `requirements.txt` and verifying that scripts work is minimal maintenance.

The trap to avoid is the opposite: over-engineering the toolkit before you need to. An abstract framework with base classes, plugins, and a configuration system before having written ten scripts is an exercise in architectural procrastination. The right time to refactor is when duplication becomes painful — not before.

---

## Maturity checklist

To assess where your toolkit stands, here is a progressive scale. Level 1 is sufficient to start. Level 4 is that of a professional toolkit shared across a team.

**Level 1 — Functional.** The scripts work. They are in a directory with a minimal README. Installation is done manually.

**Level 2 — Organized.** The directory structure reflects the workflow. Dependencies are in `requirements.txt`. A `setup.sh` installs everything. The catalog exists.

**Level 3 — Reproducible.** The virtual environment isolates dependencies. Code conventions are documented and followed. The toolkit is version-controlled with Git. Scripts produce structured JSON.

**Level 4 — Shareable.** A colleague can clone the repository, run `setup.sh`, and use the toolkit without help. Each script has a `--help`. Reports are consumable by third-party tools. The CI/CD pipeline integrates the toolkit.

The goal is not to reach level 4 immediately. It is to progress one level at a time whenever the need arises — and not before.

---


⏭️ [🎯 Checkpoint: write a script that automatically analyzes a directory of binaries and produces a JSON report](/35-automation-scripting/checkpoint.md)
