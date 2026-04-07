🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 35

## Objective

Write a single Python script, `batch_analyze.py`, that takes a directory containing ELF binaries as an argument, analyzes them automatically, and produces a consolidated JSON report. The script must leverage the tools and techniques covered in the six sections of the chapter: `lief` and `pyelftools` for parsing (35.1), the structured output architecture of Ghidra headless (35.2), `pwntools` for pattern searching (35.3), `yara-python` for signature detection (35.4), the audit logic from the CI/CD section (35.5), and organization into reusable modules (35.6).

## Specification

**Input**: a path to a directory (e.g.: `binaries/`). The script recursively traverses all files and retains only valid ELF binaries.

**Processing**: for each detected ELF binary, the script collects the following information.

*Identification* — file name, path, size in bytes, architecture (x86, x86-64, ARM...), type (executable, shared object).

*Protections* — PIE (yes/no), NX (yes/no), stack canary (presence of `__stack_chk_fail` in imports), RELRO (full, partial, none), stripped (yes/no), presence of DWARF sections.

*Sections* — list of sections with name, size, and entropy. Flag sections whose entropy exceeds 7.0.

*Dependencies* — list of dynamic libraries (`NEEDED`).

*Notable imports* — categorize imported functions into families: crypto (`EVP_*`, `SHA*`, `AES_*`, `RAND_bytes`...), network (`socket`, `connect`, `send`, `recv`...), file I/O (`fopen`, `open`, `read`, `write`...), dangerous memory (`strcpy`, `strcat`, `sprintf`, `gets`...).

*Symbols* — if the binary is not stripped, count local functions and list the five largest (by size).

*YARA* — if a rules directory is provided via `--yara-rules`, scan each binary and report matches.

**Output**: a JSON file (via `--output`, default `stdout`) containing an object with two keys: `summary` (table summarizing each binary in one line) and `details` (full report per binary). The script also displays a human-readable summary on stderr.

**Return code**: 0 if execution completes normally, 2 on fatal error.

## Solution

```python
#!/usr/bin/env python3
"""
batch_analyze.py — Automated analysis of a directory of ELF binaries  
Reverse Engineering Training — Chapter 35, Checkpoint  

This script combines lief, pyelftools, and yara-python to produce a  
structured JSON report covering identification, protections,  
sections, dependencies, imports, and YARA signatures  
for each ELF binary found in a directory.  

Usage:
  python3 batch_analyze.py binaries/
  python3 batch_analyze.py binaries/ --yara-rules yara-rules/ --output report.json
  python3 batch_analyze.py binaries/ch21-keygenme/ --verbose

Dependencies:
  pip install lief pyelftools yara-python
"""

import argparse  
import json  
import sys  
import time  
from pathlib import Path  

# ── Imports with missing-module handling ───────────────────────

try:
    import lief
except ImportError:
    print("ERROR: lief required (pip install lief)", file=sys.stderr)
    sys.exit(2)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("ERROR: pyelftools required (pip install pyelftools)", file=sys.stderr)
    sys.exit(2)

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


# ── Constants: import families ─────────────────────────────────

IMPORT_FAMILIES = {
    "crypto": {
        "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
        "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
        "EVP_CipherInit_ex", "EVP_CIPHER_CTX_new", "EVP_CIPHER_CTX_free",
        "EVP_aes_256_cbc", "EVP_aes_128_cbc", "EVP_aes_256_gcm",
        "SHA256", "SHA256_Init", "SHA256_Update", "SHA256_Final",
        "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
        "MD5", "MD5_Init", "MD5_Update", "MD5_Final",
        "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key",
        "RAND_bytes", "RAND_seed",
    },
    "network": {
        "socket", "connect", "bind", "listen", "accept", "accept4",
        "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "getaddrinfo", "gethostbyname", "inet_pton", "inet_ntop",
        "select", "poll", "epoll_create", "epoll_ctl", "epoll_wait",
        "shutdown", "setsockopt", "getsockopt",
    },
    "file_io": {
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fgets",
        "open", "close", "read", "write", "lseek", "stat", "fstat",
        "opendir", "readdir", "closedir", "rename", "unlink", "mkdir",
        "mmap", "munmap",
    },
    "dangerous": {
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "fscanf", "sscanf",
    },
}


# ── ELF file detection ────────────────────────────────────────

def is_elf(path):
    """Check whether a file starts with the ELF magic (\x7FELF)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def find_elfs(directory):
    """Recursively traverse a directory and return ELF paths."""
    elfs = []
    for path in sorted(Path(directory).rglob("*")):
        if path.is_file() and is_elf(path):
            elfs.append(path)
    return elfs


# ── Binary analysis with lief ─────────────────────────────────

def analyze_protections(binary):
    """Detect PIE, NX, canary, RELRO."""
    imports = {s.name for s in binary.imported_symbols if s.name}

    # RELRO
    has_relro_seg = False
    has_bind_now = False
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
            has_relro_seg = True
    try:
        for entry in binary.dynamic_entries:
            if entry.tag == lief.ELF.DynamicEntry.TAG.BIND_NOW:
                has_bind_now = True
            if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                if entry.value & 0x08:
                    has_bind_now = True
    except Exception:
        pass

    if has_relro_seg and has_bind_now:
        relro = "full"
    elif has_relro_seg:
        relro = "partial"
    else:
        relro = "none"

    return {
        "pie": binary.is_pie,
        "nx": binary.has_nx,
        "canary": "__stack_chk_fail" in imports,
        "relro": relro,
    }


def analyze_sections(binary):
    """List sections with size and entropy."""
    sections = []
    high_entropy = []
    for s in binary.sections:
        if not s.name:
            continue
        entry = {
            "name": s.name,
            "size": s.size,
            "entropy": round(s.entropy, 2),
        }
        sections.append(entry)
        if s.entropy > 7.0 and s.size > 64:
            high_entropy.append(s.name)
    return sections, high_entropy


def analyze_imports(binary):
    """Categorize imports by family."""
    all_imports = {s.name for s in binary.imported_symbols if s.name}
    categorized = {}
    for family, signatures in IMPORT_FAMILIES.items():
        found = sorted(all_imports & signatures)
        if found:
            categorized[family] = found
    return categorized, len(all_imports)


def analyze_stripped(binary):
    """Determine whether the binary is stripped and whether it contains DWARF."""
    static_syms = list(binary.static_symbols)
    has_symtab = len(static_syms) > 0
    debug_sections = [s.name for s in binary.sections
                      if s.name.startswith(".debug_")]
    return {
        "stripped": not has_symtab,
        "static_symbols_count": len(static_syms),
        "has_dwarf": len(debug_sections) > 0,
        "debug_sections": debug_sections,
    }


# ── Symbol analysis with pyelftools ───────────────────────────

def analyze_symbols_pyelftools(path):
    """Extract local functions and the 5 largest."""
    functions = []
    try:
        with open(str(path), "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for sym in section.iter_symbols():
                    if (sym['st_info']['type'] == 'STT_FUNC'
                            and sym['st_value'] != 0
                            and sym['st_size'] > 0):
                        functions.append({
                            "name": sym.name,
                            "addr": f"0x{sym['st_value']:x}",
                            "size": sym['st_size'],
                            "bind": sym['st_info']['bind'],
                        })
    except Exception:
        pass

    local = [f for f in functions if f["bind"] == "STB_LOCAL"]
    by_size = sorted(functions, key=lambda f: f["size"], reverse=True)
    top5 = [{"name": f["name"], "size": f["size"]} for f in by_size[:5]]

    return {
        "total_functions": len(functions),
        "local_functions": len(local),
        "top5_by_size": top5,
    }


# ── YARA scan ─────────────────────────────────────────────────

def compile_yara_rules(rules_dir):
    """Compile all .yar files from a directory."""
    if not HAS_YARA:
        return None
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        return None
    rule_files = {}
    for i, path in enumerate(sorted(rules_dir.glob("*.yar"))):
        rule_files[f"ns_{i}"] = str(path)
    if not rule_files:
        return None
    try:
        return yara.compile(filepaths=rule_files)
    except yara.Error as e:
        print(f"WARNING: YARA error: {e}", file=sys.stderr)
        return None


def scan_yara(rules, path):
    """Scan a binary and return matched rule names."""
    if rules is None:
        return None
    try:
        matches = rules.match(str(path))
        return [m.rule for m in matches]
    except yara.Error:
        return []


# ── Complete binary analysis ──────────────────────────────────

def analyze_binary(path, yara_rules=None, verbose=False):
    """Entry point: complete analysis of an ELF binary."""
    if verbose:
        print(f"  Analyzing {path.name}...", file=sys.stderr)

    binary = lief.parse(str(path))
    if binary is None:
        return {"path": str(path), "error": "lief parse failed"}

    # Identification
    ident = {
        "name": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "arch": str(binary.header.machine_type).split(".")[-1],
        "type": str(binary.header.file_type).split(".")[-1],
        "entry_point": f"0x{binary.entrypoint:x}",
    }

    # Protections
    protections = analyze_protections(binary)

    # Symbols (stripped / DWARF)
    strip_info = analyze_stripped(binary)

    # Sections
    sections, high_entropy = analyze_sections(binary)

    # Dependencies
    libraries = list(binary.libraries)

    # Categorized imports
    import_families, total_imports = analyze_imports(binary)

    # Detailed symbols (pyelftools, only if not stripped)
    if not strip_info["stripped"]:
        symbols = analyze_symbols_pyelftools(path)
    else:
        symbols = {
            "total_functions": 0,
            "local_functions": 0,
            "top5_by_size": [],
            "note": "binary is stripped",
        }

    # YARA
    yara_matches = scan_yara(yara_rules, path)

    # Assemble the report
    report = {
        "identification": ident,
        "protections": protections,
        "strip_info": strip_info,
        "sections": {
            "count": len(sections),
            "high_entropy": high_entropy,
            "details": sections,
        },
        "libraries": libraries,
        "imports": {
            "total": total_imports,
            "families": import_families,
        },
        "symbols": symbols,
    }
    if yara_matches is not None:
        report["yara"] = yara_matches

    return report


# ── Consolidated report generation ────────────────────────────

def build_summary(results):
    """Produce a summary table with one line per binary."""
    summary = []
    for r in results:
        if "error" in r:
            summary.append({"name": r.get("path", "?"), "error": r["error"]})
            continue

        ident = r["identification"]
        prot = r["protections"]
        imp = r["imports"]
        families = list(imp["families"].keys())

        entry = {
            "name": ident["name"],
            "arch": ident["arch"],
            "size": ident["size_bytes"],
            "pie": prot["pie"],
            "nx": prot["nx"],
            "canary": prot["canary"],
            "relro": prot["relro"],
            "stripped": r["strip_info"]["stripped"],
            "libraries_count": len(r["libraries"]),
            "imports_total": imp["total"],
            "import_families": families,
            "high_entropy_sections": r["sections"]["high_entropy"],
            "functions_detected": r["symbols"]["total_functions"],
        }
        if "yara" in r:
            entry["yara_matches"] = r["yara"]

        summary.append(entry)

    return summary


def print_summary(summary, file=sys.stderr):
    """Display a human-readable summary on stderr."""
    print("", file=file)
    print(f"{'Binary':<30} {'Arch':<8} {'PIE':>4} {'NX':>3} "
          f"{'Can':>4} {'RELRO':<8} {'Strip':>6} {'Funcs':>6} "
          f"{'Libs':>5} {'Imports':>8}  Flags",
          file=file)
    print("-" * 110, file=file)

    for s in summary:
        if "error" in s:
            print(f"{s['name']:<30} ERROR: {s['error']}", file=file)
            continue

        flags = []
        if s.get("import_families"):
            flags.extend(s["import_families"])
        if s.get("high_entropy_sections"):
            flags.append("HIGH_ENTROPY")
        if s.get("yara_matches"):
            flags.append(f"YARA({len(s['yara_matches'])})")

        pie = "✓" if s["pie"] else "✗"
        nx = "✓" if s["nx"] else "✗"
        can = "✓" if s["canary"] else "✗"
        strip = "✓" if s["stripped"] else "✗"

        print(f"{s['name']:<30} {s['arch']:<8} {pie:>4} {nx:>3} "
              f"{can:>4} {s['relro']:<8} {strip:>6} {s['functions_detected']:>6} "
              f"{s['libraries_count']:>5} {s['imports_total']:>8}  "
              f"{', '.join(flags) if flags else '-'}",
              file=file)

    print("", file=file)
    print(f"Total: {len(summary)} binary(ies) analyzed", file=file)


# ── Entry point ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Automated analysis of a directory of ELF binaries",
        epilog="Chapter 35 — GNU Reverse Engineering Training",
    )
    parser.add_argument(
        "directory",
        help="Directory containing the binaries to analyze",
    )
    parser.add_argument(
        "--output", "-o",
        help="JSON output file (default: stdout)",
        default=None,
    )
    parser.add_argument(
        "--yara-rules",
        help="Directory containing .yar files",
        default=None,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Display progress on stderr",
    )
    args = parser.parse_args()

    # Verify the directory
    target = Path(args.directory)
    if not target.is_dir():
        print(f"ERROR: {target} is not a directory", file=sys.stderr)
        sys.exit(2)

    # Find ELF files
    elfs = find_elfs(target)
    if not elfs:
        print(f"No ELF binaries found in {target}", file=sys.stderr)
        sys.exit(0)

    print(f"[*] {len(elfs)} ELF binary(ies) found in {target}",
          file=sys.stderr)

    # Compile YARA rules (if provided)
    yara_rules = None
    if args.yara_rules:
        if not HAS_YARA:
            print("WARNING: yara-python not installed, "
                  "YARA scan skipped", file=sys.stderr)
        else:
            yara_rules = compile_yara_rules(args.yara_rules)
            if yara_rules:
                print(f"[*] YARA rules compiled from {args.yara_rules}",
                      file=sys.stderr)

    # Analyze each binary
    results = []
    for path in elfs:
        report = analyze_binary(path, yara_rules, args.verbose)
        results.append(report)

    # Build the final report
    summary = build_summary(results)

    final_report = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "directory": str(target.resolve()),
            "binaries_found": len(elfs),
            "yara_rules": args.yara_rules,
        },
        "summary": summary,
        "details": {r["identification"]["name"]: r
                    for r in results if "identification" in r},
    }

    # Display the human-readable summary
    print_summary(summary)

    # Write the JSON
    json_output = json.dumps(final_report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            f.write(json_output)
        print(f"[+] Report written to {args.output}", file=sys.stderr)
    else:
        print(json_output)


if __name__ == "__main__":
    main()
```

## Running on the training binaries

### Minimal scan (without YARA)

```bash
python3 batch_analyze.py binaries/ch21-keygenme/
```

The script detects the five keygenme variants. The stderr summary looks like this:

```
[*] 5 ELF binary(ies) found in binaries/ch21-keygenme/

Binary                         Arch     PIE   NX  Can  RELRO    Strip  Funcs  Libs  Imports  Flags
--------------------------------------------------------------------------------------------------------------
keygenme_O0                    X86_64     ✓    ✓    ✗  partial      ✗     12      1       10  -  
keygenme_O2                    X86_64     ✓    ✓    ✗  partial      ✗      9      1       10  -  
keygenme_O3                    X86_64     ✓    ✓    ✗  partial      ✗      8      1       10  -  
keygenme_O2_strip              X86_64     ✓    ✓    ✗  partial      ✓      0      1       10  -  
keygenme_strip                 X86_64     ✓    ✓    ✗  partial      ✓      0      1       10  -  

Total: 5 binary(ies) analyzed
```

Several actionable observations appear immediately. The `Funcs` column drops from 12 (`_O0`) to 9 (`_O2`) then 8 (`_O3`) — the progressive inlining of functions by the compiler is visible quantitatively. The stripped variants show 0 functions. No variant has a canary (the Makefile does not pass `-fstack-protector`). RELRO is partial (no `-Wl,-z,now`).

### Full scan (with YARA)

```bash
python3 batch_analyze.py binaries/ \
    --yara-rules yara-rules/ \
    --output report.json \
    --verbose
```

The produced JSON report is directly consumable with `jq`:

```bash
# Which binaries have crypto imports?
jq '.summary[] | select(.import_families | index("crypto"))
    | .name' report.json

# Which binaries are stripped AND without canary?
jq '.summary[] | select(.stripped and (.canary | not))
    | {name, relro}' report.json

# Which binaries triggered YARA rules?
jq '.summary[] | select(.yara_matches | length > 0)
    | {name, yara_matches}' report.json

# Sections with high entropy (packing suspicion)?
jq '.summary[] | select(.high_entropy_sections | length > 0)
    | {name, high_entropy_sections}' report.json
```

## Mapping to chapter sections

| Script component | Reference section |  
|---|---|  
| `lief.parse()`, `analyze_protections()`, `analyze_sections()` | 35.1 — `pyelftools` and `lief` |  
| Structured JSON output with `metadata` / `summary` / `details` | 35.2 — Ghidra headless report architecture |  
| `analyze_symbols_pyelftools()`, pattern search in imports | 35.3 — `pwntools` (categorization pattern) |  
| `compile_yara_rules()`, `scan_yara()` | 35.4 — YARA rules |  
| `analyze_protections()` as assertions, implicit whitelist policy | 35.5 — CI/CD pipeline |  
| Separation into reusable functions, optional dependency handling | 35.6 — Building the toolkit |

## Validation criteria

The script is considered functional if it satisfies the following conditions.

**Detection** — it correctly identifies all ELF binaries in a directory and ignores non-ELF files (`.c` sources, Makefiles, `.hexpat` files, `.cfr` archives).

**Protections** — the PIE, NX, canary, RELRO, and stripped values match those reported by `checksec` on the same binaries.

**Sections** — section entropy is consistent (`.text` between 5 and 6.5, `.rodata` between 3 and 5 for a standard non-packed GCC binary).

**Imports** — families are correctly detected: `crypto` present for `crypto_O0` variants, `network` present for Chapter 23 binaries, `dangerous` present if the binary uses `gets` or `strcpy`.

**YARA** — if the `yara-rules/` directory is provided, the `crypto_constants.yar` and `packer_signatures.yar` rules are compiled and applied. Chapter 24 binaries trigger the crypto rules. Chapter 29 binaries (UPX-packed) trigger the packer rules.

**Symbols** — non-stripped variants display a consistent function count (decreasing with optimization level). Stripped variants display zero.

**Output** — the JSON is valid, parsable by `jq`, and contains the three keys `metadata`, `summary`, `details`. The stderr summary is readable and aligned.

---

> ✅ **This checkpoint validates all of Chapter 35.** The `batch_analyze.py` script is the central building block of the automated RE toolkit — it can be extended with new checks, integrated into a CI/CD pipeline, or used as a starting point for deeper analysis with Ghidra headless.

---


⏭️ [Chapter 36 — Resources for Further Learning](/36-resources-further-learning/README.md)
