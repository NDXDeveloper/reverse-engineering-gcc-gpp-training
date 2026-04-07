#!/usr/bin/env python3
"""
ch35-checkpoint-batch.py — Chapter 35 Checkpoint Solution
Reverse Engineering Training — Applications compiled with the GNU toolchain

Automatic analysis of a directory of ELF binaries.
Produces a consolidated JSON report covering:
  - Identification (name, size, arch, type, entry point)
  - Protections  (PIE, NX, canary, RELRO, stripped, DWARF)
  - Sections     (name, size, entropy, alerts > 7.0)
  - Dependencies  (dynamic NEEDED libraries)
  - Imports      (categorized: crypto, network, file, dangerous)
  - Symbols      (count, top 5 by size — if not stripped)
  - YARA         (optional scan with provided rules)

Usage :
  python3 ch35-checkpoint-batch.py binaries/
  python3 ch35-checkpoint-batch.py binaries/ --yara-rules yara-rules/ -o report.json
  python3 ch35-checkpoint-batch.py binaries/ch21-keygenme/ -v
  python3 ch35-checkpoint-batch.py binaries/ -o report.json && jq '.summary[]' report.json

Dependencies:
  pip install lief pyelftools          # required
  pip install yara-python              # optional (YARA scan)

MIT License — Strictly educational use.
"""

# ═══════════════════════════════════════════════════════════════
#  Imports
# ═══════════════════════════════════════════════════════════════

import argparse
import json
import sys
import time
from pathlib import Path

try:
    import lief
    # Disable lief logs on stderr (too verbose on exotic binaries)
    lief.logging.disable()
except ImportError:
    print("ERROR: lief is required (pip install lief)", file=sys.stderr)
    sys.exit(2)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("ERROR: pyelftools is required (pip install pyelftools)",
          file=sys.stderr)
    sys.exit(2)

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


# ═══════════════════════════════════════════════════════════════
#  Constants: notable import families
# ═══════════════════════════════════════════════════════════════

IMPORT_FAMILIES = {
    "crypto": {
        # OpenSSL EVP (symmetric encryption)
        "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
        "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
        "EVP_CipherInit_ex", "EVP_CIPHER_CTX_new", "EVP_CIPHER_CTX_free",
        "EVP_aes_256_cbc", "EVP_aes_128_cbc", "EVP_aes_256_gcm",
        # OpenSSL hash
        "SHA256", "SHA256_Init", "SHA256_Update", "SHA256_Final",
        "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
        "MD5", "MD5_Init", "MD5_Update", "MD5_Final",
        # OpenSSL AES bas niveau
        "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key",
        "AES_set_decrypt_key",
        # OpenSSL random
        "RAND_bytes", "RAND_seed", "RAND_poll",
        # libsodium (common in modern binaries)
        "crypto_secretbox_open_easy", "crypto_secretbox_easy",
        "crypto_box_seal", "crypto_aead_xchacha20poly1305_ietf_encrypt",
    },
    "network": {
        "socket", "connect", "bind", "listen", "accept", "accept4",
        "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "getaddrinfo", "gethostbyname", "gethostbyname_r",
        "inet_pton", "inet_ntop", "inet_addr",
        "select", "poll", "epoll_create", "epoll_create1",
        "epoll_ctl", "epoll_wait",
        "shutdown", "setsockopt", "getsockopt",
    },
    "file_io": {
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
        "fgets", "fputs", "fprintf",
        "open", "close", "read", "write", "lseek",
        "stat", "fstat", "lstat",
        "opendir", "readdir", "closedir",
        "rename", "unlink", "remove", "mkdir", "rmdir",
        "mmap", "munmap", "mprotect",
    },
    "dangerous": {
        "gets",           # unbounded read (never acceptable)
        "strcpy",         # copy without bounds
        "strcat",         # unbounded concatenation
        "sprintf",        # formatting without size limit
        "vsprintf",       # same, va_list variant
    },
    "process": {
        "fork", "execve", "execvp", "system", "popen", "pclose",
        "waitpid", "wait", "kill", "signal", "sigaction",
        "ptrace",         # often anti-debug (ch19)
    },
    "dynamic_loading": {
        "dlopen", "dlsym", "dlclose", "dlerror",
    },
}


# ═══════════════════════════════════════════════════════════════
#  ELF File Detection
# ═══════════════════════════════════════════════════════════════

ELF_MAGIC = b"\x7fELF"


def is_elf(path):
    """Checks that a file starts with the ELF magic."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except (OSError, PermissionError):
        return False


def find_elfs(directory):
    """Recursively traverses a directory and returns ELF paths."""
    elfs = []
    for path in sorted(Path(directory).rglob("*")):
        if path.is_file() and is_elf(path):
            elfs.append(path)
    return elfs


# ═══════════════════════════════════════════════════════════════
#  Analysis with lief
# ═══════════════════════════════════════════════════════════════

def analyze_identification(binary, path):
    """Basic identification properties."""
    return {
        "name": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "arch": str(binary.header.machine_type).split(".")[-1],
        "type": str(binary.header.file_type).split(".")[-1],
        "entry_point": f"0x{binary.entrypoint:x}",
        "endianness": "little" if binary.abstract.header.is_32 is not None
                      else "unknown",
    }


def analyze_protections(binary):
    """Detects PIE, NX, stack canary, RELRO."""
    imports = {s.name for s in binary.imported_symbols if s.name}

    # ── RELRO ──
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
                if entry.value & 0x08:  # DF_BIND_NOW
                    has_bind_now = True
            if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS_1:
                if entry.value & 0x01:  # DF_1_NOW
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


def analyze_stripped(binary):
    """Determines if the binary is stripped and if it contains DWARF."""
    static_syms = list(binary.static_symbols)
    has_symtab = len(static_syms) > 0
    debug_sections = sorted(
        s.name for s in binary.sections if s.name.startswith(".debug_")
    )
    return {
        "stripped": not has_symtab,
        "static_symbols_count": len(static_syms),
        "has_dwarf": len(debug_sections) > 0,
        "debug_sections": debug_sections,
    }


def analyze_sections(binary):
    """Lists sections with size and entropy."""
    ENTROPY_THRESHOLD = 7.0
    MIN_SIZE_FOR_ALERT = 64  # ignore micro-sections

    sections = []
    high_entropy = []

    for s in binary.sections:
        if not s.name:
            continue
        ent = round(s.entropy, 2)
        sections.append({
            "name": s.name,
            "size": s.size,
            "entropy": ent,
        })
        if ent > ENTROPY_THRESHOLD and s.size > MIN_SIZE_FOR_ALERT:
            high_entropy.append(f"{s.name} (entropy={ent})")

    return sections, high_entropy


def analyze_libraries(binary):
    """Lists dynamic libraries (NEEDED)."""
    return list(binary.libraries)


def analyze_imports(binary):
    """Categorizes imports by family."""
    all_imports = {s.name for s in binary.imported_symbols if s.name}
    categorized = {}

    for family, signatures in IMPORT_FAMILIES.items():
        found = sorted(all_imports & signatures)
        if found:
            categorized[family] = found

    # Uncategorized imports (for information)
    categorized_set = set()
    for fns in categorized.values():
        categorized_set.update(fns)
    uncategorized_count = len(all_imports - categorized_set)

    return categorized, len(all_imports), uncategorized_count


# ═══════════════════════════════════════════════════════════════
#  Symbol analysis with pyelftools
# ═══════════════════════════════════════════════════════════════

def analyze_symbols_pyelftools(path):
    """Extracts functions and returns a summary (top 5 by size)."""
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
        return {
            "total_functions": 0,
            "local_functions": 0,
            "global_functions": 0,
            "top5_by_size": [],
            "note": "pyelftools parse error",
        }

    local = [fn for fn in functions if fn["bind"] == "STB_LOCAL"]
    glob = [fn for fn in functions if fn["bind"] == "STB_GLOBAL"]
    by_size = sorted(functions, key=lambda fn: fn["size"], reverse=True)
    top5 = [{"name": fn["name"], "size": fn["size"], "addr": fn["addr"]}
            for fn in by_size[:5]]

    return {
        "total_functions": len(functions),
        "local_functions": len(local),
        "global_functions": len(glob),
        "top5_by_size": top5,
    }


# ═══════════════════════════════════════════════════════════════
#  Scan YARA
# ═══════════════════════════════════════════════════════════════

def compile_yara_rules(rules_dir):
    """Compiles all .yar files from a directory."""
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
        print(f"YARA WARNING : {e}", file=sys.stderr)
        return None


def scan_yara(rules, path):
    """Scans a binary with the compiled rules."""
    if rules is None:
        return None
    try:
        matches = rules.match(str(path))
        return sorted(m.rule for m in matches)
    except yara.Error:
        return []


# ═══════════════════════════════════════════════════════════════
#  Complete Analysis of a Binary
# ═══════════════════════════════════════════════════════════════

def analyze_binary(path, yara_rules=None, verbose=False):
    """Entry point: complete analysis of an ELF binary.

    Returns a JSON-serializable dict containing all information
    collected, or an error dict if parsing fails.
    """
    if verbose:
        print(f"  → {path.name} ...", file=sys.stderr, end="", flush=True)

    binary = lief.parse(str(path))
    if binary is None:
        if verbose:
            print(" ERROR (lief)", file=sys.stderr)
        return {"path": str(path), "error": "lief parse failed"}

    # ── Collection ──

    ident = analyze_identification(binary, path)
    protections = analyze_protections(binary)
    strip_info = analyze_stripped(binary)
    sections, high_entropy = analyze_sections(binary)
    libraries = analyze_libraries(binary)
    import_families, total_imports, uncat_imports = analyze_imports(binary)

    if not strip_info["stripped"]:
        symbols = analyze_symbols_pyelftools(path)
    else:
        symbols = {
            "total_functions": 0,
            "local_functions": 0,
            "global_functions": 0,
            "top5_by_size": [],
            "note": "binary is stripped — no .symtab available",
        }

    yara_matches = scan_yara(yara_rules, path)

    # ── Assembly ──

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
            "uncategorized": uncat_imports,
            "families": import_families,
        },
        "symbols": symbols,
    }

    if yara_matches is not None:
        report["yara"] = yara_matches

    if verbose:
        flags = list(import_families.keys())
        if yara_matches:
            flags.append(f"YARA:{len(yara_matches)}")
        print(f" OK [{', '.join(flags) or '-'}]", file=sys.stderr)

    return report


# ═══════════════════════════════════════════════════════════════
#  Consolidated Report
# ═══════════════════════════════════════════════════════════════

def build_summary(results):
    """Produces a summary table (one line per binary)."""
    summary = []

    for r in results:
        if "error" in r:
            summary.append({
                "name": Path(r.get("path", "?")).name,
                "error": r["error"],
            })
            continue

        ident = r["identification"]
        prot = r["protections"]
        imp = r["imports"]

        entry = {
            "name":                   ident["name"],
            "arch":                   ident["arch"],
            "size_bytes":             ident["size_bytes"],
            "pie":                    prot["pie"],
            "nx":                     prot["nx"],
            "canary":                 prot["canary"],
            "relro":                  prot["relro"],
            "stripped":               r["strip_info"]["stripped"],
            "has_dwarf":              r["strip_info"]["has_dwarf"],
            "libraries_count":        len(r["libraries"]),
            "imports_total":          imp["total"],
            "import_families":        sorted(imp["families"].keys()),
            "high_entropy_sections":  r["sections"]["high_entropy"],
            "functions_detected":     r["symbols"]["total_functions"],
        }

        if "yara" in r:
            entry["yara_matches"] = r["yara"]

        summary.append(entry)

    return summary


def print_human_summary(summary, file=sys.stderr):
    """Displays an aligned human-readable table."""
    # ── Header ──
    print("", file=file)
    hdr = (f"{'Binary':<30} {'Arch':<8} {'PIE':>4} {'NX':>3} "
           f"{'Can':>4} {'RELRO':<8} {'Strip':>6} {'DWARF':>6} "
           f"{'Funcs':>6} {'Libs':>5} {'Imp':>5}  Flags")
    print(hdr, file=file)
    print("─" * len(hdr), file=file)

    # ── Rows ──
    for s in summary:
        if "error" in s:
            print(f"{s['name']:<30} ERROR: {s['error']}", file=file)
            continue

        def tick(val):
            return "✓" if val else "✗"

        flags = []
        if s.get("import_families"):
            flags.extend(s["import_families"])
        if s.get("high_entropy_sections"):
            flags.append("HIGH_ENTROPY")
        if s.get("yara_matches"):
            flags.append(f"YARA({len(s['yara_matches'])})")

        line = (f"{s['name']:<30} {s['arch']:<8} "
                f"{tick(s['pie']):>4} {tick(s['nx']):>3} "
                f"{tick(s['canary']):>4} {s['relro']:<8} "
                f"{tick(s['stripped']):>6} {tick(s['has_dwarf']):>6} "
                f"{s['functions_detected']:>6} {s['libraries_count']:>5} "
                f"{s['imports_total']:>5}  "
                f"{', '.join(flags) if flags else '—'}")
        print(line, file=file)

    # ── Footer ──
    total = len(summary)
    errors = sum(1 for s in summary if "error" in s)
    print("", file=file)
    print(f"Total: {total} binary(ies) analyzed", file=file, end="")
    if errors:
        print(f" ({errors} error(s))", file=file)
    else:
        print("", file=file)


# ═══════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════

def main():
    # ── Arguments ──
    parser = argparse.ArgumentParser(
        description="Automatic analysis of a directory of ELF binaries",
        epilog="Chapter 35 — Reverse Engineering Training GNU",
    )
    parser.add_argument(
        "directory",
        help="Directory containing binaries to analyze",
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

    # ── Validation ──
    target = Path(args.directory)
    if not target.is_dir():
        print(f"ERROR: '{target}' is not a directory", file=sys.stderr)
        sys.exit(2)

    # ── Discovery ──
    elfs = find_elfs(target)
    if not elfs:
        print(f"No ELF binary found in {target}", file=sys.stderr)
        sys.exit(0)

    print(f"[*] {len(elfs)} ELF binary(ies) detected in {target}",
          file=sys.stderr)

    # ── YARA (optional) ──
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
            else:
                print(f"WARNING: no .yar rules found in "
                      f"{args.yara_rules}", file=sys.stderr)

    # ── Analysis ──
    if args.verbose:
        print("[*] Analysis in progress:", file=sys.stderr)

    results = []
    for path in elfs:
        report = analyze_binary(path, yara_rules, args.verbose)
        results.append(report)

    # ── Rapport ──
    summary = build_summary(results)

    final_report = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "directory": str(target.resolve()),
            "binaries_found": len(elfs),
            "yara_rules_dir": args.yara_rules,
            "tool": "ch35-checkpoint-batch.py",
        },
        "summary": summary,
        "details": {
            r["identification"]["name"]: r
            for r in results
            if "identification" in r
        },
    }

    # ── Human display (stderr) ──
    print_human_summary(summary)

    # ── JSON output ──
    json_output = json.dumps(final_report, indent=2, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(json_output)
            f.write("\n")
        print(f"[+] JSON report written to {args.output}", file=sys.stderr)
    else:
        print(json_output)

    sys.exit(0)


if __name__ == "__main__":
    main()
