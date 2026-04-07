#!/usr/bin/env python3
"""
triage.py — Automatic ELF binary triage
Reverse Engineering Training — Applications compiled with the GNU toolchain

First programmatic contact with an unknown binary.
Combines lief (protections, entropy, imports) and pyelftools (symbols, DWARF)
to produce a structured triage report — the scriptable equivalent of the
manual "first 5 minutes" workflow from chapter 5, section 7.

Usage:
  python3 triage.py <binary>
  python3 triage.py <binary> --json
  python3 triage.py <binary> --json --output report.json

Dependencies:
  pip install lief pyelftools

MIT License — Strictly educational use.
"""

import argparse
import json
import sys
import struct
from pathlib import Path

try:
    import lief
    lief.logging.disable()
except ImportError:
    print("ERROR: lief required (pip install lief)", file=sys.stderr)
    sys.exit(2)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    print("ERROR: pyelftools required (pip install pyelftools)", file=sys.stderr)
    sys.exit(2)


# ═══════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════

# Imports classified by family (same dictionary as the checkpoint)
IMPORT_FAMILIES = {
    "crypto": {
        "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
        "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
        "EVP_CipherInit_ex", "EVP_CIPHER_CTX_new", "EVP_CIPHER_CTX_free",
        "EVP_aes_256_cbc", "EVP_aes_128_cbc", "EVP_aes_256_gcm",
        "SHA256", "SHA256_Init", "SHA256_Update", "SHA256_Final",
        "SHA1", "MD5", "AES_encrypt", "AES_decrypt",
        "RAND_bytes", "RAND_seed",
    },
    "network": {
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "getaddrinfo", "gethostbyname",
    },
    "file_io": {
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "fgets",
        "open", "close", "read", "write", "lseek",
        "stat", "fstat", "mmap", "munmap",
    },
    "dangerous": {
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    },
    "process": {
        "fork", "execve", "execvp", "system", "popen",
        "ptrace", "kill", "signal",
    },
    "dynamic_loading": {
        "dlopen", "dlsym", "dlclose",
    },
}

# Known crypto constants (raw binary search)
CRYPTO_SIGNATURES = {
    "AES S-box (row 0)": bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    "SHA-256 H0 (BE)":   bytes.fromhex("6a09e667"),
    "SHA-256 H0 (LE)":   bytes.fromhex("67e6096a"),
    "SHA-256 K[0] (BE)": bytes.fromhex("428a2f98"),
    "MD5 T[1] (LE)":     bytes.fromhex("78a46ad7"),
    "ChaCha20 sigma":    b"expand 32-byte k",
    # Markers specific to our training binaries
    "CRYPT24 magic":     b"CRYPT24",
    "CFR magic":         b"CFRM",
    "ch24 KEY_MASK":     bytes.fromhex("deadbeefcafebabe"),
    "ch21 HASH_SEED":    struct.pack("<I", 0x5A3C6E2D),
}

# Entropy threshold for alerts
ENTROPY_THRESHOLD = 7.0


# ═══════════════════════════════════════════════════════════════
#  lief analysis
# ═══════════════════════════════════════════════════════════════

def triage_lief(path):
    """Analysis via lief: identification, protections, sections, imports."""
    binary = lief.parse(str(path))
    if binary is None:
        return None

    # ── Identification ──
    ident = {
        "name":        path.name,
        "path":        str(path.resolve()),
        "size_bytes":  path.stat().st_size,
        "arch":        str(binary.header.machine_type).split(".")[-1],
        "type":        str(binary.header.file_type).split(".")[-1],
        "entry_point": f"0x{binary.entrypoint:x}",
    }

    # ── Protections ──
    imports = {s.name for s in binary.imported_symbols if s.name}

    has_relro_seg = any(
        seg.type == lief.ELF.Segment.TYPE.GNU_RELRO
        for seg in binary.segments
    )
    has_bind_now = False
    try:
        for entry in binary.dynamic_entries:
            if entry.tag == lief.ELF.DynamicEntry.TAG.BIND_NOW:
                has_bind_now = True
            if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                if entry.value & 0x08:
                    has_bind_now = True
            if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS_1:
                if entry.value & 0x01:
                    has_bind_now = True
    except Exception:
        pass

    if has_relro_seg and has_bind_now:
        relro = "full"
    elif has_relro_seg:
        relro = "partial"
    else:
        relro = "none"

    protections = {
        "pie":    binary.is_pie,
        "nx":     binary.has_nx,
        "canary": "__stack_chk_fail" in imports,
        "relro":  relro,
    }

    # ── Stripped / DWARF ──
    static_syms = list(binary.static_symbols)
    debug_sections = sorted(
        s.name for s in binary.sections if s.name.startswith(".debug_")
    )
    strip_info = {
        "stripped":              len(static_syms) == 0,
        "static_symbols_count": len(static_syms),
        "has_dwarf":            len(debug_sections) > 0,
        "debug_sections":       debug_sections,
    }

    # ── Sections + entropy ──
    sections = []
    high_entropy = []
    for s in binary.sections:
        if not s.name:
            continue
        ent = round(s.entropy, 2)
        sections.append({
            "name": s.name, "size": s.size, "entropy": ent,
        })
        if ent > ENTROPY_THRESHOLD and s.size > 64:
            high_entropy.append(f"{s.name} (entropy={ent})")

    # ── Libraries ──
    libraries = list(binary.libraries)

    # ── Categorized imports ──
    all_imports = {s.name for s in binary.imported_symbols if s.name}
    import_families = {}
    for family, sigs in IMPORT_FAMILIES.items():
        found = sorted(all_imports & sigs)
        if found:
            import_families[family] = found

    # ── Crypto constant search in raw binary ──
    raw = path.read_bytes()
    crypto_findings = []
    for label, pattern in CRYPTO_SIGNATURES.items():
        offset = raw.find(pattern)
        if offset >= 0:
            crypto_findings.append({
                "label":  label,
                "offset": f"0x{offset:x}",
            })

    # ── Notable strings (extracted from .rodata) ──
    notable_strings = []
    rodata = binary.get_section(".rodata")
    if rodata:
        content = bytes(rodata.content)
        # Simplified extraction: printable ASCII sequences >= 6 characters
        current = []
        for byte in content:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 6:
                    notable_strings.append("".join(current))
                current = []
        if len(current) >= 6:
            notable_strings.append("".join(current))

    return {
        "identification":    ident,
        "protections":       protections,
        "strip_info":        strip_info,
        "sections": {
            "count":         len(sections),
            "high_entropy":  high_entropy,
            "details":       sections,
        },
        "libraries":         libraries,
        "imports": {
            "total":         len(all_imports),
            "families":      import_families,
        },
        "crypto_signatures": crypto_findings,
        "notable_strings":   notable_strings[:50],  # limit volume
    }


# ═══════════════════════════════════════════════════════════════
#  pyelftools analysis (detailed symbols)
# ═══════════════════════════════════════════════════════════════

def triage_pyelftools(path):
    """Analysis via pyelftools: functions, DWARF, NEEDED."""
    result = {
        "functions": [],
        "source_files": [],
    }

    try:
        with open(str(path), "rb") as f:
            elf = ELFFile(f)

            # ── Functions ──
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for sym in section.iter_symbols():
                    if (sym['st_info']['type'] == 'STT_FUNC'
                            and sym['st_value'] != 0
                            and sym['st_size'] > 0):
                        result["functions"].append({
                            "name": sym.name,
                            "addr": f"0x{sym['st_value']:x}",
                            "size": sym['st_size'],
                            "bind": sym['st_info']['bind'],
                        })

            result["functions"].sort(key=lambda fn: fn.get("size", 0),
                                     reverse=True)

            # ── DWARF: source files ──
            if elf.has_dwarf_info():
                dwarf = elf.get_dwarf_info()
                sources = set()
                for cu in dwarf.iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag == 'DW_TAG_compile_unit':
                            name = die.attributes.get('DW_AT_name')
                            if name:
                                sources.add(name.value.decode(errors='replace'))
                result["source_files"] = sorted(sources)

    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════
#  Assembly and display
# ═══════════════════════════════════════════════════════════════

def triage(path):
    """Entry point: complete triage of an ELF binary."""
    path = Path(path)

    if not path.is_file():
        return {"error": f"File not found: {path}"}

    # Check ELF magic
    with open(path, "rb") as f:
        if f.read(4) != b"\x7fELF":
            return {"error": f"Not an ELF file: {path}"}

    report = triage_lief(path)
    if report is None:
        return {"error": f"lief failed to parse: {path}"}

    # Enrich with pyelftools if not stripped
    if not report["strip_info"]["stripped"]:
        pe = triage_pyelftools(path)
        report["symbols"] = {
            "total_functions":  len(pe["functions"]),
            "local_functions":  len([f for f in pe["functions"]
                                     if f["bind"] == "STB_LOCAL"]),
            "global_functions": len([f for f in pe["functions"]
                                     if f["bind"] == "STB_GLOBAL"]),
            "top5_by_size":     pe["functions"][:5],
        }
        report["source_files"] = pe["source_files"]
    else:
        report["symbols"] = {
            "total_functions": 0,
            "note": "binary is stripped",
        }
        report["source_files"] = []

    return report


def print_human_report(report):
    """Display a human-readable report on stderr."""
    if "error" in report:
        print(f"ERROR: {report['error']}", file=sys.stderr)
        return

    ident = report["identification"]
    prot = report["protections"]
    strip = report["strip_info"]

    def tick(val):
        return "✓" if val else "✗"

    print(f"\n{'═' * 60}", file=sys.stderr)
    print(f"  TRIAGE — {ident['name']}", file=sys.stderr)
    print(f"{'═' * 60}\n", file=sys.stderr)

    print(f"  Path       : {ident['path']}", file=sys.stderr)
    print(f"  Size       : {ident['size_bytes']:,} bytes", file=sys.stderr)
    print(f"  Arch       : {ident['arch']}", file=sys.stderr)
    print(f"  Type       : {ident['type']}", file=sys.stderr)
    print(f"  Entry      : {ident['entry_point']}", file=sys.stderr)

    print(f"\n  Protections:", file=sys.stderr)
    print(f"    PIE      : {tick(prot['pie'])}", file=sys.stderr)
    print(f"    NX       : {tick(prot['nx'])}", file=sys.stderr)
    print(f"    Canary   : {tick(prot['canary'])}", file=sys.stderr)
    print(f"    RELRO    : {prot['relro']}", file=sys.stderr)
    print(f"    Stripped : {tick(strip['stripped'])}", file=sys.stderr)
    print(f"    DWARF    : {tick(strip['has_dwarf'])}", file=sys.stderr)

    # Libraries
    libs = report["libraries"]
    print(f"\n  Libraries ({len(libs)}):", file=sys.stderr)
    for lib in libs:
        print(f"    - {lib}", file=sys.stderr)

    # Imports
    imp = report["imports"]
    print(f"\n  Imports ({imp['total']} total):", file=sys.stderr)
    for family, funcs in imp["families"].items():
        print(f"    [{family}] {', '.join(funcs)}", file=sys.stderr)

    # Symbols
    sym = report.get("symbols", {})
    if sym.get("total_functions", 0) > 0:
        print(f"\n  Functions ({sym['total_functions']} total, "
              f"{sym['local_functions']} local, "
              f"{sym['global_functions']} global):", file=sys.stderr)
        print(f"    Top 5 by size:", file=sys.stderr)
        for fn in sym.get("top5_by_size", []):
            print(f"      {fn['addr']}  {fn['size']:>5}B  {fn['name']}",
                  file=sys.stderr)

    # DWARF sources
    sources = report.get("source_files", [])
    if sources:
        print(f"\n  Source files (DWARF):", file=sys.stderr)
        for src in sources:
            print(f"    - {src}", file=sys.stderr)

    # Crypto constants
    crypto = report.get("crypto_signatures", [])
    if crypto:
        print(f"\n  Crypto constants detected:", file=sys.stderr)
        for c in crypto:
            print(f"    - {c['label']} @ {c['offset']}", file=sys.stderr)

    # High entropy sections
    high_ent = report["sections"]["high_entropy"]
    if high_ent:
        print(f"\n  Warning: high entropy sections:", file=sys.stderr)
        for s in high_ent:
            print(f"    - {s}", file=sys.stderr)

    # Notable strings (first 10)
    strings = report.get("notable_strings", [])
    if strings:
        print(f"\n  Notable strings ({len(strings)} found, "
              f"first 10):", file=sys.stderr)
        for s in strings[:10]:
            display = s if len(s) <= 70 else s[:67] + "..."
            print(f"    \"{display}\"", file=sys.stderr)

    print(f"\n{'═' * 60}\n", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Automatic ELF binary triage",
        epilog="RE Training — Chapter 35",
    )
    parser.add_argument("binary", help="Path to the binary to analyze")
    parser.add_argument("--json", action="store_true",
                        help="JSON output on stdout (default: human on stderr)")
    parser.add_argument("--output", "-o",
                        help="JSON output file")
    args = parser.parse_args()

    report = triage(args.binary)

    # Always display human report on stderr
    print_human_report(report)

    # JSON output if requested
    if args.json or args.output:
        json_str = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w") as f:
                f.write(json_str + "\n")
            print(f"[+] JSON → {args.output}", file=sys.stderr)
        else:
            print(json_str)

    # Return code
    sys.exit(2 if "error" in report else 0)


if __name__ == "__main__":
    main()
