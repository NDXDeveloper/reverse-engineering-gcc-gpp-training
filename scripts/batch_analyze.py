#!/usr/bin/env python3
"""
batch_analyze.py — Batch binary analysis via Ghidra headless
Reverse Engineering Training — Applications compiled with the GNU toolchain

Python wrapper around `analyzeHeadless` that orchestrates:
  1. Import and auto-analysis of a directory of binaries
  2. Execution of post-analysis Ghidra scripts (function extraction,
     decompilation, crypto constant scanning)
  3. Consolidation of JSON reports produced by the scripts

This script replaces the `batch_ghidra.sh` shell pipeline from section 35.2
with a more portable Python version, easier to integrate into a
CI/CD pipeline (section 35.5).

Prerequisites:
  - Ghidra installed, GHIDRA_HOME variable defined
  - Ghidra scripts in the directory specified by --scripts
  - Java 17+ (required by Ghidra 10+)

Usage:
  python3 batch_analyze.py binaries/ch21-keygenme/
  python3 batch_analyze.py binaries/ --scripts ghidra_scripts/ --output reports/
  python3 batch_analyze.py binaries/ --timeout 300 --max-cpu 4

MIT License — Strictly educational use.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
#  Locating Ghidra
# ═══════════════════════════════════════════════════════════════

def find_headless():
    """Locate the Ghidra analyzeHeadless script."""
    # 1. GHIDRA_HOME environment variable
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
        if candidate.is_file():
            return str(candidate)

    # 2. Alias/command in PATH
    which = shutil.which("analyzeHeadless")
    if which:
        return which

    # 3. Common locations
    for path in [
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/local/ghidra/support/analyzeHeadless",
        Path.home() / "ghidra" / "support" / "analyzeHeadless",
    ]:
        if Path(path).is_file():
            return str(path)

    return None


# ═══════════════════════════════════════════════════════════════
#  ELF detection
# ═══════════════════════════════════════════════════════════════

def find_elfs(directory):
    """Find ELF files in a directory (recursive)."""
    elfs = []
    for path in sorted(Path(directory).rglob("*")):
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as f:
                if f.read(4) == b"\x7fELF":
                    elfs.append(path)
        except (OSError, PermissionError):
            continue
    return elfs


# ═══════════════════════════════════════════════════════════════
#  Running analyzeHeadless
# ═══════════════════════════════════════════════════════════════

def run_headless(headless_path, project_dir, project_name, args_list,
                 env_extra=None, verbose=False):
    """Launch analyzeHeadless with the given arguments.

    Returns (return_code, stdout, stderr).
    """
    cmd = [headless_path, str(project_dir), project_name] + args_list

    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    if verbose:
        print(f"  CMD: {' '.join(cmd[:6])}...", file=sys.stderr)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=3600,  # 1h max global
    )

    return result.returncode, result.stdout, result.stderr


# ═══════════════════════════════════════════════════════════════
#  Pipeline phases
# ═══════════════════════════════════════════════════════════════

def phase_import(headless, project_dir, project_name, binaries_dir,
                 timeout_per_file, max_cpu, verbose):
    """Phase 1: import and auto-analysis of all binaries."""
    print("[*] Phase 1: Import and analysis...", file=sys.stderr)

    args = [
        "-import", str(binaries_dir),
        "-recursive",
        "-overwrite",
        "-analysisTimeoutPerFile", str(timeout_per_file),
    ]
    if max_cpu:
        args += ["-max-cpu", str(max_cpu)]

    code, stdout, stderr = run_headless(
        headless, project_dir, project_name, args, verbose=verbose
    )

    if code != 0:
        print(f"  WARNING: analyzeHeadless returned {code}",
              file=sys.stderr)
        if verbose:
            # Display the last error lines
            for line in stderr.splitlines()[-10:]:
                print(f"    {line}", file=sys.stderr)

    # Count imported binaries (heuristic on the output)
    imported = stdout.count("Import succeeded")
    print(f"  [{imported} binary(ies) imported]", file=sys.stderr)
    return code


def phase_script(headless, project_dir, project_name, script_path,
                 script_args, output_dir, verbose):
    """Phase N: execute a post-analysis script on all binaries."""
    script_name = Path(script_path).name
    print(f"[*] Running {script_name}...", file=sys.stderr)

    args = [
        "-process",           # process all binaries in the project
        "-noanalysis",        # do not re-run auto-analysis
        "-postScript", str(script_path),
    ]
    if script_args:
        args.extend(script_args)

    env_extra = {"GHIDRA_OUTPUT": str(output_dir)}

    code, stdout, stderr = run_headless(
        headless, project_dir, project_name, args,
        env_extra=env_extra, verbose=verbose,
    )

    if code != 0 and verbose:
        for line in stderr.splitlines()[-5:]:
            print(f"    {line}", file=sys.stderr)

    return code


# ═══════════════════════════════════════════════════════════════
#  Report consolidation
# ═══════════════════════════════════════════════════════════════

def merge_reports(output_dir):
    """Merge JSON files produced by Ghidra scripts."""
    report = {}

    for json_path in sorted(Path(output_dir).glob("*.json")):
        try:
            with open(json_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  WARNING: {json_path.name} unreadable ({e})",
                  file=sys.stderr)
            continue

        # Identify report type by its content
        binary_name = data.get("binary", json_path.stem)

        report.setdefault(binary_name, {})

        if "functions" in data:
            report[binary_name]["functions"] = data
        elif "findings" in data:
            report[binary_name]["crypto"] = data
        else:
            # Generic report
            report[binary_name][json_path.stem] = data

    return report


def build_final_report(merged, binaries_dir, output_dir):
    """Build the final consolidated report."""
    summary = []
    for name, data in sorted(merged.items()):
        func_count = data.get("functions", {}).get("count", 0)
        crypto_count = len(data.get("crypto", {}).get("findings", []))
        summary.append({
            "binary":              name,
            "functions_detected":  func_count,
            "crypto_constants":    crypto_count,
        })

    return {
        "metadata": {
            "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "binaries_dir":   str(Path(binaries_dir).resolve()),
            "tool":           "batch_analyze.py (Ghidra headless)",
        },
        "summary": summary,
        "details": merged,
    }


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Batch binary analysis via Ghidra headless",
        epilog="RE Training — Chapter 35",
    )
    parser.add_argument(
        "binaries_dir",
        help="Directory containing the binaries to analyze",
    )
    parser.add_argument(
        "--scripts", "-s",
        help="Directory containing Ghidra scripts "
             "(default: static/ghidra/ or ghidra_scripts/)",
        default=None,
    )
    parser.add_argument(
        "--output", "-o",
        help="Output directory for reports "
             "(default: /tmp/ghidra_batch_output/)",
        default=None,
    )
    parser.add_argument(
        "--timeout", "-t",
        help="Analysis timeout per file in seconds (default: 300)",
        type=int, default=300,
    )
    parser.add_argument(
        "--max-cpu",
        help="Number of threads for analysis (default: auto)",
        type=int, default=None,
    )
    parser.add_argument(
        "--keep-project",
        help="Do not delete the temporary Ghidra project",
        action="store_true",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed progress",
    )
    args = parser.parse_args()

    # ── Checks ──

    headless = find_headless()
    if headless is None:
        print("ERROR: analyzeHeadless not found.", file=sys.stderr)
        print("  Set GHIDRA_HOME or add Ghidra to PATH.",
              file=sys.stderr)
        sys.exit(2)
    print(f"[*] Ghidra headless: {headless}", file=sys.stderr)

    binaries_dir = Path(args.binaries_dir)
    if not binaries_dir.is_dir():
        print(f"ERROR: '{binaries_dir}' is not a directory",
              file=sys.stderr)
        sys.exit(2)

    elfs = find_elfs(binaries_dir)
    if not elfs:
        print(f"No ELF found in {binaries_dir}", file=sys.stderr)
        sys.exit(0)
    print(f"[*] {len(elfs)} ELF binary(ies) detected", file=sys.stderr)

    # ── Ghidra scripts directory ──

    scripts_dir = None
    if args.scripts:
        scripts_dir = Path(args.scripts)
    else:
        # Search in conventional locations
        for candidate in ["static/ghidra", "ghidra_scripts", "scripts/ghidra"]:
            if Path(candidate).is_dir():
                scripts_dir = Path(candidate)
                break

    scripts = []
    if scripts_dir and scripts_dir.is_dir():
        scripts = sorted(scripts_dir.glob("*.py"))
        print(f"[*] {len(scripts)} Ghidra script(s) in {scripts_dir}",
              file=sys.stderr)
    else:
        print("[*] No Ghidra scripts directory found — "
              "import and analysis only", file=sys.stderr)

    # ── Working directories ──

    output_dir = Path(args.output) if args.output else Path(
        tempfile.mkdtemp(prefix="ghidra_batch_output_")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    project_dir = Path(tempfile.mkdtemp(prefix="ghidra_batch_project_"))
    project_name = "batch"

    print(f"[*] Ghidra project: {project_dir}/{project_name}", file=sys.stderr)
    print(f"[*] Output        : {output_dir}", file=sys.stderr)

    # ── Phase 1: Import ──

    phase_import(
        headless, project_dir, project_name,
        binaries_dir, args.timeout, args.max_cpu, args.verbose,
    )

    # ── Phases 2..N: Scripts ──

    for script_path in scripts:
        phase_script(
            headless, project_dir, project_name,
            script_path, [], output_dir, args.verbose,
        )

    # ── Consolidation ──

    print("[*] Consolidating reports...", file=sys.stderr)
    merged = merge_reports(output_dir)
    final = build_final_report(merged, binaries_dir, output_dir)

    report_path = output_dir / "report.json"
    with open(report_path, "w") as f:
        json.dump(final, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # ── Summary ──

    print(f"\n{'='*50}", file=sys.stderr)
    print(f"  Report: {report_path}", file=sys.stderr)
    print(f"  Binaries analyzed: {len(elfs)}", file=sys.stderr)
    for s in final["summary"]:
        flags = []
        if s["crypto_constants"] > 0:
            flags.append(f"CRYPTO({s['crypto_constants']})")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(f"    {s['binary']:<30} "
              f"{s['functions_detected']:>4} functions{flag_str}",
              file=sys.stderr)
    print(f"{'='*50}\n", file=sys.stderr)

    # ── Cleanup ──

    if not args.keep_project:
        shutil.rmtree(project_dir, ignore_errors=True)
        if args.verbose:
            print(f"[*] Temporary project deleted", file=sys.stderr)

    # JSON output on stdout as well
    print(json.dumps(final, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
