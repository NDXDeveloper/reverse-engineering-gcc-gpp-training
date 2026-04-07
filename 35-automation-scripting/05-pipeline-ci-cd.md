🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 35.5 — Integration into a CI/CD Pipeline for Binary Regression Auditing

> 🔧 **Tools covered**: GitHub Actions, shell scripts, `lief`, `yara-python`, `readelf`, `checksec`  
> 📁 **Reference files**: `check_env.sh`, `yara-rules/*.yar`, `scripts/triage.py`  
> 🎯 **Objective**: automatically detect, at each commit, security regressions and anomalies in binaries produced by a project

---

## Why audit binaries in a pipeline

Throughout this training, we have analyzed binaries *after* their production — in the posture of a reverse engineer, facing an unknown artifact. This section reverses the perspective: we place ourselves on the side of the developer or security engineer who *produces* the binaries, and we integrate RE tools into the build process to detect problems *before* an external analyst finds them.

Binary regressions are unintended changes in a binary's properties between two versions. They go unnoticed in standard functional tests because the program works correctly — it is its security posture or attack surface that has changed. A few concrete examples drawn from real-world situations:

A developer temporarily disables `-fstack-protector` to debug an obscure crash, forgets to re-enable it, and the production binary loses its stack canaries. Unit tests pass. The binary is deployed. Six months later, an auditor discovers the missing protection.

A build chain update switches from Full RELRO to Partial RELRO without anyone noticing — the GOT table becomes writable again, opening the door to GOT overwrite attacks.

A release binary is shipped with debug symbols (`-g`) and without stripping, exposing internal function names, source file paths, and variable names to adversarial analysts.

A dependency is added (`libcrypto`, `libcurl`) without the security team being informed — the binary gains additional attack surface.

All of these cases are automatically detectable with the tools covered in this chapter. The idea is to transform manual checks into assertions executed at every build, exactly as is done for unit tests.

---

## Pipeline architecture

The binary audit pipeline is inserted after the compilation step and before the deployment step. It does not replace functional tests — it complements them with checks specific to binary properties.

```
   ┌───────────┐     ┌──────────┐     ┌────────────────┐     ┌──────────┐
   │  Source   │────▶│  Build   │────▶│ Binary audit   │────▶│  Deploy  │
   │  (git)    │     │  (make)  │     │  (CI stage)    │     │          │
   └───────────┘     └──────────┘     └────────────────┘     └──────────┘
                                             │
                                      ┌──────┴──────┐
                                      │   Verify    │
                                      │  - checksec │
                                      │  - symbols  │
                                      │  - deps     │
                                      │  - YARA     │
                                      │  - size     │
                                      │  - entropy  │
                                      └─────────────┘
```

The audit stage produces a JSON report and a return code: 0 if all checks pass, non-zero if a regression is detected. The pipeline can then block deployment or simply issue a warning, depending on the team's policy.

---

## The audit script: `audit_binary.py`

The core of the pipeline is a single Python script that takes a binary as input, runs all checks, and produces a structured report. It combines `lief` (section 35.1), `yara-python` (section 35.4), and shell calls for tools that lack Python bindings.

```python
#!/usr/bin/env python3
"""
audit_binary.py — Automated security audit of an ELF binary

Checks:
  1. Compilation protections (PIE, NX, canary, RELRO)
  2. Presence/absence of debug symbols
  3. Dynamic dependencies (new libs, sensitive libs)
  4. YARA scan (crypto constants, packer signatures)
  5. Section entropy (packing detection)
  6. Binary size (bloat detection)

Usage:
  python3 audit_binary.py <binary> [--policy policy.json] [--output report.json]

Return code:
  0 = all checks pass
  1 = at least one FAIL
  2 = execution error
"""

import argparse  
import json  
import sys  
import subprocess  
from pathlib import Path  

try:
    import lief
except ImportError:
    print("ERROR: lief required (pip install lief)", file=sys.stderr)
    sys.exit(2)

try:
    import yara
except ImportError:
    yara = None  # YARA optional, YARA checks will be skipped


# ── Default policy ───────────────────────────────────────────

DEFAULT_POLICY = {
    "require_pie":           True,
    "require_nx":            True,
    "require_canary":        True,
    "require_relro":         "full",     # "full", "partial", "none"
    "require_stripped":      True,
    "forbid_debug_symbols":  True,
    "max_size_bytes":        10_000_000,  # 10 MB
    "entropy_threshold":     7.2,         # above = packing suspicion
    "allowed_libraries":     [],          # empty = no restriction
    "forbidden_libraries":   [],          # e.g.: ["libasan.so"]
    "yara_rules_dir":        None,        # path to .yar files
}


# ── Individual checks ────────────────────────────────────────

def check_protections(binary, policy):
    """Check PIE, NX, canary, RELRO."""
    results = []

    # PIE
    if policy["require_pie"]:
        ok = binary.is_pie
        results.append({
            "check": "PIE",
            "status": "PASS" if ok else "FAIL",
            "detail": f"is_pie={binary.is_pie}",
        })

    # NX (No-Execute)
    if policy["require_nx"]:
        ok = binary.has_nx
        results.append({
            "check": "NX",
            "status": "PASS" if ok else "FAIL",
            "detail": f"has_nx={binary.has_nx}",
        })

    # Stack canary (detected via __stack_chk_fail import)
    if policy["require_canary"]:
        imports = {s.name for s in binary.imported_symbols if s.name}
        has_canary = "__stack_chk_fail" in imports
        results.append({
            "check": "Stack canary",
            "status": "PASS" if has_canary else "FAIL",
            "detail": f"__stack_chk_fail imported: {has_canary}",
        })

    # RELRO
    required = policy["require_relro"]
    if required != "none":
        has_relro = False
        has_bind_now = False
        for seg in binary.segments:
            if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
                has_relro = True
        # Look for BIND_NOW in .dynamic
        try:
            for entry in binary.dynamic_entries:
                if entry.tag == lief.ELF.DynamicEntry.TAG.BIND_NOW:
                    has_bind_now = True
                if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                    if entry.value & 0x08:  # DF_BIND_NOW
                        has_bind_now = True
        except Exception:
            pass

        if required == "full":
            ok = has_relro and has_bind_now
            detail = f"GNU_RELRO={has_relro}, BIND_NOW={has_bind_now}"
        else:  # partial
            ok = has_relro
            detail = f"GNU_RELRO={has_relro}"

        results.append({
            "check": f"RELRO ({required})",
            "status": "PASS" if ok else "FAIL",
            "detail": detail,
        })

    return results


def check_symbols(binary, policy):
    """Check presence/absence of symbols and debug info."""
    results = []

    static_syms = list(binary.static_symbols)
    has_symtab = len(static_syms) > 0

    # Debug sections
    debug_sections = [s.name for s in binary.sections
                      if s.name.startswith(".debug_")]

    if policy["require_stripped"]:
        results.append({
            "check": "Stripped (.symtab)",
            "status": "FAIL" if has_symtab else "PASS",
            "detail": f"{len(static_syms)} static symbols found",
        })

    if policy["forbid_debug_symbols"]:
        ok = len(debug_sections) == 0
        results.append({
            "check": "No debug sections",
            "status": "PASS" if ok else "FAIL",
            "detail": f"debug sections: {debug_sections}" if debug_sections
                      else "none",
        })

    return results


def check_libraries(binary, policy):
    """Check dynamic dependencies."""
    results = []
    libs = list(binary.libraries)

    # Forbidden libraries (e.g.: libasan = sanitizer left in production)
    forbidden = policy.get("forbidden_libraries", [])
    found_forbidden = [lib for lib in libs
                       if any(f in lib for f in forbidden)]
    if forbidden:
        results.append({
            "check": "No forbidden libraries",
            "status": "FAIL" if found_forbidden else "PASS",
            "detail": f"forbidden found: {found_forbidden}" if found_forbidden
                      else f"libs: {libs}",
        })

    # Allowed libraries (strict whitelist)
    allowed = policy.get("allowed_libraries", [])
    if allowed:
        unexpected = [lib for lib in libs
                      if not any(a in lib for a in allowed)]
        results.append({
            "check": "Only allowed libraries",
            "status": "FAIL" if unexpected else "PASS",
            "detail": f"unexpected: {unexpected}" if unexpected
                      else f"libs: {libs}",
        })

    # Always list dependencies in the report (informational)
    results.append({
        "check": "Library inventory",
        "status": "INFO",
        "detail": f"{len(libs)} libraries: {libs}",
    })

    return results


def check_entropy(binary, policy):
    """Detect sections with abnormally high entropy."""
    results = []
    threshold = policy["entropy_threshold"]
    high_entropy = []

    for section in binary.sections:
        if section.size == 0:
            continue
        e = section.entropy
        if e > threshold:
            high_entropy.append(f"{section.name} ({e:.2f})")

    results.append({
        "check": f"Entropy < {threshold}",
        "status": "FAIL" if high_entropy else "PASS",
        "detail": f"high entropy: {high_entropy}" if high_entropy
                  else "all sections normal",
    })

    return results


def check_size(binary_path, policy):
    """Check that the binary size stays within limits."""
    max_size = policy["max_size_bytes"]
    actual = Path(binary_path).stat().st_size

    return [{
        "check": f"Size < {max_size // 1_000_000}MB",
        "status": "FAIL" if actual > max_size else "PASS",
        "detail": f"{actual:,} bytes",
    }]


def check_yara(binary_path, policy):
    """Run YARA rules if configured."""
    rules_dir = policy.get("yara_rules_dir")
    if not rules_dir or yara is None:
        return []

    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        return [{"check": "YARA scan", "status": "SKIP",
                 "detail": f"rules dir not found: {rules_dir}"}]

    rule_files = {}
    for i, path in enumerate(sorted(rules_dir.glob("*.yar"))):
        rule_files[f"ns_{i}"] = str(path)

    if not rule_files:
        return [{"check": "YARA scan", "status": "SKIP",
                 "detail": "no .yar files found"}]

    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(str(binary_path))
    except yara.Error as e:
        return [{"check": "YARA scan", "status": "ERROR",
                 "detail": str(e)}]

    match_names = [m.rule for m in matches]
    return [{
        "check": "YARA scan",
        "status": "INFO",
        "detail": f"{len(match_names)} matches: {match_names}"
                  if match_names else "no matches",
    }]


# ── Orchestration ────────────────────────────────────────────

def audit(binary_path, policy):
    """Run all checks and return the report."""
    binary = lief.parse(str(binary_path))
    if binary is None:
        return {"error": f"Cannot parse {binary_path}"}, 2

    results = []
    results.extend(check_protections(binary, policy))
    results.extend(check_symbols(binary, policy))
    results.extend(check_libraries(binary, policy))
    results.extend(check_entropy(binary, policy))
    results.extend(check_size(binary_path, policy))
    results.extend(check_yara(binary_path, policy))

    fails = [r for r in results if r["status"] == "FAIL"]

    report = {
        "binary": str(binary_path),
        "total_checks": len([r for r in results if r["status"] != "INFO"]),
        "passed": len([r for r in results if r["status"] == "PASS"]),
        "failed": len(fails),
        "results": results,
    }

    exit_code = 1 if fails else 0
    return report, exit_code


# ── Entry point ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ELF binary audit")
    parser.add_argument("binary", help="Path to the binary to audit")
    parser.add_argument("--policy", help="JSON policy file",
                        default=None)
    parser.add_argument("--output", help="JSON output file",
                        default=None)
    args = parser.parse_args()

    # Load policy
    policy = dict(DEFAULT_POLICY)
    if args.policy:
        with open(args.policy) as f:
            overrides = json.load(f)
        policy.update(overrides)

    # Run audit
    report, code = audit(args.binary, policy)

    # Console output
    if "error" in report:
        print(f"ERROR: {report['error']}", file=sys.stderr)
    else:
        for r in report["results"]:
            icon = {"PASS": "✅", "FAIL": "❌", "INFO": "ℹ️",
                    "SKIP": "⏭️", "ERROR": "⚠️"}.get(r["status"], "?")
            print(f"  {icon} {r['check']:<30} {r['detail']}")
        print()
        print(f"  Result: {report['passed']}/{report['total_checks']} "
              f"checks passed"
              + (f" — {report['failed']} FAIL(s)" if report['failed'] else ""))

    # JSON output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

    sys.exit(code)
```

### Policy file

The audit policy is externalized in a JSON file, which allows adapting the rules without modifying the script. Each project can have its own policy:

```json
{
    "require_pie": true,
    "require_nx": true,
    "require_canary": true,
    "require_relro": "full",
    "require_stripped": true,
    "forbid_debug_symbols": true,
    "max_size_bytes": 5000000,
    "entropy_threshold": 7.2,
    "forbidden_libraries": [
        "libasan.so",
        "libtsan.so",
        "libubsan.so",
        "libmsan.so"
    ],
    "allowed_libraries": [
        "libc.so",
        "libpthread.so",
        "libm.so",
        "libdl.so",
        "librt.so",
        "ld-linux"
    ],
    "yara_rules_dir": "yara-rules/"
}
```

The four forbidden libraries (`libasan`, `libtsan`, `libubsan`, `libmsan`) are the GCC/Clang sanitizers — compiled with `-fsanitize=address|thread|undefined|memory`. Their presence in a production binary is a reliable indicator of poor build hygiene. The `allowed_libraries` whitelist restricts dependencies to a minimal core; any unlisted library will trigger a FAIL. For a binary like `crypto_O0` that depends on `libcrypto.so`, you would need to add `libcrypto.so` to the whitelist in the project's policy.

---

## GitHub Actions pipeline

The audit script integrates into a GitHub Actions workflow that triggers on every push or pull request.

```yaml
# .github/workflows/binary-audit.yml
name: Binary Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build-and-audit:
    runs-on: ubuntu-latest

    steps:
      # ── Code checkout ────────────────────────────────────
      - name: Checkout
        uses: actions/checkout@v4

      # ── Dependency installation ──────────────────────────
      - name: Install system dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc g++ make libssl-dev yara
          # checksec (bash script)
          wget -q https://raw.githubusercontent.com/slimm609/checksec.sh/main/checksec \
               -O /usr/local/bin/checksec
          chmod +x /usr/local/bin/checksec

      - name: Install Python dependencies
        run: |
          pip install lief yara-python

      # ── Binary compilation ───────────────────────────────
      - name: Build all binaries
        run: |
          cd binaries && make all

      # ── Audit of each target binary ──────────────────────
      - name: Audit keygenme (release variant)
        run: |
          python3 scripts/audit_binary.py \
              binaries/ch21-keygenme/keygenme_O2_strip \
              --policy policies/keygenme_policy.json \
              --output reports/keygenme_audit.json

      - name: Audit crypto (release variant)
        run: |
          python3 scripts/audit_binary.py \
              binaries/ch24-crypto/crypto_O2_strip \
              --policy policies/crypto_policy.json \
              --output reports/crypto_audit.json

      - name: Audit fileformat (release variant)
        run: |
          python3 scripts/audit_binary.py \
              binaries/ch25-fileformat/fileformat_O2_strip \
              --policy policies/default_policy.json \
              --output reports/fileformat_audit.json

      # ── Global YARA scan ─────────────────────────────────
      - name: YARA scan (all binaries)
        run: |
          yara -r yara-rules/crypto_constants.yar binaries/ > reports/yara_crypto.txt || true
          yara -r yara-rules/packer_signatures.yar binaries/ > reports/yara_packers.txt || true
          echo "=== Crypto constants ===" && cat reports/yara_crypto.txt
          echo "=== Packer signatures ===" && cat reports/yara_packers.txt

      # ── Report publication ───────────────────────────────
      - name: Upload audit reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: binary-audit-reports
          path: reports/
          retention-days: 30

      # ── checksec verification (informational) ────────────
      - name: checksec summary
        if: always()
        run: |
          echo "=== checksec — keygenme variants ==="
          for bin in binaries/ch21-keygenme/keygenme_*; do
            echo "--- $bin ---"
            checksec --file="$bin" || true
          done
```

### Step breakdown

**Build** — The pipeline compiles all binaries with `make all`. This ensures the audit covers binaries produced from the current source code, not cached artifacts.

**Targeted audit** — Each release binary (stripped `-O2` variant) is audited individually with its own policy. The `audit_binary.py` script returns a non-zero code on FAIL, which causes the GitHub Actions step to fail and blocks the pull request.

**Global YARA** — A scan of the entire `binaries/` directory with YARA rules detects patterns at the corpus level. The `|| true` prevents the pipeline from failing on the YARA scan (which is informational, not blocking).

**Reports** — All JSON and text files are published as workflow artifacts, downloadable for 30 days. This constitutes a timestamped audit trail.

---

## Regression detection through comparison

Auditing a single build is useful, but the real power of the pipeline appears when comparing two successive builds. The comparison detects *changes* — a protection that disappears, a library that appears, a section whose entropy suddenly increases.

```python
#!/usr/bin/env python3
"""
diff_audits.py — Compare two audit reports and flag regressions.

Usage: python3 diff_audits.py <old_report.json> <new_report.json>

Return code:
  0 = no regression
  1 = at least one regression detected
"""

import json  
import sys  

def load(path):
    with open(path) as f:
        return json.load(f)

def diff_reports(old, new):
    regressions = []

    old_results = {r["check"]: r for r in old["results"]}
    new_results = {r["check"]: r for r in new["results"]}

    for check, new_r in new_results.items():
        old_r = old_results.get(check)

        if old_r is None:
            continue  # New check, no comparison possible

        # Regression: PASS -> FAIL
        if old_r["status"] == "PASS" and new_r["status"] == "FAIL":
            regressions.append({
                "check": check,
                "was": old_r["detail"],
                "now": new_r["detail"],
            })

    return regressions

if __name__ == "__main__":
    old = load(sys.argv[1])
    new = load(sys.argv[2])

    regressions = diff_reports(old, new)

    if regressions:
        print(f"❌ {len(regressions)} regression(s) detected:\n")
        for r in regressions:
            print(f"  [{r['check']}]")
            print(f"    Before: {r['was']}")
            print(f"    After:  {r['now']}")
            print()
        sys.exit(1)
    else:
        print("✅ No regressions detected.")
        sys.exit(0)
```

In the pipeline, we keep the report from the last validated build (`main` branch) and compare it with the current build's report:

```yaml
      - name: Download baseline report
        uses: actions/download-artifact@v4
        with:
          name: binary-audit-reports
          path: baseline/
        continue-on-error: true   # No baseline on first run

      - name: Check for regressions
        if: hashFiles('baseline/keygenme_audit.json') != ''
        run: |
          python3 scripts/diff_audits.py \
              baseline/keygenme_audit.json \
              reports/keygenme_audit.json
```

A change from `PASS` to `FAIL` on any check (missing canary, debug symbols reappearing, forbidden library added) will block the PR with a clear message indicating what regressed and what was expected.

---

## Deployment variants

### GitLab CI

The same script adapts to GitLab CI with slightly different syntax:

```yaml
# .gitlab-ci.yml
binary-audit:
  stage: test
  image: ubuntu:22.04
  before_script:
    - apt-get update && apt-get install -y gcc make libssl-dev python3-pip yara
    - pip3 install lief yara-python
  script:
    - cd binaries && make all && cd ..
    - python3 scripts/audit_binary.py binaries/ch21-keygenme/keygenme_O2_strip
        --policy policies/keygenme_policy.json
        --output reports/keygenme_audit.json
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
```

### Local script (pre-commit hook)

For developers who want to verify before pushing, a `pre-commit` Git hook runs the audit locally:

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "=== Binary audit pre-commit ==="

# Recompile modified binaries
make -C binaries all 2>/dev/null

# Audit release variants
for bin in binaries/ch21-keygenme/keygenme_O2_strip \
           binaries/ch24-crypto/crypto_O2_strip \
           binaries/ch25-fileformat/fileformat_O2_strip; do
    if [ -f "$bin" ]; then
        python3 scripts/audit_binary.py "$bin" --policy policies/default_policy.json
        if [ $? -ne 0 ]; then
            echo ""
            echo "❌ Audit failed for $bin — commit blocked."
            echo "   Fix the issues then try again."
            exit 1
        fi
    fi
done

echo "✅ All audits pass."
```

---

## Examples of detectable regressions

To make concrete what the pipeline catches, here are the typical regressions applied to our training binaries and the expected pipeline response.

| Scenario | Modification | Detection |  
|---|---|---|  
| Canary disabled | Remove `-fstack-protector` from Makefile | `check_protections` -> FAIL (no `__stack_chk_fail`) |  
| Symbols in production | Forget `strip` in the release target | `check_symbols` -> FAIL (`.symtab` present) |  
| Debug info in production | Leave `-g` in release `CFLAGS` | `check_symbols` -> FAIL (`.debug_*` sections) |  
| Forgotten sanitizer | `-fsanitize=address` in release build | `check_libraries` -> FAIL (`libasan.so` forbidden) |  
| Reduced RELRO | Switch from `-Wl,-z,relro,-z,now` to `-Wl,-z,relro` | `check_protections` -> FAIL (BIND_NOW absent) |  
| New dependency | Add `libcurl` without updating policy | `check_libraries` -> FAIL (lib not in whitelist) |  
| Binary accidentally packed | `upx` applied in CI | `check_entropy` -> FAIL (entropy > 7.2) |  
| PIE disabled | `-no-pie` added to linker | `check_protections` -> FAIL (`is_pie=False`) |

Each row in this table corresponds to a real error observed in production projects. The pipeline detects all of them automatically, without human intervention.

---

## Limitations and extensions

The pipeline presented here is a minimal foundation. Here are the most useful extensions in practice, which are not implemented here but naturally graft onto the architecture.

**`.text` size comparison** — Beyond total binary size, monitoring the size of `.text` between two builds detects unexpected code additions (dead code, forgotten debug functions). A variation threshold of 5% above the recent average is a good starting point.

**Exported symbol analysis** — For shared libraries (`.so`), verifying that the exported API surface does not change unintentionally. A newly exported symbol is an additional entry point for an attacker.

**Compilation chain verification** — The `.comment` section of an ELF contains the compiler version (e.g.: `GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0`). Monitoring that this string does not change between builds ensures reproducibility.

**Integration with Ghidra headless** — For sensitive projects, triggering an automatic Ghidra analysis (section 35.2) on release binaries and comparing the function graph between two versions. This is heavier, but detects structural changes invisible to surface-level checks.

---


⏭️ [Building your own RE toolkit: organizing your scripts and snippets](/35-automation-scripting/06-building-toolkit.md)
