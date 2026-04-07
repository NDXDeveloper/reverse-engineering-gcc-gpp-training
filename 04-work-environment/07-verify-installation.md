🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.7 — Verify installation: provided `check_env.sh` script

> 🎯 **Goal of this section**: run the `check_env.sh` verification script, which automatically checks that all tools, dependencies, and training binaries are properly installed and configured. Understand the script's output and know how to resolve any failures.

---

## Why a verification script?

Setting up the RE environment involves about thirty tools spread across system packages, manual installs, pip packages, and direct downloads (sections 4.2 through 4.6). Even when following instructions closely, it is common for a tool to be forgotten, a version to be wrong, or an environment variable to be missing.

Rather than discovering these issues in the middle of Chapter 11 when GEF refuses to load, or at Chapter 15 when AFL++ is not in the `PATH`, the `check_env.sh` script verifies everything at once, produces a clear report, and tells you exactly what to fix.

It is also a safety net after a system update (`apt upgrade`) that could have changed versions or removed dependencies.

---

## Running the script

The script is at the root of the repository:

```bash
[vm] cd ~/formation-re
[vm] chmod +x check_env.sh
[vm] ./check_env.sh
```

> 💡 The script does not require root rights. It only verifies the presence and versions of the tools — it modifies nothing on the system.

---

## Reading the output

The script organizes its checks into **categories** corresponding to the installation waves of section 4.2. Each check produces a line with a visual indicator:

```
══════════════════════════════════════════════════════
  RE Lab — Environment check
══════════════════════════════════════════════════════

── System foundations ─────────────────────────────────
  [✔] gcc             13.2.0
  [✔] g++             13.2.0
  [✔] make            4.3
  [✔] python3         3.12.3
  [✔] pip             24.0
  [✔] java            openjdk 21.0.3
  [✔] git             2.43.0

── CLI inspection and debugging tools ─────────────────
  [✔] gdb             15.0.50
  [✔] strace          6.8
  [✔] ltrace          0.7.3
  [✔] valgrind        3.22.0
  [✔] checksec        (available)
  [✔] yara            4.3.2
  [✔] file            5.45
  [✔] strings         (binutils) 2.42
  [✔] readelf         (binutils) 2.42
  [✔] objdump         (binutils) 2.42
  [✔] nm              (binutils) 2.42
  [✔] c++filt         (binutils) 2.42
  [✔] nasm            2.16.03
  [✔] binwalk         2.3.4

── Disassemblers and editors ──────────────────────────
  [✔] ghidra          11.3 (/opt/ghidra)
  [✔] radare2         5.9.6
  [✔] imhex           1.37.4
  [✗] ida-free        NOT FOUND (optional)

── Dynamic frameworks ─────────────────────────────────
  [✔] gdb-gef         GEF loaded in ~/.gdbinit
  [✔] frida           16.2.1
  [✔] pwntools        4.13.0
  [✔] afl-fuzz        4.21c
  [✔] angr            9.2.108
  [✔] z3              4.13.0

── Python libraries ───────────────────────────────────
  [✔] pyelftools      0.31
  [✔] lief            0.15.1
  [✔] r2pipe          1.9.0
  [✔] yara-python     4.3.1

── Complementary tools ────────────────────────────────
  [✔] wireshark       4.2.5
  [✔] tcpdump         4.99.4
  [✔] upx             4.2.2
  [✗] bindiff         NOT FOUND (optional)
  [✔] clang           18.1.3
  [✔] auditd          (available)
  [✔] inotifywait     (available)

── Optional toolchains ────────────────────────────────
  [~] rustc            NOT FOUND (optional — Part VIII)
  [~] cargo            NOT FOUND (optional — Part VIII)
  [~] go               NOT FOUND (optional — Part VIII)
  [~] dotnet           NOT FOUND (optional — Part VII)

── Training binaries ──────────────────────────────────
  [✔] ch21-keygenme    5 binaries found (expected: 5)
  [✔] ch22-oop         6 binaries found (expected: 6)
  [✔] ch23-network     8 binaries found (expected: 8)
  [✔] ch24-crypto      4 binaries found (expected: 4)
  [✔] ch25-fileformat  4 binaries found (expected: 4)
  [✔] ch27-ransomware  4 binaries found (expected: 4)
  [✔] ch28-dropper     4 binaries found (expected: 4)
  [✔] ch29-packed      2 binaries found (expected: 2)
  [~] ch33-rust        0 binaries found (expected: 2) — missing toolchain
  [~] ch34-go          0 binaries found (expected: 2) — missing toolchain

── Python environment ─────────────────────────────────
  [✔] venv active      re-venv
  [✔] venv PATH        /home/re/re-venv/bin at front of PATH

══════════════════════════════════════════════════════

  RESULT: 42/46 checks passed
          0 critical failure(s)
          4 optional item(s) missing

  ✔ Your environment is ready for the training.

══════════════════════════════════════════════════════
```

### The three indicators

| Indicator | Meaning | Action required |  
|---|---|---|  
| `[✔]` | The tool is installed and working | None — all good |  
| `[✗]` | The tool is missing or broken | **Critical** if the tool is not marked "optional" — fix before moving on |  
| `[~]` | The tool is missing but **optional** | No immediate action — you will install it if you reach the relevant chapters |

### The final verdict

The script produces a three-line summary:

- **Checks passed** — the total number of `[✔]`.  
- **Critical failures** — the number of `[✗]` on non-optional tools. If this number is greater than zero, you must fix the problems before continuing.  
- **Optional items missing** — the number of `[~]`. No action required unless you plan to tackle the related parts.

The final message is either `✔ Your environment is ready for the training.` (no critical failure) or `✗ Problems must be fixed before continuing.` (at least one critical failure).

---

## Understanding what the script checks

The script performs five categories of checks:

### 1. Presence of the executables

For each tool, the script uses `command -v` (or `which`) to check that the command exists in the `PATH`:

```bash
if command -v gcc &>/dev/null; then
    version=$(gcc --version | head -1 | grep -oP '\d+\.\d+\.\d+')
    echo "  [✔] gcc             $version"
else
    echo "  [✗] gcc             NOT FOUND"
    CRITICAL_FAIL=$((CRITICAL_FAIL + 1))
fi
```

For tools installed outside the standard `PATH` (Ghidra in `/opt/ghidra`, Cutter as an AppImage in `~/tools/`), the script checks known paths or aliases defined in `~/.bashrc`.

### 2. Minimum versions

For some critical tools, the script does not only check presence — it also checks that the version is sufficient. For example, Ghidra 11.x requires Java 17+. If Java 11 is installed, Ghidra will launch but crash during analysis. The script detects this situation:

```
  [✗] java            11.0.22 (minimum required: 17)
```

The minimum versions checked are:

| Tool | Minimum version | Reason |  
|---|---|---|  
| Java (JDK) | 17 | Required by Ghidra 11.x |  
| Python 3 | 3.10 | angr, pwntools compatibility |  
| GDB | 10.0 | Supports commands used by GEF/pwndbg |  
| Frida | 15.0 | Stable hooking API |

### 3. GDB extensions

The script inspects the contents of `~/.gdbinit` to determine which GDB extension is configured:

```bash
if grep -q "gef" ~/.gdbinit 2>/dev/null; then
    echo "  [✔] gdb-gef         GEF loaded in ~/.gdbinit"
elif grep -q "pwndbg" ~/.gdbinit 2>/dev/null; then
    echo "  [✔] gdb-pwndbg      pwndbg loaded in ~/.gdbinit"
elif grep -q "peda" ~/.gdbinit 2>/dev/null; then
    echo "  [✔] gdb-peda        PEDA loaded in ~/.gdbinit"
else
    echo "  [✗] gdb-extension   No extension configured in ~/.gdbinit"
fi
```

At least one of the three extensions must be configured. Which one is up to you (section 4.2 recommends GEF).

### 4. Python packages in the venv

The script checks that the `re-venv` virtual environment is active and that the required Python packages are importable:

```bash
python3 -c "import angr" 2>/dev/null && echo "  [✔] angr" || echo "  [✗] angr"
```

If the venv is not active, pip packages installed in `re-venv` will not be visible. The script detects this and displays an explicit warning:

```
  [✗] venv active     No venv detected — activate re-venv before rerunning
```

### 5. Training binaries

For each `binaries/` sub-folder, the script counts the ELF executable files present and compares to the expected count:

```bash
count=$(find binaries/ch21-keygenme -maxdepth 1 -type f -executable \
        -exec file {} \; | grep -c "ELF")
expected=5  
if [ "$count" -eq "$expected" ]; then  
    echo "  [✔] ch21-keygenme    $count binaries found (expected: $expected)"
else
    echo "  [✗] ch21-keygenme    $count binaries found (expected: $expected)"
fi
```

If the count is lower than expected, it means `make all` has not been run or a compilation failed.

---

## Resolving common failures

### `[✗] gcc — NOT FOUND`

The `build-essential` package is not installed:

```bash
[vm] sudo apt install -y build-essential
```

### `[✗] ghidra — NOT FOUND`

Ghidra is installed in `/opt/ghidra` but the alias is not defined, or the path is different. Check:

```bash
[vm] ls /opt/ghidra*/ghidraRun
```

If the file exists, add the alias:

```bash
[vm] echo 'alias ghidra="/opt/ghidra/ghidraRun"' >> ~/.bashrc
[vm] source ~/.bashrc
```

If the file does not exist, Ghidra has not been installed — redo the section 4.2 procedure.

### `[✗] java — 11.0.22 (minimum required: 17)`

An outdated Java version is installed. Install OpenJDK 21:

```bash
[vm] sudo apt install -y openjdk-21-jdk
```

If several Java versions coexist, select the right one with `update-alternatives`:

```bash
[vm] sudo update-alternatives --config java
```

Choose the entry corresponding to OpenJDK 21.

### `[✗] gdb-extension — No extension configured`

No GDB extension is sourced in `~/.gdbinit`. Install GEF (or pwndbg, or PEDA) following the instructions of section 4.2:

```bash
[vm] bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

### `[✗] venv active — No venv detected`

The Python virtual environment is not activated. Activate it:

```bash
[vm] source ~/re-venv/bin/activate
```

If the `~/re-venv` folder does not exist, create it:

```bash
[vm] python3 -m venv ~/re-venv
[vm] source ~/re-venv/bin/activate
```

Then reinstall the required pip packages (section 4.2, waves 4–5).

### `[✗] angr — NOT FOUND` (or another pip package)

The package is not installed in the active venv:

```bash
[vm] pip install angr
```

If the install fails, check that the system dependencies are present:

```bash
[vm] sudo apt install -y python3-dev libffi-dev
[vm] pip install angr
```

### `[✗] ch24-crypto — 0 binaries found (expected: 4)`

Chapter 24 compilation failed, probably due to the missing OpenSSL dependency:

```bash
[vm] sudo apt install -y libssl-dev
[vm] cd ~/formation-re/binaries/ch24-crypto
[vm] make clean && make all
```

### `[~] rustc — NOT FOUND (optional)`

This is an optional tool. If you plan to tackle Part VIII (RE of Rust binaries), install the toolchain:

```bash
[vm] curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
[vm] source ~/.cargo/env
```

Otherwise, ignore this warning.

---

## Rerunning the script after fixes

After fixing the identified problems, rerun the script to verify that everything is resolved:

```bash
[vm] ./check_env.sh
```

Repeat the "fix → rerun" cycle until you get zero critical failures. The script is idempotent — you can run it as many times as needed with no side effects.

---

## Using the script as a diagnostic tool

The script is not limited to initial setup. You can rerun it at any time during the training to diagnose a problem:

- **After a system update** (`apt upgrade`) — to verify that no tool has been broken or removed.  
- **After restoring a snapshot** — to confirm that the snapshot indeed contains all the tools.  
- **In case of unexpected tool behavior** — to verify that the right version is in the `PATH`.  
- **On a new VM** — if you rebuild your environment from scratch, the script serves as an automated checklist.

> 💡 **Tip**: redirect the output to a file to keep a trace of your environment state at a given point in time:  
> ```bash  
> [vm] ./check_env.sh | tee ~/check_env_$(date +%Y%m%d).log  
> ```

---

## Internal structure of the script

For the curious, here is the general logic of `check_env.sh`. Understanding its structure will be useful when you write your own automation scripts (Chapter 35).

```bash
#!/usr/bin/env bash
set -euo pipefail

# Counters
PASS=0  
FAIL=0  
OPTIONAL=0  

# Utility functions
check_cmd() {
    local name="$1"
    local cmd="$2"
    local optional="${3:-false}"
    
    if command -v "$cmd" &>/dev/null; then
        local version
        version=$("$cmd" --version 2>&1 | head -1 || echo "available")
        printf "  [✔] %-16s %s\n" "$name" "$version"
        PASS=$((PASS + 1))
    elif [ "$optional" = "true" ]; then
        printf "  [~] %-16s NOT FOUND (optional)\n" "$name"
        OPTIONAL=$((OPTIONAL + 1))
    else
        printf "  [✗] %-16s NOT FOUND\n" "$name"
        FAIL=$((FAIL + 1))
    fi
}

check_python_pkg() {
    local name="$1"
    local optional="${2:-false}"
    
    if python3 -c "import $name" &>/dev/null; then
        local version
        version=$(python3 -c "import $name; print(getattr($name, '__version__', 'OK'))" 2>/dev/null)
        printf "  [✔] %-16s %s\n" "$name" "$version"
        PASS=$((PASS + 1))
    elif [ "$optional" = "true" ]; then
        printf "  [~] %-16s NOT FOUND (optional)\n" "$name"
        OPTIONAL=$((OPTIONAL + 1))
    else
        printf "  [✗] %-16s NOT FOUND\n" "$name"
        FAIL=$((FAIL + 1))
    fi
}

check_binaries_dir() {
    local dir="$1"
    local expected="$2"
    local count
    count=$(find "binaries/$dir" -maxdepth 1 -type f -executable \
            -exec file {} \; 2>/dev/null | grep -c "ELF" || echo 0)
    
    if [ "$count" -ge "$expected" ]; then
        printf "  [✔] %-16s %s binaries found (expected: %s)\n" "$dir" "$count" "$expected"
        PASS=$((PASS + 1))
    else
        printf "  [✗] %-16s %s binaries found (expected: %s)\n" "$dir" "$count" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

# ── Checks ──
# ... calls to check_cmd, check_python_pkg, check_binaries_dir ...

# ── Verdict ──
echo ""  
echo "  RESULT: $PASS/$((PASS + FAIL + OPTIONAL)) checks passed"  
echo "          $FAIL critical failure(s)"  
echo "          $OPTIONAL optional item(s) missing"  

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "  ✔ Your environment is ready for the training."
else
    echo ""
    echo "  ✗ Problems must be fixed before continuing."
    exit 1
fi
```

The script uses `set -euo pipefail` for strict behavior (stop on unhandled error), but each individual check captures its own errors to keep inspecting even when a tool is absent.

The three utility functions (`check_cmd`, `check_python_pkg`, `check_binaries_dir`) wrap the recurring check patterns. It is a good example of factoring you will see again in Chapter 35 scripts.

> 📌 The complete script is in the repository at the root (`check_env.sh`). What is shown here is a simplified version to illustrate the logic. The actual script includes additional checks (minimum versions, `.gdbinit`, venv state, `/proc/sys/kernel/core_pattern` rights for AFL++).

---

## Summary

- The `check_env.sh` script is your **central diagnostic tool**. Run it after initial installation, after every system update, and after every snapshot restore.  
- It verifies the presence, versions, and configuration of all tools, Python packages, GDB extensions, and training binaries.  
- Results are sorted into three categories: `[✔]` (OK), `[✗]` (critical failure to fix), `[~]` (optional missing).  
- **Zero critical failures** is the prerequisite for continuing the training.  
- The script is itself an example of Bash scripting best practices you will find and build upon in Chapter 35.

---


⏭️ [🎯 Checkpoint: run `check_env.sh` — all tools must be green](/04-work-environment/checkpoint.md)
