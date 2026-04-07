#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# check_env.sh — Training environment verification
#                Reverse Engineering — Compiled applications (GNU toolchain)
#
# Usage: ./check_env.sh [--no-color] [--verbose]
#
# MIT License — Strictly educational and ethical use.
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

# ── CLI Options ─────────────────────────────────────────────────────

NO_COLOR=false
VERBOSE=false

for arg in "$@"; do
    case "$arg" in
        --no-color) NO_COLOR=true ;;
        --verbose)  VERBOSE=true ;;
        --help|-h)
            echo "Usage: $0 [--no-color] [--verbose]"
            echo "  --no-color   Disable output colorization"
            echo "  --verbose    Show details for each check"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--no-color] [--verbose]"
            exit 1
            ;;
    esac
done

# ── Colors ──────────────────────────────────────────────────────────

if [ "$NO_COLOR" = true ] || [ ! -t 1 ]; then
    GREEN=""
    RED=""
    YELLOW=""
    CYAN=""
    BOLD=""
    DIM=""
    RESET=""
else
    GREEN="\033[0;32m"
    RED="\033[0;31m"
    YELLOW="\033[0;33m"
    CYAN="\033[0;36m"
    BOLD="\033[1m"
    DIM="\033[2m"
    RESET="\033[0m"
fi

# ── Counters ────────────────────────────────────────────────────────

PASS=0
FAIL=0
OPTIONAL_MISSING=0
WARNINGS=0
TOTAL=0

# ── Repository directory detection ──────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARIES_DIR="$SCRIPT_DIR/binaries"

# ── Utility functions ───────────────────────────────────────────────

print_header() {
    echo ""
    printf "  ${CYAN}${BOLD}── %s${RESET}\n" "$1"
    echo ""
}

print_banner() {
    echo ""
    echo -e "  ${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo -e "  ${BOLD}  RE Lab — Environment Verification${RESET}"
    echo -e "  ${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${DIM}Date   : $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo -e "  ${DIM}System : $(uname -srm)${RESET}"
    echo -e "  ${DIM}Repo   : $SCRIPT_DIR${RESET}"
}

# Check the presence of a command in PATH
# Arguments: display_name  command  [optional:true/false]
check_cmd() {
    local name="$1"
    local cmd="$2"
    local optional="${3:-false}"

    TOTAL=$((TOTAL + 1))

    if command -v "$cmd" &>/dev/null; then
        local version
        version=$( ("$cmd" --version 2>&1 || true) | head -1 | sed 's/^[^0-9]*//' | cut -d' ' -f1 )
        [ -z "$version" ] && version="(available)"
        printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "$name" "$version"
        PASS=$((PASS + 1))
        return 0
    elif [ "$optional" = "true" ]; then
        printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}NOT FOUND (optional)${RESET}\n" "$name"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        return 1
    else
        printf "  ${RED}[✗]${RESET} %-20s NOT FOUND\n" "$name"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Check the presence of a command AND its minimum version
# Arguments: display_name  command  minimum_version  [optional:true/false]
check_cmd_version() {
    local name="$1"
    local cmd="$2"
    local min_version="$3"
    local optional="${4:-false}"

    TOTAL=$((TOTAL + 1))

    if ! command -v "$cmd" &>/dev/null; then
        if [ "$optional" = "true" ]; then
            printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}NOT FOUND (optional)${RESET}\n" "$name"
            OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        else
            printf "  ${RED}[✗]${RESET} %-20s NOT FOUND\n" "$name"
            FAIL=$((FAIL + 1))
        fi
        return 1
    fi

    local version
    version=$( ("$cmd" --version 2>&1 || true) | head -1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1 )
    [ -z "$version" ] && version="unknown"

    if version_gte "$version" "$min_version"; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(>= %s)${RESET}\n" "$name" "$version" "$min_version"
        PASS=$((PASS + 1))
        return 0
    else
        printf "  ${RED}[✗]${RESET} %-20s %s ${RED}(minimum required: %s)${RESET}\n" "$name" "$version" "$min_version"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Check the importability of a Python package
# Arguments: display_name  python_module  [optional:true/false]
check_python_pkg() {
    local name="$1"
    local module="$2"
    local optional="${3:-false}"

    TOTAL=$((TOTAL + 1))

    if ! command -v python3 &>/dev/null; then
        printf "  ${RED}[✗]${RESET} %-20s python3 not available\n" "$name"
        FAIL=$((FAIL + 1))
        return 1
    fi

    local version
    if version=$(python3 -c "
import importlib
m = importlib.import_module('$module')
v = getattr(m, '__version__', None)
if v is None:
    v = getattr(m, 'VERSION', None)
if v is None:
    v = 'OK'
print(v)
" 2>/dev/null); then
        printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "$name" "$version"
        PASS=$((PASS + 1))
        return 0
    elif [ "$optional" = "true" ]; then
        printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}NOT FOUND (optional)${RESET}\n" "$name"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        return 1
    else
        printf "  ${RED}[✗]${RESET} %-20s NOT IMPORTABLE\n" "$name"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Check the number of ELF binaries in a binaries/ subdirectory
# Arguments: directory_name  expected_count  [optional:true/false]
check_binaries_dir() {
    local dir="$1"
    local expected="$2"
    local optional="${3:-false}"

    TOTAL=$((TOTAL + 1))

    local full_path="$BINARIES_DIR/$dir"

    if [ ! -d "$full_path" ]; then
        if [ "$optional" = "true" ]; then
            printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}Directory missing (optional)${RESET}\n" "$dir"
            OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        else
            printf "  ${RED}[✗]${RESET} %-20s Directory missing\n" "$dir"
            FAIL=$((FAIL + 1))
        fi
        return 1
    fi

    local count
    count=$(find "$full_path" -maxdepth 1 -type f -executable \
            -exec file {} \; 2>/dev/null | grep -c "ELF" || echo 0)

    if [ "$count" -ge "$expected" ]; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s ELF binary(ies) (expected: %s)\n" "$dir" "$count" "$expected"
        PASS=$((PASS + 1))
        return 0
    elif [ "$optional" = "true" ]; then
        printf "  ${YELLOW}[~]${RESET} %-20s %s ELF binary(ies) (expected: %s) ${DIM}— missing toolchain?${RESET}\n" "$dir" "$count" "$expected"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        return 1
    else
        printf "  ${RED}[✗]${RESET} %-20s %s ELF binary(ies) (expected: %s) ${DIM}— run make all${RESET}\n" "$dir" "$count" "$expected"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Compare two semantic versions (a >= b)
# Returns 0 (true) if $1 >= $2
version_gte() {
    local v1="$1"
    local v2="$2"

    # Normalize to 3 components
    local a1 a2 a3 b1 b2 b3
    IFS='.' read -r a1 a2 a3 <<< "$v1"
    IFS='.' read -r b1 b2 b3 <<< "$v2"
    a1=${a1:-0}; a2=${a2:-0}; a3=${a3:-0}
    b1=${b1:-0}; b2=${b2:-0}; b3=${b3:-0}

    if (( a1 > b1 )); then return 0; fi
    if (( a1 < b1 )); then return 1; fi
    if (( a2 > b2 )); then return 0; fi
    if (( a2 < b2 )); then return 1; fi
    if (( a3 >= b3 )); then return 0; fi
    return 1
}

# Check that a file or directory exists
# Arguments: display_name  path  [optional:true/false]
check_path() {
    local name="$1"
    local path="$2"
    local optional="${3:-false}"

    TOTAL=$((TOTAL + 1))

    if [ -e "$path" ]; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "$name" "$path"
        PASS=$((PASS + 1))
        return 0
    elif [ "$optional" = "true" ]; then
        printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}%s not found (optional)${RESET}\n" "$name" "$path"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        return 1
    else
        printf "  ${RED}[✗]${RESET} %-20s %s not found\n" "$name" "$path"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Display a verbose message (only if --verbose)
verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "      ${DIM}↳ $1${RESET}"
    fi
}

# ═════════════════════════════════════════════════════════════════════
#  START OF CHECKS
# ═════════════════════════════════════════════════════════════════════

print_banner

# ─────────────────────────────────────────────────────────────────────
#  WAVE 1 — System base and languages
# ─────────────────────────────────────────────────────────────────────

print_header "System base and languages"

check_cmd_version "gcc" "gcc" "11.0"
verbose "Package: build-essential"

check_cmd_version "g++" "g++" "11.0"
verbose "Package: build-essential"

check_cmd "make" "make"
verbose "Package: build-essential"

check_cmd_version "python3" "python3" "3.10"
verbose "Package: python3"

# pip — specific version extraction
TOTAL=$((TOTAL + 1))
if command -v pip &>/dev/null; then
    pip_version=$(pip --version 2>&1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
    printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "pip" "$pip_version"
    PASS=$((PASS + 1))
elif command -v pip3 &>/dev/null; then
    pip_version=$(pip3 --version 2>&1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
    printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(via pip3)${RESET}\n" "pip" "$pip_version"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[✗]${RESET} %-20s NOT FOUND\n" "pip"
    FAIL=$((FAIL + 1))
fi
verbose "Package: python3-pip"

# Java — specific version for Ghidra
TOTAL=$((TOTAL + 1))
if command -v java &>/dev/null; then
    java_version=$(java -version 2>&1 | head -1 | grep -oP '\d+\.\d+\.\d+|\d+' | head -1)
    java_major=$(echo "$java_version" | cut -d. -f1)
    if [ "$java_major" -ge 17 ] 2>/dev/null; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(>= 17, required by Ghidra)${RESET}\n" "java (JDK)" "$java_version"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[✗]${RESET} %-20s %s ${RED}(minimum required: 17 for Ghidra)${RESET}\n" "java (JDK)" "$java_version"
        FAIL=$((FAIL + 1))
    fi
else
    printf "  ${RED}[✗]${RESET} %-20s NOT FOUND ${DIM}(required by Ghidra)${RESET}\n" "java (JDK)"
    FAIL=$((FAIL + 1))
fi
verbose "Package: openjdk-21-jdk"

check_cmd "git" "git"

# ─────────────────────────────────────────────────────────────────────
#  WAVE 2 — CLI inspection and debugging tools
# ─────────────────────────────────────────────────────────────────────

print_header "CLI inspection and debugging tools"

check_cmd_version "gdb" "gdb" "10.0"
verbose "Package: gdb"

check_cmd "strace" "strace"
check_cmd "ltrace" "ltrace"

check_cmd_version "valgrind" "valgrind" "3.18"
verbose "Package: valgrind"

# checksec — can be a system script or a pip package
TOTAL=$((TOTAL + 1))
if command -v checksec &>/dev/null; then
    checksec_v=$(checksec --version 2>&1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1 || echo "(available)")
    [ -z "$checksec_v" ] && checksec_v="(available)"
    printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "checksec" "$checksec_v"
    PASS=$((PASS + 1))
elif python3 -c "import checksec" &>/dev/null 2>&1; then
    printf "  ${GREEN}[✔]${RESET} %-20s ${DIM}(via pip checksec.py)${RESET}\n" "checksec"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[✗]${RESET} %-20s NOT FOUND\n" "checksec"
    FAIL=$((FAIL + 1))
fi

check_cmd "yara" "yara"
check_cmd "file" "file"

# binutils — grouped check
for tool in strings readelf objdump nm c__filt strip objcopy; do
    actual_cmd="${tool/c__filt/c++filt}"
    check_cmd "$actual_cmd" "$actual_cmd"
done

check_cmd "nasm" "nasm"
check_cmd "binwalk" "binwalk"
check_cmd "xxd" "xxd"

# ─────────────────────────────────────────────────────────────────────
#  WAVE 3 — Disassemblers and graphical editors
# ─────────────────────────────────────────────────────────────────────

print_header "Disassemblers and graphical editors"

# Ghidra — manually installed in /opt
TOTAL=$((TOTAL + 1))
GHIDRA_FOUND=false
GHIDRA_PATHS=(
    "/opt/ghidra/ghidraRun"
    "/opt/ghidra*/ghidraRun"
    "$HOME/tools/ghidra*/ghidraRun"
    "$HOME/ghidra*/ghidraRun"
)

for pattern in "${GHIDRA_PATHS[@]}"; do
    # shellcheck disable=SC2086
    for candidate in $pattern; do
        if [ -x "$candidate" ] 2>/dev/null; then
            ghidra_dir=$(dirname "$candidate")
            # Try to extract version from directory name or application.properties
            ghidra_version="(found)"
            if [ -f "$ghidra_dir/application.properties" ]; then
                ghidra_version=$(grep "application.version" "$ghidra_dir/application.properties" 2>/dev/null \
                    | cut -d= -f2 | tr -d ' ' || echo "(found)")
            fi
            printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(%s)${RESET}\n" "ghidra" "$ghidra_version" "$ghidra_dir"
            PASS=$((PASS + 1))
            GHIDRA_FOUND=true
            break 2
        fi
    done
done

if [ "$GHIDRA_FOUND" = false ]; then
    # Also check via an alias
    if alias ghidra &>/dev/null 2>&1 || type ghidra &>/dev/null 2>&1; then
        printf "  ${GREEN}[✔]${RESET} %-20s ${DIM}(via alias)${RESET}\n" "ghidra"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[✗]${RESET} %-20s NOT FOUND ${DIM}(searched in /opt and ~/tools)${RESET}\n" "ghidra"
        FAIL=$((FAIL + 1))
    fi
fi

check_cmd "radare2" "r2"
verbose "Installed from source: github.com/radareorg/radare2"

# Cutter — can be installed via apt or AppImage
TOTAL=$((TOTAL + 1))
if command -v cutter &>/dev/null || command -v Cutter &>/dev/null; then
    printf "  ${GREEN}[✔]${RESET} %-20s (available)\n" "cutter"
    PASS=$((PASS + 1))
elif ls "$HOME/tools/Cutter"*.AppImage &>/dev/null 2>&1; then
    printf "  ${GREEN}[✔]${RESET} %-20s ${DIM}(AppImage in ~/tools)${RESET}\n" "cutter"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}NOT FOUND (optional — Radare2 GUI)${RESET}\n" "cutter"
    OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
fi

# ImHex — can be installed via apt, .deb, AppImage or Flatpak
TOTAL=$((TOTAL + 1))
if command -v imhex &>/dev/null; then
    imhex_v=$(imhex --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "(available)")
    [ -z "$imhex_v" ] && imhex_v="(available)"
    printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "imhex" "$imhex_v"
    PASS=$((PASS + 1))
elif flatpak list 2>/dev/null | grep -qi imhex; then
    printf "  ${GREEN}[✔]${RESET} %-20s ${DIM}(Flatpak)${RESET}\n" "imhex"
    PASS=$((PASS + 1))
elif ls "$HOME/tools/"*[Ii]m[Hh]ex* &>/dev/null 2>&1; then
    printf "  ${GREEN}[✔]${RESET} %-20s ${DIM}(AppImage in ~/tools)${RESET}\n" "imhex"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[✗]${RESET} %-20s NOT FOUND\n" "imhex"
    FAIL=$((FAIL + 1))
fi

# IDA Free — optional
TOTAL=$((TOTAL + 1))
if command -v ida64 &>/dev/null || command -v idat64 &>/dev/null; then
    printf "  ${GREEN}[✔]${RESET} %-20s (available)\n" "ida-free"
    PASS=$((PASS + 1))
elif [ -x "$HOME/idafree"*/ida64 ] 2>/dev/null || [ -x "/opt/idafree"*/ida64 ] 2>/dev/null; then
    printf "  ${GREEN}[✔]${RESET} %-20s (available)\n" "ida-free"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}NOT FOUND (optional)${RESET}\n" "ida-free"
    OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
fi

# ─────────────────────────────────────────────────────────────────────
#  WAVE 4 — GDB extensions, dynamic frameworks
# ─────────────────────────────────────────────────────────────────────

print_header "GDB extensions and dynamic frameworks"

# GDB extensions — at least one must be configured
TOTAL=$((TOTAL + 1))
GDB_EXT_FOUND=false
GDB_EXT_NAME=""

if [ -f "$HOME/.gdbinit" ]; then
    if grep -qiE "gef|GEF" "$HOME/.gdbinit" 2>/dev/null; then
        GDB_EXT_FOUND=true
        GDB_EXT_NAME="GEF"
    elif grep -qi "pwndbg" "$HOME/.gdbinit" 2>/dev/null; then
        GDB_EXT_FOUND=true
        GDB_EXT_NAME="pwndbg"
    elif grep -qi "peda" "$HOME/.gdbinit" 2>/dev/null; then
        GDB_EXT_FOUND=true
        GDB_EXT_NAME="PEDA"
    fi
fi

if [ "$GDB_EXT_FOUND" = true ]; then
    printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(loaded in ~/.gdbinit)${RESET}\n" "gdb-extension" "$GDB_EXT_NAME"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[✗]${RESET} %-20s No extension detected in ~/.gdbinit ${DIM}(GEF/pwndbg/PEDA)${RESET}\n" "gdb-extension"
    FAIL=$((FAIL + 1))
fi

# Frida
TOTAL=$((TOTAL + 1))
if command -v frida &>/dev/null; then
    frida_v=$(frida --version 2>&1 | head -1 || echo "(available)")
    frida_major=$(echo "$frida_v" | cut -d. -f1)
    if [ "${frida_major:-0}" -ge 15 ] 2>/dev/null; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(>= 15.0)${RESET}\n" "frida" "$frida_v"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[✗]${RESET} %-20s %s ${RED}(minimum required: 15.0)${RESET}\n" "frida" "$frida_v"
        FAIL=$((FAIL + 1))
    fi
else
    printf "  ${RED}[✗]${RESET} %-20s NOT FOUND ${DIM}(pip install frida-tools frida)${RESET}\n" "frida"
    FAIL=$((FAIL + 1))
fi

check_cmd "frida-trace" "frida-trace"

check_cmd "afl-fuzz" "afl-fuzz"
verbose "Package: afl++ or compiled from source"

check_cmd "afl-gcc" "afl-gcc" true
verbose "AFL++ instrumented compiler"

# ─────────────────────────────────────────────────────────────────────
#  WAVE 4 (continued) — Python libraries
# ─────────────────────────────────────────────────────────────────────

print_header "Python libraries (in the venv)"

# Venv check
TOTAL=$((TOTAL + 1))
if [ -n "${VIRTUAL_ENV:-}" ]; then
    venv_name=$(basename "$VIRTUAL_ENV")
    printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(%s)${RESET}\n" "active venv" "$venv_name" "$VIRTUAL_ENV"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[✗]${RESET} %-20s ${RED}No venv detected${RESET} ${DIM}— run: source ~/re-venv/bin/activate${RESET}\n" "active venv"
    FAIL=$((FAIL + 1))
    WARNINGS=$((WARNINGS + 1))
fi

# Venv PATH check
TOTAL=$((TOTAL + 1))
if [ -n "${VIRTUAL_ENV:-}" ] && echo "$PATH" | grep -q "$VIRTUAL_ENV/bin"; then
    printf "  ${GREEN}[✔]${RESET} %-20s ${DIM}$VIRTUAL_ENV/bin at the front of PATH${RESET}\n" "venv PATH"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[~]${RESET} %-20s ${DIM}The venv is not at the front of PATH${RESET}\n" "venv PATH"
    OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
fi

check_python_pkg "pwntools"    "pwn"
check_python_pkg "angr"        "angr"
check_python_pkg "z3-solver"   "z3"
check_python_pkg "pyelftools"  "elftools"
check_python_pkg "lief"        "lief"
check_python_pkg "r2pipe"      "r2pipe"
check_python_pkg "yara-python" "yara"

check_python_pkg "capstone"    "capstone"   true
check_python_pkg "keystone"    "keystone"   true
check_python_pkg "unicorn"     "unicorn"    true

# ─────────────────────────────────────────────────────────────────────
#  WAVE 5 — Additional tools
# ─────────────────────────────────────────────────────────────────────

print_header "Additional tools"

check_cmd "wireshark" "wireshark"
verbose "Package: wireshark — verify that the user is in the wireshark group"

check_cmd "tcpdump" "tcpdump"
check_cmd "upx" "upx"
check_cmd "clang" "clang"

# BinDiff — optional
check_cmd "bindiff" "bindiff" true

# Monitoring tools (Part VI)
check_cmd "auditctl" "auditctl"
verbose "Package: auditd"

check_cmd "inotifywait" "inotifywait"
verbose "Package: inotify-tools"

check_cmd "sysdig" "sysdig" true

# KCachegrind — optional (GUI for Callgrind)
check_cmd "kcachegrind" "kcachegrind" true

check_cmd "tmux" "tmux"

# ─────────────────────────────────────────────────────────────────────
#  Optional toolchains (Parts VII and VIII)
# ─────────────────────────────────────────────────────────────────────

print_header "Optional toolchains (Parts VII–VIII)"

check_cmd "rustc"  "rustc"  true
check_cmd "cargo"  "cargo"  true
check_cmd "go"     "go"     true
check_cmd "dotnet" "dotnet" true

# ─────────────────────────────────────────────────────────────────────
#  Training binaries
# ─────────────────────────────────────────────────────────────────────

print_header "Training binaries (binaries/)"

if [ ! -d "$BINARIES_DIR" ]; then
    TOTAL=$((TOTAL + 1))
    printf "  ${RED}[✗]${RESET} %-20s binaries/ directory not found in %s\n" "binaries/" "$SCRIPT_DIR"
    FAIL=$((FAIL + 1))
else
    check_binaries_dir "ch21-keygenme"    5
    check_binaries_dir "ch22-oop"         6
    check_binaries_dir "ch23-network"     8
    check_binaries_dir "ch24-crypto"      4
    check_binaries_dir "ch25-fileformat"  4
    check_binaries_dir "ch27-ransomware"  4
    check_binaries_dir "ch28-dropper"     4
    check_binaries_dir "ch29-packed"      2
    check_binaries_dir "ch33-rust"        2 true
    check_binaries_dir "ch34-go"          2 true
fi

# ─────────────────────────────────────────────────────────────────────
#  Repository resources
# ─────────────────────────────────────────────────────────────────────

print_header "Repository resources"

check_path "scripts/"     "$SCRIPT_DIR/scripts"
check_path "hexpat/"      "$SCRIPT_DIR/hexpat"
check_path "yara-rules/"  "$SCRIPT_DIR/yara-rules"
check_path "appendices/"  "$SCRIPT_DIR/appendices"
check_path "solutions/"   "$SCRIPT_DIR/solutions"

# ─────────────────────────────────────────────────────────────────────
#  System checks
# ─────────────────────────────────────────────────────────────────────

print_header "System configuration"

# core_pattern — required for AFL++
TOTAL=$((TOTAL + 1))
if [ -f /proc/sys/kernel/core_pattern ]; then
    core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    if [ "$core_pattern" = "core" ]; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(AFL++ compatible)${RESET}\n" "core_pattern" "$core_pattern"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[~]${RESET} %-20s %s ${DIM}— AFL++ requires 'core' (echo core | sudo tee /proc/sys/kernel/core_pattern)${RESET}\n" "core_pattern" "$core_pattern"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
    fi
else
    printf "  ${DIM}  %-20s (not applicable — /proc not available)${RESET}\n" "core_pattern"
    TOTAL=$((TOTAL - 1))
fi

# ptrace_scope — required for Frida, GDB attach, strace
TOTAL=$((TOTAL + 1))
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    if [ "$ptrace_scope" -le 1 ] 2>/dev/null; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s ${DIM}(0=all, 1=parent — OK)${RESET}\n" "ptrace_scope" "$ptrace_scope"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[~]${RESET} %-20s %s ${DIM}— Frida/GDB attach may require sudo or: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope${RESET}\n" "ptrace_scope" "$ptrace_scope"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
    fi
else
    printf "  ${DIM}  %-20s (not applicable — Yama not enabled)${RESET}\n" "ptrace_scope"
    TOTAL=$((TOTAL - 1))
fi

# ASLR — informational (not a failure, just informative)
TOTAL=$((TOTAL + 1))
if [ -f /proc/sys/kernel/randomize_va_space ]; then
    aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    case "$aslr" in
        0) aslr_label="disabled" ;;
        1) aslr_label="partial (stack)" ;;
        2) aslr_label="full" ;;
        *) aslr_label="unknown ($aslr)" ;;
    esac
    printf "  ${GREEN}[✔]${RESET} %-20s %s — %s\n" "ASLR" "$aslr" "$aslr_label"
    PASS=$((PASS + 1))
else
    printf "  ${DIM}  %-20s (not applicable)${RESET}\n" "ASLR"
    TOTAL=$((TOTAL - 1))
fi

# Available disk space
TOTAL=$((TOTAL + 1))
if command -v df &>/dev/null; then
    avail_kb=$(df --output=avail "$HOME" 2>/dev/null | tail -1 | tr -d ' ')
    avail_gb=$((avail_kb / 1024 / 1024))
    if [ "$avail_gb" -ge 15 ]; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s GB available\n" "disk space" "$avail_gb"
        PASS=$((PASS + 1))
    elif [ "$avail_gb" -ge 5 ]; then
        printf "  ${YELLOW}[~]${RESET} %-20s %s GB available ${DIM}(15 GB+ recommended)${RESET}\n" "disk space" "$avail_gb"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
    else
        printf "  ${RED}[✗]${RESET} %-20s %s GB available ${RED}(insufficient — 15 GB+ recommended)${RESET}\n" "disk space" "$avail_gb"
        FAIL=$((FAIL + 1))
    fi
fi

# Total RAM
TOTAL=$((TOTAL + 1))
if [ -f /proc/meminfo ]; then
    mem_total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_total_gb=$((mem_total_kb / 1024 / 1024))
    mem_total_mb=$((mem_total_kb / 1024))
    if [ "$mem_total_mb" -ge 7500 ]; then
        printf "  ${GREEN}[✔]${RESET} %-20s %s GB\n" "total RAM" "$mem_total_gb"
        PASS=$((PASS + 1))
    elif [ "$mem_total_mb" -ge 3500 ]; then
        printf "  ${YELLOW}[~]${RESET} %-20s %s GB ${DIM}(8 GB recommended)${RESET}\n" "total RAM" "$mem_total_gb"
        OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
    else
        printf "  ${RED}[✗]${RESET} %-20s %s GB ${RED}(minimum 4 GB, 8 GB recommended)${RESET}\n" "total RAM" "$mem_total_gb"
        FAIL=$((FAIL + 1))
    fi
fi

# Architecture
TOTAL=$((TOTAL + 1))
arch=$(uname -m)
if [ "$arch" = "x86_64" ]; then
    printf "  ${GREEN}[✔]${RESET} %-20s %s\n" "architecture" "$arch"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[~]${RESET} %-20s %s ${DIM}(target binaries are x86-64 — emulation required)${RESET}\n" "architecture" "$arch"
    OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
fi

# ═════════════════════════════════════════════════════════════════════
#  FINAL VERDICT
# ═════════════════════════════════════════════════════════════════════

echo ""
echo -e "  ${BOLD}══════════════════════════════════════════════════════${RESET}"
echo ""
printf "  ${BOLD}RESULT${RESET}: %s/%s checks passed\n" "$PASS" "$TOTAL"
printf "          ${RED}%s${RESET} critical failure(s)\n" "$FAIL"
printf "          ${YELLOW}%s${RESET} optional item(s) missing\n" "$OPTIONAL_MISSING"

if [ "$WARNINGS" -gt 0 ]; then
    printf "          ${YELLOW}%s${RESET} warning(s)\n" "$WARNINGS"
fi

echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✔ Your environment is ready for the training.${RESET}"
    if [ "$OPTIONAL_MISSING" -gt 0 ]; then
        echo -e "  ${DIM}  Missing optional items do not block the main learning path.${RESET}"
    fi
    echo ""
    echo -e "  ${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo ""
    exit 0
else
    echo -e "  ${RED}${BOLD}✗ Issues must be fixed before continuing.${RESET}"
    echo ""
    echo -e "  ${DIM}  Fix the items marked [✗], then re-run:${RESET}"
    echo -e "  ${DIM}  ./check_env.sh${RESET}"
    echo ""
    echo -e "  ${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo ""
    exit 1
fi
