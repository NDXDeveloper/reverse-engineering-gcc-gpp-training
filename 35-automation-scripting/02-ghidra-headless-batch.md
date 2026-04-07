🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 35.2 — Automating Ghidra in Headless Mode (Batch Analysis of N Binaries)

> 🔧 **Tool covered**: `analyzeHeadless` (Ghidra >= 10.x)  
> 🐍 **Scripting language**: Ghidra Python (Jython 2.7) and Java — both are supported in headless mode  
> 📁 **Example binaries**: `keygenme_O0`, `keygenme_O2`, `keygenme_strip`, `crypto_O0`, `fileformat_O0`

---

## Why headless mode?

In Chapter 8, we used Ghidra via its graphical interface — the CodeBrowser — to import a binary, launch auto-analysis, navigate the disassembly and decompiler, rename functions, and reconstruct types. This workflow is effective on a single binary, but it becomes impractical as soon as the volume increases.

A few concrete situations where the graphical interface is no longer sufficient: analyzing the five variants of `keygenme` and producing a comparative report; scanning all binaries in a directory to list functions that call `strcmp`; extracting the decompiled pseudo-code of every function in a firmware; verifying that a production build does not contain forgotten debug symbols.

Ghidra exposes a non-graphical execution mode called **headless mode**, accessible via the `analyzeHeadless` script. This mode allows you to create a Ghidra project, import one or more binaries into it, run the full auto-analysis (the same as the GUI's), and execute scripts — all from the command line, without opening any window. This is the key to integrating Ghidra into automated pipelines.

---

## Locating and launching `analyzeHeadless`

The script is located in the `support/` directory of the Ghidra installation:

```bash
# Typical location
ls $GHIDRA_HOME/support/analyzeHeadless

# On a default installation
/opt/ghidra/support/analyzeHeadless
```

> 💡 **Tip**: create an alias or a symbolic link to simplify invocation:  
> ```bash  
> echo 'alias ghidra-headless="/opt/ghidra/support/analyzeHeadless"' >> ~/.bashrc  
> source ~/.bashrc  
> ```  
>  
> All examples in this section use this `ghidra-headless` alias.

The general syntax is:

```
ghidra-headless <project_dir> <project_name> [options]
```

The first two arguments are mandatory: the directory where the Ghidra project is stored (created automatically if it does not exist), and the project name. The rest consists of options that control import, analysis, and script execution.

---

## Importing and analyzing a binary

The minimal command to import a binary and launch auto-analysis:

```bash
ghidra-headless /tmp/ghidra_projects MyProject \
    -import keygenme_O0
```

Ghidra will:
1. Create the `MyProject` project in `/tmp/ghidra_projects/` (if it does not exist)  
2. Import `keygenme_O0` by automatically detecting the format (ELF x86-64)  
3. Run the full auto-analysis (disassembly, function detection, type propagation, cross-reference analysis)  
4. Save the result in the project  
5. Exit

The console output is verbose — Ghidra logs each step of the analysis. On a simple binary like `keygenme_O0`, the process takes a few seconds. On a multi-megabyte binary (like `crypto_static` statically linked), it can take several minutes.

### Useful import options

| Option | Effect |  
|---|---|  
| `-import <file>` | Imports a file into the project |  
| `-overwrite` | Overwrites a binary already present in the project |  
| `-recursive` | Imports all files from a directory |  
| `-readOnly` | Opens an existing binary without modifying it |  
| `-noanalysis` | Imports without running auto-analysis |  
| `-analysisTimeoutPerFile <sec>` | Limits analysis time per file |  
| `-max-cpu <n>` | Number of threads for analysis |  
| `-loader ElfLoader` | Forces the ELF loader (rarely needed) |

To import all Chapter 21 binaries in a single command:

```bash
ghidra-headless /tmp/ghidra_projects BatchCh21 \
    -import binaries/ch21-keygenme/keygenme_O0 \
            binaries/ch21-keygenme/keygenme_O2 \
            binaries/ch21-keygenme/keygenme_O3 \
            binaries/ch21-keygenme/keygenme_strip \
            binaries/ch21-keygenme/keygenme_O2_strip \
    -overwrite \
    -analysisTimeoutPerFile 120
```

Or, more concisely, using `-recursive` on the directory (Ghidra will automatically filter files it can parse):

```bash
ghidra-headless /tmp/ghidra_projects BatchCh21 \
    -import binaries/ch21-keygenme/ \
    -recursive \
    -overwrite
```

---

## Executing a post-analysis script

Headless mode becomes truly valuable when combined with a script that runs *after* auto-analysis, in the context of the imported binary. The script has access to the entire Ghidra API — the same API available in the GUI's Script Manager console.

### A first script: listing functions

Let us create a minimal Python script that lists all functions detected by Ghidra and writes them to a file:

```python
# list_functions.py — Ghidra headless script
# Execution: ghidra-headless ... -postScript list_functions.py

import json  
import os  

program = currentProgram  
name = program.getName()  
listing = program.getListing()  
func_mgr = program.getFunctionManager()  

functions = []  
func = func_mgr.getFunctionAt(program.getMinAddress())  
func_iter = func_mgr.getFunctions(True)  # True = forward  

for func in func_iter:
    functions.append({
        "name": func.getName(),
        "entry": "0x" + func.getEntryPoint().toString(),
        "size": func.getBody().getNumAddresses(),
        "is_thunk": func.isThunk(),
    })

# Write the result as JSON
output_dir = os.environ.get("GHIDRA_OUTPUT", "/tmp")  
output_path = os.path.join(output_dir, name + "_functions.json")  

with open(output_path, "w") as f:
    json.dump({"binary": name, "count": len(functions), "functions": functions},
              f, indent=2)

print("[+] {} functions written to {}".format(len(functions), output_path))
```

To execute it after import and analysis:

```bash
export GHIDRA_OUTPUT=/tmp/results  
mkdir -p $GHIDRA_OUTPUT  

ghidra-headless /tmp/ghidra_projects BatchCh21 \
    -import keygenme_O0 \
    -overwrite \
    -postScript list_functions.py
```

The `-postScript` option tells Ghidra to execute the script *after* auto-analysis. There is also `-preScript` (before analysis, useful for configuring analysis options) and `-scriptPath` (to specify a directory containing scripts).

> ⚠️ **Jython, not CPython**: headless Python scripts run in the Jython 2.7 interpreter embedded in Ghidra. This means the syntax is Python 2, native C modules (`numpy`, `lief`) are not available, and f-strings do not work. Use `format()` or `%` for formatting. The usual approach is to have the Ghidra script produce a JSON or CSV file, then post-process that file with a standard CPython script that has access to the full ecosystem.

### Passing arguments to the script

You can pass arguments to the script via the command line. They are accessible in the script through the global variable `args` (a list of strings):

```bash
ghidra-headless /tmp/ghidra_projects MyProject \
    -process keygenme_O0 \
    -postScript find_callers.py "strcmp" \
    -noanalysis  # the binary is already analyzed
```

```python
# find_callers.py — Find all functions that call a given symbol

target_name = args[0] if args else "strcmp"

func_mgr = currentProgram.getFunctionManager()  
symbol_table = currentProgram.getSymbolTable()  
ref_mgr = currentProgram.getReferenceManager()  

# Find the target symbol
symbols = symbol_table.getGlobalSymbols(target_name)  
if not symbols:  
    print("[-] Symbol '{}' not found".format(target_name))
else:
    for sym in symbols:
        addr = sym.getAddress()
        refs = ref_mgr.getReferencesTo(addr)
        callers = set()
        for ref in refs:
            caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
            if caller_func:
                callers.add(caller_func.getName())
        print("[+] Functions calling '{}':".format(target_name))
        for c in sorted(callers):
            print("    - {}".format(c))
```

On `keygenme_O0`, this script will show that `check_license` calls `strcmp` — the key information the learner is trying to locate in Chapter 21. On the stripped variant, the function will be named `FUN_00401xxx` (auto-generated name by Ghidra), but the reference to `strcmp@plt` will still be detected since it is a dynamic import.

---

## Processing an already imported binary: `-process`

When a binary is already in the Ghidra project (imported and analyzed during a previous run), there is no need to reimport it. The `-process` option opens an existing program from the project:

```bash
# Execute a script on an already analyzed binary
ghidra-headless /tmp/ghidra_projects BatchCh21 \
    -process keygenme_O0 \
    -postScript list_functions.py \
    -noanalysis
```

The `-noanalysis` option avoids re-running auto-analysis (unnecessary if the binary is already analyzed). This significantly speeds up execution when iterating on scripts.

To process *all* binaries in a project, omit the name after `-process`:

```bash
# Execute the script on every binary in the project
ghidra-headless /tmp/ghidra_projects BatchCh21 \
    -process \
    -postScript list_functions.py \
    -noanalysis
```

Ghidra will execute `list_functions.py` once per binary in the project. Each execution will have access to the `currentProgram` variable corresponding to the binary being processed. This is the fundamental mechanism of batch processing.

---

## Extracting decompiled pseudo-code

One of the most powerful features of Ghidra in headless mode is access to the decompiler. The following script extracts the C pseudo-code of all functions (or a targeted function) and saves it to a file:

```python
# decompile_all.py — Extract pseudo-code from all functions
# Usage: ghidra-headless ... -postScript decompile_all.py [function_name]

from ghidra.app.decompiler import DecompInterface  
import os  

# Initialize the decompiler
decomp = DecompInterface()  
decomp.openProgram(currentProgram)  

func_mgr = currentProgram.getFunctionManager()  
prog_name = currentProgram.getName()  

# If an argument is provided, only decompile that function
target = args[0] if args else None

output_dir = os.environ.get("GHIDRA_OUTPUT", "/tmp")  
output_path = os.path.join(output_dir, prog_name + "_decompiled.c")  

count = 0  
with open(output_path, "w") as out:  
    out.write("/* Decompiled from: {} */\n\n".format(prog_name))

    for func in func_mgr.getFunctions(True):
        if target and func.getName() != target:
            continue

        result = decomp.decompileFunction(func, 30, monitor)
        if result and result.getDecompiledFunction():
            code = result.getDecompiledFunction().getC()
            out.write("/* --- {} @ {} --- */\n".format(
                func.getName(), func.getEntryPoint()))
            out.write(code)
            out.write("\n\n")
            count += 1

decomp.dispose()  
print("[+] Decompiled {} functions -> {}".format(count, output_path))  
```

Run on `keygenme_O0`:

```bash
ghidra-headless /tmp/ghidra_projects BatchCh21 \
    -process keygenme_O0 \
    -postScript decompile_all.py "check_license" \
    -noanalysis
```

The resulting file will contain the C pseudo-code of `check_license`, including the calls to `compute_hash`, `derive_key`, `format_key`, and `strcmp`. This is the same pseudo-code visible in the GUI's Decompiler pane — but here, it is generated automatically and redirected into a file that can be consumed by other scripts.

Run next on `keygenme_O2`, you will observe the effects of optimization: some functions are inlined, temporary variables have disappeared, and the code structure is more condensed. Programmatically comparing the two decompiled files allows you to precisely document the impact of optimizations — what we did manually in Chapter 16.

---

## Detecting crypto constants in a batch

By combining the Ghidra API with known patterns, you can automatically scan a set of binaries for cryptographic constants. The following script searches for AES, SHA-256 magic constants and the XOR mask from Chapter 24:

```python
# scan_crypto_constants.py — Crypto constant detection
# Searches in .rodata and .data

import json  
import os  

CRYPTO_SIGS = {
    "AES_SBOX_FIRST_ROW": "637c777bf26b6fc53001672bfed7ab76",
    "SHA256_INIT_H0":     "6a09e667",
    "SHA256_INIT_H1":     "bb67ae85",
    "SHA256_K_FIRST":     "428a2f98",
    "DEADBEEF_BE":        "deadbeef",       # big-endian (byte arrays, e.g., KEY_MASK ch24)
    "DEADBEEF_LE":        "efbeadde",       # little-endian (imm32 operand x86, e.g., HASH_XOR ch21)
    "CAFEBABE_BE":        "cafebabe",
    "CH24_KEY_MASK_HEAD": "deadbeefcafebabe",
}

prog_name = currentProgram.getName()  
memory = currentProgram.getMemory()  
results = []  

for label, hex_pattern in CRYPTO_SIGS.items():
    pattern_bytes = hex_pattern.decode("hex")
    # Search across the entire program memory
    addr = memory.findBytes(
        currentProgram.getMinAddress(),
        pattern_bytes,
        None,  # mask (None = exact match)
        True,  # forward
        monitor
    )
    if addr:
        # Identify which section the address falls in
        block = memory.getBlock(addr)
        block_name = block.getName() if block else "unknown"
        results.append({
            "constant": label,
            "address": "0x" + addr.toString(),
            "section": block_name,
        })
        print("[+] {} found at {} ({})".format(label, addr, block_name))

if not results:
    print("[-] No crypto constants found in {}".format(prog_name))

# Save
output_dir = os.environ.get("GHIDRA_OUTPUT", "/tmp")  
output_path = os.path.join(output_dir, prog_name + "_crypto_scan.json")  
with open(output_path, "w") as f:  
    json.dump({"binary": prog_name, "findings": results}, f, indent=2)
```

Run in batch on Chapter 24 binaries, this script will detect the mask `DE AD BE EF CA FE BA BE` in `.rodata` (the first eight bytes of `KEY_MASK`, stored as a byte array in big-endian). On Chapter 21 binaries, it will find `DEADBEEF_LE` (`EF BE AD DE`) in `.text`, corresponding to the immediate operand of the `xor` instruction that applies `HASH_XOR` in `compute_hash` — on x86, 32-bit integers are encoded in little-endian in the instruction stream. On Chapter 25 binaries, no crypto constant will be detected — the XOR key `{0x5A, 0x3C, 0x96, 0xF1}` is too short and too generic to appear in a standard signature database.

---

## Complete pipeline: from directory to JSON report

Here is the typical workflow for analyzing an entire directory of binaries and producing a consolidated report. We use a shell script that orchestrates the calls to `analyzeHeadless`, then a standard Python script (CPython) that merges the results.

### Step 1: shell orchestration script

```bash
#!/bin/bash
# batch_ghidra.sh — Analyze a directory of binaries with Ghidra headless
#
# Usage: ./batch_ghidra.sh <binaries_dir> <output_dir>

BINARIES_DIR="${1:?Usage: $0 <binaries_dir> <output_dir>}"  
OUTPUT_DIR="${2:?Usage: $0 <binaries_dir> <output_dir>}"  
PROJECT_DIR="/tmp/ghidra_batch_$$"  
PROJECT_NAME="batch"  
SCRIPT_DIR="$(dirname "$0")/ghidra_scripts"  

mkdir -p "$OUTPUT_DIR" "$PROJECT_DIR"

export GHIDRA_OUTPUT="$OUTPUT_DIR"

echo "=== Phase 1: Import and analysis ==="  
ghidra-headless "$PROJECT_DIR" "$PROJECT_NAME" \  
    -import "$BINARIES_DIR" \
    -recursive \
    -overwrite \
    -analysisTimeoutPerFile 300 \
    -max-cpu 4

echo ""  
echo "=== Phase 2: Function extraction ==="  
ghidra-headless "$PROJECT_DIR" "$PROJECT_NAME" \  
    -process \
    -postScript "${SCRIPT_DIR}/list_functions.py" \
    -noanalysis

echo ""  
echo "=== Phase 3: Crypto scan ==="  
ghidra-headless "$PROJECT_DIR" "$PROJECT_NAME" \  
    -process \
    -postScript "${SCRIPT_DIR}/scan_crypto_constants.py" \
    -noanalysis

echo ""  
echo "=== Phase 4: Consolidation ==="  
python3 "${SCRIPT_DIR}/merge_reports.py" "$OUTPUT_DIR"  

# Clean up temporary project
rm -rf "$PROJECT_DIR"

echo ""  
echo "[+] Final report: ${OUTPUT_DIR}/report.json"  
```

The separation into phases is deliberate. Phase 1 (import + analysis) is the most expensive in time and CPU. Phases 2 and 3 reuse the already analyzed project with `-process` and `-noanalysis`, making them fast. If you add a new extraction script later, you simply add a phase — without re-running the analysis.

### Step 2: consolidation script (CPython)

```python
#!/usr/bin/env python3
# merge_reports.py — Merge JSON files produced by Ghidra scripts
#
# Usage: python3 merge_reports.py <output_dir>

import json  
import sys  
from pathlib import Path  

output_dir = Path(sys.argv[1])  
report = {}  

# Merge function reports
for path in sorted(output_dir.glob("*_functions.json")):
    with open(path) as f:
        data = json.load(f)
    binary_name = data["binary"]
    report.setdefault(binary_name, {})
    report[binary_name]["functions"] = data

# Merge crypto reports
for path in sorted(output_dir.glob("*_crypto_scan.json")):
    with open(path) as f:
        data = json.load(f)
    binary_name = data["binary"]
    report.setdefault(binary_name, {})
    report[binary_name]["crypto"] = data

# Summary
summary = []  
for name, data in sorted(report.items()):  
    func_count = data.get("functions", {}).get("count", 0)
    crypto_count = len(data.get("crypto", {}).get("findings", []))
    summary.append({
        "binary": name,
        "functions_detected": func_count,
        "crypto_constants": crypto_count,
    })

final = {
    "summary": summary,
    "details": report,
}

output_path = output_dir / "report.json"  
with open(output_path, "w") as f:  
    json.dump(final, f, indent=2)

print(f"[+] Report: {output_path}")  
print(f"    {len(report)} binaries analyzed")  
for s in summary:  
    flag = " [CRYPTO]" if s["crypto_constants"] > 0 else ""
    print(f"    {s['binary']:<25} {s['functions_detected']:>4} functions{flag}")
```

The result is a single, structured `report.json` file, consumable by any downstream tool — a web dashboard, a diff against a previous report, or simply a `jq` command on the command line:

```bash
# Which binaries contain crypto constants?
jq '.summary[] | select(.crypto_constants > 0)' report.json

# How many functions in each keygenme variant?
jq '.summary[] | select(.binary | startswith("keygenme"))
    | {binary, functions_detected}' report.json
```

---

## Java vs Python scripts: when to choose one or the other

Ghidra supports two languages for headless scripts: Java and Python (Jython). The choice depends on what you are doing.

**Python (Jython)** is the default choice for extraction and reporting scripts. The syntax is concise, prototyping is fast, and most community examples are in Python. The main limitation is the lack of support for native CPython modules and the Python 2 syntax.

**Java** is preferable when the script deeply interacts with Ghidra's internal structures — for example, to create complex data types, manipulate the control flow graph, or call internal APIs not exposed in Python. Java scripts also have the advantage of being more performant on heavy analyses (traversing millions of instructions).

In practice within a batch pipeline, extraction scripts are written in Python (more readable, faster to develop) and Java is reserved for cases where performance or access to a specific API requires it.

> 💡 **Ghidra 11+** is gradually introducing Python 3 support via Pyhidra/Jpype. At the time of writing, the classic headless mode remains on Jython 2.7. If you are using a recent version of Ghidra, check the documentation to verify the status of Python 3 support in headless mode.

---

## Practical considerations

### Performance and resources

Ghidra's auto-analysis is memory-intensive. For a batch of many binaries, you need to adjust the JVM parameters. The `support/analyzeHeadless.bat` file (or the equivalent shell script) contains the `-Xmx` and `-Xms` options. For a heavy batch:

```bash
# In support/launch.properties (or via environment variable)
MAXMEM=8G
```

If the batch involves dozens of large binaries, it is often more efficient to parallelize by launching multiple `analyzeHeadless` instances on separate projects, then merging the results in post-processing — rather than loading everything into a single project.

### Error handling

A corrupted binary or unsupported format must not interrupt the batch. Ghidra is robust when facing invalid files — it will ignore them with an error message in the console — but it is good practice to capture return codes in the shell script:

```bash
ghidra-headless "$PROJECT_DIR" "$PROJECT_NAME" \
    -import "$file" \
    -overwrite \
    -postScript list_functions.py 2>&1 | tee "$OUTPUT_DIR/ghidra_log_${base}.txt"

if [ $? -ne 0 ]; then
    echo "[WARN] Ghidra returned non-zero for $file"
fi
```

### Reproducibility

For the same script to produce the same result on the same binary on every run, you need to control two things: the Ghidra version (auto-analysis evolves between versions) and the analysis options. You can force specific options via a `-preScript`:

```python
# set_analysis_options.py — Ensure consistent analysis options
from ghidra.program.util import GhidraProgramUtilities

# Disable analyzers that add noise or take too much time
setAnalysisOption(currentProgram, "Demangler GNU", "true")  
setAnalysisOption(currentProgram, "Stack", "true")  
setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "false")  
```

```bash
ghidra-headless "$PROJECT_DIR" "$PROJECT_NAME" \
    -import keygenme_O0 \
    -preScript set_analysis_options.py \
    -postScript list_functions.py \
    -overwrite
```

---

## Summary of key commands

| Action | Command |  
|---|---|  
| Import + analyze a binary | `ghidra-headless <dir> <proj> -import <bin>` |  
| Import an entire directory | `... -import <dir> -recursive` |  
| Execute a script after analysis | `... -postScript <script.py>` |  
| Execute a script before analysis | `... -preScript <script.py>` |  
| Pass arguments to the script | `... -postScript <script.py> "arg1" "arg2"` |  
| Process an already imported binary | `... -process <name> -noanalysis -postScript ...` |  
| Process all binaries in the project | `... -process -noanalysis -postScript ...` |  
| Specify the script directory | `... -scriptPath <dir>` |  
| Limit analysis time | `... -analysisTimeoutPerFile 300` |  
| Overwrite existing imports | `... -overwrite` |

---

*-> Next section: [35.3 — RE Scripting with `pwntools`](/35-automation-scripting/03-scripting-pwntools.md)*

⏭️ [RE Scripting with `pwntools` (interactions, patching, exploitation)](/35-automation-scripting/03-scripting-pwntools.md)
