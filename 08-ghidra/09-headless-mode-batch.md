🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.9 — Ghidra in headless mode for batch processing

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## What is headless mode?

Until now, all interactions with Ghidra went through the graphical interface: the Project Manager for managing projects, the CodeBrowser for navigating and annotating. **Headless mode** (without graphical interface) allows running Ghidra entirely on the command line. No window, no click, no display — only a process that imports binaries, launches automatic analysis, runs scripts, and produces results on standard output or in files.

This mode is designed for scenarios where human intervention is not necessary or not desirable:

- **Batch analysis** — automatically analyze 50, 100, or 1000 binaries at once, for example all versions of a firmware, all executables in a suspicious directory, or all optimization variants of your training binaries.  
- **CI/CD integration** — integrate Ghidra analysis into a continuous-integration pipeline to automatically audit each build of a project (binary regression detection, protection verification, metrics extraction).  
- **Data extraction** — run a script that extracts structured information (lists of functions, strings, crypto constants, signatures) and writes the result into a JSON, CSV, or database file.  
- **Pre-analysis** — prepare a Ghidra project with automatic analysis completed before opening it in the CodeBrowser. This saves waiting time during interactive opening, especially for large binaries.  
- **Analysis server** — deploy Ghidra on a server machine (without a screen) to process analysis requests on demand.

---

## The `analyzeHeadless` tool

The entry point of headless mode is the `analyzeHeadless` script, located in the `support/` directory of the Ghidra installation:

```
/opt/ghidra/support/analyzeHeadless
```

It's a shell script (Linux/macOS) or batch (Windows) that configures the JVM and launches Ghidra in non-interactive mode. To simplify usage, create an alias:

```bash
alias analyzeHeadless='/opt/ghidra/support/analyzeHeadless'
```

### General syntax

```bash
analyzeHeadless <project_dir> <project_name> [options]
```

The first two arguments are mandatory:

- `<project_dir>` — the directory containing (or to contain) the Ghidra project. If the directory doesn't exist, Ghidra creates it.  
- `<project_name>` — the name of the project (matching the `.gpr` file). If the project doesn't exist, Ghidra creates it automatically.

Everything else is controlled by options.

---

## Fundamental commands

### Import and analyze a binary

The most basic command imports a binary into a project, launches automatic analysis, and terminates:

```bash
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -import binaries/ch08-keygenme/keygenme_O0
```

Ghidra:

1. Creates the `HeadlessProject` project in `~/ghidra-projects/` if it doesn't exist.  
2. Imports the `keygenme_O0` file, automatically detects the format (ELF) and architecture (x86-64).  
3. Launches complete automatic analysis (all default analyzers).  
4. Saves the result in the project's database.  
5. Terminates the process.

The terminal output displays progress messages: successful import, executed analyzers, number of detected functions, elapsed time.

### Import multiple binaries

You can specify multiple files or an entire directory:

```bash
# Multiple files
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -import keygenme_O0 keygenme_O2 keygenme_O3

# An entire directory (all files will be imported)
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -import binaries/ch08-keygenme/
```

When you import a directory, Ghidra tries to import each file. Unrecognized files (Makefiles, `.c` source files, README) are ignored with a warning message.

### Work on an existing project (without import)

If the project already exists and contains analyzed binaries, you can run a script without reimporting:

```bash
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -process -noanalysis \
    -postScript my_script.py
```

The `-process` option without arguments processes **all** files in the project. To target a specific binary:

```bash
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -process keygenme_O0 -noanalysis \
    -postScript my_script.py
```

The `-noanalysis` option avoids relaunching automatic analysis on an already analyzed binary. Without this option, Ghidra would relaunch the complete analysis, which is useless if the binary was already processed.

---

## Running scripts in headless mode

### The `-preScript` and `-postScript` options

Headless mode really shines when it executes scripts. Two insertion points are available:

**`-preScript <script> [args...]`** — Executes the script **before** automatic analysis. Useful for configuring analysis options, defining pre-existing types, or modifying parameters before analyzers launch.

**`-postScript <script> [args...]`** — Executes the script **after** automatic analysis. It's the most common case: analysis was performed, the script exploits the results (data extraction, renaming, report generation).

You can chain multiple scripts:

```bash
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -import keygenme_O0 \
    -postScript rename_network_funcs.py \
    -postScript export_functions_json.py "/tmp/report.json"
```

Scripts are executed in the specified order. Additional arguments after the script name are passed to the script and accessible via `getScriptArgs()` in the Flat API.

### Passing arguments to scripts

In the Python script:

```python
args = getScriptArgs()  
if len(args) > 0:  
    output_path = args[0]
else:
    output_path = "/tmp/ghidra_export.json"

println("Export to: {}".format(output_path))
```

On the command line:

```bash
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -process keygenme_O0 -noanalysis \
    -postScript export_functions_json.py "/tmp/keygenme_report.json"
```

### Script locations

Ghidra searches for scripts in configured directories. By default:

- `~/ghidra_scripts/` — your personal scripts.  
- Ghidra's built-in script directories (in `Ghidra/Features/*/ghidra_scripts/`).

You can add additional directories via the `-scriptPath` option:

```bash
analyzeHeadless ~/ghidra-projects HeadlessProject \
    -import keygenme_O0 \
    -scriptPath /home/user/re-training/scripts/ \
    -postScript my_custom_script.py
```

---

## Important options

### Analysis control

| Option | Role |  
|---|---|  
| `-noanalysis` | Do not launch automatic analysis. Useful if you only want to import or run a script on an already-analyzed binary. |  
| `-analysisTimeoutPerFile <seconds>` | Limits analysis time per file. Indispensable for batch: a malformed or very complex binary will not block the whole chain. |

### Import control

| Option | Role |  
|---|---|  
| `-import <path>` | Imports the specified file or directory. |  
| `-overwrite` | Overwrites a binary already in the project instead of ignoring it. Useful when reimporting a recompiled version. |  
| `-recursive` | Imports subdirectories recursively. |  
| `-loader <loader>` | Forces a specific loader (for example `ElfLoader` or `BinaryLoader`). Rarely necessary — automatic detection is reliable. |  
| `-processor <language_id>` | Forces the architecture. For example `-processor x86:LE:64:default` to force x86-64. Useful for raw files without headers. |

### Output control

| Option | Role |  
|---|---|  
| `-deleteProject` | Deletes the project after processing. Useful when the project is temporary and only the script's output matters. |  
| `-log <logfile>` | Redirects Ghidra logs to a file. Recommended for batch to keep a trace of errors. |  
| `-scriptlog <logfile>` | Specifically redirects script output (`println`) to a file separate from Ghidra's system logs. |

---

## Complete example: batch analysis of a directory

Here is a complete scenario that illustrates the power of headless mode. The goal is to analyze all binaries in the `binaries/ch08-keygenme/` directory, extract for each the list of functions with their sizes and cross-references, and write the result in a JSON file.

### The extraction script

Create the `~/ghidra_scripts/batch_export.py` file:

```python
# Function export in JSON for batch analysis
# @category Export
# @author RE Training

import json  
import os  

args = getScriptArgs()  
output_dir = args[0] if len(args) > 0 else "/tmp/ghidra_batch"  

# Create the output directory if needed
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

program_name = currentProgram.getName()  
output_file = os.path.join(output_dir, program_name + ".json")  

functions_data = []  
fm = currentProgram.getFunctionManager()  

for func in fm.getFunctions(True):
    monitor.checkCancelled()
    
    entry = func.getEntryPoint().toString()
    name = func.getName()
    size = func.getBody().getNumAddresses()
    
    # Count incoming XREFs (calls to this function)
    refs_to = getReferencesTo(func.getEntryPoint())
    call_count = 0
    for ref in refs_to:
        if ref.getReferenceType().isCall():
            call_count += 1
    
    # List called functions
    called = []
    for called_func in func.getCalledFunctions(monitor):
        called.append(called_func.getName())
    
    functions_data.append({
        "name": name,
        "address": entry,
        "size": int(size),
        "callers": call_count,
        "calls": called,
        "is_thunk": func.isThunk(),
        "is_external": func.isExternal()
    })

# Program metadata
report = {
    "program": program_name,
    "format": currentProgram.getExecutableFormat(),
    "language": currentProgram.getLanguageID().toString(),
    "compiler": currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
    "function_count": len(functions_data),
    "functions": functions_data
}

with open(output_file, "w") as f:
    f.write(json.dumps(report, indent=2))

println("Export finished: {} functions -> {}".format(len(functions_data), output_file))
```

### The batch command

```bash
analyzeHeadless ~/ghidra-projects BatchAnalysis \
    -import binaries/ch08-keygenme/ \
    -recursive \
    -overwrite \
    -analysisTimeoutPerFile 300 \
    -postScript batch_export.py "/tmp/keygenme_reports" \
    -log /tmp/ghidra_batch.log \
    -scriptlog /tmp/ghidra_script.log
```

This command:

1. Creates the `BatchAnalysis` project.  
2. Recursively imports all binaries from `binaries/ch08-keygenme/`.  
3. Analyzes each binary with a 5-minute timeout.  
4. Runs `batch_export.py` on each analyzed binary, passing the output directory as an argument.  
5. Writes logs to separate files.

The result is one JSON file per binary in `/tmp/keygenme_reports/`:

```
/tmp/keygenme_reports/
├── keygenme_O0.json
├── keygenme_O0_strip.json
├── keygenme_O2.json
├── keygenme_O2_strip.json
└── keygenme_O3.json
```

Each file contains the program's metadata and the complete list of its functions with their attributes. These files can then be exploited by an external Python script to compare binaries, produce statistics, or feed a dashboard.

---

## Pipeline integration

### Orchestration shell script

For regular use, encapsulate the `analyzeHeadless` command in a shell script that handles parameters, directories, and cleanup:

```bash
#!/bin/bash
# analyze_batch.sh — Batch analysis with headless Ghidra

GHIDRA_HOME="/opt/ghidra"  
HEADLESS="${GHIDRA_HOME}/support/analyzeHeadless"  
PROJECT_DIR="/tmp/ghidra_batch_$$"  
PROJECT_NAME="batch"  
INPUT_DIR="${1:?Usage: $0 <input_dir> <output_dir>}"  
OUTPUT_DIR="${2:?Usage: $0 <input_dir> <output_dir>}"  
TIMEOUT=300  

mkdir -p "${OUTPUT_DIR}"

echo "[*] Analyzing ${INPUT_DIR}..."
"${HEADLESS}" "${PROJECT_DIR}" "${PROJECT_NAME}" \
    -import "${INPUT_DIR}" \
    -recursive \
    -overwrite \
    -analysisTimeoutPerFile ${TIMEOUT} \
    -postScript batch_export.py "${OUTPUT_DIR}" \
    -log "${OUTPUT_DIR}/ghidra.log" \
    -scriptlog "${OUTPUT_DIR}/script.log" \
    -deleteProject \
    2>&1 | tail -20

echo "[*] Results in ${OUTPUT_DIR}"  
echo "[*] $(ls -1 "${OUTPUT_DIR}"/*.json 2>/dev/null | wc -l) file(s) generated"  
```

Usage:

```bash
chmod +x analyze_batch.sh
./analyze_batch.sh binaries/ch08-keygenme/ /tmp/reports/
```

The `-deleteProject` option removes the temporary project after processing — only the JSON output files are kept. The PID (`$$`) in the project directory name avoids conflicts if multiple instances run in parallel.

### CI/CD integration

In a continuous-integration pipeline (Jenkins, GitLab CI, GitHub Actions), headless mode allows automatically verifying properties of the binary at each build:

- **Protection verification** — a post-analysis script verifies that the binary has PIE, NX, canary, and Full RELRO enabled, and fails the build if a protection is missing.  
- **Regression detection** — comparison of the number of functions, exported symbols, or crypto constants between two versions of the binary.  
- **Signature extraction** — automatic generation of YARA signatures from constants and patterns detected in the binary.

Chapter 35 (Automation and scripting) will detail a complete CI/CD pipeline with headless Ghidra.

---

## Performance and resources

### Memory consumption

Headless mode consumes as much memory as the graphical interface — or more if you process large binaries sequentially without unloading previous ones. Configure the JVM memory in `support/analyzeHeadless` or via the `MAXMEM` environment variable:

```bash
MAXMEM=8G analyzeHeadless ~/projects BatchProject -import big_binary
```

For a batch of small binaries (< 1 MB each), 4 GB suffice. For large binaries (> 10 MB) or C++ with STL, plan 8 GB or more.

### Execution time

Analysis time depends on the size and complexity of the binary:

| Type of binary | Typical size | Approx. analysis time |  
|---|---|---|  
| Small C binary (`keygenme`) | 10-50 KB | 5-15 seconds |  
| Medium C application | 100 KB - 1 MB | 30 seconds - 2 minutes |  
| C++ application with STL | 1-10 MB | 2-10 minutes |  
| Large binary (server, game) | 10-100 MB | 10-60 minutes |

These times are indicative and vary strongly according to the CPU, available memory, and code complexity (cross-reference density, number of functions, C++ template depth).

The `-analysisTimeoutPerFile` option is essential for batch: it prevents a pathological binary (highly obfuscated, unusual format) from blocking the whole processing. A value of 300 seconds (5 minutes) is a good compromise for moderate-sized binaries.

### Parallelization

`analyzeHeadless` processes binaries **sequentially** within a single invocation. To parallelize, launch multiple instances on subsets of binaries in **separate projects** (Ghidra locks the project — two instances cannot write to the same project simultaneously):

```bash
# Process batches in parallel
analyzeHeadless /tmp/proj_1 batch -import lot_1/ -postScript export.py &  
analyzeHeadless /tmp/proj_2 batch -import lot_2/ -postScript export.py &  
analyzeHeadless /tmp/proj_3 batch -import lot_3/ -postScript export.py &  
wait  
echo "All batches finished"  
```

Each instance consumes its own JVM memory. With 4 instances at 4 GB each, plan 16 GB of available RAM.

---

## Common troubleshooting

**"Java not found" or "Unsupported Java version"** — Verify that `JAVA_HOME` points to a JDK 17+ and that `java -version` confirms the right version. The `analyzeHeadless` script uses the same Java configuration as the graphical interface.

**"Project is locked"** — Another Ghidra process (graphical interface or another headless instance) has locked the project. Close the other instance or use a different project name. In case of a crash, a residual `.lock` file may persist in the `.rep/` directory — delete it manually.

**Script not found** — Verify that the script is in `~/ghidra_scripts/` or in a directory referenced by `-scriptPath`. The name must match exactly, extension included.

**Timeout exceeded** — The binary is too complex for the configured timeout. Increase `-analysisTimeoutPerFile` or analyze this binary separately with a longer timeout.

**OutOfMemoryError** — The JVM lacks memory. Increase `MAXMEM` as described above. For very large binaries, 16 GB may be necessary.

---

## Summary

Headless mode is the natural extension of Ghidra scripting towards complete automation. The `analyzeHeadless` tool allows importing, analyzing, and scripting binaries entirely on the command line, without a graphical interface. Combined with Python or Java scripts developed in section 8.8, it opens the way to batch analysis of binary collections, CI/CD pipeline integration, and systematic production of structured reports. The timeout, logging, and project-management options make the process robust for production use.

This is the last technical section of this chapter. The checkpoint that follows will let you validate all the skills acquired by importing a C++ binary into Ghidra and reconstructing its class hierarchy.

---


⏭️ [🎯 Checkpoint: import `ch20-oop` into Ghidra, reconstruct the class hierarchy](/08-ghidra/checkpoint.md)
