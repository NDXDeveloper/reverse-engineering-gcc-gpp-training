🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 9.4 — Scripting with r2pipe (Python)

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [9.3 — `r2`: essential commands](/09-ida-radare2-binja/03-r2-essential-commands.md)

---

## Why script analysis?

Section 9.3 showed how to conduct a complete analysis in `r2`'s interactive shell. This approach works well for a single target, but it reaches its limits as soon as the task becomes repetitive or voluminous: analyzing 50 binaries from the same malware campaign, systematically extracting strings and imports from each sample, searching for a specific pattern in all functions of a large binary, or producing a structured report from analysis results.

That's exactly `r2pipe`'s role: a programming interface that allows controlling Radare2 from a high-level language. You write Python (or JavaScript, Go, Rust — but Python is by far the most used), and each call sends an `r2` command to the engine, retrieves the output, and returns it as a string or directly exploitable JSON structure.

The advantage over pure shell scripting (`r2 -qc '...' | grep | awk`) is considerable: you have all of Python's power for parsing, conditional logic, report generation, interaction with other tools (databases, APIs, frameworks like `pwntools` or `angr`), and error handling.

## Installing r2pipe

`r2pipe` is a lightweight Python module that communicates with `r2` via a pipe or socket. It does not contain the analysis engine itself — Radare2 must be installed separately (cf. section 9.2).

```bash
pip install r2pipe
```

Quick verification:

```bash
python3 -c "import r2pipe; print(r2pipe.version())"
```

> 💡 If you use a Python virtual environment (recommended), activate it before installation. The `r2pipe` module has no heavy dependencies: it weighs a few tens of kilobytes.

## First steps: opening a binary and sending commands

### Connecting to a binary

```python
import r2pipe

# Open a binary — launches an r2 instance in the background
r2 = r2pipe.open("keygenme_O2_strip")

# Launch deep analysis
r2.cmd("aaa")

# Send a command and retrieve the text output
output = r2.cmd("afl")  
print(output)  

# Close the session
r2.quit()
```

The `r2pipe.open()` method accepts several types of targets:

- A path to a binary file — launches a new `r2` instance in the background.  
- `"-"` — connects to the parent `r2` session if the script is launched from the `r2` shell with the command `#!pipe python script.py`.  
- An `http://host:port` URL — connects to a remote `r2` instance launched with `r2 -c 'h' binary` (built-in HTTP server).

### `cmd()` vs `cmdj()`: raw text or JSON

The distinction between these two methods is fundamental in any `r2pipe` script.

**`cmd(command)`** sends the command and returns the raw output as a Python string. It's the exact equivalent of typing the command in the `r2` shell and copy-pasting the result. The output is human-readable tabular text, but tedious to parse programmatically.

```python
# Text output — you'd have to parse each line manually
text = r2.cmd("afl")
# "0x00401050    1     46 entry0\n0x00401080    4     31 sym.deregister..."
```

**`cmdj(command)`** sends the command with the `j` (JSON) suffix and automatically parses the output into a Python object (list or dictionary). It's the method to systematically prefer when structured output is available.

```python
# JSON output — directly exploitable
functions = r2.cmdj("aflj")
# [{"offset": 4198480, "name": "entry0", "size": 46, "nbbs": 1, ...}, ...]

for fn in functions:
    print(f"{fn['name']:40s}  addr=0x{fn['offset']:08x}  size={fn['size']}")
```

> ⚠️ Not all `r2` commands support the `j` suffix. If `cmdj()` receives non-JSON output, it will raise an exception or return `None`. When in doubt, check in the interactive shell that the command with `j` does produce JSON before using it in a script.

## Anatomy of an analysis script

Let's see a complete script that performs automatic triage of our running-thread binary. This script reproduces in a few seconds the manual workflow we unrolled in previous sections.

```python
#!/usr/bin/env python3
"""
triage_r2.py — Automatic triage of an ELF binary with r2pipe.  
Usage: python3 triage_r2.py <binary_path>  
"""

import sys  
import json  
import r2pipe  


def triage(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Deep analysis

    report = {}

    # ── 1. General information ──
    info = r2.cmdj("iIj")
    report["file"] = binary_path
    report["arch"] = info.get("arch", "unknown")
    report["bits"] = info.get("bits", 0)
    report["os"] = info.get("os", "unknown")
    report["stripped"] = info.get("stripped", False)
    report["canary"] = info.get("canary", False)
    report["nx"] = info.get("nx", False)
    report["pic"] = info.get("pic", False)
    report["relro"] = info.get("relro", "none")

    # ── 2. Sections ──
    sections = r2.cmdj("iSj")
    report["sections"] = [
        {"name": s["name"], "size": s["size"], "perm": s["perm"]}
        for s in sections
        if s.get("size", 0) > 0
    ]

    # ── 3. Imports ──
    imports = r2.cmdj("iij")
    report["imports"] = [imp["name"] for imp in imports] if imports else []

    # ── 4. Detected functions ──
    functions = r2.cmdj("aflj")
    report["function_count"] = len(functions) if functions else 0

    # Separate application functions from infrastructure functions
    infra_prefixes = (
        "sym.deregister_tm", "sym.register_tm", "sym.frame_dummy",
        "sym.__libc_csu", "sym.__do_global", "entry", "sym._init",
        "sym._fini", "sym.imp."
    )
    app_functions = [
        {"name": fn["name"], "addr": hex(fn["offset"]), "size": fn["size"]}
        for fn in (functions or [])
        if not fn["name"].startswith(infra_prefixes)
    ]
    report["app_functions"] = app_functions

    # ── 5. Interesting strings ──
    strings = r2.cmdj("izj")
    report["strings"] = [
        {"value": s["string"], "addr": hex(s["vaddr"]), "section": s["section"]}
        for s in (strings or [])
        if len(s.get("string", "")) > 3  # ignore very short strings
    ]

    # ── 6. Summary of calls in main ──
    r2.cmd("s main")
    summary = r2.cmd("pds")
    report["main_summary"] = summary.strip().split("\n") if summary else []

    r2.quit()
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>", file=sys.stderr)
        sys.exit(1)

    result = triage(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False))
```

### Execution

```bash
$ python3 triage_r2.py keygenme_O2_strip
{
  "file": "keygenme_O2_strip",
  "arch": "x86",
  "bits": 64,
  "os": "linux",
  "stripped": true,
  "canary": false,
  "nx": true,
  "pic": false,
  "relro": "partial",
  "sections": [
    {"name": ".text", "size": 418, "perm": "-r-x"},
    {"name": ".rodata", "size": 45, "perm": "-r--"},
    ...
  ],
  "imports": ["puts", "strcmp", "__isoc99_scanf"],
  "function_count": 9,
  "app_functions": [
    {"name": "sym.transform_key", "addr": "0x401120", "size": 63},
    {"name": "main", "addr": "0x401160", "size": 98}
  ],
  "strings": [
    {"value": "Enter key: ", "addr": "0x402000", "section": ".rodata"},
    {"value": "Access granted", "addr": "0x40200e", "section": ".rodata"},
    {"value": "Wrong key", "addr": "0x40201d", "section": ".rodata"}
  ],
  "main_summary": [
    "0x0040116b call sym.imp.puts           ; \"Enter key: \"",
    "0x00401181 call sym.imp.__isoc99_scanf",
    "0x00401193 call sym.imp.strcmp",
    "0x004011a3 call sym.imp.puts           ; \"Access granted\"",
    "0x004011b5 call sym.imp.puts           ; \"Wrong key\""
  ]
}
```

In about twenty lines of logic, the script produces a complete and structured JSON report. This report can be stored in a database, compared with other samples, or integrated into a broader analysis pipeline.

### Key points of the script

A few observations on design choices, transposable to any `r2pipe` script:

The script uses `cmdj()` everywhere possible and `cmd()` only for `pds` which doesn't have a reliable JSON mode. It's the golden rule: always prefer structured output.

Filtering out GCC infrastructure functions (`deregister_tm_clones`, `register_tm_clones`, etc.) is done on the Python side rather than in `r2`. It's more readable and maintainable than building `r2` commands with complex filters.

The call `r2.cmd("s main")` moves the seek in the `r2` session before calling `pds`. Each `r2` command executes in the context of the current session — the seek, flags, and comments persist from one command to the next within the same `r2pipe.open()` session.

Explicit closing with `r2.quit()` is important to release the `r2` process in the background. In case of looping over many binaries, forgetting this `quit()` can saturate system resources.

## Common use cases

### Extract cross-references to a string

```python
import r2pipe

r2 = r2pipe.open("keygenme_O2_strip")  
r2.cmd("aaa")  

# Find the address of the "Access granted" string
strings = r2.cmdj("izj")  
target = next(s for s in strings if "granted" in s.get("string", ""))  

# Get XREFs to this string
r2.cmd(f"s {target['vaddr']}")  
xrefs = r2.cmdj("axtj")  

for xref in xrefs:
    print(f"Referenced by: {xref.get('fcn_name', '?')} "
          f"@ 0x{xref['from']:x} "
          f"(type: {xref['type']})")

r2.quit()
```

This pattern — find a string, trace back XREFs, identify the calling function — is the foundation of automated analysis. It's directly transposable to more complex scenarios: find all functions that call `recv()` in a network binary, identify all functions that access a suspicious global variable, etc.

### List calls to imported functions in each function

```python
import r2pipe

r2 = r2pipe.open("keygenme_O2_strip")  
r2.cmd("aaa")  

functions = r2.cmdj("aflj") or []

for fn in functions:
    r2.cmd(f"s {fn['offset']}")
    summary = r2.cmd("pds").strip()

    if not summary:
        continue

    calls = [line for line in summary.split("\n") if "call" in line]
    if calls:
        print(f"\n── {fn['name']} (0x{fn['offset']:x}) ──")
        for c in calls:
            print(f"  {c.strip()}")

r2.quit()
```

This script produces a dependency map of each function: which imported functions it calls, and with what arguments (strings are annotated by `pds`). On a large binary, this map is a considerable analysis accelerator: it allows spotting in a few seconds the "interesting" functions (those that call encryption, network, file functions…) among hundreds of anonymous functions.

### Batch analysis of multiple binaries

```python
import r2pipe  
import json  
import glob  


def extract_info(path):
    r2 = r2pipe.open(path)
    r2.cmd("aaa")

    info = r2.cmdj("iIj") or {}
    imports = r2.cmdj("iij") or []
    strings = r2.cmdj("izj") or []

    result = {
        "file": path,
        "stripped": info.get("stripped", False),
        "nx": info.get("nx", False),
        "imports": [i["name"] for i in imports],
        "string_count": len(strings),
        "crypto_hints": [
            s["string"] for s in strings
            if any(kw in s.get("string", "").lower()
                   for kw in ("aes", "key", "encrypt", "decrypt", "cipher"))
        ]
    }

    r2.quit()
    return result


# Analyze all binaries in a directory
results = []  
for binary in glob.glob("binaries/ch09-keygenme/keygenme_*"):  
    print(f"Analyzing {binary}...", flush=True)
    results.append(extract_info(binary))

# Global report
print(json.dumps(results, indent=2))
```

This script analyzes all keygenme variants (`_O0`, `_O2`, `_O3`, `_strip`, `_O2_strip`) and produces a comparative report. You could extend it with metrics: number of functions, `.text` size, ratio of functions recognized by FLIRT, etc. This is the seed of the `batch_analyze.py` script mentioned in the `scripts/` folder of the repository, and a preview of Chapter 35 on automation.

### Decompile a function and save the result

```python
import r2pipe

r2 = r2pipe.open("keygenme_O2_strip")  
r2.cmd("aaa")  
r2.cmd("s main")  

# Decompilation via the Ghidra plugin (requires r2ghidra installed)
decompiled = r2.cmd("pdg")

if decompiled:
    with open("main_decompiled.c", "w") as f:
        f.write(decompiled)
    print("Pseudo-code saved to main_decompiled.c")
else:
    print("Decompiler not available — install r2ghidra: r2pm -i r2ghidra")

r2.quit()
```

## Launching a script from the `r2` shell

Instead of executing the Python script from the system terminal, you can launch it from an interactive `r2` session:

```
[0x00401050]> #!pipe python3 my_script.py
```

In this mode, the script can connect to the parent `r2` session using `r2pipe.open("-")` instead of a file path. The advantage is that the script inherits the already-performed analysis and all annotations (renamings, comments, flags) of the current session.

```python
import r2pipe

# Connects to the parent r2 session
r2 = r2pipe.open("-")

# No need for r2.cmd("aaa") — analysis is already done
functions = r2.cmdj("aflj")  
print(f"Number of functions: {len(functions)}")  

# No r2.quit() — the parent session continues after the script
```

This mechanism is particularly useful for short utility scripts: a script that automatically renames functions according to a heuristic, a script that colorizes basic blocks according to a computed property, etc.

## Best practices

### Handle errors and empty outputs

`r2` commands can fail silently or return unexpected results, especially on malformed or obfuscated binaries. A robust script must always check returns.

```python
# Bad — crashes if cmdj returns None
functions = r2.cmdj("aflj")  
for fn in functions:  # TypeError if functions is None  
    ...

# Good — default value and verification
functions = r2.cmdj("aflj") or []  
for fn in functions:  
    name = fn.get("name", "unknown")
    offset = fn.get("offset", 0)
    ...
```

### Prefer `cmdj()` over manual parsing

It can be tempting to parse `cmd()`'s text output with regular expressions. It's fragile: `r2`'s text format changes between versions, column alignments vary depending on the terminal width, and special characters in symbol names can break a regex. JSON output is stable, typed, and self-contained.

### Reuse the session

Opening and closing an `r2` session has a non-negligible cost: the `r2` process is launched, the binary is loaded, analysis is executed. If you need to send many commands to the same binary, open a single session and reuse it.

```python
# Bad — opens and closes r2 for each function
for addr in addresses:
    r2 = r2pipe.open("binary")
    r2.cmd("aaa")
    r2.cmd(f"s {addr}")
    result = r2.cmd("pdf")
    r2.quit()

# Good — a single session for everything
r2 = r2pipe.open("binary")  
r2.cmd("aaa")  
for addr in addresses:  
    r2.cmd(f"s {addr}")
    result = r2.cmd("pdf")
r2.quit()
```

### Save an `r2` project

After scripted annotation work (renamings, comments, flags), you can save the session state in a reopenable `r2` project:

```python
r2.cmd("Ps my_project")  # Save the project
# Later: r2 -p my_project to reopen it
```

## `r2pipe` vs other tools' APIs

It's useful to position `r2pipe` relative to the scripting interfaces of competing disassemblers, because you'll have to choose one or the other depending on context.

**`r2pipe` (Radare2)** communicates through text/JSON command exchanges with an external `r2` process. It's a simple, decoupled model: your Python script is an independent program, and `r2` is an analysis server. The advantage is lightness and portability. The disadvantage is that each command is a text string to build and an output to parse — there's no rich object API with autocompletion and strong typing.

**Ghidra scripting (Java/Python)** runs inside the Ghidra process. Scripts have access to a complete object model: `Program`, `Function`, `Instruction`, `DataType`… with typed and documented methods. It's more powerful for complex manipulations (reconstructing types, annotating structures), but scripts only run in the Ghidra environment. We covered it in chapter 8.8.

**IDAPython (IDA Pro/Home)** offers a model similar to Ghidra: direct access to IDA's internal objects from Python. It's historically the industry standard for RE scripting, but requires an IDA Pro or Home license — it's not fully available in IDA Free.

**Binary Ninja API (Python)** is considered by many the best-designed of the four, with a clean object model and well-thought-out abstractions (the multi-level BNIL IL). But it requires a commercial Binary Ninja license for local use.

In summary: `r2pipe` is the best choice when you need free, lightweight, decoupled scripting executable in a Unix pipeline. For deeper programmatic analysis with a rich object model, Ghidra scripting is the most complete free alternative.

---


⏭️ [Binary Ninja Cloud (free version) — quick start](/09-ida-radare2-binja/05-binary-ninja-cloud.md)
