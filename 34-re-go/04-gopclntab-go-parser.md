🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 34.4 — Recovering Function Names: `gopclntab` and `go_parser` for Ghidra/IDA

> 🐹 *When you strip a C binary, the function names disappear permanently. When you strip a Go binary, they are still there — hidden in a structure that the runtime uses to generate stack traces and feed the garbage collector. This structure is called `gopclntab`, and it is the reverse engineer's best friend when facing a Go binary.*

---

## Why Names Survive Stripping

To understand why `gopclntab` exists and why `strip` does not remove it, we need to return to the needs of the Go runtime.

### The Runtime's Needs

The Go runtime needs, at execution time, to be able to:

1. **Generate readable stack traces.** When a goroutine panics or a profiler captures a state, Go displays traces like `main.parseKey(...)` with the source file and line number. This information must be in the binary.  
2. **Identify stack frames for the GC.** The garbage collector must walk the stacks of all goroutines to find live pointers. For this, it needs to know, for each PC (program counter) address, which function is currently executing, what its frame size is, and where the pointers are within that frame.  
3. **Support `runtime.Callers` and the `runtime` package.** The functions `runtime.Caller()`, `runtime.FuncForPC()`, and the `runtime/pprof` package all depend on the ability to resolve a PC address to a function name.

These needs are **functional**, not optional. If you remove `gopclntab`, the binary no longer works: panics crash without a trace, the GC can no longer walk stacks, and the program is unstable or even unusable.

### What `strip` Actually Removes

The `strip -s` command on a Go binary removes:

- the ELF symbol table (`.symtab`),  
- the DWARF debug information (`.debug_*`),  
- the dynamic symbol table if applicable.

But it **does not touch** the `.gopclntab`, `.go.buildid`, `.noptrdata`, `.noptrbss` sections, nor the type structures in `.rodata` — because this data is referenced by the runtime code and participates in the program's operation. From `strip`'s perspective, these are ordinary data, not debug metadata.

> 💡 **RE tip**: this is the fundamental difference from C. In C, function names in `.symtab` are only used for debugging and linking — the program never needs them at runtime. In Go, function metadata is a runtime dependency. Stripping is therefore largely cosmetic.

---

## Anatomy of `gopclntab`

### Locating the Table

The `gopclntab` (Go PC-Line Table) table is stored in a dedicated ELF section or in `.noptrdata`. To locate it:

**Method 1 — By section name:**

```bash
readelf -S binaire | grep gopclntab
```

On a non-stripped binary, you will see a `.gopclntab` section. On some Go versions or after stripping, the section may not have this name, but the data is always present in `.noptrdata`.

**Method 2 — By magic number:**

The table starts with a header containing a magic number that varies by Go version:

| Go version | Magic (4 bytes, little-endian) |  
|---|---|  
| Go 1.2 – 1.15 | `FB FF FF FF` |  
| Go 1.16 – 1.17 | `FA FF FF FF` |  
| Go 1.18 – 1.19 | `F0 FF FF FF` |  
| Go 1.20+ | `F1 FF FF FF` |

```bash
# Search for the magic in the binary
xxd binaire | grep -i 'f1ff ffff\|f0ff ffff\|faff ffff\|fbff ffff'
```

**Method 3 — Via the runtime:**

The runtime accesses `gopclntab` via the global variable `runtime.pclntab` (or `runtime.firstmoduledata.pclntable`). If you find the `runtime.firstmoduledata` symbol (section 34.6), the `pclntable` field gives you the table's address and size directly.

### Header Structure (Go 1.20+)

The `gopclntab` header has evolved significantly between versions. Here is the current format (Go 1.20+):

```
Offset   Size     Field            Description
──────   ──────   ─────            ───────────
+0x00    4        magic            Magic number (0xFFFFFFF1 in Go 1.20+)
+0x04    1        pad1             Padding (0x00)
+0x05    1        pad2             Padding (0x00)
+0x06    1        minLC            Minimum instruction quantum (1 on amd64)
+0x07    1        ptrSize          Pointer size (8 on amd64)
+0x08    N        nfunc            Number of functions (integer of ptrSize size)
+0x08+N  N        nfiles           Number of source files
+0x08+2N ...      textStart        Base address of the .text segment
+...     ...      funcnameOffset   Offset to the function name table
+...     ...      cutabOffset      Offset to the CU (compilation units) table
+...     ...      filetabOffset    Offset to the file name table
+...     ...      pctabOffset      Offset to the PC (program counter) table
+...     ...      pclnOffset       Offset to the pcln table (function entries)
```

The exact offsets of fields after `nfiles` depend on the version. The important thing is that the header contains relative offsets to five sub-tables.

### The Function Table (`functab`)

After the header, the `functab` table contains one entry per function. Each entry maps a start PC address to an offset to a `_func` record:

```
functab entry (Go 1.20+, each entry = 2 × 4 bytes)
┌───────────────────────┬───────────────────────────┐
│ funcoff (uint32)      │ funcdata_offset (uint32)  │
│ Relative PC offset    │ Offset to the _func       │
│ from textStart        │ record in pclntab         │
└───────────────────────┴───────────────────────────┘
```

### The `_func` Record

Each function is described by a `_func` record:

```
_func (Go 1.20+, simplified)
Offset   Size     Field        Description
──────   ──────   ─────        ───────────
+0x00    4        entryOff     Entry PC offset (relative to textStart)
+0x04    4        nameOff      Offset in the name table → function name
+0x08    4        args          Argument size in bytes
+0x0C    4        deferreturn   Defer return point offset (0 if no defer)
+0x10    4        pcsp          Offset in pctab → PC-to-SP delta table
+0x14    4        pcfile        Offset in pctab → PC-to-file index table
+0x18    4        pcln          Offset in pctab → PC-to-line number table
+0x1C    4        npcdata       Number of pcdata entries
+0x20    4        cuOffset      Compilation unit index
+0x24    1        startLine     Start line (relative offset)
+0x25    1        funcID        Function ID (for special runtime functions)
+0x26    1        flag          Flags
+0x27    1        (padding)
+0x28    4        nfuncdata     Number of funcdata entries
```

The `nameOff` field is your primary target: it points into the function name table, where you will find strings like `main.parseKey`, `runtime.newproc`, etc.

### The Function Name Table

This is simply an area of null-terminated strings (one of the rare places where Go uses null terminators — for compatibility with C and the system). Each name is a fully qualified path: `main.main`, `main.(*ChecksumValidator).Validate`, `runtime.mallocgc`, etc.

### The PC-Value Tables (pcsp, pcfile, pcln)

The `pcsp`, `pcfile`, and `pcln` tables use a compact encoding called **pc-value encoding**: a sequence of bytes that encodes (delta-PC, delta-value) pairs using a variable encoding (similar to LEB128/varint). For each PC address within the function, these tables allow recovering:

- **pcsp**: the delta between SP and the top of the frame → gives the stack frame size at each instruction,  
- **pcfile**: the source file index → which `.go` file is involved,  
- **pcln**: the line number → PC-to-line correspondence.

In RE, the pcln table is useful for mapping back to source line numbers, and pcsp for understanding the stack layout.

---

## Extracting Names Manually

### With a Minimal Python Script

To extract function names from a stripped Go binary without specialized tools, the approach is:

1. Locate the `gopclntab` magic in the file.  
2. Parse the header to get `nfunc` and the sub-table offsets.  
3. Iterate over `functab`: for each entry, read `nameOff` from the `_func` record, then read the corresponding string from the name table.

Here is the skeleton (for Go 1.20+, amd64):

```python
import struct

def find_gopclntab(data):
    """Search for the gopclntab magic in the binary."""
    magics = [b'\xf1\xff\xff\xff', b'\xf0\xff\xff\xff',
              b'\xfa\xff\xff\xff', b'\xfb\xff\xff\xff']
    for m in magics:
        off = data.find(m)
        if off != -1:
            return off, m
    return None, None

def read_cstring(data, offset):
    """Read a null-terminated string."""
    end = data.index(b'\x00', offset)
    return data[offset:end].decode('utf-8', errors='replace')

def extract_func_names(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    base, magic = find_gopclntab(data)
    if base is None:
        print("gopclntab not found")
        return

    ptr_size = data[base + 7]
    # Read nfunc (8 bytes on amd64)
    nfunc = struct.unpack_from('<Q', data, base + 8)[0]
    # ... parse the sub-table offsets according to the version ...
    # ... iterate over functab and read the names ...
    print(f"Found {nfunc} functions at offset 0x{base:x}")
```

This skeleton illustrates the approach. In practice, use the dedicated tools presented below — they handle the subtleties of each version.

### With `objdump` on a Non-Stripped Binary

If the binary is not stripped, `objdump -t` displays Go symbols normally:

```bash
objdump -t crackme_go | grep 'main\.'
```

But on a stripped binary, `objdump -t` shows nothing. This is where specific tools come into play.

---

## GoReSym (Mandiant)

### Overview

GoReSym is an open-source tool developed by Mandiant (Google) specifically to extract metadata from Go binaries. It parses `gopclntab`, type structures, and `moduledata` to produce a complete listing of functions, types, and source files.

### Installation

```bash
go install github.com/mandiant/GoReSym@latest
```

Or download a pre-compiled binary from the GitHub releases.

### Usage

```bash
# Full extraction in JSON format
GoReSym -t -d -p /chemin/vers/crackme_go_strip

# Options:
#   -t   extract types
#   -d   extract file/line information
#   -p   extract package names
```

The JSON output contains:

```json
{
  "Version": "go1.22.1",
  "BuildInfo": { ... },
  "TabMeta": {
    "VA": 5234688,
    "Version": "1.20",
    "Endian": "LittleEndian",
    "CpuQuantum": 1,
    "CpuWordSize": 8
  },
  "Types": [ ... ],
  "UserFunctions": [
    {
      "Start": 4923648,
      "End": 4924160,
      "PackageName": "main",
      "FullName": "main.parseKey",
      "FileName": "/home/user/crackme_go/main.go",
      "StartLine": 71
    },
    ...
  ],
  "StdFunctions": [ ... ]
}
```

Key points for RE:

- **`UserFunctions`** vs **`StdFunctions`**: GoReSym automatically separates business code functions from standard library and runtime functions. This is exactly the filtering you need.  
- **`Start` / `End`**: the virtual addresses of the start and end of each function — directly usable to create symbols in Ghidra or IDA.  
- **`FileName` / `StartLine`**: the source path and line number. The path reveals the project structure, package names, and sometimes the developer's username or build environment.  
- **`Version`**: the exact Go compiler version — essential for determining the ABI (section 34.2).

> 💡 **RE tip**: run GoReSym first on any unknown Go binary. In a few seconds, you get the compiler version, the list of user functions with their addresses, and the defined types. It is the equivalent of a supercharged `nm` for Go.

### Exploiting the Output with `jq`

```bash
# List only functions from the main package
GoReSym -p crackme_go_strip | jq '.UserFunctions[] | select(.PackageName=="main") | .FullName'

# Count functions by package
GoReSym -p crackme_go_strip | jq '[.UserFunctions[].PackageName] | group_by(.) | map({pkg: .[0], count: length}) | sort_by(-.count)'

# Extract user-defined types
GoReSym -t crackme_go_strip | jq '.Types[] | select(.PackageName=="main")'
```

---

## go_parser for IDA

### Overview

`go_parser` is an IDAPython script that parses the internal structures of a Go binary and automatically applies function names, types, and comments in the IDA database.

### Installation and Usage

1. Clone the repository: `git clone https://github.com/0xjiayu/go_parser.git`  
2. In IDA, open the stripped Go binary.  
3. Run `File → Script File...` and select `go_parser.py`.  
4. The script automatically detects the Go version and parses `gopclntab`.

After execution, the script:

- renames all functions with their Go names (`main.parseKey`, `runtime.mallocgc`, etc.),  
- creates comments with file names and line numbers,  
- defines Go strings as named data,  
- partially reconstructs type structures.

> ⚠️ **Note**: `go_parser` is no longer actively maintained and may not support the most recent Go versions (1.22+). For recent binaries, prefer GoReSym combined with an import script.

---

## Plugins and Scripts for Ghidra

### Ghidra Native Support

Since Ghidra 10.2 (late 2022), the analyzer includes basic Go binary support:

- automatic Go language detection during import,  
- partial `gopclntab` parsing to rename functions,  
- recognition of the stack check preamble.

This native support is a good starting point but remains limited. Function names are generally recovered, but types, structures, and function signatures are not automatically reconstructed.

### `GoReSym` + Ghidra Import Script

The most reliable method is to use GoReSym for extraction, then a Ghidra script (Java or Python) to apply the results:

**Step 1 — Extraction with GoReSym:**

```bash
GoReSym -t -d -p crackme_go_strip > metadata.json
```

**Step 2 — Ghidra Python import script:**

```python
# apply_goresym.py — Ghidra script to apply GoReSym results
# Run in Ghidra Script Manager (Window → Script Manager)
import json

# Load the JSON file produced by GoReSym
json_path = askFile("Select GoReSym JSON", "Open").getPath()  
with open(json_path, 'r') as f:  
    data = json.load(f)

listing = currentProgram.getListing()  
func_mgr = currentProgram.getFunctionManager()  
space = currentProgram.getAddressFactory().getDefaultAddressSpace()  

count = 0  
for func_info in data.get("UserFunctions", []) + data.get("StdFunctions", []):  
    addr = space.getAddress(func_info["Start"])
    name = func_info["FullName"]

    # Rename the function if it exists
    func = func_mgr.getFunctionAt(addr)
    if func is not None:
        func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        count += 1
    else:
        # Create the function if Ghidra did not detect it
        try:
            createFunction(addr, name)
            count += 1
        except:
            pass

    # Add a comment with the source file and line
    if "FileName" in func_info and "StartLine" in func_info:
        comment = "{}:{}".format(func_info["FileName"], func_info["StartLine"])
        setPreComment(addr, comment)

print("Applied {} function names.".format(count))
```

This script walks through the JSON, renames each function at its address, and adds a pre-instruction comment with the source file and line number. After execution, Ghidra's Symbol Tree and Listing become readable.

### `ghidra-go-analyzer` (Community)

The `ghidra-go-analyzer` project is a dedicated Ghidra extension that goes further than the import script:

- complete `gopclntab` parsing with multi-version support,  
- Go type reconstruction (structs, interfaces, slices),  
- application of the correct ABI (stack or registers) to signatures,  
- closure detection and linking to parent functions.

Installation is done via the Ghidra Extension Manager. Search for the project on GitHub for the version compatible with your Ghidra version.

---

## Radare2 and `r2go`

Radare2 has basic Go support via the automatic analysis `aaa`. Recent versions of Radare2 detect `gopclntab` and rename functions.

For deeper analysis, the `r2go` plugin and dedicated r2pipe scripts allow extracting metadata. The command-line approach:

```bash
# Automatic analysis (detects Go and parses gopclntab)
r2 -A crackme_go_strip

# List functions (Go names should appear)
afl~main.

# If automatic analysis did not work, force parsing
# by manually searching for the gopclntab magic
/x f1ffffff
```

The support is less comprehensive than GoReSym + Ghidra, but sufficient for quick command-line triage.

---

## `moduledata`: The Keystone

### `runtime.firstmoduledata` Structure

All the Go binary's metadata is accessible via the `runtime.firstmoduledata` structure (or `runtime.moduledata` in some versions). It is the runtime's central entry point to the function, type, and name tables:

```
runtime.moduledata (main fields, simplified)  
Field              Description  
─────              ───────────
pclntable          Slice to the complete gopclntab table  
ftab               Slice to the function table  
filetab            Slice to the source file table  
findfunctab        Pointer to the fast lookup table  
text               Start address of the .text segment  
etext              End address of the .text segment  
noptrdata          Start of the .noptrdata section  
enoptrdata         End of the .noptrdata section  
data               Start of the .data section  
edata              End of the .data section  
bss                Start of .bss  
ebss               End of .bss  
typelinks          Slice of offsets to type descriptors  
itablinks          Slice of pointers to itabs  
modulename         Module name (string)  
next               Pointer to the next moduledata (plugins)  
```

### Locating `moduledata` in a Stripped Binary

If symbols are absent, `moduledata` can be found through several methods:

**Method 1 — By reference from `runtime.main`:**

The `runtime.main` function (recoverable via `gopclntab`) accesses `firstmoduledata` early in its execution. By following cross-references from this function, you will find the `moduledata` address.

**Method 2 — By pattern search:**

`moduledata` contains the `text` and `etext` addresses (start and end of the `.text` segment). If you know these addresses (via `readelf -l`), search in memory for two consecutive pointers matching these values.

**Method 3 — Via GoReSym:**

GoReSym automatically locates `moduledata` and exposes it in its JSON output (`ModuleMeta` field).

> 💡 **RE tip**: once `moduledata` is located, you have access to all the binary's metadata. The `typelinks` field leads you to type descriptors (section 34.3), `pclntable` gives you `gopclntab`, and the `text`/`etext`, `data`/`edata` pairs give you the exact segment boundaries.

---

## Recommended Workflow

Here is the optimal procedure when facing a stripped Go binary:

```
1. Identification
   └─► strings binaire | grep 'go1\.'       → compiler version
   └─► readelf -S binaire | grep gopclntab  → section presence

2. Metadata extraction
   └─► GoReSym -t -d -p binaire > meta.json
   └─► jq '.Version' meta.json              → confirm Go version
   └─► jq '.UserFunctions | length' meta.json → number of user functions

3. Function triage
   └─► jq '.UserFunctions[] | .FullName' meta.json
       → identify business packages and functions

4. Import into the disassembler
   └─► Ghidra: run the GoReSym import script
   └─► IDA: run go_parser or import via IDAPython
   └─► Radare2: r2 -A (auto analysis) then verify afl~main.

5. Targeted analysis
   └─► Focus on main.* functions and business packages
   └─► Ignore runtime.*, internal/*, vendor/*
```

This workflow transforms a stripped Go binary — apparently opaque with its thousands of anonymous functions — into a target almost as readable as a binary with symbols.

---

## Limitations and Countermeasures

### What `gopclntab` Does Not Give You

- **The source code.** You get function names and line numbers, but not the Go code itself.  
- **Local variable names.** Only function and type names are in the runtime metadata. Local variables are not included (they are in the DWARF info, removed by `strip`).  
- **Developer comments.** Obviously absent from the binary.

### Malware Author Countermeasures

Some Go malware developers attempt to neutralize this metadata:

- **Name garbling** with tools like `garble` (formerly `burrern`). `garble` replaces function, package, and type names with random identifiers or hashes. The metadata is still present in `gopclntab`, but the names are unreadable (`a0b1c2d3.x4y5z6` instead of `main.parseKey`).  
- **Post-compilation modification of `gopclntab`**. Technically possible but fragile: if names are corrupted inconsistently, the runtime may crash.  
- **Compilation with `-ldflags="-s -w"`** which removes DWARF information and the symbol table, but **does not remove `gopclntab`** — this option is often misunderstood by developers who think they have hidden their names.

When facing a garbled binary:

1. The names are unreadable, but the function **structure** remains intact. You can still count functions, measure their size, and analyze cross-references.  
2. The **type descriptors** are partially garbled, but standard library types (which are not garbled) give you clues about the structures used.  
3. **String literals** in the code are generally not garbled by `garble` (unless a specific option is used). They remain a source of information.  
4. **Dynamic analysis** (GDB, Frida) is not affected by garbling — behaviors and values in memory remain identical.

> 💡 **RE tip**: when facing a garbled binary, focus on string literals, constants, runtime calls (`runtime.mapaccess*`, `runtime.chansend1`, etc.), and structural patterns rather than function names. Garbling hides the names, not the logic.

---

## Key Takeaways

1. **`gopclntab` survives `strip`** because it is a functional dependency of the runtime, not debug metadata.  
2. **GoReSym is the reference tool.** Run it systematically first on any Go binary. It gives you the compiler version, function names, types, and source files.  
3. **Import the results into your disassembler.** A script of a few dozen lines is enough to transform Ghidra or IDA from a mass of anonymous functions into a structured and named view.  
4. **`moduledata` is the keystone.** It ties all metadata together — `gopclntab`, types, segments, itabs.  
5. **Garbling (`garble`) is the main countermeasure.** It makes names unreadable but does not remove the structures. Analysis by behavior and string literals remains effective.  
6. **Filter the noise.** With thousands of runtime functions, your sanity depends on your ability to ignore `runtime.*` and focus on application packages.

⏭️ [Go Strings: the `(ptr, len)` structure and implications for `strings`](/34-re-go/05-strings-go-ptr-len.md)
