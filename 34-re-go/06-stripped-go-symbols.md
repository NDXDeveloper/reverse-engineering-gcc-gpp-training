🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 34.6 — Stripped Go Binaries: recovering symbols via internal structures

> 🐹 *The previous sections laid the foundations: you know the runtime (34.1), calling conventions (34.2), data structures (34.3), `gopclntab` (34.4), and strings (34.5). This final section brings all these elements together in a complete workflow for the most common real-world case: a stripped Go binary, without DWARF, sometimes garbled, that you must analyze end-to-end.*

---

## The Spectrum of Go Stripping

Not all stripped Go binaries are equal. The level of opacity varies depending on the measures taken by the developer:

| Level | Measures applied | What remains exploitable |  
|---|---|---|  
| 0 | None (raw binary) | Everything: `.symtab`, DWARF, `gopclntab`, types, names |  
| 1 | `strip -s` | `gopclntab`, types, function names, `moduledata` |  
| 2 | `-ldflags="-s -w"` | `gopclntab`, types, function names, `moduledata` |  
| 3 | `strip -s` + `-ldflags="-s -w"` | `gopclntab`, types, function names, `moduledata` |  
| 4 | `garble build` | `gopclntab` (garbled names), types (garbled names), structure intact |  
| 5 | `garble -literals -seed=random build` | `gopclntab` (garbled), types (garbled), encrypted string literals |

The essential point: levels 1 through 3 are **functionally identical** for the reverse engineer. Whether the developer uses `strip`, `-ldflags`, or both, the runtime's internal structures remain intact. The real break occurs at level 4, with the introduction of `garble`.

---

## Step 1 — Identification and Triage

Before diving into reconstruction, confirm that you are facing a Go binary and assess the stripping level.

### Confirm the Binary's Go Nature

```bash
# Quick test — at least one of these indicators is sufficient
file binaire                                    # often "statically linked"  
readelf -S binaire | grep -E 'gopclntab|go\.buildid|noptrdata'  
strings binaire | grep -c 'runtime\.'          # > 100 = almost certainly Go  
strings binaire | grep -oP 'go1\.\d+\.\d+'    # compiler version  
xxd binaire | grep -i 'f1ff ffff'              # gopclntab magic (Go 1.20+)  
```

### Assess the Stripping Level

```bash
# ELF symbol table present?
readelf -s binaire | head -20
# If "no symbols" → stripped (level ≥ 1)

# DWARF sections present?
readelf -S binaire | grep debug
# If no .debug_* section → DWARF removed

# Readable function names in gopclntab?
strings binaire | grep 'main\.' | head -10
# If "main.parseKey", "main.main" → names intact (levels 1-3)
# If "a1b2c3.x4y5" or absent → garbled (levels 4-5)

# Readable string literals?
strings binaire | grep -iE 'error|invalid|usage|license'
# If present → no literal encryption
# If absent or unintelligible → garble -literals (level 5)
```

> 💡 **RE tip**: this triage phase takes less than a minute and saves you from wasting time with an unsuitable strategy. A level 1-3 binary can be handled in a few minutes with GoReSym. A level 5 binary requires a radically different approach.

---

## Step 2 — Recovering Function Names

### Levels 1-3: Direct Extraction

This is the favorable case. The full names are in `gopclntab`, readable in plain text:

```bash
# Full extraction with GoReSym
GoReSym -t -d -p binaire > metadata.json

# Quick verification
jq '.TabMeta.Version' metadata.json        # pclntab version  
jq '.UserFunctions | length' metadata.json  # number of user functions  
jq '.UserFunctions[:5]' metadata.json       # preview of first functions  
```

Then import the results into your disassembler (Ghidra script from section 34.4).

### Level 4: Garbled Names

`garble` replaces names with identifiers derived from a hash. You get functions named according to a scheme like:

```
Lhx3F2a.Kp9mW1    (instead of main.parseKey)  
Lhx3F2a.Yn4rQ7    (instead of main.validateGroups)  
Lhx3F2a.main       (main.main is sometimes preserved)  
```

The package prefix is garbled (`Lhx3F2a` instead of `main`), but it remains consistent — all functions from the same package share the same prefix. This allows you to group functions by package, even without knowing the real name.

**Progressive renaming strategy:**

1. Identify `main.main` (sometimes preserved, otherwise it is the function called by `runtime.main`).  
2. From `main.main`, follow calls to map the functions of the main package.  
3. Rename them manually as you build understanding: `Lhx3F2a.Kp9mW1` → `main.func_validate_key` (descriptive name chosen by you).  
4. Use cross-references and strings to guess the role of each function.

### Level 5: Garbled Names + Encrypted Literals

`garble -literals` encrypts string literals by replacing them with decryption calls at runtime. In the disassembly, instead of a `LEA` into `.rodata`, you will see:

```asm
; Encrypted string literal — decrypted at runtime
LEA     RAX, [données_chiffrées]  
MOV     RBX, longueur  
CALL    garble_decrypt_func         ; decryption function inserted by garble  
; After return: RAX = ptr to the decrypted string, RBX = len
```

`garble`'s decryption functions typically use XOR with a derived key. They are recognizable by their pattern: buffer allocation, XOR loop, return of a string header.

**Countermeasures:**

1. **Dynamic analysis** — set a breakpoint right after the decryption call and read the plaintext string in the return registers. This is the most direct method.  
2. **Decryption pattern identification** — locate the decryption functions (small functions called frequently, with an XOR loop), then write a script that emulates them to decrypt all strings statically.  
3. **Frida** — hook the decryption function and log each decrypted string with its return address (to know which function uses it).

```javascript
// Frida — capture strings decrypted by garble
// First identify the address of the decryption function
var decryptFunc = ptr("0x4A1234"); // address found through static analysis

Interceptor.attach(decryptFunc, {
    onLeave: function(retval) {
        var strPtr = this.context.rax;
        var strLen = this.context.rbx.toInt32();
        if (strLen > 0 && strLen < 4096) {
            var caller = this.returnAddress;
            console.log("[" + caller + "] Decrypted: " +
                        Memory.readUtf8String(strPtr, strLen));
        }
    }
});
```

---

## Step 3 — Reconstructing `moduledata`

### Why `moduledata` Is Central

As seen in section 34.4, `runtime.firstmoduledata` is the central node linking all metadata. Reconstructing it in a stripped binary opens access to all type information, segment boundaries, and the function table.

### Location by Signature

`moduledata` has a predictable layout with certain fields containing known addresses. The approach: find in memory a zone in `.noptrdata` or `.data` whose fields match the ELF segment addresses.

```python
# locate_moduledata.py — location heuristic
# Approach: moduledata contains the text/etext/data/edata addresses
# that correspond to the ELF segment boundaries.

import struct  
from elftools.elf.elffile import ELFFile  

def find_moduledata(filepath):
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        f.seek(0)
        data = f.read()

    # Retrieve segment boundaries from the ELF headers
    text_start = None
    text_end = None
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_flags'] & 0x1:  # executable
            text_start = seg['p_vaddr']
            text_end = seg['p_vaddr'] + seg['p_memsz']
            break

    if text_start is None:
        print(".text segment not found")
        return

    # Search data sections for a pair (text_start, text_end)
    # Moduledata contains these addresses in consecutive fields
    target = struct.pack('<QQ', text_start, text_end)

    offset = 0
    while True:
        pos = data.find(target, offset)
        if pos == -1:
            break
        print(f"Candidate moduledata at file offset 0x{pos:x}")
        # Verification: the pclntable field should point to the gopclntab magic
        # (exact offsets depend on the Go version)
        offset = pos + 1

find_moduledata("crackme_go_strip")
```

### Location by Reference from `runtime.main`

If you have already recovered function names via `gopclntab`, `runtime.main` is identifiable. At the beginning of its execution, it accesses `firstmoduledata`:

```asm
; Excerpt from runtime.main (simplified)
LEA     RAX, [runtime.firstmoduledata]  
MOV     RCX, [RAX + offset_hasmain]  
TEST    RCX, RCX  
JZ      .no_main  
```

The address loaded by the `LEA` is that of `moduledata`. In Ghidra, follow the cross-reference from `runtime.main` to the data.

### Parsing `moduledata`

Once the address is found, the useful fields to extract (offsets for Go 1.21+, amd64):

```
Offset   Size     Field          What it gives you
──────   ──────   ─────          ────────────────────
+0x00    24       pclntable      Slice (ptr, len, cap) to gopclntab
+0x18    24       ftab           Slice to the function table
+0x30    24       filetab        Slice to the source file table
+0x48    8        findfunctab    Pointer to the fast lookup table
+0x50    8        minpc          Smallest PC address (≈ start of .text)
+0x58    8        maxpc          Largest PC address (≈ end of .text)
+0x60    8        text           Address of .text
+0x68    8        etext          End of .text
+0x70    24       noptrdata      Slice of .noptrdata
+0x88    24       data           Slice of .data
...
+0x???   24       typelinks      Slice of offsets to types   ← key for step 4
+0x???   24       itablinks      Slice to itabs              ← key for interfaces
```

The offsets vary between Go versions. The reliable method: locate the `pclntable` field (its `ptr` should point to the `gopclntab` magic) and use it as an anchor to calibrate the other fields' offsets.

> 💡 **RE tip**: GoReSym does all this work automatically and exposes `moduledata` in its JSON output. But understanding the manual mechanism is crucial for cases where GoReSym fails (very recent Go versions not yet supported, modified binaries).

---

## Step 4 — Type Reconstruction

### The `typelinks` Field

The `typelinks` field of `moduledata` contains a slice of offsets (int32) relative to a base address. Each offset points to a `runtime._type` descriptor (section 34.3). By iterating over this slice, you get the complete list of types defined and used in the program.

### Extracting Types with GoReSym

```bash
GoReSym -t crackme_go_strip | jq '.Types[] | select(.PackageName=="main")'
```

Typical output:

```json
{
  "Kind": "struct",
  "Name": "main.ChecksumValidator",
  "Size": 8,
  "Fields": [
    { "Name": "ExpectedSums", "Type": "map[int]uint16", "Offset": 0 }
  ]
}
```

Each type exposes its `Kind` (struct, interface, slice, map, etc.), its full name, its size, and for structs, the list of fields with their names, types, and offsets. This is sufficient to reconstruct the equivalent `.h` headers.

### Manual Reconstruction in Ghidra

When GoReSym provides type definitions, create them in Ghidra to improve the pseudo-code:

1. Open the **Data Type Manager** (left panel).  
2. Create a new folder `go_types`.  
3. For each struct, create a structure with fields at the correct offsets and sizes.  
4. Apply these types to variables in the decompiler: right-click on a variable → *Retype Variable*.

For example, for `ChecksumValidator`:

```
Structure: ChecksumValidator (8 bytes)
  +0x00  pointer  ExpectedSums    (pointer to hmap)
```

And for a `Validator` interface passed as arguments (16 bytes, section 34.3):

```
Structure: Validator_iface (16 bytes)
  +0x00  pointer  tab     (pointer to itab)
  +0x08  pointer  data    (pointer to the concrete value)
```

Applying these types transforms Ghidra's pseudo-code from a mass of opaque memory accesses into readable code with field names.

### Reconstructing itabs

The `itablinks` field of `moduledata` lists the pre-built itabs. Each itab (section 34.3) links a concrete type to an interface and contains the method pointers. By parsing them, you get:

- the list of (type, interface) pairs implemented in the program,  
- the addresses of concrete methods for each interface.

This is the Go equivalent of reconstructing vtables in C++ (Chapter 17). The difference is that Go itabs are explicitly listed in `moduledata`, whereas C++ vtables must be found by heuristic.

```python
# Pseudo-code: parse itablinks from moduledata
itablinks_ptr, itablinks_len, _ = read_slice(moduledata + ITABLINKS_OFFSET)  
for i in range(itablinks_len):  
    itab_addr = read_uint64(itablinks_ptr + i * 8)
    inter_type = read_uint64(itab_addr + 0x00)    # interface type descriptor
    concrete_type = read_uint64(itab_addr + 0x08)  # concrete type descriptor
    first_method = read_uint64(itab_addr + 0x18)   # address of the first method
    # ... read the interface and concrete type names from the type descriptors ...
```

---

## Step 5 — Reconstructing the Call Graph

### Cross-References and `main` Package Functions

Once functions are named and types reconstructed, the call graph builds naturally in Ghidra via cross-references (XREF, Chapter 8). For a Go binary, the most effective strategy:

1. **Start from `main.main`** and explore depth-first.  
2. **Mark direct calls** (`CALL main.parseKey`, `CALL main.validateGroups`) — these are the graph edges.  
3. **Identify indirect calls** (`CALL reg` via itab) — each interface dispatch is a point of polymorphism. Use the reconstructed itabs to resolve possible targets.  
4. **Spot goroutine launches** (`CALL runtime.newproc`) — each occurrence creates a concurrent branch. The argument is the target function's address.

### Ghidra Script: main Package Call Graph

```python
# call_graph_main.py — Ghidra script
# Builds the call graph of main.* functions and displays it.

func_mgr = currentProgram.getFunctionManager()  
ref_mgr = currentProgram.getReferenceManager()  
funcs = func_mgr.getFunctions(True)  

main_funcs = {}  
for f in funcs:  
    name = f.getName()
    if name.startswith("main."):
        main_funcs[f.getEntryPoint()] = name

print("=== main package call graph ===")  
for addr, name in sorted(main_funcs.items(), key=lambda x: x[1]):  
    callees = []
    # Walk through the function's instructions
    body = f.getBody() if f.getEntryPoint() == addr else \
           func_mgr.getFunctionAt(addr).getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        if inst.getMnemonicString() == "CALL":
            for ref in inst.getReferencesFrom():
                target = ref.getToAddress()
                target_func = func_mgr.getFunctionAt(target)
                if target_func:
                    callees.append(target_func.getName())
    # Filter to keep only calls to main.* and key runtime functions
    interesting = [c for c in callees
                   if c.startswith("main.") or c in
                   ("runtime.newproc", "runtime.gopanic")]
    if interesting:
        f_name = main_funcs.get(addr, "?")
        for callee in interesting:
            print("  {} --> {}".format(f_name, callee))
```

---

## Step 6 — Reconstructing Logic Without Names (Level 5)

When facing a garbled binary with encrypted literals (the worst case), names and strings no longer help you. You must rely on **structure** and **behavior**.

### Exploitable Invariants

Even at the maximum obfuscation level, certain elements remain unchanged:

| Element | Why it survives | What it tells you |  
|---|---|---|  
| Runtime calls (`runtime.makemap`, `runtime.chansend1`, etc.) | The runtime is never garbled | Data types used (map, channel, slice) |  
| `gopclntab` structure | Required by the runtime | Number of functions, sizes, PC-to-file mapping |  
| Stack preambles | Generated by the compiler | Function boundary identification |  
| System calls (`syscall.Syscall6`) | Interface with the kernel | Network, file, process behavior |  
| Stdlib types | Not garbled | `net.Conn`, `crypto/aes.Block`, `os.File` reveal capabilities |  
| Structure sizes | In `runtime._type.size` | Memory footprint, even without names |

### Behavior-Based Workflow

```
1. Identify syscalls (strace)
   └─► socket, connect, open, read, write, mmap
   └─► Classifies the binary: network? file? crypto?

2. Identify stdlib packages used
   └─► strings binaire | grep -E 'crypto/|net/|os/|encoding/'
   └─► Stdlib names are NOT garbled by garble

3. Map functions by size and complexity
   └─► Large main.* functions (garbled) = business logic
   └─► Small functions = utilities, validations

4. Targeted dynamic analysis
   └─► Breakpoints on runtime.chansend1 → data flow
   └─► Breakpoints on crypto/aes.newCipher → key extraction
   └─► Breakpoints on net.(*conn).Write → network data

5. Progressive renaming
   └─► func_0x4A1234 → func_send_data (based on observed behavior)
   └─► Iterate until sufficient coverage
```

### The Decisive Advantage of the Non-Garbled Stdlib

`garble` cannot garble Go's standard library — it is precompiled and shared among all programs. This means the **boundaries between business code and the stdlib** are always visible:

```
main.Lhx3F2a.Kp9mW1           ← business code (garbled)
  └─► crypto/aes.NewCipher     ← stdlib (readable!)
  └─► encoding/hex.Decode      ← stdlib (readable!)
  └─► net.(*Dialer).DialContext ← stdlib (readable!)
```

By following calls from garbled functions to the stdlib, you reconstruct the program's behavior: this function does AES encryption, that one decodes hexadecimal, that one opens a network connection.

> 💡 **RE tip**: in Ghidra, use the *Function Call Trees* feature (right-click on a function → *References → Show Call Trees*) to quickly visualize which stdlib functions are called by each garbled function. This is often sufficient to understand the function's general role.

---

## Complementary Tools

### `redress` (go-re)

`redress` is a tool specialized in Go binary analysis. It reconstructs interfaces, types, packages, and the call graph:

```bash
# Installation
go install github.com/goretk/redress@latest

# List packages
redress -pkg binaire

# Display types and interfaces
redress -type binaire

# Display compiler information
redress -compiler binaire
```

`redress` uses the `gore` library (Go Reverse Engineering library), which can also be used directly in Go to write custom analysis scripts.

### `gore` (Go Library)

```go
// Minimal example with gore
package main

import (
    "fmt"
    "github.com/goretk/gore"
)

func main() {
    f, err := gore.Open("crackme_go_strip")
    if err != nil { panic(err) }
    defer f.Close()

    // Compiler version
    v, _ := f.GetCompilerVersion()
    fmt.Println("Go version:", v)

    // Packages
    pkgs, _ := f.GetPackages()
    for _, p := range pkgs {
        fmt.Printf("Package: %s (%d functions)\n", p.Name, len(p.Functions))
    }

    // Types
    types, _ := f.GetTypes()
    for _, t := range types {
        fmt.Printf("Type: %s (kind: %d, size: %d)\n", t.Name, t.Kind, t.Size)
    }
}
```

### `GoStringUngarbler` and Deobfuscation Tools

For binaries garbled with `-literals`, community tools attempt to identify and emulate the string decryption functions. Search for `GoStringUngarbler` or `garble deobfuscator` on GitHub. These tools are inherently fragile (tied to the `garble` version), but can save considerable time when they work.

---

## Complete Workflow Summary

```
                    Unknown Go binary
                           │
                    ┌──────┴──────┐
                    │   Triage    │
                    │  (1 min)    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
         Readable names  Garbled names Garbled names
         (levels 1-3)   (level 4)    + encrypted lits
              │            │           (level 5)
              ▼            ▼            │
         GoReSym       GoReSym          ▼
         + import      + progressive Dynamic
         Ghidra        renaming      analysis
              │            │         (GDB/Frida)
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────┴──────┐
                    │ moduledata  │
                    │ + typelinks │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │   Types     │
                    │reconstructed│
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │   Call      │
                    │   graph     │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │   Logic     │
                    │  analysis   │
                    └─────────────┘
```

---

## Key Takeaways

1. **Assess the stripping level first.** Levels 1-3 (strip/ldflags) are handled quickly. Levels 4-5 (garble) require an adapted strategy.  
2. **`gopclntab` + `moduledata` + `typelinks` form a triptych.** Together, they contain function names, type definitions, and interface tables — everything needed to reconstruct the program's architecture.  
3. **The stdlib is never garbled.** This is your main leverage against an obfuscated binary: calls to `crypto/*`, `net/*`, `os/*` reveal the program's behavior.  
4. **Dynamic analysis bypasses garbling.** Values in memory, decrypted strings, and syscall arguments are always in plaintext at runtime.  
5. **Rename progressively.** Do not try to understand everything at once. Start from `main.main`, follow the calls, and rename each function as soon as you understand its role. The disassembly's clarity improves iteration after iteration.  
6. **Tool up.** GoReSym, `redress`, `gore`, Ghidra scripts — each tool saves you hours of manual work. Invest the time to install and master them.

⏭️ [🎯 Checkpoint: analyze a stripped Go binary, recover functions, and reconstruct the logic](/34-re-go/checkpoint.md)
