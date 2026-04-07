🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 35.1 — Python Scripts with `pyelftools` and `lief` (ELF Parsing and Modification)

> 📦 **Libraries covered**:  
> - `pyelftools` (read-only) — faithful parsing of ELF, DWARF, `.symtab`, `.dynamic` structures  
> - `lief` (read + write) — parsing, modification, and reconstruction of ELF, PE, Mach-O binaries  
>  
> 🐍 **Prerequisites**: Python 3.8+, `pip install pyelftools lief`

---

## Why two libraries?

The Python ecosystem offers several libraries for manipulating ELF binaries. Two of them have established themselves as the pillars of any RE automation toolkit, and they do not replace each other — they complement each other.

`pyelftools` is a pure Python library created by Eli Bendersky. It does only one thing: parse ELF structures according to the specification, exposing each field exactly as it appears on disk. It does not modify anything, does not reconstruct anything, and that is precisely what makes it powerful. When you want to read an ELF header, walk the symbol table, inspect DWARF information, or extract entries from the `.dynamic` section, `pyelftools` gives direct and unsurprising access to each structure. Its mental model is that of `readelf`: you read, you inspect, you report.

`lief` (Library to Instrument Executable Formats) is a more ambitious project. Written in C++ with Python bindings, it parses ELF, PE, and Mach-O formats, but it also allows you to *modify* them: add a section, rename a symbol, change the entry point, inject a dynamic dependency, patch bytes in `.text`, then rewrite the binary to disk. Where `pyelftools` is a microscope, `lief` is both a microscope and a scalpel.

In practice, an automated triage script will often start with `pyelftools` for inspection (it is lighter, faster to write, and the correspondence with `readelf` output makes verification easier). As soon as the script needs to *transform* the binary — patch a byte, add a metadata section, modify a flag — you switch to `lief`.

---

## Part A — `pyelftools`: Programmatic ELF Inspection

### Installation and basic import

```bash
pip install pyelftools
```

The main entry point is the `ELFFile` class, which takes a file object opened in binary mode:

```python
from elftools.elf.elffile import ELFFile

with open("keygenme_O0", "rb") as f:
    elf = ELFFile(f)
    print(f"Class :   {elf.elfclass}-bit")
    print(f"Endian :  {elf.little_endian and 'little' or 'big'}")
    print(f"Machine : {elf['e_machine']}")
    print(f"Type :    {elf['e_type']}")
    print(f"Entry :   0x{elf['e_entry']:x}")
```

> ⚠️ **Important note**: `ELFFile` reads the file on demand (*lazy parsing*). The file must remain open for the entire duration of use of the `elf` object. If you close the file and then try to access a section, you will get an error.

### Reading the ELF header

The `elf.header` object exposes all ELF header fields as a dictionary. Field names follow exactly the ELF specification nomenclature (`e_type`, `e_machine`, `e_version`, `e_entry`, etc.), which makes the correspondence with `readelf -h` immediate:

```python
hdr = elf.header  
print(f"Program headers : {hdr['e_phnum']}")  
print(f"Section headers : {hdr['e_shnum']}")  
print(f"String table    : index {hdr['e_shstrndx']}")  
```

### Iterating over sections

The `iter_sections()` method returns an iterator over all sections of the binary. Each section exposes its name, type, flags, and raw data:

```python
from elftools.elf.elffile import ELFFile

def list_sections(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        print(f"{'Index':>5}  {'Name':<20}  {'Type':<18}  {'Size':>10}  {'Addr':>12}")
        print("-" * 72)
        for i, section in enumerate(elf.iter_sections()):
            print(f"{i:5d}  {section.name:<20}  "
                  f"{section['sh_type']:<18}  "
                  f"{section['sh_size']:10d}  "
                  f"0x{section['sh_addr']:010x}")

list_sections("keygenme_O0")
```

To retrieve the raw data of a specific section — for example `.rodata`, where constants like `HASH_SEED` or the strings from `keygenme.c` reside — use `get_section_by_name()`:

```python
rodata = elf.get_section_by_name(".rodata")  
if rodata:  
    data = rodata.data()
    print(f".rodata : {len(data)} bytes")
    # Look for the keygenme banner
    idx = data.find(b"KeyGenMe")
    if idx >= 0:
        print(f"  Found 'KeyGenMe' at offset {idx} in .rodata")
```

### Extracting the symbol table

The symbol table (`.symtab`) only exists in non-stripped binaries. `pyelftools` exposes symbols through sections of type `SymbolTableSection`:

```python
from elftools.elf.sections import SymbolTableSection

def list_functions(path):
    """List FUNC-type symbols (functions) from a binary."""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        functions = []
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value'] != 0:
                    functions.append({
                        "name": sym.name,
                        "addr": sym['st_value'],
                        "size": sym['st_size'],
                        "bind": sym['st_info']['bind'],
                    })
        # Sort by address
        functions.sort(key=lambda s: s["addr"])
        return functions

for fn in list_functions("keygenme_O0"):
    print(f"  0x{fn['addr']:08x}  {fn['size']:5d}  {fn['bind']:<8}  {fn['name']}")
```

On `keygenme_O0` (compiled with `-g`), this script will list `main`, `check_license`, `compute_hash`, `derive_key`, `format_key`, `rotate_left`, and `read_line`. On `keygenme_strip`, the list will be empty — this is exactly what makes a stripped binary harder to analyze.

### Comparing symbols between variants

One of the immediate use cases for `pyelftools` in automation is comparing two variants of the same binary. The following script takes two paths and reports functions present in one but absent from the other:

```python
def compare_symbols(path_a, path_b):
    funcs_a = {fn["name"] for fn in list_functions(path_a)}
    funcs_b = {fn["name"] for fn in list_functions(path_b)}

    only_a = funcs_a - funcs_b
    only_b = funcs_b - funcs_a

    if only_a:
        print(f"Functions present only in {path_a}:")
        for name in sorted(only_a):
            print(f"  - {name}")
    if only_b:
        print(f"Functions present only in {path_b}:")
        for name in sorted(only_b):
            print(f"  - {name}")
    if not only_a and not only_b:
        print("Symbol tables are identical (function names).")

compare_symbols("keygenme_O0", "keygenme_O2")
```

On `keygenme`, a `-O0` vs `-O2` comparison will typically reveal that some functions like `rotate_left` have disappeared — the compiler inlined them. This type of automatic detection is valuable when analyzing a patch between two versions of a piece of software.

### Inspecting segments (program headers)

Segments define how the loader maps the binary into memory. They are essential for understanding the memory layout at runtime:

```python
def list_segments(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            print(f"  {seg['p_type']:<16}  "
                  f"offset=0x{seg['p_offset']:06x}  "
                  f"vaddr=0x{seg['p_vaddr']:010x}  "
                  f"memsz=0x{seg['p_memsz']:06x}  "
                  f"flags={'R' if seg['p_flags'] & 4 else '-'}"
                  f"{'W' if seg['p_flags'] & 2 else '-'}"
                  f"{'X' if seg['p_flags'] & 1 else '-'}")
```

### Reading dynamic entries

For dynamically linked binaries — like `crypto_O0` which depends on `libcrypto` — the `.dynamic` section contains the dependencies, search paths, and binding flags. `pyelftools` exposes them via `DynamicSection`:

```python
from elftools.elf.dynamic import DynamicSection

def list_needed(path):
    """Simplified equivalent of `ldd`: list NEEDED entries."""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        needed = []
        for section in elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed.append(tag.needed)
        return needed

libs = list_needed("crypto_O0")  
print("Dynamic dependencies:")  
for lib in libs:  
    print(f"  - {lib}")
# Expected: libcrypto.so.x, libc.so.6
```

This script is the building block for automatically detecting whether a binary embeds cryptographic dependencies — a valuable indicator during triage.

### Accessing DWARF information

If the binary was compiled with `-g`, the DWARF debug information is accessible. `pyelftools` offers a complete DWARF parser that allows you to retrieve source file names, line numbers, and data types:

```python
def list_source_files(path):
    """Extract source files referenced in DWARF information."""
    with open(path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("No DWARF information.")
            return
        dwarf = elf.get_dwarf_info()
        sources = set()
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == 'DW_TAG_compile_unit':
                    name = die.attributes.get('DW_AT_name')
                    comp_dir = die.attributes.get('DW_AT_comp_dir')
                    if name:
                        sources.add(name.value.decode())
        for src in sorted(sources):
            print(f"  {src}")

list_source_files("keygenme_O0")
# Expected: keygenme.c
```

---

## Part B — `lief`: Binary Inspection *and* Modification

### Installation and first contact

```bash
pip install lief
```

With `lief`, parsing is done in a single static call. The binary is fully loaded into memory — no *lazy parsing* like `pyelftools`, which means you do not need to keep the file open:

```python
import lief

binary = lief.parse("keygenme_O0")  
print(f"Format :     {binary.format}")  
print(f"Type :       {binary.header.file_type}")  
print(f"Machine :    {binary.header.machine_type}")  
print(f"Entry point: 0x{binary.entrypoint:x}")  
print(f"PIE :        {binary.is_pie}")  
print(f"NX :         {binary.has_nx}")  
```

You will immediately notice that `lief` exposes high-level properties (`is_pie`, `has_nx`) that would require several lines with `pyelftools`. It is this ergonomics that makes `lief` well-suited for rapid triage scripts.

### Sections: reading and searching

```python
for section in binary.sections:
    print(f"  {section.name:<20}  "
          f"size={section.size:>8}  "
          f"offset=0x{section.offset:06x}  "
          f"entropy={section.entropy:.2f}")
```

The `entropy` property is automatically computed by `lief`. It is a first-order indicator for detecting compressed or encrypted data. On `crypto_O2_strip`, the `.text` and `.rodata` sections will have moderate entropy (4-6), while a section containing encrypted or packed data will often exceed 7.

To search for specific bytes in a section — for example the magic constants from `keygenme`:

```python
import struct

rodata = binary.get_section(".rodata")  
if rodata:  
    content = bytes(rodata.content)
    # Look for HASH_SEED = 0x5A3C6E2D (little-endian)
    seed_bytes = struct.pack("<I", 0x5A3C6E2D)
    offset = content.find(seed_bytes)
    if offset >= 0:
        print(f"HASH_SEED found in .rodata at offset +0x{offset:x}")
```

### Symbols and imports

`lief` distinguishes between static symbols (`.symtab`), dynamic symbols (`.dynsym`), and imported functions. To list imports — which is essential for characterizing a binary even when stripped:

```python
def audit_imports(path):
    binary = lief.parse(path)
    imported = [sym.name for sym in binary.imported_symbols if sym.name]
    print(f"Imports from {path} ({len(imported)} symbols):")
    for name in sorted(imported):
        print(f"  {name}")
    return imported

# On crypto_O0, you will see: EVP_EncryptInit_ex, SHA256, RAND_bytes, etc.
# On keygenme_O0: strcmp, printf, fgets, strlen, etc.
```

This script, applied to `crypto_O0`, will immediately reveal the OpenSSL functions used — `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex`, `SHA256`, `RAND_bytes` — which allows you to identify at a glance that the binary performs AES encryption via the OpenSSL EVP API.

### Automated multi-binary triage

By combining `lief` features, you can build a triage script that produces a structured report for each binary in a directory:

```python
import lief  
import json  
import sys  
from pathlib import Path  

def triage(path):
    """Quick triage of an ELF binary. Returns a JSON-serializable dict."""
    binary = lief.parse(str(path))
    if binary is None:
        return {"path": str(path), "error": "not a valid binary"}

    # Notable imported functions (crypto, network, dangerous)
    imports = {sym.name for sym in binary.imported_symbols if sym.name}

    crypto_markers = imports & {
        "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex",
        "SHA256", "SHA1", "MD5", "AES_encrypt", "AES_decrypt",
        "RAND_bytes", "EVP_aes_256_cbc", "EVP_aes_128_cbc",
    }
    network_markers = imports & {
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom", "getaddrinfo",
    }

    # Sections and entropy
    sections_info = []
    for s in binary.sections:
        sections_info.append({
            "name": s.name,
            "size": s.size,
            "entropy": round(s.entropy, 2),
        })

    # Protection detection
    report = {
        "path":       str(path),
        "type":       str(binary.header.file_type).split(".")[-1],
        "machine":    str(binary.header.machine_type).split(".")[-1],
        "entry":      f"0x{binary.entrypoint:x}",
        "pie":        binary.is_pie,
        "nx":         binary.has_nx,
        "stripped":   len(list(binary.static_symbols)) == 0,
        "num_sections": len(binary.sections),
        "sections":   sections_info,
        "needed":     [lib for lib in binary.libraries],
        "imports_count": len(imports),
        "crypto":     sorted(crypto_markers),
        "network":    sorted(network_markers),
    }
    return report

# Usage on a directory
if __name__ == "__main__":
    target_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    results = []
    for path in sorted(target_dir.glob("*")):
        if path.is_file() and not path.suffix:
            results.append(triage(path))
    print(json.dumps(results, indent=2))
```

Run on the `binaries/ch21-keygenme/` directory, this script will produce a JSON containing the triage report for all five variants. The differences will clearly stand out: `keygenme_O0` has symbols, `keygenme_strip` no longer does; all of them import `strcmp` (confirming the presence of a string comparison); none has any crypto or network marker. Run on `binaries/ch24-crypto/`, the `crypto` field will be filled with OpenSSL functions.

### Modifying a binary: patching the entry point

`lief` allows you to modify ELF structures and then rewrite the binary. The simplest example is modifying the entry point:

```python
binary = lief.parse("keygenme_O0")  
print(f"Original entry point: 0x{binary.entrypoint:x}")  

# Suppose we want to point the entry to a different address
# (in practice, to a function identified during analysis)
# Here we are only demonstrating the mechanism:
original_entry = binary.entrypoint  
binary.header.entrypoint = 0x401000  # fictitious address for the example  

binary.write("keygenme_O0_patched")  
print("Patched binary written to keygenme_O0_patched")  

# Restore to avoid breaking our working binary
binary.header.entrypoint = original_entry
```

> ⚠️ Modifying the entry point to an invalid address produces a binary that will segfault on launch. In an RE context, this capability is used to redirect execution to injected code or to bypass a packer that decrypts code at startup.

### Modifying a binary: patching bytes

The most common use case in RE is *patching*: modifying a few bytes in `.text` to change the program's behavior. We saw in Chapter 21 that the license verification in `keygenme` ends with a `strcmp` followed by a conditional jump (`jz` / `jnz`). With `lief`, you can automate this transformation.

The principle is to locate the byte sequence to modify, then use `patch_address()` to write the new bytes:

```python
binary = lief.parse("keygenme_O0")

# Look for opcode 0x75 (jnz) followed by a short displacement
# in the .text section, near the strcmp call
text = binary.get_section(".text")  
content = bytes(text.content)  
base_addr = text.virtual_address  

# Naive search — in production, you would use a disassembler
# to precisely identify the offset of the jump.
# Here, we illustrate the patching mechanism.
offset = content.find(b"\x75")  # jnz (short jump)  
if offset >= 0:  
    target_addr = base_addr + offset
    # Replace jnz (0x75) with jz (0x74) — invert the condition
    binary.patch_address(target_addr, [0x74])
    binary.write("keygenme_O0_cracked")
    print(f"Patched jnz -> jz at 0x{target_addr:x}")
```

> 💡 The naive search for an opcode `0x75` across all of `.text` is obviously not reliable — the same byte can appear as immediate data or in another context. In production, you would combine `lief` with a disassembler (`capstone`) to precisely locate the instruction to patch. Chapter 21, section 6 details the manual approach with ImHex; here, the goal is to show how `lief` allows you to programmatically perform this transformation.

### Adding a section

`lief` allows you to add sections to an existing binary. This is useful for injecting audit metadata (analysis date, hash, identifier) or for preparing a binary to receive instrumented code:

```python
import lief  
import time  

binary = lief.parse("keygenme_O0")

# Create a metadata section
meta = lief.ELF.Section()  
meta.name = ".re_audit"  
meta.type = lief.ELF.Section.TYPE.NOTE  
meta.content = list(f"Audited on {time.ctime()} by triage.py\x00".encode())  
meta.alignment = 1  

binary.add(meta)  
binary.write("keygenme_O0_audited")  

# Verification
check = lief.parse("keygenme_O0_audited")  
audit_section = check.get_section(".re_audit")  
print(f"Section added: {audit_section.name}, {audit_section.size} bytes")  
print(f"Content: {bytes(audit_section.content).decode(errors='replace')}")  
```

### Modifying dynamic dependencies

You can add or remove libraries from the `NEEDED` list. This is the programmatic mechanism behind the `LD_PRELOAD` technique seen in Chapter 22 — except that here, the modification is permanent in the binary:

```python
binary = lief.parse("crypto_O0")  
print("Libraries before:", binary.libraries)  

# Add a library (for example a custom hook)
binary.add_library("libhook.so")  
binary.write("crypto_O0_hooked")  

modified = lief.parse("crypto_O0_hooked")  
print("Libraries after:", modified.libraries)  
```

---

## Part C — Combining Both Libraries

In practice, a sophisticated triage script will use both libraries according to their respective strengths. Here is a common pattern: `pyelftools` for fine-grained inspection of DWARF structures and symbol tables, `lief` for rapid triage and transformations.

```python
import lief  
from elftools.elf.elffile import ELFFile  
from elftools.elf.sections import SymbolTableSection  

def deep_audit(path):
    """
    Combined audit:
    - lief for high-level properties and entropy
    - pyelftools for DWARF details and the symbol table
    """
    # --- Phase 1: lief (overview) ---
    binary = lief.parse(path)
    report = {
        "path": path,
        "pie": binary.is_pie,
        "nx": binary.has_nx,
        "libraries": list(binary.libraries),
        "imports": sorted(s.name for s in binary.imported_symbols if s.name),
        "high_entropy_sections": [
            s.name for s in binary.sections if s.entropy > 6.5
        ],
    }

    # --- Phase 2: pyelftools (fine details) ---
    with open(path, "rb") as f:
        elf = ELFFile(f)

        # Local functions (not imported)
        local_funcs = []
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if (sym['st_info']['type'] == 'STT_FUNC'
                            and sym['st_info']['bind'] == 'STB_LOCAL'
                            and sym['st_value'] != 0):
                        local_funcs.append(sym.name)
        report["local_functions"] = sorted(local_funcs)

        # Source files (DWARF)
        if elf.has_dwarf_info():
            dwarf = elf.get_dwarf_info()
            sources = set()
            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag == 'DW_TAG_compile_unit':
                        name_attr = die.attributes.get('DW_AT_name')
                        if name_attr:
                            sources.add(name_attr.value.decode())
            report["source_files"] = sorted(sources)
        else:
            report["source_files"] = []

    return report
```

On `keygenme_O0`, the `local_functions` field will contain `compute_hash`, `derive_key`, `format_key`, `rotate_left`, `check_license`, `read_line` — all the functions declared `static` in `keygenme.c`. On the stripped variant, this list will be empty, but the `imports` will still contain `strcmp`, `printf`, `strlen`, `fgets`, confirming the nature of the binary. The `source_files` field will contain `keygenme.c` for variants compiled with `-g`, and will be empty for stripped variants.

---

## When to use what — summary

| Task | `pyelftools` | `lief` |  
|---|---|---|  
| Read ELF headers | ✅ Faithful to the spec | ✅ More ergonomic |  
| Parse DWARF (debug info) | ✅ Complete parser | ❌ Not supported |  
| Inspect `.symtab` / `.dynsym` | ✅ | ✅ |  
| Compute section entropy | ❌ (must code it yourself) | ✅ Built-in |  
| PIE / NX / RELRO detection | ❌ (manual flag reading) | ✅ Direct properties |  
| Patch bytes in `.text` | ❌ Read-only | ✅ `patch_address()` |  
| Add / remove a section | ❌ | ✅ `add()` / `remove()` |  
| Modify `NEEDED` entries | ❌ | ✅ `add_library()` |  
| Rewrite binary to disk | ❌ | ✅ `write()` |  
| Minimal external dependency | ✅ Pure Python | ❌ C++ extension |

The rule of thumb is simple: if your script only *reads*, `pyelftools` is more predictable and maps better to `readelf` output. If your script needs to *modify* the binary or if you need high-level properties (entropy, PIE, NX) without extra code, `lief` is the natural choice. And if you need both — which is frequent — nothing prevents you from using them together in the same script.

---


⏭️ [Automating Ghidra in headless mode (batch analysis of N binaries)](/35-automation-scripting/02-ghidra-headless-batch.md)
