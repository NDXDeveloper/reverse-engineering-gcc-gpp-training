🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 34.5 — Go Strings: the `(ptr, len)` structure and implications for `strings`

> 🐹 *The `strings` command is the reverse engineer's number one reflex when facing an unknown binary (Chapter 5). On a C binary, it works remarkably well. On a Go binary, it produces misleading results — merged strings, incomprehensible fragments, thousands of false positives. Understanding why, and knowing how to extract the real strings, is an essential skill for Go RE.*

---

## Recap: Strings in C vs in Go

### The C Model: Null-Terminated

In C, a string is a byte array terminated by a null byte (`\0`). The compiler places each string literal in `.rodata` with its terminator, and the code references it through a simple pointer:

```
.rodata :
  0x1000: 48 65 6C 6C 6F 00         "Hello\0"
  0x1006: 57 6F 72 6C 64 00         "World\0"
```

The `strings` command looks for exactly this pattern: sequences of printable bytes of minimum length (default 4), terminated by a null or an end of section. On C code, each string is clearly delimited — `strings` finds them reliably.

### The Go Model: `(ptr, len)`

In Go, a string is a 16-byte header (section 34.3):

```
┌──────────────────┐
│  ptr   (8 bytes) │ → points to the UTF-8 data
├──────────────────┤
│  len   (8 bytes) │ → length in bytes
└──────────────────┘
```

The pointed-to data is **not** null-terminated. The length is carried by the header, not by a sentinel byte. This has a direct consequence: the Go compiler has no reason to insert a `\0` between two consecutive strings in `.rodata`.

---

## The String Blob: How GCC/Go Stores Literals

### Concatenation in `.rodata`

The Go compiler groups all string literals from the program into a contiguous area of `.rodata` (or `.go.string`). The strings are stored end-to-end, without separators:

```
.rodata (excerpt from crackme_go):
  0x4A000: 69 6E 76 61 6C 69 64 20 67 72 6F 75 70 20 63 68
           "invalid group ch"
  0x4A010: 65 63 6B 73 75 6D 2E 4F 72 64 65 72 20 63 6F 6E
           "ecksum.Order con"    ← no \0 between the two strings
  0x4A020: 73 74 72 61 69 6E 74 42 72 61 76 6F 2C 20 72 65
           "straintBravo, re"    ← "constraint" continues directly into "Br"
  0x4A030: 76 65 72 73 65 72 20 21 ...
           "verser !"
```

No `\0` between strings. Each use in the code references an offset and a length in this blob:

```asm
; Reference to "invalid key" (11 bytes starting at 0x4A010)
LEA     RAX, [0x4A010]         ; ptr  
MOV     RBX, 11                ; len = 11  
```

### Substring Sharing (Partial Interning)

The compiler can go further: if one string is a suffix or subset of another, it reuses the same storage. For example, if the program contains the literals `"format invalid"` and `"invalid"`, the compiler may store only `"format invalid"` and point `"invalid"` to offset `+7` in the same data.

This sharing is invisible at the source code level but produces pointers that land in the middle of another string — making any naive reconstruction even more difficult.

---

## Why `strings` Fails on Go Binaries

### Problem 1: String Merging

Without null separators, `strings` sees a long contiguous sequence of printable characters and reports it as a single giant string:

```bash
$ strings crackme_go_strip | head -5
Format errorinvalid keyValid group checksums.Order constraint  
met.Cross verification OK.Valid key! Bravo, reve  
rser!Usage: ...  
```

Instead of seven distinct strings, `strings` produces an unreadable block. The analyst must guess where one string ends and the next one begins.

### Problem 2: Volume of Noise

A Go binary embeds the standard library and the runtime. The `.rodata` section contains thousands of internal strings: runtime error messages, function names, type descriptors, `fmt` format strings, panic messages, compiler source file names (`/usr/local/go/src/runtime/...`). On a typical `crackme_go`:

```bash
$ strings crackme_go | wc -l
12847

$ strings crackme_go_strip | wc -l
11203
```

Among these thousands of lines, only a few dozen come from the business code. The signal-to-noise ratio is catastrophic.

### Problem 3: Binary False Positives

Since `strings` merely looks for sequences of printable bytes, binary data (opcodes, hash tables, numeric constants) can accidentally form sequences that look like text. This phenomenon exists in C too, but it is amplified in Go by the binary's size.

### Problem 4: Multi-Byte UTF-8 Strings

Go treats strings as UTF-8 byte sequences. Non-ASCII characters (accents, emojis, CJK) are encoded on 2 to 4 bytes. The default `strings` option (ASCII search) may truncate or miss these strings. The `-e S` option (UTF-8 encoding) helps partially, but does not solve the other problems.

---

## Techniques for Correctly Extracting Go Strings

### Technique 1: Extraction via `gopclntab` and Assembly References

The most reliable method is to find strings by following references in the disassembled code. Each string literal used in the program produces a characteristic pair of instructions:

```asm
; New ABI pattern (Go ≥ 1.17) — string as argument
LEA     RAX, [rip + offset_dans_rodata]   ; ptr  
MOV     RBX, longueur_immédiate            ; len  
```

```asm
; Old ABI pattern (Go < 1.17) — string on the stack
LEA     RAX, [rip + offset_dans_rodata]  
MOV     [RSP+arg_offset], RAX              ; ptr on the stack  
MOV     QWORD PTR [RSP+arg_offset+8], len  ; len on the stack  
```

By searching for these patterns in the disassembly, you can extract each (address, length) pair and reconstruct the exact string.

**Ghidra Python script for extracting Go strings:**

```python
# extract_go_strings.py — Ghidra script
# Searches for LEA + MOV imm patterns that indicate Go string literals.

from ghidra.program.model.scalar import Scalar  
import re  

listing = currentProgram.getListing()  
mem = currentProgram.getMemory()  
results = []  

# Iterate over all instructions in the .text segment
text_block = mem.getBlock(".text")  
if text_block is None:  
    print(".text section not found")
else:
    inst_iter = listing.getInstructions(text_block.getStart(), True)
    prev_inst = None

    while inst_iter.hasNext():
        inst = inst_iter.next()
        # Search for: LEA REG, [addr] followed by MOV REG, immediate
        if prev_inst is not None:
            prev_mn = prev_inst.getMnemonicString()
            curr_mn = inst.getMnemonicString()

            if prev_mn == "LEA" and curr_mn == "MOV":
                # Check that the MOV has an immediate operand (the length)
                num_ops = inst.getNumOperands()
                if num_ops >= 2:
                    scalar = inst.getScalar(1)
                    if scalar is not None:
                        str_len = scalar.getUnsignedValue()
                        if 1 <= str_len <= 4096:
                            # Read the references from the LEA
                            refs = prev_inst.getReferencesFrom()
                            for ref in refs:
                                addr = ref.getToAddress()
                                try:
                                    buf = bytearray(str_len)
                                    mem.getBytes(addr, buf)
                                    s = buf.decode('utf-8', errors='replace')
                                    if all(c.isprintable() or c in '\n\r\t' for c in s):
                                        results.append((addr, str_len, s))
                                except:
                                    pass
        prev_inst = inst

    print("Go strings extracted: {}".format(len(results)))
    for addr, length, s in sorted(results, key=lambda x: x[0]):
        print("  0x{} [{}] : {}".format(addr, length, repr(s)))
```

This script is a heuristic — it does not capture 100% of strings (some are loaded indirectly, via structures or tables), but it extracts the vast majority of literals used in the application code.

### Technique 2: Extraction via `runtime.stringStruct` Structures

Global variables and struct fields containing strings are stored in `.data` or `.noptrdata` as `(ptr, len)` headers. By scanning these sections for pairs (pointer into `.rodata`, reasonable integer), you can reconstruct additional strings:

```python
# Pseudo-code for scanning string headers in .data
for offset in range(data_start, data_end, 8):
    ptr = read_uint64(offset)
    length = read_uint64(offset + 8)
    if rodata_start <= ptr < rodata_end and 1 <= length <= 10000:
        s = read_bytes(ptr, length).decode('utf-8', errors='replace')
        if is_printable(s):
            print(f"String header at 0x{offset:x}: [{length}] {s!r}")
```

### Technique 3: GoReSym and Strings

GoReSym (section 34.4) does not directly extract string literals from code, but it provides:

- **function names** (which are themselves strings in `gopclntab`'s name table),  
- **type names** (in the `runtime._type` descriptors),  
- **source file names** (in the file table).

These strings are extracted cleanly, with their correct boundaries.

### Technique 4: Enhanced `strings` with Filtering

If you must use `strings` despite its limitations, combine it with intelligent filtering to reduce noise:

```bash
# Exclude runtime and stdlib paths
strings -n 6 crackme_go_strip | grep -v '/usr/local/go' \
    | grep -v 'runtime\.' | grep -v 'internal/' \
    | grep -v 'sync\.' | grep -v 'syscall\.' \
    | grep -v 'encoding/' | grep -v 'unicode/' \
    | grep -v 'reflect\.' | grep -v 'errors\.'
```

```bash
# Search for patterns specific to business code
strings -n 6 crackme_go_strip | grep -iE 'key|license|password|valid|error|flag|secret'
```

```bash
# Limit to strings of reasonable length (not merged blobs)
strings -n 6 crackme_go_strip | awk 'length < 80'
```

These commands do not solve the merging problem, but they significantly reduce noise.

### Technique 5: Dynamic Extraction with GDB

In dynamic analysis, strings are easier to capture — they appear in registers and on the stack as (ptr, len) pairs at the moment of use:

```gdb
# Breakpoint on a function that receives a string argument
# New ABI: RAX = ptr, RBX = len
break main.parseKey  
run DEAD-BEEF-CAFE-BABE  

# At the stop, display the string
x/s $rax
# Caution: x/s assumes a null terminator, it may display too much.
# Correct method — use the length:
printf "%.*s\n", (int)$rbx, (char*)$rax
```

The GDB command `printf "%.*s\n"` with the `%.*s` format is the key: it uses the explicit length (`$rbx`) instead of looking for a null.

```gdb
# With GEF/pwndbg, more readable helper:
define go_str
    set $ptr = $arg0
    set $len = $arg1
    printf "Go string [%d]: ", $len
    eval "x/%dbs $ptr", $len
end

# Usage:
go_str $rax $rbx
```

### Technique 6: Hooking with Frida

Frida allows intercepting functions that manipulate strings and displaying them properly:

```javascript
// Hook runtime.gostring to capture C string → Go string conversions
// But more useful: hook application functions
Interceptor.attach(Module.findExportByName(null, "main.parseKey"), {
    onEnter: function(args) {
        // New Go ABI: first string arg = (RAX, RBX)
        // Frida exposes registers via this.context
        var ptr = this.context.rax;
        var len = this.context.rbx.toInt32();
        if (len > 0 && len < 4096) {
            console.log("parseKey called with: " +
                        Memory.readUtf8String(ptr, len));
        }
    }
});
```

> 💡 **RE tip**: hooking `fmt.Fprintf`, `fmt.Sprintf`, and `os.(*File).WriteString` with Frida captures most of the strings displayed on screen or written to files by the program. This is often sufficient to understand the application logic without analyzing the disassembly in detail.

---

## Strings in the Crackme: A Concrete Case

Let us apply these techniques to our `crackme_go_strip`. Here is what each method reveals:

### Raw `strings`

```bash
$ strings -n 8 crackme_go_strip | grep -i 'valid\|error\|key\|check\|bravo'
```

The result is probably a merged fragment containing several messages end-to-end. It is difficult to determine the exact boundaries.

### GoReSym — Function Names

```bash
$ GoReSym -p crackme_go_strip | jq '.UserFunctions[].FullName' | head
"main.main"
"main.parseKey"
"main.hexVal"
"main.validateGroups"
"main.validateCross"
"main.validateOrder"
"main.(*ChecksumValidator).Validate"
"main.(*CrossValidator).Validate"
```

The function names already reveal the program's structure and business vocabulary. Each name is extracted cleanly thanks to the null-terminated name table in `gopclntab`.

### GDB — Dynamic Capture

```gdb
# Set a breakpoint on the string comparison in validateGroups
break main.(*ChecksumValidator).Validate  
run DEAD-BEEF-CAFE-BABE  

# Inspect the receiver (*ChecksumValidator) and the arguments
info registers rax rbx rcx rdi rsi
```

In dynamic analysis, strings appear decomposed into (ptr, len) pairs in the registers, directly readable.

---

## Tool and Effectiveness Summary

```
Method                       Effort    Precision   Coverage
─────────────────────────    ──────    ─────────   ──────────
strings (raw)                Minimal   Low         High (but noisy and merged)  
strings + grep filtering     Low       Medium      Medium  
GoReSym (func/type names)    Low       Excellent   Names only, not literals  
Ghidra LEA+MOV script        Medium    Good        Good (literals referenced in code)  
String header scan           Medium    Good        Global variables and struct fields  
GDB printf %.*s              Medium    Excellent   Limited to executed paths  
Frida hooking                Medium    Excellent   Limited to executed paths  
```

In practice, the combination of **GoReSym** (function and type names) + **Ghidra script** (literals in code) + **Frida/GDB** (dynamic validation) covers virtually all needs.

---

## Common Pitfalls

### Pitfall 1: `x/s` in GDB

GDB's `x/s $rax` command displays a null-terminated string at the address in `RAX`. But since Go strings are not null-terminated, GDB will continue reading past the end of the string, displaying parasitic data from the next string in the `.rodata` blob. Always use `printf "%.*s\n"` with the explicit length.

### Pitfall 2: Ghidra and the `char *` Type

When Ghidra detects a `LEA` into `.rodata`, it may attempt to automatically create a `char *` null-terminated data at that address. Since there is no null, Ghidra creates a "string" that encompasses all following strings. This corrupts the `.rodata` display. To fix this, delete the auto-created data (`Clear Code Bytes`) and recreate it manually with the correct length.

### Pitfall 3: Length in Bytes vs Length in Runes

In Go, `len("café")` returns 5 (bytes), not 4 (characters), because `é` is encoded as 2 bytes in UTF-8. The `len` field in the string header is always in **bytes**. If you read `len = 5` for a string that appears to have 4 characters, think multi-byte UTF-8.

### Pitfall 4: Empty Strings and Nil Strings

The empty string `""` has an arbitrary `ptr` (often non-nil, pointing to a valid location) and `len = 0`. The zero-value string (never initialized) has `ptr = nil` and `len = 0`. Both are functionally equivalent in Go, but in RE, a null pointer in a string header indicates an uninitialized variable rather than an explicit `""`.

### Pitfall 5: `[]byte` vs `string`

The header of a byte slice `[]byte` (24 bytes: ptr, len, cap) and the header of a string (16 bytes: ptr, len) look alike in their first two fields. If you see a pattern that looks like a string but with a third word (capacity), it is a `[]byte`. The distinction matters: `[]byte` values are mutable, strings are not. A `[]byte` buffer will likely be modified in place, while a string will be copied if it needs to change.

---

## Key Takeaways

1. **Go strings are not null-terminated.** This is the source of all problems with `strings`. The compiler stores them end-to-end in `.rodata` without separators.  
2. **Do not trust raw `strings`.** Use it only as a rough first pass, with aggressive filtering to eliminate runtime noise.  
3. **Look for `LEA` + `MOV imm` pairs.** This is the characteristic assembly pattern of a Go string literal. A Ghidra script or a grep in the disassembly captures them effectively.  
4. **In dynamic analysis, use the explicit length.** `printf "%.*s\n", len, ptr` in GDB, or `Memory.readUtf8String(ptr, len)` in Frida.  
5. **GoReSym extracts names, not literals.** Combine it with other techniques to cover all the program's strings.  
6. **Watch out for substring sharing.** Two different string headers may point to overlapping regions in `.rodata`. This does not indicate an error — it is a compiler optimization.

⏭️ [Stripped Go Binaries: recovering symbols via internal structures](/34-re-go/06-stripped-go-symbols.md)
