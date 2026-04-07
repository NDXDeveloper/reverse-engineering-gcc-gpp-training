🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 20.6 — Exporting and Cleaning Pseudo-Code to Produce Recompilable Code

> 📘 **Chapter 20 — Decompilation and Source Code Reconstruction**  
> **Part IV — Advanced RE Techniques**

---

## The objective and its limits

The previous sections showed how to obtain readable pseudo-code, how to guide it by retyping and renaming in Ghidra, how to cross-reference with RetDec, how to formalize types in a header, and how to eliminate third-party library noise. This final section pushes the approach to its logical conclusion: **exporting pseudo-code out of Ghidra and cleaning it enough so that it compiles**.

Let's be honest from the start: producing functionally identical code to the original binary that compiles and runs correctly is an objective rarely achieved at 100%. Section 20.1 explained why — too much information is irreversibly lost. But pursuing this objective does not need to fully succeed to be useful. Pseudo-code cleaned to 80% that compiles with a few stubs is already a valuable deliverable: it serves as executable documentation, a basis for writing tests, a starting point for a port or rewrite, and a reference for understanding binary behavior without reopening Ghidra every time.

This section details the complete process: extraction from Ghidra, systematic cleanup, resolving compilation issues, and scripts that automate part of the work.

---

## Extracting pseudo-code from Ghidra

### Manual export function by function

The most direct method is copy-paste from the Decompiler panel. Select all pseudo-code for a function (Ctrl+A in the panel), copy (Ctrl+C), and paste into a text editor. This is simple, but tedious when the binary contains dozens of functions of interest.

The copied pseudo-code includes the function signature, body, and local variable declarations. It does not include types defined in the Data Type Manager (structures, enums), nor prototypes of called functions — these must be added separately, typically via the header reconstructed in section 20.4.

### Export via the Ghidra menu

Ghidra offers a more structured export via *File → Export Program*. Among the available formats, the **C/C++** option exports the entire decompiled pseudo-code into a single `.c` file. This file contains all functions that the decompiler could process, preceded by their type declarations.

To access it: *File → Export Program → Format: C/C++ → Options* (you can choose whether to include headers, types, address comments). The resulting file can span several thousand lines for a medium-sized binary.

The full export is a good starting point, but it contains everything — including library functions identified by Function ID, GCC runtime stubs, and functions that do not need to be reconstructed. The cleanup work that follows is therefore essential.

### Export via Ghidra script (headless or interactive)

For finer control, a Ghidra script in Python (Jython) or Java allows selectively exporting functions of interest. Here is an example Python script that exports only functions tagged `USER_CODE` (using the Function Tags mentioned in section 20.5):

```python
# export_user_functions.py — Ghidra Script (Jython)
# Exports pseudo-code for functions tagged USER_CODE

from ghidra.app.decompiler import DecompInterface  
from ghidra.util.task import ConsoleTaskMonitor  

output_path = "/tmp/decompiled_user_code.c"  
tag_name = "USER_CODE"  

decomp = DecompInterface()  
decomp.openProgram(currentProgram)  
monitor = ConsoleTaskMonitor()  

fm = currentProgram.getFunctionManager()  
functions = fm.getFunctions(True)  

with open(output_path, "w") as f:
    f.write("/* Pseudo-code exported from Ghidra */\n")
    f.write("/* Binary: %s */\n\n" % currentProgram.getName())

    for func in functions:
        tags = func.getTags()
        tag_names = [t.getName() for t in tags]
        if tag_name in tag_names:
            result = decomp.decompileFunction(func, 60, monitor)
            if result.decompileCompleted():
                code = result.getDecompiledFunction().getC()
                f.write("/* --- %s @ 0x%x --- */\n" %
                        (func.getName(), func.getEntryPoint().getOffset()))
                f.write(code)
                f.write("\n\n")

decomp.dispose()  
print("[+] Export complete: %s" % output_path)  
```

This script can be launched in interactive mode (*Script Manager → Run*) or in headless mode for batch processing (chapter 8, section 9). The advantage is producing only business code, without library function noise.

The script can be adapted to filter by other criteria: by namespace, by address range, by naming convention (exclude all functions starting with `__` or `std::`), or by minimum size (ignore stub functions with fewer than 10 instructions).

---

## Anatomy of raw exported pseudo-code

Before cleaning, let's examine what a raw export typically contains. Here is a representative excerpt from `keygenme_O2_strip`, after renaming and retyping in Ghidra but without cleanup:

```c
void derive_key(char *username,uint32_t seed,uint8_t *out_key)

{
  size_t sVar1;
  uint32_t hash_r0;
  uint32_t hash_r1;
  uint32_t uVar2;
  size_t i;
  
  sVar1 = strlen(username);
  hash_r0 = seed;
  for (i = 0; i < sVar1; i = i + 1) {
    uVar2 = (uint32_t)(byte)username[i];
    hash_r0 = ((hash_r0 ^ uVar2) << 5 | (hash_r0 ^ uVar2) >> 0x1b) +
              uVar2 * 0x1000193;
    hash_r0 = hash_r0 ^ hash_r0 >> 0x10;
  }
  *out_key = (byte)(hash_r0 >> 0x18);
  out_key[1] = (byte)(hash_r0 >> 0x10);
  out_key[2] = (byte)(hash_r0 >> 8);
  out_key[3] = (byte)hash_r0;
  hash_r1 = hash_r0 ^ 1;
  for (i = 0; i < sVar1; i = i + 1) {
    uVar2 = (uint32_t)(byte)username[i];
    hash_r1 = ((hash_r1 ^ uVar2) << 5 | (hash_r1 ^ uVar2) >> 0x1b) +
              uVar2 * 0x1000193;
    hash_r1 = hash_r1 ^ hash_r1 >> 0x10;
  }
  out_key[4] = (byte)(hash_r1 >> 0x18);
  out_key[5] = (byte)(hash_r1 >> 0x10);
  /* ... continues for rounds 2 and 3 ... */
  return;
}
```

This pseudo-code is functionally correct, but it presents several problems that prevent compilation and hinder readability. Let's identify them systematically.

---

## Categories of problems to fix

### Problem 1: non-standard Ghidra types

Ghidra's pseudo-code uses internal types that do not exist in standard C:

| Ghidra type | Meaning | C replacement |  
|---|---|---|  
| `byte` | Unsigned 8-bit integer | `uint8_t` |  
| `ushort` | Unsigned 16-bit integer | `uint16_t` |  
| `uint` | Unsigned 32-bit integer | `uint32_t` |  
| `ulong` | Unsigned 64-bit integer | `uint64_t` |  
| `undefined` | Untyped byte | `uint8_t` |  
| `undefined2` | 2 untyped bytes | `uint16_t` |  
| `undefined4` | 4 untyped bytes | `uint32_t` |  
| `undefined8` | 8 untyped bytes | `uint64_t` |  
| `bool` | Ghidra boolean | `_Bool` or `int` |  
| `code` | Code pointer | Function pointer |  
| `longlong` | Signed 64-bit integer | `int64_t` |

The fix is mechanical: a global find-and-replace in the text editor. The order of replacements matters — process `undefined4` before `undefined` to avoid partial replacements.

### Problem 2: explicit Ghidra casts

Ghidra inserts explicit casts very frequently, often more than necessary. The raw pseudo-code is littered with expressions like:

```c
uVar2 = (uint32_t)(byte)username[i];
```

Here, the double cast `(byte)` then `(uint32_t)` is technically correct (extract an unsigned byte then promote to 32 bits), but standard C performs this promotion implicitly when `username` is a `char *`. Cleanup consists of removing redundant casts while keeping those that are semantically necessary (notably signedness casts).

The practical rule: a cast is kept if it changes behavior (signed → unsigned, explicit truncation, pointer conversion). It is removed if it only makes explicit an implicit C promotion.

### Problem 3: hexadecimal constants

The decompiler displays almost all constants in hexadecimal: `0x1b` instead of `27`, `0x18` instead of `24`, `0x10` instead of `16`. Some of these values are more readable in decimal (sizes, counters, bit shifts), others are more readable in hexadecimal (masks, magic numbers, addresses).

The conversion cannot be blindly automated — it requires semantic judgment. Some useful heuristics: shift arguments (`>> 0x18`) are clearer in decimal (`>> 24`). Multiplicative constants like `0x01000193` are algorithm identifiers and should remain in hexadecimal. Sizes like `0x40` are often clearer in decimal (`64`) unless they correspond to notable powers of 2.

### Problem 4: missing prototypes and includes

The exported pseudo-code contains no `#include`. Libc functions (`strlen`, `printf`, `fgets`, `memcmp`) are called without prior declaration. The compiler issues warnings (implicit function declaration) or errors depending on the targeted C standard.

The fix consists of adding necessary includes at the top of the file. The most common ones for our binaries:

```c
#include <stdio.h>      /* printf, fgets, fprintf, puts */
#include <stdlib.h>     /* atoi, malloc, free, exit */
#include <string.h>     /* strlen, memcmp, memcpy, strncmp, memset */
#include <stdint.h>     /* uint8_t, uint32_t, etc. */
#include <stddef.h>     /* size_t, offsetof */
#include <unistd.h>     /* close, read, write (POSIX) */
#include <sys/socket.h> /* socket, bind, listen, accept (network) */
#include <arpa/inet.h>  /* htons, inet_pton (network) */
```

The header reconstructed in section 20.4 must also be included to provide structure, enumeration, and constant definitions.

### Problem 5: local variables declared at block start

Ghidra declares all local variables at the beginning of the function, in C89 style. This compiles, but makes the code less readable than the C99/C11 style where variables are declared at the point of first use. Cleanup consists of moving declarations closer to their usage when it improves clarity.

This cleanup is optional — it does not change semantics — but it considerably brings the code closer to what a human developer would write.

### Problem 6: compiler-unrolled code

As seen in section 20.2, loops unrolled by GCC appear in pseudo-code as repetitive linear code. The fix is to **refactor** the code by reintroducing the loops and auxiliary functions that the compiler had inlined or unrolled.

For `derive_key`, this means extracting the hashing loop into a separate `mix_hash` function and reintroducing the outer loop over the 4 rounds. This is the inverse transformation of the inlining/unrolling performed by GCC. It is also the most impactful correction on readability, and the one requiring the most understanding of the code logic.

### Problem 7: explicit void return

Ghidra adds an explicit `return;` at the end of every `void` function. This is valid in C but non-idiomatic — the usual convention is to omit the `return` at the end of `void` functions. Removing it is cosmetic but contributes to the "normalcy" of the produced code.

### Problem 8: unnecessarily complex expressions

The decompiler sometimes produces correct but more complex expressions than necessary. The expression `(hash ^ uVar2) << 5 | (hash ^ uVar2) >> 0x1b` is correct, but it computes `hash ^ uVar2` twice. A natural cleanup is to introduce a temporary variable:

```c
uint32_t tmp = hash ^ (uint32_t)username[i];  
hash = (tmp << 5) | (tmp >> 27);  /* rotate_left(tmp, 5) */  
```

Better yet, if the rotation pattern has been identified (section 20.2), a macro or inline function can be reintroduced:

```c
static inline uint32_t rotate_left(uint32_t val, unsigned int n) {
    return (val << n) | (val >> (32 - n));
}
```

---

## Step-by-step cleanup process

Here is the complete process, in recommended order. Each step builds on the previous one.

### Step 1: prepare the skeleton

Create a `.c` file with necessary includes, include the reconstructed header, and add a header comment documenting the origin:

```c
/*
 * keygenme_reconstructed.c
 *
 * Code reconstructed by decompilation of keygenme_O2_strip
 * Source binary SHA256: [hash]
 * Tools: Ghidra 11.x + RetDec 5.0
 * Date: [date]
 *
 * NOTE: this code is an approximate reconstruction.
 * It may differ from the original source in names,
 * style and micro-optimizations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "keygenme_reconstructed.h"
```

### Step 2: replace Ghidra types

Apply the mechanical replacements across the entire file. A `sed` script does the job:

```bash
sed -i \
    -e 's/\bundefined8\b/uint64_t/g' \
    -e 's/\bundefined4\b/uint32_t/g' \
    -e 's/\bundefined2\b/uint16_t/g' \
    -e 's/\bundefined\b/uint8_t/g' \
    -e 's/\bbyte\b/uint8_t/g' \
    -e 's/\bushort\b/uint16_t/g' \
    -e 's/\bulong\b/uint64_t/g' \
    -e 's/\blonglong\b/int64_t/g' \
    keygenme_reconstructed.c
```

The order of replacements matters: `undefined8` before `undefined` to avoid transforming `undefined8` into `uint8_t8`.

### Step 3: first compilation attempt

Compile with maximum warnings to identify remaining issues:

```bash
gcc -Wall -Wextra -Wpedantic -std=c11 -c keygenme_reconstructed.c
```

The `-c` flag compiles without linking — we are not yet trying to produce an executable, only verifying that the code is syntactically and semantically valid. Warnings and errors guide the next corrections.

Typical errors at this stage are: undeclared functions (add a prototype or include), undefined types (check the header), and pointer incompatibilities (adjust casts).

### Step 4: clean up casts and constants

Manually walk through the code to remove redundant casts and convert hexadecimal constants to decimal where appropriate. This step is the most subjective — it pertains to coding style rather than correctness.

### Step 5: refactor unrolled constructs

Identify repetitive code blocks and refactor them into loops and auxiliary functions. This is the step requiring the most logic understanding and having the greatest impact on readability.

For `derive_key`, this means reintroducing `mix_hash` and `rotate_left` as separate functions, and replacing the linear sequence of 4 rounds with a `for` loop. The result is code structurally close to the original:

```c
static uint32_t rotate_left(uint32_t value, unsigned int count) {
    count &= 31;
    return (value << count) | (value >> (32 - count));
}

static uint32_t mix_hash(const char *data, size_t len, uint32_t seed) {
    uint32_t h = seed;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h  = rotate_left(h, 5);
        h += (uint32_t)data[i] * 0x01000193;
        h ^= (h >> 16);
    }
    return h;
}

static void derive_key(const char *username, uint32_t seed, uint8_t *out) {
    size_t ulen = strlen(username);
    uint32_t state[ROUND_COUNT];

    state[0] = mix_hash(username, ulen, seed);
    for (int r = 1; r < ROUND_COUNT; r++) {
        state[r] = mix_hash(username, ulen, state[r - 1] ^ (uint32_t)r);
    }

    for (int r = 0; r < ROUND_COUNT; r++) {
        out[r * 4 + 0] = (uint8_t)(state[r] >> 24);
        out[r * 4 + 1] = (uint8_t)(state[r] >> 16);
        out[r * 4 + 2] = (uint8_t)(state[r] >>  8);
        out[r * 4 + 3] = (uint8_t)(state[r]);
    }
}
```

This code is a faithful reconstruction — it is not identical to the original source (variable names and style differ), but it implements the same logic and produces the same results.

### Step 6: full compilation and testing

Once all functions are cleaned, attempt a full compilation with linking:

```bash
gcc -Wall -Wextra -std=c11 -o keygenme_reconstructed keygenme_reconstructed.c
```

If called functions are not reconstructed (for example, library functions not included), create **stubs** — minimal implementations that allow compilation without reproducing the complete behavior:

```c
/* Stub — replace with actual implementation if needed */
void unresolved_FUN_004018a0(void) {
    fprintf(stderr, "[STUB] FUN_004018a0 called\n");
    abort();
}
```

Stubs allow the code to compile and run partially. Each call to an unimplemented stub is clearly signaled, guiding the remaining reconstruction work.

### Step 7: functional validation

The ultimate test is verifying that the reconstructed binary behaves like the original. For `keygenme`, this means:

```bash
# Test with the same input on both binaries
echo -e "testuser\n12345678-12345678-12345678-12345678" | ./keygenme_O2_strip  
echo -e "testuser\n12345678-12345678-12345678-12345678" | ./keygenme_reconstructed  
```

Both must produce the same output. If this holds for multiple inputs (including a valid input), the reconstructed code is functionally equivalent to the original binary.

For the network server (`server_O2_strip`), validation consists of launching the reconstructed server and connecting the original client — if the communication works, the protocol is correctly implemented.

---

## Automating cleanup with scripts

Some cleanup steps are mechanical enough to be scripted. Here is a minimal Python script that performs the most common transformations:

```python
#!/usr/bin/env python3
"""
clean_ghidra_export.py — Basic cleanup of a Ghidra C export.

Performs type replacements, removes void returns,  
and reformats common hexadecimal constants.  

Usage: python3 clean_ghidra_export.py input.c > output.c
"""

import re  
import sys  

def clean(source):
    # Replace Ghidra types (order matters)
    replacements = [
        (r'\bundefined8\b', 'uint64_t'),
        (r'\bundefined4\b', 'uint32_t'),
        (r'\bundefined2\b', 'uint16_t'),
        (r'\bundefined\b',  'uint8_t'),
        (r'\bbyte\b',       'uint8_t'),
        (r'\bushort\b',     'uint16_t'),
        (r'\buint\b',       'uint32_t'),
        (r'\bulong\b',      'uint64_t'),
        (r'\blonglong\b',   'int64_t'),
    ]
    for pattern, replacement in replacements:
        source = re.sub(pattern, replacement, source)

    # Remove "return;" at end of void functions
    source = re.sub(r'\n\s*return;\n\}', '\n}', source)

    # Simplify double casts (uint32_t)(uint8_t) on char[] accesses
    source = re.sub(
        r'\(uint32_t\)\(uint8_t\)(\w+\[)',
        r'(uint8_t)\1',
        source
    )

    # Convert i = i + 1 to i++
    source = re.sub(
        r'(\w+) = \1 \+ 1',
        r'\1++',
        source
    )

    # Convert i = i - 1 to i--
    source = re.sub(
        r'(\w+) = \1 - 1',
        r'\1--',
        source
    )

    return source

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.c>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        source = f.read()

    print(clean(source))
```

This script handles simple cases. Complex transformations (refactoring unrolled loops, reintroducing auxiliary functions) remain human work — this is the part of RE that requires understanding the logic, not just the syntax.

---

## When to stop

Pseudo-code cleanup is a process of diminishing returns. The first corrections (types, includes, prototypes) are mechanical and bring immediate gain. Refactoring loops and inlined functions requires more effort but considerably improves readability. Beyond that, you enter the territory of cosmetic polishing — renaming variables to match project conventions, reorganizing functions in a logical order, adding comments documenting acquired understanding.

The stopping point depends on the analysis objective:

**For a security audit**, raw annotated pseudo-code in Ghidra is generally sufficient. The deliverable is an analysis report, not recompilable code. Cleanup work is limited to the reconstructed header and annotations in the Ghidra project.

**For writing a companion tool** (keygen, replacement client, plugin), only the functions needed to understand the interface and algorithms are cleaned up. The rest of the binary does not need to be reconstructed. The header from section 20.4 is often sufficient.

**For a complete reconstruction** (interoperability, porting, in-depth malware analysis), full cleanup is justified. This is the most demanding and rarest scenario.

**For a professional RE report**, the header `.h` + cleaned pseudo-code `.c` of key functions constitutes a standard deliverable. It documents acquired understanding in a verifiable (the code compiles) and reusable (another analyst can pick it up) manner.

In all cases, the reconstructed code must be clearly identified as such — header comments indicating the origin (source binary, hash, tools used, date) are essential to avoid any confusion with authentic source code.

---

## Pitfalls specific to C++ code

C++ binaries add additional difficulties to the cleanup process.

### C pseudo-code for C++

Ghidra produces C pseudo-code, even when the original binary is C++. Virtual method calls appear as calls through function pointers, the `this` pointer is an explicit parameter, and constructors/destructors contain vtable initialization code that has no direct syntactic equivalent in C.

If the objective is to produce a recompilable `.cpp` file, the classes must be **rewritten** rather than cleaning the C pseudo-code. The C++ header reconstructed in section 20.4 serves as a skeleton, and method bodies are adapted from Ghidra pseudo-code by transcribing them into C++ syntax with implicit `this->`, method calls by name, and explicit inheritance.

### C++ exceptions

Ghidra's pseudo-code sometimes includes reconstructed `try/catch` blocks, but more often it shows the low-level mechanism: calls to `__cxa_allocate_exception`, `__cxa_throw`, cleanup tables in `.gcc_except_table`. Cleaning this code into valid C++ requires understanding the GCC exception mechanism (chapter 17, section 4) and transcribing it into idiomatic `throw`/`catch`.

### The STL

Instantiated STL template code is verbose and specific to the libstdc++ implementation. Attempting to clean it into C++ code directly using `std::vector` and `std::map` is legitimate, but you must accept that the reconstructed code uses the STL at a higher abstraction level than what the pseudo-code shows — replacing dozens of lines of internal manipulation with a simple `vec.push_back(elem)`.

---

## The reconstructed file as a living work base

Reconstructed code is not a frozen deliverable — it is a living document that evolves with the analysis. As the binary is better understood (discovering new structures, correcting type hypotheses, identifying new functions), the reconstructed code is updated.

The recommended organization in the training repository is as follows:

```
analysis/
├── keygenme/
│   ├── keygenme_reconstructed.h    ← header (section 20.4)
│   ├── keygenme_reconstructed.c    ← cleaned pseudo-code
│   ├── notes.md                    ← analysis journal
│   └── Makefile                    ← reconstructed code compilation
├── server/
│   ├── ch20_network_reconstructed.h
│   ├── server_reconstructed.c
│   ├── notes.md
│   └── Makefile
└── ...
```

The `Makefile` in each subdirectory compiles the reconstructed code and runs validation tests. The `notes.md` file documents decisions made during analysis — why a particular structure was reconstructed in a particular way, what hypotheses remain unverified, what parts of the binary were not analyzed.

This documentation discipline transforms a one-off analysis effort into a reusable knowledge base. This is what distinguishes a professional analysis from an ad hoc decompilation exercise — and it is exactly what the practical cases in Part V put into practice.

---

> 🎯 **Chapter 20 Checkpoint**: produce a complete `.h` for the `ch20-network` binary (the stripped network server). The header must contain all protocol constants, message structures, type and command enumerations, and main function signatures. It must compile without errors when included in an empty C file, and structure sizes must match the offsets observed in Ghidra.  
> 

⏭️ [🎯 Checkpoint: produce a complete `.h` for the `ch20-network` binary](/20-decompilation/checkpoint.md)
