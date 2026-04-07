🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.4 — LLVM-based obfuscation (Hikari, O-LLVM) — recognizing patterns

> 🎯 **Objective**: Understand why LLVM has become the reference obfuscation platform, know the main projects (O-LLVM, Hikari, Pluto, Armariris), identify the specific patterns each of their passes produces in a binary, and know how to distinguish them from artisanal obfuscation.

---

## Why LLVM changes the game for obfuscation

The previous section presented CFF and BCF as abstract techniques. In practice, the question that arises is: *how are these transformations applied to the code?*

The answer, in the vast majority of cases encountered today, can be summed up in one word: **LLVM**.

LLVM is a modular compilation infrastructure. Its architecture rests on an intermediate representation (IR) independent of the target architecture. Source code is transformed into IR by a frontend (Clang for C/C++), then the IR passes through a series of optimization **passes** before being translated into machine code by a backend.

What makes LLVM so attractive for obfuscation is that optimization passes are independent, pluggable modules. Anyone can write a custom pass that transforms the IR — and thus the final code — in the desired way. An obfuscation pass integrates into the pipeline exactly like a standard optimization pass. From the developer's perspective, obfuscating code amounts to adding a flag to the compilation command.

This means obfuscation operates on the IR, **before** machine code generation. It therefore automatically benefits from all standard LLVM backend optimizations (register allocation, scheduling, instruction selection). The obfuscated code is "clean" machine code produced by a mature compiler — not a patchwork applied after the fact on the binary. This is what makes it so hard to distinguish from simply optimized code, and so resistant to naive de-obfuscation tools.

### The relationship with GCC

This tutorial is centered on the GNU chain. So why discuss LLVM?

Because LLVM-obfuscated binaries end up in the same environments as GCC binaries: same ELF format, same System V AMD64 calling conventions, same shared libraries, same loader. An analyst reversing Linux binaries will encounter binaries produced by obfuscated Clang/LLVM as often — if not more often — than GCC binaries protected by artisanal means. Knowing how to recognize LLVM patterns is an essential skill, regardless of which compiler *you* use.

Furthermore, the final linker can be `ld` (GNU) even when the compiler is Clang. Both chains coexist in the same ecosystem.

## O-LLVM: the founding project

### History

Obfuscator-LLVM (O-LLVM) is a university project born in 2010 at the University of Upper Alsace (Mulhouse). It was the first LLVM-based obfuscation framework published as open source. Although no longer actively maintained (its last official support targets LLVM 4.0), O-LLVM defined the three canonical passes that all successor projects have adopted and improved.

### O-LLVM's three passes

#### Pass 1: Control Flow Flattening (`-fla`)

This is the reference CFF implementation described in Section 19.3. O-LLVM's `-fla` pass transforms each function by adding:

- A dispatch variable (often named `switchVar` in the IR) allocated on the stack  
- An encompassing `while(true)` loop  
- A `switch` on the dispatch variable, with one case per original basic block

The assembly pattern produced by O-LLVM `-fla` has specific characteristics distinguishing it from manually implemented CFF:

- **The dispatch variable is always on the stack**, never in a dedicated register. You see a `mov eax, [rbp-0xNN]` followed by a series of `cmp eax, imm` at the beginning of each iteration.  
- **Dispatch values are sequential integers** often starting at 0. O-LLVM doesn't apply randomization on case identifiers in its base version. Values 0, 1, 2, 3… appear in plaintext in comparisons.  
- **The dispatcher is implemented as a comparison cascade**, not a jump table. Even with 30 cases, O-LLVM generates a linear series of `cmp`/`je` rather than a `jmp [rax*8 + table]`. This is a very recognizable pattern in the graph — a long "corridor" of comparison nodes before branching.  
- **The switch's default block contains a jump to the function exit** or an `unreachable`.

#### Pass 2: Bogus Control Flow (`-bcf`)

O-LLVM's BCF implementation inserts conditional branches based on opaque predicates. The predicates used by O-LLVM are relatively simple and recognizable:

- **Predicate on global variables** — O-LLVM creates two global variables (often named `x` and `y` in the IR, visible in `.data` or `.bss`) and uses the predicate `(x * (x - 1)) % 2 == 0`. This expression is always true because the product of two consecutive integers is always even.  
- **Dead code is a slightly modified clone of the real code** — O-LLVM doesn't generate random code for the false path. It clones the real basic block and inserts minor modifications (different constants, additional operations). This makes the false path credible but also means the analyst will see "nearly identical" blocks in the graph.  
- **The predicate's global variables are never modified** — They're initialized to 0 and stay at 0. If the analyst spots two global variables frequently read but never written, it's a strong O-LLVM BCF indicator.

#### Pass 3: Instruction substitution (`-sub`)

The substitution pass replaces simple arithmetic and logical operations with equivalent but more complex sequences. For example:

- `a + b` → `a - (-b)`  
- `a + b` → `(a ^ b) + 2 * (a & b)` (addition via bit manipulation)  
- `a - b` → `a + (~b) + 1` (subtraction via two's complement)  
- `a ^ b` → `(a & ~b) | (~a & b)` (XOR via logical decomposition)  
- `a | b` → `(a & ~b) | b`  
- `a & b` → `(~(~a | ~b))`

These substitutions are applied recursively: the result of a first substitution can itself be substituted, creating increasingly long operation chains for an originally trivial operation.

The assembly pattern is characteristic: you see long sequences of `not`, `and`, `or`, `xor`, `neg`, `add` that ultimately yield a simple result. An `add eax, ebx` from the original can become 8 to 12 instructions. The experienced analyst recognizes these arithmetic identity sequences and mentally simplifies them — or uses a symbolic simplification tool.

## Hikari: the modernized successor

### Presentation

Hikari (光, "light" in Japanese — an ironic name for an obfuscator) is an O-LLVM fork ported to newer LLVM versions. It was developed by Zhang (naville) and has been widely used in the iOS/macOS ecosystem, but ELF binaries obfuscated by Hikari also exist.

Hikari adopts O-LLVM's three passes and adds several more.

### Hikari's additional passes

#### String encryption (`-enable-strcry`)

Hikari encrypts `.rodata` character strings and inserts decryption code that runs at program initialization (in `.init_array` or in C++ constructors). Plaintext strings never appear in the on-disk file.

The pattern is recognizable:

- The `.rodata` section contains apparently random byte blobs where readable strings were expected  
- The `.init_array` section contains pointers to decryption functions that didn't exist in the source code  
- These decryption functions traverse byte arrays and apply XOR or more complex decryption  
- `strings` returns almost nothing useful, even without packing

For the analyst, the countermeasure is to recover strings from memory after the constructors have executed (with GDB or Frida), since decryption has already occurred when `main()` runs.

#### Function pointer encryption (`-enable-fco`)

Hikari encrypts function pointers stored in tables (C++ vtables, callback arrays). At runtime, each pointer is decrypted just before the indirect call. This complicates XREF analysis: Ghidra can't follow a `call rax` if `rax`'s value is the result of dynamic decryption.

#### Anti Class Dump (`-enable-acdobf`)

Specific to Objective-C (iOS/macOS), this pass renames classes and methods to destroy runtime metadata. Less relevant for this tutorial's ELF C/C++ binaries, but mentioned for completeness.

#### Call indirection (`-enable-indibran`)

Direct calls (`call 0x401234`) are replaced by indirect calls via a register (`call rax`), where `rax` is calculated from an obfuscated expression. This destroys the static call graph: Ghidra can no longer build the list of functions called by a given function, since targets are dynamically calculated.

## Other derived projects

O-LLVM's legacy has spawned a constellation of projects:

- **Armariris** — Chinese O-LLVM fork, maintained longer, with improvements to opaque predicate robustness. Patterns are nearly identical to O-LLVM.  
- **Pluto** — Recent LLVM obfuscator targeting LLVM 16+, with improved CFF passes (dispatch value randomization, jump table dispatcher rather than comparison cascade). Patterns differ notably from O-LLVM.  
- **Tigress** — A source-to-source C obfuscator (not LLVM-based, but often compared). Tigress can apply code virtualization, a more powerful technique than CFF where the original code is translated to a custom virtual machine's bytecode. The result is an interpreter embedded in the binary — fundamentally different from LLVM patterns.

## Recognizing patterns: diagnostic guide

Facing a suspect binary, here's the approach to identify the obfuscation tool used.

### Step 1 — Is the binary compiled with Clang/LLVM?

Check the `.comment` section (if not stripped):

```bash
$ readelf -p .comment suspect_binary
  [     0]  clang version 14.0.0 (https://...)
```

If the binary is stripped, other clues betray Clang: internal section names, register allocation patterns (Clang and GCC have slightly different register allocation strategies), prologue/epilogue structure.

Caution: a Clang binary isn't necessarily obfuscated. And conversely, an obfuscated binary may have its `.comment` section stripped. This step guides analysis but doesn't conclude.

### Step 2 — Identify CFF

Open a suspect function in Ghidra's Function Graph:

- **O-LLVM / Armariris pattern** — Dispatcher as a linear cascade of `cmp`/`je`. Sequential dispatch values (0, 1, 2…). Dispatch variable on stack. "Comb" shape in the graph: a long corridor of comparison nodes with lateral branches.  
- **Hikari pattern** — Similar to O-LLVM for basic CFF. If strings are absent and `.init_array` contains decryption functions, it's a Hikari indicator.  
- **Pluto pattern** — Dispatcher via jump table (`jmp [reg*8 + table]`). Randomized dispatch values (not sequential). "Clean star" shape in the graph rather than comb.

### Step 3 — Identify BCF

Search in `.data` or `.bss`:

- **O-LLVM / Armariris** — Two global variables (often 4 bytes each, initialized to 0) referenced by many functions but never written. The predicate `(x * (x-1)) % 2 == 0` translates in assembly to an `imul`/`dec`/`and` sequence (the `% 2` optimized to `and 1`).  
- **Hikari** — Similar predicates, sometimes with variables in `.bss` rather than `.data`.  
- **Pluto** — More varied predicates, sometimes using libc math functions (`sin`, `cos`) to make symbolic resolution harder.

### Step 4 — Identify instruction substitution

Look for abnormally long logical operation sequences:

- Seeing 6 to 12 cascading `not`/`and`/`or`/`xor` instructions for a result a single `add` or `xor` would have produced  
- Intermediate constants have no business meaning — they're artifacts of mathematical identities  
- The same substitution patterns repeat throughout the binary (the obfuscator applies the same transformations everywhere)

### Step 5 — Identify string encryption (Hikari)

```bash
$ strings suspect_binary | wc -l
23
```

If `strings` returns very few results on a non-packed binary (normal sections, no abnormal `.text` entropy), it's a string encryption indicator. Check `.init_array`:

```bash
$ readelf -x .init_array suspect_binary
$ objdump -d -j .init_array suspect_binary
```

If `.init_array` contains many entries pointing to functions that XOR data blocks, it's Hikari string encryption (or equivalent).

### Summary table

| Indicator | O-LLVM | Hikari | Pluto |  
|---|---|---|---|  
| CFF dispatcher | `cmp`/`je` cascade | `cmp`/`je` cascade | Jump table |  
| Dispatch values | Sequential (0,1,2…) | Sequential | Randomized |  
| BCF globals | 2 vars in `.data`, never written | 2 vars in `.bss` | Varied patterns |  
| Substitution | Classic `not`/`and`/`or` | Same as O-LLVM | Extended identities |  
| String encryption | No | Yes (`-enable-strcry`) | Variable |  
| Call indirection | No | Yes (`-enable-indibran`) | Variable |  
| Target LLVM | ≤ 4.0 | 6.0 – 12.0 | ≥ 16.0 |

## Analysis strategies for LLVM obfuscation

The general CFF and BCF bypass strategies (Section 19.3) apply. Here are approaches specific to LLVM-obfuscated binaries.

### Exploiting O-LLVM's known weaknesses

O-LLVM's sequential dispatch values and weak opaque predicates are programmatically exploitable:

- The IDA plugin **D-810** automatically detects and removes O-LLVM's CFF and BCF by identifying the dispatch variable and reconstructing the CFG. Its authors published the heuristics used, which are transposable to Ghidra scripts.  
- The BCF's two global variables can be identified by script: search for global variables referenced for reading by more than N functions but never for writing.

### Recovering encrypted strings (Hikari)

Three possible approaches:

- **Frida** — Hook `.init_array` functions or wait until they've finished, then dump decrypted `.rodata` from memory.  
- **GDB** — Set a breakpoint on `main`, run the program (constructors will have already executed decryption), then examine strings in memory with `x/s`.  
- **Emulation** — Use Unicorn Engine or angr's emulation mode to execute only the decryption functions without launching the entire binary.

### Resolving indirect calls (Hikari)

Hikari's call indirection calculates each `call`'s target from an obfuscated constant. In practice, the target is often `base + constant ^ key`, where the key is fixed for the entire binary. A Ghidra script can:

1. Identify all `call reg` preceded by an obfuscated calculation  
2. Extract the constant and key  
3. Calculate the real target  
4. Add manual XREFs in Ghidra

### Symbolic simplification

For the substitution pass, symbolic analysis frameworks excel:

- **Miasm** — Lift code to IR, apply simplification rules, and see that 10 instructions reduce to one `add`.  
- **Triton** — Symbolically evaluate an instruction sequence and obtain the simplified expression.  
- **Z3** (Chapter 18) — Prove equivalence between the obfuscated sequence and a simple operation.

Automating this simplification is the foundation of modern de-obfuscation tools.

### The realistic approach

Facing a binary obfuscated by Hikari with all five passes enabled (CFF + BCF + substitution + string encryption + call indirection), complete analysis is a multi-day job. The realistic approach is:

1. **Recover strings** — GDB or Frida, 5 minutes. This restores textual landmarks.  
2. **Identify critical functions** — Via XREF on recovered strings and dynamic imports.  
3. **Analyze dynamically** — Hook critical functions with Frida, observe inputs/outputs.  
4. **Surgically de-obfuscate** — Only reconstruct the CFG of the 2 or 3 functions requiring structural understanding (verification routine, decryption, protocol).  
5. **Ignore the rest** — Obfuscated auxiliary functions not on the analysis's critical path aren't worth the invested time.

---


⏭️ [Stack canaries (`-fstack-protector`), ASLR, PIE, NX](/19-anti-reversing/05-canaries-aslr-pie-nx.md)
