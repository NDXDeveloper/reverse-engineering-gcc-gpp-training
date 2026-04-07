🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.5 — Compilation flags and their impact on RE (`-O0` through `-O3`, `-g`, `-s`, `-fPIC`, `-pie`)

> 🎯 **Goal of this section**: Understand how the main GCC flags transform the produced binary, and know how to assess the difficulty of an RE analysis based on the compilation options used.

---

## Why compilation flags matter in RE

Faced with an unknown binary, one of the reverse engineer's first questions is: **under what conditions was this program compiled?** The answer radically influences the analysis strategy:

- A binary compiled with `-O0 -g` (debug, no optimization) is almost transparent — disassembly corresponds line-for-line to the source, and variable names are available.  
- The same program compiled with `-O2 -s` (optimized and stripped) is a whole different challenge — inlined functions, variables in registers, no symbol names.

Compilation flags act as cursors on a spectrum going from "almost the source code" to "opaque binary puzzle". Knowing them lets you anticipate what you will find in the binary and adapt your tools accordingly.

To concretely illustrate each flag, we will use our `hello.c` running example and compare the produced binaries.

## Optimization flags: `-O0`, `-O1`, `-O2`, `-O3`, `-Os`

### `-O0` — No optimization (default)

This is the default level when no `-O` flag is specified. The compiler produces machine code that faithfully follows the structure of the source code, without any attempt to improve performance.

**Characteristics of the produced code:**

- Each local variable is stored on the stack at a fixed address. The compiler performs constant round-trips between registers and the stack (*spilling*), even when the value has just been loaded.  
- Each function call is a real `call` — no function is inlined.  
- Control structures (`if`, `for`, `while`, `switch`) are mechanically translated into comparisons and jumps, in a predictable order.  
- Dead code (never executed) is kept.  
- The prologue and epilogue of each function follow the standard scheme (`push rbp; mov rbp, rsp; ... leave; ret`), which makes function boundaries trivial to identify.

**RE impact**: this is the ideal scenario. The correspondence between source and assembly is almost direct. The Ghidra decompiler produces pseudo-code very close to the original C. This is the level we will use in most exercises in this training (`_O0` variants).

```bash
gcc -O0 -o hello_O0 hello.c
```

### `-O1` — Conservative optimizations

The compiler activates an initial batch of optimizations that improve performance without excessively increasing compilation time or radically transforming the code.

**Typical optimizations activated:**

- Constant propagation: if the compiler can prove that a variable is always `42`, it replaces the variable with the constant.  
- Dead code elimination: `if` branches whose condition is always false are removed.  
- Improved register allocation: local variables are kept in registers instead of being systematically stored on the stack.  
- Strength reduction: a multiplication by a power of 2 is replaced by a left shift (`shl`).  
- Common subexpression elimination (CSE): if `a + b` is computed twice, the result is reused.

**RE impact**: the code is more compact and more fluid, but remains globally readable. Functions retain their identity (no inlining at this level). The main visible change is the disappearance of redundant memory accesses — variables "live" in registers rather than on the stack, which makes tracking values a little less immediate.

```bash
gcc -O1 -o hello_O1 hello.c
```

### `-O2` — Standard optimizations (production)

This is the most common optimization level for production builds. It activates the vast majority of optimizations that do not sacrifice code size in favor of speed.

**Additional optimizations compared to `-O1`:**

- **Function inlining**: small functions are integrated into the caller. Our `check()` function, which only calls `strcmp` and compares the result, has a good chance of being inlined into `main()` — it then disappears as a distinct function.  
- **Instruction scheduling**: the compiler reorders instructions to exploit the processor's pipeline and mask memory latencies.  
- **Loop optimization**: partial unrolling (*loop unrolling*), loop-invariant code motion, etc.  
- **Tail call optimization**: a call in tail position is transformed into a jump, saving a stack frame (detailed in Chapter 16, section 16.4).  
- **Peephole optimizations**: short instruction sequences are replaced by more efficient equivalent sequences.

**RE impact**: this is the border beyond which analysis becomes noticeably harder. Functions can disappear (inlining), variables no longer have a stable correspondence with memory locations, and instruction order no longer reflects the logical structure of the source. The Ghidra decompiler still produces usable pseudo-code, but it requires more interpretation work from the analyst.

```bash
gcc -O2 -o hello_O2 hello.c
```

### `-O3` — Aggressive optimizations

This level activates additional optimizations that favor speed at the potential expense of binary size.

**Additional optimizations compared to `-O2`:**

- **Automatic vectorization**: loops operating on arrays are transformed into SIMD instructions (SSE/AVX), which process several elements in parallel. In assembly, this translates into instructions operating on the `xmm0`–`xmm15` or `ymm0`–`ymm15` registers (Chapter 3, section 3.9).  
- **Aggressive loop unrolling**: the body of the loop is duplicated several times to reduce the cost of branching.  
- **Even more aggressive inlining**: larger functions are candidates for inlining.  
- **Speculative transformations**: the compiler may duplicate code to optimize the most likely paths.

**RE impact**: the code becomes significantly harder to read. Unrolled loops produce long sequences of repetitive instructions. SIMD instructions are opaque if you do not know their semantics. The control flow graph (CFG) can become complex due to path duplication. For our small `hello.c`, the difference with `-O2` is minimal — the impact of `-O3` is most felt on code with compute-intensive loops.

```bash
gcc -O3 -o hello_O3 hello.c
```

### `-Os` — Size optimization

This flag enables the same optimizations as `-O2` but **disables** those that increase code size (loop unrolling, aggressive inlining, generous function alignment). The goal is to produce the most compact binary possible.

**RE impact**: paradoxically, an `-Os` binary can be easier to analyze than an `-O2` binary, because functions are less often inlined (inlining increases size) and loops are not unrolled. The code is compact but structured.

```bash
gcc -Os -o hello_Os hello.c
```

### Concrete comparison on our running example

Let's compile `hello.c` at each level and compare:

```bash
for opt in O0 O1 O2 O3 Os; do
    gcc -$opt -o hello_$opt hello.c
done  
ls -l hello_O*  
```

| Variant | Binary size (indicative) | `check()` visible? | Instructions in `main` (approx.) |  
|---|---|---|---|  
| `hello_O0` | ~16 KB | Yes, distinct function | ~35–40 |  
| `hello_O1` | ~16 KB | Yes, but trimmed | ~25–30 |  
| `hello_O2` | ~16 KB | Often inlined | ~20–25 |  
| `hello_O3` | ~16 KB | Inlined | ~20–25 |  
| `hello_Os` | ~16 KB | Sometimes preserved | ~20–25 |

The size differences are small on such a small program. On a real project of several thousand lines, the gaps become significant — a `-O3` binary can be 20 to 50% larger than an `-Os` binary.

To observe the differences in the assembly code:

```bash
# Compare the disassembly of main() between O0 and O2
objdump -d -j .text hello_O0 | grep -A 50 '<main>'  > main_O0.txt  
objdump -d -j .text hello_O2 | grep -A 50 '<main>'  > main_O2.txt  
diff --color main_O0.txt main_O2.txt  
```

> 💡 **RE tip**: To guess the optimization level of an unknown binary, look for clues. The systematic presence of `push rbp; mov rbp, rsp` prologues in all functions suggests `-O0` or `-O1`. The absence of the frame pointer (direct use of `rsp`) and very compact functions suggest `-O2` or higher. The presence of SIMD instructions (`movaps`, `paddd`, `vaddps`…) in simple loops is a clue for `-O3`. The `.comment` section sometimes reveals the exact command line (some distributions preserve it).

## Debug flag: `-g`

The `-g` flag tells GCC to generate **debug information** in DWARF format and embed it in the binary (or in a separate file with `-gsplit-dwarf`).

```bash
gcc -O0 -g -o hello_debug hello.c
```

### What `-g` adds to the binary

DWARF information is stored in dedicated sections:

| Section | Content |  
|---|---|  
| `.debug_info` | Descriptions of types, variables, functions, parameters, scopes |  
| `.debug_abbrev` | Abbreviations of DWARF descriptions |  
| `.debug_line` | Machine address ↔ source file line correspondence |  
| `.debug_str` | Strings used in debug info |  
| `.debug_aranges` | Address ranges covered by each compilation unit |  
| `.debug_frame` | Stack-unwinding information (more detailed than `.eh_frame`) |  
| `.debug_loc` | Variable location (in which register or at what stack offset) |  
| `.debug_ranges` | Discontinuous address ranges (for optimized code) |

The impact on size is considerable:

```bash
ls -lh hello_O0 hello_debug
# hello_O0:    ~16 KB
# hello_debug: ~30-50 KB   (sometimes 2-3x larger)
```

### Impact on RE

DWARF information is a treasure for the reverse engineer:

- **Names of functions, parameters, and local variables**: instead of seeing `rbp-8`, you see `input`. Instead of `func_1234`, you see `check`.  
- **Complete types**: `struct`, `enum`, `typedef`, `class` are described with all their fields, sizes, and alignments. Ghidra and GDB import and apply them automatically.  
- **Source-assembly correspondence**: each machine instruction is mapped to a precise line of the source file. GDB uses this correspondence for source-level debugging (`list`, `next`, `step`).  
- **Scope information**: variables are associated with their scope (block, function), which tells you when a variable is "live".

```bash
# See the DWARF information
readelf --debug-dump=info hello_debug | head -80

# See the line-address correspondence
readelf --debug-dump=decodedline hello_debug
```

> 💡 **In RE**: In real analysis, debug information is almost always absent — production builds do not include `-g`. However, it sometimes appears in specific cases: embedded firmwares compiled in haste, leaked development builds, debug packages of Linux distributions (`*-dbgsym`, `*-debuginfo`), or via public `debuginfod` servers. Always check with `readelf -S binary | grep debug` — a pleasant surprise is always possible.

### Combining `-g` and optimizations

The `-g` and `-O` flags are not mutually exclusive. It is perfectly valid to compile with `-O2 -g`:

```bash
gcc -O2 -g -o hello_O2_debug hello.c
```

The binary will contain optimized code *and* DWARF information. However, the debug information will be less precise than with `-O0 -g`: inlined variables or those kept in registers are harder to locate, and the line-address correspondence can present unusual jumps (code for line N can be mixed with that for line N+3 after reordering).

GDB signals these situations with messages like "optimized out" when you try to display a variable that no longer exists as such in the machine code.

## Stripping flag: `-s`

The `-s` flag asks the linker to **remove all non-dynamic symbol tables** from the final binary. It is the equivalent of running the `strip` command after compilation.

```bash
gcc -O0 -s -o hello_stripped hello.c
```

### What `-s` removes

| Element | Before `-s` | After `-s` |  
|---|---|---|  
| `.symtab` (complete symbols) | ✅ Present | ❌ Removed |  
| `.strtab` (symbol names) | ✅ Present | ❌ Removed |  
| `.debug_*` sections | ✅ If `-g` | ❌ Removed |  
| `.dynsym` (dynamic symbols) | ✅ Present | ✅ **Preserved** |  
| `.dynstr` (dynamic names) | ✅ Present | ✅ **Preserved** |

The distinction is crucial: dynamic symbols (`.dynsym`) are **never removed** by `strip` or `-s`, because they are essential for the loader's operation. That is why the names of imported functions (`strcmp`, `printf`, `malloc`…) always remain visible.

### Impact on RE

Stripping is the **most common obstacle** in RE. Without `.symtab`, you lose:

- The names of all internal functions (the author named them `check`, `validate_license`, `decrypt_config`… but you only see addresses).  
- The names of global variables.  
- The size of functions (Ghidra and other tools must recompute it by control-flow analysis).

What you keep despite stripping:

- The names of imported functions (via `.dynsym`).  
- Literal strings in `.rodata`.  
- The structure of the machine code (instructions do not change).  
- `.eh_frame` information (useful for detecting function boundaries).

```bash
# Compare symbols before and after stripping
readelf -s hello_O0 | grep FUNC | wc -l       # e.g.: 35 functions  
readelf -s hello_stripped                       # (empty)  
readelf --dyn-syms hello_stripped | grep FUNC   # strcmp, printf, puts... still there  
```

> 💡 **RE tip**: The `strip` tool offers finer control than the `-s` flag. The `strip --strip-unneeded` option removes only symbols not required for relocation, preserving global function symbols. It is a middle ground some projects use. With `strip --only-keep-debug`, you can extract debug information into a separate file — a technique used by Linux distributions for their `*-dbgsym` packages.

## Code-positioning flags: `-fPIC` and `-pie`

These two flags concern the **position-independence** of the code — its ability to function correctly regardless of the memory address at which it is loaded.

### `-fPIC` — Position-Independent Code

This flag asks the compiler to generate code that contains **no hardcoded absolute addresses**. All references to data and functions go through relative indirections (via the `rip` register in x86-64, via the GOT for external symbols).

```bash
gcc -fPIC -shared -o libhello.so hello_lib.c
```

`-fPIC` is **mandatory** to compile shared libraries (`.so`). Without it, the code would contain absolute addresses that would only work if the library were loaded at a specific address — which is incompatible with dynamic loading (several `.so` files sharing the same address space).

**Impact on assembly**: instead of accessing a global variable via an absolute address, the code uses an access relative to the program counter:

```asm
# Without -fPIC (absolute address — rare in modern x86-64)
mov    eax, DWORD PTR [0x404028]

# With -fPIC (relative to rip)
mov    eax, DWORD PTR [rip+0x2f1a]    # address computed relative to rip
```

In x86-64, the rip-relative addressing mode is native and efficient, which makes the overhead of `-fPIC` negligible on this architecture (unlike x86-32, where an extra register had to be sacrificed).

### `-pie` — Position-Independent Executable

This flag tells the linker to produce a **position-independent executable** — a program that can be loaded at any address in memory. It is the technical prerequisite for **ASLR** (Address Space Layout Randomization — section 2.8).

```bash
gcc -pie -o hello_pie hello.c
```

Since GCC 6+ and modern Linux distributions, `-pie` is **enabled by default**. Your `gcc hello.c -o hello` already produces a PIE binary. You can verify it:

```bash
readelf -h hello | grep Type
# Type: DYN (Position-Independent Executable file)

# To explicitly disable PIE:
gcc -no-pie -o hello_nopie hello.c  
readelf -h hello_nopie | grep Type  
# Type: EXEC (Executable file)
```

**RE impact**: in a PIE binary (`ET_DYN`), all the addresses displayed by the disassembler are **offsets relative to the load base**, not absolute addresses. At each execution, ASLR assigns a different base. This means that:

- The addresses in `objdump` or Ghidra typically start at `0x1000` (relative offset), not at `0x401000` (typical absolute address of an `ET_EXEC`).  
- To set a breakpoint in GDB on a PIE binary, you must either use a function name (`break main`) or compute the runtime address (`break *($base + 0x1234)`). GDB extensions like GEF and pwndbg handle this automatically (Chapter 12).  
- XREFs (cross-references) in RE tools work on relative offsets and remain consistent.

| Characteristic | Non-PIE (`ET_EXEC`) | PIE (`ET_DYN`) |  
|---|---|---|  
| Base address | Fixed (e.g.: `0x400000`) | Random (ASLR) |  
| Addresses in disassembly | Absolute | Offsets relative to the base |  
| ASLR of code | ❌ Impossible | ✅ Enabled |  
| GDB breakpoints on address | Simple | Require a calculation or symbol name |  
| Machine code | Can contain absolute addresses | Entirely relative to `rip` |

> 💡 **In RE**: When you analyze a binary with `checksec` (Chapter 5, section 5.6), the line "PIE: enabled" indicates a position-independent binary. If PIE is disabled, addresses are fixed from one execution to the next, which simplifies dynamic debugging but weakens security.

## Summary: flags × RE impact matrix

The following table summarizes the impact of each flag on the key aspects of RE analysis:

| Flag | Code readability | Symbols | Debug info | Binary size | Security |  
|---|---|---|---|---|---|  
| `-O0` | ★★★★★ Excellent | Unchanged | Unchanged | Base | No optimization |  
| `-O1` | ★★★★ Good | Unchanged | Unchanged | ≈ Base | — |  
| `-O2` | ★★★ Medium | Unchanged | Unchanged | ≈ Base | — |  
| `-O3` | ★★ Difficult | Unchanged | Unchanged | ↑ Bigger | — |  
| `-Os` | ★★★ Medium | Unchanged | Unchanged | ↓ Smaller | — |  
| `-g` | Unchanged | Unchanged | ✅ Complete DWARF | ↑↑ Much larger | — |  
| `-s` | Unchanged | ❌ Stripped | ❌ Removed | ↓ Smaller | Light obfuscation |  
| `-fPIC` | Slightly changed | Unchanged | Unchanged | ≈ Base | `.so` prerequisite |  
| `-pie` | Relative addresses | Unchanged | Unchanged | ≈ Base | ✅ Enables ASLR |

The most frequent combinations in practice:

| Context | Typical flags | RE difficulty |  
|---|---|---|  
| Developer debug build | `-O0 -g` | ★ Trivial |  
| Standard release build | `-O2 -s -pie` | ★★★★ High |  
| Hardened release build | `-O2 -s -pie -fstack-protector-strong` | ★★★★★ Maximum |  
| Shared library | `-O2 -fPIC -shared` | ★★★ Medium (exported symbols visible) |  
| Embedded firmware | `-Os -static` | ★★★★ High (static, no dynamic symbols) |

## Other useful flags to know

A few additional flags you will encounter in RE analysis:

### `-fstack-protector` and variants

Enables **stack canary** protection: a sentinel value is placed on the stack between local variables and the return address. If a buffer overflow overwrites the canary, the program detects the corruption and calls `__stack_chk_fail` before returning. In assembly, you will recognize this pattern by an access to `fs:0x28` (the canary value in the TLS) at the start of the function and a comparison before the `ret`.

Variants are `-fstack-protector` (functions with `char` buffers only), `-fstack-protector-strong` (broader, recommended), and `-fstack-protector-all` (all functions).

Covered in depth in Chapter 19, section 19.5.

### `-fno-omit-frame-pointer`

Forces the compiler to keep the **frame pointer** (`rbp`) in every function, even with optimizations. Without this flag (default behavior at `-O1` and above), the compiler can use `rbp` as a general register, which makes the stack harder to read in GDB.

This flag is often enabled in profiling builds (it makes *stack unwinding* easier for profilers like `perf`).

### `-flto` — Link-Time Optimization

Enables **inter-module optimization**: instead of optimizing each `.c` file independently, the compiler keeps an intermediate representation in the `.o` files and optimizes the whole at link time. This makes it possible to inline functions defined in different files and to eliminate dead code at the whole-program scale.

**RE impact**: boundaries between source modules disappear completely. The binary is even more optimized (and therefore harder to analyze) than with `-O2` alone. Covered in depth in Chapter 16, section 16.5.

### `-static`

Produces a **statically linked** binary: all the code from the libraries is copied into the executable. The binary is self-contained but much larger, and libc functions are no longer identifiable through the PLT (since there is no PLT). Function signatures (FLIRT, Ghidra) become essential (Chapter 20, section 20.5).

## How to determine the flags of an unknown binary

The binary does not generally contain an explicit record of the `gcc` command line used. But several clues make it possible to guess them:

| Clue | Command / Tool | What it reveals |  
|---|---|---|  
| `.comment` section | `readelf -p .comment binary` | GCC version (sometimes the full line) |  
| Presence of `.debug_*` | `readelf -S binary \| grep debug` | Compiled with `-g` |  
| `file` says "stripped" | `file binary` | Compiled with `-s` or stripped afterwards |  
| `DYN` vs `EXEC` type | `readelf -h binary \| grep Type` | PIE enabled or not |  
| Systematic `push rbp` prologues | Disassembly | `-O0` or `-fno-omit-frame-pointer` |  
| Absence of frame pointer (`rbp`) | Disassembly | `-O1` or higher |  
| SIMD instructions in loops | Disassembly | `-O3` likely |  
| Calls to `__stack_chk_fail` | `objdump -d \| grep stack_chk` | `-fstack-protector` |  
| `checksec` | `checksec --file=binary` | PIE, NX, canary, RELRO |  
| Abnormally large size | `ls -lh binary` | `-static` or `-g` or `-O3` |

---

> 📖 **We now know how compilation flags shape the binary.** Among all the artifacts `-g` can produce, DWARF information deserves special treatment given how valuable it is when present. That is the subject of the next section.  
>  
> → 2.6 — Understanding DWARF symbol files

⏭️ [Understanding DWARF symbol files](/02-gnu-compilation-chain/06-dwarf-symbols.md)
