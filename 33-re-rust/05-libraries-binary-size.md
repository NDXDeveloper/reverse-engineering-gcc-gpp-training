🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 33.5 — Embedded Libraries and Binary Size (everything is statically linked)

> 📦 One of the most common shocks when opening a Rust binary in a disassembler is the number of functions: thousands, even tens of thousands, for a program that seems trivial. This mass of code comes from the stdlib and third-party crates, statically embedded in the binary. For the RE analyst, the challenge is not to read all this code — it is to intelligently ignore it in order to focus on the application logic.

---

## Why Rust Links Everything Statically

### The Rust Distribution Model

In C, the standard library (`glibc`) is a shared library (`.so`) installed on every Linux system. A C program references it dynamically via the PLT/GOT and does not embed it in its binary. Result: a dynamically compiled "Hello, World!" in C weighs a few kilobytes.

Rust makes the opposite choice. The Rust stdlib (`libstd`, `libcore`, `liballoc`, etc.) is **statically** linked by default. There is no `libstd-rust.so` installed on systems — each Rust binary carries its own copy of the stdlib.

The reasons for this choice are multiple. The Rust stdlib evolves rapidly between compiler versions, and ABI stability guarantees do not exist between `rustc` versions. Two programs compiled with different `rustc` versions could not share the same `.so` without risk of incompatibility. Static linking guarantees that each binary is self-contained and works on any Linux system with a compatible libc.

### Third-Party Crates: The Same Principle

The Rust ecosystem relies on `crates.io`, a library (crate) registry that `cargo` downloads and compiles automatically. Each crate is compiled into a static library (`.rlib`) and linked into the final binary. A typical Rust project depends on dozens, even hundreds of crates — and each one is embedded.

Our crackme does not use any third-party crate (only the stdlib), but a real project like a web server or a CLI tool could pull hundreds of transitive dependencies. A simple HTTP server with `tokio` and `axum` can produce a 10 to 20 MB binary containing code from 200+ crates.

---

## Anatomy of a Rust Binary's Size

### Breakdown by Component

Let's revisit the three variants of our crackme to quantify the distribution:

```bash
$ cd binaries/ch33-rust/
$ make all
```

| Variant | Size | Functions (FUNC) | Comment |  
|---|---|---|---|  
| `crackme_rust_debug` | ~15 MB | ~25,000 | Full debug, DWARF, nothing eliminated |  
| `crackme_rust_release` | ~4.3 MB | ~8,000 | Optimized, dead code partially eliminated |  
| `crackme_rust_strip` | ~406 KB | ? (stripped) | LTO + strip + panic=abort |

The jump from 15 MB to 4 MB is mainly explained by dead code elimination that LLVM performs at `-O3`: stdlib functions that are not called (directly or transitively) are removed. The jump from 4 MB to 400 KB is explained by LTO, which allows LLVM to see the entire program as a single compilation unit and eliminate even more unused code, combined with `panic = "abort"` which removes the entire unwinding mechanism.

### Visualizing the Distribution with `bloaty`

The `bloaty` tool (Google) allows decomposing a binary's size by section, by symbol, or by compiled source file:

```bash
$ bloaty crackme_rust_release -d sections
    FILE SIZE        VM SIZE
 --------------  --------------
  41.2%  1.72Mi   48.5%  1.72Mi    .text
  20.3%   870Ki   23.9%   870Ki    .rodata
  15.1%   647Ki    0.0%       0    .symtab
  10.2%   438Ki    0.0%       0    .strtab
   5.8%   249Ki    6.8%   249Ki    .eh_frame
   ...
```

Key observations: `.text` (executable code) represents about half the size. `.rodata` (read-only data: strings, trait tables, constants) represents one fifth. `.symtab` and `.strtab` (symbol tables) together weigh a quarter of the binary — and disappear when stripped. `.eh_frame` (unwinding tables) weighs about 6% and disappears with `panic = "abort"`.

You can also decompose by symbol to identify the biggest contributors:

```bash
$ bloaty crackme_rust_release -d symbols -n 20
```

The most voluminous functions are almost always from the stdlib: the formatter (`core::fmt`), the allocator, panic handling, hashing code for `HashMap`, `Display` and `Debug` implementations. Application code represents only a tiny fraction of the total.

---

## The Problem for the RE Analyst: Signal-to-Noise Ratio

### Thousands of Functions, a Handful of Interesting Ones

On the non-stripped release binary, we can count the functions:

```bash
$ nm crackme_rust_release | grep ' T \| t ' | wc -l
    4721

$ nm crackme_rust_release | rustfilt | grep 'crackme_rust::' | wc -l
    18
```

Out of 4,721 functions in `.text`, only **18 belong to our application code**. The rest comes from `core`, `alloc`, `std`, and the Rust runtime. The signal-to-noise ratio is approximately **1 to 260**.

On a stripped binary, this distinction disappears: all functions are anonymous. The analyst faces thousands of undifferentiated functions, the vast majority being library code they have no interest in analyzing.

### The Effect on the Decompiler

The decompiler (Ghidra, IDA) attempts to decompile every function. On a Rust binary, this produces thousands of decompiled functions, most of which are irrelevant to the analysis. The call graph becomes an unreadable tangle, and Ghidra's Symbol Tree turns into an endless list.

The problem is compounded by the fact that stdlib code is often more complex than application code: formatting management (`core::fmt`), the allocator, the panic mechanism, trait implementations for standard types — all of this generates dense and hard-to-read pseudo-code that overwhelms the analyst if they do not sort through it.

---

## Strategy 1: Separate Application Code by Symbols

This is the most effective approach when the binary is not stripped. All application functions share the same crate prefix in their mangled name.

### Filter with `nm` and `rustfilt`

```bash
# List only application functions
$ nm crackme_rust_release | rustfilt | grep 'crackme_rust::'

# List the crates present in the binary
$ nm crackme_rust_release | rustfilt | grep '::' | \
    sed 's/^\([^ ]* \)\?[^ ]* //' | cut -d: -f1 | sort -u
```

The second command produces the list of embedded crates:

```
alloc  
core  
crackme_rust  
std  
std_detect  
```

Our crackme has no third-party dependencies, but on a real project you would see the complete list here: `serde`, `tokio`, `clap`, `regex`, etc. This list is itself valuable information: it reveals the libraries used by the application, which gives clues about its functionality (networking, crypto, parsing, etc.).

### Annotate in Ghidra

In Ghidra, after automatic analysis and demangling, you can use the Symbol Tree to filter:

1. Open the **Symbol Table** (Window → Symbol Table).  
2. Filter by the application crate name (text search).  
3. Select all application functions and assign them a dedicated label or namespace.  
4. The remaining functions (stdlib) can be grouped into a "stdlib" namespace to visually reduce them.

Some analysts go further and color functions in the Function Graph: green for application code, gray for the stdlib. This allows immediately seeing the interesting areas in the call graph.

---

## Strategy 2: Identify the stdlib by Addresses

Even without symbols, stdlib code and application code tend to occupy distinct address ranges in `.text`. The linker places object files in the order it receives them, and application code is generally linked before the stdlib.

### Locate the Application `main`

The ELF entry point (`_start`) calls `__libc_start_main`, which eventually calls the program's `main`. In Rust, this `main` is a compiler-generated wrapper that initializes the runtime then calls your `fn main()`.

```bash
# Find the entry point
$ readelf -h crackme_rust_strip | grep "Entry point"
  Entry point address:               0x8060

# In GDB, trace to the application main
(gdb) break *0x8060
(gdb) run
(gdb) si 50    # Step forward until the call to main
```

Once the application `main` is located, its address serves as an anchor point. Functions at nearby addresses are probably also application code (since they come from the same object file). Functions at very different addresses are probably stdlib.

### Using the Memory Map

The `.map` files produced by the linker (enabled with `-C link-args=-Wl,-Map=output.map` in `RUSTFLAGS`) give the exact placement of each object section in the final binary. This is the most precise method for delineating code regions.

---

## Strategy 3: Known Function Signatures

This is the premier approach for stripped binaries. The idea is to automatically recognize stdlib functions by comparing their bytes against a pre-computed signature database. We will detail the tools in section 33.6, but here is the principle.

Community projects compile the Rust stdlib for each `rustc` version and each target, then extract signatures (hash of the first bytes of each function). These signatures are distributed as files compatible with Ghidra (FIDB format) or IDA (FLIRT format).

Applying these signatures to a stripped binary allows automatically naming hundreds to thousands of functions. The application code is what remains after this cleanup — the functions that the signature database did not recognize.

The effectiveness depends on the exact match between the `rustc` version and target used to compile the binary and those used to generate the signatures. A version mismatch can significantly reduce the recognition rate.

---

## Strategy 4: XREF-based Approach from `main`

Rather than trying to classify all functions, a more pragmatic approach is to start from the application `main` and follow calls in depth.

### Building the Application Call Graph

1. Locate the application `main` (see strategy 2).  
2. In Ghidra, open the **Function Call Graph** (Window → Function Call Graph) centered on `main`.  
3. Browse the graph level by level. The first levels of calls are almost always application code.  
4. When you reach functions that look like stdlib (formatting, allocation, I/O), stop descending into that branch.

This "top-down" method is often the most effective in practice: instead of sorting 5,000 functions, you only examine a few dozen by following the execution thread.

### Recognizing stdlib Functions Without Naming Them

Even without signatures, certain stdlib functions are recognizable by their structure:

**Formatting functions** (`core::fmt::*`) take complex `fmt::Arguments` structures as parameters (multiple pointers to `.rodata`) and call many sub-functions. They are large and highly branched.

**Allocation functions** (`__rust_alloc`, `__rust_dealloc`) are short wrappers that directly call `malloc`/`free` via the PLT. They are fewer than 10 instructions.

**Panic functions** are identifiable by the `.rodata` strings they reference (see section 33.3).

**Hashing code** (for `HashMap`) contains recognizable magic constants (SipHash uses specific initialization constants).

**I/O code** (`std::io::*`) goes through syscalls or libc calls (`write`, `read`) visible in the PLT/GOT.

By combining these heuristics, an experienced analyst can classify the main stdlib functions without a signature database, simply by recognizing their structural patterns.

---

## The Impact of LTO on Crate Separation

Link-Time Optimization (LTO) radically transforms the binary's structure. Without LTO, each crate is compiled separately and its functions form a relatively continuous block in `.text`. The boundaries between crates are preserved, which makes separation easier.

With LTO (enabled in our `release-strip` profile), LLVM merges all crates into a single compilation unit before optimizing. The consequences for RE are significant.

**Cross-crate inlining.** Stdlib functions can be inlined into application code, and vice versa. Application code and stdlib code end up mixed within the same functions. An "application" function may contain dozens of lines of code from `core::fmt` or `alloc::vec`.

**Function reordering.** LLVM may reorder functions to optimize instruction cache locality. Application functions no longer form a contiguous block — they are scattered among stdlib functions.

**Aggressive elimination.** LTO allows LLVM to see which stdlib functions are actually used and eliminate the rest. The binary is smaller, but the remaining functions are often partial fragments (partially inlined functions, specialized for a single call site).

> ⚠️ **Practical consequence**: on a binary compiled with LTO and stripped, address-based separation strategies (strategy 2) and signature-based strategies (strategy 3) become less effective. The top-down approach from `main` (strategy 4) remains the most reliable, as it follows the actual execution flow instead of looking for structural boundaries that no longer exist.

---

## Comparison with Other Languages

To put the size and noise problem in perspective, here is a comparison with other native languages encountered in RE:

| Language | Stdlib linking | "Hello World" size (release, Linux x86-64) | Functions in the binary | Separation difficulty |  
|---|---|---|---|---|  
| C (GCC) | Dynamic (glibc) | ~16 KB | ~20 | Trivial (almost everything is application code) |  
| C++ (GCC) | Dynamic (libstdc++) | ~17 KB | ~30 | Easy (instantiated templates identifiable) |  
| Rust | Static (stdlib) | ~400 KB – 4 MB | ~4,000 – 8,000 | Difficult (stdlib mixed with application code) |  
| Go | Static (runtime + stdlib) | ~1.8 MB | ~6,000 | Medium (`gopclntab` helps, see ch. 34) |

Rust and Go share the same static linking model and suffer from the same noise problem. The main difference is that Go preserves function names in its `gopclntab` table even after stripping, whereas Rust has no such mechanism. On a stripped binary, Rust RE is objectively harder than Go RE.

---

## Reducing Size at the Source (Developer Perspective)

This section is aimed at analysts who have access to the source code (audit case) or who want to understand why a target binary is unusually small or large.

Rust developers have several levers to reduce their binary size:

| Technique | Typical impact | Effect on RE |  
|---|---|---|  
| `panic = "abort"` | -30% to -50% | Removes unwinding code and reduces panic strings |  
| `lto = true` | -20% to -60% | Eliminates cross-crate dead code, but blurs boundaries |  
| `codegen-units = 1` | -5% to -15% | Better global optimizations |  
| `strip = true` | -15% to -25% | Removes symbols and debug info |  
| `opt-level = "z"` | -10% to -20% | Optimizes for size rather than speed |  
| `cargo-bloat` → refactoring | Variable | Reduces dependencies, thus the number of embedded crates |

An unusually small Rust binary (< 200 KB) was probably compiled with all these options enabled, or even with `#![no_std]` (no stdlib at all, only `core`). In that case, the binary contains little library code and analysis is paradoxically simpler — but the application code must reimplement what the stdlib normally provides (allocation, I/O, formatting), which can make it more complex.

---

## Summary for the Analyst

When facing a large Rust binary, the recommended approach is as follows:

1. **Estimate the signal-to-noise ratio.** If the binary is not stripped, count application functions vs the total. If stripped, the raw size gives an order of magnitude: a 5 MB binary probably contains less than 1% application code.

2. **Choose the appropriate separation strategy.** Not stripped → filter by crate name (strategy 1). Stripped without LTO → signatures + address-based separation (strategies 2 and 3). Stripped with LTO → top-down approach from `main` (strategy 4).

3. **Do not try to understand everything.** The Rust stdlib is known and documented code. When you identify a function as stdlib (by its name, signature, or structure), annotate it and move on. Your analysis time should focus on the application code.

4. **Leverage indirect clues.** The list of embedded crates (via symbols or strings) reveals the project's dependencies: `serde` = serialization, `reqwest` = HTTP, `ring` = cryptography, `clap` = CLI argument parsing, `tokio` = async runtime. These clues orient the analysis before even reading the assembly.

---

> **Next section: 33.6 — Specific Tools: `cargo-bloat`, Ghidra Signatures for the Rust stdlib** — we will review the concrete tools that automate the separation of application code from the stdlib, and their step-by-step usage.

⏭️ [Specific Tools: `cargo-bloat`, Ghidra Signatures for the Rust stdlib](/33-re-rust/06-tools-cargo-bloat-ghidra.md)
