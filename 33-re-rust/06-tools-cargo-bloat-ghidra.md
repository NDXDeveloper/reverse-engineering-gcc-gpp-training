🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 33.6 — Specific Tools: `cargo-bloat`, Ghidra Signatures for the Rust stdlib

> 🧰 The previous sections described Rust patterns and conceptual strategies for navigating a large binary. This section moves to concrete tools: those on the developer side that help understand a binary's composition, and those on the analyst side that automate stdlib identification to isolate the application code.

---

## Developer-Side Tools (when you have the source code)

These tools are useful in two scenarios: you are conducting a security audit and have access to the source code, or you are compiling a reference binary to prepare signatures.

### `cargo-bloat` — What Is Taking Up Space?

`cargo-bloat` is a `cargo` extension that analyzes the size of each function and each crate in the final binary. It is the most direct diagnostic tool for understanding the composition of a Rust binary.

**Installation:**

```bash
$ cargo install cargo-bloat
```

**Analysis by function — the biggest contributors:**

```bash
$ cd binaries/ch33-rust/crackme_rust/
$ cargo bloat --release -n 20
```

The output looks like this:

```
 File  .text    Size        Crate Name
 3.8%  8.1%  6.0KiB          std std::rt::lang_start_internal
 2.5%  5.3%  3.9KiB         core core::fmt::write
 2.1%  4.5%  3.3KiB         core core::fmt::Formatter::pad
 1.8%  3.9%  2.9KiB          std std::io::Write::write_fmt
 1.5%  3.2%  2.4KiB         core core::fmt::num::<impl ...>::fmt
 0.9%  1.9%  1.4KiB crackme_rust crackme_rust::ChecksumValidator::validate  (*)
 0.7%  1.5%  1.1KiB crackme_rust crackme_rust::FormatValidator::validate    (*)
 0.5%  1.0%    768B crackme_rust crackme_rust::main                         (*)
 ...
```

The lines marked `(*)` are the application functions — they represent a tiny fraction of the total. The biggest contributors are systematically the formatting functions (`core::fmt`), I/O (`std::io`), and runtime initialization (`std::rt`).

**Analysis by crate — dependency distribution:**

```bash
$ cargo bloat --release --crates
```

```
 File  .text    Size Crate
 45.2% 62.1% 230KiB std
 28.1% 24.3%  90KiB core
  8.5%  7.4%  27KiB alloc
  4.3%  3.7%  14KiB crackme_rust
  2.1%  1.8%   7KiB compiler_builtins
  ...
```

This view shows that the stdlib (`std` + `core` + `alloc`) represents more than 80% of the code, while the application crate weighs only 4%. On a project with third-party dependencies, you would see each crate's contribution here — revealing the most "costly" libraries in terms of size.

> 💡 **RE application**: running `cargo bloat --crates` on the source code of an audit target immediately gives you the list of embedded crates and their relative weight. This prepares your analysis: if `ring` represents 15% of the binary, you know there is significant cryptography; if `serde_json` is present, there is JSON serialization, etc.

### `cargo-bloat` with Crate Filter

To focus on application code:

```bash
$ cargo bloat --release --filter crackme_rust -n 30
```

This command lists only the functions from the `crackme_rust` crate, sorted by decreasing size. This is the exact map of the code the analyst will need to reverse.

### `twiggy` — Size Dependency Graph Analysis

`twiggy` (Mozilla) is a tool complementary to `cargo-bloat`. It analyzes the retention graph: for each function, it indicates why it is in the binary (who calls it) and how much space it "retains" (itself plus everything it exclusively calls).

```bash
$ cargo install twiggy
$ cargo build --release
$ twiggy top target/release/crackme_rust -n 15
$ twiggy dominators target/release/crackme_rust | head -30
```

The `dominators` command is particularly useful: it shows the retention hierarchy. If a 500-byte application function exclusively calls a 20 KB stdlib branch, the dominator shows that this function "costs" 20.5 KB total. For the RE analyst, this reveals which application functions pull in the largest stdlib portions — and therefore which execution paths will be the most complex to analyze.

---

## Analyst-Side Tools (without source code)

### `rustfilt` — Command-Line Demangling

Covered in detail in section 33.2, `rustfilt` is the indispensable tool for any non-stripped Rust binary analysis. Reminder of essential usages:

```bash
# Demangle a single symbol
$ echo "_RNvNtCs9g8eSEAj0m_13crackme_rust17ChecksumValidator3new" | rustfilt

# Demangle the complete nm output
$ nm crackme_rust_release | rustfilt > symbols_demangled.txt

# Demangle objdump output
$ objdump -d -M intel crackme_rust_release | rustfilt | less

# List only application functions
$ nm crackme_rust_release | rustfilt | grep ' T .*crackme_rust::'
```

The `objdump | rustfilt` pipe transforms an unreadable disassembly (mangled symbols of 80+ characters) into a comprehensible listing where each `call` displays the demangled name of the target function.

### `rustc-demangle` — Programmable Library

For automated analysis scripts, the `rustc-demangle` library (the engine behind `rustfilt`) is available in Rust and C. It allows integrating demangling into custom tools:

```python
# In Python, via subprocess
import subprocess

def rust_demangle(symbol):
    result = subprocess.run(
        ['rustfilt'],
        input=symbol,
        capture_output=True,
        text=True
    )
    return result.stdout.strip()
```

For intensive usage (processing thousands of symbols), calling `rustfilt` once with all symbols as input is much more performant than calling it in a loop.

---

## Ghidra Signatures for the Rust stdlib

### The Stripped Binary Problem

On a stripped Rust binary, Ghidra assigns generic names to functions (`FUN_00401230`, `FUN_00401450`, etc.). Among the thousands of functions, the majority comes from the stdlib — but without signatures, Ghidra cannot identify them.

**Function signatures** (Function ID, or FIDB in Ghidra) solve this problem. The principle: compare the first bytes of each function in the target binary against a database of known functions (compiled from the Rust stdlib). When a match is found, the function is automatically renamed.

### Community Rust Signature Projects

Several projects maintain signature databases for the Rust stdlib:

**`rust-std-ghidra-sigs`** — The most established project. It provides FIDB files for Ghidra, generated from the stdlib compiled for different `rustc` versions and different targets.

```bash
# Clone the signature repository
$ git clone https://github.com/<project>/rust-std-ghidra-sigs.git
```

The FIDB files are organized by rustc version and by target:

```
rust-std-ghidra-sigs/
├── 1.75.0/
│   ├── x86_64-unknown-linux-gnu.fidb
│   ├── x86_64-unknown-linux-musl.fidb
│   └── ...
├── 1.76.0/
│   └── ...
└── ...
```

**`sigkit`** (for IDA) — The FLIRT format equivalent for IDA users. The principle is identical: pre-computed signatures to apply to the binary.

> ⚠️ **Version matching.** The effectiveness of signatures depends on the exact match between the `rustc` version used to compile the target binary and the one used to generate the signatures. A single minor version offset can reduce the recognition rate from 90% to 50%, because LLVM optimizations subtly change the generated code between versions. Identifying the `rustc` version is therefore an important preliminary step (see below).

### Installing Signatures in Ghidra

Installation follows Ghidra's standard workflow for FIDB files:

**Step 1 — Copy the FIDB file into the Ghidra directory:**

```bash
$ cp rust-std-ghidra-sigs/1.76.0/x86_64-unknown-linux-gnu.fidb \
    $GHIDRA_HOME/Features/Base/data/fidb/
```

Alternatively, in Ghidra: File → Install Extensions → or place the `.fidb` in the user folder `~/.ghidra/<version>/fidb/`.

**Step 2 — Apply signatures during analysis:**

When importing a binary, in the Analysis Options panel:
1. Make sure **Function ID** is checked in the analyzer list.  
2. Click the configuration button (gear icon) next to Function ID.  
3. Verify that the Rust FIDB file is listed and enabled.  
4. Launch the analysis.

**Step 3 — Verify the results:**

After analysis, open the Symbol Table and filter by source "Function ID Analyzer". Recognized functions appear with their full stdlib name.

```
FUN_00401230  →  core::fmt::write  
FUN_00401450  →  core::panicking::panic_fmt  
FUN_00401890  →  alloc::raw_vec::RawVec<T,A>::reserve_for_push  
FUN_00401a20  →  std::io::stdio::_print  
...
```

Functions not recognized are either application code or stdlib functions that have diverged (different `rustc` version, different compilation options). In both cases, the analyst must decide — but the work is considerably reduced.

### Generating Your Own Signatures

If no pre-existing signature matches the `rustc` version of the target, you can generate your own. The process is as follows:

**1. Identify the target's `rustc` version** (see the dedicated section below).

**2. Compile the stdlib with that exact version:**

```bash
# Install the specific rustc version via rustup
$ rustup install 1.76.0
$ rustup default 1.76.0

# Compile a minimal project to produce the stdlib .rlib files
$ cargo new --bin dummy_project
$ cd dummy_project
$ cargo build --release
```

The stdlib `.rlib` files are found in the `~/.rustup/toolchains/1.76.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/` directory.

**3. Generate the FIDB file with Ghidra:**

Ghidra provides a headless tool to create FIDB files from libraries:

```bash
$ $GHIDRA_HOME/support/analyzeHeadless /tmp ghidra_project \
    -import ~/.rustup/toolchains/1.76.0-*/lib/rustlib/*/lib/*.rlib \
    -postScript CreateFidDatabase.java \
    -scriptPath $GHIDRA_HOME/Features/Base/ghidra_scripts/
```

The exact process may vary depending on the Ghidra version. Consult the Ghidra documentation for details on the `CreateFidDatabase` script.

**4. Test on the target binary** by following the installation steps described above.

---

## Identifying the `rustc` Version in a Binary

To apply the right signatures, you need to know the `rustc` version used to compile the target. Several clues allow deducing it.

### The `.comment` String

The ELF `.comment` section sometimes contains the compiler version:

```bash
$ readelf -p .comment crackme_rust_release

String dump of section '.comment':
  [     0]  rustc version 1.76.0 (07dca489a 2024-02-04)
```

This section often survives stripping (`strip --strip-all` does not always remove it, but `strip --remove-section=.comment` does). This is the first place to check.

```bash
# Also check on a stripped binary
$ readelf -p .comment crackme_rust_strip 2>/dev/null
```

### Strings in `.rodata`

Stdlib panic messages contain paths to the stdlib source code, which sometimes include the version:

```bash
$ strings crackme_rust_strip | grep -i "rustc\|rust-src\|toolchain"
$ strings crackme_rust_strip | grep "library/std/src"
```

Paths of the form `/rustc/<commit_hash>/library/core/src/...` contain the `rustc` commit hash. This hash can be looked up in the Rust GitHub repository to identify the exact version:

```bash
$ strings crackme_rust_strip | grep -oP '/rustc/[a-f0-9]+/' | head -1
/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce/

# Look up this hash on GitHub:
# https://github.com/rust-lang/rust/commit/07dca489ac2d933c78d3c5158e3f43beefeb02ce
# → corresponds to rustc 1.76.0
```

### Entropy and Size as Indirect Clues

The binary's size and section proportions vary between `rustc` versions (LLVM optimizations evolve). This is not a precise method, but combined with other clues, it can help narrow down the range of candidate versions.

---

## Radare2 and Rust Binaries

Radare2 has useful features for Rust RE, accessible from the command line.

### Automatic Demangling

```bash
# Enable global demangling
$ r2 -A crackme_rust_release
[0x00008060]> e asm.demangle=true
[0x00008060]> e bin.demangle=true

# List functions with demangled names
[0x00008060]> afl~crackme_rust
```

The `~crackme_rust` filter after `afl` (analyze functions list) acts as a built-in `grep` and displays only the application functions.

### Signatures with `zignatures`

Radare2 has its own signature system called `zignatures` (`z` commands). You can generate signatures from a reference binary and apply them to a stripped target:

```bash
# On the reference binary (with symbols)
$ r2 crackme_rust_release
[0x00008060]> aa
[0x00008060]> zg           # Generate zignatures for all functions
[0x00008060]> zos sigs.z   # Save to a file

# On the stripped binary
$ r2 crackme_rust_strip
[0x00008060]> aa
[0x00008060]> zo sigs.z    # Load zignatures
[0x00008060]> z/           # Apply (search for matches)
[0x00008060]> afl          # Recognized functions are renamed
```

This method works well when the reference binary and the target were compiled with the same `rustc` version and the same options. This is typically the case during an audit where you can recompile the project.

---

## Binary Ninja and IDA: Rust Support

### Binary Ninja

Binary Ninja recognizes Rust v0 mangling natively in its recent versions. Its features relevant to Rust RE include automatic demangling on import, an extensible type system (for defining `RustStr`, `RustString`, etc.), and a rich Python API that allows automating function classification by crate. The community plugin `bn-rust-demangle` fills the gaps in older versions.

### IDA Free / IDA Pro

IDA handles Rust v0 demangling since version 7.7. For earlier versions, the `ida-rust-demangle` plugin fills this role. IDA's FLIRT system is the equivalent of Ghidra's FIDB: pre-computed `.sig` files allow recognizing the stdlib. The `ida-rust-sig` project provides FLIRT signatures for different `rustc` versions.

Applying FLIRT signatures in IDA is done via the menu File → Load File → FLIRT signature file, then selecting the appropriate `.sig` file.

---

## Ghidra Scripts for Rust Analysis

Beyond signatures, a few Ghidra scripts (Java or Python) automate recurring tasks in Rust analysis.

### Crate Classification Script

This script iterates through demangled symbols, extracts the crate name from each function, and creates corresponding namespaces in Ghidra:

```python
# classify_rust_crates.py — Ghidra Script (Jython)
# Classifies Rust functions by crate into Ghidra namespaces

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()  
st = currentProgram.getSymbolTable()  
ns_cache = {}  

for func in fm.getFunctions(True):
    name = func.getName()
    # Demangled functions contain "::" as separator
    if "::" not in name:
        continue
    crate = name.split("::")[0]
    if crate not in ns_cache:
        ns_cache[crate] = st.createNameSpace(
            None, crate, SourceType.ANALYSIS
        )
    func.setParentNamespace(ns_cache[crate])

print("Classified {} crates".format(len(ns_cache)))  
for crate, ns in sorted(ns_cache.items()):  
    count = len([f for f in fm.getFunctions(True)
                 if f.getParentNamespace() == ns])
    print("  {} : {} functions".format(crate, count))
```

After execution, the Symbol Tree displays functions grouped by crate (`core`, `alloc`, `std`, `crackme_rust`, etc.), which makes navigation immediately more productive.

### Panic Annotation Script

This script searches for references to panic strings in `.rodata` and annotates the corresponding functions:

```python
# annotate_rust_panics.py — Ghidra Script (Jython)
# Adds comments to Rust panic sites

from ghidra.program.model.listing import CodeUnit

listing = currentProgram.getListing()  
mem = currentProgram.getMemory()  
strings_found = 0  

# Search for panic strings in .rodata
for block in mem.getBlocks():
    if block.getName() != ".rodata":
        continue
    # Iterate through defined data in .rodata
    data = listing.getDefinedData(block.getStart(), True)
    while data is not None and block.contains(data.getAddress()):
        val = data.getDefaultValueRepresentation()
        if val and ("panicked at" in val or "unwrap()" in val
                     or "index out of bounds" in val):
            # Find XREFs to this string
            refs = getReferencesTo(data.getAddress())
            for ref in refs:
                func = getFunctionContaining(ref.getFromAddress())
                if func:
                    listing.setComment(
                        ref.getFromAddress(),
                        CodeUnit.EOL_COMMENT,
                        "RUST PANIC: " + val[:60]
                    )
                    strings_found += 1
        data = listing.getDefinedData(data.getAddress().next(), True)

print("Annotated {} panic sites".format(strings_found))
```

These annotations are visible in the Listing and in the decompiler, allowing instant identification of panic paths in the code without having to follow each XREF manually.

---

## Integrated Workflow: From Import to Application Code

To conclude this chapter, here is the complete recommended workflow for analyzing an unknown Rust binary, from initial import to isolating the application code.

**Phase 1 — Triage (5 minutes)**

```bash
$ file target_binary
$ strings -n 3 target_binary | grep -E '\.rs:|panicked|rustc|RUST'
$ readelf -p .comment target_binary
$ checksec --file=target_binary
$ readelf -S target_binary | wc -l
$ nm target_binary 2>/dev/null | head -5    # Stripped or not?
```

Expected result: you know it is Rust, whether it is stripped, and the probable `rustc` version used.

**Phase 2 — Import and Signatures (10 minutes)**

1. Import the binary into Ghidra, enable full analysis.  
2. Enable the Rust Demangler in the analysis options.  
3. Apply the FIDB signatures matching the identified `rustc` version.  
4. Check the recognition rate in the Symbol Table.

**Phase 3 — Classification (10 minutes)**

1. Run the crate classification script (if the binary has symbols).  
2. If stripped: identify the application `main` via the entry point, then explore the call graph in depth.  
3. Annotate panic functions with the dedicated script.

**Phase 4 — Targeted Analysis**

1. Focus on the identified application functions.  
2. Apply the Ghidra types `RustStr`, `RustString`, `PanicLocation` to relevant locations.  
3. Use the patterns from section 33.3 to decode `Option`, `Result`, `match` constructs.  
4. Use the patterns from section 33.4 to find strings and comparisons.

At this point, you are working on a manageable subset of functions, with annotated types and readable names — optimal conditions for in-depth analysis.

---

> 📌 **End of Chapter 33.** You now have the knowledge and tools needed to approach the reverse engineering of Rust binaries compiled with the GNU toolchain. The patterns presented in this chapter cover the vast majority of constructs you will encounter in practice. To go further, Chapter 34 applies a similar approach to Go binaries — another statically linked language whose RE presents its own challenges.

⏭️ [Chapter 34 — Reverse Engineering Go Binaries](/34-re-go/README.md)
