🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 20.3 — RetDec (Avast) — Offline Static Decompilation

> 📘 **Chapter 20 — Decompilation and Source Code Reconstruction**  
> **Part IV — Advanced RE Techniques**

---

## Why a second decompiler?

The previous section presented Ghidra as the central decompilation tool in this training, and it is. So why devote an entire section to another decompiler?

The reason is twofold. First, **no decompiler is universally better** — each uses different heuristics, and where Ghidra produces confusing pseudo-code, RetDec can sometimes offer a more readable reconstruction, and vice versa. Cross-referencing the results of two decompilers on the same binary is a common practice in professional RE, just as one cross-references an `objdump` disassembly with a Ghidra view.

Second, RetDec has a characteristic that fundamentally distinguishes it from Ghidra: it operates **entirely from the command line**, without a graphical interface, and directly produces `.c` and `.dsm` files on disk. This makes it ideal for **integration into scripts and automated pipelines** — a topic we will revisit in chapter 35 (Automation and Scripting).

---

## Introduction to RetDec

RetDec (short for *Retargetable Decompiler*) is an open source decompiler originally developed by the research lab at Avast Software, now maintained as a community project on GitHub. Its source code is published under the MIT license.

### Internal architecture

RetDec adopts a three-stage pipeline architecture, conceptually similar to Ghidra's but with different technical choices:

**Front-end: disassembly and lifting.** The ELF binary is analyzed to extract sections, symbols, and functions. The x86-64 machine code is translated into an intermediate representation based on LLVM IR (Intermediate Representation). This choice of LLVM as the internal IR is what makes RetDec "retargetable" — it can theoretically accept any architecture for which a lifting front-end exists.

**Middle-end: optimizations and analyses.** On this IR, RetDec applies analysis passes that include type detection, control structure reconstruction, idiom recognition (such as divisions by multiplicative inverse), library function identification (via its own signatures), and type propagation. These passes use standard LLVM optimizations enriched with RE-specific passes.

**Back-end: pseudo-code emission.** The optimized IR is converted to C pseudo-code. This pseudo-code is written to a `.c` file on disk, accompanied by an annotated disassembly `.dsm` file and optionally a control flow graph.

### Supported formats

RetDec natively handles ELF (Linux), PE (Windows), Mach-O (macOS), COFF, and raw binary formats. For our training binaries compiled with GCC on Linux, the ELF format is automatically detected. Supported architectures include x86, x86-64, ARM, MIPS, and PowerPC — a spectrum comparable to Ghidra's.

---

## Installation

RetDec can be installed in several ways depending on the work environment.

### Via pre-compiled packages

The official GitHub repository (`avast/retdec`) publishes pre-compiled releases for Linux. On Ubuntu/Debian, the recommended method is to download the latest release archive and extract it:

```bash
# Download the latest release (adjust the version number)
wget https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz

# Extract
tar -xf RetDec-v5.0-Linux-Release.tar.xz

# Add to PATH (put in ~/.bashrc to persist)
export PATH="$PWD/retdec/bin:$PATH"

# Verify the installation
retdec-decompiler --help
```

### Building from source

For those who want the latest development version or need to modify RetDec:

```bash
git clone https://github.com/avast/retdec.git  
cd retdec  
mkdir build && cd build  
cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/retdec-install  
make -j$(nproc)  
make install  
```

Building from source requires CMake ≥ 3.16, a C++17 compiler, and can take 20 to 40 minutes depending on the machine. LLVM dependencies are included in the repository (no system-wide LLVM installation required).

### Quick verification

To confirm that RetDec works in our environment, let's decompile a test binary:

```bash
retdec-decompiler keygenme_O0
```

RetDec should produce two files: `keygenme_O0.c` (pseudo-code) and `keygenme_O0.dsm` (annotated disassembly). If these files appear, the installation is functional.

---

## Command-line usage

### Basic decompilation

The simplest command takes a binary as an argument and produces the corresponding pseudo-code:

```bash
retdec-decompiler keygenme_O2_strip
```

RetDec displays its progress on standard output — format detection, architecture identification, function analysis, optimization passes, code emission. Output files are created in the same directory as the input binary:

```
keygenme_O2_strip.c      ← C pseudo-code  
keygenme_O2_strip.dsm    ← annotated disassembly  
```

### Useful options

RetDec offers several options that modify the decompilation behavior.

**Selecting a specific function.** By default, RetDec decompiles the entire binary. To process only a single function (which is much faster on large binaries):

```bash
# By symbol name
retdec-decompiler --select-functions derive_key keygenme_O2

# By address range
retdec-decompiler --select-ranges 0x401200-0x401350 keygenme_O2_strip
```

**Disabling certain passes.** If an optimization pass produces a less readable result than the input (this happens with variable elimination or loop simplification), it can be disabled:

```bash
retdec-decompiler --backend-no-opts keygenme_O3
```

**Outputting intermediate LLVM IR.** For advanced analysts who want to inspect the intermediate representation produced by the lifting front-end:

```bash
retdec-decompiler --print-after-all keygenme_O2
```

This command displays the LLVM IR after each optimization pass, allowing you to observe the transformations applied. The produced IR can then be analyzed with standard LLVM tools (`opt`, `llvm-dis`).

**Configuration file.** For repeated analyses with the same options, RetDec accepts a JSON configuration file:

```bash
retdec-decompiler --config config.json keygenme_O2
```

---

## Analyzing the produced pseudo-code

Let's now compare RetDec's output with Ghidra's on the same functions from our training binaries.

### verify_key function at -O0

Here is a typical RetDec output for the `verify_key` function of `keygenme_O0`:

```c
// Address range: 0x401290 - 0x4012d8
int32_t verify_key(uint8_t * expected, uint8_t * provided) {
    int32_t result = 0;
    for (int32_t i = 0; i < 16; i++) {
        result |= (int32_t)expected[i] ^ (int32_t)provided[i];
    }
    return result == 0;
}
```

Several immediate observations. First, the reconstruction is very faithful to the original source — the `for` loop is clean, the byte-by-byte XOR comparison is clear, and the conditional return is well expressed. RetDec even identified the loop size as the literal `16` and not `0x10`, a formatting choice that improves readability.

Additionally, RetDec displays the function's addresses as a comment (`Address range`), which makes it easy to locate in the disassembly. It also correctly inferred the `uint8_t *` types for both parameters, likely thanks to byte-by-byte memory access patterns.

### derive_key function at -O2

On `keygenme_O2`, the `derive_key` logic is inlined into `main`. But RetDec's LLVM passes can in some cases reconstruct the outer loop where Ghidra showed 4 blocks of linear code (section 20.2). Here is a representative reconstruction of the derivation passage in the pseudo-code of `main`:

```c
// Address range: 0x401580 - 0x401720
void derive_key(char * username, uint32_t seed, uint8_t * out) {
    int64_t len = strlen(username);
    uint32_t state = seed;
    for (int32_t r = 0; r < 4; r++) {
        if (r != 0) {
            state = state ^ (uint32_t)r;
        }
        for (int64_t i = 0; i < len; i++) {
            uint32_t c = (uint32_t)(uint8_t)username[i];
            state = (state ^ c) << 5 | (state ^ c) >> 27;
            state += c * 0x1000193;
            state ^= state >> 16;
        }
        out[r * 4] = (uint8_t)(state >> 24);
        out[r * 4 + 1] = (uint8_t)(state >> 16);
        out[r * 4 + 2] = (uint8_t)(state >> 8);
        out[r * 4 + 3] = (uint8_t)state;
    }
}
```

This result is actually **better** than Ghidra's on this particular case: the outer 4-round loop is reconstructed, the inlining of `mix_hash` and `rotate_left` is visible but the structure remains compact. The logic is much easier to understand at a glance.

This is not a general rule — on other functions in the same binary, Ghidra may produce superior pseudo-code. This is exactly why cross-referencing two decompilers has value.

### The C++ case: oop_O2

On the C++ binary, RetDec shows a significant limitation: its handling of virtual dispatch and STL containers is less mature than Ghidra's. Virtual calls appear as indirect calls through function pointers, with no attempt to resolve the vtable. STL template functions are not always correctly identified, and the pseudo-code may contain bulky casts to generic types.

For C++ binaries with inheritance and polymorphism, Ghidra remains the tool of choice. RetDec shines more on pure C and binaries with procedural logic.

---

## RetDec vs Ghidra: compared strengths and weaknesses

### Where RetDec does better

**Loop reconstruction.** RetDec's LLVM passes sometimes excel at reconstituting the original iterative structure from unrolled code, as we saw with `derive_key`. LLVM's loop detection heuristics benefit from decades of compiler research.

**Output formatting readability.** RetDec produces well-indented and formatted C pseudo-code, with address comments, function separators, and a consistent naming convention. The output `.c` file is directly readable in any text editor or IDE.

**Batch processing.** Decompiling 50 binaries in a single shell loop is trivial with RetDec and impractical with Ghidra in GUI mode (although Ghidra headless also allows it — chapter 8, section 9). An automated analysis pipeline can integrate RetDec as a preprocessing step.

**Compiler idiom recognition.** RetDec recognizes certain GCC idioms that Ghidra does not always simplify, notably constant divisions via multiplicative inverse. Where Ghidra may display `(uint64_t)x * 0xAAAAAAABull >> 33`, RetDec can reconstruct `x / 3`.

### Where Ghidra does better

**Interactivity.** This is the fundamental difference. Ghidra allows renaming, retyping, restructuring, commenting, navigating by cross-references — all in real time, with immediate re-decompilation. RetDec produces a static file. If the result is unsatisfactory, you can modify the options and rerun, but you cannot guide the decompilation function by function.

**C++ support.** Ghidra handles vtables, RTTI, name demangling, C++ exceptions, and STL containers with much more maturity. For a G++ binary, Ghidra is clearly superior.

**Script and plugin ecosystem.** Ghidra scripts (Java/Python) allow automating renaming, type creation, and annotation tasks that have no equivalent in RetDec.

**Disassembly/pseudo-code synchronization.** Ghidra's bidirectional Listing ↔ Decompiler view is irreplaceable for daily analytical work. With RetDec, you must manually correlate addresses between the `.c` file and the `.dsm` file.

**Community and documentation.** Ghidra, backed by the NSA and a large community, benefits from thousands of third-party scripts, tutorials, plugins, and active support. RetDec's ecosystem is more modest.

### Summary table

| Criterion | Ghidra Decompiler | RetDec |  
|---|---|---|  
| Usage mode | Interactive GUI + headless | CLI only |  
| License | Apache 2.0 | MIT |  
| Output language | Pseudo-C (panel) | `.c` file on disk |  
| Internal IR | P-code | LLVM IR |  
| C++ support | Excellent (vtable, RTTI, STL) | Basic |  
| Loop reconstruction | Good | Very good |  
| Compiler idioms | Good | Very good |  
| Pipeline integration | Via headless (heavy) | Native CLI (lightweight) |  
| Interactive correction | Yes (renaming, retyping) | No |  
| Quality on pure C -O2 | Very good | Very good |  
| Quality on C++ -O2 | Very good | Average |

---

## Combined RetDec + Ghidra workflow

In practice, the two tools are not mutually exclusive — they complement each other. Here is a workflow that leverages the strengths of each.

**Step 1: quick decompilation with RetDec.** Run RetDec from the command line on the target binary to get an overview. Open the `.c` file in a text editor and browse through the functions. This step takes a few seconds and gives a first glimpse of the program structure — number of functions, library calls, strings, notable constants.

**Step 2: interactive analysis in Ghidra.** Import the same binary into Ghidra for in-depth analysis work. Use the interactive pseudo-code to rename, retype, create structures, and follow cross-references.

**Step 3: cross-referencing on difficult functions.** When Ghidra's pseudo-code is confusing on a specific function (often due to a poorly reconstructed loop or an unrecognized idiom), consult RetDec's output for the same function. Comparing the two representations often helps converge on the correct interpretation.

**Step 4: validation through disassembly.** In case of persistent doubt between the two pseudo-codes, the disassembly in Ghidra (Listing or Function Graph view) is the final arbiter. Machine code does not lie — decompilers interpret it.

This workflow applies particularly well to C binaries compiled with GCC at `-O2` or `-O3`, where the two decompilers have complementary strengths. On C++, Ghidra dominates sufficiently that RetDec primarily serves as an occasional "second opinion."

---

## Known RetDec limitations

Beyond the comparison with Ghidra, RetDec has some limitations of its own that the analyst should be aware of.

**Decompilation time on large binaries.** The LLVM pipeline is computationally intensive. A binary of a few megabytes can take several minutes to fully decompile. The `--select-functions` or `--select-ranges` option is essential for large binaries — decompile only the functions of interest rather than the whole thing.

**No persistent session management.** Unlike Ghidra which saves the project with all annotations, RetDec produces stateless output files. If you rerun the decompilation, you start from scratch. Annotations and corrections must be maintained in separate files (or in Ghidra).

**Limited DWARF support.** RetDec leverages DWARF information when present, but with less depth than Ghidra. Complex types (nested structures, unions, C++ template types) are not always correctly reconstructed from DWARF.

**Slowed development.** Since the project's transfer out of Avast, the development pace has decreased. GitHub issues are not always addressed promptly, and some announced features (improved C++ support, better exception handling) have not yet been implemented. The analyst should be aware that RetDec is a mature tool whose evolution is uncertain.

---


⏭️ [Reconstructing a `.h` file from a binary (types, structs, API)](/20-decompilation/04-reconstructing-header.md)
