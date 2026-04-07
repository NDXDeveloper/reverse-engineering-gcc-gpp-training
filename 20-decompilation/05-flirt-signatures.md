🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 20.5 — Identifying Embedded Third-Party Libraries (FLIRT / Ghidra Signatures)

> 📘 **Chapter 20 — Decompilation and Source Code Reconstruction**  
> **Part IV — Advanced RE Techniques**

---

## The problem: hundreds of functions that are not yours

When opening a stripped binary in Ghidra, the Symbol Tree displays hundreds, sometimes thousands of functions named `FUN_XXXXXXXX`. The analyst knows that only a fraction of these functions constitute the program's business logic — the rest comes from statically linked libraries or compiler-embedded runtime code.

The phenomenon is particularly pronounced in three situations:

**Statically linked binaries.** When a program is compiled with `gcc -static`, the entire libc (and potentially other libraries) is copied into the final binary. A simple static `hello world` weighs over 750 KB on x86-64 and contains more than a thousand functions — of which only one is user code.

**Binaries embedding crypto libraries.** Our `crypto.c` (chapter 24) may embed statically compiled OpenSSL or libsodium functions. An analyst who does not recognize these functions will waste hours trying to understand an AES or SHA-256 implementation that is actually standard library code.

**C++ binaries with the STL.** Standard Template Library templates are instantiated in every compilation unit that uses them. The `oop_O2_strip` binary contains dozens of functions from `std::vector`, `std::map`, `std::string`, and `std::unique_ptr` — template code that pollutes the function list and drowns the business logic.

Identifying these third-party libraries is a considerable productivity multiplier. Recognizing that a 200-line pseudo-code function is actually an optimized `memcpy` from glibc, or that the 15 interconnected functions starting at address `0x408000` constitute mbedTLS's AES implementation, allows naming them, "setting them aside," and focusing analysis effort on the code that actually matters.

---

## General principle: signature matching

The fundamental idea is simple: compute a fingerprint (signature) of each known function in a library from its first bytes of machine code, then compare these fingerprints with the functions in the analyzed binary. If a fingerprint matches, the library function's name can be assigned to the unknown binary function.

This principle is implemented by two distinct systems we will study: **FLIRT** (Fast Library Identification and Recognition Technology), originally developed by Hex-Rays for IDA, and **Function ID** (FID), Ghidra's native system.

### Matching challenges

The signature approach is not trivial. Several factors complicate matching:

**Relocations.** When a library is compiled, internal addresses (inter-function calls, global data accesses) are not yet resolved — they contain relocation slots that will be filled by the linker. Two compilations of the same library with different base addresses produce different bytes at these locations. The signature must therefore **mask** the bytes corresponding to relocations and only compare invariant bytes.

**Compiler versions.** The same `strlen` function compiled by GCC 11 and GCC 13 may produce slightly different machine code (register choices, instruction scheduling). Signature databases must cover multiple compiler versions to be effective.

**Optimization levels.** The same library compiled at `-O0` and `-O2` produces radically different code. Signatures are therefore specific to an optimization level — a signature database created from glibc at `-O2` will not recognize a glibc linked at `-O0`.

**Short functions.** A 5-instruction function produces a very short and therefore potentially ambiguous signature — multiple different functions may have the same signature. Signature systems handle this ambiguity through confirmation mechanisms (verifying subsequent bytes, verifying cross-references).

---

## FLIRT: the historical standard

FLIRT is the oldest and most widespread signature system in the RE world. Although it was designed for IDA, its signature files (`.sig`) are documented and can be used in other tools, including indirectly in Ghidra via third-party plugins.

### How FLIRT works

The FLIRT process operates in two phases:

**Signature creation phase (offline).** Starting from object files (`.o`) or static libraries (`.a`) of a known library. The `pelf` tool (for ELF) or `pcf` (for COFF) parses these files, extracts each function's code, masks relocation bytes, and produces a pattern file (`.pat`). Then, the `sigmake` tool compiles these patterns into a compact signature file (`.sig`) that can be distributed and applied quickly.

The chain is therefore: `.a` / `.o` → `pelf` → `.pat` → `sigmake` → `.sig`

**Application phase (during analysis).** When the analyst loads a `.sig` file in IDA (or in a compatible tool), the FLIRT engine scans all functions in the binary and compares their first bytes with the patterns in the database. For each match, the function is renamed with the library function's name.

### FLIRT pattern format

A FLIRT pattern is a sequence of hexadecimal bytes where dots (`..`) represent masked bytes (relocations). For example:

```
558BEC83EC..8B45..8945..8B4D..894D..EB..8B55..0FB602 ... strlen
```

The first bytes (`558BEC83EC`) correspond to the x86 32-bit function prologue (`push ebp; mov ebp, esp; sub esp, ...`). In x86-64, the equivalent prologue would be `554889E54883EC...`. The `..` mark variable sizes (stack offset relocation), and the following bytes are the invariant function body. The name `strlen` is associated with this signature.

### Creating your own FLIRT signatures for GCC

For our training binaries, we might want to create signatures for the glibc used on our system. The FLIRT tools (`pelf`, `sigmake`) are distributed with the IDA SDK (available to license holders). For those without IDA, open source alternatives exist:

**`flair` / `pat2sig`** — open source reimplementation of the FLIRT pipeline, available on GitHub. Allows creating `.pat` files from `.a` files and compiling them into `.sig`.

**`lscan`** — Python tool that applies FLIRT signatures to an ELF binary without requiring IDA.

**`sig-from-lib`** — script that automates signature extraction from static libraries installed on the system (`/usr/lib/x86_64-linux-gnu/*.a`).

The typical workflow for creating a signature database for the local glibc:

```bash
# Locate the libc static library
ls /usr/lib/x86_64-linux-gnu/libc.a

# Extract patterns (with a compatible tool)
pelf /usr/lib/x86_64-linux-gnu/libc.a libc_glibc236.pat

# Resolve collisions and compile
sigmake libc_glibc236.pat libc_glibc236.sig
```

If `sigmake` detects collisions (multiple functions with the same pattern), it produces an `.exc` (exceptions) file that the analyst must manually edit to resolve ambiguities before rerunning `sigmake`.

---

## Function ID: Ghidra's native system

Ghidra integrates its own function identification system called **Function ID** (FID). It is conceptually similar to FLIRT but with a different implementation and database format.

### Function ID architecture

Function ID uses databases in `.fidb` format (Function ID Database) stored in Ghidra's installation directory. Each database contains records associating a hash of a function's machine code with its name and source library.

The system uses two-level hashing:

**Full hash.** Computed over the entire function body, masking relocation opcodes. This is the primary matching criterion.

**Specific hash.** Computed over a restricted subset of invariant bytes (typically opcodes without operands). Used to confirm ambiguous full hash matches.

When Ghidra analyzes a binary, Function ID automatically compares each detected function against its databases. Found matches are displayed in the *Function Signature Source* column of the Symbol Tree, marked as "FID" with a confidence score.

### Databases shipped with Ghidra

Ghidra comes with pre-built FID databases for the most common libraries. They are found in the `Ghidra/Features/FunctionID/data/` directory:

```
Ghidra/Features/FunctionID/data/
├── libc_glibc_2.XX_x64.fidb      ← glibc for x86-64
├── libstdcpp_XX_x64.fidb          ← libstdc++ for x86-64
├── libm_glibc_2.XX_x64.fidb      ← libm (math) for x86-64
├── libcrypto_openssl_XX.fidb      ← OpenSSL libcrypto
└── ...
```

The available versions depend on the Ghidra release. If the exact glibc version of your target binary is not covered, signatures from a close version can still produce partial matches — functions stable between versions (like `strlen`, `memcpy`, `printf`) are recognized even with a slight version mismatch.

### Checking and configuring Function ID

To see which FID databases are active in a Ghidra project: menu *Tools → Function ID → Manage FID Databases*. This window lists all installed databases, their state (active/inactive) and the number of functions they contain.

If the initial automatic analysis did not apply Function ID (this can happen if the option was disabled), it can be rerun manually: menu *Analysis → One Shot → Function ID*. Ghidra scans all functions and applies found matches.

After execution, check results in the Symbol Tree: identified functions are renamed with their library name. The *Function ID Results* window (accessible via *Window → Function ID Results*) displays a summary of matches, with the confidence score for each identification.

### Creating your own Function ID databases

When the provided databases do not cover the libraries embedded in the target binary, you can create your own FID databases. Ghidra provides the necessary tools via the *Tools → Function ID* menu.

The workflow consists of:

1. **Create a new empty FID database.** *Tools → Function ID → Create New FID Database*. Choose a descriptive name like `libsodium_1.0.18_x64_O2.fidb`.

2. **Import the reference library.** Compile (or obtain) the target library statically with symbols. Import the `.a` or `.o` files into a dedicated Ghidra project and run the full analysis.

3. **Populate the FID database.** *Tools → Function ID → Populate FID from Programs*. Select the reference program (the analyzed library) and the target FID database. Ghidra computes hashes for each named function and records them in the database.

4. **Apply the database to the target binary.** Copy the `.fidb` file to Ghidra's FID directory, or load it manually via *Manage FID Databases*. Rerun Function ID analysis on the target binary.

This method is particularly useful for specialized libraries that Ghidra does not natively know — crypto libraries (libsodium, mbedTLS, wolfSSL), network frameworks (libevent, statically compiled libcurl), or game engines.

---

## Advanced Ghidra signatures: Function Tags and Data Type Archives

Beyond Function ID, Ghidra offers two complementary mechanisms that help identify and manage library functions.

### Data Type Archives (.gdt)

Data type archives are `.gdt` files containing C/C++ type definitions for known libraries. When Ghidra detects a call to `printf` via PLT, it looks up `printf`'s signature in the `.gdt` archives to automatically apply the correct number and types of parameters.

The archives shipped with Ghidra cover standard system headers (POSIX, Windows API, etc.). New ones can be created via *Parse C Source* (the same mechanism used in section 20.4 to reimport a reconstructed header). By importing libsodium or OpenSSL headers into a `.gdt` archive, you enrich the type signatures that Ghidra will apply when it recognizes these functions.

The FID (code hash identification) + GDT (type application) combination is powerful: FID finds the name, GDT applies the complete signature with correct types.

### Function Tags

Function Tags allow categorizing identified functions. After recognizing a set of functions as belonging to glibc, you can assign them the tag `LIBRARY_GLIBC` for easy filtering in the Symbol Tree. Ghidra automatically applies the `LIBRARY_FUNCTION` tag to FID-identified functions, but you can create more granular custom tags.

In practice, you progressively build a taxonomy: `LIBRARY_GLIBC`, `LIBRARY_LIBCRYPTO`, `LIBRARY_STL`, `COMPILER_RUNTIME`, `USER_CODE`. This classification allows filtering the Symbol Tree to display only "interesting" functions — a considerable comfort when the binary contains 3000 functions of which 2500 are library code.

---

## Practical case: identifying glibc in a static binary

Let's take a concrete scenario. We compile our `keygenme.c` statically:

```bash
gcc -static -O2 -s -o keygenme_static keygenme.c
```

The resulting binary is about 900 KB and contains over 1100 functions in Ghidra, all named `FUN_XXXXXXXX`.

### Before Function ID

The initial analysis of `main` in Ghidra shows calls to unknown functions. The pseudo-code of `main` contains calls like:

```c
    FUN_00410230(local_88, 0x40, FUN_004112a0);  /* fgets? */
    sVar1 = FUN_00409c10(local_88);               /* strlen? */
    FUN_00410180("Username: ");                    /* printf? */
```

We can guess the semantics from the arguments (a 64-byte buffer, `stdin`, a format string), but without certainty.

### Applying Function ID

Activate the glibc FID databases: *Tools → Function ID → Manage FID Databases* → check the `libc_glibc` database corresponding to the x86-64 architecture. Then *Analysis → One Shot → Function ID*.

Within seconds, Ghidra identifies hundreds of functions. The pseudo-code of `main` transforms:

```c
    fgets(local_88, 0x40, stdin);
    sVar1 = strlen(local_88);
    printf("Username: ");
```

Called functions are now named, and — thanks to `.gdt` archives — their signatures (parameter and return types) are correctly applied. The entire pseudo-code of `main` gains readability at once.

### What remains unidentified

Function ID does not recognize everything. Glibc-internal functions (static functions, runtime initialization functions) and user code functions remain as `FUN_XXXXXXXX`. But the signal-to-noise ratio is radically improved: instead of 1100 unknown functions, we perhaps have 200, most of which are internal libc functions that can be ignored.

To identify user code in this mass, look for functions called from `main` that are not marked `LIBRARY_FUNCTION`. In our case, `derive_key`, `parse_key_input`, and `verify_key` are the three unidentified functions called from `main` — these are the ones containing the business logic.

---

## Recognizing crypto libraries without signatures

Signatures are the ideal approach when available. But when facing an unknown crypto library or a custom implementation, other clues must be used. This technique complements the signature approach and will be explored further in chapter 24.

### Magic constants

Each cryptographic algorithm uses characteristic constants that appear in plain text in the binary, in the `.rodata` section or directly as immediate values. Appendix J of this tutorial provides a complete reference table. Some of the most common examples:

**AES.** The AES S-box is a 256-byte array starting with `0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5`. Its presence in `.rodata` is near-certain proof of an AES implementation.

**SHA-256.** The 8 initialization values (IV) are `0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19`. The 64 round constants are also characteristic.

**MD5.** The round constants are derived from the sine function and start with `0xd76aa478, 0xe8c7b756, 0x242070db`.

**RC4.** No fixed constant, but the S-array initialization pattern (permutation of 0 to 255) is recognizable in disassembly.

### Searching in Ghidra

Searching for these constants in Ghidra is done via *Search → Memory* in hexadecimal mode. Searching for the sequence `63 7c 77 7b f2 6b 6f c5` locates the AES S-box. Once found, cross-references from that address lead directly to the encryption/decryption functions.

The `strings` command-line tool can also reveal indicative strings: `"AES-256-CBC"`, `"EVP_EncryptInit"`, `"mbedtls_aes_crypt_ecb"` — even in a stripped binary, these library-internal strings are not always removed.

### YARA rules

YARA rules (covered in chapter 6, section 10, and chapter 35, section 4) formalize the search for magic constants into reusable rules. The training's `yara-rules/crypto_constants.yar` directory contains ready-to-use rules for the most common algorithms. Applying these rules with `yara` on the command line (or from ImHex) on an unknown binary allows rapid identification even before opening Ghidra:

```bash
yara yara-rules/crypto_constants.yar keygenme_O2_strip
```

---

## Impact on the decompilation workflow

Identifying third-party libraries transforms the decompilation workflow in several ways.

### Reducing the analysis scope

On our `keygenme_static` with over 1100 functions, after applying Function ID, only about a dozen unidentified functions deserve detailed analysis. Analysis time drops from several days (if you tried to understand every function) to a few hours.

### Cascading pseudo-code improvement

When Ghidra renames `FUN_00409c10` to `strlen` and applies the signature `size_t strlen(const char *)`, the pseudo-code of **all calling functions** automatically improves. The parameter passed to `strlen` is now typed as `const char *`, which in turn can correct the type of the source local variable, which in turn can improve the pseudo-code of functions that initialize it. The cascading effect is significant.

### Identifying the technical ecosystem

Knowing that a binary embeds mbedTLS rather than OpenSSL, or libcurl rather than a custom HTTP implementation, immediately orients the analysis. You can consult the documentation of the identified library to understand the expected call patterns, data structures used, and common configuration errors. Decompilation becomes an audit of the use of a known API rather than an exercise in understanding opaque code.

### Building a personal signature database

Over the course of analyses, the analyst progressively builds their own collection of `.fidb` databases for frequently encountered libraries. This collection becomes a reusable asset: each new binary analyzed automatically benefits from identifications made during previous analyses. Chapter 35 (section 6 — Building Your Own RE Toolkit) covers the organization of this collection.

---


⏭️ [Exporting and cleaning pseudo-code to produce recompilable code](/20-decompilation/06-exporting-pseudocode.md)
