🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 24.2 — Identifying Embedded Crypto Libraries (OpenSSL, libsodium, custom)

> 🎯 **Objective of this section**: determine whether the crypto routines detected in 24.1 come from a known library or a homegrown implementation, and understand why this distinction fundamentally changes the analysis strategy.

---

## Why this question is crucial

The previous section taught us how to identify *which algorithm* a binary uses. But knowing that a binary performs AES-256 is not enough to reverse it effectively. You also need to know *how* that AES is implemented, because this determines the entire course of the analysis.

**If the binary uses OpenSSL**, the API is publicly documented. We know the function signatures, the parameter order, the internal data structures (`EVP_CIPHER_CTX`, `EVP_MD_CTX`...). We can read OpenSSL's source code to understand exactly what each function does, set relevant breakpoints, and even use FLIRT/Ghidra signatures to automatically rename hundreds of functions in a stripped binary. RE becomes an exercise in recognizing known patterns.

**If the binary uses a custom implementation**, none of this applies. The structures are unknown, the functions don't match any signature, and the logic must be reconstructed manually. Analysis time goes from a few hours to potentially several days.

The distinction between these two cases is therefore an efficiency multiplier. Spending 15 minutes identifying the library can save dozens later on.

---

## Case 1: Dynamic linking — the easy case

When a binary is dynamically linked to a crypto library, identification is nearly immediate.

### `ldd` — list dependencies

```bash
$ ldd crypto_O0
    linux-vdso.so.1 (0x00007ffd...)
    libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3 (0x00007f...)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
    /lib64/ld-linux-x86-64.so.2 (0x00007f...)
```

The presence of `libcrypto.so` (OpenSSL), `libsodium.so`, `libgcrypt.so`, `libmbedcrypto.so`, or `libwolfssl.so` is an instant diagnosis. Here are the most common libraries and their `.so` files:

| Library | Typical `.so` file | Additional clues |  
|---|---|---|  
| OpenSSL | `libcrypto.so`, `libssl.so` | Functions `EVP_*`, `SHA*`, `AES_*`, `RSA_*` |  
| LibreSSL | `libcrypto.so` (OpenSSL fork) | API nearly identical to OpenSSL |  
| libsodium (NaCl) | `libsodium.so` | Functions `crypto_secretbox_*`, `crypto_box_*` |  
| libgcrypt (GnuPG) | `libgcrypt.so` | Functions `gcry_cipher_*`, `gcry_md_*` |  
| mbedTLS (ARM) | `libmbedcrypto.so`, `libmbedtls.so` | Functions `mbedtls_aes_*`, `mbedtls_sha256_*` |  
| wolfSSL | `libwolfssl.so` | Functions `wc_AesSetKey`, `wc_Sha256*` |  
| Botan | `libbotan-*.so` | C++ namespace `Botan::` |  
| Nettle (GnuTLS) | `libnettle.so`, `libhogweed.so` | Functions `nettle_aes*`, `nettle_sha256*` |

### `nm -D` — dynamic symbols

Even on a stripped binary, **dynamic symbols** (those imported from `.so` files) remain visible — they are needed by the dynamic linker to resolve addresses at load time:

```bash
$ nm -D crypto_O2_strip | grep -i evp
                 U EVP_aes_256_cbc
                 U EVP_CIPHER_CTX_free
                 U EVP_CIPHER_CTX_new
                 U EVP_EncryptFinal_ex
                 U EVP_EncryptInit_ex
                 U EVP_EncryptUpdate
```

The `U` means "undefined" — the symbol is imported from an external library. This is a goldmine: we know not only the library but the exact functions being called. For OpenSSL, these function names allow you to go directly to the `EVP` API documentation and understand the encryption flow without even opening the disassembler.

### `readelf --dynamic` — robust alternative

If `ldd` refuses to work (binary for a different architecture, or caution against execution), `readelf` provides the same information without executing the binary:

```bash
$ readelf --dynamic crypto_O2_strip | grep NEEDED
 0x0000000000000001 (NEEDED)  Shared library: [libcrypto.so.3]
 0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]
```

### `objdump -T` — dynamic symbol table with demangling

For C++ binaries that use a C++ crypto library (Botan, Crypto++), symbols are mangled. `objdump -TC` (with demangling) is more readable than `nm`:

```bash
$ objdump -TC binary_cpp | grep -i cipher
0000000000000000      DF *UND*  ... Botan::Cipher_Mode::create(...)
```

---

## Case 2: Static linking — the main challenge

When a binary is statically linked (`-static`), all library functions are copied into the binary. `ldd` shows nothing (or indicates "not a dynamic executable"), and if the binary is also stripped, function names disappear. This is the most common case in realistic RE: malware, firmware, IoT binaries, Go and Rust applications embedding their dependencies.

### Step 1: Confirm static linking

```bash
$ file crypto_static
crypto_static: ELF 64-bit LSB executable, x86-64, ...  
statically linked, ...  

$ ldd crypto_static
    not a dynamic executable
```

### Step 2: Targeted `strings` — the library's internal strings

Crypto libraries contain internal strings (error messages, algorithm names, version information) that survive stripping because they reside in `.rodata`, not in the symbol table.

**OpenSSL** is particularly verbose:

```bash
$ strings crypto_static | grep -i openssl
OpenSSL 3.0.2 15 Mar 2022
...

$ strings crypto_static | grep -i "aes-"
aes-128-cbc  
aes-128-ecb  
aes-256-cbc  
aes-256-gcm  
...
```

OpenSSL embeds an internal table of all supported algorithms, with their names in ASCII. Even in a stripped and statically linked binary, this table remains accessible.

Here are the typical `strings` fingerprints per library:

**OpenSSL / LibreSSL**:
```
OpenSSL X.Y.Z ...  
EVP_CipherInit_ex  
aes-256-cbc  
SHA256  
PKCS7 padding  
```

**libsodium**:
```
libsodium  
sodium_init  
crypto_secretbox_xsalsa20poly1305  
```

**mbedTLS**:
```
MBEDTLS_ERR_AES_INVALID_KEY_LENGTH  
mbedtls_aes_crypt_cbc  
```

**wolfSSL**:
```
wolfSSL  
wolfCrypt  
wc_AesSetKey failed  
```

**Absence of identifiable strings** → likely a custom implementation. This is the signal to switch to structural analysis (see below).

### Step 3: FLIRT / Ghidra signatures — automatically rename functions

This is the most powerful technique for dealing with a stripped static binary. The idea is as follows: functions from a library compiled with the same options (version, compiler, architecture) always produce the same byte sequences at the beginning of each function. By creating a signature database from the compiled library, you can then scan an unknown binary and reassociate each function with its original name.

#### FLIRT (Fast Library Identification and Recognition Technology) — IDA

FLIRT is the historic signature format, developed by Hex-Rays for IDA. The process is as follows:

1. Compile the target library under the same conditions as the analyzed binary (same version, same architecture, same compiler).  
2. Extract signatures with `pelf` (for static `.a` files) or `sigmake` to produce a `.sig` file.  
3. Apply the `.sig` file in IDA: recognized functions are automatically renamed.

Pre-generated FLIRT signature collections exist for common versions of OpenSSL, glibc, libcrypto, etc. The community maintains them on GitHub (for example the `sig-database` project).

#### Function ID (FID) — Ghidra

Ghidra has its own signature system, called **Function ID** (FID). It works on the same principle but with a different format:

1. In Ghidra, open **Analysis → One Shot → Function ID** or enable the FID analyzer during import.  
2. Ghidra compares the binary's functions against its built-in FID database.  
3. Matched functions are renamed in the Symbol Tree.

Ghidra ships with FID databases for standard libraries (glibc, libstdc++...). For OpenSSL or other specific libraries, you need to create your own FID databases. The process:

1. Compile `libcrypto.a` in the targeted version.  
2. Import the `.a` into a dedicated Ghidra project, let the analysis run.  
3. Use **Tools → Function ID → Create new empty FidDb**, then **Populate FidDb from programs** to generate the database.  
4. Apply this database to the target binary.

This is an upfront investment, but on a real case (malware statically linked to OpenSSL 1.1.1), this technique can rename hundreds of functions at once and transform an opaque disassembly into something navigable.

#### Radare2 Signatures

Radare2 has its own mechanism via the `zg` command (signature generation) and `z/` (application). The `r2-zignatures` framework allows importing FLIRT signatures or creating native Radare2 signatures:

```bash
# Apply a signature file to the loaded binary
[0x00401000]> zo openssl_3.0.2_x64.z
[0x00401000]> z/
# => recognized functions renamed
```

### Step 4: Structural heuristics — when signatures don't match

Signatures only work if the version, compiler, and compilation options match closely enough. If the match is partial or nonexistent, you can still identify the library through structural characteristics.

**Size and number of crypto functions**: a complete OpenSSL implementation linked statically adds thousands of functions to the binary. If `afl` (list functions) in Radare2 or the Function List in Ghidra shows 3000+ functions in a binary that should be simple, it's a strong indicator of an embedded library.

**Call graph around constants**: starting from the constants identified in 24.1 (AES S-box, SHA-256 IV), trace back the XREFs in Ghidra. If the function accessing the S-box is called by a cascade of intermediate functions with a regular structure (round functions, key schedule, EVP wrapper...), this is the sign of a well-architected library, not a minimal copy-paste.

**Internal data structures**: OpenSSL uses structures like `EVP_CIPHER_CTX` (several hundred bytes) with function pointers (algorithm dispatch). If the Ghidra decompiler shows accesses to a large structure with indirect calls via structure fields, this is a classic pattern of a dispatch-based crypto API.

---

## Case 3: Custom implementation — the warning signs

When no known library is identified, you're facing one of these scenarios:

**Custom implementation of a standard algorithm** — The developer coded (or copied) their own version of AES, SHA-256, etc. The magic constants are present (detected in 24.1) but the code organization doesn't match any known library. This is common in the embedded world, malware, and projects that want to avoid an external dependency.

**Entirely custom algorithm** — The developer invented their own scheme. No standard constants, no recognizable pattern. This is the most difficult case and, paradoxically, often the least cryptographically robust — homegrown crypto is rarely solid.

### How to recognize them

Several clues converge toward a custom implementation:

- No internal strings from a known library in `strings`.  
- Standard crypto constants are present but isolated (not surrounded by the hundreds of functions of a real library).  
- The call graph around the constants is short: 2-3 functions, not a deep hierarchy.  
- The crypto functions are small and compact (a few dozen lines in the decompiler) rather than the optimized and voluminous implementations of libraries.  
- The code mixes business logic and crypto in the same function, instead of the clean layered separation of an API like EVP.

### Analysis strategy

When facing custom code, the approach changes:

1. **If standard constants are present**: we know which algorithm is implemented. We can compare the decompiled code with a reference implementation (for example, the NIST AES reference implementation or the SHA-256 RFC) to verify there are no variants or errors. In particular, we check the key schedule, the number of rounds, and the mode of operation.

2. **If no standard constants are found**: the code must be analyzed structurally. We look for fixed-counter loops (round indicator), massive XOR operations (substitution, mixing), bit rotations, accesses to arrays of characteristic size (256 = substitution, 16 = block size...). Dynamic analysis with Frida (section 24.3) then becomes indispensable for observing data in transit.

---

## Application to our binaries

### `crypto_O0` (dynamic, not stripped)

This is the textbook case of instant diagnosis:

```bash
$ ldd crypto_O0 | grep crypto
    libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3

$ nm -D crypto_O0 | grep -c "EVP\|SHA\|AES\|RAND"
8
```

Verdict in 10 seconds: OpenSSL, EVP API, AES-256-CBC, SHA-256, RAND_bytes.

### `crypto_O2_strip` (dynamic, stripped)

Local symbols are gone, but dynamic symbols are intact:

```bash
$ nm crypto_O2_strip
nm: crypto_O2_strip: no symbols

$ nm -D crypto_O2_strip | grep EVP
                 U EVP_aes_256_cbc
                 U EVP_CIPHER_CTX_free
                 ...
```

Same verdict. Stripping does not hide dynamic imports.

### `crypto_static` (static, not stripped)

No more `ldd`, but `strings` and constants do the job:

```bash
$ ldd crypto_static
    not a dynamic executable

$ strings crypto_static | grep -c -i openssl
12

$ strings crypto_static | grep "aes-256"
aes-256-cbc  
aes-256-cfb  
...
```

OpenSSL's internal strings give away the library. If we had also stripped the binary, these strings would still be there.

### Hypothetical case: `crypto_static` stripped + `strings` cleaned

If an adversary took the trouble to also remove the internal strings (which is rare but possible), the following would remain:

1. The magic constants (identified in 24.1): they prove AES + SHA-256.  
2. The binary size: a 2+ MB binary for a simple program suggests a large embedded library.  
3. FLIRT/FID signatures: if we have the right compiled version of OpenSSL.  
4. Structural analysis of the call graph: the depth and regularity of the EVP architecture.

Even in this extreme case, identification remains possible with reasonable effort.

---

## Summary table: decision tree

```
Is the binary dynamically linked to a crypto .so?
├── YES → ldd + nm -D → immediate identification
│         → Read the API docs, set breakpoints on known functions
│
└── NO (static or no crypto .so)
    │
    ├── strings reveals internal strings from a known library?
    │   ├── YES → Library identified
    │   │         → Create/apply FLIRT/FID signatures to rename functions
    │   │
    │   └── NO
    │       │
    │       ├── Standard crypto constants found (section 24.1)?
    │       │   ├── YES → Standard algorithm, custom implementation or micro-library
    │       │   │         → Compare the decompiled output with the reference implementation
    │       │   │
    │       │   └── NO → Entirely custom crypto
    │       │             → Structural + dynamic analysis mandatory
    │       │
    │       └── FLIRT/FID signatures match?
    │           ├── YES → Library identified despite absence of strings
    │           └── NO → Confirm custom, analyze manually
```

---

## Summary

| Technique | Works on | Effort | What it reveals |  
|---|---|---|---|  
| `ldd` | Dynamic binary | None | Name of the `.so` |  
| `nm -D` | Dynamic binary (even stripped) | None | Exact imported functions |  
| `readelf --dynamic` | Dynamic binary, without execution | None | Dependencies without risk |  
| Targeted `strings` | Static or dynamic | Low | Library via its internal strings |  
| FLIRT signatures | Stripped static (IDA) | Medium | Mass function renaming |  
| Function ID (FID) | Stripped static (Ghidra) | Medium | Mass function renaming |  
| Structural analysis | Any binary | High | Custom vs library, code architecture |

Identifying the crypto library is a modest time investment that guides the entire rest of the analysis. Once this step is completed, you know exactly which functions to target for extracting secrets — which is precisely the subject of the next section.

---


⏭️ [Extracting Keys and IVs from Memory with GDB/Frida](/24-crypto/03-extracting-keys-iv.md)
