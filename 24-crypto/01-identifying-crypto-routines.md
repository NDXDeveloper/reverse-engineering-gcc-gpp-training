🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 24.1 — Identifying Crypto Routines (Magic Constants: AES S-box, SHA256 IV…)

> 🎯 **Objective of this section**: when facing an unknown binary, be able to quickly determine which cryptographic algorithms it uses — even if it is stripped, optimized, and does not link against any identifiable dynamic library.

---

## The problem: how a binary "hides" its crypto

When a developer uses cryptography in their program, they can do it in several ways, from the most visible to the most discreet:

**Favorable case** — The binary is dynamically linked to a known crypto library (`libcrypto.so` from OpenSSL, `libsodium.so`, `libgcrypt.so`…). A simple `ldd` or `nm` reveals the functions used. We will cover this case in detail in section 24.2.

**Intermediate case** — The binary is statically linked. The crypto functions are embedded in the binary itself. Symbols may be present (if not stripped) or absent. No more `ldd` to help us.

**Unfavorable case** — The developer integrated their own implementation of a standard algorithm (copy-pasted from GitHub, homemade implementation…), or uses an entirely custom crypto algorithm. The binary is stripped. No function names, no library names give anything away.

In the last two cases, there is an extremely reliable lever: **mathematical constants**. Each cryptographic algorithm relies on specific numerical values, defined by the standard or the original research paper. These constants are unique fingerprints: a developer can rename their functions, obfuscate their control flow, compile with `-O3 -s` — but they cannot modify the AES constants without breaking the algorithm.

---

## Crypto magic constants: catalog of the most common ones

### AES (Rijndael)

AES uses a 256-byte **S-box** (Substitution box) that performs a non-linear substitution during each round. This table is absolutely characteristic:

```
63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0  
B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15  
...
```

The first 4 bytes `63 7C 77 7B` are the most sought-after signature in crypto RE. You will also find the **inverse S-box** (used for decryption), which starts with `52 09 6A D5`, as well as the **pre-computed Rijndael tables** (`Te0`, `Te1`, `Te2`, `Te3` for optimized T-table implementations), which are arrays of 256 32-bit words each. These T-tables are even larger (4 × 1024 bytes) and therefore even easier to spot in the binary.

**Where to find them**: `.rodata` section (read-only constant data), sometimes `.data` if the implementation declares them as mutable, or directly inlined in `.text` for bitsliced implementations.

### SHA-256

SHA-256 uses two sets of constants:

**Initialization vectors (H0–H7)** — 8 32-bit words derived from the square roots of the first 8 prime numbers:

```
6A09E667  BB67AE85  3C6EF372  A54FF53A
510E527F  9B05688C  1F83D9AB  5BE0CD19
```

**Round constants (K0–K63)** — 64 32-bit words derived from the cube roots of the first 64 prime numbers:

```
428A2F98  71374491  B5C0FBCF  E9B5DBA5
3956C25B  59F111F1  923F82A4  AB1C5ED5
...
```

The first word `0x428A2F98` is the classic SHA-256 signature in RE. The presence of these 64 32-bit constants in `.rodata` is a near-certain signal.

**Variants**: SHA-224 shares the same round constants but different IVs (`C1059ED8…`). SHA-512 and SHA-384 use 64-bit constants (`0x6A09E667F3BCC908…` for SHA-512).

### MD5

MD5 uses 64 32-bit constants derived from the sine function, the first of which are:

```
D76AA478  E8C7B756  242070DB  C1BDCEEE  
F57C0FAF  4787C62A  A8304613  FD469501  
...
```

The word `0xD76AA478` is the typical signature. In practice, MD5 is used less and less for encryption but remains common for hashing (integrity verification, fingerprints).

### SHA-1

SHA-1 uses 4 round constants:

```
5A827999  6ED9EBA1  8F1BBCDC  CA62C1D6
```

And IVs (`67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0`) that are partially shared with MD5 — beware of false positives if you search only for the IVs.

### ChaCha20 / Salsa20

ChaCha20 uses a 16-byte constant in ASCII: `"expand 32-byte k"` (for 256-bit keys) or `"expand 16-byte k"` (128 bits). This string is directly detectable with `strings`. It is one of the rare crypto algorithms where a simple text search is sufficient.

### RC4

RC4 does not use characteristic static constants (its S-box is dynamically initialized from the key). However, the KSA (Key Scheduling Algorithm) has a recognizable pattern in the disassembly: an initialization loop of 256 iterations that fills an array from 0 to 255, followed by a permutation loop. This is a case where the structural pattern replaces the magic constant.

### DES / 3DES

DES uses several permutation and substitution tables. The most identifiable are the **8 S-boxes** of 64 bytes each, the first of which starts with:

```
0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07
```

You will also find the initial permutation (IP) and final permutation (FP) tables. DES is considered obsolete but remains present in legacy code.

### Blowfish

Blowfish is initialized with the decimals of pi encoded in hexadecimal. The first values of the P-array are:

```
243F6A88  85A308D3  13198A2E  03707344
A4093822  299F31D0  082EFA98  EC4E6C89
```

The word `0x243F6A88` is a reliable signature (these are the fractional bits of pi).

### RSA

RSA does not have fixed magic constants like symmetric algorithms. However, RSA can be identified by the presence of large integer manipulation functions (big number / bignum) and by the ASN.1/DER structures of keys. The OID `1.2.840.113549.1.1.1` (encoded `06 09 2A 86 48 86 F7 0D 01 01 01`) is the signature of an RSA key in PKCS format.

---

## Method 1: `strings` — the wide-mesh net

The first thing to do when facing a binary suspected of performing crypto is to run `strings` with a smart filter. We are not looking for raw constants here (they are binary, not ASCII), but for textual clues:

```bash
$ strings crypto_O2_strip | grep -iE 'aes|sha|md5|crypt|cipher|key|iv|salt|hmac|pbkdf|hash|encrypt|decrypt|openssl|libcrypto|gcrypt|sodium'
```

On our `crypto_O0` binary (not stripped, dynamically linked), this command immediately reveals the OpenSSL function names since the dynamic symbols are visible. But on `crypto_O2_strip`, it is more discreet: you can still find strings like internal OpenSSL error messages, algorithm names embedded in the library, or in our case the `CRYPT24` magic of the file format.

For algorithms statically embedded or custom implementations, `strings` is generally not enough. You need to move on to raw bytes.

## Method 2: binary `grep` on known constants

You can search directly for the first bytes of a known constant in the binary. The `grep` command with the `-c` (count) option on a hex dump is a quick approach:

```bash
# Search for the AES S-box (first bytes)
$ xxd crypto_O2_strip | grep "637c 777b"

# Search for the first SHA-256 IV (little-endian on x86: 67 E6 09 6A)
$ xxd crypto_O2_strip | grep "67e6 096a"
```

> ⚠️ **Beware of endianness.** The constants are documented in big-endian in the specifications, but on x86-64 they are stored in little-endian in memory. The first SHA-256 IV is `0x6A09E667` in the spec, but appears as `67 E6 09 6A` in the binary. This is a classic trap that wastes time.

For a more systematic search, you can use a small Python script:

```python
#!/usr/bin/env python3
"""Quick scan for well-known crypto constants in a binary."""

import sys

SIGNATURES = {
    "AES S-box": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
    "AES Inv S-box": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38]),
    "SHA-256 IV (LE)": bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa5"),
    "SHA-256 K[0] (LE)": bytes.fromhex("982f8a4228e9f04b"),
    "MD5 T[0] (LE)": bytes.fromhex("78a46ad7"),
    "Blowfish P (LE)": bytes.fromhex("886a3f24"),
    "ChaCha20 sigma": b"expand 32-byte k",
    "DES S-box 1": bytes([0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08]),
}

def scan(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    for name, sig in SIGNATURES.items():
        offset = data.find(sig)
        if offset != -1:
            print(f"  [+] {name:25s} found at offset 0x{offset:08X}")
        else:
            print(f"  [ ] {name:25s} not found")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    print(f"Scanning {sys.argv[1]}...")
    scan(sys.argv[1])
```

When running it on our dynamically linked binary (`crypto_O0`), the AES and SHA-256 constants will **not** be found in the binary itself — they reside in `libcrypto.so`. However, on `crypto_static` (statically linked), they will appear clearly.

## Method 3: `binwalk` — entropy analysis and signatures

`binwalk` is known for firmware analysis, but its signature engine and entropy analysis are very useful for crypto detection:

```bash
# Search for known crypto signatures
$ binwalk -R crypto_static

# Entropy analysis: encrypted data has entropy close to 1.0
$ binwalk -E secret.enc
```

The entropy analysis on `secret.enc` will show a characteristic profile: a low-entropy header (magic, version, structured IV) followed by a very high-entropy block (the encrypted data). This "staircase" profile is a classic indicator of a file containing encrypted or compressed data.

On the binary itself, a high-entropy zone in the `.rodata` or `.data` section can betray substitution tables or embedded encrypted data.

## Method 4: Ghidra — searching for constants in the disassembly

Ghidra is the most powerful tool for this task because it not only finds the constants but also traces back to the functions that use them via cross-references.

### Byte search (Scalar Search)

In the CodeBrowser, the **Search → For Scalars** command allows you to search for a numerical value throughout the entire binary. To find the SHA-256 constants:

1. Open **Search → For Scalars**  
2. Enter `0x6A09E667` (first SHA-256 IV)  
3. Ghidra lists all occurrences — in instructions (`mov`, constant loading) and in data

Each result is clickable. A double-click positions you in the listing, and from there, the XREFs (cross-references) show which functions access this constant.

### Raw byte search (Memory Search)

To search for a byte sequence (like the AES S-box):

1. **Search → Memory** (or `S`)  
2. Select **Hex** as the format  
3. Enter the first bytes: `63 7C 77 7B F2 6B 6F C5`  
4. Ghidra indicates the exact address in the data section

Once the S-box is located, right-click → **References → Find References to** to see which functions access it. These functions are, by definition, AES functions (or at the very least, functions that manipulate the AES S-box).

### Structural analysis

Beyond isolated constants, Ghidra allows you to recognize the *structure* of a crypto algorithm in the decompiler. For example, a typical AES implementation compiled with GCC presents a recognizable pattern: a loop of 10 rounds (AES-128), 12 rounds (AES-192), or 14 rounds (AES-256), each round involving indexed accesses to substitution tables, XORs with round subkeys, and mixing operations (ShiftRows, MixColumns). Even without function names, this structure is characteristic.

The decompiler will typically display something resembling indexed accesses into a large array (`sbox[state[i]]`), rotations (`>> 8`, `<< 24`), and cascading XORs — all within a counted loop. This pattern is a strong signal even when constants are scattered or accessed indirectly.

## Method 5: YARA rules — automated detection

YARA is the reference tool for pattern detection in binary files. Writing (or using) YARA rules that target crypto constants allows automating identification across large collections of binaries.

Here is an example rule for detecting AES:

```yara
rule AES_SBox
{
    meta:
        description = "Detects AES S-box (Rijndael forward substitution table)"
        author      = "RE Training"

    strings:
        $sbox = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
        }

    condition:
        $sbox
}

rule SHA256_Constants
{
    meta:
        description = "Detects SHA-256 round constants (first 8 values)"

    strings:
        // Big-endian (documentation order)
        $k_be = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
        // Little-endian (x86/x64 in-memory order)
        $k_le = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9 }

    condition:
        $k_be or $k_le
}
```

Run it with:

```bash
$ yara crypto_rules.yar crypto_static
AES_SBox crypto_static  
SHA256_Constants crypto_static  
```

The `yara-rules/crypto_constants.yar` repository provided with the training contains a complete set of rules covering the most common algorithms. The community also maintains collections of crypto YARA rules, notably in the **Yara-Rules** project on GitHub.

> 💡 **ImHex integrates a YARA engine** (cf. section 6.10). You can apply these same rules directly from ImHex during hexadecimal inspection of the binary, which allows you to immediately visualize the context around each match.

## Application on our `crypto_O0` binary

Let's put this into practice on the chapter's binary. Let's start with the classic triage:

```bash
$ file crypto_O0
crypto_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, with debug_info, not stripped  
```

The binary is dynamically linked and not stripped: this is the favorable case. A quick `nm` confirms the presence of OpenSSL symbols:

```bash
$ nm -D crypto_O0 | grep -i -E 'sha|aes|evp|rand'
                 U EVP_aes_256_cbc
                 U EVP_CIPHER_block_size
                 U EVP_CIPHER_CTX_free
                 U EVP_CIPHER_CTX_new
                 U EVP_EncryptFinal_ex
                 U EVP_EncryptInit_ex
                 U EVP_EncryptUpdate
                 U RAND_bytes
                 U SHA256
```

We already know a lot: AES-256-CBC, SHA-256, random generation with `RAND_bytes`. The AES and SHA-256 constants are not in the binary itself but in `libcrypto.so` (since it is dynamically linked).

Let's switch to `crypto_static` for a more realistic exercise:

```bash
$ file crypto_static
crypto_static: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),  
statically linked, BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped  
```

Statically linked. Even though the symbols are present here (not stripped), let's imagine we ignore them. Let's run our scan script:

```
Scanning crypto_static...
  [+] AES S-box                found at offset 0x001A3F40
  [+] AES Inv S-box            found at offset 0x001A4040
  [+] SHA-256 IV (LE)          found at offset 0x0019B260
  [+] SHA-256 K[0] (LE)        found at offset 0x0019B280
  [ ] MD5 T[0] (LE)            not found
  [ ] Blowfish P (LE)          not found
  [ ] ChaCha20 sigma           not found
  [ ] DES S-box 1              not found
```

Clear result: AES and SHA-256 confirmed, no other algorithm detected. We can now open the binary in Ghidra, navigate to offset `0x001A3F40`, and follow the XREFs to find the functions that use the S-box — these will be the AES encryption functions.

## What we find vs. what we don't

It is important to keep in mind the limitations of constant-based detection:

**What this method detects well**: all standard algorithms that rely on pre-computed tables or constants — AES, SHA-*, MD5, DES, Blowfish, Whirlpool, and many others. This covers the vast majority of cases.

**What this method detects poorly**: algorithms that do not use characteristic static constants, such as RC4 (dynamic table), certain stream ciphers (simple XOR, Vernam), or entirely custom constructions based on arithmetic operations without tables. For these cases, you need to analyze the *structure* of the code (loop patterns, recurring arithmetic operations, size of manipulated blocks) rather than searching for constants.

**Common pitfall**: implementations that compute the tables on the fly instead of storing them statically. Some AES implementations generate the S-box at runtime from the generator polynomial in GF(2⁸). In this case, the S-box does not exist in the static binary — it only appears in memory once the program is running. This is a case where dynamic analysis (section 24.3) takes over.

---

## Summary

At this point, you have an arsenal of techniques to answer the first fundamental question: *which algorithm is being used?*

| Method | Effort | Reliability | Use case |  
|---|---|---|---|  
| `strings` + `grep` | Minimal | Low (indicative) | Quick first filter, ASCII strings |  
| `xxd` + hex `grep` | Low | Medium | Targeted search for a known constant |  
| Python scan script | Low | Good | Systematic multi-algorithm scan |  
| `binwalk` entropy | Low | Medium | Detect the *presence* of crypto, not the algorithm |  
| Ghidra Scalar Search | Medium | Excellent | Identification + XREF tracing |  
| YARA rules | Low (if rules ready) | Excellent | Batch detection, automation |

The next section tackles a complementary problem: once the constants are identified, how to determine whether they come from a known library (OpenSSL, libsodium…) or from a homemade implementation — and why this distinction radically changes the RE strategy.

---


⏭️ [Identifying embedded crypto libraries (OpenSSL, libsodium, custom)](/24-crypto/02-identifying-crypto-libs.md)
