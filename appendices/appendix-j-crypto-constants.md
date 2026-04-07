🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix J — Common Crypto Magic Constants (AES, SHA, MD5, RC4…)

> 📎 **Reference sheet** — This appendix gathers the characteristic hexadecimal values of the most widespread cryptographic algorithms. When you encounter a suspicious byte sequence in `.rodata`, `.data`, or in a memory dump, this table allows you to quickly identify it. It is particularly useful in the context of Chapters 24 (reversing a binary with encryption) and 27 (ransomware analysis).

---

## Why search for crypto constants?

The vast majority of cryptographic algorithms rely on **predefined mathematical constants**: substitution tables (S-boxes), initialization vectors (IV), round constants, and initial hash values. These constants are fixed by the algorithm specifications and are identical across all conforming implementations, whether they come from OpenSSL, libsodium, mbedTLS, or a custom implementation.

This property makes them **reliable fingerprints**: if you find the first 16 bytes of the AES S-box in a binary, you know with near certainty that the binary uses AES. It doesn't matter whether the code is obfuscated, stripped, or compiled with `-O3` — the constants don't change.

The typical workflow is as follows: you search for the constants from this appendix in the binary (using `strings`, ImHex, YARA, or a Python script), then you locate the code that references them via cross-references (xrefs). That code is the crypto routine, and from there you can trace back to the keys, IVs, and processed data.

### Search methods

Several tools allow you to search for these constants in a binary:

| Method | Command / Tool | Context |  
|--------|----------------|---------|  
| ImHex | `Edit → Find → Hex Pattern` | Visual search in the hex view |  
| Radare2 | `/x 637c777b` | Byte search in the file |  
| YARA | Rule with condition `{ 63 7C 77 7B ... }` | Automated scan of files/directories |  
| Python | `data.find(b'\x63\x7c\x77\x7b')` | Triage script |  
| GDB | `find 0x400000, 0x500000, 0x637c777b` | Memory search (runtime) |  
| `grep -c` | `xxd binary \| grep "637c 777b"` | Quick shell search |  
| Ghidra | `Search → Memory → Hex` | Search in static analysis |

> ⚠️ **Endianness**: the constants are listed in this appendix in the order they appear in memory (byte by byte). On x86-64 (little-endian), multi-byte values read as `uint32_t` appear in reversed order in registers. For example, the first 4 bytes of the AES S-box (`63 7C 77 7B`) will be read as the dword `0x7B777C63` by a `mov eax, [addr]`. Keep this in mind when searching for constants in the disassembly rather than in the hex view.

---

## 1 — AES (Advanced Encryption Standard / Rijndael)

AES is the most widely used symmetric encryption algorithm in the world. Its constants are the most frequently searched for in binary RE.

### 1.1 — S-box (substitution table)

The AES S-box is a 256-byte array used in the SubBytes operation of each encryption round. It is the most recognizable AES constant.

**First bytes (detection signature)**:

```
63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0  
B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15  
```

The first 4 bytes (`63 7C 77 7B`) are the minimum signature sufficient to identify AES with very high confidence. If you're looking for a shorter pattern, `63 7C 77 7B F2 6B 6F C5` (8 bytes) virtually eliminates any risk of false positive.

### 1.2 — Inverse S-box

The inverse S-box is used for decryption (InvSubBytes operation). Its presence in a binary indicates that it implements AES decryption (and not just encryption).

**First bytes**:

```
52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB
```

### 1.3 — Rcon (Round Constants)

The round constants are used in key expansion (*key schedule*). It is a small array (10–14 entries depending on key size):

```
01 00 00 00
02 00 00 00
04 00 00 00
08 00 00 00
10 00 00 00
20 00 00 00
40 00 00 00
80 00 00 00
1B 00 00 00
36 00 00 00
```

In little-endian dword format: `0x00000001`, `0x00000002`, `0x00000004`, ..., `0x0000001B`, `0x00000036`.

### 1.4 — Precomputed T-tables

Optimized AES implementations (known as *T-table implementation*) precompute four tables of 256 dwords each (T0, T1, T2, T3) that combine SubBytes, ShiftRows, and MixColumns into a single lookup. Each table is 1024 bytes.

**First dwords of T0** (little-endian):

```
C66363A5 F87C7C84 EE777799 F67B7B8D  
FFF2F20D D66B6BBD DE6F6FB1 91C5C554  
```

The presence of four consecutive 1 KB tables (total: 4 KB) in `.rodata` is a strong indicator of a T-table AES implementation.

### 1.5 — AES-NI (hardware instructions)

On modern processors, AES can be implemented via the AES-NI hardware instructions. In this case, **no S-box or T-table appears in the binary** — the constants are embedded in the processor's microcode. The instructions to look for are:

| Instruction | Description |  
|-------------|-------------|  
| `aesenc` | One round of AES encryption |  
| `aesenclast` | Last round of encryption |  
| `aesdec` | One round of AES decryption |  
| `aesdeclast` | Last round of decryption |  
| `aeskeygenassist` | Key expansion |  
| `aesimc` | Key conversion for decryption |

If you see these instructions in the disassembly, the binary uses hardware AES. The round keys will be in XMM registers and not in memory tables, which makes key extraction more complex (you need to capture them dynamically with GDB or Frida).

---

## 2 — SHA-256

SHA-256 is the most widely used hash function in the SHA-2 family.

### 2.1 — Initial values (H0–H7)

These are the 8 32-bit values that initialize the hash state. They correspond to the fractional parts of the square roots of the first 8 prime numbers.

```
6A09E667 BB67AE85 3C6EF372 A54FF53A
510E527F 9B05688C 1F83D9AB 5BE0CD19
```

In little-endian memory (bytes):

```
67 E6 09 6A  85 AE 67 BB  72 F3 6E 3C  3A F5 4F A5
7F 52 0E 51  8C 68 05 9B  AB D9 83 1F  19 CD E0 5B
```

### 2.2 — Round constants (K0–K63)

SHA-256 uses 64 32-bit constants (fractional parts of the cube roots of the first 64 prime numbers). These 256 bytes (64 × 4) are a very reliable signature.

**First dwords**:

```
428A2F98 71374491 B5C0FBCF E9B5DBA5
3956C25B 59F111F1 923F82A4 AB1C5ED5
D807AA98 12835B01 243185BE 550C7DC3
72BE5D74 80DEB1FE 9BDC06A7 C19BF174
```

The sequence `428A2F98 71374491 B5C0FBCF E9B5DBA5` is the recommended minimum signature. In little-endian memory: `98 2F 8A 42  91 44 37 71  CF FB C0 B5  A5 DB B5 E9`.

---

## 3 — SHA-1

SHA-1 is obsolete for security but still widely present in existing code (Git, legacy certificates, non-security integrity verification).

### 3.1 — Initial values (H0–H4)

```
67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0
```

In little-endian memory:

```
01 23 45 67  89 AB CD EF  FE DC BA 98  76 54 32 10  F0 E1 D2 C3
```

> 💡 The first 4 values (`67452301 EFCDAB89 98BADCFE 10325476`) are **shared with MD5**. Only the 5th value (`C3D2E1F0`) distinguishes SHA-1 from MD5. If you find the first 4 without the 5th, it is probably MD5. If all 5 are present, it is SHA-1.

### 3.2 — Round constants

SHA-1 uses 4 32-bit constants, each used for 20 rounds:

| Rounds | Constant | Hexadecimal LE |  
|--------|----------|----------------|  
| 0–19 | `5A827999` | `99 79 82 5A` |  
| 20–39 | `6ED9EBA1` | `A1 EB D9 6E` |  
| 40–59 | `8F1BBCDC` | `DC BC 1B 8F` |  
| 60–79 | `CA62C1D6` | `D6 C1 62 CA` |

---

## 4 — SHA-512

### 4.1 — Initial values

SHA-512 uses 8 64-bit values:

```
6A09E667F3BCC908  BB67AE8584CAA73B
3C6EF372FE94F82B  A54FF53A5F1D36F1
510E527FADE682D1  9B05688C2B3E6C1F
1F83D9ABFB41BD6B  5BE0CD19137E2179
```

The upper 32 bits of each value are identical to those of SHA-256 (`6A09E667`, `BB67AE85`, etc.). The presence of 64-bit values (instead of 32-bit) distinguishes SHA-512 from SHA-256.

### 4.2 — Round constants

SHA-512 uses 80 64-bit constants. The first ones:

```
428A2F98D728AE22  7137449123EF65CD
B5C0FBCFEC4D3B2F  E9B5DBA58189DBBC
```

Same remark: the upper 32 bits are identical to SHA-256.

---

## 5 — MD5

### 5.1 — Initial values

```
67452301 EFCDAB89 98BADCFE 10325476
```

In little-endian memory:

```
01 23 45 67  89 AB CD EF  FE DC BA 98  76 54 32 10
```

These values are shared with SHA-1 (see §3.1). If you find exactly these 4 values without the 5th from SHA-1, it is MD5.

### 5.2 — T constants (sine table)

MD5 uses 64 32-bit constants derived from the sine function: `T[i] = floor(2^32 × abs(sin(i+1)))`. These constants are very distinctive.

**First dwords**:

```
D76AA478 E8C7B756 242070DB C1BDCEEE  
F57C0FAF 4787C62A A8304613 FD469501  
698098D8 8B44F7AF FFFF5BB1 895CD7BE
6B901122 FD987193 A679438E 49B40821
```

The sequence `D76AA478 E8C7B756 242070DB C1BDCEEE` is the minimum MD5 signature. In little-endian memory: `78 A4 6A D7  56 B7 C7 E8  DB 70 20 24  EE CE BD C1`.

---

## 6 — SHA-3 / Keccak

### 6.1 — Round Constants

SHA-3 (Keccak) uses 24 64-bit constants for its 24 rounds. Unlike the SHA-2 functions, Keccak has no initial values — the state is initialized to zero.

**First constants**:

```
0000000000000001  0000000000008082
800000000000808A  8000000080008000
000000000000808B  0000000080000001
8000000080008081  8000000000008009
000000000000008A  0000000000000088
```

The sequence `0000000000000001 0000000000008082 800000000000808A` is the Keccak/SHA-3 signature.

### 6.2 — Rotation table (ρ offsets)

```
0  1  62 28 27
36 44 6  55 20
3  10 43 25 39
41 45 15 21 8
18 2  61 56 14
```

This 5×5 table of small integers can be stored in different forms in memory depending on the implementation.

---

## 7 — HMAC and key derivation

HMAC has no constants of its own — it uses the constants of the underlying hash function (SHA-256, SHA-1, MD5, etc.). However, two padding values are characteristic of any HMAC implementation:

| Value | Role | Bytes |  
|-------|------|-------|  
| `ipad` | Inner padding | `0x36` repeated (64-byte block: `36 36 36 36 ...`) |  
| `opad` | Outer padding | `0x5C` repeated (64-byte block: `5C 5C 5C 5C ...`) |

The presence of blocks of `0x36` and `0x5C` repeated over 64 bytes (or 128 bytes for SHA-512) near SHA or MD5 constants indicates HMAC.

For PBKDF2 and HKDF, there are no additional constants beyond those of HMAC and the underlying hash. However, HKDF uses the fixed string `"expand"` in some implementations (such as in TLS 1.3: `"tls13 "` followed by a label).

---

## 8 — ChaCha20

### 8.1 — Expansion constant

ChaCha20 initializes its state with the ASCII constant `"expand 32-byte k"` (for 256-bit keys):

```
65 78 70 61  6E 64 20 33  32 2D 62 79  74 65 20 6B
```

In little-endian dwords:

```
61707865  3320646E  79622D32  6B206574
```

This ASCII string is the most reliable ChaCha20 signature (and Salsa20, which uses the same constant). It appears in plaintext in `.rodata` and is easily spotted with `strings`.

For 128-bit keys, the constant is `"expand 16-byte k"`:

```
65 78 70 61  6E 64 20 31  36 2D 62 79  74 65 20 6B
```

---

## 9 — Salsa20

Salsa20 uses the same constants as ChaCha20 (`"expand 32-byte k"` and `"expand 16-byte k"`). The difference between the two algorithms is in the order of internal operations (quarter round), not in the constants. If you find this constant, check the function structure to distinguish ChaCha20 from Salsa20.

---

## 10 — RC4

RC4 uses no predefined constants — its internal state is a 256-byte permutation (S-box from 0x00 to 0xFF) initialized from the key. However, the **S-box initialization** is recognizable:

### 10.1 — Initialization pattern

```asm
; for (i = 0; i < 256; i++) S[i] = i;
xor    ecx, ecx
.L_init:
mov    byte ptr [rdi+rcx], cl     ; S[i] = i  
add    ecx, 1  
cmp    ecx, 256  
jl     .L_init  
```

### 10.2 — KSA (Key Scheduling Algorithm) pattern

```asm
; j = 0
; for (i = 0; i < 256; i++) {
;     j = (j + S[i] + key[i % keylen]) % 256;
;     swap(S[i], S[j]);
; }
```

The recognizable RC4 pattern is the 256-iteration loop with byte `swap` operations indexed by `i` and `j`, where `j` is accumulated modulo 256 (`and ej, 0xFF` or `movzx`). The absence of magic constants makes RC4 one of the hardest algorithms to identify by constants alone — you need to recognize the code pattern.

---

## 11 — Blowfish / Twofish

### 11.1 — Blowfish — Initial S-boxes

Blowfish uses 4 S-boxes of 256 dwords each (4 KB total), initialized with the decimal digits of π.

**First dwords of S-box 0**:

```
D1310BA6 98DFB5AC 2FFD72DB D01ADFB7  
B8E1AFED 6A267E96 BA7C9045 F12C7F99  
```

**First dwords of the P-array (initial subkeys)**:

```
243F6A88 85A308D3 13198A2E 03707344
A4093822 299F31D0 082EFA98 EC4E6C89
```

The value `243F6A88` corresponds to the hexadecimal decimal digits of π. It is the Blowfish signature.

### 11.2 — Twofish

Twofish uses key-derived S-boxes (no fixed constants for the S-boxes), but its key generation sub-constants include values derived from the RS and MDS constants. Twofish is harder to identify by constants than Blowfish.

---

## 12 — DES / 3DES

DES uses several fixed constant tables. Although DES is obsolete, it remains present in legacy code.

### 12.1 — Permutation tables

DES uses initial permutation (IP), final permutation (FP), expansion (E), and permutation (P) tables. These tables contain small integers (1–64) and are not very distinctive individually.

### 12.2 — DES S-boxes

DES uses 8 S-boxes of 64 entries of 4 bits each. The first bytes of S-box 1:

```
14 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07
00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08
```

---

## 13 — RSA

RSA itself has no magic constants in the usual sense. However, RSA implementations are identifiable by:

**The standard public exponent**: the value `0x10001` (65537) is used as the public exponent in nearly all RSA keys. In memory: `01 00 01 00` (in 32-bit LE) or `01 00 01` (in 3 bytes big-endian in ASN.1 structures).

**ASN.1/DER key markers**: RSA keys encoded in PEM/DER format contain recognizable ASN.1 sequences:

| Sequence | Meaning |  
|----------|---------|  
| `30 82` | Start of SEQUENCE (ASN.1 structure) |  
| `02 01 00` | INTEGER = 0 (PKCS#1 private key version) |  
| `06 09 2A 86 48 86 F7 0D 01 01 01` | OID `1.2.840.113549.1.1.1` = rsaEncryption |  
| `06 09 2A 86 48 86 F7 0D 01 01 0B` | OID `1.2.840.113549.1.1.11` = sha256WithRSAEncryption |

---

## 14 — Elliptic Curves (ECC)

### 14.1 — NIST curve parameters

The standard NIST curves use generator (base point) and order constants. The P-256 (secp256r1) parameters are the most common:

**X coordinate of the P-256 base point**:

```
6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
```

**Y coordinate of the P-256 base point**:

```
4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
```

### 14.2 — Curve25519

Curve25519 uses the base constant `9` (the base point is `x = 9`). This is not a distinctive sequence. Implementations are identifiable by the constant `121665` (the coefficient `d` of the Edwards25519 curve: `d = -121665/121666`) and by the prime number `2^255 - 19`:

```
7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
```

In practice, Curve25519 is often identified by the presence of the `libsodium` library or by function names `crypto_box`, `crypto_scalarmult`, `X25519` in the symbols.

---

## 15 — CRC-32

CRC-32 uses a lookup table of 256 dwords (1024 bytes) derived from the generator polynomial.

### 15.1 — Standard CRC-32 (polynomial `0xEDB88320`, reflected)

**First dwords of the table**:

```
00000000 77073096 EE0E612C 990951BA
076DC419 706AF48F E963A535 9E6495A3
```

The sequence `00000000 77073096 EE0E612C 990951BA` is the signature of standard CRC-32 (used by zlib, gzip, PNG, etc.).

### 15.2 — CRC-32C (Castagnoli, polynomial `0x82F63B78`)

**First dwords**:

```
00000000 F26B8303 E13B70F7 1350F3F4
C79A971F 35F1141C 26A1E7E8 D4CA64EB
```

CRC-32C is used by iSCSI, Btrfs, and certain network protocols.

---

## 16 — Base64

The standard Base64 alphabet is a recognizable ASCII string:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

In hexadecimal:

```
41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50
51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66
67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76
77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F
```

This alphabet is directly visible with `strings`. The URL-safe variant uses `-_` instead of `+/`.

Base64 is not encryption but it is ubiquitous in binaries that handle encoded data (tokens, cookies, configurations, serialized data). Its presence often indicates data encoding/decoding and can lead to encoded keys or secrets.

---

## 17 — Quick detection summary table

This table summarizes the minimum signatures to search for each algorithm. Four to eight bytes are generally sufficient to identify the algorithm with confidence.

| Algorithm | Minimum signature (hex) | Size | Typical location |  
|-----------|-------------------------|------|------------------|  
| **AES** (S-box) | `63 7C 77 7B F2 6B 6F C5` | 8 bytes | `.rodata` or `.data` |  
| **AES** (inverse S-box) | `52 09 6A D5 30 36 A5 38` | 8 bytes | `.rodata` or `.data` |  
| **AES** (T-table T0) | `A5 63 63 C6 84 7C 7C F8` | 8 bytes (LE dwords) | `.rodata` |  
| **SHA-256** (H init) | `67 E6 09 6A 85 AE 67 BB` | 8 bytes (LE) | `.rodata` |  
| **SHA-256** (K) | `98 2F 8A 42 91 44 37 71` | 8 bytes (LE) | `.rodata` |  
| **SHA-1** (H init) | `01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 F0 E1 D2 C3` | 20 bytes (LE) | `.rodata` |  
| **MD5** (H init) | `01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10` | 16 bytes (LE) | `.rodata` |  
| **MD5** (T sine) | `78 A4 6A D7 56 B7 C7 E8` | 8 bytes (LE) | `.rodata` |  
| **SHA-3/Keccak** (RC) | `01 00 00 00 00 00 00 00 82 80 00 00 00 00 00 00` | 16 bytes | `.rodata` |  
| **ChaCha20/Salsa20** | `65 78 70 61 6E 64 20 33` (`"expand 3"`) | 8 bytes (ASCII) | `.rodata` |  
| **Blowfish** (P-array) | `88 6A 3F 24 D3 08 A3 85` | 8 bytes (LE) | `.rodata` |  
| **CRC-32** (table) | `00 00 00 00 96 30 07 77` | 8 bytes (LE) | `.rodata` |  
| **RSA** (public exponent) | `01 00 01` or `00 01 00 01` | 3–4 bytes | `.data`, `.rodata` |  
| **HMAC** (ipad) | `36 36 36 36 36 36 36 36` | 8 bytes | `.rodata` or dynamic |  
| **Base64** (alphabet) | `41 42 43 44 45 46 47 48` (`"ABCDEFGH"`) | 8 bytes (ASCII) | `.rodata` |

---

## 18 — Generic YARA rule for crypto detection

Here is a YARA rule skeleton that combines several signatures. You can adapt and extend it for your analysis needs:

```yara
rule Crypto_Constants {
    meta:
        description = "Detects common crypto constants in a binary"
        author = "RE GCC Training"

    strings:
        // AES
        $aes_sbox     = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $aes_inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }

        // SHA-256 initial values (little-endian)
        $sha256_h = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }

        // SHA-256 round constants (little-endian)
        $sha256_k = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9 }

        // MD5 sine table (little-endian)
        $md5_t = { 78 A4 6A D7 56 B7 C7 E8 DB 70 20 24 EE CE BD C1 }

        // MD5 / SHA-1 initial values (little-endian)
        $md5_sha1_h = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }

        // ChaCha20 / Salsa20
        $chacha = "expand 32-byte k"
        $chacha16 = "expand 16-byte k"

        // Blowfish P-array (little-endian)
        $blowfish_p = { 88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03 }

        // CRC-32 table
        $crc32 = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 }

    condition:
        any of them
}
```

This rule can be used directly with YARA on the command line (`yara crypto.yar ./binary`), integrated into ImHex (Chapter 6.10), or deployed in an automated analysis pipeline (Chapter 35.4).

---

## 19 — Identification strategy in the absence of constants

Some algorithms have no easily searchable distinctive constants. Here is how to approach them:

**RC4** — No constants. Look for the code pattern: a 256-iteration loop initializing a sequential array (`S[i] = i`), followed by a KSA loop with swaps and modulo 256 accumulation.

**Simple XOR** — No constants. Look for `xor` instructions on data blocks with a repetitive pattern. Entropy analysis in ImHex can reveal a naive XOR (high but uniform entropy).

**Custom algorithms** — Homemade crypto implementations by definition have no cataloged constants. Look for indirect indicators: loops with many XOR operations, rotations (`rol`/`ror`), 16/32/64-byte data structures (common block sizes), and function names or strings suggesting encryption (`encrypt`, `decrypt`, `key`, `iv`, `cipher`, `hash`).

**Known libraries** — If the binary is dynamically linked with OpenSSL, libsodium, mbedTLS, or another crypto library, the imported function names (`EVP_EncryptInit`, `crypto_aead_xchacha20poly1305_ietf_encrypt`, etc.) directly identify the algorithms without needing to search for constants. Check imports with `ii` (r2) or `readelf -s --dyn-syms`.

---

> 📚 **Further reading**:  
> - **Chapter 24** — [Reversing a binary with encryption](/24-crypto/README.md) — identification and extraction of crypto keys.  
> - **Chapter 27** — [Analysis of a Linux ELF ransomware](/27-ransomware/README.md) — practical case of AES detection and key extraction.  
> - **Appendix E** — [ImHex cheat sheet](/appendices/appendix-e-cheatsheet-imhex.md) — searching for magic bytes and patterns in the hexadecimal view.  
> - **Appendix I** — [Recognizable GCC patterns](/appendices/appendix-i-gcc-patterns.md) — code idioms that surround crypto constants (loops, S-box lookups).  
> - **Chapter 35, section 35.4** — [Writing YARA rules](/35-automation-scripting/04-yara-rules.md) — automating detection with YARA.  
> - **Findcrypt** — Ghidra/IDA plugin that automates crypto constant detection (uses a database similar to this appendix).  
> - **hashID / hash-identifier** — Command-line tools for identifying a hash from its length and format.

⏭️ [Reverse Engineering Glossary](/appendices/appendix-k-glossary.md)
