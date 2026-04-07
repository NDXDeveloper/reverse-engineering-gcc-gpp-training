🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 24.4 — Visualizing the Encrypted Format and Structures with ImHex

> 🎯 **Objective of this section**: map the exact structure of the `secret.enc` file using ImHex, understand the layout of metadata and encrypted data, and produce a reusable `.hexpat` pattern that documents the format.

---

## Why examine the encrypted file

The previous sections focused on the binary that *produces* the encrypted file. We identified the algorithm (AES-256-CBC), the library (OpenSSL), and extracted the key and IV from memory. One might think the work is done — just decrypt with those parameters.

In reality, there is a missing link: **how is the data packaged inside the `.enc` file?** An encrypted file is almost never a simple raw dump of the ciphertext. It generally contains a header with metadata: a magic number to identify the format, version information, the IV (which must be transmitted to the recipient), the original file size (to remove padding), sometimes an authentication MAC, a salt for the KDF, or flags indicating the algorithm used.

If we try to decrypt while ignoring this header — by passing the entire file to `AES-256-CBC` — we will get noise, because the first bytes are not ciphertext. We need to know exactly **at which offset the encrypted data begins** and **how many bytes to decrypt**.

This is where ImHex comes in. Where `xxd` shows raw bytes, ImHex allows you to overlay a structured interpretation on the file, colorize regions, and validate hypotheses about the format in real time using `.hexpat` patterns.

---

## First contact: raw visual inspection

Let's open `secret.enc` in ImHex. The first instinct is to look at the first lines of the file in hex view, before any interpretation:

```
Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   Decoded text
00000000  43 52 59 50 54 32 34 00  01 00 10 00 9C 71 2E B5   CRYPT24.....q..
00000010  38 F4 A0 6D 1C 83 E7 52  BF 49 06 DA XX XX XX XX   8..m...R.I......
00000020  XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX   ................
```

*(The `XX` represent the ciphertext bytes, which vary with each execution due to the random IV.)*

Several immediate observations, even before looking at the source code:

**Bytes 0x00–0x07**: `43 52 59 50 54 32 34 00` — in ASCII, this gives `CRYPT24\0`. This is an 8-byte magic number, null-terminated. Magic bytes are the format's calling card: they allow a tool (or `file`) to identify the file type unambiguously.

**Bytes 0x08–0x09**: `01 00` — two isolated bytes. If we interpret them as a major/minor version number, we get `1.0`. This is a hypothesis to confirm, but the position right after the magic and the low values are consistent.

**Bytes 0x0A–0x0B**: `10 00` — in little-endian, `0x0010` = 16 in decimal. If this is the length of the next field, 16 bytes corresponds exactly to the size of an AES block (and therefore an IV for CBC).

**Bytes 0x0C–0x1B**: 16 bytes. If the previous hypothesis is correct, this is the IV. We can verify it by comparing it with the IV captured by GDB/Frida in section 24.3 — they must match.

**Bytes 0x1C–0x1F**: 4 bytes. In little-endian, they give an integer that could be the original file size before encryption. If `secret.txt` is, for example, 342 bytes, we should find `0x00000156` here, stored as `56 01 00 00`.

**Bytes 0x20 and beyond**: the rest of the file. This is probably the pure ciphertext.

This reasoning is typical of file format RE: we formulate hypotheses from visual patterns, then validate them one by one.

---

## Validation with ImHex's Data Inspector

ImHex has a **Data Inspector** panel that displays the interpretation of the byte (or group of bytes) under the cursor in all common formats simultaneously: uint8, int8, uint16 LE/BE, uint32 LE/BE, float, double, ASCII, UTF-8, etc.

Let's place the cursor at different positions:

**Cursor at 0x0A** (the field we suspect is the IV length):

| Format | Value |  
|---|---|  
| uint16 LE | 16 |  
| uint16 BE | 4096 |

The value `16` in little-endian is consistent with our hypothesis (IV size). The big-endian value `4096` does not make sense in this context — confirmation that the format is little-endian, which is expected for an x86-64 binary.

**Cursor at 0x1C** (suspected original size):

| Format | Value |  
|---|---|  
| uint32 LE | (size of `secret.txt` in bytes) |

We can verify with `wc -c secret.txt` in the terminal. If the values match, the hypothesis is confirmed.

---

## Entropy analysis: visualizing the plaintext/encrypted boundary

ImHex offers an **Entropy Analysis** view (via **View → Information** or the analysis icon). This view calculates Shannon entropy per block and displays it as a graph.

For `secret.enc`, the entropy profile is characteristic:

- **Bytes 0x00–0x1F (header)**: low to medium entropy. The magic is predictable ASCII text, the version and size are small integers with many zeros. The IV has high entropy (it is pure randomness) but it is short (16 bytes).  
- **Bytes 0x20 and beyond (ciphertext)**: very high entropy, close to 8.0 bits/byte (the theoretical maximum). This is the visual signature of encrypted (or compressed) data. A homogeneous block of high entropy indicates that the encryption is working correctly — the plaintext patterns have been completely destroyed.

This sharp transition between low and high entropy visually confirms offset 0x20 as the start of the ciphertext. If the ciphertext started earlier or later, the transition would be shifted.

> 💡 **Tip**: if you encounter an unknown format with no magic or documentation, entropy analysis is often the first tool to use. It reveals the macro structure of the file: text zones (entropy ~4–5), structured data zones (entropy ~5–6), compressed or encrypted zones (entropy ~7.5–8.0), and padding/zero zones (entropy ~0).

---

## Writing a `.hexpat` pattern for the CRYPT24 format

Now that the structure is understood, we formalize it in an ImHex pattern. This serves both as an analysis tool (ImHex colorizes and annotates the file in real time) and as executable documentation of the format.

### The complete pattern

```cpp
// crypt24.hexpat — ImHex pattern for the CRYPT24 format
// Reverse Engineering Training — Chapter 24

#pragma description "CRYPT24 encrypted file format"
#pragma magic [ 43 52 59 50 54 32 34 00 ]  // "CRYPT24\0"
#pragma endian little

import std.io;  
import std.mem;  

// ── Base types ──────────────────────────────────────────────

// Magic number: 8 bytes, must be "CRYPT24\0"
struct Magic {
    char value[8];
} [[static, color("4A90D9")]];

// Version: major.minor, each on 1 byte
struct Version {
    u8 major;
    u8 minor;
} [[static, color("50C878")]];

// IV length, stored on 2 bytes LE
// Allows the format to support other IV sizes in the future
struct IVLength {
    u16 length;
} [[static, color("F5A623")]];

// IV: byte array of variable size (read from iv_length)
struct IV {
    u8 bytes[parent.iv_length.length];
} [[color("E74C3C")]];

// Original file size before encryption (uint32 LE)
// Needed to remove PKCS7 padding after decryption
struct OriginalSize {
    u32 size;
} [[static, color("9B59B6")]];

// Encrypted data: the rest of the file
struct CipherData {
    u8 data[std::mem::size() - $];
} [[color("7F8C8D")]];

// ── Main structure ───────────────────────────────────────

struct Crypt24File {
    Magic       magic;          // 0x00: "CRYPT24\0" (8 bytes)
    Version     version;        // 0x08: major.minor version (2 bytes)
    IVLength    iv_length;      // 0x0A: IV length (2 bytes)
    IV          iv;             // 0x0C: IV (iv_length.length bytes)
    OriginalSize orig_size;     // 0x1C: original size (4 bytes)
    CipherData  ciphertext;     // 0x20: encrypted data (rest of file)
};

// ── Entry point ─────────────────────────────────────────────

Crypt24File file @ 0x00;

// ── Validations ────────────────────────────────────────────

// Check the magic
std::assert(
    file.magic.value == "CRYPT24\0",
    "Invalid magic: expected CRYPT24"
);

// Check the version (we only support 1.x for now)
std::assert(
    file.version.major == 1,
    "Unsupported major version"
);

// Check that the IV has a reasonable size (8, 12, or 16 bytes)
std::assert(
    file.iv_length.length == 8 ||
    file.iv_length.length == 12 ||
    file.iv_length.length == 16,
    "Unexpected IV length"
);

// Check that the ciphertext is a multiple of 16 (AES block size)
std::assert(
    std::mem::size() - 0x20 != 0,
    "Empty ciphertext"
);

// ── Informational output in the ImHex console ─────────────────

std::print("=== CRYPT24 File Analysis ===");  
std::print("Version:       {}.{}", file.version.major, file.version.minor);  
std::print("IV length:     {} bytes", file.iv_length.length);  
std::print("Original size: {} bytes", file.orig_size.size);  
std::print("Cipher length: {} bytes",  
           std::mem::size() - 0x20);
std::print("Padding bytes: {} bytes",
           (std::mem::size() - 0x20) - file.orig_size.size);
```

### What the pattern produces in ImHex

Once the pattern is applied (**File → Load Pattern** or dragged into the Pattern Editor), ImHex:

1. **Colorizes** each region of the file according to the defined color scheme: blue for the magic, green for the version, orange for the IV length, red for the IV, purple for the original size, gray for the ciphertext.

2. **Structures** the Pattern Data panel with a navigable tree: you can expand `Crypt24File` → `magic` → `value` and see each field with its interpreted value.

3. **Validates** the assertions automatically: if the magic does not match or if the version is unexpected, ImHex displays a clear error. This is a safety net that prevents applying the wrong pattern to the wrong file.

4. **Displays** in the console the computed information: original size, ciphertext size, number of padding bytes.

---

## Bookmarks: manually annotating areas of interest

In addition to the pattern, ImHex's **Bookmarks** allow you to add free-form annotations on file regions. This is useful for observations that do not fit into a structured pattern:

- Select bytes 0x0C to 0x1B → right-click → **Add Bookmark** → "IV — compare with the value captured by GDB/Frida in section 24.3".  
- Select the last 1 to 16 bytes of the file → **Add Bookmark** → "Likely PKCS7 padding — verify that the last N bytes equal N".

Bookmarks are saved in the ImHex project and can be exported. This is a good way to document your observations throughout the analysis.

---

## Visualizing PKCS7 padding

AES-CBC uses PKCS7 padding: if the last block of the plaintext is not complete (16 bytes), it is padded with bytes whose value equals the number of bytes added. For example, if 5 bytes are missing, `05 05 05 05 05` is added.

We cannot directly see the padding in the encrypted file (it is encrypted with the rest), but we can deduce it:

```
Ciphertext size  = file size - 0x20 (header offset)  
Original size    = orig_size field (read from the header)  
Padding          = ciphertext size - original size  
```

If `secret.txt` is 342 bytes, the ciphertext will be 352 bytes (next multiple of 16), and the padding will be 10 bytes (`0x0A 0x0A 0x0A...`). The `orig_size` field in the header gives us this information without needing to decrypt.

> 💡 **Important detail for section 24.5**: some decryption libraries (like `pycryptodome`) automatically remove PKCS7 padding if requested. The `orig_size` field then serves as cross-validation: after decryption and padding removal, the size must match `orig_size`.

---

## Comparison with other `.enc` files

If we encrypt multiple files with the same binary, ImHex allows us to compare them via the **Diff** view (see section 6.7). The expected observations:

- **The magic, version, and IV length are identical** across all files — these are format constants.  
- **The IV is different** for each encryption — this is the correct behavior of CBC encryption with a random IV (`RAND_bytes`).  
- **The ciphertext is completely different** even for the same plaintext — thanks to the distinct IV.  
- **The original size varies** depending on the source file.

If, during comparison, we discovered that two files encrypted from the same plaintext produce the same ciphertext, this would be a serious red flag: it would mean the IV is being reused (or absent), which compromises the security of the scheme. This is the kind of flaw that an RE analyst can detect visually in ImHex.

---

## Structure mapping summary

The CRYPT24 format is now fully documented. Here is the final map:

```
secret.enc
├─ [0x00..0x07]  Magic         "CRYPT24\0"           (8 bytes, fixed)
├─ [0x08]        Version maj.  0x01                   (1 byte)
├─ [0x09]        Version min.  0x00                   (1 byte)
├─ [0x0A..0x0B]  IV length     0x0010 (16)            (uint16 LE)
├─ [0x0C..0x1B]  IV            (16 random bytes)      (variable)
├─ [0x1C..0x1F]  Orig. size    (plaintext size)       (uint32 LE)
└─ [0x20..EOF]   Ciphertext    (AES-256-CBC, PKCS7)   (variable)
```

Each field was identified by visual observation, confirmed by the Data Inspector and the values captured in section 24.3, and formalized in the `.hexpat` pattern. This map will guide the writing of the decryption script in the next section: we know exactly which bytes to read, at which offset, in which format, and what to do with them.

---


⏭️ [Reproducing the encryption scheme in Python](/24-crypto/05-reproducing-encryption-python.md)
