// ch24_crypt24.hexpat — ImHex pattern for the CRYPT24 format
// Reverse Engineering Training — Chapter 24
//
// This pattern parses .enc files produced by the ch24-crypto binary.
//
// Format structure:
//   [0x00..0x07]  Magic         "CRYPT24\0"           (8 bytes)
//   [0x08]        Major version 0x01                   (1 byte)
//   [0x09]        Minor version 0x00                   (1 byte)
//   [0x0A..0x0B]  IV length     0x0010 (16)            (uint16 LE)
//   [0x0C..0x1B]  IV            (16 random bytes)
//   [0x1C..0x1F]  Orig. size    (plaintext size)       (uint32 LE)
//   [0x20..EOF]   Ciphertext    (AES-256-CBC, PKCS7)
//
// Usage: open a .enc file in ImHex, load this pattern.
//
// MIT License — Strictly educational use.

#pragma description "CRYPT24 encrypted file format"
#pragma magic [ 43 52 59 50 54 32 34 00 ]  // "CRYPT24\0"
#pragma endian little

import std.io;
import std.mem;

// ── Base types ─────────────────────────────────────────────────

struct Magic {
    char value[8];
} [[static, color("4A90D9")]];

struct Version {
    u8 major;
    u8 minor;
} [[static, color("50C878")]];

struct IVLength {
    u16 length;
} [[static, color("F5A623")]];

struct IV {
    u8 bytes[parent.iv_length.length];
} [[color("E74C3C")]];

struct OriginalSize {
    u32 size;
} [[static, color("9B59B6")]];

struct CipherData {
    u8 data[std::mem::size() - $];
} [[color("7F8C8D")]];

// ── Main structure ─────────────────────────────────────────────

struct Crypt24File {
    Magic       magic;          // 0x00: "CRYPT24\0" (8 bytes)
    Version     version;        // 0x08: major.minor version (2 bytes)
    IVLength    iv_length;      // 0x0A: IV length (2 bytes)
    IV          iv;             // 0x0C: IV (iv_length.length bytes)
    OriginalSize orig_size;     // 0x1C: original size (4 bytes)
    CipherData  ciphertext;     // 0x20: encrypted data (rest of file)
};

// ── Entry point ────────────────────────────────────────────────

Crypt24File file @ 0x00;

// ── Validations ────────────────────────────────────────────────

std::assert(
    file.magic.value == "CRYPT24\0",
    "Invalid magic: expected CRYPT24"
);

std::assert(
    file.version.major == 1,
    "Unsupported major version"
);

std::assert(
    file.iv_length.length == 8 ||
    file.iv_length.length == 12 ||
    file.iv_length.length == 16,
    "Unexpected IV length"
);

std::assert(
    std::mem::size() - 0x20 != 0,
    "Empty ciphertext"
);

// ── Informational display ──────────────────────────────────────

std::print("=== CRYPT24 File Analysis ===");
std::print("Version:       {}.{}", file.version.major, file.version.minor);
std::print("IV length:     {} bytes", file.iv_length.length);
std::print("Original size: {} bytes", file.orig_size.size);
std::print("Cipher length: {} bytes",
           std::mem::size() - 0x20);
std::print("Padding bytes: {} bytes",
           (std::mem::size() - 0x20) - file.orig_size.size);
