/*
 * ch25_fileformat.hexpat — ImHex pattern for the CFR v2 format
 *
 * Reference pattern for chapter 25.
 * Applies to: demo.cfr, packed_noxor.cfr, packed_xor.cfr
 * Produces complete colorization with no orphan bytes.
 *
 * MIT License — Strictly educational use.
 *
 * ──────────────────────────────────────────────────────────
 *  CFR v2 Format — Structure summary
 * ──────────────────────────────────────────────────────────
 *
 *  ┌──────────────────────────────┐  0x00
 *  │   Header (32 bytes)          │
 *  ├──────────────────────────────┤  0x20
 *  │   Record 0                   │
 *  │     rec_header (8)           │
 *  │     name       (name_len)    │
 *  │     data       (data_len)    │
 *  │     crc16      (2)           │
 *  ├──────────────────────────────┤
 *  │   Record 1 .. N-1            │
 *  ├──────────────────────────────┤
 *  │   Footer (12 bytes)          │  optional (flags.has_footer)
 *  └──────────────────────────────┘
 *
 * ──────────────────────────────────────────────────────────
 *  Algorithms
 * ──────────────────────────────────────────────────────────
 *
 *  CRC-32   : poly=0xEDB88320, init=0xFFFFFFFF, xorOut=0xFFFFFFFF
 *             header_crc  → covers bytes [0x00..0x0F]
 *             global_crc  → covers everything before the footer
 *
 *  CRC-16   : poly=0x1021, init=0x1D0F, xorOut=0x0000
 *             per record  → covers name || data_original (before XOR)
 *
 *  XOR      : rotating key {0x5A, 0x3C, 0x96, 0xF1}
 *             applied to data only (not to names)
 *             index reset to 0 at the beginning of each record
 */

#pragma endian little
#pragma pattern_limit 131072

import std.mem;

// ═══════════════════════════════════════════════════════════
//  Enums & Bitfields
// ═══════════════════════════════════════════════════════════

enum RecordType : u8 {
    TEXT   = 0x01,
    BINARY = 0x02,
    META   = 0x03
    // Values > 0x03 accepted by the parser (treated as opaque BINARY)
};

bitfield HeaderFlags {
    xor_enabled : 1;    // bit 0 — data XOR with rotating key {5A, 3C, 96, F1}
    has_footer  : 1;    // bit 1 — CRFE footer present at end of file
    reserved    : 14;   // bits 2-15 — reserved (must be 0)
};

// ═══════════════════════════════════════════════════════════
//  Header (32 fixed bytes)
//
//  Offset  Size    Field
//  0x00    4       magic           "CFRM"
//  0x04    2       version         0x0002
//  0x06    2       flags           bitfield (XOR, FOOTER)
//  0x08    4       num_records     number of records (max 1024)
//  0x0C    4       timestamp       UNIX epoch (seconds)
//  0x10    4       header_crc      CRC-32 of bytes [0x00..0x0F]
//  0x14    8       author          ASCII, null-padded
//  0x1C    4       data_len_xor    XOR of all data_len values
// ═══════════════════════════════════════════════════════════

struct CFRHeader {
    char        magic[4]
        [[comment("Format identifier, must be \"CFRM\" (0x4346524D)")]];

    u16         version
        [[comment("Format version (this pattern covers v2 = 0x0002)")]];

    HeaderFlags flags
        [[comment("Bit 0: XOR on data / Bit 1: footer present")]];

    u32         num_records
        [[comment("Number of records (max 1024)")]];

    u32         timestamp
        [[comment("Creation date (UNIX epoch, seconds)")]];

    u32         header_crc
        [[comment("CRC-32 (poly 0xEDB88320, init 0xFFFFFFFF) of bytes [0x00..0x0F]")]];

    char        author[8]
        [[comment("Archive author, ASCII, null-padded")]];

    u32         data_len_xor
        [[comment("XOR of all record data_len fields")]];
};

// ═══════════════════════════════════════════════════════════
//  Record (variable size)
//
//  Layout of each record:
//    [RecordHeader  8 bytes]
//    [name          name_len bytes, ASCII, never XOR-ed]
//    [data          data_len bytes, XOR if flags.xor_enabled]
//    [crc16         2 bytes, CRC-16/CCITT init=0x1D0F]
//
//  The CRC-16 is computed on (name || data_ORIGINAL),
//  i.e. on the data BEFORE the XOR transformation.
// ═══════════════════════════════════════════════════════════

struct RecordHeader {
    RecordType type
        [[comment("0x01=TEXT, 0x02=BINARY, 0x03=META")]];

    u8 flags
        [[comment("Reserved, should be 0x00 (ignored by the parser)")]];

    u16 name_len
        [[comment("Name length in bytes (can be 0)")]];

    u32 data_len
        [[comment("Payload length in bytes (can be 0)")]];
};

struct Record {
    RecordHeader rh;

    char name[rh.name_len]
        [[comment("ASCII name, NOT null-terminated, NOT subject to XOR")]];

    u8 data[rh.data_len]
        [[comment("Payload. If header.flags.xor_enabled: XOR rotating key {5A,3C,96,F1}. Otherwise: plaintext data.")]];

    u16 crc16
        [[comment("CRC-16 (poly 0x1021, init 0x1D0F, no final XOR) computed on name||data_original (before XOR)")]];
};

// ═══════════════════════════════════════════════════════════
//  Footer (12 bytes, optional)
//
//  Present only if header.flags.has_footer == 1.
//  Located immediately after the last record.
//
//  Offset  Size    Field
//  +0x00   4       magic           "CRFE"
//  +0x04   4       total_size      total file size
//  +0x08   4       global_crc      CRC-32 of everything before the footer
// ═══════════════════════════════════════════════════════════

struct CFRFooter {
    char magic[4]
        [[comment("Footer identifier, must be \"CRFE\" (0x43524645)")]];

    u32 total_size
        [[comment("Total file size in bytes (must == actual size)")]];

    u32 global_crc
        [[comment("CRC-32 (same algo as header_crc) of everything before the footer")]];
};

// ═══════════════════════════════════════════════════════════
//  Instantiation
//
//  The header is placed at offset 0.
//  Records follow immediately (offset 0x20 = 32).
//  The footer is placed at end of file if the flag is set.
//
//  Coverage check:
//    header (32) + Σ records + footer (12 if present) == file size
// ═══════════════════════════════════════════════════════════

CFRHeader header @ 0x00;

Record records[header.num_records] @ 0x20;

if (header.flags.has_footer) {
    CFRFooter footer @ (std::mem::size() - 12);
}
