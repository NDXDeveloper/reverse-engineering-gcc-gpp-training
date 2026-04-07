// ============================================================
// ch06_fileformat.hexpat
// ImHex pattern for the .cdb format (Custom Database)
// Reverse Engineering Training — Chapter 6, section 6.11
//
// This pattern parses sample.cdb files produced by the
// ch06-fileformat binary.
//
// Format structure:
//   FileHeader      (32 bytes)   — magic "CDB2", version, counters
//   FieldDescriptor[] (N × 32 B) — description of each field
//   Padding          (variable)  — alignment to 32 bytes
//   Record[]         (N × 68 B)  — database data
//   Footer           (12 bytes)  — magic "CDB2", validation counters
//
// Usage: open sample.cdb in ImHex, load this pattern.
// ============================================================

#include <std/io.pat>

// ────────────────────────────────────────────
//  Enums
// ────────────────────────────────────────────

enum FieldType : u16 {
    STRING  = 0x0001,
    TEXT    = 0x0002,
    INTEGER = 0x0003
};

// ────────────────────────────────────────────
//  Structure: CDB_Header (32 bytes)
// ────────────────────────────────────────────

struct CDB_Header {
    char   magic[4]        [[color("FF4444"),
                             comment("Magic 'CDB2' — identifies the format")]];
    u16    version         [[comment("Format major version")]];
    u16    sub_version     [[comment("Format minor version")]];
    u32    record_count    [[comment("Number of records in the database")]];
    u32    data_offset     [[format("hex"),
                             comment("Offset of data (records) from the beginning of the file")]];
    u32    unknown_10      [[comment("Reserved field (observed: always 1)")]];
    u32    field_count     [[comment("Number of field descriptors")]];
    u8     reserved[8]     [[comment("Reserved bytes (always null)")]];
};

// ────────────────────────────────────────────
//  Structure: CDB_FieldDescriptor (32 bytes)
// ────────────────────────────────────────────

struct CDB_FieldDescriptor {
    u16       field_id     [[comment("Numeric field identifier")]];
    FieldType field_type   [[comment("Field data type")]];
    char      field_name[20] [[comment("Field name (null-terminated)")]];
    u32       max_size     [[comment("Maximum size of the field value")]];
    u32       flags        [[format("hex"),
                             comment("Field flags (observed: 0x01 = indexed)")]];
};

// ────────────────────────────────────────────
//  Structure: CDB_Record (68 bytes)
// ────────────────────────────────────────────

struct CDB_Record {
    u32  record_id     [[comment("Unique record identifier (auto-incremented)")]];
    char name[20]      [[color("44FF44"),
                         comment("'name' field — string of 20 bytes max")]];
    char description[40] [[color("44AAFF"),
                           comment("'description' field — string of 40 bytes max")]];
    u32  value         [[comment("'value' field — 32-bit integer")]];
};

// ────────────────────────────────────────────
//  Structure: CDB_Footer (12 bytes)
// ────────────────────────────────────────────

struct CDB_Footer {
    char magic[4]          [[color("FF4444"),
                             comment("End magic — must match header magic")]];
    u32  record_count      [[comment("Number of records (cross-validation with header)")]];
    u32  data_end_offset   [[format("hex"),
                             comment("End-of-data offset")]];
};

// ────────────────────────────────────────────
//  File instantiation
// ────────────────────────────────────────────

CDB_Header header @ 0x00;

CDB_FieldDescriptor field_descriptors[header.field_count] @ sizeof(CDB_Header);

// Padding between descriptors and data
u8 padding[header.data_offset - sizeof(CDB_Header) - header.field_count * sizeof(CDB_FieldDescriptor)]
    @ sizeof(CDB_Header) + header.field_count * sizeof(CDB_FieldDescriptor)
    [[comment("Alignment padding before data")]];

CDB_Record records[header.record_count] @ header.data_offset;

CDB_Footer footer @ header.data_offset + header.record_count * sizeof(CDB_Record);

// ────────────────────────────────────────────
//  Debug information
// ────────────────────────────────────────────

std::print("=== CDB File Summary ===");
std::print("  Magic       : {}", header.magic);
std::print("  Version     : {}.{}", header.version, header.sub_version);
std::print("  Fields      : {}", header.field_count);
std::print("  Records     : {}", header.record_count);
std::print("  Data offset : 0x{:X}", header.data_offset);
