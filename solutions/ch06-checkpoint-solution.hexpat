// ============================================================
// ch06-checkpoint-solution.hexpat
// Chapter 6 checkpoint solution
// Format: .pkt file (custom protocol capture ch23)
// Reverse Engineering Training — GCC compiled applications
// ============================================================
//
// FORMAT DESCRIPTION
// ==================
// The .pkt file is a proprietary capture format produced
// by the ch06-fileformat binary. It stores a sequence of
// packets from the chapter 23 custom network protocol.
//
// General structure:
//
//   ┌──────────────────────────┐  offset 0x00
//   │   FileHeader (32 bytes)  │
//   ├──────────────────────────┤  offset 0x20
//   │   SessionInfo (48 bytes) │
//   ├──────────────────────────┤  offset 0x50
//   │   Packet #1              │
//   │     PacketHeader (20 B)  │
//   │     Payload (variable)   │
//   ├──────────────────────────┤
//   │   Packet #2              │
//   │     ...                  │
//   ├──────────────────────────┤
//   │   ...                    │
//   ├──────────────────────────┤
//   │   FileFooter (16 bytes)  │
//   └──────────────────────────┘
//
// CONVENTIONS
// ===========
// - Network fields (IP addresses, ports, sequence numbers)
//   are in big-endian, per network convention.
// - File format metadata fields (offsets, sizes, structure
//   counters) are in little-endian, per x86 convention.
// - Timestamps are 64-bit Unix timestamps (seconds since
//   epoch) in little-endian.
//
// ============================================================

#include <std/io.pat>
#include <std/mem.pat>

// ────────────────────────────────────────────
//  Enums
// ────────────────────────────────────────────

// Packet type in the ch23 custom protocol.
// Identified by observing recurring values in the
// PacketHeader packet_type field: values 0x01 to 0x06
// appear in captures, others may exist.
enum PacketType : u8 {
    HANDSHAKE_INIT   = 0x01,   // Client → Server: connection initiation
    HANDSHAKE_ACK    = 0x02,   // Server → Client: acknowledgment
    AUTH_REQUEST     = 0x03,   // Client → Server: credential submission
    AUTH_RESPONSE    = 0x04,   // Server → Client: auth result
    DATA_TRANSFER    = 0x05,   // Bidirectional: data transfer
    DISCONNECT       = 0x06    // Bidirectional: connection close
};

// Packet direction — inferred from observation: 0x01 = client
// to server, 0x02 = server to client.
enum PacketDirection : u8 {
    CLIENT_TO_SERVER = 0x01,
    SERVER_TO_CLIENT = 0x02
};

// Authentication response status (in the payload of
// AUTH_RESPONSE packets).
enum AuthStatus : u8 {
    AUTH_SUCCESS     = 0x00,
    AUTH_FAILURE     = 0x01,
    AUTH_EXPIRED     = 0x02,
    AUTH_BANNED      = 0x03
};

// Packet flags — bitmask on 1 byte.
// Identified by cross-referencing different packets:
// bit 0 seems to indicate payload compression,
// bit 1 the presence of a checksum at the end of the payload.
bitfield PacketFlags {
    compressed   : 1 [[comment("Compressed payload (not encountered in sample.pkt)")]];
    has_checksum : 1 [[comment("A 4-byte CRC32 follows the payload")]];
    encrypted    : 1 [[comment("Encrypted payload (not encountered in sample.pkt)")]];
    fragmented   : 1 [[comment("Fragmented packet (not encountered)")]];
    reserved     : 4;
};

// Protocol version — encoded on 2 bytes.
// Observed: major=1, minor=0 in all samples.
enum ProtoVersion : u16 {
    V1_0 = 0x0100
};

// ────────────────────────────────────────────
//  Structure: FileHeader (32 bytes)
// ────────────────────────────────────────────
// The first 32 bytes of the .pkt file identify the format,
// its version, and provide the global counters needed
// to parse the rest of the file.
//
// Identification:
//   - Offset 0x00: magic "PKT\x00" (50 4B 54 00)
//   - Offset 0x04: file format version (u16 LE)
//
// Counters and offsets:
//   - packet_count  : total number of packets in the file
//   - total_length  : total file size in bytes
//   - data_offset   : offset of the first packet (after SessionInfo)
//   - footer_offset : offset of the FileFooter at end of file

struct FileHeader {
    char    magic[4]        [[color("FF8844"),
                              comment("Magic 'PKT\\0' — identifies the .pkt format")]];
    u16     format_version  [[comment("File format version (1 = current)")]];
    u16     proto_version   [[comment("Captured protocol version (0x0100 = v1.0)")]];
    u32     packet_count    [[comment("Total number of packets in the capture")]];
    u32     total_length    [[format("hex"),
                              comment("Total file size (must match actual size)")]];
    u32     data_offset     [[format("hex"),
                              comment("Offset of the first PacketHeader")]];
    u32     footer_offset   [[format("hex"),
                              comment("Offset of the FileFooter")]];
    u64     capture_start   [[comment("Unix timestamp of capture start")]];
};

// ────────────────────────────────────────────
//  Structure: SessionInfo (48 bytes)
// ────────────────────────────────────────────
// Metadata of the captured network session.
// Placed immediately after the FileHeader.
//
// IP addresses and ports are in big-endian (network
// convention). Other fields are in little-endian.
//
// Note: IPv4 addresses are stored as 4 raw bytes
// rather than a u32, because their natural representation
// is dotted-decimal (e.g. 192.168.1.10), not an integer.

struct IPv4Address {
    u8 octet_1;
    u8 octet_2;
    u8 octet_3;
    u8 octet_4;
};

struct SessionInfo {
    IPv4Address client_ip     [[color("AADDFF"),
                                comment("Client IP address")]];
    be u16      client_port   [[comment("Client source port (big-endian)")]];
    padding[2]                [[comment("4-byte alignment")]];
    IPv4Address server_ip     [[color("AADDFF"),
                                comment("Server IP address")]];
    be u16      server_port   [[comment("Server port (big-endian)")]];
    padding[2]                [[comment("4-byte alignment")]];
    u64         session_id    [[format("hex"),
                                comment("Unique session identifier")]];
    u64         capture_end   [[comment("Unix timestamp of capture end")]];
    char        capture_host[16] [[comment("Capture machine hostname, null-terminated")]];
};

// ────────────────────────────────────────────
//  Structure: PacketHeader (20 bytes)
// ────────────────────────────────────────────
// Each captured packet is preceded by a 20-byte header
// describing its type, direction, size and sequencing
// metadata.
//
// The payload_length field determines the number of data
// bytes immediately following this header. A packet's total
// size is therefore: 20 + payload_length
// (+ 4 CRC bytes if the has_checksum flag is set).

struct PacketHeader {
    be u32          sequence_num   [[comment("Sequence number (big-endian, protocol convention)")]];
    PacketType      packet_type    [[color("CC88FF"),
                                     comment("Packet type (see PacketType enum)")]];
    PacketDirection direction      [[comment("Packet direction")]];
    PacketFlags     flags          [[comment("Flags: compression, checksum, encryption")]];
    padding[1]                     [[comment("Alignment")]];
    u32             payload_length [[comment("Payload size in bytes (excluding CRC)")]];
    u32             timestamp_delta [[comment("Delta in ms since capture_start")]];
};

// ────────────────────────────────────────────
//  Payload structures by packet type
// ────────────────────────────────────────────
// Payload content depends on packet_type. The structures
// below model formats observed in sample.pkt. For
// unobserved types or variable-size unstructured payloads,
// we fall through to the default case (raw u8 array).

// HANDSHAKE_INIT Payload (Client → Server)
// The client sends its protocol version and a random
// 16-byte nonce for the initial exchange.
struct PayloadHandshakeInit {
    be u16 proto_version   [[comment("Protocol version requested by the client")]];
    u8     nonce[16]       [[color("66DD66"),
                             comment("Random nonce (16 bytes) for the handshake")]];
    padding[2]             [[comment("Alignment")]];
};

// HANDSHAKE_ACK Payload (Server → Client)
// The server confirms the version and sends back its own nonce.
struct PayloadHandshakeAck {
    be u16 proto_version   [[comment("Version accepted by the server")]];
    u8     server_nonce[16] [[color("66DD66"),
                              comment("Server nonce (16 bytes)")]];
    be u32 session_token   [[format("hex"),
                             comment("Session token assigned by the server")]];
};

// AUTH_REQUEST Payload (Client → Server)
// The client sends a username and a password hash
// (SHA-256, 32 bytes).
struct PayloadAuthRequest {
    char username[32]     [[color("FFEE55"),
                            comment("Username, null-terminated, padded to 32 bytes")]];
    u8   password_hash[32] [[color("FF6666"),
                             comment("SHA-256 of the password (32 bytes)")]];
};

// AUTH_RESPONSE Payload (Server → Client)
// The server returns the authentication result.
struct PayloadAuthResponse {
    AuthStatus status     [[comment("Authentication result")]];
    padding[3]            [[comment("4-byte alignment")]];
    be u32 user_id        [[comment("Assigned user ID (0 if failed)")]];
    char   message[32]    [[color("FFEE55"),
                            comment("Text message ('Welcome', 'Access denied'...)")]];
};

// DATA_TRANSFER Payload (bidirectional)
// Application data transfer. The content is an opaque blob
// whose semantics depend on the application.
// We parse the first identified structured fields, the
// rest is a raw buffer.
struct PayloadDataTransfer {
    be u16 data_type      [[comment("Application data sub-type")]];
    be u16 fragment_id    [[comment("Fragment ID (0 if not fragmented)")]];
    // The rest of the payload is a raw data buffer.
    // Its size is: payload_length - 4 (the 4 bytes above).
    // Note: we cannot compute this size directly here
    // since we don't have access to the parent. We use
    // conditional parsing in the Packet structure instead.
};

// DISCONNECT Payload (bidirectional)
// Simple disconnect notification with a reason code.
struct PayloadDisconnect {
    be u16 reason_code    [[comment("Reason code: 0=normal, 1=timeout, 2=error")]];
    char   reason_text[30] [[color("FFEE55"),
                             comment("Textual description of the reason")]];
};

// ────────────────────────────────────────────
//  Structure: Packet (variable size)
// ────────────────────────────────────────────
// A complete packet = PacketHeader + Payload + optional CRC.
//
// The payload is conditionally parsed based on packet_type.
// For types with known internal structure, we use the
// corresponding typed structure. For unknown types or
// payloads whose size doesn't match a fixed structure,
// we parse as raw bytes.
//
// If the has_checksum flag is set, a 4-byte CRC32 follows
// immediately after the payload.

struct Packet {
    PacketHeader hdr;

    // --- Conditional payload based on packet type ---

    if (hdr.packet_type == PacketType::HANDSHAKE_INIT &&
        hdr.payload_length == 20) {
        PayloadHandshakeInit payload;

    } else if (hdr.packet_type == PacketType::HANDSHAKE_ACK &&
               hdr.payload_length == 22) {
        PayloadHandshakeAck payload;

    } else if (hdr.packet_type == PacketType::AUTH_REQUEST &&
               hdr.payload_length == 64) {
        PayloadAuthRequest payload;

    } else if (hdr.packet_type == PacketType::AUTH_RESPONSE &&
               hdr.payload_length == 40) {
        PayloadAuthResponse payload;

    } else if (hdr.packet_type == PacketType::DATA_TRANSFER &&
               hdr.payload_length >= 4) {
        // For DATA_TRANSFER, parse the 4-byte sub-header
        // then the rest as raw bytes.
        PayloadDataTransfer data_header;
        u8 data_body[hdr.payload_length - 4]
            [[color("BBBBBB"), comment("Raw application data")]];

    } else if (hdr.packet_type == PacketType::DISCONNECT &&
               hdr.payload_length == 32) {
        PayloadDisconnect payload;

    } else {
        // Unknown type or unexpected size — raw parsing
        u8 raw_payload[hdr.payload_length]
            [[color("BBBBBB"), comment("Raw payload (unrecognized type)")]];
    }

    // --- Optional CRC32 ---
    if (hdr.flags.has_checksum == 1) {
        u32 crc32 [[format("hex"), color("66DD66"),
                     comment("Payload CRC32 (integrity check)")]];
    }
};

// ────────────────────────────────────────────
//  Structure: FileFooter (16 bytes)
// ────────────────────────────────────────────
// The footer closes the file and provides integrity
// verification fields: the packet count (must match
// FileHeader.packet_count), the total number of
// captured payload bytes, and an end magic.

struct FileFooter {
    u32  total_payload_bytes [[format("hex"),
                               comment("Sum of all packets' payload_length")]];
    u32  packet_count_check  [[comment("Must match FileHeader.packet_count")]];
    u32  file_crc32          [[format("hex"),
                               comment("CRC32 of entire file excluding footer (global check)")]];
    char magic[4]            [[color("FF8844"),
                               comment("End magic 'TKP\\0' (reverse of 'PKT\\0')")]];
};

// ────────────────────────────────────────────
//  File instantiation
// ────────────────────────────────────────────

// 1. Global header at offset 0
FileHeader file_header @ 0x00;

// 2. Session information right after the header (offset 0x20)
SessionInfo session @ sizeof(file_header);

// 3. Packet array — placed at the offset indicated by the header.
//    Each Packet has a variable size (header + payload + optional
//    CRC), but ImHex handles variable-size structure arrays: it
//    parses each element sequentially, each advancing the cursor
//    by its own size.
Packet packets[file_header.packet_count] @ file_header.data_offset;

// 4. Footer — placed at the offset indicated by the header.
FileFooter file_footer @ file_header.footer_offset;

// ────────────────────────────────────────────
//  Consistency assertions (optional)
// ────────────────────────────────────────────
// These checks produce a warning in the ImHex console
// if values don't match. They don't block parsing but
// signal a potentially corrupted file or a pattern error.

std::print("=== Consistency checks ===");
std::print("  File size             : 0x{:X}", std::mem::size());
std::print("  total_length (header) : 0x{:X}", file_header.total_length);
std::print("  packet_count (header) : {}", file_header.packet_count);
std::print("  packet_count (footer) : {}", file_footer.packet_count_check);

if (file_header.total_length != std::mem::size()) {
    std::print("  [!] WARNING: total_length does not match actual file size");
}

if (file_header.packet_count != file_footer.packet_count_check) {
    std::print("  [!] WARNING: header/footer packet_count mismatch");
}

std::print("=== Parsing completed successfully ===");
