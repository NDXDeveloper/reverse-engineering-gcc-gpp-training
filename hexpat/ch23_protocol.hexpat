/*!
 * hexpat/ch23_protocol.hexpat
 * ImHex pattern for the ch23-network custom protocol
 *
 * Reverse Engineering Training — Chapter 23
 * Reconstructed by reverse engineering the server and client binaries.
 *
 * ┌─────────────────────────────────────────────────────────┐
 * │  Usage                                                  │
 * │                                                         │
 * │  1. Capture a session with Wireshark:                   │
 * │     - Filter: tcp.port == 4444                          │
 * │     - Analyze → Follow → TCP Stream                     │
 * │     - Show data as: Raw → Save as: ch23_stream.bin      │
 * │                                                         │
 * │  2. Open ch23_stream.bin in ImHex                       │
 * │                                                         │
 * │  3. Load this file in the Pattern Editor (▶)            │
 * │                                                         │
 * │  Result: each message is decoded, colorized and         │
 * │  annotated in the hex view and the Pattern Data         │
 * │  panel.                                                 │
 * └─────────────────────────────────────────────────────────┘
 *
 * Reconstructed protocol:
 *
 *   Header (4 bytes, common to all messages):
 *     [magic:1 = 0xC0] [msg_type:1] [payload_len:2 big-endian]
 *
 *   msg_type convention:
 *     bit 7 = 0 → request  (client → server): 0x01–0x04
 *     bit 7 = 1 → response (server → client): 0x81–0x84
 *     0xFF      → server error
 *
 *   Protocol sequence:
 *     HELLO_REQ  (0x01) → HELLO_RESP (0x81)  + 8-byte challenge
 *     AUTH_REQ   (0x02) → AUTH_RESP  (0x82)  password XOR-ed with challenge
 *     CMD_REQ    (0x03) → CMD_RESP   (0x83)  commands: PING/LIST/READ/INFO
 *     QUIT_REQ   (0x04) → QUIT_RESP  (0x84)  clean disconnect
 *
 *   Commands (first byte of CMD_REQ payload):
 *     0x01 = PING   → response "PONG"
 *     0x02 = LIST   → file list [count][idx,nlen,name]*
 *     0x03 = READ   → file content by index
 *     0x04 = INFO   → server information
 *
 * Associated files:
 *   - binaries/ch23-network/server.c   — server source code
 *   - binaries/ch23-network/client.c   — client source code
 *   - 23-network/03-frames-imhex-hexpat.md — tutorial section
 *
 * MIT License — Strictly educational use.
 */

#pragma endian big
#pragma pattern_limit 1024

import std.io;
import std.mem;

// ═══════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════

#define PROTO_MAGIC    0xC0
#define CHALLENGE_LEN  8

// ═══════════════════════════════════════════
//  Enums
// ═══════════════════════════════════════════

enum MsgType : u8 {
    HELLO_REQ    = 0x01,
    AUTH_REQ     = 0x02,
    CMD_REQ      = 0x03,
    QUIT_REQ     = 0x04,
    HELLO_RESP   = 0x81,
    AUTH_RESP    = 0x82,
    CMD_RESP     = 0x83,
    QUIT_RESP    = 0x84,
    ERROR        = 0xFF
};

enum AuthStatus : u8 {
    AUTH_FAIL = 0x00,
    AUTH_OK   = 0x01
};

enum CmdId : u8 {
    CMD_PING = 0x01,
    CMD_LIST = 0x02,
    CMD_READ = 0x03,
    CMD_INFO = 0x04
};

enum ErrCode : u8 {
    ERR_BAD_MAGIC          = 0x01,
    ERR_BAD_TYPE           = 0x02,
    ERR_WRONG_STATE        = 0x03,
    ERR_AUTH_FAIL          = 0x04,
    ERR_BAD_CMD            = 0x05,
    ERR_PAYLOAD_TOO_LARGE  = 0x06
};

// ═══════════════════════════════════════════
//  Base structures
// ═══════════════════════════════════════════

/*!
 * Length-prefixed string (1 byte).
 * Used in the AUTH payload for username and password.
 *
 * Format: [len:1][data:len]
 */
struct LPString {
    u8   len                           [[color("AAAAAA")]];
    char value[len]                    [[color("FFD93D")]];
} [[format("format_lpstring")]];

fn format_lpstring(LPString s) {
    return std::format("\"{}\" ({} bytes)", s.value, s.len);
};

/*!
 * File entry in the LIST response.
 *
 * Format: [index:1][name_len:1][name:name_len]
 */
struct FileEntry {
    u8   index                         [[color("45B7D1")]];
    u8   name_len                      [[color("AAAAAA")]];
    char name[name_len]                [[color("A8E6CF")]];
} [[format("format_file_entry")]];

fn format_file_entry(FileEntry f) {
    return std::format("[{}] \"{}\"", f.index, f.name);
};

// ═══════════════════════════════════════════
//  Protocol header (4 fixed bytes)
// ═══════════════════════════════════════════

/*!
 * Common header for all messages.
 *
 *  Offset  Size   Field
 *  0       1      Magic byte (always 0xC0)
 *  1       1      Message type (see MsgType enum)
 *  2       2      Payload length in big-endian
 */
struct ProtoHeader {
    u8      magic                      [[color("FF6B6B")]];
    MsgType msg_type                   [[color("4ECDC4")]];
    u16     payload_len                [[color("45B7D1")]];
} [[static, format("format_header")]];

fn format_header(ProtoHeader h) {
    return std::format("[0x{:02X}] {} — {} bytes",
                       h.magic, h.msg_type, h.payload_len);
};

// ═══════════════════════════════════════════
//  Payloads — Requests (client → server)
// ═══════════════════════════════════════════

/*!
 * HELLO Request (type 0x01)
 *
 * Payload: "HELLO" (5 bytes) + padding (3 zero bytes)
 * Total payload_len = 8
 */
struct HelloPayload {
    char identifier[5]                 [[color("A8E6CF")]];

    if (parent.header.payload_len > 5) {
        u8 padding[parent.header.payload_len - 5]
                                       [[color("808080")]];
    }
};

/*!
 * AUTH Request (type 0x02)
 *
 * Payload: two length-prefixed strings:
 *   [user_len:1][username:N][pass_len:1][password_xored:M]
 *
 * The password is XOR-ed with the challenge (8 bytes)
 * received in HELLO_RESP. Cyclic XOR: pass[i] ^= challenge[i % 8].
 */
struct AuthRequestPayload {
    LPString username;
    LPString password;                 // XOR-ed with the challenge!
};

/*!
 * CMD Request (type 0x03)
 *
 * Payload: [command_id:1][args:N]
 *   command_id: PING=0x01, LIST=0x02, READ=0x03, INFO=0x04
 *   args      : depends on the command (e.g.: READ → [file_index:1])
 */
struct CmdRequestPayload {
    CmdId command_id                   [[color("4ECDC4")]];

    if (parent.header.payload_len > 1) {
        u8 args[parent.header.payload_len - 1]
                                       [[color("FFD93D")]];
    }
};

// ═══════════════════════════════════════════
//  Payloads — Responses (server → client)
// ═══════════════════════════════════════════

/*!
 * HELLO Response (type 0x81)
 *
 * Payload: "WELCOME" (7 bytes) + challenge (8 random bytes)
 * Total payload_len = 15 (0x0F)
 *
 * The challenge is generated by getrandom() server-side and changes
 * with each connection. It is used to XOR the password in AUTH_REQ.
 */
struct WelcomePayload {
    char banner[7]                     [[color("A8E6CF")]];
    u8   challenge[CHALLENGE_LEN]      [[color("C9B1FF")]];

    // Absorb any extra bytes if payload_len > 15
    if (parent.header.payload_len > 7 + CHALLENGE_LEN) {
        u8 extra[parent.header.payload_len - 7 - CHALLENGE_LEN]
                                       [[color("808080")]];
    }
};

/*!
 * AUTH Response (type 0x82)
 *
 * Payload (2 bytes):
 *   [reserved:1 = 0x00][status:1]
 *   status: 0x00 = AUTH_FAIL, 0x01 = AUTH_OK
 */
struct AuthResponsePayload {
    u8         reserved                [[color("808080")]];
    AuthStatus status                  [[color("FF6B6B")]];
};

/*!
 * CMD Response (type 0x83)
 *
 * Payload: [status:1][data:N]
 *   status = 0x01 (OK) or 0x00 (FAIL)
 *   data   = depends on the command:
 *     PING → "PONG" (4 bytes)
 *     LIST → [count:1][FileEntry]*
 *     READ → file content (plain text)
 *     INFO → server information (plain text)
 */
struct CmdResponsePayload {
    u8 status_code                     [[color("4ECDC4")]];

    if (parent.header.payload_len > 1) {
        u8 data[parent.header.payload_len - 1]
                                       [[color("A8E6CF")]];
    }
};

/*!
 * QUIT Response (type 0x84)
 *
 * Payload: "BYE" (3 bytes)
 */
struct QuitResponsePayload {
    char message[parent.header.payload_len]
                                       [[color("A8E6CF")]];
};

/*!
 * ERROR (type 0xFF)
 *
 * Payload: [error_code:1][error_message:N]
 *   error_code   : see ErrCode enum
 *   error_message: ASCII text describing the error
 */
struct ErrorPayload {
    ErrCode error_code                 [[color("FF6B6B")]];

    if (parent.header.payload_len > 1) {
        char error_message[parent.header.payload_len - 1]
                                       [[color("FFAAAA")]];
    }
};

/*!
 * Generic payload for unrecognized types.
 * Reads raw bytes without interpretation.
 */
struct GenericPayload {
    u8 data[parent.header.payload_len] [[color("CCCCCC")]];
};

// ═══════════════════════════════════════════
//  Complete message (header + payload)
// ═══════════════════════════════════════════

struct ProtoMessage {
    ProtoHeader header;

    // Magic byte validation — signals a stream misalignment
    std::assert(header.magic == PROTO_MAGIC,
                "Invalid magic byte — stream may be misaligned");

    if (header.payload_len > 0) {
        match (header.msg_type) {
            // Requests (client → server)
            (MsgType::HELLO_REQ):    HelloPayload          payload;
            (MsgType::AUTH_REQ):     AuthRequestPayload    payload;
            (MsgType::CMD_REQ):      CmdRequestPayload     payload;
            // QUIT_REQ has an empty payload (payload_len == 0),
            // so this branch is never reached — this is expected.
            (MsgType::QUIT_REQ):     GenericPayload        payload;

            // Responses (server → client)
            (MsgType::HELLO_RESP):   WelcomePayload        payload;
            (MsgType::AUTH_RESP):    AuthResponsePayload   payload;
            (MsgType::CMD_RESP):     CmdResponsePayload    payload;
            (MsgType::QUIT_RESP):    QuitResponsePayload   payload;

            // Error
            (MsgType::ERROR):        ErrorPayload          payload;

            // Unknown type — generic fallback
            (_):                     GenericPayload        payload;
        }
    }
} [[format("format_message")]];

fn format_message(ProtoMessage m) {
    // Indicate direction for easier reading
    str direction;
    if (u8(m.header.msg_type) == 0xFF) {
        direction = "ERR";
    } else if ((u8(m.header.msg_type) & 0x80) != 0) {
        direction = "S→C";
    } else {
        direction = "C→S";
    }

    return std::format("[{}] {} — {} bytes payload",
                       direction, m.header.msg_type,
                       m.header.payload_len);
};

// ═══════════════════════════════════════════
//  Entry point — decode the entire stream
// ═══════════════════════════════════════════

ProtoMessage messages[while($ < std::mem::size())] @ 0x00;
