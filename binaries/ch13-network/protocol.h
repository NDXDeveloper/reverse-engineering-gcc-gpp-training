/**
 * binaries/ch13-network/protocol.h
 *
 * Definition of the custom "GCRP" protocol (GCC-RE Protocol)
 * used between the training client and server.
 *
 * Packet format:
 * ┌──────────┬─────────┬──────────┬──────────────────────┐
 * │ magic(4) │ type(1) │ len(2)   │ payload(0..1024)     │
 * └──────────┴─────────┴──────────┴──────────────────────┘
 *
 * - magic   : 4 bytes, always "GCRP" (0x47 0x43 0x52 0x50)
 * - type    : 1 byte, message type identifier
 * - len     : 2 bytes, big-endian, payload size
 * - payload : 0 to 1024 bytes, variable content depending on type
 *
 * MIT License — strictly educational use.
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* ═══════════════════════════════════════════════
 * Protocol constants
 * ═══════════════════════════════════════════════ */

#define GCRP_MAGIC        "GCRP"
#define GCRP_MAGIC_U32    0x50524347   /* "GCRP" in little-endian x86 */
#define GCRP_HEADER_SIZE  7            /* magic(4) + type(1) + len(2) */
#define GCRP_MAX_PAYLOAD  1024
#define GCRP_PORT         4444
#define GCRP_AUTH_KEY     0xA5         /* XOR key for token encoding */

/* ═══════════════════════════════════════════════
 * Message types
 * ═══════════════════════════════════════════════ */

#define MSG_AUTH_REQ      0x01   /* Client → Server: authentication request    */
#define MSG_AUTH_RESP     0x02   /* Server → Client: authentication response   */
#define MSG_PING          0x03   /* Client → Server: heartbeat                 */
#define MSG_PONG          0x04   /* Server → Client: heartbeat response        */
#define MSG_DATA_REQ      0x05   /* Client → Server: data request              */
#define MSG_DATA_RESP     0x06   /* Server → Client: response with data        */
#define MSG_GOODBYE       0x07   /* Client → Server: end of session            */
#define MSG_ERROR         0xFF   /* Server → Client: error                     */

/* ═══════════════════════════════════════════════
 * Authentication result codes
 * ═══════════════════════════════════════════════ */

#define AUTH_OK           0x00
#define AUTH_FAILED       0x01
#define AUTH_EXPIRED      0x02

/* ═══════════════════════════════════════════════
 * Protocol structures
 * ═══════════════════════════════════════════════ */

#pragma pack(push, 1)

/**
 * Common header for all GCRP packets.
 */
typedef struct {
    char     magic[4];      /* "GCRP"                              */
    uint8_t  type;          /* MSG_AUTH_REQ, MSG_PING, etc.        */
    uint16_t payload_len;   /* big-endian, payload size            */
} gcrp_header_t;

/**
 * Authentication request payload (MSG_AUTH_REQ).
 * The token is the username XOR-ed byte by byte with GCRP_AUTH_KEY.
 */
typedef struct {
    char    username[32];   /* username, null-terminated            */
    uint8_t token[32];      /* username XOR GCRP_AUTH_KEY           */
    uint32_t timestamp;     /* Unix timestamp (little-endian)      */
} auth_req_payload_t;

/**
 * Authentication response payload (MSG_AUTH_RESP).
 */
typedef struct {
    uint8_t  result;        /* AUTH_OK, AUTH_FAILED, AUTH_EXPIRED   */
    uint32_t session_id;    /* session identifier (if AUTH_OK)     */
    char     message[64];   /* human-readable message              */
} auth_resp_payload_t;

/**
 * Ping payload (MSG_PING).
 */
typedef struct {
    uint32_t seq;           /* sequence number                     */
    uint32_t timestamp;     /* Unix timestamp                      */
} ping_payload_t;

/**
 * Pong payload (MSG_PONG).
 */
typedef struct {
    uint32_t seq;           /* sequence number (ping echo)         */
    uint32_t server_time;   /* server timestamp                    */
} pong_payload_t;

/**
 * Data request payload (MSG_DATA_REQ).
 */
typedef struct {
    uint32_t session_id;    /* session identifier                  */
    uint8_t  resource_id;   /* requested resource identifier       */
} data_req_payload_t;

/**
 * Data response payload (MSG_DATA_RESP).
 */
typedef struct {
    uint8_t  resource_id;
    uint16_t data_len;      /* big-endian                          */
    char     data[512];     /* resource content                    */
} data_resp_payload_t;

#pragma pack(pop)

/* ═══════════════════════════════════════════════
 * Inline helpers
 * ═══════════════════════════════════════════════ */

/**
 * Encodes a uint16 in big-endian into a buffer.
 */
static inline void put_u16_be(uint8_t *dst, uint16_t val) {
    dst[0] = (val >> 8) & 0xFF;
    dst[1] = val & 0xFF;
}

/**
 * Decodes a big-endian uint16 from a buffer.
 */
static inline uint16_t get_u16_be(const uint8_t *src) {
    return ((uint16_t)src[0] << 8) | (uint16_t)src[1];
}

/**
 * Encodes the authentication token: XOR of username with the key.
 */
static inline void encode_token(const char *username, uint8_t *token, size_t len) {
    for (size_t i = 0; i < len; i++) {
        token[i] = (uint8_t)username[i] ^ GCRP_AUTH_KEY;
    }
}

/**
 * Verifies the authentication token.
 * Returns 1 if valid, 0 otherwise.
 */
static inline int verify_token(const char *username, const uint8_t *token, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (((uint8_t)username[i] ^ GCRP_AUTH_KEY) != token[i]) {
            return 0;
        }
    }
    return 1;
}

#endif /* PROTOCOL_H */
