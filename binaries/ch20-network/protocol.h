 /*
 * protocol.h — Custom client/server protocol definition
 *
 * Reverse Engineering Training — Chapter 20
 * MIT License — Strictly educational use
 *
 * Simple binary protocol:
 *   [magic 2B][version 1B][type 1B][payload_len 2B (BE)][payload NB][checksum 1B]
 *
 * Message types:
 *   0x01 AUTH_REQ   — client sends username + hash
 *   0x02 AUTH_RESP  — server responds OK/FAIL + token
 *   0x03 CMD_REQ    — client sends a command
 *   0x04 CMD_RESP   — server responds with data
 *   0x05 PING       — keepalive
 *   0x06 PONG       — keepalive response
 *   0xFF DISCONNECT — end of session
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define PROTO_MAGIC_0       0xC0
#define PROTO_MAGIC_1       0xFE
#define PROTO_VERSION       0x01
#define PROTO_MAX_PAYLOAD   1024
#define PROTO_HEADER_SIZE   6
#define PROTO_TOKEN_LEN     16
#define PROTO_HASH_LEN      32

#define DEFAULT_PORT        4337

/* Message types */
typedef enum {
    MSG_AUTH_REQ    = 0x01,
    MSG_AUTH_RESP   = 0x02,
    MSG_CMD_REQ     = 0x03,
    MSG_CMD_RESP    = 0x04,
    MSG_PING        = 0x05,
    MSG_PONG        = 0x06,
    MSG_DISCONNECT  = 0xFF
} msg_type_t;

/* Protocol header (serialized in big-endian on the network) */
typedef struct __attribute__((packed)) {
    uint8_t  magic[2];       /* 0xC0 0xFE */
    uint8_t  version;        /* 0x01 */
    uint8_t  type;           /* msg_type_t */
    uint16_t payload_len;    /* big-endian */
} proto_header_t;

/* Payload AUTH_REQ */
typedef struct __attribute__((packed)) {
    char    username[32];
    uint8_t password_hash[PROTO_HASH_LEN]; /* simplified hash */
} auth_req_payload_t;

/* Payload AUTH_RESP */
typedef struct __attribute__((packed)) {
    uint8_t  success;                  /* 0x00 = fail, 0x01 = success */
    uint8_t  token[PROTO_TOKEN_LEN];   /* session token if success */
} auth_resp_payload_t;

/* Payload CMD_REQ */
typedef struct __attribute__((packed)) {
    uint8_t  token[PROTO_TOKEN_LEN];
    uint8_t  cmd_id;
    uint16_t arg_len;    /* big-endian */
    /* followed by arg_len bytes of arguments */
} cmd_req_header_t;

/* Available commands */
typedef enum {
    CMD_LIST_FILES  = 0x01,
    CMD_READ_FILE   = 0x02,
    CMD_GET_INFO    = 0x03,
    CMD_ECHO        = 0x10
} cmd_id_t;

/* --- Protocol utility functions --- */

static inline uint8_t proto_checksum(const uint8_t *data, size_t len) {
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++)
        sum ^= data[i];
    return sum;
}

static inline uint16_t read_be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline void write_be16(uint8_t *p, uint16_t val) {
    p[0] = (uint8_t)(val >> 8);
    p[1] = (uint8_t)(val & 0xFF);
}

#endif /* PROTOCOL_H */
