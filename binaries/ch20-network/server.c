/*
 * server.c — TCP server with custom binary protocol
 *
 * Reverse Engineering Training — Chapter 20
 * MIT License — Strictly educational use
 *
 * Listens on port 4337, accepts one client at a time.
 * Authentication by username + hash, then command execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include "protocol.h"

#define BACKLOG 1

/* Hardcoded credentials (to be recovered via RE) */
static const char *VALID_USER = "admin";
static const uint8_t VALID_HASH[PROTO_HASH_LEN] = {
    0xa7, 0x5f, 0x5a, 0x35, 0x8f, 0xc1, 0xbc, 0x8e,
    0xab, 0xa8, 0x4f, 0xd3, 0xc7, 0x6d, 0xb6, 0x8e,
    0xa1, 0xe6, 0xab, 0x71, 0xef, 0x77, 0x5c, 0x2f,
    0x82, 0x04, 0xf8, 0xcd, 0xbc, 0x07, 0x47, 0x2d
};

static uint8_t session_token[PROTO_TOKEN_LEN];
static int     authenticated = 0;

static void generate_token(uint8_t *token) {
    /* Pseudo-random token (intentionally weak for RE) */
    uint32_t seed = 0xCAFEBABE;
    for (int i = 0; i < PROTO_TOKEN_LEN; i++) {
        seed = seed * 1103515245 + 12345;
        token[i] = (uint8_t)((seed >> 16) & 0xFF);
    }
}

static ssize_t send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

static ssize_t recv_all(int fd, uint8_t *buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(fd, buf + received, len - received, 0);
        if (n <= 0) return -1;
        received += (size_t)n;
    }
    return (ssize_t)received;
}

static int send_message(int fd, uint8_t type,
                        const uint8_t *payload, uint16_t plen) {
    uint8_t frame[PROTO_HEADER_SIZE + PROTO_MAX_PAYLOAD + 1];
    frame[0] = PROTO_MAGIC_0;
    frame[1] = PROTO_MAGIC_1;
    frame[2] = PROTO_VERSION;
    frame[3] = type;
    write_be16(&frame[4], plen);

    if (plen > 0)
        memcpy(&frame[PROTO_HEADER_SIZE], payload, plen);

    /* Checksum over header + payload */
    uint8_t chk = proto_checksum(frame, PROTO_HEADER_SIZE + plen);
    frame[PROTO_HEADER_SIZE + plen] = chk;

    return (send_all(fd, frame, PROTO_HEADER_SIZE + plen + 1) > 0) ? 0 : -1;
}

static int recv_message(int fd, uint8_t *type,
                        uint8_t *payload, uint16_t *plen) {
    uint8_t hdr[PROTO_HEADER_SIZE];
    if (recv_all(fd, hdr, PROTO_HEADER_SIZE) < 0) return -1;

    if (hdr[0] != PROTO_MAGIC_0 || hdr[1] != PROTO_MAGIC_1) {
        fprintf(stderr, "[srv] Invalid magic\n");
        return -1;
    }
    if (hdr[2] != PROTO_VERSION) {
        fprintf(stderr, "[srv] Unsupported version: 0x%02x\n", hdr[2]);
        return -1;
    }

    *type = hdr[3];
    *plen = read_be16(&hdr[4]);

    if (*plen > PROTO_MAX_PAYLOAD) return -1;

    if (*plen > 0) {
        if (recv_all(fd, payload, *plen) < 0) return -1;
    }

    /* Read and verify the checksum */
    uint8_t chk_recv;
    if (recv_all(fd, &chk_recv, 1) < 0) return -1;

    uint8_t chk_calc = proto_checksum(hdr, PROTO_HEADER_SIZE);
    if (*plen > 0)
        chk_calc ^= proto_checksum(payload, *plen);

    if (chk_recv != chk_calc) {
        fprintf(stderr, "[srv] Invalid checksum\n");
        return -1;
    }

    return 0;
}

static void handle_auth(int fd, const uint8_t *payload, uint16_t plen) {
    auth_resp_payload_t resp;
    memset(&resp, 0, sizeof(resp));

    if (plen < sizeof(auth_req_payload_t)) {
        resp.success = 0;
        send_message(fd, MSG_AUTH_RESP, (uint8_t *)&resp, sizeof(resp));
        return;
    }

    const auth_req_payload_t *req = (const auth_req_payload_t *)payload;

    if (strncmp(req->username, VALID_USER, 32) == 0 &&
        memcmp(req->password_hash, VALID_HASH, PROTO_HASH_LEN) == 0) {
        generate_token(session_token);
        resp.success = 1;
        memcpy(resp.token, session_token, PROTO_TOKEN_LEN);
        authenticated = 1;
        printf("[srv] Auth OK for '%s'\n", req->username);
    } else {
        resp.success = 0;
        printf("[srv] Auth FAIL for '%.*s'\n", 32, req->username);
    }

    send_message(fd, MSG_AUTH_RESP, (uint8_t *)&resp, sizeof(resp));
}

static void handle_cmd(int fd, const uint8_t *payload, uint16_t plen) {
    if (plen < sizeof(cmd_req_header_t)) return;
    const cmd_req_header_t *hdr = (const cmd_req_header_t *)payload;

    /* Verify the token */
    if (!authenticated ||
        memcmp(hdr->token, session_token, PROTO_TOKEN_LEN) != 0) {
        const char *err = "ERR:NOT_AUTH";
        send_message(fd, MSG_CMD_RESP,
                     (const uint8_t *)err, (uint16_t)strlen(err));
        return;
    }

    switch (hdr->cmd_id) {
    case CMD_ECHO: {
        uint16_t arg_len = read_be16((const uint8_t *)&hdr->arg_len);
        const uint8_t *args = payload + sizeof(cmd_req_header_t);
        send_message(fd, MSG_CMD_RESP, args, arg_len);
        break;
    }
    case CMD_GET_INFO: {
        const char *info =
            "KeyGenMe Training Server v1.0 -- RE Training GCC";
        send_message(fd, MSG_CMD_RESP,
                     (const uint8_t *)info, (uint16_t)strlen(info));
        break;
    }
    case CMD_LIST_FILES: {
        const char *files = "config.dat\nusers.db\nsecret.key\nlog.txt";
        send_message(fd, MSG_CMD_RESP,
                     (const uint8_t *)files, (uint16_t)strlen(files));
        break;
    }
    case CMD_READ_FILE: {
        const char *content = "FLAG{pr0t0c0l_r3v3rs3d_gcc}\n";
        send_message(fd, MSG_CMD_RESP,
                     (const uint8_t *)content, (uint16_t)strlen(content));
        break;
    }
    default: {
        const char *err = "ERR:UNKNOWN_CMD";
        send_message(fd, MSG_CMD_RESP,
                     (const uint8_t *)err, (uint16_t)strlen(err));
        break;
    }
    }
}

static void handle_client(int client_fd) {
    uint8_t  payload[PROTO_MAX_PAYLOAD];
    uint8_t  type;
    uint16_t plen;

    authenticated = 0;
    printf("[srv] Client connected\n");

    while (recv_message(client_fd, &type, payload, &plen) == 0) {
        switch (type) {
        case MSG_AUTH_REQ:
            handle_auth(client_fd, payload, plen);
            break;
        case MSG_CMD_REQ:
            handle_cmd(client_fd, payload, plen);
            break;
        case MSG_PING:
            send_message(client_fd, MSG_PONG, NULL, 0);
            break;
        case MSG_DISCONNECT:
            printf("[srv] Client disconnected cleanly\n");
            return;
        default:
            fprintf(stderr, "[srv] Unknown type: 0x%02x\n", type);
            break;
        }
    }
    printf("[srv] Client disconnected\n");
}

int main(void) {
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(DEFAULT_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv_fd); return 1;
    }
    if (listen(srv_fd, BACKLOG) < 0) {
        perror("listen"); close(srv_fd); return 1;
    }

    printf("[srv] Listening on port %d...\n", DEFAULT_PORT);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(srv_fd,
                            (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) { perror("accept"); continue; }

        handle_client(cli_fd);
        close(cli_fd);
    }

    close(srv_fd);
    return 0;
}
