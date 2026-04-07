/*
 * client.c — TCP client for the custom protocol
 *
 * Reverse Engineering Training — Chapter 20
 * MIT License — Strictly educational use
 *
 * Connects to the server, authenticates and sends commands.
 * Students must reverse-engineer the protocol from the server
 * binary alone, then write their own client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "protocol.h"

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

    uint8_t chk = proto_checksum(frame, PROTO_HEADER_SIZE + plen);
    frame[PROTO_HEADER_SIZE + plen] = chk;

    return (send_all(fd, frame, PROTO_HEADER_SIZE + plen + 1) > 0) ? 0 : -1;
}

static int recv_message(int fd, uint8_t *type,
                        uint8_t *payload, uint16_t *plen) {
    uint8_t hdr[PROTO_HEADER_SIZE];
    if (recv_all(fd, hdr, PROTO_HEADER_SIZE) < 0) return -1;

    if (hdr[0] != PROTO_MAGIC_0 || hdr[1] != PROTO_MAGIC_1) return -1;

    *type = hdr[3];
    *plen = read_be16(&hdr[4]);
    if (*plen > PROTO_MAX_PAYLOAD) return -1;

    if (*plen > 0) {
        if (recv_all(fd, payload, *plen) < 0) return -1;
    }

    uint8_t chk_recv;
    if (recv_all(fd, &chk_recv, 1) < 0) return -1;

    return 0;
}

/* Simplified password hash (to be recovered via RE) */
static void compute_password_hash(const char *password, uint8_t *out) {
    memset(out, 0, PROTO_HASH_LEN);
    size_t len = strlen(password);
    uint32_t h = 0x811c9dc5; /* FNV-1a offset basis */

    for (int round = 0; round < PROTO_HASH_LEN; round++) {
        for (size_t i = 0; i < len; i++) {
            h ^= (uint8_t)password[i];
            h *= 0x01000193; /* FNV prime */
        }
        h ^= (uint32_t)round;
        out[round] = (uint8_t)(h & 0xFF);
        h = (h >> 8) | (h << 24);
    }
}

int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    uint16_t port = DEFAULT_PORT;

    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = (uint16_t)atoi(argv[2]);

    printf("[cli] Connecting to %s:%d...\n", host, port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(fd); return 1;
    }

    printf("[cli] Connected.\n");

    /* --- Authentication --- */
    auth_req_payload_t auth_req;
    memset(&auth_req, 0, sizeof(auth_req));
    strncpy(auth_req.username, "admin", sizeof(auth_req.username) - 1);
    compute_password_hash("s3cr3t_p4ss!", auth_req.password_hash);

    send_message(fd, MSG_AUTH_REQ,
                 (uint8_t *)&auth_req, sizeof(auth_req));

    uint8_t  resp_payload[PROTO_MAX_PAYLOAD];
    uint8_t  resp_type;
    uint16_t resp_len;

    if (recv_message(fd, &resp_type, resp_payload, &resp_len) < 0) {
        fprintf(stderr, "[cli] Auth receive error\n");
        close(fd); return 1;
    }

    auth_resp_payload_t *auth_resp = (auth_resp_payload_t *)resp_payload;
    if (!auth_resp->success) {
        fprintf(stderr, "[cli] Authentication failed\n");
        close(fd); return 1;
    }
    printf("[cli] Authenticated! Token received.\n");

    uint8_t token[PROTO_TOKEN_LEN];
    memcpy(token, auth_resp->token, PROTO_TOKEN_LEN);

    /* --- Send CMD_GET_INFO --- */
    uint8_t cmd_buf[sizeof(cmd_req_header_t)];
    cmd_req_header_t *cmd = (cmd_req_header_t *)cmd_buf;
    memcpy(cmd->token, token, PROTO_TOKEN_LEN);
    cmd->cmd_id = CMD_GET_INFO;
    write_be16((uint8_t *)&cmd->arg_len, 0);

    send_message(fd, MSG_CMD_REQ, cmd_buf, sizeof(cmd_req_header_t));

    if (recv_message(fd, &resp_type, resp_payload, &resp_len) == 0) {
        resp_payload[resp_len] = '\0';
        printf("[cli] Server info: %s\n", (char *)resp_payload);
    }

    /* --- Send CMD_LIST_FILES --- */
    cmd->cmd_id = CMD_LIST_FILES;
    send_message(fd, MSG_CMD_REQ, cmd_buf, sizeof(cmd_req_header_t));

    if (recv_message(fd, &resp_type, resp_payload, &resp_len) == 0) {
        resp_payload[resp_len] = '\0';
        printf("[cli] Files:\n%s\n", (char *)resp_payload);
    }

    /* --- Send CMD_READ_FILE --- */
    cmd->cmd_id = CMD_READ_FILE;
    send_message(fd, MSG_CMD_REQ, cmd_buf, sizeof(cmd_req_header_t));

    if (recv_message(fd, &resp_type, resp_payload, &resp_len) == 0) {
        resp_payload[resp_len] = '\0';
        printf("[cli] Content: %s", (char *)resp_payload);
    }

    /* --- Ping --- */
    send_message(fd, MSG_PING, NULL, 0);
    if (recv_message(fd, &resp_type, resp_payload, &resp_len) == 0) {
        printf("[cli] Pong received!\n");
    }

    /* --- Disconnect --- */
    send_message(fd, MSG_DISCONNECT, NULL, 0);
    printf("[cli] Disconnected.\n");

    close(fd);
    return 0;
}
