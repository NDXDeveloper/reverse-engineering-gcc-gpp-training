/**
 * binaries/ch13-network/server.c
 *
 * Training server using the custom GCRP protocol.
 * Listens on port 4444, handles one client at a time.
 *
 * Compilation: see Makefile
 * Usage:       ./server_O0 [port]
 *
 * MIT License — strictly educational use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"

/* ═══════════════════════════════════════════════
 * Resource data (responses to MSG_DATA_REQ)
 * ═══════════════════════════════════════════════ */

static const char *resources[] = {
    [0] = "FLAG{fr1da_h00k5_ar3_p0w3rful}",
    [1] = "This is confidential resource #1.",
    [2] = "AES-256-CBC key: 0xDEADBEEF (fake, for the exercise).",
    [3] = "Simulated binary data for reverse engineering.",
};
#define NUM_RESOURCES 4

/* ═══════════════════════════════════════════════
 * GCRP packet send / receive
 * ═══════════════════════════════════════════════ */

/**
 * Sends exactly `len` bytes on the socket.
 * Handles partial sends (short writes).
 */
static int send_all(int sock, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = send(sock, p, remaining, 0);
        if (n <= 0) return -1;
        p += n;
        remaining -= n;
    }
    return 0;
}

/**
 * Receives exactly `len` bytes from the socket.
 */
static int recv_all(int sock, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = recv(sock, p, remaining, 0);
        if (n <= 0) return -1;
        p += n;
        remaining -= n;
    }
    return 0;
}

/**
 * Sends a complete GCRP packet (header + payload).
 */
static int send_packet(int sock, uint8_t type,
                       const void *payload, uint16_t payload_len) {
    gcrp_header_t hdr;
    memcpy(hdr.magic, GCRP_MAGIC, 4);
    hdr.type = type;
    put_u16_be((uint8_t *)&hdr.payload_len, payload_len);

    if (send_all(sock, &hdr, GCRP_HEADER_SIZE) < 0) return -1;
    if (payload_len > 0 && payload) {
        if (send_all(sock, payload, payload_len) < 0) return -1;
    }
    return 0;
}

/**
 * Receives a GCRP packet. Fills `type`, `payload` and `payload_len`.
 * Returns 0 on success, -1 on error.
 */
static int recv_packet(int sock, uint8_t *type,
                       void *payload, uint16_t *payload_len) {
    gcrp_header_t hdr;
    if (recv_all(sock, &hdr, GCRP_HEADER_SIZE) < 0) return -1;

    /* Verify magic */
    if (memcmp(hdr.magic, GCRP_MAGIC, 4) != 0) {
        fprintf(stderr, "[!] Invalid magic: %02x %02x %02x %02x\n",
                (uint8_t)hdr.magic[0], (uint8_t)hdr.magic[1],
                (uint8_t)hdr.magic[2], (uint8_t)hdr.magic[3]);
        return -1;
    }

    *type = hdr.type;
    *payload_len = get_u16_be((const uint8_t *)&hdr.payload_len);

    if (*payload_len > GCRP_MAX_PAYLOAD) {
        fprintf(stderr, "[!] Payload too large: %u\n", *payload_len);
        return -1;
    }

    if (*payload_len > 0) {
        if (recv_all(sock, payload, *payload_len) < 0) return -1;
    }

    return 0;
}

/* ═══════════════════════════════════════════════
 * Message handlers
 * ═══════════════════════════════════════════════ */

static uint32_t current_session_id = 0;
static int authenticated = 0;

/**
 * Handles an authentication request.
 */
static int handle_auth(int sock, const void *payload, uint16_t len) {
    if (len < sizeof(auth_req_payload_t)) {
        fprintf(stderr, "[!] AUTH_REQ payload too small (%u)\n", len);
        return -1;
    }

    const auth_req_payload_t *req = (const auth_req_payload_t *)payload;
    printf("[*] AUTH_REQ: user=\"%s\" timestamp=%u\n",
           req->username, req->timestamp);

    auth_resp_payload_t resp;
    memset(&resp, 0, sizeof(resp));

    /* Verify the token */
    size_t ulen = strnlen(req->username, 32);
    if (ulen == 0 || !verify_token(req->username, req->token, ulen)) {
        resp.result = AUTH_FAILED;
        strncpy(resp.message, "Authentication failed: invalid token.", 63);
        printf("[*] AUTH_RESP: FAILED\n");
    } else {
        /* Generate a pseudo-random session ID */
        current_session_id = (uint32_t)(time(NULL) ^ 0xCAFEBABE);
        authenticated = 1;

        resp.result = AUTH_OK;
        resp.session_id = current_session_id;
        snprintf(resp.message, 63, "Welcome, %s. Session %08X.",
                 req->username, current_session_id);
        printf("[*] AUTH_RESP: OK session=%08X\n", current_session_id);
    }

    return send_packet(sock, MSG_AUTH_RESP, &resp, sizeof(resp));
}

/**
 * Handles a ping.
 */
static int handle_ping(int sock, const void *payload, uint16_t len) {
    if (len < sizeof(ping_payload_t)) return -1;

    const ping_payload_t *ping = (const ping_payload_t *)payload;
    printf("[*] PING seq=%u\n", ping->seq);

    pong_payload_t pong;
    pong.seq = ping->seq;
    pong.server_time = (uint32_t)time(NULL);

    return send_packet(sock, MSG_PONG, &pong, sizeof(pong));
}

/**
 * Handles a data request.
 */
static int handle_data_req(int sock, const void *payload, uint16_t len) {
    if (len < sizeof(data_req_payload_t)) return -1;

    const data_req_payload_t *req = (const data_req_payload_t *)payload;
    printf("[*] DATA_REQ: session=%08X resource=%u\n",
           req->session_id, req->resource_id);

    /* Verify session */
    if (!authenticated || req->session_id != current_session_id) {
        const char *err = "Not authenticated or invalid session.";
        return send_packet(sock, MSG_ERROR, err, strlen(err));
    }

    /* Verify resource ID */
    if (req->resource_id >= NUM_RESOURCES) {
        const char *err = "Unknown resource ID.";
        return send_packet(sock, MSG_ERROR, err, strlen(err));
    }

    /* Build the response */
    data_resp_payload_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.resource_id = req->resource_id;

    const char *content = resources[req->resource_id];
    size_t clen = strlen(content);
    if (clen > sizeof(resp.data)) clen = sizeof(resp.data);

    put_u16_be((uint8_t *)&resp.data_len, (uint16_t)clen);
    memcpy(resp.data, content, clen);

    /* Send: resource_id(1) + data_len(2) + data(clen) */
    uint16_t resp_len = 1 + 2 + (uint16_t)clen;
    return send_packet(sock, MSG_DATA_RESP, &resp, resp_len);
}

/* ═══════════════════════════════════════════════
 * Server main loop
 * ═══════════════════════════════════════════════ */

static void handle_client(int client_sock, struct sockaddr_in *client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));
    printf("\n[+] Client connected: %s:%d\n", client_ip, ntohs(client_addr->sin_port));

    authenticated = 0;
    current_session_id = 0;

    uint8_t payload[GCRP_MAX_PAYLOAD];
    uint8_t type;
    uint16_t payload_len;

    while (1) {
        if (recv_packet(client_sock, &type, payload, &payload_len) < 0) {
            printf("[-] Connection lost or protocol error.\n");
            break;
        }

        switch (type) {
            case MSG_AUTH_REQ:
                if (handle_auth(client_sock, payload, payload_len) < 0) goto done;
                break;

            case MSG_PING:
                if (handle_ping(client_sock, payload, payload_len) < 0) goto done;
                break;

            case MSG_DATA_REQ:
                if (handle_data_req(client_sock, payload, payload_len) < 0) goto done;
                break;

            case MSG_GOODBYE:
                printf("[*] GOODBYE received. Closing session.\n");
                goto done;

            default:
                fprintf(stderr, "[!] Unknown message type: 0x%02x\n", type);
                const char *err = "Unknown message type.";
                send_packet(client_sock, MSG_ERROR, err, strlen(err));
                break;
        }
    }

done:
    close(client_sock);
    printf("[-] Client disconnected.\n");
}

int main(int argc, char *argv[]) {
    uint16_t port = GCRP_PORT;
    if (argc > 1) {
        port = (uint16_t)atoi(argv[1]);
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 1) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }

    printf("=== GCRP Server v1.0 ===\n");
    printf("[*] Listening on port %u...\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr,
                                 &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }
        handle_client(client_sock, &client_addr);
    }

    close(server_sock);
    return 0;
}
