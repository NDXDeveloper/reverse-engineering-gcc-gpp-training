/**
 * binaries/ch13-network/client.c
 *
 * Training client using the custom GCRP protocol.
 * Connects to the server, authenticates, sends pings,
 * requests resources, then disconnects.
 *
 * Compilation: see Makefile
 * Usage:       ./client_O0 [ip] [port] [username]
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
 * GCRP packet send / receive
 * ═══════════════════════════════════════════════ */

static int send_all(int sock, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = send(sock, p, remaining, 0);
        if (n <= 0) {
            perror("send");
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

static int recv_all(int sock, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = recv(sock, p, remaining, 0);
        if (n <= 0) {
            if (n == 0) fprintf(stderr, "[!] Connection closed by server.\n");
            else perror("recv");
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

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

static int recv_packet(int sock, uint8_t *type,
                       void *payload, uint16_t *payload_len) {
    gcrp_header_t hdr;
    if (recv_all(sock, &hdr, GCRP_HEADER_SIZE) < 0) return -1;

    if (memcmp(hdr.magic, GCRP_MAGIC, 4) != 0) {
        fprintf(stderr, "[!] Invalid response (wrong magic).\n");
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
 * Client logic
 * ═══════════════════════════════════════════════ */

/**
 * Phase 1: Authentication.
 * Builds the XOR token and sends MSG_AUTH_REQ.
 * Returns the session_id on success, 0 otherwise.
 */
static uint32_t do_authenticate(int sock, const char *username) {
    auth_req_payload_t req;
    memset(&req, 0, sizeof(req));

    strncpy(req.username, username, sizeof(req.username) - 1);
    size_t ulen = strlen(req.username);

    /* Encode the token: XOR each byte of username with the key */
    encode_token(req.username, req.token, ulen);

    req.timestamp = (uint32_t)time(NULL);

    printf("[*] Sending AUTH_REQ: user=\"%s\"\n", req.username);

    if (send_packet(sock, MSG_AUTH_REQ, &req, sizeof(req)) < 0) {
        return 0;
    }

    /* Receive the response */
    uint8_t type;
    uint16_t resp_len;
    uint8_t resp_buf[GCRP_MAX_PAYLOAD];

    if (recv_packet(sock, &type, resp_buf, &resp_len) < 0) {
        return 0;
    }

    if (type != MSG_AUTH_RESP) {
        fprintf(stderr, "[!] Unexpected response (type 0x%02x).\n", type);
        return 0;
    }

    const auth_resp_payload_t *resp = (const auth_resp_payload_t *)resp_buf;

    if (resp->result == AUTH_OK) {
        printf("[+] Authenticated! Session ID: %08X\n", resp->session_id);
        printf("    Message: %s\n", resp->message);
        return resp->session_id;
    } else {
        printf("[-] Authentication failed (code %u).\n", resp->result);
        printf("    Message: %s\n", resp->message);
        return 0;
    }
}

/**
 * Phase 2: Heartbeat pings.
 */
static int do_ping(int sock, uint32_t seq) {
    ping_payload_t ping;
    ping.seq = seq;
    ping.timestamp = (uint32_t)time(NULL);

    printf("[*] Sending PING seq=%u\n", seq);

    if (send_packet(sock, MSG_PING, &ping, sizeof(ping)) < 0) {
        return -1;
    }

    uint8_t type;
    uint16_t resp_len;
    uint8_t resp_buf[GCRP_MAX_PAYLOAD];

    if (recv_packet(sock, &type, resp_buf, &resp_len) < 0) {
        return -1;
    }

    if (type == MSG_PONG) {
        const pong_payload_t *pong = (const pong_payload_t *)resp_buf;
        printf("[+] PONG received: seq=%u server_time=%u\n",
               pong->seq, pong->server_time);
    } else {
        fprintf(stderr, "[!] Unexpected response to PING (type 0x%02x).\n", type);
    }

    return 0;
}

/**
 * Phase 3: Resource requests.
 */
static int do_request_data(int sock, uint32_t session_id, uint8_t resource_id) {
    data_req_payload_t req;
    req.session_id = session_id;
    req.resource_id = resource_id;

    printf("[*] Sending DATA_REQ: session=%08X resource=%u\n",
           session_id, resource_id);

    if (send_packet(sock, MSG_DATA_REQ, &req, sizeof(req)) < 0) {
        return -1;
    }

    uint8_t type;
    uint16_t resp_len;
    uint8_t resp_buf[GCRP_MAX_PAYLOAD];

    if (recv_packet(sock, &type, resp_buf, &resp_len) < 0) {
        return -1;
    }

    if (type == MSG_DATA_RESP) {
        const data_resp_payload_t *resp = (const data_resp_payload_t *)resp_buf;
        uint16_t data_len = get_u16_be((const uint8_t *)&resp->data_len);
        printf("[+] DATA_RESP: resource=%u len=%u\n", resp->resource_id, data_len);
        printf("    Content: \"%.*s\"\n", data_len, resp->data);
    } else if (type == MSG_ERROR) {
        printf("[-] Server error: \"%.*s\"\n", resp_len, (char *)resp_buf);
    } else {
        fprintf(stderr, "[!] Unexpected response (type 0x%02x).\n", type);
    }

    return 0;
}

/**
 * Phase 4: Clean disconnect.
 */
static int do_goodbye(int sock) {
    printf("[*] Sending GOODBYE.\n");
    return send_packet(sock, MSG_GOODBYE, NULL, 0);
}

/* ═══════════════════════════════════════════════
 * Entry point
 * ═══════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    const char *server_ip = "127.0.0.1";
    uint16_t port = GCRP_PORT;
    const char *username = "admin";

    if (argc > 1) server_ip = argv[1];
    if (argc > 2) port = (uint16_t)atoi(argv[2]);
    if (argc > 3) username = argv[3];

    printf("=== GCRP Client v1.0 ===\n");
    printf("[*] Connecting to %s:%u as \"%s\"...\n",
           server_ip, port, username);

    /* Create the socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    /* Connect to the server */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "[!] Invalid IP address: %s\n", server_ip);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    printf("[+] Connected!\n\n");

    /* ── Phase 1: Authentication ── */
    uint32_t session_id = do_authenticate(sock, username);
    if (session_id == 0) {
        fprintf(stderr, "[-] Unable to authenticate. Aborting.\n");
        close(sock);
        return 1;
    }
    printf("\n");

    /* ── Phase 2: Heartbeat pings ── */
    for (uint32_t i = 1; i <= 3; i++) {
        do_ping(sock, i);
        usleep(200000);  /* 200ms between each ping */
    }
    printf("\n");

    /* ── Phase 3: Resource requests ── */
    for (uint8_t r = 0; r < 4; r++) {
        do_request_data(sock, session_id, r);
        usleep(100000);  /* 100ms between each request */
    }

    /* Request a non-existent resource (error test) */
    do_request_data(sock, session_id, 99);
    printf("\n");

    /* ── Phase 4: Disconnect ── */
    do_goodbye(sock);

    close(sock);
    printf("[*] Disconnected.\n");

    return 0;
}
