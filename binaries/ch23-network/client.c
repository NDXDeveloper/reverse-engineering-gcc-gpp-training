/*
 * ch23-network — client.c
 * TCP client for the custom binary protocol
 * Reverse Engineering Training — Chapter 23
 *
 * MIT License — Strictly educational use
 *
 * Usage: ./client <host> [port] [username] [password]
 *   host     : server address (default: 127.0.0.1)
 *   port     : TCP port (default: 4444)
 *   username : identifier (default: admin)
 *   password : password (default: s3cur3P@ss!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* ═══════════════════════════════════════════
 *  Protocol constants
 * ═══════════════════════════════════════════ */

#define PROTO_MAGIC       0xC0
#define PROTO_PORT        4444
#define HEADER_SIZE       4
#define MAX_PAYLOAD       4096
#define CHALLENGE_LEN     8

/* Message types */
#define MSG_HELLO_REQ     0x01
#define MSG_AUTH_REQ      0x02
#define MSG_CMD_REQ       0x03
#define MSG_QUIT_REQ      0x04
#define MSG_HELLO_RESP    0x81
#define MSG_AUTH_RESP     0x82
#define MSG_CMD_RESP      0x83
#define MSG_QUIT_RESP     0x84
#define MSG_ERROR         0xFF

/* Commands */
#define CMD_PING          0x01
#define CMD_LIST          0x02
#define CMD_READ          0x03
#define CMD_INFO          0x04

/* Status */
#define STATUS_OK         0x01
#define STATUS_FAIL       0x00

/* ═══════════════════════════════════════════
 *  Network utility functions
 * ═══════════════════════════════════════════ */

static int recv_exact(int fd, void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t r = recv(fd, (uint8_t *)buf + total, n - total, 0);
        if (r <= 0)
            return -1;
        total += (size_t)r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t w = send(fd, (const uint8_t *)buf + total, n - total, 0);
        if (w <= 0)
            return -1;
        total += (size_t)w;
    }
    return 0;
}

/* ═══════════════════════════════════════════
 *  Protocol functions
 * ═══════════════════════════════════════════ */

static int proto_send(int fd, uint8_t msg_type,
                      const uint8_t *payload, uint16_t payload_len)
{
    uint8_t header[HEADER_SIZE];
    header[0] = PROTO_MAGIC;
    header[1] = msg_type;
    header[2] = (payload_len >> 8) & 0xFF;
    header[3] = payload_len & 0xFF;

    if (send_all(fd, header, HEADER_SIZE) < 0)
        return -1;

    if (payload_len > 0 && payload != NULL) {
        if (send_all(fd, payload, payload_len) < 0)
            return -1;
    }

    return 0;
}

static int proto_recv(int fd, uint8_t *msg_type,
                      uint8_t *payload, uint16_t *payload_len)
{
    uint8_t header[HEADER_SIZE];

    if (recv_exact(fd, header, HEADER_SIZE) < 0) {
        fprintf(stderr, "[!] Failed to receive header.\n");
        return -1;
    }

    if (header[0] != PROTO_MAGIC) {
        fprintf(stderr, "[!] Bad magic byte: 0x%02X (expected 0x%02X)\n",
                header[0], PROTO_MAGIC);
        return -1;
    }

    *msg_type    = header[1];
    *payload_len = ((uint16_t)header[2] << 8) | (uint16_t)header[3];

    if (*payload_len > MAX_PAYLOAD) {
        fprintf(stderr, "[!] Payload too large: %u bytes\n", *payload_len);
        return -1;
    }

    if (*payload_len > 0) {
        if (recv_exact(fd, payload, *payload_len) < 0) {
            fprintf(stderr, "[!] Failed to receive payload.\n");
            return -1;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════
 *  Lightweight crypto (XOR with challenge)
 * ═══════════════════════════════════════════ */

static void xor_with_challenge(uint8_t *data, size_t len,
                               const uint8_t *challenge)
{
    for (size_t i = 0; i < len; i++) {
        data[i] ^= challenge[i % CHALLENGE_LEN];
    }
}

/* ═══════════════════════════════════════════
 *  Protocol sequences
 * ═══════════════════════════════════════════ */

/* Phase 1 : Handshake HELLO */
static int do_handshake(int fd, uint8_t *challenge_out)
{
    printf("[*] Sending HELLO...\n");

    /* HELLO Request: "HELLO" + 3 padding bytes */
    uint8_t hello_payload[8];
    memcpy(hello_payload, "HELLO", 5);
    memset(hello_payload + 5, 0, 3);

    if (proto_send(fd, MSG_HELLO_REQ, hello_payload, 8) < 0) {
        fprintf(stderr, "[!] Failed to send HELLO.\n");
        return -1;
    }

    /* Receive the response */
    uint8_t resp[MAX_PAYLOAD];
    uint8_t resp_type;
    uint16_t resp_len;

    if (proto_recv(fd, &resp_type, resp, &resp_len) < 0)
        return -1;

    if (resp_type == MSG_ERROR) {
        fprintf(stderr, "[!] Server error: %.*s\n",
                resp_len > 1 ? resp_len - 1 : 0, resp + 1);
        return -1;
    }

    if (resp_type != MSG_HELLO_RESP) {
        fprintf(stderr, "[!] Unexpected response type: 0x%02X\n", resp_type);
        return -1;
    }

    if (resp_len < 7 + CHALLENGE_LEN) {
        fprintf(stderr, "[!] HELLO response too short.\n");
        return -1;
    }

    /* Verify the "WELCOME" banner */
    if (memcmp(resp, "WELCOME", 7) != 0) {
        fprintf(stderr, "[!] Invalid HELLO response banner.\n");
        return -1;
    }

    /* Extract the challenge */
    memcpy(challenge_out, resp + 7, CHALLENGE_LEN);

    printf("[+] Handshake OK — received challenge: ");
    for (int i = 0; i < CHALLENGE_LEN; i++)
        printf("%02X", challenge_out[i]);
    printf("\n");

    return 0;
}

/* Phase 2: Authentication */
static int do_auth(int fd, const char *username, const char *password,
                   const uint8_t *challenge)
{
    printf("[*] Authenticating as '%s'...\n", username);

    size_t ulen = strlen(username);
    size_t plen = strlen(password);

    if (ulen > 255 || plen > 255) {
        fprintf(stderr, "[!] Username or password too long.\n");
        return -1;
    }

    /* Build the AUTH payload:
     *   [user_len:1][username:ulen][pass_len:1][password_xored:plen] */
    uint8_t payload[512];
    size_t offset = 0;

    payload[offset++] = (uint8_t)ulen;
    memcpy(payload + offset, username, ulen);
    offset += ulen;

    payload[offset++] = (uint8_t)plen;
    memcpy(payload + offset, password, plen);

    /* XOR the password with the challenge */
    xor_with_challenge(payload + offset, plen, challenge);
    offset += plen;

    if (proto_send(fd, MSG_AUTH_REQ, payload, (uint16_t)offset) < 0) {
        fprintf(stderr, "[!] Failed to send AUTH.\n");
        return -1;
    }

    /* Receive the response */
    uint8_t resp[MAX_PAYLOAD];
    uint8_t resp_type;
    uint16_t resp_len;

    if (proto_recv(fd, &resp_type, resp, &resp_len) < 0)
        return -1;

    if (resp_type == MSG_ERROR) {
        fprintf(stderr, "[!] Server error: %.*s\n",
                resp_len > 1 ? resp_len - 1 : 0, resp + 1);
        return -1;
    }

    if (resp_type != MSG_AUTH_RESP || resp_len < 2) {
        fprintf(stderr, "[!] Unexpected AUTH response.\n");
        return -1;
    }

    if (resp[1] == STATUS_OK) {
        printf("[+] Authentication successful!\n");
        return 0;
    } else {
        fprintf(stderr, "[-] Authentication FAILED.\n");
        return -1;
    }
}

/* Phase 3: Send a command */
static int do_command(int fd, uint8_t cmd_id,
                      const uint8_t *args, uint16_t args_len)
{
    uint8_t payload[MAX_PAYLOAD];
    payload[0] = cmd_id;

    if (args_len > 0 && args != NULL)
        memcpy(payload + 1, args, args_len);

    if (proto_send(fd, MSG_CMD_REQ, payload,
                   (uint16_t)(1 + args_len)) < 0) {
        fprintf(stderr, "[!] Failed to send command.\n");
        return -1;
    }

    /* Receive the response */
    uint8_t resp[MAX_PAYLOAD];
    uint8_t resp_type;
    uint16_t resp_len;

    if (proto_recv(fd, &resp_type, resp, &resp_len) < 0)
        return -1;

    if (resp_type == MSG_ERROR) {
        fprintf(stderr, "[!] Server error: %.*s\n",
                resp_len > 1 ? resp_len - 1 : 0, resp + 1);
        return -1;
    }

    if (resp_type != MSG_CMD_RESP) {
        fprintf(stderr, "[!] Unexpected response type: 0x%02X\n", resp_type);
        return -1;
    }

    if (resp_len < 1) {
        fprintf(stderr, "[!] Empty command response.\n");
        return -1;
    }

    if (resp[0] != STATUS_OK) {
        fprintf(stderr, "[-] Command failed (status=0x%02X).\n", resp[0]);
        return -1;
    }

    /* Display response data */
    if (resp_len > 1) {
        printf("[+] Response (%u bytes):\n", resp_len - 1);
        fwrite(resp + 1, 1, resp_len - 1, stdout);
        if (resp[resp_len - 1] != '\n')
            printf("\n");
    }

    return 0;
}

/* Phase 4: Clean disconnect */
static int do_quit(int fd)
{
    printf("[*] Sending QUIT...\n");

    if (proto_send(fd, MSG_QUIT_REQ, NULL, 0) < 0) {
        fprintf(stderr, "[!] Failed to send QUIT.\n");
        return -1;
    }

    uint8_t resp[MAX_PAYLOAD];
    uint8_t resp_type;
    uint16_t resp_len;

    if (proto_recv(fd, &resp_type, resp, &resp_len) < 0)
        return -1;

    if (resp_type == MSG_QUIT_RESP && resp_len >= 3 &&
        memcmp(resp, "BYE", 3) == 0) {
        printf("[+] Server acknowledged disconnect.\n");
    }

    return 0;
}

/* ═══════════════════════════════════════════
 *  File list display
 * ═══════════════════════════════════════════ */

static void print_file_list(const uint8_t *data, uint16_t len)
{
    if (len < 2) return;

    /* data[0] = STATUS_OK (already verified), data[1] = count */
    /* We receive data starting from resp+1 */
    uint8_t count = data[0];
    printf("[+] Available files (%d):\n", count);

    size_t offset = 1;
    for (int i = 0; i < count && offset < len; i++) {
        uint8_t idx = data[offset++];
        if (offset >= len) break;
        uint8_t nlen = data[offset++];
        if (offset + nlen > len) break;

        printf("    [%d] %.*s\n", idx, nlen, data + offset);
        offset += nlen;
    }
}

/* ═══════════════════════════════════════════
 *  Complete demo sequence
 * ═══════════════════════════════════════════ */

static int run_demo_session(int fd, const char *username,
                            const char *password)
{
    uint8_t challenge[CHALLENGE_LEN];

    printf("\n── Phase 1 : Handshake ──────────────────\n");
    if (do_handshake(fd, challenge) < 0)
        return -1;

    printf("\n── Phase 2: Authentication ──────────────\n");
    if (do_auth(fd, username, password, challenge) < 0)
        return -1;

    printf("\n── Phase 3: Commands ────────────────────\n");

    /* PING */
    printf("\n[*] CMD: PING\n");
    do_command(fd, CMD_PING, NULL, 0);

    /* INFO */
    printf("\n[*] CMD: INFO\n");
    do_command(fd, CMD_INFO, NULL, 0);

    /* LIST — receive and display the list */
    printf("\n[*] CMD: LIST\n");
    {
        uint8_t payload[1] = { CMD_LIST };
        if (proto_send(fd, MSG_CMD_REQ, payload, 1) < 0)
            return -1;

        uint8_t resp[MAX_PAYLOAD];
        uint8_t resp_type;
        uint16_t resp_len;
        if (proto_recv(fd, &resp_type, resp, &resp_len) < 0)
            return -1;

        if (resp_type == MSG_CMD_RESP && resp_len > 1 &&
            resp[0] == STATUS_OK) {
            print_file_list(resp + 1, resp_len - 1);
        }
    }

    /* READ — read each file */
    printf("\n[*] CMD: READ files\n");
    for (uint8_t i = 0; i < 4; i++) {
        printf("\n--- Reading file index %d ---\n", i);
        uint8_t args[1] = { i };
        do_command(fd, CMD_READ, args, 1);
    }

    printf("\n── Phase 4: Disconnect ──────────────────\n");
    do_quit(fd);

    return 0;
}

/* ═══════════════════════════════════════════
 *  Entry point
 * ═══════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    const char *host     = "127.0.0.1";
    uint16_t    port     = PROTO_PORT;
    const char *username = "admin";
    const char *password = "s3cur3P@ss!";

    if (argc >= 2) host     = argv[1];
    if (argc >= 3) port     = (uint16_t)atoi(argv[2]);
    if (argc >= 4) username = argv[3];
    if (argc >= 5) password = argv[4];

    if (port == 0) port = PROTO_PORT;

    printf("╔══════════════════════════════════════╗\n");
    printf("║   ch23-network client v1.0           ║\n");
    printf("║   Target: %s:%-5d           ║\n", host, port);
    printf("╚══════════════════════════════════════╝\n");

    /* Create the socket and connect */
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "[!] Invalid address: %s\n", host);
        close(fd);
        return 1;
    }

    printf("[*] Connecting to %s:%d...\n", host, port);

    if (connect(fd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    printf("[+] Connected!\n");

    int result = run_demo_session(fd, username, password);

    close(fd);

    if (result == 0)
        printf("\n[+] Session completed successfully.\n");
    else
        printf("\n[-] Session ended with errors.\n");

    return result == 0 ? 0 : 1;
}
