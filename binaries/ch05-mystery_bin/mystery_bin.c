/*
 * mystery_bin.c — Training binary for the chapter 5 checkpoint
 *
 * Reverse Engineering Training — Applications compiled with the GNU toolchain
 * MIT License — Strictly educational use
 *
 * This program is designed to produce interesting results with
 * each tool from chapter 5 (file, strings, readelf, nm, ldd, strace,
 * ltrace, checksec). It contains no malicious functionality.
 *
 * Features:
 *   - Password authentication (strcmp visible in ltrace)
 *   - Configuration file reading (visible in strace)
 *   - Simple XOR encryption of a message (constants visible in strings)
 *   - Result written to a file (visible in strace)
 *   - Light anti-debug check (/proc access visible in strace)
 *   - Multiple named functions (visible in nm)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

/* --------------------------------------------------------------------------
 * Constants and global data
 * (visible in strings / readelf -x .rodata)
 * -------------------------------------------------------------------------- */

#define MAX_INPUT     256
#define XOR_KEY_LEN   16
#define CONFIG_PATH   "/tmp/mystery.conf"
#define OUTPUT_PATH   "/tmp/mystery.out"
#define MAGIC_HEADER  "MYST"
#define VERSION_TAG   "mystery-tool v2.4.1-beta"

static const char *MASTER_PASSWORD = "R3v3rs3M3!2024";

static const unsigned char XOR_KEY[XOR_KEY_LEN] = {
    0x4D, 0x59, 0x53, 0x54, 0x45, 0x52, 0x59, 0x4B,  /* MYSTERYK */
    0x45, 0x59, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35   /* EY012345 */
};

/* Output file header structure */
typedef struct {
    char     magic[4];       /* "MYST" */
    uint32_t version;        /* 0x00020401 */
    uint32_t data_length;
    uint32_t checksum;
    uint64_t timestamp;
} __attribute__((packed)) MysteryHeader;

/* Global variable for verbose mode */
static int g_verbose = 0;

/* --------------------------------------------------------------------------
 * Utility functions
 * -------------------------------------------------------------------------- */

/*
 * compute_checksum — Computes a simple checksum (byte sum)
 * (visible in nm as a T symbol)
 */
static uint32_t compute_checksum(const unsigned char *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        sum ^= (sum << 3);
    }
    return sum;
}

/*
 * xor_encrypt — Encrypts/decrypts a buffer with the XOR key
 * (visible in nm, encryption logic for RE)
 */
static void xor_encrypt(unsigned char *buf, size_t len,
                         const unsigned char *key, size_t key_len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key[i % key_len];
    }
}

/*
 * check_debugger — Light anti-debug check
 * Reads /proc/self/status to detect a tracer (ptrace)
 * (file access will be visible in strace)
 */
static int check_debugger(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(f);
            if (tracer_pid != 0) {
                fprintf(stderr, "[!] Debugger detected (pid: %d)\n", tracer_pid);
                return 1;
            }
            return 0;
        }
    }

    fclose(f);
    return 0;
}

/* --------------------------------------------------------------------------
 * Main functions
 * -------------------------------------------------------------------------- */

/*
 * authenticate_user — Prompts for and verifies the password
 * (strcmp visible in ltrace, prompt visible in strings)
 */
static int authenticate_user(void)
{
    char input[MAX_INPUT];

    printf("=== %s ===\n", VERSION_TAG);
    printf("Enter access password: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error: failed to read input.\n");
        return 0;
    }

    /* Remove the newline */
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    if (strcmp(input, MASTER_PASSWORD) != 0) {
        fprintf(stderr, "Authentication failed. Access denied.\n");
        return 0;
    }

    printf("Authentication successful. Welcome.\n");
    return 1;
}

/*
 * load_config — Attempts to load a configuration file
 * (file opening will be visible in strace)
 */
static int load_config(void)
{
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) {
        if (g_verbose) {
            printf("[*] Config file not found: %s (using defaults)\n", CONFIG_PATH);
        }
        return 0;
    }

    char line[256];
    printf("[*] Loading configuration from %s\n", CONFIG_PATH);

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "verbose=", 8) == 0) {
            g_verbose = atoi(line + 8);
        }
        /* Other config options could be parsed here */
    }

    fclose(f);
    return 1;
}

/*
 * process_message — Encrypts a message and writes it to a file
 * (file operations visible in strace, structure visible in xxd)
 */
static int process_message(const char *message)
{
    size_t msg_len = strlen(message);

    /* Allocate a buffer for the encrypted message */
    unsigned char *encrypted = (unsigned char *)malloc(msg_len);
    if (!encrypted) {
        fprintf(stderr, "Error: memory allocation failed.\n");
        return 0;
    }

    /* Copy and encrypt */
    memcpy(encrypted, message, msg_len);
    xor_encrypt(encrypted, msg_len, XOR_KEY, XOR_KEY_LEN);

    /* Prepare the header */
    MysteryHeader header;
    memcpy(header.magic, MAGIC_HEADER, 4);
    header.version     = 0x00020401;
    header.data_length = (uint32_t)msg_len;
    header.checksum    = compute_checksum(encrypted, msg_len);
    header.timestamp   = (uint64_t)time(NULL);

    /* Write the output file */
    FILE *f = fopen(OUTPUT_PATH, "wb");
    if (!f) {
        fprintf(stderr, "Error: cannot open output file %s\n", OUTPUT_PATH);
        free(encrypted);
        return 0;
    }

    fwrite(&header, sizeof(MysteryHeader), 1, f);
    fwrite(encrypted, 1, msg_len, f);
    fclose(f);

    printf("[+] Message encrypted and written to %s (%zu bytes)\n",
           OUTPUT_PATH, sizeof(MysteryHeader) + msg_len);

    if (g_verbose) {
        printf("[*] Checksum: 0x%08X\n", header.checksum);
        printf("[*] Timestamp: %lu\n", header.timestamp);
    }

    free(encrypted);
    return 1;
}

/*
 * interactive_mode — Main interaction loop
 */
static void interactive_mode(void)
{
    char input[MAX_INPUT];

    printf("\nCommands: encrypt <message> | status | quit\n");

    while (1) {
        printf("mystery> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        /* Remove the newline */
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
            printf("Goodbye.\n");
            break;
        } else if (strcmp(input, "status") == 0) {
            printf("[*] Tool: %s\n", VERSION_TAG);
            printf("[*] Config: %s\n", CONFIG_PATH);
            printf("[*] Output: %s\n", OUTPUT_PATH);
            printf("[*] XOR key length: %d bytes\n", XOR_KEY_LEN);
            printf("[*] Verbose: %s\n", g_verbose ? "on" : "off");
        } else if (strncmp(input, "encrypt ", 8) == 0) {
            const char *message = input + 8;
            if (strlen(message) == 0) {
                printf("Usage: encrypt <message>\n");
            } else {
                process_message(message);
            }
        } else if (strlen(input) > 0) {
            printf("Unknown command: '%s'. Try: encrypt, status, quit\n", input);
        }
    }
}

/* --------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    /* Anti-debug check (light, bypassable) */
    if (check_debugger()) {
        fprintf(stderr, "[!] Exiting due to debugger presence.\n");
        return 2;
    }

    /* Load configuration */
    load_config();

    /* Check arguments */
    if (argc > 1 && strcmp(argv[1], "--verbose") == 0) {
        g_verbose = 1;
    }

    /* Authentication */
    if (!authenticate_user()) {
        return 1;
    }

    /* Interactive mode */
    interactive_mode();

    return 0;
}
