/**
 * binaries/ch13-keygenme/keygenme.c
 *
 * Training crackme for reverse engineering.
 * Asks for a license key and verifies its validity.
 *
 * Compilation: see Makefile
 * Usage:       ./keygenme_O0
 *              ./keygenme_O0 <key>    (non-interactive mode)
 *
 * Valid key: GCC-RE-2024-XPRO
 *
 * Verification architecture:
 *   validate_key(input)
 *     ├── strlen(input)                    → length check
 *     ├── format / prefix checks           → inline, no short-circuit
 *     ├── compute_hash(input, len, ...)    → normalize + compute checksum
 *     └── check_hash(hash_buf, checksum)   → strcmp with reference key
 *
 *   All steps are executed unconditionally:
 *   strlen() and strcmp() are ALWAYS visible in Frida / strace / ltrace
 *   traces, regardless of the provided input.
 *
 * Expected traces with frida-trace (input "AAAA"):
 *   puts("=== KeyGenMe v1.0 ===")
 *   puts("Enter the license key:")
 *   scanf()
 *   strlen("AAAA")
 *   strcmp("AAAA", "GCC-RE-2024-XPRO")
 *   puts("Invalid key. Access denied.")
 *
 * Traces with frida-trace -I "keygenme_O0":
 *   main()
 *      | print_banner()
 *      | read_input()
 *      | validate_key()
 *      |    | compute_hash()
 *      |    | check_hash()
 *      | print_result()
 *
 * MIT License — strictly educational use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════ */

#define KEY_LENGTH        16
#define CHECKSUM_EXPECTED 0x03FC   /* ASCII sum of "GCC-RE-2024-XPRO" = 1020 */
#define XOR_KEY           0x37     /* XOR key for reference encoding          */
#define MAX_INPUT         256

/*
 * Reference key encoded with XOR using XOR_KEY (0x37).
 * Plaintext key: "GCC-RE-2024-XPRO"
 *
 * Calculation:
 *   'G' (0x47) ^ 0x37 = 0x70    'R' (0x52) ^ 0x37 = 0x65
 *   'C' (0x43) ^ 0x37 = 0x74    'E' (0x45) ^ 0x37 = 0x72
 *   '-' (0x2D) ^ 0x37 = 0x1A    '2' (0x32) ^ 0x37 = 0x05
 *   '0' (0x30) ^ 0x37 = 0x07    '4' (0x34) ^ 0x37 = 0x03
 *   'X' (0x58) ^ 0x37 = 0x6F    'P' (0x50) ^ 0x37 = 0x67
 *   'R' (0x52) ^ 0x37 = 0x65    'O' (0x4F) ^ 0x37 = 0x78
 *   '\0'(0x00) ^ 0x37 = 0x37
 */
static const uint8_t encoded_key[] = {
    0x70, 0x74, 0x74, 0x1A,  /* G  C  C  -  */
    0x65, 0x72, 0x1A,        /* R  E  -     */
    0x05, 0x07, 0x05, 0x03,  /* 2  0  2  4  */
    0x1A,                    /* -           */
    0x6F, 0x67, 0x65, 0x78,  /* X  P  R  O  */
    0x37                     /* \0          */
};

/* ═══════════════════════════════════════════════
 * Banner
 * ═══════════════════════════════════════════════ */

static void print_banner(void) {
    puts("=== KeyGenMe v1.0 ===");
    puts("");
}

/* ═══════════════════════════════════════════════
 * Verification functions
 * ═══════════════════════════════════════════════ */

/**
 * Decodes the XOR-encoded reference key.
 * Writes the result into `out` (KEY_LENGTH + 1 bytes).
 */
static void decode_reference_key(char *out) {
    for (int i = 0; i <= KEY_LENGTH; i++) {
        out[i] = (char)(encoded_key[i] ^ XOR_KEY);
    }
}

/**
 * Normalizes the input and computes an additive checksum.
 *
 * - Copies input into hash_buf (truncated or padded to KEY_LENGTH).
 * - Computes the sum of ASCII codes and stores it in *checksum_out.
 *
 * hash_buf contains the length-normalized input, so the
 * strcmp() in check_hash() compares the user input
 * (or its truncated version) to the reference key.
 *
 * input_len is provided by the caller to avoid a second
 * strlen() call (which would be visible in Frida traces).
 */
static void compute_hash(const char *input, size_t input_len,
                         char *hash_buf, uint16_t *checksum_out) {
    /* Normalize: copy up to KEY_LENGTH characters */
    memset(hash_buf, 0, KEY_LENGTH + 1);
    size_t copy_len = (input_len < KEY_LENGTH) ? input_len : KEY_LENGTH;
    memcpy(hash_buf, input, copy_len);
    hash_buf[KEY_LENGTH] = '\0';

    /* Compute additive checksum (sum of ASCII codes) */
    uint16_t sum = 0;
    for (int i = 0; i < KEY_LENGTH; i++) {
        sum += (uint8_t)hash_buf[i];
    }
    *checksum_out = sum;
}

/**
 * Verifies the hash:
 *   1. Checks that the checksum matches CHECKSUM_EXPECTED.
 *   2. Decodes the reference key and compares via strcmp().
 *
 * strcmp() is ALWAYS executed — no short-circuit on the
 * checksum — to guarantee its visibility in traces.
 *
 * Returns 1 if everything is valid, 0 otherwise.
 */
static int check_hash(const char *hash_buf, uint16_t checksum) {
    int valid = 1;

    /* Checksum verification */
    if (checksum != CHECKSUM_EXPECTED) {
        valid = 0;
        /* Continue — no short-circuit */
    }

    /* Decode the reference key and compare via strcmp.
     * This is THE strcmp that Frida intercepts and that reveals
     * the expected key "GCC-RE-2024-XPRO" as the second argument. */
    char reference[KEY_LENGTH + 1];
    decode_reference_key(reference);

    if (strcmp(hash_buf, reference) != 0) {
        valid = 0;
    }

    return valid;
}

/**
 * Main validation function.
 *
 * Executes ALL steps unconditionally so that strlen()
 * and strcmp() are always visible in traces, regardless
 * of the input.
 *
 * Returns 1 if the key is valid, 0 otherwise.
 */
static int validate_key(const char *key) {
    int valid = 1;

    /* ── Step 1: length ──
     * A single strlen call — the value is reused later. */
    size_t len = strlen(key);
    if (len != KEY_LENGTH) {
        valid = 0;
    }

    /* ── Step 2: format XXX-XX-XXXX-XXXX ──
     * Only check if length allows index access.
     * No short-circuit: set valid to 0 but continue. */
    if (len >= KEY_LENGTH) {
        if (key[3] != '-' || key[6] != '-' || key[11] != '-') {
            valid = 0;
        }
    } else {
        valid = 0;
    }

    /* ── Step 3: "GCC" prefix ── */
    if (len >= 3) {
        if (key[0] != 'G' || key[1] != 'C' || key[2] != 'C') {
            valid = 0;
        }
    } else {
        valid = 0;
    }

    /* ── Step 4: compute_hash + check_hash ──
     * Always executed, even if previous steps failed.
     * compute_hash normalizes the input and computes the checksum.
     * check_hash compares via strcmp and verifies the checksum. */
    char hash_buf[KEY_LENGTH + 1];
    uint16_t checksum;

    compute_hash(key, len, hash_buf, &checksum);

    if (!check_hash(hash_buf, checksum)) {
        valid = 0;
    }

    return valid;
}

/* ═══════════════════════════════════════════════
 * Result display
 * ═══════════════════════════════════════════════ */

static void print_result(int valid) {
    puts("");
    if (valid) {
        puts("Valid key! Access granted.");
    } else {
        puts("Invalid key. Access denied.");
    }
}

/* ═══════════════════════════════════════════════
 * User input reading
 * ═══════════════════════════════════════════════ */

/**
 * Reads the key from stdin via scanf.
 * Returns 0 if OK, -1 on error.
 */
static int read_input(char *buf, size_t bufsize) {
    puts("Enter the license key:");

    if (scanf("%255s", buf) != 1) {
        return -1;
    }
    buf[bufsize - 1] = '\0';

    return 0;
}

/* ═══════════════════════════════════════════════
 * Entry point
 * ═══════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    char input[MAX_INPUT];

    print_banner();

    if (argc > 1) {
        /* Non-interactive mode: key passed as argument */
        strncpy(input, argv[1], MAX_INPUT - 1);
        input[MAX_INPUT - 1] = '\0';
    } else {
        /* Interactive mode: read from stdin */
        if (read_input(input, sizeof(input)) < 0) {
            fprintf(stderr, "Read error.\n");
            return 1;
        }
    }

    int result = validate_key(input);
    print_result(result);

    return result ? 0 : 1;
}
