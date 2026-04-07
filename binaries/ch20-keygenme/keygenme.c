/*
 * keygenme.c — License key verification program (educational)
 *
 * Reverse Engineering Training — Chapter 20
 * MIT License — Strictly educational use
 *
 * This binary implements a key validation routine based on:
 *   - a username transformed via XOR and rotation
 *   - a key format XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (hex)
 *   - a byte-by-byte comparison
 *
 * Compiled at different optimization levels to observe the impact
 * on disassembly and decompilation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define KEY_LEN       16
#define MAX_USER      64
#define MAGIC_SEED    0xDEADBEEF
#define ROUND_COUNT   4

typedef struct {
    char     username[MAX_USER];
    uint8_t  expected_key[KEY_LEN];
    uint32_t seed;
} license_ctx_t;

static uint32_t rotate_left(uint32_t value, unsigned int count) {
    count &= 31;
    return (value << count) | (value >> (32 - count));
}

static uint32_t mix_hash(const char *data, size_t len, uint32_t seed) {
    uint32_t h = seed;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h  = rotate_left(h, 5);
        h += (uint32_t)data[i] * 0x01000193;
        h ^= (h >> 16);
    }
    return h;
}

static void derive_key(const char *username, uint32_t seed, uint8_t *out) {
    size_t ulen = strlen(username);
    uint32_t state[ROUND_COUNT];

    state[0] = mix_hash(username, ulen, seed);
    for (int r = 1; r < ROUND_COUNT; r++) {
        state[r] = mix_hash(username, ulen, state[r - 1] ^ (uint32_t)r);
    }

    for (int r = 0; r < ROUND_COUNT; r++) {
        out[r * 4 + 0] = (uint8_t)(state[r] >> 24);
        out[r * 4 + 1] = (uint8_t)(state[r] >> 16);
        out[r * 4 + 2] = (uint8_t)(state[r] >>  8);
        out[r * 4 + 3] = (uint8_t)(state[r] >>  0);
    }
}

static int parse_key_input(const char *input, uint8_t *out) {
    /* Expected format: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (hex) */
    if (strlen(input) != KEY_LEN * 2 + 3)
        return -1;

    int pos = 0;
    for (int group = 0; group < 4; group++) {
        for (int b = 0; b < 4; b++) {
            unsigned int byte_val;
            if (sscanf(&input[pos], "%2x", &byte_val) != 1)
                return -1;
            out[group * 4 + b] = (uint8_t)byte_val;
            pos += 2;
        }
        if (group < 3) {
            if (input[pos] != '-')
                return -1;
            pos++;
        }
    }
    return 0;
}

static int verify_key(const uint8_t *expected, const uint8_t *provided) {
    int result = 0;
    /* Constant-time comparison (intentionally visible in RE) */
    for (int i = 0; i < KEY_LEN; i++) {
        result |= expected[i] ^ provided[i];
    }
    return (result == 0) ? 1 : 0;
}

static void print_banner(void) {
    puts("+-----------------------------------------+");
    puts("|       KeyGenMe -- RE Training            |");
    puts("|   Reverse Engineering GCC Training       |");
    puts("+-----------------------------------------+");
    puts("");
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    license_ctx_t ctx;
    char key_input[128];
    uint8_t provided_key[KEY_LEN];

    print_banner();

    printf("Username: ");
    if (!fgets(ctx.username, MAX_USER, stdin))
        return 1;

    /* Remove the newline */
    size_t len = strlen(ctx.username);
    if (len > 0 && ctx.username[len - 1] == '\n')
        ctx.username[len - 1] = '\0';

    if (strlen(ctx.username) < 3) {
        fprintf(stderr, "[!] Username too short (min 3 characters).\n");
        return 1;
    }

    ctx.seed = MAGIC_SEED;
    derive_key(ctx.username, ctx.seed, ctx.expected_key);

    printf("License key (XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX): ");
    if (!fgets(key_input, sizeof(key_input), stdin))
        return 1;

    len = strlen(key_input);
    if (len > 0 && key_input[len - 1] == '\n')
        key_input[len - 1] = '\0';

    if (parse_key_input(key_input, provided_key) != 0) {
        fprintf(stderr, "[!] Invalid key format.\n");
        return 1;
    }

    if (verify_key(ctx.expected_key, provided_key)) {
        puts("[+] Valid key! License activated.");
        puts("[+] FLAG: RE{k3yg3n_m4st3r_gcc}");
        return 0;
    } else {
        puts("[-] Invalid key. Try again.");
        return 1;
    }
}
