/*
 * ch14-keygenme.c — Keygen-me for RE training
 *
 * Accepts a serial key as argument and validates it against
 * a derived hash of the expected format.
 *
 * Key format: XXXX-XXXX-XXXX-XXXX (16 hex chars + 3 dashes)
 *
 * Validation pipeline:
 *   1. Format check (length, dashes)
 *   2. Extract hex groups → 4 × uint16_t
 *   3. Transform each group through a substitution table (256 entries)
 *   4. Hash the 4 transformed values with a simple Feistel-like network
 *   5. Compare result against hardcoded magic value
 *
 * Intentional characteristics for RE training:
 *   - Callgrind: transform_byte called 256× (table init), hash_groups
 *     called with 4× inner loop of 16 rounds → identifiable pattern
 *   - Memcheck: leaked validation context (48 bytes)
 *   - ASan: off-by-one read in format_check (reads 1 byte past key)
 *   - UBSan: signed shift overflow in hash_groups
 *   - strcmp used for final comparison → visible in Callgrind/ltrace
 *
 * Build: see accompanying Makefile
 * Usage: ./keygenme <XXXX-XXXX-XXXX-XXXX>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ═══════════════════════════════════════════════════════════════════ */
/*  Constants                                                         */
/* ═══════════════════════════════════════════════════════════════════ */

#define KEY_LEN         19      /* "XXXX-XXXX-XXXX-XXXX" */
#define NUM_GROUPS      4
#define GROUP_HEX_LEN   4
#define FEISTEL_ROUNDS  16
#define TABLE_SIZE      256

#define EXPECTED_HASH   0xC0FFEE42u

#define CTX_SIZE        48

/* ═══════════════════════════════════════════════════════════════════ */
/*  Substitution table — built at runtime                             */
/* ═══════════════════════════════════════════════════════════════════ */

static uint8_t g_sbox[TABLE_SIZE];
static int     g_sbox_ready = 0;

/*
 * transform_byte — single-byte substitution.
 * Callgrind sees this called 256× during table init, then 8× during
 * key processing (4 groups × 2 bytes each).
 */
static uint8_t transform_byte(uint8_t v) {
    /* Affine bijection mod 256: f(v) = (v * 0xD7 + 0x2B) ^ 0x9E */
    return (uint8_t)(((v * 0xD7u) + 0x2Bu) ^ 0x9Eu);
}

static void init_sbox(void) {
    if (g_sbox_ready) return;
    for (int i = 0; i < TABLE_SIZE; i++)
        g_sbox[i] = transform_byte((uint8_t)i);
    g_sbox_ready = 1;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Validation context — intentionally leaked                         */
/* ═══════════════════════════════════════════════════════════════════ */

struct val_ctx {
    uint16_t groups[NUM_GROUPS];        /* offset 0,  8 bytes  */
    uint16_t transformed[NUM_GROUPS];   /* offset 8,  8 bytes  */
    uint32_t hash;                      /* offset 16, 4 bytes  */
    uint32_t expected;                  /* offset 20, 4 bytes  */
    char     key_copy[KEY_LEN + 1];     /* offset 24, 20 bytes */
    uint32_t status;                    /* offset 44, 4 bytes  */
};                                      /* total: 48 bytes     */

/* ═══════════════════════════════════════════════════════════════════ */
/*  Format checking                                                   */
/*  BUG: reads key[KEY_LEN] — 1 byte past the string if strlen==19   */
/*  ASan detects this as stack-buffer-overflow or heap-buffer-overflow */
/* ═══════════════════════════════════════════════════════════════════ */

static int format_check(const char *key) {
    /* Check length */
    size_t len = strlen(key);
    if (len != KEY_LEN)
        return 0;

    /* Check dashes at positions 4, 9, 14 */
    if (key[4] != '-' || key[9] != '-' || key[14] != '-')
        return 0;

    /* Check hex digits — BUG: loop goes to KEY_LEN (inclusive) */
    for (int i = 0; i <= KEY_LEN; i++) {               /* off-by-one: <= */
        if (i == 4 || i == 9 || i == 14) continue;
        if (!isxdigit((unsigned char)key[i]))           /* reads key[19] */
            return 0;
    }

    return 1;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Extract hex groups                                                */
/* ═══════════════════════════════════════════════════════════════════ */

static void extract_groups(const char *key, uint16_t groups[NUM_GROUPS]) {
    /* Group positions: 0, 5, 10, 15 */
    const int offsets[NUM_GROUPS] = { 0, 5, 10, 15 };
    char buf[GROUP_HEX_LEN + 1];

    for (int g = 0; g < NUM_GROUPS; g++) {
        memcpy(buf, key + offsets[g], GROUP_HEX_LEN);
        buf[GROUP_HEX_LEN] = '\0';
        groups[g] = (uint16_t)strtoul(buf, NULL, 16);
    }
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Transform groups through S-box                                    */
/* ═══════════════════════════════════════════════════════════════════ */

static void transform_groups(const uint16_t *in, uint16_t *out) {
    init_sbox();
    for (int g = 0; g < NUM_GROUPS; g++) {
        uint8_t hi = (uint8_t)(in[g] >> 8);
        uint8_t lo = (uint8_t)(in[g] & 0xFF);
        out[g] = (uint16_t)((g_sbox[hi] << 8) | g_sbox[lo]);
    }
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Hash — Feistel-like network                                       */
/*  BUG: uses signed int for shifts → UBSan flags left shift of       */
/*       negative value                                                */
/* ═══════════════════════════════════════════════════════════════════ */

static uint32_t hash_groups(const uint16_t transformed[NUM_GROUPS]) {
    /* Pack into two 32-bit halves */
    int L = (int)((transformed[0] << 16) | transformed[1]);    /* signed! */
    int R = (int)((transformed[2] << 16) | transformed[3]);    /* signed! */

    for (int round = 0; round < FEISTEL_ROUNDS; round++) {
        int F = ((R << 5) | ((unsigned)R >> 27))                /* SIGNED SHIFT */
               ^ (R + (int)(round * 0x9E3779B9u));              /* golden ratio */
        int new_R = L ^ F;
        L = R;
        R = new_R;
    }

    return (uint32_t)(L ^ R);
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Validate — orchestrator                                           */
/* ═══════════════════════════════════════════════════════════════════ */

static struct val_ctx *validate_key(const char *key) {
    struct val_ctx *ctx = malloc(CTX_SIZE);              /* 48 bytes — LEAK */
    if (!ctx) return NULL;
    memset(ctx, 0, CTX_SIZE);

    ctx->expected = EXPECTED_HASH;
    strncpy(ctx->key_copy, key, KEY_LEN);
    ctx->key_copy[KEY_LEN] = '\0';

    /* Step 1: format check */
    if (!format_check(key)) {
        ctx->status = 1;   /* bad format */
        return ctx;
    }

    /* Step 2: extract hex groups */
    extract_groups(key, ctx->groups);

    /* Step 3: transform through S-box */
    transform_groups(ctx->groups, ctx->transformed);

    /* Step 4: hash */
    ctx->hash = hash_groups(ctx->transformed);

    /* Step 5: compare */
    char hash_str[16], expected_str[16];
    snprintf(hash_str,     sizeof(hash_str),     "%08X", ctx->hash);
    snprintf(expected_str, sizeof(expected_str),  "%08X", ctx->expected);

    if (strcmp(hash_str, expected_str) == 0)
        ctx->status = 0;   /* success */
    else
        ctx->status = 2;   /* wrong key */

    return ctx;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Main                                                              */
/* ═══════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <XXXX-XXXX-XXXX-XXXX>\n", argv[0]);
        return 1;
    }

    const char *key = argv[1];
    struct val_ctx *ctx = validate_key(key);

    if (!ctx) {
        fprintf(stderr, "Error: allocation failed\n");
        return 1;
    }

    switch (ctx->status) {
        case 0:
            printf("SUCCESS — Valid key: %s\n", ctx->key_copy);
            printf("Hash: 0x%08X\n", ctx->hash);
            break;
        case 1:
            printf("FAILED — Invalid format. Expected: XXXX-XXXX-XXXX-XXXX (hex)\n");
            break;
        case 2:
            printf("FAILED — Wrong key.\n");
            printf("Your hash:     0x%08X\n", ctx->hash);
            printf("Expected hash: 0x%08X\n", ctx->expected);
            break;
        default:
            printf("FAILED — Unknown error.\n");
    }

    /* BUG: ctx is never freed → Memcheck reports 48 bytes definitely lost */
    return (ctx->status == 0) ? 0 : 1;
}
