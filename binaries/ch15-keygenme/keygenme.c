/*
 * keygenme.c — Training crackme / keygenme
 *
 * Training binary for chapter 15 (Fuzzing).
 *
 * Valid key format:  RENG-XXXX-XXXX-XXXX
 *   - Fixed prefix: "RENG-"
 *   - 3 groups of 4 uppercase hexadecimal characters, separated by '-'
 *   - Total length: 19 characters
 *   - Mathematical constraints between groups:
 *       - group1 XOR group2 == 0xBEEF
 *       - group3 == (group1 + group2) & 0xFFFF
 *
 * Valid key example:  RENG-1234-ACDB-BF01
 *   group1 = 0x1234
 *   group2 = 0xACDB  → 0x1234 XOR 0xACDB = 0xBEEF  ✓
 *   group3 = 0xBF0F  → (0x1234 + 0xACDB) & 0xFFFF = 0xBF0F  ✓
 *   (Note: this example is illustrative — verify the calculations)
 *
 * The validation routine has multiple steps/branches, making it
 * interesting for fuzzing (section 15.2) and for static/dynamic
 * analysis (chapter 21).
 *
 * MIT License — Strictly educational use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ═══════════════════════════════════════════
 *  Constants
 * ═══════════════════════════════════════════ */

#define KEY_LENGTH      19          /* "RENG-XXXX-XXXX-XXXX" */
#define PREFIX          "RENG-"
#define PREFIX_LEN      5
#define GROUP_LEN       4
#define SEPARATOR       '-'
#define XOR_SECRET      0xBEEFu
#define MAX_INPUT       256

/* ═══════════════════════════════════════════
 *  Utility functions
 * ═══════════════════════════════════════════ */

/*
 * is_hex_group — Checks that `s` contains exactly `len`
 * uppercase hexadecimal characters (0-9, A-F).
 */
static int is_hex_group(const char *s, int len)
{
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

/*
 * hex_to_u16 — Converts a 4-character hex string to uint16_t.
 * Assumes the string has already been validated by is_hex_group.
 */
static uint16_t hex_to_u16(const char *s)
{
    uint16_t val = 0;
    for (int i = 0; i < GROUP_LEN; i++) {
        val <<= 4;
        char c = s[i];
        if (c >= '0' && c <= '9')
            val |= (uint16_t)(c - '0');
        else if (c >= 'A' && c <= 'F')
            val |= (uint16_t)(c - 'A' + 10);
    }
    return val;
}

/* ═══════════════════════════════════════════
 *  Key validation — step by step
 *
 *  Each step is a distinct branch that the
 *  fuzzer can progressively discover.
 * ═══════════════════════════════════════════ */

/*
 * validate_key — Main validation routine.
 *
 * Returns:
 *   0  = valid key
 *  -1  = invalid key (different reasons depending on the failed step)
 */
static int validate_key(const char *key)
{
    /* ── Step 1: length check ── */
    size_t len = strlen(key);
    if (len != KEY_LENGTH) {
        fprintf(stderr, "Error: invalid key length (expected %d, got %zu)\n",
                KEY_LENGTH, len);
        return -1;
    }

    /* ── Step 2: "RENG-" prefix check ── */
    if (strncmp(key, PREFIX, PREFIX_LEN) != 0) {
        fprintf(stderr, "Error: invalid prefix\n");
        return -1;
    }

    /* ── Step 3: separator check ── */
    /*    Expected positions: 4, 9, 14 (0-based index) */
    if (key[4] != SEPARATOR || key[9] != SEPARATOR || key[14] != SEPARATOR) {
        fprintf(stderr, "Error: invalid separator positions\n");
        return -1;
    }

    /* ── Step 4: group extraction and validation ── */
    const char *group1_str = key + PREFIX_LEN;       /* offset 5, "XXXX" */
    const char *group2_str = key + PREFIX_LEN + 5;   /* offset 10, "XXXX" */
    const char *group3_str = key + PREFIX_LEN + 10;  /* offset 15, "XXXX" */

    if (!is_hex_group(group1_str, GROUP_LEN)) {
        fprintf(stderr, "Error: group 1 contains non-hex characters\n");
        return -1;
    }
    if (!is_hex_group(group2_str, GROUP_LEN)) {
        fprintf(stderr, "Error: group 2 contains non-hex characters\n");
        return -1;
    }
    if (!is_hex_group(group3_str, GROUP_LEN)) {
        fprintf(stderr, "Error: group 3 contains non-hex characters\n");
        return -1;
    }

    /* ── Step 5: conversion to numeric values ── */
    uint16_t g1 = hex_to_u16(group1_str);
    uint16_t g2 = hex_to_u16(group2_str);
    uint16_t g3 = hex_to_u16(group3_str);

    /* ── Step 6: XOR constraint between group 1 and group 2 ── */
    /*    g1 XOR g2 must equal 0xBEEF                            */
    uint16_t xor_result = g1 ^ g2;
    if (xor_result != XOR_SECRET) {
        fprintf(stderr, "Error: XOR check failed (0x%04X ^ 0x%04X = 0x%04X, expected 0x%04X)\n",
                g1, g2, xor_result, XOR_SECRET);
        return -1;
    }

    /* ── Step 7: sum constraint for group 3 ── */
    /*    g3 must equal (g1 + g2) & 0xFFFF       */
    uint16_t expected_g3 = (g1 + g2) & 0xFFFF;
    if (g3 != expected_g3) {
        fprintf(stderr, "Error: checksum failed (expected 0x%04X, got 0x%04X)\n",
                expected_g3, g3);
        return -1;
    }

    /* ── Step 8 (bonus): additional constraint ── */
    /*    Group 1 must not be zero                  */
    if (g1 == 0x0000) {
        fprintf(stderr, "Error: group 1 must not be zero\n");
        return -1;
    }

    /* ══════════════════ VALID KEY ══════════════════ */
    return 0;
}

/* ═══════════════════════════════════════════
 *  Display functions
 * ═══════════════════════════════════════════ */

static void print_banner(void)
{
    printf("+-----------------------------------------+\n");
    printf("|   RENG KeygenMe — Training Binary       |\n");
    printf("|   Format: RENG-XXXX-XXXX-XXXX           |\n");
    printf("+-----------------------------------------+\n\n");
}

static void print_success(const char *key)
{
    printf("Key accepted: %s\n", key);
    printf("  Congratulations! The key is valid.\n");
}

static void print_failure(void)
{
    printf("Key rejected.\n");
}

/* ═══════════════════════════════════════════
 *  Entry point
 * ═══════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    char input[MAX_INPUT];

    if (argc >= 2) {
        /* Argument mode: key passed via argv[1] */
        strncpy(input, argv[1], MAX_INPUT - 1);
        input[MAX_INPUT - 1] = '\0';
    } else {
        /* Interactive mode: read from stdin */
        print_banner();
        printf("Enter your key: ");
        fflush(stdout);

        if (!fgets(input, MAX_INPUT, stdin)) {
            fprintf(stderr, "Error: failed to read input\n");
            return 1;
        }

        /* Remove trailing newline */
        size_t slen = strlen(input);
        if (slen > 0 && input[slen - 1] == '\n') {
            input[slen - 1] = '\0';
        }
    }

    /* ── Validation ── */
    int result = validate_key(input);

    if (result == 0) {
        print_success(input);
        return 0;
    } else {
        print_failure();
        return 1;
    }
}
