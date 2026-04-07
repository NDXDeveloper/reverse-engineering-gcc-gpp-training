/*
 * keygenme.c — Pedagogical crackme for the GNU Reverse Engineering training
 *
 * Chapter 21 — Reversing a simple C program (keygenme)
 *
 * Description:
 *   The program asks for a username and a license key.
 *   The valid key is derived from the name via a simple but
 *   non-trivial algorithm, designed to be interesting to reverse:
 *     1. Hash computation on the username (additions, XOR, rotations)
 *     2. Derivation of 4 hexadecimal groups from the hash
 *     3. Expected format: XXXX-XXXX-XXXX-XXXX
 *
 * Compilation: see the associated Makefile (produces 5 variants).
 *
 * MIT License — Strictly educational use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ──────────────────────────────────────────────
 * Constants intentionally visible via strings(1)
 * to guide the learner during initial triage.
 * ────────────────────────────────────────────── */
static const char BANNER[]    = "=== KeyGenMe v1.0 — RE Training ===";
static const char PROMPT_USER[] = "Enter username: ";
static const char PROMPT_KEY[]  = "Enter license key (XXXX-XXXX-XXXX-XXXX): ";
static const char MSG_OK[]      = "[+] Valid license! Welcome, %s.\n";
static const char MSG_FAIL[]    = "[-] Invalid license. Try again.\n";
static const char MSG_ERR_LEN[] = "[-] Username must be between 3 and 31 characters.\n";

#define USERNAME_MAX  32
#define KEY_LEN       19  /* XXXX-XXXX-XXXX-XXXX = 4*4 + 3 dashes */

#define HASH_SEED     0x5A3C6E2D
#define HASH_MUL      0x1003F
#define HASH_XOR      0xDEADBEEF

/* ──────────────────────────────────────────────
 * rotate_left — 32-bit left rotation.
 * Visible as a (shl + shr + or) pattern in ASM.
 * ────────────────────────────────────────────── */
static uint32_t rotate_left(uint32_t value, unsigned int count)
{
    count &= 31;
    return (value << count) | (value >> (32 - count));
}

/* ──────────────────────────────────────────────
 * compute_hash — Username hashing function.
 *
 * Points of interest for RE:
 *   - HASH_SEED constant identifiable in .rodata / imm32
 *   - Loop over each character (classic pattern)
 *   - Mixing: multiplication, XOR, rotation
 * ────────────────────────────────────────────── */
static uint32_t compute_hash(const char *username)
{
    uint32_t h = HASH_SEED;
    size_t len = strlen(username);

    for (size_t i = 0; i < len; i++) {
        h += (uint32_t)username[i];
        h *= HASH_MUL;
        h = rotate_left(h, (unsigned int)(username[i] & 0x0F));
        h ^= HASH_XOR;
    }

    /* Final avalanche to diffuse bits */
    h ^= (h >> 16);
    h *= 0x45D9F3B;
    h ^= (h >> 16);

    return h;
}

/* ──────────────────────────────────────────────
 * derive_key — Derives 4 groups of 16 bits from the hash.
 *
 * Each group undergoes a different transformation
 * to make the algorithm more interesting to reverse.
 * ────────────────────────────────────────────── */
static void derive_key(uint32_t hash, uint16_t groups[4])
{
    groups[0] = (uint16_t)((hash & 0xFFFF) ^ 0xA5A5);
    groups[1] = (uint16_t)(((hash >> 16) & 0xFFFF) ^ 0x5A5A);
    groups[2] = (uint16_t)((rotate_left(hash, 7) & 0xFFFF) ^ 0x1234);
    groups[3] = (uint16_t)((rotate_left(hash, 13) & 0xFFFF) ^ 0xFEDC);
}

/* ──────────────────────────────────────────────
 * format_key — Formats the key as "XXXX-XXXX-XXXX-XXXX".
 * The buffer must be at least KEY_LEN + 1 bytes.
 * ────────────────────────────────────────────── */
static void format_key(const uint16_t groups[4], char *out)
{
    snprintf(out, KEY_LEN + 1, "%04X-%04X-%04X-%04X",
             groups[0], groups[1], groups[2], groups[3]);
}

/* ──────────────────────────────────────────────
 * check_license — Central verification point.
 *
 * This is the function the learner must locate.
 * The final strcmp is the key decision point:
 *   - jz  → valid key
 *   - jnz → invalid key
 *
 * Returns 1 if the key is valid, 0 otherwise.
 * ────────────────────────────────────────────── */
static int check_license(const char *username, const char *user_key)
{
    uint32_t hash;
    uint16_t groups[4];
    char expected[KEY_LEN + 1];

    hash = compute_hash(username);
    derive_key(hash, groups);
    format_key(groups, expected);

    /* ── Decision point: strcmp ── */
    if (strcmp(expected, user_key) == 0) {
        return 1;
    }
    return 0;
}

/* ──────────────────────────────────────────────
 * read_line — Safe line reading (without newline).
 * ────────────────────────────────────────────── */
static int read_line(char *buf, size_t size)
{
    if (fgets(buf, (int)size, stdin) == NULL)
        return -1;

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

/* ──────────────────────────────────────────────
 * main — Entry point.
 * ────────────────────────────────────────────── */
int main(void)
{
    char username[USERNAME_MAX];
    char user_key[KEY_LEN + 2]; /* +2 for \n and \0 */

    printf("%s\n\n", BANNER);

    /* Read the username */
    printf("%s", PROMPT_USER);
    if (read_line(username, sizeof(username)) != 0)
        return EXIT_FAILURE;

    size_t ulen = strlen(username);
    if (ulen < 3 || ulen >= USERNAME_MAX) {
        printf("%s", MSG_ERR_LEN);
        return EXIT_FAILURE;
    }

    /* Read the license key */
    printf("%s", PROMPT_KEY);
    if (read_line(user_key, sizeof(user_key)) != 0)
        return EXIT_FAILURE;

    /* Verification */
    if (check_license(username, user_key)) {
        printf(MSG_OK, username);
        return EXIT_SUCCESS;
    } else {
        printf("%s", MSG_FAIL);
        return EXIT_FAILURE;
    }
}
