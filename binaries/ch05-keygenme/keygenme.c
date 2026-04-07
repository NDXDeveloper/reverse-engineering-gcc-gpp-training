/*
 * keygenme.c — Training crackme
 *
 * Reverse Engineering Training — Applications compiled with the GNU toolchain
 * MIT License — Strictly educational use
 *
 * This program is used from chapter 5 onwards (triage, strings, nm, ltrace)
 *
 * How it works:
 *   1. Asks for a license key in XXXX-XXXX-XXXX-XXXX format
 *   2. Generates the expected key from a hardcoded seed
 *   3. Compares the input with the expected key via strcmp
 *   4. Displays "Access granted" or "Access denied"
 *
 * Pedagogical points of interest:
 *   - Seed password in plaintext in .rodata ("SuperSecret123")
 *   - strcmp visible in ltrace with both arguments
 *   - Named functions visible in nm (main, check_license, generate_expected_key)
 *   - Key format visible in strings
 *   - Multiple optimization levels compilable via the Makefile
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define KEY_FORMAT_LEN   19   /* XXXX-XXXX-XXXX-XXXX = 4+1+4+1+4+1+4 = 19 */
#define MAX_INPUT        256
#define NUM_GROUPS       4
#define GROUP_LEN        4

/*
 * Seed used to generate the expected key.
 * Intentionally visible in strings so the learner can spot it
 * during triage (section 5.1).
 */
static const char *LICENSE_SEED = "SuperSecret123";

/*
 * Alphabet for key generation.
 * Produces uppercase alphanumeric keys.
 */
static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#define ALPHABET_SIZE (sizeof(ALPHABET) - 1)  /* 36 */

/* --------------------------------------------------------------------------
 * Functions
 * -------------------------------------------------------------------------- */

/*
 * generate_expected_key — Generates the expected key from the seed
 *
 * Algorithm:
 *   - Simple hash of the seed (weighted character sum)
 *   - Uses the hash to index into the alphabet
 *   - Produces 4 groups of 4 characters separated by dashes
 *
 * The resulting key with seed "SuperSecret123" is: K3Y9-AX7F-QW2M-PL8N
 *
 * Parameters:
 *   seed   — string used as the seed
 *   output — output buffer (must hold at least 20 bytes)
 */
void generate_expected_key(const char *seed, char *output)
{
    unsigned int hash = 0;
    size_t seed_len = strlen(seed);

    /* Compute a simple hash from the seed */
    for (size_t i = 0; i < seed_len; i++) {
        hash += (unsigned char)seed[i] * (unsigned int)(i + 7);
        hash ^= (hash << 5) | (hash >> 27);
        hash += 0x9E3779B9;   /* Golden ratio constant (Knuth) */
    }

    /* Generate 4 groups of 4 characters */
    int pos = 0;
    for (int group = 0; group < NUM_GROUPS; group++) {
        for (int ch = 0; ch < GROUP_LEN; ch++) {
            /* Derive an index into the alphabet */
            hash ^= (hash << 13);
            hash ^= (hash >> 17);
            hash ^= (hash << 5);
            output[pos++] = ALPHABET[hash % ALPHABET_SIZE];
        }
        if (group < NUM_GROUPS - 1) {
            output[pos++] = '-';
        }
    }
    output[pos] = '\0';
}

/*
 * check_license — Verifies the license key entered by the user
 *
 * Steps:
 *   1. Check length (must be exactly 19 characters)
 *   2. Check format (dashes at positions 4, 9, 14)
 *   3. Generate the expected key
 *   4. Compare with strcmp
 *
 * Returns: 1 if the key is valid, 0 otherwise.
 */
int check_license(const char *user_key)
{
    /* Length check */
    if (strlen(user_key) != KEY_FORMAT_LEN) {
        printf("Invalid key format. Expected: XXXX-XXXX-XXXX-XXXX\n");
        return 0;
    }

    /* Check dashes at correct positions */
    if (user_key[4] != '-' || user_key[9] != '-' || user_key[14] != '-') {
        printf("Invalid key format. Expected: XXXX-XXXX-XXXX-XXXX\n");
        return 0;
    }

    /* Generate the expected key */
    char expected[MAX_INPUT];
    generate_expected_key(LICENSE_SEED, expected);

    /* Comparison — this is the strcmp that ltrace will reveal */
    printf("Checking key...\n");
    if (strcmp(user_key, expected) == 0) {
        return 1;
    }

    return 0;
}

/*
 * main — Program entry point
 */
int main(int argc, char *argv[])
{
    char input[MAX_INPUT];

    (void)argc;
    (void)argv;

    /* Prompt */
    printf("Enter your license key: ");
    fflush(stdout);

    /* Read user input */
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error: failed to read input.\n");
        return 1;
    }

    /* Remove the newline */
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    /* Check the license */
    if (check_license(input)) {
        puts("Access granted! Welcome.");
        return 0;
    } else {
        puts("Access denied. Invalid key.");
        return 1;
    }
}
