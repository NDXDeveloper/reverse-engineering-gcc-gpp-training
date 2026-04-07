/*
 * keygenme.c — Training binary for the Reverse Engineering course.
 *
 * MIT License — Strictly educational use.
 *
 * This program reads a user key, applies a transformation
 * (XOR + rotation), then compares the result with an expected string.
 *
 * The reverse engineer's goal is to:
 *   1. Understand the applied transformation (transform_key).
 *   2. Find the valid key, either through static analysis, or by
 *      symbolic resolution (angr/Z3), or by writing a keygen.
 *
 * Compilation: see the associated Makefile.
 */

#include <stdio.h>
#include <string.h>

/* XOR key used for transformation — intentionally simple
 * for a first RE exercise. */
#define XOR_KEY  0x2A
#define ROT_AMT  3

/* Expected string after transformation.
 * In practice, the valid key is the one that, after transform_key(),
 * produces exactly this string. */
static const char *expected = "s3cr3t_k3y";

/*
 * transform_key — Transforms the user key in place.
 *
 * For each character:
 *   1. XOR with XOR_KEY (0x2A)
 *   2. Circular left rotation of ROT_AMT bits (on 8 bits)
 *
 * The transformation is invertible, which makes writing a keygen possible.
 */
void transform_key(char *key)
{
    size_t i;
    unsigned char c;

    for (i = 0; key[i] != '\0'; i++) {
        c = (unsigned char)key[i];
        c ^= XOR_KEY;
        c = (c << ROT_AMT) | (c >> (8 - ROT_AMT));
        key[i] = (char)c;
    }
}

/*
 * check_key — Compares the transformed key with the expected value.
 * Returns 1 if the key is valid, 0 otherwise.
 */
int check_key(const char *transformed)
{
    return strcmp(transformed, expected) == 0;
}

int main(void)
{
    char input[26];  /* 25 characters max + '\0' */

    printf("Enter key: ");
    fflush(stdout);

    if (scanf("%25s", input) != 1) {
        fprintf(stderr, "Read error\n");
        return 1;
    }

    transform_key(input);

    if (check_key(input)) {
        puts("Access granted");
    } else {
        puts("Wrong key");
    }

    return 0;
}
