/*
 * keygenme_v2.c — Fixed version
 * Reverse Engineering Training — Chapter 10 (Binary Diffing)
 *
 * This program verifies a serial entered by the user.
 * FIX: check_serial() now validates the input length
 * (between 4 and 32 characters inclusive) before passing it to transform().
 *
 * The transform() function remains unchanged from v1 — only the
 * upstream validation has been added. This is a frequent fix pattern:
 * protecting the caller rather than modifying the vulnerable code itself.
 *
 * Compile with the provided Makefile or manually:
 *   gcc -O0 -g -o keygenme_v2 keygenme_v2.c
 *
 * MIT License — Strictly educational and ethical use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERIAL_MIN_LEN   4
#define SERIAL_MAX_LEN  32

/* ------------------------------------------------------------------ */
/*  transform() — transforms a serial into a numeric value             */
/*                                                                     */
/*  UNCHANGED from v1. The internal 64-byte buffer is still present,   */
/*  but it is now protected by the length validation in check_serial().*/
/* ------------------------------------------------------------------ */
int transform(const char *input)
{
    char buf[64];
    int  acc = 0;
    int  i;

    /*
     * Copies input into a local buffer.
     * Still strcpy (unsafe), but the length is now guaranteed
     * <= 32 by check_serial(), so no overflow.
     */
    strcpy(buf, input);

    /* Simple hashing algorithm (for educational purposes) */
    for (i = 0; buf[i] != '\0'; i++) {
        acc = (acc * 31 + (unsigned char)buf[i]) & 0xFFFF;
    }

    /* Additional mixing based on length */
    acc ^= (i * 0x1337) & 0xFFFF;

    return acc;
}

/* ------------------------------------------------------------------ */
/*  check_serial() — checks if the serial is valid                     */
/*                                                                     */
/*  VERSION v2 (fixed): length validation added.                       */
/*  The input must be between SERIAL_MIN_LEN and SERIAL_MAX_LEN        */
/*  characters to be accepted.                                         */
/* ------------------------------------------------------------------ */
int check_serial(const char *input)
{
    size_t len;
    int    transformed;

    /* FIX: length check before any processing */
    len = strlen(input);

    if (len < SERIAL_MIN_LEN || len > SERIAL_MAX_LEN) {
        puts("Access denied.");
        return 0;
    }

    transformed = transform(input);

    if (transformed == 0x5A42) {
        puts("Access granted!");
        return 1;
    }

    puts("Access denied.");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  usage() — display help                                             */
/* ------------------------------------------------------------------ */
void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s <serial>\n", progname);
    fprintf(stderr, "  Checks whether the provided serial is valid.\n");
}

/* ------------------------------------------------------------------ */
/*  main()                                                             */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    return check_serial(argv[1]) ? EXIT_SUCCESS : EXIT_FAILURE;
}
