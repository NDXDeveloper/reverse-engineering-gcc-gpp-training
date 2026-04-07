/*
 * keygenme_v1.c — Vulnerable version
 * Reverse Engineering Training — Chapter 10 (Binary Diffing)
 *
 * This program verifies a serial entered by the user.
 * VULNERABILITY: check_serial() does not validate the input length
 * before passing it to transform(), which uses a fixed-size buffer.
 * An overly long input causes a buffer overflow; an overly short
 * input causes an out-of-bounds read.
 *
 * Compile with the provided Makefile or manually:
 *   gcc -O0 -g -o keygenme_v1 keygenme_v1.c
 *
 * MIT License — Strictly educational and ethical use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  transform() — transforms a serial into a numeric value             */
/*                                                                     */
/*  WARNING: uses an internal 64-byte buffer. If input exceeds         */
/*  this size, a buffer overflow occurs (vulnerable in v1, fixed       */
/*  in v2 by a check in check_serial).                                 */
/* ------------------------------------------------------------------ */
int transform(const char *input)
{
    char buf[64];
    int  acc = 0;
    int  i;

    /*
     * Copies input into a local buffer WITHOUT size checking.
     * This is where the overflow occurs if input > 64 bytes.
     * Note: strcpy is used intentionally to illustrate the vuln.
     */
    strcpy(buf, input);  /* CWE-120: Buffer Copy without Checking Size */

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
/*  VERSION v1 (vulnerable): no length check.                          */
/*  The input is passed directly to transform().                       */
/* ------------------------------------------------------------------ */
int check_serial(const char *input)
{
    int transformed;

    /* NO length check — this is the vulnerability */

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
