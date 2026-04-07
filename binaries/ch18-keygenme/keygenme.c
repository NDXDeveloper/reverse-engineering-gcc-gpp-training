/*
 * keygenme.c — Training crackme for the Reverse Engineering course
 *
 * Related chapter:
 *   - Chapter 18: Solving with symbolic execution (angr / Z3)
 *
 * Compilation: see Makefile (produces multiple O0/O2/O3/strip variants)
 *
 * Usage: ./keygenme <serial>
 *        The serial is a string of 16 hexadecimal characters (64 bits).
 *        Example: ./keygenme 4A5F...
 *
 * MIT License — Strictly educational use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* --------------------------------------------------------------------------
 * Constants used in the verification routine.
 * In RE, these values appear as immediates in the disassembly
 * and serve as anchor points for the analyst.
 * -------------------------------------------------------------------------- */

#define SERIAL_LEN      16    /* 16 hex chars = 8 bytes = 64 bits */

#define MAGIC_A         0x5A3CE7F1U
#define MAGIC_B         0x1F4B8C2DU
#define MAGIC_C         0xDEAD1337U
#define MAGIC_D         0x8BADF00DU

#define EXPECTED_HIGH   0xA11C3514U
#define EXPECTED_LOW    0xF00DCAFEU

/* --------------------------------------------------------------------------
 * Transformation functions — intentionally non-trivial to encourage
 * using symbolic execution rather than manual solving.
 * -------------------------------------------------------------------------- */

/*
 * Bit mixing inspired by hash functions.
 * Pedagogical goal: show that a few lines of C produce
 * dense assembly that is hard to invert mentally.
 */
static uint32_t mix32(uint32_t v, uint32_t seed)
{
    v ^= seed;
    v  = ((v >> 16) ^ v) * 0x45D9F3BU;
    v  = ((v >> 16) ^ v) * 0x45D9F3BU;
    v  = (v >> 16) ^ v;
    return v;
}

/*
 * Feistel-like round: applies 4 rounds on two 32-bit halves.
 * The Feistel network is a cryptography classic; here it is used
 * for pedagogical purposes to create a cross-dependency between
 * the high and low parts of the serial.
 */
static void feistel4(uint32_t *left, uint32_t *right)
{
    uint32_t l = *left;
    uint32_t r = *right;
    uint32_t tmp;

    /* Round 1 */
    tmp = r;
    r   = l ^ mix32(r, MAGIC_A);
    l   = tmp;

    /* Round 2 */
    tmp = r;
    r   = l ^ mix32(r, MAGIC_B);
    l   = tmp;

    /* Round 3 */
    tmp = r;
    r   = l ^ mix32(r, MAGIC_C);
    l   = tmp;

    /* Round 4 */
    tmp = r;
    r   = l ^ mix32(r, MAGIC_D);
    l   = tmp;

    *left  = l;
    *right = r;
}

/* --------------------------------------------------------------------------
 * Main verification routine.
 * Returns 1 if the serial is valid, 0 otherwise.
 *
 * In RE, this is the function to locate and understand.
 * With angr, you can solve it without even reading it.
 * -------------------------------------------------------------------------- */
static int check_serial(const char *serial)
{
    uint32_t high, low;
    char buf[9];

    if (strlen(serial) != SERIAL_LEN)
        return 0;

    /* Verify that all characters are valid hexadecimal */
    for (int i = 0; i < SERIAL_LEN; i++) {
        char c = serial[i];
        int valid = (c >= '0' && c <= '9') ||
                    (c >= 'A' && c <= 'F') ||
                    (c >= 'a' && c <= 'f');
        if (!valid)
            return 0;
    }

    /* Split the serial into two 32-bit halves */
    memcpy(buf, serial, 8);
    buf[8] = '\0';
    high = (uint32_t)strtoul(buf, NULL, 16);

    memcpy(buf, serial + 8, 8);
    buf[8] = '\0';
    low = (uint32_t)strtoul(buf, NULL, 16);

    /* Apply the Feistel network */
    feistel4(&high, &low);

    /* Final check */
    if (high == EXPECTED_HIGH && low == EXPECTED_LOW)
        return 1;

    return 0;
}

/* --------------------------------------------------------------------------
 * Entry point — distinct messages to facilitate targeting with angr
 * (look for the address of "Access Granted" and avoid "Access Denied").
 * -------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <serial>\n", argv[0]);
        printf("  The serial is a string of %d hexadecimal characters.\n",
               SERIAL_LEN);
        return 1;
    }

    if (check_serial(argv[1])) {
        puts("Access Granted!");
        return 0;
    } else {
        puts("Access Denied.");
        return 1;
    }
}
