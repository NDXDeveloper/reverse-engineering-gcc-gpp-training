/*
 * keygenme.c — Training binary for the Reverse Engineering course
 *
 * This program implements a simple serial verification system:
 *   1. compute_hash()  — computes a numeric hash from the username
 *   2. check_serial()  — compares the provided serial to the expected hash
 *   3. main()          — orchestrates everything and displays the result
 *
 * Compiled at different optimization levels, this binary serves as support
 * to compare the assembly code produced by GCC (-O0, -O2, -O3).
 *
 * Usage: ./keygenme <username> <serial>
 *
 * MIT License — strictly educational use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * compute_hash — Computes a 32-bit hash from a string.
 *
 * Intentionally simple algorithm to be readable in assembly:
 *   - Iterates over each character of the string
 *   - Accumulates the ASCII value in an accumulator
 *   - Applies a shift and XOR at each iteration
 *
 * At -O0, each step is visible as a distinct instruction.
 * At -O2, GCC optimizes memory accesses and restructures the loop.
 * At -O3, the loop may be unrolled or vectorized.
 */
unsigned int compute_hash(const char *input)
{
    unsigned int hash = 0x5381;
    int i;

    for (i = 0; input[i] != '\0'; i++) {
        hash = (hash << 5) + hash;      /* hash * 33 */
        hash = hash ^ (unsigned char)input[i];
        hash = hash + (unsigned int)i;
    }

    return hash;
}

/*
 * check_serial — Verifies if the serial matches the username.
 *
 * Converts the hash to a hexadecimal string via sprintf, then compares
 * with the serial provided by the user via strcmp.
 *
 * Points of interest for RE:
 *   - The call to sprintf@plt is a strong semantic anchor point.
 *   - The call to strcmp@plt immediately reveals the validation mechanism.
 *   - The local buffer (64 bytes) is visible in the prologue via sub rsp.
 *   - The return value (0 or 1) creates two distinct exit paths.
 */
int check_serial(const char *username, const char *serial)
{
    unsigned int hash;
    char expected[64];

    hash = compute_hash(username);
    sprintf(expected, "%08x", hash);

    if (strcmp(expected, serial) == 0) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * main — Program entry point.
 *
 * Points of interest for RE:
 *   - The argc == 3 check creates a visible branch (cmp edi, 3 / jne).
 *   - The strings "Usage:", "Valid serial!", "Invalid serial."
 *     are stored in .rodata and referenced via lea rdi, [rip+...].
 *   - The two return paths (return 0 / return 1) create
 *     the patterns xor eax,eax and mov eax,1 before ret.
 */
int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s <username> <serial>\n", argv[0]);
        printf("Example: %s admin 0000abcd\n", argv[0]);
        return 1;
    }

    const char *username = argv[1];
    const char *serial   = argv[2];

    if (check_serial(username, serial)) {
        puts("Valid serial!");
        return 0;
    } else {
        puts("Invalid serial.");
        return 1;
    }
}
