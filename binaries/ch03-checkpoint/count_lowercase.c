/*
 * Reverse Engineering Training — Chapter 3 — Checkpoint
 *
 * count_lowercase.c
 *
 * Simple program serving as support for the chapter 3 checkpoint.
 * The goal is to disassemble the count_lowercase() function compiled
 * with -O0 and manually annotate it using the 5-step method.
 *
 * Compilation: see the provided Makefile.
 *   make all       → produces -O0, -O2, -O0 stripped variants
 *   make clean     → removes generated binaries
 *
 * Usage:
 *   ./count_lowercase_O0 <string>
 *   Displays the number of lowercase letters ('a'-'z') in the string.
 *
 * Example:
 *   $ ./count_lowercase_O0 "Hello World 123"
 *   Lowercase count: 7
 *
 * MIT License — Strictly educational use.
 */

#include <stdio.h>
#include <string.h>

/*
 * count_lowercase — Counts ASCII lowercase letters in a buffer.
 *
 * @param str  Pointer to the character buffer to analyze.
 * @param len  Number of characters to examine in the buffer.
 * @return     The number of characters in the 'a'-'z' range.
 *
 * This is the function the student must recover through reverse engineering
 * from the disassembly provided in the checkpoint.
 */
int count_lowercase(const char *str, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            count++;
        }
    }
    return count;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    int length = (int)strlen(input);
    int result = count_lowercase(input, length);

    printf("Lowercase count: %d\n", result);
    return 0;
}
