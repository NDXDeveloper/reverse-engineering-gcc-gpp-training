/*
 * keygenme.c — Training binary for the Reverse Engineering course
 *
 * Simple pedagogical crackme: the program asks for a password
 * and compares it to an expected value via strcmp.
 *
 * Compiled at different optimization levels and with/without symbols
 * to serve as support for chapter 12.
 *
 * MIT License — Strictly educational use.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ───────────────────────────────────────────────────────────
 * Expected password — stored in .rodata as a constant.
 * In RE, it can be found via `strings`, Ghidra, or by
 * intercepting strcmp with GDB/GEF/pwndbg/Frida.
 * ─────────────────────────────────────────────────────────── */
static const char *EXPECTED_PASSWORD = "s3cr3t_k3y";

/* ───────────────────────────────────────────────────────────
 * strip_newline — removes the trailing '\n' left by fgets.
 *
 * Classic pattern: strlen + replacement. This processing
 * is visible in RE via the strlen import in the GOT and
 * the write of a '\0' in the buffer before the strcmp call.
 * ─────────────────────────────────────────────────────────── */
static void strip_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
        str[len - 1] = '\0';
}

/* ───────────────────────────────────────────────────────────
 * check_password — verification routine.
 *
 * In RE, this function is identifiable by:
 *   - its name (if the binary is not stripped)
 *   - the cross-reference to strcmp@plt
 *   - the test eax, eax → jne/je pattern after the strcmp call
 *
 * Returns 1 if the password is correct, 0 otherwise.
 * ─────────────────────────────────────────────────────────── */
static int check_password(const char *input)
{
    if (strcmp(input, EXPECTED_PASSWORD) == 0) {
        puts("Correct password!");
        return 1;
    } else {
        puts("Incorrect password.");
        return 0;
    }
}

/* ───────────────────────────────────────────────────────────
 * main — entry point.
 *
 * Linear flow: prompt display → read via fgets →
 * '\n' cleanup → check_password call → return code.
 *
 * The 64-byte buffer is intentionally oversized compared
 * to the expected password. In an exploitation variant
 * (out of scope for this crackme), one could study an
 * overflow — here the goal is solely RE of the
 * verification logic.
 * ─────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    char buffer[64];

    printf("=== KeyGenMe v1.0 ===\n");
    printf("Enter the password: ");

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        fprintf(stderr, "Read error.\n");
        return EXIT_FAILURE;
    }

    strip_newline(buffer);

    if (check_password(buffer))
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}
