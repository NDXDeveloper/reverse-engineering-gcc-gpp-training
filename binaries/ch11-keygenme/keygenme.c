/*
 * keygenme.c — Training binary for the RE course
 *
 * Simple crackme with key verification via strcmp.
 * Used from chapter 11 (GDB) onwards.
 *
 * Compilation: see the associated Makefile.
 *
 * Usage:
 *   ./keygenme_O0
 *   Enter your key: VALID-KEY-2025
 *   Correct!
 *
 * MIT License — strictly educational use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────────────────────────
 * Constants and global data
 * ────────────────────────────────────────────── */

/* Expected key, stored in plaintext in .rodata.
 * In RE, it will be visible with `strings` or in Ghidra.
 * Later chapters show more resistant variants. */
static const char EXPECTED_KEY[] = "VALID-KEY-2025";

/* Global variable observable with a watchpoint (section 11.5).
 * 0 = locked, 1 = unlocked. */
int access_granted = 0;

/* ──────────────────────────────────────────────
 * Functions
 * ────────────────────────────────────────────── */

/*
 * transform_input — Cleans user input.
 *
 * Removes the trailing newline left by fgets.
 * Simple function, useful for observing the prologue/epilogue
 * and the calling convention (rdi = pointer to the buffer).
 */
void transform_input(char *input)
{
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }
}

/*
 * check_key — Checks if the provided key is correct.
 *
 * This is THE target function for the reverse engineer:
 *   - Its first argument (rdi) points to the user input.
 *   - It calls strcmp, whose arguments (rdi, rsi) reveal
 *     the expected key when a breakpoint is set.
 *   - It returns 1 (success) or 0 (failure) in rax.
 *
 * At -O0, the structure is readable: prologue, strcmp call,
 * return value test, conditional jump, epilogue.
 * At -O2, the compiler may inline strcmp or reorder code.
 */
int check_key(const char *input)
{
    if (strcmp(input, EXPECTED_KEY) == 0) {
        return 1;
    }
    return 0;
}

/*
 * main — Program entry point.
 *
 * Landmarks for GDB (chapter 11):
 *   - Locatable via __libc_start_main (section 11.4).
 *   - The input[64] buffer is on the stack (section 11.3).
 *   - fgets reads from stdin → redirect with run < input.txt
 *     or automate with pwntools (section 11.9).
 *   - The conditional jump after check_key (jz/jnz) is the target
 *     for binary patching.
 */
int main(int argc, char *argv[])
{
    char input[64];

    printf("Enter your key: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    transform_input(input);

    if (check_key(input)) {
        access_granted = 1;
        printf("Correct!\n");
        return 0;
    } else {
        printf("Wrong key!\n");
        return 1;
    }
}
