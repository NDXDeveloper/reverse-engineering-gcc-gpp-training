/* hello.c — Chapter 2 walkthrough
 *
 * Intentionally simple program but rich enough to illustrate
 * each step of the GNU compilation chain:
 *
 *   - The preprocessor replaces the SECRET macro (section 2.1, 2.2)
 *   - The compiler transforms check() into machine instructions (section 2.1)
 *   - The linker resolves strcmp/printf from libc via PLT/GOT (section 2.9)
 *   - The loader maps everything into memory at execution time (section 2.7)
 *
 * Compiled at different optimization levels and with/without symbols
 * to observe the impact of compilation flags (section 2.5).
 *
 * MIT License — This content is strictly educational and ethical.
 */

#include <stdio.h>
#include <string.h>

#define SECRET "RE-101"

int check(const char *input) {
    return strcmp(input, SECRET) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    if (check(argv[1])) {
        printf("Access granted.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
