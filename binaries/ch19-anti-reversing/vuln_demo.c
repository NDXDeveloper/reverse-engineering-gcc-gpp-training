/*
 * vuln_demo.c — Chapter 19 training binary
 * Reverse Engineering Training — GNU Toolchain
 *
 * This program intentionally contains a buffer overflow
 * to observe the effect of compiler protections:
 *
 *   - Stack canary (-fstack-protector / -fstack-protector-all)
 *   - NX (non-executable stack)
 *   - PIE (Position Independent Executable)
 *   - RELRO (Partial vs Full)
 *
 * Compiled with different flag combinations via the Makefile,
 * it allows visually observing (with checksec, GDB, readelf)
 * the impact of each protection.
 *
 * This binary is INTENTIONALLY vulnerable.
 * Strictly educational use — MIT License
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════
 * Function pointer table (GOT-relevant)
 *
 * These function pointers stored in .data are
 * interesting to demonstrate RELRO impact:
 * - Partial RELRO: GOT writable after startup
 * - Full RELRO: GOT read-only after resolution
 * ═══════════════════════════════════════════ */

typedef void (*action_fn)(const char *);

static void greet(const char *name)
{
    printf("Hello, %s!\n", name);
}

static void farewell(const char *name)
{
    printf("Goodbye, %s!\n", name);
}

/* Dispatch table — stored in .data */
static action_fn actions[] = { greet, farewell };

/* ═══════════════════════════════════════════
 * Vulnerable function — buffer overflow
 *
 * The local buffer is 64 bytes but strcpy does not
 * check the size. With stack canary enabled, the
 * program will detect the overflow and call
 * __stack_chk_fail. Without canary, the overflow
 * will silently overwrite the return address.
 * ═══════════════════════════════════════════ */
static void process_input(const char *data)
{
    char buffer[64];

    /* INTENTIONAL VULNERABILITY
     * strcpy does not check the size of data.
     * If strlen(data) > 63, buffer overflow. */
    strcpy(buffer, data);

    printf("Processing: %s\n", buffer);

    /* Use the dispatch table to demonstrate
     * function pointer calls */
    if (strlen(buffer) > 0) {
        actions[0](buffer);
    }
}

/* ═══════════════════════════════════════════
 * Function with stack variables
 *
 * Allows observing the stack memory layout
 * and canary position with GDB/GEF.
 * ═══════════════════════════════════════════ */
static int authenticate(void)
{
    char username[32];
    char password[32];
    int auth_flag = 0;

    printf("Username: ");
    fflush(stdout);

    if (!fgets(username, sizeof(username), stdin))
        return 0;

    printf("Password: ");
    fflush(stdout);

    if (!fgets(password, sizeof(password), stdin))
        return 0;

    /* Remove newlines */
    username[strcspn(username, "\n")] = '\0';
    password[strcspn(password, "\n")] = '\0';

    /* Simplistic check.
     * The interesting point is the layout of auth_flag
     * relative to the buffers on the stack. */
    if (strcmp(username, "admin") == 0 &&
        strcmp(password, "s3cur3") == 0) {
        auth_flag = 1;
    }

    return auth_flag;
}

/* Forward declaration needed for print_address_info() */
int main(int argc, char *argv[]);

/* ═══════════════════════════════════════════
 * Address information display
 *
 * Allows visualizing the effect of ASLR and PIE:
 * addresses change with each execution if
 * PIE + ASLR are active.
 * ═══════════════════════════════════════════ */
static void print_address_info(void)
{
    int stack_var = 42;
    static int data_var = 100;
    char *heap_var = malloc(16);

    printf("\n--- Address information ---\n");
    printf("  main()       @ %p  (.text)\n", (void *)main);
    printf("  greet()      @ %p  (.text)\n", (void *)greet);
    printf("  actions[]    @ %p  (.data)\n", (void *)actions);
    printf("  data_var     @ %p  (.data)\n", (void *)&data_var);
    printf("  stack_var    @ %p  (stack)\n", (void *)&stack_var);
    printf("  heap_var     @ %p  (heap)\n",  (void *)heap_var);
    printf("--------------------------------\n\n");

    free(heap_var);
}

/* ═══════════════════════════════════════════
 * Entry point
 * ═══════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    printf("=== vuln_demo — Chapter 19 ===\n");
    printf("Compiler protection demonstration\n\n");

    print_address_info();

    if (argc > 1) {
        /* Direct mode: pass input as argument
         * to easily trigger the overflow */
        printf("[argument mode] Processing argv[1]...\n");
        process_input(argv[1]);
    } else {
        /* Interactive mode: authentication */
        if (authenticate()) {
            printf(">>> Authentication successful.\n");
            actions[0]("authenticated user");
        } else {
            printf(">>> Authentication failed.\n");
            actions[1]("intruder");
        }
    }

    return 0;
}
