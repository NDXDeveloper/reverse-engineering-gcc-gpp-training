/* ============================================================================
 * Chapter 16 — Section 16.5
 * lto_utils.c — Utility functions for the LTO demo
 *
 * Simple display and array manipulation functions.
 * With LTO, trivial functions (utils_clamp, utils_array_max)
 * will be inlined into lto_main.c even though they are in a
 * separate file. Without LTO, they remain as calls.
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <string.h>
#include "lto_utils.h"

/* --------------------------------------------------------------------------
 * Array display — will NOT be inlined (I/O, too large).
 * Used to prevent dead code elimination.
 * -------------------------------------------------------------------------- */
void utils_print_array(const char *label, const int *data, int n)
{
    printf("[%s] ", label);
    int display = (n > 10) ? 10 : n;
    for (int i = 0; i < display; i++) {
        printf("%d ", data[i]);
    }
    if (n > 10) printf("... (%d total)", n);
    printf("\n");
}

/* --------------------------------------------------------------------------
 * Sequential fill — trivial, cross-module inlined with LTO.
 * -------------------------------------------------------------------------- */
void utils_fill_sequence(int *data, int n, int start, int step)
{
    for (int i = 0; i < n; i++) {
        data[i] = start + i * step;
    }
}

/* --------------------------------------------------------------------------
 * Clamp — very trivial (3 comparisons).
 * Will be inlined everywhere with LTO. Without LTO: call utils_clamp
 * via PLT/GOT or direct call depending on linkage.
 *
 * At -O2, even without LTO, GCC can use cmov for this function
 * (in its own file). With LTO, the cmov appears directly in main().
 * -------------------------------------------------------------------------- */
int utils_clamp(int value, int low, int high)
{
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

/* --------------------------------------------------------------------------
 * Array maximum — simple loop, inlinable with LTO.
 *
 * RE interest: without LTO, you see a call utils_array_max + its loop.
 * With LTO, the loop is merged into the caller, potentially combined
 * with other loops (loop fusion).
 * -------------------------------------------------------------------------- */
int utils_array_max(const int *data, int n)
{
    int max = data[0];
    for (int i = 1; i < n; i++) {
        if (data[i] > max)
            max = data[i];
    }
    return max;
}

/* --------------------------------------------------------------------------
 * int → hex conversion into a buffer.
 * Medium size, inlined with LTO only if a single call site.
 *
 * Contains a fixed-iteration loop (8 nibbles for a 32-bit int)
 * that GCC can fully unroll.
 * -------------------------------------------------------------------------- */
char *utils_int_to_hex(int value, char *buf, int bufsize)
{
    static const char hex_chars[] = "0123456789ABCDEF";

    if (bufsize < 11) {  /* "0x" + 8 hex digits + '\0' */
        buf[0] = '\0';
        return buf;
    }

    buf[0] = '0';
    buf[1] = 'x';

    unsigned int uval = (unsigned int)value;
    for (int i = 7; i >= 0; i--) {
        buf[2 + (7 - i)] = hex_chars[(uval >> (i * 4)) & 0xF];
    }
    buf[10] = '\0';

    return buf;
}
