/* ============================================================================
 * Chapter 16 — Section 16.5
 * lto_math.c — Mathematical functions for the LTO demo
 *
 * This file is compiled SEPARATELY from lto_main.c and lto_utils.c.
 *
 * Without LTO (-flto):
 *   Each .c file is compiled into an independent .o. The compiler
 *   cannot see beyond file boundaries. Functions defined here
 *   CANNOT be inlined into lto_main.c, even if they are trivial.
 *   Each call generates a call through the linker.
 *
 * With LTO (-flto):
 *   GCC preserves an intermediate representation (GIMPLE) in the .o files.
 *   At link time, it merges all files and can:
 *     - Inline these functions into main() (cross-module inlining)
 *     - Propagate constants across files
 *     - Eliminate cross-module dead code
 *     - Devirtualize indirect calls
 *
 * For RE:
 *   - Without LTO, these functions appear as distinct symbols.
 *   - With LTO, they can disappear entirely from the binary.
 *   → The call graph is radically different.
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include "lto_math.h"

/* --------------------------------------------------------------------------
 * Trivial function — will be cross-module inlined with -flto -O2.
 * Without LTO, it always generates a call.
 * -------------------------------------------------------------------------- */
int math_square(int x)
{
    return x * x;
}

/* --------------------------------------------------------------------------
 * Trivial function — same thing.
 * -------------------------------------------------------------------------- */
int math_cube(int x)
{
    return x * x * x;
}

/* --------------------------------------------------------------------------
 * Medium-sized function — inlined with LTO if few call sites.
 *
 * Contains a loop and a branch, making it "medium-sized"
 * from the inlining heuristics perspective.
 * -------------------------------------------------------------------------- */
long math_sum_of_powers(int n, int power)
{
    long total = 0;
    for (int i = 1; i <= n; i++) {
        long val = 1;
        for (int p = 0; p < power; p++) {
            val *= i;
        }
        total += val;
    }
    return total;
}

/* --------------------------------------------------------------------------
 * Function with magic constants for RE.
 *
 * The polynomial hash uses recognizable constants (31, 0x5F3759DF)
 * in the disassembly. With LTO, these constants appear directly
 * in main()'s body (or the caller's), which can be confusing.
 *
 * Without LTO: you see a call math_hash → look at the body → spot
 *   the constant 31 and the polynomial hash pattern.
 * With LTO: the constant 31 appears in main() without obvious context.
 * -------------------------------------------------------------------------- */
unsigned int math_hash(const char *str)
{
    unsigned int hash = 0x5F3759DF;  /* Recognizable constant */

    while (*str) {
        hash = hash * 31 + (unsigned char)(*str);
        str++;
    }

    /* Finalization — bit mixing */
    hash ^= (hash >> 16);
    hash *= 0x45D9F3B;
    hash ^= (hash >> 16);

    return hash;
}

/* --------------------------------------------------------------------------
 * Function with division by constant — the magic number.
 *
 * Without LTO: the division by 7 generates a magic number in math_divide_sum.
 * With LTO: the magic number appears in the caller, mixed with its code.
 * -------------------------------------------------------------------------- */
int math_divide_sum(const int *data, int n, int divisor)
{
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += data[i] / divisor;
    }
    return sum;
}

/* --------------------------------------------------------------------------
 * Function that will NOT be inlined even with LTO — too large.
 *
 * GCC's inlining threshold is based on the number of "gimple statements".
 * This function is deliberately large to remain as a call.
 * -------------------------------------------------------------------------- */
long math_complex_transform(const int *data, int n)
{
    long result = 0;
    long running_min = data[0];
    long running_max = data[0];
    long running_avg = 0;

    /* First pass: statistics */
    for (int i = 0; i < n; i++) {
        if (data[i] < running_min) running_min = data[i];
        if (data[i] > running_max) running_max = data[i];
        running_avg += data[i];
    }
    running_avg /= (n > 0 ? n : 1);

    /* Second pass: transformation */
    long range = running_max - running_min;
    if (range == 0) range = 1;

    for (int i = 0; i < n; i++) {
        long normalized = ((data[i] - running_min) * 1000) / range;
        long deviation = data[i] - running_avg;
        result += normalized * normalized + deviation;
    }

    /* Third pass: rotating checksum */
    unsigned int checksum = 0xDEADBEEF;
    for (int i = 0; i < n; i++) {
        checksum ^= (unsigned int)(data[i] * 0x9E3779B9);
        checksum = (checksum << 7) | (checksum >> 25);
    }

    return result + (long)checksum;
}
