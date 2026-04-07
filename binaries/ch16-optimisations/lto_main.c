/* ============================================================================
 * Chapter 16 — Section 16.5
 * lto_main.c — Entry point for the Link-Time Optimization demo
 *
 * This file uses functions from lto_math.c and lto_utils.c.
 *
 * Compilation and comparison:
 *
 *   WITHOUT LTO:
 *     gcc -O2 -g -o build/lto_demo_O2 lto_main.c lto_math.c lto_utils.c -lm
 *
 *   WITH LTO:
 *     gcc -O2 -g -flto -o build/lto_demo_O2_flto lto_main.c lto_math.c lto_utils.c -lm
 *
 * Recommended analysis — compare visible symbols:
 *
 *   nm build/lto_demo_O2      | grep ' T '    → all functions present
 *   nm build/lto_demo_O2_flto | grep ' T '    → trivial functions gone
 *
 * Compare the call graph in Ghidra:
 *   → Without LTO: main() calls math_square, math_cube, utils_clamp, etc.
 *   → With LTO: main() contains the inlined code, fewer XREFs.
 *
 * Compare sizes:
 *   ls -la build/lto_demo_O2 build/lto_demo_O2_flto
 *   → LTO often produces a slightly smaller binary (cross-module dead code
 *     elimination) or larger one (cross-module inlining).
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "lto_math.h"
#include "lto_utils.h"

#define DATA_SIZE 32

int main(int argc, char *argv[])
{
    int input = 8;
    if (argc > 1)
        input = atoi(argv[1]);

    /* ----- Using trivial functions from lto_math ----- */

    /* Without LTO: call math_square (symbol visible in nm).
     * With LTO: inlined → imul or lea in main's body. */
    int sq = math_square(input);
    int cb = math_cube(input);
    printf("square(%d) = %d\n", input, sq);
    printf("cube(%d)   = %d\n", input, cb);

    /* ----- Medium-sized functions ----- */

    /* sum_of_powers: nested loop.
     * Without LTO: call math_sum_of_powers.
     * With LTO: potentially inlined if single call site. */
    long sop2 = math_sum_of_powers(input, 2);  /* Sum of squares */
    long sop3 = math_sum_of_powers(input, 3);  /* Sum of cubes */
    printf("sum_of_squares(%d) = %ld\n", input, sop2);
    printf("sum_of_cubes(%d)   = %ld\n", input, sop3);

    /* ----- Hash — recognizable constants ----- */

    /* The constant 0x5F3759DF and the multiplier 31 from math_hash
     * appear in main()'s body with LTO.
     * Without LTO, you need to follow the call to find them. */
    unsigned int h1 = math_hash("hello");
    unsigned int h2 = math_hash("reverse engineering");
    printf("hash('hello')      = 0x%08X\n", h1);
    printf("hash('reverse eng')= 0x%08X\n", h2);

    /* ----- Using functions from lto_utils ----- */

    int data[DATA_SIZE];

    /* utils_fill_sequence: trivial, inlined with LTO.
     * Without LTO: call utils_fill_sequence. */
    utils_fill_sequence(data, DATA_SIZE, input, 3);

    /* utils_array_max: simple loop, inlined with LTO. */
    int mx = utils_array_max(data, DATA_SIZE);
    printf("array_max = %d\n", mx);

    /* utils_clamp: very trivial, always inlined with LTO.
     * Without LTO: call utils_clamp → you see the cmp/cmov inside.
     * With LTO: cmp/cmov directly in main(). */
    int clamped = utils_clamp(sq, 0, 10000);
    printf("clamp(%d, 0, 10000) = %d\n", sq, clamped);

    /* utils_int_to_hex: medium size. */
    char hexbuf[16];
    utils_int_to_hex(sq, hexbuf, sizeof(hexbuf));
    printf("hex(%d) = %s\n", sq, hexbuf);

    /* ----- Division by constant across files ----- */

    /* Without LTO: call math_divide_sum. The magic number for division
     *   by 7 is in math_divide_sum.
     * With LTO: the magic number ends up in main(). */
    int dsum = math_divide_sum(data, DATA_SIZE, 7);
    printf("divide_sum(/7) = %d\n", dsum);

    /* ----- Large function — remains a call even with LTO ----- */

    long ct = math_complex_transform(data, DATA_SIZE);
    printf("complex_transform = %ld\n", ct);

    /* ----- Final display (prevents dead code elimination) ----- */

    utils_print_array("data", data, DATA_SIZE);

    /* Use sqrt to justify -lm and show a library call
     * that is NEVER inlined (shared library). */
    double root = sqrt((double)sq);
    printf("sqrt(%d) = %.4f\n", sq, root);

    return 0;
}
