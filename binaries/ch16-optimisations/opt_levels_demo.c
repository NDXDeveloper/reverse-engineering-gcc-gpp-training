/* ============================================================================
 * Chapter 16 — Section 16.1
 * opt_levels_demo.c — Impact of -O0, -O1, -O2, -O3, -Os on disassembly
 *
 * This file gathers several common C patterns whose assembly
 * translation varies drastically depending on optimization level:
 *
 *   - Simple arithmetic (additions, multiplications, divisions)
 *   - Conditional branches (if/else, switch)
 *   - Accumulation loop
 *   - Helper function call
 *   - Stack-allocated array access
 *
 * Compile with:
 *   gcc -O0 -g -o opt_levels_demo_O0 opt_levels_demo.c
 *   gcc -O2 -g -o opt_levels_demo_O2 opt_levels_demo.c
 *
 * Then compare:
 *   objdump -d -M intel opt_levels_demo_O0 | grep -A 40 '<compute>:'
 *   objdump -d -M intel opt_levels_demo_O2 | grep -A 40 '<compute>:'
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Simple helper function — potential inlining target from -O1.
 * At -O0, it generates an explicit call.
 * At -O2+, it is inlined and can even be evaluated at compile time
 * if the arguments are constants.
 * -------------------------------------------------------------------------- */
static int square(int x)
{
    return x * x;
}

/* --------------------------------------------------------------------------
 * Function with conditional branch.
 * Observation points:
 *   -O0: classic cmp + jle/jg, both branches are present.
 *   -O1: the compiler may use cmov (conditional move) to
 *         eliminate the branch if the body is simple.
 *   -O2: constant propagation possible if called with known value.
 * -------------------------------------------------------------------------- */
static int clamp(int value, int low, int high)
{
    if (value < low)
        return low;
    if (value > high)
        return high;
    return value;
}

/* --------------------------------------------------------------------------
 * Classification function — switch/case.
 * Observation points:
 *   -O0: cascade of cmp/je (sequential comparisons).
 *   -O2: GCC may generate a jump table if cases are dense,
 *         or a reordered comparison series (binary search).
 *   -Os: prefers compact cascade over jump table.
 * -------------------------------------------------------------------------- */
static const char *classify_grade(int score)
{
    switch (score / 10) {
        case 10:
        case 9:  return "A";
        case 8:  return "B";
        case 7:  return "C";
        case 6:  return "D";
        case 5:  return "E";
        default: return "F";
    }
}

/* --------------------------------------------------------------------------
 * Accumulation loop with arithmetic.
 * Observation points:
 *   -O0: the loop variable and accumulator live on the stack,
 *         with load/store at each iteration.
 *   -O1: variables move to registers.
 *   -O2: the compiler may reduce the loop to a closed-form formula
 *         (Gauss) or partially unroll it.
 *   -O3: aggressive unrolling + potential vectorization.
 * -------------------------------------------------------------------------- */
static long sum_of_squares(int n)
{
    long total = 0;
    for (int i = 1; i <= n; i++) {
        total += square(i);
    }
    return total;
}

/* --------------------------------------------------------------------------
 * Stack array manipulation + division.
 * Observation points:
 *   -O0: each array access is an explicit offset calculation
 *         from rbp. Division generates an idiv.
 *   -O2: GCC replaces division by a constant with multiplication
 *         by the modular inverse ("magic number").
 *         The array may be partially eliminated if values
 *         are propagated.
 * -------------------------------------------------------------------------- */
static int compute(int a, int b)
{
    int data[8];

    for (int i = 0; i < 8; i++) {
        data[i] = a * (i + 1) + b;
    }

    int result = 0;
    for (int i = 0; i < 8; i++) {
        result += data[i] / 7;      /* Division by constant → magic number at O2 */
    }

    result += data[3] % 5;          /* Modulo by constant → also transformed */

    return result;
}

/* --------------------------------------------------------------------------
 * Function with string and library call.
 * Observation points:
 *   -O0: strlen is an explicit call via PLT.
 *   -O2: if the string is a known constant, strlen can be replaced
 *         by a constant at compile time. puts can replace printf
 *         when there is no format specifier.
 * -------------------------------------------------------------------------- */
static void print_info(const char *label, int value)
{
    printf("[%s] (len=%zu) = %d\n", label, strlen(label), value);
}

/* --------------------------------------------------------------------------
 * Function with many parameters — observe passing via System V AMD64
 * registers (rdi, rsi, rdx, rcx, r8, r9) then overflow onto the stack.
 * -------------------------------------------------------------------------- */
static int multi_args(int a, int b, int c, int d, int e, int f, int g, int h)
{
    /* The first 6 (a-f) pass through registers, g and h through the stack.
     * At -O0, everything is copied to the stack in the prologue.
     * At -O2, computations stay in registers. */
    return (a + b) * (c - d) + (e ^ f) - (g | h);
}

/* --------------------------------------------------------------------------
 * Entry point — uses all functions to prevent GCC from
 * eliminating them as dead code (dead code elimination).
 * -------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    int input = 42;
    if (argc > 1) {
        input = atoi(argv[1]);
    }

    /* square + sum_of_squares */
    int sq = square(input);
    long sos = sum_of_squares(input);

    /* clamp */
    int clamped = clamp(input, 0, 100);

    /* classify_grade */
    const char *grade = classify_grade(clamped);

    /* compute */
    int comp = compute(input, sq);

    /* multi_args */
    int multi = multi_args(input, sq, clamped, comp,
                           input + 1, sq - 1, clamped + 2, comp - 3);

    /* Display results */
    print_info("square", sq);
    print_info("sum_of_squares", (int)sos);
    print_info("clamp", clamped);
    print_info("compute", comp);
    print_info("multi_args", multi);
    printf("Grade: %s\n", grade);

    return 0;
}
