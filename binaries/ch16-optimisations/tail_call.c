/* ============================================================================
 * Chapter 16 — Section 16.4
 * tail_call.c — Tail call optimization and its impact on the stack
 *
 * Tail call optimization (TCO) transforms a function call in tail
 * position (the last action before return) into a simple jmp.
 * Consequences:
 *   - No new frame on the stack → no stack growth
 *   - The call/ret disappears → GDB backtrace is truncated
 *   - Tail recursion becomes a loop
 *
 * This file illustrates:
 *   1. Tail recursion → transformed into a loop
 *   2. NON-tail recursion → remains a recursive call
 *   3. Tail call to another function (mutual recursion)
 *   4. Tail call prevented by work after the call
 *   5. Tail call prevented by destructors / cleanup
 *   6. Impact on GDB backtrace
 *
 * Observation points:
 *   -O0: NEVER TCO. Each call = call + new frame.
 *   -O1: TCO enabled for simple cases (direct tail recursion).
 *   -O2: more aggressive TCO, includes tail calls to other functions.
 *   -O3: same as -O2 for TCO (no additional gain).
 *
 * Key test: compare the stack with GDB
 *   gdb ./build/tail_call_O0 -ex 'b factorial_tail' -ex 'r 10' -ex 'bt'
 *   gdb ./build/tail_call_O2 -ex 'b factorial_tail' -ex 'r 10' -ex 'bt'
 *   → At O0, the backtrace shows N frames. At O2, a single frame.
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>

/* ==========================================================================
 * 1. Tail recursion — factorial with accumulator
 *
 * The recursive call is the last instruction: it's a tail call.
 *
 *   -O0: call factorial_tail at each level → N frames on the stack.
 *   -O2: the call is replaced by a jmp to the function start.
 *         Parameters are updated in registers, then
 *         jmp factorial_tail (or jmp to the start label).
 *         → 1 single frame, recursion becomes a loop.
 * ========================================================================== */

static long factorial_tail(int n, long accumulator)
{
    if (n <= 1)
        return accumulator;

    /* Tail position: nothing after this call */
    return factorial_tail(n - 1, accumulator * n);
}

long factorial(int n)
{
    return factorial_tail(n, 1);
}

/* ==========================================================================
 * 2. NON-tail recursion — classic factorial
 *
 * Here, the recursive call result is multiplied AFTER the return.
 * This is NOT a tail call. The compiler CANNOT optimize.
 *
 *   -O0 and -O2: call factorial_notail in both cases.
 *   (GCC may however transform to iterative via other passes,
 *    but this is not TCO strictly speaking.)
 * ========================================================================== */

static long factorial_notail(int n)
{
    if (n <= 1)
        return 1;

    /* NOT in tail position: multiplication after return */
    return n * factorial_notail(n - 1);
}

/* ==========================================================================
 * 3. Tail call to another function (mutual/indirect tail call)
 *
 * is_even and is_odd call each other in tail position.
 *
 *   -O0: two functions with mutual calls → stack overflow if n is large.
 *   -O2: calls are replaced by jmps → no stack growth.
 *         GCC may even merge both into a single loop.
 * ========================================================================== */

/* Forward declarations for mutual recursion */
static int is_odd(unsigned int n);

static int is_even(unsigned int n)
{
    if (n == 0) return 1;
    return is_odd(n - 1);    /* Tail call to is_odd */
}

static int is_odd(unsigned int n)
{
    if (n == 0) return 0;
    return is_even(n - 1);   /* Tail call to is_even */
}

/* ==========================================================================
 * 4. Tail call PREVENTED — work after the call
 *
 * These functions look like tail calls but aren't, because there is
 * work after the recursive call.
 * ========================================================================== */

/* Addition after the call → not a tail call */
static int sum_recursive(int n)
{
    if (n <= 0) return 0;
    return n + sum_recursive(n - 1);  /* n + ... prevents TCO */
}

/* Tail-recursive version with accumulator — for comparison */
static int sum_tail(int n, int acc)
{
    if (n <= 0) return acc;
    return sum_tail(n - 1, acc + n);  /* Valid tail call */
}

/* ==========================================================================
 * 5. Tail call prevented by local stack
 *
 * If the function has a local array or an object requiring cleanup
 * (e.g.: variable-length array, alloca, or in C++ a destructor),
 * TCO is blocked because the frame must remain active for cleanup.
 * ========================================================================== */

static int process_with_buffer(int n, int threshold)
{
    /* This local buffer prevents TCO because the frame must remain
     * for deallocation (in theory; GCC can sometimes work around this). */
    int buffer[64];

    buffer[n % 64] = n;

    if (n <= 0)
        return buffer[0];

    if (n > threshold)
        return process_with_buffer(n - 2, threshold);  /* Tail position... */
    else
        return process_with_buffer(n - 1, threshold);  /* ...but buffer blocks */
}

/* ==========================================================================
 * 6. Tail call via function pointer
 *
 * TCO also works with indirect calls in tail position,
 * although it is less frequently optimized.
 *
 *   -O2: GCC may emit a jmp [rax] instead of call [rax] + ret.
 * ========================================================================== */

typedef long (*transform_fn)(long, int);

static long double_it(long val, int steps)
{
    if (steps <= 0) return val;
    return double_it(val * 2, steps - 1);
}

static long triple_it(long val, int steps)
{
    if (steps <= 0) return val;
    return triple_it(val * 3, steps - 1);
}

static long apply_transform(transform_fn fn, long initial, int steps)
{
    /* Indirect tail call — jmp [register] at -O2 */
    return fn(initial, steps);
}

/* ==========================================================================
 * 7. RE detection example: recognizing a TCO in the binary
 *
 * Tail call signature in the disassembly:
 *   - The function ends with a jmp to itself (or another fn)
 *     instead of a call + ret.
 *   - No push rbp / sub rsp at the return point.
 *   - GDB backtrace shows only one frame even after N recursions.
 *
 * RE trap: one can confuse a TCO with a while loop written in the
 * source. Only structural analysis (parameters reinitialized
 * + backward jmp) can distinguish them.
 * ========================================================================== */

/* GCD (Euclid's algorithm) — naturally tail recursive */
static int gcd(int a, int b)
{
    if (b == 0) return a;
    return gcd(b, a % b);   /* Tail call */
}

/* Fast modular exponentiation — tail recursive with accumulator */
static long mod_pow_tail(long base, int exp, long mod, long acc)
{
    if (exp == 0) return acc;

    if (exp % 2 == 1)
        return mod_pow_tail(base, exp - 1, mod, (acc * base) % mod);
    else
        return mod_pow_tail((base * base) % mod, exp / 2, mod, acc);
}

static long mod_pow(long base, int exp, long mod)
{
    return mod_pow_tail(base % mod, exp, mod, 1);
}

/* ==========================================================================
 * Entry point
 * ========================================================================== */

int main(int argc, char *argv[])
{
    int input = 12;
    if (argc > 1)
        input = atoi(argv[1]);

    /* 1. Tail recursive factorial */
    long fact_t = factorial(input);
    printf("factorial_tail(%d) = %ld\n", input, fact_t);

    /* 2. Non-tail recursive factorial */
    long fact_nt = factorial_notail(input);
    printf("factorial_notail(%d) = %ld\n", input, fact_nt);

    /* 3. Mutual tail calls */
    printf("is_even(%d) = %d\n", input, is_even((unsigned)input));
    printf("is_odd(%d)  = %d\n", input, is_odd((unsigned)input));

    /* 4. Non-tail vs tail sum */
    int s1 = sum_recursive(input);
    int s2 = sum_tail(input, 0);
    printf("sum_recursive(%d) = %d\n", input, s1);
    printf("sum_tail(%d)      = %d\n", input, s2);

    /* 5. Buffer prevents TCO */
    int pb = process_with_buffer(input, 5);
    printf("process_with_buffer(%d, 5) = %d\n", input, pb);

    /* 6. Indirect tail call */
    transform_fn fn = (input % 2 == 0) ? double_it : triple_it;
    long tr = apply_transform(fn, 1, input);
    printf("apply_transform(1, %d) = %ld\n", input, tr);

    /* 7. GCD and modular exponentiation */
    int g = gcd(input * 7, input * 3);
    long mp = mod_pow(input, 13, 1000000007L);
    printf("gcd(%d, %d) = %d\n", input * 7, input * 3, g);
    printf("mod_pow(%d, 13, 1e9+7) = %ld\n", input, mp);

    return 0;
}
