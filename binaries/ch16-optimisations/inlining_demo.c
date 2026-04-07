/* ============================================================================
 * Chapter 16 — Section 16.2
 * inlining_demo.c — Function inlining: when the function disappears
 *
 * This file illustrates the different GCC inlining scenarios:
 *
 *   1. Trivial function (getter/setter) — inlined from -O1
 *   2. Medium function — inlined starting at -O2
 *   3. Large function — rarely inlined except with __attribute__((always_inline))
 *   4. Recursive function — never inlined (except partial unrolling at -O3)
 *   5. Function called via pointer — never inlined (indirect call)
 *   6. Inlining chain (A calls B which calls C) — propagation
 *   7. Impact on the call graph as seen in Ghidra
 *
 * Key observations for RE:
 *   - At -O0: each function generates a symbol, a prologue/epilogue,
 *     an explicit call. The call graph is complete.
 *   - At -O2: small functions disappear from the binary. Their code
 *     is merged into the caller. Ghidra's call graph is incomplete —
 *     inlined functions no longer appear as XREFs.
 *   - At -O3: even more aggressive inlining, including medium-sized
 *     functions called multiple times (code duplication).
 *
 * Compile and compare:
 *   objdump -d -M intel build/inlining_demo_O0 | grep '<.*>:'
 *   objdump -d -M intel build/inlining_demo_O2 | grep '<.*>:'
 *   → Count the number of visible functions in each case.
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ==========================================================================
 * 1. Trivial functions — inlined from -O1
 *
 * These functions are so short that the call/ret overhead exceeds the
 * body cost. GCC systematically inlines them from -O1.
 * At -O0, they generate a real call with push rbp / mov rbp, rsp prologue.
 * ========================================================================== */

typedef struct {
    int x;
    int y;
    int z;
} Vec3;

/* Getter — a single useful instruction (mov) */
static int vec3_get_x(const Vec3 *v)
{
    return v->x;
}

/* Setter — a store + a return */
static void vec3_set_x(Vec3 *v, int val)
{
    v->x = val;
}

/* Trivial computation — will be reduced to a lea or add */
static int vec3_length_squared(const Vec3 *v)
{
    return v->x * v->x + v->y * v->y + v->z * v->z;
}

/* ==========================================================================
 * 2. Medium-sized function — inlined at -O2 if called few times
 *
 * GCC uses a heuristic based on the estimated body size
 * (in "gimple statements") and the number of call sites.
 * A function called only once is almost always inlined at -O2.
 * ========================================================================== */

static int transform_value(int input, int factor, int offset)
{
    int result = input;

    /* A few operations — not trivial, but not huge */
    result = result * factor;
    result = result + offset;

    if (result < 0)
        result = -result;

    result = result % 1000;

    if (result > 500)
        result = 1000 - result;

    return result;
}

/* ==========================================================================
 * 3. Large function — resists inlining at -O2
 *
 * This function is deliberately long. GCC does not inline it at -O2
 * because the code size overhead exceeds the gain.
 * You can force inlining with __attribute__((always_inline)).
 *
 * For RE: a function that remains visible is easier to analyze.
 * ========================================================================== */

static int heavy_computation(const int *data, int len)
{
    int acc = 0;
    int min_val = data[0];
    int max_val = data[0];

    for (int i = 0; i < len; i++) {
        acc += data[i] * data[i];
        if (data[i] < min_val) min_val = data[i];
        if (data[i] > max_val) max_val = data[i];
    }

    int range = max_val - min_val;
    if (range == 0) range = 1;

    int normalized = 0;
    for (int i = 0; i < len; i++) {
        normalized += ((data[i] - min_val) * 100) / range;
    }

    int checksum = 0;
    for (int i = 0; i < len; i++) {
        checksum ^= (data[i] << (i % 8));
        checksum = (checksum >> 3) | (checksum << 29);  /* rotate right 3 */
    }

    return acc + normalized + checksum;
}

/* ==========================================================================
 * 4. Recursive function — NOT inlined
 *
 * Inlining a recursive function is theoretically impossible
 * (depth unknown at compile time). GCC never inlines it directly,
 * but may unroll the first few levels at -O3.
 * ========================================================================== */

static int fibonacci(int n)
{
    if (n <= 1)
        return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

/* Iterative version for comparison — will be inlined at -O2 if called
 * only once. */
static int fibonacci_iter(int n)
{
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

/* ==========================================================================
 * 5. Indirect call via function pointer — NEVER inlined
 *
 * The compiler cannot inline a call whose target is determined
 * at runtime. This is the same mechanism that makes C++ virtual
 * dispatch (via vtable) opaque to the optimizer.
 *
 * For RE: a call [rax] or call [rbx+offset] signals an indirect
 * call — look for where the pointer comes from.
 * ========================================================================== */

typedef int (*operation_fn)(int, int);

static int op_add(int a, int b) { return a + b; }
static int op_sub(int a, int b) { return a - b; }
static int op_mul(int a, int b) { return a * b; }

static int apply_operation(operation_fn op, int a, int b)
{
    /* call [register] — never inlined */
    return op(a, b);
}

/* ==========================================================================
 * 6. Inlining chain — A calls B which calls C
 *
 * At -O2, C is inlined into B, then B+C is inlined into A.
 * Result: in the binary, only A exists, with all code merged.
 * The call graph loses two levels.
 * ========================================================================== */

static int step_c(int x)
{
    return x * 3 + 1;
}

static int step_b(int x)
{
    int tmp = step_c(x);
    return tmp + step_c(tmp);
}

static int step_a(int x)
{
    return step_b(x) + step_b(x + 1);
}

/* ==========================================================================
 * 7. Functions with __attribute__ — explicit control
 *
 * noinline: forces GCC NOT to inline (useful for debug/profiling).
 * always_inline: forces inlining even if GCC considers it unprofitable.
 * ========================================================================== */

__attribute__((noinline))
static int forced_noinline(int x)
{
    return x * x + x + 1;
}

/* always_inline must be static inline to work */
__attribute__((always_inline))
static inline int forced_inline(int x)
{
    /* This code will be duplicated at each call site, even if it's large */
    int result = x;
    for (int i = 0; i < 10; i++) {
        result = (result * 31) ^ (result >> 3);
    }
    return result;
}

/* ==========================================================================
 * Entry point
 * ========================================================================== */

int main(int argc, char *argv[])
{
    int input = 10;
    if (argc > 1)
        input = atoi(argv[1]);

    /* --- 1. Trivial functions (inlined from -O1) --- */
    Vec3 v = { input, input + 1, input + 2 };
    vec3_set_x(&v, input * 2);
    int vx = vec3_get_x(&v);
    int vlen = vec3_length_squared(&v);
    printf("Vec3: x=%d, len²=%d\n", vx, vlen);

    /* --- 2. Medium function (inlined at -O2 if single call site) --- */
    int transformed = transform_value(input, 7, -13);
    printf("Transformed: %d\n", transformed);

    /* --- 3. Large function (remains a call even at -O2) --- */
    int data[] = { input, input*2, input*3, input+5, input-3,
                   input*4, input+7, input-1 };
    int heavy = heavy_computation(data, 8);
    printf("Heavy: %d\n", heavy);

    /* --- 4. Recursion vs iteration --- */
    int fib_r = fibonacci(input % 25);       /* Keeps a recursive call */
    int fib_i = fibonacci_iter(input % 90);  /* Can be inlined */
    printf("Fib recursive(%d)=%d, iterative(%d)=%d\n",
           input % 25, fib_r, input % 90, fib_i);

    /* --- 5. Indirect call (never inlined) --- */
    operation_fn ops[] = { op_add, op_sub, op_mul };
    int op_result = apply_operation(ops[input % 3], input, input + 5);
    printf("Indirect call result: %d\n", op_result);

    /* --- 6. Inlining chain A → B → C --- */
    int chain = step_a(input);
    printf("Chain A->B->C: %d\n", chain);

    /* --- 7. noinline / always_inline attributes --- */
    int ni = forced_noinline(input);        /* Always a call */
    int fi = forced_inline(input);          /* Always inlined */
    int fi2 = forced_inline(input + 1);     /* Duplicated here too */
    printf("noinline=%d, always_inline=%d, %d\n", ni, fi, fi2);

    return 0;
}
