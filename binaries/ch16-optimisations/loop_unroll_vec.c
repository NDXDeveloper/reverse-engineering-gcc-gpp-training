/* ============================================================================
 * Chapter 16 — Section 16.3
 * loop_unroll_vec.c — Loop unrolling and vectorization (SIMD/SSE/AVX)
 *
 * This file contains loops designed to highlight:
 *
 *   1. Simple loop unrolling — the loop body is replicated N times
 *   2. Automatic vectorization (auto-vectorization) — iterations are
 *      grouped to use SIMD registers (xmm/ymm)
 *   3. Loops that GCC CANNOT vectorize (dependencies, aliasing)
 *   4. Peeling and "remainder" handling code (tail/epilogue)
 *
 * Observation points:
 *
 *   -O0: one loop = one cmp + jle + body + jmp. Literal.
 *   -O1: variables in registers, no unrolling.
 *   -O2: partial unrolling (typically 2x or 4x), basic vectorization.
 *   -O3: aggressive unrolling + SSE/AVX vectorization, "prologue" loop
 *         for alignment, vectorized main loop, "epilogue" loop for
 *         remaining elements.
 *   -Os: NO unrolling (increases size), minimal vectorization.
 *
 * To force AVX2 (256-bit ymm registers):
 *   gcc -O3 -mavx2 -g -o loop_unroll_vec_O3 loop_unroll_vec.c
 *
 * Recommended analysis:
 *   objdump -d -M intel build/loop_unroll_vec_O3 | less
 *   → Look for instructions: movdqa, paddd, pmulld (SSE)
 *      or vpaddd, vpmulld, vmovdqu (AVX)
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE 1024

/* Prevent GCC from optimizing away unused results */
static void consume(const void *ptr, size_t size)
{
    /* Forces the compiler to consider the memory as read.
     * At -O2+, this function is inlined but the barrier remains. */
    __asm__ volatile("" : : "r"(ptr), "r"(size) : "memory");
}

/* ==========================================================================
 * 1. Vectorizable loop — element-wise addition
 *
 * Ideal pattern for vectorization: no inter-iteration dependency,
 * uniform operation on contiguous data.
 *
 *   -O0: scalar loop, adds one int at a time.
 *   -O2: may vectorize with movdqu + paddd (4 ints in SSE).
 *   -O3 -mavx2: vpaddd on ymm (8 ints simultaneously).
 *
 * In the disassembly, look for:
 *   - movdqu xmm0, [rdi+rax*4]   <- loads 4 integers (128 bits)
 *   - paddd  xmm0, xmm1           <- parallel addition of 4 integers
 *   - vmovdqu ymm0, [rdi+rax*4]  <- loads 8 integers (256 bits, AVX)
 * ========================================================================== */

static void vec_add(int *dst, const int *a, const int *b, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = a[i] + b[i];
    }
}

/* ==========================================================================
 * 2. Vectorizable loop — multiply + accumulate (dot product)
 *
 * Reduction (a single accumulator): GCC must prove that the reduction
 * is associative and commutative (true for integers, not always
 * for floats without -ffast-math).
 *
 *   -O2: may vectorize with vector accumulator, then horizontal
 *         reduction at the end (phaddd or shuffle sequence).
 *   -O3: uses multiple accumulators to hide latency.
 * ========================================================================== */

static long dot_product(const int *a, const int *b, int n)
{
    long sum = 0;
    for (int i = 0; i < n; i++) {
        sum += (long)a[i] * (long)b[i];
    }
    return sum;
}

/* ==========================================================================
 * 3. Loop with visible unrolling — compile-time known count
 *
 * When the iteration count is known and small, GCC can fully unroll
 * the loop (no cmp/jmp at all).
 *
 *   -O0: classic loop, 16 iterations.
 *   -O2: partial unrolling (e.g.: 4 iterations per round).
 *   -O3: full unrolling possible (16 sequential instructions).
 * ========================================================================== */

static void fixed_size_init(int arr[16])
{
    for (int i = 0; i < 16; i++) {
        arr[i] = i * i + 1;
    }
}

/* ==========================================================================
 * 4. NON-vectorizable loop — inter-iteration dependency
 *
 * Each iteration depends on the result of the previous one. Impossible
 * to parallelize. GCC can still unroll, but not vectorize.
 *
 * For RE: if you don't see SIMD instructions in an O3 loop,
 * it's probably because of a dependency.
 * ========================================================================== */

static void dependent_loop(int *data, int n)
{
    for (int i = 1; i < n; i++) {
        data[i] = data[i - 1] * 3 + data[i];
    }
}

/* ==========================================================================
 * 5. Loop with potential aliasing — restrict needed
 *
 * Without the restrict keyword, GCC cannot prove that dst and src
 * do not overlap in memory. It must therefore remain conservative.
 *
 * vec_add_alias  : without restrict → vectorization possible but with tests.
 * vec_add_noalias: with restrict → direct vectorization.
 *
 * Compare the disassembly of both at -O2.
 * ========================================================================== */

static void vec_add_alias(int *dst, const int *src, int n)
{
    /* GCC doesn't know if dst and src overlap.
     * It may generate two versions: one vectorized and one scalar,
     * with a runtime aliasing test. */
    for (int i = 0; i < n; i++) {
        dst[i] = dst[i] + src[i];
    }
}

static void vec_add_noalias(int * restrict dst, const int * restrict src, int n)
{
    /* With restrict, GCC is guaranteed there is no aliasing.
     * Direct vectorization, no runtime test. */
    for (int i = 0; i < n; i++) {
        dst[i] = dst[i] + src[i];
    }
}

/* ==========================================================================
 * 6. Float loop — -ffast-math changes everything
 *
 * Floating-point addition is NOT associative (IEEE 754 rounding).
 * Without -ffast-math, GCC does not vectorize float reductions.
 * You can verify by comparing -O3 and -O3 -ffast-math.
 *
 * Note: this file is compiled without -ffast-math by default.
 * To test: gcc -O3 -ffast-math -g -o test_fastmath loop_unroll_vec.c
 * ========================================================================== */

static float float_sum(const float *data, int n)
{
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        sum += data[i];
    }
    return sum;
}

/* ==========================================================================
 * 7. memset/memcpy loop — compiler recognition
 *
 * GCC recognizes certain loop patterns as disguised memset or memcpy
 * and replaces them with optimized libc calls (or rep stosb / rep movsb
 * instructions).
 *
 *   -O0: explicit loop.
 *   -O2: replaced by a call to memset/memcpy.
 *
 * For RE: if you see a memset where the source code doesn't have one,
 * it's this optimization.
 * ========================================================================== */

static void zero_fill(int *arr, int n)
{
    for (int i = 0; i < n; i++) {
        arr[i] = 0;
    }
}

static void copy_array(int *dst, const int *src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

/* ==========================================================================
 * 8. Strength reduction — loop transformation
 *
 * GCC transforms multiplications depending on the loop index
 * into successive additions (strength reduction).
 *   Ex: data[i * stride] → a pointer is incremented by stride each round.
 *
 *   -O0: explicit imul at each iteration.
 *   -O2: the imul disappears, replaced by an add on the pointer.
 * ========================================================================== */

static void strided_write(int *data, int n, int stride, int value)
{
    for (int i = 0; i < n; i++) {
        data[i * stride] = value + i;
    }
}

/* ==========================================================================
 * Entry point
 * ========================================================================== */

int main(int argc, char *argv[])
{
    int n = ARRAY_SIZE;
    if (argc > 1)
        n = atoi(argv[1]);
    if (n <= 0 || n > ARRAY_SIZE)
        n = ARRAY_SIZE;

    /* Stack-allocated arrays */
    int a[ARRAY_SIZE], b[ARRAY_SIZE], dst[ARRAY_SIZE];
    float fdata[ARRAY_SIZE];

    /* Initialization with deterministic values */
    for (int i = 0; i < ARRAY_SIZE; i++) {
        a[i] = i + 1;
        b[i] = (i * 7 + 3) % 100;
        fdata[i] = (float)(i * 0.1);
    }

    /* 1. Vectorizable addition */
    vec_add(dst, a, b, n);
    consume(dst, sizeof(dst));

    /* 2. Dot product (reduction) */
    long dp = dot_product(a, b, n);
    printf("Dot product: %ld\n", dp);

    /* 3. Fixed size — full unrolling */
    int fixed[16];
    fixed_size_init(fixed);
    consume(fixed, sizeof(fixed));

    /* 4. Inter-iteration dependency — non-vectorizable */
    memcpy(dst, a, (size_t)n * sizeof(int));
    dependent_loop(dst, n);
    consume(dst, sizeof(dst));

    /* 5. Aliasing: with and without restrict */
    memcpy(dst, a, (size_t)n * sizeof(int));
    vec_add_alias(dst, b, n);

    memcpy(dst, a, (size_t)n * sizeof(int));
    vec_add_noalias(dst, b, n);
    consume(dst, sizeof(dst));

    /* 6. Floats — conditional vectorization */
    float fs = float_sum(fdata, n);
    printf("Float sum: %f\n", fs);

    /* 7. memset/memcpy recognition */
    zero_fill(dst, n);
    copy_array(dst, a, n);
    consume(dst, sizeof(dst));

    /* 8. Strength reduction */
    memset(dst, 0, sizeof(dst));
    strided_write(dst, n / 4, 4, 42);
    consume(dst, sizeof(dst));

    /* Use fixed to prevent elimination */
    int sum = 0;
    for (int i = 0; i < 16; i++) sum += fixed[i];
    printf("Fixed sum: %d, dst[0]=%d\n", sum, dst[0]);

    return 0;
}
