/* ============================================================================
 * Chapter 16 — Section 16.6
 * gcc_idioms.c — Recognizable GCC patterns and idioms
 *
 * This file gathers the most frequent transformations that GCC
 * applies to C code and that a reverse engineer must know how to
 * recognize instantly in a disassembly.
 *
 * Each function isolates ONE idiom. Systematically compare -O0 and -O2.
 *
 * List of covered idioms:
 *
 *   1.  Division by constant → multiplication by magic number
 *   2.  Modulo by power of 2 → AND bitmask
 *   3.  Modulo by non-power-of-2 constant → magic number + adjustment
 *   4.  Multiplication by constant → lea/shl/add combination
 *   5.  Simple branch → cmov (conditional move)
 *   6.  Single bit test → test + jnz / setnz
 *   7.  Boolean normalization (!!x) → comparison + setnz
 *   8.  Dense switch → jump table
 *   9.  Sparse switch → binary comparison tree
 *  10.  Bit rotation (no C operator) → rol/ror
 *  11.  abs() without branch → sar + xor + sub
 *  12.  min/max without branch → cmp + cmov
 *  13.  Structure initialization → rep stosq or mov sequence
 *  14.  Inline strcmp/memcmp → 8-byte block comparison
 *  15.  Population count (popcount) → popcnt if -mpopcnt
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ==========================================================================
 * 1. Division by constant → magic number
 *
 * GCC replaces  x / N  with  (x * MAGIC) >> SHIFT  when N is known.
 * This is the most famous and most confusing optimization in RE.
 *
 *   x / 7  at -O0:  idiv with divisor 7
 *   x / 7  at -O2:  imul by 0x92492493 (or similar), then shift
 *
 * Formula: MAGIC ≈ (2^(32+s)) / N, rounded, where s is the shift.
 * Reference: "Hacker's Delight" chapter 10.
 * ========================================================================== */

int idiom_div_by_constant(int x)
{
    int a = x / 3;
    int b = x / 7;
    int c = x / 10;
    int d = x / 100;
    int e = x / 127;
    return a + b + c + d + e;
}

/* Unsigned variant — the magic number is different (no correction
 * for negative numbers). */
unsigned int idiom_udiv_by_constant(unsigned int x)
{
    unsigned int a = x / 3;
    unsigned int b = x / 7;
    unsigned int c = x / 10;
    return a + b + c;
}

/* ==========================================================================
 * 2. Modulo by power of 2 → AND
 *
 *   x % 8   at -O0: idiv then take edx (remainder)
 *   x % 8   at -O2: and eax, 7 (for unsigned)
 *
 * For signed values, GCC adds a correction (test + lea + and)
 * because C modulo has the sign of the dividend.
 * ========================================================================== */

int idiom_mod_power_of_2(int x)
{
    return x % 8;     /* Signed: correction needed */
}

unsigned int idiom_umod_power_of_2(unsigned int x)
{
    return x % 8;     /* Unsigned: simple and */
}

int idiom_mod_16(int x)
{
    return x % 16;
}

/* ==========================================================================
 * 3. Modulo by non-power-of-2 constant → magic number + sub
 *
 *   x % 7  =  x - (x / 7) * 7
 *
 * GCC first computes x/7 with the magic number (idiom 1),
 * then multiplies the result by 7 and subtracts.
 * ========================================================================== */

int idiom_mod_non_pow2(int x)
{
    return x % 7;
}

/* ==========================================================================
 * 4. Multiplication by constant → lea / shl / add
 *
 * GCC avoids imul when possible and uses combinations of
 * lea (which can do a + b*{1,2,4,8}) and shifts.
 *
 *   x * 3  → lea eax, [rdi + rdi*2]
 *   x * 5  → lea eax, [rdi + rdi*4]
 *   x * 9  → lea eax, [rdi + rdi*8]
 *   x * 10 → lea eax, [rdi + rdi*4] ; add eax, eax
 *   x * 7  → lea eax, [rdi + rdi*8] ; sub eax, rdi ; sub eax, rdi
 *            or via shl + sub
 *   x * 2  → add eax, eax  (or shl eax, 1)
 *   x * 4  → shl eax, 2
 * ========================================================================== */

int idiom_mul_by_constant(int x)
{
    int a = x * 2;
    int b = x * 3;
    int c = x * 5;
    int d = x * 7;
    int e = x * 9;
    int f = x * 10;
    int g = x * 15;
    int h = x * 100;
    return a + b + c + d + e + f + g + h;
}

/* ==========================================================================
 * 5. Branch → cmov (conditional move)
 *
 * When both branches of an if/else are simple assignments,
 * GCC replaces them with a cmov to avoid pipeline stalls.
 *
 *   if (a > b) result = a; else result = b;
 *   →  cmp edi, esi
 *      cmovl eax, esi    (if a < b, take b)
 *
 * cmov is non-speculative: both values are computed,
 * only the assignment is conditional.
 * ========================================================================== */

int idiom_cmov_max(int a, int b)
{
    return (a > b) ? a : b;
}

int idiom_cmov_abs(int x)
{
    return (x < 0) ? -x : x;
}

int idiom_cmov_clamp(int x, int lo, int hi)
{
    if (x < lo) x = lo;
    if (x > hi) x = hi;
    return x;
}

/* ==========================================================================
 * 6. Bit test → test + setcc / jcc
 *
 *   if (x & 0x80) → test edi, 0x80 ; jnz ...
 *   flag = (x & 4) != 0 → test edi, 4 ; setnz al
 * ========================================================================== */

int idiom_test_bit(int flags)
{
    int result = 0;
    if (flags & 0x01) result += 1;     /* test edi, 1 */
    if (flags & 0x04) result += 10;    /* test edi, 4 */
    if (flags & 0x80) result += 100;   /* test edi, 0x80 */
    return result;
}

/* ==========================================================================
 * 7. Boolean normalization — !!x → cmp + setne
 *
 *   !!x    in C converts any value to 0 or 1.
 *   -O2:  test edi, edi ; setne al ; movzx eax, al
 * ========================================================================== */

int idiom_bool_normalize(int x)
{
    return !!x;
}

int idiom_bool_from_compare(int a, int b)
{
    return (a == b);   /* cmp + sete + movzx */
}

/* ==========================================================================
 * 8. Dense switch → jump table
 *
 * When case values are close together (0, 1, 2, 3, 4, 5...),
 * GCC generates a jump table in .rodata:
 *   cmp edi, 5           ← bounds check
 *   ja  .Ldefault        ← out of bounds → default
 *   jmp [.Ljumptable + rdi*8]  ← indirect jump via the table
 *
 * The jump table is an array of pointers to each case block.
 * ========================================================================== */

const char *idiom_switch_dense(int day)
{
    switch (day) {
        case 0: return "Monday";
        case 1: return "Tuesday";
        case 2: return "Wednesday";
        case 3: return "Thursday";
        case 4: return "Friday";
        case 5: return "Saturday";
        case 6: return "Sunday";
        default: return "Unknown";
    }
}

/* ==========================================================================
 * 9. Sparse switch → comparison tree
 *
 * When values are far apart, a jump table would be too large.
 * GCC generates a binary comparison tree (binary search on cases).
 * ========================================================================== */

const char *idiom_switch_sparse(int code)
{
    switch (code) {
        case 1:    return "START";
        case 7:    return "PAUSE";
        case 42:   return "ANSWER";
        case 100:  return "PERCENT";
        case 255:  return "MAX_BYTE";
        case 1000: return "KILO";
        default:   return "UNKNOWN";
    }
}

/* ==========================================================================
 * 10. Bit rotation → rol / ror
 *
 * C has no rotation operator, but GCC recognizes the pattern
 *   (x << n) | (x >> (32 - n))
 * and replaces it with a rol (rotate left) instruction.
 *
 *   -O0: two shifts + one or.
 *   -O2: a single rol edx, cl (or rol with immediate).
 * ========================================================================== */

unsigned int idiom_rotate_left(unsigned int x, int n)
{
    return (x << n) | (x >> (32 - n));
}

unsigned int idiom_rotate_right(unsigned int x, int n)
{
    return (x >> n) | (x << (32 - n));
}

/* Rotation by constant — recognized even more easily */
unsigned int idiom_rotate_left_13(unsigned int x)
{
    return (x << 13) | (x >> 19);
}

/* ==========================================================================
 * 11. abs() without branch → sar + xor + sub (or neg + cmov)
 *
 * Classic pattern to compute absolute value without branching:
 *   int mask = x >> 31;       ← sar eax, 31 (all bits = sign)
 *   return (x ^ mask) - mask; ← xor + sub
 *
 * Or more often in modern GCC:
 *   neg eax ; cmovs eax, edi  ← if result is negative, keep original
 * ========================================================================== */

int idiom_abs_manual(int x)
{
    int mask = x >> 31;
    return (x ^ mask) - mask;
}

/* ==========================================================================
 * 12. min/max → cmp + cmov
 *
 * The ternary pattern  (a < b) ? a : b  is transformed into cmp + cmov.
 * No branch, no pipeline stall.
 * ========================================================================== */

int idiom_min(int a, int b) { return (a < b) ? a : b; }
int idiom_max(int a, int b) { return (a > b) ? a : b; }

unsigned int idiom_umin(unsigned int a, unsigned int b)
{
    return (a < b) ? a : b;   /* cmovb instead of cmovl (unsigned) */
}

/* ==========================================================================
 * 13. Structure initialization → rep stosq / mov sequence
 *
 * Zeroing a structure:
 *   -O0: call to memset, or store loop.
 *   -O2: sequence of mov qword [rbp-X], 0 (for small structs)
 *         or rep stosq (for large structs).
 *
 * Initialization with values:
 *   -O2: sequence of immediate movs, sometimes combined into movdqa if
 *         values fit in an SSE register.
 * ========================================================================== */

typedef struct {
    int    id;
    int    type;
    double value;
    char   name[32];
    int    flags;
    int    padding;
} Record;

Record idiom_struct_init(int id)
{
    Record r;
    memset(&r, 0, sizeof(r));   /* → rep stosq or sequence of mov 0 */
    r.id = id;
    r.type = 1;
    r.value = 3.14159;
    r.flags = 0x0F;
    return r;
}

/* ==========================================================================
 * 14. Short string comparison → block comparison
 *
 * When the length is known and short, GCC can inline the comparison
 * by loading 4 or 8-byte words at once.
 *
 *   strcmp(s, "ABCD") at -O2:
 *   → mov eax, [rdi]
 *   → cmp eax, 0x44434241    ("ABCD" in little-endian)
 * ========================================================================== */

int idiom_strcmp_known(const char *input)
{
    if (strcmp(input, "OK") == 0)       return 1;
    if (strcmp(input, "FAIL") == 0)     return 2;
    if (strcmp(input, "ERROR") == 0)    return 3;
    if (strcmp(input, "TIMEOUT") == 0)  return 4;
    return 0;
}

/* ==========================================================================
 * 15. Population count (popcount) → popcnt
 *
 * If compiled with -mpopcnt (included in -march=native on modern CPUs),
 * GCC recognizes the bit counting pattern and emits popcnt.
 *
 * Without -mpopcnt: GCC emits the classic computation (Hamming weight)
 * with the magic constants 0x55555555, 0x33333333, 0x0F0F0F0F.
 *
 *   gcc -O2 -mpopcnt -g -o test gcc_idioms.c  ← to see popcnt
 * ========================================================================== */

int idiom_popcount(unsigned int x)
{
    return __builtin_popcount(x);
}

/* Manual version — GCC recognizes it too at -O2! */
int idiom_popcount_manual(unsigned int x)
{
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    return (x * 0x01010101) >> 24;
}

/* ==========================================================================
 * 16. BONUS — Sign extension and zero extension
 *
 * When GCC must convert a smaller type to a larger one:
 *   char → int:  movsx eax, dil   (sign extend)
 *   unsigned char → int:  movzx eax, dil   (zero extend)
 * ========================================================================== */

int idiom_sign_extend(char c)
{
    return (int)c;    /* movsx */
}

int idiom_zero_extend(unsigned char c)
{
    return (int)c;    /* movzx */
}

/* ==========================================================================
 * Entry point
 * ========================================================================== */

int main(int argc, char *argv[])
{
    int input = 42;
    if (argc > 1)
        input = atoi(argv[1]);

    unsigned int uinput = (unsigned int)input;

    /* 1-3. Division and modulo */
    printf("div_const(%d) = %d\n", input, idiom_div_by_constant(input));
    printf("udiv_const(%u) = %u\n", uinput, idiom_udiv_by_constant(uinput));
    printf("mod8(%d) = %d\n", input, idiom_mod_power_of_2(input));
    printf("umod8(%u) = %u\n", uinput, idiom_umod_power_of_2(uinput));
    printf("mod16(%d) = %d\n", input, idiom_mod_16(input));
    printf("mod7(%d) = %d\n", input, idiom_mod_non_pow2(input));

    /* 4. Multiplication by constant */
    printf("mul_const(%d) = %d\n", input, idiom_mul_by_constant(input));

    /* 5. cmov */
    printf("max(%d, 17) = %d\n", input, idiom_cmov_max(input, 17));
    printf("abs(%d) = %d\n", -input, idiom_cmov_abs(-input));
    printf("clamp(%d, 10, 50) = %d\n", input, idiom_cmov_clamp(input, 10, 50));

    /* 6-7. Bit test and bool */
    printf("test_bit(0x%X) = %d\n", input, idiom_test_bit(input));
    printf("bool_norm(%d) = %d\n", input, idiom_bool_normalize(input));
    printf("bool_cmp(%d, 42) = %d\n", input, idiom_bool_from_compare(input, 42));

    /* 8-9. Switch */
    printf("day(%d) = %s\n", input % 7, idiom_switch_dense(input % 7));
    printf("code(%d) = %s\n", input, idiom_switch_sparse(input));

    /* 10. Rotation */
    printf("rotl(%u, 5) = 0x%08X\n", uinput, idiom_rotate_left(uinput, 5));
    printf("rotr(%u, 5) = 0x%08X\n", uinput, idiom_rotate_right(uinput, 5));
    printf("rotl13(%u)  = 0x%08X\n", uinput, idiom_rotate_left_13(uinput));

    /* 11. abs */
    printf("abs_manual(%d) = %d\n", -input, idiom_abs_manual(-input));

    /* 12. min/max */
    printf("min(%d, 30) = %d\n", input, idiom_min(input, 30));
    printf("max(%d, 30) = %d\n", input, idiom_max(input, 30));
    printf("umin(%u, 30) = %u\n", uinput, idiom_umin(uinput, 30));

    /* 13. Struct init */
    Record r = idiom_struct_init(input);
    printf("record: id=%d type=%d val=%.2f flags=0x%X\n",
           r.id, r.type, r.value, r.flags);

    /* 14. Inline strcmp */
    printf("strcmp('OK')   = %d\n", idiom_strcmp_known("OK"));
    printf("strcmp('FAIL') = %d\n", idiom_strcmp_known("FAIL"));
    printf("strcmp(argv0)  = %d\n", idiom_strcmp_known(argv[0]));

    /* 15. Popcount */
    printf("popcount(0x%X) = %d\n", uinput, idiom_popcount(uinput));
    printf("popcount_manual(0x%X) = %d\n", uinput, idiom_popcount_manual(uinput));

    /* 16. Extensions */
    printf("sign_extend(0xFE) = %d\n", idiom_sign_extend((char)0xFE));
    printf("zero_extend(0xFE) = %d\n", idiom_zero_extend((unsigned char)0xFE));

    return 0;
}
