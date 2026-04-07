/* ============================================================================
 * Chapter 16 — Section 16.5
 * lto_math.h — Declarations for lto_math.c
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#ifndef LTO_MATH_H
#define LTO_MATH_H

int          math_square(int x);
int          math_cube(int x);
long         math_sum_of_powers(int n, int power);
unsigned int math_hash(const char *str);
int          math_divide_sum(const int *data, int n, int divisor);
long         math_complex_transform(const int *data, int n);

#endif /* LTO_MATH_H */
