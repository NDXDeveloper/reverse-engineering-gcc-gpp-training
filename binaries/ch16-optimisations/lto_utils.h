/* ============================================================================
 * Chapter 16 — Section 16.5
 * lto_utils.h — Declarations for lto_utils.c
 *
 * MIT License — Strictly educational use.
 * ============================================================================ */

#ifndef LTO_UTILS_H
#define LTO_UTILS_H

void  utils_print_array(const char *label, const int *data, int n);
void  utils_fill_sequence(int *data, int n, int start, int step);
int   utils_clamp(int value, int low, int high);
int   utils_array_max(const int *data, int n);
char *utils_int_to_hex(int value, char *buf, int bufsize);

#endif /* LTO_UTILS_H */
