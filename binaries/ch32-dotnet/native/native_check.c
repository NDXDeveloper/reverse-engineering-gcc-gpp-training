/*
 * native_check.c — Native library for LicenseChecker (Chapter 32)
 *
 * Compiled with GCC as shared library, called from C# via P/Invoke.
 *
 * RE points of interest:
 *   - Exported symbols visible with nm / objdump / readelf
 *   - Algorithms analyzable with Ghidra, GDB or Frida (native side)
 *   - Salt differs from the C# side → both sides must be reversed
 *
 * Compilation:
 *   gcc -shared -fPIC -O2 -Wall -o libnative_check.so native_check.c
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── Constants ────────────────────────────────────────────────────────
 *
 * The native salt is DIFFERENT from the managed salt ("REV3RSE!").
 * This is a classic trap: the student who only reverses the C# side
 * will get an incorrect segment B.
 */

static const uint8_t NATIVE_SALT[] = {
    0x4E, 0x41, 0x54, 0x49, 0x56, 0x45, 0x52, 0x45
};
/* ASCII : "NATIVERE" */

static const uint32_t FNV_OFFSET = 0x811C9DC5u;
static const uint32_t FNV_PRIME  = 0x01000193u;


/* ──────────────────────────────────────────────────────────────────────
 * compute_native_hash()
 *
 * FNV-1a hash of the input buffer, salted with NATIVE_SALT[].
 *
 * Algorithm:
 *   1. Initialize hash = FNV_OFFSET
 *   2. For each byte of data : hash = (hash XOR octet) * FNV_PRIME
 *   3. For each byte of NATIVE_SALT: same
 *   4. Fold-XOR 32→16 bits : (hash >> 16) ^ (hash & 0xFFFF)
 *   5. Return masked to 16 bits
 *
 * Parameters:
 *   data   — byte buffer (username encoded UTF-8, lowercase)
 *   length — buffer size
 *
 * Returns: 16-bit hash in a uint32_t
 * ────────────────────────────────────────────────────────────────────── */

uint32_t compute_native_hash(const uint8_t *data, int length)
{
    uint32_t hash = FNV_OFFSET;

    /* Hash of user data */
    for (int i = 0; i < length; i++)
    {
        hash ^= (uint32_t)data[i];
        hash *= FNV_PRIME;
    }

    /* Hash of the native salt */
    for (int i = 0; i < (int)sizeof(NATIVE_SALT); i++)
    {
        hash ^= (uint32_t)NATIVE_SALT[i];
        hash *= FNV_PRIME;
    }

    /* Fold-XOR 32→16 */
    uint32_t folded = (hash >> 16) ^ (hash & 0xFFFFu);
    return folded & 0xFFFFu;
}


/* ──────────────────────────────────────────────────────────────────────
 * compute_checksum()
 *
 * Checksum combining key segments A, B, C.
 * Called from C# to produce the native part of segment D.
 *
 * Algorithm:
 *   1. val = segA
 *   2. Left rotation 3 bits (16 bits), XOR segB
 *   3. Right rotation 7 bits (16 bits), XOR segC
 *   4. val = (val * 0x5BD1) & 0xFFFF
 *   5. val ^= 0x1337
 *
 * Returns: 16-bit checksum in a uint32_t
 * ────────────────────────────────────────────────────────────────────── */

uint32_t compute_checksum(uint32_t seg_a, uint32_t seg_b, uint32_t seg_c)
{
    uint32_t val = seg_a & 0xFFFFu;

    /* Left rotation 3 bits (on 16 bits) + XOR seg_b */
    val = ((val << 3) | (val >> 13)) & 0xFFFFu;
    val ^= seg_b & 0xFFFFu;

    /* Right rotation 7 bits (on 16 bits) + XOR seg_c */
    val = ((val >> 7) | (val << 9)) & 0xFFFFu;
    val ^= seg_c & 0xFFFFu;

    /* Final multiplicative mixing */
    val = (val * 0x5BD1u) & 0xFFFFu;
    val ^= 0x1337u;

    return val & 0xFFFFu;
}


/* ──────────────────────────────────────────────────────────────────────
 * verify_integrity()
 *
 * Native-side integrity check (exercise only).
 * NOT called in the main flow of LicenseValidator.cs.
 * Present as a Frida hooking target (§32.2 / §32.3).
 *
 * Parameters:
 *   username       — username (ASCII/UTF-8)
 *   seg_a..seg_d   — the 4 key segments
 *
 * Returns: 1 if valid, 0 otherwise
 * ────────────────────────────────────────────────────────────────────── */

int verify_integrity(const char *username,
                     uint32_t seg_a, uint32_t seg_b,
                     uint32_t seg_c, uint32_t seg_d)
{
    if (username == NULL)
        return 0;

    size_t len = strlen(username);
    if (len == 0 || len > 256)
        return 0;

    /* Conversion to lowercase (ASCII only) */
    uint8_t lower[256];
    for (size_t i = 0; i < len; i++)
    {
        uint8_t c = (uint8_t)username[i];
        if (c >= 'A' && c <= 'Z')
            c += 0x20;
        lower[i] = c;
    }

    /* Verify segment B (native hash) */
    uint32_t expected_b = compute_native_hash(lower, (int)len);
    if ((seg_b & 0xFFFFu) != expected_b)
        return 0;

    /* Verify that segment D is non-zero */
    /* (partial check: the complete segment D depends
     *  also on the managed part which we don't have here) */
    if (seg_d == 0)
        return 0;

    /* Verify native checksum consistency */
    uint32_t chk = compute_checksum(seg_a & 0xFFFFu,
                                    seg_b & 0xFFFFu,
                                    seg_c & 0xFFFFu);
    (void)chk;

    return 1;
}
