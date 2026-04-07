/*
 * packed_sample.c — Chapter 29 training binary
 * Reverse Engineering Training — GNU Toolchain
 *
 * Description:
 *   Program intentionally rich in strings, recognizable constants
 *   and verification logic. Once packed with UPX,
 *   all this information disappears from static analysis.
 *   The goal of the exercise is to:
 *     1. Detect that the binary is packed
 *     2. Decompress it (statically or dynamically)
 *     3. Reconstruct an analyzable ELF
 *     4. Recover the logic below
 *
 * Compilation: see associated Makefile
 * MIT License — Strictly educational use
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ──────────────────────────────────────────────
 * Constants recognizable in static analysis
 * (visible with `strings` on the unpacked binary)
 * ────────────────────────────────────────────── */

#define BANNER \
    "╔══════════════════════════════════════╗\n" \
    "║   Ch29 — PackedSample v1.0          ║\n" \
    "║   RE Training — GNU Toolchain         ║\n" \
    "╚══════════════════════════════════════╝\n"

#define SECRET_FLAG   "FLAG{unp4ck3d_and_r3c0nstruct3d}"
#define AUTHOR_TAG    "Author: RE-Training-GNU"
#define BUILD_MARKER  "BUILD:ch29-packed-2025"

/* Marker intentionally placed in .rodata for the ImHex exercise */
static const char g_watermark[] = "<<< WATERMARK:PACKED_SAMPLE_ORIGINAL >>>";

/* ──────────────────────────────────────────────
 * "Magic" constants simulating a routine
 * crypto (recognizable in a hex dump)
 * Here: the first 16 bytes of the AES S-box
 * ────────────────────────────────────────────── */
static const uint8_t g_fake_sbox[16] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
};

/* ──────────────────────────────────────────────
 * Embedded XOR key (8 bytes)
 * ────────────────────────────────────────────── */
static const uint8_t g_xor_key[8] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
};

/* ──────────────────────────────────────────────
 * Message encrypted via XOR with g_xor_key
 * Plaintext: "SUCCESS!" (8 bytes)
 *   'S'^0xDE=0x8D  'U'^0xAD=0xF8  'C'^0xBE=0xFD
 *   'C'^0xEF=0xAC  'E'^0xCA=0x8F  'S'^0xFE=0xAD
 *   'S'^0xBA=0xE9  '!'^0xBE=0x9F
 * ────────────────────────────────────────────── */
static const uint8_t g_encrypted_msg[8] = {
    0x8D, 0xF8, 0xFD, 0xAC, 0x8F, 0xAD, 0xE9, 0x9F
};

/* ──────────────────────────────────────────────
 * Utility functions
 * ────────────────────────────────────────────── */

/*
 * xor_decode — Decrypts a buffer with a cyclic XOR key.
 *   dst: output buffer (must be allocated by the caller, +1 for '\0')
 *   src: encrypted data
 *   len: data size
 *   key: XOR key
 *   klen: key size
 */
static void xor_decode(char *dst, const uint8_t *src, size_t len,
                        const uint8_t *key, size_t klen)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)(src[i] ^ key[i % klen]);
    }
    dst[len] = '\0';
}

/*
 * compute_checksum — Computes a simple checksum on a buffer.
 *   Used for user key verification.
 *   Algorithm: weighted byte sum (weight = position + 1),
 *   reduced modulo 0xFFFF.
 */
static uint32_t compute_checksum(const char *buf, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += (uint32_t)((unsigned char)buf[i]) * (uint32_t)(i + 1);
    }
    return sum & 0xFFFF;
}

/*
 * check_license_key — Checks if the license key is valid.
 *
 *   Expected format: "RE29-XXXX" where XXXX is a hexadecimal number
 *   such that the checksum of the prefix "RE29-" equals XXXX (in hex).
 *
 *   Checksum("RE29-") :
 *     'R'*1 + 'E'*2 + '2'*3 + '9'*4 + '-'*5
 *     = 82 + 138 + 150 + 228 + 225 = 823
 *     = 0x0337
 *
 *   So the valid key is: RE29-0337
 */
static int check_license_key(const char *key)
{
    const char *prefix = "RE29-";
    size_t prefix_len = strlen(prefix);

    /* Check the prefix */
    if (strlen(key) != 9) {
        return 0;
    }
    if (strncmp(key, prefix, prefix_len) != 0) {
        return 0;
    }

    /* Extract the hexadecimal part */
    const char *hex_part = key + prefix_len;
    char *endptr = NULL;
    unsigned long user_val = strtoul(hex_part, &endptr, 16);

    if (endptr == NULL || *endptr != '\0') {
        return 0;  /* Non-hexadecimal characters */
    }

    /* Compute the expected checksum */
    uint32_t expected = compute_checksum(prefix, prefix_len);

    return (user_val == expected);
}

/* ──────────────────────────────────────────────
 * Debug information display
 * (useful after unpacking to verify the
 * reconstruction)
 * ────────────────────────────────────────────── */
static void print_debug_info(void)
{
    printf("[DEBUG] Author      : %s\n", AUTHOR_TAG);
    printf("[DEBUG] Build        : %s\n", BUILD_MARKER);
    printf("[DEBUG] Watermark    : %s\n", g_watermark);
    printf("[DEBUG] Fake S-box[0]: 0x%02X\n", g_fake_sbox[0]);
    printf("[DEBUG] Fake S-box[1]: 0x%02X\n", g_fake_sbox[1]);
    printf("[DEBUG] XOR key[0..3]: %02X %02X %02X %02X\n",
           g_xor_key[0], g_xor_key[1], g_xor_key[2], g_xor_key[3]);
}

/* ──────────────────────────────────────────────
 * Entry point
 * ────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    printf("%s\n", BANNER);

    /* Debug mode: display internal metadata */
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        print_debug_info();
        printf("\n");
    }

    /* Ask for the license key */
    printf("[*] Enter your license key (format RE29-XXXX): ");
    fflush(stdout);

    char input[64];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "[!] Read error.\n");
        return EXIT_FAILURE;
    }

    /* Remove the newline */
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
        len--;
    }

    /* Verification */
    if (check_license_key(input)) {
        /* Decrypt and display the success message */
        char decoded[9];
        xor_decode(decoded, g_encrypted_msg, sizeof(g_encrypted_msg),
                   g_xor_key, sizeof(g_xor_key));

        printf("\n[+] Valid key! Decrypted message: %s\n", decoded);
        printf("[+] Flag : %s\n", SECRET_FLAG);
        printf("[+] Congratulations, you recovered the logic after unpacking!\n");
    } else {
        printf("\n[-] Invalid key.\n");
        printf("[-] Hint: analyze the check_license_key function...\n");
        printf("[-] ... but first, you need to unpack the binary.\n");
    }

    return EXIT_SUCCESS;
}
