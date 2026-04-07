/* ============================================================================
 * crypto.c — Chapter 24 training binary
 * Reverse Engineering Training — Applications compiled with the GNU toolchain
 *
 * This program encrypts a file with AES-256-CBC.
 * The key is derived from a hardcoded passphrase via SHA-256 + XOR.
 *
 * Compilation: see Makefile (produces crypto_O0, crypto_O2, etc.)
 * Dependency: libssl-dev (OpenSSL)
 *
 * Usage: ./crypto_O0 <file_to_encrypt>
 *         -> produces <file_to_encrypt>.enc
 *
 * Output format (.enc) :
 *   Offset  Size    Field
 *   0x00    8       Magic "CRYPT24\0"
 *   0x08    1       Major version (0x01)
 *   0x09    1       Minor version (0x00)
 *   0x0A    2       IV length (16, little-endian)
 *   0x0C    16      IV (random)
 *   0x1C    4       Original file size (little-endian, uint32)
 *   0x20    N       Encrypted data (AES-256-CBC, padding PKCS7)
 *
 * MIT License — Strictly educational and ethical use.
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* --------------------------------------------------------------------------
 * File format constants
 * ------------------------------------------------------------------------ */

#define MAGIC       "CRYPT24"
#define MAGIC_LEN   8          /* 7 characters + '\0' */
#define VERSION_MAJ 0x01
#define VERSION_MIN 0x00
#define IV_LEN      16         /* AES block size */
#define KEY_LEN     32         /* AES-256 */

/* --------------------------------------------------------------------------
 * Hardcoded passphrase — this is *the* secret the student must find.
 * In production, this would obviously be a security disaster.
 * It is intentionally made non-trivial to spot with `strings`
 * by building it character by character in build_passphrase().
 * ------------------------------------------------------------------------ */

static void build_passphrase(char *out, size_t max_len)
{
    /* "r3vers3_m3_1f_y0u_c4n!" built in pieces */
    const char part1[] = { 'r', '3', 'v', 'e', 'r', 's', '3', '_', '\0' };
    const char part2[] = { 'm', '3', '_', '1', 'f', '_', '\0' };
    const char part3[] = { 'y', '0', 'u', '_', 'c', '4', 'n', '!', '\0' };

    if (max_len < strlen(part1) + strlen(part2) + strlen(part3) + 1) {
        fprintf(stderr, "Buffer too small for passphrase\n");
        exit(EXIT_FAILURE);
    }

    out[0] = '\0';
    strcat(out, part1);
    strcat(out, part2);
    strcat(out, part3);
}

/* --------------------------------------------------------------------------
 * Secondary XOR mask applied after the SHA-256 of the passphrase.
 * These bytes are easily spotted in .rodata / .data.
 * ------------------------------------------------------------------------ */

static const unsigned char KEY_MASK[KEY_LEN] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE,
    0x0B, 0xAD, 0xF0, 0x0D, 0xDE, 0xAD, 0xC0, 0xDE,
    0x8B, 0xAD, 0xF0, 0x0D, 0x0D, 0x15, 0xEA, 0x5E
};

/* --------------------------------------------------------------------------
 * derive_key() — AES-256 key derivation.
 *
 *   1. Build the passphrase in memory
 *   2. Compute SHA-256(passphrase)  ->  hash[32]
 *   3. XOR hash[i] ^ KEY_MASK[i]   ->  final key[32]
 *
 * This is the logic the student must reconstruct.
 * ------------------------------------------------------------------------ */

static void derive_key(unsigned char *out_key)
{
    char passphrase[64];
    unsigned char sha_hash[SHA256_DIGEST_LENGTH];

    /* Step 1: build the passphrase */
    build_passphrase(passphrase, sizeof(passphrase));

    /* Step 2: SHA-256 of the passphrase */
    SHA256((const unsigned char *)passphrase, strlen(passphrase), sha_hash);

    /* Step 3: XOR with the mask */
    for (int i = 0; i < KEY_LEN; i++) {
        out_key[i] = sha_hash[i] ^ KEY_MASK[i];
    }

    /* Cleanup (good practice, but the key remains in out_key) */
    memset(passphrase, 0, sizeof(passphrase));
    memset(sha_hash, 0, sizeof(sha_hash));
}

/* --------------------------------------------------------------------------
 * read_file() — Reads an entire file into memory.
 * Returns the allocated buffer (caller must free) and its size.
 * ------------------------------------------------------------------------ */

static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 100 * 1024 * 1024) { /* 100 MB limit */
        fprintf(stderr, "Error: file too large or empty (%ld bytes)\n", fsize);
        fclose(f);
        return NULL;
    }

    unsigned char *buf = malloc((size_t)fsize);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        perror("fread");
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)fsize;
    return buf;
}

/* --------------------------------------------------------------------------
 * encrypt_data() — Encrypts a buffer with AES-256-CBC (PKCS7 padding).
 * Returns the encrypted buffer (to be freed) and its size.
 * ------------------------------------------------------------------------ */

static unsigned char *encrypt_data(const unsigned char *plaintext,
                                   size_t pt_len,
                                   const unsigned char *key,
                                   const unsigned char *iv,
                                   size_t *out_ct_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error: EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    /* Output buffer: plaintext + one extra block for padding */
    size_t max_ct = pt_len + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char *ciphertext = malloc(max_ct);
    if (!ciphertext) {
        perror("malloc");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0;
    int total = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)pt_len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptUpdate failed\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptFinal_ex failed\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    *out_ct_len = (size_t)total;
    return ciphertext;
}

/* --------------------------------------------------------------------------
 * write_encrypted_file() — Writes the .enc file in CRYPT24 format.
 * ------------------------------------------------------------------------ */

static int write_encrypted_file(const char *out_path,
                                const unsigned char *iv,
                                uint32_t original_size,
                                const unsigned char *ciphertext,
                                size_t ct_len)
{
    FILE *f = fopen(out_path, "wb");
    if (!f) {
        perror(out_path);
        return -1;
    }

    /* Magic (8 bytes, null-terminated) */
    fwrite(MAGIC, 1, MAGIC_LEN, f);

    /* Version (2 bytes) */
    uint8_t ver_maj = VERSION_MAJ;
    uint8_t ver_min = VERSION_MIN;
    fwrite(&ver_maj, 1, 1, f);
    fwrite(&ver_min, 1, 1, f);

    /* IV length (2 bytes, little-endian) */
    uint16_t iv_len_le = (uint16_t)IV_LEN;
    fwrite(&iv_len_le, sizeof(uint16_t), 1, f);

    /* IV (16 bytes) */
    fwrite(iv, 1, IV_LEN, f);

    /* Original size (4 bytes, little-endian) */
    fwrite(&original_size, sizeof(uint32_t), 1, f);

    /* Encrypted data */
    fwrite(ciphertext, 1, ct_len, f);

    fclose(f);
    return 0;
}

/* --------------------------------------------------------------------------
 * print_hex() — Displays a buffer in hexadecimal (debug / feedback).
 * ------------------------------------------------------------------------ */

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* --------------------------------------------------------------------------
 * main()
 * ------------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_to_encrypt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *input_path = argv[1];

    /* Build the output path : input_path + ".enc" */
    size_t out_path_len = strlen(input_path) + 5; /* ".enc\0" */
    char *output_path = malloc(out_path_len);
    if (!output_path) {
        perror("malloc");
        return EXIT_FAILURE;
    }
    snprintf(output_path, out_path_len, "%s.enc", input_path);

    /* 1. Read the source file */
    size_t pt_len = 0;
    unsigned char *plaintext = read_file(input_path, &pt_len);
    if (!plaintext) {
        free(output_path);
        return EXIT_FAILURE;
    }
    printf("[*] Read %zu bytes from '%s'\n", pt_len, input_path);

    /* 2. Derive the key */
    unsigned char key[KEY_LEN];
    derive_key(key);
    print_hex("[*] Derived key", key, KEY_LEN);

    /* 3. Generate a random IV */
    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed\n");
        free(plaintext);
        free(output_path);
        return EXIT_FAILURE;
    }
    print_hex("[*] Generated IV", iv, IV_LEN);

    /* 4. Encrypt */
    size_t ct_len = 0;
    unsigned char *ciphertext = encrypt_data(plaintext, pt_len, key, iv, &ct_len);
    if (!ciphertext) {
        free(plaintext);
        free(output_path);
        return EXIT_FAILURE;
    }
    printf("[*] Encrypted: %zu bytes -> %zu bytes\n", pt_len, ct_len);

    /* 5. Write the .enc file */
    if (write_encrypted_file(output_path, iv, (uint32_t)pt_len,
                             ciphertext, ct_len) != 0) {
        free(ciphertext);
        free(plaintext);
        free(output_path);
        return EXIT_FAILURE;
    }
    printf("[+] Encrypted file written to '%s'\n", output_path);

    /* Format recap for the curious student who runs the binary */
    printf("\n");
    printf("[*] File format reminder:\n");
    printf("    [0x00] Magic:    CRYPT24\\0\n");
    printf("    [0x08] Version:  %d.%d\n", VERSION_MAJ, VERSION_MIN);
    printf("    [0x0A] IV len:   %d\n", IV_LEN);
    printf("    [0x0C] IV:       (see above)\n");
    printf("    [0x1C] Orig sz:  %u\n", (uint32_t)pt_len);
    printf("    [0x20] Data:     %zu bytes (AES-256-CBC)\n", ct_len);

    /* Cleanup */
    memset(key, 0, KEY_LEN);
    free(ciphertext);
    free(plaintext);
    free(output_path);

    return EXIT_SUCCESS;
}
