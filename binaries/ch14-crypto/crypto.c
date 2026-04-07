/*
 * ch14-crypto.c — Simplified file encryptor for RE training
 *
 * Implements a simplified AES-256-CBC-like cipher with SHA-256-like
 * key derivation. NOT suitable for real cryptographic use.
 *
 * Intentional bugs for Valgrind/sanitizer training:
 *   - Memory leaks (key, IV, context, salt never freed)
 *   - Partially uninitialized IV (4 bytes left unset)
 *   - Signed integer overflows in hash derivation (int vs uint32_t)
 *   - Uninitialized bytes written to output file
 *
 * Build: see accompanying Makefile
 * Usage: ./crypto <encrypt|decrypt> <input> <output> <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════ */
/*  Constants                                                         */
/* ═══════════════════════════════════════════════════════════════════ */

#define BLOCK_SIZE      16
#define KEY_SIZE        32
#define IV_SIZE         16
#define NUM_ROUNDS      14

#define CTX_MODE_OFF    0
#define CTX_IV_OFF      4
#define CTX_RK_OFF      20
#define CTX_RK_LEN      216
#define CTX_SIZE        240      /* 4 + 16 + 216 + 4(pad) = 240 */

#define HASH_ROUNDS     64
#define HASH_DIGEST     32
#define SALT_SIZE       64
#define IO_BUF_SIZE     4096
#define PWD_BUF_SIZE    1024
#define OUT_BLK_SIZE    128
#define OUT_HDR_SIZE    8

#define MODE_CBC        1
#define FILE_MAGIC      0x43525950u  /* "CRYP" */
#define FILE_VERSION    1

/* SHA-256 round constants — cube roots of first 64 primes.
   These well-known constants make the binary identifiable by
   FindCrypt / YARA crypto-constant rules (see ch24, Annexe J). */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA-256 initial hash values — square roots of first 8 primes */
static const uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* ═══════════════════════════════════════════════════════════════════ */
/*  Simplified S-box (NOT real AES — bijection on [0,255])            */
/* ═══════════════════════════════════════════════════════════════════ */

static uint8_t sbox(uint8_t v) {
    /* f(v) = ((v * 0xB7 + 0x63) mod 256) ^ 0x5A
       0xB7 is odd → multiplication mod 256 is bijective */
    return (uint8_t)(((v * 0xB7u) + 0x63u) ^ 0x5Au);
}

static uint8_t sbox_inv(uint8_t v) {
    /* Precomputed inverse table — built once on first call */
    static uint8_t inv[256];
    static int ready = 0;
    if (!ready) {
        for (int i = 0; i < 256; i++)
            inv[sbox((uint8_t)i)] = (uint8_t)i;
        ready = 1;
    }
    return inv[v];
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Hash — simplified SHA-256-like compression                        */
/*  BUG: uses 'int' (signed) → signed overflow detected by UBSan     */
/* ═══════════════════════════════════════════════════════════════════ */

static void hash_compress(int state[8], const uint8_t *block) {
    int W[64];
    int i;

    /* Message schedule — expand 16 words to 64 */
    for (i = 0; i < 16; i++)
        W[i] = (int)((block[4*i] << 24) | (block[4*i+1] << 16) |
                      (block[4*i+2] << 8) | block[4*i+3]);
    for (i = 16; i < 64; i++) {
        int s0 = ((W[i-15] >> 7) | (W[i-15] << 25)) ^
                 ((W[i-15] >> 18) | (W[i-15] << 14)) ^
                 (W[i-15] >> 3);
        int s1 = ((W[i-2] >> 17) | (W[i-2] << 15)) ^
                 ((W[i-2] >> 19) | (W[i-2] << 13)) ^
                 (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;           /* SIGNED OVERFLOW */
    }

    int a = state[0], b = state[1], c = state[2], d = state[3];
    int e = state[4], f = state[5], g = state[6], h = state[7];

    for (i = 0; i < 64; i++) {
        int S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                 ((e >> 25) | (e << 7));
        int ch = (e & f) ^ (~e & g);
        int t1 = h + S1 + ch + (int)K[i] + W[i];     /* SIGNED OVERFLOW */
        int S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                 ((a >> 22) | (a << 10));
        int maj = (a & b) ^ (a & c) ^ (b & c);
        int t2 = S0 + maj;                             /* SIGNED OVERFLOW */
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void derive_hash(const uint8_t *data, size_t len, uint8_t out[HASH_DIGEST]) {
    int state[8];
    for (int i = 0; i < 8; i++)
        state[i] = (int)H_INIT[i];

    uint8_t block[64];
    size_t pos;

    /* Process full blocks */
    for (pos = 0; pos + 64 <= len; pos += 64)
        hash_compress(state, data + pos);

    /* Final block with padding */
    memset(block, 0, 64);
    if (len > pos)
        memcpy(block, data + pos, len - pos);
    block[len - pos] = 0x80;

    if (len - pos >= 56) {
        hash_compress(state, block);
        memset(block, 0, 64);
    }

    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        block[63 - j] = (uint8_t)(bits >> (8 * j));
    hash_compress(state, block);

    /* Serialize state to output */
    for (int j = 0; j < 8; j++) {
        out[4*j]   = (uint8_t)(state[j] >> 24);
        out[4*j+1] = (uint8_t)(state[j] >> 16);
        out[4*j+2] = (uint8_t)(state[j] >> 8);
        out[4*j+3] = (uint8_t)(state[j]);
    }
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Password reading & key derivation                                 */
/* ═══════════════════════════════════════════════════════════════════ */

static uint8_t *read_password(const char *arg) {
    uint8_t *buf = malloc(PWD_BUF_SIZE);               /* A6: 1024 bytes */
    if (!buf) return NULL;
    strncpy((char *)buf, arg, PWD_BUF_SIZE - 1);
    buf[PWD_BUF_SIZE - 1] = '\0';
    size_t len = strlen((char *)buf);
    uint8_t *pwd = malloc(len + 1);
    if (pwd) memcpy(pwd, buf, len + 1);
    free(buf);                                         /* A6 freed here */
    return pwd;
}

static uint8_t *generate_salt(const char *pwd) {
    uint8_t *salt = malloc(SALT_SIZE);                 /* A7: 64 bytes — LEAK */
    if (!salt) return NULL;
    size_t pwd_len = strlen(pwd);
    for (int i = 0; i < SALT_SIZE; i++)
        salt[i] = (uint8_t)(pwd[i % pwd_len] * 0x9Eu + 0x37u + (unsigned)i);
    return salt;
}

static uint8_t *derive_key(const char *password_arg) {
    uint8_t *pwd = read_password(password_arg);
    if (!pwd) return NULL;

    uint8_t *salt = generate_salt((const char *)pwd);
    if (!salt) { free(pwd); return NULL; }

    uint8_t *key = malloc(KEY_SIZE);                   /* A1: 32 bytes — LEAK */
    if (!key) { free(pwd); return NULL; }

    /* PBKDF2-like: hash(password || salt) */
    size_t pwd_len = strlen((const char *)pwd);
    size_t combined_len = pwd_len + SALT_SIZE;
    uint8_t *combined = malloc(combined_len);
    if (!combined) { free(pwd); return NULL; }
    memcpy(combined, pwd, pwd_len);
    memcpy(combined + pwd_len, salt, SALT_SIZE);

    uint8_t *tmp = malloc(HASH_DIGEST);                /* A8: 32 bytes temp */
    if (!tmp) { free(combined); free(pwd); return NULL; }
    derive_hash(combined, combined_len, tmp);

    /* Second pass: hash(tmp || salt) for strengthening */
    uint8_t second_input[HASH_DIGEST + SALT_SIZE];
    memcpy(second_input, tmp, HASH_DIGEST);
    memcpy(second_input + HASH_DIGEST, salt, SALT_SIZE);
    derive_hash(second_input, HASH_DIGEST + SALT_SIZE, key);

    free(tmp);                                         /* A8 freed */
    free(combined);
    free(pwd);
    /* salt (A7) and key (A1) intentionally NOT freed */
    return key;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  IV preparation                                                    */
/*  BUG: only 12 of 16 bytes initialized — Memcheck/MSan will flag   */
/* ═══════════════════════════════════════════════════════════════════ */

static uint8_t *prepare_iv(void) {
    uint8_t *iv = malloc(IV_SIZE);                     /* A2: 16 bytes — LEAK */
    if (!iv) return NULL;
    uint32_t t = (uint32_t)time(NULL);
    memcpy(iv,     &t, 4);                             /* bytes [0..3]  */
    t ^= 0xDEADBEEFu;
    memcpy(iv + 4, &t, 4);                             /* bytes [4..7]  */
    t = (t >> 16) | (t << 16);
    memcpy(iv + 8, &t, 4);                             /* bytes [8..11] */
    /* bytes [12..15] NEVER initialized — vulnerability */
    return iv;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Cipher context & key expansion                                    */
/* ═══════════════════════════════════════════════════════════════════ */

static uint8_t *g_io_buf = NULL;                       /* A3 global ref */
static uint8_t *g_ctx    = NULL;                       /* A5 global ref */

static uint8_t *init_aes_ctx(void) {
    uint8_t *ctx = malloc(CTX_SIZE);                   /* A5: 240 bytes — LEAK */
    if (!ctx) return NULL;
    memset(ctx, 0, CTX_SIZE);
    return ctx;
}

static void expand_key(uint8_t *ctx, const uint8_t *raw_key) {
    uint8_t *rk = ctx + CTX_RK_OFF;

    /* Copy raw 32-byte key as base material */
    memcpy(rk, raw_key, KEY_SIZE);

    /* 14 rounds of key expansion — Callgrind sees exactly 14 iterations */
    for (int round = 0; round < NUM_ROUNDS; round++) {
        int dst = ((round + 2) * BLOCK_SIZE) % CTX_RK_LEN;
        int src = ((round + 1) * BLOCK_SIZE) % CTX_RK_LEN;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            rk[dst + i] = sbox(rk[src + i])
                         ^ rk[(dst + i - 1 + CTX_RK_LEN) % CTX_RK_LEN]
                         ^ (uint8_t)(round + 1);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Block encrypt / decrypt                                           */
/* ═══════════════════════════════════════════════════════════════════ */

static void encrypt_block_ecb(const uint8_t *ctx,
                              const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE];
    const uint8_t *rk = ctx + CTX_RK_OFF;

    memcpy(state, in, BLOCK_SIZE);

    for (int round = 0; round < NUM_ROUNDS; round++) {
        /* Substitution */
        for (int i = 0; i < BLOCK_SIZE; i++)
            state[i] = sbox(state[i]);

        /* Permutation — rotate left by 1 */
        uint8_t tmp = state[0];
        for (int i = 0; i < BLOCK_SIZE - 1; i++)
            state[i] = state[i + 1];
        state[BLOCK_SIZE - 1] = tmp;

        /* Round key XOR */
        int rk_off = (round * BLOCK_SIZE) % CTX_RK_LEN;
        for (int i = 0; i < BLOCK_SIZE; i++)
            state[i] ^= rk[rk_off + i];
    }

    memcpy(out, state, BLOCK_SIZE);
}

static void decrypt_block_ecb(const uint8_t *ctx,
                              const uint8_t *in, uint8_t *out) {
    uint8_t state[BLOCK_SIZE];
    const uint8_t *rk = ctx + CTX_RK_OFF;

    memcpy(state, in, BLOCK_SIZE);

    for (int round = NUM_ROUNDS - 1; round >= 0; round--) {
        /* Reverse round key XOR */
        int rk_off = (round * BLOCK_SIZE) % CTX_RK_LEN;
        for (int i = 0; i < BLOCK_SIZE; i++)
            state[i] ^= rk[rk_off + i];

        /* Reverse permutation — rotate right by 1 */
        uint8_t tmp = state[BLOCK_SIZE - 1];
        for (int i = BLOCK_SIZE - 1; i > 0; i--)
            state[i] = state[i - 1];
        state[0] = tmp;

        /* Reverse substitution */
        for (int i = 0; i < BLOCK_SIZE; i++)
            state[i] = sbox_inv(state[i]);
    }

    memcpy(out, state, BLOCK_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  File I/O helpers                                                  */
/* ═══════════════════════════════════════════════════════════════════ */

static uint8_t *init_io(void) {
    g_io_buf = malloc(IO_BUF_SIZE);                    /* A3: 4096 bytes */
    return g_io_buf;
}

static int read_block(FILE *fp, uint8_t *block) {
    memset(block, 0, BLOCK_SIZE);                      /* zero-pad short blocks */
    size_t n = fread(block, 1, BLOCK_SIZE, fp);
    return (int)n;
}

static void write_block(FILE *fp, const uint8_t *ct, int ct_len, uint32_t flags) {
    uint8_t *out = malloc(OUT_BLK_SIZE);               /* A4: 128 bytes */
    if (!out) return;
    /* Header: 8 bytes — always initialized */
    uint32_t payload_size = (uint32_t)ct_len;
    memcpy(out, &payload_size, 4);
    memcpy(out + 4, &flags, 4);
    /* Ciphertext: only ct_len bytes written, rest UNINITIALIZED */
    memcpy(out + OUT_HDR_SIZE, ct, (size_t)ct_len);
    /* BUG: fwrite sends all 128 bytes including uninitialized portion */
    fwrite(out, 1, OUT_BLK_SIZE, fp);
    free(out);                                         /* A4 freed */
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  File header                                                       */
/* ═══════════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)
struct file_header {
    uint32_t magic;
    uint32_t version;
    uint32_t orig_size;
    uint32_t mode;
    uint8_t  iv[IV_SIZE];
};
#pragma pack(pop)

/* ═══════════════════════════════════════════════════════════════════ */
/*  Encrypt / Decrypt file processing                                 */
/* ═══════════════════════════════════════════════════════════════════ */

static int process_encrypt(const char *in_path, const char *out_path,
                           uint8_t *ctx, const uint8_t *iv) {
    FILE *fin = fopen(in_path, "rb");
    if (!fin) { perror("fopen input"); return -1; }
    FILE *fout = fopen(out_path, "wb");
    if (!fout) { perror("fopen output"); fclose(fin); return -1; }

    /* Determine original file size */
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    /* Write file header */
    struct file_header hdr;
    hdr.magic     = FILE_MAGIC;
    hdr.version   = FILE_VERSION;
    hdr.orig_size = (uint32_t)file_size;
    hdr.mode      = MODE_CBC;
    memcpy(hdr.iv, iv, IV_SIZE);  /* Copies partially-uninit IV into header */
    fwrite(&hdr, 1, sizeof(hdr), fout);

    /* CBC state lives inside the context at CTX_IV_OFF */
    uint8_t *iv_state = ctx + CTX_IV_OFF;

    uint8_t plainblock[BLOCK_SIZE], cipherblock[BLOCK_SIZE];
    int bytes_read, block_count = 0;

    while ((bytes_read = read_block(fin, plainblock)) > 0) {
        /* CBC: XOR plaintext with previous ciphertext (or IV) */
        for (int i = 0; i < BLOCK_SIZE; i++)
            plainblock[i] ^= iv_state[i];

        encrypt_block_ecb(ctx, plainblock, cipherblock);

        /* Update CBC state */
        memcpy(iv_state, cipherblock, BLOCK_SIZE);

        uint32_t flags = (bytes_read < BLOCK_SIZE) ? 1u : 0u;
        write_block(fout, cipherblock, BLOCK_SIZE, flags);
        block_count++;
    }

    /* If file size was exact multiple of BLOCK_SIZE, add padding block */
    if (file_size > 0 && (file_size % BLOCK_SIZE) == 0) {
        memset(plainblock, BLOCK_SIZE, BLOCK_SIZE);    /* PKCS7 full pad */
        for (int i = 0; i < BLOCK_SIZE; i++)
            plainblock[i] ^= iv_state[i];
        encrypt_block_ecb(ctx, plainblock, cipherblock);
        write_block(fout, cipherblock, BLOCK_SIZE, 1);
        block_count++;
    }

    fclose(fin);
    fclose(fout);
    return block_count;
}

static int process_decrypt(const char *in_path, const char *out_path,
                           uint8_t *ctx) {
    FILE *fin = fopen(in_path, "rb");
    if (!fin) { perror("fopen input"); return -1; }

    /* Read and validate file header */
    struct file_header hdr;
    if (fread(&hdr, 1, sizeof(hdr), fin) != sizeof(hdr)) {
        fprintf(stderr, "Error: cannot read file header\n");
        fclose(fin); return -1;
    }
    if (hdr.magic != FILE_MAGIC) {
        fprintf(stderr, "Error: bad magic 0x%08X (expected 0x%08X)\n",
                hdr.magic, FILE_MAGIC);
        fclose(fin); return -1;
    }

    FILE *fout = fopen(out_path, "wb");
    if (!fout) { perror("fopen output"); fclose(fin); return -1; }

    /* CBC previous-ciphertext initialized from file header IV */
    uint8_t prev_ct[BLOCK_SIZE];
    memcpy(prev_ct, hdr.iv, IV_SIZE);

    uint8_t in_blk[OUT_BLK_SIZE];
    uint8_t cipherblock[BLOCK_SIZE], plainblock[BLOCK_SIZE];
    uint32_t written = 0;

    while (fread(in_blk, 1, OUT_BLK_SIZE, fin) == OUT_BLK_SIZE) {
        uint32_t payload_size, flags;
        memcpy(&payload_size, in_blk, 4);
        memcpy(&flags, in_blk + 4, 4);
        memcpy(cipherblock, in_blk + OUT_HDR_SIZE, BLOCK_SIZE);

        decrypt_block_ecb(ctx, cipherblock, plainblock);

        /* CBC: XOR with previous ciphertext */
        for (int i = 0; i < BLOCK_SIZE; i++)
            plainblock[i] ^= prev_ct[i];
        memcpy(prev_ct, cipherblock, BLOCK_SIZE);

        /* Truncate last block to original file size */
        uint32_t to_write = BLOCK_SIZE;
        if (flags & 1u) {
            uint32_t remaining = hdr.orig_size - written;
            if (remaining < BLOCK_SIZE)
                to_write = remaining;
        }
        fwrite(plainblock, 1, to_write, fout);
        written += to_write;
    }

    fclose(fin);
    fclose(fout);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Cleanup — intentionally incomplete                                */
/* ═══════════════════════════════════════════════════════════════════ */

static void cleanup(void) {
    if (g_io_buf) { free(g_io_buf); g_io_buf = NULL; }
    /* BUG: g_ctx (A5), key (A1), iv (A2), salt (A7) NEVER freed.
       Memcheck reports: A1,A2 = definitely lost; A5 = still reachable;
       A7 = definitely lost. */
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Main                                                              */
/* ═══════════════════════════════════════════════════════════════════ */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <encrypt|decrypt> <input> <output> <password>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode_str = argv[1];
    const char *input    = argv[2];
    const char *output   = argv[3];
    const char *password = argv[4];

    int encrypting = (strcmp(mode_str, "encrypt") == 0);
    int decrypting = (strcmp(mode_str, "decrypt") == 0);
    if (!encrypting && !decrypting) {
        fprintf(stderr, "Error: mode must be 'encrypt' or 'decrypt'\n");
        return 1;
    }

    /* Initialize I/O buffer */
    if (!init_io()) {
        fprintf(stderr, "Error: I/O buffer allocation failed\n");
        return 1;
    }

    /* Derive key from password */
    uint8_t *key = derive_key(password);
    if (!key) {
        fprintf(stderr, "Error: key derivation failed\n");
        return 1;
    }

    /* Initialize cipher context */
    g_ctx = init_aes_ctx();
    if (!g_ctx) {
        fprintf(stderr, "Error: context allocation failed\n");
        return 1;
    }

    /* Prepare IV (partially uninitialized — intentional bug) */
    uint8_t *iv = prepare_iv();
    if (!iv) {
        fprintf(stderr, "Error: IV preparation failed\n");
        return 1;
    }

    /* Configure context */
    uint32_t mode_val = MODE_CBC;
    memcpy(g_ctx + CTX_MODE_OFF, &mode_val, sizeof(mode_val));
    memcpy(g_ctx + CTX_IV_OFF, iv, IV_SIZE);

    /* Expand key into round keys */
    expand_key(g_ctx, key);

    /* Process file */
    int result;
    if (encrypting) {
        result = process_encrypt(input, output, g_ctx, iv);
        if (result >= 0)
            printf("Encrypted: %d block(s) written to %s\n", result, output);
        else
            fprintf(stderr, "Encryption failed\n");
    } else {
        result = process_decrypt(input, output, g_ctx);
        if (result == 0)
            printf("Decrypted to %s\n", output);
        else
            fprintf(stderr, "Decryption failed\n");
    }

    cleanup();
    return (result < 0) ? 1 : 0;
}
