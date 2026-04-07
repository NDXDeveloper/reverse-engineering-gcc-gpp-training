/*
 * fuzz_fileformat.c — libFuzzer harness for the CSTM parser
 *
 * Directly calls the parsing functions from fileformat.c
 * (made non-static by the FUZZ_TARGET macro).
 *
 * Compilation (both files in the same command):
 *   clang -DFUZZ_TARGET -fsanitize=fuzzer,address,undefined -g -O1 \
 *       -o fuzz_fileformat fuzz_fileformat.c fileformat.c
 *
 * Usage:
 *   mkdir corpus && echo -ne 'CSTM\x01\x00\x00\x00' > corpus/seed.bin
 *   ./fuzz_fileformat corpus/
 *
 * MIT License — Strictly educational use.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════
 *  Structures and constants reproduced from fileformat.c
 * ══════════════════════════════════════════════════════════ */

#define MAGIC           "CSTM"
#define MAGIC_SIZE      4
#define HEADER_SIZE     8
#define MAX_VERSION     3

typedef struct {
    char     magic[MAGIC_SIZE];
    uint8_t  version;
    uint8_t  flags;
    uint16_t section_count;
} __attribute__((packed)) FileHeader;

/* ══════════════════════════════════════════════════════════
 *  Prototypes for fileformat.c functions
 *  (non-static when compiled with -DFUZZ_TARGET)
 * ══════════════════════════════════════════════════════════ */

int parse_header(const uint8_t *file_data, size_t file_size,
                 FileHeader *header);
int verify_signature(const uint8_t *file_data, size_t file_size,
                     const FileHeader *header);
int parse_sections(const uint8_t *file_data, size_t file_size,
                   const FileHeader *header);
int validate_checksum(const uint8_t *file_data, size_t file_size,
                      const FileHeader *header);

/* ══════════════════════════════════════════════════════════
 *  libFuzzer harness — entry point
 * ══════════════════════════════════════════════════════════ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Quick reject for inputs that are too small (avoids noise) */
    if (size < HEADER_SIZE) {
        return 0;
    }

    /* Limit size to keep fuzzing fast */
    if (size > 1024 * 1024) {
        return 0;
    }

    /*
     * Suppress stdout to avoid flooding the terminal.
     * In production one would use freopen("/dev/null", "w", stdout)
     * once in LLVMFuzzerInitialize, but here we keep the code
     * simple and self-contained.
     */
    FILE *devnull = fopen("/dev/null", "w");
    FILE *saved_stdout = stdout;
    if (devnull) {
        stdout = devnull;
    }

    /* ── Reproduce the main() logic in-process ── */

    FileHeader header;

    if (parse_header(data, size, &header) != 0) {
        goto cleanup;
    }

    /* Signature verification for version 3 */
    if (header.version == 3) {
        if (verify_signature(data, size, &header) != 0) {
            goto cleanup;
        }
    }

    /* Section parsing */
    if (header.section_count > 0) {
        parse_sections(data, size, &header);
    }

    /* Checksum validation if the flag is set */
    if (header.flags & 0x01) {
        validate_checksum(data, size, &header);
    }

cleanup:
    /* Restore stdout */
    if (devnull) {
        stdout = saved_stdout;
        fclose(devnull);
    }

    return 0;
}

/*
 * LLVMFuzzerInitialize — Optional initialization hook.
 * Called once before the first iteration.
 * Can be used to parse harness arguments.
 */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    /* Suppress stderr for parser error messages
     * (optional — uncomment if output is too verbose) */
    /* freopen("/dev/null", "w", stderr); */

    return 0;
}
