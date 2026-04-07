/*
 * ch14-fileformat.c — Custom binary file format parser for RE training
 *
 * Implements a reader/writer for a custom file format ".cdat"
 * (Compact Data Archive Table) used to store a collection of
 * named records with typed fields.
 *
 * File layout:
 *   ┌──────────────────────────────────┐
 *   │  File Header (24 bytes)          │
 *   │    magic      : 4 bytes "CDAT"   │
 *   │    version    : 2 bytes          │
 *   │    flags      : 2 bytes          │
 *   │    num_records: 4 bytes          │
 *   │    index_off  : 8 bytes          │
 *   │    checksum   : 4 bytes          │
 *   ├──────────────────────────────────┤
 *   │  Record 0                        │
 *   │    record_header (16 bytes)      │
 *   │      name_len  : 1 byte          │
 *   │      type      : 1 byte          │
 *   │      flags     : 2 bytes         │
 *   │      data_len  : 4 bytes         │
 *   │      timestamp : 8 bytes         │
 *   │    name        : name_len bytes  │
 *   │    data        : data_len bytes  │
 *   ├──────────────────────────────────┤
 *   │  Record 1 ...                    │
 *   ├──────────────────────────────────┤
 *   │  Index Table (at index_off)      │
 *   │    entry[0]: offset (8 bytes)    │
 *   │    entry[1]: offset (8 bytes)    │
 *   │    ...                           │
 *   └──────────────────────────────────┘
 *
 * Record types:
 *   0x01 = TEXT   (UTF-8 string, no null terminator)
 *   0x02 = BLOB   (raw binary)
 *   0x03 = INT32  (4 bytes, little-endian)
 *   0x04 = FLOAT  (8 bytes, IEEE 754 double)
 *
 * Intentional bugs for Valgrind/sanitizer training:
 *   - Heap overflow: name buffer allocated as name_len, but parser
 *     reads name_len+1 bytes (off-by-one) — ASan detects
 *   - Stack buffer overflow: checksum computed over a fixed 256-byte
 *     buffer, but file header can cause overread — ASan detects
 *   - Memory leak: index table never freed
 *   - Uninitialized padding bytes in record headers written to file
 *   - Signed overflow: checksum accumulation uses int
 *   - UBSan: shift by more than 31 bits when flags field is crafted
 *
 * Build: see accompanying Makefile
 *
 * Usage:
 *   ./fileformat create <output.cdat>             — create sample file
 *   ./fileformat parse  <input.cdat>              — parse and dump
 *   ./fileformat add    <file.cdat> <name> <data> — append record
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════ */
/*  Format constants                                                  */
/* ═══════════════════════════════════════════════════════════════════ */

#define MAGIC           0x54414443u  /* "CDAT" in little-endian */
#define FORMAT_VERSION  2
#define MAX_NAME_LEN    255
#define MAX_DATA_LEN    (1 << 20)   /* 1 MiB */
#define MAX_RECORDS     1024
#define CHECKSUM_BUF    256

/* Record types */
#define TYPE_TEXT   0x01
#define TYPE_BLOB   0x02
#define TYPE_INT32  0x03
#define TYPE_FLOAT  0x04

/* ═══════════════════════════════════════════════════════════════════ */
/*  On-disk structures                                                */
/* ═══════════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)

struct file_header {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t num_records;
    uint64_t index_offset;
    uint32_t checksum;
};  /* 24 bytes */

struct record_header {
    uint8_t  name_len;
    uint8_t  type;
    uint16_t flags;
    uint32_t data_len;
    uint64_t timestamp;
};  /* 16 bytes */

#pragma pack(pop)

/* ═══════════════════════════════════════════════════════════════════ */
/*  In-memory record                                                  */
/* ═══════════════════════════════════════════════════════════════════ */

struct record {
    struct record_header hdr;
    char    *name;      /* allocated: name_len bytes — BUG: should be +1 */
    uint8_t *data;      /* allocated: data_len bytes */
};

/* ═══════════════════════════════════════════════════════════════════ */
/*  Checksum — simple additive with rotation                          */
/*  BUG: uses 'int' (signed) → overflow detected by UBSan            */
/*  BUG: reads from a 256-byte stack buffer, can overread             */
/* ═══════════════════════════════════════════════════════════════════ */

static uint32_t compute_checksum(const void *data, size_t len) {
    uint8_t buf[CHECKSUM_BUF];
    const uint8_t *src = (const uint8_t *)data;
    int acc = 0;                                       /* signed — UBSan */

    /* Copy into fixed-size stack buffer
     * BUG: if len > CHECKSUM_BUF, reads beyond buf in the loop below
     * (memcpy is capped, but the loop iterates over 'len' not 'copied') */
    size_t to_copy = (len < CHECKSUM_BUF) ? len : CHECKSUM_BUF;
    memcpy(buf, src, to_copy);

    for (size_t i = 0; i < len; i++) {                 /* iterates 'len' */
        acc += (int)buf[i % CHECKSUM_BUF];             /* SIGNED OVERFLOW */
        acc = (acc << 3) | ((unsigned)acc >> 29);       /* rotate left 3 */
    }

    return (uint32_t)acc;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Index table — allocated, never freed                              */
/* ═══════════════════════════════════════════════════════════════════ */

static uint64_t *g_index_table = NULL;                 /* LEAK */
static uint32_t  g_index_count = 0;

static void index_add(uint64_t offset) {
    if (g_index_count == 0) {
        g_index_table = malloc(MAX_RECORDS * sizeof(uint64_t));
        if (!g_index_table) return;
    }
    if (g_index_count < MAX_RECORDS)
        g_index_table[g_index_count++] = offset;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Write helpers                                                     */
/* ═══════════════════════════════════════════════════════════════════ */

static int write_record(FILE *fp, const char *name, uint8_t type,
                        const void *data, uint32_t data_len) {
    uint64_t offset = (uint64_t)ftell(fp);
    index_add(offset);

    struct record_header rh;
    /* BUG: struct not fully zeroed — padding bytes uninitialised
     * Memcheck: "Syscall param write(buf) contains uninitialised byte(s)" */
    rh.name_len  = (uint8_t)strlen(name);
    rh.type      = type;
    /* rh.flags not set — 2 bytes uninitialised */
    rh.data_len  = data_len;
    rh.timestamp = (uint64_t)time(NULL);

    fwrite(&rh, 1, sizeof(rh), fp);
    fwrite(name, 1, rh.name_len, fp);
    fwrite(data, 1, data_len, fp);

    return 0;
}

static int write_file_header(FILE *fp, uint32_t num_records,
                             uint64_t index_offset) {
    struct file_header fh;
    fh.magic        = MAGIC;
    fh.version      = FORMAT_VERSION;
    fh.flags        = 0;
    fh.num_records  = num_records;
    fh.index_offset = index_offset;
    fh.checksum     = compute_checksum(&fh, sizeof(fh) - sizeof(fh.checksum));

    fseek(fp, 0, SEEK_SET);
    fwrite(&fh, 1, sizeof(fh), fp);

    return 0;
}

static int write_index(FILE *fp) {
    if (!g_index_table || g_index_count == 0) return -1;
    fwrite(g_index_table, sizeof(uint64_t), g_index_count, fp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Read / parse helpers                                              */
/* ═══════════════════════════════════════════════════════════════════ */

static struct record *read_record(FILE *fp) {
    struct record *rec = malloc(sizeof(struct record));
    if (!rec) return NULL;

    if (fread(&rec->hdr, 1, sizeof(rec->hdr), fp) != sizeof(rec->hdr)) {
        free(rec);
        return NULL;
    }

    /* Validate name_len */
    if (rec->hdr.name_len == 0 || rec->hdr.name_len > MAX_NAME_LEN) {
        fprintf(stderr, "  [!] Invalid name_len: %u\n", rec->hdr.name_len);
        free(rec);
        return NULL;
    }

    /* Validate data_len */
    if (rec->hdr.data_len > MAX_DATA_LEN) {
        fprintf(stderr, "  [!] Invalid data_len: %u\n", rec->hdr.data_len);
        free(rec);
        return NULL;
    }

    /* BUG: allocates exactly name_len, but code below reads name_len bytes
     * then accesses name[name_len] to null-terminate → heap overflow of 1 byte
     * ASan detects: heap-buffer-overflow, 0 bytes after block of size N */
    rec->name = malloc(rec->hdr.name_len);
    if (!rec->name) { free(rec); return NULL; }
    if (fread(rec->name, 1, rec->hdr.name_len, fp) != rec->hdr.name_len) {
        free(rec->name); free(rec);
        return NULL;
    }
    rec->name[rec->hdr.name_len] = '\0';               /* OFF-BY-ONE WRITE */

    /* Allocate and read data */
    rec->data = malloc(rec->hdr.data_len);
    if (!rec->data) { free(rec->name); free(rec); return NULL; }
    if (fread(rec->data, 1, rec->hdr.data_len, fp) != rec->hdr.data_len) {
        free(rec->data); free(rec->name); free(rec);
        return NULL;
    }

    return rec;
}

static void free_record(struct record *rec) {
    if (!rec) return;
    free(rec->name);
    free(rec->data);
    free(rec);
}

static const char *type_name(uint8_t type) {
    switch (type) {
        case TYPE_TEXT:  return "TEXT";
        case TYPE_BLOB:  return "BLOB";
        case TYPE_INT32: return "INT32";
        case TYPE_FLOAT: return "FLOAT";
        default:         return "UNKNOWN";
    }
}

static void print_record_data(const struct record *rec) {
    switch (rec->hdr.type) {
        case TYPE_TEXT:
            printf("    data  : \"%.*s\"\n",
                   (int)rec->hdr.data_len, (const char *)rec->data);
            break;
        case TYPE_INT32:
            if (rec->hdr.data_len >= 4) {
                int32_t val;
                memcpy(&val, rec->data, 4);
                printf("    data  : %d (0x%08X)\n", val, (uint32_t)val);
            }
            break;
        case TYPE_FLOAT:
            if (rec->hdr.data_len >= 8) {
                double val;
                memcpy(&val, rec->data, 8);
                printf("    data  : %f\n", val);
            }
            break;
        case TYPE_BLOB:
        default:
            printf("    data  : [%u bytes binary]\n", rec->hdr.data_len);
            break;
    }
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Flag decoding                                                     */
/*  BUG: shift by flag bit index — if bit > 31, UBSan flags it       */
/* ═══════════════════════════════════════════════════════════════════ */

static void decode_flags(uint16_t flags) {
    const char *flag_names[] = {
        "COMPRESSED", "ENCRYPTED", "INDEXED", "READONLY",
        "HIDDEN", "SYSTEM", "ARCHIVE", "TEMPORARY",
        "SPARSE", "VIRTUAL", "LINKED", "CACHED",
        "DIRTY", "LOCKED", "SIGNED", "EXTENDED"
    };

    if (flags == 0) {
        printf("    flags : (none)\n");
        return;
    }

    printf("    flags : ");
    int first = 1;
    for (int i = 0; i < 16; i++) {
        /* BUG: when i comes from untrusted data and exceeds 31,
         * this would be UB. Here i is bounded to [0,15] so it's safe,
         * but the record.flags field can trigger UBSan via
         * a different code path (see process_record_flags). */
        if (flags & (1u << i)) {
            printf("%s%s", first ? "" : " | ", flag_names[i]);
            first = 0;
        }
    }
    printf("\n");
}

/*
 * Process extended flags — reads the flags field as a shift amount.
 * BUG: if flags value > 31, the left shift is UB for signed int.
 */
static uint32_t process_record_flags(uint16_t flags) {
    int shift = (int)flags;                            /* could be > 31 */
    int result = 1 << shift;                           /* UB if shift >= 32 */
    return (uint32_t)result;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Command: create — write a sample .cdat file                       */
/* ═══════════════════════════════════════════════════════════════════ */

static int cmd_create(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) { perror("fopen"); return 1; }

    /* Write placeholder header (will be overwritten at the end) */
    struct file_header placeholder;
    memset(&placeholder, 0, sizeof(placeholder));
    fwrite(&placeholder, 1, sizeof(placeholder), fp);

    /* Write sample records */
    const char *text1 = "Hello, Reverse Engineering!";
    write_record(fp, "greeting", TYPE_TEXT,
                 text1, (uint32_t)strlen(text1));

    int32_t val = 0xDEADBEEF;
    write_record(fp, "magic_number", TYPE_INT32,
                 &val, sizeof(val));

    double pi = 3.14159265358979;
    write_record(fp, "pi_value", TYPE_FLOAT,
                 &pi, sizeof(pi));

    uint8_t blob[] = { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0xAA, 0x55 };
    write_record(fp, "sample_blob", TYPE_BLOB,
                 blob, sizeof(blob));

    const char *text2 = "This is a longer text record for testing "
                        "the parser with more substantial data content.";
    write_record(fp, "long_text", TYPE_TEXT,
                 text2, (uint32_t)strlen(text2));

    /* Write index table */
    uint64_t index_off = (uint64_t)ftell(fp);
    write_index(fp);

    /* Rewrite header with correct values */
    write_file_header(fp, g_index_count, index_off);

    fclose(fp);
    printf("Created %s: %u records\n", path, g_index_count);

    /* BUG: g_index_table never freed → Memcheck leak */
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Command: parse — read and dump a .cdat file                       */
/* ═══════════════════════════════════════════════════════════════════ */

static int cmd_parse(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("fopen"); return 1; }

    /* Read file header */
    struct file_header fh;
    if (fread(&fh, 1, sizeof(fh), fp) != sizeof(fh)) {
        fprintf(stderr, "Error: truncated file header\n");
        fclose(fp); return 1;
    }

    /* Validate magic */
    if (fh.magic != MAGIC) {
        fprintf(stderr, "Error: bad magic 0x%08X (expected 0x%08X)\n",
                fh.magic, MAGIC);
        fclose(fp); return 1;
    }

    /* Verify checksum */
    uint32_t expected_cksum = fh.checksum;
    uint32_t computed_cksum = compute_checksum(&fh,
                                  sizeof(fh) - sizeof(fh.checksum));
    if (computed_cksum != expected_cksum) {
        fprintf(stderr, "Warning: checksum mismatch "
                "(computed 0x%08X, stored 0x%08X)\n",
                computed_cksum, expected_cksum);
    }

    printf("=== CDAT File: %s ===\n", path);
    printf("  Version    : %u\n", fh.version);
    printf("  Flags      : 0x%04X\n", fh.flags);
    printf("  Records    : %u\n", fh.num_records);
    printf("  Index at   : 0x%lX\n", (unsigned long)fh.index_offset);
    printf("  Checksum   : 0x%08X (%s)\n", expected_cksum,
           (computed_cksum == expected_cksum) ? "OK" : "MISMATCH");
    printf("\n");

    /* Read index table (for offset validation) */
    uint64_t *idx = NULL;
    if (fh.index_offset > 0 && fh.num_records > 0 &&
        fh.num_records <= MAX_RECORDS) {
        idx = malloc(fh.num_records * sizeof(uint64_t));         /* LEAK */
        if (idx) {
            long saved = ftell(fp);
            fseek(fp, (long)fh.index_offset, SEEK_SET);
            size_t read_n = fread(idx, sizeof(uint64_t), fh.num_records, fp);
            if (read_n != fh.num_records) {
                fprintf(stderr, "Warning: incomplete index table "
                        "(%zu of %u entries)\n", read_n, fh.num_records);
            }
            fseek(fp, saved, SEEK_SET);
        }
    }

    /* Parse records sequentially */
    for (uint32_t i = 0; i < fh.num_records; i++) {
        printf("--- Record %u ---\n", i);

        if (idx) {
            printf("    index_off: 0x%lX (current: 0x%lX)\n",
                   (unsigned long)idx[i], (unsigned long)ftell(fp));
        }

        struct record *rec = read_record(fp);
        if (!rec) {
            fprintf(stderr, "  [!] Failed to read record %u\n", i);
            break;
        }

        printf("    name  : \"%s\" (%u bytes)\n", rec->name, rec->hdr.name_len);
        printf("    type  : %s (0x%02X)\n", type_name(rec->hdr.type), rec->hdr.type);
        decode_flags(rec->hdr.flags);
        printf("    size  : %u bytes\n", rec->hdr.data_len);
        printf("    time  : %lu\n", (unsigned long)rec->hdr.timestamp);

        print_record_data(rec);

        /* Process extended flags — triggers UBSan if flags > 31 */
        if (rec->hdr.flags > 0) {
            uint32_t flag_val = process_record_flags(rec->hdr.flags);
            printf("    fval  : 0x%08X\n", flag_val);
        }

        printf("\n");
        free_record(rec);
    }

    /* BUG: idx never freed → Memcheck reports leak
     * Size = num_records × 8 bytes */
    fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Command: add — append a text record to existing file              */
/* ═══════════════════════════════════════════════════════════════════ */

static int cmd_add(const char *path, const char *name, const char *data) {
    FILE *fp = fopen(path, "r+b");
    if (!fp) { perror("fopen"); return 1; }

    /* Read existing header */
    struct file_header fh;
    if (fread(&fh, 1, sizeof(fh), fp) != sizeof(fh)) {
        fprintf(stderr, "Error: cannot read header\n");
        fclose(fp); return 1;
    }
    if (fh.magic != MAGIC) {
        fprintf(stderr, "Error: not a CDAT file\n");
        fclose(fp); return 1;
    }

    /* Read existing index */
    g_index_count = 0;
    if (fh.num_records > 0 && fh.num_records <= MAX_RECORDS) {
        g_index_table = malloc(MAX_RECORDS * sizeof(uint64_t));
        if (g_index_table) {
            fseek(fp, (long)fh.index_offset, SEEK_SET);
            fread(g_index_table, sizeof(uint64_t), fh.num_records, fp);
            g_index_count = fh.num_records;
        }
    }

    /* Seek to old index position (overwrite it with new record) */
    fseek(fp, (long)fh.index_offset, SEEK_SET);

    /* Write new record */
    write_record(fp, name, TYPE_TEXT, data, (uint32_t)strlen(data));

    /* Write updated index */
    uint64_t new_index_off = (uint64_t)ftell(fp);
    write_index(fp);

    /* Update header */
    write_file_header(fp, g_index_count, new_index_off);

    fclose(fp);
    printf("Added record \"%s\" (%zu bytes) to %s\n",
           name, strlen(data), path);

    /* BUG: g_index_table leaked again */
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  Main                                                              */
/* ═══════════════════════════════════════════════════════════════════ */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s create <output.cdat>\n"
        "  %s parse  <input.cdat>\n"
        "  %s add    <file.cdat> <name> <data>\n",
        prog, prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "create") == 0 && argc == 3) {
        return cmd_create(argv[2]);
    }
    else if (strcmp(cmd, "parse") == 0 && argc == 3) {
        return cmd_parse(argv[2]);
    }
    else if (strcmp(cmd, "add") == 0 && argc == 5) {
        return cmd_add(argv[2], argv[3], argv[4]);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }
}
