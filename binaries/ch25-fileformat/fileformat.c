/*
 * fileformat.c — Custom archive format "CFR" (Custom Format Records)
 *
 * Training binary for Chapter 25: Reversing a custom file format
 * MIT License — Strictly educational use.
 *
 * Commands:
 *   generate <output.cfr>                  Create a demo archive
 *   pack [-x] <output.cfr> <file1> [...]   Pack files into a CFR archive
 *   list <input.cfr>                       List records in archive
 *   read <input.cfr>                       Display record contents
 *   unpack <input.cfr> [output_dir]        Extract records to files
 *   validate <input.cfr>                   Verify archive integrity
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

/* ============================================================
 *  Format constants
 * ============================================================ */

#define HDR_MAGIC       "CFRM"
#define FTR_MAGIC       "CRFE"
#define FMT_VERSION     0x0002

#define REC_TEXT         0x01
#define REC_BINARY       0x02
#define REC_META         0x03

#define FL_XOR           (1 << 0)   /* data XOR-obfuscated          */
#define FL_FOOTER        (1 << 1)   /* footer with global CRC       */

#define MAX_NAME_LEN     255
#define MAX_RECORDS      1024
#define AUTHOR_LEN       8
#define RESERVED_LEN     4
#define XOR_KEY_LEN      4

static const uint8_t xor_key[XOR_KEY_LEN] = {0x5A, 0x3C, 0x96, 0xF1};

/* ============================================================
 *  On-disk structures (little-endian, packed)
 * ============================================================ */

#pragma pack(push, 1)

typedef struct {
    char     magic[4];          /* 0x00  "CFRM"                          */
    uint16_t version;           /* 0x04  format version (0x0002)         */
    uint16_t flags;             /* 0x06  FL_XOR | FL_FOOTER              */
    uint32_t num_records;       /* 0x08  number of records               */
    uint32_t timestamp;         /* 0x0C  UNIX timestamp of creation      */
    uint32_t header_crc;        /* 0x10  CRC-32 of bytes [0x00..0x0F]    */
    char     author[AUTHOR_LEN];/* 0x14  null-padded author tag          */
    uint8_t  reserved[RESERVED_LEN]; /* 0x1C  XOR of all data_len values */
} cfr_header_t;                 /* Total: 32 bytes                       */

typedef struct {
    uint8_t  type;              /* REC_TEXT / REC_BINARY / REC_META      */
    uint8_t  flags;             /* per-record flags (reserved, set to 0) */
    uint16_t name_len;          /* length of record name                 */
    uint32_t data_len;          /* length of record payload              */
} cfr_rec_hdr_t;               /* 8 bytes, followed by name + data + crc16 */

typedef struct {
    char     magic[4];          /* "CRFE"                                */
    uint32_t total_size;        /* total file size including footer      */
    uint32_t global_crc;        /* CRC-32 of everything before footer    */
} cfr_footer_t;                /* 12 bytes                              */

#pragma pack(pop)

/* ============================================================
 *  CRC implementations
 * ============================================================ */

static uint32_t crc32_tbl[256];
static int crc32_ready = 0;

static void crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (c & 1 ? 0xEDB88320u : 0);
        crc32_tbl[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t crc32_compute(const uint8_t *buf, size_t len) {
    if (!crc32_ready) crc32_init();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_tbl[(crc ^ buf[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *buf, size_t len) {
    if (!crc32_ready) crc32_init();
    crc ^= 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_tbl[(crc ^ buf[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFu;
}

/* CRC-16/CCITT variant — non-standard init value 0x1D0F */
static uint16_t crc16_compute(const uint8_t *buf, size_t len) {
    uint16_t crc = 0x1D0F;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i] << 8;
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
    }
    return crc;
}

/* ============================================================
 *  XOR obfuscation (rotating 4-byte key)
 * ============================================================ */

static void xor_transform(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= xor_key[i % XOR_KEY_LEN];
}

/* ============================================================
 *  Helpers
 * ============================================================ */

static void set_author(char out[AUTHOR_LEN]) {
    const char *user = getenv("USER");
    if (!user || !*user) user = "anon";
    memset(out, 0, AUTHOR_LEN);
    strncpy(out, user, AUTHOR_LEN);
}

static uint32_t compute_reserved(const uint32_t *dlens, uint32_t n) {
    uint32_t v = 0;
    for (uint32_t i = 0; i < n; i++)
        v ^= dlens[i];
    return v;
}

static const char *rec_type_str(uint8_t t) {
    switch (t) {
        case REC_TEXT:   return "TEXT";
        case REC_BINARY: return "BINARY";
        case REC_META:   return "META";
        default:         return "UNKNOWN";
    }
}

static uint8_t guess_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (dot && (strcmp(dot, ".txt") == 0 || strcmp(dot, ".md") == 0 ||
                strcmp(dot, ".csv") == 0 || strcmp(dot, ".log") == 0))
        return REC_TEXT;
    if (dot && strcmp(dot, ".meta") == 0)
        return REC_META;
    return REC_BINARY;
}

static int write_all(FILE *fp, const void *buf, size_t len) {
    return fwrite(buf, 1, len, fp) == len ? 0 : -1;
}

static int read_all(FILE *fp, void *buf, size_t len) {
    return fread(buf, 1, len, fp) == len ? 0 : -1;
}

/* ============================================================
 *  Write a single record to file
 * ============================================================ */

static int write_record(FILE *fp, uint8_t type, const char *name,
                        const uint8_t *data, uint32_t data_len,
                        int do_xor) {
    uint16_t nlen = (uint16_t)strlen(name);
    cfr_rec_hdr_t rh = {type, 0, nlen, data_len};

    if (write_all(fp, &rh, sizeof(rh)) < 0) return -1;
    if (write_all(fp, name, nlen) < 0)       return -1;

    /* CRC-16 is computed on name + original (pre-XOR) data */
    uint16_t crc;
    {
        uint16_t c = 0x1D0F;
        const uint8_t *p;
        /* compute over name */
        p = (const uint8_t *)name;
        for (size_t i = 0; i < nlen; i++) {
            c ^= (uint16_t)p[i] << 8;
            for (int j = 0; j < 8; j++)
                c = (c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1;
        }
        /* compute over original data */
        for (size_t i = 0; i < data_len; i++) {
            c ^= (uint16_t)data[i] << 8;
            for (int j = 0; j < 8; j++)
                c = (c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1;
        }
        crc = c;
    }

    if (do_xor && data_len > 0) {
        uint8_t *tmp = malloc(data_len);
        if (!tmp) return -1;
        memcpy(tmp, data, data_len);
        xor_transform(tmp, data_len);
        int r = write_all(fp, tmp, data_len);
        free(tmp);
        if (r < 0) return -1;
    } else {
        if (data_len > 0 && write_all(fp, data, data_len) < 0)
            return -1;
    }

    if (write_all(fp, &crc, sizeof(crc)) < 0) return -1;
    return 0;
}

/* ============================================================
 *  cmd_generate — create a demo .cfr archive
 * ============================================================ */

static int cmd_generate(const char *outpath) {
    FILE *fp = fopen(outpath, "w+b");
    if (!fp) { perror(outpath); return 1; }

    /* Sample records */
    const char *names[]  = {"greeting.txt", "data.bin", "version.meta", "notes.txt"};
    const char *texts[]  = {
        "Hello from the CFR archive format!\nThis is a sample text record.",
        NULL, /* binary */
        "format=CFR\nversion=2\nauthor=student",
        "This archive was generated for Chapter 25 of the RE training.\n"
        "Your mission: reverse-engineer this format completely."
    };
    uint8_t bin_data[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    uint8_t types[] = {REC_TEXT, REC_BINARY, REC_META, REC_TEXT};
    uint32_t num_rec = 4;
    uint16_t flags = FL_FOOTER;

    /* Build data pointers and lengths */
    const uint8_t *datas[4];
    uint32_t dlens[4];
    for (int i = 0; i < 4; i++) {
        if (types[i] == REC_BINARY || texts[i] == NULL) {
            datas[i] = bin_data;
            dlens[i] = sizeof(bin_data);
        } else {
            datas[i] = (const uint8_t *)texts[i];
            dlens[i] = (uint32_t)strlen(texts[i]);
        }
    }

    /* Write header */
    cfr_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, HDR_MAGIC, 4);
    hdr.version     = FMT_VERSION;
    hdr.flags       = flags;
    hdr.num_records = num_rec;
    hdr.timestamp   = (uint32_t)time(NULL);
    hdr.header_crc  = 0; /* computed on first 16 bytes */
    set_author(hdr.author);

    /* reserved = XOR of all data lengths */
    uint32_t rv = compute_reserved(dlens, num_rec);
    memcpy(hdr.reserved, &rv, 4);

    /* Compute header CRC on first 16 bytes (magic..timestamp) */
    hdr.header_crc = crc32_compute((const uint8_t *)&hdr, 16);

    write_all(fp, &hdr, sizeof(hdr));

    /* Write records */
    for (uint32_t i = 0; i < num_rec; i++)
        write_record(fp, types[i], names[i], datas[i], dlens[i],
                     flags & FL_XOR);

    /* Write footer */
    if (flags & FL_FOOTER) {
        long pos = ftell(fp);
        cfr_footer_t ftr;
        memcpy(ftr.magic, FTR_MAGIC, 4);
        ftr.total_size = (uint32_t)pos + sizeof(ftr);

        /* Global CRC: flush then read back everything written so far */
        fflush(fp);
        fseek(fp, 0, SEEK_SET);
        uint8_t *all = malloc(pos);
        if (all) {
            fread(all, 1, pos, fp);
            ftr.global_crc = crc32_compute(all, pos);
            free(all);
        } else {
            ftr.global_crc = 0;
        }
        fseek(fp, pos, SEEK_SET);
        write_all(fp, &ftr, sizeof(ftr));
    }

    fclose(fp);
    printf("[+] Generated %s (%u records)\n", outpath, num_rec);
    return 0;
}

/* ============================================================
 *  cmd_pack — pack files into a CFR archive
 * ============================================================ */

static int cmd_pack(int argc, char **argv) {
    int do_xor = 0;
    int argi = 0;

    if (argc > 0 && strcmp(argv[0], "-x") == 0) {
        do_xor = 1;
        argi++;
    }
    if (argc - argi < 2) {
        fprintf(stderr, "Usage: pack [-x] <output.cfr> <file1> [...]\n");
        return 1;
    }

    const char *outpath = argv[argi++];
    int nfiles = argc - argi;
    if (nfiles > MAX_RECORDS) {
        fprintf(stderr, "Too many files (max %d)\n", MAX_RECORDS);
        return 1;
    }

    uint16_t flags = FL_FOOTER | (do_xor ? FL_XOR : 0);

    /* Read all input files first */
    uint8_t  *fdata[MAX_RECORDS];
    uint32_t  fsize[MAX_RECORDS];
    uint8_t   ftype[MAX_RECORDS];
    char     *fname[MAX_RECORDS];

    for (int i = 0; i < nfiles; i++) {
        const char *path = argv[argi + i];
        FILE *fin = fopen(path, "rb");
        if (!fin) { perror(path); return 1; }
        fseek(fin, 0, SEEK_END);
        fsize[i] = (uint32_t)ftell(fin);
        fseek(fin, 0, SEEK_SET);
        fdata[i] = malloc(fsize[i] ? fsize[i] : 1);
        if (fsize[i]) fread(fdata[i], 1, fsize[i], fin);
        fclose(fin);
        fname[i] = basename((char *)path);
        ftype[i] = guess_type(fname[i]);
    }

    FILE *fp = fopen(outpath, "w+b");
    if (!fp) { perror(outpath); return 1; }

    cfr_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, HDR_MAGIC, 4);
    hdr.version     = FMT_VERSION;
    hdr.flags       = flags;
    hdr.num_records = (uint32_t)nfiles;
    hdr.timestamp   = (uint32_t)time(NULL);
    set_author(hdr.author);

    uint32_t rv = compute_reserved(fsize, nfiles);
    memcpy(hdr.reserved, &rv, 4);
    hdr.header_crc = crc32_compute((const uint8_t *)&hdr, 16);

    write_all(fp, &hdr, sizeof(hdr));

    for (int i = 0; i < nfiles; i++)
        write_record(fp, ftype[i], fname[i], fdata[i], fsize[i],
                     flags & FL_XOR);

    if (flags & FL_FOOTER) {
        long pos = ftell(fp);
        cfr_footer_t ftr;
        memcpy(ftr.magic, FTR_MAGIC, 4);
        ftr.total_size = (uint32_t)pos + sizeof(ftr);
        fflush(fp);
        fseek(fp, 0, SEEK_SET);
        uint8_t *all = malloc(pos);
        if (all) {
            fread(all, 1, pos, fp);
            ftr.global_crc = crc32_compute(all, pos);
            free(all);
        } else {
            ftr.global_crc = 0;
        }
        fseek(fp, pos, SEEK_SET);
        write_all(fp, &ftr, sizeof(ftr));
    }

    fclose(fp);
    for (int i = 0; i < nfiles; i++) free(fdata[i]);
    printf("[+] Packed %d file(s) into %s\n", nfiles, outpath);
    return 0;
}

/* ============================================================
 *  Read & parse helpers
 * ============================================================ */

typedef struct {
    cfr_header_t hdr;
    struct {
        cfr_rec_hdr_t rh;
        char         *name;
        uint8_t      *data;     /* after un-XOR if applicable */
        uint16_t      stored_crc;
    } recs[MAX_RECORDS];
    cfr_footer_t ftr;
    int has_footer;
    long file_size;
} cfr_archive_t;

static void free_archive(cfr_archive_t *ar) {
    for (uint32_t i = 0; i < ar->hdr.num_records; i++) {
        free(ar->recs[i].name);
        free(ar->recs[i].data);
    }
}

static int parse_archive(const char *path, cfr_archive_t *ar) {
    memset(ar, 0, sizeof(*ar));
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return -1; }

    fseek(fp, 0, SEEK_END);
    ar->file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (read_all(fp, &ar->hdr, sizeof(ar->hdr)) < 0) {
        fprintf(stderr, "[-] Failed to read header\n");
        fclose(fp); return -1;
    }

    if (memcmp(ar->hdr.magic, HDR_MAGIC, 4) != 0) {
        fprintf(stderr, "[-] Invalid magic: expected CFRM\n");
        fclose(fp); return -1;
    }

    if (ar->hdr.num_records > MAX_RECORDS) {
        fprintf(stderr, "[-] Too many records (%u)\n", ar->hdr.num_records);
        fclose(fp); return -1;
    }

    int do_xor = ar->hdr.flags & FL_XOR;

    for (uint32_t i = 0; i < ar->hdr.num_records; i++) {
        if (read_all(fp, &ar->recs[i].rh, sizeof(cfr_rec_hdr_t)) < 0) {
            fprintf(stderr, "[-] Failed to read record %u header\n", i);
            fclose(fp); free_archive(ar); return -1;
        }

        uint16_t nlen = ar->recs[i].rh.name_len;
        uint32_t dlen = ar->recs[i].rh.data_len;

        ar->recs[i].name = calloc(1, nlen + 1);
        if (read_all(fp, ar->recs[i].name, nlen) < 0) {
            fprintf(stderr, "[-] Failed to read record %u name\n", i);
            fclose(fp); free_archive(ar); return -1;
        }

        ar->recs[i].data = malloc(dlen ? dlen : 1);
        if (dlen && read_all(fp, ar->recs[i].data, dlen) < 0) {
            fprintf(stderr, "[-] Failed to read record %u data\n", i);
            fclose(fp); free_archive(ar); return -1;
        }

        /* Un-XOR the data in place */
        if (do_xor && dlen > 0)
            xor_transform(ar->recs[i].data, dlen);

        if (read_all(fp, &ar->recs[i].stored_crc, 2) < 0) {
            fprintf(stderr, "[-] Failed to read record %u CRC\n", i);
            fclose(fp); free_archive(ar); return -1;
        }
    }

    /* Check for footer */
    ar->has_footer = 0;
    if (ar->hdr.flags & FL_FOOTER) {
        long pos = ftell(fp);
        if (pos + (long)sizeof(cfr_footer_t) <= ar->file_size) {
            if (read_all(fp, &ar->ftr, sizeof(ar->ftr)) == 0 &&
                memcmp(ar->ftr.magic, FTR_MAGIC, 4) == 0) {
                ar->has_footer = 1;
            }
        }
    }

    fclose(fp);
    return 0;
}

/* ============================================================
 *  cmd_list
 * ============================================================ */

static int cmd_list(const char *path) {
    cfr_archive_t ar;
    if (parse_archive(path, &ar) < 0) return 1;

    printf("Archive : %s\n", path);
    printf("Version : 0x%04X\n", ar.hdr.version);
    printf("Flags   : 0x%04X", ar.hdr.flags);
    if (ar.hdr.flags & FL_XOR)    printf(" [XOR]");
    if (ar.hdr.flags & FL_FOOTER) printf(" [FOOTER]");
    printf("\n");
    printf("Records : %u\n", ar.hdr.num_records);
    printf("Author  : %.8s\n", ar.hdr.author);
    printf("Created : %u\n\n", ar.hdr.timestamp);

    printf("  # | Type   | Size       | Name\n");
    printf("----+--------+------------+-------------------------\n");
    for (uint32_t i = 0; i < ar.hdr.num_records; i++) {
        printf(" %2u | %-6s | %10u | %s\n", i,
               rec_type_str(ar.recs[i].rh.type),
               ar.recs[i].rh.data_len,
               ar.recs[i].name);
    }

    free_archive(&ar);
    return 0;
}

/* ============================================================
 *  cmd_read — display contents
 * ============================================================ */

static int cmd_read(const char *path) {
    cfr_archive_t ar;
    if (parse_archive(path, &ar) < 0) return 1;

    for (uint32_t i = 0; i < ar.hdr.num_records; i++) {
        printf("=== Record %u: %s [%s, %u bytes] ===\n", i,
               ar.recs[i].name,
               rec_type_str(ar.recs[i].rh.type),
               ar.recs[i].rh.data_len);

        if (ar.recs[i].rh.type == REC_TEXT ||
            ar.recs[i].rh.type == REC_META) {
            fwrite(ar.recs[i].data, 1, ar.recs[i].rh.data_len, stdout);
            printf("\n");
        } else {
            /* Hex dump for binary records */
            uint32_t len = ar.recs[i].rh.data_len;
            if (len > 256) len = 256;
            for (uint32_t j = 0; j < len; j++) {
                if (j % 16 == 0) printf("  %04x: ", j);
                printf("%02x ", ar.recs[i].data[j]);
                if (j % 16 == 15 || j == len - 1) printf("\n");
            }
            if (ar.recs[i].rh.data_len > 256)
                printf("  ... (%u bytes total)\n", ar.recs[i].rh.data_len);
        }
        printf("\n");
    }

    free_archive(&ar);
    return 0;
}

/* ============================================================
 *  cmd_unpack — extract records to files
 * ============================================================ */

static int cmd_unpack(const char *path, const char *outdir) {
    cfr_archive_t ar;
    if (parse_archive(path, &ar) < 0) return 1;

    if (outdir) {
        mkdir(outdir, 0755);
    }

    for (uint32_t i = 0; i < ar.hdr.num_records; i++) {
        char outpath[512];
        if (outdir)
            snprintf(outpath, sizeof(outpath), "%s/%s", outdir, ar.recs[i].name);
        else
            snprintf(outpath, sizeof(outpath), "%s", ar.recs[i].name);

        FILE *fout = fopen(outpath, "wb");
        if (!fout) { perror(outpath); continue; }
        fwrite(ar.recs[i].data, 1, ar.recs[i].rh.data_len, fout);
        fclose(fout);
        printf("[+] Extracted: %s (%u bytes)\n", outpath, ar.recs[i].rh.data_len);
    }

    free_archive(&ar);
    return 0;
}

/* ============================================================
 *  cmd_validate — verify archive integrity
 * ============================================================ */

static int cmd_validate(const char *path) {
    cfr_archive_t ar;
    if (parse_archive(path, &ar) < 0) return 1;

    int errors = 0;

    /* 1. Header CRC (first 16 bytes) */
    uint32_t expected_hcrc = crc32_compute((const uint8_t *)&ar.hdr, 16);
    /* Recompute: zero out header_crc field for computation */
    {
        cfr_header_t tmp;
        memcpy(&tmp, &ar.hdr, sizeof(tmp));
        tmp.header_crc = 0;
        expected_hcrc = crc32_compute((const uint8_t *)&tmp, 16);
    }
    if (ar.hdr.header_crc != expected_hcrc) {
        printf("[FAIL] Header CRC: stored=0x%08X computed=0x%08X\n",
               ar.hdr.header_crc, expected_hcrc);
        errors++;
    } else {
        printf("[ OK ] Header CRC: 0x%08X\n", ar.hdr.header_crc);
    }

    /* 2. Reserved field = XOR of all data_len */
    uint32_t rv = 0;
    for (uint32_t i = 0; i < ar.hdr.num_records; i++)
        rv ^= ar.recs[i].rh.data_len;
    uint32_t stored_rv;
    memcpy(&stored_rv, ar.hdr.reserved, 4);
    if (stored_rv != rv) {
        printf("[FAIL] Reserved check: stored=0x%08X computed=0x%08X\n",
               stored_rv, rv);
        errors++;
    } else {
        printf("[ OK ] Reserved check: 0x%08X\n", rv);
    }

    /* 3. Per-record CRC-16 */
    for (uint32_t i = 0; i < ar.hdr.num_records; i++) {
        uint16_t nlen = ar.recs[i].rh.name_len;
        uint32_t dlen = ar.recs[i].rh.data_len;

        /* CRC-16 over name + original data */
        uint16_t c = 0x1D0F;
        const uint8_t *p = (const uint8_t *)ar.recs[i].name;
        for (uint16_t k = 0; k < nlen; k++) {
            c ^= (uint16_t)p[k] << 8;
            for (int j = 0; j < 8; j++)
                c = (c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1;
        }
        p = ar.recs[i].data;
        for (uint32_t k = 0; k < dlen; k++) {
            c ^= (uint16_t)p[k] << 8;
            for (int j = 0; j < 8; j++)
                c = (c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1;
        }

        if (ar.recs[i].stored_crc != c) {
            printf("[FAIL] Record %u (%s) CRC-16: stored=0x%04X computed=0x%04X\n",
                   i, ar.recs[i].name, ar.recs[i].stored_crc, c);
            errors++;
        } else {
            printf("[ OK ] Record %u (%s) CRC-16: 0x%04X\n",
                   i, ar.recs[i].name, c);
        }
    }

    /* 4. Footer checks */
    if (ar.has_footer) {
        if (ar.ftr.total_size != (uint32_t)ar.file_size) {
            printf("[FAIL] Footer total_size: stored=%u actual=%ld\n",
                   ar.ftr.total_size, ar.file_size);
            errors++;
        } else {
            printf("[ OK ] Footer total_size: %u\n", ar.ftr.total_size);
        }

        /* Re-read file for global CRC */
        long payload_size = ar.file_size - sizeof(cfr_footer_t);
        FILE *fp = fopen(path, "rb");
        if (fp) {
            uint8_t *all = malloc(payload_size);
            if (all) {
                fread(all, 1, payload_size, fp);
                uint32_t gc = crc32_compute(all, payload_size);
                if (ar.ftr.global_crc != gc) {
                    printf("[FAIL] Global CRC: stored=0x%08X computed=0x%08X\n",
                           ar.ftr.global_crc, gc);
                    errors++;
                } else {
                    printf("[ OK ] Global CRC: 0x%08X\n", gc);
                }
                free(all);
            }
            fclose(fp);
        }
    } else if (ar.hdr.flags & FL_FOOTER) {
        printf("[WARN] Footer flag set but no valid footer found\n");
        errors++;
    }

    printf("\n%s: %d error(s)\n", path, errors);
    free_archive(&ar);
    return errors ? 1 : 0;
}

/* ============================================================
 *  Usage & main
 * ============================================================ */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s generate <output.cfr>\n"
        "  %s pack [-x] <output.cfr> <file1> [...]\n"
        "  %s list <archive.cfr>\n"
        "  %s read <archive.cfr>\n"
        "  %s unpack <archive.cfr> [output_dir]\n"
        "  %s validate <archive.cfr>\n"
        "\nOptions:\n"
        "  -x   Enable XOR obfuscation on data\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "generate") == 0) {
        return cmd_generate(argv[2]);
    } else if (strcmp(cmd, "pack") == 0) {
        return cmd_pack(argc - 2, argv + 2);
    } else if (strcmp(cmd, "list") == 0) {
        return cmd_list(argv[2]);
    } else if (strcmp(cmd, "read") == 0) {
        return cmd_read(argv[2]);
    } else if (strcmp(cmd, "unpack") == 0) {
        return cmd_unpack(argv[2], argc > 3 ? argv[3] : NULL);
    } else if (strcmp(cmd, "validate") == 0) {
        return cmd_validate(argv[2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
