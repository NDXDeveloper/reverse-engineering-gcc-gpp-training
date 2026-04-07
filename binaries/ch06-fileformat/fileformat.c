/*
 * fileformat.c — Custom .cdb and .pkt file generator
 * Reverse Engineering Training — Chapter 6
 *
 * This program generates two proprietary data files:
 *   - sample.cdb : "Custom Database" format (practical case 6.11)
 *   - sample.pkt : "Packet Capture" format (ch. 6 checkpoint)
 *
 * These files are the analysis targets for the ImHex .hexpat
 * patterns written in chapter 6.
 *
 * Compilation: see Makefile (gcc -O0 -g for the debug version)
 * Usage: ./fileformat_O0 [--output-dir <dir>]
 *
 * MIT License — Strictly educational use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>  /* htons, htonl */

/* ================================================================
 *  SECTION 1: .cdb Format (Custom Database)
 *
 *  Structure:
 *    FileHeader (32 bytes)
 *    FieldDescriptor[] (field_count x 32 bytes)
 *    Padding (alignment up to data_offset)
 *    Record[] (record_count x record_size)
 *    Footer (12 bytes)
 * ================================================================ */

#define CDB_MAGIC           "CDB2"
#define CDB_VERSION         2
#define CDB_SUB_VERSION     1
#define CDB_FIELD_COUNT     3
#define CDB_RECORD_COUNT    5
#define CDB_HEADER_SIZE     32
#define CDB_FIELD_DESC_SIZE 32
#define CDB_FOOTER_SIZE     12

/* Max field sizes in a record */
#define FIELD_NAME_MAXSZ    20
#define FIELD_DESC_MAXSZ    40
#define FIELD_VALUE_MAXSZ   4

/* Record size = 4 (id) + 20 (name) + 40 (desc) + 4 (value) = 68 */
#define CDB_RECORD_SIZE     (4 + FIELD_NAME_MAXSZ + FIELD_DESC_MAXSZ + FIELD_VALUE_MAXSZ)

/* Field types */
#define FTYPE_STRING   0x0001
#define FTYPE_TEXT     0x0002
#define FTYPE_INTEGER  0x0003

#pragma pack(push, 1)

typedef struct {
    char     magic[4];
    uint16_t version;
    uint16_t sub_version;
    uint32_t record_count;
    uint32_t data_offset;
    uint32_t unknown_10;      /* reserved — always 1 */
    uint32_t field_count;
    uint8_t  reserved[8];
} CDB_Header;

typedef struct {
    uint16_t field_id;
    uint16_t field_type;
    char     field_name[20];
    uint32_t max_size;
    uint32_t flags;
} CDB_FieldDescriptor;

typedef struct {
    uint32_t record_id;
    char     name[FIELD_NAME_MAXSZ];
    char     description[FIELD_DESC_MAXSZ];
    uint32_t value;
} CDB_Record;

typedef struct {
    char     magic[4];
    uint32_t record_count;
    uint32_t data_end_offset;
} CDB_Footer;

#pragma pack(pop)

/* Test data for records */
static const struct {
    const char *name;
    const char *description;
    uint32_t    value;
} cdb_test_data[CDB_RECORD_COUNT] = {
    { "Alpha",   "First entry in the database",    42   },
    { "Beta",    "Second entry with more data",     128  },
    { "Gamma",   "Third entry for testing",         255  },
    { "Delta",   "Another record in the set",       1000 },
    { "Epsilon", "Final entry of the sample file",  9999 },
};

static int generate_cdb(const char *output_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/sample.cdb", output_dir);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("fopen sample.cdb");
        return -1;
    }

    /* Offset calculations */
    uint32_t descriptors_size = CDB_FIELD_COUNT * CDB_FIELD_DESC_SIZE;
    uint32_t after_descriptors = CDB_HEADER_SIZE + descriptors_size;
    /* Align data_offset to 32 bytes */
    uint32_t data_offset = (after_descriptors + 31) & ~31u;
    uint32_t padding_size = data_offset - after_descriptors;
    uint32_t data_size = CDB_RECORD_COUNT * CDB_RECORD_SIZE;
    uint32_t footer_offset = data_offset + data_size;

    /* --- Header --- */
    CDB_Header hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, CDB_MAGIC, 4);
    hdr.version      = CDB_VERSION;
    hdr.sub_version  = CDB_SUB_VERSION;
    hdr.record_count = CDB_RECORD_COUNT;
    hdr.data_offset  = data_offset;
    hdr.unknown_10   = 1;
    hdr.field_count  = CDB_FIELD_COUNT;
    fwrite(&hdr, sizeof(hdr), 1, fp);

    /* --- Field descriptors --- */
    CDB_FieldDescriptor fields[CDB_FIELD_COUNT];
    memset(fields, 0, sizeof(fields));

    fields[0].field_id   = 1;
    fields[0].field_type = FTYPE_STRING;
    strncpy(fields[0].field_name, "name", sizeof(fields[0].field_name));
    fields[0].max_size   = FIELD_NAME_MAXSZ;
    fields[0].flags      = 0x00000001;

    fields[1].field_id   = 2;
    fields[1].field_type = FTYPE_TEXT;
    strncpy(fields[1].field_name, "description", sizeof(fields[1].field_name));
    fields[1].max_size   = FIELD_DESC_MAXSZ;
    fields[1].flags      = 0x00000002;

    fields[2].field_id   = 3;
    fields[2].field_type = FTYPE_INTEGER;
    strncpy(fields[2].field_name, "value", sizeof(fields[2].field_name));
    fields[2].max_size   = FIELD_VALUE_MAXSZ;
    fields[2].flags      = 0x00000003;

    fwrite(fields, sizeof(CDB_FieldDescriptor), CDB_FIELD_COUNT, fp);

    /* --- Alignment padding --- */
    uint8_t zeros[32] = {0};
    if (padding_size > 0) {
        fwrite(zeros, 1, padding_size, fp);
    }

    /* --- Records --- */
    for (int i = 0; i < CDB_RECORD_COUNT; i++) {
        CDB_Record rec;
        memset(&rec, 0, sizeof(rec));
        rec.record_id = (uint32_t)(i + 1);
        strncpy(rec.name, cdb_test_data[i].name, FIELD_NAME_MAXSZ);
        strncpy(rec.description, cdb_test_data[i].description, FIELD_DESC_MAXSZ);
        rec.value = cdb_test_data[i].value;
        fwrite(&rec, sizeof(rec), 1, fp);
    }

    /* --- Footer --- */
    CDB_Footer ftr;
    memset(&ftr, 0, sizeof(ftr));
    memcpy(ftr.magic, "CFEO", 4);
    ftr.record_count    = CDB_RECORD_COUNT;
    ftr.data_end_offset = footer_offset;
    fwrite(&ftr, sizeof(ftr), 1, fp);

    fclose(fp);
    printf("[+] Generated %s (%u bytes)\n", path, footer_offset + CDB_FOOTER_SIZE);
    return 0;
}

/* ================================================================
 *  SECTION 2: .pkt Format (Packet Capture)
 *
 *  Structure:
 *    FileHeader (32 bytes)
 *    SessionInfo (48 bytes)
 *    Packet[] (variable) — each packet:
 *      PacketHeader (20 bytes)
 *      Payload (variable)
 *      Optional CRC32 (4 bytes if has_checksum flag)
 *    FileFooter (16 bytes)
 * ================================================================ */

#define PKT_MAGIC           "PKT"        /* followed by \0 */
#define PKT_FOOTER_MAGIC    "TKP"        /* followed by \0 */
#define PKT_FORMAT_VERSION  1
#define PKT_PROTO_VERSION   0x0100       /* version 1.0 */

/* Packet types */
#define PTYPE_HANDSHAKE_INIT  0x01
#define PTYPE_HANDSHAKE_ACK   0x02
#define PTYPE_AUTH_REQUEST     0x03
#define PTYPE_AUTH_RESPONSE    0x04
#define PTYPE_DATA_TRANSFER    0x05
#define PTYPE_DISCONNECT       0x06

/* Directions */
#define DIR_CLIENT_TO_SERVER  0x01
#define DIR_SERVER_TO_CLIENT  0x02

/* Flags */
#define PFLAG_COMPRESSED  0x01
#define PFLAG_HAS_CRC     0x02
#define PFLAG_ENCRYPTED   0x04
#define PFLAG_FRAGMENTED  0x08

/* Auth status */
#define AUTH_SUCCESS  0x00
#define AUTH_FAILURE  0x01

#pragma pack(push, 1)

typedef struct {
    char     magic[4];          /* "PKT\0" */
    uint16_t format_version;    /* LE */
    uint16_t proto_version;     /* LE (stores 0x0100) */
    uint32_t packet_count;      /* LE */
    uint32_t total_length;      /* LE */
    uint32_t data_offset;       /* LE */
    uint32_t footer_offset;     /* LE — filled in later */
    uint64_t capture_start;     /* LE — Unix timestamp */
} PKT_FileHeader;

typedef struct {
    uint8_t  client_ip[4];
    uint16_t client_port;       /* BE (network order) */
    uint8_t  pad1[2];
    uint8_t  server_ip[4];
    uint16_t server_port;       /* BE */
    uint8_t  pad2[2];
    uint64_t session_id;        /* LE */
    uint64_t capture_end;       /* LE — Unix timestamp */
    char     capture_host[16];  /* null-terminated */
} PKT_SessionInfo;

typedef struct {
    uint32_t sequence_num;      /* BE */
    uint8_t  packet_type;
    uint8_t  direction;
    uint8_t  flags;
    uint8_t  pad;
    uint32_t payload_length;    /* LE */
    uint32_t timestamp_delta;   /* LE — ms since capture_start */
} PKT_PacketHeader;

typedef struct {
    uint32_t total_payload_bytes; /* LE */
    uint32_t packet_count_check;  /* LE */
    uint32_t file_crc32;          /* LE — simplified for the tutorial */
    char     magic[4];            /* "TKP\0" */
} PKT_FileFooter;

#pragma pack(pop)

/* Simplified CRC32 (table-based) */
static uint32_t crc32_table[256];
static int crc32_table_init = 0;

static void init_crc32_table(void)
{
    if (crc32_table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_init = 1;
}

static uint32_t compute_crc32(const void *data, size_t len)
{
    init_crc32_table();
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

/* Helper: write a complete packet, returns total bytes written */
static size_t write_packet(FILE *fp, uint32_t seq, uint8_t type,
                           uint8_t dir, uint8_t flags,
                           uint32_t ts_delta,
                           const void *payload, uint32_t payload_len)
{
    PKT_PacketHeader phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.sequence_num   = htonl(seq);            /* big-endian */
    phdr.packet_type    = type;
    phdr.direction      = dir;
    phdr.flags          = flags;
    phdr.payload_length = payload_len;            /* native little-endian */
    phdr.timestamp_delta = ts_delta;

    fwrite(&phdr, sizeof(phdr), 1, fp);
    fwrite(payload, 1, payload_len, fp);

    size_t total = sizeof(phdr) + payload_len;

    /* Optional CRC */
    if (flags & PFLAG_HAS_CRC) {
        uint32_t crc = compute_crc32(payload, payload_len);
        fwrite(&crc, sizeof(crc), 1, fp);
        total += 4;
    }

    return total;
}

static int generate_pkt(const char *output_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/sample.pkt", output_dir);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("fopen sample.pkt");
        return -1;
    }

    uint64_t capture_start = 1710500000;  /* fixed timestamp for reproducibility */
    uint32_t data_offset = sizeof(PKT_FileHeader) + sizeof(PKT_SessionInfo);

    /* --- FileHeader (placeholder, we'll come back to write footer_offset) --- */
    PKT_FileHeader fhdr;
    memset(&fhdr, 0, sizeof(fhdr));
    memcpy(fhdr.magic, PKT_MAGIC, 4);     /* "PKT\0" */
    fhdr.format_version = PKT_FORMAT_VERSION;
    fhdr.proto_version  = PKT_PROTO_VERSION;
    fhdr.packet_count   = 7;               /* number of packets below */
    fhdr.total_length   = 0;               /* filled in later */
    fhdr.data_offset    = data_offset;
    fhdr.footer_offset  = 0;               /* filled in later */
    fhdr.capture_start  = capture_start;
    fwrite(&fhdr, sizeof(fhdr), 1, fp);

    /* --- SessionInfo --- */
    PKT_SessionInfo sess;
    memset(&sess, 0, sizeof(sess));
    sess.client_ip[0] = 192; sess.client_ip[1] = 168;
    sess.client_ip[2] = 1;   sess.client_ip[3] = 10;
    sess.client_port   = htons(54321);
    sess.server_ip[0] = 10;  sess.server_ip[1] = 0;
    sess.server_ip[2] = 0;   sess.server_ip[3] = 1;
    sess.server_port   = htons(8443);
    sess.session_id    = 0xDEADBEEFCAFE0001ULL;
    sess.capture_end   = capture_start + 3600;
    strncpy(sess.capture_host, "re-lab-vm", sizeof(sess.capture_host));
    fwrite(&sess, sizeof(sess), 1, fp);

    /* --- Packets --- */
    uint32_t total_payload = 0;
    uint32_t seq = 1;

    /* Packet 1: HANDSHAKE_INIT (client → server) — 20 bytes payload */
    {
        uint8_t payload[20];
        memset(payload, 0, sizeof(payload));
        uint16_t pv = htons(0x0100);
        memcpy(payload, &pv, 2);
        /* nonce: 16 pseudo-random bytes */
        uint8_t nonce[16] = {
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
        };
        memcpy(payload + 2, nonce, 16);
        /* 2 padding bytes already zero */
        write_packet(fp, seq++, PTYPE_HANDSHAKE_INIT,
                     DIR_CLIENT_TO_SERVER, 0x00, 0, payload, 20);
        total_payload += 20;
    }

    /* Packet 2: HANDSHAKE_ACK (server → client) — 22 bytes payload, with CRC */
    {
        uint8_t payload[22];
        memset(payload, 0, sizeof(payload));
        uint16_t pv = htons(0x0100);
        memcpy(payload, &pv, 2);
        uint8_t server_nonce[16] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        memcpy(payload + 2, server_nonce, 16);
        uint32_t token = htonl(0xCAFEBABE);
        memcpy(payload + 18, &token, 4);
        write_packet(fp, seq++, PTYPE_HANDSHAKE_ACK,
                     DIR_SERVER_TO_CLIENT, PFLAG_HAS_CRC, 50, payload, 22);
        total_payload += 22;
    }

    /* Packet 3: AUTH_REQUEST (client → server) — 64 bytes payload, with CRC */
    {
        uint8_t payload[64];
        memset(payload, 0, sizeof(payload));
        strncpy((char *)payload, "admin", 32);
        /* Fake SHA-256 hash of the password */
        uint8_t fake_hash[32] = {
            0x5E, 0x88, 0x48, 0x98, 0xDA, 0x28, 0x04, 0x71,
            0x51, 0xD0, 0xE5, 0x6F, 0x8D, 0xC6, 0x29, 0x27,
            0x73, 0x60, 0x3D, 0x0D, 0x6A, 0xAB, 0xBD, 0xD6,
            0x2A, 0x11, 0xEF, 0x72, 0x1D, 0x15, 0x42, 0xD8
        };
        memcpy(payload + 32, fake_hash, 32);
        write_packet(fp, seq++, PTYPE_AUTH_REQUEST,
                     DIR_CLIENT_TO_SERVER, PFLAG_HAS_CRC, 120, payload, 64);
        total_payload += 64;
    }

    /* Packet 4: AUTH_RESPONSE (server → client) — 40 bytes payload */
    {
        uint8_t payload[40];
        memset(payload, 0, sizeof(payload));
        payload[0] = AUTH_SUCCESS;
        /* padding[3] already zero */
        uint32_t uid = htonl(1001);
        memcpy(payload + 4, &uid, 4);
        strncpy((char *)payload + 8, "Welcome, admin!", 32);
        write_packet(fp, seq++, PTYPE_AUTH_RESPONSE,
                     DIR_SERVER_TO_CLIENT, 0x00, 250, payload, 40);
        total_payload += 40;
    }

    /* Packet 5: DATA_TRANSFER (client → server) — 36 bytes payload, with CRC */
    {
        uint8_t payload[36];
        memset(payload, 0, sizeof(payload));
        uint16_t dt = htons(0x0001);   /* data_type */
        memcpy(payload, &dt, 2);
        uint16_t frag = htons(0x0000); /* fragment_id */
        memcpy(payload + 2, &frag, 2);
        /* Body: simulated application data */
        const char *app_data = "GET /api/v1/status HTTP/1.1";
        memcpy(payload + 4, app_data, strlen(app_data));
        write_packet(fp, seq++, PTYPE_DATA_TRANSFER,
                     DIR_CLIENT_TO_SERVER, PFLAG_HAS_CRC, 500, payload, 36);
        total_payload += 36;
    }

    /* Packet 6: DATA_TRANSFER (server → client) — 48 bytes, with CRC */
    {
        uint8_t payload[48];
        memset(payload, 0, sizeof(payload));
        uint16_t dt = htons(0x0002);   /* data_type = response */
        memcpy(payload, &dt, 2);
        uint16_t frag = htons(0x0000);
        memcpy(payload + 2, &frag, 2);
        const char *resp = "{\"status\":\"ok\",\"uptime\":86400}";
        memcpy(payload + 4, resp, strlen(resp));
        write_packet(fp, seq++, PTYPE_DATA_TRANSFER,
                     DIR_SERVER_TO_CLIENT, PFLAG_HAS_CRC, 620, payload, 48);
        total_payload += 48;
    }

    /* Packet 7: DISCONNECT (client → server) — 32 bytes payload */
    {
        uint8_t payload[32];
        memset(payload, 0, sizeof(payload));
        uint16_t reason = htons(0x0000);  /* normal disconnect */
        memcpy(payload, &reason, 2);
        strncpy((char *)payload + 2, "Client closing connection", 30);
        write_packet(fp, seq++, PTYPE_DISCONNECT,
                     DIR_CLIENT_TO_SERVER, 0x00, 3500, payload, 32);
        total_payload += 32;
    }

    /* --- Footer --- */
    uint32_t footer_pos = (uint32_t)ftell(fp);
    PKT_FileFooter fftr;
    memset(&fftr, 0, sizeof(fftr));
    fftr.total_payload_bytes = total_payload;
    fftr.packet_count_check  = fhdr.packet_count;
    fftr.file_crc32          = 0;  /* placeholder — computed after */
    memcpy(fftr.magic, PKT_FOOTER_MAGIC, 4);
    fwrite(&fftr, sizeof(fftr), 1, fp);

    uint32_t total_file_size = footer_pos + sizeof(PKT_FileFooter);

    /* --- Go back to header to fill in footer_offset and total_length --- */
    fseek(fp, 0, SEEK_SET);
    fhdr.footer_offset = footer_pos;
    fhdr.total_length  = total_file_size;
    fwrite(&fhdr, sizeof(fhdr), 1, fp);

    /* --- Compute CRC32 of the file (excluding footer) and write it --- */
    fseek(fp, 0, SEEK_SET);
    uint8_t *file_buf = (uint8_t *)malloc(footer_pos);
    if (file_buf) {
        fread(file_buf, 1, footer_pos, fp);
        uint32_t file_crc = compute_crc32(file_buf, footer_pos);
        free(file_buf);
        /* Write the CRC in the footer (offset footer_pos + 8) */
        fseek(fp, footer_pos + 8, SEEK_SET);
        fwrite(&file_crc, sizeof(file_crc), 1, fp);
    }

    fclose(fp);
    printf("[+] Generated %s (%u bytes, %u packets)\n",
           path, total_file_size, fhdr.packet_count);
    return 0;
}

/* ================================================================
 *  MAIN
 * ================================================================ */

int main(int argc, char *argv[])
{
    const char *output_dir = ".";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output-dir") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        }
    }

    printf("[*] Generating sample files in '%s'\n", output_dir);

    if (generate_cdb(output_dir) != 0) {
        fprintf(stderr, "[-] Failed to generate .cdb file\n");
        return 1;
    }

    if (generate_pkt(output_dir) != 0) {
        fprintf(stderr, "[-] Failed to generate .pkt file\n");
        return 1;
    }

    printf("[*] Done. Use ImHex to analyze the generated files.\n");
    return 0;
}
