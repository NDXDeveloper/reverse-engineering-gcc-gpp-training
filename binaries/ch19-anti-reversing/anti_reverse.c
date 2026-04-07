/*
 * anti_reverse.c — Chapter 19 training binary
 * Reverse Engineering Training — GNU Toolchain
 *
 * This program implements a crackme protected by multiple layers
 * of anti-reverse engineering techniques:
 *
 *   1. Debugger detection via ptrace (section 19.7)
 *   2. Debugger detection via /proc/self/status (section 19.7)
 *   3. Timing check to detect single-stepping (section 19.7)
 *   4. Scanning for int3 (0xCC) instructions in own code (section 19.8)
 *   5. Integrity check (checksum) on the .text section (section 19.8)
 *   6. Compilable with various protections: canary, PIE, RELRO (sections 19.5-19.6)
 *   7. Strippable and packable via the Makefile (sections 19.1-19.2)
 *
 * The secret: the password is derived from an XOR on an encoded string.
 *
 * Compilation: see the associated Makefile.
 *
 * Strictly educational use — MIT License
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>

/* ═══════════════════════════════════════════════════════
 * CONFIGURATION — enable/disable each protection
 * via -D flags at compilation time (see Makefile)
 * ═══════════════════════════════════════════════════════ */

/* Default values if not defined by the Makefile */
#ifndef ENABLE_PTRACE_CHECK
#define ENABLE_PTRACE_CHECK 1
#endif

#ifndef ENABLE_PROCFS_CHECK
#define ENABLE_PROCFS_CHECK 1
#endif

#ifndef ENABLE_TIMING_CHECK
#define ENABLE_TIMING_CHECK 1
#endif

#ifndef ENABLE_INT3_SCAN
#define ENABLE_INT3_SCAN 1
#endif

#ifndef ENABLE_CHECKSUM
#define ENABLE_CHECKSUM 1
#endif

/* ═══════════════════════════════════════════
 * Encoded data — the "hidden" password
 * ═══════════════════════════════════════════ */

/*
 * The plaintext password is: "R3vers3!"
 * It is stored XORed with key 0x5A so it does not
 * appear directly in `strings`.
 */
static const uint8_t encoded_pass[] = {
    0x08, /* 'R' ^ 0x5A */
    0x69, /* '3' ^ 0x5A */
    0x2C, /* 'v' ^ 0x5A */
    0x3F, /* 'e' ^ 0x5A */
    0x28, /* 'r' ^ 0x5A */
    0x29, /* 's' ^ 0x5A */
    0x69, /* '3' ^ 0x5A */
    0x73, /* '!' ^ 0x5A */
};

#define PASS_LEN (sizeof(encoded_pass))
#define XOR_KEY  0x5A

/* ═══════════════════════════════════════════
 * Intentionally vague error messages
 * ═══════════════════════════════════════════ */
static const char *msg_env_error  = "Error: non-compliant environment.\n";
static const char *msg_integrity  = "Error: integrity compromised.\n";

/* ═══════════════════════════════════════════
 * PROTECTION 1 — ptrace detection
 * Section 19.7
 *
 * Principle: a process can only be ptraced by a single
 * parent. If PTRACE_TRACEME fails, a debugger is
 * already attached.
 * ═══════════════════════════════════════════ */
static int check_ptrace(void)
{
#if ENABLE_PTRACE_CHECK
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1; /* debugger detected */
    }
    /* Detach immediately to not block potential
     * subsequent fork() calls */
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
#endif
    return 0;
}

/* ═══════════════════════════════════════════
 * PROTECTION 2 — /proc/self/status reading
 * Section 19.7
 *
 * Principle: the TracerPid field in /proc/self/status
 * indicates the PID of the process tracing us. If it is
 * non-zero, a debugger is attached.
 * ═══════════════════════════════════════════ */
static int check_procfs(void)
{
#if ENABLE_PROCFS_CHECK
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp)
        return 0; /* no procfs = let it pass */

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            fclose(fp);
            return (pid != 0) ? 1 : 0;
        }
    }
    fclose(fp);
#endif
    return 0;
}

/* ═══════════════════════════════════════════
 * PROTECTION 3 — Timing check
 * Section 19.7
 *
 * Principle: measure the execution time of a trivial
 * block. Under a debugger (single-step), this time
 * explodes. Threshold: 50 ms for an instant operation.
 * ═══════════════════════════════════════════ */
static int check_timing(void)
{
#if ENABLE_TIMING_CHECK
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Trivial block — should take < 1 ms */
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);

    long elapsed_ms = (t2.tv_sec - t1.tv_sec) * 1000 +
                      (t2.tv_nsec - t1.tv_nsec) / 1000000;

    if (elapsed_ms > 50) {
        return 1; /* abnormally slow execution */
    }
#endif
    return 0;
}

/* ═══════════════════════════════════════════
 * PROTECTION 4 — int3 (0xCC) scanning
 * Section 19.8
 *
 * Principle: when GDB sets a software breakpoint,
 * it writes the 0xCC (int3) opcode at the beginning
 * of the targeted instruction. We scan our own code
 * to detect these bytes.
 *
 * Note: we scan verify_password since it is the
 * most likely breakpoint target.
 * ═══════════════════════════════════════════ */

/* Forward declaration — defined below */
static int verify_password(const char *input);

static int scan_int3(void)
{
#if ENABLE_INT3_SCAN
    const uint8_t *fn_ptr = (const uint8_t *)verify_password;

    /*
     * Scan the first 128 bytes of verify_password.
     * We look for 0xCC that is not part of legitimate code.
     * Note: 0xCC can legitimately appear in operands, but
     * rarely at the start of an instruction in typical GCC code.
     */
    for (int i = 0; i < 128; i++) {
        if (fn_ptr[i] == 0xCC) {
            return 1; /* breakpoint detected */
        }
    }
#endif
    return 0;
}

/* ═══════════════════════════════════════════
 * PROTECTION 5 — Code checksum
 * Section 19.8
 *
 * Principle: compute a simple hash over the bytes
 * of verify_password. If the code has been patched
 * (e.g. a NOP over a jz/jnz), the checksum changes.
 *
 * The expected checksum is computed at first non-debugged
 * execution and hardcoded. In practice, the Makefile could
 * inject the correct value; here we use a simplified
 * dynamic computation for the demo.
 * ═══════════════════════════════════════════ */

/* Size of the block to verify */
#define CHECKSUM_LEN 64

static uint32_t compute_checksum(const uint8_t *ptr, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (sum << 3) | (sum >> 29); /* rotation */
        sum ^= ptr[i];
    }
    return sum;
}

/*
 * The expected checksum is stored here.
 * Value 0 = disabled (first compilation).
 * The Makefile post-build script can patch this value.
 */
static volatile uint32_t expected_checksum = 0;

static int check_code_integrity(void)
{
#if ENABLE_CHECKSUM
    if (expected_checksum == 0)
        return 0; /* checksum not initialized, skip */

    uint32_t actual = compute_checksum(
        (const uint8_t *)verify_password, CHECKSUM_LEN);

    if (actual != expected_checksum) {
        return 1; /* code modified */
    }
#endif
    return 0;
}

/* ═══════════════════════════════════════════
 * Password verification routine
 *
 * This is the reverse engineer's main target.
 * The password is decoded in memory via XOR,
 * compared character by character (no strcmp
 * to avoid trivial hooking).
 * ═══════════════════════════════════════════ */
static int verify_password(const char *input)
{
    if (strlen(input) != PASS_LEN)
        return 0;

    /* Decode the password in memory */
    char decoded[PASS_LEN + 1];
    for (size_t i = 0; i < PASS_LEN; i++) {
        decoded[i] = (char)(encoded_pass[i] ^ XOR_KEY);
    }
    decoded[PASS_LEN] = '\0';

    /* Character-by-character comparison
     * (avoids being able to hook strcmp/memcmp) */
    int result = 1;
    for (size_t i = 0; i < PASS_LEN; i++) {
        if (input[i] != decoded[i]) {
            result = 0;
            /* We do NOT exit immediately to avoid
             * a timing side-channel (always traverse
             * the entire string) */
        }
    }

    /* Clear the decoded password from memory */
    explicit_bzero(decoded, sizeof(decoded));

    return result;
}

/* ═══════════════════════════════════════════
 * SIGTRAP handler — bonus protection
 * Section 19.8
 *
 * If someone sends a SIGTRAP (or if int3 is executed
 * outside a debugger), we catch it instead of crashing,
 * which disrupts the debugger.
 * ═══════════════════════════════════════════ */
static volatile int trap_detected = 0;

static void sigtrap_handler(int sig)
{
    (void)sig;
    trap_detected = 1;
}

/* ═══════════════════════════════════════════
 * Entry point
 * ═══════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    /* Install SIGTRAP handler */
    signal(SIGTRAP, sigtrap_handler);

    /* ── Layer 1: ptrace detection ── */
    if (check_ptrace()) {
        fprintf(stderr, "%s", msg_env_error);
        return 1;
    }

    /* ── Layer 2: /proc/self/status detection ── */
    if (check_procfs()) {
        fprintf(stderr, "%s", msg_env_error);
        return 1;
    }

    /* ── Layer 3: timing check ── */
    if (check_timing()) {
        fprintf(stderr, "%s", msg_env_error);
        return 1;
    }

    /* ── Layer 4: int3 scan ── */
    if (scan_int3()) {
        fprintf(stderr, "%s", msg_integrity);
        return 1;
    }

    /* ── Layer 5: code integrity ── */
    if (check_code_integrity()) {
        fprintf(stderr, "%s", msg_integrity);
        return 1;
    }

    /* ── Main logic ── */
    printf("=== Crackme Chapter 19 ===\n");
    printf("Password: ");
    fflush(stdout);

    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        return 1;
    }

    /* Remove the newline */
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    if (verify_password(input)) {
        printf(">>> Access granted. Well done!\n");
        printf(">>> Flag: CTF{ant1_r3v3rs3_byp4ss3d}\n");
        return 0;
    } else {
        printf(">>> Incorrect password.\n");
        return 1;
    }
}
