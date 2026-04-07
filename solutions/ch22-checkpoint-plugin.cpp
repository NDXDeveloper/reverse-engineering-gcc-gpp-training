/*
 * solutions/ch22-checkpoint-plugin.cpp
 *
 * ⚠️  SPOILER — Chapter 22 checkpoint solution
 *
 * Reverse Engineering Training — MIT License
 *
 * This file contains:
 *   1. The reconstructed header (processor_reconstructed.h) inline
 *   2. The LeetSpeakProcessor plugin implementation
 *   3. The extern "C" factory functions
 *   4. A memory layout verification program (at end of file,
 *      compilable separately with -DCHECK_LAYOUT)
 *
 * ═══════════════════════════════════════════════════════════════════
 *  COMPLETE SOLVING APPROACH
 * ═══════════════════════════════════════════════════════════════════
 *
 * ── Step A: identify factory symbols ───────────────────────────
 *
 *   $ strings oop_O2_strip | grep -iE 'create|destroy|plugin'
 *     create_processor
 *     destroy_processor
 *     ./plugins
 *     .so
 *     [Pipeline] loading plugin: %s
 *     [Pipeline] missing symbols in %s
 *
 *   → The host expects two extern "C" symbols:
 *       Processor* create_processor(uint32_t id);
 *       void       destroy_processor(Processor* p);
 *
 *   Confirmation with ltrace:
 *   $ ltrace -e dlsym ./oop_O2_strip -p ./plugins "test" 2>&1
 *     dlsym(0x..., "create_processor")  = 0x...
 *     dlsym(0x..., "destroy_processor") = 0x...
 *
 * ── Step B: reconstruct the class hierarchy ────────────────────
 *
 *   $ strings oop_O2_strip | grep -E '^[0-9]+[A-Z]'
 *     9Processor
 *     19UpperCaseProcessor
 *     16ReverseProcessor
 *     8Pipeline
 *
 *   $ strings plugins/plugin_alpha.so | grep -E '^[0-9]+[A-Z]'
 *     15Rot13Processor
 *
 *   $ strings plugins/plugin_beta.so | grep -E '^[0-9]+[A-Z]'
 *     19XorCipherProcessor
 *
 *   $ nm -C plugins/plugin_alpha.so | grep typeinfo
 *     ... V typeinfo for Rot13Processor
 *     ... U typeinfo for Processor           ← parent = Processor
 *
 *   Hierarchy:
 *     Processor (abstract)
 *     ├── UpperCaseProcessor
 *     ├── ReverseProcessor
 *     ├── Rot13Processor       (plugin_alpha.so)
 *     └── XorCipherProcessor   (plugin_beta.so)
 *
 * ── Step C: reconstruct the vtable ─────────────────────────────
 *
 *   Method: examine the Rot13Processor vtable in Ghidra.
 *   Location: nm -C plugin_alpha.so | grep vtable
 *     → vtable for Rot13Processor at an address in .data.rel.ro
 *
 *   The vptr points after offset-to-top and typeinfo. Entries:
 *
 *   Index  Offset  Symbol (if available)                Deduced from
 *   ─────  ──────  ───────────────────────────────────  ──────────────────
 *   [0]    +0x00   ~Rot13Processor() (complete dtor)    all plugins
 *   [1]    +0x08   ~Rot13Processor() (deleting dtor)    all plugins
 *   [2]    +0x10   Rot13Processor::name()               returns "Rot13Processor"
 *   [3]    +0x18   Rot13Processor::configure()          compares "half_rot"
 *   [4]    +0x20   Rot13Processor::process()            core processing
 *   [5]    +0x28   Rot13Processor::status()             returns status string
 *
 *   Cross-verification:
 *   - The UpperCaseProcessor vtable (in oop_O0) has the same 6 slots.
 *   - The Processor vtable has __cxa_pure_virtual at slots 2–5
 *     → confirms that name/configure/process/status are pure virtual.
 *   - Slot 0/1 of Processor points to an actual destructor
 *     → the destructor is virtual but not pure.
 *
 *   Signature confirmation via disassembly:
 *   - name()      : no argument other than this (rdi), returns ptr (rax)
 *   - configure() : this(rdi), key(rsi), value(rdx), returns bool (eax)
 *   - process()   : this(rdi), input(rsi), in_len(rdx), output(rcx),
 *                    out_cap(r8), returns int (eax)
 *   - status()    : no argument other than this (rdi), returns ptr (rax)
 *
 * ── Step D: reconstruct the memory layout ──────────────────────
 *
 *   Analysis of [rdi+offset] accesses in Processor methods
 *   (observed in UpperCaseProcessor and ReverseProcessor from oop_O0):
 *
 *   Instruction observed in configure():
 *     ; No specific access to Processor fields in configure()
 *
 *   Instruction observed in process():
 *     movzx  eax, BYTE PTR [rdi+0x10]    ; test enabled_
 *     test   al, al
 *     je     .skip                         ; if (!enabled_) return -1;
 *
 *   Instruction observed in the UpperCaseProcessor constructor:
 *     lea    rax, [rip + vtable + 0x10]
 *     mov    QWORD PTR [rdi], rax          ; vptr       @ +0x00
 *     mov    DWORD PTR [rdi+0x08], esi     ; id_        @ +0x08
 *     mov    DWORD PTR [rdi+0x0C], 0x0A    ; priority_  @ +0x0C (10)
 *     mov    BYTE  PTR [rdi+0x10], 0x01    ; enabled_   @ +0x10 (true)
 *
 *   In UpperCaseProcessor::process(), specific accesses:
 *     movzx  eax, BYTE PTR [rdi+0x11]     ; skip_digits_ @ +0x11
 *
 *   In UpperCaseProcessor::status():
 *     mov    rsi, QWORD PTR [rdi+0x18]    ; bytes_processed_ @ +0x18
 *
 *   Reconstructed Processor layout (base class):
 *     +0x00  vptr          (8 bytes)
 *     +0x08  id_           (4 bytes, uint32_t)
 *     +0x0C  priority_     (4 bytes, int)
 *     +0x10  enabled_      (1 byte, bool)
 *     +0x11  (padding)     (7 bytes)
 *     Total: 0x18 = 24 bytes
 *
 *   Reconstructed UpperCaseProcessor layout:
 *     +0x00–0x17  inherited from Processor  (24 bytes)
 *       → +0x10   enabled_  (bool, 1 byte)
 *     +0x11       skip_digits_         (1 byte, bool — placed without padding after enabled_)
 *     +0x12       (padding)            (6 bytes)
 *     +0x18       bytes_processed_     (8 bytes, size_t)
 *     Total: 0x20 = 32 bytes   ← confirmed by operator new(0x20)
 *
 *   Reconstructed Rot13Processor layout (plugin_alpha.so):
 *     Observed in create_processor → operator new(0x28) → 40 bytes
 *     +0x00–0x17  inherited from Processor
 *       → +0x10   enabled_  (bool)
 *     +0x11       half_rot_            (1 byte, bool — after enabled_ without padding)
 *     +0x12       (padding)            (6 bytes)
 *     +0x18       total_rotated_       (8 bytes, size_t)
 *     +0x20       call_count_          (8 bytes, size_t)
 *     Total: 0x28 = 40 bytes  ← confirmed by operator new(0x28)
 *
 *   Reconstructed XorCipherProcessor layout (plugin_beta.so):
 *     Observed in create_processor → operator new(0x50) → 80 bytes
 *     +0x00–0x17  inherited from Processor
 *       → +0x10   enabled_  (bool)
 *     +0x11       key_[32]             (32 bytes, unsigned char[] — no alignment required)
 *     +0x31       (padding)            (7 bytes, alignment for size_t)
 *     +0x38       key_len_             (8 bytes, size_t)
 *     +0x40       printable_output_    (1 byte, bool)
 *     +0x41       (padding)            (7 bytes)
 *     +0x48       bytes_xored_         (8 bytes, size_t)
 *     Total: 0x50 = 80 bytes  ← confirmed
 *
 * ── Step E: verify the discovery contract ──────────────────────
 *
 *   The host scans a directory and filters by ".so":
 *   $ strace -e openat ./oop_O2_strip -p ./plugins "test" 2>&1 | grep plugin
 *     openat(AT_FDCWD, "./plugins", O_RDONLY|O_DIRECTORY) = 3
 *     openat(AT_FDCWD, "./plugins/plugin_alpha.so", ...) = 4
 *     openat(AT_FDCWD, "./plugins/plugin_beta.so", ...)  = 4
 *
 *   → Simply place our .so in the ./plugins/ directory.
 *   → The filename must end with ".so".
 *
 * ── Step F: compile, verify, execute ───────────────────────────
 *
 *   Compilation:
 *   $ g++ -shared -fPIC -std=c++17 -O2 \
 *         -o plugins/plugin_gamma.so ch22-checkpoint-plugin.cpp
 *
 *   Symbol verification:
 *   $ nm -CD plugins/plugin_gamma.so | grep -E 'T (create|destroy)'
 *     ... T create_processor
 *     ... T destroy_processor
 *
 *   RTTI verification:
 *   $ nm -C plugins/plugin_gamma.so | grep typeinfo
 *     ... V typeinfo for LeetSpeakProcessor
 *     ... U typeinfo for Processor             ← OK: parent as U
 *
 *   Execution:
 *   $ ./oop_O2_strip -p ./plugins "Hello World from RE"
 *     [STEP] UpperCaseProcessor → "HELLO WORLD FROM RE"
 *     [STEP] ReverseProcessor   → "ER MORF DLROW OLLEH"
 *     [STEP] Rot13Processor     → "..."
 *     [STEP] LeetSpeakProcessor → "..."           ← Our plugin
 *     [STEP] XorCipherProcessor → "..."
 *
 * ═══════════════════════════════════════════════════════════════════
 */

/* ====================================================================
 * PART 1: Reconstructed Header
 * ====================================================================
 *
 * This header is the direct product of reverse engineering.
 * It was reconstructed without access to the original processor.h file.
 *
 * Critical points to respect:
 *   - The order of virtual methods determines the vtable.
 *   - The order and type of fields determine the memory layout.
 *   - The destructor must be virtual (otherwise the vtable is shifted).
 *   - Protected fields allow access from derived classes.
 * ==================================================================== */

#ifndef CHECK_LAYOUT  /* Not included in layout verification mode */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

class Processor {
public:
    Processor(uint32_t id, int priority)
        : id_(id), priority_(priority), enabled_(true) {}

    /* Vtable slot [0] and [1] — virtual destructor (complete + deleting) */
    virtual ~Processor() {}

    /* Vtable slot [2] — returns the human-readable processor name */
    virtual const char* name() const = 0;

    /* Vtable slot [3] — configures via key/value pair */
    virtual bool configure(const char* key, const char* value) = 0;

    /* Vtable slot [4] — main processing */
    virtual int process(const char* input, size_t in_len,
                        char* output, size_t out_cap) = 0;

    /* Vtable slot [5] — status string */
    virtual const char* status() const = 0;

    /* Non-virtual accessors (often inlined at -O2) */
    uint32_t id() const { return id_; }
    int priority() const { return priority_; }
    bool enabled() const { return enabled_; }
    void set_enabled(bool e) { enabled_ = e; }

protected:
    uint32_t id_;        /* +0x08 */
    int      priority_;  /* +0x0C */
    bool     enabled_;   /* +0x10 */
    /* padding +0x11 to +0x17, total struct = 0x18 (24 bytes) */
};


/* ====================================================================
 * PART 2: Plugin Implementation
 * ====================================================================
 *
 * LeetSpeakProcessor — transforms text into "l33t sp34k".
 *
 * LeetSpeakProcessor memory layout:
 *   +0x00–0x17  inherited from Processor  (24 bytes)
 *     → +0x10   enabled_  (bool)
 *   +0x11       aggressive_          (1 byte, bool — after enabled_ without padding)
 *   +0x12       (padding)            (6 bytes)
 *   +0x18       chars_converted_     (8 bytes, size_t)
 *   Total: 0x20 = 32 bytes
 *
 * Chosen priority: 40
 *   → Inserts between Rot13Processor (30) and XorCipherProcessor (50)
 *   → Verified by the order of appearance in pipeline output
 * ==================================================================== */

class LeetSpeakProcessor : public Processor {
public:
    LeetSpeakProcessor(uint32_t id)
        : Processor(id, 40), aggressive_(false), chars_converted_(0) {}

    ~LeetSpeakProcessor() override {
        fprintf(stderr, "[LeetSpeak #%u] destroyed\n", id_);
    }

    const char* name() const override {
        return "LeetSpeakProcessor";
    }

    bool configure(const char* key, const char* value) override {
        if (strcmp(key, "aggressive") == 0) {
            aggressive_ = (strcmp(value, "true") == 0);
            return true;
        }
        return false;
    }

    int process(const char* input, size_t in_len,
                char* output, size_t out_cap) override
    {
        if (!enabled_ || !input || !output) return -1;

        size_t n = (in_len < out_cap - 1) ? in_len : out_cap - 1;

        for (size_t i = 0; i < n; i++) {
            output[i] = to_leet(input[i]);
        }
        output[n] = '\0';
        chars_converted_ += n;
        return (int)n;
    }

    const char* status() const override {
        static char buf[128];
        snprintf(buf, sizeof(buf),
                 "[LeetSpeak #%u] converted=%zu aggressive=%s",
                 id_, chars_converted_, aggressive_ ? "yes" : "no");
        return buf;
    }

private:
    bool   aggressive_;
    size_t chars_converted_;

    char to_leet(char c) const {
        switch (c) {
            case 'A': case 'a': return '4';
            case 'E': case 'e': return '3';
            case 'I': case 'i': return '1';
            case 'O': case 'o': return '0';
            case 'S': case 's': return '5';
            case 'T': case 't': return '7';
            default:
                if (aggressive_) {
                    switch (c) {
                        case 'B': case 'b': return '8';
                        case 'G': case 'g': return '9';
                        case 'L': case 'l': return '1';
                        default: return c;
                    }
                }
                return c;
        }
    }
};


/* ====================================================================
 * PART 3: Factory Functions (extern "C")
 * ====================================================================
 *
 * These two functions constitute the contract between host and plugin.
 *
 * Identified by:
 *   $ strings oop_O2_strip | grep -E 'create_processor|destroy_processor'
 *   $ ltrace -e dlsym ./oop_O2_strip -p ./plugins "test"
 *
 * The extern "C" is essential — without it, symbols are mangled
 * (e.g.: _Z16create_processorj) and dlsym cannot find them.
 * ==================================================================== */

extern "C" {

Processor* create_processor(uint32_t id) {
    fprintf(stderr, "[plugin_gamma] creating LeetSpeakProcessor id=%u\n", id);
    return new LeetSpeakProcessor(id);
}

void destroy_processor(Processor* p) {
    fprintf(stderr, "[plugin_gamma] destroying processor\n");
    delete p;
}

} /* extern "C" */


#else /* CHECK_LAYOUT — Layout verification program */


/* ====================================================================
 * PART 4: Memory Layout Verification
 * ====================================================================
 *
 * Compile separately:
 *   g++ -std=c++17 -O2 -DCHECK_LAYOUT \
 *       -o check_layout ch22-checkpoint-plugin.cpp
 *
 * Run:
 *   ./check_layout
 *
 * Expected output (must match offsets observed in the binary):
 *   sizeof(Processor)          = 24   (0x18)
 *   sizeof(LeetSpeakProcessor) = 32   (0x20)
 *   offset id_                 = 8    (0x08)
 *   offset priority_           = 12   (0x0C)
 *   offset enabled_            = 16   (0x10)
 * ==================================================================== */

#include <cstddef>
#include <cstdint>
#include <cstdio>

class Processor {
public:
    Processor(uint32_t id, int priority)
        : id_(id), priority_(priority), enabled_(true) {}
    virtual ~Processor() {}
    virtual const char* name() const = 0;
    virtual bool configure(const char* key, const char* value) = 0;
    virtual int process(const char* input, size_t in_len,
                        char* output, size_t out_cap) = 0;
    virtual const char* status() const = 0;

    /* Made public solely for offsetof() in this test */
    uint32_t id_;
    int      priority_;
    bool     enabled_;
};

class LeetSpeakProcessor : public Processor {
public:
    LeetSpeakProcessor() : Processor(0, 0), aggressive_(false), cc_(0) {}
    const char* name() const override { return ""; }
    bool configure(const char*, const char*) override { return false; }
    int process(const char*, size_t, char*, size_t) override { return 0; }
    const char* status() const override { return ""; }

    bool   aggressive_;
    size_t cc_;
};

int main() {
    printf("sizeof(Processor)          = %zu  (0x%02zx)\n",
           sizeof(Processor), sizeof(Processor));
    printf("sizeof(LeetSpeakProcessor) = %zu  (0x%02zx)\n",
           sizeof(LeetSpeakProcessor), sizeof(LeetSpeakProcessor));
    printf("offset id_                 = %zu  (0x%02zx)\n",
           offsetof(Processor, id_), offsetof(Processor, id_));
    printf("offset priority_           = %zu  (0x%02zx)\n",
           offsetof(Processor, priority_), offsetof(Processor, priority_));
    printf("offset enabled_            = %zu  (0x%02zx)\n",
           offsetof(Processor, enabled_), offsetof(Processor, enabled_));
    printf("offset aggressive_         = %zu  (0x%02zx)\n",
           offsetof(LeetSpeakProcessor, aggressive_),
           offsetof(LeetSpeakProcessor, aggressive_));
    printf("offset chars_converted_    = %zu  (0x%02zx)\n",
           offsetof(LeetSpeakProcessor, cc_),
           offsetof(LeetSpeakProcessor, cc_));

    /* Automated checks */
    int errors = 0;

    if (sizeof(Processor) != 24) {
        printf("FAIL: sizeof(Processor) should be 24\n");
        errors++;
    }
    if (offsetof(Processor, id_) != 8) {
        printf("FAIL: id_ should be at offset 8\n");
        errors++;
    }
    if (offsetof(Processor, priority_) != 12) {
        printf("FAIL: priority_ should be at offset 12\n");
        errors++;
    }
    if (offsetof(Processor, enabled_) != 16) {
        printf("FAIL: enabled_ should be at offset 16\n");
        errors++;
    }

    if (errors == 0)
        printf("\nAll layout checks PASSED.\n");
    else
        printf("\n%d layout check(s) FAILED.\n", errors);

    return errors;
}

#endif /* CHECK_LAYOUT */
