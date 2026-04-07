/*
 * plugin_alpha.cpp — Plugin "ROT13 Processor"
 *
 * Reverse Engineering Training — Chapter 22
 * MIT License — Strictly educational use
 *
 * This plugin applies ROT13 encryption on alphabetic characters.
 * It is dynamically loaded by the main application via dlopen/dlsym.
 *
 * Exported symbols (extern "C"):
 *   - Processor* create_processor(uint32_t id)
 *   - void destroy_processor(Processor* p)
 *
 * In RE, this .so will be analyzed separately. The student must:
 *   1. Identify factory symbols with nm -CD
 *   2. Find the Rot13Processor class and its vtable
 *   3. Understand that this class inherits from Processor (same interface)
 */

#include "processor.h"

#include <cctype>
#include <cstdio>
#include <cstring>

class Rot13Processor : public Processor {
public:
    Rot13Processor(uint32_t id)
        : Processor(id, 30), half_rot_(false) {}

    ~Rot13Processor() override {
        fprintf(stderr, "[ROT13 #%u] destroyed\n", id_);
    }

    const char* name() const override {
        return "Rot13Processor";
    }

    bool configure(const char* key, const char* value) override {
        /* "half_rot" → ROT6 instead of ROT13 (for variety) */
        if (strcmp(key, "half_rot") == 0) {
            half_rot_ = (strcmp(value, "true") == 0);
            return true;
        }
        return false;
    }

    int process(const char* input, size_t in_len,
                char* output, size_t out_cap) override
    {
        if (!enabled_ || !input || !output) return -1;

        int shift = half_rot_ ? 6 : 13;
        size_t n = (in_len < out_cap - 1) ? in_len : out_cap - 1;

        for (size_t i = 0; i < n; i++) {
            char c = input[i];
            if (c >= 'a' && c <= 'z')
                output[i] = 'a' + (c - 'a' + shift) % 26;
            else if (c >= 'A' && c <= 'Z')
                output[i] = 'A' + (c - 'A' + shift) % 26;
            else
                output[i] = c;
        }
        output[n] = '\0';
        total_rotated_ += n;
        call_count_++;
        return (int)n;
    }

    const char* status() const override {
        static char buf[128];
        snprintf(buf, sizeof(buf),
                 "[ROT13 #%u] rotated=%zu calls=%zu half=%s",
                 id_, total_rotated_, call_count_,
                 half_rot_ ? "yes" : "no");
        return buf;
    }

private:
    bool   half_rot_;
    size_t total_rotated_ = 0;
    size_t call_count_    = 0;
};

/* === Factory functions (extern "C" to avoid mangling) === */

extern "C" {

Processor* create_processor(uint32_t id) {
    fprintf(stderr, "[plugin_alpha] creating Rot13Processor with id=%u\n", id);
    return new Rot13Processor(id);
}

void destroy_processor(Processor* p) {
    fprintf(stderr, "[plugin_alpha] destroying processor\n");
    delete p;
}

} /* extern "C" */
