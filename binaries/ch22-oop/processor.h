/*
 * processor.h — Common interface for the data processing system
 *
 * Reverse Engineering Training — Chapter 22
 * MIT License — Strictly educational use
 *
 * This interface defines the contract that every processor (internal or plugin)
 * must respect. In RE, this is the interface that must be reconstructed
 * from vtables and virtual calls.
 */

#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <cstddef>
#include <cstdint>

/* --------------------------------------------------------------------
 * Abstract base class: Processor
 *
 * Memory layout (GCC / Itanium ABI, x86-64):
 *   +0x00  vptr          → points to the vtable in .rodata
 *   +0x08  id_           → uint32_t, unique identifier (4 bytes)
 *   +0x0C  priority_     → int, execution priority (4 bytes)
 *   +0x10  enabled_      → bool (1 byte)
 *   +0x11  (7B padding for struct alignment to 8)
 *   Total: 0x18 (24 bytes)
 *
 * Vtable (from vptr, GCC Itanium ABI):
 *   [0] → ~Processor() D1       (complete object destructor)
 *   [1] → ~Processor() D0       (deleting destructor)
 *   [2] → name()
 *   [3] → configure()
 *   [4] → process()
 *   [5] → status()
 * -------------------------------------------------------------------- */
class Processor {
public:
    Processor(uint32_t id, int priority)
        : id_(id), priority_(priority), enabled_(true) {}

    virtual ~Processor() {}

    /* Returns the human-readable processor name */
    virtual const char* name() const = 0;

    /* Configures the processor with a key/value pair */
    virtual bool configure(const char* key, const char* value) = 0;

    /* Processes an input buffer, writes to the output buffer.
     * Returns the number of bytes written, or -1 on error. */
    virtual int process(const char* input, size_t in_len,
                        char* output, size_t out_cap) = 0;

    /* Returns a status string (for logging) */
    virtual const char* status() const = 0;

    /* Non-virtual accessors */
    uint32_t id() const { return id_; }
    int priority() const { return priority_; }
    bool enabled() const { return enabled_; }
    void set_enabled(bool e) { enabled_ = e; }

protected:
    uint32_t id_;
    int      priority_;
    bool     enabled_;
};

/* --------------------------------------------------------------------
 * Plugin convention:
 *
 * Each plugin .so must export two C functions:
 *   - Processor* create_processor(uint32_t id)
 *   - void destroy_processor(Processor* p)
 *
 * The symbol is extern "C" to avoid name mangling.
 * -------------------------------------------------------------------- */
typedef Processor* (*create_func_t)(uint32_t id);
typedef void       (*destroy_func_t)(Processor*);

#define PLUGIN_CREATE_SYMBOL  "create_processor"
#define PLUGIN_DESTROY_SYMBOL "destroy_processor"

#endif /* PROCESSOR_H */
