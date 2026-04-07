🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Write a Compatible `.so` Plugin That Integrates into the Application Without the Sources

> **Objective**: validate all the skills from chapter 22 by producing a functional plugin for `oop_O2_strip` — the optimized and stripped binary, without access to source files.  
> **Deliverable**: a `plugin_gamma.so` file that is discovered, loaded, and executed by the pipeline alongside `plugin_alpha.so` and `plugin_beta.so`.  
> **Estimated time**: 45–90 minutes depending on comfort level with the tools.

---

## Context

You are working solely from the `oop_O2_strip` binary and the two compiled plugins (`plugin_alpha.so`, `plugin_beta.so`). You have no access to the source code, nor to the `processor.h` header. Your mission is to reconstruct enough information about the `Processor` interface to write a third-party plugin that integrates into the pipeline without errors.

This checkpoint mobilizes all four sections of the chapter:

- **22.1** — Reconstruct the class hierarchy and the memory layout of `Processor`.  
- **22.2** — Identify the plugin contract (`dlopen`/`dlsym`, factory symbols, instantiation convention).  
- **22.3** — Understand virtual dispatch to implement virtual methods in the correct order.  
- **22.4** — Use `LD_PRELOAD` or other dynamic techniques to validate hypotheses along the way.

---

## Phase 1 — Reconstructing the plugin interface contract

The first step is to answer three questions without opening any code editor:

1. **What symbols does the host binary expect from a plugin?**  
2. **What is the signature of each factory symbol?**  
3. **What interface must the returned object implement?**

### 1.1 — Identifying factory symbols

The strings passed to `dlsym` are stored in plaintext in `.rodata`. Even on a stripped binary, they are accessible:

```bash
$ strings oop_O2_strip | grep -iE 'create|destroy|processor|plugin'
```

You should find the two symbol names: `create_processor` and `destroy_processor`. Confirm with `ltrace`:

```bash
$ ltrace -e dlsym ./oop_O2_strip -p ./plugins "test" 2>&1 | grep dlsym
```

The `dlsym(handle, "create_processor")` and `dlsym(handle, "destroy_processor")` calls confirm the exact names.

### 1.2 — Determining factory signatures

Analyze an existing plugin to recover the prototypes. `plugin_alpha.so` has its symbols:

```bash
$ nm -CD plugins/plugin_alpha.so | grep -E 'create|destroy'
0000000000001200 T create_processor
0000000000001280 T destroy_processor
```

Open `create_processor` in Ghidra (or `objdump -d -M intel`) and observe:

- **The argument**: a single parameter arrives in `rdi` (System V convention). The code passes it to the class constructor — it is an integer (the ID). The type is `uint32_t` based on usage (stored on 32 bits in the object).  
- **The return value**: `rax` contains the result of `operator new` followed by the constructor. It is a pointer to an object — a `Processor*`.

For `destroy_processor`: a single argument in `rdi` (the pointer to the object), no return value. The body calls the destructor then `operator delete`.

Reconstructed signatures:

```c
extern "C" Processor* create_processor(uint32_t id);  
extern "C" void destroy_processor(Processor* p);  
```

### 1.3 — Reconstructing the `Processor` interface

This is the most substantial step. You need to recover the `Processor` vtable and the memory layout of objects.

**From RTTI strings** of `oop_O2_strip`:

```bash
$ strings oop_O2_strip | grep -E '^[0-9]+[A-Z]'
```

You identify `9Processor`, `19UpperCaseProcessor`, `16ReverseProcessor`. The `__cxa_pure_virtual` entry in the `Processor` vtable confirms the pure virtual methods.

**From a plugin's vtable** — open the `Rot13Processor` vtable in `plugin_alpha.so` (technique from section 22.1). Count the entries:

| Index | Offset | Method (deduced from analysis) |  
|-------|--------|-------------------------------|  
| 0 | `+0x00` | Destructor (complete) |  
| 1 | `+0x08` | Destructor (deleting) |  
| 2 | `+0x10` | `name()` — returns `const char*` |  
| 3 | `+0x18` | `configure()` — takes 2 `const char*`, returns `bool` |  
| 4 | `+0x20` | `process()` — takes `const char*`, `size_t`, `char*`, `size_t`, returns `int` |  
| 5 | `+0x28` | `status()` — returns `const char*` |

Confirm by cross-referencing with the `XorCipherProcessor` vtable in `plugin_beta.so` — same number of entries, same offsets, same calling conventions.

**From the memory layout** — examine the `[rdi+offset]` accesses in each plugin's methods and in the host binary's internal classes. The offsets common to all classes give you the fields inherited from `Processor`:

| Offset | Size | Deduced field |  
|--------|--------|-------------|  
| `+0x00` | 8 | vptr |  
| `+0x08` | 4 | id (uint32_t) |  
| `+0x0C` | 4 | priority (int) |  
| `+0x10` | 1 | enabled (bool) |  
| `+0x11`–`+0x17` | 7 | padding |

The base size is therefore 0x18 (24 bytes). Each derived class adds its own fields after `enabled_`. Note: a `bool` in a subclass can be placed directly at `+0x11` (after `enabled_` at `+0x10`) without intermediate padding, since `bool` requires only 1-byte alignment.

---

## Phase 2 — Writing the reconstructed header

From the information in phase 1, write a minimal header that will allow you to compile a compatible plugin:

```cpp
/* processor_reconstructed.h
 *
 * Header reconstructed by reverse engineering of oop_O2_strip
 * and plugins plugin_alpha.so / plugin_beta.so.
 *
 * No access to the original source code.
 */

#ifndef PROCESSOR_RECONSTRUCTED_H
#define PROCESSOR_RECONSTRUCTED_H

#include <cstddef>
#include <cstdint>

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

    uint32_t id() const { return id_; }
    int priority() const { return priority_; }
    bool enabled() const { return enabled_; }
    void set_enabled(bool e) { enabled_ = e; }

protected:
    uint32_t id_;
    int      priority_;
    bool     enabled_;
};

#endif
```

> ⚠️ **The order of virtual methods is critical.** The vtable is built in declaration order. If you declare `configure()` before `name()`, your vtable will be incompatible and the program will crash by calling the wrong method through the wrong slot. This is where your section 22.1 analysis (vtable reconstruction) is directly put to the test.

### Layout verification

Compile a minimal test program to verify that your header produces the same memory layout as the original binary:

```cpp
// check_layout.cpp
#include "processor_reconstructed.h"
#include <cstdio>
#include <cstddef>

class DummyProcessor : public Processor {  
public:  
    DummyProcessor() : Processor(0, 0) {}
    const char* name() const override { return "dummy"; }
    bool configure(const char*, const char*) override { return false; }
    int process(const char*, size_t, char*, size_t) override { return 0; }
    const char* status() const override { return "ok"; }
};

int main() {
    printf("sizeof(Processor)      = %zu\n", sizeof(Processor));
    printf("sizeof(DummyProcessor) = %zu\n", sizeof(DummyProcessor));

    DummyProcessor d;
    char* base = (char*)&d;
    printf("offset vptr     = %zu\n", (size_t)0);  /* always 0 */
    printf("offset id_      = %zu\n", offsetof(DummyProcessor, id_));
    printf("offset priority = %zu\n", offsetof(DummyProcessor, priority_));
    printf("offset enabled  = %zu\n", offsetof(DummyProcessor, enabled_));
    return 0;
}
```

```bash
$ g++ -std=c++17 -O2 -o check_layout check_layout.cpp
$ ./check_layout
sizeof(Processor)      = 24  
sizeof(DummyProcessor) = 24  
offset id_      = 8  
offset priority = 12  
offset enabled  = 16  
```

If these values match what you observed in the binary (section 22.1 and phase 1), your header is correct. If a value differs, revisit the field order or a member's type — an `int64_t` instead of an `int` would shift everything that follows.

---

## Phase 3 — Implementing the plugin

With the verified header, write your plugin. The processor implementation itself is free — what matters for compatibility is respecting the interface and the plugin convention. Here is an example "LeetSpeak" processor that transforms text into l33t speak:

```cpp
/* plugin_gamma.cpp
 *
 * "LeetSpeak" plugin for ch22-oop.
 * Compiled from a reconstructed header, without access to original sources.
 *
 * Compile:
 *   g++ -shared -fPIC -std=c++17 -O2 -o plugin_gamma.so plugin_gamma.cpp
 */

#include "processor_reconstructed.h"

#include <cstdio>
#include <cstring>

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

/* ── Factory extern "C": contract identified in phase 1 ── */

extern "C" {

Processor* create_processor(uint32_t id) {
    fprintf(stderr, "[plugin_gamma] creating LeetSpeakProcessor id=%u\n", id);
    return new LeetSpeakProcessor(id);
}

void destroy_processor(Processor* p) {
    fprintf(stderr, "[plugin_gamma] destroying processor\n");
    delete p;
}

}
```

### Compilation

```bash
$ g++ -shared -fPIC -std=c++17 -O2 -o plugins/plugin_gamma.so plugin_gamma.cpp
```

The `-fPIC` flag is mandatory for a shared object. The `-std=c++17` option ensures compatibility with the host binary (compiled with the same standard). The `-O2` flag is not functionally necessary but produces code comparable to the other plugins for analysis.

> ⚠️ **`-rdynamic` is not needed here.** This flag concerns the host executable (to export its symbols to plugins). The plugin itself does not need to make its internal symbols visible to the host — only the two `extern "C"` functions must be exported, which is the default behavior.

---

## Phase 4 — Pre-execution verification

Before launching the binary, perform a series of static checks to maximize the chances of first-run success.

### 4.1 — Verify exported symbols

```bash
$ nm -CD plugins/plugin_gamma.so | grep -E 'create|destroy'
0000000000001200 T create_processor
0000000000001260 T destroy_processor
```

Both symbols are present, exported (`T`), and unmangled (no `_Z` — the `extern "C"` works). If you see a mangled symbol like `_Z16create_processorj`, the `extern "C"` is missing or misplaced.

### 4.2 — Verify RTTI and vtable

```bash
$ nm -C plugins/plugin_gamma.so | grep -E 'vtable|typeinfo'
```

You should see:

```
0000000000003d00 V vtable for LeetSpeakProcessor
0000000000003d50 V typeinfo for LeetSpeakProcessor
0000000000003d68 V typeinfo name for LeetSpeakProcessor
                 U typeinfo for Processor
                 U vtable for __cxa_pure_virtual
```

The `U` (undefined) before `typeinfo for Processor` is normal — this symbol will be resolved at load time by the dynamic linker, from the host executable (which exports it thanks to `-rdynamic`). If this symbol does not appear as undefined, your `LeetSpeakProcessor` does not recognize `Processor` as its parent — check the inheritance.

### 4.3 — Compare vtable structure

Examine your plugin's vtable and compare it with `plugin_alpha.so`'s:

```bash
$ objdump -d -M intel --section=.text plugins/plugin_gamma.so | head -100
```

Or in Ghidra, verify that your vtable has the same number of entries in the same order as `Rot13Processor`'s. The first two entries must be the two destructor variants, followed by `name`, `configure`, `process`, `status`.

### 4.4 — Verify ABI compatibility

```bash
$ readelf -h plugins/plugin_gamma.so | grep -E 'Class|Machine'
  Class:                             ELF64
  Machine:                           Advanced Micro Devices X86-64

$ readelf -h oop_O2_strip | grep -E 'Class|Machine'
  Class:                             ELF64
  Machine:                           Advanced Micro Devices X86-64
```

Both must match: same class (ELF64), same architecture (x86-64).

---

## Phase 5 — Execution and validation

### 5.1 — First launch

```bash
$ ./oop_O2_strip -p ./plugins "Hello World from RE"
```

If everything is correct, the output should show your processor in the pipeline:

```
[Pipeline] loading plugin: ./plugins/plugin_gamma.so
[plugin_gamma] creating LeetSpeakProcessor id=3
[Pipeline] loaded: ./plugins/plugin_gamma.so (name=LeetSpeakProcessor, id=3, priority=40)
...
=== Pipeline Start ===
Input: "Hello World from RE"

[STEP] UpperCaseProcessor        → "HELLO WORLD FROM RE"
[STEP] ReverseProcessor          → "ER MORF DLROW OLLEH"
[STEP] Rot13Processor            → "RE ZBES QYJBJ BYYRU"
[STEP] LeetSpeakProcessor        → "R3 Z835 QYJ8J 8YYRU"
[STEP] XorCipherProcessor        → "..."

Output: "..."
=== Pipeline End ===

--- Status ---
  [UpperCase #0] processed=19 skip_digits=no
  [Reverse #0] chunks=1 word_mode=no
  [ROT13 #1] rotated=19 half=no
  [LeetSpeak #3] converted=19 aggressive=no
  [XorCipher #2] xored=19 key=42 printable=yes
--------------
```

Your plugin appears between `Rot13Processor` (priority 30) and `XorCipherProcessor` (priority 50), in accordance with its priority of 40. The priority-based sorting — which you observed in virtual dispatch (section 22.3) — places your processor at the right position in the chain.

### 5.2 — Troubleshooting on failure

**Segfault at loading** — The vtable is probably incompatible. Common causes:

- Virtual methods declared in the wrong order → vtable slots are shifted → the host calls `name()` but lands on `configure()`.  
- Non-virtual destructor → slot 0 of the vtable does not contain the expected destructor.  
- Missing or incorrectly sized field in the base class → member offsets are shifted → the host reads `priority_` where `enabled_` is located.

To diagnose, launch under GDB:

```bash
$ gdb -q --args ./oop_O2_strip -p ./plugins "test"
(gdb) run
```

On segfault, examine the backtrace (`bt`), the faulting instruction (`x/i $rip`), and the registers. If the crash is on a `call [rax+0xNN]`, compare the offset with your vtable table — an unexpected offset reveals a shift.

**Plugin loaded but no output** — Verify that `process()` returns a positive byte count (not 0, not -1). The pipeline interprets a negative value as an error and stops. Also check that `enabled_` is initialized to `true` in the constructor — if it is `false`, the pipeline skips your processor.

**"missing symbols"** — The message `[Pipeline] missing symbols in plugin_gamma.so` indicates that `dlsym` did not find `create_processor` or `destroy_processor`. Check with `nm -CD` that the symbols are properly exported and unmangled.

### 5.3 — Dynamic validation with `LD_PRELOAD`

Use the `operator new` interception library (section 22.4) to verify that your object is allocated with the expected size:

```bash
$ LD_PRELOAD=./preload_new.so ./oop_O2_strip -p ./plugins "test"
```

If your `LeetSpeakProcessor` has a `sizeof` of 40 bytes (24 inherited + `bool` + padding + `size_t`), you should see:

```
[PRELOAD:new] size=40   → 0x...  (UpperCase/Reverse-sized)
[PRELOAD:new] size=40   → 0x...  (UpperCase/Reverse-sized)
[PRELOAD:new] size=40   → 0x...  (LeetSpeak — same size)
[PRELOAD:new] size=48   → 0x...  (Rot13-sized)
[PRELOAD:new] size=80   → 0x...  (XorCipher-sized)
```

---

## Validation criteria

The checkpoint is considered passed when all the following conditions are met:

| # | Criterion | How to verify |  
|---|---------|-----------------|  
| 1 | The plugin is compiled without access to the original `processor.h` header | The header used is a reconstructed file, documenting the RE choices |  
| 2 | `plugin_gamma.so` exports both unmangled factory symbols | `nm -CD plugin_gamma.so` shows `create_processor` and `destroy_processor` |  
| 3 | The `oop_O2_strip` binary loads the plugin without errors | No `dlopen error` or `missing symbols` message |  
| 4 | The processor appears in the pipeline and produces output | The line `[STEP] LeetSpeakProcessor → "..."` is visible |  
| 5 | The processor respects priority ordering | It inserts at the correct position in the processing chain |  
| 6 | The program terminates cleanly (no segfault, no leak) | The destructor is called, `valgrind` reports no leaks |  
| 7 | `name()` and `status()` return coherent strings | The strings appear in the `--- Status ---` section |

---

## What this checkpoint validates

By producing a functional plugin from a stripped binary, you have demonstrated that you can:

- **Reconstruct an abstract C++ interface** from vtables, RTTI, and observed memory accesses — without source code, without documentation (22.1).  
- **Identify the contract of a plugin system** by analyzing `dlopen`/`dlsym` calls and associated strings (22.2).  
- **Understand virtual dispatch** well enough to implement methods in the correct order and produce a compatible vtable (22.3).  
- **Use dynamic techniques** (`LD_PRELOAD`, GDB, `ltrace`) to validate hypotheses and diagnose issues (22.4).

This workflow — observe, reconstruct, implement, verify — is representative of reverse engineering work in real conditions: interoperability with closed systems, plugin development for proprietary applications, or modular malware analysis.

---


⏭️ [Chapter 23 — Reversing a Network Binary (client/server)](/23-network/README.md)
