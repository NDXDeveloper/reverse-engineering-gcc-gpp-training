🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 22.4 — Patching Behavior via `LD_PRELOAD`

> 🛠️ **Tools used**: `LD_PRELOAD`, GCC/G++, `nm`, `ltrace`, GDB, `readelf`  
> 📦 **Binaries**: `oop_O0`, `oop_O2`, `plugins/plugin_alpha.so`  
> 📚 **Prerequisites**: Sections 22.1–22.3, Chapter 2.9 (PLT/GOT), Chapter 5.4 (`ldd`), Chapter 13 (Frida — for comparison)

---

## Introduction

Until now, we have analyzed the `ch22-oop` binary without modifying it. We reconstructed the class hierarchy, understood the plugin mechanism, and decoded virtual dispatch. But reverse engineering is not limited to observation — it also includes **active experimentation**: modifying a behavior to validate a hypothesis, bypassing a check, or exploring an otherwise inaccessible execution path.

The `LD_PRELOAD` technique enables exactly this. By injecting a custom shared library **before** all others in the dynamic linker's resolution order, you can **replace any function** exported by a library, including libc, without touching the target binary. The original program does not know it is using your version of the function — the replacement is transparent.

This technique sits at the boundary between dynamic analysis (chapter 13 — Frida) and binary patching (chapter 21.6). It is lighter than Frida (no JS runtime to inject) and more reversible than patching (the binary is never modified). It is an everyday tool for the reverse engineer, the systems developer, and the security analyst.

---

## How `LD_PRELOAD` works

### The symbol resolution mechanism

When the dynamic linker (`ld.so`) loads a program, it resolves imported symbols (like `printf`, `malloc`, `dlopen`) by searching shared libraries in a precise order:

1. **`LD_PRELOAD`** — the libraries listed in this environment variable, loaded first.  
2. **Direct dependencies** of the binary (listed in `DT_NEEDED` entries of the dynamic ELF header).  
3. **Dependencies of dependencies** (recursive resolution).

The fundamental rule is: **the first symbol found wins**. If your `LD_PRELOAD` library exports a `strcmp` symbol, your version will be used by the program, not libc's. libc is still loaded, but its `strcmp` is "shadowed" by yours for all calls going through the PLT.

### What `LD_PRELOAD` can intercept

- **libc functions**: `strcmp`, `strlen`, `malloc`, `free`, `open`, `read`, `write`, `printf`, `time`, `rand`...  
- **`libdl` functions**: `dlopen`, `dlsym`, `dlclose`.  
- **`libstdc++` functions**: `operator new`, `operator delete`, `__cxa_throw`...  
- **C functions exported by the binary itself** (if compiled with `-rdynamic`).  
- **`extern "C"` symbols from plugins**: `create_processor`, `destroy_processor`.

### What `LD_PRELOAD` cannot intercept

- **Internal calls** that do not go through the PLT. If a function calls another function from the same binary (or same `.so`) and the call is statically resolved at link time, `LD_PRELOAD` cannot intercept it. This is often the case at `-O2` with `static` functions or those resolved via the local GOT.  
- **Direct system calls** (`syscall`). A program that calls `write` via libc can be intercepted; a program that directly executes `syscall(1, fd, buf, len)` cannot.  
- **Mangled C++ methods** — in theory it is possible (symbol mangling produces an exportable name), but in practice, internal C++ methods are almost never resolved via the PLT. They are called directly, without going through the dynamic linker.  
- **Intra-module virtual calls** — dispatch goes through the vtable in memory, not through the linker. `LD_PRELOAD` cannot replace a vtable entry.

> 💡 **Summary**: `LD_PRELOAD` intercepts what goes through PLT/GOT — that is, symbols dynamically resolved by `ld.so`. To intercept internal code (including virtual methods), you need complementary techniques: Frida (in-memory hooking), binary patching, or runtime vtable manipulation.

---

## Practical case 1 — Intercepting `strcmp` to trace comparisons

### Scenario

You are analyzing a binary that verifies a password or license via `strcmp`. Rather than setting manual breakpoints in GDB, you want to **automatically log** every `strcmp` call with its two arguments.

This scenario is directly applicable to our `oop_O0` binary: each processor's `configure()` method uses `strcmp` to compare key names (like `"skip_digits"`, `"word_mode"`, `"half_rot"`). Intercepting `strcmp` instantly reveals the accepted configuration options.

### The interception library

```c
/* preload_strcmp.c
 *
 * Compile:
 *   gcc -shared -fPIC -o preload_strcmp.so preload_strcmp.c -ldl
 *
 * Usage:
 *   LD_PRELOAD=./preload_strcmp.so ./oop_O0 -s "Hello World"
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* Pointer to the original strcmp (resolved on first call) */
static int (*real_strcmp)(const char*, const char*) = NULL;

/* Our version of strcmp — called instead of the original */
int strcmp(const char* s1, const char* s2) {
    /* Lazily resolve the real strcmp */
    if (!real_strcmp) {
        real_strcmp = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "strcmp");
    }

    /* Log the call */
    fprintf(stderr, "[PRELOAD] strcmp(\"%s\", \"%s\")", s1, s2);

    /* Call the real strcmp */
    int result = real_strcmp(s1, s2);

    fprintf(stderr, " → %d\n", result);
    return result;
}
```

### Key points of the code

**`RTLD_NEXT`** — This is the magic constant that makes everything work. Passed to `dlsym`, it means "search for this symbol in the **next** library in the resolution order, skipping the current library." This is how our `strcmp` can call the real `strcmp` from libc without creating infinite recursion.

**`_GNU_SOURCE`** — Required for `RTLD_NEXT` to be defined in `<dlfcn.h>`. Without this macro, compilation fails.

**Lazy resolution** — The `real_strcmp` pointer is initialized on first call via `dlsym(RTLD_NEXT, "strcmp")`. This avoids initialization order problems when the library is loaded.

**`fprintf(stderr, ...)`** — We write to `stderr`, not `stdout`, to avoid polluting the program's standard output. If the program redirects `stdout` to a file or pipe, our logs remain visible in the terminal.

### Compilation and execution

```bash
$ gcc -shared -fPIC -o preload_strcmp.so preload_strcmp.c -ldl

$ LD_PRELOAD=./preload_strcmp.so ./oop_O0 -s "Hello World"
```

Output on `stderr`:

```
[PRELOAD] strcmp("skip_digits", "skip_digits") → 0
[PRELOAD] strcmp("skip_digits", "word_mode") → -4
[PRELOAD] strcmp("word_mode", "word_mode") → 0
...
```

The result `→ 0` indicates a match. You immediately see which configuration keys are compared, and by deduction, which options each processor supports.

---

## Practical case 2 — Intercepting `dlopen` to control plugin loading

### Scenario

You want to understand how the program reacts if a plugin is absent, corrupted, or replaced by another. Rather than manipulating the file system, you intercept `dlopen` to filter, redirect, or block loading.

### The interception library

```c
/* preload_dlopen.c
 *
 * Compile:
 *   gcc -shared -fPIC -o preload_dlopen.so preload_dlopen.c -ldl
 *
 * Usage:
 *   LD_PRELOAD=./preload_dlopen.so ./oop_O0 -p ./plugins "Hello"
 *
 * Control via environment variables:
 *   BLOCK_PLUGIN=plugin_beta.so   → blocks loading this plugin
 *   REDIRECT_PLUGIN=alpha:beta    → redirects alpha to beta
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void* (*real_dlopen)(const char*, int) = NULL;

static void init_real_dlopen(void) {
    if (!real_dlopen) {
        real_dlopen = (void* (*)(const char*, int))dlsym(RTLD_NEXT, "dlopen");
    }
}

void* dlopen(const char* filename, int flags) {
    init_real_dlopen();

    fprintf(stderr, "[PRELOAD:dlopen] request: \"%s\" flags=%d\n",
            filename ? filename : "(null)", flags);

    if (!filename) {
        return real_dlopen(filename, flags);
    }

    /* ── Conditional blocking ── */
    const char* blocked = getenv("BLOCK_PLUGIN");
    if (blocked && strstr(filename, blocked)) {
        fprintf(stderr, "[PRELOAD:dlopen] BLOCKED: %s\n", filename);
        return NULL;  /* Simulate a loading failure */
    }

    /* ── Conditional redirection ── */
    const char* redirect = getenv("REDIRECT_PLUGIN");
    if (redirect) {
        /* Format: "source_pattern:dest_pattern" */
        char buf[256];
        strncpy(buf, redirect, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char* sep = strchr(buf, ':');
        if (sep) {
            *sep = '\0';
            const char* from = buf;
            const char* to = sep + 1;
            if (strstr(filename, from)) {
                /* Build the new path */
                static char new_path[512];
                strncpy(new_path, filename, sizeof(new_path) - 1);
                char* pos = strstr(new_path, from);
                if (pos) {
                    /* Simple replacement (approximately same length) */
                    size_t prefix_len = (size_t)(pos - new_path);
                    snprintf(new_path + prefix_len,
                             sizeof(new_path) - prefix_len,
                             "%s%s", to, pos + strlen(from));
                    fprintf(stderr, "[PRELOAD:dlopen] REDIRECT: %s → %s\n",
                            filename, new_path);
                    filename = new_path;
                }
            }
        }
    }

    /* ── Actual call ── */
    void* handle = real_dlopen(filename, flags);
    fprintf(stderr, "[PRELOAD:dlopen] result: %p %s\n",
            handle, handle ? "OK" : dlerror());
    return handle;
}
```

### Usage scenarios

**Block a plugin** to observe the pipeline's behavior without it:

```bash
$ BLOCK_PLUGIN=plugin_beta.so \
  LD_PRELOAD=./preload_dlopen.so ./oop_O0 -p ./plugins "Hello"
```

```
[PRELOAD:dlopen] request: "./plugins/plugin_alpha.so" flags=2
[PRELOAD:dlopen] result: 0x5555557a4000 OK
[PRELOAD:dlopen] request: "./plugins/plugin_beta.so" flags=2
[PRELOAD:dlopen] BLOCKED: ./plugins/plugin_beta.so
[Pipeline] dlopen error: (null)
```

The beta plugin is blocked. You can observe how the pipeline handles the absence of a plugin — does it crash, does it continue with the remaining processors, does it display an explicit error message?

**Redirect a plugin** to see what happens if the same plugin is loaded twice under different names:

```bash
$ REDIRECT_PLUGIN=beta:alpha \
  LD_PRELOAD=./preload_dlopen.so ./oop_O0 -p ./plugins "Hello"
```

```
[PRELOAD:dlopen] request: "./plugins/plugin_alpha.so" flags=2
[PRELOAD:dlopen] result: 0x5555557a4000 OK
[PRELOAD:dlopen] request: "./plugins/plugin_beta.so" flags=2
[PRELOAD:dlopen] REDIRECT: ./plugins/plugin_beta.so → ./plugins/plugin_alpha.so
[PRELOAD:dlopen] result: 0x5555557a4000 OK
```

The returned handle is the same (`0x5555557a4000`) because `dlopen` returns the existing handle if the library is already loaded. The pipeline will have two `Rot13Processor` instances instead of one of each. This kind of experimentation is valuable for understanding how the program handles edge cases.

---

## Practical case 3 — Intercepting `time` and `rand` for deterministic execution

### Scenario

Many binaries use `time()` as a seed for `srand()`, or call `rand()` for internal decisions (C2 server selection, delay before execution, key generation...). By intercepting these functions, you make execution perfectly reproducible — essential for comparing runs in GDB or for malware analysis.

### The library

```c
/* preload_deterministic.c
 *
 * Compile:
 *   gcc -shared -fPIC -o preload_deterministic.so preload_deterministic.c -ldl
 *
 * Usage:
 *   LD_PRELOAD=./preload_deterministic.so ./target
 *   FAKE_TIME=1700000000 LD_PRELOAD=./preload_deterministic.so ./target
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ── Frozen time() ── */
time_t time(time_t* tloc) {
    const char* env = getenv("FAKE_TIME");
    time_t fake = env ? (time_t)atol(env) : 1700000000; /* Nov 14, 2023 */

    if (tloc) *tloc = fake;
    fprintf(stderr, "[PRELOAD] time() → %ld (fixed)\n", (long)fake);
    return fake;
}

/* ── Deterministic rand() ── */
static unsigned int call_count = 0;

int rand(void) {
    /* Simple deterministic sequence: always the same values */
    unsigned int val = (call_count * 1103515245 + 12345) & 0x7fffffff;
    call_count++;
    fprintf(stderr, "[PRELOAD] rand() → %u (call #%u)\n", val, call_count);
    return (int)val;
}

/* ── Neutralized srand() ── */
void srand(unsigned int seed) {
    fprintf(stderr, "[PRELOAD] srand(%u) → ignored\n", seed);
    /* Does nothing — we want to keep our deterministic sequence */
}
```

This technique is directly applicable to chapter 27 (ransomware analysis) and chapter 28 (dropper analysis) where behavior often depends on time and randomness.

---

## Practical case 4 — Intercepting `operator new` to trace C++ object allocations

### Scenario

You want to know **which objects are created**, **when**, and **of what size**. In C++, all dynamic object allocation goes through `operator new` (unless overridden per class). By intercepting it, you get a journal of all object constructions.

### The library

```cpp
/* preload_new.cpp — NOTE: compile as C++
 *
 * Compile:
 *   g++ -shared -fPIC -o preload_new.so preload_new.cpp -ldl
 *
 * Usage:
 *   LD_PRELOAD=./preload_new.so ./oop_O0 -p ./plugins "Hello"
 */

#define _GNU_SOURCE
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <new>

/* Resolve the original operator new */
static void* (*real_new)(size_t) = nullptr;

static void init_real_new() {
    if (!real_new) {
        real_new = (void* (*)(size_t))dlsym(RTLD_NEXT, "_Znwm");
        /* _Znwm = mangled name of operator new(unsigned long) on x86-64 */
    }
}

/* Replace operator new(size_t) */
void* operator new(size_t size) {
    init_real_new();

    void* ptr = real_new(size);

    fprintf(stderr, "[PRELOAD:new] size=%-4zu → %p", size, ptr);

    /* Heuristic: known sizes of our classes */
    switch (size) {
        case 24:  fprintf(stderr, "  (Processor-sized)");       break;
        case 40:  fprintf(stderr, "  (UpperCase/Reverse-sized)"); break;
        case 48:  fprintf(stderr, "  (Rot13-sized)");           break;
        case 80:  fprintf(stderr, "  (XorCipher-sized)");       break;
    }

    fprintf(stderr, "\n");
    return ptr;
}

/* Replace operator delete(void*) */
void operator delete(void* ptr) noexcept {
    fprintf(stderr, "[PRELOAD:delete] %p\n", ptr);

    void (*real_delete)(void*) =
        (void (*)(void*))dlsym(RTLD_NEXT, "_ZdlPv");
    if (real_delete) real_delete(ptr);
}

/* Variant with size (C++14) */
void operator delete(void* ptr, size_t size) noexcept {
    fprintf(stderr, "[PRELOAD:delete] %p size=%zu\n", ptr, size);

    void (*real_delete)(void*, size_t) =
        (void (*)(void*, size_t))dlsym(RTLD_NEXT, "_ZdlPvm");
    if (real_delete)
        real_delete(ptr, size);
    else {
        void (*fallback)(void*) =
            (void (*)(void*))dlsym(RTLD_NEXT, "_ZdlPv");
        if (fallback) fallback(ptr);
    }
}
```

### Output

```bash
$ LD_PRELOAD=./preload_new.so ./oop_O0 -p ./plugins "Hello RE"
```

```
[PRELOAD:new] size=40   → 0x5555558070f0  (UpperCase/Reverse-sized)
[PRELOAD:new] size=40   → 0x555555807130  (UpperCase/Reverse-sized)
[PRELOAD:new] size=48   → 0x555555808010  (Rot13-sized)
[PRELOAD:new] size=80   → 0x555555808050  (XorCipher-sized)
...
[PRELOAD:delete] 0x555555808050 size=80
[PRELOAD:delete] 0x555555808010 size=48
[PRELOAD:delete] 0x555555807130 size=40
[PRELOAD:delete] 0x5555558070f0 size=40
```

You see the creation order (UpperCase, Reverse, Rot13, XorCipher) and destruction order (reverse — the `Pipeline` destroys plugins before internal processors). The allocation sizes confirm your `sizeof` estimates for each class, reconstructed in section 22.1.

> 💡 **The mangled symbol `_Znwm`**: this is the Itanium name mangling for `operator new(unsigned long)`. On 32-bit platforms, it is `_Znwj` (`j` = `unsigned int`). You can recover these names with `echo "_Znwm" | c++filt` → `operator new(unsigned long)`.

---

## Combining multiple interceptions in a single library

In practice, you will often group multiple interceptions in a single library to get a complete picture of behavior:

```c
/* preload_full.c — Combined interception for RE of ch22-oop
 *
 * Compile:
 *   gcc -shared -fPIC -o preload_full.so preload_full.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* ── strcmp: trace configuration comparisons ── */
int strcmp(const char* s1, const char* s2) {
    static int (*real)(const char*, const char*) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "strcmp");
    int r = real(s1, s2);
    if (r == 0)  /* Only log matches to reduce noise */
        fprintf(stderr, "[CMP] \"%s\" == \"%s\"\n", s1, s2);
    return r;
}

/* ── dlopen: trace loaded plugins ── */
void* dlopen(const char* path, int flags) {
    static void* (*real)(const char*, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "dlopen");
    fprintf(stderr, "[DL] dlopen(\"%s\")\n", path ? path : "NULL");
    void* h = real(path, flags);
    fprintf(stderr, "[DL] → %p\n", h);
    return h;
}

/* ── dlsym: trace symbol resolutions ── */
void* dlsym(void* handle, const char* symbol) {
    /* Caution: we cannot use dlsym(RTLD_NEXT, "dlsym")
     * from dlsym itself — infinite recursion.
     * Solution: use __libc_dlsym or resolve at load time. */
    static void* (*real)(void*, const char*) = NULL;
    if (!real) {
        /* Direct access via the internal GNU ABI */
        void* libdl = __libc_dlopen_mode("libdl.so.2", 0x80000002);
        if (libdl)
            real = __libc_dlsym(libdl, "dlsym");
    }
    if (!real) {
        fprintf(stderr, "[DL] FATAL: cannot resolve real dlsym\n");
        return NULL;
    }

    fprintf(stderr, "[DL] dlsym(%p, \"%s\")\n", handle, symbol);
    void* r = real(handle, symbol);
    fprintf(stderr, "[DL] → %p\n", r);
    return r;
}
```

> ⚠️ **The `dlsym` in `dlsym` pitfall**: intercepting `dlsym` is tricky because `RTLD_NEXT` itself goes through `dlsym`. The code above works around the problem with `__libc_dlsym`, a glibc internal function. This approach works on Linux/glibc but is not portable. A more robust alternative is to resolve the pointer in a constructor function `__attribute__((constructor))` at library load time, before any call.

---

## `LD_PRELOAD` vs Frida vs binary patching

These three techniques modify a program's behavior without recompilation. Their domains overlap but are not identical.

**`LD_PRELOAD`** operates at the dynamic linker level. It intercepts symbols resolved via PLT/GOT — mainly shared library functions. It is the simplest technique to implement (one `.c` file, one compilation line, one environment variable) and the lightest in overhead. It requires no special tools, works on any Linux, and leaves no trace in the binary.

**Frida** operates at the process memory level. It can hook any address — including internal functions, virtual methods, vtable entries, and individual instructions. It is more powerful than `LD_PRELOAD` but requires the Frida runtime, a JavaScript script, and greater overhead. Frida is the right choice when you need to intercept internal code that does not go through the PLT.

**Binary patching** modifies the ELF file itself: inverting a conditional jump, replacing a `call`, NOP-ifying a check. It is permanent (the file is modified) and precise (you change exactly the bytes you want), but fragile (an incorrect offset corrupts the binary) and non-reversible without a backup. Patching is the right choice when you need to produce a modified redistributable binary.

| Criterion | `LD_PRELOAD` | Frida | Binary patching |  
|---------|-------------|-------|-----------------|  
| Scope | PLT/GOT symbols | Any memory address | Any file byte |  
| Complexity | Low (C + gcc) | Medium (JS + runtime) | Variable (hex editor → scripts) |  
| Reversibility | Total (env. variable) | Total (detach agent) | Requires backup |  
| Overhead | Near zero | Moderate | None |  
| C++ virtual methods | No (not in PLT) | Yes (hook by address) | Yes (modify vtable or call) |  
| Persistence | Per session (env. var.) | Per session (agent) | Permanent (file modified) |  
| Static binary | No | Yes | Yes |

In day-to-day RE, the best practice is to start with `LD_PRELOAD` for simple interceptions (libc, libdl), move to Frida when you need to hook internal code or vtables, and resort to patching only when a modified binary is needed.

---

## Protections and countermeasures

`LD_PRELOAD` is a powerful technique, but some binaries seek to protect against it.

### setuid/setgid binaries

The dynamic linker **ignores** `LD_PRELOAD` for setuid or setgid binaries. This is a Linux kernel security protection: allowing a non-root user to inject code into a privileged binary would be a trivial privilege escalation.

```bash
$ ls -l /usr/bin/passwd
-rwsr-xr-x 1 root root 68208 ... /usr/bin/passwd
                                    ↑ setuid bit
$ LD_PRELOAD=./preload_strcmp.so /usr/bin/passwd
# → LD_PRELOAD is silently ignored
```

### Detection by the program

A program can detect the presence of `LD_PRELOAD` in several ways:

- **Read the environment variable**: `getenv("LD_PRELOAD")`. Trivial to bypass by intercepting `getenv` itself.  
- **Read `/proc/self/environ`**: direct access to the process environment block. Harder to bypass with `LD_PRELOAD` alone.  
- **Read `/proc/self/maps`**: lists libraries mapped in memory. Your preloaded `.so` appears there with its full path.  
- **Compare function addresses**: the program can verify that the address of `strcmp` falls within the expected libc address range. If it falls elsewhere, an interception is detected.

### Bypassing detections

For most educational RE and CTF cases, these detections are not present. If you encounter them, Frida offers stealthier mechanisms (process injection without environment variable), and binary patching can neutralize checks directly in the code.

### Full RELRO

A binary compiled with Full RELRO (`-Wl,-z,relro,-z,now`) resolves **all** symbols at load time and marks the GOT as read-only. This does not prevent `LD_PRELOAD` from working (interposition happens before the GOT is written), but prevents GOT modification after loading — a complementary technique sometimes combined with `LD_PRELOAD`.

---

## Writing a proper `LD_PRELOAD` library

Based on the examples in this section, here are the best practices to follow systematically.

**Always resolve the original function via `RTLD_NEXT`.** Never reimplement the function yourself (unless you intentionally want to block it). Always call the original after your instrumentation so the program behaves normally.

**Log to `stderr`, not `stdout`.** Standard output is often redirected or parsed by the program. `stderr` remains available for your diagnostic messages.

**Handle lazy resolution.** Initialize pointers to original functions on first call (or in an `__attribute__((constructor))`), not globally. The initialization order of libraries at load time is not guaranteed.

**Compile with `-fPIC` and `-shared`.** This is mandatory to produce a shared object compatible with `LD_PRELOAD`. Forgetting `-fPIC` produces relocation errors at load time.

**Use `__attribute__((constructor))` for initial setup.** If you need to open a log file or initialize global state, use a constructor function rather than doing it on the first intercepted call:

```c
__attribute__((constructor))
static void preload_init(void) {
    fprintf(stderr, "[PRELOAD] Library loaded, PID=%d\n", getpid());
}

__attribute__((destructor))
static void preload_fini(void) {
    fprintf(stderr, "[PRELOAD] Library unloaded\n");
}
```

**Keep the library as lightweight as possible.** Each intercepted call adds overhead. If you intercept `malloc`, every program allocation goes through your code — including those from `fprintf` in your interception. Watch out for infinite recursion (`malloc` → `fprintf` → `malloc` → ...). Use `write(2, ...)` instead of `fprintf(stderr, ...)` in memory allocation function interceptions.

---

## Summary

`LD_PRELOAD` is an RE tool that is both simple and powerful. By injecting a shared library before all others in the linker's resolution order, you can intercept, log, modify, or block any library call without touching the target binary.

In the context of our `ch22-oop` binary, this technique allowed us to trace configuration comparisons (`strcmp`), control plugin loading (`dlopen`), and monitor C++ object allocations (`operator new`). Combined with the techniques from previous sections — vtable analysis, virtual dispatch understanding, plugin tracing — it completes your toolkit for reverse engineering object-oriented C++ applications.

At this chapter's checkpoint, you will put all this knowledge into practice by writing a compatible `.so` plugin that integrates into the application without the sources — the loop is closed: from reverse engineering to creating interoperable code.

---


⏭️ [🎯 Checkpoint: write a compatible `.so` plugin that integrates into the application without the sources](/22-oop/checkpoint.md)
