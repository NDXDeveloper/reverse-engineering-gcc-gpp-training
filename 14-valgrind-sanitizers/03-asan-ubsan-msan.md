🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 14.3 — AddressSanitizer (ASan), UBSan, MSan — compiling with `-fsanitize`

> 🎯 **Goal of this section**: Understand the operation, strengths, and differences of the three main GCC/Clang sanitizers — AddressSanitizer, UndefinedBehaviorSanitizer, and MemorySanitizer — know how to recompile a binary to enable them, and interpret their reports from a reverse-engineering perspective to deduce the target program's internal structure, logical flaws, and data flow.

---

## Sanitizers vs Valgrind: two instrumentation philosophies

In sections 14.1 and 14.2, we worked with Valgrind, which instruments a binary **from the outside**, at runtime, without modifying it. Sanitizers take the opposite approach: they instrument the binary **from the inside**, at compile time, by injecting verification code directly into the produced binary.

This fundamental difference has direct consequences on what you can observe.

| Criterion | Valgrind (Memcheck) | Sanitizers (ASan/UBSan/MSan) |  
|---|---|---|  
| Binary modification | None | Recompilation required |  
| Instrumentation method | Software VM at runtime | Code injected at compile time |  
| Typical slowdown | 10–50x | 1.5–3x (ASan), ~1x (UBSan) |  
| Stack overflow detection | Limited | Excellent (ASan) |  
| Heap overflow detection | Good | Excellent (ASan, redzones) |  
| UB (undefined behavior) detection | No | Yes (UBSan) |  
| Uninitialized read detection | Yes (V-bits) | Yes (MSan only) |  
| Works on third-party binary | Yes | No (sources needed) |

The natural question in an RE context: **if sanitizers require sources, what use are they?**

The answer is threefold. First, within this training, we have the sources for all training binaries — we can thus recompile them with sanitizers to explore their behavior. Second, in real RE situations, it happens that you reconstruct approximate source code from decompilation (Chapter 20) — you can then recompile with sanitizers to verify your hypotheses. Third, some open-source projects distribute instrumented builds ("sanitizer builds") intended for fuzzing, and these builds are directly analyzable.

Finally, sanitizers' execution speed (only 1.5 to 3x slowdown for ASan, versus 10–50x for Valgrind) makes them much more practical for **instrumented fuzzing** (Chapter 15): you can execute millions of inputs under ASan in the time it would take to execute a few thousand under Valgrind.

---

## AddressSanitizer (ASan)

ASan is the most used of the three sanitizers. It detects memory access errors — buffer overflows, use-after-free, use-after-return, double free — with remarkable precision and speed.

### How it works

ASan relies on two complementary mechanisms:

**1. Shadow memory** — Like Memcheck, ASan maintains shadow memory. But where Memcheck uses one bit per byte, ASan uses a more compact scheme: each group of 8 bytes of application memory is represented by **1 byte** of shadow memory. This byte encodes how many of the 8 bytes are accessible (from 0 = none to 8 = all, or a special value for poisoned zones). This 1:8 ratio is what makes ASan much faster than Memcheck (1:1 or more).

**2. Redzones** — At compile time, ASan inserts **poisoned zones** around each stack variable and around each heap allocation. These redzones are marked as inaccessible in the shadow memory. Any access to a redzone immediately triggers an error report.

Concretely, when you declare a 64-byte buffer on the stack, ASan surrounds it with 32 bytes of redzone on each side. If the program writes beyond the 64 bytes, it hits the redzone and ASan detects it instantly — even if the overflow is only a single byte.

This is why ASan is **superior to Valgrind for stack buffer overflow detection**. Valgrind can't poison zones around stack variables (it doesn't know their layout), while ASan instruments them at compile time because it has the compiler's information about each variable's size and position.

### Compiling with ASan

The basic syntax with GCC:

```bash
gcc -fsanitize=address -g -O0 -o my_binary_asan my_binary.c
```

Let's detail the flags:

**`-fsanitize=address`** — Enables AddressSanitizer. GCC inserts instrumentation code (shadow memory checks, redzones) into the compiled binary and automatically links the ASan runtime library (`libasan`).

**`-g`** — Adds debug symbols. Indispensable for ASan to display line numbers and function names in its reports. Without `-g`, ASan displays only raw addresses — exploitable but much less readable.

**`-O0`** — Disables optimizations. Recommended for the finest analysis since inlining and code reorganizations mask some problems. However, ASan also works with `-O1` and `-O2`. With `-O2`, some variables are optimized into registers and escape redzone instrumentation.

For a C++ project with multiple files:

```bash
g++ -fsanitize=address -g -O0 -o oop_asan main.cpp utils.cpp -lstdc++
```

> ⚠️ **Warning** — All object files must be compiled with `-fsanitize=address`. If you link a file compiled with ASan with one compiled without, results will be inconsistent and false positives may appear.

### ASan environment options

ASan's runtime behavior is configured via the `ASAN_OPTIONS` environment variable:

```bash
ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:halt_on_error=0:log_path=asan_report" \
    ./my_binary_asan arg1 arg2
```

The most useful options in RE:

**`detect_leaks=1`** — Enables LeakSanitizer (LSan), which detects memory leaks similarly to Memcheck. Enabled by default on Linux. As with Memcheck, leaks reveal structure sizes and allocation functions.

**`detect_stack_use_after_return=1`** — Detects access to a function's local variables after its return. This option is memory-costly (ASan moves stack frames to the heap to poison them after return), but it detects a subtle bug that escapes Memcheck.

**`halt_on_error=0`** — By default, ASan stops the program at the first error. With `halt_on_error=0`, it continues execution and reports all errors encountered. In RE, you generally want to see *all* errors for the most complete picture of the program's memory behavior.

**`log_path=asan_report`** — Redirects reports to files prefixed with `asan_report` (one file per PID: `asan_report.12345`). Without this option, ASan writes to `stderr`.

**`symbolize=1`** — Enables address symbolization. Requires `llvm-symbolizer` or `addr2line` to be available in the PATH. If the binary was compiled with `-g`, reports will contain function names and line numbers.

### Anatomy of an ASan report

A typical ASan report for a stack buffer overflow:

```
=================================================================
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd4a3c2e50
    at pc 0x00401a3f bp 0x7ffd4a3c2df0 sp 0x7ffd4a3c2de8
WRITE of size 4 at 0x7ffd4a3c2e50 thread T0                     ← (1)
    #0 0x401a3e in process_key /src/keygenme.c:47                ← (2)
    #1 0x401b11 in validate_input /src/keygenme.c:82
    #2 0x4012e7 in main /src/keygenme.c:112
    #3 0x7f3a2c1b0d8f in __libc_start_call_main (libc.so.6+0x29d8f)

Address 0x7ffd4a3c2e50 is located in stack of thread T0          ← (3)
    at offset 80 in frame
    #0 0x401980 in process_key /src/keygenme.c:31

  This frame has 2 object(s):                                    ← (4)
    [32, 64) 'key_buffer' (line 33)                              ← size = 32 bytes
    [96, 128) 'hash_output' (line 34)                            ← size = 32 bytes
HINT: this may be a false positive if your program uses
    some custom stack unwind mechanism
```

Let's dissect each part from an RE perspective:

**(1) Nature and size of the access** — "WRITE of size 4": the program writes 4 bytes (an `int` or `uint32_t`) at an invalid address. It's a **stack buffer overflow** — the write exceeds a local variable's bounds.

**(2) Call stack with names and lines** — Thanks to `-g`, we see the error occurs in `process_key` at line 47, called by `validate_input` (line 82), itself called by `main` (line 112). If working without symbols, we'd see raw addresses, but the call stack structure would remain readable.

**(3) Location in the stack frame** — "at offset 80 in frame" gives the exact offset of the faulting access in `process_key`'s frame. The frame starts at offset 0, so the access is at 80 bytes from the frame's start.

**(4) Frame object layout** — This is the most precious part for RE. ASan gives us the **exact layout of the function's local variables**:

- `key_buffer` occupies bytes [32, 64) → size 32 bytes, starts at frame offset 32.  
- `hash_output` occupies bytes [96, 128) → size 32 bytes, starts at offset 96.  
- The space between 64 and 96 (32 bytes) is the **redzone** inserted by ASan between the two variables.

The faulting access is at offset 80, which falls in the redzone between `key_buffer` and `hash_output`. This means the program writes 16 bytes beyond `key_buffer`'s end (64 + 16 = 80). The buffer is 32 bytes but the program tries to write 48 bytes — probably because the hashing routine produces a 48-byte output on a buffer sized for 32.

> 💡 **RE tip** — The frame object layout given by ASan is information that even Ghidra doesn't always provide correctly. Decompilers reconstruct local variables by heuristic, sometimes with size or position errors. ASan knows the exact layout since it has access to the compiler's information. It's a powerful verification tool for validating or correcting local-variable reconstruction in Ghidra.

### ASan report: heap buffer overflow

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000040
READ of size 1 at 0x602000000040 thread T0
    #0 0x401c7e in decrypt_block /src/crypto.c:156
    #1 0x401da4 in process_file /src/crypto.c:201
    #2 0x4012e7 in main /src/crypto.c:245

0x602000000040 is located 0 bytes after 32-byte region [0x602000000020,0x602000000040)
allocated by thread T0 here:                                      ← (5)
    #0 0x7f3a2c8b0808 in __interceptor_malloc (libasan.so.8+0xb0808)
    #1 0x401b89 in init_cipher_ctx /src/crypto.c:98
    #2 0x401da4 in process_file /src/crypto.c:189
```

**(5) Allocation provenance** — ASan indicates the faulting block is exactly **32 bytes**, was allocated in `init_cipher_ctx` at line 98, and the access occurs "0 bytes after" — exactly one byte past the block's end. It's a classic off-by-one.

In RE, exploitable information is identical to Memcheck's (cf. section 14.1), but with two major advantages:

- ASan gives the **exact redzone sizes** and therefore the **exact position of the overflow**, whereas Memcheck only detects accesses beyond the allocated block without precision on the distance.  
- ASan provides these reports **much faster** (1.5–3x slowdown vs 10–50x), making it viable for repeated executions with many inputs.

### ASan report: use-after-free

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000010
READ of size 8 at 0x603000000010 thread T0
    #0 0x401e23 in send_response /src/network.c:178
    #1 0x4012e7 in main /src/network.c:230

0x603000000010 is located 0 bytes inside of 128-byte region [0x603000000010,0x603000000090)
freed by thread T0 here:                                          ← (6)
    #0 0x7f3a2c8b1230 in __interceptor_free (libasan.so.8+0xb1230)
    #1 0x401d10 in close_connection /src/network.c:162

previously allocated by thread T0 here:                           ← (7)
    #0 0x7f3a2c8b0808 in __interceptor_malloc (libasan.so.8+0xb0808)
    #1 0x401c45 in open_connection /src/network.c:134
```

This report is a gold mine for network binary RE:

**(6) Who freed the block** — The `close_connection` function (line 162) frees a 128-byte block. It's the connection-closing function.

**(7) Who allocated it** — The `open_connection` function (line 134) had allocated this block. It's the connection-opening function.

The program then tries to read 8 bytes from this block via `send_response` — an attempt to send data on an already-closed connection. In RE, this report reveals the **complete lifecycle of a connection structure**: allocation in `open_connection`, use in `send_response`, freeing in `close_connection`. The 128-byte size gives us the connection structure's size, and the read offset (0 bytes inside = at the very beginning of the block) points to this structure's first field — probably a socket descriptor or a pointer to the send buffer.

> 💡 **RE tip** — ASan's use-after-free reports are particularly interesting because they reveal three functions at once: the allocator, the freer, and the late user. It's a lifecycle graph that neither Memcheck nor static disassembly provides as directly.

---

## UndefinedBehaviorSanitizer (UBSan)

UBSan detects **undefined behavior** (UB) in C and C++. Unlike ASan which focuses on memory errors, UBSan targets language-standard violations that, while compiling without error, produce unpredictable results.

### Why UB interests the reverse engineer

Undefined behaviors are invisible in disassembly — you see normal arithmetic instructions, comparisons, jumps. Nothing signals that an operation is undefined. Yet UBs have a major impact on program behavior, and especially on how the compiler optimizes the code.

When GCC detects a potential UB at compile time, the standard authorizes it to **assume the UB never happens** and optimize accordingly. This produces assembly code whose logic seems inconsistent with what you imagine from the source code. For example, a comparison that should always be true can disappear from the binary because GCC deduced it was unnecessary by assuming the absence of UB.

In RE, when you encounter code whose logic seems "broken" or "missing" after decompilation, the cause is often a UB exploited by the optimizer. UBSan allows **confirming this hypothesis** by recompiling the code and observing the UBs that trigger.

### Types of UB detected by UBSan

UBSan detects a wide range of undefined behaviors, including:

- **Signed integer overflow** — Addition, subtraction, or multiplication of two signed integers whose result exceeds the type's range. In C, `INT_MAX + 1` is undefined (unlike unsigned which wraps). GCC can optimize loops or conditions by assuming this overflow doesn't happen.  
- **Shift overflow** — Shifting a negative number, or shifting more bits than the type's size (`x << 33` for a 32-bit `int`).  
- **Division by zero** — Integer or floating-point.  
- **Null pointer dereference** — Dereferencing a null pointer.  
- **Out-of-bounds array access** — Out-of-bounds array access (when the compiler can determine bounds).  
- **Misaligned pointer** — Access through a misaligned pointer for its type (for example, reading an `int` at an odd address).  
- **Invalid enum value** — In C++, conversion to an `enum` type of a value not in the defined range.  
- **Invalid bool value** — In C++, a `bool` that's neither 0 nor 1.  
- **Return from non-void function without value** — A function declared as returning a value but reaching a path without `return`.

### Compiling with UBSan

```bash
gcc -fsanitize=undefined -g -O0 -o my_binary_ubsan my_binary.c
```

You can enable specific sub-categories:

```bash
# Only signed integer overflows and shifts
gcc -fsanitize=signed-integer-overflow,shift -g -O0 -o my_binary_ubsan my_binary.c

# Everything except vfptr (useful in C++ with complex polymorphism)
gcc -fsanitize=undefined -fno-sanitize=vptr -g -O0 -o my_binary_ubsan my_binary.cpp
```

> 💡 **RE tip** — In an RE context, the most revealing sub-sanitizer is `signed-integer-overflow`. Crypto routines and hashing functions intensively manipulate integers, and intentional overflows (which are technically UB in signed) betray the computation's logic. If UBSan reports a signed overflow in a 64-iteration loop, you're probably looking at a SHA-256 round with modular additions.

### Typical UBSan report

```
/src/keygenme.c:47:15: runtime error: signed integer overflow:
    2147483647 + 1 cannot be represented in type 'int'              ← (1)
    #0 0x401a3e in transform_key /src/keygenme.c:47
    #1 0x401b11 in validate_input /src/keygenme.c:82
    #2 0x4012e7 in main /src/keygenme.c:112
```

**(1) Precise diagnostic** — UBSan identifies the exact operation (`2147483647 + 1`), the type concerned (`int`), and explains why it's UB. The number `2147483647` is `INT_MAX` — the maximum value of a 32-bit signed `int`. Adding 1 causes an overflow.

In RE, this information tells us that the `transform_key` function performs an addition on an `int` that reaches `INT_MAX`. It's characteristic of a **hash or checksum computation** using modular additions. The developer was probably thinking in `unsigned int` (where wrapping is defined), but declared the variable as `int` (signed) — a common error.

### Combining UBSan with ASan

ASan and UBSan are compatible and can be enabled simultaneously:

```bash
gcc -fsanitize=address,undefined -g -O0 -o my_binary_full my_binary.c
```

This combination is the recommended configuration for RE analysis: you get both memory errors (ASan) and undefined behaviors (UBSan) in a single run. UBSan's performance overhead is negligible on top of ASan.

UBSan's runtime behavior is controlled via `UBSAN_OPTIONS`:

```bash
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=ubsan_report" \
    ./my_binary_full arg1 arg2
```

**`print_stacktrace=1`** — Displays the complete call stack for each error. Disabled by default for UBSan (unlike ASan). In RE, the call stack is essential — always enable this option.

**`halt_on_error=0`** — As with ASan, continue after each error to see all UBs.

---

## MemorySanitizer (MSan)

MSan detects **reads of uninitialized memory** — the same type of errors as Valgrind Memcheck's V-bit tracking. It's the most specialized of the three sanitizers, and also the most constraining to set up.

### Difference with Memcheck

MSan and Memcheck detect the same type of problem, but their approaches differ:

- **Memcheck** works on any binary, without recompilation. Its software-VM instrumentation is universal but slow (10–50x).  
- **MSan** requires recompilation, but its compile-time instrumentation is much faster (about 3x slowdown) and more precise for tracking uninitialized-value propagation through operations.

MSan excels where Memcheck can miss cases: when an uninitialized value is copied, combined with other values, then used much later in the program. MSan follows this propagation instruction by instruction thanks to the code it injected, while Memcheck can sometimes lose track in complex cases (SIMD operations, for example).

### Usage constraints

MSan has a major constraint: **all libraries linked to the program must be compiled with MSan**. If the program calls a standard libc function (compiled without MSan), MSan can't track uninitialized values through that function and may produce false positives or false negatives.

In practice, this means either:

- Statically link a libc compiled with MSan (complex to set up).  
- Use the `-fsanitize-memory-track-origins` option and accept some imprecisions at library boundaries.

> ⚠️ **Warning** — MSan is **only available with Clang**, not GCC. If your compilation chain is GCC, you'll have to use Clang for this step or fall back on Valgrind Memcheck for uninitialized-read detection.

### Compiling with MSan (Clang)

```bash
clang -fsanitize=memory -fsanitize-memory-track-origins=2 -g -O0 \
    -o my_binary_msan my_binary.c
```

**`-fsanitize=memory`** — Enables MemorySanitizer.

**`-fsanitize-memory-track-origins=2`** — Enables origin tracking with depth 2. Without this option, MSan reports the use of an uninitialized value but doesn't say where it comes from. With `=1`, it traces back to the allocation. With `=2`, it additionally traces back to the last store operation — showing the propagation path of the uninitialized value.

### Typical MSan report

```
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x401c7e in encrypt_block /src/crypto.c:156
    #1 0x401da4 in process_file /src/crypto.c:201
    #2 0x4012e7 in main /src/crypto.c:245

  Uninitialized value was stored to memory at
    #0 0x401b45 in prepare_iv /src/crypto.c:122
    #1 0x401da4 in process_file /src/crypto.c:195

  Uninitialized value was created by a heap allocation
    #0 0x7f3a2c4a0808 in malloc
    #1 0x401b20 in init_cipher_ctx /src/crypto.c:98
```

This three-level report gives us the **complete flow of an uninitialized datum**:

1. **Creation** — `init_cipher_ctx` allocates a block on the heap (line 98). This block contains (among other things) space for an IV.  
2. **Storage** — `prepare_iv` writes to this block (line 122), but apparently not all bytes — some remain uninitialized.  
3. **Use** — `encrypt_block` uses the uninitialized value in an encryption operation (line 156).

> 💡 **RE tip** — This three-stage report gives us a **data flow** that crosses three functions. In RE, it's free taint analysis: you see exactly how data propagates from allocation to use through an intermediate transformation. This type of information is normally hard to extract without specialized tools like Triton or angr's taint engine.

---

## Sanitizer combinability

The three sanitizers are not all compatible with each other. Here's the compatibility matrix:

| Combination | Compatible? | Notes |  
|---|---|---|  
| ASan + UBSan | Yes | Recommended configuration, most common combination |  
| ASan + MSan | No | Both instrument memory in incompatible ways |  
| UBSan + MSan | Yes | Possible with Clang |  
| ASan + TSan | No | TSan (ThreadSanitizer) has its own shadow memory |  
| UBSan + TSan | Yes | Possible |

In practice, for a complete RE analysis, perform **two separate runs**:

```bash
# Run 1: ASan + UBSan (memory errors + undefined behavior)
gcc -fsanitize=address,undefined -g -O0 -o binary_asan_ubsan source.c  
ASAN_OPTIONS="halt_on_error=0:log_path=asan" \  
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \  
    ./binary_asan_ubsan test_input

# Run 2: MSan (uninitialized reads) — Clang only
clang -fsanitize=memory -fsanitize-memory-track-origins=2 -g -O0 \
    -o binary_msan source.c
MSAN_OPTIONS="halt_on_error=0:log_path=msan" \
    ./binary_msan test_input
```

Then merge reports for the complete picture.

---

## Compilation flag impact on reports

Sanitizers interact with optimization levels in subtle ways. Understanding these interactions is crucial to avoid misinterpreting a report.

### ASan and optimizations

| Flag | Impact on ASan |  
|---|---|  
| `-O0` | Best coverage — all variables are in memory, all redzones present. Most detailed reports. |  
| `-O1` | Some variables promoted to registers, escaping redzones. Reports remain reliable but may miss some local-variable overflows. |  
| `-O2` / `-O3` | Aggressive inlining — inlined functions lose their own redzones. Reports still valid for heap, but stack coverage is degraded. |

### UBSan and optimizations

UBSan has an interesting peculiarity: some UBs are only detectable **with optimizations enabled**.

Example: a signed integer overflow in a loop may be invisible at `-O0` because the compiler generates naive code that wraps naturally. At `-O2`, GCC optimizes the loop by assuming the overflow doesn't happen, producing different behavior — and it's this different behavior that UBSan captures.

The RE recommendation: run UBSan both at `-O0` (exhaustive detection) and at `-O2` (detection of UBs exploited by the optimizer). Comparing both reports reveals which UBs are actively exploited by the compiler in the optimized binary version.

### MSan and optimizations

MSan is the most sensitive to optimizations. With `-O2`, the compiler can reorder memory accesses or eliminate redundant reads/writes, modifying the propagation flow of uninitialized values. Reports remain correct (no false negatives), but origin tracking can become confused (the displayed path no longer exactly matches the source code).

In summary:

```
┌─────────────────────────────────────────────────────┐
│  Recommendation: ALWAYS start with -O0 -g           │
│  for the most readable and complete reports.        │
│  Rerun at -O2 only if you want to verify            │
│  a behavior specific to optimization.               │
└─────────────────────────────────────────────────────┘
```

---

## Selective compilation: instrumenting a single file

In a multi-file project, you don't always need to instrument the entire program. GCC allows compiling some files with sanitizers and others without. The linker handles linking the appropriate runtime library as soon as at least one file is instrumented:

```bash
# Instrument only crypto.c, not main.c or utils.c
gcc -c -fsanitize=address -g -O0 crypto.c -o crypto_asan.o  
gcc -c -g -O0 main.c -o main.o  
gcc -c -g -O0 utils.c -o utils.o  
gcc -fsanitize=address -o program crypto_asan.o main.o utils.o  
```

In RE, this approach is useful when you've partially reconstructed a program's sources and want to instrument only the module you're studying (for example, the crypto module) without suffering noise from errors in the rest of the code.

> ⚠️ **Warning** — Interactions between instrumented and non-instrumented code can produce false positives. ASan doesn't see writes made by non-instrumented code, and may consider memory written by `utils.o` as still uninitialized. Use this technique judiciously and verify results by cross-referencing.

---

## Reading an ASan report without symbols

In real RE situations, you sometimes recompile reconstructed sources **without `-g`** (by choice or necessity — reconstructed sources don't always compile cleanly with symbols). ASan reports then contain only addresses.

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000040
READ of size 1 at 0x602000000040 thread T0
    #0 0x401c7e (/path/to/my_binary+0x1c7e)
    #1 0x401da4 (/path/to/my_binary+0x1da4)
    #2 0x4012e7 (/path/to/my_binary+0x12e7)
```

The addresses in parentheses (`+0x1c7e`) are offsets from the binary's base. You can correlate them with the disassembly:

```bash
# Find the function containing the address
objdump -d my_binary | grep -B 20 "401c7e"

# Or use addr2line if the binary has minimal symbols
addr2line -e my_binary 0x401c7e
```

The method is identical to that described in section 14.1 for Memcheck: note addresses, find them in Ghidra or objdump, and progressively enrich your understanding of the binary.

---

## Comparative summary of the three sanitizers

| Aspect | ASan | UBSan | MSan |  
|---|---|---|---|  
| **Target** | Memory errors | Undefined behavior | Uninitialized reads |  
| **Compiler** | GCC + Clang | GCC + Clang | Clang only |  
| **Slowdown** | ~2x | ~1.1x | ~3x |  
| **Extra memory** | ~3x | Negligible | ~3x |  
| **Compatible with ASan** | — | Yes | No |  
| **Key RE info** | Buffer sizes, structure layout, allocation lifecycle | Arithmetic operations, hash/crypto logic, optimization bugs | Data flow, value propagation, rudimentary taint analysis |  
| **When to use in RE** | Always first | When suspecting integer calculations (crypto, hash, checksums) | When looking for sensitive data flow (keys, IV, secrets) |

---

## Sanitizers as a bridge to fuzzing

Sanitizers reach their full dimension when coupled with **fuzzing** (Chapter 15). A fuzzer like AFL++ generates thousands of inputs per second and executes them against the instrumented binary. Sanitizers detect errors triggered by these inputs and produce reports for each crash.

The fuzzer + ASan combination is the industry standard for vulnerability research. In RE, it allows **discovering code paths** you'd never have exercised manually and **characterizing the parser's behavior** on malformed inputs.

We'll deepen this combination in Chapter 15. For now, remember that sanitizers aren't just one-off analysis tools — they're the **detector** that gives value to the inputs generated by the fuzzer.

---


⏭️ [Leveraging sanitizer reports to understand internal logic](/14-valgrind-sanitizers/04-leveraging-reports.md)
