🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 16.2 — Function inlining: when the function disappears from the binary

> **Associated source file**: `binaries/ch16-optimisations/inlining_demo.c`  
> **Compilation**: `make s16_2` (produces 6 variants in `build/`)

---

## Introduction

In the previous section, we saw that the `square()` function disappeared from the binary in `-O2`. This phenomenon — **inlining** — is probably the compiler transformation with the most impact on the reverse engineer's work.

Inlining consists of replacing a function call (`call`) with a copy of the function's body directly in the caller. The result is a binary where certain functions no longer exist as independent entities: no symbol, no prologue, no address to set a breakpoint on. Their code is merged into the caller's, sometimes transformed beyond recognition after interaction with other optimization passes.

For the reverse engineer, inlining has direct consequences:

- The **call graph** reconstructed by Ghidra or IDA is incomplete. Functions that existed in the source appear nowhere.  
- The `main()` function (or another high-level function) becomes **abnormally long** — it contains the code of dozens of merged sub-functions.  
- **Cross-references** (XREF) to inlined functions don't exist, since the call was removed.  
- The **GDB backtrace** doesn't show inlined functions in the call stack (unless DWARF information is present and GDB knows how to exploit it).

This section explores the rules governing inlining in GCC, the scenarios where it occurs or not, and techniques for detecting and mentally "undoing" it during analysis.

---

## How GCC decides to inline a function

Inlining isn't a binary choice. GCC uses a set of heuristics to decide whether the benefit (eliminating the `call`/`ret` cost, opening new optimization opportunities) justifies the cost (increased code size, instruction cache pressure).

### The main criteria

**The estimated body size of the function.** GCC measures a function's complexity in "gimple statements" — an internal intermediate representation. A function with fewer than ~40 statements is considered "small" and eligible for inlining in `-O2`. The exact threshold is controlled by the parameter `--param max-inline-insns-auto` (default value: 40 in `-O2`).

**The number of call sites.** A function called only once is almost always inlined in `-O2`, regardless of its size — because inlining doesn't duplicate code in this case. Conversely, a function called 50 times will only be inlined if it's very small, to avoid `.text` size explosion.

**The function's linkage.** Only functions whose definition is visible at compile time can be inlined. Concretely:

- `static` functions defined in the same `.c` file are the first candidates.  
- Functions in other compilation units can only be inlined with `-flto` (Link-Time Optimization, cf. Section 16.5).  
- Shared library (`.so`) functions are **never** inlined — the compiler doesn't see their code.

**The optimization level.** Inlining is disabled in `-O0`, conservative in `-O1`, standard in `-O2`, and aggressive in `-O3`. In `-Os`, inlining is more restrictive than in `-O2` because code duplication increases binary size.

### The role of attributes

The developer can influence inlining decisions with GCC attributes:

- `__attribute__((always_inline))` + `static inline`: forces inlining, even if GCC deems it unprofitable. The body is duplicated at every call site, including in `-O0` (provided minimal optimization is enabled).  
- `__attribute__((noinline))`: prohibits inlining. The function remains an explicit `call` at all optimization levels. This is useful for profiling and debugging.  
- `inline` (C99/C++ keyword): it's a **suggestion**, not an order. GCC is free to ignore it. In practice, the `inline` keyword alone has little effect on GCC's decisions in `-O2` — automatic heuristics are more determining.

---

## Scenario 1 — Trivial functions: inlined from `-O1`

The shortest functions — getters, setters, single-expression computations — are systematically inlined from the first optimization level.

```c
typedef struct {
    int x;
    int y;
    int z;
} Vec3;

static int vec3_get_x(const Vec3 *v)
{
    return v->x;
}

static void vec3_set_x(Vec3 *v, int val)
{
    v->x = val;
}

static int vec3_length_squared(const Vec3 *v)
{
    return v->x * v->x + v->y * v->y + v->z * v->z;
}
```

### In `-O0`

Each function exists as an independent symbol with its own stack frame:

```asm
vec3_get_x:
    push   rbp
    mov    rbp, rsp
    mov    QWORD PTR [rbp-0x8], rdi     ; save pointer v
    mov    rax, QWORD PTR [rbp-0x8]
    mov    eax, DWORD PTR [rax]          ; read v->x
    pop    rbp
    ret
```

The call from `main()`:

```asm
    ; int vx = vec3_get_x(&v);
    lea    rdi, [rbp-0x20]               ; address of v
    call   vec3_get_x
    mov    DWORD PTR [rbp-0x24], eax     ; store vx on stack
```

Six "management" instructions (prologue, save, restore, epilogue) for a single useful instruction (`mov eax, [rax]`). The signal-to-noise ratio is catastrophic.

### In `-O1` and above

All three functions disappear. The `vec3_get_x(&v)` call is replaced by a direct memory access:

```asm
    ; int vx = vec3_get_x(&v) — inlined
    mov    eax, DWORD PTR [rsp+0x10]     ; direct read of v.x
```

And `vec3_length_squared(&v)`:

```asm
    ; vec3_length_squared inlined
    mov    eax, DWORD PTR [rsp+0x10]     ; v.x
    imul   eax, eax                       ; x*x
    mov    edx, DWORD PTR [rsp+0x14]     ; v.y
    imul   edx, edx                       ; y*y
    add    eax, edx                       ; x*x + y*y
    mov    edx, DWORD PTR [rsp+0x18]     ; v.z
    imul   edx, edx                       ; z*z
    add    eax, edx                       ; x*x + y*y + z*z
```

The `call` is replaced by the operations themselves. GCC can then apply further optimizations on this inlined code: if `v.x`'s value is already in a register (for example after `vec3_set_x`), it eliminates the redundant load.

### What RE should remember

If you're analyzing an optimized binary and see direct accesses to structure fields (`[rsp+offset]`) without a prior `call`, a getter/setter was likely inlined. Look for access patterns at fixed offsets from the same base pointer — this is often the sign of a structure whose accessors were absorbed.

---

## Scenario 2 — Medium-sized function: inlining depends on context

```c
static int transform_value(int input, int factor, int offset)
{
    int result = input;
    result = result * factor;
    result = result + offset;
    if (result < 0)
        result = -result;
    result = result % 1000;
    if (result > 500)
        result = 1000 - result;
    return result;
}
```

This function has about ten "gimple statements." It's in the inlining grey zone: small enough to be inlined if called few times, but large enough for GCC to hesitate if it's called everywhere.

### Single call site → inlined in `-O2`

If `transform_value` is called only once in the program, GCC systematically inlines it in `-O2`. The reason is simple: inlining doesn't duplicate code when there's only one caller. The binary is even potentially smaller, since the function's prologue/epilogue disappears.

After inlining, the code ends up integrated in `main()`, and GCC can apply additional optimizations that wouldn't have been possible without inlining. For example, if `factor` equals 7 (a constant known in `main()`), GCC can propagate this constant and replace `imul` with a `lea` + `shl` combination.

### Multiple call sites → size threshold

If you call `transform_value` at 10 different locations, GCC duplicates the body 10 times. For a function of this size, the code size cost outweighs: GCC leaves a classic `call`.

The threshold isn't absolute — it depends on body size, number of sites, and the `--param max-inline-insns-auto` flag. In `-O3`, the threshold is raised and larger functions are inlined even with multiple callers.

### How to verify

```bash
# Count symbols in O0 vs O2
nm build/inlining_demo_O0 | grep 'transform_value'
# → t transform_value   (local symbol present)

nm build/inlining_demo_O2 | grep 'transform_value'
# → (nothing — the function was inlined)
```

If `transform_value` appears in `nm` at `-O2`, it wasn't inlined (too many callers or too large). If it doesn't appear, it's inlined.

---

## Scenario 3 — Large function: resists inlining

```c
static int heavy_computation(const int *data, int len)
{
    int acc = 0;
    int min_val = data[0];
    int max_val = data[0];

    for (int i = 0; i < len; i++) {
        acc += data[i] * data[i];
        if (data[i] < min_val) min_val = data[i];
        if (data[i] > max_val) max_val = data[i];
    }

    int range = max_val - min_val;
    if (range == 0) range = 1;

    int normalized = 0;
    for (int i = 0; i < len; i++) {
        normalized += ((data[i] - min_val) * 100) / range;
    }

    int checksum = 0;
    for (int i = 0; i < len; i++) {
        checksum ^= (data[i] << (i % 8));
        checksum = (checksum >> 3) | (checksum << 29);
    }

    return acc + normalized + checksum;
}
```

This function contains three loops, branches, and a significant code volume. Even in `-O3`, GCC keeps it as a separate function with an explicit `call`.

### In `-O2`

```bash
nm build/inlining_demo_O2 | grep 'heavy_computation'
# → t heavy_computation   (still present!)
```

The function appears as a local symbol `t` — it has its own prologue, epilogue, and `main()` calls it with a `call`.

```asm
    ; in main()
    lea    rdi, [rsp+0x30]              ; data[]
    mov    esi, 8                        ; len = 8
    call   heavy_computation
```

This is good news for RE: large functions remain identifiable entities in the binary, even optimized. You can analyze them separately, set breakpoints on them, and name them in Ghidra.

### The lesson for RE

As a general rule, if a function has more than 30–50 instructions in `-O0`, it will survive inlining. It's the "small" functions (getters, wrappers, one-line utilities) that disappear. Functions with loops, complex conditional code, or calls to other functions resist.

---

## Scenario 4 — Recursion: never directly inlined

```c
static int fibonacci(int n)
{
    if (n <= 1)
        return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}
```

Inlining a recursive function is generally impossible: the recursion depth isn't known at compile time, so the compiler can't "unroll" all levels.

### What GCC actually does

In `-O2`, `fibonacci` remains a recursive function with two `call fibonacci` in its body. However, GCC can apply a subtle optimization in `-O3`: **partial recursion unrolling**. It inlines one or two levels of the recursive call, creating an "unrolled" version that reduces the number of actual calls.

Concretely, GCC can transform this:

```c
// Conceptually, one level of unrolling:
return fibonacci(n - 1) + fibonacci(n - 2);
// ↓ inline fibonacci(n-1):
// = (fibonacci(n-2) + fibonacci(n-3)) + fibonacci(n-2);
```

In the disassembly, this manifests as a larger function body with `call fibonacci` but at shifted depths. The pattern remains recognizable: a function that calls itself is always recursive, even if the compiler unrolled one level.

### Comparison with the iterative version

```c
static int fibonacci_iter(int n)
{
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}
```

`fibonacci_iter` isn't recursive — it's a simple loop. In `-O2`, it's inlined in `main()` (single call site, reasonable size), and the loop is optimized with registers:

```asm
    ; fibonacci_iter inlined
    cmp    edi, 1
    jle    .L_base_case
    xor    eax, eax                     ; a = 0
    mov    ecx, 1                       ; b = 1
    mov    edx, 2                       ; i = 2
.L_fib_loop:
    lea    esi, [rax+rcx]              ; tmp = a + b
    mov    eax, ecx                     ; a = b
    mov    ecx, esi                     ; b = tmp
    add    edx, 1                       ; i++
    cmp    edx, edi
    jle    .L_fib_loop
    ; ecx = result
```

The contrast is striking: the iterative version is compact and entirely in registers, while the recursive version retains `call`s and stack growth proportional to `n`.

### What RE should remember

When encountering a `call` to the function itself in an optimized binary, you've confirmed a recursion — the compiler couldn't eliminate it. If the recursion was terminal (tail recursion), it may have been transformed into a loop by tail call optimization (Section 16.4), in which case there's no longer a visible recursive `call`.

---

## Scenario 5 — Indirect call: inlining is impossible

```c
typedef int (*operation_fn)(int, int);

static int op_add(int a, int b) { return a + b; }  
static int op_sub(int a, int b) { return a - b; }  
static int op_mul(int a, int b) { return a * b; }  

static int apply_operation(operation_fn op, int a, int b)
{
    return op(a, b);    /* indirect call */
}
```

When a function is called via a pointer, the compiler doesn't know at compile time which function will be executed. It therefore can't copy a specific body — inlining is impossible.

### In `-O2`

The indirect call remains a `call` via a register:

```asm
    ; apply_operation — the indirect call persists
    call   rax                          ; call via function pointer
```

Or, if `apply_operation` itself is inlined in `main()`:

```asm
    ; in main() — apply_operation inlined but indirect call remains
    mov    rax, QWORD PTR [rsp+rbx*8]   ; load ops[input % 3]
    mov    edi, r12d                     ; a = input
    lea    esi, [r12+5]                  ; b = input + 5
    call   rax                           ; indirect call
```

The `call rax` is the signature of an indirect call. In C++, virtual calls (via vtable) produce exactly the same pattern: `call [register + offset]`.

### Devirtualization

There's a special case: if GCC can **prove** which function will be called despite the pointer (for example, if the pointer is initialized with a constant just before the call), it can "devirtualize" the call and inline the target function. This is rare without LTO, but possible:

```c
operation_fn op = op_add;   // known constant  
int result = op(3, 4);      // GCC can inline op_add  
```

In `-O2`, GCC can transform this into a simple `lea eax, [3+4]` → `mov eax, 7`. But if the pointer comes from an array or a condition, devirtualization fails.

### What RE should remember

A `call rax` or `call [reg+offset]` in an optimized binary is an **indirect call** — the compiler couldn't resolve the target. Your RE work is to trace back the chain to find where the register's value comes from:

1. Look for the last `mov` or `lea` that writes to the register used by the `call`.  
2. Trace back to the source: an array of function pointers, a vtable, a callback passed as parameter.  
3. Identify the possible targets — these are the functions whose address is stored in that array or vtable.

---

## Scenario 6 — Inlining chain: A → B → C

When function A calls B which calls C, and both B and C are eligible for inlining, GCC merges them in cascade. The result is that C's body ends up directly in A, with no trace of B.

```c
static int step_c(int x)
{
    return x * 3 + 1;
}

static int step_b(int x)
{
    int tmp = step_c(x);
    return tmp + step_c(tmp);
}

static int step_a(int x)
{
    return step_b(x) + step_b(x + 1);
}
```

### In `-O0`

The call graph is complete — three functions, three levels:

```
main() → step_a() → step_b() → step_c()
```

You can set a breakpoint on each, observe arguments, walk up the stack. Ghidra's graph shows all XREFs.

### In `-O2`

All three functions are merged. `step_c` is inlined into `step_b`, then `step_b` (which now contains `step_c`'s code) is inlined into `step_a`, which is itself inlined into `main()`.

The result in `main()`:

```asm
    ; step_a(input) — everything inlined
    ; step_c(x) = x * 3 + 1

    ; step_b(x) = step_c(x) + step_c(step_c(x))
    ; = (x*3+1) + ((x*3+1)*3+1)
    ; = (x*3+1) + (x*9+3+1)
    ; = (x*3+1) + (x*9+4)
    ; = x*12 + 5

    ; step_a(x) = step_b(x) + step_b(x+1)
    ; = (x*12+5) + ((x+1)*12+5)
    ; = x*12+5 + x*12+12+5
    ; = x*24 + 22

    ; GCC can reduce all this to:
    lea    eax, [rdi*8]                 ; eax = x * 8
    lea    eax, [rax+rdi*2]            ; eax = x * 8 + x * 2 = x * 10
    lea    eax, [rax+rdi*2]            ; eax = x * 10 + x * 2 = x * 12
    ; ... or another lea combination to reach x*24+22
```

Depending on the GCC version, the result can be even simpler: GCC evaluates the complete algebraic expression and produces the closed formula `x * 24 + 22` in a few instructions.

### Impact on the call graph

```bash
# In O0 — 4 visible functions
nm build/inlining_demo_O0 | grep -E 'step_[abc]|main'
# → t step_a
# → t step_b
# → t step_c
# → T main

# In O2 — only main survives
nm build/inlining_demo_O2 | grep -E 'step_[abc]|main'
# → T main
```

In Ghidra, the call graph of `main()` in `-O2` shows no reference to `step_a`, `step_b`, or `step_c`. Two entire levels of abstraction have disappeared.

### What RE should remember

When you see an abnormally long `main()` function in an optimized binary, with sequences of arithmetic computation that don't seem to match an obvious logic, consider the hypothesis of an inlining chain. The compiler may have merged 3, 4, or 5 function levels and algebraically simplified the result.

To reconstruct the layers, look for "logical blocks" in the code: groups of instructions that compute an intermediate result reused later. Each block was potentially a separate function in the source.

---

## Scenario 7 — Explicit control: `noinline` and `always_inline`

```c
__attribute__((noinline))
static int forced_noinline(int x)
{
    return x * x + x + 1;
}

__attribute__((always_inline))
static inline int forced_inline(int x)
{
    int result = x;
    for (int i = 0; i < 10; i++) {
        result = (result * 31) ^ (result >> 3);
    }
    return result;
}
```

### `noinline` — the function survives at all costs

Even in `-O3`, `forced_noinline` remains an explicit `call`:

```asm
    ; in main()
    mov    edi, r12d
    call   forced_noinline              ; explicit call, even in O3
```

```bash
nm build/inlining_demo_O3 | grep forced_noinline
# → t forced_noinline   (still present)
```

This is a valuable tool for developers who want to keep anchor points in the binary (for profiling, for example). For RE, a `noinline` function is identifiable by the fact that it exists as a symbol while equivalent or larger functions were inlined — it's a clue that the developer explicitly marked the function.

### `always_inline` — forced duplication

`forced_inline` is duplicated at **every** call site, regardless of code size. If called 3 times, its body appears 3 times in the binary:

```asm
    ; First call: forced_inline(input)
    mov    eax, r12d
    ; Unrolled loop (10 iterations → 10x the body)
    imul   ecx, eax, 31
    mov    edx, eax
    sar    edx, 3
    xor    ecx, edx                     ; result = (result*31) ^ (result>>3)
    imul   eax, ecx, 31
    mov    edx, ecx
    sar    edx, 3
    xor    eax, edx
    ; ... (8 more iterations)
    ; result in eax

    ; ... later in main() ...

    ; Second call: forced_inline(input + 1)
    lea    eax, [r12+1]
    ; Same sequence duplicated entirely
    imul   ecx, eax, 31
    mov    edx, eax
    sar    edx, 3
    xor    ecx, edx
    ; ... etc.
```

The loop code (10 iterations × a few instructions) is duplicated at each call site. In `-O3`, the loop is furthermore completely unrolled, producing a long linear sequence without any `jmp`.

### What RE should remember

If you see the **same instruction pattern** duplicated at several locations in an optimized binary, it's probably an `always_inline` function (or a C macro, which has a similar effect). Look for repeated sequences: same opcodes, same constants (`31`, `>> 3`), same structure — only the input registers change.

This pattern is also frequent in inline implementations of cryptographic primitives (SHA-256 rounds, AES, etc.) and in macros like `MIN()` / `MAX()`.

---

## Inlining and DWARF information

An often overlooked aspect: even when a function is inlined, DWARF debug information (if the binary is compiled with `-g`) can preserve a trace of the inlining. The `.debug_info` section contains `DW_TAG_inlined_subroutine` entries that indicate:

- The name of the inlined function.  
- The source file and line number of the original call.  
- The address range in the binary where the inlined code resides.

GDB exploits this information. When you step into optimized code with `-O2 -g`, GDB can display the inlined function's name in the backtrace:

```
#0  0x00401234 in main ()
    inlined from vec3_get_x at inlining_demo.c:52
```

Ghidra can also read DWARF and annotate inlined regions in the decompiler — provided the binary hasn't been stripped.

On a stripped binary (`-s`), all this information disappears. Only the raw code remains, and it's up to you to reconstruct inlined functions through pattern analysis.

---

## Summary: when is a function inlined?

| Function characteristic | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |  
|---|---|---|---|---|---|  
| Trivial (1–3 useful instructions) | No | Yes | Yes | Yes | Yes |  
| Medium size, 1 call site | No | Possible | Yes | Yes | Possible |  
| Medium size, N call sites | No | No | Possible | Yes | No |  
| Large (loops, branches) | No | No | No | Rarely | No |  
| Recursive | No | No | No | Partial (1–2 levels) | No |  
| Indirect call (function pointer) | No | No | No | No | No |  
| `__attribute__((always_inline))` | No* | Yes | Yes | Yes | Yes |  
| `__attribute__((noinline))` | No | No | No | No | No |

*\* `always_inline` can work in `-O0` if the function is also declared `static inline` and GCC has the minimum required support, but behavior varies across versions.*

---

## Techniques for detecting inlining in RE

Here's a practical methodology for identifying inlined functions in a binary you're analyzing:

**1. Compare function count with a reference `-O0` binary.** If you have access to the non-optimized binary (or can recompile it), compare the number of `T`/`t` symbols in `nm`. Functions missing in `-O2` were inlined.

**2. Look for "disconnected" code blocks in `main()`.** In Ghidra, if `main()` has 300 lines of decompilation when a similar program should have 30, the bulk is inlined code. Identify "logical blocks" — sequences that compute an intermediate result — and name them as sub-functions.

**3. Spot recurring constants.** If the same magic constant (e.g., `0x5F3759DF`, `31`, `0x9E3779B9`) appears at multiple locations in the binary, it's probably a utility function (hash, checksum) that was inlined at each call site. Each occurrence is a copy of the same body.

**4. Look for duplicated code patterns.** With `objdump -d`, look for identical opcode sequences appearing at different addresses. If the same sequence of 10 instructions (same opcodes, same constants, different registers) appears 3 times in `main()`, it's a function inlined 3 times.

**5. Use DWARF information if available.** On a binary with symbols (`-g`), run:

```bash
readelf --debug-dump=info build/inlining_demo_O2 | grep -A 2 'DW_TAG_inlined_subroutine'
```

This lists all inlined functions with their original name and address range.

**6. Use Compiler Explorer to verify hypotheses.** If you suspect a code block is a standard inlined function (e.g., `strlen`, `abs`, a known hash), type the candidate function on [godbolt.org](https://godbolt.org) with the same compiler and optimization level. Compare the produced assembly pattern with what you see in the binary.

---


⏭️ [Loop unrolling and vectorization (SIMD/SSE/AVX)](/16-compiler-optimizations/03-unrolling-vectorization.md)
