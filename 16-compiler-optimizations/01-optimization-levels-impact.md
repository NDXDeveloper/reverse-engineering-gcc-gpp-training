🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 16.1 — Impact of `-O1`, `-O2`, `-O3`, `-Os` on disassembled code

> **Associated source file**: `binaries/ch16-optimisations/opt_levels_demo.c`  
> **Compilation**: `make s16_1` (produces 6 variants in `build/`)

---

## Introduction

When you run `gcc -O0 program.c`, the compiler translates your C code into assembly in the most literal way possible: each variable lives on the stack, each operation generates the corresponding instructions in the order you wrote them, and each function call produces an explicit `call`. It's "readable" assembly — almost a word-for-word translation.

As soon as you go up a notch with `-O1`, then `-O2`, `-O3`, or `-Os`, GCC progressively activates hundreds of optimization passes that transform this code in depth. The result is faster (or more compact), but its structure can become unrecognizable compared to the original source.

For the reverse engineer, understanding what each optimization level does is a fundamental skill. It allows answering the question that arises with every unknown binary: *does what I see in the disassembly reflect the developer's logic, or a compiler transformation?*

---

## Overview of optimization levels

Before diving into disassembly, it's essential to understand what each flag activates. GCC groups its optimization passes into cumulative levels — each level includes all passes from the previous level, plus additional ones.

### `-O0` — No optimization

This is the default level. GCC performs no transformations:

- Each local variable is allocated on the stack (in the function's frame).  
- Each variable read produces a `mov` from the stack, each write a `mov` to the stack — even if the value was just computed in a register.  
- Each function call produces an explicit `call`, even for trivial `static` functions.  
- Branches follow exactly the if/else structure of the source.  
- No code reorganization, no dead code elimination.

This is the ideal level for learning RE because the source → assembly correspondence is direct. It's also the level used with `-g` for debugging, since breakpoints and line-by-line stepping work predictably.

### `-O1` — Conservative optimizations

GCC begins to transform the code, but remains cautious:

- **Register allocation**: frequently used local variables are placed in registers instead of the stack. Unnecessary load/stores disappear.  
- **Constant propagation**: if a variable always equals 42, GCC replaces its usage with the immediate 42.  
- **Dead code elimination**: code whose result is never used is removed.  
- **Algebraic simplification**: `x * 1` → `x`, `x + 0` → `x`, `x * 2` → `x + x` or `shl`.  
- Simple **branch merging**.  
- **Inlining of trivial functions** marked `static` and called only once.

The code remains relatively faithful to the source structure, but variables live in registers, making tracking in GDB slightly less straightforward.

### `-O2` — Standard optimizations (the production case)

This is the most common level in binaries you'll encounter in RE. It adds to `-O1`:

- **More aggressive inlining**: reasonably sized `static` functions are inlined, even if called multiple times.  
- **Partial loop unrolling**: a loop of N iterations can be transformed into a loop of N/2 iterations processing 2 elements per turn.  
- **Instruction reordering**: GCC rearranges instructions to maximize CPU pipeline parallelism. Assembly order no longer matches source line order.  
- **Division replacement with multiplications**: `x / 7` becomes a multiplication by a "magic number" followed by a shift (detail in Section 16.6).  
- **Conditional moves** (`cmov`): simple branches (ternary-type `a > b ? a : b`) are replaced with `cmov` instructions that avoid branch mispredictions.  
- **Peephole optimizations**: replacing instruction sequences with shorter equivalents (`lea` instead of `add` + `mov`, etc.).  
- **Tail call optimization**: a call in tail position is replaced by a `jmp` (detail in Section 16.4).  
- **Common subexpression elimination** (CSE): if `a * b` is computed twice, GCC computes it once and reuses the result.

### `-O3` — Aggressive optimizations

Adds to `-O2` transformations that increase code size in exchange for performance:

- **Automatic vectorization**: loops over arrays are transformed to use SIMD instructions (SSE, AVX). Instead of processing one `int` per iteration, GCC processes 4 (SSE, 128 bits) or 8 (AVX, 256 bits) in parallel.  
- **Aggressive loop unrolling**: loops are unrolled more than in `-O2`.  
- **Even more aggressive inlining**: the size threshold for inlining is raised.  
- **Function cloning**: the same function can be duplicated with different specializations depending on the call context.  
- **Loop interchange**, **loop fusion**, **loop distribution**.

`-O3` code is often noticeably larger than `-O2` code, and its structure can diverge considerably from the source. For RE, this is the most demanding level to analyze.

### `-Os` — Size optimization

Activates the same passes as `-O2`, **except those that increase code size**:

- No loop unrolling.  
- No vectorization (SIMD instructions add prologue/epilogue code).  
- More conservative inlining (the size cost of duplication outweighs the gain).  
- Preference for compact loops and function calls.  
- Use of `rep stosb` / `rep movsb` rather than unrolled `mov` sequences.

`-Os` is found in embedded firmware, bootloaders, and certain binaries where `.text` segment size is critical. For RE, `-Os` produces code closer to `-O1` in terms of readability, while using the same algebraic transformations as `-O2` (magic numbers for divisions, `cmov`, etc.).

---

## Concrete comparisons on `opt_levels_demo.c`

Throughout this section, disassembly examples use Intel syntax (obtained with `objdump -d -M intel`). Exact addresses and offsets may vary depending on your GCC version; it's the **structural patterns** that matter.

> 💡 **Reproduce at home**: after `make s16_1`, use the Makefile's utility command:  
> ```bash  
> make disasm_compare BIN=opt_levels_demo  
> ```

### Case 1 — Simple arithmetic function: `square()`

The `square()` function is a textbook case — a single computation, a single parameter:

```c
static int square(int x)
{
    return x * x;
}
```

#### In `-O0`

The function exists as a standalone symbol, with its own prologue and epilogue:

```asm
square:
    push   rbp
    mov    rbp, rsp
    mov    DWORD PTR [rbp-0x4], edi    ; save x to stack
    mov    eax, DWORD PTR [rbp-0x4]    ; reload x from stack
    imul   eax, DWORD PTR [rbp-0x4]    ; eax = x * x (stack read)
    pop    rbp
    ret
```

The parameter `x` arrives in `edi` (System V convention), is copied to the stack, then reloaded from the stack for the multiplication. This is absurd in terms of performance, but this is what `-O0` produces: a systematic stack round-trip for every variable.

When `main()` calls `square(input)`, we see an explicit `call square`:

```asm
    ; in main(), calling square(input)
    mov    edi, DWORD PTR [rbp-0x14]   ; load input from stack
    call   square                       ; explicit call
    mov    DWORD PTR [rbp-0x18], eax   ; store result to stack
```

#### In `-O2`

The `square()` function **completely disappears** from the binary. GCC inlines it at each call site. Where `main()` called `square(input)`, we simply find:

```asm
    ; in main() — square(input) inlined
    imul   ebx, ebx                    ; ebx = input * input (1 instruction)
```

No `call`, no prologue, no stack access. The variable `input` is already in `ebx` (register allocation), and the result `sq` also stays in a register for immediate reuse.

If you look for the `square` symbol in the symbol table (`nm build/opt_levels_demo_O2`), it no longer exists. For the reverse engineer, the function has been **absorbed** — it must be mentally reconstructed.

#### What to remember

In `-O0`, every function, even trivial ones, is a `call` with prologue/epilogue. In `-O2`, trivial `static` functions are systematically inlined. If you're analyzing an optimized binary and can't find a `square` function in Ghidra, that's normal — it no longer exists as an independent entity.

---

### Case 2 — Conditional branch: `clamp()`

```c
static int clamp(int value, int low, int high)
{
    if (value < low)
        return low;
    if (value > high)
        return high;
    return value;
}
```

#### In `-O0`

The source code structure is faithfully reproduced with two comparisons and two conditional jumps:

```asm
clamp:
    push   rbp
    mov    rbp, rsp
    mov    DWORD PTR [rbp-0x4], edi     ; value
    mov    DWORD PTR [rbp-0x8], esi     ; low
    mov    DWORD PTR [rbp-0xc], edx     ; high

    ; if (value < low)
    mov    eax, DWORD PTR [rbp-0x4]
    cmp    eax, DWORD PTR [rbp-0x8]
    jge    .L_not_low                   ; jump if value >= low
    mov    eax, DWORD PTR [rbp-0x8]     ; return low
    jmp    .L_end

.L_not_low:
    ; if (value > high)
    mov    eax, DWORD PTR [rbp-0x4]
    cmp    eax, DWORD PTR [rbp-0xc]
    jle    .L_not_high                  ; jump if value <= high
    mov    eax, DWORD PTR [rbp-0xc]     ; return high
    jmp    .L_end

.L_not_high:
    mov    eax, DWORD PTR [rbp-0x4]     ; return value

.L_end:
    pop    rbp
    ret
```

You can read the assembly code almost like C — two `cmp` + `jge`/`jle`, three exit paths. Each variable access goes through the stack.

#### In `-O2`

GCC replaces the branches with two `cmov` instructions — **conditional moves** that avoid any jump:

```asm
    ; clamp inlined in main()
    ; edi = value, esi = low, edx = high  (or already in registers)
    cmp    edi, esi
    cmovl  edi, esi        ; if (value < low) value = low
    cmp    edi, edx
    cmovg  edi, edx        ; if (value > high) value = high
    ; edi contains the result
```

Four instructions, zero branches. It's faster because the CPU doesn't have to predict a branch, and it's also more compact.

#### How to recognize it in RE

When you see a `cmp` + `cmovCC` sequence in an optimized binary, you can mentally "de-optimize" it into a simple if/else. Common variants are `cmovl` / `cmovg` (signed), `cmovb` / `cmova` (unsigned), `cmove` / `cmovne` (equality).

A common pitfall: `cmov` computes **both** possible values before the condition. If one of the branches has a side effect (function call, memory write), GCC cannot use `cmov` and falls back to a classic branch.

---

### Case 3 — Switch/case: `classify_grade()`

```c
static const char *classify_grade(int score)
{
    switch (score / 10) {
        case 10:
        case 9:  return "A";
        case 8:  return "B";
        case 7:  return "C";
        case 6:  return "D";
        case 5:  return "E";
        default: return "F";
    }
}
```

#### In `-O0`

GCC generates a **comparison cascade** — a linear sequence of `cmp` + `je` (jump if equal):

```asm
classify_grade:
    push   rbp
    mov    rbp, rsp
    mov    DWORD PTR [rbp-0x4], edi

    ; Compute score / 10 (via idiv)
    mov    eax, DWORD PTR [rbp-0x4]
    cdq
    mov    ecx, 10
    idiv   ecx                          ; eax = score / 10
    mov    DWORD PTR [rbp-0x8], eax

    ; Comparison cascade
    cmp    DWORD PTR [rbp-0x8], 10
    je     .L_case_A
    cmp    DWORD PTR [rbp-0x8], 9
    je     .L_case_A
    cmp    DWORD PTR [rbp-0x8], 8
    je     .L_case_B
    cmp    DWORD PTR [rbp-0x8], 7
    je     .L_case_C
    ; ... etc.
    jmp    .L_default

.L_case_A:
    lea    rax, [rip+str_A]             ; "A"
    jmp    .L_end
; ... etc.
```

Each `case` produces a `cmp` + `je`. The compiler tests them in order. It's simple to read but inefficient for a large number of cases.

#### In `-O2`

GCC applies two optimizations simultaneously:

1. **The division by 10** is replaced by a multiplication by the magic number (cf. Section 16.6).  
2. **The switch is transformed into a jump table** — an array of pointers stored in `.rodata`.

```asm
    ; Division by 10 via magic number
    mov    eax, edi
    mov    edx, 0x66666667              ; magic number for /10
    imul   edx
    sar    edx, 2                       ; edx = score / 10
    mov    eax, edi
    sar    eax, 31
    sub    edx, eax                     ; correction for negatives

    ; Jump table bounds check
    sub    edx, 5                       ; normalize: case 5 → index 0
    cmp    edx, 5
    ja     .L_default                   ; out of bounds → "F"

    ; Indirect jump via table
    lea    rax, [rip+.L_jumptable]
    movsxd rdx, DWORD PTR [rax+rdx*4]  ; load offset from table
    add    rax, rdx
    jmp    rax                          ; jump to the right case
```

The jump table is a data block in `.rodata` containing the relative offsets of each case. Instead of N comparisons, the CPU performs a single indexed memory access + an indirect jump. Complexity goes from O(N) to O(1).

#### How to recognize it in RE

The jump table pattern is one of the most important to recognize:

1. A `cmp` + `ja` that checks bounds (protection against an out-of-table index).  
2. A `lea` that loads the table's base address.  
3. An indexed access `[base + index*4]` (or `*8` in 64-bit).  
4. A `jmp rax` — the indirect jump.

Ghidra automatically recognizes jump tables and reconstructs the switch in the decompiler. But if the binary is obfuscated or the table is relocated, you need to know how to spot it manually by looking for the `lea` + `movsxd` + `add` + `jmp reg` pattern.

In `-Os`, GCC often prefers to **keep the comparison cascade** rather than the jump table, because the table takes up space in `.rodata`. This is a clue for identifying the optimization flag used.

---

### Case 4 — Accumulation loop: `sum_of_squares()`

```c
static long sum_of_squares(int n)
{
    long total = 0;
    for (int i = 1; i <= n; i++) {
        total += square(i);
    }
    return total;
}
```

#### In `-O0`

The loop is translated literally: counter on the stack, accumulator on the stack, `call square` at each iteration.

```asm
sum_of_squares:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 0x18
    mov    DWORD PTR [rbp-0x14], edi    ; n on stack

    ; total = 0
    mov    QWORD PTR [rbp-0x8], 0

    ; i = 1
    mov    DWORD PTR [rbp-0xc], 1

.L_loop_check:
    ; i <= n ?
    mov    eax, DWORD PTR [rbp-0xc]
    cmp    eax, DWORD PTR [rbp-0x14]
    jg     .L_loop_end

    ; call square(i)
    mov    edi, DWORD PTR [rbp-0xc]     ; load i from stack
    call   square
    cdqe                                ; sign-extend 32→64 bits
    add    QWORD PTR [rbp-0x8], rax     ; total += result

    ; i++
    add    DWORD PTR [rbp-0xc], 1

    jmp    .L_loop_check

.L_loop_end:
    mov    rax, QWORD PTR [rbp-0x8]     ; return total
    leave
    ret
```

Each iteration does two stack accesses (read `i`, write `total`) and a `call` to `square`. It's verbose but perfectly readable.

#### In `-O2`

GCC applies several cascading transformations:

1. `square(i)` is inlined — the `call` disappears, replaced by an `imul`.  
2. `i` and `total` live in registers — no stack access.  
3. The loop may be partially unrolled (2 iterations per turn).

```asm
    ; sum_of_squares inlined in main()
    ; ecx = n (already in a register)
    xor    eax, eax                     ; total = 0
    test   ecx, ecx
    jle    .L_done                      ; if n <= 0, skip
    mov    edx, 1                       ; i = 1

.L_loop:
    mov    esi, edx
    imul   esi, edx                     ; esi = i * i  (square inlined)
    movsxd rsi, esi
    add    rax, rsi                     ; total += i*i
    add    edx, 1                       ; i++
    cmp    edx, ecx
    jle    .L_loop                      ; loop

.L_done:
    ; rax = total (result)
```

The loop is reduced to 5 useful instructions per iteration: `imul`, `movsxd`, `add`, `add`, `cmp`+`jle`. No memory access, everything in registers.

#### In `-O3`

In addition to what `-O2` does, GCC can:

- **Unroll the loop** (process 2 or 4 iterations per turn).  
- **Vectorize** if the body allows it (here, `long` accumulation and `imul` make vectorization difficult, so GCC often settles for unrolling).

The unrolling produces code like:

```asm
.L_loop_unrolled:
    ; Iteration i
    mov    esi, edx
    imul   esi, edx
    movsxd rsi, esi
    add    rax, rsi

    ; Iteration i+1 (unrolled)
    lea    esi, [edx+1]
    imul   esi, esi
    movsxd rsi, esi
    add    rax, rsi

    add    edx, 2                       ; i += 2
    cmp    edx, ecx
    jle    .L_loop_unrolled

    ; + "epilogue" loop for remainder if n is odd
```

The number of loop iterations is divided by 2, at the cost of a doubled loop body. You recognize an unrolling by the fact that the counter is incremented by 2 (or 4, 8…) instead of 1.

---

### Case 5 — Division by constant and magic numbers: `compute()`

```c
static int compute(int a, int b)
{
    int data[8];
    for (int i = 0; i < 8; i++)
        data[i] = a * (i + 1) + b;

    int result = 0;
    for (int i = 0; i < 8; i++)
        result += data[i] / 7;

    result += data[3] % 5;
    return result;
}
```

#### In `-O0`

The division by 7 uses the `idiv` instruction — a real hardware division:

```asm
    ; result += data[i] / 7
    mov    eax, DWORD PTR [rbp+rax*4-0x30]  ; load data[i]
    cdq                                      ; sign extension → edx:eax
    mov    ecx, 7
    idiv   ecx                               ; eax = quotient, edx = remainder
    add    DWORD PTR [rbp-0x34], eax         ; result += quotient
```

The `idiv` instruction is one of the slowest in the x86 instruction set — it takes between 20 and 90 cycles depending on the CPU. That's why GCC replaces it starting from `-O1`.

#### In `-O2`

GCC replaces `x / 7` with a multiplication by the "magic number" `0x92492493` (or a variant depending on sign) followed by a shift:

```asm
    ; data[i] / 7  via magic number
    mov    eax, DWORD PTR [rsp+rsi*4]       ; load data[i]
    mov    edx, 0x92492493                   ; magic number for /7
    imul   edx                               ; edx:eax = x * magic
    ; edx contains the high-order bits of the product
    add    edx, eax                          ; correction (specific to /7)
    sar    edx, 2                            ; arithmetic shift
    mov    ecx, edx
    shr    ecx, 31                           ; extract sign bit
    add    edx, ecx                          ; final correction for negatives
    ; edx = x / 7
```

This pattern is explained in detail in Section 16.6. The key idea for RE: when you see an `imul` by an improbable hexadecimal constant followed by `sar`, you're looking at a transformed division by constant. The original divisor can be recovered from the magic number.

Similarly, `data[3] % 5` is transformed into: compute `x / 5` via magic number, then `x - (x/5) * 5`.

---

### Case 6 — Parameter passing: `multi_args()`

```c
static int multi_args(int a, int b, int c, int d, int e, int f, int g, int h)
{
    return (a + b) * (c - d) + (e ^ f) - (g | h);
}
```

#### In `-O0`

The System V AMD64 convention passes the first 6 integer parameters in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`. The rest go through the stack. In `-O0`, **all** are copied to the stack in the prologue:

```asm
multi_args:
    push   rbp
    mov    rbp, rsp

    ; Save the 6 register parameters to the stack
    mov    DWORD PTR [rbp-0x4],  edi    ; a
    mov    DWORD PTR [rbp-0x8],  esi    ; b
    mov    DWORD PTR [rbp-0xc],  edx    ; c
    mov    DWORD PTR [rbp-0x10], ecx    ; d
    mov    DWORD PTR [rbp-0x14], r8d    ; e
    mov    DWORD PTR [rbp-0x18], r9d    ; f
    ; g and h are already on the stack (above the return address)
    ; g = [rbp+0x10], h = [rbp+0x18]

    ; (a + b)
    mov    eax, DWORD PTR [rbp-0x4]
    add    eax, DWORD PTR [rbp-0x8]
    ; (c - d)
    mov    edx, DWORD PTR [rbp-0xc]
    sub    edx, DWORD PTR [rbp-0x10]
    ; (a+b) * (c-d)
    imul   eax, edx
    ; ... etc.
```

#### In `-O2`

If the function is inlined, all computation is done in registers without any stack access. If it's not inlined (for example if it were `__attribute__((noinline))`), parameters stay in their arrival registers without being copied to the stack:

```asm
multi_args:
    ; No prologue — optimized leaf function
    lea    eax, [rdi+rsi]          ; eax = a + b
    mov    r10d, edx
    sub    r10d, ecx               ; r10d = c - d
    imul   eax, r10d               ; eax = (a+b) * (c-d)
    xor    r8d, r9d                ; r8d = e ^ f
    add    eax, r8d                ; eax += (e ^ f)
    mov    r10d, DWORD PTR [rsp+0x8]
    or     r10d, DWORD PTR [rsp+0x10]  ; r10d = g | h (from stack)
    sub    eax, r10d               ; eax -= (g | h)
    ret
```

Note that `g` and `h` (the 7th and 8th parameters) are still read from the stack — the calling convention requires it. But the first 6 are never saved.

---

### Case 7 — Library call: `print_info()`

```c
static void print_info(const char *label, int value)
{
    printf("[%s] (len=%zu) = %d\n", label, strlen(label), value);
}
```

#### In `-O0`

The call to `strlen` generates a `call strlen@plt` — a call via the PLT (Procedure Linkage Table) to the C library:

```asm
    ; strlen(label)
    mov    rdi, QWORD PTR [rbp-0x8]    ; load label
    call   strlen@plt                   ; dynamic call via PLT

    ; printf(format, label, strlen_result, value)
    mov    rcx, QWORD PTR [rbp-0x8]    ; label → rsi
    mov    rdx, rax                     ; strlen result → rdx
    mov    r8d, DWORD PTR [rbp-0xc]    ; value → rcx (after shift)
    lea    rdi, [rip+.LC_fmt]          ; format string → rdi
    call   printf@plt
```

#### In `-O2`

If `label` is a constant known at compile time (which is the case in our calls like `print_info("square", sq)`), GCC **evaluates `strlen` at compile time** and replaces it with a constant:

```asm
    ; print_info("square", sq) — inlined
    ; strlen("square") = 6 — evaluated at compile time
    mov    edx, 6                       ; strlen resolved to constant!
    lea    rsi, [rip+.LC_square]        ; "square"
    mov    ecx, ebx                     ; value (already in a register)
    lea    rdi, [rip+.LC_fmt]           ; format string
    xor    eax, eax                     ; variadic: 0 float args
    call   printf@plt
```

The `call strlen` has completely disappeared — replaced by `mov edx, 6`. This is **interprocedural constant propagation**: GCC knows the first argument is `"square"`, that `strlen("square")` equals 6, and substitutes directly.

> ⚠️ Warning: this optimization only works if the string is known at compile time. If `label` comes from user input, `strlen` remains a `call strlen@plt` even in `-O2`.

---

## Comparative summary

The table below summarizes the key differences observable in disassembly by optimization level:

| Aspect | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |  
|---|---|---|---|---|---|  
| Local variables | Stack | Registers | Registers | Registers | Registers |  
| Trivial `static` functions | Explicit `call` | Inlined (1 site) | Inlined (multi-site) | Aggressive inlining | Inlined (conservative) |  
| if/else branches | `cmp` + `jcc` | `cmp` + `jcc` | `cmov` if possible | `cmov` | `cmov` if possible |  
| Dense switch | `cmp`+`je` cascade | Cascade or jump table | Jump table | Jump table | Cascade (compact) |  
| Division by constant | `idiv` | Magic number | Magic number | Magic number | Magic number |  
| Loops | Literal, stack | Registers | Partial unrolling | Unrolling + SIMD vectorization | No unrolling |  
| `.text` size | Large (verbose) | Medium | Medium-large | Large (duplicated code) | Small |  
| RE readability | Excellent | Good | Moderate | Difficult | Moderate |

---

## Impact on binary size

Compile `opt_levels_demo.c` at different levels and compare sizes:

```bash
$ make s16_1
$ ls -lhS build/opt_levels_demo_*
```

Typical result (GCC 13, x86-64, Linux):

```
build/opt_levels_demo_O0         ~21 KB   (largest — verbose, DWARF symbols)  
build/opt_levels_demo_O3         ~18 KB   (unrolled/duplicated code + DWARF)  
build/opt_levels_demo_O2         ~17 KB   (good compromise)  
build/opt_levels_demo_O1         ~17 KB  
build/opt_levels_demo_Os         ~16 KB   (most compact with symbols)  
build/opt_levels_demo_O2_strip   ~14 KB   (stripped — no DWARF or symbols)  
```

Most of the difference between `-O0` and the others comes from eliminating unnecessary stack accesses and inlining that removes prologues/epilogues. Stripping (`-s`) removes symbol tables and DWARF information, further reducing size significantly.

Use `readelf -S` to compare the `.text` section size (executable code) independently from metadata:

```bash
readelf -S build/opt_levels_demo_O0 | grep '\.text'  
readelf -S build/opt_levels_demo_O2 | grep '\.text'  
```

---

## Impact on the number of visible functions

A simple but revealing indicator is the number of `T`-type symbols (functions in `.text`) visible with `nm`:

```bash
$ nm build/opt_levels_demo_O0 | grep ' t \| T ' | wc -l
  12      ← main + all static functions

$ nm build/opt_levels_demo_O2 | grep ' t \| T ' | wc -l
  3       ← main + a few non-inlined functions
```

In `-O0`, each `static` function appears with a local symbol (lowercase `t`). In `-O2`, inlined functions disappear — only those too large to be inlined and `main` remain.

For RE on a stripped binary (`_O2_strip`), `nm` shows nothing. You must then use Ghidra or another disassembler to reconstruct function boundaries through heuristic analysis of prologues/epilogues.

---

## Practical tips for RE

Here are the reflexes to adopt when facing a binary whose optimization level you don't know:

**1. Check for `idiv` by constants.** If you see `idiv ecx` with `ecx = 7` (or any other constant), the binary is probably at `-O0`. Starting from `-O1`, GCC systematically replaces these divisions with magic numbers.

**2. Check for `cmov` instructions.** `cmov` instructions are virtually absent in `-O0` and ubiquitous from `-O2` onward. Their presence is a reliable optimization indicator.

**3. Count functions.** A binary with many small functions (`push rbp` / `mov rbp, rsp` prologues everywhere) is typical of `-O0`. A binary where `main()` is a long monolithic sequence suggests aggressive inlining (`-O2` or higher).

**4. Look for jump tables.** The presence of jump tables in `.rodata` indicates at least `-O2`. In `-Os`, switches are often left as comparison cascades.

**5. Look for SIMD instructions.** Instructions like `movdqa`, `paddd`, `pmulld` (SSE) or `vpaddd`, `vmovdqu` (AVX) in loop bodies indicate `-O3` — or `-O2` with explicit `-ftree-vectorize`.

**6. Observe loop structure.** A counter incremented by 1 each turn is typical of `-O0` or `-O1`. A counter incremented by 2, 4, or 8 indicates unrolling (`-O2` or `-O3`). The presence of an "epilogue" loop (processing remaining elements after the main loop) is characteristic of vectorization.

**7. Look at memory accesses in functions.** If the first `mov` instructions in a function body copy parameter registers (`edi`, `esi`, `edx`, `ecx`) to the stack then immediately reload them, it's `-O0`. In `-O2`, parameters stay in registers.

---


⏭️ [Function inlining: when the function disappears from the binary](/16-compiler-optimizations/02-inlining.md)
