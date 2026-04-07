🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 16.4 — Tail call optimization and its impact on the stack

> **Associated source file**: `binaries/ch16-optimisations/tail_call.c`  
> **Compilation**: `make s16_4` (produces 6 variants in `build/`)

---

## Introduction

The previous sections showed how GCC transforms the *content* of functions (inlining, unrolling, vectorization). Tail call optimization (TCO) transforms something more fundamental: the **relationship between functions** — the way they call each other and how the execution stack evolves.

The principle is simple: when a function's last action before returning is a call to another function (or to itself), the `call` + `ret` can be replaced by a simple `jmp`. The caller's stack frame is reused by the callee, instead of stacking a new one.

The consequences for the reverse engineer are profound:

- A **recursion** can transform into a **loop** — there's no longer a visible recursive `call` in the binary.  
- The **GDB backtrace** is truncated: intermediate frames no longer exist on the stack, so `bt` doesn't show them.  
- Two functions in **mutual recursion** (A calls B which calls A) can become a single loop — the two functions appear merged.  
- A `call [rax]` (indirect call) can become a `jmp [rax]`, which changes the pattern signature in RE.

This section explores each scenario in detail, with annotated disassembly and pitfalls to avoid during analysis.

---

## What is a tail call?

A call is in **tail position** when it's the very last operation before the `return`. No computation, no transformation, no operation applies to the call's result — it's returned as-is to the caller.

### What IS a tail call

```c
return other_function(x, y);      /* Tail call — result is returned directly */  
return self(n - 1, acc * n);      /* Tail recursion — recursive call in tail position */  
```

### What IS NOT a tail call

```c
return n * factorial(n - 1);      /* NOT a tail call — multiplication AFTER the call */  
return 1 + process(data);         /* NOT a tail call — addition AFTER the call */  

int result = compute(x);  
log(result);                      /* NOT a tail call — code executes after compute() */  
return result;  
```

The distinction is subtle but crucial. In the first non-tail case, the result of `factorial(n - 1)` must return to the current frame to be multiplied by `n`. The frame therefore can't be freed before the recursive call returns. In a true tail call, the frame has no more use after the call — it can be recycled.

### What the compiler does

In `-O0`, TCO is **always disabled**. Every call generates a `call` with a new frame.

Starting from `-O1`, GCC begins applying TCO. In `-O2`, it covers most cases. In `-O3`, behavior is identical to `-O2` for TCO (there's no "more aggressive TCO" — it either applies or it doesn't).

The concrete transformation in the binary:

```
BEFORE (without TCO):            AFTER (with TCO):

call target_function            ; Update parameters in registers
; ... ret from target returns    jmp target_function
;     here                       ; target's ret returns directly
ret                              ; to OUR caller
```

The `call` + `ret` is replaced by a `jmp`. Since `jmp` doesn't push a return address onto the stack, the target function's `ret` will return directly to the current function's caller — one level up in the call chain.

---

## Scenario 1 — Tail recursion: factorial with accumulator

Tail recursion is the most emblematic case of TCO. It's also the most transformative: a recursion of depth N is converted into a flat loop, with no stack growth at all.

```c
static long factorial_tail(int n, long accumulator)
{
    if (n <= 1)
        return accumulator;
    return factorial_tail(n - 1, accumulator * n);
}

long factorial(int n)
{
    return factorial_tail(n, 1);
}
```

The recursive call `return factorial_tail(n - 1, accumulator * n)` is in tail position: nothing happens between the recursive call's return and the current function's `return`. The accumulator carries the intermediate result "downward" instead of reconstructing it "on the way back up."

### In `-O0` — classic recursion

```asm
factorial_tail:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 0x10
    mov    DWORD PTR [rbp-0x4], edi      ; n on stack
    mov    QWORD PTR [rbp-0x10], rsi     ; accumulator on stack

    ; if (n <= 1)
    cmp    DWORD PTR [rbp-0x4], 1
    jg     .L_recurse
    mov    rax, QWORD PTR [rbp-0x10]     ; return accumulator
    jmp    .L_end

.L_recurse:
    ; accumulator * n
    mov    eax, DWORD PTR [rbp-0x4]
    cdqe
    imul   rax, QWORD PTR [rbp-0x10]     ; rax = accumulator * n

    ; factorial_tail(n - 1, accumulator * n)
    mov    rsi, rax                       ; 2nd param = accumulator * n
    mov    edi, DWORD PTR [rbp-0x4]
    sub    edi, 1                         ; 1st param = n - 1
    call   factorial_tail                 ; RECURSIVE CALL

.L_end:
    leave
    ret
```

Each recursive call stacks a new frame. For `factorial(20)`, there are 20 frames on the stack, each occupying ~32 bytes. The GDB backtrace shows all 20 levels:

```
(gdb) bt
#0  factorial_tail (n=1, accumulator=2432902008176640000) at tail_call.c:6
#1  factorial_tail (n=2, accumulator=1216451004088320000) at tail_call.c:8
#2  factorial_tail (n=3, accumulator=405483668029440000) at tail_call.c:8
...
#19 factorial_tail (n=20, accumulator=1) at tail_call.c:8
#20 factorial (n=20) at tail_call.c:13
#21 main (argc=1, argv=0x7fffffffde18) at tail_call.c:150
```

### In `-O2` — transformation to loop

GCC recognizes the tail recursion pattern and transforms it into a loop. The `call factorial_tail` is replaced by a `jmp` to the beginning of the function (or, more often, by a complete restructuring into a `while` loop):

```asm
factorial_tail:
    ; No full prologue — leaf function or minimal prologue
    mov    rax, rsi                       ; rax = accumulator
    cmp    edi, 1
    jle    .L_done                        ; if (n <= 1) return accumulator

.L_loop:
    ; "Loop" body — formerly the recursive case
    movsxd rdx, edi                      ; rdx = n (64-bit extended)
    imul   rax, rdx                      ; accumulator *= n
    sub    edi, 1                         ; n--
    cmp    edi, 1
    jg     .L_loop                        ; while (n > 1)

.L_done:
    ret                                   ; return accumulator (in rax)
```

The transformation is radical:

- The `call factorial_tail` has **completely disappeared**. There's no longer a recursive call — it's a `jg .L_loop` loop.  
- Parameters `n` and `accumulator` are updated **in registers** (`edi` and `rax`) instead of being passed via a new frame.  
- The stack doesn't grow at all. For `factorial(20)`, there's **a single frame** on the stack, regardless of depth.  
- The GDB backtrace shows only one level:

```
(gdb) bt
#0  factorial_tail (n=1, accumulator=2432902008176640000) at tail_call.c:6
#1  factorial (n=20) at tail_call.c:13
#2  main (argc=1, argv=0x7fffffffde18) at tail_call.c:150
```

The 18 intermediate frames have disappeared. This is the most visible effect of TCO for an analyst debugging with GDB.

### How to recognize it in RE

The optimized tail recursion pattern is easy to confuse with a simple `while` loop written in the source. Both produce exactly the same assembly. Here are the clues to distinguish a transformed tail recursion:

1. **Parameter registers are reinitialized before the backward `jmp`/`jg`.** In a classic loop, the counter is incremented. In a transformed tail recursion, parameters are recalculated according to the recursive function's signature: `edi` receives `n - 1`, `rax` receives `accumulator * n`.

2. **The parameter structure matches a function signature.** If the "loop body" manipulates exactly registers `edi` and `rsi` (the first two System V parameters), and the loop exit condition corresponds to a recursive base case (`n <= 1`), the source was likely recursive.

3. **In practice, the distinction is often unimportant for RE.** Whether the source was a tail recursion or a while loop, the behavior is identical. What matters is understanding the algorithm, not the original syntactic form.

---

## Scenario 2 — NON-tail recursion: the `call` survives

```c
static long factorial_notail(int n)
{
    if (n <= 1)
        return 1;
    return n * factorial_notail(n - 1);
}
```

The multiplication by `n` occurs **after** the recursive call returns. The result of `factorial_notail(n - 1)` must return to the current frame to be multiplied. The frame can't be freed — TCO is impossible.

### In `-O2`

```asm
factorial_notail:
    push   rbx                           ; callee-saved register save
    mov    ebx, edi                      ; ebx = n (saved for after the call)

    cmp    edi, 1
    jle    .L_base

    lea    edi, [rbx-1]                  ; edi = n - 1
    call   factorial_notail              ; RECURSIVE CALL (call, not jmp!)

    movsxd rbx, ebx
    imul   rax, rbx                      ; rax = n * recursive_result
    pop    rbx
    ret

.L_base:
    mov    eax, 1                        ; return 1
    pop    rbx
    ret
```

The `call factorial_notail` is still present. GCC can't transform it into `jmp`, because it must retrieve the result in `rax` to multiply it by `n` (preserved in `ebx`, a callee-saved register).

Note the `push rbx` at the start: GCC needs to preserve `n` during the recursive call, so it uses `ebx` (callee-saved) and saves it to the stack. This is a classic non-tail recursion pattern.

### The lesson for RE

If you see a `call` to the function itself followed by operations on the result (`imul rax, rbx` here), it's **non-tail recursion**. The presence of a callee-saved register `push` (`rbx`, `r12`–`r15`) that preserves a parameter for use after the `call` is the sign that TCO couldn't apply.

Conversely, if you see a `jmp` to the beginning of the function (or a loop) with only parameter register updates, it's an optimized tail recursion — or a native loop.

---

## Scenario 3 — Mutual recursion: `is_even` / `is_odd`

TCO isn't limited to self-recursion. It also applies when a function calls **another function** in tail position. The most interesting case is mutual recursion.

```c
static int is_even(unsigned int n)
{
    if (n == 0) return 1;
    return is_odd(n - 1);
}

static int is_odd(unsigned int n)
{
    if (n == 0) return 0;
    return is_even(n - 1);
}
```

Each function calls the other in tail position. Without TCO, a call to `is_even(1000000)` would stack a million frames and cause a stack overflow.

### In `-O0` — guaranteed stack overflow

```asm
is_even:
    push   rbp
    mov    rbp, rsp
    mov    DWORD PTR [rbp-0x4], edi
    cmp    DWORD PTR [rbp-0x4], 0
    jne    .L_not_zero
    mov    eax, 1
    jmp    .L_end
.L_not_zero:
    mov    edi, DWORD PTR [rbp-0x4]
    sub    edi, 1
    call   is_odd                         ; call (not jmp)
.L_end:
    pop    rbp
    ret
```

For `is_even(1000000)`, the stack grows by ~32 bytes per call × 1,000,000 = ~32 MB. On a system with a stack limit of 8 MB (default `ulimit -s` value), that's a guaranteed stack overflow.

### In `-O2` — fusion into a single loop

GCC applies TCO to both functions. Better yet, it can **fuse** them into a single loop since both functions have the same structure (decrement `n` and alternate):

```asm
is_even:
    ; GCC fuses is_even and is_odd
    ; The result is: is_even(n) = (n % 2 == 0)
    ; But without this simplification, the TCO version looks like:

    test   edi, edi
    je     .L_return_1

.L_loop:
    sub    edi, 1                        ; n--
    je     .L_return_0                   ; if (n == 0) return 0  (is_odd base case)
    sub    edi, 1                        ; n--
    jne    .L_loop                       ; if (n != 0) continue  (is_even base case)

.L_return_1:
    mov    eax, 1
    ret

.L_return_0:
    xor    eax, eax
    ret
```

The two mutual `call`s have been replaced by a loop that decrements `n` by 2 each turn (once for `is_odd`, once for `is_even`). The two functions have been **fused** into a single loop.

In some GCC versions, the compiler goes even further and recognizes that all this mutual recursion is equivalent to `n % 2 == 0`:

```asm
is_even:
    ; Ultra-optimized version
    mov    eax, edi
    and    eax, 1                        ; n & 1
    xor    eax, 1                        ; invert the bit (even = !odd)
    ret
```

Three instructions. A million recursion levels reduced to an `and` + `xor`.

### What RE should remember

Mutual recursion optimized by TCO produces surprising patterns: two functions that in the source call each other alternately can end up fused into a single loop in the binary. If the `is_odd` symbol has disappeared and `is_even` contains a loop that decrements by 2, the analyst may not suspect there were two functions originally.

A clue: if the loop has **two** distinct exit conditions with different return values (`return 0` and `return 1`), and the counter is decremented twice per turn, it's potentially a fused mutual recursion.

---

## Scenario 4 — What blocks TCO

TCO fails as soon as the current function's frame must remain active after the call. Here are the most common cases.

### Work after the call

```c
static int sum_recursive(int n)
{
    if (n <= 0) return 0;
    return n + sum_recursive(n - 1);   /* n + ... prevents TCO */
}
```

The addition of `n` after the recursive call's return blocks TCO. The frame must stay active to store `n`. In `-O2`, GCC can however transform this recursion into iteration through other means (implicit accumulation), but that's not TCO per se.

Compare with the tail-recursive version:

```c
static int sum_tail(int n, int acc)
{
    if (n <= 0) return acc;
    return sum_tail(n - 1, acc + n);   /* Valid tail call */
}
```

### In `-O2` — side-by-side comparison

`sum_recursive`:

```asm
sum_recursive:
    ; GCC can transform to iteration through recurrence analysis,
    ; but the mechanism is different from TCO.
    ; Typical version: accumulation in a register.
    test   edi, edi
    jle    .L_zero
    xor    eax, eax                      ; acc = 0
.L_loop:
    add    eax, edi                      ; acc += n
    sub    edi, 1                        ; n--
    jnz    .L_loop                       ; while (n != 0)
    ret
.L_zero:
    xor    eax, eax
    ret
```

`sum_tail`:

```asm
sum_tail:
    ; Direct TCO — parameters are updated and we loop
    test   edi, edi
    jle    .L_return_acc
.L_loop:
    add    esi, edi                      ; acc += n
    sub    edi, 1                        ; n--
    jnz    .L_loop
.L_return_acc:
    mov    eax, esi                      ; return acc
    ret
```

Both versions produce nearly identical assembly. The difference is in the **mechanism**: `sum_tail` is transformed by TCO (replacing `call` with `jmp`), while `sum_recursive` is transformed by a different recurrence analysis pass. The result for RE is the same — a loop — but the fact that GCC can "save" `sum_recursive` doesn't mean TCO applied.

### Local stack buffer

```c
static int process_with_buffer(int n, int threshold)
{
    int buffer[64];
    buffer[n % 64] = n;

    if (n <= 0) return buffer[0];

    if (n > threshold)
        return process_with_buffer(n - 2, threshold);
    else
        return process_with_buffer(n - 1, threshold);
}
```

Despite the calls being in tail position, the `buffer[64]` array allocated on the stack prevents TCO in some cases. The frame must remain active for `buffer` to exist while the function is executing. If the compiler can't prove that `buffer` is no longer accessed after the recursive call point, it preserves the frame.

In practice, GCC is sometimes smart enough to realize that `buffer` isn't accessed after the recursive call and applies TCO anyway. But it's an edge case whose outcome depends on the GCC version and optimization level.

### What RE should remember

If you see a recursive `call` in a `-O2` binary (instead of the expected `jmp` for TCO), look for what blocks the optimization: an operation after the `call` (multiplication, addition, result transformation), a local array, or a callee-saved register `push`/`pop` indicating the function needs to restore state after the call returns.

---

## Scenario 5 — Tail call to another function

TCO doesn't only apply to self-recursion. Any call in tail position to **any function** can be transformed into a `jmp`.

```c
typedef long (*transform_fn)(long, int);

static long apply_transform(transform_fn fn, long initial, int steps)
{
    return fn(initial, steps);   /* Indirect tail call */
}
```

### In `-O0`

```asm
apply_transform:
    push   rbp
    mov    rbp, rsp
    mov    QWORD PTR [rbp-0x8], rdi      ; fn
    mov    QWORD PTR [rbp-0x10], rsi     ; initial
    mov    DWORD PTR [rbp-0x14], edx     ; steps

    mov    esi, DWORD PTR [rbp-0x14]     ; 2nd param = steps
    mov    rdi, QWORD PTR [rbp-0x10]     ; 1st param = initial
    mov    rax, QWORD PTR [rbp-0x8]      ; rax = fn
    call   rax                           ; indirect call
    pop    rbp
    ret
```

`call rax` + `ret`: the classic indirect call.

### In `-O2`

```asm
apply_transform:
    ; Parameter rearrangement for tail call
    mov    rax, rdi                      ; rax = fn
    mov    rdi, rsi                      ; 1st param = initial (was in rsi)
    mov    esi, edx                      ; 2nd param = steps (was in edx)
    jmp    rax                           ; TAIL CALL — jmp instead of call
```

The `call rax` has become `jmp rax`. There's no `push rbp`, no `ret` — the function `apply_transform` doesn't even create a stack frame. It simply rearranges the parameters (since `fn`, `initial`, and `steps` aren't in the registers expected by the target function) then jumps directly.

The `ret` of the target function (`double_it` or `triple_it`) will return directly to `apply_transform`'s caller — that is, `main()`.

### The `jmp` at end-of-function pattern

This is an extremely common pattern in optimized binaries, even outside recursion. Whenever a function ends with `return another_function(...)`, GCC emits a `jmp` instead of `call` + `ret`. Here are frequent examples:

```asm
; Wrapper that adds a parameter
wrapper:
    mov    edx, 42                       ; add a 3rd parameter
    jmp    real_function                 ; direct tail call

; Dispatch — the caller chooses the target
dispatch:
    cmp    edi, 1
    je     .L_handler_a
    cmp    edi, 2
    je     .L_handler_b
    jmp    default_handler               ; tail call to default

.L_handler_a:
    jmp    handler_a                     ; tail call
.L_handler_b:
    jmp    handler_b                     ; tail call
```

### What RE should remember

A `jmp` to **another function** (not a local label) at the end of a function is a tail call. Don't confuse it with a `jmp` to an internal label (which is a conditional branch or loop). The distinction:

- `jmp .L_loop` → local branch (label in the same function)  
- `jmp printf@plt` → tail call to `printf`  
- `jmp rax` → indirect tail call

If you see a "function" in Ghidra that doesn't end with `ret` but with a `jmp` to another function, it's a tail call. Ghidra generally handles this case well and shows the relationship in the decompiler, but some less sophisticated disassemblers may poorly delimit function boundaries.

---

## Scenario 6 — Classic algorithmic examples

Two well-known algorithms are naturally tail-recursive and perfectly illustrate TCO in practice.

### GCD (Euclidean algorithm)

```c
static int gcd(int a, int b)
{
    if (b == 0) return a;
    return gcd(b, a % b);
}
```

#### In `-O2`

```asm
gcd:
    test   esi, esi
    je     .L_done                       ; if (b == 0) return a

.L_loop:
    mov    eax, edi                      ; eax = a
    cdq                                  ; sign extension
    idiv   esi                           ; eax = a/b, edx = a%b
    mov    edi, esi                      ; a = b
    mov    esi, edx                      ; b = a % b
    test   esi, esi
    jne    .L_loop                       ; while (b != 0)

.L_done:
    mov    eax, edi                      ; return a
    ret
```

The recursive `call gcd` has been replaced by the loop `jne .L_loop`. Parameters are updated in `edi` (a = b) and `esi` (b = a % b) — exactly the System V parameter registers, since they're the same as those of the original recursive call.

The `idiv` is preserved here because the modulo depends on runtime values (not a constant), so GCC can't apply the magic number.

### Fast modular exponentiation

```c
static long mod_pow_tail(long base, int exp, long mod, long acc)
{
    if (exp == 0) return acc;
    if (exp % 2 == 1)
        return mod_pow_tail(base, exp - 1, mod, (acc * base) % mod);
    else
        return mod_pow_tail((base * base) % mod, exp / 2, mod, acc);
}
```

#### In `-O2`

```asm
mod_pow_tail:
    ; rdi = base, esi = exp, rdx = mod, rcx = acc
    test   esi, esi
    je     .L_return_acc

.L_loop:
    test   esi, 1                        ; exp odd?
    jz     .L_even

    ; Odd case: acc = (acc * base) % mod
    mov    rax, rcx
    imul   rax, rdi                      ; rax = acc * base
    cqo
    idiv   rdx                           ; rdx:rax / mod → remainder in rdx
    ; ... (rcx = rdx, the new acc)
    sub    esi, 1                        ; exp--

    test   esi, esi
    je     .L_return_acc
    jmp    .L_even_entry

.L_even:
.L_even_entry:
    ; Even case: base = (base * base) % mod, exp /= 2
    mov    rax, rdi
    imul   rax, rdi                      ; rax = base * base
    cqo
    idiv   rdx                           ; remainder in rdx
    ; ... (rdi = rdx, the new base)
    shr    esi, 1                        ; exp /= 2

    test   esi, esi
    jne    .L_loop

.L_return_acc:
    mov    rax, rcx                      ; return acc
    ret
```

Both branches of the recursive call (even and odd) are fused into a single loop with a `test esi, 1` to choose the path. All four parameters (`base`, `exp`, `mod`, `acc`) are updated in registers at each loop turn. The O(log n) fast exponentiation algorithm, written recursively in the source, becomes an iterative loop in the binary.

---

## Impact on debugging with GDB

TCO has a direct impact on the debugging experience, and this knowledge is useful for the reverse engineer who uses GDB for dynamic analysis.

### Truncated backtrace

This is the most visible effect. When TCO applies, intermediate frames no longer exist on the stack:

```
# In -O0 (no TCO):
(gdb) bt
#0  factorial_tail (n=1, accumulator=2432902008176640000)
#1  factorial_tail (n=2, accumulator=1216451004088320000)
#2  factorial_tail (n=3, accumulator=405483668029440000)
...
#19 factorial_tail (n=20, accumulator=1)
#20 factorial (n=20)
#21 main ()

# In -O2 (TCO enabled):
(gdb) bt
#0  factorial_tail (n=7, accumulator=????)
#1  factorial (n=20)
#2  main ()
```

In `-O2`, the backtrace shows only a single frame for `factorial_tail`, regardless of the current recursion level. The 19 intermediate frames never existed on the stack.

### Breakpoints and stepping

Setting a breakpoint on a TCO-optimized function works, but the behavior can seem strange:

```
(gdb) b factorial_tail
Breakpoint 1 at 0x401234
(gdb) r 10
Breakpoint 1, factorial_tail ()
(gdb) c
Breakpoint 1, factorial_tail ()   ← same breakpoint, next loop turn
(gdb) c
Breakpoint 1, factorial_tail ()
```

The breakpoint is hit at each loop iteration (since the `jmp` returns to the beginning of the function). In `-O0`, the breakpoint would only be hit once per frame (at the first call), then you'd need to `step` to enter the recursive calls.

### Tip: use the `-O0 -g` binary to understand, the `-O2` binary to validate

In RE situations, compile the same source (if available) with `-O0 -g` to understand the logic with GDB (complete backtrace, variables on stack), then validate your understanding on the `-O2` (or stripped) binary. This is exactly the approach of the provided Makefile, which produces both variants.

---

## Summary of TCO patterns in RE

| What you see | What it is | What was in the source |  
|---|---|---|  
| `jmp` to the beginning of the function itself, parameters updated in registers | Optimized tail recursion | `return f(new_params);` |  
| Loop with System V parameter register updates (`edi`, `esi`, `edx`, `ecx`) | Same — indistinguishable from native loop | `return f(...)` or `while(...)` |  
| `jmp other_function` at end of function (no `ret`) | Tail call to another function | `return other_function(...)` |  
| `jmp rax` / `jmp [reg+offset]` at end of function | Indirect tail call | `return fn_ptr(...)` |  
| Recursive `call` followed by `imul`/`add` on `rax` | NON-tail recursion (TCO impossible) | `return n * f(n-1)` |  
| `push rbx` + recursive `call` + use of `ebx` after the `call` | Non-tail recursion with callee-saved save | Same — compiler preserves post-call state |  
| Loop that decrements by 2, two exit conditions | Fused mutual recursion | `A() → B() → A()` |  
| GDB backtrace with single frame for deep recursion | TCO applied | Tail recursion |

---

## Summary

Tail call optimization is an elegant transformation that eliminates the stack cost of calls in tail position. For the reverse engineer, its main impact is the **disappearance of intermediate stack frames**: a recursion transforms into a loop, two mutually recursive functions fuse, and the GDB backtrace no longer reflects the call history.

The practical rule is simple: if a function ends with a `jmp` (to itself, to another function, or via a register) instead of a `call` + `ret`, it's a tail call. And if you see a loop whose "variables" correspond exactly to System V parameter registers (`rdi`, `rsi`, `rdx`, `rcx`), consider the hypothesis that it's a transformed tail recursion.

---


⏭️ [Link-Time Optimizations (`-flto`) and their effects on the call graph](/16-compiler-optimizations/05-link-time-optimization.md)
