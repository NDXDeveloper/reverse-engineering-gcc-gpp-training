🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 16 Checkpoint

> **Spoilers** — Only read this solution after attempting the checkpoint yourself.

---

## Reference Environment

- GCC 13.2.0 (Ubuntu 24.04)  
- x86-64, Linux 6.8  
- Binaries compiled via `make s16_1`

Exact addresses and details vary by GCC version. This solution describes the **structural patterns** — if you identified the same type of optimization with different addresses or registers, that's correct.

---

## Preliminary Step — Symbol Comparison

```bash
$ nm build/opt_levels_demo_O0 | grep ' t ' | sort
000000000040116a t clamp
0000000000401199 t classify_grade
00000000004011fd t compute
0000000000401288 t multi_args
00000000004012d5 t print_info
0000000000401150 t square
000000000040117a t sum_of_squares

$ nm build/opt_levels_demo_O2 | grep ' t ' | sort
(nothing, or only 1-2 surviving functions)
```

**Finding**: at `-O0`, 7 `static` functions are visible as local symbols (`t`). At `-O2`, most (or all) have disappeared — they were **inlined** into `main()`.

This is already a first identifiable optimization without even looking at the disassembly.

---

## Optimization 1: Inlining of `square()`

### Location

Function `square()` and its call sites in `main()`.

### At `-O0`

`square()` exists as an independent function with its own prologue:

```asm
square:
    push   rbp
    mov    rbp, rsp
    mov    DWORD PTR [rbp-0x4], edi
    mov    eax, DWORD PTR [rbp-0x4]
    imul   eax, DWORD PTR [rbp-0x4]
    pop    rbp
    ret
```

The call in `main()`:

```asm
    mov    edi, DWORD PTR [rbp-0x14]     ; load input
    call   square
    mov    DWORD PTR [rbp-0x18], eax     ; store sq
```

### At `-O2`

The `square` symbol no longer exists. Where `main()` called `square(input)`, we simply find:

```asm
    imul   ebx, ebx                      ; sq = input * input
```

A single instruction replaces 7 instructions (prologue + body + epilogue) plus the `call`/`ret` overhead.

### Recognition Clue

The absence of the `square` symbol in `nm` and the absence of `call square` in `main()`'s disassembly. The presence of an isolated `imul reg, reg` (self-multiplication) matches the body of `square()`.

---

## Optimization 2: Division by Constant → Magic Number in `compute()`

### Location

Function `compute()`, loop containing `data[i] / 7`.

### At `-O0`

The division uses the `idiv` instruction:

```asm
    mov    eax, DWORD PTR [rbp+rax*4-0x30]   ; load data[i]
    cdq                                       ; sign extension
    mov    ecx, 7
    idiv   ecx                                ; eax = data[i] / 7
    add    DWORD PTR [rbp-0x34], eax          ; result += quotient
```

The divisor `7` is explicitly visible in the `mov ecx, 7`.

### At `-O2`

The division is replaced by a multiplication with the magic number `0x92492493`:

```asm
    mov    eax, DWORD PTR [rsp+rsi*4+...]
    mov    edx, 0x92492493                    ; magic number for /7
    imul   edx
    add    edx, eax                           ; additive correction
    sar    edx, 2                             ; arithmetic shift
    mov    eax, edx
    shr    eax, 31                            ; sign bit extraction
    add    edx, eax                           ; negative correction
```

The same pattern is found for `data[3] % 5` (modulo), which uses the division-by-5 magic number (`0x66666667`) followed by a reverse multiplication and subtraction.

### Recognition Clue

The presence of `imul` by a large hexadecimal constant (`0x92492493`) followed by `sar` is the unmistakable marker of division by constant. The complete absence of `idiv` instructions in the `-O2` binary confirms that all constant divisions were transformed.

---

## Optimization 3: Branch → `cmov` in `clamp()`

### Location

Function `clamp()` (inlined into `main()` at `-O2`).

### At `-O0`

Two conditional branches, three exit paths:

```asm
clamp:
    push   rbp
    mov    rbp, rsp
    mov    DWORD PTR [rbp-0x4], edi
    mov    DWORD PTR [rbp-0x8], esi
    mov    DWORD PTR [rbp-0xc], edx

    mov    eax, DWORD PTR [rbp-0x4]
    cmp    eax, DWORD PTR [rbp-0x8]
    jge    .L_not_low
    mov    eax, DWORD PTR [rbp-0x8]      ; return low
    jmp    .L_end

.L_not_low:
    mov    eax, DWORD PTR [rbp-0x4]
    cmp    eax, DWORD PTR [rbp-0xc]
    jle    .L_not_high
    mov    eax, DWORD PTR [rbp-0xc]      ; return high
    jmp    .L_end

.L_not_high:
    mov    eax, DWORD PTR [rbp-0x4]      ; return value

.L_end:
    pop    rbp
    ret
```

Two `cmp` + `jge`/`jle`, three `jmp`, and each variable is reloaded from the stack.

### At `-O2`

Both branches are replaced by two `cmov`:

```asm
    ; clamp inlined into main()
    cmp    edi, esi
    cmovl  edi, esi                      ; if (value < low) value = low
    cmp    edi, edx
    cmovg  edi, edx                      ; if (value > high) value = high
```

Four instructions, zero branches, zero stack access.

### Recognition Clue

The sequence `cmp` + `cmovl` followed by `cmp` + `cmovg` on the same register is the exact pattern of a clamp (saturation between two bounds). The absence of any `jmp`/`jge`/`jle` for this logic confirms `cmov` usage.

---

## Optimization 4: Jump Table in `classify_grade()`

### Location

Function `classify_grade()`, the switch on `score / 10`.

### At `-O0`

Linear comparison cascade:

```asm
classify_grade:
    ; ... score / 10 computation via idiv ...
    cmp    DWORD PTR [rbp-0x8], 10
    je     .L_case_A
    cmp    DWORD PTR [rbp-0x8], 9
    je     .L_case_A
    cmp    DWORD PTR [rbp-0x8], 8
    je     .L_case_B
    cmp    DWORD PTR [rbp-0x8], 7
    je     .L_case_C
    cmp    DWORD PTR [rbp-0x8], 6
    je     .L_case_D
    cmp    DWORD PTR [rbp-0x8], 5
    je     .L_case_E
    jmp    .L_default
```

Seven sequential comparisons, one per case.

### At `-O2`

The switch is transformed into a jump table with indirect jump:

```asm
    ; score / 10 via magic number (0x66666667)
    ; ...

    ; Bounds check
    sub    edx, 5                         ; normalization (case 5 → index 0)
    cmp    edx, 5
    ja     .L_default                     ; out of bounds → default

    ; Jump via table
    lea    rax, [rip+.L_jumptable]
    movsxd rdx, DWORD PTR [rax+rdx*4]
    add    rax, rdx
    jmp    rax
```

Additionally, the `score / 10` that used `idiv` at `-O0` is itself transformed into a magic number (`0x66666667`) — this is a **second optimization** nested in the same function.

### Recognition Clue

The pattern `lea` + `movsxd [base+index*4]` + `add` + `jmp rax` is the jump table signature. The preceding `cmp` + `ja` is the bounds check (protection against out-of-table index). The initial subtraction (`sub edx, 5`) normalizes the cases so the index starts at 0.

---

## Optimization 5: Register Allocation (stack variables → registers)

### Location

All functions, but particularly visible in `main()` and loops.

### At `-O0`

Each local variable is stored on the stack. Each use generates a load, each modification a store:

```asm
    ; int input = 42;
    mov    DWORD PTR [rbp-0x14], 42

    ; sq = square(input)
    mov    edi, DWORD PTR [rbp-0x14]     ; load input
    call   square
    mov    DWORD PTR [rbp-0x18], eax     ; store sq

    ; clamped = clamp(input, 0, 100)
    mov    edx, 100
    mov    esi, 0
    mov    edi, DWORD PTR [rbp-0x14]     ; re-load input (again!)
    call   clamp
    mov    DWORD PTR [rbp-0x1c], eax     ; store clamped
```

The variable `input` is reloaded from `[rbp-0x14]` at each use, even though its value hasn't changed.

### At `-O2`

Variables live in callee-saved registers (`ebx`, `r12d`, `r13d`, etc.) for the entire duration of `main()`:

```asm
    ; input in ebx for the entire function
    mov    ebx, eax                       ; ebx = input (from atoi or 42)

    ; sq = input * input (square inlined)
    imul   r12d, ebx, ebx                ; r12d = sq = input^2

    ; clamped = clamp(input, 0, 100) (clamp inlined)
    mov    eax, ebx
    ; ... cmov for the clamp ...
    mov    r13d, eax                      ; r13d = clamped
```

`input` is read once and stays in `ebx`. `sq` stays in `r12d`. `clamped` stays in `r13d`. No stack access for these variables.

### Recognition Clue

The near-total absence of `mov DWORD PTR [rbp-0x...], ...` in `main()`'s body at `-O2`. The intensive use of callee-saved registers (`ebx`, `r12d`–`r15d`) preserved by `push`/`pop` at the start and end of `main()`.

---

## Optimization 6: Constant Propagation for `strlen`

### Location

Function `print_info()`, calls with string literals.

### At `-O0`

Each call to `print_info("square", sq)` generates a `call strlen@plt`:

```asm
    ; strlen(label)
    mov    rdi, QWORD PTR [rbp-0x8]      ; label = "square"
    call   strlen@plt                     ; dynamic call
    ; ... uses the result in printf ...
```

### At `-O2`

GCC knows that `label` points to `"square"` (compile-time constant) and evaluates `strlen("square") = 6` at compile time:

```asm
    ; print_info("square", sq) inlined
    mov    edx, 6                         ; strlen("square") = 6, statically evaluated
    lea    rsi, [rip+.LC_square]          ; "square"
    mov    ecx, r12d                      ; value = sq
    lea    rdi, [rip+.LC_fmt]             ; format string
    xor    eax, eax
    call   printf@plt
```

The `call strlen` has completely disappeared, replaced by the immediate `6`.

### Recognition Clue

The absence of `call strlen@plt` in the `-O2` binary for calls with string literals. The presence of a `mov edx, N` (where N matches the string length) just before `call printf`.

To verify: count the letters of each string literal and check that the constant in the `mov` matches.

---

## Optimization 7: Cascaded Inlining of `sum_of_squares()` + `square()`

### Location

`sum_of_squares()` loop, inlined into `main()`.

### At `-O0`

Two levels of calls: `main()` → `sum_of_squares()` → `square()`:

```asm
    ; In sum_of_squares:
.L_loop:
    mov    edi, DWORD PTR [rbp-0xc]      ; i
    call   square                         ; call to square(i)
    cdqe
    add    QWORD PTR [rbp-0x8], rax      ; total += result
    add    DWORD PTR [rbp-0xc], 1        ; i++
    ; ...
    jmp    .L_loop
```

### At `-O2`

Both functions are cascaded-inlined into `main()`. The entire loop reduces to:

```asm
    ; sum_of_squares inlined, square() inlined inside
    xor    eax, eax                       ; total = 0
    mov    edx, 1                         ; i = 1
.L_sos_loop:
    mov    ecx, edx
    imul   ecx, edx                      ; ecx = i * i (square inlined)
    movsxd rcx, ecx
    add    rax, rcx                      ; total += i*i
    add    edx, 1                        ; i++
    cmp    edx, ebx                      ; i <= n?
    jle    .L_sos_loop
```

Two levels of `call` have been eliminated. The body of `square(i)` — a simple `imul ecx, edx` — appears directly in the loop.

### Recognition Clue

The absence of `call sum_of_squares` AND `call square` in `main()`. The presence of a loop with `imul reg, reg` (self-multiplication) and an accumulator — this is the sum-of-squares signature with `square()` inlined.

---

## Optimization 8: Multiplication by Constant via `lea`

### Location

Various locations in `compute()` and `multi_args()`, inlined into `main()`.

### At `-O0`

Multiplications use `imul`:

```asm
    ; a * (i + 1) in compute()
    mov    eax, DWORD PTR [rbp-0x24]     ; i
    add    eax, 1                        ; i + 1
    imul   eax, DWORD PTR [rbp-0x14]    ; * a
```

### At `-O2`

For small multipliers, GCC uses `lea`:

```asm
    ; Examples in inlined code
    lea    eax, [rdi+rdi*2]              ; x * 3
    lea    eax, [rdi+rdi*4]              ; x * 5
```

### Recognition Clue

A `lea` with a scale factor (`*2`, `*4`, `*8`) that is not used as an address calculation (no dereference `[...]` afterward) is a disguised multiplication.

---

## Optimization 9 (bonus): `printf` Replacement by `puts`

### Location

The `printf("Grade: %s\n", grade)` call at the end of `main()`.

### At `-O0`

```asm
    lea    rdi, [rip+.LC_grade_fmt]      ; "Grade: %s\n"
    mov    rsi, rax                       ; grade
    call   printf@plt
```

### At `-O2`

If GCC detects a `printf` whose format is a simple string without specifiers (e.g. `printf("Hello\n")`), it replaces it with `puts`. This replacement doesn't apply to all `printf` calls in the program (those with `%d`, `%s`, etc. remain `printf`), but it can apply to certain simple cases.

### Recognition Clue

The presence of a `call puts@plt` in the `-O2` binary where the source only contains `printf`. Verifiable by comparing library calls between both versions:

```bash
objdump -d build/opt_levels_demo_O0 | grep 'call.*@plt' | sort -u  
objdump -d build/opt_levels_demo_O2 | grep 'call.*@plt' | sort -u  
```

---

## Summary of Identified Optimizations

| # | Optimization | Chapter section | Difficulty |  
|---|---|---|---|  
| 1 | Inlining of `square()` | 16.2 | Easy |  
| 2 | Division by constant → magic number | 16.6, idiom 1 | Medium |  
| 3 | Branch → `cmov` in `clamp()` | 16.6, idiom 5 | Easy |  
| 4 | Switch → jump table | 16.6, idiom 8 | Medium |  
| 5 | Register allocation | 16.1 | Easy |  
| 6 | `strlen` resolved at compile time | 16.1 | Medium |  
| 7 | Cascaded inlining (`sum_of_squares` + `square`) | 16.2 | Medium |  
| 8 | Multiplication via `lea` | 16.6, idiom 4 | Easy |  
| 9 | `printf` → `puts` | 16.7 | Easy |

If you found **3 or more**, you've validated the checkpoint. If you found all 9 (or others not listed here, like loop unrolling in `compute()`), you've mastered the subject.

---

⏭️
