🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix I — Recognizable GCC Patterns in Assembly (Compiler Idioms)

> 📎 **Reference Sheet** — This appendix catalogs the characteristic x86-64 instruction sequences that GCC generates for common C/C++ constructs. Recognizing these idioms (*compiler idioms*) dramatically accelerates reading disassembly: instead of deciphering each instruction individually, you identify the pattern at a glance and reconstruct the corresponding C construct. The appendix is organized by construct type, with the original C code, the typical assembly code produced by GCC, and the explanations needed for identification.

---

## Conventions

All assembly examples use **Intel syntax** and correspond to code compiled by GCC on x86-64 Linux (System V AMD64 ABI). Optimization levels are indicated when they affect the pattern. The registers used in the examples are illustrative — GCC may choose any available register depending on the context.

The following abbreviations are used:

| Abbreviation | Meaning |  
|-------------|---------------|  
| `-O0` | No optimization (debug mode, most readable code) |  
| `-O1` | Basic optimization |  
| `-O2` | Standard optimization (default for production) |  
| `-O3` | Aggressive optimization (vectorization, unrolling) |

---

## 1 — Zeroing a Register

### Pattern

```asm
xor    eax, eax
```

### C Equivalent

```c
int x = 0;
// or: return 0;
// or: preparation of rax before a variadic call (al = 0)
```

### Explanation

`xor eax, eax` is the universal idiom for zeroing a register. It is preferred over `mov eax, 0` because it is encoded in 2 bytes instead of 5 and it breaks data dependencies on modern processors (the processor recognizes the pattern as a *zeroing idiom*). GCC uses it systematically at all optimization levels.

In x86-64, writing to a 32-bit register (`eax`) automatically zeroes the upper 32 bits of the corresponding 64-bit register (`rax`). So `xor eax, eax` zeroes all of `rax`.

This pattern has three common contexts: initializing a variable to zero, preparing the return value `return 0`, and setting `al = 0` before a call to a variadic function (`printf`, etc.) to indicate that no XMM register is used.

---

## 2 — Division by Constant via Magic Multiplication

### Pattern (unsigned division)

```asm
mov    eax, edi           ; eax = dividend  
mov    edx, 0xCCCCCCCD    ; magic constant for /10  
imul   rax, rdx           ; 64-bit multiplication  
shr    rax, 35            ; shift to obtain the quotient  
```

### Alternate Pattern (unsigned division, `mul` form)

```asm
mov    eax, edi  
mov    ecx, 0xAAAAAAAB    ; magic constant for /3  
mul    rcx                ; rdx:rax = rax * rcx  
shr    rdx, 1             ; quotient in rdx  
```

### Pattern (signed division)

```asm
mov    eax, edi  
mov    edx, 0x66666667    ; signed magic constant for /5  
imul   edx                ; edx:eax = eax * edx (signed)  
sar    edx, 1             ; arithmetic shift  
mov    eax, edx  
shr    eax, 31            ; sign bit extraction  
add    edx, eax           ; correction for negative numbers  
```

### C Equivalent

```c
unsigned q = x / 10;   // first pattern  
unsigned q = x / 3;    // second pattern  
int q = x / 5;         // third pattern (signed)  
```

### Explanation

GCC replaces **every integer division by a compile-time known constant** with a multiplication followed by a shift. The `div`/`idiv` instruction is extremely slow (20–90 cycles depending on the processor) while `imul` + `shr` takes 3–4 cycles.

The "magic constant" is the modular multiplicative inverse of the divisor, computed by the compiler. Each divisor has its own constant. Here are the most common ones:

| Divisor | Type | Magic Constant | Shift |  
|----------|------|-------------------|----------|  
| 3 | unsigned | `0xAAAAAAAB` | `shr rdx, 1` |  
| 5 | unsigned | `0xCCCCCCCD` | `shr rax, 34` |  
| 7 | unsigned | `0x24924925` | `shr rdx, 2` (after adjustment) |  
| 10 | unsigned | `0xCCCCCCCD` | `shr rax, 35` |  
| 12 | unsigned | `0xAAAAAAAB` | `shr rdx, 3` |  
| 100 | unsigned | `0x51EB851F` | `shr rdx, 5` |  
| 1000 | unsigned | `0x10624DD3` | `shr rdx, 6` |  
| 3 | signed | `0x55555556` | (no additional shift) |  
| 5 | signed | `0x66666667` | `sar edx, 1` |  
| 7 | signed | `0x92492493` | `sar edx, 2` (after adjustment) |  
| 10 | signed | `0x66666667` | `sar edx, 2` |

**How to identify this pattern**: if you see an `imul` or `mul` with a large hexadecimal constant that doesn't seem meaningful, followed by a `shr` or `sar`, it is almost certainly a division by constant. To find the divisor, you can use the Python calculator: `hex(round((2**35) / 10))` → `0xCCCCCCCD` (for unsigned division by 10 with shift 35).

For signed division, the pattern is more complex because GCC must correct for rounding toward zero (C signed division rounds toward zero, unlike arithmetic shift which rounds toward negative infinity). The correction consists of adding the sign bit of the intermediate result (`shr eax, 31` + `add`).

---

## 3 — Modulo by Constant

### Pattern (power of 2)

```asm
and    eax, 0x0F          ; x % 16  
and    eax, 0x07          ; x % 8  
and    eax, 0x01          ; x % 2 (parity test)  
```

### Pattern (non-power of 2)

GCC first computes the quotient via magic multiplication (pattern §2), then reconstructs the remainder:

```asm
; x % 10 (unsigned)
mov    eax, edi  
mov    edx, 0xCCCCCCCD  
imul   rax, rdx  
shr    rax, 35            ; quotient q = x / 10  
lea    eax, [rax+rax*4]   ; eax = q * 5  
add    eax, eax           ; eax = q * 10  
sub    edi, eax           ; remainder = x - q * 10  
mov    eax, edi  
```

### C Equivalent

```c
unsigned r = x % 16;   // → and  
unsigned r = x % 10;   // → magic mul + sub  
```

### Explanation

For powers of 2, unsigned modulo reduces to an AND mask: `x % 2^n` is equivalent to `x & (2^n - 1)`. This is a very common pattern.

For other constants, GCC uses the identity `x % d = x - (x / d) * d`: it computes the quotient via magic multiplication, multiplies the quotient by the divisor (often via `lea` for small constants), then subtracts from the original dividend.

For signed modulo by a power of 2, the pattern is more complex because the remainder must have the same sign as the dividend:

```asm
; x % 8 (signed)
mov    eax, edi  
cdq                        ; edx = sign of eax (0 or -1)  
shr    edx, 29             ; edx = 0 or 7 (correction bias)  
add    eax, edx            ; add bias if negative  
and    eax, 7              ; mask  
sub    eax, edx            ; remove bias  
```

---

## 4 — Multiplication by Small Constant via `lea`

### Patterns

```asm
lea    eax, [rdi+rdi*2]         ; eax = rdi * 3  
lea    eax, [rdi*4]             ; eax = rdi * 4  
lea    eax, [rdi+rdi*4]         ; eax = rdi * 5  
lea    eax, [rdi+rdi*8]         ; eax = rdi * 9  
lea    eax, [rdi+rdi*2]  
add    eax, eax                 ; eax = rdi * 6  (3 * 2)  
lea    eax, [rdi+rdi*2]  
lea    eax, [rax+rax*4]         ; eax = rdi * 15 (3 * 5)  
lea    eax, [rdi+rdi*4]  
add    eax, eax                 ; eax = rdi * 10 (5 * 2)  
```

### C Equivalent

```c
int y = x * 3;  
int y = x * 5;  
int y = x * 10;  
// etc.
```

### Explanation

`lea` can compute `base + index * scale + displacement` in a single cycle, with `scale` limited to 1, 2, 4, or 8. GCC exploits this capability to replace multiplications by small constants (typically 2–15) with one or two `lea` instructions, sometimes combined with `add` or `shl`.

This pattern is very common at `-O2` and above. It is faster than an `imul` because `lea` has a latency of 1 cycle versus 3 for `imul`. Additionally, `lea` does not modify flags, which avoids data dependencies.

**How to identify it**: a `lea` whose memory operand uses the same register as both base and index (`[rdi+rdi*N]`) is almost always a multiplication, not a memory access.

---

## 5 — `if` / `else` Structure

### Pattern `-O0` (with frame pointer)

```asm
cmp    dword ptr [rbp-0x4], 5    ; compare x with 5  
jne    .L_else                    ; if x != 5, jump to else  
; --- then block ---
call   do_something  
jmp    .L_end  
.L_else:
; --- else block ---
call   do_other
.L_end:
```

### Pattern `-O2` (branchless with `cmov`)

```asm
cmp    edi, 5  
cmove  eax, ecx      ; if edi == 5, eax = ecx ("then" value)  
                      ; otherwise eax keeps the "else" value
```

### C Equivalent

```c
// -O0 version
if (x == 5) {
    do_something();
} else {
    do_other();
}

// -O2 version (branchless)
int result = (x == 5) ? value_then : value_else;
```

### Explanation

The fundamental `if`/`else` pattern is a `cmp` followed by a conditional jump. The crucial point is that **the jump condition is the inverse of the C `if` condition**: the jump skips over the `then` block to the `else`, so an `if (x == 5)` produces a `jne` (jump if *not* equal).

Starting from `-O2`, GCC replaces simple branches with `cmovcc` instructions when both branches are simple expressions (not function calls). This is the *branchless* pattern: instead of jumping, the processor computes both values and conditionally selects the right one. This is more performant when the branch is hard to predict.

---

## 6 — `for` / `while` Loop

### `for` Pattern at `-O0`

```asm
mov    dword ptr [rbp-0x4], 0    ; int i = 0  
jmp    .L_cond                    ; jump to condition  
.L_body:
; --- loop body ---
add    dword ptr [rbp-0x4], 1    ; i++
.L_cond:
cmp    dword ptr [rbp-0x4], 10   ; i < 10 ?  
jl     .L_body                    ; if so, repeat  
```

### `for` Pattern at `-O2` (counter in a register)

```asm
xor    ecx, ecx                  ; i = 0
.L_loop:
; --- loop body (uses ecx as counter) ---
add    ecx, 1                    ; i++  (or inc ecx / lea ecx,[rcx+1])  
cmp    ecx, 10                   ; i < 10 ?  
jl     .L_loop  
```

### Reversed `for` Pattern (count-down) at `-O2`

```asm
mov    ecx, 10                   ; counter = 10
.L_loop:
; --- body ---
sub    ecx, 1                    ; counter--  
jnz    .L_loop                   ; loop while != 0  
```

### `while` Pattern at `-O2` (duplicated condition)

```asm
; GCC can transform while(cond) into: if(cond) do { ... } while(cond)
test   edi, edi                  ; loop entry: x != 0 ?  
je     .L_skip                   ; if x == 0, don't enter  
.L_loop:
; --- body ---
test   edi, edi  
jne    .L_loop  
.L_skip:
```

### C Equivalent

```c
for (int i = 0; i < 10; i++) { ... }  
while (x != 0) { ... }  
```

### Explanation

At `-O0`, GCC places the loop condition **at the bottom** and jumps to it from the initialization. The loop body is between the body label and the condition label. The counter is stored in memory (stack).

At `-O2`, the counter is in a register, and GCC may reverse the counting direction (count-down) because `sub + jnz` is often more efficient than `add + cmp + jl` (a `sub` that reaches zero sets ZF directly, eliminating the need for a separate `cmp`).

GCC can also transform a `while` into a `do-while` with an initial guard test (*loop rotation*). This `if(cond) do { ... } while(cond)` scheme is more efficient because it places the backward jump at the end of the loop, which is better predicted by the branch predictor.

**How to identify a loop**: look for a backward jump (to a lower address). Forward jumps are `if`/`else`, backward jumps are loops.

---

## 7 — `switch` / `case`

### Pattern: jump table (consecutive cases)

```asm
; switch (x) with cases 0, 1, 2, 3, 4
cmp    edi, 4  
ja     .L_default               ; if x > 4, default case  
lea    rdx, [rip + .L_jumptable]  
movsxd rax, dword ptr [rdx+rdi*4]  ; read relative offset  
add    rax, rdx                 ; absolute address of the case  
jmp    rax                      ; indirect jump  
```

The jump table is stored in `.rodata` and contains relative offsets (4 bytes each) to each `case` label.

### Pattern: chain of `cmp`/`jz` (sparse cases)

```asm
; switch (x) with cases 1, 50, 100, 999
cmp    edi, 50  
je     .L_case_50  
cmp    edi, 100  
je     .L_case_100  
cmp    edi, 999  
je     .L_case_999  
cmp    edi, 1  
je     .L_case_1  
jmp    .L_default  
```

### Pattern: binary tree of comparisons (numerous sparse cases)

```asm
cmp    edi, 50  
jg     .L_upper_half       ; if x > 50, search in the upper half  
cmp    edi, 10  
je     .L_case_10  
cmp    edi, 25  
je     .L_case_25  
cmp    edi, 50  
je     .L_case_50  
jmp    .L_default  
.L_upper_half:
cmp    edi, 100  
je     .L_case_100  
; ...
```

### C Equivalent

```c
switch (x) {
    case 0: ...; break;
    case 1: ...; break;
    // ...
}
```

### Explanation

GCC chooses the `switch` implementation strategy based on the density and number of `case` values:

- **Jump table**: when `case` values are close together and form a dense range. This is the most efficient case (O(1)), recognizable by the `lea` toward `.rodata` followed by an indirect `jmp` via an index.  
- **Comparison chain**: when there are few `case` values (typically < 5) or values are very sparse. This is the easiest case to read.  
- **Binary tree**: when there are many sparse `case` values. GCC generates a series of comparisons that partitions the value space by dichotomy (O(log n)).

**How to identify a jump table**: look for a `lea` toward `.rodata` followed by `movsxd` (loading a signed 32-bit offset), `add`, and `jmp rax`. The presence of a `cmp + ja` just before (bounds check) confirms the pattern. The size of the jump table in `.rodata` (number of entries × 4 bytes) indicates the number of `case` values.

---

## 8 — Function Calls and Conventions

### Pattern: call with ≤ 6 integer arguments

```asm
mov    edx, 3              ; 3rd argument  
mov    esi, 2              ; 2nd argument  
lea    rdi, [rip+.LC0]     ; 1st argument (string address)  
call   printf@plt  
```

### Pattern: variadic call (`printf` and family)

```asm
lea    rdi, [rip+.LC0]     ; format string  
mov    esi, 42             ; first %d argument  
xor    eax, eax            ; al = 0 (no floating-point argument)  
call   printf@plt  
```

### Pattern: call with floating-point arguments

```asm
movsd  xmm0, qword ptr [rip+.LC1]  ; 1st double arg  
mov    edi, 42                       ; 1st integer arg  
mov    eax, 1                        ; al = 1 (one xmm register used)  
call   mixed_func@plt  
```

### Pattern: saving a caller-saved register before a call

```asm
push   rbx                 ; save rbx (callee-saved) in the prologue  
mov    ebx, edi            ; copy 1st argument into rbx  
call   some_func           ; rbx survives the call  
mov    edi, ebx            ; reuse the saved value  
call   other_func  
pop    rbx                 ; restore rbx in the epilogue  
```

### Explanation

The pattern of saving into a callee-saved register (`rbx`, `r12`–`r15`) is an important clue in RE: it shows that a value must survive a `call`, meaning it is reused afterward. If you see `mov ebx, edi` at the beginning of a function, it means the first argument will be needed later. This helps understand the data flow through the function.

---

## 9 — Function Prologue and Epilogue

### Pattern: full prologue (`-O0`)

```asm
push   rbp  
mov    rbp, rsp  
sub    rsp, 0x20           ; 32 bytes of locals  
mov    dword ptr [rbp-0x14], edi   ; save 1st argument on the stack  
mov    dword ptr [rbp-0x18], esi   ; save 2nd argument  
```

### Pattern: optimized prologue (`-O2`, no frame pointer)

```asm
push   rbx                 ; save callee-saved  
push   r12                 ; save callee-saved  
sub    rsp, 0x18           ; locals + alignment  
```

### Pattern: leaf function without prologue (red zone)

```asm
; No push or sub rsp!
mov    dword ptr [rsp-0x4], edi   ; direct storage in the red zone
; ... computations ...
ret
```

### Pattern: epilogue with `leave`

```asm
leave                      ; mov rsp, rbp ; pop rbp  
ret  
```

### Pattern: optimized epilogue

```asm
add    rsp, 0x18  
pop    r12  
pop    rbx  
ret  
```

### Explanation

The prologue and epilogue frame each function. Their form provides valuable information:

- **Number of callee-saved `push`es** → number of "register variables" used by the function (complexity indicator)  
- **Size of `sub rsp`** → total space for local variables and arguments for called functions  
- **Presence of `push rbp` / `mov rbp, rsp`** → frame pointer used (typical of `-O0`, makes reading easier)  
- **Absence of `sub rsp` with `[rsp-offset]` accesses** → leaf function using the red zone  
- **Order of `pop`s** → exact reverse of the `push` order (if this is not the case, the binary may be corrupted or obfuscated)

---

## 10 — Stack Canary (Buffer Overflow Protection)

### Pattern

```asm
; Prologue
mov    rax, qword ptr fs:[0x28]    ; load canary from TLS  
mov    qword ptr [rbp-0x8], rax    ; store canary on the stack  
xor    eax, eax                     ; clear rax (don't leave the canary in a register)  

; ... function body ...

; Epilogue
mov    rax, qword ptr [rbp-0x8]    ; reload canary from the stack  
xor    rax, qword ptr fs:[0x28]    ; compare with original value  
jne    .L_stack_smash              ; if different → corruption detected  
leave  
ret  

.L_stack_smash:
call   __stack_chk_fail@plt        ; never returns (abort)
```

### Explanation

This pattern is generated when the binary is compiled with `-fstack-protector` (enabled by default on most distributions). The `fs:[0x28]` access is the most reliable marker of a stack canary on glibc x86-64. The `xor eax, eax` after loading the canary is a security cleanup to avoid leaving the value in a register.

In RE, this pattern tells you that the function handles a local buffer (which is what triggered the protection). The call to `__stack_chk_fail` at the end of the function confirms the presence of the canary. If you see a `jne` toward `__stack_chk_fail`, do not confuse this branch with business logic — it is purely protection.

---

## 11 — Accessing Global Variables in PIE/PIC

### Pattern (global variable in PIE code)

```asm
lea    rax, [rip+global_var]       ; load the variable's address (RIP-relative)  
mov    eax, dword ptr [rax]        ; load the value  
```

Or, in a single instruction if the size is known:

```asm
mov    eax, dword ptr [rip+global_var]   ; direct RIP-relative access
```

### Pattern (string literal in `.rodata`)

```asm
lea    rdi, [rip+.LC0]            ; address of string in .rodata  
call   puts@plt  
```

### Explanation

In PIE code (*Position-Independent Executable*, the default on modern distributions), all references to fixed addresses use **RIP-relative** addressing: the address is expressed as an offset from the current instruction (`rip`). This is what allows the binary to be loaded at any address (ASLR).

In RE, the pattern `lea reg, [rip+offset]` followed by `call` almost always indicates passing a string address or global variable address as a function argument. `mov reg, [rip+offset]` is the loading of a global variable's *value*. Ghidra and IDA automatically resolve these offsets to symbol names, but in `objdump` you will see the raw offset and will need to calculate it manually.

---

## 12 — PLT Call and GOT Resolution

### Pattern (call via PLT)

```asm
call   printf@plt                  ; indirect call via PLT
```

In the `.plt` section, the stub looks like:

```asm
printf@plt:
    jmp    qword ptr [rip+printf@GOTPCREL]  ; jump via GOT
    push   0x3                               ; index in the relocation table
    jmp    .plt_resolve                      ; call to the dynamic resolver
```

### Pattern (GOT access in Full RELRO)

```asm
; .plt.got or .plt.sec (with CET)
endbr64  
jmp    qword ptr [rip+printf@GOTPCREL]  
```

### Explanation

Every call to a shared library function goes through the PLT. On the first call, the PLT stub invokes the dynamic resolver of `ld.so`, which writes the actual function address into the GOT. Subsequent calls jump directly to the correct address.

In RE, if you see `call <name>@plt`, you know it is a call to an imported function. The name after `@plt` identifies the function. On a stripped binary, Ghidra and IDA automatically name these stubs. In `objdump`, you will see the PLT stub address with the comment `<printf@plt>`.

---

## 13 — Boolean Expressions

### Pattern: `return (a == b)`

```asm
cmp    edi, esi  
sete   al               ; al = 1 if edi == esi, 0 otherwise  
movzx  eax, al          ; zero-extend to 32 bits (int/bool return value)  
ret  
```

### Pattern: `return (a < b)` (signed)

```asm
cmp    edi, esi  
setl   al  
movzx  eax, al  
ret  
```

### Pattern: `return (a != 0)` (boolean normalization)

```asm
test   edi, edi  
setne  al  
movzx  eax, al  
ret  
```

### Pattern: `&&` / `||` combination (short-circuit)

```asm
; if (a > 0 && b < 10)
test   edi, edi  
jle    .L_false          ; a <= 0 → short-circuit, result false  
cmp    esi, 10  
jge    .L_false          ; b >= 10 → result false  
; ... true block ...
```

### Explanation

The `cmp`/`setcc`/`movzx` triplet is GCC's canonical pattern for boolean expressions that are returned or assigned. `setcc` produces an 8-bit result (0 or 1) in an 8-bit register (`al`, `cl`, etc.), and `movzx` extends it to 32 bits.

For `&&` and `||` operators, GCC implements C's short-circuit evaluation: if the first operand of `&&` is false, the second is not evaluated (direct jump to the `false` result). Similarly, if the first operand of `||` is true, the second is skipped.

---

## 14 — Ternary Operator and `min` / `max`

### Pattern: ternary with `cmov`

```asm
; result = (a > b) ? a : b    → max(a, b)
cmp    edi, esi  
cmovl  edi, esi          ; if edi < esi, edi = esi  
mov    eax, edi  
ret  
```

### Pattern: `abs()` (absolute value)

```asm
; abs(x) for a signed int
mov    eax, edi  
cdq                       ; edx = sign of eax (0 or -1)  
xor    eax, edx           ; if negative: one's complement  
sub    eax, edx           ; if negative: +1 (completes two's complement)  
ret  
```

### Alternate `abs()` Pattern with `cmov`

```asm
mov    eax, edi  
neg    eax                ; eax = -edi  
cmovl  eax, edi           ; if result is negative (edi was positive), restore edi  
ret  
```

### Explanation

`cmovcc` instructions are the sign of ternary expressions or `min`/`max` at `-O2`. GCC prefers them to branches because they eliminate branch misprediction penalties.

The `abs()` pattern via `cdq`/`xor`/`sub` is a classic idiom that exploits two's complement properties: XOR with -1 gives the one's complement, and subtracting -1 is equivalent to adding 1, which completes the negation.

---

## 15 — Bit Testing and Flag Manipulation

### Pattern: testing a specific bit

```asm
test   eax, 0x04          ; test bit 2  
jnz    .L_bit_set          ; jump if the bit is 1  
```

### Pattern: bit-field extraction

```asm
; unsigned field = (x >> 4) & 0x0F;
mov    eax, edi  
shr    eax, 4  
and    eax, 0x0F  
```

### Pattern: setting a bit

```asm
; x |= (1 << 3);
or     eax, 0x08
```

### Pattern: clearing a bit

```asm
; x &= ~(1 << 3);
and    eax, 0xFFFFFFF7     ; = ~0x08
```

### Explanation

Bit manipulations are very common in system, network, and cryptographic code. The `test` + `jnz`/`jz` pattern tests a bit without modifying the value (unlike `and` which modifies the destination). The constant masks in `and` and `or` indicate which bits are extracted or modified.

---

## 16 — Array Access and Indexing

### Pattern: accessing an integer array

```asm
mov    eax, dword ptr [rbx+rcx*4]      ; arr[i] (int, 4 bytes)  
mov    rax, qword ptr [rbx+rcx*8]      ; arr[i] (long/pointer, 8 bytes)  
movzx  eax, byte ptr [rbx+rcx]         ; arr[i] (char/uint8_t, 1 byte)  
```

### Pattern: accessing an array of structures

```asm
; struct S { int a; int b; char c; };  → sizeof(S) = 12 (with padding)
; access to arr[i].b
imul   rax, rcx, 12       ; offset = i * sizeof(S) = i * 12  
mov    eax, dword ptr [rbx+rax+4]     ; +4 = offset of field b in S  
```

### Pattern: array traversal with pointer

```asm
; At -O2, GCC can transform for(i=0;i<n;i++) arr[i] into:
mov    rax, rbx            ; ptr = &arr[0]  
lea    rdx, [rbx+rcx*4]   ; end = &arr[n]  
.L_loop:
mov    dword ptr [rax], 0  ; *ptr = 0  
add    rax, 4              ; ptr++  
cmp    rax, rdx            ; ptr < end ?  
jne    .L_loop  
```

### Explanation

The scale factor in `[base+index*scale]` reveals the element size: `*1` = bytes/chars, `*2` = shorts, `*4` = ints/floats, `*8` = longs/doubles/pointers. When the scale factor is not a power of 2, GCC uses an explicit `imul` to compute the offset, indicating a non-standard structure size.

At `-O2`, GCC often transforms indexed loops (`arr[i]`) into pointer-based loops (`*ptr++`) with an end pointer comparison (*pointer-based loop*). This is more efficient because it eliminates the index multiplication at each iteration.

---

## 17 — C++ Virtual Calls (vtable dispatch)

### Pattern

```asm
mov    rax, qword ptr [rdi]          ; load the vptr (first qword of the object)  
call   qword ptr [rax+0x10]          ; call the 3rd virtual method  
```

### Pattern with `this != nullptr` check

```asm
test   rdi, rdi                       ; this == nullptr ?  
je     .L_null_handler  
mov    rax, qword ptr [rdi]           ; vptr  
call   qword ptr [rax+0x08]           ; 2nd virtual method  
```

### Pattern: dynamic_cast / RTTI

```asm
mov    rsi, qword ptr [rip+typeinfo_for_Derived]  ; target RTTI  
mov    rdi, rbx                       ; source object  
call   __dynamic_cast                 ; runtime RTTI check  
test   rax, rax                       ; cast succeeded ?  
je     .L_cast_failed  
```

### Explanation

A C++ virtual call always follows the same two-step scheme: dereference `[rdi]` to obtain the vtable pointer (the vptr is always the first field of a polymorphic object), then jump to a fixed offset in the vtable. The offset divided by 8 gives the virtual method index (0x00 = 1st, 0x08 = 2nd, 0x10 = 3rd, etc.).

This pattern is the most reliable marker of object-oriented C++ code. If you see `mov rax, [rdi]; call [rax+offset]`, you are looking at a virtual call. `rdi` contains `this`, and the offset in the vtable identifies the called method.

---

## 18 — C++ Exceptions (`try` / `catch` / `throw`)

### Pattern: `throw`

```asm
mov    edi, 4                         ; size of the exception object  
call   __cxa_allocate_exception       ; allocate the exception object  
mov    dword ptr [rax], 42            ; initialize the exception (here an int)  
mov    edx, 0                         ; destructor (nullptr for int)  
lea    rsi, [rip+typeinfo_for_int]    ; RTTI of the thrown type  
mov    rdi, rax                       ; pointer to the exception  
call   __cxa_throw                    ; throw the exception (does not return)  
```

### Pattern: recognizing a `try`/`catch`

The `try` code itself is not visible in the instructions — it is encoded in the `.gcc_except_table` section as LSDA (*Language Specific Data Area*) tables. However, the `catch` code is a *landing pad* function called by the stack unwinding mechanism:

```asm
.L_landing_pad:
cmp    edx, 1                         ; exception type (index in the table)  
je     .L_catch_block  
call   _Unwind_Resume                 ; re-throw if not the right type  

.L_catch_block:
mov    rdi, rax                       ; pointer to the exception object  
call   __cxa_begin_catch  
; ... catch block code ...
call   __cxa_end_catch
```

### Explanation

The functions `__cxa_allocate_exception`, `__cxa_throw`, `__cxa_begin_catch`, `__cxa_end_catch`, and `_Unwind_Resume` are the definitive markers of the C++ exception mechanism. If you see these calls in a binary, you know it uses exceptions. The presence of `__cxa_throw` indicates a `throw`, `__cxa_begin_catch`/`__cxa_end_catch` bracket a `catch` block, and `_Unwind_Resume` propagates an uncaught exception to the upper frame.

---

## 19 — `std::string` (libstdc++ GCC)

### Pattern: SSO (Small String Optimization) — short string

```asm
; std::string s = "hello";  (5 chars + nul → fits in the SSO buffer)
lea    rdi, [rbp-0x20]               ; address of std::string on the stack  
lea    rsi, [rip+.LC0]               ; "hello"  
call   std::string::basic_string(char const*)  
```

### Memory Layout (libstdc++)

```
; std::string on the stack (sizeof = 32 bytes)
[rbp-0x20]  → pointer to data (or to internal buffer if SSO)
[rbp-0x18]  → size (length)
[rbp-0x10]  → capacity (if dynamically allocated) or start of SSO buffer
```

### Pattern: accessing `s.size()` and `s.data()`

```asm
mov    rax, qword ptr [rbx+0x08]     ; s.size() = 2nd qword  
mov    rdi, qword ptr [rbx]          ; s.data() = 1st qword (pointer)  
```

### Explanation

`std::string` in libstdc++ (GCC) uses *Small String Optimization*: strings of 15 bytes or fewer are stored directly in the `string` object itself (no heap allocation). Beyond 15 bytes, a buffer is allocated on the heap. The object is always 32 bytes on x86-64.

In RE, a `std::string` appears as a 32-byte structure with three 8-byte fields. The first is a pointer to the data, the second is the length. Recognizing this layout allows identifying C++ string manipulations in disassembled code.

---

## 20 — C++ Object Construction and Destruction

### Pattern: `new` and `delete`

```asm
; MyClass* p = new MyClass(42);
mov    edi, 24                        ; sizeof(MyClass) = 24  
call   operator new(unsigned long)    ; allocate on the heap  
mov    rbx, rax                       ; save the pointer  
mov    esi, 42                        ; constructor argument  
mov    rdi, rax                       ; this = allocated pointer  
call   MyClass::MyClass(int)          ; constructor  

; delete p;
mov    rdi, rbx                       ; this  
call   MyClass::~MyClass()            ; destructor  
mov    esi, 24                        ; size (for the deallocator)  
mov    rdi, rbx  
call   operator delete(void*, unsigned long)  
```

### Pattern: local object with destructor (RAII)

```asm
; { std::vector<int> v; ... }
; The destructor is called automatically at end of scope
lea    rdi, [rbp-0x20]               ; this = address of v on the stack  
call   std::vector<int>::~vector()    ; destructor at end of scope  
```

### Explanation

The `operator new` / constructor and destructor / `operator delete` pair is the fundamental C++ allocation scheme. The size passed to `operator new` (first argument, in `edi`) directly gives the `sizeof` of the class — valuable information for reconstructing the class structure.

Local object destructors are systematically called before the `ret` or before each early `return`. If you see multiple calls to the same destructor in a function, it corresponds to different exit paths (each `return` calls the destructors of local objects in scope).

---

## 21 — Recognizing Inlined Standard Functions

GCC automatically inlines certain libc functions for simple cases. Recognizing them avoids wasting time analyzing "mysterious" code.

### Inlined `memset` (small known size)

```asm
; memset(buf, 0, 32) → zeroing 32 bytes
pxor   xmm0, xmm0                    ; xmm0 = 0  
movaps xmmword ptr [rbp-0x30], xmm0  ; 16 bytes to 0  
movaps xmmword ptr [rbp-0x20], xmm0  ; 16 bytes to 0  
```

Or with `rep stosb`:

```asm
xor    eax, eax           ; value to write = 0  
mov    ecx, 32            ; number of bytes  
lea    rdi, [rbp-0x30]    ; destination  
rep    stosb               ; fills 32 bytes with 0  
```

### Inlined `memcpy`

```asm
; memcpy(dst, src, 24) → copy 24 bytes
movdqu xmm0, xmmword ptr [rsi]       ; load 16 bytes from src  
movdqu xmmword ptr [rdi], xmm0       ; write 16 bytes to dst  
mov    rax, qword ptr [rsi+0x10]     ; load remaining 8 bytes  
mov    qword ptr [rdi+0x10], rax     ; write 8 bytes  
```

### Inlined `strlen` (rare, very simple case)

```asm
; strlen of compile-time known string
mov    eax, 5              ; GCC computes strlen("hello") at compile time
```

### Explanation

When the size is known at compile time and is small (typically ≤ 64 bytes), GCC replaces `memset`, `memcpy`, `memmove`, and sometimes `strcmp` with inline instruction sequences. For larger sizes, it emits a call to the libc function via PLT. For `strlen` on a string literal, GCC computes the result entirely at compile time and replaces it with a constant.

---

## 22 — Vectorized Code (GCC Auto-Vectorization)

### Pattern: scalar loop followed by the "tail"

```asm
; Vectorized loop (processes 4 elements per iteration)
.L_vector_loop:
movdqu xmm0, xmmword ptr [rdi+rax]   ; load 4 ints  
paddd  xmm0, xmm1                     ; packed addition  
movdqu xmmword ptr [rsi+rax], xmm0   ; store 4 results  
add    rax, 16  
cmp    rax, rdx  
jl     .L_vector_loop  

; Tail: processes remaining elements one by one
.L_scalar_tail:
mov    ecx, dword ptr [rdi+rax]       ; load 1 int  
add    ecx, ebx                        ; scalar addition  
mov    dword ptr [rsi+rax], ecx       ; store 1 result  
add    rax, 4  
cmp    rax, r8  
jl     .L_scalar_tail  
```

### Explanation

When GCC vectorizes a loop (`-ftree-vectorize`, enabled by default at `-O2`), it generates two versions of the loop: a SIMD version that processes N elements in parallel (N = 4 for `int` in 128-bit XMM registers), and a scalar version (*tail*) that processes the remaining elements when the total count is not a multiple of N.

The scalar version (tail) is much more readable and contains the same logic as the original C loop. In RE, always analyze the tail first to understand what the loop does, then verify that the SIMD version does the same thing in parallel.

---

## 23 — Miscellaneous Idioms

### `likely` / `unlikely` (branch prediction)

```c
if (__builtin_expect(x == 0, 0)) { error(); }
```

```asm
test   edi, edi  
jne    .L_continue          ; the "normal" path is the fall-through  
; error block (placed after the jmp, in the "cold" path)
call   error
.L_continue:
```

GCC places the "likely" path as fall-through (sequential) and the "unlikely" path after a jump. This is a layout optimization for the instruction cache.

### `__builtin_unreachable()`

```asm
ud2                         ; invalid instruction → crash if reached
```

GCC inserts `ud2` after theoretically unreachable points. In RE, `ud2` means "the compiler determined that this point should never be reached."

### Returning a structure by value (hidden pointer)

```asm
; struct BigStruct func();
; The caller prepares space and passes the pointer in rdi:
lea    rdi, [rsp+0x10]     ; space for the return  
call   func                 ; func writes to [rdi] and returns rdi in rax  
```

When the first argument visible in C should be in `rdi` but `rdi` contains a local pointer from the caller, it is a structure return via hidden pointer (see Appendix B, §4.4).

---

> 📚 **Further reading**:  
> - **Appendix A** — [x86-64 Opcode Quick Reference](/appendices/appendix-a-opcodes-x86-64.md) — the individual instructions used in these patterns.  
> - **Appendix B** — [System V AMD64 ABI Calling Conventions](/appendices/appendix-b-system-v-abi.md) — the convention underlying the call and prologue/epilogue patterns.  
> - **Chapter 16** — [Understanding Compiler Optimizations](/16-compiler-optimizations/README.md) — pedagogical coverage of GCC transformations that produce these patterns.  
> - **Chapter 17** — [Reverse Engineering C++ with GCC](/17-re-cpp-gcc/README.md) — detail on C++ patterns (vtables, RTTI, exceptions, STL).  
> - **Compiler Explorer** — [https://godbolt.org/](https://godbolt.org/) — essential online tool for observing the assembly code produced by GCC for any C/C++ fragment in real time.

⏭️ [Common Crypto Magic Constants (AES, SHA, MD5, RC4...)](/appendices/appendix-j-crypto-constants.md)
