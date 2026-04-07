🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.2 — Essential instructions: `mov`, `push`/`pop`, `call`/`ret`, `lea`

> 🎯 **Goal of this section**: master the instructions you find in virtually *every function* of a GCC-compiled binary. These six instructions (and their variants) form the backbone of any disassembled program — understanding them means being able to read the majority of the code.

---

## Overview

If you analyzed GCC's output statistically, you would find that a handful of instructions come up overwhelmingly. Before talking about arithmetic (section 3.3) or conditional jumps (section 3.4), you first need to understand the instructions that **move data**, **manage the stack**, and **organize function calls** — because they form the connective tissue between all the others.

| Instruction | Summary role |  
|---|---|  
| `mov` | Copies a value from a source to a destination |  
| `push` | Pushes a value (decrements `rsp`, then writes) |  
| `pop` | Pops a value (reads, then increments `rsp`) |  
| `call` | Calls a function (pushes `rip`, then jumps) |  
| `ret` | Returns from a function (pops `rip`) |  
| `lea` | Computes an address *without* accessing memory |

---

## `mov` — the Swiss-army knife of data movement

`mov` is, by far, the most frequent instruction in any x86-64 binary. Its role is simple: **copy** a value from source to destination. Despite its name (*move*), it is indeed a copy — the source is not erased.

### Intel syntax (used in this tutorial)

```
mov  destination, source
```

The destination is always on the left, the source on the right. It is the opposite of AT&T syntax (see box further below).

### Common forms of `mov`

In x86-64, `mov` can operate between registers, between a register and memory, or with an immediate value. Here are the forms you will encounter constantly:

**Register ← Register**

```asm
mov     rbp, rsp          ; copies rsp into rbp (start of prologue)  
mov     rdi, rax           ; prepares the 1st argument of a call  
```

This is the fastest form — everything stays inside the processor, no memory access.

**Register ← Immediate value**

```asm
mov     eax, 0             ; zeroes eax (and therefore rax)  
mov     edi, 0x1           ; loads the constant 1 into edi (1st argument = 1)  
mov     rax, 0x400580      ; loads a 64-bit address into rax  
```

> 💡 **For RE**: when you see `mov edi, <constant>` just before a `call`, it is the first integer argument of the called function. The constant gives you the parameter's value directly.

**Register ← Memory** (read)

```asm
mov     eax, dword [rbp-0x4]      ; reads an int (32-bit) from the stack  
mov     rax, qword [rip+0x2a3f]   ; reads a pointer (64-bit) from .data/.bss  
mov     al, byte [rdi]             ; reads a byte (char) pointed to by rdi  
```

The brackets `[ ]` indicate a **memory access** (dereference). The expression inside the brackets is the effective address. The prefixes `dword`, `qword`, `byte` specify the access size (4, 8, 1 bytes respectively) — they are sometimes omitted by the disassembler when the size is obvious from the register used.

**Memory ← Register** (write)

```asm
mov     dword [rbp-0x4], eax      ; writes eax into a local variable (int)  
mov     qword [rbp-0x10], rdi     ; saves a pointer on the stack  
mov     byte [rax+rcx], dl        ; writes a byte into an array  
```

**Memory ← Immediate value**

```asm
mov     dword [rbp-0x4], 0x0      ; initializes a local variable to 0  
mov     qword [rbp-0x8], 0x0      ; initializes a pointer to NULL  
```

### What `mov` CANNOT do

A fundamental rule of x86-64: **`mov` cannot transfer directly from one memory address to another**. To copy a value from one memory location to another, you must go through an intermediate register:

```asm
; Copy the variable at [rbp-0x8] to [rbp-0x4]
mov     eax, dword [rbp-0x8]     ; memory → register  
mov     dword [rbp-0x4], eax     ; register → memory  
```

This is a very common pattern in `-O0` code, where each C variable lives on the stack and the compiler makes constant round-trips between the stack and registers.

### Correspondence with C

```c
int x = 42;          // →  mov  dword [rbp-0x4], 0x2a  
int y = x;           // →  mov  eax, dword [rbp-0x4]  
                     //    mov  dword [rbp-0x8], eax
char c = buf[i];     // →  mov  al, byte [rax+rcx]
*ptr = value;        // →  mov  dword [rax], edx
```

### The `mov` variants to know

Beyond basic `mov`, several variants appear regularly in GCC code:

**`movzx`** — *Move with Zero Extension*

```asm
movzx   eax, byte [rdi]     ; reads a byte, zero-extends to 32 bits  
movzx   ecx, word [rbp-0x2] ; reads 16 bits, zero-extends to 32 bits  
```

`movzx` is the typical translation of an `unsigned char` or `unsigned short` access that is then used in an `int` expression. Zero-extension guarantees that the upper bits are clean.

**`movsx` / `movsxd`** — *Move with Sign Extension*

```asm
movsx   eax, byte [rdi]     ; reads a signed byte, sign-extends to 32 bits  
movsxd  rax, dword [rbp-0x4] ; reads an int (32-bit), sign-extends to 64-bit  
```

`movsx` does the same as `movzx`, but propagates the sign bit. It is the translation of a `char` (signed) or `short` (signed) promoted to `int`. `movsxd` is specific to 64-bit mode and extends a 32-bit `int` to a 64-bit signed `long` — you see it often when an `int` is used as an index into an array of pointers.

**`cmovXX`** — *Conditional Move*

```asm
cmp     eax, ebx  
cmovl   eax, ecx       ; if eax < ebx (signed), then eax = ecx  
```

`cmov` instructions are conditional `mov`s: the transfer happens only if the condition (based on flags, like jumps) is true. GCC uses them to avoid branching on simple `if` statements with assignment — it is more performant because it avoids branch prediction mistakes. You recognize them by the condition suffix: `cmovz`, `cmovnz`, `cmovl`, `cmovge`, `cmova`, etc.

```c
// C code
int min = (a < b) ? a : b;
```

```asm
; GCC with -O2 may generate:
mov     eax, edi          ; eax = a  
cmp     edi, esi          ; compare a and b  
cmovg   eax, esi          ; if a > b, eax = b  
; result: eax = min(a, b)
```

> 💡 **For RE**: when you see a `cmovXX` where you expected a `jXX` + `mov`, it means the compiler optimized a ternary operator `? :` or a simple `if` with assignment. The logic is identical, but the control flow is linear — no jump.

---

## `push` and `pop` — stack management

The stack is a memory zone managed by the processor via the `rsp` register. It works on the LIFO principle (*Last In, First Out*) and grows toward lower addresses on x86-64.

### `push` — push a value

```
push  source
```

`push` performs two atomic operations:

1. **Decrements `rsp`** by 8 bytes (in 64-bit mode).  
2. **Writes** the source value at the address pointed to by the new `rsp`.

```asm
push    rbp          ; rsp -= 8, then [rsp] = rbp  
push    rbx          ; rsp -= 8, then [rsp] = rbx  
push    0x42         ; rsp -= 8, then [rsp] = 0x42  
```

In terms of effect, `push rbp` is equivalent to:

```asm
sub     rsp, 8  
mov     qword [rsp], rbp  
```

But `push` is more compact (a single opcode) and the processor optimizes it internally.

### `pop` — pop a value

```
pop  destination
```

`pop` does the reverse:

1. **Reads** the value at the address pointed to by `rsp`.  
2. **Increments `rsp`** by 8 bytes.

```asm
pop     rbx          ; rbx = [rsp], then rsp += 8  
pop     rbp          ; rbp = [rsp], then rsp += 8  
```

### Role of `push`/`pop` in GCC code

You will systematically see them in three contexts:

**1. Function prologue — saving callee-saved registers**

```asm
push    rbp              ; saves the old base pointer  
push    rbx              ; saves rbx (callee-saved, about to be used)  
push    r12              ; saves r12 (callee-saved, about to be used)  
```

The number of `push`es at the start of a function tells you how many callee-saved registers the function uses — it is an indicator of its complexity.

**2. Function epilogue — restoration (in reverse order)**

```asm
pop     r12              ; restores r12  
pop     rbx              ; restores rbx  
pop     rbp              ; restores rbp  
ret  
```

The order of `pop`s is **strictly reverse** to the order of `push`es — it is the LIFO nature of the stack. If the order does not match, there is a problem (or intentional obfuscation).

**3. Stack alignment**

Sometimes, GCC inserts an extra `push` solely to align `rsp` on 16 bytes (a requirement of the System V AMD64 convention before a `call`). You will see for example a `push rax` whose value is never used — it is only there to decrement `rsp` by 8.

> 💡 **For RE**: counting `push`es at the start of a function and `pop`s at the end is a first reflex for sanity-checking. If the numbers do not match, it deserves investigation: unusual stack frame, aggressive optimization, or obfuscated code.

---

## `call` and `ret` — function calls

Function calls are the structuring mechanism of any compiled program. Understanding `call` and `ret` is essential to following the execution flow in a disassembler.

### `call` — function call

```
call  target
```

`call` performs two operations:

1. **Pushes the return address**: `rsp -= 8`, then `[rsp] = rip` (the address of the instruction *following* the `call`).  
2. **Jumps** to the target address: `rip = target`.

The pushed return address is what allows `ret` to know where to resume execution after the called function.

**Direct form** — the target address is encoded in the instruction:

```asm
call    0x401150                ; direct call to a fixed address  
call    my_function             ; the disassembler shows the name if symbols exist  
call    printf@plt              ; call through the PLT (dynamic library)  
```

**Indirect form** — the address is read from a register or memory:

```asm
call    rax                     ; indirect call via a register  
call    qword [rbx+0x18]       ; indirect call via memory (function pointer)  
call    qword [rax]             ; C++ virtual dispatch via vtable  
```

> 💡 **For RE**: the distinction is crucial. A direct `call` gives you the target immediately — you can navigate to the called function in your disassembler. An indirect `call` requires dynamic or contextual analysis to resolve the target. In C++, `call qword [rax+offset]` is the characteristic pattern of a virtual method call via the vtable (detailed in Chapter 17).

### `ret` — function return

```
ret
```

`ret` performs the inverse of the pushing part of `call`:

1. **Pops the return address**: `rip = [rsp]`, then `rsp += 8`.

Execution resumes at the instruction following the original `call`.

Occasionally, you will see a `ret imm16` variant (for example `ret 0x8`) which pops the return address then adds the immediate value to `rsp`. It is rare in System V AMD64 code (used more in Windows `__stdcall` conventions), but it can appear in inline assembly or functions with non-standard conventions.

### Visualizing a complete call

Here is the full cycle of a function call, viewed from the stack's side:

```
BEFORE the call:
    rsp →  ┌──────────────────┐
           │  (data)          │
           └──────────────────┘

AFTER the call (entry into the called function):
    rsp →  ┌──────────────────┐
           │ return address   │  ← pushed by call
           ├──────────────────┤
           │  (data)          │
           └──────────────────┘

AFTER the prologue (push rbp / mov rbp, rsp / sub rsp, N):
    rsp →  ┌──────────────────┐
           │ local variables  │  ← space reserved by sub rsp, N
           ├──────────────────┤
    rbp →  │ saved old rbp    │  ← saved by push rbp
           ├──────────────────┤
           │ return address   │  ← pushed by call
           ├──────────────────┤
           │  (caller data)
           └──────────────────┘

AFTER ret (return to caller):
    rsp →  ┌──────────────────┐
           │  (data)          │  ← rsp restored, back to caller
           └──────────────────┘
```

---

## `lea` — the most misunderstood instruction

`lea` (*Load Effective Address*) is an instruction that **computes an address without accessing memory**. It is probably the instruction that most confuses RE beginners, because its syntax looks like a memory access — but it neither reads nor writes memory.

### Syntax

```
lea  destination, [expression]
```

The expression inside brackets is computed according to the same addressing-mode rules as `mov` — but instead of reading memory at the resulting address, `lea` places **the address itself** into the destination register.

### Direct comparison with `mov`

```asm
mov     rax, [rbp-0x10]     ; reads the value IN MEMORY at address rbp-0x10
                              ; → rax = contents of memory

lea     rax, [rbp-0x10]     ; computes the address rbp-0x10, puts it in rax
                              ; → rax = rbp - 0x10 (no memory access)
```

Same syntax with brackets, but fundamentally different behavior. `mov` dereferences, `lea` computes.

### The three uses of `lea` in GCC code

**Use 1 — Computing the address of a local variable** (equivalent to the `&` operator in C)

```c
// C code
int x = 42;  
scanf("%d", &x);    // passes the address of x  
```

```asm
; Assembly
mov     dword [rbp-0x4], 0x2a    ; x = 42  
lea     rsi, [rbp-0x4]            ; rsi = &x (address of x on the stack)  
lea     rdi, [rip+0x1234]         ; rdi = address of the "%d" string  
call    scanf@plt  
```

Here, `lea rsi, [rbp-0x4]` places the address of `x` (not its value) into `rsi`. This is exactly C's `&` operator.

**Use 2 — Loading the address of global data / a string** (RIP-relative addressing)

```asm
lea     rdi, [rip+0x2e5a]        ; rdi = address of a string in .rodata  
call    puts@plt  
```

This pattern is ubiquitous in PIE (*Position Independent Executable*) binaries, which are GCC's default mode on modern distributions. All references to global data and literal strings go through a `lea` with RIP-relative addressing. In Ghidra or IDA, the disassembler often resolves this offset and directly displays the string:

```asm
lea     rdi, [rip+0x2e5a]    ; "Hello, world!"
```

**Use 3 — Disguised arithmetic** (the most confusing repurposing)

GCC frequently uses `lea` to perform **simple additions and multiplications in a single instruction**, exploiting the processor's address-computation mechanism:

```asm
lea     eax, [rdi+rsi]           ; eax = rdi + rsi        (addition)  
lea     eax, [rdi+rdi*2]         ; eax = rdi * 3          (multiplication by 3)  
lea     eax, [rdi*4+0x5]         ; eax = rdi * 4 + 5      (scale + offset)  
lea     eax, [rdi+rsi*8+0xa]     ; eax = rdi + rsi*8 + 10 (combination)  
```

This use has **nothing to do with addresses** — it is pure arithmetic. GCC chooses `lea` over an `add` + `imul` sequence because `lea` can combine an addition, a shift (multiplication by 1, 2, 4, or 8), and an immediate offset in a single instruction.

```c
// C code
int index = row * 3 + col;
```

```asm
; GCC -O2
lea     eax, [rdi+rdi*2]     ; eax = row * 3  
add     eax, esi              ; eax = row * 3 + col  
```

Or even more compact if the registers are well placed:

```asm
lea     eax, [rsi+rdi*2+rdi]  ; eax = col + row*2 + row = col + row*3
```

> 💡 **For RE**: when you see a `lea` whose bracket expression involves multiplications (`*2`, `*4`, `*8`) or additions of registers, don't look for a memory access — it is arithmetic optimized by the compiler. Just translate the expression as-is.

### The x86-64 addressing mode at a glance

The bracket expression, whether in a `mov` or an `lea`, follows the general form:

```
[base + index * scale + displacement]
```

Where:

- **base**: any register (often `rbp`, `rsp`, `rax`…)  
- **index**: any register except `rsp`  
- **scale**: a multiplicative factor, only **1, 2, 4, or 8**  
- **displacement**: a signed immediate constant (8 or 32 bits)

All components are optional. Here are concrete examples and their meaning in C terms:

| Assembly | Address computation | Typical C correspondence |  
|---|---|---|  
| `[rbp-0x4]` | `rbp - 4` | Local `int` variable |  
| `[rdi]` | `rdi` | Dereference `*ptr` |  
| `[rdi+0x10]` | `rdi + 16` | Structure field `ptr->field` |  
| `[rdi+rsi*4]` | `rdi + rsi*4` | Array of `int`: `arr[i]` |  
| `[rdi+rsi*8]` | `rdi + rsi*8` | Array of pointers: `ptrs[i]` |  
| `[rip+0x2345]` | `rip + 0x2345` | Global data / literal string |

The *scale* factor (1, 2, 4, 8) corresponds exactly to the element size in an array: 1 for `char`, 2 for `short`, 4 for `int`/`float`, 8 for `long`/`double`/pointer. It is a valuable clue for guessing the type of the manipulated data.

---

## AT&T syntax vs Intel syntax — the essentials

Two syntaxes coexist in the GNU ecosystem. By default, `objdump` and GAS (the GNU assembler) use AT&T syntax, while most RE tools (Ghidra, IDA, Binary Ninja) use Intel syntax. Here are the main differences:

| Characteristic | Intel (this tutorial) | AT&T (`objdump` default) |  
|---|---|---|  
| Operand order | `mov dest, src` | `mov src, dest` |  
| Register prefix | none (`rax`) | `%` (`%rax`) |  
| Immediate prefix | none (`0x42`) | `$` (`$0x42`) |  
| Size suffix | keyword (`dword`, `qword`) | instruction suffix (`l`, `q`) |  
| Memory access | `[rbp-0x4]` | `-0x4(%rbp)` |

The same code in both syntaxes:

```asm
; Intel
mov     dword [rbp-0x4], 0x2a  
lea     rdi, [rip+0x1234]  
call    puts@plt  
```

```asm
# AT&T
movl    $0x2a, -0x4(%rbp)  
lea     0x1234(%rip), %rdi  
call    puts@plt  
```

To force `objdump` into Intel syntax:

```bash
objdump -d -M intel ./my_binary
```

This tutorial uses Intel syntax exclusively. Chapter 7 revisits both syntaxes in detail and how to convert between them.

---

## `nop` — the instruction that does nothing (but matters)

You will regularly come across `nop` (*No Operation*) instructions in disassembled code. They perform no operation and modify no register or flag.

```asm
nop                          ; 1 byte — opcode 0x90  
nop dword [rax]              ; multi-byte (padding)  
nop word [rax+rax+0x0]       ; long variant (padding)  
```

GCC inserts `nop`s to **align** the start of functions or loops on 16-byte boundaries, which improves instruction-cache and branch-prediction performance. It is never application logic — in RE, you can ignore them without losing information.

> 💡 **For RE**: if you see unusually long sequences of `nop` inside a function (not just as padding between functions), it may be the sign of a **patch** applied to the binary — the original opcodes have been replaced with `nop`s to disable an instruction or a branch. It is a classic binary patching technique that we will see in Chapter 21.

---

## Putting it all together: reading a complete prologue and epilogue

Now that each instruction is understood individually, let's look at how they chain together in a real GCC -O0-compiled function:

```c
// Source C code
#include <stdio.h>

void greet(const char *name) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Hello, %s!", name);
    puts(buf);
}
```

```asm
; GCC -O0 disassembly (Intel syntax, simplified)

greet:
    ; === PROLOGUE ===
    push    rbp                      ; saves the old base pointer
    mov     rbp, rsp                 ; establishes the new base pointer
    sub     rsp, 0x50                ; reserves 80 bytes on the stack (buf + alignment)
    
    ; save the argument name (passed in rdi)
    mov     qword [rbp-0x48], rdi    ; stores name on the stack

    ; === BODY ===
    ; call to snprintf(buf, 64, "Hello, %s!", name)
    mov     rcx, qword [rbp-0x48]    ; rcx = name         (4th argument)
    lea     rdx, [rip+0xf2a]         ; rdx = "Hello, %s!" (3rd argument)
    mov     esi, 0x40                ; esi = 64            (2nd argument)
    lea     rdi, [rbp-0x40]          ; rdi = &buf[0]       (1st argument — address of buf)
    call    snprintf@plt

    ; call to puts(buf)
    lea     rdi, [rbp-0x40]          ; rdi = &buf[0]       (1st argument)
    call    puts@plt

    ; === EPILOGUE ===
    leave                            ; equivalent to: mov rsp, rbp / pop rbp
    ret                              ; returns to the caller
```

Every instruction in this example has been covered in this section:

- `push rbp` / `mov rbp, rsp` / `sub rsp, N` — the classic prologue.  
- `mov` in its register-memory variants to save and load values.  
- `lea` to compute the address of `buf` (local variable) and the address of the format string.  
- `call` for function calls via the PLT.  
- `leave` + `ret` — the epilogue. `leave` is a shortcut for `mov rsp, rbp` followed by `pop rbp`; it undoes in one instruction what the prologue built in two.

---

## What to remember going forward

1. **`mov`** is everywhere — learn to quickly read its forms (register ← memory, memory ← register, register ← immediate) and the size prefixes (`byte`, `dword`, `qword`).  
2. **`push`/`pop`** bracket functions (prologue/epilogue) and save callee-saved registers — counting them verifies the sanity of a stack frame.  
3. **`call`/`ret`** structure the execution flow — a direct `call` gives the target, an indirect `call` requires resolution (function pointer, vtable, PLT).  
4. **`lea`** never touches memory — it is either computing an address (`&x` in C) or optimized arithmetic (`a + b*4 + c`).  
5. **Brackets `[ ]` always mean a memory access**, except in an `lea` where they delimit the effective-address computation.  
6. **Intel syntax** (dest, src) is the standard of this tutorial and of most RE tools.

---


⏭️ [Arithmetic and logic: `add`, `sub`, `imul`, `xor`, `shl`/`shr`, `test`, `cmp`](/03-x86-64-assembly/03-arithmetic-logic.md)
