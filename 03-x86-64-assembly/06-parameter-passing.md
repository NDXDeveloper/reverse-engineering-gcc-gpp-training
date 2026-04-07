🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.6 — Parameter passing: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` then the stack

> 🎯 **Goal of this section**: know how to identify, in disassembled code, the arguments passed to each function call — a fundamental RE reflex. Section 3.5 laid down the rules of the System V AMD64 convention. Here, we move on to practice: how these rules actually appear in GCC disassembly, which patterns to observe, and which pitfalls to avoid.

---

## The "read the arguments" reflex

In RE, every `call` you encounter raises the same immediate question: **"what arguments does this function receive?"**. The answer is in the instructions that **precede** the `call` — they are the argument preparation instructions.

The method is always the same:

1. Spot the `call`.  
2. Walk back instruction by instruction to identify writes into `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (and `xmm0`–`xmm7` for floating-point).  
3. Check whether there are `push`es or `mov [rsp+X], ...` for arguments beyond the sixth.

```asm
; Which call is this?
mov     edx, 0xa             ; 3rd argument = 10  
lea     rsi, [rip+0x2f1a]    ; 2nd argument = address of a string  
mov     rdi, rbx              ; 1st argument = value of rbx (a pointer?)  
call    some_function  
```

In three lines, you know that `some_function` receives three arguments: a pointer in `rdi`, a string in `rsi`, and the integer 10 in `rdx`.

---

## Register order recap

For integer and pointer arguments:

```
Argument:    1st     2nd     3rd     4th     5th     6th     7th+  
Register:    rdi     rsi     rdx     rcx     r8      r9      stack  
```

For floating-point arguments (`float`, `double`):

```
Argument:    1st     2nd     3rd     4th     5th     6th     7th     8th     9th+  
Register:    xmm0    xmm1    xmm2    xmm3    xmm4    xmm5    xmm6    xmm7    stack  
```

Integer and floating-point counters are **independent**. A function `f(int a, double b, int c)` uses `edi` for `a`, `xmm0` for `b`, and `esi` for `c` — not `rdx`.

---

## Detailed practical examples

### Simple call: `puts(msg)`

```c
puts("Hello, world!");
```

```asm
lea     rdi, [rip+0x2e5a]    ; rdi = address of "Hello, world!" in .rodata  
call    puts@plt  
```

A single argument, a pointer to a string. The `lea` with RIP-relative addressing is the standard pattern for loading the address of a literal string.

### Call with multiple types: `printf(fmt, n, x)`

```c
printf("n = %d, x = %f\n", n, x);
```

```asm
lea     rdi, [rip+0x1b3f]        ; 1st arg (int #1): format string  
mov     esi, dword [rbp-0x4]     ; 2nd arg (int #2):  n  
movsd   xmm0, qword [rbp-0x10]  ; 1st float arg:     x  
mov     eax, 1                    ; number of SSE registers used (variadic)  
call    printf@plt  
```

Notice how the counters are independent: `rdi` takes the 1st integer argument, `rsi` the 2nd integer argument, and `xmm0` the 1st floating-point argument. The `mov eax, 1` is the SSE counter specific to variadic functions (cf. section 3.5).

### Call with 6 arguments: `mmap`

```c
void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
```

```asm
xor     r9d, r9d              ; 6th arg: offset = 0  
mov     r8d, 0xffffffff       ; 5th arg: fd = -1  
mov     ecx, 0x22             ; 4th arg: MAP_PRIVATE|MAP_ANONYMOUS (0x22)  
mov     edx, 0x3              ; 3rd arg: PROT_READ|PROT_WRITE (0x3)  
mov     esi, 0x1000           ; 2nd arg: length = 4096  
xor     edi, edi              ; 1st arg: addr = NULL  
call    mmap@plt  
```

The six argument registers are used. Note that GCC uses `xor edi, edi` to pass `NULL` (0) and `xor r9d, r9d` to pass 0 — the zeroing idiom seen in section 3.3.

> 💡 **For RE**: when you know the prototype of the called function (because it is a libc function, a syscall wrapper, or because you have already analyzed it), you can **name** each argument register. That is the first step of annotating the disassembly.

### Call with more than 6 arguments: arguments on the stack

```c
long result = func7(10, 20, 30, 40, 50, 60, 70);
```

```asm
; 7th argument → stack
mov     dword [rsp], 0x46        ; [rsp] = 70 (7th argument, at top of stack)  
mov     r9d, 0x3c                ; 6th arg = 60  
mov     r8d, 0x32                ; 5th arg = 50  
mov     ecx, 0x28                ; 4th arg = 40  
mov     edx, 0x1e                ; 3rd arg = 30  
mov     esi, 0x14                ; 2nd arg = 20  
mov     edi, 0xa                 ; 1st arg = 10  
call    func7  
```

When the space for stack arguments has been reserved in the prologue (via the `sub rsp`), GCC uses `mov [rsp+offset], value` rather than `push`. That avoids changing `rsp` between arguments.

If there are multiple stack arguments, they are laid out at increasing offsets from `rsp`:

```asm
mov     qword [rsp+0x8], 80     ; 8th argument  
mov     qword [rsp], 70         ; 7th argument (at the top)  
; ... registers for the first 6 ...
call    func8
```

> 💡 **For RE**: stack arguments are less intuitive to spot than register arguments, because `mov [rsp+X], ...` can be confused with writes to local variables. The key is **proximity to the `call`**: if a `mov [rsp+X]` appears in the argument-prep block just before a `call`, it is probably a stack argument, not a local variable.

---

## Passing structures by value

When a structure is passed by value, the behavior depends on its size and composition:

### Small structures (≤ 16 bytes)

Structures of 16 bytes or less containing integer types are decomposed and passed in registers:

```c
typedef struct {
    int x;
    int y;
} Point;

void draw(Point p, int color);
```

```asm
; draw((Point){10, 20}, 0xFF0000)
; The Point struct (8 bytes) fits in a single 64-bit register
mov     rdi, 0x0000001400000000a  ; rdi = {x=10, y=20} packed into 64 bits
                                   ; (10 in low 32 bits, 20 in high 32 bits)
mov     esi, 0xff0000             ; 2nd arg: color  
call    draw  
```

In practice, GCC may use one or two registers depending on the size and content:

| Struct size | Content | Registers used |  
|---|---|---|  
| ≤ 8 bytes, integers | `int`, `short`, `char`, pointers | 1 register (`rdi`) |  
| 9–16 bytes, integers | two 8-byte fields | 2 registers (`rdi` + `rsi`) |  
| ≤ 16 bytes, mixed | integers + floating-point | 1 integer (`rdi`) + 1 SSE (`xmm0`) |

### Large structures (> 16 bytes)

Structures larger than 16 bytes are passed **by copying onto the stack**. The caller copies the entire structure onto the stack before the `call`:

```c
typedef struct {
    char name[32];
    int id;
    double score;
} Record;

void process(Record r);
```

```asm
; Copying the structure onto the stack before the call
sub     rsp, 0x30                    ; reserves space  
mov     rax, qword [rbp-0x38]       ; copies the first 8 bytes  
mov     qword [rsp], rax  
mov     rax, qword [rbp-0x30]       ; copies the next 8  
mov     qword [rsp+0x8], rax  
; ... copy continues ...
call    process
```

> ⚠️ **For RE**: a series of `mov`s that copy 8-byte blocks from `[rbp-X]` to `[rsp+Y]` just before a `call` is the signature of a large structure being passed by value. If you see this pattern, the function receives a structure, not a series of independent arguments. GCC may also use `rep movsb` or `rep movsq` for larger copies.

### The common case: passing by pointer

In practice, C programmers pass large structures by pointer (`const struct *`), which reduces to simply passing a pointer in a register:

```c
void process(const Record *r);
```

```asm
lea     rdi, [rbp-0x38]     ; rdi = address of the local structure  
call    process  
```

This is the most frequent form in real code. A `lea rdi, [rbp-X]` followed by a `call` almost always means "pass the address of a local variable".

---

## Recognizing arguments in optimized code

At `-O0`, argument preparation is a predictable, linear block of instructions just before the `call`. With optimizations (`-O1` and above), things get more complicated.

### Argument propagation

GCC can propagate arguments from one function directly into the argument registers of the next function, without going through the stack:

```c
void wrapper(int a, int b) {
    inner(a, b, 0);
}
```

At `-O0`:

```asm
; Saves arguments on the stack, then reloads them
wrapper:
    push    rbp
    mov     rbp, rsp
    mov     dword [rbp-0x4], edi     ; saves a
    mov     dword [rbp-0x8], esi     ; saves b
    mov     edx, 0                    ; 3rd arg = 0
    mov     esi, dword [rbp-0x8]     ; reloads b → 2nd arg
    mov     edi, dword [rbp-0x4]     ; reloads a → 1st arg
    call    inner
    ; ...
```

At `-O2`:

```asm
; Arguments stay in their original registers
wrapper:
    xor     edx, edx         ; 3rd arg = 0
    jmp     inner             ; tail call — rdi and rsi are already in place!
```

The optimized code is much more compact: `rdi` and `rsi` already contain `a` and `b` (since `wrapper` received them in those same registers), so GCC just adds the third argument and makes a *tail call* (`jmp` instead of `call` — cf. Chapter 16).

> 💡 **For RE**: in optimized code, arguments are not always visibly written into the registers right before the `call`. If a function receives `x` in `rdi` and immediately calls `inner(x, ...)`, `rdi` is never rewritten — it is already in place. You then have to walk further back in the code (even to the start of the function) to understand where the value comes from.

### Interleaved argument preparations

Optimized GCC may **interleave** argument preparations for several calls or mix computations with argument loads:

```asm
mov     ebx, edi              ; saves 1st arg into rbx (callee-saved)  
lea     rdi, [rip+0x1234]    ; prepares 1st arg of the FIRST call  
mov     esi, ebx              ; prepares 2nd arg of the FIRST call  
call    printf@plt  

mov     edi, ebx              ; prepares 1st arg of the SECOND call  
call    process  
```

Here, `ebx` serves as a callee-saved "temporary variable" to preserve the original `edi` value across the first `call`. It is a classic optimization pattern.

### Computed arguments

The argument may be the result of a complex computation, not a simple copy:

```c
process(a * 3 + offset, ptr->field);
```

```asm
lea     edi, [rax+rax*2]         ; edi = a * 3  
add     edi, ecx                  ; edi = a * 3 + offset (1st argument)  
mov     esi, dword [rdx+0x10]    ; esi = ptr->field       (2nd argument)  
call    process  
```

The first argument is not a simple load but the result of a `lea` + `add`. It is common in optimized code, and you must follow the chain of computations to understand the actual value passed.

---

## Special case: libc functions

Standard C library functions are the ones you will most often encounter in a binary. Knowing their prototype makes it possible to identify arguments instantly:

### `memcpy` / `memmove`

```c
void *memcpy(void *dest, const void *src, size_t n);
```

```asm
mov     edx, 0x40              ; 3rd arg: n = 64 bytes  
lea     rsi, [rbp-0x60]        ; 2nd arg: src = local address  
mov     rdi, rbx                ; 1st arg: dest = pointer in rbx  
call    memcpy@plt  
```

`rdi` = destination, `rsi` = source, `rdx` = size. The destination-source-size order is the same as in C.

### `strcmp` / `strncmp`

```c
int strcmp(const char *s1, const char *s2);
```

```asm
lea     rsi, [rip+0x1a2b]     ; 2nd arg: constant string "password"  
mov     rdi, rax                ; 1st arg: user input  
call    strcmp@plt  
test    eax, eax                ; check if return == 0 (equal strings)  
je      .success  
```

This pattern (`strcmp` followed by `test eax, eax` / `je` or `jne`) is the classic target of crackme reverse engineering and password checks — we come back to it in detail in Chapter 21.

### `malloc` / `calloc` / `free`

```c
void *malloc(size_t size);  
void *calloc(size_t nmemb, size_t size);  
void free(void *ptr);  
```

```asm
; malloc(256)
mov     edi, 0x100          ; 1st arg: size = 256  
call    malloc@plt  
mov     rbx, rax             ; saves the returned pointer  

; calloc(10, sizeof(int))
mov     esi, 4               ; 2nd arg: element size = 4  
mov     edi, 0xa             ; 1st arg: number of elements = 10  
call    calloc@plt  

; free(ptr)
mov     rdi, rbx             ; 1st arg: pointer to free  
call    free@plt  
```

### `open` / `read` / `write` / `close`

```c
int open(const char *pathname, int flags, mode_t mode);  
ssize_t read(int fd, void *buf, size_t count);  
ssize_t write(int fd, const void *buf, size_t count);  
```

```asm
; open("config.dat", O_RDONLY)
xor     esi, esi               ; 2nd arg: flags = O_RDONLY (0)  
lea     rdi, [rip+0x2345]     ; 1st arg: pathname  
call    open@plt  
mov     ebx, eax               ; saves the returned fd  

; read(fd, buf, 1024)
mov     edx, 0x400             ; 3rd arg: count = 1024  
lea     rsi, [rbp-0x420]      ; 2nd arg: buf (local buffer)  
mov     edi, ebx               ; 1st arg: fd  
call    read@plt  
```

> 💡 **For RE**: progressively building a mental "map" of libc prototypes is one of the most rewarding investments. When you see a `call` to a libc function, instantly decoding the arguments gives you the context: which string is compared, which file is opened, how many bytes are read, to what address you copy…

---

## Arguments and C++ functions: the `this` pointer

In C++ compiled by GCC (Itanium ABI), non-static methods of a class receive a **hidden first argument**: the `this` pointer, passed in `rdi`.

```cpp
class Player {  
public:  
    void set_health(int hp);
    int get_health() const;
};

player.set_health(100);  
player.get_health();  
```

```asm
; player.set_health(100)
mov     esi, 0x64            ; visible 2nd arg = 100 (hp)  
mov     rdi, rbx              ; 1st arg = &player (this)  
call    _ZN6Player10set_healthEi  

; player.get_health()
mov     rdi, rbx              ; only arg = &player (this)  
call    _ZNK6Player10get_healthEv  
```

All explicit method arguments are **shifted by one position** compared to the C++ prototype:

| C++ parameter | Actual register |  
|---|---|  
| `this` (implicit) | `rdi` |  
| 1st explicit parameter | `rsi` |  
| 2nd explicit parameter | `rdx` |  
| 3rd explicit parameter | `rcx` |  
| … | … |

> ⚠️ **For RE**: this is a classic pitfall. If you analyze a C++ method and identify its parameters, remember that `rdi` is `this` — the first "real" parameter is in `rsi`. Chapter 17 covers the C++ object model and name mangling in depth.

---

## When arguments are no longer in registers

Several situations cause arguments received in registers to end up on the stack at the start of the function:

### The "spill" at `-O0`

At `-O0`, GCC **systematically saves** all arguments received by register onto the stack, even though it could keep them in registers:

```asm
func:
    push    rbp
    mov     rbp, rsp
    mov     dword [rbp-0x14], edi    ; spill arg 1
    mov     dword [rbp-0x18], esi    ; spill arg 2
    mov     dword [rbp-0x1c], edx    ; spill arg 3
    ; ... the body uses [rbp-0x14] etc. rather than edi/esi/edx
```

It is a debugging behavior: by keeping everything on the stack, GDB can always inspect arguments even after registers have been reused. At `-O1+`, these spills disappear and arguments remain in registers as long as possible.

> 💡 **For RE**: at `-O0`, the first instructions after the prologue are often `mov [rbp-X], rdi/rsi/rdx/...`. That is the argument spill. By counting them, you directly obtain the **number of parameters** of the function and their order. It is one of the advantages of RE on a non-optimized binary.

### Saving before an internal `call`

Even in optimized code, if a function needs to preserve an argument across an internal `call` (since `rdi`, `rsi`, etc. are caller-saved), it saves it either in a callee-saved register or on the stack:

```asm
; Save into a callee-saved
func:
    push    rbx
    mov     ebx, edi          ; saves arg1 into rbx (callee-saved)
    ; ... 
    call    helper             ; rdi is clobbered, but ebx survives
    mov     edi, ebx           ; restores arg1 for later use
```

```asm
; Save onto the stack
func:
    sub     rsp, 0x18
    mov     dword [rsp+0xc], edi    ; saves arg1 onto the stack
    ; ...
    call    helper
    mov     edi, dword [rsp+0xc]    ; reloads arg1
```

---

## Deducing the prototype of an unknown function

One of the central exercises of RE is to reconstruct the prototype of a function whose source code you do not have. Here is the systematic method:

### Step 1 — Identify the number of arguments

Analyze **all call sites** of the function (via cross-references / XREFs in Ghidra or IDA). For each call, note which registers are written in the preparation block:

```
Call site 1:  rdi, rsi, edx written    → at least 3 arguments  
Call site 2:  rdi, rsi, edx written    → confirms 3 arguments  
Call site 3:  only rdi, rsi written    → possibly 2 arguments? Check rdx  
```

If `rdx` is not explicitly written at site 3, it may hold a leftover value — but if the function actually uses `rdx`, GCC guarantees it is initialized. You then have to look at the function body to see whether `rdx`/`edx` is read.

### Step 2 — Identify the argument types

Observe the size of the registers used and the operations performed on the arguments:

| Observation | Probable type |  
|---|---|  
| `mov edi, ...` (32-bit) | `int` or `unsigned int` |  
| `mov rdi, ...` (64-bit) | pointer, `long`, `size_t` |  
| `lea rdi, [rip+...]` | pointer to global data / string |  
| `lea rdi, [rbp-X]` | pointer to local variable |  
| `movsd xmm0, ...` | `double` |  
| `movss xmm0, ...` | `float` |  
| `movzx edi, byte [...]` | `unsigned char` promoted to `int` |  
| `movsx edi, byte [...]` | `char` (signed) promoted to `int` |

### Step 3 — Identify the return type

Observe how the caller uses `rax`/`eax`/`xmm0` after the `call`:

```asm
call    mystery_func  
test    eax, eax         ; compares return with 0 → returns int (or bool)  
je      .error  

call    mystery_func  
mov     rbx, rax          ; saves a pointer → returns void* or char*  
mov     rdi, rax  
call    strlen@plt         ; passes return to strlen → it is a string!  

call    mystery_func       ; no use of rax afterward → returns void  
mov     edi, 0  
call    exit@plt  
```

### Step 4 — Synthesize the prototype

Combining the information:

```
Arguments:  rdi = pointer (char*), esi = int, edx = int  
Return:     eax tested as boolean, then string passed to puts  

→ Reconstructed prototype:
   int mystery_func(const char *input, int param1, int param2);
```

> 💡 **For RE**: Ghidra performs this analysis automatically and proposes an inferred prototype in its "Decompiler" window. But the result is not always correct — knowing how to do this analysis manually is essential to validate or correct the tool's inferences.

---

## Difference with the Windows x64 (Microsoft ABI) convention

If you analyze a Windows binary compiled with MinGW (GCC for Windows), the calling convention is **different**:

| Aspect | System V AMD64 (Linux) | Microsoft x64 (Windows) |  
|---|---|---|  
| Argument registers | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` | `rcx`, `rdx`, `r8`, `r9` |  
| Number of register args | 6 | 4 |  
| *Shadow space* | No | Yes (32 bytes reserved by the caller) |  
| Red zone | 128 bytes | None |  
| Callee-saved registers | `rbx`, `rbp`, `r12`–`r15` | `rbx`, `rbp`, `rdi`, `rsi`, `r12`–`r15` |  
| SSE variadic counter | `al` | No |

The two most visible differences in the disassembly:

1. **Register order**: under Windows, the first argument is in `rcx` (not `rdi`). If you see `mov ecx, ...` as the first argument, you are probably analyzing a Windows binary.  
2. **Shadow space**: under Windows, the caller always reserves 32 bytes on the stack before each `call`, even if the called function does not use these bytes. That produces a systematic `sub rsp, 0x20` (or more) before each `call`.

This tutorial focuses on the System V AMD64 (Linux) convention, but this difference is important to know if you analyze a PE binary compiled with MinGW — the GCC compile flags are the same, but the calling convention changes.

---

## What to remember going forward

1. **Reading arguments = walking back from the `call`** by identifying writes into `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (integers) and `xmm0`–`xmm7` (floats).  
2. **At `-O0`**, arguments are systematically spilled onto the stack at the start of the function — counting them gives you the number of parameters.  
3. **In optimized code**, arguments can remain in their original registers, be propagated directly, or be saved into callee-saved registers (`rbx`, `r12`…) rather than on the stack.  
4. **In C++**, `rdi` is always `this` for non-static methods — all explicit parameters are shifted by one position.  
5. **The register size reveals the type**: `edi` = `int`, `rdi` = pointer, `xmm0` via `movsd` = `double`, `xmm0` via `movss` = `float`.  
6. **Libc prototypes** are your best ally: knowing `strcmp(rdi, rsi)`, `memcpy(rdi, rsi, rdx)`, `open(rdi, esi, edx)` considerably speeds up analysis.  
7. **Under Windows** (MinGW), the convention changes: `rcx`, `rdx`, `r8`, `r9` instead of `rdi`, `rsi`, `rdx`, `rcx` — and the 32-byte shadow space is omnipresent.

---


⏭️ [Reading an assembly listing without panicking: a practical 5-step method](/03-x86-64-assembly/07-reading-assembly-method.md)
