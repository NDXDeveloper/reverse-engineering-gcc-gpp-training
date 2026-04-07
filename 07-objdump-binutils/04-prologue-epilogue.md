🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 7.4 — Reading function prologues/epilogues in practice

> 🔧 **Tools used**: `objdump`, `readelf`  
> 📦 **Binaries**: `keygenme_O0`, `keygenme_O2`, `keygenme_strip` (`binaries/ch07-keygenme/` directory)  
> 📝 **Syntax**: Intel (via `-M intel`)

---

## The prologue and epilogue: the boundaries of each function

Chapter 3 (section 3.5) introduced the theory of the prologue and epilogue within the System V AMD64 calling convention. This section moves to practice: we will read these sequences **directly in an `objdump` listing**, learn to spot them instantly, understand their variants depending on the optimization level, and above all use them as a navigation tool in a binary — particularly when symbols are absent.

In RE, the prologue and epilogue serve two essential roles:

- **Delimiting functions.** This is the most immediate role. A prologue marks the start of a function, an epilogue marks its end. On a stripped binary, it is your primary means of segmenting the instruction flow into logical units.  
- **Revealing the internal structure of the function.** The size of the stack allocation tells you how much space is reserved for local variables. Saving *callee-saved* registers tells you which registers the function uses. The presence or absence of the frame pointer informs you about the optimization level.

---

## The classic prologue at `-O0`

Let's start with the most common and most readable case: a function compiled without optimization.

```bash
objdump -d -M intel keygenme_O0 | less
```

Search for the start of any function. You'll systematically find this sequence:

```asm
push   rbp                    ; (1) Save the old frame pointer  
mov    rbp, rsp               ; (2) Establish the new frame pointer  
sub    rsp, 0x20              ; (3) Allocate space for local variables  
```

Let's break down each instruction.

### Instruction (1): `push rbp`

Before establishing its own *stack frame*, the function saves the calling function's frame pointer. It's a contract: when the function ends, it will restore `rbp` to its original value, so the caller recovers its own frame intact.

After this instruction, `rsp` has decreased by 8 (the size of a 64-bit register) and the old value of `rbp` is at the top of the stack.

### Instruction (2): `mov rbp, rsp`

The frame pointer now points to the current top of the stack. From this instant, `rbp` is "anchored": it will not move during the entire function execution, even if `rsp` fluctuates (function calls, dynamic allocations). All local variables will be accessible via negative displacements relative to `rbp` (`[rbp-0x4]`, `[rbp-0x8]`, etc.), and arguments passed via the stack (if any) via positive displacements (`[rbp+0x10]`, `[rbp+0x18]`, etc.).

### Instruction (3): `sub rsp, N`

The stack pointer descends by `N` bytes to reserve local-variable space. The value of `N` gives you a precious indication: a function with `sub rsp, 0x80` (128 bytes) probably has many local variables or a stack array, while a function with `sub rsp, 0x10` (16 bytes) only has a few.

This instruction is sometimes absent for very simple *leaf* functions (functions that don't call any other function), because they can work entirely in registers without touching the stack beyond saving `rbp`.

> 💡 **Alignment**: the System V AMD64 convention requires that `rsp` be aligned on 16 bytes **before** each `call` instruction. GCC adjusts the value of `sub rsp, N` to guarantee this alignment. You'll sometimes see allocations that seem larger than necessary — that's alignment padding, not hidden variables.

### Variant with callee-saved register saves

When the function needs to use *callee-saved* registers (`rbx`, `r12`–`r15`), it saves them in the prologue:

```asm
push   rbp  
mov    rbp, rsp  
push   rbx                    ; save rbx (callee-saved)  
push   r12                    ; save r12 (callee-saved)  
sub    rsp, 0x18              ; allocate local variables  
```

Order is significant: the callee-saved register `push`es come **after** establishing the frame pointer and **before** allocating local variables. Each extra `push` shifts `rsp` by 8 bytes, and GCC takes this into account when computing the `sub rsp`.

In RE, counting callee-saved register `push`es tells you how many "heavy" registers the function uses internally. A function that saves `rbx`, `r12`, `r13`, and `r14` is probably complex, with many values to preserve across sub-function calls.

---

## The classic epilogue at `-O0`

The epilogue is the exact mirror of the prologue. It undoes everything the prologue built, in reverse order:

```asm
leave                          ; (1) Restore rsp and rbp  
ret                            ; (2) Return to the caller  
```

### Instruction (1): `leave`

The `leave` instruction is a shortcut for two operations:

```asm
mov    rsp, rbp                ; rsp returns to the frame pointer level  
pop    rbp                     ; restore the old frame pointer  
```

It cancels in one go the allocation of local variables (`sub rsp, N`) and the save of the frame pointer (`push rbp`). After `leave`, the stack is in the exact state it was in just after the `call` that invoked the function — that is, the top of the stack contains the return address.

### Instruction (2): `ret`

`ret` pops the return address (placed by the caller's `call`) and jumps to that address. Execution resumes in the calling function, just after the `call`.

### Variant with callee-saved register restoration

If the prologue saved registers, the epilogue restores them in **reverse order**:

```asm
; Epilogue with restoration
add    rsp, 0x18              ; free local variables  
pop    r12                     ; restore r12 (inverse of push r12)  
pop    rbx                     ; restore rbx (inverse of push rbx)  
pop    rbp                     ; restore rbp (inverse of push rbp)  
ret  
```

Note that in this case, `leave` is **not** used. GCC explicitly generates `add rsp` followed by `pop`s in reverse order of the prologue's `push`es. The stack is a LIFO structure — the last register saved is the first restored.

### Variant without `leave`: `pop rbp` + `ret`

Sometimes, instead of `leave`, GCC generates the equivalent decomposed sequence:

```asm
pop    rbp  
ret  
```

It's functionally identical to `leave` + `ret` when there was no `sub rsp` allocation (the stack is already at the right level). The processor executes them equivalently.

---

## The stack-frame layout in memory

To properly read a prologue, you need to have in mind the stack-frame layout after its establishment. Here is what the stack looks like after a full prologue:

```
High addresses (beginning of stack)
┌──────────────────────────────────┐
│  Arguments passed via the stack  │  [rbp+0x18], [rbp+0x10]
│  (7th argument and beyond)       │  (if > 6 arguments)
├──────────────────────────────────┤
│  Return address                  │  [rbp+0x8]
│  (pushed by the caller's         │
│  call instruction)               │
├──────────────────────────────────┤
│  Saved old rbp                   │  [rbp+0x0]  ← rbp points here
├──────────────────────────────────┤
│  Callee-saved registers          │  [rbp-0x8], [rbp-0x10]…
│  (rbx, r12, r13…)                │
├──────────────────────────────────┤
│  Local variables                 │  [rbp-0x14], [rbp-0x18]…
│  (int, char[], pointers…)        │
├──────────────────────────────────┤
│  Alignment / padding zone        │
├──────────────────────────────────┤
│  (free space)                    │  ← rsp points here
└──────────────────────────────────┘
Low addresses (top of stack)
```

This diagram is the key to interpreting memory accesses in the function body:

- `[rbp-0x4]` → first local variable (typically a 4-byte `int`)  
- `[rbp-0x8]` → second local variable, or continuation of an 8-byte variable  
- `[rbp-0x18]` → a parameter saved on the stack (GCC at `-O0` often copies parameters from registers to the stack at the start of the function)  
- `[rbp+0x8]` → return address (rarely accessed directly, except in security or exploitation code)  
- `[rbp+0x10]` → 7th argument (if the function has more than 6)

### Guessing local variables from the prologue

The `sub rsp, N` instruction gives you the total size of local space. Scanning the function body, `[rbp-X]` accesses reveal the offsets used. By crossing the two, you can reconstruct the list of local variables:

```asm
sub    rsp, 0x20                       ; 32 bytes allocated

; In the function body:
mov    DWORD PTR [rbp-0x4], 0x0        ; 4-byte local variable (int?)  
mov    DWORD PTR [rbp-0x8], 0x0        ; another 4-byte variable  
mov    QWORD PTR [rbp-0x18], rdi       ; save of the 1st parameter (pointer, 8 bytes)  
```

Here, you can deduce at least three local variables: two `int`s (4 bytes each) and a pointer (8 bytes), plus alignment padding. It's not an exact reconstruction of the source code, but it's an exploitable approximation.

---

## Prologues and epilogues at `-O2`: optimized variants

As seen in section 7.3, optimization significantly changes the appearance of prologues. Here are the forms you will encounter in practice.

### Case 1: no prologue at all (optimized *leaf function*)

A short function that doesn't call any other function and doesn't need a stack:

```asm
; Function start (no push rbp, no sub rsp)
movzx  eax, BYTE PTR [rdi]  
movsx  edx, al  
add    edx, esi  
mov    eax, edx  
ret  
```

No prologue, no epilogue other than `ret`. The function works entirely in registers. It's the most compact and fastest case, but also the most disorienting when searching for function boundaries in a stripped binary — there is no start marker.

### Case 2: minimal prologue with register saves

The function needs callee-saved registers but doesn't allocate space on the stack beyond that:

```asm
push   rbx                    ; save rbx  
mov    rbx, rdi               ; rbx = first parameter (kept across calls)  
; ... body ...
pop    rbx                    ; restore rbx  
ret  
```

No `push rbp` / `mov rbp, rsp`. The frame pointer is not maintained. The only `push`/`pop`s are those of callee-saved registers the function needs. It's the most common form at `-O2` for medium-sized functions.

### Case 3: prologue with stack allocation but no frame pointer

The function needs stack space (for example, for a local array or to save more values than registers allow), but does not use `rbp` as a frame pointer:

```asm
sub    rsp, 0x28              ; direct allocation  
mov    QWORD PTR [rsp+0x8], rbx  ; callee-saved on the stack  
mov    QWORD PTR [rsp], r12       ; same  
; ... body: access via [rsp+N] instead of [rbp-N] ...
mov    r12, QWORD PTR [rsp]  
mov    rbx, QWORD PTR [rsp+0x8]  
add    rsp, 0x28  
ret  
```

Accesses to local variables go through **`rsp`** instead of `rbp`. That's harder to read because `rsp` changes on every `push`, `pop`, `call`, and `sub rsp` — you have to track its value mentally. Advanced disassemblers like Ghidra handle this automatically by recomputing "stack depth" at each instruction.

### Case 4: frame pointer explicitly maintained despite `-O2`

If you compile with `-O2 -fno-omit-frame-pointer`, GCC maintains the frame pointer even in optimized mode. That's the case for some projects that want reliable backtraces in production (the Linux kernel, some servers). You then find the classic `push rbp` / `mov rbp, rsp` prologue, but the rest of the code is optimized (registers, reordering, etc.).

Some distributions compile system packages with `-fno-omit-frame-pointer` by default (Fedora notably). If you analyze a system binary and see classic prologues despite visibly optimized code, it's probably this flag.

---

## Recognizing function boundaries in a stripped listing

Let's put into practice what we know. On a stripped binary, function boundaries are no longer marked by labels. Here is a mental algorithm to apply when reading an `objdump` listing:

### Step 1: look for start patterns

Scan the listing for these sequences, in order of reliability:

1. **`push rbp` + `mov rbp, rsp`** — very strong signal of a function start at `-O0`/`-O1` or with `-fno-omit-frame-pointer`.  
2. **`endbr64`** — indirect flow-control instruction (*Indirect Branch Tracking*, IBT, part of CET). GCC inserts it at the start of each function when the binary is compiled with `-fcf-protection` (enabled by default on recent distributions). If you see `endbr64`, it's almost certainly the start of a function.  
3. **`push rbx`** or **`push r12`** at sequence start (just after a previous `ret`) — probable start of an optimized function that saves callee-saved registers.  
4. **`sub rsp, N`** just after a `ret` — probable start of an optimized leaf function with stack allocation.

### Step 2: look for end patterns

1. **`ret`** (or `rep ret`, an AMD idiom to avoid a branch-prediction penalty) — end of function.  
2. **`leave` + `ret`** — end of function with frame pointer.  
3. **Sequence of `pop` + `ret`** — end of function with register restoration.

### Step 3: correlate with `call`s

Each `call <address>` in the listing tells you a function starts at `<address>`. Collect all `call` targets: each is a confirmed function entry point.

```bash
# Extract the target addresses of all internal calls
objdump -d -M intel keygenme_strip | \
    grep -oP 'call\s+\K[0-9a-f]+(?=\s)' | \
    sort -u
```

### Step 4: beware of false positives

Some sequences look like prologues without being:

- **`push rbp` in the middle of a function**: rare but possible in code that manipulates `rbp` as a general-purpose register (at `-O2` without frame pointer, `rbp` can be used for anything).  
- **`ret` that is not a function end**: functions with multiple return paths have multiple `ret`s. The first `ret` encountered is not necessarily the end of the function — there may be other blocks after (else branch, error handling).  
- **Padding between functions**: GCC often inserts `nop` bytes (or `nop DWORD PTR [rax]`, a multi-byte form of `nop`) between functions to align them on 16-byte boundaries. These `nop`s appear between a `ret` and the next prologue. They do not belong to any function.

```asm
; End of the previous function
    11e0:       c3                      ret
; Alignment padding
    11e1:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
; Start of the next function
    11e8:       f3 0f 1e fa             endbr64
    11ec:       55                      push   rbp
```

If you see multi-byte `nop`s between a `ret` and a `push rbp` (or `endbr64`), it's padding — you've just confirmed a boundary between two functions.

---

## `endbr64`: the modern function-start marker

On binaries compiled with recent GCC on current distributions, you'll systematically see `endbr64` (opcode `f3 0f 1e fa`) at the very start of each function, before even the `push rbp`:

```asm
0000000000001139 <compute_hash>:
    1139:       f3 0f 1e fa             endbr64
    113d:       55                      push   rbp
    113e:       48 89 e5                mov    rbp, rsp
    ...
```

This instruction is part of Intel CET (*Control-flow Enforcement Technology*) technology. It tells the processor this address is a legitimate target of indirect branching. Its role is purely security-related (preventing certain flow-hijacking attacks), but for us in RE, it's a **reliable function-start marker**, even more recognizable than `push rbp` because the byte sequence `f3 0f 1e fa` is always identical.

```bash
# Count functions via endbr64
objdump -d -M intel keygenme_strip | grep -c "endbr64"
```

This count also includes PLT entries and a few C *runtime* stubs, but it's an excellent approximation of the function count.

---

## Reading a prologue to deduce the function's signature

The prologue and the first instructions of the function body give you clues about the function's **signature** (number and types of parameters).

Reminder of the System V AMD64 convention: the first 6 integer/pointer arguments are passed in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (in that order). Floating-point arguments use `xmm0`–`xmm7`. The return value is in `rax` (integer) or `xmm0` (floating-point).

At `-O0`, GCC systematically copies parameters from registers to the stack at the start of the function:

```asm
push   rbp  
mov    rbp, rsp  
sub    rsp, 0x20  
mov    QWORD PTR [rbp-0x18], rdi       ; save of the 1st parameter (64-bit pointer/integer)  
mov    DWORD PTR [rbp-0x1c], esi       ; save of the 2nd parameter (32-bit int)  
```

Seeing these initial `mov`s, you can deduce:

- The function takes at least 2 parameters.  
- The first (`rdi`) is a 64-bit integer or a pointer (saved with `QWORD PTR`).  
- The second (`esi`) is a 32-bit integer (saved with `DWORD PTR`, and it's `esi` — the low 32 bits of `rsi`).

At `-O2`, parameters are not copied on the stack (they stay in registers), but you can observe which argument registers are **used** in the first instructions:

```asm
; Start of an optimized function
movzx  eax, BYTE PTR [rdi]            ; uses rdi → 1st parameter (pointer)  
test   esi, esi                        ; uses esi → 2nd parameter (int)  
```

If the function uses `rdi`, `rsi`, and `rdx` in its first instructions (without having received them from a previous `call` or having computed them), it probably takes 3 parameters. It's a heuristic, not a certainty — but it works remarkably well in practice.

---

## Recognizing the return value

The return value is read in the instructions just **before** the `ret`:

```asm
; The function returns an int
mov    eax, DWORD PTR [rbp-0x4]       ; load the local 'result' variable  
leave  
ret  

; The function returns a pointer
mov    rax, QWORD PTR [rbp-0x10]      ; load a pointer  
leave  
ret  

; The function returns 0 (success / false)
xor    eax, eax                        ; eax = 0 (classic idiom)  
ret  

; The function returns 1 (true)
mov    eax, 0x1  
ret  
```

If a function has multiple `ret`s (multiple return paths), examine each of them. Often, one path returns 0 and another returns 1 — that's the pattern of a validation function (`bool check_something(…)`).

The `xor eax, eax` instruction just before a `ret` is an extremely common idiom worth memorizing: it sets `eax` to zero in two bytes (shorter and faster than `mov eax, 0`). GCC uses it systematically.

---

## Summary

The prologue and epilogue are the structural boundaries of each function. At `-O0`, the canonical prologue `push rbp` / `mov rbp, rsp` / `sub rsp, N` is systematic and easy to spot. At `-O2`, the frame pointer often disappears, the prologue reduces to `push`es of callee-saved registers or a simple `sub rsp`, and accesses to local variables go through `rsp` instead of `rbp`. The `endbr64` instruction, present on modern binaries, constitutes an even more reliable function-start marker than `push rbp`. The first instructions after the prologue reveal the function's parameters (via the argument registers used), and the instructions preceding `ret` reveal the return value. On a stripped binary, combining the search for prologues, epilogues, `call` targets, and alignment padding makes it possible to reconstruct the function map without any symbol.

---


⏭️ [Identifying `main()` and C++ functions (name mangling)](/07-objdump-binutils/05-identifying-main-mangling.md)
