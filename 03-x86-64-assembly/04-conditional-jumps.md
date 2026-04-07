🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.4 — Conditional and unconditional jumps: `jmp`, `jz`/`jnz`, `jl`, `jge`, `jle`, `ja`…

> 🎯 **Goal of this section**: master the jump instructions that translate *all* of C's control flow (`if`, `else`, `while`, `for`, `switch`, `break`, `continue`…) into assembly. Learn to recognize them and mentally reconstruct the original control structures.

---

## The fundamental mechanism

In C, control flow is expressed with structured keywords: `if`, `else`, `while`, `for`, `switch`. In assembly, **there is only one mechanism**: the jump. All C control structures reduce to combinations of conditional and unconditional jumps.

The principle, already hinted at in sections 3.1 and 3.3, boils down to two steps:

1. An instruction sets the flags (`cmp`, `test`, or any arithmetic/logic operation).  
2. A jump instruction **reads the flags** and modifies `rip` (jumps) if the condition is met.

If the condition is not met, execution simply continues at the next instruction — `rip` advances normally.

---

## `jmp` — unconditional jump

```
jmp  target
```

`jmp` transfers execution to the target address **without any condition**. It does not consult the flags. It is the direct equivalent of a `goto` in C.

**Direct form** (the most common):

```asm
jmp     .loop_start         ; jumps to a label within the same function  
jmp     0x40115a            ; jumps to an absolute address  
```

**Indirect form** (via register or memory):

```asm
jmp     rax                 ; jumps to the address in rax  
jmp     qword [rax+rcx*8]  ; jumps through a table (switch/jump table)  
```

In RE, you will see `jmp` in four main contexts:

- **Loops**: the backward jump that returns to the start of the loop.  
- **`else`**: the jump that skips the `then` block to reach the `else` block (or the end of the `if`).  
- **`break` / `continue`**: in loops and `switch` statements.  
- **Jump tables**: GCC's optimized implementation of `switch` (`jmp qword [table + index*8]`).

### Encoding: short jump vs near jump

The disassembler always displays the resolved target address, but in the binary encoding, the jump is relative to `rip`:

- **Short jump** (`jmp rel8`): 1-byte signed offset → ±128 bytes. Total encoding: 2 bytes.  
- **Near jump** (`jmp rel32`): 4-byte signed offset → ±2 GB. Total encoding: 5 bytes.

This distinction has a direct impact in **binary patching** (Chapter 21): replacing a jump with another requires respecting the original encoding size, otherwise all subsequent instructions shift.

---

## Conditional jumps — full reference table

Conditional jumps test one or more flags of `RFLAGS`. Each mnemonic corresponds to a precise condition. Most have **synonyms** — two different names for the same opcode — reflecting merely a different reading context ("zero" vs "equal", "less than" vs "not greater than or equal").

### Jumps for signed comparisons

These jumps are used after a `cmp` between signed values (`int`, `long`, signed `char`):

| Mnemonic | Synonym | Condition | Tested flags | C equivalent |  
|---|---|---|---|---|  
| `je` | `jz` | Equal / Zero | ZF = 1 | `a == b` |  
| `jne` | `jnz` | Not equal / Not zero | ZF = 0 | `a != b` |  
| `jl` | `jnge` | Less than | SF ≠ OF | `a < b` |  
| `jle` | `jng` | Less or equal | ZF = 1 or SF ≠ OF | `a <= b` |  
| `jg` | `jnle` | Greater than | ZF = 0 and SF = OF | `a > b` |  
| `jge` | `jnl` | Greater or equal | SF = OF | `a >= b` |

### Jumps for unsigned comparisons

These jumps are used after a `cmp` between unsigned values (`unsigned int`, pointers, `size_t`):

| Mnemonic | Synonym | Condition | Tested flags | C equivalent |  
|---|---|---|---|---|  
| `je` | `jz` | Equal / Zero | ZF = 1 | `a == b` |  
| `jne` | `jnz` | Not equal / Not zero | ZF = 0 | `a != b` |  
| `jb` | `jnae`, `jc` | Below | CF = 1 | `a < b` |  
| `jbe` | `jna` | Below or equal | CF = 1 or ZF = 1 | `a <= b` |  
| `ja` | `jnbe` | Above | CF = 0 and ZF = 0 | `a > b` |  
| `jae` | `jnb`, `jnc` | Above or equal | CF = 0 | `a >= b` |

### Single-flag jumps

| Mnemonic | Condition | Typical use |  
|---|---|---|  
| `js` | SF = 1 (negative result) | Sign test after arithmetic |  
| `jns` | SF = 0 (positive or zero result) | Sign test |  
| `jo` | OF = 1 (signed overflow) | Overflow check |  
| `jno` | OF = 0 (no overflow) | — |  
| `jp` / `jpe` | PF = 1 (even parity) | Rare in application code |  
| `jnp` / `jpo` | PF = 0 (odd parity) | Rare in application code |

### The memory aid

x86 terminology uses two word families to distinguish signed and unsigned:

- **Signed** → magnitude vocabulary: *Less*, *Greater* → `jl`, `jg`, `jle`, `jge`  
- **Unsigned** → position vocabulary: *Below*, *Above* → `jb`, `ja`, `jbe`, `jae`  
- **Equality** → shared: *Equal*, *Zero* → `je`/`jz`, `jne`/`jnz`

> 💡 **For RE**: the `jl`/`jg` (signed) vs `jb`/`ja` (unsigned) distinction directly gives you the signedness of the compared variables. If GCC generates a `jb` after a `cmp`, the two operands are treated as unsigned. It is a type hint as reliable as the `shr` vs `sar` distinction seen in section 3.3.

---

## Inverted condition: the GCC reflex

One point that often confuses RE beginners: **GCC almost always inverts the condition compared to the C source**. The reason is purely logical — the compiler generates code sequentially and uses the jump to *skip over* the block that must not be executed.

```c
// C code
if (x == 42) {
    do_something();
}
// ...
```

The natural expectation would be a `je` (Jump if Equal) to `do_something`. But GCC does the opposite:

```asm
cmp     eax, 0x2a          ; compares x with 42  
jne     .after_if           ; if x != 42, JUMP OVER the if block  
call    do_something        ; this code is only reached if x == 42  
.after_if:
; ...
```

The compiler places the code of the `then` block immediately after the `cmp`, and uses a jump with the **inverted** condition to skip it if the condition is false. Result:

| C condition | GCC jump (to skip the block) |  
|---|---|  
| `if (a == b)` | `jne` |  
| `if (a != b)` | `je` |  
| `if (a < b)` | `jge` |  
| `if (a >= b)` | `jl` |  
| `if (a > b)` | `jle` |  
| `if (a <= b)` | `jg` |

It is systematic at `-O0`. With optimizations enabled, GCC can reorder the code differently (placing the most likely case as fallthrough), but the inversion principle remains very common.

> ⚠️ **Reading rule**: when you encounter a conditional jump in RE, always ask yourself **"which block does this jump skip?"** rather than **"which block does this jump go to?"**. It is by identifying what is *skipped* that you reconstruct the original condition.

---

## Recognizing control structures

### Simple `if`

```c
if (a > 0) {
    result = 1;
}
```

```asm
cmp     eax, 0  
jle     .end_if           ; if a <= 0, skip the block  
mov     dword [rbp-0x4], 1 ; result = 1  
.end_if:
```

The pattern is: `cmp` → conditional jump (inverted condition) to a label after the block → body of the `if` → label.

### `if` / `else`

```c
if (a > 0) {
    result = 1;
} else {
    result = -1;
}
```

```asm
cmp     eax, 0  
jle     .else_block        ; if a <= 0, go to else  
mov     dword [rbp-0x4], 1 ; result = 1 (then block)  
jmp     .end_if            ; jump over the else  
.else_block:
mov     dword [rbp-0x4], 0xffffffff  ; result = -1 (else block)
.end_if:
```

The unconditional `jmp` between the `then` block and the `else` block is the characteristic signature of the `if`/`else`. Without it, execution would "fall through" into the `else` after executing the `then`.

The complete pattern is: `cmp` → conditional jump to `.else` → then block → `jmp` to `.end` → else block → `.end`.

### `if` / `else if` / `else` (condition chain)

```c
if (x == 1) {
    a();
} else if (x == 2) {
    b();
} else {
    c();
}
```

```asm
cmp     eax, 1  
jne     .elif_2  
call    a  
jmp     .end  
.elif_2:
cmp     eax, 2  
jne     .else_block  
call    b  
jmp     .end  
.else_block:
call    c
.end:
```

Each condition is a `cmp` + jump-to-next-condition pair, with an unconditional `jmp` at the end of each block to reach the exit. It is a linear cascade recognizable in the control flow graph.

### `while` loop

```c
while (i < 10) {
    process(i);
    i++;
}
```

GCC at `-O0` typically generates a structure with the test at the top:

```asm
.loop_test:
    cmp     dword [rbp-0x4], 9     ; compare i with 9
    jg      .loop_end               ; if i > 9, exit loop
    ; loop body
    mov     edi, dword [rbp-0x4]
    call    process
    add     dword [rbp-0x4], 1      ; i++
    jmp     .loop_test              ; return to test
.loop_end:
```

In optimized mode (`-O1` and above), GCC often prefers placing the test **at the end** of the loop, with an initial jump to the test:

```asm
    jmp     .loop_test              ; jump directly to the test
.loop_body:
    ; loop body
    mov     edi, eax
    call    process
    add     ebx, 1                  ; i++
.loop_test:
    cmp     ebx, 9
    jle     .loop_body              ; if i <= 9, return to body
```

This second form is more performant because the backward jump (`jle .loop_body`) is the loop's "normal" jump — and modern processors predict backward jumps as *taken* by default, which corresponds to the most frequent case (loops generally iterate several times).

> 💡 **For RE**: the signature of a loop in assembly is a **backward jump** (to an address lower than the current address). When you spot a `jXX` whose target is *before* the current instruction, you are at the end of a loop. The `cmp` or `test` that precedes that jump is the continuation condition.

### `for` loop

```c
for (int i = 0; i < n; i++) {
    arr[i] = 0;
}
```

```asm
    ; initialization: i = 0
    mov     dword [rbp-0x4], 0
    jmp     .for_test
.for_body:
    ; body: arr[i] = 0
    mov     eax, dword [rbp-0x4]       ; eax = i
    cdqe                                 ; signed extension → rax
    mov     dword [rbp-0x30+rax*4], 0   ; arr[i] = 0
    ; increment: i++
    add     dword [rbp-0x4], 1
.for_test:
    ; test: i < n
    mov     eax, dword [rbp-0x4]
    cmp     eax, dword [rbp-0x8]        ; compare i with n
    jl      .for_body                    ; if i < n, return to body
```

The `for` loop is distinguished from the `while` loop by the presence of an **increment** block clearly separated just before the test. In practice, the two produce very similar structures in assembly.

### `do…while` loop

```c
do {
    process(i);
    i++;
} while (i < 10);
```

```asm
.loop_body:
    mov     edi, dword [rbp-0x4]
    call    process
    add     dword [rbp-0x4], 1
    cmp     dword [rbp-0x4], 9
    jle     .loop_body              ; return to start if i <= 9
```

It is the most compact form: no initial jump, the test is at the end, a single conditional jump. This is also why optimized GCC often transforms `while` and `for` loops into `do…while` preceded by a guard test — it eliminates one unconditional `jmp` per loop.

### Visual summary of loop patterns

```
while (test at top, -O0)      while (test at bottom, -O1+)    do...while
──────────────────────────     ──────────────────────────     ──────────────────

  ┌──────────────┐               jmp ─────┐                    ┌──────────────┐
  │              ▼                        ▼                    │              ▼
  │          ┌──────┐              ┌──────────────┐            │         ┌─────────┐
  │          │ TEST │              │    BODY      │            │         │  BODY   │
  │          └──┬───┘              └──────┬───────┘            │         └────┬────┘
  │        true │  false                  │                    │              │
  │        ┌────┘└────┐            ┌──────▼───────┐            │         ┌────▼────┐
  │        ▼          ▼            │    TEST      │            │         │  TEST   │
  │   ┌─────────┐  exit            └──┬───────┬───┘            │         └──┬───┬──┘
  │   │  BODY   │                 true│       │false           │       true │   │ false
  │   └────┬────┘                     │       ▼                └────────────┘   ▼
  └────────┘                     ┌────┘     exit                             exit
                                 │
                                 └──► (back to BODY)
```

---

## `switch` and jump tables

`switch` statements produce two distinct patterns depending on the number of `case` labels and the density of their values.

### Few `case` labels: `cmp`/`je` cascade

For a `switch` with few cases (typically fewer than 5–6), GCC generates a chain of comparisons, identical to a series of `if`/`else if`:

```c
switch (cmd) {
    case 1: handle_start(); break;
    case 2: handle_stop();  break;
    case 3: handle_reset(); break;
    default: handle_error();
}
```

```asm
cmp     eax, 1  
je      .case_1  
cmp     eax, 2  
je      .case_2  
cmp     eax, 3  
je      .case_3  
jmp     .default            ; no case → default  

.case_1:
    call    handle_start
    jmp     .end_switch
.case_2:
    call    handle_stop
    jmp     .end_switch
.case_3:
    call    handle_reset
    jmp     .end_switch
.default:
    call    handle_error
.end_switch:
```

Each `break` translates to a `jmp .end_switch`. The absence of `break` (fallthrough) would translate to the absence of this `jmp` — the code would "fall" into the next case.

### Many dense `case` labels: the jump table

When the values are numerous enough and close to each other, GCC generates a **jump table** — an array of addresses indexed by the `switch` value. It is significantly more performant than a cascade of comparisons, because the access is O(1).

```c
switch (opcode) {
    case 0: op_nop();    break;
    case 1: op_load();   break;
    case 2: op_store();  break;
    case 3: op_add();    break;
    case 4: op_sub();    break;
    case 5: op_mul();    break;
    case 6: op_div();    break;
    case 7: op_halt();   break;
    default: op_invalid();
}
```

```asm
    ; bound check (opcode <= 7)
    cmp     edi, 7
    ja      .default                  ; if opcode > 7 (unsigned), → default

    ; jump via the table
    lea     rdx, [rip+.jump_table]    ; rdx = address of the table
    movsxd  rax, dword [rdx+rdi*4]   ; reads 32-bit relative offset
    add     rax, rdx                  ; computes absolute address
    jmp     rax                       ; jumps to the matching case

; ... code of case_0 through case_7 ...

.default:
    call    op_invalid

; Table in .rodata (data, not code)
.jump_table:
    .long   .case_0 - .jump_table
    .long   .case_1 - .jump_table
    .long   .case_2 - .jump_table
    ; ... etc.
```

Characteristics of a jump table in disassembly:

1. An initial **`cmp` + `ja`** that checks the value is in bounds (the `ja` is unsigned, so a negative value is also rejected as it is interpreted as a very large unsigned number).  
2. An **indirect `jmp`** via an address computation involving an index register and a scale factor (`*4` or `*8`).  
3. A **data block** in `.rodata` containing the offsets or addresses of each case.

> 💡 **For RE**: Ghidra and IDA generally recognize jump tables automatically and display the `switch` cases in a structured way. But in `objdump` or manual analysis, you must spot the indirect `jmp` and read the table in `.rodata` to identify the targets. Section 3.8 revisits the RIP-relative addressing used in this context.

### Sparse values: binary search or indexed table

When `switch` values are numerous but sparse (for example `case 10`, `case 200`, `case 5000`), GCC may generate a **binary-tree search** — a cascade of `cmp` organized to bisect the value space, with logarithmic depth. You recognize this pattern by the "diamond" structure of the control-flow graph, where each node compares with a median value and branches left or right.

---

## Conditional jumps without `cmp`: exploiting the flags of a preceding operation

GCC does not always insert a `cmp` or `test` before a conditional jump. If the **preceding** instruction has already set the flags usefully, the compiler chains the jump directly:

```asm
sub     eax, 1              ; eax-- (updates ZF if the result is 0)  
jz      .reached_zero        ; if sub's result is 0, jumps  

add     ecx, edx             ; ecx += edx (updates SF)  
js      .negative            ; if the result is negative, jumps  

and     eax, 0x3             ; eax &= 3 (updates ZF)  
jnz     .not_aligned         ; if eax & 3 != 0, not aligned on 4  
```

This pattern is more common in optimized code (`-O1` and above) because the compiler fuses the test with the operation. At `-O0`, GCC is more conservative and often inserts an explicit `cmp` or `test` even after a `sub` or `add`.

> 💡 **For RE**: if you see a conditional jump without a `cmp`/`test` immediately before, look at the preceding instruction — it is what set the flags. The `sub eax, 1` / `jz` sequence is a compact form of `eax--; if (eax == 0)`.

---

## The `setXX` instruction — storing a condition in a byte

The `setXX` instructions are cousins of `jXX`: instead of jumping, they **store** the result of the condition (0 or 1) into an 8-bit register:

```asm
cmp     eax, ebx  
setl    al              ; al = 1 if eax < ebx (signed), 0 otherwise  
movzx   eax, al         ; extends to 32 bits (eax = 0 or 1)  
```

Each `jXX` has its corresponding `setXX`: `setz`, `setnz`, `setl`, `setg`, `setb`, `seta`, etc.

GCC uses `setXX` to translate boolean expressions that are **stored** into a variable rather than used in an `if`:

```c
int is_positive = (x > 0);    // →  test edi, edi / setg al / movzx eax, al  
int are_equal = (a == b);     // →  cmp edi, esi / sete al / movzx eax, al  
return x < y;                 // →  cmp edi, esi / setl al / movzx eax, al  
```

> 💡 **For RE**: when you see a `setXX` followed by a `movzx`, it is the storage of a boolean condition into an `int`. Translate it directly into `variable = (condition)`.

---

## Recognizing the logical operators `&&` and `||`

C's short-circuit logical operators produce characteristic patterns in assembly.

### `&&` (logical AND with short-circuit)

```c
if (a > 0 && b > 0) {
    action();
}
```

```asm
cmp     eax, 0  
jle     .skip           ; if a <= 0, short-circuit → jump (no need to test b)  
cmp     ecx, 0  
jle     .skip           ; if b <= 0, jump  
call    action  
.skip:
```

Each condition is a `cmp` + jump to the same target (the exit). As soon as one condition is false, you short-circuit. Both jumps go to the **same label** — that is the signature of `&&`.

### `||` (logical OR with short-circuit)

```c
if (a > 0 || b > 0) {
    action();
}
```

```asm
cmp     eax, 0  
jg      .do_action      ; if a > 0, short-circuit → condition true  
cmp     ecx, 0  
jle     .skip           ; if b <= 0 (and a <= 0), no condition true  
.do_action:
call    action
.skip:
```

Here, the first true condition suffices — the first jump goes directly to the **body** of the `if`. The second condition is the last resort, with the usual inverted logic.

> 💡 **For RE**: two consecutive conditional jumps to **the same label** → `&&`. A conditional jump to the **body** followed by a conditional jump to the **exit** → `||`. This pattern is reliable and frequent.

---

## The ternary operator and `cmovXX`

The simple case of the ternary operator `? :` has already been seen in section 3.2 with `cmovXX`. But when the expression is more complex (function calls in the branches, side effects), GCC falls back to classic jumps:

```c
// Simple case → cmov (no jump)
int min = (a < b) ? a : b;

// Complex case → classic jumps
char *msg = valid ? compute_msg() : get_default();
```

```asm
; Complex case: the functions must be called conditionally
test    edi, edi  
jz      .use_default  
call    compute_msg  
jmp     .done  
.use_default:
call    get_default
.done:
; rax holds the result
```

---

## Control flow and graphs in disassemblers

Modern RE tools display control flow as a **graph** where each basic block of linear instructions is a node, and each jump is an edge. This representation makes control structures immediately visual:

- An **`if`/`else`** forms a diamond: a node that forks into two paths that reconverge.  
- A **loop** forms a cycle: an edge that goes back up to a previous node.  
- A **`switch`** with jump table forms a star: a central node with multiple outgoing edges toward the cases.  
- A **`break`** is an edge that leaves the loop's cycle.  
- A **`continue`** is an edge that goes directly back up to the loop's test.

```
    if / else                   while loop                  switch (cascade)
  ─────────────               ──────────────              ──────────────────

      ┌─────┐                    ┌─────┐                  ┌──────┐
      │ TEST│                    │ TEST│◄──┐              │ cmp 1│
      └──┬──┘                    └──┬──┘   │              └──┬───┘
     true│ false              true│ false  │              == │  !=
     ┌───┘└───┐               ┌───┘└───┐   │            ┌───┘└───┐
     ▼        ▼               ▼        ▼   │            ▼   ┌──────┐
  ┌──────┐┌──────┐        ┌──────┐  exit   │         ┌────┐ │ cmp 2│
  │ THEN ││ ELSE │        │ BODY │         │         │ c1 │ └──┬───┘
  └──┬───┘└──┬───┘        └──┬───┘         │         └──┬─┘ == │  !=
     └───┬───┘               └─────────────┘            │   ┌──┘└───┐
         ▼                                              │   ▼    ┌──────┐
       rest                                             │ ┌────┐ │ cmp 3│
                                                        │ │ c2 │ └──┬───┘
                                                        │ └──┬─┘ == │  !=
                                                        │    │   ┌──┘└───┐
                                                        │    │   ▼       ▼
                                                        │    │ ┌────┐ ┌─────┐
                                                        │    │ │ c3 │ │ def │
                                                        │    │ └──┬─┘ └──┬──┘
                                                        └────┴────┴──────┘
                                                                 ▼
                                                                rest
```

In Ghidra, this view is the **Function Graph** (`Window → Function Graph`). In IDA, it is the **Graph** view (`Space`). In Cutter/Radare2, it is the `VV` command. These graphical views are often more readable than a linear listing for reconstructing control flow — they make the patterns described in this section immediately identifiable at a glance.

---

## What to remember going forward

1. **`jmp`** is the only unconditional jump — it translates `goto`s, `break`s, `else` clauses, and loop-start returns.  
2. **Conditional jumps read with an inverted condition**: GCC uses `jne` to implement `if (a == b)` because the jump *skips* the `then` block.  
3. **Signed vs unsigned** is revealed by the mnemonic chosen: `jl`/`jg` = signed, `jb`/`ja` = unsigned.  
4. **A backward jump** (to a lower address) almost always signals a **loop**.  
5. **Two jumps to the same label** = `&&`, **one jump to the body + one to the exit** = `||`.  
6. **`setXX`** stores a boolean condition into a register instead of jumping — it is the translation of `variable = (condition)`.  
7. **Jump tables** (indirect `jmp` + table in `.rodata`) are the optimized implementation of `switch` statements with many dense cases.  
8. The **graphical views** of disassemblers (Ghidra Function Graph, IDA Graph view) make these patterns visually obvious.

---


⏭️ [The stack: prologue, epilogue and System V AMD64 calling conventions](/03-x86-64-assembly/05-stack-prologue-epilogue.md)
