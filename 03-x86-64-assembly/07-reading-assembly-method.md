🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 3.7 — Reading an assembly listing without panicking: a practical 5-step method

> 🎯 **Goal of this section**: provide a structured, reproducible method to tackle any assembly listing, even an unknown one without symbols. Sections 3.1 through 3.6 presented the individual building blocks — this section assembles them into a concrete workflow you can apply today.

---

## The problem

You open a binary in a disassembler. You see hundreds of lines of `mov`, `lea`, `cmp`, `jne`, `call`… The natural reflex is to try to read the code instruction by instruction, top to bottom, like C. It does not work: you drown in details, you lose the thread, you panic.

Assembly does not read like source code. It reads **in successive layers**, from the most general to the most precise — exactly as you analyze a text in a foreign language you only partially master: first the overall structure, then the meaning of each paragraph, then the individual words.

The 5-step method that follows formalizes this approach. It applies to a **single function** — in RE, you almost always work function by function.

---

## Method overview

```
Step 1 — Delimit          Find the start and end of the function
       ↓
Step 2 — Structure        Identify the blocks and the control flow
       ↓
Step 3 — Characterize     Read the calls and the notable constants
       ↓
Step 4 — Annotate         Name variables, arguments, blocks
       ↓
Step 5 — Rewrite          Rewrite as C pseudo-code
```

Each step produces a concrete result that feeds the next one. You **never** try to understand everything at once — you refine progressively.

---

## Step 1 — Delimit the function

Before reading anything, you need to know **where the function starts** and **where it ends**.

### Finding the start

If the binary has symbols, the disassembler displays the function's name and starting address. Otherwise, look for a **prologue**:

- `push rbp` / `mov rbp, rsp` — classic prologue with frame pointer.  
- `sub rsp, N` — prologue without frame pointer.  
- `push rbx` / `push r12` / … — callee-saved saves right at the start.  
- An address referenced by a `call` from another function.

In Ghidra or IDA, detection is automatic. In `objdump`, look for `<function_name>:` labels or, if the binary is stripped, for the target addresses of `call`s.

### Finding the end

Look for all exit points of the function:

- `ret` — the most common case (there may be several in the same function).  
- `jmp` to another function (tail call, cf. Chapter 16).  
- `call __stack_chk_fail` — exit via stack-corruption detection (never returns).

> 💡 **Tip**: in `objdump`, the next function generally starts right after the last `ret` (or after a few `nop` paddings). In Ghidra/IDA, function boundaries are visually marked.

### What you know after step 1

- The start and end addresses of the function.  
- Its approximate size in bytes (a complexity indicator).  
- Whether it has a frame pointer or not (presence of `push rbp` / `mov rbp, rsp`).  
- How many callee-saved registers it uses (number of `push`es in the prologue).  
- Whether it has a stack canary (presence of `mov rax, [fs:0x28]`).  
- The size of the reserved local space (value of `sub rsp, N`).

---

## Step 2 — Structure: identify the blocks and the control flow

The goal is to turn the linear listing into a **map** of logical blocks and their connections — without yet understanding the detail of each instruction.

### Spotting basic blocks

A *basic block* is a sequence of linear instructions with no internal jump and no jump target inside. It begins at a jump target (or at the start of the function) and ends at a jump or a `ret`. Concretely:

- Each **jump target** (`jXX target` → `target` is the start of a new block).  
- Each **jump instruction** (`jXX`, `jmp`) is the end of a block.  
- Each **`call`** does NOT cut a block (execution is considered to continue after the `call`, except for special cases like `exit` or `abort`).

### Drawing the arrows

For each jump, draw an arrow to its target:

- **Arrow pointing down** (jump to a higher address) → `if`/`else` branching, `break`, `continue`.  
- **Arrow pointing up** (jump to a lower address) → **loop** (this is the most reliable signal).  
- **`jmp` to another function** → tail call.

### Recognizing high-level structures

With the arrows drawn, the patterns from section 3.4 become visual:

| Arrow pattern | Probable C structure |  
|---|---|  
| `cmp` → down jump (skip) → block → convergence | `if` |  
| `cmp` → down jump → block → `jmp` down → block → convergence | `if` / `else` |  
| `cmp` → up jump (return) | Loop (`while`, `for`, `do…while`) |  
| Cascade of `cmp`/`je` to distinct blocks, each followed by a `jmp` to the same exit | `switch` (cascade) |  
| `cmp` + `ja` (bound) → indirect `jmp` | `switch` (jump table) |

### Use the disassembler's graph view

If you use Ghidra, IDA, or Cutter, **switch to graph view** — step 2 is done automatically:

- Ghidra: `Window → Function Graph`  
- IDA: press `Space` to toggle between listing and graph  
- Cutter: graph view by default

Each node is a basic block, each edge is a jump. Green arrows generally indicate the "condition true" branch and red arrows the "condition false" branch.

Even if you work in `objdump` (raw listing), **drawing the graph by hand** on paper is an investment that speeds up all the following steps.

### What you know after step 2

- The number of logical blocks (= structural complexity).  
- The loops and their location.  
- The conditional branches and the `if`/`else`/`switch` structure.  
- The exit points of the function.  
- A "skeleton" of the logic without knowing the details.

---

## Step 3 — Characterize: calls, constants, and notable operations

Now that you have the map, look for the **landmarks** — the elements that give meaning to the blocks without needing to read every instruction.

### List every `call`

Each `call` is a major clue. For each call, note:

- **The target**: known libc function (`strcmp`, `malloc`, `printf`, `open`…), named internal function, or indirect call (function pointer / vtable).  
- **The arguments**: walk back through the writes into `rdi`, `rsi`, `rdx`… just before the `call` (method from section 3.6).  
- **Use of the return value**: what does the code do with `rax`/`eax` after the `call`?

A single `call strcmp` followed by a `test eax, eax` / `jne` tells you the block is a **string check**. A `call malloc` followed by a `test rax, rax` / `je` tells you the block is an **allocation with error check**. This contextual information is often enough to understand the role of each block without reading the details.

### Spotting notable constants

Some immediate values are signatures:

| Constant | Probable meaning |  
|---|---|  
| `0x0` / `0x1` | Booleans, flags, NULL |  
| `0xa` (10), `0x64` (100) | Numeric bases, sizes |  
| `0x20` (32), `0x7e` (126) | Printable-ASCII bounds |  
| `0x41` ('A'), `0x61` ('a'), `0x30` ('0') | Character manipulation |  
| `0xff`, `0xffff`, `0xffffffff` | Masks, -1 in unsigned |  
| `0x400`, `0x1000` | Page sizes (1024, 4096) |  
| `0x5f3759df` | Fast inverse square root (famous constant) |  
| `0x67452301`, `0xefcdab89`… | MD5 initialization constants |  
| `0x6a09e667`… | SHA-256 initialization constants |  
| `0x63727970`, `0x746f0000` | ASCII encoded as integer ("cryp", "to") |

> 💡 **Tip**: in Ghidra, click on a constant and see whether the decompiler interprets it as an ASCII character. In `objdump`, mentally convert hexadecimal constants to ASCII or decimal — it often reveals their meaning.

### Identifying referenced strings

`lea rdi, [rip+offset]` instructions that load `.rodata` addresses point to literal strings. In Ghidra/IDA, these strings are displayed as comments. In `objdump`, you have to fetch them with `strings` or `readelf`:

```asm
lea     rdi, [rip+0x1a2b]    ; in Ghidra: "Invalid password"
```

A single string like `"Invalid password"` or `"License expired"` instantly identifies the role of an entire block.

### Spotting structural operations

Without reading the detail, certain operations reveal the nature of the code:

- **`xor` in a loop** on a buffer → XOR encryption/decryption.  
- **Series of `shl`/`shr`/`and`/`or`** → bit manipulation, field parsing.  
- **`imul` with magic constant** → division by a constant (cf. section 3.3).  
- **Repeated `[reg+offset]` accesses with the same base register** → structure field accesses.  
- **`[reg+index*4]` or `[reg+index*8]`** → array traversal.

### What you know after step 3

- The **probable role** of each block (verification, allocation, computation, I/O, crypto…).  
- The **data handled** (strings, files, buffers, structures).  
- The **external dependencies** (libc functions, syscalls).  
- A **global hypothesis** about what the function does.

---

## Step 4 — Annotate: name variables, arguments, and blocks

This is the step where the raw disassembly is turned into something readable. Annotation is the fundamental work of the reverse engineer — it is what distinguishes an unreadable listing from a workable analysis.

### Naming the function arguments

Based on the analysis of call sites (XREF) and the start of the function, identify the input registers and give them names:

```
rdi → input_str    (pointer to a string, deduced from a later call strcmp)  
esi → key_length   (integer, used as a loop bound)  
```

### Naming local variables

For each recurring stack offset (`[rbp-0x4]`, `[rbp-0x8]`, `[rsp+0x1c]`…), give a name based on the observed usage:

```
[rbp-0x04] → counter     (incremented in a loop, compared with key_length)
[rbp-0x08] → result      (set to 0 or 1, returned in eax at the end of the function)
[rbp-0x10] → temp_ptr    (pointer, passed as argument to strcmp)
```

### Naming blocks

Each basic block identified in step 2 deserves a descriptive name:

```
Block 0x401120–0x40113a → prologue + init  
Block 0x40113a–0x401158 → loop_body (main loop)  
Block 0x401158–0x401168 → loop_test (continuation condition)  
Block 0x401168–0x401178 → success_path (returns 1)  
Block 0x401178–0x401188 → failure_path (returns 0)  
```

### Adding comments to key instructions

No need to comment every line — focus on:

- The **`cmp`s**: which condition is tested and why.  
- The **`call`s**: what the call does, with which arguments.  
- The **decision points**: why the code takes one path or the other.  
- The **non-trivial computations**: arithmetic `lea`s, magic division constants, bit manipulations.

In Ghidra/IDA, use the renaming functions (`L` key for labels, `N` for functions in Ghidra; `N` in IDA) and comments (`/` or `;`). In a text listing, annotate directly in a separate file or use inline comments.

### What you know after step 4

- Every variable has a meaningful name.  
- Every block has an identified role.  
- The obscure parts are reduced to the most complex individual instructions.  
- The listing is annotated enough to be re-read days later without starting over.

---

## Step 5 — Rewrite as C pseudo-code

The final step consists of **rewriting the logic** into readable C pseudo-code. It is not automatic decompilation — it is your understanding, validated by the annotated listing, translated into a human language.

### Reconstruction method

Start from the structure identified in step 2 and fill it with the details from steps 3 and 4:

```c
// Reconstructed pseudo-code
int check_key(const char *input, int expected_length) {
    // Check the length
    if (strlen(input) != expected_length)
        return 0;

    // Walk through each character
    int sum = 0;
    for (int i = 0; i < expected_length; i++) {
        sum += input[i] ^ 0x42;   // XOR with fixed key
    }

    // Compare the checksum
    if (sum == 0x1337)
        return 1;
    
    return 0;
}
```

### Pseudo-code writing rules

- **Do not aim for syntactic perfection.** The goal is understanding, not recompilation. `if (thing)` is enough even if the exact code is `if (*(int*)(buf + off) == 0x42)`.  
- **Keep meaningful constants** (`0x42`, `0x1337`) — they matter for RE.  
- **Flag uncertainties.** If you are not sure of a type or operation, mark it: `/* exact type unknown, probably unsigned */`.  
- **Go back and forth** with the listing. Pseudo-code often reveals inconsistencies that send you back for a targeted re-reading of the disassembly.

### Validating the pseudo-code

Three verification means:

1. **Internal consistency**: does the pseudo-code make sense? Are the types consistent? Do the loops terminate?  
2. **Dynamic testing**: if you have access to the binary, use GDB to execute the function with known inputs and verify that the behavior matches your pseudo-code (cf. Chapters 11–12).  
3. **Comparison with the decompiler**: compare your pseudo-code with the Ghidra Decompiler output. Divergences point to errors in one or the other — both are useful.

---

## The method applied: complete example

Here is a raw assembly listing (Intel syntax, 20 lines). Let's apply the 5 steps.

```asm
0x401120:  push    rbp
0x401121:  mov     rbp, rsp
0x401124:  mov     dword [rbp-0x14], edi
0x401127:  mov     qword [rbp-0x20], rsi
0x40112b:  mov     dword [rbp-0x4], 0x0
0x401132:  mov     dword [rbp-0x8], 0x0
0x401139:  jmp     0x401156
0x40113b:  mov     eax, dword [rbp-0x8]
0x40113e:  movsxd  rdx, eax
0x401141:  mov     rax, qword [rbp-0x20]
0x401145:  add     rax, rdx
0x401148:  movzx   eax, byte [rax]
0x40114b:  movsx   eax, al
0x40114e:  add     dword [rbp-0x4], eax
0x401151:  add     dword [rbp-0x8], 0x1
0x401155:  nop
0x401156:  mov     eax, dword [rbp-0x8]
0x401159:  cmp     eax, dword [rbp-0x14]
0x40115c:  jl      0x40113b
0x40115e:  mov     eax, dword [rbp-0x4]
0x401161:  pop     rbp
0x401162:  ret
```

### Step 1 — Delimit

- **Start**: `0x401120` — prologue `push rbp` / `mov rbp, rsp`.  
- **End**: `0x401162` — `ret`.  
- Frame pointer: **yes** (`push rbp` / `mov rbp, rsp`).  
- No additional callee-saved (a single `push`).  
- No `sub rsp` → small local space (red zone sufficient or compiler confident).  
- No stack canary.  
- Size: 67 bytes → short function.

Spilled arguments:

```
[rbp-0x14] ← edi   → 1st argument, 32-bit (int)
[rbp-0x20] ← rsi   → 2nd argument, 64-bit (pointer)
```

The function takes 2 parameters: an `int` and a pointer.

### Step 2 — Structure

Let's identify the jumps:

- `0x401139: jmp 0x401156` → downward jump (skip, goes to the test).  
- `0x40115c: jl 0x40113b` → **upward** jump → **loop**.

Blocks:

```
Block A [0x401120–0x401139]: prologue + initialization + jmp to test  
Block B [0x40113b–0x401155]: loop body  
Block C [0x401156–0x40115c]: loop test (cmp + jl back to body)  
Block D [0x40115e–0x401162]: return the value  
```

Structure: `init → jmp test → [body → test → if true back to body] → return`. This is a **`for`/`while` loop with the test at the bottom** (classic GCC pattern).

### Step 3 — Characterize

- **No `call`** → standalone function, no external calls.  
- **Constant `0x0`**: initialization of two local variables to 0.  
- **`movzx` + `movsx`** on a byte (`byte [rax]`) → reading a signed `char`.  
- **`add dword [rbp-0x4], eax`** → accumulation (sum).  
- **`add dword [rbp-0x8], 0x1`** → increment → loop counter.  
- **`cmp eax, dword [rbp-0x14]`** → compares the counter with the 1st argument (the bound).  
- **`jl`** → signed comparison, loop while `counter < bound`.  
- **Return in `eax`** → returns `[rbp-0x4]`, the accumulated sum.

Hypothesis: the function **sums the values of the characters** of a string (or a buffer) over a given length.

### Step 4 — Annotate

```
[rbp-0x14]: edi  → len       (loop bound, int)
[rbp-0x20]: rsi  → str       (pointer to the buffer, char*)
[rbp-0x04]:      → sum       (accumulator, initialized to 0)
[rbp-0x08]:      → i         (loop counter, initialized to 0)

Block A: prologue, argument spill, init sum=0, i=0  
Block B: loop body — reads str[i], adds to sum, increments i  
Block C: test — if i < len, return to block B  
Block D: returns sum  
```

### Step 5 — Rewrite

```c
int sum_chars(const char *str, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += (int)str[i];    // movsx → signed char promoted to int
    }
    return sum;
}
```

Twenty lines of assembly → five lines of C. The method took a few minutes. Without a method, the same twenty lines could take much longer and yield a less reliable result.

---

## When to speed up, when to slow down

The 5-step method is complete and rigorous, but in practice you will adapt its intensity to the context:

### Speed up (quick pass)

- **Trivial functions** (< 10 instructions): steps 1 and 5 are often enough.  
- **libc functions / obvious wrappers**: a single `call` to a known function with direct argument passing → the pseudo-code reads itself.  
- **When you have a decompiler**: Ghidra Decompiler does steps 2 through 5 automatically. Quickly validate its output rather than redoing everything by hand.

### Slow down (deep analysis)

- **Nested loops**: carefully draw the control-flow graph, each backward jump is a loop.  
- **Long functions (> 100 instructions)**: split them into logical sub-functions (the blocks between two major `call`s).  
- **Optimized code (`-O2`/`-O3`)**: compiler idioms (magic constants, `cmov`, arithmetic `lea`) require slower decoding at step 3.  
- **Obfuscated code**: each step takes longer, and you need to add a "mental deobfuscation" step (cf. Chapter 19).  
- **Crypto / bit manipulation**: series of `xor`, `shl`, `ror`, `and` operations often require instruction-by-instruction analysis with concrete values on paper.

---

## Common mistakes to avoid

### Reading top to bottom without structuring first

This is the most frequent beginner mistake. Without step 2 (structure), you get lost in the jumps. **Always** identify the control structure before reading the detail of the blocks.

### Confusing application logic and ABI plumbing

The prologue, epilogue, argument spills, the canary, alignment padding — all of that is calling-convention "plumbing". Learn to recognize them so you can **ignore** them quickly and focus on the code that matters.

### Neglecting types

Register sizes (`eax` vs `rax`), the choice of `movsx` vs `movzx`, the choice of `jl` vs `jb` — each detail gives you typing information. Ignoring these clues leads to incorrect pseudo-code.

### Wanting to understand everything in one pass

Some instructions will resist the first pass. Note them, move on, and come back once the global context is understood. Understanding is iterative — accept temporary uncertainty.

### Forgetting to verify dynamically

Elegant pseudo-code can be completely wrong. As soon as possible, validate your understanding with GDB: set a breakpoint, execute with known inputs, check that registers and memory match your predictions (cf. Chapters 11–12).

---

## Method cheat sheet

```
┌─────────────────────────────────────────────────────────────────┐
│                   5-STEP READING METHOD                         │
├──────────────┬──────────────────────────────────────────────────┤
│ 1. DELIMIT   │ Start (prologue), end (ret), size, arguments     │
│              │ → Result: perimeter of the function              │
├──────────────┼──────────────────────────────────────────────────┤
│ 2. STRUCTURE │ Blocks, jumps, loops (upward arrows),            │
│              │ if/else, switch                                  │
│              │ → Result: control flow graph                     │
├──────────────┼──────────────────────────────────────────────────┤
│ 3. CHARACTER-│ call (+ arguments + return), constants,          │
│    IZE       │ strings, notable operations                      │
│              │ → Result: role of each block                     │
├──────────────┼──────────────────────────────────────────────────┤
│ 4. ANNOTATE  │ Name arguments, local variables, blocks,         │
│              │ comment the key instructions                     │
│              │ → Result: readable, durable listing              │
├──────────────┼──────────────────────────────────────────────────┤
│ 5. REWRITE   │ Rewrite as C pseudo-code, check                  │
│              │ consistency, compare with the decompiler         │
│              │ → Result: validated understanding                │
└──────────────┴──────────────────────────────────────────────────┘
```

---

## What to remember going forward

1. **Never read a listing instruction by instruction, top to bottom** — always structure first (step 2).  
2. **`call`s and strings are the best landmarks** — they give you context effortlessly (step 3).  
3. **Annotation is the most profitable investment** — an annotated listing is re-read in minutes, a raw listing needs to be redone from scratch (step 4).  
4. **C pseudo-code is the final deliverable** — that is what you share, document, and verify (step 5).  
5. **The method improves with practice** — patterns are recognized faster and faster, steps merge together, and what took an hour ends up taking a few minutes.

---


⏭️ [Difference between library call (`call printf@plt`) and direct syscall (`syscall`)](/03-x86-64-assembly/08-call-plt-vs-syscall.md)
