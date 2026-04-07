🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 7 — Checkpoint Solution

## Disassemble `keygenme_O0` and `keygenme_O2`, list the key differences

> **Spoilers** — This file contains the complete solution for the chapter 7 checkpoint.  
> Exact addresses may vary depending on your GCC version, distribution and linking options. What matters are the **fundamental observations**, not the precise numerical values.

---

## 1. Initial Triage

### File Sizes

```bash
$ ls -l keygenme_O0 keygenme_O2
-rwxr-xr-x 1 user user  20536  keygenme_O0
-rwxr-xr-x 1 user user  16432  keygenme_O2
```

The `-O0` binary is about 25% larger. The difference mainly comes from the larger `.text` section and debug sections if `-g` is included.

### `.text` Section Size

```bash
$ readelf -S keygenme_O0 | grep '\.text'
  [16] .text             PROGBITS   0000000000001060  00001060
       00000000000001c5  0000000000000000  AX       0     0     16

$ readelf -S keygenme_O2 | grep '\.text'
  [16] .text             PROGBITS   0000000000001060  00001060
       0000000000000142  0000000000000000  AX       0     0     16
```

The `.text` section goes from about **0x1c5 (453) bytes** at `-O0` to about **0x142 (322) bytes** at `-O2`, roughly a 30% reduction. Optimized code is more compact.

### Symbol Presence

```bash
$ file keygenme_O0
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, [...], with debug_info, not stripped

$ file keygenme_O2
keygenme_O2: ELF 64-bit LSB pie executable, x86-64, [...], not stripped
```

Both binaries retain their symbols (not stripped). The `-O0` binary additionally contains DWARF debug information (`with debug_info`), which is expected if the `Makefile` uses `-g` with `-O0`.

### Approximate Number of User Functions

```bash
$ nm keygenme_O0 | grep ' T ' | grep -v '_'
0000000000001139 T compute_hash
0000000000001189 T check_serial
00000000000011e2 T main

$ nm keygenme_O2 | grep ' T ' | grep -v '_'
0000000000001060 T compute_hash
0000000000001090 T check_serial
00000000000010e0 T main
```

Both binaries contain the **same 3 user functions**: `compute_hash`, `check_serial`, and `main`. No function was inlined at `-O2` in this case (all three are still present as distinct symbols). This can be explained by the functions being large enough or called from multiple locations, which discourages inlining even at `-O2`.

> **Note**: depending on your GCC version and actual function sizes, `compute_hash` could be inlined into `check_serial` at `-O2`. If that's your case, you'll only see 2 user functions — this is a valid observation to document.

---

## 2. Locating `main()`

### Via Symbols (direct method)

Since neither binary is stripped, locating is immediate:

```bash
$ objdump -d -M intel keygenme_O0 | grep '<main>:'
00000000000011e2 <main>:

$ objdump -d -M intel keygenme_O2 | grep '<main>:'
00000000000010e0 <main>:
```

### Via `_start` (practicing the stripped method)

For practice, let's verify via the entry point:

```bash
$ readelf -h keygenme_O0 | grep "Entry point"
  Entry point address:               0x1060
```

Disassembling `_start`:

```bash
$ objdump -d -M intel --start-address=0x1060 --stop-address=0x1090 keygenme_O0
```

We find `lea rdi, [rip+0x163]` at address `0x1078` (7 bytes). Next instruction at `0x107f`. Address of `main` = `0x107f + 0x163` = **`0x11e2`** — consistent with the symbol.

---

## 3. Prologue and Epilogue Comparison

### `compute_hash`

**At `-O0`:**

```asm
0000000000001139 <compute_hash>:
    1139:       f3 0f 1e fa             endbr64
    113d:       55                      push   rbp
    113e:       48 89 e5                mov    rbp, rsp
    1141:       48 89 7d e8             mov    QWORD PTR [rbp-0x18], rdi
    1145:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4], 0x0
    114c:       c7 45 f8 00 00 00 00    mov    DWORD PTR [rbp-0x8], 0x0
    ...
    1186:       c9                      leave
    1187:       c3                      ret
```

- Full prologue: `endbr64` + `push rbp` + `mov rbp, rsp`.  
- No explicit `sub rsp` (GCC judges that space below `rbp` suffices without adjustment, local variables fit in the *red zone* or space is implicitly reserved).  
- The `rdi` parameter is immediately saved to the stack at `[rbp-0x18]`.  
- Two local variables initialized to 0: `[rbp-0x4]` (hash) and `[rbp-0x8]` (i).  
- Epilogue: `leave` + `ret`.

**At `-O2`:**

```asm
0000000000001060 <compute_hash>:
    1060:       f3 0f 1e fa             endbr64
    1064:       0f b6 07                movzx  eax, BYTE PTR [rdi]
    1067:       84 c0                   test   al, al
    1069:       74 1b                   je     1086 <compute_hash+0x26>
    ...
    1086:       c3                      ret
```

- **No classic prologue.** No `push rbp`, no `mov rbp, rsp`, no stack allocation.  
- The frame pointer is omitted (`-fomit-frame-pointer` active by default at `-O2`).  
- The `rdi` parameter is **not** saved to the stack — it's used directly in registers.  
- The function immediately begins with useful code (loading the first byte of the string).  
- Epilogue: a simple `ret`, without `leave` or `pop rbp`.

> **Key observation**: the prologue goes from 5 instructions (18 bytes) at `-O0` to 0 instructions at `-O2`. The epilogue goes from 2 instructions to 1.

### `check_serial`

**At `-O0`:**

```asm
0000000000001189 <check_serial>:
    1189:       f3 0f 1e fa             endbr64
    118d:       55                      push   rbp
    118e:       48 89 e5                mov    rbp, rsp
    1191:       48 83 ec 40             sub    rsp, 0x40
    1195:       48 89 7d c8             mov    QWORD PTR [rbp-0x38], rdi
    1199:       48 89 75 c0             mov    QWORD PTR [rbp-0x40], rsi
    ...
    11df:       c9                      leave
    11e0:       c3                      ret
```

- Full prologue with `sub rsp, 0x40` (64 bytes allocated) — the function uses a local buffer (probably for `sprintf`).  
- Both parameters (`rdi` and `rsi`) are saved to the stack.  
- Epilogue: `leave` + `ret`.

**At `-O2`:**

```asm
0000000000001090 <check_serial>:
    1090:       f3 0f 1e fa             endbr64
    1094:       53                      push   rbx
    1095:       48 89 f3                mov    rbx, rsi
    1098:       48 83 ec 30             sub    rsp, 0x30
    ...
    10dc:       48 83 c4 30             add    rsp, 0x30
    10e0:       5b                      pop    rbx
    10e1:       c3                      ret
```

- **No frame pointer** (`rbp` is neither saved nor used).  
- Saves `rbx` (callee-saved) because the function needs a stable register across internal `call`s — `rsi` (2nd parameter) is copied into `rbx` to survive calls.  
- Stack allocation reduced to `0x30` (48 bytes) instead of `0x40` (64 bytes) — less padding needed without the frame pointer.  
- Local variable access via `[rsp+N]` instead of `[rbp-N]`.  
- Epilogue: `add rsp, 0x30` + `pop rbx` + `ret` (no `leave`).

### `main`

**At `-O0`:**

- Full prologue: `endbr64` + `push rbp` + `mov rbp, rsp` + `sub rsp, 0x10`.  
- Saves `edi` (argc) and `rsi` (argv) to the stack.  
- Epilogue: `leave` + `ret`.

**At `-O2`:**

- Minimal or absent prologue depending on whether `main` calls other functions (if so, likely `sub rsp, 0x8` for alignment before the `call`).  
- No saving of `argc`/`argv` to the stack — direct register usage.  
- Epilogue: `add rsp` (if allocation) + `ret`.

---

## 4. Differences in Function Bodies

### Focus on `compute_hash`

This is the most instructive function for observing optimizations.

#### Variable Access: Stack vs Registers

**`-O0`** — All local variables live on the stack:

| Variable | `-O0` Location | `-O2` Location |  
|---|---|---|  
| `input` (parameter) | `[rbp-0x18]` (copy of `rdi`) | `rdi` (stays in register) |  
| `hash` | `[rbp-0x4]` | `edx` or `eax` |  
| `i` (counter) | `[rbp-0x8]` | `rcx` or inferred from pointer advancement |

At `-O2`, no local variable touches the stack. Everything stays in registers.

#### Instruction Count

```bash
$ objdump -d -M intel keygenme_O0 | sed -n '/<compute_hash>:/,/^$/p' | grep '^ ' | wc -l
22

$ objdump -d -M intel keygenme_O2 | sed -n '/<compute_hash>:/,/^$/p' | grep '^ ' | wc -l
13
```

The function goes from about **22 instructions** at `-O0` to about **13 instructions** at `-O2` — roughly a 40% reduction.

#### Concrete Optimizations Observed

**Optimization 1: Elimination of unnecessary store-loads.**

At `-O0`, each operation follows the "load from stack → operate → store to stack" pattern:

```asm
; -O0: hash += (int)input[i]
mov    eax, DWORD PTR [rbp-0x8]       ; load i  
cdqe  
add    rax, QWORD PTR [rbp-0x18]      ; compute &input[i]  
movzx  eax, BYTE PTR [rax]            ; load input[i]  
movsx  eax, al                         ; sign extension  
add    DWORD PTR [rbp-0x4], eax        ; hash += ... (memory write)  
```

At `-O2`, the same operation:

```asm
; -O2: hash += (int)input[i]
movsx  eax, BYTE PTR [rdi+rcx]        ; load input[i] directly (rdi=input, rcx=i)  
add    edx, eax                        ; hash += ... (edx = hash, all in registers)  
```

Six instructions reduced to two. Intermediate stack memory accesses have completely disappeared.

**Optimization 2: Strength reduction on multiplication.**

If `compute_hash` contains `hash = hash * 8` (or `hash <<= 3`):

```asm
; -O0: explicit multiplication or shift via the stack
mov    eax, DWORD PTR [rbp-0x4]       ; load hash  
shl    eax, 3                          ; hash *= 8  
mov    DWORD PTR [rbp-0x4], eax        ; store hash  

; -O2: shift directly on the register
shl    edx, 3                          ; single instruction, edx = hash
```

Three instructions (load-shift-store) become one.

**Optimization 3: Loop restructuring.**

At `-O0`, the `for` loop follows the canonical pattern with an initial jump to the test:

```asm
; -O0
    mov    DWORD PTR [rbp-0x8], 0x0    ; i = 0
    jmp    .test                        ; jump to test at loop end
.body:
    ; ... body ...
    add    DWORD PTR [rbp-0x8], 0x1    ; i++
.test:
    ; load input[i], compare with 0
    jne    .body                        ; if != '\0', continue
```

At `-O2`, GCC often reorganizes into a *do-while* with a pre-entry test:

```asm
; -O2
    movzx  eax, BYTE PTR [rdi]         ; load input[0]
    test   al, al                       ; empty string?
    je     .end                         ; if so, skip entire loop
.loop:
    ; ... body (all in registers) ...
    movzx  eax, BYTE PTR [rdi+rcx]     ; load next character
    test   al, al
    jne    .loop                        ; continue if != '\0'
.end:
```

The test is now at the **end of the loop** (`do-while` structure), saving one jump compared to the `for` pattern with initial test. The `i` counter can be replaced by a direct pointer increment (`rdi+rcx` with `rcx` incremented, or `rdi` incremented directly).

**Optimization 4 (if observable): `i` counter elimination.**

At `-O2`, GCC can eliminate the `i` variable and use an **advancing pointer** instead:

```asm
; Instead of i++ and input[i], the compiler does:
    inc    rdi                          ; input pointer++
    movzx  eax, BYTE PTR [rdi]         ; load *input
```

The `i` counter no longer exists as a variable — it is implicitly encoded in the pointer position. This is a *strength reduction* optimization applied to array indexing.

### Focus on `check_serial`

Notable observations:

- At `-O0`, the call to `compute_hash` passes the parameter via the stack (loading `[rbp-0x38]` into `rdi` before the `call`). At `-O2`, the parameter is already in the correct register or is transferred directly between registers.  
- The calls to `sprintf` and `strcmp` are present in both versions (these libc functions are not inlined).  
- At `-O2`, the return value of `strcmp` can be directly propagated as `check_serial`'s return value without intermediate storage, whereas at `-O0`, the result is stored on the stack then reloaded into `eax` before `ret`.

---

## 5. Function Calls and PLT

```bash
$ objdump -d -M intel keygenme_O0 | grep 'call' | grep 'plt' | sort -u
    call   1030 <puts@plt>
    call   1040 <printf@plt>
    call   1050 <sprintf@plt>
    call   1060 <strcmp@plt>

$ objdump -d -M intel keygenme_O2 | grep 'call' | grep 'plt' | sort -u
    call   1030 <puts@plt>
    call   1040 <printf@plt>
    call   1050 <sprintf@plt>
    call   1060 <strcmp@plt>
```

The same libc functions are called in both versions. Optimization did not change external dependencies — which makes sense, since these functions come from shared libraries and are not candidates for inlining.

Internal calls:

```bash
$ objdump -d -M intel keygenme_O0 | grep 'call' | grep -v 'plt'
    call   1139 <compute_hash>
    call   1189 <check_serial>

$ objdump -d -M intel keygenme_O2 | grep 'call' | grep -v 'plt'
    call   1060 <compute_hash>
    call   1090 <check_serial>
```

Both internal calls (`main` → `check_serial` → `compute_hash`) are preserved in both versions. `compute_hash` was not inlined into `check_serial` at `-O2`. Addresses differ (optimized code is more compact, functions are placed at different offsets), but the call structure is identical.

> **Note**: if your GCC version inlined `compute_hash` into `check_serial` at `-O2`, you won't see the `call compute_hash` in the optimized version. This is an equally valid result — document it as an inlining optimization.

---

## 6. Summary

The following table summarizes the key differences:

| Criterion | `-O0` | `-O2` |  
|---|---|---|  
| `.text` size | ~453 bytes | ~322 bytes (−30%) |  
| `compute_hash` prologue | `endbr64` + `push rbp` + `mov rbp,rsp` | `endbr64` only (no frame) |  
| Local variables | On the stack (`[rbp-N]`) | In registers |  
| Instructions in `compute_hash` | ~22 | ~13 (−40%) |  
| Loop structure | `for` with initial jump to test | `do-while` with pre-test |  
| Parameter access | Copied to stack at entry | Stay in `rdi`, `rsi` |  
| Epilogue | `leave` + `ret` | `ret` (or `pop` + `ret`) |  
| PLT calls | Identical | Identical |  
| Internal calls | `main` → `check_serial` → `compute_hash` | Same (or `compute_hash` inlined) |

**Additional difficulties at `-O2` without the `-O0` version:**

If we only received the `-O2` binary without ever seeing the `-O0` version, the main difficulties would be:

- **Identifying function boundaries** on a stripped binary would be harder because the `push rbp` / `mov rbp, rsp` prologue is absent. One would need to rely on `endbr64`, `call` targets, and `ret` to delimit functions.

- **Reconstructing local variables** would require tracing registers instead of simply listing `[rbp-N]` accesses. A single register can be reused for different variables during the function, making analysis more ambiguous.

- **Understanding the loop** would be less immediate: the optimized `do-while` structure with pre-test doesn't have the familiar symmetry of the canonical `for`. Since the `i` counter has potentially disappeared (replaced by a pointer increment), one must reconstruct the loop semantics from memory access patterns.

- **Relating code to mental source** would be generally slower. At `-O0`, one can almost read the assembly like C. At `-O2`, one must first understand the logical blocks ("this sequence computes a hash by iterating over a string"), then only reconstruct the pseudo-code. The process is reversed: at `-O0`, you read instruction by instruction and meaning emerges; at `-O2`, you must first grasp the overall intent to interpret individual instructions.

That said, the `-O2` binary remains perfectly analyzable with the techniques covered in this chapter. PLT calls (`strcmp`, `sprintf`) provide strong semantic anchor points, strings in `.rodata` reveal program messages, and the call structure `main` → `check_serial` → `compute_hash` (if preserved) segments the analysis into manageable blocks. Moving to a tool like Ghidra (chapter 8) would make the `-O2` analysis significantly more comfortable, especially thanks to the decompiler and flow graph.

⏭️
