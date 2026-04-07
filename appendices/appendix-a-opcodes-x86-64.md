🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix A — Quick Reference of Common x86-64 Opcodes in RE

> 📎 **Reference Sheet** — This appendix lists the x86-64 instructions you will encounter most often when reverse engineering binaries compiled with GCC/G++. It is not intended to replace the Intel manual (over 2,500 pages) but to cover the ~95% of instructions found in a typical ELF binary.

---

## Notation Conventions

Throughout this appendix, instructions are presented in **Intel syntax** (destination on the left, source on the right), which is the default syntax of Ghidra, IDA, and the most widely used in RE literature. To get this syntax with `objdump`, use the `-M intel` flag.

The following abbreviations are used in the tables:

| Notation | Meaning |  
|----------|---------|  
| `reg` | General-purpose register (e.g., `rax`, `ecx`, `r8d`) |  
| `r/m` | Register or memory operand (e.g., `rax`, `[rbp-0x10]`) |  
| `imm` | Immediate value (constant encoded in the instruction) |  
| `mem` | Memory operand only |  
| `rel` | Relative address (offset from `rip`) |  
| `RFLAGS` | Flags register (ZF, SF, CF, OF, etc.) |

Size suffixes follow the Intel convention:

| Suffix / Prefix | Size | Example register |  
|------------------|------|------------------|  
| `byte` | 8 bits | `al`, `cl`, `r8b` |  
| `word` | 16 bits | `ax`, `cx`, `r8w` |  
| `dword` | 32 bits | `eax`, `ecx`, `r8d` |  
| `qword` | 64 bits | `rax`, `rcx`, `r8` |

> 💡 **Important reminder**: in x86-64, writing to a 32-bit register (e.g., `mov eax, 0`) automatically zeroes the upper 32 bits of the corresponding 64-bit register (`rax`). GCC heavily exploits this behavior to save one encoding byte (`xor eax, eax` instead of `xor rax, rax`).

---

## 1 — Data Transfer

These instructions alone account for a considerable portion of disassembled code. The `mov` family and its variants form the foundation of every program.

### 1.1 — Basic Moves

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `mov` | `r/m, r/m/imm` | Copies the source to the destination | None |  
| `movzx` | `reg, r/m` (smaller size) | Copy with zero extension (unsigned) | None |  
| `movsx` | `reg, r/m` (smaller size) | Copy with sign extension (signed) | None |  
| `movsxd` | `reg64, r/m32` | Sign extension 32→64 bits | None |  
| `cmovcc` | `reg, r/m` | Conditional copy (based on flags, see §7) | None |

**What you will see in RE**: `movzx eax, byte ptr [rbp-0x1]` is the classic GCC pattern for loading a `char` or `unsigned char` into a 32-bit register. `movsx` appears when the source variable is signed and the compiler must preserve the sign during widening. `movsxd` is common when an `int` (32-bit) is used as an index into an array of pointers (64-bit).

### 1.2 — Address Loading

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `lea` | `reg, mem` | Loads the effective address (not the contents) | None |

`lea` (*Load Effective Address*) is one of the most versatile and most misleading instructions for the RE beginner. It computes an address but **never reads memory**. GCC uses it in three main contexts:

- **Actual address computation**: `lea rdi, [rip+0x2a3e]` loads the address of a string in `.rodata` for a future call to `printf` or `puts`. This is the "normal" use of `lea`.  
- **Disguised arithmetic**: `lea eax, [rdi+rsi*4+0x5]` computes `rdi + rsi*4 + 5` in a single instruction, without touching the flags. GCC often prefers `lea` over an `add`/`imul` sequence because it is more compact and does not modify `RFLAGS`.  
- **Passing a pointer to a local variable**: `lea rdi, [rbp-0x20]` passes the address of a local buffer as the first argument to a function. If you see `lea` followed by `call`, it is almost always a pointer pass.

### 1.3 — Stack Operations

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `push` | `r/m/imm` | Decrements `rsp` by 8, then writes the value to `[rsp]` | None |  
| `pop` | `r/m` | Reads the value at `[rsp]`, then increments `rsp` by 8 | None |

In x86-64 with the System V AMD64 calling convention, `push` and `pop` are mainly visible in **function prologues and epilogues** to save/restore callee-saved registers (`rbx`, `rbp`, `r12`–`r15`). Parameter passing is done via registers (see Appendix B), so argument `push`es are rare unless a function has more than 6 integer parameters.

### 1.4 — Exchange and Conversion

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `xchg` | `r/m, reg` | Atomically exchanges the two operands | None |  
| `bswap` | `reg` | Reverses the byte order (endianness) | None (undefined for 16 bits) |  
| `cbw` / `cwde` / `cdqe` | (implicit) | Sign extension into `ax`/`eax`/`rax` | None |  
| `cwd` / `cdq` / `cqo` | (implicit) | Sign-extends `ax`/`eax`/`rax` into `dx`/`edx`/`rdx` | None |

`cdq` is extremely common: it almost always precedes an `idiv` instruction to prepare the `edx:eax` pair before a 32-bit signed division. If you see `cdq` followed by `idiv`, you are looking at a signed division in C (`/` or `%` on `int` values). `bswap` appears in networking code to convert between host and network byte order (`htonl`/`ntohl`).

---

## 2 — Integer Arithmetic

### 2.1 — Basic Operations

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `add` | `r/m, r/m/imm` | Addition: `dest = dest + src` | CF, OF, SF, ZF, AF, PF |  
| `sub` | `r/m, r/m/imm` | Subtraction: `dest = dest - src` | CF, OF, SF, ZF, AF, PF |  
| `inc` | `r/m` | Increment: `dest = dest + 1` | OF, SF, ZF, AF, PF (not CF) |  
| `dec` | `r/m` | Decrement: `dest = dest - 1` | OF, SF, ZF, AF, PF (not CF) |  
| `neg` | `r/m` | Negation (two's complement): `dest = -dest` | CF, OF, SF, ZF, AF, PF |  
| `adc` | `r/m, r/m/imm` | Addition with carry: `dest = dest + src + CF` | CF, OF, SF, ZF, AF, PF |  
| `sbb` | `r/m, r/m/imm` | Subtraction with borrow: `dest = dest - src - CF` | CF, OF, SF, ZF, AF, PF |

> 💡 `inc` and `dec` do not modify the **Carry Flag (CF)**. This subtlety is rarely important in pure RE, but it is exploited in certain multi-precision arithmetic sequences where the CF must be preserved between an `add`/`adc`.

**Common GCC pattern**: when GCC optimizes a loop counter, it often uses `add reg, 1` rather than `inc reg` starting from `-O2`, because performance considerations on older processors (partial flag dependency) have left traces in the compiler's heuristics. Do not be surprised to see both forms coexisting in the same binary.

### 2.2 — Multiplication

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `imul` | `r/m` | Signed multiplication: `rdx:rax = rax × r/m` (1-operand form) | CF, OF (SF, ZF undefined) |  
| `imul` | `reg, r/m` | Truncated signed multiplication: `reg = reg × r/m` (2-operand form) | CF, OF |  
| `imul` | `reg, r/m, imm` | Truncated signed multiplication: `reg = r/m × imm` (3-operand form) | CF, OF |  
| `mul` | `r/m` | Unsigned multiplication: `rdx:rax = rax × r/m` | CF, OF |

The 2- or 3-operand form of `imul` is by far the most common in GCC code. The 1-operand form (`imul r/m` or `mul r/m`), which implicitly uses `rax` and produces a double-width result in `rdx:rax`, appears mainly in two cases: constant-optimized divisions (see below) and multi-precision arithmetic.

**Critical pattern — Division by constant via magic multiplication**: GCC systematically transforms divisions by constants into a multiplication by the "magic number" (multiplicative inverse) followed by a shift. For example, a division by 10 of an `unsigned int` can become:

```
mov     eax, edi  
mov     edx, 0xCCCCCCCD  
imul    rdx, rax            ; or mul edx depending on context  
shr     rdx, 35  
```

If you see an `imul` or `mul` with a "weird" hexadecimal constant like `0xCCCCCCCD`, `0x55555556`, `0x92492493`, or `0xAAAAAAAB`, it is almost certainly an optimized division. Appendix I details the most common magic constants and their corresponding divisors.

### 2.3 — Division

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `idiv` | `r/m` | Signed division: `rax = rdx:rax / r/m`, `rdx = rdx:rax % r/m` | Undefined |  
| `div` | `r/m` | Unsigned division: `rax = rdx:rax / r/m`, `rdx = rdx:rax % r/m` | Undefined |

The `div`/`idiv` instructions are **rare** in optimized code, precisely because GCC replaces them with magic multiplications (see above). When you see one, it is generally in code compiled with `-O0` (no optimization) or in a division where the divisor is not known at compile time (variable).

The typical pattern for a signed division at `-O0` is:

```
mov     eax, [rbp-0x4]     ; load the dividend  
cdq                         ; sign-extend eax into edx  
idiv    dword ptr [rbp-0x8] ; divide edx:eax by the divisor  
; result: eax = quotient, edx = remainder
```

---

## 3 — Logical and Bitwise Operations

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `and` | `r/m, r/m/imm` | Bitwise AND | CF=0, OF=0, SF, ZF, PF |  
| `or` | `r/m, r/m/imm` | Bitwise OR | CF=0, OF=0, SF, ZF, PF |  
| `xor` | `r/m, r/m/imm` | Bitwise exclusive OR | CF=0, OF=0, SF, ZF, PF |  
| `not` | `r/m` | Inverts all bits (one's complement) | None |  
| `test` | `r/m, r/m/imm` | Bitwise AND **without storing the result** (sets flags) | CF=0, OF=0, SF, ZF, PF |

### Fundamental Idioms to Recognize

**`xor reg, reg`** — This is the universal idiom for zeroing a register. `xor eax, eax` is encoded in 2 bytes versus 5 for `mov eax, 0`. GCC uses it systematically. When you read `xor eax, eax`, mentally read `eax = 0`.

**`test reg, reg`** — Tests whether a register is zero by performing an AND with itself without modifying the value. Sets ZF if the register is zero, SF if the sign bit is 1. This is the standard pattern for `if (x == 0)` or `if (x != 0)` in C, followed by a `jz` (jump if zero) or `jnz` (jump if not zero).

**`test reg, imm`** — Tests whether certain bits are set. `test eax, 1` checks parity (bit 0), which corresponds to `if (x % 2 == 0)` or `if (x & 1)`. `test eax, 0x80` checks bit 7 (sign of a byte).

**`and reg, imm`** — Often used as a mask or modulo by a power of 2. `and eax, 0xFF` is equivalent to a cast to `unsigned char`. `and eax, 0x7` is equivalent to `x % 8` for an unsigned integer.

**`or reg, 0xFFFFFFFF`** — Sets all bits to 1, equivalent to `reg = -1` in signed. Sometimes used for error return values.

---

## 4 — Shifts and Rotations

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `shl` / `sal` | `r/m, imm8/cl` | Logical/arithmetic left shift | CF (last bit shifted out), OF, SF, ZF, PF |  
| `shr` | `r/m, imm8/cl` | Logical right shift (inserts 0s) | CF, OF, SF, ZF, PF |  
| `sar` | `r/m, imm8/cl` | Arithmetic right shift (preserves the sign) | CF, OF, SF, ZF, PF |  
| `rol` | `r/m, imm8/cl` | Rotate left | CF, OF |  
| `ror` | `r/m, imm8/cl` | Rotate right | CF, OF |  
| `rcl` | `r/m, imm8/cl` | Rotate left through carry | CF, OF |  
| `rcr` | `r/m, imm8/cl` | Rotate right through carry | CF, OF |  
| `shld` | `r/m, reg, imm8/cl` | Double-precision left shift | CF, OF, SF, ZF, PF |  
| `shrd` | `r/m, reg, imm8/cl` | Double-precision right shift | CF, OF, SF, ZF, PF |

**`shl` and `shr` as multiplication/division by power of 2** — `shl eax, 3` is equivalent to `eax *= 8` and `shr eax, 2` is equivalent to `eax /= 4` (unsigned division). GCC systematically uses these shifts when the multiplier or divisor is an exact power of 2.

**`sar` for signed division** — `sar eax, 31` extracts the sign bit (produces `0` if positive, `-1` if negative). This pattern appears in the signed division by power of 2 idiom: to compute `x / 4` on a signed `int`, GCC generates a sequence that adds a bias of `3` (`divisor - 1`) if `x` is negative, then performs the `sar`. This corrects the round-toward-zero behavior required by the C standard for signed divisions.

**Rotations** — `rol` and `ror` are relatively rare in standard compiled C code. Their presence is a strong indicator of cryptographic code (SHA-256, ChaCha20, etc.) or obfuscation routines. If you see rotations in otherwise "normal" code, it is an interesting red flag.

---

## 5 — Comparison and Test

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `cmp` | `r/m, r/m/imm` | Subtraction without storing the result (sets flags) | CF, OF, SF, ZF, AF, PF |  
| `test` | `r/m, r/m/imm` | Logical AND without storing the result (sets flags) | CF=0, OF=0, SF, ZF, PF |

`cmp` and `test` are the two instructions that almost always precede a conditional jump or a `cmovcc`/`setcc`. They do not modify any data — they only set the flags for subsequent instructions.

**Fundamental difference**: `cmp a, b` performs `a - b` (subtraction) while `test a, b` performs `a & b` (logical AND). Use this distinction to understand what the code is testing:

- `cmp eax, 5` followed by `jl` → tests if `eax < 5` (numeric comparison)  
- `test eax, eax` followed by `jz` → tests if `eax == 0` (null test)  
- `test al, 0x20` followed by `jnz` → tests if bit 5 is set (bit test)

---

## 6 — Unconditional Jumps and Calls

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `jmp` | `rel/r/m` | Unconditional jump | None |  
| `call` | `rel/r/m` | Function call: pushes the next `rip`, then jumps | None |  
| `ret` | (none or `imm16`) | Function return: pops `rip` (and adds `imm16` to `rsp` if present) | None |

**`jmp` in RE** — Three main forms:  
- `jmp 0x401234` — direct jump, fixed target (the simplest case to analyze)  
- `jmp rax` — indirect jump via register, typical of switch-case compiled into a jump table or C++ virtual dispatch (vtable)  
- `jmp qword ptr [rip+0x2abc]` — jump via GOT/PLT, typical of calls to shared library functions in PIC/PIE code

**`call` in RE** — Same scheme as `jmp`:  
- `call 0x401100` — direct call to an internal function  
- `call rax` — indirect call, often a function pointer or a C++ virtual call (`call qword ptr [rax+0x10]` = call to the 3rd virtual method)  
- `call printf@plt` — call via PLT to a library function (see Chapter 2.9)

**`ret`** — In the vast majority of cases, `ret` takes no operand. The `ret imm16` form (which adjusts `rsp` after the `pop rip`) is a remnant of the `stdcall` calling convention (Windows 32-bit) and almost never appears in System V AMD64 code.

---

## 7 — Conditional Jumps

Conditional jumps test the state of flags set by a preceding instruction (`cmp`, `test`, `sub`, `add`, etc.). Each mnemonic corresponds to a specific condition. Some have aliases (synonyms) for improved readability.

### 7.1 — Zero and Equality Conditions

| Instruction | Alias | Condition (flags) | C semantics after `cmp a, b` |  
|-------------|-------|-------------------|-------------------------------|  
| `jz` | `je` | ZF = 1 | `a == b` |  
| `jnz` | `jne` | ZF = 0 | `a != b` |

### 7.2 — Unsigned Conditions

These jumps are used after a comparison between **unsigned** values. The mnemonics use the terms *above* and *below*.

| Instruction | Alias | Condition (flags) | C semantics after `cmp a, b` (unsigned) |  
|-------------|-------|-------------------|------------------------------------------|  
| `ja` | `jnbe` | CF = 0 AND ZF = 0 | `a > b` |  
| `jae` | `jnb`, `jnc` | CF = 0 | `a >= b` |  
| `jb` | `jnae`, `jc` | CF = 1 | `a < b` |  
| `jbe` | `jna` | CF = 1 OR ZF = 1 | `a <= b` |

### 7.3 — Signed Conditions

These jumps are used after a comparison between **signed** values (int, long). The mnemonics use the terms *greater* and *less*.

| Instruction | Alias | Condition (flags) | C semantics after `cmp a, b` (signed) |  
|-------------|-------|-------------------|----------------------------------------|  
| `jg` | `jnle` | ZF = 0 AND SF = OF | `a > b` |  
| `jge` | `jnl` | SF = OF | `a >= b` |  
| `jl` | `jnge` | SF ≠ OF | `a < b` |  
| `jle` | `jng` | ZF = 1 OR SF ≠ OF | `a <= b` |

### 7.4 — Individual Flag Conditions

| Instruction | Alias | Condition (flags) | Typical use in RE |  
|-------------|-------|-------------------|-------------------|  
| `js` | — | SF = 1 | The result is negative |  
| `jns` | — | SF = 0 | The result is positive or zero |  
| `jo` | — | OF = 1 | Signed overflow |  
| `jno` | — | OF = 0 | No signed overflow |  
| `jp` | `jpe` | PF = 1 | Even parity (rare in standard RE) |  
| `jnp` | `jpo` | PF = 0 | Odd parity (rare in standard RE) |  
| `jcxz` | `jecxz`, `jrcxz` | `(r/e)cx = 0` | Rare — directly tests the counter register |

### 7.5 — Reading a Conditional Jump in RE: Quick Method

When you encounter a conditional jump in a disassembly, trace back to the instruction that set the flags (usually the `cmp` or `test` immediately above) and apply the correspondence:

1. Identify the two operands of the `cmp`/`test`: these are the compared values (let's call them `A` and `B` for `cmp A, B`).  
2. Look at the jump mnemonic to determine the condition.  
3. Determine whether the comparison is signed or unsigned by looking at the mnemonics (*above/below* = unsigned, *greater/less* = signed).

The jump is taken if the condition is true, and execution falls through if the condition is false. In an `if`/`else` structure compiled by GCC, the conditional jump generally jumps to the `else` block (or past the end of the `if`), and the fall-through executes the `then` block. In other words, the jump condition is often the **inverse** of the `if` condition in C:

```c
// C code
if (x == 5) {
    do_something();
}
```

```asm
; Typical assembly code (GCC)
cmp     eax, 5  
jne     skip          ; jump if x != 5 (inverse of the C condition)  
call    do_something  
skip:  
```

---

## 8 — Conditional Instructions Without Jumps

### 8.1 — `SETcc` — Set a Byte Based on a Condition

| Instruction | Operands | Description |  
|-------------|----------|-------------|  
| `setcc` | `r/m8` | Sets the operand to 1 if condition `cc` is true, 0 otherwise |

The condition suffixes are the same as for jumps (`sete`, `setne`, `setl`, `setge`, `seta`, `setb`, etc.).

**In RE**: `sete al` followed by `movzx eax, al` is the standard GCC pattern for a boolean expression like `return (a == b);`. The `movzx` widens the 8-bit result to 32 bits for use as an `int` return value (or `bool` promoted to `int`).

### 8.2 — `CMOVcc` — Conditional Move

| Instruction | Operands | Description |  
|-------------|----------|-------------|  
| `cmovcc` | `reg, r/m` | Copies the source to the destination if condition `cc` is true |

Same condition suffixes as for jumps and `setcc`. `cmovcc` is heavily used by GCC starting from `-O2` to avoid branches in ternary expressions and `min`/`max`:

```c
// C code
int result = (a > b) ? a : b;  // max(a, b)
```

```asm
; Assembly code (GCC -O2)
cmp     edi, esi  
cmovl   edi, esi      ; if edi < esi, then edi = esi  
mov     eax, edi       ; return the result  
```

---

## 9 — String and Memory Block Manipulation

These instructions operate on blocks of bytes pointed to by `rsi` (source) and `rdi` (destination), with `rcx` as the counter. They are often preceded by the `rep` or `repne` prefix.

| Instruction | Common prefix | Description |  
|-------------|---------------|-------------|  
| `movsb/w/d/q` | `rep` | Copies `rcx` elements from `[rsi]` to `[rdi]` |  
| `stosb/w/d/q` | `rep` | Fills `rcx` elements at `[rdi]` with the value of `al`/`ax`/`eax`/`rax` |  
| `lodsb/w/d/q` | (rare) | Loads an element from `[rsi]` into `al`/`ax`/`eax`/`rax` |  
| `cmpsb/w/d/q` | `repz`/`repnz` | Compares elements from `[rsi]` and `[rdi]` |  
| `scasb/w/d/q` | `repnz` | Searches for `al`/`ax`/`eax`/`rax` in the block at `[rdi]` |

**In RE**: these instructions often appear in inline implementations of `memcpy` (`rep movsb`), `memset` (`rep stosb`), `strcmp`/`memcmp` (`repz cmpsb`), and `strlen` (`repnz scasb`). GCC generates these sequences either directly (built-in functions) or when it inlines libc functions. `rep movsq` copies 8 bytes per iteration and is used for copies of compile-time known and aligned sizes.

The direction flag (DF in RFLAGS) controls the traversal direction: DF = 0 means forward traversal (the normal case, guaranteed by the System V convention at every function entry), DF = 1 means backward traversal (very rare, must be restored by `cld` before returning).

---

## 10 — Advanced Bit Manipulation

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `bt` | `r/m, reg/imm8` | Copies bit number `src` of `dest` into CF | CF |  
| `bts` | `r/m, reg/imm8` | Like `bt`, then sets the bit to 1 | CF |  
| `btr` | `r/m, reg/imm8` | Like `bt`, then clears the bit to 0 | CF |  
| `btc` | `r/m, reg/imm8` | Like `bt`, then inverts the bit | CF |  
| `bsf` | `reg, r/m` | Bit Scan Forward: index of the first set bit (from LSB) | ZF |  
| `bsr` | `reg, r/m` | Bit Scan Reverse: index of the first set bit (from MSB) | ZF |  
| `popcnt` | `reg, r/m` | Counts the number of set bits | ZF (CF=OF=SF=PF=0) |  
| `lzcnt` | `reg, r/m` | Counts leading zeros | CF, ZF |  
| `tzcnt` | `reg, r/m` | Counts trailing zeros | CF, ZF |

These instructions are less common in standard "business logic" code but appear in data structure implementations (bitmaps, sets), hashing algorithms, and GCC builtins (`__builtin_ctz`, `__builtin_clz`, `__builtin_popcount`). `bsf`/`tzcnt` corresponds to `__builtin_ctz()` and `bsr`/`lzcnt` to `__builtin_clz()`. GCC can emit `popcnt` if `-mpopcnt` or `-march=native` is used on a compatible processor.

---

## 11 — System Calls and Special Instructions

| Instruction | Operands | Description | Affected Flags |  
|-------------|----------|-------------|----------------|  
| `syscall` | (implicit) | Linux x86-64 system call | RCX, R11 clobbered |  
| `nop` | (none or `r/m`) | No Operation (does nothing) | None |  
| `int 3` | — | Breakpoint (trap for the debugger) | — |  
| `ud2` | — | Undefined instruction (raises `#UD` — intentional crash) | — |  
| `endbr64` | — | End Branch 64 — CET marker (Control-flow Enforcement) | None |  
| `hlt` | — | Halt the processor (ring 0 only) | — |  
| `cpuid` | (implicit) | Processor identification | EAX, EBX, ECX, EDX |  
| `rdtsc` | — | Reads the cycle counter into `edx:eax` | None |  
| `pause` | — | Spin-wait hint (optimizes busy-wait loops) | None |

**`syscall`** — In Linux x86-64, the system call interface passes the syscall number in `rax`, and arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` (note: `r10` and not `rcx` for the 4th argument, unlike the function calling convention). The result is returned in `rax`. See `unistd_64.h` or `ausyscall --dump` for the number table.

**`nop`** — Multi-byte `nop`s (`nop dword ptr [rax+0x0]`, etc.) are **alignment padding** inserted by GCC/the assembler to align jump targets or function starts on 16-byte boundaries. They have no logical significance. Do not waste time analyzing them.

**`endbr64`** — Present at the beginning of every function and every indirect jump target if the binary was compiled with CET (Intel Control-flow Enforcement Technology, `-fcf-protection`). It is a security marker that validates indirect branch destinations. It is functionally a `nop` on processors without CET.

**`int 3`** (opcode `0xCC`) — The software breakpoint. GDB writes this opcode at the breakpoint address, replacing the original byte. It is also the instruction that some anti-debugging techniques look for in their own code (see Chapter 19.8).

**`ud2`** — Intentionally generates an "undefined instruction" exception. GCC inserts it after `__builtin_unreachable()` or at the end of an exhaustive `switch` to mark a theoretically unreachable path. In practice, if execution reaches `ud2`, the program crashes with `SIGILL`.

**`rdtsc`** — Reads the processor's cycle counter (Time Stamp Counter). Used in performance measurements and — more relevantly in RE — in **timing-based anti-debugging techniques** (Chapter 19.7). The typical pattern: two `rdtsc` instructions bracketing a code block, with a comparison of the difference against a threshold.

---

## 12 — Common Floating-Point Instructions (SSE/SSE2)

Modern floating-point code in x86-64 uses SSE registers (`xmm0`–`xmm15`) rather than the obsolete x87 FPU. The System V AMD64 convention passes floats in `xmm0`–`xmm7` and returns them in `xmm0`.

| Instruction | Operands | Description |  
|-------------|----------|-------------|  
| `movss` | `xmm, xmm/m32` | Moves a `float` (scalar single) |  
| `movsd` | `xmm, xmm/m64` | Moves a `double` (scalar double) |  
| `movaps` / `movups` | `xmm, xmm/m128` | Moves 128 bits aligned / unaligned (packed) |  
| `addss` / `addsd` | `xmm, xmm/m` | `float` / `double` addition |  
| `subss` / `subsd` | `xmm, xmm/m` | `float` / `double` subtraction |  
| `mulss` / `mulsd` | `xmm, xmm/m` | `float` / `double` multiplication |  
| `divss` / `divsd` | `xmm, xmm/m` | `float` / `double` division |  
| `comiss` / `comisd` | `xmm, xmm/m` | Ordered comparison (sets ZF, CF, PF) |  
| `ucomiss` / `ucomisd` | `xmm, xmm/m` | Unordered comparison (handles NaN) |  
| `cvtsi2ss` / `cvtsi2sd` | `xmm, r/m32/64` | Converts integer → `float` / `double` |  
| `cvtss2si` / `cvtsd2si` | `reg, xmm/m` | Converts `float` / `double` → integer (with rounding) |  
| `cvttss2si` / `cvttsd2si` | `reg, xmm/m` | Converts `float` / `double` → integer (truncation toward 0) |  
| `cvtss2sd` / `cvtsd2ss` | `xmm, xmm/m` | Converts between `float` and `double` |  
| `xorps` / `xorpd` | `xmm, xmm/m128` | Packed XOR (used to zero an SSE register) |  
| `sqrtss` / `sqrtsd` | `xmm, xmm/m` | `float` / `double` square root |  
| `maxss` / `minss` | `xmm, xmm/m` | `float` maximum / minimum |  
| `maxsd` / `minsd` | `xmm, xmm/m` | `double` maximum / minimum |

**Suffix mnemonics**: `ss` = Scalar Single (`float`), `sd` = Scalar Double (`double`), `ps` = Packed Single (4 × `float`), `pd` = Packed Double (2 × `double`).

**`xorps xmm0, xmm0`** — The floating-point equivalent of `xor eax, eax`: zeroes the `xmm0` register. Ubiquitous pattern at the beginning of a function when a floating-point variable is initialized to `0.0`.

**In RE**: if you see instructions with the `ss` suffix, the code is manipulating `float` values. If the suffixes are `sd`, they are `double` values. The `cvt*` instructions indicate type conversions (explicit or implicit casts in C). Packed instructions (`ps`, `pd`) outside of explicitly vectorized code often signal automatic SIMD optimizations by GCC (`-ftree-vectorize`, enabled by default at `-O2`).

---

## 13 — Common SIMD Instructions (Beyond Scalar)

When GCC vectorizes a loop or the source code uses intrinsics, you will encounter packed instructions. Here are the most common ones, which you should be able to recognize without necessarily understanding in detail:

| Instruction | Registers | Short description |  
|-------------|-----------|-------------------|  
| `paddd` / `paddq` | `xmm` | Packed addition of 32/64-bit integers |  
| `psubd` / `psubq` | `xmm` | Packed subtraction of 32/64-bit integers |  
| `pmulld` | `xmm` | Packed multiplication of 32-bit integers |  
| `pcmpeqd` / `pcmpgtd` | `xmm` | Packed integer comparison (==, >) |  
| `pand` / `por` / `pxor` | `xmm` | Packed logical operations |  
| `pshufd` | `xmm, xmm, imm8` | Dword shuffle within a register |  
| `punpcklbw/wd/dq/qdq` | `xmm` | Packed interleave |  
| `movdqa` / `movdqu` | `xmm, m128` | 128-bit aligned / unaligned move (integers) |  
| `pshufb` | `xmm, xmm` | Byte shuffle (SSSE3 — fast lookup tables) |

**AVX prefixes**: if the binary is compiled with `-mavx` or `-march=haswell` (and beyond), the same instructions appear with a `v` prefix and `ymm` (256-bit) or `zmm` (512-bit) registers: `vaddps`, `vmovups`, `vpaddd`, etc. The logic is identical but the width is doubled or quadrupled.

**In RE**: do not panic when facing SIMD instructions. First identify the loop they implement (SIMD instructions are almost always in a loop body), then look for a non-vectorized version of the same processing — GCC often generates a "scalar tail" after the vectorized loop, which processes the remaining elements one by one and is much more readable. Analyze this tail to understand the logic, then verify that the SIMD loop does the same thing in parallel.

---

## 14 — Summary Table by Frequency in RE

To conclude, here is an approximate ranking of instructions by frequency of appearance in a typical x86-64 ELF binary compiled with GCC. This ranking is based on statistical counts of common binaries and gives an idea of what you will see most often.

| Rank | Instructions | Category |  
|------|-------------|----------|  
| 1 | `mov`, `lea` | Transfer |  
| 2 | `call`, `ret` | Call/return |  
| 3 | `cmp`, `test` | Comparison |  
| 4 | `jz/je`, `jnz/jne`, `jmp` | Jumps |  
| 5 | `push`, `pop` | Stack |  
| 6 | `add`, `sub` | Arithmetic |  
| 7 | `xor`, `and`, `or` | Logic |  
| 8 | `shl`, `shr`, `sar` | Shifts |  
| 9 | `movzx`, `movsx` | Extensions |  
| 10 | `imul` | Multiplication |  
| 11 | `nop`, `endbr64` | Padding/CET |  
| 12 | `cmovcc`, `setcc` | Branchless conditional |  
| 13 | `jl`, `jg`, `jle`, `jge`, `ja`, `jb`, `jbe`, `jae` | Signed/unsigned jumps |  
| 14 | `movss`, `movsd`, `addsd`, `mulsd` | SSE floating-point |  
| 15 | `rep movsb/q`, `rep stosb/q` | Memory blocks |

The instructions in ranks 1 through 8 alone constitute the vast majority of the code you will analyze. If you have a thorough command of these ~20 instructions and the usage patterns described in this appendix, you can comfortably read most disassembled functions.

---

> 📚 **Further reading**:  
> - **Appendix B** — [System V AMD64 ABI Calling Conventions](/appendices/appendix-b-system-v-abi.md) — complements this appendix with details on parameter passing and stack management.  
> - **Appendix I** — [Recognizable GCC Patterns in Assembly](/appendices/appendix-i-gcc-patterns.md) — catalogs the idiomatic instruction sequences that GCC generates for common C/C++ constructs.  
> - **Chapter 3** — [x86-64 Assembly Basics for RE](/03-x86-64-assembly/README.md) — revisits these instructions in a progressive learning context with practical examples.  
> - **Intel Manual** — *Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 2* — the exhaustive (and voluminous) reference for all x86-64 instructions.

⏭️ [System V AMD64 ABI Calling Conventions (summary table)](/appendices/appendix-b-system-v-abi.md)
