🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 34.2 — Go Calling Convention (stack-based then register-based since Go 1.17)

> 🐹 *If you have spent hours mastering the System V AMD64 convention (Chapter 3), prepare for a culture shock. Go long used a calling convention entirely based on the stack — no arguments in registers, no return value in `RAX`. Since Go 1.17, a register-based ABI was introduced, but it still differs significantly from what C does. Understanding both conventions is essential to correctly read the disassembly of a Go binary.*

---

## Why Go Did Not Adopt the System V Convention

The System V AMD64 convention, used by GCC and Clang for C/C++ on Linux, passes the first six integer arguments in `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9` and the return value in `RAX` (Chapter 3, section 3.6). It is efficient, well-documented, and universal on 64-bit Unix systems.

Go deliberately chose a different path for several reasons:

- **Multiple return values.** In Go, a function can return multiple values (`result, err`). The System V convention only provides `RAX` and `RDX` for returns. Go needed a more flexible mechanism.  
- **Growable stacks.** The stack growth mechanism (section 34.1) requires being able to copy an entire stack, including call frames. If arguments are in registers, they are not on the stack and are not copied automatically — this complicates the runtime.  
- **Compiler portability.** The Go team favored a single, simple convention across all architectures, rather than adapting the compiler to each platform ABI's quirks.  
- **Simplicity of the original compiler.** The Go compiler (originally derived from Plan 9) did not have a sophisticated register allocator. Passing everything through the stack was simpler to implement.

These reasons were valid in the language's early days, but performance eventually justified a migration. In 2021, Go 1.17 introduced a register-based ABI — initially on amd64 only, then extended to arm64 in Go 1.18.

---

## The Old Convention: Everything on the Stack (Go < 1.17)

### Principle

Before Go 1.17, **all** arguments and **all** return values were passed on the stack. The caller pushes arguments from right to left (like `cdecl`), calls the function, and retrieves the return values from reserved slots on the stack above the arguments.

### Stack Frame Layout

For a call `result, err := myFunction(a, b, c)`:

```
Increasing addresses ↑

┌─────────────────────────┐
│   err (return 2)        │  ← RSP + 40  (reserved by the caller)
├─────────────────────────┤
│   result (return 1)     │  ← RSP + 32  (reserved by the caller)
├─────────────────────────┤
│   c (argument 3)        │  ← RSP + 24
├─────────────────────────┤
│   b (argument 2)        │  ← RSP + 16
├─────────────────────────┤
│   a (argument 1)        │  ← RSP + 8
├─────────────────────────┤
│   return address        │  ← RSP (pushed by CALL)
└─────────────────────────┘
```

Note several major differences from System V:

- **No `RBP` frame pointer.** Go does not use a `push rbp; mov rbp, rsp` prologue. The frame pointer was optionally reintroduced later (Go 1.7, `-buildmode` flag), but is not systematic. The absence of `RBP` complicates stack unwinding in GDB — this is why Go provides its own stack metadata via `gopclntab`.  
- **No red zone.** Unlike System V which reserves 128 bytes below `RSP`, Go does not use a red zone.  
- **The caller reserves space for returns.** Return values are written by the callee directly into pre-allocated slots on the caller's stack frame. This is how Go natively handles multiple returns.  
- **The caller cleans the stack.** After the return, the caller adjusts `RSP` to pop the arguments and returns.

### Assembly Example (Old ABI)

Go code:

```go
func add(x int, y int) int {
    return x + y
}

func caller() {
    r := add(10, 20)
    _ = r
}
```

Generated assembly (Go ≤ 1.16, simplified):

```asm
; --- caller ---
; Stack check preamble omitted for clarity
SUB     RSP, 24                ; reserve 24 bytes: 2 args (16) + 1 return (8)  
MOV     QWORD PTR [RSP], 10   ; argument x = 10  
MOV     QWORD PTR [RSP+8], 20 ; argument y = 20  
CALL    main.add  
MOV     RAX, [RSP+16]         ; retrieve the return value  
ADD     RSP, 24                ; clean the frame  
RET  

; --- add ---
MOV     RAX, [RSP+8]          ; x (first argument)  
ADD     RAX, [RSP+16]         ; y (second argument)  
MOV     [RSP+24], RAX         ; write the return in the slot reserved by the caller  
RET  
```

Key takeaways for RE:

- Arguments are accessible via positive offsets from `RSP` in the callee (accounting for the 8 bytes of the return address).  
- The return value is written at an even higher offset — just above the arguments.  
- `RAX` is **not** the return value. If you reflexively read `RAX` after a `CALL` as in C, you will get garbage.

> ⚠️ **Classic RE pitfall**: Ghidra's decompiler assumes the System V convention by default and interprets `RAX` as the return value. On an old ABI Go binary, the pseudo-code will be **wrong**. You will need to manually correct function signatures or use a Go plugin for Ghidra.

---

## The New Convention: Register-Based ABI (Go ≥ 1.17)

### Motivation

The stack-only ABI was simple but costly. Every function call involved numerous memory accesses to push and pop arguments. Google's internal benchmarks showed a 5 to 10% overhead on real programs. In 2021, the "register-based calling convention" proposal was adopted and deployed in Go 1.17.

### Registers Used

The new Go ABI defines two register sequences:

**Integer registers (arguments and returns):**

| Order | Register |  
|---|---|  
| 1 | `RAX` |  
| 2 | `RBX` |  
| 3 | `RCX` |  
| 4 | `RDI` |  
| 5 | `RSI` |  
| 6 | `R8` |  
| 7 | `R9` |  
| 8 | `R10` |  
| 9 | `R11` |

**Floating-point registers (arguments and returns):**

| Order | Register |  
|---|---|  
| 1 | `X0` |  
| 2 | `X1` |  
| … | … |  
| 15 | `X14` |

Registers are assigned in order to arguments from left to right. The **same sequences** are used for return values, starting from the beginning. If registers are exhausted, remaining arguments spill onto the stack.

### Comparison with System V AMD64

| Aspect | System V AMD64 (C/C++) | Go register ABI (≥ 1.17) |  
|---|---|---|  
| 1st integer argument | `RDI` | `RAX` |  
| 2nd integer argument | `RSI` | `RBX` |  
| 3rd integer argument | `RDX` | `RCX` |  
| 4th integer argument | `RCX` | `RDI` |  
| 5th integer argument | `R8` | `RSI` |  
| 6th integer argument | `R9` | `R8` |  
| 1st return value | `RAX` | `RAX` |  
| 2nd return value | `RDX` | `RBX` |  
| Multiple returns (> 2) | Not native | Yes (continuing register sequence) |  
| Goroutine `g` register | — | `R14` (reserved) |  
| Frame pointer | `RBP` (optional) | `RBP` (optional, since Go 1.7) |  
| Red zone | 128 bytes | None |

Caution: both conventions start with `RAX` for the first return, which can create an illusion of compatibility. But the argument order differs completely. Never assume that `RDI` contains the first argument in Go.

> 💡 **RE tip**: a quick way to distinguish the ABI: in the old convention, the first significant instruction of a small function accesses `[RSP+8]` for its first argument. In the new one, it directly uses `RAX`.

### Reserved Registers

Certain registers are reserved by the runtime and are never used to pass arguments:

| Register | Reserved usage |  
|---|---|  
| `R14` | Pointer to the current goroutine (`g`) |  
| `RSP` | Stack pointer |  
| `RBP` | Frame pointer (when enabled) |  
| `R12`, `R13` | Reserved (may be used in future versions) |

`R14` is particularly important for RE: every function preamble accesses it for the stack check (`MOV RAX, [R14+0x10]`). It is a reliable marker that you are in Go code.

### Assembly Example (New ABI)

The same `add` code compiled with Go ≥ 1.17:

```asm
; --- caller ---
MOV     RAX, 10                ; argument x in RAX (register 1)  
MOV     RBX, 20                ; argument y in RBX (register 2)  
CALL    main.add  
; RAX now contains the return value
; (direct use, no longer need to read from the stack)

; --- add ---
; RAX = x (argument 1)
; RBX = y (argument 2)
ADD     RAX, RBX               ; RAX = x + y  
RET                             ; RAX = return value  
```

This is radically more compact. But for an example with multiple returns:

```go
func divide(a, b int) (int, error) { ... }
```

```asm
; After CALL main.divide:
;   RAX = quotient (return 1, integer → integer register 1)
;   RBX = error    (return 2, interface → integer registers 2 and 3)
; Note: a Go interface occupies 2 words (type pointer + data pointer),
; so error consumes RBX and RCX.
```

### The Spill Zone

Even with the register ABI, Go maintains a "spill zone" on the stack. Upon entering a function, the compiler may copy (spill) some argument registers onto the stack. This is necessary for:

- runtime calls that might need to find arguments on the stack (GC, stack growth),  
- situations where the compiler runs out of registers (register pressure),  
- debugging (spilled arguments are visible in stack traces).

In assembly, you will often see this pattern right after the stack check preamble:

```asm
; Spilling register arguments to the stack
MOV     [RSP+offset1], RAX     ; save arg1  
MOV     [RSP+offset2], RBX     ; save arg2  
; ... function body ...
```

> 💡 **RE tip**: these spill instructions at the beginning of a function give you a valuable clue about the number and order of arguments, even if the decompiler does not reconstruct them correctly. Count the consecutive `MOV [RSP+...], register` instructions right after the stack preamble: each one likely corresponds to a function argument.

---

## The Case of Structures and Interfaces

### Passing Structures

Small structures whose fields are all simple types are "decomposed" and passed field by field in registers:

```go
type Point struct {
    X int
    Y int
}

func distance(p Point) float64 { ... }
```

Here, `p.X` will go into `RAX` and `p.Y` into `RBX`, as if the function had two `int` arguments. In RE, the structure is not visible as such in the registers — you see two independent integers.

Large structures or those containing complex types (pointers, slices, interfaces) are passed by implicit pointer.

### Passing Interfaces

A Go interface is a pair of two pointers (16 bytes on amd64):

```
┌───────────────────┐
│  itable pointer   │  → points to the itab (method table + type)
├───────────────────┤
│  data pointer     │  → points to the concrete data
└───────────────────┘
```

When an interface is passed as an argument, it consumes **two consecutive registers**:

```asm
; Calling a function accepting a Validator interface (section 34.3)
; RAX = itable pointer
; RBX = data pointer
CALL    main.runValidator
```

This is a critical point for RE: if you see a function that seems to receive a "mysterious pointer" in `RAX` followed by another in `RBX`, think of an interface. Method dispatch will then go through the itab (see section 34.3).

For error returns in Go — the `(result, error)` pattern — the same principle applies: `error` is an interface and consumes two return registers.

---

## Variadic Functions and Closures

### Variadic Functions

In Go, variadic functions (`func f(args ...int)`) receive a slice. The variadic parameter is transformed by the compiler into an argument of type `[]int`, which occupies three registers or three stack slots:

```asm
; f(1, 2, 3) with f(args ...int)
; The compiler creates an [3]int array on the stack, then passes a slice:
;   RAX = pointer to the array
;   RBX = length (3)
;   RCX = capacity (3)
CALL    main.f
```

### Closures

A Go closure is implemented as a pointer to a structure containing the function pointer and the captured variables:

```go
func makeAdder(n int) func(int) int {
    return func(x int) int {
        return x + n
    }
}
```

In assembly, the closure is a memory block whose first field is the pointer to the anonymous function's code, followed by the captured variables:

```
┌──────────────────┐
│  func pointer    │  → main.makeAdder.func1
├──────────────────┤
│  n (captured)    │  → value or pointer depending on escape analysis
└──────────────────┘
```

At the call site, the `RDX` register points to this closure structure (in the new ABI). The anonymous function accesses captured variables via dereferences relative to `RDX`:

```asm
; main.makeAdder.func1:
; RDX = pointer to the closure
; RAX = argument x
MOV     RCX, [RDX+8]          ; RCX = n (captured variable)  
ADD     RAX, RCX               ; return x + n  
RET  
```

> 💡 **RE tip**: the symbol of a Go closure follows the pattern `package.enclosingFunction.funcN` — for example `main.makeAdder.func1`. This naming is preserved in `gopclntab` and allows you to associate each closure with its parent function, even in a stripped binary.

---

## Identifying the ABI Version in an Unknown Binary

When facing a Go binary whose compiler version you do not know, here is how to determine which calling convention is used:

### Method 1 — Compiler Version

```bash
strings binaire | grep -oP 'go1\.\d+'
```

If the result is `go1.17` or higher, the register ABI is active on amd64. Otherwise, it is the old stack ABI.

### Method 2 — Assembly Inspection

Take a small identifiable function (for example `main.main` or a utility function) and observe how it accesses its arguments:

- **Old ABI**: the first memory accesses after the preamble read `[RSP+8]`, `[RSP+16]`, etc.  
- **New ABI**: the function body directly uses `RAX`, `RBX`, `RCX` without loading them from the stack (aside from possible spills).

### Method 3 — Internal Symbol `internal/abi`

Go binaries ≥ 1.17 contain symbols from the `internal/abi` package. Their presence in `gopclntab` or in strings is a reliable indicator:

```bash
strings binaire | grep 'internal/abi'
```

### Method 4 — Examining the `runtime.rt0_go` Prologue

The `runtime.rt0_go` code differs between versions. On recent versions, you will see instructions setting up `R14` as the `g` register early in the prologue — which does not exist before Go 1.17.

---

## Configuring Ghidra for the Go ABI

By default, Ghidra applies the System V convention to all functions. On a Go binary, this produces incorrect function signatures and misleading pseudo-code. A few adjustments:

### For the Old ABI (Stack)

1. Modify analyzed functions to use a custom "stack-only" convention.  
2. Manually define parameters as stack variables at the correct offsets.  
3. Mark the return value as being on the stack, not in `RAX`.

### For the New ABI (Registers)

1. The Go register sequence (`RAX`, `RBX`, `RCX`, `RDI`, `RSI`, `R8`, `R9`, `R10`, `R11`) does not match any Ghidra preset.  
2. For important functions, manually edit the signature in the Decompiler panel: right-click → *Edit Function Signature*, then assign the correct registers to parameters.  
3. Community scripts (such as those from the `go-re-ghidra` or `GoReSym` project) partially automate this work by applying correct signatures from `gopclntab` metadata.

> 💡 **RE tip**: do not try to correct the calling convention of *all* functions. Focus on functions in the `main.*` package and business packages. Leaving `runtime.*` functions with incorrect signatures is acceptable — you generally do not need to decompile them cleanly.

---

## Comparative Summary

| Characteristic | Go old ABI (< 1.17) | Go new ABI (≥ 1.17) | System V AMD64 (C) |  
|---|---|---|---|  
| Integer arguments | Stack only | `RAX`, `RBX`, `RCX`, `RDI`, `RSI`, `R8`-`R11` | `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9` |  
| Returns | Stack only | `RAX`, `RBX`, `RCX`, `RDI`, `RSI`, `R8`-`R11` | `RAX`, `RDX` |  
| Multiple returns | Native (via stack) | Native (via registers) | Not native |  
| Frame pointer | Absent (then optional) | Optional (`RBP`) | `RBP` (conventional) |  
| `g` register (goroutine) | TLS | `R14` | — |  
| Red zone | No | No | 128 bytes |  
| Caller-cleanup | Yes | Yes | Yes |  
| Spill zone | — | Yes (arguments copied to stack) | — |

---

## Key Takeaways

1. **Never assume System V.** As soon as you identify a Go binary, forget `RDI`/`RSI` as arguments and `RAX` as the sole return (except for the coincidence with the new ABI for the first return).  
2. **Identify the compiler version** first. The `go1.XX` string in the binary's strings determines the applicable ABI.  
3. **Multiple returns are normal.** A `(int, error)` potentially consumes 3 return registers (one for the int, two for the error interface).  
4. **Count the spills.** The `MOV [RSP+...], REG` instructions at the beginning of a function reveal the number of arguments.  
5. **Interfaces consume two registers.** Each parameter or return of interface type "costs" two slots in the register sequence.  
6. **Adapt Ghidra.** Manually correct the signatures of key functions, or use the automated tools described in section 34.4.

⏭️ [Go Data Structures in Memory: slices, maps, interfaces, channels](/34-re-go/03-data-structures-memory.md)
