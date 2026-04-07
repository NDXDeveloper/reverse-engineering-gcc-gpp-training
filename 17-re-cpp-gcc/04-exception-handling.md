🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.4 — Exception handling (`.eh_frame`, `.gcc_except_table`, `__cxa_throw`)

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## Why exceptions are complex in RE

C++ exceptions are the hardest mechanism to follow in disassembly. Unlike `if`/`else` and loops, which translate to visible conditional jumps in the control flow, exceptions create an **invisible control flow**: when a `throw` executes, execution jumps directly to the matching `catch`, potentially several stack frames up, unwinding the stack and calling destructors of all local objects along the way. None of this appears as `jmp` or `call` instructions in the assembly listing.

This invisible flow is orchestrated by two actors:

1. **The C++ runtime** (`__cxa_*` functions in `libstdc++` and `libgcc`) that implements the mechanics of throwing, propagating, and catching exceptions.  
2. **Compiler-generated metadata** (`.eh_frame` and `.gcc_except_table` sections) describing, for each instruction in the program, what to do if an exception occurs: which destructor to call, which `catch` matches, how to restore registers.

For the reverse engineer, the consequence is twofold. On one hand, the `throw` → `catch` flow is practically invisible in a classic disassembler (objdump shows nothing of this mechanism). On the other hand, exception metadata contain valuable information: they indicate which functions can throw exceptions, which types are intercepted, and which code ranges are protected by a `try`.

## GCC's "zero-cost" model

GCC uses the **zero-cost exception handling** model (also called *table-driven*). The principle is that the normal execution path (when no exception is thrown) pays **no cost**: no extra instructions, no reserved registers, no comparisons. All overhead is transferred to the exceptional path and to static metadata stored in the binary.

Concretely:

- **No visible `try` in assembly.** A `try` block generates no instructions. It's defined solely by an address range in the metadata tables.  
- **`throw` is a function call.** It calls `__cxa_allocate_exception` then `__cxa_throw`, two runtime functions.  
- **`catch` is a "landing pad."** It's a code block in the function not reachable by normal control flow. It's referenced only by the metadata tables.  
- **Stack unwinding** is driven by `.eh_frame` tables, which describe how to restore registers and the stack pointer frame by frame.

This model contrasts with Windows' older model (SEH, *Structured Exception Handling*) where structures are explicitly pushed onto the stack at each `try` entry.

## The `__cxa_*` runtime functions

GCC's C++ runtime (`libstdc++` and `libgcc`) provides a set of functions whose `__cxa_` prefix identifies the C++ ABI. Here are those a reverse engineer encounters most often.

### `__cxa_allocate_exception`

```c
void* __cxa_allocate_exception(size_t thrown_size);
```

Allocates memory for the exception object on a dedicated exception heap (not the general heap). The `thrown_size` argument is the exception object's size. The returned pointer is the space where the exception object will be constructed.

In assembly:

```nasm
mov    edi, 48                        ; size of AppException object  
call   __cxa_allocate_exception@plt  
; rax = pointer to allocated memory for the exception
```

> 💡 **In RE:** the value passed in `edi` is the exception class's size. This directly gives you the thrown object's `sizeof`, which helps reconstruct the exception class structure.

### `__cxa_throw`

```c
void __cxa_throw(void* thrown_exception, std::type_info* tinfo, void (*dest)(void*));
```

Throws the exception. This function **never returns** — it triggers stack unwinding. Its three arguments are:

| Argument | Register | Meaning |  
|----------|----------|---------|  
| `thrown_exception` | `rdi` | Pointer to the exception object (returned by `__cxa_allocate_exception`) |  
| `tinfo` | `rsi` | Pointer to the exception type's `_ZTI` structure |  
| `dest` | `rdx` | Pointer to the exception object's destructor (or `nullptr`) |

In assembly, the complete sequence of a `throw AppException("msg", 42)` looks like:

```nasm
; 1. Allocate space for the exception
mov    edi, 48  
call   __cxa_allocate_exception@plt  
mov    rbx, rax                       ; save the pointer  

; 2. Construct the exception object in the allocated space
mov    rdi, rbx                       ; this = allocated space  
lea    rsi, [rip+.LC_msg]            ; "msg"  
mov    edx, 42                        ; code  
call   AppException::AppException(std::string const&, int)  

; 3. Throw the exception
mov    rdi, rbx                       ; exception object  
lea    rsi, [rip+_ZTI12AppException]  ; typeinfo → identifies the type  
lea    rdx, [rip+_ZN12AppExceptionD1Ev] ; exception destructor  
call   __cxa_throw@plt  
; ← flow NEVER returns here
```

> 💡 **Crucial RE pattern:** the sequence `__cxa_allocate_exception` → construction → `__cxa_throw` identifies a `throw`. The second argument of `__cxa_throw` (in `rsi`) points to the `_ZTI` giving the exact type of the thrown exception. The third argument (in `rdx`) is the class destructor, providing yet another link to the class hierarchy.

### `__cxa_begin_catch`

```c
void* __cxa_begin_catch(void* exception_object);
```

Called at the beginning of a `catch` block. It marks the exception as "being handled" and returns a pointer to the exception object. This pointer is then used in the catch body to access exception members (e.g., `e.what()`, `e.code()`).

```nasm
; Start of a landing pad (catch)
mov    rdi, rax                       ; rax contains the propagated exception  
call   __cxa_begin_catch@plt  
; rax = pointer to exception object
; Catch code follows...
mov    rdi, rax  
call   AppException::what() const     ; use the exception  
```

### `__cxa_end_catch`

```c
void __cxa_end_catch();
```

Called at the end of a `catch` block. It destroys the exception object (if the reference count reaches 0) and cleans up the runtime state. If not called, the runtime leaks exceptions.

```nasm
; End of catch block
call   __cxa_end_catch@plt
; Execution continues normally after the try/catch
```

### `__cxa_rethrow`

```c
void __cxa_rethrow();
```

Rethrows the exception currently being handled (the `throw;` without argument). Never returns.

### `__cxa_get_exception_ptr`

```c
void* __cxa_get_exception_ptr(void* exception_object);
```

Returns a pointer to the exception object without modifying runtime state. Used in certain exception copy scenarios.

### `_Unwind_Resume`

```c
void _Unwind_Resume(struct _Unwind_Exception* exception_object);
```

A `libgcc` function (not `libstdc++`) that resumes stack unwinding. It's called when a landing pad (cleanup code or `catch`) can't handle the exception and must propagate it higher up the stack. In assembly, you'll see it after destructor calls in a cleanup landing pad:

```nasm
; Cleanup landing pad: destroy local objects then propagate
mov    rdi, rax                       ; exception object
; ... call destructors of local variables ...
call   _Unwind_Resume@plt
; ← never returns
```

> 💡 **In RE:** `_Unwind_Resume` marks the end of a cleanup landing pad (not a `catch`, but a cleanup that destroys local objects). If you see `_Unwind_Resume` in a function, the function contains objects with automatic storage duration that require cleanup on exception (typically `std::string`, `std::vector`, smart pointers, etc.).

## Exception flow overview

Here's the complete path of an exception from `throw` to `catch`, as GCC's runtime executes it:

```
Source code:                       What happens in the binary:

                                   ┌────────────────────────────────┐
throw AppException("x", 1);  ──→   │ __cxa_allocate_exception(48)   │
                                   │ AppException::AppException()   │
                                   │ __cxa_throw(obj, _ZTI, dtor)   │
                                   └───────────┬────────────────────┘
                                               │ (does not return)
                                               ▼
                                   ┌────────────────────────────────┐
                                   │ Phase 1: Search                │
                                   │ _Unwind_RaiseException()       │
                                   │ walks .eh_frame to go up       │
                                   │ through frames                 │
                                   │ consults .gcc_except_table     │
                                   │ to find a catch matching       │
                                   │ the _ZTI type                  │
                                   └───────────┬────────────────────┘
                                               │
                                               ▼
                                   ┌────────────────────────────────┐
                                   │ Phase 2: Cleanup               │
                                   │ re-unwinds the stack frame     │
                                   │ by frame, executes cleanup     │
                                   │ landing pads (dtors),          │
                                   │ restores registers             │
                                   └───────────┬────────────────────┘
                                               │
                                               ▼
                                   ┌────────────────────────────────┐
catch (const AppException& e)  ──→ │ Catch landing pad:             │
                                   │ __cxa_begin_catch(obj)         │
                                   │ ... catch body ...             │
                                   │ __cxa_end_catch()              │
                                   └────────────────────────────────┘
```

The runtime proceeds in two phases: first a **search phase** that goes up the stack without modifying it to find a compatible handler, then a **cleanup phase** that actually unwinds the stack, calls destructors, and transfers control to the `catch` landing pad.

## The `.eh_frame` section

The `.eh_frame` section contains stack unwinding information (*unwind information*). It's encoded in **DWARF Call Frame Information (CFI)** format, the same format debuggers use to walk the call stack. It's present even in C (GCC uses it for `__attribute__((cleanup))` and debuggers) but it's indispensable in C++ for exceptions.

### `.eh_frame` structure

`.eh_frame` is composed of two types of entries:

**CIE (Common Information Entry)** — shared between multiple functions with similar unwinding properties. Contains:  
- The format version  
- The augmentation string (indicates extensions, like the presence of a pointer to `.gcc_except_table`)  
- Code and data alignment  
- The return address register  
- Initial CFI instructions (default register state at function start)

**FDE (Frame Description Entry)** — one per function (or per code range). Contains:  
- The start address and length of the described code range  
- A pointer to the parent CIE  
- An optional pointer to the **LSDA** (Language-Specific Data Area) in `.gcc_except_table`  
- Function-specific CFI instructions (how registers evolve instruction by instruction)

CFI instructions are a mini bytecode language describing, for each code point, how to find the previous stack pointer and saved registers. The unwinder interprets these instructions to go up the stack frame by frame.

### Visualizing `.eh_frame`

```bash
# Display raw .eh_frame content
$ readelf --debug-dump=frames oop_O0

# More readable version with CFI instruction decoding
$ readelf --debug-dump=frames-interp oop_O0
```

A typical output excerpt:

```
00000098 0000002c 0000009c FDE cie=00000000 pc=0000000000401a2c..0000000000401b14
  Augmentation data: Pointer to LSDA = 0x00403120
  DW_CFA_advance_loc: 1 to 0000000000401a2d
  DW_CFA_def_cfa_offset: 16
  DW_CFA_offset: r6 (rbp) at cfa-16
  DW_CFA_advance_loc: 3 to 0000000000401a30
  DW_CFA_def_cfa_register: r6 (rbp)
  ...
```

Key points for RE:

- The range `pc=0x401a2c..0x401b14` identifies the covered function.  
- **`Pointer to LSDA`** is the link to `.gcc_except_table` — if this pointer is non-null, the function has `try/catch` blocks or objects requiring cleanup on exception.  
- `DW_CFA_*` instructions describe how to restore registers. They're generally not needed for exception RE, but they're used by GDB for backtrace.

> 💡 **In RE:** if an FDE has a non-null LSDA pointer, the corresponding function contains `try/catch` blocks or local objects with destructors. If the LSDA pointer is null (or the FDE has no augmentation), the function doesn't handle exceptions locally — if an exception passes through, the stack is simply unwound with no special action.

## The `.gcc_except_table` section

This is where the most interesting information for the reverse engineer resides. The `.gcc_except_table` (also called **LSDA**, *Language-Specific Data Area*) contains, for each function that handles exceptions, the following tables:

### LSDA structure

Each LSDA starts with a header followed by three tables:

```
LSDA Header:
┌─────────────────────────────────────────────┐
│  @LPStart encoding (1 byte)                 │  How landing pad addresses are encoded
├─────────────────────────────────────────────┤
│  @LPStart (variable, if encoding ≠ omit)    │  Base for landing pad addresses
├─────────────────────────────────────────────┤
│  @TType encoding (1 byte)                   │  How types are encoded
├─────────────────────────────────────────────┤
│  @TType base offset (ULEB128, if enc ≠ omit)│  Offset to end of type table
├─────────────────────────────────────────────┤
│  Call site encoding (1 byte)                │  How call site entries are encoded
├─────────────────────────────────────────────┤
│  Call site table length (ULEB128)           │  Size of call site table in bytes
├═════════════════════════════════════════════╡
│  Call Site Table                            │  (see below)
├═════════════════════════════════════════════╡
│  Action Table                               │  (see below)
├═════════════════════════════════════════════╡
│  Type Table (read backwards)                │  (see below)
└─────────────────────────────────────────────┘
```

### The Call Site Table

The call site table is the main table. Each entry describes an instruction range and what should happen if an exception is thrown during execution of that range:

| Field | Encoding | Meaning |  
|-------|----------|---------|  
| `cs_start` | offset | Range start (relative to function start) |  
| `cs_len` | length | Range length in bytes |  
| `cs_lp` | offset | **Landing pad** address (relative to `@LPStart`), or 0 if no handler |  
| `cs_action` | ULEB128 | Index into action table (1-indexed), or 0 for cleanup-only |

**Field interpretation:**

- If `cs_lp == 0`: no landing pad for this range. If an exception occurs here, unwinding continues to the caller frame.  
- If `cs_lp != 0` and `cs_action == 0`: there's a landing pad, but it's **cleanup only** (no `catch`). The landing pad calls destructors of local objects then calls `_Unwind_Resume` to propagate the exception.  
- If `cs_lp != 0` and `cs_action != 0`: there's a landing pad with one or more `catch` blocks. The action table describes which types are intercepted.

> 💡 **In RE:** the call site table tells you exactly which code ranges are in a `try` block. If `cs_start` to `cs_start + cs_len` covers instructions from `0x401a50` to `0x401a90`, it means a `try` block encompasses this code in the original source.

### The Action Table

The action table is an array of entries, each composed of two SLEB128-encoded fields:

| Field | Meaning |  
|-------|---------|  
| `ar_filter` | Index into the type table (1-indexed). Positive = `catch` of this type. 0 = cleanup. Negative = exception specification filter. |  
| `ar_disp` | Displacement to the next action in the chain (in bytes), or 0 if this is the last action. |

Actions are chained: if `ar_disp` is non-zero, there's a next handler to check (for multiple `catch` blocks in the same `try`). The runtime walks the chain until it finds a matching type or reaches the end.

**Example — a `try` with three `catch` blocks:**

```cpp
try {
    // ...
} catch (const ParseError& e) {     // action #1: type index 3
    // ...
} catch (const AppException& e) {   // action #2: type index 2
    // ...
} catch (const std::exception& e) { // action #3: type index 1
    // ...
}
```

The action chain would be:

```
Action #1: ar_filter = 3, ar_disp = → action #2  
Action #2: ar_filter = 2, ar_disp = → action #3  
Action #3: ar_filter = 1, ar_disp = 0 (end of chain)  
```

The runtime tests `ParseError` first, then `AppException`, then `std::exception` — in source code order. The order matters because `ParseError` inherits from `AppException` which inherits from `std::exception`: a `catch(std::exception&)` first would catch all exceptions.

### The Type Table

The type table contains pointers to the `_ZTI` (typeinfo) structures of types intercepted by `catch` blocks. It's read **backwards** from the `@TType base` address: index 1 is the last element, index 2 is the second-to-last, etc.

```
@TType base (end of type table):
  ...
  [index 3] → _ZTI10ParseError        (typeinfo address)
  [index 2] → _ZTI12AppException
  [index 1] → _ZTISt9exception
```

> 💡 **In RE:** the type table tells you which exception types are intercepted in the function. By resolving pointers to the `_ZTI`s, you get exception class names via `_ZTS` strings. This reveals which error types the developer planned to handle, which is high-level information about the program's logic.

### Visualizing `.gcc_except_table`

Unfortunately, there's no standard tool that cleanly decodes `.gcc_except_table` as readably as `readelf` does for `.eh_frame`. Here are the available options:

```bash
# Raw section dump
$ readelf -x .gcc_except_table oop_O0

# With objdump (hexadecimal)
$ objdump -s -j .gcc_except_table oop_O0

# Dedicated tool: dwarfdump (if installed)
$ dwarfdump --eh-frame oop_O0
```

In practice, the reverse engineer often uses Ghidra or a Python script to parse the LSDA. The ULEB128/SLEB128 encodings and relative pointers make manual decoding tedious but not impossible.

**In Ghidra:** the `.gcc_except_table` section appears in the Memory Map. Ghidra doesn't automatically decode it into readable structures, but the decompiler takes it into account for certain analyses. You can create a Ghidra script that parses LSDA entries and annotates landing pads in the listing.

## Landing pads in assembly

A landing pad is the entry point for exception handling code in a function. It's the address the runtime transfers control to after stack unwinding. There are two types.

### Catch landing pad

A `catch` landing pad always starts with a call to `__cxa_begin_catch`:

```nasm
; Landing pad for catch (const AppException& e)
.L_catch_AppException:
    mov    rdi, rax                       ; rax = exception object (passed by runtime)
    call   __cxa_begin_catch@plt
    mov    rbx, rax                       ; rbx = pointer to AppException

    ; --- Catch body ---
    mov    rdi, rbx
    call   AppException::what() const     ; e.what()
    mov    rsi, rax
    lea    rdi, [rip+.LC_format]
    call   printf@plt

    ; --- End of catch ---
    call   __cxa_end_catch@plt
    jmp    .L_after_try_catch             ; continue after try/catch
```

The `rax` register contains the pointer to the exception object when entering the landing pad. This is a convention of the unwinding runtime: the register is defined by CFI instructions in `.eh_frame`.

> 💡 **In RE:** to find landing pads in a function, search for calls to `__cxa_begin_catch`. Each call corresponds to a `catch`. The code between `__cxa_begin_catch` and `__cxa_end_catch` is the catch body. If the landing pad ends with a `jmp` to the code following the try/catch, it's a normal catch. If it ends with `__cxa_rethrow`, it's a `throw;` (rethrow).

### Cleanup landing pad

A cleanup landing pad doesn't intercept the exception — it executes destructors of local objects then propagates the exception upward:

```nasm
; Cleanup landing pad: destroy a local std::string
.L_cleanup:
    mov    rbx, rax                       ; save the exception
    lea    rdi, [rbp-0x40]               ; address of local string
    call   std::string::~basic_string()   ; destructor
    mov    rdi, rbx                       ; restore the exception
    call   _Unwind_Resume@plt            ; propagate
```

The pattern is: save the exception, call one or more destructors, then call `_Unwind_Resume`.

> 💡 **In RE:** a landing pad that doesn't contain `__cxa_begin_catch` but ends with `_Unwind_Resume` is a cleanup. The presence of cleanups indicates the function constructs local objects with automatic storage duration (RAII) — typically `std::string`, `std::vector`, smart pointers, lock guards, etc. The number and type of destructors called in the cleanup give you clues about the function's local variables.

### Multiple landing pads in a function

A function can have multiple landing pads if it contains:
- Multiple `catch` blocks for the same `try` (one landing pad per `catch`, or a single one with internal dispatch).  
- Multiple nested or sequential `try` blocks.  
- Local objects requiring cleanup at different points in the function.

In the disassembly, landing pads often appear **after** the function's normal code (after the final `ret` or `jmp`), in a code area not reachable by ordinary control flow. This is a useful visual signature: code after a function's `ret`, starting by manipulating `rax` and calling `__cxa_begin_catch` or `_Unwind_Resume`, is a landing pad.

## The complete `throw` → `catch` sequence in the binary

Let's bring all elements together by following an exception end to end in our binary. Take the case of constructing a `Circle` with a negative radius:

```cpp
// In Circle::Circle(), if r <= 0:
throw AppException("Invalid radius", 10);

// Caught higher up in main():
catch (const AppException& e) {
    std::cerr << e.what() << " (code " << e.code() << ")" << std::endl;
    return 1;
}
```

**Step 1 — `throw` in `Circle::Circle()`:**

```nasm
; Circle::Circle() — radius check
    ucomisd xmm2, xmm3               ; compare r with 0.0
    ja     .radius_ok                  ; if r > 0, continue

    ; r <= 0: throw exception
    mov    edi, 48                     ; sizeof(AppException)
    call   __cxa_allocate_exception@plt
    mov    rbx, rax

    mov    rdi, rbx                    ; this = exception space
    lea    rsi, [rip+.LC_invalid_radius] ; "Invalid radius"
    mov    edx, 10                     ; code = 10
    call   _ZN12AppExceptionC1ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEi

    mov    rdi, rbx
    lea    rsi, [rip+_ZTI12AppException]
    lea    rdx, [rip+_ZN12AppExceptionD1Ev]
    call   __cxa_throw@plt
    ; ← flow doesn't return here
```

**Step 2 — The runtime takes control:**

`__cxa_throw` calls `_Unwind_RaiseException` (from `libgcc`), which consults `.eh_frame` to find the FDE for `Circle::Circle()`. If the FDE has an LSDA, the runtime consults `.gcc_except_table` for this function. If no handler matches (or there are only cleanups), the runtime goes up to the caller frame (the function that called `Circle::Circle()`), and so on.

**Step 3 — Intermediate cleanups:**

If intermediate frames contain local objects to destroy, their cleanup landing pads are executed. For example, if `Circle::Circle()` was called from a function that had constructed a local `std::string`, that string's cleanup is executed before going further up.

**Step 4 — Arrival at `catch` in `main()`:**

The runtime finds `main()`'s LSDA, walks the call site table, finds the range containing the call to `Circle::Circle()`, checks the action table, and determines that the `AppException` type matches the `catch`. It transfers control to the landing pad:

```nasm
; Landing pad in main()
.L_catch_AppException:
    mov    rdi, rax
    call   __cxa_begin_catch@plt
    mov    rbx, rax                    ; rbx = AppException*

    ; Catch body: e.what()
    mov    rdi, rbx
    call   _ZNK12AppException4whatEv   ; AppException::what() const
    mov    rsi, rax
    ; ... print the message ...

    ; e.code()
    mov    rdi, rbx
    mov    eax, DWORD PTR [rbx+0x28]  ; direct access to code_ field (known offset)

    ; ... print the code ...

    call   __cxa_end_catch@plt
    mov    eax, 1                      ; return 1
    jmp    .L_main_epilogue
```

## Recognizing `try`/`catch` without metadata

Even without parsing `.gcc_except_table`, a reverse engineer can spot `try`/`catch` blocks by observing patterns in the disassembly:

**Signs of a `throw`:**  
- Call to `__cxa_allocate_exception` followed by a constructor then `__cxa_throw`.  
- `__cxa_throw` is often the last call before unreachable code or a landing pad.

**Signs of a `catch`:**  
- Call to `__cxa_begin_catch` followed by handling code then `__cxa_end_catch`.  
- Catch code is often located after the normal flow (after the function's `ret`), in an area reachable only via the exception runtime.

**Signs of cleanup (RAII):**  
- Code that saves `rax`, calls one or more destructors, then calls `_Unwind_Resume`.  
- Often located after normal code, like catches.

**Signs of a `try` (without parsing tables):**  
- Harder to identify. Function calls located between the function start and the first landing pad are probably in a `try` block, especially if the function contains catches.  
- Ghidra sometimes reconstructs `try`/`catch` blocks in the decompiler, displaying them as pseudo-instructions `try`/`catch`.

## Impact of `-fno-exceptions`

The `-fno-exceptions` flag completely disables C++ exception support. The resulting binary:

- Contains no `.gcc_except_table`.  
- May still contain `.eh_frame` (for debuggers), but without LSDA pointers.  
- Contains no calls to `__cxa_throw`, `__cxa_begin_catch`, `__cxa_end_catch`, `_Unwind_Resume`.  
- Contains no landing pads.  
- `throw` causes a compilation error.  
- `try`/`catch` causes a compilation error.

In RE, the total absence of these symbols in the PLT and of the `.gcc_except_table` section confirms the binary was compiled with `-fno-exceptions`.

> ⚠️ **Warning:** some projects disable exceptions but use libraries that enable them (like `libstdc++`). In that case, you'll see `__cxa_*` symbols in dynamic dependencies but no direct use in the binary's code.

## Impact of optimization levels

GCC optimizations affect exceptions in several ways:

**In `-O0`:** the code is faithful to the source. Each `throw`, `catch`, and cleanup is clearly separated. Landing pads are easy to identify.

**In `-O2` / `-O3`:**  
- GCC can **eliminate dead code** after a `throw` (since `__cxa_throw` never returns).  
- Destructors in cleanups can be **inlined**, making landing pads longer and less recognizable.  
- If GCC proves an exception can't be thrown in a range, it can **remove the corresponding landing pad** and call site entry.  
- `catch(...)` (catch-all) can be optimized differently.  
- Functions declared `noexcept` allow GCC to remove cleanups for calls to those functions.

**The `noexcept` attribute:** functions declared `noexcept` don't generate landing pads for calls they contain. If an exception nonetheless escapes a `noexcept` function, the runtime calls `std::terminate()`. In RE, if you see a call to `std::terminate` in a landing pad (instead of `_Unwind_Resume` or `__cxa_begin_catch`), it's the sign of a `noexcept` violation:

```nasm
; noexcept violation handler
.L_noexcept_violation:
    call   std::terminate@plt         ; terminates the program
```

## Summary of patterns to recognize

| Assembly pattern | Meaning |  
|------------------|---------|  
| `call __cxa_allocate_exception; ...; call __cxa_throw` | `throw ExceptionType(args)` |  
| `rsi` argument of `__cxa_throw` = `lea [_ZTI...]` | Type of thrown exception (typeinfo) |  
| `rdx` argument of `__cxa_throw` = `lea [_ZN...D1Ev]` | Exception class destructor |  
| `edi` argument of `__cxa_allocate_exception` = constant | `sizeof(ExceptionClass)` |  
| `call __cxa_begin_catch; ...; call __cxa_end_catch` | `catch` block |  
| Code after `ret` containing `__cxa_begin_catch` | Catch landing pad |  
| Code saving `rax`, calling dtors, then `_Unwind_Resume` | Cleanup landing pad (RAII) |  
| `call __cxa_rethrow` | `throw;` (rethrow in a catch) |  
| `call std::terminate` in a landing pad | `noexcept` violation |  
| FDE with non-null LSDA pointer in `.eh_frame` | Function containing try/catch or cleanups |  
| Absence of `.gcc_except_table` and `__cxa_*` in PLT | Binary compiled with `-fno-exceptions` |

---


⏭️ [STL internals: `std::vector`, `std::string`, `std::map`, `std::unordered_map` in memory](/17-re-cpp-gcc/05-stl-internals.md)
