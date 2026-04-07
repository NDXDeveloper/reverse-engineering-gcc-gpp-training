🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 33.3 — Recognizing Rust Patterns: `Option`, `Result`, `match`, panics

> 🔍 When symbols are absent, the ability to recognize idiomatic Rust constructs directly in the assembly becomes the analyst's main asset. This section catalogs the most frequent patterns — those you will encounter in virtually every Rust binary — and teaches you to identify them without hesitation.

---

## The Fundamental Principle: Rust Enums Are Tagged Unions

Before diving into the assembly, you need to understand the underlying memory model. In Rust, `Option<T>`, `Result<T, E>`, and all user-defined `enum`s share the same memory representation: a **tagged union** (or discriminated union).

```rust
enum Option<T> {
    None,    // discriminant = 0
    Some(T), // discriminant = 1
}

enum Result<T, E> {
    Ok(T),   // discriminant = 0
    Err(E),  // discriminant = 1
}
```

In memory, the compiler allocates:

```
┌────────────────┬──────────────────────────┐
│  Discriminant  │  Payload (T or E)        │
│  (tag)         │                          │
│  1 to 8 bytes  │  size of the largest     │
│                │  variant                 │
└────────────────┴──────────────────────────┘
```

The discriminant (or "tag") is an integer that indicates which variant is active. Its size depends on the number of variants: 1 byte is enough for `Option` (2 variants) and `Result` (2 variants), but an `enum` with more than 256 variants would use 2 bytes, etc.

> 💡 **Niche optimization.** The Rust compiler exploits invalid values of a type to store the discriminant there. For example, `Option<&T>` has **no** separate tag: `None` is represented by a null pointer (`0x0`), and `Some(&T)` by the non-null pointer itself. Everything fits in 8 bytes instead of 16. Similarly, `Option<NonZeroU32>` encodes `None` as the value `0`. In RE, this means that a test on `Option<&T>` translates to a simple `test rdi, rdi` / `jz` — no explicit tag read. This is an extremely common pattern that you must know how to recognize.

---

## Pattern 1: `Option<T>` and the Discriminant Test

### General Case (no niche optimization)

For an `Option<u32>` for example, the compiler produces an 8-byte layout: 4 bytes of tag + 4 bytes of payload (or the reverse, depending on alignment). The variant test looks like this at `-O0`:

```nasm
; Option<u32> stored on the stack at [rbp-0x10]
; Layout: [rbp-0x10] = tag (4 bytes), [rbp-0x0C] = payload (4 bytes)

    mov     eax, dword [rbp-0x10]     ; Load the discriminant
    cmp     eax, 0                     ; 0 = None
    je      .handle_none
    ; Here the variant is Some — access the payload:
    mov     ecx, dword [rbp-0x0C]     ; Load the u32 value from Some
    ; ... use ecx ...
    jmp     .after_match

.handle_none:
    ; ... handle None ...

.after_match:
```

The recognizable pattern: **reading an integer, comparing to 0 (or 1), conditional branch, then accessing adjacent memory for the payload**. This is the signature of a `match` on an `Option` or any two-variant enum.

At `-O2` / `-O3`, LLVM often simplifies by merging the test and the branch:

```nasm
    cmp     dword [rbp-0x10], 0
    je      .handle_none
    mov     ecx, dword [rbp-0x0C]
```

### Case with Niche Optimization (`Option<&T>`, `Option<Box<T>>`)

For types where the value `0` is invalid (references, `Box`, `NonZero*`), the discriminant is the pointer itself:

```nasm
; Option<&str> — the fat pointer (ptr, len) is on the stack
; None = ptr is null

    mov     rax, qword [rbp-0x10]     ; Load the pointer
    test    rax, rax                   ; Test if null
    jz      .is_none
    ; Some — rax contains the valid pointer
    mov     rcx, qword [rbp-0x08]     ; Load the &str length
    ; ... use the &str ...
```

This `test reg, reg` / `jz` pattern is ubiquitous in Rust code. When you see a pointer tested against zero followed by a branch to panic code or an error path, it is almost certainly an `Option` with niche optimization.

> 🔑 **RE tip**: in Ghidra, search for XREFs to panic functions. Each XREF is potentially an `unwrap()` or `expect()` on an `Option` or `Result`. Following the XREF chain allows you to quickly locate the program's critical decision points.

---

## Pattern 2: `unwrap()` — the Branch to Panic

The `.unwrap()` call on an `Option` or `Result` translates in assembly to a discriminant test followed by a branch to a panic function on failure.

### `Option::unwrap()`

```rust
let value = some_option.unwrap();
```

Produces in assembly (optimized version):

```nasm
    test    rax, rax                    ; Test the discriminant / pointer
    jz      .panic_unwrap_none          ; If None → panic
    ; Normal continuation with the unwrapped value in rax
    ; ...

.panic_unwrap_none:
    ; Prepare arguments for the panic message
    lea     rdi, [rip + .Lstr_unwrap_msg]  ; "called `Option::unwrap()` on a `None` value"
    lea     rsi, [rip + .Lstr_location]     ; "src/main.rs:42:17"
    call    core::panicking::panic          ; Never returns
    ud2                                     ; Illegal instruction (hint: unreachable)
```

The recognizable elements:

1. **The test** (`test` / `cmp`) immediately before a conditional branch.  
2. **The call to `core::panicking::panic`** (or `core::panicking::panic_fmt` for formatted messages). Even on a stripped binary, the string `"called \`Option::unwrap()\` on a \`None\` value"` is in `.rodata` and identifiable via `strings`.  
3. **The `ud2` instruction** after the panic call. LLVM inserts this illegal instruction as a marker for unreachable code (the `panic` never returns). This is a very reliable visual indicator: if you see `ud2` after a `call`, the `call` in question is almost certainly a function that does not return (`noreturn`).

### `Result::unwrap()`

The pattern is identical, but the panic message differs:

```nasm
    cmp     byte [rbp-0x20], 0          ; Result discriminant: 0 = Ok, 1 = Err
    jne     .panic_unwrap_err           ; If Err → panic
    ; Normal continuation with the Ok value
    ; ...

.panic_unwrap_err:
    lea     rdi, [rip + .Lstr_result_msg]  ; "called `Result::unwrap()` on an `Err` value: ..."
    ; ...
    call    core::panicking::panic_fmt
    ud2
```

### `expect()` — the Variant with a Custom Message

The `.expect("message")` method produces the same pattern as `.unwrap()`, but the message in `.rodata` is the one provided by the developer:

```nasm
    lea     rdi, [rip + .Lstr_custom]   ; "Failed to parse the config file"
```

This custom message is an additional clue for the analyst: it often describes the developer's intent at that point in the code.

---

## Pattern 3: The `?` Operator (Error Propagation)

The `?` operator is the most commonly used syntactic sugar in Rust for propagating errors. It translates to a discriminant test on `Result` followed by an early return from the current function with the `Err` value.

```rust
fn parse_input(s: &str) -> Result<u32, String> {
    let value = s.parse::<u32>().map_err(|e| e.to_string())?;
    Ok(value * 2)
}
```

In assembly, the `?` produces:

```nasm
    ; Return from s.parse::<u32>() — Result<u32, ParseIntError> in [rsp+...]
    cmp     byte [rsp+0x20], 0           ; Test discriminant: 0 = Ok, 1 = Err
    jne     .propagate_error             ; If Err → propagate

    ; Ok path: extract the value and continue
    mov     eax, dword [rsp+0x24]        ; Ok payload (u32)
    shl     eax, 1                       ; value * 2
    ; Build the return Result::Ok
    mov     byte [rsp+0x30], 0           ; Tag = Ok
    mov     dword [rsp+0x34], eax        ; Payload = value * 2
    jmp     .return

.propagate_error:
    ; Err path: convert the error and propagate it
    ; ... call to map_err / to_string ...
    mov     byte [rsp+0x30], 1           ; Tag = Err
    ; Copy the Err payload into the return Result
    ; ...

.return:
    ; The Result is in [rsp+0x30], return to caller
    ret
```

The difference from `unwrap()` is crucial: **there is no call to `panic`**. The error path returns cleanly to the caller by constructing a `Result::Err`. It is an early return, not a crash.

> 🔑 **RE tip**: when you see a discriminant test followed by a `jmp` to the function epilogue (not to a `call panic`), it is probably a `?`. If the jump leads to a panic call, it is an `unwrap()` or `expect()`. This distinction tells you whether the developer chose to handle the error gracefully or to crash on failure.

---

## Pattern 4: `match` on a User-Defined Enum

Our crackme defines a `LicenseType` enum with three variants:

```rust
enum LicenseType {
    Trial { days_left: u32 },       // discriminant = 0
    Standard { seats: u32 },        // discriminant = 1
    Enterprise { seats: u32, support: bool },  // discriminant = 2
}
```

The exhaustive `match` on this enum translates to a **comparison cascade** or a **jump table** depending on the number of variants and the optimization level.

### Comparison Cascade (few variants, `-O0` to `-O2`)

```nasm
    ; The LicenseType discriminant is in eax (or on the stack)
    movzx   eax, byte [rbp-0x28]        ; Load the tag (1 byte is enough for 3 variants)
    
    test    eax, eax                     ; == 0? (Trial)
    je      .match_trial
    
    cmp     eax, 1                       ; == 1? (Standard)
    je      .match_standard
    
    cmp     eax, 2                       ; == 2? (Enterprise)
    je      .match_enterprise
    
    ; If we reach here, it's unreachable (the match is exhaustive)
    ud2

.match_trial:
    ; Access days_left: dword [rbp-0x24]
    mov     ecx, dword [rbp-0x24]
    test    ecx, ecx
    je      .trial_expired               ; days_left == 0
    mov     eax, 5                       ; return 5
    jmp     .match_end

.trial_expired:
    xor     eax, eax                     ; return 0
    jmp     .match_end

.match_standard:
    ; Access seats: dword [rbp-0x24]
    mov     eax, dword [rbp-0x24]
    add     eax, 10                      ; return 10 + seats
    jmp     .match_end

.match_enterprise:
    ; Access seats and support
    mov     eax, dword [rbp-0x24]        ; seats
    shl     eax, 1                       ; seats * 2
    add     eax, 50                      ; 50 + seats * 2
    movzx   ecx, byte [rbp-0x20]        ; support (bool)
    test    ecx, ecx
    je      .no_support
    add     eax, 100                     ; + 100 if support
.no_support:
    ; eax contains the result

.match_end:
    ; Code continues with the result in eax
```

The recognizable pattern: **a sequence of `cmp` / `je` on the same register or memory location, with consecutive values (0, 1, 2…)**. Each branch leads to a block that accesses the payload at a fixed offset from the enum base. This is exactly the structure of a C `switch`, and decompilation tools generally reconstruct it well.

### Jump Table (many variants, `-O2` / `-O3`)

When the enum has enough variants (typically ≥ 4), LLVM may choose to emit a jump table rather than a comparison cascade:

```nasm
    movzx   eax, byte [rbp-0x28]        ; Load the tag
    cmp     eax, 5                       ; Upper bound (number of variants - 1)
    ja      .unreachable                 ; Defense against invalid values
    lea     rcx, [rip + .Ljump_table]   ; Address of the jump table
    movsxd  rax, dword [rcx + rax*4]    ; Offset from the table
    add     rax, rcx                     ; Target address = table + offset
    jmp     rax                          ; Indirect jump

.Ljump_table:
    .long   .variant_0 - .Ljump_table
    .long   .variant_1 - .Ljump_table
    .long   .variant_2 - .Ljump_table
    ; ...
```

This pattern — `lea` to a table, `movsxd` indexed by the tag, `add`, indirect `jmp` — is the same as the one generated for an optimized C/C++ `switch`. Ghidra and IDA generally reconstruct it as a `switch-case` in the decompiler.

### Match on Ranges

Our crackme uses a `match` with value ranges in `determine_license`:

```rust
match value {
    0x0000..=0x00FF => LicenseType::Trial { days_left: 30 },
    0x0100..=0x0FFF => LicenseType::Standard { ... },
    0x1000..=0xFFFF => LicenseType::Enterprise { ... },
}
```

This pattern translates to **bounded comparisons**:

```nasm
    movzx   eax, word [rbp-0x0A]        ; value (u16)
    
    cmp     eax, 0xFF
    jbe     .range_trial                 ; 0x0000..=0x00FF
    
    cmp     eax, 0xFFF
    jbe     .range_standard              ; 0x0100..=0x0FFF (implicit: > 0xFF)
    
    ; Otherwise: 0x1000..=0xFFFF → Enterprise
    jmp     .range_enterprise
```

The `jbe` (jump if below or equal, unsigned comparison) or `jle` (signed) instructions on immediate constants reveal a match on ranges. The analyst can reconstruct the bounds directly from the immediate values.

---

## Pattern 5: Panics

Panics are ubiquitous in Rust code — even code that never explicitly calls them contains them, because the compiler inserts bounds checks on slice accesses, overflow tests in debug mode, and implicit `unwrap` code.

### Panic Functions

There are several panic functions in the Rust stdlib. The most common ones, ranked by frequency of occurrence:

| Function | Triggered by | Typical message in `.rodata` |  
|---|---|---|  
| `core::panicking::panic` | `unwrap()` on `None`, `panic!("message")` | The literal message or the standard unwrap message |  
| `core::panicking::panic_fmt` | `panic!("format {}", arg)`, `expect()`, `unwrap()` on `Err` | Formatted message with arguments |  
| `core::panicking::panic_bounds_check` | Array access `array[i]` with `i` out of bounds | `"index out of bounds: the len is {} but the index is {}"` |  
| `core::slice::index::slice_index_order_fail` | Slice `&arr[a..b]` with `a > b` | `"slice index starts at {} but ends at {}"` |

On a stripped binary, these functions no longer have names, but the associated strings in `.rodata` are still there. Searching for these strings with `strings` and then tracing the XREFs in the disassembler is the most reliable method for locating panic points.

### Recognizing a Panic Call in Assembly

All panic functions share a common trait: they are marked `#[cold]` and `-> !` (diverging, never return). LLVM places them in "cold" code blocks at the end of functions, and systematically inserts `ud2` after the call.

```nasm
; Main block ("hot" path)
    test    rax, rax
    jz      .cold_path              ; Branch to the cold block
    ; ... normal continuation ...
    ret

; Cold block (panic) — often placed after the function's `ret`
.cold_path:
    lea     rdi, [rip + .Lpanic_msg]
    lea     rsi, [rip + .Lpanic_loc]
    call    _some_panic_function
    ud2
```

The structure is always the same:

1. A conditional branch (`jz`, `jne`, `ja`…) to a block at the end of the function.  
2. The block loads the address of a message (`.Lpanic_msg`) and a source location (`.Lpanic_loc`) into the argument registers.  
3. A `call` to the panic function.  
4. `ud2` immediately after.

> 💡 **`ud2` as a visual signature.** In an assembly listing, `ud2` instructions are easy to spot. Each `ud2` signals the end of a panic path. If you see many `ud2`s scattered throughout a function, the function contains numerous checks (bounds checks, unwraps, etc.). This is an indicator of the "validation density" of Rust code.

### The Panic Location Structure

The source location passed as an argument to panic functions is a `core::panic::Location` structure stored in `.rodata`:

```
struct Location {
    file: &str,     // (pointer, length) → "src/main.rs"
    line: u32,      // 42
    column: u32,    // 17
}
```

In memory, this gives a 24-byte sequence in `.rodata`: pointer to the file string (8 bytes), string length (8 bytes), line number (4 bytes), column number (4 bytes).

In Ghidra, defining a `PanicLocation` type with this structure and applying it to each reference allows automatic decoding of source locations — a considerable time saver on large binaries.

### `panic = "abort"` vs `panic = "unwind"`

The behavior on panic depends on the compilation profile:

With `panic = "unwind"` (default), the panic unwinds the stack by calling the destructors (`Drop`) of each local variable. This requires `.eh_frame` tables and generates additional code in each function (the exception handling "landing pads", similar to C++). The advantage for the analyst: more visible structural code.

With `panic = "abort"`, the panic directly calls `abort()` (which triggers `SIGABRT`). No stack unwinding, no destructors, no landing pads. The binary is smaller and simpler, but contains fewer structural clues. This is the profile used by our `crackme_rust_strip` variant.

---

## Pattern 6: Bounds Checks

Rust systematically checks that accesses to slices and vectors are within bounds. This innocent Rust access:

```rust
let x = my_vec[i];
```

Produces in assembly:

```nasm
    ; rdi = pointer to the Vec's data
    ; rsi = Vec length
    ; rcx = index i

    cmp     rcx, rsi                  ; i >= len?
    jae     .bounds_check_failed      ; If so → panic (unsigned comparison)
    mov     eax, dword [rdi + rcx*4]  ; Valid access: load the element
    ; ...

.bounds_check_failed:
    ; rcx = index, rsi = len → passed as arguments to the panic message
    mov     rdi, rcx
    mov     rsi, rsi
    call    core::panicking::panic_bounds_check
    ud2
```

The `cmp` + `jae` (jump if above or equal, unsigned) pattern before each indexed access is the bounds check signature. At `-O2`/`-O3`, LLVM sometimes eliminates these checks when it can prove the index is always valid (for example, in a `for i in 0..vec.len()` loop). But in the general case, each indexed access generates this test.

> 🔑 **RE tip**: the density of bounds checks in a function tells you it manipulates collections (slices, `Vec`, `String`). If you see a bounds check followed by a memory access to `[base + index * N]`, the value `N` gives you the size of each element, which helps reconstruct the type: `N = 1` for `u8`/`i8`/`Vec<u8>`, `N = 4` for `u32`/`i32`/`f32`, `N = 8` for `u64`/`f64`/pointers, etc.

---

## Pattern 7: Closures and Iterators

Rust encourages the use of iterators and closures instead of indexed loops. This idiomatic code:

```rust
let sum: u32 = values.iter().filter(|&&x| x > 10).map(|&x| x * 2).sum();
```

Compiles to code that is often **as efficient as a C loop** thanks to LLVM's aggressive inlining. After optimization, the iterator chain is fused into a single loop:

```nasm
    ; Fused loop — no trace of individual filter/map/sum
    xor     eax, eax                  ; sum = 0
    xor     ecx, ecx                  ; i = 0
.loop:
    cmp     ecx, edx                  ; i < len?
    jge     .done
    mov     esi, dword [rdi + rcx*4]  ; load values[i]
    cmp     esi, 10                   ; filter: x > 10?
    jle     .skip
    lea     esi, [rsi + rsi]          ; map: x * 2
    add     eax, esi                  ; sum += x * 2
.skip:
    inc     ecx
    jmp     .loop
.done:
```

At `-O0`, the situation is very different: each iterator adapter (`filter`, `map`, `sum`) is a separate function, with intermediate structures allocated on the stack. The code is much more verbose but easier to follow, because each step is distinct.

> 💡 **RE consequence**: in optimized mode, do not look for calls to `Iterator::filter` or `Iterator::map` — they have been inlined. What you will see is a compact loop. In debug mode, you will see dozens of iterator functions with explicit mangled names — more readable but more verbose.

---

## Pattern 8: Trait Objects and Dynamic Dispatch

Our crackme uses `Box<dyn Validator>`, a trait object that goes through dynamic dispatch (vtable). In memory, a `Box<dyn Validator>` is a 16-byte fat pointer:

```
┌────────────────┬────────────────┐
│  data_ptr      │  vtable_ptr    │
│  (8 bytes)     │  (8 bytes)     │
└────────────────┴────────────────┘
```

The `vtable_ptr` points to a table in `.rodata` that contains:

```
┌────────────────────────────────────┐
│  drop_fn       (destructor)        │  offset 0x00
│  size           (type size)        │  offset 0x08
│  align          (alignment)        │  offset 0x10
│  method_1       (Validator::name)  │  offset 0x18
│  method_2       (Validator::validate) offset 0x20
└────────────────────────────────────┘
```

The first three fields (`drop`, `size`, `align`) are always present in every Rust trait vtable. The trait methods follow in their declaration order.

The call `validator.validate(serial)` via the trait object translates to:

```nasm
    ; rax = pointer to the fat pointer (data_ptr, vtable_ptr)
    mov     rdi, qword [rax]          ; data_ptr → first argument (self)
    mov     rcx, qword [rax+8]        ; vtable_ptr
    mov     rsi, qword [rbp-0x18]     ; serial (second argument)
    mov     rdx, qword [rbp-0x10]     ; serial length
    call    qword [rcx+0x20]          ; Indirect call via vtable (offset 0x20 = validate)
```

The recognizable pattern: **an indirect `call` via an indexed register** (`call [rcx+offset]`), where the register was loaded from a pointer stored next to another pointer (the fat pointer). The constant offset (`0x20` in this example) indicates which trait method is being called.

> 🔑 **Difference from C++**: C++ vtables contain only virtual methods. Rust vtables additionally contain `drop`, `size` and `align` in the header. If you see a vtable whose first three slots are a function pointer, a "reasonable" integer (~a few bytes to a few KB), and a small power of 2 (1, 2, 4, 8, 16…), it is almost certainly a Rust trait vtable.

---

## Visual Pattern Summary

| Assembly pattern | Likely Rust construct |  
|---|---|  
| `test reg, reg` / `jz` (on a pointer) | `Option<&T>` or `Option<Box<T>>` with niche optimization |  
| `cmp byte/dword [mem], 0` / `je`\|`jne` | `match` on `Option<T>` or `Result<T, E>` (discriminant test) |  
| Test + `jz` → `call panic` + `ud2` | `.unwrap()` or `.expect()` |  
| Test + `jne` → copy Err payload + `jmp` epilogue | `?` operator (error propagation) |  
| `cmp reg, imm` / `jae` → `call panic_bounds_check` + `ud2` | Indexed access `slice[i]` or `vec[i]` |  
| Cascade of `cmp` / `je` on values 0, 1, 2… | `match` on an enum with few variants |  
| `lea` + `movsxd` + `jmp [reg]` (jump table) | `match` on an enum with many variants (optimized) |  
| `cmp` + `jbe` / `ja` on constants | `match` on value ranges |  
| `call [reg+offset]` with prior loading of a fat pointer | Call via a trait object (`dyn Trait`) |  
| `ud2` | End of a path that never returns (panic, `process::exit`) |

---

> **Next section: 33.4 — Strings in Rust: `&str` vs `String` in Memory (no null terminator)** — we will see how Rust represents character strings and why classic tools like `strings` give incomplete results.

⏭️ [Strings in Rust: `&str` vs `String` in Memory (no null terminator)](/33-re-rust/04-rust-strings-memory.md)
