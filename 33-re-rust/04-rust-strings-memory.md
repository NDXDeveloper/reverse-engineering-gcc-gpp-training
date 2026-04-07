🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 33.4 — Strings in Rust: `&str` vs `String` in Memory (no null terminator)

> 🔤 Character strings are often the first entry point of an RE analysis: error messages, configuration keys, URLs, interface labels… In Rust, their memory representation fundamentally differs from C. An analyst who applies C reflexes to Rust strings will miss data, incorrectly split others, and waste precious time. This section explains exactly what changes and how to adapt your tools.

---

## The C Model: Refresher

In C, a string is a pointer to a sequence of bytes terminated by a null byte (`\0`). This is the model that all classic tools (`strings`, `gdb`, `x/s`) expect:

```
Pointer ──▶ [ 'H' 'e' 'l' 'l' 'o' '\0' ]
              0x00  0x01 0x02 0x03 0x04 0x05
```

The length is not stored: it is deduced by scanning bytes until the `\0`. This model is simple but fragile (buffer overflows) and forbids `\0` in the content.

---

## The Rust Model: Fat Pointers and Explicit Length

Rust uses two main types for strings, and neither relies on a null terminator.

### `&str` — the String Reference (fat pointer)

A `&str` is a **fat pointer** of 16 bytes composed of two fields:

```
┌──────────────────┬──────────────────┐
│  ptr  (8 bytes)  │  len  (8 bytes)  │
│  pointer to      │  length in       │
│  UTF-8 data      │  bytes (no       │
│                  │  trailing \0)    │
└──────────────────┴──────────────────┘
        Total size: 16 bytes
```

The pointed-to data is a sequence of UTF-8 bytes **without a null terminator**:

```
ptr ──▶ [ 'H' 'e' 'l' 'l' 'o' ]    ← no \0
         0x00 0x01 0x02 0x03 0x04

len = 5
```

When a `&str` is passed as a function argument, it occupies **two registers** according to the System V AMD64 convention:

```nasm
; Passing &str as argument: occupies 2 consecutive registers
    lea     rdi, [rip + .Lstr_data]    ; ptr → first register
    mov     rsi, 5                      ; len → second register
    call    some_function_taking_str
```

This is an extremely common pattern in Rust code: a `lea` followed by a `mov` of an immediate constant, both targeting consecutive argument registers (`rdi`/`rsi`, `rsi`/`rdx`, `rdx`/`rcx`, etc.). This `(address, length)` pair is the signature of a `&str` being passed.

### `String` — the Heap-Allocated String

A `String` is a 24-byte structure on the stack, composed of three fields:

```
┌──────────────────┬──────────────────┬──────────────────┐
│  ptr  (8 bytes)  │  len  (8 bytes)  │  cap  (8 bytes)  │
│  pointer to      │  current         │  allocated       │
│  heap buffer     │  length          │  capacity        │
└──────────────────┴──────────────────┴──────────────────┘
        Total size: 24 bytes (on the stack)
```

The buffer pointed to by `ptr` is allocated on the heap via the global allocator. As with `&str`, it contains **no null terminator**. The difference from `&str` is the `cap` (capacity) field, which indicates the total size of the allocated buffer — `len` can be less than `cap` if the string was created with a reserve.

In memory on the stack, a `String` looks exactly like a `Vec<u8>` — which is in fact its internal implementation. If you know how to recognize a `Vec` (section 33.3), you know how to recognize a `String`.

```nasm
; String stored on the stack at [rbp-0x28]
; [rbp-0x28] = ptr (to heap)
; [rbp-0x20] = len
; [rbp-0x18] = cap

    mov     rdi, qword [rbp-0x28]     ; ptr
    mov     rsi, qword [rbp-0x20]     ; len
    ; Pass the implicit &str (ptr, len) to a function
    call    some_function
```

### Relationship Between `&str` and `String`

A `String` can be converted to `&str` at zero cost (it is a simple borrow of `ptr` and `len`, without copying `cap`). In RE, this means that a 24-byte `String` on the stack can "become" a 16-byte `&str` by ignoring the third field. When a function takes a `&str` parameter and receives a `String`, the compiler simply extracts the first two fields.

---

## String Literals in `.rodata`

String literals in Rust (`"Hello"`, `"RUST-"`, error messages…) are stored in the `.rodata` section of the binary, exactly as in C. But how they are referenced differs.

### In C

```c
const char *msg = "Hello";
// .rodata: 48 65 6C 6C 6F 00      ← 6 bytes, with the \0
```

The C compiler stores the string with its trailing `\0`. The code references it via a simple pointer.

### In Rust

```rust
let msg: &str = "Hello";
// .rodata: 48 65 6C 6C 6F          ← 5 bytes, WITHOUT \0
// Elsewhere (code or .rodata): pointer to "Hello" + length 5
```

The Rust compiler stores the string **without `\0`**. The length is encoded either as an immediate constant in the code (`mov rsi, 5`) or in a reference structure in `.rodata`.

> ⚠️ **The LLVM nuance.** In practice, LLVM sometimes adds a `\0` after string literals in `.rodata` — not because Rust requires it, but because LLVM reuses its C infrastructure and this extra `\0` costs only one byte. This means `strings` may still find these strings. But **this behavior is not guaranteed**: it depends on the LLVM version, optimizations, and how strings are merged in memory. Do not rely on it.

### Concatenation of Literals in `.rodata`

When multiple `&str` literals are stored in `.rodata`, LLVM may place them contiguously without any separator:

```
Offset 0x1000: 52 55 53 54 2D         "RUST-"  
Offset 0x1005: 52 75 73 74 43 72 61   "RustCrackMe-v3.3"  
               63 6B 4D 65 2D 76 33
               2E 33
Offset 0x1016: 50 72 65 66 69 78 43   "PrefixCheck"
               68 65 63 6B
```

As seen by `strings`, this could produce a single long string with no relation to reality, because the data flows together without `\0` between them. This is a classic Rust RE pitfall.

---

## Impact on the `strings` Tool

The `strings` tool searches for sequences of at least N bytes (4 by default) composed of printable characters, terminated by a `\0` or end of section. Its behavior with Rust strings is unpredictable:

**Favorable case**: LLVM inserted a `\0` after the string, or the string is followed by alignment padding containing null bytes. `strings` finds it correctly.

**Unfavorable case — merging**: two strings are contiguous without an intermediate `\0`. `strings` merges them into a single longer string, devoid of meaning.

**Unfavorable case — truncation**: a string contains non-ASCII bytes (multibyte UTF-8: accented characters, emojis, CJK characters). `strings` with its default parameters may truncate it at the first non-printable byte.

**Unfavorable case — invisibility**: a short string (< 4 bytes) without an adjacent `\0` is not detected at all.

### Improving `strings` Results

A few options mitigate these problems:

```bash
# Reduce the minimum length to capture short strings
$ strings -n 2 crackme_rust_release | head -30

# Force UTF-8 encoding on the entire .rodata section
$ strings -e S crackme_rust_release

# Extract only the .rodata section
$ objcopy -O binary -j .rodata crackme_rust_release rodata.bin
$ strings rodata.bin
```

Even with these adjustments, `strings` remains an imperfect triage tool for Rust binaries. For reliable extraction, you need to cross-reference with analysis in the disassembler.

---

## Recognizing `&str` in the Disassembler

### Argument Passing Pattern

The most frequent pattern is passing a `&str` literal as a function argument. In Intel syntax:

```nasm
    lea     rdi, [rip + 0x1a3f]       ; Pointer to data in .rodata
    mov     esi, 0x11                  ; Length = 17 (0x11)
    call    core::fmt::write           ; Or any other function taking a &str
```

The `lea` loads the data address (the fat pointer's `ptr`), and the `mov` loads the length into the next register. This pair is the signature of a `&str`.

To find the string content in Ghidra, follow the `lea` address: it points into `.rodata` to exactly `0x11` (17) bytes of UTF-8 data. Ghidra will not necessarily display the string automatically (since there is no `\0`), but you can read it manually by selecting the 17 bytes at that address.

> 💡 **Creating a `&str` type in Ghidra.** Define a `RustStr` structure of 16 bytes with a `ptr` field (pointer) and a `len` field (ulong). Apply this type to locations on the stack or in `.rodata` where you identify fat pointers. The decompiler will then display `rust_str.ptr` and `rust_str.len` instead of raw values.

### String in `.rodata` with Reference Structure Pattern

Sometimes, the compiler creates a reference structure in `.rodata` that contains the complete fat pointer:

```nasm
; Instead of two lea/mov instructions, a single structure is loaded
    lea     rax, [rip + .Lref_str]     ; Points to the (ptr, len) structure in .rodata
    mov     rdi, qword [rax]           ; ptr
    mov     rsi, qword [rax+8]         ; len
```

In `.rodata`, the structure looks like this (hex view):

```
.Lref_str:
    .quad   .Lstr_data        ; 8 bytes: data address
    .quad   17                ; 8 bytes: length
```

This pattern is frequent for strings passed to the `format!`, `println!`, `eprintln!` macros — they use complex `fmt::Arguments` structures that reference literals via fat pointers in `.rodata`.

### `&str` Comparison Pattern

Comparing two `&str` values in Rust (`==`) is not done with `strcmp` (which looks for a `\0`). The compiler emits code that first compares the lengths, then the content:

```nasm
    ; Comparison of two &str: (rdi, rsi) vs (rdx, rcx)
    ; rdi = ptr1, rsi = len1, rdx = ptr2, rcx = len2

    cmp     rsi, rcx                   ; Compare lengths
    jne     .not_equal                 ; If different lengths → not equal

    ; Lengths match: compare content byte by byte
    mov     rdi, rdi                   ; ptr1 (already in place)
    mov     rsi, rdx                   ; ptr2
    mov     rdx, rcx                   ; len (common to both)
    call    memcmp                     ; or bcmp — raw comparison
    test    eax, eax
    jnz     .not_equal

.equal:
    ; ...

.not_equal:
    ; ...
```

The key point: the comparison goes through **`memcmp`** (or `bcmp`), not `strcmp`. This is an additional clue that you are analyzing Rust. If you see a length `cmp` followed by a `call memcmp`, it is almost certainly a `&str` or `&[u8]` slice comparison.

> 🔑 **Implication for our crackme RE**: the `"RUST-"` prefix verification in `PrefixValidator::validate` uses `starts_with`, which boils down to a `memcmp` of the first N bytes (where N is the prefix length). By setting a breakpoint on `memcmp` in GDB and inspecting the arguments, you can capture the expected prefix without even reading the disassembly.

---

## Recognizing `String` in the Disassembler

### `String` Allocation

Creating a `String` goes through the allocator. A `String::new()` initializes a `(ptr, len, cap)` triplet with null values (no allocation as long as the string is empty):

```nasm
    ; String::new() — empty string, no allocation
    mov     qword [rbp-0x28], 1        ; ptr = dangling pointer (Rust convention for cap=0)
    mov     qword [rbp-0x20], 0        ; len = 0
    mov     qword [rbp-0x18], 0        ; cap = 0
```

> 💡 The `ptr` of an empty `String` or `Vec` is not `NULL` (`0x0`) in Rust — it is an intentional "dangling" pointer, often `0x1` or the type's alignment. This is a difference from C where an empty vector would typically have a null pointer. If you see a pointer initialized to `1` in a `(ptr, len, cap)` triplet, it is an empty `String` or `Vec`.

A `String::from("Hello")` or `"Hello".to_string()` triggers a heap allocation:

```nasm
    ; Allocate a 5-byte buffer on the heap
    mov     edi, 5                      ; requested size
    mov     esi, 1                      ; alignment (1 for u8)
    call    __rust_alloc                ; Call to the global allocator
    test    rax, rax                    ; Check if allocation succeeded
    je      .alloc_failed               ; → OOM panic

    ; Copy "Hello" into the allocated buffer
    mov     rdi, rax                    ; destination = heap buffer
    lea     rsi, [rip + .Lstr_hello]   ; source = literal in .rodata
    mov     edx, 5                      ; 5 bytes
    call    memcpy

    ; Initialize the String triplet on the stack
    mov     qword [rbp-0x28], rax      ; ptr = heap buffer
    mov     qword [rbp-0x20], 5        ; len = 5
    mov     qword [rbp-0x18], 5        ; cap = 5
```

The pattern: `__rust_alloc` (or `__rust_alloc_zeroed`) followed by `memcpy` from `.rodata`, then storage of a `(ptr, len, cap)` triplet on the stack. This is the signature of constructing a `String` from a literal.

### `String` Destruction (Drop)

When a `String` goes out of scope, Rust automatically inserts a destructor call that frees the heap buffer:

```nasm
    ; String Drop — free the buffer
    mov     rdi, qword [rbp-0x28]     ; ptr
    mov     rsi, qword [rbp-0x18]     ; cap (not len — we free the total capacity)
    mov     edx, 1                     ; alignment
    call    __rust_dealloc
```

The call to `__rust_dealloc` (a wrapper around `free`) with `cap` as the size is the signature of a `String` or `Vec` `Drop`. Note that it is `cap` that is passed, not `len` — all allocated memory is freed, not just the used portion.

---

## Rust Allocator Functions

Rust's global allocator exposes a set of recognizable functions in the binary, even when stripped. They replace C's `malloc`/`free`:

| Rust function | C equivalent | Assembly signature |  
|---|---|---|  
| `__rust_alloc` | `malloc` | `rdi` = size, `rsi` = alignment → `rax` = pointer |  
| `__rust_alloc_zeroed` | `calloc` | Same, but memory initialized to zero |  
| `__rust_dealloc` | `free` | `rdi` = pointer, `rsi` = size, `rdx` = alignment |  
| `__rust_realloc` | `realloc` | `rdi` = pointer, `rsi` = old size, `rdx` = alignment, `rcx` = new size |

The key difference from C: **the Rust allocator always receives the size and alignment**, whereas C's `malloc`/`free` only take the pointer (the size is managed internally by the allocator). If you see an "allocation" call that takes an alignment argument in addition to the size, it is the Rust allocator.

On a non-stripped binary, these functions are explicitly named. On a stripped binary, they delegate to `malloc`/`free` (via the libc) and appear as simple wrappers around C functions.

---

## Rust Strings and C Interoperability (FFI)

When Rust code calls C functions (via FFI), it must convert its `&str` to C strings terminated by `\0`. The `CString` type from the Rust stdlib allocates a buffer with a trailing `\0`:

```rust
use std::ffi::CString;  
let c_str = CString::new("Hello").unwrap();  
unsafe { libc_function(c_str.as_ptr()); }  
```

In assembly, creating a `CString` is recognizable: allocation of `len + 1` bytes, content copy, writing a `\0` at the end:

```nasm
    ; CString::new("Hello")
    mov     edi, 6                      ; 5 + 1 for the \0
    mov     esi, 1
    call    __rust_alloc
    ; ... copy "Hello" ...
    mov     byte [rax+5], 0             ; Add the null terminator
```

This `mov byte [rax+len], 0` is the marker of a conversion to a C string. If you see it, the Rust code is interfacing with a C library at that point — which can reveal interesting FFI calls.

> 💡 The reverse also exists: `CStr::from_ptr` converts a C pointer (`*const c_char`) to a Rust reference. This code calls `strlen` to determine the length, then constructs a fat pointer `(ptr, len)`. If you see a `call strlen` in Rust code, it is an interoperability point with C.

---

## Practical Strategies for the Analyst

### Finding Strings in a Stripped Rust Binary

The most reliable method combines several approaches:

**Step 1 — Triage with `strings`.** Run `strings` normally to capture strings that are isolated or followed by a `\0`. This covers panic messages, source paths, and some of the application literals.

```bash
$ strings -n 3 crackme_rust_strip > strings_output.txt
```

**Step 2 — Search for `lea`/`mov` patterns in the code.** In Ghidra, search for instructions of the type `lea reg, [rip + offset]` followed by `mov reg, imm`. The `imm` is the length. The offset points to data in `.rodata`. This search identifies `&str` values that `strings` missed.

**Step 3 — Spot formatting structures.** The `format!`, `println!`, `eprintln!` macros create `fmt::Arguments` structures in `.rodata` that contain arrays of fat pointers to the format string fragments. These structures are recognizable by their regular size and internal pointers to `.rodata`.

**Step 4 — Trace `memcmp` dynamically.** If you have a way to execute the binary (GDB, Frida), set a breakpoint on `memcmp` and `bcmp`. Each hit reveals the compared strings with their exact lengths — no need for `\0`.

```bash
# In GDB:
(gdb) break memcmp
(gdb) run test_user RUST-0000-0000-0000-0000
# At each hit, inspect rdi (ptr1), rsi (ptr2), rdx (len)
(gdb) x/s $rdi
(gdb) x/Ns $rsi    # where N = $rdx
```

### Defining Types in Ghidra

Create these structures in Ghidra's Data Type Manager to facilitate annotation:

```c
// Fat pointer &str
struct RustStr {
    char *ptr;       // Pointer to UTF-8 data
    ulong len;       // Length in bytes
};

// String (allocated string)
struct RustString {
    char *ptr;       // Pointer to heap buffer
    ulong len;       // Current length
    ulong cap;       // Allocated capacity
};

// Panic location (seen in 33.3)
struct PanicLocation {
    struct RustStr file;  // Source file name
    uint line;            // Line number
    uint col;             // Column number
};
```

Applying these types to identified locations on the stack or in `.rodata` transforms the decompiler's pseudo-code: instead of raw pointer and integer manipulations, you will see accesses to `str.ptr`, `str.len`, `string.cap` — making the logic immediately readable.

---

## Summary of C vs Rust Differences for Strings

| Aspect | C (`char *`) | Rust `&str` | Rust `String` |  
|---|---|---|---|  
| **Representation** | Simple pointer (8 bytes) | Fat pointer (16 bytes) | Triplet (24 bytes) |  
| **Terminator** | `\0` required | None | None |  
| **Length** | Computed by `strlen` | Stored in the fat pointer | Stored in the structure |  
| **Data storage** | Stack, heap or `.rodata` | `.rodata` (literals) | Heap |  
| **Comparison** | `strcmp` (looks for `\0`) | `memcmp` (explicit length) | `memcmp` (via deref to `&str`) |  
| **`strings` tool** | Reliable | Partial — incomplete results | Partial — data on the heap |  
| **Allocation** | `malloc` / `free` | No allocation (borrowing) | `__rust_alloc` / `__rust_dealloc` |  
| **Argument passing** | 1 register (`rdi`) | 2 registers (`rdi` + `rsi`) | Pointer to the structure |

---

> **Next section: 33.5 — Embedded Libraries and Binary Size (everything is statically linked)** — we will see why Rust binaries are so large and how to isolate application code from stdlib noise to focus your analysis.

⏭️ [Embedded Libraries and Binary Size (everything is statically linked)](/33-re-rust/05-libraries-binary-size.md)
