🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.9 — C++20 coroutines: recognizing the frame and state machine pattern

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## What coroutines change for RE

A classic function starts at its entry point, executes until its `return`, and can't be interrupted in between. A coroutine breaks this model: it can **suspend** its execution at arbitrary points (`co_await`, `co_yield`), return control to the caller, then **resume** later exactly where it left off, with all its local state intact.

To achieve this magic, the compiler applies a deep transformation. The linear function from the source code is sliced into fragments and reassembled as a **state machine**. Local variables, which would normally live on the stack, are moved into a **coroutine frame** allocated on the heap (because the caller's stack may be gone by the time of resumption). Each suspension point becomes a numbered state, and resuming the coroutine consists of jumping directly to the right state via a dispatch (switch or jump table).

The result in disassembly is disorienting: an apparently simple function in the source code transforms into one or more complex functions containing an initial dispatch on a state index, jumps to non-contiguous code blocks, and systematic memory accesses via a heap pointer instead of the stack. Without knowing the patterns of this transformation, the decompiled code is virtually incomprehensible.

> ⚠️ **GCC support.** C++20 coroutine support in GCC is available since GCC 10 (experimental) and considered stable from GCC 11. The generated code has evolved between versions. The patterns described here correspond to GCC 11–14. Newer versions might optimize certain aspects differently.

> ⚠️ **Training binary.** The `ch17-oop` binary for this chapter doesn't include coroutines. The examples in this section are provided as source code and pseudo-assembly for illustration. To experiment, compile the examples with `g++ -std=c++20 -fcoroutines -O0 -g`.

## Quick refresher on the C++20 coroutine model

A function is a coroutine if its body contains at least one of three operators: `co_await`, `co_yield`, or `co_return`. The compiler then automatically deduces the coroutine type from the return type, which must provide a nested **promise type**.

Here's a minimal generator illustrating the concepts:

```cpp
#include <coroutine>
#include <iostream>
#include <optional>

struct Generator {
    struct promise_type {
        int current_value;
        bool finished = false;

        Generator get_return_object() {
            return Generator{
                std::coroutine_handle<promise_type>::from_promise(*this)
            };
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() { std::terminate(); }
        std::suspend_always yield_value(int value) {
            current_value = value;
            return {};
        }
        void return_void() { finished = true; }
    };

    std::coroutine_handle<promise_type> handle;

    bool next() {
        if (!handle || handle.done()) return false;
        handle.resume();
        return !handle.promise().finished;
    }

    int value() const { return handle.promise().current_value; }

    ~Generator() { if (handle) handle.destroy(); }
};

Generator range(int start, int end) {
    for (int i = start; i < end; ++i) {
        co_yield i;
    }
}
```

The `range()` code is linear and readable. But what GCC makes of it is radically different.

## The coroutine frame

### Allocation and layout

When a coroutine is called, GCC allocates a **coroutine frame** on the heap. This frame contains everything the coroutine needs to survive between suspensions:

```
Coroutine frame (heap-allocated):
┌──────────────────────────────────────────────┐
│  resume function pointer (void(*)(frame*))   │  offset 0    — pointer to resume function
├──────────────────────────────────────────────┤
│  destroy function pointer (void(*)(frame*))  │  offset 8    — pointer to destroy function
├──────────────────────────────────────────────┤
│  promise object (promise_type)               │  offset 16   — the promise object
├──────────────────────────────────────────────┤
│  suspension index (int or short)             │  offset 16 + sizeof(promise)
├──────────────────────────────────────────────┤
│  coroutine local variables:                  │
│    copied parameters                         │
│    automatic variables                       │
│    temporaries needed across suspend         │
├──────────────────────────────────────────────┤
│  (padding / alignment)                       │
└──────────────────────────────────────────────┘
```

The first two fields are fundamental:

- **`resume`** (offset 0): pointer to the function that resumes coroutine execution. When `handle.resume()` is called, the runtime calls `frame->resume(frame)`.

- **`destroy`** (offset 8): pointer to the function that destroys the frame and frees its resources. Called by `handle.destroy()`.

These two function pointers are the main dispatch mechanism. They replace the classic polymorphism's vptr/vtable with a more direct mechanism.

### Allocation in assembly

The initial call to coroutine `range(1, 10)` generates:

```nasm
range(int, int):
    ; 1. Allocate the coroutine frame
    mov    edi, 48                        ; frame size (varies with local variables)
    call   operator new(unsigned long)@plt
    mov    rbx, rax                       ; rbx = pointer to frame

    ; 2. Initialize function pointers
    lea    rax, [rip+range.resume]        ; address of resume function
    mov    QWORD PTR [rbx], rax           ; frame->resume = &range.resume
    lea    rax, [rip+range.destroy]       ; address of destroy function
    mov    QWORD PTR [rbx+8], rax         ; frame->destroy = &range.destroy

    ; 3. Construct the promise object
    lea    rdi, [rbx+16]                  ; this = &frame->promise
    call   Generator::promise_type::promise_type()

    ; 4. Copy parameters into the frame
    mov    DWORD PTR [rbx+36], esi        ; frame->start = start (first parameter)
    mov    DWORD PTR [rbx+40], edx        ; frame->end = end (second parameter)

    ; 5. Initialize the suspension index
    mov    DWORD PTR [rbx+32], 0          ; frame->index = 0 (initial state)

    ; 6. Call promise.get_return_object()
    lea    rdi, [rbx+16]
    call   Generator::promise_type::get_return_object()
    ; rax = the Generator (contains the coroutine_handle)

    ; 7. Call promise.initial_suspend()
    ; If result is suspend_always → coroutine is suspended immediately
    ; Control returns to caller with the Generator
    ret
```

> 💡 **RE pattern:** a function that starts with `operator new`, stores two function pointers at offsets 0 and 8 of the allocated block, initializes a state index, copies its parameters into the heap block, then returns without having executed the main logic — this is the **ramp function** of a coroutine. The actual logic is in the resume function.

### Heap Allocation Elision (HALO)

The C++20 standard allows the compiler to elide the coroutine frame's heap allocation when it can prove the coroutine's lifetime is contained within the caller's. This is the **HALO** optimization (*Heap Allocation eLision Optimization*).

In practice, GCC applies HALO in limited fashion. In `-O2`, if the coroutine is entirely consumed in a local loop and the compiler can determine its lifetime, the frame may be placed on the caller's stack instead of the heap. In that case, `operator new` disappears from the generated code.

In RE, the absence of `operator new` at the start of a coroutine means either HALO or that the allocation was inlined/optimized. Check whether the two function pointers (resume/destroy) are still present at fixed offsets of a stack object.

## The state machine transformation

### The principle

GCC slices the coroutine body into **segments** separated by suspension points (`co_await`, `co_yield`). Each segment receives a state number. The resume function starts with a dispatch that jumps to the right segment based on the current state index.

For the `range()` coroutine:

```cpp
Generator range(int start, int end) {
    for (int i = start; i < end; ++i) {
        co_yield i;      // suspension point
    }
}
```

The states are:

| Index | Meaning |  
|-------|---------|  
| 0 | Initial entry (after `initial_suspend`, first `resume`) |  
| 1 | Resume after `co_yield` |  
| (final) | Coroutine finished (`final_suspend`) |

### The resume function

The `range.resume` function contains the complete state machine:

```nasm
range.resume:                             ; void range.resume(frame*)
    push   rbp
    mov    rbp, rsp
    mov    rbx, rdi                       ; rbx = frame pointer

    ; ---- Dispatch on state index ----
    mov    eax, DWORD PTR [rbx+32]        ; load suspension index
    cmp    eax, 0
    je     .L_state_0                     ; state 0: first entry
    cmp    eax, 1
    je     .L_state_1                     ; state 1: resume after co_yield
    ; invalid or finished state
    ud2                                    ; unreachable (or jmp to cleanup)

; =========================================
; STATE 0: First execution
; =========================================
.L_state_0:
    ; Initialize i = start
    mov    eax, DWORD PTR [rbx+36]        ; frame->start
    mov    DWORD PTR [rbx+44], eax        ; frame->i = start

.L_loop_check:
    ; Check i < end
    mov    eax, DWORD PTR [rbx+44]        ; frame->i
    cmp    eax, DWORD PTR [rbx+40]        ; frame->end
    jge    .L_loop_done                   ; i >= end → exit loop

    ; co_yield i → call promise.yield_value(i)
    mov    esi, DWORD PTR [rbx+44]        ; i
    lea    rdi, [rbx+16]                  ; &frame->promise
    call   Generator::promise_type::yield_value(int)

    ; Prepare suspension
    mov    DWORD PTR [rbx+32], 1          ; frame->index = 1 (next state)
    ; Return → coroutine is suspended
    pop    rbp
    ret

; =========================================
; STATE 1: Resume after co_yield
; =========================================
.L_state_1:
    ; Increment i (loop continues)
    add    DWORD PTR [rbx+44], 1          ; frame->i++
    jmp    .L_loop_check                  ; back to loop test

; =========================================
; END: Loop finished
; =========================================
.L_loop_done:
    ; Implicit co_return (return_void)
    lea    rdi, [rbx+16]
    call   Generator::promise_type::return_void()

    ; final_suspend
    ; Mark coroutine as finished
    mov    DWORD PTR [rbx+32], -1         ; index = -1 (or other sentinel value)
    pop    rbp
    ret
```

### Dispatch anatomy

The initial dispatch is the most recognizable pattern. GCC uses either a series of comparisons (`cmp`/`je`) or a **jump table** (`jmp [table + rax*8]`) when the number of states is sufficient:

**Dispatch by comparisons (few states):**

```nasm
mov    eax, [rbx+offset_index]  
test   eax, eax  
je     .L_state_0  
cmp    eax, 1  
je     .L_state_1  
cmp    eax, 2  
je     .L_state_2  
jmp    .L_invalid  
```

**Dispatch by jump table (many states):**

```nasm
mov    eax, [rbx+offset_index]  
cmp    eax, MAX_STATE  
ja     .L_invalid  
lea    rcx, [rip+.L_jump_table]  
movsxd rax, eax  
jmp    QWORD PTR [rcx+rax*8]  

.L_jump_table:
    .quad  .L_state_0
    .quad  .L_state_1
    .quad  .L_state_2
    .quad  .L_state_3
```

> 💡 **RE pattern:** a function that starts by loading an integer from a heap pointer (the frame), then does a switch/dispatch to different code blocks, is probably a coroutine's resume function. The heap pointer is the coroutine frame, and the integer is the state index. This pattern is analogous to a state machine switch, but the key is that the first argument (`rdi`) is the frame and the dispatch is the very first thing the function does.

### The destroy function

The `range.destroy` function has a structure similar to `resume`, but instead of executing the coroutine's code, it destroys local objects according to the current state and frees the frame:

```nasm
range.destroy:                            ; void range.destroy(frame*)
    mov    rbx, rdi

    ; Dispatch on index to determine which objects are alive
    mov    eax, DWORD PTR [rbx+32]
    ; ... depending on state, destroy the appropriate local objects ...

    ; Destroy the promise object
    lea    rdi, [rbx+16]
    call   Generator::promise_type::~promise_type()

    ; Free the frame
    mov    rdi, rbx
    call   operator delete(void*)@plt
    ret
```

The dispatch in `destroy` is necessary because alive objects in the frame depend on the suspension point where the coroutine was interrupted. If the coroutine is destroyed at state 1, variable `i` is alive and destructors for all local objects active at that state must be called.

## `coroutine_handle` and its operations

### `coroutine_handle` layout

```
std::coroutine_handle<promise_type> (sizeof = 8 bytes):
┌──────────────────────────────────────┐
│  _M_fr_ptr (void*)                   │  offset 0    — pointer to coroutine frame
└──────────────────────────────────────┘
```

A `coroutine_handle` is a simple raw pointer to the frame. It's a minimal wrapper, similar in spirit to a `unique_ptr` without automatic lifetime management.

### `handle.resume()`

```cpp
handle.resume();
```

```nasm
mov    rax, QWORD PTR [rbp-0x10]     ; rax = handle._M_fr_ptr (the frame)  
mov    rdi, rax                       ; first argument = frame  
call   QWORD PTR [rax]               ; indirect call: frame->resume(frame)  
```

The call is an **indirect call via the first QWORD of the frame**. That's the `resume` function pointer at offset 0.

> 💡 **Fundamental RE pattern:** `mov rdi, rax; call [rax]` where `rax` is a heap pointer — this is a `coroutine_handle::resume()`. The frame is both the `this` (passed in `rdi`) and the source of the function pointer (loaded from offset 0 of `rax`). This pattern is similar to a virtual call via vptr, except the function pointer is directly in the object instead of in a separate table.

### `handle.destroy()`

```nasm
mov    rax, QWORD PTR [rbp-0x10]     ; frame  
mov    rdi, rax  
call   QWORD PTR [rax+8]             ; indirect call: frame->destroy(frame)  
```

Same pattern, but at offset 8 instead of 0.

### `handle.done()`

```cpp
if (handle.done()) { /* coroutine finished */ }
```

GCC implements `done()` by checking if the `resume` pointer is null or by testing the state index:

```nasm
; Variant 1: test the resume pointer
mov    rax, QWORD PTR [rbp-0x10]     ; frame  
cmp    QWORD PTR [rax], 0            ; frame->resume == nullptr?  
sete   al                             ; done = (resume == nullptr)  

; Variant 2: test the state index
mov    rax, QWORD PTR [rbp-0x10]  
mov    eax, DWORD PTR [rax+32]       ; state index  
cmp    eax, -1                        ; final state?  
sete   al  
```

The variant depends on the GCC version and optimizations. In both cases, the pattern is a test on the frame followed by a comparison with a sentinel value (nullptr or -1).

### `handle.promise()`

```cpp
auto& promise = handle.promise();
```

```nasm
mov    rax, QWORD PTR [rbp-0x10]     ; frame  
lea    rax, [rax+16]                  ; &frame->promise (offset 16, after the two fn pointers)  
```

Simple offset addition to the promise object in the frame.

## `co_await` in detail

`co_await` is the most general operator. It takes an *awaitable* and generates a three-step protocol:

```cpp
co_await expr;
// Conceptual equivalent:
auto&& awaitable = expr;  
if (!awaitable.await_ready()) {  
    // suspend the coroutine
    awaitable.await_suspend(handle);
    // ... coroutine is suspended here ...
    // ... resumes when someone calls handle.resume() ...
}
auto result = awaitable.await_resume();
```

### In assembly

```nasm
; co_await some_awaitable
    ; 1. Call await_ready()
    lea    rdi, [rbp-0x28]               ; &awaitable
    call   Awaitable::await_ready()
    test   al, al
    jnz    .L_no_suspend                 ; true → no need to suspend

    ; 2. Prepare suspension
    mov    DWORD PTR [rbx+32], 2         ; index = next state
    ; Build coroutine_handle to pass to await_suspend
    mov    QWORD PTR [rbp-0x30], rbx     ; handle._M_fr_ptr = frame

    ; 3. Call await_suspend(handle)
    lea    rdi, [rbp-0x28]               ; &awaitable
    lea    rsi, [rbp-0x30]               ; &handle
    call   Awaitable::await_suspend(std::coroutine_handle<>)

    ; 4. Return (coroutine is suspended)
    pop    rbp
    ret

.L_no_suspend:
    ; No suspension — continue directly

.L_resume_point:                         ; ← arrive here when resume() is called
    ; 5. Call await_resume()
    lea    rdi, [rbp-0x28]
    call   Awaitable::await_resume()
    ; Result is in rax (or xmm0)
```

> 💡 **RE pattern:** the sequence `await_ready` → branch → index update → `await_suspend` → `ret` is the signature of a `co_await` suspension point. The `ret` in the middle of the function's logic (not at the end) is unusual for a normal function and betrays the coroutine nature.

### `co_await suspend_always` and `suspend_never`

The most common awaitable types are `std::suspend_always` and `std::suspend_never`, which are empty classes with trivial methods:

- `suspend_always::await_ready()` always returns `false` → the coroutine always suspends.  
- `suspend_never::await_ready()` always returns `true` → the coroutine never suspends.

In `-O2`, GCC inlines these calls and eliminates the branch:

```nasm
; co_await suspend_always (optimized)
; await_ready() = false → always suspend, no test
mov    DWORD PTR [rbx+32], N          ; update index  
pop    rbp  
ret                                    ; suspend directly  

; co_await suspend_never (optimized)
; await_ready() = true → never suspend, code eliminated
; nothing is generated, execution continues
```

## `co_yield` in detail

`co_yield expr` is syntactic sugar for `co_await promise.yield_value(expr)`. GCC transforms it exactly this way:

```nasm
; co_yield i
    ; 1. Call promise.yield_value(i)
    mov    esi, DWORD PTR [rbx+44]       ; frame->i
    lea    rdi, [rbx+16]                 ; &frame->promise
    call   promise_type::yield_value(int)
    ; returns an awaitable (suspend_always in our case)

    ; 2. co_await on the result (suspend_always)
    ; await_ready() = false → suspend
    mov    DWORD PTR [rbx+32], 1         ; index = next state
    pop    rbp
    ret                                   ; suspend
```

> 💡 **In RE:** a call to a method named `yield_value` (or a method on the object at offset 16 of the frame, which is the promise) followed by a suspension is a `co_yield`. The passed argument is the value the coroutine produces.

## `co_return` in detail

`co_return expr` calls `promise.return_value(expr)` (or `promise.return_void()` without expression), then executes `final_suspend`:

```nasm
; co_return (void)
    lea    rdi, [rbx+16]                 ; &frame->promise
    call   promise_type::return_void()

    ; final_suspend
    lea    rdi, [rbx+16]
    call   promise_type::final_suspend()
    ; If suspend_always: mark as finished
    mov    QWORD PTR [rbx], 0            ; frame->resume = nullptr (done)
    mov    DWORD PTR [rbx+32], -1        ; index = terminal state
    pop    rbp
    ret
```

Zeroing the `resume` pointer (or setting it to `nullptr`) is the termination mark. After this, `handle.done()` will return `true`.

## Local variables in the frame

Local variables of a coroutine that live across a suspension point are **frame-promoted**. GCC analyzes which variables are alive on both sides of a `co_await`/`co_yield` and moves them into the coroutine frame instead of keeping them on the stack.

```cpp
Generator range(int start, int end) {
    for (int i = start; i < end; ++i) {  // i lives across co_yield
        co_yield i;
    }
}
```

Variable `i` is alive before `co_yield` (it's computed) and after (it's incremented). It must therefore reside in the frame:

```
range() frame:
  offset 0  : resume function pointer
  offset 8  : destroy function pointer
  offset 16 : promise_type
  offset 32 : suspension index
  offset 36 : start (copied parameter)
  offset 40 : end (copied parameter)
  offset 44 : i (promoted local variable)
```

> 💡 **In RE:** in the resume function, all local variable accesses go through the frame pointer (first argument, `rdi`, often saved in `rbx`). You'll see virtually no `rbp`-based (local stack) accesses for coroutine variables. Systematic access to `[rbx+offset]` for reading and writing variables, combined with the initial dispatch, confirms the function is a coroutine resume.

Variables that don't cross a suspension point (temporaries used only between two suspensions) can stay on the resume function's stack. GCC optimizes by promoting to the frame only what's strictly necessary.

## Difference between ramp and resume

GCC separates the coroutine into two (or three) functions:

| Function | Role | When it's called |  
|----------|------|------------------|  
| **Ramp** (`range`) | Allocates frame, initializes, executes `initial_suspend` | At the initial coroutine call |  
| **Resume** (`range.resume`) | Contains the complete state machine | At each `handle.resume()` |  
| **Destroy** (`range.destroy`) | Destroys objects by state, frees frame | At `handle.destroy()` |

The ramp is the function visible in the symbol table under the original name. Resume and destroy are internal functions whose names contain GCC-specific suffixes.

```bash
$ nm -C coroutine_binary | grep range
0000000000401200 T range(int, int)                    # ramp
0000000000401350 t range(int, int) [clone .resume]    # resume
0000000000401500 t range(int, int) [clone .destroy]   # destroy
```

The `[clone .resume]` and `[clone .destroy]` suffixes unambiguously identify coroutine functions. On a stripped binary, these names disappear, but the structural patterns remain.

> 💡 **In RE:** in a binary with symbols, `[clone .resume]` and `[clone .destroy]` instantly identify coroutines. In a stripped binary, look for function pairs that take a heap pointer as their sole argument, where the first contains a dispatch on a heap integer (resume) and the second calls destructors then `operator delete` (destroy).

## Recognizing a coroutine in a stripped binary

Without symbols, here are the clues to combine:

### Ramp structural clues

- `operator new` call at function start.  
- Storage of **two function pointers** at offsets 0 and 8 of the allocated block.  
- Initialization of an integer (the index) to 0 in the same block.  
- Copy of function parameters into the heap block.  
- Quick return (the function is short: it allocates, initializes, and returns).

### Resume structural clues

- Single argument: a heap pointer (the frame).  
- **Immediate dispatch** on an integer read from the frame (the state index): `mov eax, [rdi+N]; cmp/je` or jump table.  
- Systematic variable accesses via frame pointer (`[rbx+offset]`), little or no access via `rbp`.  
- **Multiple `ret`s** in the middle of the function (one per suspension point), not just at the end.  
- Index update before each internal `ret` (`mov DWORD [rbx+N], new_state`).  
- Absence of classic prologue/epilogue with stack allocation for local variables (they're in the frame).

### Destroy structural clues

- Same single argument as resume (frame pointer).  
- Similar dispatch to resume (but simpler).  
- Calls to destructors (frame local variables).  
- Ends with `operator delete` (frame deallocation).

### Cross clues

- The ramp stores resume and destroy addresses in the frame. Cross-references (XREF) in Ghidra from the ramp to resume and destroy confirm the relationship.  
- Resume and destroy share the same frame layout (same offsets for the same data).  
- Resume may call destroy (on exception or termination).

## Impact of optimizations

### In `-O0`

The code is faithful to the standard transformation. Each `co_await`, `co_yield`, `co_return` is visible as a distinct sequence. Calls to promise methods (`initial_suspend`, `yield_value`, `final_suspend`, etc.) are explicit. The dispatch is a simple switch.

### In `-O2` / `-O3`

GCC applies significant optimizations:

- **Promise method inlining.** Calls to `await_ready`, `await_suspend`, `await_resume`, `yield_value`, etc. are inlined. The `co_await` protocol can reduce to a few instructions.

- **Trivial suspension elimination.** If `await_ready()` is constexpr `true` (as with `suspend_never`), all suspension code is eliminated.

- **Dispatch simplification.** If the number of states is small and predictable, GCC can replace the switch with direct branches or even merge states.

- **HALO.** The heap allocation can be elided (frame placed on the caller's stack).

- **Resume tail call.** In certain cases, `handle.resume()` can become a tail call, eliminating one stack level.

In `-O2`, the `range` coroutine can simplify to the point where the state machine is barely recognizable — states are merged, promise calls are inlined, and the code looks like an ordinary loop with unexpected `ret`s.

> 💡 **Practical tip:** as with other C++ features (vtables, lambdas), always analyze the `-O0` variant first to understand the structure, then switch to `-O2` to see what optimizations changed.

## Coroutines and exceptions

If an exception is thrown in a coroutine body, it's not propagated to the `resume()` caller. Instead, the runtime calls `promise.unhandled_exception()`, which can store the exception for later rethrowing:

```cpp
void unhandled_exception() {
    exception_ptr_ = std::current_exception();
}
```

In assembly, this manifests as a landing pad in the resume function that, instead of calling `_Unwind_Resume`, calls the promise's `unhandled_exception` method:

```nasm
; Landing pad in range.resume
.L_exception_handler:
    mov    rdi, rax                       ; exception object
    call   __cxa_begin_catch@plt
    ; Call promise.unhandled_exception()
    lea    rdi, [rbx+16]                 ; &frame->promise
    call   promise_type::unhandled_exception()
    call   __cxa_end_catch@plt
    ; Go to final_suspend
    jmp    .L_final_suspend
```

> 💡 **In RE:** a landing pad that calls a method on the object at offset 16 of the frame (the promise) instead of propagating the exception is the `unhandled_exception()` handler of a coroutine.

## Summary of patterns to recognize

| Assembly pattern | Meaning |  
|------------------|---------|  
| `operator new` + store two fn ptrs at offsets 0 and 8 + init index + quick return | Coroutine ramp function |  
| Immediate dispatch `mov eax, [rdi+N]; cmp; je` + frame pointer access + multiple `ret`s | Coroutine resume function |  
| Same dispatch + destructors + `operator delete` | Coroutine destroy function |  
| `mov rdi, rax; call [rax]` (indirect call via offset 0 of frame) | `coroutine_handle::resume()` |  
| `mov rdi, rax; call [rax+8]` (indirect call via offset 8 of frame) | `coroutine_handle::destroy()` |  
| `cmp QWORD [frame], 0` or `cmp DWORD [frame+N], -1` | `coroutine_handle::done()` |  
| `lea rax, [frame+16]` | Access to promise object |  
| Integer update in frame then `ret` | Suspension point (state index update) |  
| Symbol `[clone .resume]` / `[clone .destroy]` | Coroutine identified by symbols |  
| Landing pad calling a method on the promise instead of propagating | `unhandled_exception()` in a coroutine |  
| Exclusive variable access via `[rbx+offset]` (heap), not via `rbp` (stack) | Local variables promoted to coroutine frame |

---


⏭️ [Checkpoint: reconstruct the classes of the `ch17-oop` binary from disassembly alone](/17-re-cpp-gcc/checkpoint.md)
