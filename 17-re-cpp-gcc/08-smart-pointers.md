🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.8 — Smart pointers in assembly: `unique_ptr` vs `shared_ptr` (reference counting)

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## Two philosophies, two binary footprints

Modern C++ smart pointers (`std::unique_ptr` and `std::shared_ptr`) embody two radically different ownership models. This difference is directly reflected in the machine code GCC generates:

- **`unique_ptr`** is a **zero-cost abstraction**. In the vast majority of cases, the compiler reduces it to a simple raw pointer. There's no additional structure in memory, no indirection, no counter. The generated code is identical (or nearly identical) to a `T*` with a `delete` at the right place.

- **`shared_ptr`** involves a **control block** allocated on the heap, an **atomic reference counter**, and conditional destruction mechanics. The generated code is significantly more complex: atomic operations (`lock xadd`, `lock cmpxchg`), indirections via the control block, virtual calls for destruction, and interactions with `weak_ptr`.

For the reverse engineer, recognizing these patterns allows identifying the ownership model without access to source code — high-level design information.

## `std::unique_ptr<T>`: the benevolent ghost

### Memory layout

```
std::unique_ptr<T> (with default deleter):
┌──────────────────────────────────────┐
│  _M_t._M_p  (T*)                     │  offset 0    — pointer to managed object
└──────────────────────────────────────┘
sizeof = 8 bytes (identical to T*)
```

That's all. A single pointer. Thanks to the *Empty Base Optimization* (EBO), the default deleter (`std::default_delete<T>`) occupies no space because it's an empty class. The `sizeof(unique_ptr<T>)` is exactly `sizeof(T*)`.

> ⚠️ **Exception:** if a non-empty custom deleter is used (`unique_ptr<T, MyDeleter>`), it's stored in the object and increases the `sizeof`. For example, a deleter containing a function pointer brings the `sizeof` to 16 bytes. In RE, a 16-byte "unique_ptr" probably contains a custom deleter.

### Construction

```cpp
auto config = std::make_unique<Config>("default", 100, true);
```

GCC generates:

```nasm
; 1. Allocate memory
mov    edi, 48                        ; sizeof(Config)  
call   operator new(unsigned long)@plt  
mov    rbx, rax                       ; rbx = raw pointer  

; 2. Construct the object
mov    rdi, rbx                       ; this = allocated memory  
lea    rsi, [rip+.LC_default]        ; "default"  
mov    edx, 100                       ; maxShapes  
mov    ecx, 1                         ; verbose = true  
call   Config::Config(std::string const&, int, bool)  

; 3. Store the pointer in unique_ptr (on the stack)
mov    QWORD PTR [rbp-0x20], rbx     ; unique_ptr._M_p = raw pointer
```

Step 3 is a simple `mov`. There's no additional structure — the `unique_ptr` is literally the raw pointer stored at a stack location.

> 💡 **In RE:** `std::make_unique<T>(args)` compiles to `operator new(sizeof(T))` + constructor + pointer storage. It's **indistinguishable** from a `new T(args)` stored in a raw pointer. The only difference is that `unique_ptr`'s destructor (or exception cleanup) will call `delete` automatically.

### Accessing the managed object

```cpp
config->name;         // operator->
(*config).verbose;    // operator*
config.get();         // get()
```

All these operations reduce to a raw pointer dereference:

```nasm
; config->name (operator->)
mov    rax, QWORD PTR [rbp-0x20]     ; load raw pointer
; rax points directly to Config, access members normally
lea    rsi, [rax+0x00]               ; &config->name (offset 0 in Config)
```

There's no additional indirection compared to a `T*`. This is the "zero-cost abstraction" in action.

### Move semantics

`unique_ptr` can't be copied, only moved. An `std::move` transfers ownership:

```cpp
auto config2 = std::move(config);
// config is now nullptr
```

```nasm
; std::move on unique_ptr = pointer transfer
mov    rax, QWORD PTR [rbp-0x20]     ; load config._M_p  
mov    QWORD PTR [rbp-0x28], rax     ; config2._M_p = config._M_p  
mov    QWORD PTR [rbp-0x20], 0       ; config._M_p = nullptr  
```

Three instructions. Moving a `unique_ptr` is a pointer copy followed by zeroing the source. No function call, no atomic operation.

> 💡 **RE pattern:** a sequence `mov rax, [src]; mov [dst], rax; mov QWORD PTR [src], 0` is the characteristic `unique_ptr` move pattern. The source null-out is the signature distinguishing a move from a copy.

### Null test

```cpp
if (!config) { /* moved, now null */ }
```

```nasm
cmp    QWORD PTR [rbp-0x20], 0       ; config._M_p == nullptr?  
je     .L_is_null  
```

Direct pointer test, identical to `if (ptr == nullptr)`.

### Destruction

The `unique_ptr` destructor calls `delete` on the pointer if it's non-null:

```nasm
; unique_ptr destructor (often inlined)
mov    rdi, QWORD PTR [rbp-0x20]     ; load _M_p  
test   rdi, rdi                       ; nullptr?  
je     .L_skip_delete  
; Call the object's destructor then free memory
call   Config::~Config()  
mov    rdi, QWORD PTR [rbp-0x20]  
call   operator delete(void*)@plt  
.L_skip_delete:
```

Or more compactly in `-O2` (Config's destructor is inlined):

```nasm
mov    rdi, QWORD PTR [rbp-0x20]  
test   rdi, rdi  
je     .L_done  
call   operator delete(void*)@plt     ; Config has no non-trivial destructor  
.L_done:
```

> 💡 **In RE:** the `unique_ptr` destructor is often inlined into the enclosing function or cleanup landing pad. It manifests as `test rdi, rdi; je .skip; call delete; .skip:` — a null test followed by conditional `delete`. It's indistinguishable from `if (ptr) delete ptr;` on a raw pointer.

### `unique_ptr` with array

```cpp
auto buffer = std::make_unique<char[]>(256);
```

```nasm
mov    edi, 256  
call   operator new[](unsigned long)@plt   ; new[] instead of new  
mov    QWORD PTR [rbp-0x30], rax  
```

The difference from scalar `unique_ptr` is the use of `operator new[]` and `operator delete[]`. The destructor will call `delete[]` instead of `delete`. In RE, the `new`/`new[]` distinction identifies the `unique_ptr` type (scalar vs array).

### Summary: `unique_ptr` is invisible

In summary, `unique_ptr` with the default deleter leaves **no specific structural trace** in the binary. It's strictly equivalent to a raw pointer in terms of generated code. The only difference is an automatic `delete` in the destructor and exception landing pads. In RE, you cannot distinguish a `unique_ptr<T>` from a manually managed `T*` with `new`/`delete` by examining machine code alone. Only symbols (when they exist) or usage patterns (systematic move, absence of copy) can suggest `unique_ptr` usage.

## `std::shared_ptr<T>`: the full machinery

### Memory layout

```
std::shared_ptr<T> (sizeof = 16 bytes):
┌──────────────────────────────────────┐
│  _M_ptr (T*)                         │  offset 0    — pointer to managed object
├──────────────────────────────────────┤
│  _M_refcount (_Sp_counted_base*)     │  offset 8    — pointer to control block
└──────────────────────────────────────┘
```

Two pointers: one to the object, one to the **control block** managing the lifetime. The `sizeof` is always 16, regardless of `T`.

### The control block

The control block is the heart of the `shared_ptr` machinery. It's allocated on the heap and contains reference counters. Its structure varies depending on how the `shared_ptr` was created.

**Case `std::make_shared<T>(args)`:**

`make_shared` allocates the control block and the `T` object in a **single contiguous memory block**. The control block type is `_Sp_counted_ptr_inplace<T, Alloc>`:

```
_Sp_counted_ptr_inplace<T, Alloc> (single allocation):
┌──────────────────────────────────────┐
│  vptr (vtable pointer)               │  offset 0    — control block vtable
├──────────────────────────────────────┤
│  _M_use_count  (atomic<int>)         │  offset 8    — strong references (shared_ptr)
├──────────────────────────────────────┤
│  _M_weak_count (atomic<int>)         │  offset 12   — weak references + 1
├──────────────────────────────────────┤
│  _M_storage:                         │  offset 16   — (padding/alignment possible)
│    T object (constructed in place)   │               — the object itself
└──────────────────────────────────────┘
```

The `T` object is included directly in the control block. A single `operator new` call suffices for everything. This is why `make_shared` is recommended: one allocation instead of two.

**Case `shared_ptr<T>(new T(...))`:**

When a `shared_ptr` is constructed from a raw pointer, the control block is allocated separately. The type is `_Sp_counted_ptr<T*, Deleter>`:

```
_Sp_counted_ptr<T*>:
┌──────────────────────────────────────┐
│  vptr                                │  offset 0
├──────────────────────────────────────┤
│  _M_use_count  (atomic<int>)         │  offset 8
├──────────────────────────────────────┤
│  _M_weak_count (atomic<int>)         │  offset 12
├──────────────────────────────────────┤
│  _M_ptr (T*)                         │  offset 16   — pointer to object (separate)
└──────────────────────────────────────┘

+ T object on the heap (separate allocation)
```

In this case, two allocations occur: one for the `T` object, one for the control block.

> 💡 **In RE:** with `make_shared`, you see a single `operator new` whose size is `sizeof(control block) + sizeof(T)`. With `shared_ptr(new T)`, you see two `operator new`s: one of `sizeof(T)` then a smaller one for the control block. The single allocation size is a direct clue: `16 + sizeof(T)` (or more with alignment).

### The control block's vptr

The control block has its own **vptr** because `_Sp_counted_base` is a polymorphic class. The destructor and deallocation method are virtual:

```
vtable of _Sp_counted_ptr_inplace<Circle, allocator<Circle>>:
  [offset-to-top]  = 0
  [typeinfo]        = &_ZTI...
  [slot 0]          → _M_dispose()    — destroy the T object (call its destructor)
  [slot 1]          → _M_destroy()    — destroy and deallocate the control block itself
  [slot 2]          → destructor
```

In RE, each type `T` used with `make_shared` generates its own `_Sp_counted_ptr_inplace<T>` class with its own vtable. This vtable appears in `.rodata` and its slots point to functions that call `T`'s destructor. This is an additional source of information about instantiated types.

> 💡 **In RE:** `_Sp_counted_ptr_inplace<T>` vtables in `.rodata` reveal the types used with `make_shared`. By examining the `_M_dispose` slot (which calls `T`'s destructor), you can identify type `T` even on a stripped binary.

### Construction with `make_shared`

```cpp
auto sharedCircle = std::make_shared<Circle>(0, 0, 5.0);
```

```nasm
; 1. Allocate control block + object in a single block
mov    edi, 80                        ; sizeof(control block + Circle) with alignment  
call   operator new(unsigned long)@plt  
mov    rbx, rax  

; 2. Initialize the control block
lea    rdx, [rip+_ZTVNSt23_Sp_counted_ptr_inplaceI6CircleSaIS0_EEE+16]  
mov    QWORD PTR [rbx], rdx          ; control block vptr  
mov    DWORD PTR [rbx+8], 1          ; _M_use_count = 1  
mov    DWORD PTR [rbx+12], 1         ; _M_weak_count = 1  

; 3. Construct Circle in the control block's storage
lea    rdi, [rbx+16]                  ; this = &control_block->_M_storage
; ... pass arguments (0, 0, 5.0) in xmm0, xmm1, xmm2 ...
call   Circle::Circle(double, double, double)

; 4. Initialize shared_ptr on the stack
lea    rax, [rbx+16]                  ; address of Circle object  
mov    QWORD PTR [rbp-0x20], rax     ; shared_ptr._M_ptr = &object  
mov    QWORD PTR [rbp-0x18], rbx     ; shared_ptr._M_refcount = &control_block  
```

Key points:
- The single allocation (`operator new(80)`) covers the control block and the `Circle`.  
- Counters are initialized to 1 (one `shared_ptr` and one implicit weak count).  
- The object address (`rbx+16`) and control block address (`rbx`) are stored in the `shared_ptr`'s two fields.

### Copy: atomic increment

```cpp
auto copy1 = sharedCircle;   // copy → increments the counter
```

```nasm
; Copy shared_ptr: copy both pointers + increment use_count
mov    rax, QWORD PTR [rbp-0x20]     ; _M_ptr  
mov    QWORD PTR [rbp-0x30], rax     ; copy._M_ptr = original._M_ptr  

mov    rax, QWORD PTR [rbp-0x18]     ; _M_refcount (control block)  
mov    QWORD PTR [rbp-0x28], rax     ; copy._M_refcount = original._M_refcount  

; Atomically increment use_count
lock xadd DWORD PTR [rax+8], ecx     ; atomic increment of _M_use_count
; (ecx was previously loaded with 1)
```

The **`lock xadd`** instruction is the signature of atomic reference counting. The `lock` prefix guarantees atomicity on multiprocessor architectures. The offset `+8` from the control block is `_M_use_count`.

> 💡 **Fundamental RE pattern:** `lock xadd DWORD PTR [reg+8], ...` or `lock add DWORD PTR [reg+8], 1` is the signature of a `shared_ptr::use_count` increment. The `lock` prefix is the infallible marker of atomic operations, and offset `+8` from a heap pointer points to `_M_use_count` in the control block.

In `-O2`, GCC may use other atomic instructions:

```nasm
; Variant with lock add (simpler, when old value isn't needed)
lock add DWORD PTR [rax+8], 1

; Variant with lock cmpxchg (for certain conditional operations)
lock cmpxchg DWORD PTR [rax+8], ecx
```

### Destruction: atomic decrement and conditional release

The `shared_ptr` destructor decrements the counter and frees the object if the counter reaches zero:

```nasm
; shared_ptr destructor (often inlined)
shared_ptr_destructor:
    mov    rax, QWORD PTR [rbp-0x18]     ; control block
    test   rax, rax
    je     .L_null_ptr                     ; empty shared_ptr → nothing to do

    ; Atomically decrement _M_use_count
    mov    ecx, -1
    lock xadd DWORD PTR [rax+8], ecx     ; old_value = _M_use_count; _M_use_count--
    ; ecx now contains the old value

    cmp    ecx, 1                          ; old value == 1?
    jne    .L_still_alive                  ; no → other shared_ptrs still exist

    ; use_count dropped to 0 → destroy the object
    mov    rdi, rax                        ; this = control block
    mov    rax, QWORD PTR [rdi]           ; control block vptr
    call   QWORD PTR [rax+0x10]          ; virtual call to _M_dispose()
                                           ; → calls T's destructor

    ; Decrement _M_weak_count
    mov    rax, QWORD PTR [rbp-0x18]
    mov    ecx, -1
    lock xadd DWORD PTR [rax+12], ecx    ; _M_weak_count--
    cmp    ecx, 1
    jne    .L_weak_alive

    ; weak_count also at 0 → destroy the control block
    mov    rdi, rax
    mov    rax, QWORD PTR [rdi]
    call   QWORD PTR [rax+0x18]          ; virtual call to _M_destroy()
                                           ; → frees the control block (operator delete)

.L_weak_alive:
.L_still_alive:
.L_null_ptr:
```

This destructor is rich in RE information:

1. **`lock xadd [rax+8], ecx` with `ecx = -1`**: atomic decrement of `_M_use_count`. The old value is retrieved in `ecx`.

2. **`cmp ecx, 1; jne`**: if the old value was 1, the new counter is 0 → this is the last `shared_ptr`, the object must be destroyed.

3. **`call [rax+0x10]`**: virtual call to `_M_dispose()` via the control block vtable. This function calls `T`'s destructor.

4. **`lock xadd [rax+12], ecx`**: atomic decrement of `_M_weak_count` (offset 12).

5. **`call [rax+0x18]`**: virtual call to `_M_destroy()`. This function frees the control block itself.

> 💡 **In RE:** the `shared_ptr` destructor is one of the most verbose and most recognizable patterns. The two `lock xadd` (offsets 8 and 12), the two comparisons with 1, and the two virtual calls via the control block vtable form a unique fingerprint. If you see this pattern, the object is a `shared_ptr`.

### `shared_ptr` move

Moving a `shared_ptr` **doesn't touch the counters** — it's a simple pointer transfer:

```nasm
; auto sp2 = std::move(sp1);
mov    rax, QWORD PTR [rbp-0x20]     ; sp1._M_ptr  
mov    QWORD PTR [rbp-0x30], rax     ; sp2._M_ptr = sp1._M_ptr  
mov    rax, QWORD PTR [rbp-0x18]     ; sp1._M_refcount  
mov    QWORD PTR [rbp-0x28], rax     ; sp2._M_refcount = sp1._M_refcount  
mov    QWORD PTR [rbp-0x20], 0       ; sp1._M_ptr = nullptr  
mov    QWORD PTR [rbp-0x18], 0       ; sp1._M_refcount = nullptr  
```

No `lock`, no atomic operation. The move is as fast as copying two pointers + zeroing the source.

> 💡 **RE pattern:** copying two consecutive QWORDs followed by zeroing the sources (four `mov`s, two to `0`) is a `shared_ptr` move. The absence of `lock` operations distinguishes it from a copy.

### `shared_ptr::use_count()`

```cpp
std::cout << sharedCircle.use_count() << std::endl;
```

```nasm
mov    rax, QWORD PTR [rbp-0x18]     ; control block  
mov    eax, DWORD PTR [rax+8]        ; load _M_use_count (non-atomic read suffices)  
```

Reading `use_count()` is a simple memory read at offset 8 of the control block. No `lock` needed for the read on x86-64 (aligned reads are already atomic on this architecture).

## `std::weak_ptr<T>`

### Memory layout

```
std::weak_ptr<T> (sizeof = 16 bytes):
┌──────────────────────────────────────┐
│  _M_ptr (T*)                         │  offset 0    — pointer to object (may be invalid)
├──────────────────────────────────────┤
│  _M_refcount (_Sp_counted_base*)     │  offset 8    — pointer to control block
└──────────────────────────────────────┘
```

The layout is **identical** to `shared_ptr`'s. The difference is semantic: creating a `weak_ptr` increments `_M_weak_count` (offset 12) instead of `_M_use_count` (offset 8).

### Creation from a `shared_ptr`

```cpp
std::weak_ptr<Circle> weakRef = sharedCircle;
```

```nasm
; Copy pointers
mov    rax, QWORD PTR [rbp-0x20]     ; shared._M_ptr  
mov    QWORD PTR [rbp-0x40], rax     ; weak._M_ptr  

mov    rax, QWORD PTR [rbp-0x18]     ; shared._M_refcount  
mov    QWORD PTR [rbp-0x38], rax     ; weak._M_refcount  

; Increment _M_weak_count (not use_count!)
lock add DWORD PTR [rax+12], 1       ; _M_weak_count++ (offset 12)
```

> 💡 **RE pattern:** `lock add [rax+12], 1` (offset 12) = weak count increment = `weak_ptr` construction. Compare with `lock add [rax+8], 1` (offset 8) = use count increment = `shared_ptr` copy. The offset in the control block distinguishes the two operations.

### `weak_ptr::lock()`

```cpp
if (auto locked = weakRef.lock()) {
    // use locked (which is a shared_ptr)
}
```

`lock()` attempts to promote the `weak_ptr` to a `shared_ptr`. It fails if the object has already been destroyed (`use_count == 0`). GCC generates a compare-and-swap loop:

```nasm
; weak_ptr::lock() — atomic promotion attempt
    mov    rax, QWORD PTR [rbp-0x38]     ; control block
    test   rax, rax
    je     .L_expired

.L_cas_loop:
    mov    ecx, DWORD PTR [rax+8]        ; load current use_count
    test   ecx, ecx
    je     .L_expired                      ; use_count == 0 → object destroyed

    ; Attempt atomic increment: CAS(use_count, ecx, ecx+1)
    lea    edx, [rcx+1]                   ; new value = use_count + 1
    lock cmpxchg DWORD PTR [rax+8], edx  ; if [rax+8] == ecx: [rax+8] = edx
    jne    .L_cas_loop                    ; CAS failed (concurrent) → retry

    ; CAS succeeded → build the result shared_ptr
    mov    rax, QWORD PTR [rbp-0x40]     ; weak._M_ptr
    mov    QWORD PTR [rbp-0x50], rax     ; locked._M_ptr
    mov    rax, QWORD PTR [rbp-0x38]
    mov    QWORD PTR [rbp-0x48], rax     ; locked._M_refcount
    jmp    .L_lock_done

.L_expired:
    ; Object is destroyed, return an empty shared_ptr
    mov    QWORD PTR [rbp-0x50], 0       ; locked._M_ptr = nullptr
    mov    QWORD PTR [rbp-0x48], 0       ; locked._M_refcount = nullptr

.L_lock_done:
```

> 💡 **RE pattern:** a `lock cmpxchg` loop on offset 8 of a control block, with a zero test as abandonment condition, is the signature of `weak_ptr::lock()`. The CAS (Compare-And-Swap) is necessary to handle the concurrent case: another thread could destroy the last `shared_ptr` between the read and the increment.

### `weak_ptr::expired()`

```cpp
bool isExpired = weakRef.expired();
```

```nasm
mov    rax, QWORD PTR [rbp-0x38]     ; control block  
mov    eax, DWORD PTR [rax+8]        ; _M_use_count  
test   eax, eax  
sete   al                             ; al = (use_count == 0)  
```

Simple null test of the strong reference counter.

## Comparative summary: `unique_ptr` vs `shared_ptr`

| Aspect | `unique_ptr<T>` | `shared_ptr<T>` |  
|--------|-----------------|-----------------|  
| sizeof | 8 (= `T*`) | 16 (ptr + control block) |  
| Control block | **None** | Heap, with atomic counters |  
| Construction | `new` + pointer storage | `new` + init control block + counters |  
| Copy | **Forbidden** (compilation error) | Copy + `lock xadd [cb+8]` |  
| Move | Pointer copy + null source | Copy both ptrs + null source, **no `lock`** |  
| Access (`->`, `*`) | Direct dereference | Direct dereference (identical) |  
| Destruction | `test ptr; je skip; delete` | `lock xadd -1; cmp 1; je dispose` |  
| Typical generated code | Identical to `T*` | ~20 more instructions (atomics) |  
| Recognizable in RE? | **No** (invisible) | **Yes** (lock, control block, vtable) |

## Impact of optimizations

### `unique_ptr` in `-O2`

In `-O2`, `unique_ptr` is almost systematically reduced to a raw pointer. The destructor is inlined, moves are optimized, and the final code is indistinguishable from manual memory management. The optimizer can even eliminate the pointer's stack storage if the lifetime is entirely contained in registers.

### `shared_ptr` in `-O2`

`shared_ptr` optimizations are more limited because atomic operations are memory barriers the compiler can't freely reorder. However, GCC applies some optimizations:

- **Copy elision**: if a temporary `shared_ptr` is immediately transferred (copy elision, NRVO), the counter increment and decrement are eliminated.  
- **Atomic operation fusion**: consecutive increments and decrements on the same control block can be fused (increment by 2 instead of two increments by 1).  
- **Fast path inlining**: the `use_count == 1` test in the destructor is often inlined, with a function call only for the actual destruction case.

In `-O2`, the destructor pattern is often more compact:

```nasm
; Optimized shared_ptr destructor
mov    rdi, QWORD PTR [rbp-0x18]     ; control block  
test   rdi, rdi  
je     .L_done  
lock sub DWORD PTR [rdi+8], 1        ; _M_use_count-- (lock sub instead of lock xadd)  
jne    .L_done                        ; not zero → done  
; Zero → call cleanup routine
call   std::_Sp_counted_base::_M_release()  ; handles dispose + weak_count + destroy
.L_done:
```

The `lock sub` followed by `jne` (zero flag test) is the optimized version of the `lock xadd` + `cmp 1` pattern.

> 💡 **In RE (`-O2`):** the compact pattern `lock sub DWORD [reg+8], 1; jne .skip; call _M_release` is the optimized form of the `shared_ptr` destructor. `_M_release` is a `libstdc++` function that handles all the dispose/destroy logic.

## `shared_ptr` in containers

When a `shared_ptr` is stored in a `std::vector`, every vector operation interacts with reference counters:

- **`push_back`**: copies the `shared_ptr` → `lock xadd` to increment.  
- **`erase` / `clear`**: destroys the `shared_ptr` → `lock xadd` (or `lock sub`) to decrement.  
- **Reallocation**: moves all elements to a new buffer → no `lock` (move doesn't touch counters).  
- **Vector destruction**: decrements the counter of each element.

In RE, a `std::vector<std::shared_ptr<T>>` manifests as:
- 16-byte elements in the vector buffer (scale factor 4 in `sar rax, 4` for `size()`).  
- `lock` operations on offsets 8 and 12 of control blocks during insertions and removals.  
- Calls to `_M_dispose` / `_M_release` in the vector destructor.

## Aliasing constructor

The aliasing constructor of `shared_ptr` allows creating a `shared_ptr` pointing to a sub-object while sharing ownership with an existing `shared_ptr`:

```cpp
struct Outer { Inner inner; };  
auto outer = std::make_shared<Outer>();  
std::shared_ptr<Inner> innerPtr(outer, &outer->inner);  // aliasing  
```

In assembly, the aliasing constructor copies the source `shared_ptr`'s control block but uses a different pointer for `_M_ptr`:

```nasm
; Aliasing constructor
lea    rax, [rbx+offset_of_inner]     ; address of sub-object  
mov    QWORD PTR [rbp-0x30], rax     ; new_sp._M_ptr = &outer->inner  
mov    rax, QWORD PTR [rbp-0x18]     ; outer_sp._M_refcount  
mov    QWORD PTR [rbp-0x28], rax     ; new_sp._M_refcount = outer_sp._M_refcount  
lock add DWORD PTR [rax+8], 1        ; _M_use_count++  
```

> 💡 **In RE:** if you see a `shared_ptr` whose `_M_ptr` doesn't point to the start of the allocated block (the address doesn't match `control_block + 16` for a `make_shared`), it's probably an aliasing constructor. The pointer targets a sub-object of the actually managed object.

## Summary of patterns to recognize

| Assembly pattern | Meaning |  
|------------------|---------|  
| 8-byte object = one pointer, `test; je; delete` | `unique_ptr` (or raw pointer with delete) |  
| Pointer copy + source null-out | `unique_ptr` move |  
| 16-byte object = two pointers | `shared_ptr` or `weak_ptr` |  
| `lock xadd DWORD [reg+8], 1` or `lock add DWORD [reg+8], 1` | `shared_ptr` copy (increments use_count) |  
| `lock xadd DWORD [reg+12], 1` or `lock add DWORD [reg+12], 1` | `weak_ptr` construction (increments weak_count) |  
| `lock xadd DWORD [reg+8], -1; cmp old, 1; je dispose` | `shared_ptr` destructor |  
| `lock sub DWORD [reg+8], 1; jne skip; call _M_release` | Optimized `shared_ptr` destructor (`-O2`) |  
| `lock cmpxchg` loop on `[reg+8]` with zero test | `weak_ptr::lock()` (CAS loop) |  
| `mov eax, [reg+8]; test eax, eax; sete al` | `weak_ptr::expired()` |  
| Copy of two QWORDs + zero both sources | `shared_ptr` move (no lock) |  
| Single allocation of size `16 + sizeof(T)` + init counters to 1 | `make_shared<T>()` |  
| Vtable in `.rodata` with `_M_dispose` / `_M_destroy` slots | `shared_ptr` control block (identifies type T) |  
| `operator new[]` + storage in 8-byte object | `make_unique<T[]>(N)` |

---


⏭️ [C++20 coroutines: recognizing the frame and state machine pattern](/17-re-cpp-gcc/09-coroutines-cpp20.md)
