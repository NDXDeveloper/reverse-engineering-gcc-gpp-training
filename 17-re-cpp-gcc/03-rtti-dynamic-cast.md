🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.3 — RTTI (Run-Time Type Information) and `dynamic_cast`

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## What RTTI brings to the reverse engineer

RTTI is a C++ mechanism that allows the program to determine the actual type of a polymorphic object at runtime. For the developer, this manifests through two operators: `typeid` (to query the type) and `dynamic_cast` (to perform a safe cast with type checking).

For the reverse engineer, RTTI is a windfall. GCC generates in the binary **metadata structures** that contain in plaintext the names of all polymorphic classes, the inheritance relationships between them, and sub-object offsets. These structures survive stripping because they're needed at runtime. Knowing how to read them means being able to reconstruct the complete class hierarchy of a C++ binary without access to source code.

> ⚠️ **When RTTI is absent.** The compilation flag `-fno-rtti` disables RTTI generation. In that case, the `typeinfo` structures are replaced by null pointers in vtables, and neither `typeid` nor `dynamic_cast` are available. Some projects (game engines, embedded systems) disable RTTI to reduce binary size. The first reflex in RE is to check whether the typeinfo field of vtables is null or not.

## The Itanium ABI typeinfo structures

The Itanium C++ ABI defines three types of typeinfo structures, each corresponding to a different inheritance scenario. All derive (in the C++ sense) from `std::type_info` and are instantiated by the compiler in `.rodata`.

### `__class_type_info` — class without polymorphic base

This is the simplest structure, used for classes that don't inherit from any other polymorphic class (hierarchy roots). Its memory structure is:

```
_ZTI<class>:
┌─────────────────────────────────────────────┐
│  vptr → vtable of __class_type_info         │  offset 0   (8 bytes)
├─────────────────────────────────────────────┤
│  __name → pointer to _ZTS<class>            │  offset 8   (8 bytes)
└─────────────────────────────────────────────┘
                                                 total: 16 bytes
```

The `vptr` field points to the internal vtable of `__class_type_info` (defined in `libstdc++`), not to the user class's vtable. The `__name` field points to the `_ZTS` string containing the class's mangled name in readable form (for example, `5Shape` for `Shape`).

**Example — `Shape` is the hierarchy root:**

```
_ZTI5Shape:
  [vptr]    → _ZTVN10__cxxabiv117__class_type_infoE+16
  [__name]  → _ZTS5Shape → "5Shape"
```

> 💡 **In RE:** the typeinfo structure's `vptr` pointer points to a `libstdc++` vtable. The address of this vtable identifies the **type of the typeinfo structure itself**, which tells you the class's inheritance type. Three `libstdc++` vtables are to be recognized:  
> - `__class_type_info` → no polymorphic parent class  
> - `__si_class_type_info` → single inheritance  
> - `__vmi_class_type_info` → multiple or virtual inheritance

### `__si_class_type_info` — simple non-virtual inheritance

Used when a class inherits from **a single** polymorphic base, without virtual inheritance. It extends `__class_type_info` with a pointer to the parent class's typeinfo:

```
_ZTI<derived_class>:
┌─────────────────────────────────────────────┐
│  vptr → vtable of __si_class_type_info      │  offset 0
├─────────────────────────────────────────────┤
│  __name → pointer to _ZTS<class>            │  offset 8
├─────────────────────────────────────────────┤
│  __base_type → pointer to _ZTI<parent>      │  offset 16  (8 bytes)
└─────────────────────────────────────────────┘
                                                 total: 24 bytes
```

The `__base_type` field is a pointer to the parent class's `_ZTI` structure. It's a **direct link** in the inheritance hierarchy.

**Example — `Circle` inherits from `Shape`:**

```
_ZTI6Circle:
  [vptr]        → _ZTVN10__cxxabiv120__si_class_type_infoE+16
  [__name]      → _ZTS6Circle → "6Circle"
  [__base_type] → _ZTI5Shape
```

By following the `__base_type` pointer, we reach `_ZTI5Shape`, confirming that `Circle` inherits from `Shape`. By repeating the operation for all typeinfos in the binary, we reconstruct the complete hierarchy.

**Example — inheritance chain `ParseError` → `AppException` → `std::exception`:**

```
_ZTI10ParseError:
  [vptr]        → __si_class_type_info
  [__name]      → "10ParseError"
  [__base_type] → _ZTI12AppException

_ZTI12AppException:
  [vptr]        → __si_class_type_info
  [__name]      → "12AppException"
  [__base_type] → _ZTISt9exception      (std::exception, in libstdc++)
```

The chain of `__base_type` pointers forms a directed graph that **is** the class hierarchy.

### `__vmi_class_type_info` — multiple or virtual inheritance

This is the most complex structure, used for classes with multiple inheritance, virtual inheritance, or both. It contains an array of base descriptors:

```
_ZTI<class>:
┌─────────────────────────────────────────────┐
│  vptr → vtable of __vmi_class_type_info     │  offset 0
├─────────────────────────────────────────────┤
│  __name → pointer to _ZTS<class>            │  offset 8
├─────────────────────────────────────────────┤
│  __flags (unsigned int)                     │  offset 16  (4 bytes)
├─────────────────────────────────────────────┤
│  __base_count (unsigned int)                │  offset 20  (4 bytes)
├═════════════════════════════════════════════╡
│  __base_info[0]:                            │  offset 24
│    __base_type → _ZTI<parent_0>             │    +0  (8 bytes)
│    __offset_flags (long)                    │    +8  (8 bytes)
├─────────────────────────────────────────────┤
│  __base_info[1]:                            │  offset 40
│    __base_type → _ZTI<parent_1>             │    +0
│    __offset_flags (long)                    │    +8
├─────────────────────────────────────────────┤
│  ... (as many entries as __base_count)      │
└─────────────────────────────────────────────┘
```

The specific fields:

**`__flags`** encodes inheritance properties:

| Bit | Mask | Meaning |  
|-----|------|---------|  
| 0 | `0x1` | `__non_diamond_repeat_mask` — a base appears more than once in the hierarchy without diamond |  
| 1 | `0x2` | `__diamond_shaped_mask` — diamond inheritance detected |

**`__base_count`** is the number of direct parent classes.

**`__base_info[i].__offset_flags`** is an 8-byte value encoding both the sub-object offset and flags:

| Bits | Mask | Meaning |  
|------|------|---------|  
| 0 | `0x1` | `__virtual_mask` — virtual inheritance |  
| 1 | `0x2` | `__public_mask` — public inheritance |  
| 8–63 | `>> 8` | Sub-object offset in the complete object (in bytes) |

The offset is stored in the high-order bits (right-shift by 8 to extract). The two least significant bits are the flags.

**Example — `Canvas` inherits from `Drawable` and `Serializable`:**

```
_ZTI6Canvas:
  [vptr]         → __vmi_class_type_info
  [__name]       → "6Canvas"
  [__flags]      = 0x0                (no diamond, no repetition)
  [__base_count] = 2                  (two parent classes)

  __base_info[0]:
    [__base_type]    → _ZTI8Drawable
    [__offset_flags] = 0x0000000000000002
                       offset = 0 >> 8 = 0 (sub-object at offset 0)
                       flags  = 0x2 = public, non-virtual

  __base_info[1]:
    [__base_type]    → _ZTI12Serializable
    [__offset_flags] = 0x0000000000000802
                       offset = 0x802 >> 8 = 0x8 = 8 (sub-object at offset 8)
                       flags  = 0x2 = public, non-virtual
```

This structure tells us that `Canvas` publicly inherits from `Drawable` (sub-object at offset 0) and from `Serializable` (sub-object at offset 8). This is exactly the memory layout we saw in Section 17.2.

## The typeinfo name strings (`_ZTS`)

Each `_ZTI` structure references a `_ZTS` string stored in `.rodata`. This string contains the class name in Itanium mangled format, but **without the `_Z` prefix** — it's directly the `<length><name>` form.

```bash
$ strings oop_O0 | grep -E '^[0-9]+[A-Z][a-z]'
5Shape
6Circle
9Rectangle
8Triangle
8Drawable
12Serializable
6Canvas
6Config
12AppException
10ParseError
12NetworkError
```

These strings are extremely reliable markers in RE because:

1. They're always in `.rodata` (read-only section).  
2. They survive stripping (needed for RTTI at runtime).  
3. Their `<length><name>` format is easy to recognize automatically.  
4. They contain the **exact class name** as it appears in the source code.

> 💡 **First reflex facing an unknown C++ binary:** run `strings binary | grep -oP '^\d+[A-Z]\w+'` to extract all typeinfo name strings. You'll immediately get the list of all polymorphic classes in the program.

For classes in namespaces, the format uses nested mangling:

```
N5MyApp7Network6ClientE     →   MyApp::Network::Client
```

The enclosing `N...E` indicates a qualified name, exactly as in full mangling (see Section 17.1).

## Navigating RTTI in Ghidra

### With symbols

If the binary has its symbols, the most direct method is to search for `_ZTI` in the Symbol Tree:

1. Open the Symbol Tree, filter by `_ZTI`.  
2. For each `_ZTI`, navigate to the corresponding address in the Listing.  
3. Identify the structure type by looking at the vptr: whether it points to `__class_type_info`, `__si_class_type_info`, or `__vmi_class_type_info`.  
4. For `__si_class_type_info`, follow the `__base_type` pointer (offset 16) to go up the hierarchy.  
5. For `__vmi_class_type_info`, read `__base_count` (offset 20) and walk through the `__base_info` array.

### Without symbols (stripped binary)

On a stripped binary, `_ZTI` and `_ZTS` symbols aren't directly visible in the Symbol Tree. But the data is still present in `.rodata`. Here's the procedure:

**Step 1 — Find the typeinfo name strings.** In Ghidra, open the Defined Strings window (Window → Defined Strings) or run a string search. Filter results to find strings in `<number><name>` format (for example `6Circle`, `5Shape`). These strings are the `_ZTS`.

**Step 2 — Trace back to typeinfo structures.** For each `_ZTS` string found, right-click → References → Find References to. The result gives you the address of the `_ZTI` structure referencing this string (the `__name` field at offset 8).

**Step 3 — Identify the typeinfo type.** At the found address, read the QWORD at offset 0 (the typeinfo structure's vptr). This pointer points to a vtable in `libstdc++.so`. You must identify which typeinfo class it belongs to:

- If the target pointer is in the same binary and carries a symbol containing `class_type_info`, it's a `__class_type_info` (root).  
- If the symbol contains `si_class_type_info`, it's single inheritance.  
- If the symbol contains `vmi_class_type_info`, it's multiple/virtual inheritance.

In practice, on a dynamically linked binary, these vtables are in `libstdc++.so` and aren't directly resolved in the binary. You'll see relocation entries. The trick is to note the three distinct addresses appearing as vptrs of the different typeinfo structures, then classify them: the most frequent among simple derived classes is `__si_class_type_info`, roots use `__class_type_info`, and complex cases use `__vmi_class_type_info`.

**Step 4 — Read fields and follow pointers.** Based on the identified type, read fields as described in the structures above. For each `__base_type` pointer, follow it to discover the parent class.

**Step 5 — Build the hierarchy graph.** By connecting all parent-child links, you get the complete inheritance tree.

### Ghidra script to automate extraction

Manual extraction is tedious when the binary contains dozens of classes. Here's the algorithm for a Ghidra script (Java or Python) that automates the process:

```
For each string in .rodata matching /^\d+[A-Z]\w*$/:
    Find references to this string → typeinfo_address + 8
    typeinfo_address = reference - 8
    Read vptr = QWORD[typeinfo_address]
    Read name_ptr = QWORD[typeinfo_address + 8]

    If vptr matches __si_class_type_info:
        parent_ti = QWORD[typeinfo_address + 16]
        Record link: class → parent

    If vptr matches __vmi_class_type_info:
        base_count = DWORD[typeinfo_address + 20]
        For i = 0 to base_count - 1:
            base_ti = QWORD[typeinfo_address + 24 + i*16]
            offset_flags = QWORD[typeinfo_address + 24 + i*16 + 8]
            offset = offset_flags >> 8
            is_virtual = offset_flags & 1
            is_public = (offset_flags >> 1) & 1
            Record link: class → parent_i (offset, virtual, public)

Produce the hierarchy graph
```

This script can be extended to cross-reference results with vtables and produce a complete hierarchy reconstruction, including virtual method names.

## `typeid` in assembly

The `typeid` operator applied to a polymorphic object (via a reference or dereferenced pointer) reads RTTI through the vptr. Here's what GCC generates:

```cpp
const std::type_info& ti = typeid(*shape_ptr);
```

```nasm
; rdi = shape_ptr (Shape*)
mov    rax, QWORD PTR [rdi]          ; rax = vptr  
mov    rax, QWORD PTR [rax-8]        ; rax = typeinfo ptr (offset -8 in the vtable)  
; rax now points to the actual class's _ZTI structure
```

The pattern is simple: load the vptr, then read the QWORD at offset `-8` (one slot before the virtual method slots). This is the vtable's typeinfo pointer field, described in Section 17.2.

For `typeid` on a static type (not via a polymorphic pointer), GCC emits a direct reference to the `_ZTI` structure without going through the vptr:

```cpp
const std::type_info& ti = typeid(Circle);
```

```nasm
lea    rax, [rip+_ZTI6Circle]        ; direct address of the typeinfo
```

The call to `typeid(*ptr).name()` then calls `std::type_info`'s `name()` method, which returns the `__name` pointer of the typeinfo structure — the `_ZTS` string.

> 💡 **In RE:** if you see an access to `[vptr-8]` followed by operations on the result, it's an RTTI access via `typeid`. This indicates the source code uses `typeid` or a feature that depends on it (certain logging implementations, dynamic serialization, etc.).

## `dynamic_cast` in assembly

`dynamic_cast` is C++'s safe cast: it checks at runtime whether the conversion is valid by consulting RTTI. If the conversion fails, it returns `nullptr` (for pointers) or throws a `std::bad_cast` exception (for references).

### The pointer case

```cpp
Circle* c = dynamic_cast<Circle*>(shape_ptr);  
if (c) {  
    // use c
}
```

GCC translates this `dynamic_cast` into a call to the runtime function `__dynamic_cast` defined in `libstdc++`:

```nasm
; shape_ptr is in rdi (already the first argument)
; Prepare __dynamic_cast arguments
mov    rdi, rbx                       ; arg1: source pointer (shape_ptr)  
lea    rsi, [rip+_ZTI5Shape]          ; arg2: typeinfo of source class  
lea    rdx, [rip+_ZTI6Circle]         ; arg3: typeinfo of target class  
mov    ecx, 0                         ; arg4: hint (0 = no additional info)  
call   __dynamic_cast  

; rax = result: cast pointer or NULL
test   rax, rax                       ; check if cast succeeded  
jz     .cast_failed  
; ... use rax as Circle*
```

The signature of `__dynamic_cast` is:

```c
void* __dynamic_cast(
    const void* src_ptr,              // pointer to convert
    const __class_type_info* src_type, // typeinfo of source type
    const __class_type_info* dst_type, // typeinfo of target type
    ptrdiff_t src2dst_offset           // offset hint (-1 = unknown, 0 = no info)
);
```

> 💡 **Key RE pattern:** a `call __dynamic_cast` (or `call __dynamic_cast@plt`) followed by `test rax, rax` and `jz` is the signature of a `dynamic_cast<T*>()`. The two `lea ... _ZTI...` arguments preceding the call give you the source and target types of the cast directly, in plaintext (via their associated `_ZTS` strings). This is extremely high-value information in RE — you know exactly which types the source code was manipulating.

### The reference case

For a `dynamic_cast` on a reference, failure doesn't return `nullptr` but throws `std::bad_cast`. GCC generates slightly different code:

```cpp
Circle& c = dynamic_cast<Circle&>(shape_ref);
```

```nasm
; Same __dynamic_cast call
call   __dynamic_cast  
test   rax, rax  
jnz    .cast_ok  

; Failure → throw std::bad_cast
call   __cxa_allocate_exception       ; allocate the exception object
; ... initialize bad_cast ...
call   __cxa_throw                    ; throw the exception

.cast_ok:
; use rax as Circle&
```

The difference is that the failure path ends with a `__cxa_throw` instead of a simple jump. In RE, if you see `__dynamic_cast` followed by a branch calling `__cxa_throw` with a `bad_cast` type, it's a `dynamic_cast` on a reference.

### `dynamic_cast` optimizations

GCC applies important optimizations to `dynamic_cast`:

**Downcast in a simple hierarchy without virtual inheritance.** If the compiler knows the hierarchy contains no virtual inheritance and the cast is a downcast (from base to derived), it can replace `__dynamic_cast` with a simple vptr comparison:

```nasm
; dynamic_cast<Circle*>(shape_ptr) optimized
mov    rax, QWORD PTR [rdi]            ; load vptr  
lea    rdx, [rip+_ZTV6Circle+16]       ; expected Circle vtable  
cmp    rax, rdx  
jne    .not_circle  
; rdi is a Circle*, use it directly
mov    rax, rdi  
jmp    .done  
.not_circle:
xor    eax, eax                        ; return nullptr
.done:
```

This pattern is faster than the `__dynamic_cast` call and appears frequently in `-O2`. In RE, it looks like a "handmade" type check — comparing the vptr against a known vtable is the sign of an optimized `dynamic_cast` or an explicit type verification.

**Cast to a base.** A `dynamic_cast` to a base class (upcast) is always valid. GCC replaces it with a simple pointer adjustment (identical to a `static_cast`), or even nothing at all if the base is primary.

**Trivial cast.** If the compiler can prove the object's type is already the target type, the `dynamic_cast` is eliminated entirely.

## `static_cast` vs `dynamic_cast` in assembly

It's important to distinguish the two cast types in disassembly:

| Cast | Generated code | Runtime check |  
|------|---------------|---------------|  
| `static_cast<Derived*>(base_ptr)` | Simple pointer adjustment (add/sub) or nothing | **None** — if the type is wrong, undefined behavior |  
| `dynamic_cast<Derived*>(base_ptr)` | Call to `__dynamic_cast` or vptr comparison | **Yes** — returns nullptr or throws bad_cast if invalid |  
| `reinterpret_cast<T*>(ptr)` | Nothing at all (same address) | **None** |

In RE, when you see a pointer used directly without verification or `__dynamic_cast` call, the source code probably used a `static_cast` or `reinterpret_cast`. When you see `__dynamic_cast` or a vptr comparison followed by a null test, it's a `dynamic_cast`.

## Reconstructing the complete hierarchy from RTTI: example

Let's put everything above into practice on the `oop_O2_strip` binary (optimized and stripped). We have no local symbols, but the RTTI structures are present.

**Step 1 — Extract class names:**

```bash
$ strings oop_O2_strip | grep -oP '^\d+[A-Z]\w+'
5Shape
6Circle
9Rectangle
8Triangle
8Drawable
12Serializable
6Canvas
6Config
12AppException
10ParseError
12NetworkError
```

We have 11 polymorphic classes (or more precisely 11 classes whose RTTI is present).

**Step 2 — Locate typeinfo structures in `.rodata`:**

For each string, we search for its references. For example, for `6Circle`, we find the string's address, then the address of the structure pointing to it (8 bytes before the `__name` field).

**Step 3 — Classify each typeinfo:**

By examining each typeinfo structure's vptr, we determine the type:

| Class | Typeinfo type | Reason |  
|-------|--------------|--------|  
| `Shape` | `__class_type_info` | Shape hierarchy root |  
| `Circle` | `__si_class_type_info` | Inherits from Shape only |  
| `Rectangle` | `__si_class_type_info` | Inherits from Shape only |  
| `Triangle` | `__si_class_type_info` | Inherits from Shape only |  
| `Drawable` | `__class_type_info` | Drawable hierarchy root |  
| `Serializable` | `__class_type_info` | Serializable hierarchy root |  
| `Canvas` | `__vmi_class_type_info` | Inherits from Drawable AND Serializable |  
| `AppException` | `__si_class_type_info` | Inherits from std::exception |  
| `ParseError` | `__si_class_type_info` | Inherits from AppException |  
| `NetworkError` | `__si_class_type_info` | Inherits from AppException |  
| `Config` | (no polymorphic typeinfo) | No virtual method |

> Note: `Config` in our binary has no virtual method, so no vtable or typeinfo. It won't appear in RTTI structures. The other 10 classes are polymorphic.

**Step 4 — Follow `__base_type` pointers:**

| Class | `__base_type` points to | Relationship |  
|-------|------------------------|-------------|  
| `Circle` | `_ZTI5Shape` | Circle → Shape |  
| `Rectangle` | `_ZTI5Shape` | Rectangle → Shape |  
| `Triangle` | `_ZTI5Shape` | Triangle → Shape |  
| `ParseError` | `_ZTI12AppException` | ParseError → AppException |  
| `NetworkError` | `_ZTI12AppException` | NetworkError → AppException |  
| `AppException` | `_ZTISt9exception` | AppException → std::exception |

For `Canvas` (type `__vmi_class_type_info`):

| Base | `__base_type` | offset_flags | Offset | Public | Virtual |  
|------|--------------|-------------|--------|--------|---------|  
| #0 | `_ZTI8Drawable` | `0x002` | 0 | yes | no |  
| #1 | `_ZTI12Serializable` | `0x802` | 8 | yes | no |

**Step 5 — Draw the hierarchy:**

```
std::exception
    └── AppException
            ├── ParseError
            └── NetworkError

Shape (abstract)
    ├── Circle
    ├── Rectangle
    └── Triangle

Drawable                Serializable
    └───────┬───────────────┘
          Canvas
```

All this information was extracted from a **stripped** binary solely through RTTI structures.

## RTTI and exceptions: the hidden link

RTTI is not only used by `typeid` and `dynamic_cast`. It's also essential to the C++ exception mechanism. When an exception is thrown with `throw`, the runtime must determine which `catch` matches the exception type — which requires a type comparison at runtime, exactly like `dynamic_cast`.

This is why even a program compiled with `-fno-rtti` **preserves the typeinfo structures of classes used as exceptions**. The compiler can't remove them without breaking the exception mechanism. In practice, this means:

- A `-fno-rtti` binary that uses exceptions will have typeinfo for exception classes, but not for other classes.  
- A `-fno-rtti -fno-exceptions` binary will have no typeinfo at all.  
- A default binary (no special flags) will have typeinfo for all polymorphic classes AND all exception classes (even non-polymorphic ones if they're thrown).

> 💡 **In RE:** if a binary seems compiled with `-fno-rtti` (vtables have a `0` at offset -8 instead of a typeinfo pointer) but you still find typeinfo structures for certain classes, those are the exception classes. This gives you at minimum the program's exception hierarchy.

## Detecting the presence or absence of RTTI

Here's a quick procedure to determine if a binary contains RTTI:

```bash
# 1. Search for typeinfo symbols (with symbols)
$ nm -C binary | grep 'typeinfo for'

# 2. Search for typeinfo name strings (even stripped)
$ strings binary | grep -cP '^\d+[A-Z]'

# 3. Check the typeinfo field in a known vtable
#    (if the QWORD at offset -8 from the slot start is 0 → no RTTI)
$ objdump -s -j .rodata binary | less
```

If command 2 returns significant results, RTTI is present. If it returns 0 or very few results (only strings for standard exceptions), RTTI is probably disabled.

## Summary of patterns to recognize

| Pattern | Meaning |  
|---------|---------|  
| `mov rax, [vptr]; mov rax, [rax-8]` | RTTI access via vptr (`typeid`) |  
| `lea rsi, [_ZTI...]; lea rdx, [_ZTI...]; call __dynamic_cast` | `dynamic_cast` with identifiable source and target types |  
| `call __dynamic_cast; test rax, rax; jz ...` | `dynamic_cast<T*>()` — failure branch = nullptr |  
| `call __dynamic_cast; test rax, rax; jnz .ok; call __cxa_throw` | `dynamic_cast<T&>()` — throws bad_cast on failure |  
| `cmp [rdi], vtable_addr; jne ...` | Optimized `dynamic_cast` (direct vptr comparison) |  
| String `<number><ClassName>` in `.rodata` | Typeinfo name (`_ZTS`) — class name in plaintext |  
| QWORD pointing to `__si_class_type_info` vtable, followed by string ptr, followed by `_ZTI` ptr | Simple inheritance typeinfo structure |  
| QWORD pointing to `__vmi_class_type_info` vtable, followed by string ptr, flags, count, base array | Multiple inheritance typeinfo structure |  
| `__cxa_pure_virtual` in vtable slot + typeinfo with `__class_type_info` | Abstract root class |

---


⏭️ [Exception handling (`.eh_frame`, `.gcc_except_table`, `__cxa_throw`)](/17-re-cpp-gcc/04-exception-handling.md)
