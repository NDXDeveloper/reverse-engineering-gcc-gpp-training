🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.5 — Recognizing GCC structures: C++ vtables, RTTI, exceptions

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## Why this section?

Until now, the examples in this chapter have relied mainly on C code, where the disassembly translates relatively directly into control structures and function calls. C++ compiled with GCC/G++ introduces an additional layer of complexity: the compiler generates **structural metadata** invisible in the source code but omnipresent in the binary — vtables, RTTI, exception tables. These artifacts are not executable code in the usual sense: they are **data tables** inserted in specific sections, which the C++ runtime uses to implement polymorphism, dynamic type identification, and stack unwinding during exceptions.

For an analyst who does not recognize them, these structures appear as opaque data blocks studded with pointers. For an analyst who masters them, they are a mine of information: they reveal the class hierarchy, the type names (even in a partially stripped binary), and the architecture of error handlers.

This section teaches you to identify and interpret them in Ghidra. Chapter 17 will deepen these concepts with a systematic analysis; here, the goal is to give you the recognition keys so you're not thrown off when you encounter them in your analyses.

> 💡 **Reference binary** — The examples in this section use the `ch08-oop_O0` binary (C++ compiled without optimization, with symbols). Compile it if not already done:  
> ```bash  
> cd binaries/ch08-oop/  
> make all  
> ```

---

## GCC's C++ object model: overview

GCC implements the C++ object model according to the **Itanium C++ ABI** specification, which is the de facto standard on Linux, macOS, and most Unix platforms. This ABI precisely defines how C++ language concepts are translated into binary structures: object memory layout, symbol-name encoding (name mangling), vtable format, RTTI format, and exception-handling mechanism.

Three Itanium ABI artifacts are particularly important for reverse engineering:

1. **Vtables** (virtual tables) — tables of function pointers that implement virtual dispatch (polymorphism).  
2. **RTTI** (Run-Time Type Information) — metadata that describes types and inheritance relationships, used by `dynamic_cast` and `typeid`.  
3. **Exception tables** — structures that describe `try`/`catch` blocks, cleanup functions, and expected exception types.

These three artifacts are interconnected: a vtable contains a pointer to its class's RTTI, and exception tables reference the RTTI to know which exception type a `catch` can intercept.

---

## Vtables

### What is a vtable?

When a C++ class declares at least one `virtual` method, GCC generates a **vtable** (virtual method table) for this class. The vtable is an array of function pointers stored in the `.rodata` section (or `.data.rel.ro` if the pointers require relocation). Each vtable entry points to the concrete implementation of a virtual method for this class.

At execution, each instance of a class with virtual methods contains a hidden pointer — the **vptr** (virtual pointer) — located at the very start of the object in memory (offset 0). This vptr points to the vtable of the object's real class. When the code calls a virtual method, it follows the vptr to find the vtable, then indexes into the vtable to get the address of the method to call. It's this indirection mechanism that enables polymorphism.

### Anatomy of a GCC vtable

The structure of a vtable according to the Itanium ABI is as follows (for a simple-inheritance class):

```
Offset    Content
──────    ───────────────────────────────────────
-0x10     offset-to-top (0 for the base class)
-0x08     pointer to the class's RTTI
 0x00  ←  address pointed to by the vptr
          pointer to the 1st virtual method
+0x08     pointer to the 2nd virtual method
+0x10     pointer to the 3rd virtual method
  ...     ...
```

The object's vptr points to **offset 0x00** of this structure — that is, to the first method pointer. The two entries at negative offsets (offset-to-top and RTTI pointer) precede the vtable's entry point. It's a crucial detail: when you examine a vtable in Ghidra, the RTTI pointer is located **before** the method pointers, at address `vtable - 8`.

The **offset-to-top** is 0 for a class that is not a secondary base in multiple inheritance. For multiple inheritance, it indicates the offset to apply to the `this` pointer to find the beginning of the complete object. Initially, you can ignore it — it's 0 in the vast majority of simple cases.

### Recognizing a vtable in Ghidra

In Ghidra, vtables appear in the Listing as sequences of **aligned pointers** in `.rodata` or `.data.rel.ro`. If the binary has symbols, Ghidra labels them with the `vtable for` prefix followed by the class name (or the mangled `_ZTV` symbol). If the binary is stripped, you'll see a sequence of `addr` (pointers) without an explicit label.

Here is how a typical vtable appears in Ghidra's Listing for a `Dog` class that inherits from `Animal`:

```
                     vtable for Dog
.rodata:00402040     addr       0x0                      ; offset-to-top
.rodata:00402048     addr       typeinfo for Dog          ; RTTI pointer
.rodata:00402050     addr       Dog::speak               ; 1st virtual method
.rodata:00402058     addr       Dog::~Dog                ; virtual destructor (complete)
.rodata:00402060     addr       Dog::~Dog                ; virtual destructor (deleting)
```

A few observations:

**Two destructors** — GCC systematically generates two entries for the virtual destructor: the *complete object destructor* (which destroys the object but does not free memory) and the *deleting destructor* (which destroys the object and calls `operator delete`). It's an Itanium ABI artifact you'll see in every vtable of a class with a virtual destructor. The matching mangled symbols are `_ZN3DogD1Ev` (D1, complete) and `_ZN3DogD0Ev` (D0, deleting).

**Inherited methods** — If `Dog` doesn't redefine a virtual method inherited from `Animal`, `Dog`'s vtable will contain a pointer to `Animal`'s implementation. By comparing the vtables of the base class and the derived class, you can identify which methods are overridden (the pointers differ) and which are inherited as is (the pointers are identical).

**Abstract classes** — If a virtual method is pure (`= 0`), the matching vtable entry points to `__cxa_pure_virtual`, a C++ runtime function that displays an error and terminates the program. The presence of this address in a vtable immediately signals an abstract class.

### Identifying vtables in a stripped binary

Without symbols, vtables are not labeled. But they remain identifiable by their structural characteristics:

- They're found in `.rodata` or `.data.rel.ro`.  
- They start with an integer 0 (or a small negative integer for multiple inheritance) followed by a pointer to `.rodata` (the RTTI).  
- They contain a sequence of pointers to `.text` (the virtual methods).  
- Constructors detected in `.text` contain code that writes a constant pointer (the vptr) at the beginning of the `this` object. Look for patterns like `MOV QWORD PTR [RDI], 0x402050` in constructors — the constant is the vtable's address.

In Ghidra, the most effective strategy for finding vtables in a stripped binary is to locate constructors (which initialize the vptr) and follow the pointers. Constructors are often identifiable because they call `operator new` or are called with a freshly allocated object, and they systematically write a constant at the beginning of the object.

### Annotating vtables in Ghidra

Once a vtable is identified, you can annotate it efficiently:

1. **Create a label** — Place the cursor on the first method entry (not on the offset-to-top) and create a label (`L`) named by convention `vtable_ClassName` or `vftable_ClassName`.

2. **Type the entries** — Each entry is a function pointer. Apply the `pointer` type to each slot so that Ghidra displays target addresses as navigable references.

3. **Create a Plate comment** — Add a plate comment above the vtable with the method index:
   ```
   vtable for Dog
   [0] speak()
   [1] ~Dog() (complete)
   [2] ~Dog() (deleting)
   ```

4. **Create a structure** — For large-scale projects, create a `struct vtable_Dog` type in the Data Type Manager with a function-pointer field for each slot. Apply this structure to the vtable's address to get a named display.

---

## RTTI (Run-Time Type Information)

### What is RTTI?

RTTI is a set of metadata that GCC inserts in the binary for each polymorphic class (that is, each class having at least one virtual method). This metadata allows the C++ runtime to perform dynamic type checks via `dynamic_cast` and `typeid`.

RTTI is one of the most valuable information sources in C++ binary reverse engineering, because it contains **class names in clear**, even in a stripped binary. Stripping removes the `.symtab` table (function and variable names), but the RTTI is stored in `.rodata` and is part of the program's semantics — removing it would break `dynamic_cast` and `typeid`. The only way to remove it is to compile with `-fno-rtti`, which is relatively rare in standard C++ programs (it prevents using `dynamic_cast` and `catch` by type).

### RTTI structure according to the Itanium ABI

RTTI is implemented as a hierarchy of `type_info` structures. The Itanium ABI defines several classes derived from `type_info` according to the class type:

**`__class_type_info`** — for classes without a base (root classes of the hierarchy). Structure:

```
Offset    Field                    Content
──────    ─────                    ───────
0x00      vtable ptr               pointer to __class_type_info's vtable
0x08      __type_name              pointer to the class's mangled-name string
```

**`__si_class_type_info`** — for single-inheritance non-virtual classes (*si* = single inheritance). Structure:

```
Offset    Field                    Content
──────    ─────                    ───────
0x00      vtable ptr               pointer to __si_class_type_info's vtable
0x08      __type_name              pointer to the mangled name
0x10      __base_type              pointer to the parent class's type_info
```

**`__vmi_class_type_info`** — for multiple-inheritance or virtual cases (*vmi* = virtual/multiple inheritance). A more complex structure containing an array of base descriptors.

### Recognizing RTTI in Ghidra

If the binary has symbols, Ghidra labels RTTI structures with the `typeinfo for` prefix (or the mangled `_ZTI` symbol) and name strings with `typeinfo name for` (or `_ZTS`).

In the Listing, the RTTI of a `Dog` class inheriting from `Animal` looks like this:

```
                     typeinfo name for Dog
.rodata:00402100     ds         "3Dog"                   ; mangled name (length + name)

                     typeinfo for Dog
.rodata:00402108     addr       vtable for __si_class_type_info + 0x10
.rodata:00402110     addr       typeinfo name for Dog     ; pointer to "3Dog"
.rodata:00402118     addr       typeinfo for Animal       ; pointer to parent RTTI
```

The mangled-name format is compact: `3Dog` means "a 3-character string: Dog". For a nested namespace, you'd see for example `N4Game6PlayerE` (namespace `Game`, class `Player`). Demangling follows the Itanium rules we covered with `c++filt` in Chapter 7.

### Exploiting RTTI to reconstruct the class hierarchy

RTTI is the keystone of class-hierarchy reconstruction in a C++ binary. The procedure is:

**List all RTTI** — In Ghidra, use **Search → For Strings** and look for mangled-name patterns. Typeinfo names are short strings with the `<length><name>` format. Alternatively, look for references to `__si_class_type_info` or `__class_type_info` in the Listing — each RTTI structure points to the vtable of one of these types.

**Follow base pointers** — Each `__si_class_type_info` contains a pointer to the RTTI of its parent class. By following these pointers, you reconstruct inheritance chains. `__class_type_info` entries (without a base pointer) are the roots of the hierarchy.

**Link RTTI and vtables** — Each vtable contains a pointer to its class's RTTI (at offset -8 relative to the vtable's entry point). Starting from a vtable, you can reach the RTTI and thus the class name. Starting from the RTTI, you can find the vtables by looking for cross-references to the RTTI.

In Ghidra, this exploration is done efficiently via cross-references:

1. Locate an RTTI (for example via a name string).  
2. Press `X` to see all references to this RTTI.  
3. Among the references, identify the one coming from a vtable (in `.rodata` or `.data.rel.ro`, at offset -8 of a sequence of pointers to `.text`).  
4. The vtable gives you the list of virtual methods.  
5. The RTTI gives you the class name and the link to the parent class.

> 💡 **Tip for stripped binaries** — Even without symbols, RTTI allows you to recover class names. It's often the first reflex when opening a stripped C++ binary: look for strings matching typeinfo names. If the binary was compiled with `-fno-rtti`, this information is absent, but it's an uncommon case — you can detect it by the total absence of references to `__class_type_info` and `__si_class_type_info` vtables.

### Visual summary: link between object, vtable, and RTTI

The relationship between an object in memory, its vtable, and its RTTI can be summarized as follows:

```
Object in memory (heap/stack)
┌───────────────────┐
│ vptr ─────────────────────┐
│ field_1           │       │
│ field_2           │       │
│ ...               │       │
└───────────────────┘       │
                            ▼
Vtable (.rodata)            
┌──────────────────┐       
│ offset-to-top (0)        
│ RTTI ptr ──────────────────┐
├──────────────────┤  ← vptr points here
│ ptr method_1     │         │
│ ptr method_2     │         │
│ ptr method_3     │         │
└──────────────────┘         │
                             ▼
RTTI (.rodata)
┌──────────────────┐
│ ptr vtable_type_info 
│ ptr name ("3Dog")│
│ ptr parent_RTTI ─────────→ Animal's RTTI
└──────────────────┘
```

---

## Exception tables

### C++ exception mechanism under GCC

C++ exception handling (`throw`, `try`, `catch`) is implemented by GCC according to the **zero-cost exceptions** model (also called *table-driven*). This model is based on the following principle: in the absence of an exception, the code pays no extra cost at execution (no saved register, no flag test). The cost is paid only when an exception is actually thrown. In exchange, the compiler generates **metadata tables** that describe how to unwind the stack and which `catch` handlers to invoke.

These metadata are split across two ELF sections:

- **`.eh_frame`** — contains the *Call Frame Information* (CFI), which describe how to restore register state at each point of the program. It's the information the stack unwinder uses to go back through the call chain frame by frame. This section exists even in C code (it's used by backtraces), but it's essential for C++ exceptions.

- **`.gcc_except_table`** — contains the *Language-Specific Data Areas* (LSDA), specific to C++. Each function that contains a `try`/`catch` or local objects with destructors has an LSDA describing the protected regions (*call sites*), the actions to execute (call a `catch` handler or a cleanup/destructor), and the expected exception types.

### Recognizing exception tables in Ghidra

Ghidra automatically parses `.eh_frame` during analysis (via the **GCC Exception Handlers** analyzer mentioned in section 8.2). The result is visible in several ways:

**In the Symbol Tree** — *personality routine* functions appear in the imports. The most common is `__gxx_personality_v0`, which is GCC's C++ personality routine. Its presence in the imports confirms the binary uses C++ exceptions.

**In the Listing** — Functions that throw exceptions contain calls to `__cxa_allocate_exception` (allocating the exception object), `__cxa_throw` (throwing the exception), and possibly `__cxa_begin_catch` / `__cxa_end_catch` (entering and exiting a `catch` block).

A typical `throw` pattern in the Listing:

```asm
mov     edi, 0x8                    ; exception size (sizeof(std::runtime_error))  
call    __cxa_allocate_exception    ; allocates the exception object  
; ... exception-object initialization ...
mov     edx, offset _ZNSt13runtime_errorD1Ev  ; destructor  
mov     esi, offset _ZTISt13runtime_error     ; typeinfo (RTTI) of the exception  
mov     rdi, rax                    ; pointer to the exception object  
call    __cxa_throw                 ; throws the exception (never returns)  
```

Notice that `__cxa_throw` takes the **RTTI** of the exception type as a parameter — that's how the runtime knows which `catch` block can intercept it.

**In the Decompiler** — Ghidra represents exceptions in the pseudo-code, but the quality of the representation varies. In the best cases, you'll see explicit calls to `__cxa_throw` with identifiable parameters. The decompiler doesn't rebuild `try`/`catch` blocks in their syntactic C++ form, but the control flow clearly shows normal and exceptional paths.

### Cleanup handlers (local destructors)

Beyond explicit `catch`es, exception tables also serve to guarantee that destructors of local objects are called during stack unwinding. If a function contains local variables of types with destructors (such as `std::string`, `std::vector`, `std::unique_ptr`, or any class with a non-trivial destructor), the compiler generates *cleanup handlers* in the LSDA.

In Ghidra, these cleanup handlers appear as code blocks at the end of the function that call destructors. They are not reachable via normal control flow (you won't see a conditional jump leading to them in the standard flow graph). They are only invoked by the stack-unwinding mechanism.

If you see code blocks apparently "orphaned" at the end of a C++ function in the Function Graph — code that calls destructors but is not connected to any block by an edge — these are very likely cleanup handlers for exceptions.

### What to remember for practical analysis

Exception tables are complex in their internal format, but their exploitation in reverse engineering boils down to a few key observations:

- **The presence of `__gxx_personality_v0`** in the imports confirms the binary uses C++ exceptions.  
- **Calls to `__cxa_throw`** mark exception-throwing points. The second parameter is the RTTI of the thrown type.  
- **Calls to `__cxa_begin_catch` / `__cxa_end_catch`** delimit `catch` blocks.  
- **Orphan blocks** in the Function Graph are cleanup handlers.  
- **The `.gcc_except_table` section** can be manually inspected in the Listing for advanced cases, but it's generally not necessary for functional analysis — the useful information is visible in the decompiled code.

---

## Quick recognition: summary of clues in Ghidra

Here is a summary table of indicators that signal the presence of these GCC structures in a binary opened in Ghidra:

| Indicator | What it signals | Where to find it |  
|---|---|---|  
| Symbols `_ZTV*` or labels `vtable for *` | Vtables — the binary contains polymorphic classes | Symbol Tree → Labels, or Listing in `.rodata` |  
| Symbols `_ZTI*` or labels `typeinfo for *` | RTTI — type metadata available | Symbol Tree → Labels, or Listing in `.rodata` |  
| Symbols `_ZTS*` or labels `typeinfo name for *` | Class names in clear | Defined Strings, or Listing in `.rodata` |  
| Strings in the format `<n><name>` (`3Dog`, `6Animal`) | Mangled typeinfo names | Search → For Strings |  
| Import `__gxx_personality_v0` | The binary uses C++ exceptions | Symbol Tree → Imports |  
| Imports `__cxa_throw`, `__cxa_begin_catch` | Code that throws / catches exceptions | Symbol Tree → Imports |  
| Import `__cxa_pure_virtual` | At least one abstract class (pure virtual method) | Symbol Tree → Imports |  
| Imports `__dynamic_cast` | The code uses `dynamic_cast` | Symbol Tree → Imports |  
| Sections `.eh_frame`, `.gcc_except_table` | Exception tables present | Program Trees |  
| Writing a constant to `[RDI+0]` in a constructor | vptr initialization — the constant is the vtable's address | Listing / Decompiler, in constructor functions |  
| References to `__si_class_type_info`, `__vmi_class_type_info` | RTTI structures for simple / multiple inheritance | Listing in `.rodata`, via XREF |

---

## C++ binary analysis workflow in Ghidra

By combining the techniques described above, here is an efficient workflow to approach a C++ binary in Ghidra:

**1. Verify the presence of C++** — Look at imports in the Symbol Tree. The presence of `__gxx_personality_v0`, `__cxa_throw`, `operator new`, `__dynamic_cast`, or symbols in the `std::` namespace confirms the binary is C++.

**2. Locate vtables** — Look for `_ZTV` symbols or `vtable for` labels in the Symbol Tree. In the absence of symbols, look in `.rodata` for sequences of pointers to `.text` preceded by a pointer to `.rodata` (the RTTI) and a zero (the offset-to-top).

**3. Extract class names from the RTTI** — Look for typeinfo-name strings. Even in a stripped binary, these strings are present if the RTTI was not disabled. List all detected classes.

**4. Reconstruct the inheritance hierarchy** — Follow `__base_type` pointers in `__si_class_type_info` structures to climb inheritance chains. Draw the hierarchy (even on paper) to get an overview.

**5. Identify each class's methods** — For each vtable, note the method pointers. Navigate to each method and rename it with the format `ClassName::method_purpose`. Compare parent and child vtables to distinguish overridden methods from inherited methods.

**6. Locate constructors and destructors** — Constructors initialize the vptr (writing a constant at the beginning of `this`) and call parent constructors. Destructors follow the inverse pattern: they reset the vptr to the current class's vtable (not the derived class's), call members' destructors, then the parent destructor.

**7. Create types in the Data Type Manager** — For each identified class, create a structure in Ghidra with the inferred fields. The first field is always the vptr (type `pointer`), followed by the class's data fields. Apply these structures to `this` parameters of methods.

This workflow will be practiced in depth in Chapter 17 (C++ Reverse Engineering with GCC) and in the practical case of Chapter 22 (Reversing an object-oriented C++ application).

---

## Summary

C++ binaries compiled with GCC contain three categories of structural metadata that any analyst must know how to recognize: vtables (tables of virtual-method pointers, in `.rodata`), RTTI (class names and inheritance relationships, also in `.rodata`), and exception tables (`.eh_frame` and `.gcc_except_table`). These artifacts follow the Itanium C++ ABI specification and are present even in stripped binaries (unless `-fno-rtti` was used for RTTI). Ghidra partially parses them automatically, but knowing how to identify them manually and exploit them to reconstruct the class hierarchy is a fundamental skill for C++ binary analysis.

The next section continues this logic by showing how to use Ghidra's Data Type Manager to concretely reconstruct data structures — `struct`, `class`, `enum` — from the patterns observed in the disassembly.

---


⏭️ [Reconstructing data structures (`struct`, `class`, `enum`)](/08-ghidra/06-reconstructing-structures.md)
