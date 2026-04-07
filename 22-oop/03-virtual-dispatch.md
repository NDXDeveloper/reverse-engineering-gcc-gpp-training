🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 22.3 — Understanding Virtual Dispatch: From Vtable to Method Call

> 🛠️ **Tools used**: Ghidra, GDB (+ GEF/pwndbg), `objdump -M intel`, Frida  
> 📦 **Binaries**: `oop_O0`, `oop_O2`, `oop_O2_strip`  
> 📚 **Prerequisites**: Section 22.1 (vtables and hierarchy), Section 22.2 (plugins), Chapter 17.2 (vtable object model)

---

## Introduction

In the previous sections, you reconstructed the class hierarchy and understood how plugins are loaded. But a central question remains: when the application writes `processor->process(input, len, output, cap)`, what **actually** happens at the processor level?

The source code contains no `if` to determine whether `processor` is an `UpperCaseProcessor`, a `Rot13Processor`, or a `XorCipherProcessor`. The compiler does not know either — the concrete type is only known at runtime. Yet the correct method is called every time. This mechanism, **virtual dispatch**, is the heart of C++ polymorphism, and it is also one of the most frequent patterns in C++ binary reverse engineering.

This section dissects this mechanism from every angle: raw assembly, Ghidra view, dynamic tracing, and compiler optimizations that can transform — or even eliminate — it.

---

## Anatomy of a virtual call in assembly

### The canonical pattern

Let's take the call `processor->process(input, in_len, output, out_cap)` in the `Pipeline::execute()` method. At `-O0`, GCC produces readable and predictable assembly.

The `processor` pointer is of type `Processor*`. The call goes through five steps:

```asm
; ── Step 1: load the this pointer ──────────────────────────
; processor is stored on the stack or in a register.
; Here, assume it is in a local variable at [rbp-0x28].
mov    rdi, QWORD PTR [rbp-0x28]       ; rdi = processor (= this)

; ── Step 2: read the vptr ──────────────────────────────────
; The vptr is the first field of the object, at offset +0x00.
mov    rax, QWORD PTR [rdi]            ; rax = *this = vptr

; ── Step 3: index the vtable ───────────────────────────────
; process() is the 5th vtable entry (index 4, after 2 dtors,
; name, configure). Each entry is 8 bytes on x86-64.
; Offset = 4 × 8 = 0x20.
; With GCC's 2 destructors: dtor_complete, dtor_deleting,
; name, configure → process is at index 4, offset 0x20.
mov    rax, QWORD PTR [rax+0x20]       ; rax = vtable[4] = &process()

; ── Step 4: prepare the arguments ──────────────────────────
; System V AMD64 convention: rdi=this, rsi=input, rdx=in_len,
; rcx=output, r8=out_cap
; rdi is already set (step 1).
mov    rsi, QWORD PTR [rbp-0x30]       ; rsi = input  
mov    rdx, QWORD PTR [rbp-0x38]       ; rdx = in_len  
mov    rcx, QWORD PTR [rbp-0x40]       ; rcx = output  
mov    r8,  QWORD PTR [rbp-0x48]       ; r8  = out_cap  

; ── Step 5: indirect call ──────────────────────────────────
call   rax                              ; call the virtual method
```

What distinguishes a virtual call from a direct call is the **`call rax`** (or `call QWORD PTR [rax+offset]` when steps 3 and 5 are merged). A direct call uses `call <fixed_address>` or `call <symbol@plt>`.

> 💡 **Quick reading rule**: if you see `call` followed by a register or a memory indirection (not an immediate address), it is an indirect call. In a C++ binary, an indirect call preceded by a `[rdi]` read is almost certainly virtual dispatch.

### Syntactic variants

The pattern above is the decomposed form at `-O0`. In practice, GCC may merge steps 2, 3, and 5:

```asm
; Compact form (frequent at -O1 and above)
mov    rax, QWORD PTR [rdi]            ; read the vptr  
call   QWORD PTR [rax+0x20]            ; index + call in one instruction  
```

Or, if the `this` pointer comes directly from a register:

```asm
; Ultra-compact form (frequent at -O2)
mov    rax, QWORD PTR [rbx]            ; rbx = this, read the vptr  
call   QWORD PTR [rax+0x20]            ; dispatch  
```

The **offset in `[rax+X]`** is the key to identifying which virtual method is called. Divide the offset by 8 (the pointer size on x86-64) to get the vtable index:

| Offset | Index | Method (in our binary) |  
|--------|-------|------------------------------|  
| `+0x00` | 0 | `~Processor()` (complete destructor) |  
| `+0x08` | 1 | `~Processor()` (deleting destructor) |  
| `+0x10` | 2 | `name()` |  
| `+0x18` | 3 | `configure()` |  
| `+0x20` | 4 | `process()` |  
| `+0x28` | 5 | `status()` |

This table is your **reference card** throughout the analysis. Reconstruct it in section 22.1, then use it here to decode each virtual call encountered in the disassembly.

---

## Reading in Ghidra

### The decompiler and virtual calls

Ghidra's decompiler transforms the assembly pattern into pseudo-C. However, without manual annotation, the result is often cryptic:

```c
/* Before annotation */
iVar1 = (*(code *)*(long *)(*param_1 + 0x20))
            (param_1, local_38, local_40, local_48, local_50);
```

This line reads as follows:

- `*param_1` → dereference `this` → read the vptr.  
- `*param_1 + 0x20` → entry at offset `0x20` in the vtable.  
- `*(long *)( ... )` → read the function pointer.  
- `(*(code *)( ... ))( ... )` → call that function with the arguments.

After creating the `Processor` structure and applying the type on `param_1`, the decompiled output becomes:

```c
/* After annotation */
iVar1 = (*processor->vptr->process)(processor, input, in_len, output, out_cap);
```

And if you defined a structured vtable type:

```c
/* With a typed vtable */
iVar1 = processor->vptr->process(processor, input, in_len, output, out_cap);
```

### Creating a vtable type in Ghidra

To achieve this readable result, create a structure representing the vtable in the Data Type Manager:

```
struct Processor_vtable {
    void*  dtor_complete;      /* +0x00 */
    void*  dtor_deleting;      /* +0x08 */
    void*  name;               /* +0x10 — returns const char* */
    void*  configure;          /* +0x18 — returns bool */
    void*  process;            /* +0x20 — returns int */
    void*  status;             /* +0x28 — returns const char* */
};
```

Then modify the `Processor` structure so that the first field is a pointer to `Processor_vtable`:

```
struct Processor {
    Processor_vtable*  vptr;       /* +0x00 */
    uint32_t           id_;        /* +0x08 */
    int                priority_;  /* +0x0C */
    bool               enabled_;   /* +0x10 */
    /* padding 7 bytes */
};
```

Apply this type to parameters and local variables in relevant functions. The decompiled output will immediately become comprehensible.

> 💡 To go further, you can type each vtable entry with a function pointer prototype instead of `void*`. For example, the `process` field would become `int (*process)(Processor*, const char*, size_t, char*, size_t)`. The decompiled output will then display argument types.

### Navigating from a virtual call to the implementation

Facing a `call QWORD PTR [rax+0x20]`, you know it is `process()` (index 4). But **which implementation** is called? The disassembler cannot know — it is determined at runtime by the object's concrete type.

To identify possible implementations:

1. Open each vtable reconstructed in section 22.1.  
2. Look at the entry at index 4 in each one.  
3. Each function pointer at that index is a candidate implementation.

For our binary:

| Vtable | Entry index 4 (`+0x20`) | Implementation |  
|--------|--------------------------|----------------|  
| `Processor` | `__cxa_pure_virtual` | (pure virtual — never called) |  
| `UpperCaseProcessor` | `FUN_00401a30` | `UpperCaseProcessor::process()` |  
| `ReverseProcessor` | `FUN_00401b80` | `ReverseProcessor::process()` |  
| `Rot13Processor` (plugin) | `0x7f...6150` | `Rot13Processor::process()` |  
| `XorCipherProcessor` (plugin) | `0x7f...a1c0` | `XorCipherProcessor::process()` |

The `__cxa_pure_virtual` entry in the `Processor` vtable confirms that `process()` is a pure virtual method in the base class. If it were called (which should never happen), the program would crash with a "pure virtual method called" message.

---

## Virtual dispatch seen by GDB

### Observing dispatch in real time

Set a breakpoint in `Pipeline::execute()`, just before the virtual call to `process()`. At `-O0` with symbols, you can target the exact line. Without symbols, look for the `call rax` or `call QWORD PTR [rax+0x20]` pattern in the function's disassembly.

```
(gdb) disas Pipeline::execute
   ...
   0x0000000000402340 <+208>:  mov    rax,QWORD PTR [rdi]
   0x0000000000402343 <+211>:  call   QWORD PTR [rax+0x20]
   ...
(gdb) break *0x0000000000402343
(gdb) run -p ./plugins "Hello World"
```

At each stop on this breakpoint, the called processor is different (depending on the pipeline loop). Inspect the values:

```
Breakpoint hit.

(gdb) info registers rdi rax
rdi   0x555555808010       ← this (the current Processor object)  
rax   0x7ffff7fb7d00       ← vptr (vtable address)  

(gdb) x/gx $rax+0x20
0x7ffff7fb7d20: 0x00007ffff7fb6150    ← address of process()

(gdb) info symbol 0x00007ffff7fb6150
Rot13Processor::process(...) in section .text of ./plugins/plugin_alpha.so
```

You have identified that this call will reach `Rot13Processor::process()`. Continue with `continue` to see the next pass through the loop — the vptr will be different, pointing to another processor's vtable.

### GDB script to log each dispatch

Automate the tracing with a GDB script:

```python
# trace_dispatch.py — load in GDB with: source trace_dispatch.py

import gdb

class DispatchBreakpoint(gdb.Breakpoint):
    """Breakpoint on an indirect call that logs virtual dispatch."""

    def __init__(self, addr, vtable_offset):
        super().__init__("*" + hex(addr), internal=False)
        self.vtable_offset = vtable_offset
        self.hit_count = 0

    def stop(self):
        self.hit_count += 1
        rdi = int(gdb.parse_and_eval("$rdi"))
        vptr = int(gdb.parse_and_eval("*(unsigned long long*)$rdi"))
        target_addr = int(gdb.parse_and_eval(
            "*(unsigned long long*)({} + {})".format(vptr, self.vtable_offset)))

        # Resolve the symbol
        try:
            sym = gdb.execute("info symbol {}".format(hex(target_addr)),
                              to_string=True).strip()
        except:
            sym = "???"

        print("[dispatch #{}] this={:#x} vptr={:#x} target={:#x} → {}".format(
            self.hit_count, rdi, vptr, target_addr, sym))

        return False  # Don't stop, just log

# Usage example:
# Replace the address with that of the indirect call in your binary
# DispatchBreakpoint(0x402343, 0x20)
```

This script sets a non-blocking breakpoint that displays the object's real type and the called method at each pass. Load it and instantiate it:

```
(gdb) source trace_dispatch.py
(gdb) python DispatchBreakpoint(0x402343, 0x20)
(gdb) run -p ./plugins "Hello World"
```

Output:

```
[dispatch #1] this=0x5555558070f0 vptr=0x404a40 target=0x401a30
    → UpperCaseProcessor::process(...) in section .text of oop_O0
[dispatch #2] this=0x555555807130 vptr=0x404a90 target=0x401b80
    → ReverseProcessor::process(...) in section .text of oop_O0
[dispatch #3] this=0x555555808010 vptr=0x7ffff7fb7d00 target=0x7ffff7fb6150
    → Rot13Processor::process(...) in section .text of plugin_alpha.so
[dispatch #4] this=0x555555808050 vptr=0x7ffff7daba00 target=0x7ffff7daa1c0
    → XorCipherProcessor::process(...) in section .text of plugin_beta.so
```

In four lines, you see the complete pipeline: four objects of different types, four different vtables, four different implementations of `process()`, all called from the same call site in `Pipeline::execute()`. This is polymorphism in action, made visible through instrumentation.

---

## Impact of optimizations on dispatch

### `-O0`: canonical dispatch

At `-O0`, GCC makes no optimizations. Every virtual call systematically goes through the vtable, even if the compiler could theoretically deduce the type. The code is verbose but perfectly readable — which is why we always start analysis with this variant.

### `-O2`: devirtualization

GCC at `-O2` (and especially `-O3`) can **devirtualize** a virtual call when it can prove the object's concrete type at the call site. Concretely, it replaces the `call QWORD PTR [rax+offset]` with a `call <direct_address>`.

Consider this sequence in `main()`:

```cpp
UpperCaseProcessor* upper = new UpperCaseProcessor(0);  
upper->configure("skip_digits", "true");  
```

Here, the compiler knows that `upper` is of type `UpperCaseProcessor*` — the `new` and constructor are in the same function. There is no ambiguity about the type. At `-O2`, GCC can replace:

```asm
; -O0: virtual dispatch (even when the type is known)
mov    rax, QWORD PTR [rdi]  
call   QWORD PTR [rax+0x18]        ; configure() via vtable  
```

with:

```asm
; -O2: direct call (devirtualized)
call   UpperCaseProcessor::configure()   ; direct call, no vtable
```

Or even completely inline the method if it is short enough.

**Consequence for RE**: at `-O2`, some calls that were virtual at `-O0` become direct calls. You might believe the method is not virtual, or that the class has no vtable. Always compare the `-O0` and `-O2` versions to distinguish truly non-virtual methods from devirtualized calls.

### How to recognize devirtualization

A devirtualized call presents these characteristics:

- It is a direct `call <address>` (not `call rax` or `call [rax+X]`).  
- The called function **also exists** in a vtable — you find it as a vtable entry for the class when you analyze it.  
- The `this` passed in `rdi` comes from a recent `new` or a context where the type is unambiguous.

If the same function appears both as a direct call (in `main()`) and as an indirect call (in `Pipeline::execute()`), it is a strong sign of partial devirtualization: the compiler was able to optimize in one context but not the other.

### `-O2` with LTO (`-flto`): inter-module devirtualization

With Link-Time Optimization (chapter 16.5), GCC sees the entire program at link time, including the concrete types created. It can devirtualize calls that cross `.o` file boundaries.

However, plugins loaded via `dlopen` are **never** devirtualized, because they are not available at link time. Virtual dispatch always remains an indirect `call` for plugin methods — this is an architectural guarantee you can leverage in RE.

### Dispatch inlining

At `-O3`, GCC can go further than devirtualization: it can **inline** the devirtualized method. The method's code is then copied directly into the calling function. There is neither an indirect `call` nor a direct `call` — the method has literally disappeared as a separate entity.

For the reverse engineer, this is the most complex scenario. You see processing code in `Pipeline::execute()` without understanding that it comes from an inlined virtual method. The remaining clues are:

- The inlined code is often **bracketed by a type test** (`cmp` on the vptr followed by a branch) if GCC is not completely certain of the type. This is **speculative devirtualization**: the compiler injects the expected method's code but keeps a virtual fallback just in case.  
- Memory accesses in the inlined code use the typical offsets of the class structure (for example, `[rdi+0x11]` for `skip_digits_` in `UpperCaseProcessor`).

---

## Distinguishing different call types in a C++ binary

Throughout the analysis, you will encounter three types of calls. Knowing how to distinguish them instantly is a fundamental skill.

### Direct call (non-virtual or devirtualized)

```asm
call   0x401a30                         ; fixed address in .text
; or
call   UpperCaseProcessor::process      ; if symbols present
```

**Recognition**: `call` followed by an immediate address or symbol. No vptr read, no indirection.

**Interpretation**: either the method is not virtual (non-virtual method, free function, inlined accessor), or the compiler devirtualized the call.

### Virtual call (dispatch via vtable)

```asm
mov    rax, QWORD PTR [rdi]            ; read vptr  
call   QWORD PTR [rax+0x20]            ; index and call  
```

**Recognition**: `call` via register or memory indirection, preceded by a `[rdi]` read (vptr read from `this`).

**Interpretation**: polymorphic call. The called method depends on the object's real type at runtime. The offset gives you the vtable index.

### Call via function pointer (non-virtual)

```asm
mov    rax, QWORD PTR [rbp-0x10]       ; load a function pointer  
call   rax  
```

**Recognition**: `call` via register, but **without** a prior vptr read. The function pointer comes from a variable (stack, global, structure), not from the first field of an object.

**Interpretation**: callback, function pointer stored in a structure (like the `create_func_t` and `destroy_func_t` from section 22.2), or `dlsym` result. This is not C++ polymorphism — it is "C-style" polymorphism.

The distinction between the last two cases rests on the **origin of the pointer**. If the pointer comes from `[rdi]` (first field of the object = vptr) and is then indexed, it is virtual dispatch. If the pointer comes from elsewhere, it is an ordinary function pointer.

---

## Tracing dispatch with Frida: who calls what, when

The following script intercepts a virtual call at a given address and dynamically resolves the target method:

```javascript
// frida_trace_vcall.js
// Traces a virtual call site in Pipeline::execute()

var VCALL_ADDR = ptr("0x402343");  // Address of the indirect call (adapt)  
var VTABLE_OFFSET = 0x20;          // Vtable offset (process = index 4)  

Interceptor.attach(VCALL_ADDR, {
    onEnter: function(args) {
        // At this point, rdi = this
        var thisPtr = this.context.rdi;
        var vptr = thisPtr.readPointer();
        var targetFn = vptr.add(VTABLE_OFFSET).readPointer();
        var sym = DebugSymbol.fromAddress(targetFn);

        // Read the name via the name() method — index 2 in the vtable
        var nameFn = new NativeFunction(
            vptr.add(0x10).readPointer(),   // name() at offset 0x10
            'pointer', ['pointer']);
        var name = nameFn(thisPtr).readUtf8String();

        console.log("[vcall] " + name + " → " + sym.name +
                    " (this=" + thisPtr + ")");
    }
});
```

This script goes beyond simple address tracing: it calls `name()` (another virtual method) on the object to obtain the processor's readable name. Output:

```
[vcall] UpperCaseProcessor → UpperCaseProcessor::process() (this=0x5555558070f0)
[vcall] ReverseProcessor → ReverseProcessor::process() (this=0x555555807130)
[vcall] Rot13Processor → Rot13Processor::process() (this=0x555555808010)
[vcall] XorCipherProcessor → XorCipherProcessor::process() (this=0x555555808050)
```

---

## Advanced case: virtual dispatch and multiple inheritance

Our `ch22-oop` binary uses single inheritance. But in real-world RE, you will encounter multiple inheritance. Here are the key differences to know so you are not caught off guard.

### Single inheritance: one vptr

With single inheritance (our case), each object contains a single vptr at offset `+0x00`. All virtual methods — from the base class and derived classes — are in a single vtable.

```
UpperCaseProcessor object (single inheritance):
  +0x00  vptr ──→ single vtable (all methods)
  +0x08  id_
  +0x0C  priority_
  +0x10  enabled_
  +0x11  skip_digits_          (bool, right after enabled_ without padding)
  +0x18  bytes_processed_
```

### Multiple inheritance: multiple vptrs

When a class inherits from two polymorphic base classes, the object contains **two vptrs**:

```
class Serializable { virtual void serialize(); ... };  
class Processor { virtual void process(); ... };  
class AdvancedProcessor : public Processor, public Serializable { ... };  
```

The `AdvancedProcessor` object in memory:

```
  +0x00  vptr_Processor      ──→ vtable Processor-part
  +0x08  id_ (from Processor)
  ...
  +0x20  vptr_Serializable   ──→ vtable Serializable-part
  +0x28  Serializable fields
  ...
```

In RE, the telltale sign is the presence of **two pointers to `.data.rel.ro`** within the same object, at different offsets. The class's typeinfo then uses `__vmi_class_type_info` instead of `__si_class_type_info`, and contains the list of all parent classes with their offsets.

The other sign is the **offset-to-top** in the secondary vtable. For the `Serializable` part, the offset-to-top is negative (for example `-0x20`) and indicates the distance between the `Serializable` sub-object and the beginning of the complete object. When a virtual call goes through the secondary vptr, the compiler inserts a **thunk** — a small function that adjusts the `this` pointer before jumping to the real method:

```asm
; Thunk for AdvancedProcessor::serialize() via the Serializable vptr
; Adjusts this by subtracting the sub-object offset
sub    rdi, 0x20          ; rdi pointed to the Serializable sub-object  
jmp    AdvancedProcessor::serialize()   ; now rdi points to the beginning  
```

Thunks are very short functions (2-3 instructions) that Ghidra often identifies automatically. If you see a function that only does `sub rdi, N` then `jmp <other_function>`, it is very likely a vtable thunk.

---

## Summary: reading a virtual call in 30 seconds

When facing an indirect call in a C++ binary, apply this mental routine:

**1. Identify the pattern.** `mov rax, [rdi]` followed by `call [rax+X]`? It is virtual dispatch.

**2. Calculate the index.** Offset ÷ 8 = vtable index. Consult your correspondence table (reconstructed in section 22.1).

**3. Identify candidate implementations.** For each reconstructed vtable, look at the entry at that index. These are the possible implementations.

**4. Determine the real type (if necessary).** Trace back the data flow to find where the `this` pointer comes from. If it comes from a `new UpperCaseProcessor`, the type is known. If it comes from a vector of `Processor*`, the type is ambiguous — only dynamic analysis will resolve it.

**5. Check for optimizations.** Compare with the `-O0` version. If a call is direct at `-O2` but virtual at `-O0`, it is devirtualization. If code appears inline, it is post-devirtualization inlining.

This reflex will become automatic with practice. Every C++ binary you analyze will contain dozens, even hundreds of virtual calls. The ability to decode them quickly is what distinguishes a stalled analysis from one that progresses.

---


⏭️ [Patching behavior via `LD_PRELOAD`](/22-oop/04-patching-ld-preload.md)
