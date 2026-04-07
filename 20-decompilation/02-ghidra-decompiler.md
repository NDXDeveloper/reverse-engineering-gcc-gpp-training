🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 20.2 — Ghidra Decompiler — Quality Depending on Optimization Level

> 📘 **Chapter 20 — Decompilation and Source Code Reconstruction**  
> **Part IV — Advanced RE Techniques**

---

## Ghidra's decompiler in context

The decompiler built into Ghidra is an analysis engine internally called the **Pcode Decompiler**. It operates in several phases: x86-64 machine code is first translated into an intermediate representation called P-code (an architecture-independent micro-operation language), then this P-code undergoes optimization and simplification passes, and finally the result is presented as C-like pseudo-code. This layered architecture is what allows Ghidra to decompile very different architectures (ARM, MIPS, PowerPC...) with the same reconstruction engine.

For analysts working on ELF binaries compiled with GCC, Ghidra's decompiler is the central tool in the daily workflow. It is free, open source, and its quality rivals that of Hex-Rays (IDA's commercial decompiler) on most conventional binaries. Its specific strengths and weaknesses when facing different GCC optimization levels are the subject of this section.

---

## Anatomy of a decompilation session in Ghidra

Before comparing optimization levels, let's review the basic workflow in Ghidra's CodeBrowser (covered in chapter 8).

When a function is selected in the **Listing** view (disassembly), the **Decompiler** panel immediately displays the corresponding pseudo-code. Both views are synchronized: clicking on a pseudo-code line highlights the corresponding assembly instructions, and vice versa. This bidirectional synchronization is one of Ghidra's major strengths — it enables exactly the disassembly/pseudo-code cross-referencing recommended in section 20.1.

The decompiler does not work in a vacuum. It relies on several sources of information that the analyst can enrich throughout the analysis:

**The type store.** Ghidra maintains a type database (Data Type Manager) that contains standard C/C++ types, types from known libraries (libc, libstdc++...), and analyst-defined types. The richer and more accurate this database is, the better the pseudo-code.

**Function signatures.** When Ghidra knows a function's signature (number and types of parameters, return type), it can propagate this information throughout all calling code. For libc functions called via PLT (`printf`, `strcmp`, `malloc`...), Ghidra automatically applies the correct signatures through its `.gdt` files (Ghidra Data Types).

**Symbols.** If the binary is not stripped, Ghidra retrieves function names from the ELF symbol table. If DWARF information is present (`-g`), it also retrieves local variable names, parameter types, and structure names — which makes the pseudo-code nearly identical to the source.

---

## Decompilation at -O0: the reference case

Let's start by importing `keygenme_O0_dbg` into Ghidra (compiled with `-O0 -g`). After automatic analysis, navigate to the `derive_key` function. Here is what the decompiler produces (simplified for readability):

```c
void derive_key(char *username, uint32_t seed, uint8_t *out)
{
    size_t ulen;
    uint32_t state[4];
    int r;

    ulen = strlen(username);
    state[0] = mix_hash(username, ulen, seed);
    for (r = 1; r < 4; r = r + 1) {
        state[r] = mix_hash(username, ulen, state[r - 1] ^ (uint32_t)r);
    }
    for (r = 0; r < 4; r = r + 1) {
        out[r * 4]     = (uint8_t)(state[r] >> 0x18);
        out[r * 4 + 1] = (uint8_t)(state[r] >> 0x10);
        out[r * 4 + 2] = (uint8_t)(state[r] >> 8);
        out[r * 4 + 3] = (uint8_t)state[r];
    }
    return;
}
```

The result is remarkably faithful to the original source. Parameter names are correct (thanks to DWARF), the two-loop `for` structure is intact, the call to `mix_hash` is clearly visible, and the shift operations to extract bytes are identical. The differences are cosmetic: `0x18` instead of `24`, `r = r + 1` instead of `r++`, and constants displayed in hexadecimal.

### What works well at -O0

At this optimization level, Ghidra's decompiler excels on several points:

**Function-by-function correspondence.** Each function from the source exists as a distinct function in the binary. No inlining, no merging — navigation in Ghidra's Symbol Tree faithfully reflects the code organization.

**Local variables on the stack.** At `-O0`, GCC allocates each local variable on the stack. Ghidra clearly identifies them as `local_XX` (or with their real name if DWARF is available) and can assign them a coherent type.

**Intact control structures.** `for` loops, `if/else` blocks, `switch` statements are reconstructed as-is. There is no loop inversion, no conversion to `cmov`, no unrolling.

**Explicit function calls.** Each call is a real `call` in the disassembly. The decompiler displays the call with the correct arguments passed in registers `rdi`, `rsi`, `rdx`... according to the System V AMD64 convention.

### What is still missing

Even in this favorable case, certain losses are visible.

The decompiler does not reconstruct macros: `ROUND_COUNT` appears as the literal `4`, and `MAGIC_SEED` as `0xdeadbeef`. The `typedef license_ctx_t` does not exist — Ghidra shows access to a memory block on the stack with offsets. And the distinction between `uint8_t *` and `char *` for the output buffer depends on the quality of the DWARF information.

Now let's load the same function from `keygenme_O0` (compiled with `-O0` **without** `-g`). The names disappear: `username` becomes `param_1`, `seed` becomes `param_2`, `out` becomes `param_3`, and local variables become `local_38`, `local_2c`, etc. The code structure is identical, but the naming work must now be done manually.

---

## Decompilation at -O2: the realistic case

Let's import `keygenme_O2` into a new Ghidra project. The first visible difference is that all `static` functions have been inlined into `main` — `derive_key`, `mix_hash`, and `rotate_left` no longer exist as separate functions. The pseudo-code for `main` contains everything. Here is the passage corresponding to the `derive_key` logic, extracted from the pseudo-code of `main` (representative version):

```c
void derive_key(char *param_1, uint32_t param_2, uint8_t *param_3)
{
    uint32_t uVar1;
    size_t sVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    int iVar5;
    size_t sVar6;

    sVar2 = strlen(param_1);
    uVar3 = param_2;
    for (sVar6 = 0; sVar6 < sVar2; sVar6 = sVar6 + 1) {
        uVar1 = (uint8_t)param_1[sVar6];
        uVar3 = ((uVar3 ^ uVar1) << 5 | (uVar3 ^ uVar1) >> 0x1b) +
                uVar1 * 0x1000193;
        uVar3 = uVar3 ^ uVar3 >> 0x10;
    }
    *param_3 = (uint8_t)(uVar3 >> 0x18);
    param_3[1] = (uint8_t)(uVar3 >> 0x10);
    param_3[2] = (uint8_t)(uVar3 >> 8);
    param_3[3] = (uint8_t)uVar3;
    uVar4 = uVar3 ^ 1;
    for (sVar6 = 0; sVar6 < sVar2; sVar6 = sVar6 + 1) {
        uVar1 = (uint8_t)param_1[sVar6];
        uVar4 = ((uVar4 ^ uVar1) << 5 | (uVar4 ^ uVar1) >> 0x1b) +
                uVar1 * 0x1000193;
        uVar4 = uVar4 ^ uVar4 >> 0x10;
    }
    param_3[4] = (uint8_t)(uVar4 >> 0x18);
    param_3[5] = (uint8_t)(uVar4 >> 0x10);
    /* ... continues for rounds 2 and 3 ... */
    return;
}
```

The code is much longer and denser. Let's analyze what happened.

### Visible inlining

The call to `mix_hash()` has disappeared. Its body — the XOR/rotate/multiply loop — is directly integrated into the code. Furthermore, `rotate_left(h, 5)` has been replaced by its algebraic expression: `(val << 5) | (val >> 0x1b)`. The decompiler does not know that this pattern came from a separate function in the source; it displays the raw expression.

For the analyst, the reflex is to recognize the pattern `(x << n) | (x >> (32 - n))` as a left rotation. This is one of the most common GCC idioms (Appendix I). Once identified, you can create a macro or a comment in Ghidra to clarify the pseudo-code.

### Outer loop unrolling

The `for (r = 0; r < ROUND_COUNT; r++)` loop that iterated 4 times has been partially or fully unrolled by GCC. Instead of seeing a loop with a counter, you see 4 sequential code blocks, each containing the inner hashing loop. The decompiler displays this as linear code — the notion of "4 rounds" is lost in the structure, even though the pattern repetition is visible to a trained eye.

### Variables merged into registers

At `-O0`, each element of the `state[4]` array had its stack location. At `-O2`, GCC kept these values in registers (`eax`, `edx`, etc.) and reused them sequentially. The decompiler creates temporary variables (`uVar3`, `uVar4`...) that do not correspond to any variable in the original source — they are register allocation artifacts.

### Reading strategy

When facing this optimized pseudo-code, the working method in Ghidra is as follows:

1. **Identify repetitive blocks.** The 4 copies of the inner loop indicate unrolling. Annotating each copy with a comment (`// Round 0`, `// Round 1`, etc.) immediately makes the code more readable.

2. **Rename variables.** Replace `uVar3` with `hash_r0`, `uVar4` with `hash_r1`, etc. In Ghidra, right-clicking a variable → *Rename Variable* (or `L`) propagates the name throughout the function's pseudo-code.

3. **Retype parameters.** Right-clicking on `param_1` → *Retype Variable* and choosing `char *` (or better, creating a `const char *username` type) improves readability and can trigger a cleaner re-decompilation.

4. **Create structured types.** If you have identified that `param_3` points to a 16-byte buffer filled in groups of 4, you can create a `typedef uint8_t key_bytes_t[16]` in the Data Type Manager and apply it.

---

## Decompilation at -O3: the difficult case

Let's import `keygenme_O3`. At this level, GCC may vectorize the inner loop of `mix_hash` using SSE2 instructions. The resulting pseudo-code in Ghidra may contain operations on `undefined16` types (128-bit XMM registers) or calls to intrinsics that Ghidra does not always recognize correctly.

### Vectorization and SIMD types

When GCC vectorizes a loop, it replaces scalar operations with packed operations operating on multiple elements in parallel. Ghidra's decompiler attempts to represent these operations, but the result is often pseudo-code using casts to large types (`ulong *`, `undefined8 *`) and complex bitwise operations that obscure the original logic.

On our `keygenme_O3`, here is the type of pseudo-code one can observe for the hashing loop:

```c
    uVar2 = *(ulong *)(param_1 + sVar4);
    uVar7 = (uint)uVar2 ^ uVar5;
    uVar8 = uVar7 << 5 | uVar7 >> 0x1b;
    /* ... interleaved operations on multiple bytes simultaneously ... */
```

GCC is processing multiple bytes of the username in a single memory load operation (`ulong *`), then decomposing the values. The decompiler shows this wide load but does not understand that it is a memory access optimization on a character-by-character loop.

### Tail call optimization

In `oop_O3` (the C++ binary), GCC may apply tail call optimization on virtual method calls at the end of a function. In the disassembly, a `call` becomes a `jmp`, and the decompiler may interpret this as a jump into the called function's body rather than a call followed by a return. The result can be an apparent merging of two functions in the pseudo-code, or an unexplained `goto` at the end of a function.

### When to fall back to disassembly

At `-O3`, pseudo-code reaches its readability limits. This is when Ghidra's Listing view and Function Graph view regain the advantage. The recommended strategy is to work in blocks: use pseudo-code for the overall view and navigation (thanks to cross-references), then switch to disassembly for critical passages where the pseudo-code is incomprehensible.

In Ghidra, the `Space` key in the Listing window toggles between linear mode and graph mode. Graph mode is particularly useful for visualizing the branches of a `switch` or the structure of a vectorized loop — the basic blocks and their connections are often more informative than flattened pseudo-code.

---

## The C++ case: the oop.cpp binary

The `oop_O0_dbg` binary allows us to observe the decompiler's behavior when facing C++ compiled by G++. Several specific phenomena appear.

### Virtual calls and vtables

Navigate to the `DeviceManager::process_all()` function. In the pseudo-code, the virtual call `dev->process()` appears in a form like:

```c
    (**(code **)(**(long **)(this->devices_._M_start + lVar2) + 0x20))
        (*(long *)(this->devices_._M_start + lVar2));
```

This opaque expression is actually the virtual dispatch mechanism: access the object's vptr (first dereference), index into the vtable at offset `0x20` (find the `process()` slot), then call the resulting function pointer. This is correct but unreadable.

The solution in Ghidra is to **manually reconstruct the classes and vtables** (a technique covered in detail in chapter 17, section 2). Once the analyst has created a `Device` type with a `vptr` field pointing to a `Device_vtable` structure containing the function pointers in the right order, the pseudo-code simplifies considerably:

```c
    device->vtable->process(device);
```

This is still C and not C++, but the logic is readable.

### Name mangling

Without DWARF, C++ function names in the symbol table are mangled according to the Itanium ABI. Ghidra automatically demangles them in most cases. For example, `_ZN13DeviceManager11process_allEv` is displayed as `DeviceManager::process_all()` in the Symbol Tree and in the pseudo-code. This feature works well with G++, and it is one of the first clues the analyst uses to map classes without DWARF.

However, in the stripped version (`oop_O2_strip`), local symbol names disappear. Ghidra assigns names like `FUN_00401a30`. Demangling can only apply if dynamic symbols (exports/imports) or RTTI strings remain. Fortunately, G++ preserves RTTI information by default (unless the binary is compiled with `-fno-rtti`), and Ghidra can leverage it to recover class names and the inheritance hierarchy even in a stripped binary.

### STL containers

Accesses to `std::vector`, `std::string`, and `std::map` produce verbose pseudo-code. A simple `devices_.push_back(...)` in the source transforms into several calls to instantiated template functions (`std::vector<std::unique_ptr<Device>>::push_back`, `std::__uniq_ptr_impl<Device>::...`), with interleaved exception handling.

Ghidra displays these demangled names when symbols are available, which is useful for identification but makes the pseudo-code very long. The practical strategy is to spot these STL calls, confirm their role, then skim over them to focus on the business logic surrounding them.

---

## Guiding the decompiler: analyst interventions

Ghidra's decompiler does not operate in a closed loop. Each correction made by the analyst triggers a re-decompilation that can improve the result in cascade. Here are the most impactful interventions, ranked by return on effort.

### Correcting function signatures

This is the intervention with the best effort-to-result ratio. If the decompiler believes a function takes 2 parameters when it actually takes 3, all calling functions will display incorrect pseudo-code (the third argument will appear as an uninitialized local variable). Correcting the signature via right-click → *Edit Function Signature* instantly propagates the correction throughout the entire binary.

On non-stripped GCC binaries, signatures are generally correct thanks to symbols. On stripped binaries, this is the first task to perform manually for each key function.

### Retyping variables

Changing a local variable's type from `undefined4` to `uint32_t`, or from `long` to `char *`, allows the decompiler to reformulate expressions using that variable. A memory access displayed as `*(int *)(lVar1 + 0x20)` can become `param->field_0x20` if the parameter type is correctly defined — and `ctx->expected_key[0]` if the structure is fully reconstructed.

### Defining structures in the Data Type Manager

Creating a `license_ctx_t` type with the correct fields at the correct offsets, then applying it to the `this` parameter or a local variable, radically transforms the pseudo-code. Instead of pointer arithmetic with numeric offsets, you get named field accesses. This is the tipping point where pseudo-code goes from "readable with effort" to "understandable at first glance."

### Applying calling conventions

If Ghidra gets a function's calling convention wrong (for example using `__cdecl` instead of `__fastcall`, or failing to detect a parameter passed in a non-standard register), the pseudo-code for that function and all its callers will be incorrect. Correcting the convention in the function properties resolves the issue in cascade.

---

## Comparative table: pseudo-code quality across variants

The table below summarizes the typical quality of pseudo-code produced by Ghidra on our training binaries, evaluated on 5 criteria.

| Criterion | O0 + DWARF | O0 no debug | O2 + symbols | O2 stripped | O3 stripped |  
|---|---|---|---|---|---|  
| Function names | ✅ Original | ✅ Original | ✅ Original | ❌ `FUN_XXXXX` | ❌ `FUN_XXXXX` |  
| Variable names | ✅ Original | ❌ `local_XX` | ❌ `local_XX` | ❌ `local_XX` | ❌ `local_XX` |  
| Control structures | ✅ Faithful | ✅ Faithful | ⚠️ Modified | ⚠️ Modified | ❌ Unrecognizable |  
| Source correspondence | ~95% | ~85% | ~60% | ~50% | ~30% |  
| Analyst effort required | Minimal | Renaming | Renaming + retyping | Full reconstruction | Full + disassembly |

These percentages are indicative and vary depending on source code complexity. The hashing loop in `keygenme.c` decompiles better than the virtual dispatch in `oop.cpp`, regardless of optimization level. Note that in `keygenme`, all functions are `static` and are entirely inlined into `main` starting at `-O2` — the O2/O3 columns in the table then apply to the pseudo-code of `main` as a whole.

---

## Common pitfalls and solutions

### The "it looks correct" pitfall

The decompiler always produces something that looks like valid C. The analyst may be tempted to read the pseudo-code as they would read real source code, trusting the displayed logic. This is dangerous. A poorly inferred type can silently reverse the meaning of a comparison (`signed` vs `unsigned`), and an uninitialized variable in the pseudo-code may actually be a parameter that Ghidra failed to detect.

The practical rule: **when the pseudo-code of a critical passage seems too simple or too clean, check the disassembly**. A simple `if` in the pseudo-code may mask more complex logic in the machine code.

### The stale decompilation pitfall

Ghidra does not always automatically re-decompile a function after modifications in a neighboring function. If you correct the signature of `mix_hash` and the pseudo-code of `derive_key` does not change, you need to force re-decompilation: right-click in the Decompiler → *Commit Params/Return* on the modified function, then navigate to the calling function again.

### The undetected function pitfall

Ghidra identifies functions by heuristic analysis of prologues (`push rbp; mov rbp, rsp` or `sub rsp, ...`). In a stripped optimized binary, some functions may not have a standard prologue (especially leaf functions that do not use the stack). Ghidra may then fail to detect them as distinct functions, including them in the body of the preceding function. The symptom is an abnormally long function in the pseudo-code. The solution is to manually create the function at the correct address in the Listing view (*Create Function* with `F`).

---


⏭️ [RetDec (Avast) — offline static decompilation](/20-decompilation/03-retdec.md)
