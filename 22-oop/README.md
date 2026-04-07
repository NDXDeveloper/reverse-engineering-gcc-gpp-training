🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 22 — Reversing an Object-Oriented C++ Application

> 📦 **Training binary**: `binaries/ch22-oop/`  
> 🛠️ **Main tools**: Ghidra, GDB (+ GEF/pwndbg), `objdump`, `c++filt`, `nm`, `readelf`, Frida, `LD_PRELOAD`  
> 📚 **Prerequisites**: Chapters 3 (x86-64 assembly), 8 (Ghidra), 11 (GDB), 17 (RE of C++ with GCC)

---

## Why this chapter?

The previous chapters gave you the theoretical building blocks: Itanium name mangling, the C++ object model (vtables, vptr, RTTI), exception handling, and STL internals. Chapter 17 in particular taught you to **recognize** these structures in a disassembly. It is time to scale up.

In this chapter, you will face a complete C++ binary — not an isolated snippet, but an application with a class hierarchy, inheritance, polymorphism, a dynamically loaded plugin system, and virtual calls spread across multiple modules. The goal is no longer to recognize a vtable in a 30-line listing: it is to **reconstruct the software architecture** of a program for which you have no source code.

This type of target is representative of what you will encounter in reality: business applications compiled in C++, game engines, frameworks with plugin architectures, or even object-oriented malware. Knowing how to navigate virtual dispatch and understand how objects interact through abstract interfaces is a fundamental skill in applied RE.

---

## The `ch22-oop` binary

The binary provided in `binaries/ch22-oop/` is a C++ application simulating a **modular data processing system**. Its architecture relies on several concepts that you will need to identify and reconstruct:

- **An abstract base class** defining a common interface (pure virtual methods).  
- **Several derived classes** implementing this interface with distinct behaviors.  
- **A plugin mechanism**: shared libraries (`.so`) are loaded at runtime via `dlopen` / `dlsym`, dynamically instantiated, and used through the base class interface.  
- **Ubiquitous virtual dispatch**: the application manipulates pointers to the base class and calls methods via the vtable, never knowing the concrete type at the call site.

The chapter's `Makefile` produces several variants:

| Variant | Optimization | Symbols | Pedagogical use |  
|---|---|---|---|  
| `oop_O0` | `-O0` | yes (`-g`) | First analysis, direct correspondence with the source |  
| `oop_O2` | `-O2` | yes (`-g`) | Observe the impact of optimizations on virtual dispatch |  
| `oop_O2_strip` | `-O2` | no (`-s`) | Realistic conditions — no symbols, no safety net |  
| `plugin_alpha.so` | `-O2` | yes | Dynamically loaded plugin |  
| `plugin_beta.so` | `-O2` | yes | Second plugin, different behavior |

> 💡 Always start systematically with the `_O0` variant with symbols. Once the logic is understood, move to `_O2_strip` to validate that you can recover the same information without compiler help.

---

## What you will learn

This chapter covers four complementary axes, each corresponding to a section:

**22.1 — Reconstructing the class hierarchy and vtables.** You will start from the raw binary to identify classes, their inheritance relationships, and reconstruct vtables in Ghidra. You will learn to trace back from a `call [rax+0x10]` to the concrete method called, by cross-referencing RTTI information, cross-references, and the memory structure of objects.

**22.2 — RE of a plugin system (`dlopen` / `dlsym`).** You will analyze how the application discovers, loads, and instantiates external modules at runtime. You will see how to trace calls to `dlopen` and `dlsym` (with `ltrace`, GDB, or Frida) to understand which symbol serves as the plugin entry point and how the returned object integrates into the main program's class hierarchy.

**22.3 — Understanding virtual dispatch in practice.** You will dive into the mechanics of a virtual method call at the assembly level: reading the vptr, indexing into the vtable, indirect call. You will learn to distinguish a virtual call from a direct call, to identify the devirtualization performed by the compiler at `-O2`, and to recognize cases where GCC replaces an indirect call with a direct call when it can resolve the type statically.

**22.4 — Patching behavior via `LD_PRELOAD`.** Rather than modifying the binary itself, you will use `LD_PRELOAD` to inject a shared library that **intercepts and replaces** functions or methods at runtime. This technique, at the boundary between dynamic analysis and instrumentation, is a powerful tool for quickly testing RE hypotheses without touching the target binary.

---

## Recommended methodology

The analysis of an object-oriented C++ binary follows a specific flow that differs significantly from the RE of a procedural C program. Here is the approach we will follow throughout the chapter:

```
1. Classic triage (file, strings, checksec, readelf)
       │
       ▼
2. Identify C++ symbols (nm -C, c++filt, RTTI strings)
       │
       ▼
3. Locate vtables (.rodata) and RTTI structures
       │
       ▼
4. Reconstruct the class hierarchy (Ghidra + XREF)
       │
       ▼
5. Trace virtual dispatch (GDB: break on indirect call)
       │
       ▼
6. Analyze dynamic loading (dlopen/dlsym → .so plugins)
       │
       ▼
7. Validate and experiment (LD_PRELOAD, Frida, custom plugin)
```

Step 3 is often the keystone: once vtables are identified and annotated, the program's structure reveals itself. Each vtable corresponds to a concrete class, each vtable entry is a virtual method, and cross-references on these methods show you **who calls what and in what context**.

---

## Essential refreshers from chapter 17

Before diving into the analysis, make sure you are comfortable with these concepts from chapter 17. If any of them seems unclear, reread the corresponding section before continuing.

**The vptr and vtable.** Each object of a polymorphic class contains a hidden pointer (the *vptr*) located at the beginning of the object in memory (offset `+0x00` with GCC/Itanium ABI). This pointer references the vtable of the object's concrete class, stored in `.rodata`. The vtable is an array of function pointers, one per virtual method, in declaration order.

**Itanium name mangling.** C++ symbols are encoded according to the Itanium ABI. For example, `_ZN7Vehicle5driveEv` decodes to `Vehicle::drive()`. The `c++filt` tool and the `-C` option of `nm` are your permanent allies.

**RTTI.** When not disabled (`-fno-rtti`), RTTI produces `typeinfo` structures and readable type name strings in `.rodata`. These strings (like `7Vehicle`, `3Car`) are often the first visible clue in a `strings` output for identifying the classes present.

**Virtual dispatch in assembly.** A typical virtual call (GCC, x86-64) translates to a recognizable sequence:

```asm
mov    rax, QWORD PTR [rdi]         ; rdi = this → read the vptr  
call   QWORD PTR [rax+0x10]         ; call the 3rd vtable entry  
```

The offset in `[rax+offset]` tells you which virtual method is called (offset / 8 = index in the vtable on x86-64).

---

## Links with other chapters

| Chapter | Link with chapter 22 |  
|---|---|  
| **Ch. 17 — RE of C++ with GCC** | Direct theoretical foundations: vtables, RTTI, name mangling, STL |  
| **Ch. 8 — Ghidra** | Main tool for static class reconstruction |  
| **Ch. 11 — GDB** | Tracing virtual dispatch and inspecting objects in memory |  
| **Ch. 13 — Frida** | Hooking `dlopen`/`dlsym` and virtual methods on the fly |  
| **Ch. 5 — Inspection tools** | Initial triage (`nm -C`, `readelf`, `strings`, `ltrace`) |  
| **Ch. 19 — Anti-reversing** | Understanding the impact of stripping on C++ analysis |

---

## Chapter outline

- **22.1** — [Reconstructing the class hierarchy and vtables](/22-oop/01-class-vtable-reconstruction.md)  
- **22.2** — [RE of a plugin system (dynamic loading `.so` via `dlopen`/`dlsym`)](/22-oop/02-plugin-system-dlopen.md)  
- **22.3** — [Understanding virtual dispatch: from vtable to method call](/22-oop/03-virtual-dispatch.md)  
- **22.4** — [Patching behavior via `LD_PRELOAD`](/22-oop/04-patching-ld-preload.md)  
- **🎯 Checkpoint** — [Write a compatible `.so` plugin that integrates into the application without the sources](/22-oop/checkpoint.md)

---


⏭️ [Reconstructing the class hierarchy and vtables](/22-oop/01-class-vtable-reconstruction.md)
