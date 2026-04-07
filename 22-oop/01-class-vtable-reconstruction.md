🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 22.1 — Reconstructing the Class Hierarchy and Vtables

> 🛠️ **Tools used**: `nm`, `c++filt`, `readelf`, `objdump`, Ghidra  
> 📦 **Binaries**: `oop_O0`, `oop_O2_strip`, `plugins/plugin_alpha.so`, `plugins/plugin_beta.so`  
> 📚 **Prerequisites**: Chapter 17, sections 17.1 (name mangling), 17.2 (vtable/vptr), 17.3 (RTTI)

---

## Introduction

When reversing a procedural C program, the code structure is relatively flat: functions calling each other, global data, a `main` that orchestrates everything. The call graph often suffices to understand the architecture.

With object-oriented C++, the situation changes radically. Logic is distributed across classes, calls go through virtual method pointers, and inheritance relationships define the program's architecture at least as much as the control flow. Reconstructing this architecture — the class hierarchy, interfaces, concrete implementations — is the essential first step before any in-depth analysis.

This section guides you step by step, from initial triage to complete annotation in Ghidra, using our `ch22-oop` binary.

---

## Step 1 — Triage: spotting C++ clues in the first few minutes

Before even opening a disassembler, command-line tools reveal much information about a C++ binary.

### 1.1 — `strings`: RTTI strings as first clue

RTTI strings are stored in `.rodata` and follow a specific format. They begin with a digit (the length of the name encoded according to the Itanium ABI) followed by the class name.

```bash
$ strings oop_O0 | grep -E '^[0-9]+[A-Z]'
```

On our binary with symbols, you will get strings like:

```
9Processor
19UpperCaseProcessor
16ReverseProcessor
8Pipeline
```

These strings are **typeinfo names** — each string corresponds to a polymorphic class (i.e., one with at least one virtual method). The prefix digit is the length of the following class name: `9Processor` means a 9-character name, "Processor."

> 💡 **Tip**: on a stripped binary, RTTI strings survive stripping because they are part of `.rodata`, not `.symtab`. They are often the only remaining nominal information. Only the `-fno-rtti` compilation flag removes them.

Let's test on the stripped variant:

```bash
$ strings oop_O2_strip | grep -E '^[0-9]+[A-Z]'
9Processor
19UpperCaseProcessor
16ReverseProcessor
8Pipeline
```

The same strings appear. This is your entry point, even without any symbols.

### 1.2 — `nm -C`: demangled symbols

On a non-stripped binary, `nm -C` (or `nm --demangle`) is a gold mine. Let's filter symbols related to our classes:

```bash
$ nm -C oop_O0 | grep -E '(vtable|typeinfo|Processor|Pipeline|Upper|Reverse)'
```

Typical result (simplified addresses):

```
0000000000404a00 V vtable for Processor
0000000000404a40 V vtable for UpperCaseProcessor
0000000000404a90 V vtable for ReverseProcessor
0000000000404ae0 V vtable for Pipeline
0000000000404b20 V typeinfo for Processor
0000000000404b38 V typeinfo for UpperCaseProcessor
0000000000404b58 V typeinfo for ReverseProcessor
0000000000404b78 V typeinfo for Pipeline
0000000000404b90 V typeinfo name for Processor
0000000000404b9a V typeinfo name for UpperCaseProcessor
...
0000000000401a30 T UpperCaseProcessor::process(char const*, ...)
0000000000401b80 T ReverseProcessor::process(char const*, ...)
0000000000401230 T UpperCaseProcessor::name() const
0000000000401430 T ReverseProcessor::name() const
```

Several crucial observations:

- Symbols marked `V` (weak global) in `.rodata` are the **vtables** and **typeinfo**. Their address in `.rodata` is fixed in the binary.  
- Symbols marked `T` in `.text` are the **method implementations**.  
- Demangling (`-C`) transforms `_ZTV9Processor` into `vtable for Processor` and `_ZN19UpperCaseProcessor4nameEv` into `UpperCaseProcessor::name() const`.

### 1.3 — `readelf`: locating vtables in sections

Vtables reside in `.rodata` (or sometimes `.data.rel.ro` if they contain relocations). Let's verify:

```bash
$ readelf -S oop_O0 | grep -E '(rodata|data\.rel)'
  [16] .rodata           PROGBITS   0000000000404000  004000  000c80  ...
  [20] .data.rel.ro      PROGBITS   0000000000407000  007000  000200  ...
```

With GCC and `-rdynamic`, vtables often end up in `.data.rel.ro` because they contain pointers to functions whose addresses are fixed at load time (relocations). This is an important technical detail: if you search for vtables only in `.rodata`, you may miss them.

---

## Step 2 — Anatomy of a GCC vtable (applied refresher)

Before diving into Ghidra, let's clarify the exact structure of a vtable as GCC produces it according to the Itanium ABI. Each vtable begins **two entries before** the pointer actually used by the vptr:

```
Address              Content                    Role
─────────────────────────────────────────────────────────────
vtable - 0x10        0x0000000000000000         offset-to-top (0 for single inheritance)  
vtable - 0x08        ptr → typeinfo             pointer to typeinfo structure  
vtable + 0x00  ←──── ptr → ~Destructor()        ← this is where the vptr points  
vtable + 0x08        ptr → name()  
vtable + 0x10        ptr → configure()  
vtable + 0x18        ptr → process()  
vtable + 0x20        ptr → status()  
```

The vptr stored in the object points to `vtable + 0x00`, i.e., **after** the offset-to-top and typeinfo. When you read from memory:

- `[rdi + 0x00]` → vptr → points to the first function entry  
- `[vptr + 0x00]` → virtual destructor  
- `[vptr + 0x08]` → `name()`  
- `[vptr + 0x10]` → `configure()`  
- `[vptr + 0x18]` → `process()`  
- `[vptr + 0x20]` → `status()`

> ⚠️ **Virtual destructor**: GCC often emits **two entries** for the destructor in the vtable — the "complete object destructor" and the "deleting destructor" (which calls `operator delete` after destruction). Do not be surprised to see two consecutive pointers before `name()`. The exact index depends on the GCC version and context. Always verify empirically with symbols at `-O0 -g` before analyzing the stripped version.

In practice with our binary, the vtable of `UpperCaseProcessor` will look like:

```
.data.rel.ro + offset:
  [0x00]  0x0000000000000000               ← offset-to-top
  [0x08]  ptr → typeinfo for UpperCaseProcessor
  [0x10]  ptr → UpperCaseProcessor::~UpperCaseProcessor()   ← vptr points here
  [0x18]  ptr → UpperCaseProcessor::~UpperCaseProcessor()   (deleting dtor)
  [0x20]  ptr → UpperCaseProcessor::name()
  [0x28]  ptr → UpperCaseProcessor::configure()
  [0x30]  ptr → UpperCaseProcessor::process()
  [0x38]  ptr → UpperCaseProcessor::status()
```

Each pointer in this table is a direct link to a function in `.text`. It is through these pointers that you will be able to **connect each vtable to its concrete methods**.

---

## Step 3 — Identifying the hierarchy via RTTI

### 3.1 — Itanium ABI typeinfo structure

The `typeinfo` structures stored in `.rodata` / `.data.rel.ro` encode inheritance relationships. Their layout depends on the type of inheritance:

**Class without polymorphic parent** (or hierarchy root) — type `__class_type_info`:

```
typeinfo for Processor:
  [0x00]  ptr → vtable for __class_type_info + 0x10
  [0x08]  ptr → "9Processor"                              ← typeinfo name
```

**Class with a single polymorphic parent** — type `__si_class_type_info` ("si" for *single inheritance*):

```
typeinfo for UpperCaseProcessor:
  [0x00]  ptr → vtable for __si_class_type_info + 0x10
  [0x08]  ptr → "19UpperCaseProcessor"                    ← typeinfo name
  [0x10]  ptr → typeinfo for Processor                    ← PARENT
```

It is the field at offset `+0x10` that interests us: it points to the **direct parent's** typeinfo. By following these pointers, you reconstruct the complete inheritance tree.

### 3.2 — Practical reading with `objdump`

```bash
$ objdump -s -j .data.rel.ro oop_O0 | head -40
```

This command dumps the raw section contents. You will see pointers in little-endian. By cross-referencing with typeinfo addresses known via `nm -C`, you can manually reconstruct parent-child links.

In practice however, this work is most effective in Ghidra, thanks to automatic pointer following and cross-references.

### 3.3 — Reconstructing the inheritance tree

Applying the method above to all typeinfo in our binary, we get:

```
Processor                    (abstract class, root)
├── UpperCaseProcessor       (inherits from Processor)
└── ReverseProcessor         (inherits from Processor)

Pipeline                     (non-polymorphic class? To verify)
```

> 💡 `Pipeline` has a destructor but no pure virtual method in our code. Depending on whether GCC emits a vtable for it (it has a non-virtual destructor in our implementation), it may not appear in the vtables. This kind of nuance is discovered during analysis — do not expect a perfect match with your initial hypotheses.

For plugins, the same technique applies by analyzing each `.so` separately:

```bash
$ nm -C plugins/plugin_alpha.so | grep typeinfo
```

You will discover `Rot13Processor` inheriting from `Processor`, and in `plugin_beta.so`, `XorCipherProcessor` inheriting from `Processor`.

---

## Step 4 — Analysis in Ghidra: the complete reconstruction

### 4.1 — Import and initial analysis

Import `oop_O0` into Ghidra (File → Import File). In the analysis options, make sure the following are enabled:

- **Demangler GNU** — automatically translates mangled symbols into readable C++ names.  
- **Class Recovery from RTTI** — attempts to automatically reconstruct classes from RTTI structures. This option is experimental but gives good results on GCC binaries.  
- **Aggressive Instruction Finder** — useful for stripped binaries.

Launch the analysis (Analysis → Auto Analyze). Ghidra will identify functions, demangle symbols, and attempt to reconstruct classes.

### 4.2 — The Symbol Tree: class overview

After analysis, open the **Symbol Tree** (left panel) and navigate to the **Classes** category. If RTTI recovery worked, you should see:

```
Classes/
├── Processor
│   ├── name()
│   ├── configure()
│   ├── process()
│   ├── status()
│   ├── ~Processor()
│   └── Processor()
├── UpperCaseProcessor
│   ├── name()
│   ├── configure()
│   ├── process()
│   ├── status()
│   └── ~UpperCaseProcessor()
├── ReverseProcessor
│   ├── ...
└── Pipeline
    ├── ...
```

If Ghidra correctly detected the inheritance, derived classes appear as children of `Processor` in the tree. Otherwise, you will need to establish these relationships manually (which will be the case on a stripped binary).

### 4.3 — Manually locating and annotating vtables

Even when automatic analysis works, it is essential to know how to find vtables yourself. Here is the method.

**Method A — From symbols.** In the Symbol Tree, search for `vtable for UpperCaseProcessor` (or `_ZTV19UpperCaseProcessor` if demangling did not work). Double-click to navigate to the corresponding address in the Listing. You will see a series of 64-bit pointers.

**Method B — From RTTI strings.** Open the Defined Strings window (Window → Defined Strings) and search for `UpperCaseProcessor`. You will find the typeinfo name string `19UpperCaseProcessor`. Right-click → References → Show References to Address. This leads you to the typeinfo, and the typeinfo is referenced by the vtable (two entries before the first function pointer).

**Method C — From a virtual call (reverse method).** You encounter a `call [rax+0x18]` in the disassembly. You trace back to `rax` which comes from a `mov rax, [rdi]` — this is a vptr read. Set a breakpoint dynamically (chapter 11) to obtain the vptr address. This address points into the middle of a vtable in `.data.rel.ro`. From there, you identify all entries.

### 4.4 — Creating structured types in Ghidra

Once the vtable is identified, the next step is to **create a Ghidra structure** for the type. Open the Data Type Manager (Window → Data Type Manager), right-click on your program → New → Structure.

For `Processor`:

```
struct Processor {
    void*      vptr;         /* +0x00 — pointer to vtable */
    uint32_t   id_;          /* +0x08 */
    int        priority_;    /* +0x0C — caution: check alignment */
    bool       enabled_;     /* +0x10 */
    /* padding */            /* +0x11 to +0x17 */
};                           /* total size: 0x18 (24 bytes) */
```

> 💡 Actual alignment may differ depending on the optimization level and GCC options. The sizes above correspond to the `-O0` version. At `-O2`, GCC may reorganize or optimize padding. Always verify by observing the offsets used by `mov` instructions in method code.

For `UpperCaseProcessor` (which inherits from `Processor`):

```
struct UpperCaseProcessor {
    /* inherited from Processor */
    void*      vptr;              /* +0x00 */
    uint32_t   id_;               /* +0x08 */
    int        priority_;         /* +0x0C */
    bool       enabled_;          /* +0x10 */
    /* specific to UpperCaseProcessor */
    bool       skip_digits_;      /* +0x11 — placed right after enabled_ (no padding) */
    /* padding */                 /* +0x12 to +0x17 (6 bytes, alignment for size_t) */
    size_t     bytes_processed_;  /* +0x18 */
};  /* total size: 0x20 (32 bytes) */
```

The most reliable way to determine the exact layout is to examine the class methods: each access to `this->member` translates to a `mov ... [rdi + offset]` (in System V AMD64, `rdi` is `this` at the beginning of the method). Systematically note the observed offsets.

### 4.5 — Cross-references (XREF): who calls what?

Cross-references are your primary weapon for understanding execution flow through polymorphism.

**On a method**: place the cursor on `UpperCaseProcessor::process()` and press `Ctrl+Shift+F` (or right-click → References → Show References To). You will see:

- A reference from the **vtable** (this is the entry pointing to this method).  
- References from **direct** call sites (if the compiler devirtualized the call at `-O2`).

**On the vtable**: XREFs on the vtable itself show **where the vtable is assigned to the vptr** — that is, in the class constructor. The typical pattern in the constructor is:

```asm
; UpperCaseProcessor constructor
lea    rax, [vtable for UpperCaseProcessor + 0x10]  
mov    QWORD PTR [rdi], rax          ; this->vptr = &vtable[0]  
```

The `+0x10` offset skips the offset-to-top and typeinfo to point to the first function entry. Each concrete class has this pattern in its constructor, and the XREFs on the vtable therefore list all constructors.

**On the typeinfo**: XREFs on a typeinfo lead to the vtable (which references it at offset `-0x08`) and possibly to `dynamic_cast` calls or `catch` blocks that use it for runtime type resolution.

### 4.6 — Function Graph: visualizing dispatch

For a particular virtual call, the **Function Graph** (Window → Function Graph) clearly shows the sequence:

1. Loading the vptr from the object  
2. Reading the entry in the vtable  
3. Indirect call

By hovering over the graph nodes, you can follow the data flow and identify which vtable slot is called.

---

## Step 5 — The same work on a stripped binary

On `oop_O2_strip`, the `.symtab` symbols are gone. No more `vtable for UpperCaseProcessor`, no more `UpperCaseProcessor::process()` in `nm`. Here is what changes and what remains.

### What disappears

- All function names in `.symtab` and `.dynsym` (except dynamic symbols needed by the linker: `dlopen`, `printf`, etc.).  
- Method names in Ghidra's Symbol Tree — functions appear as `FUN_00401a30`, `FUN_00401b80`, etc.  
- The `vtable for X` labels — vtables are still there, but anonymous.

### What survives

- **RTTI strings** in `.rodata` (`9Processor`, `19UpperCaseProcessor`...). They survive standard stripping. Only `-fno-rtti` removes them.  
- **Typeinfo structures** — still in `.data.rel.ro`, still functional.  
- **The vtables themselves** — the function pointer arrays are intact.  
- **Literal strings** used in the code (`"UpperCaseProcessor"`, `"skip_digits"`, `"[UpperCase #%u] destroyed"`, etc.) — referenced by methods.

### Reconstruction strategy without symbols

1. **Start from RTTI strings** to identify existing classes and their inheritance relationships (same method as step 3).

2. **Locate vtables** by searching for typeinfo structures: each typeinfo is preceded (at offset `-0x08`) by its address in a vtable. You can also search for aligned pointer patterns in `.data.rel.ro` that point into `.text`.

3. **Identify methods** by following pointers in each vtable. Each entry points to a `FUN_XXXXXXXX` — this is a virtual method. Rename it based on its position in the vtable and what the decompiler reveals.

4. **Use literal strings** as clues. If `FUN_00401a30` contains a reference to the string `"[UpperCase #%u] destroyed"`, it is probably the `UpperCaseProcessor` destructor. If another function references `"skip_digits"`, it is probably `configure()`.

5. **Compare vtables across classes**. The base class `Processor` vtable will potentially contain `__cxa_pure_virtual` entries (for pure virtual methods). Derived class vtables will have the same slots filled with concrete functions. The `__cxa_pure_virtual` entry is a reliable marker for abstract classes.

6. **Verify your hypotheses** by examining constructors. Each constructor assigns a specific vptr — XREFs on a vtable identify the constructor of the corresponding class.

> 💡 **The identification loop**: vtable → methods → strings used → class name → typeinfo → parent → parent vtable. Each puzzle piece helps you identify the next one. It is rarely linear, but all the information cross-references.

---

## Step 6 — Reconstructing plugin `.so` classes

The plugins (`plugin_alpha.so`, `plugin_beta.so`) are independent ELF binaries. They must be analyzed separately, but the method is identical.

The plugins' peculiarity is that they export `extern "C"` symbols:

```bash
$ nm -CD plugins/plugin_alpha.so | grep ' T '
0000000000001200 T create_processor
0000000000001280 T destroy_processor
```

These two symbols are your **entry point** into the plugin. By analyzing `create_processor` in Ghidra, you will see:

1. A call to `operator new` with the object size — this gives you the class's `sizeof`.  
2. The call to the plugin class's constructor.  
3. In the constructor, the vptr assignment — which leads you to the plugin's vtable.

From the vtable, you find all methods implemented by the plugin.

The plugin's typeinfo structure points to `typeinfo for Processor` in the main executable (resolved via the dynamic linker thanks to `-rdynamic`). This is how RTTI works across module boundaries — and it is also how you confirm that the plugin class inherits from `Processor`.

```
typeinfo for Rot13Processor (in plugin_alpha.so):
  [0x00]  ptr → __si_class_type_info vtable
  [0x08]  ptr → "15Rot13Processor"
  [0x10]  ptr → typeinfo for Processor          ← relocation to the executable
```

---

## Step 7 — Building the final class diagram

Combining all the information gathered — from the executable and plugins — you should be able to reconstruct the following diagram:

```
                        ┌───────────────────────────┐
                        │      <<abstract>>         │
                        │       Processor           │
                        ├───────────────────────────┤
                        │ - id_: uint32_t           │
                        │ - priority_: int          │
                        │ - enabled_: bool          │
                        ├───────────────────────────┤
                        │ + ~Processor()            │   ← virtual
                        │ + name(): const char*     │   ← pure virtual
                        │ + configure(): bool       │   ← pure virtual
                        │ + process(): int          │   ← pure virtual
                        │ + status(): const char*   │   ← pure virtual
                        │ + id(): uint32_t          │   ← non-virtual
                        │ + priority(): int         │   ← non-virtual
                        │ + enabled(): bool         │   ← non-virtual
                        │ + set_enabled(bool): void │   ← non-virtual
                        └──────────┬────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
   ┌──────────┴────────┐   ┌───────┴────────┐   ┌───────┴──────────┐
   │ UpperCaseProcessor│   │ReverseProcessor│   │  (via plugins)   │
   ├───────────────────┤   ├────────────────┤   │                  │
   │- skip_digits_     │   │- word_mode_    │   │ Rot13Processor   │
   │- bytes_processed_ │   │- chunks_proc._ │   │ XorCipherProc.   │
   └───────────────────┘   └────────────────┘   └──────────────────┘
```

Non-virtual methods (`id()`, `priority()`, etc.) **do not appear in the vtable**. At `-O2`, they are often inlined by GCC and disappear completely as distinct functions. You will find them as direct memory accesses (`mov eax, [rdi+0x08]` for `id()`) in the calling code.

---

## Method summary

Class hierarchy reconstruction follows an iterative process that can be summarized as follows:

**With symbols** (`-g`, non-stripped): vtable names, typeinfo, and method names are directly readable. Reconstruction is nearly automatic with Ghidra. Use this version to **learn the layout** before moving to the stripped version.

**Without symbols** (stripped): RTTI strings survive and provide class names. Typeinfo encodes inheritance. Vtables contain pointers to methods. Literal strings in methods confirm your identifications. The work takes longer but all the information is present — it simply needs to be linked manually.

**Without RTTI** (`-fno-rtti` + stripped): the most difficult case. No class names, no typeinfo. Vtables must be identified by their structure (arrays of pointers to `.text` in `.data.rel.ro`), constructors by the vptr write, and inheritance relationships by the sharing of the first vtable slots between parent and child classes. This case goes beyond the scope of this chapter, but the fundamental method remains the same — only the clues change.

Regardless of the difficulty level, the guiding principle is the same: **the vtable is the core of the analysis**. Find the vtables, and you will find the classes, their methods, their constructors, and their inheritance relationships.

---


⏭️ [RE of a plugin system (dynamic loading `.so` via `dlopen`/`dlsym`)](/22-oop/02-plugin-system-dlopen.md)
