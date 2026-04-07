🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Reconstruct the classes of the `ch17-oop` binary from disassembly alone

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## Objective

This checkpoint validates all the knowledge acquired in Chapter 17. The goal is to produce a **complete reconstruction of the object-oriented architecture** of the `ch17-oop` binary from the disassembly, without consulting the `oop.cpp` source code.

The final deliverable is a structured document containing: the class hierarchy, object memory layouts, annotated vtables, method prototypes, and a reconstructed class diagram. This type of deliverable corresponds to what an RE analyst would produce in a professional context — security audit, compatibility analysis, or documentation of a third-party component without source.

## Target binary

The checkpoint is performed in two passes on two binary variants:

| Pass | Binary | Objective |  
|------|--------|-----------|  
| **Pass 1** (learning) | `ch17-oop_O0` (`-O0 -g`) | Reconstruct the architecture with the comfort of symbols and non-optimized code. Learn the patterns. |  
| **Pass 2** (validation) | `ch17-oop_O2_strip` (`-O2 -s`) | Reconstruct the same architecture **without symbols and with optimizations**. This is the pass that truly validates skills. |

Pass 1 serves as reference and safety net. Pass 2 is the real challenge. Compare your results from both passes to evaluate your progress.

Compile the binaries if not already done:

```bash
cd binaries/ch17-oop/  
make all  
```

## Expected deliverables

The reconstruction document must contain the following sections.

### 1. Polymorphic class inventory

The complete list of classes that have at least one virtual method, with for each:

- The class name.  
- The inheritance type (root, simple, multiple).  
- The parent class(es).  
- Whether abstract or concrete (presence of `__cxa_pure_virtual` in the vtable).

**Expected format:** a table or organized list. For pass 2, document the method used to recover each name (`_ZTS` strings, dynamic symbols, typeinfo).

### 2. Class hierarchy diagram

A diagram showing inheritance relationships between all classes, including:

- Inheritance arrows (single line for simple inheritance, double line or annotation for multiple inheritance).  
- Abstract classes marked distinctly (italic, annotation, or convention of your choice).  
- Exception classes in a separate branch.

The diagram can be in ASCII art, Mermaid, PlantUML, or hand-drawn — the format doesn't matter as long as the information is correct and readable.

### 3. Annotated vtables

For **each polymorphic class**, the complete vtable with:

- The vtable address in `.rodata`.  
- The offset-to-top and typeinfo pointer.  
- Each numbered slot with: the address of the pointed function, the method name (demangled or reconstructed), and an indication whether it's a class's own method, inherited, or an override.

For classes with multiple inheritance, document both parts of the composite vtable and identify the thunks.

**Example format:**

```
vtable for Circle @ 0x403d00:
  [-16] offset-to-top = 0
  [-8]  typeinfo      = 0x403f20 → _ZTI6Circle
  [0]   slot 0 : 0x401c10 → Circle::~Circle() [D1]    (override)
  [8]   slot 1 : 0x401c40 → Circle::~Circle() [D0]    (override)
  [16]  slot 2 : 0x401b14 → Circle::area() const       (override)
  [24]  slot 3 : 0x401b38 → Circle::perimeter() const  (override)
  [32]  slot 4 : 0x401b64 → Circle::describe() const   (override)
```

### 4. Object memory layouts

For **each concrete class** (instantiable), the object memory layout with:

- The total `sizeof` of the object.  
- The vptr (or vptrs for multiple inheritance) with their offset.  
- Each member with its offset, size, and reconstructed type.

Members are deduced from analyzing constructors (which initialize each field) and methods (which read/write the fields).

**Example format:**

```
Circle (sizeof = 64):
  offset 0   : vptr (8 bytes) → vtable for Circle
  offset 8   : name_ (std::string, 32 bytes)
  offset 40  : x_ (double, 8 bytes)
  offset 48  : y_ (double, 8 bytes)
  offset 56  : radius_ (double, 8 bytes)
```

### 5. Reconstructed method prototypes

For each class, the list of identified methods with:

- The reconstructed prototype (return type, name, parameters).  
- Whether virtual or not.  
- The calling convention (parameters in which registers).

For pass 2, method names will be descriptive names you assign based on observed logic (for example `compute_area` instead of `area` if the exact name is unknown).

### 6. STL container identification

List each STL container usage identified in classes and functions, with:

- The container type (`std::vector`, `std::map`, `std::string`, etc.).  
- The element type (reconstructed).  
- The identification method used (sizeof, access pattern, PLT symbols).

### 7. C++ mechanism identification

For each Chapter 17 mechanism you identify in the binary, a brief note documenting:

- **Name mangling**: examples of demangled symbols and what they reveal.  
- **Vtables/vptr**: how you identified virtual dispatch.  
- **RTTI**: typeinfo structures found and the hierarchy they reveal.  
- **Exceptions**: `try`/`catch` blocks identified, intercepted exception types.  
- **Templates**: instantiations found, parameter types.  
- **Lambdas**: closures identified, their captures.  
- **Smart pointers**: `shared_ptr` patterns (atomic operations) and `unique_ptr` identified.

## Recommended methodology

The reconstruction follows a progressive process. Each step produces information that feeds the next.

### Phase A — Initial reconnaissance

Start with a binary triage using basic tools to establish the scope:

- `file` to confirm the type (64-bit ELF, dynamically linked).  
- `checksec` for protections.  
- `strings` with typeinfo string filtering (`grep -oP '^\d+[A-Z]\w+'`) to immediately get the class list.  
- `nm -C` (pass 1) or `nm -D -C` (pass 2) for available symbols.  
- `readelf -S` to identify present sections (`.rodata` for vtables, `.gcc_except_table` for exceptions).

### Phase B — Hierarchy reconstruction via RTTI

Locate typeinfo structures in `.rodata` (Section 17.3). For each typeinfo:

- Identify the type (`__class_type_info`, `__si_class_type_info`, `__vmi_class_type_info`).  
- Follow `__base_type` pointers to reconstruct inheritance links.  
- For `__vmi_class_type_info`, read the `__base_info` array to identify multiple bases and their offsets.

Produce the hierarchy diagram at the end of this phase.

### Phase C — Vtable analysis

For each vtable identified via `_ZTV` symbols (pass 1) or via typeinfo pointers (pass 2):

- List the slots and resolve addresses to corresponding functions.  
- Identify pure virtual methods (`__cxa_pure_virtual`).  
- Compare derived class vtables with parent class vtables to identify overrides.  
- For composite vtables (multiple inheritance), separate the parts and identify the thunks.

### Phase D — Constructor analysis and memory layout

Locate each class's constructors (Section 17.2). They're recognized by:

- The call to the parent constructor with the same `this`.  
- Writing the vptr at offset 0.  
- Initializing members at fixed offsets.

For each constructor, note each accessed offset and the type of data written. Cross-reference with class methods (which read the same offsets) to confirm the layout.

### Phase E — Method analysis and logic

Analyze the content of each virtual method (identified via vtables) and non-virtual methods (identified via XREFs and `main` code). Reconstruct prototypes, identify STL containers used, lambda patterns, smart pointer operations, and try/catch blocks.

### Phase F — Cross-verification

Verify your reconstruction's consistency:

- Each class in the RTTI hierarchy must have a corresponding vtable.  
- Member offsets in the layout must be consistent between the constructor and all methods.  
- Derived class vtables must have at least as many slots as parent vtables.  
- Each class's `sizeof` must be consistent with allocations observed in the code.

## Suggested tools

| Tool | Usage in this checkpoint |  
|------|--------------------------|  
| `nm -C` / `nm -D -C` | List and demangle symbols |  
| `objdump -d -C -M intel` | Disassemble with demangled names |  
| `strings` | Extract typeinfo name strings |  
| `readelf -S` / `readelf --debug-dump=frames` | Inspect sections, FDEs |  
| `c++filt` | Demangle individual symbols |  
| Ghidra | Primary analysis: decompiler, XREF, vtable navigation |  
| GDB (optional) | Confirm layouts dynamically (`print sizeof(Circle)`, etc.) |

## Validation criteria

The checkpoint is considered passed when the following conditions are met:

**Level 1 — Fundamentals (pass 1 with `oop_O0`):**

- [ ] All polymorphic classes are identified and named.  
- [ ] The inheritance hierarchy is correct (parents, inheritance type).  
- [ ] At least 3 vtables are fully annotated (all slots identified).  
- [ ] The memory layout of at least 3 concrete classes is reconstructed with correct offsets.  
- [ ] `Canvas`'s multiple inheritance is correctly documented (two vptrs, thunks).  
- [ ] At least one `try`/`catch` block is identified with intercepted exception types.

**Level 2 — Intermediate (complete pass 1):**

- [ ] All vtables are annotated, including `Canvas`'s composite vtable.  
- [ ] Memory layouts of all concrete classes are reconstructed.  
- [ ] Template instantiations (`Registry<K,V>`) are identified with their parameters.  
- [ ] At least 2 STL containers are identified with their element type.  
- [ ] At least 1 lambda is identified with its captures.  
- [ ] `shared_ptr` patterns (atomic operations) are spotted.

**Level 3 — Advanced (pass 2 with `oop_O2_strip`):**

- [ ] The class hierarchy is reconstructed without local symbols, solely via RTTI and dynamic symbols.  
- [ ] At least 5 vtables are annotated on the stripped binary.  
- [ ] Memory layouts of at least 3 classes are reconstructed on the optimized binary (offsets may differ slightly from `-O0` due to alignment).  
- [ ] Optimization effects are documented: devirtualization, method inlining, code elimination.  
- [ ] The final document could serve as a base for writing a `.h` header allowing interaction with the binary (which will be the subject of Chapter 20's checkpoint).

## Tips for success

**Start with RTTI, not with the code.** RTTI gives you the map of the territory (which classes exist, how they're related) before you explore the terrain (the method code). Without this map, you risk getting lost in details.

**Work class by class.** Don't try to reconstruct everything in one pass. Take a class (start with the simplest, for example `Circle`), reconstruct it entirely (vtable, layout, methods), then move to the next. Each reconstructed class makes the following ones easier as patterns repeat.

**Use constructors as the source of truth.** Constructors initialize all fields in order and write the vptr. They're the best source for memory layout. Destructors confirm in mirror (destruction in reverse order).

**Take notes as you go.** Each identified offset, each named function, each discovered inheritance relationship must be noted immediately. Reconstruction is a puzzle — every piece counts and may be useful later.

**Don't get stuck on STL internals.** If you identify a `std::vector<shared_ptr<Shape>>`, note it and move on. You don't need to understand the internal code of `_M_realloc_insert` to succeed at this checkpoint. Focus on the application class architecture.

**For pass 2, build on pass 1.** You already know what you're looking for. The question is no longer "which classes exist?" but "how to find them without symbols?" It's a methodology exercise, not a discovery one.

---

> 📋 **Answer key available:** [`solutions/ch17-checkpoint-solution.md`](/solutions/ch17-checkpoint-solution.md)

---


⏭️ [Chapter 18 — Symbolic execution and constraint solvers](/18-symbolic-execution/README.md)
