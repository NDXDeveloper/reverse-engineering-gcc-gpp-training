🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Import `ch08-oop` into Ghidra, reconstruct the class hierarchy

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## Goal

This checkpoint validates all the skills acquired in Chapter 8 by mobilizing them on a concrete case: complete analysis of an object-oriented C++ binary in Ghidra. The target binary is `ch08-oop_O0` (compiled without optimization, with symbols), provided in `binaries/ch08-oop/`.

The final objective is to produce a **summary document** (Markdown or text) reconstructing the program's class hierarchy: class names, inheritance relationships, virtual methods, and the structure of their fields. This document must be produced solely from the analysis in Ghidra — without consulting the source code.

> 💡 The source code `oop.cpp` is available in the same directory for verification **afterwards**. Consult it only after finishing your reconstruction to evaluate your work's accuracy.

---

## Skills evaluated

This checkpoint covers the following chapter sections:

| Section | Skill mobilized |  
|---|---|  
| 8.1 | Create a dedicated project, import the binary correctly |  
| 8.2 | Launch automatic analysis with appropriate options for a C++ binary |  
| 8.3 | Navigate the CodeBrowser: locate `main`, explore functions via Symbol Tree, read the Decompiler, use the Function Graph |  
| 8.4 | Rename functions and variables, add comments, modify function signatures |  
| 8.5 | Identify and interpret vtables, exploit RTTI to recover class names and inheritance relationships, recognize exception patterns |  
| 8.6 | Reconstruct data structures of classes in the Data Type Manager |  
| 8.7 | Use cross-references to trace method calls, link vtables to constructors, trace back from strings |  
| 8.8 | *(Optional)* Write a script that automates hierarchy extraction |  
| 8.9 | *(Optional)* Perform import and analysis via `analyzeHeadless` |

---

## Target binary

```bash
cd binaries/ch08-oop/  
make all  
```

Work on the **`ch08-oop_O0`** variant for this checkpoint. It's the most favorable case (no optimization, symbols present), which lets you validate your methodology without the additional complexity of stripping or inlining.

If you want to go further, repeat the analysis on `ch08-oop_O2_strip` (optimized and stripped) to measure the information loss and adapt your approach.

---

## Expected deliverables

### 1. Class hierarchy diagram

A textual or graphical schema showing the identified classes and their inheritance relationships. Suggested format:

```
BaseClass
├── DerivedClass1
└── DerivedClass2
    └── DerivedClass3
```

For each inheritance relationship, indicate how you identified it (RTTI, shared vtable, parent constructor call).

### 2. Description of each class

For each identified class, document:

- **Name** — as extracted from the RTTI or symbols.  
- **Total size** — deduced from the `operator new` argument or field analysis.  
- **Vtable** — vtable address, number of entries, list of virtual methods with their name (or a name you've assigned if the binary was stripped).  
- **Data fields** — offset, type, assigned name, and justification. Distinguish inherited fields from fields specific to the class.  
- **Constructor(s) and destructor(s)** — identified addresses, clues that enabled their identification (vptr initialization, parent constructor call, `operator new` call).  
- **Abstract or concrete class** — and how you determined it (presence of `__cxa_pure_virtual` in the vtable, or direct instantiation observed).

### 3. Ghidra structures

Create in Ghidra's Data Type Manager a structure for each identified class, with named and typed fields. Apply these structures to the `this` parameters of matching methods. The Decompiler's pseudo-code should reflect your annotations (access by field names rather than raw offsets).

### 4. *(Optional)* Extraction script

Write a Ghidra Python script that automates hierarchy extraction: it walks through the RTTI structures, follows parent class pointers, and produces a summary on the Console or in a JSON file.

---

## Recommended methodology

The checkpoint does not prescribe a unique procedure — the goal is precisely that you build your own workflow by combining the chapter's techniques. However, here is a reminder of the most effective entry points for this type of analysis.

### Recommended entry points

**The Symbol Tree** is your best ally on a binary with symbols. Functions are organized by namespace and class, which immediately reveals the program's structure. Browse the namespaces to identify classes and their methods.

**The RTTI** provides class names and inheritance links. Look for typeinfo name strings in Defined Strings or `typeinfo for *` labels in the Symbol Tree. Follow `__base_type` pointers to reconstruct inheritance chains.

**Vtables** list the virtual methods of each class. Compare parent and child vtables to identify which methods are overridden (different pointers) and which are inherited (identical pointers).

**Constructors** are the best place to observe the total size of an object (`operator new` argument) and the layout of its fields (sequential initializations). The writing of the vptr at `[this + 0]` confirms the vtable's address.

**Cross-references** allow linking all these elements together: XREF `(*)` to a vtable to find constructors, XREF `(c)` to a constructor to find instantiation sites, XREF `(r)` to a string to find code that uses it.

### Common pitfalls

**Confusing the two destructors** — Reminder from section 8.5: GCC generates a *complete object destructor* (D1) and a *deleting destructor* (D0) for each class with a virtual destructor. These are two distinct entries in the vtable, not two different destructors in the source code.

**Forgetting the vptr in the layout** — The vptr is the first field of every polymorphic object (offset 0, 8 bytes). It does not appear in the source code but it is present in the binary. Your structure must include it.

**Confusing inherited and own fields** — The parent class's fields are present in the derived class's object, at the same offsets. If `Animal` has a `name` field at offset 0x10 and `Dog` inherits from `Animal`, then `Dog` also has a field at offset 0x10 — it's the same inherited field, not a field specific to `Dog`.

**Neglecting padding** — Field alignment can create holes in the structure. If you observe an offset "jump" between two fields (for example, a `char` field at offset 0x08 and the next field at offset 0x10), there is padding in between. The structure's total size can be greater than the sum of its fields' sizes.

---

## Validation criteria

Your reconstruction is successful if:

- ✅ All classes in the program are identified and named.  
- ✅ Inheritance relationships are correct and documented with evidence (RTTI, vtable, constructor).  
- ✅ Virtual methods of each class are listed and correctly attributed (overridden vs inherited).  
- ✅ The structures in Ghidra's Data Type Manager reflect the real memory layout, with named and typed fields.  
- ✅ The Decompiler's pseudo-code for the main methods uses field names rather than raw offsets, thanks to the application of your structures.  
- ✅ The summary document is clear, structured, and traceable (each statement is linked to an observable clue in Ghidra).

Then compare your reconstruction with the `oop.cpp` source code to evaluate your accuracy. The most common discrepancies concern field names (impossible to recover without DWARF symbols) and the exact order of non-virtual methods (which do not appear in vtables).

---

## Going further

If you completed the checkpoint on `ch08-oop_O0` and wish to deepen, here are two extensions:

**Extension 1 — Stripped binary.** Repeat the analysis on `ch08-oop_O2_strip`. Function symbols are absent, but RTTI is still present (unless compiled with `-fno-rtti`). Your workflow will have to rely more on RTTI and structural patterns than on the Symbol Tree. Compare the time and difficulty with the non-stripped version.

**Extension 2 — Automatic extraction script.** Write a Python Ghidra script that automatically walks through all RTTI structures of the binary, rebuilds the inheritance tree, and produces a formatted report. This script can be reused on any C++ binary analyzed in Ghidra. Chapter 35 will give you additional techniques to industrialize this type of script.

---


⏭️ [Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja](/09-ida-radare2-binja/README.md)
