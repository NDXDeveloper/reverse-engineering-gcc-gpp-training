🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 31 — Decompiling .NET Assemblies

> 📦 **Part VII — Bonus: RE on .NET / C# Binaries**  
> 

---

## Why this chapter?

Chapter 30 laid the foundations: structure of a .NET assembly, role of CIL bytecode, specific PE headers, and common obfuscators. You now know *what* an assembly contains. This chapter answers the next question: **how do you transform it into readable, exploitable C# code?**

This is where .NET reverse engineering reveals its major advantage over native x86-64 binary RE. CIL bytecode preserves a considerable amount of semantic information — type names, method signatures, inheritance hierarchies, property metadata — that the native compiler irrecoverably destroys. A .NET decompiler doesn't produce approximate pseudo-code like Ghidra on a stripped ELF binary: it produces **C# code nearly identical to the original source**, with only local variable names missing (unless the PDB is present).

This decompilation fidelity has a direct consequence on your RE methodology: where analyzing a native binary requires hours of renaming, structure reconstruction, and back-and-forth between disassembler and debugger, a non-obfuscated .NET assembly reads almost like an open source project. The real challenge begins when the author has applied an obfuscator — and that's precisely why this chapter also covers bypassing techniques.

---

## What you will learn

This chapter explores three major .NET decompilers — **ILSpy**, **dnSpy/dnSpyEx**, and **dotPeek** — by confronting them with the same assemblies so you can judge their strengths and weaknesses for yourself. You will learn to:

- Open, navigate, and export decompiled C# code with each of the three tools.  
- Exploit each decompiler's unique features: dnSpy's integrated debugging, ILSpy's complete project export, dotPeek's advanced navigation.  
- Objectively compare their results on the same assembly, including in the presence of optimizations or modern C# constructs (`async/await`, `Span<T>`, pattern matching).  
- Identify the obfuscator applied to an assembly and use **de4dot** to restore analyzable bytecode.  
- Apply manual bypassing techniques when de4dot isn't enough.

---

## Prerequisites

This chapter assumes you have mastered the concepts from Chapter 30:

- The distinction between CIL bytecode and native code (section 30.1).  
- The structure of a .NET assembly: metadata tables, PE headers, CIL sections (section 30.2).  
- Common obfuscators and their visible effects (section 30.3) — this chapter shows how to counter them in practice.

Minimal familiarity with the C# language is necessary to evaluate the quality of decompiled code. You don't need to be an experienced C# developer, but you should be able to read a class, understand a property, follow an `if/else`, and recognize a method call.

If you're coming directly from Part IV (native RE), keep in mind that the workflow is fundamentally different: you no longer reason in registers and memory offsets, but in types, methods, and namespaces.

---

## Tools used in this chapter

| Tool | Role | License | Platform |  
|---|---|---|---|  
| **ILSpy** | Open source C# decompiler, community reference | MIT | Windows, Linux, macOS (via Avalonia) |  
| **dnSpy / dnSpyEx** | Decompiler + integrated debugger, IL editing | GPL v3 (dnSpyEx = maintained fork) | Windows (.NET Framework) |  
| **dotPeek** | JetBrains decompiler, IDE-like navigation | Free (proprietary) | Windows |  
| **de4dot** | Automatic .NET assembly deobfuscator | GPL v3 | Windows, Linux (Mono/.NET) |

> 💡 **dnSpy** is no longer maintained by its original author since 2020. The community fork **dnSpyEx** continues active development and adds support for .NET 6/7/8+. Throughout this chapter, "dnSpy" refers to dnSpyEx unless otherwise noted.

---

## .NET decompilation vs native decompilation: a paradigm shift

To properly situate this chapter relative to Parts II–IV of the tutorial, it's useful to understand *why* .NET decompilation is so different from decompiling a GCC binary.

When GCC compiles C/C++ to x86-64 machine code, it performs destructive transformations: local variable names disappear, structures are flattened into offset-based memory accesses, `for` loops become `cmp`/`jcc` sequences, and optimizations (`-O2`, `-O3`) rearrange code to the point of making it unrecognizable. The decompiler (Ghidra, RetDec) must then *guess* the original structure from indirect clues — it's a heuristic process, approximate by nature.

The C# compiler (Roslyn) performs a very different transformation. It produces CIL (Common Intermediate Language) bytecode designed to be interpreted or compiled on the fly (JIT) by the .NET runtime. This bytecode preserves:

- **Full type names**: namespaces, classes, interfaces, enums, delegates.  
- **Method signatures**: names, parameter types, return type, access modifiers (`public`, `private`, `internal`...).  
- **Property and event metadata**: getters, setters, handlers.  
- **Inheritance hierarchy and interface implementations**.  
- **Custom attributes** applied to types and methods.  
- **Reference tokens** to other assemblies and external types.

All this information is stored in the assembly's **metadata tables**, and decompilers use it to reconstruct high-fidelity C# code. Information loss is essentially limited to local variable names (unless the PDB file is available), developer comments, and certain syntactic subtleties (a ternary operator may become an `if/else`, a `switch` on patterns may be restructured).

This richness has a flip side: it makes intellectual property protection much harder for .NET developers, hence the existence of an entire obfuscator industry. This is why section 31.5 of this chapter is dedicated to bypassing obfuscation — it's the only real obstacle between you and the source code.

---

## Chapter outline

- **31.1** — [ILSpy — open source C# decompilation](/31-decompilation-dotnet/01-ilspy.md)  
- **31.2** — [dnSpy / dnSpyEx — decompilation + integrated debugging](/31-decompilation-dotnet/02-dnspy-dnspyex.md)  
- **31.3** — [dotPeek (JetBrains) — navigation and source export](/31-decompilation-dotnet/03-dotpeek.md)  
- **31.4** — [Comparison: ILSpy vs dnSpy vs dotPeek](/31-decompilation-dotnet/04-tools-comparison.md)  
- **31.5** — [Decompiling despite obfuscation: de4dot and bypass techniques](/31-decompilation-dotnet/05-de4dot-bypassing.md)

---


⏭️ [ILSpy — open source C# decompilation](/31-decompilation-dotnet/01-ilspy.md)
