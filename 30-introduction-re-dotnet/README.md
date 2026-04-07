🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 30 — Introduction to .NET RE

> 🔗 **Part VII — Bonus: RE on .NET / C# Binaries**  
> *Direct bridge with C# development — the same RE concepts apply to CIL/.NET bytecode.*

---

## Why a chapter on .NET in a training focused on GCC?

Throughout Parts I to VI, we worked exclusively on **native** binaries: C or C++ code compiled by GCC (or Clang) into x86-64 instructions directly executable by the processor. This model — source code → machine code — is the core of this training, and it will remain so.

So why open a parenthesis on .NET?

Because in the reverse engineer's daily practice, the boundaries between ecosystems are rarely watertight. A security audit may require you to analyze a C# application that internally calls native libraries compiled with GCC via the **P/Invoke** mechanism. A dropper may embed an obfuscated .NET payload alongside a native ELF loader. An internal enterprise tool may mix managed and native code in a single deployment. Knowing how to recognize a .NET assembly when you encounter one — and having the basic reflexes to analyze it — is part of a complete reverser's toolkit.

The other reason is **pedagogical**: RE on .NET strikingly illustrates how much the compilation model changes the difficulty of analysis. Where a stripped, `-O2`-optimized GCC binary confronts you with hours of manual reconstruction, a non-obfuscated .NET assembly often decompiles in a few seconds to C# code nearly identical to the original source. Understanding *why* this difference exists — and *when* it disappears (obfuscation, NativeAOT) — reinforces your understanding of the fundamental mechanisms covered in previous parts.

## What this chapter covers

This chapter lays the groundwork needed before tackling decompilation (Chapter 31) and .NET dynamic analysis (Chapter 32). It does not claim to replace a dedicated .NET RE training, but to give you the keys to:

- **Understand the .NET execution model** and how it radically differs from the native GCC model. CIL (Common Intermediate Language) bytecode is not machine code: it is interpreted then compiled on the fly (JIT) by the runtime. This distinction has major consequences on what a reverser can extract from a binary.

- **Read the internal structure of a .NET assembly**: the metadata, type tables, CLR-specific PE headers. You'll see that where a native ELF exposes sections like `.text`, `.data`, and `.rodata`, a .NET assembly carries with it a nearly complete description of its types, methods, and dependencies — a goldmine for the analyst.

- **Recognize common obfuscators** that try to compensate for this transparency by making the bytecode unreadable: symbol renaming, string encryption, bogus control flow insertion. You'll learn to identify the signatures of the most widespread tools (ConfuserEx, Dotfuscator, SmartAssembly) without confusing them with legitimate code.

- **Apply tools you already know** — `file`, `strings`, ImHex — to perform an initial triage on a .NET assembly, exactly as you would on a native ELF (Chapter 5). You'll find that some reflexes transfer directly, while others need to be adapted.

- **Anticipate the ecosystem's evolution** with NativeAOT and ReadyToRun, two technologies that blur the boundary between managed and native code. When a C# binary is compiled ahead-of-time, it produces a native executable that looks much more like GCC output than a classic .NET assembly — and the techniques from Parts I through IV become relevant again.

## What this chapter does not cover

The goal is not to make you a .NET RE expert in three sections. The following topics are deliberately out of scope or covered in subsequent chapters:

- Actual **decompilation** with ILSpy, dnSpy, or dotPeek → Chapter 31.  
- **Debugging** and **hooking** of .NET assemblies → Chapter 32.  
- RE of **Java/JVM** binaries (Kotlin, Scala) — a similar ecosystem in spirit, but with its own tools and specifics, which falls outside the scope of this training.  
- **Exploitation** of vulnerabilities in .NET code (deserialization, type confusion...) — a domain in its own right that belongs more to application pentesting.

## Prerequisites for this part

If you've followed Parts I through V of this training, you have all the necessary foundations. The following concepts will be drawn upon:

- The **quick triage workflow** covered in Chapter 5 (section 5.7): `file`, `strings`, `readelf`, `checksec`.  
- **Executable structure** (headers, sections, segments) covered in Chapter 2.  
- **Dynamic linking concepts** (PLT/GOT, symbol resolution) covered in sections 2.7 through 2.9 — useful for understanding P/Invoke and the bridge between managed and native code.  
- Using **ImHex** to inspect binary structures (Chapter 6).

No prior experience in C# or .NET development is required. Concepts will be introduced progressively, and parallels with C/C++ will be systematically drawn.

## Chapter outline

| Section | Title | Description |  
|---------|-------|-------------|  
| 30.1 | Fundamental differences: CIL bytecode vs native x86-64 code | The .NET execution model compared to native GCC compilation |  
| 30.2 | Structure of a .NET assembly: metadata, PE headers, CIL sections | Anatomy of a .NET file, mirroring the ELF analysis from Chapter 2 |  
| 30.3 | Common obfuscators: ConfuserEx, Dotfuscator, SmartAssembly | Recognizing and identifying protections applied to bytecode |  
| 30.4 | Inspecting an assembly with `file`, `strings` and ImHex | Applying Chapter 5's quick triage to a .NET target |  
| 30.5 | NativeAOT and ReadyToRun: when C# becomes native code | The convergence between both worlds and its implications for RE |

---

> 💡 **Note** — This chapter does not have a dedicated checkpoint. The knowledge gained will be validated by the Chapter 32 checkpoint, which draws on all knowledge from Chapters 30 through 32.

---

*Let's start with the fundamental question: what distinguishes, at the lowest level, a binary produced by `gcc` from an assembly produced by `dotnet build`?*


⏭️ [Fundamental differences: CIL bytecode vs native x86-64 code](/30-introduction-re-dotnet/01-cil-vs-native.md)
