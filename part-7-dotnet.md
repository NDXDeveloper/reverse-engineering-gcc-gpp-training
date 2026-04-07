🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part VII — Bonus: RE on .NET / C# Binaries

C# and the .NET ecosystem are ubiquitous in enterprise — business applications, internal tools, Windows services, Unity games. As a native-binary reverser, you will inevitably encounter .NET assemblies: either as direct targets or as components of a mixed architecture where C# calls native code via P/Invoke. And with the arrival of NativeAOT and ReadyToRun, the line between managed bytecode and native code is blurring — a single binary can contain both. This part gives you the keys to approach .NET RE with confidence, capitalizing on everything you already know about native RE.

---

## 🎯 Objectives of this part

By the end of these three chapters, you will be able to:

1. **Understand the structure of a .NET assembly**: metadata, PE headers, CIL sections, and what distinguishes it from a classic native ELF or PE binary.  
2. **Decompile a C# assembly with ILSpy, dnSpy, and dotPeek**, obtain source code nearly identical to the original, and choose the right tool depending on the context (decompilation only, integrated debugging, code navigation).  
3. **Bypass common .NET obfuscators** (ConfuserEx, Dotfuscator, SmartAssembly) with de4dot and manual techniques, to recover readable code.  
4. **Debug and instrument a .NET assembly on the fly**: set breakpoints on decompiled C# in dnSpy, hook .NET methods with `frida-clr`, intercept P/Invoke calls to native libraries, and patch IL directly.  
5. **Identify when a .NET binary becomes native code** (NativeAOT, ReadyToRun) and adapt your approach — know when to switch to the native RE tools seen in Parts II-IV.

---

## 📋 Chapters

| # | Title | Description | Link |  
|----|-------|-------------|------|  
| 30 | Introduction to .NET RE | CIL bytecode vs native x86-64 code, structure of a .NET assembly (metadata, PE headers, CIL sections), common obfuscators (ConfuserEx, Dotfuscator, SmartAssembly), NativeAOT and ReadyToRun. | [Chapter 30](/30-introduction-re-dotnet/README.md) |  
| 31 | Decompiling .NET assemblies | ILSpy (open source), dnSpy/dnSpyEx (decompilation + debugging), dotPeek (JetBrains), comparison of the three tools, de4dot and obfuscation bypass techniques. | [Chapter 31](/31-decompilation-dotnet/README.md) |  
| 32 | Dynamic analysis and .NET hooking | Debugging in dnSpy without sources, hooking .NET methods with Frida (`frida-clr`), intercepting P/Invoke calls (.NET → native bridge), patching IL with dnSpy, practical case of bypassing a C# license check. | [Chapter 32](/32-dynamic-analysis-dotnet/README.md) |

---

## 🔄 Bridge with native RE

If you followed Parts I through IV, you already have the fundamental reflexes — .NET RE transposes them into a more comfortable world. CIL bytecode is a high-level assembly language: where x86-64 gives you `mov` and `lea`, CIL directly manipulates objects, typed method calls, and an explicit evaluation stack. Direct consequence: .NET decompilation produces source code nearly identical to the original, where Ghidra gives you an approximate pseudo-C. The real junction point between the two worlds is P/Invoke: when a C# program calls a native DLL compiled with GCC, you find exactly the native RE techniques of Parts II-IV to analyze that DLL, and the .NET techniques of this part to understand how it is called.

---

## 🛠️ Tools covered

- **ILSpy** — open source C# decompiler, the reference for .NET assembly decompilation.  
- **dnSpy / dnSpyEx** — decompiler with integrated debugger: breakpoints, variable inspection, and IL patching directly on the decompiled C#.  
- **dotPeek** (JetBrains) — decompiler with advanced navigation and source export, integrated with the JetBrains ecosystem.  
- **de4dot** — automatic .NET deobfuscator, supports ConfuserEx, Dotfuscator, SmartAssembly, and others.  
- **Frida (`frida-clr`)** — dynamic instrumentation of the .NET runtime (CLR), C# method hooking on the fly.  
- **ImHex** — inspection of PE/.NET headers and CIL sections at the hex level.  
- **`file` / `strings`** — first triage reflexes, also applicable to .NET assemblies.

---

## ⏱️ Estimated duration

**~10-14 hours** for a native RE practitioner with C# basics.

Chapter 30 (introduction, ~2-3h) sets the conceptual framework and the differences with native. Chapter 31 (decompilation, ~3-4h) is the most tooling-heavy: you will get to grips with three decompilers and learn to bypass obfuscation. Chapter 32 (dynamic analysis, ~4-5h) culminates with a full license-bypass practical case — the .NET counterpart of the keygenme from Chapter 21.

If you do not have a C# background, add ~3-4h to familiarize yourself with the syntax and basic concepts of the language (classes, properties, delegates, LINQ). The C++ knowledge gained in the previous parts considerably speeds up this learning.

---

## 📌 Prerequisites

**Mandatory:**

- Having completed at minimum chapters 1 and 2 of **[Part I](/part-1-fundamentals.md)** (RE concepts, compilation chain, binary formats) — you must understand what a binary is and how it is produced.  
- Having **C# basics**: syntax, classes, inheritance, interfaces, properties. No need to be an expert — you will read decompiled code, not write thousands of lines of it.

**Recommended:**

- Having completed **[Part II](/part-2-static-analysis.md)** and **[Part III](/part-3-dynamic-analysis.md)** — the concepts of disassembly, decompilation, and hooking are the same, only the tools change.  
- Having completed Chapter 13 (Frida) — `frida-clr` uses the same API and the same principles as native hooking.

---

## ⬅️ Previous part

← [**Part VI — Malicious Code Analysis (Controlled Environment)**](/part-6-malware.md)

## ➡️ Next part

Final bonus module: the Reverse Engineering of Rust and Go binaries — two languages that produce native ELFs via the GNU toolchain but whose conventions, name mangling, and internal structures pose specific challenges.

→ [**Part VIII — Bonus: RE of Rust and Go Binaries**](/part-8-rust-go.md)

⏭️ [Chapter 30 — Introduction to .NET RE](/30-introduction-re-dotnet/README.md)
