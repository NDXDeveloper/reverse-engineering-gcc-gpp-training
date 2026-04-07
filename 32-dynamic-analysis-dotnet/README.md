🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 32 — Dynamic Analysis and .NET Hooking

> 🔗 *This chapter is part of [Part VII — Bonus: RE on .NET / C# Binaries](/part-7-dotnet.md).*  
> 📦 Prerequisites: having read Chapter 30 — Introduction to .NET RE and Chapter 31 — Decompiling .NET Assemblies.

---

## Why dynamic analysis on .NET?

Chapters 30 and 31 showed us that the .NET world offers a considerable advantage to the reverse engineer: thanks to the rich metadata embedded in assemblies, decompilation produces C# code often very close to the original. One might then wonder why bother with dynamic analysis.

The answer lies in several observations. First, obfuscation. Tools like ConfuserEx, Dotfuscator, or SmartAssembly don't just rename symbols: they encrypt strings at runtime, flatten control flow, inject anti-debugging code, and render the decompiled pseudo-code partially or totally unreadable. Facing a heavily obfuscated assembly, static reading alone quickly reaches its limits.

Next, a program's actual behavior can't always be read from its code. The concrete values of variables at a given moment, the exact order of method calls, the data received from the network or read from a configuration file — all of this only reveals itself at runtime. A decompiler shows you what the program *could* do; the debugger and instrumentation show you what it *does*.

Finally, patching. The .NET execution model relies on CIL (Common Intermediate Language) bytecode, which is interpreted then compiled on the fly by the JIT. This architecture offers an intervention surface that native x86-64 code doesn't have: you can modify IL instructions directly in the assembly, hook methods at the CLR runtime level, or inject C# code into a running process. These techniques are both more accessible and more powerful than their native equivalents.

## What you will learn

This chapter covers five complementary axes that form a complete dynamic analysis workflow on .NET:

**Debugging without sources with dnSpy.** dnSpy (and its maintained fork dnSpyEx) is much more than a decompiler: it's a complete debugging environment. You'll learn to set breakpoints directly on decompiled C# code, inspect local variables, the call stack, and objects in memory — all without having any source files. It's the .NET equivalent of GDB on a native binary, but with incomparably greater comfort.

**Hooking .NET methods with Frida.** Frida, which you already know from [Chapter 13](/13-frida/README.md) for native binary instrumentation, has a `frida-clr` module capable of interacting with the .NET runtime. You'll see how to intercept C# method calls, read and modify their arguments on the fly, and replace return values — without touching the binary on disk.

**Intercepting P/Invoke calls.** .NET applications don't live in an isolated world. The P/Invoke (Platform Invocation Services) mechanism allows C# code to call functions in native libraries — typically Windows DLLs or Linux `.so` files compiled with GCC. These calls constitute a bridge between the managed and native worlds, and often represent critical points of interest in RE: license checks delegated to a native library, cryptographic calls via OpenSSL, low-level system interactions. You'll learn to identify and intercept them.

**IL patching with dnSpy.** Where patching a native binary requires manipulating raw x86 opcodes and managing alignment constraints, IL patching is almost comfortable. dnSpy allows editing a method's CIL instructions, modifying a function's body, or even rewriting entire blocks in C# that the tool automatically recompiles to IL. You'll see how to surgically modify a .NET application's behavior.

**An integrated practical case.** To consolidate these techniques, you'll apply them on a .NET license verification application provided in the repository. The objective: understand the validation mechanism, bypass it through debugging, hooking, and patching, then write a keygen.

## Parallels with native dynamic analysis

If you've followed the previous parts of this training, you already have all the necessary reflexes. The table below maps native techniques to their .NET equivalents:

| Native technique (Parts II–V) | .NET equivalent (this chapter) |  
|---|---|  
| GDB / GEF on ELF binary | dnSpy debugger on .NET assembly |  
| Breakpoint on address (`break *0x401234`) | Breakpoint on decompiled C# method |  
| Frida hooking of C/C++ functions | Frida `frida-clr` hooking of .NET methods |  
| `LD_PRELOAD` to intercept calls | P/Invoke hooking to intercept native calls |  
| Patching x86 opcodes with ImHex | Editing IL instructions with dnSpy |  
| `strace` / `ltrace` to trace calls | dnSpy + Frida to trace .NET calls |

The philosophy remains identical: observe, understand, then intervene. Only the tools and the level of abstraction change.

## .NET runtime specifics to keep in mind

Before diving into practice, a few .NET runtime particularities deserve mention, as they directly influence our dynamic approach.

**JIT compilation.** CIL code is not executed directly: the CLR's JIT (Just-In-Time) compiler translates it to native code at runtime, method by method, on their first call. This means that when you set a breakpoint in dnSpy, it's actually placed on the native code generated by the JIT — but the tool presents you with the correspondence to the decompiled C#. This abstraction layer is transparent most of the time, but it can affect the execution order and observed optimizations.

**The Garbage Collector.** The .NET GC moves objects in memory. Unlike analyzing a C/C++ binary where a memory address stays stable as long as you don't explicitly free it, a .NET object can change addresses between two debugger pauses. Tools like dnSpy handle this transparently via runtime handles, but it's a point to know if you're doing low-level instrumentation.

**Application domains and assembly loading.** The CLR can load assemblies dynamically at runtime (`Assembly.Load`, `Assembly.LoadFrom`). Some obfuscators exploit this mechanism to decrypt and load code in memory without ever writing it to disk. Dynamic analysis is then the only way to access the actual code.

**NativeAOT and ReadyToRun.** As seen in Chapter 30, applications compiled with NativeAOT no longer go through the CLR and JIT: they produce a standard native binary. In this case, the techniques in this chapter don't apply, and you must return to the methods from Parts II through V. ReadyToRun assemblies contain both precompiled code and CIL, making them analyzable by both approaches.

## Tools used in this chapter

| Tool | Role | Installation |  
|---|---|---|  
| **dnSpy / dnSpyEx** | Decompilation + integrated debugging | [github.com/dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy) |  
| **Frida + frida-clr** | CLR dynamic instrumentation | `pip install frida-tools` |  
| **dotnet CLI** | Compilation and execution of samples | [dot.net](https://dot.net) |  
| **ILSpy** | Reference decompilation (comparison) | [github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) |

> 💡 **Note:** The original dnSpy is no longer maintained. The fork **dnSpyEx** is the version to use. Throughout this chapter, the term "dnSpy" refers to dnSpyEx unless otherwise noted.

## Chapter outline

- 32.1 [Debugging an assembly with dnSpy without sources](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md)  
- 32.2 [Hooking .NET methods with Frida (`frida-clr`)](/32-dynamic-analysis-dotnet/02-hooking-frida-clr.md)  
- 32.3 [Intercepting P/Invoke calls (bridge .NET → GCC native libraries)](/32-dynamic-analysis-dotnet/03-pinvoke-interception.md)  
- 32.4 [Patching a .NET assembly on the fly (modifying IL with dnSpy)](/32-dynamic-analysis-dotnet/04-patching-il-dnspy.md)  
- 32.5 [Practical case: bypassing a C# license check](/32-dynamic-analysis-dotnet/05-practical-license-csharp.md)  
- [**🎯 Checkpoint**: patch and keygen the provided .NET application](/32-dynamic-analysis-dotnet/checkpoint.md)

---


⏭️ [Debugging an assembly with dnSpy without sources](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md)
