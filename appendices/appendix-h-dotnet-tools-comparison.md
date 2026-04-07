🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix H — .NET Tools Comparison (ILSpy / dnSpy / dotPeek / de4dot)

> 📎 **Reference Sheet** — This appendix compares reverse engineering tools dedicated to .NET assemblies (C#, F#, VB.NET). It covers decompilers, debuggers, deobfuscation tools, and complementary utilities. It is the counterpart to Appendix G for the .NET ecosystem, directly related to Parts VII (Chapters 30–32) of the course.

---

## Why Specific Tools for .NET?

Reverse engineering .NET binaries is fundamentally different from reverse engineering native x86-64 binaries. A .NET assembly does not contain machine code: it contains **CIL bytecode** (*Common Intermediate Language*), a high-level intermediate language compiled on the fly (JIT) by the .NET runtime at execution time. This bytecode retains a considerable amount of metadata: class names, methods, fields, parameter types, inheritance hierarchy, attributes, and often even local variable names.

This wealth of metadata means that .NET decompilation produces a result **much more faithful** to the original source code than native binary decompilation. A .NET decompiler can typically reconstruct C# code almost identical to the original, with correct class and method names, correct types, and an accurate control flow structure. This is a striking contrast with GCC binary decompilation, where Ghidra produces at best approximate C pseudo-code with invented variable names.

The trade-off is that developers who want to protect their .NET code use **obfuscators** that rename symbols, encrypt strings, flatten control flow, and add dead code. Deobfuscation tools (such as de4dot) attempt to undo these transformations before decompilation.

The tools presented here fall into three categories: decompilers (ILSpy, dnSpy/dnSpyEx, dotPeek), debuggers (dnSpy includes a built-in debugger), and deobfuscators (de4dot).

---

## 1 — Main Comparison Table

| Criterion | **ILSpy** | **dnSpy / dnSpyEx** | **dotPeek** | **de4dot** |  
|---------|-----------|---------------------|-------------|------------|  
| **Category** | Decompiler | Decompiler + debugger | Decompiler | Deobfuscator |  
| **License** | MIT (open source) | GPL (open source) | Free (proprietary) | GPL (open source) |  
| **Maintainer** | ICSharpCode community | dnSpyEx (actively maintained community fork) | JetBrains | Community (reduced maintenance) |  
| **OS** | Windows, Linux, macOS (via Avalonia) | Windows | Windows | Windows, Linux (Mono/.NET) |  
| **Interface** | GUI | GUI | GUI | CLI |  
| **C# Decompilation** | Excellent | Excellent | Excellent | No (preprocessing) |  
| **VB.NET Decompilation** | Yes | Yes | Yes | — |  
| **F# Decompilation** | Partial | Partial | No | — |  
| **IL Decompilation** | Yes | Yes | Yes | — |  
| **Built-in Debugging** | No | **Yes** (breakpoints on decompiled C#) | No | No |  
| **IL Editing / Patching** | No | **Yes** (direct modification of IL and metadata) | No | — |  
| **Symbol Search** | Yes | Yes | Yes (with JetBrains symbol server) | — |  
| **Source Code Export** | Yes (complete C# project) | Yes (individual files or project) | Yes (complete C# project) | — |  
| **Xref Navigation** | Yes (Analyze) | Yes | Yes (with ReSharper-like navigation) | — |  
| **NuGet / Package Support** | Yes | Yes | Yes (JetBrains integration) | — |  
| **Obfuscation Handling** | Limited (displays obfuscated code as-is) | Limited (same) | Limited | **Specialized** (bypasses numerous obfuscators) |  
| **.NET Framework Support** | Yes | Yes | Yes | Yes |  
| **.NET Core / .NET 5+ Support** | Yes | Yes | Yes | Partial |  
| **NativeAOT Support** | No (native code) | No | No | No |  
| **Installation Size** | ~30 MB | ~50 MB | ~200 MB | ~10 MB |  
| **Latest Activity** | Active (2024+) | Active (dnSpyEx, 2024+) | Active (JetBrains) | Low (last major release ~2020) |  
| **Chapters** | 31.1 | 31.2, 32.1, 32.4, 32.5 | 31.3 | 31.5 |

---

## 2 — ILSpy

### 2.1 — Overview

ILSpy is the reference open-source .NET decompiler, developed by the ICSharpCode team (the creators of SharpDevelop). It is a mature project, actively maintained and widely adopted by the community. Its decompilation engine (ICSharpCode.Decompiler) is also used as a library by other tools and in CI/CD pipelines.

### 2.2 — Strengths

**Decompilation Quality** — ILSpy's decompilation engine is considered one of the best available. It faithfully reconstructs modern C# constructs: async/await, LINQ, pattern matching, tuples, records, nullable types, string interpolation. It handles the different C# language versions well (from 1.0 to 12+) and adapts the output to the chosen version.

**Cross-Platform** — Since the Avalonia-based version, ILSpy runs natively on Linux and macOS in addition to Windows. It is the only .NET GUI decompiler that runs natively on all three platforms, making it particularly interesting for analysts working on Linux.

**Complete Export** — ILSpy can export an entire assembly as a C# project (`.csproj` + `.cs` files), attempting to produce recompilable code. The result often requires manual corrections, but it is an excellent starting point.

**Reusable Library** — The `ICSharpCode.Decompiler` engine is available as a NuGet package and can be integrated into your own automated analysis tools. This is a significant advantage for scripting and batch processing.

**Extensible** — ILSpy supports a plugin system. Community extensions add features such as vulnerability scanning, export to other formats, or additional views.

### 2.3 — Limitations

ILSpy offers neither debugging nor IL editing. It is a **read-only** tool: you can examine the decompiled code, navigate through types, search for references, but you cannot set breakpoints or modify the binary. For debugging, you will need to supplement with dnSpy or Visual Studio. For patching, you will need dnSpy, `ildasm`/`ilasm`, or Mono.Cecil.

Obfuscated code handling is minimal: ILSpy displays the code as-is, with renamed names and flattened control flow. It does not attempt to bypass obfuscation. You will need to run de4dot beforehand.

### 2.4 — Essential Commands and Shortcuts

| Action | Shortcut / Method |  
|--------|---------------------|  
| Open an assembly | `File → Open` or drag-and-drop |  
| Search for a type / method | `Ctrl+Shift+F` (Search) or `F3` |  
| Navigate to definition | `F12` or double-click |  
| Analyze references (xrefs) | Right-click → `Analyze` |  
| View a method's IL | Select the method → IL tab |  
| Export as C# project | Right-click on the assembly → `Save Code...` |  
| Change target C# version | `View → Options → Decompiler → C# version` |  
| Search in decompiled code | `Ctrl+F` in the code view |  
| Copy a method's code | Select → `Ctrl+C` |

---

## 3 — dnSpy / dnSpyEx

### 3.1 — Overview

dnSpy is the most complete tool in this ecosystem because it combines three functions in one: decompiler, debugger, and editor. The original project (by 0xd4d) was archived in 2020, but an actively maintained community fork, **dnSpyEx**, has taken over and continues development with support for recent .NET runtimes.

### 3.2 — Strengths

**Debugging on Decompiled Code** — The killer feature of dnSpy. You can set breakpoints directly on decompiled C# code, inspect local variables with their reconstructed names and types, browse the call stack, and step through — all **without having the original source code**. It is the .NET equivalent of GDB+Ghidra combined into a single tool. You can debug .NET Framework, .NET Core, and .NET 5+ assemblies.

**IL and Metadata Editing** — dnSpy allows you to directly modify a method's IL code, change constant values, rename types and members, modify attributes, and even add or remove methods. Modifications can be saved to a new assembly. It is the definitive .NET patching tool.

**C# Editing** — Beyond low-level IL editing, dnSpy allows you to edit a method directly in C#: you modify the decompiled C# code, and dnSpy recompiles it to IL and reinjects it into the assembly. This is a remarkable feature that makes .NET patching as simple as modifying source code.

**Decompilation Quality** — dnSpy's decompilation engine is based on ILSpy (ICSharpCode.Decompiler), so the quality is comparable. dnSpy adds display and navigation improvements specific to its interface.

**Unified Interface** — Everything is in the same window: type tree, decompiled code, IL view, debugger, editor, search. Navigation is smooth and the tool handles multiple assemblies simultaneously.

### 3.3 — Limitations

**Windows Only** — dnSpy and dnSpyEx only run on Windows. This is their main limitation for Linux analysts. If you work on Linux, ILSpy (Avalonia) is your alternative for decompilation, and you can use the .NET CLI debugger (`dotnet-dump`, `dotnet-trace`) for dynamic analysis.

**Fork Project** — The original project was abandoned. dnSpyEx is a community fork that maintains the project, but the dependency on volunteer contributors is a long-term risk. As of today, dnSpyEx is actively maintained and follows new .NET versions.

**No NativeAOT Support** — Like all .NET decompilers, dnSpy cannot decompile binaries compiled with NativeAOT (Ahead-Of-Time), which are native code without CIL bytecode. For these binaries, you must fall back to native tools (Ghidra, IDA).

### 3.4 — Essential Commands and Shortcuts

| Action | Shortcut / Method |  
|--------|---------------------|  
| Open an assembly | `File → Open` or drag-and-drop |  
| Search for a type / method / string | `Ctrl+Shift+K` |  
| Navigate to definition | `F12` or double-click |  
| Navigate back | `Ctrl+-` (navigation back) |  
| Analyze references | Right-click → `Analyze` |  
| View IL | Right-click → `Show IL Code` |  
| **Set a breakpoint** | `F9` (on a decompiled code line) |  
| **Start debugging** | `Debug → Start Debugging` (`F5`) |  
| **Step over** | `F10` |  
| **Step into** | `F11` |  
| **Inspect a variable** | Hover over the variable during debug, or `Locals` panel |  
| **Edit a method (C#)** | Right-click on the method → `Edit Method (C#)...` |  
| **Edit a method (IL)** | Right-click → `Edit IL Instructions...` |  
| **Modify a constant** | Right-click on the field → `Edit Field...` |  
| **Save modifications** | `File → Save Module...` |  
| Export as C# project | `File → Export to Project...` |

### 3.5 — Typical Workflow: Bypassing a License Check

This workflow illustrates the combined power of dnSpy for a common RE use case (covered in detail in Chapter 32.5):

1. Open the assembly in dnSpy  
2. Search for license-related strings (`Ctrl+Shift+K` → "license", "trial", "expired")  
3. Navigate to the code that uses these strings (double-click on the result)  
4. Identify the verification method (often a `bool CheckLicense()` or similar)  
5. Set a breakpoint (`F9`) and start debugging (`F5`) to observe the flow  
6. Once the logic is understood, edit the method (`Edit Method (C#)`) to return `true` directly  
7. Save the modified module (`File → Save Module...`)

---

## 4 — dotPeek

### 4.1 — Overview

dotPeek is the free .NET decompiler from JetBrains, the company behind ReSharper, Rider, and IntelliJ. It benefits from JetBrains' expertise in code analysis and offers a familiar navigation experience for users of their IDEs.

### 4.2 — Strengths

**Decompilation Quality** — dotPeek's decompilation engine is of very high quality, comparable to ILSpy and dnSpy. JetBrains invests in maintaining this engine because it also powers decompilation in Rider and ReSharper.

**IDE-like Navigation** — dotPeek offers a navigation experience inspired by ReSharper: contextual search, "Go to Declaration", "Find Usages", "Navigate To" with type filtering, dependency graph assembly. For a C# developer accustomed to Visual Studio + ReSharper, the learning curve is immediate.

**Symbol Server** — dotPeek can function as a **local symbol server**: it generates PDB files on the fly for decompiled assemblies, allowing Visual Studio to set breakpoints and step through decompiled code. This is an alternative to dnSpy's built-in debugging, although more complex to set up.

**NuGet Package Management** — dotPeek natively understands the NuGet format and can directly open `.nupkg` packages to inspect their contents.

**Project Export** — Like ILSpy, dotPeek can export an assembly as a complete C# project.

### 4.3 — Limitations

**Windows Only** — dotPeek only runs on Windows.

**Proprietary** — Although free, dotPeek is not open source. You cannot modify its behavior, integrate it into an automated pipeline, or access its decompilation engine programmatically (unlike ILSpy's engine available as a NuGet package).

**No Editing or Patching** — dotPeek is strictly read-only. No ability to modify the assembly, whether in IL or C#.

**Installation Size** — dotPeek installs via the JetBrains Toolbox or a dedicated installer, and weighs approximately 200 MB. This is significantly heavier than ILSpy or dnSpy.

**No F# Decompilation** — dotPeek does not support decompilation to F#. For F# assemblies, the code is decompiled to C# (which is often readable but loses F# idioms).

### 4.4 — Essential Commands and Shortcuts

| Action | Shortcut / Method |  
|--------|---------------------|  
| Open an assembly | `File → Open` or drag-and-drop |  
| Search everywhere | `Ctrl+T` (Go to Everything) |  
| Search for a type | `Ctrl+N` |  
| Navigate to definition | `F12` |  
| Find usages | `Shift+F12` (Find Usages) |  
| Navigate back | `Ctrl+-` |  
| View IL | `Windows → IL Viewer` |  
| Export as C# project | Right-click on the assembly → `Export to Project` |  
| Enable symbol server | `Tools → Symbol Server` |

---

## 5 — de4dot

### 5.1 — Overview

de4dot is a command-line .NET assembly deobfuscator and cleaner. It automatically detects the obfuscator used and applies reverse transformations: restoring type and method names, decrypting strings, simplifying control flow, removing dead code, and anti-decompilation protections. It is designed to be run **before** decompilation with ILSpy or dnSpy.

### 5.2 — Supported Obfuscators

de4dot recognizes and bypasses (with varying degrees of success) the following obfuscators:

| Obfuscator | de4dot Support Level | Market Presence |  
|-------------|--------------------------|------------------------|  
| **ConfuserEx** | Good (renaming, strings, flow) | Very widespread (open source, free) |  
| **Dotfuscator** | Good (renaming, strings) | Widespread (included with Visual Studio) |  
| **SmartAssembly** | Good (renaming, strings, compression) | Common (RedGate) |  
| **Babel.NET** | Partial | Less common |  
| **Crypto Obfuscator** | Partial | Common |  
| **Eazfuscator.NET** | Partial (strings, renaming) | Common |  
| **.NET Reactor** | Partial (renaming, strings; native packing requires other tools) | Very widespread |  
| **Agile.NET** (CliSecure) | Partial | Less common |  
| **MaxtoCode** | Partial | Chinese market |  
| **Goliath.NET** | Basic | Rare |  
| **Custom obfuscators** | Heuristic detection + generic cleaning | Variable |

The support level depends on the obfuscator version. Protections constantly evolve, and since de4dot is no longer actively developed for the latest versions of these tools, results may be partial on recent protections.

### 5.3 — Essential Commands

| Command | Description |  
|----------|-------------|  
| `de4dot assembly.exe` | Automatically detects the obfuscator and cleans the assembly. Produces `assembly-cleaned.exe` |  
| `de4dot assembly.dll -o output.dll` | Specifies the output file |  
| `de4dot assembly.exe -p cr` | Forces obfuscator type detection (`cr` = Crypto Obfuscator) |  
| `de4dot assembly.exe -p un` | "Unknown" mode: applies generic heuristics without assuming a specific obfuscator |  
| `de4dot assembly.exe --dont-rename` | Cleans without renaming symbols (useful if de4dot renames incorrectly) |  
| `de4dot assembly.exe --keep-types` | Preserves existing types during cleaning |  
| `de4dot *.dll` | Processes multiple assemblies at once (useful when an application is spread across multiple DLLs) |

### 5.4 — Workflow with de4dot

The standard workflow is to run de4dot first, then open the result in a decompiler:

1. `de4dot application.exe` → produces `application-cleaned.exe`  
2. Open `application-cleaned.exe` in ILSpy or dnSpy  
3. Check if names are restored and strings are decrypted  
4. If the result is insufficient, try with `-p un` (generic mode) or more aggressive options  
5. Complete manually in the decompiler if necessary

### 5.5 — Limitations

**Reduced Maintenance** — Active development of de4dot has slowed down. The last major versions date from around 2020. Recent or updated obfuscators may no longer be correctly detected. Community forks exist and attempt to maintain support.

**No Silver Bullet** — Certain advanced protections (IL code virtualization, native packing, native code integration via mixed assemblies) exceed de4dot's capabilities. For these cases, manual work combining dynamic analysis (dnSpy in debug mode) and specialized tools is necessary.

**Limited .NET Core / .NET 5+ Support** — de4dot was primarily developed for the .NET Framework. Support for .NET Core and .NET 5+ assemblies may be incomplete.

---

## 6 — Complementary Tools

Beyond the four main tools, several complementary tools are worth mentioning for a complete .NET toolkit.

### 6.1 — Microsoft Tools

| Tool | Usage | Free | Interface |  
|-------|-------|---------|-----------|  
| `ildasm` | Official Microsoft IL disassembler — produces textual IL code | Yes (.NET SDK) | GUI + CLI |  
| `ilasm` | IL assembler — recompiles textual IL code into an assembly | Yes (.NET SDK) | CLI |  
| `dotnet-dump` | Capture and analysis of .NET process memory dumps | Yes (.NET CLI) | CLI |  
| `dotnet-trace` | Execution trace capture (ETW events) | Yes (.NET CLI) | CLI |  
| `dotnet-counters` | Real-time monitoring of .NET performance counters | Yes (.NET CLI) | CLI |  
| `PEVerify` / `ILVerify` | Verifies IL code validity (useful after patching) | Yes (.NET SDK) | CLI |

The `ildasm`/`ilasm` pair constitutes the most basic IL patching pipeline: `ildasm` decompiles the assembly into IL text, you modify the text with an editor, then `ilasm` recompiles it. This is more tedious than direct editing in dnSpy, but it works on all platforms and does not depend on any third-party tool.

### 6.2 — Programmatic Manipulation Libraries

| Library | Usage | License |  
|--------------|-------|---------|  
| **Mono.Cecil** | Reading and modifying .NET assemblies in C# (the LIEF of the .NET world) | MIT |  
| **dnlib** | Reading and modifying .NET assemblies (used by dnSpy and de4dot) | MIT |  
| **ICSharpCode.Decompiler** | ILSpy's decompilation engine, usable as a NuGet library | MIT |  
| **System.Reflection.Metadata** | Official Microsoft API for reading .NET metadata (read-only) | MIT |

**Mono.Cecil** is the .NET equivalent of LIEF for native binaries: it allows you to read an assembly, inspect and modify its types, methods, IL instructions, attributes, then save the result. It is the tool of choice for programmatic patching of .NET assemblies in automation scripts.

**dnlib** is the library used internally by dnSpy and de4dot. It is more complete than Mono.Cecil for certain scenarios (obfuscated assemblies, malformed formats) because it has been hardened to handle "broken" assemblies that obfuscators intentionally produce.

### 6.3 — Frida for .NET (`frida-clr`)

Frida (covered in detail in Chapter 13 for native binaries) also supports the .NET runtime via the `frida-clr` bridge. It allows hooking .NET methods on the fly, modifying arguments and return values, and inspecting managed objects in memory. It is the .NET equivalent of native Frida hooking, covered in Chapter 32.2.

---

## 7 — Decision Matrix: Which Tool for Which Need?

| Need | Recommended Tool | Alternative |  
|--------|------------------|-------------|  
| Decompile a .NET assembly (read-only) | **ILSpy** | dotPeek |  
| Decompile on Linux or macOS | **ILSpy** (Avalonia) | CLI: `dotnet-ildasm` |  
| Debug an assembly without sources | **dnSpy/dnSpyEx** | dotPeek (symbol server) + Visual Studio |  
| Patch an assembly (modify behavior) | **dnSpy/dnSpyEx** (C# or IL editing) | `ildasm` → text editor → `ilasm` |  
| Programmatic patching (scripting) | **Mono.Cecil** or **dnlib** | — |  
| Deobfuscate an assembly (ConfuserEx, Dotfuscator, etc.) | **de4dot** then ILSpy/dnSpy | Manual deobfuscation in dnSpy |  
| Hook .NET methods live | **Frida** (`frida-clr`) | dnSpy (breakpoints + register modification) |  
| Intercept P/Invoke calls (.NET → native) | **Frida** | `strace` + `ltrace` |  
| Analyze a NativeAOT / ReadyToRun assembly | **Ghidra** or **IDA** (native tools) | — |  
| Export a complete assembly as C# project | **ILSpy** or **dotPeek** | dnSpy |  
| Automate decompilation (batch/CI) | **ICSharpCode.Decompiler** (NuGet) | `ilspycmd` (ILSpy CLI) |

---

## 8 — Decompilation Quality Comparison

The three decompilers (ILSpy, dnSpy, dotPeek) produce very similar results because they are all based on mature engines that manipulate the same CIL metadata. Differences appear mainly in edge cases.

### 8.1 — Non-Obfuscated Code

On standard non-obfuscated C# code, the three tools produce a nearly identical result that is very faithful to the original source code. Class names, methods, properties, and most local variable names are correctly restored. Modern language constructs (async/await, LINQ, pattern matching, etc.) are generally well reconstructed by all three.

Minor differences relate to formatting style (brace placement, spaces) and certain reconstruction choices: one may produce a `foreach` where another produces a `for` with an index, for example. These differences are cosmetic and do not affect understanding.

### 8.2 — Obfuscated Code

When facing obfuscated code, the three decompilers behave the same way: they display the code as-is, with names renamed to unreadable sequences (`\u0001`, `a`, `A`, etc.) and flattened control flow. None of the three attempts to actively deobfuscate — that is the role of de4dot as a preprocessing step.

The difference lies in robustness when dealing with intentionally malformed assemblies (invalid metadata, illegal IL instructions, recursive structures). dnSpy/dnlib is generally the most robust because its underlying library has been specifically hardened for these cases. ILSpy may sometimes fail to load an assembly that an obfuscator has intentionally "broken" to block decompilation.

### 8.3 — Optimized Code (Release)

Binaries compiled in Release mode with optimizations enabled produce slightly different IL than Debug mode: some local variables are eliminated, branches are simplified, and inlining may merge small methods. The three decompilers handle these optimizations well, but the decompiled code may be slightly less readable than the original source code (missing temporary variables, more compact expressions).

---

## 9 — NativeAOT and ReadyToRun: When .NET Becomes Native

Recent .NET compilation technologies deserve special mention because they fundamentally change the RE approach:

**ReadyToRun (R2R)** — The CIL code is pre-compiled to native code but **the CIL bytecode is preserved** in the assembly alongside the native code. .NET decompilers still work because they read the CIL, not the native code. The R2R native code is only used to speed up startup. In RE, you can ignore the R2R portion and work on the CIL normally.

**NativeAOT** — The assembly is compiled entirely to native code. **The CIL bytecode is removed**. The resulting binary is a native ELF or PE executable, with no dependency on the .NET runtime. .NET decompilers (ILSpy, dnSpy, dotPeek) cannot analyze it. You must use native RE tools: Ghidra, IDA, Radare2. The code retains certain recognizable characteristics (runtime data structures, GC, exception handling) but loses the rich metadata that made .NET decompilation so effective.

NativeAOT is still a minority in the .NET ecosystem, but its adoption is growing. If running `file` on a .NET assembly returns "ELF 64-bit executable" instead of "PE32 executable (console) Intel 80386 Mono/.Net assembly", you are probably dealing with NativeAOT and the Part VII tools do not apply — switch to the Part II tools.

---

## 10 — One-Page Summary Table

```
╔══════════════════════════════════════════════════════════════════╗
║              .NET RE TOOLS — CHEAT SHEET                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  DECOMPILERS                                                     ║
║  ┌──────────┬─────────────┬──────────────┬──────────────┐        ║
║  │          │   ILSpy     │ dnSpy(Ex)    │  dotPeek     │        ║
║  ├──────────┼─────────────┼──────────────┼──────────────┤        ║
║  │ Decomp.  │     ✓       │      ✓       │      ✓       │        ║
║  │ Debug    │     ✗       │      ✓       │   (via PDB)  │        ║
║  │ Patching │     ✗       │      ✓       │      ✗       │        ║
║  │ Linux    │     ✓       │      ✗       │      ✗       │        ║
║  │ OSS      │     ✓       │      ✓       │      ✗       │        ║
║  └──────────┴─────────────┴──────────────┴──────────────┘        ║
║                                                                  ║
║  RECOMMENDED PIPELINE                                            ║
║  1. de4dot assembly.exe        (if obfuscated)                   ║
║  2. dnSpy → open the result → debug + patch                      ║
║  3. ILSpy → export C# project if full code needed                ║
║                                                                  ║
║  PROGRAMMATIC LIBRARIES                                          ║
║  Mono.Cecil / dnlib    → read and modify assemblies              ║
║  ICSharpCode.Decompiler → decompile to C# from code              ║
║                                                                  ║
║  SPECIAL CASES                                                   ║
║  NativeAOT → no more CIL → use Ghidra/IDA (native tools)         ║
║  ReadyToRun → CIL still present → standard .NET tools            ║
║  P/Invoke → .NET→native bridge → Frida or strace on native side  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

---

> 📚 **Further Reading**:  
> - **Appendix G** — [Native Tools Comparison](/appendices/appendix-g-native-tools-comparison.md) — the same comparison for native ELF binaries.  
> - **Chapter 30** — [Introduction to .NET RE](/30-introduction-re-dotnet/README.md) — CIL vs native differences, structure of a .NET assembly.  
> - **Chapter 31** — [.NET Assembly Decompilation](/31-decompilation-dotnet/README.md) — educational coverage of ILSpy, dnSpy, and dotPeek.  
> - **Chapter 32** — [Dynamic Analysis and .NET Hooking](/32-dynamic-analysis-dotnet/README.md) — debugging with dnSpy, hooking with Frida, IL patching.  
> - **ILSpy** — [https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)  
> - **dnSpyEx** — [https://github.com/dnSpyEx/dnSpy](https://github.com/dnSpyEx/dnSpy)  
> - **dotPeek** — [https://www.jetbrains.com/decompiler/](https://www.jetbrains.com/decompiler/)  
> - **de4dot** — [https://github.com/de4dot/de4dot](https://github.com/de4dot/de4dot)  
> - **Mono.Cecil** — [https://github.com/jbevain/cecil](https://github.com/jbevain/cecil)

⏭️ [Recognizable GCC Patterns in Assembly (Compiler Idioms)](/appendices/appendix-i-gcc-patterns.md)
