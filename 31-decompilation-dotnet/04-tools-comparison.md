🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 31.4 — Comparison: ILSpy vs dnSpy vs dotPeek

> 📦 **Chapter 31 — Decompiling .NET Assemblies**  
> 


---

## Why compare?

Sections 31.1 through 31.3 presented each tool individually, with its own workflow. This section puts them face to face on concrete criteria so you can choose the right tool for each situation — and most importantly understand how they complement each other. The logic is the same as the Ghidra vs IDA vs Radare2 vs Binary Ninja comparison in section 9.6, transposed to the .NET ecosystem.

An essential point before we begin: **these three tools are not in head-to-head competition**. Each occupies a distinct niche. The goal of this comparison is not to designate a "best tool" but to build a decision grid that lets you know which one to launch based on what you're doing.

---

## Summary comparison table

| Criterion | ILSpy | dnSpy (dnSpyEx) | dotPeek |  
|---|---|---|---|  
| **License** | MIT (open source) | GPL v3 (open source) | Free (proprietary) |  
| **Platforms** | Windows, Linux, macOS | Windows only | Windows only |  
| **C# decompilation** | Excellent | Very good | Very good |  
| **Recent C# support** | C# 12+ | C# 11 (catching up) | C# 12+ |  
| **IL view** | Yes | Yes | Yes (synchronized C#↔IL) |  
| **Integrated debugger** | No | Yes (.NET Fw, .NET 6+, Unity) | No (Symbol Server → VS) |  
| **C# / IL editing** | No (read-only) | Yes (C# via Roslyn + direct IL) | No (read-only) |  
| **Breakpoints on decompiled** | No | Yes | Indirect (via Symbol Server) |  
| **Project export .csproj** | Yes (complete) | No | Yes |  
| **CLI tool** | `ilspycmd` | No | No |  
| **Navigation / search** | Good | Good | Excellent (ReSharper heritage) |  
| **Type Hierarchy** | Basic | Basic | Advanced (full tree) |  
| **Structured Find Usages** | Analyze (categories) | Analyze (categories) | Find Usages (categories + context) |  
| **Semantic coloring** | Syntactic | Syntactic | Semantic (fields, params, locals...) |  
| **Built-in hex editor** | No | Yes | No |  
| **Plugins / extensibility** | Yes (plugin architecture) | Limited | No |  
| **Active development** | Very active (ICSharpCode) | Community (irregular) | Active (JetBrains) |  
| **Weight / portability** | Light, portable (ZIP) | Light, portable (ZIP) | Installer, not portable |

---

## Analysis by criterion

### Decompilation quality

All three tools produce high-quality C# on non-obfuscated assemblies compiled in Release. Differences appear on edge cases:

**Modern C# constructs.** ILSpy leads the race thanks to its very active development. Patterns introduced by the latest language versions — primary constructors (C# 12), collection expressions, `required` members — are recognized and faithfully restored. dotPeek follows closely, carried by JetBrains' resources. dnSpyEx has a slight lag on the most recent constructs, the community fork having less bandwidth to follow every Roslyn evolution.

**`async/await`.** All three tools correctly reconstruct asynchronous methods from the compiler-generated state machines. ILSpy and dotPeek tend to produce slightly cleaner code (fewer residual temporary variables) on complex cases involving multiple `await`s nested in loops and `try/catch` blocks.

**Optimized code.** When the assembly has been compiled in Release mode with optimizations enabled, the Roslyn compiler performs transformations (small method inlining, dead code elimination, branch simplification) that complicate decompilation. Results diverge marginally between tools: a variable may be named differently, an `if/else` may be restructured as a ternary operator or vice versa. These differences are cosmetic — the semantics are correct in all three cases.

**Obfuscated assemblies.** Facing an assembly protected by an obfuscator (ConfuserEx, Dotfuscator, SmartAssembly...), all three tools behave similarly: they decompile without errors, but the result is unreadable because symbol names have been replaced by random identifiers or non-printable characters. None of the three includes a deobfuscator — that's de4dot's role, covered in section 31.5. The only notable difference is that dnSpy's debugger remains functional on obfuscated code, allowing you to trace execution even when names are incomprehensible.

### Debugging

This is the criterion that most clearly separates the three tools.

**dnSpy** is the only one offering a complete integrated debugger: breakpoints (simple and conditional), stepping, variable inspection, arbitrary expression evaluation, live value modification, Set Next Statement. All directly on decompiled C# code, without PDB, without source code. For dynamic analysis of .NET assemblies, it's the reference tool.

**dotPeek** offers an indirect alternative via its Symbol Server. By generating synthetic PDBs consumed by Visual Studio, it allows setting breakpoints in Visual Studio on decompiled code. This approach works but adds friction: you must configure Visual Studio to use dotPeek's symbol server, and both tools must run simultaneously. The advantage is access to Visual Studio's full ecosystem (diagnostics, profiling, IntelliTrace); the disadvantage is the setup overhead.

**ILSpy** offers no debugging functionality. It's a purely static analysis tool. For debugging, you must switch to dnSpy or the dotPeek + Visual Studio combination.

### Editing and patching

**dnSpy** is the only one of the three that allows modifying an assembly. C# editing (recompilation via Roslyn) and direct IL editing (opcode-by-opcode modification) cover all patching scenarios, from the simplest (making a validation method return `true`) to the most surgical (inverting a conditional branch in IL). The saved module is a valid .NET assembly, immediately executable.

**ILSpy** and **dotPeek** are strictly read-only. To patch an assembly analyzed in either tool, you must either switch to dnSpy or use an external tool like `Mono.Cecil` (programmatic .NET assembly manipulation library) or `ildasm`/`ilasm` (disassembly to IL text, modification, reassembly).

### Navigation and search

**dotPeek** dominates this criterion. Its navigation system inherited from ReSharper offers fluidity and depth that the other two don't match. Fuzzy CamelCase matching in `Go to Everything`, structured `Find Usages` with contextual code excerpts, complete `Type Hierarchy` with derived classes and interface implementations — these features make dotPeek the most productive tool for exploring a large .NET codebase.

**ILSpy** and **dnSpy** offer functionally sufficient navigation — text search, Analyze/XREF, Go to Definition — but without dotPeek's finesse. The difference is barely perceptible on an assembly with a dozen types, but becomes significant on an application with hundreds of classes spread across dozens of namespaces.

### Cross-platform and integration

**ILSpy** is the only tool natively usable on **Linux and macOS** thanks to its Avalonia version. This is a decisive advantage for analysts working in a Linux VM (the recommended configuration in Chapter 4). Additionally, `ilspycmd` enables integration into scripts and automation pipelines (Chapter 35).

**dnSpy** and **dotPeek** are locked to Windows. If your RE environment is a Linux VM, these tools require an additional Windows VM or dual-boot.

### Longevity and maintenance

The longevity question is relevant when choosing a tool you'll integrate into your daily workflow.

**ILSpy** benefits from the healthiest open source model of the three. The project has been maintained by ICSharpCode for over thirteen years, with regular releases and an active contributor community. The MIT license guarantees the code will remain available even if the core team stops maintaining it.

**dotPeek** is backed by JetBrains, an established and profitable company. The risk of sudden abandonment is low, but the proprietary model means you depend entirely on JetBrains' decisions. The tool could become paid, be integrated exclusively into Rider, or be discontinued in favor of another product — you would have no recourse.

**dnSpyEx** is in the most fragile position. The original project was abandoned by its author, and the community fork depends on the volunteerism of a few contributors. The release pace is irregular. The code is under GPL v3, guaranteeing source availability, but without an active maintainer the tool risks gradually falling behind the .NET runtime. This is an additional argument for not depending on a single tool.

---

## Decision matrix by scenario

Rather than an abstract ranking, here's which tool to choose based on what you're concretely doing.

### "I want to quickly understand what an unknown assembly does"

**First choice: ILSpy.** Instant opening, clear navigation, string search. The triage workflow is the most fluid. If you're working on Linux, it's your only native GUI option. On Windows, all three tools work for this task, but ILSpy remains the lightest and fastest to launch.

### "I want to trace a method's execution and observe values at runtime"

**First choice: dnSpy.** The integrated debugger is without equivalent. Breakpoints on decompiled code, variable inspection, expression evaluation — no other tool offers this combination as directly.

**Alternative: dotPeek + Visual Studio.** Heavier to configure but functional, with the advantage of accessing Visual Studio's diagnostic tools.

### "I want to patch an assembly (modify a check, bypass a protection)"

**First choice: dnSpy.** Integrated C# and IL editing allows modifying, recompiling, and saving without leaving the tool. It's the most direct patching workflow. This capability is explored further in Chapter 32, section 32.4.

**Alternative: Programmatic modification** with `Mono.Cecil` if you need to automate patching or apply it to multiple assemblies.

### "I want to map the architecture of a complex .NET application"

**First choice: dotPeek.** ReSharper navigation, Type Hierarchy, and structured Find Usages are tailored for this scenario. The gap with ILSpy and dnSpy is particularly marked on large applications.

**Second choice: ILSpy** with project export, then opened in Rider or Visual Studio to benefit from IDE navigation.

### "I want to export decompiled code to read in an IDE"

**First choice: ILSpy.** The `.csproj` project export is the most mature and best-integrated feature. `ilspycmd -p` enables automating the operation from the command line.

**Second choice: dotPeek** via `Export to Project`, with folder structuring sometimes more faithful to the original architecture.

### "I'm working on Linux and don't have a Windows VM"

**Only choice: ILSpy** (Avalonia version or `ilspycmd`). For dynamic analysis, you'll need to use the Frida-CLR techniques from Chapter 32, section 32.2, or set up a Windows VM for dnSpy sessions.

### "I'm analyzing an obfuscated assembly"

**Phase 1: de4dot** (section 31.5) to deobfuscate the assembly.

**Phase 2: ILSpy or dotPeek** for static analysis of the cleaned assembly.

**Phase 3: dnSpy** if dynamic debugging is needed to understand parts that de4dot couldn't clarify. dnSpy's debugger works even on obfuscated code — names are unreadable but runtime values remain observable.

### "I want to integrate decompilation into a script or CI pipeline"

**Only choice: ILSpy** via `ilspycmd`. Neither dnSpy nor dotPeek offer a command-line interface. For programmatic assembly manipulation (parsing, modification, automated analysis), the `Mono.Cecil` and `System.Reflection.Metadata` libraries are the natural complements.

---

## Recommended strategy: all three together

In practice, an effective .NET reverse engineer doesn't choose a single tool — they use all three depending on context, exactly as a native binary analyst alternates between Ghidra (deep static analysis), GDB (dynamic debugging), and CLI tools (quick triage).

The recommended combination for this tutorial is:

**ILSpy** is your primary and permanent tool. It's the one you launch first on any unknown assembly. It covers triage, static decompilation, export, and automation. It works on all platforms. It's open source and sustainable.

**dnSpy** is your dynamic analysis tool. You launch it when ILSpy has identified a point of interest that you need to observe at runtime — a validation routine, a decryption flow, a network exchange. You also return to it for quick assembly patching.

**dotPeek** is your architectural exploration tool. You launch it when the assembly is large and ILSpy's or dnSpy's navigation isn't enough — when you need to map complex inheritance hierarchies, trace dependency injection chains, or simply read decompiled code with the comfort of a JetBrains IDE.

This distribution isn't rigid. On a small assembly, ILSpy alone may suffice. On a CTF where the goal is to bypass a check as fast as possible, dnSpy alone does the job. What matters is knowing each tool's strengths so you don't waste time using the wrong one in the wrong situation.

---

## Parallel with native tooling

For readers coming from Parts II–IV, here is a correspondence table that helps transpose reflexes acquired on native binaries.

| Need | Native tooling (ELF/x86-64) | .NET tooling |  
|---|---|---|  
| Static decompilation | Ghidra, RetDec | ILSpy, dotPeek |  
| Debugging on decompiled code | GDB + GEF/pwndbg (asm) | dnSpy (decompiled C#) |  
| Binary editing/patching | ImHex, `objcopy`, hex editor | dnSpy (C#/IL editing) |  
| Quick CLI triage | `file`, `strings`, `readelf` | `ilspycmd`, `file`, `strings` |  
| Code navigation | Ghidra CodeBrowser | dotPeek, ILSpy |  
| Cross-references | Ghidra XREF | Analyze (ILSpy/dnSpy), Find Usages (dotPeek) |  
| Pseudo-code export | Ghidra Export C | ILSpy `Save Code`, dotPeek `Export to Project` |  
| Scripting / automation | Ghidra headless, r2pipe | `ilspycmd`, `Mono.Cecil` |

The fundamental difference remains result quality: where the native decompiler produces approximate pseudo-code you spend hours annotating, the .NET decompiler produces C# virtually identical to the source. It's this asymmetry that makes .NET RE both more accessible and — when obfuscation enters the picture — dependent on a prior deobfuscation step. That's the subject of the next section.

---


⏭️ [Decompiling despite obfuscation: de4dot and bypass techniques](/31-decompilation-dotnet/05-de4dot-bypassing.md)
