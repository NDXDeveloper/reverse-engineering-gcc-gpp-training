🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 31.3 — dotPeek (JetBrains) — Navigation and Source Export

> 📦 **Chapter 31 — Decompiling .NET Assemblies**  
> 

---

## Introduction

dotPeek is the free .NET decompiler from **JetBrains**, the maker of Rider, ReSharper, and IntelliJ IDEA. First published in 2011, it was designed from the start to offer a navigation experience in decompiled code identical to that of a JetBrains IDE — and that's precisely where its strength lies.

dotPeek is neither open source like ILSpy, nor debugging-oriented like dnSpy. Its positioning is that of a **surgically precise code explorer**: instant navigation, multi-criteria search, type relationship display, and above all integration with the JetBrains ecosystem. If you already work with Rider or ReSharper, dotPeek integrates naturally into your workflow.

For the reverse engineer, dotPeek occupies a specific niche. It excels when the goal is to **understand the architecture of a large .NET application** — mapping dependencies, tracing inheritance hierarchies, navigating through strongly typed code with dozens of namespaces. Where ILSpy is a Swiss army knife and dnSpy a complete workshop, dotPeek is a high-precision magnifying glass.

---

## Installation

dotPeek is available for free on the JetBrains website. Download the Windows installer from the product page and follow the wizard. Unlike ILSpy and dnSpy which are portable (simple ZIP archives), dotPeek uses a standard installer that registers in the Start menu and file system.

### Platform constraints

dotPeek is a **Windows-only** application, like dnSpy. It relies on WPF technologies and the .NET Framework (not .NET 6+). No Linux or macOS version is available, and no port is planned — JetBrains directs cross-platform users toward the decompiler integrated into Rider.

### License

dotPeek is free for all use, including commercial. It is not open source: the code is not available, and the license is proprietary (JetBrains). In practice, this distinction doesn't affect RE usage — the tool is fully functional without purchase or subscription.

> 💡 If you already use **Rider** (JetBrains' cross-platform C# IDE), know that it natively integrates dotPeek's decompilation engine. You can navigate decompiled code of an assembly directly in Rider via `Navigate > Go to Declaration` on an external type. In this case, installing standalone dotPeek is only necessary if you want to work outside of Rider.

---

## Interface tour

dotPeek's interface is modeled after JetBrains IDEs. Users of Rider, IntelliJ, or WebStorm will immediately find their bearings: navigation bar at the top, project tree on the left, code editor in the center, dockable tool panels on the sides and bottom.

### Assembly Explorer

The left panel displays loaded assemblies in a hierarchical tree similar to those of ILSpy and dnSpy. The structure is the same — namespaces, types, members — but with JetBrains' characteristic icons and visual presentation. Each node explicitly displays the access modifier and member type.

A dotPeek peculiarity: the explorer visually distinguishes **your analysis assemblies** (which you explicitly opened) from **framework assemblies** (BCL, runtime) automatically resolved via references. This distinction reduces visual noise when working on an application that depends on dozens of system assemblies.

### The code panel

Decompiled C# code is displayed in the central editor with syntax highlighting, block folding, and line numbering. dotPeek supports the same viewing modes as ILSpy — C# and IL — but its C# mode benefits from JetBrains' code rendering technology, which offers a few additional visual refinements:

- **Semantic coloring**: local variables, parameters, instance fields, static fields, and properties are colored differently, even without a PDB. This visual distinction is a notable gain when reading long and complex methods.  
- **Inlays and hints**: contextual annotations displayed in light gray directly in the code — parameter names at call sites, inferred types for `var` variables, constant values. These hints are configurable and can be disabled.  
- **Usage highlighting**: clicking on a symbol automatically highlights all its occurrences in the current file, allowing you to visually trace a variable's flow through a method.

### Tool panels

dotPeek offers several dockable panels accessible via the `View > Tool Windows` menu:

- **Find Results**: results from the last search, with navigation by double-click.  
- **Type Hierarchy**: complete inheritance tree of a selected type (base classes, implemented interfaces, derived classes). This panel is a major asset for RE of complex object-oriented applications — it instantly answers the question "which classes implement this interface?" or "who inherits from this abstract class?".  
- **IL Viewer**: CIL bytecode display of the selected method, synchronized with the C# code. Clicking on a C# line positions the IL view on the corresponding CIL instructions, and vice versa. This bidirectional synchronization is smoother than ILSpy's "IL with C# comments" hybrid mode.  
- **Assembly Explorer**: the tree panel described above.

---

## Navigation: dotPeek's main strength

dotPeek inherits the navigation system from ReSharper/Rider, which is the product of over twenty years of development on .NET code analysis. It's in this area that the tool outpaces its competitors.

### Go to Everything (`Ctrl+N`)

dotPeek's universal navigation command. Type any name fragment and dotPeek searches across all loaded assemblies — types, methods, properties, fields, strings — with an intelligent fuzzy matching algorithm. Matching works on CamelCase initials: typing `VLK` finds `ValidateLicenseKey`, typing `CrHlp` finds `CryptoHelper`.

This navigation is qualitatively different from ILSpy's or dnSpy's text search. It doesn't search for substrings in names: it understands the structure of .NET identifiers and proposes relevance-weighted results. On a large application with thousands of types, this difference is tangible.

### Go to Type (`Ctrl+T`) and Go to Member (`Alt+\`)

Targeted versions of universal navigation: `Go to Type` filters exclusively for classes, structs, interfaces, enums, and delegates; `Go to Member` filters for methods, properties, fields, and events. These shortcuts eliminate noise when you know what kind of entity you're looking for.

### Find Usages (`Alt+F7`)

The equivalent of ILSpy's and dnSpy's *Analyze* command, but with more structured presentation. Results are grouped by usage category:

- **Invocations**: method call sites.  
- **Read / write access**: for fields and properties.  
- **Inheritances and implementations**: for types and interfaces.  
- **Instantiations**: for constructors.  
- **Attributes**: usages as an attribute on a type or member.

Each result displays a contextual code excerpt, not just the calling method name. This additional context often allows understanding a call's role without even navigating to the full code.

### Navigate To (context menu)

Right-clicking on a symbol in decompiled code opens a **Navigate To** submenu grouping all possible destinations:

- **Declaration**: the symbol's definition.  
- **Base Symbols**: the overridden base method or the interface this method implements.  
- **Derived Symbols**: all overrides in derived classes.  
- **Containing Type**: the class or struct containing this member.  
- **Related Files**: other types defined in the same module.

For RE of an application making heavy use of polymorphism, the Strategy pattern, or dependency injection, these navigation commands are indispensable. When you see a call to `IValidator.Validate(input)` and want to know *which concrete implementation* will execute, `Navigate To > Derived Symbols` immediately gives you the list of all classes implementing `IValidator`.

---

## Symbol Server feature

dotPeek has a unique feature that neither ILSpy nor dnSpy offer: it can function as a **local symbol server**. Activated via `Tools > Symbol Server`, this feature transforms dotPeek into a PDB server that Visual Studio or Rider can consume.

### How it works

When dotPeek generates decompiled code for an assembly, it can simultaneously produce a **synthetic PDB file** — a debug symbol file that maps IL offsets to lines of decompiled C# code. By configuring Visual Studio to query dotPeek's symbol server (a local URL like `http://localhost:33417/`), you gain the ability to:

- **Navigate decompiled code** directly from Visual Studio during a standard debugging session.  
- **Set breakpoints** in decompiled code from Visual Studio (similar to dnSpy, but via Visual Studio's standard mechanism).  
- **See the call stack** with method names and line numbers corresponding to decompiled code.

### Interest for RE

The Symbol Server is particularly useful in two scenarios:

**Scenario 1 — Debugging an application where you have the project, but not the sources of a dependency.** You're debugging your own code in Visual Studio, and when execution enters a third-party library you only have as a `.dll`, Visual Studio uses the PDBs generated by dotPeek to show you decompiled code instead of a "Source Not Found" screen.

**Scenario 2 — Alternative to dnSpy.** If you can't (or don't want to) use dnSpy, the dotPeek + Visual Studio combination offers a comparable debugging-on-decompiled-code experience, going through Visual Studio's standard mechanisms. The advantage is that you benefit from all of Visual Studio's power (diagnostics, profiling, IntelliTrace); the disadvantage is that the setup is heavier and the integration isn't as seamless as in dnSpy.

---

## Source export

dotPeek allows exporting decompiled code, but with different options from ILSpy's.

### Code copying

The simplest method: select code in the central panel and copy it (`Ctrl+C`). The code is copied with syntax highlighting if you paste into an editor that supports it. For an entire method or type, right-click on the node in the tree and choose `Copy` — the complete decompiled code is copied to the clipboard.

### Project export

`File > Export to Project` generates a file tree of `.cs` files with a `.sln` solution file. This feature is comparable to ILSpy's `Save Code`, but dotPeek's export tends to produce a better-structured project in terms of namespaces and folders, reflecting the finer understanding dotPeek has of the assembly's architecture thanks to its JetBrains analysis engine.

As with ILSpy, the exported project isn't guaranteed to be immediately recompilable — missing dependencies, circular references, and decompilation artifacts may require manual fixes. But the base is solid for reading in a full IDE.

---

## Typical RE workflow with dotPeek

dotPeek shines in a specific scenario: **you're facing a large, well-architected .NET application** (dozens of namespaces, hundreds of types, intensive use of interfaces and dependency injection), and your goal is to understand its structure before diving into implementation details.

### Phase 1 — Architectural overview

Load the main assembly and its dependencies. Use `Go to Everything` to explore top-level namespaces. Open the **Type Hierarchy** panel on key interfaces (`ILicenseService`, `IAuthProvider`, `IDataRepository`...) to map concrete implementations.

### Phase 2 — Dependency mapping

Note the referenced assemblies in the explorer. For each third-party dependency, identify its role: web framework, ORM, crypto library, logging system, dependency injection framework. This mapping tells you *how* the application is built, which guides your analysis strategy.

### Phase 3 — Targeted analysis

Once the architecture is understood, use `Find Usages` to trace critical data flows. Start from a known entry point (a controller method, an event handler, an API endpoint) and follow calls in depth. dotPeek's semantic coloring and inlays make this reading particularly fluid.

### Phase 4 — Handoff to dnSpy

When you've identified the exact method you need to observe at runtime, switch to dnSpy for dynamic debugging. dotPeek helped you find the needle in the haystack — dnSpy lets you examine it from every angle.

---

## dotPeek strengths and limitations

### Strengths

- **World-class navigation**: the navigation system inherited from ReSharper/Rider is the most powerful of all .NET decompilers. Fuzzy CamelCase search, structured `Find Usages`, and `Type Hierarchy` are productivity tools without equivalent in ILSpy or dnSpy.  
- **Semantic coloring and inlays**: decompiled code readability is superior thanks to the visual distinction of symbol categories and contextual annotations.  
- **Symbol Server**: unique feature allowing debugging in Visual Studio with decompiled code via synthetic PDBs.  
- **Synchronized IL view**: the bidirectional C#↔IL synchronization is smoother than in competing tools.  
- **Free**: no cost, even for professional or commercial use.

### Limitations

- **Windows only**: same constraint as dnSpy. Linux/macOS users must fall back to ILSpy Avalonia or Rider.  
- **No integrated debugger**: like ILSpy, dotPeek is a static analysis tool. The Symbol Server offers a bridge to Visual Studio, but it's not as direct as dnSpy's integrated debugger.  
- **No assembly editing**: no ability to modify IL or C# code and save. dotPeek is strictly read-only.  
- **Proprietary and closed**: source code is not available. You cannot extend the tool via plugins (unlike ILSpy) or audit its behavior. If JetBrains decides to discontinue dotPeek or make it paid, you have no recourse.  
- **No CLI tool**: dotPeek doesn't offer an equivalent to `ilspycmd`. Integration into automation pipelines (Chapter 35) isn't directly possible.  
- **Obfuscated assemblies**: same limitations as ILSpy and dnSpy when facing obfuscation — quality navigation doesn't compensate for unreadable symbol names.

---

## Summary

dotPeek is the tool of choice when the priority is **architectural understanding** of a complex .NET application. Its navigation inherited from ReSharper, semantic coloring, and Type Hierarchy make it an unrivaled decompiled code explorer. It doesn't replace ILSpy (export, cross-platform, CLI) or dnSpy (debugging, editing), but complements them on the specific terrain of large-scale code reading and exploration. The Symbol Server also constitutes a unique bridge to debugging in Visual Studio. The next section (31.4) formalizes the respective strengths of the three tools in a structured comparison.

---


⏭️ [Comparison: ILSpy vs dnSpy vs dotPeek](/31-decompilation-dotnet/04-tools-comparison.md)
