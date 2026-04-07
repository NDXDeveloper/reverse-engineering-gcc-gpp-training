🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 31.1 — ILSpy — Open Source C# Decompilation

> 📦 **Chapter 31 — Decompiling .NET Assemblies**  
> 


---

## Introduction to ILSpy

ILSpy is the reference open source .NET decompiler. Developed and maintained by the **ICSharpCode** team (the same authors as SharpDevelop, one of the first free C# IDEs), it is published under the MIT license and has benefited from an active community since its creation in 2011. Its goal is simple: transform a compiled .NET assembly into readable, navigable, and exportable C# code.

In the .NET reverse engineering ecosystem, ILSpy holds a special place. Unlike dnSpy which focuses on integrated debugging, or dotPeek which leverages the JetBrains ecosystem, ILSpy concentrates on **decompilation quality** and **code fidelity**. It's the tool most analysts launch first to get a quick overview of an unknown assembly.

---

## Installation

### Windows (WPF version — recommended)

The historical and most complete version of ILSpy is the WPF application for Windows. You can obtain it in several ways:

- **GitHub Release**: download the ZIP archive from the `icsharpcode/ILSpy` repository on GitHub, in the *Releases* tab. Extract and launch `ILSpy.exe` — no installation required.  
- **Microsoft Store**: ILSpy is available for free on the Microsoft Store, which simplifies updates.  
- **Chocolatey**: `choco install ilspy`.  
- **winget**: `winget install icsharpcode.ILSpy`.

### Linux and macOS (Avalonia version)

Since version 8.0, ILSpy offers an interface based on **Avalonia UI**, the cross-platform .NET framework. This version runs natively on Linux and macOS without going through Wine or Mono:

```bash
# Via the .NET global tool (requires .NET SDK 8+)
dotnet tool install --global ilspycmd

# For the Avalonia GUI, download the build
# matching your OS from the GitHub releases
```

The Avalonia version is functionally close to the WPF version, but some advanced features (notably certain plugins) may not yet be ported. For daily RE use, it's perfectly sufficient.

> 💡 **If you're working in the Linux VM** configured in Chapter 4, the Avalonia version is the natural choice. If you have a dedicated Windows workstation for .NET RE, prefer the WPF version for the full feature set.

### VS Code extension

ILSpy is also available as a Visual Studio Code extension (`icsharpcode.ilspy-vscode`). It allows decompiling an assembly directly from the VS Code file explorer. This extension is handy for quick inspections, but it doesn't offer the navigation depth of the standalone application — consider it a complement, not a replacement.

---

## Interface tour

On launch, ILSpy presents an interface organized around three main areas.

### The assembly tree (left panel)

This is the entry point for any analysis. This hierarchical tree displays loaded assemblies and their content structured according to .NET metadata:

```
📁 MyApplication.exe
├── 📁 References
│   ├── mscorlib
│   ├── System
│   └── System.Core
├── 📁 MyApplication (root namespace)
│   ├── 📁 Controllers
│   │   └── 📄 MainController
│   │       ├── .ctor()
│   │       ├── ProcessInput(string) : bool
│   │       └── ValidateLicense(string) : LicenseResult
│   ├── 📁 Models
│   │   ├── 📄 User
│   │   └── 📄 LicenseResult
│   └── 📁 Utils
│       └── 📄 CryptoHelper
└── 📁 Metadata
    ├── Assembly Attributes
    └── Module Attributes
```

Each tree node is clickable and displays the corresponding decompiled code in the central panel. Icons visually indicate the member type (class, interface, enum, method, property, field) and its access modifier (lock for `private`, diamond for `protected`, etc.).

To load an assembly, you can either use `File > Open` or drag and drop the `.dll` or `.exe` file directly into the window.

### The code panel (central area)

This is where decompiled code is displayed. By default, ILSpy decompiles to **C#**, but it offers several viewing modes accessible via the toolbar or the language dropdown:

- **C#**: the default and most useful mode for RE. The produced code is syntactically valid C# and often recompilable.  
- **IL**: displays raw CIL bytecode, instruction by instruction. Essential when C# decompilation hides a detail or when you suspect an obfuscation artifact.  
- **IL with C# comments**: a hybrid mode that interleaves CIL and the corresponding C# — very useful for understanding the correspondence between the two levels.  
- **ReadyToRun**: if the assembly contains R2R precompiled code (cf. section 30.5), this mode displays the generated native code.

The code displayed in this panel supports **syntax highlighting**, **block folding**, and most importantly **click navigation**: clicking on a type, method, or field name takes you directly to its definition, exactly like in an IDE.

### The search bar

Accessible via `Ctrl+Shift+F` or the search icon, it allows searching across all loaded assemblies. The search covers type names, members, literal constants (strings, numbers), and attributes. It's the functional equivalent of the `strings` command for the .NET world, but with full awareness of the code structure.

You can filter the search by category (type, method, field, property, event, string literal) and by access modifier, which is extremely handy for quickly locating a license verification routine or a decryption method.

---

## Key features for RE

### Cross-reference navigation

As in Ghidra with XREFs (Chapter 8, section 8.7), the ability to follow references is fundamental in RE. ILSpy offers two essential commands, accessible by right-clicking on any symbol:

- **Analyze** (`Ctrl+R`): opens a dedicated panel that displays all uses of a symbol, organized by category — "Used By", "Uses", "Exposed By", etc. It's the equivalent of Ghidra's XREFs, but with .NET metadata granularity.  
- **Go to Definition** (`F12`): navigates to the definition of the selected type or member, including in referenced assemblies.

In .NET RE, the typical strategy is to locate a point of interest (a suspicious string, a suggestive method name like `CheckLicense` or `DecryptPayload`), then trace back references to understand the calling context. ILSpy makes this process fluid thanks to the navigation history (`Alt+←` / `Alt+→`) that works like a web browser.

### Modern C# version decompilation

A strong point of ILSpy is its support for modern C# constructs. The decompiler doesn't just produce a functional equivalent: it attempts to **recognize the patterns** generated by the Roslyn compiler and restore them to their original C# syntactic form. This includes:

- **`async` / `await`**: the compiler transforms asynchronous methods into complex state machines (generated classes implementing `IAsyncStateMachine`). ILSpy reconstructs the original `async` method with its `await`s, which is infinitely more readable than the raw state machine.  
- **Pattern matching** (`switch` on types, `is` with decomposition variables): the generated CIL is a cascade of type checks and casts. ILSpy folds them back into `switch` / `is` / `when` syntax.  
- **Records** and **init-only setters** (C# 9+): recognized and restored.  
- **`using` expressions** (without block): the compiler generates a `try/finally` with `Dispose()`, ILSpy converts it back to `using`.  
- **Named tuples**: `ValueTuple<T1, T2, ...>` are displayed with `(int x, string y)` syntax.  
- **Nullable reference types**: `?` annotations are reconstructed from metadata attributes.

You can control the C# language version used for decompilation via `View > Options > Decompiler > C# Language Version`. Lowering the version can be useful to see the code "as the compiler actually generates it" rather than the syntactically sugared version.

### Complete project export

A particularly useful ILSpy feature for in-depth RE is the ability to export an entire assembly as a **Visual Studio C# project** (`.csproj`):

```
Right-click on the assembly > Save Code...
```

ILSpy then generates a file tree of `.cs` files reproducing the namespace structure, with a configured `.csproj` file. This exported project isn't always immediately recompilable (it may be missing dependencies or contain decompilation-related ambiguities), but it constitutes a solid working base for:

- **Reading code in a real IDE** (Visual Studio, Rider, VS Code) with the full power of IntelliSense, *Find All References*, and refactoring.  
- **Attempting recompilation** to validate your understanding: if the project recompiles and produces identical behavior, your analysis is correct.  
- **Modifying and recompiling** an instrumented version of the program, for example to add debug traces.

> ⚠️ Project export is a tool for **understanding**, not a piracy tool. Recompiling a proprietary assembly for redistribution would violate most software licenses and the intellectual property laws mentioned in Chapter 1, section 1.2.

---

## Advanced viewing modes

### IL view (CIL bytecode)

Switching to IL mode is essential in several RE situations:

- **When C# decompilation seems incorrect**: the decompiler can sometimes misinterpret a pattern, especially if the code was compiled with an older compiler or obfuscated. The IL view shows you exactly what's in the assembly.  
- **To understand performance**: CIL instructions like `callvirt` vs `call`, `box`/`unbox`, or `ldloc`/`stloc` sequences reveal details that decompiled C# hides.  
- **To detect obfuscation**: IL code containing absurd sequences (mass `nop`, jumps to jumps, never-used variables) betrays obfuscator intervention (cf. section 31.5).

ILSpy's IL view displays instructions with their offsets, metadata tokens resolved to readable names, and exception blocks (`try`/`catch`/`finally`/`fault`) clearly delimited. It's much more readable than the raw output of `ildasm` (Microsoft's historical tool).

### Metadata view

Accessible via the "Metadata" nodes in the tree, this view allows inspecting the assembly's raw metadata tables — TypeDef, MethodDef, FieldDef, MemberRef, AssemblyRef, etc. It's the .NET equivalent of `readelf -S` for ELF sections (Chapter 5, section 5.2): you see the internal structure as the runtime consumes it.

This view is particularly useful for:

- Checking assembly attributes (version, culture, strong name, signature).  
- Identifying exact dependencies (versions of referenced assemblies).  
- Detecting abnormal metadata entries left by an obfuscator.

---

## Typical RE workflow with ILSpy

For an unknown .NET assembly, here is the typical approach with ILSpy, organized in progressive phases.

### Phase 1 — Loading and reconnaissance

Open the assembly in ILSpy and start by examining the tree without clicking on any method. Note:

- The **namespaces** present: they reveal the application's architecture (`Controllers`, `Services`, `Models`, `Data`, `Security`, `Licensing`...).  
- The **class names**: unlike stripped ELF binaries, you have the developer's original names here. A `LicenseValidator` or `CryptoEngine` class is immediately spotted.  
- The **references**: what third-party libraries are used? `Newtonsoft.Json` for serialization? `BouncyCastle` for cryptography? `System.Net.Http` for network communications?  
- The **assembly attributes**: version, copyright, debug configuration (`DebuggableAttribute` indicates whether the assembly was compiled in Debug or Release).

### Phase 2 — Searching for points of interest

Use the search (`Ctrl+Shift+F`) to locate:

- Suspicious **string literals**: license error messages, URLs, file paths, hardcoded keys.  
- Suggestive **method names**: `Validate`, `Decrypt`, `Authenticate`, `CheckExpiry`, `GenerateKey`.  
- **Cryptographic calls**: search for `AES`, `RSA`, `SHA`, `HMAC`, `Encrypt`, `Decrypt` in member names.

### Phase 3 — Top-down analysis

Once a point of interest is identified, trace back the call graph with **Analyze** (`Ctrl+R`). Start from the target method and answer the following questions: who calls this method? With what arguments? Is the result checked in a conditional branch? This is exactly the same top-down methodology described in Chapter 21 (section 21.3) for the native keygenme, but with explicit names instead of hexadecimal addresses.

### Phase 4 — Export and analysis outside ILSpy

If the assembly is large or you need to process multiple components in parallel, export the complete project (`Save Code...`) and continue analysis in an IDE. This transition is natural with ILSpy — the tool doesn't try to lock you into its interface.

---

## Command line: `ilspycmd`

For scripted analyses or pipeline integration (cf. Chapter 35, section 35.5), ILSpy provides a command-line tool:

```bash
# Decompile an entire assembly into a C# project
ilspycmd -p -o ./output_project MyApplication.exe

# Decompile a specific type
ilspycmd -t MyApplication.Controllers.MainController MyApplication.exe

# List types present
ilspycmd -l MyApplication.exe

# Produce IL output instead of C#
ilspycmd --il MyApplication.exe
```

`ilspycmd` uses the same decompilation engine as the GUI — the result quality is identical. It's the ideal tool for automating the decompilation of a batch of assemblies or for integrating a decompilation step into a triage script (in the spirit of the `triage.py` provided in `scripts/`).

---

## ILSpy strengths and limitations

### Strengths

- **Open source and free**: no license restrictions, auditable code, extensible via plugins.  
- **Decompilation quality**: among the best on the market, with active support for the latest C# language versions and .NET runtime.  
- **Cross-platform**: the Avalonia version runs natively on Linux, which is a considerable advantage for analysts working in an RE VM.  
- **Project export**: a feature that neither dotPeek nor dnSpy offer with the same ease.  
- **CLI tool**: `ilspycmd` enables automation and pipeline integration.  
- **Active community**: bugs are fixed quickly, new C# constructs are supported with each release.

### Limitations

- **No integrated debugger**: this is the fundamental difference from dnSpy. ILSpy is a static analysis tool — you cannot set breakpoints, inspect memory, or modify values on the fly. For dynamic analysis, you'll need to complement ILSpy with dnSpy (section 31.2) or the techniques from Chapter 32.  
- **No IL editing**: ILSpy is read-only. You can view code, but not modify it directly in the assembly. For patching, dnSpy is the tool of choice (section 32.4).  
- **Obfuscated assemblies**: facing an aggressive obfuscator (renaming, control flow flattening, string encryption), ILSpy decompiles without errors but the result is unreadable — names like `a.b(c.d())` don't help you. You must first pass through a deobfuscator like de4dot (section 31.5).  
- **Mixed assemblies (C++/CLI)**: assemblies containing native code mixed with CIL (mixed mode) are only partially decompiled. The native portion requires a tool like Ghidra (Chapter 8).

---

## Summary

ILSpy is the natural starting point for any .NET assembly analysis. Its combination of decompilation quality, rich navigation, project export, and cross-platform support makes it the indispensable tool for the .NET reverse engineer. Its "static and read-only" philosophy is both its strength (simplicity, reliability) and its limitation (no debugging, no patching) — gaps that dnSpy and the dynamic techniques from Chapter 32 fill.

---


⏭️ [dnSpy / dnSpyEx — decompilation + integrated debugging (breakpoints on decompiled C#)](/31-decompilation-dotnet/02-dnspy-dnspyex.md)
