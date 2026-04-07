🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 31.2 — dnSpy / dnSpyEx — Decompilation + Integrated Debugging (Breakpoints on Decompiled C#)

> 📦 **Chapter 31 — Decompiling .NET Assemblies**  
> 

---

## Introduction

dnSpy is much more than a decompiler: it's a **complete .NET reverse engineering environment** that combines decompilation, debugging, IL editing, and memory inspection in a single interface. Where ILSpy (section 31.1) is limited to static analysis, dnSpy allows you to set a breakpoint directly on a line of decompiled C# code, launch execution, inspect local variables, and modify values live — all without having the source code or PDB files.

For a reverse engineer accustomed to the GDB workflow on native binaries (Chapters 11–12), dnSpy represents a radical comfort improvement. Imagine being able to debug a stripped ELF binary with Visual Studio-level comfort, seeing C code instead of assembly: that's exactly what dnSpy offers for the .NET world.

### dnSpy vs dnSpyEx

The original dnSpy project, created by **0xd4d** (also the author of de4dot), was archived by its author in December 2020. The GitHub repository remains accessible but no longer receives updates. The community fork **dnSpyEx** has taken over and provides active maintenance:

- Support for .NET 6, 7, 8, and 9 runtimes.  
- Decompiler and debugger bug fixes.  
- Compatibility with the latest C# constructs (required members, collection expressions, primary constructors).

Throughout the rest of this section, the name "dnSpy" refers to **dnSpyEx** unless otherwise indicated. This is the version you should install.

---

## Installation

### Download

Go to the dnSpyEx GitHub repository (`dnSpyEx/dnSpy`) and download the release matching your architecture from the *Releases* tab. Two builds are offered:

- **`dnSpy-net-win64.zip`**: version targeting .NET (recommended) — supports debugging both .NET Framework *and* .NET 6+ applications.  
- **`dnSpy-netframework.zip`**: version targeting .NET Framework 4.7.2 — only necessary if you need to debug very specific legacy runtime scenarios.

Extract the archive and launch `dnSpy.exe`. No installation required — the tool is entirely portable.

### Platform limitation

dnSpy is a **Windows-only** application. Its debugger relies on Windows CLR debugging APIs (`ICorDebug`, `DbgShim`), which have no equivalent on Linux or macOS. If you're working in a Linux VM, two options are available:

- Use dnSpy in a **dedicated Windows VM** (or dual-boot).  
- Use ILSpy (section 31.1) for static decompilation on Linux, and reserve dnSpy for dynamic debugging sessions on Windows.

This constraint is one of the reasons why it's important to master multiple tools (cf. comparison in section 31.4).

---

## Interface tour

dnSpy's interface deliberately resembles Visual Studio, making it immediately familiar to C# developers. It's organized into several areas.

### The assembly tree (left panel)

Functionally identical to ILSpy's: hierarchy of namespaces, types, methods, properties, and fields. Click navigation and node collapsing work the same way. Assemblies are loaded by drag-and-drop or via `File > Open`.

A notable difference: dnSpy automatically loads **GAC assemblies** (Global Assembly Cache) and installed .NET runtime assemblies, allowing you to navigate into the framework's internal implementations (BCL classes, runtime, etc.) without loading them manually.

### The code panel (central area)

Decompiled C# code is displayed here with full syntax highlighting. As in ILSpy, clicking on a type or member navigates to its definition. But dnSpy adds two visual capabilities absent from ILSpy:

- **The breakpoint margin**: a gray column to the left of the code, where you can click to set or remove a breakpoint (red dot). Exactly like in Visual Studio.  
- **Current line highlighting**: during debugging, the currently executing line is highlighted in yellow, with an arrow in the margin.

### Debugging panels (bottom area)

These panels are only visible during an active debugging session:

- **Locals**: local variables of the current method, with their current values, types, and ability to expand complex objects.  
- **Watch**: custom expressions evaluated at each debug step.  
- **Call Stack**: complete call stack, with navigation to each frame.  
- **Threads**: list of process threads, with ability to switch between them.  
- **Modules**: all assemblies loaded by the process, with their base addresses — useful for identifying dynamic plugin loading.  
- **Breakpoints**: centralized list of all set breakpoints, with individual enable/disable.  
- **Output**: debug messages, exceptions, `Console.WriteLine` output.

### The context menu (right-click)

dnSpy's context menu is much richer than ILSpy's and reflects its dual decompiler/debugger nature:

- **Go to Definition** / **Analyze**: navigation and cross-references, as in ILSpy.  
- **Edit Method (C#)**: opens an editor allowing you to modify a method's C# code, which dnSpy recompiles to IL and injects into the assembly.  
- **Edit IL Instructions**: direct CIL opcode editing.  
- **Edit Method Body**: modification of a method body at the IL level, with instruction visualization as a table.  
- **Set Next Statement**: during debugging, moves the execution pointer to another line — essential for skipping a verification.

---

## The debugger: the flagship feature

dnSpy's integrated debugger is what fundamentally distinguishes it from all other .NET tools. It allows debugging any .NET assembly **without source code and without PDB**, by setting breakpoints directly on decompiled C# code.

### Starting a debugging session

dnSpy offers two startup modes, analogous to GDB's `run` and `attach` modes (Chapter 11):

**"Start" mode** (`Debug > Start`): dnSpy launches the target process and attaches the debugger from startup. You can configure command-line arguments, working directory, and environment variables. This mode is ideal for console applications and command-line tools.

**"Attach" mode** (`Debug > Attach to Process`): dnSpy attaches to an already-running .NET process. The list shows all .NET processes detected on the machine, with their PID, name, and runtime version. This mode is useful for Windows services, ASP.NET applications hosted by IIS, or any process you don't control at startup.

For each mode, you must select the appropriate debugging engine:

- **.NET Framework**: for applications targeting the classic runtime (versions 2.0 through 4.8).  
- **.NET**: for .NET 6+, .NET 8 applications, etc.  
- **Unity**: for Unity games and applications (which use Mono or IL2CPP — in the IL2CPP case, the .NET debugger doesn't work because CIL has been compiled to native).

### Breakpoints on decompiled code

This is dnSpy's most impressive capability. The workflow is:

1. Navigate the tree to the method you're interested in.  
2. Click in the gray margin to the left of the line where you want to stop. A red dot appears.  
3. Start debugging (`F5`).  
4. When execution reaches that line, the process pauses. The line is highlighted in yellow.  
5. Inspect local variables in the *Locals* panel, evaluate expressions in *Watch*, examine the call stack.

This mechanism works because dnSpy performs a mapping between IL instructions and decompiled C# code lines. When you set a breakpoint on a C# line, dnSpy determines the corresponding IL offset and sets a CLR breakpoint at that offset. The mapping isn't always perfect — a breakpoint may shift by a line or two, especially in optimized code — but it's reliable in the vast majority of cases.

### Conditional breakpoints

Like GDB's conditional breakpoints (Chapter 11, section 11.5), dnSpy allows conditioning a break on a boolean expression. Right-click on a set breakpoint, then *Settings*. You can specify:

- **Condition**: a C# expression evaluated in the method's context. For example: `password.Length > 8` or `userId == 42`.  
- **Hit Count**: break only on the Nth hit ("when hit count equals 5", "when hit count is a multiple of 100").  
- **Filter**: break only on a specific thread or given process.  
- **Action**: instead of pausing, log a message to the *Output* window (tracepoint) — useful for tracing calls without interrupting execution.

Conditional breakpoints are particularly powerful for RE of validation routines. Imagine a method `CheckSerial(string serial)` called in a loop on multiple keys: a breakpoint conditioned on `serial.StartsWith("PRO-")` lets you precisely isolate the calls you're interested in.

### Memory and object inspection

During a debug pause, the *Locals* panel displays the complete state of local variables and parameters of the current method. For complex types, you can expand the object to see its fields, and continue recursively. The *Watch* window accepts any valid C# expression in the current context:

- `this.config.LicenseKey` — access a private field of the current object.  
- `System.Text.Encoding.UTF8.GetString(buffer)` — convert a byte array to a readable string.  
- `BitConverter.ToString(hashBytes).Replace("-", "")` — format a hash as hexadecimal.  
- `((MyDerivedClass)baseRef).SecretField` — cast to access a derived type's field.

This is the equivalent of GDB's `print` command (Chapter 11, section 11.2), but with the evaluation power of the full .NET runtime. You can call methods, instantiate objects, and evaluate arbitrary expressions — a comfort level unmatched in the native world.

For low-level memory inspection, `Debug > Windows > Memory` opens a hex viewer of the target process, similar to GDB's `x` command (Chapter 11, section 11.3). You can navigate by address or expression (variable name, pointer).

### Step by step

The step commands are the same as in any debugger:

| Command | Shortcut | GDB equivalent | Behavior |  
|---|---|---|---|  
| **Step Into** | `F11` | `step` | Enter the called method |  
| **Step Over** | `F10` | `next` | Execute the line without entering calls |  
| **Step Out** | `Shift+F11` | `finish` | Continue until the current method returns |  
| **Continue** | `F5` | `continue` | Resume execution until the next breakpoint |  
| **Run to Cursor** | `Ctrl+F10` | `advance` | Continue until the line where the cursor is |  
| **Set Next Statement** | — | `set $rip` | Move the execution pointer (skip code) |

**Set Next Statement** deserves special attention. This command allows moving the execution pointer to any line of the current method, without executing the intermediate lines. In RE, it's an immediate bypass tool: if a license check is on line 15 and the "valid license" code starts at line 20, you can literally skip the verification by moving execution from line 14 to line 20. It's the equivalent of modifying `$rip` in GDB, but with the safety of C# mapping — you see exactly where you're jumping.

> ⚠️ **Caution**: Set Next Statement can cause an inconsistent state if you skip variable initializations or `try/finally` blocks. Use it with discernment.

---

## Assembly editing

dnSpy's second distinctive feature is the ability to **modify an assembly** and save the changes. This is binary patching (Chapter 21, section 21.6) adapted to the .NET world.

### C# editing

Right-click on a method, then `Edit Method (C#)`. dnSpy opens a code editor in the central panel, pre-filled with the method's decompiled code. You can freely modify the C# code:

```csharp
// Before modification (original decompiled code)
public bool ValidateLicense(string key)
{
    byte[] hash = ComputeHash(key);
    return CompareBytes(hash, this.expectedHash);
}

// After modification (bypass)
public bool ValidateLicense(string key)
{
    return true;
}
```

Click `Compile`. dnSpy invokes Roslyn (the C# compiler) to transform your modified code into IL, then replaces the method body in the in-memory assembly. If compilation fails (syntax error, unresolved type), errors are displayed in a panel at the bottom of the editor, just like in Visual Studio.

C# editing has some constraints to keep in mind:

- You can only modify **one method at a time** (no multi-file refactoring).  
- The method's **types and signatures** cannot be changed (you can't add a parameter or change the return type).  
- The built-in compiler needs to **resolve all referenced types** — if a dependency assembly is missing, compilation will fail.

### Direct IL editing

For more surgical modifications, `Edit IL Instructions` displays the method body as a table of CIL instructions, with each instruction's offset, opcode, and operand. You can:

- Modify an opcode (turn a `brfalse` into `brtrue` to invert a branch — exactly like inverting a `jz`/`jnz` on a native binary in Chapter 21, section 21.4).  
- Delete instructions (replace them with `nop`).  
- Insert new instructions.  
- Modify operands (change a jump target, replace a constant).

IL editing is more powerful than C# editing because it isn't limited by what the Roslyn compiler can produce. Certain transformations (exception table modification, adding `fault` handlers, generic constraint manipulation) are only possible at the IL level.

### Saving modifications

After making your modifications (in C# or IL), save with `File > Save Module` or `File > Save All`. dnSpy writes a new assembly to disk with your changes integrated. The original assembly is not modified — dnSpy creates a new file (or asks you to confirm overwriting).

> 💡 **Best practice**: always work on a copy of the assembly and keep the original intact. Name your modified versions explicitly (`MyApp_patched_v1.exe`, `MyApp_license_bypass.exe`) to keep track of your modifications.

> ⚠️ If the assembly is **signed** (strong name), the modification invalidates the signature. The application or runtime will refuse to load the modified assembly. Section 32.4 of the next chapter covers techniques to bypass this verification.

---

## Complementary features

### Analyze (cross-references)

As in ILSpy, `Ctrl+R` on a symbol opens an *Analyzer* panel listing uses: "Used By", "Uses", "Instantiated By", "Assigned By", "Read By". The implementation is functionally equivalent to ILSpy's — dnSpy's decompilation engine is in fact an old fork of ILSpy's engine, though the two have diverged since.

### Advanced search

`Ctrl+Shift+K` opens a global search box supporting the same categories as ILSpy's (types, methods, fields, string literals), plus the ability to search in automatically loaded **runtime assemblies**. This allows finding uses of uncommon framework types that might reveal hidden functionality.

### Built-in hex editor

`Ctrl+X` on a method or field opens a hex editor positioned at the corresponding offset in the PE file. This editor is more rudimentary than ImHex (Chapter 6), but it allows quick corrections without leaving dnSpy. It's particularly useful for modifying constants (hardcoded strings, configuration bytes) directly in the binary.

### Multiple tabs and sessions

dnSpy supports multiple tabs: you can open several methods or types in separate tabs and switch between them. Combined with the bookmark system (`Ctrl+K`), this allows simultaneously keeping in view the validation routine, the hash function it calls, and the data structure it manipulates.

---

## RE debugging workflow with dnSpy

To concretely illustrate dnSpy's use in reverse engineering, here is a typical workflow facing a .NET application whose validation logic you want to understand.

### Phase 1 — Static reconnaissance

Load the assembly and browse the tree. Identify namespaces related to validation (`Licensing`, `Security`, `Auth`...). Use string search to locate error messages ("Invalid license key", "Trial expired", etc.). Trace cross-references from these strings back to the methods that use them. At this stage, the workflow is identical to ILSpy's.

### Phase 2 — Strategic breakpoint placement

You've identified the candidate method, for example `LicenseManager.ValidateKey(string)`. Set a breakpoint at the method's entry (first line of the body). If the method is long, set additional breakpoints at critical branching points — the `if`s, the `return`s, the calls to crypto functions.

### Phase 3 — Execution and observation

Start debugging (`F5`). Interact with the application normally — enter any license number and validate. Execution stops at your breakpoint. You now see:

- The **exact value** of the `key` parameter you entered, in the *Locals* panel.  
- The method's **local variables** as you step through.  
- The **return values** of called sub-methods (computed hash, comparison result, etc.).

Step through (`F10` / `F11`) the validation logic. Note at each step the transformations applied to your input: what hash function is used? What is the expected hash? Is there a salt? Is the verification symmetric (direct comparison) or asymmetric (signature verification)?

### Phase 4 — Information extraction

Using the *Watch* panel, you can evaluate expressions at each pause to extract critical data:

- The exact argument passed to a comparison function.  
- The contents of a byte array used as a decryption key.  
- The expected string before hashing.  
- The intermediate result of a cryptographic computation.

This information directly feeds the writing of a keygen (Chapter 21, section 21.8) or understanding of an encryption scheme (Chapter 24).

### Phase 5 — Quick bypass (optional)

If the immediate goal is to bypass the verification (in a CTF or authorized audit context), you can use **Set Next Statement** to skip the verification in real time, or **Edit Method** to modify the code and save a patched version of the assembly.

---

## dnSpy strengths and limitations

### Strengths

- **Debugger on decompiled code**: the flagship feature, with no equivalent in the free .NET ecosystem. Transforms .NET RE into an experience close to debugging with sources.  
- **C# and IL editing**: enables direct assembly patching, from a simple constant modification to complete method replacement.  
- **Familiar interface**: the Visual Studio layout reduces the learning curve for C# developers.  
- **Multi-runtime support**: .NET Framework, .NET 6+, Unity (Mono) — covers the majority of .NET applications encountered in practice.  
- **Conditional breakpoints and tracepoints**: allow fine-grained dynamic analysis without drowning the analyst in pauses.  
- **Free and open source** (GPL v3) via the dnSpyEx fork.

### Limitations

- **Windows only**: the debugger relies on Windows native CLR APIs. No Linux port is planned.  
- **Community-driven fork**: dnSpyEx's development pace is irregular, depending on volunteer contributions. Some features may exhibit regressions between versions.  
- **Decompilation quality**: dnSpy's decompilation engine, while good, has diverged from ILSpy's and can produce slightly different (and sometimes less faithful) results on the most recent C# constructs. ILSpy benefits from more active development of its decompilation engine.  
- **No project export**: unlike ILSpy, dnSpy doesn't offer export as a complete `.csproj` project. You can copy code method by method, but not export the entire tree in one click.  
- **Obfuscated assemblies**: like ILSpy, dnSpy faithfully displays an obfuscated assembly, but the result remains unreadable. The debugger works on obfuscated code, which helps, but doesn't replace a prior deobfuscation pass (section 31.5).  
- **No IL2CPP support**: Unity games compiled with IL2CPP (CIL is converted to C++ then compiled natively) are not debuggable by dnSpy. They require native tools like Ghidra (Chapter 8) or specialized tools like Il2CppDumper.

---

## Summary

dnSpy (via the dnSpyEx fork) is the tool of choice for **dynamic analysis** of .NET assemblies. Its unique capability of debugging on decompiled code — breakpoints, stepping, variable inspection, expression evaluation — makes it ILSpy's indispensable companion. Where ILSpy excels at reading and exporting code, dnSpy excels at observing and modifying runtime behavior. In practice, an effective .NET reverse engineer uses both: ILSpy for static reconnaissance and export, dnSpy for debugging and patching. Section 31.4 will formalize this complementarity in a detailed comparison.

---


⏭️ [dotPeek (JetBrains) — navigation and source export](/31-decompilation-dotnet/03-dotpeek.md)
