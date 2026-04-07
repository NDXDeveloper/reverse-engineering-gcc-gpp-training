🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 32.1 — Debugging an Assembly with dnSpy Without Sources

> 📁 **Files used**: `binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64/LicenseChecker.dll`  
> 🔧 **Tools**: dnSpy (dnSpyEx), dotnet runtime  
> 📖 **Prerequisites**: [Chapter 31 — Decompiling .NET Assemblies](/31-decompilation-dotnet/README.md)

---

## The principle: the debugger that needs nothing

In the native world, debugging a stripped ELF binary with GDB is an austere exercise. You work with raw addresses, registers, hexadecimal memory dumps. You set breakpoints on offsets you've painstakingly identified in Ghidra. Each local variable is a mystery you reconstruct by inspecting the stack or registers one by one.

The .NET world reverses this situation. Thanks to the metadata embedded in every assembly — type tables, method signatures, field tokens, optional debug information — a tool like dnSpy can simultaneously decompile CIL bytecode to readable C# **and** attach a debugger to the running process. The result is an experience comparable to a developer debugging their own project in Visual Studio, except here you don't possess any source files.

Concretely, this means you can set a breakpoint by clicking on a line of decompiled C# code, step through the program, inspect local variables by their reconstructed names, examine the call stack with complete method signatures, and even evaluate C# expressions on the fly in the Immediate window. It's a comfort level that the native reverse engineer can only envy.

## dnSpy vs dnSpyEx: which tool to use

The original dnSpy project, created by 0xd4d, has not been maintained since 2020. Its GitHub repository is archived. The community fork **dnSpyEx** continues development and provides support for recent .NET versions (6, 7, 8), bug fixes, and compatibility with current runtimes. This is the version to use.

dnSpyEx is available for Windows and, via Wine or a Mono compilation, can partially work on Linux. However, the integrated debugger relies on Windows debug APIs (ICorDebug) and only works fully on Windows. For our exercises, two approaches are possible: use a Windows VM for debugging with dnSpy, or use an alternative .NET debugger on Linux (like `dotnet-dump` or JetBrains Rider's integrated debugger) and reserve dnSpy for static analysis. In what follows, we assume a Windows environment with dnSpyEx, which is the canonical use case.

> 💡 **Reminder**: throughout this chapter, "dnSpy" refers to the dnSpyEx fork unless otherwise noted.

## Opening an assembly in dnSpy

On launch, dnSpy presents an interface resembling a classic IDE. The left part contains the **Assembly Explorer** — a tree listing loaded assemblies and their contents. The central part is the decompiled code editor. At the bottom, you find the debugging windows: Locals, Watch, Call Stack, Breakpoints, Output, Immediate.

To load our target, we use **File → Open** (or drag the file into the window) and select `LicenseChecker.dll`. dnSpy decompiles it instantly. In the Assembly Explorer, we unfold the tree:

```
LicenseChecker (1.0.0.0)
  └── LicenseChecker (namespace)
        ├── Program
        ├── LicenseValidator
        ├── ValidationResult
        └── NativeBridge
```

Clicking on a class displays the decompiled C# code in the central panel. The result is immediately readable: class names, method names, complete signatures, method bodies with reconstructed control logic. If the assembly isn't obfuscated (which is the case for our `LicenseChecker` compiled without protection), the decompiled code is nearly identical to the original source code.

## Understanding what dnSpy actually decompiles

It's important to understand what's happening under the hood. The `LicenseChecker.dll` assembly contains CIL bytecode, not C# source code. dnSpy performs real-time decompilation: it reads IL instructions, reconstructs the control flow (loops, conditions, try/catch blocks), infers local variable types from metadata and IL stack signatures, then produces syntactically valid C#.

This process isn't perfect. Here are the typical discrepancies you may observe between the decompiled code and the original source:

**Local variable names.** If the assembly was compiled in Release mode without a PDB (Program Database) file, local variable names are lost. dnSpy replaces them with generated names: `text`, `num`, `flag`, `array`, etc. In Debug mode or with a PDB present, the original names are preserved.

**Control structures.** The C# compiler transforms certain constructs into IL patterns that don't always transcribe back to the original syntactic form. A `switch` on strings can become a cascade of `if/else` with `string.op_Equality` calls. A `foreach` can appear as a `while` with an explicit enumerator. C# 8+ `switch` expressions (like our `DeriveLicenseLevel`) can be reconstructed differently depending on the decompiler version.

**Auto-implemented properties.** The compiler generates a hidden backing field (named `<PropertyName>k__BackingField`). dnSpy generally recognizes them and re-synthesizes them as auto-implemented properties, but not always.

**LINQ expressions and lambdas.** The compiler generates hidden internal classes (named `<>c__DisplayClass...`) to capture variables. dnSpy attempts to fold them back into lambda expressions, with variable success.

For our `LicenseChecker`, compiled in Release without obfuscation, the result will be very clean. Public and private method names, field names, constants — everything is present in the metadata. Only local variable names will potentially be replaced.

## Configuring debugging

Before launching debugging, you need to tell dnSpy how to execute the application. Use **Debug → Start Debugging** (F5) or the **Debug → Attach to Process** menu depending on whether you want to launch the program or attach to an already-running process.

For a direct launch, dnSpy asks you to configure execution in **Debug → Start Debugging → Debug an Executable**. For a modern .NET application (like our .NET 8 target), configure:

- **Executable**: the path to the `dotnet.exe` runtime (on Windows) or directly to `LicenseChecker.exe` if the application was published in self-contained mode.  
- **Arguments**: if using `dotnet.exe`, pass the path to `LicenseChecker.dll` as argument. You can also add the application's own arguments (username and key).  
- **Working Directory**: the directory containing `LicenseChecker.dll` and `libnative_check.so` (or its Windows `.dll` version).

For a classic .NET Framework assembly (not our case, but still common in RE), configuration is simpler: point directly to the `.exe` executable.

> ⚠️ **Important note**: for P/Invoke calls to `libnative_check` to work on Windows, you need to have compiled a Windows version of the native library (`.dll` instead of `.so`), or work in partial debug mode accepting that P/Invoke steps will fail. For this chapter, you can start by debugging the purely managed parts (segments A and C) and handle P/Invoke separately in section 32.3.

## Setting breakpoints on decompiled code

This is where the magic happens. In the central panel, we navigate to the `LicenseValidator.Validate()` method. We see the decompiled code corresponding to our five-step validation flow. To set a breakpoint, we click in the left margin next to the desired line — exactly like in Visual Studio or any other IDE.

Let's start by placing strategic breakpoints:

**On the `ValidateStructure` call.** This is the first test. By stopping here, we can observe the value of `licenseKey` as it arrives in the validator, and check the parsing result.

**On the `actualA != expectedA` comparison.** This is the key moment for segment A. By inspecting `expectedA` before the comparison executes, we directly get the expected value for the first key segment — without needing to understand the FNV-1a algorithm. This is the power of dynamic debugging: we let the program compute for us.

**On the `actualC != expectedC` comparison.** Same logic for segment C. The value of `expectedC` gives us the correct third segment.

**On the final `result.IsValid = true` return.** If we reach this point, the license is validated. By modifying the execution flow (see below), we could also force execution to reach this point.

Set breakpoints appear in the **Breakpoints** window (menu **Debug → Windows → Breakpoints**), with their location in the decompiled code. You can enable, disable, make them conditional, or add actions (like logging a value without stopping execution).

## Step-by-step execution and inspection

Once breakpoints are set, we start debugging with F5. The application starts, displays its banner, and waits for a username and key. We enter for example `alice` as username and `1111-2222-3333-4444` as key (deliberately incorrect — we want to observe the validation process, not succeed on the first try).

Execution stops at our first breakpoint. At this point, several windows become useful.

**The Locals window.** It displays the current method's local variables with their current values. We see `username = "alice"`, `licenseKey = "1111-2222-3333-4444"`, and the `result` object of type `ValidationResult` being constructed. For complex types (objects, arrays), you can expand the tree to inspect each field.

**The Watch window.** You can add arbitrary expressions to monitor. For example, adding `Convert.ToUInt32("1111", 16)`, dnSpy evaluates the expression and displays `4369`. Useful for verifying conversions without leaving the debugger.

**The Call Stack window.** It shows the call chain that led to the current breakpoint. In our case, we'll see something like `Program.Main → LicenseValidator.Validate`. Double-clicking on a stack frame lets you go back to the caller's context and inspect its variables.

**The Immediate window.** It's an integrated C# REPL. You can type expressions that are evaluated in the context of the current breakpoint. For example, typing `this.ComputeUserHash("alice")` will execute the method and display the result. This is extremely powerful for RE: you can call any method of the current object with arguments of your choice.

We then advance step by step with **F10** (Step Over — executes the current line without entering called methods) or **F11** (Step Into — enters the called method). Navigation is identical to a development IDE. Stepping over `ComputeUserHash(username)`, we see the `expectedA` variable take its value. We note this value — it's the correct segment A for the username `alice`.

## Extracting expected values by observation

The most direct approach to "crack" our `LicenseChecker` by debugging is to let the program compute the correct values itself. Here's the strategy, step by step.

**Retrieve segment A.** Set a breakpoint after the `ComputeUserHash(username)` call. Read the value of `expectedA` in the Locals window. This is the hexadecimal value (4 characters) that the first key segment must contain.

**Retrieve segment B.** This is trickier because it depends on the P/Invoke call. If the native library is available, you can set a breakpoint in `CheckSegmentB` and observe the value of `expected` after the call to `NativeBridge.ComputeNativeHash`. If the library isn't available, the `DllNotFoundException` will be caught and you'll need to approach the problem differently (section 32.3).

**Retrieve segment C.** Same technique: breakpoint after `ComputeCrossXor(actualA, actualB)`, read `expectedC`. But beware — for this calculation to be correct, `actualA` and `actualB` must themselves be correct. You must therefore enter a key whose first two segments are already correct. This is why we proceed iteratively: we get A, then B, relaunch with correct A-B, then get C, etc.

**Retrieve segment D.** Breakpoint after `ComputeFinalChecksum(...)`. Same constraint: the first three segments must be correct for the fourth's calculation to be valid.

This iterative approach — launch, observe, correct, relaunch — is typical of RE debugging. It works without understanding the internal algorithms: you treat the program as a black box that you query step by step.

## Modifying the execution flow

dnSpy allows modifying variable values and moving the execution pointer during debugging. These two capabilities open additional possibilities.

**Modify a variable.** In the Locals or Watch window, you can double-click on a variable's value and change it. For example, if `expectedA` is `0x7B3F` and `actualA` is `0x1111`, you can modify `actualA` to give it the value `0x7B3F` — or modify `expectedA` to match `actualA`. The following comparison will return `true`, and execution will continue to the next step.

**Move the instruction pointer.** By right-clicking on a line of code and choosing **Set Next Statement**, you force execution to resume at that line, skipping all intermediate code. You can thus jump over an `if (!segBValid) { return result; }` block to reach the next step even if the check failed.

These manipulations are temporary bypass techniques — they only affect the current execution and don't modify the binary on disk. For a permanent patch, you'll need to edit the IL (section 32.4). But they're valuable during the exploration phase: they allow "unblocking" the flow to reach code portions you couldn't observe otherwise.

## The Modules window and assembly loading

During debugging, the **Modules** window (Debug → Windows → Modules) lists all assemblies loaded in the process. For our `LicenseChecker`, we'll see at minimum the .NET runtime (`System.Private.CoreLib.dll`, `System.Runtime.dll`...), our main assembly (`LicenseChecker.dll`), and potentially dynamically loaded assemblies.

This window is particularly useful in two situations.

When the application loads assemblies at runtime — via `Assembly.Load()` or `Assembly.LoadFrom()` — they appear in the list at loading time. Some obfuscators decrypt an assembly in memory then load it dynamically. By monitoring the Modules window, you can detect this loading and immediately decompile the new assembly in dnSpy.

When trying to understand dependency resolution. If a P/Invoke call fails or a type isn't found, the Modules window shows which assemblies are actually loaded and which are missing.

## Debugging an obfuscated assembly: the limits

Our `LicenseChecker` is compiled without obfuscation, making debugging comfortable. In real-world situations, you'll encounter protected assemblies. Here are common obstacles and their impact on debugging.

**Symbol renaming.** Classes become `\u0001`, `\u0002`, etc. Methods become unreadable Unicode sequences. The decompiled code remains syntactically correct, but reading is painful. Debugging works normally — you can still set breakpoints and inspect variables, but you must first identify interesting methods by their behavior rather than their name.

**String encryption.** String literals are replaced by calls to a decryption function: instead of `"REV3RSE!"`, you see `DecryptString(12345)`. In dynamic debugging, this is actually an advantage: you let the decryption function execute and inspect the resulting value. The debugger shows the decrypted string where static analysis only sees an opaque call.

**Flattened control flow.** Methods are transformed into a `while(true)` loop with a `switch` on a state variable. The decompiled code becomes a tangle of numbered cases. Step-by-step debugging remains possible, but logical tracking is harder — you navigate through an automaton rather than a structured flow.

**Debugger detection.** Some obfuscators insert calls to `System.Diagnostics.Debugger.IsAttached` or check for dnSpy's presence by process name. These checks are easily bypassed by modifying the return value in the debugger (or by patching them, as we'll see in section 32.4).

## Comparison with native debugging (GDB)

To anchor these concepts relative to what you already know, here's a perspective comparison of both debugging experiences.

| Aspect | GDB on native ELF | dnSpy on .NET assembly |  
|---|---|---|  
| Information available without symbols | Raw addresses, registers, opcodes | Type names, methods, signatures, IL |  
| Setting breakpoints | On address or function name (if symbols) | Click on a decompiled C# line |  
| Variable inspection | `x/` + address, `info locals` (if DWARF) | Locals window with names and types |  
| Expression evaluation | `print expr` (limited to C) | Immediate window (full C#) |  
| Step into a method | `step` (if symbols, otherwise assembly) | F11 → enters decompiled C# |  
| Value modification | `set $rax = 42` or `set {int}0x... = 42` | Double-click on the value in Locals |  
| Bypassing a check | Patch `jz` → `jnz` opcode or modify flags | Variable modification or Set Next Statement |  
| Overall comfort | Spartan | Comparable to a development IDE |

The fundamental difference lies in the amount of information preserved in the binary. A stripped ELF contains virtually nothing beyond machine code; a .NET assembly, even without PDB, retains its entire type structure. This richness makes .NET debugging a qualitatively different activity from native debugging.

## Recommended methodology

To summarize, here's the general approach when tackling an unknown .NET assembly with dnSpy in debug mode:

Start with a **quick static reconnaissance**. Open the assembly in dnSpy, browse the Assembly Explorer to identify namespaces, classes, and methods. Look for entry points (`Main`, constructors, event handlers). Spot interesting strings (error messages, URLs, filenames) using the integrated search (Ctrl+Shift+K). This phase corresponds to the "quick triage" from Chapter 5, transposed to the .NET world.

Then identify **target methods**. In our case, it's `Validate()` and the methods it calls. In real-world situations, look for methods related to the functionality you're studying: license verification, protocol parsing, data decryption.

Set **strategic breakpoints** at decision points — the `if`s that separate the "success" path from the "failure" path. Launch debugging and observe the concrete values.

**Iterate**: adjust inputs based on what you observe, move breakpoints to explore different branches, use the Immediate window to test hypotheses.

And **document** as you go. dnSpy allows adding comments to decompiled code (right-click → Add Comment) and renaming symbols (right-click → Edit Method/Field). These annotations survive the session and facilitate later resumption.

---


⏭️ [Hooking .NET methods with Frida (`frida-clr`)](/32-dynamic-analysis-dotnet/02-hooking-frida-clr.md)
