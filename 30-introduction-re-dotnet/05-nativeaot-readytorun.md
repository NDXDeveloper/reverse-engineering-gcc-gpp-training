🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 30.5 — NativeAOT and ReadyToRun: When C# Becomes Native Code

> 📚 **Section objective** — Understand .NET's ahead-of-time compilation modes, know how to recognize a binary produced by ReadyToRun or NativeAOT, and identify which RE techniques — managed or native — apply in each case.

---

## The classic model: everything relies on the JIT

In the standard .NET model described in section 30.1, CIL bytecode is compiled to machine code **at runtime** by the CLR's JIT compiler. This model has advantages (the JIT can optimize for the exact CPU of the host machine) but also well-known drawbacks: slower startup time (each method must be compiled on first invocation), increased memory consumption (the JIT itself resides in memory), and dependency on the .NET runtime installed on the target machine.

From the reverser's perspective, the JIT model is comfortable: the distributed file contains pure CIL with complete metadata, and .NET decompilation tools (ILSpy, dnSpy) work directly. This is the scenario covered by sections 30.1 through 30.4.

But Microsoft has introduced two alternatives that compile all or part of C# code into machine instructions **before execution** — thus bringing the .NET binary closer to a classic native executable. These two modes have radically different implications for the analyst.

## ReadyToRun (R2R): the hybrid model

### Principle

ReadyToRun (R2R), introduced with .NET Core 3.0 and stabilized in subsequent versions, is a **partial pre-compilation** format. The `crossgen2` compiler (automatically invoked by `dotnet publish` with the appropriate option) generates native machine code for each method and embeds it in the assembly, **alongside** the original CIL bytecode.

```
$ dotnet publish -c Release -r linux-x64 /p:PublishReadyToRun=true
```

The result is a PE assembly containing both representations:

```
┌───────────────────────────────────────────┐
│          ReadyToRun Assembly              │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  CIL Bytecode    (always present)   │  │
│  │  + Metadata       (intact)          │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  R2R Native code  (pre-compiled)    │  │
│  │  x86-64 or ARM64 per target         │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  R2R Header + ReadyToRunInfo        │  │
│  │  (CIL method → native code          │  │
│  │   mapping table)                    │  │
│  └─────────────────────────────────────┘  │
└───────────────────────────────────────────┘
```

At runtime, the CLR uses the pre-compiled native code to skip the JIT phase. The CIL remains available as a **fallback**: if the runtime detects that the R2R code is incompatible (different runtime version, GC update, etc.), it ignores the native images and recompiles the CIL via the classic JIT. It's a dual-track system.

### How to recognize it

An R2R assembly remains a PE file with a CLR Header and complete metadata. The `file` command produces the same output as a classic assembly (`Mono/.Net assembly`). Triage with `strings` and `monodis` works normally — type names, method names, and user strings are intact.

The distinctive signal is the presence of an **R2R Header** in the `.text` section, identifiable by its `RTR\0` magic (bytes `52 54 52 00`). With ImHex:

```
Hex search: 52 54 52 00  
Result: found at offset 0x1A00 (example)  
```

The command-line tool `r2rdump` (provided with the .NET SDK) allows inspecting R2R content in a structured way:

```
$ dotnet tool install -g r2rdump    # one-time installation
$ r2rdump --in CrackMe.dll --header

ReadyToRun header:
  MajorVersion: 9
  MinorVersion: 2
  Flags: 0x00000023 (COMPOSITE | PLATFORM_NEUTRAL_SOURCE | MULTIMODULE_SINGLE_FILE)
  NumberOfSections: 17
```

You can also list the mapping between CIL methods and their native offsets:

```
$ r2rdump --in CrackMe.dll --methods
  CrackMe.LicenseChecker.ValidateKey(String) @ 0x00002C40
  CrackMe.Program.Main(String[]) @ 0x00002B80
```

### Impact on RE

Here's the crucial point for the reverser: **R2R removes nothing, it adds**. CIL and metadata are fully preserved. .NET decompilers (ILSpy, dnSpy) continue to work perfectly — they read the CIL and metadata, completely ignoring the R2R native code.

In practice, an R2R assembly reverses exactly like a classic assembly. The presence of pre-compiled native code doesn't hinder managed analysis and doesn't constitute a protection. It's a performance optimization, not an obfuscation technique.

The only situation where R2R native code is analytically interesting is when you want to study the **optimizations actually applied** at runtime — R2R code reflects the AOT compiler's (`crossgen2`) decisions, which may differ from the JIT's. For the typical reverser, this case is marginal.

> 📖 **R2R summary** — CIL present, metadata intact, normal decompilation. Native code is a performance bonus, not an obstacle. The analyst can ignore R2R and work on the CIL.

## NativeAOT: the paradigm shift

### Principle

NativeAOT (Native Ahead-of-Time), available in production since .NET 7, is a fundamentally different compilation mode. The AOT compiler (`ILC` — IL Compiler) transforms CIL into an **entirely native** executable that runs **without the CLR and without the JIT**. The result is a self-contained binary that depends on no .NET runtime installed on the machine.

```
$ dotnet publish -c Release -r linux-x64 /p:PublishAot=true
```

The result on Linux is a standard **ELF** file:

```
$ file CrackMe
CrackMe: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=a3b2c1..., for GNU/Linux 3.2.0, stripped  
```

No mention of `Mono/.Net assembly`. No CLR Header. No `BSJB` magic. The file looks like GCC output — because it is, more or less: native machine code linked with an embedded minimal runtime.

```
┌───────────────────────────────────────────┐
│        NativeAOT Binary (ELF)             │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  x86-64 machine code                │  │
│  │  (compiled from CIL by ILC)         │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  Embedded minimal runtime           │  │
│  │  (GC, threading, exception handling)│  │
│  └─────────────────────────────────────┘  │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  Reflection metadata (reduced)      │  │
│  │  (only if reflection is used)       │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  NO CIL                                   │
│  NO CLR/JIT                               │
│  NO complete metadata                     │
└───────────────────────────────────────────┘
```

### What disappears

The consequence for the reverser is massive. Let's compare what a classic assembly contains versus a NativeAOT binary:

| Element | Classic assembly | NativeAOT |  
|---|---|---|  
| CIL bytecode | Complete | **Absent** — compiled to native then eliminated |  
| Complete metadata (`TypeDef`, `MethodDef` tables...) | Complete | **Absent** or greatly reduced |  
| `#Strings` heap (type/method names) | Complete | **Partially present** (only for types used by reflection) |  
| `#US` heap (user strings) | Complete | Strings are in `.rodata` (like native C) |  
| CLR Header + BSJB magic | Present | **Absent** |  
| Function names in symbol table | Via .NET metadata | Present if not stripped, **lost if stripped** (like GCC) |  
| C# decompilation (ILSpy/dnSpy) | Near-perfect | **Impossible** — no CIL to decompile |  
| x86-64 disassembly (Ghidra/IDA) | Not relevant (CIL, not x86) | **Relevant** — it's machine code |

In other words: a stripped NativeAOT binary is, from the reverser's perspective, **indistinguishable from a C binary compiled by GCC and stripped**. .NET tools are useless; it's native tools — Ghidra, IDA, GDB, Frida, `objdump` — that take over. All techniques covered in Parts I through IV apply directly.

### How to recognize it

Detecting a NativeAOT binary is less immediate than detecting a classic assembly, precisely because it looks like an ordinary native executable. Here are the indicators:

**`file` reports a native ELF or PE** — with no mention of `.Net assembly`. This is the first signal: if you expected a C# program and `file` says ELF, you're probably facing NativeAOT (or the native host of a classic deployment — check for the absence of an adjacent `.dll`).

**`strings` reveals .NET runtime traces** — Even compiled natively, a NativeAOT binary embeds the minimal .NET runtime (garbage collector, thread management, exception handling). This runtime's strings are present in the binary:

```
$ strings CrackMe | grep -iE "System\.|Microsoft\.|\.NET|coreclr|S_OK"
System.Private.CoreLib  
System.Runtime.ExceptionServices  
System.Collections.Generic  
Microsoft.Win32  
```

The presence of .NET namespaces (`System.*`, `Microsoft.*`) in a native ELF is a strong sign of NativeAOT. A C program compiled by GCC would never contain these strings.

**`readelf` shows characteristic symbols** — If the binary isn't stripped, the symbol table contains recognizable names:

```
$ readelf -s CrackMe | grep -i "S_P_CoreLib\|RhNew\|RhpGc\|__managed__"
  142: 00000000004a2340  FUNC    CrackMe_CrackMe_LicenseChecker__ValidateKey
  143: 00000000004a2100  FUNC    CrackMe_CrackMe_Program__Main
  287: 00000000004f8000  FUNC    S_P_CoreLib_System_String__Concat
  412: 0000000000501200  FUNC    RhpGcAlloc
```

The NativeAOT function naming scheme is characteristic: `AssemblyName_Namespace_Class__Method`, with double underscores separating the class from the method. Functions prefixed with `Rhp` or `Rh` belong to the runtime (Runtime Helper). Functions prefixed with `S_P_CoreLib` come from the .NET standard library compiled natively.

If the binary is stripped, these symbols disappear — but the runtime strings (`System.*`) in `.rodata` persist and betray the .NET origin.

**Binary size is a contextual clue** — A simple "Hello World" in C# compiled with NativeAOT typically weighs between 1 and 3 MB on Linux (the embedded runtime adds significant base weight). The same program compiled by GCC in C weighs a few tens of KB. An unusually large binary for its apparent functionality may indicate NativeAOT — or a Go or Rust binary (Chapters 33–34), which exhibit the same embedded runtime phenomenon.

### Impact on RE

Facing a NativeAOT binary, the analyst must mentally switch to the native workflow from Parts I through IV:

**Static analysis** — Ghidra or IDA are the disassembly and decompilation tools. Ghidra's decompiler produces pseudo-C (not C#), with the usual quality — approximate but exploitable. The reconstruction techniques covered in Chapters 8 and 20 apply.

**Dynamic analysis** — GDB (Chapter 11) for debugging, Frida (Chapter 13) for dynamic instrumentation, `strace`/`ltrace` (section 5.5) for system calls. dnSpy is useless: there's no CIL to debug.

**Function identification** — If the binary isn't stripped, the NativeAOT naming scheme (`Namespace_Class__Method`) allows quickly reconstructing the program's structure. If the binary is stripped, .NET standard library signatures (FLIRT for IDA, Ghidra signatures — section 20.5) help identify runtime and BCL (Base Class Library) functions to distinguish them from application code.

**Runtime specifics** — .NET's garbage collector is present in the binary and handles memory management. Allocations go through runtime functions (`RhpGcAlloc`, `RhpNewObject`) rather than `malloc`. Virtual calls go through specific dispatchers. These patterns are recognizable with practice, but constitute background noise the analyst must learn to filter — exactly as the Go runtime (section 34.1) or the Rust runtime add infrastructure code around application code.

### NativeAOT with trimming: the extreme case

NativeAOT enables **trimming** by default: the compiler analyzes the call graph and removes all code not statically reachable. The result is a smaller binary, but also a more opaque one — entire sections of the standard library are absent, and reflection mechanisms are limited or disabled.

Trimming has a direct effect on RE: less code means less noise, but also fewer known anchor points. The analyst has fewer identifiable BCL functions by signature, complicating initial orientation in the binary.

## Summary: which mode, which tools?

| Publication mode | Binary format | CIL present? | Complete metadata? | Primary RE tools | RE difficulty |  
|---|---|---|---|---|---|  
| `dotnet build` / `dotnet publish` (standard) | PE (.dll/.exe) | Yes | Yes | ILSpy, dnSpy, monodis | Low (non-obfuscated) to medium (obfuscated) |  
| `PublishReadyToRun=true` | PE (.dll/.exe) | Yes | Yes | ILSpy, dnSpy, monodis (ignore R2R) | Same as standard |  
| `PublishAot=true` (NativeAOT) | ELF / native PE | **No** | **No** | Ghidra, IDA, GDB, Frida, objdump | High (comparable to native C/C++ RE) |  
| NativeAOT + `strip` | Stripped ELF / PE | **No** | **No** | Ghidra, IDA, GDB, Frida | Very high (identical to stripped GCC) |

The analyst's decision diagram is simple:

```
Does the binary contain a CLR Header (Data Directory 14)?
│
├─ YES → Classic .NET assembly (or R2R)
│        → .NET tools: ILSpy, dnSpy, monodis
│        → Techniques from Chapters 30-32
│
└─ NO → Native binary
         │
         ├─ strings reveals "System.*" / "S_P_CoreLib" / "Rhp*"?
         │  → Probable NativeAOT
         │  → Native tools: Ghidra, IDA, GDB
         │  → Techniques from Parts I-IV
         │  → NativeAOT symbols (if not stripped) help with orientation
         │
         └─ No .NET traces?
            → Classic native binary (C, C++, Rust, Go...)
            → Native tools: Ghidra, IDA, GDB
            → Techniques from Parts I-IV (or VIII for Rust/Go)
```

## Perspective: the convergence of worlds

The emergence of NativeAOT illustrates a fundamental industry trend: the boundary between managed and native code is gradually fading. Swift, Kotlin/Native, Dart (Flutter), and now C#/.NET allow producing self-contained native binaries from garbage-collected languages.

For the reverser, this convergence has a practical consequence: **native RE skills (x86-64, ELF, Ghidra, GDB) remain the universal foundation**. They apply to any native binary, whether the source code was written in C, C++, Rust, Go, Swift, or C# compiled with NativeAOT. Managed RE skills (.NET, JVM) are a specialized complement for the cases — still the majority — where bytecode is distributed.

The training you're following, centered on the GNU toolchain and native RE, has given you this foundation. Chapters 30 through 32 add the .NET managed layer on top. With both, you're equipped to handle the entire spectrum — from a stripped GCC binary at `-O3` to a C# assembly obfuscated by ConfuserEx, through the hybrid case of NativeAOT.

---

> 📖 **Key takeaway** — ReadyToRun adds pre-compiled native code alongside CIL, without removing metadata: RE remains managed. NativeAOT eliminates CIL and metadata to produce an entirely native executable: RE switches to Part I–IV techniques. Detection relies on the presence or absence of the CLR Header and on searching for .NET runtime traces (`System.*`, `Rhp*`) in a native binary. A reverser trained in both worlds — native and managed — is prepared for all modern .NET deployment scenarios.

---

> 🔚 **End of Chapter 30.** The foundations are laid: you understand the .NET execution model, assembly structure, common protections, initial triage, and the implications of ahead-of-time compilation. Chapter 31 moves to practice with decompilation tools (ILSpy, dnSpy, dotPeek), and Chapter 32 covers dynamic analysis and .NET assembly hooking.


⏭️ [Chapter 31 — Decompiling .NET Assemblies](/31-decompilation-dotnet/README.md)
