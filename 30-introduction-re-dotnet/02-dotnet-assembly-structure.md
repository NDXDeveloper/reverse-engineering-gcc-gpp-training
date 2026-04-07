🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 30.2 — Structure of a .NET Assembly: Metadata, PE Headers, CIL Sections

> 📚 **Section objective** — Know how to read the internal anatomy of a .NET assembly, drawing systematic parallels with the ELF structure you've mastered since Chapter 2.

---

## A PE file, not an ELF

First point that often disorients the Linux reverser: a .NET assembly is encapsulated in a **PE** (Portable Executable) format file, the historical binary format of Windows. This remains true even when the application targets .NET 6+ and runs on Linux — the .NET runtime knows how to load a PE file regardless of the host OS.

If you followed section 2.3 on binary formats, you already know the general structure of a PE: a legacy DOS header (with the famous `MZ` magic), followed by a PE header (`PE\0\0`), Optional Headers, and a section table. A .NET assembly keeps all of this, but adds a specific layer: the **CLR Header** and the entire **metadata** block.

In practice, when you run `file` on a .NET assembly, you get something like:

```
$ file MyApp.dll
MyApp.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

The keyword `Mono/.Net assembly` confirms the presence of the CLR Header. On a native Windows executable compiled by MinGW, `file` would simply show `PE32 executable` without this mention.

> 💡 **ELF parallel** — Where a Linux binary starts with the magic `\x7fELF` and exposes its structure via `readelf`, a .NET assembly starts with `MZ` (DOS) then `PE\0\0` and exposes its structure via tools like `monodis`, `ildasm`, or `dotnet-dump`. The principle is the same — a header that describes the content — but the container format differs.

## Architecture overview

Here's how the different layers of a .NET assembly nest, from outside to inside:

```
┌─────────────────────────────────────────────────────┐
│                    PE File (.dll / .exe)            │
│                                                     │
│  ┌──────────────┐                                   │
│  │  DOS Header  │  Magic "MZ" — DOS legacy          │
│  │  + DOS Stub  │  "This program cannot be run..."  │
│  └──────────────┘                                   │
│  ┌──────────────┐                                   │
│  │  PE Headers  │  Signature, COFF Header,          │
│  │              │  Optional Header (32 or 64 bit)   │
│  └──────────────┘                                   │
│  ┌───────────────────────────────────────────────┐  │
│  │   Sections                                       │
│  │                                                  │
│  │  ┌────────────────────────────────────────┐      │
│  │  │ .text                                  │      │
│  │  │                                        │      │
│  │  │  ┌─────────────┐  ┌─────────────────┐  │      │
│  │  │  │ CLR Header  │  │   CIL Bytecode  │  │      │
│  │  │  │ (72 bytes)  │  │  (method bodies)│  │      │
│  │  │  └─────────────┘  └─────────────────┘  │      │
│  │  │                                        │      │
│  │  │  ┌──────────────────────────────────┐  │      │
│  │  │  │         METADATA                 │  │      │
│  │  │  │  ┌────────┐ ┌─────────────────┐  │  │      │
│  │  │  │  │ Tables │ │     Heaps       │  │  │      │
│  │  │  │  │  (#~)  │ │ #Strings  #US   │  │  │      │
│  │  │  │  │        │ │ #Blob    #GUID  │  │  │      │
│  │  │  │  └────────┘ └─────────────────┘  │  │      │
│  │  │  └──────────────────────────────────┘  │      │
│  │  └────────────────────────────────────────┘      │
│  │                                                  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  │ .rsrc    │  │ .reloc   │  │ (others) │        │
│  │  └──────────┘  └──────────┘  └──────────┘        │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

The `.text` section concentrates most of what interests the reverser: the CLR Header, the CIL bytecode of methods, and the metadata block. Let's examine each component.

## The DOS Header and PE Header: the outer envelope

These two headers are identical to those of a native Windows executable. They contain nothing specific to .NET, but their presence is mandatory because the PE format requires it.

**The DOS Header** occupies the first 64 bytes of the file. It contains the `MZ` magic (bytes `4D 5A`) at offset 0, and the `e_lfanew` field at offset `0x3C` pointing to the PE Header. Between them, a DOS Stub displays the classic "This program cannot be run in DOS mode" message if someone tried to run the file under DOS. In .NET RE, this header has no analytical value — you pass through it to reach the PE Header.

**The PE Header** begins with the signature `PE\0\0` (bytes `50 45 00 00`), followed by the COFF Header (20 bytes) and the Optional Header. Two key pieces of information for the .NET reverser are found in the Optional Header:

- The **Data Directory** at index 14 (CLI Header, also called "COM Descriptor"): it gives the RVA (Relative Virtual Address) and size of the CLR Header. This is the entry point into the .NET world within the PE. If this Data Directory is empty or absent, the PE file is not a .NET assembly — it's a native executable.  
- The **Entry Point** in the Optional Header: for a standard .NET assembly, it points to a tiny stub (`_CorExeMain` or `_CorDllMain`) whose sole role is to hand off to the CLR. This is not the equivalent of your C program's `main()`.

> 💡 **ELF parallel** — The `e_entry` field of the ELF Header (covered in section 2.4) points to the process entry point, typically `_start`, which calls `__libc_start_main` then `main()`. In .NET, the PE Entry Point points to a CLR stub, which initializes the runtime, then invokes your C# program's `Main()` method via the metadata. The mechanics are analogous — a bootstrap before user code — but the level of indirection is higher.

## The CLR Header: gateway to the managed world

The CLR Header (also named CLI Header or COR20 Header) is a 72-byte structure, defined by the ECMA-335 standard. It's the first specifically .NET structure encountered when traversing the file. It contains pointers (RVA + size) to all critical areas of the assembly.

Here are its main fields, with their role for the reverser:

| Field | Size | RE role |  
|-------|--------|-----------------|  
| `cb` | 4 bytes | Structure size (always 72) |  
| `MajorRuntimeVersion` | 2 bytes | Minimum required CLR version |  
| `MinorRuntimeVersion` | 2 bytes | (continued) |  
| `MetaData` (RVA + Size) | 8 bytes | **Points to the metadata block** — the most important field |  
| `Flags` | 4 bytes | Indicators: `ILONLY` (no mixed native code), `32BITREQUIRED`, `STRONGNAMESIGNED`... |  
| `EntryPointToken` | 4 bytes | Metadata token of the `Main()` method (or native module if mixed) |  
| `Resources` (RVA + Size) | 8 bytes | Embedded managed resources |  
| `StrongNameSignature` | 8 bytes | Assembly cryptographic signature |  
| `VTableFixups` | 8 bytes | Vtable fixup table (mixed C++/CLI assemblies) |

The `Flags` field is a quick indicator during triage. The `COMIMAGE_FLAGS_ILONLY` flag (value `0x01`) means the assembly contains only pure CIL, with no embedded native code. If this flag is absent, you're potentially dealing with a **mixed** assembly (C++/CLI) that contains both CIL and x86-64 machine code — a hybrid case where native techniques from Parts I through IV and .NET techniques from Chapter 31 must be combined.

The `EntryPointToken` field is a **metadata token** — a 32-bit integer whose high byte identifies the metadata table (here `0x06` for the `MethodDef` table) and the following three bytes give the index in that table. For example, a token `0x06000001` designates the first method in the `MethodDef` table. By resolving this token, you directly find the program's `Main()` method.

## The metadata block: the assembly's heart

This is where the fundamental difference with a native ELF resides, and it's the reason why .NET RE is structurally richer in information than native RE.

The metadata block begins with a **Metadata Root Header** identifiable by its `BSJB` magic (bytes `42 53 4A 42`) — a historical acronym linked to the initials of the CLR developers. This header indicates the format version and, most importantly, lists the **streams** that compose the metadata.

### The five metadata streams

A standard .NET assembly contains five streams, each storing a different type of data:

**`#~` (or `#-`)** — The **metadata tables** stream. This is the most important structure. It contains a set of relational tables (similar to a database) that describe all types, methods, fields, parameters, attributes, and references of the assembly. The `#~` format is optimized (compressed tables); `#-` is the unoptimized format, less common. We detail the main tables below.

**`#Strings`** — The **identifier string heap**. It contains the names of types, methods, fields, namespaces, parameters — everything that constitutes the API and code structure. These strings are UTF-8 encoded and null-terminated. Tables in the `#~` stream reference strings by their offset in this heap.

> 💡 **ELF parallel** — The `#Strings` heap is the functional equivalent of an ELF's `.strtab` section (string table), which contains symbol names. The crucial difference: in ELF, `.strtab` disappears with `strip -s`; in .NET, `#Strings` is **always present** because it's necessary for CLR operation.

**`#US` (User Strings)** — The **user string heap**. It contains the string literals defined in the C# source code (`"Hello World"`, error messages, configuration keys...). Encoded in UTF-16LE, prefixed by their length, these strings are distinct from the identifiers in the `#Strings` heap. For the reverser, `#US` is a goldmine: it's the equivalent of an ELF's `.rodata` section, but with a direct link to the method that uses each string (via the CIL instruction `ldstr` and its token).

**`#Blob`** — The **binary data heap**. It stores encoded method signatures, default field values, marshalling specs, and other structured binary data. In routine analysis, you rarely consult it directly — decompilation tools decode it automatically.

**`#GUID`** — The **GUID identifier heap**. Each assembly has an MVID (Module Version Identifier), a unique GUID generated at each compilation. This GUID distinguishes two builds of the same source code. For the reverser, the MVID is useful for diffing (Chapter 10): two assemblies with the same MVID come from the exact same compilation.

### The main metadata tables

The `#~` stream organizes its data in **numbered tables** (from `0x00` to `0x2C`). Each table contains **rows** whose columns are indexes into other tables or into the heaps. Here are the most useful tables for the reverser:

| Table | # | Content | Approximate native equivalent |  
|-------|----|---------|-------------------------------|  
| `Module` | `0x00` | Module identity (name, MVID) | ELF filename |  
| `TypeRef` | `0x01` | References to **external** types (other assemblies) | Imported dynamic symbols (`.dynsym`) |  
| `TypeDef` | `0x02` | Definitions of all assembly **types** (classes, structs, enums, interfaces) | No direct equivalent in stripped ELF |  
| `FieldDef` | `0x04` | Fields of each type (class attributes) | Data in `.data` / `.bss` (without names) |  
| `MethodDef` | `0x06` | Definitions of all **methods** (name, signature, CIL body RVA) | Entries in `.symtab` (if not stripped) |  
| `Param` | `0x08` | Parameters of each method (name, position, flags) | DWARF information (if compiled with `-g`) |  
| `MemberRef` | `0x0A` | References to **external** methods/fields | PLT/GOT entries for imported functions |  
| `CustomAttribute` | `0x0C` | .NET attributes applied to types/methods | No equivalent |  
| `Assembly` | `0x20` | Assembly identity (name, version, culture, public key) | `SONAME` field of a `.so` |  
| `AssemblyRef` | `0x23` | References to **dependent** assemblies | `DT_NEEDED` table in ELF |

The `TypeDef` table is the starting point for any structural analysis. Each row describes a type with its name, namespace, visibility flags, and indexes into the `FieldDef` and `MethodDef` tables to list its members. It's thanks to this table that decompilers can instantly reconstruct the class hierarchy — work that, on a native C++ binary, requires manual reconstruction of vtables and RTTI (sections 17.2 and 17.3).

The `MethodDef` table is equally central. For each method, it gives the **RVA** (Relative Virtual Address) of its CIL body in the `.text` section. This RVA points to a **method header** followed by the method's CIL instructions. The method header exists in two variants: a **Tiny** format (1 byte, for small methods with no local variables or exceptions) and a **Fat** format (12 bytes, for methods with local variables, try/catch, or stack size greater than 8).

## The .text section: where the code lives

In a native ELF, the `.text` section contains executable machine code — x86-64 instructions you disassemble with `objdump` or Ghidra. In a .NET assembly, the `.text` section contains a mixture of:

- The **CLR Header** (72 bytes).  
- The **CIL method bodies**, each preceded by its method header (Tiny or Fat).  
- The complete **metadata block** (root header + streams).  
- Optionally, **managed resources** and the **strong name signature**.

The important point is that CIL bytecode is not organized as a single contiguous zone like a native ELF's `.text` would be. Method bodies are scattered throughout the section, and it's the `MethodDef` table in the metadata that locates them one by one via their RVAs. Without the metadata, CIL bytecode is a structureless byte stream — the metadata is the map that gives meaning to the territory.

## The other sections

Beyond `.text`, a .NET assembly typically contains a few additional sections:

**`.rsrc`** — **Win32 resources** (icons, manifests, version information). This section has nothing specific to .NET; it also exists in native PEs. Not to be confused with .NET managed resources (stored in `.text` and pointed to by the CLR Header).

**`.reloc`** — **Relocations** needed to load the PE at a base address different from the intended one. On a pure .NET assembly (flag `ILONLY`), this section is minimal because CIL is address-independent — only the native entry stub requires relocations.

Some assemblies may contain an **`.sdata`** or **`.data`** section if the code uses initialized global variables or mixed native code (C++/CLI). This is rare in a pure C# assembly.

> 💡 **ELF parallel** — By comparison, a typical ELF binary contains many more exploitable sections: `.text` (code), `.rodata` (constants), `.data` (initialized globals), `.bss` (uninitialized globals), `.plt`/`.got` (dynamic resolution), `.init`/`.fini` (constructors/destructors), `.eh_frame` (exceptions). The relative simplicity of a .NET PE's sectional structure reflects the fact that complexity is offloaded to the metadata rather than to the memory organization.

## The manifest: the assembly's identity

Every .NET assembly contains a **manifest** — a subset of the metadata that describes the assembly's public identity: its name, version (format `Major.Minor.Build.Revision`), culture (language), and optionally its strong name signing public key.

The manifest also lists the **references to other assemblies** (`AssemblyRef` table) that the code depends on. This is the functional equivalent of the `ldd` command on an ELF (section 5.4): it tells you what external libraries are needed for execution.

```
$ monodis --assemblyref MyApp.dll
AssemblyRef Table
  1: Version=8.0.0.0  Name=System.Runtime
  2: Version=8.0.0.0  Name=System.Console
  3: Version=8.0.0.0  Name=System.Collections
```

Compare with the `ldd` output on a native binary:

```
$ ldd my_app
    linux-vdso.so.1
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
    /lib64/ld-linux-x86-64.so.2
```

The same information — what external dependencies are required — is expressed in both worlds, but with different granularity. .NET dependencies are named and versioned assemblies; ELF dependencies are `.so` files resolved by the dynamic loader `ld.so` (section 2.7).

## Summary: reading a .NET assembly like you read an ELF

To anchor these concepts, here is the correspondence between the ELF triage steps (Chapter 5 workflow) and their .NET equivalents:

| ELF triage step | Command | .NET equivalent | Command / tool |  
|---------------------|----------|-----------------|------------------|  
| Identify file type | `file binary` | Identify a .NET assembly | `file MyApp.dll` → look for `Mono/.Net assembly` |  
| List sections | `readelf -S binary` | List PE sections | `objdump -h MyApp.dll` or ImHex |  
| Extract strings | `strings binary` | Extract strings | `strings MyApp.dll` (captures `#Strings` and `#US`) |  
| List symbols | `nm binary` | List types and methods | `monodis --typedef MyApp.dll` |  
| List dependencies | `ldd binary` | List assembly references | `monodis --assemblyref MyApp.dll` |  
| Inspect headers | `readelf -h binary` | Inspect CLR Header | ImHex with a `.hexpat` pattern or `monodis` |  
| Disassemble | `objdump -d binary` | Disassemble CIL | `monodis MyApp.dll` or `ildasm` |

This correspondence isn't perfect — the abstractions differ — but it gives you an immediate working framework by reusing the reflexes acquired in previous parts.

---

> 📖 **Key takeaway** — A .NET assembly is a PE file whose `.text` section embeds both CIL bytecode and a richly structured metadata block (tables + heaps). It's the metadata — not the bytecode — that makes the format distinctive: it carries the program's entire logical structure (types, methods, hierarchy, signatures, strings), making decompilation nearly transparent in the absence of obfuscation. The `BSJB` magic in the metadata block and Data Directory 14 in the PE Optional Header are the two markers that confirm a file's .NET nature.

---


⏭️ [Common obfuscators: ConfuserEx, Dotfuscator, SmartAssembly](/30-introduction-re-dotnet/03-common-obfuscators.md)
