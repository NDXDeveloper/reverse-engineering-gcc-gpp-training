🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 30.4 — Inspecting an Assembly with `file`, `strings` and ImHex (PE/.NET Headers)

> 📚 **Section objective** — Apply the Chapter 5 quick triage workflow to a .NET assembly, reusing tools you already know (`file`, `strings`, `xxd`, ImHex) and complementing them with a few .NET-specific commands.

---

## The triage reflex: the same first 5 minutes

Section 5.7 introduced a "quick triage" workflow: a systematic routine to apply within the first five minutes when facing an unknown binary. The goal is to answer fundamental questions — what file type, what architecture, what dependencies, what interesting strings, what protections — before engaging in deeper analysis.

This workflow remains valid on a .NET assembly. The tools are the same; what changes is the interpretation of results. Let's walk through each step on a fictitious assembly `CrackMe.exe` compiled in C# with `dotnet build`.

## Step 1 — `file`: identify the binary's nature

```
$ file CrackMe.exe
CrackMe.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Three crucial pieces of information in this output:

**`PE32 executable`** — The file is in PE (Portable Executable) format. It's not an ELF. If you're on Linux and used to seeing `ELF 64-bit LSB executable`, this output immediately confirms you're not facing a standard native Linux binary.

**`Intel 80386`** — Don't be misled by this mention. It indicates the architecture declared in the PE Header, not the actual execution architecture. "Any CPU" .NET assemblies (the default mode) often declare `Intel 80386` (PE32) or `x86-64` (PE32+) in their header, but the CIL bytecode they contain is architecture-independent. It's the CLR's JIT that produces machine code adapted to the target platform at runtime.

**`Mono/.Net assembly`** — This is the decisive marker. `file` detected the presence of the CLR Header (Data Directory index 14 in the PE Optional Header). This binary contains CIL bytecode and .NET metadata. From this point, you know that native analysis tools (`objdump -d`, Ghidra in x86 mode) won't be relevant — you need to switch to .NET tools (ILSpy, dnSpy, `monodis`).

> ⚠️ **Special case — the .NET 6+ host executable**: modern .NET projects (`dotnet publish`) sometimes produce a native Linux executable (ELF) that serves as a launcher for the runtime. In this case, `file` shows `ELF 64-bit LSB executable` — with no mention of .NET. The actual assembly is in an adjacent `.dll` file (e.g., `CrackMe.dll`). If you find an ELF accompanied by a same-named `.dll` and a `.runtimeconfig.json` file, that's a strong clue you're facing a .NET application with a native host. Triage should then target the `.dll`, not the ELF.

```
$ ls -la
-rwxr-xr-x  1 user user  143360  CrackMe          ← Native host (ELF)
-rw-r--r--  1 user user    8704  CrackMe.dll       ← .NET Assembly (CIL)
-rw-r--r--  1 user user     253  CrackMe.runtimeconfig.json
-rw-r--r--  1 user user  143808  CrackMe.deps.json

$ file CrackMe
CrackMe: ELF 64-bit LSB pie executable, x86-64, ...

$ file CrackMe.dll
CrackMe.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

## Step 2 — `strings`: extract readable strings

```
$ strings CrackMe.exe
```

On a non-obfuscated .NET assembly, `strings` produces considerably richer output than on a stripped native binary. Here are the categories of strings you'll encounter, in their typical order of appearance in the file:

**DOS Stub strings** — The classic `This program cannot be run in DOS mode` appears at the beginning of the file. Ignore it.

**Type and method names** — Come from the metadata `#Strings` heap (section 30.2). These are the program's identifiers: class names, method names, field names, namespaces, parameters.

```
CrackMe  
Program  
Main  
LicenseChecker  
ValidateKey  
_secretSalt
System.Runtime  
System.Console  
WriteLine  
ReadLine  
```

On a stripped native binary, this information would have been lost. Here, it immediately gives you an overview of the program's architecture: a `Program` class with a `Main`, a `LicenseChecker` class with a `ValidateKey` method and a `_secretSalt` field. In seconds, you have a working hypothesis about the crackme's logic.

**User strings** — Come from the `#US` (User Strings) heap. These are the source code's string literals: displayed messages, keys, URLs, formats.

```
Enter your license key:  
Invalid key. Try again.  
License activated successfully!  
SHA256  
HMAC  
```

These strings explicitly reveal the program's behavior. The presence of `SHA256` and `HMAC` indicates the use of cryptographic functions in the license verification — information that would take hours to extract from an optimized native binary.

**Referenced assembly names** — Dependency names appear in plaintext.

```
System.Runtime  
System.Console  
System.Security.Cryptography  
```

The presence of `System.Security.Cryptography` confirms the crypto hypothesis.

**Potential obfuscation markers** — This is the time to apply step 1 of the identification strategy from section 30.3.

```
$ strings CrackMe.exe | grep -iE "confuser|dotfuscator|smartassembly|preemptive|reactor"
```

An empty output suggests a non-obfuscated assembly (or an obfuscator that doesn't leave textual markers).

> 💡 **Tip** — On a .NET assembly, remember to use `strings` with the `-e l` option (little-endian 16-bit) to capture UTF-16LE encoded strings from the `#US` heap, which `strings` in default mode (ASCII/UTF-8) might miss:  
>  
> ```  
> $ strings -e l CrackMe.exe  
> Enter your license key:  
> Invalid key. Try again.  
> License activated successfully!  
> ```

> 💡 **ELF parallel** — On a native binary, `strings` essentially captures the contents of `.rodata` and symbol names (if not stripped). On a .NET assembly, the output is systematically denser because metadata cannot be stripped — they're an integral part of the format.

## Step 3 — `xxd` / `hexdump`: verify magic bytes

A quick look at the first bytes confirms the format:

```
$ xxd CrackMe.exe | head -4
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 8000 0000  ................
```

The `MZ` magic (`4D 5A`) at offset `0x00` confirms a PE. Offset `0x3C` (here the value `0x80`) points to the PE Header:

```
$ xxd -s 0x80 -l 4 CrackMe.exe
00000080: 5045 0000                                PE..
```

The `PE\0\0` signature (`50 45 00 00`) is present. To confirm this is indeed a .NET assembly and not a native PE, you need to check the Data Directory at index 14 (CLI Header). Its offset in the file depends on the Optional Header size, but the principle is simple: if this Data Directory contains a non-zero RVA, the file has a CLR Header.

This is where ImHex becomes more comfortable than `xxd` for manual exploration.

## Step 4 — ImHex: structured header exploration

ImHex (Chapter 6) is the ideal tool for visually exploring a .NET assembly's structure. Load the file and use the following features:

### Manual navigation with the Data Inspector

Place the cursor at offset `0x00` and observe ImHex's Data Inspector interpreting the first bytes as a DOS Header. Navigate to the PE Header (offset indicated by `e_lfanew` at `0x3C`), then browse through the COFF Header and Optional Header.

In the Optional Header, locate the **Data Directories table**. The 15th entry (index 14, "CLI Header") is the one we're interested in. If it contains a non-zero RVA and size, you have definitive confirmation that the file is a .NET assembly — and the RVA tells you where to find the CLR Header in the file.

### Locating the BSJB magic

The metadata block is identifiable by its `BSJB` magic (`42 53 4A 42`). Use ImHex's hex search function (Ctrl+F → Hex tab) to find this sequence:

```
Search:  42 53 4A 42  
Result:  found at offset 0x0268 (example)  
```

From this magic, you're at the beginning of the Metadata Root Header. The following bytes give the metadata format version (typically `v4.0.30319` for .NET Framework assemblies, or `v5.0`, `v6.0`, `v8.0` for modern .NET):

```
Offset 0x0268: 42 53 4A 42    ← Magic "BSJB"  
Offset 0x026C: 01 00 01 00    ← Major/minor version  
Offset 0x0270: 00 00 00 00    ← Reserved  
Offset 0x0274: 0C 00 00 00    ← Version string length (12)  
Offset 0x0278: 76 34 2E 30 2E 33 30 33 31 39 00 00  ← "v4.0.30319\0\0"  
```

This version string gives you an indication of the targeted framework. After the version string, the header lists the streams (count, relative offset, size, name) — which lets you precisely locate each heap (`#~`, `#Strings`, `#US`, `#Blob`, `#GUID`) in the file.

### Writing a `.hexpat` pattern for the CLR Header

If you want to go further with ImHex, you can write a `.hexpat` pattern that automatically parses the CLR Header. Here is a minimal pattern covering the main fields:

```c
// ImHex pattern for the CLR Header (.NET COR20)
// Position the cursor at the CLR Header start before executing

struct CLR_Header {
    u32 cb;                    // Structure size (72)
    u16 majorRuntimeVersion;
    u16 minorRuntimeVersion;
    u32 metadataRVA;
    u32 metadataSize;
    u32 flags;                 // 0x01 = ILONLY, 0x02 = 32BITREQUIRED, ...
    u32 entryPointToken;       // MethodDef token for Main()
    u32 resourcesRVA;
    u32 resourcesSize;
    u32 strongNameRVA;
    u32 strongNameSize;
    u32 codeManagerTableRVA;
    u32 codeManagerTableSize;
    u32 vTableFixupsRVA;
    u32 vTableFixupsSize;
    u32 exportAddressTableRVA;
    u32 exportAddressTableSize;
    u32 managedNativeHeaderRVA;
    u32 managedNativeHeaderSize;
};

CLR_Header clr_header @ 0x0208;  // ← Adjust this offset for your binary
```

Once the pattern is applied, ImHex displays each field with its name, value, and position — you can immediately read the `flags` to check `ILONLY`, the `entryPointToken` to identify `Main()`, and the metadata and resources RVAs.

> 💡 **Reminder** — Section 6.4 showed how to write a `.hexpat` pattern for an ELF header. The approach is identical here: define a C-like `struct` that reflects the binary layout, then anchor it at the correct offset in the file. RVA → file offset conversion requires consulting the PE section table to find the mapping — a step that .NET decompilers do automatically, but that's useful to know how to do manually for atypical cases.

### Visualizing entropy

ImHex's entropy view (menu Analysis → Entropy) gives a quick overview of encrypted or compressed zones. On a non-obfuscated .NET assembly, entropy is relatively homogeneous and moderate (between 4 and 6 bits/byte). If you observe high-entropy blocks (close to 8 bits/byte), it's a sign of:

- String encryption (section 30.3) — localized block in the resources or metadata area.  
- CIL method packing — block covering a large part of the `.text` section.  
- Encrypted or compressed resources — block in the area pointed to by the CLR Header's `Resources` field.

Mentally compare with the entropy profile of a UPX-packed native binary (section 29.1): the signature is similar — high-entropy zones indicate transformed content.

## Step 5 — .NET-specific tools: `monodis` and `dotnet`

Once the .NET nature is confirmed by the previous steps, specific tools complete the triage.

### `monodis` — the "objdump" of the .NET world

`monodis` (provided with Mono) is the functional equivalent of `objdump` for .NET assemblies. It disassembles CIL and allows inspecting metadata.

**List defined types:**

```
$ monodis --typedef CrackMe.exe
Typedef Table
  1: (TypeDef) CrackMe.Program (Flags: 00100000)
  2: (TypeDef) CrackMe.LicenseChecker (Flags: 00100000)
```

**List methods:**

```
$ monodis --method CrackMe.exe
Method Table
  1: void CrackMe.Program::Main(string[])  (param: 1, flags: 00000096, implflags: 0000)
  2: void CrackMe.Program::.ctor()  (param: 0, flags: 00001886, implflags: 0000)
  3: bool CrackMe.LicenseChecker::ValidateKey(string)  (param: 1, flags: 00000086, implflags: 0000)
  4: void CrackMe.LicenseChecker::.ctor()  (param: 0, flags: 00001886, implflags: 0000)
```

**List referenced assemblies:**

```
$ monodis --assemblyref CrackMe.exe
AssemblyRef Table
  1: Version=8.0.0.0  Name=System.Runtime
  2: Version=8.0.0.0  Name=System.Console
  3: Version=8.0.0.0  Name=System.Security.Cryptography
```

**Disassemble the complete CIL:**

```
$ monodis CrackMe.exe > CrackMe.il
```

The resulting `.il` file contains the CIL disassembly of the entire assembly, in a readable text format. It's the equivalent of `objdump -d` on an ELF — useful for a quick inspection, but a decompiler (ILSpy, dnSpy) is preferable for in-depth analysis.

### `dotnet` CLI — runtime information

If the .NET SDK is installed, the `dotnet` command can provide additional information:

```
$ dotnet --list-runtimes
Microsoft.NETCore.App 8.0.4 [/usr/share/dotnet/shared/Microsoft.NETCore.App]
```

This tells you which runtimes are available on the machine, which is useful for knowing whether you can execute the target assembly (dynamic analysis, Chapter 32).

## .NET triage workflow summary

Here is the complete sequence, condensed into a cheat sheet:

```
1.  file target.exe / target.dll
    → Confirm "Mono/.Net assembly"
    → If ELF: look for an adjacent .dll + .runtimeconfig.json

2.  strings target.dll
    strings -e l target.dll
    → Class/method names (#Strings heap)
    → User strings (#US heap)
    → Obfuscation markers (grep confuser|dotfuscator|smart...)

3.  xxd target.dll | head
    → Confirm magic MZ (4D 5A) + PE (50 45 00 00)
    → Search for BSJB magic (42 53 4A 42) for metadata

4.  ImHex
    → Data Inspector on PE headers + CLR Header
    → Search for BSJB magic, read metadata version
    → .hexpat pattern on CLR Header (flags, entryPointToken)
    → Entropy view: detect encryption/packing

5.  monodis --typedef --method --assemblyref target.dll
    → Inventory of types, methods, dependencies
    → CIL disassembly if needed (monodis target.dll)

6.  [Optional] de4dot --detect target.dll
    → Automatic obfuscator identification
```

At the end of these steps — which take less than five minutes — you have a complete profile of the assembly: its target framework, its types and methods, its dependencies, the presence or absence of obfuscation, and a first idea of its internal logic. You're ready to move on to decompilation (Chapter 31) or dynamic analysis (Chapter 32) with full knowledge of the situation.

---

> 📖 **Key takeaway** — Triaging a .NET assembly follows the same logic as triaging a native ELF binary: identify the format, extract strings, inspect headers, assess protections. The basic tools (`file`, `strings`, `xxd`, ImHex) work directly; `monodis` and `de4dot` complement them for CLR-specific aspects. The key point is the initial detection with `file`: the `Mono/.Net assembly` mention (or the presence of a `.dll` with `.runtimeconfig.json` for modern .NET deployments) immediately directs you toward the .NET toolkit.

---


⏭️ [NativeAOT and ReadyToRun: when C# becomes native code](/30-introduction-re-dotnet/05-nativeaot-readytorun.md)
