🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Patch and Keygen the Provided .NET Application

> 📁 **Target**: `binaries/ch32-dotnet/` (`LicenseChecker` application + `libnative_check.so` library)  
> 📖 **Sections covered**: [32.1](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md) through [32.5](/32-dynamic-analysis-dotnet/05-practical-license-csharp.md)  
> 📝 **Solution**: [`solutions/ch32-checkpoint-solution.md`](/solutions/ch32-checkpoint-solution.md)

---

## Context

This checkpoint validates the skills acquired throughout chapter 32. You will work on the `LicenseChecker` application — a .NET assembly accompanied by a native library compiled with GCC — and produce three deliverables that cover all the techniques seen: debugging without sources, CLR and native hooking, P/Invoke interception, and IL patching.

You have only the compiled files present in `binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64/`. You must not consult the source files (`.cs`, `.c`) during the checkpoint — they will only be used to verify your results afterward.

---

## Deliverable 1 — Frida capture script

Write a single Frida script (`capture.js`) that, when attached to the `LicenseChecker` process, simultaneously intercepts the managed methods and native functions involved in validation, and displays the following information in the console for each validation attempt:

- The username and key provided as input.  
- The expected value of each segment (A, B, C, D) as computed by the application.  
- The identification of the source of each value: computed on the CLR side or the native side.  
- The complete valid key, reconstructed from the four captured segments.

The script must handle the lazy loading of `libnative_check.so` (the library is not loaded at process startup) and must work in both `spawn` mode and `attach` mode.

**Validation criteria**: launch `LicenseChecker` with the script active, enter any username with a dummy key, and verify that the key displayed by the script is accepted during a subsequent execution without Frida.

---

## Deliverable 2 — Standalone Python keygen

Write a Python script (`keygen.py`) that takes a username as an argument and produces a valid license key, without resorting to any external tool (no Frida, no dnSpy, no the application itself).

The script must fully reimplement the validation scheme — all four segments — based on your static analysis (dnSpy for the managed side, Ghidra/objdump for the native side). Pay particular attention to the following points:

- The salts used on the C# side and the native side are not identical. Your keygen must use the correct salts for the correct segments.  
- Arithmetic operations are masked to 16 bits at each step. A missed mask produces incorrect results for certain usernames.  
- The conversion of the username to lowercase precedes the hash computation on both sides.

**Validation criteria**: the keygen must produce a key accepted by the original (unpatched) application for at least five different usernames of your choice, including a username containing non-ASCII characters (for example `café`, `müller`, or `naïve`).

---

## Deliverable 3 — Patched assembly

Produce a modified version of `LicenseChecker.dll` that accepts any license key for any username, without requiring Frida, without requiring `libnative_check.so`, and without displaying an error message.

Two variants are expected:

**Variant A — C# patch.** Rewrite the body of the `Validate()` method in C# via dnSpy's editor so that it always returns a positive result. Save as `LicenseChecker_patch_csharp.dll`.

**Variant B — Minimal IL patch.** Without rewriting the entire method, modify only the IL instructions necessary to neutralize the four segment comparisons. The computation logic (hash, XOR, checksums) must remain intact and execute normally — only the comparison results are ignored. Save as `LicenseChecker_patch_il.dll`.

**Validation criteria**: each variant must be accepted by the .NET runtime without `InvalidProgramException`, must display "Licence valide" for any username/key combination, and must work even if `libnative_check.so` is absent from the directory (for variant A; variant B may fail on segments B/D if the library is absent, which is acceptable as long as the final result is "Licence valide").

---

## Accompanying report

Each deliverable must be accompanied by brief documentation (a few paragraphs in a `rapport.md` file) describing:

- The approach followed for each deliverable: which tools, in what order, what discoveries at each step.  
- The reconstructed validation scheme, including the role of each segment and the key constants (salts, seeds, primes, multiplicative constants).  
- For the IL patch (variant B): the list of modified instructions, with their offset, the original opcode and the replacement opcode, and the justification for each change (particularly the IL stack management).  
- The difficulties encountered and how they were resolved.

---

## Self-assessment rubric

| Criterion | Achieved | Points |  
|---|---|---|  
| The Frida script captures all 4 segments and displays the valid key | ☐ | /20 |  
| The Frida script handles lazy loading of the native library | ☐ | /5 |  
| The Python keygen produces valid keys for 5+ usernames | ☐ | /20 |  
| The keygen correctly handles non-ASCII usernames | ☐ | /5 |  
| The C# patch (variant A) works without the native library | ☐ | /10 |  
| The IL patch (variant B) neutralizes all 4 checks without breaking the IL stack | ☐ | /15 |  
| The IL patch preserves the computation logic intact (only branches are modified) | ☐ | /10 |  
| The report documents the validation scheme with both salts | ☐ | /10 |  
| The report lists the modified IL instructions with justification | ☐ | /5 |  
| **Total** | | **/100** |

---

## Tips before getting started

**Start with reconnaissance.** Open the assembly in dnSpy and take the time to read the decompiled code in its entirety before launching any dynamic tool. The structure of `LicenseValidator` is linear and the method names are descriptive — static reading will give you a mental map of the flow that will guide everything that follows.

**Validate each segment independently.** Before writing the complete keygen, verify each segment separately. Use dnSpy's Immediate window to call `ComputeUserHash("test")` and compare with your Python implementation. Fix any discrepancies before moving on to the next segment.

**Back up the original assembly.** Before any patching, make a copy of `LicenseChecker.dll`. An incorrect IL patch can make the assembly non-executable, and it is faster to start over from the original than to attempt to repair a broken patch.

**Work iteratively on the IL patch.** Patch one check at a time, save, test, then move on to the next. If an `InvalidProgramException` appears, you will immediately know which patch caused it.

---


⏭️ [Part VIII — Bonus: RE of Rust and Go Binaries](/part-8-rust-go.md)
