🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 32.4 — Patching a .NET Assembly on the Fly (Modifying IL with dnSpy)

> 📁 **Files used**: `binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64/LicenseChecker.dll`  
> 🔧 **Tools**: dnSpy (dnSpyEx), ILSpy (verification)  
> 📖 **Prerequisites**: [Section 32.1](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md), CIL bytecode fundamentals ([Chapter 30](/30-introduction-re-dotnet/README.md))

---

## From temporary patches to permanent patches

The previous sections presented runtime intervention techniques: modifying a variable in the debugger (§32.1), replacing a method implementation with Frida (§32.2), intercepting a P/Invoke call to alter its return value (§32.3). All of these interventions are ephemeral — they only affect the running instance of the program and disappear as soon as it is relaunched.

IL patching is fundamentally different. It modifies the assembly file on disk. The result is a permanently altered version of the program that behaves differently on every future execution without requiring any external tools. It is the .NET equivalent of the binary patching seen in chapter 21 (where we flipped a `jz` to `jnz` in an ELF with ImHex), but with an incomparably higher level of comfort.

In the native world, patching an x86-64 binary requires manipulating raw opcodes, respecting alignment constraints, ensuring the replacement instruction is exactly the same size (or padding with `nop`), and handling any relocations. In the .NET world, dnSpy offers three editing levels: direct C# rewriting (dnSpy recompiles to IL for you), individual IL instruction editing (the equivalent of opcode-by-opcode patching), and metadata editing (renaming a type, changing a visibility modifier, modifying an attribute). Each of these levels has its uses and limitations.

## CIL bytecode: essential refresher

Before patching, we need to understand what we are modifying. The Common Intermediate Language (CIL, formerly MSIL) is the bytecode into which the C# compiler translates source code. It is a stack-based language — operands are pushed onto the stack, operations consume the top of the stack and push their result. A few key instructions for patching:

| IL Instruction | Effect | Conceptual x86 equivalent |  
|---|---|---|  
| `ldc.i4.0` | Pushes integer 0 | `mov eax, 0` |  
| `ldc.i4.1` | Pushes integer 1 | `mov eax, 1` |  
| `ldarg.0` | Pushes the first argument (or `this`) | Read from argument register |  
| `ldloc.0` | Pushes local variable 0 | Read from stack |  
| `stloc.0` | Pops to local variable 0 | Write to stack |  
| `call` | Calls a method | `call <address>` |  
| `callvirt` | Virtual call (via vtable) | `call [vtable+offset]` |  
| `ret` | Returns (the value at the top of the stack) | `ret` |  
| `br` | Unconditional branch | `jmp` |  
| `brfalse` / `brtrue` | Conditional branch if 0 / non-0 | `jz` / `jnz` |  
| `ceq` | Compares the two values on top, pushes 1 if equal | `cmp` + `sete` |  
| `nop` | Does nothing | `nop` |  
| `pop` | Pops and discards the value on top | — |

Unlike x86 where instructions have variable sizes (1 to 15 bytes), IL instructions have much more predictable sizes: one byte for the basic opcode, one or two bytes for extended opcodes (prefixed with `0xFE`), plus any operands. This regularity makes IL patching significantly less risky than x86 patching.

Another crucial point: CIL is verified by the runtime. Before executing a method, the JIT verifies that the IL stack is consistent at every instruction — every execution path must leave the stack in a correct state. A poorly constructed IL patch (for example, a stack overflow or an empty stack at a `ret` that expects a value) will be rejected by the verifier with an `InvalidProgramException`. This is a constraint absent from the native world, where an invalid opcode simply produces a crash.

## C# editing: the most comfortable mode

dnSpy allows editing the body of a method directly in C#. The workflow is remarkably simple: right-click on the method in the decompiled code, choose **Edit Method (C#)**, a code editor opens with the decompiled C#, make the desired changes, and click **Compile**. dnSpy recompiles the C# to IL and replaces the method body in the assembly.

### Bypass by rewriting `Validate()`

The most direct approach to neutralize the license check is to entirely rewrite the `Validate()` method:

Navigate to `LicenseValidator.Validate()` in dnSpy. Right-click → **Edit Method (C#)**. The editor opens with the decompiled code. Replace the entire body with:

```csharp
public ValidationResult Validate(string username, string licenseKey)
{
    return new ValidationResult
    {
        IsValid        = true,
        FailureReason  = "",
        LicenseLevel   = "Enterprise",
        ExpirationInfo = "Perpetual"
    };
}
```

Click **Compile**. If compilation succeeds (no errors in the bottom panel), the method is replaced. The decompiled code in the main panel now reflects the new version. All the validation logic — FNV-1a hash, P/Invoke calls, cross XOR, checksum — is gone. The method always returns `true`, regardless of the input.

> ⚠️ **Caution**: the modification has not yet been saved to disk. It exists only in dnSpy's memory. To persist the patch, use **File → Save Module** (or Ctrl+Shift+S). dnSpy then writes the modified version of the assembly to disk. You can save over the original or under a new name — the second option is preferable so you can compare and revert.

### Limitations of C# editing

C# editing is powerful but not always applicable. dnSpy uses its own internal C# compiler, which does not always support every syntactic construct from the version of C# used by the original project. If the decompiled code contains patterns that the internal compiler cannot handle — certain forms of pattern matching, C# 12+ features, `ref struct` types — compilation will fail.

In that case, two fallbacks are available: simplify the C# code to work around the internal compiler's limitations, or drop down to the IL level.

Additionally, C# editing recompiles the entire method. If you only want to modify a single instruction (for example, flip a conditional branch), this approach is somewhat disproportionate. Direct IL editing is more appropriate in that case.

## IL instruction editing: the surgical patch

For targeted modifications, dnSpy offers an IL instruction editor. Access it via right-click on the method → **Edit IL Instructions**. A window opens with the sequential list of the method's IL instructions, each with its offset, opcode, and operands.

### Flipping a conditional branch

Let us take a concrete case. In the `Validate()` method, after the segment A computation, the IL code contains a sequence like this:

```
IL_0040: ldloc.s  actualA         // push actualA  
IL_0042: ldloc.s  expectedA       // push expectedA  
IL_0044: beq      IL_0060         // if equal, jump to next step  
IL_0049: ldloc.0                  // otherwise: load result  
IL_004A: ldc.i4.0                 //         push false  
IL_004B: callvirt set_IsValid     //         result.IsValid = false  
...                                //         (assign FailureReason)
IL_005E: ldloc.0                  //         load result  
IL_005F: ret                      //         return (failure)  
IL_0060: ...                      // continuation of validation  
```

The `beq IL_0060` (branch if equal) instruction is the decision point. If `actualA == expectedA`, we jump to the next step; otherwise, we fall into the failure block. To bypass this check, we have several options.

**Option 1: transform `beq` into `br`.** Replace the conditional branch with an unconditional branch. Regardless of the comparison, execution always jumps to `IL_0060`. In dnSpy's IL editor, select the `beq` instruction, change the opcode to `br` (branch unconditional), and keep the same branch target. The segment A check is neutralized.

**Option 2: replace the block with `nop`.** Select all the instructions in the failure block (from `IL_0049` to `IL_005F`) and replace them with `nop`. Caution: the IL stack must also be managed. If `beq` consumes two values but the replacement code does not, the IL verifier will reject the result. The solution is to replace `beq IL_0060` with `pop` + `pop` + `br IL_0060` — pop the two values that were intended for the comparison, then branch unconditionally.

**Option 3: force the comparison result.** Just before the `beq`, insert instructions that replace the values on top of the stack with two identical values. For example, replace `ldloc.s actualA` with `ldloc.s expectedA` — the two pushed values are then identical, and the `beq` is always taken. This approach has the advantage of not modifying the control flow structure.

### Applying the patch to each validation step

The `Validate()` method contains four comparison points (segments A, B, C, D), each followed by a failure block that assigns `IsValid = false` and returns. To bypass all validation, you must patch all four conditional branches.

In practice, identify each `beq` (or `bne.un`, depending on compiler optimization — `bne.un` means "branch if not equal, unsigned") and transform it into a `br` to the continuation of the normal flow, or into `nop` with stack management.

> 💡 **Tip**: in dnSpy's IL editor, branch targets are displayed as clickable references. Hovering over a `beq IL_0060` immediately shows where the branch leads. This is the equivalent of cross-references (XREF) in Ghidra, but at the IL level.

### IL stack pitfalls

The main trap in IL patching is stack consistency. Every execution path in a method must end with the stack in an expected state. Here are the most common mistakes and how to avoid them.

**Orphaned value on the stack.** If you remove an instruction that consumed a value (for example, a `call` that took an argument), the value remains on the stack and the verifier detects it. Solution: add a `pop` to consume it.

**Empty stack at `ret` time.** If the method has a return type (for example, `ValidationResult`), the `ret` expects a value on top of the stack. If you removed instructions that produced this value, you need to add one. For a reference type, `ldnull` pushes a null reference; for a boolean, `ldc.i4.1` pushes `true`.

**Inconsistent stack depth between branches.** If two branches converge at the same point but leave the stack at different depths, the verifier rejects the code. This is the trickiest case to handle manually. C# editing avoids this problem because the internal compiler manages the stack automatically.

dnSpy displays an error in the IL editor if the stack is inconsistent, with a message indicating the problematic instruction. This is immediate feedback that allows you to correct before saving.

## Metadata editing

Beyond IL code, dnSpy allows modifying the assembly's metadata: type names, visibilities, attributes, method signatures, constant values. This capability opens additional patching possibilities.

### Changing a method's visibility

In our `LicenseChecker`, the `NativeBridge` class is marked `internal` — it is not accessible from an external assembly. If we wanted to write a C# program that calls `NativeBridge.ComputeNativeHash()` directly, we could not without modifying this visibility.

In dnSpy: right-click on the `NativeBridge` class → **Edit Type**. Change the access modifier from `internal` to `public`. Similarly, you can change the visibility of private methods (`ComputeUserHash`, `ComputeCrossXor`, etc.) to `public`. After saving, these methods are callable from any external code — which facilitates writing a C# keygen that directly reuses the original program's functions.

### Modifying a constant

`const` and `static readonly` fields appear in the metadata. You can edit them in dnSpy via right-click → **Edit Field**. For example, you could modify the value of `HashSeed` or the content of `MagicSalt` to alter the behavior of the hash algorithms without touching the IL code.

### Removing an attribute

If the assembly uses an `[Obfuscation]` attribute or an integrity verification mechanism based on a custom attribute, you can simply remove the attribute in the metadata editor. dnSpy allows this via editing the type or method carrying the attribute.

## Saving and verifying the patch

Once the modifications are made, save the assembly via **File → Save Module** (Ctrl+Shift+S). dnSpy offers several options:

**Save Module.** Writes the modified file. You can choose an output path different from the original (recommended).

**Save All.** If you modified multiple assemblies in the same session, this option saves all of them.

After saving, it is essential to **verify** that the patch works correctly.

First verification: launch the patched application and test with an arbitrary username and key. If the bypass is correct, validation succeeds.

Second verification: reopen the patched assembly in dnSpy (or in ILSpy, for a second opinion) and inspect the modified methods. The decompiled code should reflect the expected changes.

Third verification: ensure that the application works normally outside the patched path. An overly aggressive patch (for example, an inconsistent IL stack in a rarely taken path) can cause crashes in unexpected situations.

```bash
# Test the patch
cd binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64

# Back up the original
cp LicenseChecker.dll LicenseChecker.dll.bak

# Copy the patched version (if saved under a different name)
cp LicenseChecker_patched.dll LicenseChecker.dll

# Launch and test
LD_LIBRARY_PATH=. ./LicenseChecker
# Enter any username and a dummy key
# → Should display "License valid!"
```

## Protection against patching: strong name signatures

In the .NET world, an assembly can be signed with a strong cryptographic key (strong name). The signature covers the entirety of the assembly's content — if a single byte is modified, the signature becomes invalid. The CLR verifies this signature at load time and refuses assemblies with a corrupted signature.

Our `LicenseChecker` is not signed (to simplify the exercise). But in real-world situations, signed assemblies are frequently encountered. dnSpy handles this: when saving a modified assembly, it offers the **Remove Strong Name Signature** option. If you check this option, the signature is removed from the patched assembly.

Removing the signature causes a cascading problem: other assemblies that reference the modified assembly by its strong name will no longer find it. You must then patch those references as well, or disable strong name verification in the runtime configuration (.NET Framework: `<runtime><bypassTrustedAppStrongNames>`; .NET Core: generally not verified by default).

Some obfuscators add additional integrity checks in code — they compute a hash of the assembly at startup and compare it to a hardcoded value. These checks are ordinary C# methods, detectable through static analysis in dnSpy and neutralizable using the same IL patching techniques.

## Comparison with native patching

| Aspect | x86-64 patching (ch. 21, ImHex) | IL patching (.NET, dnSpy) |  
|---|---|---|  
| Abstraction level | Raw machine opcodes | Typed bytecode with metadata |  
| Size constraint | Replacement instruction must fit in the same space | Flexible — dnSpy reorganizes the bytecode |  
| Verification | None (an invalid opcode = runtime crash) | CLR IL verifier (rejection before execution) |  
| Corruption risk | High (alignment, relocations, cross-references) | Low (dnSpy manages consistency) |  
| High-level editing | Impossible (no built-in "C → x86 recompilation") | C# editing with automatic recompilation |  
| Signatures | No standard mechanism (but custom checksums) | Strong name signing (removable) |  
| Tools required | Hex editor + opcode knowledge | dnSpy only |  
| Reversibility | Difficult without backup | Easy (dnSpy can re-edit indefinitely) |

The decisive advantage of IL patching is the ability to edit in C#. Where x86 patching requires juggling hexadecimal opcodes and counting bytes, dnSpy offers an environment where you modify readable code and the internal compiler handles the translation to bytecode. This is a qualitative change that makes .NET patching accessible even without assembly language expertise.

## The three patching strategies in summary

Depending on the context and objective, choose between the three editing levels:

**C# editing** is the first choice when you want to rewrite an entire piece of logic — replace a method body, add a code path, modify an algorithm. It is intuitive, safe (the compiler verifies consistency), and requires no knowledge of IL bytecode. Its limitation is the partial support for modern C# constructs by dnSpy's internal compiler.

**IL editing** is the choice for surgical patches — flipping a branch, replacing a constant, neutralizing a call. It requires understanding the CIL stack model and maintaining stack consistency. It is the direct analog of x86 opcode patching, but with a safety net (dnSpy's IL verifier).

**Metadata editing** is the choice for structural modifications — changing the visibility of a type or method, renaming a symbol, removing an attribute, modifying a constant. It does not touch the IL code but can have profound effects on the application's behavior.

In practice, a complete patch often combines all three levels. Start with C# editing for major modifications, refine with IL editing for fine adjustments, and adapt the metadata as needed.

---


⏭️ [Practical Exercise: Bypassing a C# License Check](/32-dynamic-analysis-dotnet/05-practical-license-csharp.md)
