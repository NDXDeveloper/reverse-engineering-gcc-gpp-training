🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 32.2 — Hooking .NET Methods with Frida (`frida-clr`)

> 📁 **Files used**: `binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64/LicenseChecker.dll`  
> 🔧 **Tools**: Frida, frida-tools, frida-clr  
> 📖 **Prerequisites**: [Chapter 13 — Dynamic Instrumentation with Frida](/13-frida/README.md), [Section 32.1](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md)

---

## From native Frida to Frida CLR

In Chapter 13, you learned to use Frida to instrument native binaries: hook C/C++ functions by address or symbol, intercept `malloc`, `free`, `open`, modify arguments and return values on the fly. The engine is the same here — a JavaScript agent injected into the target process — but the intervention surface changes radically.

When instrumenting a native binary, you work at the level of memory addresses and machine calling conventions. To hook a function, you need its address (obtained via `Module.findExportByName` or calculated from a Ghidra offset). Arguments are registers or stack locations, read and written with `args[0]`, `args[1]`, etc. It's low-level, direct, and sometimes fragile.

With a .NET process, you face an additional layer: the CLR runtime. C# code is compiled to CIL bytecode, which is then translated to native code by the JIT compiler at runtime. .NET methods are not simple functions at fixed addresses — they are managed objects that the runtime knows by their metadata token, their class, their signature. Frida provides a dedicated module, `CLR` (also called `frida-clr`), that exposes these managed objects to the JavaScript agent and allows hooking them at a semantic level: by class name and method name, not by raw address.

## CLR instrumentation architecture

To understand what `frida-clr` does, you need to visualize the layers at play when attaching Frida to a .NET process:

```
┌───────────────────────────────────────────────┐
│  Frida JavaScript Agent (injected)            │
│                                               │
│   CLR bridge: access to types, methods,       │
│   fields of the managed world via runtime     │
│   APIs (ICorProfiler / metadata API)          │
│                                               │
├───────────────────────────────────────────────┤
│  CLR / CoreCLR Runtime                        │
│   ┌─────────────┐  ┌──────────────────────┐   │
│   │ JIT Compiler│  │ Garbage Collector    │   │
│   └──────┬──────┘  └──────────────────────┘   │
│          │                                    │
│          ▼                                    │
│   Generated native code (in memory)           │
├───────────────────────────────────────────────┤
│  P/Invoke native code (libnative_check.so)    │
│  → hookable via classic Interceptor           │
└───────────────────────────────────────────────┘
```

The Frida agent operates in two simultaneous modes. It can interact with the managed world via the CLR bridge — this is what interests us in this section. And it can still interact with native code via `Interceptor` and `NativeFunction`, exactly as in Chapter 13 — this will be exploited in section 32.3 for P/Invoke calls.

The CLR bridge works by leveraging the .NET runtime's profiling and metadata APIs. It enumerates loaded assemblies, traverses their type tables, resolves methods, and can install hooks by manipulating JIT stubs or using profiling mechanisms. The result: from JavaScript, you can write `CLR.classes['LicenseChecker.LicenseValidator'].methods['Validate']` and get a handle to the managed method.

## Installation and verification

Frida and its Python bindings install as in Chapter 13:

```bash
pip install frida-tools frida
```

To verify that CLR support is available, you can launch a simple .NET process and try attaching Frida:

```bash
# Launch the application in the background
cd binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64  
LD_LIBRARY_PATH=. ./LicenseChecker &  
APP_PID=$!  

# Test attachment
frida -p $APP_PID -l /dev/null --runtime=clr
```

If attachment succeeds and the Frida console opens, CLR support is operational. The `--runtime=clr` flag tells Frida to activate the CLR bridge rather than working at the native level only.

> ⚠️ **Note on compatibility**: Frida's CLR support is more mature on Windows (.NET Framework / .NET Core) than on Linux (CoreCLR). Under Linux, some features may be limited depending on the Frida and .NET runtime versions. If the CLR bridge is unavailable, an alternative approach is presented at the end of this section: hooking methods after JIT compilation, at the native level.

## Enumerating classes and methods

The first step, before any hooking, is to explore the target process's managed landscape. The CLR bridge allows listing loaded assemblies, then traversing their types and methods.

```javascript
// enum_assemblies.js
// List assemblies and their main types

"use strict";

function enumManagedTypes() {
    const dominated = CLR.assemblies;

    for (const name in dominated) {
        const assembly = dominated[name];
        console.log(`\n[Assembly] ${name}`);

        const types = assembly.classes;
        for (const typeName in types) {
            console.log(`  [Type] ${typeName}`);
            const klass = types[typeName];

            // List methods
            const methods = klass.methods;
            for (const methodName in methods) {
                console.log(`    [Method] ${methodName}`);
            }
        }
    }
}

setTimeout(enumManagedTypes, 500);
```

On our `LicenseChecker`, this script reveals the structure that dnSpy showed us statically, but this time from inside the running process:

```
[Assembly] LicenseChecker
  [Type] LicenseChecker.Program
    [Method] Main
  [Type] LicenseChecker.LicenseValidator
    [Method] Validate
    [Method] ValidateStructure
    [Method] ComputeUserHash
    [Method] CheckSegmentB
    [Method] ComputeCrossXor
    [Method] ComputeFinalChecksum
    [Method] DeriveLicenseLevel
  [Type] LicenseChecker.ValidationResult
    [Method] get_IsValid
    [Method] set_IsValid
    [Method] get_FailureReason
    [Method] set_FailureReason
    ...
  [Type] LicenseChecker.NativeBridge
    [Method] ComputeNativeHash
    [Method] ComputeChecksum
    [Method] VerifyIntegrity
```

This enumeration confirms that the CLR bridge has access to all managed metadata. We can now precisely target the methods to hook.

## Hooking a managed method

CLR hooking is done by obtaining a reference to the target method, then attaching a callback that will be invoked before and/or after each call. The syntax differs from `Interceptor.attach` (which works on native addresses) but the principle is identical.

### Capturing `Validate()` arguments

Our first target is the `Validate(string username, string licenseKey)` method of the `LicenseValidator` class. We want to intercept each call to log the arguments — the username and key provided by the user.

```javascript
// hook_validate.js
// Intercept LicenseValidator.Validate() to log inputs

"use strict";

function hookValidate() {
    const LicenseValidator = CLR.classes[
        "LicenseChecker.LicenseValidator"
    ];

    if (!LicenseValidator) {
        console.log("[-] LicenseValidator class not found.");
        console.log("    Is the assembly loaded?");
        return;
    }

    const validate = LicenseValidator.methods["Validate"];

    validate.implementation = function (username, licenseKey) {
        console.log("\n══════════════════════════════════════");
        console.log("[+] LicenseValidator.Validate() called");
        console.log(`    username   = "${username}"`);
        console.log(`    licenseKey = "${licenseKey}"`);
        console.log("══════════════════════════════════════");

        // Call the original method
        const result = this.Validate(username, licenseKey);

        // Log the result
        console.log(`\n[+] Result:`);
        console.log(`    IsValid       = ${result.IsValid}`);
        console.log(`    FailureReason = "${result.FailureReason}"`);
        console.log(`    LicenseLevel  = "${result.LicenseLevel}"`);

        return result;
    };

    console.log("[+] Hook installed on LicenseValidator.Validate()");
}

setTimeout(hookValidate, 500);
```

The `validate.implementation = function(...) { ... }` pattern replaces the method's implementation with our callback. Inside, `this.Validate(username, licenseKey)` calls the original implementation — it's the managed equivalent of the `onEnter` / `onLeave` pattern you know from `Interceptor.attach`, but combined in a single wrapper.

### Intercepting `ComputeUserHash()` to extract segment A

Let's go further. We want to capture the return value of `ComputeUserHash()` — this is the expected value for segment A.

```javascript
// hook_compute_hash.js
// Intercept ComputeUserHash() to capture expected segment A

"use strict";

function hookComputeUserHash() {
    const klass = CLR.classes["LicenseChecker.LicenseValidator"];
    const method = klass.methods["ComputeUserHash"];

    method.implementation = function (username) {
        const result = this.ComputeUserHash(username);

        // Convert to 4-character hex (segment format)
        const hex = (result >>> 0).toString(16).toUpperCase().padStart(4, "0");

        console.log(`[+] ComputeUserHash("${username}") → 0x${hex}`);
        console.log(`    ↳ Expected segment A: ${hex}`);

        return result;
    };

    console.log("[+] Hook installed on ComputeUserHash()");
}

setTimeout(hookComputeUserHash, 500);
```

By launching `LicenseChecker` with this script active and entering `alice` as username, you'll see the computed segment A in the Frida console — without having touched a debugger, without understanding the FNV-1a algorithm, and without modifying the binary.

### Intercepting `ComputeCrossXor()` to extract segment C

The same pattern applies for segment C, by hooking `ComputeCrossXor()`:

```javascript
// hook_cross_xor.js
// Intercept ComputeCrossXor() to capture expected segment C

"use strict";

function hookCrossXor() {
    const klass = CLR.classes["LicenseChecker.LicenseValidator"];
    const method = klass.methods["ComputeCrossXor"];

    method.implementation = function (segA, segB) {
        const result = this.ComputeCrossXor(segA, segB);

        const hexA = (segA >>> 0).toString(16).toUpperCase().padStart(4, "0");
        const hexB = (segB >>> 0).toString(16).toUpperCase().padStart(4, "0");
        const hexC = (result >>> 0).toString(16).toUpperCase().padStart(4, "0");

        console.log(`[+] ComputeCrossXor(0x${hexA}, 0x${hexB}) → 0x${hexC}`);
        console.log(`    ↳ Expected segment C: ${hexC}`);

        return result;
    };

    console.log("[+] Hook installed on ComputeCrossXor()");
}

setTimeout(hookCrossXor, 500);
```

## Modifying return values

Hooking isn't limited to observation. You can modify return values to alter the program's behavior without touching the binary on disk. This is the Frida equivalent of variable modification in dnSpy — but automatable and reproducible.

### Forcing validation to succeed

The most brute-force approach is to replace `Validate()`'s implementation with a version that always returns a positive result:

```javascript
// bypass_validate.js
// Force Validate() to always return IsValid = true

"use strict";

function bypassValidation() {
    const LicenseValidator = CLR.classes[
        "LicenseChecker.LicenseValidator"
    ];
    const ValidationResult = CLR.classes[
        "LicenseChecker.ValidationResult"
    ];

    LicenseValidator.methods["Validate"].implementation =
        function (username, licenseKey) {
            console.log(`[+] Validate() intercepted — bypass active`);
            console.log(`    username = "${username}"`);

            // Create a forged ValidationResult
            const fakeResult = ValidationResult.$new();
            fakeResult.IsValid = true;
            fakeResult.FailureReason = "";
            fakeResult.LicenseLevel = "Enterprise";
            fakeResult.ExpirationInfo = "Perpetual (forged by Frida)";

            return fakeResult;
        };

    console.log("[+] Bypass installed — any license will be accepted");
}

setTimeout(bypassValidation, 500);
```

This script creates a `ValidationResult` instance via `$new()` (Frida's equivalent of `new ValidationResult()`), assigns the desired properties, and returns this forged object instead of the real result. The application will display "License valid! Welcome." regardless of the key entered.

> 💡 `$new()` is specific to Frida's CLR bridge. It allows instantiating .NET objects from JavaScript. Properties are directly accessible by name, thanks to the metadata that provides Frida the mapping between C# names and memory offsets.

### Surgical approach: modifying a single check

Rather than bypassing all validation, you can target a single check. For example, if you already have the correct segments A, B, and C but segment D is problematic, you can hook only `ComputeFinalChecksum` to make it return the value you entered:

```javascript
// hook_checksum.js
// Force ComputeFinalChecksum to return the supplied segment D value

"use strict";

function hookFinalChecksum() {
    const klass = CLR.classes["LicenseChecker.LicenseValidator"];

    // We need access to the user-entered segment D.
    // Strategy: hook Validate() to capture licenseKey,
    // then hook ComputeFinalChecksum to return the
    // segment D value as entered.

    let capturedSegD = null;

    klass.methods["Validate"].implementation =
        function (username, licenseKey) {
            // Extract segment D from the entered key
            const parts = licenseKey.trim().toUpperCase().split("-");
            if (parts.length === 4) {
                capturedSegD = parseInt(parts[3], 16);
                console.log(`[+] Entered segment D: 0x${parts[3]}`);
            }
            return this.Validate(username, licenseKey);
        };

    klass.methods["ComputeFinalChecksum"].implementation =
        function (segA, segB, segC, username) {
            const realValue = this.ComputeFinalChecksum(
                segA, segB, segC, username
            );
            const realHex = (realValue >>> 0)
                .toString(16).toUpperCase().padStart(4, "0");

            console.log(`[+] Real ComputeFinalChecksum = 0x${realHex}`);

            if (capturedSegD !== null) {
                console.log(`[+] → Replaced by 0x${
                    capturedSegD.toString(16).toUpperCase().padStart(4, "0")
                } (entered segment D)`);
                return capturedSegD;
            }
            return realValue;
        };

    console.log("[+] Hooks installed (Validate + ComputeFinalChecksum)");
}

setTimeout(hookFinalChecksum, 500);
```

This approach is more subtle: the program executes all its logic normally, except at the precise moment of the final checksum where we substitute the expected value with the one the user entered. It's the equivalent of a targeted patch, but without binary modification.

## Combined script: automatic keygen via hooking

By combining multiple hooks, you can build a script that lets the application compute all segments itself, captures them, and displays the complete valid key. The idea is to launch the application with a given username and a dummy key, then read the expected values.

The subtle point is this: the original `Validate()` method is sequential with early return — if segment A is incorrect, it returns immediately without ever calling `ComputeCrossXor` or `ComputeFinalChecksum`. With a dummy key, only `ComputeUserHash` would be reached. To capture all four segments in a single pass, our hook on `Validate()` must **directly call** the computation methods in order, passing them the correct values, instead of delegating to the original implementation.

```javascript
// keygen_frida.js
// Automatic keygen by intercepting internal computations
//
// Usage:
//   frida -f ./LicenseChecker --runtime=clr -l keygen_frida.js
//   (enter any username and a dummy key AAAA-AAAA-AAAA-AAAA)

"use strict";

function installKeygen() {
    const klass = CLR.classes["LicenseChecker.LicenseValidator"];
    const segments = { A: null, B: null, C: null, D: null };

    const fmt = (v) => v !== null
        ? (v >>> 0).toString(16).toUpperCase().padStart(4, "0")
        : "????";

    // ── Logging hooks on sub-methods (optional) ──
    // These hooks only log — capture is driven
    // from the Validate hook below.

    klass.methods["ComputeUserHash"].implementation =
        function (username) {
            const val = this.ComputeUserHash(username);
            console.log(`  [CLR] ComputeUserHash("${username}") → 0x${fmt(val & 0xFFFF)}`);
            return val;
        };

    klass.methods["ComputeCrossXor"].implementation =
        function (segA, segB) {
            const val = this.ComputeCrossXor(segA, segB);
            console.log(`  [CLR] ComputeCrossXor(0x${fmt(segA)}, 0x${fmt(segB)}) → 0x${fmt(val & 0xFFFF)}`);
            return val;
        };

    klass.methods["ComputeFinalChecksum"].implementation =
        function (segA, segB, segC, username) {
            const val = this.ComputeFinalChecksum(segA, segB, segC, username);
            console.log(`  [CLR] ComputeFinalChecksum → 0x${fmt(val & 0xFFFF)}`);
            return val;
        };

    // ── Main hook: Validate ──
    // Instead of letting the original execute (it would return
    // on the first failed check), we call each computation
    // method directly with the correct values.

    klass.methods["Validate"].implementation =
        function (username, licenseKey) {
            console.log(`\n[+] Validate("${username}", "${licenseKey}")`);
            segments.A = segments.B = segments.C = segments.D = null;

            // Segment A — direct call
            segments.A = this.ComputeUserHash(username) & 0xFFFF;

            // Segment B — trigger CheckSegmentB to provoke
            // the P/Invoke call to compute_native_hash. If a native
            // hook is installed (§32.3), it will capture seg.B
            // synchronously during this call. Without a native hook,
            // seg.B will remain null — CheckSegmentB returns a bool,
            // not the hash. We pass 0 as a dummy segmentB — doesn't
            // matter, we just want compute_native_hash to be called
            // on the native side.
            try {
                // CheckSegmentB calls NativeBridge.ComputeNativeHash
                // internally and compares with segmentB. We can't
                // read 'expected' directly from CLR — we need to
                // hook it on the native side (§32.3) to capture seg.B.
                this.CheckSegmentB(username, 0);
            } catch (e) {
                console.log(`  [!] CheckSegmentB exception: ${e}`);
            }

            // Segment C — call with real A and B
            // (seg.B is captured by the native hook if installed)
            if (segments.B !== null) {
                segments.C = this.ComputeCrossXor(
                    segments.A, segments.B) & 0xFFFF;
            }

            // Segment D — call with real A, B, C
            if (segments.B !== null && segments.C !== null) {
                segments.D = this.ComputeFinalChecksum(
                    segments.A, segments.B, segments.C, username) & 0xFFFF;
            }

            // Display
            console.log("\n╔══════════════════════════════════════════╗");
            console.log("║         FRIDA KEYGEN — RESULTS            ║");
            console.log("╠══════════════════════════════════════════╣");
            console.log(`║  Username  : ${username.padEnd(25)}║`);
            console.log(`║  Segment A : ${fmt(segments.A).padEnd(25)}║`);
            console.log(`║  Segment B : ${fmt(segments.B).padEnd(25)}║`);
            console.log(`║  Segment C : ${fmt(segments.C).padEnd(25)}║`);
            console.log(`║  Segment D : ${fmt(segments.D).padEnd(25)}║`);
            console.log("║                                          ║");

            if (segments.A !== null && segments.B !== null &&
                segments.C !== null && segments.D !== null) {
                const key = `${fmt(segments.A)}-${fmt(segments.B)}`
                          + `-${fmt(segments.C)}-${fmt(segments.D)}`;
                console.log(`║  VALID KEY : ${key.padEnd(23)}║`);
            } else {
                console.log("║  ⚠ Segment B missing — install the       ║");
                console.log("║    native hook (see §32.3)               ║");
            }

            console.log("╚══════════════════════════════════════════╝\n");

            // Call the original so the program displays its message.
            // (It will fail at segment A, but we already have our values.)
            return this.Validate(username, licenseKey);
        };

    console.log("[+] Frida keygen installed — launch validation.");
}

setTimeout(installKeygen, 1000);
```

This script illustrates a fundamental pattern in dynamic RE: you don't reverse the algorithm, you call the computation functions directly and capture their results. The hook on `Validate()` short-circuits the original's linear flow (which would return on the first failed check) by calling each sub-method with the correct values.

Note that segment B cannot be captured by the CLR bridge alone: it's computed by the native library `libnative_check.so`, and the intermediate `expected` value in `CheckSegmentB` is not directly accessible. To complete the keygen, you need to add a native hook on `compute_native_hash` (section 32.3). This is precisely the added difficulty from our `LicenseChecker`'s P/Invoke architecture.

## Alternative approach: post-JIT hooking at the native level

If the CLR bridge is unavailable or works poorly on your platform, there is a fallback approach that uses Frida's native interception capabilities on the JIT-generated code.

The principle is as follows. When the CLR executes a .NET method for the first time, the JIT compiler translates it to native machine code and stores the result in memory. This native version of the method has a fixed address (as long as the application runs). If you can find this address, you can hook the method with `Interceptor.attach` — exactly like a native C function.

To find a method's JIT-compiled address, several techniques exist.

**Use runtime symbols.** CoreCLR exports internal functions for resolving methods. You can call `clr_jit_compileMethod` or inspect runtime internal structures. This is fragile and depends on the CoreCLR version.

**Force JIT compilation then scan memory.** Trigger a call to the target method (by sending any input), then search memory for the compiled method's characteristic prologue. Native prologues generated by the JIT follow recognizable patterns (`push rbp; mov rbp, rsp` or `sub rsp, N`).

**Use `frida-trace` with patterns.** You can trace calls to JIT functions to identify compilation addresses.

```javascript
// hook_post_jit.js
// Native hooking of a .NET method after JIT compilation
//
// This approach works when the CLR bridge is unavailable.
// It requires knowing the JIT-compiled method's address.

"use strict";

function hookPostJIT() {
    // Step 1: find the main module
    const mainModule = Process.enumerateModules()
        .find(m => m.name.includes("coreclr") ||
                    m.name.includes("libcoreclr"));

    if (!mainModule) {
        console.log("[-] CoreCLR not found in the process.");
        return;
    }
    console.log(`[+] CoreCLR found: ${mainModule.name} @ ${mainModule.base}`);

    // Step 2: scan memory to find the target method.
    // In practice, signatures or runtime internal structures
    // are used. Here, we assume the address was identified
    // beforehand (e.g. via a breakpoint in dnSpy, which shows
    // the native address in the Disassembly window).

    const targetAddr = ptr("0x<JIT_COMPILED_ADDRESS>");

    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            // In .NET calling convention (CoreCLR, x86-64):
            // - args[0] = 'this' pointer (the LicenseValidator instance)
            // - args[1] = first parameter (string username)
            // - args[2] = second parameter (string licenseKey)
            //
            // .NET strings in memory are objects with a header,
            // a Length field, and characters in UTF-16.

            console.log("[+] Validate() called (native post-JIT hook)");
        },
        onLeave: function (retval) {
            console.log(`[+] Validate() returns: ${retval}`);
        }
    });

    console.log("[+] Native hook installed on JIT-compiled method");
}

setTimeout(hookPostJIT, 500);
```

This approach is more complex and less elegant than the CLR bridge — you fall back into the native hooking world from Chapter 13, with the additional difficulty of needing to understand the memory representation of .NET objects (object headers, UTF-16LE string encoding, managed pointers). But it has one advantage: it always works, regardless of the Frida or runtime version, because it operates at the lowest abstraction level — machine code.

## Practical considerations

### Injection timing

In `spawn` mode (Frida launches the process), the agent is injected very early, before the CLR runtime is fully initialized. The CLR bridge may not be ready immediately. This is why the scripts above use `setTimeout` to delay hook installation. In practice, it may be necessary to adjust this delay, or use a more robust mechanism: monitor the target assembly loading and install hooks as soon as it appears.

```javascript
// Wait for the LicenseChecker assembly to be loaded
function waitForAssembly(name, callback) {
    const interval = setInterval(() => {
        if (CLR.assemblies && CLR.assemblies[name]) {
            clearInterval(interval);
            callback();
        }
    }, 100);
}

waitForAssembly("LicenseChecker", () => {
    console.log("[+] LicenseChecker assembly detected — installing hooks");
    installKeygen();
});
```

In `attach` mode (Frida attaches to an already-running process), the assembly is generally already loaded and the CLR bridge is immediately functional. This is the most reliable mode for CLR hooking.

### Handling method overloads

In C#, a class can have multiple methods with the same name but different signatures (overloads). The CLR bridge distinguishes them by their signature. If `methods["Validate"]` is ambiguous, you can use the full signature notation:

```javascript
// Specify the overload by parameter types
const validate = klass.methods[
    "Validate(System.String, System.String)"
];
```

### Garbage Collector impact

.NET objects can be moved in memory by the GC. This means a raw pointer to a managed object can become invalid at any time. The CLR bridge handles this transparently using GC handles (GCHandle). But if you attempt to manipulate managed objects via Frida's native APIs (`Memory.read*`), you expose yourself to stale pointers. The rule is simple: to interact with managed objects, use the CLR bridge; to interact with native code, use `Interceptor` and `NativeFunction`.

### Dynamically loaded assemblies

If the target application loads assemblies at runtime (via `Assembly.Load`), these only appear in `CLR.assemblies` after loading. To hook methods in a dynamically loaded assembly, you need to monitor loading (for example by hooking `Assembly.Load` itself) and install hooks at that point.

This technique is particularly relevant when facing obfuscators that decrypt an assembly in memory and load it dynamically: the decrypted assembly never exists on disk, but it appears in the managed space as soon as it's loaded, and becomes immediately hookable.

## Comparison with native Frida (Chapter 13)

| Aspect | Native Frida (Ch. 13) | Frida CLR (this section) |  
|---|---|---|  
| Target | C/C++ functions in an ELF/PE | C# methods in a .NET assembly |  
| Identification | Address or exported symbol | Class name + method name |  
| Arguments | Registers / stack (low level) | Typed C# objects (high level) |  
| Return value | Integer / raw pointer | C# object (including complex types) |  
| Object creation | `Memory.alloc` + manual writing | `ClassName.$new()` |  
| Strings | `Memory.readUtf8String(ptr)` | Direct access (JavaScript property) |  
| GC | N/A | Handles managed automatically |  
| Compatibility | Universal | Depends on Frida's CLR support |

The CLR bridge raises the abstraction level: you work with C# concepts (classes, methods, properties, instances) rather than with addresses and registers. It's more comfortable, but it's also an additional layer that can introduce incompatibilities. The native post-JIT approach remains the universal safety net.

---


⏭️ [Intercepting P/Invoke calls (bridge .NET → GCC native libraries)](/32-dynamic-analysis-dotnet/03-pinvoke-interception.md)
