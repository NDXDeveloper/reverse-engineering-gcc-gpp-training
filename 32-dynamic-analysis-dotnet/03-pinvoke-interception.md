🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 32.3 — Intercepting P/Invoke Calls (.NET Bridge → Native GCC Libraries)

> 📁 **Files used**: `binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64/LicenseChecker.dll`, `binaries/ch32-dotnet/native/libnative_check.so`  
> 🔧 **Tools**: Frida, GDB/GEF, objdump, nm, strace/ltrace, dnSpy  
> 📖 **Prerequisites**: [Chapter 5 — Basic Inspection Tools](/05-basic-inspection-tools/README.md), [Chapter 11 — GDB](/11-gdb/README.md), [Chapter 13 — Frida](/13-frida/README.md), [Section 32.2](/32-dynamic-analysis-dotnet/02-hooking-frida-clr.md)

---

## The managed–native bridge: why it is a RE hotspot

.NET applications do not live in a closed universe. Sooner or later, managed code needs to interact with the outside world: calling a cryptographic library written in C, invoking a system API not exposed by the framework, or — as in our `LicenseChecker` — delegating part of the validation logic to a native library compiled with GCC.

The mechanism that makes this possible is called **P/Invoke** (Platform Invocation Services). It is a marshalling system that allows a C# method to call a function exported by a native shared library (`.so` on Linux, `.dll` on Windows). The CLR handles converting managed types to native types, pinning objects in memory so the GC does not move them during the call, passing arguments according to the native calling convention, and then converting the return value back to a managed type.

For the reverse engineer, P/Invoke calls are major points of interest for three reasons. First, they mark trust boundaries: code crossing the managed–native bridge is often sensitive code (license checks, crypto, system interactions). Second, they provide a dual interception surface: you can hook them on the managed side (before the crossing) or on the native side (after the crossing). Finally, they require mastering both worlds — the .NET tools seen in sections 32.1–32.2 and the native tools from chapters 5 through 15.

Our `LicenseChecker` perfectly embodies this scenario. Segments A and C of the key are computed in pure C#, but segment B depends on `compute_native_hash()` and segment D partially depends on `compute_checksum()` — two functions exported by `libnative_check.so`, a library compiled with GCC. The Frida keygen script from section 32.2 was incomplete precisely because it did not capture the values computed on the native side. This section fills that gap.

## Anatomy of a P/Invoke call

Before intercepting, let us understand what happens when the CLR executes a P/Invoke call. Consider the call to `ComputeNativeHash` in our `NativeBridge.cs`:

```csharp
[DllImport("libnative_check.so", CallingConvention = CallingConvention.Cdecl,
           EntryPoint = "compute_native_hash")]
public static extern uint ComputeNativeHash(byte[] data, int length);
```

The `[DllImport]` attribute tells the CLR three things: the name of the library to load (`libnative_check.so`), the name of the native function to call (`compute_native_hash`), and the calling convention to use (`Cdecl`). When the C# code calls `NativeBridge.ComputeNativeHash(data, data.Length)`, the following sequence executes within the runtime:

**Library resolution.** On the first call, the CLR loads `libnative_check.so` using the system's dynamic loading mechanism (`dlopen` on Linux, `LoadLibrary` on Windows). The library is searched for in the application directory, then in the standard paths (`LD_LIBRARY_PATH`, `/usr/lib`, etc.). If the library is not found, a `DllNotFoundException` is thrown.

**Symbol resolution.** The CLR looks up the symbol `compute_native_hash` in the loaded library (`dlsym` on Linux, `GetProcAddress` on Windows). If the symbol does not exist, an `EntryPointNotFoundException` is thrown.

**Argument marshalling.** The CLR converts managed arguments to native types. The `byte[] data` is a managed array — the CLR pins it in memory (to prevent the GC from moving it) and passes a pointer to its content to the native code. The `int length` is a blittable type (its memory representation is identical in managed and native code) and is passed directly.

**Native call.** The CLR performs the call to the native function following the Cdecl convention: arguments are passed via registers `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (System V AMD64 ABI, exactly as seen in chapter 3). Execution leaves the managed world and enters the machine code of `libnative_check.so`.

**Return and de-marshalling.** The return value (`uint32_t` in C) is read from the `rax` register and converted to a C# `uint`. Pinned objects are released. Execution resumes in the managed world.

This sequence offers multiple interception points. You can intervene before marshalling (on the CLR side, with Frida CLR or dnSpy), after marshalling but before the native call (on the P/Invoke stub), at the native function itself (with native Frida or GDB), or on return (to modify the value sent back to the managed world).

## Step 1 — Identifying P/Invoke calls through static analysis

Before any dynamic instrumentation, we start by inventorying the P/Invoke calls present in the assembly. Several complementary approaches allow us to do this.

### From dnSpy

Opening `LicenseChecker.dll` in dnSpy and navigating to the `NativeBridge` class, we immediately see the `[DllImport]` declarations. dnSpy decompiles them faithfully, including the marshalling attributes. We identify three P/Invoke functions: `ComputeNativeHash`, `ComputeChecksum`, and `VerifyIntegrity`, all pointing to `libnative_check.so`.

We can also use dnSpy's **Analyze** feature (right-click → Analyze on a P/Invoke method) to find all call sites in the managed code. For `ComputeNativeHash`, the analysis reveals it is called from `LicenseValidator.CheckSegmentB()`. For `ComputeChecksum`, from `LicenseValidator.ComputeFinalChecksum()`. For `VerifyIntegrity`, no call site — it is declared but never used in the main flow (it is our bonus exercise target).

### From the command line

For a quick triage without a GUI, we can use `monodis` (if Mono is installed) or `ildasm` to list the native imports:

```bash
# With monodis (Mono)
monodis --implmap LicenseChecker.dll
```

The output will list the P/Invoke methods with their target library and native entry point. This is the .NET equivalent of `ldd` + `nm` for native binaries.

### Native side: inspecting libnative_check.so

The native library is a standard ELF `.so`, analyzable with all the tools from Part II. We apply the triage workflow from chapter 5:

```bash
# File type
file native/libnative_check.so

# Exported symbols
nm -D native/libnative_check.so
# → T compute_native_hash
# → T compute_checksum
# → T verify_integrity

# Strings
strings native/libnative_check.so
# → NATIVERE   (the native salt!)

# Disassembly of the exported functions
objdump -d -M intel native/libnative_check.so | less
```

The `nm -D` command confirms that all three functions are indeed exported (type `T` = text/code, global visibility). The `strings` command reveals the salt `"NATIVERE"` — a clue that the attentive reverse engineer will notice and compare with the C# salt `"REV3RSE!"`. The disassembly with `objdump` gives access to the machine code of the functions, analyzable with the techniques from chapter 7.

For a deeper analysis, we would import `libnative_check.so` into Ghidra (chapter 8), which would produce a readable C decompilation of the three functions. This is the approach to follow for understanding the native hash algorithm as part of a complete keygen.

## Step 2 — Tracing P/Invoke calls with strace and ltrace

Before reaching for Frida, system tracing tools offer a first look at the native interactions. These are the same tools seen in chapter 5 — they work identically on a .NET process, since the native code runs in the same address space.

```bash
# Trace system calls (library loading)
strace -f -e trace=openat ./LicenseChecker 2>&1 | grep native
```

> ⚠️ **Caution about early return.** The `Validate()` method is sequential: if segment A is incorrect, it returns immediately without ever calling `CheckSegmentB`, and the CLR never loads `libnative_check.so`. For `strace` to capture the `openat` of the library, you must provide a key whose **segment A is correct** (obtained beforehand via dnSpy in §32.1 or via the Frida hook in §32.2). For example, if segment A for `alice` is `7B3F`:

```bash
strace -f -e trace=openat ./LicenseChecker 2>&1 <<< "alice
7B3F-0000-0000-0000" | grep native
# → openat(AT_FDCWD, "./libnative_check.so", O_RDONLY|O_CLOEXEC) = 3
```

The filter on `openat` shows the moment the CLR loads the native library. The returned file descriptor (here `3`) confirms that the loading succeeded. With a key whose segment A is wrong, this line would not appear.

```bash
# Trace shared library calls
# (correct segment A to reach the native code)
ltrace -e 'compute_*' -f ./LicenseChecker <<< "alice
7B3F-0000-0000-0000"
# → compute_native_hash(0x7f..., 5) = 0x<segment_B_value>
```

The `ltrace` command with a filter on `compute_*` captures the calls to the functions in `libnative_check.so`, with their arguments and return values. We directly see the value returned by `compute_native_hash` — this is the expected segment B. However, `compute_checksum` does not appear here: validation fails at segment B (we entered `0000`) and returns before reaching `ComputeFinalChecksum`. To capture `compute_checksum`, we would need to provide a key with both segments A **and** B correct.

> ⚠️ `ltrace` can be unstable with modern .NET processes due to the complexity of the CoreCLR runtime. If `ltrace` crashes or captures nothing, proceed directly to Frida.

## Step 3 — Native interception with Frida

This is the most powerful and most reliable approach. We use Frida's native capabilities (the same ones from chapter 13) to hook directly into the functions exported by `libnative_check.so`. The CLR bridge is not needed here — we are working at the machine code level.

### Hooking `compute_native_hash` to capture segment B

```javascript
// hook_native_hash.js
// Intercept compute_native_hash() in libnative_check.so
//
// Usage:
//   frida -f ./LicenseChecker -l hook_native_hash.js
//   (or frida -p <PID> -l hook_native_hash.js)

"use strict";

function hookNativeHash() {
    // Look for the exported function in libnative_check.so
    const addr = Module.findExportByName("libnative_check.so",
                                         "compute_native_hash");
    if (!addr) {
        console.log("[-] compute_native_hash not found.");
        console.log("    Is the library loaded?");
        console.log("    (The P/Invoke call triggers loading on first call)");
        return;
    }

    console.log(`[+] compute_native_hash @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // C signature: uint32_t compute_native_hash(
            //                    const uint8_t *data, int length)
            //
            // System V AMD64 ABI:
            //   args[0] = rdi = pointer to data (username UTF-8)
            //   args[1] = rsi = length

            this.dataPtr = args[0];
            this.length  = args[1].toInt32();

            // Read the buffer contents (the lowercase username)
            const username = Memory.readUtf8String(this.dataPtr, this.length);
            console.log(`\n[+] compute_native_hash() called`);
            console.log(`    data    = "${username}"`);
            console.log(`    length  = ${this.length}`);

            // Bonus: dump the raw bytes of the buffer
            const bytes = Memory.readByteArray(this.dataPtr, this.length);
            console.log(`    hex     = ${hexdump(bytes, { length: this.length })}`);
        },

        onLeave: function (retval) {
            // The return value is a uint32_t in rax.
            // Only the lower 16 bits are used by the C# code.
            const raw   = retval.toUInt32();
            const seg_b = raw & 0xFFFF;
            const hex   = seg_b.toString(16).toUpperCase().padStart(4, "0");

            console.log(`    return  = 0x${raw.toString(16)} (raw)`);
            console.log(`    ↳ Expected Segment B: ${hex}`);

            // Store for use in other hooks
            this.segB = seg_b;
        }
    });

    console.log("[+] Hook installed on compute_native_hash()");
}

// Wait for the library to be loaded by the CLR.
// Loading happens on the first P/Invoke call (lazy loading).
// In spawn mode, the lib is not yet loaded at startup.

function waitForLibAndHook() {
    const mod = Process.findModuleByName("libnative_check.so");
    if (mod) {
        hookNativeHash();
    } else {
        console.log("[*] libnative_check.so not yet loaded, watching...");

        // Watch for new module loads
        const interval = setInterval(() => {
            if (Process.findModuleByName("libnative_check.so")) {
                clearInterval(interval);
                console.log("[+] libnative_check.so detected!");
                hookNativeHash();
            }
        }, 50);
    }
}

waitForLibAndHook();
```

A few points deserve attention.

**Lazy loading.** The CLR loads `libnative_check.so` on the first P/Invoke call, not at process startup. If we attach Frida before this first call, the library is not yet in memory and `Module.findExportByName` returns `null`. The script above handles this situation with periodic polling that waits for the module to appear.

**Reading the buffer.** The `data` argument is a pointer to the contents of the C# `byte[]` array. The CLR has pinned the array in memory before the call — so the pointer is valid for the entire duration of the native execution. We can read it with `Memory.readUtf8String` (if the content is a UTF-8 string) or with `Memory.readByteArray` (for a raw dump).

**The calling convention.** This is exactly the System V AMD64 ABI seen in chapter 3: first argument in `rdi` (args[0]), second in `rsi` (args[1]), return value in `rax`. Nothing .NET-specific here — once execution has crossed the P/Invoke bridge, it is standard native code.

### Hooking `compute_checksum` to capture the native part of segment D

```javascript
// hook_checksum_native.js
// Intercept compute_checksum() in libnative_check.so

"use strict";

function hookChecksum() {
    const addr = Module.findExportByName("libnative_check.so",
                                         "compute_checksum");
    if (!addr) {
        console.log("[-] compute_checksum not found.");
        return;
    }

    console.log(`[+] compute_checksum @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // uint32_t compute_checksum(uint32_t seg_a,
            //                           uint32_t seg_b,
            //                           uint32_t seg_c)
            this.segA = args[0].toUInt32() & 0xFFFF;
            this.segB = args[1].toUInt32() & 0xFFFF;
            this.segC = args[2].toUInt32() & 0xFFFF;

            const fmtHex = (v) => v.toString(16).toUpperCase().padStart(4, "0");

            console.log(`\n[+] compute_checksum() called`);
            console.log(`    seg_a = 0x${fmtHex(this.segA)}`);
            console.log(`    seg_b = 0x${fmtHex(this.segB)}`);
            console.log(`    seg_c = 0x${fmtHex(this.segC)}`);
        },

        onLeave: function (retval) {
            const val = retval.toUInt32() & 0xFFFF;
            const hex = val.toString(16).toUpperCase().padStart(4, "0");
            console.log(`    return (native part of seg D) = 0x${hex}`);
        }
    });

    console.log("[+] Hook installed on compute_checksum()");
}

// Same deferred loading pattern
const interval = setInterval(() => {
    if (Process.findModuleByName("libnative_check.so")) {
        clearInterval(interval);
        hookChecksum();
    }
}, 50);
```

## Step 4 — Combined script: the complete keygen

In section 32.2, our Frida keygen was incomplete: it captured segment A (computed on the CLR side) but not segment B (computed on the native side). Moreover, the original `Validate()` method is sequential with early return — if segment A is incorrect, it returns immediately without ever calling the computation methods for the following segments. With a dummy key, only `ComputeUserHash` is reached.

The solution: the hook on `Validate()` **directly** calls each computation method in the right order, passing them the correct values, instead of delegating to the original implementation. On the native side, the hooks on `compute_native_hash` and `compute_checksum` fire synchronously during these calls and capture the native values.

```javascript
// keygen_complete.js
// Complete keygen combining CLR hooking and native hooking
//
// Usage:
//   frida -f ./LicenseChecker --runtime=clr -l keygen_complete.js
//   Enter any username and a dummy key (e.g.: 0000-0000-0000-0000)

"use strict";

const seg     = { A: null, B: null, C: null, D: null };  
const fmtHex  = (v) => v !== null  
    ? (v >>> 0).toString(16).toUpperCase().padStart(4, "0")
    : "????";

// ═══════════════════════════════════════════════
//  NATIVE HOOKS — segment B and native part of D
// ═══════════════════════════════════════════════

function installNativeHooks() {
    // ── compute_native_hash → segment B ──
    const hashAddr = Module.findExportByName(
        "libnative_check.so", "compute_native_hash");

    if (hashAddr) {
        Interceptor.attach(hashAddr, {
            onLeave: function (retval) {
                seg.B = retval.toUInt32() & 0xFFFF;
                console.log(`  [native] compute_native_hash → 0x${fmtHex(seg.B)}  (segment B)`);
            }
        });
        console.log("[+] Native hook installed: compute_native_hash");
    }

    // ── compute_checksum → native part of segment D ──
    const chkAddr = Module.findExportByName(
        "libnative_check.so", "compute_checksum");

    if (chkAddr) {
        Interceptor.attach(chkAddr, {
            onLeave: function (retval) {
                const nativePart = retval.toUInt32() & 0xFFFF;
                console.log(`  [native] compute_checksum → 0x${fmtHex(nativePart)}  (native checksum)`);
            }
        });
        console.log("[+] Native hook installed: compute_checksum");
    }
}

// ═══════════════════════════════════════════════
//  CLR HOOKS — direct calls from Validate
// ═══════════════════════════════════════════════

function installCLRHooks() {
    const klass = CLR.classes["LicenseChecker.LicenseValidator"];
    if (!klass) {
        console.log("[-] LicenseValidator not found on the CLR side");
        return;
    }

    // ── Main hook: Validate ──
    // The original Validate() returns on the first failed check.
    // We short-circuit this flow by directly calling each
    // computation method with the correct values.

    klass.methods["Validate"].implementation = function (username, licenseKey) {
        console.log(`\n[+] Validate("${username}", "${licenseKey}")`);
        seg.A = seg.B = seg.C = seg.D = null;

        // Segment A — direct call to ComputeUserHash (pure C#)
        seg.A = this.ComputeUserHash(username) & 0xFFFF;
        console.log(`  [CLR] Segment A = 0x${fmtHex(seg.A)}`);

        // Segment B — trigger CheckSegmentB to provoke
        // the P/Invoke call to compute_native_hash.
        // The native hook (above) captures seg.B synchronously
        // during this call.
        try {
            this.CheckSegmentB(username, 0);
        } catch (e) {
            console.log(`  [!] CheckSegmentB exception: ${e}`);
        }

        // Segment C — call with the real A and B
        if (seg.B !== null) {
            seg.C = this.ComputeCrossXor(seg.A, seg.B) & 0xFFFF;
            console.log(`  [CLR] Segment C = 0x${fmtHex(seg.C)}`);
        }

        // Segment D — call with the real A, B, C
        if (seg.B !== null && seg.C !== null) {
            seg.D = this.ComputeFinalChecksum(
                seg.A, seg.B, seg.C, username) & 0xFFFF;
            console.log(`  [CLR] Segment D = 0x${fmtHex(seg.D)}`);
        }

        // Display the key
        console.log("\n╔═════════════════════════════════════════════╗");
        console.log("║      COMPLETE KEYGEN — CLR + NATIVE         ║");
        console.log("╠═════════════════════════════════════════════╣");
        console.log(`║  Username  : ${username.padEnd(28)}║`);
        console.log(`║  Segment A : ${fmtHex(seg.A).padEnd(28)}║`);
        console.log(`║  Segment B : ${fmtHex(seg.B).padEnd(28)}║`);
        console.log(`║  Segment C : ${fmtHex(seg.C).padEnd(28)}║`);
        console.log(`║  Segment D : ${fmtHex(seg.D).padEnd(28)}║`);
        console.log("║                                             ║");

        if (seg.A !== null && seg.B !== null &&
            seg.C !== null && seg.D !== null) {
            const fullKey = `${fmtHex(seg.A)}-${fmtHex(seg.B)}`
                          + `-${fmtHex(seg.C)}-${fmtHex(seg.D)}`;
            console.log(`║  VALID KEY: ${fullKey.padEnd(30)}║`);
        } else {
            console.log("║  ⚠ Incomplete capture (native lib?)      ║");
        }
        console.log("╚═════════════════════════════════════════════╝\n");

        // Call the original (it will fail, but the program
        // will display its message normally).
        return this.Validate(username, licenseKey);
    };

    console.log("[+] CLR hooks installed");
}

// ═══════════════════════════════════════════════
//  ORCHESTRATION
// ═══════════════════════════════════════════════

// Native hooks must wait for libnative_check.so to load.
// CLR hooks must wait for the assembly to load.
// We watch for both in parallel.

let nativeReady = false;  
let clrReady    = false;  

const poll = setInterval(() => {
    if (!nativeReady && Process.findModuleByName("libnative_check.so")) {
        installNativeHooks();
        nativeReady = true;
    }

    if (!clrReady && CLR && CLR.assemblies &&
        CLR.assemblies["LicenseChecker"]) {
        installCLRHooks();
        clrReady = true;
    }

    if (nativeReady && clrReady) {
        clearInterval(poll);
        console.log("\n[+] All hooks are in place. Enter a username.\n");
    }
}, 100);
```

This script illustrates the power of the CLR + native combination. The hook on `Validate()` directly calls each computation method in order — `ComputeUserHash`, `CheckSegmentB`, `ComputeCrossXor`, `ComputeFinalChecksum` — passing them the correct values (not those from the dummy key). The native hooks fire synchronously during the P/Invoke calls traversed by `CheckSegmentB` and `ComputeFinalChecksum`, capturing segment B and the native checksum. The result is a functional keygen in a single pass, which required no understanding of the internal algorithms.

## Step 5 — Interception with GDB

Frida is not the only tool capable of intercepting P/Invoke calls on the native side. GDB, with the GEF or pwndbg extensions (chapter 12), works just as well on a .NET process.

### Attaching GDB to a .NET process

```bash
# Launch the application
cd binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64  
LD_LIBRARY_PATH=. ./LicenseChecker &  
PID=$!  

# Attach GDB
gdb -p $PID
```

GDB attaches to the process. You will see a large number of threads (the CoreCLR runtime creates threads for the GC, the JIT, the finalizer, etc.). The main thread is typically blocked waiting for input (on `read` or `fgets`).

### Setting a breakpoint on the native function

```gdb
# Load the symbols from libnative_check.so (if it is already loaded)
info sharedlibrary
# → libnative_check.so should appear in the list

# Breakpoint on the exported function
break compute_native_hash  
break compute_checksum  

# Resume execution
continue
```

At this point, the program is waiting for the user to enter a username and a key. You must provide a key whose **segment A is correct** so that `Validate()` passes the first check and reaches `CheckSegmentB` — that is where the P/Invoke calls `compute_native_hash`. If segment A for `alice` is `7B3F`, type `alice` and `7B3F-0000-0000-0000` in the application terminal. The breakpoint on `compute_native_hash` triggers.

> 💡 If you enter a key with an incorrect segment A, `Validate()` returns before calling `CheckSegmentB` and the native breakpoints never trigger. This is the direct consequence of the sequential flow with early return in the C# code.

```gdb
# We are stopped at the entry of compute_native_hash.
# Inspect the arguments (System V AMD64 ABI):
#   rdi = pointer to data
#   rsi = length

info registers rdi rsi

# Read the buffer contents (the lowercase username)
x/s $rdi
# → "alice"

# Display the length
print (int)$rsi
# → 5

# Execute until the function returns
finish

# Read the return value (in rax)
print/x $rax
# → 0x<expected segment B>
```

The `finish` command executes the function until its `ret` and stops immediately after. The value in `rax` is the native hash — the expected segment B. This is the same information captured by the Frida hook, obtained here with GDB.

> 💡 If `libnative_check.so` is not yet loaded at the time of attachment (because the user has not yet submitted a key), GDB will not be able to resolve the symbol `compute_native_hash`. You can then use a *catchpoint* on `dlopen` to detect the loading:  
>  
> ```gdb  
> catch syscall openat  
> continue  
> # Submit a key in the application...  
> # GDB stops on the openat of libnative_check.so  
> # Now the library is loaded, we can set the breakpoint  
> break compute_native_hash  
> continue  
> ```

## Marshalling in detail: what you need to know

When intercepting a P/Invoke call on the native side, the arguments you observe are the result of the marshalling performed by the CLR. Understanding this marshalling is essential for correctly interpreting the values observed in GDB or Frida.

### Blittable types

Certain types have an identical memory representation in C# and C. The CLR passes them directly, without transformation. This is the case for `int`, `uint`, `long`, `double`, `byte`, and pointers (`IntPtr`). In our `LicenseChecker`, the arguments `uint segA`, `uint segB`, `uint segC` of `compute_checksum` are blittable: the values in registers `rdi`, `rsi`, `rdx` are directly the C# integers without any conversion.

### Arrays

A C# `byte[]` is a managed object with an object header, a length field, then the data. The CLR does not pass the entire object to native code — it passes a pointer to the data area (skipping the header and length). The array is pinned in memory during the call. This is why, in our hook on `compute_native_hash`, `args[0]` points directly to the username bytes, not to the complete `byte[]` object.

### Strings

String marshalling depends on the `[MarshalAs]` attribute. In our `NativeBridge`, the `VerifyIntegrity` method declares its `username` parameter with `[MarshalAs(UnmanagedType.LPStr)]`, which indicates a null-terminated ANSI (8-bit) C string. The CLR allocates a temporary buffer, copies the C# string (which is internally UTF-16) to ANSI, adds the `\0` terminator, and passes a pointer to this buffer. On the Frida side, we read this string with `Memory.readUtf8String(args[0])`.

Without `[MarshalAs]`, the default marshalling depends on the platform: `LPStr` (ANSI) on Windows with .NET Framework, `LPUTF8Str` (UTF-8) with .NET Core/5+. This is a classic RE pitfall: the same P/Invoke declaration can produce different marshalling depending on the runtime.

### Structures

For `struct` types passed by value, the CLR reproduces the memory layout respecting the alignments specified by `[StructLayout]`. Blittable structures are passed directly; others are marshalled into a temporary buffer. Our `LicenseChecker` does not use P/Invoke structures, but this is a common pattern in real-world applications (Win32 structures such as `RECT`, `POINT`, `SECURITY_ATTRIBUTES`, etc.).

## Common RE cases: what lies behind P/Invoke calls

Beyond our educational exercise, P/Invoke calls in real-world applications typically point to a limited number of library categories. Recognizing them speeds up the analysis.

**Delegated license checks.** This is our scenario. The developer places the sensitive logic in a native library to make it harder to decompile (no .NET metadata). In practice, this strategy offers little additional protection: the native library remains analyzable with the tools from Parts II through V, and the P/Invoke bridge creates a convenient interception point.

**Cryptographic libraries.** Calls to OpenSSL (`libssl.so`), libsodium, or a custom crypto library. The arguments are buffers (keys, plaintexts, ciphertexts) and sizes. Interception allows extracting keys in transit — the same technique as in chapter 24.

**Unexposed system APIs.** Direct calls to `libc` (`open`, `read`, `write`, `mmap`, `ptrace`) or to kernel-specific APIs. Often related to anti-debug mechanisms or integrity checks.

**Legacy code.** Old C/C++ libraries wrapped in a .NET interface. P/Invoke is the interoperability mechanism, not a protection measure. Interception is trivial.

## P/Invoke interception workflow summary

To synthesize the complete approach when facing an unknown P/Invoke call:

Start by **identifying** the `[DllImport]` declarations in the .NET assembly (dnSpy, `monodis`, ILSpy). Note the library name, entry point, calling convention, and marshalling attributes.

Then **inspect** the native library with the classic tools (`file`, `nm`, `strings`, `objdump`, Ghidra). Locate the target functions, understand their actual C signature, and analyze their logic if necessary.

**Intercept** the calls — on the managed side with Frida CLR (section 32.2), on the native side with Frida `Interceptor` or GDB. Native-side interception is more reliable and gives access to arguments after marshalling (i.e., as the C code receives them).

**Correlate** both sides. The arguments observed on the native side should match the values passed on the managed side (after marshalling). If a discrepancy appears, it is a clue that the marshalling is doing something unexpected — a custom `[MarshalAs]`, a string transformation, a structure marshalled differently from what was expected.

Finally, **exploit** the results: capture sensitive values (keys, hashes, tokens), bypass checks (by modifying the return value), or completely replace the native function (by redirecting the call to our own implementation with `Interceptor.replace` or `LD_PRELOAD`, as seen in chapter 22).

---


⏭️ [Patching a .NET Assembly on the Fly (Modifying IL with dnSpy)](/32-dynamic-analysis-dotnet/04-patching-il-dnspy.md)
