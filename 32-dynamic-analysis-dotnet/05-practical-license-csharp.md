🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 32.5 — Practical Exercise: Bypassing a C# License Check

> 📁 **Files used**: `binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64/LicenseChecker.dll`, `binaries/ch32-dotnet/native/libnative_check.so`  
> 🔧 **Tools**: dnSpy, Frida, GDB/GEF, nm, strings, objdump  
> 📖 **Prerequisites**: Sections [32.1](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md) through [32.4](/32-dynamic-analysis-dotnet/04-patching-il-dnspy.md)

---

## Objective and context

This practical exercise brings together all the techniques seen in the four previous sections to achieve two distinct objectives on our `LicenseChecker` application:

**Objective 1 — Keygen.** Understand the validation scheme, extract the algorithms, and write a key generator capable of producing a valid license for any username. This objective requires reversing both sides of the managed–native bridge: the C# hash (segment A), the native hash (segment B), the cross XOR (segment C), and the combined checksum (segment D).

**Objective 2 — Universal patch.** Produce a modified version of `LicenseChecker.dll` that accepts any key without verification. This objective is faster to achieve but less educational — we do not understand the algorithms, we neutralize them.

The approach follows the RE workflow that the previous chapters have built: triage, static analysis, dynamic analysis, exploitation. Each phase calls upon specific tools and each discovery feeds into the next.

---

## Phase 1 — Triage and reconnaissance

We start with the same reflex as in chapter 5: assess the target before diving into the details.

### Inspecting the deliverable

The publish directory contains several files. `LicenseChecker.dll` is the main assembly — this is our managed target. `LicenseChecker.runtimeconfig.json` indicates the target framework (.NET 8.0). `libnative_check.so` is the native library called via P/Invoke.

```bash
cd binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64

file LicenseChecker.dll
# → PE32 executable (console) Intel 80386 Mono/.Net assembly, ...

file libnative_check.so
# → ELF 64-bit LSB shared object, x86-64, dynamically linked, ...

strings LicenseChecker.dll | grep -i licen
# → LicenseValidator
# → LicenseChecker
# → LicenseLevel
# → ValidationResult
# → License valid
# → License invalid
# → libnative_check.so
# → compute_native_hash
# → compute_checksum
# → verify_integrity
```

The `strings` command on the .NET assembly is immediately revealing. Unlike a stripped native binary where `strings` only captures literals, a .NET assembly retains all type names, method names, field names, and strings in its metadata tables. We see the class names (`LicenseValidator`, `ValidationResult`), the P/Invoke function names (`compute_native_hash`, `compute_checksum`, `verify_integrity`), and the user-facing messages (`License valid`, `License invalid`). The native library name (`libnative_check.so`) is also present in cleartext.

On the native side, we apply the standard triage:

```bash
nm -D libnative_check.so
# → T compute_checksum
# → T compute_native_hash
# → T verify_integrity

strings libnative_check.so
# → NATIVERE

objdump -d -M intel libnative_check.so | head -80
```

The exported symbol `compute_native_hash` and the string `"NATIVERE"` confirm the expected structure. All three functions are visible and analyzable.

### First run

We launch the application to observe its nominal behavior:

```
$ LD_LIBRARY_PATH=. ./LicenseChecker

    ╔══════════════════════════════════════════╗
    ║   LicenseChecker v3.2.1 — Ch.32 RE Lab   ║
    ║   © 2025 RE Training GCC/G++               ║
    ╚══════════════════════════════════════════╝

  Username    : alice
  License key : AAAA-BBBB-CCCC-DDDD

  ╔═══════════════════════════════════════╗
  ║  ❌  License invalid.                 ║
  ╚═══════════════════════════════════════╝

  Reason: Segment 1 invalid (tied to username).
```

The error message is valuable. "Segment 1 invalid (tied to username)" tells us that validation fails at the very first segment, and that this segment depends on the username. This is an anchor point for the analysis.

---

## Phase 2 — Static analysis in dnSpy

We open `LicenseChecker.dll` in dnSpy. The decompiled code is immediately readable — the assembly is not obfuscated.

### Mapping the validation flow

Examining `LicenseValidator.Validate()`, we reconstruct the complete scheme. The method performs five sequential steps. If any step fails, it immediately returns a `ValidationResult` with `IsValid = false` and a specific error message. If all steps succeed, it returns `IsValid = true`.

The structure is linear — no loops, no recursion, no callbacks. Each step is isolated in its own private method. This is an architecture favorable to RE: we can attack each segment independently.

### Segment A analysis: `ComputeUserHash()`

The decompiled code of `ComputeUserHash` reveals a standard FNV-1a algorithm. We identify the characteristic constants: `0x811C9DC5` (32-bit offset basis) and `0x01000193` (prime). The username is converted to lowercase, concatenated with a salt (`MagicSalt`), then hashed. The 32-bit result is folded to 16 bits by XOR-ing the high and low halves.

Inspecting the `MagicSalt` field, we read its bytes: `0x52, 0x45, 0x56, 0x33, 0x52, 0x53, 0x45, 0x21`. Converting to ASCII: `"REV3RSE!"`. This is the managed salt.

We now have all the information to implement the segment A computation in Python.

### Segment B analysis: `CheckSegmentB()` and the P/Invoke bridge

The code in `CheckSegmentB` calls `NativeBridge.ComputeNativeHash(data, data.Length)` then compares the result (masked to 16 bits) with the supplied segment B. The P/Invoke declaration in `NativeBridge` points to `compute_native_hash` in `libnative_check.so`.

To understand the native algorithm, two options are available: reverse the `.so` library with native tools, or capture the value dynamically. We will do both — the first for the keygen, the second to validate our understanding.

We open `libnative_check.so` in Ghidra. The decompilation of `compute_native_hash` reveals the same FNV-1a algorithm as on the C# side, but with a different salt. Examining the bytes referenced in the function, we find: `0x4E, 0x41, 0x54, 0x49, 0x56, 0x45, 0x52, 0x45` → `"NATIVERE"`.

This is the trap the chapter foreshadowed: both sides use the same hash algorithm (FNV-1a) but with different salts (`"REV3RSE!"` on the C# side, `"NATIVERE"` on the native side). A reverse engineer who only looked at the C# code and assumed the native hash was identical would produce an incorrect segment B.

### Segment C analysis: `ComputeCrossXor()`

The decompiled code is explicit: left rotation of 5 bits of `segA` (on 16 bits), XOR with `segB`, multiplication by `0x9E37`, masking to 16 bits, XOR with `0xA5A5`. All constants are visible in the decompiled code — no native call involved here.

### Segment D analysis: `ComputeFinalChecksum()`

Segment D combines a managed part (sum of A + B + C, masked to 16 bits) and a native part (return value of `compute_checksum(A, B, C)` via P/Invoke). The final result is the XOR of the two parts, masked to 16 bits.

We return to Ghidra to analyze `compute_checksum`. The decompilation shows a sequence of rotations and XOR operations with the three input segments, followed by a multiplication by `0x5BD1` and an XOR with `0x1337`. All constants are extractable.

### Static analysis summary

At this point, we have a complete understanding of the license scheme:

```
Username → lowercase → UTF-8 bytes

Segment A = fold16(FNV-1a(bytes || "REV3RSE!"))  
Segment B = fold16(FNV-1a(bytes || "NATIVERE"))  
Segment C = ((rotl5_16(A) ^ B) * 0x9E37 & 0xFFFF) ^ 0xA5A5  
Segment D = (A + B + C) & 0xFFFF) ^ native_checksum(A, B, C)  

where:
  fold16(h)          = (h >> 16) ^ (h & 0xFFFF)
  rotl5_16(x)        = ((x << 5) | (x >> 11)) & 0xFFFF
  native_checksum    = ((((rotl3_16(A) ^ B) >> 7 | ... ) * 0x5BD1) ^ 0x1337
```

We could stop here and write the keygen. But the dynamic phase will allow us to validate this understanding — and to demonstrate the techniques from sections 32.1 through 32.3.

---

## Phase 3 — Dynamic validation

### Debugging with dnSpy (§32.1)

We launch `LicenseChecker` in the dnSpy debugger. We set breakpoints on the five comparison points in `Validate()`. We enter `alice` as the username and `0000-0000-0000-0000` as the key.

Execution stops at the first check (segment A). In the Locals window, we read the value of `expectedA`. Suppose it is `0x7B3F`. We note this value.

We use **Set Next Statement** to skip the failure block and reach the second check. Execution attempts to call `CheckSegmentB`, which triggers the loading of `libnative_check.so` and the P/Invoke call. In Locals, we read the value of `expected` in `CheckSegmentB` — this is segment B. Suppose `0xD4A2`.

We continue in the same manner for segments C and D, forcing the previous comparisons to succeed (by modifying variables in Locals). At the end, we have all four values:

```
alice → 7B3F-D4A2-????-????
```

Segments C and D depend on the correct values of A and B. To obtain them, we relaunch the debugger with the partially correct key `7B3F-D4A2-0000-0000`. This time, checks A and B pass, and we reach checks C and D with the correct intermediate values. We read `expectedC` and `expectedD`. The complete key is built iteratively.

### Frida hooking — automated capture (§32.2 + §32.3)

Iterative debugging works but requires several manual passes. The combined Frida script from section 32.3 automates everything in a single execution. The key point: the original `Validate()` method returns on the first failed check, so a simple wrapper is not enough. The script short-circuits this flow by directly calling each computation method (`ComputeUserHash`, `CheckSegmentB`, `ComputeCrossXor`, `ComputeFinalChecksum`) in the right order, with the correct values. The native hooks on `compute_native_hash` and `compute_checksum` fire synchronously during the P/Invoke calls, capturing the native-side values. We launch:

```bash
frida -f ./LicenseChecker --runtime=clr -l keygen_complete.js
```

The application starts under Frida's control. We enter `alice` and `0000-0000-0000-0000`. The `Validate` hook calls the computation methods directly, the native hooks capture segment B along the way, and the complete key is displayed:

```
╔═════════════════════════════════════════════╗
║      COMPLETE KEYGEN — CLR + NATIVE         ║
╠═════════════════════════════════════════════╣
║  Username  : alice                          ║
║  Segment A : 7B3F                           ║
║  Segment B : D4A2                           ║
║  Segment C : E819                           ║
║  Segment D : 5CF6                           ║
║                                             ║
║  VALID KEY: 7B3F-D4A2-E819-5CF6             ║
╚═════════════════════════════════════════════╝
```

> 💡 The values above are fictional — they depend on the exact implementation of the algorithms. Your actual values will differ.

We verify by relaunching the application without Frida, with the obtained key:

```
$ LD_LIBRARY_PATH=. ./LicenseChecker alice 7B3F-D4A2-E819-5CF6

  ╔═══════════════════════════════════╗
  ║  ✅  License valid! Welcome.      ║
  ╚═══════════════════════════════════╝

  Username   : alice
  Level      : Professional
  Expiration : Perpetual
```

The key is valid. The dynamic phase confirms our static understanding.

---

## Phase 4 — Writing the keygen

Armed with the static analysis (complete algorithms) and the dynamic validation (reference values), we write a standalone keygen in Python. This script needs no external tools — it reimplements the computation algorithms for each segment.

```python
#!/usr/bin/env python3
"""
keygen.py — Key generator for LicenseChecker (Chapter 32)

Reimplements the 4 segments of the license scheme:
  A = fold16(FNV-1a(username || "REV3RSE!"))
  B = fold16(FNV-1a(username || "NATIVERE"))
  C = ((rotl5(A) ^ B) * 0x9E37 & 0xFFFF) ^ 0xA5A5
  D = ((A + B + C) & 0xFFFF) ^ native_checksum(A, B, C)

Usage:
  python3 keygen.py <username>
"""

import sys


# ── FNV-1a 32-bit ──────────────────────────────────────────────────

FNV_OFFSET = 0x811C9DC5  
FNV_PRIME  = 0x01000193  
MASK32     = 0xFFFFFFFF  
MASK16     = 0xFFFF  


def fnv1a_32(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK32
    return h


def fold16(h: int) -> int:
    return ((h >> 16) ^ (h & MASK16)) & MASK16


# ── Segment A: managed hash (salt = "REV3RSE!") ──────────────────

def compute_segment_a(username: str) -> int:
    data = username.lower().encode("utf-8") + b"REV3RSE!"
    return fold16(fnv1a_32(data))


# ── Segment B: native hash (salt = "NATIVERE") ───────────────────

def compute_segment_b(username: str) -> int:
    data = username.lower().encode("utf-8") + b"NATIVERE"
    return fold16(fnv1a_32(data))


# ── Segment C: cross XOR with rotation ───────────────────────────

def rotl16(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (16 - shift))) & MASK16


def compute_segment_c(seg_a: int, seg_b: int) -> int:
    rot_a = rotl16(seg_a, 5)
    result = rot_a ^ seg_b
    result = (result * 0x9E37) & MASK16
    result ^= 0xA5A5
    return result


# ── Segment D: final checksum (managed ^ native) ─────────────────

def native_checksum(seg_a: int, seg_b: int, seg_c: int) -> int:
    val = seg_a & MASK16
    # Left rotation 3 bits (16-bit)
    val = rotl16(val, 3)
    val ^= seg_b & MASK16
    # Right rotation 7 bits (16-bit) = left rotation 9 bits
    val = rotl16(val, 9)
    val ^= seg_c & MASK16
    # Multiplicative mixing
    val = (val * 0x5BD1) & MASK16
    val ^= 0x1337
    return val


def compute_segment_d(seg_a: int, seg_b: int, seg_c: int) -> int:
    managed = (seg_a + seg_b + seg_c) & MASK16
    native  = native_checksum(seg_a, seg_b, seg_c)
    return (managed ^ native) & MASK16


# ── Entry point ──────────────────────────────────────────────────

def keygen(username: str) -> str:
    a = compute_segment_a(username)
    b = compute_segment_b(username)
    c = compute_segment_c(a, b)
    d = compute_segment_d(a, b, c)
    return f"{a:04X}-{b:04X}-{c:04X}-{d:04X}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <username>")
        sys.exit(1)

    username = sys.argv[1]
    key = keygen(username)

    print(f"  Username : {username}")
    print(f"  Key      : {key}")
```

We validate the keygen:

```bash
$ python3 keygen.py alice
  Username : alice
  Key      : 7B3F-D4A2-E819-5CF6

$ LD_LIBRARY_PATH=. ./LicenseChecker alice 7B3F-D4A2-E819-5CF6
  ✅  License valid! Welcome.

$ python3 keygen.py bob
  Username : bob
  Key      : 39F1-AB07-C4E3-8D2A

$ LD_LIBRARY_PATH=. ./LicenseChecker bob 39F1-AB07-C4E3-8D2A
  ✅  License valid! Welcome.
```

The keygen works for any username. Objective 1 is achieved.

---

## Phase 5 — Universal patch

The second objective — a patched version that accepts any key — is accomplished in a few minutes with dnSpy.

### Approach 1: C# rewrite of `Validate()`

We open `LicenseChecker.dll` in dnSpy. Right-click on `Validate()` → **Edit Method (C#)**. We replace the body:

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

Compile → **File → Save Module** under the name `LicenseChecker_patched.dll`. We copy this file in place of the original. Any username/key combination is accepted.

This is the fastest and most robust method. It entirely removes the dependency on `libnative_check.so` — the patched application works even if the native library is absent, since the P/Invoke calls are never reached.

### Approach 2: minimal IL patching

If we prefer a less visible patch — one that leaves the validation logic in place but neutralizes all four checks — we use the IL editor.

For each validation step, we identify the conditional branch that leads to the failure block and transform it into an unconditional branch to the continuation. In practice, in the IL code of `Validate()`, we look for the following patterns:

```
ldloc  actualX          ← load the value supplied by the user  
ldloc  expectedX        ← load the expected value  
bne.un IL_FAIL_X        ← if different, jump to the failure block  
```

For each of these four patterns, we replace `bne.un IL_FAIL_X` with `pop` + `pop` + `br IL_NEXT_X` — we pop the two comparison values and unconditionally branch to the next step. The second check (segment B) has a slightly different pattern since it goes through `CheckSegmentB` which returns a boolean, but the principle is the same: we replace the `brfalse` with a `pop` + `br`.

> Why `pop` + `pop` + `br` rather than simply replacing `bne.un` with `br`? Because `bne.un` consumes two values from the stack (the two comparison operands), while `br` consumes none. If we replaced directly without popping, the stack would be inconsistent and the IL verifier would reject the bytecode.

After patching the four branches, we save. The modified application executes the entire validation flow — it computes the hashes, calls the native functions, performs the XOR operations — but silently ignores the comparison results. Every step "succeeds" regardless of the input.

### Approach 3: `LD_PRELOAD` on the native library

To complete the panorama, we can also intervene on the native side without touching the .NET assembly. The `LD_PRELOAD` technique seen in chapter 22 allows replacing `libnative_check.so` with our own version that returns controlled values.

We write a `fake_native.c` file:

```c
#include <stdint.h>

uint32_t compute_native_hash(const uint8_t *data, int length)
{
    (void)data; (void)length;
    return 0x0000;  /* Always returns 0 */
}

uint32_t compute_checksum(uint32_t a, uint32_t b, uint32_t c)
{
    (void)a; (void)b; (void)c;
    return (a + b + c) & 0xFFFF;  /* Returns the sum (= managed part) */
}

int verify_integrity(const char *u, uint32_t a, uint32_t b,
                     uint32_t c, uint32_t d)
{
    (void)u; (void)a; (void)b; (void)c; (void)d;
    return 1;  /* Always valid */
}
```

```bash
gcc -shared -fPIC -o fake_native.so fake_native.c  
LD_PRELOAD=./fake_native.so LD_LIBRARY_PATH=. ./LicenseChecker  
```

This approach does not bypass the C#-side validation — you still need to provide a key whose segment A matches the managed hash and whose subsequent segments are consistent with the values returned by the fake library. It is therefore a partial tool, useful for isolating native behavior during analysis, but insufficient for a complete bypass on its own.

---

## Phase 6 — Summary and comparison of approaches

Each technique employed in this practical exercise has its strengths and limitations. The table below puts them in perspective to guide the choice in real-world situations.

| Approach | Effort | Result | Understanding gained | Detectability |  
|---|---|---|---|---|  
| **dnSpy debugging** (iterative) | Medium | Valid key for 1 username | Partial (values observed, not algorithms) | No trace on disk |  
| **Frida hooking** (dynamic keygen) | Medium | Valid key for 1 username per execution | Partial (same) | No trace on disk |  
| **Python keygen** (reimplementation) | High | Valid key for any username, offline | Complete (all algorithms understood) | None — standalone program |  
| **C# patch in dnSpy** | Low | Permanent universal bypass | Minimal (we know where the check is, not how) | Modified assembly (hash, size, signature) |  
| **Minimal IL patch** | Medium | Permanent universal bypass | Partial (flow structure understood) | Modified assembly (less visible) |  
| **`LD_PRELOAD`** | Low | Control of native side only | Partial (P/Invoke interface understood) | Additional `.so` file |

In practice, an experienced reverse engineer combines these approaches. They start with Frida hooking for a quick result (obtaining a valid key in a few minutes), then go deeper with static analysis to write a standalone keygen. The IL patch is reserved for situations where a permanent modification is needed and a keygen is not an option (for example, software that checks the license continuously during operation, not just at startup).

---

## Chapter recap

This practical exercise concludes chapter 32. Starting from an unknown .NET assembly accompanied by a native library, we went through a complete dynamic reverse engineering cycle:

In **section 32.1**, we discovered that dnSpy transforms debugging a .NET program without sources into an experience comparable to that of a developer in their IDE. Breakpoints on decompiled code, variable inspection, execution flow modification — all capabilities that make .NET dynamic analysis qualitatively more comfortable than its native equivalent with GDB.

In **section 32.2**, we extended this capability with Frida and its CLR bridge, moving from manual observation (one breakpoint at a time) to programmable instrumentation (hooks on all interesting methods simultaneously). The hooking keygen illustrates a powerful paradigm: we do not reverse the algorithm, we let the algorithm compute and we capture its results.

In **section 32.3**, we crossed the P/Invoke bridge to reach native code that the managed world cannot see. The combination of Frida CLR + native Frida in a single script allowed us to complete the keygen where managed hooking alone failed. GDB showed that the tools from chapter 11 apply without modification to native code called by a .NET process.

In **section 32.4**, we moved from ephemeral intervention to permanent patching. C# editing in dnSpy offers comfort with no equivalent in the native world. IL editing allows surgical patches when a complete rewrite is disproportionate. Metadata is an additional intervention surface, often underestimated.

This practical exercise showed how these four skills compose to achieve objectives of increasing complexity — from capturing a single value in the debugger to writing a standalone keygen that reimplements the entire validation scheme.

---


⏭️ [🎯 Checkpoint: Patch and Keygen the Provided .NET Application](/32-dynamic-analysis-dotnet/checkpoint.md)
