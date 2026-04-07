🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 32 Checkpoint

> **Spoilers** — Only consult this page after attempting the checkpoint yourself.

---

## Deliverable 1 — Frida Capture Script (`capture.js`)

```javascript
// capture.js — Combined CLR + native Frida script
//
// Usage (spawn):
//   frida -f ./LicenseChecker --runtime=clr -l capture.js
//
// Usage (attach):
//   frida -p <PID> --runtime=clr -l capture.js
//
// Enter any username and a fake key (e.g.: 0000-0000-0000-0000).
// The script displays the valid key computed by the application itself.

"use strict";

const seg = { A: null, B: null, C: null, D: null };  
const hex4 = (v) =>  
    v !== null
        ? (v >>> 0).toString(16).toUpperCase().padStart(4, "0")
        : "????";

// ═══════════════════════════════════════════════════════════
//  NATIVE HOOKS — libnative_check.so
// ═══════════════════════════════════════════════════════════

function installNativeHooks() {
    const mod = Process.findModuleByName("libnative_check.so");
    if (!mod) return false;

    // ── compute_native_hash → segment B ──
    const hashAddr = Module.findExportByName(
        "libnative_check.so", "compute_native_hash"
    );
    if (hashAddr) {
        Interceptor.attach(hashAddr, {
            onEnter(args) {
                this.len = args[1].toInt32();
                this.data = Memory.readUtf8String(args[0], this.len);
                console.log(`  [native] compute_native_hash("${this.data}", ${this.len})`);
            },
            onLeave(retval) {
                seg.B = retval.toUInt32() & 0xFFFF;
                console.log(`  [native]   → 0x${hex4(seg.B)}  (segment B)`);
            }
        });
    }

    // ── compute_checksum → native part of segment D ──
    const chkAddr = Module.findExportByName(
        "libnative_check.so", "compute_checksum"
    );
    if (chkAddr) {
        Interceptor.attach(chkAddr, {
            onEnter(args) {
                const a = args[0].toUInt32() & 0xFFFF;
                const b = args[1].toUInt32() & 0xFFFF;
                const c = args[2].toUInt32() & 0xFFFF;
                console.log(`  [native] compute_checksum(` +
                    `0x${hex4(a)}, 0x${hex4(b)}, 0x${hex4(c)})`);
            },
            onLeave(retval) {
                const v = retval.toUInt32() & 0xFFFF;
                console.log(`  [native]   → 0x${hex4(v)}  (native checksum)`);
            }
        });
    }

    console.log("[+] Native hooks installed on libnative_check.so");
    return true;
}

// ═══════════════════════════════════════════════════════════
//  CLR HOOKS — managed methods
// ═══════════════════════════════════════════════════════════

function installCLRHooks() {
    const klass = CLR.classes["LicenseChecker.LicenseValidator"];
    if (!klass) return false;

    // ── Main hook: Validate ──
    //
    // Crucial point: the original Validate() method is sequential
    // with early return. If segment A is incorrect, it returns
    // immediately without ever calling CheckSegmentB,
    // ComputeCrossXor, etc.
    // With a fake key, only ComputeUserHash would be reached.
    //
    // Solution: our hook directly calls each computation method
    // in the correct order, passing them the right values,
    // instead of delegating to the original implementation.
    // Native hooks fire synchronously during P/Invoke calls
    // (CheckSegmentB and ComputeFinalChecksum), capturing
    // seg.B on the native side.

    klass.methods["Validate"].implementation = function (username, licenseKey) {
        console.log("\n┌──────────────────────────────────────────────┐");
        console.log(`│  Validate("${username}", "${licenseKey}")`);
        console.log("├──────────────────────────────────────────────┤");

        // Reset captures
        seg.A = seg.B = seg.C = seg.D = null;

        // ── Segment A: direct call to ComputeUserHash ──
        seg.A = this.ComputeUserHash(username) & 0xFFFF;
        console.log(`│  [CLR] Segment A = 0x${hex4(seg.A)}`);

        // ── Segment B: trigger CheckSegmentB to invoke the
        //    P/Invoke call. The native hook captures seg.B. ──
        try {
            this.CheckSegmentB(username, 0);
        } catch (e) {
            console.log(`│  [!] CheckSegmentB exception: ${e}`);
        }
        if (seg.B !== null) {
            console.log(`│  [native] Segment B = 0x${hex4(seg.B)}`);
        } else {
            console.log("│  [!] Segment B not captured (native lib missing?)");
        }

        // ── Segment C: call with real A and B ──
        if (seg.B !== null) {
            seg.C = this.ComputeCrossXor(seg.A, seg.B) & 0xFFFF;
            console.log(`│  [CLR] Segment C = 0x${hex4(seg.C)}`);
        }

        // ── Segment D: call with real A, B, C ──
        if (seg.B !== null && seg.C !== null) {
            seg.D = this.ComputeFinalChecksum(
                seg.A, seg.B, seg.C, username) & 0xFFFF;
            console.log(`│  [CLR] Segment D = 0x${hex4(seg.D)}`);
        }

        console.log("├──────────────────────────────────────────────┤");

        if (seg.A !== null && seg.B !== null &&
            seg.C !== null && seg.D !== null) {
            const key = `${hex4(seg.A)}-${hex4(seg.B)}-${hex4(seg.C)}-${hex4(seg.D)}`;
            console.log("│");
            console.log(`│  ★ VALID KEY: ${key}`);
        } else {
            console.log("│");
            console.log("│  ⚠ Incomplete capture:");
            console.log(`│    A=${hex4(seg.A)} B=${hex4(seg.B)} C=${hex4(seg.C)} D=${hex4(seg.D)}`);
        }
        console.log("└──────────────────────────────────────────────┘\n");

        // Call the original (it will fail at segment A, but we already
        // have our values — the program will display its message).
        return this.Validate(username, licenseKey);
    };

    console.log("[+] CLR hooks installed on LicenseValidator");
    return true;
}

// ═══════════════════════════════════════════════════════════
//  ORCHESTRATION — wait for both sides to load
// ═══════════════════════════════════════════════════════════

let nativeOk = false;  
let clrOk    = false;  

console.log("[*] Waiting for assembly and native library to load...");

const poll = setInterval(() => {
    if (!nativeOk) {
        nativeOk = installNativeHooks();
    }

    if (!clrOk) {
        try {
            if (CLR && CLR.assemblies && CLR.assemblies["LicenseChecker"]) {
                clrOk = installCLRHooks();
            }
        } catch (e) { /* CLR not ready yet */ }
    }

    if (clrOk) {
        // The native lib is loaded at the first P/Invoke — retry
        if (!nativeOk) {
            nativeOk = installNativeHooks();
        }
    }

    if (clrOk && nativeOk) {
        clearInterval(poll);
        console.log("\n[+] All hooks active. Enter a username and a key.\n");
    }
}, 100);

// Timeout: if after 10s the native hooks aren't installed,
// continue — they'll be installed at the first P/Invoke call
setTimeout(() => {
    if (clrOk && !nativeOk) {
        console.log("[*] CLR hooks active, native hooks pending " +
                    "(lib will be hooked at first P/Invoke call).");
        const nativePoll = setInterval(() => {
            if (installNativeHooks()) {
                clearInterval(nativePoll);
            }
        }, 20);
    }
}, 10000);
```

### Notes on the Solution

The script handles three specific challenges:

**The early return from `Validate()`.** This is the crucial point. The original `Validate()` implementation is sequential: if segment A is incorrect, it returns immediately without ever calling `CheckSegmentB`, `ComputeCrossXor`, or `ComputeFinalChecksum`. With a fake key like `0000-0000-0000-0000`, only `ComputeUserHash` would be reached by the original. The solution is not to delegate to the original for the capture phase: the hook directly calls each computation method in the correct order, passing them the right values (the freshly computed segment A, then B captured on the native side, etc.). The original is only called at the end, so the program displays its message normally.

**The lazy loading of the `.so`.** The native library is only loaded by the CLR at the first P/Invoke call. In `spawn` mode, the process starts under Frida's control before the user has submitted a key — so the library isn't yet in memory. The periodic polling in the orchestrator detects the module's appearance and installs the native hooks as soon as it's available. The `Validate` hook itself triggers the loading by calling `CheckSegmentB`, which causes the P/Invoke call and thus the `dlopen` of the library.

**The synchronicity of native hooks.** When the CLR hook `Validate` calls `this.CheckSegmentB(username, 0)`, that call descends to `NativeBridge.ComputeNativeHash` via P/Invoke, which executes `compute_native_hash` in `libnative_check.so`. The native hook `Interceptor.attach` on `compute_native_hash` fires **synchronously** during that call — when `CheckSegmentB` returns, `seg.B` is already populated. This is what allows the script to immediately proceed with `ComputeCrossXor(seg.A, seg.B)` without waiting.

---

## Deliverable 2 — Python Keygen (`keygen.py`)

```python
#!/usr/bin/env python3
"""
keygen.py — Key generator for LicenseChecker (Chapter 32)

Validation scheme:
  Segment A = fold16(FNV-1a(lowercase(username) || b"REV3RSE!"))
  Segment B = fold16(FNV-1a(lowercase(username) || b"NATIVERE"))
  Segment C = ((rotl16(A, 5) ^ B) * 0x9E37 & 0xFFFF) ^ 0xA5A5
  Segment D = ((A + B + C) & 0xFFFF) ^ native_checksum(A, B, C)

  native_checksum(A, B, C):
      val = rotl16(A, 3) ^ B
      val = rotl16(val, 9) ^ C      # rotl16(x, 9) == rotr16(x, 7)
      val = (val * 0x5BD1) & 0xFFFF
      val ^= 0x1337

Usage:
  python3 keygen.py <username>
  python3 keygen.py --test          # validate on multiple usernames
"""

import sys

# ── Constants ────────────────────────────────────────────────────────

FNV_OFFSET = 0x811C9DC5  
FNV_PRIME  = 0x01000193  
MASK32     = 0xFFFFFFFF  
MASK16     = 0xFFFF  

SALT_MANAGED = b"REV3RSE!"   # C# salt (segment A)  
SALT_NATIVE  = b"NATIVERE"   # Native salt (segment B)  


# ── Primitives ────────────────────────────────────────────────────────

def fnv1a_32(data: bytes) -> int:
    """FNV-1a 32-bit hash."""
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK32
    return h


def fold16(h: int) -> int:
    """XOR fold 32→16 bits."""
    return ((h >> 16) ^ (h & MASK16)) & MASK16


def rotl16(value: int, shift: int) -> int:
    """16-bit left rotation."""
    value &= MASK16
    return ((value << shift) | (value >> (16 - shift))) & MASK16


# ── Segment computation ──────────────────────────────────────────────

def segment_a(username: str) -> int:
    """Segment A — Managed FNV-1a hash, salt = 'REV3RSE!'."""
    data = username.lower().encode("utf-8") + SALT_MANAGED
    return fold16(fnv1a_32(data))


def segment_b(username: str) -> int:
    """Segment B — Native FNV-1a hash, salt = 'NATIVERE'."""
    data = username.lower().encode("utf-8") + SALT_NATIVE
    return fold16(fnv1a_32(data))


def segment_c(a: int, b: int) -> int:
    """Segment C — Cross XOR with rotation and multiplicative mixing."""
    rot_a = rotl16(a, 5)
    result = rot_a ^ b
    result = (result * 0x9E37) & MASK16
    result ^= 0xA5A5
    return result


def native_checksum(a: int, b: int, c: int) -> int:
    """Native part of segment D — reproduces compute_checksum() from the .so."""
    val = a & MASK16
    val = rotl16(val, 3)         # left rotation 3 bits
    val ^= b & MASK16
    val = rotl16(val, 9)         # left rotation 9 bits = right 7 bits
    val ^= c & MASK16
    val = (val * 0x5BD1) & MASK16
    val ^= 0x1337
    return val


def segment_d(a: int, b: int, c: int) -> int:
    """Segment D — XOR between managed sum and native checksum."""
    managed = (a + b + c) & MASK16
    native  = native_checksum(a, b, c)
    return (managed ^ native) & MASK16


# ── Keygen ────────────────────────────────────────────────────────────

def keygen(username: str) -> str:
    """Generates a valid license key for the given username."""
    a = segment_a(username)
    b = segment_b(username)
    c = segment_c(a, b)
    d = segment_d(a, b, c)
    return f"{a:04X}-{b:04X}-{c:04X}-{d:04X}"


# ── Tests ─────────────────────────────────────────────────────────────

def run_tests():
    """Generates keys for multiple test usernames."""
    test_users = [
        "alice",
        "bob",
        "Charlie",           # uppercase → verifies normalization
        "café",              # non-ASCII character (multi-byte UTF-8)
        "müller",            # umlaut
        "naïve",             # umlaut + accent
        "user@2025",         # special characters
        "",                  # empty (edge case — the program rejects before)
        "a",                 # very short
        "A" * 100,           # long
    ]

    print("┌──────────────────┬───────────────────────┐")
    print("│    Username      │    Generated Key      │")
    print("├──────────────────┼───────────────────────┤")

    for user in test_users:
        if not user:
            print(f"│ {'(empty)':16s} │ {'N/A — rejected by program':21s} │")
            continue
        key = keygen(user)
        display = user if len(user) <= 16 else user[:13] + "..."
        print(f"│ {display:16s} │ {key:21s} │")

    print("└──────────────────┴───────────────────────┘")
    print()
    print("Verification:")
    print("  cd binaries/ch32-dotnet/LicenseChecker/bin/Release/net8.0/linux-x64")
    print('  LD_LIBRARY_PATH=. ./LicenseChecker <username> "<key>"')


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <username>")
        print(f"       {sys.argv[0]} --test")
        sys.exit(1)

    if sys.argv[1] == "--test":
        run_tests()
    else:
        username = sys.argv[1]
        key = keygen(username)
        print(f"  Username: {username}")
        print(f"  Key     : {key}")
```

### Key Points of the Solution

**The salt trap.** This is the central point of the checkpoint. Segment A uses the salt `"REV3RSE!"` (bytes `52 45 56 33 52 53 45 21`), read from the `MagicSalt` field of `LicenseValidator`. Segment B uses the salt `"NATIVERE"` (bytes `4E 41 54 49 56 45 52 45`), read from the `NATIVE_SALT` array in `native_check.c`. If you use the same salt for both segments, the keygen produces incorrect keys for segment B.

**The lowercase normalization.** Both sides (C# and native) convert the username to lowercase before hashing. The C# code uses `username.ToLowerInvariant()`, which applies Unicode rules. The C code simply subtracts `0x20` from A-Z characters (ASCII-only conversion). For purely ASCII usernames, both conversions are identical. For usernames containing Unicode characters (like `café` or `müller`), behavior may diverge — but `ToLowerInvariant()` on an already-lowercase username is a no-op, and the C conversion only touches ASCII letters. In practice, the key is correct if the username is converted to lowercase by Python with `.lower()` before hashing.

**Right rotation 7 = left rotation 9.** In `compute_checksum`, the C code performs `(val >> 7) | (val << 9)` on 16 bits. This is a right rotation of 7 bits, which is equivalent to a left rotation of 9 bits (since 7 + 9 = 16). The keygen's `rotl16(val, 9)` function implements this correctly.

**Segment D combines two sources.** The managed part is the sum `(A + B + C) & 0xFFFF`. The native part is the return of `compute_checksum(A, B, C)`. The final result is the XOR of both. Forgetting one of the two parts produces an incorrect segment D.

---

## Deliverable 3 — Patched Assembly

### Variant A — C# Patch (`LicenseChecker_patch_csharp.dll`)

In dnSpy, right-click on `LicenseValidator.Validate()` → **Edit Method (C#)**. Replace the entire body with:

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

Click **Compile**, then **File → Save Module** → `LicenseChecker_patch_csharp.dll`.

**Why this approach eliminates the native dependency**: the new `Validate()` implementation contains no calls to `CheckSegmentB` or `ComputeFinalChecksum`, which are the two methods going through `NativeBridge`. The `[DllImport]` declarations remain in the metadata but are never invoked, so `libnative_check.so` is never loaded.

### Variant B — Minimal IL Patch (`LicenseChecker_patch_il.dll`)

Open `LicenseValidator.Validate()` in dnSpy's IL editor (right-click → **Edit IL Instructions**).

The method contains four comparison/failure blocks, one per segment. Each block follows the same pattern. Here are the modifications for each.

#### Segment A Check

Look for the sequence that compares `actualA` and `expectedA`. The exact pattern depends on compilation, but it looks like:

```
IL_XXXX: ldloc.s  V_actualA       // push actualA (uint)  
IL_XXXX: ldloc.s  V_expectedA     // push expectedA (uint)  
IL_XXXX: bne.un   IL_FAIL_A       // if ≠, jump to failure block  
```

**Modification**: replace these three instructions with:

```
IL_XXXX: pop                       // consume expectedA (residue from ldloc)  
IL_XXXX: pop                       // consume actualA (residue from ldloc)  
         nop                       // padding if necessary
```

Or, more cleanly, replace only the `bne.un IL_FAIL_A` with the following sequence (leaving the two `ldloc` in place, since they push values that must be consumed):

```
IL_XXXX: ldloc.s  V_actualA       // (unchanged)  
IL_XXXX: ldloc.s  V_expectedA     // (unchanged)  
IL_XXXX: pop                       // discard expectedA  
IL_XXXX: pop                       // discard actualA  
IL_XXXX: br       IL_NEXT_A       // jump to next check  
```

The target `IL_NEXT_A` is the instruction following the failure block — the instruction where the segment B check begins.

> **Why `pop` + `pop` + `br` and not simply `br`**: the two preceding `ldloc` pushed two values. The `bne.un` instruction consumed them; if we replace it with `br` (which consumes nothing), the stack will be inconsistent — the CLR's IL verifier will detect two excess values and throw an `InvalidProgramException`. The two `pop` instructions restore the stack to its expected state before the jump.

#### Segment B Check

The pattern is slightly different: `CheckSegmentB` returns a `bool`, and the IL code tests that boolean:

```
IL_XXXX: ldloc.s  V_segBValid     // push the boolean  
IL_XXXX: brfalse  IL_FAIL_B       // if false, jump to failure block  
```

**Modification**: replace with:

```
IL_XXXX: ldloc.s  V_segBValid     // (unchanged)  
IL_XXXX: pop                       // discard the boolean  
IL_XXXX: br       IL_NEXT_B       // jump to next check  
```

Here a single `pop` suffices since `brfalse` only consumes one value.

#### Segment C and D Checks

Same pattern as segment A — two values pushed, `bne.un` to the failure block. Same fix: `pop` + `pop` + `br` to the next section.

#### Modification Summary

| Check | Original instruction | Replacement | Stack |  
|---|---|---|---|  
| Segment A | `bne.un IL_FAIL_A` | `pop` + `pop` + `br IL_NEXT_A` | -2 + 0 = OK |  
| Segment B | `brfalse IL_FAIL_B` | `pop` + `br IL_NEXT_B` | -1 + 0 = OK |  
| Segment C | `bne.un IL_FAIL_C` | `pop` + `pop` + `br IL_NEXT_C` | -2 + 0 = OK |  
| Segment D | `bne.un IL_FAIL_D` | `pop` + `pop` + `br IL_NEXT_D` | -2 + 0 = OK |

After these four modifications, click **OK** then **File → Save Module** → `LicenseChecker_patch_il.dll`.

**Verification**: the computation logic (FNV-1a, cross XOR, checksums) still runs normally. P/Invoke calls are still made. Only the comparison results are ignored. If `libnative_check.so` is absent, the exception in `CheckSegmentB` is caught by the original code's `try/catch`, `segBValid` is `false`, but the patch jumps over the failure block anyway — the program continues.

> **Alternative IL patch variant**: instead of replacing the conditional jumps, you can replace each `ldloc.s V_actualX` with `ldloc.s V_expectedX` just before the comparison. Since both pushed values are then identical, the `bne.un` is never taken and the flow continues naturally. This approach modifies only one instruction per check (instead of three) and doesn't change the control flow structure, making it less detectable. But it only works if the `expectedX` variables are distinct local variables — which depends on the C# compiler's optimization level.

---

## Accompanying Report (template)

### Reconstructed Validation Scheme

The `LicenseChecker` application validates a key in `AAAA-BBBB-CCCC-DDDD` format (4 groups of 4 hexadecimal characters) for a given username. Each segment is computed by a distinct algorithm.

**Segment A** — FNV-1a 32-bit hash of the username (lowercase, UTF-8 encoded) concatenated with the salt `"REV3RSE!"` (8 bytes: `52 45 56 33 52 53 45 21`). The 32-bit hash is folded to 16 bits by XOR of the high and low halves. This computation is performed entirely in C# in the `ComputeUserHash()` method. FNV-1a constants: offset basis `0x811C9DC5`, prime `0x01000193`.

**Segment B** — Same FNV-1a algorithm as segment A, but with a different salt: `"NATIVERE"` (8 bytes: `4E 41 54 49 56 45 52 45`). This computation is performed in the native library `libnative_check.so`, function `compute_native_hash()`, called via P/Invoke from `CheckSegmentB()`. The salt difference between segments A and B is the application's main trap — a reverse engineer who only reads the C# code and assumes the same salt for the native side produces an incorrect segment B.

**Segment C** — Combination of segments A and B via rotation, XOR, and multiplicative mixing. Algorithm: left rotation of A by 5 bits (on 16 bits), XOR with B, multiplication by `0x9E37` masked to 16 bits, XOR with `0xA5A5`. Computed entirely in C# in `ComputeCrossXor()`.

**Segment D** — Combination of a managed part and a native part. The managed part is the sum `(A + B + C) & 0xFFFF`. The native part is the return of `compute_checksum(A, B, C)` via P/Invoke, which performs rotations (left 3 bits, right 7 bits), XORs, a multiplication by `0x5BD1`, and an XOR with `0x1337`. The final segment D is the XOR of both parts, masked to 16 bits.

### Approach Followed

**Triage**: `file` on both binaries, `strings` on the assembly (class names, error messages, P/Invoke function names) and on the `.so` (salt `"NATIVERE"`), `nm -D` on the `.so` (exported functions).

**Managed static analysis**: opened `LicenseChecker.dll` in dnSpy, read the decompiled code of `LicenseValidator.Validate()` and its helper methods. Identified the linear 5-step flow, extracted constants (salts, FNV offset/prime, multiplicative constants).

**Native static analysis**: imported `libnative_check.so` into Ghidra, decompiled `compute_native_hash` and `compute_checksum`. Identified the native salt different from the managed salt. Reconstructed algorithms in pseudo-code.

**Dynamic validation**: combined CLR + native Frida script to capture all 4 segments. Verified that captured keys are accepted by the application. Confirmed algorithm understanding.

**Keygen**: Python implementation of all 4 segments, with the correct salts. Validated on 5+ usernames including non-ASCII characters.

**Patching**: variant A (C# rewrite of `Validate()`) and variant B (4 IL patches on conditional jumps, with stack management via `pop` before `br`).

### Challenges and Resolutions

The main challenge was identifying the two different salts. Static analysis of the C# side alone only reveals `"REV3RSE!"`. You must analyze the native library (with Ghidra, `strings`, or a Frida hook) to discover `"NATIVERE"`. Native hooking on `compute_native_hash` allows quickly validating that the native hash differs from the managed hash for the same input.

The second challenge was IL stack management for variant B patching. Naively replacing a `bne.un` with a `br` causes an `InvalidProgramException` because the stack contains two excess values. Adding two `pop` before the `br` fixes the issue. dnSpy's IL editor flags the stack error before saving, which allows detecting and correcting it immediately.

---

⏭️
