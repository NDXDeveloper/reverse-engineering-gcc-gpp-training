🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 19 Checkpoint

> **Spoilers** — Only read this solution after attempting the checkpoint yourself.

---

## Phase 1 — Triage and Protection Sheet

### Step 1 — `file`

```bash
$ file build/anti_reverse_all_checks
build/anti_reverse_all_checks: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped  
```

**Findings**:  
- ELF 64-bit x86-64, dynamically linked  
- **Stripped** — no symbols, no DWARF. We'll have to work without function names.  
- PIE (`pie executable`) — addresses will be relative.  
- No packing indication (sections present, normal dynamic linkage).

### Step 2 — `checksec`

```bash
$ checksec --file=build/anti_reverse_all_checks
[*] 'build/anti_reverse_all_checks'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Findings**:  
- **Partial RELRO** — the `.got.plt` remains writable (GOT hooking theoretically possible).  
- **Canary** — the `fs:0x28` pattern will be present in functions with buffers.  
- **NX** — non-executable stack (no impact on pure RE).  
- **PIE** — reason in offsets. GDB with GEF/pwndbg will display the base automatically.

### Step 3 — Dynamic Imports

```bash
$ nm -D build/anti_reverse_all_checks
                 U clock_gettime@GLIBC_2.17
                 U explicit_bzero@GLIBC_2.25
                 U fclose@GLIBC_2.2.5
                 U fgets@GLIBC_2.2.5
                 U fopen@GLIBC_2.2.5
                 U fprintf@GLIBC_2.2.5
                 U fflush@GLIBC_2.2.5
                 U printf@GLIBC_2.2.5
                 U ptrace@GLIBC_2.2.5
                 U signal@GLIBC_2.2.5
                 U __stack_chk_fail@GLIBC_2.4
                 U strlen@GLIBC_2.2.5
                 U strncmp@GLIBC_2.2.5
                 U strtol@GLIBC_2.2.5
```

**Suspicious functions identified**:

| Import | Suspected protection | Section |  
|---|---|---|  
| `ptrace` | Debugger detection via `PTRACE_TRACEME` | 19.7 |  
| `fopen` + `fgets` + `strncmp` + `strtol` | Reading `/proc/self/status` (TracerPid) | 19.7 |  
| `clock_gettime` | Timing check | 19.7 |  
| `signal` | SIGTRAP handler (bonus anti-debug) | 19.7 |  
| `explicit_bzero` | Memory cleanup (decoded password erased after comparison) | — |

**Notable absence**: no `mprotect` → no likely self-modifying code.

### Step 4 — Strings

```bash
$ strings build/anti_reverse_all_checks
/lib64/ld-linux-x86-64.so.2
...
/proc/self/status
TracerPid:  
Error: non-compliant environment.  
Error: integrity compromised.  
=== Crackme Chapter 19 ===
Password:
>>> Access granted. Well done!
>>> Flag: CTF{ant1_r3v3rs3_byp4ss3d}
>>> Incorrect password.
...

$ strings build/anti_reverse_all_checks | wc -l
47
```

**Findings**:  
- No UPX signature — **no packing**.  
- `"/proc/self/status"` and `"TracerPid:"` in plaintext → confirms procfs detection.  
- Two distinct error messages: `"non-compliant environment"` (anti-debug) and `"integrity compromised"` (anti-tampering int3/checksum).  
- The flag is in plaintext in `.rodata` (`CTF{ant1_r3v3rs3_byp4ss3d}`), but it is only displayed if the password is correct.  
- The password itself does **not** appear in `strings` → it is encoded.  
- 47 strings → normal count for a binary of this size, confirms absence of packing.

### Step 5 — Entropy and Sections

```bash
$ binwalk -E build/anti_reverse_all_checks
# Normal entropy (5.0–6.5), no plateau at 7.5+

$ readelf -S build/anti_reverse_all_checks | head -30
  [Nr] Name              Type             ...
  [ 1] .interp           PROGBITS
  [ 2] .note.gnu.build-id NOTE
  ...
  [14] .text             PROGBITS
  [15] .rodata           PROGBITS
  ...
  (normal sections, ~27 total)
```

**Finding**: standard ELF structure, no packing, no visible LLVM obfuscation.

### Final Protection Sheet

```
╔══════════════════════════════════════════════════════════╗
║    PROTECTION SHEET — anti_reverse_all_checks            ║
╠══════════════════════════════════════════════════════════╣
║ Format      : ELF 64-bit x86-64, dynamic, stripped        ║
║ Packing     : none                                       ║
║ Obfuscation : none detected                              ║
║ RELRO       : Partial                                    ║
║ Canary      : present                                    ║
║ NX          : enabled                                    ║
║ PIE         : enabled                                    ║
║ Anti-debug  : ptrace (nm -D) + /proc/self/status         ║
║               (strings) + clock_gettime (nm -D)          ║
║ Anti-tamper : "integrity compromised" → int3 scan or     ║
║               probable checksum                          ║
║ Signal      : SIGTRAP handler installed (signal imported)║
║ Password    : encoded (absent from strings)              ║
╠══════════════════════════════════════════════════════════╣
║ STRATEGY:                                                ║
║ 1. Frida script to bypass ptrace + procfs + timing       ║
║ 2. Hardware breakpoints (anti int3/checksum)             ║
║ 3. Ghidra static analysis for password decoding          ║
║ 4. HW breakpoint on comparison to read the password      ║
╚══════════════════════════════════════════════════════════╝
```

---

## Phase 2 — Bypassing Anti-Debug Protections

### Chosen approach: single Frida script

The most effective method against multiple combined checks is a Frida script that hooks all suspicious functions simultaneously.

#### Script `bypass_all.js`

```javascript
/*
 * bypass_all.js — Bypass all anti-debug protections
 * of anti_reverse_all_checks
 *
 * Usage: frida -f ./build/anti_reverse_all_checks -l bypass_all.js
 */

// ─── Check 1: ptrace (PTRACE_TRACEME) ───
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
        console.log("[*] ptrace(" + this.request + ") intercepted");
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0)); // simulate success
            console.log("[+] ptrace(PTRACE_TRACEME) → return 0 (bypassed)");
        }
    }
});

// ─── Check 2: /proc/self/status (TracerPid) ───
Interceptor.attach(Module.findExportByName(null, "strncmp"), {
    onEnter: function(args) {
        try {
            var s1 = args[0].readUtf8String();
            if (s1 && s1.indexOf("TracerPid:") !== -1) {
                // Rewrite the line to set TracerPid: 0
                args[0].writeUtf8String("TracerPid:\t0\n");
                console.log("[+] TracerPid rewritten to 0 (bypassed)");
            }
        } catch(e) {}
    }
});

// ─── Check 3: timing check (clock_gettime) ───
var firstCall = true;  
var savedTime = null;  

Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onEnter: function(args) {
        this.timespec = args[1];
    },
    onLeave: function(retval) {
        if (firstCall) {
            // Save the time from the first call
            savedTime = {
                sec: this.timespec.readU64(),
                nsec: this.timespec.add(8).readU64()
            };
            firstCall = false;
            console.log("[*] clock_gettime #1 recorded");
        } else {
            // Second call: write a time very close to the first
            // (1 microsecond difference → well under the 50ms threshold)
            this.timespec.writeU64(savedTime.sec);
            this.timespec.add(8).writeU64(savedTime.nsec.add(1000));
            console.log("[+] clock_gettime #2 → delta forced to ~1µs (bypassed)");
            firstCall = true; // reset for potential subsequent calls
        }
    }
});

// ─── Info: signal handler ───
Interceptor.attach(Module.findExportByName(null, "signal"), {
    onEnter: function(args) {
        var signum = args[0].toInt32();
        console.log("[*] signal(" + signum + ", handler) — SIGTRAP=" +
                    (signum === 5 ? "yes" : "no"));
    }
});

console.log("══════════════════════════════════════");  
console.log(" bypass_all.js loaded — protections neutralized");  
console.log("══════════════════════════════════════");  
```

#### Execution

```bash
$ frida -f ./build/anti_reverse_all_checks -l bypass_all.js --no-pause
══════════════════════════════════════
 bypass_all.js loaded — protections neutralized
══════════════════════════════════════
[*] signal(5, handler) — SIGTRAP=yes
[*] ptrace(0) intercepted
[+] ptrace(PTRACE_TRACEME) → return 0 (bypassed)
[+] TracerPid rewritten to 0 (bypassed)
[*] clock_gettime #1 recorded
[+] clock_gettime #2 → delta forced to ~1µs (bypassed)
=== Crackme Chapter 19 ===
Password:
```

The prompt appears — the three anti-debug checks have been passed.

#### What about the int3 scan and checksum?

The Frida script didn't need to handle the int3/checksum checks because:

- **Frida doesn't use `0xCC` breakpoints** — its `Interceptor` rewrites function prologues with a trampoline, not with `int3`. The `int3` scan detects nothing.  
- **The checksum** — in our implementation, `expected_checksum` is initialized to `0`, which disables the check. If the checksum had been active, Frida would have triggered it anyway (because Frida modifies the prologue of `verify_password` if we hook it). The solution would be to use a GDB hardware breakpoint instead of hooking `verify_password` with Frida, or to hook `check_code_integrity` to force its return to 0.

### Alternative approach: pure GDB

For those who prefer GDB without Frida:

```bash
$ gdb ./build/anti_reverse_all_checks
```

```
(gdb) set disable-randomization on

# Bypass ptrace: breakpoint on ptrace, force the return
(gdb) break ptrace
(gdb) run
(gdb) finish
(gdb) set $rax = 0
(gdb) continue

# Bypass procfs: breakpoint on strtol (TracerPid conversion)
# and force the result to 0
(gdb) break strtol
(gdb) continue
# (wait for the hit corresponding to TracerPid parsing)
(gdb) finish
(gdb) set $rax = 0
(gdb) continue

# Bypass timing: full-speed execution (continue, not step)
# The timing check doesn't trigger in continue mode.
# If necessary, break on the threshold cmp and force ZF.

# Arrival at the prompt — the checks have been passed
```

**Warning**: GDB's software breakpoints will trigger the `int3` scan if a breakpoint is placed within the first 128 bytes of `verify_password`. Use `hbreak` (hardware breakpoint) for this function.

### Bypass Log Summary

| # | Protection | Address/offset | Bypass method |  
|---|---|---|---|  
| 1 | `PTRACE_TRACEME` | Start of `main` + first call | Frida: hook `ptrace`, `retval.replace(0)` |  
| 2 | `/proc/self/status` (TracerPid) | Second check in `main` | Frida: hook `strncmp`, rewrite `TracerPid:\t0` |  
| 3 | Timing (`clock_gettime`) | Third check in `main` | Frida: hook `clock_gettime`, force delta ~1µs |  
| 4 | `int3` scan | Fourth check, scans `verify_password` | No action needed (Frida doesn't insert `0xCC`) |  
| 5 | Code checksum | Fifth check | Disabled (`expected_checksum == 0`), otherwise: hook to force return 0 |

---

## Phase 3 — Password Extraction

### Method A — Static Analysis (Ghidra)

1. **Import** `anti_reverse_all_checks` into Ghidra, launch auto-analysis.

2. **Locate the verification logic** via XREF. Search for the string `"Password:"` in the string listing (menu Search → Strings). Double-click on it to go to `.rodata`, then click on the XREF to navigate up to the referencing function — this is `main` (renamed `FUN_XXXXX` since stripped).

3. **Follow the flow** after the `fgets`. In `main`, after the prompt display and input reading, we see a call to an internal function. This is `verify_password` (renamed `FUN_YYYYY`).

4. **Analyze `verify_password`** in the decompiler. Ghidra produces something like:

```c
bool FUN_YYYYY(char *input) {
    if (strlen(input) != 8) return 0;

    char decoded[9];
    byte *encoded = &DAT_00ZZZZZZ;  // address in .rodata
    for (int i = 0; i < 8; i++) {
        decoded[i] = encoded[i] ^ 0x5a;
    }
    decoded[8] = 0;

    int result = 1;
    for (int i = 0; i < 8; i++) {
        if (input[i] != decoded[i]) result = 0;
    }

    explicit_bzero(decoded, 9);
    return result;
}
```

5. **Extract the encoded bytes** — Navigate to `DAT_00ZZZZZZ` in Ghidra. The 8 bytes are:

```
08 69 2C 3F 28 29 69 73
```

6. **Apply the XOR**:

```python
encoded = [0x08, 0x69, 0x2C, 0x3F, 0x28, 0x29, 0x69, 0x73]  
key = 0x5A  
password = ''.join(chr(b ^ key) for b in encoded)  
print(password)  # R3vers3!  
```

**Password: `R3vers3!`**

### Method B — Dynamic Analysis (GDB + hardware breakpoint)

1. Launch the binary with anti-debug bypasses (Frida script or GDB bypass).

2. Set a **hardware breakpoint** on the comparison loop in `verify_password`. To find the address without symbols, look for the `strlen` call followed by a `cmp` with `8`, then the XOR loop:

```
(gdb) hbreak *($base + 0x<offset_of_comparison_loop>)
```

3. Enter any password (e.g. `AAAAAAAA`).

4. At the breakpoint, the `decoded` buffer contains the decoded password. Read it:

```
(gdb) x/s $rbp-0x11
0x7ffd...:  "R3vers3!"
```

The exact offset of `decoded` on the stack depends on the compilation. Inspect memory accesses around the breakpoint to locate it.

**Password: `R3vers3!`**

### Method C — Frida one-liner

Since we already have an active Frida script for the anti-debug bypass, we can add a hook on the comparison:

```javascript
// Add to bypass_all.js:

// Hook explicit_bzero to detect entry into verify_password
Interceptor.attach(Module.findExportByName(null, "explicit_bzero"), {
    onEnter: function(args) {
        // explicit_bzero is called on the decoded buffer
        // just before it's erased → we read it here
        try {
            var decoded = args[0].readUtf8String();
            console.log("[+] Decoded password: " + decoded);
        } catch(e) {}
    }
});
```

The hook intercepts `explicit_bzero`, which receives the `decoded` buffer as argument just before erasing it. We read the password in plaintext at this precise moment.

```
[+] Decoded password: R3vers3!
```

### Validation

```bash
$ frida -f ./build/anti_reverse_all_checks -l bypass_all.js --no-pause
...
=== Crackme Chapter 19 ===
Password: R3vers3!
>>> Access granted. Well done!
>>> Flag: CTF{ant1_r3v3rs3_byp4ss3d}
```

---

## Summary of Identified and Bypassed Protections

| # | Protection | Category | Detection | Bypass |  
|---|---|---|---|---|  
| 1 | Stripping | Info removal | `file` → `stripped` | Manual renaming in Ghidra, XREF on strings |  
| 2 | PIE | Memory protection | `checksec` → `PIE enabled` | Relative offsets, `$base + offset` in GDB |  
| 3 | Canary | Memory protection | `checksec` → `Canary found` | No action (doesn't hinder RE) |  
| 4 | NX | Memory protection | `checksec` → `NX enabled` | No action (doesn't hinder RE) |  
| 5 | Partial RELRO | Memory protection | `checksec` → `Partial RELRO` | No action (`.got.plt` writable if needed) |  
| 6 | `PTRACE_TRACEME` | Active anti-debug | `nm -D` → `ptrace` imported | Frida hook retval → 0 |  
| 7 | `/proc/self/status` | Active anti-debug | `strings` → `"/proc/self/status"` | Frida hook `strncmp` → rewrite TracerPid |  
| 8 | Timing check | Active anti-debug | `nm -D` → `clock_gettime` | Frida hook → force minimal delta |  
| 9 | int3 scan | Anti-breakpoint | Message `"integrity compromised"` | Hardware breakpoints (or Frida without `int3`) |  
| 10 | Code checksum | Anti-tampering | Static analysis (Ghidra) | Disabled (expected=0); otherwise hw breakpoints |  
| 11 | SIGTRAP handler | Bonus anti-debug | `nm -D` → `signal` | No action (not blocking in this binary) |  
| 12 | XOR password | Anti-strings | `strings` doesn't show the password | XOR 0x5A decoding (static or dynamic) |

---

## Complete Automation Script (optional)

For those who want a Python script that solves the binary end-to-end without interaction:

```python
#!/usr/bin/env python3
"""
solve_ch19.py — Automatic solving of anti_reverse_all_checks  
RE Training — Chapter 19  
"""

# ─── Method 1: static extraction (without executing the binary) ───

def extract_password_static(binary_path):
    """Extract the password through pure static analysis."""
    with open(binary_path, "rb") as f:
        data = f.read()

    # Search for the known encoded sequence via pattern matching
    # The encoded bytes precede the XOR key in .rodata
    xor_key = 0x5A
    encoded = bytes([0x08, 0x69, 0x2C, 0x3F, 0x28, 0x29, 0x69, 0x73])

    offset = data.find(encoded)
    if offset == -1:
        print("[-] Encoded sequence not found in binary")
        return None

    print(f"[+] Encoded sequence found at offset 0x{offset:x}")
    password = ''.join(chr(b ^ xor_key) for b in encoded)
    print(f"[+] Decoded password: {password}")
    return password


# ─── Method 2: dynamic solving with pwntools ───

def solve_dynamic(binary_path):
    """Solve the crackme dynamically with pwntools + LD_PRELOAD."""
    from pwn import process, ELF, context
    import tempfile, os

    context.log_level = 'warn'

    # Create a fake ptrace
    fake_c = tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False)
    fake_c.write('long ptrace(int r, ...){ return 0; }\n')
    fake_c.close()

    fake_so = fake_c.name.replace('.c', '.so')
    os.system(f"gcc -shared -fPIC -o {fake_so} {fake_c.name}")

    password = extract_password_static(binary_path)
    if not password:
        return

    # Launch the binary with the bypass
    env = {"LD_PRELOAD": fake_so}
    p = process(binary_path, env=env)
    p.recvuntil(b"Password: ")
    p.sendline(password.encode())
    result = p.recvall(timeout=2).decode()
    print(result)

    # Cleanup
    os.unlink(fake_c.name)
    os.unlink(fake_so)


if __name__ == "__main__":
    import sys
    binary = sys.argv[1] if len(sys.argv) > 1 \
             else "build/anti_reverse_all_checks"

    print("=" * 50)
    print(" Solve Chapter 19 — anti_reverse_all_checks")
    print("=" * 50)
    print()

    password = extract_password_static(binary)
    if password:
        print()
        print(f"[✓] Password: {password}")
        print(f"[✓] Expected flag: CTF{{ant1_r3v3rs3_byp4ss3d}}")
        print()
        print("Attempting dynamic validation...")
        try:
            solve_dynamic(binary)
        except ImportError:
            print("(pwntools not installed, dynamic validation skipped)")
```

```bash
$ python3 solve_ch19.py build/anti_reverse_all_checks
==================================================
 Solve Chapter 19 — anti_reverse_all_checks
==================================================

[+] Encoded sequence found at offset 0x2040
[+] Decoded password: R3vers3!

[✓] Password: R3vers3!
[✓] Expected flag: CTF{ant1_r3v3rs3_byp4ss3d}

Attempting dynamic validation...
>>> Access granted. Well done!
>>> Flag: CTF{ant1_r3v3rs3_byp4ss3d}
```

---

⏭️
