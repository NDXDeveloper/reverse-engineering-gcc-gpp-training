🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.5 — Dynamic Analysis: GDB + Frida (Extracting the Key from Memory)

> 🔬 **Goal of this section**: irrefutably confirm the hypotheses from static analysis by observing the program **during execution**. We will intercept the arguments passed to `EVP_EncryptInit_ex` at the exact moment of the call, capture the key and IV as actually used by OpenSSL, and trace the encryption flow file by file.  
>  
> ⚠️ **Mandatory reminder**: all sample execution must be done in the sandboxed VM from [Chapter 26](/26-secure-lab/README.md). Take a snapshot **before** each launch. Verify that the network is isolated (`ip link show` — no interface toward the host).

---

## Why dynamic analysis is necessary

The static analysis in Ghidra (section 27.3) identified the key and IV in `.rodata`, and the XREFs show they are passed to `EVP_EncryptInit_ex`. So why not stop there?

Because static analysis shows what the code **could** do, not what it **actually does**. Several scenarios would invalidate our static conclusions without the disassembly easily revealing it: the key in `.rodata` could be a decoy, copied into a buffer then transformed by XOR or key derivation before use. A runtime condition (environment variable, argument, system date) could select an alternative key. The `-O2` compiler could have reorganized the code in a way the decompiler misinterprets.

Dynamic analysis provides **proof through direct observation**: we will see the exact bytes the program passes to OpenSSL, at the clock cycle when it does so.

---

## Environment preparation

### Restore a clean state

```bash
# In the sandboxed VM
make reset        # Recreates /tmp/test/ with test files  
ls -la /tmp/test/ # Verify files are present and not encrypted  
```

### Choose the variant

We will work with both variants in parallel:

- **`ransomware_O0`** (debug) — For the initial hands-on with GDB. DWARF symbols allow setting breakpoints by function name and inspecting local variables.  
- **`ransomware_O2_strip`** (stripped) — For the realistic demonstration. We will set breakpoints on shared library functions, which remain accessible even without symbols.

### Disable ASLR (optional but recommended for learning)

ASLR randomizes addresses at each execution, which complicates tracking between GDB sessions. For pedagogical reasons, we temporarily disable it:

```bash
# Disable (requires root)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Re-enable after analysis
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

> 💡 In a real-world situation, you don't disable ASLR — you work with relative offsets or use GDB/GEF capabilities to resolve addresses dynamically. Here, it's a learning convenience.

---

## Part A — Extraction with GDB

### Approach on the debug variant (`ransomware_O0`)

#### Launch GDB

```bash
$ gdb -q ./ransomware_O0
Reading symbols from ./ransomware_O0...
(gdb)
```

GDB loads the DWARF symbols. All internal functions are accessible by name.

#### Set a breakpoint on the encryption routine

Our primary target is the `aes256cbc_encrypt` function, which encapsulates the EVP calls. Let's set a breakpoint at its entry:

```gdb
(gdb) break aes256cbc_encrypt
Breakpoint 1 at 0x...: file ransomware_sample.c, line ...
```

To capture the exact moment the key is transmitted to OpenSSL, let's also set a breakpoint on the library call:

```gdb
(gdb) break EVP_EncryptInit_ex
Breakpoint 2 at 0x... (in /lib/x86_64-linux-gnu/libcrypto.so.3)
```

#### Execute and intercept

```gdb
(gdb) run
Starting program: /home/user/binaries/ch27-ransomware/ransomware_O0
==============================================
  RE Training — Chapter 27
  Pedagogical sample — DO NOT DISTRIBUTE
  Target: /tmp/test
==============================================
[*] Traversing /tmp/test ...
[+] Encrypting: /tmp/test/document.txt

Breakpoint 1, aes256cbc_encrypt (in=0x..., in_len=47, out=0x..., out_len=0x...)
    at ransomware_sample.c:...
```

The program stops at the entry of `aes256cbc_encrypt`, at the moment of encrypting the first file. The arguments are visible because the DWARF symbols include parameter names.

#### Inspect `aes256cbc_encrypt` arguments

```gdb
(gdb) print in_len
$1 = 47

(gdb) x/47c in
0x...:  "This is a strictly confidential document.\n"
```

We see the contents of `document.txt` in plaintext, ready to be encrypted. Let's continue to the `EVP_EncryptInit_ex` breakpoint:

```gdb
(gdb) continue
Continuing.

Breakpoint 2, EVP_EncryptInit_ex (ctx=0x..., type=0x..., impl=0x0,
    key=0x..., iv=0x...)
```

#### Capture the key and IV

This is the key moment of the analysis. The `EVP_EncryptInit_ex` arguments follow the System V AMD64 calling convention (covered in [Chapter 3, section 3.6](/03-x86-64-assembly/06-parameter-passing.md)):

| Register | Parameter | Meaning |  
|---|---|---|  
| `rdi` | `ctx` | EVP context (opaque) |  
| `rsi` | `type` | Pointer to the `EVP_CIPHER` structure (AES-256-CBC) |  
| `rdx` | `impl` | Engine (NULL = default implementation) |  
| `rcx` | `key` | Pointer to the encryption key |  
| `r8`  | `iv` | Pointer to the initialization vector |

Let's extract the key (32 bytes pointed to by `rcx`) and the IV (16 bytes pointed to by `r8`):

```gdb
(gdb) # AES-256 key — 32 bytes from register rcx
(gdb) x/32xb $rcx
0x...: 0x52  0x45  0x56  0x45  0x52  0x53  0x45  0x5f
0x...: 0x45  0x4e  0x47  0x49  0x4e  0x45  0x45  0x52
0x...: 0x49  0x4e  0x47  0x5f  0x49  0x53  0x5f  0x46
0x...: 0x55  0x4e  0x5f  0x32  0x30  0x32  0x35  0x21

(gdb) # Display in ASCII for confirmation
(gdb) x/s $rcx
0x...: "REVERSE_ENGINEERING_IS_FUN_2025!"

(gdb) # AES IV — 16 bytes from register r8
(gdb) x/16xb $r8
0x...: 0xde  0xad  0xbe  0xef  0xca  0xfe  0xba  0xbe
0x...: 0x13  0x37  0x42  0x42  0xfe  0xed  0xfa  0xce
```

**Definitive confirmation**: the key passed to OpenSSL at runtime is exactly the one identified in `.rodata` during static analysis. The IV is identical to our hypothesis H4. No transformation, no decoy, no derivation.

#### Inspect the result after encryption

Let's continue execution until `aes256cbc_encrypt` returns to see the ciphertext:

```gdb
(gdb) finish
Run till exit from #0  EVP_EncryptInit_ex ...
(gdb) finish
Run till exit from #0  aes256cbc_encrypt ...  
aes256cbc_encrypt returned 0        ← success  

(gdb) # out_len contains the ciphertext size
(gdb) print *out_len
$2 = 48
```

The original file was 47 bytes. The ciphertext is 48 bytes: 47 bytes of data + 1 byte of PKCS#7 padding, rounded to the next multiple of 16 (48 = 3 × 16). This result is consistent with CBC mode and confirms the padding.

### Approach on the stripped variant (`ransomware_O2_strip`)

On a binary without symbols, the strategy is different. You can't write `break aes256cbc_encrypt` because this function doesn't exist in the symbol table. However, **imported functions** (shared libraries) remain accessible.

```bash
$ gdb -q ./ransomware_O2_strip
(No debugging symbols found in ./ransomware_O2_strip)
(gdb)
```

#### Breakpoint on the library function

```gdb
(gdb) break EVP_EncryptInit_ex
Function "EVP_EncryptInit_ex" not defined.  
Make breakpoint pending on future shared library load? (y or [n]) y  
Breakpoint 1 (EVP_EncryptInit_ex) pending.  
(gdb) run
```

The breakpoint is marked *pending* because `libcrypto.so` is not yet loaded. GDB will automatically resolve it when the dynamic loader maps it into memory.

```gdb
[*] Traversing /tmp/test ...
[+] Encrypting: /tmp/test/document.txt

Breakpoint 1, 0x00007ffff7... in EVP_EncryptInit_ex () from /lib/.../libcrypto.so.3
```

The extraction is then identical: `x/32xb $rcx` for the key, `x/16xb $r8` for the IV. The fact that the binary is stripped doesn't prevent intercepting calls to dynamic libraries — this is one of the structural weaknesses of dynamic linking from a malware author's perspective.

#### Examining multiple files

To verify that the same key and IV are used for each file (which is expected since they are static), we can define a breakpoint with automatic commands:

```gdb
(gdb) break EVP_EncryptInit_ex
(gdb) commands 1
    silent
    printf "=== EVP_EncryptInit_ex called ===\n"
    printf "Key: "
    x/32xb $rcx
    printf "IV:  "
    x/16xb $r8
    continue
end
(gdb) run
```

GDB will automatically display the key and IV at each call, then resume execution. On our sample, each invocation will show the same values — confirming the absence of key rotation between files. This verification is important: a more sophisticated ransomware could generate a unique key per file.

### GDB Python script for automated extraction

To formalize the extraction, here is a GDB Python script that captures and exports the cryptographic parameters:

```python
# extract_crypto_params.py — GDB Python script
# Usage: gdb -q -x extract_crypto_params.py ./ransomware_O2_strip

import gdb  
import json  

results = []

class EvpBreakpoint(gdb.Breakpoint):
    """Breakpoint on EVP_EncryptInit_ex that captures key and IV."""
    
    def __init__(self):
        super().__init__("EVP_EncryptInit_ex", gdb.BP_BREAKPOINT)
        self.call_count = 0
    
    def stop(self):
        self.call_count += 1
        frame = gdb.newest_frame()
        
        # Read rcx (key) and r8 (iv) — System V AMD64 convention
        key_addr = int(gdb.parse_and_eval("$rcx"))
        iv_addr  = int(gdb.parse_and_eval("$r8"))
        
        # Read bytes from memory
        inferior = gdb.selected_inferior()
        key_bytes = inferior.read_memory(key_addr, 32).tobytes()
        iv_bytes  = inferior.read_memory(iv_addr, 16).tobytes()
        
        entry = {
            "call_number": self.call_count,
            "key_hex": key_bytes.hex(),
            "key_ascii": key_bytes.decode("ascii", errors="replace"),
            "iv_hex": iv_bytes.hex(),
        }
        results.append(entry)
        
        print(f"[*] Call #{self.call_count}")
        print(f"    Key : {key_bytes.hex()}")
        print(f"    IV  : {iv_bytes.hex()}")
        
        # Don't stop execution — continue automatically
        return False

# Set the breakpoint
bp = EvpBreakpoint()

# Run the program
gdb.execute("run")

# Export results after execution ends
with open("/tmp/crypto_params.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n[+] {len(results)} calls captured → /tmp/crypto_params.json")
```

Execution:

```bash
$ gdb -q -batch -x extract_crypto_params.py ./ransomware_O2_strip
[*] Call #1
    Key : 524556455253455f454e47494e454552494e475f49535f46554e5f3230323521
    IV  : deadbeefcafebabe13374242feedface
[*] Call #2
    Key : 524556455253455f454e47494e454552494e475f49535f46554e5f3230323521
    IV  : deadbeefcafebabe13374242feedface
...
[+] 6 calls captured → /tmp/crypto_params.json
```

The `-batch` flag runs GDB in non-interactive mode. The produced JSON file is directly usable by the Python decryptor (section 27.6) and constitutes evidence for the report (section 27.7).

---

## Part B — Extraction with Frida

Frida offers a complementary approach to GDB. Where GDB interrupts execution and inspects state (breakpoint paradigm), Frida **injects JavaScript code** into the target process and intercepts calls live, without interrupting the flow (hook paradigm). The program runs at near-native speed, and data is captured in passing.

### Why use Frida alongside GDB

The distinction is not just technical, it's methodological:

| Aspect | GDB | Frida |  
|---|---|---|  
| Paradigm | Stop-and-inspect | Hook-and-log |  
| Impact on execution | Interrupts the program | Near-transparent |  
| Output | Manual or scripted | Automatic structured logging |  
| Runtime modification | Possible but laborious | Native (modify arguments, returns) |  
| Anti-debug | Detectable via `ptrace` | More discreet (userspace injection) |  
| Learning curve | Complex CLI | Familiar JavaScript |

For our sample (no anti-debug), both approaches yield the same result. Frida's interest here is pedagogical: showing a second method and preparing the ground for [Chapter 28](/28-dropper/README.md) where Frida hooking will be indispensable for intercepting network communications live.

### Frida script: hooking `EVP_EncryptInit_ex`

```javascript
// hook_evp.js — Frida script to intercept EVP calls
// Usage: frida -f ./ransomware_O2_strip -l hook_evp.js --no-pause

const CYAN  = "\x1b[36m";  
const GREEN = "\x1b[32m";  
const RESET = "\x1b[0m";  

// Resolve the address of EVP_EncryptInit_ex in libcrypto
const evpInit = Module.findExportByName("libcrypto.so.3", "EVP_EncryptInit_ex");

if (evpInit) {
    console.log(`[*] EVP_EncryptInit_ex found at ${evpInit}`);

    Interceptor.attach(evpInit, {
        onEnter: function (args) {
            // Signature: EVP_EncryptInit_ex(ctx, type, impl, key, iv)
            //              args[0] args[1] args[2] args[3] args[4]
            
            const keyPtr = args[3];
            const ivPtr  = args[4];

            // Read the key (32 bytes) and IV (16 bytes)
            const keyBytes = keyPtr.readByteArray(32);
            const ivBytes  = ivPtr.readByteArray(16);

            console.log(`\n${GREEN}=== EVP_EncryptInit_ex called ===${RESET}`);

            // Display the key in hex
            console.log(`${CYAN}Key (32 bytes):${RESET}`);
            console.log(hexdump(keyPtr, { length: 32, ansi: true }));

            // Attempt ASCII display of the key
            try {
                const keyStr = keyPtr.readUtf8String(32);
                console.log(`Key (ASCII): ${keyStr}`);
            } catch (e) {
                console.log("Key (ASCII): [non-printable]");
            }

            // Display the IV in hex
            console.log(`${CYAN}IV (16 bytes):${RESET}`);
            console.log(hexdump(ivPtr, { length: 16, ansi: true }));

            // Save for onLeave if needed
            this.keyPtr = keyPtr;
            this.ivPtr  = ivPtr;
        },

        onLeave: function (retval) {
            console.log(`Return value: ${retval} (1 = success)`);
        }
    });
} else {
    // Fallback: look in libcrypto without version number
    const libs = Process.enumerateModules();
    const cryptoLib = libs.find(m => m.name.includes("libcrypto"));
    if (cryptoLib) {
        console.log(`[!] libcrypto found: ${cryptoLib.name}`);
        console.log("[!] Adapt the name in Module.findExportByName()");
    } else {
        console.log("[!] libcrypto not found in the process");
    }
}
```

#### Execution

```bash
$ frida -f ./ransomware_O2_strip -l hook_evp.js --no-pause
```

The `-f` flag tells Frida to **spawn** the process (launch it itself), which guarantees the hook is in place before the first program instruction. The `--no-pause` flag lets the program execute immediately after injection.

Output (for each encrypted file):

```
[*] EVP_EncryptInit_ex found at 0x7f...

=== EVP_EncryptInit_ex called ===
Key (32 bytes):
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
00000000  52 45 56 45 52 53 45 5f 45 4e 47 49 4e 45 45 52  REVERSE_ENGINEER
00000010  49 4e 47 5f 49 53 5f 46 55 4e 5f 32 30 32 35 21  ING_IS_FUN_2025!
Key (ASCII): REVERSE_ENGINEERING_IS_FUN_2025!  
IV (16 bytes):  
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
00000000  de ad be ef ca fe ba be 13 37 42 42 fe ed fa ce  .........7BB....
Return value: 0x1 (1 = success)
```

Frida's built-in `hexdump` produces formatted output with ASCII, more readable than GDB's raw output.

### Extended Frida script: also capturing plaintext and ciphertext

For a complete analysis, we can also hook `EVP_EncryptUpdate` to capture data before and after encryption:

```javascript
// hook_evp_full.js — Complete encryption flow capture
// Usage: frida -f ./ransomware_O2_strip -l hook_evp_full.js --no-pause

let fileCount = 0;

// --- Hook EVP_EncryptInit_ex ---
const evpInit = Module.findExportByName("libcrypto.so.3", "EVP_EncryptInit_ex");  
Interceptor.attach(evpInit, {  
    onEnter: function (args) {
        fileCount++;
        console.log(`\n[${"=".repeat(50)}]`);
        console.log(`[*] File #${fileCount}`);

        console.log("[*] Key:");
        console.log(hexdump(args[3], { length: 32, ansi: true }));
        console.log("[*] IV:");
        console.log(hexdump(args[4], { length: 16, ansi: true }));
    }
});

// --- Hook EVP_EncryptUpdate ---
const evpUpdate = Module.findExportByName("libcrypto.so.3", "EVP_EncryptUpdate");  
Interceptor.attach(evpUpdate, {  
    onEnter: function (args) {
        // args: ctx, out, out_len_ptr, in, in_len
        this.outPtr    = args[1];
        this.outLenPtr = args[2];
        const inPtr    = args[3];
        const inLen    = args[4].toInt32();

        console.log(`[*] EncryptUpdate — plaintext (${inLen} bytes):`);
        if (inLen <= 256) {
            console.log(hexdump(inPtr, { length: inLen, ansi: true }));
        } else {
            console.log(hexdump(inPtr, { length: 256, ansi: true }));
            console.log(`    ... (${inLen - 256} additional bytes)`);
        }
    },
    onLeave: function (retval) {
        const outLen = this.outLenPtr.readS32();
        console.log(`[*] EncryptUpdate — ciphertext (${outLen} bytes):`);
        if (outLen <= 256) {
            console.log(hexdump(this.outPtr, { length: outLen, ansi: true }));
        } else {
            console.log(hexdump(this.outPtr, { length: 256, ansi: true }));
            console.log(`    ... (${outLen - 256} additional bytes)`);
        }
    }
});

// --- Hook EVP_EncryptFinal_ex ---
const evpFinal = Module.findExportByName("libcrypto.so.3", "EVP_EncryptFinal_ex");  
Interceptor.attach(evpFinal, {  
    onEnter: function (args) {
        this.outPtr    = args[1];
        this.outLenPtr = args[2];
    },
    onLeave: function (retval) {
        const outLen = this.outLenPtr.readS32();
        console.log(`[*] EncryptFinal — padding block (${outLen} bytes):`);
        if (outLen > 0) {
            console.log(hexdump(this.outPtr, { length: outLen, ansi: true }));
        }
    }
});
```

This script provides a **complete trace** of the encryption flow: for each file, we see the plaintext entering `EncryptUpdate`, the ciphertext coming out, and the padding block produced by `EncryptFinal`. It's the equivalent of a real-time X-ray of the encryption process.

### Hooking `unlink` to trace deletions

A complementary script can intercept `unlink` calls to confirm which files are deleted:

```javascript
// hook_unlink.js — Trace file deletions
const unlinkAddr = Module.findExportByName(null, "unlink");

Interceptor.attach(unlinkAddr, {
    onEnter: function (args) {
        const path = args[0].readUtf8String();
        console.log(`[!] unlink("${path}")`);
    },
    onLeave: function (retval) {
        console.log(`    → return: ${retval} (0 = success)`);
    }
});
```

Output:

```
[!] unlink("/tmp/test/document.txt")
    → return: 0x0 (0 = success)
[!] unlink("/tmp/test/notes.md")
    → return: 0x0 (0 = success)
...
```

This trace confirms the destructive behavior and provides the **exact list of deleted files** — information directly usable for the incident report.

---

## Cross-verification: `ltrace`

Before concluding the dynamic analysis, a quick pass with `ltrace` offers a synthetic view of all library calls, without writing a script:

```bash
$ ltrace -e 'EVP_*+opendir+readdir+unlink+fopen+fwrite' ./ransomware_O0 2>&1 | head -40
```

The `-e` flag filters calls by name. The output chronologically mixes EVP calls, file operations, and deletions, offering a condensed chronological view of the complete behavior. It's a quick confirmation tool, less powerful than GDB or Frida but immediate.

> 💡 `ltrace` doesn't always work correctly on modern PIE binaries with certain libc versions. If the output is empty or inconsistent, prefer `strace` for system calls or Frida scripts.

---

## Complementary verification with `strace`

`strace` traces **system calls** (kernel level) rather than library calls. It confirms file operations from the operating system's perspective:

```bash
$ strace -f -e trace=openat,read,write,unlink,getdents64 ./ransomware_O2_strip 2>&1 | grep /tmp/test
```

You will see the `openat` calls on `/tmp/test/` files, the `read` of their content, the `write` of `.locked` files, and the `unlink` of the originals. This trace is a source of behavioral IOCs for the report: it proves, at the syscall level, that the program reads, writes, and deletes files in the target directory tree.

`strace` also confirms hypothesis H7 (no network communication): no `socket`, `connect`, `sendto`, or `recvfrom` calls appear in the complete trace.

```bash
$ strace -f -e trace=network ./ransomware_O2_strip 2>&1
# (no network-related output)
```

---

## Summary: dynamic confirmation table

| Hypothesis | Status before dynamic | Status after dynamic | Dynamic evidence |  
|---|---|---|---|  
| H2 — AES-256-CBC | Confirmed (static) | **Confirmed (dynamic)** | `EVP_aes_256_cbc` called, non-NULL return passed to `EncryptInit` |  
| H3 — Key = `REVERSE_...2025!` | Confirmed (static) | **Definitively confirmed** | 32 bytes read from `$rcx` at the time of `EVP_EncryptInit_ex` call |  
| H4 — IV = `DEADBEEF...FEEDFACE` | Confirmed (static) | **Definitively confirmed** | 16 bytes read from `$r8` at the time of the call |  
| H6 — Original files deleted | Confirmed (static) | **Confirmed (dynamic)** | `unlink()` traced by Frida and `strace` on each file |  
| H7 — No network | Strengthened (static) | **Confirmed (dynamic)** | `strace -e trace=network` silent |  
| H8 — No anti-debug | Strengthened (static) | **Confirmed (dynamic)** | GDB and Frida function without obstruction |  
| N1 — File read entirely into memory | Static observation | **Confirmed (dynamic)** | Full plaintext visible in `EncryptUpdate` in a single call |  
| N5 — Key/IV identical for each file | Static observation | **Confirmed (dynamic)** | GDB/Frida script: same values across all 6 calls |

All hypotheses are now at the status of **confirmed facts**. The key and IV are the necessary and sufficient input data to write the decryptor (section 27.6).

---

## Data exported for next steps

The dynamic analysis produces three usable artifacts:

1. **`/tmp/crypto_params.json`** — Export from the GDB Python script: key, IV, call count. Input for the Python decryptor.  
2. **Frida logs** — Complete traces of EVP calls with hexdumps of plaintext and ciphertext. Evidence for the report.  
3. **`strace` traces** — System calls confirming file behavior and absence of network. Behavioral IOCs for the report.

These elements, combined with the static analysis results (Ghidra call graph, ImHex pattern, YARA rules), constitute the complete file from which we will now write the decryptor and draft the final report.

⏭️ [Writing the Python decryptor](/27-ransomware/06-python-decryptor.md)
