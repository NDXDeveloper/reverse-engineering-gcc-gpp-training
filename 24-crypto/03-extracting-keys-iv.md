🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 24.3 — Extracting Keys and IVs from Memory with GDB/Frida

> 🎯 **Objective of this section**: intercept encryption keys, IVs, and plaintext data buffers at the precise moment they pass through memory, by combining classical debugging (GDB) and dynamic instrumentation (Frida).

---

## The Fundamental Principle

No matter how complex a key derivation scheme may be — hardcoded passphrase, multi-pass KDF, cascading XOR obfuscation — there is an unavoidable moment: **the final key, in plaintext, must be passed to the encryption function**. This is an absolute architectural constraint. The encryption algorithm needs the key as a byte array to operate. This moment of truth always exists, and that is where we step in.

The same reasoning applies to the IV, to the plaintext before encryption, and to the ciphertext after decryption. At a given point during execution, all these values exist in memory simultaneously. Dynamic RE consists of freezing that moment and capturing everything.

This approach has a considerable advantage over pure static analysis: you don't need to fully understand the derivation logic to obtain the key. If the binary derives its key through 47 nested obfuscation steps, you can ignore those 47 steps and simply read the final result. Understanding the derivation remains useful (for writing a keygen, for example), but for the immediate decryption of a file, the raw key is sufficient.

---

## Preparation: Identifying Interception Points

Before launching GDB or Frida, you need to know **where** to place your probes. The work from sections 24.1 and 24.2 identified the algorithm (AES-256-CBC) and the library (OpenSSL, EVP API). We therefore know which functions are called and what parameters they receive.

### Targets for OpenSSL (EVP API)

The central function is `EVP_EncryptInit_ex`. Its (simplified) signature is:

```c
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                       const EVP_CIPHER *type,  // e.g.: EVP_aes_256_cbc()
                       ENGINE *impl,            // generally NULL
                       const unsigned char *key, // ← 32 bytes for AES-256
                       const unsigned char *iv); // ← 16 bytes for CBC
```

The `key` and `iv` parameters are pointers to the plaintext buffers. On x86-64 with the System V calling convention, they are passed in registers:

| Parameter | Register | Size of pointed data |  
|---|---|---|  
| `ctx` | `rdi` | — (opaque structure) |  
| `type` | `rsi` | — (pointer to EVP descriptor) |  
| `impl` | `rdx` | — (generally `NULL`) |  
| `key` | `rcx` | 32 bytes (AES-256) |  
| `iv` | `r8` | 16 bytes (AES-CBC) |

This is the ideal interception point: at the time of the call, `rcx` points to the key and `r8` points to the IV.

Other points are also interesting depending on what you are looking for:

| Function | What we capture | Key register |  
|---|---|---|  
| `EVP_EncryptInit_ex` | Key + IV at initialization time | `rcx` (key), `r8` (iv) |  
| `EVP_EncryptUpdate` | Plaintext before encryption | `rcx` (in), `r8` (inl = size) |  
| `EVP_EncryptFinal_ex` | Last block + padding | `rsi` (out) |  
| `SHA256` | Hashed data + resulting hash | `rdi` (data), `rdx` (md_out) |  
| `RAND_bytes` | Generated IV or nonce | `rdi` (buf), `rsi` (num) |  
| `derive_key` (our function) | Key after complete derivation | Stack / local registers |

For a binary using a different library, the function names change but the principle remains identical: we target the cipher initialization function and read the parameters.

---

## Method 1: GDB — The Surgical Scalpel

GDB allows you to freeze execution at the exact instruction and inspect memory byte by byte. This is the most precise and most controlled approach.

### Breakpoint on `EVP_EncryptInit_ex`

We launch the binary under GDB with the file to encrypt as an argument:

```bash
$ gdb -q ./crypto_O0
(gdb) break EVP_EncryptInit_ex
Breakpoint 1 at 0x... (EVP_EncryptInit_ex)
(gdb) run secret.txt
```

The program stops at the time of the call. We inspect the registers to find the pointers to the key and IV:

```bash
(gdb) info registers rcx r8
rcx            0x7fffffffd9e0      # pointer to the key  
r8             0x7fffffffda10      # pointer to the IV  
```

We then read the pointed contents:

```bash
# AES-256 key: 32 bytes starting from the address in rcx
(gdb) x/32bx $rcx
0x7fffffffd9e0: 0xa3  0x1f  0x4b  0x72  0x8e  0xd0  0x55  0x19
0x7fffffffd9e8: 0xc7  0x3a  0x61  0x88  0xf2  0x0d  0xae  0x43
0x7fffffffd9f0: 0x5b  0xe9  0x17  0x6c  0xd4  0x82  0xf0  0x3e
0x7fffffffd9f8: 0xa1  0x56  0xc8  0x7d  0x09  0xbb  0x4f  0xe2

# AES-CBC IV: 16 bytes starting from the address in r8
(gdb) x/16bx $r8
0x7fffffffda10: 0x9c  0x71  0x2e  0xb5  0x38  0xf4  0xa0  0x6d
0x7fffffffda18: 0x1c  0x83  0xe7  0x52  0xbf  0x49  0x06  0xda
```

We have the key and IV. That's all we need for decryption. But let's go further.

### Dumping the Key to a File

For programmatic use (Python decryption script), we can dump the bytes directly to a file:

```bash
# Dump the key (32 bytes) to a file
(gdb) dump binary memory /tmp/key.bin $rcx ($rcx + 32)

# Dump the IV (16 bytes)
(gdb) dump binary memory /tmp/iv.bin $r8 ($r8 + 16)
```

We can verify the result immediately:

```bash
$ xxd /tmp/key.bin
00000000: a31f 4b72 8ed0 5519 c73a 6188 f20d ae43  ..Kr..U..:a....C
00000010: 5be9 176c d482 f03e a156 c87d 09bb 4fe2  [..l...>.V.}..O.

$ xxd /tmp/iv.bin
00000000: 9c71 2eb5 38f4 a06d 1c83 e752 bf49 06da  .q..8..m...R.I..
```

### Breakpoint on `derive_key` — Understanding the Derivation

If we also want to understand *how* the key is constructed (not just capture it), we set a breakpoint on the internal derivation function:

```bash
(gdb) break derive_key
Breakpoint 2 at 0x... : file crypto.c, line 73.
(gdb) run secret.txt
```

We can then step through (`next`, `step`) and observe each stage:

```bash
# After the call to build_passphrase() — read the passphrase in memory
(gdb) next
(gdb) x/s $rbp-0x50
0x7fffffffd990: "r3vers3_m3_1f_y0u_c4n!"

# After SHA256() — read the hash
(gdb) next
(gdb) x/32bx $rbp-0x30
0x7fffffffd9b0: 0x7d  0xb2  0xf5  0x9d  ...  # SHA-256 of the passphrase

# After the XOR loop — read the final key
(gdb) next  # (exiting the loop)
(gdb) x/32bx <address of out_key>
```

We thus reconstruct the entire chain: passphrase → SHA-256 → XOR with the mask → final AES key.

### Automating with a GDB Python Script

For cases where we want to capture keys without manual intervention (batch execution, or capture on a binary that encrypts multiple files), a GDB Python script is the solution:

```python
# extract_crypto_params.py — GDB script to capture key + IV
# Usage: gdb -q -x extract_crypto_params.py ./crypto_O0

import gdb

class CryptoBreakpoint(gdb.Breakpoint):
    """Breakpoint on EVP_EncryptInit_ex that dumps the key and IV."""

    def __init__(self):
        super().__init__("EVP_EncryptInit_ex", gdb.BP_BREAKPOINT)
        self.silent = True  # no standard GDB message
        self.count = 0

    def stop(self):
        self.count += 1
        inferior = gdb.selected_inferior()

        # Read registers (System V AMD64: key=rcx, iv=r8)
        rcx = int(gdb.parse_and_eval("$rcx"))
        r8  = int(gdb.parse_and_eval("$r8"))

        # Read the key (32 bytes)
        key_bytes = inferior.read_memory(rcx, 32)
        key_hex = key_bytes.tobytes().hex()

        # Read the IV (16 bytes) — r8 can be NULL if no IV
        if r8 != 0:
            iv_bytes = inferior.read_memory(r8, 16)
            iv_hex = iv_bytes.tobytes().hex()
        else:
            iv_hex = "(null — no IV)"

        print(f"\n{'='*60}")
        print(f"[*] EVP_EncryptInit_ex call #{self.count}")
        print(f"[*] Key (32 bytes): {key_hex}")
        print(f"[*] IV  (16 bytes): {iv_hex}")
        print(f"{'='*60}\n")

        # Save to files
        with open(f"/tmp/key_{self.count}.bin", "wb") as f:
            f.write(key_bytes.tobytes())
        with open(f"/tmp/iv_{self.count}.bin", "wb") as f:
            f.write(iv_bytes.tobytes() if r8 != 0 else b"")

        print(f"[+] Saved to /tmp/key_{self.count}.bin"
              f" and /tmp/iv_{self.count}.bin")

        return False  # False = don't stop, continue execution

# Install the breakpoint
CryptoBreakpoint()

# Run the program
gdb.execute("run secret.txt")
```

We launch with:

```bash
$ gdb -q -batch -x extract_crypto_params.py ./crypto_O0
```

The script silently captures each call to `EVP_EncryptInit_ex`, dumps the key and IV to files, and lets the program execute normally.

### GDB on a Stripped Binary

On `crypto_O2_strip`, the local symbols (`derive_key`, `build_passphrase`) are gone. But the dynamic symbols (`EVP_EncryptInit_ex`) are still accessible because they come from `libcrypto.so`:

```bash
$ gdb -q ./crypto_O2_strip
(gdb) break EVP_EncryptInit_ex
Breakpoint 1 at 0x... (in /lib/x86_64-linux-gnu/libcrypto.so.3)
(gdb) run secret.txt
```

The breakpoint works. The registers contain the same values. Stripping does not protect interception points located in dynamic libraries.

For the statically linked stripped binary, the `EVP_EncryptInit_ex` symbol no longer exists. You then need to find the function address manually:

1. Identify the address via crypto constants (XREF from the AES S-box in Ghidra, as seen in 24.1-24.2).  
2. Walk up the call graph to the initialization function.  
3. Set a breakpoint on the found address: `break *0x00401a3c`.

It is more laborious but the result is the same.

---

## Method 2: Frida — In-Flight Instrumentation

Frida offers a complementary approach to GDB. Where GDB freezes execution and waits for our commands, Frida injects JavaScript code into the target process, intercepts calls in real time, and reports results without interrupting execution. This is particularly well-suited when the binary performs many crypto operations (encrypting multiple files, encrypted network communication in a loop...) and you want to capture everything at once.

### Hooking `EVP_EncryptInit_ex`

The following Frida script intercepts each call to `EVP_EncryptInit_ex` and displays the key and IV:

```javascript
// hook_crypto.js — Frida script to capture crypto parameters
// Usage: frida -l hook_crypto.js -f ./crypto_O0 -- secret.txt

// Resolve the address of EVP_EncryptInit_ex in libcrypto
const EVP_EncryptInit_ex = Module.findExportByName("libcrypto.so.3",
                                                    "EVP_EncryptInit_ex");
if (!EVP_EncryptInit_ex) {
    // Try without version number
    const alt = Module.findExportByName("libcrypto.so",
                                        "EVP_EncryptInit_ex");
    if (!alt) {
        console.log("[-] EVP_EncryptInit_ex not found");
    }
}

if (EVP_EncryptInit_ex) {
    Interceptor.attach(EVP_EncryptInit_ex, {

        onEnter: function(args) {
            // args[0] = ctx, args[1] = type, args[2] = impl
            // args[3] = key, args[4] = iv

            const keyPtr = args[3];
            const ivPtr  = args[4];

            console.log("\n" + "=".repeat(60));
            console.log("[*] EVP_EncryptInit_ex called");

            // Read the key (32 bytes for AES-256)
            if (!keyPtr.isNull()) {
                const keyBuf = keyPtr.readByteArray(32);
                console.log("[*] Key (32 bytes):");
                console.log(hexdump(keyBuf, { ansi: true }));
            } else {
                console.log("[*] Key: NULL (reusing previous key)");
            }

            // Read the IV (16 bytes)
            if (!ivPtr.isNull()) {
                const ivBuf = ivPtr.readByteArray(16);
                console.log("[*] IV (16 bytes):");
                console.log(hexdump(ivBuf, { ansi: true }));
            } else {
                console.log("[*] IV: NULL (reusing previous IV)");
            }

            console.log("=".repeat(60));
        }
    });

    console.log("[+] Hooked EVP_EncryptInit_ex at " + EVP_EncryptInit_ex);
}
```

We launch with `frida` in spawn mode (Frida starts the process):

```bash
$ frida -l hook_crypto.js -f ./crypto_O0 -- secret.txt
```

The output displays the key and IV in a readable hexdump as soon as `EVP_EncryptInit_ex` is called, then the program continues normally and produces `secret.enc`.

### Extended Hooking: Capturing the Plaintext and Ciphertext

To see the data itself, we also hook `EVP_EncryptUpdate`:

```javascript
const EVP_EncryptUpdate = Module.findExportByName("libcrypto.so.3",
                                                   "EVP_EncryptUpdate");

if (EVP_EncryptUpdate) {
    Interceptor.attach(EVP_EncryptUpdate, {

        onEnter: function(args) {
            // int EVP_EncryptUpdate(ctx, out, outl, in, inl)
            // args[3] = in (plaintext), args[4] = inl (size)
            this.inPtr = args[3];
            this.inLen = args[4].toInt32();
            this.outPtr = args[1];
            this.outlPtr = args[2];

            console.log("\n[*] EVP_EncryptUpdate — plaintext ("
                        + this.inLen + " bytes):");
            if (this.inLen > 0 && this.inLen < 4096) {
                console.log(hexdump(this.inPtr.readByteArray(this.inLen),
                            { ansi: true }));
            }
        },

        onLeave: function(retval) {
            // After the call: read the written size
            const written = this.outlPtr.readInt();
            if (written > 0) {
                console.log("[*] EVP_EncryptUpdate — ciphertext ("
                            + written + " bytes):");
                console.log(hexdump(this.outPtr.readByteArray(written),
                            { ansi: true }));
            }
        }
    });

    console.log("[+] Hooked EVP_EncryptUpdate at " + EVP_EncryptUpdate);
}
```

With this hook, we see the plaintext going in and the ciphertext coming out. This is an independent means of validation: we will be able to verify that our Python decryption script (section 24.5) produces exactly the same plaintext.

### Hooking `derive_key` — Capturing the Passphrase and Hash

For functions internal to the binary (not from an external library), Frida can locate them in two ways:

**If symbols are present** (`crypto_O0`):

```javascript
const derive_key = DebugSymbol.getFunctionByName("derive_key");  
console.log("[*] derive_key at " + derive_key);  
```

**If the binary is stripped** — we use the address found via static analysis (Ghidra):

```javascript
const base = Module.findBaseAddress("crypto_O2_strip");
// Relative address found in Ghidra, for example 0x1340
const derive_key = base.add(0x1340);
```

We can then hook this function to capture the passphrase and derived key:

```javascript
Interceptor.attach(derive_key, {

    onEnter: function(args) {
        // derive_key(unsigned char *out_key)
        // args[0] = pointer to the output buffer (32 bytes)
        this.outKeyPtr = args[0];
        console.log("[*] derive_key() called, output buffer at "
                    + this.outKeyPtr);
    },

    onLeave: function(retval) {
        // On return, the buffer contains the derived key
        console.log("[*] derive_key() returned — derived key:");
        console.log(hexdump(this.outKeyPtr.readByteArray(32),
                    { ansi: true }));
    }
});
```

The `onLeave` is crucial here: it is on function return that the buffer contains the final key. If we read it in `onEnter`, the buffer would still be empty or contain residual data.

### Frida on a Statically Linked Binary

When crypto is statically linked, `Module.findExportByName("libcrypto.so.3", ...)` will find nothing (there is no `libcrypto.so.3`). You need to search for the function directly in the binary:

```javascript
// Search by name in the main binary (if symbols are present)
const func = Module.findExportByName(null, "EVP_EncryptInit_ex");

// Or by address (if stripped) — address found via Ghidra
const base = Process.enumerateModules()[0].base;  
const func = base.add(0x00045a20);  // relative address in the binary  
```

The principle is the same: once the address is known, `Interceptor.attach` works identically.

---

## Method 3: Frida + `frida-trace` — The Fast Track

For an initial diagnostic without writing a script, `frida-trace` automatically generates hooking stubs:

```bash
$ frida-trace -f ./crypto_O0 -i "EVP_*" -- secret.txt
```

Frida-trace creates a JavaScript handler file for each matched function in `__handlers__/libcrypto.so.3/`. You can edit these handlers to add parameter display. This is a good starting point when you don't yet know precisely which functions are interesting: you hook broadly (`EVP_*`, `SHA*`, `AES_*`) and observe what comes through.

---

## GDB vs Frida: When to Use Which

The two tools are complementary. The choice depends on the context:

| Criterion | GDB | Frida |  
|---|---|---|  
| **Precision** | Instruction by instruction | Function by function |  
| **Interruption** | Freezes the program | Continues execution |  
| **Exploration** | Ideal for understanding logic step by step | Ideal for capturing data in bulk |  
| **Automation** | GDB Python script | JavaScript script, r2pipe |  
| **Anti-debug** | Detectable (`ptrace`) | More discreet (injection) |  
| **Stripped binary** | Breakpoint by address | Same, but more ergonomic hook |  
| **Multiple calls** | Tedious manually | Natural (persistent hook) |

**Practical recommendation**: start with GDB to understand the flow and validate hypotheses on a single call, then switch to Frida to capture everything in production or automate extraction.

---

## Precautions and Common Pitfalls

**Timing matters.** If the binary erases the key from memory after use (`memset(key, 0, KEY_LEN)` — as our `crypto.c` does), you must capture the key *before* the cleanup. The breakpoint must be on `EVP_EncryptInit_ex` (the key is still alive there), not after the return of the wrapper function that performs the `memset`.

**ASLR and addresses.** Absolute addresses change with each execution due to ASLR. For address-based breakpoints on a PIE binary, you must either disable ASLR temporarily (`echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`), or use offsets relative to the module base (Frida handles this natively with `Module.findBaseAddress`).

**Endianness.** Bytes read from memory on x86-64 are in little-endian. If the algorithm expects the key as a byte array (which is the case for AES), there is no conversion to do — the bytes are in the correct order. However, if you compare with 32/64-bit constants (SHA-256 values for example), you need to account for the byte swap.

**`EVP_EncryptInit_ex` can be called with `key = NULL`.** OpenSSL allows splitting initialization into two calls: a first one to set the cipher, a second one to provide the key and IV. You must handle the `NULL` case in scripts (our Frida script above does this).

**Debugger detection.** Some binaries (malware, protected software) detect the presence of a debugger via `ptrace(PTRACE_TRACEME)`, checking `/proc/self/status`, or timing checks. Workarounds are covered in detail in chapter 19 (section 19.7). In summary: `LD_PRELOAD` of a `ptrace` stub, patching the check, or using Frida (which does not use `ptrace` on Linux by default when using spawn mode with `frida-gadget`).

---

## Complete Walkthrough on `crypto_O0`

Let's summarize the complete extraction flow on our training binary:

**1. Prior identification** (sections 24.1 and 24.2): AES-256-CBC via OpenSSL, SHA-256 for derivation.

**2. GDB capture of the key and IV**:
```bash
$ gdb -q ./crypto_O0
(gdb) break EVP_EncryptInit_ex
(gdb) run secret.txt
(gdb) dump binary memory /tmp/key.bin $rcx ($rcx + 32)
(gdb) dump binary memory /tmp/iv.bin $r8 ($r8 + 16)
(gdb) continue
```

**3. GDB capture of the passphrase** (to understand the derivation):
```bash
(gdb) break build_passphrase
(gdb) run secret.txt
(gdb) finish
(gdb) x/s <address of the out buffer>
"r3vers3_m3_1f_y0u_c4n!"
```

**4. Cross-validation with Frida**:
```bash
$ frida -l hook_crypto.js -f ./crypto_O0 -- secret.txt
```

We verify that the values captured by Frida match exactly those from GDB. If so, we have high confidence in our data.

**5. Result**: we have the AES-256 key (32 bytes), the IV (16 bytes), and we know the source passphrase (`r3vers3_m3_1f_y0u_c4n!`) as well as the derivation logic (SHA-256 → XOR mask). All the pieces are in hand for section 24.5 (reproduction in Python).

But before that, the next section examines the `secret.enc` file itself more closely, to understand how the encrypted data is structured and packaged.

---


⏭️ [Visualize the Encrypted Format and Structures with ImHex](/24-crypto/04-visualizing-format-imhex.md)
