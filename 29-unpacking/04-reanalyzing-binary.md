🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 29.4 — Reanalyzing the Unpacked Binary

> 🎯 **Section objective** — Apply the standard analysis workflow (Parts II–IV of the training) to the reconstructed binary, validate that unpacking and reconstruction produced a usable ELF, and fully recover the original program's logic — from quick triage through to decompilation in Ghidra.

---

## Back to square one

In sections 29.1 through 29.3, we went through three stages: detecting the packing, extracting the decompressed code, then reconstructing a valid ELF file. We now have `packed_sample_reconstructed` — a 64-bit ELF containing the original program's code and data. It's time to verify that all this work paid off by subjecting this binary to the same analysis methodology as any other executable in the training.

This section serves as both **technical validation** (is the reconstruction correct?) and **pedagogical demonstration** (the analysis that completely failed on the packed binary now works normally). We'll structure it around the quick triage workflow presented in Chapter 5 (section 5.7), then push the analysis through to decompilation.

---

## Phase 1 — Quick triage: the first 5 minutes

We apply the Chapter 5 routine in parallel to the packed binary and the reconstructed binary, to highlight the contrast.

### `file`

```
$ file packed_sample_upx_tampered
packed_sample_upx_tampered: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),  
statically linked, no section header  

$ file packed_sample_reconstructed
packed_sample_reconstructed: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),  
statically linked, not stripped  
```

The reconstructed binary is recognized as a standard ELF. The `no section header` mention has disappeared: `readelf` and Ghidra can exploit the SHT we recreated in section 29.3.

### `strings`

```
$ strings packed_sample_upx_tampered | wc -l
9

$ strings packed_sample_reconstructed | wc -l
84
```

The number of readable strings jumps from a handful to several dozen. We can now extract concrete information without executing the binary:

```
$ strings packed_sample_reconstructed | grep -i flag
FLAG{unp4ck3d_and_r3c0nstruct3d}

$ strings packed_sample_reconstructed | grep -i "key\|licence\|license\|RE29"
[*] Enter your license key (format RE29-XXXX):
[-] Hint: analyze the check_license_key function...

$ strings packed_sample_reconstructed | grep -i "author\|build\|watermark"
Author: Formation-RE-GNU  
BUILD:ch29-packed-2025  
<<< WATERMARK:PACKED_SAMPLE_ORIGINAL >>>
```

These `strings` outputs alone already reveal the program's overall behavior: it asks for a license key in the format `RE29-XXXX`, it contains a flag, and it carries identifiable metadata. On the packed binary, none of this information was accessible.

### `readelf -S` (sections)

```
$ readelf -S packed_sample_reconstructed
There are 6 section headers, starting at offset 0x6100:

Section Headers:
  [Nr] Name              Type             Address           Offset    Size
  [ 0]                   NULL             0000000000000000  00000000  0000...
  [ 1] .text             PROGBITS         0000000000401000  00001000  0003000
  [ 2] .rodata           PROGBITS         0000000000404000  00004000  0001000
  [ 3] .data             PROGBITS         0000000000405000  00005000  0001000
  [ 4] .bss              NOBITS           0000000000406000  00006000  0001000
  [ 5] .shstrtab         STRTAB           0000000000000000  00006000  000002d
```

The structure is clean. The packed binary had at best two or three sections with exotic names; the reconstructed binary has a standard SHT that every analysis tool recognizes.

### `checksec`

```
$ checksec --file=packed_sample_reconstructed
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

Protections aren't fully restored (no canary, no RELRO) because memory dump reconstruction doesn't recreate `.got`, `.plt`, or relocation metadata sections. However, NX can be correctly set if `LOAD` segment permissions were configured without the simultaneous `W+X` flags. This is an expected result: the reconstructed binary is intended for analysis, not production deployment.

---

## Phase 2 — Static analysis in Ghidra

### Import and auto-analysis

Open Ghidra, create a new project, and import `packed_sample_reconstructed`. Ghidra automatically detects the x86-64 ELF format. Run auto-analysis with default options (Decompiler Parameter ID, Aggressive Instruction Finder, etc.).

For comparison, if you had tried to import the packed binary into Ghidra, the auto-analysis would have produced an unusable result: the disassembler would have interpreted compressed data as instructions, generating thousands of false positives and an incoherent flow graph. On the reconstructed binary, analysis proceeds normally.

### Function identification

After auto-analysis, Ghidra should have automatically identified several functions in the `.text` section. In the **Symbol Tree → Functions** view, search for recognizable functions. If the binary isn't stripped (or if symbols survived in the dump), you'll directly find `main`, `check_license_key`, `xor_decode`, `compute_checksum`, and `print_debug_info`.

If the binary was stripped before packing (which is the case for our `packed_sample_O2_strip` used as the base), function names are not available. Ghidra assigns generic names (`FUN_00401000`, `FUN_004011a0`...). You must then identify functions by their content — this is exactly the reverse engineering work practiced in previous chapters.

### Identifying `main` without symbols

Start from the entry point. Navigating to address `0x401000` (our OEP), observe the startup code. If the OEP corresponds to `_start`, spot the call to `__libc_start_main` whose first argument (`rdi`) is `main`'s address. If the OEP points directly to `main` (simplified reconstruction case), you're already there.

In `main`'s decompiled output, recognize the program's structure through its strings. Ghidra resolves references to `.rodata` and displays strings in plaintext in the pseudo-code:

```c
void FUN_00401000(int argc, char **argv)
{
    puts("╔══════════════════════════════════════╗");
    // ...
    printf("[*] Enter your license key (format RE29-XXXX): ");
    fgets(local_58, 0x40, stdin);
    // ...
    if (FUN_004011a0(local_58) != 0) {
        // success branch
    }
}
```

The function `FUN_004011a0` called with user input as argument is clearly `check_license_key`. Rename it by double-clicking the name in Ghidra.

### Reconstructing the verification logic

Navigating into `check_license_key` (renamed), the decompiled output reveals the algorithm:

```c
int check_license_key(char *key)
{
    if (strlen(key) != 9) return 0;
    if (strncmp(key, "RE29-", 5) != 0) return 0;
    
    unsigned long user_val = strtoul(key + 5, &endptr, 16);
    uint32_t expected = compute_checksum("RE29-", 5);
    
    return (user_val == expected);
}
```

We identify the expected format (`RE29-XXXX`), the hexadecimal base of the variable part, and the call to `compute_checksum`. Navigating into that last function:

```c
uint32_t compute_checksum(char *buf, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += (uint32_t)buf[i] * (uint32_t)(i + 1);
    }
    return sum & 0xFFFF;
}
```

We can now compute the valid key. The checksum of `"RE29-"` is the weighted sum of each character's ASCII code, which we convert to hexadecimal to get `RE29-0337`. All this logic was completely invisible as long as the binary was packed.

### Identifying the XOR routine

Examining the "success" branch of `main`, we spot a call to a function that takes as parameters an output buffer, the `g_encrypted_msg` array, its size, the XOR key, and its length. The decompiled output of this function shows a classic XOR loop:

```c
void xor_decode(char *dst, uint8_t *src, size_t len,
                uint8_t *key, size_t klen)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i] ^ key[i % klen];
    }
    dst[len] = '\0';
}
```

By extracting the values of `g_encrypted_msg` and `g_xor_key` from `.rodata` (visible in Ghidra's Listing or in ImHex), we can reproduce the decryption manually and recover the `SUCCESS!` message.

### Spotting crypto constants

In Ghidra's **Defined Data** view (or via a byte sequence search in ImHex), we find the first 16 bytes of the AES S-box:

```
63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
```

These bytes are well-known constants (referenced in the tutorial's Appendix J). Their presence in a real binary would signal AES usage — here it's a pedagogical marker, but the identification technique is identical. On the packed binary, these constants were buried in compressed data and completely undetectable by static search.

---

## Phase 3 — Cross-validation with dynamic analysis

To confirm the static analysis conclusions, we can reuse the dynamic techniques from Chapters 11–13 on the **packed** binary (not the reconstructed one), directly targeting addresses identified in Ghidra.

### Verifying the key with GDB

Relaunch the packed binary under GDB, let it decompress to the OEP (section 29.2), then set a breakpoint on `check_license_key` at the address identified in Ghidra:

```
gef➤ break *0x4011a0  
gef➤ continue  
```

Enter `RE29-0337` as input. At the breakpoint, inspect the argument:

```
gef➤ x/s $rdi
0x7fffffffe0a0: "RE29-0337"
```

Continue execution; the program displays the success message and the flag. The key is correct.

### Hooking with Frida

We can also use Frida (Chapter 13) to intercept `check_license_key` on the packed binary during execution, without worrying about the packing:

```javascript
// hook_check_key.js
Interceptor.attach(ptr("0x4011a0"), {
    onEnter: function(args) {
        console.log("[*] check_license_key called");
        console.log("    key = " + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("    return = " + retval.toInt32());
    }
});
```

Frida injects into the process **after** the stub's decompression, which means the original code's addresses are directly accessible. This is a major advantage of dynamic instrumentation for reversing packed binaries: you completely bypass the packing by operating at the in-memory process level.

---

## Phase 4 — Comparison with the reference binary

The chapter's Makefile also produces `packed_sample_O2` (the binary compiled at `-O2` with symbols) and `packed_sample_O0` (at `-O0` with symbols). These versions serve as a **reference** for evaluating reconstruction quality.

### Structural comparison

```
$ readelf -S packed_sample_O2 | wc -l
31

$ readelf -S packed_sample_reconstructed | wc -l
9
```

The reference binary has 27 sections versus 6 in our reconstruction. The missing sections (`.plt`, `.got`, `.dynamic`, `.init`, `.fini`, `.eh_frame`, `.comment`...) were not recreated. This is expected: the reconstruction produces a **minimal but sufficient** ELF for analysis. The absent sections would provide additional information (import resolution, exception unwinding, compilation metadata) but are not essential for understanding the program's logic.

### Decompiled output comparison

Opening the reference binary and reconstructed binary side by side in two Ghidra instances, you can compare the decompiled quality function by function. Typical differences are:

- The reference binary has **function names** (`main`, `check_license_key`...) thanks to DWARF symbols. The reconstructed binary has generic names (`FUN_00401000`...) that must be manually renamed.  
- The reference binary has **correct variable types** (thanks to DWARF). The reconstructed binary uses Ghidra-inferred types (`undefined8`, `long`, `int`...) which are often correct in size but not in semantics.  
- The **code structure** (loops, conditions, calls) is identical in both cases. This is the essential point: the logic is fully recoverable.

### Binary comparison with `radiff2`

For a finer comparison, you can use `radiff2` (Chapter 10) on the code segment:

```
$ radiff2 -s packed_sample_O2_strip packed_sample_reconstructed
```

The differences should be limited to headers and metadata, not the machine code itself (provided the memory dump was done correctly and the optimization level is the same).

---

## Summary: what unpacking made possible

To conclude this chapter, let's recap the journey by comparing what could and couldn't be done before and after unpacking:

| Analysis | Packed binary | Reconstructed binary |  
|---------|---------------|---------------------|  
| `strings` → useful strings | No program strings | All strings (flag, messages, markers) |  
| `readelf -S` → sections | Absent or exotic | `.text`, `.rodata`, `.data`, `.bss` |  
| `checksec` → protections | Everything disabled (stub) | Reflects reconstructed segments |  
| Ghidra → disassembly | Noise (compressed data interpreted as code) | Coherent x86-64 code, functions identified |  
| Ghidra → decompilation | Unusable | Readable C pseudo-code, complete logic |  
| YARA → pattern detection | No matches (compressed data) | Crypto constants, strings, signatures |  
| Dynamic analysis (GDB/Frida) | Possible but requires finding the OEP first | Addresses directly usable from Ghidra |  
| Valid key identification | Impossible statically | Direct computation from decompiled output |

Unpacking is a **prerequisite** for any serious analysis of a protected binary. Without it, you work blindly; with it, you return to the normal situation of a stripped binary — a challenge certainly, but a tractable challenge with the techniques covered in the rest of the training.

---

> 📌 **Key takeaway** — The goal of unpacking is not to produce a perfect clone of the original binary. It's to produce a file structured enough for static analysis tools (Ghidra, radare2, IDA) to do their job. Once the decompiled output is readable and cross-references work, the mission is accomplished — the rest is standard reverse engineering.

⏭️ [🎯 Checkpoint: unpack `ch27-packed`, reconstruct the ELF and recover the original logic](/29-unpacking/checkpoint.md)
