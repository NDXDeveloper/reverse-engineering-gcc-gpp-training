# Solution — Chapter 27 Checkpoint

> **Spoilers** — Only consult this document after attempting the checkpoint yourself.

---

## 1. Summary of Expected Approach

The checkpoint asks to treat `ransomware_O2_strip` (stripped variant) as an unknown binary and produce four deliverables. Here is the complete walkthrough.

---

## 2. Quick Triage (5–10 min)

### Commands and Key Results

```bash
# Identification
$ file ransomware_O2_strip
ransomware_O2_strip: ELF 64-bit LSB pie executable, x86-64, [...] stripped

# Dependencies → libssl + libcrypto = OpenSSL crypto
$ readelf -d ransomware_O2_strip | grep NEEDED
  (NEEDED)  Shared library: [libssl.so.3]
  (NEEDED)  Shared library: [libcrypto.so.3]
  (NEEDED)  Shared library: [libc.so.6]

# Critical strings
$ strings ransomware_O2_strip | grep -E '(tmp|locked|RWARE|REVERSE|EVP_|CHIFFRE)'
/tmp/test
.locked
README_LOCKED.txt  
RWARE27  
REVERSE_ENGINEERING_IS_FUN_2025!  
EVP_EncryptInit_ex  
EVP_EncryptUpdate  
EVP_EncryptFinal_ex  
EVP_aes_256_cbc  
YOUR FILES HAVE BEEN ENCRYPTED!  

# Protections
$ checksec --file=ransomware_O2_strip
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

# Relevant dynamic symbols
$ readelf -s --dyn-syms ransomware_O2_strip | grep FUNC | \
    grep -E '(EVP_|opendir|readdir|unlink|fopen|stat|malloc)'
    [...] EVP_CIPHER_CTX_new
    [...] EVP_CIPHER_CTX_free
    [...] EVP_EncryptInit_ex
    [...] EVP_EncryptUpdate
    [...] EVP_EncryptFinal_ex
    [...] EVP_aes_256_cbc
    [...] opendir
    [...] readdir
    [...] stat
    [...] fopen
    [...] unlink
    [...] malloc

# IV in .rodata (hex search)
$ objdump -s -j .rodata ransomware_O2_strip | grep -A1 "dead"
 [...] deadbeef cafebabe 13374242 feedface  ................
```

### Formulated Hypotheses

| # | Hypothesis | Confidence |  
|---|---|---|  
| H1 | Ransomware targeting `/tmp/test/` | High |  
| H2 | AES-256-CBC via OpenSSL EVP | High |  
| H3 | Key = `REVERSE_ENGINEERING_IS_FUN_2025!` (32 bytes) | Medium |  
| H4 | IV = `DEADBEEFCAFEBABE13374242FEEDFACE` (16 bytes) | Medium |  
| H5 | `RWARE27` header in encrypted files | Medium |  
| H6 | Recursive traversal + deletion of originals | High |  
| H7 | No network communication | Medium |

---

## 3. Static Analysis in Ghidra (30–45 min)

### Strategy for Stripped Binary

The binary contains no internal symbols. The method consists of starting from **named imports** (OpenSSL functions in `.dynsym`) and tracing back via cross-references (XREF).

### Reconstruction Steps

**Step 1 — Find `aes256cbc_encrypt`.**
In the Symbol Tree, locate `EVP_EncryptInit_ex` → right-click → *References → Show References to*. A single call site leads to the encryption wrapper function. Rename it `aes256cbc_encrypt`.

The decompiler shows the `Init → Update → Final` sequence and two `.rodata` addresses passed as arguments 4 (`rcx` = key) and 5 (`r8` = IV) of `EVP_EncryptInit_ex`.

**Step 2 — Confirm the key and IV.**
Navigate to the 4th argument address: 32 ASCII bytes = `REVERSE_ENGINEERING_IS_FUN_2025!`. Navigate to the 5th: 16 bytes = `DE AD BE EF CA FE BA BE 13 37 42 42 FE ED FA CE`. Rename to `AES_KEY` and `AES_IV`.

**Step 3 — Find `encrypt_file`.**
XREF from `aes256cbc_encrypt` → a single caller. The decompiler shows: `fopen` → `fseek/ftell/fread` → `aes256cbc_encrypt` → `fwrite` (magic + size + ciphertext) → `unlink`. Rename `encrypt_file`.

**Step 4 — Find `traverse_directory`.**
XREF from `encrypt_file` → caller with `opendir/readdir/stat` loop and recursive call to itself. Rename `traverse_directory`.

**Step 5 — Find `main`.**
XREF from `traverse_directory`. Or: locate `__libc_start_main` in imports → XREF to `_start` → the first argument is `main`. The pseudo-code shows: `stat("/tmp/test")` → `traverse_directory` → `drop_ransom_note`.

### Final Call Graph

```
main()
 ├── print_banner()            → printf()
 ├── stat()                    → verifies /tmp/test
 ├── traverse_directory()
 │     ├── opendir() / readdir() / closedir()
 │     ├── stat()              → file or directory?
 │     ├── should_skip()       → strcmp(".locked"), strcmp("README_LOCKED.txt")
 │     ├── traverse_directory() → recursion
 │     └── encrypt_file()
 │           ├── fopen/fseek/ftell/fread/fclose  → reading
 │           ├── malloc/free
 │           ├── aes256cbc_encrypt()
 │           │     ├── EVP_CIPHER_CTX_new()
 │           │     ├── EVP_aes_256_cbc()
 │           │     ├── EVP_EncryptInit_ex()      → AES_KEY, AES_IV
 │           │     ├── EVP_EncryptUpdate()
 │           │     ├── EVP_EncryptFinal_ex()
 │           │     └── EVP_CIPHER_CTX_free()
 │           ├── snprintf()    → "%s.locked"
 │           ├── fopen/fwrite/fclose             → .locked writing
 │           └── unlink()                        → original deletion
 └── drop_ransom_note()
       ├── snprintf() / fopen() / fputs() / fclose()
```

### `.locked` Format (deduced from `encrypt_file`)

Three successive `fwrite` calls in `encrypt_file`:

1. `fwrite("RWARE27\0", 1, 8, fp)` → magic, 8 bytes  
2. `fwrite(&file_size, 8, 1, fp)` → original size, uint64_t LE  
3. `fwrite(ciphertext, 1, ciphertext_len, fp)` → encrypted payload

```
Offset   Size     Type          Content
0x00     8        char[8]       "RWARE27\0"
0x08     8        uint64_t LE   Original size
0x10     var.     byte[]        AES-256-CBC ciphertext (PKCS#7)
```

---

## 4. Dynamic Analysis — GDB (15–20 min)

### Capturing the Key and IV

```gdb
$ gdb -q ./ransomware_O2_strip

(gdb) break EVP_EncryptInit_ex
Make breakpoint pending on future shared library load? (y or [n]) y

(gdb) run

Breakpoint 1, 0x00007ffff7... in EVP_EncryptInit_ex ()

(gdb) x/32xb $rcx
0x...: 0x52 0x45 0x56 0x45 0x52 0x53 0x45 0x5f
0x...: 0x45 0x4e 0x47 0x49 0x4e 0x45 0x45 0x52
0x...: 0x49 0x4e 0x47 0x5f 0x49 0x53 0x5f 0x46
0x...: 0x55 0x4e 0x5f 0x32 0x30 0x32 0x35 0x21

(gdb) x/s $rcx
0x...: "REVERSE_ENGINEERING_IS_FUN_2025!"

(gdb) x/16xb $r8
0x...: 0xde 0xad 0xbe 0xef 0xca 0xfe 0xba 0xbe
0x...: 0x13 0x37 0x42 0x42 0xfe 0xed 0xfa 0xce
```

H3 and H4 move from "Medium" to **"Definitively Confirmed"**.

### Key Rotation Check

```gdb
(gdb) commands 1
    silent
    printf "Key: "
    x/32xb $rcx
    printf "IV:  "
    x/16xb $r8
    continue
end
(gdb) run
```

All 6 calls display the same values → **no key rotation**.

### Confirming No Network Activity

```bash
$ strace -e trace=network ./ransomware_O2_strip 2>&1 | grep -v "^---"
# (no output) → H7 confirmed
```

---

## 5. Dynamic Analysis — Frida (10–15 min)

```javascript
// hook_evp.js
const evpInit = Module.findExportByName("libcrypto.so.3", "EVP_EncryptInit_ex");  
Interceptor.attach(evpInit, {  
    onEnter(args) {
        console.log("=== EVP_EncryptInit_ex ===");
        console.log("Key:"); console.log(hexdump(args[3], { length: 32 }));
        console.log("IV:");  console.log(hexdump(args[4], { length: 16 }));
    }
});
```

```bash
$ frida -f ./ransomware_O2_strip -l hook_evp.js --no-pause
```

Result identical to GDB — cross-confirmation by a second tool.

---

## 6. ImHex Pattern (`.hexpat`)

```hexpat
/*!
 * Ch27 Solution — .locked Format
 */

#pragma endian little

struct MagicHeader {
    char signature[7] [[comment("Format ID")]];
    u8   null_term    [[comment("\\0")]];
} [[color("FF6B6B"), name("Magic")]];

struct FileMetadata {
    u64 original_size [[comment("Original file size")]];
} [[color("4ECDC4"), name("Metadata")]];

struct EncryptedPayload {
    u8 data[std::mem::size() - 16] [[comment("AES-256-CBC + PKCS#7")]];
} [[color("FFE66D"), name("Ciphertext")]];

struct LockedFile {
    MagicHeader      header;
    FileMetadata     metadata;
    EncryptedPayload payload;
};

LockedFile file @ 0x00;
```

Verification: load in ImHex on `document.txt.locked`. The `original_size` field in the Data Inspector should display `47` (size of `document.txt`).

---

## 7. YARA Rules

```yara
rule ransomware_ch27_exact
{
    meta:
        description = "Ch27 Solution — exact sample detection"
        author      = "RE Training"

    strings:
        $aes_key = {
            52 45 56 45 52 53 45 5F 45 4E 47 49 4E 45 45 52
            49 4E 47 5F 49 53 5F 46 55 4E 5F 32 30 32 35 21
        }
        $aes_iv = {
            DE AD BE EF CA FE BA BE 13 37 42 42 FE ED FA CE
        }
        $target   = "/tmp/test"       ascii
        $ext      = ".locked"         ascii
        $note     = "README_LOCKED"   ascii
        $magic    = "RWARE27"         ascii

    condition:
        uint32(0) == 0x464C457F
        and $aes_key and $aes_iv
        and 3 of ($target, $ext, $note, $magic)
}

rule ransomware_ch27_generic
{
    meta:
        description = "Ch27 Solution — generic behavioral detection"
        author      = "RE Training"

    strings:
        $evp_init   = "EVP_EncryptInit_ex"  ascii
        $evp_update = "EVP_EncryptUpdate"   ascii
        $evp_final  = "EVP_EncryptFinal_ex" ascii
        $evp_aes    = "EVP_aes_256_cbc"     ascii
        $fs_opendir = "opendir"             ascii
        $fs_readdir = "readdir"             ascii
        $fs_unlink  = "unlink"              ascii
        $locked     = ".locked"             ascii
        $magic      = "RWARE27"             ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 500KB
        and 3 of ($evp_init, $evp_update, $evp_final, $evp_aes)
        and 2 of ($fs_opendir, $fs_readdir, $fs_unlink)
        and ($locked or $magic)
}

rule ransomware_ch27_locked_file
{
    meta:
        description = "Ch27 Solution — .locked file detection"
        author      = "RE Training"

    strings:
        $magic = { 52 57 41 52 45 32 37 00 }

    condition:
        $magic at 0 and filesize > 16 and filesize < 100MB
}
```

### Validation

```bash
$ yara ch27.yar ransomware_O2_strip
ransomware_ch27_exact ransomware_O2_strip  
ransomware_ch27_generic ransomware_O2_strip  

$ yara ch27.yar /usr/bin/openssl
# (no output → no false positive)

$ yara -r ch27.yar /tmp/test/
ransomware_ch27_locked_file /tmp/test/document.txt.locked  
ransomware_ch27_locked_file /tmp/test/notes.md.locked  
[...]
```

---

## 8. Python Decryptor

The complete script is in `solutions/ch27-checkpoint-decryptor.py`.

### Hash Validation

```bash
# Before encryption
$ make reset
$ find /tmp/test -type f -exec sha256sum {} \; | sort > /tmp/before.txt

# Encryption
$ ./ransomware_O2_strip

# Decryption
$ python3 solutions/ch27-checkpoint-decryptor.py /tmp/test/ --verify

# Comparison
$ find /tmp/test -type f ! -name "*.locked" ! -name "README_LOCKED.txt" \
    -exec sha256sum {} \; | sort > /tmp/after.txt
$ diff /tmp/before.txt /tmp/after.txt
# (no output = perfect restoration)
```

---

## 9. Analysis Report (Solution Summary)

The complete report follows the template from section 27.7. Here are the essential expected elements:

**Executive Summary** — Linux ELF ransomware, AES-256-CBC, hardcoded key, 100% recoverable files, low sophistication, no network, no persistence.

**Minimum Expected IOCs**:

| Type | Value |  
|---|---|  
| Binary SHA-256 | `[hash computed by the student]` |  
| Target directory | `/tmp/test` |  
| Extension | `.locked` |  
| Ransom note | `README_LOCKED.txt` |  
| Magic header | `RWARE27\0` |  
| AES-256 key | `REVERSE_ENGINEERING_IS_FUN_2025!` |  
| AES IV | `DEADBEEFCAFEBABE13374242FEEDFACE` |  
| Crypto API | `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex` |

**ATT&CK Matrix** — T1204 (User Execution), T1083 (File Discovery), T1486 (Data Encrypted for Impact), T1485 (Data Destruction).

**Minimum Recommendations**:
1. Deploy the decryptor on affected systems.  
2. Scan infrastructure with YARA rules.  
3. Identify the initial infection vector.  
4. Verify/implement offline backups.

---

## 10. Completed Validation Grid

| Item | Status |  
|---|---|  
| Algorithm identified (AES-256-CBC) without execution | ✅ `strings` + `EVP_aes_256_cbc` in `.dynsym` |  
| Key located in `.rodata` | ✅ 32 ASCII bytes via Ghidra XREF |  
| IV located in `.rodata` | ✅ 16 bytes via Ghidra XREF + `objdump` |  
| Call graph reconstructed | ✅ 6 internal functions renamed |  
| `.locked` format mapped | ✅ 3 fields (magic 8B + size 8B + ciphertext) |  
| Key captured dynamically ($rcx) | ✅ GDB breakpoint on `EVP_EncryptInit_ex` |  
| IV captured dynamically ($r8) | ✅ GDB breakpoint on `EVP_EncryptInit_ex` |  
| No key rotation | ✅ 6 calls, same values |  
| No network confirmed | ✅ `strace -e trace=network` silent |  
| Two dynamic tools used | ✅ GDB + Frida (or strace) |  
| Decryptor parses the header | ✅ Magic + uint64_t LE |  
| AES-256-CBC decryption correct | ✅ |  
| PKCS#7 padding removed | ✅ `padding.PKCS7(128)` — 128 bits |  
| Recursive traversal | ✅ `os.walk` |  
| Hash validation | ✅ `diff` with no output |  
| Error handling | ✅ Invalid magic, truncated file, ciphertext not multiple of 16 |  
| YARA rule detects the sample | ✅ |  
| No false positive on `/usr/bin/openssl` | ✅ |  
| YARA rule detects `.locked` files | ✅ |  
| ImHex pattern loads without error | ✅ |  
| Report with executive summary | ✅ |  
| SHA-256 hashes included | ✅ |  
| At least 5 IOCs | ✅ 8 listed |  
| Crypto parameters with confirmation source | ✅ |  
| At least 3 recommendations | ✅ 4 formulated |  
| Report readable by a third party | ✅ |

**Level achieved: Excellent** (full analysis on stripped variant, all deliverables produced, ATT&CK matrix included).
