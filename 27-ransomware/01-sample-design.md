🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.1 — Sample Design: AES Encryption on `/tmp/test`, Hardcoded Key

> 📁 **Relevant files**:  
> - `binaries/ch27-ransomware/ransomware_sample.c` — complete source code  
> - `binaries/ch27-ransomware/Makefile` — compilation of all 3 variants  
>  
> 💡 This section **intentionally** describes the internal design of the sample. In a real-world scenario, you would never have access to the source code: everything exposed here, you will have to find on your own in sections 27.2 through 27.6. The goal is to give you a mental map before diving into the analysis.

---

## Why build our own sample?

Working with real malware in a training context raises three major issues. The first is legal: distributing malicious code is regulated or even prohibited depending on the jurisdiction. The second is security: real ransomware often includes evasion mechanisms, lateral movement, or persistence that make it dangerous even in a lab. The third is pedagogical: a real sample is often obfuscated, packed, and communicates with a defunct C2 infrastructure — all obstacles that bury the learning under accidental complexity.

By designing our own sample, we control every parameter. The code is auditable, the behavior is deterministic, the scope of destruction is bounded, and most importantly, we can calibrate the difficulty by producing several variants of the same binary (debug, optimized, stripped). The student knows *exactly* what they are looking for — but must find it using reverse engineering alone.

---

## Functional architecture

The sample follows a linear flow in five steps, with no complex conditional branching or evasion mechanisms. This simplicity is intentional: it allows you to focus on crypto analysis and the reconstruction of the encryption scheme.

```
main()
  │
  ├─ 1. Verify that /tmp/test/ exists
  │     └─ If missing → error message, exit(1)
  │
  ├─ 2. Recursive traversal of /tmp/test/
  │     └─ traverse_directory()
  │           ├─ Skip "." and ".."
  │           ├─ Skip .locked files (already encrypted)
  │           ├─ Skip README_LOCKED.txt (ransom note)
  │           ├─ Descend into subdirectories
  │           └─ For each regular file → encrypt_file()
  │
  ├─ 3. Encrypt each file
  │     └─ encrypt_file()
  │           ├─ Read entire file into memory (fread)
  │           ├─ AES-256-CBC encryption (OpenSSL EVP)
  │           ├─ Write <file>.locked with header
  │           └─ Delete original file (unlink)
  │
  ├─ 4. Drop the ransom note
  │     └─ drop_ransom_note()
  │
  └─ 5. Display summary and exit(0)
```

There is no network communication, no persistence mechanism, no privilege escalation attempt. The binary does one thing: encrypt files in a specific directory.

---

## Cryptographic choices

### Algorithm: AES-256-CBC

The sample uses AES in CBC (Cipher Block Chaining) mode with a 256-bit key. This choice reflects what is frequently observed in real-world ransomware: AES is fast, available everywhere, and CBC mode is one of the most common in OpenSSL-based implementations.

The core encryption call relies on the OpenSSL EVP API, which breaks down into three phases:

```c
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);  
EVP_EncryptUpdate(ctx, out, &len, in, in_len);  
EVP_EncryptFinal_ex(ctx, out + len, &len);  
```

From a reverse engineering perspective, this sequence of three calls is a **signature pattern**: when you see three successive calls to functions whose names contain `Init`, `Update`, and `Final` (or their PLT addresses if the binary is stripped), you'll know you're looking at an EVP crypto routine.

### Hardcoded key (32 bytes)

The key is declared as a `static const unsigned char` array of 32 bytes:

```c
static const unsigned char AES_KEY[32] = {
    0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x45, 0x5F,  /* REVERSE_ */
    0x45, 0x4E, 0x47, 0x49, 0x4E, 0x45, 0x45, 0x52,  /* ENGINEER */
    0x49, 0x4E, 0x47, 0x5F, 0x49, 0x53, 0x5F, 0x46,  /* ING_IS_F */
    0x55, 0x4E, 0x5F, 0x32, 0x30, 0x32, 0x35, 0x21   /* UN_2025! */
};
```

The ASCII value of this key is `REVERSE_ENGINEERING_IS_FUN_2025!`. This choice is deliberate on several levels:

- **For the `strings` exercise**: since the key consists of printable characters, a simple `strings ransomware_O0 | grep -i reverse` reveals it immediately. This is the student's first win, right at the triage stage.  
- **For the ImHex exercise**: in hex view, the sequence `52 45 56 45 52 53 45 5F ...` is visually identifiable in the `.rodata` section.  
- **For the GDB/Frida exercise**: the key is passed as an argument to `EVP_EncryptInit_ex`, making it capturable via a breakpoint or a hook on that function.

In a real ransomware, the symmetric key would obviously never be hardcoded like this. It would typically be randomly generated at each execution, then encrypted with an embedded RSA/ECDH public key, and transmitted to a C2 server or stored locally in encrypted form. The asymmetry between the public key (embedded) and the private key (held by the attacker) is what makes decryption impossible without paying. Here, we intentionally bypassed this step so that key recovery is feasible.

### Hardcoded IV (16 bytes)

The initialization vector is also static:

```c
static const unsigned char AES_IV[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE
};
```

The values `0xDEADBEEF`, `0xCAFEBABE`, `0x1337`, and `0xFEEDFACE` are **well-known magic numbers** in the world of systems development and security. They are used here for two reasons. First, they are immediately recognizable in hex view, making them easy to spot in ImHex. Second, they remind the student that real IVs should never be static: in CBC mode, reusing the same IV with the same key allows detection of whether two files start with the same content (the first encrypted blocks will be identical).

### PKCS#7 padding

CBC mode requires that the plaintext be a multiple of the block size (16 bytes for AES). OpenSSL applies PKCS#7 padding by default: if the last block is `n` bytes shorter than 16, it is padded with `n` bytes of value `n`. This detail matters for the decryptor: after decryption, this padding must be removed — or the original size stored in the `.locked` file header can be used.

---

## Encrypted file format (`.locked`)

Each encrypted file follows a simple binary format that the student will need to map with ImHex:

```
Offset   Size      Content
──────   ──────    ────────────────────────────────
0x00     8         Magic bytes: "RWARE27\0"
0x08     8         Original file size (uint64_t, little-endian)
0x10     variable  Encrypted data (AES-256-CBC, PKCS#7 padding included)
```

The `RWARE27` magic header serves as an identification marker. In an incident response context, this type of signature is what allows you to quickly inventory affected files on a compromised system (`find / -exec head -c 7 {} \; 2>/dev/null | grep RWARE27`). It is also the basis for a YARA rule (section 27.4).

The original size field at offset `0x08` is an implementation convenience: it allows the decryptor to truncate the result to the correct length after removing padding. Without this information, one would have to rely solely on PKCS#7 padding — which works, but this redundancy is common in real-world implementations.

---

## Scope of destruction: why `/tmp/test/`

The target directory is hardcoded to `/tmp/test/` via the `TARGET_DIR` constant. This choice explicitly bounds the sample's scope of destruction:

- `/tmp/` is a temporary directory, cleared on reboot on most Linux distributions.  
- The `test/` subdirectory must be manually created by the student (via `make testenv`), which constitutes an intentional action.  
- The program checks for the existence of `/tmp/test/` at startup and refuses to run if the directory does not exist.

Despite this limitation, the sample remains a program that **irreversibly deletes files** (via `unlink()`). This is why execution in a sandboxed VM with a prior snapshot remains mandatory.

The `Makefile` provides two utility targets to manage this environment:

- `make testenv` creates `/tmp/test/` and places six test files in it: a text document, a Markdown file, a fake PDF (text content), a random binary file (simulating an image), a CSV, and a file in a subdirectory to validate recursive traversal.  
- `make reset` deletes `/tmp/test/` and recreates it identically, avoiding the need to restore a full snapshot between tests.

---

## Recursive traversal and filtering

The `traverse_directory()` function uses the POSIX `opendir` / `readdir` / `closedir` API to enumerate directory entries. This choice produces characteristic assembly code that you will find in the disassembly: a loop calling `readdir` until it returns `NULL`, with calls to `stat` to distinguish files from directories, and a recursive call for subdirectories.

The filtering relies on two criteria implemented in `should_skip()`:

1. **`.locked` extension** — An already encrypted file is skipped. The check is done by comparing the last characters of the filename with the string `".locked"`. This pattern is visible with `strings` and constitutes a behavioral indicator (IOC) of the sample.  
2. **`README_LOCKED.txt` name** — The ransom note itself is excluded from encryption, otherwise it would immediately become unreadable.

From a RE perspective, these two strings (`.locked` and `README_LOCKED.txt`) will appear in the `.rodata` section and serve as valuable clues during triage.

---

## The ransom note

The `drop_ransom_note()` function writes a text file at the root of the target directory. Its content is stored as a string literal in the binary (`.rodata` section):

```
========================================
  YOUR FILES HAVE BEEN ENCRYPTED!
========================================

This is a pedagogical exercise.  
Reverse Engineering Training — Chapter 27  

Algorithm: AES-256-CBC  
The key is in the binary. Find it.  

Hint: look for the 32-byte constants...
========================================
```

In real ransomware, this note would contain a Bitcoin address, a Tor link to a payment portal, and a unique victim identifier. Here, it contains a pedagogical hint that guides the student toward the right track.

Note that the entire text will be visible via `strings`. This is a design choice: in a real triage scenario, the ransom note embedded in the binary is often the first element that allows classifying a sample as ransomware.

---

## OpenSSL dependency

The sample is dynamically linked against `libssl` and `libcrypto` (flags `-lssl -lcrypto` in the `Makefile`). This choice has direct consequences on the analysis:

- **With symbols**: calls to `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, and `EVP_EncryptFinal_ex` are visible in the dynamic symbol table. A simple `nm -D ransomware_O0 | grep EVP` lists them.  
- **Without symbols (stripped)**: internal function names disappear, but calls to the dynamic library still go through the PLT. You will see `call` instructions to PLT entries that remain resolvable via `objdump -d -j .plt` or in Ghidra.  
- **`ldd`**: the command `ldd ransomware_O0` will show the dependency on `libcrypto.so`, which is a strong indicator of the presence of cryptographic routines.  
- **`ltrace`**: by tracing library calls, `ltrace` will capture the EVP calls with their arguments — including the pointer to the key.

Using OpenSSL rather than a custom AES implementation is a realistic choice. Many real-world malware samples embed OpenSSL or reuse portions of it. This also provides practice in recognizing third-party libraries via FLIRT signatures (Ghidra/IDA) covered in [Chapter 20](/20-decompilation/README.md).

---

## The three compiled variants

The `Makefile` produces three binaries from the same source code, each offering an increasing level of analysis difficulty:

### `ransomware_O0` — Debug variant

```
gcc -Wall -Wextra -Wpedantic -O0 -g3 -ggdb -DDEBUG -o ransomware_O0 ransomware_sample.c -lssl -lcrypto
```

This is the most comfortable variant to start with. The `-O0` flag disables all optimization: each line of C code corresponds directly to a sequence of assembly instructions, all local variables are on the stack, and no function is inlined. The `-g3` flag includes maximum DWARF information: function names, variable names, line numbers, and even macro definitions.

This variant is ideal for establishing a mental mapping between the source code and the disassembly, before tackling the more difficult variants.

### `ransomware_O2` — Optimized variant with symbols

```
gcc -Wall -Wextra -Wpedantic -O2 -g -o ransomware_O2 ransomware_sample.c -lssl -lcrypto
```

The `-O2` flag enables a wide range of optimizations: inlining of small functions, basic block reordering, dead code elimination, constant propagation, and potentially vectorization of certain loops. The assembly code will be noticeably different from the `-O0` variant, but DWARF symbols remain present to guide the analysis.

The interest of this variant is twofold: concretely observe the impact of GCC optimizations on code you already know, and get used to reading denser, less sequential assembly.

### `ransomware_O2_strip` — Stripped variant

```
gcc -Wall -Wextra -Wpedantic -O2 -s -o ransomware_O2_strip ransomware_sample.c -lssl -lcrypto  
strip --strip-all ransomware_O2_strip  
```

This is the variant closest to what you would encounter in a real-world situation. Internal symbols have been removed: no more function names, no variable names, no line numbers. Only dynamic symbols (OpenSSL calls via the PLT) and strings in `.rodata` remain.

This variant is the one on which the final checkpoint must be completed. It forces you to leverage all the techniques covered in the training: pattern recognition, cross-references, dynamic analysis, and deductive reasoning.

---

## Intentional limitations of the sample

To keep the focus on cryptographic analysis and reverse engineering methodology, several aspects present in real ransomware have been intentionally omitted:

- **No random key generation** — The key is static, making it recoverable. Real ransomware would use `RAND_bytes()` or `/dev/urandom`.  
- **No asymmetric encryption** — There is no RSA/ECDH key to protect the symmetric key. This is the mechanism that makes real ransomware so hard to counter.  
- **No network communication** — No key exfiltration to a C2 server. This aspect is covered in [Chapter 28](/28-dropper/README.md) with the dropper.  
- **No persistence mechanism** — No writing to crontabs, systemd services, or init files.  
- **No anti-analysis** — No debugger detection, no VM detection, no packing. These techniques are covered in [Chapter 19](/19-anti-reversing/README.md).  
- **No secure deletion** — The original file is deleted by `unlink()`, but the data remains recoverable on disk with forensics tools. Advanced ransomware would overwrite the content before deletion.  
- **No multithreading** — Encryption is sequential. Modern ransomware massively parallelizes to maximize encryption speed.

Each of these simplifications is an open door to future exploration. Curious students can, after completing this chapter, modify the source code to add one of these features and observe its impact on the analysis.

---

## Compilation and preparation

From the `binaries/ch27-ransomware/` directory, the preparation sequence is as follows:

```bash
# Install the OpenSSL dependency (if not already done)
sudo apt install libssl-dev

# Compile all 3 variants
make all

# Prepare the test environment
make testenv

# Verify that the test files are in place
ls -la /tmp/test/

# ⚠️ TAKE A VM SNAPSHOT NOW
```

After running the sample, the environment can be restored either via the snapshot or via `make reset`, which recreates `/tmp/test/` identically.

To quickly verify that the binary works as expected on the debug variant:

```bash
./ransomware_O0
ls /tmp/test/        # The .locked files should appear  
xxd /tmp/test/document.txt.locked | head  
#   → The first 8 bytes should be 52 57 41 52 45 32 37 00 (RWARE27)
```

---

## What you will be looking for in the following sections

Now that you know the sample's architecture, set this knowledge aside. Sections 27.2 through 27.6 will ask you to **find each element** using reverse engineering alone:

- **27.2** — Quick triage with `file`, `strings`, `checksec`: what information can you extract in under five minutes, without opening a disassembler?  
- **27.3** — Static analysis in Ghidra and ImHex: where are the AES constants in the binary? How do you reconstruct the encryption flow from the disassembly?  
- **27.4** — YARA rules: how do you turn your observations into reusable detection signatures?  
- **27.5** — Dynamic analysis with GDB and Frida: how do you capture the key and IV at the exact moment they are passed to OpenSSL?  
- **27.6** — Python decryptor: how do you reproduce the AES-256-CBC scheme in reverse to restore the files?  
- **27.7** — Analysis report: how do you formalize all of this into a professional document?

⏭️ [Quick triage: `file`, `strings`, `checksec`, initial hypotheses](/27-ransomware/02-quick-triage.md)
