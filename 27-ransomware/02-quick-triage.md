🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.2 — Quick Triage: `file`, `strings`, `checksec`, Initial Hypotheses

> 🕐 **Target time**: 5 to 10 minutes maximum.  
>  
> Quick triage is the first phase of any suspicious binary analysis. The goal is not to understand everything, but to formulate as many **actionable hypotheses** as possible in minimal time, without ever executing the binary. Everything is done through passive static analysis.  
>  
> This section applies the triage workflow from [Chapter 5, section 5.7](/05-basic-inspection-tools/07-quick-triage-workflow.md) to our `ransomware_O2_strip` sample — the stripped variant, the one simulating a real-world case.

---

## Step 1 — `file`: format identification

The very first command when facing an unknown binary is `file`. It identifies the file type by analyzing its magic bytes and headers, without executing it.

```bash
$ file ransomware_O2_strip
ransomware_O2_strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped  
```

Each fragment of this output is actionable information:

| Fragment | Interpretation |  
|---|---|  
| `ELF 64-bit LSB` | Native Linux binary, 64-bit architecture, little-endian. Not bytecode (.NET, Java), not a script. |  
| `pie executable` | Compiled as a Position-Independent Executable. Addresses will be relative — ASLR active. |  
| `x86-64` | Intel/AMD 64-bit architecture. We'll be working with `rax`, `rdi`, `rsi`, etc. registers. |  
| `dynamically linked` | The binary depends on shared libraries (`.so`). We can identify them with `ldd`. |  
| `interpreter /lib64/ld-linux-x86-64.so.2` | Standard GNU/Linux loader. Nothing exotic. |  
| `stripped` | Debug symbols have been removed. No internal function names, no DWARF. Analysis will be harder. |

**First hypothesis**: we are dealing with a classic native ELF x86-64 binary, compiled with a standard GNU toolchain, dynamically linked. The fact that it is stripped suggests an intent to complicate analysis — typical behavior of a malicious binary.

---

## Step 2 — `ldd`: dynamic dependencies

Since `file` indicates a dynamically linked binary, let's list its dependencies:

```bash
$ ldd ransomware_O2_strip
    linux-vdso.so.1 (0x00007fff...)
    libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x00007f...)
    libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3 (0x00007f...)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
    /lib64/ld-linux-x86-64.so.2 (0x00007f...)
```

> ⚠️ **Security reminder**: `ldd` can theoretically trigger code execution via the loader on certain configurations. On a truly suspicious binary, prefer `objdump -p <binary> | grep NEEDED` or `readelf -d <binary> | grep NEEDED`, which passively read ELF headers without invoking the loader. In our controlled case, `ldd` is safe.

The presence of `libssl` and `libcrypto` is a **strong signal**. A program that depends on OpenSSL very likely uses cryptographic primitives — encryption, hashing, signatures, or TLS. Combined with a stripped binary of unknown origin, this dependency immediately steers the analysis toward a crypto trail.

**Refined hypothesis**: the binary performs cryptographic operations via OpenSSL. The question remains: which ones (symmetric encryption? asymmetric? hashing? TLS?) and for what purpose.

---

## Step 3 — `strings`: extracting readable strings

The `strings` command extracts sequences of printable characters from a binary. It is often the richest source of information during triage. On a stripped binary, strings are sometimes the only textual clue remaining.

```bash
$ strings ransomware_O2_strip | head -80
```

Rather than reading a raw stream of hundreds of lines, let's proceed with targeted searches.

### 3a — Searching for filesystem-related terms

```bash
$ strings ransomware_O2_strip | grep -iE '(tmp|path|dir|file|open|read|write|unlink)'
```

Expected output (relevant excerpts):

```
/tmp/test
.locked
README_LOCKED.txt
```

Three extremely telling strings. `/tmp/test` designates a target directory. `.locked` is an extension appended to files. `README_LOCKED.txt` suggests a note dropped on the system. This trifecta — target directory, transformed file extension, text note — is the classic behavioral signature of a **ransomware** or file encryption tool.

### 3b — Searching for cryptography-related terms

```bash
$ strings ransomware_O2_strip | grep -iE '(aes|crypt|encrypt|decrypt|key|cipher|EVP|ssl)'
```

Expected output (relevant excerpts):

```
EVP_EncryptInit_ex  
EVP_EncryptUpdate  
EVP_EncryptFinal_ex  
EVP_CIPHER_CTX_new  
EVP_CIPHER_CTX_free  
```

These function names appear because they are part of the dynamic symbol table (`.dynsym`) — they are not removed by `strip`, because the loader needs them at runtime to resolve OpenSSL calls. This is critical information: the binary uses the OpenSSL EVP API for **encryption** (not decryption — we don't see `EVP_DecryptInit_ex`). The `Encrypt` prefix in all three functions confirms the direction of the operation.

### 3c — Searching for the key and messages

```bash
$ strings ransomware_O2_strip | grep -iE '(reverse|engineer|password|secret|key)'
```

Expected output:

```
REVERSE_ENGINEERING_IS_FUN_2025!
```

A 32-character string (32 bytes) composed of printable ASCII characters. Its length corresponds exactly to an AES-256 key. It is stored in the `.rodata` section, in plaintext, without any obfuscation. At this point, we have a **serious candidate** for the encryption key.

### 3d — Ransom note content

```bash
$ strings ransomware_O2_strip | grep -A 15 "ENCRYPTED"
```

Expected output:

```
========================================
  YOUR FILES HAVE BEEN ENCRYPTED!
========================================
This is a pedagogical exercise.  
Reverse Engineering Training  
Algorithm: AES-256-CBC  
The key is in the binary. Find it.  
Hint: look for the 32-byte constants...  
========================================
```

The note explicitly confirms the algorithm used: **AES-256-CBC**. In a real case, the note would obviously not be this verbose, but it is not uncommon for ransomware to mention the algorithm used to convince the victim that the encryption is strong and that paying is the only option.

### 3e — Searching for the magic header

```bash
$ strings ransomware_O2_strip | grep -i "RWARE"
```

Expected output:

```
RWARE27
```

This 7-character string is likely a **magic header** written at the beginning of encrypted files. It is a format identification marker — useful for a YARA rule and for the ImHex parser.

### `strings` summary

In just a few `grep` commands, we extracted:

| Element | Value | Meaning |  
|---|---|---|  
| Target directory | `/tmp/test` | Attack scope |  
| Extension | `.locked` | Post-encryption renaming |  
| Ransom note | `README_LOCKED.txt` | Note dropped for the victim |  
| Crypto API | `EVP_Encrypt*` | Encryption via OpenSSL EVP |  
| Algorithm | `AES-256-CBC` | Mentioned in the note |  
| Key candidate | `REVERSE_ENGINEERING_IS_FUN_2025!` | 32 bytes, AES-256 candidate |  
| Magic header | `RWARE27` | Encrypted file signature |

---

## Step 4 — `readelf`: section anatomy and dynamic symbols

To complete the triage, let's examine the ELF structure more closely.

### Headers and sections

```bash
$ readelf -h ransomware_O2_strip
```

The relevant fields to note are the type (`DYN` for a PIE executable), the entry point (which won't directly correspond to `main` — see the role of `_start` and `__libc_start_main`), and the machine (`Advanced Micro Devices X86-64`).

```bash
$ readelf -S ransomware_O2_strip | grep -E '(\.text|\.rodata|\.data|\.bss|\.plt|\.got)'
```

Typical output (numbers and addresses simplified):

```
  [14] .text         PROGBITS   ...  AX  ...
  [16] .rodata       PROGBITS   ...  A   ...
  [23] .got          PROGBITS   ...  WA  ...
  [24] .got.plt      PROGBITS   ...  WA  ...
  [25] .data         PROGBITS   ...  WA  ...
  [26] .bss          NOBITS     ...  WA  ...
```

The `.rodata` section (read-only data) is the one containing our strings and constants — this is where the AES key and IV reside in memory. The `.text` section contains the executable code. The `.got` and `.got.plt` sections are involved in dynamic resolution of OpenSSL calls (PLT/GOT mechanism covered in [Chapter 2, section 2.9](/02-gnu-compilation-chain/09-plt-got-lazy-binding.md)).

### Dynamic symbols

```bash
$ readelf -s --dyn-syms ransomware_O2_strip | grep -i "FUNC"
```

This command lists functions imported from shared libraries. You will find the OpenSSL calls (`EVP_*`), standard libc functions (`fopen`, `fread`, `fwrite`, `fclose`, `malloc`, `free`, `opendir`, `readdir`, `stat`, `unlink`, `printf`, `fprintf`...), and potentially clues about the program flow.

The joint presence of `opendir`/`readdir` (directory traversal), `stat` (file type checking), `fopen`/`fread`/`fwrite` (read/write), `unlink` (deletion), and `EVP_Encrypt*` (encryption) paints a coherent scenario: the program **traverses a directory tree, reads files, encrypts them, writes the result, and deletes the originals**.

---

## Step 5 — `checksec`: protection inventory

The `checksec` tool (provided by `pwntools` or installable separately) analyzes the security protections compiled into the binary:

```bash
$ checksec --file=ransomware_O2_strip
```

Typical output:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Let's interpret each line in the context of our analysis:

| Protection | Value | Impact on RE |  
|---|---|---|  
| **RELRO** | Partial | The GOT is partially protected. PLT/GOT entries remain modifiable after the first call (lazy binding). A hook via GOT overwrite would be theoretically possible. |  
| **Stack Canary** | Present | GCC inserted stack canaries (`-fstack-protector`). Presence of `__stack_chk_fail` in dynamic symbols. No direct impact on our analysis, but indicates compilation with default security flags. |  
| **NX** | Enabled | The stack is not executable. No impact on pure RE, but relevant if exploitation were considered. |  
| **PIE** | Enabled | Confirms what `file` indicated: addresses are relative. In GDB, you'll need to wait for the binary to be loaded in memory to know absolute addresses, or work with offsets. |

`checksec` doesn't directly reveal the program's behavior, but it completes the binary's profile. The absence of specific anti-debug protections (no `ptrace` detected, no control flow obfuscation) suggests the binary is not actively trying to prevent analysis — which is consistent with our sample's design.

---

## Step 6 — Quick hex view: spotting the IV

Before moving to in-depth analysis, a quick look at the `.rodata` section in hexadecimal can reveal non-ASCII constants that `strings` doesn't capture:

```bash
$ objdump -s -j .rodata ransomware_O2_strip | head -50
```

Scanning the output, we look for recognizable sequences. Near the ASCII key `REVERSE_ENGINEERING_IS_FUN_2025!`, you should spot a 16-byte sequence:

```
dead beef cafe babe 1337 4242 feed face
```

These values — `0xDEADBEEF`, `0xCAFEBABE`, `0x1337`, `0xFEEDFACE` — are classic magic numbers from the systems world. Their grouping into a 16-byte block (128 bits), located in immediate proximity to a 32-byte key in `.rodata`, makes them a **highly probable candidate for an AES IV**. In CBC mode, the initialization vector is exactly one block, which is 16 bytes for AES — the size matches.

> 💡 **Tip**: the `objdump -s -j .rodata` command is a good compromise between `strings` (which only shows ASCII) and a full hex editor (which requires opening the tool). For deeper exploration, ImHex takes over (section 27.3).

---

## Summary: hypothesis table

At the end of this 5-to-10-minute triage, without having opened a disassembler or executed the binary, here is the full set of formulated hypotheses:

| # | Hypothesis | Confidence | Source |  
|---|---|---|---|  
| H1 | The binary is ransomware targeting `/tmp/test/` | High | `strings`: target directory, `.locked` extension, ransom note |  
| H2 | The algorithm used is AES-256-CBC | High | `strings`: explicit note + presence of `EVP_Encrypt*` in `.dynsym` |  
| H3 | The AES-256 key is `REVERSE_ENGINEERING_IS_FUN_2025!` | Medium | `strings`: 32-byte string in `.rodata`, to be confirmed dynamically |  
| H4 | The IV is `DEADBEEF CAFEBABE 1337 4242 FEEDFACE` | Medium | `objdump -s .rodata`: 16 bytes near the key, to be confirmed |  
| H5 | Encrypted files carry an `RWARE27` header | Medium | `strings`: string present, exact format to be mapped with ImHex |  
| H6 | The binary recursively traverses files and deletes originals | High | `readelf --dyn-syms`: `opendir`, `readdir`, `stat`, `unlink` |  
| H7 | No network communication | Medium | Absence of `connect`, `send`, `recv`, `socket` in `.dynsym`, to be confirmed with `strace` |  
| H8 | No anti-debug mechanism | Low | Normal `checksec`, but absence of evidence is not evidence of absence |

Hypotheses marked "Medium" or "Low" will need to be confirmed or disproved during in-depth static analysis (section 27.3) and dynamic analysis (section 27.5). "High" confidence hypotheses rest on multiple converging indicators.

---

## Methodological habit: document as you go

A professional analyst doesn't keep these observations in their head: they record them immediately. Get into the habit of maintaining a structured notes file from the triage stage. Even a simple text file suffices:

```
# Triage — ransomware_O2_strip
Date: 2025-xx-xx  
Analyst: [your name]  

## Identity
- ELF 64-bit, x86-64, PIE, dynamically linked, stripped
- Dependencies: libssl, libcrypto, libc

## IOC (Indicators of Compromise)
- File: ransomware_O2_strip (SHA256: ...)
- Target directory: /tmp/test
- Appended extension: .locked
- Ransom note: README_LOCKED.txt
- Encrypted file magic header: RWARE27

## Crypto hypotheses
- Probable algorithm: AES-256-CBC (via OpenSSL EVP)
- Key candidate: REVERSE_ENGINEERING_IS_FUN_2025! (32 bytes)
- IV candidate: DEADBEEF CAFEBABE 1337 4242 FEEDFACE (16 bytes)

## To confirm
- [ ] Key and IV actually used (GDB/Frida on EVP_EncryptInit_ex)
- [ ] Exact format of .locked files (ImHex)
- [ ] Absence of network communication (strace)
- [ ] Absence of anti-debug (dynamic analysis)
```

This document will evolve throughout the analysis and serve as the basis for the final report (section 27.7). Computing the SHA-256 hash of the binary at triage (`sha256sum ransomware_O2_strip`) is also an essential reflex: it is the sample's unique identifier, usable for VirusTotal lookups, analyst exchanges, and report traceability.

---

## What triage doesn't tell us

It is equally important to note what the quick triage **cannot** determine:

- **Is the key really the one found by `strings`?** — It could be a decoy, an unused test key, or an unrelated string. Only dynamic analysis (breakpoint on `EVP_EncryptInit_ex`) will confirm which buffer is actually passed as an argument.  
- **The exact format of `.locked` files** — We know an `RWARE27` header exists, but its size, the fields that follow, and the layout of the encrypted data remain to be mapped.  
- **The precise operating mode** — The order of operations (read, encrypt, write, delete), error handling, treatment of empty or very large files are not visible from triage.  
- **The existence of hidden features** — A binary may contain dead code, rarely-reached conditional branches, or features activated by command-line arguments. Triage only explores static data, not the control flow.

It is precisely to answer these questions that the next steps — in-depth static analysis in Ghidra and ImHex — are necessary.

⏭️ [Static analysis: Ghidra + ImHex (spotting AES constants, encryption flow)](/27-ransomware/03-static-analysis-ghidra-imhex.md)
