🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 27.4 — Identifying Corresponding YARA Rules from ImHex

> 🎯 **Goal of this section**: transform the observations accumulated during triage (27.2) and static analysis (27.3) into **YARA rules** — formal signatures capable of automatically detecting this sample (or similar variants) in a file corpus. We will use ImHex as a visual aid to identify the most discriminating binary patterns.  
>  
> This section bridges malware analysis and operational detection. The YARA rules produced here are the kind an analyst would share in an incident report to enable defenders to scan their systems.

---

## YARA in 30 seconds

YARA is a pattern matching tool for binary files. A YARA rule consists of three blocks:

- **`meta`** — Descriptive metadata (author, date, description). No impact on detection, but essential for traceability.  
- **`strings`** — The patterns to search for: ASCII/Unicode strings, hexadecimal sequences, regular expressions.  
- **`condition`** — The boolean logic that combines patterns to trigger (or not) the detection.

A well-written rule is **specific enough** to avoid false positives (detecting a legitimate binary using OpenSSL) while being **general enough** to withstand minor variations (recompilation with different flags, slight source code modification).

---

## Strategy: which patterns are discriminating?

Not all elements identified in previous sections are equal as detection signatures. The following table classifies our observations by **discriminating power**:

| Element | Specificity | Stability across variations | YARA relevance |  
|---|---|---|---|  
| AES key `REVERSE_ENGINEERING...` | Very high — unique to this sample | Low — first element an author would change | Good for this exact variant |  
| IV `DEADBEEF CAFEBABE...` | High — specific combination | Low — easily modifiable | Good for this exact variant |  
| Magic header `RWARE27` | High — format identifier | Medium — author could change it, but it's structural | Excellent for produced files |  
| Ransom note strings | Medium — specific text | Low — easily rewritten | Complementary |  
| EVP call pattern (Init+Update+Final) | Low alone — any OpenSSL program uses it | High — imposed by the API | Useful only combined with other criteria |  
| Combination of path `/tmp/test` + `.locked` + `unlink` | High in combination | Medium | Good behavioral signature |

The optimal strategy is to write **multiple rules** of different granularity: a precise rule that targets exactly this variant, a more generic rule that would survive minor modifications, and a rule targeting the produced files (the `.locked` files).

---

## Identifying patterns in ImHex

Before writing the rules, let's return to ImHex to extract the exact hexadecimal sequences that will serve as signatures. The advantage of ImHex over a simple `hexdump` is the ability to **visually select** bytes, copy them in YARA notation, and verify their uniqueness within the file.

### The AES key in the ELF binary

Navigate to the `AES-256 Key` bookmark created in section 27.3. Select the 32 bytes and copy them in hexadecimal (*Edit → Copy As → Hex String*):

```
52 45 56 45 52 53 45 5F 45 4E 47 49 4E 45 45 52
49 4E 47 5F 49 53 5F 46 55 4E 5F 32 30 32 35 21
```

This sequence is our most specific signature for the binary. It identifies not only the sample but precisely the key used — critical information in an incident response context, as it means files encrypted by this variant are decryptable.

### The IV in the ELF binary

Navigate to the `AES IV` bookmark. The 16 bytes:

```
DE AD BE EF CA FE BA BE 13 37 42 42 FE ED FA CE
```

Individually, sub-sequences like `DEADBEEF` or `CAFEBABE` are too common to serve as signatures (they appear in many programs and formats). But the 16 bytes taken together form a sufficiently unique combination.

### The magic header in a `.locked` file

Open a `.locked` file in ImHex and select the first 8 bytes:

```
52 57 41 52 45 32 37 00
```

This is the `RWARE27\0` magic. This signature is ideal for scanning a filesystem looking for files already encrypted by the sample — a frequent need during the impact assessment phase of an incident.

### Key/IV proximity in `.rodata`

A subtle but important point: in our binary, the key and IV are **consecutive in memory** (or separated by an alignment padding of a few bytes at most). This proximity is characteristic of two `static const` variables declared one after the other in the source code. In YARA, we can exploit this adjacency with the distance operator `(key_offset, iv_offset)` or more simply by searching for the key followed by the IV within a narrow window.

In ImHex, measure the distance between the last byte of the key and the first byte of the IV. If the distance is 0 (consecutive), we can combine them into a single 48-byte hex string. If an alignment gap exists (typically 0 to 16 bytes of padding), we will use a YARA wildcard.

---

## Rule 1 — Exact sample detection (`ransomware_ch27_exact`)

This first rule precisely targets our sample. It combines the AES key, IV, and specific behavioral strings. A false positive is virtually impossible.

```yara
rule ransomware_ch27_exact
{
    meta:
        description = "Detects the pedagogical ransomware sample from Chapter 27"
        author      = "RE Training"
        date        = "2025-01-01"
        hash        = "<insert SHA-256 of ransomware_O2_strip>"
        reference   = "Reverse Engineering Training — Chapter 27"
        tlp         = "WHITE"

    strings:
        // Hardcoded AES-256 key (32 bytes)
        $aes_key = {
            52 45 56 45 52 53 45 5F
            45 4E 47 49 4E 45 45 52
            49 4E 47 5F 49 53 5F 46
            55 4E 5F 32 30 32 35 21
        }

        // AES IV (16 bytes)
        $aes_iv = {
            DE AD BE EF CA FE BA BE
            13 37 42 42 FE ED FA CE
        }

        // Behavioral strings
        $target_dir   = "/tmp/test"            ascii
        $locked_ext   = ".locked"              ascii
        $ransom_note  = "README_LOCKED.txt"    ascii
        $magic_header = "RWARE27"              ascii

        // Ransom note fragment
        $note_text = "YOUR FILES HAVE BEEN ENCRYPTED" ascii

    condition:
        uint32(0) == 0x464C457F     // ELF magic ("\x7FELF")
        and $aes_key
        and $aes_iv
        and 3 of ($target_dir, $locked_ext, $ransom_note, $magic_header, $note_text)
}
```

Let's break down the design choices:

**`uint32(0) == 0x464C457F`** — This condition checks that the first 4 bytes of the file match the ELF magic number (`\x7FELF` in little-endian). It's a file type filter that prevents matching on a text file that happens to contain the string `REVERSE_ENGINEERING_IS_FUN_2025!`.

**`$aes_key` and `$aes_iv`** — Both crypto constants are required simultaneously. Finding one without the other in an ELF binary would be an extraordinary coincidence, but requiring both eliminates any doubt.

**`3 of (...)`** — Among the 5 behavioral strings, at least 3 must be present. This flexibility absorbs small variations: if an attacker modifies the ransom note text but keeps the target directory and extension, the rule still matches.

### Testing the rule

```bash
# Scan the sample
$ yara ransomware_ch27.yar ransomware_O2_strip
ransomware_ch27_exact ransomware_O2_strip

# Scan a legitimate binary to verify no false positive
$ yara ransomware_ch27.yar /usr/bin/openssl
# (no output → no false positive)
```

---

## Rule 2 — Generic behavioral detection (`ransomware_ch27_generic`)

The exact rule is fragile: if the attacker changes the key, IV, or note text, it no longer matches. A second, more generic rule captures the **behavioral pattern** — structural characteristics that would survive a recompilation with different constants.

```yara
rule ransomware_ch27_generic
{
    meta:
        description = "Detects Ch27 ransomware variants by behavioral pattern"
        author      = "RE Training"
        date        = "2025-01-01"
        reference   = "Reverse Engineering Training — Chapter 27"

    strings:
        // OpenSSL EVP API — encryption (not decryption)
        $evp_init   = "EVP_EncryptInit_ex"   ascii
        $evp_update = "EVP_EncryptUpdate"    ascii
        $evp_final  = "EVP_EncryptFinal_ex"  ascii
        $evp_aes    = "EVP_aes_256_cbc"      ascii

        // Filesystem traversal functions
        $fs_opendir = "opendir"   ascii
        $fs_readdir = "readdir"   ascii
        $fs_unlink  = "unlink"    ascii
        $fs_stat    = "stat"      ascii

        // Encrypted file extension
        $locked_ext = ".locked" ascii

        // Output format magic header
        $magic = "RWARE27" ascii

    condition:
        uint32(0) == 0x464C457F                      // ELF file
        and filesize < 500KB                          // compact sample
        and 3 of ($evp_init, $evp_update, $evp_final, $evp_aes)  // crypto API
        and 3 of ($fs_opendir, $fs_readdir, $fs_unlink, $fs_stat) // FS traversal
        and ($locked_ext or $magic)                   // ransomware marker
}
```

This rule contains **no sample-specific constants** (no key, no IV, no ransom note text). It relies on the convergence of three indicator families:

1. **Use of the OpenSSL EVP API in encryption mode** — The presence of `EVP_Encrypt*` in the `.dynsym` table is verifiable even on a stripped binary.  
2. **Recursive filesystem traversal with deletion** — The combination of `opendir` + `readdir` + `stat` + `unlink` in the same binary describes a program that enumerates files and deletes them.  
3. **Output marker** — The `.locked` extension or `RWARE27` magic identifies the ransomware purpose.

The `filesize < 500KB` condition is a pragmatic safeguard: our sample is small (a few tens of KB). This excludes large legitimate binaries that could accidentally combine OpenSSL and file manipulation functions (a backup tool, for example). This limit would need adjustment if the sample grows (e.g., adding statically linked libraries).

> ⚠️ **False positive risk**: this generic rule is more aggressive. A legitimate file encryption tool using OpenSSL, traversing directories, and deleting originals after encryption (an encrypted backup tool, for example) could theoretically match. The `.locked` or `RWARE27` marker is what reduces this risk. In a production environment, this rule would be classified as a *hunting rule* rather than a firm *detection rule* — it flags a file that **warrants investigation**, not necessarily a malicious file.

---

## Rule 3 — Encrypted file detection (`ransomware_ch27_locked_file`)

This third rule does not target the malicious binary, but the **files produced** by it. Its purpose is different: it allows scanning a compromised filesystem to identify all affected files and assess the extent of the damage.

```yara
rule ransomware_ch27_locked_file
{
    meta:
        description = "Identifies files encrypted by the Ch27 ransomware (.locked format)"
        author      = "RE Training"
        date        = "2025-01-01"
        filetype    = "locked"
        reference   = "Reverse Engineering Training — Chapter 27"

    strings:
        $magic = { 52 57 41 52 45 32 37 00 }  // "RWARE27\0"

    condition:
        $magic at 0                             // magic at the very beginning of the file
        and filesize > 16                       // at minimum header (16) + 1 encrypted block
        and filesize < 100MB                    // reasonable upper bound
}
```

The `$magic at 0` condition requires that the `RWARE27\0` signature be exactly at the beginning of the file (offset 0), not just anywhere inside. This is a strong criterion: it eliminates false positives where the string `RWARE27` would appear by chance in the middle of a text file or binary.

The `filesize > 16` condition excludes files too small to contain a complete header (16 bytes) plus at least one block of encrypted data. The `filesize < 100MB` upper bound is a performance safeguard: scanning multi-gigabyte files for an 8-byte magic is costly, and the sample reads files entirely into memory, which de facto limits the size of files it can encrypt.

### Usage in incident response

```bash
# Recursively scan a filesystem for encrypted files
$ yara -r ransomware_ch27.yar /tmp/test/
ransomware_ch27_locked_file /tmp/test/document.txt.locked  
ransomware_ch27_locked_file /tmp/test/notes.md.locked  
ransomware_ch27_locked_file /tmp/test/budget.csv.locked  
ransomware_ch27_locked_file /tmp/test/subfolder/nested.txt.locked  
...

# Count the number of affected files
$ yara -r ransomware_ch27.yar /tmp/test/ | wc -l
```

This type of scan is a standard step in the impact assessment phase of a ransomware incident. The result directly feeds into the report (section 27.7).

---

## Assembling the rules into a single file

In practice, all three rules are grouped into a single `.yar` file:

```yara
/*
 * Reverse Engineering Training — Chapter 27
 * YARA rules for the pedagogical ransomware sample
 *
 * File: yara-rules/ransomware_ch27.yar
 *
 * Rule 1: ransomware_ch27_exact        → exact sample detection
 * Rule 2: ransomware_ch27_generic      → variant detection by behavior
 * Rule 3: ransomware_ch27_locked_file  → detection of produced encrypted files
 */

import "elf"

rule ransomware_ch27_exact { ... }  
rule ransomware_ch27_generic { ... }  
rule ransomware_ch27_locked_file { ... }  
```

> 💡 The `elf` import is optional but allows access to ELF metadata in conditions (e.g., `elf.type == elf.ET_DYN` to target only PIE executables). We don't use it in our rules to remain compatible with minimal YARA, but it is common in production rules.

---

## The bridge between ImHex and YARA

An underrated aspect of ImHex is its ability to **execute YARA rules directly** on the open file (*View → YARA*). This creates a particularly efficient iterative workflow:

1. **Observe in ImHex** — Visually spot an interesting pattern (a byte sequence, a constant, a magic).  
2. **Copy in hexadecimal** — Select the bytes and copy them in hex format.  
3. **Write the YARA rule** — Integrate the sequence into a rule with appropriate conditions.  
4. **Test in ImHex** — Load the rule in ImHex's YARA panel and verify it matches the open file.  
5. **Refine** — If the rule is too broad (false positives on other files) or too narrow (doesn't match variants), adjust patterns and conditions.

This observation → formalization → test → refinement cycle is at the heart of creating quality signatures. ImHex serves as a visual test bench before deploying rules on a production YARA scanner.

---

## Considerations on rule robustness

### What breaks a YARA rule

The following modifications to the sample would invalidate certain rules:

| Modification | Rule 1 (exact) | Rule 2 (generic) | Rule 3 (files) |  
|---|---|---|---|  
| AES key change | ❌ Broken | ✅ Survives | ✅ Survives |  
| IV change | ❌ Broken | ✅ Survives | ✅ Survives |  
| Ransom note rewrite | ⚠️ Weakened (3 of 5) | ✅ Survives | ✅ Survives |  
| Extension change (`.encrypted` instead of `.locked`) | ⚠️ Weakened | ⚠️ Weakened | ✅ Survives |  
| Magic header change (`RWARE28`) | ⚠️ Weakened | ⚠️ Weakened | ❌ Broken |  
| Switch to AES-128-CTR instead of AES-256-CBC | ⚠️ Weakened | ⚠️ Weakened | ✅ Survives |  
| Custom AES implementation (without OpenSSL) | ✅ Survives (key in `.rodata`) | ❌ Broken | ✅ Survives |  
| Static linking of OpenSSL | ✅ Survives | ❌ Broken (no longer in `.dynsym`) | ✅ Survives |  
| UPX packing of the binary | ❌ Broken | ❌ Broken | ✅ Survives |

This table illustrates why we write **multiple rules of different granularity**. The exact rule is the most precise but the most fragile. The generic rule survives more variations but risks false positives. The produced-files rule is the most resilient because it targets the output, not the code — but it only detects the sample after it has already caused damage.

### Complementarity with other signatures

YARA rules are just one piece of the detection apparatus. In an operational environment, they would be supplemented by:

- **Hashes** (SHA-256, SHA-1, MD5) — Identify exactly one file, zero tolerance for variations. The hash of `ransomware_O2_strip` (computed at triage, section 27.2) is the simplest and most reliable IOC for this precise variant.  
- **Network signatures** (Snort/Suricata) — Not applicable here (no network communication), but essential for the dropper in [Chapter 28](/28-dropper/README.md).  
- **Behavioral signatures** (Sysmon, auditd) — Detect behavior at runtime: massive creation of `.locked` files, file deletion in `/tmp/test`, invocation of OpenSSL functions. Complementary to static YARA rules.

---

## Deliverables summary

At the end of this section, you have produced three concrete artifacts:

1. **`ransomware_ch27_exact`** — Exact detection rule, immediately usable on a file scanner to identify this precise sample and confirm that the key is recoverable.  
2. **`ransomware_ch27_generic`** — Hunting rule, usable to detect recompiled variants of the same sample with modified constants.  
3. **`ransomware_ch27_locked_file`** — Impact assessment rule, allowing filesystem scanning to inventory encrypted files.

These rules will feed into the IOC section of the analysis report (section 27.7). They are also archived in the repository under `yara-rules/ransomware_ch27.yar` for reference.

⏭️ [Dynamic analysis: GDB + Frida (extracting the key from memory)](/27-ransomware/05-dynamic-analysis-gdb-frida.md)
