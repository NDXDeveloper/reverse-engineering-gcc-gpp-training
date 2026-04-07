🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.10 — Applying YARA rules from ImHex (bridge to malware analysis)

> 🎯 **Goal of this section**: Understand what YARA rules are, why they are a fundamental binary-analysis tool, and how to apply them directly from ImHex to detect known patterns — cryptographic constants, packer signatures, suspicious-behavior indicators — without leaving the hex editor.

> 📁 **Files used**: `yara-rules/crypto_constants.yar`, `yara-rules/packer_signatures.yar`  
> 📦 **Test binary**: `binaries/ch24-crypto/crypto_O0` or `binaries/ch29-packed/packed_sample`

---

## YARA in a few words

YARA is a tool created by Victor Alvarez (VirusTotal) that lets you describe **binary and textual patterns** as rules, then scan files to detect the presence of these patterns. The name is sometimes interpreted as "Yet Another Recursive Acronym", but YARA is mainly known for its practical use: it is the de facto signature language of the malware-analysis industry.

A YARA rule is conceptually simple: it describes "what" a file type, malware, packer, or algorithm "looks like" by combining byte sequences, character strings, and logical conditions. If the scanned file matches the description, the rule "matches".

Here is a minimal example:

```yara
rule detect_elf {
    meta:
        description = "Detects an ELF file"
        author      = "RE Training"

    strings:
        $magic = { 7F 45 4C 46 }

    condition:
        $magic at 0
}
```

This rule declares a hex pattern `$magic` (the ELF magic number) and a condition: the pattern must be at offset 0 of the file. Any ELF file triggers this rule.

---

## Why YARA in a hex editor?

YARA is usually used on the command line (`yara rules.yar file`) or in automated analysis platforms (VirusTotal, CAPE Sandbox, Cuckoo). Integration into ImHex brings a specific advantage: the **visual localization** of matches.

When you run `yara` on the CLI, it tells you "rule X matches file Y" — a binary yes/no answer, possibly accompanied by the match offset. When you run YARA from ImHex, the bytes that triggered the match are **highlighted directly in the hex view**. You see exactly where the detected sequence is, in what context it appears (which section, which surrounding bytes), and you can immediately inspect the zone with the Data Inspector, the built-in disassembler, or a `.hexpat` pattern.

This "detection + localization + inspection" combination in one tool is what makes the YARA integration in ImHex valuable. It turns a scan that would otherwise be abstract into an act of visual exploration.

---

## Anatomy of a YARA rule

Before using YARA in ImHex, let's take the time to understand the structure of a rule. We don't need to become YARA experts at this stage — Chapter 35 will revisit it in depth for writing advanced rules — but you must know how to read and adapt an existing rule.

### The `meta` section

The `meta` section contains descriptive metadata that does not affect matching. It's documentation integrated into the rule:

```yara
meta:
    description = "Detects the AES S-box in a binary"
    author      = "RE Training"
    date        = "2025-03-15"
    reference   = "FIPS 197, S-box Table"
```

The `description`, `author`, and `date` fields are conventional. The `reference` field points to the signature's source — essential so that anyone reading the rule understands why these bytes are significant.

### The `strings` section

The `strings` section declares the patterns to search. YARA supports three types of patterns.

**Hex strings** — raw byte sequences, exactly like in ImHex's hex search:

```yara
strings:
    $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
```

Wildcards are supported with `??` for any byte, and alternatives with `(XX | YY)`:

```yara
strings:
    $call_pattern = { E8 ?? ?? ?? ?? }           // call rel32
    $jmp_or_call  = { (E8 | E9) ?? ?? ?? ?? }    // call or jmp rel32
```

**Text strings** — ASCII strings with optional modifiers:

```yara
strings:
    $str_passwd  = "password" nocase    // case-insensitive
    $str_wide    = "config" wide        // UTF-16 little-endian
    $str_both    = "secret" ascii wide  // searches both encodings
```

The `nocase` modifier is particularly useful for strings that may appear in varying case. The `wide` modifier handles UTF-16 strings we mentioned in section 6.8.

**Regular expressions** — delimited by slashes:

```yara
strings:
    $base64_block = /[A-Za-z0-9+\/]{20,}={0,2}/
```

### The `condition` section

The `condition` section is a boolean expression that determines when the rule matches. It can combine the declared patterns with logical operators and functions:

```yara
condition:
    $aes_sbox                         // the pattern exists somewhere in the file
```

```yara
condition:
    $aes_sbox and $str_passwd         // both patterns are present
```

```yara
condition:
    any of ($str_*)                   // at least one of the $str_... patterns is present
```

```yara
condition:
    #call_pattern > 50                // more than 50 occurrences of call rel32
```

```yara
condition:
    $magic at 0 and filesize < 1MB    // magic at offset 0, file < 1 MB
```

The richness of the condition language lets you write very precise rules that minimize false positives. A rule that looks for the AES S-box **and** a string `"AES"` or `"encrypt"` is more reliable than a rule that looks only for the S-box (which could appear in a compressor or in random data).

---

## Using YARA in ImHex

### Accessing the YARA view

Open the YARA view via **View → YARA**. The panel divides in two zones: a rule-file selection zone (`.yar` or `.yara`) and a results-display zone.

### Loading a rule file

Click the load button and navigate to your rule file. You can load the files provided with the training:

- `yara-rules/crypto_constants.yar` — detects common cryptographic constants (AES, SHA-256, MD5, ChaCha20, etc.)  
- `yara-rules/packer_signatures.yar` — detects signatures of known packers (UPX, ASPack, etc.)

You can also load public YARA rules from reputable community repositories.

### Launching the scan

Once the rules are loaded, click the scan button (often **Match** or a ▶ icon). ImHex scans the open file against every rule in the loaded file and displays the results in the panel: the name of each matching rule, along with the offsets of the detected patterns.

### Locating matches

Click a result in the list. ImHex **jumps to the matching offset** in the hex view and highlights the bytes that triggered the match. You can then:

- Inspect the zone with the **Data Inspector** to interpret the values.  
- Check in the **built-in disassembler** whether the bytes are in code or in data.  
- Create a **bookmark** (section 6.6) to document the finding and keep it in your project.  
- Load a **`.hexpat` pattern** to parse the structure around the match.

This "scan → locate → inspect → document" workflow is the complete value chain of YARA integration in ImHex.

---

## YARA rules useful for RE of GCC binaries

Here is a selection of rules adapted to the context of this training. They target patterns frequently encountered in GCC-compiled ELF binaries.

### Detection of cryptographic constants

```yara
rule crypto_aes_sbox {
    meta:
        description = "Detects the AES S-box (first line, 16 bytes)"
        reference   = "FIPS 197"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox
}

rule crypto_sha256_init {
    meta:
        description = "Detects SHA-256 initial values (H0-H3, little-endian)"
        reference   = "FIPS 180-4"
    strings:
        $h_init = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }
    condition:
        $h_init
}

rule crypto_chacha20_constant {
    meta:
        description = "Detects the ChaCha20 constant 'expand 32-byte k'"
    strings:
        $const = "expand 32-byte k"
    condition:
        $const
}
```

These rules correspond to the constants we listed in section 6.8. Their advantage over a manual hex search is that they can all be run **at the same time** in a single scan. Rather than searching sequentially for each constant, you load a rule file and ImHex tells you in one pass which algorithms are present.

### UPX packer detection

```yara
rule packer_upx {
    meta:
        description = "Detects the UPX signature in an ELF binary"
    strings:
        $upx_magic  = "UPX!"
        $upx_header = { 55 50 58 21 }
        $upx_info   = "This file is packed with the UPX"
    condition:
        any of them
}
```

UPX leaves identifiable markers in the binaries it compresses. If this rule matches, you know the binary is packed with UPX and that you can decompress it with `upx -d` before analyzing it (Chapters 19 and 29).

### Anti-debug technique detection

```yara
rule anti_debug_ptrace {
    meta:
        description = "Detects a potential call to ptrace (anti-debug)"
    strings:
        $ptrace_str = "ptrace" nocase
        $syscall    = { 0F 05 }
    condition:
        $ptrace_str and #syscall > 0
}
```

This rule combines a text string (`"ptrace"`) and the presence of at least one `syscall`. The conjunction of both is an indicator (not proof) that the binary uses `ptrace(PTRACE_TRACEME)` to detect a debugger — anti-reversing technique we will study in Chapter 19.

### Network-behavior indicators

```yara
rule network_indicators {
    meta:
        description = "Detects strings related to network communications"
    strings:
        $connect     = "connect" nocase
        $socket      = "socket" nocase
        $http_get    = "GET / HTTP" nocase
        $http_post   = "POST " nocase
        $user_agent  = "User-Agent:" nocase
    condition:
        3 of them
}
```

If three of these five strings are present, the binary probably does network communications — potentially an embedded HTTP client or a C2 communication module (Chapters 23 and 28).

---

## Writing your own rules: best practices

Over the course of your analyses, you will accumulate specific findings — an opcode sequence characteristic of a compiler, a magic number of a proprietary file format, a recurring obfuscation pattern. Capturing these findings as YARA rules is an investment that pays off every future analysis.

### Start with precise hex patterns

The most reliable rules rely on byte sequences long and specific enough to avoid false positives. A rule that searches `{ FF FF }` will match in almost all files. A rule that searches the first 16 bytes of the AES S-box will only match in binaries that embed AES.

The recommended minimum length for a hex pattern is **8 bytes** for a standalone pattern, or **4 bytes** if the condition combines multiple patterns. Below that, the risk of false positives is too high.

### Combine multiple indicators in the condition

A rule with a single pattern is fragile. Combining multiple indicators in the condition strengthens specificity:

```yara
rule custom_file_format_v2 {
    strings:
        $magic   = { 43 55 53 54 }     // "CUST"
        $version = { 02 00 }           // version 2
        $table   = "ENTRY_TABLE"
    condition:
        $magic at 0 and $version at 4 and $table
}
```

This rule only matches files starting with `CUST`, having version 2 at offset 4, **and** containing the string `ENTRY_TABLE` somewhere. Three combined conditions eliminate almost all false-positive risk.

### Systematically document with `meta`

Every rule must carry a `description` that explains what it detects, an `author`, and ideally a `reference` to the documentation or analysis that motivated its creation. Six months after writing the rule, these metadata will be your only memory of why these bytes are significant.

### Organize rules by theme

The training's `yara-rules/` folder illustrates organization by theme: one file for cryptographic constants, another for packer signatures. You can extend this structure with your own files:

```
yara-rules/
├── crypto_constants.yar      # AES, SHA, MD5, ChaCha20...
├── packer_signatures.yar     # UPX, ASPack, custom packers
├── anti_debug.yar            # ptrace, timing checks, /proc/self
├── network_indicators.yar    # sockets, HTTP, DNS, C2 patterns
└── custom_formats.yar        # proprietary formats encountered
```

Each file can be loaded independently in ImHex depending on the analysis context.

---

## YARA in ImHex vs YARA in CLI: complementarity

The YARA integration in ImHex does not replace the command-line tool. Both have complementary uses.

| Criterion | YARA in ImHex | YARA in CLI |  
|---|---|---|  
| Single-file scan with visual inspection | ✅ Optimal — localization and immediate context | Text result, no visualization |  
| Scanning a directory of files (batch) | ❌ One file at a time | ✅ `yara -r rules.yar folder/` |  
| Integration into an automated pipeline | ❌ GUI | ✅ Scriptable, integrable into CI/CD |  
| Rule development and testing | ✅ Immediate visual feedback on matches | Functional but less intuitive |  
| Scanning malware samples in a sandbox | Possible | ✅ More common (no GUI in sandbox) |

In practice, you will use ImHex to **develop and test** your rules (immediate visual feedback accelerates iteration) and the CLI to **deploy** those rules on file collections or in automated pipelines (Chapter 35).

---

## Bridge to Part VI: malware analysis

This section is deliberately positioned as a **bridge** to Part VI of the training (Malicious Code Analysis). The YARA rules we presented here — crypto constants, packer signatures, network indicators, anti-debug techniques — are exactly the tools malware analysts use for triaging suspect samples.

In Chapter 27 (ransomware), we will use the `crypto_constants.yar` rules to identify encryption algorithms embedded in the sample. In Chapter 28 (dropper), the `network_indicators.yar` rules will help us spot strings related to the C2 protocol. In Chapter 29 (unpacking), `packer_signatures.yar` will detect the packer used and steer us towards the right decompression strategy.

All these uses will start from the same workflow: load the rules in ImHex, run the scan, locate the matches, inspect and document. The skill you build in this section is directly transferable.

---

## Summary

YARA is a binary and textual signature language that lets you detect known patterns in a file. Its integration into ImHex adds a visual dimension to scanning: matches are localized and highlighted in the hex view, which allows immediate inspection in the context of surrounding data. Rules are organized in three sections — `meta` (documentation), `strings` (hex, text, or regex patterns), and `condition` (matching logic) — and can be combined for precise detection. In the context of this training, YARA rules serve to detect cryptographic constants, packer signatures, anti-debug techniques, and network indicators. This skill will be directly mobilized in the practical cases of Part V and the malware analysis of Part VI.

---


⏭️ [Practical case: mapping a custom file format with `.hexpat`](/06-imhex/11-practical-custom-format.md)
