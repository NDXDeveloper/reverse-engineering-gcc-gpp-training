🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 35.4 — Writing YARA Rules to Detect Patterns Across a Collection of Binaries

> 🔧 **Tools covered**: `yara` (CLI), `yara-python` (Python library)  
> 📁 **Rule files**: `yara-rules/crypto_constants.yar`, `yara-rules/packer_signatures.yar`  
> 📁 **Example binaries**: all variants from Chapters 21, 24, 25, 27

---

## YARA in the RE workflow

We have encountered YARA twice in this training: in Chapter 6 (section 10), where we applied existing rules from ImHex to identify signatures in a binary, and in Chapter 27 (section 4), where we associated YARA rules with the ransomware sample to characterize its indicators of compromise. In both cases, the rules were provided and applied to an isolated binary.

This section changes perspective. We are no longer consuming rules — we are writing them, and executing them at the scale of a collection. The goal is to transform the knowledge accumulated during manual analyses into reusable detection rules, capable of scanning a directory of binaries and answering questions such as: which ones contain AES constants? Which ones use our CFR format? Which ones exhibit the markers of the ransomware from Chapter 27?

YARA works as a pattern search engine on binary files. You describe what you are looking for (strings, hexadecimal sequences, regular expressions, structural conditions), and YARA scans files reporting those that match. It is the reference tool in malware analysis, but its usefulness is not limited to that — any pattern detection across a corpus of binaries falls within YARA's scope.

---

## Anatomy of a YARA rule

A YARA rule consists of three blocks: metadata (`meta`), strings to search for (`strings`), and the match condition (`condition`).

```
rule RuleName
{
    meta:
        description = "What the rule detects"
        author      = "your name"
        date        = "2025-01-01"

    strings:
        $a = "plain text"
        $b = { DE AD BE EF }
        $c = /regex[0-9]+/

    condition:
        $a or ($b and $c)
}
```

The `meta` block is purely informational — YARA ignores it during scanning. The `strings` define the patterns to search for: text strings (in quotes), hexadecimal sequences (in curly braces), or regular expressions (between slashes). The `condition` is a boolean expression that combines patterns and determines whether the file matches the rule.

### Pattern types

**Text strings** — The simplest form. By default, the search is case-sensitive. The `nocase` modifier makes the search case-insensitive, and `wide` searches for the UTF-16 version (a null byte between each character, common in Windows binaries).

```
strings:
    $banner = "KeyGenMe v1.0"
    $magic  = "CFRM"
    $crypto = "CRYPT24" nocase
```

**Hexadecimal sequences** — Allow searching for arbitrary bytes, including opcodes or numeric constants. Wildcards `??` replace any byte, and alternatives `(AA|BB)` allow matching multiple variants:

```
strings:
    // HASH_SEED = 0x5A3C6E2D in little-endian
    $hash_seed = { 2D 6E 3C 5A }

    // GCC -O0 prologue: push rbp; mov rbp, rsp
    $prologue = { 55 48 89 E5 }

    // call strcmp@plt — the offset varies per binary
    $call_strcmp = { E8 ?? ?? ?? ?? }     // E8 + 4 bytes of relative offset

    // XOR key from ch25: 0x5A 0x3C 0x96 0xF1
    $xor_key = { 5A 3C 96 F1 }
```

**Regular expressions** — For more flexible textual patterns:

```
strings:
    // Strings of the form "version X.Y"
    $version = /version\s+[0-9]+\.[0-9]+/

    // Partial passphrase from ch24 (built in pieces)
    $passphrase_part = /r3vers3_m3/
```

### Common conditions

The condition is the logical core of the rule. Here are the most commonly used constructions in RE.

**Simple presence** — The file contains at least one occurrence of the pattern:

```
condition:
    $magic
```

**Logical combinations** — Require multiple patterns simultaneously:

```
condition:
    $magic and $version and ($data_a or $data_b)
```

**Counting** — Require a minimum number of occurrences or a minimum number of distinct patterns from a set:

```
condition:
    #hash_seed > 0 and #hash_xor > 0    // # = number of occurrences

condition:
    2 of ($crypto_*)    // at least 2 patterns among those prefixed crypto_
```

**Position in the file** — Restrict the search to the first bytes (ideal for header magic bytes):

```
condition:
    $magic at 0    // the magic must be at the very beginning of the file
```

**File size** — Filter by size to avoid false positives:

```
condition:
    filesize < 5MB and $marker
```

**ELF module** — YARA has an `elf` module that exposes structural metadata of the binary without having to search for them manually:

```
import "elf"

rule ELF_x86_64_PIE
{
    condition:
        elf.machine == elf.EM_X86_64 and
        elf.type == elf.ET_DYN    // PIE = ET_DYN
}
```

---

## Rules for our training binaries

### Detecting the keygenme (Chapter 21)

The five variants of `keygenme` share common markers, even in stripped versions. The visible strings via `strings` (banner, error messages) are the first detection vector. The numeric constants from the hashing algorithm constitute a second vector, independent of the presence of symbols.

```
rule KeyGenMe_Ch21
{
    meta:
        description = "Detects keygenme training binary (Chapter 21)"
        chapter     = "21"
        target      = "keygenme_O0 through keygenme_O2_strip"

    strings:
        // Characteristic strings (present even when stripped)
        $banner     = "KeyGenMe v1.0"
        $prompt_key = "XXXX-XXXX-XXXX-XXXX"
        $msg_valid  = "Valid license"
        $msg_fail   = "Invalid license"

        // Algorithm constants (little-endian in .text or .rodata)
        $hash_seed  = { 2D 6E 3C 5A }    // 0x5A3C6E2D
        $hash_xor   = { EF BE AD DE }    // 0xDEADBEEF
        $hash_mul   = { 3F 00 01 00 }    // 0x0001003F — note: imm32

        // Derivation pattern: XOR with 0xA5A5 and 0x5A5A
        $derive_a   = { A5 A5 }
        $derive_b   = { 5A 5A }

    condition:
        // At least 2 strings + at least 2 constants
        (2 of ($banner, $prompt_key, $msg_valid, $msg_fail)) and
        (2 of ($hash_seed, $hash_xor, $hash_mul))
}
```

This rule detects all variants: the strings survive stripping (they are in `.rodata`, not in `.symtab`), and the numeric constants are immediate operands in the machine code, not symbols. The condition requires at least two strings *and* two constants, which considerably reduces the risk of false positives — the probability that an unrelated binary contains both `"KeyGenMe v1.0"` and the sequence `{ 2D 6E 3C 5A }` is negligible.

> 💡 **Note on `$hash_mul`**: the constant `0x1003F` fits in 17 bits, but GCC will encode it as a 32-bit immediate operand in the `imul` instruction. The sequence `{ 3F 00 01 00 }` is its little-endian 4-byte representation. With `-O2`, the compiler may replace the multiplication with a `lea` + `shl` + `add` sequence, in which case the raw constant disappears from the code — the rule continues to work thanks to the other patterns.

### Detecting crypto constants (Chapter 24)

This rule targets binaries that embed well-known cryptographic constants. It is designed to work beyond just the `crypto.c` from Chapter 24 — it will detect any binary containing an AES S-box or SHA-256 constants.

```
rule Crypto_Constants_Embedded
{
    meta:
        description = "Binary contains well-known cryptographic constants"
        chapter     = "24, 27"

    strings:
        // AES S-box (first 16 bytes of the first row)
        $aes_sbox = {
            63 7C 77 7B F2 6B 6F C5
            30 01 67 2B FE D7 AB 76
        }

        // SHA-256: initial values H0..H3 (big-endian, as stored in memory
        // if the lib stores them in BE; also search in LE)
        $sha256_h0_be = { 6A 09 E6 67 }
        $sha256_h1_be = { BB 67 AE 85 }
        $sha256_h0_le = { 67 E6 09 6A }
        $sha256_h1_le = { 85 AE 67 BB }

        // SHA-256 K[0] and K[1] (round constants)
        $sha256_k0 = { 42 8A 2F 98 }
        $sha256_k1 = { 71 37 44 91 }

        // XOR mask from ch24 (first 8 recognizable bytes)
        $ch24_mask = { DE AD BE EF CA FE BA BE }

        // CRYPT24 format magic
        $crypt24_magic = "CRYPT24"

    condition:
        // AES S-box OR at least 2 SHA-256 constants OR ch24 markers
        $aes_sbox or
        (2 of ($sha256_h0_be, $sha256_h1_be, $sha256_h0_le, $sha256_h1_le,
               $sha256_k0, $sha256_k1)) or
        ($ch24_mask and $crypt24_magic)
}
```

Applied to our binaries: `crypto_O0` and its variants will trigger the rule via the SHA-256 constants (statically linked or via libcrypto) and the `$ch24_mask` mask. `crypto_static` will also trigger it via `$aes_sbox`, since the complete AES S-box is embedded in the static binary. Binaries from Chapters 21 and 25 will not match — `0xDEADBEEF` alone is not sufficient since the condition also requires `CRYPT24`.

### Detecting the CFR format (Chapter 25)

For archive files (not binaries), we target the CFR header structure:

```
rule CFR_Archive_Format
{
    meta:
        description = "Custom Format Records archive (Chapter 25)"
        chapter     = "25"

    strings:
        $hdr_magic = "CFRM"
        $ftr_magic = "CRFE"

    condition:
        // Magic at beginning of file, valid version at bytes 4-5
        $hdr_magic at 0 and
        (uint16(4) == 0x0002) and    // version == 2
        filesize > 32                 // at least one complete header
}
```

The `uint16(offset)` function reads a 16-bit little-endian integer at the given offset in the file. This is one of YARA's most powerful mechanisms for validating a format's structure: instead of searching for a byte sequence, you interpret the data as typed fields. Here, we verify that bytes 4-5 correspond to version `0x0002`, which eliminates files that would contain the string `"CFRM"` by coincidence.

### Detecting the pedagogical ransomware (Chapter 27)

The ransomware markers combine AES constants, the passphrase built in pieces, and behavioral strings:

```
rule Ransomware_Ch27_Sample
{
    meta:
        description = "Pedagogical ransomware sample from Chapter 27"
        chapter     = "27"
        severity    = "training_only"

    strings:
        // Passphrase fragments (built dynamically)
        $pp_part1 = "r3vers3_"
        $pp_part2 = "m3_1f_"
        $pp_part3 = "y0u_c4n!"

        // XOR mask applied after SHA-256
        $key_mask = {
            DE AD BE EF CA FE BA BE
            13 37 42 42 FE ED FA CE
        }

        // Output format magic
        $out_magic = "CRYPT24"

        // Behavioral strings
        $encrypt_msg = "Encrypted file written to"
        $derived_key = "Derived key"

    condition:
        elf.machine == elf.EM_X86_64 and
        (2 of ($pp_part1, $pp_part2, $pp_part3)) and
        $key_mask and
        $out_magic
}
```

The passphrase detection is interesting: although `build_passphrase()` in `crypto.c` builds the string character by character to evade `strings`, the intermediate fragments (`"r3vers3_"`, `"m3_1f_"`, `"y0u_c4n!"`) are `const char[]` arrays initialized in the code. The compiler places them in `.rodata` as contiguous byte sequences — and YARA finds them without difficulty. This is an important lesson: string obfuscation through dynamic construction does not withstand static analysis of initialized data. For real protection, the fragments themselves would need to be encrypted.

### Detecting binaries packed with UPX (Chapter 29)

```
import "elf"

rule UPX_Packed_ELF
{
    meta:
        description = "ELF binary packed with UPX"
        chapter     = "29"

    strings:
        $upx_magic  = "UPX!"
        $upx_header = { 55 50 58 21 }    // "UPX!" in hex
        $upx_sect1  = "UPX0"
        $upx_sect2  = "UPX1"

        // UPX header signature (version info)
        $upx_ver    = /UPX\s+[0-9]+\.[0-9]+/

    condition:
        elf.type == elf.ET_EXEC and
        ($upx_magic or $upx_header) and
        ($upx_sect1 or $upx_sect2)
}
```

---

## Running rules from the command line

### Installation

```bash
# Debian / Ubuntu
sudo apt install yara

# Verify
yara --version
```

### Scanning a single file

```bash
yara crypto_constants.yar crypto_O0
```

If the file matches, YARA displays the rule name followed by the path:

```
Crypto_Constants_Embedded crypto_O0
```

### Scanning a directory recursively

```bash
yara -r crypto_constants.yar binaries/
```

The `-r` option traverses subdirectories. On our repository, this command would scan all training binaries and report those containing crypto constants — the `crypto_O0` variants and the ransomware from Chapter 27.

### Combining multiple rule files

```bash
yara -r yara-rules/crypto_constants.yar \
        yara-rules/packer_signatures.yar \
        binaries/
```

Or load all rules from a directory:

```bash
# Compile rules into a binary file for faster scans
yarac yara-rules/*.yar compiled_rules.yarc

# Scan with compiled rules
yara -r compiled_rules.yarc binaries/
```

Pre-compilation with `yarac` significantly speeds up scanning when you have many rules or many files — rule parsing is done only once.

### Useful options

| Option | Effect |  
|---|---|  
| `-r` | Recursive scan of subdirectories |  
| `-s` | Display matched strings and their offset |  
| `-m` | Display rule metadata |  
| `-c` | Count matches instead of displaying them |  
| `-n` | Display files that match no rule |  
| `-t tag` | Only scan rules bearing this tag |  
| `-p N` | Number of scan threads |

The `-s` option is particularly useful during rule development — it shows exactly which patterns matched and at which offset, allowing you to verify that the rule detects what you think:

```bash
yara -s crypto_constants.yar crypto_O0
```

```
Crypto_Constants_Embedded crypto_O0
0x2040:$ch24_mask: DE AD BE EF CA FE BA BE
0x1a3b:$sha256_k0: 42 8A 2F 98
0x3012:$crypt24_magic: CRYPT24
```

---

## Python integration with `yara-python`

To integrate YARA scanning into the automation scripts from previous sections, the `yara-python` library offers a native API:

```bash
pip install yara-python
```

### Compiling and scanning

```python
import yara

# Compile rules from a file
rules = yara.compile(filepath="yara-rules/crypto_constants.yar")

# Scan a binary
matches = rules.match("crypto_O0")  
for match in matches:  
    print(f"Rule   : {match.rule}")
    print(f"Tags   : {match.tags}")
    print(f"Meta   : {match.meta}")
    for s in match.strings:
        for instance in s.instances:
            print(f"  Offset 0x{instance.offset:x} : "
                  f"{s.identifier} = {instance.matched_data.hex()}")
```

### Compiling from a string

For dynamically generated rules — for example, from constants extracted during a previous analysis — you can compile directly from a Python string:

```python
import yara

# Generate a rule on the fly from discovered constants
hash_seed = 0x5A3C6E2D  
hash_xor  = 0xDEADBEEF  

rule_source = f'''  
rule Dynamic_KeygenMe_Detection  
{{
    strings:
        $seed = {{ {hash_seed & 0xFF:02X} {(hash_seed >> 8) & 0xFF:02X} \
{(hash_seed >> 16) & 0xFF:02X} {(hash_seed >> 24) & 0xFF:02X} }}
        $xor  = {{ {hash_xor & 0xFF:02X} {(hash_xor >> 8) & 0xFF:02X} \
{(hash_xor >> 16) & 0xFF:02X} {(hash_xor >> 24) & 0xFF:02X} }}
    condition:
        $seed and $xor
}}
'''

rules = yara.compile(source=rule_source)  
matches = rules.match("keygenme_O2_strip")  
print(f"Matches: {[m.rule for m in matches]}")  
```

This dynamic rule generation pattern is powerful: an analysis script can extract constants from an initial binary (via `pyelftools` or `lief`, as in section 35.1), then automatically generate a YARA rule to scan other binaries for the same constants.

### Scanning a complete directory

```python
import yara  
from pathlib import Path  
import json  

def scan_directory(rules_path, target_dir):
    """Scan all files in a directory and return a report."""
    rules = yara.compile(filepath=rules_path)
    results = []

    for filepath in sorted(Path(target_dir).rglob("*")):
        if not filepath.is_file():
            continue
        try:
            matches = rules.match(str(filepath))
            if matches:
                results.append({
                    "file": str(filepath),
                    "matches": [
                        {
                            "rule": m.rule,
                            "meta": m.meta,
                            "strings_count": sum(
                                len(s.instances) for s in m.strings
                            ),
                        }
                        for m in matches
                    ],
                })
        except yara.Error:
            continue  # Unreadable or oversized file

    return results

report = scan_directory("yara-rules/crypto_constants.yar", "binaries/")  
print(json.dumps(report, indent=2))  
```

---

## Integration into the batch pipeline

The YARA scan fits naturally into the pipeline built in section 35.2. We add a YARA phase between the Ghidra analysis and the consolidation:

```bash
# Additional phase in batch_ghidra.sh

echo "=== YARA Phase: pattern scan ==="  
python3 scripts/yara_scan.py \  
    --rules yara-rules/ \
    --target binaries/ \
    --output "$OUTPUT_DIR/yara_results.json"
```

The `yara_scan.py` script combines all rules from the `yara-rules/` directory and produces a JSON that can be merged with the Ghidra results in `merge_reports.py`. The final report will contain, for each binary, both structural information (functions, symbols) and pattern detections (crypto constants, packer signatures, format markers).

```python
#!/usr/bin/env python3
# yara_scan.py — Batch YARA scan with JSON output
#
# Usage: python3 yara_scan.py --rules <dir> --target <dir> --output <file>

import yara  
import json  
import argparse  
from pathlib import Path  

def compile_all_rules(rules_dir):
    """Compile all .yar files from a directory into a single Rules object."""
    rule_files = {}
    for i, path in enumerate(sorted(Path(rules_dir).glob("*.yar"))):
        rule_files[f"ns_{i}"] = str(path)
    return yara.compile(filepaths=rule_files)

def scan_all(rules, target_dir):
    results = {}
    for filepath in sorted(Path(target_dir).rglob("*")):
        if not filepath.is_file() or filepath.stat().st_size == 0:
            continue
        try:
            matches = rules.match(str(filepath))
        except yara.Error:
            continue
        if matches:
            results[str(filepath)] = [m.rule for m in matches]
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    rules = compile_all_rules(args.rules)
    results = scan_all(rules, args.target)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    total = sum(len(v) for v in results.values())
    print(f"[+] {total} detections across {len(results)} files -> {args.output}")
```

---

## Best practices for writing rules

**Name rules descriptively.** The rule name is what appears in reports. `Crypto_Constants_Embedded` is actionable; `rule1` is not. Adopting a consistent naming convention — for example `Category_Target_Detail` — makes filtering and sorting results easier.

**Document in `meta`.** The `description`, `author`, `date`, `reference` (URL to the source analysis), and `severity` fields allow understanding a rule months after it was written. In a professional environment, YARA rules without metadata are unusable by colleagues.

**Combine multiple detection vectors.** A rule that relies on a single string produces false positives. Requiring the conjunction of several independent indicators — a text string *and* a hexadecimal constant *and* a structural property — drastically reduces noise. The `Ransomware_Ch27_Sample` rule illustrates this principle: it requires passphrase fragments, the XOR mask, the CRYPT24 magic, *and* an ELF x86-64 binary.

**Test on positives *and* negatives.** A rule is reliable only if it correctly detects targets (true positives) *and* does not detect non-targets (absence of false positives). On our repository, scanning `binaries/` with each rule allows verifying both: the `KeyGenMe_Ch21` rule should match all five keygenme variants and no other binary.

**Use wildcards sparingly.** A pattern like `{ E8 ?? ?? ?? ?? }` (`call` instruction with any offset) will match hundreds of times in any binary — it is only useful in combination with other more discriminating patterns. Each wildcard exponentially broadens the match scope.

**Version control your rules.** `.yar` files are plain text — they belong in the same Git repository as the binaries and analysis scripts. Every rule modification must be tracked, because a condition change can turn a clean scan into an avalanche of false positives (or, worse, silence on true positives).

---

## What YARA does not do

YARA is a *pattern search* engine — not a disassembler, not a semantic analyzer. It does not understand the structure of x86 instructions: it searches for byte sequences, period. This has practical consequences.

A hexadecimal pattern can match in `.text` (as an opcode or operand), in `.rodata` (as data), in `.debug_info` (as DWARF information), or even in padding between sections. YARA does not tell the difference. If the same pattern `{ DE AD BE EF }` appears as a constant in the code *and* as an artifact in debug sections, YARA will report both. It is up to the calling script — or the analyst — to cross-reference the match offset with the section map (via `pyelftools` or `lief`) to determine in which context the pattern was found.

Similarly, YARA does not follow control flow. It cannot express a condition like "constant X is used as an argument to a call to `EVP_EncryptInit_ex`." For this type of semantic detection, you need to combine YARA (rapid detection of candidates) with deeper analysis (Ghidra headless, as in section 35.2) on the pre-selected binaries. It is this funnel combination — YARA as a broad and fast filter, Ghidra as a targeted and deep analyzer — that constitutes a scalable analysis pipeline.

---


⏭️ [Integration into a CI/CD pipeline for binary regression auditing](/35-automation-scripting/05-pipeline-ci-cd.md)
