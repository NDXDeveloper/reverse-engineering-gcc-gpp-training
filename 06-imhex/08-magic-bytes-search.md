🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.8 — Searching for magic bytes, encoded strings, and opcode sequences

> 🎯 **Goal of this section**: Master ImHex's search functions — hexadecimal search, string search, regular-expression search, and entropy analysis — to quickly locate signatures, encoded data, and instruction sequences in a binary.

---

## The context: finding a needle in a haystack of bytes

A medium-sized ELF binary weighs between a few tens and a few hundred kilobytes. A statically linked binary or a Go/Rust binary can exceed one megabyte. Visually scanning thousands of hexadecimal lines to find a precise motif — a magic number, a cryptographic constant, an obfuscated string, a particular opcode — is impractical.

The CLI `strings` command (seen in Chapter 5) solves part of the problem for visible ASCII strings. But it finds neither arbitrary byte sequences, nor encoded strings (XOR, Base64, UTF-16), nor machine-opcode patterns. ImHex offers a much richer set of search functions, directly integrated into the hex view.

---

## The search dialog

The search opens with `Ctrl+F`. ImHex shows a search bar at the top of the hex view with several selectable modes. Each mode corresponds to a different kind of motif.

### Hexadecimal search (Hex)

This is the most fundamental mode: you enter a byte sequence in hexadecimal notation, and ImHex finds every occurrence in the file.

```
Motif: 7F 45 4C 46
```

This search finds the ELF magic number. Results are highlighted in the hex view, and you can navigate between occurrences with the next/previous buttons (or `F3` / `Shift+F3`).

Hex search accepts spaces between bytes (for readability) but does not require them — `7F454C46` works too. It also accepts the `??` character as a **wildcard** for any byte:

```
Motif: 48 8B ?? 10
```

This motif searches for the opcode `mov reg, [reg+0x10]` in x86-64: `48 8B` is the REX.W prefix + `MOV` opcode, the third byte varies with source and destination registers, and `10` is the displacement. Wildcards are essential for searching instruction patterns without worrying about exact registers — we'll come back to this in the opcodes subsection.

### String search (String)

String mode searches for a character string in the file. ImHex automatically converts the string to bytes according to the chosen encoding.

```
String: "password"
```

ImHex looks for the bytes `70 61 73 73 77 6F 72 64` (ASCII encoding). Search options let you choose the encoding: ASCII, UTF-8, UTF-16 LE, UTF-16 BE. UTF-16 LE search is particularly useful for Windows binaries compiled with MinGW, where strings are often in wide chars (`wchar_t`, 2 bytes per character).

String search is not case-sensitive by default — you can enable or disable this option depending on the context.

### Regular-expression search (Regex)

ImHex supports regular-expression searching on content interpreted as text. This mode is useful for finding **string patterns** rather than exact strings:

```
Regex: [A-Za-z0-9+/]{20,}={0,2}
```

This pattern looks for sequences resembling **Base64**: 20 or more characters in the Base64 alphabet, followed by 0 to 2 `=` padding signs. It is a heuristic, not a guarantee — binary data can accidentally match — but it's an effective starting point for spotting encoded data.

Other regexes useful in RE:

```
https?://[^\x00]+          # Embedded URLs
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}   # IPv4 addresses
[A-Fa-f0-9]{32,64}        # MD5/SHA-1/SHA-256 hash in ASCII hex
```

---

## Searching magic bytes: identifying embedded formats

Magic bytes (or magic numbers) are fixed byte sequences placed at the start of a file or data block to identify its format. The `file` command on Linux relies precisely on a database of magic bytes to identify file types.

In a binary, files or formatted data blocks can be **embedded** in the `.rodata` or `.data` sections: images, certificates, archives, serialized configuration files. Searching for known magic bytes locates them quickly.

### Common magic bytes to know

Here are the signatures most frequently encountered in reverse engineering of GCC-compiled ELF binaries:

| Format | Magic bytes (hex) | ASCII representation |  
|---|---|---|  
| ELF | `7F 45 4C 46` | `.ELF` |  
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |  
| JPEG | `FF D8 FF` | `...` |  
| ZIP / JAR | `50 4B 03 04` | `PK..` |  
| gzip | `1F 8B` | `..` |  
| PDF | `25 50 44 46` | `%PDF` |  
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74` | `SQLite format` |  
| DER (X.509 certificate) | `30 82` | `0.` |  
| PEM (text certificate) | `2D 2D 2D 2D 2D 42 45 47 49 4E` | `-----BEGIN` |  
| Protobuf (varint) | no fixed magic, but `08` followed by small integers is a frequent pattern | — |

When you analyze an unknown binary, running a series of hex searches on these magic bytes is a quick triage reflex. If you find a PNG magic in `.rodata`, you know an image is embedded. If you find a SQLite magic, the program probably uses a local database.

### Special case: cryptographic constants

Some byte sequences signal the use of specific cryptographic algorithms. They are not magic bytes in the classical sense, but **initialization constants** (IV, S-box, round values) that the compiler places in `.rodata` or directly inline in the code.

Examples:

| Algorithm | Constant | Hex sequence (start) |  
|---|---|---|  
| AES | S-box (first line) | `63 7C 77 7B F2 6B 6F C5` |  
| SHA-256 | Initial values H0–H3 | `67 E6 09 6A 85 AE 67 BB` (little-endian) |  
| MD5 | Constants T[1]–T[2] | `78 A4 6A D7 56 B7 C7 E8` (little-endian) |  
| RC4 | No fixed constant | — (but a 256-byte S-box initialized sequentially `00 01 02 ... FF` before permutation) |  
| ChaCha20 | Constant "expand 32-byte k" | `65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B` |

Searching for these constants is a fundamental technique of cryptographic analysis that we will deepen in Chapter 24. Appendix J provides a more complete reference table. For now, retain the principle: a hex search on `63 7C 77 7B` in an unknown binary tells you in seconds whether AES is embedded.

---

## Searching encoded and obfuscated strings

Plaintext strings (`strings`) are the first thing an analyst looks for in a binary. Developers who want to hinder analysis know this, and they obfuscate sensitive strings — passwords, C2 URLs, revealing error messages. The most common obfuscation methods are XOR with a fixed key, Base64 encoding, and on-the-fly encryption (the string is decrypted in memory at runtime).

### Strings XORed with a fixed key

XOR with a constant byte is the most primitive but still very widespread obfuscation, especially in low-sophistication malware. If the string `password` is XORed with the key `0x5A`, the resulting bytes are `2A 3B 29 29 2D 35 28 3E` — unreadable by `strings` but present in the binary.

ImHex does not natively offer a "search with XOR decryption", but several approaches allow detecting these strings.

**Code-based approach.** Disassembly (Chapters 7–8) often reveals the deobfuscation routine: a loop that XORs each byte of a buffer with a constant. Once the key is identified, you can write a `.hexpat` pattern that applies the XOR on display:

```cpp
struct XorString {
    u8 raw[16];
};

fn decode_xor(u8 byte) {
    return byte ^ 0x5A;
};

XorString obfuscated @ 0x...;
```

We will see more advanced techniques with `.hexpat` scripting and transformation functions in the following chapters.

**Entropy-based approach.** A zone of data XORed with a constant byte preserves the statistical patterns of the original string (an English text XORed with `0x5A` still has a characteristic frequency distribution). Entropy analysis (see below) can help distinguish these zones from truly random or compressed data.

### Base64 strings

Base64 transforms binary data into printable ASCII characters (alphabet `A-Z`, `a-z`, `0-9`, `+`, `/`, with `=` as padding). In a binary, a Base64 string appears as a sequence of ASCII characters — `strings` finds it, but without context it looks like gibberish.

The regex search seen above is effective for spotting Base64 blocks. Once a candidate is identified, you can decode it outside ImHex:

```bash
echo "SGVsbG8gUkUh" | base64 -d
# Hello RE!
```

### UTF-16 strings

Binaries compiled with MinGW for Windows or binaries that use wide-char APIs store strings in UTF-16: each ASCII character takes 2 bytes (the character followed by a null byte). The string `Hello` becomes `48 00 65 00 6C 00 6C 00 6F 00`.

The standard `strings` command does not find them (except with the `-e l` option for little-endian 16-bit). ImHex's String search in UTF-16 LE mode detects them directly.

---

## Searching opcode sequences

Beyond data, ImHex lets you search for **machine-instruction patterns** directly in the `.text` section. That's useful to locate specific instructions without importing the binary into a full disassembler.

### Frequently searched opcodes

Here are x86-64 opcode sequences commonly searched in RE, and the matching hexadecimal motifs:

**The `int 3` instruction (software breakpoint)**:

```
Motif: CC
```

A `CC` byte in `.text` is a breakpoint (`int3`). Debuggers insert this instruction to stop execution. Finding persistent `CC`s in a binary can indicate an anti-debug technique (the program checks whether its own opcodes have been modified — Chapter 19).

**The `syscall` instruction**:

```
Motif: 0F 05
```

Searching for `0F 05` locates all direct system calls in the binary. A typical GCC-compiled binary uses libc and makes few direct syscalls. Finding many is a hint at code that intentionally bypasses libc — frequent behavior in shellcodes and malware (Part VI).

**The `nop` instruction (and its variants)**:

```
Motif: 90                    # simple nop (1 byte)  
Motif: 0F 1F 00              # long nop (3 bytes)  
Motif: 0F 1F 40 00           # long nop (4 bytes)  
Motif: 0F 1F 44 00 00        # long nop (5 bytes)  
```

GCC uses `nop`s of different sizes to align functions and loops on address boundaries. A long sequence of `nop`s often signals a function boundary or alignment padding.

**Relative `call` and `jmp` instructions**:

```
Motif: E8 ?? ?? ?? ??        # call rel32 (relative call)  
Motif: E9 ?? ?? ?? ??        # jmp rel32 (relative unconditional jump)  
```

`E8` followed by 4 bytes is a `call` with a 32-bit relative displacement. By searching this motif with wildcards, you can count the number of function calls in the binary — a rough but quick measure of code complexity.

**The `push rbp; mov rbp, rsp` sequence (function prologue)**:

```
Motif: 55 48 89 E5
```

This motif identifies the standard prologue of functions compiled by GCC without the `-fomit-frame-pointer` option (typically in `-O0`). Searching this sequence amounts to searching function entry points — a useful shortcut when the binary is stripped and you do not have a symbol table.

### Precautions with opcode search

Hex search does not account for **instruction boundaries**. The bytes `0F 05` can appear in the middle of a longer instruction without being a `syscall` — for example, in an immediate or an address displacement. For this reason, opcode search in ImHex is a **triage** tool: it identifies candidates you must then verify in the disassembler (section 6.9) or in Ghidra (Chapter 8). Never conclude that an instruction exists solely based on a hex match.

Similarly, the searched bytes may live in data sections (`.rodata`, `.data`) rather than in `.text`. Always check that results fall within the `.text` section's offset range — your ELF pattern from section 6.4 gives you these offsets.

---

## Entropy analysis: searching by statistics

All previous searches assume you know **what** to search for: a precise magic number, a string, an opcode. But how do you spot interesting zones when you do not know what they contain? Entropy analysis is the answer.

### The principle

Shannon entropy measures the degree of "disorder" of a byte sequence, on a scale of 0 to 8 bits per byte. In practice:

- **Entropy near 0** — very regular data: zero zones, uniform padding. Found in `.bss` (uninitialized, filled with zeros in the file) or in alignment zones.  
- **Entropy between 3 and 5** — structured data: machine code, ASCII text, data structures. x86-64 code has a typical entropy around 5–6 bits/byte, English text around 4.  
- **Entropy between 5 and 7** — compressed data or dense machine code, with some residual regularities.  
- **Entropy near 8** — near-random data: encrypted content, high-quality compressed data (zlib, zstd), cryptographic keys.

### ImHex's Information view

Access entropy analysis via **View → Information** (or sometimes integrated into **View → Data Information** depending on the version). ImHex computes entropy per block and displays an **entropy graph** over the entire length of the file — the horizontal axis represents offsets, the vertical axis local entropy.

This graph is a **heatmap** of the file. At a glance, you spot:

- High-entropy plateaus (near 8) — encrypted or compressed data. If a plateau covers a region of `.data` or `.rodata`, the program probably contains encrypted data that it decrypts at runtime.  
- Entropy peaks in `.text` — particularly dense code zones or data chunks embedded in the code (constant tables, jump tables).  
- Entropy troughs — padding zones, `.bss` sections, string tables (many null terminators).

### Entropy and packing detection

The most direct application of entropy analysis in RE is **packing detection**. A binary packed (compressed or encrypted) with UPX or a custom packer has a characteristic entropy profile: nearly the entire file is at high entropy (> 7), with only a small decompression stub at the beginning of `.text` at normal entropy. This profile strongly contrasts with a normal binary where `.text` oscillates around 5–6 and `.rodata` oscillates around 4–5.

We will exploit this technique in Chapter 29 to detect and identify packers. For now, remember that ImHex's entropy graph is an immediate triage tool: a glance suffices to distinguish a normal binary from a packed one.

---

## Combining techniques: search workflow

In practice, the different search techniques combine in a sequential workflow. Here is the order we recommend facing an unknown binary, complementing the quick triage workflow from Chapter 5.

**First, entropy.** Open the Information view to get the global entropy profile. Identify high-entropy zones (encryption/compression?), low-entropy zones (padding/structured data), and intermediate zones (code/text). Place exploratory bookmarks on notable zones.

**Then magic bytes.** Run hex searches on common signatures: embedded ELF, PNG, ZIP, gzip, SQLite, certificates. Each result teaches you something about the program's dependencies and embedded data.

**Then crypto constants.** Search for the first bytes of AES S-boxes, SHA-256 IVs, the ChaCha20 constant. A hit signals the use of a specific algorithm and points you towards cryptographic analysis (Chapter 24).

**Then strings.** Use ImHex's Strings panel or String search for ASCII and UTF-16 strings. Also search by regex for Base64 patterns, URLs, IP addresses.

**Finally, opcodes.** If you have hypotheses about the binary's behavior (does it make direct syscalls? does it contain anti-debug `int3`s?), search for the matching opcode sequences. Verify each hit in the disassembler.

This workflow takes a few minutes and produces a considerable amount of information about the binary before even opening a disassembler.

---

## Summary

ImHex offers a search arsenal much richer than the `strings` command: hex search with wildcards for magic bytes and opcodes, multi-encoding string search (ASCII, UTF-16) for visible text, regex search for encoded data (Base64, URLs, IPs), and entropy analysis to statistically map encrypted, compressed, textual, or padding zones. By combining these techniques in a sequential workflow — entropy, magic bytes, crypto constants, strings, opcodes — you extract in a few minutes an overview of a binary's content that guides all subsequent analysis. Each search result can immediately be bookmarked and colorized (section 6.6) to build the progressive file map.

---


⏭️ [Integration with ImHex's built-in disassembler](/06-imhex/09-integrated-disassembler.md)
