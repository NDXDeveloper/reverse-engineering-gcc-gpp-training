🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 5.7 — Quick triage workflow: the first-5-minutes routine when facing a binary

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

Sections 5.1 through 5.6 presented each tool individually. This final section assembles them into a **reproducible workflow** — an ordered sequence of commands that you will systematically run on any new binary, before even opening a disassembler.

This workflow is not a theoretical invention. It is the routine practiced by analysts in CTFs, security audits, and professional reverse engineering. The goal is to build, in less than 5 minutes, an **identity card** for the binary that will guide all subsequent analyses: which tool to use first, where to focus attention, which hypotheses to formulate.

A disciplined triage avoids costly mistakes: opening an ARM binary in an x86 disassembler, wasting time looking for symbols in a stripped binary, running malware outside a sandbox, or ignoring a protection that will render an exploitation technique useless.

---

## Workflow overview

The triage breaks down into **six steps**, each answering a precise question. Steps 1 through 5 are purely static (no execution). Step 6 is dynamic and **must only be performed if the binary is considered trusted or in a sandboxed environment**.

| Step | Question | Main tool | Duration |  
|---|---|---|---|  
| 1 — Identification | What is it? | `file` | 5 seconds |  
| 2 — Strings | What revealing texts does it contain? | `strings` | 30 seconds |  
| 3 — ELF structure | How is it organized? | `readelf` | 1 minute |  
| 4 — Symbols and imports | Which functions does it contain and use? | `nm`, `readelf -s` | 1 minute |  
| 5 — Protections | Which defenses are in place? | `checksec` | 15 seconds |  
| 6 — Behavior (sandbox) | What does it do at runtime? | `strace`, `ltrace` | 2 minutes |

---

## Step 1 — Identification: what is it?

**Goal**: determine the file type, target architecture, and base properties.

```bash
$ file keygenme_O0
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=a3f5...c4e2, for GNU/Linux 3.2.0, not stripped  
```

**Information to note**:

- **Format**: ELF, PE, Mach-O, script, archive? — Determines which tools to use.  
- **Architecture**: x86-64, ARM, MIPS, RISC-V? — Determines which disassembler and which calling conventions apply.  
- **Linking**: dynamic or static? — Affects the availability of dynamic symbols and the PLT/GOT.  
- **Stripping**: `stripped` or `not stripped`? — Determines whether local function names are available.  
- **PIE**: `pie executable` or `executable`? — Affects the addressing scheme.

**Immediate decisions**:

- If the file is not an ELF (script, Java bytecode, .NET assembly, archive…), the workflow changes completely. Adapt your tooling.  
- If the architecture is not x86-64, check that your tools support it (Ghidra supports most architectures; `objdump` needs the right binutils backend).  
- If the binary is statically linked, steps based on dynamic symbols (`nm -D`, `ldd`) will yield nothing.

---

## Step 2 — Strings: what revealing texts does it contain?

**Goal**: extract readable strings to get clues about behavior, dependencies, and sensitive data.

```bash
# Raw extraction with offsets
$ strings -t x keygenme_O0 > /tmp/strings_output.txt

# Targeted searches
$ strings keygenme_O0 | grep -iE '(error|fail|denied|invalid|success|grant|password|key|flag)'
$ strings keygenme_O0 | grep -iE '(http|ftp|ssh|/tmp/|/etc/|\.conf|\.log)'
$ strings keygenme_O0 | grep -iE '(aes|sha|md5|rsa|encrypt|decrypt|crypt)'
$ strings keygenme_O0 | grep -E '(GLIBC|GCC|clang|rustc|go\.|Go build)'
$ strings keygenme_O0 | grep '%'
```

**Information to note**:

- **User messages**: prompts, error messages, success messages — they reveal the program's flow.  
- **Data formats**: patterns like `XXXX-XXXX-XXXX`, email addresses, date formats — they reveal expected inputs.  
- **Paths and URLs**: opened files, contacted servers, configuration files.  
- **Sensitive data**: hardcoded passwords, API keys, tokens, cryptographic constants.  
- **Compilation information**: GCC/Clang/rustc version, source filenames — tell you about the development environment.  
- **printf formats**: `%s`, `%d`, `%x` — each format is a clue about the type of data manipulated.

**Immediate decisions**:

- If strings are unusually sparse or gibberish, the binary may be packed or obfuscated. Note this hypothesis for step 3.  
- If you find network paths, suspicious URLs, or shell commands, treat the binary as potentially malicious and only run it in a sandbox.

---

## Step 3 — ELF structure: how is it organized?

**Goal**: dissect the headers, sections, and segments to understand the internal structure and detect anomalies.

```bash
# ELF header: entry point, type, number of sections
$ readelf -hW keygenme_O0

# Sections: full list with flags
$ readelf -SW keygenme_O0

# Segments: memory permissions and sections→segments mapping
$ readelf -lW keygenme_O0

# Direct dependencies
$ readelf -d keygenme_O0 | grep NEEDED
```

**Information to note**:

- **Entry point**: address of `_start`. Starting point for disassembly if symbols are absent.  
- **Sections present/absent**: `.symtab` present = not stripped. `.debug_*` present = DWARF symbols. Absence of standard sections or presence of sections with unusual names = possible packing or obfuscation.  
- **Size of `.text`**: provides an estimate of the code volume to analyze. A tiny `.text` with a bulky unknown section suggests a packer.  
- **Segment permissions**: verify no segment is `RWE` (sign of NX disabled or self-modifying code).  
- **`NEEDED` dependencies**: each library is a functional clue.

**Structural-anomaly detection**:

Certain section patterns signal a non-standard binary:

```bash
# Section entropy (packing/encryption indicator)
# A section with entropy close to 8.0 (max) is likely compressed or encrypted
# This will be detailed in Chapter 29, but stay alert at triage time

# Sections with non-standard names
$ readelf -SW keygenme_O0 | grep -vE '\.(text|data|bss|rodata|symtab|strtab|shstrtab|dynsym|dynstr|plt|got|init|fini|comment|note|gnu|rela|eh_frame|interp|dynamic)'

# Size of .text vs total file size
$ readelf -SW keygenme_O0 | grep '\.text'
$ ls -l keygenme_O0
```

If `.text` represents only a tiny fraction of the file and an unknown section takes up most of the space, that is a strong sign of packing: the real code is compressed/encrypted in the large section, and the small `.text` only contains the decompression stub.

**Complement on a trusted binary**:

```bash
# Full path resolution (only if the binary is trusted!)
$ ldd keygenme_O0
```

---

## Step 4 — Symbols and imports: which functions does it contain and use?

**Goal**: chart the program's functions and the library functions it uses.

```bash
# On a non-stripped binary: full symbol table
$ nm -n keygenme_O0 | grep ' [TtWw] '

# On a stripped binary: dynamic symbols only (imports)
$ nm -D keygenme_O0

# Detailed view with sizes
$ nm -nS keygenme_O0 | grep ' T '

# For C++: demangling
$ nm -nC cpp_program | grep ' T '
```

**Information to note**:

- **Program functions** (`T`/`t` symbols): their name, address, estimated size. Function names are often the best summary of a program's architecture.  
- **Imported functions** (`U` symbols): `strcmp` = string comparison, `socket`/`connect` = network, `EVP_*` = OpenSSL, `pthread_*` = multithreading, `dlopen`/`dlsym` = dynamic plugin loading.  
- **Number of functions**: a program with 5 functions is reversed in an hour; a program with 500 functions demands a prioritization strategy.

**Table of telling imports**:

| Detected imports | Likely functionality |  
|---|---|  
| `strcmp`, `strncmp`, `memcmp` | Comparison (crackme, authentication) |  
| `socket`, `connect`, `send`, `recv` | Network communication |  
| `EVP_*`, `AES_*`, `SHA*`, `RSA_*` | Encryption (OpenSSL) |  
| `fopen`, `fread`, `fwrite`, `mmap` | File handling |  
| `fork`, `execve`, `system`, `popen` | Process/command launching |  
| `dlopen`, `dlsym` | Dynamic library/plugin loading |  
| `pthread_create`, `pthread_mutex_*` | Multithreading |  
| `ptrace` | Anti-debugging (or debugging) |  
| `getenv`, `setenv` | Reading environment variables |

---

## Step 5 — Protections: which defenses are in place?

**Goal**: inventory security protections to adapt the analysis and exploitation strategy.

```bash
$ checksec --file=keygenme_O0
```

**Information to note**:

- **NX**: enabled or not. Impact on buffer-overflow exploitability.  
- **PIE**: enabled or not. Impact on address predictability.  
- **Canary**: present or not. Impact on stack-based buffer overflows.  
- **RELRO**: No / Partial / Full. Impact on GOT overwrite.  
- **FORTIFY**: fortified or not. Impact on libc buffer overruns.

If `checksec` is not available, reproduce the checks with `readelf` (see the correspondence table in section 5.6).

---

## Step 6 — Dynamic behavior (sandbox only)

> ⚠️ **This step involves executing the binary.** Only proceed if the binary is trusted (CTF, binary you compiled yourself) or in an isolated environment (sandboxed VM, Chapter 26). When in doubt, stop at step 5.

**Goal**: observe the program's actual behavior — interactions with the filesystem, network, user.

```bash
# System calls: which files, sockets, processes?
$ strace -e trace=file,network,process -s 256 -o strace.log ./keygenme_O0

# Library calls: which arguments for strcmp, printf, etc.?
$ ltrace -s 256 -o ltrace.log ./keygenme_O0

# Quick statistical profile
$ strace -c ./keygenme_O0 <<< "test"
$ ltrace -c ./keygenme_O0 <<< "test"
```

**Information to note**:

- **Files accessed**: which files does the program open besides its libraries? Accesses to `/etc/passwd`, `/proc/self/status`, or temporary files warrant investigation.  
- **Network connections**: IP addresses, ports, protocols — the starting point of network analysis (Chapter 23).  
- **String comparisons**: `ltrace` can directly reveal keys, passwords, or expected values if the program uses `strcmp`/`strncmp`.  
- **Child processes**: does the program launch other commands? `fork` + `execve` on `/bin/sh` is suspicious behavior.  
- **Memory modifications**: `mprotect` with `PROT_EXEC` suggests self-modifying code or unpacking.

---

## The triage report

At the end of the 6 steps, gather your observations in a structured report. This report will serve as a reference throughout the analysis and can be shared with other analysts.

Here is a triage report template:

```markdown
# Triage report — [binary name]

## 1. Identification
- **File**: keygenme_O0
- **Format**: ELF 64-bit LSB PIE executable
- **Architecture**: x86-64
- **Linking**: dynamic (libc.so.6)
- **Stripping**: not stripped (symbols available)
- **Compiler**: GCC 13.2.0 (Ubuntu)

## 2. Notable strings
- Messages: "Enter your license key:", "Access granted!", "Access denied."
- Expected format: XXXX-XXXX-XXXX-XXXX
- Suspicious data: "SuperSecret123" (possible hardcoded key)
- libc functions: strcmp, strlen, printf, puts

## 3. Structure
- Entry point: 0x10c0
- Sections: 31 (including .symtab, .strtab — full symbols)
- .text size: 0x225 (549 bytes) — short program
- Dependencies: libc.so.6 only
- Anomalies: none

## 4. Identified functions
- main (0x1189, 108 bytes)
- check_license (0x11f5, 139 bytes) ← primary target
- generate_expected_key (0x1280, 53 bytes)
- Critical imports: strcmp, strlen

## 5. Protections
- NX: enabled
- PIE: enabled
- Canary: present
- RELRO: Full
- FORTIFY: no

## 6. Dynamic behavior
- Asks for a key as input, compares with strcmp
- ltrace reveals the comparison: input vs "K3Y9-AX7F-QW2M-PL8N"
- No network activity
- No suspicious file activity
- Return code: 0 (success) or 1 (failure)

## Conclusion and strategy
Simple crackme-style program. Three possible approaches:
1. The key is directly visible in ltrace → immediate resolution.
2. Static analysis of check_license in Ghidra to understand the algorithm.
3. Automatic resolution with angr via the success/failure addresses.
```

This report fits on one page and contains everything an analyst needs to decide what to do next. Total production time: under 5 minutes.

---

## Adapting the workflow to the context

The workflow above is the general case. Depending on the context, certain steps become more important or need adjustments:

### CTF / Crackme

The priority is speed. `strings` + `ltrace` can suffice to solve a simple challenge in seconds. If `ltrace` reveals nothing, move straight to the disassembler.

### Security audit

Step 5 (protections) is central. Document every missing protection as a finding. Step 4 (imports) reveals the dangerous functions used (`gets`, `strcpy`, `sprintf` without a constant format).

### Malware analysis

**Never run step 6 outside a sandbox.** Replace `ldd` with `readelf -d | grep NEEDED`. Pay particular attention to network strings (C2 addresses), suspicious imports (`ptrace`, `fork`, `execve`, `unlink`), non-standard sections, and high entropy (packing).

### Legacy binary / no sources

Step 4 is crucial to understand the program's architecture. Spend more time on function names and imports to build a mental model before opening the disassembler.

---

## Automating the triage

Once the workflow is mastered manually, it is natural to want to automate it. The training repository includes a `scripts/triage.py` script that performs steps 1 through 5 automatically and produces a structured report. Chapter 35 (section 35.6) will revisit the construction of your own automation toolkit.

In the meantime, here is the minimal chain as a shell-command sequence:

```bash
#!/bin/bash
# triage_minimal.sh — Quick triage of an ELF binary
BINARY="$1"

echo "=== IDENTIFICATION ==="  
file "$BINARY"  
echo ""  

echo "=== NOTABLE STRINGS ==="  
strings "$BINARY" | grep -iE '(error|fail|denied|success|grant|password|key|flag|http|ftp|/tmp/|/etc/)' | head -20  
echo ""  

echo "=== COMPILER ==="  
strings "$BINARY" | grep -iE '(GCC|clang|rustc|Go build)' | head -5  
echo ""  

echo "=== ELF HEADER ==="  
readelf -hW "$BINARY" 2>/dev/null | grep -E '(Type|Machine|Entry)'  
echo ""  

echo "=== SECTIONS ==="  
readelf -SW "$BINARY" 2>/dev/null | grep -E '\.(text|data|bss|rodata|symtab|strtab|dynsym)'   
echo ""  

echo "=== DEPENDENCIES ==="  
readelf -d "$BINARY" 2>/dev/null | grep NEEDED  
echo ""  

echo "=== SYMBOLS (global functions) ==="  
nm -n "$BINARY" 2>/dev/null | grep ' T ' | grep -v -E '(_start|_init|_fini|__libc|_IO_|__do_global|register_tm|deregister_tm|frame_dummy)' | head -20  
echo ""  

echo "=== IMPORTS ==="  
nm -D "$BINARY" 2>/dev/null | grep ' U ' | head -20  
echo ""  

echo "=== PROTECTIONS ==="  
checksec --file="$BINARY" 2>/dev/null || echo "(checksec not available — use readelf manually)"  
```

```bash
$ chmod +x triage_minimal.sh
$ ./triage_minimal.sh keygenme_O0
```

This script does not replace human analysis — it speeds up the collection of raw information. Interpretation, hypothesis formulation, and strategy choice remain your work.

---

## What to remember going forward

- **Triage is a discipline, not an option.** The first 5 minutes facing a binary determine the efficiency of the hours that follow. A sloppy triage leads to dead ends; a rigorous triage opens the right leads.  
- **The order of steps is not arbitrary.** Start with static, safe work (no execution), end with dynamic, risky work (controlled execution). Each step enriches the context of the next.  
- **Document your observations.** A triage report, even minimal, is a valuable reference when analysis drags on. It saves redoing the same work and eases sharing with other analysts.  
- **Adapt the workflow to the context.** CTF, audit, malware, legacy — priorities change, but the structure stays the same.  
- **Automate repetitive tasks.** Once the workflow is internalized, script it. Your future self will thank you.

With this triage workflow mastered, you are ready to move on: in-depth analysis with advanced hex editors (Chapter 6), disassembly (Chapters 7–9), and debugging (Chapter 11).

---


⏭️ [🎯 Checkpoint: perform a complete triage of the provided `mystery_bin` binary, write a one-page report](/05-basic-inspection-tools/checkpoint.md)
