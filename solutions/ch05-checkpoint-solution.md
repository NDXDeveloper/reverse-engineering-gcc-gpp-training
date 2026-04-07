🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 5 Checkpoint

> **Spoilers** — Only consult this file after writing your own triage report.

---

## Triage Report — `mystery_bin`

### 1. Identification

```bash
$ file mystery_bin
mystery_bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, with debug_info, not stripped  
```

| Property | Value | Implication |  
|---|---|---|  
| Format | ELF 64-bit | Native Linux binary |  
| Architecture | x86-64, LSB (little-endian) | Standard PC instruction set |  
| Type | PIE executable (`DYN`) | Relative addresses, ASLR possible |  
| Linking | Dynamic (`libc.so.6`) | PLT/GOT present, imports visible |  
| Debug symbols | `with debug_info` | DWARF sections present (`.debug_*`) |  
| Stripping | `not stripped` | Local function names available in `.symtab` |  
| Compiler | GCC (version visible in `.comment`) | Standard GNU toolchain |

The binary is neither stripped nor packed. Conditions are ideal for triage: all tools will produce rich results.

---

### 2. Notable Strings

```bash
$ strings mystery_bin | grep -iE '(error|fail|password|key|access|encrypt|secret|mystery|config|verbose)'
```

**User interaction messages:**

- `=== mystery-tool v2.4.1-beta ===` → tool name and version.  
- `Enter access password:` → the program asks for a password.  
- `Authentication failed. Access denied.` → failure message.  
- `Authentication successful. Welcome.` → success message.  
- `Commands: encrypt <message> | status | quit` → the program has an interactive mode with commands.

**Sensitive data:**

- `R3v3rs3M3!2024` → suspicious string that strongly resembles a hardcoded password. Strong hypothesis: this is the value compared by `strcmp` during authentication.  
- `MYSTERYK` / `EY012345` → fragments of a key, probably an XOR key visible in `.rodata`.

**File paths:**

- `/tmp/mystery.conf` → configuration file read at startup.  
- `/tmp/mystery.out` → output file written by the program.  
- `/proc/self/status` → access to the proc pseudo-filesystem, classic debugger detection technique (reading `TracerPid`).

**Compilation information:**

```bash
$ strings mystery_bin | grep GCC
GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0
```

**Printf formats:**

```bash
$ strings mystery_bin | grep '%'
[!] Debugger detected (pid: %d)
[+] Message encrypted and written to %s (%zu bytes)
[*] Checksum: 0x%08X
[*] Timestamp: %lu
```

These formats reveal that the program displays a debugger PID (anti-debug), an output file path with size, a hexadecimal checksum, and a timestamp. The program therefore performs encryption and writes the result.

**Other significant strings:**

- `MYST` → possible magic bytes of a custom file format (output file header).  
- `encrypt`, `status`, `quit`, `exit` → interactive mode commands.  
- `Unknown command:` → command parser error handling.

---

### 3. ELF Structure

```bash
$ readelf -hW mystery_bin | grep -E '(Type|Machine|Entry|Number of section)'
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x10c0
  Number of section headers:         36
```

The binary has 36 sections — more than average, explained by the presence of DWARF sections (`debug_info`).

```bash
$ readelf -SW mystery_bin | grep -E '\.(text|rodata|data|bss|debug|symtab)'
  [15] .text             PROGBITS  ...  000005XX  ...  AX  ...
  [17] .rodata           PROGBITS  ...  000002XX  ...   A  ...
  [24] .data             PROGBITS  ...  ...       ...  WA  ...
  [25] .bss              NOBITS    ...  ...       ...  WA  ...
  [27] .symtab           SYMTAB    ...  ...       ...      ...
  [28] .strtab           STRTAB    ...  ...       ...      ...
  [29] .debug_info       PROGBITS  ...  ...       ...      ...
  [30] .debug_abbrev     PROGBITS  ...  ...       ...      ...
  [31] .debug_line       PROGBITS  ...  ...       ...      ...
  [32] .debug_str        PROGBITS  ...  ...       ...      ...
```

**Observations:**

- `.text` of a few hundred bytes: modest-sized program.  
- `.rodata` contains the strings (confirmed by `strings` results).  
- `.symtab` and `.strtab` present: full symbols available.  
- `.debug_*` sections present: the binary was compiled with `-g` (DWARF symbols). This will greatly facilitate debugging with GDB if needed.  
- No unusually named sections: no signs of packing or obfuscation.

```bash
$ readelf -d mystery_bin | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
```

Only dependency: `libc.so.6`. The program does not use an external crypto library (no `libssl`, `libcrypto`, `libsodium`). Encryption is therefore implemented internally — probably the XOR algorithm suggested by the strings.

```bash
$ readelf -lW mystery_bin | grep -E '(GNU_STACK|GNU_RELRO)'
  GNU_STACK      ... RW  0x10
  GNU_RELRO      ... R   0x1
```

Non-executable stack (NX enabled). RELRO segment present.

---

### 4. Functions and Imports

**Program functions:**

```bash
$ nm -nS mystery_bin | grep ' T '
0000000000001189 000000000000005e T compute_checksum
00000000000011e7 0000000000000042 T xor_encrypt
0000000000001229 0000000000000089 T check_debugger
00000000000012b2 00000000000000c5 T authenticate_user
0000000000001377 0000000000000065 T load_config
00000000000013dc 0000000000000120 T process_message
00000000000014fc 000000000000014a T interactive_mode
0000000000001646 00000000000000a2 T main
```

> **Note**: Exact addresses and sizes may vary depending on GCC version and compilation options. The values above are indicative.

Function names are extremely revealing and allow reconstructing the program architecture:

| Function | Approx. size | Inferred role |  
|---|---|---|  
| `main` | ~160 bytes | Entry point, orchestrates steps |  
| `check_debugger` | ~140 bytes | Debugger detection (light anti-RE) |  
| `authenticate_user` | ~200 bytes | Asks and verifies the password |  
| `load_config` | ~100 bytes | Loads `/tmp/mystery.conf` |  
| `process_message` | ~290 bytes | Encrypts a message and writes it to a file |  
| `xor_encrypt` | ~65 bytes | XOR encryption routine (short = simple algorithm) |  
| `compute_checksum` | ~95 bytes | Checksum computation on data |  
| `interactive_mode` | ~330 bytes | Command loop (largest function) |

**Probable execution flow** (inferred from names and sizes):
`main` → `check_debugger` → `load_config` → `authenticate_user` → `interactive_mode` → (`process_message` → `xor_encrypt` + `compute_checksum`).

**Imports (library functions):**

```bash
$ nm -D mystery_bin | grep ' U '
                 U atoi@GLIBC_2.2.5
                 U fclose@GLIBC_2.2.5
                 U fgets@GLIBC_2.2.5
                 U fopen@GLIBC_2.2.5
                 U fprintf@GLIBC_2.2.5
                 U free@GLIBC_2.2.5
                 U fwrite@GLIBC_2.2.5
                 U malloc@GLIBC_2.2.5
                 U memcpy@GLIBC_2.14
                 U printf@GLIBC_2.2.5
                 U strcmp@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
                 U strncmp@GLIBC_2.2.5
                 U time@GLIBC_2.2.5
                 U __stack_chk_fail@GLIBC_2.4
                 U fflush@GLIBC_2.2.5
```

**Import interpretation:**

- `strcmp`, `strncmp`, `strlen` → string comparisons (authentication, command parsing).  
- `fopen`, `fgets`, `fwrite`, `fclose` → file operations (config read line by line with `fgets`, output written with `fwrite`).  
- `malloc`, `free`, `memcpy` → buffer allocation and copy (processing the message to encrypt).  
- `printf`, `fprintf`, `fflush` → display (user interface, error messages on stderr).  
- `atoi` → string → integer conversion (option parsing in config file).  
- `time` → timestamp (timestamp in output file header).  
- `__stack_chk_fail` → stack canary enabled (confirmation for checksec).

No network imports (`socket`, `connect`, `send`, `recv`): the program does not communicate over the network. No process imports (`fork`, `execve`, `system`): it does not launch subprocesses.

> **Note**: Depending on GCC version and optimization level, some libc functions may be replaced by their fortified variants: `printf` → `__printf_chk`, `fprintf` → `__fprintf_chk`, `memcpy` → `__memcpy_chk`. Likewise, `printf("text\n")` may be optimized to `puts("text")` and `atoi` may be replaced by `strtol`. These substitutions do not change the functional interpretation.

---

### 5. Protections

```bash
$ checksec --file=mystery_bin
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY  Fortified  Fortifiable  FILE  
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   XX Symbols      No       0          X            mystery_bin  
```

| Protection | Status | Manual verification |  
|---|---|---|  
| NX | Enabled | `GNU_STACK` with `RW` flags (no `E`) |  
| PIE | Enabled | `DYN` type in the ELF header |  
| Stack Canary | Present | `__stack_chk_fail` symbol imported |  
| RELRO | Full | `GNU_RELRO` segment + `BIND_NOW` entry in `.dynamic` |  
| FORTIFY | No | No `_chk` symbol in imports |  
| RPATH/RUNPATH | Absent | No embedded library paths |

The binary is properly protected on all axes except FORTIFY. All protections are at their maximum level (Full RELRO, not just Partial).

---

### 6. Dynamic Behavior

**`strace` — significant system calls:**

```bash
$ strace -e trace=file,network,process -s 256 -o strace.log ./mystery_bin
```

Relevant results (after filtering library loading noise):

```
openat(AT_FDCWD, "/proc/self/status", O_RDONLY)         = 3   # Anti-debug: TracerPid read  
read(3, "Name:\tmystery_bin\n...", 256)                  = 256  
close(3)                                                  = 0  
openat(AT_FDCWD, "/tmp/mystery.conf", O_RDONLY)          = -1 ENOENT  # Config absent (normal)  
write(1, "=== mystery-tool v2.4.1-beta ===\n", 34)       = 34  
write(1, "Enter access password: ", 23)                   = 23  
read(0, "test\n", ...)                                    = 5  
write(2, "Authentication failed. Access denied.\n", 38)   = 38  # Output on stderr  
exit_group(1)  
```

**`strace` observations:**

- The program accesses `/proc/self/status` **before** any user interaction → debugger detection. Under GDB analysis, this check could cause issues (it needs to be bypassed).  
- It attempts to open `/tmp/mystery.conf` and gracefully handles file absence (`ENOENT` → continues without error).  
- No network syscalls (`socket`, `connect`) → no network communication, confirming static analysis.  
- No `fork`/`execve` → no subprocess launching.  
- The failure message is written to `fd 2` (stderr via `fprintf(stderr, ...)`).

**`ltrace` — library calls:**

```bash
$ ltrace -s 256 -o ltrace.log ./mystery_bin <<< "test"
```

```
fopen("/proc/self/status", "r")                          = 0x55a...  
fgets("Name:\tmystery_bin\n", 256, 0x55a...)             = 0x7ff...  
strncmp("Name:\tmystery_bin\n", "TracerPid:", 10)        = -1  
fgets("...", 256, 0x55a...)                               = ...  
[... reading line by line until TracerPid ...]
strncmp("TracerPid:\t0\n", "TracerPid:", 10)             = 0   # Found!  
atoi("0\n")                                               = 0   # No tracer  
fclose(0x55a...)                                          = 0  
fopen("/tmp/mystery.conf", "r")                           = 0   # NULL = file absent  
printf("=== %s ===\n", "mystery-tool v2.4.1-beta")       = 34  
printf("Enter access password: ")                         = 23  
fgets("test\n", 256, 0x7f...)                             = 0x7ff...  
strlen("test")                                            = 4  
strcmp("test", "R3v3rs3M3!2024")                          = 1   # ← PASSWORD REVEALED!  
fprintf(0x7f..., "Authentication failed. Access denied.\n") = 38  
```

**Critical discovery**: the line `strcmp("test", "R3v3rs3M3!2024")` reveals the password in plaintext. `ltrace` displays both `strcmp` arguments — our input `"test"` and the expected value `"R3v3rs3M3!2024"`.

**Verification with the correct password:**

```bash
$ ltrace -s 256 ./mystery_bin <<< $'R3v3rs3M3!2024\nencrypt Hello World\nquit'
```

```
[... check_debugger, load_config as before ...]
strcmp("R3v3rs3M3!2024", "R3v3rs3M3!2024")               = 0   # Match!  
printf("Authentication successful. Welcome.\n")           = ...  
[... interactive mode ...]
strncmp("encrypt Hello World", "encrypt ", 8)             = 0  
strlen("Hello World")                                     = 11  
malloc(11)                                                = 0x55a...  
memcpy(0x55a..., "Hello World", 11)                       = 0x55a...  
time(NULL)                                                = 1711234567  
fopen("/tmp/mystery.out", "wb")                           = 0x55a...  
fwrite("\x4d\x59\x53\x54...", 24, 1, 0x55a...)           = 1   # Header (magic "MYST")  
fwrite("\x01\x28\x30\x20...", 1, 11, 0x55a...)           = 11  # Encrypted data  
fclose(0x55a...)                                          = 0  
free(0x55a...)                                            = <void>  
strcmp("quit", "quit")                                    = 0  
```

The program does write a file `/tmp/mystery.out` with a header starting with `MYST` followed by XOR-encrypted data.

**Statistical profile:**

```bash
$ ltrace -c ./mystery_bin <<< "test"
% time     seconds  usecs/call     calls      function
------ ----------- ----------- --------- --------------------
 30.00    0.000006           1         6 fgets
 20.00    0.000004           0        10 strncmp
 15.00    0.000003           3         1 strcmp
 10.00    0.000002           1         2 fopen
 10.00    0.000002           1         2 printf
  5.00    0.000001           1         1 strlen
  5.00    0.000001           0         2 fprintf
  5.00    0.000001           1         1 fclose
  [...]
```

The high number of `strncmp` calls (10) corresponds to reading `/proc/self/status` line by line — each line is compared with `"TracerPid:"` until finding the right one.

---

### Conclusion and Strategy

**Program nature**: `mystery_bin` is an interactive command-line encryption tool. It authenticates the user by password, then offers an interactive mode where messages can be encrypted with an XOR algorithm. Encrypted messages are written to `/tmp/mystery.out` with a custom header (magic `MYST`). The program integrates light debugger detection via `/proc/self/status`.

**Vulnerabilities identified during triage**:

1. **Hardcoded password** in plaintext in `.rodata` (`R3v3rs3M3!2024`), directly visible with `strings` and confirmed by `ltrace`. Authentication is trivially bypassable.  
2. **XOR encryption key in plaintext** in `.rodata` (`MYSTERYKEY012345`). The encryption algorithm is therefore reversible without code analysis — just XOR the encrypted data with this key.  
3. **Bypassable anti-debug**: the `TracerPid` check in `/proc/self/status` can be bypassed by patching the conditional jump, using `LD_PRELOAD` to intercept `fopen`, or simply modifying `/proc/self/status` via a fake file in a mount namespace.

**Strategy for in-depth analysis**:

- **Immediate goal**: write a Python decryptor that reads `/tmp/mystery.out`, parses the `MysteryHeader` (magic + version + data_length + checksum + timestamp = probably 24 bytes), and XORs the data with the known key.  
- **Recommended tool**: open the binary in Ghidra (chapter 8) to confirm the exact header structure (field offsets and sizes) and validate the checksum algorithm.  
- **Quick alternative**: use ImHex (chapter 6) with a `.hexpat` pattern to directly visualize the structure of `/tmp/mystery.out`.  
- **For anti-debug bypass**: a simple Frida script (chapter 13) that hooks `fopen` and returns NULL when the path is `/proc/self/status` would suffice.

---

## Self-assessment Grid

Compare your report with this grid:

| Criterion | Points | Achieved? |  
|---|---|---|  
| Format, architecture and linking correctly identified | 1 | |  
| Stripping and DWARF symbol presence mentioned | 1 | |  
| At least 3 significant strings noted **and interpreted** | 1 | |  
| Hardcoded password identified (`R3v3rs3M3!2024`) | 1 | |  
| Mention of `/proc/self/status` file and interpretation as anti-debug | 1 | |  
| Paths `/tmp/mystery.conf` and `/tmp/mystery.out` identified | 1 | |  
| Program functions listed with inferred role | 1 | |  
| Imports interpreted (notably `strcmp`, absence of network) | 1 | |  
| All 5 protections (NX, PIE, canary, RELRO, FORTIFY) documented | 1 | |  
| `strace`: `/proc/self/status` and `/tmp/mystery.conf` access observed | 1 | |  
| `ltrace`: `strcmp` with plaintext password captured | 1 | |  
| Absence of network activity noted and mentioned | 1 | |  
| Reasoned hypotheses about the program's nature | 1 | |  
| Follow-up strategy formulated (which tool, which goal) | 1 | |  
| Structured and concise report (~1 page), no raw copy-paste | 1 | |

**Indicative grading**:

- **13–15 points**: excellent — you've mastered triage. Move on to chapter 6.  
- **10–12 points**: good level — reread the sections corresponding to missed points.  
- **7–9 points**: adequate — redo the triage following the section 5.7 workflow step by step.  
- **< 7 points**: go back to sections 5.1 to 5.6 with the practical examples before retrying the checkpoint.

⏭️
