🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.3 — Locating the Verification Routine (Top-Down Approach)

> 📖 **Reminder**: this section assumes a basic proficiency with Ghidra (import, CodeBrowser, Decompiler, Symbol Tree, cross-references). If this is not the case, go back to chapter 8 (sections 8.1 to 8.7) before proceeding.

---

## Introduction

The first two sections provided us with a map of the terrain: we know the binary's format, its protections, its revealing strings, and its functions. It is time to look under the hood. The objective of this section is precise: **locate the function that decides whether the key is valid or not**, that is, identify the exact point in the code where the program takes the "success" path or the "failure" path.

To achieve this, we adopt a **top-down** approach: start from what we know (the entry point, the character strings) and descend through the call graph until reaching the verification function. This is the most natural and reliable strategy on a modestly sized binary. The reverse approach — bottom-up, starting from a call to `strcmp` and working upward — is equally valid and will be mentioned at the end of this section.

We are working on `keygenme_O0` (with symbols). At the end of the section, we will see how to apply the same approach on the stripped variant `keygenme_strip`, where function names have disappeared.

---

## Step 1 — Import and automatic analysis in Ghidra

### Project creation and import

After launching Ghidra and creating a project (or reusing an existing one), we import the binary:

1. **File → Import File** → select `keygenme_O0`.  
2. Ghidra automatically detects the format (`ELF`, `x86:LE:64:default`). Accept the default values.  
3. A dialog offers analysis options. Click **Yes** then **Analyze** to launch the automatic analysis with default options.

The analysis takes a few seconds on such a small binary. Ghidra performs several passes:

- **Disassembly**: decoding machine instructions into assembly mnemonics.  
- **Function identification**: detecting function boundaries (prologues, epilogues, `call`/`ret` patterns).  
- **Decompilation**: translating assembly into pseudo-C for each function.  
- **Reference analysis**: building the cross-reference graph (who calls whom, who references what data).  
- **DWARF import**: since the binary contains debug information, Ghidra imports function names, variable types, and structures.

> 💡 **Tip**: on a binary with DWARF, Ghidra may sometimes miss certain information on the first pass. If the decompiler displays generic types (`undefined8`, `long`) while the source uses `uint32_t` or `uint16_t`, rerun the analysis via **Analysis → Auto Analyze** specifically checking **DWARF**.

### First look at the Symbol Tree

Once the analysis is complete, the **Symbol Tree** panel (on the left in the CodeBrowser) lists the detected functions. Expanding the **Functions** folder, we find exactly the symbols that `nm` had listed in section 21.1:

```
Functions/
├── _start
├── main
├── check_license
├── compute_hash
├── derive_key
├── format_key
├── read_line
├── rotate_left
└── ... (CRT functions: __libc_csu_init, _init, _fini, etc.)
```

The C Runtime functions (`_start`, `__libc_csu_init`...) are the initialization code added by GCC/glibc before calling `main`. They can be ignored for the keygenme analysis.

---

## Step 2 — Analyzing `main()`: the starting point

Double-clicking on `main` in the Symbol Tree opens the function in both the Listing (assembly) and Decompiler (pseudo-C) panels. Let's start with the pseudo-C, which is more readable at first glance.

### Reading the decompiler

Ghidra's decompiler produces pseudo-C that looks like this (variable names may differ slightly depending on the Ghidra version and DWARF options):

```c
int main(void)
{
    char username[32];
    char user_key[21];
    size_t ulen;

    printf("%s\n\n", "=== KeyGenMe v1.0 — RE Training ===");

    printf("Enter username: ");
    if (read_line(username, 32) != 0) {
        return 1;
    }

    ulen = strlen(username);
    if ((ulen < 3) || (31 <= ulen)) {
        printf("[-] Username must be between 3 and 31 characters.\n");
        return 1;
    }

    printf("Enter license key (XXXX-XXXX-XXXX-XXXX): ");
    if (read_line(user_key, 21) != 0) {
        return 1;
    }

    if (check_license(username, user_key) != 0) {
        printf("[+] Valid license! Welcome, %s.\n", username);
        return 0;
    }
    else {
        printf("[-] Invalid license. Try again.\n");
        return 1;
    }
}
```

Even without having seen the source code, this pseudo-C is remarkably clear at `-O0` with DWARF symbols. The program flow is immediately identifiable:

1. Banner display.  
2. Username reading, length verification (3 to 31 characters).  
3. License key reading.  
4. Call to **`check_license(username, user_key)`** — this is the decision point.  
5. Based on the return value: success or failure message.

The function `check_license` is our target. Its name is explicit here thanks to symbols, but the reasoning would be the same without them: we would look for "the function called just before the fork between the success message and the failure message."

### The flow in the Listing (assembly)

Switching to the Listing panel, we observe the corresponding assembly code. Here is the critical passage around the call to `check_license`:

```nasm
; Argument setup (System V AMD64)
LEA     RDI, [RBP + username]      ; 1st argument: username  
LEA     RSI, [RBP + user_key]      ; 2nd argument: user_key  
CALL    check_license              ; function call  

; Return in EAX — convention: 1 = valid, 0 = invalid
TEST    EAX, EAX  
JZ      .label_fail                ; if EAX == 0 → jump to "failure" path  

; "Success" path (EAX != 0)
LEA     RSI, [RBP + username]  
LEA     RDI, [.rodata + MSG_OK]    ; "[+] Valid license! ..."  
CALL    printf@plt  
...

.label_fail:
; "Failure" path (EAX == 0)
LEA     RDI, [.rodata + MSG_FAIL]  ; "[-] Invalid license. ..."  
CALL    printf@plt  
```

This block is the heart of the crackme mechanism. We can read:

- **`CALL check_license`**: the program delegates verification to a subfunction.  
- **`TEST EAX, EAX`**: tests whether the return value is zero. The `TEST` instruction performs a bitwise AND without storing the result — it only sets the flags, in particular the Zero Flag (ZF).  
- **`JZ .label_fail`**: if ZF = 1 (i.e., EAX = 0, invalid key), jump to the failure path. Otherwise (EAX ≠ 0, valid key), execution continues sequentially to the success path.

This `TEST`/`JZ` pair is the program's **decision point**. This is the instruction we will patch in section 21.6 to reverse the behavior (turning the `JZ` into a `JNZ` or an unconditional `JMP`).

---

## Step 3 — Descending into `check_license()`

Double-click on `check_license` in the Listing (or in the Decompiler by clicking the function name) to navigate to its definition.

### Pseudo-C of `check_license`

```c
int check_license(char *username, char *user_key)
{
    uint32_t hash;
    uint16_t groups[4];
    char expected[20];

    hash = compute_hash(username);
    derive_key(hash, groups);
    format_key(groups, expected);

    if (strcmp(expected, user_key) == 0) {
        return 1;
    }
    return 0;
}
```

The logic is crystal clear:

1. **`compute_hash(username)`** — transforms the username into a 32-bit integer.  
2. **`derive_key(hash, groups)`** — derives 4 16-bit values from the hash.  
3. **`format_key(groups, expected)`** — formats these values into a `XXXX-XXXX-XXXX-XXXX` string.  
4. **`strcmp(expected, user_key)`** — compares the expected key (computed) with the key entered by the user.

The `strcmp` is the **ultimate comparison point**. If the two strings are identical, `strcmp` returns 0, the condition is true, and `check_license` returns 1 (success). Otherwise, it returns 0 (failure).

### The assembly Listing of `check_license`

In the Listing panel, we find these four successive calls:

```nasm
check_license:
    PUSH    RBP
    MOV     RBP, RSP
    SUB     RSP, 0x50                ; stack frame allocation
    MOV     QWORD PTR [RBP-0x48], RDI   ; save username
    MOV     QWORD PTR [RBP-0x50], RSI   ; save user_key

    ; ── canary: read ──
    MOV     RAX, QWORD PTR FS:[0x28]
    MOV     QWORD PTR [RBP-0x8], RAX

    ; ── (1) compute_hash(username) ──
    MOV     RDI, QWORD PTR [RBP-0x48]
    CALL    compute_hash
    MOV     DWORD PTR [RBP-0x0c], EAX   ; hash stored locally

    ; ── (2) derive_key(hash, groups) ──
    MOV     EDI, DWORD PTR [RBP-0x0c]
    LEA     RSI, [RBP-0x18]             ; address of groups[4] array
    CALL    derive_key

    ; ── (3) format_key(groups, expected) ──
    LEA     RDI, [RBP-0x18]
    LEA     RSI, [RBP-0x30]             ; address of expected buffer
    CALL    format_key

    ; ── (4) strcmp(expected, user_key) ──
    LEA     RDI, [RBP-0x30]             ; expected (1st argument)
    MOV     RSI, QWORD PTR [RBP-0x50]   ; user_key (2nd argument)
    CALL    strcmp@plt

    ; ── Decision point ──
    TEST    EAX, EAX
    JNE     .return_zero                ; if strcmp != 0 → invalid key

    MOV     EAX, 0x1                    ; return 1 (success)
    JMP     .epilogue

.return_zero:
    MOV     EAX, 0x0                    ; return 0 (failure)

.epilogue:
    ; ── canary: verification ──
    MOV     RDX, QWORD PTR [RBP-0x8]
    XOR     RDX, QWORD PTR FS:[0x28]
    JNE     __stack_chk_fail@plt

    LEAVE
    RET
```

Let's take the time to read this listing methodically, applying the 5-step method from chapter 3 (section 3.7):

**1. Prologue and stack frame** — The first three instructions (`PUSH RBP` / `MOV RBP, RSP` / `SUB RSP, 0x50`) create an 80-byte stack frame. This is standard at `-O0`: the compiler allocates comfortable space for local variables, even if it only uses part of it.

**2. Argument saving** — The two parameters (`username` in `RDI`, `user_key` in `RSI`) are immediately copied to the stack. At `-O0`, GCC systematically saves arguments to memory rather than keeping them in registers. This is inefficient but very readable: we know exactly where each variable resides.

**3. Canary** — Reading `FS:[0x28]` and storing it at `[RBP-0x8]` constitutes the stack canary protection code (seen in section 21.2). This block and its counterpart in the epilogue are protection noise to be ignored.

**4. The four calls** — We find the sequence `compute_hash` → `derive_key` → `format_key` → `strcmp@plt`. Each call is preceded by setting up arguments in registers (`RDI`, `RSI`) according to the System V AMD64 convention. Each function's result is in `EAX` (or `RAX` for pointers).

**5. Decision point** — After `CALL strcmp@plt`, we find the `TEST EAX, EAX` / `JNE .return_zero` pair. If `strcmp` returns a non-zero value (different strings), the jump is taken and the function returns 0 (failure). Otherwise, it returns 1 (success).

> 💡 **Note on jumps**: in `main`, it is a `JZ` that leads to failure (testing `check_license() == 0`). In `check_license`, it is a `JNE` that leads to return 0 (testing `strcmp() != 0`). Both are logically consistent, but the conditional jump used depends on how the compiler organizes the code. This is why it is essential to read the context (what happens before and after the jump) rather than relying solely on the mnemonic.

---

## Step 4 — Using cross-references (XREF)

Cross-references are one of a disassembler's most powerful tools. They answer two fundamental questions: "who calls this function?" and "who references this data?"

### XREF to success/failure strings

An alternative approach for locating the decision point is to start from the strings found by `strings` in section 21.1. In Ghidra:

1. **Window → Defined Strings** (or **Search → For Strings**).  
2. Search for `Valid license` or `Invalid license`.  
3. Double-click the string to navigate to its location in `.rodata`.  
4. In the Listing panel, the string appears with its cross-references:

```
XREF[1]: main:001015e6(*)
```

5. Click on the reference to jump directly to the point in `main` where this string is used.

We land on the `LEA RDI, [MSG_OK]` that precedes the `CALL printf@plt` — exactly in the success path. Going up a few instructions, we find the `TEST EAX, EAX` / `JZ` after the call to `check_license`.

### XREF to `strcmp`

Similarly, we can search for all calls to `strcmp` in the binary:

1. In the Symbol Tree, navigate to **Imports → strcmp**.  
2. Right-click → **References → Show References to**.

Ghidra displays the list of all code locations that call `strcmp`. On our keygenme, there is only one call — in `check_license`. On a more complex binary with multiple verifications, this technique allows quickly identifying all comparison points.

### XREF from `check_license`

Conversely, we can check who calls `check_license`:

1. Click on the `check_license` name in the Listing.  
2. Right-click → **References → Show References to**.

Result: a single caller — `main`. This confirms that all verification logic is centralized in this single function.

### Call graph

For an overview, Ghidra offers a call graph:

1. Select `main` in the Symbol Tree.  
2. **Window → Function Call Graph**.

The graph visually displays the hierarchy:

```
main
 ├── printf@plt
 ├── read_line
 │    ├── fgets@plt
 │    └── strlen@plt
 ├── strlen@plt
 └── check_license
      ├── compute_hash
      │    └── strlen@plt
      ├── derive_key
      │    └── rotate_left
      ├── format_key
      │    └── snprintf@plt
      └── strcmp@plt
```

This graph confirms and enriches the sketch we had deduced from `nm` in section 21.1. We can now see the libc calls (`strlen`, `snprintf`, `strcmp`) and understand the role of each internal function: `compute_hash` works on the username (it calls `strlen`), `format_key` produces a formatted string (it calls `snprintf`), and `check_license` orchestrates everything before comparing via `strcmp`.

---

## Step 5 — Renaming and annotation

Even on a binary with symbols, it is good practice to annotate the disassembly to document your understanding. Ghidra saves these annotations in the project — they will be available on each reopening.

### Comments at key points

Add comments (right-click → **Comments → Set Pre/Post Comment**) at strategic locations:

- On the `CALL check_license` in `main`: `// Decision point: verifies the license`  
- On the `TEST EAX, EAX` / `JZ` in `main`: `// If check_license returns 0 → failure`  
- On the `CALL strcmp@plt` in `check_license`: `// Compares computed key vs entered key`  
- On the `TEST EAX, EAX` / `JNE` in `check_license`: `// strcmp != 0 → different strings → failure`

### Custom labels

Labels can be renamed to improve readability:

- `.label_fail` → `LICENSE_INVALID` (in `main`)  
- `.return_zero` → `KEY_MISMATCH` (in `check_license`)

### Bookmarks

Ghidra allows setting bookmarks on critical addresses. Mark:

- The address of `CALL check_license` (verification entry point)  
- The address of `CALL strcmp@plt` (comparison point)  
- The address of the `JZ`/`JNE` (conditional jump to patch in section 21.6)

These bookmarks are accessible via **Window → Bookmarks** and allow instant navigation to points of interest during subsequent sessions.

---

## Applying to a stripped binary

On `keygenme_strip`, symbols have been removed. The Symbol Tree no longer contains `check_license` or `compute_hash` — all internal functions appear under Ghidra-generated names (`FUN_00101189`, `FUN_001011b2`, etc.). How do we find our way?

### Strategy 1: start from strings

Strings in `.rodata` are **not** removed by `strip` (they are part of the code, not debug symbols). We can therefore apply exactly the same XREF technique:

1. Search for `"Valid license"` in the Defined Strings.  
2. Follow the cross-reference → we land in a function (e.g., `FUN_001013d0`).  
3. This function is `main` (it contains the banner `printf`, the input reads, and the call to the verification function).  
4. Identify the call preceding the success/failure fork → this is `check_license` (rename accordingly).

### Strategy 2: start from `strcmp`

Libc imported functions remain in `.dynsym` even after stripping (they are needed by the dynamic linker). We can therefore always search for calls to `strcmp@plt`:

1. In Imports, locate `strcmp`.  
2. Follow the XREF → we arrive in the function that calls `strcmp` (this is `check_license`).  
3. Go up via the XREF of this function → we find `main`.

### Strategy 3: start from the entry point

If even the strings were absent or obfuscated (which is not the case here, but happens in practice):

1. Go to the entry point (`_start`, always present since it is needed by the loader).  
2. `_start` calls `__libc_start_main`, whose first argument (in `RDI`) is the address of `main`.  
3. Follow this address → we are in `main`.  
4. From there, descend through calls as before.

### Manual renaming

Once the functions are identified, rename them manually in Ghidra (right-click on the name → **Rename Function**) to restore a readable state:

```
FUN_001014e1  →  main  
FUN_001013d1  →  check_license  
FUN_00101229  →  compute_hash  
FUN_001012d8  →  derive_key  
FUN_00101358  →  format_key  
FUN_00101209  →  rotate_left  
FUN_00101460  →  read_line  
```

After this renaming, the decompiler produces pseudo-C nearly identical to that of the variant with symbols. This is the power of manual annotation: by investing a few minutes in renaming, you transform an opaque stripped binary into readable, documented code.

---

## Summary

At this point in the analysis, the verification routine is fully located and its structure understood:

| Element | Address (offset) | Role |  
|---|---|---|  
| `main` | `0x14e1` | User entry point, reads username and key, calls `check_license` |  
| `check_license` | `0x13d1` | Orchestrates hash → derivation → formatting → `strcmp` |  
| `compute_hash` | `0x1229` | Transforms username into 32-bit hash |  
| `derive_key` | `0x12d8` | Derives 4 16-bit groups from the hash |  
| `format_key` | `0x1358` | Produces the expected `XXXX-XXXX-XXXX-XXXX` string |  
| `strcmp@plt` | via PLT | Compares expected key and entered key |  
| Conditional jump (`main`) | `0x15dd` | `JZ` → failure if `check_license` returns 0 |  
| Conditional jump (`check_license`) | `0x143c` | `JNE` → return 0 if `strcmp` returns non-zero |

The two conditional jumps highlighted above are the targets of the next section (21.4), where we will analyze in detail the mechanics of `JZ`/`JNE` and their role in the fork between success and failure.

⏭️ [Understanding conditional jumps (`jz`/`jnz`) in the crackme context](/21-keygenme/04-conditional-jumps-crackme.md)
