🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.6 — Binary Patching: Flipping a Jump Directly in the Binary (with ImHex)

> 📖 **Reminder**: using ImHex (navigation, hex editing, bookmarks, search) is covered in chapter 6. The opcodes of relevant x86-64 conditional jumps are summarized in section 21.4 and in Appendix A.

---

## Introduction

The previous sections identified the exact decision point of the keygenme: a conditional jump of a few bytes that separates the "valid key" path from the "invalid key" path. In section 21.5, we showed that this jump could be bypassed *dynamically* by modifying a register in GDB — but that modification disappeared at the end of the session.

Binary patching makes the bypass **permanent**. We directly modify the bytes of the ELF file on disk so that the program accepts *any key*, without a debugger, without a script, without conditions. It is a surgical modification: one or two bytes suffice.

This technique is a classic of RE. It does not replace understanding the algorithm (which will come with the keygen in section 21.8), but it is immediate and demonstrates the power of machine code mastery. In a professional context, patching is also used to temporarily disable verifications during security audits or to work around bugs in binaries for which the source is not available.

> ⚠️ **Legal reminder**: modifying a binary you did not author may constitute a violation of copyright or license terms (chapter 1, section 1.2). Here, we are working on a binary we compiled ourselves for educational purposes — no restrictions apply.

---

## Which jump to patch?

We identified two conditional jumps in section 21.3:

1. **In `check_license`**: a `JNE` after `strcmp` that jumps to `return 0` if the strings differ.  
2. **In `main`**: a `JZ` after `CALL check_license` that jumps to the failure path if the function returns 0.

Both are valid patch targets, but their consequences differ:

| Patch target | Effect | Advantage | Disadvantage |  
|---|---|---|---|  
| `JNE` in `check_license` | `check_license` always returns 1 | Patch localized in the verification function | If `check_license` is called elsewhere, all verifications are neutralized |  
| `JZ` in `main` | `main` always takes the success path | Does not modify `check_license` itself | Only works for this specific call in `main` |

On our keygenme, `check_license` is called only once (from `main`), so both approaches are equivalent. We will patch the `JNE` in `check_license` — it is the most natural target, as it is the branch that directly decides the verification result.

---

## Step 1 — Locate the opcode in the file

### Finding the jump offset in Ghidra

In Ghidra, navigate to the `JNE` in `check_license` (the one following the `TEST EAX, EAX` after `CALL strcmp@plt`). The Listing panel displays, for each instruction, its virtual address and machine bytes. For example:

```
0010143a    85 c0           TEST    EAX, EAX
0010143c    75 07           JNE     .return_zero
0010143e    b8 01 00 00 00  MOV     EAX, 0x1
00101443    eb 05           JMP     .epilogue
00101445    b8 00 00 00 00  MOV     EAX, 0x0       ; .return_zero
```

The instruction of interest is at virtual address `0x0010143c` and its bytes are **`75 07`**:
- `75` = opcode of `JNE` (short form, 1-byte relative displacement).  
- `07` = displacement of +7 bytes forward (from the next instruction, i.e., `0x10143e + 7 = 0x101445`, the address of `.return_zero`).

### Converting virtual address to file offset

The address displayed by Ghidra (`0x00101337`) is a virtual address in the process address space. To patch the on-disk file, we need the **file offset**. On a typical PIE binary, Ghidra uses an image base of `0x00100000`, and the `.text` section often starts at file offset `0x1000` for virtual address `0x00101000`. The calculation is:

```
file_offset = virtual_address - virtual_section_base + file_section_offset
```

These values can be obtained with `readelf`:

```bash
$ readelf -S keygenme_O0 | grep '\.text'
  [16] .text    PROGBITS    0000000000001120  00001120  0000050b  ...
```

The "Address" column (`0x1120`) is the virtual start address of `.text`, and the "Offset" column (`0x1120` as well in this case) is its file offset. On a standard PIE binary, both coincide (the file offset and the virtual address relative to the base are identical).

So the file offset of our `JNE` is:

```
0x10143c - 0x100000 = 0x143c
```

> 💡 **Shortcut**: in Ghidra, the default image base for PIE ELF binaries is `0x100000`. The file offset is simply `virtual_address - 0x100000`. Caution: this shortcut only works if you did not change the image base during import.

### Verification with `objdump`

We can confirm with `objdump` by searching for the byte pattern:

```bash
$ objdump -d -M intel keygenme_O0 | grep -A1 "call.*strcmp@plt" | head -4
    1435:   e8 d6 fc ff ff      call   1110 <strcmp@plt>
    143a:   85 c0               test   eax,eax
    143c:   75 07               jne    1445 <check_license+0x74>
```

`objdump` directly displays file offsets (for a PIE binary, addresses displayed by `objdump` correspond to section offsets). We confirm: **offset `0x143c`**, bytes **`75 07`**.

---

## Step 2 — Open the binary in ImHex

### Create a working copy

Never patch the original. Always work on a copy:

```bash
$ cp keygenme_O0 keygenme_O0_patched
```

### Open in ImHex

Launch ImHex and open `keygenme_O0_patched`. The hex editor displays the raw file content, byte by byte.

### Navigate to the offset

Use the offset navigation function:

1. **Edit → Go to...** (or shortcut `Ctrl+G`).  
2. Enter the offset `0x143c`.  
3. ImHex positions the cursor on the byte at that offset.

You should see the bytes `75 07` at this position. To confirm you are at the right place, the preceding bytes should be `85 C0` (the `TEST EAX, EAX`) and the following bytes `B8 01 00 00 00` (the `MOV EAX, 1`).

> 💡 **Contextual verification**: never rely solely on the calculated offset. Always verify the surrounding context. If the neighboring bytes do not match what Ghidra/objdump showed, a calculation error has occurred.

### Set a bookmark

Before modifying anything, mark the position:

1. Select the two bytes `75 07`.  
2. Right-click → **Add bookmark** (or via the Bookmarks panel).  
3. Name the bookmark: `JNE after strcmp — decision point`.

This bookmark will serve as a visual reference and document the modification in the ImHex project.

---

## Step 3 — Choose the patching technique

Three classic techniques allow neutralizing a conditional jump. Each has a different behavior and effect.

### Technique A — Invert the condition: `75` → `74`

Replace the `JNE` opcode (`75`) with `JZ` (`74`). The jump still exists, but its condition is inverted:

- Before: jump if strings are **different** (wrong key → failure).  
- After: jump if strings are **identical** (correct key → failure).

The result is a program that rejects correct keys and accepts wrong ones. This is paradoxical but pedagogically interesting — and in some RE scenarios, inverting a jump is exactly what you want (for example, inverting a `JZ` that leads to success into a `JNZ`).

```
Offset 0x143c: 75 → 74  
Bytes modified: 1  
```

### Technique B — NOP the jump: `75 07` → `90 90`

Replace the two bytes of the `JNE` with two `NOP`s (No Operation, opcode `90`). The jump disappears completely — execution **always** falls through sequentially to the next instruction, which is `MOV EAX, 1` (return 1, success).

- Before: conditional jump to `return 0` if wrong key.  
- After: the jump instruction no longer exists. Execution always falls into `return 1`.

```
Offset 0x143c: 75 07 → 90 90  
Bytes modified: 2  
```

This is the cleanest technique for neutralizing a jump: the behavior is predictable (always the sequential path), and the `NOP`s do not disturb the alignment of the following code.

### Technique C — Unconditional jump to success: `75` → `EB`

Replace the `JNE` opcode (`75`) with `JMP` (`EB`). The displacement (`07`) remains unchanged. The jump is now **unconditional** — it is *always* taken, regardless of flag values.

- Before: jump to `return 0` only if wrong key.  
- After: jump to `return 0` systematically → the program rejects *every* key.

Caution: this technique is a trap if you do not think about the jump target. Here, the jump leads to `.return_zero` (failure), so making it unconditional **worsens** the situation instead of solving it. Technique C is only useful when the jump target is the *success* path.

For example, if in `main` the code were:

```nasm
TEST    EAX, EAX  
JNZ     .label_success    ; jump to success if EAX ≠ 0  
```

Then replacing `JNZ` with `JMP` would always force the success path — that would be the correct application of technique C.

### Summary of the three techniques

| Technique | Modification | Result on our `JNE` | Recommended here? |  
|---|---|---|---|  
| A — Invert (`75` → `74`) | 1 byte | Accepts wrong keys, rejects correct ones | ❌ (reverse effect) |  
| B — NOP (`75 07` → `90 90`) | 2 bytes | Accepts any key (falls into `return 1`) | ✅ |  
| C — JMP (`75` → `EB`) | 1 byte | Rejects every key (unconditional jump to `return 0`) | ❌ (opposite effect) |

**Technique B** (NOP) is the right choice for our case. It is also the most common in crackme patching practice.

---

## Step 4 — Apply the patch in ImHex

### Modifying the bytes

1. The cursor is positioned at offset `0x143c` (thanks to the bookmark).  
2. In the hexadecimal panel, click on the byte `75`.  
3. Type `90` — the byte changes from `75` to `90`. ImHex highlights it in red to signal the modification.  
4. The cursor automatically advances to the next byte (`07`).  
5. Type `90` — the byte changes from `07` to `90`.

The result in the editor:

```
Before: ... 85 C0 75 07 B8 01 00 00 00 ...  
After:  ... 85 C0 90 90 B8 01 00 00 00 ...  
```

The `TEST EAX, EAX` is still there (it is harmless — it sets the flags but nothing reads them anymore). The two `NOP`s have replaced the jump, and the next instruction (`MOV EAX, 1`) is executed unconditionally.

### Save

**File → Save** (or `Ctrl+S`). ImHex writes the modifications directly to `keygenme_O0_patched`.

> 💡 **ImHex tip**: the **Diff** panel allows comparing the modified file with the original. If you have opened `keygenme_O0` and `keygenme_O0_patched` simultaneously (in two tabs), **View → Diff** highlights the modified bytes. This is an excellent way to verify that you only touched what you intended.

---

## Step 5 — Verify the patch

### Functional test

Make the patched binary executable (if necessary) and launch it:

```bash
$ chmod +x keygenme_O0_patched
$ ./keygenme_O0_patched
=== KeyGenMe v1.0 — RE Training ===

Enter username: Alice  
Enter license key (XXXX-XXXX-XXXX-XXXX): AAAA-BBBB-CCCC-DDDD  
[+] Valid license! Welcome, Alice.
```

The program accepts a completely arbitrary key. The patch works.

We can also verify that the correct key is still accepted (it should be, since the success path is now the only possible path):

```bash
$ ./keygenme_O0_patched
Enter username: Alice  
Enter license key (XXXX-XXXX-XXXX-XXXX): DCEB-0DFC-B51F-3428  
[+] Valid license! Welcome, Alice.
```

### Verification by disassembly

We confirm the patch is correct by disassembling the modified area:

```bash
$ objdump -d -M intel keygenme_O0_patched | grep -A5 "call.*strcmp@plt"
    1435:   e8 d6 fc ff ff      call   1110 <strcmp@plt>
    143a:   85 c0               test   eax,eax
    143c:   90                  nop
    143d:   90                  nop
    143e:   b8 01 00 00 00      mov    eax,0x1
    1443:   eb 05               jmp    144a
```

The two `NOP`s appear in place of the `JNE`. The `MOV EAX, 1` is now the next instruction executed after the `TEST` — exactly what we wanted.

### Global integrity verification

To ensure we did not accidentally modify other bytes:

```bash
$ cmp -l keygenme_O0 keygenme_O0_patched
  4920 165 220
  4921   7 220
```

`cmp -l` lists the bytes that differ between the two files, with their positions (in decimal) and values (in octal). Position 5181 in decimal = `0x143d` in hexadecimal... which is `0x143c` in zero-based indexing (cmp counts from 1). The values `165` (octal) = `0x75` and `220` (octal) = `0x90`. Second byte: `7` (octal) = `0x07` → `220` = `0x90`. Exactly our two modifications, and nothing else.

---

## Alternative patch: target the `JZ` in `main`

To illustrate the importance of context, let's apply a patch to the second decision point — the `JZ` in `main` that jumps to the failure path when `check_license` returns 0.

### Locate the `JZ`

In Ghidra or `objdump`, we locate the code in `main`:

```
    15d6:   e8 f6 fd ff ff      call   13d1 <check_license>
    15db:   85 c0               test   eax,eax
    15dd:   74 22               je     1601 <main+0x120>
```

The `JZ` instruction is at offset `0x15dd`, bytes `74 22`.

### Apply the NOP

We replace `74 22` by `90 90` in a new copy of the binary:

```bash
$ cp keygenme_O0 keygenme_O0_patched_main
```

In ImHex: navigate to `0x15dd`, replace `74 22` with `90 90`, save.

### Difference in behavior

This patch has the same visible effect (any key is accepted), but the mechanism is different:
- `check_license` always returns its true value (0 for a wrong key, 1 for a correct one).  
- It is `main` that ignores the result and always takes the sequential path (success).

The distinction is subtle but important on more complex binaries: if `check_license` had side effects (writing to a log file, updating an attempt counter...), the patch in `main` would leave those effects intact, while the patch in `check_license` would bypass them as well.

---

## Handling near forms (long jumps)

Our two jumps (`75 07` and `74 22`) are **short** jumps: the opcode is 1 byte and the displacement 1 signed byte, for a total of 2 bytes. This is the most frequent case in compact functions.

On longer functions, GCC may emit **near** (or long) jumps:

```nasm
0F 85 xx xx xx xx    JNE (near, rel32)    ; 6 bytes
0F 84 xx xx xx xx    JZ  (near, rel32)    ; 6 bytes
```

The displacement is 4 signed bytes (range ±2 GB). The patching technique is the same, but the number of NOPs must be adapted:

| Jump | Size | NOP patch |  
|---|---|---|  
| `75 xx` (short JNE) | 2 bytes | `90 90` |  
| `74 xx` (short JZ) | 2 bytes | `90 90` |  
| `0F 85 xx xx xx xx` (near JNE) | 6 bytes | `90 90 90 90 90 90` |  
| `0F 84 xx xx xx xx` (near JZ) | 6 bytes | `90 90 90 90 90 90` |

Alternatively, for a 6-byte near jump, you can use a multi-byte NOP. The x86-64 processor recognizes NOP sequences up to 15 bytes. For 6 bytes, a common form is `66 0F 1F 44 00 00` (a single 6-byte NOP). In practice, six `90`s work just as well — the processor simply executes them faster with a long NOP, which is negligible for our use case.

---

## Patching optimized variants

### `-O2` with `SETcc`

In section 21.4, we saw that GCC at `-O2` can replace the branch with a `SETE` instruction:

```nasm
CALL    strcmp@plt  
TEST    EAX, EAX  
SETE    AL              ; AL = 1 if ZF=1, 0 otherwise  
MOVZX   EAX, AL  
RET  
```

There is no longer a jump to invert. To patch this code, two options:

**Option 1** — Replace `SETE AL` with `MOV AL, 1`:
```
Before: 0F 94 C0    (SETE AL)  
After:  B0 01 90    (MOV AL, 1; NOP)  
```

`MOV AL, 1` encodes in 2 bytes (`B0 01`). Since `SETE AL` takes 3, we pad with a `NOP`.

**Option 2** — Replace `TEST EAX, EAX` with `XOR EAX, EAX`:
```
Before: 85 C0       (TEST EAX, EAX)  
After:  31 C0       (XOR EAX, EAX)  
```

`XOR EAX, EAX` sets `EAX` to zero and sets ZF = 1. The `SETE AL` instruction sees ZF = 1 and sets AL = 1. The result: `check_license` always returns 1, regardless of the value returned by `strcmp`.

### `-O3` with `CMOVcc`

If the compiler uses a conditional move:

```nasm
XOR     ECX, ECX  
TEST    EAX, EAX  
MOV     EAX, 0x1  
CMOVNE  EAX, ECX         ; if strcmp ≠ 0, EAX ← 0  
```

We can NOP the `CMOVNE`:
```
Before: 0F 45 C1    (CMOVNE EAX, ECX)  
After:  90 90 90    (NOP NOP NOP)  
```

Without the `CMOVNE`, `EAX` retains the value 1 loaded by the preceding `MOV` → the function always returns 1.

---

## Summary

Binary patching is the most direct demonstration of the understanding acquired during static and dynamic analysis. By modifying one or two bytes at a precise location in the file, you fundamentally alter the program's behavior.

Here is the complete workflow, applicable to any crackme:

```
1. Identify the decision point (Ghidra, section 21.3)
         ↓
2. Understand the jump direction (section 21.4)
         ↓
3. Confirm dynamically (GDB, section 21.5)
         ↓
4. Calculate the file offset (readelf + Ghidra)
         ↓
5. Locate the bytes in ImHex (Go to offset)
         ↓
6. Verify the context (neighboring bytes)
         ↓
7. Apply the patch (NOP, inversion, or replacement)
         ↓
8. Verify (functional test + disassembly + cmp)
```

The patch solves the problem permanently, but it has a fundamental limitation: it does not produce a valid key. It bypasses the verification instead of satisfying it. For any given username, the patched program will say "valid license" regardless of the entered key — but we will not know what the *real* key is.

The next two sections tackle this problem in two complementary ways: automatic solving via symbolic execution with angr (section 21.7), which finds the correct key without understanding the algorithm in detail, and writing a keygen (section 21.8), which reproduces the algorithm to generate valid keys on demand.

⏭️ [Automatic solving with angr](/21-keygenme/07-angr-solving.md)
