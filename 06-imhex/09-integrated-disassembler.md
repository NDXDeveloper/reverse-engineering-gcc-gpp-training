🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.9 — Integration with ImHex's built-in disassembler

> 🎯 **Goal of this section**: Use ImHex's built-in disassembler to inspect machine code ad hoc without leaving the hex editor, understand its capabilities and limits compared to dedicated disassemblers (objdump, Ghidra, radare2), and know in which scenarios it brings real time savings.

> 📦 **Test binary**: any ELF from `binaries/` — for example `binaries/ch21-keygenme/keygenme_O0`

---

## The need: seeing instructions without changing tools

During an analysis in ImHex, you regularly encounter situations where the raw hex view does not suffice. You located an interesting opcode sequence in section 6.8 — an `E8` followed by 4 bytes, a `0F 05`, a `55 48 89 E5` prologue — and you want to verify what these bytes mean as assembly instructions. Or you explore the `.text` section at a given offset and you want to understand the code flow around that offset.

The classic solution is to switch to another tool: open a terminal and run `objdump -d`, or import the binary into Ghidra. But this context switch has a cost. You have to find the same offset in the other tool, mentally synchronize both views, and you lose visual contact with surrounding hexadecimal data. For a one-off check, it's disproportionate.

ImHex's built-in disassembler solves this problem. Without leaving the editor, without opening another program, you can disassemble a range of bytes and see the matching assembly mnemonics — directly next to the hex view.

---

## Technical architecture: Capstone under the hood

ImHex's disassembler relies on the **Capstone** library, an open-source multi-architecture disassembly framework. Capstone is a **linear sweep** disassembler: it reads bytes sequentially from a given starting point and decodes each instruction one after another, without analyzing control flow.

Capstone supports many architectures, and ImHex inherits its versatility: x86, x86-64, ARM, ARM64 (AArch64), MIPS, PowerPC, RISC-V, among others. In this training, we work exclusively in x86-64, but if you someday analyze an ARM firmware embedded in an ELF binary, ImHex's disassembler handles it natively.

---

## Accessing the disassembler

The disassembler is accessible via the **View → Disassembler** menu (the exact name may vary slightly depending on the ImHex version). A panel opens with several configuration parameters.

### Required configuration

Before launching disassembly, you must specify:

**The architecture.** Select `x86-64` (sometimes labeled `X86` with `64-bit` mode) for the ELF binaries we analyze. A wrong architecture choice produces incoherent disassembly — the bytes will be decoded as instructions from another architecture, with mnemonics that have no relation to the actual code.

**The start offset.** The address in the file from which ImHex begins decoding instructions. Typically the start of the `.text` section — you can retrieve this offset from your ELF pattern (the `sh_offset` field of the Section Header whose type is `SHT_PROGBITS` and whose flags include `execinstr`), or from `readelf -S`.

**The size (or end offset).** The number of bytes to disassemble. Specify the size of the `.text` section (the `sh_size` field of the matching Section Header) to disassemble all the code, or a smaller size if you're only interested in a specific area.

**The base address.** The virtual address corresponding to the start offset. This value matters so that addresses shown in the disassembly match the virtual addresses you see in `readelf`, Ghidra, or GDB. For `.text`, it's the `sh_addr` field of the Section Header. If you don't specify it (or leave it at 0), the addresses displayed will be relative offsets rather than virtual addresses — which remains readable, but complicates correlation with other tools.

### Launching the disassembly

Once the parameters are filled in, click the launch button (often **Disassemble** or a ▶ icon). ImHex decodes the bytes and displays the result in the panel as a listing: each line shows the address, the raw bytes of the instruction, and the assembly mnemonic with its operands.

```
0x00401040    55                  push   rbp
0x00401041    48 89 E5            mov    rbp, rsp
0x00401044    48 83 EC 20         sub    rsp, 0x20
0x00401048    89 7D EC            mov    dword [rbp-0x14], edi
0x0040104B    48 89 75 E0         mov    qword [rbp-0x20], rsi
0x0040104F    ...
```

The syntax used is **Intel** by default in Capstone — the same one we use in this training (destination operand on the left, source on the right). If you prefer AT&T syntax, a configuration option lets you switch.

---

## Navigation synchronized with the hex view

The major interest of the integrated disassembler compared to an external tool is the **bidirectional synchronization** with the hex view.

**From hex to disassembly.** When you click a byte in the hex view (provided it falls in the disassembled range), the matching instruction is highlighted in the disassembler panel. You immediately see which instruction the byte you're inspecting belongs to.

**From disassembly to hex.** Conversely, when you click an instruction in the disassembler panel, the hex view jumps to the matching bytes and selects them. You see the instruction's raw bytes highlighted in their hexadecimal context.

This synchronization is valuable in several situations:

- You found a suspicious opcode during a hex search (section 6.8). You click it in the hex view and the disassembler shows you the full instruction — is it a real `syscall`, or `0F 05` bytes that are part of an immediate in a longer instruction?  
- You read the disassembly and spot a `call` to an interesting address. You click the instruction and the hex view shows you the exact bytes — useful if you plan to patch this call.  
- You want to modify a conditional jump. The disassembler shows you the `jz` (opcode `74 XX`) or `jnz` (opcode `75 XX`) instruction. You click on it, the hex view selects the opcode, and you can modify it in place.

---

## Practical use cases

### Verifying an opcode-search result

In section 6.8, we searched for the `0F 05` motif to locate `syscall`s. Suppose the search returns three hits. For each hit:

1. Click the result in the hex view.  
2. The disassembler highlights the matching instruction.  
3. If the instruction shown is indeed `syscall`, it's a real hit.  
4. If the disassembler shows another instruction whose bytes contain `0F 05` as part of an operand, it's a false positive.

This verification process takes a few seconds per hit — much faster than opening `objdump` and looking up the offset manually.

### Inspecting code around a referenced string

You found the string `"Access denied"` in `.rodata` via the string search. You want to know which code references it. The approach:

1. Note the virtual address of the string (visible in your ELF pattern or via `readelf`).  
2. Search for this address in the hex view of `.text`: a `lea` (`48 8D 05 ...` or `48 8D 3D ...`) followed by the relative offset to the string.  
3. Click the result and the disassembler shows you the `lea rdi, [rip+0x...]` instruction — loading the string's address as first argument of a `call` (probably `printf` or `puts`).

This technique is a shortcut for **cross-references** (XREF) we'll see in Ghidra in Chapter 8. It's less systematic (you search the address manually) but requires no import into an external tool.

### Preparing a binary patch

You know, thanks to dynamic analysis with GDB (Chapter 11) or reading the disassembly in Ghidra (Chapter 8), that a `jz` (jump if zero) instruction at a certain offset conditions the acceptance or rejection of a serial. You want to patch it to `jnz` (jump if not zero).

1. Navigate to the offset in the hex view.  
2. The disassembler confirms it is indeed a `jz` — opcode `74` followed by a 1-byte relative displacement.  
3. Modify the `74` byte directly to `75` in the hex view.  
4. The disassembler updates and now displays `jnz` — visual confirmation that the patch is correct.  
5. Save the modified file.

This patching workflow in ImHex will be detailed in Chapter 21. The built-in disassembler is what makes the operation safe: you see the instruction before and after the modification, without leaving the editor.

---

## Limits of the built-in disassembler

ImHex's disassembler is a **spot-check** tool, not a full analysis tool. Understanding its limits is essential not to ask it for what it cannot provide.

### Linear, not recursive, disassembly

Capstone uses a **linear sweep** algorithm: it decodes bytes sequentially from the starting point, instruction after instruction. It does not follow jumps, does not resolve calls, and cannot distinguish code from data embedded in `.text` (jump tables, literal constants inserted by the compiler).

Consequence: if a data zone sits in the middle of `.text` (which happens with GCC when it inserts literal pools or address tables for `switch`es), the disassembler will interpret them as instructions — producing absurd mnemonics. Ghidra, IDA, and radare2 use **recursive** (recursive descent) algorithms that follow control flow and avoid this pitfall. ImHex's disassembler cannot.

### No control-flow graph

ImHex does not build a CFG (Control Flow Graph). You will not see basic-block diagrams, no arrows showing branches, no coloring of loops and conditions. The result is a raw linear listing — functional to read a few instructions, but inadequate to understand the logic of a complex function.

### No symbol resolution

The disassembler displays raw addresses in operands. A `call 0x401120` does not tell you it's a call to `printf@plt` — you must make the correspondence yourself by consulting the symbol table (via `nm`, `readelf -s`, or your `.hexpat` pattern). Ghidra and IDA automatically resolve these symbols and annotate the listing.

### No decompilation

ImHex does not produce C pseudo-code. The disassembler stops at the assembly-mnemonic level. If you need to see decompiled code, Ghidra (Chapter 8) is the appropriate tool.

### No continuous dynamic update

The disassembler panel does not refresh automatically when you modify bytes in the hex view. After a patch, you must relaunch the disassembly to see the updated result. That's minor friction in a patching workflow, but worth keeping in mind.

---

## When to use ImHex's disassembler vs a dedicated tool

The following table summarizes situations where the integrated disassembler is the right choice, and those where a dedicated tool is preferable.

| Situation | ImHex | Dedicated tool |  
|---|---|---|  
| Verify that a byte found by search is indeed an opcode | ✅ Immediate, no context switch | Disproportionate |  
| Confirm the instruction before/after a patch | ✅ Synced with hex view | Possible but slower |  
| Inspect 5–10 instructions around a precise offset | ✅ Fast and sufficient | Possible but slower |  
| Understand the logic of a 50+ line function | ❌ Linear listing too limited | ✅ Ghidra/IDA with CFG |  
| Follow calls and cross-references | ❌ No symbol resolution | ✅ Ghidra/IDA/radare2 |  
| Analyze a complete binary (all functions) | ❌ Not designed for this | ✅ Dedicated disassembler |  
| Examine an ARM/MIPS/RISC-V binary | ✅ Capstone multi-arch | ✅ Also supported by dedicated ones |

The rule is simple: if you need to see **a few instructions** to verify or prepare an action in ImHex, use the built-in disassembler. If you need to **understand an algorithm**, use Ghidra or radare2.

---

## Summary

ImHex's integrated disassembler, based on Capstone, turns the bytes of the `.text` section into readable assembly instructions directly in the hex editor. Its strength lies in the bidirectional synchronization with the hex view — a click in one updates the other — which speeds up verification of search results, patch preparation, and spot inspection of code. Its limits are those of a linear disassembler without flow analysis: no CFG, no symbol resolution, no decompilation, no handling of data embedded in code. It's a proximity tool, not a substitute for the disassemblers of Chapters 7–9 — and that's precisely this positioning that makes it so useful in the daily ImHex workflow.

---


⏭️ [Applying YARA rules from ImHex (bridge to malware analysis)](/06-imhex/10-yara-rules.md)
