🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 29

## Unpack `ch29-packed`, Reconstruct the ELF and Recover the Original Logic

---

## Context

The target binary for this checkpoint is `packed_sample_upx_tampered`, the variant whose UPX signatures have been deliberately altered (section 29.1). The `upx -d` command fails on this binary with the `NotPackedException` error. The purely static approach is not sufficient: you'll need to combine the static and dynamic techniques covered in this chapter to complete the unpacking.

The reference binary `packed_sample_O0` (compiled with DWARF symbols) is available in the same directory. It should not be consulted before completing the checkpoint — it will only serve as an answer key to compare your results at the end.

> ⚠️ The entire procedure must be performed in the **sandboxed VM** configured in Chapter 26, even though the binary is a harmless educational sample.

---

## Objectives

This checkpoint validates mastery of the complete unpacking pipeline as presented in sections 29.1 through 29.4. It covers four distinct skills, each corresponding to a chapter section:

**Skill 1 — Detection (section 29.1)**
Confirm that the binary is packed, identify the packer despite altered signatures, and document the converging indicators supporting the diagnosis.

**Skill 2 — Extraction (section 29.2)**
Decompress the original code, either by restoring signatures to enable static unpacking, or by performing dynamic unpacking via memory dump with GDB.

**Skill 3 — Reconstruction (section 29.3)**
Produce a valid ELF file from the extracted data, with a correct ELF header, coherent `LOAD` segments, and ideally a section header table usable by Ghidra.

**Skill 4 — Analysis (section 29.4)**
Fully recover the program's logic from the reconstructed binary: identify functions, understand the verification algorithm, and produce the valid key.

---

## Expected deliverables

The checkpoint is considered passed when the following four deliverables are produced:

### Deliverable 1 — Detection report

A short document (plain text, Markdown, or comments in a script) containing:

- The `file` output on the target binary, with an interpretation of significant elements.  
- The number of strings returned by `strings`, compared to that of the unpacked binary if available.  
- The `checksec` output, with an explanation of the missing protections.  
- The `readelf -l` output (program headers), with identification of `RWE`-flagged segments and the `MemSiz`/`FileSiz` ratio.  
- An entropy measurement (via `binwalk -E`, ImHex, or Python script), with the observed numerical value and the reference threshold.  
- The conclusion: packer identified (altered UPX), converging indicators listed.

### Deliverable 2 — Decompressed binary

The reconstructed ELF file (`packed_sample_reconstructed` or equivalent name), which must satisfy the following criteria:

- `file` recognizes it as a valid 64-bit x86-64 ELF.  
- `readelf -h` displays a coherent entry point (OEP address).  
- `readelf -l` displays at least two `LOAD` segments with distinct permissions (`r-x` for code, `rw-` for data).  
- `readelf -S` displays at minimum the `.text` and `.rodata` sections (presence of `.data`, `.bss`, and `.shstrtab` is a bonus).  
- `strings` on the reconstructed file returns the program's characteristic strings (banner, flag, user messages).

### Deliverable 3 — Logic analysis

A document describing the program's complete logic, containing:

- The list of functions identified in Ghidra (names assigned by the student if the binary is stripped), with a one-sentence description of each function's role.  
- The pseudo-code of the license verification function, either copied from the Ghidra decompiled output (renamed and annotated) or rewritten in C by the student.  
- The checksum algorithm, described in clear terms: operation performed, weights, modulo applied.  
- The step-by-step calculation of the valid key, showing the ASCII value of each prefix character, the multiplication by weight, the sum, the modulo, and the hexadecimal conversion.  
- The description of the XOR routine: key used, encrypted message, decryption result.

### Deliverable 4 — Proof of resolution

A capture or log demonstrating that the found key works. This can take any of the following forms:

- The program output executed in the VM with the correct key entered as input, displaying the success message and flag.  
- A GDB log showing a breakpoint on the verification function, the `rdi` argument containing the key, and the return value confirming validation.  
- A Frida or pwntools script that automatically sends the key and captures the output.

---

## Validation criteria

| Criterion | Passing threshold |  
|---------|-------------------|  
| The detection report cites at least 4 converging indicators out of the 8 in the grid (section 29.1) | Required |  
| The packer is correctly identified as UPX with altered signatures | Required |  
| The reconstructed ELF file passes `readelf -h` and `readelf -l` without errors | Required |  
| Ghidra imports the reconstructed file and produces coherent disassembly (no noise on `.text`) | Required |  
| The verification function is identified and its algorithm is correctly described | Required |  
| The valid key `RE29-0337` is found and validated (proof provided) | Required |  
| The reconstructed file has an SHT with at least `.text` and `.rodata` | Recommended |  
| The XOR routine is identified and the `SUCCESS!` message is recovered | Recommended |  
| The AES S-box constants are spotted and mentioned in the report | Bonus |  
| The reconstruction script is automated (Python + LIEF or equivalent) | Bonus |

---

## Methodological guidance

Without giving the step-by-step solution (available in `solutions/ch29-checkpoint-solution.md`), here are some pointers to guide the process:

- **Systematically** start with the full triage (deliverable 1) before attempting anything else. The temptation to jump straight into GDB is strong, but the detection report is a standalone deliverable and the information collected (segment addresses, entropy, permissions) will be directly useful for subsequent steps.

- For extraction, two paths are valid: restoring magic bytes followed by `upx -d` (static approach) or memory dump via GDB (dynamic approach). Both approaches are accepted. The dynamic approach is more educational since it works on any packer, but the static approach is perfectly legitimate here since the packer is identified.

- For reconstruction, the Python script with LIEF presented in section 29.3 is a solid starting point. Adapting it to the specific addresses observed in GDB is sufficient. Manual reconstruction in ImHex is also accepted but more prone to offset calculation errors.

- For analysis in Ghidra, the most effective strategy is to start from the strings: open the **Defined Strings** view, spot user messages, then trace back to the functions referencing them via cross-references (XREF). This leads directly to `main`, from which you descend into called functions.

- The license key can be found via two independent paths: through **static analysis** (reading the decompiled output and computing the checksum by hand or with a script) or through **dynamic analysis** (setting a breakpoint on the comparison and observing the expected value in a register). Both approaches are accepted; ideally, do both and verify the results match.

---

## Skills mobilized

This checkpoint synthesizes the following skills, acquired throughout the training:

| Skill | Reference chapters |  
|------------|----------------------|  
| Quick triage of an unknown binary | 5 (section 5.7) |  
| Reading ELF headers and sections | 2 (sections 2.3–2.4), 5 (section 5.2) |  
| Entropy analysis and signature searching | 6 (sections 6.8–6.10), 29 (section 29.1) |  
| Debugging with GDB (hardware breakpoints, memory dump) | 11 (sections 11.2–11.5), 12, 29 (section 29.2) |  
| Manipulating ELF structures with LIEF / ImHex | 6 (section 6.4), 35 (section 35.1), 29 (section 29.3) |  
| Disassembly and decompilation with Ghidra | 8 (sections 8.2–8.7) |  
| Identifying crypto patterns | 24 (section 24.1), Appendix J |  
| Dynamic instrumentation with Frida | 13 (sections 13.3–13.5) |

---

> 📌 **Reminder** — The complete solution can be found in `solutions/ch29-checkpoint-solution.md`. Consult it only after producing your own deliverables. Comparing your approach to the solution is often more instructive than the final result itself: there is rarely a single correct path in reverse engineering.

⏭️ [Part VII — Bonus: RE on .NET / C# Binaries](/part-7-dotnet.md)
