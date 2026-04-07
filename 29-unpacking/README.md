🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 29 — Packing Detection, Unpacking and Reconstruction

> 📦 **Objective** — Learn how to recognize a packed ELF binary, decompress it (statically or dynamically), then reconstruct an executable that can be analyzed by standard RE tools (Ghidra, objdump, radare2...).

---

## Why this chapter?

Up to this point in the training, the analyzed binaries were either provided as-is, or protected by mechanisms that could be bypassed directly: symbol stripping, control flow obfuscation, debugger detection. **Packing** represents an obstacle of a different nature: the binary you open in your disassembler is not the "real" program. The original code is compressed — sometimes encrypted — inside the file, and a small decompression stub takes care of restoring it in memory at runtime. Until you recover this decompressed code, any static analysis attempt is doomed to fail: Ghidra displays noise, `strings` returns almost nothing useful, and the control flow graph doesn't resemble anything coherent.

Packing is ubiquitous in malicious code analysis. The vast majority of ELF malware distributed in the wild uses at minimum UPX, and more sophisticated samples embed custom decompression routines, sometimes chained in multiple layers. Knowing how to detect and undo these protections is therefore an essential skill for anyone wanting to go beyond reversing "cooperative" binaries.

This chapter bridges the gap between the anti-reversing techniques seen in Chapter 19 (where we studied packing from the defender's perspective) and the malware analysis of Chapters 27–28 (where the binaries encountered are actively protected). We'll combine already-mastered tools — `checksec`, ImHex, GDB, `readelf` — with new concepts: entropy analysis, memory dumping of a running process, and manual reconstruction of a functional ELF.

---

## What is packing, concretely?

A **packer** is a tool that transforms an executable into a new executable containing a compressed (or encrypted) version of the original code, preceded by a **decompression stub**. At launch, the stub executes first: it decompresses the original code into memory, adjusts relocations and imports if necessary, then transfers control to the program's real entry point. From the end user's perspective, the behavior is identical; from the analyst's perspective, the file on disk contains only the stub and a mass of unreadable compressed data.

Packing serves two distinct motivations. The first is **size reduction**: this is the historical purpose of UPX (Ultimate Packer for eXecutables), created at a time when bandwidth and disk space were precious resources. The second is **analysis evasion**: by hiding the real code behind a compression or encryption layer, the packer prevents direct extraction of strings, YARA signatures, and any other static indicator. It is this second motivation that dominates today in the malware analysis context.

It is important to distinguish packing from other forms of protection. **Stripping** removes symbols but leaves the machine code intact and analyzable. **Control flow obfuscation** makes code harder to read, but it remains visible in the disassembler. Packing, on the other hand, makes the code purely and simply **absent** from the file on disk — it exists in executable form only in memory, during execution. This is why the decompression approach often relies on a combination of static analysis (to understand the stub) and dynamic analysis (to capture the code once decompressed).

---

## Overview of packers we'll encounter

The most common packer for ELF binaries remains **UPX**. Its format is well documented, it leaves recognizable signatures (`UPX!` in section headers, characteristic section names like `UPX0` / `UPX1`), and it provides its own decompression option (`upx -d`). This is the "easy" case — but it's also the essential starting point for understanding the general mechanism.

Beyond UPX, there are packers that deliberately modify UPX headers to prevent automatic decompression, open source packers like **Ezuri** (specifically designed for ELF binaries, widespread in IoT botnets), and **custom packers** hand-written by malware authors. The latter are the most difficult to handle: no automated tool recognizes them, and unpacking requires a thorough understanding of the decompression stub.

In this chapter, we'll primarily work with the binaries in the `ch29-packed/` directory provided in the repository, which use UPX initially, then a modified variant that resists `upx -d`, forcing a dynamic approach.

---

## General unpacking strategy

Regardless of the packer encountered, the approach follows a four-step pattern that we'll detail in the following sections:

**Step 1 — Detection.** Before attempting anything, you need to confirm that the binary is packed and, if possible, identify the packer used. We'll rely on several converging indicators: entropy analysis (a packed binary exhibits entropy close to 8.0 on compressed data sections), signatures in headers and section names, the ratio between on-disk size and in-memory segment size, and the behavior of `checksec` / `readelf`.

**Step 2 — Unpacking.** Two approaches are possible. **Static unpacking** consists of using the packer's own tool (like `upx -d`) or writing a script that reproduces the decompression algorithm. **Dynamic unpacking** consists of letting the stub do its work, then capturing the process's memory state once the code is decompressed — typically by setting a breakpoint just after control transfer to the original code, then dumping the relevant segments with GDB.

**Step 3 — Reconstruction.** The raw memory dump is not directly a valid ELF file. You need to reconstruct the ELF headers (or fix them), restore the sections, fix the entry point, and ensure that dynamic imports are correctly referenced. This step is often the most delicate, especially with custom packers.

**Step 4 — Reanalysis.** Once the ELF is reconstructed, you can finally import it into Ghidra, run `strings` on it, apply YARA rules, and proceed with classical analysis as done in previous chapters.

---

## Prerequisites for this chapter

This chapter draws on skills and tools covered in several earlier chapters. Make sure you're comfortable with the following before proceeding:

- **ELF file structure** — headers, sections, segments, entry point (Chapter 2, sections 2.3–2.4).  
- **`readelf`, `objdump`, `checksec`, `file`, `strings`** — the quick triage workflow (Chapter 5).  
- **ImHex** — hex navigation, `.hexpat` patterns, magic byte analysis (Chapter 6).  
- **GDB with GEF or pwndbg** — setting breakpoints, memory inspection, `vmmap` and `dump memory` commands (Chapters 11–12).  
- **Anti-reversing concepts** — stripping, UPX packing, binary protections (Chapter 19, sections 19.1–19.2).

The training binary `ch29-packed/` can be compiled via `make` in the `binaries/ch29-packed/` directory. The `Makefile` produces several variants: a version packed with standard UPX, a version with altered UPX headers, and the original unpacked binary (for verification).

---

## Chapter outline

- **29.1** — Identifying UPX and custom packers with `checksec` + ImHex + entropy  
- **29.2** — Static unpacking (UPX) and dynamic unpacking (memory dump with GDB)  
- **29.3** — Reconstructing the original ELF: fixing headers, sections and entry point  
- **29.4** — Reanalyzing the unpacked binary  
- **🎯 Checkpoint** — Unpack `ch29-packed`, reconstruct the ELF and recover the original logic

---

> ⚠️ **Security reminder** — As with all Part VI binaries, work exclusively in your sandboxed VM (Chapter 26). Even though the samples in this training are educational and harmless, systematically adopting proper isolation practices is an essential habit. Never take the shortcut of running a packed binary directly on your host machine.

⏭️ [Identifying UPX and custom packers with `checksec` + ImHex + entropy](/29-unpacking/01-identifying-packers.md)
