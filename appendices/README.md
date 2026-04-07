🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendices

> 📎 **Quick references and summary tables** — keep them at hand throughout the training and beyond.

---

## Why appendices?

Throughout this training, you have manipulated registers, typed GDB commands, written ImHex patterns, read ELF sections, and searched for cryptographic constants in hex dumps. Each of these activities relies on a set of factual references — opcodes, conventions, syntaxes, signatures — that it is neither realistic nor desirable to memorize entirely.

These appendices centralize all these references in a single location. They are not designed to be read linearly but to be **consulted on demand**, like a reference manual placed next to your terminal. Print them, pin them in your note editor, or keep them open in a permanent tab: that is their purpose.

---

## Appendix organization

The appendices are grouped by functional domain. Each one is self-contained and can be consulted independently of the others.

### x86-64 architecture and assembly

- **Appendix A** — Quick reference of frequent x86-64 opcodes in RE  
- **Appendix B** — System V AMD64 ABI calling conventions (summary table)  
- **Appendix I** — Recognizable GCC patterns in assembly (compiler idioms)

Appendix A provides the instruction table you will encounter in the vast majority of binaries. Appendix B details the calling convention that governs parameter passing, register preservation, and stack usage on Linux x86-64. Appendix I complements these first two by cataloging the characteristic instruction sequences that GCC produces for common C/C++ constructs: constant division via magic multiplication, switch-case transformed into jump tables, comparison idioms, etc. These three appendices form a cohesive block for anyone reading disassembly on a daily basis.

### RE tools — Cheat sheets

- **Appendix C** — GDB / GEF / pwndbg cheat sheet  
- **Appendix D** — Radare2 / Cutter cheat sheet  
- **Appendix E** — ImHex cheat sheet: `.hexpat` syntax reference

These three sheets condense the essential commands and shortcuts of the tools you have used throughout Parts II, III, and V. They follow a uniform format: command, short description, usage example. Appendix C covers native GDB as well as commands added by the GEF and pwndbg extensions. Appendix D focuses on `r2` console commands and their equivalent in the Cutter graphical interface. Appendix E documents the syntax of ImHex's `.hexpat` pattern language, with base types, attributes, conditional structures, and built-in functions.

### ELF format

- **Appendix F** — ELF sections table and their roles

This appendix lists all the ELF sections you may encounter in a binary produced by GCC or G++, with for each one its name, type, flags, typical content, and the context in which it is relevant during reverse engineering. It directly complements chapter 2 (section 2.4) and serves as a permanent reference for static analysis chapters.

### Tool comparisons

- **Appendix G** — Native tools comparison (tool / usage / free / CLI or GUI)  
- **Appendix H** — .NET tools comparison (ILSpy / dnSpy / dotPeek / de4dot)

Appendix G synthesizes in table form all the tools presented in the training for native binary reverse engineering (ELF x86-64), indicating for each whether it is free, whether it works from the command line or via a graphical interface, and in which chapters it is covered. Appendix H does the same for the .NET ecosystem covered in Part VII, comparing decompilers and patching tools on criteria of features, maintenance, and use cases.

### Cryptography and detection

- **Appendix J** — Common crypto magic constants (AES, SHA, MD5, RC4...)

This appendix gathers the characteristic hexadecimal values of the most widespread cryptographic algorithms. When you encounter a suspicious sequence in `.rodata` or in a memory dump, this table allows you to identify it quickly. It is particularly useful in the context of chapters 24 (crypto reverse) and 27 (ransomware analysis).

### Glossary

- **Appendix K** — Reverse Engineering Glossary

The glossary defines the technical terms used throughout the training, from basic vocabulary (ELF, section, segment) to advanced concepts (RTTI, lazy binding, control flow flattening). Each entry refers to the chapter where the concept is first introduced.

---

## How to use these appendices effectively

The most productive way to leverage these appendices depends on your work context.

**During the training** — consult the corresponding appendix each time a chapter references a convention, opcode, or command you have not yet mastered. References are indicated in the chapter body by the mention *(see Appendix X)*.

**During a CTF or real analysis** — keep appendices A, B, C, and I open at all times. These are the four references you will consult most often when facing unknown disassembly and needing to move fast.

**To identify a crypto algorithm** — start by searching for the first bytes of the suspicious sequence in Appendix J. If you get a match, you immediately know which algorithm is involved and can orient your analysis accordingly.

**To choose a tool** — appendices G and H allow you to compare available options according to your constraints (budget, operating system, CLI/GUI preference) without having to reread the presentation chapters.

---

## Appendix table

| Appendix | Title | Domain |  
|--------|-------|---------|  
| **A** | [Quick reference of frequent x86-64 opcodes in RE](/appendices/appendix-a-opcodes-x86-64.md) | x86-64 architecture |  
| **B** | [System V AMD64 ABI calling conventions](/appendices/appendix-b-system-v-abi.md) | x86-64 architecture |  
| **C** | [GDB / GEF / pwndbg cheat sheet](/appendices/appendix-c-cheatsheet-gdb.md) | Tools — Debugging |  
| **D** | [Radare2 / Cutter cheat sheet](/appendices/appendix-d-cheatsheet-radare2.md) | Tools — Disassembly |  
| **E** | [ImHex cheat sheet: `.hexpat` syntax](/appendices/appendix-e-cheatsheet-imhex.md) | Tools — Hex editing |  
| **F** | [ELF sections table and their roles](/appendices/appendix-f-elf-sections.md) | ELF format |  
| **G** | [Native tools comparison](/appendices/appendix-g-native-tools-comparison.md) | Comparisons |  
| **H** | [.NET tools comparison](/appendices/appendix-h-dotnet-tools-comparison.md) | Comparisons |  
| **I** | [Recognizable GCC patterns in assembly](/appendices/appendix-i-gcc-patterns.md) | x86-64 architecture |  
| **J** | [Common crypto magic constants](/appendices/appendix-j-crypto-constants.md) | Cryptography |  
| **K** | [Reverse Engineering Glossary](/appendices/appendix-k-glossary.md) | General reference |

---

> Access the appendix you need directly via the links above, or start with **Appendix A — Quick reference of frequent x86-64 opcodes** for a sequential reading.

⏭️ [Quick reference of frequent x86-64 opcodes in RE](/appendices/appendix-a-opcodes-x86-64.md)
