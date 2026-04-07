🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 6 — ImHex: advanced hexadecimal analysis

> 📦 **Binaries used in this chapter**: `binaries/ch06-fileformat/`, as well as ELFs generated in earlier chapters.  
> 📁 **ImHex patterns**: `hexpat/elf_header.hexpat`, `hexpat/ch06_fileformat.hexpat`  
> 🧰 **Required tool**: [ImHex](https://imhex.werwolv.net/) (open source, cross-platform)

---

## Why this chapter?

In Chapter 5 we laid down the basics of binary triage with command-line tools: `file`, `strings`, `xxd`, `readelf`, `objdump`. These utilities are essential, but they share a common limit — they remain **textual**. Facing an unknown file format, a C structure buried inside a binary blob, or an ELF header you want to dissect byte by byte, a terminal is no longer enough. You need to **see** the data, to **colorize** it, to **annotate** it, and above all to **parse it structurally** without writing a dedicated program.

That is precisely the role of an advanced hex editor. And among the tools available today, **ImHex** has established itself as the open source reference in the reverse engineering community. Developed by WerWolv, it goes well beyond displaying bytes in columns: its `.hexpat` pattern language, its built-in data inspector, its diff capability, its YARA support, and its embedded disassembler make it a true **visual binary analysis environment**.

This chapter is deliberately the longest in Part II, because ImHex will be a cross-cutting tool that we will use in almost every practical case to come — from binary patching (Chapter 21) to network protocol analysis (Chapter 23), and through file-format reversing (Chapter 25) and malware analysis (Chapters 27–29).

---

## What you will learn

By the end of this chapter, you will be able to:

- Explain what sets ImHex apart from classic hex editors and in which RE contexts it brings real added value.  
- Navigate ImHex's interface efficiently: Pattern Editor, Data Inspector, Bookmarks, Diff view.  
- Write `.hexpat` patterns to automatically parse and visualize binary structures — from primitive types to nested structures with pointers and dynamic arrays.  
- Build a complete pattern for the ELF header, from scratch, to understand the format in depth.  
- Parse custom C/C++ structures directly in a binary, without having the source code.  
- Colorize, annotate, and bookmark regions of a binary file to document an ongoing analysis.  
- Compare two versions of the same GCC-compiled binary using the built-in Diff view.  
- Search for magic bytes, encoded strings, and specific opcode sequences in a file.  
- Use ImHex's built-in disassembler to inspect machine code without leaving the editor.  
- Apply YARA rules directly from ImHex, bridging to malware analysis techniques.  
- Carry out a full practical case: mapping a proprietary file format by combining all the features seen.

---

## Prerequisites for this chapter

- **Chapter 2** — You must understand the structure of an ELF file (sections, segments, headers) to follow the construction of the ELF pattern in section 6.4.  
- **Chapter 3** — Basic x86-64 assembly notions will be useful for section 6.9 on the built-in disassembler.  
- **Chapter 4** — ImHex must be installed in your work environment. If it is not, refer to section 4.2.  
- **Chapter 5** — The quick triage workflow from 5.7 will be our starting point before diving into ImHex.

Familiarity with C syntax (types, `struct`, pointers) is necessary to write `.hexpat` patterns, whose syntax is directly inspired by it.

---

## Chapter outline

- **6.1** — Why ImHex goes beyond a simple hex editor  
- **6.2** — Installation and interface tour (Pattern Editor, Data Inspector, Bookmarks, Diff)  
- **6.3** — The `.hexpat` pattern language — syntax and base types  
- **6.4** — Writing a pattern to visualize an ELF header from scratch  
- **6.5** — Parsing a homemade C/C++ structure directly in the binary  
- **6.6** — Colorization, annotations, and bookmarks of binary regions  
- **6.7** — Comparing two versions of the same GCC binary (diff)  
- **6.8** — Searching for magic bytes, encoded strings, and opcode sequences  
- **6.9** — Integration with ImHex's built-in disassembler  
- **6.10** — Applying YARA rules from ImHex (bridge to malware analysis)  
- **6.11** — Practical case: mapping a custom file format with `.hexpat`  
- **🎯 Checkpoint** — Write a complete `.hexpat` for the `ch23-fileformat` format

---

## The chapter's running thread

The chapter follows a three-stage progression. We start by discovering the tool and its interface (sections 6.1–6.2), then dive into the heart of ImHex — the `.hexpat` language — by building patterns of increasing complexity (sections 6.3–6.5). Finally, we explore the complementary features that make ImHex a daily companion of the reverse engineer: diff, search, disassembly, and YARA (sections 6.6–6.10). The chapter ends with an integrative practical case (section 6.11) and a checkpoint that exercises all the skills acquired.

Throughout the chapter, we will work on ELF binaries you already compiled in earlier chapters, as well as on the `ch25-fileformat` binary that uses a proprietary file format. The `.hexpat` patterns we will write together will be reusable in later chapters — keep them in your repository's `hexpat/` folder.

> 💡 **Tip**: Keep ImHex open permanently during your RE sessions. Even when you work mainly in Ghidra or GDB, being able to switch quickly to a structured hex view is a reflex that will save you considerable time.

⏭️ [Why ImHex goes beyond a simple hex editor](/06-imhex/01-why-imhex.md)
