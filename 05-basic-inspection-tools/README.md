🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 5 — Basic binary inspection tools

> **Part II — Static Analysis**

---

## Chapter goal

Before opening a disassembler or a decompiler, the experienced reverse engineer always starts with a **quick triage** phase. This step, often overlooked by beginners, answers fundamental questions about an unknown binary in just a few minutes: what type of file is it? For which architecture was it compiled? Which libraries does it use? Which system calls does it make? Which protections are in place?

This chapter presents the command-line tools that form the **first-contact toolbox** of any analyst. These tools are lightweight, fast, available on virtually every Linux distribution, and need no graphical interface. They form the foundation on which all the deeper analyses of later chapters rest.

The goal is not only to know these tools individually, but to learn how to **chain them methodically** in order to build a mental picture of the binary before reading a single line of assembly.

---

## What you will learn

- Instantly identify the type, architecture, and format of a binary with `file`.  
- Extract readable strings from a binary to get clues about its behavior (`strings`).  
- Inspect the raw content of a file byte by byte with `xxd` and `hexdump`.  
- Dissect the internal structure of an ELF — headers, sections, segments — with `readelf` and `objdump`.  
- Explore the symbol tables to recover function and variable names with `nm`.  
- List a binary's dynamic dependencies with `ldd` and understand the resolution mechanism with `ldconfig`.  
- Observe a binary's runtime behavior without modifying it thanks to `strace` (system calls) and `ltrace` (library calls).  
- Inventory the security protections applied to a binary with `checksec`.  
- Assemble all these tools into a reproducible **quick triage workflow**: the first-5-minutes routine when facing an unknown binary.

---

## Prerequisites

This chapter builds on the notions introduced in the previous chapters:

- **Chapter 2** — The GNU compilation chain: you must understand what an ELF file is, know the main sections (`.text`, `.data`, `.rodata`, `.bss`, `.plt`, `.got`), and know what symbols and dynamic linking are.  
- **Chapter 3** — x86-64 assembly basics: a minimal familiarity with registers and basic instructions will help you interpret some `objdump` outputs, even though in-depth disassembly is covered in chapters 7 and 8.  
- **Chapter 4** — Work environment: all the tools in this chapter must be installed and functional. If you ran `check_env.sh` successfully, you are ready.

---

## Chapter outline

- **5.1** — `file`, `strings`, `xxd` / `hexdump` — first contact with an unknown binary  
- **5.2** — `readelf` and `objdump` — anatomy of an ELF (headers, sections, segments)  
- **5.3** — `nm` and `objdump -t` — inspecting symbol tables  
- **5.4** — `ldd` and `ldconfig` — dynamic dependencies and resolution  
- **5.5** — `strace` / `ltrace` — system calls and library calls (syscall vs libc)  
- **5.6** — `checksec` — binary protection inventory (ASLR, PIE, NX, canary, RELRO)  
- **5.7** — Quick triage workflow: the first-5-minutes routine when facing a binary

---

## Binaries used in this chapter

All training binaries are in the `binaries/` directory at the repository root. For this chapter, you will primarily work with:

| Binary | Description | Source |  
|---|---|---|  
| `ch05-keygenme/keygenme_O0` | Crackme compiled without optimization, with symbols | `make` in `binaries/ch05-keygenme/` |  
| `ch05-keygenme/keygenme_O2_strip` | Same crackme, optimized and stripped | idem |  
| `mystery_bin` | Unknown binary provided for the checkpoint | `binaries/ch05-mystery_bin/` |

If you have not compiled them yet, run from the repository root:

```bash
cd binaries && make all
```

---

## Teaching approach

Each section of this chapter follows the same structure:

1. **Tool overview** — what it is for and in which context to use it.  
2. **Essential options** — the most useful flags for RE, without aiming for exhaustiveness (the `man` pages are there for that).  
3. **Demonstration on a concrete binary** — each command is run on one of the training binaries, with the output commented.  
4. **Takeaways for the rest of the training** — the information to note and its use in the overall analysis workflow.

> 💡 **Practical advice**: keep a terminal open alongside your reading and reproduce every command. RE is a discipline you learn by doing — reading without hands-on work is not enough.

---

## Conventions

- Commands to run in a terminal are shown in code blocks preceded by the `$` prompt.  
- Truncated outputs are indicated by `[...]`.  
- Important items in the outputs are flagged with `# ← explanation` comments.

---


⏭️ [`file`, `strings`, `xxd` / `hexdump` — first contact with an unknown binary](/05-basic-inspection-tools/01-file-strings-xxd.md)
