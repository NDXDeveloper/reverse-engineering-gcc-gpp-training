🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part I — Fundamentals & Environment

Before launching Ghidra, setting a breakpoint in GDB, or hooking a function with Frida, you need to master what happens **between your source code and the binary running in memory**. This first part lays the foundations without which any analysis — static or dynamic — boils down to blindly navigating a stream of bytes. You will learn what an ELF binary really is, how the compiler transforms your C/C++ into machine instructions, and how to read those instructions without panicking.

---

## 🎯 Objectives of this part

By the end of these four chapters, you will be able to:

1. **Define the scope of Reverse Engineering** and clearly distinguish static from dynamic analysis, while knowing the applicable legal framework (CFAA, EUCD, DMCA).  
2. **Describe each step of the GNU compilation chain** — from the preprocessor to the linker — and explain the impact of the flags (`-O0` to `-O3`, `-g`, `-s`, `-fPIC`, `-pie`) on the produced binary.  
3. **Read and interpret an x86-64 assembly listing**: identify registers, common instructions, function prologue/epilogue, the System V AMD64 calling convention, and apply a structured 5-step method to annotate an unknown disassembly.  
4. **Navigate the structure of an ELF binary**: locate key sections (`.text`, `.data`, `.rodata`, `.plt`, `.got`), understand the role of the `ld.so` loader, and explain the PLT/GOT mechanism for dynamic resolution.  
5. **Have an operational work environment**: isolated VM, tools installed and verified, training binaries compiled and ready for analysis.  
6. **Compile the same program at different optimization levels** and concretely observe the differences in size, sections, and disassembly using `readelf` and `objdump`.

---

## 📋 Chapters

| # | Title | Description | Link |  
|----|-------|-------------|------|  
| 1 | Introduction to Reverse Engineering | Definition and objectives of RE, legal and ethical framework (CFAA, EUCD/DMCA, directive 2009/24/EC), legitimate use cases (auditing, CTF, interoperability, malware), static vs dynamic distinction, methodology and tools, target taxonomy. | [Chapter 1](/01-introduction-re/README.md) |  
| 2 | The GNU Compilation Chain | GCC architecture (4 phases), intermediate files (`.i`, `.s`, `.o`), binary formats (ELF, PE, Mach-O), key ELF sections, compilation flags (`-O0`→`-O3`, `-g`, `-s`, `-pie`), DWARF symbols, `ld.so` loader, segments and ASLR, PLT/GOT resolution (lazy binding). | [Chapter 2](/02-gnu-compilation-chain/README.md) |  
| 3 | x86-64 Assembly Basics for RE | Registers (general, `rsp`, `rbp`, `rip`, `RFLAGS`), essential instructions (`mov`, `lea`, `push`/`pop`, `call`/`ret`), arithmetic and logic, conditional jumps (signed vs unsigned), stack and System V AMD64 calling conventions, parameter passing (`rdi`→`r9`), 5-step reading method, `call@plt` vs `syscall`, SIMD introduction (SSE/AVX). | [Chapter 3](/03-x86-64-assembly/README.md) |  
| 4 | Setting Up the Work Environment | Linux distribution (Ubuntu LTS/Debian/Kali), tool installation in 5 waves (base, CLI, disassemblers, frameworks, complementary), sandboxed VM (VirtualBox/QEMU/UTM), network configuration (NAT/host-only/isolated), repository structure, compilation of binaries (`make all`), verification with `check_env.sh`. | [Chapter 4](/04-work-environment/README.md) |

---

## ⏱️ Estimated duration

**~10-15 hours** for a developer with intermediate C/C++ practice and a basic familiarity with the Linux terminal.

Chapter 2 (compilation chain, ELF, PLT/GOT) and Chapter 3 (x86-64 assembly) account for most of the learning time. If you are already comfortable with assembly, you can skim Chapter 3 and focus on the reading method (section 3.7) and the calling conventions (sections 3.5-3.6). Chapter 4 is essentially hands-on: count 1 to 2 hours to set up the VM and verify the installation.

---

## 📌 Prerequisites

- **Intermediate C/C++** — You can write, compile, and debug a program of a few hundred lines. You understand pointers, memory allocation (`malloc`/`free`), structures, and the basics of separate compilation.  
- **Linux terminal** — You are comfortable with filesystem navigation, file editing, using `make`, and common command-line operations (`grep`, `find`, pipes, redirections).  
- **Memory notions** — You have a general idea of what the stack, heap, and process address space are. No need to master the details: that is precisely what this part will consolidate.  
- **Virtualization** — You know how to install and launch a virtual machine (VirtualBox, QEMU, or UTM). The detailed configuration is covered in Chapter 4.

> 💡 If one of these points feels unclear, it is not blocking — chapters 2 and 3 cover these notions in depth. On the other hand, a minimum of practice in C and the Linux terminal is necessary to follow the exercises.

---

## ➡️ Next part

Once your environment is set up and the fundamentals are absorbed, you will move on to static analysis tools: binary inspection, disassembly with `objdump` and Ghidra, hexadecimal analysis with ImHex, and binary diffing.

→ [**Part II — Static Analysis**](/part-2-static-analysis.md)

⏭️ [Chapter 1 — Introduction to Reverse Engineering](/01-introduction-re/README.md)
