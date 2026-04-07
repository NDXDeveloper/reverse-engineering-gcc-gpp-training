🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 1.1 — Definition and objectives of Reverse Engineering

> **Chapter 1 — Introduction to Reverse Engineering**  
> 📦 No technical prerequisites — reading section.

---

## What is reverse engineering?

The term **reverse engineering** (often abbreviated **RE**) refers to the process of analyzing a finished system — a product, a mechanism, a piece of software — to understand its internal workings, without access to its design documentation or its original plans.

The idea is not specific to computing. Reverse engineering has existed for as long as engineering itself. A watchmaker who disassembles a competitor's mechanism to understand its escapement is doing reverse engineering. A chemist who analyzes the composition of a material to rediscover its formula is doing reverse engineering. The principle is always the same: start from the observable result and work back toward the design logic.

In computing, and more specifically in the context of this training, reverse engineering refers to the analysis of a **compiled binary** — an executable file produced by a compiler like GCC — with the goal of understanding what the program does, how it does it, and sometimes why it does it in a certain way, all **without access to the original source code**.

### The loss of information at the core of the problem

To understand why RE is a discipline in its own right, one must grasp a fundamental point: **compilation is a one-way process that destroys information**.

When you compile a `main.c` file with GCC, the compiler transforms human-readable source code into a sequence of machine instructions readable by a processor. Along the way, a great deal of information disappears:

- **Local variable names** no longer exist. What was `int counter` in the source becomes an operation on a register or a position on the stack, without any label.  
- **Function names** may be removed if the binary is stripped (GCC's `-s` option). Even when they are kept, `static` functions and inlined functions disappear from the final binary.  
- **Comments** are eliminated as early as the preprocessing phase — they never even reach the compiler.  
- **Data types** are not preserved as such in machine code. An `int`, an `unsigned int`, and a pointer all occupy 4 or 8 bytes — the processor does not tell them apart.  
- The **code structure** (`for`, `while`, `switch/case` loops, `if/else` conditions) is transformed into sequences of comparisons and jumps. A 5-case `switch` can become a jump table, a cascade of `cmp`/`jmp`, or a binary decision tree — depending on the optimization level.  
- The **control flow** itself can be deeply reorganized by the compiler's optimization passes (inlining, loop unrolling, basic block reordering, dead code elimination).

The reverse engineer therefore works with impoverished material. Their job consists of **reconstructing meaning** from what remains: the machine instructions, the in-memory data, the strings, the numerical constants, the system calls, and the structure of the binary itself.

It is this reconstruction — sometimes called "abstraction recovery" — that makes up all of the difficulty and all of the interest of RE.

### Software RE vs debugging: an important distinction

Reverse engineering is sometimes confused with debugging, and the two activities do share tools (GDB, for example, is central to both). But their goals and contexts differ fundamentally:

**Debugging** starts from a program whose source code you possess. You are trying to locate a specific bug: an incorrect value, an invalid memory access, an unexpected behavior. The source code is the reference — the debugger simply helps observe the execution to confirm or refute a hypothesis.

**Reverse engineering** starts from a binary whose source code you do **not** possess (or cannot use directly). The goal is not to fix a known bug, but to **understand the overall logic** of the program: what does it do? How does it process its inputs? What protocol does it use? What verification routine does it apply? Where does it store its encryption keys?

In short: debugging is a verification activity (you know what the program should do, you look for why it does not). RE is a discovery activity (you do not know what the program does, you try to understand it).

> 💡 In practice, the two activities often overlap. A developer debugging a crash in a third-party library without source code is doing RE without necessarily naming it as such. And a reverse engineer uses debugging techniques throughout their analysis. The distinction is above all a question of intent and context, not of tooling.

---

## The objectives of reverse engineering

RE is not an end in itself — it is a means in service of concrete objectives. Depending on the context, the analyst seeks to achieve one or more of the following objectives.

### 1. Understanding a program's behavior

The most fundamental objective: determining **what** a binary does. This can range from a high-level view ("this program is an FTP client that connects to port 2121") to a fine-grained understanding of a specific routine ("this function implements a rolling XOR with a 16-byte key derived from the timestamp").

This is the central objective of malware analysis (Part VI of this training): faced with a suspicious sample, the analyst must determine its capabilities, targets, persistence, and communication mechanisms, without any documentation.

It is also the goal of "reversing" CTF competitions: you are given a binary, you have to understand its logic to extract a flag.

### 2. Assessing the security of a piece of software

In the context of a commissioned security audit, RE makes it possible to examine a binary in search of vulnerabilities: buffer overflows, format-string injections, use-after-free, race conditions, cryptographic weaknesses, hardcoded secrets (keys, passwords, tokens).

This objective is central to the field of **vulnerability research**. Security researchers regularly analyze commercial software — browsers, operating systems, firmwares — to discover flaws before they are exploited. RE is the technical skill that makes this research possible when source code is not available.

### 3. Ensuring interoperability

When proprietary software uses an undocumented network protocol or a closed file format, RE is sometimes the only way to understand that protocol or format in order to develop a compatible implementation.

The most famous historical example is the Samba project, which had to reverse the Microsoft SMB/CIFS protocol to enable interoperability between Linux and Windows systems. More recently, many open source projects have used RE to interact with devices whose manufacturers do not publish specifications (graphics card drivers, USB controllers, IoT protocols).

> 💡 Interoperability is one of the use cases where the legal framework offers the reverse engineer the most protection. European directive 2009/24/EC (which replaced directive 91/250/EEC) explicitly authorizes the decompilation of a program for interoperability purposes under certain conditions. Section 1.2 details this point.

### 4. Recovering a lost implementation

It happens that an organization depends on a critical piece of software whose source code has been lost, whose publisher has disappeared, or whose documentation is non-existent. RE makes it possible to understand the program's logic well enough to maintain it, port it to a new platform, or replace it with a documented implementation.

This case is frequently encountered in industry (programmable controllers, industrial control software) and in the preservation of digital heritage (console emulators, backward compatibility).

### 5. Analyzing a patch or an update

When a publisher releases a security fix without detailing the corrected vulnerability (which is standard practice so as not to facilitate exploitation), RE makes it possible to compare the vulnerable and the fixed version of the binary to precisely identify what has changed. This technique, called **patch diffing** (or *binary diffing*), is covered in detail in Chapter 10.

It is used both by defensive security teams (to assess the urgency of a deployment) and by offensive researchers (to develop exploits targeting systems not yet patched — within an authorized research framework).

### 6. Verifying trust properties

In certain critical contexts (defense, sensitive infrastructure, security certifications), it is necessary to verify that a binary delivered by a supplier actually corresponds to what was specified and does not contain undocumented functionality: backdoors, data-collection mechanisms, hidden network calls.

RE is then used as an **independent verification** tool, complementary to source-code audits when those are possible — or as a substitute when the supplier refuses to share their sources.

### 7. Learning and understanding in depth

This is the least utilitarian objective, but perhaps the most formative: using RE to **understand how things really work**. Disassembling a program compiled with GCC means seeing with your own eyes how the compiler translates a `switch`, how it lays out a C++ vtable, how it implements a system call, how it handles memory alignment.

Many experienced developers say that RE has made them better programmers — because it forces them to understand what actually happens under the hood, beyond the abstractions of the high-level language.

It is in this spirit that this training was designed. The RE techniques you are going to learn are useful in themselves, but they are also an incomparable way to deepen your understanding of how computer systems work.

---

## Reverse engineering in this training

This training focuses on the RE of **native ELF binaries**, compiled with **GCC or G++**, for the **x86-64 architecture under Linux**. This scope is deliberately targeted to allow in-depth coverage rather than a superficial survey of all platforms.

The objectives we just listed will all be put into practice throughout the chapters:

| Objective | Main chapters |  
|---|---|  
| Understand behavior | 5–9 (static analysis), 11–13 (dynamic analysis), 21–25 (practical cases) |  
| Assess security | 15 (fuzzing), 19 (anti-reversing), 24 (crypto) |  
| Ensure interoperability | 23 (network binary), 25 (custom file format) |  
| Analyze a patch | 10 (binary diffing) |  
| Verify properties | 27–29 (malware analysis in isolated lab) |  
| Learn in depth | The entire training, and in particular chapters 2–3 (compilation, assembly) and 16–17 (optimizations, C++) |

Section 1.6 will come back to the exact scope of this training and place it within the broader landscape of RE (managed bytecode, firmware, hardware).

---

> 📖 **Takeaway** — Software reverse engineering consists of analyzing a compiled binary to understand its behavior without access to the source code. It is a process of reconstructing meaning from material impoverished by compilation. Its objectives range from pure understanding to security auditing, via interoperability, patch analysis, and trust verification.

---


⏭️ [Legal and ethical framework (licenses, CFAA / EUCD / DMCA laws)](/01-introduction-re/02-legal-ethical-framework.md)
