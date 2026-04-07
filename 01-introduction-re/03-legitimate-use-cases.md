🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 1.3 — Legitimate use cases

> **Chapter 1 — Introduction to Reverse Engineering**  
> 📦 No technical prerequisites — reading section.  
> 📖 This section extends the framework laid out in [1.2 — Legal and ethical framework](/01-introduction-re/02-legal-ethical-framework.md) by concretely illustrating the contexts in which RE is legitimately practiced.

---

## Beyond the cliché

Reverse engineering suffers from an image problem. In popular culture and in parts of the press, it is often associated with software piracy, the creation of cracks, and clandestine activities. This perception is both understandable (piracy does indeed use RE techniques) and deeply misleading (the vast majority of RE practiced daily has nothing to do with piracy).

In reality, reverse engineering is a professional skill mobilized in many fields of computing, by people acting in a perfectly legal and often commissioned context. This section reviews the main legitimate use cases — the ones this training prepares you to tackle.

---

## Security auditing and vulnerability research

### Context

Companies, government agencies, and software publishers regularly call on specialists to assess the security of their products. When source code is available, the audit takes the form of a *source code review*. But in many cases, source code is not accessible — either because the software is proprietary, because the audit is of a binary delivered by a subcontractor, or because it is desirable to verify that the deployed binary actually corresponds to the audited source.

That is where RE comes in. The analyst examines the compiled binary in search of security flaws: buffer overflows, format-string vulnerabilities, memory management errors, cryptographic weaknesses, hardcoded secrets, unencrypted communications, backdoors.

### Engagement frameworks

**Pentest (penetration test)** — A client commissions a security team to test their defenses. The scope often includes analysis of binaries deployed on the infrastructure: server applications, monitoring agents, firmware of network equipment. RE makes it possible to identify vulnerabilities that would not be visible through a simple network scan or a black-box test.

**Vulnerability research** — Security researchers analyze widely deployed software (web browsers, operating systems, network libraries) to find flaws before attackers discover them. This work relies heavily on RE and fuzzing. The vulnerabilities found are reported to publishers via coordinated disclosure programs, and often rewarded by *bug bounties*.

**Compliance auditing and certification** — In certain sectors (defense, aerospace, industrial systems, healthcare), software must pass security certifications. RE can be used to verify that the delivered binary complies with the security specifications — for example, that it does not make unforeseen network communications or include undocumented functionality.

**Incident response** — When an organization suffers an intrusion, the *incident response* team must analyze the tools left by the attacker: malware, backdoors, exfiltration scripts. RE of these artifacts is essential to understand the extent of the compromise, identify the exfiltrated data, and attribute the attack. This is the heart of Part VI of this training.

> 💡 **Link with the training** — Chapter 15 (fuzzing) and chapters 26 to 29 (malicious code analysis) directly put this use case into practice. Chapter 19 (anti-reversing) teaches you to recognize the protections you will encounter during a real audit.

---

## CTF competitions (*Capture The Flag*)

### The principle

CTFs are computer security competitions where teams or individuals solve technical challenges to score points. Among the classic categories (web, crypto, pwn, forensics, misc), the **"reversing"** category holds a central place: you are given a binary, and you must understand its logic to extract a *flag* — a secret string that proves you solved the challenge.

### Why this is a legitimate use case

CTFs are environments designed to be analyzed. Binaries are created specifically for the competition, with the consent (and often the encouragement) of their authors. There is no legal or ethical ambiguity: the explicit goal is for participants to reverse the program.

### The skills CTFs develop

The reversing category of CTFs covers a broad spectrum of skills that correspond precisely to those taught in this training:

- Quick triage of an unknown binary (identification of format, architecture, protections).  
- Reading and interpretation of x86-64 assembly code.  
- Use of disassemblers and decompilers (Ghidra, IDA, Binary Ninja).  
- Dynamic analysis with GDB and its extensions.  
- Identification of cryptographic routines or encoding algorithms.  
- Symbolic execution to solve constraints (angr, Z3).  
- Bypassing anti-RE protections (obfuscation, packing, anti-debug).

CTFs also have an important pedagogical virtue: they impose time constraints that force you to develop an efficient methodology, and the *write-ups* published after the competition are a gold mine of techniques documented by the community.

> 💡 **Link with the training** — Chapter 21 (reversing a keygenme) is directly inspired by reversing-type CTF challenges. Chapter 36 lists the CTF platforms where you can train after the course.

---

## Advanced debugging without source code

### The problem

Every developer has one day encountered a crash or an inexplicable behavior in a third-party library, a driver, or a system component for which they do not possess the source code. Classic debugging tools show a call stack with hexadecimal addresses, an instruction pointer pointing into nothing, and no variable or function name to understand what is happening.

### How RE helps

RE techniques allow this black box to be transformed into something understandable:

- **Disassemble the crash area** to understand which instruction failed and why (NULL pointer dereference, out-of-bounds access, division by zero).  
- **Trace back the control flow** to identify how the program reached that state (what arguments were passed, which branch was taken).  
- **Inspect in-memory data structures** to understand the program's internal state at the time of the crash (is the stack corrupted? Has a reference count gone negative? Has a buffer overflowed?).  
- **Trace system calls** with `strace` to observe the program's interactions with the kernel (files opened, sockets created, signals received).  
- **Hook functions** with Frida to observe arguments and return values without modifying the binary.

This use case is particularly common in the following environments:

**Embedded development** — Libraries provided by chip manufacturers (HAL, SDK) are often delivered as precompiled binaries without source code. When a bug occurs in this layer, the developer has no choice but to analyze the binary.

**Integration of third-party libraries** — An application using a proprietary library (video codec, rendering engine, payment module) may encounter crashes in that library. If the publisher is slow to respond or has gone out of business, RE of the affected component is sometimes the only way forward.

**Production debugging** — A program crashes in production but not in the development environment. The production binary is compiled with aggressive optimizations (`-O2`, `-O3`) that modify the code to the point of making source-level debugging ineffective. Understanding optimized assembly then becomes necessary to interpret core dumps.

> 💡 **Link with the training** — Chapters 11 and 12 (GDB and its extensions) cover debugging on stripped and optimized binaries in detail. Chapter 16 (compiler optimizations) will teach you to recognize the transformations applied by GCC so that you are not thrown off by optimized code.

---

## Interoperability

### The need

Interoperability is the ability of different systems to work together. In an ideal world, all protocols and file formats would be documented by public specifications. In practice, many systems use undocumented proprietary protocols or closed file formats. When you need to make your software communicate with such a system and the publisher does not provide documentation or a public API, RE is often the only recourse.

### Historical and contemporary examples

**Samba and the SMB/CIFS protocol** — The Samba project is probably the most emblematic example of RE for interoperability. The Samba team had to reverse Microsoft's file-sharing protocol to allow Linux and Unix systems to join Windows domains, access network shares, and provide compatible file services. This RE effort, carried out over more than two decades, has been recognized as legitimate under European law.

**LibreOffice and Microsoft Office formats** — LibreOffice's ability to open and edit `.docx`, `.xlsx`, and `.pptx` files rests in part on reverse engineering of the original Microsoft Office binary formats (`.doc`, `.xls`, `.ppt`), carried out before Microsoft published partial specifications under antitrust pressure.

**Open source graphics drivers** — The Nouveau project (for NVIDIA cards) and the early open source AMD drivers were developed by reversing the hardware interfaces and binary blobs provided by the manufacturers. This work made it possible to offer functional Linux graphics support for hardware whose specifications were not public.

**IoT and home automation protocols** — Many connected devices (cameras, light bulbs, thermostats, locks) use proprietary protocols to communicate with their mobile app or cloud. Developer communities reverse these protocols to integrate them into open home-automation platforms like Home Assistant, enabling users to control their devices without depending on the manufacturer's closed ecosystem.

### Interoperability RE in practice

This type of RE typically combines:

- Analysis of network traffic (packet capture with Wireshark, call tracing with `strace`).  
- RE of the client or server binary to understand how packets are constructed and interpreted.  
- Writing a replacement client or server that implements the identified protocol.

This is exactly the path followed in Chapter 23 of this training (reversing a client/server network binary).

> 💡 **Link with the training** — Chapter 23 (network binary) and Chapter 25 (custom file format) correspond directly to this use case. You will reverse an undocumented network protocol and file format to write independent implementations.

---

## Malware analysis and incident response

### Context

When an organization detects malicious software on its infrastructure, the first priority is to understand what the malware does, how it got there, what it may have exfiltrated, and how to eradicate it completely. RE is the central tool of this understanding.

### What RE brings to malware analysis

- **Identification of capabilities** — Is the malware a ransomware? A credential stealer? A keylogger? A DDoS bot? A dropper that downloads other components? Only binary analysis can answer with certainty.  
- **Extraction of indicators of compromise (IOCs)** — IP addresses or domain names of command-and-control (C2) servers, file paths created or modified, registry keys (on Windows), mutexes, distinctive strings. These IOCs are then used to detect the malware on other machines in the network.  
- **Understanding the C2 protocol** — How does the malware communicate with its operator? What protocol does it use? Are the communications encrypted? Can they be decoded to understand the commands sent and the data exfiltrated?  
- **Identification of the malware family** — By comparing techniques, constants, and reused code fragments, the analyst can tie the sample to a known malware family, which considerably accelerates the response.  
- **Development of countermeasures** — Understanding the encryption mechanism of a ransomware can make it possible to write a decryptor. Understanding the persistence mechanism of an implant allows it to be properly eradicated.

### A profession in its own right

Malware analysis has become a recognized specialization in the cybersecurity industry, with its own certifications (SANS GREM, for example), dedicated conferences, and strong demand in the job market. RE is the fundamental technical skill of this profession.

> 💡 **Link with the training** — Part VI (chapters 26 to 29) is entirely devoted to malicious code analysis in a controlled environment. You will analyze an ELF ransomware and a dropper with network communication — samples created by us for educational purposes.

---

## Preservation and software archaeology

### Saving the digital heritage

Software is a fragile cultural and technical artifact. Programs on which entire industries depend can become unusable because their publisher went bankrupt, because the target operating system is no longer supported, or because the required hardware is no longer manufactured.

RE plays a crucial role in preserving this heritage:

**Emulation and backward compatibility** — Emulators for game consoles, home computers, and old operating systems rely on RE of the original hardware and system software. Without this work, decades of software would become irremediably inaccessible.

**Industrial systems migration** — Factories, power plants, and transportation systems sometimes run on control software whose source code has been lost and whose publisher has disappeared. RE makes it possible to understand the logic of these systems in order to migrate them to modern platforms without disrupting operations.

**Data recovery** — Proprietary file formats become unreadable when the software that produced them is no longer available. RE of the format makes it possible to develop converters that save data from obsolescence.

---

## Learning and academic research

### Understanding in order to build better

RE is a remarkable learning tool. Disassembling a program means seeing the concrete result of the choices made by a compiler, a developer, or a system architect. It is moving from theory ("a virtual method call in C++ uses a vtable") to direct observation ("here are the exact instructions GCC generates to resolve this call").

Many universities integrate RE into their computer security and systems architecture curricula, precisely because it forces students to understand the mechanisms at a level of detail that high-level programming never requires.

### Academic research

RE is also a research tool in several fields:

- **Protocol analysis** — Researchers reverse network protocols to assess their security or to develop formal models.  
- **Firmware analysis** — RE of firmware on connected objects feeds IoT security research.  
- **Compiler improvement** — The study of code generated by different compilers at different optimization levels contributes to code-optimization research.  
- **Malware detection** — Research on automated malware analysis techniques (classification, family detection, similarity analysis) relies on RE to build annotated datasets.

> 💡 **Link with the training** — The entire training is designed with learning-by-doing in mind. Chapters 2 and 3 (compilation and assembly), then 16 and 17 (optimizations and C++), use RE as a tool for understanding the internal workings of programs.

---

## Synthesis: RE is a tool, not an intent

Reverse engineering is a neutral technical skill. Like a screwdriver, it can be used to build or to destroy. What distinguishes a legitimate use from an illegitimate one is the **intent**, the **context**, and the **legal framework** within which the activity takes place.

The use cases presented in this section — security auditing, CTFs, advanced debugging, interoperability, malware analysis, preservation, research — are all contexts where RE brings clear and recognized value. These are the contexts this training prepares you to face.

| Use case | Main chapters | Objective |  
|---|---|---|  
| Security auditing | 15, 19, 24, 26–29 | Find vulnerabilities, verify security properties |  
| CTF (reversing) | 21, 18 | Understand a binary's logic, extract a flag |  
| Advanced debugging | 11, 12, 14, 16 | Diagnose a crash or behavior without source code |  
| Interoperability | 23, 25 | Reverse an undocumented protocol or file format |  
| Malware analysis | 26–29 | Identify capabilities, extract IOCs, write countermeasures |  
| Learning | 2, 3, 16, 17 | Understand compilation, assembly, optimizations |

---

> 📖 **Takeaway** — RE is practiced daily by professionals in legitimate and recognized contexts. Security auditing, CTFs, debugging without source code, interoperability, malware analysis, and academic research are all fields where this skill is valued and in demand. This training prepares you for each of them.

---


⏭️ [Difference between static RE and dynamic RE](/01-introduction-re/04-static-vs-dynamic.md)
