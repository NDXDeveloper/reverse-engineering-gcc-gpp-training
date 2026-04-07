🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 36.1 — RE-Oriented CTFs: pwnable.kr, crackmes.one, root-me.org, picoCTF, Hack The Box

> 📁 `36-resources-further-learning/01-re-oriented-ctf.md`

---

## Why CTFs are the best training ground

Theory without practice leads nowhere in reverse engineering. Capture The Flag (CTF) competitions and platforms offer exactly what an analyst in training needs: binaries designed to be analyzed, progressive difficulty, and immediate feedback — either you find the flag, or you keep looking.

Unlike analyzing real-world software (where context is often unclear and results are hard to verify), a CTF challenge provides a clear framework: a precise objective, a solution that exists, and often a community that publishes write-ups after the competition. These write-ups are themselves a valuable learning resource — they reveal approaches and tools you might not have thought of.

The platforms presented below cover a wide range of skill levels and specializations. Some are exclusively dedicated to RE, while others offer RE among other categories (pwn, crypto, forensics...). We selected them for their direct relevance to the skills developed in this training course.

---

## Detailed platforms

### crackmes.one — The community reference for pure RE

**URL**: [https://crackmes.one](https://crackmes.one)  
**Cost**: Free  
**Level**: Beginner to expert  
**Focus**: Reverse engineering exclusively (crackmes)  

Crackmes.one is a community-driven platform where users submit crackmes — small binaries designed to be analyzed and "cracked." Each crackme comes with a difficulty level, a description of the target platform (Windows, Linux, macOS), and the language used. Solutions are also submitted by the community.

This is the platform most directly aligned with the content of this training course. The crackmes cover exactly the techniques we have seen: analyzing verification routines, patching conditional jumps, extracting keys, bypassing anti-debug protections, and writing keygens.

The community is active: in February 2026, crackmes.one organized its first official CTF — a week-long competition exclusively dedicated to reverse engineering, with 12 challenges covering topics ranging from custom VMs to shellcode analysis, including JIT decryption and DRM. The event is expected to become annual.

**Recommended starting point**: filter crackmes by difficulty 1-2, Linux platform, C language. This directly corresponds to the binaries we worked on in Parts II through V.

> 🔒 All downloads are password-protected: `crackmes.one`. Make sure to work in a VM — even though submissions are verified, caution is always warranted when dealing with downloaded executables.

---

### picoCTF — The ideal starting point

**URL**: [https://picoctf.org](https://picoctf.org)  
**Cost**: Free  
**Level**: Beginner to intermediate  
**Focus**: Multi-category (RE, crypto, forensics, web, pwn)  

PicoCTF is developed by Carnegie Mellon University. Originally designed for high school and college students, it offers a particularly well-crafted pedagogical progression. The annual competition takes place every spring (the 2026 edition ran from March 9 to 19), but all challenges from previous editions remain accessible year-round through the **picoGym** platform.

The "Reverse Engineering" category of picoCTF is an excellent starting point for beginners. The first challenges involve analyzing Python scripts or simple binaries with `strings` and `file`. The difficulty gradually increases toward analyzing compiled binaries, bypassing anti-debug measures, UPX unpacking, and RE of .NET binaries — topics we covered respectively in Chapters 5, 19, and 30-32.

**Recommended starting point**: begin with picoGym, filter by the "Reverse Engineering" category, and solve challenges in increasing order of difficulty. Challenges from previous editions remain top-tier educational material.

---

### Root-Me — The leading French-language platform

**URL**: [https://www.root-me.org](https://www.root-me.org)  
**Cost**: Free (paid PRO version for businesses)  
**Level**: Beginner to advanced  
**Focus**: Multi-category with a dedicated "Cracking" section for RE  

Root-Me is a French platform offering hundreds of challenges across many categories: web, networking, cryptanalysis, steganography, forensics, and of course **Cracking** (their term for reverse engineering). The Cracking section contains challenges involving ELF and PE binaries, covering various architectures (x86, ARM, MIPS).

The platform also offers a repository of technical documentation on reverse engineering, accessible from their "Repository" section. Root-Me is particularly relevant for French speakers, since challenge descriptions and part of the documentation are available in French.

Root-Me has developed a professional version, **Root-Me PRO**, used by companies and institutions for cybersecurity training. The French DGSE notably used this platform to organize recruitment challenges that included reverse engineering.

**Recommended starting point**: "Challenges > Cracking" section, starting with challenges rated 1 or 2 stars. The prerequisites indicated by Root-Me (understanding of assembly, executable formats, proficiency with disassemblers and debuggers) correspond exactly to Parts I through III of this training course.

---

### pwnable.kr — Binary exploitation in wargame mode

**URL**: [http://pwnable.kr](http://pwnable.kr)  
**Cost**: Free  
**Level**: Beginner to expert  
**Focus**: Binary exploitation (pwn) with a strong RE component  

Pwnable.kr is a wargame-style platform focused on binary exploitation. Challenges are organized into four categories of increasing difficulty: **Toddler's Bottle** (simple mistakes), **Rookiss** (classic exploitation for beginners), **Grotesque** (particularly tricky challenges), and **Hacker's Secret** (the most advanced level).

Although the emphasis is on exploitation (buffer overflow, use-after-free, format strings...), each challenge involves a significant reverse engineering phase. You must understand the binary before you can exploit it. Pwnable.kr is therefore an excellent complement for those who wish to extend their skills from RE to pwn — a natural extension of the techniques covered in this training course.

Challenges are solved by connecting via SSH to remote servers containing the binaries to analyze. Each challenge provides a flag in the form of a file to read, whose access requires exploiting a vulnerability.

**Recommended starting point**: the Toddler's Bottle category. The challenges `fd`, `collision`, `bof`, and `flag` (the latter being a pure RE challenge involving a binary packed with UPX) make an excellent transition from our Chapter 19 on anti-reversing.

---

### Hack The Box — The complete ecosystem

**URL**: [https://www.hackthebox.com](https://www.hackthebox.com)  
**Cost**: Free (limited access) / Paid VIP subscription  
**Level**: Intermediate to expert  
**Focus**: Multi-category with a dedicated "Reversing" section  

Hack The Box (HTB) is one of the most popular cybersecurity platforms in the world. It offers both full machines to compromise (pentesting) and **standalone challenges** by category. The **Reversing** category contains challenges dedicated to reverse engineering, from easy to "insane" difficulty.

RE challenges on HTB cover a broad spectrum: ELF and PE binaries, .NET applications, packed binaries, obfuscated binaries, and even challenges combining RE and cryptography. The platform provides binaries as archives protected by the password `hackthebox`.

HTB also offers **thematic packs**, such as "Malware Reversing — Essentials," which group several challenges into a structured learning path. These packs are particularly relevant for extending Chapters 26 through 29 of this training course on malicious code analysis.

One of HTB's advantages is its ranking system and very active community. The forums are full of hints (without direct spoilers) to help you get unstuck. However, the free version limits access to a restricted number of active challenges — the VIP subscription unlocks the entire catalog, including retired challenges.

**Recommended starting point**: filter challenges by the "Reversing" category and "Easy" difficulty. The first challenges typically involve analyzing ELF binaries with Ghidra or IDA — exactly the tools from Chapters 8 and 9.

---

## Other platforms and competitions worth knowing

Beyond the five main platforms, several other resources deserve mention:

**Flare-On Challenge** ([https://flare-on.com](https://flare-on.com)) — The annual competition from Google Cloud's FLARE team (formerly FireEye/Mandiant). This is **the** unmissable event for reverse engineering. Each fall, a series of progressive challenges is published, ranging from accessible crackmes to malware analysis of formidable complexity. The competition is individual and runs over several weeks. The official solutions published after the event are extremely high-quality educational resources. As an anecdote, it was Flare-On that directly inspired the creation of the crackmes.one CTF in 2026.

**Microcorruption** ([https://microcorruption.com](https://microcorruption.com)) — Created by Matasano Security (now NCC Group) in collaboration with Square, Microcorruption simulates a Texas Instruments MSP430 microcontroller directly in the browser. The challenges involve exploiting vulnerabilities in the firmware of a simulated electronic lock system (the "Lockitall LockIT Pro"). The built-in interface includes a full debugger (breakpoints, memory inspection, single-stepping). It is an excellent introduction to embedded RE for those who wish to go beyond the x86-64 covered in this training course.

**challenges.re** ([https://challenges.re](https://challenges.re)) — Created by Dennis Yurichev (author of *Reverse Engineering for Beginners*), this platform offers 87 "academic" RE exercises inspired by Project Euler. The approach differs from classic CTFs: the challenges focus on understanding disassembled code fragments, without a competitive context. Strong point: the exercises cover many architectures (x86, x64, ARM, ARM64, MIPS) and platforms (Windows, Linux, macOS), making it a good practice ground for going beyond the x86-64 Linux covered in this training course. Solutions are deliberately not published — verification is done through direct exchange with the author.

**reversing.kr** — A historic collection of RE challenges and crackmes, active from 2012 to 2019. The domain expired in late 2025 and the site is no longer directly accessible. However, the challenges and their binaries remain available through the many GitHub repositories that archived them (search "reversing.kr challenges"), and detailed write-ups for each exercise are still online. The challenges primarily involve Windows PE binaries (cracking, anti-debug, unpacking) and remain relevant for practice.

**pwn.college** ([https://pwn.college](https://pwn.college)) — A free educational platform developed by Arizona State University (ASU). It offers over 1,000 challenges covering reverse engineering, binary exploitation, shellcoding, and sandboxing, with a highly structured incremental progression. pwn.college is used for ASU's CSE 365 (Introduction to Cybersecurity) and CSE 466 (Computer Systems Security) courses. The "Reverse Engineering" module is directly relevant for consolidating the skills acquired in this training course. The platform is supported by DARPA funding through the ACE Institute (American Cybersecurity Education).

**CTFtime** ([https://ctftime.org](https://ctftime.org)) — This is not a challenge platform, but the definitive directory of all CTF competitions worldwide. CTFtime lists upcoming events, team rankings, and most importantly the **write-ups** published after each competition. By filtering by the "Reverse Engineering" category, you will find a continuous stream of new challenges and solutions to study.

---

## How to structure your practice

The sheer number of platforms and challenges available can feel overwhelming. Here is a structured approach to get the most out of them, adapted to your progression level:

**Phase 1 — Consolidate the fundamentals** (after this training course): Start with picoCTF (picoGym) and crackmes.one (difficulty 1-2). The goal is to regularly solve simple challenges to build reflexes: run `file` and `strings`, load into Ghidra, identify the verification point, understand the logic. Aim for one challenge every two to three days.

**Phase 2 — Increase the difficulty**: Move on to medium-difficulty challenges on Root-Me (Cracking) and Hack The Box (Reversing Easy/Medium). Start diversifying targets: stripped binaries, C++ binaries, .NET binaries, packed binaries. Systematically read write-ups for challenges you cannot solve after a reasonable effort.

**Phase 3 — Competitions and specialization**: Participate in online CTFs (check CTFtime for the schedule). Attempt the annual Flare-On. Tackle "Hard" and "Insane" challenges on HTB. At this stage, you begin developing specializations: malware analysis, protocol RE, embedded RE, etc.

**Cross-cutting rule**: Document every challenge you solve. Even a short text file describing your approach, the tools used, and the difficulties encountered constitutes valuable review material — and the beginning of a portfolio (see Section 36.5).

---

## Summary table

| Platform | URL | Cost | RE Specialty | Level | Language |  
|---|---|---|---|---|---|  
| **crackmes.one** | crackmes.one | Free | RE exclusively (crackmes) | Beginner → Expert | EN |  
| **picoCTF** | picoctf.org | Free | RE among other categories | Beginner → Intermediate | EN |  
| **Root-Me** | root-me.org | Free | Dedicated "Cracking" section | Beginner → Advanced | FR/EN |  
| **pwnable.kr** | pwnable.kr | Free | Pwn + RE | Beginner → Expert | EN |  
| **Hack The Box** | hackthebox.com | Freemium | Dedicated "Reversing" section | Intermediate → Expert | EN |  
| **Flare-On** | flare-on.com | Free | RE exclusively (annual) | Intermediate → Expert | EN |  
| **Microcorruption** | microcorruption.com | Free | Embedded RE (MSP430) | Beginner → Intermediate | EN |  
| **challenges.re** | challenges.re | Free | Academic RE | Intermediate | EN |  
| **pwn.college** | pwn.college | Free | RE + pwn (educational) | Beginner → Advanced | EN |  
| **CTFtime** | ctftime.org | Free | Directory + write-ups | All levels | EN |

---

**Next section: 36.2 — Recommended Reading (books, papers, blogs)**

⏭️ [Recommended Reading (books, papers, blogs)](/36-resources-further-learning/02-recommended-reading.md)
