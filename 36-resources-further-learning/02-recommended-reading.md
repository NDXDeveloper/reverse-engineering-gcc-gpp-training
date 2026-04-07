🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 36.2 — Recommended Reading (books, papers, blogs)

> 📁 `36-resources-further-learning/02-recommended-reading.md`

---

## How to approach this list

Reverse engineering is a field that covers a very broad spectrum: processor architecture, binary formats, operating systems, compilers, cryptography, malware analysis, exploitation... No single book covers all of this in depth. Progression necessarily involves cross-reading multiple sources, each illuminating a different angle.

This section organizes readings into three categories: **reference books** (to read in depth, pencil in hand), **articles and academic papers** (to delve deeper into specific techniques), and **technical blogs** (to stay current on today's practices). For each resource, we indicate the required level, relevance to this training course, and what it concretely provides.

> 💡 **Practical advice**: don't try to read everything. Choose a book that matches your next learning objective, read it alongside your CTF practice (Section 36.1), and move on to the next one when you feel you have absorbed the essentials.

---

## Reference books

### Reverse engineering fundamentals

**Dennis Yurichev — *Reverse Engineering for Beginners* (RE4B)**  
Free in PDF at [beginners.re](https://beginners.re)  
Level: beginner to intermediate  

This is the most comprehensive free book on the subject. Yurichev covers the analysis of disassembled code produced by C/C++ compilers on x86, x64, and ARM. The book takes an example-driven approach: each C language construct (loops, conditions, structures, function pointers...) is compiled and then analyzed at the assembly level. This is exactly the approach we followed in Chapters 3, 7, and 16 of this training course, but expanded across over 1,000 pages with considerable depth. The book is also known under the title *Understanding Assembly Language*.

**Training course relevance**: direct extension of Chapters 3 (x86-64 assembly), 16 (compiler optimizations), and 17 (C++ RE).

---

**Eldad Eilam — *Reversing: Secrets of Reverse Engineering***  
Wiley, 2005 — ISBN 978-0764574818  
Level: beginner to intermediate  

Despite its age, this book remains an essential classic. Eilam lays the methodological foundations of RE: how to approach an unknown binary, how to navigate disassembled code, how to recognize compiler-generated structures. The chapters on OS reverse engineering and software protection remain relevant. It is an excellent first book for anyone seeking a structured overview of the field.

**Training course relevance**: complementary overview of our entire training course, particularly Parts I and II.

---

**Bruce Dang, Alexandre Gazet, Elias Bachaalany — *Practical Reverse Engineering: x86, x64, ARM, Windows Kernel, Reversing Tools, and Obfuscation***  
Wiley, 2014 — ISBN 978-1118787311  
Level: intermediate to advanced  

Written by engineers from Microsoft and QuarksLab, this book is the natural successor to Eilam's. It covers x86, x64, and ARM (the first book to address all three architectures), Windows kernel reversing, virtual machine-based protection techniques, and obfuscation. The approach is systematic, with integrated hands-on exercises. It is the reference book for progressing from intermediate to advanced level.

**Training course relevance**: extension of Chapters 16 (optimizations), 17 (C++ RE), and 19 (anti-reversing).

---

**Chris Eagle, Kara Nance — *The Ghidra Book: The Definitive Guide***  
No Starch Press, 2nd edition 2026 — ISBN 978-1718504684  
Level: beginner to advanced  

The definitive reference guide for mastering Ghidra, the primary tool of this training course. Eagle (40 years of RE experience, author of *The IDA Pro Book*) and Nance (security consultant and Ghidra trainer) cover the entire framework: CodeBrowser navigation, decompiler, type analysis, Java/Python scripting, extensions, and headless mode. The 2nd edition (2026) incorporates Ghidra's most recent features. It is the ideal companion to Chapters 8 and 9, and a reference resource for any advanced static analysis.

**Training course relevance**: direct extension of Chapter 8 (Ghidra), with advanced scripting techniques (Chapter 35) and C++ structure analysis (Chapter 17).

---

### Malware analysis

**Michael Sikorski, Andrew Honig — *Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software***  
No Starch Press, 2012 — ISBN 978-1593272906  
Level: intermediate  

Considered *the* reference book for malware analysis. Sikorski (ex-NSA, Mandiant) and Honig (DoD) structure the learning in four progressive phases: basic static analysis, basic dynamic analysis, advanced static analysis (disassembly with IDA), and advanced dynamic analysis (debugging). The book covers anti-analysis techniques (anti-debug, anti-VM, packing) and provides hands-on labs with real samples. Although oriented toward Windows and IDA Pro, the methodology is universal and translates directly to our Linux/Ghidra context.

**Training course relevance**: direct extension of Part VI (Chapters 26-29), particularly the analysis methodology and anti-reversing techniques.

---

### Operating systems and low-level programming

**Randal E. Bryant, David R. O'Hallaron — *Computer Systems: A Programmer's Perspective* (CS:APP)**  
Pearson, 3rd edition 2015 — ISBN 978-0134092669  
Level: beginner to intermediate  

This is not strictly a RE book, but it is probably the best investment for understanding the foundations upon which all reverse engineering rests: data representation, x86-64 assembly, the compilation toolchain, linking, virtual memory, and process management. CS:APP is the standard course textbook at American universities (Carnegie Mellon foremost). If you feel gaps in understanding how a program works "from C code to the processor," this is the book you need.

**Training course relevance**: foundations of Chapters 2 (compilation toolchain), 3 (assembly), and the entire memory model used in Part III.

---

**Michael Kerrisk — *The Linux Programming Interface* (TLPI)**  
No Starch Press, 2010 — ISBN 978-1593272203  
Level: intermediate  

The absolute reference on Linux programming interfaces: system calls, processes, memory, signals, IPC, sockets, file systems. Essential for understanding what a Linux binary does when you observe it with `strace`, `ltrace`, or GDB. The book spans over 1,500 pages and reads more like an encyclopedia than a tutorial — keep it within reach as a reference.

**Training course relevance**: complement to Chapters 5 (`strace`/`ltrace`), 11 (GDB), and 23 (network binary).

---

### Exploitation and offensive security

**Jon Erickson — *Hacking: The Art of Exploitation***  
No Starch Press, 2nd edition 2008 — ISBN 978-1593271442  
Level: intermediate  

A classic that teaches C programming, x86 assembly, buffer overflows, shellcodes, and networking techniques — all in a progressive and practical manner, with an included LiveCD. Although dated in some aspects (modern protections have evolved), the fundamentals it teaches remain valid. It is the natural bridge between RE and binary exploitation.

**Training course relevance**: transition from acquired RE skills toward exploitation, complementing pwnable.kr (Section 36.1).

---

### Compilers and program analysis

**Alfred V. Aho, Monica S. Lam, Ravi Sethi, Jeffrey D. Ullman — *Compilers: Principles, Techniques, and Tools* (the "Dragon Book")**  
Pearson, 2nd edition 2006 — ISBN 978-0321486813  
Level: advanced  

The reference textbook on compiler theory. Understanding how a compiler transforms source code into machine code is fundamental to advanced RE — it allows you to recognize optimization patterns, understand why disassembled code takes a particular form, and anticipate transformations applied by GCC or Clang. This is not a book you read cover to cover: the chapters on lexical and syntactic analysis are less relevant for RE. Focus on code generation, register allocation, and optimizations.

**Training course relevance**: deeper exploration of Chapter 16 (compiler optimizations) and Chapter 17 (C++ object model).

---

## Reference articles and papers

The academic and technical literature on RE is abundant. Rather than an exhaustive list, here are the documents with direct impact on the techniques covered in this training course.

### x86-64 architecture

**Intel — *Intel® 64 and IA-32 Architectures Software Developer's Manual***  
The absolute reference for the x86-64 instruction set, available for free on Intel's website. Volume 2 (Instruction Set Reference) is the one most consulted in RE: it describes each instruction with its exact semantics, encodings, and effects on flags. Volumes 1 (Basic Architecture) and 3 (System Programming Guide) are useful for understanding processor modes, paging, and protection mechanisms. This is not a document you read — it is a document you search.

**System V Application Binary Interface — AMD64 Architecture Processor Supplement**  
The specification that defines the calling conventions covered in Chapters 3.5-3.6 of this training course: which registers carry arguments (`rdi`, `rsi`, `rdx`...), which registers are callee-saved, how the stack is aligned. It is the source document behind every function prologue and epilogue you analyze. Freely available online.

### ELF format and linking

**TIS Committee — *Executable and Linkable Format (ELF) Specification v1.2***  
The original specification of the ELF format. A dry but indispensable technical document when working with ELF headers, sections, and segments. Keep it as a reference rather than reading it sequentially. Freely available online.

**Ian Lance Taylor — *Linkers* (series of 20 blog posts, 2007)**  
A series of blog posts that explains how linkers work with remarkable clarity. Covers symbol resolution, dynamic loading, PLT/GOT, and PIC. It is the best complement to Chapter 2.9 of our training course on lazy binding.

### Program analysis and symbolic execution

**Shoshitaishvili et al. — *SOK: (State of) The Art of War: Offensive Techniques in Binary Analysis* (IEEE S&P 2016)**  
The foundational paper for the angr framework. It presents a taxonomy of binary analysis techniques (data flow analysis, symbolic execution, fuzzing) and their implementation in a unified framework. Essential reading for understanding the theoretical foundations of Chapter 18.

**De Moura, Bjørner — *Z3: An Efficient SMT Solver* (TACAS 2008)**  
The paper introducing Microsoft Research's Z3 solver. Understanding the basics of SMT solving is necessary for effectively using angr and Z3 (Chapter 18).

### Anti-reversing and obfuscation

**Collberg, Thomborson, Low — *A Taxonomy of Obfuscating Transformations* (1997)**  
The foundational paper on classifying code obfuscation techniques. It defines the categories we covered in Chapter 19: control flow obfuscation, data obfuscation, and layout obfuscation. Despite its age, the taxonomy remains the reference used throughout the literature.

### Malware analysis

**Official Flare-On Challenge solutions** (published annually on the Google Cloud FLARE team blog)  
These are not academic papers, but these detailed write-ups constitute some of the best technical resources available for malware analysis. Each solution breaks down the analyst's reasoning step by step, with tool screenshots. Archives of previous editions are available at [flare-on.com](https://flare-on.com).

---

## Technical blogs

Blogs are the most up-to-date source of information in RE. Techniques, tools, and threats evolve constantly — blogs keep pace better than books.

### Individual researcher blogs

**Exploit Reversing** — [exploitreversing.com](https://exploitreversing.com)  
Blog by Alexandre Borges, dedicated to vulnerability research, exploit development, and reverse engineering. Borges publishes technical articles of exceptional depth (some exceeding 100 pages in PDF), covering Windows malware analysis, macOS vulnerability research, and kernel exploitation. The *Malware Analysis Series* (MAS, 10 articles) and the *Exploiting Reversing Series* (ERS, publication ongoing) are remarkable advanced-level resources.

**MalwareTech** — [malwaretech.com](https://malwaretech.com)  
Blog by Marcus Hutchins, covering vulnerability research, threat intelligence, reverse engineering, and Windows internals. A mix of in-depth technical analyses and broader perspectives on security news.

**Möbius Strip Reverse Engineering** — [msreverseengineering.com](https://www.msreverseengineering.com)  
Blog focused on program analysis and deobfuscation. Notably features an extremely detailed *Program Analysis Reading List* for those who wish to delve into the theoretical foundations of static analysis and symbolic execution — an advanced complement to Chapters 18 and 20.

**Dennis Yurichev** — [yurichev.com](https://yurichev.com)  
The website of the author of *RE for Beginners*. Beyond the book, Yurichev regularly publishes analyses of disassembled code fragments and RE exercises.

### Team and corporate blogs

**Google Cloud Threat Intelligence (formerly Mandiant/FireEye)** — [cloud.google.com/blog/topics/threat-intelligence](https://cloud.google.com/blog/topics/threat-intelligence)  
The FLARE team regularly publishes analyses of malicious campaigns, advanced RE techniques, and annual Flare-On solutions. It is one of the most respected sources in the community.

**Quarkslab Blog** — [blog.quarkslab.com](https://blog.quarkslab.com)  
Blog of the French security firm Quarkslab, founded in 2011 by Fred Raynal (creator of MISC magazine). Articles cover reverse engineering, vulnerability research, kernel exploitation, fuzzing, and proprietary protocol analysis. Quarkslab also publishes open-source binary analysis tools. It is one of the rare security research blogs at this level produced by a French-speaking team.

**Kaspersky SecureList** — [securelist.com](https://securelist.com)  
Kaspersky's research arm publishes APT (Advanced Persistent Threats) analyses that often include in-depth technical details on the reverse engineering of the analyzed implants.

**Trail of Bits Blog** — [blog.trailofbits.com](https://blog.trailofbits.com)  
Trail of Bits publishes high-quality technical articles on binary analysis, fuzzing, symbolic execution, and tool development. Their work on Manticore (symbolic execution) and static analysis tools is particularly relevant.

**Carnegie Mellon SEI Blog** — [sei.cmu.edu/blog](https://www.sei.cmu.edu/blog)  
Carnegie Mellon's Software Engineering Institute regularly publishes articles on reverse engineering applied to malware analysis, particularly around Ghidra. Their articles present directly usable tools and methodologies.

**Hex-Rays Blog** — [hex-rays.com/blog](https://hex-rays.com/blog)  
The blog of the creators of IDA Pro. Even though our training course primarily uses Ghidra, Hex-Rays' articles on disassembly techniques, decompilation challenges, and new IDA features shed light on universal concepts.

### Community blogs and aggregators

**Tuts 4 You** — [tuts4you.com](https://forum.tuts4you.com)  
One of the oldest reverse engineering communities. The forum hosts discussions, tutorials, tools, and unpacking tutorials. It is also where announcements for competitions like the crackmes.one CTF are shared.

**r/ReverseEngineering** — [reddit.com/r/ReverseEngineering](https://reddit.com/r/ReverseEngineering)  
The subreddit dedicated to RE. It is an excellent aggregator: blog articles, new tools, papers, and CTF write-ups are regularly shared and discussed by the community. Subscribe to receive a continuous stream of quality RE content (see Section 36.3 for more details on communities).

**PoC||GTFO** — [pocorgtfo.hacke.rs](https://pocorgtfo.hacke.rs)  
A legendary technical zine in the security community, published by Travis Goodspeed et al. Each issue contains deeply technical articles on RE, exploitation, cryptography, and file formats — often with a good dose of humor and creativity. The zine itself is a polyglot (a file that is simultaneously a valid PDF, an image, and sometimes an executable). Archives are available for free.

---

## Book summary table

| Book | Author(s) | Year | Level | Topic | Free |  
|---|---|---|---|---|---|  
| *RE for Beginners* | D. Yurichev | Ongoing | Beg. → Inter. | General RE (x86, x64, ARM) | Yes |  
| *Reversing* | E. Eilam | 2005 | Beg. → Inter. | Methodological RE | No |  
| *Practical Reverse Engineering* | Dang, Gazet, Bachaalany | 2014 | Inter. → Advanced | Multi-arch RE + obfuscation | No |  
| *The Ghidra Book* (2nd ed.) | Eagle, Nance | 2026 | Beg. → Advanced | Mastering Ghidra | No |  
| *Practical Malware Analysis* | Sikorski, Honig | 2012 | Intermediate | Malware analysis | No |  
| *CS:APP* | Bryant, O'Hallaron | 2015 | Beg. → Inter. | Computer systems | No |  
| *The Linux Programming Interface* | M. Kerrisk | 2010 | Intermediate | Linux system programming | No |  
| *Hacking: Art of Exploitation* | J. Erickson | 2008 | Intermediate | Binary exploitation | No |  
| *Compilers (Dragon Book)* | Aho, Lam, Sethi, Ullman | 2006 | Advanced | Compiler theory | No |

---

## Suggested reading order

For a reader who has completed this training course, here is a coherent reading path:

**First read**: *Reverse Engineering for Beginners* by Yurichev. It is free, directly aligned with our chapters on assembly and optimizations, and the sheer number of examples allows you to consolidate your knowledge quickly. No need to read all 1,000+ pages — focus on the chapters corresponding to the C/C++ constructs you encounter in your CTF challenges.

**Second read**: *Practical Malware Analysis* by Sikorski and Honig if you are heading toward malware analysis (extension of our Part VI), or *Practical Reverse Engineering* by Dang et al. if you are aiming for advanced RE more broadly.

**Permanent reference**: *The Ghidra Book* (2nd edition) by Eagle and Nance, to keep open beside Ghidra during your analysis sessions. It replaces consulting fragmented online documentation and significantly accelerates mastery of the tool.

**In parallel**: *CS:APP* if you feel the need to solidify your foundations on how systems work, or *The Linux Programming Interface* if system calls and runtime behavior of Linux binaries still raise questions for you.

**Continuously**: follow two or three of the blogs listed above via RSS or via r/ReverseEngineering. Regular blog monitoring is what keeps you in sync with the evolution of tools and techniques.

---

**Next section: 36.3 — Communities and Conferences**

⏭️ [Communities and Conferences (REcon, DEF CON RE Village, PoC||GTFO, r/ReverseEngineering)](/36-resources-further-learning/03-communities-conferences.md)
