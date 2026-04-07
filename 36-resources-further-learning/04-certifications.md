🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 36.4 — Certification Paths: GREM (SANS), OSED (OffSec)

> 📁 `36-resources-further-learning/04-certifications.md`

---

## Should you pursue an RE certification?

The question is a fair one: reverse engineering is a field where competence is demonstrated above all through practice — a well-documented CTF write-up, a published malware analysis, an open-source tool you developed. Specialized security recruiters know how to read a technical profile and do not rely solely on certifications.

That said, certifications bring concrete benefits in certain contexts. They **structure learning** around a program validated by domain professionals, which prevents blind spots. They provide a **credible signal** for generalist employers (large corporations, government agencies, defense) who do not always have the internal expertise to evaluate an RE profile based on a portfolio. And they impose a **deadline and a level of rigor** that pushes you to reach plateaus you might have indefinitely postponed through self-study.

The two certifications most directly relevant to reverse engineering are **GREM** (GIAC/SANS), oriented toward malware analysis, and **OSED** (OffSec), oriented toward exploitation and exploit development. They cover complementary angles of RE and target different profiles.

---

## GREM — GIAC Reverse Engineering Malware

### Overview

| | |  
|---|---|  
| **Organization** | GIAC (Global Information Assurance Certification), affiliated with SANS |  
| **Associated training** | FOR610: Reverse-Engineering Malware (SANS) |  
| **Focus** | Analysis and reverse engineering of malicious software |  
| **Level** | Intermediate to advanced |  
| **Exam format** | 66-75 questions, 3 hours, proctored online exam |  
| **Passing score** | 73% minimum |  
| **Open book** | Yes (printed notes allowed) |  
| **Estimated total cost** | ~$2,800 USD (exam only) to ~$9,000+ USD (SANS training + exam) |  
| **Renewal** | Every 4 years (via CPE or retake) |  
| **Website** | [giac.org/certifications/reverse-engineering-malware-grem](https://www.giac.org/certifications/reverse-engineering-malware-grem/) |

### Content covered

GREM validates the ability to analyze and disassemble malicious software targeting common platforms (primarily Windows). The exam evaluates the following skills:

**Malware analysis fundamentals**: setting up an analysis lab, triage methodology, basic behavioral analysis. This directly corresponds to what we covered in Chapters 26 (secure lab) and 27 (rapid triage).

**Windows x86 assembly and static analysis**: reading and interpreting disassembled code, identifying C constructs in assembly (loops, conditions, function calls), using disassemblers. This is the direct extension of our Chapters 3 (x86-64 assembly), 7 (objdump), and 8 (Ghidra), transposed to the Windows ecosystem.

**Dynamic analysis**: using debuggers to trace the execution of a malicious sample, inspecting memory and registers. Chapters 11-12 of our training course.

**Identifying and bypassing anti-analysis techniques**: anti-debug, anti-VM, security tool detection, control flow obfuscation. Chapter 19.

**Analysis of protected executables**: packing, unpacking, binary reconstruction. Chapter 29.

**Analysis of malicious documents and .NET programs**. Chapters 30-32.

Since 2022, the exam includes **CyberLive** questions — hands-on exercises in a simulated environment where the candidate must perform concrete analysis actions (not just answer multiple-choice questions).

### Who is GREM for

GREM is designed for malware analysts, advanced SOC analysts, incident response specialists, and threat researchers. If your career goal is oriented toward malicious code analysis (in a CERT, in threat intelligence, or on an incident response team), GREM is the most recognized certification in this niche.

### Preparation

GIAC officially requires no prerequisites. In practice, the exam assumes significant proficiency with x86 assembly, disassembly and debugging tools, and an understanding of Windows system internals.

The most common path is to take the SANS **FOR610** training (Reverse-Engineering Malware: Malware Analysis Tools and Techniques), delivered in person or online. It is a very high-quality training course, but the cost is steep (several thousand dollars). The alternative is self-study using the books recommended in Section 36.2 (*Practical Malware Analysis* by Sikorski and Honig, as a priority) combined with regular practice on the platforms from Section 36.1.

Since the exam is open book, preparing a **personal index** of course notes is a skill in its own right. The most successful candidates are those who have built a structured index allowing them to quickly find information during the exam.

---

## OSED — OffSec Exploit Developer

### Overview

| | |  
|---|---|  
| **Organization** | OffSec (formerly Offensive Security) |  
| **Associated training** | EXP-301: Windows User Mode Exploit Development |  
| **Focus** | Exploit development and vulnerability reverse engineering |  
| **Level** | Intermediate to advanced |  
| **Exam format** | 3 targets to exploit, 47h45 practical exam + 24h for the report |  
| **Passing score** | Successful exploitation of targets with complete documentation |  
| **Open book** | Yes (except AI chatbots and LLMs) |  
| **Required tools** | WinDbg (debugger), IDA Free (disassembler), Python 3 (exploits) |  
| **Cost** | Included in OffSec subscription (Learn One: ~$2,499/year, including course + labs + 2 attempts) |  
| **Website** | [offsec.com/courses/exp-301](https://www.offsec.com/courses/exp-301/) |

### Content covered

OSED validates the ability to reverse-engineer Windows applications to find vulnerabilities, then develop working exploits that bypass modern protections. The EXP-301 course is structured in 13 progressive modules:

**Reverse engineering Windows binaries**: using IDA Free and WinDbg to analyze the inner workings of applications, trace user input through the code, and identify exploitable vulnerabilities. This is the direct transposition to Windows of the static and dynamic analysis techniques covered in Parts II and III of this training course.

**Stack buffer overflow and SEH overflow exploitation**: understanding the x86 stack, writing classic exploits, then bypassing Windows exception handling mechanisms. Extension of the concepts from Chapter 3 (stack, prologue/epilogue) and Chapter 19 (protections).

**Custom shellcode development**: writing assembly code to obtain a remote shell, handling space constraints (egghunters) and character restrictions. This pushes x86 assembly mastery well beyond the passive reading we practiced in this training course.

**DEP and ASLR bypass**: building advanced ROP (Return-Oriented Programming) chains to circumvent Data Execution Prevention, and memory address leak techniques to defeat Address Space Layout Randomization. Direct extension of Chapter 19.5 (ASLR, PIE, NX).

**Format string vulnerability exploitation**: reverse engineering a network protocol, building arbitrary read and write primitives through format specifiers.

### The exam: 48 hours of practical testing

The OSED exam is radically different from a multiple-choice test. The candidate receives three independent targets to exploit in 47 hours and 45 minutes, followed by 24 hours to write a detailed technical report. Each target requires reverse engineering (mandatory use of IDA Free and WinDbg), writing a working exploit in Python 3, and obtaining a remote shell as proof of exploitation.

The exam is open book (notes, online resources, OffSec platform) but prohibits the use of AI chatbots and LLMs. All exploits must be written in Python 3, and disassembly tools are limited to IDA Free — Ghidra is not permitted.

Candidate feedback is unanimous: the exam is extremely demanding. Testimonials regularly mention 36 to 48 hours of nearly continuous work, combining reverse engineering, exploit development, protection bypass, and report writing.

### Who is OSED for

OSED is aimed at pentesters, red teamers, vulnerability researchers, and malware analysts who want to master exploit development. If your goal is to understand not only how a binary works (classic RE) but also how to exploit it when it contains a vulnerability, OSED is the relevant choice.

OSED is part of OffSec's **OSCE3** trio (along with OSEP for advanced pentesting and OSWE for web security), which constitutes the highest level of OffSec certification.

### Preparation

OffSec recommends solid prior proficiency in C programming, x86 assembly, Windows internals, and debugging tools. The EXP-301 course starts from binary exploitation fundamentals but the learning curve is steep.

Having completed this training course (particularly Chapters 3, 11, 16, and 19) provides good preparation for the fundamental concepts. The main gap will be the Windows orientation (vs. Linux in our training course) and the shift from pure analysis to active exploitation.

---

## GREM vs OSED comparison

| Criterion | GREM | OSED |  
|---|---|---|  
| **Orientation** | Defensive malware analysis | Offensive vulnerability exploitation |  
| **Core competency** | Understanding what malware does | Exploiting a vulnerable binary |  
| **RE in the exam** | Analysis of malicious samples | RE to find and exploit vulnerabilities |  
| **Target platform** | Windows (primarily) | Windows (exclusively) |  
| **Exam format** | MCQ + CyberLive (3h) | 100% practical (~48h + report) |  
| **Perceived difficulty** | High | Very high |  
| **Cost** | High (SANS training) | Included in OffSec subscription |  
| **Typical career paths** | Malware analyst, CERT, threat intel, advanced SOC | Advanced pentester, red team, vuln research |  
| **Actual prerequisites** | x86 assembly, RE tools, Windows knowledge | x86 assembly, C programming, debugging, exploit basics |

The two certifications are complementary, not competing. GREM trains analysts who understand threats; OSED trains operators who know how to reproduce them. Choose based on your career direction.

---

## Other certifications to consider

Beyond GREM and OSED, other certifications touch on reverse engineering to varying degrees:

**GXPN (GIAC Exploit Researcher and Advanced Penetration Tester)** — An expert-level GIAC certification covering exploit development, fuzzing, and advanced pentesting techniques. Broader than OSED, it includes RE applied to exploitation across multiple platforms. Associated training: SANS SEC760.

**OSEE (OffSec Exploitation Expert)** — The most advanced OffSec level in exploitation, covering Windows kernel exploitation and advanced evasion techniques. OSEE is generally considered one of the most difficult certifications in the industry. The associated training (EXP-401 / AWE) is only delivered in person (historically at Black Hat and partner conferences), but the exam is online: 72 hours to discover and exploit unknown vulnerabilities, followed by 24 hours for the report.

**eCRE (eLearnSecurity Certified Reverse Engineer)** — Offered by INE (formerly eLearnSecurity), this certification covers reverse engineering on x86/x64 with a progressive approach. The exam format is practical. It is a more accessible option than GREM or OSED, in terms of both difficulty and cost.

**CompTIA CySA+ and CASP+** — These generalist cybersecurity certifications include questions on malware analysis and basic RE, but do not constitute an in-depth validation of reverse engineering skills. They are more relevant as a generalist foundation than as an RE specialization.

---

## Practical recommendations

**If you are starting your security career**: do not rush into an RE certification. First invest in practice (CTFs, challenges, personal projects) and in building a portfolio (Section 36.5). A certification takes on its full value when it validates skills already acquired, not when it replaces them.

**If you are targeting a malware analysis position**: GREM is the most direct choice. Prepare for it by combining *Practical Malware Analysis* (Section 36.2) with practice on the challenges from Part VI of this training course and platforms like Hack The Box (Malware Reversing packs).

**If you are targeting an advanced pentesting or red team position**: OSED is the logical next step, ideally after obtaining the OSCP. The EXP-301 course also constitutes an excellent training in applied RE, independently of the exam.

**If your employer funds the training**: take advantage of it. Cost is the main barrier for these certifications (especially SANS/GIAC). If the opportunity to take FOR610 or EXP-301 on your employer's budget arises, it is an investment worth making — the pedagogical quality of these training courses is widely recognized.

**French-speaking context**: in France, GIAC certifications (including GREM) are particularly valued in the defense and institutional ecosystem (ANSSI, DGA, COMCYBER, PRIS/PASSI service providers). OffSec certifications (OSED, OSCP) are more recognized in the pentesting and security consulting industry. For malware analysis positions in French CERTs (CERT-FR, sector-specific CERTs), GREM or documented equivalent experience (portfolio, published contributions) is a significant asset.

**In all cases**: certification is a milestone, not an endpoint. RE skills are maintained through regular practice, and the most respected certifications (GREM, OSED) lose credibility if not accompanied by continuous technical activity.

---

**Next section: 36.5 — Building Your RE Portfolio: Documenting Your Analyses**

⏭️ [Building Your RE Portfolio: Documenting Your Analyses](/36-resources-further-learning/05-building-portfolio.md)
