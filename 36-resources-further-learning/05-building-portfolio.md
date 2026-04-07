🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 36.5 — Building Your RE Portfolio: Documenting Your Analyses

> 📁 `36-resources-further-learning/05-building-portfolio.md`

---

## Why a portfolio is your greatest asset

In a field as specialized as reverse engineering, the traditional resume has its limits. Listing "Ghidra," "GDB," and "malware analysis" in a skills section says nothing about your actual ability to analyze an unknown binary. What convinces a recruiter, a CERT team lead, or a potential client is **seeing how you reason** when faced with a concrete technical problem.

An RE portfolio is a collection of documents that demonstrate your analysis process: how you approach a binary, what tools you use and why, how you overcome obstacles, and how you communicate your results. Every write-up, every analysis report, every tool you publish is tangible proof of your skill level.

The portfolio serves three distinct purposes. It is a **recruitment tool** — specialized employers (CERTs, threat intel, security vendors, red teams) read it carefully and often prefer a candidate with an active technical blog over a candidate with three certifications but no visible output. It is a **learning tool** — the act of writing forces you to structure your thinking, verify your hypotheses, and fill your knowledge gaps. You understand better what you can explain clearly. Finally, it is a **contribution to the community** — your write-ups help other analysts progress, exactly as other people's write-ups helped you (Section 36.1).

---

## What to include in an RE portfolio

### CTF write-ups

This is the most natural format to start with. Every CTF challenge you solve is a potential candidate for a write-up. The format is simple: challenge description, progressive analysis (with tool screenshots), solution, and lessons learned.

The best write-ups do not just show the solution — they also document the **dead ends** explored and the **intermediate reasoning**. A recruiter reading your write-up wants to understand how you think, not simply verify that you found the flag. Showing that you first tried a static approach with Ghidra, that you hit a wall on an obfuscated routine, that you switched to dynamic analysis with GDB, then finally used angr to solve the constraint — this journey is far more revealing than a 10-line script that produces the flag.

A few principles for a quality write-up:

Start with **triage** — show that you have the reflex of running `file`, `strings`, `checksec` before diving into the disassembler. This is the workflow from Chapter 5.7, and recruiters check that this reflex is ingrained.

Include **annotated screenshots** of your tools (Ghidra, GDB, ImHex...). A screenshot of the control flow graph in Ghidra with your function renames and comments shows your ability to make a stripped binary readable.

Explain the **why** behind each decision, not just the what. "I set a breakpoint on `strcmp` because `strings` had revealed success/failure messages, suggesting a password comparison" is infinitely more useful than "I set a breakpoint on `strcmp`."

End with a **lessons learned** section where you note what this challenge taught you and what you would do differently next time.

---

### Malware analysis reports

If you are heading toward malware analysis (extension of our Part VI), analysis reports are the centerpiece of your portfolio. Chapter 27.7 of this training course covered writing a standard analysis report — the portfolio is where you publish those reports.

A professional malware analysis report follows a structure that employers recognize:

The **executive summary** — two or three sentences accessible to a non-technical audience, describing what the sample does and the risk it represents.

The **indicators of compromise (IOCs)** — sample hashes (MD5, SHA-256), contacted IP addresses/domains, files created or modified, registry keys affected. These are the elements directly actionable by defense teams.

The **detailed technical analysis** — the core of the report, where you describe your reverse engineering process step by step: static analysis (Ghidra, ImHex), dynamic analysis (GDB, Frida), identification of crypto routines, key extraction, C2 protocol reconstruction, etc.

The **detection rules** — YARA rules, Snort/Suricata signatures, or Sigma indicators that you developed from your analysis. Producing detection rules demonstrates that you know how to turn an analysis into concrete protection.

> ⚠️ **Caution**: only publish analysis reports on samples you created yourself (like those in our Part VI) or on publicly available samples from databases like MalwareBazaar. Never publish analysis on samples obtained in a professional context without explicit authorization.

---

### Tools and scripts

Every utility script you develop during your RE practice is a candidate for your portfolio. The most valued types of contributions:

**Automation scripts** — a Python script that automates triage of a directory of binaries (Chapter 35 checkpoint), a Ghidra plugin that identifies specific patterns, a reusable Frida script for hooking a category of functions.

**Parsers and tools** — a Python parser for a file format you reverse-engineered (Chapter 25), an ImHex `.hexpat` pattern, a decryptor for a specific crypto scheme.

**YARA rules** — a set of rules for detecting specific malware families or compiler patterns.

Publish these tools on GitHub with a clear README that explains the problem solved, usage, and limitations. A well-maintained GitHub repository is a strong signal for a technical employer.

---

### Technical articles and original research

Beyond CTF write-ups and analysis reports, you can publish technical articles on RE topics you have explored in depth. A few examples of subjects that make excellent portfolio pieces:

A detailed comparison of the assembly code produced by GCC and Clang for the same C program (extension of Chapter 16.7). An article documenting the reverse engineering of a proprietary network protocol (Chapter 23). An analysis of the internal structures of a stripped Rust or Go binary (Chapters 33-34). A tutorial on using angr to solve a specific category of crackmes (Chapter 18).

This type of content demonstrates a capacity for deep exploration and communication that goes beyond solving individual challenges.

---

## Where to publish

### Personal blog

A personal blog is the most flexible and long-lasting format. You have full control over content, layout, and archiving. Several technical options are available:

**GitHub Pages + Jekyll/Hugo** — Free, hosted on GitHub, content in Markdown. This is the most popular choice in the security community. Your articles live in a Git repository, making versioning and contribution easy. Many RE researchers use this format (n1ght-w0lf, clearbluejar, vaktibabat...).

**A self-hosted static site** — For those who want more control. Static site generators (Hugo, Eleventy, Zola) produce fast sites with no third-party dependencies.

**Medium / Hashnode / dev.to** — Simpler to set up, but you depend on a third-party platform and formatting for technical code is sometimes limited.

Regardless of the chosen platform, the key is to **start**. A blog with three well-written write-ups has more value than a perfectly designed but empty blog.

---

### GitHub

Your GitHub profile is a natural complement to the blog. Organize your repositories by category:

A `ctf-writeups` repository grouping your write-ups by competition and year. One repository per significant tool or script you have developed. A repository for your YARA rules and ImHex patterns. An optional `re-notes` repository where you keep your research notes and personal cheat sheets.

Pay attention to READMEs: a repository without a README is a repository nobody looks at. A good README explains in one sentence what the project does, shows a usage example, and lists prerequisites.

---

### Community sharing

Once your write-ups are published, share them on community channels (Section 36.3): r/ReverseEngineering, the relevant CTF forums, Mastodon/infosec.exchange, the crackmes.one Discord. Community feedback is valuable — it corrects your mistakes, suggests alternative approaches, and increases the visibility of your work.

---

## Standard RE write-up structure

Here is a reusable skeleton for structuring your write-ups consistently:

**Title and metadata** — Challenge/sample name, platform (CTF, crackmes.one, HTB...), date, difficulty, category (RE, pwn, malware...), tools used.

**Context** — Where this binary comes from, what the objective is (find the flag, write a keygen, analyze behavior, decrypt a file...).

**Initial triage** — Results of `file`, `strings`, `checksec`, `readelf`/`objdump`. Initial hypotheses.

**Static analysis** — Loading into the disassembler, identifying key functions, renaming, reconstructing structures. Annotated screenshots.

**Dynamic analysis** (if applicable) — GDB/Frida sessions, breakpoints set, values observed, runtime behavior.

**Solution** — The reasoning that leads to the solution. The keygen code, the decryptor, or the working exploit.

**Lessons learned** — What this challenge taught, difficulties encountered, abandoned leads, what you would do differently.

This structure is not rigid — adapt it to the context. A malware report will have a different structure than a crackme write-up. But the constant is **transparency of reasoning**: show how you think, not just what you do.

---

## Mistakes to avoid

**Publishing only easy challenges.** A portfolio composed exclusively of difficulty-1 challenges impresses no one. Include analyses where you had to search, experiment, and learn something new. The most interesting write-ups are often those where the author struggled.

**Omitting failures.** A partial write-up — "here is how far I got, here is where I am stuck" — has value. It shows your methodology and intellectual honesty. The RE community respects people who document their failures as much as their successes.

**Neglecting the writing.** A poorly structured write-up, without screenshots, with uncommented code and phrases like "and then I did something and it worked" has no demonstrative value. Take the time to write well. Proofread. Have someone else proofread if possible.

**Publishing confidential information.** Never publish analysis from a professional context (client engagement, ongoing incident, internal sample) without authorization. This is a serious professional fault that can have legal consequences and destroy a reputation.

**Waiting until you are "good enough."** Imposter syndrome is pervasive in RE. Everyone feels they do not know enough to publish. The reality is that your difficulty-2 crackme write-up will help someone who is at difficulty 1, and the writing process will make you improve as well. Publish early, publish regularly, improve along the way.

---

## Concrete action plan

To turn this section into tangible results, here is a three-month plan:

**Month 1** — Create your publishing platform (GitHub Pages blog or equivalent). Write and publish your first write-up on a CTF challenge you already solved during this training course. A single well-done write-up is enough to start.

**Month 2** — Publish two additional write-ups, varying the types (a crackme, a network or crypto challenge, an analysis report on one of the Part VI samples). Create a GitHub repository for your scripts and tools.

**Month 3** — Share your publications on r/ReverseEngineering or the crackmes.one Discord. Add your blog link to your professional profile (LinkedIn, resume). Solve a new challenge specifically to document it — choosing a challenge with the mindset "I am going to write a write-up about this" profoundly changes the attention you pay to each step.

From there, maintain a pace of one or two write-ups per month. In a year, you will have a portfolio of about fifteen pieces covering various techniques — a very strong signal for any employer in the field.

---

## What recruiters actually look for

To close this section with a practical perspective, here is what RE and malware analysis team leads look for when reviewing a candidate's portfolio:

**Methodology** — Does the candidate follow a structured approach, or do they dive headfirst into the disassembler? Is initial triage present?

**Rigor** — Are claims verified? Does the candidate distinguish hypotheses from certainties? Do the screenshots match the text?

**Communication** — Is the write-up readable by someone who does not have the binary in front of them? Are the steps reproducible?

**Curiosity** — Does the candidate go beyond the minimum solution? Do they explore aspects of the binary that were not strictly necessary for the flag?

**Progression** — Are recent write-ups more in-depth than the first ones? Is the candidate tackling challenges of increasing difficulty?

No recruiter expects a perfect portfolio. What they want to see is an analyst who thinks clearly, documents their work, and keeps learning.

---

> 🎓 **You have completed Chapter 36 and Part IX of this training course.** If you followed the entire path from Chapter 1, you now have the technical foundations, the tools, the methodology, and the resources to continue your progression in reverse engineering independently. The journey is just beginning — and your portfolio will be its witness.

---


⏭️ [Appendices](/appendices/README.md)
