🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part IX — Resources & Automation

You know how to analyze a binary end to end — statically, dynamically, on C, C++, Rust, Go, .NET, and packed malware. This final part takes you from the analyst who can do everything by hand to the reverser who **automates, capitalizes, and keeps progressing**. You will build your own toolkit of reusable scripts, integrate binary analysis into automated pipelines, and walk away with a clear roadmap for what comes next: CTFs, certifications, communities, contributions.

---

## 🎯 Objectives of this part

By the end of these two chapters, you will be able to:

1. **Automate ELF binary analysis** with Python scripts using `pyelftools` and `lief` to parse, modify, and instrument binaries programmatically.  
2. **Run Ghidra analyses in headless mode** on batches of binaries, export the results automatically, and integrate this step into a binary regression audit CI/CD pipeline.  
3. **Write YARA rules** to detect recurring patterns (crypto constants, packer signatures, compiler markers) in a collection of binaries.  
4. **Organize your personal RE toolkit**: structure your scripts, snippets, templates, and rules to reuse them from one project to the next.  
5. **Identify resources and communities** to keep progressing: CTF platforms, reference readings, conferences, certifications, and building a public portfolio.

---

## 📋 Chapters

| # | Title | Description | Link |  
|----|-------|-------------|------|  
| 35 | Automation and scripting | ELF parsing and modification with `pyelftools` and `lief`, Ghidra headless for batch analysis, `pwntools` scripting, writing YARA rules, integration into a CI/CD pipeline, building a personal RE toolkit. | [Chapter 35](/35-automation-scripting/README.md) |  
| 36 | Resources for further learning | CTF platforms (pwnable.kr, crackmes.one, root-me.org, picoCTF, Hack The Box), recommended readings (books, papers, blogs), communities and conferences (REcon, DEF CON RE Village, PoC\|\|GTFO), certifications (GREM, OSED), building an RE portfolio. | [Chapter 36](/36-resources-further-learning/README.md) |

---

## 🚀 What's next?

The training has given you the foundations and the tools. Here are four concrete paths to turn those skills into expertise:

**Practice on CTFs.** It is the most direct way to progress. Start with the RE challenges on picoCTF and root-me.org (accessible), then move up to crackmes.one, pwnable.kr, and Hack The Box (intermediate to advanced). Aim for one challenge per week — regularity matters more than intensity.

**Contribute to the open source ecosystem.** Ghidra, Radare2, Frida, YARA, `lief` — all of these projects accept contributions. Writing a Ghidra script, adding signatures for a stdlib, fixing a bug in r2: it is formative, visible, and it enriches your portfolio.

**Aim for a certification.** GREM (SANS) for malware analysis, OSED (OffSec) for binary exploitation. These certifications structure your progression and are recognized by the industry. Chapter 36 details the paths and firsthand feedback.

**Specialize.** RE is a broad field. You can dive deeper into malware analysis (Part VI as a starting point), vulnerability research (fuzzing + exploitation), firmware/IoT RE, or protocol analysis. Choose the area that motivates you and go deep — versatility will come with time.

---

## ⏱️ Estimated duration

**~8-12 hours** for a practitioner who has completed the previous parts.

Chapter 35 (automation, ~5-7h) is the most technical: you will write substantial Python scripts, configure Ghidra in headless mode, and set up a pipeline. Take the time to produce clean, documented scripts — they are the ones you will reuse in your future projects. Chapter 36 (resources, ~3-5h) is a chapter of reading and exploration: browse the CTF platforms, leaf through the recommended books, sign up for the communities. Actual time depends on how deeply you dig into each resource.

---

## 📌 Prerequisites

**Mandatory:**

- Having completed **[Part I](/part-1-fundamentals.md)** through **[Part V](/part-5-practical-cases.md)** — Chapter 35 automates workflows that you need to be able to do manually, and Chapter 36 assumes you have the level to tackle intermediate CTF challenges.  
- Mastering Python at a level sufficient to write 100-200 line scripts using third-party libraries.

**Recommended:**

- Having gone through at least one of the bonus parts (**[Part VI](/part-6-malware.md)**, **[Part VII](/part-7-dotnet.md)**, **[Part VIII](/part-8-rust-go.md)**) — the YARA rules and automation scripts of Chapter 35 cover cases drawn from these parts.  
- Having an account on at least one CTF platform (root-me.org or picoCTF) to be able to follow Chapter 36's exercises live.

---

## ⬅️ Previous part

← [**Part VIII — Bonus: RE of Rust and Go Binaries**](/part-8-rust-go.md)

## 🏠 Back to the table of contents

You have gone through the entire training. Find the full table of contents, appendices, training binaries, and checkpoint solutions from the main landing page.

→ [**Training home page**](/README.md)

⏭️ [Chapter 35 — Automation and scripting](/35-automation-scripting/README.md)
