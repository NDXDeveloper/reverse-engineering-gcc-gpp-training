🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 9.6 — Ghidra vs IDA vs Radare2 vs Binary Ninja comparison

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [9.5 — Binary Ninja Cloud — quick start](/09-ida-radare2-binja/05-binary-ninja-cloud.md)

---

## Purpose of this section

After two complete chapters dedicated to disassembly tools (Ghidra in Chapter 8, IDA Free, Radare2, and Binary Ninja in sections 9.1 to 9.5), it's time to step back and compare these four tools according to concrete criteria. The goal is not to crown a winner — there is none — but to give you the keys to choose the tool best suited to each situation.

Reverse engineering is a field where versatility is a strength. The best tool is the one you master and that matches the current context: the target binary, licensing constraints, work environment, and nature of the analysis. This section helps you build your own decision grid.

## Summary comparison table

The table below covers the free editions of each tool, unless otherwise specified. It's the most relevant configuration for this training.

### General information

| Criterion | Ghidra | IDA Free | Radare2 / Cutter | Binary Ninja Cloud |  
|---|---|---|---|---|  
| **Publisher** | NSA (open source) | Hex-Rays | Community (open source) | Vector 35 |  
| **License** | Apache 2.0 | Proprietary, non-commercial | LGPL v3 (r2), GPL v3 (Cutter) | Proprietary, free (Cloud) |  
| **Commercial use** | Yes | No | Yes | No (Cloud) |  
| **Price (paid version)** | Free | ~$600 (Home) / ~$2,800+ (Pro) | Free | ~$299 (Personal) / ~$999+ (Commercial) |  
| **Open source** | Yes | No | Yes | No |  
| **Interface** | GUI (Java/Swing) | GUI (Qt) | CLI + GUI (Cutter/Qt) | Web (Cloud) / native GUI (paid) |  
| **Offline** | Yes | Yes | Yes | No (Cloud) |  
| **Host platforms** | Linux, macOS, Windows | Linux, macOS, Windows | Linux, macOS, Windows, Android, iOS | Browser (Cloud) / Linux, macOS, Windows (paid) |

### Analysis capabilities

| Criterion | Ghidra | IDA Free | Radare2 / Cutter | Binary Ninja Cloud |  
|---|---|---|---|---|  
| **Target architectures** | ~30+ (x86, ARM, MIPS, PPC, SPARC, AVR, etc.) | x86 / x64 only | ~50+ (the broadest coverage) | x86, x64, ARM, ARM64 |  
| **Binary formats** | ELF, PE, Mach-O, DEX, raw, etc. | ELF, PE, Mach-O | ELF, PE, Mach-O, DEX, COFF, raw, etc. | ELF, PE, Mach-O |  
| **Integrated decompiler** | Yes (all supported architectures) | Cloud, with quotas | Via r2ghidra / rz-ghidra plugin | Yes (HLIL) |  
| **Auto-analysis quality** | Very good | Excellent (historical reference) | Good (sometimes inferior on stripped binaries) | Very good |  
| **Function recognition (stripped binary)** | Very good | Excellent | Good | Very good |  
| **Library signatures** | FID (Function ID) | FLIRT (broader base) | Zignatures | Signature Libraries |  
| **Type propagation** | Good | Very good | Correct | Excellent |  
| **Intermediate representation** | P-code (internal) | Microcode (internal, not exposed in Free) | ESIL (emulation) | BNIL 4 levels (LLIL → MLIL → HLIL) |

### Scripting and automation

| Criterion | Ghidra | IDA Free | Radare2 / Cutter | Binary Ninja Cloud |  
|---|---|---|---|---|  
| **Scripting language** | Java, Python (Jython/Pyhidra) | IDAPython (limited in Free) | r2pipe (Python, JS, Go, Rust, etc.) | Not available (Cloud) |  
| **Object API** | Rich (Program, Function, Instruction, DataType…) | Rich (limited in Free) | Text/JSON commands | Excellent (paid only) |  
| **Headless mode (batch)** | Yes (analyzeHeadless) | No (Free) | Yes (`r2 -qc`) | No (Cloud) |  
| **Community plugins** | Growing ecosystem | Largest ecosystem (30 years) | Active ecosystem (r2pm) | More restricted ecosystem |  
| **CI/CD pipeline integration** | Possible (headless) | No (Free) | Natural (CLI-first) | No (Cloud) |

### Complementary features

| Criterion | Ghidra | IDA Free | Radare2 / Cutter | Binary Ninja Cloud |  
|---|---|---|---|---|  
| **Integrated debugger** | Yes (basic) | No (Free) | Yes (r_debug, supports ptrace and gdbserver) | No (Cloud) |  
| **Binary patching** | Via plugin or script | Limited | Native (`r2 -w`) | No (Cloud) |  
| **Binary diffing** | Via BinDiff / Diaphora | Via BinDiff / Diaphora | Native (`radiff2`) | Via plugin (paid) |  
| **Emulation** | Via extension (PCode emulation) | No (Free) | Native (ESIL) | No (Cloud) |  
| **Collaborative analysis** | Yes (Ghidra Server) | No (Free) | No (native) | Link sharing (Cloud) |  
| **ROP gadget search** | Via script | No (Free) | Native (`/R`) | No (Cloud) |  
| **YARA rules** | Via script | Via plugin | Via plugin | No (Cloud) |

## Detailed analysis by criterion

### Decompiler quality

The decompiler is often the decisive factor in choosing a tool, because it determines the speed at which an analyst understands the code.

**Ghidra** offers the best quality/accessibility ratio. Its decompiler is free, works offline, covers all supported architectures, and produces good-quality pseudo-code. On GCC x86-64 binaries, it correctly handles control structures, function calls, and most `-O2` optimization patterns. Its weaknesses appear on very optimized binaries (`-O3` with vectorization), on some `switch/case` reconstructions, and on the treatment of complex C++ types (templates, multiple inheritance). The pseudo-code tends to be verbose with explicit casts and generic variable names.

**IDA Pro** (paid version) is considered the reference in decompilation thanks to the Hex-Rays engine. The Free version offers a cloud decompiler with quotas, which makes it less practical for intensive use. When available, the result is often the most concise and readable of the four tools.

**Binary Ninja** stands out with its multi-level BNIL architecture (section 9.5). The HLIL decompiler produces clean and well-typed pseudo-code, sometimes more readable than Ghidra's thanks to better expression simplification. The ability to descend to MLIL or LLIL to verify a suspicious decompilation is a unique advantage. In the Cloud version, the decompiler is accessible without quota restriction.

**Radare2** does not have a native decompiler of comparable quality. The `pdc` command produces rudimentary pseudo-code. However, the `r2ghidra` plugin integrates Ghidra's decompiler directly into `r2` and Cutter, offering equivalent quality. It's the recommended solution.

### Function recognition and analysis of stripped binaries

This is an area where differences between tools are measurable and practically significant. On a stripped binary (`strip`), the tool must identify function bounds without the help of the symbol table, purely by heuristic.

**IDA** is historically the best at this exercise. Its function-prologue recognition algorithm, combined with FLIRT for statically linked libraries, often identifies 5 to 15% more functions than its competitors on hard cases. It's particularly visible on binaries with code mixed with data, or on binaries obfuscated with control-flow flattening.

**Ghidra** and **Binary Ninja** are close in performance, with a slight advantage to Binary Ninja on some optimized GCC patterns and an advantage to Ghidra on multi-architecture binaries thanks to its broader coverage.

**Radare2** is correct but can be behind on the hardest cases. The `aaaa` command with its aggressive heuristics catches up part of the lag, at the cost of potential false positives.

In practice, differences are often marginal on "clean" binaries compiled with GCC. They become significant on obfuscated binaries, packed binaries, or binaries statically linked with large libraries.

### Scripting and automation

This is a major differentiation axis between tools, and the criterion where the tool choice has the most impact on long-term productivity.

**Radare2** is the champion of lightweight automation and Unix integration. `r2pipe` allows driving analysis from Python with a few lines of code, the non-interactive mode (`r2 -qc`) integrates into any shell script, and each command's JSON output makes parsing trivial. For tasks like "analyze 200 binaries and produce a report", `r2` is unbeatable in terms of implementation simplicity.

**Ghidra** offers the most powerful scripting in the free ecosystem thanks to its rich object API. Java or Python scripts (via Pyhidra) have access to a complete model: programs, functions, instructions, types, memory, references. Headless mode (`analyzeHeadless`) allows batch analysis without a graphical interface. The API's learning curve is steeper than `r2pipe`'s, but the possibilities are significantly broader for complex analyses (type reconstruction, inter-procedural propagation, code transformation).

**Binary Ninja** (paid edition only) is often cited as having the best Python API in the industry: well-typed, well-documented, with abstractions specific to each BNIL level. But this API is not available in the free Cloud version.

**IDA Free** offers limited access to IDAPython. The Pro version has the most mature and best-documented API (thanks to 30 years of existence), but its price puts it out of reach of most individual users.

### Ergonomics and learning curve

**IDA** has the most mature and fluid interface. Keyboard shortcuts are logical and consistent, navigation is fast, and the tool responds well even on large binaries. An analyst experienced with IDA is extremely productive. The learning curve is moderate: the interface is intuitive for anyone who has used an IDE.

**Binary Ninja Cloud** offers the most modern and accessible experience. The web interface is clean, view synchronization is immediate, and getting started is quick. It's probably the easiest tool to approach for a complete beginner.

**Ghidra** suffers from a Java/Swing interface that may seem dated and sometimes slow, especially at startup and on large binaries. The organization in multiple windows (CodeBrowser, Symbol Tree, Decompiler, etc.) is powerful but requires adaptation time. The tool compensates with the richness of its features and its detailed official documentation.

**Radare2** has the steepest learning curve. The absence of a graphical interface by default, cryptic commands, and sometimes sparse documentation deter many beginners. In exchange, once the barrier is crossed, CLI productivity is remarkable. Cutter considerably attenuates this problem by offering a complete graphical interface.

### Collaborative work

**Ghidra** is the only free tool that offers an integrated collaborative work solution. Ghidra Server allows multiple analysts to work simultaneously on the same project, with a versioning and conflict-resolution system. It's a decisive advantage for teams.

**Binary Ninja Cloud** allows sharing links to an analysis, which is useful for communication but does not constitute real-time collaboration.

**IDA Free** and **Radare2** do not offer native collaborative features. Workarounds exist (IDA base export/import, `r2` projects shared via Git), but they are artisanal.

## Decision grid by scenario

Rather than an absolute ranking, here are recommendations by usage context. Each scenario indicates the tool to prioritize as first choice and the relevant alternatives.

### Learning RE and following this training

**First choice: Ghidra.** It's the tool this training is primarily built around (Chapter 8). Free, complete, with decompiler, and usable without restriction.

**Recommended complement: Radare2.** For CLI culture, scripting, and because a large part of CTF literature uses it.

### CTF and competitions

**First choice: Radare2 + Ghidra.** The combination `r2` for quick triage and scripting, and Ghidra for deep decompilation, is the most popular in the CTF community. `r2`'s speed in CLI is an advantage in timed-competition contexts.

**Alternative: Binary Ninja Cloud** for a quick second opinion on decompiled code, or **IDA Free** if the binary is x86-64.

### Enterprise malware analysis

**First choice: IDA Pro** (if budget allows). The industry reference, with the best decompiler, the largest base of FLIRT signatures, and the most mature plugin ecosystem for malware analysis.

**Free alternative: Ghidra.** The decompiler is free and of sufficient quality for the vast majority of analyses. Headless mode and Ghidra Server are assets for SOC teams.

**Complement: Radare2** for batch automation and scripted tasks (IOC extraction, entropy analysis, pattern searching).

### Vulnerability research and programmatic analysis

**First choice: Binary Ninja** (paid edition). The BNIL architecture and Python API are specifically designed for this type of analysis. Writing taint-analysis or pattern-matching queries on MLIL is notably more natural than on the textual pseudo-code of other tools.

**Free alternative: Ghidra** with Python scripting. The API is rich and the object model allows similar analyses, with a higher development cost.

### Firmware and exotic-architecture analysis

**First choice: Ghidra** for common architectures (ARM, MIPS, PowerPC) thanks to its multi-architecture decompiler.

**Complement: Radare2** for rare architectures (AVR, 8051, Z80, SPARC, etc.) thanks to its exceptional coverage.

**IDA Free and Binary Ninja Cloud** are ruled out in this scenario because limited to x86/x64 (IDA Free) or a subset of architectures (Binary Ninja Cloud).

### Quick scripting and pipeline integration

**First choice: Radare2 + r2pipe.** CLI mode, native JSON output, and non-interactive mode make it the most natural tool for integration into shell scripts, CI/CD pipelines, or automated analysis frameworks.

**Alternative: Ghidra headless.** Heavier to set up (JVM, launch scripts), but more powerful once configured thanks to the object API.

### Work on a remote server via SSH

**First choice: Radare2.** It's the only tool of the comparison that works comfortably in a terminal without a graphical environment. Visual modes (`V`, `VV`, `V!`) offer a terminal navigation experience.

**Limited alternative: Ghidra** in headless mode for batch analysis, but without an interactive interface.

## What's not in the tables

The comparison tables capture objective characteristics, but some less tangible factors deserve mention.

### Documentation and community

**IDA** benefits from 30 years of literature: thousands of write-ups, tutorials, university courses, and conference presentations. When you search "how to do X in RE", the answer is often in IDA language. It's a considerable ecosystem advantage.

**Ghidra** is quickly catching up since its 2019 release. Official documentation is good, and the community produces a growing volume of tutorials, plugins, and scripts. Being open source attracts academic and research contributions.

**Radare2** has official documentation (the *radare2 book*) and an active community, but the entry barrier remains the highest. Frequent updates can invalidate old tutorials.

**Binary Ninja** has very-good-quality official documentation for the API (paid edition), and an enthusiastic but more restricted community.

### Stability and maturity

**IDA** is the most stable and predictable tool. Releases are spaced and carefully tested. Behavior is consistent from one version to the next.

**Ghidra** is stable for an open-source tool of this scale, but some features (notably the decompiler on unusual patterns) can produce unexpected results. Major updates are regular.

**Binary Ninja** offers good stability in commercial versions. The Cloud version depends on Vector 35's infrastructure.

**Radare2** is the most dynamic tool in terms of development, which has a downside: occasional regressions between versions, interface changes, and documentation that can be out of sync with the installed version. The Rizin fork (Cutter's engine) adds a potential source of confusion.

### Career factor

In the professional RE world (threat intelligence, vulnerability research, forensics), **IDA Pro** remains the standard expected by employers. Mastering IDA and IDAPython is a CV asset. **Ghidra** is increasingly accepted and recognized, particularly in government agencies and teams that cannot justify IDA's cost. **Binary Ninja** is valued in academic research and vulnerability-research teams. **Radare2** is valued in the CTF community and among technical profiles that prioritize mastery of fundamentals.

The practical recommendation: master Ghidra as your main tool (free, complete, recognized), familiarize yourself with IDA (to read existing literature and be operational if your employer uses it), and keep Radare2 in your toolbelt for scripting and cases where CLI is an advantage.

## Recommendation for the rest of this training

For the following chapters (Part III — Dynamic Analysis, Part IV — Advanced Techniques, and Part V — Practical Cases), we will mainly use **Ghidra** for static analysis and decompilation, and **GDB** (Chapter 11) for dynamic analysis. Automation scripts will use **`r2pipe`** or **Ghidra scripting** depending on context. When an analysis benefits from cross-checking, we'll signal it and encourage you to compare with the tool of your choice.

What matters is not the tool, but the methodology. The chapters that follow focus on reverse-engineering techniques — tools are only the vehicle.

---


⏭️ [🎯 Checkpoint: analyze the same binary in 2 different tools, compare decompiler results](/09-ida-radare2-binja/checkpoint.md)
