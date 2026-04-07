🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix G — Comparison of Native Tools (tool / usage / free / CLI or GUI)

> 📎 **Reference sheet** — This appendix summarizes all the tools presented in the training course for reverse engineering native binaries (ELF x86-64). For each tool, it indicates its usage category, its interface (command line or graphical), its license, the chapters where it is covered, and an assessment of its difficulty level. It helps you choose the right tool for your needs without having to re-read the introductory chapters.

---

## How to read this comparison

The tools are grouped by functional category. The columns are as follows:

| Column | Meaning |  
|---------|---------------|  
| **Tool** | Name of the tool |  
| **Primary usage** | What the tool is most used for in RE |  
| **Interface** | CLI (command line), GUI (graphical interface), or both |  
| **Free** | Yes = entirely free, Freemium = limited free version, Paid = commercial license |  
| **License** | Type of open source or proprietary license |  
| **OS** | Supported operating systems |  
| **Chapters** | Training course chapters where the tool is covered |  
| **Difficulty** | Estimated learning curve (★ easy → ★★★ advanced) |

---

## 1 — Binary inspection and triage

These tools are the first ones you use when facing an unknown binary. They answer the basic questions: what is this file, what does it contain, how is it protected?

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| `file` | Identify the type of a file (ELF, PE, script, data) | CLI | Yes | BSD | Linux, macOS | 5.1 | ★ |  
| `strings` | Extract printable strings from a binary | CLI | Yes | GPL (GNU) | Linux, macOS | 5.1 | ★ |  
| `xxd` | Compact hexadecimal dump | CLI | Yes | GPL (Vim) | Linux, macOS | 5.1 | ★ |  
| `hexdump` | Configurable hexadecimal dump | CLI | Yes | BSD | Linux, macOS | 5.1 | ★ |  
| `readelf` | Inspection of ELF headers, sections, segments, symbols and relocations | CLI | Yes | GPL (GNU Binutils) | Linux | 2.4, 5.2 | ★★ |  
| `objdump` | Basic disassembly and inspection of ELF sections | CLI | Yes | GPL (GNU Binutils) | Linux | 5.2, 7.1–7.7 | ★★ |  
| `nm` | List the symbols of a binary (functions, variables, types) | CLI | Yes | GPL (GNU Binutils) | Linux | 5.3 | ★ |  
| `c++filt` | Demangling of C++ symbols (Itanium ABI) | CLI | Yes | GPL (GNU) | Linux | 7.6, 17.1 | ★ |  
| `ldd` | List shared library dependencies | CLI | Yes | GPL (glibc) | Linux | 5.4 | ★ |  
| `ldconfig` | Manage the shared library cache | CLI | Yes | GPL (glibc) | Linux | 5.4 | ★ |  
| `checksec` | Inventory of binary protections (ASLR, PIE, NX, canary, RELRO, Fortify) | CLI | Yes | Apache 2.0 | Linux | 5.6, 19.9 | ★ |  
| `binwalk` | Detection of embedded formats, signatures and entropy | CLI | Yes | MIT | Linux, macOS | 25.1 | ★ |  
| `rabin2` | Binary metadata analysis (Radare2 suite) | CLI | Yes | LGPL3 | Linux, macOS, Windows | 9.2 | ★★ |

### When to use which triage tool?

The recommended triage workflow (Chapter 5.7) chains these tools in a logical order. `file` identifies the format, `strings` reveals significant strings, `readelf -S` shows the section structure, `readelf -d` and `ldd` identify dependencies, `checksec` inventories the protections, and `nm` or `objdump -t` lists the available symbols. This 5-minute pipeline is the foundation of any analysis.

For a quick triage in a single command, `rabin2 -I` from the Radare2 suite provides a summary that combines the information from `file`, `checksec`, and `readelf` in a single output.

---

## 2 — Hexadecimal analysis

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **ImHex** | Advanced hexadecimal editor with `.hexpat` pattern language, structured visualization, bookmarks, diff, YARA | GUI | Yes | GPL2 | Linux, macOS, Windows | 6.1–6.11, 21.6, 24.4, 25.2 | ★★ |

ImHex is in a category of its own. It far surpasses traditional hexadecimal editors thanks to its pattern language (see Appendix E), which allows you to visualize binary structures with colors and a tree view, compare two versions of a binary, search for magic bytes, and apply YARA rules. It is the tool of choice for mapping file formats and precise patching.

Alternative hexadecimal editors like `HxD` (Windows), `010 Editor` (paid, cross-platform) and `Hex Fiend` (macOS) can be useful in a pinch but do not offer the pattern language that makes ImHex so powerful for RE.

---

## 3 — Disassemblers and decompilers

This is the premier category of RE. Disassemblers transform machine code into readable assembly, and decompilers attempt to reconstruct pseudo-C code from the assembly.

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **Ghidra** | Complete disassembler + decompiler, automatic analysis, Java/Python scripts, headless mode | GUI (+ headless CLI) | Yes | Apache 2.0 (NSA) | Linux, macOS, Windows | 8.1–8.9, 20.2 | ★★ |  
| **IDA Free** | Industry-standard interactive disassembler (free version limited to x86-64 cloud decompiler) | GUI | Freemium | Proprietary (Hex-Rays) | Linux, macOS, Windows | 9.1 | ★★ |  
| **IDA Pro** | Full version of IDA with local decompiler, multi-architecture, plugin SDK | GUI | Paid | Proprietary (Hex-Rays) | Linux, macOS, Windows | 9.1 | ★★★ |  
| **Radare2** | Command-line RE framework: disassembly, debugging, patching, scripting | CLI | Yes | LGPL3 | Linux, macOS, Windows | 9.2–9.4 | ★★★ |  
| **Cutter** | Graphical interface for Radare2 with integrated decompiler | GUI | Yes | GPL3 | Linux, macOS, Windows | 9.2 | ★★ |  
| **Binary Ninja** | Modern disassembler + decompiler with powerful intermediate IL | GUI | Freemium (free Cloud) | Proprietary (Vector 35) | Linux, macOS, Windows | 9.5 | ★★ |  
| **RetDec** | Standalone static decompiler (offline, no interactive interface) | CLI | Yes | MIT (Avast) | Linux, macOS, Windows | 20.3 | ★★ |  
| `objdump -d` | Basic disassembly (linear, no flow analysis) | CLI | Yes | GPL (GNU Binutils) | Linux | 7.1–7.7 | ★ |

### Which disassembler to choose?

The choice of disassembler depends on your budget, your comfort with the command line, and the complexity of the target binary.

**Ghidra** is the recommended default choice in this training course. It is entirely free, its decompiler is of good quality (comparable to IDA on many binaries), it supports Java and Python scripting, and the headless mode allows batch automation. Its drawbacks are a sometimes slow Java interface and a long initial analysis time on large binaries.

**IDA Pro** remains the industry reference. Its Hex-Rays decompiler is generally considered the best on the market, especially on optimized code and C++. Its SDK enables a very rich plugin ecosystem (BinDiff, Diaphora, FLIRT, etc.). Its high price (several thousand euros) restricts it to professionals. The IDA Free version is a good compromise for getting started with the IDA interface.

**Radare2** is the tool for power users who prefer the command line. Its strength is command composability, scripting via r2pipe, and the fact that it works on any terminal (SSH on a remote server, for example). Its learning curve is the steepest of all the tools listed here. **Cutter** mitigates this difficulty by providing a GUI, and the r2ghidra plugin gives it access to Ghidra's decompiler.

**Binary Ninja** is a modern tool that stands out through its intermediate representations (LLIL, MLIL, HLIL) enabling sophisticated programmatic analyses. The free Cloud version is sufficient to discover the tool. The commercial version is less expensive than IDA Pro.

**RetDec** is useful as a complement: you can pass it a binary and get pseudo-C code without an interactive interface. The decompilation quality is lower than Ghidra and IDA, but it can serve as a quick "second opinion."

**`objdump`** is always available on any Linux system and requires no installation. It is perfect for a quick disassembly of a function, but it only does linear disassembly (no function detection, no xrefs, no decompilation). It is the starting point before pulling out a heavier tool.

---

## 4 — Debuggers

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **GDB** | Reference Linux native debugger: breakpoints, memory inspection, Python scripting | CLI | Yes | GPL (GNU) | Linux, macOS | 11.1–11.9 | ★★ |  
| **GEF** | GDB extension: enriched context, checksec, heap, ROP gadgets, patterns | CLI (GDB extension) | Yes | MIT | Linux | 12.1–12.5 | ★★ |  
| **pwndbg** | GDB extension: advanced heap visualization, emulation, telescope, navigation | CLI (GDB extension) | Yes | MIT | Linux | 12.1–12.5 | ★★ |  
| **PEDA** | GDB extension: older, colored context, pattern search | CLI (GDB extension) | Yes | BSD | Linux | 12.1 | ★★ |  
| **r2 (debug)** | Debugger integrated into Radare2 (`-d` mode) | CLI | Yes | LGPL3 | Linux, macOS, Windows | 9.2 | ★★★ |

### GDB vs extensions: which one to install?

Native GDB is essential — it is the foundation. The extensions (GEF, pwndbg, PEDA) are installed on top and do not modify GDB itself. You only activate **one at a time** in your `.gdbinit`.

**GEF** is recommended for beginners and RE analysts. It is the easiest to install (a single Python file), has clear documentation, and its command set covers RE and basic exploitation well.

**pwndbg** is recommended for exploitation and heap analysis. Its `vis_heap_chunks`, `bins`, `tcachebins`, and `emulate` commands are superior to GEF's for working with the glibc heap. It is also the most actively maintained.

**PEDA** is the historic extension. It remains functional but is less actively developed than GEF and pwndbg. Choose it if you work in a constrained environment where installing GEF/pwndbg dependencies is difficult.

The correspondence table between GEF and pwndbg is in Appendix C, §13.

---

## 5 — Dynamic instrumentation and tracing

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| `strace` | Trace the system calls of a process | CLI | Yes | BSD/GPL | Linux | 5.5, 23.1 | ★ |  
| `ltrace` | Trace calls to shared library functions | CLI | Yes | GPL | Linux | 5.5 | ★ |  
| **Frida** | Dynamic instrumentation: function hooking, live argument/return modification, stalker (coverage) | CLI + JS scripting | Yes | wxWindows | Linux, macOS, Windows, Android, iOS | 13.1–13.7 | ★★★ |  
| **pwntools** | Python framework for automated interaction with binaries (I/O, patching, exploitation) | CLI (Python lib) | Yes | MIT | Linux | 11.9, 21.8, 23.5, 35.3 | ★★ |

### When to use strace/ltrace vs Frida?

`strace` and `ltrace` are passive tools that do not modify the program's behavior — they simply list the calls. They are perfect for a first overview of what a binary does: which files it opens, which network connections it establishes, which libc functions it calls. No special installation is required, they are available on any Linux system.

Frida is an active tool that can **modify** the program's behavior in real time: change a function's arguments, replace its return value, inject JavaScript code into the target process. It is much more powerful but also more complex. Frida is the tool of choice when you need to bypass a check (license, anti-debug) or when you need to log information internal to the program (memory buffers, crypto keys before encryption).

pwntools is not a tracing tool per se but an interaction framework. It automates stdin/stdout exchanges with a binary, file patching, exploit construction, and network communication. It is the Swiss army knife of exploitation and RE scripting in Python.

---

## 6 — Memory analysis and profiling

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **Valgrind (Memcheck)** | Detection of memory leaks, invalid accesses, use of uninitialized memory | CLI | Yes | GPL | Linux, macOS | 14.1 | ★★ |  
| **Callgrind** (+ KCachegrind) | Execution profiling, call graph, instruction counting | CLI + GUI (KCachegrind) | Yes | GPL | Linux | 14.2 | ★★ |  
| **AddressSanitizer (ASan)** | Detection of buffer overflows, use-after-free, memory leaks (compile-time) | CLI (GCC/Clang flag) | Yes | Part of GCC/Clang | Linux, macOS | 14.3 | ★ |  
| **UBSan** | Detection of undefined behaviors (signed overflow, null deref, shift) | CLI (GCC/Clang flag) | Yes | Part of GCC/Clang | Linux, macOS | 14.3 | ★ |  
| **MSan** | Detection of use of uninitialized memory (Clang only) | CLI (Clang flag) | Yes | Part of Clang | Linux | 14.3 | ★ |

### When to use Valgrind vs sanitizers?

Valgrind is a *post-compilation* analysis tool: you use it on an already compiled binary, without recompiling it. This is its main advantage in RE, since you do not always have access to the source code. It works through emulation (the binary runs inside a Valgrind virtual machine), which makes it approximately 20 to 50 times slower than native execution. Despite this slowness, Valgrind is irreplaceable for analyzing the memory behavior of a binary for which you do not have the source.

The sanitizers (ASan, UBSan, MSan) are *compile-time* instrumentations: you recompile the source code with `-fsanitize=address` (or `undefined`, `memory`). They are much faster than Valgrind (only a 2x slowdown for ASan) and detect certain bugs that Valgrind misses (and vice versa). They can only be used when you have access to the source code or can recompile the binary.

In RE, Valgrind is the default tool. Sanitizers come into play when you have reconstructed partial source code and want to test it, or when you are working on this training course's practice binaries (whose source is provided).

---

## 7 — Fuzzing

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **AFL++** | Coverage-guided fuzzing with compile-time or QEMU instrumentation | CLI | Yes | Apache 2.0 | Linux | 15.2, 25.3 | ★★ |  
| **libFuzzer** | In-process fuzzing integrated into Clang/LLVM | CLI (integrated into binary) | Yes | Apache 2.0 (LLVM) | Linux, macOS | 15.3 | ★★ |

AFL++ is the reference fuzzer for RE because it supports QEMU mode (`afl-fuzz -Q`), which allows fuzzing a binary **without recompiling it**. This makes it directly applicable to target binaries for which you do not have the source. libFuzzer requires recompiling the source code with Clang and offers superior performance but requires access to the source.

---

## 8 — Symbolic execution and solvers

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **angr** | Symbolic execution of binaries: path exploration, automatic constraint solving | CLI (Python lib) | Yes | BSD | Linux, macOS | 18.2–18.6, 21.7 | ★★★ |  
| **Z3** | SMT solver: solving logical and arithmetic constraints extracted manually | CLI (Python/C++ lib) | Yes | MIT (Microsoft) | Linux, macOS, Windows | 18.4 | ★★★ |

angr and Z3 are the two sides of symbolic execution in RE. angr is a complete framework that loads a binary, explores its execution paths, and uses Z3 internally to solve constraints. You use it when you want to solve a crackme or find an input that reaches a specific point in the program, in a semi-automatic way.

Z3 alone is useful when you have manually extracted the constraints of an algorithm (by reading the disassembly) and want to find a solution. It is more precise but requires more manual work than angr.

---

## 9 — Binary diffing

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **BinDiff** | Structural comparison of two binaries (matched functions, difference graphs) | GUI (Ghidra/IDA plugin) | Yes | Proprietary (Google) | Linux, macOS, Windows | 10.2 | ★★ |  
| **Diaphora** | Open source binary diffing (Ghidra/IDA plugin) | GUI (plugin) | Yes | AGPL | Linux, macOS, Windows | 10.3 | ★★ |  
| `radiff2` | Command-line diffing (Radare2 suite) | CLI | Yes | LGPL3 | Linux, macOS, Windows | 10.4 | ★★ |

BinDiff (formerly Zynamics, acquired by Google) is the most mature diffing tool. It compares two binaries at the function, basic block, and control flow graph levels, and produces a clear visualization of the differences. It works as a plugin for Ghidra or IDA: you export the analyses of the two binaries, then BinDiff compares them.

Diaphora offers similar functionality in open source. Its advantage is its ability to detect similar functions even when they have been significantly modified (advanced matching heuristics).

`radiff2` is more limited but works entirely in CLI, making it scriptable and usable in automated pipelines.

---

## 10 — Programmatic ELF parsing and manipulation

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **pyelftools** | Parsing ELF and DWARF files in Python (read-only) | Python lib | Yes | Public domain | Linux, macOS | 35.1 | ★★ |  
| **LIEF** | Parsing and modifying ELF, PE, Mach-O binaries in Python/C++ | Python/C++ lib | Yes | Apache 2.0 | Linux, macOS, Windows | 35.1 | ★★ |  
| **r2pipe** | Python interface to Radare2 (sends commands, retrieves results) | Python lib | Yes | LGPL3 | Linux, macOS, Windows | 9.4, 35.3 | ★★ |

pyelftools is the library of choice for reading an ELF in Python: extracting headers, sections, symbols, and DWARF information. It is read-only — you cannot modify the binary with it.

LIEF goes further: it can read **and modify** a binary (add/remove sections, change the entry point, modify imports). It is the ideal tool for programmatic patching and static instrumentation. It supports ELF, PE, and Mach-O, making it versatile.

r2pipe is not an ELF parser but an interface to the full capabilities of Radare2 from Python. Its advantage is leveraging all of r2's analysis (functions, xrefs, decompilation) rather than reimplementing a parser.

---

## 11 — Threat detection and analysis

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **YARA** | Binary pattern detection through rules (malware signatures, crypto constants, packers) | CLI (+ ImHex integration) | Yes | Apache 2.0 (VirusTotal) | Linux, macOS, Windows | 6.10, 27.4, 35.4 | ★★ |  
| **UPX** | ELF and PE binary packer/unpacker | CLI | Yes | GPL | Linux, macOS, Windows | 19.2, 29.1 | ★ |

YARA is the industry standard for writing detection signatures. You describe a pattern (byte sequence, strings, logical conditions) and YARA searches for it in a file or set of files. ImHex integrates a YARA engine directly into its interface (Chapter 6.10).

UPX is both a binary compression tool and an RE tool: `upx -d` decompresses a binary packed with UPX. This is often the first step when facing a packed binary, before attempting more advanced unpacking techniques.

---

## 12 — Network analysis

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **Wireshark** | Network traffic capture and analysis with protocol dissectors | GUI (+`tshark` CLI) | Yes | GPL2 | Linux, macOS, Windows | 23.1 | ★★ |  
| `tcpdump` | Command-line network packet capture | CLI | Yes | BSD | Linux, macOS | 26.3 | ★★ |

Wireshark is not an RE tool per se, but it is indispensable for analyzing network binaries (Chapter 23). When you are analyzing a custom client/server, Wireshark network capture combined with `strace` on socket calls is the best way to identify the protocol.

---

## 13 — Sandbox and monitoring

| Tool | Primary usage | Interface | Free | License | OS | Chapters | Difficulty |  
|-------|----------------|-----------|---------|---------|-----|-----------|------------|  
| **QEMU** | Full system emulation (VM for analysis sandbox) or user-mode emulation (for AFL++ fuzzing) | CLI | Yes | GPL2 | Linux, macOS | 4.3, 26.2 | ★★ |  
| **VirtualBox** | Desktop virtualization (analysis VM with snapshots) | GUI | Yes | GPL2 | Linux, macOS, Windows | 4.3 | ★ |  
| `auditd` | System event monitoring (file access, executions, network) | CLI | Yes | GPL | Linux | 26.3 | ★★ |  
| `inotifywait` | Monitor file system modifications in real time | CLI | Yes | GPL | Linux | 26.3 | ★ |  
| `sysdig` | System event capture and filtering (advanced alternative to strace + auditd) | CLI | Yes (OSS) | Apache 2.0 | Linux | 26.3 | ★★ |

---

## 14 — Additional tools from the Radare2 suite

The Radare2 suite includes several satellite tools covered in Appendix D. Here is a summary for the comparison:

| Tool | Primary usage | Interface | Chapters |  
|-------|----------------|-----------|-----------|  
| `rasm2` | Command-line assembler/disassembler | CLI | 9.2 |  
| `rahash2` | Hash computation, entropy, encoding/decoding | CLI | 9.2 |  
| `radiff2` | Binary diffing | CLI | 10.4 |  
| `rafind2` | Pattern search in files | CLI | 9.2 |  
| `ragg2` | De Bruijn pattern and shellcode generator | CLI | 9.2 |  
| `rarun2` | Execution launcher with controlled environment | CLI | 9.2 |  
| `rax2` | Base converter and calculator | CLI | 9.2 |

---

## 15 — Summary table by use case

This table directs you straight to the right tool based on what you are trying to do.

| Need | Recommended tool | Alternative |  
|--------|------------------|-------------|  
| Identify an unknown file | `file` + `strings` + `readelf` | `rabin2 -I` |  
| Check a binary's protections | `checksec` | `rabin2 -I`, GEF `checksec` |  
| Quickly disassemble a function | `objdump -d -M intel` | `r2 -A` → `pdf` |  
| Complete static analysis | **Ghidra** | IDA Pro, Binary Ninja |  
| Decompile to pseudo-C code | **Ghidra** (integrated decompiler) | IDA Pro (Hex-Rays), Cutter + r2ghidra |  
| Debug a binary step by step | **GDB** + GEF/pwndbg | r2 in debug mode |  
| Trace system calls | `strace` | `sysdig` |  
| Trace library calls | `ltrace` | Frida |  
| Hook functions live | **Frida** | `LD_PRELOAD`, GDB scripting |  
| Analyze the glibc heap | **pwndbg** (`vis_heap_chunks`) | GEF (`heap bins`) |  
| Visualize a binary format | **ImHex** (`.hexpat` patterns) | 010 Editor |  
| Compare two versions of a binary | **BinDiff** | Diaphora, `radiff2` |  
| Solve a crackme automatically | **angr** | Z3 (manual constraints) |  
| Fuzz a binary without the source | **AFL++** (QEMU mode) | — |  
| Fuzz with the source | **AFL++** (instrumentation) or **libFuzzer** | — |  
| Detect a packer / remove it | `checksec` + **UPX** (`upx -d`) | ImHex (entropy), GDB (memory dump) |  
| Scan for patterns (malware, crypto) | **YARA** | ImHex (search), `rafind2` |  
| Patch a binary on disk | **ImHex** or `r2 -w` | LIEF (Python), `pwntools` |  
| Automate the analysis of N binaries | **Ghidra headless** + Python | r2pipe + Python scripts |  
| Parse/modify an ELF in Python | **LIEF** | pyelftools (read-only) |  
| Capture network traffic | **Wireshark** / `tcpdump` | `sysdig` |  
| Create an analysis sandbox | **QEMU**/KVM or **VirtualBox** | UTM (macOS) |

---

## 16 — Budget: building a completely free RE lab

This entire training course can be followed with **100% free** tools. Here is the recommended toolkit for a budget of zero:

| Category | Free tool | Paid replacement (if budget available) |  
|-----------|---------------|---------------------------------------------|  
| Disassembler + decompiler | Ghidra | IDA Pro |  
| CLI disassembler | Radare2 / objdump | — |  
| GUI for r2 | Cutter + r2ghidra | Binary Ninja |  
| Debugger | GDB + GEF or pwndbg | — |  
| Hexadecimal editor | ImHex | 010 Editor |  
| Dynamic instrumentation | Frida | — |  
| Fuzzer | AFL++ | — |  
| Symbolic execution | angr + Z3 | — |  
| Diffing | Diaphora | BinDiff (also free) |  
| Scripting | pwntools + LIEF + pyelftools + r2pipe | — |  
| Virtualization | QEMU / VirtualBox | VMware Workstation Pro |  
| Network | Wireshark + tcpdump | — |  
| Pattern detection | YARA | — |

All of these tools are covered in the training course and the essential commands are documented in Appendices C, D, and E.

---

> 📚 **To go further**:  
> - **Appendix H** — [.NET Tools Comparison](/appendices/appendix-h-dotnet-tools-comparison.md) — the same comparison for the .NET/C# ecosystem.  
> - **Appendix C** — [GDB / GEF / pwndbg Cheat Sheet](/appendices/appendix-c-cheatsheet-gdb.md) — detailed debugger commands.  
> - **Appendix D** — [Radare2 / Cutter Cheat Sheet](/appendices/appendix-d-cheatsheet-radare2.md) — detailed r2 commands.  
> - **Appendix E** — [ImHex Cheat Sheet](/appendices/appendix-e-cheatsheet-imhex.md) — reference `.hexpat` syntax.  
> - **Chapter 4** — [Setting Up the Work Environment](/04-work-environment/README.md) — installation and configuration of all these tools.  
> - **Chapter 9, Section 9.6** — [Ghidra vs IDA vs Radare2 vs Binary Ninja Comparison](/09-ida-radare2-binja/06-tools-comparison.md) — detailed analysis of the 4 major disassemblers.

⏭️ [.NET Tools Comparison (ILSpy / dnSpy / dotPeek / de4dot)](/appendices/appendix-h-dotnet-tools-comparison.md)
