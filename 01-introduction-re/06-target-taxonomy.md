🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 1.6 — Target taxonomy: native binary, bytecode, firmware — where this tutorial fits

> **Chapter 1 — Introduction to Reverse Engineering**  
> 📦 No technical prerequisites — reading section.  
> 📖 This section situates the scope of this training within the global landscape of reverse engineering.

---

## One term, many targets

The term "reverse engineering" is used to describe activities which, although they share a common goal (understanding how a system works without its documentation), are applied to targets that differ greatly in nature, complexity, and tooling. Reversing an x86-64 ELF binary compiled with GCC, reversing an Android application in Dalvik bytecode, reversing a MIPS router firmware, and reversing a network protocol captured with Wireshark are four activities that all fall under RE — but that require distinct skills, tools, and approaches.

This section maps out the territory. It describes the main categories of targets encountered in RE, explains how they differ, and situates precisely the scope covered by this training.

---

## The main target categories

### Native binaries

A **native binary** is an executable file containing machine code directly runnable by a processor. The compiler (GCC, Clang, MSVC, etc.) has transformed source code into a sequence of instructions specific to a given hardware architecture. The binary is tightly tied to two parameters: the **processor architecture** (x86-64, x86-32, ARM, AArch64, MIPS, RISC-V, PowerPC…) and the target **operating system**, which determines the executable file format and the calling conventions.

The three most common native binary formats are:

**ELF (Executable and Linkable Format)** — The standard format under Linux, the BSDs, and most Unix systems. This is the format this training focuses on. An ELF file contains headers that describe its structure, sections (`.text` for code, `.data` and `.rodata` for data, `.bss` for uninitialized data, `.plt`/`.got` for dynamic symbol resolution, etc.) and segments that define how the loader must map the file into memory. Chapter 2 covers the ELF structure in depth.

**PE (Portable Executable)** — The native format of Windows. Its structure differs from ELF's (DOS and PE headers, `.text`, `.rdata`, `.data` sections, Import Address Table, Export Directory), but the principles are comparable. RE of PE binaries is a field in its own right, dominant in Windows malware analysis. This training does not cover the PE format directly, but the analysis techniques (disassembly, debugging, instrumentation) are largely transferable.

**Mach-O (Mach Object)** — The native format of macOS and iOS. Used by binaries compiled with Xcode/Clang for Apple platforms. Its structure includes *load commands* that play a role analogous to ELF program headers. RE of Mach-O binaries is relevant for analyzing macOS and iOS applications, but remains a niche compared to ELF and PE.

**Characteristics of native-binary RE:**

- The analyzed code is **raw machine code** — instructions directly executed by the processor. There is no intermediate abstraction layer.  
- The **information loss** at compilation is at its maximum: types, variable names, source code structure — all is lost or heavily degraded (cf. section 1.1).  
- Analysis relies on **disassembly** (translating machine code into assembly) and **decompilation** (reconstructing high-level pseudo-code). The quality of these operations depends on the architecture, the compiler, the optimization level, and any protections in place.  
- Tools must know the **target architecture**: an x86-64 disassembler cannot analyze an ARM binary, and vice versa. Modern tools (Ghidra, Radare2, Binary Ninja) support many architectures; others (IDA Free) are more limited.

> 💡 **This is the central category of this training.** Parts I through VI focus exclusively on x86-64 ELF native binaries compiled with GCC/G++.

---

### Managed bytecode

**Bytecode** is an intermediate code, compiled not for a physical processor but for a software **virtual machine**. The source program is compiled into bytecode, and this bytecode is executed by a runtime which interprets it or compiles it on the fly (JIT — *Just-In-Time compilation*).

The two most widespread bytecode ecosystems are:

**Java / JVM (Java Virtual Machine)** — The `javac` compiler transforms Java code into JVM bytecode, stored in `.class` files grouped into `.jar` archives. The JVM executes this bytecode on any supported platform. Other languages also target the JVM: Kotlin, Scala, Groovy, Clojure.

**.NET / CIL (Common Intermediate Language)** — The C# (or VB.NET, F#) compiler produces CIL bytecode (formerly MSIL), stored in *assemblies* (`.dll` or `.exe` files in PE format with .NET metadata). The CLR (*Common Language Runtime*) executes this bytecode, either by interpreting it or by JIT-compiling it.

**Android / Dalvik-ART** — Android applications are compiled into Dalvik bytecode (`.dex` files), executed by the ART (*Android Runtime*) runtime. Since Android 5.0, ART compiles bytecode to native code at install time (AOT — *Ahead-Of-Time*), but analysis generally focuses on `.dex` bytecode or on the decompiled Java/Kotlin code.

**Characteristics of bytecode RE:**

- The **information loss is much smaller** than for native binaries. Bytecode keeps the names of classes, methods, and fields (unless an obfuscator has renamed them). Types are explicit. The structure of the program (inheritance, interfaces, exceptions) is preserved in the metadata.  
- **Decompilation is significantly more reliable**. Tools like JD-GUI, CFR, or Procyon (for Java), ILSpy or dnSpy (for .NET), and JADX (for Android) produce reconstructed source code that is often very close to the original — sometimes even directly recompilable.  
- **Obfuscation** techniques are the main obstacle: symbol renaming (classes, methods, variables replaced by `a`, `b`, `c`), string encryption, *control flow flattening*, *string encryption*, dynamic reflection. Deobfuscation tools (de4dot for .NET, various deobfuscators for Java) can partially counter these protections.  
- Analysis is **less dependent on the hardware architecture** since bytecode is portable. An analyst does not need to master a processor-specific instruction set — they do, however, need to understand the execution model of the target virtual machine.

> 💡 **Coverage in this training** — Part VII (chapters 30 to 32) offers a bonus path on RE of .NET/C# binaries, covering decompilation with ILSpy and dnSpy, hooking with Frida, and CIL bytecode patching. Java/Android RE is not covered.

---

### Firmware and embedded systems

A **firmware** is software embedded in a hardware component: router, IP camera, industrial controller, automotive controller, medical implant, connected object (IoT). Firmware is typically flashed into non-volatile memory (NOR/NAND flash, EEPROM) and executed by an embedded microprocessor or microcontroller.

**Characteristics of firmware RE:**

- **Extraction** of the firmware is often the first difficulty. Depending on the hardware, it can be obtained by downloading from the manufacturer's website (the easiest case), by dumping the flash chip via an SPI/JTAG programmer, by intercepting an OTA (*Over-The-Air*) update, or by exploiting a debug interface.  
- Firmware is often a **complete image** containing a filesystem (SquashFS, CramFS, JFFS2), a Linux kernel (or a proprietary RTOS), shared libraries, and application executables. The `binwalk` tool is the Swiss-army knife for extracting and identifying the components of a firmware image.  
- The **architectures** encountered are varied: ARM (the most common in IoT and mobile), MIPS (routers, access points), AArch64, PowerPC, Xtensa (ESP32), AVR, and Cortex-M (microcontrollers). The analyst must master — or at least be able to read — the instruction set of the target architecture.  
- Debugging often requires **specialized hardware**: JTAG/SWD probes, UART serial adapters, logic analyzers. Emulation with QEMU is an alternative that makes it possible to run the firmware (or isolated components) on a development machine without the original hardware.  
- **Vulnerabilities** are frequent and often critical: default passwords, unauthenticated network services, unencrypted communications, plaintext embedded private keys, debug commands not removed in production.

> 💡 **Coverage in this training** — Firmware RE is not covered directly. However, the skills acquired on ELF binaries (static analysis, disassembly, debugging) are directly transferable to application components extracted from a Linux firmware. If the firmware contains ARM ELF executables, for example, Ghidra analyzes them with the same techniques taught here — only the instruction set changes.

---

### Network protocols and file formats

RE does not always target executable code. Two categories of non-executable targets deserve mention:

**Network protocols** — Understanding an undocumented communication protocol by capturing and analyzing network traffic. The analyst observes the exchanges between a client and a server, identifies the structure of messages (headers, fields, delimiters, encodings), reconstructs the protocol's state machine, and can write an independent implementation. Key tools are Wireshark (packet capture and dissection), `strace` (socket-call tracing on the application side), and RE of the client or server binary to understand how messages are built and interpreted.

**File formats** — Understanding the structure of an undocumented proprietary file format. The analyst examines sample files with a hex editor, identifies magic bytes, fixed and variable fields, offsets, index tables, compressed or encrypted sections, and reconstructs the format specification. ImHex with its `.hexpat` patterns is the central tool of this activity.

> 💡 **Coverage in this training** — Both subjects are covered by dedicated practical cases. Chapter 23 deals with RE of a custom network protocol (identification, dissection, writing a replacement client). Chapter 25 deals with RE of a custom file format (mapping, parser fuzzing, writing an independent parser, documenting the format).

---

### Obfuscated source code (JavaScript, PHP, Python…)

Although not "reverse engineering" in the traditional sense, analysis of **deliberately obfuscated source code** in interpreted languages (minified/obfuscated JavaScript, encoded PHP, Python compiled to `.pyc`) is a related activity that uses some similar techniques.

JavaScript obfuscated with tools like *javascript-obfuscator* replaces variable names with unreadable sequences, encodes strings in hexadecimal, inserts dead code, and transforms control structures. The analyst must recognize the obfuscation patterns, decode the strings, simplify the control flow — operations conceptually close to RE of managed bytecode.

> 💡 **Coverage in this training** — This subject is not covered. It falls more under web analysis and application security than under binary RE. However, the fundamental principles (understanding a transformed control flow, identifying obfuscation patterns, reconstructing the original logic) are the same.

---

### Hardware and electronic circuits

At the far end of the spectrum, **hardware reverse engineering** consists of analyzing an electronic circuit — board, chip, ASIC, FPGA — to understand how it works. This can range from tracing the schematic of a PCB (component identification, track tracing) to imaging layers of an integrated circuit by microscopy to reconstruct its netlist.

Hardware RE is a discipline in its own right, requiring electronics skills, measurement instruments (oscilloscope, logic analyzer, soldering station), and sometimes expensive equipment (electron microscope, FIB station).

> 💡 **Coverage in this training** — Hardware RE is not covered. It is mentioned here only to complete the taxonomy and show the breadth of the field.

---

## Where this training fits

The table below summarizes the coverage of each target category in this training:

| Target category | Coverage | Parts |  
|---|---|---|  
| x86-64 ELF native binaries (GCC/G++) | **Full coverage** — this is the core of the training | I to VI |  
| ELF native binaries — other architectures (ARM, MIPS) | Not covered directly, but techniques and tools (Ghidra, GDB) are transferable | — |  
| PE native binaries (Windows) | Not covered, but the methodology applies | — |  
| .NET / C# bytecode | **Bonus coverage** — decompilation, hooking, patching | VII (ch. 30–32) |  
| Java / Android bytecode | Not covered | — |  
| Rust binaries (ELF) | **Bonus coverage** — compilation and analysis specifics | VIII (ch. 33) |  
| Go binaries (ELF) | **Bonus coverage** — runtime and symbol specifics | VIII (ch. 34) |  
| Custom network protocols | **Covered** — full practical case | V (ch. 23) |  
| Custom file formats | **Covered** — full practical case | V (ch. 25) |  
| Firmware / embedded systems | Not covered directly | — |  
| Obfuscated source code (JS, PHP, Python) | Not covered | — |  
| Hardware / circuits | Not covered | — |

### Why this scope?

The choice to focus on **x86-64 ELF native binaries compiled with GCC/G++** is deliberate:

**Depth rather than breadth.** Covering every architecture, every format, and every language superficially would not have made it possible to reach the level of detail required to be truly operational. By focusing on a single target, the training can explore each aspect in depth: ELF structure, System V calling conventions, GCC-specific patterns, C++ constructs under the Itanium ABI, optimizations at each level.

**The most representative target.** x86-64 is the dominant architecture on servers, workstations, and a large share of the cloud infrastructure. Linux is omnipresent in servers, containers, and high-end embedded systems. GCC is the default compiler on most Linux distributions. Mastering the RE of x86-64 ELF GCC binaries means being able to analyze a significant share of the software deployed worldwide.

**Skill transferability.** The concepts and methodology taught here — reading assembly, understanding a control flow graph, setting a breakpoint in the right place, recognizing a compiler's patterns, combining static and dynamic analysis — transfer directly to other architectures and formats. An analyst who masters x86-64 ELF RE can get into PE Windows RE or ARM firmware RE in a few weeks of adaptation, because the fundamental principles are the same. Only the details change: the instruction set, the binary format, the calling conventions, the specific tools.

**The bonuses to broaden.** Parts VII and VIII offer entry points toward .NET bytecode and Rust/Go binaries. These parts are not aiming for exhaustiveness — they show the specifics of each target compared to the ELF/C/C++ foundation built in the main parts, and provide the keys to further self-directed study.

---

> 📖 **Takeaway** — Reverse engineering covers a very broad spectrum of targets: native binaries, managed bytecode, firmware, protocols, file formats, hardware. This training focuses on x86-64 ELF native binaries compiled with GCC/G++, with extensions to .NET, Rust, and Go. This choice favors depth over breadth while teaching a methodology and skills directly transferable to the other target categories.

---


⏭️ [🎯 Checkpoint: classify 5 given scenarios as "static" or "dynamic"](/01-introduction-re/checkpoint.md)
