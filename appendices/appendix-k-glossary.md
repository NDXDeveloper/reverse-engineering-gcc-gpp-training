🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix K — Reverse Engineering Glossary

> 📎 **Reference sheet** — This glossary defines the technical terms used throughout the course. Each entry refers to the chapter where the concept is first introduced. Terms are listed in alphabetical order. Acronyms are listed in their abbreviated form, with the full expansion in the definition.

---

## A

**ABI** (*Application Binary Interface*) — Set of conventions governing the binary interface between a compiled program and the operating system or libraries: calling conventions, structure layout, type sizes, exception handling. On Linux x86-64, the reference ABI is System V AMD64 ABI. *(Chapters 2, 3 — Appendix B)*

**Virtual address** (*Virtual Address*, VA) — Address seen by the running process, as opposed to the physical address in RAM. Each process has its own virtual address space, managed by the processor's MMU. *(Chapter 2.8)*

**AFL++** (*American Fuzzy Lop plus plus*) — Coverage-guided fuzzer that automatically generates inputs to discover crashes and execution paths in a binary. Supports compile-time instrumentation and QEMU mode for binaries without source code. *(Chapter 15.2)*

**Dynamic analysis** — RE technique that consists of executing the target program and observing its behavior in real time: memory, registers, system calls, network traffic. Complementary to static analysis. *(Chapter 1.4)*

**Static analysis** — RE technique that consists of examining the binary without executing it: disassembly, decompilation, inspection of sections, strings, and symbols. *(Chapter 1.4)*

**angr** — Python-based symbolic execution framework capable of automatically exploring a binary's execution paths and solving constraints on inputs. Uses Z3 internally. *(Chapter 18.2)*

**Anti-debugging** — Set of techniques used by a program to detect the presence of a debugger and modify its behavior accordingly (crash, false results, infinite loop). Examples: `ptrace` check, timing checks with `rdtsc`, reading `/proc/self/status`. *(Chapter 19.7)*

**ASan** (*AddressSanitizer*) — Compile-time instrumentation (GCC/Clang, `-fsanitize=address`) that detects memory errors at runtime: buffer overflows, use-after-free, double-free, memory leaks. *(Chapter 14.3)*

**ASLR** (*Address Space Layout Randomization*) — Operating system protection that randomizes the base addresses of the stack, heap, shared libraries, and (with PIE) the binary itself at each execution, making vulnerability exploitation more difficult. *(Chapter 2.8)*

**Assembly** (.NET) — In the .NET ecosystem, a deployment and versioning unit containing CIL bytecode, metadata, and resources. Corresponds to a .NET `.exe` or `.dll` file. Not to be confused with x86 assembly code. *(Chapter 30.2)*

---

## B

**Base address** — Address at which a binary or library is loaded into memory. In PIE/ASLR mode, this address is randomized at each execution. The default base address for a non-PIE ELF executable is typically `0x400000`. *(Chapter 2.8)*

**Basic block** — Contiguous sequence of instructions with no internal branching: execution enters at the beginning and exits at the end (a jump, a call, or a return). Control flow graphs (CFGs) are built from basic blocks. *(Chapter 8.3)*

**Binutils** — Collection of GNU tools for manipulating binary files: `as` (assembler), `ld` (linker), `objdump`, `readelf`, `nm`, `objcopy`, `strip`, `c++filt`, `ar`. *(Chapters 5, 7)*

**Basic block** — See *Basic block*.

**Breakpoint** — Halt point placed in a debugged program. The debugger temporarily replaces the instruction at the target address with the `int 3` opcode (`0xCC`), which triggers a trap when execution reaches that point. Can be software (memory) or hardware (DR0–DR3 registers). *(Chapter 11.2)*

**BSS** (*Block Started by Symbol*) — ELF section (`.bss`) containing global and static variables initialized to zero. Takes no space in the binary file — the space is allocated and zeroed by the loader at load time. *(Chapter 2.4 — Appendix F)*

---

## C

**Callee-saved register** — Register whose value must be restored by a function before returning to its caller. On System V AMD64: `rbx`, `rbp`, `rsp`, `r12`–`r15`. Also called *non-volatile register*. *(Chapter 3.5 — Appendix B)*

**Caller-saved register** — Register that can be freely overwritten by a called function. The caller must save its value if it still needs it after the `call`. On System V AMD64: `rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`. Also called *volatile register*. *(Chapter 3.5 — Appendix B)*

**Canary** (*stack canary*, *stack protector*) — Sentinel value placed on the stack between local variables and the return address to detect buffer overflows. On GCC x86-64 with glibc, the canary is read from `fs:[0x28]` (TLS). Enabled by `-fstack-protector`. *(Chapter 19.5 — Appendix I, §10)*

**Catchpoint** — In GDB, a breakpoint triggered by a specific system event (system call, fork, exec, library load, signal, C++ exception) rather than by reaching an address. *(Chapter 11.6)*

**CFG** (*Control Flow Graph*) — Directed graph representing a function's execution flow: nodes are basic blocks, edges are jumps and fall-throughs. Displayed by Ghidra (Function Graph), Radare2 (`VV`), and Cutter. *(Chapter 8.3)*

**CIL** (*Common Intermediate Language*) — Bytecode of the .NET platform into which C#, F#, and VB.NET languages are compiled. Equivalent of machine code for the .NET runtime (CLR). CIL is compiled into native code by the JIT at runtime. *(Chapter 30.1)*

**COMDAT** — ELF mechanism allowing the linker to merge duplicated sections (typically C++ template instantiations): only one copy is kept in the final binary. *(Chapter 17.6)*

**Control Flow Flattening** — Obfuscation technique that transforms a function's natural control flow (if/else, loops) into a large `switch` inside a loop, making the CFG unreadable. Each original basic block becomes a `case` in the switch. *(Chapter 19.3)*

**Calling convention** — Set of rules defining how arguments are passed to a function, how the return value is transmitted, and which registers must be preserved. On Linux x86-64: System V AMD64 ABI. *(Chapter 3.5 — Appendix B)*

**Core dump** — File produced by the operating system when a process crashes (SIGSEGV, SIGABRT, etc.), containing the complete memory image of the process at the time of the crash. Analyzable with GDB (`gdb -c core ./binary`). *(Chapter 11)*

**Coverage** (*code coverage*) — Measure of the proportion of a program's code that has been executed during testing or fuzzing. Coverage-guided fuzzing uses this measure to guide the generation of new inputs toward unexplored paths. *(Chapter 15.5)*

**Crackme** — Program designed as a reverse engineering challenge: the objective is to find a password, a serial key, or to bypass a verification. Used for educational purposes and in CTFs. *(Chapter 21)*

**Cross-reference** (*XREF*) — Link in static analysis indicating that an address (function, variable, string) is referenced from another address. Two types: *xref to* (what references this address) and *xref from* (what this address references). Fundamental navigation tool in disassembly. *(Chapter 8.7)*

**CTF** (*Capture The Flag*) — Information security competition where participants solve challenges (RE, exploitation, crypto, web, forensics) to obtain "flags" (validation strings). *(Chapter 1.3)*

---

## D

**de4dot** — Open source deobfuscator for .NET assemblies. Automatically detects the obfuscator used and applies reverse transformations: name restoration, string decryption, control flow simplification. *(Chapter 31.5 — Appendix H)*

**Decompiler** — Tool that transforms machine code (or bytecode) into pseudo-code in a high-level language (C, C#). Examples: Ghidra decompiler, Hex-Rays (IDA), ILSpy (.NET). The result is an approximation of the original source code, never an exact reconstruction for native binaries. *(Chapter 20)*

**Demangle** — Operation of decoding C++ symbol names transformed by *name mangling*. The `c++filt` tool (GNU) converts, for example, `_ZN5MyApp4mainEi` to `MyApp::main(int)`. *(Chapter 7.6)*

**Disassembler** — Tool that transforms binary machine code into human-readable assembly instructions. Two approaches: linear disassembly (sequential traversal) and recursive disassembly (follows branches). Examples: `objdump`, Ghidra, IDA, Radare2. *(Chapters 7, 8, 9)*

**Diffing** (*binary diffing*) — Technique of comparing two versions of the same binary to identify modified, added, or removed functions. Used for security patch analysis (patch diffing). Tools: BinDiff, Diaphora, `radiff2`. *(Chapter 10)*

**dnSpy** / **dnSpyEx** — All-in-one .NET decompiler, debugger, and editor. Allows setting breakpoints on decompiled C# code, editing IL or C# code directly, and saving modifications. dnSpyEx is the actively maintained community fork. *(Chapter 31.2 — Appendix H)*

**Dropper** — Malicious program whose function is to drop (write to disk) and execute a second malicious program (the payload). May download the payload from a C2 server or contain it encrypted within its own data. *(Chapter 28)*

**DWARF** — Standard format for debugging data embedded in ELF binaries (`.debug_*` sections). Contains the mapping between instructions and source lines, variable types, scopes, and stack unwinding information. Generated by `-g`. *(Chapter 2.6)*

**Dynamic linking** — Mechanism by which a binary resolves its dependencies on shared libraries (`.so`) at load time or runtime, rather than at compile time. Managed by the `ld.so` loader. *(Chapter 2.7)*

---

## E

**ELF** (*Executable and Linkable Format*) — Standard binary file format on Linux and most Unix systems. Contains machine code, data, and metadata organized into sections (linker view) and segments (loader view). *(Chapter 2.3 — Appendix F)*

**Endianness** — Order in which the bytes of a multi-byte value are stored in memory. **Little-endian** (x86, ARM in LE mode): the least significant byte is at the lowest address. **Big-endian** (network, SPARC, PowerPC): the most significant byte is at the lowest address. *(Chapter 2.3)*

**Entry point** — Address of the first instruction executed by a program after loading. In an ELF, the `e_entry` header field typically points to `_start` (not `main`). `_start` calls `__libc_start_main`, which in turn calls `main`. *(Chapter 2.4)*

**Epilogue** (*function epilogue*) — Sequence of instructions at the end of a function that restores saved registers, deallocates stack space, and returns to the caller. Typical form: `add rsp, N` / `pop` registers / `ret`. With frame pointer: `leave` / `ret`. *(Chapter 3.5 — Appendix I, §9)*

**Symbolic execution** — Analysis technique that executes a program by treating inputs as symbolic variables (unknowns) rather than concrete values. Allows exploring all execution paths and solving constraints on inputs to reach a specific point in the program. *(Chapter 18.1)*

---

## F

**Fall-through** — In disassembly, sequential execution that "falls through" from the current instruction to the next without a jump. When a conditional jump is not taken, execution continues in fall-through. In an `if`/`else` structure, the fall-through typically corresponds to the `then` block. *(Chapter 3.4 — Appendix I, §5)*

**Flag register** — See *RFLAGS*.

**FLIRT** (*Fast Library Identification and Recognition Technology*) — IDA technology that identifies standard library functions (libc, libstdc++, etc.) in a stripped binary by comparing code bytes against a signature database. Ghidra offers a similar feature (*Function ID*). *(Chapter 20.5)*

**Frame pointer** — Register (`rbp` on x86-64) that points to the base of the current function's stack frame, providing a fixed reference point for accessing local variables and arguments. Omitted by default at `-O1` and above (`-fomit-frame-pointer`). *(Chapter 3.5 — Appendix B)*

**Frida** — Cross-platform dynamic instrumentation framework. Allows injecting JavaScript code into a running process to hook functions, modify arguments and return values, and trace execution. *(Chapter 13)*

**Full RELRO** — Protection mode where the entire GOT (including `.got.plt`) is remapped as read-only after the initial resolution of all symbols. Enabled by `-z now`. Prevents GOT overwrite attacks but requires all symbols to be resolved at startup (no lazy binding). *(Chapter 19.6 — Appendix F)*

**Fuzzing** — Automated testing technique that generates semi-random inputs for a program to discover crashes, memory errors, and unexpected behaviors. In RE, fuzzing helps understand a binary's parsing logic by revealing execution paths triggered by different inputs. *(Chapter 15)*

---

## G

**GDB** (*GNU Debugger*) — Reference command-line debugger on Linux. Allows controlling a program's execution step by step, inspecting memory, registers, and the stack, and scripting analysis via Python. *(Chapter 11 — Appendix C)*

**GEF** (*GDB Enhanced Features*) — Single-file GDB extension adding enriched contextual display, memory search commands, heap analysis, and ROP gadget search tools. *(Chapter 12 — Appendix C)*

**Ghidra** — Open source reverse engineering suite developed by the NSA. Includes a disassembler, a decompiler, a type editor, a Java/Python scripting system, and a headless mode for batch analysis. *(Chapter 8)*

**GOT** (*Global Offset Table*) — In-memory table containing the resolved addresses of imported functions and global variables. Populated by the dynamic loader (`ld.so`) at load time or on first call (lazy binding). Classic target for exploitation attacks (GOT overwrite). *(Chapter 2.9 — Appendix F)*

**GOT overwrite** — Exploitation technique that consists of writing an attacker-controlled address into a GOT entry to hijack a function call. Blocked by Full RELRO. *(Chapter 19.6)*

---

## H

**Headless mode** — Execution mode of a tool without a graphical interface, controllable by script. Ghidra's headless mode (`analyzeHeadless`) enables automated batch analysis of binaries. *(Chapter 8.9)*

**Heap** — Dynamically allocated memory area by `malloc`/`new` during program execution. On Linux, the heap is managed by the glibc allocator (ptmalloc2). Its analysis is essential for understanding a program's runtime behavior. *(Chapter 12.4)*

**Hidden pointer** — System V AMD64 ABI mechanism for returning structures larger than 16 bytes: the caller allocates space and passes a pointer to that space as the first argument (`rdi`), shifting all visible arguments by one position. *(Appendix B, §4.4 — Appendix I, §23)*

**Hooking** — Technique that intercepts a function call to execute custom code before, after, or instead of the original function. Implementable via Frida (runtime), `LD_PRELOAD` (loading), PLT/GOT patching, or instruction rewriting. *(Chapter 13.3)*

---

## I

**IDA** (*Interactive DisAssembler*) — Reference commercial interactive disassembler (Hex-Rays). IDA Free is the limited free version. IDA Pro includes the Hex-Rays decompiler, multi-architecture support, and a plugin SDK. *(Chapter 9.1)*

**ILSpy** — Open source .NET decompiler that reconstructs C# code from CIL bytecode. Cross-platform (Windows, Linux, macOS via Avalonia). Its decompilation engine (ICSharpCode.Decompiler) is also available as a NuGet library. *(Chapter 31.1 — Appendix H)*

**ImHex** — Advanced hex editor with a pattern language (`.hexpat`), structured visualization, bookmarks, binary diff, and YARA integration. Central tool of this course for binary format mapping. *(Chapter 6 — Appendix E)*

**Inlining** (*function inlining*) — Compiler optimization that replaces a function call with the function body directly at the call site, eliminating the `call`/`ret` overhead. Makes RE more difficult because the function "disappears" from the binary as a separate entity. *(Chapter 16.2)*

**Instrumentation** — Modification of a program to add observation code (logging, counting, tracing) without altering its functional logic. Can be static (at compile time: ASan, AFL++) or dynamic (at runtime: Frida, Valgrind). *(Chapters 13, 14, 15)*

**IOC** (*Indicator of Compromise*) — Technical element for detecting the presence of malware or a compromise: file hash, C2 server IP address, characteristic string, mutex name, registry key. *(Chapter 27.7)*

**Itanium ABI** — C++ name mangling standard used by GCC, Clang, and most non-MSVC compilers. Defines how C++ function names (with namespaces, parameters, templates) are encoded into binary symbols. *(Chapter 17.1)*

---

## J

**JIT** (*Just-In-Time compilation*) — Compilation technique that converts bytecode (CIL, Java bytecode) into native machine code at runtime rather than ahead of time. Used by the .NET runtime (CLR) and the JVM. *(Chapter 30.1)*

**Jump table** — Table of addresses (or relative offsets) stored in `.rodata`, used by GCC to implement `switch` statements with consecutive `case` values. The `switch` index serves as an index into the table, and an indirect jump (`jmp`) reaches the correct `case` in O(1). *(Appendix I, §7)*

---

## K

**Keygen** (*key generator*) — Program that generates valid serial keys for software by reproducing the validation algorithm extracted through reverse engineering. In an educational context (crackme), writing a keygen demonstrates complete understanding of the verification algorithm. *(Chapter 21.8)*

---

## L

**Lazy binding** — Deferred symbol resolution mechanism: imported functions are resolved only at the time of their first call, via the PLT stub and the `ld.so` resolver. Disabled by Full RELRO (`-z now`). *(Chapter 2.9)*

**`LD_PRELOAD`** — Linux environment variable that forces loading a shared library before all others, allowing the overriding (hooking) of functions without modifying the binary. *(Chapter 22.4)*

**`ld.so`** (*dynamic linker/loader*) — Program responsible for loading shared libraries and resolving dynamic symbols at the startup of an ELF binary. Its path is specified in the `.interp` section (typically `/lib64/ld-linux-x86-64.so.2`). *(Chapter 2.7)*

**LIEF** — Python/C++ library for parsing and modifying ELF, PE, and Mach-O binaries. Allows reading headers, sections, symbols, and modifying the binary (adding sections, changing the entry point, modifying imports). *(Chapter 35.1)*

**Little-endian** — See *Endianness*.

**LSDA** (*Language Specific Data Area*) — Table in the `.gcc_except_table` section that describes code regions covered by C++ `try`/`catch` blocks, the types of caught exceptions, and cleanup actions. *(Chapter 17.4)*

---

## M

**Magic bytes** (*magic number*) — Fixed byte sequence at the beginning of a file that identifies its format. Examples: `\x7fELF` for ELF, `MZ` for PE, `PK` for ZIP, `%PDF` for PDF. *(Chapter 5.1)*

**Malware** — Malicious software designed to cause harm: virus, ransomware, trojan, dropper, rootkit, spyware. Malware analysis is one of the primary use cases for RE. *(Part VI, chapters 26–29)*

**Mangling** — See *Name mangling*.

**Memcheck** — Valgrind tool that detects memory errors at runtime: leaks, out-of-bounds access, use of uninitialized memory, double-free. Works on binaries compiled without special instrumentation. *(Chapter 14.1)*

---

## N

**Name mangling** — Transformation of C++ function and method names into unique symbols encoding the namespace, class, name, parameter types, and qualifiers. Necessary because C++ allows function overloading (same name, different parameters). Decodable with `c++filt`. *(Chapter 17.1)*

**NativeAOT** — .NET compilation technology that produces a native binary without CIL bytecode. The resulting binary is a standard ELF or PE executable, analyzable only with native RE tools (Ghidra, IDA). *(Chapter 30.5 — Appendix H)*

**NOP** (*No Operation*) — Instruction that does nothing (`0x90` on x86). Used for alignment padding between functions, patching (replacing unwanted instructions with NOPs), and certain NOP sled techniques in exploitation. Multi-byte NOPs (`0x0F 0x1F ...`) are alignment variants. *(Appendix A, §11)*

**NX** (*No-eXecute*, also called DEP/*Data Execution Prevention*) — Protection that marks data pages (stack, heap) as non-executable. The processor raises an exception if code attempts to execute in these pages. *(Chapter 19.5)*

---

## O

**Obfuscation** — Set of transformations applied to a program to make its reverse engineering more difficult without modifying its functionality. Common techniques: symbol renaming, control flow flattening, dead code insertion, string encryption. *(Chapter 19.3)*

**`objdump`** — GNU Binutils disassembly and inspection tool for ELF binary files. Performs linear disassembly (as opposed to the recursive disassembly of Ghidra/IDA). *(Chapter 7)*

**Opcode** (*operation code*) — Binary encoding of a machine instruction. For example, `0x90` is the opcode for `nop`, `0xCC` is `int 3`, `0xC3` is `ret`. An opcode can be 1 to 15 bytes on x86-64. *(Chapter 3 — Appendix A)*

---

## P

**Packer** — Tool that compresses and/or encrypts a binary by wrapping it in a decompression stub. At runtime, the stub decompresses in memory and transfers control to the original code. UPX is the most common packer. Used to reduce size and hinder static analysis. *(Chapter 19.2)*

**Partial RELRO** — Default GCC protection mode where the `.got` section is read-only after loading but `.got.plt` remains writable (required for lazy binding). Less secure than Full RELRO. *(Chapter 19.6)*

**Patching** — Direct modification of a binary's bytes to alter its behavior. Classic example: inverting a conditional jump (`jz` → `jnz`, `0x74` → `0x75`) to bypass a verification. Achievable with ImHex, `r2 -w`, or via script with LIEF/pwntools. *(Chapters 6, 21.6)*

**PIE** (*Position-Independent Executable*) — Binary compiled to be loadable at any memory address. All internal references use relative addressing (`rip`-relative). Enabled by default on modern Linux distributions. Prerequisite for ASLR to apply to the binary itself. *(Chapter 2.5)*

**PLT** (*Procedure Linkage Table*) — ELF section (`.plt`) containing indirect jump trampolines for calls to shared library functions. Each PLT entry redirects to the address stored in the corresponding GOT entry. *(Chapter 2.9 — Appendix F)*

**Prologue** (*function prologue*) — Sequence of instructions at the beginning of a function that sets up the stack frame: saving the frame pointer, allocating space for local variables, saving callee-saved registers. Typical form at `-O0`: `push rbp` / `mov rbp, rsp` / `sub rsp, N`. *(Chapter 3.5 — Appendix I, §9)*

**pwndbg** — Exploitation-oriented GDB extension with advanced glibc heap visualization (`vis_heap_chunks`), code emulation, instruction-type navigation (`nextcall`, `nextret`), and pattern generation tools. *(Chapter 12 — Appendix C)*

**pwntools** — Python framework for exploit development and automated binary interaction: I/O management (tubes), assembly/disassembly, file patching, network communication. *(Chapter 11.9)*

---

## R

**r2pipe** — Official Python library for driving Radare2 programmatically. Sends r2 commands and retrieves results as text or JSON. *(Chapter 9.4)*

**Radare2** (*r2*) — Command-line reverse engineering framework. Provides disassembly, debugging, patching, pattern searching, and scripting. Its interface relies on short, composable commands. *(Chapter 9.2 — Appendix D)*

**Ransomware** — Malware that encrypts the victim's files and demands a ransom in exchange for the decryption key. RE analysis aims to identify the encryption algorithm, extract the key, and write a decryptor. *(Chapter 27)*

**Red zone** — 128-byte area below `rsp` (addresses `[rsp-1]` to `[rsp-128]`) that leaf functions of the System V AMD64 ABI can use without adjusting `rsp`. Guaranteed not to be clobbered by interrupts. Does not exist in kernel mode. *(Appendix B, §6.3)*

**Register** — Fast storage location inside the processor. On x86-64: 16 general-purpose 64-bit registers (`rax`–`r15`), 16 SSE 128-bit registers (`xmm0`–`xmm15`), the instruction pointer (`rip`), and the flags register (`RFLAGS`). *(Chapter 3.1 — Appendix A)*

**RELRO** (*RELocation Read-Only*) — Protection that makes certain GOT sections read-only after loading, preventing their modification by an attacker. Two modes: Partial RELRO (default) and Full RELRO (`-z now`). *(Chapter 19.6)*

**Reverse debugging** — GDB feature allowing backward execution of a program (instruction by instruction) to return to a previous state. Very slow but useful for understanding how a state was reached. *(Chapter 11 — Appendix C, §2.3)*

**RFLAGS** — x86-64 processor flags register containing condition bits updated by arithmetic and logical instructions. The most commonly used flags in RE: ZF (Zero Flag), SF (Sign Flag), CF (Carry Flag), OF (Overflow Flag). *(Chapter 3.1 — Appendix A)*

**RIP-relative addressing** — x86-64 addressing mode where the address is expressed as an offset relative to the current instruction (`rip`). Used systematically in PIE/PIC code for accessing global data and strings. Example: `lea rdi, [rip+0x2a3e]`. *(Appendix I, §11)*

**ROP** (*Return-Oriented Programming*) — Exploitation technique that chains existing instruction sequences in the binary (gadgets ending with `ret`) to execute arbitrary code without injecting new code, thereby bypassing the NX protection. *(Chapter 12.3)*

**RTTI** (*Run-Time Type Information*) — Type information embedded in C++ binaries that use polymorphism (`virtual`, `dynamic_cast`, `typeid`). Contains class names and inheritance hierarchy. Useful in RE for reconstructing class structure. *(Chapter 17.3)*

---

## S

**S-box** (*Substitution box*) — Substitution table used in cryptographic algorithms to introduce confusion (non-linearity). The AES S-box (256 bytes) is the most searched-for crypto constant in RE. *(Chapter 24.1 — Appendix J)*

**Sandbox** — Isolated environment (VM, container) in which a potentially malicious program is executed without risk to the host system. Network isolation and snapshots are essential. *(Chapter 26)*

**Section** (ELF) — Named and typed logical division of an ELF file. Each section contains a specific type of data (code in `.text`, constants in `.rodata`, symbols in `.symtab`). Linker and static analysis tool view, as opposed to segments (loader view). *(Chapter 2.4 — Appendix F)*

**Segment** (ELF) — Grouping of one or more sections with common memory permissions, described by a *program header*. The kernel loader uses segments to map the binary into memory via `mmap`. *(Chapter 2.4 — Appendix F)*

**SIMD** (*Single Instruction, Multiple Data*) — Instructions that operate simultaneously on multiple data items (vectors) in a single operation. On x86-64: SSE (128-bit, `xmm` registers), AVX (256-bit, `ymm` registers), AVX-512 (512-bit, `zmm` registers). GCC auto-vectorizes loops into SIMD starting at `-O2`. *(Chapter 3.9 — Appendix A, §12–§13)*

**SMT solver** (*Satisfiability Modulo Theories*) — Logic solver capable of determining whether a set of mathematical constraints has a solution, and if so, providing one. Z3 (Microsoft) is the reference SMT solver in RE, used by angr to solve symbolic execution constraints. *(Chapter 18.4)*

**SSO** (*Small String Optimization*) — Optimization of `std::string` (libstdc++) that stores short strings (≤ 15 bytes) directly within the `string` object itself, avoiding a heap allocation. *(Chapter 17.5 — Appendix I, §19)*

**Stack** — LIFO memory area used to store return addresses, local variables, excess arguments, and saved registers. Grows toward lower addresses on x86-64. The `rsp` register points to the top (lowest address). *(Chapter 3.5)*

**Stack unwinding** — Process of walking back up the call stack to restore previous frames, typically during C++ exception propagation or backtrace generation. Uses information from the `.eh_frame` section. *(Chapter 17.4 — Appendix F)*

**Stalker** — Frida module that traces all instructions executed by a thread, providing complete dynamic code coverage. Useful for identifying execution paths taken with a given input. *(Chapter 13.6)*

**Static linking** — Integration of library code directly into the binary at compile time, producing a self-contained executable with no `.so` dependencies. The binary is larger but portable. *(Chapter 2.3)*

**`strace`** — Linux tool that traces system calls made by a process. Displays each syscall with its arguments and return value. First reflex for understanding a binary's I/O and network behavior. *(Chapter 5.5)*

**Stripping** — Removal of debugging information and the full symbol table (`.symtab`, `.strtab`, `.debug_*`) from an ELF binary via the `strip` command. Dynamic symbols (`.dynsym`) survive stripping. *(Chapter 19.1)*

**`syscall`** — x86-64 instruction that performs a Linux system call. The syscall number is in `rax`, arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. The result is returned in `rax`. Clobbers `rcx` and `r11`. *(Chapter 3.8 — Appendix A, §11 — Appendix B, §8)*

---

## T

**Tail call optimization** — Compiler optimization that replaces a `call` + `ret` at the end of a function with a simple `jmp`, reusing the caller's stack frame. Saves one stack frame and one `ret`. *(Chapter 16.4)*

**TLS** (*Thread-Local Storage*) — Mechanism allowing each thread to have its own copy of a global variable. On x86-64 with glibc, TLS data is accessed via the `fs` segment register. The stack canary is stored in TLS at offset `fs:0x28`. *(Appendix F)*

---

## U

**Unpacking** — Process of restoring a binary compressed/encrypted by a packer to its original state. Can be static (dedicated tool: `upx -d`) or dynamic (run the binary, wait for decompression in memory, then dump memory with GDB). *(Chapter 29)*

**UPX** (*Ultimate Packer for eXecutables*) — Open source packer that compresses ELF and PE binaries. Easily detected (UPX signature in headers) and decompressed (`upx -d`). *(Chapter 19.2)*

---

## V

**Valgrind** — Binary instrumentation framework that executes a program in a virtual machine to detect memory errors (Memcheck), profile execution (Callgrind), and analyze runtime behavior. Works without recompilation. *(Chapter 14)*

**VMA** (*Virtual Memory Address*) — Address in the process's virtual address space. This is the address you see in disassembly and in registers during debugging. *(Chapter 2.8)*

**Vtable** (*virtual method table*) — Table of function pointers associated with each polymorphic C++ class. Each object contains a pointer to its class's vtable (the vptr). Virtual calls go through the vtable to determine which method to call (dynamic dispatch). *(Chapter 17.2 — Appendix I, §17)*

---

## W

**Watchpoint** — Data breakpoint: halts execution when a memory address is read, written, or modified. Hardware watchpoints use the processor's debug registers (DR0–DR3, limited to 4 simultaneous). Software watchpoints are slower (internal single-stepping). *(Chapter 11.5 — Appendix C)*

---

## X

**XREF** — See *Cross-reference*.

---

## Y

**YARA** — Binary pattern detection language and tool based on rules. Each rule describes a combination of strings, byte sequences, and logical conditions. Used to scan files for malware signatures, crypto constants, or packers. Integrated into ImHex. *(Chapters 6.10, 27.4, 35.4 — Appendix J)*

---

## Z

**Z3** — Open source SMT solver developed by Microsoft Research. Used in RE to solve constraint systems extracted from binary analysis (key checks, complex branch conditions). angr uses Z3 internally. *(Chapter 18.4)*

**Zero Flag** (*ZF*) — Bit in the RFLAGS register set to 1 when the result of an arithmetic or logical operation is zero. It is the most checked flag in RE: `jz`/`je` jumps if ZF=1, `jnz`/`jne` jumps if ZF=0. `test reg, reg` sets ZF if the register is zero. *(Chapter 3.1 — Appendix A)*

---

> 📚 **Back to appendices**:  
> - [Appendices README](/appendices/README.md) — index of all appendices.  
> - [Appendix A](/appendices/appendix-a-opcodes-x86-64.md) — x86-64 Opcodes.  
> - [Appendix B](/appendices/appendix-b-system-v-abi.md) — System V Calling Conventions.  
> - [Appendix F](/appendices/appendix-f-elf-sections.md) — ELF Sections.  
> - [Appendix I](/appendices/appendix-i-gcc-patterns.md) — GCC Patterns.

⏭️
