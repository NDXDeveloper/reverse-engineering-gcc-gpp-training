# Reverse Engineering Training — Applications compiled with the GNU toolchain

> **MIT License** — This content is strictly educational and ethical.  
> All training binaries are in `binaries/`, recompilable via `make` with the provided `Makefile`.  
> Each chapter folder contains `.c` / `.cpp` sources and a dedicated `Makefile` to reproduce each binary at different optimization levels (`-O0` to `-O3`), with and without symbols.  
> Each chapter ends with a **checkpoint** (mini-exercise) to validate your understanding before moving on.

---

## [Preface](/preface.md)

- [Tutorial objectives and target audience](/preface.md#tutorial-objectives-and-target-audience)  
- [Recommended prerequisites (intermediate C/C++, Linux CLI, memory concepts)](/preface.md#recommended-prerequisites)  
- [How to use this tutorial: linear path vs. on-demand access](/preface.md#how-to-use-this-tutorial)  
- [Typographic conventions and icons used](/preface.md#typographic-conventions)  
- [Acknowledgments and resources that inspired this project](/preface.md#acknowledgments)

---

## **[Part I — Fundamentals & Environment](/part-1-fundamentals.md)**

### [Chapter 1 — Introduction to Reverse Engineering](/01-introduction-re/README.md)

- 1.1 [Definition and objectives of RE](/01-introduction-re/01-definition-objectives.md)  
- 1.2 [Legal and ethical framework (licenses, CFAA / EUCD / DMCA laws)](/01-introduction-re/02-legal-ethical-framework.md)  
- 1.3 [Legitimate use cases: security auditing, CTF, advanced debugging, interoperability](/01-introduction-re/03-legitimate-use-cases.md)  
- 1.4 [Difference between static RE and dynamic RE](/01-introduction-re/04-static-vs-dynamic.md)  
- 1.5 [Overview of the methodology and tools used in this tutorial](/01-introduction-re/05-methodology-tools.md)  
- 1.6 [Target taxonomy: native binary, bytecode, firmware — where this tutorial fits](/01-introduction-re/06-target-taxonomy.md)  
- [**Checkpoint**: classify 5 given scenarios as "static" or "dynamic"](/01-introduction-re/checkpoint.md)

### [Chapter 2 — The GNU Compilation Chain](/02-gnu-compilation-chain/README.md)

- 2.1 [GCC/G++ architecture: preprocessor → compiler → assembler → linker](/02-gnu-compilation-chain/01-gcc-architecture.md)  
- 2.2 [Compilation phases and intermediate files (`.i`, `.s`, `.o`)](/02-gnu-compilation-chain/02-compilation-phases.md)  
- 2.3 [Binary formats: ELF (Linux), PE (Windows via MinGW), Mach-O (macOS)](/02-gnu-compilation-chain/03-binary-formats.md)  
- 2.4 [Key ELF sections: `.text`, `.data`, `.bss`, `.rodata`, `.plt`, `.got`, `.init`, `.fini`](/02-gnu-compilation-chain/04-elf-sections.md)  
- 2.5 [Compilation flags and their impact on RE (`-O0` to `-O3`, `-g`, `-s`, `-fPIC`, `-pie`)](/02-gnu-compilation-chain/05-compilation-flags.md)  
- 2.6 [Understanding DWARF symbol files](/02-gnu-compilation-chain/06-dwarf-symbols.md)  
- 2.7 [The Linux Loader (`ld.so`): from ELF file to process in memory](/02-gnu-compilation-chain/07-linux-loader.md)  
- 2.8 [Segment mapping, ASLR and virtual addresses: why addresses move](/02-gnu-compilation-chain/08-segments-aslr.md)  
- 2.9 [Dynamic symbol resolution: PLT/GOT in detail (lazy binding)](/02-gnu-compilation-chain/09-plt-got-lazy-binding.md)  
- [**Checkpoint**: compile the same `hello.c` with `-O0 -g` then `-O2 -s`, compare sizes and sections with `readelf`](/02-gnu-compilation-chain/checkpoint.md)

### [Chapter 3 — x86-64 Assembly Basics for RE](/03-x86-64-assembly/README.md)

- 3.1 [General registers, pointers and flags (`rax`, `rsp`, `rbp`, `rip`, `RFLAGS`...)](/03-x86-64-assembly/01-registers-pointers-flags.md)  
- 3.2 [Essential instructions: `mov`, `push`/`pop`, `call`/`ret`, `lea`](/03-x86-64-assembly/02-essential-instructions.md)  
- 3.3 [Arithmetic and logic: `add`, `sub`, `imul`, `xor`, `shl`/`shr`, `test`, `cmp`](/03-x86-64-assembly/03-arithmetic-logic.md)  
- 3.4 [Conditional and unconditional jumps: `jmp`, `jz`/`jnz`, `jl`, `jge`, `jle`, `ja`...](/03-x86-64-assembly/04-conditional-jumps.md)  
- 3.5 [The stack: prologue, epilogue and System V AMD64 calling conventions](/03-x86-64-assembly/05-stack-prologue-epilogue.md)  
- 3.6 [Parameter passing: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` then the stack](/03-x86-64-assembly/06-parameter-passing.md)  
- 3.7 [Reading an assembly listing without panicking: a practical 5-step method](/03-x86-64-assembly/07-reading-assembly-method.md)  
- 3.8 [Difference between library call (`call printf@plt`) and direct syscall (`syscall`)](/03-x86-64-assembly/08-call-plt-vs-syscall.md)  
- 3.9 [Introduction to SIMD instructions (SSE/AVX) — recognizing them without fear](/03-x86-64-assembly/09-introduction-simd.md)  
- [**Checkpoint**: manually annotate a real disassembly listing (provided)](/03-x86-64-assembly/checkpoint.md)

### [Chapter 4 — Setting Up the Work Environment](/04-work-environment/README.md)

- 4.1 [Recommended Linux distribution (Ubuntu/Debian/Kali)](/04-work-environment/01-linux-distribution.md)  
- 4.2 [Installation and configuration of essential tools (versioned list)](/04-work-environment/02-tools-installation.md)  
- 4.3 [Creating a sandboxed VM (VirtualBox / QEMU / UTM for macOS)](/04-work-environment/03-vm-creation.md)  
- 4.4 [VM network configuration: NAT, host-only, isolation](/04-work-environment/04-vm-network-configuration.md)  
- 4.5 [Repository structure: organization of `binaries/` and per-chapter `Makefile`s](/04-work-environment/05-repository-structure.md)  
- 4.6 [Compile all training binaries in one command (`make all`)](/04-work-environment/06-compiling-binaries.md)  
- 4.7 [Verify installation: provided `check_env.sh` script](/04-work-environment/07-verify-installation.md)  
- [**Checkpoint**: run `check_env.sh` — all tools must be green](/04-work-environment/checkpoint.md)

---

## **[Part II — Static Analysis](/part-2-static-analysis.md)**

### [Chapter 5 — Basic Binary Inspection Tools](/05-basic-inspection-tools/README.md)

- 5.1 [`file`, `strings`, `xxd` / `hexdump` — first contact with an unknown binary](/05-basic-inspection-tools/01-file-strings-xxd.md)  
- 5.2 [`readelf` and `objdump` — anatomy of an ELF (headers, sections, segments)](/05-basic-inspection-tools/02-readelf-objdump.md)  
- 5.3 [`nm` and `objdump -t` — inspecting symbol tables](/05-basic-inspection-tools/03-nm-symbols.md)  
- 5.4 [`ldd` and `ldconfig` — dynamic dependencies and resolution](/05-basic-inspection-tools/04-ldd-ldconfig.md)  
- 5.5 [`strace` / `ltrace` — system calls and library calls (syscall vs libc)](/05-basic-inspection-tools/05-strace-ltrace.md)  
- 5.6 [`checksec` — inventory of binary protections (ASLR, PIE, NX, canary, RELRO)](/05-basic-inspection-tools/06-checksec.md)  
- 5.7 ["Quick triage" workflow: the first 5 minutes routine when facing a binary](/05-basic-inspection-tools/07-quick-triage-workflow.md)  
- [**Checkpoint**: perform a complete triage of the provided `mystery_bin` binary, write a one-page report](/05-basic-inspection-tools/checkpoint.md)

### [Chapter 6 — ImHex: Advanced Hexadecimal Analysis](/06-imhex/README.md)

- 6.1 [Why ImHex goes beyond a simple hex editor](/06-imhex/01-why-imhex.md)  
- 6.2 [Installation and interface tour (Pattern Editor, Data Inspector, Bookmarks, Diff)](/06-imhex/02-installation-interface.md)  
- 6.3 [The `.hexpat` pattern language — syntax and basic types](/06-imhex/03-hexpat-language.md)  
- 6.4 [Writing a pattern to visualize an ELF header from scratch](/06-imhex/04-elf-header-pattern.md)  
- 6.5 [Parsing a custom C/C++ structure directly in the binary](/06-imhex/05-custom-structure-parser.md)  
- 6.6 [Colorization, annotations and bookmarks of binary regions](/06-imhex/06-colorization-annotations.md)  
- 6.7 [Comparing two versions of the same GCC binary (diff)](/06-imhex/07-comparison-diff.md)  
- 6.8 [Searching for magic bytes, encoded strings and opcode sequences](/06-imhex/08-magic-bytes-search.md)  
- 6.9 [Integration with ImHex's built-in disassembler](/06-imhex/09-integrated-disassembler.md)  
- 6.10 [Applying YARA rules from ImHex (bridge to malware analysis)](/06-imhex/10-yara-rules.md)  
- 6.11 [Practical case: mapping a custom file format with `.hexpat`](/06-imhex/11-practical-custom-format.md)  
- [**Checkpoint**: write a complete `.hexpat` for the `ch23-fileformat` format](/06-imhex/checkpoint.md)

### [Chapter 7 — Disassembly with objdump and Binutils](/07-objdump-binutils/README.md)

- 7.1 [Disassembly of a binary compiled without symbols (`-s`)](/07-objdump-binutils/01-disassembly-without-symbols.md)  
- 7.2 [AT&T vs Intel syntax — switching between them (`-M intel`)](/07-objdump-binutils/02-att-vs-intel.md)  
- 7.3 [Comparison with/without GCC optimizations (`-O0` vs `-O2` vs `-O3`)](/07-objdump-binutils/03-optimization-comparison.md)  
- 7.4 [Reading function prologue/epilogue in practice](/07-objdump-binutils/04-prologue-epilogue.md)  
- 7.5 [Identifying `main()` and C++ functions (name mangling)](/07-objdump-binutils/05-identifying-main-mangling.md)  
- 7.6 [`c++filt` — C++ symbol demangling](/07-objdump-binutils/06-cppfilt-demangling.md)  
- 7.7 [Limitations of `objdump`: why a real disassembler is necessary](/07-objdump-binutils/07-objdump-limitations.md)  
- [**Checkpoint**: disassemble `keygenme_O0` and `keygenme_O2`, list the key differences](/07-objdump-binutils/checkpoint.md)

### [Chapter 8 — Advanced Disassembly with Ghidra](/08-ghidra/README.md)

- 8.1 [Installation and getting started with Ghidra (NSA)](/08-ghidra/01-installation-getting-started.md)  
- 8.2 [Importing an ELF binary — auto-analysis and options](/08-ghidra/02-elf-import-analysis.md)  
- 8.3 [Navigating the CodeBrowser: Listing, Decompiler, Symbol Tree, Function Graph](/08-ghidra/03-codebrowser-navigation.md)  
- 8.4 [Renaming functions and variables, adding comments, creating types](/08-ghidra/04-renaming-comments-types.md)  
- 8.5 [Recognizing GCC structures: C++ vtables, RTTI, exceptions](/08-ghidra/05-gcc-structures-vtables-rtti.md)  
- 8.6 [Reconstructing data structures (`struct`, `class`, `enum`)](/08-ghidra/06-reconstructing-structures.md)  
- 8.7 [Cross-references (XREF): tracing the usage of a function or data](/08-ghidra/07-cross-references-xref.md)  
- 8.8 [Ghidra scripts in Java/Python to automate analysis](/08-ghidra/08-scripts-java-python.md)  
- 8.9 [Ghidra in headless mode for batch processing](/08-ghidra/09-headless-mode-batch.md)  
- [**Checkpoint**: import `ch08-oop` into Ghidra, reconstruct the class hierarchy](/08-ghidra/checkpoint.md)

### [Chapter 9 — Advanced Disassembly with IDA Free, Radare2 and Binary Ninja](/09-ida-radare2-binja/README.md)

- 9.1 [IDA Free — basic workflow on a GCC binary](/09-ida-radare2-binja/01-ida-free-workflow.md)  
- 9.2 [Radare2 / Cutter — command-line and GUI analysis](/09-ida-radare2-binja/02-radare2-cutter.md)  
- 9.3 [`r2`: essential commands (`aaa`, `pdf`, `afl`, `iz`, `iS`, `VV`)](/09-ida-radare2-binja/03-r2-essential-commands.md)  
- 9.4 [Scripting with r2pipe (Python)](/09-ida-radare2-binja/04-scripting-r2pipe.md)  
- 9.5 [Binary Ninja Cloud (free version) — quick start](/09-ida-radare2-binja/05-binary-ninja-cloud.md)  
- 9.6 [Comparison: Ghidra vs IDA vs Radare2 vs Binary Ninja (features, pricing, use cases)](/09-ida-radare2-binja/06-tools-comparison.md)  
- [**Checkpoint**: analyze the same binary in 2 different tools, compare the decompiler results](/09-ida-radare2-binja/checkpoint.md)

### [Chapter 10 — Binary Diffing](/10-binary-diffing/README.md)

- 10.1 [Why compare two versions of the same binary (patch analysis, vuln detection)](/10-binary-diffing/01-why-diffing.md)  
- 10.2 [BinDiff (Google) — installation, import from Ghidra/IDA, reading results](/10-binary-diffing/02-bindiff.md)  
- 10.3 [Diaphora — open source Ghidra/IDA diffing plugin](/10-binary-diffing/03-diaphora.md)  
- 10.4 [`radiff2` — command-line diffing with Radare2](/10-binary-diffing/04-radiff2.md)  
- 10.5 [Practical case: identifying a vulnerability fix between two binary versions](/10-binary-diffing/05-practical-patch-vuln.md)  
- [**Checkpoint**: compare `keygenme_v1` and `keygenme_v2`, identify the modified function](/10-binary-diffing/checkpoint.md)

---

## **[Part III — Dynamic Analysis](/part-3-dynamic-analysis.md)**

### [Chapter 11 — Debugging with GDB](/11-gdb/README.md)

- 11.1 [Compilation with debug symbols (`-g`, DWARF)](/11-gdb/01-debug-symbols-compilation.md)  
- 11.2 [Fundamental GDB commands: `break`, `run`, `next`, `step`, `info`, `x`, `print`](/11-gdb/02-fundamental-commands.md)  
- 11.3 [Inspecting the stack, registers, memory (format and sizes)](/11-gdb/03-inspecting-stack-registers-memory.md)  
- 11.4 [GDB on a stripped binary — working without symbols](/11-gdb/04-gdb-stripped-binary.md)  
- 11.5 [Conditional breakpoints and watchpoints (memory and registers)](/11-gdb/05-conditional-breakpoints-watchpoints.md)  
- 11.6 [Catchpoints: intercepting `fork`, `exec`, `syscall`, signals](/11-gdb/06-catchpoints.md)  
- 11.7 [Remote debugging with `gdbserver` (debugging on a remote target)](/11-gdb/07-remote-debugging-gdbserver.md)  
- 11.8 [GDB Python API — scripting and automation](/11-gdb/08-gdb-python-api.md)  
- 11.9 [Introduction to `pwntools` for automating binary interactions](/11-gdb/09-introduction-pwntools.md)  
- [**Checkpoint**: write a GDB Python script that automatically dumps the arguments of every `strcmp` call](/11-gdb/checkpoint.md)

### [Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg](/12-gdb-extensions/README.md)

- 12.1 [Installation and comparison of the three extensions](/12-gdb-extensions/01-installation-comparison.md)  
- 12.2 [Real-time stack and register visualization](/12-gdb-extensions/02-stack-registers-visualization.md)  
- 12.3 [ROP gadget search from GDB](/12-gdb-extensions/03-rop-gadget-search.md)  
- 12.4 [Heap analysis with pwndbg (`vis_heap_chunks`, `bins`)](/12-gdb-extensions/04-heap-analysis-pwndbg.md)  
- 12.5 [Useful commands specific to each extension](/12-gdb-extensions/05-specific-commands.md)  
- [**Checkpoint**: trace the complete execution of `keygenme_O0` with GEF, capture the comparison moment](/12-gdb-extensions/checkpoint.md)

### [Chapter 13 — Dynamic Instrumentation with Frida](/13-frida/README.md)

- 13.1 [Frida architecture — JS agent injected into the target process](/13-frida/01-frida-architecture.md)  
- 13.2 [Injection modes: `frida`, `frida-trace`, spawn vs attach](/13-frida/02-injection-modes.md)  
- 13.3 [Hooking C and C++ functions on the fly](/13-frida/03-hooking-c-cpp-functions.md)  
- 13.4 [Intercepting calls to `malloc`, `free`, `open`, custom functions](/13-frida/04-intercepting-calls.md)  
- 13.5 [Modifying arguments and return values live](/13-frida/05-modifying-arguments-returns.md)  
- 13.6 [Stalker: tracing all executed instructions (dynamic code coverage)](/13-frida/06-stalker-code-coverage.md)  
- 13.7 [Practical case: bypassing a license check](/13-frida/07-practical-license-bypass.md)  
- [**Checkpoint**: write a Frida script that logs all calls to `send()` with their buffers](/13-frida/checkpoint.md)

### [Chapter 14 — Analysis with Valgrind and Sanitizers](/14-valgrind-sanitizers/README.md)

- 14.1 [Valgrind / Memcheck — memory leaks and runtime behavior](/14-valgrind-sanitizers/01-valgrind-memcheck.md)  
- 14.2 [Callgrind + KCachegrind — profiling and call graph](/14-valgrind-sanitizers/02-callgrind-kcachegrind.md)  
- 14.3 [AddressSanitizer (ASan), UBSan, MSan — compiling with `-fsanitize`](/14-valgrind-sanitizers/03-asan-ubsan-msan.md)  
- 14.4 [Leveraging sanitizer reports to understand internal logic](/14-valgrind-sanitizers/04-leveraging-reports.md)  
- [**Checkpoint**: run Valgrind on `ch14-crypto`, identify the key buffers in memory](/14-valgrind-sanitizers/checkpoint.md)

### [Chapter 15 — Fuzzing for Reverse Engineering](/15-fuzzing/README.md)

- 15.1 [Why fuzzing is a full-fledged RE tool](/15-fuzzing/01-why-fuzzing-for-re.md)  
- 15.2 [AFL++ — installation, instrumentation and first run on a GCC application](/15-fuzzing/02-afl-plus-plus.md)  
- 15.3 [libFuzzer — in-process fuzzing with sanitizers](/15-fuzzing/03-libfuzzer.md)  
- 15.4 [Analyzing crashes to understand parsing logic](/15-fuzzing/04-analyzing-crashes.md)  
- 15.5 [Coverage-guided fuzzing: reading coverage maps (`afl-cov`, `lcov`)](/15-fuzzing/05-coverage-guided.md)  
- 15.6 [Corpus management and custom dictionaries](/15-fuzzing/06-corpus-dictionaries.md)  
- 15.7 [Practical case: discovering hidden paths in a binary parser](/15-fuzzing/07-practical-parser-case.md)  
- [**Checkpoint**: fuzz `ch15-fileformat` with AFL++, find at least 2 crashes and analyze them](/15-fuzzing/checkpoint.md)

---

## **[Part IV — Advanced RE Techniques](/part-4-advanced-techniques.md)**

### [Chapter 16 — Understanding Compiler Optimizations](/16-compiler-optimizations/README.md)

- 16.1 [Impact of `-O1`, `-O2`, `-O3`, `-Os` on disassembled code](/16-compiler-optimizations/01-optimization-levels-impact.md)  
- 16.2 [Function inlining: when the function disappears from the binary](/16-compiler-optimizations/02-inlining.md)  
- 16.3 [Loop unrolling and vectorization (SIMD/SSE/AVX)](/16-compiler-optimizations/03-unrolling-vectorization.md)  
- 16.4 [Tail call optimization and its impact on the stack](/16-compiler-optimizations/04-tail-call-optimization.md)  
- 16.5 [Link-Time Optimizations (`-flto`) and their effects on the call graph](/16-compiler-optimizations/05-link-time-optimization.md)  
- 16.6 [Recognizing typical GCC patterns (compiler idioms)](/16-compiler-optimizations/06-gcc-patterns-idioms.md)  
- 16.7 [GCC vs Clang comparison: assembly pattern differences](/16-compiler-optimizations/07-gcc-vs-clang.md)  
- [**Checkpoint**: identify 3 optimizations applied by GCC on a provided `-O2` binary](/16-compiler-optimizations/checkpoint.md)

### [Chapter 17 — Reverse Engineering C++ with GCC](/17-re-cpp-gcc/README.md)

- 17.1 [Name mangling — Itanium ABI rules and demangling](/17-re-cpp-gcc/01-name-mangling-itanium.md)  
- 17.2 [C++ object model: vtable, vptr, single and multiple inheritance](/17-re-cpp-gcc/02-object-model-vtable.md)  
- 17.3 [RTTI (Run-Time Type Information) and `dynamic_cast`](/17-re-cpp-gcc/03-rtti-dynamic-cast.md)  
- 17.4 [Exception handling (`.eh_frame`, `.gcc_except_table`, `__cxa_throw`)](/17-re-cpp-gcc/04-exception-handling.md)  
- 17.5 [STL internals: `std::vector`, `std::string`, `std::map`, `std::unordered_map` in memory](/17-re-cpp-gcc/05-stl-internals.md)  
- 17.6 [Templates: instantiations and symbol explosion](/17-re-cpp-gcc/06-templates-instantiations.md)  
- 17.7 [Lambda, closures and captures in assembly](/17-re-cpp-gcc/07-lambda-closures.md)  
- 17.8 [Smart Pointers in assembly: `unique_ptr` vs `shared_ptr` (reference counting)](/17-re-cpp-gcc/08-smart-pointers.md)  
- 17.9 [C++20 Coroutines: recognizing the frame and state machine pattern](/17-re-cpp-gcc/09-coroutines-cpp20.md)  
- [**Checkpoint**: reconstruct the classes of the `ch17-oop` binary from disassembly alone](/17-re-cpp-gcc/checkpoint.md)

### [Chapter 18 — Symbolic Execution and Constraint Solvers](/18-symbolic-execution/README.md)

- 18.1 [Principles of symbolic execution: treating inputs as symbols](/18-symbolic-execution/01-symbolic-execution-principles.md)  
- 18.2 [angr — installation and architecture (SimState, SimManager, exploration)](/18-symbolic-execution/02-angr-installation-architecture.md)  
- 18.3 [Automatically solving a crackme with angr](/18-symbolic-execution/03-solving-crackme-angr.md)  
- 18.4 [Z3 Theorem Prover — modeling manually extracted constraints](/18-symbolic-execution/04-z3-theorem-prover.md)  
- 18.5 [Limits: path explosion, loops, system calls](/18-symbolic-execution/05-limits-path-explosion.md)  
- 18.6 [Combining with manual RE: when to use symbolic execution](/18-symbolic-execution/06-combining-with-manual-re.md)  
- [**Checkpoint**: solve `keygenme_O2_strip` with angr in less than 30 lines of Python](/18-symbolic-execution/checkpoint.md)

### [Chapter 19 — Anti-reversing and Compiler Protections](/19-anti-reversing/README.md)

- 19.1 [Stripping (`strip`) and detection](/19-anti-reversing/01-stripping-detection.md)  
- 19.2 [Packing with UPX — detect and decompress](/19-anti-reversing/02-packing-upx.md)  
- 19.3 [Control flow obfuscation (Control Flow Flattening, bogus control flow)](/19-anti-reversing/03-control-flow-obfuscation.md)  
- 19.4 [LLVM-based obfuscation (Hikari, O-LLVM) — recognizing the patterns](/19-anti-reversing/04-llvm-obfuscation.md)  
- 19.5 [Stack canaries (`-fstack-protector`), ASLR, PIE, NX](/19-anti-reversing/05-canaries-aslr-pie-nx.md)  
- 19.6 [RELRO: Partial vs Full and impact on the GOT/PLT table](/19-anti-reversing/06-relro-got-plt.md)  
- 19.7 [Debugger detection techniques (`ptrace`, timing checks, `/proc/self/status`)](/19-anti-reversing/07-debugger-detection.md)  
- 19.8 [Breakpoint countermeasures (self-modifying code, int3 scanning)](/19-anti-reversing/08-breakpoint-countermeasures.md)  
- 19.9 [Inspecting all protections with `checksec` before any analysis](/19-anti-reversing/09-checksec-full-audit.md)  
- [**Checkpoint**: identify all protections of the `anti_reverse_all_checks` binary, bypass them one by one](/19-anti-reversing/checkpoint.md)

### [Chapter 20 — Decompilation and Source Code Reconstruction](/20-decompilation/README.md)

- 20.1 [Limits of automatic decompilation (why the result is never perfect)](/20-decompilation/01-decompilation-limits.md)  
- 20.2 [Ghidra Decompiler — quality depending on optimization level](/20-decompilation/02-ghidra-decompiler.md)  
- 20.3 [RetDec (Avast) — offline static decompilation](/20-decompilation/03-retdec.md)  
- 20.4 [Reconstructing a `.h` file from a binary (types, structs, API)](/20-decompilation/04-reconstructing-header.md)  
- 20.5 [Identifying embedded third-party libraries (FLIRT / Ghidra signatures)](/20-decompilation/05-flirt-signatures.md)  
- 20.6 [Exporting and cleaning pseudo-code to produce recompilable code](/20-decompilation/06-exporting-pseudocode.md)  
- [**Checkpoint**: produce a complete `.h` for the `ch20-network` binary](/20-decompilation/checkpoint.md)

---

## **[Part V — Practical Cases on Our Applications](/part-5-practical-cases.md)**

> Each chapter uses the tools covered in Parts II-IV. Binaries are provided at multiple optimization levels and with/without symbols.

### [Chapter 21 — Reversing a Simple C Program (keygenme)](/21-keygenme/README.md)

- 21.1 [Complete static analysis of the binary (triage, strings, sections)](/21-keygenme/01-static-analysis.md)  
- 21.2 [Protection inventory with `checksec`](/21-keygenme/02-checksec-protections.md)  
- 21.3 [Locating the verification routine (top-down approach)](/21-keygenme/03-routine-localization.md)  
- 21.4 [Understanding conditional jumps (`jz`/`jnz`) in the crackme context](/21-keygenme/04-conditional-jumps-crackme.md)  
- 21.5 [Dynamic analysis: tracing the comparison with GDB](/21-keygenme/05-dynamic-analysis-gdb.md)  
- 21.6 [Binary patching: flipping a jump directly in the binary (with ImHex)](/21-keygenme/06-patching-imhex.md)  
- 21.7 [Automatic solving with angr](/21-keygenme/07-angr-solving.md)  
- 21.8 [Writing a keygen in Python with `pwntools`](/21-keygenme/08-keygen-pwntools.md)  
- [**Checkpoint**: produce a working keygen for all 3 binary variants](/21-keygenme/checkpoint.md)

### [Chapter 22 — Reversing an Object-Oriented C++ Application](/22-oop/README.md)

- 22.1 [Reconstructing the class hierarchy and vtables](/22-oop/01-class-vtable-reconstruction.md)  
- 22.2 [RE of a plugin system (dynamic loading `.so` via `dlopen`/`dlsym`)](/22-oop/02-plugin-system-dlopen.md)  
- 22.3 [Understanding virtual dispatch: from vtable to method call](/22-oop/03-virtual-dispatch.md)  
- 22.4 [Patching behavior via `LD_PRELOAD`](/22-oop/04-patching-ld-preload.md)  
- [**Checkpoint**: write a compatible `.so` plugin that integrates into the application without the sources](/22-oop/checkpoint.md)

### [Chapter 23 — Reversing a Network Binary (client/server)](/23-network/README.md)

- 23.1 [Identifying the custom protocol with `strace` + Wireshark](/23-network/01-identifying-protocol.md)  
- 23.2 [RE of the packet parser (state machine, fields, magic bytes)](/23-network/02-re-packet-parser.md)  
- 23.3 [Visualizing binary frames with ImHex and writing a `.hexpat` for the protocol](/23-network/03-frames-imhex-hexpat.md)  
- 23.4 [Replay Attack: replaying a captured request](/23-network/04-replay-attack.md)  
- 23.5 [Writing a complete replacement client with `pwntools`](/23-network/05-client-pwntools.md)  
- [**Checkpoint**: write a Python client capable of authenticating to the server without knowing the source code](/23-network/checkpoint.md)

### [Chapter 24 — Reversing an Encrypted Binary](/24-crypto/README.md)

- 24.1 [Identifying crypto routines (magic constants: AES S-box, SHA256 IV...)](/24-crypto/01-identifying-crypto-routines.md)  
- 24.2 [Identifying embedded crypto libraries (OpenSSL, libsodium, custom)](/24-crypto/02-identifying-crypto-libs.md)  
- 24.3 [Extracting keys and IVs from memory with GDB/Frida](/24-crypto/03-extracting-keys-iv.md)  
- 24.4 [Visualizing the encrypted format and structures with ImHex](/24-crypto/04-visualizing-format-imhex.md)  
- 24.5 [Reproducing the encryption scheme in Python](/24-crypto/05-reproducing-encryption-python.md)  
- [**Checkpoint**: decrypt the provided `secret.enc` file by extracting the key from the binary](/24-crypto/checkpoint.md)

### [Chapter 25 — Reversing a Custom File Format](/25-fileformat/README.md)

- 25.1 [Identifying the overall structure with `file`, `strings` and `binwalk`](/25-fileformat/01-identifying-structure.md)  
- 25.2 [Mapping fields with ImHex and an iterative `.hexpat` pattern](/25-fileformat/02-mapping-imhex-hexpat.md)  
- 25.3 [Confirming interpretation with AFL++ (parser fuzzing)](/25-fileformat/03-confirming-afl-fuzzing.md)  
- 25.4 [Writing an independent Python parser/serializer](/25-fileformat/04-parser-python.md)  
- 25.5 [Documenting the format (producing a specification)](/25-fileformat/05-documenting-specification.md)  
- [**Checkpoint**: produce a Python parser + a `.hexpat` + a format specification](/25-fileformat/checkpoint.md)

---

## **[Part VI — Malicious Code Analysis (Controlled Environment)](/part-6-malware.md)**

> **All samples in this part are created by us, for educational purposes only.** No real malware is distributed.

### [Chapter 26 — Setting Up a Secure Analysis Lab](/26-secure-lab/README.md)

- 26.1 [Isolation principles: why and how](/26-secure-lab/01-isolation-principles.md)  
- 26.2 [Dedicated VM with QEMU/KVM — snapshots and isolated network](/26-secure-lab/02-vm-qemu-kvm.md)  
- 26.3 [Monitoring tools: `auditd`, `inotifywait`, `tcpdump`, `sysdig`](/26-secure-lab/03-monitoring-tools.md)  
- 26.4 [Network captures with a dedicated bridge](/26-secure-lab/04-network-captures-bridge.md)  
- 26.5 [Golden rules: never execute outside the sandbox, never connect to the real network](/26-secure-lab/05-golden-rules.md)  
- [**Checkpoint**: deploy the lab and verify network isolation](/26-secure-lab/checkpoint.md)

### [Chapter 27 — Analysis of a Linux ELF Ransomware (self-compiled with GCC)](/27-ransomware/README.md)

- 27.1 [Sample design: AES encryption on `/tmp/test`, hardcoded key](/27-ransomware/01-sample-design.md)  
- 27.2 [Quick triage: `file`, `strings`, `checksec`, initial hypotheses](/27-ransomware/02-quick-triage.md)  
- 27.3 [Static analysis: Ghidra + ImHex (spotting AES constants, encryption flow)](/27-ransomware/03-static-analysis-ghidra-imhex.md)  
- 27.4 [Identifying corresponding YARA rules from ImHex](/27-ransomware/04-yara-rules.md)  
- 27.5 [Dynamic analysis: GDB + Frida (extracting the key from memory)](/27-ransomware/05-dynamic-analysis-gdb-frida.md)  
- 27.6 [Writing the Python decryptor](/27-ransomware/06-python-decryptor.md)  
- 27.7 [Writing a standard analysis report (IOC, behavior, recommendations)](/27-ransomware/07-analysis-report.md)  
- [**Checkpoint**: decrypt the files and produce a complete report](/27-ransomware/checkpoint.md)

### [Chapter 28 — Analysis of an ELF Dropper with Network Communication](/28-dropper/README.md)

- 28.1 [Identifying network calls with `strace` + Wireshark](/28-dropper/01-network-calls-strace-wireshark.md)  
- 28.2 [Hooking sockets with Frida (intercepting `connect`, `send`, `recv`)](/28-dropper/02-hooking-sockets-frida.md)  
- 28.3 [RE of the custom C2 protocol (commands, encoding, handshake)](/28-dropper/03-re-c2-protocol.md)  
- 28.4 [Simulating a C2 server to observe complete behavior](/28-dropper/04-simulating-c2-server.md)  
- [**Checkpoint**: write a fake C2 server that controls the dropper](/28-dropper/checkpoint.md)

### [Chapter 29 — Packing Detection, Unpacking and Reconstruction](/29-unpacking/README.md)

- 29.1 [Identifying UPX and custom packers with `checksec` + ImHex + entropy](/29-unpacking/01-identifying-packers.md)  
- 29.2 [Static unpacking (UPX) and dynamic unpacking (memory dump with GDB)](/29-unpacking/02-static-dynamic-unpacking.md)  
- 29.3 [Reconstructing the original ELF: fixing headers, sections and entry point](/29-unpacking/03-reconstructing-elf.md)  
- 29.4 [Re-analyzing the unpacked binary](/29-unpacking/04-reanalyzing-binary.md)  
- [**Checkpoint**: unpack `ch27-packed`, reconstruct the ELF and recover the original logic](/29-unpacking/checkpoint.md)

---

## **[Part VII — Bonus: RE on .NET / C# Binaries](/part-7-dotnet.md)**

> *Direct bridge with C# development — the same RE concepts apply to CIL/.NET bytecode.*

### [Chapter 30 — Introduction to .NET RE](/30-introduction-re-dotnet/README.md)

- 30.1 [Fundamental differences: CIL bytecode vs native x86-64 code](/30-introduction-re-dotnet/01-cil-vs-native.md)  
- 30.2 [Structure of a .NET assembly: metadata, PE headers, CIL sections](/30-introduction-re-dotnet/02-dotnet-assembly-structure.md)  
- 30.3 [Common obfuscators: ConfuserEx, Dotfuscator, SmartAssembly](/30-introduction-re-dotnet/03-common-obfuscators.md)  
- 30.4 [Inspecting an assembly with `file`, `strings` and ImHex (PE/.NET headers)](/30-introduction-re-dotnet/04-inspecting-assembly-imhex.md)  
- 30.5 [NativeAOT and ReadyToRun: when C# becomes native code](/30-introduction-re-dotnet/05-nativeaot-readytorun.md)

### [Chapter 31 — Decompiling .NET Assemblies](/31-decompilation-dotnet/README.md)

- 31.1 [ILSpy — open source C# decompilation](/31-decompilation-dotnet/01-ilspy.md)  
- 31.2 [dnSpy / dnSpyEx — decompilation + integrated debugging (breakpoints on decompiled C#)](/31-decompilation-dotnet/02-dnspy-dnspyex.md)  
- 31.3 [dotPeek (JetBrains) — navigation and source export](/31-decompilation-dotnet/03-dotpeek.md)  
- 31.4 [Comparison: ILSpy vs dnSpy vs dotPeek](/31-decompilation-dotnet/04-tools-comparison.md)  
- 31.5 [Decompiling despite obfuscation: de4dot and bypass techniques](/31-decompilation-dotnet/05-de4dot-bypassing.md)

### [Chapter 32 — Dynamic Analysis and .NET Hooking](/32-dynamic-analysis-dotnet/README.md)

- 32.1 [Debugging an assembly with dnSpy without the sources](/32-dynamic-analysis-dotnet/01-debug-dnspy-without-sources.md)  
- 32.2 [Hooking .NET methods with Frida (`frida-clr`)](/32-dynamic-analysis-dotnet/02-hooking-frida-clr.md)  
- 32.3 [Intercepting P/Invoke calls (bridge .NET → GCC native libraries)](/32-dynamic-analysis-dotnet/03-pinvoke-interception.md)  
- 32.4 [Patching a .NET assembly on the fly (modifying IL with dnSpy)](/32-dynamic-analysis-dotnet/04-patching-il-dnspy.md)  
- 32.5 [Practical case: bypassing a C# license check](/32-dynamic-analysis-dotnet/05-practical-license-csharp.md)  
- [**Checkpoint**: patch and keygen the provided .NET application](/32-dynamic-analysis-dotnet/checkpoint.md)

---

## **[Part VIII — Bonus: RE of Rust and Go Binaries](/part-8-rust-go.md)**

> *These languages use the GNU toolchain (linker) and produce native ELF binaries. Their RE presents specific challenges.*

### [Chapter 33 — Reverse Engineering Rust Binaries](/33-re-rust/README.md)

- 33.1 [Rust compilation specifics with the GNU toolchain (linking, symbols)](/33-re-rust/01-gnu-toolchain-compilation.md)  
- 33.2 [Rust name mangling vs C++: decoding symbols](/33-re-rust/02-rust-name-mangling.md)  
- 33.3 [Recognizing Rust patterns: `Option`, `Result`, `match`, panics](/33-re-rust/03-patterns-option-result-match.md)  
- 33.4 [Strings in Rust: `&str` vs `String` in memory (no null terminator)](/33-re-rust/04-rust-strings-memory.md)  
- 33.5 [Embedded libraries and binary size (everything is statically linked)](/33-re-rust/05-libraries-binary-size.md)  
- 33.6 [Specific tools: `cargo-bloat`, Ghidra signatures for the Rust stdlib](/33-re-rust/06-tools-cargo-bloat-ghidra.md)

### [Chapter 34 — Reverse Engineering Go Binaries](/34-re-go/README.md)

- 34.1 [Go runtime specifics: goroutines, scheduler, GC](/34-re-go/01-runtime-goroutines-gc.md)  
- 34.2 [Go calling convention (stack-based then register-based since Go 1.17)](/34-re-go/02-calling-convention.md)  
- 34.3 [Go data structures in memory: slices, maps, interfaces, channels](/34-re-go/03-data-structures-memory.md)  
- 34.4 [Recovering function names: `gopclntab` and `go_parser` for Ghidra/IDA](/34-re-go/04-gopclntab-go-parser.md)  
- 34.5 [Strings in Go: `(ptr, len)` structure and implications for `strings`](/34-re-go/05-strings-go-ptr-len.md)  
- 34.6 [Stripped Go binaries: recovering symbols via internal structures](/34-re-go/06-stripped-go-symbols.md)  
- [**Checkpoint**: analyze a stripped Go binary, recover functions and reconstruct the logic](/34-re-go/checkpoint.md)

---

## **[Part IX — Resources & Automation](/part-9-resources.md)**

### [Chapter 35 — Automation and Scripting](/35-automation-scripting/README.md)

- 35.1 [Python scripts with `pyelftools` and `lief` (ELF parsing and modification)](/35-automation-scripting/01-pyelftools-lief.md)  
- 35.2 [Automating Ghidra in headless mode (batch analysis of N binaries)](/35-automation-scripting/02-ghidra-headless-batch.md)  
- 35.3 [RE scripting with `pwntools` (interactions, patching, exploitation)](/35-automation-scripting/03-scripting-pwntools.md)  
- 35.4 [Writing YARA rules to detect patterns in a binary collection](/35-automation-scripting/04-yara-rules.md)  
- 35.5 [Integration into a CI/CD pipeline for binary regression auditing](/35-automation-scripting/05-pipeline-ci-cd.md)  
- 35.6 [Building your own RE toolkit: organizing scripts and snippets](/35-automation-scripting/06-building-toolkit.md)  
- [**Checkpoint**: write a script that automatically analyzes a directory of binaries and produces a JSON report](/35-automation-scripting/checkpoint.md)

### [Chapter 36 — Resources for Further Learning](/36-resources-further-learning/README.md)

- 36.1 [RE-oriented CTFs: pwnable.kr, crackmes.one, root-me.org, picoCTF, Hack The Box](/36-resources-further-learning/01-re-oriented-ctf.md)  
- 36.2 [Recommended reading (books, papers, blogs)](/36-resources-further-learning/02-recommended-reading.md)  
- 36.3 [Communities and conferences (REcon, DEF CON RE Village, PoC||GTFO, r/ReverseEngineering)](/36-resources-further-learning/03-communities-conferences.md)  
- 36.4 [Certification paths: GREM (SANS), OSED (OffSec)](/36-resources-further-learning/04-certifications.md)  
- 36.5 [Building your RE portfolio: documenting your analyses](/36-resources-further-learning/05-building-portfolio.md)

---

## [Appendices](/appendices/README.md)

- **Appendix A** — [Quick reference of frequent x86-64 opcodes in RE](/appendices/appendix-a-opcodes-x86-64.md)  
- **Appendix B** — [System V AMD64 ABI calling conventions (summary table)](/appendices/appendix-b-system-v-abi.md)  
- **Appendix C** — [GDB / GEF / pwndbg cheat sheet](/appendices/appendix-c-cheatsheet-gdb.md)  
- **Appendix D** — [Radare2 / Cutter cheat sheet](/appendices/appendix-d-cheatsheet-radare2.md)  
- **Appendix E** — [ImHex cheat sheet: `.hexpat` syntax reference](/appendices/appendix-e-cheatsheet-imhex.md)  
- **Appendix F** — [ELF sections table and their roles](/appendices/appendix-f-elf-sections.md)  
- **Appendix G** — [Native tools comparison (tool / usage / free / CLI or GUI)](/appendices/appendix-g-native-tools-comparison.md)  
- **Appendix H** — [.NET tools comparison (ILSpy / dnSpy / dotPeek / de4dot)](/appendices/appendix-h-dotnet-tools-comparison.md)  
- **Appendix I** — [Recognizable GCC patterns in assembly (compiler idioms)](/appendices/appendix-i-gcc-patterns.md)  
- **Appendix J** — [Common crypto magic constants (AES, SHA, MD5, RC4...)](/appendices/appendix-j-crypto-constants.md)  
- **Appendix K** — [Reverse Engineering Glossary](/appendices/appendix-k-glossary.md)

---

## Repository Structure

```
reverse-engineering-gcc-gpp-training/
│
├── README.md                              ← This file (overview + links)
├── LICENSE                                ← MIT + ethical disclaimer (EN)
├── check_env.sh                           ← Environment verification script
├── preface.md                             ← Tutorial preface
│
├── part-1-fundamentals.md                 ← Part I introduction
├── part-2-static-analysis.md              ← Part II introduction
├── part-3-dynamic-analysis.md             ← Part III introduction
├── part-4-advanced-techniques.md          ← Part IV introduction
├── part-5-practical-cases.md              ← Part V introduction
├── part-6-malware.md                      ← Part VI introduction
├── part-7-dotnet.md                       ← Part VII introduction
├── part-8-rust-go.md                      ← Part VIII introduction
├── part-9-resources.md                    ← Part IX introduction
│
│
│   ════════════════════════════════════════
│   PART I — FUNDAMENTALS & ENVIRONMENT
│   ════════════════════════════════════════
│
├── 01-introduction-re/
│   ├── README.md
│   ├── 01-definition-objectives.md
│   ├── 02-legal-ethical-framework.md
│   ├── 03-legitimate-use-cases.md
│   ├── 04-static-vs-dynamic.md
│   ├── 05-methodology-tools.md
│   ├── 06-target-taxonomy.md
│   └── checkpoint.md
│
├── 02-gnu-compilation-chain/
│   ├── README.md
│   ├── 01-gcc-architecture.md
│   ├── 02-compilation-phases.md
│   ├── 03-binary-formats.md
│   ├── 04-elf-sections.md
│   ├── 05-compilation-flags.md
│   ├── 06-dwarf-symbols.md
│   ├── 07-linux-loader.md
│   ├── 08-segments-aslr.md
│   ├── 09-plt-got-lazy-binding.md
│   └── checkpoint.md
│
├── 03-x86-64-assembly/
│   ├── README.md
│   ├── 01-registers-pointers-flags.md
│   ├── 02-essential-instructions.md
│   ├── 03-arithmetic-logic.md
│   ├── 04-conditional-jumps.md
│   ├── 05-stack-prologue-epilogue.md
│   ├── 06-parameter-passing.md
│   ├── 07-reading-assembly-method.md
│   ├── 08-call-plt-vs-syscall.md
│   ├── 09-introduction-simd.md
│   └── checkpoint.md
│
├── 04-work-environment/
│   ├── README.md
│   ├── 01-linux-distribution.md
│   ├── 02-tools-installation.md
│   ├── 03-vm-creation.md
│   ├── 04-vm-network-configuration.md
│   ├── 05-repository-structure.md
│   ├── 06-compiling-binaries.md
│   ├── 07-verify-installation.md
│   └── checkpoint.md
│
│
│   ════════════════════════════
│   PART II — STATIC ANALYSIS
│   ════════════════════════════
│
├── 05-basic-inspection-tools/
│   ├── README.md
│   ├── 01-file-strings-xxd.md
│   ├── 02-readelf-objdump.md
│   ├── 03-nm-symbols.md
│   ├── 04-ldd-ldconfig.md
│   ├── 05-strace-ltrace.md
│   ├── 06-checksec.md
│   ├── 07-quick-triage-workflow.md
│   └── checkpoint.md
│
├── 06-imhex/
│   ├── README.md
│   ├── 01-why-imhex.md
│   ├── 02-installation-interface.md
│   ├── 03-hexpat-language.md
│   ├── 04-elf-header-pattern.md
│   ├── 05-custom-structure-parser.md
│   ├── 06-colorization-annotations.md
│   ├── 07-comparison-diff.md
│   ├── 08-magic-bytes-search.md
│   ├── 09-integrated-disassembler.md
│   ├── 10-yara-rules.md
│   ├── 11-practical-custom-format.md
│   └── checkpoint.md
│
├── 07-objdump-binutils/
│   ├── README.md
│   ├── 01-disassembly-without-symbols.md
│   ├── 02-att-vs-intel.md
│   ├── 03-optimization-comparison.md
│   ├── 04-prologue-epilogue.md
│   ├── 05-identifying-main-mangling.md
│   ├── 06-cppfilt-demangling.md
│   ├── 07-objdump-limitations.md
│   └── checkpoint.md
│
├── 08-ghidra/
│   ├── README.md
│   ├── 01-installation-getting-started.md
│   ├── 02-elf-import-analysis.md
│   ├── 03-codebrowser-navigation.md
│   ├── 04-renaming-comments-types.md
│   ├── 05-gcc-structures-vtables-rtti.md
│   ├── 06-reconstructing-structures.md
│   ├── 07-cross-references-xref.md
│   ├── 08-scripts-java-python.md
│   ├── 09-headless-mode-batch.md
│   └── checkpoint.md
│
├── 09-ida-radare2-binja/
│   ├── README.md
│   ├── 01-ida-free-workflow.md
│   ├── 02-radare2-cutter.md
│   ├── 03-r2-essential-commands.md
│   ├── 04-scripting-r2pipe.md
│   ├── 05-binary-ninja-cloud.md
│   ├── 06-tools-comparison.md
│   └── checkpoint.md
│
├── 10-binary-diffing/
│   ├── README.md
│   ├── 01-why-diffing.md
│   ├── 02-bindiff.md
│   ├── 03-diaphora.md
│   ├── 04-radiff2.md
│   ├── 05-practical-patch-vuln.md
│   └── checkpoint.md
│
│
│   ═══════════════════════════════
│   PART III — DYNAMIC ANALYSIS
│   ═══════════════════════════════
│
├── 11-gdb/
│   ├── README.md
│   ├── 01-debug-symbols-compilation.md
│   ├── 02-fundamental-commands.md
│   ├── 03-inspecting-stack-registers-memory.md
│   ├── 04-gdb-stripped-binary.md
│   ├── 05-conditional-breakpoints-watchpoints.md
│   ├── 06-catchpoints.md
│   ├── 07-remote-debugging-gdbserver.md
│   ├── 08-gdb-python-api.md
│   ├── 09-introduction-pwntools.md
│   └── checkpoint.md
│
├── 12-gdb-extensions/
│   ├── README.md
│   ├── 01-installation-comparison.md
│   ├── 02-stack-registers-visualization.md
│   ├── 03-rop-gadget-search.md
│   ├── 04-heap-analysis-pwndbg.md
│   ├── 05-specific-commands.md
│   └── checkpoint.md
│
├── 13-frida/
│   ├── README.md
│   ├── 01-frida-architecture.md
│   ├── 02-injection-modes.md
│   ├── 03-hooking-c-cpp-functions.md
│   ├── 04-intercepting-calls.md
│   ├── 05-modifying-arguments-returns.md
│   ├── 06-stalker-code-coverage.md
│   ├── 07-practical-license-bypass.md
│   └── checkpoint.md
│
├── 14-valgrind-sanitizers/
│   ├── README.md
│   ├── 01-valgrind-memcheck.md
│   ├── 02-callgrind-kcachegrind.md
│   ├── 03-asan-ubsan-msan.md
│   ├── 04-leveraging-reports.md
│   └── checkpoint.md
│
├── 15-fuzzing/
│   ├── README.md
│   ├── 01-why-fuzzing-for-re.md
│   ├── 02-afl-plus-plus.md
│   ├── 03-libfuzzer.md
│   ├── 04-analyzing-crashes.md
│   ├── 05-coverage-guided.md
│   ├── 06-corpus-dictionaries.md
│   ├── 07-practical-parser-case.md
│   └── checkpoint.md
│
│
│   ══════════════════════════════════════
│   PART IV — ADVANCED RE TECHNIQUES
│   ══════════════════════════════════════
│
├── 16-compiler-optimizations/
│   ├── README.md
│   ├── 01-optimization-levels-impact.md
│   ├── 02-inlining.md
│   ├── 03-unrolling-vectorization.md
│   ├── 04-tail-call-optimization.md
│   ├── 05-link-time-optimization.md
│   ├── 06-gcc-patterns-idioms.md
│   ├── 07-gcc-vs-clang.md
│   └── checkpoint.md
│
├── 17-re-cpp-gcc/
│   ├── README.md
│   ├── 01-name-mangling-itanium.md
│   ├── 02-object-model-vtable.md
│   ├── 03-rtti-dynamic-cast.md
│   ├── 04-exception-handling.md
│   ├── 05-stl-internals.md
│   ├── 06-templates-instantiations.md
│   ├── 07-lambda-closures.md
│   ├── 08-smart-pointers.md
│   ├── 09-coroutines-cpp20.md
│   └── checkpoint.md
│
├── 18-symbolic-execution/
│   ├── README.md
│   ├── 01-symbolic-execution-principles.md
│   ├── 02-angr-installation-architecture.md
│   ├── 03-solving-crackme-angr.md
│   ├── 04-z3-theorem-prover.md
│   ├── 05-limits-path-explosion.md
│   ├── 06-combining-with-manual-re.md
│   └── checkpoint.md
│
├── 19-anti-reversing/
│   ├── README.md
│   ├── 01-stripping-detection.md
│   ├── 02-packing-upx.md
│   ├── 03-control-flow-obfuscation.md
│   ├── 04-llvm-obfuscation.md
│   ├── 05-canaries-aslr-pie-nx.md
│   ├── 06-relro-got-plt.md
│   ├── 07-debugger-detection.md
│   ├── 08-breakpoint-countermeasures.md
│   ├── 09-checksec-full-audit.md
│   └── checkpoint.md
│
├── 20-decompilation/
│   ├── README.md
│   ├── 01-decompilation-limits.md
│   ├── 02-ghidra-decompiler.md
│   ├── 03-retdec.md
│   ├── 04-reconstructing-header.md
│   ├── 05-flirt-signatures.md
│   ├── 06-exporting-pseudocode.md
│   └── checkpoint.md
│
│
│   ══════════════════════════════════════════════
│   PART V — PRACTICAL CASES ON OUR APPLICATIONS
│   ══════════════════════════════════════════════
│
├── 21-keygenme/
│   ├── README.md
│   ├── 01-static-analysis.md
│   ├── 02-checksec-protections.md
│   ├── 03-routine-localization.md
│   ├── 04-conditional-jumps-crackme.md
│   ├── 05-dynamic-analysis-gdb.md
│   ├── 06-patching-imhex.md
│   ├── 07-angr-solving.md
│   ├── 08-keygen-pwntools.md
│   └── checkpoint.md
│
├── 22-oop/
│   ├── README.md
│   ├── 01-class-vtable-reconstruction.md
│   ├── 02-plugin-system-dlopen.md
│   ├── 03-virtual-dispatch.md
│   ├── 04-patching-ld-preload.md
│   └── checkpoint.md
│
├── 23-network/
│   ├── README.md
│   ├── 01-identifying-protocol.md
│   ├── 02-re-packet-parser.md
│   ├── 03-frames-imhex-hexpat.md
│   ├── 04-replay-attack.md
│   ├── 05-client-pwntools.md
│   └── checkpoint.md
│
├── 24-crypto/
│   ├── README.md
│   ├── 01-identifying-crypto-routines.md
│   ├── 02-identifying-crypto-libs.md
│   ├── 03-extracting-keys-iv.md
│   ├── 04-visualizing-format-imhex.md
│   ├── 05-reproducing-encryption-python.md
│   └── checkpoint.md
│
├── 25-fileformat/
│   ├── README.md
│   ├── 01-identifying-structure.md
│   ├── 02-mapping-imhex-hexpat.md
│   ├── 03-confirming-afl-fuzzing.md
│   ├── 04-parser-python.md
│   ├── 05-documenting-specification.md
│   └── checkpoint.md
│
│
│   ══════════════════════════════════════════════════════════
│   PART VI — MALICIOUS CODE ANALYSIS (CONTROLLED ENV.)
│   ══════════════════════════════════════════════════════════
│
├── 26-secure-lab/
│   ├── README.md
│   ├── 01-isolation-principles.md
│   ├── 02-vm-qemu-kvm.md
│   ├── 03-monitoring-tools.md
│   ├── 04-network-captures-bridge.md
│   ├── 05-golden-rules.md
│   └── checkpoint.md
│
├── 27-ransomware/
│   ├── README.md
│   ├── 01-sample-design.md
│   ├── 02-quick-triage.md
│   ├── 03-static-analysis-ghidra-imhex.md
│   ├── 04-yara-rules.md
│   ├── 05-dynamic-analysis-gdb-frida.md
│   ├── 06-python-decryptor.md
│   ├── 07-analysis-report.md
│   └── checkpoint.md
│
├── 28-dropper/
│   ├── README.md
│   ├── 01-network-calls-strace-wireshark.md
│   ├── 02-hooking-sockets-frida.md
│   ├── 03-re-c2-protocol.md
│   ├── 04-simulating-c2-server.md
│   └── checkpoint.md
│
├── 29-unpacking/
│   ├── README.md
│   ├── 01-identifying-packers.md
│   ├── 02-static-dynamic-unpacking.md
│   ├── 03-reconstructing-elf.md
│   ├── 04-reanalyzing-binary.md
│   └── checkpoint.md
│
│
│   ══════════════════════════════════════════
│   PART VII — BONUS: RE .NET/C# BINARIES
│   ══════════════════════════════════════════
│
├── 30-introduction-re-dotnet/
│   ├── README.md
│   ├── 01-cil-vs-native.md
│   ├── 02-dotnet-assembly-structure.md
│   ├── 03-common-obfuscators.md
│   ├── 04-inspecting-assembly-imhex.md
│   └── 05-nativeaot-readytorun.md
│
├── 31-decompilation-dotnet/
│   ├── README.md
│   ├── 01-ilspy.md
│   ├── 02-dnspy-dnspyex.md
│   ├── 03-dotpeek.md
│   ├── 04-tools-comparison.md
│   └── 05-de4dot-bypassing.md
│
├── 32-dynamic-analysis-dotnet/
│   ├── README.md
│   ├── 01-debug-dnspy-without-sources.md
│   ├── 02-hooking-frida-clr.md
│   ├── 03-pinvoke-interception.md
│   ├── 04-patching-il-dnspy.md
│   ├── 05-practical-license-csharp.md
│   └── checkpoint.md
│
│
│   ═══════════════════════════════════════════════
│   PART VIII — BONUS: RE RUST AND GO BINARIES
│   ═══════════════════════════════════════════════
│
├── 33-re-rust/
│   ├── README.md
│   ├── 01-gnu-toolchain-compilation.md
│   ├── 02-rust-name-mangling.md
│   ├── 03-patterns-option-result-match.md
│   ├── 04-rust-strings-memory.md
│   ├── 05-libraries-binary-size.md
│   └── 06-tools-cargo-bloat-ghidra.md
│
├── 34-re-go/
│   ├── README.md
│   ├── 01-runtime-goroutines-gc.md
│   ├── 02-calling-convention.md
│   ├── 03-data-structures-memory.md
│   ├── 04-gopclntab-go-parser.md
│   ├── 05-strings-go-ptr-len.md
│   ├── 06-stripped-go-symbols.md
│   └── checkpoint.md
│
│
│   ═══════════════════════════════════════════
│   PART IX — RESOURCES & AUTOMATION
│   ═══════════════════════════════════════════
│
├── 35-automation-scripting/
│   ├── README.md
│   ├── 01-pyelftools-lief.md
│   ├── 02-ghidra-headless-batch.md
│   ├── 03-scripting-pwntools.md
│   ├── 04-yara-rules.md
│   ├── 05-pipeline-ci-cd.md
│   ├── 06-building-toolkit.md
│   └── checkpoint.md
│
├── 36-resources-further-learning/
│   ├── README.md
│   ├── 01-re-oriented-ctf.md
│   ├── 02-recommended-reading.md
│   ├── 03-communities-conferences.md
│   ├── 04-certifications.md
│   └── 05-building-portfolio.md
│
│
│   ══════════
│   APPENDICES
│   ══════════
│
├── appendices/
│   ├── README.md
│   ├── appendix-a-opcodes-x86-64.md
│   ├── appendix-b-system-v-abi.md
│   ├── appendix-c-cheatsheet-gdb.md
│   ├── appendix-d-cheatsheet-radare2.md
│   ├── appendix-e-cheatsheet-imhex.md
│   ├── appendix-f-elf-sections.md
│   ├── appendix-g-native-tools-comparison.md
│   ├── appendix-h-dotnet-tools-comparison.md
│   ├── appendix-i-gcc-patterns.md
│   ├── appendix-j-crypto-constants.md
│   └── appendix-k-glossary.md
│
│
│   ═══════════════════════════════════════════
│   TRAINING BINARIES & RESOURCES
│   ═══════════════════════════════════════════
│
├── binaries/                              ← All training binaries
│   ├── Makefile                           ← `make all` to recompile everything
│   ├── ch02-hello/
│   │   ├── hello.c
│   │   └── Makefile
│   ├── ch03-checkpoint/
│   │   ├── count_lowercase.c
│   │   └── Makefile
│   ├── ch05-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch05-mystery_bin/
│   │   ├── mystery_bin.c
│   │   └── Makefile
│   ├── ch06-fileformat/
│   │   ├── fileformat.c
│   │   └── Makefile
│   ├── ch07-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch08-oop/
│   │   ├── oop.cpp
│   │   └── Makefile
│   ├── ch09-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch10-keygenme/
│   │   ├── keygenme_v1.c
│   │   ├── keygenme_v2.c
│   │   └── Makefile
│   ├── ch11-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch12-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch13-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch13-network/
│   │   ├── client.c
│   │   ├── server.c
│   │   ├── protocol.h
│   │   └── Makefile
│   ├── ch14-crypto/
│   │   ├── crypto.c
│   │   └── Makefile
│   ├── ch14-fileformat/
│   │   ├── fileformat.c
│   │   └── Makefile
│   ├── ch14-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch15-fileformat/
│   │   ├── fileformat.c
│   │   ├── fuzz_fileformat.c
│   │   └── Makefile
│   ├── ch15-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch16-optimisations/
│   │   ├── gcc_idioms.c
│   │   ├── inlining_demo.c
│   │   ├── loop_unroll_vec.c
│   │   ├── lto_main.c
│   │   ├── lto_math.c
│   │   ├── lto_math.h
│   │   ├── lto_utils.c
│   │   ├── lto_utils.h
│   │   ├── opt_levels_demo.c
│   │   ├── tail_call.c
│   │   └── Makefile
│   ├── ch17-oop/
│   │   ├── oop.cpp
│   │   └── Makefile
│   ├── ch18-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch19-anti-reversing/
│   │   ├── anti_reverse.c
│   │   ├── vuln_demo.c
│   │   └── Makefile
│   ├── ch20-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch20-network/
│   │   ├── client.c
│   │   ├── server.c
│   │   ├── protocol.h
│   │   └── Makefile
│   ├── ch20-oop/
│   │   ├── oop.cpp
│   │   └── Makefile
│   ├── ch21-keygenme/
│   │   ├── keygenme.c
│   │   └── Makefile
│   ├── ch22-oop/
│   │   ├── oop.cpp
│   │   ├── plugin_alpha.cpp
│   │   ├── plugin_beta.cpp
│   │   ├── processor.h
│   │   └── Makefile
│   ├── ch23-network/
│   │   ├── client.c
│   │   ├── server.c
│   │   └── Makefile
│   ├── ch24-crypto/
│   │   ├── crypto.c
│   │   └── Makefile
│   ├── ch25-fileformat/
│   │   ├── fileformat.c
│   │   └── Makefile
│   ├── ch27-ransomware/                   ← Sandbox only
│   │   ├── ransomware_sample.c
│   │   └── Makefile
│   ├── ch28-dropper/                      ← Sandbox only
│   │   ├── dropper_sample.c
│   │   └── Makefile
│   ├── ch29-packed/
│   │   ├── packed_sample.c
│   │   └── Makefile
│   ├── ch32-dotnet/
│   │   ├── LicenseChecker/
│   │   │   ├── LicenseChecker.csproj
│   │   │   ├── LicenseValidator.cs
│   │   │   ├── NativeBridge.cs
│   │   │   └── Program.cs
│   │   ├── native/
│   │   │   └── native_check.c
│   │   └── Makefile
│   ├── ch33-rust/
│   │   ├── crackme_rust/
│   │   │   ├── src/
│   │   │   │   └── main.rs
│   │   │   └── Cargo.toml
│   │   └── Makefile
│   └── ch34-go/
│       ├── crackme_go/
│       │   ├── main.go
│       │   └── go.mod
│       └── Makefile
│
├── scripts/                               ← Python utility scripts
│   ├── triage.py                          ← Automatic binary triage
│   ├── keygen_template.py                 ← Keygen pwntools template
│   └── batch_analyze.py                   ← Ghidra headless batch analysis
│
├── hexpat/                                ← ImHex patterns (.hexpat)
│   ├── elf_header.hexpat
│   ├── ch25_fileformat.hexpat
│   └── ch23_protocol.hexpat
│
├── yara-rules/                            ← Tutorial YARA rules
│   ├── crypto_constants.yar
│   └── packer_signatures.yar
│
└── solutions/                             ← Checkpoint solutions (spoilers)
    ├── ch01-checkpoint-solution.md
    ├── ch02-checkpoint-solution.md
    ├── ch03-checkpoint-solution.md
    ├── ch04-checkpoint-solution.md
    ├── ch05-checkpoint-solution.md
    ├── ch06-checkpoint-solution.hexpat
    ├── ch07-checkpoint-solution.md
    ├── ch08-checkpoint-solution.md
    ├── ch09-checkpoint-solution.md
    ├── ch10-checkpoint-solution.md
    ├── ch11-checkpoint-solution.py
    ├── ch12-checkpoint-solution.md
    ├── ch13-checkpoint-solution.js
    ├── ch13-checkpoint-solution.py
    ├── ch14-checkpoint-solution.md
    ├── ch15-checkpoint-solution.md
    ├── ch16-checkpoint-solution.md
    ├── ch17-checkpoint-solution.md
    ├── ch18-checkpoint-solution.py
    ├── ch19-checkpoint-solution.md
    ├── ch20-checkpoint-solution.h
    ├── ch21-checkpoint-keygen.py
    ├── ch22-checkpoint-plugin.cpp
    ├── ch23-checkpoint-client.py
    ├── ch24-checkpoint-decrypt.py
    ├── ch25-checkpoint-parser.py
    ├── ch25-checkpoint-solution.hexpat
    ├── ch26-checkpoint-solution.md
    ├── ch27-checkpoint-decryptor.py
    ├── ch27-checkpoint-solution.md
    ├── ch28-checkpoint-fake-c2.py
    ├── ch29-checkpoint-solution.md
    ├── ch32-checkpoint-solution.md
    ├── ch34-checkpoint-solution.md
    └── ch35-checkpoint-batch.py
```
