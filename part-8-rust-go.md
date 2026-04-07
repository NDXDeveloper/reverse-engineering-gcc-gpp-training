🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Part VIII — Bonus: RE of Rust and Go Binaries

Rust and Go are establishing themselves in domains once dominated by C/C++: system tools, network infrastructure, CLIs, malware, and an increasing share of CTF challenges. Both produce native ELF binaries — often via the GNU linker — but their RE bears no resemblance to that of C/C++. A 500-line Rust binary weighs several megabytes due to the static linking of the stdlib. A Go binary embeds its own runtime (scheduler, garbage collector) and uses an atypical calling convention. Function names, string representation, in-memory data structures — everything is different. This part teaches you to recognize these specifics and adapt your tools accordingly.

---

## 🎯 Objectives of this part

By the end of these two chapters, you will be able to:

1. **Identify a Rust or Go binary** from the initial triage and immediately adapt your analysis strategy (tools, signatures, assumptions about memory layout).  
2. **Reverse a Rust binary**: decode the name mangling, recognize `Option`/`Result`/`match`/`panic` patterns, understand the memory representation of strings (`&str` vs `String`, no null terminator), and filter out the noise of the statically linked stdlib with `cargo-bloat` and Ghidra signatures.  
3. **Reverse a Go binary**: navigate the runtime (goroutines, scheduler, GC), understand the calling convention (stack-based then register-based since Go 1.17), interpret internal structures (`slice`, `map`, `interface`, `channel`), and recover function names via `gopclntab` even on a stripped binary.  
4. **Apply native RE tools** (Ghidra, GDB, Frida) to Rust and Go binaries while knowing where they hit their limits and which specialized plugins or scripts fill those gaps.  
5. **Compare the assembly patterns** produced by GCC (C/C++), rustc, and the Go compiler for the same algorithm, and leverage these differences during analysis.

---

## 📋 Chapters

| # | Title | Language | Specific challenges | Link |  
|----|-------|---------|-------------------|------|  
| 33 | RE of Rust binaries | Rust | Name mangling distinct from C++, ubiquitous `Option`/`Result`/`match`/`panic` patterns, strings without a null terminator, statically linked stdlib (~4 MB of noise), dedicated Ghidra signatures. | [Chapter 33](/33-re-rust/README.md) |  
| 34 | RE of Go binaries | Go | Embedded runtime (goroutines, GC, scheduler), non-standard calling convention, `(ptr, len)` strings, internal structures (`slice`, `map`, `interface`), `gopclntab` table to recover symbols on stripped binaries. | [Chapter 34](/34-re-go/README.md) |

---

## 🆚 Rust vs Go vs C++ in RE

| Criterion | C/C++ (GCC) | Rust (rustc) | Go |  
|---------|-------------|-------------|-----|  
| **Name mangling** | Itanium ABI (`_ZN...`), demangled by `c++filt` | Own format (`_ZN...` + hash), demangled by `rustfilt` | No classic mangling — readable names with full path (`main.processData`) |  
| **Calling convention** | System V AMD64 (registers `rdi`, `rsi`, `rdx`…) | System V AMD64 (identical to C) | Stack-based (≤1.16), custom register-based (≥1.17) — neither System V nor Windows |  
| **Strings** | Null-terminated (`char*`) | `&str` = `(ptr, len)`, no `\0`; `String` = `(ptr, len, capacity)` | `(ptr, len)`, no `\0` — similar to Rust |  
| **Linking** | Dynamic by default (libc, libstdc++) | Static by default (entire stdlib embedded) | Static by default (runtime + stdlib embedded) |  
| **Binary size (hello world)** | ~16 KB (dynamic) | ~4 MB (static, stdlib included) | ~2 MB (static, runtime included) |  
| **Specialized tools** | `c++filt`, Ghidra, IDA (native support) | `rustfilt`, `cargo-bloat`, Rust Ghidra signatures | `go_parser` (Ghidra/IDA), `gopclntab`, `redress` |

The central point: Ghidra, GDB, and Frida work on all three, but their decompiler produces very noisy results on Rust and Go without suitable signatures. The effort of this part focuses on recognizing patterns specific to each language and using the right plugins to filter out the noise.

---

## ⏱️ Estimated duration

**~8-12 hours** for a C/C++ native RE practitioner.

Chapter 33 (Rust, ~4-6h) is denser because Rust patterns in assembly are verbose — the systematic handling of `Result`/`Option` and panics generates a lot of code that you will learn to filter. Chapter 34 (Go, ~4-6h) requires an effort of adaptation to the calling convention and internal structures, but the `gopclntab` table considerably eases work on stripped binaries — a luxury that neither C nor Rust offers.

If you have never written Rust or Go, plan an additional ~2h per language to read an introductory syntax tutorial. You do not need to master these languages — just recognize their basic constructs when you encounter them in the decompiler.

---

## 📌 Prerequisites

**Mandatory:**

- Having completed **[Part I](/part-1-fundamentals.md)** (ELF format, x86-64 assembly, calling conventions) and **[Part II](/part-2-static-analysis.md)** (Ghidra, `objdump`, `readelf`, `strings`).  
- Knowing how to navigate Ghidra: import, decompiler, XREF, function renaming.

**Recommended:**

- Having completed Chapter 16 (compiler optimizations) and Chapter 17 (C++ RE with GCC) of **[Part IV](/part-4-advanced-techniques.md)** — the comparison with C++ patterns is a recurring thread in this part.  
- Having completed at least one practical case of **[Part V](/part-5-practical-cases.md)** to have the reflex of the full workflow triage → static analysis → dynamic analysis.  
- Basic familiarity with Rust and/or Go syntax. No need to know how to write code — just recognize a `match`, a `Result<T, E>`, a goroutine, or a `defer` when you see them.

---

## ⬅️ Previous part

← [**Part VII — Bonus: RE on .NET / C# Binaries**](/part-7-dotnet.md)

## ➡️ Next part

To close the training: automating your RE workflows (Python scripts, Ghidra headless, YARA, CI/CD pipelines) and resources to keep progressing (CTFs, readings, certifications, communities).

→ [**Part IX — Resources & Automation**](/part-9-resources.md)

⏭️ [Chapter 33 — Reverse Engineering of Rust binaries](/33-re-rust/README.md)
