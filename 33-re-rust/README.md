🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 33 — Reverse Engineering Rust Binaries

> 🦀 *Rust produces native ELF binaries that go through the GNU linker, but their reverse engineering is a radically different experience from that of a C or C++ binary. This chapter gives you the keys to not drown in an ocean of symbols and generated code.*

---

## Why a chapter dedicated to Rust?

At first glance, a Rust binary looks like any other ELF executable: same format, same `.text`, `.data`, `.rodata` sections, same `ld` linker at the end of the chain. One might think the techniques covered in previous parts are sufficient. In practice, opening a Rust binary in Ghidra or Radare2 for the first time is often a shock.

Where a C program compiled with GCC produces a binary of a few tens of kilobytes with a handful of clearly identifiable functions, a "Hello, World!" in Rust commonly weighs **several megabytes** and contains **thousands of functions**. The reason is simple: Rust statically links its standard library by default, and the compiler generates a considerable amount of code for its zero-cost abstractions — abstractions that, at the assembly level, do indeed have a cost in code volume to analyze.

Several characteristics of Rust make its RE specific:

**A name mangling scheme distinct from C++.** Rust uses its own symbol decoration scheme (the "v0" format stabilized since 2021), different from C++'s Itanium mangling. Classic tools like `c++filt` don't work; you need `rustfilt` or demanglers integrated into recent disassemblers. Demangled names are often long and include the full path of the crate, module, and generic parameters.

**Recurring and recognizable code patterns.** Rust's type system — with `Option<T>`, `Result<T, E>`, exhaustive pattern matching, and `panic!` handling — translates to assembly as repetitive patterns. An `unwrap()` systematically generates a branch to panic code. A `match` on an `enum` produces jump tables or comparison cascades with predictable memory layouts. Learning to recognize these idioms considerably accelerates analysis.

**String handling without null terminator.** Rust's `&str` types are *fat pointers* composed of a pointer and a length, without C's trailing `\0`. This means the `strings` tool frequently misses strings or splits them incorrectly. The `strings` command remains useful for initial triage, but you must be aware of this limitation and know where to look for `(ptr, len)` structures in memory.

**Large binaries with static linking.** By default, `cargo build` in release mode produces a binary that embeds the entirety of the used standard library, plus all dependencies (crates). The call graph is massive, and distinguishing application code from stdlib or third-party crate code becomes a major challenge. Tools like `cargo-bloat` (developer-side) and known function signatures in Ghidra help filter the noise.

**No inheritance or classic vtables.** Unlike C++, Rust has no class inheritance or vtables in the traditional sense. Polymorphism goes through *trait objects* (`dyn Trait`), which use *fat pointers* containing a pointer to the data and a pointer to a trait vtable. The layout differs from C++ and requires a specific approach to reconstruct dynamic types.

---

## What you will learn

This chapter covers the essential aspects of reverse engineering Rust binaries compiled with the GNU toolchain:

- How Rust interacts with the GNU toolchain during compilation and linking, and what this implies for symbols and ELF sections.  
- How Rust name mangling works and the tools to decode symbols.  
- The characteristic assembly patterns of `Option`, `Result`, `match`, and panics, so you can recognize them without hesitation in a listing.  
- The memory representation of Rust strings (`&str` and `String`) and the pitfalls this poses for classic analysis tools.  
- Why Rust binaries are so large and how to isolate application code from library code.  
- Specialized tools (`rustfilt`, `cargo-bloat`, Ghidra signatures for the Rust stdlib) that make analysis practical.

---

## Prerequisites for this chapter

This chapter assumes you've mastered the fundamentals covered in previous parts:

- Static analysis with Ghidra or an equivalent disassembler (Chapters 8–9).  
- Reading x86-64 assembly and System V AMD64 calling conventions (Chapter 3).  
- ELF binary structure: sections, symbols, dynamic vs static linking (Chapter 2).  
- Using triage tools (`file`, `strings`, `readelf`, `checksec`) for first contact with an unknown binary (Chapter 5).

Knowledge of the Rust language is not strictly necessary, but having written a few simple Rust programs (manipulating `Option`, `Result`, `String`, iterators) will greatly facilitate understanding of the assembly patterns presented.

---

## Training binary

The binary used throughout this chapter is `crackme_rust`, located in `binaries/ch33-rust/`. The Rust source code is provided in `binaries/ch33-rust/crackme_rust/src/main.rs` with its `Cargo.toml`.

The associated `Makefile` allows producing several variants:

| Variant | Command | Description |  
|---|---|---|  
| Debug with symbols | `make debug` | Unoptimized binary, full symbols — ideal for learning patterns |  
| Release | `make release` | Optimized (`-O3` equivalent), symbols present |  
| Release stripped | `make release-strip` | Optimized and stripped — the realistic case |

Start by compiling all variants and already observe the size difference between them: this is your first clue about what makes Rust RE unique.

---

## Chapter outline

- **33.1** — Rust compilation specifics with the GNU toolchain (linking, symbols)  
- **33.2** — Rust name mangling vs C++: decoding symbols  
- **33.3** — Recognizing Rust patterns: `Option`, `Result`, `match`, panics  
- **33.4** — Strings in Rust: `&str` vs `String` in memory (no null terminator)  
- **33.5** — Embedded libraries and binary size (everything is statically linked)  
- **33.6** — Specific tools: `cargo-bloat`, Ghidra signatures for the Rust stdlib

---

> **Start with section 33.1** to understand how `rustc` relies on the GNU toolchain and what this changes for the analyst.

⏭️ [Rust compilation specifics with the GNU toolchain (linking, symbols)](/33-re-rust/01-gnu-toolchain-compilation.md)
