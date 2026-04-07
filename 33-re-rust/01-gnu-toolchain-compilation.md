🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 33.1 — Rust Compilation Specifics with the GNU Toolchain (linking, symbols)

> 🦀 Rust has its own compiler (`rustc`) and its own build manager (`cargo`), but at the end of the chain, it is the **GNU linker `ld`** that assembles the final binary on Linux. Understanding this relationship is essential for the RE analyst, as it determines what is found — and what is not found — in the produced ELF binary.

---

## Overview of the Rust Compilation Chain

When you run `cargo build` or `rustc`, here is what happens under the hood:

```
              ┌──────────────────────────────────────────────────────┐
              │                    Rust Compiler                     │
              │                                                      │
  main.rs ───▶│  Parsing ──▶ HIR ──▶ MIR ──▶ LLVM IR ──▶ Object code │
              │                                (.o / .rlib)          │
              └──────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
              ┌──────────────────────────────────────────────────────┐
              │              GNU Linker (ld / cc)                    │
              │                                                      │
              │  Application .o                                      │
              │  + .rlib Rust stdlib (libstd, libcore, liballoc…)    │──▶ ELF executable
              │  + .a / .so C libraries (libc, libpthread…)          │
              │  + crt0 / crti / crtn (C runtime startup)            │
              └──────────────────────────────────────────────────────┘
```

Two essential points emerge from this diagram:

1. **`rustc` does not directly produce an executable.** It generates object code (`.o`) via the LLVM backend, then delegates linking to the system linker — by default `cc` (which invokes `ld` internally) on GNU/Linux distributions.

2. **The final binary goes through the C runtime.** Even a "pure" Rust program is linked with `crt0.o`, `crti.o`, `crtn.o` and the system `libc`. The actual ELF entry point is not `main()` but `_start`, which calls `__libc_start_main`, which eventually calls the Rust `main` (after Rust runtime initialization). This detail is identical to classic C, and the RE analyst finds the same patterns at the very beginning of execution.

---

## Rust and LLVM: Why It Is Not GCC

Unlike the C/C++ binaries covered in previous chapters (compiled directly by GCC), Rust uses **LLVM** as its code generation backend. The `rustc` compiler transforms source code into an LLVM intermediate representation (LLVM IR), then LLVM produces the machine code.

This has direct consequences on what the analyst observes in the disassembly:

**The assembly idioms differ from those of GCC.** LLVM and GCC do not emit the same machine code for the same operations. For example, LLVM tends to use `cmov` (conditional move) more aggressively than GCC, to organize basic blocks differently, and to produce function prologues/epilogues with slightly different sequences. If you are accustomed to the GCC patterns from Chapter 16, expect subtle but noticeable differences.

**The optimizations are LLVM's, not GCC's.** The optimization passes (inlining, loop unrolling, vectorization, dead code elimination) are applied by LLVM. The optimized result resembles what Clang (LLVM's C/C++ compiler) would produce rather than GCC. If you have already compared GCC and Clang as in Chapter 16.7, you will recognize the same LLVM "flavors" in Rust binaries.

**But the linker remains GNU.** This is the convergence point with the GNU toolchain: once the object code is produced by LLVM, it is indeed `ld` (or `gold`, or `mold` if configured) that performs the linking. The ELF sections, symbol tables, PLT/GOT resolution, RELRO — all of this is identical to a C binary linked with the GNU toolchain. The analyst can therefore apply the same ELF inspection techniques seen in Chapter 2.

> 💡 **For the RE analyst**, this distinction means that your ELF inspection tools (`readelf`, `objdump`, `checksec`) work exactly as on a C binary, but the patterns at the instruction level will be "LLVM-flavored" rather than "GCC-flavored".

---

## Linking in Detail: What Goes Into the Binary?

### Static Linking of the Rust stdlib

By default, Rust **statically** links its standard library. This includes:

- **`libcore`** — primitive types, `Option`, `Result`, iterators, fundamental traits.  
- **`liballoc`** — memory allocator, `Box`, `Vec`, `String`, `Rc`, `Arc`.  
- **`libstd`** — I/O, networking, threads, filesystem, `HashMap`, and everything OS-dependent.  
- **`libpanic_unwind`** (or `libpanic_abort`)** — panic mechanism.

All this code ends up **embedded in the final binary**. This is why a "Hello, World!" in Rust weighs several megabytes while its C equivalent fits in a few kilobytes.

Let's verify with our crackme:

```bash
$ cd binaries/ch33-rust/
$ make debug release release-strip

$ ls -lh crackme_rust_*
-rwxr-xr-x 1 user user  15M  crackme_rust_debug
-rwxr-xr-x 1 user user 4.3M  crackme_rust_release
-rwxr-xr-x 1 user user 406K  crackme_rust_strip
```

> ⚠️ Exact sizes vary depending on the `rustc` version and platform, but the orders of magnitude are representative.

The debug binary is **~15 MB** for a program of about a hundred lines. The optimized release drops to **~4 MB** thanks to LLVM's dead code elimination. The stripped version with LTO and `panic=abort` goes under one megabyte, because LTO allows LLVM to eliminate even more unused functions and `panic=abort` removes the entire unwinding mechanism.

### Dynamic Linking of the libc

Although the Rust stdlib is statically linked, the **system libc** (`glibc` or `musl`) remains **dynamically** linked by default. We can verify this:

```bash
$ ldd crackme_rust_release
    linux-vdso.so.1 (0x00007ffc...)
    libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f...)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
    /lib64/ld-linux-x86-64.so.2 (0x00007f...)

$ ldd crackme_rust_debug
    # Same list — the libc is always dynamic
```

We find the classic dependencies: `libc.so.6`, `libgcc_s.so.1` (for stack unwinding), and the loader `ld-linux-x86-64.so.2`. The analyst therefore finds the usual PLT/GOT mechanisms for libc calls (`write`, `read`, `mmap`, `pthread_*`, etc.).

> 💡 It is possible to produce a **fully static** Rust binary by compiling with the `x86_64-unknown-linux-musl` target (musl libc statically linked). In that case, `ldd` will display "not a dynamic executable" and there will be neither PLT nor GOT — only direct syscalls. This is a case encountered in certain command-line tools distributed as single binaries.

---

## ELF Anatomy of a Rust Binary

The ELF sections of a Rust binary are the same as those of a C/C++ binary. Nothing Rust-specific at the format level — it is the content that differs.

```bash
$ readelf -S crackme_rust_release | grep -E '^\s+\[' | head -20
```

We find the usual sections: `.text`, `.rodata`, `.data`, `.bss`, `.plt`, `.got`, `.got.plt`, `.eh_frame`, `.eh_frame_hdr`, `.symtab`, `.strtab`, `.dynstr`, `.dynsym`.

Some specific observations:

**`.rodata` is massive.** Rust stores a significant amount of read-only data there: string literals (with their lengths), panic messages, formatting information (`fmt::Arguments`), trait tables, and RTTI-like data used by the panic mechanism. On our release crackme, `.rodata` represents a significant portion of the binary.

```bash
$ readelf -S crackme_rust_release | grep rodata
  [17] .rodata           PROGBITS    ...   0001a3c0  000000  ...
```

**`.eh_frame` is large when `panic = "unwind"`.** Rust's unwinding mechanism (identical in principle to C++) relies on `.eh_frame` tables to unwind the stack in case of panic. With the `release-strip` profile configured with `panic = "abort"`, this section is nearly absent, because the program directly calls `abort()` on panic instead of unwinding the stack.

```bash
$ size crackme_rust_release crackme_rust_strip
   text    data     bss     dec     hex filename
 387234    9520     280  397034   60e6a crackme_rust_release
  78642    4896     280   83818   4776a crackme_rust_strip
```

The difference in `text` segment size between the two variants illustrates the combined impact of LTO and `panic=abort`.

**No Rust-specific section.** Unlike Go (which has dedicated sections like `gopclntab`, see Chapter 34), Rust does not create any custom section in the ELF. The analyst has no "structural marker" indicating that it is a Rust binary — they must deduce it from the content (name mangling, panic messages, code patterns).

---

## Symbols: A Gold Mine When Present

### Non-stripped Binary

On a non-stripped Rust binary, the symbol table is exceptionally rich. Rust name mangling (detailed in section 33.2) encodes the full path of each function: crate, module, type, method, and generic parameters.

```bash
$ nm crackme_rust_release | wc -l
    8234

$ nm crackme_rust_release | grep 'T ' | head -10
```

Over 8,000 symbols for a program of about a hundred lines — the vast majority come from the stdlib. Among them, we find our application functions:

```bash
$ nm crackme_rust_release | grep crackme_rust
```

The symbols are in mangled form. For example, the `ChecksumValidator::new` function appears in a form like:

```
_RNvMNtCs...crackme_rust...ChecksumValidator3new
```

The `_R` prefix immediately identifies a Rust symbol ("v0" mangling format). We will detail the decoding in section 33.2.

### Stripped Binary

On the stripped binary, the situation changes dramatically:

```bash
$ nm crackme_rust_strip
nm: crackme_rust_strip: no symbols

$ nm -D crackme_rust_strip | wc -l
    42
```

The `.symtab` table has been removed. Only dynamic symbols (`.dynsym`) remain, corresponding to functions imported from the libc. All application logic and the stdlib have become anonymous.

This is the realistic scenario: outside the open-source world, distributed Rust binaries are almost always stripped. The analyst must then rely on other clues to reconstruct the program's structure.

### What Survives Stripping

Even on a stripped binary, certain elements remain exploitable:

**Character strings.** Panic messages systematically contain the source path (`src/main.rs:42:5`) and the error message. These strings survive stripping because they are data in `.rodata`, not symbols.

```bash
$ strings crackme_rust_strip | grep -E '\.rs:'
src/main.rs:87:42  
src/main.rs:103:17  
library/core/src/fmt/mod.rs:...  
library/core/src/panicking.rs:...  
```

These paths reveal not only that it is a Rust binary, but also the module structure and source code line numbers. This is an extremely valuable clue that is not found in a stripped C binary (unless compiled with `-g`, which is rare in production).

> ⚠️ With `panic = "abort"` and `strip = true`, some panic messages are nonetheless reduced or eliminated. The `release-strip` profile of our `Cargo.toml` uses `panic = "abort"`, which removes some of these strings. In practice, many Rust projects keep `panic = "unwind"` even in release, which leaves more traces.

**Libc and runtime strings.** Calls to the libc go through the PLT and the names of imported functions remain visible in `.dynsym`:

```bash
$ readelf -d crackme_rust_strip | grep NEEDED
 0x0000000000000001 (NEEDED)    Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)    Shared library: [libc.so.6]
```

**Constants in `.rodata`.** Application string literals (our error messages, the `RUST-` prefix, the banner, etc.) are always present:

```bash
$ strings crackme_rust_strip | grep -i "rust"
RUST-  
RustCrackMe-v3.3  
```

---

## Identifying a Rust Binary Without Symbols

When you encounter an unknown and stripped ELF binary, how do you know it was compiled in Rust? Several heuristics converge:

**Stdlib panic messages.** The presence of strings containing `panicked at`, `unwrap()`, `called \`Option::unwrap()\` on a \`None\` value`, or paths like `library/core/src/` or `library/std/src/` is a near-certain marker.

```bash
$ strings crackme_rust_strip | grep -c "panick"
```

**`.rs` source paths.** Even stripped, the binary often contains paths like `src/main.rs`, `src/lib.rs`, or crate paths (`/home/user/.cargo/registry/src/...`). The `.rs` suffix and the `src/` structure are characteristic.

**The abnormally large size.** A simple program weighing several megabytes without exotic dynamic dependencies suggests massive static linking — typical of Rust (and Go, but Go has other markers, see Chapter 34).

**The presence of `libgcc_s.so.1` in the dependencies.** This library is necessary for stack unwinding and is almost always present on Rust binaries compiled with `panic = "unwind"`.

**The absence of C++ mangled symbols.** If the binary is large, contains panic messages with `.rs` paths, but no Itanium symbols (`_Z...`), it is very likely Rust and not C++.

---

## Impact of Compilation Options on RE

The following table summarizes the effect of the main Rust compilation options on the difficulty of reverse engineering. These options are controlled via `Cargo.toml` (profiles) or via flags passed directly to `rustc`.

| Option | Effect on the binary | RE Impact |  
|---|---|---|  
| `opt-level = 0` | No optimization, code 1:1 with source | Readable, direct correspondence with Rust source |  
| `opt-level = 3` | Aggressive inlining, vectorization, elimination | Merged functions, reorganized control flow |  
| `debug = true` | Full DWARF information | Variable names, types, line numbers in GDB |  
| `debug = false` | No DWARF | Loss of variable names and source correspondence |  
| `strip = true` | Removal of `.symtab` and `.strtab` | No more function names, purely structural analysis |  
| `lto = true` | Link-Time Optimization (inter-crate) | Boundaries between crates erased, cross-crate inlining |  
| `panic = "unwind"` | Full unwinding mechanism | Large `.eh_frame`, rich panic messages |  
| `panic = "abort"` | Direct `abort()` on panic | Smaller binary, fewer panic strings |  
| `codegen-units = 1` | Single codegen thread | Better global optimizations, more inlining |

The most difficult combination to reverse is that of our `release-strip` profile: `opt-level = 3` + `lto = true` + `strip = true` + `panic = "abort"` + `codegen-units = 1`. It is also the most common combination in production.

---

## The `cargo` Command and the Linker: Seeing What Happens

To observe the complete compilation chain, including the linker invocation, you can ask `cargo` to be verbose:

```bash
$ cd binaries/ch33-rust/crackme_rust/
$ cargo build --release -v 2>&1 | tail -5
```

The last line of the verbose output shows the linker call with all its arguments. You typically see:

```
cc -m64 [...] crackme_rust.o [...] -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc [...]
```

This is a call to `cc` (a wrapper for `gcc`) which invokes the GNU linker, passing it the Rust object files and system libraries. We find `-lpthread` (POSIX threads, used by the Rust runtime), `-ldl` (dynamic loading), and `-lc` (libc).

> 💡 This command is useful for understanding exactly which libraries are dynamically linked to the binary. By changing the linker (via the `RUSTFLAGS="-C linker=..."` variable or via `.cargo/config.toml`), you can also use `mold` or `lld` instead of `ld` — which does not change the ELF format but may slightly affect the section layout.

---

## Summary for the RE Analyst

When you open a Rust binary in your disassembler:

- **The ELF format is standard.** All inspection tools (`readelf`, `objdump`, `checksec`, `nm`, `ldd`) work normally. There is nothing "magical" about a Rust binary at the format level.

- **The code volume is massive.** Do not be surprised to find thousands of functions when the program seems simple. The vast majority come from the statically linked Rust stdlib. Your priority is to isolate the application code — we will see how in sections 33.5 and 33.6.

- **The assembly patterns are LLVM, not GCC.** If you know GCC idioms, expect differences. On the other hand, if you have already analyzed Clang binaries, you will be on familiar ground.

- **Symbols are your best ally.** When they are present, Rust symbols encode a considerable amount of information (full path, generic types). When they are absent, strings in `.rodata` (panic messages, source paths) take over as the first structural clue.

- **The entry point is classic.** `_start` → `__libc_start_main` → Rust `main`. The Rust runtime initializes the allocator and the panic mechanism before calling your `fn main()`, but this initialization is known and identifiable code with stdlib signatures.

---

> **Next section: 33.2 — Rust vs C++ Name Mangling: Decoding Symbols** — we will dive into Rust's "v0" mangling format, the tools to decode it, and how to leverage demangled symbols to speed up analysis.

⏭️ [Rust vs C++ Name Mangling: Decoding Symbols](/33-re-rust/02-rust-name-mangling.md)
