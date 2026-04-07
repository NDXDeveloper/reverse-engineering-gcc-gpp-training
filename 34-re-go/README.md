🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 34 — Reverse Engineering Go Binaries

> 🐹 *Go produces statically linked native ELF binaries, embedding a complete runtime. Their reverse engineering is disconcerting at first contact, but the language's internal structures — once understood — paradoxically become a powerful ally for the analyst.*

---

## Why a chapter dedicated to Go?

Go (sometimes called Golang) has become a language of choice for developing system tools, cloud infrastructure, CLIs, and — it must be acknowledged — modern malware. Projects like Docker, Kubernetes, Terraform, and Caddy are written in Go. On the offensive side, many recent malware families (Bazar, Sunshuttle, Kaiji, certain ransomware) have adopted Go for its ease of cross-compilation and the imposing size of its binaries, which complicates analysis.

As a reverse engineer, you will inevitably encounter a Go binary. And the first encounter is often disconcerting: the binary weighs several megabytes even for a simple "Hello, World!", `objdump` displays thousands of unknown functions, Ghidra's decompiler produces barely readable pseudo-code, and calling conventions don't resemble what you know from C or C++.

This chapter gives you the keys to transform this apparent complexity into an advantage.

---

## What makes Go binaries so different

### A complete embedded runtime

Unlike a C program that delegates most work to the kernel and libc, a Go binary embeds its own runtime: a goroutine scheduler, a garbage collector, a memory allocator, extensible stack management, and the entirety of the used standard library. A three-line `main.main()` drags behind it hundreds of internal functions prefixed with `runtime.`, `sync.`, `fmt.`, `os.`, etc. This explains the characteristic size of Go binaries — often between 2 and 15 MB for a command-line tool — and the considerable noise in the function list.

### Static linking by default

By default, the Go compiler produces a statically linked binary. There are no dependencies on `libc.so` or other shared libraries (unless CGo is explicitly enabled). Consequently, `ldd` will respond `not a dynamic executable`, and the binary will embed its own wrappers around Linux system calls via `runtime.syscall` or `syscall.Syscall6`. This autonomy complicates initial triage: tools like `ltrace` won't capture anything, and `strace` will remain your main dynamic analysis ally.

### Non-standard calling conventions

Through Go 1.16 inclusive, Go used an entirely stack-based calling convention — all arguments and all return values went through the stack, without using the `rdi`, `rsi`, `rdx` registers you'd expect in code following the System V AMD64 ABI. Since Go 1.17, a register-based convention was introduced, closer to (but not identical to) what C does. In practice, you'll encounter both variants depending on the compiler version, which directly affects how you read the disassembly.

### Rich metadata, even after stripping

This is Go's paradox: even a stripped binary retains rich internal structures. The `gopclntab` table (Go PC-Line Table), `runtime._type` type information, and module tables often allow recovering function names, line-by-line correspondences, and type definitions — information that stripping a C binary would permanently destroy. These metadata, intended for the runtime (stack traces, garbage collector, reflection), become a gift for the reverse engineer who knows where to look.

---

## Prerequisites for this chapter

This chapter assumes you're comfortable with the concepts covered in previous parts, particularly:

- Disassembly and navigation in Ghidra (Chapter 8),  
- x86-64 assembly basics and System V calling conventions (Chapter 3),  
- Using GDB for dynamic analysis (Chapter 11),  
- Stripping concepts and symbol reconstruction (Chapter 19).

No prior knowledge of the Go language is strictly necessary, but basic familiarity with its syntax (functions, goroutines, slices, interfaces) will greatly facilitate understanding. If you've never written Go, a quick run through the *Tour of Go* (tour.golang.org) in one hour is enough to acquire the vocabulary.

---

## Training binary

The binary used throughout this chapter is `crackme_go`, whose sources are in `binaries/ch34-go/crackme_go/main.go`. The associated `Makefile` produces several variants:

| Variant | Description |  
|---|---|  
| `crackme_go` | Standard binary with symbols |  
| `crackme_go_strip` | Stripped binary (`strip -s`) |  
| `crackme_go_upx` | Stripped then UPX-compressed binary |  
| `crackme_go_nopie` | Binary without PIE (fixed addresses, easier static analysis) |  
| `crackme_go_race` | Binary with data race detector (additional runtime instrumentation) |

Compile everything with `make` from the `binaries/ch34-go/` directory. You can verify the Go compiler version embedded in the binary with `go version crackme_go` or by searching for the `go1.` string in the `strings` output.

---

## Chapter outline

| Section | Topic |  
|---|---|  
| 34.1 | Go runtime specifics: goroutines, scheduler, GC |  
| 34.2 | Go calling convention (stack-based then register-based since Go 1.17) |  
| 34.3 | Go data structures in memory: slices, maps, interfaces, channels |  
| 34.4 | Recovering function names: `gopclntab` and `go_parser` for Ghidra/IDA |  
| 34.5 | Strings in Go: `(ptr, len)` structure and implications for `strings` |  
| 34.6 | Stripped Go binaries: recovering symbols via internal structures |  
| 🎯 | **Checkpoint**: analyze a stripped Go binary, recover functions and reconstruct the logic |

---

## Tips before getting started

**Don't panic at the volume.** A typical Go binary contains thousands of functions, but the vast majority belong to the runtime and standard library. Your actual target — the business code written by the developer — is generally hiding in the `main` package and a few internal packages. Learning to filter noise to focus on the signal is the core skill of this chapter.

**Think in terms of packages, not files.** Go's organizational unit is the package, and this is directly reflected in symbol names: `main.checkLicense`, `crypto/aes.newCipher`, `net/http.(*Client).Do`. This hierarchical naming convention — when accessible — is a goldmine for understanding a Go program's architecture without its sources.

**Equip yourself.** The RE ecosystem has caught up on Go. Scripts like `go_parser` for IDA, Mandiant's `GoReSym` module, or analyzers integrated into the latest Ghidra versions considerably facilitate the work. We'll cover them in detail in section 34.4.

⏭️ [Go runtime specifics: goroutines, scheduler, GC](/34-re-go/01-runtime-goroutines-gc.md)
