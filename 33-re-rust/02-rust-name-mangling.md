🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 33.2 — Rust vs C++ Name Mangling: Decoding Symbols

> 🏷️ Name mangling is the transformation that the compiler applies to function and type names to make them unique in the symbol table. Rust and C++ use two radically different schemes. Recognizing them at first glance and knowing how to decode them is one of the first reflexes to acquire when facing a non-stripped binary.

---

## Why Name Mangling Exists

An ELF binary cannot contain two symbols with the same name. Yet, in a language like Rust or C++, it is common to have multiple functions with the same "human" name: methods in different modules, generic functions instantiated with different types, trait implementations for different types, etc.

The compiler solves this problem by encoding in the symbol name all the information necessary to make it unique: the module path (crate, submodule), the type name, the method name, the generic parameters, and a disambiguation hash.

For the RE analyst, the mangled symbol is a gold mine of information — **provided you know how to read it**.

---

## C++ Mangling (Itanium ABI) — Refresher

As seen in Chapter 17.1, C++ compilers conforming to the Itanium ABI (GCC, Clang) use a mangling scheme that begins with the `_Z` prefix. Here is a quick refresher:

```
Mangled symbol:   _ZN7MyClass6methodEi
                  ││ │       │      ││
                  │╰─┤       │      │╰── parameter type: int
                  │  │       │      ╰─── E = end of qualified part
                  │  │       ╰────────── "method" (6 characters)
                  │  ╰────────────────── "MyClass" (7 characters)
                  ╰───────────────────── _ZN = C++ symbol in a namespace

Demangled:        MyClass::method(int)
```

The characteristics of Itanium mangling that the RE analyst recognizes instantly:

- `_Z` prefix (or `_ZN` for qualified names).  
- Names are "length-prefixed" encoded: the number indicates the count of characters that follow.  
- Parameter types are encoded by letters: `i` = `int`, `d` = `double`, `Ss` = `std::string`, etc.  
- The `c++filt` tool decodes them perfectly.

---

## Rust Mangling — The "v0" Format

Rust has used several mangling schemes throughout its evolution. The current scheme, called **"v0"** (or "RFC 2603"), has been stable since Rust 1.57 (late 2021). This is the one found in all recent Rust binaries.

### Recognizing a Rust Symbol

The criterion is simple: **a Rust v0 symbol starts with `_R`**.

```
_RNvNtCs9g8eSEAj0m_13crackme_rust17ChecksumValidator3new
^^
Rust v0 prefix
```

This `_R` prefix is the equivalent of C++'s `_Z`. As soon as you see `_R` in a symbol table, you know it is Rust.

> ⚠️ **Caution regarding legacy mangling.** Binaries compiled with Rust versions prior to 1.57 (or with the `-C symbol-mangling-version=legacy` option) use an older scheme that superficially resembles C++ mangling: symbols start with `_ZN` and contain a 17-character hexadecimal hash at the end (prefixed with `h`). This format is increasingly rare, but it can mislead an analyst who mistakes it for C++ Itanium. The distinguishing clue is precisely this `h` suffix followed by a fixed-length hexadecimal hash.

### Anatomy of a Rust v0 Symbol

Let's dissect a complete symbol from our crackme:

```
_RNvNtCs9g8eSEAj0m_13crackme_rust17ChecksumValidator3new
```

The decoding reads from left to right:

```
_R                         → Prefix: Rust v0 symbol
  N                        → Namespace path (start of qualified path)
   v                       → "value" namespace (function, constant)
    Nt                     → Nested in a "type" namespace
      Cs9g8eSEAj0m_       → Crate hash (unique crate identifier)
        13crackme_rust     → Crate name: "crackme_rust" (13 characters)
          17ChecksumValidator → Type name: "ChecksumValidator" (17 chars)
            3new           → Function name: "new" (3 chars)
```

The demangled result is:

```
crackme_rust::ChecksumValidator::new
```

### Namespace Prefixes

The v0 mangling distinguishes two types of namespaces, encoded by a lowercase letter after `N`:

| Letter | Namespace | Meaning |  
|---|---|---|  
| `v` | Value | Functions, constants, static variables |  
| `t` | Type | Types (`struct`, `enum`, `trait`, `impl`) |

This distinction is useful in RE: it immediately tells you whether a symbol is a function or a type, even before demangling it.

### Generic Types

When a Rust function is generic, the concrete type parameters are encoded in the mangled symbol. For example, an instantiation of `Vec<u32>::push` might appear as:

```
_RNvMs_NtCs...5alloc3vec8Vec$u20$u32$GT$4push
```

Types are encoded with special markers: `$u20$` for a space, `$GT$` for `>`, `$LT$` for `<`, `$RF$` for `&`, etc. The demangled symbol gives:

```
<alloc::vec::Vec<u32>>::push
```

This information is valuable: it tells you exactly which concrete type is being manipulated, which helps reconstruct the program's data structures.

### The Crate Hash

Each compiled crate is assigned a unique hash (the `Cs9g8eSEAj0m_` sequence in our example). This hash guarantees uniqueness even if two crates have the same name. For the RE analyst, this hash makes it possible to **group all functions from the same crate** by filtering on a common prefix, which is very useful for separating application code from stdlib code.

---

## Decoding Symbols in Practice

### `rustfilt` — Rust's `c++filt`

The reference tool for demangling Rust symbols is **`rustfilt`**, installable via `cargo`:

```bash
$ cargo install rustfilt
```

Its usage is identical to `c++filt` — it reads from standard input and replaces mangled symbols with their readable form:

```bash
$ echo "_RNvNtCs9g8eSEAj0m_13crackme_rust17ChecksumValidator3new" | rustfilt
crackme_rust::ChecksumValidator::new
```

It can be used in a pipe with `nm`, `objdump` or any tool that displays symbols:

```bash
$ nm crackme_rust_release | rustfilt | grep crackme_rust
```

This command displays all application symbols of the crackme in demangled form, providing an immediate map of the program.

### `nm` with Built-in Demangling

Recent versions of `nm` (binutils ≥ 2.36) natively recognize Rust v0 mangling via the `--demangle` (or `-C`) option:

```bash
$ nm -C crackme_rust_release | grep crackme_rust
```

Depending on the binutils version, the result may be partial or complete. If demangling seems incomplete, use `rustfilt` which is always up to date with format changes.

### `c++filt` — Does NOT Work for Rust v0

This is a classic pitfall. The `c++filt` tool only understands C++ Itanium mangling. Applied to a Rust v0 symbol, it leaves it unchanged:

```bash
$ echo "_RNvNtCs9g8eSEAj0m_13crackme_rust17ChecksumValidator3new" | c++filt
_RNvNtCs9g8eSEAj0m_13crackme_rust17ChecksumValidator3new
```

The symbol comes out as-is — `c++filt` does not know what to do with it. However, `c++filt` does work on Rust symbols in the **legacy** format (those starting with `_ZN...h<hash>`) since they borrow the Itanium syntax. But the result is then misleading because the internal naming conventions are not the same.

> 💡 **Simple rule**: `_Z` → `c++filt`; `_R` → `rustfilt`.

### Demangling in Disassemblers

Modern disassemblers handle Rust v0 mangling to varying degrees:

**Ghidra** (≥ 10.2) recognizes and automatically demangles Rust v0 symbols upon import. Function names appear in their readable form in the Symbol Tree and Listing. If demangling does not happen automatically, check that the "Demangle Rust" option is enabled in the analysis options (Analysis → One Shot → Demangler Rust).

**IDA** (≥ 7.7 / recent IDA Free) supports Rust demangling in its recent versions. Older versions leave symbols mangled, in which case an IDAPython script calling `rustfilt` as a subprocess can fill the gap.

**Radare2 / Cutter** supports Rust demangling via the `iDr` command (list demangled Rust symbols) or by enabling global demangling with `e asm.demangle=true`. Support has progressively improved across versions.

**Binary Ninja** handles Rust v0 mangling natively in its recent versions.

---

## Side-by-Side Comparison: Rust v0 vs C++ Itanium

The following table parallels the two schemes for analogous constructs. This comparison helps develop the recognition reflex.

| Concept | C++ (Itanium) | Rust (v0) |  
|---|---|---|  
| **Prefix** | `_Z` | `_R` |  
| **Free function** | `_Z3fooi` → `foo(int)` | `_RNvCs..._7mycrate3foo` → `mycrate::foo` |  
| **Method** | `_ZN7MyClass3barEv` → `MyClass::bar()` | `_RNvNtCs..._7mycrate7MyClass3bar` → `mycrate::MyClass::bar` |  
| **Nested namespace** | `_ZN2ns7MyClass3barEi` → `ns::MyClass::bar(int)` | `_RNvNtNtCs..._7mycrate2ns7MyClass3bar` → `mycrate::ns::MyClass::bar` |  
| **Template / Generic** | `_Z3fooIiEvT_` → `void foo<int>(int)` | Types encoded in the path with `$LT$`, `$GT$` |  
| **Type encoding** | Compact letters (`i`, `d`, `Ss`…) | No parameter type encoding in the symbol |  
| **Hash / Disambiguation** | None (except ABI tag) | Systematic crate hash |  
| **Demangling tool** | `c++filt` | `rustfilt` |

A fundamental difference: C++ mangling encodes the **parameter types** of the function (to distinguish overloads), whereas Rust mangling does not. Rust does not have function overloading in the C++ sense — two functions in the same scope cannot have the same name with different signatures. Uniqueness is guaranteed by the module path and the crate hash.

---

## Leveraging Demangled Symbols for RE

On a non-stripped Rust binary, demangled symbols provide a nearly complete map of the program. Here is how to get the most out of them.

### Separating Application Code from the stdlib

The crate hash in each symbol allows filtering by origin. All functions from our crackme share the same crate hash:

```bash
$ nm crackme_rust_release | rustfilt | grep '^[0-9a-f]* T' | \
    grep 'crackme_rust::' | head -15
```

Conversely, stdlib functions begin with known prefixes:

```bash
$ nm crackme_rust_release | rustfilt | grep -E '(core|std|alloc)::' | wc -l
```

This simple filtering separates the few dozen application functions from the thousands of stdlib functions, drastically reducing the analysis surface.

### Reconstructing the Program Architecture

Demangled symbols directly reveal the modular structure:

```
crackme_rust::main  
crackme_rust::print_banner  
crackme_rust::usage_and_exit  
crackme_rust::determine_license  
crackme_rust::ValidationPipeline::new  
crackme_rust::ValidationPipeline::add  
crackme_rust::ValidationPipeline::run  
crackme_rust::PrefixValidator::validate      (via <PrefixValidator as Validator>::validate)  
crackme_rust::FormatValidator::validate       (via <FormatValidator as Validator>::validate)  
crackme_rust::ChecksumValidator::new  
crackme_rust::ChecksumValidator::validate     (via <ChecksumValidator as Validator>::validate)  
crackme_rust::LicenseType::max_features  
```

In a single command, you get the list of all functions, their modules, and the trait implementation relationships (the `<Type as Trait>::method` symbols explicitly indicate which type implements which trait). This is the equivalent of a class diagram, extracted directly from the binary.

### Identifying Generic Instantiations

Symbols of instantiated generic functions contain the concrete types. By searching for instantiations of standard types, you can deduce which types the application uses:

```bash
$ nm crackme_rust_release | rustfilt | grep 'Vec<' | sort -u
```

This command lists all `Vec` instantiations in the binary. If you see `Vec<Box<dyn crackme_rust::Validator>>`, you know the program stores polymorphic validators in a vector — high-level structural information obtained without reading a single assembly instruction.

### Finding Trait Implementations

Trait vtable symbols (see section 33.3 for details on trait objects) appear with explicit names:

```bash
$ nm crackme_rust_release | rustfilt | grep 'vtable'
```

Each listed vtable corresponds to a concrete implementation of a trait for a given type. This is the direct equivalent of C++ vtables from Chapter 17.2, but with naming that explicitly encodes the `Type → Trait` relationship.

---

## What to Do When the Binary Is Stripped?

On a stripped binary, mangled symbols are gone. But all is not lost. Here are the fallback strategies, ranked by effectiveness:

**1. Panic strings.** As seen in section 33.1, panic messages contain source paths (`src/main.rs:42:5`). By cross-referencing the line number with the address of the code that references this string (via XREFs in Ghidra), you can assign an approximate name to each function.

**2. Known function signatures.** Community projects provide signature databases for the Rust stdlib, usable in Ghidra (FIDB format) or IDA (FLIRT format). We will detail them in section 33.6. Applying these signatures allows automatically naming hundreds of stdlib functions, which clears the way to the application code.

**3. Comparison with a reference binary.** If you can compile a Rust program with the same `rustc` version and the same target, you get a reference binary whose stdlib functions are at the same relative offset. Binary diffing tools (Chapter 10) then allow transferring the names of identified functions.

**4. Structural patterns.** Even without names, Rust functions have recognizable signatures at the assembly level (section 33.3). An `unwrap` always generates the same pattern: discriminant test followed by a branch to a panic call. A trained analyst eventually recognizes these constructs on sight.

---

## Summary: Reflexes to Acquire

| Situation | Action |  
|---|---|  
| You see `_R` in `nm` | It's Rust v0 → use `rustfilt` |  
| You see `_ZN...h<16 hex>` | It's legacy Rust → `c++filt` works partially, prefer `rustfilt` |  
| You see `_ZN...` without `h` hash | It's classic C++ Itanium → `c++filt` |  
| Non-stripped binary | `nm -C` or `nm \| rustfilt` to map the program in 30 seconds |  
| Stripped binary | Panic strings + stdlib signatures + diffing to reconstruct names |  
| In Ghidra | Check that "Demangler Rust" is enabled in the analysis options |  
| Targeted search | Filter by crate name to isolate application code |

---

> **Next section: 33.3 — Recognizing Rust Patterns: `Option`, `Result`, `match`, panics** — we move from the symbol level to the instruction level to identify idiomatic Rust constructs in the disassembly.

⏭️ [Recognizing Rust Patterns: `Option`, `Result`, `match`, panics](/33-re-rust/03-patterns-option-result-match.md)
