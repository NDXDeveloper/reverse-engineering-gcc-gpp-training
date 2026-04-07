🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 7.6 — `c++filt` — demangling C++ symbols

> 🔧 **Tools used**: `c++filt`, `nm`, `objdump`, `readelf`  
> 📦 **Binaries**: `oop` (`binaries/ch22-oop/` directory)  
> 📝 **Syntax**: Intel (via `-M intel`)

---

## Why a dedicated section for `c++filt`?

Section 7.5 introduced *name mangling* and showed that the `-C` option of `objdump` and `nm` decodes it automatically. So why dedicate an entire section to `c++filt`?

Because `-C` does not cover all scenarios. You will encounter mangled names **outside** `objdump` and `nm`: in crash logs, in `readelf` output, in Valgrind reports, in `strace`/`ltrace` traces, in text files exported by Ghidra, in Python script outputs, in linker error messages, or simply copy-pasted into a terminal. `c++filt` is the dedicated standalone demangling tool: it takes a mangled name as input and produces its readable version as output, independently of any other tool.

It's also a tool you can integrate into **shell pipelines**, which makes it indispensable as soon as you script your analyses.

---

## Basic usage

### Direct argument mode

The simplest form: pass one or more mangled names as arguments.

```bash
$ c++filt _ZN6Animal5speakEv
Animal::speak()

$ c++filt _ZN3DogC1ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEi
Dog::Dog(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, int)
```

You can pass multiple symbols at once:

```bash
$ c++filt _ZN6Animal5speakEv _ZN3Cat5speakEv _ZN3Dog5speakEv
Animal::speak()  
Cat::speak()  
Dog::speak()  
```

Each name is demangled independently, one per line.

### Filter mode (stdin)

This is the most powerful mode. `c++filt` reads its standard input line by line and replaces **every mangled name** it finds in the text, leaving the rest intact. That means you can plug it at the end of any pipeline without disturbing the output formatting:

```bash
$ nm binaries/ch22-oop/oop | c++filt
```

The result is identical to `nm -C`, but the mechanics differ: here, `nm` produces its raw output (with mangled names), and `c++filt` transforms it downstream. This approach is more flexible because it works with **any text source**, not only tools that support `-C`.

The filter is smart: it recognizes mangled names in the middle of a text line and does not touch the rest. For example:

```bash
$ echo "The function _ZN6Animal5speakEv is called here" | c++filt
The function Animal::speak() is called here
```

Surrounding text is preserved, only the mangled name is replaced. That's what makes `c++filt` usable on arbitrary outputs: logs, error reports, disassembler exports, comments, etc.

---

## Integration into analysis pipelines

### With `readelf`

Unlike `objdump` and `nm`, some versions of `readelf` do not have a `-C` option. Piping to `c++filt` solves the problem:

```bash
# Demangled dynamic symbols
$ readelf --dyn-syms binaries/ch22-oop/oop | c++filt

# Full demangled symbol table
$ readelf -s binaries/ch22-oop/oop | c++filt
```

### With `objdump` (when `-C` is not enough)

Sometimes, you want to post-process an `objdump` listing already saved to a file. Rather than regenerating it with `-C`, filter the existing file:

```bash
$ c++filt < oop_disasm.asm > oop_disasm_demangled.asm
```

### With `addr2line`

The `addr2line` tool, which converts addresses to file names and line numbers, produces mangled names by default. Piping to `c++filt` makes the output readable:

```bash
$ addr2line -f -e binaries/ch22-oop/oop 0x1234 | c++filt
Animal::speak()
/home/user/oop.cpp:42
```

(`addr2line` also accepts the `-C` option directly, but the pipe version works with every version.)

### With crash logs and backtraces

Backtraces produced by `glibc` (via `backtrace_symbols()`), by GDB, or by crash handlers often contain mangled names:

```
#3  0x00005555555552a0 in _ZN3Dog5speakEv ()
#4  0x0000555555555380 in _ZN6AnimalC2ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEi ()
```

Pass the entire backtrace through `c++filt`:

```bash
$ cat crash.log | c++filt
#3  0x00005555555552a0 in Dog::speak() ()
#4  0x0000555555555380 in Animal::Animal(std::__cxx11::basic_string<...>, int) ()
```

The backtrace instantly becomes understandable.

### With `grep` to filter then demangle

Pipeline order matters. If you're looking for a specific mangled symbol, filter **before** demangling (searching on the mangled name is more precise):

```bash
# Find all Animal class methods, then demangle
$ nm binaries/ch22-oop/oop | grep '_ZN6Animal' | c++filt
0000000000001234 T Animal::speak()
0000000000001380 T Animal::Animal(std::__cxx11::basic_string<...>, int)
00000000000013f0 T Animal::~Animal()
```

If you're searching by demangled name (for example all functions containing `speak`), demangle **before** filtering:

```bash
# Demangle then search by readable name
$ nm binaries/ch22-oop/oop | c++filt | grep 'speak'
0000000000001234 T Animal::speak()
00000000000012a0 T Dog::speak()
0000000000001310 T Cat::speak()
```

The nuance is subtle but important in complex pipelines.

---

## `c++filt` options

`c++filt` has a few useful options beyond the default behavior.

### `-t`: demangle individual types

By default, `c++filt` expects mangled function or variable names (starting with `_Z`). The `-t` option lets it demangle **isolated type encodings** as well, such as those found in function signatures:

```bash
$ c++filt -t i
int

$ c++filt -t PKc
char const*

$ c++filt -t NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
```

It's very useful when you manually decompose a mangled name and want to verify your interpretation of a type fragment.

### `-p`: do not display parameter types

The `-p` option (*no-params*) produces a simplified demangling that omits parameter types:

```bash
$ c++filt -p _ZN6AnimalC2ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEi
Animal::Animal(...)

# Comparison without -p:
$ c++filt _ZN6AnimalC2ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEi
Animal::Animal(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, int)
```

When STL types make names unreadably long, `-p` offers a clearer overview. You lose overload information (you no longer distinguish constructors that differ by their parameters), but you gain readability.

### `-s`: specify the mangling scheme

By default, `c++filt` uses the platform's scheme (Itanium ABI under Linux/GCC). If you work on a binary from another compiler, you can force a different scheme:

```bash
# Itanium ABI (GCC, Clang) — default under Linux
$ c++filt -s gnu-v3 _ZN6Animal5speakEv

# Old GCC 2.x scheme (very rare today)
$ c++filt -s gnu _ZN6Animal5speakEv
```

In practice, you'll almost never need to change the scheme under Linux. This option becomes relevant if you analyze a binary compiled with an exotic or very old compiler.

> 💡 **Note on MSVC**: Microsoft's compiler uses its own *name mangling* scheme, totally different from the Itanium ABI. MSVC mangled names start with `?` (for example `?speak@Animal@@UEAAXXZ`). `c++filt` does **not** support MSVC demangling. For Windows binaries, use `undname.exe` (Microsoft tool), `llvm-undname` (LLVM project), or the built-in demangler of Ghidra/IDA. This case remains outside the scope of this tutorial, which centers on the GNU chain, but deserves to be mentioned to avoid confusion if you come across `?...@@...` symbols.

---

## Building a class inventory with `nm` + `c++filt`

By combining the tools seen so far, you can quickly extract the object structure of a C++ binary. Here is a scriptable mini-workflow:

### List all classes

```bash
$ nm -C binaries/ch22-oop/oop | grep ' T ' | awk -F'::' 'NF>1 {print $1}' | \
    sed 's/^.* //' | sort -u
Animal  
Cat  
Dog  
```

The `grep ' T '` filters functions defined in `.text`. The `awk` extracts what precedes `::`. The `sed` removes the address and symbol type. The `sort -u` deduplicates.

### List the methods of a given class

```bash
$ nm -C binaries/ch22-oop/oop | grep ' T .*Animal::'
0000000000001234 T Animal::speak()
0000000000001380 T Animal::Animal(std::__cxx11::basic_string<...>, int)
0000000000001390 T Animal::Animal(std::__cxx11::basic_string<...>, int)
00000000000013f0 T Animal::~Animal()
0000000000001410 T Animal::~Animal()
```

Apparent duplicates (`Animal::Animal` twice, `~Animal` twice) correspond to the `C1`/`C2` and `D1`/`D2` variants mentioned in section 7.5.

### List vtables and RTTI

```bash
$ nm -C binaries/ch22-oop/oop | grep -E 'vtable|typeinfo'
0000000000003d00 V vtable for Animal
0000000000003d28 V vtable for Cat
0000000000003d50 V vtable for Dog
0000000000002050 V typeinfo for Animal
0000000000002068 V typeinfo for Cat
0000000000002080 V typeinfo for Dog
0000000000002040 V typeinfo name for Animal
0000000000002048 V typeinfo name for Cat
0000000000002050 V typeinfo name for Dog
```

With demangling, `_ZTV` becomes `vtable for ...`, `_ZTI` becomes `typeinfo for ...`, and `_ZTS` becomes `typeinfo name for ...`. The listing is directly readable.

### Generate a structured summary

Let's combine all into a one-liner script that produces a hierarchical inventory:

```bash
$ nm -C binaries/ch22-oop/oop | grep ' T ' | grep '::' | \
    awk -F'::' '{class=$1; sub(/^.* /, "", class); method=$2; print class " → " method}' | \
    sort
Animal → Animal(std::__cxx11::basic_string<...>, int)  
Animal → speak()  
Animal → ~Animal()  
Cat → Cat(std::__cxx11::basic_string<...>, int)  
Cat → speak()  
Cat → ~Cat()  
Dog → Dog(std::__cxx11::basic_string<...>, int)  
Dog → speak()  
Dog → ~Dog()  
```

In seconds, you have an overview of the class hierarchy: three classes (`Animal`, `Cat`, `Dog`), each with a constructor, a destructor, and a `speak()` method — probably virtual given it exists in every class. This summary, produced before even opening a graphical disassembler, already guides your analysis.

---

## The limits of demangling

Demangling is not a miracle solution. Here are cases where it won't help you:

**Stripped binary without C++ dynamic symbols.** If the binary is statically linked (no `libstdc++.so`) and fully stripped, there are no mangled names left to demangle. `c++filt` has nothing to work with. In this case, you have to resort to Chapter 17 techniques: rebuilding classes from vtables, allocation patterns (`operator new` followed by a constructor), and object memory layout.

**Deeply nested templates.** Demangling produces technically correct names but sometimes unreadable ones due to STL template-type verbosity:

```bash
$ c++filt _ZNSt8__detail9_Map_baseINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESt4pairIKS6_iESaIS9_ENS_10_Select1stESt8equal_toIS6_ESt4hashIS6_ENSA_18_Mod_range_hashingENSA_20_Default_ranged_hashENSA_20_Prime_rehash_policyENSA_17_Hashtable_traitsILb1ELb0ELb1EEELb1EEixERS8_
```

The demangled result spans several lines and mentions half a dozen template types. In practice, the appropriate reaction is to recognize this is an internal method of `std::unordered_map` and move on. The `-p` option helps, but does not fully solve the problem. Habit and STL knowledge are your best allies.

**Deliberately obfuscated symbols.** Some post-compilation obfuscators replace symbol names with random identifiers that do not follow the Itanium scheme. `c++filt` leaves them unchanged since they do not start with `_Z`. There is no automatic countermeasure — that's the very goal of obfuscation.

**`extern "C"` functions in C++.** Functions declared `extern "C"` in C++ are **not** mangled — they use the raw C name, without `_Z` prefix. That's intentional (to allow C/C++ interoperability), but it means these functions are not identifiable as C++ by name alone. If a C++ binary exposes an API in `extern "C"`, the API functions will look like C in the symbol table.

---

## Summary

`c++filt` is the standalone demangling tool of the Binutils suite. It works in direct-argument mode (pass a symbol on the command line) or in filter mode (read stdin and replace mangled names in text). Its filter mode makes it indispensable in shell pipelines: combined with `nm`, `readelf`, `addr2line`, or log files, it turns cryptic identifiers into readable C++ names. The `-t` option decodes isolated type encodings, and `-p` produces a simplified demangling without parameter types. Associated with `nm -C` and a few `grep`/`awk` commands, it allows you to quickly build the inventory of classes, methods, vtables, and RTTI of a C++ binary. Its limits appear on stripped binaries without residual symbols, on deeply nested templates (verbosity), and facing deliberate obfuscation.

---


⏭️ [Limitations of `objdump`: why a real disassembler is necessary](/07-objdump-binutils/07-objdump-limitations.md)
