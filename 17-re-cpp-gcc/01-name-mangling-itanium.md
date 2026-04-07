🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.1 — Name mangling — Itanium ABI rules and demangling

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## Why name mangling exists

In C, each function has a unique name in the global space. The function `connect` in an object file corresponds exactly to the symbol `connect` in the symbol table. The linker only needs to match names.

C++ makes this simplicity impossible. The language allows **overloading** (multiple functions with the same name but different parameters), **namespaces** (multiple functions with the same name in different name spaces), **class methods** (the same function name in different classes), and **templates** (the same function instantiated with different types). All these entities must nonetheless coexist in a flat ELF-format symbol table, where each symbol must be unique.

**Name mangling** (or *name decoration*) is the mechanism by which the C++ compiler encodes in the symbol name all the information needed to make it unique: the namespace, the class, the function name, its parameter types, qualifiers (`const`, `volatile`), and template parameters. The result is a string that's opaque to a human but perfectly decodable by tools.

For the reverse engineer, name mangling is both an obstacle and a gold mine. An obstacle because raw symbols are unreadable. A gold mine because a mangled symbol contains **more information than the original function name** — it encodes the complete signature, which allows reconstructing prototypes without access to source code.

## The Itanium C++ ABI

GCC, Clang, and most C++ compilers on Linux/macOS/FreeBSD follow the **Itanium C++ ABI**, a standard that defines (among other things) the name mangling rules. This standard was initially designed for the Intel Itanium (IA-64) processor, but it became the de facto standard on all Unix platforms, regardless of processor architecture.

> ⚠️ **MSVC (Microsoft Visual C++) uses a completely different mangling scheme.** The rules described here don't apply to PE binaries compiled with MSVC. However, if you use MinGW (GCC targeting Windows), Itanium mangling does apply, even on a PE binary.

The complete specification is public and available in the *Itanium C++ ABI* document (https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling). What follows is a practical subset covering the most frequent cases in reverse engineering.

## Anatomy of a mangled symbol

Every symbol mangled according to the Itanium ABI starts with the prefix `_Z`. This is the universal marker: if a symbol in `nm` or `objdump` starts with `_Z`, it's a mangled C++ symbol. If not, it's either a C symbol or a C++ symbol declared `extern "C"`.

The general structure of a mangled symbol is:

```
_Z <encoding>
```

The encoding breaks down into two parts: a **qualified name** (which includes namespaces and classes) and a **type signature** (the function's parameters).

### Free functions (non-member)

For a simple function without namespace or class, the encoding is:

```
_Z <name_length> <name> <parameter_types>
```

The name length is encoded in decimal, followed by the name itself, followed by the parameter type codes.

**Example — `int compute(int x, double y)`:**

```
_Z7computeid
│ │       ││
│ │       │└─ d = double (second parameter)
│ │       └── i = int (first parameter)
│ └───────── compute (7 characters)
└─────────── C++ mangled prefix
```

The return type **is not encoded** in the mangling of ordinary functions (it is only for template instances, see below).

### Base type codes

Here are the codes for the most common fundamental types:

| Code | C++ type | Note |  
|------|----------|------|  
| `v` | `void` | Function with no parameter |  
| `b` | `bool` | |  
| `c` | `char` | |  
| `h` | `unsigned char` | |  
| `s` | `short` | |  
| `t` | `unsigned short` | |  
| `i` | `int` | The most frequent |  
| `j` | `unsigned int` | |  
| `l` | `long` | |  
| `m` | `unsigned long` | |  
| `x` | `long long` | |  
| `y` | `unsigned long long` | |  
| `f` | `float` | |  
| `d` | `double` | |  
| `e` | `long double` | |  
| `z` | `...` (ellipsis) | Variadic functions |

Compound types use prefixes:

| Prefix | Meaning | Example |  
|--------|---------|---------|  
| `P` | Pointer to | `Pi` = `int*` |  
| `R` | Lvalue reference | `Ri` = `int&` |  
| `O` | Rvalue reference (C++11) | `Oi` = `int&&` |  
| `K` | `const` | `Ki` = `const int` |  
| `V` | `volatile` | `Vi` = `volatile int` |

These prefixes combine. A `const int*` (pointer to const int) is encoded `PKi`, while an `int* const` (const pointer to int) is encoded `KPi`. The reading order is right to left, exactly as the C++ declaration is read.

**Combination examples:**

```
PKc        → const char*            (very frequent: C strings)  
PRKi       → const int&             (pass by const reference)  
PPi        → int**                  (double pointer)  
PFviE      → void(*)(int)           (function pointer: void(int))  
```

### Qualified names (namespaces and classes)

When a function belongs to a namespace or class, the name is wrapped in an `N...E` block (for *nested name*):

```
_Z N <qualifier1> <qualifier2> ... <function_name> E <types>
```

Each qualifier is encoded as `<length><name>`.

**Example — `MyApp::Network::Client::connect(int port)`:**

```
_ZN5MyApp7Network6Client7connectEi
  │ │     │       │      │       ││
  │ │     │       │      │       │└ i = int
  │ │     │       │      │       └─ E = end of qualified name
  │ │     │       │      └──────── connect (7 chars)
  │ │     │       └─────────────── Client (6 chars)
  │ │     └─────────────────────── Network (7 chars)
  │ └───────────────────────────── MyApp (5 chars)
  └─────────────────────────────── N = start of qualified name (nested)
```

### Const methods and qualifiers

A `const` method (the `const` on `this`) is marked by a `K` after the `N`:

```cpp
void Shape::describe() const;
```

```
_ZNK5Shape8describeEv
   ││                │
   │└ K = const method
   └─ N = nested
```

### Constructors and destructors

Constructors and destructors have special encodings instead of the function name:

| Code | Meaning |  
|------|---------|  
| `C1` | Complete object constructor |  
| `C2` | Base object constructor |  
| `C3` | Allocating constructor (rare) |  
| `D0` | Deleting destructor |  
| `D1` | Complete object destructor |  
| `D2` | Base object destructor |

In practice, GCC often generates **two versions** of the constructor (C1 and C2) and **two or three versions** of the destructor (D0, D1, D2). The difference concerns behavior with virtual inheritance: C1/D1 handle virtual sub-objects, C2/D2 don't. When there's no virtual inheritance, GCC generally merges them into a single implementation, but both symbols exist.

**Example — `Circle` constructor:**

```
_ZN6CircleC1Eddd
   │      ││ │││
   │      ││ ││└ d = double (third param: r)
   │      ││ │└─ d = double (second param: y)
   │      ││ └── d = double (first param: x)
   │      │└──── 1 = complete object constructor
   │      └───── C = constructor
   └──────────── Circle (6 chars)
```

> 💡 **In RE:** when you see `C1` and `C2` for the same class with identical content, it's normal. Focus on just one. When you see `D0`, it's the destructor called via `delete` — it calls the D1 destructor then frees memory.

### Overloaded operators

Operators use special codes starting with a two-letter suffix:

| Code | Operator | Code | Operator |  
|------|----------|------|----------|  
| `nw` | `new` | `dl` | `delete` |  
| `na` | `new[]` | `da` | `delete[]` |  
| `pl` | `+` | `mi` | `-` |  
| `ml` | `*` | `dv` | `/` |  
| `rm` | `%` | `an` | `&` (bitwise) |  
| `or` | `\|` | `eo` | `^` |  
| `aS` | `=` | `pL` | `+=` |  
| `mI` | `-=` | `mL` | `*=` |  
| `eq` | `==` | `ne` | `!=` |  
| `lt` | `<` | `gt` | `>` |  
| `le` | `<=` | `ge` | `>=` |  
| `ls` | `<<` | `rs` | `>>` |  
| `cl` | `()` | `ix` | `[]` |

**Example — `bool Shape::operator==(const Shape& other) const`:**

```
_ZNK5ShapeeqERKS_
         ││  │││
         ││  ││└ S_ = substitution (refers to Shape, already mentioned)
         ││  │└─ K = const
         ││  └── R = reference
         │└───── eq = operator==
         └────── K = const method
```

The `S_` here is a **substitution** mechanism: to avoid repeating already-encoded types, the ABI uses shorthand codes. `S_` designates the first substitution candidate (here, `Shape`). Subsequent substitutions are `S0_`, `S1_`, etc.

### Templates

Template instantiations are encoded with `I...E` enclosing the template arguments:

```
_Z <name> I <template_args> E <param_types>
```

**Example — `void process<int, double>(int, double)`:**

```
_Z7processIidEvi d
         │ ││ │││ │
         │ ││ ││└ d = param double
         │ ││ │└─ i = param int
         │ ││ └── v = void (return type, present for templates)
         │ │└──── E = end of template args
         │ └───── id = <int, double>
         └─────── I = start of template args
```

> 💡 **Note:** for template functions, the return type **is** encoded in the symbol (unlike ordinary functions). This is a frequent source of confusion during manual decoding.

**Example with our `Registry`:**

The method `Registry<std::string, int>::add(const std::string&, const int&)` produces a symbol like:

```
_ZN8RegistryINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEiE3addERKS5_RKi
```

This symbol is long, but it completely encodes: the template class `Registry`, its parameters (`std::string` and `int`), the method name `add`, and the parameter types. In practice, nobody decodes this by hand — that's the tools' job.

### Standard substitutions

The Itanium ABI defines abbreviations for the most common standard library types:

| Code | Meaning |  
|------|---------|  
| `St` | `std::` |  
| `Sa` | `std::allocator` |  
| `Sb` | `std::basic_string` |  
| `Ss` | `std::basic_string<char, std::char_traits<char>, std::allocator<char>>` (= `std::string`) |  
| `Si` | `std::basic_istream<char, std::char_traits<char>>` |  
| `So` | `std::basic_ostream<char, std::char_traits<char>>` (= `std::ostream`) |  
| `Sd` | `std::basic_iostream<char, std::char_traits<char>>` |

> ⚠️ **Note GCC ≥ 5 (C++11 ABI):** GCC uses `NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE` instead of `Ss` for `std::string` since the switch to the new ABI. You'll see `__cxx11` in symbols — it's the sign of the new ABI. The old ABI (GCC 4.x) used `Ss`.

## Demangling tools

### `c++filt`

The GNU toolchain's standard tool for demangling symbols:

```bash
$ echo '_ZN6CircleC1Eddd' | c++filt
Circle::Circle(double, double, double)

$ echo '_ZNK5Shape8describeEv' | c++filt
Shape::describe() const

$ echo '_ZN8RegistryINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEiE3addERKS5_RKi' | c++filt
Registry<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, int>::add(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, int const&)
```

`c++filt` can also filter an entire stream. Combine it with `nm` or `objdump`:

```bash
# List all demangled symbols of a binary
$ nm oop_O0 | c++filt

# Disassemble with demangled names
$ objdump -d -M intel oop_O0 | c++filt

# Search for symbols of a specific class
$ nm oop_O0 | c++filt | grep 'Circle::'
```

### `nm` with the `-C` option

`nm` integrates automatic demangling via the `-C` flag (or `--demangle`):

```bash
$ nm -C oop_O0 | grep 'Circle'
0000000000401a2c T Circle::Circle(double, double, double)
0000000000401a2c T Circle::Circle(double, double, double)
0000000000401b14 T Circle::area() const
0000000000401b38 T Circle::perimeter() const
0000000000401b64 T Circle::describe() const
0000000000401c98 T Circle::radius() const
```

We can see the two constructor symbols (C1 and C2) pointing to the same address — GCC merged them.

### `objdump` with the `-C` option

```bash
$ objdump -d -C -M intel oop_O0 | head -30
```

The `-C` flag enables demangling in the disassembly listing. The `call` instructions then display the full function name instead of the mangled symbol.

### Demangling in Ghidra

Ghidra automatically demangles Itanium symbols when importing an ELF binary. Demangled names appear in the Symbol Tree, Listing, and Decompiler. To see the original mangled name, right-click a symbol and look for properties or consult the "Defined Strings" view.

If automatic demangling doesn't work (for example after an import with non-standard options), you can trigger it manually:

1. Menu **Analysis** → **One Shot** → **Demangler GNU**.  
2. Or via a Ghidra script that calls `DemanglerCmd`.

### Demangling in Radare2

```bash
# Enable demangling (enabled by default)
$ r2 -A oop_O0
[0x00401080]> e bin.demangle = true

# List functions with demangled names
[0x00401080]> afl

# Disassemble a function with demangled name
[0x00401080]> pdf @ sym.Circle::area
```

### Programmatic demangling in Python

For RE scripting, the `cxxfilt` library (Python wrapper) or `subprocess` with `c++filt`:

```python
# With the cxxfilt library (pip install cxxfilt)
import cxxfilt

mangled = '_ZN6CircleC1Eddd'  
print(cxxfilt.demangle(mangled))  
# → Circle::Circle(double, double, double)
```

```python
# With subprocess (no external dependency)
import subprocess

def demangle(symbol):
    result = subprocess.run(
        ['c++filt', symbol],
        capture_output=True, text=True
    )
    return result.stdout.strip()

print(demangle('_ZNK5Shape8describeEv'))
# → Shape::describe() const
```

## Reading mangling by hand: practical method

Even with tools, it's useful to know how to decode simple cases by hand — for example when you're in GDB without `c++filt` handy, or when analyzing a truncated symbol. Here's a 5-step procedure:

**Step 1 — Check the prefix.** Does the symbol start with `_Z`? If not, it's not an Itanium mangled symbol. If it starts with `_ZTV`, it's a vtable. `_ZTI` is a typeinfo (RTTI). `_ZTS` is a type name string.

**Step 2 — Identify the qualified name.** After `_Z`, look for `N` (start of qualified name). Read the successive length+name pairs until the `E`. If `K` appears right after `N`, it's a `const` method. If there's no `N`, it's a free function: read length+name directly.

**Step 3 — Identify the constructor/destructor.** If the last component of the name is `C1`, `C2`, `D0`, `D1`, `D2`, it's a constructor or destructor.

**Step 4 — Decode the parameter types.** After the `E` (or after the name for a free function), each character or group of characters encodes a parameter type. Use the base type code table. Watch for `P`, `R`, `K` prefixes that combine.

**Step 5 — Handle substitutions.** `S_`, `S0_`, `S1_`… reference previously mentioned types. `St` = `std::`, `Ss` = `std::string`, etc.

**Complete decoding example:**

Symbol: `_ZN7MyClass7processERKSsi`

```
_Z              → mangled symbol
  N             → start of qualified name
    7MyClass    → "MyClass" (7 chars)
    7process    → "process" (7 chars)
  E             → end of qualified name
    R           → reference to...
     K          → const...
      Ss        → std::string
    i           → int

Result: MyClass::process(const std::string&, int)
```

## Special symbols to recognize

Certain mangled prefixes identify internal C++ structures that the reverse engineer will encounter frequently:

| Prefix | Meaning | Where to find it |  
|--------|---------|------------------|  
| `_ZTV` | Class **vtable** | `.rodata` — table of virtual function pointers |  
| `_ZTI` | Class **typeinfo** | `.rodata` — RTTI structure |  
| `_ZTS` | **typeinfo name** (string) | `.rodata` — class name in plaintext |  
| `_ZTT` | **VTT** (virtual table table) | `.rodata` — virtual inheritance |  
| `_ZThn` | **Non-virtual thunk** | `.text` — pointer adjustment for multiple inheritance |  
| `_ZTv` | **Virtual thunk** | `.text` — adjustment for virtual inheritance |  
| `_ZGV` | **Guard variable** | `.bss` — protection for local static variable initialization |  
| `_ZGVN` | **Guard variable (nested)** | `.bss` — same within a namespace/class |

**Concrete examples from the `oop_O0` binary:**

```bash
$ nm oop_O0 | grep '_ZTV'
0000000000403d00 V _ZTV6Circle         # vtable for Circle
0000000000403d60 V _ZTV9Rectangle      # vtable for Rectangle
0000000000403dc0 V _ZTV8Triangle       # vtable for Triangle
0000000000403c40 V _ZTV5Shape          # vtable for Shape
0000000000403e20 V _ZTV6Canvas         # vtable for Canvas
0000000000403ea0 V _ZTV8Drawable       # vtable for Drawable
0000000000403ec0 V _ZTV12Serializable  # vtable for Serializable

$ nm oop_O0 | grep '_ZTI'
0000000000403f20 V _ZTI6Circle         # typeinfo for Circle
0000000000403f38 V _ZTI9Rectangle      # typeinfo for Rectangle
0000000000403f50 V _ZTI8Triangle       # typeinfo for Triangle
0000000000403f10 V _ZTI5Shape          # typeinfo for Shape
0000000000403f68 V _ZTI6Canvas         # typeinfo for Canvas

$ nm oop_O0 | grep '_ZTS'
0000000000403f00 V _ZTS6Circle         # typeinfo name → "6Circle"
0000000000403ef8 V _ZTS5Shape          # typeinfo name → "5Shape"
```

> 💡 **RE tip:** the `_ZTS` strings contain the class name in plaintext (in mangled but very readable form). Even on a stripped binary, if RTTI hasn't been disabled (`-fno-rtti`), these strings are present in `.rodata` and allow recovering the names of all polymorphic classes. This is often the first reflex when facing an unknown C++ binary:  
>  
> ```bash  
> $ strings oop_O2_strip | grep -E '^[0-9]+[A-Z]'  
> 6Circle  
> 9Rectangle  
> 8Triangle  
> 5Shape  
> 6Canvas  
> 8Drawable  
> 12Serializable  
> 12AppException  
> 10ParseError  
> 12NetworkError  
> ```  
>  
> These strings follow the `<length><name>` format of Itanium mangling — they are directly the class names.

## Special cases to know

### `extern "C"` functions

A function declared `extern "C"` in C++ **is not mangled**. Its symbol in the binary is identical to what a C compiler would produce. This is the standard mechanism for C/C++ interoperability:

```cpp
extern "C" void my_callback(int x);  // symbol: my_callback (no _Z)
```

In RE, if you see a mix of `_Z...` symbols and unprefixed symbols in a C++ binary, the latter are probably functions exported for a C API or callbacks.

### Global and class static variables

Global variables and static class members are also mangled:

```cpp
int MyClass::instanceCount;  // → _ZN7MyClass13instanceCountE
```

The final `E` marks the end of the qualified name, and there are no parameter types (it's not a function).

### Functions in anonymous namespaces

GCC uses a special internal namespace for anonymous namespaces, typically encoded as `_ZN12_GLOBAL__N_1...`. If you see `_GLOBAL__N_1` in a demangled symbol, it's an entity with internal linkage (the equivalent of file-level `static`).

### Truncated mangled symbols

In a stripped binary, you won't see local symbols. But dynamically referenced symbols (exports, PLT) remain present. A symbol can also be truncated in `strings` output — always start decoding from the left and stop when the string is cut off.

## Impact of stripping on C++ symbols

The behavior of stripping (`strip` or `-s`) on C++ symbols depends on the symbol type:

| Symbol type | After `strip` | Why |  
|-------------|---------------|-----|  
| Local functions (private methods, etc.) | **Removed** | Not needed at runtime |  
| Dynamically exported functions | **Preserved** | Needed by the dynamic linker |  
| PLT symbols (`func@plt`) | **Preserved** | Dynamic resolution |  
| vtables (`_ZTV...`) | **Preserved** | Needed at runtime (virtual resolution) |  
| typeinfo (`_ZTI...`, `_ZTS...`) | **Preserved*** | Needed for RTTI and exceptions |  
| Guard variables (`_ZGV...`) | **Preserved** | Needed at runtime |

*\*typeinfo are preserved unless the binary was compiled with `-fno-rtti` AND exceptions don't use them.*

Practical consequence: **even a stripped C++ binary often preserves vtables and typeinfo**, which gives the reverse engineer the names of all polymorphic classes and the structure of their virtual function tables. This is a major difference from C, where stripping effectively removes all naming information.

```bash
# Compare symbol count before/after strip
$ nm oop_O0 | wc -l
1847
$ nm oop_O0_strip 2>/dev/null | wc -l
0

# But dynamic symbols survive
$ nm -D oop_O0_strip | c++filt | grep -c '.'
287
```

---


⏭️ [C++ object model: vtable, vptr, single and multiple inheritance](/17-re-cpp-gcc/02-object-model-vtable.md)
