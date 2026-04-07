🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.6 — Templates: instantiations and symbol explosion

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## The template problem in RE

C++ templates are a compilation mechanism — they don't exist at runtime. The compiler generates a complete code copy for each combination of template parameters used in the program. A simple `std::vector` instantiated with three different types (`int`, `double`, `std::string`) produces three complete sets of functions in the binary: three `push_back`s, three `operator[]`s, three destructors, three reallocations, etc.

For the reverse engineer, the consequences are manifold. The symbol table explodes in size, often dominated by STL instantiations. The binary contains nearly identical code duplicated for each instantiation, making navigation confusing. Mangled symbols become very long and hard to read, even demangled. And on a stripped binary, template parameter information is completely lost — it must be reconstructed by analyzing memory accesses and element sizes.

## How GCC instantiates templates

### The implicit instantiation mechanism

When the compiler encounters a template use with concrete arguments, it generates ("instantiates") the specialized code for those arguments. This process is called **implicit instantiation**:

```cpp
Registry<std::string, std::shared_ptr<Shape>> shapeRegistry("shapes");  
Registry<int, std::string> idRegistry("ids");  
```

These two lines trigger the generation of two complete function families:

```
Registry<std::string, std::shared_ptr<Shape>>::Registry(std::string const&)  
Registry<std::string, std::shared_ptr<Shape>>::add(std::string const&, std::shared_ptr<Shape> const&)  
Registry<std::string, std::shared_ptr<Shape>>::get(std::string const&) const  
Registry<std::string, std::shared_ptr<Shape>>::contains(std::string const&) const  
Registry<std::string, std::shared_ptr<Shape>>::size() const  
Registry<std::string, std::shared_ptr<Shape>>::forEach(std::function<...>) const  

Registry<int, std::string>::Registry(std::string const&)  
Registry<int, std::string>::add(int const&, std::string const&)  
Registry<int, std::string>::get(int const&) const  
Registry<int, std::string>::contains(int const&) const  
Registry<int, std::string>::size() const  
Registry<int, std::string>::forEach(std::function<...>) const  
```

Each instantiation produces a complete set of functions, with distinct machine code because the types have different sizes, alignments, and operations.

### Instantiation in each translation unit

In C++, templates are defined in headers. Each `.cpp` file that includes a header and uses a template generates its own instantiations. If three source files use `std::vector<int>`, the compiler produces three copies of all `std::vector<int>` functions, one in each `.o` object file.

The linker eliminates duplicates through the **COMDAT** mechanism: template instantiations are emitted as *weak* symbols in COMDAT sections (`.text._ZN...`, one section per function), and the linker keeps only one copy of each identical symbol. This is why template instantiations appear as type `W` (weak) symbols in `nm` output:

```bash
$ nm oop_O0 | c++filt | grep 'Registry.*add'
0000000000402a10 W Registry<std::__cxx11::basic_string<char, ...>, std::shared_ptr<Shape>>::add(...)
0000000000402e80 W Registry<int, std::__cxx11::basic_string<char, ...>>::add(...)
```

The `W` indicates a weak symbol — the linker kept this copy, but other object files could have provided the same.

> 💡 **In RE:** `W` (weak) symbols in `nm` are almost always template instantiations or inline functions. Their volume often dominates a C++ binary's symbol table. Filter them to focus on application code: `nm -C binary | grep ' T '` shows only strong global symbols (non-template functions defined explicitly).

## Symbol explosion in practice

### Measuring the scale

On our training binary, let's compare symbol counts:

```bash
# Total defined symbols
$ nm oop_O0 | wc -l
1847

# Weak symbols (mainly template instantiations)
$ nm oop_O0 | grep ' W ' | wc -l
1203

# Strong symbols (application code + embedded libstdc++)
$ nm oop_O0 | grep ' T ' | wc -l
312
```

In this example, **65% of symbols** are weak instantiations. And this ratio is modest — a real project using the STL intensively, Boost, or template-heavy libraries can reach 90% weak symbols.

### Main sources of explosion

The most voluminous instantiations almost always come from the STL:

```bash
$ nm -C oop_O0 | grep ' W ' | sed 's/.*W //' | cut -d'(' -f1 | sort | uniq -c | sort -rn | head -15
     47  std::__cxx11::basic_string<char, ...>::
     38  std::vector<std::shared_ptr<Shape>, ...>::
     31  std::_Rb_tree<std::__cxx11::basic_string<char, ...>, ...>::
     24  std::shared_ptr<Shape>::
     19  std::_Hashtable<std::__cxx11::basic_string<char, ...>, ...>::
     16  Registry<std::__cxx11::basic_string<char, ...>, std::shared_ptr<Shape>>::
     14  Registry<int, std::__cxx11::basic_string<char, ...>>::
     12  std::_Sp_counted_ptr_inplace<Circle, ...>::
     ...
```

`std::string` alone generates dozens of instantiated functions (constructors for different cases, operators, `append`, `assign`, `compare`, iterators...). Multiplied by the containers using it, the volume becomes considerable.

### Recursive instantiations

Some template instantiations trigger others in cascade. For example, `std::map<std::string, std::shared_ptr<Shape>>` instantiates:
- `std::_Rb_tree<std::string, std::pair<const std::string, std::shared_ptr<Shape>>, ...>`  
- which instantiates `std::_Rb_tree_node<std::pair<const std::string, std::shared_ptr<Shape>>>`  
- which instantiates iterators, allocators, etc.  
- `std::pair<const std::string, std::shared_ptr<Shape>>` instantiates its constructors, comparison operators, etc.

Each level of the template hierarchy generates its own set of functions. The result is an instantiation tree whose total volume can be surprising.

## Recognizing instantiations in disassembly

### With symbols: reading the mangling

Template parameters are encoded between `I` and `E` in the mangled symbol (see Section 17.1). A symbol like:

```
_ZN8RegistryINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESt10shared_ptrI5ShapeEE3addERKS5_RKSA_
```

demangles to:

```
Registry<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>,
         std::shared_ptr<Shape>>::add(
             std::__cxx11::basic_string<char, ...> const&,
             std::shared_ptr<Shape> const&)
```

The template parameters (`std::string` and `std::shared_ptr<Shape>`) are fully encoded in the name, giving access to exact types even without source code.

In practice, these symbols are so long that tools often truncate them. Use `c++filt` in pipe mode for full rendering, or `nm --no-demangle` to see the raw form and decode it manually if needed.

### Without symbols: identifying by code

On a stripped binary, template parameters are no longer visible. They must be reconstructed by analyzing the generated code. Here are the main clues.

**Element size.** As seen in Section 17.5, the scale factor in `std::vector`'s `size()` calculations reveals `sizeof(T)`:

```nasm
; vector::size() for vector<shared_ptr<Shape>>
mov    rax, [rdi+8]       ; _M_finish  
sub    rax, [rdi]         ; - _M_start  
sar    rax, 4             ; / 16 → sizeof(shared_ptr) = 16  
```

The shift `sar rax, 4` (division by 16) indicates elements are 16 bytes, matching `std::shared_ptr` (two 8-byte pointers).

**Operations on elements.** Template function code uses operations specific to the instantiated type. For example, `Registry<int, std::string>::add` will compare keys with a simple `cmp` instruction, while `Registry<std::string, ...>::add` will call `std::string::compare` or `operator<` for strings. The type of comparison, copy, and destruction operations reveals the template type.

**Destructors in cleanup landing pads.** When a container is destroyed, it calls the destructor of each element. If elements are `std::string`, you'll see the characteristic SSO pattern (`lea rdx, [rdi+16]; cmp [rdi], rdx`). If they're `shared_ptr`, you'll see the atomic decrement of the reference counter.

**Hash and comparison functions.** For `std::unordered_map`, the instantiated hash function is specific to the key type. `std::hash<int>` is trivial (often the identity), while `std::hash<std::string>` calls a character hashing function (MurmurHash, FNV, or similar depending on the libstdc++ version).

### Recognizing two instantiations of the same template

When the same template is instantiated with different types, the generated code has the same **structure** (same branches, same logical sequence) but different **details** (access sizes, called functions, registers used). In RE, two functions that are structurally similar but differ in memory access sizes and called functions are probably two instantiations of the same template.

For example, `Registry<string, shared_ptr<Shape>>::add` and `Registry<int, string>::add` will have:
- The same logic: check if the key exists (`entries_.count(key)`), throw an exception if yes, insert otherwise.  
- Different calls: one will call `std::map<string, ...>::count`, the other `std::map<int, ...>::count`.  
- Different copy sizes: `string` keys (32 bytes) vs `int` keys (4 bytes).

This pattern of "same structure, different details" is the signature of template instantiations in a stripped binary.

## Templates and optimizations

### Inlining of template functions

GCC is particularly aggressive in inlining template functions, especially at `-O2` and `-O3`. The reasons are multiple:
- Template functions are defined in headers, thus visible in each translation unit.  
- Many template functions are small (accessors, wrappers, adapters).  
- Inlining eliminates the function call cost while enabling further optimizations (constant propagation, dead code elimination).

At `-O2`, it's common for a template instantiation to **not appear at all** as a distinct function in the binary — its code was inlined into all call sites. This is a problem in RE because the correspondence between symbols and actual functions in `.text` is lost.

```bash
# In -O0, each instantiation is a distinct function
$ nm -C oop_O0 | grep 'Registry.*contains' | wc -l
2

# In -O2, some disappear (inlined)
$ nm -C oop_O2 | grep 'Registry.*contains' | wc -l
0
```

> 💡 **In RE:** if you can't find an expected template method in a `-O2` binary's symbol table, it was probably inlined. Search for its code (the logic it should contain) directly in the calling functions.

### Identical Code Folding (ICF)

When two template instantiations produce **identical machine code**, the linker can merge them into a single copy. This is **Identical Code Folding** (ICF), enabled by `--icf=all` in `ld.gold` and `lld`, or partially by `ld.bfd` with COMDAT sections.

For example, `std::vector<int*>::push_back` and `std::vector<double*>::push_back` produce exactly the same machine code because both types are 8-byte pointers with the same copy semantics. With ICF, only one copy remains in the binary, and both symbols point to the same address.

```bash
# Two symbols, same address → ICF
$ nm oop_O2 | c++filt | grep 'vector.*push_back'
0000000000403a20 W std::vector<int*, ...>::push_back(int* const&)
0000000000403a20 W std::vector<double*, ...>::push_back(double* const&)
```

> ⚠️ **RE trap:** with ICF, two functions with different names and different parameter types share the same address. If you set a breakpoint in GDB on one, you also intercept calls to the other. If you rename the function in Ghidra, the new name applies to all merged instantiations. Be aware that a single function may serve multiple types.

### Specialization and its impact

C++ allows **specializing** a template for a particular type, providing a different implementation:

```cpp
template<>  
class Registry<int, int> {  
    // Completely different implementation
};
```

In RE, a specialization manifests as an instantiation whose code is structurally different from other instantiations of the same template. If `Registry<string, Shape*>::add` and `Registry<int, string>::add` are structurally similar, but `Registry<int, int>::add` has completely different logic, the latter is probably a specialization.

The standard library extensively uses internal specializations. For example, `std::hash` is specialized for each base type (`int`, `long`, `double`, `string`, `pointer`...), and each specialization has different hashing code.

## The STL: the main source of templates in RE

In practice, the vast majority of template instantiations encountered in RE come from the STL, not application code. Here are the most voluminous families.

### `std::basic_string` and its dependencies

`std::string` is technically `std::basic_string<char, std::char_traits<char>, std::allocator<char>>`. Each operation (`append`, `assign`, `compare`, `find`, `substr`, iterators, copy and move constructors, etc.) is a distinct instantiation. A typical binary easily contains 30 to 50 instantiated functions related to `std::string`.

If the program uses `std::wstring` (wide characters), that's a second complete set of instantiations with `wchar_t`.

### `std::vector` and its allocators

Each `std::vector<T>` for a distinct type `T` generates a complete set of functions. The most costly in code volume are:
- `_M_realloc_insert` (reallocation during push_back)  
- `_M_fill_assign` and `_M_range_insert` (range insertion)  
- Copy and move constructors

### `std::map` / `std::set` (red-black tree)

The `_Rb_tree` implementation is shared by `std::map`, `std::set`, `std::multimap`, and `std::multiset`. But instantiations are distinct for each key/value type combination because comparisons and element constructors differ.

### `std::shared_ptr` and the control block

`std::make_shared<T>(args...)` instantiates `_Sp_counted_ptr_inplace<T, allocator<T>, ...>`, a control block that contains the `T` object directly (to avoid a separate allocation). Each type `T` used with `make_shared` produces a distinct control block with its own vtable, destructor, and deallocation logic.

### `std::function`

`std::function<R(Args...)>` is a polymorphic wrapper that can encapsulate any callable (function, lambda, functor). Internally, it uses type erasure, generating distinct management template classes for each stored callable type. If a `std::function<void(int)>` is initialized with three different lambdas in the program, each lambda produces its own management instantiations.

## RE strategies facing template explosion

### Sort and filter

The first strategy is to **sort symbols by relevance**:

```bash
# Application symbols (non-STL, non-standard template)
$ nm -C oop_O0 | grep ' [TW] ' | grep -v 'std::' | grep -v '__gnu_cxx' | grep -v '__cxa'

# Application template instantiations only
$ nm -C oop_O0 | grep ' W ' | grep -v 'std::' | grep -v 'basic_string'
```

The idea is to separate "STL noise" from the application template code you're actually trying to understand.

### Identify patterns rather than instances

Rather than analyzing each instantiation individually, identify the **common pattern**. Analyze a single instantiation in detail (preferably the one with the simplest type, like `int`), understand the logic, then apply that understanding to other instantiations by adapting sizes and types.

### Use Ghidra signatures

Ghidra has a **Function ID** (FID) mechanism and signatures that can automatically identify `libstdc++` functions. When Ghidra recognizes `std::vector<int>::push_back`, it names it automatically, eliminating much of the noise. Verify that `libstdc++` signatures are loaded:

1. In Ghidra, menu **Analysis** → **Auto Analyze** → verify that "Function ID" is enabled.  
2. If STL functions aren't recognized, import `.fidb` signature files for your `libstdc++` version.

### Ignore STL internal details

In RE, you generally don't need to understand the inner workings of `std::vector::_M_realloc_insert`. What matters is recognizing that the calling function performs a `push_back` on a vector, not the reallocation details. Identify the container, identify the operation, and move on to the application logic.

The exception is when a vulnerability or specific behavior lies in the container usage (out-of-bounds, use-after-free, iterator invalidation). In that case, knowledge of internal layouts (Section 17.5) becomes essential.

## Explicit instantiation and `extern template`

Some projects use **explicit instantiation** to control where and how templates are instantiated:

```cpp
// In a .cpp: force instantiation here
template class Registry<int, std::string>;

// In a header: prevent automatic instantiation elsewhere
extern template class Registry<int, std::string>;
```

In RE, explicit instantiations appear as strong symbols (`T` in `nm`) instead of weak symbols (`W`). This indicates the developer intentionally controlled the instantiation, probably to reduce compilation time or binary size.

```bash
# Strong symbols = explicit instantiations
$ nm -C oop_O0 | grep ' T .*Registry'
0000000000402a10 T Registry<int, std::string>::add(...)

# Weak symbols = implicit instantiations
$ nm -C oop_O0 | grep ' W .*Registry'
0000000000402e80 W Registry<std::string, std::shared_ptr<Shape>>::add(...)
```

## Variadic templates and fold expressions

Variadic templates (C++11) and fold expressions (C++17) deserve mention as they produce characteristic code patterns.

A variadic template like:

```cpp
template<typename... Args>  
void log(const char* fmt, Args... args) {  
    printf(fmt, args...);
}
```

instantiated with `log("x=%d y=%f", 42, 3.14)` produces a single concrete instantiation `log<int, double>(const char*, int, double)`. The generated code is identical to a direct `printf` call — the variadic mechanism is entirely resolved at compilation.

In RE, variadic templates are recognized by the presence of many instantiations of the same template with type lists of different lengths:

```
log<int>(const char*, int)  
log<int, double>(const char*, int, double)  
log<int, double, std::string const&>(const char*, int, double, std::string const&)  
```

Each argument combination used in the program generates its own instantiation.

## `if constexpr` and compile-time specialization

C++17's `if constexpr` generates code where only the valid branch is compiled:

```cpp
template<typename T>  
void process(T val) {  
    if constexpr (std::is_integral_v<T>) {
        // code for integers — only this code exists for T=int
    } else {
        // code for other types — only this code exists for T=double
    }
}
```

In RE, two instantiations of the same template can have **very different** code if they use `if constexpr`. Unlike normal instantiations where the structure is identical, `if constexpr` produces functions whose body varies fundamentally depending on the type. Don't confuse this with explicit specialization — the mechanism is different but the RE result is similar.

## Summary of patterns to recognize

| Pattern | Meaning |  
|---------|---------|  
| `W` (weak) symbols in `nm` | Implicit template instantiations |  
| `T` (global) symbols with template types | Explicit instantiations |  
| Two functions at the same address with different names | ICF (Identical Code Folding) — instantiations with same-size types |  
| Structurally identical code with different access sizes | Two instantiations of the same template with different types |  
| `I...E` in a mangled symbol | Template parameters (Section 17.1) |  
| `__cxx11` in symbols | New ABI for `std::string` and associated containers (GCC ≥ 5) |  
| Expected functions absent in `-O2` | Template inlined by the compiler |  
| 60–90% of symbols related to `std::` | Normal — the STL dominates template volume |  
| Same template, radically different code per instantiation | `if constexpr` or template specialization |

---


⏭️ [Lambda, closures, and captures in assembly](/17-re-cpp-gcc/07-lambda-closures.md)
