🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 17.5 — STL internals: `std::vector`, `std::string`, `std::map`, `std::unordered_map` in memory

> **Chapter 17 — Reverse Engineering C++ with GCC**  
> **Part IV — Advanced RE Techniques**

---

## Why knowing the STL's internal layout matters

When a reverse engineer encounters a memory access like `mov rax, [rdi+8]` in a C++ binary, the immediate question is: "what does offset 8 represent?" If `rdi` points to a `std::vector`, offset 8 corresponds to the end pointer (`_M_finish`). If `rdi` points to a `std::string`, offset 8 is the string length (`_M_string_length`). Without knowing the internal layouts, each memory access is a guessing game.

The C++ standard library (STL) implemented in `libstdc++` (shipped with GCC) uses stable and documented internal data structures. Their layout doesn't change between minor GCC versions, and major changes (like the switch to the new `__cxx11` ABI for `std::string` in GCC 5) are rare and well-identified. Knowing these layouts by heart allows instantly decoding recurring memory patterns in any C++ binary compiled with GCC.

> ⚠️ **These layouts are specific to `libstdc++` (GCC).** Clang uses `libc++` by default on macOS, whose layouts differ. MSVC uses its own STL implementation. This chapter focuses exclusively on `libstdc++`, the standard library shipped with GCC on Linux.

## `std::vector<T>`

`std::vector` is the most frequent container in C++. Its internal layout is deceptively simple: three pointers, nothing more.

### Memory layout

```
std::vector<T> (sizeof = 24 bytes on x86-64):
┌──────────────────────────────────────┐
│  _M_start   (T*)                     │  offset 0    — start of allocated buffer
├──────────────────────────────────────┤
│  _M_finish  (T*)                     │  offset 8    — one-past-the-end (first invalid element)
├──────────────────────────────────────┤
│  _M_end_of_storage (T*)              │  offset 16   — end of allocated capacity
└──────────────────────────────────────┘
```

The three pointers define everything:

- **`_M_start`**: points to the first element. Corresponds to `vec.data()` and `vec.begin()`.  
- **`_M_finish`**: points just after the last element. Corresponds to `vec.end()`.  
- **`_M_end_of_storage`**: points to the end of the heap-allocated buffer.

Vector metrics are derived from the three pointers:

| Property | Calculation | C++ code |  
|----------|-------------|----------|  
| Element count | `(_M_finish - _M_start) / sizeof(T)` | `vec.size()` |  
| Capacity | `(_M_end_of_storage - _M_start) / sizeof(T)` | `vec.capacity()` |  
| Empty? | `_M_start == _M_finish` | `vec.empty()` |  
| Access element i | `_M_start + i * sizeof(T)` | `vec[i]` |

The element buffer is allocated separately on the heap. An empty vector has all three pointers at `nullptr` (or at a single sentinel address).

### Characteristic assembly patterns

**`vec.size()`:**

```nasm
mov    rax, QWORD PTR [rdi+8]        ; _M_finish  
sub    rax, QWORD PTR [rdi]          ; _M_finish - _M_start = size in bytes  
sar    rax, 3                         ; divide by 8 if sizeof(T) == 8 (e.g., pointer)  
; rax = number of elements
```

The `sar` (shift arithmetic right) or `shr` serves as division by `sizeof(T)`. The shift value is a direct clue to element size:

| Shift | sizeof(T) | Probable type |  
|-------|-----------|---------------|  
| 0 | 1 | `char`, `uint8_t`, `bool` |  
| 1 | 2 | `short`, `int16_t` |  
| 2 | 4 | `int`, `float`, `uint32_t` |  
| 3 | 8 | `long`, `double`, `pointer`, `size_t` |  
| 4 | 16 | Small struct, `__int128` |  
| 5 | 32 | `std::string` (new ABI) |

> 💡 **In RE:** when you see `sub rax, rcx; sar rax, N` after loading two adjacent QWORDs from the same object, it's almost certainly a `vec.size()`. The shift N gives you `sizeof(T) = 2^N`, which may be enough to identify the element type.

**`vec[i]` (indexed access):**

```nasm
mov    rax, QWORD PTR [rdi]          ; _M_start (buffer base)  
mov    rax, QWORD PTR [rax+rcx*8]    ; _M_start[i] with sizeof(T) == 8  
```

Indexed access is a simple dereference with a scale factor. The factor (here `*8`) is `sizeof(T)`.

**`vec.push_back(val)`:**

```nasm
mov    rax, QWORD PTR [rdi+8]        ; _M_finish  
cmp    rax, QWORD PTR [rdi+16]       ; _M_finish vs _M_end_of_storage  
je     .L_realloc                     ; if equal, buffer full → reallocate  

; Space available: place the element at _M_finish
mov    QWORD PTR [rax], rsi          ; store the value  
add    QWORD PTR [rdi+8], 8          ; _M_finish += sizeof(T)  
jmp    .L_done  

.L_realloc:
; Call reallocation (complex: new buffer, copy, free)
call   std::vector<T>::_M_realloc_insert(...)
.L_done:
```

The pattern `cmp [rdi+8], [rdi+16]` followed by `je` to a reallocation function is the `push_back` signature. The comparison `_M_finish == _M_end_of_storage` tests whether capacity is exhausted.

**Iteration `for (auto& elem : vec)`:**

```nasm
mov    rbx, QWORD PTR [rdi]          ; rbx = _M_start (begin iterator)  
mov    r12, QWORD PTR [rdi+8]        ; r12 = _M_finish (end iterator)  
.L_loop:
cmp    rbx, r12                       ; begin == end?  
je     .L_end  
; ... use rbx as pointer to current element ...
add    rbx, 8                         ; advance by sizeof(T)  
jmp    .L_loop  
.L_end:
```

The range-for compiles to a loop between `_M_start` and `_M_finish` with an increment of `sizeof(T)`.

## `std::string` (new ABI `__cxx11`, GCC ≥ 5)

Since GCC 5, `std::string` uses the **new ABI** identifiable by the namespace `std::__cxx11::basic_string`. The major change from the old ABI is the switch from the COW (*Copy-On-Write*) model to a model with **Small String Optimization (SSO)**.

### Memory layout

```
std::__cxx11::basic_string<char> (sizeof = 32 bytes on x86-64):
┌──────────────────────────────────────┐
│  _M_dataplus._M_p  (char*)           │  offset 0    — pointer to data
├──────────────────────────────────────┤
│  _M_string_length  (size_t)          │  offset 8    — string length
├──────────────────────────────────────┤
│  _M_local_buf[16]  /  _M_allocated   │  offset 16   — local SSO buffer (16 bytes)
│  capacity                            │               or allocated capacity
└──────────────────────────────────────┘
```

The three zones:

- **`_M_dataplus._M_p`** (offset 0): pointer to string data. For short strings (≤ 15 characters + null terminator), this pointer points to `_M_local_buf` at offset 16 of the same object. For long strings, it points to a heap-allocated buffer.

- **`_M_string_length`** (offset 8): string length in bytes (without null terminator). Corresponds to `str.size()` and `str.length()`.

- **`_M_local_buf` / capacity** (offset 16): 16-byte union. In SSO mode (short string), these 16 bytes directly contain the string characters. In heap mode (long string), the first `size_t` (8 bytes) contains the allocated capacity.

### Small String Optimization (SSO)

SSO is a crucial optimization to recognize in RE. The idea is to avoid a heap allocation for small strings by storing data directly in the `std::string` object itself.

**Short string (≤ 15 chars) — SSO mode:**

```
String object on the stack:
┌──────────────────────────────────────┐
│  _M_p = address of [offset 16]  ───┐ │  offset 0    — points to itself
├──────────────────────────────────┐ │ │
│  _M_string_length = 5            │ │ │  offset 8
├──────────────────────────────────┤ │ │
│  'H' 'e' 'l' 'l' 'o' '\0' ... ←┘ │  offset 16   — inline data
│  (padding to 16 bytes)               │
└──────────────────────────────────────┘
```

The `_M_p` pointer points inside the object itself (offset 16). No heap allocation occurs.

**Long string (> 15 chars) — heap mode:**

```
String object on the stack:           Buffer on the heap:
┌─────────────────────────────┐      ┌────────────────────────────┐
│  _M_p ──────────────────────┼──→   │  'T' 'h' 'i' 's' ' ' 'i'   │
├─────────────────────────────┤      │  's' ' ' 'a' ' ' 'l' 'o'   │
│  _M_string_length = 25      │      │  'n' 'g' ' ' 's' 't' 'r'   │
├─────────────────────────────┤      │  'i' 'n' 'g' '!' '\0'      │
│  _M_allocated_capacity = 30 │      └────────────────────────────┘
│  (8 bytes, rest is padding) │
└─────────────────────────────┘
```

The `_M_p` pointer points to the heap. The allocated capacity is stored at offset 16.

### Distinguishing SSO and heap in RE

The test the code performs to determine the mode is:

```nasm
; rdi = pointer to std::string
mov    rax, QWORD PTR [rdi]          ; _M_p  
lea    rdx, [rdi+16]                 ; address of _M_local_buf  
cmp    rax, rdx                      ; _M_p == &_M_local_buf?  
je     .L_short_string                ; yes → SSO, no free needed  
; No → long string, buffer is on the heap
mov    rdi, rax  
call   operator delete(void*)        ; free the heap buffer  
```

> 💡 **Fundamental RE pattern:** `lea rdx, [rdi+16]; cmp [rdi], rdx` is the SSO test signature in the destructor or reallocation operations of `std::string`. If you see it, the object at `rdi` is a `std::string` with the new ABI. This pattern is extremely frequent — you'll see it in any C++ binary compiled with GCC ≥ 5.

### The `std::string` constructor

The constructor initializes the SSO pointer:

```nasm
; Constructing a std::string from a const char*
; rdi = this (string to construct), rsi = source (const char*)
std::string::basic_string(const char*):
    lea    rax, [rdi+16]              ; address of local buffer
    mov    QWORD PTR [rdi], rax       ; _M_p = &_M_local_buf (initial SSO mode)
    ; ... calculate length, copy data ...
    ; if length > 15: allocate on heap and update _M_p
```

The first action is always `lea rax, [rdi+16]; mov [rdi], rax` — initializing `_M_p` to point to the local buffer. If the string is too long, an allocation follows and `_M_p` is updated.

### The `std::string` destructor

```nasm
std::string::~basic_string():
    mov    rax, QWORD PTR [rdi]       ; _M_p
    lea    rdx, [rdi+16]              ; &_M_local_buf
    cmp    rax, rdx                   ; SSO?
    je     .L_done                    ; yes → nothing to free
    mov    rdi, rax                   ; no → free the heap buffer
    call   operator delete(void*)
.L_done:
    ret
```

This destructor is one of the most frequent in any C++ binary. You'll see it in cleanup landing pads (Section 17.4), in destructors of any class containing a `std::string`, and in epilogues of functions with local `std::string`s.

### Old ABI (GCC < 5, or `-D_GLIBCXX_USE_CXX11_ABI=0`)

The old ABI uses a COW (*Copy-On-Write*) model with a different layout:

```
Old ABI std::string (sizeof = 8 bytes):
┌──────────────────────────────────────┐
│  _M_p (char*) → shared buffer        │  offset 0    — only visible field
└──────────────────────────────────────┘

Shared buffer on the heap:
┌──────────────────────────────────────┐
│  _M_length   (size_t)                │  offset -24 from _M_p
├──────────────────────────────────────┤
│  _M_capacity (size_t)                │  offset -16
├──────────────────────────────────────┤
│  _M_refcount (atomic<int>)           │  offset -8   (COW counter)
├══════════════════════════════════════╡
│  string data + '\0'                  │  offset 0 ← _M_p points here
└──────────────────────────────────────┘
```

The `std::string` object is only 8 bytes (a single pointer). Length, capacity, and reference count are stored *before* the string data, at negative offsets from `_M_p`. The reference count enables COW: multiple `std::string`s can share the same buffer, and a copy is only made upon modification.

> 💡 **In RE:** if a `std::string` is only 8 bytes and you see accesses to `[_M_p - 24]`, `[_M_p - 16]`, `[_M_p - 8]`, it's the old COW ABI. If the object is 32 bytes with the `lea rdx, [rdi+16]; cmp [rdi], rdx` pattern, it's the new SSO ABI. The presence of `__cxx11` in mangled symbols confirms the new ABI.

## `std::map<K, V>`

`std::map` is implemented as a **red-black tree**. It's a node-based structure with individually heap-allocated nodes, making it more complex to traverse in RE than a `vector`.

### `std::map` object layout

```
std::map<K, V> (sizeof = 48 bytes on x86-64):
┌──────────────────────────────────────┐
│  _M_key_compare (comparator)         │  offset 0    — functor object (often empty: 0 or 1 byte)
├──────────────────────────────────────┤
│  _M_header:                          │
│  ┌──────────────────────────────┐    │
│  │  _M_color (int/enum)         │    │  offset 8    — header node color (RED)
│  ├──────────────────────────────┤    │
│  │  _M_parent (node*)           │    │  offset 16   — tree root
│  ├──────────────────────────────┤    │
│  │  _M_left (node*)             │    │  offset 24   — leftmost node (begin)
│  ├──────────────────────────────┤    │
│  │  _M_right (node*)            │    │  offset 32   — rightmost node (rbegin)
│  └──────────────────────────────┘    │
├──────────────────────────────────────┤
│  _M_node_count (size_t)              │  offset 40   — number of elements
└──────────────────────────────────────┘
```

The `_M_header` is a sentinel node containing no data. It serves as an anchor for the tree: its `_M_parent` points to the root, its `_M_left` to the smallest element (used by `begin()`), and its `_M_right` to the largest (used by `rbegin()`).

> ⚠️ **The 48-byte sizeof** may vary slightly depending on whether the comparator is an empty object (case of `std::less<K>`, which benefits from *empty base optimization*) or a stateful object. In practice, with the default comparator, the size is almost always 48 bytes.

### Node layout

Each tree node is individually heap-allocated:

```
_Rb_tree_node<pair<const K, V>>:
┌──────────────────────────────────────┐
│  _M_color  (int)                     │  offset 0    — RED (0) or BLACK (1)
├──────────────────────────────────────┤
│  _M_parent (_Rb_tree_node_base*)     │  offset 8    — parent node
├──────────────────────────────────────┤
│  _M_left   (_Rb_tree_node_base*)     │  offset 16   — left child
├──────────────────────────────────────┤
│  _M_right  (_Rb_tree_node_base*)     │  offset 24   — right child
├══════════════════════════════════════╡
│  _M_value_field:                     │  offset 32   — data start
│    first  (const K)                  │               — the key
│    second (V)                        │               — the value
└──────────────────────────────────────┘
```

The first 32 bytes constitute the node base (color, parent, left, right). The data (`std::pair<const K, V>`) starts at offset 32.

### Characteristic assembly patterns

**`map.size()`:**

```nasm
mov    rax, QWORD PTR [rdi+40]       ; _M_node_count
```

A simple load at offset 40. No calculation needed.

**`map.find(key)` and tree navigation:**

```nasm
; Red-black tree search
; rdi = map*, rsi = key to find
mov    rax, QWORD PTR [rdi+16]       ; _M_parent = tree root  
lea    rdx, [rdi+8]                   ; header address (sentinel = end())  
.L_search:
    test   rax, rax
    je     .L_not_found
    ; Compare current node's key with search key
    mov    rcx, QWORD PTR [rax+32]    ; node->first (the key, offset 32)
    cmp    rcx, rsi
    jl     .L_go_right
    jg     .L_go_left
    ; Found
    jmp    .L_found
.L_go_left:
    mov    rax, QWORD PTR [rax+16]    ; node->_M_left
    jmp    .L_search
.L_go_right:
    mov    rax, QWORD PTR [rax+24]    ; node->_M_right
    jmp    .L_search
```

> 💡 **RE pattern:** a loop that alternately loads `[rax+16]` (left) or `[rax+24]` (right) based on a comparison result, with a null test as termination condition, is a red-black tree search. Data access is at offset 32 of the node.

**Iteration (`for (auto& [k, v] : map)`):**

`std::map` iteration uses the in-order successor. The pattern is more complex than `vector`'s because it must navigate the tree:

```nasm
; Advance iterator: find in-order successor
; rdi = current node
mov    rax, QWORD PTR [rdi+24]       ; rax = _M_right  
test   rax, rax  
je     .L_no_right_child  
; Descend left in right subtree
.L_leftmost:
    mov    rdx, QWORD PTR [rax+16]    ; rdx = _M_left
    test   rdx, rdx
    je     .L_found_next
    mov    rax, rdx
    jmp    .L_leftmost

.L_no_right_child:
; Go up while coming from the right
    mov    rax, QWORD PTR [rdi+8]     ; parent
    ; ... ascent logic ...
```

This pattern is characteristic of a binary tree iterator increment. The `_Rb_tree_increment` function from `libstdc++` is often called directly.

## `std::unordered_map<K, V>`

`std::unordered_map` is a **hash table** with chaining via linked lists. Its layout is significantly more complex than `std::map`'s.

### `std::unordered_map` object layout

Internally, `libstdc++` implements `std::unordered_map` via `_Hashtable`. The simplified layout is:

```
std::unordered_map<K, V> (sizeof = 56 bytes on x86-64):
┌──────────────────────────────────────┐
│  _M_bucket_count (size_t)            │  offset 0    — number of buckets
├──────────────────────────────────────┤
│  _M_buckets (__node_base**)          │  offset 8    — array of pointers to lists
├──────────────────────────────────────┤
│  _M_bbegin._M_node:                  │
│  ┌──────────────────────────────┐    │
│  │  _M_nxt (__node_base*)       │    │  offset 16   — head of global linked list
│  └──────────────────────────────┘    │
├──────────────────────────────────────┤
│  _M_element_count (size_t)           │  offset 24   — number of elements
├──────────────────────────────────────┤
│  _M_rehash_policy:                   │
│  ┌──────────────────────────────┐    │
│  │  _M_max_load_factor (float)  │    │  offset 32
│  ├──────────────────────────────┤    │
│  │  _M_next_resize (size_t)     │    │  offset 40   (may vary with alignment)
│  └──────────────────────────────┘    │
├──────────────────────────────────────┤
│  _M_single_bucket (__node_base*)     │  offset 48   — single bucket (optimization for 1 bucket)
└──────────────────────────────────────┘
```

> ⚠️ **Exact offsets may vary** depending on the `libstdc++` version and template parameters (hash, equality, allocator). The layout above is for GCC 7 through 14 with default parameters. Always verify by inspecting the analyzed binary's constructors.

### Node layout

```
_Hash_node<pair<const K, V>>:
┌──────────────────────────────────────┐
│  _M_nxt (__node_base*)               │  offset 0    — next node in list
├──────────────────────────────────────┤
│  _M_hash (size_t)                    │  offset 8    — precalculated hash (if cached)
├──────────────────────────────────────┤
│  _M_v:                               │  offset 16   — data start
│    first  (const K)                  │               — the key
│    second (V)                        │               — the value
└──────────────────────────────────────┘
```

> 💡 **Note:** the `_M_hash` field is only present if the hash is cached, which is the default when the hash function isn't trivial. For integer keys with the default hash, `libstdc++` may omit this field.

### Characteristic assembly patterns

**`umap.size()`:**

```nasm
mov    rax, QWORD PTR [rdi+24]       ; _M_element_count
```

**Key lookup (`umap.find(key)` / `umap[key]`):**

```nasm
; 1. Calculate key hash
mov    rdi, rsi                       ; key  
call   std::hash<K>::operator()(K)    ; or inline: hashing instructions  
; rax = hash

; 2. Find the bucket
xor    edx, edx  
div    QWORD PTR [rdi]               ; hash % _M_bucket_count  
; rdx = bucket index

; 3. Load bucket list head
mov    rax, QWORD PTR [rdi+8]        ; _M_buckets  
mov    rax, QWORD PTR [rax+rdx*8]    ; _M_buckets[index]  

; 4. Walk the linked list
.L_chain:
    test   rax, rax
    je     .L_not_found
    cmp    QWORD PTR [rax+16], rsi    ; compare node's key
    je     .L_found
    mov    rax, QWORD PTR [rax]       ; _M_nxt
    jmp    .L_chain
```

> 💡 **RE pattern:** a hash calculation followed by a `div` by a value loaded from the object, then a linked list traversal (loop with `[rax] → rax`), is characteristic of a `std::unordered_map` access. The presence of a hash function call (or inline hashing instructions like `imul` + shifts from FNV or MurmurHash) confirms the identification.

## `std::shared_ptr<T>` (structural overview)

Although covered in detail in Section 17.8, the `std::shared_ptr` layout deserves a preview here because it constantly appears in STL containers (e.g., `std::vector<std::shared_ptr<Shape>>`).

### Memory layout

```
std::shared_ptr<T> (sizeof = 16 bytes):
┌──────────────────────────────────────┐
│  _M_ptr (T*)                         │  offset 0    — pointer to managed object
├──────────────────────────────────────┤
│  _M_refcount (_Sp_counted_base*)     │  offset 8    — pointer to control block
└──────────────────────────────────────┘

Control block (_Sp_counted_base) on the heap:
┌──────────────────────────────────────┐
│  vptr                                │  offset 0    — control block vtable
├──────────────────────────────────────┤
│  _M_use_count  (atomic<int>)         │  offset 8    — strong reference count
├──────────────────────────────────────┤
│  _M_weak_count (atomic<int>)         │  offset 12   — weak reference count + 1
├──────────────────────────────────────┤
│  (data specific to control block     │  offset 16+
│   type: deleter, object for          │
│   make_shared, etc.)                 │
└──────────────────────────────────────┘
```

A `std::vector<std::shared_ptr<Shape>>` has its 16-byte elements in the vector's buffer. The `sar rax, 4` (division by 16) in the `size()` calculation is the signature of a vector of shared_ptr.

## Identifying STL containers in a stripped binary

On a stripped binary, there are no symbols to identify types. Here's a systematic method for recognizing STL containers:

### By object size

| sizeof | Probable container |  
|--------|-------------------|  
| 8 | `std::string` (old ABI), raw pointer, `std::unique_ptr` |  
| 16 | `std::shared_ptr`, `std::weak_ptr`, `std::array<T,N>` (small) |  
| 24 | `std::vector` |  
| 32 | `std::string` (new ABI `__cxx11`) |  
| 48 | `std::map`, `std::set`, `std::multimap`, `std::multiset` |  
| 56 | `std::unordered_map`, `std::unordered_set` |

When a constructor allocates an object or initializes a member, and you can determine the size used (from the allocation or from adjacent member offsets), this table gives you a starting point.

### By access patterns

| Observed pattern | Container |  
|-----------------|-----------|  
| Three adjacent pointers, `sub` + `sar` for size | `std::vector` |  
| `lea rdx, [rdi+16]; cmp [rdi], rdx` (SSO test) | `std::string` (`__cxx11`) |  
| Left/right tree navigation with color | `std::map` / `std::set` |  
| Hash + modulo + linked list traversal | `std::unordered_map` / `std::unordered_set` |  
| Two pointers (T* + control block*), atomic accesses | `std::shared_ptr` |

### By `libstdc++` functions called

Even in a stripped binary, calls to `libstdc++.so` functions via PLT remain visible with their mangled symbols. Some functions unambiguously identify the container:

| PLT symbol | Container |  
|-----------|-----------|  
| `_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE...` | `std::string` |  
| `_ZSt18_Rb_tree_incrementPKSt18_Rb_tree_node_base` | `std::map` / `std::set` (iterator increment) |  
| `_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base` | `std::map` / `std::set` (iterator decrement) |  
| `_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_` | `std::map` / `std::set` (insertion) |  
| `_ZNSt10_HashtableI...` | `std::unordered_map` / `std::unordered_set` |

```bash
# List STL symbols in the PLT
$ objdump -d -j .plt oop_O2_strip | c++filt | grep 'std::'
```

### By error strings

`libstdc++` includes characteristic error strings that survive in the binary:

```bash
$ strings oop_O2_strip | grep -i 'vector\|map\|string\|hash'
vector::_M_realloc_insert  
basic_string::_M_construct null not valid  
basic_string::_M_create  
```

The presence of `vector::_M_realloc_insert` in the strings is direct proof of `std::vector` usage.

## Reconstruction in Ghidra

To reconstruct an STL container in Ghidra:

1. **Identify the container** using the techniques above (size, access patterns, PLT symbols).

2. **Create the structure in the Data Type Manager.** For example, for `std::vector<int>`:

   ```
   struct vector_int {
       int* _M_start;          // offset 0
       int* _M_finish;         // offset 8
       int* _M_end_of_storage; // offset 16
   };
   ```

3. **Apply the type** to local variables and class members in the decompiler. The pseudo-code becomes immediately more readable when `param_1->field_0x8 - param_1->field_0x0` transforms into `vec->_M_finish - vec->_M_start`.

4. **For nested containers** (e.g., `std::vector<std::string>`), first create the inner structure (`string_cxx11`), then use it as the element type in the vector. Ghidra will automatically calculate correct offsets.

> 💡 **Practical tip:** create a library of STL types in Ghidra (a `.gdt` file) that you'll reuse across projects. `libstdc++` layouts don't change often — once the structures are created, they're valid for all GCC binaries of the same ABI generation.

## Layout summary

| Container | sizeof | Key fields (offsets) | RE signature |  
|-----------|--------|---------------------|-------------|  
| `std::vector<T>` | 24 | start(0), finish(8), end_storage(16) | 3 ptrs, `sub`+`sar` for size |  
| `std::string` (cxx11) | 32 | ptr(0), length(8), local_buf(16) | `lea [rdi+16]; cmp [rdi], rdx` (SSO) |  
| `std::string` (old) | 8 | ptr(0), metadata at negative offsets | Accesses `[ptr-24]`, `[ptr-8]` |  
| `std::map<K,V>` | 48 | parent(16), left(24), right(32), count(40) | Left/right tree navigation |  
| `std::unordered_map<K,V>` | 56 | bucket_count(0), buckets(8), count(24) | Hash + modulo + linked list |  
| `std::shared_ptr<T>` | 16 | ptr(0), control_block(8) | `lock xadd` (atomic counter) |

---


⏭️ [Templates: instantiations and symbol explosion](/17-re-cpp-gcc/06-templates-instantiations.md)
