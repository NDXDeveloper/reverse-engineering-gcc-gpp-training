🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.5 — Parsing a homemade C/C++ structure directly in the binary

> 🎯 **Goal of this section**: Learn to identify C/C++ structures compiled into an ELF binary, to deduce their memory layout without the source code, and to write `.hexpat` patterns to visualize them — taking padding, alignment, and GCC specifics into account.

> 📦 **Test binary**: `binaries/ch22-oop/oop_O0` (compiled with symbols) then `binaries/ch22-oop/oop_O0_strip` (without symbols)

---

## The problem: structures without source code

In section 6.4, we parsed the ELF header — a perfectly documented format whose specification gives the type, size, and offset of every field. In the real life of reverse engineering, the situation is rarely that comfortable. The binary you analyze contains structures defined by the developer — a `struct Config`, a `class Player`, a `struct PacketHeader` — whose documentation and source code you do not have.

These structures do exist in the binary, though. They are stored in the `.data` section (initialized globals), `.bss` (uninitialized globals), `.rodata` (constants), or on the stack and heap at runtime. The compiler translated the C/C++ definition into a layout of bytes in memory, possibly adding padding to respect the architecture's alignment constraints. Our job is to recover this layout and describe it in a `.hexpat` pattern.

---

## Reminder: how GCC organizes a structure in memory

Before parsing anything in ImHex, you have to understand the rules GCC applies when it translates a C `struct` into bytes. These rules are dictated by the **System V AMD64 ABI** we saw in Chapter 3.

### Natural alignment

Each primitive type has a **natural alignment** equal to its size (up to a maximum of 8 bytes on x86-64):

| C type | Size | Alignment |  
|---|---|---|  
| `char`, `uint8_t` | 1 byte | 1 byte |  
| `short`, `uint16_t` | 2 bytes | 2 bytes |  
| `int`, `uint32_t`, `float` | 4 bytes | 4 bytes |  
| `long`, `uint64_t`, `double`, pointers | 8 bytes | 8 bytes |

An `int` field must start at an address that is a multiple of 4. A `double` field must start at an address that is a multiple of 8. If the previous field ends at an address that does not respect this constraint, the compiler inserts **padding bytes** between the two fields to realign.

### Internal padding

Let's take a concrete example. Suppose the developer wrote:

```c
struct PlayerInfo {
    uint8_t  level;       // 1 byte
    uint32_t score;       // 4 bytes
    uint8_t  health;      // 1 byte
    uint64_t unique_id;   // 8 bytes
};
```

In memory, GCC does not place these fields contiguously. Here is the actual layout:

```
Offset  Content               Size
0x00    level (uint8_t)       1 byte
0x01    --- padding ---       3 bytes  (align score on 4)
0x04    score (uint32_t)      4 bytes
0x08    health (uint8_t)      1 byte
0x09    --- padding ---       7 bytes  (align unique_id on 8)
0x10    unique_id (uint64_t)  8 bytes
0x18    (end)                 Total: 24 bytes
```

The structure occupies 24 bytes while the useful data is only 14. The 10 remaining bytes are padding invisible at the C source-code level but very real in the binary. If your `.hexpat` pattern does not take this padding into account, every field after the first hole will be shifted and the parsed values will be wrong.

### Tail padding

GCC also adds padding at the **end** of the structure so that the total size is a multiple of the alignment of the largest member. That guarantees arrays of structures respect every element's alignment.

In our example, the widest member is `unique_id` (alignment 8). The structure ends at offset `0x18` (24), which is already a multiple of 8 — no tail padding needed. But consider this variant:

```c
struct CompactInfo {
    uint32_t score;      // 4 bytes
    uint8_t  level;      // 1 byte
};
```

The useful data occupies 5 bytes, but the widest member is `score` (alignment 4). The total size of the structure is rounded up to 8 bytes (next multiple of 4), with 3 bytes of padding after `level`.

### The `__attribute__((packed))` attribute

Some developers use `__attribute__((packed))` to suppress all padding and force a compact layout. This is common in network protocol structures and file formats. A packed structure occupies exactly the sum of its members' sizes, with no holes. In `.hexpat`, this simply translates to a structure without `padding[]` between fields.

When you analyze an unknown binary, you do not know a priori whether a structure is packed or not. ImHex's Data Inspector and hex view will let you decide: if the parsed values make sense without padding, the structure is likely packed; if they only become coherent by adding holes at alignment points, it is not.

---

## Method: recovering the layout of an unknown structure

Recovering the memory layout of a structure whose source code you do not have is an iterative process that combines several sources of information. Here is the general approach.

### Step 1 — Locate the structure in the binary

Before parsing, you have to know **where** the structure lives in the file. Several clues help locate it.

**Character strings.** If the structure contains strings or pointers to `.rodata`, the `strings` command or ImHex's Strings panel can reveal readable texts whose offset points to the data area we are interested in.

**Disassembly.** By analyzing the code in Ghidra or objdump (Chapters 7–8), you see the instructions that access the structure: `mov`s with offsets relative to a base register. These offsets give you the relative positions of the fields. For example, `mov eax, [rbx+0x10]` indicates that a 4-byte field sits at offset `0x10` in the structure pointed to by `rbx`.

**The `.data` and `.rodata` sections.** Initialized globals live in `.data`, constants in `.rodata`. The Section Header Table (which we parsed in 6.4) gives the offsets and sizes of these sections in the file. You can navigate directly to these offsets in ImHex.

**The decompiler.** If you have already imported the binary in Ghidra (Chapter 8), the decompiler provides an approximate reconstruction of the structures as C-like pseudo-code. This reconstruction is imperfect but gives a solid starting point — probable types, number of fields, approximate size.

### Step 2 — Formulate a layout hypothesis

From the gathered clues, you formulate a first hypothesis about the structure: how many fields, which types, in what order. You write the matching `.hexpat` pattern.

At this stage, do not aim for perfection. Start with the fields you are sure of (the magic number if there is one, the integers whose value is recognizable, the pointers whose address is plausible) and leave uncertainty zones marked by temporary `u8 unknown_XX[N]`.

### Step 3 — Evaluate, verify, adjust

Evaluate the pattern in ImHex and examine the parsed values. Questions to ask yourself:

- Do the integers have plausible values? A `uint32_t` that equals `0x00000003` for a counter is plausible. A `uint32_t` that equals `0x7F454C46` is an ELF magic number, not a counter.  
- Do the pointers point to existing regions of the file or address space? A pointer `0x00404020` in a binary whose `.data` begins at `0x00404000` is plausible. A pointer `0xCCCCCCCC` is uninitialized padding.  
- Are there "holes" with null bytes between significant fields? These are probably alignment padding bytes.  
- Are strings readable and null-terminated?

Adjust your pattern, re-evaluate, and repeat until all values are coherent.

---

## Concrete case: parsing a global structure in `.data`

Let's put this method into practice on a realistic scenario. Suppose that during the analysis of the `ch22-oop` binary, the disassembly and strings have let us identify a global variable in the `.data` section that looks like a configuration structure. The Section Header Table gives us the offset of `.data` in the file.

After exploring in ImHex, we observe the following block at the offset of this variable (values are fictional but realistic):

```
00 00 80 3F 00 00 00 00  03 00 00 00 00 00 00 00
E8 03 00 00 00 00 00 00  01 00 00 00 00 00 00 00
48 65 6C 6C 6F 00 00 00  00 00 00 00 00 00 00 00
```

Let's analyze these 48 bytes using the Data Inspector.

Placing the cursor at offset `0x00`, the Data Inspector shows us that `float` = `1.0` (the bytes `00 00 80 3F` are the little-endian IEEE 754 representation of `1.0`). That is a strong hint: the first field is probably a `float`.

Bytes `0x04`–`0x07` are null — likely padding to align the next field on 8 bytes.

At offset `0x08`, `uint32_t` = `3`. A plausible value for a counter or identifier.

Bytes `0x0C`–`0x0F` are null — more padding, this time to align a 64-bit field.

At offset `0x10`, `uint32_t` = `1000` (`0x03E8`). Followed by null padding up to `0x17`.

At offset `0x18`, `uint32_t` = `1`. A boolean or a flag?

Finally, at offset `0x20`, we read `Hello` followed by zeros — a null-terminated C string in a 16-byte buffer.

Cross-referencing these observations with the disassembled code (where we see accesses to `[base+0x00]`, `[base+0x08]`, `[base+0x10]`, `[base+0x18]`, `[base+0x20]`), we formulate this hypothesis:

```cpp
struct AppConfig {
    float  scale;            // 0x00: 4 bytes
    padding[4];              // 0x04: alignment on 8
    u32    max_retries;      // 0x08: 4 bytes
    padding[4];              // 0x0C: alignment on 8
    u32    timeout_ms;       // 0x10: 4 bytes
    padding[4];              // 0x14: alignment on 8
    u32    verbose;          // 0x18: 4 bytes (boolean)
    padding[4];              // 0x1C: alignment on 8
    char   label[16];        // 0x20: fixed string
};                           // Total size: 48 bytes

AppConfig config @ 0x...;    // replace with the real offset in .data
```

Let's evaluate this pattern. In the Pattern Data tree, we see:

```
config
├── scale        = 1.0
├── max_retries  = 3
├── timeout_ms   = 1000
├── verbose      = 1
└── label        = "Hello"
```

The values are coherent, the types make sense, and the total size (48 bytes) matches the observed data block. The pattern is validated.

> 💡 **Why so much padding?** You'll notice that each 4-byte field is followed by 4 bytes of padding, as if the compiler aligned everything on 8 bytes. This is a frequent behavior when the structure contains at least one 8-byte member (a pointer or a `uint64_t`), or when the compiler chooses a conservative alignment. Here, the structure's global alignment is probably dictated by a 64-bit member we did not see (perhaps removed during refactoring), or by an explicit alignment pragma.

---

## C++ structures: member data and vtable pointer

When you parse a C++ object rather than a C structure, an additional element comes into play: the **vtable pointer** (`vptr`). For any class containing at least one virtual method, GCC adds an implicit pointer at the beginning of the object. This pointer takes 8 bytes (on x86-64) and points to the class's vtable in `.rodata`.

Concretely, if the source code declares:

```cpp
class Enemy {  
public:  
    virtual void update();
    virtual void render();
    uint32_t hp;
    float    speed;
    uint64_t id;
};
```

The object's layout in memory is:

```
Offset  Content                Size
0x00    vptr (→ vtable)        8 bytes    ← added by the compiler
0x08    hp (uint32_t)          4 bytes
0x0C    speed (float)          4 bytes
0x10    id (uint64_t)          8 bytes
0x18    (end)                  Total: 24 bytes
```

The matching `.hexpat` pattern:

```cpp
struct Enemy {
    u64   vptr         [[format("hex"), comment("Pointer to the vtable")]];
    u32   hp;
    float speed;
    u64   id           [[format("hex")]];
};
```

The `vptr` is a pointer to a **virtual address** (not a file offset). Its value will be an address in the `.rodata` range, typically something like `0x00403D50`. If you see an 8-byte value at the beginning of an object that points to `.rodata`, that is a very strong hint you are dealing with a polymorphic C++ object. We will dig deeper into vtable analysis in Chapter 17.

### Single inheritance

With inheritance, the parent class's member data is placed **before** the derived class's. The `vptr` is inherited (and potentially updated to point to the derived class's vtable):

```cpp
// C++: class Boss : public Enemy { uint32_t phase; };

struct Boss {
    // --- inherited members from Enemy ---
    u64   vptr         [[format("hex"), comment("Boss's vtable")]];
    u32   hp;
    float speed;
    u64   id           [[format("hex")]];
    // --- Boss's own members ---
    u32   phase;
    padding[4];        // tail alignment (size multiple of 8)
};
```

This "parent prefix" layout is the reason an `Enemy*` pointer can point to a `Boss` object in memory — the first bytes have the same structure. In `.hexpat`, we can model this more elegantly with nested structures:

```cpp
struct Enemy {
    u64   vptr [[format("hex")]];
    u32   hp;
    float speed;
    u64   id   [[format("hex")]];
};

struct Boss {
    Enemy base;          // inheritance = inclusion of parent at head
    u32   phase;
    padding[4];
};
```

---

## Arrays of structures in `.data` and `.rodata`

Structures do not always live alone. It is very common to find **arrays of structures** in `.data` (mutable global array) or `.rodata` (constant array, such as a lookup table). A `.hexpat` pattern parses these arrays very naturally:

```cpp
struct LevelEntry {
    u32  level_id;
    u32  enemy_count;
    float difficulty;
    padding[4];
};

// If we know there are 10 levels:
LevelEntry levels[10] @ 0x...;
```

When the number of elements is not known in advance, two approaches are possible. If a counter exists somewhere in the binary (a `num_levels` field in a configuration structure, for example), refer to it directly:

```cpp
AppConfig config @ 0x...;  
LevelEntry levels[config.max_retries] @ 0x...;  // if max_retries is the counter  
```

If no counter is available, you can compute the number of elements from the known size of the data zone. For example, if the `.rodata` section contains a 160-byte block starting at a given offset and each `LevelEntry` is 16 bytes, you can write:

```cpp
#include <std/mem.pat>

u32 block_size = 160;  // determined by analysis  
LevelEntry levels[block_size / sizeof(LevelEntry)] @ 0x...;  
```

---

## Common pitfalls and workarounds

### Zeros are not always padding

When you see null bytes between two identified fields, the temptation is strong to declare them as `padding`. But a zero can also be a **legitimate value**: a zero counter, a `false` boolean, an uninitialized integer. Always cross-reference with the disassembly: if the code explicitly reads a value at that offset (a `mov` or a `cmp`), it is not padding.

### Alignment of GCC vs Clang vs MSVC

The alignment rules described in this section apply to **GCC and Clang on x86-64 Linux** (System V ABI). If you analyze a binary compiled with MSVC (Windows), the padding rules differ slightly, notably for structures containing `long double` or for bitfield alignment. In the context of this training, we stay on GCC/Linux, but keep this nuance in mind if you run into binaries cross-compiled with MinGW.

### Structures with bitfields

C bitfields (`uint32_t flags : 3;`) are compiled as bitmasks inside a machine word. GCC can group several bitfields in the same integer or spread them across multiple ones, according to complex rules that depend on types and declaration order. In `.hexpat`, the `bitfield` type (seen in section 6.4) lets you model these cases, but you first have to determine the underlying machine word size by observation.

### Unions and variants

When the same byte block seems to have different interpretations across instances (sometimes it's an integer, sometimes a string, sometimes a pointer), you are probably dealing with a C `union` or a variant field. The `union` type of `.hexpat` combined with a conditional `if` on a discriminant field lets you model these cases:

```cpp
struct TaggedValue {
    u8 tag;
    padding[7];
    union {
        u64   as_integer;
        double as_float;
        char   as_string[8];
    } value;
};
```

---

## Recap workflow

Here is the complete approach to parse an unknown structure in a binary, summarized in seven steps:

1. **Locate** the data area in the file (via `readelf`, Ghidra, or the Section Headers parsed in 6.4).  
2. **Explore** visually in ImHex: move the cursor, watch the Data Inspector, spot recognizable values.  
3. **Cross-reference** with the disassembly: identify memory accesses (`mov`, `lea`) that reveal field offsets.  
4. **Formulate** a layout hypothesis: types, sizes, padding.  
5. **Write** the matching `.hexpat` pattern.  
6. **Evaluate** and verify: are the parsed values coherent? Do the types make sense in context?  
7. **Iterate**: adjust the pattern, add enums and comments, refine field names.

This workflow is iterative and converges gradually. The first iterations produce an approximate pattern with `unknown` fields. Following iterations, enriched by the disassembly and dynamic tests (Chapters 11–13), refine the understanding to a complete, documented pattern.

---

## Summary

Parsing C/C++ structures in a binary without source code is one of ImHex's most powerful uses in reverse engineering. The key is to understand GCC's padding and alignment rules on x86-64: natural type alignment, internal padding between fields, tail padding for arrays. For C++ objects, the `vptr` at the head of the object is a recognizable marker that signals a polymorphic object. The approach is always iterative — locate, explore, formulate a hypothesis, write the pattern, evaluate, adjust — and enriches itself through the analysis by combining ImHex's information with that of the disassembler and debugger. The resulting `.hexpat` pattern captures this understanding in a durable, shareable way.

---


⏭️ [Colorization, annotations, and bookmarks of binary regions](/06-imhex/06-colorization-annotations.md)
