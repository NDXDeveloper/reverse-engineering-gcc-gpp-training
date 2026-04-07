🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.3 — The `.hexpat` pattern language — syntax and base types

> 🎯 **Goal of this section**: Master the foundations of the `.hexpat` language — primitive types, structures, enumerations, arrays, conditionals, and special variables — so you can write simple to intermediate parsing patterns on any binary file.

---

## Language philosophy

The `.hexpat` language (for *hex pattern*) is a declarative language with C-style syntax whose goal is to **describe the layout of data in a binary file**. When you write a pattern, you do not program a behavior — you describe a structure. ImHex then takes care of overlaying that description onto the bytes of the file, extracting values, showing them in the Pattern Data tree, and colorizing the matching regions in the hex view.

If you can write a C `struct`, you already know how to write 80% of a `.hexpat` pattern. The language deliberately reuses C syntax to minimize the learning curve for developers and reverse engineers, who manipulate C structures daily. Differences with C cover aspects specific to binary parsing: explicit placement in memory, formatting attributes, variable-size types, and a few constructions absent from standard C.

---

## Primitive types

The primitive types of `.hexpat` correspond to the integer and floating-point types found in binary files. They are named explicitly, without ambiguity about size.

### Integers

| `.hexpat` type | Size | Signed | C equivalent |  
|---|---|---|---|  
| `u8` | 1 byte | No | `uint8_t` |  
| `s8` | 1 byte | Yes | `int8_t` |  
| `u16` | 2 bytes | No | `uint16_t` |  
| `s16` | 2 bytes | Yes | `int16_t` |  
| `u32` | 4 bytes | No | `uint32_t` |  
| `s32` | 4 bytes | Yes | `int32_t` |  
| `u64` | 8 bytes | No | `uint64_t` |  
| `s64` | 8 bytes | Yes | `int64_t` |  
| `u128` | 16 bytes | No | `__uint128_t` |  
| `s128` | 16 bytes | Yes | `__int128_t` |

### Floats

| `.hexpat` type | Size | C equivalent |  
|---|---|---|  
| `float` | 4 bytes | `float` (IEEE 754) |  
| `double` | 8 bytes | `double` (IEEE 754) |

### Characters and booleans

| `.hexpat` type | Size | Description |  
|---|---|---|  
| `char` | 1 byte | ASCII character, shown as a character in the tree |  
| `char16` | 2 bytes | UTF-16 character |  
| `bool` | 1 byte | Shown as `true` (≠ 0) or `false` (= 0) |

### Special type: `padding`

The `padding` type consumes bytes without showing them in the results tree. It is used to skip padding zones or reserved fields that you do not want to clutter the display with:

```cpp
padding[4];   // skip 4 bytes without displaying them
```

---

## Endianness

By default, ImHex interprets multi-byte types as **little-endian**, which matches the native behavior of the x86/x86-64 architectures we work on. If you need to parse big-endian data (network formats, some file formats), you have two options.

**Specify endianness globally**, at the top of the file:

```cpp
#pragma endian big
```

**Specify endianness per type**, with the `le` and `be` prefixes:

```cpp
be u32 magic;    // this field is big-endian  
le u16 flags;    // this one is explicitly little-endian  
u32 size;        // this one follows the global pragma (little-endian by default)  
```

In the context of this training, nearly all x86-64 ELF binaries are little-endian. You will only need `be` for network fields (Chapters 23 and 28) or magic numbers that follow a big-endian convention.

---

## Variables and placement

### Declaring a variable

In `.hexpat`, declaring a variable does not reserve memory as in C — it **overlays the file** at the current read cursor position. After evaluation, the cursor advances by the size of the type.

```cpp
u32 magic;      // read 4 bytes at the current position, advance by 4  
u16 version;    // read 2 bytes at the new position, advance by 2  
u32 file_size;  // read 4 bytes, advance by 4  
```

If the file begins with `7f 45 4c 46 02 00 40 00 00 00`, then after evaluation:

- `magic` equals `0x464c457f` (the first 4 bytes in little-endian)  
- `version` equals `0x0002`  
- `file_size` equals `0x00000040`

Variables appear in the Pattern Data tree with their name, type, offset, and interpreted value.

### Explicit placement with `@`

The `@` operator places a variable at an **absolute offset** in the file, independently of the cursor's current position:

```cpp
u32 magic @ 0x00;          // read 4 bytes at offset 0  
u16 e_type @ 0x10;         // read 2 bytes at offset 16  
u64 e_entry @ 0x18;        // read 8 bytes at offset 24  
```

This is the syntax you will use most often for isolated variables and entry points of your patterns. Inside structures (see below), placement is sequential and automatic — the `@` operator is then used to place the structure instance itself.

---

## Structures (`struct`)

Structures are the fundamental mechanism for describing composite data blocks. The syntax is nearly identical to C:

```cpp
struct FileHeader {
    u32 magic;
    u16 version;
    u16 flags;
    u32 data_offset;
    u32 data_size;
};
```

Inside a structure, fields are read **sequentially**: each field starts where the previous one ends. The total size of the structure is the sum of the sizes of its fields (here: 4 + 2 + 2 + 4 + 4 = 16 bytes).

To instantiate a structure on the file, declare it like a variable:

```cpp
FileHeader header @ 0x00;
```

ImHex parses the first 16 bytes of the file according to the `FileHeader` description, and displays an expandable node in the Pattern Data tree containing the five fields with their values.

### Nested structures

Structures can contain other structures, exactly as in C:

```cpp
struct Timestamp {
    u16 year;
    u8  month;
    u8  day;
    u8  hour;
    u8  minute;
    u8  second;
};

struct FileHeader {
    u32 magic;
    u16 version;
    Timestamp created;
    Timestamp modified;
    u32 data_size;
};

FileHeader header @ 0x00;
```

In the Pattern Data tree, `header.created` appears as an expandable sub-node containing the fields `year`, `month`, `day`, etc. The colorization in the hex view assigns distinct colors to the different nested structures, which gives an immediate visual reading of the data layout.

---

## Enumerations (`enum`)

Enumerations associate **symbolic names with numeric values**, exactly as in C. The difference in `.hexpat` is that you must specify the underlying type, because the size of the enum determines the number of bytes read:

```cpp
enum FileType : u16 {
    TEXT     = 0x0001,
    BINARY   = 0x0002,
    ARCHIVE  = 0x0003,
    IMAGE    = 0x0004
};
```

When ImHex encounters a field of type `FileType`, it reads 2 bytes (because the underlying type is `u16`) and displays the matching symbolic name in the tree. If the bytes are `03 00` (little-endian), the tree displays `ARCHIVE (3)` rather than a raw number. This readability makes all the difference when exploring an unknown format.

Use in a structure:

```cpp
struct FileHeader {
    u32 magic;
    FileType type;    // reads 2 bytes, displays the symbolic name
    u32 data_size;
};
```

If a read value does not match any member of the enum, ImHex displays the raw numeric value with an indicator flagging it as out of spec. That is a useful signal in RE: an unexpected value may indicate an unknown format version, corruption, or a field you have misidentified.

---

## Arrays

Arrays let you parse **sequences of elements of the same type**. `.hexpat` supports three forms of arrays.

### Fixed-size array

```cpp
u8 sha256_hash[32];           // 32 consecutive bytes  
u32 section_offsets[16];      // 16 integers of 4 bytes = 64 bytes  
```

### Dynamic-size array (referenced by a field)

This is the most common form in RE, because the size of an array almost always depends on a field read earlier:

```cpp
struct RecordTable {
    u32 count;
    Record records[count];    // 'count' elements of type Record
};
```

ImHex evaluates `count` by reading the file, then parses exactly `count` instances of `Record` in sequence. This is a behavior impossible to reproduce with a classic hex editor.

### Character array (strings)

A `char` array is displayed as a string in the Pattern Data tree:

```cpp
char name[16];    // displayed as a 16-character string
```

For null-terminated strings whose length is not known in advance, `.hexpat` offers the `str` type with a termination syntax we will see in the advanced features.

---

## Unions (`union`)

A union declares **alternative interpretations** of the same byte region, exactly as in C. All members start at the same offset, and the size of the union is that of the largest member:

```cpp
union Value {
    u32 as_uint;
    s32 as_int;
    float as_float;
};
```

This construction is useful when a field can be interpreted in several ways depending on context. For example, in some formats, a 4-byte field is an integer in one record type and a float in another. With a union, ImHex displays both interpretations and you pick the one that makes sense.

You can combine unions and structures to model variant-field formats:

```cpp
struct TaggedValue {
    u8 type;
    union {
        u32 integer_value;
        float float_value;
        char string_value[4];
    } value;
};
```

---

## Conditions and optional fields

The `.hexpat` language supports `if` / `else` statements inside structures to parse **fields that only exist under certain conditions**:

```cpp
struct Packet {
    u8 type;
    u16 length;

    if (type == 0x01) {
        u32 source_ip;
        u32 dest_ip;
    } else if (type == 0x02) {
        char hostname[length];
    }
};
```

Here, the `Packet` structure has variable content depending on the value of the `type` field. ImHex evaluates the condition at parse time, reads the matching fields, and ignores the branches not taken. The effective size of the structure therefore depends on the file's content — a behavior essential for parsing real formats, which are almost always conditional.

Conditions can reference any field already read in the structure or in a parent structure, as well as global variables.

---

## Attributes

Attributes modify the display or parsing behavior of a variable. They are placed after the declaration, between double brackets `[[...]]`:

### `[[color]]` — display color

```cpp
u32 magic [[color("FF0000")]];    // highlighted in red in the hex view
```

You can specify the color in RGB hexadecimal. It complements the automatic colors assigned by ImHex — useful for making a critical field stand out (a key, a checksum, a decision point).

### `[[name]]` — display name

```cpp
u16 e_type [[name("ELF Type")]];
```

Replaces the variable name in the Pattern Data tree with a more readable name. The variable name in the code stays unchanged.

### `[[comment]]` — comment

```cpp
u32 e_entry [[comment("Program entry point")]];
```

Adds a comment visible in the Pattern Data tree on hover. It is the equivalent of a documentation comment, but integrated into the parsing result.

### `[[format]]` — custom formatting

```cpp
u32 permissions [[format("hex")]];    // displayed in hex rather than decimal
```

Available formats include `hex`, `octal`, `binary`, and you can define custom formatting functions for more elaborate displays.

### `[[hidden]]` — hide a field

```cpp
u16 reserved [[hidden]];
```

The field is parsed (the cursor advances) but does not appear in the Pattern Data tree. Useful for reserved or padding fields you want to cleanly skip without cluttering the display.

---

## Pointers

The `.hexpat` language lets you declare **pointers** — fields whose value is an offset to another position in the file. The syntax uses the `*` operator as in C:

```cpp
struct Header {
    u32 magic;
    u32 *name_table : u32;   // 32-bit pointer to a structure
};
```

The syntax `*name_table : u32` means: "read a `u32` at the current position, interpret it as an absolute offset in the file, and parse the pointed-to structure at that offset". The type after `:` is the type of the pointer itself (its size as a field in the parent structure).

You can also point to complex types:

```cpp
struct NameEntry {
    u16 length;
    char name[length];
};

struct Header {
    u32 magic;
    NameEntry *names : u32;    // follows the pointer to a NameEntry
};
```

In the Pattern Data tree, ImHex displays the pointer value (the offset) and makes the pointed content expandable. In the hex view, the pointed region is colorized, which creates a visual link between the pointer and its target — extremely practical for understanding cross-references in a binary format.

---

## Special variables and built-in functions

The `.hexpat` language provides several **special variables** and **built-in functions** that give access to information about the parsing context.

### `$` — current cursor position

The `$` variable contains the current offset of the read cursor. It is updated automatically at each parsed field. It is used mainly in conditions and for debugging:

```cpp
struct Section {
    u32 offset;
    u32 size;
    // Save the current position to return to it
};
```

### `std::mem::size()` — file size

```cpp
#include <std/mem.pat>

if ($ < std::mem::size()) {
    // there is still data to parse
}
```

### `std::mem::read_unsigned()` — read without advancing the cursor

Lets you read a value at a given offset without modifying the cursor position. Useful for conditions of the "look ahead before deciding what to parse here" kind:

```cpp
#include <std/mem.pat>

u8 next_byte = std::mem::read_unsigned($, 1);
```

### The standard library (`std::`)

ImHex provides a standard library importable via `#include` that contains pre-written types, functions, and patterns:

```cpp
#include <std/mem.pat>       // memory functions (size, read, etc.)
#include <std/io.pat>        // display functions (print, format)
#include <std/string.pat>    // string manipulation
#include <std/math.pat>      // math functions
```

These modules are installed with ImHex (or via the Content Store) and cover common needs. We will use `std::mem` and `std::io` regularly in the patterns of the following sections.

---

## Comments and `#include`

Comments follow C/C++ syntax:

```cpp
// Single-line comment

/*
   Multi-line
   comment
*/
```

The `#include` directive lets you import other `.hexpat` files, whether standard library modules or your own shared type files:

```cpp
#include <std/mem.pat>              // standard library (angle brackets)
#include "my_common_types.hexpat"   // local file (double quotes)
```

This inclusion mechanism is essential for organizing complex patterns into reusable modules. Once you have written a pattern for the ELF header (section 6.4), you can include it in other patterns that analyze specific sections.

---

## Putting it all together: a first complete pattern

Here is a minimal but complete pattern that parses a hypothetical simple file format — a header followed by a table of records:

```cpp
#include <std/mem.pat>

// Expected magic number
#define EXPECTED_MAGIC 0x464D5448  // "HTMF" in little-endian

enum RecordType : u8 {
    TEXT   = 0x01,
    NUMBER = 0x02,
    BLOB   = 0x03
};

struct Record {
    RecordType type;
    u16 data_length;

    if (type == RecordType::TEXT) {
        char data[data_length];
    } else if (type == RecordType::NUMBER) {
        u64 value;
        padding[data_length - 8];
    } else {
        u8 raw_data[data_length];
    }
};

struct FileHeader {
    u32 magic [[color("FF4444"), comment("Must equal 0x464D5448")]];
    u16 version;
    u16 record_count;
    Record records[record_count];
};

FileHeader file @ 0x00;
```

This pattern illustrates most of the concepts seen in this section: primitive types, typed enum, structure with conditional fields, dynamic-size array, formatting attributes, and explicit placement with `@`. In about thirty lines, it describes a format capable of parsing a real file — and ImHex will show you the result as a colorized, navigable, documented tree.

---

## Common errors and debugging

When you develop a pattern, errors are inevitable. Here are the most frequent ones and how to diagnose them.

**"Variable does not fit in file"** — your pattern tries to read past the end of the file. Usual causes: a misinterpreted `count` field that produces a gigantic value, or a structure whose size does not match reality. Check values in the Data Inspector.

**"Unexpected token"** — syntax error. Missing semicolons after a declaration and mismatched braces are the most frequent causes.

**Inconsistent values in the tree** — if the parsed values make no sense (huge integers, unreadable strings), you likely have an **alignment** problem. A forgotten field or one of wrong size in your structure shifts everything after it. Compare the offsets shown in the tree with what you see in the hex view.

**Wrong endianness** — if a `u16` field that should be `0x0002` shows `0x0200`, you have an endianness problem. Add a `#pragma endian big` or use the `be` / `le` prefixes on the affected fields.

> 💡 **Debugging tip**: The `std::print()` function (imported via `#include <std/io.pat>`) lets you display values in ImHex's output console during pattern evaluation. It is the equivalent of a debug `printf`:  
> ```cpp  
> #include <std/io.pat>  
> u32 count @ 0x08;  
> std::print("count = {}", count);  
> ```

---

## Summary

The `.hexpat` language is a simplified C specialized for binary parsing. Its primitive types (`u8`–`u128`, `float`, `double`, `char`, `bool`) cover every data type found in binary files. Structures, enumerations, arrays, unions, and conditionals let you describe formats ranging from the simplest to the most elaborate. The `@` operator places variables at absolute offsets, the `[[...]]` attributes control display, and pointers follow cross-references. With these foundations, you are ready to write the complete ELF pattern of section 6.4 — an exercise that will put into practice all the concepts of this section on a format you already know.

---


⏭️ [Writing a pattern to visualize an ELF header from scratch](/06-imhex/04-elf-header-pattern.md)
