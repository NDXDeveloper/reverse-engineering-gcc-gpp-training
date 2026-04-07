🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Appendix E — ImHex Cheat Sheet: `.hexpat` Reference Syntax

> 📎 **Reference card** — This appendix documents the syntax of the `.hexpat` pattern language specific to ImHex. This language allows you to describe the structure of a binary file so that ImHex can visualize it with colors, annotations, and hierarchical decomposition. It covers types, structures, attributes, control flow, built-in functions, and common idioms for RE of ELF binaries and custom formats.

---

## What is a `.hexpat` file?

A `.hexpat` file (*hex pattern*) is a script written in ImHex's pattern language. It describes how to interpret a sequence of raw bytes as typed and named data structures. When you load a `.hexpat` into ImHex, the software automatically colors the corresponding regions in the hex view and displays the field tree in the *Pattern Data* panel.

The language deliberately resembles C, with specific extensions for binary manipulation. If you know how to write a `struct` in C, you already know how to write most of a `.hexpat`.

The typical workflow is iterative: you write a minimal pattern, observe the result in ImHex, refine the types and sizes, and repeat until you have mapped the entire format. This is exactly the process described in Chapters 6 and 25.

---

## 1 — Base Types

### 1.1 — Integer Types

| `.hexpat` Type | Size | C Equivalent | Signed? |  
|----------------|------|--------------|---------|  
| `u8` | 1 byte | `uint8_t` | No |  
| `u16` | 2 bytes | `uint16_t` | No |  
| `u32` | 4 bytes | `uint32_t` | No |  
| `u64` | 8 bytes | `uint64_t` | No |  
| `u128` | 16 bytes | `__uint128_t` | No |  
| `s8` | 1 byte | `int8_t` | Yes |  
| `s16` | 2 bytes | `int16_t` | Yes |  
| `s32` | 4 bytes | `int32_t` | Yes |  
| `s64` | 8 bytes | `int64_t` | Yes |  
| `s128` | 16 bytes | `__int128_t` | Yes |

### 1.2 — Floating-Point Types

| `.hexpat` Type | Size | C Equivalent |  
|----------------|------|--------------|  
| `float` | 4 bytes | `float` (IEEE 754 single precision) |  
| `double` | 8 bytes | `double` (IEEE 754 double precision) |

### 1.3 — Character and Boolean Types

| `.hexpat` Type | Size | Description |  
|----------------|------|-------------|  
| `char` | 1 byte | ASCII character (displayed as a character in the panel) |  
| `char16` | 2 bytes | UTF-16 character |  
| `bool` | 1 byte | Boolean (0 = false, non-zero = true) |

### 1.4 — Special `padding` Type

| `.hexpat` Type | Description |  
|----------------|-------------|  
| `padding[N]` | Advances by N bytes without displaying them in the Pattern Data panel |

`padding` is extremely useful for skipping filler bytes (alignment padding) in structures without cluttering the tree with meaningless fields.

---

## 2 — Endianness

By default, ImHex interprets multi-byte values in **little-endian** (the native byte order of x86). You can change the endianness globally or locally.

### 2.1 — Global Endianness

```cpp
#pragma endian little    // Default — little-endian for the entire file
#pragma endian big       // Big-endian for the entire file
```

### 2.2 — Local Endianness (per type)

```cpp
le u32 magic;            // Explicit little-endian  
be u32 network_field;    // Explicit big-endian  
```

The `le` and `be` prefixes apply to a single declaration and take precedence over the global `#pragma`. This is essential for formats that mix both byte orders (network protocols with big-endian headers and little-endian payloads, for example).

---

## 3 — Variables and Placement

### 3.1 — Variable Declaration

Variables in a `.hexpat` are **placed in the file** at the current read cursor position. Each declaration automatically advances the cursor by the size of the type.

```cpp
u32 magic;          // Reads 4 bytes at the current position, advances by 4  
u16 version;        // Reads 2 bytes at the new position, advances by 2  
u8  flags;          // Reads 1 byte, advances by 1  
```

### 3.2 — Explicit Placement with `@`

The `@` operator places a variable at an absolute address in the file without modifying the current cursor position for subsequent declarations:

```cpp
u32 magic @ 0x00;           // Reads 4 bytes at offset 0x00  
u16 version @ 0x04;         // Reads 2 bytes at offset 0x04  
u32 data_offset @ 0x08;     // Reads 4 bytes at offset 0x08  
```

### 3.3 — Current Position: `$`

The special variable `$` represents the current read cursor position in the file. It is very useful for offset calculations and assertions:

```cpp
u32 header_start = $;       // Saves the current position
// ... declarations ...
u32 header_size = $ - header_start;  // Computes the size read
```

### 3.4 — Relative Placement with `addressof`

The built-in function `addressof(variable)` returns the start address of a previously declared variable:

```cpp
u32 data_offset;  
u8  data[16] @ addressof(data_offset) + data_offset;  
// Places the 'data' array at the computed address
```

---

## 4 — Arrays

### 4.1 — Fixed-Size Arrays

```cpp
u8  raw_bytes[16];           // 16 raw bytes  
u32 table[8];                // 8 dwords (32 bytes total)  
char signature[4];           // 4 ASCII characters (e.g.: "ELF\x7f")  
```

### 4.2 — Variable-Size Arrays (runtime)

The size of an array can be an expression computed from previously read fields:

```cpp
u32 count;  
u32 entries[count];          // 'count' entries of 4 bytes each  
```

```cpp
u16 name_length;  
char name[name_length];      // Variable-length string  
```

### 4.3 — Unlimited-Size Arrays with Sentinel

The `while` operator allows reading elements until a condition is met. This is useful for lists terminated by a marker (sentinel value):

```cpp
// Reads u32 values until encountering the value 0
u32 entries[while(std::mem::read_unsigned($, 4) != 0x00)];
```

### 4.4 — C String Arrays (null-terminated)

For null-terminated strings, use the `str` type provided by the standard library:

```cpp
#include <std/string.pat>

std::string::NullString null_terminated_string @ 0x100;
```

Or, more simply with the built-in `char[]` type and a null terminator:

```cpp
char my_string[] @ 0x100;   // Reads until the first \0
```

When a `char` array is declared without an explicit size, ImHex reads it until the first null byte encountered.

---

## 5 — Structures (`struct`)

Structures are the heart of the `.hexpat` language. They group sequential fields into a named logical unit, exactly like in C.

### 5.1 — Basic Declaration

```cpp
struct FileHeader {
    char     magic[4];       // 4 bytes: format signature
    u16      version;        // 2 bytes: version number
    u16      flags;          // 2 bytes: flags
    u32      entry_count;    // 4 bytes: number of entries
    u32      data_offset;    // 4 bytes: offset to data
};

FileHeader header @ 0x00;   // Instantiates the structure at offset 0
```

### 5.2 — Nested Structures

```cpp
struct Vec2 {
    float x;
    float y;
};

struct Entity {
    u32   id;
    Vec2  position;
    Vec2  velocity;
    u8    type;
};

Entity entities[10] @ 0x100;  // 10 consecutive entities
```

### 5.3 — Structures with Dynamic Size

A structure's fields can depend on values previously read within the same structure:

```cpp
struct Chunk {
    u32  chunk_type;
    u32  chunk_size;
    u8   data[chunk_size];    // Size read dynamically
    u32  checksum;
};
```

### 5.4 — Structures with Inheritance

The language supports simple inheritance, similar to C++:

```cpp
struct Base {
    u32 type;
    u32 size;
};

struct ExtendedHeader : Base {
    u16 flags;
    u16 version;
    // The type and size fields from Base are included at the beginning
};
```

---

## 6 — Unions (`union`)

A union overlays multiple interpretations at the same memory location. All fields of a union start at the same address.

```cpp
union Value {
    u32   as_uint;
    s32   as_int;
    float as_float;
    u8    as_bytes[4];
};

Value val @ 0x100;
// The same 4 bytes are visible under 4 different interpretations
```

Unions are particularly useful for fields whose interpretation depends on a discriminant type read elsewhere:

```cpp
struct TaggedValue {
    u8 type;
    union {
        u32   integer_val;
        float float_val;
        char  string_val[4];
    } value;
};
```

---

## 7 — Enumerations (`enum`)

### 7.1 — Basic Syntax

```cpp
enum FileType : u16 {
    EXECUTABLE = 0x0001,
    SHARED_LIB = 0x0002,
    OBJECT     = 0x0003,
    CORE_DUMP  = 0x0004
};

FileType type @ 0x10;   // Displayed by name if the value matches
```

The underlying type (here `u16`) determines the size in bytes of the enumeration. ImHex displays the symbolic name if the value matches one of the members; otherwise, the raw value is displayed.

### 7.2 — Use in Conditions

Enum values can be used in conditional expressions (`if`, `match`) to drive the parsing:

```cpp
enum SectionType : u32 {
    TEXT   = 0x01,
    DATA   = 0x02,
    BSS    = 0x03,
    CUSTOM = 0xFF
};

struct Section {
    SectionType type;
    u32 size;

    if (type == SectionType::TEXT || type == SectionType::DATA) {
        u8 content[size];
    } else if (type == SectionType::BSS) {
        padding[size];        // BSS has no content in the file
    }
};
```

---

## 8 — Bitfields

Bitfields allow decomposing an integer into individual bit fields, which is essential for parsing flags, control registers, and packed fields.

### 8.1 — Syntax

```cpp
bitfield ElfFlags {
    executable : 1;
    writable   : 1;
    readable   : 1;
    reserved   : 29;
};

ElfFlags flags @ 0x20;
```

Each field specifies its number of bits. The sum of bits must match the size of the underlying type (here implicitly 32 bits, since 1+1+1+29 = 32).

### 8.2 — Bitfields in Structures

```cpp
bitfield TcpFlags {
    fin : 1;
    syn : 1;
    rst : 1;
    psh : 1;
    ack : 1;
    urg : 1;
    ece : 1;
    cwr : 1;
};

struct TcpHeader {
    be u16     src_port;
    be u16     dst_port;
    be u32     seq_number;
    be u32     ack_number;
    u8         data_offset_reserved;
    TcpFlags   flags;
    be u16     window_size;
    be u16     checksum;
    be u16     urgent_pointer;
};
```

### 8.3 — Padding in Bitfields

Use `padding` to skip reserved bits without giving them a name:

```cpp
bitfield StatusRegister {
    carry     : 1;
    zero      : 1;
    sign      : 1;
    overflow  : 1;
    padding   : 4;       // 4 reserved bits, ignored in the display
};
```

---

## 9 — Conditional Control Flow

### 9.1 — `if` / `else`

Conditional control flow inside a structure allows parsing differently based on read values:

```cpp
struct Record {
    u8 type;
    u32 size;

    if (type == 0x01) {
        u32 integer_data;
    } else if (type == 0x02) {
        float float_data;
    } else if (type == 0x03) {
        char string_data[size];
    } else {
        u8 raw_data[size];
    }
};
```

### 9.2 — `match` (pattern matching)

The `match` statement is a more readable alternative to a chain of `if`/`else` when comparing a single value:

```cpp
struct Packet {
    u8 opcode;
    u16 length;

    match (opcode) {
        (0x01): u8 payload_a[length];
        (0x02): u16 payload_b[length / 2];
        (0x03): {
            u32 sub_type;
            u8  payload_c[length - 4];
        }
        (_): u8 unknown_payload[length];   // _ = default case
    }
};
```

### 9.3 — Loops

The language supports `for` and `while` loops inside structures for parsing repetitive sequences whose structure is not a simple homogeneous array:

```cpp
struct FileFormat {
    u32 magic;
    u32 num_chunks;

    // For loop to parse N variable-size chunks
    for (u32 i = 0, i < num_chunks, i = i + 1) {
        Chunk chunk;
    }
};
```

> ⚠️ **Watch the syntax**: `for` loops in `.hexpat` use **commas** (`,`) as separators between the initialization, condition, and increment clauses, not semicolons (`;`) as in C.

```cpp
struct NullTerminatedList {
    // While loop to read until a marker
    u32 entry;
    while (entry != 0x00000000) {
        u32 entry;
    }
};
```

---

## 10 — Custom Functions

### 10.1 — Syntax

```cpp
fn calculate_checksum(u32 offset, u32 size) {
    u32 sum = 0;
    for (u32 i = 0, i < size, i = i + 1) {
        sum = sum + std::mem::read_unsigned(offset + i, 1);
    }
    return sum & 0xFF;
};
```

Functions can return a value and accept typed parameters. They are useful for factoring out calculations reused in multiple structures (checksums, relative offsets, decodings).

### 10.2 — Functions in Assertions and Attributes

```cpp
fn is_valid_magic(u32 value) {
    return value == 0x7F454C46;  // "\x7fELF"
};

struct ElfHeader {
    u32 magic;
    std::assert(is_valid_magic(magic), "Invalid magic: this is not an ELF");
    // ... rest of the header
};
```

---

## 11 — Attributes

Attributes modify the display or parsing behavior of a variable. They are placed after the declaration, within double brackets `[[...]]`.

### 11.1 — Display Attributes

| Attribute | Description | Example |  
|-----------|-------------|---------|  
| `[[color("RRGGBB")]]` | Custom color for the field in the hex view | `u32 magic [[color("FF0000")]];` |  
| `[[name("label")]]` | Alternative display name (replaces the variable name) | `u32 e_type [[name("ELF Type")]];` |  
| `[[comment("text")]]` | Adds a comment displayed in the Pattern Data panel | `u16 version [[comment("Must be 2")]];` |  
| `[[format("fmt")]]` | Custom display format for the value | `u32 addr [[format("0x{:08X}")]];` |  
| `[[hidden]]` | Hides the field in the Pattern Data panel (but still reads it) | `u8 reserved[4] [[hidden]];` |  
| `[[sealed]]` | Prevents unfolding of sub-fields (structure displayed on a single line) | `Vec2 pos [[sealed]];` |  
| `[[single_color]]` | Applies a single color to the entire structure (no alternating colors) | `struct Block { ... } [[single_color]];` |  
| `[[highlight_hidden]]` | Colors the field in the hex view even if it is `[[hidden]]` | `padding[4] [[highlight_hidden]];` |  
| `[[inline]]` | Displays the sub-structure's fields at the same level as the parent | `Vec2 pos [[inline]];` |

### 11.2 — Transformation Attributes

| Attribute | Description | Example |  
|-----------|-------------|---------|  
| `[[transform("fn")]]` | Applies a transformation function to the displayed value | See below |  
| `[[pointer_base("fn")]]` | Defines the base for pointer fields (base address) | `u32 offset [[pointer_base("base_addr")]];` |

The `[[transform]]` attribute is powerful for displaying a decoded value without modifying the underlying data:

```cpp
fn decode_xor(u8 value) {
    return value ^ 0xAA;
};

u8 encoded_byte [[transform("decode_xor")]];
// The hex view shows the raw byte, the Pattern Data panel shows the decoded value
```

### 11.3 — Parsing Control Attributes

| Attribute | Description | Example |  
|-----------|-------------|---------|  
| `[[static]]` | The field is evaluated at compile time (constant) | `u32 MAGIC = 0x7F454C46 [[static]];` |  
| `[[no_unique_address]]` | The field does not advance the cursor (overlaps the previous one) | `u32 alt_view [[no_unique_address]];` |

### 11.4 — Combining Attributes

Multiple attributes can be combined on a single field, separated by commas:

```cpp
u32 magic [[color("FF6600"), name("Magic Number"), comment("0x7F454C46 = ELF")]];
```

---

## 12 — Preprocessor Directives

| Directive | Description | Example |  
|-----------|-------------|---------|  
| `#include <file>` | Includes a standard library file | `#include <std/mem.pat>` |  
| `#include "file.hexpat"` | Includes a local file | `#include "my_types.hexpat"` |  
| `#define NAME value` | Defines a preprocessor constant | `#define HEADER_SIZE 64` |  
| `#pragma endian big` | Sets the global endianness | `#pragma endian big` |  
| `#pragma base_address 0x400000` | Sets the base address for offsets | `#pragma base_address 0x400000` |  
| `#pragma pattern_limit N` | Increases the pattern limit (default: 2 million) | `#pragma pattern_limit 5000000` |  
| `#pragma array_limit N` | Increases the array size limit | `#pragma array_limit 100000` |

> 💡 If ImHex displays a "pattern limit reached" error on a large file, increase `#pragma pattern_limit`. The default of 2 million patterns is sufficient for most formats, but ELF files with large symbol tables may exceed this limit.

---

## 13 — Standard Library (`std::`)

ImHex provides a standard library of functions and types accessible via `#include`. Here are the most useful modules for RE.

### 13.1 — `std::mem` — Memory Access

```cpp
#include <std/mem.pat>
```

| Function | Description |  
|----------|-------------|  
| `std::mem::read_unsigned(offset, size)` | Reads an unsigned integer of `size` bytes at `offset` |  
| `std::mem::read_signed(offset, size)` | Reads a signed integer |  
| `std::mem::read_string(offset, length)` | Reads a string of `length` bytes |  
| `std::mem::find_sequence(offset, bytes...)` | Searches for a byte sequence starting from `offset` |  
| `std::mem::find_string(offset, string)` | Searches for a string starting from `offset` |  
| `std::mem::size()` | Total size of the loaded file |  
| `std::mem::base_address()` | Base address of the file |

### 13.2 — `std::string` — String Types

```cpp
#include <std/string.pat>
```

| Type | Description |  
|------|-------------|  
| `std::string::NullString` | Null-terminated C string (variable size) |  
| `std::string::SizedString<N>` | Fixed-size string of N bytes |

### 13.3 — `std::assert` — Assertions and Validation

```cpp
#include <std/core.pat>
```

| Function | Description |  
|----------|-------------|  
| `std::assert(condition, message)` | Stops parsing with an error message if the condition is false |  
| `std::assert_warn(condition, message)` | Displays a warning without stopping parsing |  
| `std::print("format", args...)` | Prints a message in the ImHex console |

Usage example:

```cpp
struct ElfHeader {
    u32 magic;
    std::assert(magic == 0x464C457F,
        "Invalid magic number: expected 0x7F454C46 (ELF)");

    u8 class;
    std::assert(class == 1 || class == 2,
        "Invalid ELF class: expected 1 (32-bit) or 2 (64-bit)");

    // If we reach here, the assertions passed
    u8 data;
    u8 version;
    u8 os_abi;
};
```

### 13.4 — `std::math` — Mathematical Functions

```cpp
#include <std/math.pat>
```

| Function | Description |  
|----------|-------------|  
| `std::math::min(a, b)` | Minimum of two values |  
| `std::math::max(a, b)` | Maximum of two values |  
| `std::math::abs(x)` | Absolute value |  
| `std::math::ceil(x)` | Round up |  
| `std::math::floor(x)` | Round down |  
| `std::math::log2(x)` | Base-2 logarithm |

### 13.5 — `type::` — Extended Types

```cpp
#include <type/magic.pat>
#include <type/guid.pat>
#include <type/ip.pat>
#include <type/time.pat>
```

| Type | Description |  
|------|-------------|  
| `type::Magic<"ELF">` | Automatically verifies that the bytes match the expected string |  
| `type::GUID` | Parses and displays a GUID/UUID (16 bytes) |  
| `type::IP4Address` | IPv4 address (4 bytes, displayed in dotted notation) |  
| `type::IP6Address` | IPv6 address (16 bytes) |  
| `type::time32_t` | 32-bit Unix timestamp (displayed as a readable date) |  
| `type::time64_t` | 64-bit Unix timestamp |

---

## 14 — Operators

### 14.1 — Arithmetic and Logical Operators

| Operator | Description |  
|----------|-------------|  
| `+`, `-`, `*`, `/`, `%` | Arithmetic |  
| `&`, `\|`, `^`, `~` | Bitwise AND, OR, XOR, NOT |  
| `<<`, `>>` | Bitwise shifts |  
| `&&`, `\|\|`, `!` | Logical AND, OR, NOT |  
| `==`, `!=`, `<`, `>`, `<=`, `>=` | Comparisons |

### 14.2 — `.hexpat`-Specific Operators

| Operator | Description | Example |  
|----------|-------------|---------|  
| `@` | Placement at an address | `u32 x @ 0x100;` |  
| `$` | Current cursor position | `u32 here = $;` |  
| `addressof(var)` | Start address of a variable | `addressof(header)` |  
| `sizeof(type_or_var)` | Size in bytes of a type or variable | `sizeof(u32)` → 4 |  
| `parent` | Reference to the enclosing parent structure | `parent.size` |

---

## 15 — Namespaces

Namespaces allow organizing types and avoiding name collisions in large patterns:

```cpp
namespace elf {
    enum Class : u8 {
        ELFCLASS32 = 1,
        ELFCLASS64 = 2
    };

    struct Ident {
        char     magic[4];
        Class    class;
        u8       data;
        u8       version;
        u8       os_abi;
        padding[8];
    };
};

namespace custom_format {
    struct Header {
        u32 magic;
        u16 version;
    };
};

elf::Ident elf_ident @ 0x00;  
custom_format::Header custom_header @ 0x200;  
```

---

## 16 — Common Patterns for RE

### 16.1 — Parsing a 64-bit ELF Header

```cpp
#include <std/core.pat>

enum ElfClass : u8 {
    ELFCLASS32 = 1,
    ELFCLASS64 = 2
};

enum ElfData : u8 {
    ELFDATA2LSB = 1,  // Little-endian
    ELFDATA2MSB = 2   // Big-endian
};

enum ElfType : u16 {
    ET_NONE   = 0,
    ET_REL    = 1,
    ET_EXEC   = 2,
    ET_DYN    = 3,
    ET_CORE   = 4
};

enum ElfMachine : u16 {
    EM_386     = 3,
    EM_ARM     = 40,
    EM_X86_64  = 62,
    EM_AARCH64 = 183
};

struct ElfIdent {
    char       magic[4]    [[comment("Must be 0x7F 'E' 'L' 'F'")]];
    ElfClass   class;
    ElfData    data;
    u8         version;
    u8         os_abi;
    padding[8]             [[comment("Padding EI_ABIVERSION + reserved")]];
};

struct Elf64Header {
    ElfIdent    ident       [[color("FF6600")]];
    ElfType     type        [[color("0066FF")]];
    ElfMachine  machine;
    u32         version;
    u64         entry       [[comment("Entry point"), format("0x{:016X}")]];
    u64         ph_offset   [[comment("Program Header Table offset")]];
    u64         sh_offset   [[comment("Section Header Table offset")]];
    u32         flags;
    u16         eh_size     [[comment("Size of this header")]];
    u16         ph_entry_size;
    u16         ph_num      [[comment("Number of program headers")]];
    u16         sh_entry_size;
    u16         sh_num      [[comment("Number of section headers")]];
    u16         sh_strndx   [[comment("Index of the .shstrtab section")]];
};

Elf64Header elf_header @ 0x00;
```

### 16.2 — Parsing a Custom Network Protocol (TLV)

The TLV (*Type-Length-Value*) pattern is an extremely common idiom in binary protocols:

```cpp
#pragma endian big     // Network protocols are often big-endian

enum MessageType : u8 {
    HANDSHAKE  = 0x01,
    AUTH       = 0x02,
    DATA       = 0x03,
    HEARTBEAT  = 0x04,
    DISCONNECT = 0xFF
};

struct TLVMessage {
    MessageType type    [[color("FF0000")]];
    be u16      length  [[color("00FF00")]];

    match (type) {
        (MessageType::HANDSHAKE): {
            u8  protocol_version;
            u32 client_id;
        }
        (MessageType::AUTH): {
            u8   username_len;
            char username[username_len];
            u8   token[32];
        }
        (MessageType::DATA): {
            u8 payload[length];
        }
        (MessageType::HEARTBEAT): {
            u32 timestamp;
            u32 seq_number;
        }
        (_): {
            u8 raw[length];
        }
    }
};

// Parse the entire file as a sequence of TLV messages
TLVMessage messages[while($ < std::mem::size())] @ 0x00;
```

### 16.3 — Format with Offset Table (indirect)

Many binary formats use an offset table in the header that points to the actual data:

```cpp
struct EntryHeader {
    u32 name_offset;
    u32 data_offset;
    u32 data_size;
    u16 type;
    u16 flags;
};

struct FileFormat {
    char magic[8]        [[comment("Format signature")]];
    u32  version;
    u32  entry_count;
    u32  string_table_offset;

    // Entry table (sequential after the header)
    EntryHeader entries[entry_count];

    // The data pointed to by offsets are NOT sequential
    // They are accessed via @ placement
};

FileFormat file_header @ 0x00;

// Accessing the data of a specific entry:
// u8 first_entry_data[file_header.entries[0].data_size]
//     @ file_header.entries[0].data_offset;
```

### 16.4 — Simple XOR Decoding

```cpp
fn xor_decode(u8 value) {
    return value ^ 0x37;
};

struct ObfuscatedString {
    u8 length;
    u8 data[length] [[transform("xor_decode"),
                       comment("XOR 0x37 to decode")]];
};

ObfuscatedString secret @ 0x200;
```

### 16.5 — Crypto Magic Constants (partial AES S-box)

```cpp
// Check for the presence of the AES S-box in a binary
// The first 16 bytes of the AES S-box are:
// 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76

fn check_aes_sbox(u32 offset) {
    return std::mem::read_unsigned(offset, 1) == 0x63 &&
           std::mem::read_unsigned(offset + 1, 1) == 0x7C &&
           std::mem::read_unsigned(offset + 2, 1) == 0x77 &&
           std::mem::read_unsigned(offset + 3, 1) == 0x7B;
};

// If you know the offset of the S-box:
u8 aes_sbox[256] @ 0x402000 [[color("FF00FF"), comment("AES S-box")]];
```

---

## 17 — Debugging a `.hexpat` Pattern

When a pattern does not work as expected, here are the most useful debugging techniques.

**Use `std::print`** to display intermediate values in the ImHex console:

```cpp
#include <std/io.pat>

struct Debug {
    u32 magic;
    std::print("Magic read: 0x{:08X} at offset {}", magic, $ - 4);

    u32 size;
    std::print("Size: {} bytes", size);
};
```

**Check the cursor position** with `$` at each critical step:

```cpp
struct MyStruct {
    u32 field_a;
    std::print("Position after field_a: 0x{:X}", $);
    u16 field_b;
    std::print("Position after field_b: 0x{:X}", $);
};
```

**Use `std::assert`** to validate invariants as you go:

```cpp
struct Chunk {
    u32 size;
    std::assert(size < 0x10000000, "Suspicious chunk size (> 256 MB)");
    std::assert($ + size <= std::mem::size(), "Chunk exceeds end of file");
    u8 data[size];
};
```

**Start minimal**: first parse only the header with basic types, verify that the values are consistent, then add secondary structures one by one. Never try to parse a complete format on the first attempt.

**Check the Console panel** in ImHex (View → Console): parsing errors and `std::print` messages are displayed there.

---

## 18 — Quick Reference: Condensed Syntax

```
╔══════════════════════════════════════════════════════════════════╗
║                   .HEXPAT — QUICK SYNTAX                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  BASE TYPES                                                      ║
║  u8 u16 u32 u64 u128    s8 s16 s32 s64 s128                      ║
║  float double   char char16   bool   padding[N]                  ║
║                                                                  ║
║  ENDIANNESS                                                      ║
║  #pragma endian big/little   |   be u32 x;   le u16 y;           ║
║                                                                  ║
║  PLACEMENT                                                       ║
║  Type name @ 0xADDR;        $ = current position                 ║
║  addressof(var)              sizeof(type)                        ║
║                                                                  ║
║  STRUCTURE           UNION              ENUM                     ║
║  struct S {          union U {          enum E : u16 {           ║
║    u32 a;              u32 as_int;        A = 0x01,              ║
║    u16 b;              float as_f;        B = 0x02               ║
║  };                  };                 };                       ║
║                                                                  ║
║  BITFIELD                                                        ║
║  bitfield Flags {                                                ║
║    read : 1;  write : 1;  exec : 1;  padding : 5;                ║
║  };                                                              ║
║                                                                  ║
║  ARRAYS                                                          ║
║  u8 data[16];             // fixed size                          ║
║  u8 data[count];          // variable size                       ║
║  char str[];              // null-terminated                     ║
║  T arr[while(cond)];      // sentinel                            ║
║                                                                  ║
║  CONTROL FLOW (in struct)                                        ║
║  if (expr) { ... } else { ... }                                  ║
║  match (val) { (0x01): ...; (_): ...; }                          ║
║  for (init, cond, incr) { ... }    ← commas, not ;               ║
║                                                                  ║
║  ATTRIBUTES                                                      ║
║  [[color("RRGGBB")]]    [[name("label")]]    [[hidden]]          ║
║  [[comment("text")]]    [[transform("fn")]]  [[sealed]]          ║
║  [[format("0x{:X}")]]   [[inline]]           [[no_unique_addr]]  ║
║                                                                  ║
║  STANDARD LIBRARY                                                ║
║  #include <std/mem.pat>     std::mem::read_unsigned(off, sz)     ║
║  #include <std/core.pat>    std::assert(cond, msg)               ║
║  #include <std/io.pat>      std::print("fmt", args)              ║
║  #include <std/string.pat>  std::string::NullString              ║
║                                                                  ║
║  PRAGMAS                                                         ║
║  #pragma endian big/little                                       ║
║  #pragma base_address 0x400000                                   ║
║  #pragma pattern_limit 5000000                                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

---

> 📚 **Further reading**:  
> - **Chapter 6** — [ImHex: Advanced Hexadecimal Analysis](/06-imhex/README.md) — progressive pedagogical coverage of ImHex and the `.hexpat` language.  
> - **Chapter 25** — [Reversing a Custom File Format](/25-fileformat/README.md) — complete practical case study of mapping an unknown format with `.hexpat`.  
> - **Appendix F** — [ELF Section Table and Their Roles](/appendices/appendix-f-elf-sections.md) — complementary reference for writing ELF patterns.  
> - **Appendix J** — [Common Crypto Magic Constants](/appendices/appendix-j-crypto-constants.md) — byte sequences to search for with ImHex in a crypto binary.  
> - **ImHex Documentation** — [https://docs.werwolv.net/pattern-language/](https://docs.werwolv.net/pattern-language/) — complete official reference for the pattern language.  
> - **Community Patterns Repository** — [https://github.com/WerWolv/ImHex-Patterns](https://github.com/WerWolv/ImHex-Patterns) — collection of ready-to-use `.hexpat` files for many formats.

⏭️ [ELF Section Table and Their Roles](/appendices/appendix-f-elf-sections.md)
