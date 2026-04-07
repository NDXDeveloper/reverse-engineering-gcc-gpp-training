🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.6 — Reconstructing data structures (`struct`, `class`, `enum`)

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## The central challenge of reverse engineering

When a compiler produces machine code, the source code's data structures — `struct`, `class`, `enum`, `union` — cease to exist as named entities. They are reduced to **memory-access patterns**: reads and writes at constant offsets relative to a base pointer. The compiler knows that a `player->health` translates to an access at `[rdi + 0x0c]`, but this semantic information ("it's a player's health field") is lost in the binary.

Reconstructing these structures from disassembled code is one of the most demanding and gratifying tasks of reverse engineering. It's deduction work: you observe access patterns in the code, collect clues (sizes, alignments, inferred types, usage context), and progressively reconstruct the original structure — or at least a functionally equivalent one.

Ghidra provides a set of powerful tools to facilitate this work. This section shows you how to use them methodically.

---

## Recognizing that a structure exists

Before reconstructing a structure, you first have to detect its presence. Here are the characteristic patterns in the Decompiler's pseudo-code that betray the existence of an underlying structure.

### Accesses at multiple offsets from the same pointer

It's the most common signal. When the Decompiler shows expressions like:

```c
*(int *)(param_1 + 0)
*(int *)(param_1 + 4)
*(char **)(param_1 + 8)
*(long *)(param_1 + 0x10)
*(undefined4 *)(param_1 + 0x18)
```

The `param_1` parameter is a pointer to a structure whose fields are at offsets 0x00, 0x04, 0x08, 0x10, and 0x18. Each dereference with a distinct type and offset corresponds to a different field.

### Allocation followed by sequential initializations

When a function calls `malloc` (or `operator new`) with a constant size, then writes at successive offsets of the returned pointer, it's a constructor initializing a structure's fields:

```c
void * pvVar1 = malloc(0x20);       // allocation of 32 bytes
*(int *)pvVar1 = 1;                  // offset 0x00: an integer
*(int *)((long)pvVar1 + 4) = 100;    // offset 0x04: an integer
*(char **)((long)pvVar1 + 8) = "default";  // offset 0x08: a pointer
*(long *)((long)pvVar1 + 0x10) = 0;  // offset 0x10: a long
```

The size passed to `malloc` (here 0x20 = 32 bytes) gives you the **total size** of the structure. The initializations give you the offsets, types, and default values of each field.

### Passed as first argument to multiple functions

In C++, the `this` pointer is passed as the first argument (`rdi` register in System V AMD64 convention). If you observe that the same pointer is passed as `param_1` to multiple different functions that all access offsets of this pointer, these functions are probably methods of the same class, and the pointer is a `this`.

### Arrays of structures

An access pattern like:

```c
*(int *)(base + i * 0x18)
*(int *)(base + i * 0x18 + 4)
*(long *)(base + i * 0x18 + 8)
```

reveals an array of structures of size 0x18 (24 bytes), where `i` is the index. The constant multiplier corresponds to the structure's `sizeof`, and the small added offsets correspond to individual fields.

---

## Ghidra's structure editor

### Accessing the editor

To create a new structure:

1. Open the **Data Type Manager** (**Window → Data Type Manager**).  
2. In the tree, locate the category bearing your program's name (for example `ch08-oop_O0`).  
3. Right-click on this category → **New → Structure**.  
4. Name the structure (for example `player_t`, `packet_header_t`, `config_entry`).  
5. The **structure editor** opens.

### Editor interface

The structure editor is a dedicated window that presents fields in tabular form:

| Column | Role |  
|---|---|  
| **Offset** | Position of the field in bytes from the start of the structure |  
| **Length** | Size of the field in bytes |  
| **DataType** | Type of the field (`int`, `char *`, `float`, another structure, etc.) |  
| **Name** | Name of the field |  
| **Comment** | Optional comment |

The structure is initially empty, with a size of 0. You can build it in two ways.

### Field-by-field construction (manual method)

This is the most controlled method. You add fields one by one based on the accesses observed in the Decompiler:

1. Click on the first empty row of the table.  
2. In the **DataType** column, type the first field's type (for example `int`).  
3. In the **Name** column, name the field (for example `id`).  
4. Move to the next row for the next field.

The editor automatically handles offsets and the total size of the structure. If you need to insert a field at a precise offset that leaves a hole between two existing fields, Ghidra automatically inserts padding bytes (`undefined1`) to fill the space.

**Padding and alignment handling** — GCC aligns fields according to the target platform's rules. On x86-64, an `int` (4 bytes) is aligned on a 4-byte boundary, a `long` or pointer (8 bytes) on an 8-byte boundary. That means "holes" (padding) sometimes appear between fields. For example:

```c
struct example {
    char  a;        // offset 0x00, 1 byte
    // 3 bytes of implicit padding
    int   b;        // offset 0x04, 4 bytes
    char  c;        // offset 0x08, 1 byte
    // 7 bytes of implicit padding
    long  d;        // offset 0x10, 8 bytes
};  // sizeof = 0x18 (24 bytes)
```

In Ghidra, you model these holes by leaving `undefined1` bytes between named fields, or by explicitly representing them as a `byte[3] padding_1` field. In practice, it's cleaner to let Ghidra handle padding automatically — bytes not assigned between two fields are displayed in gray.

### Construction by total size (skeleton method)

If you know the total size of the structure (via the `malloc` or `operator new` argument), you can start by defining it:

1. In the structure editor, change the size at the bottom of the window (**Size** field) to the observed value.  
2. The structure is filled with `undefined1` bytes.  
3. Click on the offset of a field you've identified and change its type.

This approach is useful when you only know a few fields of a large structure: you lay out the skeleton of the right size, fill in the known fields, and leave unknown zones as `undefined` to complete later.

### Nested structures

Structures can contain other structures — as an inline field (not a pointer). For example, a `game_state_t` structure could contain a `player_t` field directly included at a certain offset. In the editor, you simply type the name of the nested structure in the **DataType** column: Ghidra recognizes it if it exists in the Data Type Manager.

Similarly, a field can be a **pointer to a structure**: type `player_t *` for a pointer to `player_t`. This distinction matters: an inline field occupies `sizeof(player_t)` bytes in the parent structure, while a pointer always occupies 8 bytes (on x86-64).

### Arrays in structures

For a field that is an array, use bracket notation: `char[32]` for a 32-character buffer, `int[10]` for an array of 10 integers. Ghidra automatically computes the resulting size.

---

## Auto Create Structure: the assisted method

Ghidra offers a semi-automatic feature that considerably speeds up structure reconstruction by analyzing access patterns in the code.

### How to use it

1. In the Decompiler, identify a parameter or variable that is visibly a pointer to a structure (you see accesses to `param_1 + offset`).  
2. Right-click on this parameter → **Auto Create Structure**.  
3. Ghidra analyzes all accesses to this pointer in the current function, deduces the offsets and types of each field, creates a structure in the Data Type Manager, and automatically applies it to the parameter.

### Typical result

The pseudo-code goes from:

```c
undefined8 FUN_004012a0(long param_1)
{
    if (*(int *)(param_1 + 0xc) < 100) {
        *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + *(int *)(param_1 + 0x10);
    }
    puts(*(char **)(param_1 + 0x18));
    return 0;
}
```

to:

```c
undefined8 FUN_004012a0(astruct * param_1)
{
    if (param_1->field_0xc < 100) {
        param_1->field_0xc = param_1->field_0xc + param_1->field_0x10;
    }
    puts(param_1->field_0x18);
    return 0;
}
```

### Limits of Auto Create Structure

The tool has limits you must know:

**Scope limited to a single function** — Auto-creation only analyzes the current function. If the structure is used in 10 different functions and each function accesses different fields, auto-creation in a single function will only see a subset of fields. You'll have to complete the structure manually by examining the other functions.

**Generic names** — Fields are named `field_0xNN` (where NN is the hex offset). You'll have to manually rename them to semantic names.

**Sometimes imprecise types** — The inferred type is based on the size and usage context in the function. A field accessed as `*(int *)(ptr + 0x4)` will be typed `int`, which is often correct. But a field only accessed by an 8-byte `MOV` could be a `long`, `double`, pointer, or another type of the same size — the tool can't always distinguish.

**Doesn't detect arrays** — If a field is actually an inline array (for example `char name[64]`), auto-creation may fragment it into multiple small-sized fields or treat it as a single blob.

### Recommended strategy

The best approach combines auto-creation and manual work:

1. Launch Auto Create Structure on the function that accesses the most fields — often the constructor or an initialization function.  
2. Examine the created structure in the editor. Rename the fields for which you have a meaningful name.  
3. Go through the other functions that use the same type of pointer. For each new field accessed, add it manually in the structure editor.  
4. Refine the types as you go: replace `undefined4` with `int`, `float`, or `enum` depending on context.

---

## Reconstructing C++ classes

C++ class reconstruction follows the same principles as for C structures, with specifics related to the object model described in section 8.5.

### Memory layout of a C++ object

A C++ object in memory is organized as follows (single inheritance, without virtual base classes):

```
Offset    Content
──────    ───────
0x00      vptr (pointer to the vtable) — only if the class has virtual methods
0x08      fields inherited from the parent class (in declaration order)
...       fields specific to the class (in declaration order)
```

The vptr, if present, is **always** the first field (offset 0). It occupies 8 bytes on x86-64. Parent class fields come next (except the parent's vptr, which is "fused" with the child class's). Then fields specific to the derived class.

### Reconstruction steps

**1. Identify the vptr** — If the class's constructor writes a constant to `[this + 0]`, this field is the vptr. Create a first field `void * vptr` at offset 0x00 (or a `pointer` type to the vtable if you've already modeled it).

**2. Determine the total size** — Look for the `operator new` call that allocates the object. The argument is the class's `sizeof`. For example, `operator new(0x28)` indicates a 40-byte class.

**3. Identify inherited fields** — If you've already reconstructed the parent class, its fields occupy the same offsets in the derived class (after the vptr). You can include the parent structure as the first (inline) field, or duplicate its fields.

**4. Identify own fields** — Examine the constructor and the class's methods to find accesses to offsets located after the inherited fields.

**5. Model in Ghidra** — Create the structure in the Data Type Manager. Here is an example for a `Dog` class inheriting from `Animal`:

```
struct Dog {                          // sizeof = 0x28 (40 bytes)
    void *      vptr;                 // 0x00 — pointer to vtable_Dog
    int         age;                  // 0x08 — inherited from Animal
    int         health;               // 0x0c — inherited from Animal
    char *      name;                 // 0x10 — inherited from Animal
    int         tricks_count;         // 0x18 — specific to Dog
    int         padding;              // 0x1c — alignment
    char *      breed;                // 0x20 — specific to Dog
};
```

**6. Apply the type** — Modify the signature of each method so that `param_1` (the implicit `this`) is of type `Dog *`. The Decompiler will then replace all raw accesses with named accesses to fields.

### Multiple inheritance

Multiple inheritance complicates the memory layout. When a class `C` inherits from both `A` and `B`, the object contains **two** sub-objects: sub-object `A` starts at offset 0, followed by sub-object `B` (which includes its own vptr). The object therefore has **two vptrs**:

```
struct C {
    // A sub-object
    void * vptr_A;          // 0x00 — C's vtable as A
    // A's fields...
    
    // B sub-object
    void * vptr_B;          // 0xNN — C's vtable as B
    // B's fields...
    
    // C's own fields
};
```

The value of the offset-to-top in the secondary vtable (sub-object `B`'s) indicates the negative offset to find the start of the complete `C` object from sub-object `B`. Multiple inheritance is rarer and significantly more complex to reconstruct. Chapter 17 will return to this in detail.

---

## Reconstructing enums from constants

### Detecting an enum in the pseudo-code

Enums manifest in disassembled code as **integer constants used in comparisons or switches**. Here are the revealing patterns:

**Chain of `if`/`else if` with sequential constants**:

```c
if (local_c == 0) { ... }  
else if (local_c == 1) { ... }  
else if (local_c == 2) { ... }  
else if (local_c == 3) { ... }  
```

**`switch` statement with numbered cases** — Ghidra often detects jump tables and presents them as a `switch` in the Decompiler:

```c
switch(command) {
    case 0: ...
    case 1: ...
    case 2: ...
    case 3: ...
}
```

**Constants used as flags with bitwise operations**:

```c
if ((flags & 1) != 0) { ... }   // FLAG_ACTIVE   = 0x01  
if ((flags & 2) != 0) { ... }   // FLAG_VISIBLE  = 0x02  
if ((flags & 4) != 0) { ... }   // FLAG_LOCKED   = 0x04  
```

### Deducing value names

Enum value names are never present in the binary (unless log or error messages mention them in clear). You must deduce them from context:

- **Associated strings** — If a `case` displays a message like `puts("Processing authentication...")`, the matching value is probably `CMD_AUTH` or `STATE_AUTHENTICATING`.  
- **Called functions** — If a `case` calls `send_ping_response()`, the value is probably `CMD_PING`.  
- **Position in the sequence** — Values 0, 1, 2, 3… of an enum often correspond to a logical progression: `STATE_INIT`, `STATE_CONNECTED`, `STATE_AUTHENTICATED`, `STATE_RUNNING`.  
- **Power-of-2 values** — 1, 2, 4, 8, 16… indicate flags combinable by bitwise OR.

### Create the enum in Ghidra

1. Data Type Manager → right-click on the program's category → **New → Enum**.  
2. Name the enum (`command_e`, `state_e`, `flags_e`).  
3. Add each value with its name and numeric constant.  
4. Define the **size** of the enum. Examine the assembly code to determine whether comparisons use 32-bit operations (`cmp eax, ...` → 4 bytes) or 8-bit (`cmp al, ...` → 1 byte). The default 4-byte size is correct in most cases on x86-64.  
5. Confirm.

Then apply the enum's type to the affected variable or parameter in the Decompiler (key `T`). The pseudo-code immediately replaces numeric constants with symbolic names:

```c
// Before
if (param_2 == 2) { send_data(param_1); }

// After applying the command_e enum
if (command == CMD_DATA) { send_data(connection); }
```

---

## Reconstructing unions

Unions are rarer than structures, but they appear in some contexts: network protocols with packets of different formats, interpreters with polymorphic AST nodes, or dual-use structures (access by individual field or by raw block).

### Detecting a union

The characteristic signal is **the same offset accessed with different types** depending on context:

```c
// In one branch
*(int *)(param_1 + 8) = 42;

// In another branch
*(float *)(param_1 + 8) = 3.14;

// In a third branch
*(char **)(param_1 + 8) = "hello";
```

If the three accesses are at the same offset (0x08) but with incompatible types, it's the sign of a union at that offset.

Another clue is a **discriminant** (or *tag*) field: an integer at a nearby offset (often just before the union zone) whose value determines which "member" of the union is active:

```c
if (*(int *)(param_1 + 4) == 0) {
    // int access at param_1 + 8
} else if (*(int *)(param_1 + 4) == 1) {
    // float access at param_1 + 8
} else {
    // char* access at param_1 + 8
}
```

Here, offset 0x04 is the tag, and offset 0x08 is a union.

### Create the union in Ghidra

1. Data Type Manager → right-click → **New → Union**.  
2. Name the union (for example `value_u`).  
3. Add members with their respective types (`int int_val`, `float float_val`, `char * str_val`).  
4. The union's size is automatically that of the largest member.

You can then include this union as a field of an enclosing structure:

```
struct tagged_value {
    int         type_tag;     // 0x00
    int         padding;      // 0x04
    value_u     value;        // 0x08 — union
};
```

---

## Composite types frequent in GCC binaries

Some complex types appear frequently in binaries compiled with GCC/G++. Recognizing them considerably speeds up analysis.

### Linked lists

Characteristic pattern: a pointer-type field at a fixed offset that points to a structure of the same type.

```c
struct node {
    int     data;        // 0x00
    int     padding;     // 0x04
    node *  next;        // 0x08
};
```

In the Decompiler, you'll see a loop that follows pointers:

```c
while (current != NULL) {
    // ... processing of current->data ...
    current = *(long *)(current + 8);   // current = current->next
}
```

### Structures with flexible array member

In C99/C11, a structure can end with an unspecified-size array:

```c
struct message {
    int     length;
    char    data[];    // flexible array
};
```

Allocation is typically `malloc(sizeof(struct message) + data_length)`. In the Decompiler, you'll see a `malloc` whose argument is a sum of a constant and a variable. The flexible array starts right after the last fixed field.

In Ghidra, model the fixed part as a normal structure. The flexible array cannot be represented directly in the structure editor (its size is variable), but you can add a `char[0] data` field as a semantic indicator, or simply add a comment.

### Common STL types

C++ Standard Template Library (STL) containers have predictable memory layouts with GCC/libstdc++. Chapter 17 will detail them exhaustively, but here is an overview for recognition:

**`std::string`** (also called `std::basic_string<char>`) — With libstdc++, a `std::string` in memory occupies 32 bytes on x86-64 and contains a pointer to buffer data, the size (length), and the capacity. Short strings (15 characters or less) use SSO (Small String Optimization) and store data directly in the object without dynamic allocation.

**`std::vector<T>`** — A `std::vector` occupies 24 bytes and contains three pointers: buffer start (`_M_start`), data end (`_M_finish`), and allocated buffer end (`_M_end_of_storage`). The size is `finish - start`, the capacity is `end - start`.

If you recognize these patterns, you can create the matching structures in the Data Type Manager or import types from a libstdc++ header.

---

## Reconstruction best practices

**Start with the most used structures.** A structure passed as a parameter to 20 functions will have a much bigger propagation impact than a structure used in a single function. Identify the program's "central types" by looking for which pointers are most frequently passed between functions.

**Use constructors as a starting point.** Constructors (and initialization functions in C) generally access all the structure's fields to initialize them. They are the best place to get a complete view of the layout.

**Iterate.** You won't reconstruct a structure in a single pass. Start with fields you identify with certainty, leave unknown zones as `undefined`, and come back to complete them as you analyze other functions.

**Name semantically, not structurally.** Prefer `health` to `field_0x0c`, and `connection_state` to `int_at_offset_4`. If you don't yet know a field's role, a temporary name like `field_0x0c_int` is acceptable, but replace it as soon as you have a hypothesis.

**Document uncertainties.** Use the **Comment** column of the structure editor to note your hypotheses and questions: "probably a reference counter", "could be a bitfield flags", "TODO: verify dynamically".

**Compare sizes.** If `malloc` allocates 0x40 bytes and your structure is only 0x30, fields are missing (or trailing padding). Check that your structure's total size matches the allocated size.

**Relaunch the Decompiler Parameter ID.** After creating and applying significant structures, relaunch the **Decompiler Parameter ID** analyzer (via **Analysis → Auto Analyze…**). It will propagate your new types into caller and callee functions, potentially revealing new information.

---

## Summary

Data structure reconstruction is an iterative process based on observing memory-access patterns in disassembled code. Ghidra provides a complete structure editor, an auto-creation feature that speeds up initial work, and a type system that propagates structures throughout the program. C++ classes follow the same principles with the additional layer of the vptr and inheritance. Enums and unions complete the palette by replacing magic constants and modeling multi-use fields. Each reconstructed and applied structure enriches the Decompiler's pseudo-code and makes neighboring functions more readable, creating a momentum effect that accelerates overall analysis.

The next section addresses an essential tool for navigating relationships between functions and data at the scale of the entire program: cross-references (XREF).

---


⏭️ [Cross-references (XREF): tracking the use of a function or data item](/08-ghidra/07-cross-references-xref.md)
