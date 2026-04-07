🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.4 — Renaming functions and variables, adding comments, creating types

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## Why annotate?

Ghidra's automatic analysis produces a structured but **anonymous** disassembly. Functions are called `FUN_004011a0`, variables `local_28` or `param_1`, types are `undefined8` or `long`. This result is functionally correct — the decompiler faithfully shows what the code does — but it's incomprehensible at the scale of an entire program. Identifying the business logic of a binary by reading only anonymous pseudo-code is like reading a novel where all characters are called "Person A", "Person B", and "Person C".

Annotation is the process by which you turn this raw disassembly into a readable and maintainable document. It's the core of the reverse-engineering work: each rename, each comment, each type you define captures a part of your understanding and makes it exploitable for the rest of the analysis.

Annotation is not a separate step from analysis — it's an integral part of it. You don't first read the whole binary then annotate: you annotate **as you go**, each discovery being immediately recorded in the Ghidra project. This presents a major advantage: annotations **propagate**. Renaming a function in the Symbol Tree instantly updates all `CALL`s referencing it in the Listing and all invocations in the Decompiler. Retyping a parameter to `struct player_t *` transforms all accesses to its fields in the pseudo-code. Each annotation amplifies overall readability.

---

## Renaming functions

### Why rename functions as a priority

Renaming functions is the most rewarding action in terms of readability. A function named `FUN_00401230` says nothing; the same function renamed `validate_license_key` immediately transforms understanding of every function that calls it. The pseudo-code of a `main` that calls `FUN_00401230(param_1)` is opaque; the same `main` that calls `validate_license_key(user_input)` tells a story.

### How to rename

Multiple methods lead to the same result:

**From the Listing** — Place the cursor on the function's label (its name above the first instruction) and press `L`. An input dialog appears with the current name. Type the new name and confirm.

**From the Decompiler** — Click the function name at the top of the pseudo-code (in the signature), then press `L`. Same dialog, same effect.

**From the Symbol Tree** — Right-click the function → **Rename**. Useful for renaming without navigating to the function.

**From the menu** — Right-click the function name in any panel → **Rename Function**.

### Recommended naming conventions

Ghidra imposes no convention, but adopting a consistent style from the start will save you confusion as the number of renamed functions grows:

- **snake_case** for C functions: `check_password`, `parse_header`, `send_response`. It's the most common convention in C code under Linux and the most natural to read in the Decompiler.  
- **CamelCase with namespace** for C++ functions: if you identify that a method belongs to a class, use the `ClassName::methodName` notation. Ghidra automatically creates the matching namespace in the Symbol Tree.  
- **Functional prefixes** for functions whose general role you understand without knowing the details: `init_`, `cleanup_`, `handle_`, `process_`, `parse_`, `validate_`, `alloc_`, `free_`. Even a partial name like `parse_something` is infinitely more useful than `FUN_004015c0`.  
- **`maybe_` or `prob_` prefix** for functions whose role you're not certain of: `maybe_decrypt_buffer`, `prob_auth_check`. It explicitly signals uncertainty without losing the hypothesis.

> 💡 **Don't seek perfection** — An approximate name is always better than `FUN_XXXXXXXX`. You can rename a function as many times as you wish as your understanding evolves. What matters is capturing your current hypothesis.

### Renaming and propagation

When you rename a function, the change propagates **immediately** in:

- all `CALL`s to this function in the Listing;  
- all invocations in the Decompiler's pseudo-code (in the function itself and all caller functions);  
- the Symbol Tree;  
- cross-references;  
- search results.

This automatic propagation is cumulative. Renaming 10 key functions can make the pseudo-code of dozens of calling functions readable without any other modification.

---

## Renaming variables and parameters

### Local variables

The decompiler names local variables according to their stack position (`local_28`, `local_10`) or their inferred role (`iVar1`, `pVar2`). These names are opaque. Rename them as soon as you understand their use.

**From the Decompiler** — Click the variable, press `L`, enter the new name. The renaming propagates throughout the current function's pseudo-code.

**From the Listing** — Click the reference to the local variable (displayed as a stack offset, for example `[RBP + local_28]`), press `L`.

Renaming a local variable is **local to the function** — it only affects the pseudo-code of the function where the variable is defined.

### Function parameters

Parameters (`param_1`, `param_2`…) are renamed exactly like local variables, but with a broader impact. When you rename `param_1` to `filename` in the `open_config_file` function, the Decompiler updates the displayed signature of this function. Any caller function that passes an argument at this position will see the correspondence in the `CALL` context, facilitating data-flow understanding.

To rename a parameter, you can also go through editing the full function signature (see "Modifying a function's signature" later in this section).

### Global variables

Global variables (in `.data`, `.bss`, or `.rodata`) are by default named according to their address (`DAT_00404020`). Rename them via the Listing by placing the cursor on the data label and pressing `L`.

Renaming a global variable is **global to the program**: it propagates in every function that accesses it, in the Listing as in the Decompiler. Renaming `DAT_00404020` to `g_config_buffer` (by convention, the `g_` prefix signals a global variable) instantly clarifies all the code that manipulates it.

---

## Adding comments

Comments are your analysis logbook. They capture your hypotheses, observations, and questions for later. Ghidra offers multiple types of comments, each suited to a different use.

### Comment types

**EOL Comment (End Of Line)** — End-of-line comment, displayed to the right of the instruction in the Listing. It's the most common type, used for brief annotations on a specific instruction.

- Shortcut: `;` (semicolon key)  
- Typical use: explain an instruction's role, note a concrete value observed dynamically, flag a recognized pattern.

Example:

```
00401189  cmp  DWORD PTR [rbp-0x4], 0x5    ; compares the loop counter to 5
```

**Pre Comment** — Comment displayed **above** the instruction, on its own line. Used for longer explanatory blocks that apply to a group of instructions.

- Shortcut: `Ctrl+;`  
- Typical use: describe the start of a logical block ("Here begins the checksum verification"), document a complex algorithm, note an instruction sequence that forms a known idiom.

**Post Comment** — Comment displayed **below** the instruction. Less common, used to note the consequences of an instruction or what happens after its execution.

- Shortcut: right-click → **Comments → Set Post Comment**

**Plate Comment** — Comment displayed in a box above a function's label, like a documentation block. It's the equivalent of a Doxygen comment for a disassembled function.

- Shortcut: right-click → **Comments → Set Plate Comment**  
- Typical use: summary of the function's role, description of parameters, notes on observed behavior.

Example of a plate comment:

```
/****************************************
 * Checks whether the license key passed
 * as parameter is valid.
 * param_1: pointer to the key string
 * Returns 1 if valid, 0 otherwise.
 * Algorithm: rolling XOR on each
 * character with seed 0x42.
 ****************************************/
```

**Repeatable Comment** — Comment that propagates automatically to every place referencing this address. If you place a repeatable comment on a global variable, it will appear next to each instruction that accesses that variable. Powerful, but to be used sparingly to avoid visual noise.

- Shortcut: right-click → **Comments → Set Repeatable Comment**

### Comments in the Decompiler

The Decompiler displays Pre and EOL comments associated with the matching assembly instructions, integrated into the pseudo-code. You can also add comments directly from the Decompiler via right-click → **Comments**, but these comments are actually attached to the underlying assembly instructions.

### Commenting strategy

A few principles for useful comments:

- **Comment the "why", not the "what"** — The instruction `CMP EAX, 0x10` is already readable. What's valuable is "compares the input length to 16, the expected size of an AES-128 key".  
- **Use plate comments for function summaries** — That's the first thing you'll read when you revisit a function days later.  
- **Note your uncertainties** — A comment like "TODO: check whether it's RC4 or a custom XOR" is precious. It saves you from redoing the reasoning later.  
- **Mark points of dynamic interest** — "Place a breakpoint here to capture the cleartext key" prepares the dynamic-analysis phase (Part III).

---

## Modifying a function's signature

A function's signature — its return type, its name, and the list of typed parameters — is the most structuring annotation you can make. It conditions the quality of the pseudo-code not only in the function itself, but in every function that calls it.

### Accessing the signature editor

- From the Decompiler: right-click on the function name → **Edit Function Signature** (or `F` key).  
- From the Listing: right-click on the function label → **Edit Function**.

The editor displays a text field containing the current signature in a format close to C:

```c
undefined8 FUN_004011a0(undefined8 param_1, undefined4 param_2)
```

You can directly modify this line like C code:

```c
int check_password(char * user_input, int max_length)
```

On validation, Ghidra updates:

- the function name in the Symbol Tree and the Listing;  
- the return type (here `undefined8` → `int`);  
- the names and types of parameters;  
- the Decompiler's pseudo-code, which immediately reflects the new types.

### Advanced signature options

The full editor (accessible via the **Edit** button or via **Function → Edit Function** in the menu) offers additional options:

**Calling Convention** — Default `__stdcall` for System V AMD64 (despite the name inherited from Windows, Ghidra uses it as the default convention on x86-64 Linux). You generally don't have to modify it, except if you encounter a function that uses a non-standard convention (for example, a hand-written assembly function that passes parameters via the stack rather than via registers).

**Inline / No Return** — Two boolean attributes. `Inline` tells Ghidra the function is meant to be inlined (rarely useful in RE). `No Return` indicates the function never returns (like `exit`, `abort`, `__stack_chk_fail`). Checking `No Return` improves the accuracy of the control-flow graph by preventing Ghidra from treating code after a `CALL` to this function as reachable code.

**Custom Storage** — Lets you specify manually in which registers or stack locations each parameter is passed. Useful when Ghidra gets the parameter-to-register assignment wrong, which can happen with variadic functions, functions derived from inline assembly code, or non-standard calling conventions.

### Impact of the signature on the Decompiler

The signature is the information that has the most impact on pseudo-code quality. Let's take a concrete example. Before correcting the signature:

```c
undefined8 FUN_004011a0(undefined8 param_1)
{
    undefined4 uVar1;
    uVar1 = *(undefined4 *)(param_1 + 0x10);
    if (*(int *)(param_1 + 0xc) < 100) {
        *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar1;
    }
    return 0;
}
```

After creating a `player_t` structure (section 8.6) and modifying the signature:

```c
int update_health(player_t * player)
{
    int heal_amount;
    heal_amount = player->heal_rate;
    if (player->health < 100) {
        player->health = player->health + heal_amount;
    }
    return 0;
}
```

The code is functionally identical, but the second version is immediately comprehensible. All the work lies in defining the structure and correcting the signature — the Decompiler does the rest.

---

## Creating and applying types

### Types in Ghidra

Ghidra's type system is one of its most powerful assets for turning an opaque disassembly into readable pseudo-code. A "type" in Ghidra can be:

- a **primitive type**: `int`, `long`, `char`, `float`, `double`, `void *`, etc.;  
- a **typedef**: an alias for another type (`typedef unsigned int uint32_t`);  
- an **enum**: a set of named constants;  
- a **structure** (`struct`): an arrangement of fields at fixed offsets;  
- a **union**: fields that share the same memory location;  
- a **function pointer**: a type describing a callback's signature.

### Where to manage types: the Data Type Manager

The Data Type Manager (**Window → Data Type Manager**) is the central interface for creating, modifying, importing, and applying types. It displays a tree of categories:

- **BuiltInTypes** — primitive types, not modifiable;  
- **Current program** (your binary's name) — types specific to this binary. It's here that you'll create your custom structures;  
- **Archives** — the loaded type archives (`.gdt`). The `generic_clib` archive is particularly useful, because it contains signatures of hundreds of standard libc functions.

### Create a typedef

A typedef is useful for replacing Ghidra's generic types with semantic names. For example, if you observe that an `undefined4` is systematically used as a player identifier, create a typedef:

1. In the Data Type Manager, right-click on your program's category → **New → Typedef**.  
2. Name: `player_id_t`.  
3. Base type: `uint` (or `unsigned int`).  
4. Confirm.

You can then apply this type to variables and parameters in the Decompiler via `T` (Retype).

### Create an enum

Enumerations are precious for replacing magic constants with meaningful names. When you see in the pseudo-code comparisons like `if (param_2 == 1)` … `else if (param_2 == 2)` … `else if (param_2 == 3)`, there's probably an underlying enumeration.

1. In the Data Type Manager, right-click on your program's category → **New → Enum**.  
2. Name the enum (for example `command_type_e`).  
3. Add values: `CMD_PING = 0`, `CMD_AUTH = 1`, `CMD_DATA = 2`, `CMD_QUIT = 3`.  
4. Define the size (1, 2, 4, or 8 bytes) according to the use observed in the binary.  
5. Confirm.

Then apply this type to the affected parameter or variable in the Decompiler. The pseudo-code goes from `if (param_2 == 1)` to `if (command == CMD_AUTH)`, which is considerably more readable.

### Create a structure (struct)

Creating structures is the most transformative typing operation. It's detailed in section 8.6, but here is the basic principle.

When the Decompiler shows repeated accesses to offsets of a pointer:

```c
*(int *)(param_1 + 0)     // offset 0x00
*(int *)(param_1 + 4)     // offset 0x04
*(char *)(param_1 + 8)    // offset 0x08
*(long *)(param_1 + 0x10) // offset 0x10
```

This indicates there's a structure whose fields sit at these offsets. You can create it:

1. Data Type Manager → right-click on your program → **New → Structure**.  
2. Name it (for example `config_t`).  
3. The **structure editor** opens. Add fields one by one:  
   - Offset `0x00`: `int id`  
   - Offset `0x04`: `int flags`  
   - Offset `0x08`: `char name[8]`  
   - Offset `0x10`: `long timestamp`  
4. Confirm.

Then apply the type `config_t *` to the parameter in the Decompiler. Ghidra automatically replaces every offset-based access with named field accesses.

> 💡 **Shortcut from the Decompiler** — Instead of creating the structure entirely by hand, you can use the **Auto Create Structure** feature: right-click on a pointer-type parameter in the Decompiler → **Auto Create Structure**. Ghidra analyzes all accesses to this pointer in the function and generates a structure with the inferred fields. The result isn't perfect (field names are generic like `field_0x4`), but the offset structure is correct. You can then refine it by renaming fields.

### Applying a type to data in the Listing

In the Listing, you can apply a type to a data address (in `.data`, `.rodata`, `.bss`) by positioning the cursor on the address and pressing `T`. A dialog lets you choose the type in the Data Type Manager.

This is useful for typing global variables, arrays of structures, or constants whose format was not automatically detected. For example, applying the type `char[256]` to a zone of `.bss` transforms 256 individual `undefined1` bytes into a named and coherent buffer.

### Importing types from a C header file

When you know some of the program's structures (for example, if the binary uses a library whose headers are public), you can import them directly:

1. **File → Parse C Source…** in the CodeBrowser.  
2. Paste or load the content of the `.h` file.  
3. Ghidra parses C definitions and adds the resulting types to the Data Type Manager.

This works with structures, enums, typedefs, and function signatures. It's a considerable time saver when the binary uses known libraries (OpenSSL, SQLite, protobuf, etc.) whose headers are publicly available.

> ⚠️ **Limitation** — Ghidra's C parser doesn't support the full C/C++ language. Complex macros, C++ templates, and some GCC-specific constructions can fail. In that case, simplify the header by keeping only the relevant structures and typedefs before importing it.

### Type archives (`.gdt`)

Ghidra uses type archives in the `.gdt` (Ghidra Data Types) format to store sets of types reusable across projects. Several archives are provided:

- `generic_clib.gdt` — types and signatures of the standard libc;  
- `generic_clib_64.gdt` — 64-bit variant;  
- `windows_*.gdt` — Windows API types (useful if you analyze a PE binary compiled with MinGW).

You can create your own archives for types you define frequently. In the Data Type Manager, right-click on a category → **Save As → Archive**. This archive can then be imported into other projects, which is particularly useful if you analyze multiple binaries of the same software sharing the same data structures.

---

## Propagation and consistency

One of the most satisfying aspects of annotation in Ghidra is the **propagation cascade**. Here is a concrete example of the chain reaction a single annotation can trigger:

1. You create a `packet_header_t` structure with fields `magic`, `version`, `payload_size`, `command`.  
2. You identify the function `FUN_00401500` as the one that parses network packets. You rename it `parse_packet` and modify its signature so `param_1` is of type `packet_header_t *`.  
3. The Decompiler of `parse_packet` now shows named accesses: `header->magic`, `header->command`, `header->payload_size`.  
4. The function `FUN_00401700` calls `parse_packet`. In `FUN_00401700`'s Decompiler, the argument passed to `parse_packet` is now typed as `packet_header_t *`, and accesses to this variable before the call also show field names.  
5. You rename `FUN_00401700` to `handle_connection`. Its pseudo-code is now largely readable without any other annotation in this function.

Each annotation creates a domino effect. That's why it's rewarding to invest time in creating good structures and correcting key function signatures — the effort multiplies across the program.

---

## Undo / Redo

All modifications you make — renames, comments, types, signatures — are **reversible**. Ghidra maintains a complete undo history:

- **`Ctrl+Z`** — undo the last modification;  
- **`Ctrl+Shift+Z`** (or `Ctrl+Y`) — redo an undone modification.

The undo history is persistent within a session. If you close and reopen the project, modifications are saved but the undo history is lost. If you wish to be able to revert to a prior state after closing, use **file versions**: right-click on the binary in the Project Manager → **Check In** to create a versioned save point.

---

## Summary

Annotation is the process that turns an anonymous disassembly into an exploitable technical document. The three pillars of this transformation are renaming (functions, variables, global data), comments (EOL, Pre, Plate, Repeatable), and the type system (typedefs, enums, structures, header import, `.gdt` archives). Each annotation propagates automatically in the Listing, the Decompiler, and the Symbol Tree, creating a cumulative effect where each addition enriches the project's overall readability.

The next section addresses a direct application case of these skills: the recognition and annotation of GCC-specific structures in C++ binaries — vtables, RTTI, and exception tables.

---


⏭️ [Recognizing GCC structures: C++ vtables, RTTI, exceptions](/08-ghidra/05-gcc-structures-vtables-rtti.md)
