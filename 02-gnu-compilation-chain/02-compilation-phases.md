🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 2.2 — Compilation phases and intermediate files (`.i`, `.s`, `.o`)

> 🎯 **Goal of this section**: Concretely produce and inspect each intermediate file of the compilation chain, learn to read their content, and develop the reflex of exploiting these artifacts when they are available during an RE analysis.

---

## Why care about intermediate files?

In section 2.1 we described the compilation pipeline conceptually. Here we move on to practice. GCC's `-save-temps` flag keeps all intermediate files on disk, which allows us to "photograph" the state of the code at each stage of the transformation.

For the reverse engineer, these intermediate files are valuable in two situations:

1. **During learning**: observing the output of each phase trains you to recognize patterns you will later find in an unknown binary. Seeing how an `if/else` in C becomes `cmp` + `jz` instructions in the `.s` prepares you to walk the path backwards.

2. **During a real analysis**: if you have access to a project's build system (code audit, open source project analysis, internal security incident), the `.o` files before linking often contain more information than the final executable — local symbols, unresolved relocations, debug sections specific to each compilation unit.

## Generating all intermediates at once

Let's return to our `hello.c` running example and compile it while keeping all artifacts:

```bash
gcc -save-temps -O0 -o hello hello.c
```

After execution, the directory contains:

```
hello.c       ← Original source  
hello.i       ← Preprocessor output  
hello.s       ← Compiler output (textual assembly)  
hello.o       ← Assembler output (ELF object file)  
hello         ← Final executable (after linking)  
```

You can also produce each file individually, which is sometimes more explicit:

```bash
gcc -E  hello.c -o hello.i      # Preprocessor only  
gcc -S  hello.c -o hello.s      # Preprocessor + compilation  
gcc -c  hello.c -o hello.o      # Preprocessor + compilation + assembly  
gcc     hello.c -o hello        # Full pipeline  
```

> ⚠️ **Note**: with `-S` and `-c`, GCC implicitly runs all the *previous* phases. The `-S` flag does not assume you are providing a `.i` — it starts from the `.c` and stops after generating the `.s`.

Let's now compare the sizes to get a first intuition:

```bash
wc -l hello.i hello.s  
ls -lh hello.o hello  
```

Typical result (exact values depend on your system and GCC version):

| File | Indicative size | Indicative lines |  
|---------|-------------------|--------------------|  
| `hello.c` | ~0.4 KB | ~20 lines |  
| `hello.i` | ~30–60 KB | ~800–2000 lines |  
| `hello.s` | ~2–4 KB | ~80–150 lines |  
| `hello.o` | ~2–4 KB | (binary) |  
| `hello` | ~16–20 KB | (binary) |

The `.i` is large because it integrates all the headers. The `.s` is compact because it only contains the assembly code of *your* source — libc functions are not yet included. The size jump between `.o` and the final executable is explained by the addition of CRT code, the PLT/GOT structures, the complete ELF headers, and the dynamic linking metadata.

## The `.i` file — Preprocessor output

### File structure

The `.i` file is **pure C**, syntactically valid, ready to be parsed by the compiler. It consists of three elements:

**Line markers** (*linemarkers*) are directives in the form `# number "file" flags` which allow the compiler to report errors and warnings by referencing the correct line numbers in the original files:

```c
# 1 "hello.c"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 1 "<command-line>" 2
# 1 "hello.c"
# 1 "/usr/include/stdio.h" 1 3 4
# 27 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 1 3 4
...
```

The numeric flags after the filename have a precise meaning: `1` indicates the start of a new file (entering an `#include`), `2` indicates returning to the including file (leaving an `#include`), `3` signals that the content comes from a system header, and `4` indicates that the content should be treated as wrapped in an implicit `extern "C"` block.

**Header content** occupies the vast majority of the file. You will find the declarations of `printf`, `strcmp`, the system typedefs (`size_t`, `FILE`, etc.), and the whole transitive chain of inclusions.

**Your code**, at the very bottom of the file, with macros expanded:

```c
# 6 "hello.c"
int check(const char *input) {
    return strcmp(input, "RE-101") == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    if (check(argv[1])) {
        printf("Access granted.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
```

Note that `SECRET` has disappeared, replaced by its value `"RE-101"`.

### What you can gain from it (RE perspective)

Examining a `.i` is rarely useful in classic RE (you generally do not have access to the intermediate files of a target binary). But it is an excellent learning tool for understanding **what the compiler actually receives**:

- You realize the amount of code coming from headers that has nothing to do with the author's code.  
- You identify the exact prototypes of libc functions as GCC sees them, which helps understand calling conventions.  
- You can verify how conditional macros (`#ifdef DEBUG`, `#ifdef __linux__`, etc.) were resolved, which sheds light on the differences between a debug build and a release build.

To navigate quickly in a large `.i`, search for your functions:

```bash
grep -n "^int check\|^int main" hello.i
```

## The `.s` file — Compiler output (textual assembly)

### File structure

The `.s` file is **assembly code** in text format, in AT&T syntax by default under GCC. It contains a mix of machine instructions and **assembler directives** (meta-instructions intended for `as`, not for the processor).

Here is the complete `.s` of our `hello.c` compiled with `-O0` (simplified for readability, exact details vary with the GCC version):

```asm
        .file   "hello.c"
        .text
        .section        .rodata
.LC0:
        .string "RE-101"
.LC1:
        .string "Usage: %s <password>\n"
.LC2:
        .string "Access granted."
.LC3:
        .string "Access denied."
        .text
        .globl  check
        .type   check, @function
check:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $16, %rsp
        movq    %rdi, -8(%rbp)
        movq    -8(%rbp), %rax
        leaq    .LC0(%rip), %rsi
        movq    %rax, %rdi
        call    strcmp@PLT
        testl   %eax, %eax
        sete    %al
        movzbl  %al, %eax
        leave
        ret
        .size   check, .-check
        .globl  main
        .type   main, @function
main:
        pushq   %rbp
        movq    %rsp, %rbp
        subq    $16, %rsp
        movl    %edi, -4(%rbp)
        movq    %rsi, -16(%rbp)
        cmpl    $2, -4(%rbp)
        je      .L4
        movq    -16(%rbp), %rax
        movq    (%rax), %rax
        movq    %rax, %rsi
        leaq    .LC1(%rip), %rdi
        movl    $0, %eax
        call    printf@PLT
        movl    $1, %eax
        jmp     .L5
.L4:
        movq    -16(%rbp), %rax
        addq    $8, %rax
        movq    (%rax), %rax
        movq    %rax, %rdi
        call    check
        testl   %eax, %eax
        je      .L6
        leaq    .LC2(%rip), %rdi
        call    puts@PLT
        jmp     .L7
.L6:
        leaq    .LC3(%rip), %rdi
        call    puts@PLT
.L7:
        movl    $0, %eax
.L5:
        leave
        ret
        .size   main, .-main
```

### Anatomy of the elements

**Assembler directives** (lines starting with a period) do not generate machine instructions. They guide the `as` assembler in building the object file:

| Directive | Role |  
|-----------|------|  
| `.file "hello.c"` | Records the name of the source file (debug metadata) |  
| `.text` | Switches to the `.text` section (executable code) |  
| `.section .rodata` | Switches to the `.rodata` section (read-only data) |  
| `.string "RE-101"` | Places a `\0`-terminated string at the current position |  
| `.globl check` | Declares the `check` symbol as global (visible from other `.o` files) |  
| `.type check, @function` | Indicates that `check` is a function (ELF information) |  
| `.size check, .-check` | Records the size of the function (current position minus start) |

**Labels** (words followed by `:`) are symbolic anchors. Function labels (`check:`, `main:`) bear readable names. Labels generated by the compiler (`.L4`, `.L5`, `.L6`, `.L7`) are **local labels** — they correspond to the branching points of your `if/else`. The `.L` prefix is a GCC convention indicating an internal label, not exported in the symbol table.

**Instructions** constitute the machine code the processor will execute. We will study them in detail in Chapter 3. For now, note some correspondences with the C code:

| C code | Corresponding assembly |  
|--------|-------------------------|  
| `strcmp(input, SECRET)` | `leaq .LC0(%rip), %rsi` then `call strcmp@PLT` |  
| `== 0` | `testl %eax, %eax` + `sete %al` |  
| `if (argc != 2)` | `cmpl $2, -4(%rbp)` + `je .L4` |  
| `printf(...)` | Loading arguments + `call printf@PLT` |  
| `return 0` | `movl $0, %eax` |

> 💡 **Observation**: GCC replaced `printf("Access granted.\n")` with `call puts@PLT`. This is a **common optimization**: when `printf` is called with a simple string without a format (no `%`), GCC silently replaces it with `puts`, which is lighter. This is a first example of a compiler idiom you will learn to recognize (Chapter 16, section 16.6).

### Getting Intel syntax

By default, GCC produces assembly in AT&T syntax (source operands before destination, `%` and `$` prefixes). If you prefer Intel syntax (the one used by IDA, the one many find more readable):

```bash
gcc -S -masm=intel hello.c -o hello_intel.s
```

The same `movq %rdi, -8(%rbp)` instruction then becomes `mov QWORD PTR [rbp-8], rdi`. We will dig deeper into both syntaxes in Chapter 7, section 7.2.

### Comparing optimization levels in the `.s`

One of the most instructive uses of the `.s` is the comparison between optimization levels. Let's generate the four variants:

```bash
gcc -S -O0 hello.c -o hello_O0.s  
gcc -S -O1 hello.c -o hello_O1.s  
gcc -S -O2 hello.c -o hello_O2.s  
gcc -S -O3 hello.c -o hello_O3.s  
```

Then let's count the instruction lines (excluding directives and blank lines):

```bash
for f in hello_O0.s hello_O1.s hello_O2.s hello_O3.s; do
    echo "$f : $(grep -cE '^\s+[a-z]' $f) instructions"
done
```

Typical result:

| File | Instructions (approx.) | Observations |  
|---------|------------------------|--------------|  
| `hello_O0.s` | ~35–40 | Verbose code, direct correspondence with the C |  
| `hello_O1.s` | ~25–30 | Variables kept in registers, fewer memory accesses |  
| `hello_O2.s` | ~20–25 | `check()` potentially inlined into `main()` |  
| `hello_O3.s` | ~20–25 | Similar to `-O2` for this small program |

At `-O0`, each local variable is stored on the stack and reloaded on each use — this is inefficient but faithful to the source. Starting at `-O1`, GCC begins to keep values in registers and to eliminate unnecessary round-trips with the stack. At `-O2`, the `check()` function can be **inlined**: its code is inserted directly into `main()`, and the `check:` label disappears. We will dig deeper into these transformations in Chapter 16.

A `diff` between two `.s` files is a powerful learning tool:

```bash
diff --color hello_O0.s hello_O2.s
```

## The `.o` file — Assembler output (object file)

### Nature of the file

The `.o` file is the first **binary** artifact of the pipeline. It is a file in ELF (Executable and Linkable Format) format, but of type `ET_REL` (*relocatable*) — it cannot be executed directly. It contains:

- The **machine code** encoded from the assembly instructions.  
- The **data** (literal strings, initialized global variables).  
- A local and global **symbol table**.  
- **Relocation entries** that mark the addresses to be fixed up by the linker.  
- Optionally, **debug information** (if compiled with `-g`).

Check the nature of the file:

```bash
file hello.o
# hello.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

The keyword `relocatable` confirms that this is an object file (not an executable, not a shared library).

### Inspecting the sections

```bash
readelf -S hello.o
```

Simplified output:

```
Section Headers:
  [Nr] Name              Type             Offset   Size
  [ 0]                   NULL             000000   000000
  [ 1] .text             PROGBITS         000040   000089
  [ 2] .rela.text        RELA             000298   0000c0
  [ 3] .data             PROGBITS         0000c9   000000
  [ 4] .bss              NOBITS           0000c9   000000
  [ 5] .rodata           PROGBITS         0000c9   000050
  [ 6] .comment          PROGBITS         000119   00002c
  [ 7] .note.GNU-stack   PROGBITS         000145   000000
  [ 8] .eh_frame         PROGBITS         000148   000058
  [ 9] .rela.eh_frame    RELA             000358   000030
  [10] .symtab           SYMTAB           0001a0   000108
  [11] .strtab           STRTAB           0002a8   000035
  [12] .shstrtab         STRTAB           000388   000061
```

Points to note:

- **`.text`** (89 bytes) contains the machine code of `check()` and `main()`.  
- **`.rela.text`** contains the **relocations** of `.text` — the places where the linker will have to insert the final addresses of `strcmp`, `printf`, `puts`, and the `.LC0` string.  
- **`.data`** and **`.bss`** are empty: our program has no initialized (`.data`) or uninitialized (`.bss`) global variables.  
- **`.rodata`** (80 bytes) contains the literal strings: `"RE-101"`, `"Usage: %s <password>\n"`, `"Access granted."`, `"Access denied."`.  
- **`.symtab`** and **`.strtab`** make up the symbol table and the associated name table.  
- **`.eh_frame`** contains stack-unwinding information for exception handling (even in C, this section is present to enable the *stack unwinding* used by debuggers and profiling tools).

### Inspecting the symbol table

```bash
readelf -s hello.o
```

Simplified output:

```
Symbol table '.symtab' contains 11 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS hello.c
     2: 0000000000000000     0 SECTION LOCAL  DEFAULT    1 .text
     3: 0000000000000000     0 SECTION LOCAL  DEFAULT    5 .rodata
     4: 0000000000000000    41 FUNC    GLOBAL DEFAULT    1 check
     5: 0000000000000029    96 FUNC    GLOBAL DEFAULT    1 main
     6: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND strcmp
     7: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND printf
     8: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts
```

This table is rich in insights:

- **`check`** is defined in section 1 (`.text`), at offset 0, size 41 bytes, of type `FUNC`, with a `GLOBAL` binding (visible from other object files).  
- **`main`** is defined at offset `0x29` (41 in decimal — right after `check`), size 96 bytes.  
- **`strcmp`**, **`printf`**, and **`puts`** are marked `UND` (*undefined*): they are referenced but not defined in this object file. The linker will have to resolve them.

> 💡 **RE tip**: In a `.o` file, all local symbols are still present — even those marked `static` in C. It is the linker, during stripping, that removes them. If you have access to a project's `.o` files, you have more information than in the final stripped binary.

### Inspecting the relocations

```bash
readelf -r hello.o
```

Simplified output:

| Offset | Type | Sym. Name + Addend |  
|---|---|---|  
| `0x12` | `R_X86_64_PC32` | `.rodata - 4` |  
| `0x1a` | `R_X86_64_PLT32` | `strcmp - 4` |  
| `0x40` | `R_X86_64_PC32` | `.rodata + 22` |  
| `0x49` | `R_X86_64_PLT32` | `printf - 4` |  
| `0x60` | `R_X86_64_PLT32` | `puts - 4` |  
| `0x6f` | `R_X86_64_PLT32` | `puts - 4` |

Each entry says: "at offset X in `.text`, there is a reference to symbol Y that will need to be fixed up." The `R_X86_64_PLT32` type indicates a relative relocation for a call via PLT — this is the standard mechanism for dynamic library functions (detailed in section 2.9).

### Disassembling the `.o`

You can disassemble the object file exactly like an executable:

```bash
objdump -d hello.o
# or in Intel syntax:
objdump -d -M intel hello.o
```

The result is almost identical to the contents of the `.s`, but in decoded form from the binary. You will notice that the addresses of the calls to `strcmp`, `printf`, and `puts` are zero — they are waiting to be filled in by the linker:

```
  17:   e8 00 00 00 00          call   1c <check+0x1c>
```

These four bytes `00 00 00 00` will be replaced at link time by the relative displacement to the corresponding PLT stub.

## The final executable — After linking

To complete the overview, let's briefly examine what changes in the final binary compared to the `.o` (details will come in sections 2.4 to 2.9 and in Chapter 5):

```bash
readelf -S hello | head -30
```

You will notice the appearance of many additional sections absent from the `.o`:

| Section | Origin |  
|---------|---------|  
| `.interp` | Path to the dynamic loader (`/lib64/ld-linux-x86-64.so.2`) |  
| `.plt` and `.plt.got` | Procedure Linkage Table stubs (dynamic resolution) |  
| `.got` and `.got.plt` | Global Offset Table (addresses resolved at runtime) |  
| `.init` and `.fini` | Initialization and finalization code (CRT) |  
| `.init_array` and `.fini_array` | Pointers to global constructors/destructors |  
| `.dynamic` | Information table for the dynamic loader |  
| `.dynsym` and `.dynstr` | Dynamic symbol table and associated names |

The `.rela.text` section has disappeared: the relocations have been resolved. The addresses in the machine code now point to the PLT stubs. The file has moved from type `ET_REL` (relocatable) to type `ET_DYN` (shared object / position-independent executable) or `ET_EXEC` (fixed-address executable):

```bash
readelf -h hello | grep Type
# Type: DYN (Position-Independent Executable file)
```

## Summary: from source to binary at a glance

| Information | `hello.c` (C source) | `hello.i` (preprocessed C) | `hello.s` (ASM text) | `hello.o` (relocatable ELF) | `hello` (ELF executable) |  
|---|---|---|---|---|---|  
| **Indicative size** | ~20 lines | ~800–2000 lines | ~80–150 lines | ~2–4 KB | ~16–20 KB |  
| Macros | ✅ | ❌ Expanded | ❌ | ❌ | ❌ |  
| Comments | ✅ | ❌ | ❌ | ❌ | ❌ |  
| C types | ✅ | ✅ | ❌ Reduced to sizes | ❌ | ❌ |  
| Variable names | ✅ | ✅ | ❌ Registers / offsets | ❌ | ❌ |  
| Function names | ✅ | ✅ | ✅ Labels | ✅ Symbols | ⚠️ If not stripped |  
| Control structures | ✅ | ✅ | ✅ Jumps | ✅ Jumps | ✅ Jumps |  
| Relocations | — | — | `@PLT` references | ✅ Present | ❌ Resolved |

Each column is a snapshot of the available information. Reading right-to-left — starting from the final binary and trying to recover the source — is precisely the definition of reverse engineering.

## Essential commands to remember

| Goal | Command |  
|----------|----------|  
| Keep all intermediates | `gcc -save-temps hello.c -o hello` |  
| Preprocessor only | `gcc -E hello.c -o hello.i` |  
| Compilation only (→ assembly) | `gcc -S hello.c -o hello.s` |  
| Assembly only (→ object) | `gcc -c hello.c -o hello.o` |  
| Intel syntax for the `.s` | `gcc -S -masm=intel hello.c -o hello.s` |  
| See GCC's internal commands | `gcc -v hello.c -o hello` |  
| Display without running | `gcc -### hello.c -o hello` |  
| Sections of a `.o` or ELF | `readelf -S hello.o` |  
| Symbols | `readelf -s hello.o` |  
| Relocations | `readelf -r hello.o` |  
| Disassembly | `objdump -d hello.o` |

---

> 📖 **Now that we know how to produce and read the intermediate files**, it is time to understand the format of the final product. In the next section, we will examine the three major native binary formats — ELF, PE, and Mach-O — and why this training focuses on ELF.  
>  
> → [2.3 — Binary formats: ELF (Linux), PE (Windows via MinGW), Mach-O (macOS)](/02-gnu-compilation-chain/03-binary-formats.md)

⏭️ [Binary formats: ELF (Linux), PE (Windows via MinGW), Mach-O (macOS)](/02-gnu-compilation-chain/03-binary-formats.md)
