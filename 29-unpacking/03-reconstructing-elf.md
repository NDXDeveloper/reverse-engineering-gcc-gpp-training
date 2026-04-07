🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 29.3 — Reconstructing the Original ELF: Fixing Headers, Sections and Entry Point

> 🎯 **Section objective** — Transform the raw memory dumps obtained in section 29.2 into a **valid ELF file** that can be imported into Ghidra, radare2, or any other static analysis tool. We'll cover manual reconstruction (to understand each field) and Python script-assisted reconstruction (to automate the process).

---

## Why raw dumps aren't enough

At the end of section 29.2, we have binary files (`code.bin`, `data_ro.bin`, `data_rw.bin`) containing the exact contents of the decompressed process's memory regions. We verified with `strings` and `objdump -D` that the machine code is indeed present and coherent. Why can't we simply open these files in Ghidra?

The problem is that these dumps are **flat memory images** — byte sequences with no structural metadata. But a disassembler like Ghidra needs to know where code begins, where data is, what the entry point is, what virtual addresses are associated with each byte, and how sections relate to each other. All this information is normally carried by the **ELF header** and the **section header table** (SHT), which are absent from the raw dump.

You can indeed import a raw dump into Ghidra as a "Raw Binary" by manually specifying the architecture (x86-64), base address, and entry point. But the result is poor: Ghidra can't distinguish code from data, can't identify strings in `.rodata`, and doesn't reconstruct cross-references correctly. A well-formed ELF produces an incomparably better analysis.

Reconstruction therefore consists of **repackaging** the dumps into an ELF container by recreating the metadata that the packer had removed or replaced.

---

## Quick ELF anatomy: what needs to be reconstructed

Let's recall the structure of an ELF file (detailed in Chapter 2, sections 2.3–2.4). An ELF is composed of three metadata layers:

The **ELF header** occupies the first 64 bytes of the file (in 64-bit). It contains the magic (`\x7fELF`), the class (32/64-bit), endianness, file type (`ET_EXEC` or `ET_DYN`), architecture (`EM_X86_64`), entry point (`e_entry`), and offsets to the two tables that follow.

The **program header table** (PHT) describes the **segments** — contiguous file regions that will be mapped into memory by the loader. Each `Phdr` entry specifies the segment type (`PT_LOAD`, `PT_NOTE`...), file and memory offsets, on-disk and in-memory sizes, and permission flags (`PF_R`, `PF_W`, `PF_X`). The PHT is what the Linux kernel uses to load the binary; it is **mandatory** for execution.

The **section header table** (SHT) describes the **sections** — a finer logical division (`.text`, `.rodata`, `.data`, `.bss`...) used by analysis tools but **not by the loader**. This is why UPX can remove the SHT without preventing the binary from executing. But it's precisely the SHT that makes Ghidra effective: without it, the disassembler can't distinguish code from data and loses a large part of its automatic analysis capability.

Our reconstruction objective is therefore threefold: recreate a correct ELF header, build a functional PHT, and — as much as possible — recreate an SHT with at minimum the `.text`, `.rodata`, `.data`, and `.bss` sections.

---

## Step 1 — Collect information from GDB

Before starting reconstruction, we gather all necessary information. We resume the GDB session from section 29.2, stopped at the OEP:

### OEP address

This is the value of `rip` when the hardware breakpoint was hit:

```
gef➤ print/x $rip
$1 = 0x401000
```

This address will become the `e_entry` field of our reconstructed ELF.

### Complete memory map

```
gef➤ vmmap  
Start              End                Offset Perm  Path  
0x0000000000400000 0x0000000000401000 0x0000 r--p  packed_sample_upx_tampered
0x0000000000401000 0x0000000000404000 0x1000 r-xp  packed_sample_upx_tampered
0x0000000000404000 0x0000000000405000 0x4000 r--p  packed_sample_upx_tampered
0x0000000000405000 0x0000000000406000 0x5000 rw-p  packed_sample_upx_tampered
0x0000000000406000 0x0000000000407000 0x0000 rw-p  [heap]
...
```

We deduce four relevant regions from the binary (ignoring the heap, stack, and libc/vdso mappings):

| Start address | End address | Size     | Permissions | Likely role         |  
|---------------|-------------|----------|-------------|---------------------|  
| `0x400000`    | `0x401000`  | `0x1000` | `r--`       | ELF header + PHT    |  
| `0x401000`    | `0x404000`  | `0x3000` | `r-x`       | `.text` (code)      |  
| `0x404000`    | `0x405000`  | `0x1000` | `r--`       | `.rodata` (read-only data) |  
| `0x405000`    | `0x406000`  | `0x1000` | `rw-`       | `.data` + `.bss`    |

### Region dumps

If not already done, dump each region:

```
gef➤ dump binary memory region_hdr.bin  0x400000 0x401000  
gef➤ dump binary memory region_text.bin 0x401000 0x404000  
gef➤ dump binary memory region_ro.bin   0x404000 0x405000  
gef➤ dump binary memory region_rw.bin   0x405000 0x406000  
```

---

## Step 2 — Manual reconstruction with a hex editor

This approach is tedious but instructive. It lets you understand precisely each byte of the ELF header. We'll use it here to reconstruct a minimal ELF, then automate with Python.

### 2a — Assemble a flat file

Start by concatenating the dumps in virtual address order:

```
$ cat region_hdr.bin region_text.bin region_ro.bin region_rw.bin > flat_dump.bin
$ ls -la flat_dump.bin
-rw-r--r-- 1 user user 24576 ... flat_dump.bin
```

The file is `0x6000` bytes (6 pages of 4 KB). The good news is that `region_hdr.bin` potentially already contains an ELF header — the one the UPX stub left in memory. Let's check:

```
$ xxd flat_dump.bin | head -4
00000000: 7f45 4c46 0201 0103 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 e813 4000 0000 0000  ..>.......@.....
00000020: 4000 0000 0000 0000 0000 0000 0000 0000  @...............
00000030: 0000 0000 4000 3800 0300 0000 0000 0000  ....@.8.........
```

The `\x7fELF` magic is present. However, this header reflects the **packed** binary's state — the entry point (`e_entry`) points to the stub, not the OEP, and the PHT describes the packed file's segments, not the decompressed code. Several fields need correcting.

### 2b — Fix the ELF header

Open `flat_dump.bin` in ImHex. You can load the `elf_header.hexpat` pattern from the repository (Chapter 6, section 6.4) to visualize the fields. The corrections to apply are:

**`e_entry` (offset `0x18`, 8 bytes, little-endian)** — The entry point. Replace the current value (stub address) with the OEP observed in GDB. If the OEP is `0x401000`:

```
Offset 0x18: 00 10 40 00 00 00 00 00
```

**`e_phoff` (offset `0x20`, 8 bytes)** — The program header table offset in the file. Usually located right after the ELF header, at offset `0x40` (64 in decimal, i.e., the ELF header size in 64-bit). Verify the value is correct; if the packed file moved the PHT, correct it.

**`e_shoff` (offset `0x28`, 8 bytes)** — The section header table offset. On a UPX-packed binary, this field is often `0` (table absent). We'll leave it at `0` for now and recreate the SHT in step 3.

**`e_phnum` (offset `0x38`, 2 bytes)** — The number of entries in the PHT. We'll update it after reconstructing the program headers.

**`e_shnum` (offset `0x3C`, 2 bytes)** — The number of entries in the SHT. Set to `0` if not reconstructing the SHT, or to the number of created sections otherwise.

### 2c — Reconstruct the program header table

The PHT must describe the segments as they exist in our reconstructed file. Each `Phdr` entry is 56 bytes in 64-bit ELF and contains the following fields:

```
Offset  Size    Field       Description
0x00    4       p_type      Segment type (1 = PT_LOAD)
0x04    4       p_flags     Permissions (PF_R=4, PF_W=2, PF_X=1)
0x08    8       p_offset    Offset in file
0x10    8       p_vaddr     Virtual address
0x18    8       p_paddr     Physical address (= p_vaddr in practice)
0x20    8       p_filesz    Size in file
0x28    8       p_memsz     Size in memory
0x30    8       p_align     Alignment (typically 0x1000)
```

For our binary, we create three `PT_LOAD` segments corresponding to the three useful regions (you can merge the header and code into one segment if preferred, or separate them for more precision):

**Segment 1 — Code (`r-x`)**:  
- `p_type` = `1` (`PT_LOAD`)  
- `p_flags` = `5` (`PF_R | PF_X`)  
- `p_offset` = `0x0000` (start of file — includes the header)  
- `p_vaddr` = `0x400000`  
- `p_filesz` = `0x4000`  
- `p_memsz` = `0x4000`  
- `p_align` = `0x1000`

**Segment 2 — Read-only data (`r--`)**:  
- `p_flags` = `4` (`PF_R`)  
- `p_offset` = `0x4000`  
- `p_vaddr` = `0x404000`  
- `p_filesz` = `0x1000`  
- `p_memsz` = `0x1000`

**Segment 3 — Read-write data (`rw-`)**:  
- `p_flags` = `6` (`PF_R | PF_W`)  
- `p_offset` = `0x5000`  
- `p_vaddr` = `0x405000`  
- `p_filesz` = `0x1000`  
- `p_memsz` = `0x2000` (larger than `p_filesz` if `.bss` exists — the difference will be zero-filled by the loader)

Write these entries at offset `0x40` in the file (right after the ELF header) and update `e_phnum` = `3`.

---

## Step 3 — Recreate a section header table (optional but recommended)

The SHT is not necessary for execution but dramatically transforms the quality of analysis in Ghidra. Without an SHT, Ghidra treats the entire `r-x` segment as a monolithic block of code. With an SHT, it can distinguish `.text` from `.init` and `.fini`, identify `.rodata` separately, and handle `.bss` correctly.

### Principle

The SHT is an array of `Shdr` structures (64 bytes each in 64-bit ELF) placed somewhere in the file (often at the end). Each entry describes a section with its name, type, flags, virtual address, file offset, and size.

Section names are stored in a special section of type `SHT_STRTAB` called `.shstrtab`, referenced by the `e_shstrndx` field of the ELF header.

### Minimum sections to recreate

For proper analysis in Ghidra, we recommend recreating at minimum the following sections:

| Section     | Type          | Flags       | Address    | Content                          |  
|-------------|---------------|-------------|------------|----------------------------------|  
| *(null)*    | `SHT_NULL`    | —           | `0`        | Mandatory entry (index 0)        |  
| `.text`     | `SHT_PROGBITS`| `AX`        | `0x401000` | Main executable code             |  
| `.rodata`   | `SHT_PROGBITS`| `A`         | `0x404000` | Read-only data                   |  
| `.data`     | `SHT_PROGBITS`| `WA`        | `0x405000` | Initialized data                 |  
| `.bss`      | `SHT_NOBITS`  | `WA`        | `0x406000` | Uninitialized data               |  
| `.shstrtab` | `SHT_STRTAB`  | —           | —          | Section name table               |

The flags are: `A` = `SHF_ALLOC` (the section occupies memory at runtime), `W` = `SHF_WRITE`, `X` = `SHF_EXECINSTR`.

Building `.shstrtab` simply consists of concatenating section names separated by null bytes:

```
\0.text\0.rodata\0.data\0.bss\0.shstrtab\0
```

Each `Shdr` entry references its section name by an offset into this string table.

### SHT placement in the file

Add the `.shstrtab` and SHT at the end of the file:

1. Write `.shstrtab` at the end of the current file. Note its offset.  
2. Write the 6 `Shdr` entries (6 × 64 = 384 bytes) immediately after. Note the start offset.  
3. Update the ELF header: `e_shoff` = SHT offset, `e_shnum` = 6, `e_shstrndx` = 5 (`.shstrtab` index).

---

## Step 4 — Automated reconstruction with `lief` (Python)

Manual reconstruction is an instructive exercise, but in real-world situations you use a script. The **LIEF** library (Library to Instrument Executable Formats, covered in Chapter 35) allows programmatic manipulation of ELF structures.

Here is the reconstruction script's logic. We create an empty ELF, insert segments and sections from the memory dumps, and set the entry point:

```python
import lief

# --- Parameters extracted from GDB ---
OEP        = 0x401000  
BASE_ADDR  = 0x400000  

regions = [
    # (dump_file,        vaddr,     perm,         section_name)
    ("region_hdr.bin",  0x400000, "r--",        None),
    ("region_text.bin", 0x401000, "r-x",        ".text"),
    ("region_ro.bin",   0x404000, "r--",        ".rodata"),
    ("region_rw.bin",   0x405000, "rw-",        ".data"),
]

# --- Create the ELF binary ---
elf = lief.ELF.Binary("reconstructed", lief.ELF.ELF_CLASS.CLASS64)  
elf.header.entrypoint = OEP  
elf.header.file_type  = lief.ELF.E_TYPE.EXECUTABLE  

for dump_path, vaddr, perms, sec_name in regions:
    data = open(dump_path, "rb").read()

    # Create PT_LOAD segment
    seg = lief.ELF.Segment()
    seg.type            = lief.ELF.SEGMENT_TYPES.LOAD
    seg.flags           = 0
    if "r" in perms: seg.flags |= lief.ELF.SEGMENT_FLAGS.R
    if "w" in perms: seg.flags |= lief.ELF.SEGMENT_FLAGS.W
    if "x" in perms: seg.flags |= lief.ELF.SEGMENT_FLAGS.X
    seg.virtual_address = vaddr
    seg.physical_address= vaddr
    seg.alignment       = 0x1000
    seg.content         = list(data)
    elf.add(seg)

    # Create the corresponding section
    if sec_name:
        sec = lief.ELF.Section(sec_name)
        sec.content         = list(data)
        sec.virtual_address = vaddr
        sec.alignment       = 0x10

        if "x" in perms:
            sec.type  = lief.ELF.SECTION_TYPES.PROGBITS
            sec.flags = (lief.ELF.SECTION_FLAGS.ALLOC |
                         lief.ELF.SECTION_FLAGS.EXECINSTR)
        elif "w" in perms:
            sec.type  = lief.ELF.SECTION_TYPES.PROGBITS
            sec.flags = (lief.ELF.SECTION_FLAGS.ALLOC |
                         lief.ELF.SECTION_FLAGS.WRITE)
        else:
            sec.type  = lief.ELF.SECTION_TYPES.PROGBITS
            sec.flags = lief.ELF.SECTION_FLAGS.ALLOC

        elf.add(sec, loaded=True)

# --- Write the result ---
elf.write("packed_sample_reconstructed")  
print("[+] Reconstructed ELF: packed_sample_reconstructed")  
```

> ⚠️ **Warning** — LIEF handles ELF internal consistency (offsets, alignments, string tables), eliminating the majority of manual calculation errors. However, the result may slightly differ from the original binary depending on the LIEF version and alignment heuristics used. The goal is not to reproduce the original binary byte-for-byte, but to obtain an ELF correct enough for static analysis.

### Alternative: `pyelftools` in write mode

The `pyelftools` library is primarily designed for reading, not writing. For reconstruction, LIEF is the recommended choice. If you prefer to stay in a minimal ecosystem, you can also build the ELF file byte-by-byte with Python's `struct` module, manually encoding each header field — this is essentially the automation of the manual procedure described in step 2, but in script form rather than hex editor.

---

## Step 5 — Validating the reconstructed ELF

Once the file is produced, perform a series of checks to ensure its validity.

### Structural verification with `readelf`

```
$ readelf -h packed_sample_reconstructed
```

Verify that the magic is correct, the type is `EXEC`, the architecture is `Advanced Micro Devices X86-64`, the entry point matches the OEP, and the PHT and SHT offsets are consistent.

```
$ readelf -l packed_sample_reconstructed
```

Verify that the `LOAD` segments cover the correct address ranges with the correct permissions.

```
$ readelf -S packed_sample_reconstructed
```

Verify the presence of `.text`, `.rodata`, `.data` sections with correct types and flags.

### Content verification with `strings` and `objdump`

```
$ strings packed_sample_reconstructed | grep FLAG
FLAG{unp4ck3d_and_r3c0nstruct3d}

$ objdump -d packed_sample_reconstructed | head -30
```

`objdump -d` should produce coherent disassembly starting from address `0x401000`, with recognizable functions (prologues, calls to PLT addresses, etc.).

### Execution test (optional, in sandbox)

If you want to verify the reconstructed binary is functional, you can try executing it in the sandboxed VM. This will only work if dynamic imports are correctly resolved, which isn't guaranteed after a memory dump reconstruction. The primary objective of reconstruction is **static analyzability**, not re-executability.

### Import into Ghidra

The final test is importing into Ghidra. Open the reconstructed file with default parameters and run auto-analysis. Points to check: does Ghidra correctly recognize the entry point? Does it identify the `main` function? Do `.rodata` strings appear in the Listing and Decompiler? Are cross-references between code and data resolved?

If Ghidra produces readable decompiled output for the program's functions (you should recognize `check_license_key`, `xor_decode`, `compute_checksum`...), the reconstruction is successful.

---

## Special cases and common difficulties

### The entry point doesn't point to `main`

In a standard GCC binary, `e_entry` points to `_start`, which calls `__libc_start_main`, which calls `main`. The CRT code (`_start`, `__libc_csu_init`, `__libc_csu_fini`) is normally included in the `.text` section. If the memory dump doesn't cover this area (for example because the CRT was provided by the stub and not by the original program), the reconstructed entry point may not correspond to `_start`. In this case, point `e_entry` directly to `main` (identifiable by its calls to `printf`, `fgets`, etc.) and accept that the binary won't be truly executable but perfectly analyzable.

### Dynamic imports and PLT/GOT

If the original program used shared libraries (which is the case for our `packed_sample`), the decompressed code contains `call` instructions to PLT entries that redirect to the GOT. In memory at dump time, the GOT may already contain resolved addresses (if lazy binding has been performed) or still contain the addresses of the PLT resolution routine.

Faithfully reconstructing the PLT/GOT and the `.dynamic`, `.dynsym`, `.dynstr` sections is considerable work beyond this section's scope. In practice, you have two options. The first is to do without for static analysis: Ghidra will see `call` instructions to fixed addresses, and the analyst can manually annotate them by identifying the relevant libc functions (from the constants passed as arguments, the number of parameters, etc.). The second is to recover these sections from the packed binary itself — some packers (including UPX) leave the `.dynamic` and `.dynsym` sections relatively intact on disk, since the stub needs them for post-decompression resolution.

### PIE (Position-Independent Executable) binaries

If the original binary was compiled with `-pie`, all addresses in the memory dump are relative to a base randomly chosen by the loader (ASLR). The reconstructed ELF will need to use the `ET_DYN` type (not `ET_EXEC`) and virtual addresses will need to be adjusted by subtracting the load base. You can find this base by comparing the address of `_start` in the dump with the offset of `_start` in the packed file (which is a relative offset from the base).

In our case, the Makefile compiles with `-no-pie`, which considerably simplifies reconstruction: virtual addresses in the dump directly correspond to addresses in the ELF file.

### `.bss` sections — uninitialized data

The `.bss` section takes no space in the ELF file (its on-disk size is zero) but reserves space in memory (zero-filled by the loader). In memory, `.bss` is located immediately after `.data`, in the same `rw-` page. The memory dump of the `rw-` region therefore contains both `.data` and `.bss`.

To separate the two in the reconstructed ELF, you need to determine where `.data` ends and `.bss` begins. Without symbols or the original SHT, the boundary is impossible to determine with certainty. The common heuristic is to look for a long sequence of zeros at the end of the `rw-` region — these zeros are probably `.bss`. When in doubt, you can simply include the entire region in `.data` (file size = memory size, no explicit `.bss`). Static analysis won't suffer significantly.

---

> 📌 **Key takeaway** — Reconstructing an ELF from memory dumps is an **iterative** process. Start with a minimal ELF (header + one single `LOAD` segment), import it into Ghidra, evaluate the analysis quality, then refine by adding sections and correcting metadata. Perfection is not the goal: an ELF "good enough" for Ghidra to produce readable decompiled output is a successful ELF.

⏭️ [Reanalyzing the unpacked binary](/29-unpacking/04-reanalyzing-binary.md)
