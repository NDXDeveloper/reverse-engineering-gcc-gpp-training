🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 29.2 — Static Unpacking (UPX) and Dynamic Unpacking (Memory Dump with GDB)

> 🎯 **Section objective** — Master the two major families of unpacking techniques: the **static** approach, which exploits the packer's own tool or reproduces its algorithm without execution, and the **dynamic** approach, which lets the stub do the work then captures the result from memory. We'll apply both to our binaries `packed_sample_upx` (standard UPX) and `packed_sample_upx_tampered` (altered UPX).

---

## Two philosophies, one goal

Unpacking consists of recovering the program's original code as it exists in memory after decompression. Two paths lead to this result:

- **Static unpacking** works on the file, without ever executing it. You use either the decompression command provided by the packer (when it exists and works), or a script that reimplements the decompression algorithm by analyzing the packed file's format. The advantage is safety — no potentially malicious code executes on the machine. The drawback is that this approach only works if you know (or can identify) the packer and its format.

- **Dynamic unpacking** executes the binary in a controlled environment and intercepts the memory state once the stub has finished. The stub does all the decompression work; the analyst only needs to capture the result at the right moment. The advantage is universality — the technique works regardless of the packer, including custom or deliberately altered packers. The drawback is that the binary actually executes, hence the absolute necessity of working in a sandboxed VM (Chapter 26).

In practice, you always attempt the static approach first. If it fails (unknown packer, altered signatures, custom packer), you switch to the dynamic approach.

---

## Part A — Static unpacking with UPX

### The simple case: `upx -d`

UPX natively provides a decompression option. This is the most favorable scenario:

```
$ cp packed_sample_upx packed_sample_upx_restored
$ upx -d packed_sample_upx_restored
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reese

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     18472 <-      7152   38.72%   linux/amd64   packed_sample_upx_restored

Unpacked 1 file.
```

UPX reads its own compression metadata (the `l_info`/`p_info` header located via the `UPX!` magic), decompresses the data, rebuilds the original sections, and restores the entry point. The resulting binary is functionally identical to the pre-packing binary.

You can immediately verify the result:

```
$ strings packed_sample_upx_restored | grep FLAG
FLAG{unp4ck3d_and_r3c0nstruct3d}

$ readelf -S packed_sample_upx_restored | head -5
There are 27 section headers, starting at offset 0x3a08:
```

The strings are back, all 27 standard sections are restored, and `checksec` once again shows the original binary's protections. Static unpacking with UPX is as simple as that — when signatures are intact.

### When `upx -d` fails

Let's try the same command on our altered variant:

```
$ cp packed_sample_upx_tampered test_restore
$ upx -d test_restore
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reese

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: test_restore: NotPackedException: not packed by UPX

Unpacked 0 files.
```

UPX looks for its `UPX!` magic to locate its internal structures. Since we replaced `UPX!` with `FKP!` in the Makefile, UPX no longer recognizes its own format and refuses decompression. This technique is trivial to implement (a few modified bytes) but sufficient to block the automated tool.

### Workaround: manually restoring signatures

Before switching to the dynamic approach, we can attempt a static repair. If we know the binary was packed with UPX then altered, we just need to restore the original magic bytes. We know the substitutions made by our Makefile (`FKP!` → `UPX!`, `XP_0` → `UPX0`, etc.), but in a real-world situation, you'd have to guess them.

The approach is to open the binary in ImHex and search for candidate patterns. We know the UPX magic is usually found near the end of the file and that section names are in the section header table. Searching for `FKP!` in ImHex:

```
$ python3 -c "
data = open('packed_sample_upx_tampered','rb').read()  
idx = data.find(b'FKP!')  
print(f'FKP! found at offset 0x{idx:X}')  
"
FKP! found at offset 0x1BD0
```

Replace `FKP!` with `UPX!` (and section names if necessary), save, and retry `upx -d`. This approach works for UPX because the underlying compression format hasn't changed — only the recognition signatures were altered.

However, this method has obvious limitations. If the packer modified not only the signatures but also the metadata structure, or if it's an entirely custom packer, static repair is impossible. This is where the dynamic approach comes in.

---

## Part B — Dynamic unpacking with GDB

Dynamic unpacking rests on a fundamental principle: **regardless of the packer, the original code eventually exists in plaintext in the process's memory**. The stub decompresses the code, then transfers control to the original entry point (Original Entry Point, or **OEP**). If you manage to interrupt execution just after this transfer, you can dump the memory regions containing the decompressed code.

### Step 1 — Understanding the stub's execution flow

Before setting breakpoints, it's useful to understand what the UPX stub does at a high level. The typical sequence is:

1. The Linux loader maps the packed file's segments into memory.  
2. Execution begins at the stub's entry point (`e_entry` in the ELF header).  
3. The stub decompresses data from the compressed segment to the destination segment (the `LOAD` segment with the large `MemSiz`).  
4. The stub restores dynamic imports if necessary (PLT/GOT symbol resolution).  
5. The stub performs a jump (`jmp` or `call` followed by `ret`) to the OEP — the real entry point of the original program.  
6. The original program executes normally.

The goal is to intercept execution between steps 5 and 6.

### Step 2 — Identifying the OEP with GDB

Let's launch the packed binary under GDB (with GEF or pwndbg installed):

```
$ gdb -q ./packed_sample_upx_tampered
```

Start by examining the file's entry point:

```
gef➤ info file  
Entry point: 0x4013e8  
```

This is the **stub's** entry point, not the original program's. Set a breakpoint on it and start execution:

```
gef➤ break *0x4013e8  
gef➤ run  
```

At this point, we're at the very beginning of the decompression stub. The approach for finding the OEP varies by packer, but for UPX, several techniques are well-established.

#### Technique A — Find the stub's last `jmp`

The UPX stub invariably ends with an unconditional jump to the OEP. This `jmp` is the last control transfer before the original program takes over. You could spot it by single-stepping through the stub with `stepi`, but that's tedious. A more efficient approach is to set a **hardware execution breakpoint** on a memory address known to belong to the decompressed code.

#### Technique B — Breakpoint on the destination segment

With `readelf -l`, we noted that the destination segment (the one with the large `MemSiz`) starts at a certain address. The original code will be decompressed to this area. Set a hardware execution breakpoint on the first bytes of this area:

```
gef➤ hbreak *0x401000  
gef➤ continue  
```

The hardware breakpoint (`hbreak` and not `break`) is essential here. A software breakpoint (`break`) writes an `int3` instruction at the target address, but this memory area will be overwritten by the stub during decompression, which would erase the breakpoint. A hardware breakpoint uses the processor's debug registers (DR0–DR3) and survives memory writes.

When the breakpoint is hit, we're at the first instructions of the decompressed original code. `rip` points to the OEP:

```
gef➤ info registers rip  
rip    0x401000  
```

#### Technique C — Breakpoint on `__libc_start_main`

If the original program is dynamically linked to libc (which isn't the case with standard UPX, but can be with other packers), you can set a breakpoint on `__libc_start_main`. This function is called by the CRT startup code (`_start`), and its first argument (in `rdi` per the System V AMD64 convention) is the address of `main()`. By inspecting `rdi` at the time of the call, you directly obtain `main`'s address in the decompressed code.

#### Technique D — Catch syscall execve

Some packers (not UPX, but more complex packers) decompress the binary into a temporary file then execute it via `execve`. In this case, a `catch syscall execve` in GDB will intercept the moment the "real" binary is launched.

### Step 3 — Map the decompressed memory regions

Once at the OEP, examine the process's memory map:

```
gef➤ vmmap
```

With GEF or pwndbg, `vmmap` displays all the process's memory regions with their permissions and the mapping source (file or anonymous). Identify the regions containing the decompressed code and data. Typically:

```
Start              End                Perm  Name
0x0000000000400000 0x0000000000401000 r--p  packed_sample_upx_tampered
0x0000000000401000 0x0000000000404000 r-xp  packed_sample_upx_tampered
0x0000000000404000 0x0000000000405000 r--p  packed_sample_upx_tampered
0x0000000000405000 0x0000000000406000 rw-p  packed_sample_upx_tampered
```

The relevant regions are those marked `r-xp` (decompressed executable code) and `rw-p` (decompressed data). Note the start and end addresses of each region.

> 💡 **GEF tip** — The `xinfo <address>` command gives details about the memory region containing a given address. Useful for verifying that an address belongs to the decompressed code and not to the stub.

### Step 4 — Dump the memory

GDB allows saving memory regions to files with the `dump` command:

```
gef➤ dump binary memory code.bin 0x401000 0x404000  
gef➤ dump binary memory data_ro.bin 0x404000 0x405000  
gef➤ dump binary memory data_rw.bin 0x405000 0x406000  
```

Each command creates a binary file containing an exact copy of the memory between the two specified addresses. These files contain the decompressed machine code and the original program's data.

You can also dump the entire mapped memory space in a single command with pwndbg:

```
pwndbg> dumpmem /tmp/full_dump/ --writable --executable
```

Or use the `/proc` method from a second terminal (knowing the PID of the process stopped under GDB):

```
$ cat /proc/<pid>/maps
$ dd if=/proc/<pid>/mem bs=1 skip=$((0x401000)) count=$((0x3000)) \
     of=code.bin 2>/dev/null
```

### Step 5 — Immediate verification of the dump

Before moving on to reconstruction (section 29.3), verify that the dump actually contains the original code:

```
$ strings code.bin | grep FLAG
FLAG{unp4ck3d_and_r3c0nstruct3d}

$ strings code.bin | grep "Enter your"
[*] Enter your license key (format RE29-XXXX):
```

If the program's characteristic strings are present in the dump, the extraction succeeded. You can also check for coherent opcodes at the beginning of the dump:

```
$ objdump -b binary -m i386:x86-64 -D code.bin | head -20
```

You should recognize valid x86-64 instructions — function prologues (`push rbp` / `mov rbp, rsp` at `-O0`, or `sub rsp, ...` at `-O2`), calls (`call`), etc. — and not the random noise you'd get if the dump was done too early (before decompression finished) or at the wrong addresses.

---

## When dynamic unpacking gets complicated

The procedure described above works directly for UPX and the majority of simple packers. Some more advanced packers add obstacles that you'll encounter in real-world analyses:

### Multi-pass decompression

Some packers chain multiple layers of compression or encryption. The first-level stub decompresses a second-level stub, which itself decompresses the original code. In this case, the hardware breakpoint on the destination segment triggers too early — you land on the intermediate stub, not the final code. The solution is to iterate: once the first breakpoint is hit, examine the code, determine it's not yet the original program, and set a new breakpoint on the next transfer jump.

### Anti-debugging in the stub

The stub can include anti-debugging checks (Chapter 19, section 19.7): calling `ptrace(PTRACE_TRACEME)` to detect GDB, checking `/proc/self/status` for a tracer presence, or timing measurements to detect single-stepping. The bypasses covered in Chapter 19 apply directly here. With GDB, you can use `catch syscall ptrace` to intercept the call and force its return value to 0 with `set $rax = 0` before continuing.

### Memory permission rewriting

Sophisticated packers use `mprotect` to change memory page permissions during decompression: the destination area is first `RW-` (to write the decompressed code), then switched to `R-X` (to execute it), and finally the stub area is set to `---` (inaccessible) to erase its traces. If you dump too late, the stub may have already erased some useful information. A `catch syscall mprotect` in GDB lets you track these transitions.

### Relocated original code

If the original binary was compiled as PIE (`-pie`), the addresses in the decompressed code are relative and must be relocated. The stub normally handles this relocation before transferring control, but the memory dump will contain absolute addresses corresponding to the location chosen by the loader for this particular execution. The reconstruction (section 29.3) will need to account for this.

---

## Summary: unpacking decision tree

The decision logic follows a simple path:

```
The binary is packed (confirmed in 29.1)
│
├─ The packer is identified (UPX, Ezuri...)
│  │
│  ├─ Does the decompression tool work?
│  │  ├─ YES → upx -d (or equivalent) → done
│  │  └─ NO → Altered signatures?
│  │     ├─ YES → Attempt magic byte repair → retry
│  │     └─ NO → Switch to dynamic
│  │
│  └─ No decompression tool available → Switch to dynamic
│
└─ Unknown / custom packer → Go directly to dynamic
   │
   ├─ 1. Launch under GDB in the sandboxed VM
   ├─ 2. Find the OEP (hbreak destination segment / last jmp)
   ├─ 3. Map memory regions (vmmap)
   ├─ 4. Dump code + data (dump binary memory)
   └─ 5. Verify the dump (strings, objdump -D)
```

The raw dumps obtained at step 5 are not yet ELF files usable by Ghidra or radare2. Transforming these dumps into an analyzable ELF is the subject of the next section (29.3 — Reconstructing the original ELF).

---

> 📌 **Key takeaway** — Static unpacking is always preferable when possible: faster, safer, and the result is often a complete ELF. Dynamic unpacking is the universal solution but produces raw dumps that require reconstruction work. In practice, both approaches are complementary: you try static, then validate (or correct) with dynamic.

⏭️ [Reconstructing the original ELF: fixing headers, sections and entry point](/29-unpacking/03-reconstructing-elf.md)
