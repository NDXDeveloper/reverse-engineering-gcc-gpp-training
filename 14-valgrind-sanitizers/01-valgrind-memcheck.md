🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 14.1 — Valgrind / Memcheck — memory leaks and runtime behavior

> 🎯 **Goal of this section**: Master using Valgrind Memcheck on a target binary to extract structural information exploitable in RE — allocation sizes, buffer lifetimes, sensitive data flows — from memory error and leak reports.

---

## What is Valgrind?

Valgrind is a framework for **dynamic binary instrumentation** on Linux. Concretely, it intercepts a program's execution instruction by instruction, without modifying it on disk, and injects analysis code on the fly. The target program executes in a kind of software virtual machine controlled by Valgrind.

The fundamental point for us: **Valgrind requires no recompilation or modification of the binary**. It works on any ELF executable — stripped, optimized, without symbols. That's what makes it a full-fledged RE tool and not just a development tool.

Valgrind is actually a suite of tools (called "tools") sharing the same instrumentation engine. The main ones are:

- **Memcheck** (default tool) — detects memory access errors, leaks, uninitialized reads.  
- **Callgrind** — call and instruction profiler (covered in section 14.2).  
- **Massif** — heap usage profiler.  
- **Helgrind** / **DRD** — race-condition detectors in multi-threaded programs.

In this section, we focus on **Memcheck**, the most useful tool in an RE context.

---

## How Memcheck instruments execution

To understand what Memcheck can teach us and what its limits are, it's useful to know how it works under the hood.

### The shadow memory model

Memcheck maintains a **shadow copy** of every byte of memory used by the program. For each real byte, Memcheck stores two pieces of information:

- **Addressability bit** (A-bit): is this byte in a valid zone? Was it allocated by `malloc`, is it part of the active stack, or does it belong to a mapped segment? Access to a byte whose A-bit is "invalid" triggers an *Invalid read* or *Invalid write* error.  
- **Definedness bit** (V-bit): has this byte been initialized? Has a value been written to it since its allocation? Use of a byte whose V-bit is "undefined" in a condition, system call, or I/O operation triggers a *Conditional jump or move depends on uninitialised value(s)* or *Syscall param ... contains uninitialised byte(s)* error.

### What this means for RE

This shadow memory model implies that Memcheck tracks **every byte manipulated by the program**, from its allocation to its release. By reading the reports, you get:

- The **exact sizes of each dynamic allocation** — when Memcheck reports a leak of 32 bytes allocated at address `0x5204a0`, you know a 32-byte structure exists in the program.  
- The **precise moment when data is written then read** — uninitialized read errors indicate buffers that are allocated but not yet filled, characteristic of cryptographic key buffers or network receive buffers.  
- **Buffer overflows** — an *Invalid read of size 4* just past the end of a 64-byte block tells you the program indexes a 64-byte array and exceeds its limit.

### Instrumentation cost

Memcheck slows execution by a factor of approximately **10 to 50x**. This means for a binary that runs in one second, the analysis will take between 10 and 50 seconds. For most training binaries in this course, that's perfectly acceptable. For long-running or interactive programs, you'll sometimes need to adapt the strategy (limit inputs, automate interactions).

---

## Basic launch

The fundamental command to analyze a binary with Memcheck:

```bash
valgrind ./my_binary arg1 arg2
```

Memcheck is the default tool, so it's not necessary to specify it explicitly. However, for clarity, you can write:

```bash
valgrind --tool=memcheck ./my_binary arg1 arg2
```

The program runs normally (inputs/outputs, user interactions), but all memory activity is instrumented. At the end of execution, Memcheck displays a summary on `stderr`.

### Essential options for RE

Here is the command line we'll systematically use in this training:

```bash
valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --verbose \
    --log-file=valgrind_report.txt \
    ./my_binary arg1 arg2
```

Let's detail each option:

**`--leak-check=full`** — Enables detailed leak reporting. Without this option, Memcheck only gives a global summary (total bytes lost). With `full`, you get for each leak: block size, address, and the call stack at the moment of allocation. It's this call stack that interests us in RE: it reveals which function allocated the buffer.

**`--show-leak-kinds=all`** — By default, Memcheck only shows "definitely lost" and "possibly lost" leaks. In RE, "still reachable" leaks (blocks still accessible at program exit but never freed) are equally interesting: they often correspond to persistent global structures like configuration tables, caches, or cryptographic contexts.

**`--track-origins=yes`** — When Memcheck detects use of an uninitialized value, this option traces back to the **origin** of the non-initialization (the block allocation or variable declaration). This costs a bit more memory and time, but is indispensable for understanding data flow. Without this option, you know an uninitialized value is used, but not where it comes from.

**`--verbose`** — Displays additional information about the analysis process, loaded libraries, and instrumentation statistics.

**`--log-file=valgrind_report.txt`** — Redirects Valgrind's output to a file. This is important because Memcheck writes to `stderr`, which mixes with the target program's error output. With a dedicated file, you cleanly separate both streams and can analyze the report at leisure.

---

## Anatomy of a Memcheck report

A Memcheck report consists of three main parts: errors detected during execution, the leak summary at exit, and global statistics. Let's examine each in detail.

### Report header

```
==12345== Memcheck, a memory error detector
==12345== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==12345== Using Valgrind-3.22.0 and LibVEX; rerun with -h for copyright info
==12345== Command: ./ch14-crypto encrypt secret.txt output.enc
==12345== Parent PID: 6789
```

The number `12345` is the analyzed process's PID. It prefixes each report line, which allows untangling outputs when analyzing multiple processes (for example a fork). The `Command:` line recalls exactly the launched command — useful when analyzing several variants of the same binary.

### Memory access errors

These are errors reported **during execution**, at the moment they occur.

#### Invalid read / Invalid write

```
==12345== Invalid read of size 4                          ← read size
==12345==    at 0x401A3F: ??? (in ./ch24-crypto)          ← faulting instruction address
==12345==    by 0x401B12: ??? (in ./ch24-crypto)          ← caller
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)          ← caller's caller
==12345==    by 0x7FEDC3: (below main) (libc-start.c:308)
==12345==  Address 0x5204a40 is 0 bytes after a block of size 64 alloc'd
==12345==    at 0x4C2FB0F: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x40198A: ??? (in ./ch24-crypto)
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)
```

Let's dissect this report from an RE perspective:

- **`Invalid read of size 4`** — The program attempts to read 4 bytes at an invalid address. The size `4` likely indicates access to an `int` or `uint32_t`.  
- **`at 0x401A3F`** — The address of the instruction performing the read. You can find it in Ghidra, objdump, or GDB to precisely identify the instruction.  
- **The call stack** (`by 0x401B12`, `by 0x4012E8`) — Without symbols, you see `???`, but the addresses are exploitable. You can cross-reference them with the disassembly to reconstruct the call path.  
- **`Address 0x5204a40 is 0 bytes after a block of size 64 alloc'd`** — This is the most precious line. It tells us the read address is located **immediately after** a 64-byte block allocated by `malloc`. In other words, the program accesses `buffer[64]` on a 64-size buffer, i.e., an **off-by-one** or **array overflow**.

> 💡 **RE tip** — The mention "0 bytes after a block of size N" is a reliable indicator of the actual size of a dynamically allocated structure. Note this size: it will help you reconstruct the corresponding `struct` in Ghidra.

- **The allocation stack** (`at 0x4C2FB0F: malloc`, `by 0x40198A`) — We know the function at address `0x40198A` is the one that allocated this 64-byte block. In RE, it's often an initialization function or a constructor.

#### Conditional jump depends on uninitialised value

```
==12345== Conditional jump or move depends on uninitialised value(s)
==12345==    at 0x401C7E: ??? (in ./ch24-crypto)
==12345==    by 0x401D45: ??? (in ./ch24-crypto)
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)
==12345==  Uninitialised value was created by a heap allocation
==12345==    at 0x4C2FB0F: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401B89: ??? (in ./ch24-crypto)
```

This error type is particularly interesting in crypto RE. It tells us a **branch decision** in the program depends on data that hasn't been initialized yet. In a cryptographic context, this can indicate:

- A key buffer allocated but not yet filled at the moment the program tries to use it in a calculation.  
- An uninitialized IV (initialization vector) — which is both a security bug and a structural indicator for RE.  
- An internal state of a PRNG (pseudo-random number generator) using uninitialized memory as an entropy source (bad practice, but common in amateur code).

> 💡 **RE tip** — With `--track-origins=yes`, the line "Uninitialised value was created by a heap allocation at ..." gives you the address of the function that allocated the buffer. Correlated with the usage address, you can trace the data flow between allocation and first use — it's a rudimentary but effective form of taint analysis.

#### Syscall param contains uninitialised byte(s)

```
==12345== Syscall param write(buf) points to uninitialised byte(s)
==12345==    at 0x4F4E810: write (write.c:27)
==12345==    by 0x401E23: ??? (in ./ch24-crypto)
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)
==12345==  Address 0x5205040 is 8 bytes inside a block of size 128 alloc'd
==12345==    at 0x4C2FB0F: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401DA1: ??? (in ./ch24-crypto)
```

This report tells us the program passes to the `write()` system call a buffer containing uninitialized bytes. Exploitable information:

- The buffer is **128 bytes** (allocated block size).  
- Uninitialized bytes start **8 bytes** inside the block — so the first 8 bytes are initialized. This strongly resembles an **8-byte header** followed by a partially uninitialized payload.  
- The function at `0x401E23` is the one writing data to a file descriptor, probably a network send or encrypted-file write function.  
- The function at `0x401DA1` is the one that allocated the 128-byte buffer.

> 💡 **RE tip** — When Memcheck reports "Address 0x... is N bytes inside a block of size M", the pair (N, M) gives you the offset and buffer size. If you observe N equals 8, 16, or 32, it's often a structure header followed by a payload.

### The leak summary

At the end of execution, Memcheck displays a summary of all allocated blocks that weren't freed:

```
==12345== HEAP SUMMARY:
==12345==     in use at exit: 2,160 bytes in 5 blocks
==12345==   total heap usage: 23 allocs, 18 frees, 4,832 bytes allocated
==12345==
==12345== 32 bytes in 1 blocks are definitely lost in loss record 1 of 5
==12345==    at 0x4C2FB0F: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401B89: ??? (in ./ch24-crypto)
==12345==    by 0x401C12: ??? (in ./ch24-crypto)
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)
==12345==
==12345== 64 bytes in 1 blocks are definitely lost in loss record 2 of 5
==12345==    at 0x4C2FB0F: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401A20: ??? (in ./ch24-crypto)
==12345==    by 0x401B89: ??? (in ./ch24-crypto)
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)
==12345==
==12345== 240 bytes in 1 blocks are still reachable in loss record 3 of 5
==12345==    at 0x4C2FB0F: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==12345==    by 0x401C30: ??? (in ./ch24-crypto)
==12345==    by 0x4012E8: ??? (in ./ch24-crypto)
==12345==
==12345== LEAK SUMMARY:
==12345==    definitely lost: 96 bytes in 2 blocks
==12345==    indirectly lost: 0 bytes in 0 blocks
==12345==      possibly lost: 0 bytes in 0 blocks
==12345==    still reachable: 1,528 bytes in 3 blocks
==12345==         suppressed: 0 bytes in 0 blocks
```

#### Leak categories and their meaning in RE

**Definitely lost** — Blocks whose pointer was lost: no program variable points to them anymore. In RE, these blocks often correspond to temporary allocations (intermediate calculation buffers, conversion buffers, parsing results) the developer forgot to free. The size of these blocks is a direct indicator of the program's temporary structure sizes.

**Indirectly lost** — Blocks accessible only through a "definitely lost" block. For example, if a structure contains a pointer to a buffer, and the structure itself is lost, the buffer is "indirectly lost". In RE, this reveals **nested structures** — a parent structure containing pointers to sub-structures.

**Possibly lost** — Blocks whose Memcheck isn't certain are lost — typically when a pointer points to the middle of a block rather than its beginning. In C++, this happens with interior pointers (pointer to a member of an allocated object). In RE, it's an indicator of structure manipulation with offsets (access via offset rather than via the base pointer).

**Still reachable** — Blocks still pointed to by variables at program exit, but never freed. It's technically a leak, but often intentional (global allocations implicitly freed at exit). In RE, these blocks are particularly interesting because they correspond to the program's **persistent structures**: crypto contexts, configuration tables, caches, global state.

> 💡 **RE tip** — The line "total heap usage: 23 allocs, 18 frees, 4,832 bytes allocated" gives a profile of the program's memory management. If the allocation count is very high relative to program size, it probably uses dynamic structures (linked lists, trees, maps). If instead there are few large allocations, it pre-allocates fixed buffers.

---

## Reading addresses and correlating with disassembly

On a stripped binary, Memcheck displays `???` instead of function names. Raw addresses are nonetheless exploitable. Here's the method to correlate them with the disassembly.

### Step 1 — Note the report's key addresses

In the previous example, interesting addresses are:

- `0x401B89` — allocates a 32-byte block  
- `0x401DA1` — allocates a 128-byte block  
- `0x4019F0` — allocates a 1024-byte block  
- `0x401A3F` — performs an invalid 4-byte read  
- `0x401C7E` — uses an uninitialized value in a branch

### Step 2 — Find these addresses in the disassembly

With `objdump`:

```bash
objdump -d -M intel ./ch24-crypto | grep -A 5 "401b89"
```

Or in Ghidra, using `G` (Go to Address) and entering `0x401b89`.

The instruction at this address will typically be a `call` to `malloc@plt` or the instruction right after (the return address). Going back in the function, you can identify the allocation logic: what calculations determine the size passed to `malloc`, where this size comes from, etc.

### Step 3 — Combine with GDB

You can set a breakpoint at the address reported by Valgrind to inspect the program's state at the time of the error:

```bash
gdb ./ch24-crypto
(gdb) break *0x401A3F
(gdb) run encrypt secret.txt output.enc
```

> ⚠️ **Warning** — You can't run GDB *inside* Valgrind (or vice versa) trivially. The approach is sequential: first run Valgrind to get interesting addresses, then use GDB separately to inspect those addresses. However, Valgrind offers a built-in GDB server via `--vgdb=yes` that allows attaching GDB to a program being analyzed by Valgrind (see the box below).

### Valgrind's built-in GDB server

Valgrind has a powerful but little-known feature: a **built-in GDB server** that allows debugging the program *during* its execution under Valgrind. This combines the best of both worlds: Memcheck's memory instrumentation and GDB's interactive control.

```bash
# Terminal 1: launch Valgrind with the GDB server enabled
valgrind --vgdb=yes --vgdb-error=0 ./ch24-crypto encrypt secret.txt output.enc
```

The `--vgdb-error=0` option tells Valgrind to stop **before the program's first instruction** and wait for a GDB connection.

```bash
# Terminal 2: connect with GDB
gdb ./ch24-crypto
(gdb) target remote | vgdb
(gdb) continue
```

From there, GDB controls the program's execution through Valgrind. You can set breakpoints, inspect memory, and simultaneously benefit from Memcheck diagnostics. When Memcheck detects an error, execution automatically stops in GDB, allowing you to inspect the program's exact state at the moment of the error.

> 💡 **RE tip** — With `--vgdb-error=1`, Valgrind only stops at the first Memcheck error. It's often the most practical mode: you let the program run freely until Memcheck detects something interesting, then you switch to GDB to explore.

---

## Suppression files

When analyzing a binary with Memcheck, you'll often see dozens of errors from **system libraries** (glibc, libstdc++, libcrypto, etc.) that don't directly concern the target program. These false positives — or rather, errors in code that doesn't interest us — pollute the report and complicate analysis.

Valgrind uses **suppression files** (`.supp`) to filter these known errors. The system ships with default suppressions (often in `/usr/lib/valgrind/default.supp`), but they don't cover everything.

### Generate a suppression file

```bash
valgrind --gen-suppressions=all --log-file=raw_report.txt ./ch24-crypto encrypt secret.txt output.enc
```

The `--gen-suppressions=all` option makes Memcheck display, after each error, a ready-to-copy suppression block. You then extract the suppressions you want to ignore and place them in a `my_project.supp` file:

```
{
   glibc_cond_uninit
   Memcheck:Cond
   obj:/usr/lib/x86_64-linux-gnu/libc.so.6
}
{
   libcrypto_reachable
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   obj:/usr/lib/x86_64-linux-gnu/libcrypto.so.*
}
```

### Use a suppression file

```bash
valgrind --leak-check=full --suppressions=./my_project.supp ./ch24-crypto encrypt secret.txt output.enc
```

> 💡 **RE tip** — Build your suppression file iteratively. On the first run, identify errors from system libraries and suppress them. On the second run, the report will only contain errors from the target binary. This `.supp` file becomes a reusable artifact for all analyses of the same type of binary.

---

## Concrete case: analyzing `ch24-crypto` under Memcheck

Let's put all this into practice on Chapter 24's encryption binary. The goal is to extract structural information **before even opening Ghidra**.

### Launching the analysis

```bash
valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --log-file=ch24_valgrind.txt \
    ./ch24-crypto encrypt testfile.txt output.enc
```

First create a test file:

```bash
echo "This is a test file for Valgrind analysis" > testfile.txt
```

### Methodical information extraction

After execution, open `ch24_valgrind.txt` and proceed with systematic reading. Here's the type of information you can extract and how to record it:

**1. Global allocation profile** — Start with the `HEAP SUMMARY`:

```
==12345== total heap usage: 15 allocs, 12 frees, 3,456 bytes allocated
```

15 allocations for a file-encryption program is relatively few. The program probably uses fixed-size buffers rather than dynamic allocations in a loop. The 3 unfreed blocks (15 - 12 = 3) are our priority targets.

**2. Leaking block inventory** — Note each unfreed block with its size and allocating function's address:

| Size | Category | Allocation function | RE hypothesis |  
|--------|-----------|----------------------|--------------|  
| 32 bytes | definitely lost | `0x401B89` | AES-256 key (256 bits = 32 bytes) |  
| 16 bytes | definitely lost | `0x401B45` | IV / nonce (128 bits = 16 bytes) |  
| 1024 bytes | still reachable | `0x4019F0` | File read/write buffer |

The sizes of 32 and 16 bytes are immediately suspicious in an encryption program: 32 bytes = 256 bits (AES-256 key size) and 16 bytes = 128 bits (AES block size, and therefore an IV size for CBC/CTR modes).

**3. Uninitialized read errors** — If Memcheck reports use of an uninitialized value in the function manipulating the 32-byte block, this suggests the key is **derived** from another buffer (for example by a KDF) and there's a moment when the buffer is allocated but not yet filled.

**4. Partial call graph construction** — By collecting all call-stack addresses from the various error reports, you can reconstruct a partial call graph:

```
0x4012E8 (main or wrapper)
├── 0x4019F0 → allocates 4096 bytes (file buffer) — freed in cleanup
├── 0x401B89 → allocates 32 bytes (probable key)
├── 0x401A20 → allocates 64 bytes (derivation salt)
├── 0x401B45 → allocates 16 bytes (probable IV)
├── 0x401C30 → allocates 240 bytes (crypto context)
├── 0x401C12 → uses the 32-byte block (key expansion)
├── 0x401DA1 → allocates 128 bytes (per-block output buffer)
└── 0x401E23 → writes the 128-byte buffer (write syscall)
```

This graph, obtained **solely from the Memcheck report**, already gives us a structural understanding of the program: initialization, crypto buffer allocation, encryption, result writing.

> 💡 **RE tip** — Before even opening the disassembler, note these addresses and sizes in a working file. When you open the binary in Ghidra, you can directly rename functions: `0x401B89` → `alloc_key_buffer`, `0x401B45` → `alloc_iv_buffer`, etc. This Valgrind pre-work considerably accelerates the subsequent static analysis.

---

## Advanced options useful in RE

### Deep origin tracking

```bash
valgrind --track-origins=yes --expensive-definedness-checks=yes ./my_binary
```

The `--expensive-definedness-checks=yes` option activates additional checks on undefined-value propagation through arithmetic and logical operations. It's slower, but allows detecting subtle cases where an uninitialized value is masked by an operation (`xor`, `and`) before being used — a common pattern in cryptographic code.

### Tracking file descriptors

```bash
valgrind --track-fds=yes ./my_binary
```

This option lists all file descriptors open and not closed at program exit. In RE, this reveals files, sockets, and pipes manipulated by the program, with descriptor numbers — information directly correlatable with `read`/`write`/`send`/`recv` calls observed in the disassembly.

### Limiting analysis to an address range

Memcheck instruments the entire process, including shared libraries. You can't limit instrumentation to an address range, but you can filter the report after the fact:

```bash
grep "by 0x40" ch24_valgrind.txt | sort -u
```

This command extracts all call addresses in the binary's `.text` segment (typically at `0x40xxxx` for a non-PIE binary), eliminating duplicates. You thus get the list of all binary functions involved in memory operations reported by Memcheck.

> ⚠️ **Warning** — For a PIE (Position Independent Executable) binary, addresses will be randomized at each execution. You can disable ASLR to get stable addresses:  
> ```bash  
> setarch x86_64 -R valgrind --leak-check=full ./my_pie_binary  
> ```  
> The `-R` option of `setarch` disables address randomization for this process only.

---

## Memcheck limits in an RE context

Memcheck is a powerful tool, but it's important to know its limits to avoid over-interpreting its reports.

**Memcheck only detects errors that occur.** If a code path containing a buffer overflow isn't executed during analysis, Memcheck won't report it. Coverage depends on the provided inputs. That's why we'll often combine Memcheck with fuzzing (Chapter 15): the fuzzer generates varied inputs exercising different paths, and Memcheck detects errors on those paths.

**Memcheck doesn't detect stack overflows.** Stack A-bits are managed in a simplified way. A stack buffer overflow will only be detected if it goes beyond the mapped stack zone. For stack buffer overflows, sanitizers (ASan, see section 14.3) are more effective.

**Memcheck doesn't detect out-of-bounds accesses within a single allocated block.** If a program allocates a 128-byte block and accesses byte 100 when it should only access the first 64, Memcheck won't report anything (the address is in a valid block). Only accesses *past* the block's end or *before* its start are detected.

**The slowdown is significant.** The 10-50x factor can make analysis impractical for interactive or long-running programs. In these cases, prefer short executions with targeted inputs.

**Statically linked binaries cause problems.** If the binary includes its own copy of `malloc`/`free` (static link with glibc), Memcheck won't be able to intercept allocations automatically. You'll need to use the `--soname-synonyms` option or more advanced redirection techniques.

---

## Summary: what Memcheck teaches us in RE

To conclude this section, here are the concrete pieces of information you can extract from a Memcheck report and their direct utility in reverse engineering:

| Memcheck information | RE utility |  
|---|---|  
| Allocated block sizes | Size of the program's structures / buffers |  
| Allocation function address | Identification of initialization functions |  
| Allocation call stacks | Partial call graph, without symbols |  
| Offset of invalid accesses within a block | Structure field layout |  
| Uninitialized reads | Data flows, crypto key buffers |  
| Leak categories (lost/reachable) | Distinction between temporary vs persistent structures |  
| Unclosed file descriptors | Files and sockets manipulated |  
| Global allocation profile | Complexity of the program's memory management |

Memcheck is a **first-pass** tool: it doesn't give all the answers, but it provides a working framework — addresses, sizes, relationships between functions — that considerably accelerates the static analysis that follows.

---


⏭️ [Callgrind + KCachegrind — profiling and call graph](/14-valgrind-sanitizers/02-callgrind-kcachegrind.md)
