🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 12.4 — Heap analysis with pwndbg (`vis_heap_chunks`, `bins`)

> **Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg**  
> **Part III — Dynamic Analysis**

---

## Why analyze the heap in reverse engineering?

The heap is the memory region where a program dynamically allocates data at runtime via `malloc`, `calloc`, `realloc`, and `new`. In reverse engineering, the heap is omnipresent: dynamically constructed strings, network receive buffers, on-the-fly allocated data structures, C++ objects instantiated with `new` — all of this resides on the heap.

Understanding the heap's state at a given moment allows answering concrete questions during analysis. Where does the program store the password entered by the user? What is the size of the buffer allocated for network data? When is a C++ object freed, and is its memory actually cleared or does the content persist? Does a custom encryption use a temporary heap buffer to store the derived key?

Beyond RE, heap analysis is fundamental in vulnerability exploitation. Use-after-free, double-free, heap overflow, and heap corruption bugs are among the most exploited vulnerabilities today. Understanding them — even just to detect them during an audit — requires knowing how to read the allocator's internal state.

pwndbg is the extension that excels in this domain. Its heap commands directly parse the internal structures of the glibc allocator (`ptmalloc2`) and present them in a readable form. GEF offers similar but less detailed commands. PEDA offers virtually nothing in this area. That's why this section focuses on pwndbg, with mentions of GEF when an equivalent exists.

---

## Reminder: how the glibc allocator (ptmalloc2) works

To read the output of pwndbg's heap commands, you need to understand the basic concepts of the glibc allocator. This section provides the necessary minimum — a complete study of ptmalloc2 is a subject in itself that goes beyond this chapter's scope.

### Chunks

The fundamental unit of the glibc heap is the **chunk**. Each call to `malloc(n)` returns a pointer to a chunk's data area. The chunk itself begins a few bytes before this pointer, in a header (metadata) that the allocator uses for its internal management.

On x86-64, an allocated chunk's header contains two 8-byte fields:

- `prev_size` (8 bytes): size of the previous chunk, only if the latter is free. When the previous chunk is in use, this field is recycled as data space by the previous chunk.  
- `size` (8 bytes): total size of the current chunk (header included), aligned to 16 bytes. The 3 least significant bits of this field are flags: `PREV_INUSE` (bit 0), `IS_MMAPPED` (bit 1), and `NON_MAIN_ARENA` (bit 2).

The pointer returned by `malloc` points to the data that immediately follows this 16-byte header. When the analyst sees an address returned by `malloc`, the chunk's header is located 16 bytes before.

### Freed chunks and bins

When a chunk is freed by `free`, it's not returned to the operating system — it's inserted into a **free chunk list** called a **bin**. The allocator maintains several bin categories to optimize reuse:

**Tcache bins** (Thread-Local Cache, introduced in glibc 2.26) are singly-linked per-thread lists, indexed by chunk size. Each tcache bin can hold up to 7 chunks of the same size. It's the first place the allocator looks during a new `malloc` of matching size. Tcache bins are the fastest but also the simplest to exploit in case of vulnerability, as they perform few integrity checks.

**Fastbins** are global singly-linked lists (shared between threads) for small chunks (up to 160 bytes by default on x86-64). They work in LIFO (Last In, First Out): the last freed chunk is the first reallocated.

The **unsorted bin** is a doubly-linked list that serves as a temporary buffer. When a freed chunk doesn't fit in a fastbin or tcache, it's placed in the unsorted bin. During a subsequent `malloc`, the allocator walks the unsorted bin and sorts chunks into appropriate bins.

**Small bins** (62 bins for sizes 32 to 1008 bytes) and **large bins** (63 bins for larger sizes) are sorted doubly-linked lists that contain chunks after their passage through the unsorted bin.

### The arena and the top chunk

The **arena** is the allocator's main data structure. It contains pointers to all bins, the synchronization mutex, and global metadata. The main process uses the **main arena**, and additional threads can create secondary arenas.

The **top chunk** is the chunk at the upper boundary of the heap. When no bin contains a chunk of sufficient size to satisfy a `malloc`, the allocator carves from the top chunk. If the top chunk itself is too small, the heap is extended via `brk` or `mmap`.

---

## pwndbg's heap commands

### `heap` — overview

The `heap` command (without arguments) displays the list of all heap chunks, in address order:

```
pwndbg> heap  
Allocated chunk | PREV_INUSE  
Addr: 0x555555559000  
Size: 0x291  

Allocated chunk | PREV_INUSE  
Addr: 0x555555559290  
Size: 0x21  

Free chunk (tcachebins) | PREV_INUSE  
Addr: 0x5555555592b0  
Size: 0x31  

Allocated chunk | PREV_INUSE  
Addr: 0x5555555592e0  
Size: 0x41  

Top chunk | PREV_INUSE  
Addr: 0x555555559320  
Size: 0x20ce1  
```

Each entry indicates the chunk's address, size, and state (allocated, free with the bin type, or top chunk). The `PREV_INUSE` flag is noted when active — which is the normal case for a chunk whose previous neighbor is in use.

This view allows quickly mapping the heap: how many chunks exist, what their sizes are, which are free. It's often the first command to type when analyzing the heap.

### `vis_heap_chunks` — visual representation

`vis_heap_chunks` (or its alias `vis`) is pwndbg's most emblematic command for heap analysis. It produces a graphical representation of chunks in memory, with per-chunk coloring that lets you immediately see boundaries, headers, and data:

```
pwndbg> vis_heap_chunks
```

The output looks like this (colors are represented here by comments):

```
0x555555559000  0x0000000000000000  0x0000000000000291  ........  ← chunk 1 header
0x555555559010  0x0000000000000000  0x0000000000000000  ........
...
0x555555559290  0x0000000000000000  0x0000000000000021  ........  ← chunk 2 header (size=0x21)
0x5555555592a0  0x00000000deadbeef  0x0000000000000000  ........  ← chunk 2 data
0x5555555592b0  0x0000000000000000  0x0000000000000031  ........  ← chunk 3 header (free, size=0x31)
0x5555555592c0  0x0000555555559010  0x0000000000000000  ........  ← chunk 3 fd pointer
...
0x555555559320  0x0000000000000000  0x0000000000020ce1  ........  ← top chunk
```

In a terminal with colors, each chunk is displayed in a different color (alternating hues), which makes chunk boundaries immediately visible. Each header's `size` field is highlighted. For free chunks, the `fd` (forward) and `bk` (backward) pointers of bin lists are visible in the data area.

You can limit the display to an address range or a number of chunks:

```
pwndbg> vis_heap_chunks 5              # the first 5 chunks  
pwndbg> vis_heap_chunks 0x555555559290 3  # 3 chunks starting from this address  
```

`vis_heap_chunks` is irreplaceable for understanding the heap's spatial layout. By seeing chunks side by side with their sizes, the analyst can spot a heap overflow (a chunk whose data spills into the next chunk's header), a corrupted chunk (inconsistent size), or simply understand how the program organizes its structures in memory.

### `bins` — state of free chunk lists

The `bins` command displays the state of all allocator bin categories:

```
pwndbg> bins  
tcachebins  
0x30 [  1]: 0x5555555592c0 ◂— 0x0

fastbins  
empty  

unsortedbin  
empty  

smallbins  
empty  

largebins  
empty  
```

This output indicates that a chunk of size 0x30 is present in the tcache, and that all other bin categories are empty. The format for each entry shows the size, the number of chunks in brackets, then the bin's pointer chain.

When multiple chunks of the same size are freed, the list grows:

```
tcachebins
0x30 [  3]: 0x555555559370 —▸ 0x555555559340 —▸ 0x5555555592c0 ◂— 0x0
```

Reading is left to right: `0x555555559370` is the list head (the next chunk that will be returned by a `malloc(0x20)`), followed by `0x555555559340`, then `0x5555555592c0`. The final `0x0` indicates the end of the list.

pwndbg also offers specialized commands per category:

```
pwndbg> tcachebins       # tcache bins only  
pwndbg> fastbins         # fastbins only  
pwndbg> unsortedbin      # unsorted bin only  
pwndbg> smallbins        # small bins only  
pwndbg> largebins        # large bins only  
```

### `top_chunk` — the boundary chunk

```
pwndbg> top_chunk  
Top chunk  
Addr: 0x555555559320  
Size: 0x20ce1  
```

This command displays the top chunk's address and size. The top chunk's size decreases with each `malloc` not satisfied by a bin, and increases when the heap is extended. Monitoring the top chunk's evolution helps understand the program's allocation pattern.

### `arena` — allocator metadata

```
pwndbg> arena  
Arena main_arena (at 0x7ffff7e19c80)  
  Top:           0x555555559320
  Last Remainder: 0x0
  Bins:          ...
  Fastbins:      ...
```

The `arena` command displays the main arena's metadata (or a specified arena). It's useful for verifying that the allocator is not in a corrupted state and for manually finding bin pointers if needed.

### `mp_` — global allocator parameters

```
pwndbg> mp_  
mp_ @ 0x7ffff7e1b280 {  
  trim_threshold   = 131072,
  top_pad          = 131072,
  mmap_threshold   = 131072,
  arena_test       = 8,
  arena_max        = 0,
  n_mmaps          = 0,
  n_mmaps_max      = 65536,
  max_n_mmaps      = 0,
  no_dyn_threshold = 0,
  mmapped_mem      = 0,
  max_mmapped_mem  = 0,
  sbrk_base        = 0x555555559000,
  tcache_bins      = 64,
  tcache_max_bytes = 1032,
  tcache_count     = 7,
  tcache_unsorted_limit = 0,
}
```

These parameters govern the allocator's behavior: `tcache_count` confirms the maximum number of chunks per tcache bin (7 by default), `tcache_max_bytes` indicates the maximum size for a chunk to be eligible for tcache, and `mmap_threshold` is the size beyond which `malloc` uses `mmap` rather than heap extension via `brk`.

### `malloc_chunk` — inspecting a specific chunk

To examine a given chunk in detail:

```
pwndbg> malloc_chunk 0x555555559290  
Allocated chunk | PREV_INUSE  
Addr: 0x555555559290  
prev_size: 0x0  
size: 0x21  
fd: 0xdeadbeef  
bk: 0x0  
```

The `fd` and `bk` fields are only meaningful for a freed chunk (they form the list links). For an allocated chunk, these bytes are part of user data — here, the value `0xdeadbeef` is simply data stored by the program.

---

## Equivalents in GEF

GEF offers a family of `heap` commands that cover part of pwndbg's features:

```
gef➤ heap chunks          # list of chunks (equivalent of pwndbg's `heap`)  
gef➤ heap bins             # bin state (equivalent of `bins`)  
gef➤ heap bins tcache      # tcache bins only  
gef➤ heap bins fast        # fastbins only  
gef➤ heap bins unsorted    # unsorted bin only  
gef➤ heap chunk 0x555555559290   # specific chunk inspection  
gef➤ heap arenas           # list of arenas  
```

GEF doesn't offer a direct equivalent of `vis_heap_chunks` — it's pwndbg's most differentiating command. GEF's chunk display is textual and linear, without the per-chunk coloring that makes visual reading so effective. For serious heap analysis, pwndbg remains the tool of choice.

GEF partially compensates with the `heap set-arena` command for working with non-main arenas in multi-threaded programs, and with heap-corruption detection heuristics that display warnings when inconsistencies are detected.

---

## Practical heap-analysis strategy

Heap analysis isn't an abstract exercise — it answers concrete questions. Here is a methodology adapted to the reverse-engineering context.

### Mapping allocations

The first step is understanding the program's allocation pattern. Set a breakpoint after the initialization phase (for example at the beginning of user-input processing) and examine the heap:

```
pwndbg> break main  
pwndbg> run  
pwndbg> next 20          # advance past the first initializations  
pwndbg> heap  
```

This gives a snapshot of the heap at a given moment. Note the chunk sizes: chunks of 0x21 (16 bytes of data + 16 of header, aligned) are typical of small structures or short strings. Chunks of 0x411 (1024 bytes of data) suggest a read buffer. Unusually sized chunks may indicate complex data structures.

### Tracking a specific allocation

To trace a specific buffer's allocation, set a breakpoint on `malloc` and observe the requested size (in `RDI`) and the returned address (in `RAX` after return):

```
pwndbg> break malloc  
pwndbg> commands  
> silent
> printf "malloc(%d) = ", $rdi
> finish
> printf "%p\n", $rax
> continue
> end
pwndbg> run
```

This GDB script displays each `malloc` call with its size and result. Cross-referencing this information with `vis_heap_chunks` lets you identify which chunk contains which data.

For a more targeted approach, a conditional breakpoint filters on a specific size:

```
pwndbg> break malloc if $rdi == 256
```

### Observing frees and reuse

Setting a breakpoint on `free` reveals when and which chunks are freed:

```
pwndbg> break free  
pwndbg> commands  
> silent
> printf "free(%p)\n", $rdi
> continue
> end
```

After a series of allocations and frees, `bins` shows chunks available for reuse. If a program frees a chunk containing sensitive data (encryption key, password) without clearing it beforehand, that data persists in the free chunk and is visible with `vis_heap_chunks` — a major point of interest for Chapter 24 (reversing a binary with encryption).

### Detecting anomalies

`vis_heap_chunks` makes heap corruptions visible. A chunk whose `size` field doesn't align with the start of the next chunk indicates corruption. A free chunk whose `fd` pointer points outside the heap suggests a write-after-free or heap overflow. pwndbg displays warning messages when it detects such inconsistencies:

```
pwndbg> heap
...
Corrupt chunk | PREV_INUSE  
Addr: 0x5555555593a0  
Size: 0x4141414141414141 (invalid)  
```

A size of `0x4141414141414141` is the classic sign of an overflow that wrote `'A'` (0x41) over the chunk's header — exactly the type of vulnerability you seek to identify during an audit.

---

## Combining with Frida and Valgrind

pwndbg's heap commands offer a snapshot at a breakpoint. For a more dynamic view, they complement the tools seen in neighboring chapters.

**Frida** (Chapter 13) allows hooking `malloc` and `free` to log all allocation operations continuously, without setting breakpoints that slow execution. The Frida script can record the complete allocation history, then you switch to pwndbg to inspect the resulting state at a specific moment.

**Valgrind / Memcheck** (Chapter 14) detects memory leaks and invalid heap accesses with an execution overhead, but without requiring manual breakpoints. Valgrind's reports can guide pwndbg analysis: if Memcheck reports a use-after-free at address `0x5555555592c0`, you know exactly which chunk to examine with `malloc_chunk`.

The combined approach — Valgrind for global diagnosis, pwndbg for detailed inspection, Frida for continuous tracing — constitutes a complete arsenal for heap analysis in reverse engineering.

---

## Limits and caveats

pwndbg's heap commands rely on parsing glibc's internal structures. This implies several limitations.

**Dependency on glibc version.** ptmalloc2's internal structures evolve between glibc versions. Tcache was introduced in glibc 2.26. Integrity checks on `fd` pointers (safe-linking) were added in glibc 2.32. pwndbg maintains support for different versions, but a mismatch is possible with very recent or very old versions. The `heap` command displays a warning if it detects an incompatibility.

**Alternative allocators.** If the program uses a custom allocator (jemalloc, tcmalloc, mimalloc, or a homemade allocator), pwndbg's heap commands won't work — they're specific to ptmalloc2. pwndbg displays an error message in this case. Analysis must then be done manually by identifying the alternative allocator's structures in the binary.

**Statically linked binaries.** When glibc is statically linked, pwndbg may have trouble locating the allocator's internal symbols (`main_arena`, `mp_`). The `set main-arena` command allows manually specifying the address if pwndbg doesn't find it automatically.

**Multi-threaded programs.** Programs with multiple threads can use secondary arenas. By default, heap commands operate on the main arena. To inspect a specific arena:

```
pwndbg> arenas                    # list all arenas  
pwndbg> heap --arena 0x7ffff0000b60  # inspect a specific arena  
```

---


⏭️ [Useful commands specific to each extension](/12-gdb-extensions/05-specific-commands.md)
