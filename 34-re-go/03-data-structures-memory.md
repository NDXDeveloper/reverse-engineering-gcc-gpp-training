🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 34.3 — Go Data Structures in Memory: slices, maps, interfaces, channels

> 🐹 *In C, an array is a pointer, a string is a null-terminated pointer, and an "interface" does not exist at the language level. In Go, every fundamental data structure carries metadata in memory — length, capacity, type pointer, internal counter. For the reverse engineer, these structures have fixed and recognizable layouts that, once mastered, allow you to quickly reconstruct a Go program's logic from the disassembly.*

---

## Preamble: Sizes and Alignment on amd64

Throughout this section, sizes and offsets are given for the **amd64** architecture (Linux 64-bit), which is the primary target of this training course. On amd64:

- a pointer occupies 8 bytes,  
- a Go `int` occupies 8 bytes (Go fixes the size of `int` to the machine word size),  
- natural alignment is 8 bytes for 8-byte types.

On arm64, the sizes are identical. On 32-bit architectures, divide by two.

---

## Slices

The slice is the most ubiquitous data structure in Go. Every `[]byte`, `[]int`, `[]string`, and even variadic arguments (section 34.2) are slices.

### Memory Layout

A slice is a **24-byte header** composed of three fields:

```
Offset   Size     Field       Description
──────   ──────   ─────       ───────────
+0x00    8        ptr         Pointer to the first element of the underlying array
+0x08    8        len         Number of elements currently in the slice
+0x10    8        cap         Total capacity of the underlying array
```

Schematic representation:

```
         Slice header (24 bytes)                     Backing array
       ┌──────────┬──────┬──────┐               ┌───┬───┬───┬───┬───┐
       │   ptr  ──┼──────┼──────┼─────────────► │ 0 │ 1 │ 2 │ . │ . │
       ├──────────┤      │      │               └───┴───┴───┴───┴───┘
       │   len=3  │      │      │                 ◄── len ──►
       ├──────────┤      │      │                 ◄────── cap ──────►
       │   cap=5  │      │      │
       └──────────┴──────┴──────┘
```

### What You Will See in Assembly

When a slice is passed as an argument (new ABI ≥ 1.17), it consumes **three consecutive registers**:

```asm
; Call to process(data []byte)
; RAX = ptr   (pointer to the backing array)
; RBX = len   (length)
; RCX = cap   (capacity)
CALL    main.process
```

With the old ABI (< 1.17), these three values occupy three consecutive 8-byte slots on the stack.

Accessing an element `data[i]` typically produces:

```asm
; Accessing data[i] in a loop
; RAX = ptr, RBX = len, RCX = current index
CMP     RCX, RBX               ; bounds check: i < len?  
JAE     runtime.panicIndex      ; if i >= len → panic  
MOVZX   EDX, BYTE PTR [RAX+RCX] ; load data[i]  
```

The `CMP` + `JAE` before each access is Go's **bounds checking**. It is an extremely frequent and immediately recognizable pattern. In a tight loop, you will see it at every iteration (unless the compiler was able to prove the index is always valid and eliminated it — which happens with optimizations).

> 💡 **RE tip**: the pattern `CMP reg, reg; JAE runtime.panicIndex` is a reliable marker of a slice or array access. By spotting it, you know that the register being compared contains an index and the other contains the length. This helps you reconstruct loops.

### Slice vs Array

A Go array (`[5]int`) is a fixed-size value, allocated in place (on the stack or within a struct). It has **no** header — it is just `5 × 8 = 40` contiguous bytes. Slices, on the other hand, are always 24-byte headers pointing to an array.

In RE, the distinction is made by usage: if you see three registers (ptr, len, cap) or three consecutive words on the stack, it is a slice. If you see direct access to a fixed-size block without a header, it is an array.

### `append` and Growth

The `append` operation can trigger a reallocation if `len == cap`. The compiler generates a call to `runtime.growslice`:

```asm
; s = append(s, elem)
CMP     RBX, RCX               ; len == cap?  
JNE     .no_grow                ; no → direct append  
; Need to grow
CALL    runtime.growslice       ; allocate a new backing array
; RAX = new ptr, RBX = new len, RCX = new cap
.no_grow:
; Write the element at position len, increment len
```

> 💡 **RE tip**: a `CALL runtime.growslice` tells you that a slice is being built dynamically — typically in a data accumulation loop. This is often a clue that the function parses or collects elements.

---

## Maps

Go maps (`map[K]V`) are hash tables implemented by the runtime. Their internal structure is significantly more complex than slices.

### Memory Layout: `runtime.hmap`

A `map` type variable in Go is a **pointer** to a `runtime.hmap` structure:

```
runtime.hmap (simplified, amd64)  
Offset   Size     Field         Description  
──────   ──────   ─────         ───────────
+0x00    8        count          Number of elements in the map
+0x08    1        flags          Internal state (iterator, writing, etc.)
+0x09    1        B              Log2 of the number of buckets (2^B buckets)
+0x0A    2        (padding)
+0x0C    4        noverflow      Approximate number of overflow buckets
+0x10    8        hash0          Random seed for the hash function
+0x18    8        buckets        Pointer to the current bucket array
+0x20    8        oldbuckets     Pointer to the old buckets (during a rehash)
+0x28    8        nevacuate      Evacuation progress counter
+0x30    8        extra          Pointer to pre-allocated overflow buckets
```

Each bucket contains 8 key-value pairs organized as follows:

```
bmap (bucket, simplified)
┌──────────────────────────────┐
│  tophash [8]uint8            │  ← 8 bytes: high hash of each key
├──────────────────────────────┤
│  keys [8]KeyType             │  ← 8 × sizeof(K) bytes
├──────────────────────────────┤
│  values [8]ValueType         │  ← 8 × sizeof(V) bytes
├──────────────────────────────┤
│  overflow *bmap              │  ← pointer to the next overflow bucket
└──────────────────────────────┘
```

Keys and values are grouped separately (all keys together, then all values) rather than interleaved. This is a memory alignment optimization that reduces padding.

### What You Will See in Assembly

Creating a map generates a call to `runtime.makemap`:

```asm
; m := make(map[string]int)
; The compiler passes a pointer to the type descriptor
LEA     RAX, [type.map[string]int]   ; type descriptor  
XOR     EBX, EBX                      ; hint = 0 (initial size)  
CALL    runtime.makemap  
; RAX = pointer to hmap
```

Read access (`v := m[key]`) goes through `runtime.mapaccess1` or `runtime.mapaccess2` (the `2` variant additionally returns a boolean `ok`):

```asm
; v, ok := m[key]
LEA     RAX, [type.map[string]int]  
MOV     RBX, [address_of_m]           ; hmap pointer  
LEA     RCX, [key]                    ; pointer to the key  
CALL    runtime.mapaccess2_faststr    ; optimized variant for string keys  
; RAX = pointer to the value (or to a zero value if absent)
; RBX = bool (ok)
```

Writing (`m[key] = value`) uses `runtime.mapassign`:

```asm
LEA     RAX, [type.map[string]int]  
MOV     RBX, [address_of_m]  
LEA     RCX, [key]  
CALL    runtime.mapassign_faststr  
; RAX = pointer to the slot where the value should be written
MOV     QWORD PTR [RAX], value       ; write the value into the slot
```

Deletion (`delete(m, key)`) goes through `runtime.mapdelete`.

> 💡 **RE tip**: the `_fast32`, `_fast64`, `_faststr` variants of map functions are optimized versions for common key types. The suffix reveals the key type: `faststr` → `string`, `fast64` → `int64` or `uint64`, `fast32` → `int32` or `uint32`. This is free type information.

### Iterating Over a Map

The loop `for k, v := range m` translates to a pair of calls:

```asm
CALL    runtime.mapiterinit    ; initialize an iterator (hiter structure on the stack)
.loop:
; Check if the iterator is done
CMP     QWORD PTR [RSP+offset_key], 0   ; key pointer == nil?  
JEQ     .done  
; ... process the key and value ...
CALL    runtime.mapiternext    ; advance to the next element  
JMP     .loop  
.done:
```

The `hiter` structure (the iterator) is approximately 120 bytes and is allocated on the caller's stack. The `mapiterinit` + `mapiternext` loop pattern is characteristic of a `range` over a map.

### Dumping a Map from GDB

To inspect a map during dynamic analysis, you need to navigate the structure manually:

1. Retrieve the `hmap` pointer (register or stack depending on context).  
2. Read the `count` field at offset `+0x00` to get the number of elements.  
3. Read `B` at offset `+0x09` to calculate the number of buckets (`1 << B`).  
4. Read `buckets` at offset `+0x18` to get the start of the bucket array.  
5. Walk through each bucket by reading the `tophash`, then the keys and values.

> 💡 **RE tip**: a shortcut during dynamic analysis is to set a breakpoint on `runtime.mapaccess1` or `runtime.mapassign` and observe the arguments. You will get the type descriptor (which reveals the K and V types) and the key being looked up or inserted — without having to parse the internal structure.

---

## Interfaces

Interfaces are the central mechanism for polymorphism in Go. In memory, they take two forms depending on whether the interface is empty or not.

### Non-Empty Interface: `runtime.iface`

An interface declaring at least one method (for example `Validator` in our crackme) is represented by an `iface`:

```
runtime.iface (16 bytes)  
Offset   Size     Field   Description  
──────   ──────   ─────   ───────────
+0x00    8        tab     Pointer to the itab (interface table)
+0x08    8        data    Pointer to the concrete value
```

The `itab` is the key to dynamic dispatch. It contains the virtual method table for a given (concrete type, interface type) pair:

```
runtime.itab (simplified)  
Offset   Size     Field       Description  
──────   ──────   ─────       ───────────
+0x00    8        inter       Pointer to the interface's type descriptor
+0x08    8        _type       Pointer to the concrete type's type descriptor
+0x10    4        hash        Hash of the concrete type (speeds up type assertions)
+0x14    4        (padding)
+0x18    8        fun[0]      Pointer to the 1st method of the concrete type
+0x20    8        fun[1]      Pointer to the 2nd method (if applicable)
...      ...      fun[N]      ...
```

The `fun` array contains the function pointers in the same order as the methods declared in the interface. This is Go's equivalent of the C++ vtable, but with a major difference: in C++, the vtable is associated with the concrete type, while the Go itab is specific to the (concrete type, interface) pair.

### Dynamic Dispatch in Assembly

When code calls a method on an interface:

```go
var v Validator = &ChecksumValidator{...}  
v.Validate(group, index)  
```

The compiler generates:

```asm
; RAX = itab pointer (iface.tab)
; RBX = data pointer (iface.data)
; --- Loading the method pointer from the itab ---
MOV     RCX, [RAX+0x18]       ; RCX = itab.fun[0] (address of Validate)
; --- Preparing arguments ---
MOV     RAX, RBX               ; arg1 = receiver (data pointer)
; ... other arguments in the following registers ...
CALL    RCX                    ; indirect call via the method pointer
```

The pattern `MOV reg, [itab+offset]; CALL reg` is the signature of Go interface dispatch. The offset in the itab depends on the method index: `+0x18` for the first, `+0x20` for the second, etc.

> 💡 **RE tip**: when you see a `CALL reg` (indirect call) with the register loaded from a structure at a fixed offset, it is almost certainly an interface dispatch. To find out which method is being called, find the itab in memory and read the corresponding function pointer — it will lead you to the concrete implementation.

### Empty Interface: `runtime.eface`

The empty interface `interface{}` (or `any` since Go 1.18) does not need an itab since it declares no methods. Its representation is simpler:

```
runtime.eface (16 bytes)  
Offset   Size     Field    Description  
──────   ──────   ─────    ───────────
+0x00    8        _type    Pointer to the concrete type's type descriptor
+0x08    8        data     Pointer to the concrete value
```

The difference from `iface`: the first field points directly to the type descriptor instead of an itab. In assembly, conversions to `interface{}` go through `runtime.convT` (or its variants `convT64`, `convTstring`, etc.) rather than `runtime.convI` (which builds an itab).

### Type Assertions and Type Switches

The type assertion `v.(ConcreteType)` translates to a comparison of the type hash stored in the itab:

```asm
; val, ok := v.(ConcreteType)
MOV     RAX, [interface_tab]         ; load the itab  
MOV     ECX, [RAX+0x10]             ; load itab.hash  
CMP     ECX, hash_du_type_attendu   ; compare with the hash known at compile time  
JNE     .not_match  
; ... extract the value ...
```

A `type switch` produces a cascade of similar hash comparisons.

> 💡 **RE tip**: the hash constants in type assertion comparisons are computed at compile time. If you find the same constants in the `runtime._type` entries listed in `.rodata`, you can identify the concrete types being tested.

---

## Channels

Channels are the communication mechanism between goroutines. In memory, a channel is a pointer to a `runtime.hchan` structure.

### Memory Layout: `runtime.hchan`

```
runtime.hchan (simplified, amd64)  
Offset   Size     Field       Description  
──────   ──────   ─────       ───────────
+0x00    8        qcount      Number of elements currently in the buffer
+0x08    8        dataqsiz    Size of the circular buffer (0 = unbuffered)
+0x10    8        buf         Pointer to the circular buffer
+0x18    8        elemsize    Size of one element
+0x20    4        closed      Flag: is the channel closed?
+0x24    4        (padding)
+0x28    8        elemtype    Pointer to the element type descriptor
+0x30    8        sendx       Write index in the circular buffer
+0x38    8        recvx       Read index in the circular buffer
+0x40    8        recvq       Wait queue of goroutines reading (waitq)
+0x48    8        sendq       Wait queue of goroutines writing (waitq)
+0x50    8        lock        Internal mutex (runtime.mutex)
```

### Unbuffered vs Buffered Channels

The distinction is made by the `dataqsiz` field:

- **Unbuffered** (`make(chan int)`): `dataqsiz = 0`, `buf` is nil. Each send blocks until a receiver is ready.  
- **Buffered** (`make(chan int, 10)`): `dataqsiz = 10`, `buf` points to a circular array of 10 elements.

### What You Will See in Assembly

Creating a channel:

```asm
; ch := make(chan int, 4)
LEA     RAX, [type.chan int]    ; type descriptor  
MOV     RBX, 4                  ; buffer size  
CALL    runtime.makechan  
; RAX = pointer to hchan
```

Sending on a channel (`ch <- value`):

```asm
; ch <- value
MOV     RAX, [address_ch]       ; hchan pointer  
LEA     RBX, [value]           ; pointer to the value to send  
CALL    runtime.chansend1  
```

Receiving from a channel (`value := <-ch`):

```asm
; value := <-ch
MOV     RAX, [address_ch]       ; hchan pointer  
LEA     RBX, [destination]      ; pointer where the received value will be written  
CALL    runtime.chanrecv1  
```

The `select` (channel multiplexing) produces a call to `runtime.selectgo`, which takes an array of `scase` (select cases) describing each branch:

```asm
LEA     RAX, [tableau_scase]  
MOV     RBX, nombre_de_cas  
CALL    runtime.selectgo  
; RAX = index of the selected case
```

> 💡 **RE tip**: the `runtime.chansend1` and `runtime.chanrecv1` calls reveal the synchronization points between goroutines. By setting breakpoints on these functions and inspecting the `hchan` pointer, you can trace inter-goroutine data flows. Read `hchan.elemtype` to find out the transmitted type, and `hchan.qcount` to see how many elements are waiting in the buffer.

### Closing a Channel

Closing (`close(ch)`) goes through `runtime.closechan`. The `closed` field at offset `+0x20` is set to a non-zero value.

---

## Strings

Go strings are **not** null-terminated. This fundamental difference from C has direct consequences in RE.

### Memory Layout: `runtime.stringHeader`

```
String header (16 bytes)  
Offset   Size     Field   Description  
──────   ──────   ─────   ───────────
+0x00    8        ptr     Pointer to the UTF-8 data (not null-terminated)
+0x08    8        len     Length in bytes
```

This is the same layout as a slice, but **without the `cap` field** — Go strings are immutable; they cannot grow.

### Consequences for RE

1. **`strings` (the command) misses strings.** The `strings` utility looks for sequences of printable bytes terminated by a null or of minimum length. Go strings, stored end-to-end without nulls between them in `.rodata`, form a long continuous sequence. `strings` may merge them into a single giant string or split them incorrectly.

2. **String comparisons are not `strcmp`.** In Go, comparing two strings is done first by length, then by `memcmp`:

```asm
; Comparing two strings s1 and s2
CMP     RCX, RDI               ; compare lengths  
JNE     .not_equal              ; if len(s1) != len(s2) → not equal  
; Lengths match → compare contents
MOV     RDI, RAX               ; ptr1  
MOV     RSI, RBX               ; ptr2  
MOV     RDX, RCX               ; len  
CALL    runtime.memequal  
; or inline: REPE CMPSB
```

3. **String literals are concatenated in `.rodata`.** The Go compiler stores all string constants in a contiguous area of `.rodata`. Each usage references an offset and a length within this area. The same byte sequence can be shared between multiple strings (partial interning).

> 💡 **RE tip**: to correctly extract Go strings, do not rely on the `strings` command. Instead, use the metadata from `gopclntab` or the `runtime.stringHeader` structures referenced in the code. In section 34.5, we will see techniques dedicated to properly extracting Go strings.

### Strings in Arguments (New ABI)

Since a string is a 16-byte header (ptr + len), it consumes **two consecutive registers** when passed as an argument:

```asm
; Call to process(s string)
; RAX = ptr (pointer to the UTF-8 data)
; RBX = len (length)
CALL    main.process
```

This is the same behavior as for interfaces (2 words → 2 registers). Keep this in mind when counting a function's arguments.

---

## Structures (structs)

### Memory Layout

Go structs follow the same padding and alignment rules as C:

```go
type Header struct {
    Magic   uint32   // +0x00, 4 bytes
    Version uint8    // +0x04, 1 byte
    // 3 bytes padding to align the next field
    Length  uint64   // +0x08, 8 bytes
    Flags   uint16   // +0x10, 2 bytes
    // 6 bytes padding to align the struct to 8 bytes
}
// Total size: 24 bytes
```

The Go compiler **never** reorders fields — the memory order is guaranteed to match the declaration order. This is a valuable property for RE: if you can recover the source definition (via the runtime's type metadata, see below), the mapping to memory is direct.

### Type Metadata: `runtime._type`

Go embeds type descriptors in the binary for the GC, reflection, and interfaces. Each type has a `runtime._type`:

```
runtime._type (simplified)  
Offset   Size     Field       Description  
──────   ──────   ─────       ───────────
+0x00    8        size        Type size in bytes
+0x08    8        ptrdata     Size of the area containing pointers (for the GC)
+0x10    4        hash        Type hash (used by interfaces)
+0x14    1        tflag       Type flags
+0x15    1        align       Alignment
+0x16    1        fieldAlign  Field alignment within a struct
+0x17    1        kind        Type kind (bool, int, slice, map, struct, etc.)
+0x18    8        equal       Pointer to the equality function
+0x20    8        gcdata      Pointer bitmap for the GC
+0x28    4        str         Offset to the type name (in a string table)
+0x2C    4        ptrToThis   Offset to the type *T
```

The `kind` field at offset `+0x17` is a constant among:

| Value | Go type |  
|---|---|  
| 1 | `bool` |  
| 2 | `int` |  
| 3 | `int8` |  
| ... | ... |  
| 17 | `array` |  
| 18 | `chan` |  
| 19 | `func` |  
| 20 | `interface` |  
| 21 | `map` |  
| 22 | `ptr` |  
| 23 | `slice` |  
| 24 | `string` |  
| 25 | `struct` |

For composite types (struct, map, slice, etc.), extended descriptors follow the base `_type`. For example, a `structType` adds the list of fields with their names, types, and offsets.

> 💡 **RE tip**: `runtime._type` descriptors survive stripping. They are essential to the runtime (GC, reflection, interfaces) and cannot be removed without breaking the program. By parsing them, you can reconstruct the program's type definitions — names, fields, sizes. This is a source of information that C will never give you.

---

## Visual Summary

```
              Header
Type          size      Header fields                  Assembly pattern
────────────  ────────  ─────────────────────────────  ────────────────────────────────
slice         24 bytes  ptr, len, cap                  3 registers or 3 stack slots  
string        16 bytes  ptr, len                       2 registers or 2 stack slots  
interface     16 bytes  itab/type, data                2 registers; CALL [itab+0x18]  
map           8 bytes   *hmap (pointer only)           1 register; CALL runtime.mapaccess*  
channel       8 bytes   *hchan (pointer only)          1 register; CALL runtime.chansend1/chanrecv1  
struct        variable  aligned fields, source order   access by fixed offsets  
```

---

## Key Takeaways

1. **Count the registers.** A slice argument consumes 3 registers, a string or interface consumes 2, a pointer (map, channel) consumes 1. This counting is your main tool for reconstructing signatures.  
2. **Recognize the runtime functions.** `runtime.makeslice`, `runtime.growslice`, `runtime.makemap`, `runtime.mapaccess*`, `runtime.makechan`, `runtime.chansend1`, `runtime.chanrecv1` — each call tells you what type of structure is being manipulated.  
3. **Bounds checks are your friends.** The `CMP; JAE runtime.panicIndex` pattern reveals slice and array accesses, and gives you the length and index in the registers.  
4. **The `_fast*` suffixes reveal types.** `mapaccess1_fast64` → `int64` key, `mapassign_faststr` → `string` key.  
5. **The `runtime._type` descriptors are a gold mine.** They survive stripping and allow reconstructing the program's types. We will exploit them in detail in sections 34.4 and 34.6.  
6. **Strings are not null-terminated.** Do not trust the `strings` command — the specific techniques in section 34.5 are essential.

⏭️ [Recovering Function Names: `gopclntab` and `go_parser` for Ghidra/IDA](/34-re-go/04-gopclntab-go-parser.md)
