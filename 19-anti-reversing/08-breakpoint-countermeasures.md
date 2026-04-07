🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.8 — Breakpoint countermeasures (self-modifying code, int3 scanning)

> 🎯 **Objective**: Understand how a binary can detect or neutralize breakpoints set by a debugger, know the two main countermeasure families — opcode scanning and self-modifying code — and master the bypass techniques that enable debugging despite these protections.

---

## How a software breakpoint works

To understand the countermeasures, you must first understand what they target. A software breakpoint is the most common type of breakpoint in GDB. Its operation is mechanical:

1. The analyst requests a breakpoint at a given address (`break *0x401234`).  
2. GDB **saves** the original byte at that address.  
3. GDB **writes** the opcode `0xCC` (`int3` instruction) in place of the target instruction's first byte.  
4. When the processor reaches that address, it executes `int3`, generating a `SIGTRAP` signal.  
5. The kernel notifies GDB (via `ptrace`). GDB regains control.  
6. GDB **restores** the original byte, displays the program state, and waits for commands.

The crucial point is step 3: the breakpoint physically modifies code in memory. The `0xCC` byte is written in the process's `.text` section. This byte is visible to the process itself if it inspects its own memory. This is the property countermeasures exploit.

## Technique 1 — `int3` opcode scanning (`0xCC`)

### Principle

The idea is direct: the binary reads its own instructions in memory and searches for the `0xCC` byte. If `0xCC` appears where it shouldn't be, a debugger has set a breakpoint.

### Implementation in our binary

Our `anti_reverse.c` binary implements this technique in `scan_int3`:

```c
static int scan_int3(void)
{
    const uint8_t *fn_ptr = (const uint8_t *)verify_password;

    for (int i = 0; i < 128; i++) {
        if (fn_ptr[i] == 0xCC) {
            return 1; /* breakpoint detected */
        }
    }
    return 0;
}
```

The binary casts the `verify_password` function pointer to a byte pointer, then scans the first 128 bytes looking for `0xCC`. If GDB has set a breakpoint anywhere in `verify_password`'s first 128 bytes, the scan detects it.

### The false positive problem

The `0xCC` byte isn't exclusively the `int3` opcode. It can legitimately appear in machine code:

- As an operand byte: `mov eax, 0x004011CC` contains `0xCC` in the immediate address encoding  
- As part of a multi-byte opcode: in certain SSE/AVX instructions, `0xCC` can appear as a prefix or internal byte  
- As padding: GCC sometimes inserts `int3` (`0xCC`) between functions for code alignment. These `0xCC`s are legitimate and aren't breakpoints.

A naive scanner searching for `0xCC` byte by byte will produce false positives. More sophisticated implementations disassemble their own code to only check each instruction's first bytes (where GDB writes the breakpoint), or compare in-memory code with a reference copy stored elsewhere.

Our implementation is intentionally simplistic to remain pedagogical. A production scanner would use an integrated disassembler or a reference hash.

### Recognizing the technique in disassembly

The pattern is characteristic:

```nasm
; Load address of function to scan
lea    rdi, [rip+0x1234]       ; address of verify_password
; Scanning loop
xor    ecx, ecx                ; counter i = 0
.loop:
  movzx  eax, byte [rdi+rcx]  ; read byte at fn_ptr[i]
  cmp    al, 0xCC              ; compare to int3
  je     .breakpoint_found     ; breakpoint detected!
  inc    ecx
  cmp    ecx, 128              ; or another limit
  jl     .loop
```

Key indicators:

- A pointer to a function in the binary itself (not to data or an external library) loaded into a register  
- A loop reading individual bytes from that pointer with `movzx` or `mov byte`  
- A comparison of each byte with the constant `0xCC`  
- A branch to an error path if `0xCC` is found

In Ghidra's decompiler, the pattern appears clearly as a loop traversing a byte array with a comparison against `0xCC` — even without symbols, the cast to `uint8_t*` and the `0xCC` constant are strong signals.

### Bypasses

**Method 1 — Use hardware breakpoints**

This is the cleanest method. x86-64 processors have four hardware debug registers (`DR0` to `DR3`) that allow setting breakpoints without modifying code in memory. A hardware breakpoint is invisible to any `0xCC` scan because no byte is modified.

```
(gdb) hbreak *0x401234
Hardware assisted breakpoint 1 at 0x401234
```

The `hbreak` command (instead of `break`) in GDB uses a hardware breakpoint. The limitation is that only four simultaneous hardware breakpoints are available, which can be constraining during a complex analysis session. They must be used strategically: reserve them for functions the binary scans, and use software breakpoints for the rest of the code.

**Method 2 — Set breakpoints after the scan**

If the scan occurs at the beginning of `main()` (as in our binary), the analyst can let the scan pass during normal execution, then set breakpoints afterward. The scan has already occurred and won't repeat (unless the binary scans periodically).

```
(gdb) break main
(gdb) run
(gdb) # advance past the scan
(gdb) next
(gdb) next
...
(gdb) # now set breakpoints on verify_password
(gdb) break verify_password
(gdb) continue
```

**Method 3 — NOP the scan itself**

Replace the scan function with `nop`s + `xor eax, eax` + `ret` (so it returns 0 = "no breakpoint found"). This permanently disables the scan.

With GDB, this can be done in memory without modifying the file:

```
(gdb) # Overwrite scan_int3's start with: xor eax, eax ; ret
(gdb) set *(unsigned int *)scan_int3 = 0x00C3C031
```

The bytes `31 C0 C3` correspond to `xor eax, eax` (`31 C0`) followed by `ret` (`C3`). The function immediately returns 0.

**Method 4 — Frida**

Frida doesn't use `int3` breakpoints for its instrumentation. Frida's `Interceptor` rewrites the target function's prologue with a trampoline (jump to hook), not with a `0xCC`. The `int3` scan doesn't detect Frida.

Frida can also be used to disable the scan itself:

```javascript
// Replace scan_int3 with a function returning 0
var scan_addr = Module.findExportByName(null, "scan_int3");
// If binary is stripped, find address by pattern matching:
// var scan_addr = ptr("0x401234");

Interceptor.replace(scan_addr, new NativeCallback(function() {
    return 0;
}, 'int', []));
```

## Technique 2 — Code integrity verification (checksum)

### Principle

The `0xCC` scanning looks for a specific byte. Integrity verification is more general: it computes a hash or checksum on a code portion and compares the result to a reference value. Any modification — whether a `0xCC` breakpoint, a patching `nop`, an inverted jump, or any alteration — changes the checksum and triggers detection.

### Implementation in our binary

```c
#define CHECKSUM_LEN 64

static uint32_t compute_checksum(const uint8_t *ptr, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (sum << 3) | (sum >> 29); /* rotation */
        sum ^= ptr[i];
    }
    return sum;
}

static volatile uint32_t expected_checksum = 0;

static int check_code_integrity(void)
{
    if (expected_checksum == 0)
        return 0; /* checksum not initialized */

    uint32_t actual = compute_checksum(
        (const uint8_t *)verify_password, CHECKSUM_LEN);

    if (actual != expected_checksum) {
        return 1; /* code modified */
    }
    return 0;
}
```

The reference checksum (`expected_checksum`) is computed during a non-debugged execution and injected into the binary by a post-build script. At each execution, the binary recalculates the checksum on `verify_password`'s first 64 bytes and compares. If a single byte changed (breakpoint, patch, NOP), the checksum differs.

### Advantages over `int3` scanning

The checksum detects **all** types of modification, not just breakpoints:

- An `int3` breakpoint (`0xCC`) → different checksum  
- An inverted jump (`je` → `jne`, opcode `0x74` → `0x75`) → different checksum  
- A `nop` inserted to disable an instruction → different checksum  
- A Frida inline hook (prologue rewrite) → different checksum

This is a more robust protection than simple `0xCC` scanning, but it has its own weaknesses.

### Recognizing the technique in disassembly

The checksum pattern is:

```nasm
; Load address of function to verify
lea    rsi, [rip+0x...]          ; address of verify_password  
mov    edx, 64                    ; length to verify  
; Hash calculation loop
xor    eax, eax                   ; sum = 0
.hash_loop:
  movzx  ecx, byte [rsi]         ; read a code byte
  rol    eax, 3                   ; rotation (or shl+shr+or)
  xor    eax, ecx                ; XOR with byte
  inc    rsi
  dec    edx
  jnz    .hash_loop
; Comparison with expected value
cmp    eax, dword [rip+0x...]    ; expected_checksum  
jne    .integrity_fail  
```

Indicators:

- A pointer to the binary's own code (like for `int3` scanning)  
- An accumulation loop reading bytes and combining them (XOR, rotation, addition — typical simple hash operations)  
- A comparison of the result with a constant stored in `.data` or `.rodata`  
- A branch to an error path on mismatch

### Bypasses

**Method 1 — Hardware breakpoints**

Like for `int3` scanning, hardware breakpoints don't modify code in memory. The checksum remains identical. This is the most direct solution.

**Method 2 — Patch the expected checksum**

If you know the checksum value with your modifications applied, you can update `expected_checksum` to match the new code. In GDB:

```
(gdb) # Set a breakpoint (which modifies code)
(gdb) break *verify_password
(gdb) # Calculate the new checksum of modified code
(gdb) # ... or simply patch expected_checksum to 0
(gdb) # to disable the check (0 = skip)
(gdb) set *(int*)&expected_checksum = 0
(gdb) continue
```

In our implementation, the value `0` for `expected_checksum` disables the check. This is an intentional weakness for pedagogical purposes. A robust implementation wouldn't have this escape.

**Method 3 — Disable the verification function**

Same approach as for `int3` scanning: overwrite `check_code_integrity`'s beginning with `xor eax, eax; ret` so it always returns 0.

**Method 4 — Restore code before the check**

If the analyst knows when the checksum is verified, they can restore the original bytes just before the check (temporarily remove breakpoints), let the check pass, then put breakpoints back. GDB already does part of this work when it restores the original byte during a `continue`, but multiple breakpoints or breakpoints in the verified zone require manual management.

A Python GDB script can automate this dance:

```python
import gdb

class ChecksumBypass(gdb.Breakpoint):
    """Breakpoint that disables itself during integrity verification."""
    def __init__(self, addr, check_start, check_end):
        super().__init__("*" + hex(addr))
        self.check_start = check_start
        self.check_end = check_end

    def stop(self):
        # Check if we're in the verification zone
        rip = int(gdb.parse_and_eval("$rip"))
        if self.check_start <= rip <= self.check_end:
            return False  # don't stop during check
        return True
```

## Technique 3 — Self-modifying code

### Principle

Self-modifying code is a technique where the program modifies its own instructions in memory during execution. The typical sequence is:

1. Critical code is stored encrypted or encoded in the binary.  
2. At runtime, a decryption routine decodes the instructions.  
3. The decrypted code executes.  
4. Optionally, the code is re-encrypted after execution to not remain in plaintext in memory.

The impact on reverse engineering is twofold:

- **Static analysis is ineffective** — The disassembler (Ghidra, objdump) analyzes code as it is in the file. If this code is encrypted, disassembly produces meaningless noise.  
- **Breakpoints are unstable** — If the binary rewrites the code zone where a breakpoint is set, the breakpoint is overwritten. Moreover, the breakpoint's `0xCC` byte will be interpreted as an encrypted/encoded byte, corrupting the decryption and producing invalid decrypted code.

### Implementation on Linux

Self-modifying code requires the memory page containing the code to be both writable and executable. On a system with NX enabled (the default), `.text` pages are `R-X` (read-execute, not write). The binary must call `mprotect` to add write permission:

```c
#include <sys/mman.h>
#include <unistd.h>

void decrypt_code(void *func_addr, size_t len, uint8_t key) {
    /* Make the page writable */
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)func_addr & ~(page_size - 1));
    mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    /* Decrypt code (simple XOR for example) */
    uint8_t *ptr = (uint8_t *)func_addr;
    for (size_t i = 0; i < len; i++) {
        ptr[i] ^= key;
    }

    /* Optional: reset to read-execute only */
    mprotect(page_start, page_size, PROT_READ | PROT_EXEC);
}
```

The `mprotect` call with `PROT_WRITE | PROT_EXEC` is a major alarm signal during triage. Simultaneously writable and executable pages are rare in legitimate code and indicate either self-modifying code, a JIT compiler, or a packer.

### Recognizing self-modifying code in disassembly

Indicators in static analysis:

- **`mprotect@plt` call** visible in dynamic imports. The `prot` argument (third argument, in `edx`) contains `0x7` (`PROT_READ | PROT_WRITE | PROT_EXEC`). The constant `0x7` in `mprotect`'s third argument is the most reliable signal.

- **Unreadable code zones** — The disassembler produces invalid or absurd instructions in certain areas. This is encrypted code. Ghidra may mark these zones as "bad instructions" or interpret them as data.

- **XOR loop pattern on code** — A loop that reads and rewrites bytes starting from a `.text` address, often with XOR or a decryption operation:

```nasm
; Typical decryption routine
lea    rdi, [rip+0x...]      ; address of encrypted code  
mov    ecx, 256               ; length  
mov    al, 0x37               ; XOR key  
.decrypt_loop:
  xor    byte [rdi], al       ; decrypt one byte
  inc    rdi
  dec    ecx
  jnz    .decrypt_loop
```

- **Call followed by execution of decrypted zone** — After the decryption loop, a `call` or `jmp` to the freshly decrypted code's address.

### Bypasses

**Method 1 — Dump after decryption**

The simplest strategy: let the code decrypt itself, then recover the result.

1. Set a hardware breakpoint on the instruction following decryption (the `call` or `jmp` to decrypted code).  
2. Run the program. Decryption executes normally.  
3. At the breakpoint, the code is in plaintext in memory. Dump it with GDB:

```
(gdb) dump memory decrypted_func.bin 0x<start> 0x<end>
```

The dump can then be disassembled separately or analyzed in Ghidra.

**Method 2 — Breakpoint on `mprotect`**

The `mprotect` call is the pivotal moment: it precedes decryption. By setting a breakpoint on `mprotect`, you identify the addresses and sizes of zones that will be modified (`mprotect`'s arguments give the base address and page size).

```
(gdb) break mprotect
(gdb) run
(gdb) # Inspect arguments
(gdb) info registers rdi rsi rdx
# rdi = page address
# rsi = size
# rdx = protections (0x7 = RWX)
(gdb) # Continue until after decryption
(gdb) finish
(gdb) # Now code is decrypted, we can analyze it
```

**Method 3 — Emulation of the decryption routine**

If the decryption algorithm is identified (simple XOR, AES, RC4…), it can be reproduced outside the binary. Extract the encrypted blob from the ELF file, apply decryption in Python, and analyze the result statically without ever running the binary.

```python
with open("anti_reverse", "rb") as f:
    data = bytearray(f.read())

# Offset and size of encrypted code (identified in Ghidra)
start = 0x1234  
length = 256  
key = 0x37  

for i in range(length):
    data[start + i] ^= key

# Write decrypted binary
with open("anti_reverse_decrypted", "wb") as f:
    f.write(data)
```

**Method 4 — Frida with Memory.protect**

Frida can intercept memory permission changes and decryption:

```javascript
Interceptor.attach(Module.findExportByName(null, "mprotect"), {
    onEnter: function(args) {
        var addr = args[0];
        var size = args[1].toInt32();
        var prot = args[2].toInt32();
        if (prot === 7) { // PROT_READ|PROT_WRITE|PROT_EXEC
            console.log("[*] mprotect RWX on " + addr +
                        " (size: " + size + ")");
            this.target_addr = addr;
            this.target_size = size;
        }
    },
    onLeave: function(retval) {
        if (this.target_addr) {
            // Dump zone after code will be decrypted
            // (can add a hook further for timing)
            console.log("[*] RWX zone ready, decryption will follow");
        }
    }
});
```

## Combining techniques

The three techniques in this section reinforce each other when combined:

- **`int3` scanning** detects software breakpoints on targeted functions.  
- **Checksums** detect all types of modification, including patches and inline hooks.  
- **Self-modifying code** prevents static analysis and makes breakpoints unstable.

A binary combining all three forces the analyst to work almost exclusively with hardware breakpoints, execute code at full speed (no single-stepping), and wait for the code to decrypt before analyzing it.

Despite this, the analyst always has handholds. Self-modifying code must decrypt at some point — and at that moment, it's in plaintext in memory. The checksum must read the code — and its result can be forced. The `int3` scan doesn't detect hardware breakpoints. Each protection has its Achilles' heel.

## Synthesis: software vs hardware breakpoints

The following table summarizes both breakpoint types' visibility against each countermeasure:

| Countermeasure | Software breakpoint (`0xCC`) | Hardware breakpoint (`DR0–DR3`) |  
|---|---|---|  
| `int3` scanning | Detected | Invisible |  
| Code checksum | Detected | Invisible |  
| Self-modifying code | Overwritten by decryption | Survives decryption |  
| DR* register detection | Invisible | Detectable (reading `DR7`) |

The last row mentions a technique not implemented in our binary but that exists: some programs read the debug registers (`DR0`–`DR3` and control register `DR7`) to detect hardware breakpoints. On Linux, a process can't read its own DR registers directly (they're accessible only via `ptrace`), making this detection more complex. Some malware uses intentionally provoked exceptions and inspects the signal context to extract DR register values, but this technique remains rare.

The practical rule for the analyst: facing a binary with breakpoint countermeasures, start with hardware breakpoints. If the four slots are insufficient, combine with software breakpoints placed only outside scanned or verified zones.

---


⏭️ [Inspecting all protections with `checksec` before any analysis](/19-anti-reversing/09-checksec-full-audit.md)
