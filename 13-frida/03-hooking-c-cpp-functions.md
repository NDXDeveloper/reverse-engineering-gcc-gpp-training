🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.3 — Hooking C and C++ functions on the fly

> 🧰 **Tools used**: `frida`, `frida-trace`, Python 3 + `frida` module  
> 📦 **Binaries used**: `binaries/ch13-keygenme/keygenme_O0`, `binaries/ch13-oop/oop_O0`  
> 📖 **Prerequisites**: [13.1 — Frida's architecture](/13-frida/01-frida-architecture.md), [13.2 — Injection modes](/13-frida/02-injection-modes.md), [Chapter 3 — x86-64 assembly](/03-x86-64-assembly/README.md) (calling conventions)

---

## The Interceptor API: the centerpiece

We saw in section 13.1 that Frida installs trampolines in the target process's code. The API that exposes this mechanism to JavaScript is `Interceptor`. It's the tool you'll use most often — nearly all dynamic RE scenarios with Frida go through `Interceptor.attach()`.

The principle is simple: you designate a memory address (a function's entry), and you provide two optional callbacks — `onEnter`, called when execution reaches that address, and `onLeave`, called when the function returns. Between the two, the original function executes normally, without modification.

```javascript
Interceptor.attach(address, {
    onEnter(args) {
        // Called BEFORE the function executes
        // args[0], args[1]... = function arguments
    },
    onLeave(retval) {
        // Called AFTER the function has returned
        // retval = return value
    }
});
```

The difficulty isn't in the API itself — it's concise and intuitive. The difficulty is **finding the address** of the function to hook and **correctly interpreting its arguments**. That's where the skills acquired in previous parts converge: static analysis (Ghidra, objdump), knowledge of calling conventions (Chapter 3), and understanding of the ELF format (Chapter 2).

---

## Hooking an exported C function by name

The simplest case is a function whose symbol is present in a shared library's export table — typically libc functions.

### Resolution by name with `Module.findExportByName`

```javascript
// Find strcmp's address in any loaded module
const strcmp_addr = Module.findExportByName(null, "strcmp");
```

The first argument is the module name (library). `null` means "search all loaded modules". You can restrict the search:

```javascript
// Only in libc
const strcmp_addr = Module.findExportByName("libc.so.6", "strcmp");
```

If the function isn't found, `findExportByName` returns `null`. There's a variant that throws an exception:

```javascript
// Throws an exception if the symbol doesn't exist
const strcmp_addr = Module.getExportByName(null, "strcmp");
```

> 💡 **Convention**: `find*` methods return `null` on failure, `get*` methods throw an exception. This pattern is systematic in the Frida API.

### Complete hook on `strcmp`

Let's combine symbol resolution and hooking. Recall `strcmp`'s signature:

```c
int strcmp(const char *s1, const char *s2);
```

Per the System V AMD64 convention (Chapter 3, section 3.6), `s1` is in `rdi` and `s2` in `rsi`. In Frida, `args[0]` corresponds to `rdi`, `args[1]` to `rsi`, and so on for subsequent arguments (`rdx`, `rcx`, `r8`, `r9`).

```javascript
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        const s1 = args[0].readUtf8String();
        const s2 = args[1].readUtf8String();
        console.log(`strcmp("${s1}", "${s2}")`);
    },
    onLeave(retval) {
        console.log(`  => return: ${retval.toInt32()}`);
    }
});
```

Typical output on `keygenme_O0`:

```
strcmp("SECRETKEY-2024", "test123")
  => return: 1
strcmp("SECRETKEY-2024", "SECRETKEY-2024")
  => return: 0
```

The return value `0` indicates a match. In two lines of hook, we extracted the expected key — exactly like with a conditional breakpoint in GDB, but without interrupting the program.

### The `args` object: an array of `NativePointer`s

Each element of `args` is a `NativePointer` — a Frida object that encapsulates a 64-bit memory address. It has read methods adapted to the pointed data type:

| Method | Corresponding C type | Example |  
|---|---|---|  
| `args[i].readUtf8String()` | `const char *` (UTF-8) | Character string |  
| `args[i].readCString()` | `const char *` (ASCII) | Classic C string |  
| `args[i].readU8()` | `uint8_t` (dereferenced) | Byte at the pointed address |  
| `args[i].readU32()` | `uint32_t` (dereferenced) | 32-bit integer at the pointed address |  
| `args[i].readU64()` | `uint64_t` (dereferenced) | 64-bit integer at the pointed address |  
| `args[i].readPointer()` | `void *` (dereferenced) | Pointer at the pointed address |  
| `args[i].readByteArray(n)` | `void *` + size | Buffer of `n` bytes |  
| `args[i].toInt32()` | `int` (direct value) | Integer passed by value |  
| `args[i].toUInt32()` | `unsigned int` (direct value) | Unsigned integer by value |

The distinction is fundamental: `.readUtf8String()` **dereferences the pointer** and reads the string at the pointed address, while `.toInt32()` interprets the **pointer value itself** as an integer. For an `int fd` argument passed by value, use `.toInt32()`. For a `const char *buf` argument that's a pointer to data, use `.readUtf8String()` or `.readByteArray(n)`.

### Hook on `open`

Let's illustrate with another classic example — the `open` system call (actually, the libc wrapper `open`):

```c
int open(const char *pathname, int flags, mode_t mode);
```

```javascript
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter(args) {
        this.path = args[0].readUtf8String();
        this.flags = args[1].toInt32();
    },
    onLeave(retval) {
        const fd = retval.toInt32();
        console.log(`open("${this.path}", ${this.flags}) = ${fd}`);
    }
});
```

Note the use of `this` to transmit data from `onEnter` to `onLeave`. The `this` object is a per-invocation storage space: each call to the hooked function has its own `this`, which avoids collisions when the function is called simultaneously by multiple threads or recursively.

---

## Hooking a local function (without export) by address

A binary's interesting functions aren't always exported. A `check_password` function in `keygenme_O0` won't appear in libc's exports — it's a function internal to the binary. If the binary isn't stripped, it may appear in the local symbol table. If the binary is stripped, you'll need to find its address by other means (Ghidra, objdump, static analysis).

### Resolution in the main binary

For local symbols (not exported but present in the symbol table), `Module.enumerateSymbols()` or `DebugSymbol.fromName()` can work:

```javascript
// List all symbols of the main binary
const mod = Process.enumerateModules()[0]; // first module = main binary  
const symbols = mod.enumerateSymbols();  

symbols.forEach(sym => {
    if (sym.name.includes("check") || sym.name.includes("verify")) {
        console.log(`${sym.name} @ ${sym.address}`);
    }
});
```

### Hook by raw address

When the binary is stripped and symbols have disappeared, the address remains. Suppose Ghidra indicates the verification function starts at offset `0x1234` in the binary. You need to convert this offset to a runtime virtual address.

```javascript
// Base address of the main module
const base = Process.enumerateModules()[0].base;

// Offset found in Ghidra
const offset = 0x1234;

// Virtual address = base + offset
const check_addr = base.add(offset);

console.log(`Target function @ ${check_addr}`);

Interceptor.attach(check_addr, {
    onEnter(args) {
        console.log("check_password() called");
        console.log("  arg0 (rdi):", args[0].readUtf8String());
    },
    onLeave(retval) {
        console.log("  return:", retval.toInt32());
    }
});
```

**Why add the base?** Binaries compiled with `-pie` (Position-Independent Executable, modern GCC's default) are loaded at a random base address by ASLR (section 2.8). The offset `0x1234` in Ghidra is relative to the start of the ELF file. In memory, the binary starts at address `base`, so the function is at `base + 0x1234`.

For a non-PIE binary (compiled with `-no-pie`), addresses in Ghidra directly correspond to virtual addresses, and you can use the raw address:

```javascript
// Non-PIE binary: Ghidra address is the in-memory address
Interceptor.attach(ptr("0x401234"), {
    onEnter(args) { /* ... */ }
});
```

> ⚠️ **Classic pitfall**: using an absolute Ghidra address on a PIE binary. The base address in Ghidra is often `0x100000` or `0x0`, while the real address in memory will be something like `0x556a3f200000`. Always check with `Process.enumerateModules()[0].base` if the binary is PIE.

### Shortcut with `Module.getBaseAddress`

If you know the module name:

```javascript
const base = Module.getBaseAddress("keygenme_O0");  
Interceptor.attach(base.add(0x1234), { /* ... */ });  
```

---

## Hooking C++ functions

C++ introduces two major complications for hooking: **name mangling** and **virtual functions**. Both were studied in detail in Chapter 17 (sections 17.1 and 17.2), and Frida provides tools to handle them.

### Name mangling: finding the actual C++ symbol

Recall that the C++ compiler transforms function names to encode their signature. The method `Animal::speak(std::string const&)` becomes something like `_ZN6Animal5speakERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE`. It's this mangled name that appears in the binary's symbol table.

**Approach 1: search for the mangled symbol in the binary.**

You can enumerate exports or symbols and filter by the demangled name:

```javascript
const mod = Process.enumerateModules()[0];

mod.enumerateSymbols().forEach(sym => {
    // The name field contains the mangled name
    // Frida doesn't demangle automatically, but we can search for fragments
    if (sym.name.includes("Animal") && sym.name.includes("speak")) {
        console.log(`${sym.name} @ ${sym.address}`);
    }
});
```

**Approach 2: use the mangled name directly.**

If you identified the mangled symbol via `nm`, `objdump -t`, `c++filt` (Chapter 7, section 7.6), or Ghidra, you can pass it directly:

```javascript
const speak_addr = Module.findExportByName(null,
    "_ZN6Animal5speakERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
);

if (speak_addr) {
    Interceptor.attach(speak_addr, {
        onEnter(args) {
            // In C++, args[0] = this (implicit pointer to the object)
            console.log("Animal::speak() called");
            console.log("  this:", args[0]);
        }
    });
}
```

**Approach 3: `frida-trace` with globs.**

`frida-trace` handles name mangling very well thanks to globs:

```bash
# Hook all methods of the Animal class
frida-trace -f ./oop_O0 -i "*Animal*"

# Hook all speak methods, regardless of class
frida-trace -f ./oop_O0 -i "*speak*"
```

`frida-trace` resolves mangled symbols and displays demangled names in its output, making it an excellent reconnaissance tool for C++.

### The implicit `this` pointer

Crucial point for C++ hooking: in the Itanium ABI convention (used by GCC, see Chapter 17 section 17.1), the `this` pointer is passed as the **first implicit argument** of any non-static method. This means that in a Frida hook:

- `args[0]` = `this` (pointer to the object)  
- `args[1]` = first explicit argument of the method  
- `args[2]` = second explicit argument  
- etc.

```cpp
// C++ signature:
class Crypto {
    int decrypt(const char *input, char *output, int length);
};
```

```javascript
// Frida hook — beware the offset caused by this
Interceptor.attach(decrypt_addr, {
    onEnter(args) {
        // args[0] = this (pointer to the Crypto object)
        // args[1] = input (const char *)
        // args[2] = output (char *)
        // args[3] = length (int)

        this.thisPtr = args[0];
        this.input = args[1];
        this.length = args[3].toInt32();

        console.log(`Crypto::decrypt() called`);
        console.log(`  this   : ${this.thisPtr}`);
        console.log(`  input  : ${this.input.readByteArray(this.length)}`);
        console.log(`  length : ${this.length}`);
    },
    onLeave(retval) {
        // Read the output buffer after the function has filled it
        // (output is at args[2], saved if necessary in onEnter)
    }
});
```

Forgetting the `this` offset is the most frequent error in C++ hooking. If your arguments seem shifted by one position — the "string" you read from `args[0]` looks like a heap address rather than text — it's probably because you're reading `this` instead of the first real argument.

### Hooking virtual functions via the vtable

For virtual functions, the actual function address called depends on the object's dynamic type, via the vtable mechanism (Chapter 17, section 17.2). You can either hook the specific implementation of a class (by finding its address via symbol or in Ghidra), or intercept the indirect call by hooking the vtable slot.

**Direct approach: hook the implementation.**

If Ghidra or `nm` shows that `Dog::speak()` is at address `0x2a40` (offset), hook it like any function:

```javascript
const base = Process.enumerateModules()[0].base;  
Interceptor.attach(base.add(0x2a40), {  
    onEnter(args) {
        console.log("Dog::speak() (concrete implementation)");
    }
});
```

This hook will only capture calls to `Dog::speak()`, not `Cat::speak()` — even if both are called via an `Animal*` pointer. It's generally what you want in RE: understanding which concrete implementation is executed.

**Vtable approach: read and replace table pointers.**

This advanced approach consists of locating the vtable in memory and replacing the function pointer with a custom trampoline. It's more complex and rarely necessary — we mention it for completeness, but hooking by direct address covers the vast majority of cases.

```javascript
// Read the vptr of an object (first field of the object in memory)
const obj_addr = ptr("0x...");  // address of an Animal object  
const vtable_ptr = obj_addr.readPointer();  

// The first vtable slot is often the first virtual function
const first_virtual_fn = vtable_ptr.readPointer();  
console.log(`First virtual function @ ${first_virtual_fn}`);  

// We can hook this address
Interceptor.attach(first_virtual_fn, {
    onEnter(args) {
        console.log("Virtual function slot 0 called");
    }
});
```

---

## Enumeration and function searching

Before hooking, you often need to explore the binary to find interesting functions. Frida offers several enumeration mechanisms.

### List loaded modules

```javascript
Process.enumerateModules().forEach(mod => {
    console.log(`${mod.name.padEnd(30)} base=${mod.base} size=${mod.size}`);
});
```

Typical output:

```
keygenme_O0                    base=0x555555554000 size=0x3000  
linux-vdso.so.1                base=0x7ffd12ffe000 size=0x2000  
libc.so.6                      base=0x7f8a3c200000 size=0x1c1000  
ld-linux-x86-64.so.2           base=0x7f8a3c3e0000 size=0x2b000  
```

### List a module's exports

```javascript
const libc = Process.getModuleByName("libc.so.6");  
libc.enumerateExports().forEach(exp => {  
    if (exp.type === 'function' && exp.name.includes("str")) {
        console.log(`${exp.name} @ ${exp.address}`);
    }
});
```

### List a module's imports

Imports show which external functions the binary calls — it's the dynamic equivalent of PLT/GOT analysis (Chapter 2, section 2.9):

```javascript
const main_mod = Process.enumerateModules()[0];  
main_mod.enumerateImports().forEach(imp => {  
    console.log(`Import: ${imp.name} from ${imp.module} @ ${imp.address}`);
});
```

Output:

```
Import: puts from libc.so.6 @ 0x7f8a3c245e10  
Import: strcmp from libc.so.6 @ 0x7f8a3c2c4560  
Import: printf from libc.so.6 @ 0x7f8a3c25f900  
Import: scanf from libc.so.6 @ 0x7f8a3c260120  
```

This list is a gold mine for RE. Imports reveal the binary's capabilities: it uses `strcmp` (string comparison — maybe a password check), `printf`/`scanf` (console I/O), etc.

### Pattern search in symbols

For binaries with symbols (not stripped), `DebugSymbol` offers a reverse search — from address to name:

```javascript
// Which symbol is at this address?
const sym = DebugSymbol.fromAddress(ptr("0x555555555189"));  
console.log(sym);  // { address: 0x555555555189, name: "check_password", ... }  
```

---

## Hooking multiple functions in a single pass

In real situations, you often want to hook a set of functions simultaneously. Here's a common pattern that installs hooks on all comparison functions:

```javascript
const targets = ["strcmp", "strncmp", "memcmp", "strcasecmp"];

targets.forEach(name => {
    const addr = Module.findExportByName(null, name);
    if (addr === null) {
        console.log(`[!] ${name} not found`);
        return;
    }

    Interceptor.attach(addr, {
        onEnter(args) {
            this.funcName = name;
            try {
                // Try to read the first two arguments as strings
                this.a = args[0].readUtf8String();
                this.b = args[1].readUtf8String();
            } catch (e) {
                // If reading fails (binary buffer, invalid address), log the address
                this.a = args[0].toString();
                this.b = args[1].toString();
            }
        },
        onLeave(retval) {
            const result = retval.toInt32();
            // Only log matches (return == 0)
            if (result === 0) {
                send({
                    func: this.funcName,
                    a: this.a,
                    b: this.b,
                    match: true
                });
            }
        }
    });

    console.log(`[+] Hook installed on ${name} @ ${addr}`);
});
```

The `try/catch` block around `readUtf8String()` is an indispensable precaution. `strcmp` always receives valid strings, but `memcmp` can receive arbitrary binary buffers. Attempting to read a binary buffer as a UTF-8 string can throw an exception if the bytes don't form a valid UTF-8 sequence.

---

## Hook filtering: avoiding noise

A hook on `strcmp` in a non-trivial program can generate hundreds of calls per second — the libc itself uses `strcmp` internally for all sorts of operations. It's crucial to filter to capture only relevant calls.

### Filter by argument content

```javascript
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        const s1 = args[0].readUtf8String();
        const s2 = args[1].readUtf8String();

        // Only log if one of the arguments contains "KEY" or "password"
        if (s1 && (s1.includes("KEY") || s1.includes("password")) ||
            s2 && (s2.includes("KEY") || s2.includes("password"))) {
            console.log(`strcmp("${s1}", "${s2}")`);
        }
    }
});
```

### Filter by caller (backtrace)

You can inspect the call stack to only hook `strcmp` calls from the main binary (not from libc or other libraries):

```javascript
const main_mod = Process.enumerateModules()[0];  
const main_base = main_mod.base;  
const main_end = main_base.add(main_mod.size);  

Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        // Return address = who called strcmp
        const caller = this.returnAddress;

        // Continue only if the caller is in the main binary
        if (caller.compare(main_base) >= 0 && caller.compare(main_end) < 0) {
            console.log(`strcmp from the main binary:`);
            console.log(`  "${args[0].readUtf8String()}" vs "${args[1].readUtf8String()}"`);
        }
    }
});
```

`this.returnAddress` is a `NativePointer` containing the address of the instruction following the `call` that invoked the hooked function. By checking that this address is in the main module's memory range, you eliminate all libc-internal calls.

### Complete backtrace

For deeper diagnosis, Frida can produce a complete backtrace:

```javascript
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("strcmp() called, backtrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join('\n'));
    }
});
```

`Thread.backtrace()` returns an array of return addresses (the call stack). `DebugSymbol.fromAddress` converts each address to a readable symbol name. The `Backtracer.ACCURATE` mode uses DWARF information for precise stack unwinding; `Backtracer.FUZZY` is faster but less reliable.

---

## Detaching a hook

Hooks installed by `Interceptor.attach()` remain active until explicitly removed or the script is unloaded. To remove a specific hook:

```javascript
const listener = Interceptor.attach(addr, {
    onEnter(args) { /* ... */ }
});

// Later, when no longer needed:
listener.detach();
```

To remove **all** hooks installed by the script:

```javascript
Interceptor.detachAll();
```

Detaching restores the function's original instructions — the trampoline is removed and the function returns to its native behavior.

---

## `Interceptor.replace`: replacing a function entirely

`Interceptor.attach` observes and can modify arguments and return value, but the original function always executes. `Interceptor.replace` goes further: it completely replaces the function with a JavaScript implementation.

```javascript
const orig_check = new NativeFunction(
    Module.findExportByName(null, "check_password"),
    'int',           // return type
    ['pointer']      // argument types
);

Interceptor.replace(Module.findExportByName(null, "check_password"),
    new NativeCallback(function (input) {
        console.log(`check_password("${input.readUtf8String()}") → forced to 1`);
        return 1;  // Always return "success"
    }, 'int', ['pointer'])
);
```

Here, `check_password` will never execute again — it's entirely replaced by our callback that systematically returns `1`. It's the equivalent of binary patching, but without modifying the file on disk and with the ability to retain conditional logic.

We keep a reference to the original function via `NativeFunction` in case we want to call it from our replacement:

```javascript
Interceptor.replace(check_addr,
    new NativeCallback(function (input) {
        const str = input.readUtf8String();

        // Call the original function for "normal" inputs
        if (str.startsWith("admin_")) {
            console.log("Admin bypass activated");
            return 1;
        }
        // Otherwise, let the original verification proceed
        return orig_check(input);
    }, 'int', ['pointer'])
);
```

> ⚠️ `Interceptor.replace` is more fragile than `Interceptor.attach`. If the signature (types and number of arguments) doesn't exactly match the original function, behavior is undefined — likely crash. Always verify the signature via Ghidra or the decompiler before replacing a function.

---

## `NativeFunction`: calling native functions from JavaScript

The `NativeFunction` object allows calling any function in the target process from your JavaScript code, as if calling a C function:

```javascript
const puts = new NativeFunction(
    Module.findExportByName(null, "puts"),
    'int',          // return type
    ['pointer']     // argument types
);

// Allocate a string in memory and pass it to puts
const msg = Memory.allocUtf8String("Message injected by Frida!");  
puts(msg);  
```

This code allocates a string in the target process's heap, then calls the real libc `puts` function to display it. The message appears in the target program's `stdout` — not in the Frida console.

Types supported by `NativeFunction` and `NativeCallback` follow a simplified syntax:

| Frida type | C type | Size |  
|---|---|---|  
| `'void'` | `void` | — |  
| `'int'` | `int` / `int32_t` | 32 bits |  
| `'uint'` | `unsigned int` | 32 bits |  
| `'long'` | `long` / `int64_t` | 64 bits |  
| `'pointer'` | `void *`, `char *`, any pointer | 64 bits |  
| `'float'` | `float` | 32 bits |  
| `'double'` | `double` | 64 bits |

---

## Robustness: handling errors in hooks

A hook that throws an uncaught JavaScript exception will be silently disabled by Frida. The target process continues running, but your hook no longer executes — and if you're not watching the console, you won't know why your logs stopped.

**Survival rule**: always surround hook bodies with a `try/catch` in production scripts.

```javascript
Interceptor.attach(addr, {
    onEnter(args) {
        try {
            const s = args[0].readUtf8String();
            console.log(`arg0 = "${s}"`);
        } catch (e) {
            console.log(`[!] Error in onEnter: ${e.message}`);
            console.log(`    args[0] = ${args[0]}`);
        }
    }
});
```

The most common errors are attempts to read unmapped memory (`readUtf8String` on a `NULL` or invalid pointer), and encoding problems (binary buffer read as UTF-8).

---

## What to remember

- `Interceptor.attach(address, {onEnter, onLeave})` is Frida hooking's central function. It doesn't modify the target function's execution, but allows observing and altering its arguments and return value.  
- For **exported** functions (libc, libraries), resolve the address by name with `Module.findExportByName`.  
- For a binary's **internal** functions (especially stripped), compute `base + offset` from the offset found in Ghidra or objdump.  
- In **C++**, `args[0]` is the implicit `this` pointer — explicit arguments start at `args[1]`. Function names are mangled.  
- `this.returnAddress` and `Thread.backtrace()` allow filtering calls by caller.  
- `Interceptor.replace` entirely replaces a function with a JavaScript callback.  
- `NativeFunction` allows calling any function in the target process from JavaScript.  
- Always protect hooks with `try/catch` to avoid silent deactivations.

---

> **Next section**: 13.4 — Intercepting calls to `malloc`, `free`, `open`, custom functions — we'll apply these hooking techniques to concrete scenarios of memory-allocation interception, file I/O, and application functions.

⏭️ [Intercepting calls to `malloc`, `free`, `open`, custom functions](/13-frida/04-intercepting-calls.md)
