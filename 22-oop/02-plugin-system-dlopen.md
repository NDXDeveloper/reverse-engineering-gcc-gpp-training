🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 22.2 — RE of a Plugin System (Dynamic Loading `.so` via `dlopen`/`dlsym`)

> 🛠️ **Tools used**: `ltrace`, `strace`, GDB (+ GEF/pwndbg), Ghidra, Frida, `readelf`, `nm`  
> 📦 **Binaries**: `oop_O0`, `oop_O2_strip`, `plugins/plugin_alpha.so`, `plugins/plugin_beta.so`  
> 📚 **Prerequisites**: Section 22.1 (vtables and hierarchy), Chapter 5 (`ltrace`/`strace`), Chapter 11 (GDB), Chapter 13 (Frida)

---

## Introduction

In the previous section, we reconstructed the class hierarchy and located the vtables. But one question remains: the classes `Rot13Processor` and `XorCipherProcessor` appear nowhere in the main executable. They live in shared libraries (`.so`) loaded **at runtime**, not at link time. Static analysis of the executable alone does not reveal them.

This pattern — a host application loading external modules via `dlopen` / `dlsym` — is extremely common in the real world. It is found in browsers (plugins), web servers (Apache/Nginx modules), game engines (mods), audio frameworks (VST/LV2 plugins), and in many malware samples that download and load additional components on the fly.

For the reverse engineer, a plugin system poses specific challenges:

- **The code is not present in the analyzed executable** — you must identify *which* files are loaded and *where* to find them.  
- **Symbols are resolved at runtime** — calls go through pointers obtained via `dlsym`, not through the PLT.  
- **The plugin interface is implicit** — the contract between host and plugin (which symbols to export, which class to instantiate) is documented nowhere in the binary.

This section teaches you to detect, trace, and understand a plugin system, from static triage through dynamic hooking.

---

## The `dl*` APIs: technical refresher

Before diving into the analysis, let's recall the four `libdl` functions you will systematically encounter.

**`dlopen(const char *filename, int flags)`** — Loads a shared library into memory. Returns an opaque *handle* (`void*`) or `NULL` on error. Common flags are `RTLD_NOW` (immediate resolution of all symbols) and `RTLD_LAZY` (on-demand resolution). The chosen flag influences the observable behavior at loading time.

**`dlsym(void *handle, const char *symbol)`** — Looks up a symbol by name in the loaded library. Returns a pointer to the symbol (`void*`) or `NULL` if the symbol does not exist. This is where the factory symbol name appears **in plaintext** in the binary — a crucial clue for RE.

**`dlclose(void *handle)`** — Unloads the library. Decrements a reference counter; the library is only actually unloaded when the counter reaches zero.

**`dlerror(void)`** — Returns a string describing the last error that occurred in the `dl*` functions. Often called right after a `dlopen` or `dlsym` that failed.

These four functions are in `libdl.so` and appear in the executable's PLT. They are therefore visible with `objdump -d` (entries `dlopen@plt`, `dlsym@plt`, etc.) even on a stripped binary.

---

## Step 1 — Static detection of the plugin mechanism

### 1.1 — Spotting `dl*` imports

The first question when facing an unknown binary is: "does it use dynamic loading?" The answer is in the import table.

```bash
$ objdump -T oop_O0 | grep -i dl
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.34  dlopen
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.34  dlsym
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.34  dlclose
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.34  dlerror
```

Four `dl*` imports — the binary loads modules dynamically. On a stripped binary, this information is always available because dynamic symbols (`.dynsym`) are not removed by `strip`.

Alternatively, with `readelf`:

```bash
$ readelf -d oop_O2_strip | grep NEEDED
 0x0000000000000001 (NEEDED)  Shared library: [libdl.so.2]
 0x0000000000000001 (NEEDED)  Shared library: [libstdc++.so.6]
 0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]
```

The dependency on `libdl.so.2` confirms the use of dynamic loading APIs.

> 💡 On recent glibc versions (≥ 2.34), the `dl*` functions are integrated directly into `libc.so.6` and `libdl.so` is merely a compatibility stub. Do not rely on the absence of `libdl.so` in the NEEDED entries to conclude there is no dynamic loading — always check the imported symbols.

### 1.2 — Finding the searched symbol names

`dlsym` takes a symbol name as an argument in the form of a string. This name is stored in plaintext in `.rodata`:

```bash
$ strings oop_O0 | grep -i 'processor\|plugin\|create\|destroy\|factory'
create_processor  
destroy_processor  
[Pipeline] loading plugin: %s
[Pipeline] dlopen error: %s
[Pipeline] missing symbols in %s
./plugins
.so
```

You immediately obtain:

- The **factory symbol names**: `create_processor` and `destroy_processor`.  
- The **default search directory**: `./plugins`.  
- The **filtered suffix**: `.so`.  
- **Diagnostic messages** that reveal the loading logic.

On a stripped binary, these strings are still present — they are part of `.rodata` and are essential for the program to function.

### 1.3 — The `opendir` / `readdir` pattern: automatic plugin discovery

Our application does not load a hardcoded plugin name — it scans a directory. This pattern is detected via the imports:

```bash
$ objdump -T oop_O0 | grep -E 'opendir|readdir|closedir'
0000000000000000      DF *UND*  ...  opendir
0000000000000000      DF *UND*  ...  readdir
0000000000000000      DF *UND*  ...  closedir
```

The combined presence of `opendir`/`readdir` and `dlopen` indicates an **automatic discovery** mechanism: the application lists files in a directory, filters by extension, and loads each `.so` found. This is a classic plugin architecture pattern.

---

## Step 2 — Static analysis of the plugin loader in Ghidra

### 2.1 — Locating the loading function

In Ghidra, search for cross-references to `dlopen` in the PLT. Click on `dlopen` in the Symbol Tree (under *Imports* or *External*), then `Ctrl+Shift+F` (References To).

You will find one or more call sites. On our binary, there is only one, in the `Pipeline::load_plugin()` method. With symbols, Ghidra identifies it directly. Without symbols, you will see a `FUN_XXXXXXXX` — rename it based on context.

### 2.2 — Dissecting the loading flow

By reading the decompiled output (or disassembly) of this function, you will identify the following flow:

```
load_plugin(path):
  1. handle = dlopen(path, RTLD_NOW)
     └── if NULL → log error via dlerror(), return false

  2. create_fn = dlsym(handle, "create_processor")
     destroy_fn = dlsym(handle, "destroy_processor")
     └── if either is NULL → log error, dlclose(handle), return false

  3. instance = create_fn(next_id++)
     └── if NULL → log error, dlclose(handle), return false

  4. Store {handle, create_fn, destroy_fn, instance} in a vector
     Add instance to the global Processor* vector

  5. Return true
```

Each step is identifiable by the calls to `dl*` functions and by the `NULL` checks that follow. In disassembly, the pattern is very regular:

```asm
; Step 1 — dlopen
lea    rdi, [rbp-0x110]       ; path (local variable or argument)  
mov    esi, 0x2               ; RTLD_NOW = 2  
call   dlopen@plt  
test   rax, rax  
je     .error_dlopen          ; jump if handle == NULL  
mov    [rbp-0x08], rax        ; save the handle  

; Step 2 — dlsym for create_processor
mov    rdi, rax               ; handle  
lea    rsi, [rip+0x...]       ; → "create_processor"  
call   dlsym@plt  
test   rax, rax  
je     .error_dlsym  
mov    [rbp-0x10], rax        ; save the function pointer  

; Step 2b — dlsym for destroy_processor
mov    rdi, [rbp-0x08]        ; handle  
lea    rsi, [rip+0x...]       ; → "destroy_processor"  
call   dlsym@plt  
test   rax, rax  
je     .error_dlsym  
mov    [rbp-0x18], rax  
```

> 💡 **Important clue**: the string passed as the second argument to `dlsym` is always a literal in `.rodata`. Ghidra displays it directly in the decompiled output. This is the formal proof of the interface contract between the host and the plugin.

### 2.3 — Understanding the interface contract

At this point, you have reconstructed the plugin contract without having the sources:

- The plugin must export an `extern "C"` symbol named `create_processor` that takes a `uint32_t` and returns a `Processor*`.  
- The plugin must export an `extern "C"` symbol named `destroy_processor` that takes a `Processor*` and returns nothing.  
- The object returned by `create_processor` is manipulated exclusively through the `Processor` interface (virtual dispatch).

This is exactly the information you will need in section 22.4 (and at the checkpoint) to write your own compatible plugin.

### 2.4 — Analyzing `load_plugins_from_dir`

The method that calls `load_plugin` in a loop follows this pattern:

```
load_plugins_from_dir(dir):
  d = opendir(dir)
  └── if NULL → return 0

  while (entry = readdir(d)) != NULL:
      if entry->d_name ends with ".so":
          build full path (dir + "/" + d_name)
          load_plugin(full_path)
          increment counter

  closedir(d)
  return counter
```

The `.so` extension test typically translates to a `strlen` computation followed by a `strcmp` or `memcmp` on the last 3 characters. At `-O2`, GCC may optimize this check into a direct 3-byte comparison or even a `cmp` on a masked 32-bit integer.

---

## Step 3 — Dynamic tracing with `ltrace`

Static analysis gave you the loader's structure. Dynamic analysis shows you what **actually** happens at runtime.

### 3.1 — `ltrace`: tracing `libdl` calls

`ltrace` intercepts calls to shared libraries. It is the ideal tool for observing `dlopen`/`dlsym` in action:

```bash
$ ltrace -e dlopen,dlsym,dlclose ./oop_O0 -p ./plugins "Hello RE"
```

Typical output:

```
dlopen("./plugins/plugin_alpha.so", 2)          = 0x5555557a4000  
dlsym(0x5555557a4000, "create_processor")       = 0x7ffff7fb6200  
dlsym(0x5555557a4000, "destroy_processor")      = 0x7ffff7fb6280  
dlopen("./plugins/plugin_beta.so", 2)           = 0x5555557b8000  
dlsym(0x5555557b8000, "create_processor")       = 0x7ffff7daa180  
dlsym(0x5555557b8000, "destroy_processor")      = 0x7ffff7daa210  
...
dlclose(0x5555557b8000)                         = 0  
dlclose(0x5555557a4000)                         = 0  
```

In a single command you get:

- The **exact paths** of loaded plugins.  
- The **flag** passed to `dlopen` (2 = `RTLD_NOW`).  
- The **symbol names** searched by `dlsym`.  
- The **addresses** returned for each symbol — these are the factory function addresses in the process memory space.  
- The **loading and unloading order**.

### 3.2 — `strace`: seeing file system accesses

`strace` shows the underlying system calls. Combined with `ltrace`, it reveals which files are actually opened:

```bash
$ strace -e openat,mmap ./oop_O0 -p ./plugins "Hello RE" 2>&1 | grep plugin
```

```
openat(AT_FDCWD, "./plugins", O_RDONLY|O_NONBLOCK|O_DIRECTORY) = 3  
openat(AT_FDCWD, "./plugins/plugin_alpha.so", O_RDONLY|O_CLOEXEC) = 4  
mmap(NULL, 16384, PROT_READ, MAP_PRIVATE, 4, 0) = 0x7ffff7fb0000  
openat(AT_FDCWD, "./plugins/plugin_beta.so", O_RDONLY|O_CLOEXEC)  = 4  
mmap(NULL, 16384, PROT_READ, MAP_PRIVATE, 4, 0) = 0x7ffff7da0000  
```

We see the `openat` on the directory (for `opendir`), then the opening of each `.so` by `dlopen` (which uses `openat` + `mmap` internally).

> 💡 **Malware context**: on a suspicious sample, `strace` is your first reflex to see if the binary attempts to load modules from unexpected locations (`/tmp`, `/dev/shm`, a network path...). A `dlopen` on a file in `/tmp/.cache/libupdate.so` would be an immediate red flag.

---

## Step 4 — Tracing with GDB: observing loading in real time

### 4.1 — Breakpoints on `dlopen` and `dlsym`

Launch GDB and set breakpoints on the `dl*` functions:

```
$ gdb -q ./oop_O0
(gdb) break dlopen
(gdb) break dlsym
(gdb) run -p ./plugins "Hello RE"
```

First stop on `dlopen`:

```
Breakpoint 1, dlopen (file=0x7fffffffd4f0 "./plugins/plugin_alpha.so", mode=2)
```

GDB directly shows you the arguments. The flag `mode=2` corresponds to `RTLD_NOW`. Continue with `continue` to reach `dlsym`:

```
Breakpoint 2, dlsym (handle=0x5555557a4000, name=0x404120 "create_processor")
```

The `name` argument is the symbol string being searched.

### 4.2 — Examining the return value

Place a conditional breakpoint after `dlsym` returns to capture the function pointer:

```
(gdb) break dlsym
(gdb) commands
> finish
> print/x $rax
> info symbol $rax
> end
(gdb) continue
```

After `finish`, `$rax` contains the address returned by `dlsym`. The `info symbol` command tells you which symbol this address corresponds to:

```
$1 = 0x7ffff7fb6200
create_processor in section .text of ./plugins/plugin_alpha.so
```

### 4.3 — Following the factory call

The key moment is the call `instance = create_fn(next_id)`. To intercept it, you need to find the indirect call site. Two approaches:

**Approach 1 — Breakpoint on the factory itself**:

```
(gdb) break create_processor
```

If the plugin has symbols, GDB resolves the name directly. Otherwise, use the address obtained in the previous step:

```
(gdb) break *0x7ffff7fb6200
```

At the stop, you are at the plugin factory's entry. Inspect the arguments:

```
(gdb) print $rdi
$2 = 1                          ← the id passed to the constructor
```

Continue step by step (`step`) to see the `new` and the `Rot13Processor` constructor.

**Approach 2 — Inspect the returned object**:

After `create_processor` returns, examine the object:

```
(gdb) finish
(gdb) print/x $rax
$3 = 0x555555808010              ← address of the allocated object

(gdb) x/6gx $rax
0x555555808010: 0x00007ffff7fb7d00  0x0000000100000001
0x555555808020: 0x0000000000000000  0x0000000000000000
0x555555808030: 0x0000000000000000  0x0000000000000000
```

The first quadword (`0x00007ffff7fb7d00`) is the **vptr** — it points to the `Rot13Processor` vtable in `plugin_alpha.so`. Examine this vtable:

```
(gdb) x/8gx 0x00007ffff7fb7d00
0x7ffff7fb7d00: 0x00007ffff7fb6050   ← ~Rot13Processor() (complete)
0x7ffff7fb7d08: 0x00007ffff7fb60a0   ← ~Rot13Processor() (deleting)
0x7ffff7fb7d10: 0x00007ffff7fb60f0   ← name()
0x7ffff7fb7d18: 0x00007ffff7fb6110   ← configure()
0x7ffff7fb7d20: 0x00007ffff7fb6150   ← process()
0x7ffff7fb7d28: 0x00007ffff7fb61c0   ← status()
```

Each entry points to a function in the `plugin_alpha.so` address space. You can verify with `info symbol` on each address.

### 4.4 — The `info sharedlibrary` command

At any time, GDB can list loaded shared libraries:

```
(gdb) info sharedlibrary
From                To                  Syms Read   Shared Object Library
0x00007ffff7fc1000  0x00007ffff7fe2000  Yes          /lib64/ld-linux-x86-64.so.2
0x00007ffff7f80000  0x00007ffff7fb0000  Yes          /lib/x86-64-linux-gnu/libdl.so.2
0x00007ffff7d00000  0x00007ffff7e80000  Yes          /lib/x86-64-linux-gnu/libc.so.6
0x00007ffff7fb0000  0x00007ffff7fb8000  Yes          ./plugins/plugin_alpha.so
0x00007ffff7da0000  0x00007ffff7dac000  Yes          ./plugins/plugin_beta.so
```

Plugins appear in the list once loaded by `dlopen`. If you set the breakpoint before `dlopen`, they are not yet visible — and GDB cannot resolve their symbols. This is why the breakpoint on `dlopen` followed by a `finish` is necessary to then work with the plugin's symbols.

---

## Step 5 — Hooking with Frida: in-depth interception

Frida offers a more flexible approach than GDB for tracing a plugin system. The idea is to intercept `dlopen` and `dlsym` to automatically log the entire loading process, then hook the factory functions to inspect created objects.

### 5.1 — Basic script: tracing `dlopen` and `dlsym`

```javascript
// frida_trace_plugins.js
// Usage: frida -l frida_trace_plugins.js -- ./oop_O0 -p ./plugins "Hello RE"

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        this.flags = args[1].toInt32();
        console.log("[dlopen] path=" + this.path + " flags=" + this.flags);
    },
    onLeave: function(retval) {
        console.log("[dlopen] handle=" + retval);
        if (retval.isNull()) {
            var dlerror = new NativeFunction(
                Module.findExportByName(null, "dlerror"), 'pointer', []);
            var err = dlerror().readUtf8String();
            console.log("[dlopen] ERROR: " + err);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "dlsym"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.symbol = args[1].readUtf8String();
        console.log("[dlsym] handle=" + this.handle +
                    " symbol=\"" + this.symbol + "\"");
    },
    onLeave: function(retval) {
        console.log("[dlsym] → " + retval);

        // If it's the factory, dynamically hook the returned pointer
        if (this.symbol === "create_processor" && !retval.isNull()) {
            hookFactory(retval, this.handle);
        }
    }
});

function hookFactory(fnPtr, dlHandle) {
    Interceptor.attach(fnPtr, {
        onEnter: function(args) {
            this.id = args[0].toInt32();
            console.log("[create_processor] id=" + this.id);
        },
        onLeave: function(retval) {
            if (retval.isNull()) {
                console.log("[create_processor] returned NULL");
                return;
            }
            console.log("[create_processor] object at " + retval);

            // Read the vptr (first quadword of the object)
            var vptr = retval.readPointer();
            console.log("[create_processor] vptr = " + vptr);

            // Read the first 6 vtable entries
            for (var i = 0; i < 6; i++) {
                var entry = vptr.add(i * Process.pointerSize).readPointer();
                var info = DebugSymbol.fromAddress(entry);
                console.log("  vtable[" + i + "] = " + entry +
                            " (" + info.name + ")");
            }
        }
    });
}
```

### 5.2 — Frida script output

```
[dlopen] path=./plugins/plugin_alpha.so flags=2
[dlopen] handle=0x5555557a4000
[dlsym] handle=0x5555557a4000 symbol="create_processor"
[dlsym] → 0x7ffff7fb6200
[dlsym] handle=0x5555557a4000 symbol="destroy_processor"
[dlsym] → 0x7ffff7fb6280
[create_processor] id=1
[create_processor] object at 0x555555808010
[create_processor] vptr = 0x7ffff7fb7d00
  vtable[0] = 0x7ffff7fb6050 (Rot13Processor::~Rot13Processor())
  vtable[1] = 0x7ffff7fb60a0 (Rot13Processor::~Rot13Processor())
  vtable[2] = 0x7ffff7fb60f0 (Rot13Processor::name() const)
  vtable[3] = 0x7ffff7fb6110 (Rot13Processor::configure())
  vtable[4] = 0x7ffff7fb6150 (Rot13Processor::process())
  vtable[5] = 0x7ffff7fb61c0 (Rot13Processor::status() const)
[dlopen] path=./plugins/plugin_beta.so flags=2
[dlopen] handle=0x5555557b8000
...
```

In a single run, Frida gives you:

- Each loaded plugin, with its handle.  
- The searched symbols and their resolved addresses.  
- The object created by each factory, its vptr, and the complete vtable with method names (if plugin symbols are present).

### 5.3 — Hooking virtual methods of the plugin

Once the vtable is known, you can individually hook the plugin's methods. For example, to intercept `process()` on each plugin:

```javascript
function hookProcessMethod(vptr, className) {
    // process() is at index 4 of the vtable (after 2 dtors, name, configure)
    var processAddr = vptr.add(4 * Process.pointerSize).readPointer();

    Interceptor.attach(processAddr, {
        onEnter: function(args) {
            // args[0] = this, args[1] = input, args[2] = in_len
            var input = args[1].readUtf8String();
            var len = args[2].toInt32();
            console.log("[" + className + "::process] input=\"" +
                        input + "\" len=" + len);
        },
        onLeave: function(retval) {
            console.log("[" + className + "::process] returned " +
                        retval.toInt32());
        }
    });
}
```

This technique is particularly powerful on stripped binaries: you need no symbols, only the vptr and vtable offsets.

---

## Step 6 — Static analysis of plugins in Ghidra

### 6.1 — Importing a `.so` separately

Each plugin must be imported as a separate Ghidra project (or in the same project, but as a separate binary). During import, Ghidra automatically detects the ELF shared object format.

After automatic analysis, your investigation entry point is the `create_processor` symbol — visible in the Symbol Tree under *Functions* or *Exports*.

### 6.2 — From factory to vtable

The decompiled output of `create_processor` in `plugin_alpha.so` will look like:

```c
Processor * create_processor(uint32_t id) {
    Rot13Processor *obj = (Rot13Processor *)operator.new(0x28);
    Rot13Processor::Rot13Processor(obj, id);
    return obj;
}
```

The size passed to `operator new` (`0x28` = 40 bytes) gives you `sizeof(Rot13Processor)`. Comparing it to the base `sizeof(Processor)` (24 bytes reconstructed in section 22.1), you know that `Rot13Processor` adds 16 bytes of its own data.

Entering the constructor, you will see the vptr assignment:

```asm
lea    rax, [rip + vtable_for_Rot13Processor + 0x10]  
mov    QWORD PTR [rdi], rax  
```

Follow this address to reach the vtable and identify all the plugin's methods.

### 6.3 — Linking the plugin to the host

The `Rot13Processor` typeinfo contains a reference to the `Processor` typeinfo:

```
typeinfo for Rot13Processor:
  [0x00]  ptr → __si_class_type_info
  [0x08]  ptr → "15Rot13Processor"
  [0x10]  RELOCATION → typeinfo for Processor (in the executable)
```

In Ghidra, this relocation appears in the plugin's `.rela.dyn` section. The entry points to an external symbol (`typeinfo for Processor`), confirming that `Rot13Processor` inherits from `Processor` and that resolution happens at load time via the dynamic linker.

Verify with `readelf`:

```bash
$ readelf -r plugins/plugin_alpha.so | grep typeinfo
0000000000003d90  R_X86_64_64  0000000000000000 _ZTI9Processor + 0
```

The symbol `_ZTI9Processor` (`typeinfo for Processor`) is an external relocation — the dynamic linker will resolve it to the typeinfo address in the main executable (hence the importance of the `-rdynamic` flag when compiling the host).

---

## Step 7 — Reconstructing the complete plugin system protocol

Combining all observations from the previous steps, you can now document the complete protocol:

```
┌─────────────────────────────────────────────────────────────────┐
│                  PLUGIN PROTOCOL                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. DISCOVERY                                                   │
│     The host scans the ./plugins/ directory (configurable -p)   │
│     and filters files by .so extension                          │
│                                                                 │
│  2. LOADING                                                     │
│     dlopen(path, RTLD_NOW)                                      │
│     → The .so is mapped into memory, its relocations resolved   │
│                                                                 │
│  3. SYMBOL RESOLUTION                                           │
│     dlsym(handle, "create_processor")  → create_func_t          │
│     dlsym(handle, "destroy_processor") → destroy_func_t         │
│     → Two mandatory extern "C" symbols                          │
│                                                                 │
│  4. INSTANTIATION                                               │
│     Processor* obj = create_processor(id)                       │
│     → The plugin allocates and constructs a derived object      │
│     → The object is returned as Processor*                      │
│                                                                 │
│  5. USAGE                                                       │
│     The host calls obj->name(), obj->process(), etc.            │
│     → Virtual dispatch via the plugin's vtable                  │
│     → The host never knows the concrete type                    │
│                                                                 │
│  6. DESTRUCTION                                                 │
│     destroy_processor(obj)                                      │
│     → The plugin frees the object (delete)                      │
│     dlclose(handle)                                             │
│     → The .so is unloaded                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

This diagram is the main deliverable of this section. With it, you have everything needed to:

- Understand how the host interacts with plugins.  
- Write a compatible plugin (section 22.4 and checkpoint).  
- Identify suspicious behavior if a plugin does more than the interface provides for (malware context).

---

## Edge cases and common pitfalls

**`RTLD_LAZY` vs `RTLD_NOW`** — With `RTLD_LAZY`, symbols are only resolved on first call. This means a `dlopen` can succeed even if the plugin has missing dependencies — the error will only occur at runtime. In RE, if you see `RTLD_LAZY` (flag = 1), know that `dlopen` alone does not guarantee the plugin is valid.

**Mangled symbols as factory** — Some applications use C++ mangled symbol names as plugin entry points (instead of `extern "C"`). The `dlsym` will then contain a string like `_ZN6PluginC1Ev`. This is rarer because it is fragile (mangling depends on the compiler and ABI), but it exists.

**`dlmopen` and namespaces** — On some complex plugin architectures, you will encounter `dlmopen` which loads the library in a separate linker namespace. Symbols are not shared between namespaces, which complicates RTTI resolution. In RE, the approach remains the same but vtable addresses between host and plugin no longer share the same typeinfo.

**Plugins that load other plugins** — A plugin can itself call `dlopen`. This is frequent in layered architectures (a codec plugin loading a hardware decoding sub-plugin, for example). Frida with the recursive hook shown above will capture these nested loadings automatically.

---

## Summary

Analyzing a `dlopen`/`dlsym` plugin system follows a three-phase process. First, **static detection**: spotting `dl*` imports, factory symbol strings in `.rodata`, and the `opendir`/`readdir` pattern. Then, **static reconstruction** in Ghidra: following the flow from `dlopen` to the factory call, identifying the interface contract, and linking the plugin to the host's class hierarchy via RTTI relocations. Finally, **dynamic validation**: `ltrace` for a quick overview, GDB to inspect objects and vtables in memory, Frida for automated tracing and hooking of the plugin's virtual methods.

The result of this analysis is a complete understanding of the plugin protocol: how it is discovered, loaded, instantiated, used, and destroyed. This understanding is the necessary foundation for the next section, where we will dive into the details of virtual dispatch that allows the host to call plugin methods without knowing its concrete type.

---


⏭️ [Understanding virtual dispatch: from vtable to method call](/22-oop/03-virtual-dispatch.md)
