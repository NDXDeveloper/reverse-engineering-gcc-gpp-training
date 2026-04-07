🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 5.4 — `ldd` and `ldconfig` — dynamic dependencies and resolution

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Introduction

In the previous section, `nm -D` revealed the names of the functions imported by the binary — `printf`, `strcmp`, `strlen`… But it did not tell us **where** these functions actually come from at runtime. When the dynamic loader (`ld.so`) loads the program into memory, it has to locate each shared library (`.so`) containing the required symbols, map it into memory, and resolve the addresses. If a single dependency is missing or incompatible, the program refuses to start.

Understanding a binary's dynamic dependencies is an essential triage step for several reasons:

- **Functional clue**: the list of linked libraries reveals the program's capabilities. A binary that depends on `libssl.so` does cryptography. A binary that depends on `libpcap.so` captures network traffic. A binary that depends on `libpthread.so` is multithreaded.  
- **Compatibility**: a binary compiled on one distribution may not work on another if library versions differ. Knowing the exact dependencies helps diagnose this kind of problem.  
- **Attack surface**: every linked library is a potential hijacking vector (`LD_PRELOAD`, Linux-style DLL hijacking, `.so` replacement). Knowing which libraries are loaded and from which path is a piece of security information.  
- **Static vs dynamic binary**: a binary with no dynamic dependencies is statically linked — all code is embedded. This changes the RE approach considerably (bigger binary, no dynamic symbols, no PLT/GOT).

This section presents `ldd`, the tool that lists dynamic dependencies and their resolution paths, as well as `ldconfig` and the library-resolution mechanism under Linux.

---

## `ldd` — listing dynamic dependencies

### How it works

`ldd` displays the list of shared libraries a binary depends on, as well as the **full path** to the `.so` file that will actually be loaded at runtime. It works by invoking the dynamic loader (`ld.so`) with special environment variables that tell it to display the resolutions without actually executing the program.

### Basic usage

```bash
$ ldd keygenme_O0
	linux-vdso.so.1 (0x00007ffcabffe000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2a3c600000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f2a3c8f2000)
```

Each line follows the format: **library name** `=>` **resolved path** `(load address)`. Let's break down the three entries:

**`linux-vdso.so.1`** — the *Virtual Dynamic Shared Object*. It is not a file on disk — it is a memory page injected directly by the Linux kernel into every process's address space. It contains optimized implementations of some frequent system calls (`gettimeofday`, `clock_gettime`, `getcpu`) that can execute in user space without the cost of crossing into kernel mode. The vDSO has no filesystem path, which is why there is no `=>` followed by a path. The address in parentheses varies on every execution because of ASLR.

**`libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6`** — the GNU standard C library (glibc). This is where `printf`, `strcmp`, `strlen`, `malloc`, and hundreds of other functions live. The `=>` indicates that the `libc.so.6` name has been resolved to the file `/lib/x86_64-linux-gnu/libc.so.6` on the system. That path depends on the distribution: on Arch Linux it would be `/usr/lib/libc.so.6`, on CentOS `/lib64/libc.so.6`. The address in parentheses is the base address at which the library would be loaded.

**`/lib64/ld-linux-x86-64.so.2`** — the dynamic loader itself. It is listed because it is technically part of the process's dependencies (it is the first thing invoked to load everything else). Its path is absolute and matches the `INTERP` field seen in the program headers with `readelf -l`.

### A binary with more dependencies

On a more complex program, the list is longer and reveals the program's capabilities:

```bash
$ ldd /usr/bin/curl
	linux-vdso.so.1 (0x00007fff6c5fc000)
	libcurl.so.4 => /lib/x86_64-linux-gnu/libcurl.so.4 (0x00007f3e8c400000)
	libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f3e8c3e0000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f3e8c3d8000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3e8c200000)
	libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x00007f3e8c150000)
	libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3 (0x00007f3e8bd00000)
	libnghttp2.so.14 => /lib/x86_64-linux-gnu/libnghttp2.so.14 (0x00007f3e8bcd0000)
	[...]
	/lib64/ld-linux-x86-64.so.2 (0x00007f3e8c6a0000)
```

Without even knowing `curl`, this output teaches us that the program uses network transfers (`libcurl`), compression (`libz`), multi-threading (`libpthread`), TLS/SSL (`libssl`, `libcrypto`), and HTTP/2 (`libnghttp2`). Each library is a lead for RE investigation.

### The case of a statically linked binary

```bash
$ ldd static_binary
	not a dynamic executable
```

This message indicates the binary has no dynamic dependencies — all code is embedded in the executable. We can confirm with `file`:

```bash
$ file static_binary
static_binary: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, [...]
```

A statically linked binary is significantly bigger (often several megabytes even for a simple program) because it embeds a copy of every libc function it uses. For RE, this means:

- No `.dynsym` section — imported function names are absent.  
- No PLT/GOT — function calls are direct.  
- libc functions are inlined into the binary and can be hard to identify without signatures (FLIRT in IDA, function ID in Ghidra — see Chapter 20, section 20.5).

### Transitive dependencies

`ldd` does not just list the binary's **direct** dependencies (those declared by the `NEEDED` entries in the `.dynamic` section). It also resolves **transitive** dependencies — libraries that the program's libraries themselves depend on.

For example, if your binary depends on `libcurl.so.4`, and `libcurl.so.4` depends on `libssl.so.3`, `libz.so.1`, etc., all those indirect dependencies will appear in `ldd`'s output. To distinguish direct from transitive dependencies, compare with `readelf -d`:

```bash
# Direct dependencies only (from the .dynamic section)
$ readelf -d keygenme_O0 | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]

# All dependencies (direct + transitive)
$ ldd keygenme_O0
	linux-vdso.so.1 (0x00007ffcabffe000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2a3c600000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f2a3c8f2000)
```

In this simple case, the only direct dependency is `libc.so.6`. The other two (`linux-vdso.so.1` and `ld-linux-x86-64.so.2`) are system components that are always present. On a more complex binary, the difference between direct and transitive dependencies can be significant.

### Missing dependencies

If a library cannot be found, `ldd` clearly signals it:

```bash
$ ldd binary_with_missing_dep
	linux-vdso.so.1 (0x00007ffce93f8000)
	libcustom_crypto.so.1 => not found
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8a1c600000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f8a1c8f0000)
```

`not found` indicates the loader cannot find `libcustom_crypto.so.1`. The program will refuse to start until this dependency is satisfied. For RE, a missing dependency is a clue: it may correspond to a proprietary library, a separately deployed component, or an artifact of the build environment.

### Security warning on `ldd`

> ⚠️ **`ldd` is not safe on an untrusted binary.**

`ldd` works by invoking the dynamic loader on the target binary. On some systems and configurations, this can lead to partial execution of the binary's code — in particular the constructors defined in the `.init` and `.init_array` sections, which run before `main()`.

A malicious binary could exploit this behavior to execute code simply by being analyzed with `ldd`. This is a known and documented risk.

**Safe alternatives** to list dependencies without any risk of execution:

```bash
# Method 1: readelf -d (parses only headers, executes nothing)
$ readelf -d suspect_binary | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]

# Method 2: objdump -p (same principle, parsing only)
$ objdump -p suspect_binary | grep NEEDED
  NEEDED               libc.so.6
```

Both methods only list **direct** dependencies (with no path resolution or transitive dependencies), but they are completely safe because they merely parse the ELF headers without ever invoking the loader.

In a malware-analysis environment (Chapter 26), **never use `ldd` directly on a suspicious binary**. Prefer `readelf -d`, or run `ldd` inside a disposable sandbox.

---

## The library-resolution mechanism under Linux

When the dynamic loader (`ld-linux-x86-64.so.2`) receives a dependency like `libc.so.6`, it has to find the corresponding `.so` file on the filesystem. It follows a precise search algorithm, in the following order:

### 1. `DT_RPATH` / `DT_RUNPATH` (encoded in the binary)

The binary can contain search paths compiled directly into its `.dynamic` section. Those paths are added at compile time with the `-rpath` or `-runpath` options of `ld`:

```bash
$ readelf -d binary | grep -E 'RPATH|RUNPATH'
 0x000000000000001d (RUNPATH)            Library runpath: [/opt/myapp/lib]
```

If present, the loader will look for `.so` files in `/opt/myapp/lib` before any other location. This is common in commercial software that ships its own libraries.

### 2. `LD_LIBRARY_PATH` (environment variable)

If the `LD_LIBRARY_PATH` environment variable is defined, its directories are consulted next:

```bash
$ export LD_LIBRARY_PATH=/home/user/custom_libs:/opt/libs
$ ldd keygenme_O0
# The loader will search /home/user/custom_libs first, then /opt/libs
```

For RE, `LD_LIBRARY_PATH` is an interposition tool: you can force the loading of a modified version of a library by placing it in a higher-priority directory. This is a technique close to `LD_PRELOAD` (Chapter 22, section 22.4).

### 3. The `ldconfig` cache (`/etc/ld.so.cache`)

This is the primary resolution mechanism on a standard system. The `/etc/ld.so.cache` file is a binary cache that maps library names to their full paths. It is generated by the `ldconfig` command.

### 4. The default directories

As a last resort, the loader searches the standard system directories: `/lib`, `/usr/lib`, and on 64-bit systems, `/lib64`, `/usr/lib64`, as well as multi-arch directories like `/lib/x86_64-linux-gnu` on Debian/Ubuntu.

---

## `ldconfig` — managing the library cache

### Role of `ldconfig`

`ldconfig` is the administration tool that maintains the `/etc/ld.so.cache` cache. Its role is twofold:

1. **Scan the directories** listed in `/etc/ld.so.conf` (and its included files from `/etc/ld.so.conf.d/`) to inventory every available shared library.  
2. **Create and update the versioning symlinks** (for example, `libssl.so.3` → `libssl.so.3.0.12`).

### Listing the current cache

```bash
$ ldconfig -p | head -20
1847 libs found in cache `/etc/ld.so.cache'
	libz.so.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libz.so.1
	libxtables.so.12 (libc6,x86-64) => /lib/x86_64-linux-gnu/libxtables.so.12
	libxml2.so.2 (libc6,x86-64) => /lib/x86_64-linux-gnu/libxml2.so.2
	[...]
```

The `-p` option (or `--print-cache`) displays the cache content in readable form. Each entry shows the library name, its architecture (`libc6,x86-64`), and its resolved path.

### Searching for a specific library

```bash
# Where is libssl?
$ ldconfig -p | grep libssl
	libssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3

# Which crypto libraries are available?
$ ldconfig -p | grep -iE '(crypto|ssl|gnutls)'
	libssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3
	libgnutls.so.30 (libc6,x86-64) => /lib/x86_64-linux-gnu/libgnutls.so.30
	libcrypto.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libcrypto.so.3

# How many libraries in total?
$ ldconfig -p | head -1
1847 libs found in cache `/etc/ld.so.cache'
```

### Usefulness for RE

`ldconfig -p` is useful in two situations:

**Check a dependency's availability** — when `ldd` signals `not found`, you can check whether the library exists in the cache, whether it is present under a slightly different name (version problem), or whether it is completely absent from the system.

**Identify the exact version of a library** — for deep reversing, it is sometimes necessary to analyze the library's code itself (for example, to understand the exact behavior of an encryption function called by the binary). `ldconfig -p` gives the exact path to the `.so` file, on which you can then use all the tools seen in this chapter.

---

## `LD_PRELOAD` — a word on library interposition

Although Chapter 22 (section 22.4) is devoted to patching via `LD_PRELOAD`, it is worth understanding the principle now, as it is tightly linked to the library-resolution mechanism.

The `LD_PRELOAD` environment variable forces a shared library to be loaded **before** all others. If that library defines a symbol with the same name as one in a standard library (for example `strcmp`), the preloaded version will be used, because the loader resolves symbols in the order of loading.

```bash
# Principle (detailed in Chapter 22)
$ LD_PRELOAD=./my_custom_libc.so ./keygenme_O0
```

This technique is a powerful RE tool: you can intercept and modify the behavior of any library function without modifying the binary itself. It relies entirely on the dynamic-resolution mechanism we just described.

> ⚠️ `LD_PRELOAD` is ignored for setuid/setgid binaries, for obvious security reasons.

---

## Checking required symbol versions

GNU/Linux libraries use a **symbol versioning** mechanism that lets the same library provide multiple versions of the same function. For example, `libc.so.6` can simultaneously provide `realpath@GLIBC_2.2.5` (old implementation) and `realpath@GLIBC_2.3` (new implementation).

We already got a glimpse of this versioning in section 5.3 with the `@GLIBC_2.2.5` and `@GLIBC_2.34` suffixes in `nm -D` output. For a detailed view of required versions:

```bash
$ readelf -V keygenme_O0

Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x0000000000000598  Offset: 0x000598  Link: 7 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 2
  0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 3
  0x0020:   Name: GLIBC_2.34   Flags: none  Version: 2
```

This output tells us the binary requires two versions of the GLIBC interface: `GLIBC_2.2.5` and `GLIBC_2.34`. The highest version (`GLIBC_2.34`) is the binding constraint — the binary will not work on a system with a glibc older than 2.34.

To know which glibc version is installed:

```bash
$ /lib/x86_64-linux-gnu/libc.so.6 --version
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8) stable release version 2.39.
[...]

# Or more simply:
$ ldd --version
ldd (Ubuntu GLIBC 2.39-0ubuntu8) 2.39
```

This check is essential when a binary compiled on a recent system refuses to run on an older one with the classic error:

```
./program: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found
```

---

## Practical workflow: from dependency to analysis

Here is how dependency information fits into the RE process:

```bash
# 1. List direct dependencies (safe, even on a suspicious binary)
$ readelf -d keygenme_O0 | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]

# 2. Resolve full paths (if the binary is trusted)
$ ldd keygenme_O0
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2a3c600000)
	[...]

# 3. Check the library's exact version
$ file /lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64-linux-gnu/libc.so.6: ELF 64-bit LSB shared object, x86-64, [...]

# 4. If needed, analyze the library itself
$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep strcmp
0000000000091ef0 T strcmp
0000000000091ef0 i strcmp

# 5. Check the required symbol versions
$ readelf -V keygenme_O0
```

This workflow starts from the question "what does this binary depend on?" and drills down to the level of detail required. In most cases, steps 1 and 2 are enough. Steps 3 through 5 come into play when you need to understand the exact behavior of a library function or diagnose a compatibility problem.

---

## What to remember going forward

- **`ldd` gives the complete dependency map** — names, resolved paths, and load addresses. Every listed library is a functional clue about the program's behavior.  
- **Never use `ldd` on a suspicious binary** — prefer `readelf -d | grep NEEDED`, which parses headers with no risk of code execution.  
- **`readelf -d | grep NEEDED`** lists direct dependencies. `ldd` adds transitive dependencies and path resolution.  
- **The resolution order** is: `RPATH`/`RUNPATH` → `LD_LIBRARY_PATH` → `ldconfig` cache → default directories. It is this order that makes interposition techniques like `LD_PRELOAD` possible.  
- **`ldconfig -p`** lets you search a library in the system cache and get its exact path.  
- **Symbol versioning** (`@GLIBC_2.x.y`) indicates the minimum required library version. `readelf -V` gives the full detail.  
- A `not a dynamic executable` message from `ldd` means a statically linked binary — the RE approach changes significantly (no `.dynsym`, no PLT/GOT, bigger binary).

---


⏭️ [`strace` / `ltrace` — system calls and library calls (syscall vs libc)](/05-basic-inspection-tools/05-strace-ltrace.md)
