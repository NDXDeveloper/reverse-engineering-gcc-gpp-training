🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.7 — Debugger detection techniques (`ptrace`, timing checks, `/proc/self/status`)

> 🎯 **Objective**: Understand the most common debugger detection techniques on Linux, know how to identify them in disassembly and the decompiler, and master the bypass methods adapted to each technique.

---

## The principle of debugger detection

The previous sections covered passive protections: stripping removes information, packing hides code, obfuscation deforms logic, memory protections restrict manipulations. None of these techniques actively react to an analyst's presence.

Debugger detection is an **active** protection. The binary inspects its own execution environment looking for clues betraying a debugger's presence. If it detects one, it modifies its behavior: exit immediately, display a fake result, corrupt its own data, take a different execution path, or simply loop forever.

It's a cat and mouse game. Each detection technique has its bypasses, and each bypass can itself be detected by a second-level technique. In practice, most binaries implement only the classic techniques — those covered in this section — and an analyst who knows them neutralizes them in minutes.

Our training binary `anti_reverse.c` implements three of these techniques, individually activatable to study them in isolation.

## Technique 1 — `PTRACE_TRACEME`

### How it works

This is the most classic debugger detection technique on Linux, and often the first a RE beginner encounters. It relies on a fundamental property of the `ptrace` API: **a process can only be traced by a single parent at a time**.

When GDB attaches a process (or launches it), it uses `ptrace(PTRACE_ATTACH, ...)` or `ptrace(PTRACE_TRACEME, ...)` to establish the tracing relationship. This relationship is exclusive — the kernel refuses a second `ptrace` on an already-traced process.

The technique exploits this exclusivity: the binary attempts to trace itself at startup with `PTRACE_TRACEME`. If the call succeeds, nobody else is tracing it — no debugger. If the call fails (returns `-1` with `errno = EPERM`), a debugger is already attached.

### Implementation in our binary

Here's the implementation in `anti_reverse.c`:

```c
static int check_ptrace(void)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1; /* debugger detected */
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0;
}
```

And in `main()`:

```c
if (check_ptrace()) {
    fprintf(stderr, "%s", msg_env_error);
    return 1;
}
```

The error message is intentionally vague (`"Error: non-conforming environment."`) to avoid indicating the refusal's cause. A message like `"Debugger detected"` would make the analyst's job too easy.

### Recognizing the technique in disassembly

In disassembly, the `ptrace` detection manifests as:

```nasm
; Call to ptrace(PTRACE_TRACEME, 0, 0, 0)
xor    ecx, ecx              ; 4th argument = NULL  
xor    edx, edx              ; 3rd argument = NULL  
xor    esi, esi              ; 2nd argument = 0 (pid)  
xor    edi, edi              ; 1st argument = PTRACE_TRACEME (0)  
call   ptrace@plt  
; Return check
cmp    rax, -1               ; or: test rax, rax / js  
je     .debugger_detected  
```

Key indicators:

- A call to `ptrace@plt` visible in dynamic imports (even on a stripped binary)  
- The first argument (`edi`) is `0`, corresponding to `PTRACE_TRACEME` (the constant equals 0 in `<sys/ptrace.h>`)  
- The return is compared to `-1` or tested for a negative result  
- The failure branch leads to a program exit or error message

In Ghidra, the decompiler produces something very readable:

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    fprintf(stderr, "Error: non-conforming environment.\n");
    return 1;
}
```

### Bypasses

**Method 1 — `LD_PRELOAD` with a fake `ptrace`**

Create a shared library that redefines `ptrace` to always return 0 (success):

```c
/* fake_ptrace.c */
long ptrace(int request, ...) {
    return 0;
}
```

```bash
gcc -shared -fPIC -o fake_ptrace.so fake_ptrace.c  
LD_PRELOAD=./fake_ptrace.so ./anti_reverse_ptrace_only  
```

The binary's `ptrace` function calls our version (returning 0) instead of the real one. The check passes without issue. This method is simple but doesn't work if the binary detects `LD_PRELOAD` (by reading `/proc/self/maps` or the environment variable).

**Method 2 — Patch the conditional jump**

In GDB or with a hex editor, invert the conditional jump following the `ptrace` call. Replace `je .debugger_detected` with `jne .debugger_detected` (change opcode `0x74` to `0x75`, or `0x84` to `0x85` for near jumps). The binary then follows the "no debugger" path even when ptrace fails.

**Method 3 — NOP the ptrace call**

Replace the `call ptrace@plt` instruction with `nop`s (opcode `0x90`), and ensure `eax` contains 0 afterward (which is often already the case if the argument preparation `xor` set `eax` to 0 earlier). This completely removes the check.

**Method 4 — Breakpoint after the check in GDB**

The most pragmatic method: don't try to bypass the check itself, but set a breakpoint *after* the detection block and manually modify the flow.

```
(gdb) break main
(gdb) run
(gdb) # identify address after ptrace check
(gdb) set $rip = 0x<address_after_check>
(gdb) continue
```

Or more elegantly, set a breakpoint on `ptrace` and force its return value:

```
(gdb) break ptrace
(gdb) run
(gdb) finish
(gdb) set $rax = 0
(gdb) continue
```

**Method 5 — Frida**

```javascript
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onLeave: function(retval) {
        retval.replace(ptr(0));
        console.log("[*] ptrace() → return 0 (bypassed)");
    }
});
```

Frida intercepts the `ptrace` call and forces the return value to 0.

### Variants and hardening

More robust `ptrace` detection implementations exist:

- **Direct syscall** — Instead of `ptrace()` (which goes through PLT and can be hooked via `LD_PRELOAD`), the binary uses `syscall(SYS_ptrace, PTRACE_TRACEME, ...)` or the `syscall` instruction directly in inline assembly. This bypasses `LD_PRELOAD` and PLT hooks.  
- **Multiple calls** — The `ptrace` check is repeated at multiple points in the program, not just at startup. A one-time bypass is no longer sufficient.  
- **Fork + ptrace** — The process creates a child with `fork()`, the child attempts to trace the parent with `PTRACE_ATTACH`. If the parent is already being debugged, the attach fails. This variant resists `LD_PRELOAD` bypass on `ptrace` since it's a separate process doing the test.

## Technique 2 — Reading `/proc/self/status`

### How it works

The virtual filesystem `/proc` exposes information about each running process. The file `/proc/self/status` contains metadata about the current process, including the `TracerPid` field:

```
$ cat /proc/self/status | grep TracerPid
TracerPid:	0
```

`TracerPid` indicates the PID of the process tracing the current process. If no debugger is attached, the value is `0`. If GDB (or any other `ptrace` tracer) is attached, the value is GDB's PID.

### Implementation in our binary

```c
static int check_procfs(void)
{
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp)
        return 0;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            fclose(fp);
            return (pid != 0) ? 1 : 0;
        }
    }
    fclose(fp);
    return 0;
}
```

### Recognizing the technique in disassembly

Indicators in disassembly:

- A call to `fopen@plt` with the string `"/proc/self/status"` as argument (visible in `.rodata`, even on a stripped binary)  
- A read loop with `fgets@plt`  
- A `strncmp@plt` or manual comparison against the string `"TracerPid:"`  
- A `strtol@plt` or `atoi@plt` to convert the numeric value  
- A test against 0 followed by a branch to the exit

The appearance of `"/proc/self/status"` in `strings` is an immediate alarm signal during triage. Other procfs files used for detection include `/proc/self/stat`, `/proc/self/wchan`, and `/proc/self/maps`.

### Bypasses

**Method 1 — Hook `fopen` to redirect the file**

```c
/* fake_procfs.c */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef FILE *(*real_fopen_t)(const char *, const char *);

FILE *fopen(const char *path, const char *mode) {
    real_fopen_t real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (strcmp(path, "/proc/self/status") == 0) {
        /* Redirect to a forged file with TracerPid: 0 */
        return real_fopen("/tmp/fake_status", mode);
    }
    return real_fopen(path, mode);
}
```

Prepare `/tmp/fake_status` with content identical to `/proc/self/status` but `TracerPid: 0`, then launch the binary with `LD_PRELOAD=./fake_procfs.so`.

**Method 2 — Frida**

```javascript
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path && path.indexOf("/proc/self/status") !== -1) {
            this.shouldPatch = true;
        }
    },
    onLeave: function(retval) {
        /* Patching is better done on fgets or strncmp */
    }
});

/* More direct approach: hook strncmp */
Interceptor.attach(Module.findExportByName(null, "strncmp"), {
    onEnter: function(args) {
        var s1 = args[0].readUtf8String();
        if (s1 && s1.indexOf("TracerPid:") !== -1) {
            /* Rewrite content to set TracerPid: 0 */
            args[0].writeUtf8String("TracerPid:\t0\n");
        }
    }
});
```

**Method 3 — Patch the branch in GDB**

Like for `ptrace`: identify the `cmp` testing the `TracerPid` value against 0, and force the result or jump over the check.

```
(gdb) break check_procfs
(gdb) run
(gdb) finish
(gdb) set $rax = 0
(gdb) continue
```

**Method 4 — `mount` namespace (advanced isolation)**

You can run the binary in a `mount` namespace where `/proc` is a custom filesystem, without real tracing information. This is the most robust but also the heaviest solution.

### Variants

- **Reading `/proc/self/stat`** — Field number 6 of `/proc/self/stat` also indicates the tracer's PID. The advantage for the binary author: the string `"TracerPid"` appears nowhere, parsing is done by position in the file.  
- **Reading `/proc/self/wchan`** — If the process is waiting on `ptrace_stop`, the `wchan` file contains this information.  
- **Reading `/proc/self/maps`** — To detect injected libraries (`LD_PRELOAD`) or Frida's presence (whose agent appears as a memory mapping named `frida-agent-*`).

## Technique 3 — Timing checks

### How it works

This is the most subtle of the three techniques. It doesn't look for a specific debugger signature — it measures the **execution time** of a code block.

When an analyst uses GDB in single-step mode (`stepi`, `nexti`), each instruction is executed individually. The process is stopped and restarted at each step, taking milliseconds per instruction. A block of 1000 instructions that normally executes in microseconds takes several seconds in single-stepping.

The binary measures time before and after a trivial block. If the elapsed time exceeds an abnormally high threshold, a debugger is slowing execution.

### Implementation in our binary

```c
static int check_timing(void)
{
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Trivial block — should take < 1 ms */
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);

    long elapsed_ms = (t2.tv_sec - t1.tv_sec) * 1000 +
                      (t2.tv_nsec - t1.tv_nsec) / 1000000;

    if (elapsed_ms > 50) {
        return 1; /* abnormally slow execution */
    }
    return 0;
}
```

The 50 ms threshold is conservative. In normal execution, the 1000-iteration loop takes well under a millisecond. Under GDB single-stepping, it takes tens of seconds.

### Time sources used

Different time sources offer different levels of precision and bypass resistance:

**`clock_gettime(CLOCK_MONOTONIC)`** — What our binary uses. Monotonic clock (never goes backward), nanosecond precision. It's a libc call using the vDSO to avoid a real syscall — therefore fast and difficult to intercept by a simple syscall hook.

**`rdtsc` / `rdtscp`** — The `rdtsc` assembly instruction (Read Time-Stamp Counter) directly reads the processor's cycle counter. It's the most precise method and hardest to bypass because there's no function call to hook — it's a single machine instruction:

```nasm
rdtsc                     ; EDX:EAX = cycle counter  
shl    rdx, 32  
or     rax, rdx           ; RAX = full 64-bit counter  
```

**`gettimeofday`** — Less precise than `clock_gettime` but widely used. Same principle.

**`time(NULL)`** — Second-only precision. Used with wide thresholds, or combined with long loops.

### Recognizing the technique in disassembly

Indicators:

- Two calls to a time function (`clock_gettime@plt`, `gettimeofday@plt`) bracketing a trivial code block  
- Or two `rdtsc` instructions bracketing a code block, with the difference compared to a threshold  
- A comparison of elapsed time (`cmp`, `sub`) against a constant (the threshold in milliseconds or cycles)  
- A branch to an error path if the threshold is exceeded  
- The `volatile` keyword in the original code manifests in assembly as repeated memory accesses on the loop variable instead of register optimization

The presence of `clock_gettime` or `gettimeofday` in dynamic imports isn't suspicious by itself (many legitimate programs measure time), but combined with a conditional branch immediately after, it's a timing check pattern.

### Bypasses

**Method 1 — Skip the entire block in GDB**

The simplest method: don't single-step through the timing check. Set a breakpoint **after** the check and execute the block in `continue` mode (full speed).

```
(gdb) break *0x<address_after_timing_check>
(gdb) run
(gdb) continue
```

At full execution speed, GDB doesn't slow the process detectably. The timing check only triggers if the analyst single-steps through the measured block.

**Method 2 — Force the comparison result**

Set a breakpoint on the `cmp` comparing elapsed time to the threshold, and modify the register or flag:

```
(gdb) break *0x<cmp_address>
(gdb) run
(gdb) set $eflags = ($eflags | 0x40)    # set ZF=1 so jg doesn't jump
(gdb) continue
```

Or directly modify the time variable to contain a value under the threshold.

**Method 3 — Hook the time source**

With `LD_PRELOAD` or Frida, intercept `clock_gettime` to return consistent values simulating fast execution:

```javascript
var clock_gettime = Module.findExportByName(null, "clock_gettime");  
var callCount = 0;  
var baseTime = 0;  

Interceptor.attach(clock_gettime, {
    onLeave: function(retval) {
        var timespec = this.context.rsi; // 2nd argument = struct timespec*
        if (callCount === 0) {
            baseTime = timespec.readU64();
        } else {
            // Simulate 1 µs elapsed per call
            timespec.writeU64(baseTime + callCount * 1000);
        }
        callCount++;
    }
});
```

This approach is more complex but necessary if the timing check is repeated throughout execution.

**Method 4 — Patch the threshold or NOP**

Modify the threshold constant in the binary (replace `50` with `999999999`) or NOP the comparison and conditional jump. This is a permanent patch rendering the check inoperative.

**Bypassing `rdtsc`** — If the timing check uses `rdtsc` rather than a libc call, `LD_PRELOAD` and Frida function hooks don't work (there's no function to hook). Options are:

- Patch the `rdtsc` instructions in the binary (replace them with `nop`s and load a fixed value)  
- Use a hypervisor that intercepts `rdtsc` (some VMs allow controlling the returned value)  
- Single-step only outside the measured block (method 1)

## Combining techniques

In practice, a serious binary combines all three techniques — that's what our `anti_reverse_all_checks` variant does. The execution order is designed to maximize resistance:

1. **`ptrace` first** — Detects GDB immediately at launch.  
2. **`/proc/self/status` second** — Detects debuggers that don't trigger `ptrace` (Frida in attach mode, certain custom tracers).  
3. **Timing check last** — Detects single-stepping through the code, even if both previous checks were bypassed.

Each check uses the same vague error message, preventing the analyst from knowing which check triggered the detection without reading the code.

### Global bypass strategy

Facing a binary combining multiple checks, the efficient strategy is to identify and neutralize all checks in a single pass:

1. **Triage with `strings`** — Look for `"/proc/self/status"`, `"TracerPid"`, and note the presence of `ptrace` and `clock_gettime` in imports (`nm -D`).  
2. **Quick static analysis** — In Ghidra, spot calls to `ptrace`, `fopen("/proc/self/status")`, and `clock_gettime` in the first functions called by `main`. Cross-references on these imports lead directly to the check functions.  
3. **Global Frida script** — Write a single script that hooks `ptrace`, `fopen`, and `clock_gettime` simultaneously. Launch the binary with this script and all checks pass at once.  
4. **Binary patching** — For a permanent solution, NOP the calls or invert conditional jumps in each detection block with a hex editor.

## Additional detection techniques

Beyond the three techniques implemented in our binary, other debugger detection methods exist on Linux. They're not implemented in `anti_reverse.c` to keep the binary pedagogical, but you'll encounter them in the wild:

**Signal handlers** — The process installs a handler for `SIGTRAP`. Normally, when the process executes an `int3` instruction (opcode `0xCC`), the handler is called and sets a flag. Under GDB, the `SIGTRAP` is intercepted by the debugger before reaching the process's handler — the flag is never set. The binary checks the flag and deduces a debugger's presence. Our binary installs a `SIGTRAP` handler for demonstration (`sigtrap_handler`), though it doesn't actively use it as a check.

**Environment detection** — Check for environment variables like `_` (which contains the launcher executable's path — `gdb` or `ltrace` reveal themselves there), `LD_PRELOAD` (betraying library injection), or `LINES`/`COLUMNS` (defined by terminals but not always in a debugging context).

**Reading `/proc/self/maps`** — Look for suspicious memory mappings: `frida-agent`, `vgdb` (Valgrind), or unknown `.so` libraries indicating injection.

**Detection by `ppid`** — Check if the parent process (`getppid()`) is a debugger by reading `/proc/<ppid>/comm` or `/proc/<ppid>/cmdline`.

**Reading `/proc/self/exe`** — Compare the on-disk binary with the in-memory image to detect modifications (software breakpoints).

Each of these techniques follows the same pattern: inspect the environment, detect an anomaly, react. And each can be bypassed with the same tool families: hooking (`LD_PRELOAD`, Frida), patching (GDB, hex editor), isolation (namespaces, VM).

---


⏭️ [Breakpoint countermeasures (self-modifying code, int3 scanning)](/19-anti-reversing/08-breakpoint-countermeasures.md)
