🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 11.8 — GDB Python API — scripting and automation

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## Going beyond interactive scripting's limits

Previous sections showed how to automate simple tasks with `commands` blocks and convenience variables (`$count`, `$base`, etc.). These mechanisms suffice for basic logging — display `strcmp` arguments at each call, count a loop's iterations. But they quickly reach their limits:

- GDB's command language has no data structures (no lists, dictionaries, sets).  
- String handling is rudimentary (no slicing, advanced formatting, regular expressions).  
- There's no error handling (an `x/s` on an invalid address interrupts the script).  
- You can't interact with the filesystem, network, or other tools.  
- Writing complex conditional logic with `if`/`else`/`while` in GDB syntax is painful and unreadable.

**GDB's Python API** solves all these limitations. Since GDB 7.0 (2009), a complete Python interpreter is embedded in GDB. It exposes the debugger's entire state — breakpoints, registers, memory, frames, threads, symbols — as Python objects manipulable with the full power of the language. You can write Python scripts that execute in GDB's context, access the same information as interactive commands, and produce structured results.

For the reverse engineer, it's a category change: you move from an interactive tool used manually to a **programmable analysis platform**.

## First steps: running Python in GDB

### Inline `python` command

The most direct way to execute Python in GDB is the `python` command:

```
(gdb) python print("Hello from GDB Python")
Hello from GDB Python
```

For a multi-line block:

```
(gdb) python
>import os
>print(f"GDB process PID: {os.getpid()}")
>print(f"Current directory: {os.getcwd()}")
>end
GDB process PID: 12345  
Current directory: /home/user/binaries/ch11-keygenme  
```

The block ends with `end` on its own line, like `commands` blocks.

### Loading an external Python script

For longer scripts, write them in a `.py` file and load them with `source`:

```
(gdb) source my_script.py
```

Or at GDB launch:

```bash
$ gdb -q -x my_script.py ./keygenme_O0
```

The script executes in GDB's context with full access to the `gdb` module.

### Checking Python availability

On most modern distributions, GDB is compiled with Python support. To verify:

```
(gdb) python print(gdb.VERSION)
14.2

(gdb) python import sys; print(sys.version)
3.11.6 (main, Oct  2 2023, 13:45:54) [GCC 13.2.0]
```

If `python` produces a `Python scripting is not supported in this copy of GDB` error, you need to install a GDB version compiled with Python (standard `gdb` package on Debian/Ubuntu/Fedora).

## The `gdb` module: API anatomy

Everything goes through the `gdb` module, automatically imported in GDB's Python context. Here are its main components, organized by category.

### Executing GDB commands from Python

The `gdb.execute()` function is the bridge between Python and GDB's command language:

```python
# Execute a GDB command
gdb.execute("break main")

# Capture the output in a Python string
output = gdb.execute("info registers", to_string=True)  
print(output)  

# Execute silently (no display in GDB terminal)
gdb.execute("continue", from_tty=False)
```

The `to_string=True` parameter is crucial: it redirects the command's output to a Python string instead of displaying it in the terminal. You can then parse this string with the usual Python tools.

### Reading and writing registers

```python
# Read a register
rax = gdb.selected_frame().read_register("rax")  
rdi = gdb.selected_frame().read_register("rdi")  
rip = gdb.selected_frame().read_register("rip")  

print(f"rax = {int(rax):#x}")  
print(f"rdi = {int(rdi):#x}")  
print(f"rip = {int(rip):#x}")  
```

`read_register()` returns a `gdb.Value` object. Convert it to a Python integer with `int()` for numerical manipulations.

To write to a register:

```python
gdb.execute("set $rax = 1")
```

There's no direct `write_register()` method in the API — you go through `gdb.execute()` with the `set` command.

### Reading and writing memory

The `gdb.selected_inferior()` object represents the debugged process and gives access to its memory:

```python
inferior = gdb.selected_inferior()

# Read 32 bytes at an address
data = inferior.read_memory(0x7fffffffe100, 32)
# data is a memoryview object, convertible to bytes
raw = bytes(data)  
print(raw)           # b'TEST-KEY\n\x00\x00...'  
print(raw.hex())     # 544553542d4b45590a00...  

# Read a null-terminated string
addr = 0x402010  
data = inferior.read_memory(addr, 64)  
string = bytes(data).split(b'\x00')[0].decode('utf-8', errors='replace')  
print(string)        # "Enter your key: "  
```

To write to memory:

```python
# Write raw bytes
inferior.write_memory(0x7fffffffe100, b"PATCHED\x00")

# Write an integer value (4 bytes, little-endian)
import struct  
inferior.write_memory(0x404050, struct.pack("<I", 42))  
```

### Evaluating C expressions

`gdb.parse_and_eval()` evaluates an expression in the debugged program's context, exactly like the `print` command:

```python
# Evaluate a C expression
result = gdb.parse_and_eval("check_key(input)")  
print(f"Return: {int(result)}")  

# Read a variable
argc = gdb.parse_and_eval("argc")  
print(f"argc = {int(argc)}")  

# Dereference a pointer
val = gdb.parse_and_eval("*(int *)0x404050")  
print(f"Value at 0x404050: {int(val)}")  

# Access a register
rax = gdb.parse_and_eval("$rax")  
print(f"rax = {int(rax):#x}")  
```

It's often the most concise method to read a value, but it's slower than `read_register()` because it goes through GDB's expression parser.

### Navigating stack frames

```python
# Current frame
frame = gdb.selected_frame()  
print(f"Function: {frame.name()}")           # "check_key" or None if stripped  
print(f"PC: {frame.pc():#x}")                # Current address  
print(f"Architecture: {frame.architecture().name()}")  

# Walk up the stack
caller = frame.older()  
if caller:  
    print(f"Caller: {caller.name()} at {caller.pc():#x}")

# Iterate over all frames
frame = gdb.newest_frame()  
while frame is not None:  
    print(f"  #{frame.level()} {frame.name() or '??'} @ {frame.pc():#x}")
    frame = frame.older()
```

### Manipulating breakpoints

```python
# Create a breakpoint
bp = gdb.Breakpoint("*0x401156")  
print(f"Breakpoint {bp.number} created at {bp.location}")  

# Conditional breakpoint
bp2 = gdb.Breakpoint("strcmp")  
bp2.condition = '*(char *)$rdi == 0x56'    # First char = 'V'  

# List existing breakpoints
for bp in gdb.breakpoints():
    print(f"BP #{bp.number}: {bp.location}, enabled={bp.enabled}, hits={bp.hit_count}")

# Disable / delete
bp.enabled = False  
bp.delete()  
```

### Accessing symbols and types

```python
# Look up a symbol by name
sym, _ = gdb.lookup_symbol("check_key")  
if sym:  
    print(f"Type: {sym.type}")
    print(f"Address: {sym.value().address}")

# Look up a global symbol
sym = gdb.lookup_global_symbol("global_flag")  
if sym:  
    print(f"global_flag = {int(sym.value())}")

# Resolve an address to a symbol
block = gdb.block_for_pc(0x401156)  
if block and block.function:  
    print(f"Function at 0x401156: {block.function.name}")
```

## Scripted breakpoints: the `gdb.Breakpoint` class

The real power of the Python API lies in the ability to subclass `gdb.Breakpoint` to create breakpoints whose behavior is entirely defined in Python. The `stop()` method is called at each trigger and returns `True` to stop execution or `False` to continue.

### Basic structure

```python
class MyBreakpoint(gdb.Breakpoint):
    def __init__(self, location):
        super().__init__(location)
    
    def stop(self):
        # Inspect state...
        # Return True to stop, False to continue
        return False
```

### Example: log all calls to `strcmp`

```python
class StrcmpLogger(gdb.Breakpoint):
    def __init__(self):
        super().__init__("strcmp")
        self.silent = True          # Suppress GDB's standard message
        self.calls = []             # Accumulate results
    
    def stop(self):
        frame = gdb.selected_frame()
        rdi = int(frame.read_register("rdi"))
        rsi = int(frame.read_register("rsi"))
        
        inf = gdb.selected_inferior()
        try:
            s1 = bytes(inf.read_memory(rdi, 128)).split(b'\x00')[0].decode('utf-8', errors='replace')
            s2 = bytes(inf.read_memory(rsi, 128)).split(b'\x00')[0].decode('utf-8', errors='replace')
        except gdb.MemoryError:
            return False    # Invalid address, ignore
        
        self.calls.append((s1, s2))
        print(f"[strcmp] \"{s1}\" vs \"{s2}\"")
        
        return False    # Don't stop — continue execution

# Instantiate
logger = StrcmpLogger()
```

After a `run`, the `logger.calls` list contains all pairs of compared strings. You can analyze them after execution:

```python
for s1, s2 in logger.calls:
    if "KEY" in s1 or "KEY" in s2:
        print(f"  → Interesting comparison: \"{s1}\" vs \"{s2}\"")
```

### Example: advanced conditional breakpoint

Python conditions can be arbitrarily complex — far beyond what GDB's `if` syntax allows:

```python
import re

class SmartBreak(gdb.Breakpoint):
    """Stops on strcmp only if an argument matches a regex pattern."""
    
    def __init__(self, pattern):
        super().__init__("strcmp")
        self.silent = True
        self.pattern = re.compile(pattern)
    
    def stop(self):
        inf = gdb.selected_inferior()
        frame = gdb.selected_frame()
        
        for reg in ("rdi", "rsi"):
            addr = int(frame.read_register(reg))
            try:
                s = bytes(inf.read_memory(addr, 256)).split(b'\x00')[0].decode('utf-8', errors='replace')
                if self.pattern.search(s):
                    print(f"[MATCH] {reg} = \"{s}\"")
                    return True     # Stop — we found something
            except gdb.MemoryError:
                continue
        
        return False    # No match, continue

# Only stop when strcmp receives a string containing "KEY" or "PASS"
SmartBreak(r"(?i)(key|pass)")
```

This breakpoint uses Python regular expressions, handles memory errors, and only stops on relevant comparisons. It's incomparably more powerful than a classic `break strcmp if ...`.

## GDB events: reacting automatically

The API exposes an event system you can subscribe to:

```python
def on_stop(event):
    """Called at each program stop (breakpoint, watchpoint, signal...)."""
    if isinstance(event, gdb.BreakpointEvent):
        print(f"Stopped on breakpoint(s): {[bp.number for bp in event.breakpoints]}")
    elif isinstance(event, gdb.SignalEvent):
        print(f"Signal received: {event.stop_signal}")
    
    # Display key registers at each stop
    frame = gdb.selected_frame()
    rip = int(frame.read_register("rip"))
    rax = int(frame.read_register("rax"))
    print(f"  rip={rip:#x}  rax={rax:#x}")

gdb.events.stop.connect(on_stop)
```

Available events:

| Event | Triggered when... |  
|---|---|  
| `gdb.events.stop` | The program stops (breakpoint, signal, watchpoint, step) |  
| `gdb.events.cont` | The program resumes execution |  
| `gdb.events.exited` | The program terminates |  
| `gdb.events.new_thread` | A new thread is created |  
| `gdb.events.new_inferior` | A new process (inferior) is created |  
| `gdb.events.memory_changed` | Memory is modified by a GDB command |  
| `gdb.events.register_changed` | A register is modified by a GDB command |

To unsubscribe:

```python
gdb.events.stop.disconnect(on_stop)
```

## Creating custom GDB commands

You can define new GDB commands by subclassing `gdb.Command`:

```python
class DumpArgs(gdb.Command):
    """Display the first 6 arguments (System V AMD64 convention)."""
    
    def __init__(self):
        super().__init__("dump-args", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        frame = gdb.selected_frame()
        inf = gdb.selected_inferior()
        
        for i, reg in enumerate(regs):
            val = int(frame.read_register(reg))
            # Try to interpret as a string
            desc = ""
            if 0x400000 <= val <= 0x7fffffffffff:
                try:
                    data = bytes(inf.read_memory(val, 64)).split(b'\x00')[0]
                    if all(0x20 <= b < 0x7f for b in data) and len(data) > 2:
                        desc = f'  → "{data.decode()}"'
                except gdb.MemoryError:
                    pass
            print(f"  arg{i+1} ({reg}) = {val:#018x}{desc}")

DumpArgs()
```

After loading this script, a new command is available:

```
(gdb) dump-args
  arg1 (rdi) = 0x00007fffffffe100  → "TEST-KEY"
  arg2 (rsi) = 0x0000000000402020  → "VALID-KEY-2025"
  arg3 (rdx) = 0x000000000000000f
  arg4 (rcx) = 0x0000000000000000
  arg5 (r8)  = 0x0000000000000000
  arg6 (r9)  = 0x0000000000000000
```

The command automatically detects pointers to printable strings and displays them. You can use it at any breakpoint to instantly see the arguments of an unknown function.

Another example — a command to scan the stack for pointers to `.text` (return-address detection, useful on stripped binaries):

```python
class ScanStack(gdb.Command):
    """Scan the stack for return addresses in .text."""
    
    def __init__(self):
        super().__init__("scan-stack", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        depth = int(arg) if arg else 64     # Number of words to scan
        frame = gdb.selected_frame()
        rsp = int(frame.read_register("rsp"))
        inf = gdb.selected_inferior()
        
        # Find .text bounds
        mappings = gdb.execute("info proc mappings", to_string=True)
        text_start, text_end = None, None
        for line in mappings.splitlines():
            if "r-xp" in line and "libc" not in line and "ld-" not in line:
                parts = line.split()
                text_start = int(parts[0], 16)
                text_end = int(parts[1], 16)
                break
        
        if not text_start:
            print("Cannot find .text")
            return
        
        import struct
        data = bytes(inf.read_memory(rsp, depth * 8))
        for i in range(depth):
            val = struct.unpack_from("<Q", data, i * 8)[0]
            if text_start <= val < text_end:
                offset = rsp + i * 8
                # Check if the preceding instruction is a call
                try:
                    disas = gdb.execute(f"x/i {val - 5}", to_string=True)
                    marker = " ← probable ret addr" if "call" in disas else ""
                    print(f"  rsp+{i*8:#06x} [{offset:#x}]: {val:#x}{marker}")
                except:
                    print(f"  rsp+{i*8:#06x} [{offset:#x}]: {val:#x}")

ScanStack()
```

```
(gdb) scan-stack
  rsp+0x0038 [0x7fffffffe0f8]: 0x4011a5 ← probable ret addr
  rsp+0x0078 [0x7fffffffe138]: 0x401060
```

## Complete scripts: automated workflow examples

### Tracing calls to a list of functions

This script creates a logging breakpoint on each function in a list and produces an execution trace:

```python
# trace_calls.py — trace calls to targeted functions
import gdb  
import time  

class CallTracer(gdb.Breakpoint):
    trace = []
    
    def __init__(self, func_name):
        super().__init__(func_name)
        self.silent = True
        self.func_name = func_name
    
    def stop(self):
        frame = gdb.selected_frame()
        rdi = int(frame.read_register("rdi"))
        rsi = int(frame.read_register("rsi"))
        rdx = int(frame.read_register("rdx"))
        
        entry = {
            "func": self.func_name,
            "rdi": rdi, "rsi": rsi, "rdx": rdx,
            "rip": int(frame.read_register("rip")),
            "caller": frame.older().pc() if frame.older() else 0
        }
        CallTracer.trace.append(entry)
        return False

# Functions to trace
targets = ["strcmp", "memcmp", "strlen", "strcpy", "malloc", "free", "open"]  
for func in targets:  
    try:
        CallTracer(func)
    except:
        pass    # Function doesn't exist in this binary

# End-of-program hook to display summary
def on_exit(event):
    print(f"\n{'='*60}")
    print(f"Complete trace: {len(CallTracer.trace)} calls captured")
    print(f"{'='*60}")
    for i, e in enumerate(CallTracer.trace):
        print(f"  [{i:3d}] {e['func']:10s}  rdi={e['rdi']:#x}  "
              f"caller={e['caller']:#x}")

gdb.events.exited.connect(on_exit)
```

### Exporting results in JSON

A major advantage of Python: you can export results in structured formats for later analysis:

```python
# export_analysis.py — export analysis data in JSON
import gdb  
import json  

class AnalysisExporter:
    def __init__(self, output_path):
        self.output_path = output_path
        self.data = {
            "binary": gdb.current_progspace().filename,
            "breakpoint_hits": [],
            "memory_snapshots": [],
            "strings_found": []
        }
    
    def capture_state(self, label=""):
        frame = gdb.selected_frame()
        inf = gdb.selected_inferior()
        
        state = {
            "label": label,
            "rip": int(frame.read_register("rip")),
            "registers": {}
        }
        for reg in ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp"]:
            state["registers"][reg] = int(frame.read_register(reg))
        
        self.data["breakpoint_hits"].append(state)
    
    def save(self):
        with open(self.output_path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"Analysis exported to {self.output_path}")

exporter = AnalysisExporter("/tmp/analysis_results.json")
```

The JSON file can then be re-read by an external Python script, imported into a Jupyter notebook, or compared with another binary's analysis.

## Integration in the `.gdbinit` file

You can automatically load your Python scripts at GDB startup:

```
# ~/.gdbinit
source ~/re-toolkit/dump_args.py  
source ~/re-toolkit/scan_stack.py  
source ~/re-toolkit/strcmp_logger.py  

# Or an entire directory
python  
import glob, os  
for f in sorted(glob.glob(os.path.expanduser("~/re-toolkit/gdb-scripts/*.py"))):  
    gdb.execute(f"source {f}")
end
```

Custom commands (`dump-args`, `scan-stack`, etc.) become available in all GDB sessions, like native commands.

## Limits and best practices

**Performance.** Each trigger of a Python breakpoint causes a round-trip between the debugged process and GDB's Python interpreter. On a loop executed millions of times, this considerably slows execution. For intensive tracing cases, prefer Frida (Chapter 13) which injects code directly into the process without ptrace round-trips.

**Thread safety.** GDB's Python API is not thread-safe. Don't launch Python threads that simultaneously access `gdb.*` objects. All code must execute in GDB's main thread.

**Error handling.** Systematically wrap memory accesses with `try/except gdb.MemoryError`. An invalid address in a register must not crash the entire script:

```python
try:
    data = bytes(inferior.read_memory(addr, 64))
except gdb.MemoryError:
    data = None
```

**Idempotence.** When you reload a script with `source`, classes and instances are recreated. If the script creates breakpoints, they accumulate at each reload. Add cleanup logic:

```python
# Delete old breakpoints from this script before creating new ones
for bp in gdb.breakpoints() or []:
    if hasattr(bp, '_my_script_marker'):
        bp.delete()
```

**Debugging the scripts themselves.** Python errors are displayed in GDB's terminal. For finer debugging, use `traceback`:

```python
import traceback  
try:  
    # Code likely to crash
    pass
except Exception as e:
    traceback.print_exc()
```

---

> **Takeaway:** GDB's Python API transforms the debugger into a programmable analysis platform. Scripted breakpoints (`gdb.Breakpoint` with `stop()`) allow creating arbitrarily complex observation probes. Custom commands (`gdb.Command`) enrich GDB's vocabulary with RE-adapted tools. And the ability to export results to JSON, parse outputs with regex, accumulate statistics in Python dictionaries — all of this makes GDB Python scripting the glue that ties dynamic analysis to the rest of the reverse-engineering workflow. This chapter's checkpoint will put these skills into practice with a complete automated tracing script.

⏭️ [Introduction to `pwntools` to automate interactions with a binary](/11-gdb/09-introduction-pwntools.md)
