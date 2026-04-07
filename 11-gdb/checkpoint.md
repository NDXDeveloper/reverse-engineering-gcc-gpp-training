🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Write a GDB Python script that automatically dumps the arguments of each call to `strcmp`

> **Chapter 11 — Debugging with GDB**  
> **Part III — Dynamic Analysis**

---

## Goal

This checkpoint validates the skills acquired throughout Chapter 11 by mobilizing them in a single script. The objective is to produce a GDB Python script (`strcmp_dump.py`) that, once loaded in GDB, intercepts **every call to `strcmp`** in the target binary, displays both compared strings readably, accumulates results, and produces a **summary report** at the end of execution.

This type of script is an everyday RE tool: on a stripped binary, setting a scripted breakpoint on `strcmp` (or `memcmp`, `strncmp`) is often the fastest way to discover what the program compares — and therefore to extract keys, passwords, tokens, or expected values.

## Skills mobilized

| Section | Skill used |  
|---|---|  
| 11.1 | Understanding why the script also works on a stripped binary (`.dynsym` preserved) |  
| 11.2 | Breakpoints on library functions (`break strcmp`) |  
| 11.3 | Reading `rdi`/`rsi` registers (System V AMD64 arguments), memory reading with interpretation |  
| 11.4 | Working without symbols — `strcmp` is resolved via the PLT |  
| 11.5 | Breakpoint with conditional logic (noise filtering) |  
| 11.8 | Python API: `gdb.Breakpoint`, `read_register()`, `read_memory()`, `gdb.events.exited` |  
| 11.9 | Optional: launching the binary via pwntools and loading the script |

## Target binary

The script must work on `keygenme_O0` (with symbols) **and** `keygenme_O2_strip` (stripped and optimized). Both use `strcmp` to compare the user key with the expected key.

```bash
$ cd binaries/ch11-keygenme/
$ make    # Generates keygenme_O0, keygenme_O2, keygenme_O2_strip, etc.
```

## Script design

### General architecture

The script relies on three components:

1. **A scripted breakpoint** (`StrcmpDumper`) that subclasses `gdb.Breakpoint`, is set on `strcmp`, and implements `stop()` to capture arguments at each call.  
2. **An event handler** connected to `gdb.events.exited` that displays the summary report when the program terminates.  
3. **Robust memory-reading logic** that handles invalid addresses, non-printable strings, and abnormally long buffers.

### Technical challenges

Several problems must be anticipated:

**Invalid or very long strings.** The `rdi` or `rsi` register may contain an invalid address, a `NULL` pointer, or point to a multi-megabyte buffer. The script must read cautiously, with a maximum size and a `try/except` on `gdb.MemoryError`.

**Parasitic calls.** The glibc itself calls `strcmp` during program initialization (locale resolution, library loading). These calls have nothing to do with the binary's logic. The script must record them without polluting the main display — they'll be filtered in the report.

**Double encoding.** Compared strings may contain non-ASCII characters (raw bytes, partial UTF-8 sequences). Decoding must use `errors='replace'` to never crash.

**Performance.** On a program that calls `strcmp` hundreds of times, each trigger causes a ptrace round-trip. The script must be as lightweight as possible in `stop()` — accumulate data and defer analysis to the final report.

## Complete script: `strcmp_dump.py`

```python
#!/usr/bin/env python3
"""
strcmp_dump.py — GDB Python script to trace strcmp calls.

Usage in GDB:
    (gdb) source strcmp_dump.py
    (gdb) run
    
The script:
  1. Sets a silent breakpoint on strcmp.
  2. At each call, reads both strings (rdi, rsi) and records them.
  3. At program end, displays a summary report.
"""
import gdb

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
MAX_STRING_LEN = 256        # Maximum size read per string  
SHOW_LIVE = True            # Display each call in real time  
FILTER_EMPTY = True         # Ignore calls where a string is empty  

# ──────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────
def safe_read_string(inferior, addr, max_len=MAX_STRING_LEN):
    """Read a null-terminated C string at the given address.
    
    Returns the decoded string, or None if the address is invalid.
    """
    if addr == 0:
        return None
    
    try:
        raw = bytes(inferior.read_memory(addr, max_len))
    except gdb.MemoryError:
        return None
    
    # Extract up to the first null byte
    null_pos = raw.find(b'\x00')
    if null_pos != -1:
        raw = raw[:null_pos]
    
    # Decode to UTF-8 with replacement for invalid bytes
    return raw.decode('utf-8', errors='replace')


def is_printable_string(s):
    """Check if a string is reasonably printable."""
    if not s:
        return False
    printable_ratio = sum(1 for c in s if c.isprintable() or c in '\t\n\r') / len(s)
    return printable_ratio > 0.8


def format_string(s, max_display=80):
    """Format a string for display, with truncation if necessary."""
    if s is None:
        return "<NULL>"
    if len(s) == 0:
        return "<empty>"
    
    # Escape control characters
    display = repr(s)[1:-1]     # Use repr() and remove the quotes
    
    if len(display) > max_display:
        return display[:max_display - 3] + "..."
    return display

# ──────────────────────────────────────────────
# Scripted breakpoint
# ──────────────────────────────────────────────
class StrcmpDumper(gdb.Breakpoint):
    """Breakpoint on strcmp that captures arguments at each call."""
    
    def __init__(self):
        # Clean up previous instances (idempotence on reload)
        for bp in gdb.breakpoints() or []:
            if hasattr(bp, '_is_strcmp_dumper'):
                bp.delete()
        
        super().__init__("strcmp", type=gdb.BP_BREAKPOINT)
        self._is_strcmp_dumper = True    # Marker for cleanup
        self.silent = True               # Suppress standard GDB message
        self.calls = []                  # List of all captured calls
        self.call_count = 0
        
        gdb.write("[strcmp_dump] Breakpoint installed on strcmp.\n")
    
    def stop(self):
        """Called at each trigger. Returns False to not stop."""
        self.call_count += 1
        
        frame = gdb.selected_frame()
        inferior = gdb.selected_inferior()
        
        # Read the addresses of both arguments
        rdi = int(frame.read_register("rdi"))
        rsi = int(frame.read_register("rsi"))
        
        # Read the strings
        s1 = safe_read_string(inferior, rdi)
        s2 = safe_read_string(inferior, rsi)
        
        # Filter calls with an empty string if configured
        if FILTER_EMPTY and (s1 is None or s2 is None or s1 == "" or s2 == ""):
            return False
        
        # Identify the caller (return address)
        caller_frame = frame.older()
        caller_pc = caller_frame.pc() if caller_frame else 0
        caller_name = caller_frame.name() if caller_frame and caller_frame.name() else "??"
        
        # Record the call
        entry = {
            "num": self.call_count,
            "s1": s1,
            "s2": s2,
            "s1_addr": rdi,
            "s2_addr": rsi,
            "caller_pc": caller_pc,
            "caller_name": caller_name,
            "match": s1 == s2 if (s1 is not None and s2 is not None) else None
        }
        self.calls.append(entry)
        
        # Real-time display
        if SHOW_LIVE:
            match_indicator = ""
            if entry["match"] is True:
                match_indicator = "  ✓ MATCH"
            elif entry["match"] is False:
                match_indicator = "  ✗"
            
            gdb.write(
                f"[strcmp #{self.call_count}] "
                f"\"{format_string(s1)}\" vs \"{format_string(s2)}\""
                f"  (caller: {caller_name} @ {caller_pc:#x})"
                f"{match_indicator}\n"
            )
        
        return False    # Never stop — continue execution


# ──────────────────────────────────────────────
# End-of-execution report
# ──────────────────────────────────────────────
def on_exit(event):
    """Display the summary report when the program terminates."""
    if not hasattr(StrcmpDumper, '_instance'):
        return
    
    dumper = StrcmpDumper._instance
    calls = dumper.calls
    
    gdb.write(f"\n{'=' * 70}\n")
    gdb.write(f"  strcmp_dump REPORT — {len(calls)} calls captured "
              f"({dumper.call_count} total, {dumper.call_count - len(calls)} filtered)\n")
    gdb.write(f"{'=' * 70}\n\n")
    
    if not calls:
        gdb.write("  No strcmp calls captured.\n")
        return
    
    # Section 1: all calls
    gdb.write("  Recorded calls:\n")
    gdb.write(f"  {'#':>4}  {'Match':>5}  {'Caller':<20}  {'String 1':<30}  {'String 2':<30}\n")
    gdb.write(f"  {'—'*4}  {'—'*5}  {'—'*20}  {'—'*30}  {'—'*30}\n")
    
    for e in calls:
        match = " ✓" if e["match"] else " ✗" if e["match"] is False else " ?"
        caller = f"{e['caller_name']}"[:20]
        gdb.write(
            f"  {e['num']:>4}  {match:>5}  {caller:<20}  "
            f"{format_string(e['s1'], 30):<30}  "
            f"{format_string(e['s2'], 30):<30}\n"
        )
    
    # Section 2: exact matches (potentially interesting)
    matches = [e for e in calls if e["match"] is True]
    if matches:
        gdb.write(f"\n  Exact matches ({len(matches)}):\n")
        for e in matches:
            gdb.write(f"    strcmp #{e['num']}: \"{format_string(e['s1'])}\" "
                      f"(caller: {e['caller_name']} @ {e['caller_pc']:#x})\n")
    
    # Section 3: unique strings seen (deduplication)
    all_strings = set()
    for e in calls:
        if e["s1"] and is_printable_string(e["s1"]):
            all_strings.add(e["s1"])
        if e["s2"] and is_printable_string(e["s2"]):
            all_strings.add(e["s2"])
    
    if all_strings:
        gdb.write(f"\n  Unique strings observed ({len(all_strings)}):\n")
        for s in sorted(all_strings):
            gdb.write(f"    • {format_string(s)}\n")
    
    # Section 4: unique call sites
    callers = {}
    for e in calls:
        key = e["caller_pc"]
        if key not in callers:
            callers[key] = {"name": e["caller_name"], "count": 0}
        callers[key]["count"] += 1
    
    gdb.write(f"\n  Unique call sites ({len(callers)}):\n")
    for pc, info in sorted(callers.items(), key=lambda x: -x[1]["count"]):
        gdb.write(f"    {pc:#x} ({info['name']}) — {info['count']} call(s)\n")
    
    gdb.write(f"\n{'=' * 70}\n")


# ──────────────────────────────────────────────
# Initialization
# ──────────────────────────────────────────────
def init():
    """Script entry point."""
    # Create the breakpoint
    dumper = StrcmpDumper()
    StrcmpDumper._instance = dumper
    
    # Subscribe to the program-exit event
    # (disconnect first to avoid duplicates on reload)
    try:
        gdb.events.exited.disconnect(on_exit)
    except ValueError:
        pass    # Not yet connected
    gdb.events.exited.connect(on_exit)
    
    gdb.write("[strcmp_dump] Script loaded. Launch the program with 'run'.\n")
    gdb.write(f"[strcmp_dump] Config: SHOW_LIVE={SHOW_LIVE}, "
              f"FILTER_EMPTY={FILTER_EMPTY}, "
              f"MAX_STRING_LEN={MAX_STRING_LEN}\n")

init()
```

## Usage

### Basic session

```bash
$ gdb -q ./keygenme_O0
(gdb) source strcmp_dump.py
[strcmp_dump] Breakpoint installed on strcmp.
[strcmp_dump] Script loaded. Launch the program with 'run'.
[strcmp_dump] Config: SHOW_LIVE=True, FILTER_EMPTY=True, MAX_STRING_LEN=256
(gdb) run
Enter your key: TEST-KEY-123
[strcmp #1] "TEST-KEY-123" vs "VALID-KEY-2025"  (caller: check_key @ 0x401189)  ✗
Wrong key!
[Inferior 1 (process 56789) exited with code 01]

======================================================================
  strcmp_dump REPORT — 1 calls captured (3 total, 2 filtered)
======================================================================

  Recorded calls:
     #  Match  Caller                String 1                        String 2
     —  —————  ————————————————————  ——————————————————————————————  ——————————————————————————————
     1      ✗  check_key             TEST-KEY-123                    VALID-KEY-2025

  Unique strings observed (2):
    • TEST-KEY-123
    • VALID-KEY-2025

  Unique call sites (1):
    0x401189 (check_key) — 1 call(s)

======================================================================
```

The expected key (`VALID-KEY-2025`) appears directly in the report. On a real crackme, that's often all you need.

### On the stripped binary

```bash
$ gdb -q ./keygenme_O2_strip
(gdb) source strcmp_dump.py
[strcmp_dump] Breakpoint installed on strcmp.
(gdb) run
Enter your key: AAAA
[strcmp #1] "AAAA" vs "VALID-KEY-2025"  (caller: ?? @ 0x401175)  ✗
Wrong key!
```

The script works identically. The caller name is `??` (no symbols), but the address `0x401175` can be correlated with the disassembly in Ghidra. The expected string is still captured.

### With pwntools

```python
#!/usr/bin/env python3
"""Launch the keygenme under GDB with the strcmp_dump script."""
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug("./keygenme_O2_strip", '''
    source strcmp_dump.py
    continue
''')

p.sendlineafter(b"Enter your key: ", b"TEST")  
p.interactive()  
```

The `strcmp_dump.py` script is loaded into the GDB session opened by pwntools. The report displays in the GDB pane when the program terminates.

## Validation criteria

The checkpoint is successful if the script:

| Criterion | Verified by |  
|---|---|  
| Loads without error in GDB | `source strcmp_dump.py` produces no Python traceback |  
| Intercepts calls to `strcmp` | Calls are displayed in real time during execution |  
| Displays both compared strings | The "String 1" and "String 2" columns are filled |  
| Identifies the caller | The address (and name if available) of the call site is displayed |  
| Handles invalid addresses | No crash if a register contains an unmapped address |  
| Produces a report at the end | The summary block displays when the program terminates |  
| Works on a stripped binary | The script produces the same results on `keygenme_O2_strip` |  
| Is reloadable | A second `source strcmp_dump.py` does not create duplicate breakpoints |

## Extension ideas

Once the base script is functional, here are possible improvements to go further:

- **Support `strncmp` and `memcmp`** by adding additional breakpoints. For `memcmp`, the third argument (`rdx`) gives the size to compare — you must read exactly `rdx` bytes instead of looking for a null terminator.  
- **Export to JSON** with `json.dump()` in the `on_exit` handler, for later analysis in an external Python script or notebook.  
- **Add a caller filter**: only capture `strcmp` calls from the binary's code (addresses in `.text`) and ignore those called from glibc.  
- **Capture the return value** by setting a second breakpoint on `strcmp`'s `ret` instruction, or by using a `FinishBreakpoint` (a `gdb.Breakpoint` subclass that triggers at a function's return).

---

> **Validation:** if the script displays the expected string (`VALID-KEY-2025` or equivalent) during the keygenme's execution with any key, the checkpoint is successful. You now have a reusable tracing tool for any binary using `strcmp` — a tool that will serve you starting from Chapter 21 and throughout Part V.

⏭️ [Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg](/12-gdb-extensions/README.md)
