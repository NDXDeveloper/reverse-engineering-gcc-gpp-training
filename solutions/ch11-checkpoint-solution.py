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
SHOW_LIVE = True            # Display each call in real-time
FILTER_EMPTY = True         # Ignore calls where a string is empty

# ──────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────
def safe_read_string(inferior, addr, max_len=MAX_STRING_LEN):
    """Reads a null-terminated C string at the given address.

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

    # Decode as UTF-8 with replacement for invalid bytes
    return raw.decode('utf-8', errors='replace')


def is_printable_string(s):
    """Checks if a string is reasonably printable."""
    if not s:
        return False
    printable_ratio = sum(1 for c in s if c.isprintable() or c in '\t\n\r') / len(s)
    return printable_ratio > 0.8


def format_string(s, max_display=80):
    """Formats a string for display, with truncation if needed."""
    if s is None:
        return "<NULL>"
    if len(s) == 0:
        return "<empty>"

    # Escape control characters
    display = repr(s)[1:-1]     # Use repr() and strip quotes

    if len(display) > max_display:
        return display[:max_display - 3] + "..."
    return display

# ──────────────────────────────────────────────
# Scripted breakpoint
# ──────────────────────────────────────────────
class StrcmpDumper(gdb.Breakpoint):
    """Breakpoint on strcmp that captures arguments at each call."""

    def __init__(self):
        # Clean up previous instances (idempotent on reload)
        for bp in gdb.breakpoints() or []:
            if hasattr(bp, '_is_strcmp_dumper'):
                bp.delete()

        super().__init__("strcmp", type=gdb.BP_BREAKPOINT)
        self._is_strcmp_dumper = True    # Marker for cleanup
        self.silent = True               # Suppress standard GDB message
        self.calls = []                  # List of all captured calls
        self.call_count = 0

        gdb.write("[strcmp_dump] Breakpoint set on strcmp.\n")

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
                match_indicator = "  MATCH"
            elif entry["match"] is False:
                match_indicator = "  MISMATCH"

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
    """Displays the summary report when the program terminates."""
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
        match = " Y" if e["match"] else " N" if e["match"] is False else " ?"
        caller = f"{e['caller_name']}"[:20]
        gdb.write(
            f"  {e['num']:>4}  {match:>5}  {caller:<20}  "
            f"{format_string(e['s1'], 30):<30}  "
            f"{format_string(e['s2'], 30):<30}\n"
        )

    # Section 2: matching calls (potentially interesting)
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
            gdb.write(f"    - {format_string(s)}\n")

    # Section 4: unique callers
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

    # Subscribe to the program exit event
    # (disconnect first to avoid duplicates on reload)
    try:
        gdb.events.exited.disconnect(on_exit)
    except ValueError:
        pass    # Not yet connected
    gdb.events.exited.connect(on_exit)

    gdb.write("[strcmp_dump] Script loaded. Start the program with 'run'.\n")
    gdb.write(f"[strcmp_dump] Config: SHOW_LIVE={SHOW_LIVE}, "
              f"FILTER_EMPTY={FILTER_EMPTY}, "
              f"MAX_STRING_LEN={MAX_STRING_LEN}\n")

init()
