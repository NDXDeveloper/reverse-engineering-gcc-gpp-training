🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 21.5 — Dynamic Analysis: Tracing the Comparison with GDB

> 📖 **Reminder**: fundamental GDB commands (`break`, `run`, `next`, `step`, `info`, `x`, `print`) are presented in chapter 11 (sections 11.2 to 11.5). GEF/pwndbg extensions are covered in chapter 12. This section assumes a basic proficiency with these tools.

---

## Introduction

Until now, all our analysis has been static: we read the binary without ever executing it. We know the code structure, the functions involved, the conditional jumps, and the corresponding opcodes. But static analysis produces *hypotheses*. Dynamic analysis *confirms* them.

The objective of this section is twofold:

1. **Validate our understanding** by observing the running program — verify that the flow follows the path we deduced.  
2. **Capture the expected key** directly from memory, at the moment when `check_license` builds the `expected` string before comparing it with `strcmp`.

The tool is GDB, the standard debugger from the GNU toolchain. We will use the GEF extension for register and stack visualization, but all native GDB commands work without an extension.

---

## Preparing the GDB session

### Launching with GEF

```bash
$ gdb -q keygenme_O0
```

The `-q` flag (quiet) suppresses the welcome message. If GEF is installed (chapter 12), the prompt changes from `(gdb)` to `gef➤`. Otherwise, all commands remain identical — only the display differs.

### Disabling ASLR

Our binary is PIE (section 21.2). With active ASLR, the base address changes on each execution, complicating address tracking. We disable randomization for this session:

```bash
gef➤ set disable-randomization on
```

This setting is enabled by default in GDB, but it is good practice to verify it explicitly. It only affects the process launched from GDB — the host system remains protected.

### Verifying symbols

Since we are working on `keygenme_O0` compiled with `-g`, GDB has access to DWARF symbols:

```bash
gef➤ info functions
```

We find the complete list of functions: `main`, `check_license`, `compute_hash`, `derive_key`, `format_key`, `rotate_left`, `read_line`. If this command returns an empty list or only libc symbols, the binary is stripped — we will address that case at the end of this section.

---

## Strategy 1 — Breakpoint on `check_license`

The first approach consists of setting a breakpoint at the entry of `check_license` to observe the received arguments, then stepping forward to `strcmp` to capture the expected key.

### Setting the breakpoint

```bash
gef➤ break check_license  
Breakpoint 1 at 0x5555555552f0: file keygenme.c, line 90.  
```

GDB displays the resolved address and, thanks to DWARF, the corresponding source file and line number.

### Running the program

```bash
gef➤ run
```

The program starts and displays its banner, then waits for the username input:

```
=== KeyGenMe v1.0 — RE Training ===

Enter username:
```

We enter a test name, for example `Alice`, then an arbitrary key when prompted:

```
Enter username: Alice  
Enter license key (XXXX-XXXX-XXXX-XXXX): AAAA-BBBB-CCCC-DDDD  
```

Execution stops immediately at the breakpoint:

```
Breakpoint 1, check_license (username=0x7fffffffe010 "Alice",
    user_key=0x7fffffffe030 "AAAA-BBBB-CCCC-DDDD") at keygenme.c:90
```

GDB displays the function arguments. We already see our two inputs: `"Alice"` and `"AAAA-BBBB-CCCC-DDDD"`. With GEF, the register panel shows:

```
$rdi = 0x7fffffffe010 → "Alice"
$rsi = 0x7fffffffe030 → "AAAA-BBBB-CCCC-DDDD"
```

This is consistent with the System V AMD64 convention: the first argument is in `RDI`, the second in `RSI`.

### Advancing to `strcmp`

Rather than stepping instruction by instruction through `compute_hash`, `derive_key`, and `format_key`, we set a second breakpoint directly on the call to `strcmp`:

```bash
gef➤ break strcmp@plt  
Breakpoint 2 at 0x555555555080  
gef➤ continue  
```

Execution resumes and stops at the entry of `strcmp`. At this precise moment, the two arguments of `strcmp` are in `RDI` and `RSI`:

```bash
gef➤ info registers rdi rsi  
rdi    0x7fffffffdfe0    → points to the EXPECTED key (computed)  
rsi    0x7fffffffe030    → points to the ENTERED key (by user)  
```

### Capturing the expected key

We read the string pointed to by `RDI` — this is the key the program computed for the username `"Alice"`:

```bash
gef➤ x/s $rdi
0x7fffffffdfe0: "DCEB-0DFC-B51F-3428"
```

The expected key for `"Alice"` is `DCEB-0DFC-B51F-3428`.

We verify the entered key for comparison:

```bash
gef➤ x/s $rsi
0x7fffffffe030: "AAAA-BBBB-CCCC-DDDD"
```

The two strings are different. If we let execution continue, `strcmp` will return a non-zero value, the `JNE` will be taken, and the program will display "Invalid license."

### Verification: relaunch with the correct key

We relaunch the program with the captured key:

```bash
gef➤ run
```

GDB offers to restart the process — confirm with `y`. We enter `Alice` again as username, but this time we enter the captured key:

```
Enter username: Alice  
Enter license key (XXXX-XXXX-XXXX-XXXX): DCEB-0DFC-B51F-3428  
```

The breakpoint on `strcmp` triggers. We verify:

```bash
gef➤ x/s $rdi
0x7fffffffdfe0: "DCEB-0DFC-B51F-3428"
gef➤ x/s $rsi
0x7fffffffe030: "DCEB-0DFC-B51F-3428"
```

The two strings are identical. We continue execution:

```bash
gef➤ continue
[+] Valid license! Welcome, Alice.
```

The hypothesis is confirmed: we captured the valid key directly from memory.

---

## Strategy 2 — Breakpoint on `strcmp` only

The previous strategy required knowing the name `check_license`. On a stripped binary, this name no longer exists. A more direct approach consists of setting a breakpoint solely on `strcmp@plt`, without worrying about the calling function.

```bash
gef➤ break strcmp@plt  
gef➤ run  
```

After entering username and key, the breakpoint triggers on each call to `strcmp` in the program. On our keygenme, there is only one call, so we land directly at the right place. On a more complex binary with multiple `strcmp` calls, we use GDB commands to identify the correct one:

```bash
# Display backtrace to see where the call comes from
gef➤ backtrace
#0  __strcmp_sse2 () at ...
#1  0x0000555555555338 in check_license (...)
#2  0x0000555555555405 in main (...)
```

The backtrace confirms that this `strcmp` call comes from `check_license`, itself called from `main`.

> 💡 **On a stripped binary**, the backtrace will display raw addresses instead of function names:  
> ```  
> #1  0x0000555555555338 in ?? ()  
> #2  0x0000555555555405 in ?? ()  
> ```  
> The addresses remain usable: they can be correlated with offsets in Ghidra to confirm you are at the right location.

---

## Strategy 3 — Observing the `strcmp` return and the jump

Instead of capturing the key before `strcmp`, we can observe what happens *after* — the `strcmp` return and the conditional jump.

### Breakpoint after `strcmp`

We set the breakpoint not on `strcmp` itself, but on the instruction following its call in `check_license`. From Ghidra, we noted that the `TEST EAX, EAX` is at a certain address (for example `0x1335` as offset). In GDB, with ASLR disabled and a known base:

```bash
# With symbols: use an offset relative to check_license
gef➤ disassemble check_license
```

We locate the `TEST EAX, EAX` instruction after `CALL strcmp@plt` and set the breakpoint on its address:

```bash
gef➤ break *check_license+69
```

The `*function+offset` trick allows targeting a specific instruction inside a function. The byte offset is calculated from the function's start.

### Observing the flags

After entering username and key, execution stops on the `TEST EAX, EAX`. We inspect:

```bash
# strcmp return value
gef➤ print $eax
$1 = -14
```

`strcmp` returned -14 (non-zero value — the strings differ). After executing `TEST`, we advance one instruction:

```bash
gef➤ stepi
```

We are now on the `JNE`. We check the Zero Flag state:

```bash
gef➤ print $eflags
$2 = [ PF IF ]
```

The Zero Flag (`ZF`) does not appear in the list — it is 0. With GEF, the flags panel directly displays:

```
flags: ... [zero:0] ...
```

Since ZF = 0, the `JNE` (Jump if Not Zero) **will be taken** → the program jumps to the failure path.

### Relaunching with the correct key

Relaunching with the correct key:

```bash
gef➤ print $eax
$3 = 0
```

`strcmp` returned 0 (identical strings). After `TEST EAX, EAX`:

```
flags: ... [zero:1] ...
```

ZF = 1, so the `JNE` **will not be taken** → execution continues sequentially to `return 1` → success.

We observed in real time exactly the mechanism described in section 21.4.

---

## Strategy 4 — Modifying `EAX` on the fly

GDB is not just for observation — it also allows modifying the state of a running process. We can force the program to take the success path *without knowing the key* by modifying the value of `EAX` after `strcmp`.

### Procedure

1. Set a breakpoint just after the call to `strcmp` in `check_license` (on the `TEST EAX, EAX`).  
2. Launch the program and enter any username and key.  
3. At the breakpoint, `EAX` contains a non-zero value (incorrect key).  
4. Force `EAX` to 0:

```bash
gef➤ set $eax = 0
```

5. Continue execution:

```bash
gef➤ continue
[+] Valid license! Welcome, Alice.
```

The program displays the success message even though the entered key was wrong. We "cheated" by simulating a 0 return from `strcmp`.

### Alternative: modifying the Zero Flag directly

We can also act on the flag rather than the register. Position on the `JNE` instruction (after `TEST` has set the flags):

```bash
# Force ZF = 1 by setting the corresponding bit in EFLAGS
gef➤ set $eflags |= (1 << 6)  
gef➤ continue  
[+] Valid license! Welcome, Alice.
```

Bit 6 of `EFLAGS` is the Zero Flag. By forcing it to 1, the `JNE` is no longer taken and execution follows the success path.

> ⚠️ **Note**: this modification is ephemeral. It exists only in this execution, in this GDB session. The on-disk binary is not modified. For a permanent change, the binary must be patched — this is the subject of section 21.6.

---

## Strategy 5 — Dumping the key with a conditional breakpoint

To go further with automation, we can use a conditional breakpoint with automatic commands. The idea: each time `strcmp` is called, GDB automatically displays both compared strings, then lets the program continue.

```bash
gef➤ break strcmp@plt  
gef➤ commands 1  
  > silent
  > printf "── strcmp intercepted ──\n"
  > printf "  expected : %s\n", (char*)$rdi
  > printf "  user_key : %s\n", (char*)$rsi
  > printf "────────────────────\n"
  > continue
  > end
gef➤ run
```

From now on, each time `strcmp` is hit, GDB displays both arguments then automatically resumes execution. The output looks like:

```
=== KeyGenMe v1.0 — RE Training ===

Enter username: Alice  
Enter license key (XXXX-XXXX-XXXX-XXXX): TEST-TEST-TEST-TEST  
── strcmp intercepted ──
  expected : DCEB-0DFC-B51F-3428
  user_key : TEST-TEST-TEST-TEST
────────────────────
[-] Invalid license. Try again.
```

We captured the expected key without interrupting the program flow. This technique is particularly useful on binaries that perform multiple successive verifications or that are sensitive to interruptions (timing-based anti-debug).

### Conditional breakpoint with filter

If the binary contained many `strcmp` calls (configuration checking, file path comparisons...), we could filter to log only relevant calls:

```bash
# Only stop if the expected string contains a dash (XXXX-XXXX format)
gef➤ break strcmp@plt if $_regex((char*)$rdi, ".*-.*-.*-.*")
```

The `$_regex` command is a GDB internal function that performs a regular expression match. It allows precisely targeting `strcmp` calls related to license verification without being disturbed by others.

---

## Working without symbols: the `keygenme_strip` case

On the stripped variant, internal function names have disappeared. Strategies 1 and 3 (which use the name `check_license`) no longer work directly. Here is how to adapt.

### `strcmp@plt` remains accessible

Dynamic symbols (functions imported from libc) survive stripping because they are in `.dynsym`, not `.symtab`. We can always set:

```bash
gef➤ break strcmp@plt
```

This is why **strategy 2** (breakpoint on `strcmp@plt`) works identically on a stripped binary. The backtrace will display raw addresses instead of names, but the arguments in `RDI`/`RSI` are the same.

### Breakpoint by absolute address

If we want to set a breakpoint on an internal function (the stripped equivalent of `check_license`), we use the offset found in Ghidra:

```bash
# Offset in Ghidra: 0x001012f0
# PIE base (ASLR off): often 0x555555554000 on x86-64
# Absolute address = base + offset

gef➤ break *0x5555555552f0
```

We can also use the `info proc mappings` command after an initial `run` (then `Ctrl+C` or temporary breakpoint) to find the exact base:

```bash
gef➤ starti  
gef➤ info proc mappings  
```

`starti` launches the program and stops on the very first instruction (before even `_start`). The `info proc mappings` output shows the binary's load base, from which we calculate absolute addresses.

### GDB script for automation

To avoid manually recalculating addresses at each session, we can write a small GDB command file:

```bash
# file: trace_strcmp.gdb
set disable-randomization on  
break strcmp@plt  
commands  
  silent
  printf "expected: %s\n", (char*)$rdi
  printf "user_key: %s\n", (char*)$rsi
  continue
end  
run  
```

Launching:

```bash
$ gdb -q -x trace_strcmp.gdb keygenme_strip
```

GDB automatically executes the commands from the file. We obtain the expected key without manual intervention, whether the binary is stripped or not.

---

## Strategy summary

| Strategy | Breakpoint target | Information obtained | Works stripped? |  
|---|---|---|---|  
| 1 — BP on `check_license` | Function entry | Arguments (username, user_key) | ❌ (name absent) |  
| 2 — BP on `strcmp@plt` | libc call | Expected key vs entered key | ✅ |  
| 3 — BP after `strcmp` | `TEST EAX, EAX` | Return value, flag state | ✅ (by address) |  
| 4 — Modify `EAX` | `TEST EAX, EAX` | Verification bypass | ✅ (by address) |  
| 5 — Auto conditional BP | `strcmp@plt` | Automatic log without interruption | ✅ |

**Strategy 2** is the most universal: it works with or without symbols, requires no address calculation, and directly gives the expected key. It is the one to prefer as a first approach.

**Strategy 4** (modifying `EAX`) is a dynamic bypass — useful for quickly verifying that you identified the right decision point, but ephemeral. For a permanent bypass, we move to binary patching (section 21.6). For a clean solution, we write a keygen (section 21.8).

---

## What dynamic analysis brought us

Complementing the static analysis from previous sections, GDB allowed us to:

- **Confirm** that `check_license` receives the username and entered key as arguments.  
- **Observe** the expected key in memory, computed by `compute_hash` → `derive_key` → `format_key`.  
- **Capture** a valid key for a given username, proving our understanding of the algorithm.  
- **Verify** the conditional jump mechanism by observing `EAX` and the Zero Flag in real time.  
- **Demonstrate** that a dynamic bypass is possible by modifying a register or flag.

We now have all the puzzle pieces. The last three sections of the chapter exploit this understanding in three different ways: permanent binary patching (21.6), automatic solving via symbolic execution (21.7), and writing a keygen that reproduces the algorithm (21.8).

⏭️ [Binary patching: flipping a jump directly in the binary (with ImHex)](/21-keygenme/06-patching-imhex.md)
