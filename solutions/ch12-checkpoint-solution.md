🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 12 Checkpoint

> Trace the complete execution of `keygenme_O0` with GEF, capture the comparison moment

---

## Spoilers

This file contains the complete solution for the chapter 12 checkpoint. Attempting the checkpoint on your own before consulting this solution is strongly recommended — it's through practice that commands become reflexes.

---

## Expected Environment

```bash
$ gdb-gef --version
GNU gdb (Ubuntu 15.x-...) ...

$ file binaries/ch12-keygenme/keygenme_O0
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
for GNU/Linux 3.2.0, BuildID[sha1]=..., not stripped  
```

The binary is a 64-bit ELF, PIE, dynamically linked and not stripped. The "not stripped" mention confirms the presence of debug symbols.

---

## Detailed Solution

### 1. Initial Reconnaissance

```
$ gdb-gef -q ./keygenme_O0

gef> checksec
[+] checksec for './keygenme_O0'
Canary                        : Y  
NX                            : Y  
PIE                           : Y  
Fortify                       : N  
RelRO                         : Full  
```

The binary has the standard protections of a recent GCC. For this checkpoint (logic analysis, not exploitation), these protections don't prevent anything — they are simply noted.

```
gef> info functions
...
0x0000000000001169  main
0x0000000000001245  check_password
...

gef> got  
GOT protection: Full RELRO | GOT functions: 6  

[0x3fd8] puts@GLIBC_2.2.5          →  0x...
[0x3fe0] printf@GLIBC_2.2.5        →  0x...
[0x3fe8] fgets@GLIBC_2.2.5         →  0x...
[0x3ff0] strcmp@GLIBC_2.2.5         →  0x...
[0x3ff8] strlen@GLIBC_2.2.5        →  0x...
```

**Key observations:**

- The binary contains a `check_password` function — this is likely the verification routine.  
- The GOT table confirms the `strcmp` import — the comparison mechanism is a standard string comparison.  
- `fgets` is imported — the program reads user input via `fgets` (not `scanf`), meaning the input potentially includes a trailing `\n`.

### 2. Breakpoints and Launch

```
gef> break main  
Breakpoint 1 at 0x116d: file keygenme.c, line 18.  

gef> break check_password  
Breakpoint 2 at 0x1249: file keygenme.c, line 8.  

gef> break strcmp  
Breakpoint 3 at 0x1030  

gef> run
```

Three breakpoints set: `main` for general observation, `check_password` for the verification routine, and `strcmp` for the comparison moment. Expected trigger order is `main` → `check_password` → `strcmp`.

### 3. Context at `main` Entry

GDB stops on `main`. The GEF context displays:

```
──────────────────────────────── registers ────────────────────────────────
$rax   : 0x0000555555555169  →  <main+0> push rbp
$rdi   : 0x1                              ← argc = 1
$rsi   : 0x00007fffffffe1a8  →  0x00007fffffffe47a  →  "./keygenme_O0"
...
──────────────────────────────────── code ─────────────────────────────────
   0x555555555169 <main+0>:     push   rbp
   0x55555555516a <main+1>:     mov    rbp, rsp
 → 0x55555555516d <main+4>:     sub    rsp, 0x40
   0x555555555171 <main+8>:     mov    DWORD PTR [rbp-0x34], edi
   0x555555555174 <main+11>:    mov    QWORD PTR [rbp-0x40], rsi
   ...
   0x555555555198 <main+47>:    call   0x555555555030 <puts@plt>
   ...
   0x5555555551b5 <main+76>:    call   0x555555555050 <fgets@plt>
   ...
   0x5555555551d0 <main+103>:   call   0x555555555245 <check_password>
──────────────────────────────────── stack ────────────────────────────────
0x00007fffffffe090│+0x0000: 0x00007fffffffe1a8  →  ...    ← $rsp
...
```

**Verification with `xinfo`:**

```
gef> xinfo $rsi
──────────────────── xinfo: 0x7fffffffe1a8 ────────────────────
Page: 0x7ffffffde000 → 0x7ffffffff000 (size=0x21000)  
Permissions: rw-  
Pathname: [stack]  
Segment: [stack]  
```

Confirmed: `RSI` points to the stack, it's indeed `argv`.

**Reading the disassembly:** The `main` code visible in the code section shows the expected logical sequence: `puts` call (prompt display), `fgets` call (input reading), then `check_password` call. This is a classic linear flow for a simple crackme.

### 4. Advancing to `check_password`

```
gef> continue
```

The program displays its prompt:

```
Enter the password:
```

We type `test123` and validate. GDB stops on the `check_password` breakpoint.

The context shows:

```
──────────────────────────────── registers ────────────────────────────────
$rdi   : 0x00007fffffffe050  →  "test123\n"
...
```

**Important observation:** The input in `RDI` is `"test123\n"` with a newline. This is a consequence of `fgets` which preserves the `\n`. If the program compares this string directly with `strcmp`, the `\n` will cause the comparison to fail even with the correct password. Two possibilities: either the program removes the `\n` before comparing (a `strlen` + replacement is a common pattern), or the expected string includes the `\n` (unlikely). The presence of `strlen` in the GOT imports suggests the first hypothesis.

### 5. Capturing the Comparison on `strcmp`

```
gef> continue
```

GDB stops on `strcmp`. The context displays the arguments:

```
──────────────────────────────── registers ────────────────────────────────
$rdi   : 0x00007fffffffe050  →  "test123"
$rsi   : 0x0000555555556004  →  "s3cr3t_k3y"
...
```

The `\n` has disappeared from the user input — the program removed it between `fgets` and `strcmp`, confirming the hypothesis.

**Main result: the expected password is `s3cr3t_k3y`.**

**Address qualification with `xinfo`:**

```
gef> xinfo $rdi
──────────────────── xinfo: 0x7fffffffe050 ────────────────────
Page: 0x7ffffffde000 → 0x7ffffffff000 (size=0x21000)  
Permissions: rw-  
Pathname: [stack]  
```

```
gef> xinfo $rsi
──────────────────── xinfo: 0x555555556004 ────────────────────
Page: 0x555555556000 → 0x555555557000 (size=0x1000)  
Permissions: r--  
Pathname: /home/user/binaries/ch12-keygenme/keygenme_O0  
Segment: .rodata  
```

- `RDI` → stack → local buffer containing cleaned user input  
- `RSI` → `.rodata` → constant compiled into the binary = expected password

The expected string is a static read-only constant. It could have been found with a simple `strings` on the binary, but the checkpoint's objective is to capture it dynamically via the GEF context.

**In-depth inspection with `dereference`:**

```
gef> dereference $rdi 4
0x00007fffffffe050│+0x0000: "test123"           ← $rdi
0x00007fffffffe058│+0x0008: 0x0000000000000000
0x00007fffffffe060│+0x0010: 0x0000000000000000
0x00007fffffffe068│+0x0018: 0x0000000000000000

gef> dereference $rsi 4
0x0000555555556004│+0x0000: "s3cr3t_k3y"        ← $rsi
0x000055555555600c│+0x0008: 0x0000000000007934
0x0000555555556014│+0x0010: "Correct password!"
0x000055555555601c│+0x0018: "password!"
```

The `dereference` on `RSI` reveals a bonus: the string `"Correct password!"` is located right after the expected password in `.rodata`. This is the success message — additional confirmation that we're at the right place.

### 6. Post-comparison Control Flow

```
gef> finish  
Run till exit from #0  strcmp () ...  
0x0000555555555268 in check_password ()
```

The context after returning from `strcmp`:

```
──────────────────────────────── registers ────────────────────────────────
$rax   : 0xffffffffffffffa1             ← strcmp return, non-zero (strings differ)
...
──────────────────────────────────── code ─────────────────────────────────
   0x555555555263 <check_password+30>: call   0x555555555060 <strcmp@plt>
 → 0x555555555268 <check_password+35>: test   eax, eax
   0x55555555526a <check_password+37>: jne    0x55555555527e <check_password+57>
   0x55555555526c <check_password+39>: lea    rdi, [rip+0xda1]    ; "Correct password!"
   0x555555555273 <check_password+46>: call   0x555555555030 <puts@plt>
   ...
   0x55555555527e <check_password+57>: lea    rdi, [rip+0xd93]    ; "Incorrect password."
   0x555555555285 <check_password+64>: call   0x555555555030 <puts@plt>
```

**Flow analysis:**

- `RAX = 0xffffffffffffffa1` — non-zero value, strings differ.  
- The next instruction is `test eax, eax` which sets `ZF` based on whether `EAX` is zero or not.  
- `jne 0x55555555527e` jumps to the failure message if `ZF == 0` (i.e. if `EAX != 0`, i.e. if strings differ).  
- If `ZF == 1` (strings identical), execution falls through to the success block (`"Correct password!"`).

The pattern is: `strcmp` → `test eax, eax` → `jne failure` → (otherwise) success. This is the classic variant "success code is the fall-through, failure code is the jump".

```
gef> stepi
```

After executing `test eax, eax`, the context shows flags:

```
$eflags: [...SF ... NF ...] — ZF absent (ZF=0)
```

`ZF` is not set because `EAX` was non-zero. The `jne` will therefore be taken → failure.

```
gef> stepi
```

The instruction pointer (`RIP`) jumps to `0x55555555527e` (the failure block), confirming the analysis.

### 7. Forcing the Success Path

We restart from the conditional jump. Relaunch the program:

```
gef> run  
Enter the password: test123  
```

GDB stops on `strcmp`. Advance to the jump:

```
gef> finish  
gef> stepi          # execute test eax, eax  
```

The context shows `ZF=0`. Force `ZF` to 1:

```
gef> edit-flags +zero
```

Verify in the registers section that `ZF` is now active. Continue:

```
gef> continue
```

Program output:

```
Correct password!
```

The program took the success path thanks to the flag modification. This confirms that our flow understanding is correct: the only condition separating success from failure is the `ZF` value after `test eax, eax`.

**Cross-verification with the correct password:**

```
gef> run  
Enter the password: s3cr3t_k3y  
```

GDB stops on `strcmp`. The context now shows:

```
$rdi   : 0x00007fffffffe050  →  "s3cr3t_k3y"
$rsi   : 0x0000555555556004  →  "s3cr3t_k3y"
```

Both strings are identical.

```
gef> finish
```

`RAX = 0x0` — `strcmp` returns 0.

```
gef> stepi          # test eax, eax
```

`ZF = 1` — strings are equal.

```
gef> stepi          # jne → NOT TAKEN
```

The `jne` is not taken. Execution falls through to the success block.

```
gef> continue  
Correct password!  
```

The correct password works without flag modification.

### 8. Cross-verification with pwndbg

```bash
gdb-pwndbg -q ./keygenme_O0
```

```
pwndbg> break strcmp  
pwndbg> run  
Enter the password: test123  
```

At the `strcmp` stop, the pwndbg context displays:

```
 REGISTERS
*RAX  ...
*RDI  0x7fffffffe050 ◂— 'test123'
*RSI  0x555555556004 ◂— 's3cr3t_k3y'
 ...
```

Asterisks before `RDI` and `RSI` indicate these registers were modified since the last stop. Pointed strings are displayed directly — same result as GEF, different presentation.

Navigate to the conditional jump:

```
pwndbg> finish  
pwndbg> nextjmp  
```

The pwndbg context stops on the `jne` and displays:

```
 > 0x55555555526a <check_password+37>    jne    0x55555555527e <check_password+57>    TAKEN
```

The `TAKEN` annotation confirms the jump will be taken (toward failure), consistent with an incorrect password.

**Differences observed between GEF and pwndbg on this checkpoint:**

| Aspect | GEF | pwndbg |  
|---|---|---|  
| Modified registers | Value colorization | Asterisk `*` + grayed-out old value |  
| Jump prediction | Version-dependent | Explicit `TAKEN` / `NOT TAKEN` |  
| `strcmp` arguments | Visible via dereferencing in registers section | Visible in registers + annotated in disassembly |  
| Reaching the jump | Manual `stepi` | `nextjmp` (one command) |  
| Flag modification | `edit-flags +zero` (by name) | `set $eflags \|= 0x40` (by mask) |

---

## Results Summary

| Element | Value |  
|---|---|  
| Expected password | `s3cr3t_k3y` |  
| Password location | `.rodata` section at offset `0x6004` |  
| Comparison function | `strcmp`, called from `check_password+30` |  
| Input reading mechanism | `fgets` → `\n` cleanup via `strlen` → `strcmp` |  
| Branching pattern | `test eax, eax` → `jne` to failure (success = fall-through) |  
| Decisive flag | `ZF` (Zero Flag) after `test eax, eax` |  
| Binary protections | Canary Y, NX Y, PIE Y, Full RELRO, Fortify N |

---

## Common Errors

**The breakpoint on `strcmp` doesn't trigger.** If the program uses `strncmp` or `memcmp` instead of `strcmp`, the breakpoint will never be reached. Check the GOT table with `got` to identify the correct comparison function and adjust the breakpoint.

**The context shows `\n` in the user's string.** If the context at the `strcmp` moment shows `"test123\n"` instead of `"test123"`, it means the program didn't clean the `fgets` newline. The comparison will always fail, even with the correct password. This isn't an analysis bug — it's actual program behavior that should be noted. If the program doesn't remove the `\n`, the password provided can never match via `stdin` (except by sending input without `\n` via a pipe or `pwntools`).

**`edit-flags` doesn't seem to have any effect.** Make sure to execute `edit-flags` *after* `test eax, eax` and *before* `jne`. If the command is executed before `test`, it will overwrite the flags. The correct order is: `finish` → `stepi` (executes `test`) → `edit-flags +zero` → `stepi` or `continue`.

**The captured password doesn't work outside GDB.** If the binary is compiled with PIE and ASLR, addresses change with each execution, but the string in `.rodata` remains the same. The password `s3cr3t_k3y` works regardless of ASLR. If the password doesn't work, check that the trailing `\n` in the input doesn't interfere with the program launched outside GDB (test with `echo -n "s3cr3t_k3y" | ./keygenme_O0`).

**The GEF context is too large and scrolls off screen.** Reduce the number of displayed lines:

```
gef> gef config context.nb_lines_code 8  
gef> gef config context.nb_lines_stack 6  
```

Or temporarily remove unnecessary sections:

```
gef> gef config context.layout "regs code"
```

---

⏭️
