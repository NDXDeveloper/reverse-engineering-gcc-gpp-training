🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Trace the complete execution of `keygenme_O0` with GEF, capture the comparison moment

> **Chapter 12 — Enhanced GDB: PEDA, GEF, pwndbg**  
> **Part III — Dynamic Analysis**

---

## Goal

This checkpoint validates mastery of the three central skills of the chapter: knowing how to read the automatic context of a GDB extension, using specific commands to inspect program state, and combining these tools to locate verification logic in a binary. The scenario is deliberately simple — a binary compiled without optimization and with symbols — to focus on getting started with extensions rather than on reverse-engineering difficulty itself.

The `keygenme_O0` binary is a program that asks the user for a password and displays a success or failure message. The goal is to trace its execution with GEF, identify the comparison function, capture both compared strings, and understand the control flow leading to password acceptance or rejection.

---

## Prerequisites

- GEF installed and functional (section 12.1), verifiable with `gdb-gef -q -batch -ex "gef help"`  
- The `keygenme_O0` binary compiled and present in `binaries/ch12-keygenme/`  
- A terminal of at least 120 columns and 40 lines for comfortable context display

```bash
cd binaries/ch12-keygenme/  
make keygenme_O0  
file keygenme_O0  
```

The `file` command should confirm a 64-bit ELF binary, not stripped ("not stripped"). Symbol presence is essential for this checkpoint — stripped variants will be addressed in later chapters.

---

## Step 1 — Initial reconnaissance from GEF

Launch GDB with GEF on the binary:

```bash
gdb-gef -q ./keygenme_O0
```

The first action inside GEF is to check the binary's protections. This establishes the security context before any dynamic analysis:

```
gef➤ checksec
```

The output indicates the state of NX, PIE, RELRO, canaries, and Fortify. For a binary compiled with recent GCC's default options, expect to see PIE enabled, NX enabled, and probably canaries. This information isn't immediately necessary for tracing the comparison, but it's part of the triage routine every reverse engineer should automate (section 5.7).

Next, consult the functions available in the binary:

```
gef➤ info functions
```

Since the binary is not stripped, GDB lists all functions with their names. Look for program functions (not libc ones): `main`, and potentially auxiliary functions like `check_password`, `verify`, `validate`, or similar. The presence of `strcmp`, `strncmp`, or `memcmp` in the imports (visible via the PLT table) is a strong hint about the comparison mechanism.

```
gef➤ got
```

GEF's `got` command lists imported functions. If `strcmp@plt` appears, you know the program uses a standard string comparison — that's our primary target.

---

## Step 2 — Set strategic breakpoints

Two breakpoints are needed for this analysis: one on `main` to observe initialization, and one on the comparison function to capture the critical moment.

```
gef➤ break main  
gef➤ break strcmp  
```

If step 1 revealed a dedicated verification function (for example `check_password`), set an additional breakpoint on it:

```
gef➤ break check_password
```

Launch the program:

```
gef➤ run
```

GDB stops on `main`. The GEF context displays automatically: registers, disassembly, and stack. It's the first contact with the context in a real situation.

---

## Step 3 — Read the context at `main`'s entry

At the stop on `main`, the GEF context displays several immediately exploitable pieces of information.

**Registers section.** `RDI` contains `argc` (the command-line argument count) and `RSI` contains `argv` (the pointer to the argument array). With GEF's recursive dereferencing, `RSI` shows the executable's path string. These values confirm the program was launched correctly.

**Code section.** The disassembly shows `main`'s prologue (`push rbp ; mov rbp, rsp ; sub rsp, ...`) followed by the function's first instructions. By visually scanning the displayed instructions, you can spot calls (`call`) to I/O functions (`puts@plt`, `printf@plt`, `scanf@plt`, `fgets@plt`) and the comparison (`strcmp@plt`).

**Stack section.** At `main`'s entry, the stack contains the return address to `__libc_start_call_main` and the initial setup data. GEF dereferences the return address and displays the calling function's name, confirming the normal program-entry path.

Use `xinfo` to verify the nature of an interesting address seen in registers:

```
gef➤ xinfo $rsi
```

The output confirms the address points to the stack (`[stack]` region) and corresponds to `argv`.

---

## Step 4 — Advance to the comparison

Continue execution to reach the comparison point:

```
gef➤ continue
```

The program displays its prompt and waits for input. Type any password — for example `test123` — and confirm. GDB stops on the `strcmp` breakpoint.

This is the checkpoint's central moment. The GEF context automatically displays the program's complete state at the comparison point.

---

## Step 5 — Capture the comparison arguments

At the stop on `strcmp`, the `RDI` and `RSI` registers contain the comparison's two arguments (System V AMD64 convention: first argument in `RDI`, second in `RSI`).

The GEF context directly displays the dereferenced values:

```
$rdi   : 0x00007fffffffe0b0  →  "test123"
$rsi   : 0x0000555555556004  →  "s3cr3t_k3y"
```

User input (`test123`) is in `RDI`, and the expected string (`s3cr3t_k3y`) is in `RSI` — or vice versa, depending on the implementation. GEF's context makes both values readable without any additional command.

To confirm and deepen the inspection, use `xinfo` on each address:

```
gef➤ xinfo $rdi  
gef➤ xinfo $rsi  
```

The address pointed to by `RDI` should be in the stack (`[stack]`) — it's the buffer where user input was stored. The address pointed to by `RSI` should be in the binary's `.rodata` section — it's a constant compiled into the program. This distinction is significant: it confirms the expected password is a static string built into the binary, not a dynamically computed value.

To verify the full extent of both strings beyond what the context shows:

```
gef➤ dereference $rdi 4  
gef➤ dereference $rsi 4  
```

The `dereference` command (GEF's equivalent of pwndbg's `telescope`) displays several memory words from the address, with recursive dereferencing. This lets you see whether the strings are longer than what the context summary shows.

---

## Step 6 — Understand the post-comparison control flow

After capturing the arguments, you need to understand what the program does with `strcmp`'s result. Set a temporary breakpoint on the instruction following the `call strcmp` in the calling function:

```
gef➤ finish
```

`finish` executes until `strcmp`'s return. The GEF context displays again, this time in the calling function, just after the `call`. The `RAX` register contains `strcmp`'s return value: 0 if strings are identical, a non-zero value otherwise.

The disassembly in the context's code section shows the following instructions. The typical pattern is:

```nasm
call   strcmp@plt  
test   eax, eax        ; tests if EAX == 0  
jne    0x555555551xyz   ; jumps if not zero (failure)  
; ... success code ...
```

Or the inverse variant:

```nasm
call   strcmp@plt  
test   eax, eax  
je     0x555555551xyz   ; jumps if zero (success)  
; ... failure code ...
```

GEF's context shows the `test eax, eax` instruction with the resulting flags state. If the input didn't match the expected password, `EAX` is non-zero, the Zero Flag (`ZF`) is 0, and `jne` will be taken (or `je` won't be taken). GEF's disassembly section allows following this reasoning visually.

Advance one instruction to execute the `test`:

```
gef➤ stepi
```

The new context shows the updated flags. Consulting the registers section reveals whether `ZF` is active or not. It's the flag that determines the verification result.

Advance one more instruction to reach the conditional jump:

```
gef➤ stepi
```

The context shows the jump instruction. To verify which path the program will take, you can use GEF's prediction — the target branch is annotated if sufficient information is available — or simply read `ZF`'s state and apply the jump rule (`jne` jumps if `ZF == 0`, `je` jumps if `ZF == 1`).

---

## Step 7 — Force the success path

To confirm understanding of the control flow, you can force the program to take the success path by modifying the Zero Flag:

```
gef➤ edit-flags +zero       # if jne must be avoided (ZF=1 → jne NOT TAKEN)
```

Or conversely:

```
gef➤ edit-flags -zero       # if je must be forced not to jump
```

After the modification, continue execution:

```
gef➤ continue
```

The program should display the success message, confirming that the flow understanding is correct. This live flag-modification technique is a fundamental validation tool in reverse engineering: it lets you test a hypothesis about the program's logic without modifying the binary on disk.

---

## Step 8 — Cross-verification with pwndbg

To consolidate mastery of switching between extensions, relaunch the analysis with pwndbg and observe the presentation differences:

```bash
gdb-pwndbg -q ./keygenme_O0
```

```
pwndbg> break strcmp  
pwndbg> run  
Enter password: test123  
```

At the stop on `strcmp`, compare pwndbg's context with GEF's. Notable differences to observe are the annotation of `strcmp` arguments in the DISASM section (pwndbg displays inferred arguments directly in the disassembly), the `TAKEN` / `NOT TAKEN` prediction on the following conditional jump, and the presentation of modified registers with the old value grayed out.

Use pwndbg's semantic navigation command to reach the conditional jump directly:

```
pwndbg> finish  
pwndbg> nextjmp  
```

`nextjmp` advances execution to the next jump, which directly reaches the `jne` or `je` that interests us, without counting `stepi`s. pwndbg's context then displays the branch prediction, visually confirming the path the program will take.

---

## What this checkpoint validates

By completing these steps, the following skills are acquired.

**Reading the automatic context** — knowing how to immediately identify argument registers (`RDI`, `RSI`) at a stop on a `call`, spotting return addresses on the stack, and understanding register-modification coloring.

**Using specific commands** — `checksec` for triage, `got` for imports, `xinfo` to qualify an address, `dereference` for recursive dereferencing, `edit-flags` for live flag modification.

**Control-flow navigation** — combining `break`, `continue`, `finish`, `stepi`, and `nextjmp` to precisely reach the point of interest in execution, understanding the link between `test`/`cmp`, flags, and conditional jumps.

**Switching between extensions** — verifying that the same result (`strcmp`'s arguments) is accessible with GEF and pwndbg, and appreciating the differences in presentation and commands.

These skills will be intensively mobilized in the practical cases of Part V (Chapters 21 to 25) and in the malware analysis of Part VI (Chapters 27 to 29).

---


⏭️ [Chapter 13 — Dynamic instrumentation with Frida](/13-frida/README.md)
