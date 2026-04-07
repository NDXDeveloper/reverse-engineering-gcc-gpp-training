🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 18.6 — Combining with manual RE: when to use symbolic execution

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## Two approaches, one objective

Throughout this chapter, we've presented symbolic execution and manual reverse engineering as two distinct approaches. In reality, experienced analysts don't choose one **or** the other — they combine them constantly, switching from one to the other depending on what the binary throws at them.

Manual RE (Ghidra, GDB, Frida) excels where symbolic execution fails: understanding a program's overall architecture, identifying data structures, following network interactions, navigating voluminous code. Symbolic execution excels where manual RE fails: solving complex constraint systems, finding an input satisfying a precise condition, methodically exploring hundreds of branches.

The challenge is knowing **when** to switch from one to the other, and **how** to circulate information between the two.

---

## The practitioner's decision tree

Facing a new binary, here's the reasoning an analyst who masters both approaches follows:

```
  New binary to analyze
           │
           ▼
  ┌─────────────────────────┐
  │  Quick triage (ch. 5)   │    file, strings, checksec, readelf
  │  5 minutes              │
  └──────────┬──────────────┘
             │
             ▼
  ┌─────────────────────────────────────────┐
  │  Does the binary contain clear          │
  │  success/failure strings?               │
  │  ("Access Granted", "Valid", "OK"...)   │
  └──────┬─────────────────────┬────────────┘
         │                     │
        Yes                    No
         │                     │
         ▼                     ▼
  ┌──────────────┐    ┌──────────────────────┐
  │ Try angr     │    │ Classic static       │
  │ in stdout    │    │ analysis (Ghidra)    │
  │ mode         │    │ to understand the    │
  │ (10 min max) │    │ logic                │
  └──────┬───────┘    └──────────┬───────────┘
         │                       │
    ┌────┴────┐                  │
    │         │                  │
  Success   Failure              │
    │         │                  │
    ▼         ▼                  ▼
  Done      ┌──────────────────────────────┐
            │  Identify the verification   │
            │  function and its inputs     │
            └──────────┬───────────────────┘
                       │
              ┌────────┴────────┐
              │                 │
        Simple logic      Complex logic
        (< 50 decompiled   (crypto transforms,
         lines)             nested loops)
              │                   │
              ▼                   │
        ┌────────────┐      ┌─────┴──────┐
        │ Solve      │      │            │
        │ by hand    │   angr on      Z3 with
        │ or with    │   isolated     manually
        │ GDB        │   function     extracted
        └────────────┘   (blank_state) constraints
```

This isn't a rigid algorithm — it's a heuristic that refines with experience. The essential point is that **symbolic execution is never the first step**. Quick triage and a minimum of static analysis always come first, if only to determine whether symbolic execution has a chance of working.

---

## Hybrid workflow #1 — The "controlled blind shot"

This is the most common workflow in CTFs and on small binaries. It consists of trying angr as soon as possible, investing minimal human effort.

### Steps

1. **Triage** (5 minutes) — `file`, `strings`, `checksec`. Identify binary type, success/failure strings, active protections.

2. **Brute angr attempt** (10 minutes) — Write a minimal script with `entry_state`, stdout criteria, basic input constraints (printable ASCII or hexadecimal based on what `strings` suggests). Launch with a 5-minute timeout.

3. **Evaluate the result**:  
   - **Success** → Verify the solution on the binary, move to the next problem.  
   - **Timeout with thousands of active states** → Path explosion. Move to workflow #2.  
   - **Timeout with few states** → The solver is stuck on complex expressions. Move to workflow #3.  
   - **Error** → Read the message, hook the problematic function, relaunch. If the problem persists, move to workflow #2.

### Human investment

About 15 minutes. If it works, it's the best possible effort/result ratio.

### When it works

- CTF crackmes (the majority).  
- Binaries with isolated verification logic and clear success/failure messages.  
- Small programs (< 100 KB) without complex environment interactions.

---

## Hybrid workflow #2 — The "Ghidra-guided scalpel"

When the blind shot fails, human effort must be invested to guide symbolic execution. The principle: use static analysis to **reduce the scope** of symbolic execution to the strict minimum.

### Steps

1. **Static analysis** (30–60 minutes) — Open the binary in Ghidra. Locate the verification function (via cross-references to success/failure strings, Chapter 8). Rename variables, reconstruct types, understand the global control flow.

2. **Identify boundaries** — Precisely determine:  
   - The **entry address** of the verification function.  
   - The **registers or memory addresses** containing inputs at the function's entry point (System V convention: `rdi`, `rsi`, `rdx`…).  
   - The **exit addresses**: the different `return`s (success vs failure).  
   - The **functions called** by the verification routine and whether they're problematic (crypto, I/O, complex loops).

3. **Prepare the angr state** — Create a `blank_state` at the function's entry address, inject symbolic inputs into the correct registers, allocate memory buffers if needed.

4. **Hook problematic zones** — If Ghidra analysis revealed problematic functions (hashing, file access, giant loops), hook them with adapted SimProcedures.

5. **Launch angr on the reduced scope** — With `find` and `avoid` pointing to return addresses identified in Ghidra.

### Concrete example

Suppose Ghidra reveals this structure in a license validation binary:

```c
// Ghidra pseudo-code (cleaned up)
int validate_license(char *key) {
    if (strlen(key) != 24) return -1;           // 0x401200

    char decoded[12];
    base64_decode(key, decoded);                 // 0x401220

    uint32_t checksum = crc32(decoded, 8);       // 0x401250
    if (checksum != 0xCAFEBABE) return -2;       // 0x401270

    uint32_t *vals = (uint32_t *)decoded;
    transform(vals[0], vals[1]);                 // 0x401290
    if (vals[0] != 0x1337 || vals[1] != 0x7331)
        return -3;                               // 0x4012C0

    return 0;                                    // 0x4012D0 (success)
}
```

Static analysis reveals three obstacles:

- `base64_decode` — Well supported by angr (existing SimProcedure or easy to model).  
- `crc32` — Modelable in Z3 (Section 18.4) but can slow angr if the input is long.  
- `transform` — A few arithmetic operations, ideal candidate for symbolic execution.

**Hybrid strategy**: we don't launch angr on the entirety of `validate_license`. We decompose the problem:

1. The CRC-32 applies to the first 8 decoded bytes. We model `crc32(bytes[0:8]) == 0xCAFEBABE` in Z3, obtaining bytes 0 through 7.  
2. Bytes 8 through 11 (the two remaining `uint32_t`s) must satisfy `transform(vals[0], vals[1]) == (0x1337, 0x7331)`. We launch angr with `blank_state` at `transform`'s address with symbolic `vals[0]` and `vals[1]`.  
3. We combine the 12 found bytes, encode them in base64, and get the 24-character key.

Each sub-problem is solved in seconds, where angr on the entire function would probably have blocked on the symbolic CRC-32.

---

## Hybrid workflow #3 — The "all Z3 guided by Ghidra"

When angr simply can't handle the binary (obfuscation, self-modifying code, complex system interactions), we abandon automatic symbolic execution in favor of complete manual modeling in Z3.

### Steps

1. **In-depth static analysis** (1–3 hours) — Fully understand the verification logic in Ghidra. Rename every variable, annotate every operation, reconstruct the complete pseudo-code.

2. **Dynamic validation** — Run the binary in GDB with known inputs to confirm code understanding. Compare memory values observed with those predicted by your understanding.

3. **Translation to Z3** — Translate the Ghidra pseudo-code into a Z3 script, operation by operation (as in Section 18.4). Verify each step by comparing Z3 and GDB on concrete values.

4. **Resolution** — Submit constraints to Z3. Verify the solution on the real binary.

### The Ghidra ↔ Z3 ↔ GDB ping-pong

This workflow isn't linear — it's a constant back-and-forth between three windows:

```
  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
  │   Ghidra    │     │  Python/Z3  │     │     GDB     │
  │             │     │             │     │             │
  │  Read the   │────→│  Translate  │────→│  Validate   │
  │  pseudo-code│     │  to Z3      │     │  with a     │
  │             │←────│             │←────│  known      │
  │  Correct    │     │  Adjust     │     │  input      │
  │  if error   │     │  if error   │     │             │
  └─────────────┘     └─────────────┘     └─────────────┘
```

The typical cycle:

1. Read a block of 5–10 lines in Ghidra.  
2. Translate it to Z3.  
3. Test the translation with a known concrete value: compute the result in Z3 (`simplify(expression)`) and compare it to what GDB shows at the same program point.  
4. If they match, move to the next block. If they diverge, there's a translation error — go back to Ghidra and verify.

This process is methodical and reliable. Each block is individually validated, avoiding silent error accumulation. On a 50-line decompiled function, expect 30 to 60 minutes for complete translation and validation.

---

## When not to use symbolic execution

The reflex of wanting to solve everything with angr is natural when you've just discovered the tool. But some problems are better solved otherwise, even when symbolic execution is technically possible:

### The problem is trivial

If the verification is a simple `strcmp(input, "password123")`, you need neither angr nor Z3. `strings` found it in 2 seconds, or GDB by setting a breakpoint on `strcmp`. Symbolic execution would work, but it would be unnecessary overkill.

**Practical rule**: if you can solve the problem in less than 5 minutes with GDB or `strings`, don't launch angr.

### The problem is dynamic

The program downloads a key from a server, decrypts a payload in memory, or adapts its behavior based on the time. Symbolic execution operates in a static, deterministic world. For inherently dynamic problems, Frida (Chapter 13) is the tool of choice:

```javascript
// Frida: intercept the decryption result on the fly
Interceptor.attach(ptr("0x401300"), {
    onLeave: function(retval) {
        console.log("Decrypted key: " + Memory.readByteArray(retval, 32));
    }
});
```

### The problem is structural

You're trying to understand a program's architecture, identify its modules, reconstruct its C++ classes (Chapter 17), or map its network interactions (Chapter 23). Symbolic execution doesn't help here — it's a job for Ghidra, cross-references, structure reconstruction, and call graph analysis.

### The problem requires patching

You want to modify a binary's behavior: invert a conditional jump (Chapter 21), replace a function (Chapter 22), bypass a check via `LD_PRELOAD`. Symbolic execution **finds** the right input, but it doesn't **modify** the binary. If your goal is patching, go directly to ImHex (Chapter 6) or a binary editor.

---

## The analyst's complete toolbox

To conclude this chapter, here's an overview of all techniques and tools covered in this training, positioned according to their use relative to symbolic execution:

```
  ┌───────────────────────────────────────────────────────────────┐
  │                     UNDERSTAND THE BINARY                     │
  │                                                               │
  │   strings, file, checksec    → Triage (5 min)                 │
  │   readelf, objdump           → ELF structure                  │
  │   Ghidra, IDA, Binary Ninja  → Decompilation                  │
  │   ImHex                      → Hexadecimal analysis           │
  └───────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
  ┌───────────────────────────────────────────────────────────────┐
  │                    OBSERVE EXECUTION                          │
  │                                                               │
  │   GDB / GEF / pwndbg         → Step-by-step debugging         │
  │   strace / ltrace            → System / library calls         │
  │   Frida                      → Dynamic hooking                │
  │   Valgrind                   → Memory analysis                │
  └───────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
  ┌───────────────────────────────────────────────────────────────┐
  │                    SOLVE AUTOMATICALLY                        │
  │                                                               │
  │   angr                       → Complete symbolic execution    │
  │   Z3                         → Constraint resolution          │
  │   AFL++ / libFuzzer          → Fuzzing (random exploration)   │
  └───────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
  ┌───────────────────────────────────────────────────────────────┐
  │                    MODIFY THE BINARY                          │
  │                                                               │
  │   ImHex                      → Hexadecimal patching           │
  │   LD_PRELOAD                 → Function replacement           │
  │   pwntools                   → Scripting and interactions     │
  │   LIEF / pyelftools          → Programmatic modification      │
  └───────────────────────────────────────────────────────────────┘
```

Symbolic execution (angr + Z3) sits in the "solve automatically" category. It's the most powerful of the three categories when it works, but it depends on the first two (understand and observe) to be correctly configured, and it may require the fourth (modify) to exploit its results.

---

## Synthesis case: how approaches complement each other

To anchor these ideas, here's the typical flow of a complete analysis on a non-trivial binary — the kind of target you'll encounter in Chapters 21 through 25:

**Minute 0–5: Triage** — `file` confirms an x86-64 dynamically linked ELF. `strings` reveals `"License valid"` and `"Invalid license"`. `checksec` shows PIE enabled, no canary. Hypothesis: crackme or license verification.

**Minute 5–15: angr attempt** — Standard script with `entry_state`, stdout criterion. Timeout after 5 minutes — 4000 active states, none found. Path explosion is clear. We note `strace` shows an `open("config.ini", ...)` — the program reads a configuration file.

**Minute 15–60: Ghidra analysis** — We open the binary in Ghidra. The decompiler reveals `main` reads a key from `argv[1]`, loads parameters from `config.ini`, then calls `validate(key, params)`. The `validate` function performs 3 operations: base64 decoding, an HMAC-SHA256 hash of the result with config file parameters, and a final comparison. The hash is the blocker — it's what makes angr explode.

**Minute 60–75: Hybrid strategy** — We identify the hash applies to the decoded result, not the raw input. We launch GDB, set a breakpoint after base64_decode, note the expected hash value (extracted from the comparison in Ghidra). We realize we can't invert SHA-256, but we can intercept the value *before* the hash.

**Minute 75–90: Frida** — We write a Frida script that hooks the hash function and logs its input argument with a valid license (obtained from a trial version, for example). We get the bytes that base64_decode must produce.

**Minute 90–100: Z3** — We model the inverse base64 transformation in Z3 (or simply in pure Python, base64 being bijective) to go from the expected bytes back to the license key.

**Minute 100–105: Verification** — We test the key. `"License valid"`. Done.

In this analysis, **no single tool** would have sufficed. angr failed. Ghidra alone would have identified the problem but not found the key. GDB alone wouldn't have shown the overall structure. Frida alone wouldn't have known what to intercept without Ghidra. It's the **combination** that produces the result.

---

## Reflexes to develop

Over the course of analyses, certain reflexes become automatic:

**Always start with triage.** Five minutes of `strings`/`file`/`checksec` can save you an hour of unnecessary work. If `strings` directly reveals the password in plaintext, no advanced tool is needed.

**Try angr early, but with a timeout.** The cost of a failed angr attempt is 5–10 minutes. The gain of a successful attempt is potentially hours of manual RE saved. The ratio is favorable.

**When angr fails, understand why before retrying.** Relaunching the same script hoping for a different result doesn't work. Diagnose (Section 18.5), then adjust strategy.

**Isolate the target function.** The majority of symbolic execution problems come from code **around** the verification function, not from the function itself. `blank_state` is your best friend.

**Validate every step.** Whether using angr, Z3, or manual analysis, test intermediate results with GDB. A translation error detected early costs 2 minutes to fix. Detected at the end, it can cost an hour of debugging.

**Document your analysis.** Note key addresses, hypotheses, intermediate results. When switching between Ghidra, angr, Z3, and GDB, it's easy to lose the thread. A simple text file with your chronological observations makes all the difference.

---

## Key points to remember

- Symbolic execution is **never the first step**. Quick triage and a minimum of static analysis always precede it.

- **Three hybrid workflows** cover most situations: the blind shot (brute angr, 15 min), the Ghidra-guided scalpel (targeted angr, 1–2h), and all-manual Z3 (3h+).

- The key is knowing how to **decompose the problem**: isolate sub-functions, solve each piece with the best-suited tool, then recombine results.

- Symbolic execution is unsuited for **trivial** problems (use `strings`/GDB), **dynamic** problems (use Frida), **structural** problems (use Ghidra), or **patching** problems (use ImHex/LD_PRELOAD).

- The **combination** of tools — not mastery of a single one — is what makes the difference between a beginner and an effective analyst.

- **Documenting as you go** and **validating every step** are the habits that transform fumbling into a reliable methodology.

---

> You now have all the knowledge needed to tackle this chapter's **checkpoint**: solving `keygenme_O2_strip` with angr in under 30 lines of Python. Everything you need is in Sections 18.2 and 18.3 — this checkpoint is the opportunity to verify you can do it autonomously, without copying the course scripts.

⏭️ [Checkpoint: solve `keygenme_O2_strip` with angr in under 30 lines of Python](/18-symbolic-execution/checkpoint.md)
