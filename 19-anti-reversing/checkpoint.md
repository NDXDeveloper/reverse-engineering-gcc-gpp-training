🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 19

## Objective

Identify **all** protections of the `anti_reverse_all_checks` binary, bypass them one by one, and find the password to obtain the flag.

This checkpoint draws on all chapter skills:

| Section | Assessed skill |  
|---|---|  
| 19.1 | Detecting stripping and adapting strategy |  
| 19.2 | Detecting potential packing and decompressing |  
| 19.5–19.6 | Identifying compiler protections (canary, NX, PIE, RELRO) |  
| 19.7 | Identifying and bypassing debugger detection |  
| 19.8 | Identifying and bypassing breakpoint countermeasures |  
| 19.9 | Applying the systematic triage workflow with `checksec` |

---

## Target binary

```
binaries/ch19-anti-reversing/build/anti_reverse_all_checks
```

This binary was compiled with `make anti_debug`. It combines all application-level protections implemented in `anti_reverse.c`, is compiled with `-O2`, and has been stripped. It's the chapter's most resistant variant.

You must **not** consult the `anti_reverse.c` source code to solve this checkpoint. The goal is to find the protections and password through analysis alone.

---

## Required work

### Phase 1 — Triage and protection sheet

Apply the Section 19.9 triage workflow on `anti_reverse_all_checks`:

1. Run `file` on the binary. Note the format, architecture, linkage, stripping status.  
2. Run `checksec`. Note each line: RELRO, canary, NX, PIE.  
3. Inspect dynamic imports with `nm -D`. List suspicious functions betraying anti-RE protections.  
4. Run `strings` and `strings | wc -l`. Look for packer signatures, procfs paths, business logic strings.  
5. Check entropy with `binwalk -E` and section structure with `readelf -S`.

Produce a **protection sheet** summary (free text, a few lines) listing:

- All detected compiler protections  
- All suspected application protections  
- The planned analysis strategy (which tools, which bypasses)

### Phase 2 — Anti-debug protection bypass

Using techniques of your choice (GDB, Frida, `LD_PRELOAD`, patching, or a combination):

1. Identify each anti-debug check present in the binary. For each, note the address (or offset) of the function and the technique used.  
2. Bypass each check individually. Document the chosen method.  
3. Reach the `"Password: "` prompt — proof that all checks have been passed.

**Hint**: the single-protection variants (`anti_reverse_ptrace_only`, `anti_reverse_timing_only`, `anti_reverse_procfs_only`, `anti_reverse_int3_only`) can serve as sandboxes to test each bypass in isolation before combining them.

### Phase 3 — Password extraction

Once anti-debug protections are bypassed:

1. Locate the password verification routine in the disassembly (Ghidra, objdump, or directly in GDB).  
2. Understand the expected password's encoding/decoding mechanism.  
3. Extract the password using one of the following methods:  
   - Static analysis: reconstruct the decoding algorithm and reproduce it  
   - Dynamic analysis: set a breakpoint (hardware!) on the comparison and read the expected value in memory  
   - Scripting: write a script that automates extraction

4. Validate the password: the program should display the flag `CTF{...}`.

---

## Deliverables

The checkpoint is validated when you have:

1. **The protection sheet** — The complete summary of protections identified during triage.  
2. **The bypass journal** — For each anti-debug protection, the technique used to neutralize it (a few lines per protection suffice: protection name, address/offset, bypass method, command or script used).  
3. **The password and flag** — Proof the binary was completely solved.  
4. **Optional** — A script (GDB Python, Frida JS, or shell) that automates the complete bypass and password extraction in a single run.

---

## Success criteria

| Criterion | Expected |  
|---|---|  
| Complete triage | All 5 workflow steps were applied |  
| Compiler protections | RELRO, canary, NX, PIE correctly identified |  
| Application protections | All anti-debug techniques listed and located |  
| Bypass | Each check is neutralized by a documented method |  
| Password | The flag is obtained by submitting the correct password |

---

## Tips

- Start with triage. Don't touch GDB before you have a complete protection sheet.  
- Dynamic imports (`nm -D`) tell half the story, even on a stripped binary.  
- Facing multiple combined checks, a single Frida script that hooks all suspicious functions is often faster than individual bypasses in GDB.  
- The password is not stored in plaintext in the binary. Look for a reversible encoding.  
- Hardware breakpoints are your allies on this binary. Use `hbreak` in GDB.  
- If stuck, the `anti_reverse_debug` variant (with symbols, without anti-debug protections) allows understanding the program structure before tackling the hardened version.

---


⏭️ [Chapter 20 — Decompilation and source code reconstruction](/20-decompilation/README.md)
