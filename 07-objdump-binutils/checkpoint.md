🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 7

## Disassemble `keygenme_O0` and `keygenme_O2`, list the key differences

> 📦 **Binaries**: `keygenme_O0` and `keygenme_O2` (`binaries/ch07-keygenme/` directory)  
> 🔧 **Tools**: `objdump`, `readelf`, `nm`, `c++filt`, `grep`, `diff`  
> ⏱️ **Estimated duration**: 30 to 45 minutes  
> 📝 **Deliverable**: a short report (free text or Markdown) documenting your observations

---

## Goal

This checkpoint validates the skills acquired in all of Chapter 7. You will disassemble two variants of the same program — compiled respectively at `-O0` and `-O2` — and produce a structured comparative report that highlights the transformations introduced by optimization.

The goal is not to understand the complete logic of the program (that will be the subject of Chapter 21). The objective here is to **demonstrate your ability to read, navigate, and compare `objdump` listings** by applying the techniques seen in sections 7.1 to 7.7.

---

## What your report must cover

### 1. Initial triage of both binaries

Before disassembling, characterize each binary with the tools of Chapter 5:

- File sizes and size of the `.text` section (via `readelf -S`).  
- Presence or absence of symbols (`file`, `nm`).  
- Approximate number of user functions in `.text`.

Note the first quantitative differences between both versions.

### 2. Identification of `main()` and user functions

By applying the techniques of section 7.5:

- Locate `main()` in each binary (via symbols if available, or through `_start` and `__libc_start_main` if you want to practice the method on a stripped binary).  
- List the user functions present in both versions (names and addresses).  
- Note whether both binaries contain the same number of user functions, or whether some disappeared at `-O2` (inlining).

### 3. Comparison of prologues and epilogues

By applying the techniques of section 7.4, for each user function:

- Describe the prologue at `-O0`: presence of the frame pointer, size of the stack allocation (`sub rsp, N`), callee-saved registers saved.  
- Describe the prologue at `-O2`: is the frame pointer still present? Does the function allocate space on the stack? Which registers are saved?  
- Note the matching epilogues (`leave`+`ret` vs `pop`+`ret` vs `ret` alone).

### 4. Differences in the function bodies

This is the core of the report. For at least one function (preferably the most interesting one — the one containing the verification logic), compare:

- **Variable accesses**: at `-O0`, identify the `[rbp-N]` accesses (variables on the stack). At `-O2`, identify the registers that replace these variables.  
- **Number of instructions**: count (or estimate) the number of instructions in the function for each version.  
- **Visible optimizations**: spot concrete transformations — disappearance of useless store-loads, strength reduction (multiplication replaced by a shift), constant propagation, instruction reordering.  
- **Loop structure**: if the function contains a loop, compare its structure in both versions. Is the initialization/test/body/increment pattern preserved at `-O2`?

### 5. Function calls and PLT

- Are the same libc functions called in both versions (`printf`, `strcmp`, `puts`…)?  
- Are there internal `call`s that disappeared at `-O2` (sign of inlining)?  
- Are PLT calls identical in both listings?

### 6. Synthesis

Conclude with a summary paragraph answering the question: **if you received the `-O2` binary without ever having seen the `-O0` version, what additional difficulties would you have encountered in understanding the program's logic?**

---

## Recommended method

Here is an efficient workflow to produce the report:

```bash
# 1. Generate both complete listings
objdump -d -M intel keygenme_O0 > /tmp/O0.asm  
objdump -d -M intel keygenme_O2 > /tmp/O2.asm  

# 2. Optional: generate a version with interleaved source (if -g)
objdump -d -S -M intel keygenme_O0 > /tmp/O0_src.asm

# 3. Compare side by side
diff -y --width=160 /tmp/O0.asm /tmp/O2.asm | less

# 4. Count functions (approximation via prologues)
grep -c "push   rbp" /tmp/O0.asm  
grep -c "push   rbp" /tmp/O2.asm  

# 5. Count instructions in .text
grep -c '^ ' /tmp/O0.asm  
grep -c '^ ' /tmp/O2.asm  

# 6. List internal function calls
grep "call" /tmp/O0.asm | grep -v "plt" | sort -u  
grep "call" /tmp/O2.asm | grep -v "plt" | sort -u  
```

Open both `.asm` files in your text editor with a split view, and work function by function.

---

## Validation criteria

Your checkpoint is validated if your report:

- ✅ Correctly identifies `main()` and user functions in both binaries.  
- ✅ Describes at least one prologue/epilogue difference between `-O0` and `-O2`.  
- ✅ Identifies at least two concrete optimizations in a function body (for example: variables moved from stack to registers, removal of store-loads, strength reduction).  
- ✅ Notes the difference in instruction count between both versions for at least one function.  
- ✅ Contains a synthesis on the impact of optimization on readability in RE.

Don't aim for exhaustiveness: a clear 1- to 2-page report covering these points is sufficient. The quality of observation trumps quantity.

---

## Verification

Compare your report with the solution available in `solutions/ch07-checkpoint-solution.md`. The solution lists the expected differences — yours do not have to be identical (addresses may vary according to your GCC version and distribution), but the substantive observations (type of optimizations, impact on structure) must converge.

---

> **Next chapter**: Chapter 8 — Advanced disassembly with Ghidra

⏭️ [Chapter 8 — Advanced disassembly with Ghidra](/08-ghidra/README.md)
