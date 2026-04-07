🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Perform a complete triage of the `mystery_bin` binary

> **Chapter 5 — Basic binary inspection tools**  
> **Part II — Static Analysis**

---

## Goal

This checkpoint validates your mastery of all the tools presented in Chapter 5. You will apply the quick triage workflow (section 5.7) to a binary you have never seen — `mystery_bin` — and produce a structured one-page analysis report.

The `mystery_bin` binary was compiled with GCC from C or C++ source code you do not know. You know nothing else about it. Your job is to discover, using only the tools from Chapter 5, everything that can be learned about this binary **without opening it in a disassembler**.

---

## Binary location

```bash
$ ls binaries/ch05-mystery_bin/mystery_bin
```

If the binary has not been compiled yet, run from the repository root:

```bash
$ cd binaries && make all
```

---

## Instructions

### What you need to do

Apply the six steps of the triage workflow in order. For each step, run the appropriate commands, observe the results, and note the relevant information. At the end of the triage, write a structured report that synthesizes your observations and formulates hypotheses about the program's nature and behavior.

### What you need to produce

A Markdown (or text) file of roughly one page, structured along the report template presented in section 5.7. The report must cover the following six sections:

1. **Identification** — format, architecture, linking, stripping, compiler.  
2. **Notable strings** — messages, paths, suspicious data, formats.  
3. **ELF structure** — entry point, notable sections, dependencies, possible anomalies.  
4. **Functions and imports** — program functions (if available), imported library functions.  
5. **Protections** — state of each protection (NX, PIE, canary, RELRO, FORTIFY).  
6. **Dynamic behavior** — `strace`/`ltrace` observations (in an appropriate environment).

The report must conclude with a **hypotheses and strategy section**: based on your observations, what does this program do? What are the most promising investigation leads for deeper reverse engineering? Which tool would you open first to continue the analysis?

### What you must not use

This checkpoint is limited to Chapter 5's tools. Do not open the binary in Ghidra, IDA, Radare2, or any other disassembler/decompiler. Do not use GDB. The goal is precisely to measure what you can learn **without** these advanced tools.

---

## Methodological help

### Reference commands per step

Here is a summary of the key commands for each step, as presented throughout the chapter:

**Step 1 — Identification:**

```bash
$ file mystery_bin
```

**Step 2 — Strings:**

```bash
$ strings mystery_bin | head -40
$ strings -t x mystery_bin | grep -iE '(error|fail|password|key|flag|secret|http|socket|crypt)'
$ strings mystery_bin | grep -iE '(GCC|clang|rustc)'
$ strings mystery_bin | grep '%'
```

**Step 3 — ELF structure:**

```bash
$ readelf -hW mystery_bin
$ readelf -SW mystery_bin
$ readelf -lW mystery_bin
$ readelf -d mystery_bin | grep NEEDED
```

**Step 4 — Symbols and imports:**

```bash
# Try the full table first
$ nm -nS mystery_bin 2>/dev/null | grep ' T '

# If "no symbols", fall back to dynamic symbols
$ nm -D mystery_bin

# Detailed view
$ readelf -s mystery_bin
```

**Step 5 — Protections:**

```bash
$ checksec --file=mystery_bin

# Or manually if checksec is not available:
$ readelf -lW mystery_bin | grep GNU_STACK
$ readelf -h mystery_bin | grep Type
$ readelf -s mystery_bin | grep __stack_chk_fail
$ readelf -lW mystery_bin | grep GNU_RELRO
$ readelf -d mystery_bin | grep BIND_NOW
```

**Step 6 — Dynamic behavior (sandbox):**

```bash
$ strace -e trace=file,network,process -s 256 -o strace.log ./mystery_bin
$ ltrace -s 256 -o ltrace.log ./mystery_bin
$ strace -c ./mystery_bin <<< "test"
$ ltrace -c ./mystery_bin <<< "test"
```

### Guiding questions

During the triage, keep these questions in mind to guide your observations:

- Is the binary stripped? If so, which function names remain accessible?  
- Which shared libraries does it use? What do they reveal about its features?  
- Do the strings suggest user interaction? A network protocol? Encryption? File handling?  
- Are there signs of anti-reversing (unusual sections, suspicious entropy, imports like `ptrace`)?  
- Does the dynamic behavior (`strace`/`ltrace`) confirm or contradict the hypotheses from static analysis?  
- What would be your next action if you had to continue the analysis beyond the triage?

---

## Validation criteria

Your triage report is considered complete if:

- [ ] The six sections are present and filled in.  
- [ ] The format, architecture, and linking type are correctly identified.  
- [ ] The stripping state is mentioned and its consequences on analysis are understood.  
- [ ] At least 3 meaningful strings are noted and interpreted (not just listed).  
- [ ] The main ELF sections are identified and any anomalies are flagged.  
- [ ] The program's functions and/or imports are listed with a functional interpretation.  
- [ ] The 5 main protections (NX, PIE, canary, RELRO, FORTIFY) are documented.  
- [ ] The dynamic behavior is observed and the results are consistent with the static analysis.  
- [ ] The report concludes with reasoned hypotheses and a strategy for what comes next.  
- [ ] The report fits on roughly one page — concise and structured, not a raw copy-paste of command outputs.

---

## Common mistakes to avoid

**Copy-pasting raw command output without interpreting it.** The report is not a terminal log. Every observation must be accompanied by its interpretation: what does this result mean? What does it tell us about the binary?

**Forgetting dynamic symbols on a stripped binary.** If `nm` without options returns "no symbols", many beginners conclude there are no symbols and move on. You need to think of `nm -D` for the imports — it is often the most valuable source of information on a stripped binary.

**Ignoring negative results.** The absence of an item is information in itself. If `strings` finds no URL, that is a hint that the program probably does no network (or is obfuscating its strings). If `strace` shows no `openat` beyond the libraries' loading, the program reads no files. Document those absences.

**Running `ldd` or step 6 on a potentially malicious binary without a sandbox.** In this checkpoint, the binary is provided by the training and is not malicious. But get into the habit of treating step 6 with caution — it is a reflex that will protect you in real situations.

**Mixing observation and hypothesis.** "The binary imports `strcmp`" is an observation. "The program probably compares user input with an expected value" is a hypothesis deduced from that observation. Both belong in the report, but they must be clearly distinguished.

---

## Going further

If you finish the triage quickly and want to dig deeper, here are some additional leads that stay within Chapter 5's toolset:

- Compare the output of `readelf -s` and `nm` — is the information strictly identical? Are there symbols one sees that the other does not?  
- Use `readelf -x .rodata` to examine the read-only data section. Are strings contiguous or interspersed with null bytes and numeric data?  
- If the binary accesses files at runtime (visible in `strace`), use `strings -t x` to locate file paths in the binary, then `xxd -s <offset>` to examine their hexadecimal context.  
- Run the binary several times with different inputs and compare the `ltrace` outputs. Does the behavior change with the input? Which functions are called in one case and not in the other?

---

## Solution

The checkpoint solution is available in `solutions/ch05-checkpoint-solution.md`. Consult it **after** writing your own report — the value of the exercise lies in the process, not the result.

---

> ✅ **Checkpoint validated?** You master the basic inspection tools and the quick triage workflow. You are ready for Chapter 6, where we dive into advanced hexadecimal analysis with ImHex.  
>  
> 

⏭️ [Chapter 6 — ImHex: advanced hexadecimal analysis](/06-imhex/README.md)
