🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 34

## Analyze a stripped Go binary, recover functions, and reconstruct the logic

> *This checkpoint validates all the skills from Chapter 34. You work exclusively on `crackme_go_strip` — the stripped binary, without ELF symbols or DWARF. Your objective: reconstruct enough context to understand the validation logic and produce a valid key.*

---

## Target Binary

```
binaries/ch34-go/crackme_go_strip
```

Compile it beforehand if not already done:

```bash
cd binaries/ch34-go && make
```

> ⚠️ **Rules of the game**: do **not** consult the source code `main.go` before completing the checkpoint. You may however use the non-stripped binary `crackme_go` to verify your results after the fact.

---

## Objectives

The checkpoint is broken down into six progressive objectives. Each one draws on one or more sections from the chapter.

### Objective 1 — Triage and Identification (sections 34.1, 34.5)

Determine, without consulting the source, the following information:

- the exact version of the Go compiler used,  
- the binary's size and the reason for that size,  
- whether the binary is statically or dynamically linked,  
- the active protections (`checksec`),  
- the character strings relevant to the business code (filtering out runtime noise).

**Deliverable**: a triage paragraph summarizing your findings, similar to the Chapter 5 workflow adapted to Go specifics.

### Objective 2 — Symbol Recovery (section 34.4)

Extract function names from the binary's internal structures:

- locate `gopclntab` (by its magic number or via a tool),  
- extract the complete list of user functions (`main.*` package),  
- identify the `pclntab` format version and confirm consistency with the compiler version.

**Deliverable**: the list of `main` package functions with their start and end addresses, and the total number of functions in the binary (runtime included).

### Objective 3 — Import into the Disassembler and ABI Identification (sections 34.2, 34.4)

Import the recovered symbols into Ghidra (or the tool of your choice):

- apply the function names to the disassembly,  
- determine which calling convention is used (stack-based or register-based) by examining the prologue of at least two functions from the `main` package,  
- identify the register used for the goroutine pointer `g` and verify the stack check preamble.

**Deliverable**: a screenshot or annotated excerpt of the `main.main` disassembly showing the restored function names and a note on the identified ABI.

### Objective 4 — Type and Data Structure Reconstruction (sections 34.3, 34.6)

Identify the data structures used by the crackme:

- which types are defined in the `main` package (structs, interfaces) — extract them via GoReSym or `typelinks`,  
- for each struct, provide the list of fields, their types, and offsets,  
- identify the interfaces and list the concrete types that implement them (via itabs),  
- spot the uses of slices, maps, and channels in the code by searching for characteristic runtime calls (`runtime.makemap`, `runtime.makechan`, `runtime.growslice`, etc.).

**Deliverable**: a reconstructed type definitions file (pseudo-Go or pseudo-C), and a list of dynamic data structures used by the program.

### Objective 5 — Validation Logic Analysis (sections 34.1, 34.2, 34.3, 34.5)

Reconstruct the license key validation flow:

- from `main.main`, trace the call graph to the validation functions,  
- identify how many validation steps exist and in what order they execute,  
- for each step, determine the success condition (which comparison, which operands, which expected value),  
- identify whether goroutines are launched (`runtime.newproc`) and what role they play in the validation,  
- extract the key constants (expected values, seeds, magic bytes) from `.rodata` or the code.

**Deliverable**: a natural language description of the validation algorithm, step by step, with the extracted constants.

### Objective 6 — Produce a Valid Key

Based on your understanding of the logic, produce a license key accepted by the program:

- run the binary with your candidate key and verify the success message,  
- if you wish, write a short script (Python, Go, or other) that generates valid keys.

**Deliverable**: at least one valid key, accompanied by your reasoning.

---

## Suggested Tools

| Tool | Usage in this checkpoint |  
|---|---|  
| `file`, `readelf`, `checksec` | Initial triage (objective 1) |  
| `strings` + filtering | Raw string extraction (objective 1) |  
| GoReSym | Function, type, and Go version extraction (objectives 2, 4) |  
| `jq` | Exploiting GoReSym's JSON output |  
| Ghidra + import script | Disassembly and decompilation (objectives 3, 4, 5) |  
| GDB (+ GEF/pwndbg) | Dynamic analysis, register inspection (objectives 5, 6) |  
| Frida (optional) | Hooking validation functions (objective 5) |  
| Python | Keygen (objective 6) |

---

## Validation Criteria

| Criterion | Achieved | Not achieved |  
|---|---|---|  
| Compiler version identified | The exact version (e.g., `go1.22.1`) is found | Version absent or incorrect |  
| `main.*` functions listed | Complete list with consistent addresses | Partial list or incorrect addresses |  
| ABI correctly identified | Convention named (stack or register) with assembly evidence | ABI not determined or confused with System V |  
| Types reconstructed | At least the structs and the main interface with fields and offsets | Types absent or incomplete |  
| Validation logic described | All steps identified with conditions and constants | Missing steps or incorrect conditions |  
| Valid key produced | The binary displays the success message | Key rejected |

The checkpoint is passed when all six criteria are met.

---

## Methodological Tips

**Follow the order of the objectives.** Each step builds on the previous one. Attempting to reverse the logic (objective 5) without first recovering function names (objective 2) is possible but much more laborious.

**Start with static analysis, validate with dynamic.** Formulate hypotheses by reading the disassembly, then confirm them with GDB. For example, if you think a function returns a boolean, set a breakpoint at its return and observe `RAX`.

**Filter the runtime.** When you open the binary in Ghidra after importing symbols, the Symbol Tree will contain thousands of entries. Immediately filter on `main.*` in the Symbol Tree search bar. The `runtime.*`, `fmt.*`, `sync.*`, etc. functions are only relevant when you encounter them as call targets from `main` code.

**For channels and goroutines, think in terms of data flow.** If a validation passes through goroutines communicating via a channel, the question is not how the scheduler works, but what data enters and exits the channel. Set a breakpoint on `runtime.chansend1` and `runtime.chanrecv1` to capture this data.

**Take notes on everything.** Keep a notebook (text file, Ghidra comments, or paper notebook) with your discoveries as you go. RE is an iterative process — an apparently insignificant piece of information at objective 2 may become crucial at objective 5.

---

## Verification

Once your key is found, you can verify with the non-stripped binary:

```bash
./crackme_go YOUR-KEY-HERE-TEST
```

The non-stripped binary and the stripped binary execute the same code — a valid key for one is valid for the other. Comparing both binaries in Ghidra (one with symbols, the other with your reconstructed symbols) is an excellent way to measure the quality of your reconstruction.

The complete solution can be found in `solutions/ch34-checkpoint-solution.md`.

⏭️ [Part IX — Resources & Automation](/part-9-resources.md)
