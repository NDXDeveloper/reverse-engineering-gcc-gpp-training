🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 9.5 — Binary Ninja Cloud (free version) — quick start

> 📘 **Chapter 9 — Advanced disassembly with IDA Free, Radare2, and Binary Ninja**  
> Previous section: [9.4 — Scripting with r2pipe (Python)](/09-ida-radare2-binja/04-scripting-r2pipe.md)

---

## Binary Ninja in a few words

Binary Ninja (often abbreviated "Binja") is a disassembler and decompiler developed by Vector 35, a company founded by veterans of the CTF scene and security research. Launched in 2016, it quickly made a place alongside IDA and Ghidra thanks to two distinctive strengths: an **exceptionally well-designed Python API**, and a **multi-level intermediate representation system** (BNIL — *Binary Ninja Intermediate Language*) that facilitates programmatic analysis at different degrees of abstraction.

Binary Ninja exists in several commercial editions (Personal, Commercial, Enterprise), but Vector 35 offers a **free version usable in the browser**: **Binary Ninja Cloud**. It's this version we'll use here. It offers access to the decompiler, graph navigation, and most analysis features — enough to evaluate the tool and integrate it into your RE toolbox.

## Accessing Binary Ninja Cloud

Binary Ninja Cloud is a web application. There's nothing to install — a modern browser suffices.

1. Go to [cloud.binary.ninja](https://cloud.binary.ninja).  
2. Create a free account (email + password) or log in if you already have one.  
3. You reach a dashboard listing your previous analyses (empty on first use).

To start an analysis, click **Upload** and select your binary. We use `keygenme_O2_strip` as in the previous sections.

> ⚠️ **Privacy.** The binary is uploaded to Vector 35's servers to be analyzed. Never upload a binary containing sensitive, proprietary, or classified data to a third-party cloud service. For the training binaries of this course, there's no risk.

After the upload, Binary Ninja automatically launches its analysis. Progress is displayed in real time. Once analysis is finished, the main interface opens.

## Limitations of the Cloud version

Before exploring the interface, let's clarify what the Cloud version allows and does not allow compared to the paid editions.

**What's available:**

The Cloud version gives access to Binary Ninja's complete analysis engine, including the decompiler (called *High Level IL* or HLIL). Graph navigation, function and variable renaming, cross-references, comments, and visualization of the different IL levels are all present. It's considerably more generous than IDA Free: you have a functional decompiler without quota restrictions.

**What's not available:**

The Python API — one of Binary Ninja's main assets — is not accessible in the Cloud version. Scripting and automation require a local license (Personal or higher). Similarly, headless mode for batch analysis, community plugins, and advanced type import/export are not available. The Cloud version works exclusively in the browser, which implies dependence on the internet connection and Vector 35's servers. Finally, the size of uploadable binaries and the number of simultaneous analyses may be limited.

For the context of this chapter — getting to know the tool and comparing its analysis with Ghidra, IDA, and Radare2 — these limitations are not blocking.

## Discovering the interface

Binary Ninja Cloud's interface is clean and modern, with an organization reminiscent of both IDA and Ghidra but with its own vocabulary.

### The central view: Linear and Graph

The main area displays the analyzed code. As in IDA, two modes are available:

- **Linear View** — the sequential listing of the whole binary, function after function, with addresses, bytes, and annotated disassembly. It's the equivalent of IDA's text mode.  
- **Graph View** — the basic-block view with control-flow edges. Each block is a rectangle containing instructions, and conditional branches are represented by colored edges. Navigation is via drag-and-pan and wheel (zoom).

Toggling between the two views is done via tabs at the top of the central view or keyboard shortcuts.

### The functions panel

The left side panel lists detected functions. Each entry displays the name (or `sub_XXXX` for unrecognized functions), the address, and sometimes the return type inferred by the analysis. A search field at the top allows filtering by name — very useful on large binaries with hundreds of functions.

A click on a function navigates to it in the central view.

### The decompilation panel

It's one of the most important panels. Binary Ninja displays the decompiled pseudo-code of the current function, synchronized with the disassembly view. Decompilation quality is generally good, comparable to Ghidra's on GCC x86-64 binaries, with sometimes differences in presentation style and handling of certain optimization patterns.

The displayed pseudo-code corresponds to Binary Ninja's **HLIL** (*High Level Intermediate Language*) level — the highest level of abstraction, closest to C. We'll come back to IL levels below.

### Strings

Access to strings is via the menu or search bar. Binary Ninja detects strings in data sections and allows navigating to their cross-references, as in the other tools.

### Cross-references

By selecting a symbol (function name, variable, address), you can display its cross-references. Binary Ninja distinguishes code references (calls, jumps) from data references (reads, writes), with a dedicated panel that lists each occurrence with its context.

## BNIL architecture: Binary Ninja's peculiarity

What fundamentally distinguishes Binary Ninja from other disassemblers is its **multi-level intermediate representation system**, called BNIL (*Binary Ninja Intermediate Language*). Understanding this architecture, even without access to the API, illuminates the tool's philosophy and helps interpret its results.

### The problem BNIL solves

A classic disassembler works at two levels: raw assembly (machine instructions) and decompiled pseudo-code (approximate C). The problem is that the jump between these two levels is immense. Assembly is too detailed to reason about program logic (each trivial operation in C becomes 3 to 5 instructions), and the pseudo-code is sometimes too simplified or unfaithful (the decompiler made assumptions that may be wrong).

BNIL introduces intermediate levels that let you choose the degree of abstraction suited to your need.

### The four levels

Binary Ninja transforms machine code through a chain of increasingly abstract representations:

**Disassembly** — native machine instructions (x86-64 in our case). It's the same level as what `objdump`, IDA, or `r2` produce. Each instruction is specific to the target architecture.

**LLIL (Low Level IL)** — a first abstraction that uniformizes instructions of all architectures into a common intermediate language. The peculiarities of x86-64 (instructions with multiple side effects, implicit flags, complex addressing) are decomposed into simple and explicit operations. For example, a `push rax` instruction in x86-64 is decomposed into two LLIL operations: decrement `rsp` by 8, then write `rax` to the address pointed to by `rsp`. This level is architecture-independent.

**MLIL (Medium Level IL)** — an additional level of abstraction that introduces variable notions (instead of registers and stack locations), eliminates explicit stack manipulations, and resolves calling conventions. Register parameter passing (`rdi`, `rsi`…) is replaced by named arguments. This level approaches classic three-address code in compilation.

**HLIL (High Level IL)** — the most abstract level, closest to C. Control structures (`if`, `while`, `for`, `switch`) are rebuilt, expressions are combined and simplified, and the result resembles readable C. It's what the decompilation panel displays.

### Why it's useful in practice

In the Cloud interface, you can toggle between these levels for the current function. The interest is twofold.

When the HLIL decompiler produces a dubious result (mis-typed variable, aberrant control structure), descending to the MLIL or LLIL level allows verifying what the code actually does, without falling back into the complexity of raw assembly. It's an intermediate confidence level that neither IDA nor Ghidra offer in as structured a way.

When you want to understand how a complex x86-64 instruction decomposes (for example a `rep movsb`, a `lock cmpxchg`, or a SIMD instruction), switching to LLIL explicitly shows each micro-operation, which is pedagogically valuable.

> 💡 Binary Ninja's Python API (available in paid editions) allows working programmatically on each of these IL levels. This makes the tool particularly suited to automated vulnerability research and taint analysis: you can write queries on MLIL like "find all paths where data from `recv()` reaches a `memcpy()` without passing through a size check". This kind of analysis is notably more complex to write directly on assembly or on the textual pseudo-code of a decompiler.

## Workflow on `keygenme_O2_strip`

The workflow in Binary Ninja Cloud is consistent with the chapter's general methodology.

**1 — Upload and analyze.** Load `keygenme_O2_strip` via the web interface. Wait for automatic analysis to finish.

**2 — Inspect functions.** Browse the function list in the side panel. Identify `main` (if recognized) or candidate `sub_*` functions. Binary Ninja generally detects `main` on GCC ELF binaries by following the `__libc_start_main` pattern, like IDA.

**3 — Explore strings.** Use the search function to locate characteristic strings ("Access granted", "Wrong key"). Navigate to the string, then trace back cross-references.

**4 — Read the decompiled code.** Display the HLIL panel for the verification function. Compare the pseudo-code with the one obtained under Ghidra for the same binary — differences in style and decompilation fidelity are instructive.

**5 — Descend into IL levels.** If a passage in HLIL is ambiguous, toggle to MLIL then LLIL to understand the real mechanics.

**6 — Annotate.** Rename identified functions and variables. Annotations are saved in your Cloud space and persist between sessions.

## Renaming and annotation

Binary Ninja Cloud supports standard annotation operations:

- **Rename a function** — right-click on the function name → *Rename*. The new name propagates throughout the analysis (disassembly, decompiled view, XREF).  
- **Rename a variable** — in the decompilation panel, right-click on a variable → *Rename*. As Binary Ninja works at the MLIL/HLIL level with real variables (not registers), renaming is consistent and propagated throughout the pseudo-code.  
- **Change a type** — right-click → *Change Type*. You can specify the type of a local variable, a parameter, or the return value of a function. Binary Ninja propagates types across IL levels.  
- **Add a comment** — right-click on an instruction → *Add Comment*. The comment appears in the disassembly and may be visible in the decompiled view depending on context.

## Strengths and weaknesses

### Where Binary Ninja excels

**Decompiler quality.** On GCC x86-64 binaries with moderate optimization (`-O2`), Binary Ninja's HLIL decompiler often produces cleaner pseudo-code than Ghidra's, with better handling of arithmetic expressions and type casts. On `-O0` binaries, both are excellent. On `-O3` binaries with vectorization, results diverge and neither is systematically better than the other.

**BNIL architecture.** The ability to navigate between four abstraction levels in the interface is a unique pedagogical and analytical asset. No other free tool offers this granularity.

**User interface.** The Cloud interface is responsive, clean, and intuitive. Synchronization between graph view and decompiled code is fluid. Keyboard shortcuts are consistent and the learning curve is gentle for someone coming from IDA or Ghidra.

**Typing and propagation.** Binary Ninja is particularly good at deducing and propagating data types. If you type a parameter as `struct sockaddr_in *`, the tool propagates this information throughout the function and rebuilds accesses to the structure's fields.

### Where Binary Ninja Cloud is limited

**No scripting.** This is the major limitation. Binary Ninja's Python API is considered by many the best on the market in terms of design (documentation, consistency, typing), but it's not available in the Cloud version. For automation, `r2pipe` or Ghidra scripting remain the free alternatives.

**No offline mode.** The Cloud version requires a permanent internet connection. On a restrictive enterprise network, in an isolated analysis lab (Chapter 26), or simply on a train, the tool is inaccessible. Ghidra and Radare2 work entirely offline.

**Mandatory upload.** The binary is sent to Vector 35's servers. It's prohibitive for some professional contexts (confidential malware analysis, NDA audit, government binaries).

**Architecture support.** The Cloud version covers x86, x86-64, ARM, and ARM64, which suffices for the vast majority of cases. But for more exotic architectures (MIPS, PowerPC, SPARC, microcontrollers), Ghidra and Radare2 have an advantage.

**Plugin ecosystem.** IDA benefits from 30 years of community plugins, and Ghidra from a rapidly growing ecosystem. Binary Ninja has an active but smaller plugin community, and plugins are not usable in the Cloud version anyway.

## Quick comparison of the decompiled view: Binary Ninja vs Ghidra

To illustrate concretely the differences, here is the type of result you can get for the same verification function of `keygenme_O2_strip` in both tools.

**Ghidra** typically produces faithful but verbose pseudo-code, with explicit casts (`(char *)`, `(int)`) and generated variable names (`local_18`, `param_1`). The control structure is correct but may appear heavy.

**Binary Ninja HLIL** tends to produce more concise code, with more readable variable names by default (`var_18` renamed to `arg1` if it's a recognized parameter), and simplified expressions. `if/else`s are sometimes better reconstructed, with fewer parasitic `goto`s.

Both tools can make different mistakes: Ghidra may mis-infer a return type, Binary Ninja may poorly reconstruct an unrolled loop. That's why the practice of **cross-checking** — comparing the decompiled output of two tools on the same binary — is so precious. One's errors are often corrected by the other.

## When to use Binary Ninja Cloud

Binary Ninja Cloud finds its place in your workflow in the following situations:

- **Second opinion on decompiled code.** You've analyzed a binary in Ghidra and a passage of the pseudo-code seems suspicious. Uploading the binary to Binary Ninja Cloud and comparing the HLIL with Ghidra's decompiled output takes a few minutes and can lift the ambiguity.

- **Exploring IL levels.** You want to understand how a complex assembly instruction decomposes, or verify what the compiler actually did at an intermediate level. The LLIL and MLIL views are unique to Binary Ninja.

- **Quick analysis without installation.** You're on a machine where Ghidra and Radare2 aren't installed. Binary Ninja Cloud works in any browser, without installation, without configuration.

- **Evaluation before purchase.** If you're considering investing in a Binary Ninja license (Personal at a few hundred dollars), the Cloud version lets you test analysis quality and tool philosophy before committing.

For heavy analyses, scripting, offline work, or confidentiality contexts, Ghidra and Radare2 remain the preferred choices in the free ecosystem.

---


⏭️ [Ghidra vs IDA vs Radare2 vs Binary Ninja comparison (features, price, use cases)](/09-ida-radare2-binja/06-tools-comparison.md)
