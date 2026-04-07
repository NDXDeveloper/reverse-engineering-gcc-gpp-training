🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 19.3 — Control flow obfuscation (Control Flow Flattening, bogus control flow)

> 🎯 **Objective**: Understand the two main control flow obfuscation techniques — Control Flow Flattening (CFF) and Bogus Control Flow (BCF) — know how to recognize them in disassembly and understand approaches for restoring a readable structure.

---

## Control flow obfuscation: the problem

Stripping removes names. Packing hides code on disk. Control flow obfuscation attacks something more fundamental: it destroys the program's **logical structure** as it appears in disassembly, while preserving its functional behavior.

Well-written C code translates to assembly as a relatively readable control graph (CFG — Control Flow Graph): basic blocks connected by conditional and unconditional branches reflecting the source code's `if`, `else`, `for`, `while`, and `switch`. An experienced analyst can mentally reconstruct the high-level logic by reading this graph.

Control flow obfuscation aims to make this reconstruction impossible — or at least so laborious that the analyst spends hours instead of minutes. The code produces the same result, but the route it takes to get there has become a labyrinth.

Two techniques dominate this field: **Control Flow Flattening** and **Bogus Control Flow**. They're often combined.

## Control Flow Flattening (CFF)

### The principle

Control Flow Flattening is the most emblematic and effective technique. Its principle is simple to state:

**All basic blocks of a function are extracted from their natural hierarchy and placed at the same level, inside a `while(true)` loop driven by a dispatch variable (a `switch`).**

To illustrate, take a trivial C function:

```c
int check(int x) {
    int result = 0;
    if (x > 10) {
        result = x * 2;
    } else {
        result = x + 5;
    }
    return result;
}
```

The normal compiler produces a clear, linear CFG:

```
    [entry]
        |
    [cmp x, 10]
      /       \
   [x > 10]  [x <= 10]
     |            |
 [result=x*2] [result=x+5]
      \       /
     [return result]
```

After Control Flow Flattening, the structure becomes:

```c
int check_flattened(int x) {
    int result = 0;
    int state = 0;  /* dispatch variable */

    while (1) {
        switch (state) {
            case 0:  /* entry block */
                if (x > 10)
                    state = 1;
                else
                    state = 2;
                break;
            case 1:  /* then branch */
                result = x * 2;
                state = 3;
                break;
            case 2:  /* else branch */
                result = x + 5;
                state = 3;
                break;
            case 3:  /* exit */
                return result;
        }
    }
}
```

The flattened version's CFG looks like this:

```
         ┌──────────────────────────┐
         │    dispatcher (switch)   │◄─────┐
         └──────────────────────────┘      │
          /      |       |       \         │
     [case 0] [case 1] [case 2]  [case 3]  │
         \       |       |       /         │
          └──────┴───────┴──────┘──────────┘
                                   │
                              (case 3: return)
```

All blocks are now "siblings" at the same hierarchical level, all connected to the central dispatcher. The causal relationship between blocks — the fact that case 1 can only be reached if `x > 10` — is hidden behind the `state` variable. For an analyst reading the disassembly, each case appears independent. Reconstructing the logical order requires manually tracing all dispatch variable transitions.

### What it looks like in assembly

In x86-64 assembly, the dispatcher manifests as a recognizable pattern. You typically observe:

- A variable on the stack or in a register serving as a state counter  
- A cascade of comparisons (`cmp` + `je`/`jne`) or a jump table (`jmp [rax*8 + table]`) implementing the switch  
- Unconditional jumps (`jmp`) at the end of each block that systematically return to the dispatcher  
- The absence of direct jumps between business logic blocks — everything goes through the dispatcher

In Ghidra, a flattened function's Function Graph presents a characteristic "star" or "spider" shape: a central node (the dispatcher) with many outgoing edges to case blocks, and as many return edges from each block back to the dispatcher.

### Impact on analysis

CFF is devastating against decompilers. Ghidra, IDA, and other tools attempt to reconstruct high-level structures (`if`, `while`, `for`) from the CFG. Faced with a flattened function, the decompiler produces a giant `while(true)` containing a massive `switch` — technically correct but useless for understanding the logic.

On a 50-line C function, CFF can produce a 20-to-30-case switch. On a complex function of several hundred lines, the result becomes a monster of hundreds of cases where the analyst drowns.

CFF also resists symbolic execution (Chapter 18) well: the dispatch variable introduces complex data dependencies that increase the number of paths to explore.

## Bogus Control Flow (BCF)

### The principle

Bogus Control Flow takes a complementary approach to CFF. Instead of reorganizing existing blocks, it **adds fake ones**.

The principle: insert conditional branches whose condition is **always true** (or always false) but whose evaluation is complex enough that a static analyst — human or software — can't easily determine it. The code on the "wrong" side of the branch is dead code (never executed), but it looks like legitimate code.

Let's revisit our function:

```c
int check(int x) {
    int result = 0;
    if (x > 10) {
        result = x * 2;
    } else {
        result = x + 5;
    }
    return result;
}
```

After BCF insertion:

```c
int check_bogus(int x) {
    int result = 0;

    /* Opaque predicate: (y*y) >= 0 is ALWAYS true
     * for any integer y, but the compiler and
     * disassembler don't "see" it easily. */
    volatile int y = x | 1;
    if ((y * y) >= 0) {
        /* True path — always executed */
        if (x > 10) {
            result = x * 2;
        } else {
            result = x + 5;
        }
    } else {
        /* False path — NEVER executed
         * but contains credible code */
        result = x ^ 0xDEAD;
        result = result << 3;
        if (result > 100)
            result = result - 42;
    }

    return result;
}
```

### Opaque predicates

The core of BCF relies on **opaque predicates**: boolean expressions whose value is constant (always true or always false) but whose proof of constancy is mathematically difficult.

Classic opaque predicates exploit number theory properties:

- `(x * (x + 1)) % 2 == 0` — The product of two consecutive integers is always even. Always true.  
- `(x² ≥ 0)` — The square of an integer is always positive or zero. Always true (ignoring signed overflow, which the compiler can't assume).  
- `(x³ - x) % 3 == 0` — By Fermat's little theorem. Always true.  
- `(2 * x + 1) % 2 == 1` — An odd number stays odd. Always true.

An experienced human analyst can recognize these patterns. But an automatic static analysis tool must formally prove the expression is constant, which is generally an undecidable problem in the general case (reducible to the halting problem for sufficiently complex predicates).

More sophisticated implementations use global variables modified in other functions to make the predicate even more opaque to inter-procedural analysis.

### Impact on analysis

BCF doubles or triples the number of basic blocks in the CFG. The analyst sees branches that must be evaluated one by one: is this `if` real or fake? The decompiler, unable to solve the opaque predicate, displays both paths as if they were both possible.

Combined with CFF, the result is devastating: a flattened function where half the switch cases contain dead code, and transitions between cases pass through opaque predicates. The control graph becomes a tangle of nodes where the signal (real code) is drowned in noise (fake code).

## CFF + BCF combined: recognizing the global pattern

On a binary encountered "in the wild" (malware, protected software, CTF challenge), the two techniques are almost always combined. Here are the visual and technical signatures to recognize them.

### In the Function Graph (Ghidra / IDA / Cutter)

- **Star shape** — A massive central node (the dispatcher) connected to many blocks. This is CFF.  
- **Duplicated or near-identical blocks** — Blocks that do almost the same thing, some of which are never reached. This is BCF.  
- **Abnormal branch density** — The ratio (number of branches) / (number of useful instructions) is much higher than in normal code.  
- **Dispatch variable** — A local variable (often an integer) that is read and written in every block and controls a central `cmp`/`je` or `switch`.

### In the decompiler

- A `while(1)` or `do { ... } while(true)` encompassing all function logic  
- A giant `switch` or cascade of `if/else if` on the same variable  
- Dead code blocks the decompiler couldn't eliminate  
- Complex conditional expressions involving arithmetic operations unrelated to business logic (opaque predicates)

### In binary metrics

- **Number of basic blocks per function** abnormally high. A 30-line C function producing 80 basic blocks was probably obfuscated.  
- **Cyclomatic complexity** very high. Cyclomatic complexity measures the number of linearly independent paths in the CFG. CFF makes it explode.  
- **Binary size** — Obfuscation significantly increases code size (×2 to ×5 depending on aggressiveness).

## Bypass strategies

Control flow obfuscation is significantly harder to bypass than stripping or packing. There's no equivalent of `upx -d` to automatically "de-flatten" a binary. The following approaches are complementary.

### Dynamic analysis: bypass rather than understand

Facing a heavily obfuscated function, the first question is: *do I really need to understand its internal structure?*

Often, the answer is no. If the goal is to understand what a function does (not how it does it), dynamic analysis short-circuits the obfuscation:

- **Frida** (Chapter 13) — Hook the function's entry and exit, observe arguments and return value. It doesn't matter that the internal flow is a labyrinth if you know `f(42)` returns `1` and `f(0)` returns `0`.  
- **GDB** — Set a breakpoint at entry, execute with different inputs, observe results. Obfuscated code executes exactly like the original.  
- **Symbolic execution** (Chapter 18) — angr can explore paths through the dispatcher and solve constraints, though path explosion is a risk on heavily flattened functions.  
- **Execution tracing** — Stalker (Frida) or `strace`/`ltrace` to observe behavior without reading code.

### Dispatch variable analysis

If structural understanding is necessary, the CFF key is the dispatch variable. It's the technique's Achilles' heel.

1. **Identify the variable** — In the decompiler, spot the integer variable read at the beginning of each main loop iteration and written at the end of each block.  
2. **Trace the values** — For each switch case, note the value assigned to the dispatch variable at the block's end. This gives the actual transitions between blocks.  
3. **Reconstruct the graph** — Draw a graph where each case is a node and transitions (dispatch values) are edges. This graph is the original CFG, unfolded.

This approach is tedious but reliable. It's essentially what automatic de-obfuscation tools do, formalized.

### Opaque predicate elimination

For BCF, the goal is identifying fake branches:

- **Pattern matching** — Recognize classic opaque predicates (`x*(x+1) % 2`, `x² >= 0`) in the decompiler. With experience, they become recognizable.  
- **Concrete execution** — Execute the function with multiple input values and trace which blocks are actually reached. Blocks that never execute, regardless of input, are dead code.  
- **Symbolic simplification** — Tools like Miasm or Triton can simplify expressions and prove a predicate is constant.

### Specialized de-obfuscation tools

Several research projects and open-source tools specifically target CFF:

- **D-810** — IDA plugin that detects and removes CFF produced by O-LLVM (Section 19.4).  
- **SATURN** (academic research) — Symbolic execution approach to reconstruct the original CFG.  
- **Custom Ghidra/IDA scripts** — Dispatch variable analysis can be scripted. A Python script in Ghidra can identify switch blocks, trace transitions, and produce a simplified graph.  
- **Miasm** — Binary analysis framework that lifts code to intermediate representation, simplifies expressions, and re-emits de-obfuscated code.

These tools have limitations and don't work universally. Obfuscation being a race between attacker and defender, each new generation of tools is followed by new obfuscation techniques that resist them.

### The pragmatic approach

In practice, facing a CFF + BCF obfuscated binary, the experienced analyst combines approaches:

1. **Triage** — Identify CFF/BCF presence (star shape in graph, giant switch in decompiler).  
2. **Dynamic analysis first** — Understand function behavior through observation before diving into the code.  
3. **Target** — Only manually de-obfuscate critical functions (the verification routine, decryption, parsing). Ignore auxiliary functions.  
4. **Automate** — If multiple functions follow the same obfuscation pattern (same tool, same parameters), write a script to automate reconstruction.

Control flow obfuscation is a time multiplier, not an insurmountable wall. It transforms a 30-minute analysis into a multi-hour one — but it doesn't make code incomprehensible for a determined and well-equipped analyst.

---


⏭️ [LLVM-based obfuscation (Hikari, O-LLVM) — recognizing patterns](/19-anti-reversing/04-llvm-obfuscation.md)
