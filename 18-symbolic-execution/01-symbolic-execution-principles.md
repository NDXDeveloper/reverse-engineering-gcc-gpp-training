🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 18.1 — Symbolic execution principles: treating inputs as symbols

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## The problem with concrete execution

Let's return for a moment to what you've been doing since the beginning of this training when dynamically analyzing a binary. With GDB (Chapter 11), you launch the program with a **concrete input** — for example `./keygenme AAAA1111BBBB2222` — and observe what happens: which registers take which values, which branch is taken, where the program decides to reject your input.

This approach works, but it has a fundamental limitation: **you explore only one path at a time**. If your input fails at the first `if`, you have no information about what would happen if that `if` were satisfied. You must then modify your input, relaunch, observe again, and so on. It's an essentially manual process, guided by your intuition and understanding of the code.

Consider a concrete case. Here's a simplified fragment of our keygenme's verification logic:

```c
uint32_t high = parse_hex(serial, 0, 8);  
uint32_t low  = parse_hex(serial, 8, 8);  

feistel4(&high, &low);

if (high == 0xA11C3514 && low == 0xF00DCAFE) {
    puts("Access Granted!");
} else {
    puts("Access Denied.");
}
```

To find the correct serial by concrete execution, you would theoretically need to try all 2⁶⁴ possible input combinations over 16 hexadecimal characters. Even at a billion attempts per second, that would take about 585 years. Bruteforce is not an option.

Symbolic execution proposes a radically different approach.

---

## The central idea: symbols instead of values

Instead of saying "`high` equals `0x41414141`" (the concrete value corresponding to `"AAAA"`), symbolic execution says:

> "`high` equals **α**, where **α** is an unsigned 32-bit integer whose value is not yet known."

Similarly, `low` becomes **β**. These two unknowns are **symbolic variables** — exactly like the *x* and *y* variables you manipulated in high school algebra.

From there, the symbolic execution engine no longer computes numerical results: it builds **symbolic expressions**. When the program executes `high ^= 0x5A3CE7F1`, the engine doesn't produce a number, it produces the expression **α ⊕ 0x5A3CE7F1**. When the program then executes a shift and a multiplication, the expression grows more complex, but it remains a formula in terms of **α** and **β**.

This simple idea has profound consequences: at the end of execution, the engine doesn't have "an answer," it has **a system of equations** describing all transformations applied to the inputs.

---

## Step-by-step symbolic execution

Let's take an intentionally minimalist example to understand the mechanism. Forget the keygenme for a moment and consider this function:

```c
int check(int x) {
    int y = x * 3 + 7;
    if (y > 100) {
        if (x % 2 == 0) {
            return 1;  // SUCCESS
        }
        return 0;      // FAIL path A
    }
    return 0;          // FAIL path B
}
```

### Step 1 — Symbolic state initialization

The engine creates an **initial state** where `x` is not a number but a symbol **α** (a signed 32-bit integer).

```
Initial state:
  x = α          (symbolic, signed 32-bit)
  Constraints:  ∅  (no constraints yet)
```

### Step 2 — Executing `y = x * 3 + 7`

The engine evaluates the instruction symbolically:

```
  y = α × 3 + 7
```

It doesn't know `y`'s value, but it knows its **relationship** with `α`.

### Step 3 — The first branch: `if (y > 100)`

This is where symbolic execution fundamentally diverges from concrete execution. Instead of taking **one** side of the branch, the engine explores **both** by creating two distinct states:

```
State A (THEN branch):
  x = α
  y = α × 3 + 7
  Constraints: { α × 3 + 7 > 100 }

State B (ELSE branch):
  x = α
  y = α × 3 + 7
  Constraints: { α × 3 + 7 ≤ 100 }
```

Each state carries with it the **set of constraints** accumulated along its path. This set is called the *path constraint*.

### Step 4 — The second branch: `if (x % 2 == 0)`

State A reaches a new branch and splits again:

```
State A1 (SUCCESS):
  Constraints: { α × 3 + 7 > 100,  α mod 2 = 0 }

State A2 (FAIL path A):
  Constraints: { α × 3 + 7 > 100,  α mod 2 ≠ 0 }
```

State B has reached `return 0` directly and doesn't split further.

### Step 5 — Querying the solver

We now have three constraint sets, one per terminal path. If our goal is to reach `return 1` (SUCCESS), we submit state A1's constraints to an **SMT solver**:

```
Find α ∈ Z₃₂ such that:
  α × 3 + 7 > 100
  α mod 2 = 0
```

The first constraint simplifies to **α > 31**. Combined with the parity, the solver can propose for example **α = 32**. We verify: `32 × 3 + 7 = 103 > 100` ✓, `32 mod 2 = 0` ✓. It's a valid input.

The solver found **the** value (or rather **one** value among those possible) that leads to the desired path, without ever executing the program with a concrete input.

---

## The symbolic execution tree

This bifurcation process at each branch produces a structure called the **Symbolic Execution Tree**. Each internal node corresponds to a conditional branch, and each leaf corresponds to a terminal program path (exit, crash, infinite loop…).

```
                          check(α)
                             │
                        y = α×3 + 7
                             │
                    ┌────────┴────────┐
                    │                 │
              y > 100 ?          y ≤ 100 ?
           (α×3+7 > 100)     (α×3+7 ≤ 100)
                    │                 │
            ┌───────┴──────┐      return 0
            │              │     (FAIL path B)
       α mod 2 = 0   α mod 2 ≠ 0
            │              │
        return 1       return 0
        (SUCCESS)     (FAIL path A)
```

In our two-branch example, the tree has 3 leaves. That's manageable. But imagine a program with 50 successive branches: the tree can theoretically have **2⁵⁰ leaves** (over a quadrillion). This is the path explosion problem, which we'll address in detail in Section 18.5.

---

## Reference vocabulary

Before going further, let's establish the terms you'll encounter in angr's documentation, research papers, and the RE community:

**Symbolic variable** — An unknown representing a program input. In angr, it's created with `claripy.BVS("name", size_in_bits)` — a **symbolic bitvector**. The bit size is crucial: a `uint32_t` is a 32-bit bitvector, a `char` is an 8-bit bitvector.

**Concrete value** — The opposite of a symbolic value: a fixed number, like `0x41` or `42`. In angr, `claripy.BVV(0x41, 8)` creates a **concrete** 8-bit bitvector with value `0x41`.

**Symbolic state** — A snapshot of the entire program context at a given point: registers (some symbolic, others concrete), memory (likewise), and the set of accumulated path constraints. In angr, this is a `SimState` object.

**Path constraint** — The conjunction (logical AND) of all conditions encountered along an execution path. Each branch adds either the condition itself (THEN branch) or its negation (ELSE branch). The solver must satisfy **all** constraints simultaneously.

**SMT solver** (*Satisfiability Modulo Theories*) — A program capable of determining whether a set of constraints on bitvectors, arrays, arithmetic… has a solution, and if so, providing one. **Z3** (Microsoft Research) is the reference SMT solver and the one used internally by angr.

**Satisfiable / Unsatisfiable** — A constraint set is *satisfiable* (SAT) if at least one assignment of symbolic variables makes all constraints true. It's *unsatisfiable* (UNSAT) if no assignment works — meaning the corresponding path is **impossible** (dead path).

**Exploration** — The process by which the symbolic execution engine traverses the path tree, decides which states to advance, and optionally applies strategies to prune useless branches. In angr, it's the `SimulationManager` that orchestrates exploration.

---

## From theory to reverse engineering

Let's place all of this in the context of reverse engineering a binary compiled with GCC.

### We don't have the source code

The previous example started from C code to build the tree. In practice, the symbolic execution engine works directly on the **binary** — on machine instructions, not source code. angr, for example, translates the binary into an intermediate representation (VEX IR, the same IR as Valgrind's) then executes this IR symbolically. This means symbolic execution works without sources, without symbols, and even on stripped and optimized binaries.

### Branches are machine instructions

A C `if` becomes a `cmp` followed by `jz` or `jnz` in x86-64. For the symbolic engine, it's exactly the same thing: the instruction `cmp rax, 0xA11C3514` followed by `jne fail` creates a bifurcation with two mirror constraints:

- THEN branch: the symbolic value in `rax` equals `0xA11C3514`.  
- ELSE branch: the symbolic value in `rax` differs from `0xA11C3514`.

### The objective is defined by addresses

In symbolic execution applied to RE, you don't say "I want to reach `return 1`." You say **"I want to reach address `0x401234`"** (that of `puts("Access Granted!")`) **and avoid address `0x401250`** (that of `puts("Access Denied.")`). The engine explores the tree looking for a path that leads to the target address without passing through the addresses to avoid. Once this path is found, it collects its constraints and queries the solver.

This is exactly what we'll do in Section 18.3 with angr on our keygenme.

### The solver does the reverse work

The essential point is this: you **don't need to understand** the verification routine in detail to solve it. Our keygenme's 4-round Feistel network, with its chained shifts, multiplications, and XORs, produces dense assembly that's difficult to mentally invert. But the symbolic engine simply **propagates** the expressions through each instruction, and the SMT solver resolves the resulting equation system. Where the human analyst would have to invert the `mix32` function then each Feistel round by reasoning backwards, the solver explores the solution space in seconds.

This is what makes symbolic execution such a powerful reverse engineering tool: it **short-circuits understanding** of the code. You only need to know *where* the success condition is, not *how* it works.

---

## Symbolic, concolic, and DSE execution

Several variants of symbolic execution exist. It's useful to distinguish them as you'll encounter them in the literature and in some tools' options.

### Pure symbolic execution (Static Symbolic Execution)

This is what we've described so far: all inputs are symbolic from the start, and the engine explores the path tree exhaustively. It's the most powerful approach in theory, but also the most prone to path explosion.

### Concolic execution

The term "concolic" is a portmanteau of **conc**rete and symb**olic**. The idea is to combine both: you launch the program with a **concrete input** (for example, a random serial) and record the path taken. In parallel, you maintain symbolic constraints along this path. Then, you **negate** one of the constraints to force exploration of an alternative path, and relaunch with the new concrete input produced by the solver.

The advantage is that concrete execution naturally resolves environment interactions (system calls, libraries) where purely symbolic execution would need to model them. The disadvantage is that exploration is less systematic.

The historical reference tool for concolic execution is **SAGE** (Microsoft), used internally for fuzzing Windows software. **KLEE** (LLVM-based) is another major academic tool combining both approaches.

### Dynamic Symbolic Execution (DSE)

This is the generic term encompassing both previous approaches when they operate on a running (or simulated) program. angr does DSE: it simulates binary execution in its own engine (SimEngine) while maintaining symbolic state. It can switch between concrete and symbolic execution as needed, giving it great flexibility.

---

## What the SMT solver can solve

The SMT solver working behind the scenes (Z3, in angr's case via the `claripy` library) can reason about:

- **Bitvector arithmetic**: addition, subtraction, multiplication, division, modulo — all on fixed-size integers (8, 16, 32, 64 bits), with overflow handling exactly as the processor does.  
- **Bitwise operations**: AND, OR, XOR, NOT, logical and arithmetic shifts, rotations.  
- **Comparisons**: equality, inequality, greater/less than (signed and unsigned).  
- **Arrays** (array theory): reading and writing at symbolic indices in an array, which models memory accesses with symbolic pointers.  
- **Bit concatenation and extraction**: taking the low 8 bits of a 32-bit bitvector, concatenating two 32-bit bitvectors into a 64-bit one, etc.

This is precisely the set of operations found in a compiled program. Each x86-64 instruction translates to one or more bitvector operations, and the solver knows how to resolve them.

However, the solver **cannot** efficiently reason about cryptographic hash functions designed to be one-way (SHA-256, etc.), nor about complex floating-point arithmetic (though Z3 has partial float support). These are cases where symbolic execution reaches its limits, which we'll detail in Section 18.5.

---

## Visual summary of the process

To solidify the concepts, here's the complete symbolic execution flow applied to RE of a binary:

```
  ┌──────────────────┐
  │  ELF Binary      │    Input: the file compiled by GCC
  │  (keygenme_O2)   │
  └────────┬─────────┘
           │
           ▼
  ┌───────────────────────┐
  │  Loading (Loader)     │    The engine loads the binary, resolves
  │  + Translation to IR  │    imports, translates machine code to IR
  └────────┬──────────────┘
           │
           ▼
  ┌───────────────────────────┐
  │  Create the initial       │    Inputs (argv, stdin...) are
  │  symbolic state           │    replaced by symbolic variables
  └────────┬──────────────────┘
           │
           ▼
  ┌───────────────────────────┐
  │  Explore the path tree    │    The engine executes symbolically,
  │                           │    forks at each branch,
  │  (SimulationManager)      │    accumulates constraints
  └────────┬──────────────────┘
           │
           ▼
  ┌───────────────────────────┐
  │  Target path reached?     │──── No ──→ Continue exploration
  │  ("find" address)         │             or declare failure
  └────────┬──────────────────┘
           │ Yes
           ▼
  ┌───────────────────────────┐
  │  Resolve path             │    The SMT solver (Z3) looks for an
  │  constraints              │    assignment of symbolic variables
  └────────┬──────────────────┘    satisfying ALL constraints
           │
           ▼
  ┌───────────────────────────┐
  │  Concrete solution        │    → The valid serial, for example
  │  (input values)           │      "4F2A8B1D73E590C6"
  └───────────────────────────┘
```

---

## Key points to remember

- Symbolic execution replaces inputs with **mathematical variables** and propagates **expressions** instead of computing values.

- At each conditional branch, execution **splits**: one path adds the condition as a constraint, the other adds its negation.

- An **SMT solver** (Z3) determines whether concrete values exist satisfying all constraints for a given path.

- In RE, you define an objective by an **address to reach** and **addresses to avoid**, without needing to understand the detail of the intermediate logic.

- Symbolic execution operates on the **binary** directly, not on source code. It therefore works on stripped, optimized, symbolless binaries.

- **Path explosion** is the technique's main enemy: each branch potentially doubles the number of states to explore.

---

> In the next section (18.2), we'll move from theory to practice by installing **angr** and exploring its architecture: `SimState`, `SimulationManager`, exploration strategies, and the `claripy` library for manipulating symbolic bitvectors.

⏭️ [angr — installation and architecture (SimState, SimManager, exploration)](/18-symbolic-execution/02-angr-installation-architecture.md)
