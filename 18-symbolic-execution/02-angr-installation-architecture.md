🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 18.2 — angr — installation and architecture (SimState, SimManager, exploration)

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## What is angr?

angr is a binary analysis framework developed by the **SecLab** laboratory at UC Santa Barbara (UCSB). Written in Python, it offers a coherent set of tools to load a binary, disassemble it, build its control flow graph, and above all execute it symbolically — all from a Python script or interactive shell.

angr was born in the CTF (Capture The Flag) world, where it became the weapon of choice for automatically solving crackmes and reverse engineering challenges. But its applications go well beyond competitions: vulnerability analysis, security property verification, automatic code exploration, fuzzing guided by symbolic execution…

What distinguishes angr from other symbolic execution tools (KLEE, Manticore, Triton) is its ability to work directly on **compiled binaries** — not on source code, not on LLVM bytecode — and its flexibility of use via a rich, well-documented Python API.

---

## Installation

### Prerequisites

angr requires Python **3.10 or higher**. Installation in a **dedicated virtual environment** is nearly mandatory: angr bundles dozens of dependencies (including its own forks of some libraries) that can conflict with other Python packages on your system.

### Installation in a virtualenv

```bash
# Create a dedicated virtual environment
python3 -m venv ~/angr-env

# Activate it
source ~/angr-env/bin/activate

# Install angr (pulls all dependencies automatically)
pip install angr

# Verify the installation
python3 -c "import angr; print(angr.__version__)"
```

Installation can take several minutes: angr compiles some C dependencies (notably `unicorn`, the CPU emulation engine, and `z3-solver`). On a modest machine, expect 5 to 10 minutes.

### Notable dependencies installed automatically

angr is not a monolithic tool — it's an ecosystem of libraries developed by the same team. Understanding these building blocks will help you navigate the documentation and error messages:

| Library | Role |  
|---|---|  
| **CLE** (*CLE Loads Everything*) | Binary loader. Reads ELF, PE, Mach-O formats, shared libraries, handles memory mapping and import resolution. Conceptual equivalent of the Linux loader (`ld.so`) seen in Chapter 2. |  
| **archinfo** | Database of supported architectures (x86, x86-64, ARM, MIPS, PPC…). Defines registers, word sizes, calling conventions. |  
| **pyvex** | Machine code to **VEX** IR (Intermediate Representation) translator, the same intermediate representation used by Valgrind (Chapter 14). Each x86-64 instruction is decomposed into VEX micro-operations. |  
| **claripy** | Library for manipulating symbolic and concrete bitvectors. Python interface to the Z3 solver. This is the layer that creates symbolic variables, builds expressions, and queries the solver. |  
| **SimEngine** | Execution engine: interprets VEX instructions by propagating values (symbolic or concrete) through registers and memory. |  
| **unicorn** | CPU emulation engine (optional). Used to accelerate execution of purely concrete code portions (without symbolic values). |

### Quick verification

Open a Python shell in your virtualenv and test loading the keygenme:

```python
import angr

# Load the binary
proj = angr.Project("./keygenme_O0", auto_load_libs=False)

# Basic information
print(f"Architecture : {proj.arch.name}")  
print(f"Entry point  : {hex(proj.entry)}")  
print(f"Binary name  : {proj.filename}")  
```

If you see `Architecture : AMD64` and an entry point address without errors, the installation is functional.

> 💡 **`auto_load_libs=False`** — This parameter tells CLE to **not** load shared libraries (libc, ld-linux, etc.). This is almost always what you want in symbolic execution: loading libc would introduce thousands of additional functions to explore, causing the path space to explode. angr replaces library functions with **SimProcedures** — simplified Python models that simulate standard function behavior (`strlen`, `strcmp`, `printf`, `malloc`…) without executing their actual machine code.

---

## angr architecture: overview

Here's how the different building blocks fit together when you use angr to solve a crackme:

```
  Your Python script
         │
         ▼
  ┌─────────────────────────────────────────────────────┐
  │                    angr.Project                     │
  │                                                     │
  │   ┌──────────┐    ┌──────────┐     ┌──────────────┐ │
  │   │   CLE    │    │ archinfo │     │   pyvex      │ │
  │   │ (loader) │    │ (arch)   │     │ (x86→VEX IR) │ │
  │   └────┬─────┘    └──────────┘     └──────┬───────┘ │
  │        │                                  │         │
  │        ▼                                  ▼         │
  │   Mapped memory                  VEX IR instructions│
  │                                          │          │
  │                    ┌─────────────────────┐          │
  │                    │     SimEngine       │          │
  │                    │ (symb. execution)   │          │
  │                    └────────┬────────────┘          │
  │                             │                       │
  │              ┌──────────────┼───────────────┐       │
  │              ▼              ▼               ▼       │
  │        ┌──────────┐   ┌──────────┐    ┌──────────┐  │
  │        │ SimState │   │ SimState │    │ SimState │  │
  │        │ (path1)  │   │ (path2)  │    │ (path3)  │  │
  │        └────┬─────┘   └────┬─────┘    └────┬─────┘  │
  │             │              │               │        │
  │             └──────────────┼───────────────┘        │
  │                            ▼                        │
  │                  ┌──────────────────┐               │
  │                  │SimulationManager │               │
  │                  │ (orchestrator)   │               │
  │                  └────────┬─────────┘               │
  │                           │                         │
  │                           ▼                         │
  │                     ┌──────────┐                    │
  │                     │ claripy  │                    │
  │                     │ (Z3)     │                    │
  │                     └──────────┘                    │
  └─────────────────────────────────────────────────────┘
```

Let's detail the three central components you'll manipulate in every angr script.

---

## The Project: entry point for all analysis

Everything begins with creating a `Project` object. It's the equivalent of "opening a binary in Ghidra" — the binary is loaded, parsed, and ready to be analyzed.

```python
import angr

proj = angr.Project("./keygenme_O0", auto_load_libs=False)
```

The `Project` gives access to:

- **`proj.loader`** — The CLE object that loaded the binary. You can inspect segments, sections, imported and exported symbols, and linked libraries.  
- **`proj.arch`** — The detected architecture. Contains information about registers (`proj.arch.registers`), pointer sizes, endianness, etc.  
- **`proj.entry`** — The entry point address (`_start`), not that of `main`.  
- **`proj.factory`** — The *factory* that creates states, basic blocks, call graphs, and `SimulationManager`s.

### Finding the address of `main`

If the binary contains symbols (compiled with `-g`, not stripped), angr can resolve `main` directly:

```python
main_addr = proj.loader.find_symbol("main").rebased_addr  
print(f"main() is at address: {hex(main_addr)}")  
```

If the binary is stripped, you'll need to find `main`'s address by other means — for example by spotting it in Ghidra (Chapter 8) or with `objdump` (Chapter 7), then passing it manually to angr.

---

## The SimState: a program snapshot

A `SimState` (simulation state) represents the program's **complete state** at a given moment: the values of all registers, memory contents, open file descriptors, and especially the set of **constraints** accumulated on symbolic variables.

### Creating an initial state

```python
# State starting at the binary's entry point
state = proj.factory.entry_state()

# State starting at a specific address (e.g., main)
state = proj.factory.blank_state(addr=0x401156)
```

**`entry_state()`** creates a state simulating the program's complete startup (passing through `_start`, libc initialization, then call to `main`). It's the most realistic but also the slowest.

**`blank_state(addr=...)`** creates an "empty" state positioned at an arbitrary address, with stack and registers initialized to unconstrained symbolic values. It's faster but may require manual setup (initializing arguments, memory…).

### Inspecting a state

A state's registers and memory can contain symbolic or concrete values:

```python
# Read the rip register value (64 bits)
print(state.regs.rip)           # <BV64 0x401156>  (concrete)

# Read 4 bytes from memory at a given address
val = state.memory.load(0x404000, 4, endness=proj.arch.memory_endness)  
print(val)                       # May be symbolic or concrete  
```

### Accessing the solver

Each state embeds its own **solver** via `state.solver`. This is the interface to claripy and Z3:

```python
# Create a 64-bit symbolic bitvector
x = state.solver.BVS("x", 64)

# Add a constraint
state.solver.add(x > 0x1000)  
state.solver.add(x < 0x2000)  

# Ask for a concrete solution
solution = state.solver.eval(x)  
print(f"Solution: {hex(solution)}")  

# Check if constraints are satisfiable
print(state.solver.satisfiable())  # True or False
```

This mechanism is at the heart of symbolic execution: each conditional branch adds constraints to the state's solver, and at the end we ask the solver to produce a concrete value for the inputs.

---

## The SimulationManager: orchestrating exploration

The `SimulationManager` (often abbreviated `simgr`) is the conductor of symbolic execution. It manages a collection of states and advances them through the binary, handling bifurcations, filtering, and exploration strategies.

### Creation

```python
simgr = proj.factory.simgr(state)
```

### Stashes: categorizing states

The `SimulationManager` organizes states into named **stashes**. Each stash is a simple Python list of `SimState` objects:

| Stash | Contents |  
|---|---|  
| **`active`** | States being explored. At each `.step()` call, these states advance by one basic block. |  
| **`found`** | States that reached a **target address** (defined by you). This is what you're interested in. |  
| **`avoided`** | States that reached an **address to avoid** (e.g., `"Access Denied."`). They're removed from exploration. |  
| **`deadended`** | States that terminated normally (`exit` call, end of `main`…). |  
| **`errored`** | States that caused an internal angr error (unsupported instruction, impossible memory access…). |  
| **`unsat`** | States whose constraints became unsatisfiable (impossible path). |

You can inspect stashes at any time:

```python
print(f"Active states: {len(simgr.active)}")  
print(f"Found states: {len(simgr.found)}")  
print(f"Avoided states: {len(simgr.avoided)}")  
```

### Advancing exploration

The `.step()` method advances **all** active states by one basic block. At each conditional branch, a state splits into two (or more) new states, each with updated constraints:

```python
# One exploration step
simgr.step()

# The initial state may have split
print(f"Active states after one step: {len(simgr.active)}")
```

Calling `.step()` manually in a loop would be tedious. The `.explore()` method automates the process with stopping criteria.

---

## The `.explore()` method: the workflow core

The `explore()` method is the one you'll use most often. It advances exploration automatically until a state reaches a target address or all paths are exhausted:

```python
simgr.explore(
    find=0x40125A,     # Address of puts("Access Granted!")
    avoid=0x40126E     # Address of puts("Access Denied.")
)
```

### What does `explore()` do internally?

At each iteration:

1. Each state in the `active` stash advances by one basic block.  
2. If a state reaches the `find` address, it's moved to the `found` stash.  
3. If a state reaches an `avoid` address, it's moved to the `avoided` stash and **is no longer explored** — this pruning considerably reduces the search space.  
4. If a state reaches an `exit` or an impossible path, it's moved to `deadended` or `unsat`.  
5. Exploration continues as long as the `active` stash isn't empty and `found` hasn't received a state.

### Using functions as criteria

Instead of numeric addresses, you can pass **Python functions** that receive a state and return `True`/`False`. This is more readable and flexible:

```python
simgr.explore(
    find=lambda s: b"Access Granted" in s.posix.dumps(1),
    avoid=lambda s: b"Access Denied" in s.posix.dumps(1)
)
```

Here, `s.posix.dumps(1)` returns everything the state has written to **stdout** (file descriptor 1). We simply check if the success message appears in the output. This approach has the advantage of working even on a stripped binary where exact addresses are unknown — you only need to know the displayed strings.

### Extracting the solution

Once a state is in `found`, you can query its solver to get concrete values for the symbolic inputs:

```python
if simgr.found:
    found_state = simgr.found[0]

    # If the input is argv[1]
    serial = found_state.solver.eval(argv1_symbolic, cast_to=bytes)
    print(f"Valid serial: {serial}")
else:
    print("No solution found.")
```

We'll see the complete code in Section 18.3.

---

## claripy: manipulating bitvectors

claripy is the library underpinning all symbolic manipulation in angr. You'll use it directly when you want to create symbolic variables, set constraints manually, or build expressions.

### Symbolic and concrete bitvectors

```python
import claripy

# Symbolic bitvector: 64 bits, named "serial"
serial_sym = claripy.BVS("serial", 64)

# Concrete bitvector: 64 bits, value 0xDEADBEEF
magic = claripy.BVV(0xDEADBEEF, 64)
```

The `S` in `BVS` stands for *Symbolic*, the `V` in `BVV` stands for *Value* (concrete).

### Operations on bitvectors

Bitvectors support all operations the processor performs — these are the same operations Z3 knows how to solve:

```python
a = claripy.BVS("a", 32)  
b = claripy.BVS("b", 32)  

# Arithmetic
expr1 = a + b  
expr2 = a * 3 + 7  
expr3 = a - claripy.BVV(100, 32)  

# Bitwise
expr4 = a ^ b  
expr5 = a >> 16          # Logical right shift  
expr6 = a & 0xFF         # Mask low 8 bits  

# Comparisons (return boolean expressions)
cond1 = a > b            # Unsigned by default  
cond2 = claripy.SGT(a, b)  # Signed (Signed Greater Than)  
cond3 = a == claripy.BVV(0x1337, 32)  

# Concatenation and extraction
full = claripy.Concat(a, b)           # 64 bits (a || b)  
low_byte = claripy.Extract(7, 0, a)   # Low 8 bits of a  
```

### Constraining characters

A frequent RE use case: constraining inputs to be printable ASCII characters (or hexadecimal, as in our keygenme):

```python
# Create a symbolic 8-bit character
c = claripy.BVS("c", 8)

# Constrain to hexadecimal character [0-9A-Fa-f]
is_digit   = claripy.And(c >= ord('0'), c <= ord('9'))  
is_upper   = claripy.And(c >= ord('A'), c <= ord('F'))  
is_lower   = claripy.And(c >= ord('a'), c <= ord('f'))  
is_hex     = claripy.Or(is_digit, is_upper, is_lower)  
```

Adding these input constraints **before** launching exploration drastically reduces the search space and accelerates resolution.

---

## SimProcedures: simulating libc

When angr encounters a call to `strlen`, `strcmp`, `printf`, or any other standard library function, it doesn't actually execute it (that would be far too complex symbolically). Instead, it uses **SimProcedures** — simplified Python implementations of these functions that know how to reason about symbolic arguments.

For example, the SimProcedure for `strlen` knows that if passed a pointer to a buffer containing symbolic bytes, the result depends on the position of the first null byte — and it encodes this relationship as a constraint.

angr provides SimProcedures for several hundred standard functions. You can list them:

```python
# See which functions are hooked by SimProcedures
for name, simproc in proj._sim_procedures.items():
    print(f"  {name} → {simproc.__class__.__name__}")
```

You can also write your own SimProcedures to replace custom functions from the binary. This is a powerful tool when a function causes problems for symbolic execution (too complex, too many paths, unsupported system call):

```python
class MySkipFunction(angr.SimProcedure):
    """Replaces a function by always returning 0."""
    def run(self):
        return 0

# Hook the function at address 0x401000
proj.hook(0x401000, MySkipFunction())
```

We'll see concrete use cases for hooks in Section 18.3.

---

## Exploration strategies

By default, `explore()` uses a **BFS** (Breadth-First Search) strategy: all active states advance one step at each iteration. This strategy is fair but can be slow if many paths diverge.

angr offers other strategies via the `SimulationManager`'s `techniques` parameter:

```python
# DFS: explores one path in depth before moving to the next
simgr = proj.factory.simgr(state)  
simgr.use_technique(angr.exploration_techniques.DFS())  
simgr.explore(find=target, avoid=bad)  
```

The most useful exploration techniques:

| Technique | Behavior | When to use |  
|---|---|---|  
| **BFS** (default) | Advances all states in parallel, level by level. | Good default choice, fair exploration. |  
| **DFS** | Explores a single path to the end before backtracking. | When the solution is "deep" but has few branches. |  
| **LengthLimiter** | Limits the maximum number of basic blocks a state can traverse. | Prevents infinite loops from blocking exploration. |  
| **LoopSeer** | Detects loops and limits the number of allowed iterations. | Essential as soon as the binary contains loops. |  
| **Veritesting** | Merges paths that reconverge (*merging*), reducing the number of states. | Reduces path explosion in certain cases. |

You can combine multiple techniques:

```python
simgr.use_technique(angr.exploration_techniques.DFS())  
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))  
```

The choice of exploration strategy is often the determining factor between a 10-second resolution and a timeout after 30 minutes. We'll revisit this in Section 18.5 on symbolic execution limits.

---

## Passing arguments to the program

Our keygenme expects a command-line argument (`argv[1]`). You need to tell angr that this argument is **symbolic**. Here's how:

```python
import angr  
import claripy  

proj = angr.Project("./keygenme_O0", auto_load_libs=False)

# Create a 16-byte symbolic bitvector (16 hex chars × 8 bits)
serial_len = 16  
serial_chars = [claripy.BVS(f"c{i}", 8) for i in range(serial_len)]  
serial_bvs = claripy.Concat(*serial_chars)  

# Build argv: [program_name, symbolic_serial]
# angr expects arguments as claripy objects
state = proj.factory.entry_state(
    args=["./keygenme_O0", serial_bvs]
)

# Constrain each character to be hexadecimal
for c in serial_chars:
    is_digit = claripy.And(c >= ord('0'), c <= ord('9'))
    is_upper = claripy.And(c >= ord('A'), c <= ord('F'))
    is_lower = claripy.And(c >= ord('a'), c <= ord('f'))
    state.solver.add(claripy.Or(is_digit, is_upper, is_lower))
```

This pattern — creating individual symbolic characters, concatenating them, constraining them, then passing them as an argument — is the most common pattern in CTF and RE with angr. You'll find it virtually identical in every solving script.

---

## Essential API summary

Here are the calls you'll use in 90% of your angr scripts:

```python
import angr  
import claripy  

# 1. Load the binary
proj = angr.Project("./binary", auto_load_libs=False)

# 2. Create symbolic inputs
sym_input = claripy.BVS("input", N_BITS)

# 3. Create an initial state
state = proj.factory.entry_state(args=[...])
# or
state = proj.factory.blank_state(addr=ADDR)

# 4. Add constraints on inputs
state.solver.add(CONSTRAINT)

# 5. Create the SimulationManager
simgr = proj.factory.simgr(state)

# 6. Explore
simgr.explore(find=ADDR_SUCCESS, avoid=ADDR_FAIL)

# 7. Extract the solution
if simgr.found:
    s = simgr.found[0]
    solution = s.solver.eval(sym_input, cast_to=bytes)
    print(solution)
```

These seven steps constitute the skeleton of every symbolic execution script with angr. Section 18.3 will put them into practice on our keygenme, from start to finish.

---

## Key points to remember

- angr is a **Python framework** that loads, disassembles, and symbolically executes compiled binaries, without access to source code.

- The **Project** loads the binary via CLE and gives access to all analyses.

- A **SimState** represents the program's complete state (registers, memory, constraints) at a given execution point.

- The **SimulationManager** orchestrates exploration by managing state stashes (`active`, `found`, `avoided`, `deadended`…).

- **claripy** is the symbolic bitvector library: `BVS` for symbols, `BVV` for concrete values, arithmetic and bitwise operations, constraints.

- **SimProcedures** replace library functions (libc) with Python models capable of symbolic reasoning.

- **`auto_load_libs=False`** is nearly mandatory to prevent path explosion from loading the complete libc.

- The choice of **exploration strategy** (BFS, DFS, LoopSeer…) can make the difference between a fast resolution and a timeout.

---

> In the next section (18.3), we'll assemble all these building blocks to **automatically solve the keygenme**: from loading the binary to extracting the valid serial, in about twenty lines of Python.

⏭️ [Automatically solving a crackme with angr](/18-symbolic-execution/03-solving-crackme-angr.md)
