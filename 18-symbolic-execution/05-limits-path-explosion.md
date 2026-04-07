🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 18.5 — Limits: path explosion, loops, system calls

> **Chapter 18 — Symbolic execution and constraint solvers**  
> Part IV — Advanced RE Techniques

---

## Symbolic execution is not magic

The previous sections showed the power of symbolic execution: solving a crackme in a few lines of Python, without understanding the program's logic. But this power comes at a price. Symbolic execution hits fundamental limits — not implementation bugs a future angr version will fix, but theoretical obstacles inherent to the approach itself.

Understanding these limits is essential for two reasons. First, it will save you from spending hours waiting for an angr script to finish when it never will. Second, it will guide you toward the right strategy: knowing when symbolic execution is the right tool, when to combine it with other techniques, and when to abandon it in favor of a purely manual approach.

---

## Limit #1 — Path explosion

This is symbolic execution's main enemy and the reason it can't "solve everything automatically."

### The problem

Each conditional branch whose condition depends on a symbolic value **doubles** the number of active states. With *n* successive branches, the number of states can reach **2ⁿ**. A realistic program contains hundreds, even thousands of branches.

Take a concrete example. Imagine a function that validates a password character by character:

```c
int check_password(const char *input) {
    if (input[0] != 'S') return 0;
    if (input[1] != 'e') return 0;
    if (input[2] != 'c') return 0;
    if (input[3] != 'r') return 0;
    if (input[4] != 'e') return 0;
    if (input[5] != 't') return 0;
    if (input[6] != '!') return 0;
    return 1;
}
```

Seven branches, 2⁷ = 128 theoretical paths. Here it's manageable. But consider more realistic validation iterating over a 64-character string with transformation operations at each iteration — the number of paths explodes well beyond what a computer can explore.

### Why it explodes in practice

The problem isn't just the number of branches in the target function. It's the **total** number of branches on the execution path, including:

- libc initialization code (`__libc_start_main`, constructors).  
- SimProcedures modeling library functions — even simplified, they contain internal branches.  
- Functions called by the target function (format checking, memory allocation…).  
- Implicit branches added by compiler optimizations (vectorization branches, loop size tests…).

A program that seems simple in C can produce an execution tree of several million nodes once compiled and simulated in angr.

### Symptoms

You'll recognize path explosion by these signs:

- The number of states in `simgr.active` grows indefinitely (hundreds, then thousands, then tens of thousands).  
- Memory consumption climbs continuously (each state carries its own registers, memory, and constraints).  
- The script has been running for several minutes without `simgr.found` receiving a state.  
- Z3 solver calls become increasingly slow as accumulated constraints grow more complex.

### Mitigation strategies

**Prune with `avoid`** — Each address in the `avoid` list immediately removes all states reaching it. The more avoid addresses you provide, the earlier you prune the tree. In practice, identify not only the final failure message but also early returns (the `return 0` in the middle of the function):

```python
simgr.explore(
    find=addr_success,
    avoid=[
        addr_fail_strlen,      # return 0 if wrong length
        addr_fail_format,      # return 0 if invalid character
        addr_fail_compare,     # return 0 if comparison fails
        addr_fail_final        # puts("Access Denied.")
    ]
)
```

**Constrain inputs** — The more symbolic variables are constrained, the fewer paths the solver allows. Constraining each character to be a hexadecimal digit eliminates 94% of the ASCII space at each branch depending on a character's value.

**Start later** — Instead of starting from `_start` or `main`, start at the verification function's entry with `blank_state` (as seen in Section 18.3). You eliminate all branches from initialization and argument parsing code.

**Limit depth** — `LengthLimiter` stops states that have traversed too many basic blocks:

```python
simgr.use_technique(angr.exploration_techniques.LengthLimiter(
    max_length=2000
))
```

**Merge states (Veritesting)** — When two paths diverge then reconverge (a very common pattern with `if/else`), Veritesting can merge them into a single state with conditional constraints, reducing the total state count:

```python
simgr.use_technique(angr.exploration_techniques.Veritesting())
```

Veritesting doesn't work in all cases and can sometimes slow exploration instead of accelerating it. It's a tool to try empirically.

---

## Limit #2 — Loops depending on symbolic inputs

### The problem

Consider this loop:

```c
int count = 0;  
for (int i = 0; i < input_length; i++) {  
    if (input[i] == 'X')
        count++;
}
if (count == 3)
    success();
```

If `input_length` is a **concrete** value (say 16), the loop unrolls 16 times and each iteration adds a branch (the `if`). This is manageable — 2¹⁶ = 65,536 paths maximum.

But if `input_length` is **symbolic** (the engine doesn't know how many times to iterate), angr can't determine when to stop unrolling. It can theoretically unroll the loop indefinitely, creating new states at each iteration.

Even with a concrete bound, loops remain problematic if they contain branches. A 100-iteration loop with one symbolic `if` per iteration potentially produces 2¹⁰⁰ paths — a number exceeding the atoms in the observable universe.

### Symptoms

- Active state count grows linearly and indefinitely (states multiply at each loop iteration).  
- You see the same addresses recurring in active states when inspecting them.  
- Exploration never progresses past the loop to the rest of the function.

### Mitigation strategies

**LoopSeer** — This exploration technique is designed specifically for this problem. It detects loops in the control flow graph and limits iteration count:

```python
cfg = proj.analyses.CFGFast()  
simgr.use_technique(angr.exploration_techniques.LoopSeer(  
    cfg=cfg,
    bound=10       # Maximum 10 iterations per loop
))
```

The bound choice is a trade-off. Too low, and you miss the solution if it requires more iterations. Too high, and path explosion returns. In practice, start with a low bound (5–10) and increase if the solution isn't found.

**Hook the loop** — If you understand what the loop does thanks to Ghidra (e.g., it computes a checksum on the input), you can replace it with a SimProcedure directly modeling the result:

```python
class ChecksumHook(angr.SimProcedure):
    def run(self, buf_ptr, length):
        # Model the result as a symbolic value
        # with appropriate constraints
        result = self.state.solver.BVS("checksum", 32)
        return result

proj.hook(addr_loop_start, ChecksumHook(), length=loop_size_in_bytes)
```

The `length` parameter indicates how many bytes of machine code the hook replaces — angr will skip those bytes and resume execution after.

**Switch to Z3** — When the loop is too complex for angr but you've understood its logic in Ghidra, model it directly in Z3 with Python unrolling (as seen in Section 18.4). Python can unroll a 10,000-iteration loop in milliseconds to build the corresponding Z3 expression.

---

## Limit #3 — System calls and the environment

### The problem

A real program doesn't live in a vacuum. It interacts with the operating system via system calls: reading files, opening sockets, getting the time, allocating memory, creating processes… Each of these interactions poses a problem for symbolic execution:

- **The result is unpredictable.** What does `read(fd, buf, 16)` return? It depends on the file content, which doesn't exist in angr's simulated environment.  
- **The call can have side effects.** `fork()` creates a new process. `mmap()` modifies the address space. `ioctl()` modifies a device state.  
- **The result can be a branch source.** If the program checks `open()`'s return value and behaves differently on success vs failure, that's an additional branch to explore.

angr handles this problem in two ways:

1. **SimProcedures** for common libc functions (`open`, `read`, `write`, `close`, `malloc`, `free`, `printf`, `strcmp`…). These models are functional but simplified — for example, `open` in angr opens a simulated in-memory file, not a real file.

2. **SimOS** for direct system calls (`syscall`). angr models a subset of Linux syscalls, but many remain unsupported.

### What works well

- String manipulation functions (`strlen`, `strcmp`, `strcpy`, `memcpy`, `memcmp`…) are well modeled and reason correctly about symbolic arguments.  
- `malloc`/`free` work with a simplified allocator.  
- `printf`/`puts`/`fprintf` write to a simulated stream (accessible via `state.posix.dumps(fd)`).  
- Input from `argv` and `stdin` is well supported.

### What causes problems

**Files and I/O** — If the program reads a key from a file (`fopen`/`fread`), angr must know what to return. You can pre-load a simulated file:

```python
# Simulate the contents of "config.dat"
content = claripy.BVS("file_content", 128)  # 16 symbolic bytes

simfile = angr.SimFile("config.dat", content=content)  
state.fs.insert("config.dat", simfile)  
```

**Networking** — Sockets (`socket`, `connect`, `send`, `recv`) are only partially supported. If the binary communicates with a server for validation (Chapter 23), angr can't simulate the communication. Solution: hook network functions to return symbolic data or predefined concrete values.

**Threads and processes** — `fork`, `pthread_create`, signals… are not reliably supported. If the binary is multi-threaded, angr is generally not the right tool.

**Rare system calls** — `ioctl`, `mmap` with exotic flags, `prctl`, `seccomp`… Each unsupported syscall causes an error or unpredictable behavior. States reaching them end up in `simgr.errored`.

**Time and randomness** — `time()`, `gettimeofday()`, `rand()`, `/dev/urandom`… If the binary uses time as a seed (anti-debug timing check, Chapter 19), the result will be an unconstrained symbolic bitvector — which may or may not work depending on the rest of the program. `rand()` is modeled by a SimProcedure returning a symbolic value.

### General strategy

Facing a binary that heavily interacts with its environment, the best approach is to **reduce the scope** of symbolic execution. Instead of simulating the entire program, isolate the verification function and feed it symbolic inputs via `blank_state` (Section 18.3). All I/O, network, and system logic falls outside the analysis scope.

---

## Limit #4 — Symbolic expression complexity

### The problem

As symbolic execution progresses, symbolic expressions associated with registers and memory become increasingly complex. A value starting as the simple symbol **α** can, after a few dozen instructions, become an expression of several thousand nodes in claripy's internal syntax tree.

Each time the engine must fork (evaluate whether a symbolic condition can be both true **and** false), it queries Z3 with the current expression plus all accumulated path constraints. If the expression is huge, Z3 can take seconds — even minutes — to answer for **each** fork.

### Symptoms

- Exploration progressively slows even if the active state count remains stable.  
- Solver calls (visible by enabling claripy logging) take increasingly long.  
- Memory consumption increases due to expression sizes stored in each state.

### Mitigation strategies

**Concretize irrelevant values** — If certain variables don't influence the success condition, you can fix them to concrete values to simplify expressions. For example, if the program reads a configuration file unrelated to serial validation, simulate it with concrete content rather than symbolic.

**Enable aggressive simplification** — angr simplifies expressions by default, but you can force additional passes:

```python
state.options.add(angr.options.OPTIMIZE_IR)
```

**Use unicorn mode** — For purely concrete code portions (no symbolic values involved), angr can switch to the unicorn emulation engine, which is much faster:

```python
state.options.add(angr.options.UNICORN)
```

Caution: unicorn can't execute code manipulating symbolic values. angr automatically switches between SimEngine (symbolic) and unicorn (concrete) based on context.

---

## Limit #5 — Symbolic memory and symbolic pointers

### The problem

When the program performs a memory access with a pointer whose value is symbolic (e.g., `array[x]` where `x` is symbolic), angr must consider **all** possible addresses that pointer could take. This is the symbolic memory access problem.

```c
char table[256] = { ... };  
char result = table[user_input[0]];  // user_input[0] is symbolic  
```

The index `user_input[0]` can be any byte from 0 to 255. The result `result` therefore depends on 256 possible cases. angr must either fork into 256 states (one per possible index value) or build a giant symbolic expression like `If(index == 0, table[0], If(index == 1, table[1], ...))`.

### The double penalty

Symbolic memory accesses combine two problems:

1. **State explosion** if angr forks for each possible pointer value.  
2. **Giant expressions** if angr uses nested `If`s to represent all possibilities.

In both cases, a single machine instruction (`movzx eax, byte [rsi + rax]`) can be enough to derail exploration.

### Mitigation strategies

**Constrain the index** — If you know the index is limited (e.g., a printable ASCII character between 0x20 and 0x7E), add this constraint. This reduces cases from 256 to 95.

**Hook the access** — If the indexed access is part of a known function (substitution table, S-box), replace the entire function with a SimProcedure or switch to Z3 as seen in Section 18.4.

**Concretization strategies** — angr offers concretization strategies for symbolic addresses. By default, it uses an "any" strategy that chooses one possible concrete value and continues. You can configure more elaborate strategies:

```python
# Concretize symbolic memory reads by choosing
# one value among possible ones (loss of completeness)
state.memory.read_strategies = [
    angr.concretization_strategies.SimConcretizationStrategyRange(128)
]
```

---

## Limit #6 — Cryptographic functions and hashing

### The problem

Cryptographic hash functions (SHA-256, MD5, bcrypt…) are designed to be one-way functions: it's computationally infeasible to invert the result to find the input. This property also resists SMT solvers.

If a binary does:

```c
if (sha256(input) == expected_hash)
    success();
```

Symbolic execution will propagate expressions through SHA-256's hundreds of operations, producing a symbolic expression of colossal complexity. When the solver must satisfy `sha256_expression(α) == expected_hash`, it faces the same problem as cryptographic inversion — and it will fail, either by timeout or memory exhaustion.

### Why our keygenme works and SHA-256 doesn't

Our keygenme uses a Feistel network with a `mix32` function that superficially resembles hashing. Why does Z3 solve it in milliseconds?

The difference is the **size** and **structure** of the problem:

- `mix32` performs about 10 operations on 32-bit bitvectors. SHA-256 performs several thousand on 32-bit bitvectors with non-linear substitutions.  
- The 4-round Feistel produces a symbolic expression of a few hundred nodes. SHA-256 produces hundreds of thousands.  
- `mix32`'s operations (XOR, shift, multiplication) stay in the domain of linear or quasi-linear bitvectors. SHA-256 uses non-linear operations specifically chosen to resist algebraic resolution.

### Workaround strategies

**Extract the key at runtime** — Rather than inverting the hash, use GDB or Frida (Chapter 13) to intercept the value **before** it's hashed. This is the approach in Chapter 24 (reversing binaries with encryption).

**Hook the hash function** — Replace `sha256` with a SimProcedure returning an unconstrained symbolic value. Symbolic execution will bypass the hash and solve constraints **around** the hash call. You'll get the expected hash result (the value that must enter the hash for the program to succeed), but not the input producing that result:

```python
class SkipSHA256(angr.SimProcedure):
    def run(self, input_ptr, input_len, output_ptr):
        # Write a symbolic 256-bit result
        result = self.state.solver.BVS("sha256_out", 256)
        self.state.memory.store(output_ptr, result)

proj.hook_symbol("SHA256", SkipSHA256())
```

**Combine with bruteforce** — If the hash applies to a small input (a 4-digit PIN, a short token), classic bruteforce can be more efficient than symbolic execution. Sometimes the best solution is the simplest one.

---

## Summary table of limits and remedies

| Limit | Cause | Main symptom | Remedies |  
|---|---|---|---|  
| **Path explosion** | Too many symbolic branches | Thousands of active states, rising memory | Aggressive `avoid`, constrain inputs, `blank_state`, Veritesting |  
| **Symbolic loops** | Loop whose bound or body depends on symbolic value | States never progress past the loop | `LoopSeer`, hook the loop, switch to Z3 |  
| **System calls** | Unmodeled OS interactions | States in `errored`, incorrect behavior | Custom SimProcedures, `SimFile`, reduce scope |  
| **Complex expressions** | Accumulation of symbolic operations | Progressive solver slowdown | Concretize irrelevant values, unicorn mode, `OPTIMIZE_IR` |  
| **Symbolic pointers** | Memory access with symbolic index | State explosion or giant `If` expressions | Constrain index, hook access, concretization strategies |  
| **Crypto / hashing** | Functions designed to resist inversion | Solver timeout | Extract values at runtime (GDB/Frida), hook hash, bruteforce |

---

## Knowing when to give up: when symbolic execution isn't the answer

There are entire categories of binaries for which symbolic execution isn't the right tool:

**Massively multi-threaded binaries** — angr doesn't model thread scheduling. Race conditions and synchronization (mutexes, semaphores) are invisible.

**Self-modifying code** — If the binary modifies its own instructions in memory at runtime (anti-reversing technique, Chapter 19), angr executes the original code, not the modified code. You'll need to unpack the binary first (Chapter 29).

**Binaries with control flow obfuscation** — Control Flow Flattening (Chapter 19) replaces normal branches with a central dispatcher using a state variable. Symbolic execution sees dozens of branches at each dispatcher iteration, causing immediate path explosion. Specialized deobfuscation tools are needed upstream.

**I/O-dominated logic** — A web server, network client, GUI application… If the interesting logic is intimately intertwined with input/output, symbolic execution will spend its time modeling system interactions instead of solving useful constraints. Frida (Chapter 13) is often more suited in this case.

**Large codebases** — A multi-megabyte binary with hundreds of functions isn't a good candidate for global symbolic execution. Isolate the function of interest and work on that fragment.

The ability to recognize these situations quickly and choose another tool is a skill just as important as mastering angr.

---

## Diagnosing a stuck angr script

When your script has been running too long, here's a diagnostic checklist to follow in order:

**1. Inspect stashes**

```python
print(f"active:    {len(simgr.active)}")  
print(f"found:     {len(simgr.found)}")  
print(f"avoided:   {len(simgr.avoided)}")  
print(f"deadended: {len(simgr.deadended)}")  
print(f"errored:   {len(simgr.errored)}")  
```

- `active` continuously growing → path explosion.  
- `errored` non-empty → unsupported syscall or instruction.  
- `deadended` full but `found` empty → target is never reached, check the `find` address.

**2. Examine where active states are**

```python
for s in simgr.active[:10]:
    print(hex(s.addr))
```

If all states are at nearby addresses, they're probably stuck in a loop. If addresses are very dispersed, it's classic path explosion.

**3. Examine errors**

```python
for err in simgr.errored:
    print(err)
```

Errors will often indicate the exact cause: unsupported syscall, impossible memory access, symbolic division by zero…

**4. Enable logging**

```python
import logging  
logging.getLogger("angr").setLevel(logging.INFO)  
# Or for the solver:
logging.getLogger("claripy").setLevel(logging.DEBUG)
```

Verbose angr logging shows each executed basic block, each fork, and each solver call. It's chatty but diagnostic.

**5. Limit time**

Rather than waiting indefinitely, set a reasonable time limit and analyze the exploration state on expiration:

```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Exploration too long")

signal.signal(signal.SIGALRM, timeout_handler)  
signal.alarm(120)  # 2 minutes maximum  

try:
    simgr.explore(find=target, avoid=bad)
except TimeoutError:
    print("Timeout reached. Exploration state:")
    print(f"  active: {len(simgr.active)}")
    print(f"  found:  {len(simgr.found)}")
    # Analyze active states to understand the blockage
```

---

## Key points to remember

- **Path explosion** is symbolic execution's fundamental limit: each symbolic branch can double the state count. Remedies are pruning (`avoid`), input constraints, late start (`blank_state`), and exploration techniques (Veritesting, LoopSeer).

- **Symbolic loops** are a special case of path explosion. `LoopSeer` with a reasonable bound is the first thing to try. Hooking the loop or switching to Z3 are the alternatives.

- **System calls** and environment interactions are partially modeled. Reducing the analysis scope to the target function is the most reliable strategy.

- **Cryptographic functions** resist symbolic inversion by design. Dynamic value extraction (GDB/Frida) is often the only viable option.

- Knowing how to **diagnose** a stuck script (inspecting stashes, examining active state addresses, reading errors) is as important as knowing how to write the script.

- Knowing how to **give up** symbolic execution in favor of another tool (Frida, GDB, manual analysis) is a skill in its own right. Symbolic execution is a tool in your toolbox, not a universal solution.

---

> In the next section (18.6), we'll see how to **combine** symbolic execution with manual reverse engineering to get the best of both worlds — the solver's power and the analyst's intuition.

⏭️ [Combining with manual RE: when to use symbolic execution](/18-symbolic-execution/06-combining-with-manual-re.md)
