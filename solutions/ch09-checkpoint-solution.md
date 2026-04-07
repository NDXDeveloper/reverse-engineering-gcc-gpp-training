🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 9 Checkpoint

## Ghidra vs Radare2/Cutter Comparison on `keygenme_O2_strip`

> **Spoiler** — This document is the solution for the chapter 9 checkpoint. Try the exercise yourself before consulting this solution.  
>  
> This solution uses the **Ghidra + Cutter (Radare2)** combination as the tool pair. Observations would be similar with other combinations; specific divergence points would change, but the methodology remains the same.

---

## 1. Function Recognition

### Ghidra

After import and auto-analysis (default options, "Analyze All"), Ghidra detects **9 functions** in the binary:

| Address | Name assigned by Ghidra |  
|---|---|  
| `0x00401050` | `entry` |  
| `0x00401080` | `FUN_00401080` |  
| `0x004010b0` | `FUN_004010b0` |  
| `0x004010f0` | `FUN_004010f0` |  
| `0x00401110` | `FUN_00401110` |  
| `0x00401120` | `FUN_00401120` |  
| `0x00401160` | `main` |  
| `0x004011d0` | `FUN_004011d0` |  
| `0x004011e0` | `FUN_004011e0` |

Ghidra identifies `main` automatically by analyzing the first argument passed to `__libc_start_main` in `entry`. Functions `FUN_00401080` to `FUN_00401110` correspond to GCC infrastructure functions (`deregister_tm_clones`, `register_tm_clones`, `__do_global_dtors_aux`, `frame_dummy`). `FUN_004011d0` and `FUN_004011e0` are `__libc_csu_fini` and `__libc_csu_init`.

### Cutter (Radare2)

After opening with `aaaa` analysis, Cutter detects **9 functions**:

| Address | Name assigned by Cutter |  
|---|---|  
| `0x00401050` | `entry0` |  
| `0x00401080` | `sym.deregister_tm_clones` |  
| `0x004010b0` | `sym.register_tm_clones` |  
| `0x004010f0` | `sym.__do_global_dtors_aux` |  
| `0x00401110` | `sym.frame_dummy` |  
| `0x00401120` | `fcn.00401120` |  
| `0x00401160` | `main` |  
| `0x004011d0` | `sym.__libc_csu_fini` |  
| `0x004011e0` | `sym.__libc_csu_init` |

### Observations

The total number of detected functions is **identical** (9 functions). This is expected on a small, cleanly GCC-compiled binary: entry points are clearly defined and function prologues are standard.

The most visible difference is **naming**. Radare2 automatically recognizes and names GCC infrastructure functions (`deregister_tm_clones`, `register_tm_clones`, `__do_global_dtors_aux`, `frame_dummy`, `__libc_csu_init`, `__libc_csu_fini`), while Ghidra leaves them as generic `FUN_*`. This is explained by `r2`'s naming heuristics that identify these functions by their byte patterns and relative position in the `.text` section. This is an ergonomic advantage of Radare2 on this type of binary: initial triage is faster because infrastructure functions are immediately recognizable and can be ignored.

Both tools correctly identify `main` via the same mechanism (analyzing the first argument of `__libc_start_main`).

The application function at `0x00401120` is named `FUN_00401120` by Ghidra and `fcn.00401120` by Cutter — neither can give it a meaningful name without symbols. This is the `transform_key` function from the original source code (verifiable by opening the `keygenme_O0` version with symbols).

## 2. Decompiled Verification Function

The main verification function is `main` at `0x00401160`. Here are the pseudo-codes produced by each tool.

### Ghidra

```c
undefined8 main(void)
{
  int iVar1;
  char local_1c [20];
  
  puts("Enter key: ");
  __isoc99_scanf("%25s", local_1c);
  FUN_00401120(local_1c);
  iVar1 = strcmp(local_1c, "s3cr3t_k3y");
  if (iVar1 == 0) {
    puts("Access granted");
  }
  else {
    puts("Wrong key");
  }
  return 0;
}
```

### Cutter (r2ghidra / embedded Ghidra decompiler)

```c
int32_t main(void)
{
  int32_t iVar1;
  char s [20];

  puts("Enter key: ");
  __isoc99_scanf("%25s", s);
  fcn.00401120(s);
  iVar1 = strcmp(s, "s3cr3t_k3y");
  if (iVar1 == 0) {
    puts("Access granted");
  } else {
    puts("Wrong key");
  }
  return 0;
}
```

> **Note**: Cutter uses the `r2ghidra` (or `rz-ghidra`) plugin which embeds the same decompilation engine as Ghidra. Results are therefore structurally very similar. For a more contrasted comparison, one could use `r2`'s native decompiler (`pdc`) or Binary Ninja Cloud. The example remains instructive because the differences, even minor, illustrate the impact of integration.

### Line-by-line Comparison

**Readability.** Both pseudo-codes are very close and immediately understandable. The crackme logic is clear in both cases: read input, transform it, compare to an expected value.

**Return types.** Ghidra infers `undefined8` for `main`'s return, which is its default type for unresolved 64-bit values. Cutter displays `int32_t`, which is closer to reality (the `return 0` at function end corresponds to `eax = 0`, i.e. a 32-bit return). Advantage Cutter on this point, though the difference is cosmetic.

**Variable names.** Ghidra names the buffer `local_1c` (offset from frame pointer), Cutter names it `s`. The name `s` is more readable but less informative about memory location. Ghidra names the `strcmp` result `iVar1`, Cutter also `iVar1` — same convention since they share the underlying decompilation engine.

**Control structure.** Both tools reconstruct a clean `if/else`, without `goto`. The condition (`iVar1 == 0`) is identical. The direct correspondence with the `jne` at `0x0040119a` in the disassembly is correct in both cases.

**Call to transformation function.** Ghidra displays `FUN_00401120(local_1c)` while Cutter displays `fcn.00401120(s)`. The semantics are identical, only names differ. Both tools correctly detect that this function takes the buffer as parameter (passed via `rdi` per System V convention).

**Comparison string.** Both tools correctly extract the string `"s3cr3t_k3y"` passed to `strcmp`. This string is the crackme's "expected key" (after input transformation by `FUN_00401120`/`fcn.00401120`).

**Errors or artifacts.** No notable artifacts or errors in either tool on this function. The simplicity of the `-O2` code for `main` (no complex inlining, no vectorization) explains this convergence.

### Divergence on `FUN_00401120` / `fcn.00401120`

The comparison is more interesting on the `transform_key` function at `0x00401120`, where the compiler applied optimizations (`-O2`).

**Ghidra** produces a `while` loop with XOR operations and shifts on the buffer characters. The structure is correct but intermediate expressions use verbose `(int)(char)` casts.

**Cutter (r2ghidra)** produces a nearly identical result, with slight variations in sub-expression ordering and temporary naming. This confirms both use the same engine.

For a real decompilation divergence, one should compare Ghidra with **`r2`'s native decompiler** (`pdc`) or with **Binary Ninja HLIL**:

- `pdc` (native Radare2) produces notably more rudimentary pseudo-code on this function: no `while` loop reconstruction, conditions expressed as `goto`, variables named by their source register (`rdi`, `rsi`). The transformation structure is much harder to read.  
- Binary Ninja HLIL (if used as second tool) tends to better simplify the transformation loop's arithmetic expressions, producing more compact code.

## 3. Cross-references and Navigation

### Ghidra

1. Open the *Defined Strings* window (menu *Window → Defined Strings*).  
2. Type "granted" in the filter bar — the string `"Access granted"` appears at `0x0040200e`.  
3. Double-click navigates to the address in `.rodata`.  
4. Right-click on the string → *References → Show References to Address* (or shortcut depending on version).  
5. A single XREF appears: `main` at `0x0040119c` (instruction `LEA RDI, [.rodata:"Access granted"]`).  
6. Double-click on the XREF navigates to the instruction in `main`.  
7. Switch to the decompiled view via the Decompiler panel.

**Total: 4 actions** (filter strings → double-click → XREF → double-click). Navigation is smooth, panels stay synchronized.

### Cutter

1. Open the *Strings* widget (side panel or menu *Windows → Strings*).  
2. Type "granted" in the filter — the string appears at `0x0040200e`.  
3. Double-click navigates to the address in the disassembly view.  
4. Right-click → *Show X-Refs* (or key `X`).  
5. An XREF appears: `main+0x3c` at `0x0040119c`.  
6. Double-click navigates to the instruction.  
7. The decompiler widget (r2ghidra) synchronizes automatically.

**Total: 4 actions** identical. Ergonomics are comparable. Cutter displays the XREF in `main+0x3c` format (offset relative to function start), which is slightly more informative than the absolute address alone displayed by Ghidra.

### CLI Variant (pure Radare2)

In CLI, the same workflow boils down to 5 commands as detailed in section 9.3:

```
iz~granted → s 0x0040200e → axt → s main → pdf
```

Raw CLI speed is superior (no menu navigation), but the lack of visual synchronization between views requires mentally chaining results.

## 4. Annotations and Renaming

### Ghidra

- **Rename `main`** — already automatically named, no change needed.  
- **Rename `FUN_00401120`** — right-click in the Listing or Symbol Tree → *Rename Function* → type `transform_key` → Enter. The name propagates immediately in the disassembly, decompiler, and Symbol Tree.  
- **Rename `local_1c`** in the decompiler — right-click on `local_1c` → *Rename Variable* → type `user_input`. The pseudo-code updates all occurrences in the function. The Listing (assembly view) displays a comment reflecting the new name.  
- **Rename `iVar1`** → `cmp_result`. Same procedure, immediate propagation.  
- **Persistence** — annotations are automatically saved in the Ghidra project file (`.gpr` / `.rep`). After closing and reopening, all renames are preserved.

### Cutter

- **Rename `fcn.00401120`** — right-click in the Functions panel → *Rename* → type `transform_key`. Immediate propagation in disassembly and XREFs. The decompiler updates the call.  
- **Rename `s`** in the decompiler — right-click → *Rename* → `user_input`. Propagation in pseudo-code is immediate.  
- **Rename `iVar1`** → `cmp_result`. Same procedure.  
- **Persistence** — Cutter offers project saving (*File → Save Project*). After reopening, annotations are preserved.

### Observations

The experience is very similar in both tools. Both support renaming from the decompiled view, which is the most natural workflow (you rename what you understand, when you understand it). Propagation is immediate in both cases.

A minor difference: in Ghidra, the `L` keyboard shortcut allows renaming directly from the Listing without going through a context menu, which is slightly faster. In Cutter, the `N` key (inherited from `r2`) plays a similar role in disassembly mode, but not in the decompilation panel where right-click is needed.

## 5. Summary and Reasoned Preference

### Assessment on `keygenme_O2_strip`

On this specific binary (small, ELF x86-64, GCC `-O2`, stripped but no obfuscation), both tools produce very close analysis results. The number of detected functions is identical, decompiled quality is comparable (especially since Cutter uses the same Ghidra engine), and navigation and annotation operations are functionally equivalent.

### Observed Ghidra Advantages

- The decompiler interface is natively integrated and doesn't depend on additional plugins.  
- The Symbol Tree panel offers a complete hierarchical view (functions, labels, classes, namespaces) absent from Cutter.  
- Official documentation and available tutorials are more numerous and more structured.  
- The ability to define data structures and apply them to the binary (*Data Type Manager* menu) is more advanced than in Cutter.

### Observed Cutter / Radare2 Advantages

- Automatic naming of GCC infrastructure functions accelerates initial triage: functions to ignore are immediately identifiable.  
- The Dashboard offers an instant visual summary (architecture, protections, entropy, hashes) without opening additional windows.  
- The integrated `r2` console allows switching to CLI for quick operations (search, filtering, JSON export) without leaving the interface.  
- The `pds` command (call + string summary) has no direct equivalent in Ghidra and allows function triage in a single command.

### Personal Recommendation (to adapt)

For a binary of this size and complexity, **Ghidra alone is more than sufficient**. Cutter/Radare2's contribution primarily manifests in two situations:

- When you need a **second opinion** on suspicious decompiled output — though in this specific case, since Cutter uses the same Ghidra decompiler, you would rather use Binary Ninja Cloud or `r2`'s native `pdc` to get a genuinely different perspective.  
- When you want to **script or automate** part of the analysis — `r2pipe` and CLI mode are significantly lighter than Ghidra scripting for one-off tasks.

On a larger, more obfuscated binary, or one requiring batch processing, the Ghidra (decompilation) + Radare2 (scripting) combination would become a real advantage.

---

> This solution is an example of the expected report. Your own report may diverge on specific observations (especially if you chose IDA Free or Binary Ninja Cloud as your second tool), on expressed preferences, and on the level of detail. The key is having used both tools and having formulated concrete, reasoned observations.

⏭️
