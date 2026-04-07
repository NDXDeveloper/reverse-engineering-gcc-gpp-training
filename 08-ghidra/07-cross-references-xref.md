🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.7 — Cross-references (XREF): tracking the use of a function or data item

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## What is a cross-reference?

A cross-reference (abbreviated **XREF**) is a link that connects two locations in a binary: a **source** (the place making the reference) and a **destination** (the referenced place). When a `CALL 0x004011a0` instruction is at address `0x00401350`, Ghidra records a cross-reference whose source is `0x00401350` and destination is `0x004011a0`. Similarly, when a `LEA RDI, [0x00402010]` instruction loads the address of a string in `.rodata`, Ghidra creates a cross-reference from the instruction to the data.

Cross-references are the **connective tissue** of an analyzed binary. They materialize the relationships between code and data: which functions call which functions, what code accesses which global variable, which instructions reference which string, which constructors initialize which vptr. Without them, the binary would be a set of isolated fragments; with them, it becomes a navigable graph where each element is connected to its usage context.

Effective exploitation of cross-references is one of the skills that distinguishes a beginner analyst from an experienced one. It's what allows you to answer questions like: "Who calls this function?", "Where is this error string used?", "Which functions access this global variable?", "From how many places is this flag modified?".

---

## Types of cross-references

Ghidra categorizes cross-references according to the nature of the link between source and destination. Each type is identified by a suffix in the Listing display.

### Code references

These references connect instructions to each other or instructions to function entry points.

**Call (`c`)** — The source is a `CALL` instruction and the destination is the entry point of the called function. It's the most common and useful reference type for understanding a program's architecture.

```
XREF[2]:  main:00401203(c), handle_input:00401345(c)
```

This display above a function indicates it is called from two places: once from `main` at address `0x00401203`, and once from `handle_input` at address `0x00401345`.

**Unconditional Jump (`j`)** — The source is an unconditional jump (`JMP`) to the destination. These references appear between basic blocks of the same function (internal branches) or sometimes between functions (tail calls, PLT trampolines).

**Conditional Jump (`j`)** — The source is a conditional jump (`JZ`, `JNZ`, `JL`, `JGE`, etc.) to the destination. As with unconditional jumps, these references connect basic blocks.

> 💡 Ghidra uses the same `(j)` suffix for conditional and unconditional jumps. To distinguish them, examine the source instruction.

**Fall-through (`f`)** — The implicit reference connecting an instruction to the next instruction in memory when there is no jump. This type is rarely displayed explicitly but it exists in Ghidra's internal model and contributes to building the control-flow graph.

### Data references

These references connect code to data, or data to other data.

**Read (`r`)** — The source code reads the data at the destination. For example, a `MOV EAX, [global_counter]` instruction creates a read reference to `global_counter`.

**Write (`w`)** — The source code writes to the data at the destination. For example, `MOV [global_counter], EAX` creates a write reference.

**Data/Pointer (`*`)** — The source is a data item (not an instruction) that contains a pointer to the destination. It's typical of vtables (pointers to methods), function-pointer tables, GOT entries, and structures containing pointers to other structures.

```
XREF[1]:  .data.rel.ro:00402050(*)
```

This display on a function indicates that a pointer to it exists in `.data.rel.ro` at address `0x00402050` — probably a vtable entry.

### Suffix summary

| Suffix | Type | Meaning |  
|---|---|---|  
| `(c)` | Call | Function call (`CALL`) |  
| `(j)` | Jump | Conditional or unconditional jump |  
| `(f)` | Fall-through | Implicit sequential flow |  
| `(r)` | Read | Data read |  
| `(w)` | Write | Data write |  
| `(*)` | Data/Pointer | Pointer in a data table |

---

## Displaying XREF in the Listing

### Function header

Above a function's label, Ghidra displays a summary of incoming cross-references. When the number of references is low (typically 5 or fewer), they are listed individually:

```
                     ******************************************************
                     *                    FUNCTION                         *
                     ******************************************************
                     XREF[3]:  main:00401203(c),
                               process_input:00401345(c),
                               handle_event:004015a0(c)
```

When the number exceeds the display threshold (configurable), Ghidra displays only the counter `XREF[47]` with a clickable link to see the complete list.

### Data header

The same principle applies to data (global variables, strings, constants). Above a string in `.rodata`, for example:

```
                     XREF[1]:  check_password:004012b8(r)
.rodata:00402060     ds  "Invalid password. Try again."
```

This indicates that a single instruction, at address `0x004012b8` in the `check_password` function, references this string — in read.

### Margin indicators

Ghidra also places small icons in the Listing's left margin to signal references. Arrows indicate flow direction: an incoming arrow signals a jump or call destination, an outgoing arrow signals a jump or call from this instruction.

---

## The References window

### Displaying an element's references

To see the complete and detailed list of cross-references to or from an element, select it in the Listing or Decompiler and press **`X`** (or right-click → **References → Show References to**). The **References** window opens with a table listing all references.

This table contains the following columns:

- **From Location** — the reference's source address;  
- **From Label** — the function or label containing the source;  
- **Ref Type** — the type of the reference (`UNCONDITIONAL_CALL`, `DATA`, `READ`, `WRITE`, `COMPUTED_JUMP`, etc.);  
- **To Location** — the destination address;  
- **To Label** — the function or label of the destination.

Double-click any row to navigate directly to the source address. It's the fundamental mechanism for navigation by usage context.

### References from an element (References from)

The inverse operation is also possible. Right-click on an element → **References → Show References from** displays the list of everything this element references. For a function, it shows all the functions it calls and all the data it accesses — it's essentially the list of its dependencies.

### Filtering references

The References window lets you filter by type. If a global variable has 200 references and you're only interested in writes, you can filter to display only references of type `WRITE`. This considerably reduces noise when you're looking for "where is this flag modified?" among dozens of reads.

---

## Concrete use cases for XREF

Cross-references are a transversal tool that intervenes at almost every step of the analysis. Here are the most common scenarios.

### Tracing back from a string

It's probably the most common use for a beginner, and it remains fundamental at all levels. The typical scenario:

1. You open **Defined Strings** and spot a suspect string: `"License valid. Access granted."`.  
2. Double-click to navigate to this string in `.rodata`.  
3. Press `X` to see the references to this string.  
4. The References window shows a single reference: `check_license:00401456(r)`.  
5. Double-click to navigate to the instruction that loads this string. You're now in the `check_license` function, exactly at the place that displays the success message.  
6. Trace back in this function's control flow to understand what condition leads to this message.

This "string → XREF → code → flow analysis" workflow is one of the most effective for quickly locating a feature in an unknown binary.

### Understanding the use of a global variable

When you identify an important global variable (a counter, a configuration flag, a data buffer), XREF show you its entire lifecycle:

1. Navigate to the variable in `.data` or `.bss`.  
2. Press `X`.  
3. Examine references sorted by type:  
   - `(w)` references show places where the variable is **modified** — typically initialization and updates.  
   - `(r)` references show places where the variable is **read** — functions that depend on its value.  
   - `(*)` references show places where its **address** is taken — often to pass it to a function by pointer.

This complete diagnosis gives you the impact map of a global variable across the entire program.

### Identifying callers of a function (ascending call graph)

To understand in what context a function is invoked:

1. Navigate to the target function.  
2. Press `X`.  
3. Filter by `CALL` type.  
4. The resulting list shows all call sites.

If the function is only called from one place, its role is strongly constrained by the caller's context. If it's called from 50 places, it's probably a generic utility function (a helper, a wrapper, a common validation function).

The number of callers is also an indicator of a function's importance in the program's architecture. A function with a large number of Call XREFs often deserves to be analyzed and renamed as a priority.

### Identifying called functions (descending call graph)

The inverse operation — which functions are called by a given function — is accessible via **References from**. This gives a high-level view of what the function does: if it calls `socket`, `connect`, `send`, `recv`, it's a network function. If it calls `fopen`, `fread`, `fclose`, it's a file I/O function.

### Tracking a vtable pointer

In a C++ binary, `(*)` type XREFs are particularly valuable for linking vtables to constructors and destructors:

1. Navigate to a vtable in `.rodata`.  
2. Press `X` on the vtable address (the entry point, not the offset-to-top).  
3. `(w)` references to this address come from constructors and destructors that initialize the vptr. Each constructor writes the vtable's address at the beginning of the `this` object.  
4. You immediately identify which functions are constructors for this class.

This pattern is reliable even in stripped binaries, because the vptr initialization mechanism is inherent to the object model and cannot be removed.

### Locating switch handlers via function table

Some programs implement dispatch via a table of function pointers rather than a classic `switch`:

```c
// In .rodata: a table of pointers
handler_table[0] = &handle_cmd_ping;  
handler_table[1] = &handle_cmd_auth;  
handler_table[2] = &handle_cmd_data;  
```

`(*)` type XREFs on each handler indicate their presence in this table. By examining the code that indexes the table, you understand the dispatch mechanism. XREFs save you from missing handlers that are never directly called by `CALL` but only via the table.

---

## The Call Graph

### Function Call Graph

Beyond individual XREFs, Ghidra can build a visual **call graph** showing call relationships between functions. Access it via:

- **Window → Function Call Graph**

This graph displays the current function at the center, with its callers (functions that call it) on one side and its callees (functions it calls) on the other. You can extend the graph by double-clicking a node to explore its own callers and callees.

The call graph is useful for:

- **Understanding a function's position in the overall architecture** — is it a high-level function (many callees, few callers) or a utility function (few callees, many callers)?  
- **Identifying execution paths** — how do you reach this function from `main`? What are the possible call chains?  
- **Visualizing dependencies** — which libraries or subsystems are engaged by a function?

### Function Call Trees

The **Window → Function Call Trees** menu offers a tree view (textual, not graphical) of the same information. Two tabs:

- **Incoming Calls** — the tree of callers, recursively. The root is the current function, and each level shows who calls the previous level.  
- **Outgoing Calls** — the tree of callees, recursively. The root is the current function, and each level shows what it calls.

This tree view is often more practical than the visual graph for deep analyses, because it's more compact and more easily navigable when the node count is high.

---

## Manual references

### When Ghidra misses a reference

Ghidra's automatic analysis is high-performance, but it doesn't detect every reference. Common cases of missed references are:

**Indirect calls via register** — A `CALL RAX` instruction calls the function whose address is in `RAX`. Ghidra can't always statically resolve `RAX`'s value at that place, and the reference may be missing. It's frequent in C++ virtual dispatch (call via vtable) and in callbacks/function pointers.

**Computed addresses** — If an address is built by a complex arithmetic sequence (`LEA` + `ADD` + shift), Ghidra may not resolve it to a reference.

**Untyped data tables** — An array of pointers in `.data` that wasn't typed as such appears as a sequence of 64-bit integers, without references to the pointed functions.

### Create a reference manually

You can add manual references to fill these gaps:

1. Place the cursor in the Listing at the source address.  
2. Right-click → **References → Add Reference from…**  
3. Specify the destination address and the reference type (Call, Data, Read, Write).  
4. Confirm.

The reference appears in the Listing and in `X` (Show References) results. Manual references are visually identical to automatic ones — Ghidra treats them the same way for navigation and analysis.

> ⚠️ **Caution** — Only add manual references when you're reasonably certain of the relationship. An erroneous reference can mislead subsequent analysis and the decompiler. If in doubt, prefer a comment that notes the hypothesis.

### Delete an incorrect reference

If automatic analysis created an erroneous reference (which happens sometimes with poorly typed data or ambiguous instructions), you can delete it via right-click → **References → Delete Reference from…**. Select the reference to delete in the list that appears.

---

## Advanced reference searching

### Search → For Direct References

The **Search → For Direct References** menu allows searching for all occurrences of a specific address in the binary, including in non-analyzed zones or raw data. It's more exhaustive than standard XREFs, which only show references detected by the analysis.

This type of search is useful for finding references that analysis missed: pointers in untyped data tables, hardcoded addresses in zones interpreted as data rather than code, or references in unusual sections.

### Search → For Address Tables

This heuristic search tries to locate **pointer tables** in data sections — contiguous sequences of values that are all valid addresses in the program's space. It's particularly useful for detecting handler tables, unlabeled vtables, or function-pointer arrays.

Ghidra parameters this search with minimum-length criteria (number of consecutive entries that must be valid addresses) and alignment. Results are candidates — you must validate them manually.

---

## XREF workflow integrated into analysis

Cross-references are not an isolated tool used occasionally — they integrate at every stage of the analysis workflow. Here is how they intervene in the different phases described in the previous sections of this chapter.

**During initial triage** — After identifying interesting strings in Defined Strings, use XREFs to locate the code that uses them. In a few clicks, you go from a string `"Connection refused"` to the network-handling function that produces it.

**During renaming (section 8.4)** — When you rename a function, verify its XREFs to make sure the name is consistent in all call contexts. If `FUN_00401500` is called from a network function and from a file function, the chosen name must reflect this versatility (for example `read_buffer` rather than `read_socket`).

**During structure reconstruction (section 8.6)** — `(w)` type XREFs on a global variable or structure field show the functions that modify the structure. Analyzing these functions completes your knowledge of the layout by revealing fields that the initial function did not access.

**During C++ analysis (section 8.5)** — `(*)` XREFs to vtables identify constructors. `(c)` XREFs to `__cxa_throw` locate exception-throwing points. XREFs to typeinfo allow tracing inheritance relationships.

**During dynamic-analysis preparation (Part III)** — Identify via XREFs the critical functions (license verification, decryption, authentication) and note their addresses to set breakpoints on them in GDB (Chapter 11) or hooks in Frida (Chapter 13).

---

## Summary

Cross-references are the central mechanism that connects a binary's elements to each other in Ghidra. They come as code references (Call, Jump) and data references (Read, Write, Pointer), identifiable by their suffixes in the Listing. The `X` key is the most important shortcut of this section — it opens the References window from any element and allows instant navigation to all usage contexts. The call graph and call trees offer higher-level views of the program's architecture. Finally, manual references and advanced searches fill in the gaps of automatic analysis when relationships are missed.

The next section introduces Ghidra scripts in Java and Python, which allow automating repetitive operations — including systematic exploitation of cross-references at the scale of an entire binary.

---


⏭️ [Ghidra scripts in Java/Python to automate analysis](/08-ghidra/08-scripts-java-python.md)
