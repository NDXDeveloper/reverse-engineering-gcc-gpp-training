🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.8 — Ghidra scripts in Java/Python to automate analysis

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## Why script Ghidra?

Previous sections have shown you how to annotate a binary manually: rename a function, create a type, follow a cross-reference. This work is effective at small scale — a few dozen functions, a handful of structures. But real binaries often contain hundreds or even thousands of functions, dozens of vtables, hundreds of strings to classify. Repetitive tasks consume considerable time and are subject to human error.

Scripting is the answer to this scaling problem. Ghidra exposes nearly all of its features via a **programmatic API** accessible in Java and Python (via Jython, a Java implementation of Python 2.7). A script can do everything you do manually in the interface, and more: iterate over every function in the program, filter by criterion, rename in bulk, create structures automatically, extract data, produce reports.

Common scripting use cases are:

- **Bulk renaming** — renaming all functions matching a pattern (for example, prefixing functions that call `malloc` with `alloc_`).  
- **Information extraction** — listing all strings referenced by a family of functions, extracting all calls to a specific function with their arguments.  
- **Pattern detection** — looking for characteristic instruction sequences (cryptographic constants, compiler idioms, obfuscation patterns).  
- **Automatic reconstruction** — creating structures for each detected vtable, applying types to families of similar functions.  
- **Report generation** — producing a JSON or text summary of the analysis for documentation or integration into a pipeline.

---

## The scripting environment

### The Script Manager

The entry point for scripting in the CodeBrowser is the **Script Manager**, accessible via **Window → Script Manager** or the script icon (sheet with a green arrow) in the toolbar.

The Script Manager displays:

- **A tree of categories** on the left, organizing scripts by theme (Analysis, Data, Functions, Search, etc.).  
- **The list of scripts** in the center, with their name, description, and category.  
- **A toolbar** with buttons for running, editing, creating, and managing scripts.

Ghidra ships with **several hundred pre-integrated scripts** covering a wide variety of tasks. Before writing your own script, browse the existing ones — chances are someone has already solved a similar problem. Pre-integrated scripts also serve as code examples to learn the API.

### Creating a new script

1. In the Script Manager, click the **New Script** button (blank page icon with a `+`).  
2. Choose the language: **Java** or **Python**.  
3. Give the script a name (for example `ListCryptoConstants.java` or `rename_network_funcs.py`).  
4. Ghidra opens the integrated script editor with a basic skeleton.

User scripts are stored by default in `~/ghidra_scripts/`. You can add additional script directories via **Edit → Script Directories** in the Script Manager.

### Running a script

Select the script in the Script Manager and click **Run** (green ▶ button), or double-click directly on the script. The output (calls to `println` in Java, `print` in Python) displays in the **Console** at the bottom of the CodeBrowser.

You can also assign a keyboard shortcut to a frequently used script: right-click on the script → **Assign Key Binding**.

---

## The Flat API: the universal entry point

Whether you write in Java or Python, your scripts inherit from a base class — `GhidraScript` — that exposes a set of high-level methods called the **Flat API**. These methods provide simplified access to Ghidra's features without needing to directly manipulate the framework's internal classes.

Flat API methods are available directly in the script body (without object prefix in Java, and via global variables in Python). Here are the most important ones, grouped by domain.

### Navigation and addresses

| Method | Role |  
|---|---|  
| `currentProgram` | Reference to the program currently open in the CodeBrowser |  
| `currentAddress` | The address where the cursor is in the Listing |  
| `currentFunction` | The function containing the cursor |  
| `toAddr(String)` | Converts a hex string to an `Address` object (ex: `toAddr("00401200")`) |  
| `getAddressFactory()` | Access to the program's address factory |

### Functions

| Method | Role |  
|---|---|  
| `getFirstFunction()` | Returns the program's first function (by address) |  
| `getFunctionAfter(Function)` | Returns the next function in the address space |  
| `getFunctionAt(Address)` | Returns the function at the exact given address |  
| `getFunctionContaining(Address)` | Returns the function containing the given address |  
| `getGlobalFunctions(String)` | Searches for functions by name |

### Memory and data

| Method | Role |  
|---|---|  
| `getByte(Address)` | Reads a byte at the given address |  
| `getInt(Address)` | Reads a 32-bit integer |  
| `getLong(Address)` | Reads a 64-bit integer |  
| `getBytes(Address, int)` | Reads a byte array of the specified size |  
| `getDataAt(Address)` | Returns the data element defined at this address |

### User interaction

| Method | Role |  
|---|---|  
| `println(String)` | Displays a message in the Console |  
| `askString(String, String)` | Displays a dialog asking the user for text input |  
| `askAddress(String, String)` | Asks for an address |  
| `askChoice(String, String, List, T)` | Asks for a choice among a list of options |  
| `askYesNo(String, String)` | Asks for yes/no confirmation |

### Monitoring

| Method | Role |  
|---|---|  
| `monitor` | Reference to the script's progress monitor |  
| `monitor.setMessage(String)` | Updates the progress message |  
| `monitor.checkCancelled()` | Checks if the user cancelled the script (raises an exception if so) |

---

## Writing Python (Jython) scripts

### Python environment in Ghidra

Ghidra uses **Jython** — a Python 2.7 implementation that runs on the JVM. This means the syntax is Python 2 (not Python 3), but you have access to the entire Java Ghidra API from Python. In practice, the most notable syntactic differences are:

- `print` is a statement, not a function: `print "Hello"` (not `print("Hello")`, though this form also works in Python 2).  
- Strings are ASCII/Latin-1 by default, not Unicode.  
- Some Python 3 libraries are not available.

> ⚠️ **Ghidra 11.x and Pyhidra** — Recent versions of Ghidra progressively introduce **CPython 3** support via the Pyhidra module (based on JPype). This feature is still evolving. In this tutorial, we use Jython (Python 2.7) which is the stable and documented method. The principles and API remain identical — only Python 2 vs 3 syntax conventions differ.

### Python script skeleton

```python
# List all the program's functions and their cross-reference counts
# @category Analysis
# @author RE Training

from ghidra.program.model.symbol import RefType

func = getFirstFunction()  
while func is not None:  
    name = func.getName()
    entry = func.getEntryPoint()
    ref_count = len(getReferencesTo(entry))
    println("{} @ {} — {} XREFs".format(name, entry, ref_count))
    func = getFunctionAfter(func)
```

The special comments in the header (`@category`, `@author`, `@keybinding`, `@description`) are **metadata** that Ghidra uses to organize the script in the Script Manager. `@category` determines which category the script appears in.

### Iterating over functions

The most common pattern in a Ghidra script is iteration over all the program's functions:

```python
func = getFirstFunction()  
while func is not None:  
    # ... processing of func ...
    func = getFunctionAfter(func)
```

This pattern uses the Flat API. A more concise alternative uses the Function Manager:

```python
fm = currentProgram.getFunctionManager()  
for func in fm.getFunctions(True):  # True = forward iteration  
    # ... processing of func ...
```

### Accessing a function's instructions

To iterate over the assembly instructions of a function:

```python
listing = currentProgram.getListing()  
func = getFunctionAt(toAddr("00401200"))  
if func is not None:  
    body = func.getBody()  # AddressSetView covering the function body
    instr = listing.getInstructionAt(body.getMinAddress())
    while instr is not None and body.contains(instr.getAddress()):
        println("{} {}".format(instr.getMnemonicString(), instr))
        instr = instr.getNext()
```

### Accessing cross-references

```python
# Find all functions that call strcmp
refs = getReferencesTo(toAddr("00401080"))  # strcmp's address in PLT  
for ref in refs:  
    caller_addr = ref.getFromAddress()
    caller_func = getFunctionContaining(caller_addr)
    if caller_func is not None:
        println("strcmp called from {} @ {}".format(
            caller_func.getName(), caller_addr))
```

### Rename a function via script

```python
func = getFunctionAt(toAddr("004011a0"))  
if func is not None:  
    func.setName("validate_key", ghidra.program.model.symbol.SourceType.USER_DEFINED)
    println("Function renamed to validate_key")
```

The `SourceType.USER_DEFINED` parameter tells Ghidra that the name was defined by the user (as opposed to an auto-generated or symbol-imported name).

### Add a comment via script

```python
from ghidra.program.model.listing import CodeUnit

addr = toAddr("00401200")  
cu = listing.getCodeUnitAt(addr)  
cu.setComment(CodeUnit.EOL_COMMENT, "Start of license verification")  
```

The comment-type constants are `EOL_COMMENT`, `PRE_COMMENT`, `POST_COMMENT`, `PLATE_COMMENT`, and `REPEATABLE_COMMENT`.

---

## Writing Java scripts

### Java script skeleton

```java
// List imported functions
// @category Analysis
// @author RE Training

import ghidra.app.script.GhidraScript;  
import ghidra.program.model.listing.Function;  
import ghidra.program.model.listing.FunctionIterator;  
import ghidra.program.model.symbol.SymbolTable;  

public class ListImports extends GhidraScript {

    @Override
    protected void run() throws Exception {
        FunctionIterator functions = currentProgram
            .getFunctionManager()
            .getExternalFunctions();
        
        while (functions.hasNext()) {
            Function func = functions.next();
            println("Import: " + func.getName() 
                    + " from " + func.getExternalLocation()
                                     .getLibraryName());
        }
    }
}
```

The Java script is a class that extends `GhidraScript` and implements the `run()` method. The filename must match the class name (here `ListImports.java`). Ghidra automatically compiles the script before executing it — you don't need to compile it manually.

### Java vs Python: which language to choose?

Both languages access the same API. The choice is a matter of preference and context:

**Python (Jython)** is preferable for fast prototyping, short scripts, and exploratory analyses. The syntax is more concise, there's no explicit compilation, and the trial-and-error loop is faster. It's the recommended choice for most scripts in this tutorial.

**Java** is preferable for complex and performant scripts: large data volumes, elaborate business logic, integration with third-party Java libraries. Java also offers better autocompletion support if you use an external IDE (Eclipse, IntelliJ) with the Ghidra project configured as a dependency.

In practice, start in Python for everything, and migrate to Java only if you encounter performance or feature limitations.

---

## Useful script examples

### List all calls to a function with their arguments

This script searches for all call sites to a given function and tries to extract the value of the first argument (often a string passed in `RDI`):

```python
# List puts() calls with the string passed as argument
# @category Analysis

target_name = askString("Target function", "Name of the function to trace:")  
fm = currentProgram.getFunctionManager()  
listing = currentProgram.getListing()  
rm = currentProgram.getReferenceManager()  

# Find the target function (can be a thunk/PLT)
targets = getGlobalFunctions(target_name)  
if not targets:  
    println("Function '{}' not found".format(target_name))
else:
    for target in targets:
        refs = getReferencesTo(target.getEntryPoint())
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                caller = getFunctionContaining(call_addr)
                caller_name = caller.getName() if caller else "???"
                
                # Look for the previous instruction that loads RDI
                instr = listing.getInstructionAt(call_addr)
                prev = instr.getPrevious()
                arg_info = ""
                # Go back a few instructions to find LEA/MOV into RDI
                for i in range(5):
                    if prev is None:
                        break
                    mnemonic = prev.getMnemonicString()
                    if "LEA" in mnemonic or "MOV" in mnemonic:
                        operands = prev.toString()
                        if "RDI" in operands.upper():
                            arg_info = " | arg1 hint: {}".format(operands)
                            break
                    prev = prev.getPrevious()
                
                println("[{}] CALL {} @ {}{}".format(
                    caller_name, target_name, call_addr, arg_info))
```

This script illustrates several important patterns: user interaction (`askString`), function search by name, iteration over filtered references, and going back in instructions to extract context.

### Rename functions with a prefix based on their imports

This script automatically prefixes functions that call network functions:

```python
# Prefix functions that make network calls
# @category Analysis

network_funcs = ["socket", "connect", "bind", "listen", 
                 "accept", "send", "recv", "close"]
fm = currentProgram.getFunctionManager()

for net_name in network_funcs:
    targets = getGlobalFunctions(net_name)
    for target in targets:
        refs = getReferencesTo(target.getEntryPoint())
        for ref in refs:
            if ref.getReferenceType().isCall():
                caller = getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                name = caller.getName()
                if name.startswith("FUN_") and not name.startswith("net_"):
                    new_name = "net_" + name
                    caller.setName(new_name, 
                        ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    println("Renamed {} -> {}".format(name, new_name))
```

### Search for cryptographic constants

This script searches for known constants (here the first bytes of the AES S-box) in the program's memory space:

```python
# Search for the AES S-box in the binary
# @category Search

aes_sbox_start = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]

memory = currentProgram.getMemory()  
search_bytes = bytes(bytearray(aes_sbox_start))  
addr = memory.findBytes(memory.getMinAddress(), search_bytes, None, True, monitor)  

if addr is not None:
    println("AES S-box found at address: {}".format(addr))
    # Find functions referencing this address
    refs = getReferencesTo(addr)
    for ref in refs:
        func = getFunctionContaining(ref.getFromAddress())
        if func:
            println("  Referenced by: {} @ {}".format(
                func.getName(), ref.getFromAddress()))
else:
    println("AES S-box not found")
```

### Export a JSON summary of functions

```python
# Export a JSON summary of all functions
# @category Export

import json

output = []  
fm = currentProgram.getFunctionManager()  

for func in fm.getFunctions(True):
    entry = func.getEntryPoint().toString()
    name = func.getName()
    size = func.getBody().getNumAddresses()
    xref_count = len(getReferencesTo(func.getEntryPoint()))
    called = []
    for f_called in func.getCalledFunctions(monitor):
        called.append(f_called.getName())
    
    output.append({
        "name": name,
        "address": entry,
        "size": int(size),
        "xref_count": xref_count,
        "calls": called
    })

# Write the file
filepath = askString("Export", "JSON file path:")  
with open(filepath, "w") as f:  
    f.write(json.dumps(output, indent=2))
println("Export finished: {} functions".format(len(output)))
```

This type of script is particularly useful for feeding external tools (Jupyter notebooks, statistical analysis scripts, graph-visualization tools) with data extracted from Ghidra.

---

## The internal API: going further

The Flat API covers common needs, but for advanced tasks, you'll need to access Ghidra's **internal classes**. The most important packages are:

### `ghidra.program.model`

The heart of the data model. The main subpackages:

- `ghidra.program.model.listing` — `Function`, `Instruction`, `Data`, `CodeUnit`, `Listing`. Access to disassembled content.  
- `ghidra.program.model.symbol` — `Symbol`, `SymbolTable`, `Namespace`, `Reference`, `RefType`, `SourceType`. Management of symbols, namespaces, and references.  
- `ghidra.program.model.address` — `Address`, `AddressSet`, `AddressSpace`. Address manipulation.  
- `ghidra.program.model.mem` — `Memory`, `MemoryBlock`. Access to the program's raw memory.  
- `ghidra.program.model.data` — `DataType`, `Structure`, `Enum`, `Union`, `Pointer`. Type manipulation.  
- `ghidra.program.model.pcode` — `PcodeOp`, `Varnode`. Access to the P-Code intermediate representation used by the decompiler.

### `ghidra.app.decompiler`

Programmatic access to the decompiler. You can invoke the decompiler on a function and retrieve the C pseudo-code in structured form:

```python
from ghidra.app.decompiler import DecompInterface

decomp = DecompInterface()  
decomp.openProgram(currentProgram)  

func = getFunctionAt(toAddr("00401200"))  
results = decomp.decompileFunction(func, 30, monitor)  # 30s timeout  

if results.decompileCompleted():
    code = results.getDecompiledFunction().getC()
    println(code)
else:
    println("Decompilation failed")

decomp.dispose()
```

This access is powerful for producing bulk pseudo-code exports or for programmatically analyzing the decompiled code's structure.

### API documentation

Ghidra's complete Javadoc documentation is accessible:

- **In Ghidra**: **Help → Ghidra API Help** menu in the CodeBrowser. The Javadoc opens in a browser.  
- **Online**: on Ghidra's GitHub repository, documentation files are generated at each release.  
- **By exploration**: in the Script Manager, pre-integrated scripts are commented and constitute a base of practical examples. Use **Edit** on an existing script to read its source code.

> 💡 **Learning tip** — The best way to learn the API is through exploration. Open Ghidra's Python console (**Window → Python**) and test calls interactively. Type `currentProgram.` then explore available methods via autocompletion (Tab key). This interactive loop is much more effective than exhaustive reading of the Javadoc.

---

## The interactive Python console

Beyond saved scripts, Ghidra offers an **interactive Python console** accessible via **Window → Python**. It's a REPL (Read-Eval-Print Loop) that lets you type Python commands one by one and see the result immediately.

The console is ideal for:

- **Exploring the API** — test methods, inspect objects, verify hypotheses.  
- **One-off analyses** — "how many functions call `malloc`?" is answered in three lines in the console, without creating a script file.  
- **Prototyping** — test your script's logic before formalizing it in a file.

All Flat API variables are available in the console: `currentProgram`, `currentAddress`, `currentFunction`, `getFirstFunction()`, etc.

---

## Scripting best practices

**Use `monitor.checkCancelled()`** in long loops. This allows the user to cleanly interrupt the script via the cancel button in the interface. Without this check, a script iterating over thousands of functions cannot be interrupted otherwise than by killing Ghidra.

```python
for func in fm.getFunctions(True):
    monitor.checkCancelled()  # raises CancelledException if cancelled
    monitor.setMessage("Analysis of {}".format(func.getName()))
    # ... processing ...
```

**Wrap modifications in transactions.** Ghidra uses a transaction system to guarantee database integrity. Scripts launched from the Script Manager automatically manage transactions. If you use the API from a different context (plugin, interactive console for writes), you'll have to manage transactions manually:

```python
txid = currentProgram.startTransaction("My script")  
try:  
    # ... modifications ...
    currentProgram.endTransaction(txid, True)  # True = commit
except:
    currentProgram.endTransaction(txid, False)  # False = rollback
```

**Prefer `println()` over `print`.** The Flat API's `println()` function writes to the CodeBrowser's Console, visible in the graphical interface. Python's `print` statement writes to the Java process's standard output, which isn't visible in the interface (unless you launched Ghidra from a terminal).

**Test on a small sample before running in bulk.** Add a counter and a temporary `break` to validate your script on the first 10 functions before launching it on the program's 5000 functions.

**Version your scripts.** Keep your scripts in a directory versioned with Git. They constitute reusable capital from one analysis project to another. The `~/ghidra_scripts/` directory is a good candidate for making it a Git repo.

---

## Summary

Scripting is the lever that transforms Ghidra from an interactive tool into an automated analysis platform. The Flat API provides simplified access to the program's functions, instructions, data, references, and types, both in Python (Jython) and in Java. Pre-integrated scripts offer a library of immediately exploitable examples, and the interactive Python console enables exploration and quick prototyping. For advanced needs, the internal API gives access to the decompiler, the P-Code model, and all of Ghidra's data structures.

Chapter 35 (Automation and scripting) will return to Ghidra scripting in a large-scale automation context, including the headless mode we address in the next section.

---


⏭️ [Ghidra in headless mode for batch processing](/08-ghidra/09-headless-mode-batch.md)
