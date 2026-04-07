🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 13 — Dynamic instrumentation with Frida

> 📦 **Binaries used**: `binaries/ch13-keygenme/`, `binaries/ch13-network/`, `binaries/ch14-crypto/`  
> 🧰 **Required tools**: `frida`, `frida-tools`, `frida-trace`, Python 3 with the `frida` module  
> 📖 **Prerequisites**: [Chapter 11 — GDB](/11-gdb/README.md), [Chapter 12 — Enhanced GDB](/12-gdb-extensions/README.md), JavaScript basics

---

## Why this chapter?

In Chapters 11 and 12, we explored classic debugging with GDB and its extensions. GDB is an extraordinarily powerful tool, but it imposes a fundamental constraint: the target program's execution is **interrupted** at each breakpoint. You work in "stop-and-inspect" mode — you stop the process, inspect its state, resume. This approach becomes laborious when you want to observe a large number of function calls, modify return values on the fly across hundreds of invocations, or interact with a program without it perceiving the slightest interruption.

Frida radically changes the game. Instead of suspending the process, Frida **injects a JavaScript agent directly into the target program's memory space**, while it's running. This agent can read and write memory, intercept function calls, replace arguments, modify return values — all **without ever stopping execution**. The program continues to run normally, unaware that an invisible observer is rewriting the rules in real time.

If GDB is a microscope that requires the sample's immobility, Frida is an onboard camera that films continuously.

---

## What Frida brings to the reverse engineer

Frida's use cases in RE are numerous, but they revolve around a few recurring scenarios:

**Observe without disturbing.** You want to know which functions are called, with what arguments, and what they return — without altering the program's behavior. It's the dynamic equivalent of a cross-reference analysis in Ghidra, but with real execution values instead of static assumptions.

**Modify behavior live.** A license-verification function returns `0` (failure)? You can force the return to `1` without touching the on-disk binary. A `connect()` call points to a remote server? You can redirect the arguments to `127.0.0.1`. Frida allows testing RE hypotheses instantly, without a patching–recompilation–relaunch cycle.

**Trace execution at scale.** With the Stalker engine, Frida can instrument every instruction executed by a given thread. You thus obtain complete dynamic code coverage — precious information for understanding which paths are actually taken, which branches remain dead, and how the program reacts to different inputs.

**Automate complex interactions.** Combined with Python on the controller side, Frida allows scripting complete scenarios: inject data, observe the program's reaction, adjust inputs accordingly. It's halfway between debugging and guided fuzzing.

---

## Frida in our methodology

This chapter fits in the logical progression of Part III (Dynamic Analysis). Until now, our dynamic toolbox comprised:

- **`strace` / `ltrace`** (Chapter 5) — passive observation of system and library calls, with no control over the process.  
- **GDB** (Chapters 11–12) — total but intrusive control, with execution halted at each inspection point.

Frida positions itself between the two: more powerful than `strace` (you can modify behavior, not just observe it), and less intrusive than GDB (no execution halt). In the following chapters of Part V (Practical Cases), we'll use Frida intensively — to extract encryption keys from memory (Chapter 24), intercept network communications (Chapter 23), and bypass anti-debug protections that would render GDB unusable (Chapter 19).

---

## Scope and limits

Frida is a cross-platform framework that works on Linux, Windows, macOS, Android, and iOS. In the context of this training, we focus exclusively on **Linux x86-64** with ELF binaries compiled by GCC/G++, consistent with the tutorial's scope. The concepts and JavaScript APIs presented here are however directly transferable to other platforms — only injection details and library names change.

It's important to keep in mind that Frida is not inherently a stealth tool. A program determined to detect instrumentation can do so (presence of `frida-agent` in memory, additional threads, timing anomalies). We'll briefly address these detection aspects here, and Chapter 19 (Anti-reversing) will deepen debugger and instrumentation detection techniques.

---

## Chapter outline

- **13.1** — [Frida's architecture — JS agent injected into the target process](/13-frida/01-frida-architecture.md)  
- **13.2** — [Injection modes: `frida`, `frida-trace`, spawn vs attach](/13-frida/02-injection-modes.md)  
- **13.3** — [Hooking C and C++ functions on the fly](/13-frida/03-hooking-c-cpp-functions.md)  
- **13.4** — [Intercepting calls to `malloc`, `free`, `open`, custom functions](/13-frida/04-intercepting-calls.md)  
- **13.5** — [Modifying arguments and return values live](/13-frida/05-modifying-arguments-returns.md)  
- **13.6** — [Stalker: tracing all executed instructions (dynamic code coverage)](/13-frida/06-stalker-code-coverage.md)  
- **13.7** — [Practical case: bypassing a license check](/13-frida/07-practical-license-bypass.md)  
- **🎯 Checkpoint** — [Write a Frida script that logs all calls to `send()` with their buffers](/13-frida/checkpoint.md)

---

## Quick installation

Before starting section 13.1, make sure Frida is installed and functional:

```bash
# Installation via pip (Python 3)
pip install frida-tools frida

# Version check
frida --version

# Quick test: list local processes
frida-ps
```

If `frida-ps` displays the list of running processes, the environment is ready. In case of permission issues, running as `sudo` may be necessary for injection into processes belonging to other users — we'll detail the implications in section 13.1.

> 💡 The `check_env.sh` script provided at the repository root automatically checks for Frida's presence among other required tools.

⏭️ [Frida's architecture — JS agent injected into the target process](/13-frida/01-frida-architecture.md)
