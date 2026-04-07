🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 13.2 — Injection modes: `frida`, `frida-trace`, spawn vs attach

> 🧰 **Tools used**: `frida`, `frida-trace`, `frida-ps`, Python 3 + `frida` module  
> 📦 **Binaries used**: `binaries/ch13-keygenme/keygenme_O0`  
> 📖 **Prerequisites**: [13.1 — Frida's architecture](/13-frida/01-frida-architecture.md)

---

## Two fundamental injection strategies

In section 13.1, we saw that Frida injects its agent into the target process. An immediate practical question remains: **when** does this injection occur relative to the program's lifecycle? The answer defines Frida's two fundamental modes, and the choice between them conditions what you can or cannot instrument.

### Attach mode: hook into an existing process

In this mode, the target program is already running. Frida attaches to it, injects the agent, and instrumentation begins from that point.

```bash
# The program is already running (PID 4567)
frida -p 4567 -l my_script.js
```

Or by process name:

```bash
frida -n keygenme_O0 -l my_script.js
```

In Python:

```python
import frida

session = frida.attach("keygenme_O0")   # by name
# or
session = frida.attach(4567)            # by PID
```

**When to use it.** Attach mode is the natural choice when the target is a long-running service (a server, a daemon), when you want to instrument a program already in an interesting state (network connection established, file opened), or when you don't control the program's launch (process started by another service).

**The limitation.** Everything that executed before attachment is invisible. If the function you want to hook has already been called — a C++ global constructor, an initialization routine, a license check executed at `main()` before any interaction — you arrive too late. Hooks only apply to **future** calls of the function.

### Spawn mode: launch and instrument from the start

In this mode, Frida launches the program itself, suspends it before the first user instruction executes, injects the agent, then releases the process.

```bash
frida -f ./keygenme_O0 -l my_script.js
```

The `-f` flag (for *file*) tells Frida to spawn the binary. The process is created in a suspended state: the dynamic loader (`ld.so`) has done its work (loading libraries, PLT/GOT resolution), but `main()` hasn't started yet — nor even `__attribute__((constructor))` constructors in most cases.

In Python:

```python
import frida

pid = frida.spawn(["./keygenme_O0"])  
session = frida.attach(pid)  

script = session.create_script("""
    // Hooks installed here, BEFORE main() executes
    Interceptor.attach(Module.findExportByName(null, "strcmp"), {
        onEnter(args) {
            send({
                a: args[0].readUtf8String(),
                b: args[1].readUtf8String()
            });
        }
    });
""")
script.load()

frida.resume(pid)  // The program starts now, with hooks in place
```

The crucial detail is the call to `frida.resume(pid)`. After `spawn`, the process is paused. You have all the time to install your hooks. When you call `resume`, the program starts and every `strcmp` call will be intercepted from the very first — including those occurring in `main()` or in global constructors.

In CLI, Frida displays a `[Local::keygenme_O0]->` prompt after the spawn. The process is suspended. You can type `%resume` to restart it:

```
     ____
    / _  |   Frida 16.x.x - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       %resume   -> Resume the main thread of the spawned process

[Local::keygenme_O0]-> %resume
```

### The deciding question: "Do I need the startup?"

The choice between attach and spawn often comes down to this question. Here are common scenarios:

| Scenario | Recommended mode | Reason |  
|---|---|---|  
| Hook `strcmp` during password input (after startup) | **attach** | Verification happens after user interaction — no rush |  
| Hook an `__attribute__((constructor))` constructor | **spawn** | Executes before `main()`, impossible to catch in attach |  
| Instrument a permanently running server | **attach** | Server is already launched, you want to observe future requests |  
| Analyze a malware's initialization routine | **spawn** | Interesting behavior occurs immediately at launch |  
| Bypass an anti-debug check at startup | **spawn** | Must hook the check before it executes |  
| Interactively explore an already-running program | **attach** | Program is in an interesting state you don't want to lose |

In practice, **spawn** mode is the safest when you don't yet know the binary: you're certain to miss nothing. **Attach** mode is more practical for interactive sessions and persistent services.

---

## Command-line tools

Frida provides several executables, each suited to a different use. They all share the same injection mechanism (attach or spawn), but differ in what they do once the agent is in place.

### `frida` — the interactive REPL

The `frida` command opens an interactive session with a JavaScript prompt. It's the equivalent of GDB's interactive mode: you type commands, explore, experiment.

```bash
# Interactive attach
frida -n keygenme_O0

# Interactive spawn
frida -f ./keygenme_O0
```

Once in the REPL, you have access to the full Frida API:

```javascript
// List loaded modules
Process.enumerateModules().forEach(m => console.log(m.name, m.base));

// Find the address of an exported function
Module.findExportByName(null, "strcmp")
// => "0x7f3a8b2c4560"

// Read a string at an address
Memory.readUtf8String(ptr("0x402010"))

// Set up a quick hook
Interceptor.attach(Module.findExportByName(null, "puts"), {
    onEnter(args) {
        console.log("puts() called with:", args[0].readUtf8String());
    }
});
```

The REPL is ideal for the exploratory phase: you search for addresses, test hooks, validate hypotheses before writing a complete script. Tab completion works on Frida API objects.

**Loading a script from a file.** You can combine the REPL with a script file via the `-l` option:

```bash
frida -f ./keygenme_O0 -l hooks.js
```

The script is loaded and executed automatically, and the REPL stays open for additional commands. It's the most common workflow: a script file for the main hooks, the REPL for live adjustments.

**The `--no-pause` flag.** By default in spawn mode, Frida suspends the process and waits for `%resume`. If your script is autonomous and doesn't need manual intervention between loading and launching, the `--no-pause` flag chains automatically:

```bash
frida -f ./keygenme_O0 -l hooks.js --no-pause
```

### `frida-ps` — list processes

Simple utility that lists accessible processes, useful for finding a PID or verifying that a target process is running:

```bash
# Local processes
frida-ps

# With PIDs
frida-ps -a

# On a remote device (via frida-server)
frida-ps -H 192.168.1.100
```

### `frida-trace` — quick tracing without writing code

`frida-trace` is the most immediately productive tool of the Frida suite. It automatically generates hooks for the functions you specify, without writing a single line of JavaScript.

```bash
# Trace all calls to strcmp and strlen in keygenme_O0
frida-trace -f ./keygenme_O0 -i "strcmp" -i "strlen"
```

Typical output:

```
Instrumenting...  
strcmp: Auto-generated handler at /tmp/__handlers__/libc.so.6/strcmp.js  
strlen: Auto-generated handler at /tmp/__handlers__/libc.so.6/strlen.js  
Started tracing 2 functions. Press Ctrl+C to stop.  

           /* TID 0x1234 */
  3245 ms  strcmp(s1="SECRETKEY", s2="userinput")
  3245 ms  strlen(s="userinput")
```

What just happened is remarkable: in a single command, without any script, you obtained the `strcmp` arguments — and potentially the crackme's secret key. What would have required a conditional breakpoint in GDB, then manual inspection of registers `rdi` and `rsi`, is done here in seconds.

**Function selection options:**

The `-i` option (for *include*) accepts function names and globs:

```bash
# All functions starting with "str"
frida-trace -f ./keygenme_O0 -i "str*"

# All functions containing "crypt"
frida-trace -f ./keygenme_O0 -i "*crypt*"

# Combine multiple patterns
frida-trace -f ./keygenme_O0 -i "strcmp" -i "memcmp" -i "open"
```

The `-x` option (for *exclude*) excludes functions from tracing:

```bash
# Trace all "str*" functions except strlen
frida-trace -f ./keygenme_O0 -i "str*" -x "strlen"
```

The `-I` (uppercase) option filters by module (library):

```bash
# Only functions from the main binary, not from libc
frida-trace -f ./keygenme_O0 -I "keygenme_O0"
```

**Auto-generated handlers.** `frida-trace` creates JavaScript files in a `__handlers__/` folder. Each file contains a hook skeleton you can modify:

```javascript
// __handlers__/libc.so.6/strcmp.js (auto-generated)
{
  onEnter(log, args, state) {
    log('strcmp(' +
      'a="' + args[0].readUtf8String() + '"' +
      ', b="' + args[1].readUtf8String() + '"' +
    ')');
  },
  onLeave(log, retval, state) {
    // log('strcmp retval=' + retval);
  }
}
```

You can edit this file to add logic — filter certain calls, log the return value, save arguments to a file. On the next `frida-trace` launch, it will reuse your modified version instead of generating a new one. It's a natural progression path: start with auto-generated raw tracing, then refine handlers as you understand the binary better.

**Tracing system calls with `-S` (Stalker).** Since recent versions, `frida-trace` can also trace system calls directly:

```bash
frida-trace -f ./keygenme_O0 -S open -S read -S write
```

### `frida-kill` — terminate a process

Simple utility to kill a process by PID, useful in automation scripts:

```bash
frida-kill 4567
```

### `frida-ls-devices` — list accessible devices

Lists Frida "devices": the local machine, connected USB devices (Android/iOS), and remote `frida-server` instances:

```bash
frida-ls-devices
```

---

## Python scripting: production mode

CLI tools are perfect for exploration, but complex RE scenarios require a structured Python script. The Python `frida` module offers total control over the instrumentation lifecycle.

### Anatomy of a Python Frida script

A Python Frida script always follows the same five-step structure:

```python
import frida  
import sys  

# 1. JavaScript agent code (executed INSIDE the target process)
agent_code = """
'use strict';

// Hook on strcmp
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        this.arg0 = args[0].readUtf8String();
        this.arg1 = args[1].readUtf8String();
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            send({
                event: "strcmp_match",
                a: this.arg0,
                b: this.arg1
            });
        }
    }
});
"""

# 2. Callback for messages received from the agent
def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(f"[*] strcmp match: '{payload['a']}' == '{payload['b']}'")
    elif message['type'] == 'error':
        print(f"[!] Agent error: {message['stack']}")

# 3. Launch the process (spawn)
pid = frida.spawn(["./keygenme_O0"])  
session = frida.attach(pid)  

# 4. Load and activate the script
script = session.create_script(agent_code)  
script.on('message', on_message)  
script.load()  

# 5. Resume execution and wait
frida.resume(pid)  
print("[*] Hooks active. Ctrl+C to quit.")  
sys.stdin.read()  # Block until interruption  
```

Let's detail the key steps.

**Step 1: the agent code.** It's a Python string containing JavaScript. This code will be executed by the V8 engine inside the target process. You use `send()` to send data to the Python script, and the Frida API (`Interceptor`, `Module`, `Memory`…) to interact with the process.

> 💡 **Best practice**: use `'use strict';` at the start of agent scripts to enable JavaScript strict mode, which turns silent errors into explicit errors and helps debugging.

**Step 2: the `on_message` callback.** Each call to `send()` in the agent triggers this callback on the Python side. The `message` parameter is a dictionary with a `type` field (`'send'` for normal messages, `'error'` for JavaScript exceptions) and a `payload` field containing the JSON sent by `send()`. The `data` parameter contains optional binary data (we'll see this mechanism in section 13.4).

**Step 3: spawn + attach.** `frida.spawn()` creates the process in suspended state and returns its PID. `frida.attach()` connects a Frida session to this PID. These two steps are separated to allow installing hooks between them.

**Step 5: resume + wait.** `frida.resume()` releases the process. `sys.stdin.read()` blocks the Python script indefinitely (until Ctrl+C), which keeps the Frida session active. Without this wait, the Python script would end, the session would be destroyed, and the agent would be unloaded from the process.

### Variant: attach to an existing process

```python
# Instead of spawn + resume:
session = frida.attach("keygenme_O0")  # or frida.attach(pid)

script = session.create_script(agent_code)  
script.on('message', on_message)  
script.load()  
# No resume() — the process was already running

sys.stdin.read()
```

### Variant: detect process end

When the target process terminates (normal exit, crash, kill), the Frida session is destroyed. You can react to this event:

```python
def on_detached(reason):
    print(f"[*] Detached: {reason}")
    # reason: "application-requested", "process-terminated", "server-terminated"...

session.on('detached', on_detached)
```

This allows writing robust scripts that don't stay blocked after the target process ends, or that automatically relaunch instrumentation.

---

## Passing arguments to the target process

In spawn mode, command-line arguments are passed to the process via the list provided to `frida.spawn()`:

```python
# Equivalent of: ./keygenme_O0 mypassword
pid = frida.spawn(["./keygenme_O0", "mypassword"])
```

In CLI:

```bash
frida -f ./keygenme_O0 -l hooks.js -- mypassword
```

The double dash `--` separates Frida arguments from the target program's arguments. Everything after `--` is transmitted to the process.

For programs that read their input on `stdin` rather than via arguments, the situation is more delicate in spawn mode, because Frida controls the launch. In Python, the process inherits the Python script's `stdin`, allowing you to send data via a pipe:

```bash
echo "mypassword" | python3 my_frida_script.py
```

Or by redirecting a file:

```bash
python3 my_frida_script.py < inputs.txt
```

---

## Environment variables and working directory

`frida.spawn()` accepts additional options to configure the process's environment:

```python
pid = frida.spawn(
    ["./keygenme_O0"],
    env={
        "LD_LIBRARY_PATH": "/opt/libs",
        "MY_DEBUG_FLAG": "1"
    },
    cwd="/home/user/binaries/ch13-keygenme"
)
```

This avoids modifying the Python script's own environment and gives precise control over the target process's execution context.

---

## Sessions, scripts, and lifecycle

When you start writing non-trivial Frida scripts, it's important to understand the object hierarchy and their lifetimes.

**Device** → The system where the target process runs (local machine, USB device, remote server). Obtained implicitly or via `frida.get_local_device()`.

**Session** → The connection to a specific process. Created by `frida.attach()`. Destroyed when the process ends, when you call `session.detach()`, or when the Python script ends.

**Script** → A JavaScript script loaded into a session. You can load multiple scripts into the same session. Each script has its own JavaScript scope, but they share the same address space (since they execute in the same process).

```python
session = frida.attach(pid)

# Two independent scripts in the same session
script_hooks = session.create_script(hooks_js_code)  
script_monitor = session.create_script(monitoring_js_code)  

script_hooks.load()  
script_monitor.load()  
```

The ability to load multiple scripts is useful for separating concerns: one script for function hooks, another for memory monitoring, a third for code coverage. Each sends its messages with a distinct format, and the Python callback routes them.

---

## Spawn gating: intercepting child processes

Some programs create child processes via `fork()` or `exec()`. By default, Frida only follows the parent process. **Spawn gating** allows automatically intercepting child processes:

```python
device = frida.get_local_device()  
device.on('child-added', on_child_added)  
device.enable_spawn_gating()  

def on_child_added(child):
    print(f"[*] New child process: PID {child.pid}")
    child_session = device.attach(child.pid)
    # Instrument the child...
    device.resume(child.pid)
```

This mechanism is particularly useful when analyzing malware that forks to bypass debugging (parent dies, child continues), or network services that create a child process per client connection.

---

## Commands and options summary

| Command | Mode | Usage |  
|---|---|---|  
| `frida -p <PID> -l script.js` | attach | Instrument an existing process |  
| `frida -n <name> -l script.js` | attach | Same, by process name |  
| `frida -f ./binary -l script.js` | spawn | Launch and instrument from the start |  
| `frida -f ./binary -l script.js --no-pause` | spawn | Spawn without waiting for `%resume` |  
| `frida -f ./binary -- arg1 arg2` | spawn | Pass arguments to the binary |  
| `frida-trace -f ./binary -i "func"` | spawn | Quick auto-generated tracing |  
| `frida-trace -n <name> -i "func*"` | attach | Tracing with globs on existing process |  
| `frida-ps` | — | List processes |  
| `frida-kill <PID>` | — | Terminate a process |

---

## What to remember

- **Attach** hooks into an existing process — practical but you miss everything that executed before injection.  
- **Spawn** launches the binary in suspended state, injects the agent, then resumes — guarantees missing nothing, indispensable for initialization code.  
- **`frida`** opens an interactive JavaScript REPL, ideal for exploration.  
- **`frida-trace`** automatically generates hooks for specified functions — the fastest tool for a first look at a binary's dynamic behavior.  
- In **Python**, the cycle is `spawn` → `attach` → `create_script` → `load` → `resume`, with an `on_message` callback to receive agent data.  
- The `--no-pause` flag and the `frida.resume()` method control when the process actually starts executing.  
- **Spawn gating** allows following child processes created by `fork`/`exec`.

---

> **Next section**: 13.3 — Hooking C and C++ functions on the fly — we'll dive into the `Interceptor` API and learn to hook functions with and without symbols.

⏭️ [Hooking C and C++ functions on the fly](/13-frida/03-hooking-c-cpp-functions.md)
