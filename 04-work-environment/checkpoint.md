🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 4

> **Goal**: validate that your reverse engineering environment is complete, functional, and ready to host the next 32 chapters. This checkpoint is the last lock before we get to the real work.

---

## What you should have at this stage

If you followed sections 4.1 through 4.7, your environment consists of:

- an Ubuntu 24.04 LTS (or Debian/Kali) **VM** in x86-64, with at least 4 GB RAM and 60 GB of disk;  
- **two configured network interfaces**: NAT (for Internet) and host-only (for isolation);  
- all the **RE tools** installed (waves 1 through 5 of section 4.2);  
- a **Python virtual environment** (`re-venv`) containing angr, pwntools, Frida, pyelftools, LIEF, Z3, and the other libraries;  
- an active **GDB extension** (GEF, pwndbg, or PEDA);  
- all **training binaries** compiled via `make all` in `binaries/`;  
- a VM **`tools-ready` snapshot** in that state.

---

## Validation: run `check_env.sh`

Activate your Python virtual environment, go to the repository root, and launch the script:

```bash
[vm] source ~/re-venv/bin/activate
[vm] cd ~/formation-re
[vm] chmod +x check_env.sh
[vm] ./check_env.sh
```

### Expected result

The script should end with the message:

```
  ✔ Your environment is ready for the training.
```

with **zero critical failures** (`0 critical failure(s)`).

Items marked `[~]` (optional missing) are acceptable — they concern tools needed only for bonus parts (VII, VIII) or non-blocking components like `kcachegrind`, `sysdig`, or `bindiff`. You can install them later if needed.

### If critical failures appear

Each `[✗]` line in the script output identifies a missing or misconfigured tool. Section 4.7 details the causes and fixes for each common case. The cycle is simple:

1. Identify the `[✗]` lines.  
2. Apply the fix (usually an `apt install` or a `pip install`).  
3. Rerun `./check_env.sh`.  
4. Repeat until zero critical failures.

---

## Success criteria

| Criterion | Expected |  
|---|---|  
| Critical failures (`[✗]`) | **0** |  
| System foundations (gcc, g++, python3, java, gdb) | All `[✔]` |  
| Disassemblers (Ghidra, Radare2, ImHex) | All `[✔]` |  
| GDB extension (GEF, pwndbg, or PEDA) | At least one `[✔]` |  
| Python virtual environment active | `[✔]` |  
| Python libraries (angr, pwntools, frida, z3) | All `[✔]` |  
| C/C++ training binaries (ch21–ch29) | All `[✔]` with the right count |  
| System configuration (ptrace_scope, disk space, RAM) | No `[✗]` |  
| Script exit code | `0` (success) |

---

## Keep a record

Keep a dated log of the script's output. It will serve as a reference in case of future issues (system update, snapshot restore, VM migration):

```bash
[vm] ./check_env.sh | tee ~/check_env_$(date +%Y%m%d).log
```

---

## Take the reference snapshot

If not already done, this is the time to take (or update) the `tools-ready` snapshot of your VM. This snapshot is the training's reference state: system installed, tools configured, binaries compiled, everything green.

**VirtualBox**: Machine → Take Snapshot → `tools-ready`

**QEMU/KVM**:
```bash
[host] virsh snapshot-create-as RE-Lab tools-ready --description "Chapter 4 checkpoint OK"
```

**UTM**: camera icon → `tools-ready`

> 💡 If a `tools-ready` snapshot already existed, delete it and recreate it so it reflects the most recent state.

---

## What next?

Your lab is operational. You have all the tools, all the target binaries, and an isolated, reproducible environment.

**Part II — Static Analysis** begins at Chapter 5 with the basic binary inspection tools. You will immediately put the environment built here into practice: `file`, `strings`, `readelf`, `objdump`, `checksec` — all verified and ready for use by `check_env.sh`.


⏭️ [Part II — Static Analysis](/part-2-static-analysis.md)
