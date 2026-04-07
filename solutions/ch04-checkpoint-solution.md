🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Checkpoint Solution — Chapter 4

> **Exercise**: Run `check_env.sh` and get zero critical failures.

---

## Procedure

```bash
# 1. Activate the Python virtual environment
source ~/re-venv/bin/activate

# 2. Navigate to the repository root
cd ~/formation-re

# 3. Make the script executable
chmod +x check_env.sh

# 4. Run the script
./check_env.sh
```

---

## Expected Result

The script should end with:

```
  RESULT: XX/XX checks passed
          0 critical failure(s)
          N optional item(s) missing

  ✔ Your environment is ready for the training.
```

The exit code should be `0`:

```bash
echo $?
# 0
```

---

## Validation Criteria

| Category | Verified elements | Expected result |  
|---|---|---|  
| **System base** | gcc, g++, make, python3, java (JRE), gdb | All `[✔]` |  
| **Binutils** | objdump, readelf, nm, strings, c++filt, strip, ldd | All `[✔]` |  
| **Tracing** | strace, ltrace | All `[✔]` |  
| **Disassemblers** | Ghidra (analyzeHeadless), Radare2 (r2) | All `[✔]` |  
| **Hex editor** | ImHex | `[✔]` |  
| **GDB extension** | GEF, pwndbg or PEDA | At least one `[✔]` |  
| **Python libs** | angr, pwntools, frida, z3, pyelftools, lief, r2pipe, yara | All `[✔]` |  
| **Fuzzing** | AFL++ (afl-fuzz) | `[✔]` |  
| **Memory analysis** | Valgrind | `[✔]` |  
| **Detection** | checksec, YARA | All `[✔]` |  
| **System** | x86-64 architecture, disk space >= 15 GB, RAM >= 4 GB | No `[✗]` |  
| **Binaries** | ch* subdirectories compiled via `make all` | Correct count |

---

## Resolving Common Failures

### `[✗]` on a command-line tool

```bash
# Identify the missing package
apt search <tool>

# Install
sudo apt install -y <package>
```

### `[✗]` on a Python package

```bash
# Make sure the venv is activated
source ~/re-venv/bin/activate

# Install the missing package
pip install <package>
```

### `[✗]` on Ghidra

Ghidra is not in APT repositories. Verify that the installation directory is in your `PATH`:

```bash
echo $PATH | tr ':' '\n' | grep -i ghidra
# If empty, add to ~/.bashrc:
export PATH="$PATH:/opt/ghidra/support"
```

### `[✗]` on training binaries

```bash
cd ~/formation-re/binaries  
make all  
```

### `[✗]` on GDB extension

Verify that your `~/.gdbinit` loads the extension:

```bash
cat ~/.gdbinit | grep -E 'gef|pwndbg|peda'
```

If no line appears, add the one for your chosen extension (only one):

```bash
# For GEF:
echo 'source ~/.gdbinit-gef.py' >> ~/.gdbinit

# For pwndbg:
echo 'source ~/pwndbg/gdbinit.py' >> ~/.gdbinit
```

---

## Keep the Log

```bash
./check_env.sh | tee ~/check_env_$(date +%Y%m%d).log
```

This log serves as a reference in case of future issues (system update, snapshot restore).

---

## Take the Snapshot

After validation (0 critical failures), take the reference snapshot:

**VirtualBox**: Machine → Take Snapshot → `tools-ready`

**QEMU/KVM**:
```bash
virsh snapshot-create-as RE-Lab tools-ready --description "Chapter 4 checkpoint OK"
```

This snapshot represents the training's reference state: system installed, tools configured, binaries compiled, all green.

---

⏭️ [Part II — Static Analysis](/part-2-static-analysis.md)
