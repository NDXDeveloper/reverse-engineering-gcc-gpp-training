🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Checkpoint Solution — Chapter 1

> **Exercise**: Classify 5 scenarios as "static analysis", "dynamic analysis" or "combination of both".

---

## Classification Criterion

The determining criterion is: **is the program executed during the described operation?**

- **No** → Static analysis  
- **Yes** → Dynamic analysis  
- **Both** → Combination

---

## Scenario 1 — Static Analysis

> Triage of a suspect ELF binary with `file`, `strings`, `readelf -S`.

**Classification: Static analysis**

The binary is never executed. All operations (`file`, `strings`, `readelf`) examine the file as it is stored on disk. This is the triage phase (cf. section 1.5, Phase 1), which is entirely static. The C2 server URL was found in the binary's embedded data, not by observing an actual network connection.

---

## Scenario 2 — Combination of Both

> Identification of the verification function in Ghidra, then confirmation with GDB by inspecting registers at a breakpoint on `strcmp`.

**Classification: Static + dynamic combination**

This scenario illustrates the static → dynamic cycle described in section 1.4. The identification of the verification function and locating the `strcmp` call were performed through **static analysis** (reading the decompiled code in Ghidra). The confirmation by setting a breakpoint, executing the program and inspecting registers falls under **dynamic analysis** (the program is running).

This is the typical example of complementarity between both approaches: static identifies *where* to look, dynamic reveals the *concrete values*.

---

## Scenario 3 — Static Analysis

> Navigating `main`'s CFG in Ghidra, renaming variables, adding comments, reconstructing a structure.

**Classification: Static analysis**

The binary is not executed. All the work — CFG navigation, variable renaming, adding comments, structure reconstruction — is done on the disassembled and decompiled representation of the binary in Ghidra. This is in-depth static analysis (cf. section 1.5, Phase 2): reading and annotating the code without ever running it.

---

## Scenario 4 — Dynamic Analysis

> Executing the binary in a sandbox with Wireshark capture and `strace` tracing.

**Classification: Dynamic analysis**

The program is executed in a sandbox, and its behavior is observed in real-time through two channels: network traffic captured by Wireshark and system calls traced by `strace`. The analyst does not examine disassembled code — they observe what the program **does** (connecting to an IP address, sending packets with a certain structure). The information comes entirely from observing execution.

---

## Scenario 5 — Combination of Both

> Checking for UPX packing with `readelf -S` (static), then launching in GDB to breakpoint at the OEP and dump the decompressed code (dynamic).

**Classification: Static + dynamic combination**

This scenario chains both approaches sequentially:

1. **Static**: Examining section names with `readelf` — reading the file structure on disk to identify the packer (`UPX0`, `UPX1` sections).  
2. **Dynamic**: Launching in GDB, setting a breakpoint at the OEP and dumping the decompressed code from memory — the program must execute for decompression to occur.  
3. **Static** (continued): Analyzing the dumped code in Ghidra will be static again.

This is a typical case of packed binary RE, where dynamic analysis is necessary to obtain the actual code before being able to analyze it statically.

---

## Summary

| Scenario | Classification | Key reason |  
|----------|---------------|------------|  
| 1 | Static | `file`, `strings`, `readelf` — no execution |  
| 2 | Combination | Ghidra (static) + GDB breakpoint (dynamic) |  
| 3 | Static | Ghidra CFG, renaming, annotations — no execution |  
| 4 | Dynamic | Sandbox execution + Wireshark + `strace` |  
| 5 | Combination | `readelf` (static) + GDB memory dump (dynamic) |

---

⏭️ [Chapter 2 — The GNU Compilation Chain](/02-gnu-compilation-chain/README.md)
