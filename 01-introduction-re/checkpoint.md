🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Chapter 1

> **Chapter 1 — Introduction to Reverse Engineering**  
> 🎯 This checkpoint validates your understanding of the fundamental concepts before moving on to Chapter 2.  
> ⏱️ Estimated time: 10 minutes.

---

## Goal

The distinction between static analysis and dynamic analysis is one of the structuring concepts of this training (cf. [section 1.4](/01-introduction-re/04-static-vs-dynamic.md)). This checkpoint asks you to classify five concrete scenarios into one or the other category — or to identify cases that fall under both.

Beyond simple classification, the goal is to make sure you understand **why** each scenario falls under one approach rather than the other. The decisive criterion, to recall, is simple: is the program executed during the analysis, or not?

---

## The 5 scenarios

Read each scenario and determine whether it falls under **static analysis**, **dynamic analysis**, or a **combination of both**. Justify your answer in one or two sentences.

---

### Scenario 1

> You receive a suspicious ELF binary as part of an incident response. Before any execution, you run `file` to identify the format, `strings` to extract readable strings, and `readelf -S` to list the sections. You spot a string that looks like a C2 server URL.

---

### Scenario 2

> You have identified the password verification function of a crackme thanks to Ghidra. To confirm your understanding of the algorithm, you launch the program in GDB, set a breakpoint just before the `strcmp` call, enter an arbitrary password, and inspect the `rdi` and `rsi` registers to see the two strings being compared.

---

### Scenario 3

> You open a binary in Ghidra. You navigate the control flow graph of the `main` function, rename local variables based on their apparent usage, add comments on the conditional blocks, and reconstruct a `struct packet_header` from the memory-access offsets observed in the decompiled pseudo-code.

---

### Scenario 4

> You are analyzing a network binary. You launch it in a sandboxed environment while Wireshark captures the traffic on the local interface. In parallel, you run `strace` to observe the `connect`, `send`, and `recv` system calls. You identify the IP address of the remote server and the structure of the first packets exchanged.

---

### Scenario 5

> You suspect that a binary is packed with UPX. To verify, you examine the section names with `readelf -S` (you find `UPX0` and `UPX1`), then you launch the binary in GDB, set a breakpoint on the original entry point (OEP) after decompression, and dump the decompressed code from memory to analyze it in Ghidra.

---

## Answers

> ⚠️ **Try to answer before reading the solutions below.** The checkpoint only has value if you formulate your own answers first.

<details>
<summary><strong>Click to reveal the answers</strong></summary>

---

### Scenario 1 — Static analysis

The binary is never executed. All the operations (`file`, `strings`, `readelf`) examine the file as it is stored on disk. This is the triage phase, which is entirely static. The C2 server URL was found in the binary's embedded data, not by observing an actual network connection.

---

### Scenario 2 — Combination of both

This scenario illustrates the static → dynamic cycle described in section 1.4. The identification of the verification function and locating the `strcmp` call were done via **static analysis** (reading the decompiled code in Ghidra). The confirmation by setting a breakpoint, running the program, and inspecting the registers falls under **dynamic analysis** (the program is running). This is a textbook example of the complementarity between the two approaches: the static side identifies *where* to look, the dynamic side reveals the *concrete values*.

---

### Scenario 3 — Static analysis

The binary is not executed. All the work — navigating the CFG, renaming variables, adding comments, reconstructing structures — is done on the disassembled and decompiled representation of the binary in Ghidra. This is in-depth static analysis: you read and annotate the code without ever running it.

---

### Scenario 4 — Dynamic analysis

The program is executed in a sandbox, and its behavior is observed in real time through two channels: network traffic captured by Wireshark, and system calls traced by `strace`. The analyst is not examining the disassembled code here — they observe what the program **does** (connect to an IP address, send packets of a certain structure). This is pure dynamic analysis: the information comes entirely from observing the execution.

---

### Scenario 5 — Combination of both

This scenario chains both approaches sequentially. Examining the section names with `readelf` is a **static** operation — you read the structure of the file on disk to identify the packer. Launching it in GDB, setting a breakpoint on the OEP, and dumping the decompressed code from memory fall under **dynamic analysis** — the program must run for decompression to take place. Subsequent analysis of the dumped code in Ghidra will again be static. This is a typical case of packed-binary RE, where dynamic analysis is necessary to obtain the real code before it can be analyzed statically.

</details>

---

## Self-assessment

If you correctly classified the five scenarios and your justifications align with the logic laid out above, you have absorbed the fundamental concepts of Chapter 1. You can move on to Chapter 2.

If you hesitated on one or more scenarios, re-read [section 1.4 — Difference between static RE and dynamic RE](/01-introduction-re/04-static-vs-dynamic.md) before continuing. The central criterion is always the same: **is the program executed during the described operation?** If yes, it is dynamic analysis. If not, it is static analysis. If the scenario chains both, it is a combination — and that is the most common case in practice.

---


⏭️ [Chapter 2 — The GNU Compilation Chain](/02-gnu-compilation-chain/README.md)
