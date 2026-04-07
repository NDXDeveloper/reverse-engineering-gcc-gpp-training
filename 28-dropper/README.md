🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 28 — Analysis of an ELF Dropper with Network Communication

> ⚠️ **Security reminder** — The binary analyzed in this chapter (`dropper_sample`) is a sample **created by us**, for strictly educational purposes. It must **never** be executed outside the sandboxed VM set up in [Chapter 26](/26-secure-lab/README.md). No real malware is distributed in this training.

---

## Chapter objectives

A **dropper** is a program whose primary function is to drop or download a payload onto the target system, then execute it. Unlike a ransomware that carries its own destructive logic, the dropper is merely a **delivery vehicle**: it communicates with a command and control (C2) server to receive instructions, download additional components, and orchestrate the next stages of infection.

This chapter puts you in the shoes of an analyst who receives a suspicious ELF binary exhibiting abnormal network activity. Your mission is to **fully understand** its behavior, from network system calls to the C2 protocol it implements, then demonstrate your understanding by writing a fake C2 server capable of controlling it.

By the end of this chapter, you will be able to:

- **Identify and trace network calls** from a suspicious binary using `strace` and Wireshark, correlating observed syscalls with captured network frames.  
- **Hook socket functions** (`connect`, `send`, `recv`, `socket`, `getaddrinfo`...) with Frida to intercept exchanged data in real time, without modifying the binary.  
- **Reconstruct a custom C2 protocol** by identifying the initial handshake, command format, encoding used, and the client's state machine.  
- **Write a fake C2 server** in Python that simulates the real server, allowing you to observe the dropper's complete behavior in a controlled environment.

---

## Context: what is a dropper?

In the attack chain (*kill chain*), the dropper typically comes after the initial exploitation phase. Its role is minimalist by design: it must be **small**, **stealthy**, and **generic enough** not to trigger antivirus heuristics. Once executed, it contacts a C2 server, identifies itself, waits for orders, and executes received commands — typically downloading and executing a more sophisticated second binary.

Our educational sample (`binaries/ch28-dropper/dropper_sample.c`) reproduces this pattern in a simplified manner:

1. **Connection** — The dropper opens a TCP socket to a hardcoded address and port.  
2. **Handshake** — It sends an identification message containing metadata about the machine (hostname, PID, a version identifier).  
3. **Command loop** — It enters a loop where it waits for server commands, interprets them, and sends back a result.  
4. **Payload** — Upon receiving a specific command, it writes data to a file in `/tmp/` and attempts to execute it.

The protocol used is **custom** (non-HTTP, non-TLS): messages are structured in binary fields with a *magic byte*, a command type byte, a two-byte length field (little-endian), and a variable-size body. This kind of homegrown protocol is common in real-world malware, as it makes detection via network signatures more difficult.

---

## Why this chapter matters

Analyzing network communications is one of the pillars of malware analysis. A malicious binary can be perfectly harmless as long as it doesn't receive instructions from its C2. Understanding the network protocol means understanding **what the attacker can order the malware to do** — and therefore assessing the actual scope of the threat.

This chapter leverages and combines skills acquired throughout the training:

| Skill | Reference chapters |  
|---|---|  
| Quick triage and static analysis | [Ch. 5](/05-basic-inspection-tools/README.md), [Ch. 7](/07-objdump-binutils/README.md), [Ch. 8](/08-ghidra/README.md) |  
| Hex analysis and `.hexpat` patterns | [Ch. 6](/06-imhex/README.md) |  
| Debugging with GDB | [Ch. 11](/11-gdb/README.md), [Ch. 12](/12-gdb-extensions/README.md) |  
| Dynamic instrumentation with Frida | [Ch. 13](/13-frida/README.md) |  
| RE of a network protocol | [Ch. 23](/23-network/README.md) |  
| Secure analysis lab | [Ch. 26](/26-secure-lab/README.md) |

While [Chapter 23](/23-network/README.md) taught you how to reverse-engineer a **legitimate** network protocol (documented client/server), this chapter goes a step further: the protocol is **deliberately opaque**, the binary is potentially hostile, and the end goal is no longer just to understand but to **take control** of the malware by simulating its infrastructure.

---

## Chapter binary

The sample is compiled from `binaries/ch28-dropper/dropper_sample.c` via its dedicated `Makefile`. Several variants are produced:

| Binary | Optimization | Symbols | Usage |  
|---|---|---|---|  
| `dropper_O0` | `-O0` | Yes (`-g`) | Learning — readable code, DWARF symbols available |  
| `dropper_O2` | `-O2` | Yes (`-g`) | Intermediate — observe the impact of optimizations |  
| `dropper_O2_strip` | `-O2` | No (`strip`) | Realistic — conditions close to a real sample |

> 💡 **Always** start with the `_O0` variant to understand the logic, then move on to `_O2_strip` to verify that your analysis holds without symbols.

---

## Analysis methodology

The recommended approach for this chapter follows a four-stage progression, each section corresponding to a subsection:

```
 ┌──────────────────────────────────────────────────────────┐
 │  28.1  Identify network calls (strace + Wireshark)       │
 │        → What addresses? What ports? What syscalls?      │
 └──────────────────┬───────────────────────────────────────┘
                    ▼
 ┌──────────────────────────────────────────────────────────┐
 │  28.2  Hook sockets with Frida                           │
 │        → Intercept data in the clear, buffer by buffer,  │
 │          without touching the binary                     │
 └──────────────────┬───────────────────────────────────────┘
                    ▼
 ┌──────────────────────────────────────────────────────────┐
 │  28.3  RE of the custom C2 protocol                      │
 │        → Reconstruct message format, state machine,      │
 │          supported commands                              │
 └──────────────────┬───────────────────────────────────────┘
                    ▼
 ┌──────────────────────────────────────────────────────────┐
 │  28.4  Simulate a C2 server                              │
 │        → Write a fake Python C2, observe the dropper's   │
 │          complete behavior                               │
 └──────────────────────────────────────────────────────────┘
```

This progression mirrors the real workflow of a malware analyst: start with passive observation (what is this binary doing on the network?), then instrument more and more actively until you can pilot the malware yourself.

---

## Prerequisites

Before starting this chapter, make sure that:

- Your **analysis lab** is operational (isolated VM, host-only or dedicated bridge network, snapshots in place) — see [Chapter 26](/26-secure-lab/README.md).  
- You are comfortable with **`strace`** for tracing system calls — see [Section 5.5](/05-basic-inspection-tools/05-strace-ltrace.md).  
- You have mastered the **basics of Frida** (injection, `Interceptor.attach`, buffer reading) — see [Chapter 13](/13-frida/README.md).  
- You have already analyzed a **custom network protocol** in [Chapter 23](/23-network/README.md).  
- **Wireshark** (or `tcpdump`) is installed in your environment — see [Section 4.2](/04-work-environment/02-tools-installation.md).

> ⚠️ **Never run the dropper with a connection to the real network.** Even though the sample is educational and the C2 server doesn't exist, it is essential to maintain rigorous hygiene practices. Work exclusively within your isolated network.

---

## Chapter outline

- **28.1** — [Identifying network calls with `strace` + Wireshark](/28-dropper/01-network-calls-strace-wireshark.md)  
- **28.2** — [Hooking sockets with Frida (`connect`, `send`, `recv`)](/28-dropper/02-hooking-sockets-frida.md)  
- **28.3** — [RE of the custom C2 protocol (commands, encoding, handshake)](/28-dropper/03-re-c2-protocol.md)  
- **28.4** — [Simulating a C2 server to observe complete behavior](/28-dropper/04-simulating-c2-server.md)  
- **🎯 Checkpoint** — [Write a fake C2 server that controls the dropper](/28-dropper/checkpoint.md)

⏭️ [Identifying network calls with `strace` + Wireshark](/28-dropper/01-network-calls-strace-wireshark.md)
