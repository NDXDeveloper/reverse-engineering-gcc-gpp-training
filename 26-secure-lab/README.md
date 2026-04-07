🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 26 — Setting Up a Secure Analysis Lab

> **Part VI — Malicious Code Analysis (Controlled Environment)**

---

## Why an entire chapter on the lab?

Until now, the binaries we have manipulated were harmless: crackmes, controlled network programs, file parsers. Running them on your work machine posed no real risk. With this sixth part, the situation changes radically. We are going to analyze programs whose **behavior is intentionally destructive** — file encryption, communication with a command and control (C2) server, code injection. Even though all the samples provided in this training are created by us and strictly educational, they faithfully reproduce the mechanisms of real malware. Running them without precautions would be like handling a dangerous chemical reagent on the kitchen table.

Malicious code analysis therefore does not begin by opening Ghidra or launching GDB. It begins with **building an isolated, reproducible, and disposable environment** in which you can observe the behavior of a hostile binary without endangering your data, your local network, or the machines around you.

This chapter lays the foundations of this environment. Without it, none of the following chapters (27, 28, 29) should be attempted.

---

## What you will learn

This chapter covers the entire process of setting up a secure analysis laboratory, from the isolation philosophy to the concrete verification that your environment is properly sealed. You will discover the fundamental principles that justify each layer of protection, the creation of a dedicated virtual machine with QEMU/KVM configured for snapshotting and quick rollback, the installation and configuration of monitoring tools needed for behavioral observation (`auditd`, `inotifywait`, `tcpdump`, `sysdig`), the setup of an isolated network via a dedicated bridge to capture traffic without ever exposing it to the outside, and finally the strict discipline rules that must accompany every malicious code analysis session.

> 🔧 **Note on training binaries** — Unlike other chapters in this training, chapter 26 contains **no binaries to compile or analyze**. This is an infrastructure chapter: it builds the environment in which the samples from subsequent chapters will be executed. There is no `binaries/ch26-*/` directory in the repository. The first binaries to handle in this lab will be those from chapter 27 (`binaries/ch27-ransomware/`), chapter 28 (`binaries/ch28-dropper/`), and chapter 29 (`binaries/ch29-packed/`). The `clean-base` snapshot must imperatively be taken **before** introducing any sample into the VM.

---

## Prerequisites

Before starting this chapter, you should be comfortable with the following:

- **Basic Linux administration** — package management, network configuration, system file editing. Chapter 4 (Work Environment) covers these fundamentals.  
- **Virtualization** — you have already created and used a VM in chapter 4. Here, we go further in configuration, particularly regarding networking and snapshots.  
- **Tools from Parts II and III** — `strace`, `ltrace`, GDB, Frida, Ghidra. The lab we are building is the theater in which all these tools will be deployed against hostile targets.  
- **Minimal networking knowledge** — understanding what a network interface, a bridge, and a basic `iptables` rule are. Nothing expert-level, but you need to be able to read `ip addr` output without being lost.

---

## Lab architecture

The overall lab design rests on a simple principle: **the analysis machine is never the host machine**. Here is the target architecture we will build in the following sections:

```
┌─────────────────────────────────────────────────────────┐
│                    HOST MACHINE                          │
│                                                         │
│   Role: control the VM, store snapshots,                │
│         write reports.                                  │
│   Rule: NO sample is EVER executed here.                │
│                                                         │
│   ┌───────────────────────────────────────────────┐     │
│   │          ANALYSIS VM (QEMU/KVM)               │     │
│   │                                               │     │
│   │  - Guest system: minimal Debian/Ubuntu        │     │
│   │  - RE tools installed (GDB, Ghidra, Frida…)   │     │
│   │  - Samples copied to /tmp/malware/            │     │
│   │  - Snapshots before each execution            │     │
│   │                                               │     │
│   │  Network: isolated bridge (br-malware)        │     │
│   │           ├─ no route to Internet             │     │
│   │           ├─ no route to LAN                  │     │
│   │           └─ tcpdump captures all traffic     │     │
│   └───────────────────────────────────────────────┘     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Three security layers are stacked:

1. **Execution isolation** — the code runs in a VM, not on the host. If the sample corrupts the guest system, a snapshot rollback is enough to return to a clean state in seconds.  
2. **Network isolation** — the VM is connected to a virtual bridge that routes to nothing. The malware can attempt to call a C2, exfiltrate data, or scan the network: its packets will never leave the bridge. Meanwhile, `tcpdump` captures them entirely for later analysis.  
3. **Behavioral isolation** — monitoring tools (`auditd`, `inotifywait`, `sysdig`) observe the sample's actions in real time: files created or modified, system calls, child processes launched. This layer is what transforms the lab into a true observatory.

---

## Difference from chapter 4

In chapter 4, we had already set up a VM for the work environment. Why not simply reuse that VM? For two fundamental reasons.

The first is a matter of **analytical cleanliness**. Your work VM contains your projects, your Ghidra configurations, your scripts, your notes. A malicious sample that encrypts `/home` or modifies shared libraries could compromise all this work. The analysis VM must be **disposable**: it is restored to a clean state before each session, with nothing to regret.

The second is a matter of **network rigor**. The chapter 4 VM probably had NAT or host-only access with a gateway — which is perfect for installing packages and following the tutorial. But for malware analysis, the slightest network access to the outside is a propagation or exfiltration vector. Here, the network is intentionally severed, and this severance is verified before each analysis.

---

## Tools specific to this part

In addition to tools already installed in previous parts, this chapter introduces several utilities dedicated to behavioral observation:

- **`auditd`** — the Linux kernel audit framework. It allows tracing specific system events (file opens, binary executions, permission changes) with fine granularity and low performance footprint.  
- **`inotifywait`** (from the `inotify-tools` package) — real-time monitoring of filesystem events. When a sample creates, modifies, or deletes a file, `inotifywait` reports it immediately.  
- **`tcpdump`** — raw network packet capture on the isolated bridge. The `.pcap` files produced will then be analyzed with Wireshark on the host machine.  
- **`sysdig`** — a system visibility tool that combines the capabilities of `strace`, `tcpdump`, and `lsof` in a unified interface with a powerful filtering language. Particularly useful for correlating network activity and file activity.

We will install and configure each of these tools in the dedicated sections.

---

## Chapter outline

- **26.1** — Isolation principles: why and how  
- **26.2** — Dedicated VM with QEMU/KVM — snapshots and isolated network  
- **26.3** — Monitoring tools: `auditd`, `inotifywait`, `tcpdump`, `sysdig`  
- **26.4** — Network captures with a dedicated bridge  
- **26.5** — Golden rules: never execute outside the sandbox, never connect to the real network  
- **🎯 Checkpoint** — Deploy the lab and verify network isolation

---

## What comes next? The binaries from chapters 27 to 29

Once this chapter is validated, the lab is ready to receive its first samples. Each subsequent chapter in this Part VI provides a binary compiled with GCC, along with its sources and a dedicated `Makefile`:

| Chapter | Binary | Source | Behavior |  
|---|---|---|---|  
| **27** — Ransomware | `ransomware_sample` | `binaries/ch27-ransomware/` | Encrypts files in `/tmp/test/` with AES, hardcoded key |  
| **28** — Dropper | `dropper_sample` | `binaries/ch28-dropper/` | Contacts a C2 server, receives commands, exfiltrates data |  
| **29** — Packed | `packed_sample` | `binaries/ch29-packed/` | UPX-packed binary, hidden logic to extract after unpacking |

These binaries will be compiled on your host machine (or in the chapter 4 work VM) via `make`, then **transferred** into the analysis VM by `scp` — never executed outside the lab. The complete workflow (compilation → transfer → snapshot → monitoring → execution → collection → rollback) will be detailed step by step starting from chapter 27.

> ⚠️ **Important reminder** — All these samples are created by us, compiled with GCC from provided sources. No real malware is distributed with this training. However, these samples reproduce genuinely malicious behaviors (file encryption, C2 communication, packing). Treat them with the same rigor as if they were real samples: this is both a security measure and a professional reflex to acquire right now.

⏭️ [Isolation principles: why and how](/26-secure-lab/01-isolation-principles.md)
