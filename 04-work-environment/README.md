🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 4 — Setting Up the Work Environment

> 🔧 **Chapter goal**: build a functional, reproducible, and isolated reverse engineering environment, ready to host all the exercises of the training.

---

## Why a whole chapter on the environment?

Reverse engineering relies on a constellation of tools — disassemblers, debuggers, hex editors, instrumentation frameworks, fuzzers — that interact with each other and with the host operating system. A poorly installed tool, an incompatible version, or a binary executed without isolation can turn a learning session into a debugging nightmare… or a security incident.

This chapter exists to avoid these pitfalls. By following it, you will obtain:

- a **dedicated virtual machine**, isolated from your main system, in which you can run unknown binaries safely;  
- a **set of versioned, tested tools**, installed in a consistent manner, so that all the examples of this training work without surprises;  
- a **clear project structure**, with training binaries compilable in a single command;  
- a **verification script** (`check_env.sh`) that validates everything is in place before you start.

> 💡 **Tip**: even if you already practice RE and some tools are already installed on your machine, take the time to set up the VM described here. Working in a standardized environment will save you version drift and allow you to follow each chapter identically.

---

## What we are going to set up

The chapter covers seven steps, each in its own section:

1. **Choice of the Linux distribution** — Why we recommend Ubuntu LTS (or Debian/Kali depending on your profile), and the criteria that guide this choice: package availability, compatibility with RE tools, community documentation.

2. **Installation of essential tools** — The complete, versioned list of everything we will need throughout the training: GCC/G++, GDB (+ GEF/pwndbg extensions), Ghidra, Radare2, ImHex, Frida, AFL++, angr, pwntools, Valgrind, binutils, and the complementary utilities. Each tool comes with its recommended installation method.

3. **Creating a sandboxed VM** — Step-by-step guide to set up a virtual machine with VirtualBox, QEMU/KVM, or UTM (macOS Apple Silicon). We configure snapshots there to be able to return to a clean state at any time.

4. **VM network configuration** — How to configure the network in NAT mode for package installation, then switch to host-only or an isolated network for dynamic-analysis and malware-analysis chapters (Part VI).

5. **Repository structure** — Presentation of the `binaries/` tree, the per-chapter `Makefile`s, and the organizational logic of sources, ImHex patterns, YARA rules, and utility scripts.

6. **Compiling the training binaries** — A simple `make all` from the `binaries/` directory produces all the necessary variants: optimization levels `-O0` through `-O3`, with and without debug symbols, with and without stripping. We explain what each Makefile target generates and why.

7. **Verifying the installation** — The `check_env.sh` script goes through the list of expected tools, checks their versions, verifies that the training binaries are compiled, and that the VM is correctly configured. Everything must be green before moving on.

---

## Prerequisites before starting

Before tackling this chapter, make sure you have:

- **A host computer** with at least 8 GB of RAM (16 GB recommended), 40 GB of free disk space, and a processor supporting hardware virtualization (VT-x / AMD-V). On macOS Apple Silicon, UTM with x86-64 emulation is the chosen option.  
- **A hypervisor installed**: VirtualBox (all platforms), QEMU/KVM (Linux), or UTM (macOS). If you do not have one yet, section 4.3 will guide you.  
- **The knowledge from Chapters 1 to 3**: you must understand what an ELF file is, what the `.text` and `.data` sections are for, and be able to read a basic assembly listing. If that is not the case, go back to the previous chapters — the technical environment will not make up for conceptual gaps.

---

## Target architecture

The following diagram summarizes the environment we are going to build:

```
┌─────────────────────────────────────────────────────┐
│                  Host machine                       │
│  (Windows / macOS / Linux — your everyday OS)       │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │         RE Lab VM (Ubuntu LTS x86-64)         │  │
│  │                                               │  │
│  │  ┌─────────────┐  ┌────────────────────────┐  │  │
│  │  │  RE tools   │  │   Training repository  │  │  │
│  │  │             │  │                        │  │  │
│  │  │  GDB + GEF  │  │  binaries/             │  │  │
│  │  │  Ghidra     │  │  scripts/              │  │  │
│  │  │  Radare2    │  │  hexpat/               │  │  │
│  │  │  ImHex      │  │  yara-rules/           │  │  │
│  │  │  Frida      │  │  solutions/            │  │  │
│  │  │  AFL++      │  │                        │  │  │
│  │  │  angr       │  │  Makefile              │  │  │
│  │  │  pwntools   │  │  check_env.sh          │  │  │
│  │  │  Valgrind   │  │                        │  │  │
│  │  │  ...        │  │                        │  │  │
│  │  └─────────────┘  └────────────────────────┘  │  │
│  │                                               │  │
│  │  Network: NAT (install) → Host-only (analysis)│  │
│  │  Snapshots: baseline, post-install, clean     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

The guiding idea is simple: **all RE work happens inside the VM, never on the host**. This separation protects your main system and guarantees a reproducible environment. If something goes wrong — a trapped binary, a broken dependency, a risky operation — just restore a snapshot.

---

## Conventions for this chapter

- Commands to run **on the host machine** are prefixed with `[host]`.  
- Commands to run **inside the VM** are prefixed with `[vm]`.  
- Paths are relative to the root of the training repository, unless otherwise stated.  
- The versions listed are those tested at the time of writing. More recent versions will work in the vast majority of cases, but if unexpected behavior occurs, falling back to the documented version is the first thing to try.

---

## Chapter outline

| Section | Content |  
|---|---|  
| 4.1 | Recommended Linux distribution (Ubuntu/Debian/Kali) |  
| 4.2 | Installation and configuration of essential tools |  
| 4.3 | Creating a sandboxed VM (VirtualBox / QEMU / UTM) |  
| 4.4 | VM network configuration: NAT, host-only, isolation |  
| 4.5 | Repository structure: organization of `binaries/` and `Makefile`s |  
| 4.6 | Compile all training binaries (`make all`) |  
| 4.7 | Verify installation: `check_env.sh` script |  
| **🎯 Checkpoint** | Run `check_env.sh` — all tools must be green |

---


⏭️ [Recommended Linux distribution (Ubuntu/Debian/Kali)](/04-work-environment/01-linux-distribution.md)
