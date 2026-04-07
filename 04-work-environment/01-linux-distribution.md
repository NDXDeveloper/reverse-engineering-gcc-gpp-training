🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.1 — Recommended Linux distribution (Ubuntu/Debian/Kali)

> 🎯 **Goal of this section**: choose the Linux distribution that will serve as the base of your reverse engineering VM, understanding the criteria that drive this choice.

---

## Why Linux?

Almost all the reverse engineering tools we will use in this training are natively developed for Linux or find their best support there. GDB, Radare2, Frida, AFL++, angr, pwntools, the GNU binutils — all are projects born in the Unix/Linux ecosystem. Even Ghidra, which is cross-platform, integrates more naturally into a Linux workflow where you constantly switch between the terminal and the disassembler.

Beyond the tools, the **targets** of this training are ELF binaries compiled with GCC/G++. Working under Linux means being able to run, debug, and instrument them directly, without emulation or compatibility layers.

Finally, mastery of the Linux command line is a fundamental RE skill. Analysts spend a significant share of their time in a terminal — launching scripts, inspecting the memory of a process, capturing network traffic, or automating repetitive tasks.

---

## The three candidates

Three distributions come up consistently in RE and offensive-security environments. All three belong to the Debian family and share the `apt` package manager, which makes it easy to transpose install instructions from one distribution to another.

### Ubuntu LTS — the default choice for this training

Ubuntu LTS (Long Term Support) is the distribution we recommend as a working base. Here is why:

**Package availability.** The Ubuntu repositories contain the vast majority of the tools we need, either directly in the official repositories or through community-maintained PPAs. For non-packaged tools (Ghidra, ImHex, GEF…), manual installation is systematically documented on Ubuntu first by the maintainers of these projects.

**Stability and support cycle.** An LTS version is supported for five years. This means the installation instructions in this tutorial will remain valid for a long time without needing updates. At the time of writing, **Ubuntu 24.04 LTS (Noble Numbat)** is the recommended version.

**Documentation and community.** When a problem occurs — a missing dependency, a version conflict, a tool refusing to start — the likelihood of finding a solution on a forum, GitHub issue, or Stack Overflow is highest with Ubuntu. This is a pragmatic advantage that should not be underestimated.

**Lightness possible.** For a VM dedicated to RE, it is not necessary to install a heavy desktop environment. Ubuntu Server (no GUI) or Ubuntu with a minimal desktop (Xfce, LXQt) makes it possible to limit RAM and disk consumption, only launching a graphical interface for the tools that require one (Ghidra, ImHex, Cutter).

> 📌 **Recommended version**: Ubuntu 24.04 LTS, **amd64** architecture (x86-64).  
> If you use an Apple Silicon Mac, section 4.3 details how to proceed with UTM and x86-64 emulation.

### Debian stable — the minimalist alternative

Debian stable is the foundation on which Ubuntu is built. It offers even higher stability, with rigorously tested packages. In exchange, the software versions in the stable repositories are often older than in Ubuntu.

**When to choose Debian over Ubuntu?**

- You prefer a clean system without Canonical-specific additions (snap, etc.).  
- You are already comfortable with Debian and do not want to change your habits.  
- You are setting up a lab on a physical machine with very limited resources.

In practice, all the `apt install` commands in this training work just as well on Debian as on Ubuntu. The rare divergences (package names, available versions) are flagged when they arise.

### Kali Linux — the security-specialized distribution

Kali Linux is the most famous distribution in offensive security. It is maintained by OffSec (formerly Offensive Security) and integrates hundreds of preinstalled tools, many of which are relevant for RE: GDB, Radare2, Ghidra, binutils, pwntools, checksec, strace, ltrace, Wireshark, and many others.

**Advantages for this training:**

- Many tools are **already installed** on first boot. This considerably reduces setup time.  
- Kali ships with **pre-optimized configurations** for security work (permissions, paths, aliases).  
- Official VM images (for VirtualBox, VMware, QEMU) are directly downloadable and ready to use.

**Drawbacks to know:**

- Kali is a **rolling release** distribution. Packages are updated frequently, which can occasionally break a dependency or change expected behavior. It is the opposite of the stability sought with Ubuntu LTS.  
- The system is designed to be used as **root** by default (even though recent versions create a non-root `kali` user). This philosophy, suitable for one-off pentesting, is debatable for a daily learning environment.  
- The **volume of preinstalled tools** is double-edged: the disk and memory footprint is higher, and it is easy to get lost among hundreds of tools, most of which are not relevant to RE.  
- When a tool is not in the Kali repositories, manual installation is sometimes less well documented than on Ubuntu.

> 💡 **Our recommendation**: if you already use Kali daily and are comfortable with it, you can perfectly well follow this training on it. Otherwise, go with Ubuntu LTS — you will have a more predictable environment and you will install only what you actually need.

---

## Summary table

| Criterion | Ubuntu LTS | Debian stable | Kali Linux |  
|---|---|---|---|  
| **Release model** | LTS (5 years of support) | Stable (~2 years between versions) | Rolling release |  
| **Preinstalled RE tools** | Few (manual install) | Very few | Many |  
| **Package freshness** | Recent | Conservative | Very recent |  
| **Base image size** | ~3 GB (Desktop), ~1 GB (Server) | ~600 MB (netinst) | ~4 GB (VM image) |  
| **Minimum RAM for RE** | 4 GB (8 GB recommended) | 2 GB (8 GB recommended) | 4 GB (8 GB recommended) |  
| **Community documentation** | Abundant | Abundant | Good (pentest-oriented) |  
| **Breakage risk after `apt upgrade`** | Low | Very low | Moderate |  
| **Ideal for** | Following this training | Minimalists, lightweight machines | Existing Kali users |

---

## What about other distributions?

**Fedora / Arch / openSUSE** are perfectly capable distributions for hosting an RE environment. If you master one, you will know how to adapt the install commands (`dnf`, `pacman`, `zypper`). However, this training does not provide specific instructions for these distributions. In case of packaging-related problems, you will be on your own.

**WSL2 (Windows Subsystem for Linux)** is a tempting option for Windows users who do not want to create a VM. WSL2 works for some of the tools (GDB, binutils, compilation, Python scripts) but has significant limitations for RE:

- The absence of a native graphical interface makes using Ghidra, ImHex, or Cutter more tedious (you have to configure an X server or use WSLg).  
- Low-level instrumentation (Frida, advanced ptrace, some Valgrind features) may behave differently or not work at all, because the WSL2 kernel is not a standard Linux kernel.  
- Isolation is weak: WSL2 shares the filesystem and network with the Windows host, which is problematic for the malware-analysis chapters (Part VI).

For these reasons, we advise against WSL2 as the main environment for this training. If you are on Windows, the VM remains the recommended route.

---

## Which ISO to download?

If you follow our recommendation (Ubuntu 24.04 LTS), here are the two options:

- **Ubuntu Desktop 24.04 LTS** — if you want a complete graphical environment (GNOME) to comfortably use Ghidra, ImHex, and Cutter. This is the simplest choice to get started.  
  → Download: [ubuntu.com/download/desktop](https://ubuntu.com/download/desktop)

- **Ubuntu Server 24.04 LTS** — if you prefer a lightweight system and install a minimal desktop afterwards (`sudo apt install xfce4 xfce4-goodies`). Better for machines with limited RAM.  
  → Download: [ubuntu.com/download/server](https://ubuntu.com/download/server)

> ⚠️ **Architecture**: be sure to download the **amd64** (x86-64) version. The training binaries are compiled for that architecture. An ARM64 image (even on an Apple Silicon Mac via UTM) will require x86-64 emulation described in section 4.3.

---

## Summary

- **Default choice**: Ubuntu 24.04 LTS (amd64), Desktop or Server version depending on your resources.  
- **Acceptable alternatives**: Debian stable if you master it, Kali if you are already using it.  
- **Avoid for this training**: WSL2 (isolation and compatibility limitations), non-Debian distributions (no documented support here).  
- The distribution choice is not critical — all tools install on the three candidates. What matters is having a **stable, isolated, reproducible** environment.

---


⏭️ [Installation and configuration of essential tools (versioned list)](/04-work-environment/02-tools-installation.md)
