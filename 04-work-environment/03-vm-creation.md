🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.3 — Creating a sandboxed VM (VirtualBox / QEMU / UTM for macOS)

> 🎯 **Goal of this section**: create an isolated virtual machine that will serve as a reverse engineering lab throughout the training. By the end of this section, you will have a functional VM, with a snapshot system set up so you can return to a clean state at any time.

---

## Why a VM and not directly the host?

Working in a virtual machine is not a matter of tidiness. It is a **fundamental security measure** and a productivity tool for the reverse engineer.

### Isolation and security

Reverse engineering implies running binaries whose behavior you do not control. Even the training binaries of this course — which we wrote ourselves — will be executed under unusual conditions: code injection with Frida, fuzzing with random inputs, running samples simulating a ransomware or a dropper (Part VI). A misstep, a binary that behaves unexpectedly under instrumentation, and your host system could be affected.

The VM acts as a **disposable container**. If something goes wrong, the damage stays confined to the VM. A snapshot restored in a few seconds, and you are back to square one.

### Reproducibility

A virtualized environment is identical from one session to the next. No surprise system update that breaks a dependency, no conflict with software installed for another project. When the instructions in this tutorial say "run this command", the result will be the same for everyone.

### Snapshots: your safety net

Snapshots are point-in-time captures of the VM's complete state (disk, memory, configuration). We will create several throughout the setup:

| Snapshot | When to take it | Use |  
|---|---|---|  
| `base-install` | After the system install, before the tools | Start over if the tool installation fails |  
| `tools-ready` | After section 4.2 (all tools installed) | Reference state for the training |  
| `pre-malware` | Before tackling Part VI | Isolate malware experiments |

> 💡 **Golden rule**: take a snapshot *before* any risky or irreversible operation. Restoring a snapshot takes 10 seconds. Reinstalling a system takes an hour.

---

## Choosing the hypervisor

The choice of hypervisor depends on your host system and your hardware constraints. Here are the three options we document.

### VirtualBox — the cross-platform choice

**For whom**: Windows, macOS (Intel), or Linux users who want a free, graphical, simple-to-learn solution.

**Advantages:**  
- Free and open source (GPLv3 license).  
- Available on Windows, macOS (Intel and Apple Silicon via beta), Linux.  
- Intuitive graphical interface for managing VMs and snapshots.  
- Large community and abundant documentation.  
- Guest Additions improve integration (screen resizing, shared folders, shared clipboard).

**Drawbacks:**  
- Performance inferior to QEMU/KVM on Linux (no native KVM acceleration).  
- On macOS Apple Silicon, x86-64 support is experimental and slow (emulation, no native virtualization).

**Recommended version**: VirtualBox 7.1+.

### QEMU/KVM — native performance under Linux

**For whom**: Linux users who want the best possible performance.

**Advantages:**  
- Near-native performance thanks to KVM acceleration (the CPU executes the VM's code directly without translation).  
- Very flexible: drivable from the command line or via the `virt-manager` graphical interface.  
- Perfect for headless or automated setups.  
- Supports snapshots, virtual networks, device passthrough.

**Drawbacks:**  
- Linux only (KVM is a Linux kernel module).  
- Initial configuration more technical than VirtualBox.  
- `virt-manager` is functional but less polished than VirtualBox's interface.

**Required packages**: `qemu-system-x86`, `libvirt-daemon-system`, `virt-manager`, `ovmf`.

### UTM — the solution for macOS Apple Silicon

**For whom**: users of M1/M2/M3/M4 Macs who need to emulate the x86-64 architecture.

**Advantages:**  
- Native macOS graphical interface, elegant and simple.  
- Based on QEMU as a backend, so benefits from its maturity.  
- Supports **ARM64 virtualization** (near-native, very fast) and **x86-64 emulation** (slower, but functional).  
- Available free on GitHub (paid on the App Store, same software).  
- Integrated snapshot management.

**Drawbacks:**  
- x86-64 emulation is significantly slower than native virtualization. Count a slowdown factor of 3 to 5 compared to native. It is usable for learning, but heavy fuzzing sessions (Chapter 15) will be penalized.  
- Less community documentation than VirtualBox.

**Critical point — architecture**: the binaries of this training are compiled for **x86-64**. On an Apple Silicon Mac, you have two options:

1. **x86-64 emulation** (recommended for this training): UTM uses QEMU in TCG emulation mode. The entire guest OS and all binaries run in x86-64. Everything works, but it is slower.  
2. **ARM64 virtualization**: fast, but x86-64 binaries will not run natively. You will have to install `qemu-user-static` in the VM to emulate x86-64 at user level — a more complex configuration and sometimes incompatible with some tools (GDB, Frida, ptrace).

> 📌 **Our recommendation for Apple Silicon**: use UTM in **x86-64 emulation** mode. Performance is sufficient for learning. Full compatibility with the tools and binaries is worth the speed tradeoff.

---

## Step-by-step guide: VirtualBox

### 1. Install VirtualBox

Download the installer from [virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads) for your host system. Install it following the default instructions.

On a Linux host, you can also use apt:

```bash
[host] sudo apt install -y virtualbox virtualbox-ext-pack
```

Check that hardware virtualization is enabled in your machine's BIOS/UEFI (VT-x for Intel, AMD-V for AMD). Without it, VirtualBox will run in software-emulation mode, which is much slower.

### 2. Creating the VM

Open VirtualBox and click **New**. Configure as follows:

| Parameter | Recommended value |  
|---|---|  
| Name | `RE-Lab` |  
| Type | Linux |  
| Version | Ubuntu (64-bit) |  
| RAM | **4096 MB** minimum — **8192 MB** recommended |  
| Processors | **2 vCPU** minimum — **4 vCPU** recommended |  
| Hard disk | Create a virtual disk, **60 GB**, dynamically allocated |  
| Graphics controller | VMSVGA |  
| Video memory | 128 MB |

> 💡 **Why 60 GB?** Ghidra consumes a lot of space for its analysis projects (databases, indices). AFL++ generates bulky fuzzing corpora. 40 GB is a minimum, 60 GB is comfortable. With the disk dynamically allocated, it will only consume on the host the space actually used.

### 3. Installing the system

Insert the Ubuntu 24.04 LTS ISO into the virtual drive (**Storage** setting → IDE controller → optical disk), then boot the VM.

During Ubuntu installation:

- **Partitioning**: use the default scheme (entire disk, LVM if proposed). No need for complexity here.  
- **Username**: `re` (or any other — the tutorial commands use `$USER`).  
- **Hostname**: `re-lab`.  
- **Additional packages**: install the OpenSSH server if proposed (useful to connect via SSH from the host).

Once installation finishes, reboot and eject the ISO from the virtual drive.

### 4. Guest Additions

Guest Additions greatly improve the experience:

- Dynamic resizing of the VM screen.  
- Shared clipboard between host and VM (essential for copying commands).  
- Shared folders between host and VM.  
- Better mouse integration.

```bash
[vm] sudo apt install -y virtualbox-guest-utils virtualbox-guest-x11
[vm] sudo reboot
```

After reboot, enable in the VirtualBox menu: **Devices → Shared Clipboard → Bidirectional**.

### 5. First snapshot

The system is installed, the Guest Additions are active. Take your first snapshot:

**Machine → Take a snapshot** → name it `base-install`.

This is your most basic fallback point. If anything goes wrong in the next steps, you can restore this state.

---

## Step-by-step guide: QEMU/KVM

### 1. Installation

```bash
[host] sudo apt install -y \
    qemu-system-x86 \
    qemu-utils \
    libvirt-daemon-system \
    libvirt-clients \
    virt-manager \
    bridge-utils \
    ovmf
```

Add your user to the required groups:

```bash
[host] sudo usermod -aG libvirt,kvm $USER
```

Log out then back in for the groups to take effect.

Verify that KVM is available:

```bash
[host] kvm-ok
# expected: "INFO: /dev/kvm exists" and "KVM acceleration can be used"
```

### 2. Creating the VM with virt-manager

Launch `virt-manager` (graphical interface). Click **Create a new virtual machine**:

- **Installation method**: local install media (ISO).  
- **ISO**: select the Ubuntu 24.04 LTS ISO.  
- **Memory**: 4096 MB minimum, 8192 MB recommended.  
- **CPU**: 2 minimum, 4 recommended.  
- **Storage**: create a 60 GB disk (qcow2 format, which is automatically thin-provisioned).  
- **Network**: default NAT (virbr0). We will adjust this in section 4.4.

Tick **Customize configuration before install** to verify:
- **Firmware**: UEFI (OVMF) preferably, BIOS otherwise.  
- **Chipset**: Q35 (more modern than i440FX).  
- **Video**: QXL or Virtio (better graphical performance than VGA).

Start the installation and follow the same steps as for VirtualBox.

### 3. Installing the SPICE agent (equivalent of Guest Additions)

```bash
[vm] sudo apt install -y spice-vdagent qemu-guest-agent
[vm] sudo systemctl enable --now spice-vdagent qemu-guest-agent
```

This enables dynamic screen resizing and shared clipboard.

### 4. Command-line creation (GUI-less alternative)

For those who prefer the command line, here is the complete equivalent:

```bash
# Disk creation
[host] qemu-img create -f qcow2 ~/vms/re-lab.qcow2 60G

# Launch the installation
[host] qemu-system-x86_64 \
    -enable-kvm \
    -m 8192 \
    -smp 4 \
    -cpu host \
    -drive file=~/vms/re-lab.qcow2,format=qcow2,if=virtio \
    -cdrom ~/iso/ubuntu-24.04-desktop-amd64.iso \
    -boot d \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -vga qxl \
    -display sdl
```

After installation, remove the `-cdrom` and `-boot d` parameters for subsequent boots.

### 5. Snapshots with QEMU

With `virt-manager`: right-click the VM → **Snapshots** → **Create**.

On the command line (VM stopped):

```bash
[host] qemu-img snapshot -c base-install ~/vms/re-lab.qcow2
```

To list snapshots:

```bash
[host] qemu-img snapshot -l ~/vms/re-lab.qcow2
```

To restore:

```bash
[host] qemu-img snapshot -a base-install ~/vms/re-lab.qcow2
```

With libvirt (VM running or stopped):

```bash
[host] virsh snapshot-create-as RE-Lab base-install --description "After system install"
[host] virsh snapshot-list RE-Lab
[host] virsh snapshot-revert RE-Lab base-install
```

---

## Step-by-step guide: UTM (macOS Apple Silicon)

### 1. Installing UTM

Download UTM from [github.com/utmapp/UTM/releases](https://github.com/utmapp/UTM/releases) (free) or from the Mac App Store (paid, same software).

Drag `UTM.app` into your Applications folder.

### 2. Creating the VM in x86-64 emulation

Open UTM and click **Create a new virtual machine**:

- **Type**: select **Emulate** (not "Virtualize").  
- **Operating system**: Linux.  
- **Architecture**: **x86_64**. This is the crucial point — do not select ARM64.  
- **System**: leave the default values (QEMU machine type `q35`).

Hardware parameters:

| Parameter | Recommended value |  
|---|---|  
| Memory | **8192 MB** (emulation consumes more RAM) |  
| CPU | **4 cores** (UTM will translate x86 instructions via TCG) |  
| Acceleration backend | TCG (selected automatically in emulation mode) |

Storage:

- Create a new **60 GB** disk (qcow2 format).

Network:

- **Shared** mode (equivalent of VirtualBox's NAT). Enough to download packages.

### 3. Installing the system

Add the Ubuntu 24.04 LTS ISO as a removable CD/DVD drive in the VM settings (**Drives** tab), then boot.

> ⚠️ **Installation will be slower than with VirtualBox/QEMU-KVM.** x86-64 emulation on Apple Silicon is functional but noticeably slower. Count 30 to 60 minutes for the full Ubuntu Desktop install. Be patient — once installed, day-to-day use is quite viable.

> 💡 **Performance tip**: if the slowness of the GNOME desktop bothers you, install a lighter desktop after installation:  
> ```bash  
> [vm] sudo apt install -y xfce4 xfce4-goodies  
> ```  
> Then select "Xfce Session" on the login screen.

### 4. SPICE agent

Same as for QEMU/KVM:

```bash
[vm] sudo apt install -y spice-vdagent
[vm] sudo systemctl enable --now spice-vdagent
```

### 5. Snapshots in UTM

In the VM window, click the camera icon (or **Menu → Take a snapshot**). Name the snapshot `base-install`.

To restore: open the snapshot list, select the desired one, click **Restore**.

### 6. Expected performance and optimizations

TCG emulation imposes significant overhead. Here are some reference points to calibrate your expectations:

| Operation | Native time (KVM) | Emulated time (UTM/TCG) | Factor |  
|---|---|---|---|  
| Compiling a small C project | ~2 s | ~8 s | ×4 |  
| Launching Ghidra + auto-analysis | ~15 s | ~50 s | ×3 |  
| Interactive GDB session | Real-time | Near real-time | ×1.5 |  
| AFL++ fuzzing (execs/sec) | ~2000 | ~300–500 | ×4–6 |

These numbers are indicative and vary with the Mac model and workload. For learning, it is plenty. For intensive fuzzing on real projects, an x86-64 workstation will be clearly preferable.

**Possible optimizations:**  
- Allocate the **maximum RAM** your Mac can offer to the VM (Apple chips' unified memory handles sharing well).  
- Use a **lightweight desktop** (Xfce, LXQt) rather than GNOME.  
- For purely CLI tasks (GDB, strace, scripts), connect via **SSH** from the macOS terminal rather than using the emulated graphical display.  
- Disable visual effects in the desktop preferences.

---

## SSH access to the VM (all hypervisors)

Whichever hypervisor you pick, SSH access from the host is extremely convenient: it lets you work in your usual terminal, use your preferred text editor, and transfer files with `scp`.

Make sure the SSH server is installed in the VM:

```bash
[vm] sudo apt install -y openssh-server
[vm] sudo systemctl enable --now ssh
```

The connection method depends on the network configuration:

- **VirtualBox (NAT with port forwarding)**: add a rule in **Settings → Network → Advanced → Port forwarding**: TCP protocol, host port 2222, guest port 22. Then:
  ```bash
  [host] ssh -p 2222 re@127.0.0.1
  ```

- **QEMU/KVM (NAT via virbr0)**: the VM gets an IP on the 192.168.122.0/24 network. Find it with `ip a` inside the VM, then:
  ```bash
  [host] ssh re@192.168.122.xxx
  ```

- **UTM (shared mode)**: works like the QEMU NAT. Find the IP with `ip a` inside the VM.

- **Host-only mode** (all hypervisors): after configuration in section 4.4, the VM will be reachable on a dedicated private network.

> 💡 **Tip**: add an entry in `~/.ssh/config` on the host to simplify connection:  
> ```  
> Host re-lab  
>     HostName 127.0.0.1  
>     Port 2222  
>     User re  
> ```  
> You can then simply type `ssh re-lab`.

---

## Shared folders between host and VM

Shared folders make it easy to transfer files (binaries, scripts, notes) between host and VM without going through SSH/SCP.

### VirtualBox

1. In **Settings → Shared Folders**, add a host folder (e.g., `~/shared-re`).  
2. Check **Auto-mount** and **Make Permanent**.  
3. In the VM:
   ```bash
   [vm] sudo usermod -aG vboxsf $USER
   [vm] # Logout/login required
   ```
   The folder will be available at `/media/sf_<name>`.

### QEMU/KVM (virtio-fs or 9p)

With `virt-manager`, add a **Filesystem** device pointing to a directory on the host. In the VM:

```bash
[vm] sudo mount -t 9p -o trans=virtio shared /mnt/shared
```

For automatic mounting at boot, add to `/etc/fstab`:

```
shared /mnt/shared 9p trans=virtio,version=9p2000.L,rw 0 0
```

### UTM

UTM offers sharing via VirtFS. In the VM settings, **Sharing** tab, add a directory. The mount in the VM is identical to QEMU's (9p mount).

> ⚠️ **Part VI (malware)**: when analyzing malicious code, **disable shared folders**. Malware in the VM could theoretically write to the shared filesystem and affect the host. This risk is low with our pedagogical samples, but security hygiene demands removing that vector.

---

## Post-creation checklist

Before moving on, check that your VM ticks every box:

- [ ] The Ubuntu 24.04 LTS system boots correctly.  
- [ ] The screen resizes dynamically (Guest Additions / SPICE agent installed).  
- [ ] The shared clipboard works (copy text on the host, paste in the VM).  
- [ ] SSH access from the host works (`ssh re-lab`).  
- [ ] Internet is reachable inside the VM (`ping 8.8.8.8` and `curl https://example.com`).  
- [ ] A `base-install` snapshot has been created.  
- [ ] The VM has at least 4 GB RAM, 2 vCPUs, and 60 GB of disk.

If everything is green, you are ready to install the tools (section 4.2, if not already done) and then configure the network for the analysis phases (section 4.4).

---

## Summary

- **VirtualBox** is the simplest and most portable choice — our default recommendation if you are on Windows or macOS Intel.  
- **QEMU/KVM** offers the best performance on a Linux host thanks to hardware KVM acceleration.  
- **UTM** is the best option on macOS Apple Silicon, in **x86-64 emulation** mode — slower but fully compatible with the training binaries.  
- Whichever hypervisor, what matters is to work in an environment that is **isolated**, **snapshottable**, and **reproducible**. The VM is your safety net.

---


⏭️ [VM network configuration: NAT, host-only, isolation](/04-work-environment/04-vm-network-configuration.md)
