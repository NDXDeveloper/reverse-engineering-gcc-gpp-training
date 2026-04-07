🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 26.2 — Dedicated VM with QEMU/KVM — Snapshots and Isolated Network

> **Chapter 26 — Setting Up a Secure Analysis Lab**  
> **Part VI — Malicious Code Analysis (Controlled Environment)**

---

## Why QEMU/KVM

In Chapter 4, we introduced several virtualization solutions (VirtualBox, QEMU, UTM). For the malware analysis lab, this course recommends **QEMU/KVM** as the primary hypervisor, for several reasons.

KVM (Kernel-based Virtual Machine) has been integrated directly into the Linux kernel since version 2.6.20. It is not a third-party piece of software installed on top of the system: it is a kernel module that leverages the processor's hardware virtualization extensions (Intel VT-x or AMD-V) to execute guest code nearly natively. Performance is close to bare-metal, which is valuable when running Ghidra or a fuzzer inside the VM.

QEMU provides device emulation (disk, network, display, USB, etc.) and the user interface. Combined with KVM, it forms a mature, audited duo, widely used in the industry (it is the foundation of virtualization for most cloud providers), and entirely open source. For our purposes, three properties are decisive:

- **Internal snapshots in qcow2 format** — the qcow2 disk image format natively supports snapshots. No need to copy a 20 GB file to save the VM state: the snapshot records only the delta from the previous state, making it virtually instantaneous.  
- **Fine-grained network control** — QEMU allows creating virtual network interfaces attached to standard Linux bridges. You can configure network isolation with native system tools (`ip`, `bridge`, `iptables`) without relying on a proprietary abstraction layer.  
- **Command-line control** — everything is scriptable. Creating a VM, taking a snapshot, restoring a state, starting an analysis: everything can be encapsulated in reproducible shell scripts, which aligns with our reproducibility requirement (Section 26.1).

> 💡 **If you are on macOS or Windows** — UTM (macOS, based on QEMU) and VirtualBox (cross-platform) are viable alternatives. The principles of this chapter (snapshots, isolated network, least privilege) apply in the same way. The specific commands will differ, but the logic remains identical. The appendix of this chapter provides VirtualBox equivalents for the QEMU commands presented here.

---

## Checking Hardware Virtualization Support

Before any installation, let's verify that the processor supports hardware virtualization and that the KVM module is loaded.

```bash
# Check CPU flags (intel: vmx, amd: svm)
grep -Ec '(vmx|svm)' /proc/cpuinfo
```

If the command returns `0`, hardware virtualization is either absent from the processor or disabled in the BIOS/UEFI. In that case, access your machine's firmware settings and enable "Intel VT-x" or "AMD-V" / "SVM Mode" depending on your processor.

```bash
# Check that the KVM module is loaded
lsmod | grep kvm
```

You should see `kvm` and `kvm_intel` (or `kvm_amd`) in the list. If not:

```bash
sudo modprobe kvm  
sudo modprobe kvm_intel   # or kvm_amd  
```

For a complete diagnostic, the `cpu-checker` package provides the `kvm-ok` command:

```bash
sudo apt install cpu-checker  
kvm-ok  
```

The expected output is: `INFO: /dev/kvm exists` followed by `KVM acceleration can be used`.

---

## Installing Packages

On Debian/Ubuntu, the installation is done in a single command:

```bash
sudo apt update  
sudo apt install qemu-system-x86 qemu-utils libvirt-daemon-system \  
                 libvirt-clients virtinst virt-manager bridge-utils
```

Package details:

- `qemu-system-x86` — the QEMU emulator for the x86-64 architecture.  
- `qemu-utils` — utilities for manipulating disk images (`qemu-img`).  
- `libvirt-daemon-system` and `libvirt-clients` — the libvirt management layer, which provides a unified API for controlling QEMU/KVM. We will primarily use it through `virsh`.  
- `virtinst` — command-line VM installation tools (`virt-install`).  
- `virt-manager` — optional graphical interface but useful for getting started.  
- `bridge-utils` — network bridge management utilities (`brctl`), complemented by the modern `ip` command.

Add your user to the `libvirt` group to avoid working as root:

```bash
sudo usermod -aG libvirt $(whoami)  
newgrp libvirt  
```

Verify that the libvirt service is active:

```bash
sudo systemctl enable --now libvirtd  
systemctl status libvirtd  
```

---

## Creating the qcow2 Disk Image

The **qcow2** (QEMU Copy-On-Write version 2) format is the natural choice for our lab. It offers three essential properties: dynamic allocation (the file only takes up on the host disk the space actually used by the VM), native snapshot support, and optional compression.

Let's create a 30 GB image for our analysis VM:

```bash
qemu-img create -f qcow2 malware-lab.qcow2 30G
```

This command creates a file that weighs only a few hundred KB on disk. The 30 GB represents the maximum size the VM will be able to use — space will be allocated as the guest system writes data.

> 💡 **Why 30 GB?** It's a compromise. The minimal Debian system with our RE tools occupies about 8-10 GB. The rest leaves room for samples, `tcpdump` captures, Ghidra exports, and temporary analysis files. If space runs out, the image can be enlarged later with `qemu-img resize`.

---

## Installing the Guest System

We install a minimal Debian (or Ubuntu Server) system. The goal is to have a lightweight system, without a superfluous desktop environment, on which we will install only the tools needed for analysis.

Download the installation ISO:

```bash
# Example with Debian 12 (Bookworm) netinst
wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.*-amd64-netinst.iso
```

> ⚠️ **Important** — Downloading the ISO and installing packages in the VM require temporary network access. This network will be **permanently cut off** before the first sample execution. Network access during installation is not a violation of our isolation principles: no hostile code is present in the VM at this stage.

Launch the installation with `virt-install`:

```bash
virt-install \
  --name malware-lab \
  --ram 4096 \
  --vcpus 2 \
  --disk path=./malware-lab.qcow2,format=qcow2 \
  --cdrom debian-12.*-amd64-netinst.iso \
  --os-variant debian12 \
  --network network=default \
  --graphics spice \
  --video virtio \
  --boot uefi \
  --noautoconsole
```

Details of the important parameters:

- `--ram 4096` — 4 GB of RAM. Sufficient for GDB and Frida. If you plan to use Ghidra inside the VM (and not on the host), increase to 8 GB.  
- `--vcpus 2` — two virtual cores. The monitoring tools and the sample need to be able to run in parallel without blocking each other.  
- `--network network=default` — libvirt's default NAT network, **used only during installation**. We will replace it with an isolated bridge before any analysis.  
- `--boot uefi` — UEFI boot. This is the standard configuration of modern systems, and some malware checks the boot mode.

Open the graphical console to complete the installation:

```bash
virt-manager &
# Or via console:
virsh console malware-lab
```

During the Debian installation, choose the following options:

- Partitioning: entire disk, everything in a single partition (simplicity).  
- Software: uncheck everything except "standard system utilities" and "SSH server". No desktop environment.  
- Create a non-root user named `analyst`.

---

## Installing RE Tools in the VM

Once the system is installed and booted, connect via SSH (the default NAT network allows this) and install the necessary tools:

```bash
# Basic tools
sudo apt update && sudo apt upgrade -y  
sudo apt install -y build-essential gdb strace ltrace \  
                    python3 python3-pip python3-venv \
                    tcpdump inotify-tools auditd sysdig \
                    wget curl git unzip file binutils \
                    net-tools nmap hexdump xxd

# Frida
python3 -m venv ~/re-venv  
source ~/re-venv/bin/activate  
pip install frida-tools pwntools  

# GEF (GDB extension)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

For Ghidra, two approaches are possible. If you plan to use it from the VM (requires more RAM and an X server or VNC access), install it in the VM. Otherwise — and this is the recommended approach — use Ghidra on the host for static analysis, and reserve the VM for dynamic analysis (GDB, Frida, strace, monitoring). This separation is natural: static analysis does not require executing the sample, so no need for isolation.

> 💡 **Transferring a binary from the VM to the host for static analysis** — Use `scp` via the host-only network (which we will configure below), or temporarily mount a shared directory for the duration of the transfer. The sample never needs to be executed on the host: we copy it only to load it into Ghidra.

Create the working directory for samples:

```bash
mkdir -p ~/malware-samples  
chmod 700 ~/malware-samples  
```

---

## Hardening the VM

Before taking the reference snapshot, let's apply the hardening measures that reduce the attack surface in accordance with the principle of least privilege (Section 26.1).

### Disabling Unnecessary Features

Shut down the VM and modify its configuration with `virsh edit`:

```bash
virsh shutdown malware-lab  
virsh edit malware-lab  
```

In the VM's XML, check or modify the following points:

**Remove unnecessary devices.** Remove the `<channel>` sections related to SPICE file sharing, the `<redirdev>` device (USB redirection), and the `<filesystem>` if present (shared folder):

```xml
<!-- REMOVE if present: shared folder -->
<!-- <filesystem type='mount' accessmode='mapped'>
  <source dir='/home/user/shared'/>
  <target dir='shared'/>
</filesystem> -->

<!-- REMOVE if present: USB redirection -->
<!-- <redirdev bus='usb' type='spicevmc'/> -->
```

**Disable the shared clipboard.** If a SPICE channel `com.redhat.spice.0` is defined, make sure no agent is installed in the VM (`spice-vdagent`). The simplest approach is not to install that package.

**Limit USB controllers.** If the VM does not need USB (our case), remove the USB controller or leave it empty with no attached devices.

### Creating a Dedicated User for Sample Execution

In the VM, we will separate the `analyst` user (who runs the analysis tools) from an even more restricted user who will execute the samples:

```bash
sudo useradd -m -s /bin/bash sample-runner  
sudo chmod 700 /home/sample-runner  
```

The idea is to run samples under `sample-runner` (via `sudo -u sample-runner`) while the monitoring tools run under `analyst` or `root`. This adds a layer of privilege separation within the VM itself: if the sample attempts to access `analyst`'s files (notes, scripts, GDB configurations), Unix permissions will prevent it.

---

## Snapshot Management

Snapshots are the cornerstone of reversibility. With the qcow2 format, QEMU stores snapshots inside the image file itself as copy-on-write layers. Creating a snapshot is virtually instantaneous and only costs the space of blocks modified after the snapshot.

### The Reference Snapshot (Golden Image)

After installing the system, the tools, and hardening — but **before copying any sample into the VM** — take the reference snapshot:

```bash
# VM shut down (offline snapshot — the most reliable)
virsh snapshot-create-as malware-lab \
  --name "clean-base" \
  --description "Debian 12 + RE tools, hardened, no sample present" \
  --atomic
```

This snapshot is your **guaranteed rollback point**. Whatever happens in the VM after this point, you can always return to this clean state.

Verify its creation:

```bash
virsh snapshot-list malware-lab
```

### Analysis Workflow with Snapshots

Each sample analysis session follows the same three-step workflow:

```
1. RESTORE the clean-base snapshot
   └─ virsh snapshot-revert malware-lab --snapshotname "clean-base"

2. PREPARE the session
   ├─ Start the VM
   ├─ Copy the sample into ~/malware-samples/
   ├─ Enable monitoring (auditd, tcpdump, inotifywait)
   ├─ Take a named pre-execution snapshot
   │   └─ virsh snapshot-create-as malware-lab \
   │        --name "pre-exec-ch27-ransomware-$(date +%Y%m%d-%H%M)"
   └─ Verify network isolation (see Section 26.4)

3. EXECUTE and OBSERVE
   ├─ Run the sample under the sample-runner user
   ├─ Observe with the monitoring tools
   ├─ Collect artifacts (pcap, auditd logs, modified files)
   └─ Optional: take a post-execution snapshot if the
      compromised VM state is worth preserving for analysis
```

After the session, we revert to the `clean-base` snapshot for the next analysis. Collected artifacts (`.pcap` files, logs) are transferred to the host via `scp` before the rollback.

### Snapshot Reference Commands

```bash
# List snapshots
virsh snapshot-list malware-lab

# Create a snapshot (VM running — live snapshot)
virsh snapshot-create-as malware-lab \
  --name "descriptive-name" \
  --description "Description of the state"

# Create a snapshot (VM shut down — offline snapshot, more reliable)
virsh shutdown malware-lab  
virsh snapshot-create-as malware-lab --name "descriptive-name" --atomic  

# Restore a snapshot
virsh snapshot-revert malware-lab --snapshotname "clean-base"

# Delete a snapshot that is no longer needed
virsh snapshot-delete malware-lab --snapshotname "name-to-delete"

# View snapshot details
virsh snapshot-info malware-lab --snapshotname "clean-base"
```

> 💡 **Live vs offline snapshots** — A live snapshot captures the complete state of the running VM (including RAM). It is heavier but allows you to resume exactly where you left off. An offline snapshot (VM shut down) captures only the disk state. For the `clean-base` snapshot, offline mode is preferable: it is smaller, faster to restore, and there is no memory state to preserve at this stage.

---

## Network Configuration: From NAT to Isolation

This is the most critical step of the entire setup. We will create a network configuration that allows two mutually exclusive modes of operation:

- **Maintenance mode** — the VM has network access (NAT) to install or update packages. No sample is present or executed in this mode.  
- **Analysis mode** — the VM is connected to an isolated bridge with no route to the outside. This is the only mode in which a sample can be executed.

### Creating the Isolated Network with libvirt

Libvirt manages virtual networks through XML files. Let's create a network named `isolated-malware`:

```bash
cat > /tmp/isolated-malware.xml << 'EOF'
<network>
  <name>isolated-malware</name>
  <bridge name="br-malware" stp="on" delay="0"/>
  <ip address="10.66.66.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.66.66.100" end="10.66.66.200"/>
    </dhcp>
  </ip>
  <!-- NO <forward>: this is what makes the network isolated.
       Without a <forward> element, libvirt creates no
       iptables NAT rules or routing to the outside. -->
</network>
EOF

virsh net-define /tmp/isolated-malware.xml  
virsh net-start isolated-malware  
virsh net-autostart isolated-malware  
```

The absence of a `<forward>` tag is the key. Let's compare with libvirt's `default` network:

```xml
<!-- "default" network (NAT to the outside — DANGEROUS for analysis) -->
<network>
  <name>default</name>
  <forward mode='nat'/>          <!-- ← This line grants Internet access -->
  <bridge name='virbr0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>...</dhcp>
  </ip>
</network>

<!-- "isolated-malware" network (no way out — SAFE for analysis) -->
<network>
  <name>isolated-malware</name>
  <!-- No <forward>: nothing gets out -->
  <bridge name='br-malware'/>
  <ip address='10.66.66.1' netmask='255.255.255.0'>
    <dhcp>...</dhcp>
  </ip>
</network>
```

### Switching the VM Between the Two Networks

To switch from maintenance mode to analysis mode (and vice versa), we modify the VM's network interface:

```bash
# Switch to analysis mode (isolated network)
virsh detach-interface malware-lab network --current  
virsh attach-interface malware-lab network isolated-malware --current  

# Switch to maintenance mode (NAT — never with a sample present)
virsh detach-interface malware-lab network --current  
virsh attach-interface malware-lab network default --current  
```

In the VM, restart the DHCP client to obtain an address on the new network:

```bash
sudo dhclient -r && sudo dhclient  
ip addr show  
```

In analysis mode, the VM will obtain an address in `10.66.66.x`. It will be able to communicate with the host at `10.66.66.1` (useful for `scp`), but **no route leads beyond that**.

### Locking Down the Configuration with iptables on the Host

As an additional precaution, let's add `iptables` rules on the host that explicitly block all forwarding from the `br-malware` bridge:

```bash
# Block all forwarding from/to br-malware
sudo iptables -I FORWARD -i br-malware -o eth0 -j DROP  
sudo iptables -I FORWARD -i eth0 -o br-malware -j DROP  

# Also block toward other interfaces (wlan0, etc.)
sudo iptables -I FORWARD -i br-malware ! -o br-malware -j DROP
```

> ⚠️ Replace `eth0` with the actual name of your external network interface (`ip route show default` to identify it).

These rules are an **additional safety net**. Even if a libvirt misconfiguration created an unintended route, `iptables` would block the traffic at the host kernel level.

To persist these rules across reboots:

```bash
sudo apt install iptables-persistent  
sudo netfilter-persistent save  
```

---

## Automating the Workflow with Scripts

Everything we have done manually so far can (and should) be encapsulated in scripts. Here is the recommended structure:

### Session Preparation Script

```bash
#!/bin/bash
# prepare_analysis.sh — Prepares the VM for an analysis session
# Usage: ./prepare_analysis.sh <sample-name>

set -euo pipefail

SAMPLE_NAME="${1:?Usage: $0 <sample-name>}"  
VM_NAME="malware-lab"  
TIMESTAMP=$(date +%Y%m%d-%H%M%S)  
SNAPSHOT_NAME="pre-exec-${SAMPLE_NAME}-${TIMESTAMP}"  

echo "[*] Restoring clean-base snapshot..."  
virsh snapshot-revert "$VM_NAME" --snapshotname "clean-base"  

echo "[*] Starting the VM..."  
virsh start "$VM_NAME"  

echo "[*] Waiting for boot (30s)..."  
sleep 30  

echo "[*] Switching to isolated network..."  
virsh detach-interface "$VM_NAME" network --current 2>/dev/null || true  
virsh attach-interface "$VM_NAME" network isolated-malware --current  

echo "[*] Taking pre-execution snapshot: $SNAPSHOT_NAME"  
virsh snapshot-create-as "$VM_NAME" \  
  --name "$SNAPSHOT_NAME" \
  --description "Before execution of $SAMPLE_NAME"

echo "[+] VM ready for analysis of: $SAMPLE_NAME"  
echo "    Snapshot: $SNAPSHOT_NAME"  
echo "    Network : isolated-malware (10.66.66.0/24)"  
echo ""  
echo "    Next steps:"  
echo "    1. ssh analyst@10.66.66.100"  
echo "    2. Copy the sample: scp $SAMPLE_NAME analyst@10.66.66.100:~/malware-samples/"  
echo "    3. Start monitoring (see Section 26.3)"  
echo "    4. Execute the sample"  
```

### Post-Analysis Cleanup Script

```bash
#!/bin/bash
# cleanup_analysis.sh — Collects artifacts and restores the clean state
# Usage: ./cleanup_analysis.sh <sample-name>

set -euo pipefail

SAMPLE_NAME="${1:?Usage: $0 <sample-name>}"  
VM_NAME="malware-lab"  
TIMESTAMP=$(date +%Y%m%d-%H%M%S)  
OUTPUT_DIR="./analyses/${SAMPLE_NAME}-${TIMESTAMP}"  

mkdir -p "$OUTPUT_DIR"

echo "[*] Collecting artifacts from the VM..."  
VM_IP="10.66.66.100"  

scp "analyst@${VM_IP}:~/captures/*.pcap" "$OUTPUT_DIR/" 2>/dev/null || echo "    No pcap"  
scp "analyst@${VM_IP}:~/captures/audit.log" "$OUTPUT_DIR/" 2>/dev/null || echo "    No audit log"  
scp "analyst@${VM_IP}:~/captures/inotify.log" "$OUTPUT_DIR/" 2>/dev/null || echo "    No inotify log"  

echo "[*] Artifacts saved in: $OUTPUT_DIR"

echo "[*] Restoring clean-base snapshot..."  
virsh snapshot-revert "$VM_NAME" --snapshotname "clean-base"  

echo "[+] Cleanup complete. The VM has been reverted to the clean state."
```

These scripts are starting points. Adapt them to your workflow and enrich them as you perform analyses.

---

## Post-Installation Checks

Before considering the lab operational, verify the following points:

```bash
# 1. The VM starts correctly
virsh start malware-lab  
virsh list --all    # State: "running"  

# 2. The clean-base snapshot exists and is restorable
virsh snapshot-list malware-lab  
virsh snapshot-revert malware-lab --snapshotname "clean-base"  

# 3. The isolated network is active
virsh net-list --all
# "isolated-malware" must be "active"

# 4. In analysis mode, the VM does NOT have Internet access
# (From the VM, after switching to isolated-malware):
ping -c 3 8.8.8.8          # Must fail (timeout)  
ping -c 3 1.1.1.1          # Must fail (timeout)  
curl -m 5 http://example.com  # Must fail (timeout)  

# 5. In analysis mode, the VM can reach the host
ping -c 3 10.66.66.1       # Must succeed (host ↔ VM communication)

# 6. The host does NOT forward packets from the bridge
sudo iptables -L FORWARD -v | grep br-malware
# The DROP rules must be present
```

Check #4 is the most important. If `ping 8.8.8.8` succeeds from the VM in analysis mode, **the lab is not isolated**. Do not proceed until this issue is resolved.

---

## Network Architecture Summary

```
HOST MACHINE
│
├── eth0 (or wlan0) ─────────── Internet / LAN
│     │
│     │  iptables: DROP all forwarding from br-malware
│     │
├── virbr0 (192.168.122.0/24) ── "default" network (NAT)
│     │                            └─ Maintenance mode only
│     │
├── br-malware (10.66.66.0/24) ── "isolated-malware" network
│     │                              ├─ No <forward>
│     │                              ├─ No NAT
│     │                              ├─ No external route
│     │                              └─ tcpdump listens here
│     │
│     └── VM malware-lab
│           └─ 10.66.66.100 (DHCP)
│
└── Absolute rule: the VM is NEVER on virbr0
    when a sample is present in ~/malware-samples/
```

---

> 📌 **Key takeaway** — The VM is a disposable tool. Treat it like a latex glove: put it on clean, handle the sample, then throw it away (rollback) and grab a fresh one (snapshot). If you hesitate to restore the snapshot because you have "important stuff in the VM," that's a sign your host/VM separation isn't strict enough. Notes, reports, and analysis scripts live on the host. The VM contains only what can be destroyed without regret.

⏭️ [Monitoring tools: `auditd`, `inotifywait`, `tcpdump`, `sysdig`](/26-secure-lab/03-monitoring-tools.md)
