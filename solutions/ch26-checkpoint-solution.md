🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Solution — Chapter 26 Checkpoint
# Deploy the Lab and Verify Network Isolation

> **Spoiler** — This file contains the complete solution for the chapter 26 checkpoint. Try to perform the deployment on your own before consulting this solution.

---

## Overview

This solution presents all the commands to execute, in order, to deploy the lab from scratch and validate each item on the checkpoint checklist. Each command is accompanied by the expected output, so you can compare with your own results and precisely identify the source of any discrepancy.

The solution is divided into two parts: **deployment** (if you haven't built the lab yet) and **verification** (if the lab is already in place and you only want to validate the checkpoint).

---

## Part A — Complete Lab Deployment

### A.1 — Host Prerequisites

```bash
# Check hardware virtualization support
grep -Ec '(vmx|svm)' /proc/cpuinfo
# Expected: a number > 0 (number of cores with VT-x/AMD-V support)

# Install required packages
sudo apt update  
sudo apt install -y qemu-system-x86 qemu-utils libvirt-daemon-system \  
                    libvirt-clients virtinst virt-manager bridge-utils \
                    cpu-checker wireshark tshark

# Check KVM
sudo modprobe kvm  
sudo modprobe kvm_intel  # or kvm_amd depending on your CPU  
kvm-ok  
# Expected:
# INFO: /dev/kvm exists
# KVM acceleration can be used

# Add user to the libvirt group
sudo usermod -aG libvirt $(whoami)  
newgrp libvirt  

# Start libvirtd
sudo systemctl enable --now libvirtd  
systemctl is-active libvirtd  
# Expected: active
```

### A.2 — VM Creation

```bash
# Create the disk image
mkdir -p ~/malware-lab  
cd ~/malware-lab  
qemu-img create -f qcow2 malware-lab.qcow2 30G  
# Expected:
# Formatting 'malware-lab.qcow2', fmt=qcow2 size=32212254720 ...

# Check actual size on disk (dynamic allocation)
ls -lh malware-lab.qcow2
# Expected: only a few hundred KB

# Download the Debian ISO (adjust version as needed)
wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.7.0-amd64-netinst.iso

# Launch the installation
virt-install \
  --name malware-lab \
  --ram 4096 \
  --vcpus 2 \
  --disk path=./malware-lab.qcow2,format=qcow2 \
  --cdrom debian-12.7.0-amd64-netinst.iso \
  --os-variant debian12 \
  --network network=default \
  --graphics spice \
  --video virtio \
  --boot uefi \
  --noautoconsole
# Expected: "Domain installation still in progress..."

# Open the graphical console to complete the installation
virt-manager &
```

**Choices during Debian installation:**

- Language: your preference (doesn't affect the lab).  
- Partitioning: entire disk, everything in a single partition.  
- Software to install: uncheck everything **except** "standard system utilities" and "SSH server".  
- Create a user: `analyst` (password of your choice).  
- Root password: set a password (needed for initial `sudo`).

### A.3 — Post-Installation Configuration in the VM

Once Debian is installed and the VM has rebooted, connect via SSH from the host (the default NAT network allows this via the IP assigned by `virbr0`'s DHCP):

```bash
# Find the VM's IP
virsh domifaddr malware-lab
# Expected: an address in 192.168.122.x

# Connect
ssh analyst@192.168.122.xxx
```

In the VM:

```bash
# Switch to root for initial configuration
su -

# Add analyst to the sudo group
usermod -aG sudo analyst  
exit  

# Reconnect as analyst with sudo available
exit  
ssh analyst@192.168.122.xxx  

# Install RE and monitoring tools
sudo apt update && sudo apt upgrade -y  
sudo apt install -y build-essential gdb strace ltrace \  
                    python3 python3-pip python3-venv \
                    tcpdump inotify-tools auditd \
                    wget curl git unzip file binutils \
                    net-tools nmap xxd dnsutils

# Install sysdig
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash

# Install Frida and pwntools in a venv
python3 -m venv ~/re-venv  
source ~/re-venv/bin/activate  
pip install frida-tools pwntools  
deactivate  

# Install GEF (GDB extension)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Create the sample-runner user
sudo useradd -m -s /bin/bash sample-runner  
sudo chmod 700 /home/sample-runner  

# Create working directories
mkdir -p ~/malware-samples ~/captures  
chmod 700 ~/malware-samples  
```

### A.4 — VM Hardening

```bash
# Verify that spice-vdagent is NOT installed
dpkg -l | grep spice-vdagent
# Expected: no output (not installed on a minimal Debian)
# If present:
# sudo apt remove --purge spice-vdagent

# Verify that no shared folder is mounted
mount | grep -iE '(vboxsf|vmhgfs|9p|shared)'
# Expected: no output
```

On the **host**, edit the VM configuration to remove unnecessary devices:

```bash
virsh shutdown malware-lab  
virsh edit malware-lab  
```

In the XML editor, check and remove if present:

- `<filesystem>` blocks (shared folders).  
- `<redirdev>` blocks (USB redirection).  
- `<channel>` blocks related to `spicevmc` other than the main channel.

Save and exit the editor.

### A.5 — Creating auditd Rules

In the VM:

```bash
sudo tee /etc/audit/rules.d/malware-analysis.rules << 'EOF'
-D
-b 8192

# Program execution
-a always,exit -F arch=b64 -S execve -k exec_monitor

# File open/create
-a always,exit -F arch=b64 -S open,openat -F dir=/home -k file_access
-a always,exit -F arch=b64 -S open,openat -F dir=/tmp -k file_access
-a always,exit -F arch=b64 -S open,openat -F dir=/etc -k file_access

# Network connections
-a always,exit -F arch=b64 -S connect -k net_connect
-a always,exit -F arch=b64 -S bind -k net_bind
-a always,exit -F arch=b64 -S accept,accept4 -k net_accept

# Permissions
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k perm_change
-a always,exit -F arch=b64 -S chown,fchown,fchownat -k owner_change

# Processes
-a always,exit -F arch=b64 -S clone,fork,vfork -k proc_create
-a always,exit -F arch=b64 -S ptrace -k ptrace_use
-a always,exit -F arch=b64 -S kill,tkill,tgkill -k signal_send

# File deletion/renaming
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -k file_delete

# Persistence
-w /etc/crontab -p wa -k persist_cron
-w /etc/cron.d/ -p wa -k persist_cron
-w /var/spool/cron/ -p wa -k persist_cron
-w /etc/systemd/system/ -p wa -k persist_systemd
-w /etc/init.d/ -p wa -k persist_init
-w /home/sample-runner/.bashrc -p wa -k persist_shell
-w /home/sample-runner/.profile -p wa -k persist_shell
EOF

sudo augenrules --load  
sudo auditctl -l  
# Expected: the complete list of rules is displayed (about twenty lines)
```

### A.6 — clean-base Snapshot

```bash
# On the host — cleanly shut down the VM
virsh shutdown malware-lab

# Wait for complete shutdown
virsh list --all | grep malware-lab
# Expected: "shut off"

# Take the reference snapshot
virsh snapshot-create-as malware-lab \
  --name "clean-base" \
  --description "Debian 12 + RE tools + monitoring + hardened. No samples." \
  --atomic

# Verify
virsh snapshot-list malware-lab
# Expected:
#  Name          Creation Time               State
# ---------------------------------------------------
#  clean-base    2025-06-15 14:00:00 +0200   shutoff
```

### A.7 — Isolated Network and iptables Rules

On the **host**:

```bash
# Create the isolated network
cat > /tmp/isolated-malware.xml << 'EOF'
<network>
  <name>isolated-malware</name>
  <bridge name="br-malware" stp="on" delay="0"/>
  <ip address="10.66.66.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.66.66.100" end="10.66.66.200"/>
    </dhcp>
  </ip>
</network>
EOF

virsh net-define /tmp/isolated-malware.xml  
virsh net-start isolated-malware  
virsh net-autostart isolated-malware  

# Verify
virsh net-list --all | grep isolated-malware
# Expected: isolated-malware   active   yes   ...

ip addr show br-malware
# Expected: inet 10.66.66.1/24 ...

# Add blocking iptables rules
# Identify the external network interface
DEFAULT_IF=$(ip route show default | awk '{print $5}' | head -1)  
echo "Detected external interface: $DEFAULT_IF"  

sudo iptables -I FORWARD -i br-malware -o "$DEFAULT_IF" -j DROP  
sudo iptables -I FORWARD -i "$DEFAULT_IF" -o br-malware -j DROP  
sudo iptables -I FORWARD -i br-malware ! -o br-malware -j DROP  

# Persist rules
sudo apt install -y iptables-persistent  
sudo netfilter-persistent save  

# Verify
sudo iptables -L FORWARD -v -n | grep br-malware
# Expected: 2-3 DROP rules mentioning br-malware
```

### A.8 — Automation Scripts

On the **host**, create the scripts in the lab directory:

```bash
cd ~/malware-lab  
mkdir -p scripts analyses  
```

**`scripts/prepare_analysis.sh`**:

```bash
cat > scripts/prepare_analysis.sh << 'SCRIPT'
#!/bin/bash
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

echo "[*] Waiting for DHCP (10s)..."  
sleep 10  

echo "[*] Taking pre-execution snapshot: $SNAPSHOT_NAME"  
virsh snapshot-create-as "$VM_NAME" \  
  --name "$SNAPSHOT_NAME" \
  --description "Before execution of $SAMPLE_NAME"

echo ""  
echo "[+] VM ready for analysis of: $SAMPLE_NAME"  
echo "    Snapshot: $SNAPSHOT_NAME"  
echo "    Network : isolated-malware (10.66.66.0/24)"  
SCRIPT  
chmod +x scripts/prepare_analysis.sh  
```

**`scripts/cleanup_analysis.sh`**:

```bash
cat > scripts/cleanup_analysis.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail

SAMPLE_NAME="${1:?Usage: $0 <sample-name>}"  
VM_NAME="malware-lab"  
TIMESTAMP=$(date +%Y%m%d-%H%M%S)  
OUTPUT_DIR="./analyses/${SAMPLE_NAME}-${TIMESTAMP}"  
VM_IP="10.66.66.100"  

mkdir -p "$OUTPUT_DIR"

echo "[*] Collecting artifacts from the VM..."  
scp "analyst@${VM_IP}:~/captures/*" "$OUTPUT_DIR/" 2>/dev/null || echo "    No captures"  
scp "analyst@${VM_IP}:/var/log/audit/audit.log" "$OUTPUT_DIR/" 2>/dev/null || echo "    No audit log"  

echo "[*] Artifacts saved to: $OUTPUT_DIR"  
ls -la "$OUTPUT_DIR/"  

echo "[*] Restoring clean-base snapshot..."  
virsh snapshot-revert "$VM_NAME" --snapshotname "clean-base"  

echo "[+] Cleanup complete."  
SCRIPT  
chmod +x scripts/cleanup_analysis.sh  
```

**`scripts/start_monitoring.sh`** (to copy into the VM):

```bash
cat > scripts/start_monitoring.sh << 'VMSCRIPT'
#!/bin/bash
set -euo pipefail

echo "=== Network Isolation Check ==="  
if ip route | grep -q "^default"; then  
    echo "[FAIL] Default route detected — DO NOT EXECUTE"
    exit 1
fi  
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then  
    echo "[FAIL] Internet accessible — DO NOT EXECUTE"
    exit 1
fi  
echo "[OK] Network isolation confirmed"  
echo ""  

CAPTURE_DIR=~/captures/$(date +%Y%m%d-%H%M%S)  
mkdir -p "$CAPTURE_DIR"  

echo "[*] Loading auditd rules..."  
sudo augenrules --load  
sudo truncate -s 0 /var/log/audit/audit.log  

echo "[*] Starting inotifywait..."  
inotifywait -m -r \  
  --timefmt '%Y-%m-%d %H:%M:%S' \
  --format '%T %w%f %e' \
  -e create,delete,modify,move,attrib \
  /home/sample-runner/ /tmp/ /etc/ /var/ \
  > "$CAPTURE_DIR/inotify.log" 2>&1 &
INOTIFY_PID=$!

echo "[*] Starting sysdig..."  
sudo sysdig -w "$CAPTURE_DIR/sysdig.scap" "user.name=sample-runner" &  
SYSDIG_PID=$!  

echo ""  
echo "[+] Monitoring active. Captures in: $CAPTURE_DIR"  
echo "    inotifywait PID: $INOTIFY_PID"  
echo "    sysdig PID     : $SYSDIG_PID"  
echo ""  
echo "    To stop: kill $INOTIFY_PID && sudo kill $SYSDIG_PID"  
echo "    Remember: tcpdump must run on the HOST"  
echo ""  
echo "    Execute the sample:"  
echo "    sudo -u sample-runner ~/malware-samples/<sample>"  
VMSCRIPT  
chmod +x scripts/start_monitoring.sh  
```

---

## Part B — Complete Verification (Checkpoint Protocol)

This part executes exactly the verification protocol described in the checkpoint. If you followed Part A, each command should produce the expected result.

### B.1 — Virtualization Infrastructure

```bash
kvm-ok
# ✅ Expected:
# INFO: /dev/kvm exists
# KVM acceleration can be used

systemctl is-active libvirtd
# ✅ Expected: active

virsh list --all | grep malware-lab
# ✅ Expected:
#  -   malware-lab   shut off
# (or "running" if the VM is started)

virsh snapshot-list malware-lab | grep clean-base
# ✅ Expected:
#  clean-base   2025-06-15T14:00:00+02:00   shutoff

virsh net-list --all | grep isolated-malware
# ✅ Expected:
#  isolated-malware   active   yes   ...
```

**Result: 5/5 ✅**

### B.2 — Network Isolation

```bash
# Start and switch to the isolated network
virsh start malware-lab  
sleep 30  
virsh detach-interface malware-lab network --current 2>/dev/null || true  
virsh attach-interface malware-lab network isolated-malware --current  
sleep 10  

# Connect to the VM
ssh analyst@10.66.66.100
# (If the connection fails, the VM may not have obtained its IP yet.
#  Use virsh console malware-lab and run sudo dhclient)
```

In the VM:

```bash
sudo dhclient -r && sudo dhclient

# Test 1: correct IP address
ip addr show | grep "10.66.66"
# ✅ Expected: inet 10.66.66.100/24 (or .101, .102... depending on DHCP)

# Test 2: communication with the host
ping -c 3 10.66.66.1
# ✅ Expected:
# 3 packets transmitted, 3 received, 0% packet loss

# Test 3: Internet inaccessible (Google DNS IP)
ping -c 3 -W 2 8.8.8.8
# ✅ Expected:
# 3 packets transmitted, 0 received, 100% packet loss

# Test 4: Internet inaccessible (Cloudflare IP)
ping -c 3 -W 2 1.1.1.1
# ✅ Expected:
# 3 packets transmitted, 0 received, 100% packet loss

# Test 5: public DNS resolution impossible
host example.com
# ✅ Expected:
# ;; connection timed out; no servers could be reached
# (or Host example.com not found if dnsmasq runs without universal resolution)

# Test 6: no default route
ip route
# ✅ Expected:
# 10.66.66.0/24 dev enp1s0 proto kernel scope link src 10.66.66.100
# (NO "default via ..." line)

# Test 7: download impossible
curl -m 5 http://example.com
# ✅ Expected:
# curl: (28) Connection timed out
# or curl: (6) Could not resolve host: example.com
```

On the **host**:

```bash
sudo iptables -L FORWARD -v -n | grep br-malware
# ✅ Expected: lines containing DROP and br-malware
# Example:
#     0     0 DROP   all  --  br-malware !br-malware  0.0.0.0/0   0.0.0.0/0
#     0     0 DROP   all  --  br-malware eth0         0.0.0.0/0   0.0.0.0/0
#     0     0 DROP   all  --  eth0       br-malware   0.0.0.0/0   0.0.0.0/0
```

**Result: 8/8 ✅**

### B.3 — Monitoring

In the VM:

```bash
# --- auditd ---
sudo systemctl is-active auditd
# ✅ Expected: active

sudo augenrules --load  
sudo auditctl -l | head -5  
# ✅ Expected: rules are displayed
# -a always,exit -F arch=b64 -S execve -F key=exec_monitor
# -a always,exit -F arch=b64 -S open,openat -F dir=/tmp -F key=file_access
# ...

touch /tmp/test_audit_verify  
sudo ausearch -k file_access -ts recent --interpret 2>/dev/null | grep test_audit_verify  
# ✅ Expected: at least one line mentioning test_audit_verify
rm /tmp/test_audit_verify

# --- inotifywait ---
which inotifywait
# ✅ Expected: /usr/bin/inotifywait

inotifywait -m -r /tmp/ --format '%T %w%f %e' --timefmt '%H:%M:%S' &  
INOTIFY_PID=$!  
sleep 1  
echo "test" > /tmp/test_inotify_verify  
# ✅ Expected: one or more lines appear immediately:
# 14:35:22 /tmp/test_inotify_verify CREATE
# 14:35:22 /tmp/test_inotify_verify MODIFY
kill $INOTIFY_PID 2>/dev/null  
rm /tmp/test_inotify_verify  

# --- sysdig ---
sudo sysdig --version
# ✅ Expected: a version number (e.g.: sysdig version 0.35.1)

sudo timeout 3 sysdig "evt.type=open and proc.name=bash" 2>/dev/null | head -3
# ✅ Expected: a few event lines or nothing (no error)
```

On the **host**:

```bash
# --- tcpdump ---
# Terminal 1 (host): start tcpdump
sudo timeout 15 tcpdump -i br-malware -c 10 --print &  
TCPDUMP_PID=$!  

# Terminal 2 (VM): generate traffic
ssh analyst@10.66.66.100 'ping -c 5 10.66.66.1'

# ✅ Expected in tcpdump output:
# 14:36:01.123456 IP 10.66.66.100 > 10.66.66.1: ICMP echo request ...
# 14:36:01.123789 IP 10.66.66.1 > 10.66.66.100: ICMP echo reply ...
```

**Result: 4/4 ✅**

### B.4 — Hardening

In the VM:

```bash
# No shared folder
mount | grep -iE '(vboxsf|vmhgfs|9p|shared)'
# ✅ Expected: no output

# spice-vdagent absent
pgrep spice-vdagent
# ✅ Expected: no PID (return code 1)

# sample-runner user
id sample-runner
# ✅ Expected: uid=1001(sample-runner) gid=1001(sample-runner) groups=1001(sample-runner)
# (uid/gid numbers may vary)

# /home/sample-runner permissions
ls -ld /home/sample-runner/
# ✅ Expected: drwx------ 2 sample-runner sample-runner ... /home/sample-runner/

# malware-samples directory
ls -ld ~/malware-samples/
# ✅ Expected: drwx------ 2 analyst analyst ... /home/analyst/malware-samples/
```

**Result: 5/5 ✅**

### B.5 — Complete Snapshot Cycle

On the **host**:

```bash
# Create a test snapshot
virsh snapshot-create-as malware-lab \
  --name "test-checkpoint-solution" \
  --description "Test snapshot for the ch26 checkpoint solution"
# ✅ Expected: Domain snapshot test-checkpoint-solution created

# Create a marker file in the VM
ssh analyst@10.66.66.100 'echo "MARKER_CHECKPOINT_CH26" > ~/marker.txt'

# Verify that the file exists
ssh analyst@10.66.66.100 'cat ~/marker.txt'
# ✅ Expected: MARKER_CHECKPOINT_CH26

# Restore the snapshot (the VM is stopped by the revert)
virsh snapshot-revert malware-lab --snapshotname "test-checkpoint-solution"

# Restart the VM
virsh start malware-lab  
sleep 30  

# Switch back to the isolated network to reconnect
virsh detach-interface malware-lab network --current 2>/dev/null || true  
virsh attach-interface malware-lab network isolated-malware --current  
sleep 10  

# Verify that the marker has DISAPPEARED
ssh analyst@10.66.66.100 'cat ~/marker.txt 2>&1'
# ✅ Expected:
# cat: /home/analyst/marker.txt: No such file or directory

# Clean up the test snapshot
virsh snapshot-delete malware-lab --snapshotname "test-checkpoint-solution"
# ✅ Expected: Domain snapshot test-checkpoint-solution deleted
```

**Result: 3/3 ✅**

---

## Completed Validation Grid

```
INFRASTRUCTURE
  ✅  kvm-ok confirms virtualization support
  ✅  The malware-lab VM exists and starts
  ✅  The clean-base snapshot exists and is restorable
  ✅  The isolated-malware network is active

NETWORK ISOLATION
  ✅  The VM obtains a 10.66.66.x IP
  ✅  The VM can reach the host (10.66.66.1)
  ✅  ping 8.8.8.8 fails from the VM
  ✅  ping 1.1.1.1 fails from the VM
  ✅  host example.com fails from the VM
  ✅  ip route shows no default route
  ✅  iptables on the host shows DROP rules on br-malware

MONITORING
  ✅  auditd is active, rules load, a test event is captured
  ✅  inotifywait detects test file creation
  ✅  tcpdump on the host captures bridge traffic
  ✅  sysdig runs without error

HARDENING
  ✅  No shared folder mounted
  ✅  spice-vdagent absent or inactive
  ✅  The sample-runner user exists
  ✅  /home/sample-runner/ has 700 permissions
  ✅  ~/malware-samples/ exists

SNAPSHOTS
  ✅  A test snapshot can be created
  ✅  A file created after the snapshot disappears after rollback
  ✅  The test snapshot is cleaned up

TOTAL: 22/22 ✅ — Checkpoint passed.
```

---

## Common Problems and Solutions

### "`ping 8.8.8.8` succeeds from the VM"

This is the most common and most critical problem. Possible causes:

1. **The VM is still on the `default` network.** Check with `virsh domiflist malware-lab`. If the "Source" column shows `default`, switch:
   ```bash
   virsh detach-interface malware-lab network --current
   virsh attach-interface malware-lab network isolated-malware --current
   ```

2. **IP forwarding is enabled on the host.** Check with `cat /proc/sys/net/ipv4/ip_forward`. If the value is `1`, the iptables rules must block forwarding from `br-malware`. Recheck the iptables rules.

3. **The iptables rules are not loaded.** After a host reboot, rules may disappear if `iptables-persistent` wasn't installed correctly. Run `sudo netfilter-persistent reload`.

### "SSH to 10.66.66.100 fails"

1. **The VM hasn't obtained an IP.** Connect via `virsh console malware-lab` and run `sudo dhclient`.

2. **The IP is different.** DHCP may assign `.101`, `.102`, etc. Check from the VM console with `ip addr show`.

3. **The SSH service is not installed.** From the console: `sudo apt install openssh-server`.

### "`auditctl -l` shows "No rules""

The rules file exists but hasn't been loaded. Run:
```bash
sudo augenrules --load
```

If the error persists, check the file syntax:
```bash
sudo auditctl -R /etc/audit/rules.d/malware-analysis.rules
```

Syntax errors will be displayed with the line number.

### "The snapshot revert doesn't seem to work"

If the marker file still exists after the revert, verify that you restored the correct snapshot (the one taken **before** creating the file). Check with:
```bash
virsh snapshot-list malware-lab
```

Make sure the `test-checkpoint-solution` snapshot was indeed created before writing the `marker.txt` file.

---

## Final Lab State

After validating the checkpoint, your lab architecture is as follows:

```
~/malware-lab/
├── malware-lab.qcow2              ← VM disk image (with integrated clean-base snapshot)
├── scripts/
│   ├── prepare_analysis.sh        ← Prepares an analysis session
│   ├── cleanup_analysis.sh        ← Collects artifacts and rollback
│   └── start_monitoring.sh        ← To copy into the VM, starts monitoring
└── analyses/                      ← Artifacts directory (empty for now)
```

The `malware-lab` VM contains:

```
/home/analyst/
├── malware-samples/               ← Directory for samples (empty, ready)
├── captures/                      ← Directory for monitoring logs
└── re-venv/                       ← Python environment (Frida, pwntools)

/home/sample-runner/                ← Sample execution user (drwx------)

/etc/audit/rules.d/
└── malware-analysis.rules          ← auditd rules ready to be loaded
```

You are ready for chapter 27.

---

⏭️
