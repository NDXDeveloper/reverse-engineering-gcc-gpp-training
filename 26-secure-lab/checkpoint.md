🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 🎯 Checkpoint — Deploy the Lab and Verify Network Isolation

> **Chapter 26 — Setting Up a Secure Analysis Lab**  
> **Part VI — Malicious Code Analysis (Controlled Environment)**

---

## Objective

This checkpoint validates that your analysis lab is operational and correctly isolated **before** tackling chapters 27, 28, and 29. This is not yet about analyzing a sample — it is about verifying that the environment in which you will do so is reliable. This is the last gate to pass through before handling hostile code.

By the end of this checkpoint, you must have a functional lab that passes all the checks described below. If a single point fails, identify the cause and fix it before proceeding. The following chapters **assume** that this checkpoint is validated.

---

## What you must have in place

The following table summarizes each expected component, the chapter section that details it, and the validation criterion.

| Component | Reference section | Validation criterion |  
|---|---|---|  
| QEMU/KVM functional | 26.2 | `kvm-ok` returns a success message |  
| `malware-lab` VM operational | 26.2 | `virsh list --all` shows the VM |  
| Minimal Debian/Ubuntu system installed | 26.2 | SSH connection to the VM works |  
| RE tools installed in the VM | 26.2 | GDB, strace, Frida, pwntools available |  
| Hardened VM | 26.2 | No shared folders, no `spice-vdagent`, `sample-runner` user created |  
| `clean-base` snapshot | 26.2 | `virsh snapshot-list malware-lab` shows it |  
| `isolated-malware` network active | 26.2 / 26.4 | `virsh net-list --all` shows it active |  
| `br-malware` bridge configured | 26.4 | `ip addr show br-malware` shows `10.66.66.1/24` |  
| `iptables` blocking rules | 26.2 | `iptables -L FORWARD` shows DROP rules on `br-malware` |  
| `auditd` installed and configurable | 26.3 | `systemctl status auditd` active, `auditctl -l` loads rules |  
| `inotify-tools` installed | 26.3 | `which inotifywait` returns a path |  
| `tcpdump` available on the host | 26.3 / 26.4 | `sudo tcpdump -i br-malware -c 1` produces no error |  
| `sysdig` installed in the VM | 26.3 | `sudo sysdig --version` returns a version |  
| Automation scripts in place | 26.2 / 26.3 | `prepare_analysis.sh`, `cleanup_analysis.sh`, `start_monitoring.sh` are executable |

---

## Verification protocol

Follow this protocol in order. Each step depends on the previous one succeeding.

### Phase 1 — Virtualization infrastructure verification

On the **host** machine, run:

```bash
# KVM is functional
kvm-ok

# libvirtd is running
systemctl is-active libvirtd

# The VM exists
virsh list --all | grep malware-lab

# The clean-base snapshot exists
virsh snapshot-list malware-lab | grep clean-base

# The isolated network is active
virsh net-list --all | grep isolated-malware
```

**Expected result**: all five commands return positive results. The VM may be in `shut off` or `running` state. The `isolated-malware` network must be `active`.

### Phase 2 — Network isolation verification

Start the VM and switch it to the isolated network:

```bash
# On the host
virsh start malware-lab
# Wait for complete boot

# Switch to the isolated network
virsh detach-interface malware-lab network --current 2>/dev/null || true  
virsh attach-interface malware-lab network isolated-malware --current  
```

Connect to the VM and run the tests:

```bash
# In the VM (ssh analyst@10.66.66.100 or via virsh console)

# Renew the DHCP lease
sudo dhclient -r && sudo dhclient

# Test 1: the VM has an address on the correct subnet
ip addr show | grep "10.66.66"
# Expected: an address in 10.66.66.x/24

# Test 2: the VM can reach the host on the bridge
ping -c 3 10.66.66.1
# Expected: 3 packets received, 0% loss

# Test 3: the VM CANNOT reach the Internet
ping -c 3 -W 2 8.8.8.8
# Expected: 100% loss (timeout)

# Test 4: the VM CANNOT reach the Internet (second IP)
ping -c 3 -W 2 1.1.1.1
# Expected: 100% loss (timeout)

# Test 5: the VM CANNOT resolve public names
host example.com
# Expected: resolution failure (timeout or SERVFAIL)

# Test 6: no default route
ip route
# Expected: only "10.66.66.0/24 dev enp1s0 ..."
# NO "default via ..." line

# Test 7: no download possible
curl -m 5 http://example.com
# Expected: timeout or connection error
```

**Expected result**: tests 1 and 2 succeed, tests 3 through 7 fail. This is exactly the desired behavior: the VM communicates with the host via the bridge, but it cannot reach anything beyond.

Also verify the `iptables` rules on the **host**:

```bash
# On the host
sudo iptables -L FORWARD -v -n | grep br-malware
# Expected: at least one DROP rule on input and/or output on br-malware
```

### Phase 3 — Monitoring verification

Still in the VM (on the isolated network), verify that each monitoring tool works.

**`auditd`**:

```bash
# Load the analysis rules
sudo augenrules --load  
sudo auditctl -l  
# Expected: the list of rules defined in section 26.3 is displayed
# (exec_monitor, file_access, net_connect, etc.)

# Generate a test event
touch /tmp/test_audit_file

# Verify capture
sudo ausearch -k file_access --interpret | tail -5
# Expected: an event showing the open/creation of /tmp/test_audit_file

# Cleanup
rm /tmp/test_audit_file
```

**`inotifywait`**:

```bash
# Launch inotifywait in the background on /tmp/
inotifywait -m -r /tmp/ --format '%T %w%f %e' --timefmt '%H:%M:%S' &  
INOTIFY_PID=$!  

# Generate a test event
echo "test" > /tmp/test_inotify_file

# Expected: inotifywait displays a line like:
# 14:35:22 /tmp/test_inotify_file CREATE
# 14:35:22 /tmp/test_inotify_file MODIFY

# Cleanup
kill $INOTIFY_PID  
rm /tmp/test_inotify_file  
```

**`tcpdump`** (on the **host**):

```bash
# On the host — launch a 10-second capture
sudo timeout 10 tcpdump -i br-malware -c 5 --print 2>&1

# Meanwhile, in the VM, generate traffic:
ping -c 3 10.66.66.1

# Expected: tcpdump on the host displays the ICMP packets (ping)
# between 10.66.66.100 and 10.66.66.1
```

**`sysdig`**:

```bash
# In the VM — quick 5-second capture
sudo timeout 5 sysdig "evt.type=open and proc.name=bash" 2>/dev/null | head -10
# Expected: events showing open() calls made by bash
# (Even if there are only a few lines or none, the absence of errors
#  confirms that sysdig is working)
```

### Phase 4 — VM hardening verification

```bash
# No shared folder mounted
mount | grep -iE '(vboxsf|vmhgfs|9p|shared)'
# Expected: no results

# spice-vdagent is not installed or not active
pgrep spice-vdagent
# Expected: no PID returned

# The sample-runner user exists
id sample-runner
# Expected: uid and gid displayed

# The sample-runner home directory is protected
ls -ld /home/sample-runner/
# Expected: permissions drwx------ (700)

# The sample working directory exists
ls -ld ~/malware-samples/
# Expected: the directory exists with permissions 700
```

### Phase 5 — Complete snapshot cycle verification

This phase simulates a complete analysis cycle without a real sample. It verifies that snapshots work and that rollback restores a clean state.

```bash
# On the host — take a test snapshot
virsh snapshot-create-as malware-lab \
  --name "test-checkpoint" \
  --description "Chapter 26 checkpoint verification snapshot"

# In the VM — create a marker file
ssh analyst@10.66.66.100 'echo "This file proves the snapshot works" > ~/marker.txt'  
ssh analyst@10.66.66.100 'cat ~/marker.txt'  
# Expected: the file contents are displayed

# On the host — restore the snapshot
virsh snapshot-revert malware-lab --snapshotname "test-checkpoint"

# Restart the VM (reverting to an offline snapshot stops the VM)
virsh start malware-lab
# Wait for boot...

# Verify the marker has disappeared
ssh analyst@10.66.66.100 'cat ~/marker.txt 2>&1'
# Expected: "No such file or directory"
# The file no longer exists: the rollback worked.

# Clean up the test snapshot
virsh snapshot-delete malware-lab --snapshotname "test-checkpoint"
```

**Expected result**: the `marker.txt` file exists before rollback and has disappeared after. This is proof that the snapshot mechanism works correctly and that any state created after a snapshot can be cleanly erased.

---

## Validation grid

Go through this grid and check each point. **All points must be validated** to consider the checkpoint passed.

```
INFRASTRUCTURE
  □  kvm-ok confirms virtualization support
  □  The malware-lab VM exists and starts
  □  The clean-base snapshot exists and is restorable
  □  The isolated-malware network is active

NETWORK ISOLATION
  □  The VM gets an IP in 10.66.66.x
  □  The VM can reach the host (10.66.66.1)
  □  ping 8.8.8.8 fails from the VM
  □  ping 1.1.1.1 fails from the VM
  □  host example.com fails from the VM
  □  ip route shows no default route
  □  iptables on the host shows DROP rules on br-malware

MONITORING
  □  auditd is active, rules load, a test event is captured
  □  inotifywait detects the creation of a test file
  □  tcpdump on the host captures bridge traffic
  □  sysdig runs without errors

HARDENING
  □  No shared folder mounted
  □  spice-vdagent absent or inactive
  □  The sample-runner user exists
  □  /home/sample-runner/ has permissions 700
  □  ~/malware-samples/ exists

SNAPSHOTS
  □  A test snapshot can be created
  □  A file created after the snapshot disappears after rollback
  □  The test snapshot is cleaned up
```

---

## In case of failure

If one or more points fail, the following table points to the section to reread and the most common causes.

| Symptom | Probable cause | Section to reread |  
|---|---|---|  
| `kvm-ok` fails | VT-x/AMD-V disabled in BIOS | 26.2 (Checking support) |  
| The VM does not start | Corrupted qcow2 image or incorrect path | 26.2 (Creating the image) |  
| No `clean-base` snapshot | Forgotten during initial installation | 26.2 (The reference snapshot) |  
| `ping 8.8.8.8` succeeds from the VM | VM still on the `default` (NAT) network | 26.2 (Switching between networks) |  
| `ping 10.66.66.1` fails | DHCP not renewed or bridge misconfigured | 26.4 (Bridge anatomy) |  
| `host example.com` succeeds | `dnsmasq` resolving to INetSim — acceptable if intentional | 26.4 (DNS responder) |  
| `auditctl -l` shows no rules | Rules file absent or not loaded | 26.3 (Configuring auditd rules) |  
| `inotifywait`: command not found | `inotify-tools` not installed | 26.3 (Installation) |  
| `tcpdump -i br-malware` fails | Bridge not created or different name | 26.4 (Verifying topology) |  
| `sysdig` fails | Kernel module not loaded or incomplete installation | 26.3 (sysdig installation) |  
| Rollback does not remove the file | Snapshot taken after the file was created | 26.2 (Snapshot management) |

---

## What this checkpoint validates

By successfully completing this checkpoint, you have demonstrated that:

- You master the creation and management of an analysis VM with QEMU/KVM.  
- Your isolated network is truly sealed — no traffic can leave the `br-malware` bridge.  
- Your monitoring tools work and are capable of capturing system, file, and network activity.  
- Your VM is hardened according to the principle of least privilege.  
- The snapshot mechanism guarantees you total reversibility.

Your lab is ready. Chapter 27 will introduce the first hostile sample: an ELF ransomware compiled with GCC, which will encrypt files in `/tmp/test/` with a hardcoded AES key. Everything you built in this chapter — isolation, monitoring, snapshots, golden rules — will be mobilized to observe it, understand it, and ultimately write a decryptor.

---

> 📌 **Progression rule** — Do not proceed to chapter 27 unless **all** points in the validation grid are checked. A partially functional lab is a lab that gives a false sense of security — it is worse than a nonexistent lab, because you run samples in it believing you are protected.

⏭️ [Chapter 27 — Analysis of a Linux ELF Ransomware (self-compiled with GCC)](/27-ransomware/README.md)
