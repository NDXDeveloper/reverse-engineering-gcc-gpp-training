🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 26.3 — Monitoring Tools: `auditd`, `inotifywait`, `tcpdump`, `sysdig`

> **Chapter 26 — Setting Up a Secure Analysis Lab**  
> **Part VI — Malicious Code Analysis (Controlled Environment)**

---

## The Role of Monitoring in Malware Analysis

In section 26.1, we defined behavioral isolation as the third axis of the lab: not preventing the malware from acting, but **recording each of its actions** for later analysis. The tools in this chapter are the surveillance cameras of our aquarium.

Let us recall an important distinction. In previous chapters, we already used `strace` and `ltrace` to trace system calls and library calls of a targeted process. These tools remain essential and will be widely used in chapters 27 and 28. But they have a limitation: they observe **a single process** (and possibly its children). However, a malware can launch independent processes, modify files through indirect mechanisms, or interact with the system in a way that `strace` does not capture because the activity occurs outside the traced process tree.

The four tools presented here operate at a different level. They are not attached to a particular process: they monitor **the system as a whole** — the kernel, the file system, the network. Together, they form a complete coverage that ensures no significant action from the sample goes unnoticed.

| Tool | What it observes | Granularity | Mode |  
|---|---|---|---|  
| `auditd` | System calls at the kernel level | Event by event | Real-time + logs |  
| `inotifywait` | File system modifications | File by file | Real-time |  
| `tcpdump` | Raw network traffic | Packet by packet | `.pcap` capture |  
| `sysdig` | Everything (syscalls, network, files, processes) | Event by event | Real-time + capture |

---

## `auditd` — Linux Kernel Auditing

### What is `auditd`?

The Linux audit framework is a mechanism built into the kernel that allows recording system events reliably and efficiently. It consists of two parts: a kernel component (`kauditd`) that intercepts events, and a user-space daemon (`auditd`) that receives these events and writes them to a log file.

What makes `auditd` particularly well-suited for malware analysis is its position in the system. It operates at the kernel level, upstream of any library or abstraction. A malware can bypass the libc by making direct system calls via the `syscall` instruction — `ltrace` will see nothing, but `auditd` will capture the event because it sits at the mandatory checkpoint: the kernel interface.

### Installation and Verification

`auditd` should normally already be installed if you followed section 26.2. Let's verify:

```bash
sudo apt install auditd audispd-plugins  
sudo systemctl enable --now auditd  
sudo systemctl status auditd  
```

The main log file is `/var/log/audit/audit.log`. The query tools are `ausearch` (log search) and `aureport` (summary reports).

### Configuring Audit Rules for Malware Analysis

By default, `auditd` monitors almost nothing — you must explicitly tell it what to observe via rules. Rules are loaded from `/etc/audit/rules.d/` or added dynamically with `auditctl`.

For a malware analysis session, we want to monitor the actions most revealing of a hostile program's behavior. Let's create a dedicated rules file:

```bash
sudo tee /etc/audit/rules.d/malware-analysis.rules << 'EOF'
# =============================================================
# auditd rules for malware analysis
# Enable BEFORE running the sample, disable AFTER
# =============================================================

# Remove existing rules to start from a clean slate
-D

# Buffer size (increase if events are lost)
-b 8192

# -----------------------------------------------------------
# 1. Program execution (execve)
#    Captures every binary launch, including child processes
#    and execution chains
# -----------------------------------------------------------
-a always,exit -F arch=b64 -S execve -k exec_monitor

# -----------------------------------------------------------
# 2. File opening and creation
#    Captures file access in write and create mode
# -----------------------------------------------------------
-a always,exit -F arch=b64 -S open,openat -F dir=/home -k file_access
-a always,exit -F arch=b64 -S open,openat -F dir=/tmp -k file_access
-a always,exit -F arch=b64 -S open,openat -F dir=/etc -k file_access

# -----------------------------------------------------------
# 3. Network connections (connect, bind, accept)
#    Captures network communication attempts
# -----------------------------------------------------------
-a always,exit -F arch=b64 -S connect -k net_connect
-a always,exit -F arch=b64 -S bind -k net_bind
-a always,exit -F arch=b64 -S accept,accept4 -k net_accept

# -----------------------------------------------------------
# 4. Permission and attribute modifications
#    A malware installing itself often modifies permissions
# -----------------------------------------------------------
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k perm_change
-a always,exit -F arch=b64 -S chown,fchown,fchownat -k owner_change

# -----------------------------------------------------------
# 5. Process operations
#    Detection of fork, kill, ptrace (anti-debug or injection)
# -----------------------------------------------------------
-a always,exit -F arch=b64 -S clone,fork,vfork -k proc_create
-a always,exit -F arch=b64 -S ptrace -k ptrace_use
-a always,exit -F arch=b64 -S kill,tkill,tgkill -k signal_send

# -----------------------------------------------------------
# 6. File deletion and renaming
#    Ransomware: deletion of originals after encryption
# -----------------------------------------------------------
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -k file_delete

# -----------------------------------------------------------
# 7. System configuration modifications
#    Persistence: crontab, services, startup scripts
# -----------------------------------------------------------
-w /etc/crontab -p wa -k persist_cron
-w /etc/cron.d/ -p wa -k persist_cron
-w /var/spool/cron/ -p wa -k persist_cron
-w /etc/systemd/system/ -p wa -k persist_systemd
-w /etc/init.d/ -p wa -k persist_init
-w /home/sample-runner/.bashrc -p wa -k persist_shell
-w /home/sample-runner/.profile -p wa -k persist_shell

# Make rules immutable (optional, prevents the malware from
# disabling them — requires a reboot to modify)
# -e 2
EOF
```

Load the rules:

```bash
sudo augenrules --load  
sudo auditctl -l    # Verify that the rules are active  
```

### Anatomy of an Audit Event

An `auditd` event is a multi-line record. Here is a typical example captured during the execution of a binary:

```
type=SYSCALL msg=audit(1718450023.456:1284): arch=c000003e syscall=59  
success=yes exit=0 a0=55a3c2f1b0 a1=55a3c2f1e0 a2=55a3c2f210 a3=0  
items=2 ppid=1432 pid=1587 uid=1001 gid=1001 euid=1001  
comm="ransomware_sam" exe="/home/sample-runner/malware-samples/ransomware_sample"  
key="exec_monitor"  
type=EXECVE msg=audit(1718450023.456:1284): argc=1  
a0="/home/sample-runner/malware-samples/ransomware_sample"  
type=PATH msg=audit(1718450023.456:1284): item=0  
name="/home/sample-runner/malware-samples/ransomware_sample"  
inode=262278 dev=fd:01 mode=0100755  
```

The key fields to read are `syscall` (the system call number — 59 corresponds to `execve`), `exe` (the binary that made the call), `pid`/`ppid` (process ID and its parent), `uid` (user), and `key` (the category we defined in our rules). The `key` field is particularly useful for filtering results.

### Querying Logs with `ausearch` and `aureport`

After an analysis session, the raw logs in `/var/log/audit/audit.log` are voluminous. `ausearch` allows efficient filtering:

```bash
# All events related to program execution
sudo ausearch -k exec_monitor --interpret

# All attempted network connections
sudo ausearch -k net_connect --interpret

# All deleted or renamed files
sudo ausearch -k file_delete --interpret

# Events generated by a specific PID
sudo ausearch -p 1587 --interpret

# Events since a specific date/time
sudo ausearch -k exec_monitor --start "06/15/2025" "14:30:00" --interpret
```

The `--interpret` option translates numeric values into readable names (syscall numbers to names, UIDs to usernames, etc.).

For a summary view, `aureport` generates reports by category:

```bash
# Summary of program executions
sudo aureport -x --summary

# Summary of file accesses
sudo aureport -f --summary

# Summary of network events
sudo aureport --comm --summary

# Complete timeline
sudo aureport -ts today
```

### Exporting Logs for Analysis Outside the VM

Before restoring the snapshot, transfer the logs to the host:

```bash
# From the host
scp analyst@10.66.66.100:/var/log/audit/audit.log ./analyses/session-xxx/
```

---

## `inotifywait` — Real-Time File System Monitoring

### What is `inotifywait`?

`inotifywait` is a utility from the `inotify-tools` package that leverages the Linux kernel's `inotify` mechanism to monitor file system events in real time. Unlike `auditd` which captures all file-related system calls and produces detailed but verbose logs, `inotifywait` offers a focused and immediate view: "this file was just created," "this directory was just modified."

Its primary value in our context is **real-time detection of file modifications during sample execution**. For a ransomware, for example, you will see scrolling in real time the list of encrypted files in the exact order the malware processes them.

### Installation

```bash
sudo apt install inotify-tools
```

### Usage for Malware Analysis

The following command recursively monitors the most interesting directories and produces a timestamped log:

```bash
inotifywait -m -r \
  --timefmt '%Y-%m-%d %H:%M:%S' \
  --format '%T %w%f %e' \
  -e create,delete,modify,move,attrib \
  /home/sample-runner/ /tmp/ /etc/ /var/ \
  | tee ~/captures/inotify.log
```

Option details:

- `-m` (monitor) — continuous mode. Without this option, `inotifywait` stops after the first event.  
- `-r` — recursive monitoring of all subdirectories.  
- `--timefmt` and `--format` — timestamped and readable output format.  
- `-e` — event types to monitor: creation, deletion, modification, move, attribute change.  
- `| tee` — displays the output in real time while recording it to a file.

### Example Output

Here is what `inotifywait` produces when a ransomware encrypts files in `/tmp/test/`:

```
2025-06-15 14:32:01 /tmp/test/document.txt MODIFY
2025-06-15 14:32:01 /tmp/test/document.txt.enc CREATE
2025-06-15 14:32:01 /tmp/test/document.txt DELETE
2025-06-15 14:32:01 /tmp/test/photo.jpg MODIFY
2025-06-15 14:32:01 /tmp/test/photo.jpg.enc CREATE
2025-06-15 14:32:01 /tmp/test/photo.jpg DELETE
2025-06-15 14:32:02 /tmp/test/RANSOM_NOTE.txt CREATE
```

The sequence speaks for itself: for each file, the malware reads it (`MODIFY` because it opens the file), creates the encrypted version (`.enc`), deletes the original, then drops a ransom note.

### Limitations of `inotifywait`

`inotifywait` only sees events on the directories you asked it to monitor. If the sample writes to an unexpected directory (for example `/dev/shm` or a directory it creates itself at the root), `inotifywait` will not capture it unless that path is in the list. This is why `inotifywait` complements `auditd` but does not replace it: `auditd` sees all `open`/`write` calls regardless of the path, while `inotifywait` offers a more readable but limited view restricted to specified paths.

> 💡 **Tip** — For maximum coverage, you can monitor `/` recursively (`inotifywait -m -r /`), but be prepared for a considerable volume of noise: every log write, every system access will generate an event. Filtering after the fact with `grep` is then essential.

---

## `tcpdump` — Network Capture on the Isolated Bridge

### Role in the Lab

`tcpdump` is the most universal command-line network capture tool. In our lab, it has a specific role: capture all network traffic emitted by the VM on the `br-malware` bridge and save it to a `.pcap` file for later analysis with Wireshark.

Even though our network is isolated and the packets lead nowhere, their content is a goldmine of information. DNS resolution attempts reveal the domain names the malware tries to contact. TCP SYN packets show the IP addresses and ports of C2 servers. The content of HTTP requests (or custom protocols) reveals the communication protocol format. All of this without the malware ever reaching its destination.

### Two Possible Capture Points

Capture can be done at two locations, each with its advantages:

**On the host, on the bridge interface** — this is the recommended method. `tcpdump` runs on the host machine and listens on the `br-malware` interface. The sample cannot detect the capture or interfere with it, since `tcpdump` runs outside the VM.

```bash
# On the host — recommended method
sudo tcpdump -i br-malware -w ./analyses/session-xxx/capture.pcap -v
```

**Inside the VM, on the VM's network interface** — useful if you want to observe traffic in real time from the VM, but the sample could theoretically detect the `tcpdump` process or attempt to kill it.

```bash
# Inside the VM — alternative method
sudo tcpdump -i enp1s0 -w ~/captures/capture.pcap -v
```

### Recommended Capture Options

```bash
sudo tcpdump -i br-malware \
  -w ./captures/capture_$(date +%Y%m%d_%H%M%S).pcap \
  -s 0 \
  -v \
  --print
```

- `-i br-malware` — capture interface (the isolated bridge).  
- `-w` — write to a `.pcap` file with a timestamp in the name.  
- `-s 0` — capture full packets (no truncation). Essential for analyzing payload content.  
- `-v` — verbose output on the console.  
- `--print` — displays packets in real time in addition to writing them to the file. Useful for observing activity during execution.

### Quickly Reading a Capture from the Command Line

After the session, you can pre-filter the capture before opening it in Wireshark:

```bash
# Total number of captured packets
tcpdump -r capture.pcap | wc -l

# DNS queries only (reveals contacted domains)
tcpdump -r capture.pcap -n port 53

# TCP SYN connections (outgoing connection attempts)
tcpdump -r capture.pcap 'tcp[tcpflags] & tcp-syn != 0'

# HTTP traffic (if the C2 uses plaintext HTTP)
tcpdump -r capture.pcap -A port 80

# Conversation summary (source IP → destination IP)
tcpdump -r capture.pcap -n -q | awk '{print $3, $4, $5}' | sort | uniq -c | sort -rn
```

For an in-depth analysis, transfer the `.pcap` to the host and open it in Wireshark. Chapter 23 (Reversing a Network Binary) covers reading Wireshark captures in depth.

### Why Capture on the Host Rather Than in the VM

Three reasons justify the preference for host-side capture:

First, **security**. If the sample is a malware that attempts to disable monitoring tools, it can kill the `tcpdump` process inside the VM. On the host, it has no access to the capture process.

Second, **reliability**. If the malware corrupts the VM's file system, the `.pcap` file stored in the VM could be damaged or lost. On the host, it is safe.

Third, **practicality**. The `.pcap` file is directly accessible on the host for analysis with Wireshark, without needing to transfer it from the VM before the snapshot rollback.

---

## `sysdig` — Unified System Visibility

### What is `sysdig`?

`sysdig` is a system visibility tool that captures kernel events (system calls, network activity, file operations, process management) in a single, queryable stream. It is often described as the combination of `strace`, `tcpdump`, and `lsof` in a single tool, with a powerful filtering language inspired by Wireshark's.

Its primary advantage in the context of malware analysis is **correlation**. Where `auditd` captures syscalls, `inotifywait` captures file events, and `tcpdump` captures network packets in separate streams, `sysdig` unifies them in a single timeline. You can see, in the same stream, the sample opening a file, reading it, connecting to a socket, and writing data — all with consistent timestamps.

### Installation

`sysdig` requires a kernel module or an eBPF driver. On Debian/Ubuntu:

```bash
# Installation from the official sysdig repositories
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash
```

Verify the installation:

```bash
sudo sysdig --version
```

> ⚠️ `sysdig` requires root privileges to access kernel events. In the analysis VM, this is acceptable — the `analyst` user will use `sudo`.

### Capture and Filtering

#### Real-Time Mode

```bash
# All system events (very verbose)
sudo sysdig

# Filter by process name
sudo sysdig proc.name=ransomware_sample

# Filter by user (the sample runs under sample-runner)
sudo sysdig user.name=sample-runner

# File activity only
sudo sysdig "evt.type in (open, openat, read, write, close, unlink, rename)"

# Network activity only
sudo sysdig "evt.type in (connect, accept, send, sendto, recv, recvfrom)"

# Combination: file AND network activity of the sample
sudo sysdig "user.name=sample-runner and evt.type in (open, openat, write, connect, send)"
```

#### Capture Mode (Recording for Deferred Analysis)

Like `tcpdump`, `sysdig` can write its capture to a file for later analysis:

```bash
# Capture all events to a file
sudo sysdig -w ~/captures/sysdig_session.scap

# Capture only events from the sample-runner user
sudo sysdig -w ~/captures/sysdig_session.scap "user.name=sample-runner"
```

To replay the capture after the session:

```bash
# Replay the capture with the same filters as live sysdig
sudo sysdig -r ~/captures/sysdig_session.scap "evt.type=connect"

# Replay and format with a chisel (see below)
sudo sysdig -r ~/captures/sysdig_session.scap -c topfiles_bytes
```

#### Chisels: Pre-Built Analysis Scripts

`sysdig` provides "chisels" — pre-built analysis scripts that extract targeted metrics. Several are directly useful for malware analysis:

```bash
# List available chisels
sudo sysdig -cl

# Top files by write volume
# (reveals the files the malware modifies the most)
sudo sysdig -c topfiles_bytes "user.name=sample-runner"

# Top network connections
sudo sysdig -c topconns

# Process launch timeline
# (detects forks, execs, launch chains)
sudo sysdig -c spy_users "user.name=sample-runner"

# Follow a process's I/O (enhanced strace equivalent)
sudo sysdig -c echo_fds "proc.name=ransomware_sample"

# List all files opened by the sample
sudo sysdig -c list_login_shells
```

### `sysdig` vs Other Tools: When to Use It

`sysdig` does not replace the other three tools — it complements them. Here is how to combine them:

- **`tcpdump`** remains the reference tool for raw network capture (`.pcap`). `sysdig` captures network activity at the syscall level, but does not produce a `.pcap` directly usable by Wireshark. For protocol analysis, `tcpdump` + Wireshark remains unbeatable.  
- **`auditd`** is preferable when you need **persistent and certifiable logs**. In a professional incident response context, `auditd` logs have an evidentiary value that `sysdig` does not (standardized format, verifiable integrity).  
- **`inotifywait`** offers an immediate and readable view of file modifications, ideal for observing in real time what a ransomware is doing. Its output is easier to read than a filtered `sysdig` stream.  
- **`sysdig`** excels when you need to **correlate** multiple types of activity in a single timeline, or when you want to do a quick exploratory analysis without yet knowing exactly what to look for.

In practice, in the following chapters, we will systematically launch `tcpdump` (host-side) and `inotifywait` + `auditd` (inside the VM) before each sample execution. `sysdig` will be used as a supplement for targeted analyses when initial observations point toward specific behaviors.

---

## Complete Monitoring Workflow

Let's put all the tools together to form the standard monitoring workflow for an analysis session. This workflow is launched **after** preparing the VM (snapshot restored, network isolated, sample copied) and **before** executing the sample.

### Step 1 — Open Four Terminals

The most readable approach is to dedicate one terminal to each tool. If you work with `tmux` or `screen` (recommended), create four panes.

### Step 2 — Start the Captures

**Terminal 1 — `tcpdump` on the host:**

```bash
# ON THE HOST (not inside the VM)
ANALYSIS_DIR="./analyses/$(date +%Y%m%d-%H%M%S)"  
mkdir -p "$ANALYSIS_DIR"  
sudo tcpdump -i br-malware -s 0 -w "$ANALYSIS_DIR/capture.pcap" --print  
```

**Terminal 2 — `auditd` inside the VM:**

```bash
# INSIDE THE VM (ssh analyst@10.66.66.100)
sudo augenrules --load  
sudo ausearch -k exec_monitor --start now --interpret -i  
# (waits for events)
```

**Terminal 3 — `inotifywait` inside the VM:**

```bash
# INSIDE THE VM
inotifywait -m -r \
  --timefmt '%Y-%m-%d %H:%M:%S' \
  --format '%T %w%f %e' \
  -e create,delete,modify,move,attrib \
  /home/sample-runner/ /tmp/ /etc/ /var/ \
  | tee ~/captures/inotify.log
```

**Terminal 4 — Execution terminal inside the VM:**

```bash
# INSIDE THE VM — this terminal will be used to launch the sample
cd ~/malware-samples/  
sha256sum ransomware_sample    # Verify the hash before execution  
```

### Step 3 — Execute the Sample

In terminal 4:

```bash
sudo -u sample-runner ./ransomware_sample
```

The other three terminals display the observed activity in real time. Take notes as you go: "at T+2s, the sample opens /tmp/test/document.txt," "at T+3s, connection attempt toward 185.x.x.x:443," etc.

### Step 4 — Stop the Captures and Collect

After execution (or when you have observed enough), stop the captures (`Ctrl+C` on each terminal), then collect the artifacts:

```bash
# INSIDE THE VM — copy the auditd logs
sudo cp /var/log/audit/audit.log ~/captures/

# ON THE HOST — retrieve the artifacts from the VM
scp analyst@10.66.66.100:~/captures/* "$ANALYSIS_DIR/"
```

The resulting artifact structure:

```
analyses/20250615-143200/
├── capture.pcap           ← Network traffic (tcpdump, captured on the host)
├── audit.log              ← Kernel events (auditd)
├── inotify.log            ← File modifications (inotifywait)
└── notes.md               ← Your real-time observations
```

---

## Writing a Monitoring Launch Script

To avoid forgetting a step or making a configuration error in the heat of the moment, automate the monitoring launch inside the VM:

```bash
#!/bin/bash
# start_monitoring.sh — Run inside the VM before the sample
# Usage: ./start_monitoring.sh

set -euo pipefail

CAPTURE_DIR=~/captures/$(date +%Y%m%d-%H%M%S)  
mkdir -p "$CAPTURE_DIR"  

echo "[*] Loading auditd rules..."  
sudo augenrules --load  

echo "[*] Purging previous auditd logs..."  
sudo truncate -s 0 /var/log/audit/audit.log  

echo "[*] Starting inotifywait in the background..."  
inotifywait -m -r \  
  --timefmt '%Y-%m-%d %H:%M:%S' \
  --format '%T %w%f %e' \
  -e create,delete,modify,move,attrib \
  /home/sample-runner/ /tmp/ /etc/ /var/ \
  > "$CAPTURE_DIR/inotify.log" 2>&1 &
INOTIFY_PID=$!  
echo "    inotifywait PID: $INOTIFY_PID"  

echo "[*] Starting sysdig in the background..."  
sudo sysdig -w "$CAPTURE_DIR/sysdig.scap" "user.name=sample-runner" &  
SYSDIG_PID=$!  
echo "    sysdig PID: $SYSDIG_PID"  

echo ""  
echo "[+] Monitoring active. Capture directory: $CAPTURE_DIR"  
echo "    To stop: kill $INOTIFY_PID && sudo kill $SYSDIG_PID"  
echo "    Don't forget: tcpdump must be running on the HOST (not here)"  
echo ""  
echo "    Run the sample when you are ready:"  
echo "    sudo -u sample-runner /home/sample-runner/malware-samples/<sample>"  
```

---

## Performance Considerations

Monitoring tools consume resources. When they all run simultaneously in a VM with 4 GB of RAM and 2 vCPUs, the impact is not negligible.

`auditd` is the lightest — its kernel component adds minimal overhead per syscall, and the user-space daemon writes sequentially to a file. `inotifywait` is also very light as long as it is not monitoring tens of thousands of files recursively. `tcpdump` (host-side) does not impact VM performance at all. `sysdig` is the most resource-intensive: its kernel driver captures all events and transfers them to user space. On an active system, this can represent a considerable volume of events.

If the VM becomes too slow for the sample to execute normally — which could modify its behavior and skew the analysis — lighten the configuration. Start by removing `sysdig` (the essential information is covered by the other three tools) and reduce the scope of `inotifywait` to only the directories you suspect are targeted by the sample.

---

> 📌 **Key Takeaway** — Monitoring is the memory of the analysis. Without it, executing a sample in the lab is like running a scientific experiment without taking notes: you observe in the moment, but you lose the details. `auditd` captures the "what" (which syscalls), `inotifywait` shows the "where" (which files), `tcpdump` records the "with whom" (which network traffic), and `sysdig` ties it all together in a coherent "when." Launch them **before** the sample, collect the artifacts **before** the rollback, and you will have a solid foundation for each analysis in the following chapters.

⏭️ [Network Captures with a Dedicated Bridge](/26-secure-lab/04-network-captures-bridge.md)
