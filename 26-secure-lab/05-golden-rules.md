🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 26.5 — Golden Rules: Never Execute Outside the Sandbox, Never Connect to the Real Network

> **Chapter 26 — Setting Up a Secure Analysis Lab**  
> **Part VI — Malicious Code Analysis (Controlled Environment)**

---

## Why Non-Negotiable Rules

The previous sections built a technically solid lab: dedicated VM, isolated bridge, pre-deployed monitoring, systematic snapshots. But the infrastructure only protects if it is **used correctly at every session, without exception**. The history of malware analysis — in academic laboratories and professional environments alike — is littered with incidents caused not by a technical flaw, but by a human shortcut. A rushed analyst who runs "just a quick test" on the host. An intern who connects the VM to NAT to download a tool, forgetting that a sample is already loaded. A researcher who shares a directory between the host and the VM to "save time."

These golden rules do not exist because the technology is insufficient. They exist because the technology is useless if discipline does not follow. They are deliberately absolute, without nuance, without "except if." This categorical nature is intentional: in the heat of the moment, facing a binary you are eager to understand, the temptation to take a shortcut is real. A rule open to interpretation becomes a rule that gets bypassed. An absolute rule remains a wall.

---

## Rule #1 — Never Execute a Sample Outside the Analysis VM

This is the foundational rule, the one from which all others derive. A sample — whatever it is, regardless of how much you trust it — is **never** executed on the host machine, never on the workstation VM from Chapter 4, never on any machine that is not the dedicated analysis VM built in this chapter.

### What "Execute" Means

The definition is broad and intentionally conservative:

- **Directly running the binary** (`./sample`) — the obvious case.  
- **Loading it into a debugger and letting it run** (`gdb ./sample` followed by `run`) — GDB launches the process, the code executes.  
- **Opening it with a tool that implicitly executes it** — some profiling or code coverage tools execute the binary internally.  
- **Passing it to an automation script** — a `pwntools` script that calls `process('./sample')` executes the binary.  
- **Fuzzing it** — AFL++ and libFuzzer execute the binary thousands of times. Doing so outside the VM amounts to executing the sample outside the VM thousands of times.

### What is NOT Execution and Can Be Done on the Host

Static analysis requires no execution. The following operations are safe on the host:

- Loading the binary into **Ghidra** (Ghidra analyzes the file, it does not execute it).  
- Running `file`, `strings`, `readelf`, `objdump`, `nm` on the file.  
- Opening the binary in **ImHex** for hexadecimal analysis.  
- Computing its hash (`sha256sum`).  
- Applying **YARA** rules to the file.  
- Examining the binary with `binwalk`.

The boundary is clear: if the tool reads the file as a sequence of bytes, it is static analysis. If the tool hands control to the code contained in the file, it is execution.

> 💡 **Special case of booby-trapped archives and documents** — If you ever analyze real-world samples beyond this training course, beware of files that are not ELF binaries but exploit vulnerabilities in the software that opens them (booby-trapped PDFs, malicious Office documents, crafted images). In these cases, even "opening" the file in the targeted software constitutes potential execution. This scenario does not apply to this training course (our samples are ELF binaries), but the reflex should be acquired.

### Why This Rule Is Absolute

"I know this sample is harmless, I compiled it myself." This sentence is the preamble to the majority of lab incidents. Three reasons justify the absence of exceptions:

First, **muscle memory**. If you get into the habit of executing "trusted" samples on the host, the gesture becomes automatic. The day you handle a sample whose harmlessness you are no longer certain of, the reflex takes over before reflection does.

Second, **certainty is an illusion**. Even a sample you compiled yourself can exhibit unexpected behavior. A buffer overflow in your own code, environment-dependent behavior, a third-party library making an undocumented network call. The VM is there to absorb the unexpected.

Third, **professional credibility**. If you ever work on a threat analysis team, your colleagues and management will expect you to apply this rule without thinking. Discovering it under pressure is not the right time.

---

## Rule #2 — Never Connect the VM to the Real Network When a Sample Is Present

The wording is precise: "when a sample is present." The VM can — and should — have network access during installation and maintenance (updates, package installation). But as soon as a suspicious file is anywhere in the VM (even if it has not yet been executed), the network must be isolated.

### What "Real Network" Means

- The **default NAT network** from libvirt (`virbr0` / `default`) — it provides Internet access through the host.  
- A network **bridged to the host's physical interface** — the VM gets an address on the real LAN.  
- A **host-only network with IP forwarding enabled** on the host — packets can reach the LAN via the host.  
- Any configuration where `ping 8.8.8.8` **succeeds** from the VM.

The `isolated-malware` network (`br-malware`) is **not** a real network in the sense of this rule. It is designed to capture traffic without letting it out.

### The Typical Violation Scenario

The classic scenario unfolds as follows:

1. The analyst finishes a session. They restore the `clean-base` snapshot.  
2. They switch the VM back to the `default` (NAT) network to install a tool they had forgotten.  
3. They copy a new sample into the VM for the next session.  
4. They forget to switch back to the isolated network.  
5. They execute the sample. The sample contacts its real C2, exfiltrates whatever data it finds, or scans the LAN.

The critical step is step 4 — a two-second oversight that can have significant consequences. The countermeasure is procedural: **always verify network isolation before executing a sample**, and never copy a sample into the VM while the network is not isolated.

### Systematic Verification

Before each execution, run this sequence in the VM:

```bash
# 3-point verification
echo "=== Network isolation verification ==="

# 1. No default route
if ip route | grep -q "^default"; then
    echo "[FAIL] Default route detected — DO NOT EXECUTE"
    ip route
    exit 1
else
    echo "[OK] No default route"
fi

# 2. No Internet access
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "[FAIL] Internet accessible — DO NOT EXECUTE"
    exit 1
else
    echo "[OK] Internet unreachable"
fi

# 3. Public DNS resolution impossible
if host example.com >/dev/null 2>&1; then
    echo "[WARN] Public DNS resolves — check if INetSim is intentionally active"
else
    echo "[OK] Public DNS unreachable"
fi

echo "=== Isolation confirmed ==="
```

Integrate this verification into the `start_monitoring.sh` script from section 26.3, at the very beginning — before launching the monitoring tools. If the verification fails, the script stops and nothing runs.

---

## Rule #3 — Always Take a Snapshot Before Executing a Sample

This rule guarantees reversibility. Without a pre-execution snapshot, the sample's effects on the VM are **permanent** (until restoring the `clean-base` snapshot, which also erases your session configuration).

The pre-execution snapshot captures the exact state of the VM at the moment when everything is ready: sample copied, monitoring started, network isolated. If the sample's execution causes a system crash, kernel panic, or unrecoverable state, you can return to that precise moment without losing your preparation.

### Naming Convention

A snapshot is only useful if it is identifiable. Adopt a strict convention:

```
pre-exec-<sample-name>-<YYYYMMDD>-<HHMM>
```

Examples:

```
pre-exec-ch27-ransomware-20250615-1432  
pre-exec-ch28-dropper-20250616-0915  
pre-exec-ch29-packed-upx-20250616-1100  
```

Avoid generic names (`test`, `snapshot1`, `before-exec`). In three weeks, when you are searching for a specific snapshot among a dozen, the descriptive name will save you considerable time.

---

## Rule #4 — Never Share Resources Between the Host and the Analysis VM

This rule follows from the principle of least privilege (section 26.1), but it deserves to be stated as a rule in its own right due to the frequency of violations.

### Shared Folders

Shared folders (VirtualBox Shared Folders, `virtio-9p` in QEMU, VMware Shared Folders) create direct access from the guest system to the host's filesystem. Malware that traverses the VM's mount points will find this shared folder and may read, modify, or encrypt the host's files.

The solution is to never configure a shared folder on the analysis VM. File transfers are done exclusively via `scp` over the host-only network or the isolated bridge, which gives full control over what is transferred and in which direction.

### Shared Clipboard

The shared clipboard is bidirectional. If you copy a file path or command on the host, the sample can read it in the VM. Conversely, malware that places content in the VM's clipboard (a technique used by clipboard stealers) can contaminate the host's clipboard.

Verify that `spice-vdagent` is not installed in the VM:

```bash
dpkg -l | grep spice-vdagent
# If present:
sudo apt remove --purge spice-vdagent
```

### USB Devices

USB passthrough (redirecting a physical USB device to the VM) exposes the device's firmware to the malware's actions. Some malware specifically targets USB devices to propagate (infected USB drives remain a real attack vector). Never redirect a USB device to the analysis VM.

### Drag and Drop

Some hypervisors offer drag and drop of files between the host and the VM. This feature implies a communication channel between the two systems that constitutes an attack surface. Disable it.

---

## Rule #5 — Always Hash Samples Before and After Handling

The cryptographic hash (SHA-256) is the sample's fingerprint. It serves two essential functions.

### Unambiguous Identification

In an analysis report, the hash identifies the sample unambiguously. Saying "I analyzed the ransomware from Chapter 27" is ambiguous — there may be multiple versions, recompilations, modifications. Saying "I analyzed the binary with SHA-256 `a1b2c3d4...`" is unambiguous and verifiable by anyone who has the same file.

### Accidental Modification Detection

If the sample's hash changes between the moment you copied it into the VM and the moment you start the analysis, the file has been modified — perhaps by a transfer error, perhaps by another process in the VM. Analyzing an accidentally modified binary produces incorrect results without you realizing it.

### In Practice

```bash
# On the host, before the transfer
sha256sum ransomware_sample
# a1b2c3d4e5f6... ransomware_sample

# In the VM, after the transfer
sha256sum ~/malware-samples/ransomware_sample
# a1b2c3d4e5f6... (must be identical)
```

Record the hash in your session notes. If you write a report (Chapter 27, section 27.7), the hash goes in the "Sample Identification" section.

---

## Rule #6 — Collect Artifacts Before Rollback

Rolling back a snapshot is irreversible: everything that existed in the VM after the snapshot is **destroyed**. The `auditd` logs, the `inotifywait` captures, the files modified by the sample, the GDB memory dumps — everything disappears.

Before each rollback, systematically transfer the artifacts to the host:

```bash
# From the host
ANALYSIS_DIR="./analyses/ch27-ransomware-$(date +%Y%m%d-%H%M%S)"  
mkdir -p "$ANALYSIS_DIR"  

scp analyst@10.66.66.100:~/captures/* "$ANALYSIS_DIR/"  
scp analyst@10.66.66.100:/var/log/audit/audit.log "$ANALYSIS_DIR/"  

# Optional: retrieve files modified by the sample
scp -r analyst@10.66.66.100:/tmp/test/ "$ANALYSIS_DIR/modified_files/"
```

Verify that the files are on the host before launching the rollback. The command `ls -la "$ANALYSIS_DIR/"` should show non-empty files.

The `cleanup_analysis.sh` script from section 26.2 automates this collection, but a visual check before rollback remains a good habit.

---

## Rule #7 — Document Every Analysis Session

Malware analysis is not a solitary, ephemeral act. You will reread your own notes in a week. A colleague may need to reproduce your analysis. A report will need to be written. Without documentation, the analysis produced only memories — and memories are unreliable.

### What Every Session Should Record

Each analysis session should produce a notes file (even a brief one) containing:

- **Date and time** of the session's start and end.  
- **SHA-256 hash** of the analyzed sample.  
- **Snapshot name** used as a base and name of the pre-execution snapshot.  
- **Network configuration**: full isolation or semi-isolated (INetSim, fake C2).  
- **Active monitoring tools**: which ones, with what parameters.  
- **Execution commands**: how the sample was launched, under which user, with what arguments.  
- **Chronological observations**: what happened, in what order, what was unexpected.  
- **Collected artifacts**: list of retrieved files and their location on the host.  
- **Open questions**: what remains to investigate in the next session.

A minimalist template:

```markdown
# Analysis Session — [sample name]

- **Date**: 2025-06-15, 14:30 – 15:45
- **Sample**: ransomware_sample (SHA-256: a1b2c3d4...)
- **Base snapshot**: clean-base
- **Pre-exec snapshot**: pre-exec-ch27-ransomware-20250615-1430
- **Network**: full isolation (no INetSim)
- **Monitoring**: auditd + inotifywait + tcpdump (host)

## Observations

- T+0s: launch under sample-runner
- T+1s: opening of /tmp/test/ (inotifywait)
- T+2s: sequential reading of all .txt files
- T+3s: creation of corresponding .enc files
- T+5s: deletion of originals
- T+6s: creation of RANSOM_NOTE.txt
- T+7s: process terminates (exit 0)
- No network activity detected (tcpdump: 0 packets besides ARP/DHCP)

## Artifacts

- analyses/ch27-ransomware-20250615-1430/capture.pcap
- analyses/ch27-ransomware-20250615-1430/audit.log
- analyses/ch27-ransomware-20250615-1430/inotify.log
- analyses/ch27-ransomware-20250615-1430/modified_files/

## Open Questions

- Is the encryption algorithm AES-CBC or AES-CTR?
- Is the key hardcoded or derived from an input?
```

---

## Rule #8 — Never Analyze a Sample on a Machine Containing Sensitive Data

This rule concerns the professional context more than this training course, but the principle must be instilled now.

The analysis VM is isolated, but the host machine is not necessarily. If your host contains confidential professional data, SSH keys to production servers, API tokens, client databases — and a sample manages to escape from the VM (a rare but not impossible scenario), that data is exposed.

In a professional setting, the analysis machine is ideally a dedicated machine, disconnected from the corporate network, with no access to internal resources. In the context of this training course, your samples are created by you and the risk of escape is negligible, but keep the reflex: do not store on your lab's host machine any elements whose compromise would have serious consequences.

---

## Pre-Execution Checklist

All the rules above are summarized in a checklist to go through mentally (or physically, by checking it off) before each sample execution. Print it, stick it next to your screen, integrate it into your scripts.

```
┌─────────────────────────────────────────────────────────┐
│              PRE-EXECUTION CHECKLIST                    │
│                                                         │
│  □  The sample is in the analysis VM                    │
│     (NOT on the host, NOT in another VM)                │
│                                                         │
│  □  The VM is on the isolated network (br-malware)      │
│     → ping 8.8.8.8 fails                                │
│     → no default route (ip route)                       │
│                                                         │
│  □  A pre-execution snapshot has been taken             │
│     → descriptive name with date                        │
│                                                         │
│  □  Monitoring is active                                │
│     → tcpdump on the host                               │
│     → auditd loaded in the VM                           │
│     → inotifywait launched in the VM                    │
│                                                         │
│  □  No shared folders, USB, or clipboard                │
│     between the host and the VM                         │
│                                                         │
│  □  The sample hash has been verified                   │
│                                                         │
│  □  Session notes are open                              │
│     (ready to record observations)                      │
│                                                         │
│  All checked? → You may execute.                        │
│  A point is missing? → Fix it BEFORE executing.         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Automated Verification Script

For analysts who prefer automation over pure discipline, here is a script that programmatically verifies the critical points of the checklist. This script runs **in the VM** just before launching the sample:

```bash
#!/bin/bash
# preflight_check.sh — Pre-execution verification in the VM
# Usage: source preflight_check.sh (must be sourced, not executed,
#        so it can interrupt the shell session on failure)

PASS=0  
FAIL=0  

check() {
    local description="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "[OK]   $description"
        ((PASS++))
    else
        echo "[FAIL] $description"
        ((FAIL++))
    fi
}

echo "========================================"  
echo "  PRE-EXECUTION VERIFICATION"  
echo "  $(date)"  
echo "========================================"  
echo ""  

# 1. No default route
ip route | grep -q "^default"  
check "No default route" "$?"  
# Here $? is 0 if grep found a match (= bad), 1 otherwise (= good)
# Let's invert the logic:
ip route | grep -q "^default"  
DEFAULT_ROUTE=$?  
check "No default route" "$((1 - DEFAULT_ROUTE))"  

# 2. Internet unreachable
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1  
INTERNET=$?  
check "Internet unreachable (ping 8.8.8.8)" "$INTERNET"  

# 3. No shared folder mounted
mount | grep -qiE '(vboxsf|vmhgfs|9p|shared)'  
SHARED=$?  
check "No shared folder mounted" "$((1 - SHARED))"  

# 4. spice-vdagent absent (clipboard)
pgrep -x spice-vdagent >/dev/null 2>&1  
CLIPBOARD=$?  
check "Shared clipboard inactive (spice-vdagent)" "$((1 - CLIPBOARD))"  

# 5. auditd active
systemctl is-active --quiet auditd  
AUDITD=$?  
check "auditd active" "$((1 - AUDITD))"  

# 6. auditd rules loaded
RULES_COUNT=$(sudo auditctl -l 2>/dev/null | grep -c -v "No rules")
[ "$RULES_COUNT" -gt 0 ] 2>/dev/null
check "auditd rules loaded ($RULES_COUNT rules)" "$?"

echo ""  
echo "========================================"  
echo "  Result: $PASS OK, $FAIL FAIL"  
echo "========================================"  

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  ⛔ AT LEAST ONE CHECK FAILED"
    echo "     Fix the issues before executing the sample."
    echo ""
else
    echo ""
    echo "  ✅ ALL CHECKS PASSED"
    echo "     You may execute the sample."
    echo ""
fi
```

> 💡 This script is a safety net, not a substitute for judgment. It verifies the technically automatable points, but cannot verify that you have taken your notes, that you have properly hashed the sample, or that your snapshot is correctly named. Human discipline remains the last line of defense.

---

## When the Rules Seem Excessive

At this stage of the training course, some of these rules may seem disproportionate relative to the samples we are handling. After all, they are binaries we compiled ourselves from provided sources. The actual risk is minimal.

This objection is perfectly legitimate, and yet the answer remains the same: apply the rules anyway. Here is why.

The goal of this training course is not only to teach you how to analyze the provided samples. It is to give you the skills and reflexes to analyze **any** binary, including those you will encounter later in a professional context or an advanced CTF — binaries whose source, author, and capabilities you will not know. Reflexes are built through repetition in a safe environment, not through theory. Each analysis session on our pedagogical samples is a rehearsal that anchors the gesture. When you face a real unknown sample, the checklist will be an automatism, not a chore to learn under pressure.

It is exactly the same principle as airline pilots who go through their pre-flight checklist at every takeoff, including when they have been flying for 20 years and know the aircraft by heart. It is not a question of competence — it is a question of reliability.

---

> 📌 **Key Takeaway** — The eight rules in this section are not gradual recommendations. They are invariants. The most sophisticated infrastructure protects nothing if the analyst takes a shortcut. Snapshot before, isolation verified, monitoring active, artifacts collected, notes taken — at every session, without exception. The pre-execution checklist is your last line of defense between a successful analysis and an avoidable incident.

⏭️ [🎯 Checkpoint: deploy the lab and verify network isolation](/26-secure-lab/checkpoint.md)
