🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.4 — VM network configuration: NAT, host-only, isolation

> 🎯 **Goal of this section**: understand the different network modes available for your VM, know which one to use for which work phase, and configure the interfaces needed to switch from one mode to another in seconds.

---

## The network, a vector to master

The network is both a tool and a risk in reverse engineering. A tool, because some training binaries communicate over the network (Chapter 23 — client/server, Chapter 28 — dropper with C2 protocol). A risk, because a malicious binary executed inside the VM could try to contact an external server, exfiltrate data, or propagate.

The strategy is simple: **you give the VM exactly the level of network access it needs, and not one byte more.** To this end, we configure several network interfaces and switch between them depending on the context.

---

## The three network modes

### NAT — Internet access, no direct access from the host

In NAT (Network Address Translation) mode, the VM accesses the Internet through the host, which acts as a router. The VM gets a private IP address (typically 10.0.2.x for VirtualBox, 192.168.122.x for QEMU/KVM) and can browse the web, download packages, clone Git repositories.

On the other hand, the host and the local network cannot initiate a connection to the VM — unless you configure port-forwarding rules, as we did for SSH in section 4.3.

```
┌─────────────┐       NAT          ┌──────────────┐       ┌──────────┐
│     VM      │ ──── (10.0.2.x) ──→│    Host      │ ────→ │ Internet │
│   RE-Lab    │ ←── responses ─────│  (router)    │ ←──── │          │
└─────────────┘                    └──────────────┘       └──────────┘
                                          ↑
                           No incoming connection
                           (except SSH port forwarding)
```

**When to use it:**

- During system and tool installation (sections 4.2–4.3) — you need `apt`, `pip`, `wget`.  
- When you work on chapters that do not involve running suspicious binaries.  
- To update the VM occasionally.

**Residual risk**: if you execute a malicious binary while in NAT mode, that binary has Internet access. It could theoretically contact a command server, download a payload, or exfiltrate data. That is exactly what we want to avoid for Part VI.

### Host-only — host ↔ VM communication, no Internet

In host-only mode (private host network), the VM and the host are connected on a private virtual network. The VM can communicate with the host (and with other VMs on the same host-only network), but it has **no Internet access**.

```
┌─────────────┐    host-only     ┌──────────────┐
│     VM      │ ← 192.168.56.x ─→│    Host      │       ✗ Internet
│   RE-Lab    │                  │              │
└─────────────┘                  └──────────────┘
       ↕
  Other VMs on
  the same network
```

**When to use it:**

- During dynamic-analysis chapters (Part III) when you run and instrument training binaries.  
- For the network exercises of Chapter 23: client and server run inside the VM (or between two VMs), and the traffic stays confined.  
- When you want to capture the VM's network traffic with Wireshark or `tcpdump` on the host.

**Key advantage**: a binary executed inside the VM cannot reach the Internet. Even if it tries to connect to a C2 server, the connection will silently fail or be refused.

### Internal / isolated network — no communication with the host or Internet

In internal-network mode (VirtualBox) or isolated-network mode (QEMU/KVM), the VM can only communicate with other VMs attached to the same virtual network. The host itself is unreachable.

```
┌─────────────┐    isolated      ┌─────────────┐
│    VM 1     │ ← 10.99.0.x ───→ │    VM 2     │       ✗ Internet
│  (malware)  │                  │  (monitor)  │       ✗ Host
└─────────────┘                  └─────────────┘
```

**When to use it:**

- Part VI (malicious code analysis) — this is the safest mode for running the ransomware and dropper samples.  
- Chapter 28 (dropper with network communication): you can simulate a fake C2 server on a second VM connected to the same isolated network, while keeping everything cut off from the outside world.

**This is the maximum isolation level.** Even if the VM is compromised, the malware cannot reach the host, the Internet, or the local network.

---

## Summary table

| Mode | Internet | Host → VM access | VM → host access | Inter-VM access | Main usage |  
|---|---|---|---|---|---|  
| **NAT** | Yes | Via port forwarding | No | No | Installation, updates |  
| **Host-only** | No | Yes (private network) | Yes (private network) | Yes (same network) | Dynamic analysis, network exercises |  
| **Isolated / internal** | No | No | No | Yes (same network) | Malware analysis (Part VI) |

---

## Configuration per hypervisor

### VirtualBox

VirtualBox allows attaching up to four network adapters to a VM. We configure two to be able to switch easily:

**Adapter 1 — NAT (enabled by default)**

In **Settings → Network → Adapter 1**:

- Attached to: **NAT**  
- Adapter type: Intel PRO/1000 MT Desktop (or Virtio for better performance if the drivers are installed in the VM)

This will be the interface used for installations and updates. You can disable it (uncheck "Enable Network Adapter") when you do not need Internet.

> 💡 **SSH port-forwarding rule** (if not already done in section 4.3): in **Advanced → Port Forwarding**, add a TCP rule host port 2222 → guest port 22.

**Adapter 2 — Host-only**

Before configuring the adapter, create the host-only network in VirtualBox:

1. **File → Host Network Manager** (or **Tools → Network** in recent versions).  
2. Click **Create**. A `vboxnet0` network appears with a default range (typically 192.168.56.0/24).  
3. Verify that the **DHCP server** is enabled (DHCP Server tab) — this simplifies IP address assignment in the VM.

Then in **Settings → Network → Adapter 2**:

- Tick **Enable Network Adapter**.  
- Attached to: **Host-Only Adapter**.  
- Name: `vboxnet0`.

**Internal network (for Part VI)**

When you tackle malware analysis, you will temporarily replace host-only with an **internal network**:

- Attached to: **Internal Network**.  
- Name: `malware-lab` (name it as you like — VMs on the same internal-network name will see each other).

This network has no DHCP server by default. You will need to configure IP addresses manually in the VMs (see below).

### QEMU/KVM (with libvirt)

Libvirt manages virtual networks via XML files. Three networks interest us.

**`default` network (NAT) — already present**

Libvirt automatically creates a `default` network in NAT mode (`virbr0` interface, 192.168.122.0/24 range). Verify it is active:

```bash
[host] virsh net-list --all
# Should show: default   active   yes   yes
```

If it is not active:

```bash
[host] virsh net-start default
[host] virsh net-autostart default
```

**Host-only network — to create**

Create a definition file `hostonly.xml`:

```xml
<network>
  <name>hostonly</name>
  <bridge name="virbr1" />
  <ip address="192.168.100.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.100.100" end="192.168.100.200" />
    </dhcp>
  </ip>
</network>
```

Note the absence of a `<forward>` tag — that is what keeps traffic from leaking outside.

```bash
[host] virsh net-define hostonly.xml
[host] virsh net-start hostonly
[host] virsh net-autostart hostonly
```

Add a second network interface to the VM via `virt-manager`: **Add Hardware → Network → Network source: hostonly**.

**Isolated network — to create for Part VI**

```xml
<network>
  <name>isolated-malware</name>
  <bridge name="virbr2" />
  <ip address="10.99.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.99.0.100" end="10.99.0.200" />
    </dhcp>
  </ip>
</network>
```

Same principle — no `<forward>`, so no route to the outside. VMs connected to this network will only be able to communicate with each other.

```bash
[host] virsh net-define isolated-malware.xml
[host] virsh net-start isolated-malware
```

> 💡 We do not activate `net-autostart` for the isolated network: you will start it manually when you need it (Part VI).

### UTM (macOS)

UTM offers the network modes in each VM's settings, **Network** tab:

- **Shared Network**: NAT equivalent. The VM accesses the Internet through the host. This is the default mode.  
- **Host Only**: private network between the host and the VM, with no Internet access.  
- **None**: no network connectivity. The VM is fully isolated.

UTM does not natively support multi-VM internal networks like VirtualBox. To simulate an isolated network between two VMs, you can use a shared host-only network and add macOS firewall rules to block forwarding, or simply set both VMs to host-only mode (they will see each other on the same subnet).

**Recommended configuration for this training:**

| Phase | UTM mode |  
|---|---|  
| Installation, updates | Shared Network |  
| Chapters 1–25 (learning) | Shared Network or Host Only |  
| Part VI (malware) | Strict Host Only or None |

---

## Configuring the interfaces inside the VM

With two network adapters configured, the VM will see two interfaces (typically `enp0s3` and `enp0s8` under VirtualBox, or `ens3` and `ens4` under QEMU/KVM). Ubuntu uses Netplan for network configuration.

Check the detected interfaces:

```bash
[vm] ip link show
```

If the second interface (host-only) has no IP address, DHCP has not been enabled on it. Edit the Netplan configuration:

```bash
[vm] sudo nano /etc/netplan/01-netcfg.yaml
```

Example configuration for two interfaces, the first in DHCP (NAT) and the second in DHCP (host-only):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: true
```

Apply the configuration:

```bash
[vm] sudo netplan apply
[vm] ip addr show
```

You should see an IP address on each interface — for example 10.0.2.15 (NAT) and 192.168.56.101 (host-only).

> 💡 **Tip**: interface names (`enp0s3`, `ens3`, `eth0`…) vary by hypervisor and virtual adapter type. Use `ip link show` to identify yours.

---

## Switching between network modes

Switching between modes happens **without restarting the VM** in most cases.

### Quick method: enable/disable interfaces inside the VM

To cut Internet access while keeping the host-only network:

```bash
[vm] sudo ip link set enp0s3 down    # disables the NAT interface
```

To re-enable it:

```bash
[vm] sudo ip link set enp0s3 up
[vm] sudo dhclient enp0s3             # requests a new IP via DHCP
```

### Hypervisor-side method

**VirtualBox**: in the menu of the running VM, **Devices → Network → Adapter 1 → Connect/Disconnect the network cable**. The effect is instant — it is like unplugging a virtual Ethernet cable.

**QEMU/KVM (virsh)**:

```bash
[host] virsh domif-setlink RE-Lab enp0s3 down    # disconnects the NAT interface
[host] virsh domif-setlink RE-Lab enp0s3 up      # reconnects
```

**UTM**: change the network mode in the VM settings. A VM reboot may be required.

---

## Recommended network workflow per training phase

| Phase | NAT interface | Host-only interface | Isolated network | Rationale |  
|---|---|---|---|---|  
| **Installation** (4.2–4.3) | Active | Inactive | — | Need Internet for `apt`/`pip`/downloads |  
| **Parts I–II** (ch. 1–10) | Active | Active | — | No risk, static analysis only |  
| **Part III** (ch. 11–15) | **Disabled** | Active | — | Executing and instrumenting binaries — cut Internet as a precaution |  
| **Parts IV–V** (ch. 16–25) | Case by case | Active | — | Disable NAT while executing binaries |  
| **Part VI** (ch. 26–29) | **Disabled** | **Disabled** | **Active** | Maximum isolation for malware analysis |  
| **Parts VII–IX** (ch. 30–36) | Active | Active | — | No significant risk |

> 📌 **Simple rule**: if you are about to execute a binary and you do not need the Internet for that exercise, **cut the NAT interface**. It is a 5-second action that eliminates an entire category of risks.

---

## Verifying isolation

After configuring your interfaces, verify that the behavior matches your expectations.

**Internet access test:**

```bash
[vm] ping -c 3 8.8.8.8
```

- If the NAT interface is active → replies received.  
- If the NAT interface is disabled → `Network is unreachable` or no reply. That is the expected behavior.

**Host ↔ VM connectivity test (host-only):**

```bash
# From the VM, ping the host (host-only network address)
[vm] ping -c 3 192.168.56.1

# From the host, ping the VM
[host] ping -c 3 192.168.56.101
```

**Full isolation test (internal/isolated network):**

```bash
[vm] ping -c 3 8.8.8.8            # should fail
[vm] ping -c 3 192.168.56.1       # should fail (host unreachable)
[vm] ping -c 3 10.99.0.101        # should succeed (other VM on the same isolated network)
```

---

## Network traffic capture

Being able to capture the VM's network traffic is essential for Chapter 23 (custom protocol) and Part VI (malware analysis).

### From the VM (the simplest)

```bash
[vm] sudo tcpdump -i enp0s8 -w /tmp/capture.pcap
```

Then open `/tmp/capture.pcap` in Wireshark (inside the VM) or transfer it to the host via the shared folder or SCP.

### From the host (on the bridge interface)

On a Linux host with QEMU/KVM, you can capture directly on the virtual bridge:

```bash
[host] sudo tcpdump -i virbr1 -w ~/capture-hostonly.pcap
```

With VirtualBox, capture is possible via the `VBoxManage` command:

```bash
[host] VBoxManage modifyvm "RE-Lab" --nictrace2 on --nictracefile2 ~/capture.pcap
```

> 📌 **Chapters concerned**: 23 (network protocol analysis with Wireshark), 26 (secure lab), 28 (network dropper).

---

## Summary

- Configure **two network interfaces** on your VM: one NAT (Internet) and one host-only (private network).  
- **Switch between modes** depending on the work phase by enabling/disabling the interfaces — no reboot needed.  
- For **Part VI (malware)**, use an isolated/internal network with no access to the host or the Internet.  
- The golden rule: **cut the NAT interface before executing a suspicious binary.** Restoring Internet takes 5 seconds; recovering from a data exfiltration is much harder.  
- Systematically verify your isolation with `ping` tests before starting a dynamic-analysis session.

---


⏭️ [Repository structure: organization of `binaries/` and per-chapter `Makefile`s](/04-work-environment/05-repository-structure.md)
