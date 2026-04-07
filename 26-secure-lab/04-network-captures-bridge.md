🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 26.4 — Network Captures with a Dedicated Bridge

> **Chapter 26 — Setting Up a Secure Analysis Lab**  
> **Part VI — Malicious Code Analysis (Controlled Environment)**

---

## Objective of this section

In section 26.2, we created the isolated network `isolated-malware` and its bridge `br-malware`. In section 26.3, we saw how to launch `tcpdump` to capture traffic. This section goes further. It details the bridge's network architecture, explains how to configure it to maximize visibility into the malware's activity, and presents capture analysis techniques that will be essential in chapters 27 (ransomware) and 28 (dropper with C2 communication).

Capturing network traffic on an isolated network may seem paradoxical — nothing goes out, nothing comes in, so what's the point? In reality, the packets that the malware **attempts** to send are just as revealing as those it successfully delivers. A DNS query to `evil-c2.example.com` that goes unanswered betrays the C2 domain. A SYN to `185.x.x.x:4443` that times out reveals the address and port of the command server. A UDP packet containing an encoded binary blob exposes the format of the exfiltration protocol. All this information can be captured on a network that leads nowhere.

---

## Anatomy of the `br-malware` bridge

A Linux bridge is a virtual network switch that operates at layer 2 (data link layer). It connects the virtual network interfaces attached to it, exactly like a physical switch connects Ethernet cables. When libvirt creates the `isolated-malware` network, it sets up the following architecture:

```
                    HOST MACHINE
    ┌──────────────────────────────────────────┐
    │                                          │
    │   br-malware (10.66.66.1/24)             │
    │   ├── vnet0 ←──── virtual interface      │
    │   │                attached to the VM    │
    │   │                                      │
    │   └── (no physical interface)            │
    │                                          │
    │   The VM sees an enp1s0 interface        │
    │   that obtains 10.66.66.100 via DHCP     │
    │                                          │
    │   No masquerade, no forwarding,          │
    │   no default route on this bridge        │
    │                                          │
    └──────────────────────────────────────────┘
```

The host has an IP address on the bridge (`10.66.66.1`) because libvirt configures it to serve as a DHCP server (via `dnsmasq`). This address enables bidirectional host ↔ VM communication (for `scp`, `ssh`), but **no route** connects the bridge to the host's external network interface (`eth0`, `wlan0`…). Packets sent by the VM to an address outside the `10.66.66.0/24` subnet arrive at the bridge, have nowhere to go, and are silently dropped by the host's network stack.

This is precisely the behavior we exploit: the bridge is a network dead end, but a dead end on which we have a microphone.

### Verify the bridge topology

```bash
# View the interfaces attached to the bridge
bridge link show br-malware

# Or with ip
ip link show master br-malware

# View the bridge's IP configuration
ip addr show br-malware
```

You should see `br-malware` with the address `10.66.66.1/24` and a `vnetX` interface attached (the host-side virtual interface of the VM's virtual network cable).

### Verify the absence of routing

```bash
# Verify that no route exits the bridge
ip route show dev br-malware
# Expected: only "10.66.66.0/24 proto kernel scope link src 10.66.66.1"

# Verify that forwarding is blocked by iptables
sudo iptables -L FORWARD -v -n | grep br-malware
# Expected: DROP rules for input and output
```

If `ip route` shows a default route or a route to another subnet via `br-malware`, there is a configuration problem. Do not proceed until you have fixed it.

---

## Capture point: host vs VM

We addressed this question in section 26.3. Let's explore the technical implications of each approach in more depth here.

### Capture on the host (recommended)

When `tcpdump` listens on the `br-malware` interface on the host, it positions itself at the bridge level. It sees **all traffic** passing through the bridge: packets sent by the VM, packets sent by the host to the VM (DHCP responses, for example), and ARP address resolution packets.

```bash
# Full capture on the bridge
sudo tcpdump -i br-malware -s 0 -w capture.pcap --print
```

Advantages:

- **Invisibility** — the sample cannot detect the capture. There is no `tcpdump` process inside the VM, no `.pcap` file being written to the guest filesystem, no interface in promiscuous mode visible from inside.  
- **Integrity** — even if the malware corrupts the VM (deletes files, kernel panic), the `.pcap` file is safe on the host.  
- **No overhead in the VM** — the VM's CPU and I/O resources remain entirely available for the sample and other monitoring tools.

Disadvantage:

- Traffic internal to the VM (loopback `127.0.0.1`) is not visible on the bridge. If the sample communicates with another process via localhost, that communication will not appear in the capture. For this scenario, a complementary capture inside the VM on the `lo` interface may be necessary.

### Capture inside the VM (complementary)

Useful in two specific situations: capturing loopback traffic, or observing traffic from the sample's exact perspective (before any transformation by the bridge).

```bash
# In the VM — loopback capture
sudo tcpdump -i lo -s 0 -w ~/captures/loopback.pcap --print

# In the VM — network interface capture
sudo tcpdump -i enp1s0 -s 0 -w ~/captures/vm_capture.pcap --print
```

This capture is vulnerable to the malware's actions (deletion, corruption), and it creates a detectable `tcpdump` process. Reserve it for cases where loopback traffic is relevant.

---

## Capturing intelligently: capture filters vs display filters

`tcpdump` allows filtering traffic at two levels. Understanding the difference is essential to avoid losing critical information.

### Capture filters (BPF)

Capture filters are applied **at recording time**. Packets that do not match the filter are never written to the `.pcap` file. What is filtered out is **permanently lost**.

```bash
# Capture only TCP traffic
sudo tcpdump -i br-malware -s 0 -w capture_tcp.pcap tcp

# Capture only DNS traffic
sudo tcpdump -i br-malware -s 0 -w capture_dns.pcap port 53

# Capture only traffic originating from the VM
sudo tcpdump -i br-malware -s 0 -w capture_vm.pcap src host 10.66.66.100
```

**Rule for malware analysis: do not filter at capture time.** You do not yet know which protocol or port the sample will use. A C2 can communicate on port 443, 8080, 53, or a completely exotic port. Capture everything (`-s 0`, no BPF filter) and filter later during analysis.

The only reasonable exception is to exclude SSH traffic if you are connected to the VM via SSH through the bridge, as this administrative traffic would pollute the capture:

```bash
# Capture everything EXCEPT administrative SSH
sudo tcpdump -i br-malware -s 0 -w capture.pcap 'not port 22'
```

### Display filters (post-capture)

Display filters are applied when replaying the `.pcap` file. The original file remains intact — you only filter what you see.

With `tcpdump` in replay mode:

```bash
# Replay filtering DNS queries
tcpdump -r capture.pcap -n port 53

# Replay filtering HTTP traffic
tcpdump -r capture.pcap -A port 80

# Replay filtering SYNs (connection attempts)
tcpdump -r capture.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

With Wireshark (display filters, different syntax):

```
dns  
http  
tcp.flags.syn == 1 && tcp.flags.ack == 0  
ip.dst != 10.66.66.1  
tcp.port == 4443  
frame contains "RANSOM"  
```

Wireshark offers unmatched ergonomics for analyzing complex protocols. Always transfer the `.pcap` to the host to examine it in Wireshark once the capture is complete.

---

## Simulating a realistic network environment (optional)

Some malware only reveals its full behavior if it manages to communicate. A dropper that receives no response from its C2 server may remain dormant. Ransomware that needs to retrieve its encryption key from a server will not encrypt anything if the connection fails. In these cases, a completely silent network can limit observability.

Two techniques allow simulating a minimal network environment while maintaining isolation.

### Technique 1 — DNS responder with `dnsmasq`

The `dnsmasq` server provided by libvirt for DHCP can also serve as a DNS resolver. Properly configured, it can respond to all DNS queries by returning an IP address under our control (typically the host's address on the bridge, `10.66.66.1`).

Modify the isolated network configuration to enable DNS with universal resolution:

```bash
# Create an additional dnsmasq configuration file
sudo mkdir -p /etc/dnsmasq.d  
sudo tee /etc/dnsmasq.d/malware-lab.conf << 'EOF'  
# Respond to ALL DNS queries with the host's IP on the bridge
# The malware believes it resolves its C2 domains, but everything points to us
address=/#/10.66.66.1  
EOF  
```

Restart the libvirt network to apply:

```bash
virsh net-destroy isolated-malware  
virsh net-start isolated-malware  
```

From now on, when the malware makes a DNS query for `evil-c2.example.com`, it receives `10.66.66.1` as a response. It will then attempt to connect to that address — where we can have a fake server listening.

> ⚠️ **This technique makes the network "semi-isolated"** — the VM can resolve names and connect to the host. Data still never leaves the bridge, but the malware has a network peer. Enable this technique only when the sample's behavior requires it (chapter 28 in particular), and disable it for analyses where total isolation is preferred (chapter 27).

### Technique 2 — `INetSim`: Internet services simulator

`INetSim` is a tool designed specifically for malware analysis. It simulates about a dozen common Internet services (HTTP, HTTPS, DNS, FTP, SMTP, IRC…) on a single machine. The malware believes it is communicating with real servers, while it is actually talking to a simulator that records every exchange.

Installation on the host (or in a dedicated services VM):

```bash
sudo apt install inetsim
```

Configuration to listen on the bridge:

```bash
sudo tee /etc/inetsim/inetsim.conf << 'EOF'
# Listen only on the bridge interface
service_bind_address 10.66.66.1

# DNS: resolve everything to us
dns_default_ip 10.66.66.1

# Services to enable
start_service dns  
start_service http  
start_service https  
start_service smtp  
start_service ftp  

# Logging directory
report_dir /var/log/inetsim/report

# Directory for files served via HTTP/FTP
data_dir /var/lib/inetsim  
EOF  
```

Launch:

```bash
sudo inetsim
```

`INetSim` will respond to HTTP requests with a default page, accept SMTP connections and record emails the malware attempts to send, serve dummy files via FTP, etc. Every interaction is logged in `/var/log/inetsim/report/`.

> 💡 **In the context of this training**, `INetSim` will primarily be used in chapter 28 (dropper with C2 communication) to allow the sample to complete its handshake and reveal its full behavior. In chapter 27 (ransomware), the sample does not need network access to function — total isolation is therefore maintained.

### Technique 3 — Handcrafted fake C2 server

For cases where `INetSim` is not enough (custom non-HTTP protocol), you can write a fake server in Python that responds to the malware's specific protocol. This is precisely the subject of chapter 28 (section 28.4 — Simulating a C2 server). At this stage, simply note that the isolated bridge allows running a server on `10.66.66.1` that will be accessible by the VM without any traffic leaving the physical machine.

---

## Rotation and sizing of captures

A `tcpdump` capture with no filter or size limit can grow rapidly, especially if the malware generates traffic in a loop (periodic C2 beacon, network scan). Over a 30-minute session, a chatty sample can produce several hundred MB of `.pcap`.

### Rotation by file size

`tcpdump` can split the capture into successive files when a size threshold is reached:

```bash
# Rotate every 100 MB, keep a maximum of 10 files
sudo tcpdump -i br-malware -s 0 \
  -w capture_%Y%m%d_%H%M%S.pcap \
  -C 100 \
  -W 10 \
  --print
```

- `-C 100` — creates a new file every 100 MB (the value is in millions of bytes).  
- `-W 10` — keeps a maximum of 10 files (the oldest are overwritten).

### Rotation by duration

```bash
# Rotate every 5 minutes
sudo tcpdump -i br-malware -s 0 \
  -w capture_%Y%m%d_%H%M%S.pcap \
  -G 300 \
  --print
```

- `-G 300` — creates a new file every 300 seconds (5 minutes).

### Volume estimation

To size your captures, here are some benchmarks:

| Sample behavior | Estimated volume (30 min) |  
|---|---|  
| No network activity (local ransomware) | < 1 KB (ARP/DHCP only) |  
| Periodic C2 beacon (every 30 s) | 1 – 10 MB |  
| Active network scan (SYN across IP range) | 50 – 500 MB |  
| Data exfiltration (continuous upload) | 100 MB – several GB |

For short sessions and our educational samples, a monolithic capture (a single file, no rotation) is more than sufficient. Rotation becomes relevant for extended analyses or very chatty samples.

---

## Analyzing a capture: 5-step methodology

Once the capture is complete and retrieved on the host, the analysis follows a structured process. This process will be applied concretely in chapters 27 and 28.

### Step 1 — Statistical overview

Before opening Wireshark, get the measure of the capture:

```bash
# General statistics
capinfos capture.pcap

# Number of packets
tcpdump -r capture.pcap | wc -l

# Breakdown by protocol (with tshark, the Wireshark CLI)
tshark -r capture.pcap -q -z io,phs
```

The `tshark -z io,phs` command (Protocol Hierarchy Statistics) displays the traffic breakdown by protocol. It is the equivalent of the Statistics → Protocol Hierarchy menu in Wireshark. This view immediately tells you whether the sample generated DNS, HTTP, raw TCP, UDP, ICMP traffic, etc.

### Step 2 — Identify the endpoints

What IP addresses did the sample attempt to contact?

```bash
# IP conversations (source → destination)
tshark -r capture.pcap -q -z conv,ip

# Unique endpoints
tshark -r capture.pcap -q -z endpoints,ip
```

In our lab, the VM has the address `10.66.66.100` and the host `10.66.66.1`. Any destination address that is **neither one nor the other** is an address the malware attempted to reach externally — it is a potential IOC (Indicator of Compromise).

### Step 3 — Extract DNS queries

DNS queries are often the first network action of a malware: resolving the domain name of its C2 server.

```bash
# List all DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort -u
```

This command extracts the domain names the sample attempted to resolve. Each of these names is a top-tier IOC.

### Step 4 — Examine TCP connections

```bash
# List outgoing SYNs (connection attempts initiated by the VM)
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 10.66.66.100" \
  -T fields -e ip.dst -e tcp.dstport | sort -u
```

Each `(destination IP, destination port)` pair represents a service the malware attempted to reach. Common ports provide clues: 443 (HTTPS/TLS), 80 (HTTP), 4444 (Metasploit default), 8443, 8080 (proxies/C2), 53 (DNS or DNS tunneling), 6667 (IRC).

### Step 5 — Examine the payloads

For connections that succeeded (in cases where `INetSim` or a fake C2 was responding), extract the exchanged content:

```bash
# Follow a specific TCP stream (stream index 0, 1, 2…)
tshark -r capture.pcap -q -z "follow,tcp,ascii,0"

# Export all HTTP objects retrieved by the sample
tshark -r capture.pcap --export-objects http,./http_objects/

# Search for a string in the payloads
tshark -r capture.pcap -Y 'frame contains "HELLO"' -V
```

For custom protocols (binary, non-HTTP), the `follow,tcp,raw` command exports the raw content in hexadecimal. This dump can then be loaded into ImHex to apply a `.hexpat` pattern — this is exactly the workflow we will follow in chapter 23 (Reversing a network binary) and chapter 28 (C2 protocol).

---

## Integration with Wireshark on the host

For in-depth capture analysis, Wireshark offers features that the command line cannot match: visual stream tracking, automatic decoding of hundreds of protocols, time graphs, session reconstruction.

### Installation on the host

```bash
# On the host (not in the VM)
sudo apt install wireshark tshark
```

### Dedicated profile for malware analysis

Create a dedicated Wireshark profile (Edit → Configuration Profiles → New) with the following columns, optimized for malicious traffic analysis:

| Column | Field | Purpose |  
|---|---|---|  
| Time | `frame.time_relative` | Time elapsed since the start of the capture |  
| Source | `ip.src` | Source IP |  
| Destination | `ip.dst` | Destination IP |  
| Protocol | `_ws.col.Protocol` | Detected protocol |  
| Dst Port | `tcp.dstport` or `udp.dstport` | Destination port |  
| Length | `frame.len` | Packet size |  
| Info | `_ws.col.Info` | Packet summary |

Add coloring rules to highlight:

- In red: DNS traffic to unknown domains.  
- In orange: SYNs with no response (failed connections — the sample is trying to reach an inaccessible C2).  
- In green: established TCP streams (the sample is communicating with `INetSim` or a fake C2).

### Open the capture

```bash
wireshark ./analyses/session-xxx/capture.pcap &
```

---

## Automating IOC extraction from a capture

After several analyses, the process of extracting IOCs (Indicators of Compromise) from a `.pcap` file becomes repetitive. The following script automates steps 2 through 4 of our methodology:

```bash
#!/bin/bash
# extract_ioc.sh — Extracts network IOCs from a pcap capture
# Usage: ./extract_ioc.sh capture.pcap

set -euo pipefail

PCAP="${1:?Usage: $0 <file.pcap>}"  
VM_IP="10.66.66.100"  
HOST_IP="10.66.66.1"  
OUTPUT="${PCAP%.pcap}_ioc.txt"  

echo "=== IOCs extracted from: $PCAP ===" > "$OUTPUT"  
echo "Date: $(date)" >> "$OUTPUT"  
echo "" >> "$OUTPUT"  

# Queried DNS domains
echo "--- Queried DNS domains ---" >> "$OUTPUT"  
tshark -r "$PCAP" -Y "dns.flags.response == 0" \  
  -T fields -e dns.qry.name 2>/dev/null | sort -u >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Contacted IP addresses (excluding host and VM)
echo "--- Destination IP addresses (outside lab) ---" >> "$OUTPUT"  
tshark -r "$PCAP" -Y "ip.src == $VM_IP && ip.dst != $HOST_IP" \  
  -T fields -e ip.dst 2>/dev/null | sort -u >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Destination ports
echo "--- TCP destination ports ---" >> "$OUTPUT"  
tshark -r "$PCAP" \  
  -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == $VM_IP" \
  -T fields -e ip.dst -e tcp.dstport 2>/dev/null | sort -u >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "--- UDP destination ports ---" >> "$OUTPUT"  
tshark -r "$PCAP" -Y "ip.src == $VM_IP && udp" \  
  -T fields -e ip.dst -e udp.dstport 2>/dev/null | sort -u >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Statistics
echo "--- Statistics ---" >> "$OUTPUT"  
echo "Total packets: $(tshark -r "$PCAP" 2>/dev/null | wc -l)" >> "$OUTPUT"  
echo "Capture duration: $(capinfos -u "$PCAP" 2>/dev/null | grep 'Capture duration' | awk -F: '{print $2}')" >> "$OUTPUT"  

echo "[+] IOCs extracted to: $OUTPUT"  
cat "$OUTPUT"  
```

This script produces a summary text file that can be attached to the analysis report (chapter 27, section 27.7).

---

## Network scenarios by sample type

The following three chapters present samples with very different network profiles. Here is how to adapt the bridge configuration for each case:

### Chapter 27 — Ransomware (minimal network activity)

The provided ransomware encrypts local files with a hardcoded key. It does not need the network to function. The ideal configuration is total isolation:

- `dnsmasq` in DHCP-only mode (no universal DNS resolution).  
- No `INetSim`.  
- `tcpdump` runs anyway to verify the absence of traffic — or to detect unexpected network behavior that would enrich the analysis.

### Chapter 28 — Dropper with C2 communication

The dropper attempts to contact a command server to receive instructions. Without a response, it remains dormant or only executes partial behavior. To observe its full behavior:

- Enable universal DNS resolution (everything resolves to `10.66.66.1`).  
- Launch `INetSim` on the host, or better: write a fake C2 server adapted to the sample's specific protocol (this is the subject of section 28.4).  
- `tcpdump` captures the entirety of the exchanges between the dropper and the fake C2.

### Chapter 29 — Packed binary

The packed sample normally generates no network activity (packing is a protection, not a behavior). Total isolation is appropriate. `tcpdump` serves as a safety net to confirm the absence of traffic.

---

## Capture pipeline summary

```
BEFORE executing the sample
│
├─ 1. Verify isolation: ping 8.8.8.8 must fail from the VM
├─ 2. Optional: enable INetSim / universal dnsmasq if the sample needs network access
├─ 3. Launch tcpdump on the host: sudo tcpdump -i br-malware -s 0 -w capture.pcap
│
DURING execution
│
├─ 4. Monitor tcpdump --print in real time (DNS names, SYNs, payloads)
│
AFTER execution
│
├─ 5. Stop tcpdump (Ctrl+C)
├─ 6. Quick verification: capinfos + tcpdump -r (overview)
├─ 7. IOC extraction: ./extract_ioc.sh capture.pcap
├─ 8. In-depth analysis: Wireshark on the host
└─ 9. Archive the .pcap with the other session artifacts
```

---

> 📌 **Key takeaway** — The `br-malware` bridge is a packet trap. The malware sends freely, its packets are captured in full, but they go nowhere. When the sample needs a network peer to reveal its behavior, `INetSim` or a fake C2 server on `10.66.66.1` plays the role of the outside world without ever opening a breach in the isolation. The resulting `.pcap` capture is an artifact as valuable as `auditd` logs or `inotifywait` observations — archive it systematically, it will be the basis for protocol analysis and IOC extraction.

⏭️ [Golden rules: never execute outside the sandbox, never connect to the real network](/26-secure-lab/05-golden-rules.md)
