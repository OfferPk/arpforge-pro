# ARPForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for enterprise network administrators, penetration testers, and NetDevOps engineers deploying Dynamic ARP Inspection (DAI) and First-Hop Security.**

---

## 1\. Quickstart: Web Application Studio

The **ARPForge Pro Web Studio** is completely self-contained with zero external dependencies. Open `source-code/index.html` directly in any modern web browser:

\# Optional local web server

cd product\_128/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Industry Presets**:  
   - **Enterprise Zero-Trust DAI (Grade A+)**: Configured with global DAI, DHCP Snooping synchronization, deep validation checks (`src-mac`, `dst-mac`, `ip`), 15 pps rate-limiting, and auto-errdisable recovery.  
   - **Data Center Static Server DAI (Grade A+)**: Demonstrates static ARP ACL filtering (`ip arp inspection filter STATIC-SERVERS static`) preventing outages for non-DHCP servers.  
   - **Vulnerable Legacy ARP Poisoning (Grade F)**: Replicates unhardened default switches vulnerable to Ettercap/Bettercap MitM poisoning.  
2. **ARP Packet Parameters**: Configure Opcode (1 Request, 2 Reply, Gratuitous ARP), Sender/Target IPv4 and MAC addresses, and Ethernet header MACs.  
3. **Dynamic ARP Inspection (DAI) Simulator**: Real-time simulation of DAI inspection against an authoritative binding database, deep-packet checks, and trust boundaries.  
4. **Two-Way ARP Cache Status**: Shows real-time cache table states for the Default Gateway and Victim Host.  
5. **10-Point Zero-Trust Scorecard**: Automated evaluation against CIS Cisco IOS Benchmark and NIST SP 800-125B (0–100%, Grades A+ to F).  
6. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard copy and binary `.pcap` capture file export.  
7. **Multi-Platform Synthesizer**: Instant configuration generation for Cisco IOS-XE, Cisco Nexus NX-OS, Arista EOS, Juniper Junos, and Linux arptables/nftables.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/arpforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/arpforge-cli.py \--dissect

### 2.2 Simulating Dynamic ARP Inspection & Poisoning Defense

\# Check hardened preset (Protected against MitM)

./build/arpforge-cli.py \--preset build/presets/enterprise-zero-trust-dai.json \--simulate

\# Check vulnerable preset (Exploitable)

./build/arpforge-cli.py \--preset build/presets/vulnerable-legacy-arp-poisoning.json \--simulate

### 2.3 Analyzing CPU Rate-Limiting & Burst Protection

./build/arpforge-cli.py \--preset build/presets/enterprise-zero-trust-dai.json \--ratelimit

### 2.4 Running 10-Point Zero-Trust Layer 2 FHS Audits

\# Audit Enterprise Zero-Trust DAI preset

./build/arpforge-cli.py \--preset build/presets/enterprise-zero-trust-dai.json \--audit

\# Audit Vulnerable Legacy preset

./build/arpforge-cli.py \--preset build/presets/vulnerable-legacy-arp-poisoning.json \--audit

### 2.5 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing packet decoders or validating with Wireshark:

./build/arpforge-cli.py \--preset build/presets/enterprise-zero-trust-dai.json \--pcap arp-frame.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-e \-n \-r arp-frame.pcap

### 2.6 Automated CI/CD Pipeline Gating (`--strict`)

Integrate ARPForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit Layer 2 First-Hop Security (DAI)

  run: |

    python3 build/arpforge-cli.py \\

      \--preset build/presets/switch-dai-config.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and zero critical DAI vulnerabilities. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or critical flaw detected. Pipeline halts.*

---

## 3\. Production Configuration Examples

### 3.1 Cisco Catalyst 9300 Hardened Zero-Trust DAI Configuration

\! 1\. Authoritative DHCP Snooping Database

ip dhcp snooping

ip dhcp snooping vlan 10,20,100

no ip dhcp snooping information option

\!

\! 2\. Global DAI Activation

ip arp inspection vlan 10,20,100

\!

\! 3\. Deep-Packet Payload & Header Validation Checks

ip arp inspection validate src-mac dst-mac ip

\!

\! 4\. Control Plane Protection: Rate Limiting & Auto Err-Disable Recovery

errdisable recovery cause arp-inspection

errdisable recovery interval 30

ip arp inspection message-log rate-limit 32

\!

\! 5\. Static ARP ACL for Non-DHCP Infrastructure

arp access-list STATIC-SERVERS

 permit ip host 192.168.1.10 mac host 0050.56a1.b2c3

\!

ip arp inspection filter STATIC-SERVERS vlan 10,20,100 static

\!

\! 6\. Core Trunk Uplink (Trust Boundary)

interface TenGigabitEthernet1/0/48

 description CORE-DISTRIBUTION-TRUNK

 switchport mode trunk

 ip dhcp snooping trust

 ip arp inspection trust

 no shutdown

\!

\! 7\. User-Facing Edge Access Ports (Untrusted & Rate-Limited)

interface range GigabitEthernet1/0/1 \- 24

 description USER-WORKSTATIONS

 switchport mode access

 switchport access vlan 10

 ip arp inspection limit rate 15

 storm-control broadcast level 5.0

 no shutdown

---

## 4\. Troubleshooting Layer 2 DAI Outages

1. **Static IP Server or Printer Disconnected When DAI Enabled**:  
   - *Cause*: Static devices do not obtain leases from DHCP, so no entry exists in the DHCP Snooping database. DAI drops their ARP replies.  
   - *Resolution*: Create an `arp access-list` permitting the static host and apply it with the `static` keyword: `ip arp inspection filter <acl-name> vlan <id> static`.  
2. **Access Switchport Enters `err-disabled` State**:  
   - *Cause*: Host exceeded the 15 pps rate limit during boot, VM migration, or network scan.  
   - *Resolution*: Enable automated recovery: `errdisable recovery cause arp-inspection` `errdisable recovery interval 30`.  
3. **Switch CPU Reaches 100% During Outage**:  
   - *Cause*: Rate-limiting was disabled (`ip arp inspection limit none`) or set excessively high on untrusted ports, allowing an ARP storm to overwhelm the CPU.  
   - *Resolution*: Enforce `ip arp inspection limit rate 15` on all untrusted access interfaces.  
4. **Legitimate Inter-Switch ARP Traffic Dropped**:  
   - *Cause*: Core trunk uplinks were left in the default untrusted state.  
   - *Resolution*: Configure `ip arp inspection trust` on all inter-switch trunks and default gateway links.