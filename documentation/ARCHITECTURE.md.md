# ARPForge Pro \- Architecture & Technical Specification

> **IETF RFC 826 (Address Resolution Protocol), RFC 5227 (IPv4 Address Conflict Detection), and Dynamic ARP Inspection (DAI) First-Hop Security Engineering Specification**

---

## 1\. Executive Summary & Standards Baseline

**Address Resolution Protocol (ARP)**, formalized in **IETF RFC 826**, is the fundamental Layer 2/Layer 3 binding mechanism in IPv4 Ethernet networks. Operating between the Data Link Layer (Layer 2\) and Network Layer (Layer 3), ARP dynamically resolves 32-bit IPv4 addresses into 48-bit IEEE 802.3 MAC addresses.

However, RFC 826 was designed in 1982 for cooperative computing environments and possesses zero cryptographic authentication, zero state tracking, and zero message validation:

- **Stateless Trust**: Operating systems update their internal ARP cache upon receiving *any* ARP reply, regardless of whether an ARP request was ever transmitted.  
- **Unauthenticated Mapping**: Any host on a local broadcast domain can broadcast or unicast an unsolicited ARP reply claiming to possess the default gateway IP (`192.168.1.1 is at attacker-mac`).  
- **Pervasive Man-in-the-Middle (MitM)**: Rogue endpoints running tools like Ettercap, Bettercap, or Arpspoof poison both the default gateway and victim hosts simultaneously, intercepting all cleartext and encrypted traffic, DNS queries, and credentials before Layer 3 firewalls ever inspect the packets.

\+-----------------------------------------------------------------------------------------+

|                                  ARP & DAI PROTOCOL SUMMARY                             |

\+--------------------------+---------------------------------------+----------------------+

| Layer / Domain           | Standard / Mechanism                  | Operational Purpose  |

\+--------------------------+---------------------------------------+----------------------+

| Address Resolution       | IETF RFC 826 (EtherType 0x0806)       | Maps 32-bit IPv4 to  |

|                          | Hardware Type 0x0001, Protocol 0x0800 | 48-bit MAC addresses |

\+--------------------------+---------------------------------------+----------------------+

| Address Conflict Detect  | IETF RFC 5227 (ACD)                   | Probes & announces IP|

|                          | Gratuitous ARP (GARP)                 | ownership on link-up |

\+--------------------------+---------------------------------------+----------------------+

| First-Hop Security (FHS) | Dynamic ARP Inspection (DAI)          | Intercepts & validates|

|                          | Hardware ASIC snoop against DHCP DB   | all untrusted ARPs   |

\+--------------------------+---------------------------------------+----------------------+

| Deep Header Validation   | "ip arp inspection validate"          | Checks src-mac,      |

|                          | (src-mac, dst-mac, ip)                | dst-mac, and valid IP|

\+--------------------------+---------------------------------------+----------------------+

| CPU Rate Limiting        | "ip arp inspection limit rate 15"     | Prevents switch CPU  |

|                          | Auto-recovery timer (30s)             | exhaustion DoS floods|

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. Ethernet II & ARP Packet Wire Structure

### 2.1 Complete 64-Byte On-Wire Ethernet II ARP Frame

An ARP packet is encapsulated directly within an Ethernet II frame (EtherType `0x0806`). Because an Ethernet payload \+ header must reach a minimum of 64 bytes on the physical wire (or 60 bytes before the 4-byte CRC32 Frame Check Sequence), the 28-byte ARP packet is padded with 18 bytes of trailing zeros:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  Destination MAC Address (Bytes 0-3)          |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|  Dest MAC (Bytes 4-5)         |   Source MAC Address (Bytes 0-1)|

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  Source MAC Address (Bytes 2-5)               |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|       EtherType \= 0x0806      |  Hardware Type \= 0x0001 (Eth) |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|   Protocol Type \= 0x0800 (IP) | Hw Size \= 6   | Proto Size \= 4|

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|          Opcode (1=Req, 2=Reply, 3=RARP Req, 4=RARP Reply)   |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  Sender Hardware MAC Address (Bytes 0-3)      |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|  Sender MAC (Bytes 4-5)       |   Sender IPv4 Address (0-1)   |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|  Sender IPv4 Address (2-3)    |   Target Hardware MAC (0-1)   |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  Target Hardware MAC Address (Bytes 2-5)      |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  Target IPv4 Address (Bytes 0-3)              |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  Padding (18 Bytes of 0x00 to reach 60B)      |

|                               ...                             |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                  32-Bit Frame Check Sequence (CRC32 FCS)      |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

---

## 3\. Attack Mechanics: ARP Cache Poisoning & MitM

### 3.1 Two-Way Unsolicited ARP Reply Poisoning

                      \+-------------------+

                      | Default Gateway   |

                      | 192.168.1.1       |

                      | MAC: 00:50:56:... |

                      \+---------+---------+

                                |

                   Trunk Port   | (Trusted)

                    \+-----------+-----------+

                    | Core / Dist Switch    |

                    \+-----+-----------+-----+

                          |           |

            Untrusted Gi1/0/1         | Untrusted Gi1/0/2

                          |           |

       \+------------------+--+     \+--+------------------+

       | Attacker Workstation |     | Victim Workstation   |

       | 192.168.1.50         |     | 192.168.1.100        |

       | MAC: 00:1a:2b:3c:... |     | MAC: 00:11:22:33:... |

       \+---------------------+     \+---------------------+

1. **Attack Vector 1 (Poisoning Victim)**:  
   - Attacker crafts an unsolicited ARP Reply: `Sender MAC: 00:1a:2b:3c:... (Attacker) | Sender IP: 192.168.1.1 (Gateway)` `Target MAC: 00:11:22:33:... (Victim)   | Target IP: 192.168.1.100 (Victim)`  
   - Victim receives the reply, updates its ARP cache: `192.168.1.1 -> 00:1a:2b:3c:...`.  
   - All outbound Internet and corporate WAN traffic from the victim is now transmitted directly to the attacker\!  
2. **Attack Vector 2 (Poisoning Gateway)**:  
   - Attacker crafts an unsolicited ARP Reply to the Gateway: `Sender MAC: 00:1a:2b:3c:... (Attacker) | Sender IP: 192.168.1.100 (Victim)` `Target MAC: 00:50:56:a1:... (Gateway)  | Target IP: 192.168.1.1 (Gateway)`  
   - Gateway updates its ARP cache: `192.168.1.100 -> 00:1a:2b:3c:...`.  
   - Inbound return traffic destined for the victim is also routed to the attacker\!  
3. **Full Duplex Man-in-the-Middle (MitM)**:  
   - Attacker enables kernel IP forwarding (`sysctl -w net.ipv4.ip_forward=1`).  
   - The victim's internet connection continues functioning without disruption, while the attacker sniffs, tampers, or redirects all communications.

---

## 4\. First-Hop Security: Dynamic ARP Inspection (DAI) Engineering

**Dynamic ARP Inspection (DAI)** is a Layer 2 hardware ASIC security feature that prevents ARP poisoning by intercepting, inspecting, and discarding invalid ARP packets on untrusted switchports.

### 4.1 Binding Database Synchronization

DAI validates incoming ARP packets against the **DHCP Snooping Binding Database**: \$\$\\text{DAI Validation Key} \= \\left\\langle \\text{VLAN ID}, \\text{MAC Address}, \\text{IPv4 Address}, \\text{Interface} \\right\\rangle\$\$

- When a host acquires an IP via DHCP, DHCP Snooping records the lease binding.  
- When an ARP request or reply arrives on an untrusted port, the switch ASIC checks:  
  1. Does the sender IP exist in the database?  
  2. Does the sender MAC in the ARP packet match the bound MAC?  
  3. Did the packet arrive on the bound physical port?  
- If any check fails, the packet is **silently dropped**, and a rate-limited syslog alert is generated.

### 4.2 Static ARP ACLs for Non-DHCP Devices

In enterprise environments, servers, printers, storage arrays, and IP PBXs use static IP addressing and do not generate DHCP Snooping bindings. Without static mapping, **DAI will drop all static device ARP traffic**:

arp access-list STATIC-SERVERS

 permit ip host 192.168.1.10 mac host 0050.56a1.b2c3

\!

ip arp inspection filter STATIC-SERVERS vlan 10 static

*Note: The `static` keyword instructs the switch to check the ARP ACL first. If no match is found, it falls back to the DHCP Snooping database. Omitting `static` causes all non-ACL traffic to be dropped\!*

### 4.3 Deep Payload Validation Checks

Standard DAI only checks IP-to-MAC bindings. Attackers can bypass basic checks by spoofing the Ethernet header while placing a valid IP in the ARP body. Cisco DAI provides three additional hardware checks:

1. `src-mac`: Verifies Ethernet header source MAC equals ARP sender MAC.  
2. `dst-mac`: Verifies Ethernet header destination MAC equals ARP target MAC in ARP replies.  
3. `ip`: Validates against illegal IP addresses (`0.0.0.0`, `255.255.255.255`, and multicast ranges `224.0.0.0/4`).

ip arp inspection validate src-mac dst-mac ip

### 4.4 Switch CPU Hardware Rate-Limiting & Err-Disabled Recovery

Because ARP packets are broadcast (`ff:ff:ff:ff:ff:ff`), untrusted switches punt ARP frames to the switch CPU for DAI evaluation. An attacker flooding 5,000 ARP packets/sec will drive switch CPU utilization to 100%, causing routing protocol flaps (OSPF/BGP dead-timer expirations).

- **Rate-Limiting**: Caps incoming ARP packets per untrusted port to 15 pps: `ip arp inspection limit rate 15`  
- **Err-Disabled Recovery**: If a host bursts beyond 15 pps (e.g. during an OS network scan or reboot), the switch places the port into `err-disabled` state. Automated recovery restores the port after 30 seconds: `errdisable recovery cause arp-inspection` `errdisable recovery interval 30`

---

## 5\. 10-Point Zero-Trust Layer 2 FHS (DAI) Audit Rubric

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **DAI-SEC-01** | Global DAI Active per VLAN | 15 pts | `ip arp inspection vlan <list>` enabled on all host subnets. |
| **DAI-SEC-02** | Core Trunk Trust Boundary | 15 pts | Uplinks explicitly configured with `ip arp inspection trust`. |
| **DAI-SEC-03** | Untrusted Edge Access Ports | 12 pts | Edge ports maintain default untrusted state (`no ip arp inspection trust`). |
| **DAI-SEC-04** | Strict Payload Validation | 12 pts | Enforces `ip arp inspection validate src-mac dst-mac ip`. |
| **DAI-SEC-05** | Hardware CPU Rate Limiting | 10 pts | Capped at 15–30 pps on edge ports to prevent CPU DoS. |
| **DAI-SEC-06** | Err-Disabled Auto Recovery | 10 pts | Restores burst-tripped ports automatically (`interval 30`). |
| **DAI-SEC-07** | Static Device ARP ACL Mapping | 8 pts | Maps static servers/printers to prevent outage blackholes. |
| **DAI-SEC-08** | DHCP Snooping Synchronization | 8 pts | Active on same VLANs to feed authoritative lease database. |
| **DAI-SEC-09** | Message-Log Buffer Tuning | 5 pts | Rate-limits syslog traps to prevent console lockups. |
| **DAI-SEC-10** | Broadcast Storm Control | 5 pts | Limits broadcast ARP storm floods to 5.0% link bandwidth. |

