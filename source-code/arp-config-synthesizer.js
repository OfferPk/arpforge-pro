/**
 * ARPForge Pro - Multi-Platform Layer 2 First-Hop Security (DAI) Synthesizer
 * 
 * Synthesizes production-hardened configurations for Cisco IOS-XE,
 * Cisco Nexus NX-OS, Arista EOS, Juniper Junos, and Linux (arptables/nftables).
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ArpConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(params) {
    const vlans = params.daiVlans || '10,20,100';
    const rate = params.arpRateLimitPps || 15;
    const hasStaticAcl = Boolean(params.staticArpAclConfigured);
    const staticIp = params.staticIp || '192.168.1.10';
    const staticMac = (params.staticMac || '0050.56a1.b2c3').replace(/:/g, '').replace(/(\w{4})/g, '$1.').replace(/\.$/, '');

    let staticAclConfig = '';
    if (hasStaticAcl) {
      staticAclConfig = `!
! 5. Static ARP ACL for Non-DHCP Infrastructure (Printers, Servers, PBXs)
arp access-list STATIC-SERVERS
 permit ip host ${staticIp} mac host ${staticMac}
!
ip arp inspection filter STATIC-SERVERS vlan ${vlans} static
`;
    }

    return `! ==============================================================================
! Cisco Catalyst / IOS-XE Production Dynamic ARP Inspection (DAI) Configuration
! Platform: Cisco Catalyst 9300 / 9500 running IOS-XE 17.x+
! Standards: IETF RFC 826 | CIS Cisco IOS Benchmark | NIST SP 800-125B
! ==============================================================================

! 1. Authoritative DHCP Snooping Database Prerequisite
ip dhcp snooping
ip dhcp snooping vlan ${vlans}
no ip dhcp snooping information option
!
! 2. Global Dynamic ARP Inspection (DAI) Activation
ip arp inspection vlan ${vlans}
!
! 3. Deep-Packet Payload & Header Validation Checks
ip arp inspection validate src-mac dst-mac ip
!
! 4. Control Plane Protection: Rate Limiting & Auto Err-Disable Recovery
errdisable recovery cause arp-inspection
errdisable recovery interval 30
ip arp inspection message-log rate-limit 32
${staticAclConfig}!
! 6. Core Distribution & Gateway Trunk Uplink (Trust Boundary)
interface TenGigabitEthernet1/0/48
 description CORE-DISTRIBUTION-TRUNK-UPLINK
 switchport mode trunk
 ip dhcp snooping trust
 ip arp inspection trust
 no shutdown
!
! 7. User-Facing Edge Access Ports (Untrusted & Rate-Limited)
interface range GigabitEthernet1/0/1 - 24
 description END-USER-WORKSTATIONS
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 ! Hardware Rate-Limiting: Capped at ${rate} pps to prevent CPU starvation DoS
 ip arp inspection limit rate ${rate}
 storm-control broadcast level 5.0
 no shutdown
`;
  }

  function synthesizeCiscoNxos(params) {
    const vlans = params.daiVlans || '10,20,100';

    return `! ==============================================================================
! Cisco Nexus NX-OS Data Center Spine-Leaf DAI Configuration
! ==============================================================================
feature dhcp
!
ip dhcp snooping
ip dhcp snooping vlan ${vlans}
!
ip arp inspection vlan ${vlans}
ip arp inspection validate src-mac dst-mac ip
!
interface Ethernet1/1
  description SPINE-UPLINK-TRUNK
  switchport mode trunk
  ip dhcp snooping trust
  ip arp inspection trust
!
interface Ethernet1/2-24
  description COMPUTE-NODE-ACCESS
  switchport mode access
  switchport access vlan 10
  ip arp inspection limit rate 20
`;
  }

  function synthesizeArista(params) {
    const vlans = params.daiVlans || '10,20,100';
    const rate = params.arpRateLimitPps || 15;

    return `! ==============================================================================
! Arista EOS Production Dynamic ARP Inspection Configuration
! ==============================================================================
ip dhcp snooping
ip dhcp snooping vlan ${vlans}
!
ip arp inspection vlan ${vlans}
ip arp inspection validate src-mac dst-mac ip
!
interface Ethernet49/1
   description LEAF-SPINE-TRUNK
   switchport mode trunk
   ip dhcp snooping trust
   ip arp inspection trust
!
interface Ethernet1-24
   description HOST-ACCESS-PORTS
   switchport mode access
   switchport access vlan 10
   ip arp inspection rate ${rate}
`;
  }

  function synthesizeJunos(params) {
    const vlanId = (params.daiVlans || '10').split(',')[0].trim();

    return `# ==============================================================================
# Juniper Junos OS Enterprise Dynamic ARP Inspection Configuration
# ==============================================================================
set vlans vlan-${vlanId} switch-options dynamic-arp-inspection
set vlans vlan-${vlanId} switch-options dhcp-security

# Core Trunk Trust Boundary (Bypasses Inspection)
set vlans vlan-${vlanId} switch-options interface ge-0/0/0.0 overrides trusted

# Edge Access Port Rate-Limiting
set vlans vlan-${vlanId} switch-options interface ge-0/0/1.0 dynamic-arp-inspection rate-limit 15
`;
  }

  function synthesizeLinux(params) {
    const gatewayIp = params.gatewayIp || '192.168.1.1';
    const gatewayMac = params.gatewayMac || '00:50:56:a1:b2:c3';

    return `# ==============================================================================
# Linux Anti-ARP Poisoning Defense (arptables & nftables)
# Protects Linux Host/Bridge against Default Gateway ARP Hijacking
# ==============================================================================
# 1. Flush Existing ARP Rules
arptables -F

# 2. Block Rogue ARP Replies claiming the Default Gateway IP from wrong MAC
arptables -A INPUT --source-ip ${gatewayIp} --source-mac ! ${gatewayMac} -j DROP

# 3. Allow Legitimate Gateway ARP Traffic
arptables -A INPUT --source-ip ${gatewayIp} --source-mac ${gatewayMac} -j ACCEPT

# 4. Modern nftables Ingress ARP Anti-Spoofing Rule
# nft add table netdev filter
# nft add chain netdev filter ingress '{ type filter hook ingress device eth0 priority 0; }'
# nft add rule netdev filter ingress arp saddr ip ${gatewayIp} ether saddr != ${gatewayMac} drop
`;
  }

  return {
    synthesizeCiscoIosXe,
    synthesizeCiscoNxos,
    synthesizeArista,
    synthesizeJunos,
    synthesizeLinux
  };
}));
