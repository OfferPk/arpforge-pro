/**
 * ARPForge Pro - IETF RFC 826, RFC 5227 & Dynamic ARP Inspection (DAI) Protocol Engine
 * 
 * Provides bit-exact binary ARP frame forging, Wireshark-style hex formatting,
 * PCAP capture generation, and Layer 2 ARP Cache Poisoning / DAI defense simulation.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ArpProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Constants per IETF RFC 826 & RFC 5227
  const ETHERTYPE_ARP = 0x0806;
  const HARDWARE_TYPE_ETHERNET = 0x0001;
  const PROTOCOL_TYPE_IPV4 = 0x0800;
  const HARDWARE_SIZE_MAC = 6;
  const PROTOCOL_SIZE_IPV4 = 4;

  const ARP_OPCODES = {
    REQUEST: 1,
    REPLY: 2,
    RARP_REQUEST: 3,
    RARP_REPLY: 4,
    DRARP_REQUEST: 5,
    DRARP_REPLY: 6,
    DRARP_ERROR: 7,
    INARP_REQUEST: 8,
    INARP_REPLY: 9
  };

  const ARP_OPCODE_NAMES = {
    1: 'ARP Request (who-has)',
    2: 'ARP Reply (is-at)',
    3: 'RARP Request',
    4: 'RARP Reply',
    8: 'InARP Request',
    9: 'InARP Reply'
  };

  function parseMac(macStr) {
    if (!macStr) return [0, 0, 0, 0, 0, 0];
    const clean = macStr.replace(/[^a-fA-F0-9]/g, '');
    if (clean.length !== 12) return [0, 0, 0, 0, 0, 0];
    const bytes = [];
    for (let i = 0; i < 12; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    return bytes;
  }

  function formatMac(bytes) {
    if (!bytes || bytes.length !== 6) return '00:00:00:00:00:00';
    return bytes.map(b => b.toString(16).padStart(2, '0')).join(':');
  }

  function parseIpv4(ipStr) {
    if (!ipStr) return [0, 0, 0, 0];
    const parts = ipStr.trim().split('.');
    if (parts.length !== 4) return [0, 0, 0, 0];
    const bytes = parts.map(p => {
      const n = parseInt(p, 10);
      return isNaN(n) ? 0 : Math.max(0, Math.min(255, n));
    });
    return bytes;
  }

  function formatIpv4(bytes) {
    if (!bytes || bytes.length !== 4) return '0.0.0.0';
    return bytes.join('.');
  }

  // Standard IEEE 802.3 32-bit Frame Check Sequence (CRC32)
  function calculateCrc32(byteArray) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < byteArray.length; i++) {
      crc ^= byteArray[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
      }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  /**
   * Forges a complete 64-byte binary Ethernet II + ARP frame with CRC32 FCS
   */
  function forgeArpFrame(options) {
    const opts = options || {};
    const opcode = parseInt(opts.opcode, 10) || ARP_OPCODES.REQUEST;
    const isGratuitous = Boolean(opts.isGratuitous);

    const ethSrc = parseMac(opts.ethSrcMac || '00:1a:2b:3c:4d:5e');
    let ethDst = parseMac(opts.ethDstMac || (opcode === ARP_OPCODES.REQUEST ? 'ff:ff:ff:ff:ff:ff' : '00:50:56:a1:b2:c3'));
    if (isGratuitous) {
      ethDst = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    }

    const senderMac = parseMac(opts.senderMac || opts.ethSrcMac || '00:1a:2b:3c:4d:5e');
    const senderIp = parseIpv4(opts.senderIp || '192.168.1.50');
    let targetMac = parseMac(opts.targetMac || (opcode === ARP_OPCODES.REQUEST ? '00:00:00:00:00:00' : '00:50:56:a1:b2:c3'));
    let targetIp = parseIpv4(opts.targetIp || '192.168.1.1');

    if (isGratuitous) {
      targetMac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
      targetIp = senderIp.slice(); // In GARP, Target IP == Sender IP
    }

    // 1. Ethernet Header (14 bytes)
    const ethHeader = [
      ...ethDst,
      ...ethSrc,
      (ETHERTYPE_ARP >> 8) & 0xff, ETHERTYPE_ARP & 0xff
    ];

    // 2. ARP Packet Header & Payload (28 bytes)
    const arpPayload = [
      (HARDWARE_TYPE_ETHERNET >> 8) & 0xff, HARDWARE_TYPE_ETHERNET & 0xff,
      (PROTOCOL_TYPE_IPV4 >> 8) & 0xff, PROTOCOL_TYPE_IPV4 & 0xff,
      HARDWARE_SIZE_MAC,
      PROTOCOL_SIZE_IPV4,
      (opcode >> 8) & 0xff, opcode & 0xff,
      ...senderMac,
      ...senderIp,
      ...targetMac,
      ...targetIp
    ];

    // Combine Ethernet Header + ARP Payload (14 + 28 = 42 bytes)
    const frameWithoutFcs = ethHeader.concat(arpPayload);

    // 3. Ethernet Minimum Frame Padding (42 bytes -> 60 bytes minimum payload + header before 4B FCS)
    while (frameWithoutFcs.length < 60) {
      frameWithoutFcs.push(0x00);
    }

    // 4. Calculate 4-Byte CRC32 Frame Check Sequence
    const crc = calculateCrc32(frameWithoutFcs);
    const fcs = [
      crc & 0xff,
      (crc >> 8) & 0xff,
      (crc >> 16) & 0xff,
      (crc >> 24) & 0xff
    ];

    const rawBytes = frameWithoutFcs.concat(fcs);

    return {
      rawBytes: rawBytes,
      totalLength: rawBytes.length,
      opcode: opcode,
      opcodeName: isGratuitous ? 'Gratuitous ARP (Announcement/Probe)' : (ARP_OPCODE_NAMES[opcode] || `Opcode ${opcode}`),
      isGratuitous: isGratuitous,
      ethSrcMac: formatMac(ethSrc),
      ethDstMac: formatMac(ethDst),
      senderMac: formatMac(senderMac),
      senderIp: formatIpv4(senderIp),
      targetMac: formatMac(targetMac),
      targetIp: formatIpv4(targetIp),
      crc32Hex: '0x' + crc.toString(16).padStart(8, '0')
    };
  }

  /**
   * Generates Wireshark-style 16-bytes per line hex dump with ASCII sidebar
   */
  function formatHexDump(rawBytes) {
    if (!rawBytes || !rawBytes.length) return '';
    const lines = [];

    for (let i = 0; i < rawBytes.length; i += 16) {
      const chunk = rawBytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');

      let hexPart1 = '';
      for (let j = 0; j < 8; j++) {
        if (j < chunk.length) {
          hexPart1 += chunk[j].toString(16).padStart(2, '0') + ' ';
        } else {
          hexPart1 += '   ';
        }
      }

      let hexPart2 = '';
      for (let j = 8; j < 16; j++) {
        if (j < chunk.length) {
          hexPart2 += chunk[j].toString(16).padStart(2, '0') + ' ';
        } else {
          hexPart2 += '   ';
        }
      }

      const hexPart = (hexPart1 + ' ' + hexPart2).trimEnd();

      let asciiPart = '';
      for (let j = 0; j < chunk.length; j++) {
        const b = chunk[j];
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      }

      lines.push(`${offset}   ${hexPart.padEnd(48, ' ')}   |${asciiPart}|`);
    }

    return lines.join('\n');
  }

  /**
   * Generates a binary PCAP capture file (pcap format, Ethernet DLT 1)
   */
  function generatePcap(frameObj) {
    const rawBytes = frameObj.rawBytes;
    const pcapHeader = new Uint8Array(24);
    const pcapView = new DataView(pcapHeader.buffer);

    // Standard PCAP Global Header
    pcapView.setUint32(0, 0xa1b2c3d4, true); // Magic Number (Microsecond timestamps, Little-Endian)
    pcapView.setUint16(4, 2, true);          // Major Version 2
    pcapView.setUint16(6, 4, true);          // Minor Version 4
    pcapView.setInt32(8, 0, true);           // GMT to local timezone offset (0)
    pcapView.setUint32(12, 0, true);         // Accuracy of timestamps (0)
    pcapView.setUint32(16, 262144, true);    // Max snapshot length (256KB)
    pcapView.setUint32(20, 1, true);         // Link-Layer Header Type (DLT_EN10MB = 1: Ethernet)

    // Packet Record Header (16 bytes)
    const nowMs = Date.now();
    const sec = Math.floor(nowMs / 1000);
    const usec = (nowMs % 1000) * 1000;

    const recordHeader = new Uint8Array(16);
    const recordView = new DataView(recordHeader.buffer);
    recordView.setUint32(0, sec, true);
    recordView.setUint32(4, usec, true);
    recordView.setUint32(8, rawBytes.length, true);  // Included packet length
    recordView.setUint32(12, rawBytes.length, true); // Original packet length

    const fullPcap = new Uint8Array(24 + 16 + rawBytes.length);
    fullPcap.set(pcapHeader, 0);
    fullPcap.set(recordHeader, 24);
    fullPcap.set(new Uint8Array(rawBytes), 40);

    return fullPcap;
  }

  /**
   * Simulates ARP Cache Poisoning (Man-in-the-Middle) & Dynamic ARP Inspection (DAI)
   */
  function simulateArpPoisoning(params) {
    const p = params || {};
    const daiEnabled = Boolean(p.daiEnabled);
    const isTrunkPort = Boolean(p.isTrunkPort);
    const trustPort = Boolean(p.trustPort);
    const validateSrcMac = Boolean(p.validateSrcMac);
    const validateDstMac = Boolean(p.validateDstMac);
    const validateIp = Boolean(p.validateIp);

    const ethSrcMac = (p.ethSrcMac || '00:1a:2b:3c:4d:5e').toLowerCase();
    const senderMac = (p.senderMac || '00:1a:2b:3c:4d:5e').toLowerCase();
    const senderIp = (p.senderIp || '192.168.1.1').trim();

    const ethDstMac = (p.ethDstMac || '00:50:56:a1:b2:c3').toLowerCase();
    const targetMac = (p.targetMac || '00:50:56:a1:b2:c3').toLowerCase();
    const targetIp = (p.targetIp || '192.168.1.100').trim();

    const isSpoofed = Boolean(p.isSpoofed);
    const bindingDb = p.bindingDatabase || [
      { mac: '00:50:56:a1:b2:c3', ip: '192.168.1.1', vlan: 10, interface: 'Gi1/0/24' },
      { mac: '00:11:22:33:44:55', ip: '192.168.1.100', vlan: 10, interface: 'Gi1/0/1' }
    ];

    // If port is trusted (e.g. core trunk uplink), DAI inspection is bypassed
    if (trustPort || isTrunkPort) {
      return {
        verdict: 'FORWARDED_TRUSTED',
        riskLevel: 'LOW',
        action: 'Forwarded unconditionally (DAI Trust Enabled)',
        title: 'DAI TRUST BOUNDARY: Packet Bypassed Inspection',
        summary: 'Interface is marked as "ip arp inspection trust". Packet forwarded directly to ASIC switching fabric without database lookup.',
        details: ['Port Trust: ENABLED', 'Inspection: Bypassed']
      };
    }

    // If DAI is disabled on the VLAN
    if (!daiEnabled) {
      if (isSpoofed) {
        return {
          verdict: 'POISONED_CRITICAL',
          riskLevel: 'CRITICAL',
          action: 'MITM EXPLOIT SUCCEEDED: ARP Cache Poisoned',
          title: 'CRITICAL EXPLOIT: Unauthenticated ARP Packet Poisoned Subnet',
          summary: `Dynamic ARP Inspection is DISABLED on VLAN. Attacker spoofed ${senderIp} -> ${senderMac}. Target host ${targetIp} updated ARP cache and routed all traffic through attacker!`,
          details: [
            'DAI Status: DISABLED',
            `Spoofed Mapping: ${senderIp} => ${senderMac}`,
            'Victim ARP Cache: POISONED',
            'Man-in-the-Middle Interception: ACTIVE'
          ]
        };
      }
      return {
        verdict: 'FORWARDED_UNPROTECTED',
        riskLevel: 'WARN',
        action: 'Forwarded (DAI Disabled on VLAN)',
        title: 'WARNING: Subnet Lacks First-Hop Security (DAI)',
        summary: 'Legitimate ARP frame forwarded, but the VLAN has no DAI protection. Highly vulnerable to rogue Ettercap/Bettercap injection.',
        details: ['DAI Status: DISABLED on VLAN']
      };
    }

    // DAI is ENABLED on this untrusted port:
    const checks = [];

    // 1. Validate SRC-MAC (Ethernet Header vs ARP Sender MAC)
    if (validateSrcMac) {
      if (ethSrcMac !== senderMac) {
        return {
          verdict: 'DROPPED_SRC_MAC_MISMATCH',
          riskLevel: 'PROTECTED',
          action: 'DISCARDED by DAI: Source MAC Mismatch',
          title: 'PROTECTED: Blocked by "validate src-mac"',
          summary: `Ethernet header source MAC (${ethSrcMac}) does not match ARP sender MAC (${senderMac}). Injected spoofed frame discarded.`,
          details: [
            'DAI Validation: src-mac check failed',
            `Eth Src: ${ethSrcMac}`,
            `ARP Sender: ${senderMac}`
          ]
        };
      }
      checks.push('SRC-MAC Validation: PASSED');
    }

    // 2. Validate DST-MAC (Ethernet Header vs ARP Target MAC)
    if (validateDstMac && p.opcode === ARP_OPCODES.REPLY) {
      if (ethDstMac !== targetMac && ethDstMac !== 'ff:ff:ff:ff:ff:ff') {
        return {
          verdict: 'DROPPED_DST_MAC_MISMATCH',
          riskLevel: 'PROTECTED',
          action: 'DISCARDED by DAI: Destination MAC Mismatch',
          title: 'PROTECTED: Blocked by "validate dst-mac"',
          summary: `Ethernet destination MAC (${ethDstMac}) does not match ARP target MAC (${targetMac}) in ARP reply. Frame dropped.`,
          details: [
            'DAI Validation: dst-mac check failed',
            `Eth Dst: ${ethDstMac}`,
            `ARP Target: ${targetMac}`
          ]
        };
      }
      checks.push('DST-MAC Validation: PASSED');
    }

    // 3. Validate IP (Disallow 0.0.0.0, 255.255.255.255, Multicast IPs)
    if (validateIp) {
      const sParts = parseIpv4(senderIp);
      const tParts = parseIpv4(targetIp);
      const isIllegalSender = (sParts[0] === 0 && sParts[1] === 0 && sParts[2] === 0 && sParts[3] === 0) ||
                              (sParts[0] === 255 && sParts[1] === 255 && sParts[2] === 255 && sParts[3] === 255) ||
                              (sParts[0] >= 224 && sParts[0] <= 239);
      const isIllegalTarget = (tParts[0] === 255 && tParts[1] === 255 && tParts[2] === 255 && tParts[3] === 255) ||
                              (tParts[0] >= 224 && tParts[0] <= 239);

      if (isIllegalSender || isIllegalTarget) {
        return {
          verdict: 'DROPPED_ILLEGAL_IP',
          riskLevel: 'PROTECTED',
          action: 'DISCARDED by DAI: Illegal IP Address',
          title: 'PROTECTED: Blocked by "validate ip"',
          summary: `ARP packet contains invalid IP address (Sender: ${senderIp}, Target: ${targetIp}). Discarded.`,
          details: ['DAI Validation: illegal IP address format']
        };
      }
      checks.push('IP Validation: PASSED');
    }

    // 4. DHCP Snooping Binding Database Lookup
    const matchingBinding = bindingDb.find(b => b.ip === senderIp);

    if (matchingBinding) {
      if (matchingBinding.mac.toLowerCase() === senderMac) {
        return {
          verdict: 'FORWARDED_VALIDATED',
          riskLevel: 'PROTECTED',
          action: 'FORWARDED: Validated against DHCP Snooping Binding Database',
          title: 'PROTECTED: Legitimate Host Binding Confirmed',
          summary: `DAI successfully matched Sender IP ${senderIp} to MAC ${senderMac} in DHCP Snooping Database on VLAN 10. Frame forwarded.`,
          details: [
            ...checks,
            `DHCP Snooping Match: ${matchingBinding.ip} <-> ${matchingBinding.mac}`,
            `Assigned Interface: ${matchingBinding.interface}`
          ]
        };
      } else {
        return {
          verdict: 'DROPPED_BINDING_MISMATCH',
          riskLevel: 'PROTECTED',
          action: 'DISCARDED by DAI: Binding Database Mismatch',
          title: 'PROTECTED: Rogue ARP Spoof Blocked by DAI',
          summary: `Sender ${senderMac} claimed IP ${senderIp}, but DHCP Snooping Database assigns ${senderIp} to MAC ${matchingBinding.mac}. Rogue ARP reply dropped!`,
          details: [
            ...checks,
            `Expected MAC: ${matchingBinding.mac}`,
            `Claimed MAC: ${senderMac}`,
            'Result: Packet silently dropped, syslog rate-limited alert generated'
          ]
        };
      }
    }

    // If IP is not found in DHCP Snooping DB (e.g. static IP without static ARP ACL)
    return {
      verdict: 'DROPPED_UNMAPPED_STATIC_IP',
      riskLevel: 'WARN',
      action: 'DISCARDED by DAI: Unmapped IP (Static Device Drop Hazard)',
      title: 'WARNING: Dropped Unmapped IP (Static Server / Printer Outage Hazard)',
      summary: `IP ${senderIp} has no entry in DHCP Snooping Database. Unless an explicit ARP ACL ("ip arp inspection filter") is applied, legitimate static devices lose connectivity!`,
      details: [
        `Unknown IP: ${senderIp}`,
        'Cause: No matching DHCP Snooping binding found',
        'Remediation: Configure static ARP ACL or DHCP reservation'
      ]
    };
  }

  /**
   * Calculates CPU Rate Limiting & Err-Disabled Thresholds
   */
  function calculateRateLimit(pps, burstIntervalSec) {
    const rate = Math.max(1, parseInt(pps, 10) || 15);
    const interval = Math.max(1, parseInt(burstIntervalSec, 10) || 1);
    const maxBurstsAllowed = rate * interval;

    return {
      configuredPps: rate,
      burstWindowSec: interval,
      maxBurstPackets: maxBurstsAllowed,
      cpuUtilizationEstimate: rate <= 15 ? '< 2% (Safe)' : rate <= 50 ? '5-15% (Moderate)' : '> 40% (CPU Starvation Risk)',
      recommendedRecoverySec: 30
    };
  }

  return {
    ETHERTYPE_ARP,
    HARDWARE_TYPE_ETHERNET,
    PROTOCOL_TYPE_IPV4,
    ARP_OPCODES,
    ARP_OPCODE_NAMES,
    parseMac,
    formatMac,
    parseIpv4,
    formatIpv4,
    calculateCrc32,
    forgeArpFrame,
    formatHexDump,
    generatePcap,
    simulateArpPoisoning,
    calculateRateLimit
  };
}));
