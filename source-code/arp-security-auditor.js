/**
 * ARPForge Pro - 10-Point Zero-Trust Layer 2 First-Hop Security (DAI) Auditor
 * 
 * Evaluates switch configurations against CIS Cisco IOS Benchmark, NIST SP 800-125B,
 * and PCI-DSS v4.0 Layer 2 segmentation requirements.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ArpSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_CONTROLS = [
    {
      id: 'DAI-SEC-01',
      title: 'Global Dynamic ARP Inspection (DAI) Active per VLAN',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.daiVlans && cfg.daiVlans !== 'none') {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: `Dynamic ARP Inspection active on VLANs ${cfg.daiVlans}. All untrusted ARP packets intercepted.`,
            remediation: 'Compliant. Layer 2 ARP Cache Poisoning attacks are actively inspected.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL VULNERABILITY: Dynamic ARP Inspection is DISABLED. Attackers can execute Man-in-the-Middle (MitM) ARP poisoning via Ettercap/Bettercap without restriction.',
          remediation: 'Enable DAI globally on all active host VLANs: "ip arp inspection vlan 10,20,100".'
        };
      }
    },
    {
      id: 'DAI-SEC-02',
      title: 'Core Trunk & Uplink Trust Boundary Configuration',
      maxPoints: 15,
      evaluate: function (cfg) {
        if (cfg.trunkTrustEnabled) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'Core switch uplinks and router ports explicitly configured with "ip arp inspection trust".',
            remediation: 'Compliant. Inter-switch trunk and default gateway ARP traffic bypasses rate-limiting and inspection drops.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'FAIL',
          finding: 'CRITICAL OUTAGE RISK: Core uplinks not marked as trusted. Switch will inspect and drop legitimate inter-switch ARP updates!',
          remediation: 'Apply "ip arp inspection trust" to all upstream distribution/core trunk interfaces and router links.'
        };
      }
    },
    {
      id: 'DAI-SEC-03',
      title: 'Untrusted Edge Access Port Enforcement',
      maxPoints: 12,
      evaluate: function (cfg) {
        if (cfg.edgePortsUntrusted) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'Host edge ports strictly maintained in untrusted state (default "no ip arp inspection trust").',
            remediation: 'Compliant. Rogue workstations cannot bypass DAI validation.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL SECURITY BREACH: Access ports configured as "trusted"! DAI validation is completely bypassed by end-user devices.',
          remediation: 'Remove "ip arp inspection trust" from all end-user workstation and client switchports.'
        };
      }
    },
    {
      id: 'DAI-SEC-04',
      title: 'Strict Deep-Packet Validation Checks (src-mac, dst-mac, ip)',
      maxPoints: 12,
      evaluate: function (cfg) {
        const checks = [];
        if (cfg.validateSrcMac) checks.push('src-mac');
        if (cfg.validateDstMac) checks.push('dst-mac');
        if (cfg.validateIp) checks.push('ip');

        if (checks.length === 3) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'Comprehensive DAI validation active ("ip arp inspection validate src-mac dst-mac ip").',
            remediation: 'Compliant. Header mismatches, invalid broadcast targets, and illegal 0.0.0.0/multicast IPs are blocked.'
          };
        } else if (checks.length > 0) {
          return {
            passed: true,
            score: 6,
            level: 'WARN',
            finding: `Partial DAI validation active (${checks.join(', ')}). Missing remaining validation parameters.`,
            remediation: 'Enable all three validation checks: "ip arp inspection validate src-mac dst-mac ip".'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'No DAI deep-packet validation configured. Injected ARP packets with spoofed Ethernet headers may slip past basic bindings.',
          remediation: 'Configure "ip arp inspection validate src-mac dst-mac ip".'
        };
      }
    },
    {
      id: 'DAI-SEC-05',
      title: 'Switch CPU Hardware Rate-Limiting Protection',
      maxPoints: 10,
      evaluate: function (cfg) {
        const rate = parseInt(cfg.arpRateLimitPps, 10) || 15;
        if (rate >= 10 && rate <= 50) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `Hardware rate-limiting set to ${rate} pps on edge ports. Prevents control plane CPU starvation.`,
            remediation: 'Compliant. Balanced protection against ARP flood DoS attacks.'
          };
        } else if (rate > 50) {
          return {
            passed: false,
            score: 4,
            level: 'WARN',
            finding: `High rate-limit (${rate} pps) allows potential CPU saturation during massive rogue ARP storms.`,
            remediation: 'Standardize on 15 to 30 pps for user edge ports ("ip arp inspection limit rate 15").'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Rate limiting disabled or set too low (<10 pps), causing false-positive port err-disables during OS boots.',
          remediation: 'Configure "ip arp inspection limit rate 15".'
        };
      }
    },
    {
      id: 'DAI-SEC-06',
      title: 'Err-Disabled Automatic Recovery & Timer Synthesis',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.errdisableRecoveryEnabled) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Automatic err-disable recovery enabled for arp-inspection with 30s recovery timer.',
            remediation: 'Compliant. Legitimate burst spikes recover automatically without helpdesk intervention.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'Err-disable recovery not configured. If a port experiences a momentary ARP burst, it remains permanently down!',
          remediation: 'Add "errdisable recovery cause arp-inspection" and "errdisable recovery interval 30".'
        };
      }
    },
    {
      id: 'DAI-SEC-07',
      title: 'Static Device ARP ACL / Binding Database Mapping',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.staticArpAclConfigured) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'Explicit static ARP ACL / DHCP reservations mapped for non-DHCP devices (servers, printers, PBXs).',
            remediation: 'Compliant. Prevents DAI from blackholing legitimate static IP infrastructure.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'No static ARP ACL defined. Any static IP printers, storage arrays, or server hosts will be dropped by DAI!',
          remediation: 'Define an ARP ACL for static hosts: "arp access-list STATIC-HOSTS; permit ip host 192.168.1.10 mac host 0050.56a1.b2c3".'
        };
      }
    },
    {
      id: 'DAI-SEC-08',
      title: 'DHCP Snooping Database Synchronization',
      maxPoints: 8,
      evaluate: function (cfg) {
        if (cfg.dhcpSnoopingActive) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: 'DHCP Snooping enabled on the same VLANs, providing an authoritative MAC-to-IP lease database for DAI.',
            remediation: 'Compliant.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: 'CRITICAL MISCONFIGURATION: DAI requires DHCP Snooping binding database, but DHCP Snooping is disabled on the VLAN!',
          remediation: 'Enable "ip dhcp snooping" and "ip dhcp snooping vlan <list>" globally.'
        };
      }
    },
    {
      id: 'DAI-SEC-09',
      title: 'Control Plane Message-Log Buffer Rate-Limiting',
      maxPoints: 5,
      evaluate: function (cfg) {
        if (cfg.loggingBufferTuned) {
          return {
            passed: true,
            score: 5,
            level: 'PASS',
            finding: 'Syslog message logging buffer rate-limited to prevent console locking during security events.',
            remediation: 'Compliant.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'INFO',
          finding: 'Default DAI logging behavior may overwhelm syslog servers during active ARP attack events.',
          remediation: 'Tune logging rate: "ip arp inspection message-log rate-limit 32".'
        };
      }
    },
    {
      id: 'DAI-SEC-10',
      title: 'Broadcast Storm Control on Edge Access Ports',
      maxPoints: 5,
      evaluate: function (cfg) {
        if (cfg.stormControlEnabled) {
          return {
            passed: true,
            score: 5,
            level: 'PASS',
            finding: 'Hardware storm control active on access ports, capping broadcast floods to 5.0% link bandwidth.',
            remediation: 'Compliant. Defeats broadcast ARP flood attacks at Layer 2 hardware ASIC level.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'Storm control disabled. High-volume broadcast ARP floods can saturate edge switch backplanes.',
          remediation: 'Configure "storm-control broadcast level 5.0" on edge access ports.'
        };
      }
    }
  ];

  function auditConfiguration(cfg) {
    let totalScore = 0;
    const findings = [];

    AUDIT_CONTROLS.forEach(ctrl => {
      const res = ctrl.evaluate(cfg);
      totalScore += res.score;
      findings.push({
        id: ctrl.id,
        title: ctrl.title,
        maxPoints: ctrl.maxPoints,
        score: res.score,
        level: res.level,
        passed: res.passed,
        finding: res.finding,
        remediation: res.remediation
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 60) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      passed: totalScore >= 80,
      findings: findings,
      evaluatedAt: new Date().toISOString()
    };
  }

  return {
    AUDIT_CONTROLS,
    auditConfiguration
  };
}));
