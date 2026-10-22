/**
 * ARPForge Pro - Web Studio Controller & Preset Manager
 */

(function () {
  'use strict';

  const PRESETS = {
    'enterprise-zero-trust': {
      opcode: 2,
      isGratuitous: false,
      senderIp: '192.168.1.1',
      senderMac: '00:1a:2b:3c:4d:5e', // Injected rogue MAC spoofing gateway
      targetIp: '192.168.1.100',
      targetMac: '00:50:56:a1:b2:c3',
      ethSrcMac: '00:1a:2b:3c:4d:5e',
      ethDstMac: '00:50:56:a1:b2:c3',
      daiEnabled: true,
      daiVlans: '10,20,100',
      trunkTrustEnabled: true,
      edgePortsUntrusted: true,
      portTrust: false,
      validateSrcMac: true,
      validateDstMac: true,
      validateIp: true,
      arpRateLimitPps: 15,
      errdisableRecoveryEnabled: true,
      staticArpAclConfigured: true,
      dhcpSnoopingActive: true,
      loggingBufferTuned: true,
      stormControlEnabled: true
    },
    'datacenter-static': {
      opcode: 2,
      isGratuitous: false,
      senderIp: '192.168.1.10',
      senderMac: '00:50:56:a1:b2:c3',
      targetIp: '192.168.1.1',
      targetMac: '00:0c:29:4f:8a:12',
      ethSrcMac: '00:50:56:a1:b2:c3',
      ethDstMac: '00:0c:29:4f:8a:12',
      daiEnabled: true,
      daiVlans: '10,20',
      trunkTrustEnabled: true,
      edgePortsUntrusted: true,
      portTrust: false,
      validateSrcMac: true,
      validateDstMac: true,
      validateIp: true,
      arpRateLimitPps: 20,
      errdisableRecoveryEnabled: true,
      staticArpAclConfigured: true,
      dhcpSnoopingActive: true,
      loggingBufferTuned: true,
      stormControlEnabled: true
    },
    'vulnerable-legacy': {
      opcode: 2,
      isGratuitous: false,
      senderIp: '192.168.1.1',
      senderMac: '00:1a:2b:3c:4d:5e',
      targetIp: '192.168.1.100',
      targetMac: '00:50:56:a1:b2:c3',
      ethSrcMac: '00:1a:2b:3c:4d:5e',
      ethDstMac: '00:50:56:a1:b2:c3',
      daiEnabled: false,
      daiVlans: 'none',
      trunkTrustEnabled: false,
      edgePortsUntrusted: false,
      portTrust: true, // Erroneously trusted access port
      validateSrcMac: false,
      validateDstMac: false,
      validateIp: false,
      arpRateLimitPps: 0,
      errdisableRecoveryEnabled: false,
      staticArpAclConfigured: false,
      dhcpSnoopingActive: false,
      loggingBufferTuned: false,
      stormControlEnabled: false
    }
  };

  let currentConfig = Object.assign({}, PRESETS['enterprise-zero-trust']);
  let activeTab = 'cisco-ios';
  let forgedFrameCache = null;

  // DOM Elements
  const selectArpOpcode = document.getElementById('select-arp-opcode');
  const inputSenderIp = document.getElementById('input-sender-ip');
  const inputSenderMac = document.getElementById('input-sender-mac');
  const inputTargetIp = document.getElementById('input-target-ip');
  const inputTargetMac = document.getElementById('input-target-mac');
  const inputEthSrc = document.getElementById('input-eth-src');
  const inputEthDst = document.getElementById('input-eth-dst');
  const badgeFrameLen = document.getElementById('badge-frame-len');

  const selectDaiState = document.getElementById('select-dai-state');
  const selectPortTrust = document.getElementById('select-port-trust');
  const selectValidateSrc = document.getElementById('select-validate-src');
  const selectValidateDst = document.getElementById('select-validate-dst');
  const selectValidateIp = document.getElementById('select-validate-ip');
  const inputRateLimit = document.getElementById('input-rate-limit');

  const badgeDaiStatus = document.getElementById('badge-dai-status');
  const daiDiagBanner = document.getElementById('dai-diag-banner');
  const daiDiagTitle = document.getElementById('dai-diag-title');
  const daiDiagDesc = document.getElementById('dai-diag-desc');

  const badgeCacheStatus = document.getElementById('badge-cache-status');
  const gatewayCacheText = document.getElementById('gateway-cache-text');
  const victimCacheText = document.getElementById('victim-cache-text');

  const auditGradeCircle = document.getElementById('audit-grade-circle');
  const auditScoreText = document.getElementById('audit-score-text');
  const auditComplianceText = document.getElementById('audit-compliance-text');
  const auditScoreBar = document.getElementById('audit-score-bar');
  const auditStatusBadge = document.getElementById('audit-status-badge');
  const findingsContainer = document.getElementById('findings-container');

  const hexDissectorBox = document.getElementById('hex-dissector-box');
  const synthesizerOutputBox = document.getElementById('synthesizer-output-box');

  const btnCopyHex = document.getElementById('btn-copy-hex');
  const btnDownloadPcap = document.getElementById('btn-download-pcap');
  const btnCopyConfig = document.getElementById('btn-copy-config');
  const presetButtons = document.querySelectorAll('.btn-preset');
  const tabButtons = document.querySelectorAll('.tab-btn');

  function updateUiFromConfig() {
    selectArpOpcode.value = currentConfig.isGratuitous ? 'garp' : String(currentConfig.opcode || 2);
    inputSenderIp.value = currentConfig.senderIp;
    inputSenderMac.value = currentConfig.senderMac;
    inputTargetIp.value = currentConfig.targetIp;
    inputTargetMac.value = currentConfig.targetMac;
    inputEthSrc.value = currentConfig.ethSrcMac;
    inputEthDst.value = currentConfig.ethDstMac;

    selectDaiState.value = currentConfig.daiEnabled ? 'enabled' : 'disabled';
    selectPortTrust.value = currentConfig.portTrust ? 'trusted' : 'untrusted';
    selectValidateSrc.value = currentConfig.validateSrcMac ? 'true' : 'false';
    selectValidateDst.value = currentConfig.validateDstMac ? 'true' : 'false';
    selectValidateIp.value = currentConfig.validateIp ? 'true' : 'false';
    inputRateLimit.value = currentConfig.arpRateLimitPps || 15;

    recomputeAll();
  }

  function readConfigFromUi() {
    const opVal = selectArpOpcode.value;
    if (opVal === 'garp') {
      currentConfig.opcode = 2;
      currentConfig.isGratuitous = true;
    } else {
      currentConfig.opcode = parseInt(opVal, 10) || 2;
      currentConfig.isGratuitous = false;
    }

    currentConfig.senderIp = inputSenderIp.value.trim();
    currentConfig.senderMac = inputSenderMac.value.trim();
    currentConfig.targetIp = inputTargetIp.value.trim();
    currentConfig.targetMac = inputTargetMac.value.trim();
    currentConfig.ethSrcMac = inputEthSrc.value.trim();
    currentConfig.ethDstMac = inputEthDst.value.trim();

    currentConfig.daiEnabled = (selectDaiState.value === 'enabled');
    currentConfig.daiVlans = currentConfig.daiEnabled ? '10,20,100' : 'none';
    currentConfig.portTrust = (selectPortTrust.value === 'trusted');
    currentConfig.edgePortsUntrusted = !currentConfig.portTrust;

    currentConfig.validateSrcMac = (selectValidateSrc.value === 'true');
    currentConfig.validateDstMac = (selectValidateDst.value === 'true');
    currentConfig.validateIp = (selectValidateIp.value === 'true');
    currentConfig.arpRateLimitPps = parseInt(inputRateLimit.value, 10) || 15;

    recomputeAll();
  }

  function recomputeAll() {
    // 1. Forge Binary ARP Frame
    forgedFrameCache = ArpProtocolEngine.forgeArpFrame({
      opcode: currentConfig.opcode,
      isGratuitous: currentConfig.isGratuitous,
      ethSrcMac: currentConfig.ethSrcMac,
      ethDstMac: currentConfig.ethDstMac,
      senderMac: currentConfig.senderMac,
      senderIp: currentConfig.senderIp,
      targetMac: currentConfig.targetMac,
      targetIp: currentConfig.targetIp
    });

    badgeFrameLen.textContent = `FRAME: ${forgedFrameCache.totalLength}B`;
    hexDissectorBox.textContent = ArpProtocolEngine.formatHexDump(forgedFrameCache.rawBytes);

    // 2. Simulate Dynamic ARP Inspection
    const isSpoof = (currentConfig.senderIp === '192.168.1.1' && currentConfig.senderMac.toLowerCase() !== '00:50:56:a1:b2:c3');

    const simRes = ArpProtocolEngine.simulateArpPoisoning({
      daiEnabled: currentConfig.daiEnabled,
      isTrunkPort: false,
      trustPort: currentConfig.portTrust,
      validateSrcMac: currentConfig.validateSrcMac,
      validateDstMac: currentConfig.validateDstMac,
      validateIp: currentConfig.validateIp,
      ethSrcMac: currentConfig.ethSrcMac,
      senderMac: currentConfig.senderMac,
      senderIp: currentConfig.senderIp,
      ethDstMac: currentConfig.ethDstMac,
      targetMac: currentConfig.targetMac,
      targetIp: currentConfig.targetIp,
      opcode: currentConfig.opcode,
      isSpoofed: isSpoof
    });

    daiDiagTitle.textContent = simRes.title;
    daiDiagDesc.textContent = simRes.summary;

    if (simRes.riskLevel === 'CRITICAL') {
      badgeDaiStatus.textContent = 'EXPLOITED';
      badgeDaiStatus.className = 'badge badge-rose';
      daiDiagBanner.className = 'diag-banner diag-critical';

      badgeCacheStatus.textContent = 'POISONED';
      badgeCacheStatus.className = 'badge badge-rose';
      victimCacheText.textContent = `192.168.1.1 => ${currentConfig.senderMac} [POISONED / MITM ACTIVE!]`;
      victimCacheText.style.color = 'var(--primary-rose)';
      gatewayCacheText.textContent = `192.168.1.100 => ${currentConfig.targetMac} [COMPROMISED]`;
      gatewayCacheText.style.color = 'var(--primary-amber)';
    } else if (simRes.riskLevel === 'WARN') {
      badgeDaiStatus.textContent = 'UNPROTECTED';
      badgeDaiStatus.className = 'badge badge-amber';
      daiDiagBanner.className = 'diag-banner diag-warn';

      badgeCacheStatus.textContent = 'WARNING';
      badgeCacheStatus.className = 'badge badge-amber';
      victimCacheText.textContent = `192.168.1.1 => 00:50:56:a1:b2:c3 [SUSCEPTIBLE]`;
      victimCacheText.style.color = 'var(--primary-amber)';
      gatewayCacheText.textContent = `192.168.1.100 => 00:11:22:33:44:55 [SUSCEPTIBLE]`;
      gatewayCacheText.style.color = 'var(--primary-amber)';
    } else {
      badgeDaiStatus.textContent = 'PROTECTED';
      badgeDaiStatus.className = 'badge badge-emerald';
      daiDiagBanner.className = 'diag-banner diag-protected';

      badgeCacheStatus.textContent = 'CLEAN';
      badgeCacheStatus.className = 'badge badge-emerald';
      victimCacheText.textContent = `192.168.1.1 => 00:50:56:a1:b2:c3 [AUTHENTIC GATEWAY]`;
      victimCacheText.style.color = '#34d399';
      gatewayCacheText.textContent = `192.168.1.100 => 00:11:22:33:44:55 [AUTHENTIC HOST]`;
      gatewayCacheText.style.color = '#34d399';
    }

    // 3. 10-Point Zero-Trust Layer 2 FHS Audit
    const audit = ArpSecurityAuditor.auditConfiguration({
      daiVlans: currentConfig.daiVlans,
      trunkTrustEnabled: currentConfig.trunkTrustEnabled,
      edgePortsUntrusted: currentConfig.edgePortsUntrusted,
      validateSrcMac: currentConfig.validateSrcMac,
      validateDstMac: currentConfig.validateDstMac,
      validateIp: currentConfig.validateIp,
      arpRateLimitPps: currentConfig.arpRateLimitPps,
      errdisableRecoveryEnabled: currentConfig.errdisableRecoveryEnabled,
      staticArpAclConfigured: currentConfig.staticArpAclConfigured,
      dhcpSnoopingActive: currentConfig.dhcpSnoopingActive,
      loggingBufferTuned: currentConfig.loggingBufferTuned,
      stormControlEnabled: currentConfig.stormControlEnabled
    });

    auditScoreText.textContent = `${audit.score} / 100 Points`;
    auditGradeCircle.textContent = audit.grade;
    auditGradeCircle.className = `grade-circle grade-${audit.grade.toLowerCase().replace('+', 'plus')}`;
    auditScoreBar.style.width = `${audit.score}%`;

    if (audit.passed) {
      auditScoreBar.style.background = 'var(--primary-emerald)';
      auditComplianceText.textContent = 'Zero-Trust Hardened';
      auditComplianceText.style.color = 'var(--primary-emerald)';
      auditStatusBadge.textContent = 'PASSING';
      auditStatusBadge.className = 'badge badge-emerald';
    } else {
      auditScoreBar.style.background = 'var(--primary-rose)';
      auditComplianceText.textContent = 'Non-Compliant / Audit Failure';
      auditComplianceText.style.color = 'var(--primary-rose)';
      auditStatusBadge.textContent = 'CRITICAL FAILS';
      auditStatusBadge.className = 'badge badge-rose';
    }

    // Render findings
    findingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = `finding-item ${f.level.toLowerCase()}`;
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 0.2rem;">
          <span>[${f.level}] ${f.id} - ${f.title}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxPoints} pts</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.78rem;">${f.finding}</div>
      `;
      findingsContainer.appendChild(div);
    });

    // 4. Update Synthesizer Output
    renderSynthesizerConfig();
  }

  function renderSynthesizerConfig() {
    const synthParams = {
      daiVlans: currentConfig.daiVlans || '10,20,100',
      arpRateLimitPps: currentConfig.arpRateLimitPps || 15,
      staticArpAclConfigured: currentConfig.staticArpAclConfigured,
      staticIp: '192.168.1.10',
      staticMac: '0050.56a1.b2c3'
    };

    let text = '';
    if (activeTab === 'cisco-ios') {
      text = ArpConfigSynthesizer.synthesizeCiscoIosXe(synthParams);
    } else if (activeTab === 'cisco-nxos') {
      text = ArpConfigSynthesizer.synthesizeCiscoNxos(synthParams);
    } else if (activeTab === 'arista') {
      text = ArpConfigSynthesizer.synthesizeArista(synthParams);
    } else if (activeTab === 'juniper') {
      text = ArpConfigSynthesizer.synthesizeJunos(synthParams);
    } else if (activeTab === 'linux') {
      text = ArpConfigSynthesizer.synthesizeLinux(synthParams);
    }
    synthesizerOutputBox.textContent = text;
  }

  // Event Listeners
  [selectArpOpcode, inputSenderIp, inputSenderMac, inputTargetIp, inputTargetMac,
   inputEthSrc, inputEthDst, selectDaiState, selectPortTrust, selectValidateSrc,
   selectValidateDst, selectValidateIp, inputRateLimit].forEach(el => {
    el.addEventListener('change', readConfigFromUi);
    el.addEventListener('input', readConfigFromUi);
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        currentConfig = Object.assign({}, PRESETS[presetKey]);
        updateUiFromConfig();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.getAttribute('data-tab');
      renderSynthesizerConfig();
    });
  });

  btnCopyHex.addEventListener('click', () => {
    navigator.clipboard.writeText(hexDissectorBox.textContent).then(() => {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(() => btnCopyHex.textContent = 'Copy Hex', 2000);
    });
  });

  btnCopyConfig.addEventListener('click', () => {
    navigator.clipboard.writeText(synthesizerOutputBox.textContent).then(() => {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(() => btnCopyConfig.textContent = 'Copy Config', 2000);
    });
  });

  btnDownloadPcap.addEventListener('click', () => {
    if (!forgedFrameCache) return;
    const pcapBytes = ArpProtocolEngine.generatePcap(forgedFrameCache);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `arp-frame-op${currentConfig.opcode}-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Initial load
  updateUiFromConfig();
})();
