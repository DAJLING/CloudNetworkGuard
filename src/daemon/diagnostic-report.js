function sanitizeProvider(provider = {}) {
  return {
    source: provider.source || 'unknown',
    error: provider.error || null,
    ipType: provider.ipType || null,
    countryCode: provider.countryCode || null,
    regionName: provider.regionName || null,
    asn: provider.asn || null,
    riskScore: typeof provider.riskScore === 'number' ? provider.riskScore : null,
    confidence: typeof provider.confidence === 'number' ? provider.confidence : null
  };
}

function summarizeEnvironmentConsistency(environmentConsistency = {}) {
  const backup = environmentConsistency.backup || {};
  return {
    supported: environmentConsistency.supported === true,
    enabled: Boolean(environmentConsistency.enabled),
    deriveFromExitIp: environmentConsistency.deriveFromExitIp !== false,
    lastTargetProfile: environmentConsistency.lastTargetProfile || null,
    backup: {
      hasBackup: Boolean(backup.hasBackup),
      createdAt: backup.createdAt || null
    },
    lastApplyResult: environmentConsistency.lastApplyResult
      ? { ok: environmentConsistency.lastApplyResult.ok === true, at: environmentConsistency.lastApplyResult.at || null }
      : null,
    lastRestoreResult: environmentConsistency.lastRestoreResult
      ? { ok: environmentConsistency.lastRestoreResult.ok === true, at: environmentConsistency.lastRestoreResult.at || null }
      : null,
    pendingPostApplyCheck: Boolean(environmentConsistency.pendingPostApplyCheck)
  };
}

function summarizeTargetConfig(targetConfig = {}) {
  const staticResidentialIp = targetConfig.staticResidentialIp
    ? targetConfig.staticResidentialIp === '0.0.0.0'
      ? 'skipped'
      : 'configured'
    : 'missing';
  const validation = targetConfig.validation || {};
  const rules = Array.isArray(targetConfig.rules) ? targetConfig.rules : [];
  const guardedRules = rules.filter((rule) => rule.action !== 'ALLOW');
  const allowedRules = rules.filter((rule) => rule.action === 'ALLOW');
  return {
    rules: rules.length,
    rulePreview: {
      total: rules.length,
      guarded: guardedRules.length,
      allowed: allowedRules.length,
      guardedDomains: guardedRules.map((rule) => rule.domainPattern).filter(Boolean).slice(0, 20),
      allowedDomains: allowedRules.map((rule) => rule.domainPattern).filter(Boolean).slice(0, 20)
    },
    validation: {
      services: validation.services || {},
      webProbe: validation.webProbe || null,
      useCustomHosts: Boolean(validation.useCustomHosts)
    },
    healthCheckHosts: targetConfig.healthCheckHosts || [],
    controlHosts: targetConfig.controlHosts || [],
    webProbeUrl: targetConfig.webProbeUrl || null,
    staticResidentialIp
  };
}

function summarizeMonitoring(monitoring = {}) {
  return {
    enabled: monitoring.enabled === true,
    intervalMinutes: Number(monitoring.intervalMinutes) || 15,
    running: monitoring.running === true,
    lastRunAt: monitoring.lastRunAt || null,
    lastResult: monitoring.lastResult
      ? {
          verdict: monitoring.lastResult.verdict || 'UNKNOWN',
          reasons: Array.isArray(monitoring.lastResult.reasons) ? monitoring.lastResult.reasons : [],
          checkedAt: monitoring.lastResult.checkedAt || null
        }
      : null,
    lastError: monitoring.lastError || null
  };
}

function summarizePlatformCapabilities(status = {}) {
  const os = status.platform && status.platform.os ? status.platform.os : process.platform;
  const firewallMode = status.firewall && status.firewall.mode ? status.firewall.mode : '';
  const firewallFallback =
    os === 'darwin' || firewallMode.startsWith('PF_')
      ? 'macos-pf'
      : os === 'win32'
        ? 'windows-netsh'
        : 'unsupported';
  return {
    os,
    environmentConsistency: status.environmentConsistency && status.environmentConsistency.supported === true,
    firewallFallback
  };
}

function buildSafetyNotes(status = {}) {
  const notes = [];
  const mode = status.firewall && status.firewall.mode ? status.firewall.mode : '';
  const os = status.platform && status.platform.os ? status.platform.os : process.platform;
  if (os === 'darwin' || mode.startsWith('PF_')) {
    notes.push('macOS pf fallback uses an app-owned anchor and a marked pf.conf block.');
    notes.push('Emergency restore removes managed proxy, firewall, hosts, and environment changes where possible.');
  }
  if (mode === 'PARTIAL_BLOCK' || mode === 'PARTIAL_CLEAR') {
    notes.push('Firewall fallback is partial; run Emergency restore before retrying privileged changes.');
  }
  return notes;
}

function buildDiagnosticReport(status = {}) {
  const check = status.lastCheck || {};
  const ip = check.ip || {};
  return {
    generatedAt: new Date().toISOString(),
    guardState: status.guardState || 'UNKNOWN',
    checkedAt: check.checkedAt || null,
    verdict: check.verdict || 'UNKNOWN',
    reasons: Array.isArray(check.reasons) ? check.reasons : [],
    allowTargetTraffic: check.allowTargetTraffic === true,
    guidance: status.guidance || null,
    exitIp: {
      maskedIp: ip.maskedIp || null,
      ipType: ip.ipType || null,
      countryCode: ip.countryCode || null,
      regionName: ip.regionName || null,
      asn: ip.asn || null,
      riskScore: typeof ip.riskScore === 'number' ? ip.riskScore : null,
      confidence: typeof ip.confidence === 'number' ? ip.confidence : null
    },
    providers: Array.isArray(check.providers) ? check.providers.map(sanitizeProvider) : [],
    externalAccess: check.externalAccess || null,
    claudeWeb: check.claudeWeb || null,
    environment: check.environment || null,
    binding: status.binding || check.binding || null,
    firewall: status.firewall || null,
    usage: check.usage || null,
    monitoring: summarizeMonitoring(status.monitoring || {}),
    platformCapabilities: summarizePlatformCapabilities(status),
    targetConfig: summarizeTargetConfig(status.targetConfig || check.targets || {}),
    environmentConsistency: summarizeEnvironmentConsistency(status.environmentConsistency || {}),
    safetyNotes: buildSafetyNotes(status)
  };
}

module.exports = {
  buildDiagnosticReport
};
