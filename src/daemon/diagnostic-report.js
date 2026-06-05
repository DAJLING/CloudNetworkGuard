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
  return {
    rules: Array.isArray(targetConfig.rules) ? targetConfig.rules.length : 0,
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
    targetConfig: summarizeTargetConfig(status.targetConfig || check.targets || {}),
    environmentConsistency: summarizeEnvironmentConsistency(status.environmentConsistency || {})
  };
}

module.exports = {
  buildDiagnosticReport
};
