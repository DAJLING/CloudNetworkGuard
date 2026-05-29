const { CheckReason, NetworkVerdict } = require('../shared/constants');

const BLOCKED_REGION_CODES = new Set(['CN', 'HK', 'MO']);

function normalizeCountryCode(countryCode) {
  const normalized = String(countryCode || 'unknown').trim().toUpperCase();
  return normalized || 'UNKNOWN';
}

function isBlockedRegion(countryCode) {
  return BLOCKED_REGION_CODES.has(normalizeCountryCode(countryCode));
}

function scoreProviderResults(providerResults) {
  const usable = providerResults.filter((result) => result && !result.error);
  const reasons = new Set();
  let riskScore = 0;
  let confidence = 0;
  let ip = null;
  let ipType = 'unknown';
  let asn = null;
  let countryCode = 'unknown';
  let regionName = 'unknown';
  let hasKnownRegion = false;
  let hasBlockedRegion = false;

  if (usable.length === 0) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reasons: [CheckReason.PROVIDER_UNAVAILABLE],
      riskScore: 100,
      confidence: 0,
      ip: null,
      ipType,
      asn,
      countryCode,
      regionName,
      sources: providerResults
    };
  }

  for (const result of usable) {
    ip = ip || result.ip || null;
    asn = asn || result.asn || null;
    confidence += result.confidence || 20;

    if (result.ipType && result.ipType !== 'unknown') ipType = result.ipType;
    const resultCountryCode = normalizeCountryCode(result.countryCode);
    if (resultCountryCode !== 'UNKNOWN') {
      hasKnownRegion = true;
      countryCode = resultCountryCode;
    }
    if (result.regionName && result.regionName !== 'unknown') regionName = result.regionName;

    if (isBlockedRegion(resultCountryCode)) {
      hasBlockedRegion = true;
    }

    if (result.ipType === 'hosting' || result.ipType === 'datacenter') {
      reasons.add(CheckReason.DATACENTER_IP);
      riskScore += 45;
    }

    if (result.isProxy || result.isVpn || result.isTor) {
      reasons.add(CheckReason.VPN_OR_PROXY_RISK);
      riskScore += 45;
    }

    if (result.isBlacklisted) {
      reasons.add(CheckReason.BLACKLISTED);
      riskScore += 60;
    }

    if (typeof result.riskScore === 'number') {
      riskScore += Math.max(0, Math.min(result.riskScore, 100)) / usable.length;
    }
  }

  confidence = Math.min(100, confidence);
  if (hasBlockedRegion || !hasKnownRegion) {
    reasons.add(CheckReason.BLOCKED_REGION);
    riskScore += 100;
    if (!hasKnownRegion) {
      countryCode = 'UNKNOWN';
      regionName = 'unknown';
    }
  }
  riskScore = Math.min(100, Math.round(riskScore));

  if (reasons.size > 0 || riskScore >= 65) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reasons: Array.from(reasons),
      riskScore,
      confidence,
      ip,
      ipType,
      asn,
      countryCode,
      regionName,
      sources: providerResults
    };
  }

  if (ipType !== 'residential') {
    return {
      verdict: NetworkVerdict.WARN,
      reasons: [],
      riskScore,
      confidence,
      ip,
      ipType,
      asn,
      countryCode,
      regionName,
      sources: providerResults
    };
  }

  return {
    verdict: NetworkVerdict.PASS,
    reasons: [],
    riskScore,
    confidence,
    ip,
    ipType,
    asn,
    countryCode,
    regionName,
    sources: providerResults
  };
}

function combineVerdicts({ externalAccess, providerScore, staticObservation, environmentScore, claudeWebScore, bindingScore, usageScore }) {
  const reasons = [];

  const accessResults = externalAccess.results || [];
  if (accessResults.some((result) => result.dns && !result.dns.ok)) reasons.push(CheckReason.DNS_CHECK_FAILED);
  if (accessResults.some((result) => result.dns && result.dns.ok && result.tcp && !result.tcp.ok)) {
    reasons.push(CheckReason.TCP_CHECK_FAILED);
  }
  if (accessResults.some((result) => result.tcp && result.tcp.ok && result.tls && !result.tls.ok)) {
    reasons.push(CheckReason.TLS_CHECK_FAILED);
  }
  if (externalAccess.claudeControlOk === false) reasons.push(CheckReason.CLAUDE_CONTROL_CHECK_FAILED);
  if (!externalAccess.ok) reasons.push(CheckReason.NO_EXTERNAL_ACCESS);
  reasons.push(...(providerScore.reasons || []));
  if (staticObservation.reason) reasons.push(staticObservation.reason);
  if (environmentScore && environmentScore.reasons) reasons.push(...environmentScore.reasons);
  if (claudeWebScore && claudeWebScore.reasons) reasons.push(...claudeWebScore.reasons);
  if (bindingScore && bindingScore.reasons) reasons.push(...bindingScore.reasons);
  if (usageScore && usageScore.reasons) reasons.push(...usageScore.reasons);

  if (
    !externalAccess.ok ||
    providerScore.verdict === NetworkVerdict.BLOCK ||
    (staticObservation && staticObservation.verdict === NetworkVerdict.BLOCK) ||
    (environmentScore && environmentScore.verdict === NetworkVerdict.BLOCK) ||
    (claudeWebScore && claudeWebScore.verdict === NetworkVerdict.BLOCK) ||
    (bindingScore && bindingScore.verdict === NetworkVerdict.BLOCK) ||
    (usageScore && usageScore.verdict === NetworkVerdict.BLOCK)
  ) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reasons: Array.from(new Set(reasons)),
      allowTargetTraffic: false
    };
  }

  if (staticObservation.verdict === NetworkVerdict.OBSERVING) {
    return {
      verdict: NetworkVerdict.OBSERVING,
      reasons: Array.from(new Set(reasons)),
      allowTargetTraffic: false
    };
  }

  if (providerScore.verdict === NetworkVerdict.WARN) {
    return {
      verdict: NetworkVerdict.WARN,
      reasons: Array.from(new Set(reasons)),
      allowTargetTraffic: true
    };
  }

  return {
    verdict: NetworkVerdict.PASS,
    reasons: Array.from(new Set(reasons)),
    allowTargetTraffic: true
  };
}

module.exports = {
  BLOCKED_REGION_CODES,
  normalizeCountryCode,
  isBlockedRegion,
  scoreProviderResults,
  combineVerdicts
};
