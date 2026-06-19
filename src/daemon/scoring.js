const { CheckReason, NetworkVerdict } = require('../shared/constants');

const BLOCKED_REGION_CODES = new Set(['CN', 'HK', 'MO']);
const CLAUDE_SUPPORTED_REGION_CODES = new Set([
  'AL', 'DZ', 'AD', 'AO', 'AG', 'AR', 'AM', 'AU', 'AT', 'AZ',
  'BS', 'BH', 'BD', 'BB', 'BE', 'BZ', 'BJ', 'BT', 'BO', 'BA',
  'BW', 'BR', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA',
  'TD', 'CL', 'CO', 'KM', 'CG', 'CR', 'CI', 'HR', 'CY',
  'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ',
  'EE', 'SZ', 'FJ', 'FI', 'FR', 'GA', 'GM', 'GE', 'DE',
  'GH', 'GR', 'GD', 'GT', 'GN', 'GW', 'GY', 'HT', 'HN', 'HU',
  'IS', 'IN', 'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO',
  'KZ', 'KE', 'KI', 'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR',
  'LI', 'LT', 'LU', 'MG', 'MW', 'MY', 'MV', 'MT',
  'MP', 'MH', 'MR', 'MU', 'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MA',
  'MZ', 'NA', 'NR', 'NP', 'NL', 'NZ', 'NE', 'NG', 'MK',
  'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH',
  'PL', 'PT', 'QA', 'RO', 'RW', 'KN', 'LC', 'VC', 'WS', 'SM',
  'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI',
  'SB', 'ZA', 'KR', 'ES', 'LK', 'SR', 'SE', 'CH',
  'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TO', 'TT', 'TN', 'TR',
  'TM', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UY', 'UZ', 'VU',
  'VA', 'VN', 'ZM', 'ZW'
]);
const PING0_RISK_SCORE_LIMIT = 30;
const PING0_SHARED_USERS_LIMIT = 100;
const PING0_SOURCE = 'ping0.cc';
const DEFAULT_ENABLED_CHECKS = Object.freeze({
  staticResidentialIp: true,
  ipType: true,
  region: true,
  proxyRisk: true,
  dns: true,
  tcp: true,
  tls: true,
  controlHosts: true,
  webProbe: true,
  environment: true,
  exitBinding: true,
  usageRate: true
});

function normalizeCountryCode(countryCode) {
  const normalized = String(countryCode || 'unknown').trim().toUpperCase();
  return normalized || 'UNKNOWN';
}

function isBlockedRegion(countryCode) {
  const normalized = normalizeCountryCode(countryCode);
  if (normalized === 'UNKNOWN') return false;
  return BLOCKED_REGION_CODES.has(normalized) || !CLAUDE_SUPPORTED_REGION_CODES.has(normalized);
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function hasRequiredPing0RiskData(result) {
  return Boolean(result && isFiniteNumber(result.riskScore) && isFiniteNumber(result.sharedUsersMax));
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
  let ping0Purity = null;
  let sharedUsers = null;
  let sharedUsersMax = null;
  let hasKnownRegion = false;
  let hasBlockedRegion = false;
  let ping0Result = null;

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
      ping0Purity,
      sharedUsers,
      sharedUsersMax,
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
    if (result.source === PING0_SOURCE) {
      ping0Result = result;
      ping0Purity = result.ping0Purity || ping0Purity;
      sharedUsers = result.sharedUsers || sharedUsers;
      if (isFiniteNumber(result.sharedUsersMax)) sharedUsersMax = result.sharedUsersMax;
    }

    if (isBlockedRegion(resultCountryCode)) {
      hasBlockedRegion = true;
    }

    if (result.isProxy || result.isVpn || result.isTor) {
      reasons.add(CheckReason.VPN_OR_PROXY_RISK);
      riskScore += 45;
    }

    if (result.source === PING0_SOURCE && isFiniteNumber(result.riskScore) && result.riskScore > PING0_RISK_SCORE_LIMIT) {
      reasons.add(CheckReason.VPN_OR_PROXY_RISK);
      riskScore += 45;
    }

    if (result.source === PING0_SOURCE && isFiniteNumber(result.sharedUsersMax) && result.sharedUsersMax > PING0_SHARED_USERS_LIMIT) {
      reasons.add(CheckReason.IP_SHARED_USERS_RISK);
      riskScore += 45;
    }

    if (result.isBlacklisted) {
      reasons.add(CheckReason.BLACKLISTED);
      riskScore += 60;
    }

    if (isFiniteNumber(result.riskScore)) {
      riskScore += Math.max(0, Math.min(result.riskScore, 100)) / usable.length;
    }
  }

  if (!hasRequiredPing0RiskData(ping0Result)) {
    reasons.add(CheckReason.IP_RISK_DATA_UNAVAILABLE);
    riskScore += 45;
  }
  if (ipType === 'hosting' || ipType === 'datacenter') {
    reasons.add(CheckReason.DATACENTER_IP);
    riskScore += 45;
  }
  if (ipType !== 'residential') {
    reasons.add(CheckReason.IP_TYPE_UNCONFIRMED);
    riskScore += 25;
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
      ping0Purity,
      sharedUsers,
      sharedUsersMax,
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
    ping0Purity,
    sharedUsers,
    sharedUsersMax,
    sources: providerResults
  };
}

function normalizeEnabledChecks(enabledChecks = {}) {
  return {
    ...DEFAULT_ENABLED_CHECKS,
    ...(enabledChecks || {})
  };
}

function hasProviderDependentCheck(enabledChecks) {
  return Boolean(
    enabledChecks.staticResidentialIp ||
      enabledChecks.ipType ||
      enabledChecks.region ||
      enabledChecks.proxyRisk ||
      enabledChecks.exitBinding
  );
}

function providerReasonsForEnabledChecks(providerScore, enabledChecks) {
  const providerReasons = new Set(providerScore.reasons || []);
  const reasons = [];

  if (hasProviderDependentCheck(enabledChecks) && providerReasons.has(CheckReason.PROVIDER_UNAVAILABLE)) {
    reasons.push(CheckReason.PROVIDER_UNAVAILABLE);
  }
  if (enabledChecks.ipType && providerReasons.has(CheckReason.DATACENTER_IP)) {
    reasons.push(CheckReason.DATACENTER_IP);
  }
  if (enabledChecks.ipType && providerReasons.has(CheckReason.IP_TYPE_UNCONFIRMED)) {
    reasons.push(CheckReason.IP_TYPE_UNCONFIRMED);
  }
  if (enabledChecks.region && providerReasons.has(CheckReason.BLOCKED_REGION)) {
    reasons.push(CheckReason.BLOCKED_REGION);
  }
  if (enabledChecks.proxyRisk && providerReasons.has(CheckReason.VPN_OR_PROXY_RISK)) {
    reasons.push(CheckReason.VPN_OR_PROXY_RISK);
  }
  if (enabledChecks.proxyRisk && providerReasons.has(CheckReason.BLACKLISTED)) {
    reasons.push(CheckReason.BLACKLISTED);
  }
  if (enabledChecks.proxyRisk && providerReasons.has(CheckReason.IP_SHARED_USERS_RISK)) {
    reasons.push(CheckReason.IP_SHARED_USERS_RISK);
  }
  if (enabledChecks.proxyRisk && providerReasons.has(CheckReason.IP_RISK_DATA_UNAVAILABLE)) {
    reasons.push(CheckReason.IP_RISK_DATA_UNAVAILABLE);
  }
  if (
    enabledChecks.proxyRisk &&
    providerScore.verdict === NetworkVerdict.BLOCK &&
    reasons.length === 0 &&
    providerReasons.size === 0 &&
    typeof providerScore.riskScore === 'number' &&
    providerScore.riskScore >= 65
  ) {
    reasons.push(CheckReason.VPN_OR_PROXY_RISK);
  }

  return reasons;
}

function combineVerdicts({
  externalAccess = { ok: true, results: [] },
  providerScore = { verdict: NetworkVerdict.PASS, reasons: [] },
  staticObservation = { verdict: NetworkVerdict.PASS, reason: null },
  environmentScore,
  claudeWebScore,
  bindingScore,
  usageScore,
  enabledChecks = {}
}) {
  const checks = normalizeEnabledChecks(enabledChecks);
  const reasons = [];

  const accessResults = externalAccess.results || [];
  if (checks.dns && accessResults.some((result) => result.dns && !result.dns.ok)) reasons.push(CheckReason.DNS_CHECK_FAILED);
  if (
    checks.tcp &&
    accessResults.some((result) => result.tcp && !result.tcp.ok && (!result.dns || result.dns.ok || result.tcp.error !== 'DNS_FAILED'))
  ) {
    reasons.push(CheckReason.TCP_CHECK_FAILED);
  }
  if (
    checks.tls &&
    accessResults.some((result) => result.tls && !result.tls.ok && (!result.tcp || result.tcp.ok || result.tls.error !== 'TCP_FAILED'))
  ) {
    reasons.push(CheckReason.TLS_CHECK_FAILED);
  }
  if (checks.controlHosts && externalAccess.claudeControlOk === false) {
    reasons.push(CheckReason.CLAUDE_CONTROL_CHECK_FAILED);
  }

  const externalAccessEnabled = checks.dns || checks.tcp || checks.tls || checks.controlHosts;
  if (externalAccessEnabled && !externalAccess.ok) reasons.push(CheckReason.NO_EXTERNAL_ACCESS);
  const enabledProviderReasons = providerReasonsForEnabledChecks(providerScore, checks);
  reasons.push(...enabledProviderReasons);
  if (checks.staticResidentialIp && staticObservation.reason) reasons.push(staticObservation.reason);
  if (checks.environment && environmentScore && environmentScore.reasons) reasons.push(...environmentScore.reasons);
  if (checks.webProbe && claudeWebScore && claudeWebScore.reasons) reasons.push(...claudeWebScore.reasons);
  if (checks.exitBinding && bindingScore && bindingScore.reasons) reasons.push(...bindingScore.reasons);
  if (checks.usageRate && usageScore && usageScore.reasons) reasons.push(...usageScore.reasons);

  if (
    (externalAccessEnabled && !externalAccess.ok) ||
    enabledProviderReasons.length > 0 ||
    (checks.staticResidentialIp && staticObservation && staticObservation.verdict === NetworkVerdict.BLOCK) ||
    (checks.environment && environmentScore && environmentScore.verdict === NetworkVerdict.BLOCK) ||
    (checks.webProbe && claudeWebScore && claudeWebScore.verdict === NetworkVerdict.BLOCK) ||
    (checks.exitBinding && bindingScore && bindingScore.verdict === NetworkVerdict.BLOCK) ||
    (checks.usageRate && usageScore && usageScore.verdict === NetworkVerdict.BLOCK)
  ) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reasons: Array.from(new Set(reasons)),
      allowTargetTraffic: false
    };
  }

  if (checks.staticResidentialIp && staticObservation.verdict === NetworkVerdict.OBSERVING) {
    return {
      verdict: NetworkVerdict.OBSERVING,
      reasons: Array.from(new Set(reasons)),
      allowTargetTraffic: false
    };
  }

  if (checks.ipType && providerScore.verdict === NetworkVerdict.WARN) {
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
  PING0_RISK_SCORE_LIMIT,
  PING0_SHARED_USERS_LIMIT,
  normalizeCountryCode,
  isBlockedRegion,
  scoreProviderResults,
  normalizeEnabledChecks,
  providerReasonsForEnabledChecks,
  combineVerdicts
};
