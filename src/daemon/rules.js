const { DEFAULT_TARGET_RULES } = require('../shared/constants');

function normalizeHost(host) {
  return String(host || '')
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
}

function domainMatches(pattern, host) {
  const normalizedPattern = normalizeHost(pattern);
  const normalizedHost = normalizeHost(host);

  if (!normalizedPattern || !normalizedHost) return false;
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(2);
    return normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`);
  }

  return normalizedHost === normalizedPattern;
}

function isGuardedTarget(host, rules = DEFAULT_TARGET_RULES) {
  const normalizedHost = normalizeHost(host);
  return rules.some((rule) => rule.action === 'GUARD' && domainMatches(rule.domainPattern, normalizedHost));
}

module.exports = {
  normalizeHost,
  domainMatches,
  isGuardedTarget
};
