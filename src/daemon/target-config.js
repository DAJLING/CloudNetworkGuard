const fs = require('fs');
const path = require('path');
const {
  DEFAULT_TARGET_CONTROL_HOSTS,
  DEFAULT_TARGET_HEALTH_HOSTS,
  DEFAULT_TARGET_RULES,
  DEFAULT_TARGET_WEB_PROBE_URL
} = require('../shared/constants');
const { normalizeHost } = require('./rules');
const { defaultDataDir } = require('./store');

const TARGET_CONFIG_FILE = 'target-rules.json';
const STATIC_IP_SKIP_VALUE = '0.0.0.0';

function defaultTargetConfigPath() {
  if (process.env.NETWORK_GUARD_TARGET_CONFIG) return process.env.NETWORK_GUARD_TARGET_CONFIG;
  return path.join(defaultDataDir(), TARGET_CONFIG_FILE);
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function isValidIpv4(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function normalizeStaticResidentialIp(value, { allowEmpty = true } = {}) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    if (allowEmpty) return '';
    throw new Error('STATIC_RESIDENTIAL_IP_REQUIRED');
  }
  if (!isValidIpv4(normalized)) throw new Error('INVALID_STATIC_RESIDENTIAL_IP');
  return normalized;
}

function normalizeAction(action) {
  return String(action || 'GUARD').trim().toUpperCase() === 'ALLOW' ? 'ALLOW' : 'GUARD';
}

function normalizeDomainPattern(pattern) {
  const raw = String(pattern || '').trim();
  let hostLike = raw;
  try {
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(raw)) {
      hostLike = new URL(raw).hostname;
    } else {
      hostLike = raw.split('/')[0];
    }
  } catch {
    hostLike = raw;
  }
  const normalized = normalizeHost(hostLike);
  if (!normalized) return '';
  return normalized;
}

function hostFromPattern(pattern) {
  return normalizeDomainPattern(pattern).replace(/^\*\./, '');
}

function normalizeRule(rule, index) {
  const domainPattern = normalizeDomainPattern(rule && (rule.domainPattern || rule.host || rule.domain));
  if (!domainPattern) return null;

  return {
    id: String((rule && rule.id) || `target-${index + 1}`).trim() || `target-${index + 1}`,
    domainPattern,
    processNames: Array.isArray(rule && rule.processNames) ? rule.processNames.map(String).filter(Boolean) : [],
    action: normalizeAction(rule && rule.action)
  };
}

function normalizeHosts(hosts) {
  if (!Array.isArray(hosts)) return [];
  return unique(hosts.map(hostFromPattern));
}

function deriveHostsFromRules(rules) {
  return unique(
    rules
      .filter((rule) => rule.action === 'GUARD')
      .map((rule) => hostFromPattern(rule.domainPattern))
  );
}

function defaultTargetConfig() {
  return {
    version: 1,
    rules: DEFAULT_TARGET_RULES,
    healthCheckHosts: DEFAULT_TARGET_HEALTH_HOSTS,
    controlHosts: DEFAULT_TARGET_CONTROL_HOSTS,
    firewallHosts: deriveHostsFromRules(DEFAULT_TARGET_RULES),
    webProbeUrl: DEFAULT_TARGET_WEB_PROBE_URL,
    staticResidentialIp: ''
  };
}

function normalizeTargetConfig(raw, filePath) {
  const rules = Array.isArray(raw && raw.rules)
    ? raw.rules.map(normalizeRule).filter(Boolean)
    : DEFAULT_TARGET_RULES.map(normalizeRule).filter(Boolean);
  const derivedHosts = deriveHostsFromRules(rules);
  const healthCheckHosts = normalizeHosts(raw && raw.healthCheckHosts);
  const controlHosts = normalizeHosts(raw && raw.controlHosts);
  const firewallHosts = normalizeHosts(raw && raw.firewallHosts);
  const resolvedHealthHosts = healthCheckHosts.length ? healthCheckHosts : derivedHosts.slice(0, 3);
  const webProbeUrl =
    raw && Object.prototype.hasOwnProperty.call(raw, 'webProbeUrl')
      ? raw.webProbeUrl
      : DEFAULT_TARGET_WEB_PROBE_URL;
  let staticResidentialIp = '';
  let staticResidentialIpError = null;
  try {
    staticResidentialIp = normalizeStaticResidentialIp(raw && raw.staticResidentialIp);
  } catch (error) {
    staticResidentialIpError = error.message || 'INVALID_STATIC_RESIDENTIAL_IP';
  }

  return {
    path: filePath,
    version: Number(raw && raw.version) || 1,
    rules,
    healthCheckHosts: resolvedHealthHosts,
    controlHosts: controlHosts.length ? controlHosts : resolvedHealthHosts.slice(0, 2),
    firewallHosts: firewallHosts.length ? firewallHosts : derivedHosts,
    webProbeUrl: typeof webProbeUrl === 'string' && webProbeUrl.trim() ? webProbeUrl.trim() : null,
    staticResidentialIp,
    staticResidentialIpError,
    error: null,
    loadedAt: new Date().toISOString()
  };
}

class TargetConfigManager {
  constructor({ filePath = defaultTargetConfigPath() } = {}) {
    this.filePath = filePath;
  }

  ensureDefaultFile() {
    if (fs.existsSync(this.filePath)) return;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, `${JSON.stringify(defaultTargetConfig(), null, 2)}\n`);
  }

  load() {
    try {
      this.ensureDefaultFile();
      const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      return normalizeTargetConfig(parsed, this.filePath);
    } catch (error) {
      return {
        ...normalizeTargetConfig(defaultTargetConfig(), this.filePath),
        error: error.message || 'TARGET_CONFIG_LOAD_FAILED'
      };
    }
  }

  readRaw() {
    this.ensureDefaultFile();
    return JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
  }

  saveRaw(raw) {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, `${JSON.stringify(raw, null, 2)}\n`);
  }

  setStaticResidentialIp(value) {
    const staticResidentialIp = normalizeStaticResidentialIp(value);
    const raw = this.readRaw();
    raw.staticResidentialIp = staticResidentialIp;
    this.saveRaw(raw);
    return normalizeTargetConfig(raw, this.filePath);
  }
}

module.exports = {
  STATIC_IP_SKIP_VALUE,
  TARGET_CONFIG_FILE,
  defaultTargetConfig,
  defaultTargetConfigPath,
  deriveHostsFromRules,
  isValidIpv4,
  normalizeStaticResidentialIp,
  normalizeTargetConfig,
  TargetConfigManager
};
