const fs = require('fs');
const path = require('path');
const {
  DEFAULT_TARGET_CONTROL_HOSTS,
  DEFAULT_TARGET_HEALTH_HOSTS,
  DEFAULT_TARGET_RULES,
  DEFAULT_TARGET_WEB_PROBE_URL,
  VALIDATION_SERVICES
} = require('../shared/constants');
const { normalizeHost } = require('./rules');
const { defaultDataDir } = require('./store');

const TARGET_CONFIG_FILE = 'target-rules.json';
const STATIC_IP_SKIP_VALUE = '0.0.0.0';
const CLAUDE_TARGET_SUFFIXES = Object.freeze(['claude.ai', 'anthropic.com']);

const DEFAULT_VALIDATION_CHECKS = Object.freeze({
  staticResidentialIp: true,
  ipType: true,
  region: true,
  proxyRisk: true,
  dns: true,
  tcp: true,
  tls: true,
  controlHosts: true,
  environment: true,
  exitBinding: true,
  usageRate: true
});

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

function isClaudeHost(host) {
  const normalized = normalizeHost(host).replace(/^\*\./, '');
  return CLAUDE_TARGET_SUFFIXES.some(
    (suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`)
  );
}

function normalizeRule(rule, index) {
  const domainPattern = normalizeDomainPattern(rule && (rule.domainPattern || rule.host || rule.domain));
  if (!domainPattern || !isClaudeHost(domainPattern)) return null;

  return {
    id: String((rule && rule.id) || `target-${index + 1}`).trim() || `target-${index + 1}`,
    domainPattern,
    processNames: Array.isArray(rule && rule.processNames) ? rule.processNames.map(String).filter(Boolean) : [],
    action: normalizeAction(rule && rule.action)
  };
}

function normalizeHosts(hosts) {
  if (!Array.isArray(hosts)) return [];
  return unique(hosts.map(hostFromPattern).filter(isClaudeHost));
}

function normalizeWebProbeUrl(value) {
  try {
    const url = new URL(String(value || '').trim());
    if ((url.protocol === 'https:' || url.protocol === 'http:') && isClaudeHost(url.hostname)) {
      return url.toString();
    }
  } catch {
    // Fall through to the Claude default.
  }
  return DEFAULT_TARGET_WEB_PROBE_URL;
}

function deriveHostsFromRules(rules) {
  return unique(
    rules
      .filter((rule) => rule.action === 'GUARD')
      .map((rule) => hostFromPattern(rule.domainPattern))
  );
}

function defaultValidation() {
  return {
    services: { claude: true },
    checks: { ...DEFAULT_VALIDATION_CHECKS },
    webProbe: { enabled: true, url: DEFAULT_TARGET_WEB_PROBE_URL },
    useCustomHosts: false,
    customHealthCheckHosts: [],
    customControlHosts: []
  };
}

function normalizeValidationChecks(rawChecks) {
  const input = rawChecks && typeof rawChecks === 'object' ? rawChecks : {};
  return Object.fromEntries(
    Object.keys(DEFAULT_VALIDATION_CHECKS).map((checkId) => [checkId, input[checkId] !== false])
  );
}

function normalizeValidation(raw) {
  if (!raw || typeof raw !== 'object') {
    return defaultValidation();
  }

  const services = raw.services && typeof raw.services === 'object' ? raw.services : {};
  const webProbe = raw.webProbe && typeof raw.webProbe === 'object' ? raw.webProbe : {};
  const customHealthCheckHosts = normalizeHosts(raw.customHealthCheckHosts);
  const customControlHosts = normalizeHosts(raw.customControlHosts);

  return {
    services: {
      claude: services.claude !== false
    },
    checks: normalizeValidationChecks(raw.checks),
    webProbe: {
      enabled: webProbe.enabled !== false,
      url: normalizeWebProbeUrl(webProbe.url)
    },
    useCustomHosts: raw.useCustomHosts === true,
    customHealthCheckHosts,
    customControlHosts
  };
}

function legacyValidationFromRaw(raw) {
  const hasExplicitHosts = Array.isArray(raw.healthCheckHosts) && raw.healthCheckHosts.length > 0;
  if (!hasExplicitHosts) return null;

  return {
    ...defaultValidation(),
    useCustomHosts: true,
    customHealthCheckHosts: normalizeHosts(raw.healthCheckHosts),
    customControlHosts: normalizeHosts(raw.controlHosts),
    webProbe: {
      enabled: Boolean(raw.webProbeUrl),
      url: normalizeWebProbeUrl(raw.webProbeUrl)
    }
  };
}

function hasTargetValidationChecks(validation) {
  const normalized = normalizeValidation(validation);
  return Boolean(
    normalized.checks.dns ||
      normalized.checks.tcp ||
      normalized.checks.tls ||
      normalized.checks.controlHosts
  );
}

function hasEnabledValidationChecks(validation) {
  const normalized = normalizeValidation(validation);
  return Boolean(
    normalized.webProbe.enabled ||
      Object.values(normalized.checks).some(Boolean)
  );
}

function resolveValidationHosts(validation) {
  const normalized = normalizeValidation(validation);
  const needsTargetHosts = hasTargetValidationChecks(normalized);

  if (needsTargetHosts && !normalized.useCustomHosts && !normalized.services.claude) {
    throw new Error('VALIDATION_SERVICE_REQUIRED');
  }

  if (normalized.useCustomHosts) {
    const healthCheckHosts = normalized.customHealthCheckHosts;
    const controlHosts = normalized.customControlHosts.length
      ? normalized.customControlHosts
      : healthCheckHosts.slice();
    if (needsTargetHosts && !healthCheckHosts.length) {
      throw new Error('VALIDATION_CUSTOM_HOSTS_REQUIRED');
    }
    return {
      validation: normalized,
      healthCheckHosts: needsTargetHosts ? healthCheckHosts : [],
      controlHosts: needsTargetHosts ? controlHosts : [],
      webProbeUrl: normalized.webProbe.enabled ? normalized.webProbe.url : null
    };
  }

  const healthCheckHosts = [];
  const controlHosts = [];
  if (needsTargetHosts && normalized.services.claude) {
    healthCheckHosts.push(...VALIDATION_SERVICES.claude.healthCheckHosts);
    controlHosts.push(...VALIDATION_SERVICES.claude.controlHosts);
  }
  let webProbeUrl = null;
  if (normalized.webProbe.enabled) {
    webProbeUrl = normalized.webProbe.url || VALIDATION_SERVICES.claude.defaultWebProbeUrl;
  }

  return {
    validation: normalized,
    healthCheckHosts: unique(healthCheckHosts),
    controlHosts: unique(controlHosts),
    webProbeUrl
  };
}

function defaultTargetConfig() {
  const validation = defaultValidation();
  const resolved = resolveValidationHosts(validation);
  return {
    version: 1,
    rules: DEFAULT_TARGET_RULES,
    validation: resolved.validation,
    healthCheckHosts: resolved.healthCheckHosts,
    controlHosts: resolved.controlHosts,
    firewallHosts: deriveHostsFromRules(DEFAULT_TARGET_RULES),
    webProbeUrl: resolved.webProbeUrl,
    staticResidentialIp: ''
  };
}

function normalizeTargetConfig(raw, filePath) {
  const normalizedRules = Array.isArray(raw && raw.rules)
    ? raw.rules.map(normalizeRule).filter(Boolean)
    : DEFAULT_TARGET_RULES.map(normalizeRule).filter(Boolean);
  const rules = normalizedRules.length
    ? normalizedRules
    : DEFAULT_TARGET_RULES.map(normalizeRule).filter(Boolean);
  const derivedHosts = deriveHostsFromRules(rules);
  const firewallHosts = normalizeHosts(raw && raw.firewallHosts);

  let validation = raw && raw.validation ? normalizeValidation(raw.validation) : legacyValidationFromRaw(raw || {});
  if (!validation) validation = defaultValidation();

  let resolvedHosts;
  let validationError = null;
  try {
    resolvedHosts = resolveValidationHosts(validation);
  } catch (error) {
    validationError = error.message || 'VALIDATION_CONFIG_INVALID';
    resolvedHosts = resolveValidationHosts(defaultValidation());
  }

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
    validation: resolvedHosts.validation,
    healthCheckHosts: resolvedHosts.healthCheckHosts,
    controlHosts: resolvedHosts.controlHosts,
    firewallHosts: firewallHosts.length ? firewallHosts : derivedHosts,
    webProbeUrl: resolvedHosts.webProbeUrl,
    staticResidentialIp,
    staticResidentialIpError,
    validationError,
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

  applyResolvedValidation(raw, validationInput) {
    const resolved = resolveValidationHosts(validationInput);
    raw.validation = resolved.validation;
    raw.healthCheckHosts = resolved.healthCheckHosts;
    raw.controlHosts = resolved.controlHosts;
    raw.webProbeUrl = resolved.webProbeUrl;
    return resolved;
  }

  saveValidation(validationInput) {
    const raw = this.readRaw();
    this.applyResolvedValidation(raw, validationInput);
    this.saveRaw(raw);
    return normalizeTargetConfig(raw, this.filePath);
  }

  saveRules(rulesInput) {
    const normalizedRules = Array.isArray(rulesInput)
      ? rulesInput.map(normalizeRule).filter(Boolean)
      : [];
    if (Array.isArray(rulesInput) && normalizedRules.length !== rulesInput.length) {
      throw new Error('CLAUDE_TARGET_REQUIRED');
    }
    if (!normalizedRules.length) throw new Error('TARGET_RULES_REQUIRED');

    const ids = new Set();
    for (const rule of normalizedRules) {
      if (ids.has(rule.id)) throw new Error('TARGET_RULE_IDS_DUPLICATE');
      ids.add(rule.id);
    }

    const raw = this.readRaw();
    raw.rules = normalizedRules;
    raw.firewallHosts = deriveHostsFromRules(normalizedRules);
    this.saveRaw(raw);
    return normalizeTargetConfig(raw, this.filePath);
  }

  resetValidationToDefaults() {
    const raw = this.readRaw();
    this.applyResolvedValidation(raw, defaultValidation());
    this.saveRaw(raw);
    return normalizeTargetConfig(raw, this.filePath);
  }

  resetToDefaults() {
    this.saveRaw(defaultTargetConfig());
    return normalizeTargetConfig(this.readRaw(), this.filePath);
  }
}

module.exports = {
  DEFAULT_VALIDATION_CHECKS,
  CLAUDE_TARGET_SUFFIXES,
  STATIC_IP_SKIP_VALUE,
  TARGET_CONFIG_FILE,
  defaultTargetConfig,
  defaultTargetConfigPath,
  defaultValidation,
  deriveHostsFromRules,
  hasEnabledValidationChecks,
  hasTargetValidationChecks,
  isClaudeHost,
  isValidIpv4,
  normalizeStaticResidentialIp,
  normalizeTargetConfig,
  normalizeValidation,
  normalizeWebProbeUrl,
  resolveValidationHosts,
  TargetConfigManager,
  VALIDATION_SERVICES
};
