const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  TargetConfigManager,
  DEFAULT_VALIDATION_CHECKS,
  deriveHostsFromRules,
  hasEnabledValidationChecks,
  normalizeStaticResidentialIp,
  normalizeTargetConfig,
  resolveValidationHosts,
  defaultValidation
} = require('../src/daemon/target-config');

test('TargetConfigManager writes a default editable config file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  const config = manager.load();

  assert.equal(fs.existsSync(filePath), true);
  assert.equal(config.rules.some((rule) => rule.domainPattern === 'claude.ai'), true);
  assert.equal(config.rules.some((rule) => rule.domainPattern === '*.anthropic.com'), true);
  assert.equal(config.firewallHosts.includes('claude.ai'), true);
  assert.equal(config.staticResidentialIp, '');
  assert.deepEqual(config.validation.checks, DEFAULT_VALIDATION_CHECKS);
});

test('normalizeTargetConfig supports user-added and removed target rules', () => {
  const config = normalizeTargetConfig(
    {
      version: 1,
      rules: [
        { id: 'custom-api', domainPattern: 'https://api.anthropic.com/v1/messages', action: 'GUARD' },
        { id: 'custom-web', domainPattern: '*.claude.ai', action: 'GUARD' }
      ],
      healthCheckHosts: ['api.anthropic.com'],
      controlHosts: ['api.anthropic.com']
    },
    'fixture.json'
  );

  assert.deepEqual(
    config.rules.map((rule) => rule.domainPattern),
    ['api.anthropic.com', '*.claude.ai']
  );
  assert.deepEqual(config.healthCheckHosts, ['api.anthropic.com']);
  assert.deepEqual(config.controlHosts, ['api.anthropic.com']);
  assert.equal(config.firewallHosts.includes('claude.ai'), true);
});

test('deriveHostsFromRules converts wildcard rules into firewall host candidates', () => {
  assert.deepEqual(
    deriveHostsFromRules([
      { domainPattern: '*.anthropic.com', action: 'GUARD' },
      { domainPattern: 'claude.ai', action: 'GUARD' },
      { domainPattern: 'status.anthropic.com', action: 'ALLOW' }
    ]),
    ['anthropic.com', 'claude.ai']
  );
});

test('TargetConfigManager validates and saves static residential IP', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });

  assert.equal(manager.setStaticResidentialIp('203.0.113.10').staticResidentialIp, '203.0.113.10');
  assert.equal(manager.setStaticResidentialIp('0.0.0.0').staticResidentialIp, '0.0.0.0');
  assert.throws(() => manager.setStaticResidentialIp('999.1.1.1'), /INVALID_STATIC_RESIDENTIAL_IP/);
});

test('resolveValidationHosts supports Claude-only validation', () => {
  const resolved = resolveValidationHosts({
    services: { claude: true },
    webProbe: { enabled: true, url: 'https://claude.ai/' },
    useCustomHosts: false
  });

  assert.deepEqual(resolved.healthCheckHosts, ['claude.ai', 'api.anthropic.com']);
  assert.deepEqual(resolved.controlHosts, ['claude.ai', 'api.anthropic.com']);
  assert.equal(resolved.webProbeUrl, 'https://claude.ai/');
});

test('resolveValidationHosts allows non-target checks without selected services', () => {
  const resolved = resolveValidationHosts({
    services: { claude: false },
    checks: {
      ...DEFAULT_VALIDATION_CHECKS,
      dns: false,
      tcp: false,
      tls: false,
      controlHosts: false
    },
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  assert.deepEqual(resolved.healthCheckHosts, []);
  assert.deepEqual(resolved.controlHosts, []);
  assert.equal(hasEnabledValidationChecks(resolved.validation), true);
});

test('resolveValidationHosts supports saving all validation checks disabled', () => {
  const resolved = resolveValidationHosts({
    services: { claude: false },
    checks: Object.fromEntries(Object.keys(DEFAULT_VALIDATION_CHECKS).map((key) => [key, false])),
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  assert.deepEqual(resolved.healthCheckHosts, []);
  assert.deepEqual(resolved.controlHosts, []);
  assert.equal(resolved.webProbeUrl, null);
  assert.equal(hasEnabledValidationChecks(resolved.validation), false);
});

test('TargetConfigManager saves and resets validation config', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  manager.load();

  const saved = manager.saveValidation({
    services: { claude: true },
    webProbe: { enabled: true, url: 'https://claude.ai/' },
    useCustomHosts: false
  });
  assert.deepEqual(saved.validation.services, { claude: true });
  assert.deepEqual(saved.healthCheckHosts, ['claude.ai', 'api.anthropic.com']);

  const reset = manager.resetValidationToDefaults();
  assert.deepEqual(reset.validation.services, defaultValidation().services);
  assert.deepEqual(reset.healthCheckHosts, ['claude.ai', 'api.anthropic.com']);
});

test('TargetConfigManager saves editable target rules and derives firewall hosts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  manager.load();

  const saved = manager.saveRules([
    { id: 'custom-api', domainPattern: 'https://api.anthropic.com/v1', action: 'GUARD' },
    { id: 'allowed-status', domainPattern: 'status.anthropic.com', action: 'ALLOW' },
    { id: 'wildcard', domainPattern: '*.claude.ai', action: 'GUARD' }
  ]);

  assert.deepEqual(saved.rules.map((rule) => rule.domainPattern), ['api.anthropic.com', 'status.anthropic.com', '*.claude.ai']);
  assert.deepEqual(saved.firewallHosts, ['api.anthropic.com', 'claude.ai']);
  assert.equal(saved.rules[1].action, 'ALLOW');
});

test('TargetConfigManager rejects targets outside Claude and Anthropic', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const manager = new TargetConfigManager({ filePath: path.join(tmp, 'target-rules.json') });
  manager.load();

  assert.throws(
    () => manager.saveRules([{ id: 'other', domainPattern: 'api.example.com', action: 'GUARD' }]),
    /CLAUDE_TARGET_REQUIRED/
  );
});

test('normalizeTargetConfig removes legacy non-Claude targets', () => {
  const config = normalizeTargetConfig(
    {
      version: 1,
      rules: [
        { id: 'claude-web', domainPattern: 'claude.ai', action: 'GUARD' },
        { id: 'legacy-other', domainPattern: 'api.example.com', action: 'GUARD' }
      ],
      healthCheckHosts: ['claude.ai', 'api.example.com'],
      firewallHosts: ['claude.ai', 'api.example.com']
    },
    'fixture.json'
  );

  assert.deepEqual(config.rules.map((rule) => rule.domainPattern), ['claude.ai']);
  assert.deepEqual(config.healthCheckHosts, ['claude.ai']);
  assert.deepEqual(config.firewallHosts, ['claude.ai']);
});

test('TargetConfigManager rejects empty editable target rules', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const manager = new TargetConfigManager({ filePath: path.join(tmp, 'target-rules.json') });
  manager.load();

  assert.throws(() => manager.saveRules([]), /TARGET_RULES_REQUIRED/);
});

test('TargetConfigManager resetToDefaults restores factory target config', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  manager.saveValidation({
    services: { claude: true },
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  const reset = manager.resetToDefaults();
  assert.equal(reset.validation.services.claude, true);
  assert.deepEqual(reset.rules.map((rule) => rule.domainPattern), [
    '*.anthropic.com',
    'claude.ai',
    '*.claude.ai'
  ]);
});

test('normalizeStaticResidentialIp supports empty values for first-run setup', () => {
  assert.equal(normalizeStaticResidentialIp(''), '');
  assert.equal(normalizeStaticResidentialIp(' 0.0.0.0 '), '0.0.0.0');
  assert.throws(() => normalizeStaticResidentialIp('', { allowEmpty: false }), /STATIC_RESIDENTIAL_IP_REQUIRED/);
});
