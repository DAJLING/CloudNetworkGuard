const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  TargetConfigManager,
  deriveHostsFromRules,
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
  assert.equal(config.rules.some((rule) => rule.domainPattern === 'api.openai.com'), true);
  assert.equal(config.firewallHosts.includes('claude.ai'), true);
  assert.equal(config.staticResidentialIp, '');
});

test('normalizeTargetConfig supports user-added and removed target rules', () => {
  const config = normalizeTargetConfig(
    {
      version: 1,
      rules: [
        { id: 'custom-api', domainPattern: 'https://api.example.com/v1/messages', action: 'GUARD' },
        { id: 'custom-web', domainPattern: '*.example.org', action: 'GUARD' }
      ],
      healthCheckHosts: ['api.example.com'],
      controlHosts: ['api.example.com']
    },
    'fixture.json'
  );

  assert.deepEqual(
    config.rules.map((rule) => rule.domainPattern),
    ['api.example.com', '*.example.org']
  );
  assert.deepEqual(config.healthCheckHosts, ['api.example.com']);
  assert.deepEqual(config.controlHosts, ['api.example.com']);
  assert.equal(config.firewallHosts.includes('example.org'), true);
  assert.equal(config.rules.some((rule) => rule.domainPattern === 'claude.ai'), false);
});

test('deriveHostsFromRules converts wildcard rules into firewall host candidates', () => {
  assert.deepEqual(
    deriveHostsFromRules([
      { domainPattern: '*.openai.com', action: 'GUARD' },
      { domainPattern: 'chatgpt.com', action: 'GUARD' },
      { domainPattern: 'ignored.example.com', action: 'ALLOW' }
    ]),
    ['openai.com', 'chatgpt.com']
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
    services: { claude: true, codex: false },
    webProbe: { enabled: true, url: 'https://claude.ai/' },
    useCustomHosts: false
  });

  assert.deepEqual(resolved.healthCheckHosts, ['claude.ai', 'api.anthropic.com']);
  assert.deepEqual(resolved.controlHosts, ['claude.ai', 'api.anthropic.com']);
  assert.equal(resolved.webProbeUrl, 'https://claude.ai/');
});

test('resolveValidationHosts supports Codex-only validation without web probe', () => {
  const resolved = resolveValidationHosts({
    services: { claude: false, codex: true },
    webProbe: { enabled: true, url: 'https://claude.ai/' },
    useCustomHosts: false
  });

  assert.deepEqual(resolved.healthCheckHosts, ['api.openai.com', 'chat.openai.com', 'auth.openai.com']);
  assert.deepEqual(resolved.controlHosts, ['api.openai.com']);
  assert.equal(resolved.webProbeUrl, null);
});

test('TargetConfigManager saves and resets validation config', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  manager.load();

  const saved = manager.saveValidation({
    services: { claude: true, codex: false },
    webProbe: { enabled: true, url: 'https://claude.ai/' },
    useCustomHosts: false
  });
  assert.equal(saved.validation.services.codex, false);
  assert.deepEqual(saved.healthCheckHosts, ['claude.ai', 'api.anthropic.com']);

  const reset = manager.resetValidationToDefaults();
  assert.deepEqual(reset.validation.services, defaultValidation().services);
  assert.equal(reset.healthCheckHosts.includes('api.openai.com'), true);
});

test('TargetConfigManager saves editable target rules and derives firewall hosts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  manager.load();

  const saved = manager.saveRules([
    { id: 'custom-api', domainPattern: 'https://api.example.com/v1', action: 'GUARD' },
    { id: 'allowed-docs', domainPattern: 'docs.example.com', action: 'ALLOW' },
    { id: 'wildcard', domainPattern: '*.example.org', action: 'GUARD' }
  ]);

  assert.deepEqual(saved.rules.map((rule) => rule.domainPattern), ['api.example.com', 'docs.example.com', '*.example.org']);
  assert.deepEqual(saved.firewallHosts, ['api.example.com', 'example.org']);
  assert.equal(saved.rules[1].action, 'ALLOW');
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
    services: { claude: true, codex: false },
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  const reset = manager.resetToDefaults();
  assert.equal(reset.validation.services.claude, true);
  assert.equal(reset.validation.services.codex, true);
  assert.equal(reset.rules.some((rule) => rule.domainPattern === 'api.openai.com'), true);
});

test('normalizeStaticResidentialIp supports empty values for first-run setup', () => {
  assert.equal(normalizeStaticResidentialIp(''), '');
  assert.equal(normalizeStaticResidentialIp(' 0.0.0.0 '), '0.0.0.0');
  assert.throws(() => normalizeStaticResidentialIp('', { allowEmpty: false }), /STATIC_RESIDENTIAL_IP_REQUIRED/);
});
