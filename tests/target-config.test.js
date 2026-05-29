const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { TargetConfigManager, deriveHostsFromRules, normalizeStaticResidentialIp, normalizeTargetConfig } = require('../src/daemon/target-config');

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

test('normalizeStaticResidentialIp supports empty values for first-run setup', () => {
  assert.equal(normalizeStaticResidentialIp(''), '');
  assert.equal(normalizeStaticResidentialIp(' 0.0.0.0 '), '0.0.0.0');
  assert.throws(() => normalizeStaticResidentialIp('', { allowEmpty: false }), /STATIC_RESIDENTIAL_IP_REQUIRED/);
});
