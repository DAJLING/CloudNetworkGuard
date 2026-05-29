const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { GuardService } = require('../src/daemon/guard-service');
const { Store } = require('../src/daemon/store');
const { GuardMode, GuardState } = require('../src/shared/constants');

test('GuardService persists enable and disable states without applying system proxy when skipped', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');
  service.firewallManager.applyBlock = async () => ({ mode: 'BLOCK', rules: [{ name: 'fixture', remoteIp: '203.0.113.10' }] });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.providers = async () => [
    {
      source: 'fixture',
      ip: '203.0.113.10',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 90
    }
  ];
  service.checker.externalAccessCheck = async () => ({ ok: true, results: [] });
  service.checker.claudeWebProbe = async () => ({ verdict: 'PASS', reasons: [], status: 200 });
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' });

  service.checker.now = () => 1000;
  const enabled = await service.enableGuard();
  assert.equal(enabled.guardState, GuardState.ENABLED);
  assert.equal(enabled.firewall.mode, 'CLEARED');

  const disabled = await service.disableGuard();
  assert.equal(disabled.guardState, GuardState.DISABLED);
  assert.equal(disabled.firewall.mode, 'CLEARED');

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService strict validate mode releases firewall when checks pass', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');
  let applyCount = 0;
  let clearCount = 0;
  service.firewallManager.applyBlock = async () => {
    applyCount += 1;
    return { mode: 'BLOCK', rules: [{ name: 'fixture', remoteIp: '203.0.113.10' }] };
  };
  service.firewallManager.clearBlock = async () => {
    clearCount += 1;
    return { mode: 'CLEARED', rules: [] };
  };
  service.checker.checkNow = async () => {
    const check = {
      checkedAt: new Date().toISOString(),
      verdict: 'PASS',
      reasons: [],
      allowTargetTraffic: true
    };
    store.update({ lastCheck: check });
    return check;
  };

  const enabled = await service.enableGuard(GuardMode.STRICT_VALIDATE);
  assert.equal(enabled.guardMode, GuardMode.STRICT_VALIDATE);
  assert.equal(enabled.firewall.mode, 'CLEARED');
  assert.equal(applyCount, 1);
  assert.equal(clearCount, 1);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService reloads editable target config into status and firewall manager', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({
    firewall: {
      mode: 'BLOCK',
      rules: [{ name: 'old-rule', remoteIp: '203.0.113.8' }],
      lastError: null,
      updatedAt: null
    }
  });
  const clearCalls = [];
  service.firewallManager.clearBlock = async (rules) => {
    clearCalls.push(rules);
    return { mode: 'CLEARED', rules: [] };
  };

  fs.writeFileSync(
    path.join(tmp, 'target-rules.json'),
    JSON.stringify(
      {
        version: 1,
        rules: [{ id: 'example-api', domainPattern: 'api.example.com', action: 'GUARD' }],
        healthCheckHosts: ['api.example.com'],
        controlHosts: ['api.example.com']
      },
      null,
      2
    )
  );

  const status = await service.reloadTargetConfig();
  assert.equal(status.targetConfig.rules.length, 1);
  assert.equal(status.targetConfig.rules[0].domainPattern, 'api.example.com');
  assert.deepEqual(service.firewallManager.hosts, ['api.example.com']);
  assert.deepEqual(clearCalls[0], [{ name: 'old-rule', remoteIp: '203.0.113.8' }]);
});

test('GuardService blocks enable when static residential IP is missing', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });

  const status = await service.enableGuard();

  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(status.actionRequired.type, 'STATIC_RESIDENTIAL_IP_REQUIRED');
  assert.equal(status.lastCheck.checkItems[0].verdict, 'FAIL');

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService blocks enable when configured static residential IP does not match current exit', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('203.0.113.9');
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.providers = async () => [
    {
      source: 'fixture',
      ip: '203.0.113.10',
      ipType: 'residential',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 90
    }
  ];

  const status = await service.enableGuard();

  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(status.actionRequired.type, 'STATIC_RESIDENTIAL_IP_MISMATCH');
  assert.equal(status.lastCheck.reasons.includes('STATIC_RESIDENTIAL_IP_MISMATCH'), true);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});
