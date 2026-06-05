const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { GuardService, shouldUseSystemProxy } = require('../src/daemon/guard-service');
const { Store } = require('../src/daemon/store');
const { GuardMode, GuardState } = require('../src/shared/constants');
const { DEFAULT_VALIDATION_CHECKS } = require('../src/daemon/target-config');

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

test('GuardService keeps guard disabled when enable-time network check fails', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');
  service.firewallManager.applyBlock = async () => ({ mode: 'BLOCK', rules: [] });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.checkNow = async () => ({
    checkedAt: new Date().toISOString(),
    verdict: 'BLOCK',
    reasons: ['DNS_CHECK_FAILED'],
    allowTargetTraffic: false,
    checkItems: []
  });

  const status = await service.enableGuard();
  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(status.lastCheck.allowTargetTraffic, false);
  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService runs network check before applying firewall block on enable', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');

  const events = [];
  service.firewallManager.applyBlock = async () => {
    events.push('apply');
    return { mode: 'BLOCK', rules: [{ name: 'fixture', remoteIp: '203.0.113.10' }] };
  };
  service.firewallManager.clearBlock = async () => {
    events.push('clear');
    return { mode: 'CLEARED', rules: [] };
  };
  service.checker.checkNow = async () => {
    events.push('check');
    assert.equal(store.getState().checkingNetwork, true);
    return {
      checkedAt: new Date().toISOString(),
      verdict: 'PASS',
      reasons: [],
      allowTargetTraffic: true,
      checkItems: []
    };
  };

  const status = await service.enableGuard();
  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(events.includes('check'), true);
  assert.equal(events.includes('apply'), false);
  assert.ok(events.filter((item) => item === 'clear').length >= 1);
  assert.equal(store.getState().checkingNetwork, false);
  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('shouldUseSystemProxy is false on Windows unless explicitly enabled', () => {
  const previousPlatform = process.platform;
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' });
  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
  delete process.env.NETWORK_GUARD_USE_SYSTEM_PROXY;
  assert.equal(shouldUseSystemProxy(), false);
  process.env.NETWORK_GUARD_USE_SYSTEM_PROXY = '1';
  assert.equal(shouldUseSystemProxy(), true);
  delete process.env.NETWORK_GUARD_USE_SYSTEM_PROXY;
  Object.defineProperty(process, 'platform', { configurable: true, value: previousPlatform });
});

test('GuardService does not enable Windows system proxy by default', async () => {
  if (process.platform !== 'win32') return;
  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
  delete process.env.NETWORK_GUARD_USE_SYSTEM_PROXY;

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
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'zh-CN' });

  let enableCalled = false;
  service.proxyManager.enable = async () => {
    enableCalled = true;
    return { applied: true, platform: 'win32' };
  };
  service.proxyManager.disable = async () => ({ applied: true, platform: 'win32' });

  const enabled = await service.enableGuard();
  assert.equal(enableCalled, false);
  assert.equal(enabled.guardState, GuardState.ENABLED);
  assert.equal(store.getState().systemProxyApplied, false);
  assert.equal(enabled.proxy.mode, 'FIREWALL_ONLY');
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
  assert.equal(applyCount, 0);
  assert.ok(clearCount >= 1);

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

test('GuardService saveTargetRules persists rules and reloads firewall hosts', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });

  const status = await service.saveTargetRules([
    { id: 'custom-api', domainPattern: 'api.example.com', action: 'GUARD' }
  ]);

  assert.equal(status.targetConfig.rules.length, 1);
  assert.deepEqual(service.firewallManager.hosts, ['api.example.com']);
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

test('GuardService skips static residential IP preflight when that check is disabled', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
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
  service.checker.externalAccessCheck = async () => ({ ok: true, claudeControlOk: true, results: [] });
  service.checker.claudeWebProbe = async () => ({ verdict: 'PASS', reasons: [], skipped: true });
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' });
  await service.saveValidationConfig({
    services: { claude: true, codex: true },
    checks: { ...DEFAULT_VALIDATION_CHECKS, staticResidentialIp: false },
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  const status = await service.enableGuard();

  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(status.actionRequired, null);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService keeps guard disabled when every validation check is disabled', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  await service.saveValidationConfig({
    services: { claude: false, codex: false },
    checks: Object.fromEntries(Object.keys(DEFAULT_VALIDATION_CHECKS).map((key) => [key, false])),
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  const status = await service.enableGuard();

  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(status.actionRequired.type, 'VALIDATION_CHECK_REQUIRED');
  assert.equal(status.lastCheck.allowTargetTraffic, false);

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

test('GuardService emergencyRestore disables guard and clears managed network changes', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({
    guardState: GuardState.ENABLED,
    firewall: {
      mode: 'BLOCK',
      rules: [{ name: 'fixture', remoteIp: '203.0.113.10' }],
      lastError: null,
      updatedAt: null
    }
  });
  let proxyDisabled = false;
  let clearedRules = null;
  service.proxyManager.disable = async () => {
    proxyDisabled = true;
    return { applied: true, platform: 'test' };
  };
  service.firewallManager.clearBlock = async (rules) => {
    clearedRules = rules;
    return { mode: 'CLEARED', rules: [] };
  };

  const status = await service.emergencyRestore();

  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(proxyDisabled, true);
  assert.deepEqual(clearedRules, [{ name: 'fixture', remoteIp: '203.0.113.10' }]);
  assert.equal(status.firewall.mode, 'CLEARED');
  assert.equal(status.recovery.lastResult.ok, true);
  assert.equal(status.logs[0].type, 'emergency-restore');
});

test('GuardService emergencyRestore reports partial failures by layer', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({
    guardState: GuardState.ENABLED,
    firewall: {
      mode: 'BLOCK',
      rules: [{ name: 'fixture', remoteIp: '203.0.113.10' }],
      lastError: null,
      updatedAt: null
    }
  });
  service.proxyManager.disable = async () => {
    throw new Error('PROXY_DENIED');
  };
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });

  const status = await service.emergencyRestore();

  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(status.recovery.lastResult.ok, false);
  assert.equal(status.recovery.lastResult.steps.proxy.ok, false);
  assert.match(status.recovery.lastResult.steps.proxy.error, /PROXY_DENIED/);
});

test('GuardService resetExitBinding clears the stored exit fingerprint', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({ boundExitIpHash: 'existing-hash' });

  const status = service.resetExitBinding();

  assert.equal(status.binding.bound, false);
  assert.equal(store.getState().boundExitIpHash, null);
  assert.equal(status.logs[0].type, 'exit-binding-reset');
});

test('GuardService does not block target usage when usage-rate validation is disabled', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.targetConfig.validation.checks.usageRate = false;
  store.update({
    guardState: GuardState.ENABLED,
    lastCheck: {
      checkedAt: new Date().toISOString(),
      verdict: 'PASS',
      reasons: [],
      allowTargetTraffic: true
    },
    usageEvents: Array.from({ length: 200 }, () => ({ host: 'api.openai.com', at: Date.now() }))
  });

  const result = service.recordTargetRequest('api.openai.com');

  assert.equal(result.block, false);
  assert.equal(store.getState().lastCheck.allowTargetTraffic, true);
});

test('GuardService rebindExitToCurrent binds the current provider IP without exposing it', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
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

  const status = await service.rebindExitToCurrent();

  assert.equal(status.binding.bound, true);
  assert.equal(status.binding.currentMaskedIp, '203.0.x.x');
  assert.equal(JSON.stringify(status).includes('203.0.113.10'), false);
  assert.equal(status.logs[0].type, 'exit-binding-rebound');
});

test('GuardService rebindExitToCurrent reports provider failures', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.checker.providers = async () => [{ source: 'fixture', error: 'OFFLINE' }];

  await assert.rejects(() => service.rebindExitToCurrent(), /PROVIDER_UNAVAILABLE/);
});

test('GuardService completeSetup persists first-run completion metadata', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });

  const status = service.completeSetup({ staticIpStrategy: 'skip' });

  assert.equal(status.setup.completed, true);
  assert.equal(status.setup.staticIpStrategy, 'skip');
  assert.ok(status.setup.completedAt);
});

test('GuardService reopenSetup marks setup as incomplete', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.completeSetup({ staticIpStrategy: 'manual' });

  const status = service.reopenSetup();

  assert.equal(status.setup.completed, false);
  assert.equal(status.setup.completedAt, null);
});

test('GuardService decorateCheckWithFirewall skips failure when guard is disabled', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({ guardState: GuardState.DISABLED });

  const decorated = service.decorateCheckWithFirewall(
    { verdict: 'BLOCK', reasons: ['ENVIRONMENT_MISMATCH'], checkItems: [] },
    { mode: 'PARTIAL_CLEAR', rules: [], lastError: 'access denied' }
  );

  const firewallItem = decorated.checkItems.find((item) => item.id === 'firewall');
  assert.equal(firewallItem.verdict, 'SKIPPED');
  assert.equal(firewallItem.reason, null);
});

test('GuardService decorateCheckWithFirewall treats macOS pf modes as successful firewall states', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({ guardState: GuardState.ENABLED });

  const blocked = service.decorateCheckWithFirewall(
    { verdict: 'BLOCK', reasons: ['DNS_CHECK_FAILED'], checkItems: [] },
    { mode: 'PF_BLOCK', rules: [{ anchor: 'com.local.claude-codex-network-guard' }], lastError: null }
  );
  const cleared = service.decorateCheckWithFirewall(
    { verdict: 'PASS', reasons: [], checkItems: [] },
    { mode: 'PF_CLEARED', rules: [], lastError: null }
  );

  assert.equal(blocked.checkItems.find((item) => item.id === 'firewall').verdict, 'PASS');
  assert.equal(cleared.checkItems.find((item) => item.id === 'firewall').verdict, 'PASS');
});

test('GuardService applyEnvironmentConsistency sets pendingPostApplyCheck', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({
    lastCheck: {
      ip: { countryCode: 'US', regionName: 'Texas', maskedIp: '38.150.x.x' }
    }
  });
  service.environmentConsistency.apply = async () => ({
    ok: true,
    restartRequired: true,
    steps: { 'windows.timezone': { ok: true } },
    lastTargetProfile: {
      timeZone: 'America/Chicago',
      language: 'en-US',
      languages: ['en-US']
    },
    backup: { hasBackup: true, createdAt: '2026-05-30T01:00:00.000Z', path: '/tmp/backup.json' }
  });

  const result = await service.applyEnvironmentConsistency();

  assert.equal(result.restartRequired, true);
  assert.equal(service.store.getState().environmentConsistency.pendingPostApplyCheck, true);
  assert.equal(service.store.getState().environmentConsistency.enabled, true);
  assert.equal(result.status.environmentConsistency.lastTargetProfile.timeZone, 'America/Chicago');
});

test('GuardService setMonitoringConfig persists enabled interval', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });

  const status = service.setMonitoringConfig({ enabled: true, intervalMinutes: 5 });

  assert.equal(status.monitoring.enabled, true);
  assert.equal(status.monitoring.intervalMinutes, 5);
});

test('GuardService runMonitoringTick records compact result and skips overlap', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  let calls = 0;
  service.checkNow = async () => {
    calls += 1;
    return { verdict: 'PASS', reasons: [], checkedAt: '2026-06-05T00:00:00.000Z' };
  };

  await service.runMonitoringTick();
  service.monitoringRunning = true;
  await service.runMonitoringTick();

  const monitoring = store.getState().monitoring;
  assert.equal(calls, 1);
  assert.equal(monitoring.lastResult.verdict, 'PASS');
  assert.equal(monitoring.lastError, 'MONITORING_ALREADY_RUNNING');
});
