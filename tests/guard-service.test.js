const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { GuardService, shouldUseSystemProxy } = require('../src/daemon/guard-service');
const { Store } = require('../src/daemon/store');
const { CheckReason, GuardMode, GuardState } = require('../src/shared/constants');
const { DEFAULT_VALIDATION_CHECKS } = require('../src/daemon/target-config');

function safePing0(overrides = {}) {
  return {
    source: 'ping0.cc',
    ip: '203.0.113.10',
    ipType: 'residential',
    countryCode: 'US',
    regionName: 'United States',
    isProxy: false,
    isVpn: false,
    isTor: false,
    riskScore: 0,
    ping0Purity: '低风险',
    sharedUsers: '1 - 10 (安全)',
    sharedUsersMax: 10,
    confidence: 45,
    ...overrides
  };
}

function passCheck(overrides = {}) {
  return {
    checkedAt: new Date().toISOString(),
    verdict: 'PASS',
    reasons: [],
    allowTargetTraffic: true,
    checkItems: [],
    ...overrides
  };
}

test('GuardService persists enable and disable states without applying system proxy when skipped', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');
  service.firewallManager.applyBlock = async () => ({ mode: 'BLOCK', rules: [{ name: 'fixture', remoteIp: '203.0.113.10' }] });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.providers = async () => [safePing0()];
  service.checker.externalAccessCheck = async () => ({ ok: true, results: [] });
  service.checker.claudeWebProbe = async () => ({ verdict: 'PASS', reasons: [], status: 200 });
  service.checker.browserWebRtcCheck = async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] });
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' });

  service.checker.now = () => 1000;
  const enabled = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  assert.equal(enabled.guardState, GuardState.ENABLED);
  assert.equal(enabled.firewall.mode, 'CLEARED');

  const disabled = await service.disableGuard();
  assert.equal(disabled.guardState, GuardState.DISABLED);
  assert.equal(disabled.firewall.mode, 'CLEARED');

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService runs full network check before enabling when risk is accepted', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');
  service.firewallManager.applyBlock = async () => ({ mode: 'BLOCK', rules: [] });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  let checkCalls = 0;
  service.checker.checkNow = async () => {
    checkCalls += 1;
    return passCheck();
  };

  const status = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(checkCalls, 1);
  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService enables guard in blocking mode when preflight check fails', async () => {
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
    return passCheck({
      verdict: 'BLOCK',
      reasons: ['IP_RISK_DATA_UNAVAILABLE'],
      allowTargetTraffic: false
    });
  };

  const status = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(status.lastCheck.allowTargetTraffic, false);
  assert.equal(events.includes('check'), true);
  assert.equal(events.includes('apply'), true);
  assert.equal(store.getState().checkingNetwork, false);
  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService fails closed when system proxy cannot be applied during enable', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('0.0.0.0');
  service.checker.checkNow = async () => passCheck();
  service.proxyManager.enable = async () => {
    throw new Error('Wi-Fi: HTTPS 127.0.0.1:7897');
  };
  service.firewallManager.applyBlock = async () => ({ mode: 'PF_BLOCK', rules: [{ anchor: 'fixture' }], lastError: null });

  const status = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });

  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(status.lastCheck.allowTargetTraffic, false);
  assert.equal(status.lastCheck.reasons.includes(CheckReason.SYSTEM_PROXY_NOT_APPLIED), true);
  assert.equal(status.actionRequired.type, CheckReason.SYSTEM_PROXY_NOT_APPLIED);
  assert.equal(status.firewall.mode, 'PF_BLOCK');
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
  service.checker.providers = async () => [safePing0()];
  service.checker.externalAccessCheck = async () => ({ ok: true, results: [] });
  service.checker.claudeWebProbe = async () => ({ verdict: 'PASS', reasons: [], status: 200 });
  service.checker.browserWebRtcCheck = async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] });
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'zh-CN' });

  let enableCalled = false;
  service.proxyManager.enable = async () => {
    enableCalled = true;
    return { applied: true, platform: 'win32' };
  };
  service.proxyManager.disable = async () => ({ applied: true, platform: 'win32' });

  const enabled = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
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

  const enabled = await service.enableGuard(GuardMode.STRICT_VALIDATE, { acceptNoStaticIpRisk: true });
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
        rules: [{ id: 'anthropic-api', domainPattern: 'api.anthropic.com', action: 'GUARD' }],
        healthCheckHosts: ['api.anthropic.com'],
        controlHosts: ['api.anthropic.com']
      },
      null,
      2
    )
  );

  const status = await service.reloadTargetConfig();
  assert.equal(status.targetConfig.rules.length, 1);
  assert.equal(status.targetConfig.rules[0].domainPattern, 'api.anthropic.com');
  assert.deepEqual(service.firewallManager.hosts, ['api.anthropic.com']);
  assert.deepEqual(clearCalls[0], [{ name: 'old-rule', remoteIp: '203.0.113.8' }]);
});

test('GuardService saveTargetRules persists rules and reloads firewall hosts', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });

  const status = await service.saveTargetRules([
    { id: 'custom-api', domainPattern: 'api.anthropic.com', action: 'GUARD' }
  ]);

  assert.equal(status.targetConfig.rules.length, 1);
  assert.deepEqual(service.firewallManager.hosts, ['api.anthropic.com']);
});

test('GuardService requires risk acknowledgement when static residential IP is missing', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });

  const status = await service.enableGuard();

  assert.equal(status.guardState, GuardState.DISABLED);
  assert.equal(status.actionRequired.type, 'CLAUDE_ACCOUNT_RISK_ACK_REQUIRED');
  assert.equal(status.lastCheck.checkItems[0].verdict, 'FAIL');

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService skips static residential IP preflight when that check is disabled', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.providers = async () => [safePing0()];
  service.checker.externalAccessCheck = async () => ({ ok: true, claudeControlOk: true, results: [] });
  service.checker.claudeWebProbe = async () => ({ verdict: 'PASS', reasons: [], skipped: true });
  service.checker.browserWebRtcCheck = async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] });
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' });
  await service.saveValidationConfig({
    services: { claude: true },
    checks: { ...DEFAULT_VALIDATION_CHECKS, staticResidentialIp: false },
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  const status = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });

  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(status.actionRequired, null);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService enables guard with datacenter IP warning when traffic is allowed', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.providers = async () => [safePing0({ ipType: 'datacenter' })];
  service.checker.externalAccessCheck = async () => ({ ok: true, claudeControlOk: true, results: [] });
  service.checker.claudeWebProbe = async () => ({ verdict: 'PASS', reasons: [], skipped: true });
  service.checker.browserWebRtcCheck = async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] });
  service.checker.environmentCheck = () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' });
  await service.saveValidationConfig({
    services: { claude: true },
    checks: { ...DEFAULT_VALIDATION_CHECKS, staticResidentialIp: false },
    webProbe: { enabled: false, url: '' },
    useCustomHosts: false
  });

  const status = await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });

  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(status.lastCheck.verdict, 'WARN');
  assert.equal(status.lastCheck.allowTargetTraffic, true);
  assert.equal(status.lastCheck.reasons.includes(CheckReason.DATACENTER_IP), true);
  assert.equal(status.lastCheck.checkItems.find((item) => item.id === 'ip-type').verdict, 'WARN');

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService keeps guard disabled when every validation check is disabled', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  await service.saveValidationConfig({
    services: { claude: false },
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

test('GuardService blocks matching target request when configured static residential IP does not match current exit', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.setStaticResidentialIp('203.0.113.9');
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.checkNow = async () => passCheck();
  service.checker.providers = async () => [safePing0()];

  const status = await service.enableGuard();
  const decision = await service.evaluateGuardedTargetRequest('api.anthropic.com');

  assert.equal(status.guardState, GuardState.ENABLED);
  assert.equal(decision.block, true);
  assert.equal(decision.reasons.includes('STATIC_RESIDENTIAL_IP_MISMATCH'), true);
  assert.equal(store.getState().lastCheck.reasons.includes('STATIC_RESIDENTIAL_IP_MISMATCH'), true);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService allows matching target request from supported region without static IP after acknowledgement', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.checkNow = async () => passCheck();
  service.checker.providers = async () => [safePing0()];

  await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  const decision = await service.evaluateGuardedTargetRequest('claude.ai');

  assert.equal(decision.block, false);
  assert.equal(store.getState().lastCheck.allowTargetTraffic, true);
  assert.equal(store.getState().lastCheck.requestGate.mode, 'REGION_ONLY');

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService allows target request from datacenter IP while recording warning', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.checker.checkNow = async () => passCheck();
  service.checker.providers = async () => [safePing0({ ipType: 'datacenter' })];

  await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  const decision = await service.evaluateGuardedTargetRequest('claude.ai');

  assert.equal(decision.block, false);
  assert.equal(store.getState().lastCheck.verdict, 'WARN');
  assert.equal(store.getState().lastCheck.allowTargetTraffic, true);
  assert.equal(store.getState().lastCheck.reasons.includes(CheckReason.DATACENTER_IP), true);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService blocks target request while current guard status disallows traffic', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  let providerCalls = 0;
  service.checker.providers = async () => {
    providerCalls += 1;
    return [safePing0()];
  };
  store.update({
    guardState: GuardState.ENABLED,
    lastCheck: passCheck({
      verdict: 'BLOCK',
      reasons: ['ENVIRONMENT_MISMATCH'],
      allowTargetTraffic: false
    })
  });

  const decision = await service.evaluateGuardedTargetRequest('claude.ai');

  assert.equal(decision.block, true);
  assert.deepEqual(decision.reasons, ['ENVIRONMENT_MISMATCH']);
  assert.equal(providerCalls, 0);
});

test('GuardService blocks target request when Ping0 risk data is unavailable', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.firewallManager.applyBlock = async () => ({ mode: 'BLOCK', rules: [] });
  service.checker.checkNow = async () => passCheck();
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
    },
    { source: 'ping0.cc', error: 'CAPTCHA_REQUIRED' }
  ];

  await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  const decision = await service.evaluateGuardedTargetRequest('claude.ai');

  assert.equal(decision.block, true);
  assert.equal(decision.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), true);
  assert.equal(store.getState().lastCheck.allowTargetTraffic, false);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService blocks matching target request from unsupported Claude region without static IP', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });
  service.firewallManager.applyBlock = async () => ({ mode: 'BLOCK', rules: [] });
  service.checker.checkNow = async () => passCheck();
  service.checker.providers = async () => [safePing0({ ip: '198.51.100.10', countryCode: 'CN', regionName: 'China' })];

  await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  const decision = await service.evaluateGuardedTargetRequest('claude.ai');

  assert.equal(decision.block, true);
  assert.deepEqual(decision.reasons, ['BLOCKED_REGION']);
  assert.equal(store.getState().lastCheck.allowTargetTraffic, false);

  delete process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY;
});

test('GuardService rechecks request exit after an allowed request inside the cache window', async () => {
  process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY = '1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  const firewallModes = [];
  service.firewallManager.clearBlock = async () => {
    firewallModes.push('CLEARED');
    return { mode: 'CLEARED', rules: [] };
  };
  service.firewallManager.applyBlock = async () => {
    firewallModes.push('BLOCK');
    return { mode: 'BLOCK', rules: [{ name: 'fixture', remoteIp: '198.51.100.10' }] };
  };
  service.checker.checkNow = async () => passCheck();
  const providerResponses = [
    [safePing0()],
    [safePing0({ ip: '198.51.100.10', countryCode: 'CN', regionName: 'China' })]
  ];
  let providerCalls = 0;
  service.checker.providers = async () => providerResponses[providerCalls++] || providerResponses.at(-1);

  await service.enableGuard('AUTO', { acceptNoStaticIpRisk: true });
  const allowed = await service.evaluateGuardedTargetRequest('claude.ai');
  const blocked = await service.evaluateGuardedTargetRequest('claude.ai');

  assert.equal(allowed.block, false);
  assert.equal(blocked.block, true);
  assert.deepEqual(blocked.reasons, ['BLOCKED_REGION']);
  assert.equal(providerCalls, 2);
  assert.equal(store.getState().lastCheck.allowTargetTraffic, false);
  assert.equal(firewallModes.includes('BLOCK'), true);

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
    usageEvents: Array.from({ length: 200 }, () => ({ host: 'api.anthropic.com', at: Date.now() }))
  });

  const result = service.recordTargetRequest('api.anthropic.com');

  assert.equal(result.block, false);
  assert.equal(store.getState().lastCheck.allowTargetTraffic, true);
});

test('GuardService status guidance separates checking from completed pass', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });

  store.update({
    checkingNetwork: true,
    lastCheck: {
      checkedAt: new Date().toISOString(),
      verdict: 'PASS',
      reasons: [],
      allowTargetTraffic: true
    }
  });
  assert.equal(service.getStatus().guidance.title, '正在校验网络');
  assert.equal(service.getStatus().checkingNetwork, true);

  store.update({ checkingNetwork: false });
  const status = service.getStatus();

  assert.equal(status.guidance.title, '检测完成');
  assert.equal(status.checkingNetwork, false);
});

test('GuardService rebindExitToCurrent binds the current provider IP without exposing it', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.checker.providers = async () => [safePing0()];

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
    { mode: 'PF_BLOCK', rules: [{ anchor: 'com.local.claude-network-guard' }], lastError: null }
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

test('GuardService setMonitoringConfig keeps background monitoring disabled', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });

  const status = service.setMonitoringConfig({ enabled: true, intervalMinutes: 5 });

  assert.equal(status.monitoring.enabled, false);
  assert.equal(status.monitoring.intervalMinutes, 5);
  assert.equal(service.monitoringTimer, null);
});

test('GuardService runMonitoringTick is disabled and does not run checks', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  let calls = 0;
  service.checkNow = async () => {
    calls += 1;
    return { verdict: 'PASS', reasons: [], checkedAt: '2026-06-05T00:00:00.000Z' };
  };

  const result = await service.runMonitoringTick();

  const monitoring = store.getState().monitoring;
  assert.equal(result, null);
  assert.equal(calls, 0);
  assert.equal(monitoring.enabled, false);
  assert.equal(monitoring.lastError, null);
});

test('GuardService reapplies mac system proxy when it drifts while guard is enabled', async () => {
  if (process.platform !== 'darwin') return;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({
    guardState: GuardState.ENABLED,
    systemProxyApplied: true,
    lastCheck: passCheck()
  });
  service.proxyManager.verifyMacProxyApplied = async () => ({ ok: false, results: [{ service: 'Wi-Fi', ok: false }] });
  let reapplyCalls = 0;
  service.setSystemProxyEnabled = async (enabled) => {
    reapplyCalls += 1;
    assert.equal(enabled, true);
    service.proxy.setUpstreamProxy({ host: '127.0.0.1', port: 7897 });
    store.update({ systemProxyApplied: true });
    return { applied: true, upstreamProxy: { host: '127.0.0.1', port: 7897 } };
  };

  const result = await service.ensureSystemProxyStillApplied();

  assert.equal(result.ok, true);
  assert.equal(reapplyCalls, 1);
  assert.equal(service.getStatus().proxy.upstream.port, 7897);
  assert.equal(store.getState().logs[0].type, 'system-proxy-reapplied');
});

test('GuardService fails closed when mac system proxy cannot be reapplied', async () => {
  if (process.platform !== 'darwin') return;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({
    guardState: GuardState.ENABLED,
    systemProxyApplied: true,
    lastCheck: passCheck()
  });
  service.proxyManager.verifyMacProxyApplied = async () => ({ ok: false, results: [{ service: 'Wi-Fi', ok: false }] });
  service.setSystemProxyEnabled = async () => {
    throw new Error('Wi-Fi: HTTP 127.0.0.1:7897');
  };
  service.firewallManager.applyBlock = async () => ({ mode: 'PF_BLOCK', rules: [{ anchor: 'fixture' }], lastError: null });

  const result = await service.ensureSystemProxyStillApplied();
  const status = service.getStatus();

  assert.equal(result.ok, false);
  assert.equal(status.lastCheck.allowTargetTraffic, false);
  assert.equal(status.lastCheck.reasons.includes('SYSTEM_PROXY_NOT_APPLIED'), true);
  assert.equal(status.firewall.mode, 'PF_BLOCK');
  assert.equal(status.actionRequired.type, 'SYSTEM_PROXY_NOT_APPLIED');
});
