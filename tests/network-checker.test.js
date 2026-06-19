const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('dns').promises;
const { dnsProbe, buildCheckItems, NetworkChecker } = require('../src/daemon/network-checker');
const { CheckReason } = require('../src/shared/constants');

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

function createMemoryStore(overrides = {}) {
  const state = {
    salt: 'fixture-salt',
    clientEnvironment: {
      timeZone: 'America/New_York',
      language: 'en-US',
      languages: ['en-US'],
      webRtcLocalIpCount: 0
    },
    environmentConsistency: {},
    ...overrides
  };
  return {
    state,
    store: {
      getState: () => state,
      update: (patch) => Object.assign(state, patch),
      appendLog: () => {}
    }
  };
}

test('dnsProbe falls back to system resolver when direct DNS resolve is refused', async () => {
  const originalResolve = dns.resolve;
  const originalLookup = dns.lookup;

  dns.resolve = async () => {
    const error = new Error('query refused');
    error.code = 'ECONNREFUSED';
    throw error;
  };
  dns.lookup = async () => [
    { address: '198.18.0.49', family: 4 },
    { address: '198.18.0.50', family: 4 }
  ];

  try {
    const result = await dnsProbe('claude.ai');

    assert.equal(result.ok, true);
    assert.deepEqual(result.addresses, ['198.18.0.49', '198.18.0.50']);
    assert.equal(result.error, null);
    assert.equal(result.resolver, 'system');
    assert.equal(result.fallbackFrom, 'ECONNREFUSED');
  } finally {
    dns.resolve = originalResolve;
    dns.lookup = originalLookup;
  }
});

test('NetworkChecker skips Claude Web probe until Ping0 risk data is available', async () => {
  const { store } = createMemoryStore();
  const checker = new NetworkChecker({
    store,
    providers: async () => [
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
    ],
    externalAccessCheck: async () => ({ ok: true, claudeControlOk: true, results: [] }),
    claudeWebProbe: async () => {
      throw new Error('web probe should wait for prechecks');
    },
    browserWebRtcCheck: async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] }),
    environmentCheck: () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' }),
    getTargetConfig: () => ({
      validation: {
        services: { claude: true },
        checks: {
          staticResidentialIp: false,
          ipType: true,
          region: true,
          proxyRisk: true,
          dns: false,
          tcp: false,
          tls: false,
          controlHosts: false,
          environment: true,
          exitBinding: false,
          usageRate: false
        },
        webProbe: { enabled: true, url: 'https://claude.ai/' }
      },
      healthCheckHosts: [],
      controlHosts: [],
      webProbeUrl: 'https://claude.ai/',
      staticResidentialIp: ''
    }),
    now: () => 1000
  });

  const check = await checker.checkNow();

  assert.equal(check.verdict, 'BLOCK');
  assert.equal(check.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), true);
  assert.equal(check.claudeWeb.skipped, true);
  assert.equal(check.claudeWeb.skipReason, 'PRECHECK_FAILED');
  assert.match(check.checkItems.find((item) => item.id === 'claude-web').detail, /前置安全校验未通过/);
});

test('NetworkChecker reuses cached Ping0 risk data for the same exit IP when CAPTCHA blocks refresh', async () => {
  let providerRun = 0;
  const { store } = createMemoryStore();
  const targetConfig = {
    validation: {
      services: { claude: true },
      checks: {
        staticResidentialIp: false,
        ipType: true,
        region: true,
        proxyRisk: true,
        dns: false,
        tcp: false,
        tls: false,
        controlHosts: false,
        webProbe: false,
        environment: false,
        exitBinding: false,
        usageRate: false
      },
      webProbe: { enabled: false }
    },
    healthCheckHosts: [],
    controlHosts: [],
    webProbeUrl: '',
    staticResidentialIp: ''
  };
  const checker = new NetworkChecker({
    store,
    providers: async () => {
      providerRun += 1;
      const base = {
        source: 'ip-api.com',
        ip: '203.0.113.10',
        ipType: 'residential',
        countryCode: 'US',
        regionName: 'United States',
        isProxy: false,
        isVpn: false,
        isTor: false,
        riskScore: 0,
        confidence: 90
      };
      return providerRun === 1 ? [base, safePing0({ ip: '203.0.113.10' })] : [base, { source: 'ping0.cc', error: 'PING0_CAPTCHA_REQUIRED' }];
    },
    externalAccessCheck: async () => ({ ok: true, claudeControlOk: true, results: [] }),
    claudeWebProbe: async () => ({ verdict: 'PASS', reasons: [], skipped: true }),
    browserWebRtcCheck: async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] }),
    environmentCheck: () => ({ verdict: 'PASS', reasons: [] }),
    getTargetConfig: () => targetConfig,
    now: () => providerRun === 1 ? 1000 : 2000
  });

  await checker.checkNow();
  const check = await checker.checkNow();
  const ping0 = check.providers.find((provider) => provider.source === 'ping0.cc');

  assert.equal(check.ip.ipType, 'residential');
  assert.equal(check.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), false);
  assert.equal(ping0.cached, true);
  assert.equal(ping0.cacheReason, 'PING0_CAPTCHA_REQUIRED');
  assert.equal(ping0.sharedUsersMax, 10);
});

test('NetworkChecker uses proxycheck risk data when Ping0 is blocked by CAPTCHA', async () => {
  const { store } = createMemoryStore();
  const checker = new NetworkChecker({
    store,
    providers: async () => [
      {
        source: 'ip-api.com',
        ip: '203.0.113.10',
        ipType: 'residential',
        countryCode: 'US',
        regionName: 'United States',
        isProxy: false,
        isVpn: false,
        isTor: false,
        riskScore: 0,
        confidence: 30
      },
      { source: 'ping0.cc', error: 'PING0_CAPTCHA_REQUIRED' },
      {
        source: 'proxycheck.io',
        ip: '203.0.113.10',
        ipType: 'residential',
        countryCode: 'US',
        regionName: 'United States',
        isProxy: false,
        isVpn: false,
        isTor: false,
        isBlacklisted: false,
        riskScore: 12,
        ping0Purity: '低风险',
        sharedUsers: '设备估计 8',
        sharedUsersMax: 8,
        confidence: 90
      }
    ],
    externalAccessCheck: async () => ({ ok: true, claudeControlOk: true, results: [] }),
    claudeWebProbe: async () => ({ verdict: 'PASS', reasons: [], status: 200 }),
    browserWebRtcCheck: async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] }),
    environmentCheck: () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' }),
    getTargetConfig: () => ({
      validation: {
        services: { claude: true },
        checks: {
          staticResidentialIp: false,
          ipType: true,
          region: true,
          proxyRisk: true,
          dns: false,
          tcp: false,
          tls: false,
          controlHosts: false,
          environment: true,
          exitBinding: false,
          usageRate: false
        },
        webProbe: { enabled: true, url: 'https://claude.ai/' }
      },
      healthCheckHosts: [],
      controlHosts: [],
      webProbeUrl: 'https://claude.ai/',
      staticResidentialIp: ''
    }),
    now: () => 1000
  });

  const check = await checker.checkNow();
  const proxyRisk = check.checkItems.find((item) => item.id === 'proxy-risk');

  assert.equal(check.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), false);
  assert.equal(check.verdict, 'PASS');
  assert.match(proxyRisk.detail, /Proxycheck 风控 12/);
});

test('NetworkChecker runs Claude Web probe after prechecks pass', async () => {
  const { store } = createMemoryStore();
  let webProbeCalls = 0;
  const checker = new NetworkChecker({
    store,
    providers: async () => [safePing0()],
    externalAccessCheck: async () => ({ ok: true, claudeControlOk: true, results: [] }),
    claudeWebProbe: async () => {
      webProbeCalls += 1;
      return { verdict: 'PASS', reasons: [], status: 200 };
    },
    browserWebRtcCheck: async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] }),
    environmentCheck: () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' }),
    getTargetConfig: () => ({
      validation: {
        services: { claude: true },
        checks: {
          staticResidentialIp: false,
          ipType: true,
          region: true,
          proxyRisk: true,
          dns: false,
          tcp: false,
          tls: false,
          controlHosts: false,
          environment: true,
          exitBinding: false,
          usageRate: false
        },
        webProbe: { enabled: true, url: 'https://claude.ai/' }
      },
      healthCheckHosts: [],
      controlHosts: [],
      webProbeUrl: 'https://claude.ai/',
      staticResidentialIp: ''
    }),
    now: () => 1000
  });

  const check = await checker.checkNow();

  assert.equal(check.verdict, 'PASS');
  assert.equal(webProbeCalls, 1);
  assert.equal(check.claudeWeb.status, 200);
});

test('NetworkChecker runs Claude Web probe when prechecks only warn for datacenter IP', async () => {
  const { store } = createMemoryStore();
  let webProbeCalls = 0;
  const checker = new NetworkChecker({
    store,
    providers: async () => [safePing0({ ipType: 'datacenter' })],
    externalAccessCheck: async () => ({ ok: true, claudeControlOk: true, results: [] }),
    claudeWebProbe: async () => {
      webProbeCalls += 1;
      return { verdict: 'PASS', reasons: [], status: 200 };
    },
    browserWebRtcCheck: async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] }),
    environmentCheck: () => ({ verdict: 'PASS', reasons: [], timeZone: 'America/New_York', language: 'en-US' }),
    getTargetConfig: () => ({
      validation: {
        services: { claude: true },
        checks: {
          staticResidentialIp: false,
          ipType: true,
          region: true,
          proxyRisk: true,
          dns: false,
          tcp: false,
          tls: false,
          controlHosts: false,
          environment: true,
          exitBinding: false,
          usageRate: false
        },
        webProbe: { enabled: true, url: 'https://claude.ai/' }
      },
      healthCheckHosts: [],
      controlHosts: [],
      webProbeUrl: 'https://claude.ai/',
      staticResidentialIp: ''
    }),
    now: () => 1000
  });

  const check = await checker.checkNow();

  assert.equal(check.verdict, 'WARN');
  assert.equal(check.allowTargetTraffic, true);
  assert.equal(check.reasons.includes(CheckReason.DATACENTER_IP), true);
  assert.equal(webProbeCalls, 1);
  assert.equal(check.claudeWeb.status, 200);
});

test('NetworkChecker runs and reports only enabled validation items', async () => {
  const state = {
    salt: 'fixture-salt',
    clientEnvironment: {
      timeZone: 'America/New_York',
      language: 'en-US',
      languages: ['en-US'],
      webRtcLocalIpCount: 0
    },
    environmentConsistency: {}
  };
  const store = {
    getState: () => state,
    update: (patch) => Object.assign(state, patch),
    appendLog: () => {}
  };
  const checker = new NetworkChecker({
    store,
    providers: async () => {
      throw new Error('providers should not run');
    },
    externalAccessCheck: async () => {
      throw new Error('external access should not run');
    },
    claudeWebProbe: async () => {
      throw new Error('web probe should not run');
    },
    browserWebRtcCheck: async () => ({ supported: true, ok: true, requiredPolicy: 'disable_non_proxied_udp', browsers: [] }),
    getTargetConfig: () => ({
      validation: {
        services: { claude: false },
        checks: {
          staticResidentialIp: false,
          ipType: false,
          region: false,
          proxyRisk: false,
          dns: false,
          tcp: false,
          tls: false,
          controlHosts: false,
          environment: true,
          exitBinding: false,
          usageRate: false
        },
        webProbe: { enabled: false, url: '' }
      },
      healthCheckHosts: [],
      controlHosts: [],
      webProbeUrl: null,
      staticResidentialIp: ''
    }),
    now: () => 1000
  });

  const check = await checker.checkNow();

  assert.equal(check.verdict, 'PASS');
  assert.deepEqual(check.checkItems.map((item) => item.id), ['environment']);
});

test('buildCheckItems includes provider error details when providers are unavailable', () => {
  const items = buildCheckItems({
    targetConfig: {
      validation: {
        checks: {
          staticResidentialIp: false,
          ipType: true,
          region: true,
          proxyRisk: true,
          dns: false,
          tcp: false,
          tls: false,
          controlHosts: false,
          webProbe: false,
          environment: false,
          exitBinding: false,
          usageRate: false
        },
        webProbe: { enabled: false }
      }
    },
    externalAccess: { ok: true, results: [] },
    providerScore: {
      verdict: 'BLOCK',
      reasons: [CheckReason.PROVIDER_UNAVAILABLE],
      ipType: 'unknown',
      sources: [
        { source: 'ipwho.is', error: 'fetch failed: ECONNRESET' },
        { source: 'ping0.cc', error: 'fetch failed: ECONNRESET' }
      ]
    },
    staticObservation: { verdict: 'PASS', reason: null },
    environment: { verdict: 'PASS', reasons: [] },
    claudeWeb: { verdict: 'PASS', reasons: [], skipped: true },
    binding: { verdict: 'PASS', reasons: [] },
    usage: null
  });

  assert.match(items.find((item) => item.id === 'ip-type').detail, /ipwho\.is: fetch failed: ECONNRESET/);
  assert.match(items.find((item) => item.id === 'proxy-risk').detail, /ping0\.cc: fetch failed: ECONNRESET/);
});
