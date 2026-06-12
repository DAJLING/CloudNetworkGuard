const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('dns').promises;
const { dnsProbe, NetworkChecker } = require('../src/daemon/network-checker');

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
