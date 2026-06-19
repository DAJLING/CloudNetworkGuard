const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreProviderResults, combineVerdicts } = require('../src/daemon/scoring');
const { CheckReason, NetworkVerdict } = require('../src/shared/constants');

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

test('scoreProviderResults blocks datacenter and proxy risk', () => {
  const score = scoreProviderResults([
    {
      source: 'fixture',
      ip: '198.51.100.2',
      ipType: 'hosting',
      isProxy: true,
      isVpn: false,
      isTor: false,
      riskScore: 80,
      confidence: 50
    },
    safePing0({ ipType: 'hosting', isProxy: true, riskScore: 80 })
  ]);

  assert.equal(score.verdict, NetworkVerdict.BLOCK);
  assert.equal(score.reasons.includes(CheckReason.DATACENTER_IP), true);
  assert.equal(score.reasons.includes(CheckReason.VPN_OR_PROXY_RISK), true);
});

test('scoreProviderResults lets Ping0 residential classification override hosting hints', () => {
  const score = scoreProviderResults([
    {
      source: 'ip-api.com',
      ip: '198.51.100.20',
      ipType: 'hosting',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 15,
      confidence: 25
    },
    safePing0({ ip: '198.51.100.20', ipType: 'residential' })
  ]);

  assert.equal(score.ipType, 'residential');
  assert.equal(score.reasons.includes(CheckReason.DATACENTER_IP), false);
});

test('scoreProviderResults warns for datacenter IP without forcing a block', () => {
  const score = scoreProviderResults([
    safePing0({
      ipType: 'datacenter',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0
    })
  ]);

  assert.equal(score.verdict, NetworkVerdict.WARN);
  assert.equal(score.reasons.includes(CheckReason.DATACENTER_IP), true);
  assert.equal(score.reasons.includes(CheckReason.IP_TYPE_UNCONFIRMED), false);
});

test('scoreProviderResults keeps datacenter-only risk as warning even when score crosses block threshold', () => {
  const score = scoreProviderResults([
    safePing0({
      ipType: 'datacenter',
      riskScore: 30
    })
  ]);

  assert.equal(score.verdict, NetworkVerdict.WARN);
  assert.equal(score.riskScore >= 65, true);
  assert.deepEqual(score.reasons, [CheckReason.DATACENTER_IP]);
});

test('scoreProviderResults blocks mainland China, Hong Kong, and Macau regions', () => {
  for (const countryCode of ['CN', 'HK', 'MO']) {
    const score = scoreProviderResults([
      {
        source: 'fixture',
        ip: '203.0.113.2',
        ipType: 'residential',
        countryCode,
        regionName: countryCode,
        isProxy: false,
        isVpn: false,
        isTor: false,
        riskScore: 0,
        confidence: 90
      },
      safePing0()
    ]);

    assert.equal(score.verdict, NetworkVerdict.BLOCK);
    assert.equal(score.reasons.includes(CheckReason.BLOCKED_REGION), true);
  }
});

test('scoreProviderResults blocks country codes outside Claude supported regions', () => {
  for (const countryCode of ['RU', 'CF', 'NI']) {
    const score = scoreProviderResults([
      {
        source: 'fixture',
        ip: '203.0.113.12',
        ipType: 'residential',
        countryCode,
        regionName: countryCode,
        isProxy: false,
        isVpn: false,
        isTor: false,
        riskScore: 0,
        confidence: 90
      },
      safePing0()
    ]);

    assert.equal(score.verdict, NetworkVerdict.BLOCK);
    assert.equal(score.reasons.includes(CheckReason.BLOCKED_REGION), true);
  }
});

test('scoreProviderResults allows official Mariana Islands region', () => {
  const score = scoreProviderResults([safePing0({ countryCode: 'MP', regionName: 'Mariana Islands' })]);

  assert.equal(score.verdict, NetworkVerdict.PASS);
  assert.equal(score.reasons.includes(CheckReason.BLOCKED_REGION), false);
});

test('scoreProviderResults blocks unknown region only when no source has a known region', () => {
  const unknownOnly = scoreProviderResults([
    {
      source: 'fixture',
      ip: '203.0.113.2',
      ipType: 'residential',
      countryCode: 'unknown',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 90
    },
    safePing0({ countryCode: 'unknown', regionName: 'unknown' })
  ]);

  assert.equal(unknownOnly.verdict, NetworkVerdict.BLOCK);
  assert.equal(unknownOnly.reasons.includes(CheckReason.BLOCKED_REGION), true);

  const knownFallback = scoreProviderResults([
    {
      source: 'fixture-a',
      ip: '203.0.113.2',
      ipType: 'residential',
      countryCode: 'unknown',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 40
    },
    {
      source: 'fixture-b',
      ip: '203.0.113.2',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 50
    },
    safePing0()
  ]);

  assert.equal(knownFallback.reasons.includes(CheckReason.BLOCKED_REGION), false);
});

test('scoreProviderResults blocks when Ping0 risk data is missing', () => {
  const noPing0 = scoreProviderResults([
    {
      source: 'fixture',
      ip: '203.0.113.20',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 90
    }
  ]);

  const ping0Error = scoreProviderResults([
    {
      source: 'fixture',
      ip: '203.0.113.20',
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
  ]);

  const partialPing0 = scoreProviderResults([safePing0({ riskScore: null })]);

  assert.equal(noPing0.verdict, NetworkVerdict.BLOCK);
  assert.equal(noPing0.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), true);
  assert.equal(ping0Error.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), true);
  assert.equal(partialPing0.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), true);
});

test('scoreProviderResults accepts proxycheck risk data when Ping0 is unavailable', () => {
  const score = scoreProviderResults([
    {
      source: 'fixture',
      ip: '203.0.113.20',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 0,
      confidence: 90
    },
    { source: 'ping0.cc', error: 'CAPTCHA_REQUIRED' },
    {
      source: 'proxycheck.io',
      ip: '203.0.113.20',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      isBlacklisted: false,
      riskScore: 12,
      sharedUsers: '设备估计 8',
      sharedUsersMax: 8,
      confidence: 90
    }
  ]);

  assert.equal(score.reasons.includes(CheckReason.IP_RISK_DATA_UNAVAILABLE), false);
  assert.equal(score.verdict, NetworkVerdict.PASS);
  assert.equal(score.sharedUsersMax, 8);
});

test('scoreProviderResults blocks when IP type is unknown', () => {
  const score = scoreProviderResults([safePing0({ ipType: 'unknown' })]);

  assert.equal(score.verdict, NetworkVerdict.BLOCK);
  assert.equal(score.reasons.includes(CheckReason.IP_TYPE_UNCONFIRMED), true);
});

test('scoreProviderResults blocks ping0 risk scores above purity threshold', () => {
  const score = scoreProviderResults([
    {
      source: 'ping0.cc',
      ip: '198.51.100.3',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 31,
      sharedUsers: '10 - 100 (一般)',
      sharedUsersMax: 100,
      confidence: 45
    }
  ]);

  assert.equal(score.verdict, NetworkVerdict.BLOCK);
  assert.equal(score.reasons.includes(CheckReason.VPN_OR_PROXY_RISK), true);
});

test('scoreProviderResults blocks ping0 shared user ranges above threshold', () => {
  const score = scoreProviderResults([
    {
      source: 'ping0.cc',
      ip: '198.51.100.4',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 30,
      sharedUsers: '100 - 1000 (风险)',
      sharedUsersMax: 1000,
      confidence: 45
    }
  ]);

  assert.equal(score.verdict, NetworkVerdict.BLOCK);
  assert.equal(score.reasons.includes(CheckReason.IP_SHARED_USERS_RISK), true);
});

test('scoreProviderResults passes ping0 risk and sharing at threshold', () => {
  const score = scoreProviderResults([
    {
      source: 'ping0.cc',
      ip: '198.51.100.5',
      ipType: 'residential',
      countryCode: 'US',
      regionName: 'United States',
      isProxy: false,
      isVpn: false,
      isTor: false,
      riskScore: 30,
      sharedUsers: '10 - 100 (一般)',
      sharedUsersMax: 100,
      confidence: 45
    }
  ]);

  assert.equal(score.verdict, NetworkVerdict.PASS);
  assert.deepEqual(score.reasons, []);
});

test('combineVerdicts blocks while static residential IP is still observing', () => {
  const combined = combineVerdicts({
    externalAccess: { ok: true },
    providerScore: {
      verdict: NetworkVerdict.PASS,
      reasons: [],
      ipType: 'residential'
    },
    staticObservation: {
      verdict: NetworkVerdict.OBSERVING,
      reason: CheckReason.STATIC_WINDOW_PENDING
    }
  });

  assert.equal(combined.verdict, NetworkVerdict.OBSERVING);
  assert.equal(combined.allowTargetTraffic, false);
  assert.deepEqual(combined.reasons, [CheckReason.STATIC_WINDOW_PENDING]);
});

test('combineVerdicts blocks static residential IP failures', () => {
  const combined = combineVerdicts({
    externalAccess: { ok: true },
    providerScore: {
      verdict: NetworkVerdict.PASS,
      reasons: [],
      ipType: 'residential'
    },
    staticObservation: {
      verdict: NetworkVerdict.BLOCK,
      reason: CheckReason.STATIC_RESIDENTIAL_IP_MISMATCH
    }
  });

  assert.equal(combined.verdict, NetworkVerdict.BLOCK);
  assert.equal(combined.reasons.includes(CheckReason.STATIC_RESIDENTIAL_IP_MISMATCH), true);
});

test('combineVerdicts still blocks provider risk when static IP check is skipped', () => {
  const combined = combineVerdicts({
    externalAccess: { ok: true },
    providerScore: {
      verdict: NetworkVerdict.BLOCK,
      reasons: [CheckReason.VPN_OR_PROXY_RISK],
      ipType: 'residential'
    },
    staticObservation: {
      verdict: NetworkVerdict.PASS,
      reason: null,
      skipped: true
    }
  });

  assert.equal(combined.verdict, NetworkVerdict.BLOCK);
  assert.equal(combined.reasons.includes(CheckReason.VPN_OR_PROXY_RISK), true);
});

test('combineVerdicts allows datacenter IP with a warning reason', () => {
  const combined = combineVerdicts({
    externalAccess: { ok: true },
    providerScore: {
      verdict: NetworkVerdict.WARN,
      reasons: [CheckReason.DATACENTER_IP],
      ipType: 'datacenter'
    },
    staticObservation: {
      verdict: NetworkVerdict.PASS,
      reason: null
    }
  });

  assert.equal(combined.verdict, NetworkVerdict.WARN);
  assert.equal(combined.allowTargetTraffic, true);
  assert.deepEqual(combined.reasons, [CheckReason.DATACENTER_IP]);
});

test('combineVerdicts ignores provider reasons for disabled validation items', () => {
  const combined = combineVerdicts({
    externalAccess: { ok: true, results: [] },
    providerScore: {
      verdict: NetworkVerdict.BLOCK,
      reasons: [CheckReason.BLOCKED_REGION],
      riskScore: 100,
      ipType: 'residential'
    },
    staticObservation: {
      verdict: NetworkVerdict.PASS,
      reason: null
    },
    enabledChecks: {
      staticResidentialIp: false,
      ipType: false,
      region: false,
      proxyRisk: false,
      exitBinding: false
    }
  });

  assert.equal(combined.verdict, NetworkVerdict.PASS);
  assert.equal(combined.reasons.includes(CheckReason.BLOCKED_REGION), false);
});

test('combineVerdicts reports DNS and Claude control failures separately', () => {
  const combined = combineVerdicts({
    externalAccess: {
      ok: false,
      claudeControlOk: false,
      results: [
        {
          host: 'claude.ai',
          ok: false,
          dns: { ok: false, error: 'ENOTFOUND' },
          tcp: { ok: false, error: 'DNS_FAILED' },
          tls: { ok: false, error: 'TCP_FAILED' }
        }
      ]
    },
    providerScore: {
      verdict: NetworkVerdict.PASS,
      reasons: [],
      ipType: 'residential'
    },
    staticObservation: {
      verdict: NetworkVerdict.PASS,
      reason: null
    }
  });

  assert.equal(combined.verdict, NetworkVerdict.BLOCK);
  assert.equal(combined.reasons.includes(CheckReason.DNS_CHECK_FAILED), true);
  assert.equal(combined.reasons.includes(CheckReason.TCP_CHECK_FAILED), false);
  assert.equal(combined.reasons.includes(CheckReason.CLAUDE_CONTROL_CHECK_FAILED), true);
  assert.equal(combined.allowTargetTraffic, false);
});

test('combineVerdicts reports TCP failures when DNS succeeded', () => {
  const combined = combineVerdicts({
    externalAccess: {
      ok: false,
      claudeControlOk: false,
      results: [
        {
          host: 'api.anthropic.com',
          ok: false,
          dns: { ok: true, addresses: ['203.0.113.10'] },
          tcp: { ok: false, error: 'ETIMEDOUT' },
          tls: { ok: false, error: 'TCP_FAILED' }
        }
      ]
    },
    providerScore: {
      verdict: NetworkVerdict.PASS,
      reasons: [],
      ipType: 'residential'
    },
    staticObservation: {
      verdict: NetworkVerdict.PASS,
      reason: null
    }
  });

  assert.equal(combined.reasons.includes(CheckReason.DNS_CHECK_FAILED), false);
  assert.equal(combined.reasons.includes(CheckReason.TCP_CHECK_FAILED), true);
  assert.equal(combined.reasons.includes(CheckReason.CLAUDE_CONTROL_CHECK_FAILED), true);
});
