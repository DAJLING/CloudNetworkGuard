const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreProviderResults, combineVerdicts } = require('../src/daemon/scoring');
const { CheckReason, NetworkVerdict } = require('../src/shared/constants');

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
    }
  ]);

  assert.equal(score.verdict, NetworkVerdict.BLOCK);
  assert.equal(score.reasons.includes(CheckReason.DATACENTER_IP), true);
  assert.equal(score.reasons.includes(CheckReason.VPN_OR_PROXY_RISK), true);
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
      }
    ]);

    assert.equal(score.verdict, NetworkVerdict.BLOCK);
    assert.equal(score.reasons.includes(CheckReason.BLOCKED_REGION), true);
  }
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
    }
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
    }
  ]);

  assert.equal(knownFallback.reasons.includes(CheckReason.BLOCKED_REGION), false);
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
