const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDiagnosticReport } = require('../src/daemon/diagnostic-report');

test('buildDiagnosticReport returns latest check without full IP exposure', () => {
  const report = buildDiagnosticReport({
    guardState: 'ENABLED',
    lastCheck: {
      checkedAt: '2026-05-30T00:00:00.000Z',
      verdict: 'BLOCK',
      reasons: ['DATACENTER_IP'],
      ip: {
        maskedIp: '203.0.x.x',
        countryCode: 'US',
        regionName: 'United States',
        asn: 'AS64500',
        riskScore: 90,
        confidence: 60
      },
      providers: [{ source: 'fixture', ip: '203.0.113.10', riskScore: 90, confidence: 60 }],
      externalAccess: { results: [{ host: 'claude.ai', dns: { ok: true }, tcp: { ok: false, error: 'TIMEOUT' }, tls: { ok: false } }] }
    },
    firewall: { mode: 'BLOCK', rules: [] },
    targetConfig: { staticResidentialIp: '203.0.113.10' },
    binding: { bound: true, currentMaskedIp: '203.0.x.x' }
  });

  assert.equal(report.verdict, 'BLOCK');
  assert.equal(JSON.stringify(report).includes('203.0.113.10'), false);
  assert.equal(report.exitIp.maskedIp, '203.0.x.x');
  assert.equal(report.providers[0].source, 'fixture');
  assert.equal(report.targetConfig.staticResidentialIp, 'configured');
});

test('buildDiagnosticReport handles missing checks', () => {
  const report = buildDiagnosticReport({ guardState: 'DISABLED' });

  assert.equal(report.verdict, 'UNKNOWN');
  assert.deepEqual(report.reasons, []);
  assert.deepEqual(report.providers, []);
});

test('buildDiagnosticReport includes environmentConsistency summary', () => {
  const report = buildDiagnosticReport({
    guardState: 'DISABLED',
    environmentConsistency: {
      enabled: true,
      deriveFromExitIp: true,
      lastTargetProfile: { timeZone: 'America/Chicago', language: 'en-US' },
      backup: { hasBackup: true, createdAt: '2026-05-30T01:00:00.000Z' },
      lastApplyResult: { ok: true, at: '2026-05-30T02:00:00.000Z' }
    }
  });

  assert.equal(report.environmentConsistency.enabled, true);
  assert.equal(report.environmentConsistency.backup.createdAt, '2026-05-30T01:00:00.000Z');
  assert.equal(report.environmentConsistency.lastTargetProfile.timeZone, 'America/Chicago');
});
