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

test('buildDiagnosticReport includes environment consistency supported flag', () => {
  const report = buildDiagnosticReport({
    environmentConsistency: {
      supported: true,
      enabled: true,
      deriveFromExitIp: true,
      backup: { hasBackup: true, createdAt: '2026-05-31T01:00:00.000Z' },
      lastTargetProfile: { timeZone: 'America/Chicago', language: 'en-US' },
      lastApplyResult: { ok: true, at: '2026-05-31T01:01:00.000Z', steps: { secret: { ok: true } } }
    }
  });

  assert.equal(report.environmentConsistency.supported, true);
  assert.equal(report.environmentConsistency.backup.createdAt, '2026-05-31T01:00:00.000Z');
  assert.deepEqual(report.environmentConsistency.lastApplyResult, {
    ok: true,
    at: '2026-05-31T01:01:00.000Z'
  });
  assert.equal(JSON.stringify(report).includes('secret'), false);
});

test('buildDiagnosticReport includes monitoring platform rule preview and macOS safety notes', () => {
  const report = buildDiagnosticReport({
    platform: { os: 'darwin' },
    monitoring: {
      enabled: true,
      intervalMinutes: 5,
      lastRunAt: '2026-06-05T00:00:00.000Z',
      lastResult: { verdict: 'PASS', reasons: [] }
    },
    firewall: { mode: 'PF_BLOCK', lastError: null },
    targetConfig: {
      rules: [
        { id: 'api', domainPattern: 'api.example.com', action: 'GUARD' },
        { id: 'docs', domainPattern: 'docs.example.com', action: 'ALLOW' }
      ],
      staticResidentialIp: '203.0.113.10'
    },
    environmentConsistency: { supported: true }
  });

  assert.equal(report.monitoring.enabled, true);
  assert.equal(report.monitoring.intervalMinutes, 5);
  assert.equal(report.platformCapabilities.firewallFallback, 'macos-pf');
  assert.deepEqual(report.targetConfig.rulePreview.guardedDomains, ['api.example.com']);
  assert.equal(JSON.stringify(report).includes('203.0.113.10'), false);
  assert.match(report.safetyNotes.join(' '), /Emergency restore/);
});
