const test = require('node:test');
const assert = require('node:assert/strict');
const { CheckReason } = require('../src/shared/constants');
const { reasonCatalog, getReasonGuidance, getTopReasonGuidance } = require('../src/shared/reason-catalog');

test('reason catalog covers every CheckReason', () => {
  for (const reason of Object.values(CheckReason)) {
    assert.ok(reasonCatalog[reason], `${reason} is missing guidance`);
    assert.ok(reasonCatalog[reason].title, `${reason} is missing title`);
    assert.ok(reasonCatalog[reason].explanation, `${reason} is missing explanation`);
    assert.ok(['info', 'warning', 'block'].includes(reasonCatalog[reason].severity), `${reason} has invalid severity`);
    assert.ok(Array.isArray(reasonCatalog[reason].actions), `${reason} is missing actions`);
  }
});

test('getReasonGuidance returns a safe fallback for unknown reasons', () => {
  const guidance = getReasonGuidance('NEW_REASON');

  assert.equal(guidance.reason, 'NEW_REASON');
  assert.equal(guidance.severity, 'warning');
  assert.ok(guidance.title);
});

test('getTopReasonGuidance picks the highest-priority reason', () => {
  const guidance = getTopReasonGuidance(['PROVIDER_UNAVAILABLE', 'STATIC_RESIDENTIAL_IP_MISMATCH']);

  assert.equal(guidance.reason, 'STATIC_RESIDENTIAL_IP_MISMATCH');
});

test('getTopReasonGuidance puts warning-only IP type guidance behind blocking errors', () => {
  const guidance = getTopReasonGuidance([CheckReason.DATACENTER_IP, CheckReason.ENVIRONMENT_MISMATCH]);

  assert.equal(reasonCatalog[CheckReason.DATACENTER_IP].severity, 'warning');
  assert.equal(guidance.reason, CheckReason.ENVIRONMENT_MISMATCH);
});

test('Ping0 risk data guidance opens manual verification first', () => {
  const guidance = getReasonGuidance(CheckReason.IP_RISK_DATA_UNAVAILABLE);

  assert.equal(guidance.actions[0].id, 'open-ping0-verify');
  assert.equal(guidance.actions[0].tone, 'primary');
});
