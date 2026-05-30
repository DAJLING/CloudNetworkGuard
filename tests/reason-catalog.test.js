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
