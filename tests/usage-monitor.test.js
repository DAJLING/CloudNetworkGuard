const test = require('node:test');
const assert = require('node:assert/strict');
const { recordTargetUsage } = require('../src/daemon/usage-monitor');
const { CheckReason, NetworkVerdict } = require('../src/shared/constants');

test('recordTargetUsage blocks when target request rate exceeds threshold', () => {
  const state = {
    usageEvents: [
      { at: 1000, host: 'claude.ai' },
      { at: 1100, host: 'claude.ai' }
    ]
  };
  const result = recordTargetUsage({
    state,
    host: 'claude.ai',
    now: 1200,
    windowMs: 1000,
    maxRequests: 2
  });

  assert.equal(result.verdict, NetworkVerdict.BLOCK);
  assert.equal(result.reasons.includes(CheckReason.USAGE_RATE_RISK), true);
});
