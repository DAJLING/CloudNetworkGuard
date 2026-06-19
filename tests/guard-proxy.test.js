const test = require('node:test');
const assert = require('node:assert/strict');
const { GuardProxy } = require('../src/daemon/guard-proxy');
const { GuardState } = require('../src/shared/constants');

test('GuardProxy awaits guarded target request decision', async () => {
  const proxy = new GuardProxy({
    getStatus: () => ({ guardState: GuardState.ENABLED }),
    getTargetRules: () => [{ id: 'claude', domainPattern: 'claude.ai', action: 'GUARD' }],
    onTargetRequest: async (host) => ({ block: host === 'claude.ai', reasons: ['BLOCKED_REGION'] })
  });

  const decision = await proxy.evaluateTargetRequest('claude.ai');

  assert.equal(decision.block, true);
  assert.deepEqual(decision.reasons, ['BLOCKED_REGION']);
});

test('GuardProxy bypasses request gate when guard is disabled', async () => {
  let calls = 0;
  const proxy = new GuardProxy({
    getStatus: () => ({ guardState: GuardState.DISABLED }),
    getTargetRules: () => [{ id: 'claude', domainPattern: 'claude.ai', action: 'GUARD' }],
    onTargetRequest: async () => {
      calls += 1;
      return { block: true, reasons: ['BLOCKED_REGION'] };
    }
  });

  const decision = await proxy.evaluateTargetRequest('claude.ai');

  assert.equal(decision.block, false);
  assert.equal(calls, 0);
});
