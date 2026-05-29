const test = require('node:test');
const assert = require('node:assert/strict');
const { observeStaticIp } = require('../src/daemon/static-ip-observer');
const { CheckReason, NetworkVerdict } = require('../src/shared/constants');

test('observeStaticIp requires the configured stability window', () => {
  const first = observeStaticIp({
    currentIp: '203.0.113.10',
    now: 1000,
    storeState: null,
    salt: 'salt',
    staticWindowMs: 5000
  });

  assert.equal(first.verdict, NetworkVerdict.OBSERVING);
  assert.equal(first.reason, CheckReason.STATIC_WINDOW_PENDING);

  const second = observeStaticIp({
    currentIp: '203.0.113.10',
    now: 7000,
    storeState: first.nextState,
    salt: 'salt',
    staticWindowMs: 5000
  });

  assert.equal(second.verdict, NetworkVerdict.PASS);
  assert.equal(second.reason, null);
});

test('observeStaticIp detects IP changes without storing the full IP', () => {
  const first = observeStaticIp({
    currentIp: '203.0.113.10',
    now: 1000,
    storeState: null,
    salt: 'salt',
    staticWindowMs: 5000
  });
  const changed = observeStaticIp({
    currentIp: '203.0.113.11',
    now: 2000,
    storeState: first.nextState,
    salt: 'salt',
    staticWindowMs: 5000
  });

  assert.equal(changed.verdict, NetworkVerdict.OBSERVING);
  assert.equal(changed.reason, CheckReason.IP_CHANGED);
  assert.equal(changed.nextState.maskedIp, '203.0.x.x');
  assert.equal(Object.prototype.hasOwnProperty.call(changed.nextState, 'ip'), false);
});
