const test = require('node:test');
const assert = require('node:assert/strict');
const { NotificationDeduper, getBlockingNotificationSignature } = require('../src/main/notification-state');

function status({ allowTargetTraffic = false, reasons = ['BLOCKED_REGION'], verdict = 'BLOCK', firewallMode = 'BLOCK' } = {}) {
  return {
    guardState: 'ENABLED',
    guardMode: 'STRICT_VALIDATE',
    firewall: { mode: firewallMode, lastError: null },
    lastCheck: {
      verdict,
      reasons,
      allowTargetTraffic
    }
  };
}

test('getBlockingNotificationSignature ignores repeated reason ordering', () => {
  assert.equal(
    getBlockingNotificationSignature(status({ reasons: ['TCP_CHECK_FAILED', 'DNS_CHECK_FAILED'] })),
    getBlockingNotificationSignature(status({ reasons: ['DNS_CHECK_FAILED', 'TCP_CHECK_FAILED'] }))
  );
});

test('NotificationDeduper only notifies once per blocking state', () => {
  const deduper = new NotificationDeduper();
  assert.equal(deduper.shouldNotifyBlocked(status()), true);
  assert.equal(deduper.shouldNotifyBlocked(status()), false);
  assert.equal(deduper.shouldNotifyBlocked(status({ reasons: ['TCP_CHECK_FAILED'] })), true);
});

test('NotificationDeduper resets after traffic is released', () => {
  const deduper = new NotificationDeduper();
  assert.equal(deduper.shouldNotifyBlocked(status()), true);
  deduper.resetIfReleased(status({ allowTargetTraffic: true, reasons: [] }));
  assert.equal(deduper.shouldNotifyBlocked(status()), true);
});
