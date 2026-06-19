const { GuardState } = require('../shared/constants');

function normalizeReasons(reasons) {
  return Array.from(new Set(reasons || [])).sort();
}

function getBlockingNotificationSignature(status) {
  if (!status || status.guardState !== GuardState.ENABLED) return null;
  const check = status.lastCheck;
  if (!check || check.allowTargetTraffic === true) return null;

  return JSON.stringify({
    guardState: status.guardState,
    guardMode: status.guardMode || 'AUTO',
    verdict: check.verdict || 'UNKNOWN',
    reasons: normalizeReasons(check.reasons),
    firewallMode: status.firewall ? status.firewall.mode : 'UNKNOWN',
    firewallError: status.firewall ? status.firewall.lastError || null : null
  });
}

class NotificationDeduper {
  constructor() {
    this.lastBlockingSignature = null;
  }

  shouldNotifyBlocked(status) {
    const signature = getBlockingNotificationSignature(status);
    if (!signature) {
      this.lastBlockingSignature = null;
      return false;
    }

    if (signature === this.lastBlockingSignature) return false;
    this.lastBlockingSignature = signature;
    return true;
  }

  resetIfReleased(status) {
    if (!getBlockingNotificationSignature(status)) {
      this.lastBlockingSignature = null;
    }
  }
}

module.exports = {
  NotificationDeduper,
  getBlockingNotificationSignature
};
