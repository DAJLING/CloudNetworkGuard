const crypto = require('crypto');
const { CheckReason, NetworkVerdict } = require('../shared/constants');

const DEFAULT_STATIC_WINDOW_MS = 24 * 60 * 60 * 1000;

function hashIp(ip, salt) {
  return crypto.createHash('sha256').update(`${salt}:${ip}`).digest('hex');
}

function maskIp(ip) {
  if (!ip) return null;
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return `${parts.slice(0, 2).join(':')}:...`;
  }
  const parts = ip.split('.');
  if (parts.length !== 4) return 'masked';
  return `${parts[0]}.${parts[1]}.x.x`;
}

function observeStaticIp({ currentIp, now = Date.now(), storeState, salt, staticWindowMs = DEFAULT_STATIC_WINDOW_MS }) {
  if (!currentIp) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reason: CheckReason.PROVIDER_UNAVAILABLE,
      nextState: storeState || null
    };
  }

  const currentHash = hashIp(currentIp, salt);
  const existing = storeState && storeState.ipHash === currentHash ? storeState : null;
  const firstSeenAt = existing ? existing.firstSeenAt : now;
  const nextState = {
    ipHash: currentHash,
    maskedIp: maskIp(currentIp),
    firstSeenAt,
    lastSeenAt: now
  };

  if (storeState && storeState.ipHash && storeState.ipHash !== currentHash) {
    return {
      verdict: NetworkVerdict.OBSERVING,
      reason: CheckReason.IP_CHANGED,
      nextState
    };
  }

  if (now - firstSeenAt < staticWindowMs) {
    return {
      verdict: NetworkVerdict.OBSERVING,
      reason: CheckReason.STATIC_WINDOW_PENDING,
      nextState
    };
  }

  return {
    verdict: NetworkVerdict.PASS,
    reason: null,
    nextState
  };
}

module.exports = {
  hashIp,
  maskIp,
  observeStaticIp
};
