const { CheckReason, NetworkVerdict } = require('../shared/constants');

const DEFAULT_USAGE_WINDOW_MS = 10 * 60 * 1000;
const DEFAULT_MAX_TARGET_REQUESTS = 80;

function pruneUsageEvents(events, now, windowMs = DEFAULT_USAGE_WINDOW_MS) {
  return (events || []).filter((event) => now - event.at <= windowMs);
}

function recordTargetUsage({ state, host, now = Date.now(), windowMs = DEFAULT_USAGE_WINDOW_MS, maxRequests = DEFAULT_MAX_TARGET_REQUESTS }) {
  const events = pruneUsageEvents(state.usageEvents, now, windowMs);
  events.push({ at: now, host });
  const risky = events.length > maxRequests;

  return {
    nextEvents: events,
    verdict: risky ? NetworkVerdict.BLOCK : NetworkVerdict.PASS,
    reasons: risky ? [CheckReason.USAGE_RATE_RISK] : [],
    count: events.length,
    windowMs,
    maxRequests
  };
}

module.exports = {
  DEFAULT_USAGE_WINDOW_MS,
  DEFAULT_MAX_TARGET_REQUESTS,
  pruneUsageEvents,
  recordTargetUsage
};
