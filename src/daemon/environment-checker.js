const { CheckReason, NetworkVerdict } = require('../shared/constants');

const BLOCKED_TIME_ZONES = new Set(['Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Macau', 'Asia/Chongqing', 'Asia/Harbin']);
const BLOCKED_LANGUAGES = ['zh-CN', 'zh-HK', 'zh-MO'];

function normalizeLanguage(language) {
  return String(language || '').trim();
}

function checkClientEnvironment(environment = {}) {
  const reasons = [];
  const timeZone = environment.timeZone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown';
  const language = normalizeLanguage(environment.language || Intl.DateTimeFormat().resolvedOptions().locale);
  const languages = Array.isArray(environment.languages) ? environment.languages.map(normalizeLanguage) : [];

  if (BLOCKED_TIME_ZONES.has(timeZone)) reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  if ([language, ...languages].some((item) => BLOCKED_LANGUAGES.includes(item))) {
    reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  }

  if (environment.webRtcLocalIpCount && environment.webRtcLocalIpCount > 0) {
    reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  }

  return {
    verdict: reasons.length ? NetworkVerdict.BLOCK : NetworkVerdict.PASS,
    reasons: Array.from(new Set(reasons)),
    timeZone,
    language,
    languages,
    webRtcLocalIpCount: environment.webRtcLocalIpCount || 0
  };
}

module.exports = {
  BLOCKED_TIME_ZONES,
  BLOCKED_LANGUAGES,
  checkClientEnvironment
};
