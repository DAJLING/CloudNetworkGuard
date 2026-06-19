const { CheckReason, NetworkVerdict } = require('../shared/constants');

const BLOCKED_TIME_ZONES = new Set(['Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Macau', 'Asia/Chongqing', 'Asia/Harbin']);
const BLOCKED_LANGUAGES = ['zh-CN', 'zh-HK', 'zh-MO'];

function normalizeLanguage(language) {
  return String(language || '').trim();
}

function buildEnvironmentCheckInput(clientEnvironment = {}, consistency = {}) {
  const consistencyActive =
    consistency.enabled === true && consistency.lastApplyResult && consistency.lastApplyResult.ok === true;
  const keepChineseInput = consistency.keepChineseInput !== false;
  const merged = {
    ...clientEnvironment,
    browserWebRtc: clientEnvironment.browserWebRtc || null,
    keepChineseInput,
    trustConsistencyLanguage: keepChineseInput,
    trustConsistencyWebRtc: consistencyActive
  };

  if (consistencyActive && !keepChineseInput && consistency.lastTargetProfile && consistency.lastTargetProfile.language) {
    merged.language = consistency.lastTargetProfile.language;
    merged.languages =
      consistency.lastTargetProfile.languages && consistency.lastTargetProfile.languages.length
        ? consistency.lastTargetProfile.languages
        : [consistency.lastTargetProfile.language];
  }

  return merged;
}

function checkClientEnvironment(environment = {}) {
  const reasons = [];
  const timeZone = environment.timeZone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown';
  const language = normalizeLanguage(environment.language || Intl.DateTimeFormat().resolvedOptions().locale);
  const languages = Array.isArray(environment.languages) ? environment.languages.map(normalizeLanguage) : [];

  if (BLOCKED_TIME_ZONES.has(timeZone)) reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  const trustLanguage =
    environment.trustConsistencyLanguage === true || environment.keepChineseInput === true;
  if (!trustLanguage && [language, ...languages].some((item) => BLOCKED_LANGUAGES.includes(item))) {
    reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  }

  const trustWebRtc =
    environment.trustConsistencyWebRtc === true ||
    environment.trustConsistencyLanguage === true ||
    environment.ignoreWebRtcLocalIp === true;
  if (!trustWebRtc && environment.webRtcLocalIpCount && environment.webRtcLocalIpCount > 0) {
    reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  }
  const browserWebRtc = environment.browserWebRtc || null;
  if (browserWebRtc && browserWebRtc.supported !== false && browserWebRtc.ok === false) {
    reasons.push(CheckReason.ENVIRONMENT_MISMATCH);
  }

  return {
    verdict: reasons.length ? NetworkVerdict.BLOCK : NetworkVerdict.PASS,
    reasons: Array.from(new Set(reasons)),
    timeZone,
    language,
    languages,
    webRtcLocalIpCount: environment.webRtcLocalIpCount || 0,
    browserWebRtc,
    webRtcCheckSkipped: trustWebRtc && environment.webRtcLocalIpCount > 0,
    languageCheckSkipped: trustLanguage && [language, ...languages].some((item) => BLOCKED_LANGUAGES.includes(item))
  };
}

module.exports = {
  BLOCKED_TIME_ZONES,
  BLOCKED_LANGUAGES,
  buildEnvironmentCheckInput,
  checkClientEnvironment
};
