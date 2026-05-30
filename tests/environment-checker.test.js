const test = require('node:test');
const assert = require('node:assert/strict');
const { checkClientEnvironment, buildEnvironmentCheckInput } = require('../src/daemon/environment-checker');
const { CheckReason, NetworkVerdict } = require('../src/shared/constants');

test('checkClientEnvironment blocks mainland/HK/Macau browser environments', () => {
  const result = checkClientEnvironment({
    timeZone: 'Asia/Shanghai',
    language: 'zh-CN',
    languages: ['zh-CN', 'en-US'],
    webRtcLocalIpCount: 0
  });

  assert.equal(result.verdict, NetworkVerdict.BLOCK);
  assert.equal(result.reasons.includes(CheckReason.ENVIRONMENT_MISMATCH), true);
});

test('checkClientEnvironment passes neutral environment values', () => {
  const result = checkClientEnvironment({
    timeZone: 'America/New_York',
    language: 'en-US',
    languages: ['en-US'],
    webRtcLocalIpCount: 0
  });

  assert.equal(result.verdict, NetworkVerdict.PASS);
  assert.deepEqual(result.reasons, []);
});

test('checkClientEnvironment skips language block when Chinese input is kept during alignment', () => {
  const result = checkClientEnvironment({
    timeZone: 'America/New_York',
    language: 'zh-CN',
    languages: ['zh-CN', 'en-US'],
    webRtcLocalIpCount: 0,
    trustConsistencyLanguage: true
  });

  assert.equal(result.verdict, NetworkVerdict.PASS);
  assert.equal(result.languageCheckSkipped, true);
});

test('checkClientEnvironment skips language block when keepChineseInput is set (detect path)', () => {
  const result = checkClientEnvironment({
    timeZone: 'America/New_York',
    language: 'zh-CN',
    languages: ['zh-CN', 'en-US'],
    webRtcLocalIpCount: 0,
    keepChineseInput: true
  });

  assert.equal(result.verdict, NetworkVerdict.PASS);
  assert.equal(result.languageCheckSkipped, true);
});

test('checkClientEnvironment skips webRtc block when consistency alignment is trusted', () => {
  const result = checkClientEnvironment({
    timeZone: 'America/New_York',
    language: 'en-US',
    languages: ['en-US'],
    webRtcLocalIpCount: 2,
    trustConsistencyWebRtc: true
  });

  assert.equal(result.verdict, NetworkVerdict.PASS);
  assert.equal(result.webRtcCheckSkipped, true);
});

test('buildEnvironmentCheckInput reports aligned language without changing Electron locale', () => {
  const merged = buildEnvironmentCheckInput(
    { language: 'zh-CN', languages: ['zh-CN', 'en-US'] },
    {
      enabled: true,
      keepChineseInput: false,
      lastApplyResult: { ok: true },
      lastTargetProfile: { language: 'en-US', languages: ['en-US'] }
    }
  );

  assert.equal(merged.language, 'en-US');
  assert.deepEqual(merged.languages, ['en-US']);
  assert.equal(merged.keepChineseInput, false);
  assert.equal(merged.trustConsistencyLanguage, false);
});

test('buildEnvironmentCheckInput keeps zh-CN when keepChineseInput is enabled', () => {
  const merged = buildEnvironmentCheckInput(
    { language: 'zh-CN', languages: ['zh-CN', 'en-US'] },
    {
      enabled: true,
      keepChineseInput: true,
      lastApplyResult: { ok: true },
      lastTargetProfile: { language: 'en-US', languages: ['en-US'] }
    }
  );

  assert.equal(merged.language, 'zh-CN');
  assert.deepEqual(merged.languages, ['zh-CN', 'en-US']);
  assert.equal(merged.trustConsistencyLanguage, true);
});
