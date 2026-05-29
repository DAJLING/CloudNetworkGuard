const test = require('node:test');
const assert = require('node:assert/strict');
const { checkClientEnvironment } = require('../src/daemon/environment-checker');
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
