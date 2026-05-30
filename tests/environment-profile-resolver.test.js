const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveEnvironmentProfile } = require('../src/daemon/environment-profile-resolver');

test('resolveEnvironmentProfile maps US Texas to Central', () => {
  const profile = resolveEnvironmentProfile({
    countryCode: 'US',
    regionName: 'Texas, United States'
  });
  assert.equal(profile.timeZone, 'America/Chicago');
  assert.equal(profile.windowsTimeZone, 'Central Standard Time');
  assert.equal(profile.language, 'en-US');
  assert.deepEqual(profile.languages, ['en-US']);
});

test('resolveEnvironmentProfile maps US California to Pacific', () => {
  const profile = resolveEnvironmentProfile({
    countryCode: 'US',
    regionName: 'California'
  });
  assert.equal(profile.timeZone, 'America/Los_Angeles');
  assert.equal(profile.windowsTimeZone, 'Pacific Standard Time');
});

test('resolveEnvironmentProfile maps GB to London', () => {
  const profile = resolveEnvironmentProfile({ countryCode: 'GB', regionName: 'England' });
  assert.equal(profile.timeZone, 'Europe/London');
  assert.equal(profile.language, 'en-GB');
});

test('resolveEnvironmentProfile prefers user override', () => {
  const profile = resolveEnvironmentProfile(
    { countryCode: 'US', regionName: 'California' },
    { timeZone: 'Europe/London', language: 'en-GB' }
  );
  assert.equal(profile.timeZone, 'Europe/London');
  assert.equal(profile.language, 'en-GB');
  assert.equal(profile.derivedFrom, 'override');
});

test('resolveEnvironmentProfile defaults unknown country to US Eastern', () => {
  const profile = resolveEnvironmentProfile({ countryCode: 'XX', regionName: null });
  assert.equal(profile.timeZone, 'America/New_York');
  assert.equal(profile.derivedFrom, 'fallback');
});
