const test = require('node:test');
const assert = require('node:assert/strict');
const { EnvironmentConsistencyService } = require('../src/daemon/environment-consistency-service');

test('apply creates backup then applies profile', async () => {
  let saved = false;
  const backupStore = {
    exists: () => false,
    save: (snapshot) => {
      saved = true;
      return snapshot;
    },
    getSummary: () => ({ hasBackup: true, createdAt: '2026-05-30T01:00:00.000Z', path: '/tmp/backup.json' })
  };
  let applyOptions = null;
  const applier = {
    isSupported: () => true,
    isBrowserRunning: async () => [],
    captureCurrentState: async () => ({ version: 1, windows: {} }),
    applyProfile: async (_profile, options) => {
      applyOptions = options;
      return { ok: true, steps: { 'windows.timezone': { ok: true } }, keepChineseInput: true };
    }
  };
  const service = new EnvironmentConsistencyService({
    dataDir: '/tmp',
    backupStore,
    applier,
    platform: 'win32',
    resolveProfile: () => ({
      timeZone: 'America/Chicago',
      windowsTimeZone: 'Central Standard Time',
      language: 'en-US',
      languages: ['en-US'],
      countryCode: 'US',
      derivedFrom: 'exit-ip'
    })
  });

  const result = await service.apply({
    exitIp: { countryCode: 'US', regionName: 'Texas' },
    config: { deriveFromExitIp: true, profileOverride: {} }
  });

  assert.equal(saved, true);
  assert.equal(result.ok, true);
  assert.equal(result.restartRequired, true);
  assert.equal(result.lastTargetProfile.timeZone, 'America/Chicago');
  assert.equal(applyOptions.keepChineseInput, true);
});

test('apply fails fast when browsers are running and browser language changes are enabled', async () => {
  const service = new EnvironmentConsistencyService({
    dataDir: '/tmp',
    backupStore: { exists: () => false, getSummary: () => ({ hasBackup: false, createdAt: null }) },
    applier: {
      isSupported: () => true,
      isBrowserRunning: async () => ['chrome'],
      captureCurrentState: async () => {
        throw new Error('should not capture when browsers are running');
      },
      applyProfile: async () => ({ ok: true, steps: {} })
    },
    platform: 'win32'
  });

  const result = await service.apply({
    exitIp: { countryCode: 'US', regionName: 'Texas' },
    config: { deriveFromExitIp: true, keepChineseInput: false, profileOverride: {} }
  });

  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
});

test('windows apply blocks running browsers even when keeping Chinese input', async () => {
  let applied = false;
  const service = new EnvironmentConsistencyService({
    dataDir: '/tmp',
    backupStore: {
      exists: () => true,
      load: () => ({ version: 1, windows: {} }),
      getSummary: () => ({ hasBackup: true, createdAt: '2026-06-06T01:00:00.000Z' })
    },
    applier: {
      isSupported: () => true,
      isBrowserRunning: async () => ['chrome'],
      applyProfile: async () => {
        applied = true;
        return { ok: true, steps: { 'windows.timezone': { ok: true } } };
      }
    },
    platform: 'win32',
    resolveProfile: () => ({
      timeZone: 'America/Chicago',
      windowsTimeZone: 'Central Standard Time',
      language: 'en-US',
      languages: ['en-US']
    })
  });

  const result = await service.apply({
    exitIp: { countryCode: 'US', regionName: 'Texas' },
    config: { deriveFromExitIp: true, keepChineseInput: true, profileOverride: {} }
  });

  assert.equal(applied, false);
  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
});

test('restore fails without backup', async () => {
  const backupStore = { exists: () => false };
  const service = new EnvironmentConsistencyService({
    dataDir: '/tmp',
    backupStore,
    applier: { isSupported: () => true },
    platform: 'win32'
  });
  const result = await service.restore();
  assert.equal(result.ok, false);
  assert.equal(result.steps.backup.error, 'BACKUP_NOT_FOUND');
});

test('service reports supported on darwin when mac applier supports it', () => {
  const service = new EnvironmentConsistencyService({
    dataDir: '/tmp',
    platform: 'darwin',
    backupStore: { getSummary: () => ({ hasBackup: false, createdAt: null }) },
    applier: { isSupported: () => true }
  });

  assert.equal(service.isSupported(), true);
});

test('darwin apply creates backup and returns restartRequired', async () => {
  let saved = false;
  const service = new EnvironmentConsistencyService({
    dataDir: '/tmp',
    platform: 'darwin',
    backupStore: {
      exists: () => false,
      save: (snapshot) => {
        saved = true;
        return snapshot;
      },
      getSummary: () => ({ hasBackup: true, createdAt: '2026-05-31T01:00:00.000Z' })
    },
    applier: {
      isSupported: () => true,
      isBrowserRunning: async () => [],
      captureCurrentState: async () => ({ version: 1, platform: 'darwin', mac: {} }),
      applyProfile: async () => ({ ok: true, steps: { 'mac.timezone': { ok: true } } })
    },
    resolveProfile: () => ({
      timeZone: 'America/Los_Angeles',
      windowsTimeZone: 'Pacific Standard Time',
      language: 'en-US',
      languages: ['en-US'],
      countryCode: 'US',
      derivedFrom: 'exit-ip'
    })
  });

  const result = await service.apply({
    exitIp: { countryCode: 'US', regionName: 'California' },
    config: { deriveFromExitIp: true, profileOverride: {} }
  });

  assert.equal(saved, true);
  assert.equal(result.ok, true);
  assert.equal(result.restartRequired, true);
  assert.equal(result.lastTargetProfile.timeZone, 'America/Los_Angeles');
});
