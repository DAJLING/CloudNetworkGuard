const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { EnvironmentBackupStore } = require('../src/daemon/environment-backup-store');

test('EnvironmentBackupStore saves and loads snapshot', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-backup-'));
  const store = new EnvironmentBackupStore(path.join(tmp, 'environment-backup.json'));
  const snapshot = {
    version: 1,
    createdAt: new Date().toISOString(),
    platform: 'win32',
    windows: { timeZoneId: 'China Standard Time' }
  };
  store.save(snapshot);
  assert.deepEqual(store.load(), snapshot);
});

test('EnvironmentBackupStore getSummary when missing', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-backup-'));
  const store = new EnvironmentBackupStore(path.join(tmp, 'missing.json'));
  assert.deepEqual(store.getSummary(), {
    hasBackup: false,
    createdAt: null,
    path: store.filePath
  });
});
