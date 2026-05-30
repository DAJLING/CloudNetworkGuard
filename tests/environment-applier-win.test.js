const test = require('node:test');
const assert = require('node:assert/strict');
const { EnvironmentApplierWin } = require('../src/daemon/environment-applier-win');

test('captureCurrentState returns windows timezone from mock exec', async () => {
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command, args) => {
      const script = args[args.length - 1] || '';
      if (script.includes('Get-TimeZone')) return 'China Standard Time\r\n';
      if (script.includes('Get-WinUserLanguageList')) return '[{"LanguageId":"zh-Hans"}]';
      throw new Error(`unexpected: ${command} ${script}`);
    },
    fsImpl: {
      existsSync: () => false,
      readFileSync: () => '{}',
      writeFileSync: () => {},
      renameSync: () => {}
    }
  });

  const state = await applier.captureCurrentState();
  assert.equal(state.windows.timeZoneId, 'China Standard Time');
  assert.equal(state.chrome.installed, false);
});

test('applyProfile blocks when browser is running', async () => {
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command) => {
      if (command === 'tasklist') return 'chrome.exe   123 Console';
      return '';
    },
    fsImpl: {
      existsSync: () => true,
      readFileSync: () => '{"intl":{"accept_languages":"zh-CN"}}',
      writeFileSync: () => {},
      renameSync: () => {}
    }
  });

  const result = await applier.applyProfile({
    windowsTimeZone: 'Central Standard Time',
    language: 'en-US',
    languages: ['en-US']
  });
  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
});

test('applyProfile keeps Chinese input when keepChineseInput is true', async () => {
  let script = '';
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command, args) => {
      if (command === 'powershell.exe') {
        script = args[args.length - 1] || '';
      }
      if (command === 'tasklist') return 'INFO: No tasks';
      if (command === 'reg') return '';
      if (command === 'tzutil') return '';
      return '';
    },
    fsImpl: {
      existsSync: (p) => String(p).includes('Chrome') || String(p).includes('Edge'),
      readFileSync: () => '{"intl":{"accept_languages":"zh-CN"}}',
      writeFileSync: () => {},
      renameSync: () => {}
    }
  });

  const result = await applier.applyProfile(
    { windowsTimeZone: 'Eastern Standard Time', language: 'en-US', languages: ['en-US'] },
    { keepChineseInput: true }
  );

  assert.equal(result.ok, true);
  assert.equal(result.keepChineseInput, true);
  assert.equal(result.steps['windows.language'].skipped, true);
  assert.equal(result.steps['windows.language'].reason, 'KEEP_CHINESE_INPUT');
  assert.doesNotMatch(script, /Set-WinUserLanguageList/);
});

test('restoreWindowsLanguages rebuilds full user language list from backup', async () => {
  let script = '';
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command, args) => {
      if (command === 'powershell.exe') {
        script = args[args.length - 1] || '';
        return '';
      }
      return '';
    },
    fsImpl: {
      existsSync: () => false,
      readFileSync: () => '{}',
      writeFileSync: () => {},
      renameSync: () => {}
    }
  });

  const result = await applier.restoreWindowsLanguages([
    { LanguageId: 'zh-Hans', LanguageTag: 'zh-CN' },
    { LanguageId: 'en-US' }
  ]);

  assert.equal(result.ok, true);
  assert.match(script, /New-WinUserLanguageList 'zh-Hans'/);
  assert.match(script, /\$list\.Add\('en-US'\)/);
});

test('isSupported is false on non-windows', () => {
  const applier = new EnvironmentApplierWin({ platform: 'darwin' });
  assert.equal(applier.isSupported(), false);
});
