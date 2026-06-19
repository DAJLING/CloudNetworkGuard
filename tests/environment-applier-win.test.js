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

test('applyProfile blocks browser preference changes when browser is running', async () => {
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
  }, { keepChineseInput: false });
  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
});

test('applyProfile blocks when browser is running even when keepChineseInput is true', async () => {
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

  const result = await applier.applyProfile(
    { windowsTimeZone: 'Eastern Standard Time', language: 'en-US', languages: ['en-US'] },
    { keepChineseInput: true }
  );

  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
});

test('applyProfile keeps Chinese input and applies WebRTC policy when browsers are closed', async () => {
  let script = '';
  const regCommands = [];
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command, args) => {
      if (command === 'powershell.exe') {
        script = args[args.length - 1] || '';
      }
      if (command === 'tasklist') return 'No tasks are running';
      if (command === 'reg') {
        regCommands.push(args);
        return '';
      }
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
  assert.equal(result.steps['chrome.webrtc'].ok, true);
  assert.equal(result.steps['edge.webrtc'].ok, true);
  assert.equal(regCommands.filter((args) => args.includes('WebRtcIPHandlingPolicy') && args.includes('disable_non_proxied_udp')).length, 2);
});

test('restoreBrowserWebRtc deletes policy when backup had no policy', async () => {
  const regCommands = [];
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command, args) => {
      if (command === 'reg') {
        regCommands.push(args);
        return '';
      }
      return '';
    }
  });

  const result = await applier.restoreBrowserWebRtc('chrome', {
    installed: true,
    webrtcPolicy: null
  });

  assert.equal(result.ok, true);
  assert.equal(regCommands.length, 1);
  assert.deepEqual(regCommands[0].slice(0, 2), ['delete', 'HKCU\\Software\\Policies\\Google\\Chrome']);
});

test('restoreBrowserWebRtc restores previous policy value from backup', async () => {
  const regCommands = [];
  const applier = new EnvironmentApplierWin({
    platform: 'win32',
    execFile: async (command, args) => {
      if (command === 'reg') {
        regCommands.push(args);
        return '';
      }
      return '';
    }
  });

  const result = await applier.restoreBrowserWebRtc('edge', {
    installed: true,
    webrtcPolicy: 'default_public_interface_only'
  });

  assert.equal(result.ok, true);
  assert.equal(regCommands.length, 1);
  assert.equal(regCommands[0][0], 'add');
  assert.equal(regCommands[0].includes('default_public_interface_only'), true);
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
