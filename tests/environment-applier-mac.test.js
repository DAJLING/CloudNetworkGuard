const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { isDeepStrictEqual } = require('node:util');
const { EnvironmentApplierMac, localeFromLanguage } = require('../src/daemon/environment-applier-mac');

function memoryFs(files = {}) {
  const calls = [];
  return {
    calls,
    existsSync: (filePath) => Object.prototype.hasOwnProperty.call(files, filePath),
    readFileSync: (filePath) => files[filePath],
    writeFileSync: (filePath, content) => {
      calls.push({ method: 'writeFileSync', filePath, content });
      files[filePath] = content;
    },
    renameSync: (from, to) => {
      calls.push({ method: 'renameSync', from, to });
      files[to] = files[from];
      delete files[from];
    },
    mkdirSync: () => {}
  };
}

test('captureCurrentState captures mac timezone and browser preferences', async () => {
  const homeDir = '/Users/alice';
  const chromePrefs = path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Preferences');
  const fsImpl = memoryFs({
    [chromePrefs]: JSON.stringify({
      intl: { accept_languages: 'zh-CN,zh' },
      webrtc: { ip_handling_policy: 'default' }
    })
  });
  const calls = [];
  const runner = {
    run: async (command, args) => {
      calls.push({ command, args });
      if (command === 'systemsetup') return 'Time Zone: Asia/Shanghai\n';
      if (command === 'defaults' && args.includes('AppleLanguages')) return '(\n    "zh-Hans-CN",\n    "en-US"\n)\n';
      if (command === 'defaults' && args.includes('AppleLocale')) return 'zh_CN\n';
      if (command === 'pgrep') throw new Error('not used');
      return '';
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', homeDir, fsImpl, runner });

  const state = await applier.captureCurrentState();

  assert.equal(state.platform, 'darwin');
  assert.equal(state.mac.timeZone, 'Asia/Shanghai');
  assert.deepEqual(state.mac.appleLanguages, ['zh-Hans-CN', 'en-US']);
  assert.equal(state.mac.appleLocale, 'zh_CN');
  assert.equal(state.chrome.installed, true);
  assert.equal(state.chrome.intlAcceptLanguages, 'zh-CN,zh');
  assert.equal(state.chrome.webrtcPreference, 'default');
});

test('isBrowserRunning detects Chrome and Edge with pgrep', async () => {
  const runner = {
    run: async (command, args) => {
      assert.equal(command, 'pgrep');
      if (JSON.stringify(args) === JSON.stringify(['-x', 'Google Chrome'])) return '123\n';
      if (JSON.stringify(args) === JSON.stringify(['-x', 'Microsoft Edge'])) return '456\n';
      throw new Error(`unexpected args: ${JSON.stringify(args)}`);
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', runner });

  assert.deepEqual(await applier.isBrowserRunning(), ['chrome', 'edge']);
});

test('localeFromLanguage normalizes all language subtags', () => {
  assert.equal(localeFromLanguage('en-US'), 'en_US');
  assert.equal(localeFromLanguage('zh-Hans-CN'), 'zh_Hans_CN');
});

test('patchBrowserPreferences updates intl and WebRTC fields atomically', () => {
  const prefsPath = '/tmp/Preferences';
  const files = {
    [prefsPath]: JSON.stringify({ intl: { accept_languages: 'zh-CN,zh' } })
  };
  const fsImpl = memoryFs(files);
  const applier = new EnvironmentApplierMac({ platform: 'darwin', fsImpl });

  applier.patchBrowserPreferences(prefsPath, {
    acceptLanguages: 'en-US',
    webRtcPolicy: 'disable_non_proxied_udp'
  });

  assert.deepEqual(
    fsImpl.calls.map((call) => call.method),
    ['writeFileSync', 'renameSync']
  );
  assert.equal(fsImpl.calls[0].filePath, `${prefsPath}.ng-tmp`);
  assert.equal(fsImpl.calls[1].from, `${prefsPath}.ng-tmp`);
  assert.equal(fsImpl.calls[1].to, prefsPath);
  const prefs = JSON.parse(files[prefsPath]);
  assert.equal(prefs.intl.accept_languages, 'en-US');
  assert.equal(prefs.webrtc.ip_handling_policy, 'disable_non_proxied_udp');
});

test('patchBrowserPreferences preserves existing preference file mode', () => {
  const prefsPath = '/tmp/Preferences';
  const files = {
    [prefsPath]: JSON.stringify({ intl: { accept_languages: 'zh-CN,zh' } })
  };
  const fsImpl = {
    ...memoryFs(files),
    statSync: (filePath) => {
      assert.equal(filePath, prefsPath);
      return { mode: 0o100600 };
    },
    chmodSync: (filePath, mode) => {
      fsImpl.calls.push({ method: 'chmodSync', filePath, mode });
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', fsImpl });

  applier.patchBrowserPreferences(prefsPath, {
    acceptLanguages: 'en-US'
  });

  assert.deepEqual(
    fsImpl.calls.map((call) => call.method),
    ['writeFileSync', 'chmodSync', 'renameSync']
  );
  assert.equal(fsImpl.calls[1].filePath, `${prefsPath}.ng-tmp`);
  assert.equal(fsImpl.calls[1].mode, 0o100600);
  assert.equal(fsImpl.calls[2].from, `${prefsPath}.ng-tmp`);
  assert.equal(fsImpl.calls[2].to, prefsPath);
});

test('applyProfile applies timezone and skips language when keeping Chinese input', async () => {
  const privileged = [];
  const runner = {
    run: async () => '',
    runPrivilegedCommands: async (commands) => {
      privileged.push(commands);
      return '';
    }
  };
  const applier = new EnvironmentApplierMac({
    platform: 'darwin',
    runner,
    fsImpl: memoryFs({})
  });
  applier.isBrowserRunning = async () => [];

  const result = await applier.applyProfile(
    { timeZone: 'America/Chicago', language: 'en-US', languages: ['en-US'] },
    { keepChineseInput: true }
  );

  assert.equal(result.ok, true);
  assert.equal(result.steps['mac.timezone'].ok, true);
  assert.equal(result.steps['mac.language'].skipped, true);
  assert.equal(result.steps['mac.language'].reason, 'KEEP_CHINESE_INPUT');
  assert.equal(result.steps['chrome.language'].skipped, true);
  assert.equal(result.steps['chrome.language'].reason, 'KEEP_CHINESE_INPUT');
  assert.equal(result.steps['edge.language'].skipped, true);
  assert.equal(result.steps['edge.language'].reason, 'KEEP_CHINESE_INPUT');
  assert.deepEqual(privileged[0], [['systemsetup', '-settimezone', 'America/Chicago']]);
});

test('applyTimeZone rejects empty timezone before privileged mutation', async () => {
  const privileged = [];
  const runner = {
    runPrivilegedCommands: async (commands) => {
      privileged.push(commands);
      throw new Error('unexpected privileged command');
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', runner });

  const result = await applier.applyTimeZone('');

  assert.equal(result.ok, false);
  assert.equal(result.error, 'TIMEZONE_EMPTY');
  assert.deepEqual(privileged, []);
});

test('applyLanguage derives AppleLocale from first language written', async () => {
  const commands = [];
  const runner = {
    run: async (command, args) => {
      commands.push([command, args]);
      return '';
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', runner });

  const result = await applier.applyLanguage('en-US', ['fr-FR']);

  assert.equal(result.ok, true);
  assert.deepEqual(commands, [
    ['defaults', ['write', 'NSGlobalDomain', 'AppleLanguages', '-array', 'fr-FR']],
    ['defaults', ['write', 'NSGlobalDomain', 'AppleLocale', 'fr_FR']]
  ]);
});

test('restoreLanguage deletes AppleLocale when original locale was absent', async () => {
  const commands = [];
  const runner = {
    run: async (command, args) => {
      commands.push([command, args]);
      return '';
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', runner });

  const result = await applier.restoreLanguage({ appleLanguages: [], appleLocale: '' });

  assert.equal(result.ok, true);
  assert.deepEqual(commands, [
    ['defaults', ['delete', 'NSGlobalDomain', 'AppleLocale']]
  ]);
});

test('applyProfile patches browser language when keepChineseInput is false', async () => {
  const homeDir = '/Users/alice';
  const chromePrefs = path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Preferences');
  const edgePrefs = path.join(homeDir, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Preferences');
  const files = {
    [chromePrefs]: JSON.stringify({ intl: { accept_languages: 'zh-CN,zh' } }),
    [edgePrefs]: JSON.stringify({})
  };
  const runner = {
    run: async () => '',
    runPrivilegedCommands: async () => ''
  };
  const applier = new EnvironmentApplierMac({
    platform: 'darwin',
    homeDir,
    runner,
    fsImpl: memoryFs(files)
  });
  applier.isBrowserRunning = async () => [];

  const result = await applier.applyProfile(
    { timeZone: 'Europe/London', language: 'en-GB', languages: ['en-GB'] },
    { keepChineseInput: false }
  );

  assert.equal(result.ok, true);
  assert.equal(result.steps['mac.language'].ok, true);
  assert.equal(JSON.parse(files[chromePrefs]).intl.accept_languages, 'en-GB');
  assert.equal(JSON.parse(files[edgePrefs]).webrtc.ip_handling_policy, 'disable_non_proxied_udp');
});

test('applyProfile fails fast when browsers are running', async () => {
  const mutations = [];
  const runner = {
    run: async (command, args = []) => {
      mutations.push({ type: 'run', command, args });
      throw new Error(`unexpected command: ${command}`);
    },
    runPrivilegedCommands: async (commands) => {
      mutations.push({ type: 'privileged', commands });
      throw new Error('unexpected privileged command');
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', runner });
  applier.isBrowserRunning = async () => ['chrome', 'edge'];
  applier.patchBrowserPreferences = () => {
    mutations.push({ type: 'preferences' });
    throw new Error('unexpected browser preferences patch');
  };

  const result = await applier.applyProfile({
    timeZone: 'America/New_York',
    language: 'en-US',
    languages: ['en-US']
  });

  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
  assert.deepEqual(result.steps.preflight.running, ['chrome', 'edge']);
  assert.deepEqual(mutations, []);
});

test('restoreFromBackup restores timezone, language, and browser preferences', async () => {
  const homeDir = '/Users/alice';
  const chromePrefs = path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Preferences');
  const files = {
    [chromePrefs]: JSON.stringify({
      intl: { accept_languages: 'en-US' },
      webrtc: { ip_handling_policy: 'disable_non_proxied_udp' }
    })
  };
  const privileged = [];
  const commands = [];
  const expectedCommands = [
    ['defaults', ['write', 'NSGlobalDomain', 'AppleLanguages', '-array', 'zh-Hans-CN', 'en-US']],
    ['defaults', ['write', 'NSGlobalDomain', 'AppleLocale', 'zh_CN']]
  ];
  const runner = {
    run: async (command, args) => {
      const call = [command, args];
      commands.push(call);
      if (expectedCommands.some((expected) => isDeepStrictEqual(expected, call))) {
        return '';
      }
      throw new Error(`unexpected command: ${command} ${args.join(' ')}`);
    },
    runPrivilegedCommands: async (commands) => {
      privileged.push(commands);
      return '';
    }
  };
  const applier = new EnvironmentApplierMac({
    platform: 'darwin',
    homeDir,
    runner,
    fsImpl: memoryFs(files)
  });
  applier.isBrowserRunning = async () => [];

  const result = await applier.restoreFromBackup({
    platform: 'darwin',
    mac: {
      timeZone: 'Asia/Shanghai',
      appleLanguages: ['zh-Hans-CN', 'en-US'],
      appleLocale: 'zh_CN'
    },
    chrome: {
      installed: true,
      preferencesPath: chromePrefs,
      intlAcceptLanguages: 'zh-CN,zh',
      webrtcPreference: null
    },
    edge: { installed: false }
  });

  assert.equal(result.ok, true);
  assert.equal(result.steps['mac.timezone'].ok, true);
  assert.equal(result.steps['mac.language'].ok, true);
  assert.deepEqual(privileged[0], [['systemsetup', '-settimezone', 'Asia/Shanghai']]);
  assert.deepEqual(commands, expectedCommands);
  const prefs = JSON.parse(files[chromePrefs]);
  assert.equal(prefs.intl.accept_languages, 'zh-CN,zh');
  assert.equal(prefs.webrtc.ip_handling_policy, undefined);
});

test('restoreFromBackup removes browser language when original preference was absent', async () => {
  const homeDir = '/Users/alice';
  const chromePrefs = path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Preferences');
  const files = {
    [chromePrefs]: JSON.stringify({
      intl: { accept_languages: 'en-US' }
    })
  };
  const runner = {
    run: async () => '',
    runPrivilegedCommands: async () => ''
  };
  const applier = new EnvironmentApplierMac({
    platform: 'darwin',
    homeDir,
    runner,
    fsImpl: memoryFs(files)
  });
  applier.isBrowserRunning = async () => [];

  const result = await applier.restoreFromBackup({
    platform: 'darwin',
    chrome: {
      installed: true,
      preferencesPath: chromePrefs,
      intlAcceptLanguages: null
    },
    edge: { installed: false }
  });

  assert.equal(result.ok, true);
  const prefs = JSON.parse(files[chromePrefs]);
  assert.equal(prefs.intl.accept_languages, undefined);
});
