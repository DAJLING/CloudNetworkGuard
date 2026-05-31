const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { EnvironmentApplierMac } = require('../src/daemon/environment-applier-mac');

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
