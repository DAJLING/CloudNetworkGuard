# macOS Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make macOS match the Windows guard feature surface by adding macOS environment consistency apply/restore and `pf` direct-client fallback blocking.

**Architecture:** Add focused macOS units rather than branching through the Windows applier: a narrow macOS command runner, `EnvironmentApplierMac`, platform selection in `EnvironmentConsistencyService`, and a macOS `pf` backend in `FirewallManager`. Existing renderer, IPC, store, and GuardService flows stay shared, with small status/documentation updates for macOS modes.

**Tech Stack:** Electron 42, Node.js CommonJS, Node test runner, macOS `systemsetup`, `defaults`, `pgrep`, AppleScript administrator authorization, and `pfctl`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/daemon/macos-command-runner.js` | Quote shell arguments, run unprivileged commands, and run privileged macOS shell scripts through AppleScript authorization. |
| `tests/macos-command-runner.test.js` | Verify quoting, command joining, and privileged AppleScript invocation without mutating the host. |
| `src/daemon/environment-applier-mac.js` | Capture, apply, and restore macOS time zone, language/locale, Chrome/Edge language, and Chrome/Edge WebRTC settings. |
| `tests/environment-applier-mac.test.js` | Verify macOS capture, browser preflight, apply, restore, and preference patching using mocked dependencies. |
| `src/daemon/environment-consistency-service.js` | Select Windows or macOS environment applier by platform and report support on both platforms. |
| `tests/environment-consistency-service.test.js` | Cover `darwin` support and macOS apply flow orchestration. |
| `src/daemon/firewall-manager.js` | Add injectable dependencies and a macOS `pf` backend alongside the existing Windows backend. |
| `tests/firewall-manager.test.js` | Cover `pf` rule rendering, `pf.conf` patching, macOS apply/clear command flow, and failure results. |
| `src/daemon/guard-service.js` | Preserve shared status behavior and ensure macOS firewall success modes are treated as valid firewall results. |
| `tests/guard-service.test.js` | Cover macOS support status and firewall decoration for `PF_BLOCK` / `PF_CLEARED`. |
| `src/daemon/diagnostic-report.js` | Include environment consistency `supported` in the diagnostic summary. |
| `tests/diagnostic-report.test.js` | Verify `supported` is summarized without leaking backup contents. |
| `src/renderer/renderer.js` | Make environment consistency restart guidance platform-neutral. |
| `tests/renderer-static.test.js` | Verify there is no Windows-only restart copy for the shared environment consistency flow. |
| `README.md` | Document macOS `pf` fallback and administrator authorization behavior. |

## Scope Check

The spec covers two related platform parity subsystems: environment consistency and direct-client fallback blocking. They share the same user-facing guard flow and both need to be complete for macOS parity, so keep them in one implementation plan with independent, testable tasks.

---

### Task 1: macOS Command Runner

**Files:**
- Create: `src/daemon/macos-command-runner.js`
- Create: `tests/macos-command-runner.test.js`

- [ ] **Step 1: Write the failing tests**

```javascript
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MacCommandRunner,
  quoteShellArg,
  joinShellCommand
} = require('../src/daemon/macos-command-runner');

test('quoteShellArg wraps values safely for shell scripts', () => {
  assert.equal(quoteShellArg('/Library/Application Support/App'), "'/Library/Application Support/App'");
  assert.equal(quoteShellArg("Bob's Mac"), "'Bob'\\''s Mac'");
  assert.equal(quoteShellArg(''), "''");
});

test('joinShellCommand quotes command arguments', () => {
  assert.equal(
    joinShellCommand(['/usr/sbin/systemsetup', '-settimezone', 'America/Los_Angeles']),
    "'/usr/sbin/systemsetup' '-settimezone' 'America/Los_Angeles'"
  );
});

test('runPrivilegedScript invokes osascript with administrator privileges', async () => {
  const calls = [];
  const runner = new MacCommandRunner({
    execFile: async (command, args) => {
      calls.push({ command, args });
      return 'ok';
    }
  });

  const output = await runner.runPrivilegedScript('echo ready');

  assert.equal(output, 'ok');
  assert.equal(calls[0].command, 'osascript');
  assert.deepEqual(calls[0].args, [
    '-e',
    'do shell script "echo ready" with administrator privileges'
  ]);
});

test('writeFilePrivileged writes via a temporary base64 script', async () => {
  const calls = [];
  const runner = new MacCommandRunner({
    execFile: async (command, args) => {
      calls.push({ command, args });
      return '';
    }
  });

  await runner.writeFilePrivileged('/etc/pf.anchors/example', 'block drop out quick to 203.0.113.10\n');

  assert.equal(calls[0].command, 'osascript');
  assert.match(calls[0].args[1], /base64 --decode/);
  assert.match(calls[0].args[1], /mv/);
  assert.doesNotMatch(calls[0].args[1], /203\.0\.113\.10/);
});
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
node --test tests/macos-command-runner.test.js
```

Expected: FAIL with `Cannot find module '../src/daemon/macos-command-runner'`.

- [ ] **Step 3: Implement the macOS command runner**

Create `src/daemon/macos-command-runner.js` with:

```javascript
const { execFile } = require('child_process');

const DEFAULT_TIMEOUT_MS = 45000;

function execFilePromise(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      { windowsHide: true, ...options },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(String(stderr || stdout || error.message).trim() || error.message));
          return;
        }
        resolve(stdout);
      }
    );

    if (options.timeoutMs) {
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error('COMMAND_TIMEOUT'));
      }, options.timeoutMs);
      child.once('exit', () => clearTimeout(timer));
    }
  });
}

function quoteShellArg(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function escapeAppleScriptString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function joinShellCommand(parts = []) {
  return parts.map(quoteShellArg).join(' ');
}

class MacCommandRunner {
  constructor({ execFile: customExecFile = null, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.execFile = customExecFile || ((command, args) => execFilePromise(command, args, { timeoutMs }));
    this.timeoutMs = timeoutMs;
  }

  async run(command, args = []) {
    return this.execFile(command, args);
  }

  async runCommand(parts = []) {
    if (!parts.length) throw new Error('COMMAND_EMPTY');
    const [command, ...args] = parts;
    return this.run(command, args);
  }

  async runPrivilegedScript(script) {
    const escaped = escapeAppleScriptString(script);
    return this.run('osascript', ['-e', `do shell script "${escaped}" with administrator privileges`]);
  }

  async runPrivilegedCommands(commands = []) {
    if (!commands.length) return '';
    const script = commands.map(joinShellCommand).join(' && ');
    return this.runPrivilegedScript(script);
  }

  async writeFilePrivileged(filePath, content) {
    const encoded = Buffer.from(String(content), 'utf8').toString('base64');
    const tempPath = `${filePath}.network-guard-tmp`;
    const script = [
      `printf %s ${quoteShellArg(encoded)} | base64 --decode > ${quoteShellArg(tempPath)}`,
      `mv ${quoteShellArg(tempPath)} ${quoteShellArg(filePath)}`,
      `chmod 0644 ${quoteShellArg(filePath)}`
    ].join(' && ');
    return this.runPrivilegedScript(script);
  }

  async removeFilePrivileged(filePath) {
    return this.runPrivilegedScript(`rm -f ${quoteShellArg(filePath)}`);
  }
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  MacCommandRunner,
  quoteShellArg,
  joinShellCommand,
  execFilePromise
};
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```powershell
node --test tests/macos-command-runner.test.js
```

Expected: PASS, all four tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/daemon/macos-command-runner.js tests/macos-command-runner.test.js
git commit -m "feat: add macos privileged command runner"
```

---

### Task 2: macOS Environment Applier Capture and Browser Helpers

**Files:**
- Create: `src/daemon/environment-applier-mac.js`
- Create: `tests/environment-applier-mac.test.js`

- [ ] **Step 1: Write failing capture and helper tests**

```javascript
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { EnvironmentApplierMac } = require('../src/daemon/environment-applier-mac');

function memoryFs(files = {}) {
  return {
    existsSync: (filePath) => Object.prototype.hasOwnProperty.call(files, filePath),
    readFileSync: (filePath) => files[filePath],
    writeFileSync: (filePath, content) => {
      files[filePath] = content;
    },
    renameSync: (from, to) => {
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
      if (command === 'pgrep' && args.includes('Google Chrome')) return '123\n';
      if (command === 'pgrep' && args.includes('Microsoft Edge')) throw new Error('not running');
      return '';
    }
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', runner });

  assert.deepEqual(await applier.isBrowserRunning(), ['chrome']);
});

test('patchBrowserPreferences updates intl and WebRTC fields atomically', () => {
  const prefsPath = '/tmp/Preferences';
  const files = {
    [prefsPath]: JSON.stringify({ intl: { accept_languages: 'zh-CN,zh' } })
  };
  const applier = new EnvironmentApplierMac({ platform: 'darwin', fsImpl: memoryFs(files) });

  applier.patchBrowserPreferences(prefsPath, {
    acceptLanguages: 'en-US',
    webRtcPolicy: 'disable_non_proxied_udp'
  });

  const prefs = JSON.parse(files[prefsPath]);
  assert.equal(prefs.intl.accept_languages, 'en-US');
  assert.equal(prefs.webrtc.ip_handling_policy, 'disable_non_proxied_udp');
});
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
node --test tests/environment-applier-mac.test.js
```

Expected: FAIL with `Cannot find module '../src/daemon/environment-applier-mac'`.

- [ ] **Step 3: Implement capture, preflight, and preference helpers**

Create `src/daemon/environment-applier-mac.js` with:

```javascript
const fs = require('fs');
const os = require('os');
const path = require('path');
const { MacCommandRunner } = require('./macos-command-runner');

const WEBRTC_POLICY = 'disable_non_proxied_udp';
const BROWSER_REGISTRY = {
  chrome: {
    processName: 'Google Chrome',
    preferencesParts: ['Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Preferences']
  },
  edge: {
    processName: 'Microsoft Edge',
    preferencesParts: ['Library', 'Application Support', 'Microsoft Edge', 'Default', 'Preferences']
  }
};

function stepResult(ok, error = null, extra = {}) {
  return { ok, error, ...extra };
}

function parseSystemsetupTimeZone(output) {
  const match = String(output || '').match(/Time Zone:\s*(.+)$/im);
  return match ? match[1].trim() : String(output || '').trim();
}

function parseDefaultsArray(output) {
  return String(output || '')
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^"|"[,]?$/g, '').replace(/,$/, ''))
    .filter((line) => line && line !== '(' && line !== ')');
}

function localeFromLanguage(language) {
  const normalized = String(language || 'en-US').replace('-', '_');
  return normalized || 'en_US';
}

class EnvironmentApplierMac {
  constructor({
    platform = process.platform,
    homeDir = os.homedir(),
    fsImpl = fs,
    runner = new MacCommandRunner()
  } = {}) {
    this.platform = platform;
    this.homeDir = homeDir;
    this.fs = fsImpl;
    this.runner = runner;
  }

  isSupported() {
    return this.platform === 'darwin';
  }

  getBrowserPreferencesPath(browserId) {
    const browser = BROWSER_REGISTRY[browserId];
    return path.join(this.homeDir, ...browser.preferencesParts);
  }

  async captureCurrentState() {
    if (!this.isSupported()) throw new Error('UNSUPPORTED_PLATFORM');

    const timeZoneOutput = await this.runner.run('systemsetup', ['-gettimezone']);
    const languagesOutput = await this.runner
      .run('defaults', ['read', 'NSGlobalDomain', 'AppleLanguages'])
      .catch(() => '');
    const localeOutput = await this.runner
      .run('defaults', ['read', 'NSGlobalDomain', 'AppleLocale'])
      .catch(() => '');

    return {
      version: 1,
      createdAt: new Date().toISOString(),
      platform: 'darwin',
      mac: {
        timeZone: parseSystemsetupTimeZone(timeZoneOutput),
        appleLanguages: parseDefaultsArray(languagesOutput),
        appleLocale: String(localeOutput || '').trim()
      },
      chrome: this.captureBrowserState('chrome'),
      edge: this.captureBrowserState('edge')
    };
  }

  captureBrowserState(browserId) {
    const preferencesPath = this.getBrowserPreferencesPath(browserId);
    const installed = this.fs.existsSync(preferencesPath);
    const snapshot = {
      installed,
      preferencesPath,
      intlAcceptLanguages: null,
      webrtcPolicy: null,
      webrtcPreference: null,
      webrtcPolicyApplied: false
    };

    if (!installed) return snapshot;

    const prefs = this.readPreferences(preferencesPath);
    snapshot.intlAcceptLanguages = prefs.intl && prefs.intl.accept_languages ? prefs.intl.accept_languages : null;
    snapshot.webrtcPreference =
      prefs.webrtc && prefs.webrtc.ip_handling_policy ? prefs.webrtc.ip_handling_policy : null;
    snapshot.webrtcPolicyApplied = snapshot.webrtcPreference === WEBRTC_POLICY;
    return snapshot;
  }

  readPreferences(preferencesPath) {
    return JSON.parse(this.fs.readFileSync(preferencesPath, 'utf8'));
  }

  async isBrowserRunning() {
    const running = [];
    for (const [browserId, browser] of Object.entries(BROWSER_REGISTRY)) {
      try {
        await this.runner.run('pgrep', ['-x', browser.processName]);
        running.push(browserId);
      } catch {
        continue;
      }
    }
    return running;
  }

  patchBrowserPreferences(preferencesPath, { acceptLanguages = null, webRtcPolicy = null }) {
    if (!this.fs.existsSync(preferencesPath)) throw new Error('PREFERENCES_NOT_FOUND');
    const prefs = this.readPreferences(preferencesPath);
    if (acceptLanguages !== null) {
      prefs.intl = prefs.intl || {};
      prefs.intl.accept_languages = acceptLanguages;
    }
    if (webRtcPolicy !== null) {
      prefs.webrtc = prefs.webrtc || {};
      prefs.webrtc.ip_handling_policy = webRtcPolicy;
    }
    const tempPath = `${preferencesPath}.ng-tmp`;
    this.fs.writeFileSync(tempPath, JSON.stringify(prefs));
    this.fs.renameSync(tempPath, preferencesPath);
  }
}

module.exports = {
  EnvironmentApplierMac,
  BROWSER_REGISTRY,
  WEBRTC_POLICY,
  parseSystemsetupTimeZone,
  parseDefaultsArray,
  localeFromLanguage
};
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```powershell
node --test tests/environment-applier-mac.test.js
```

Expected: PASS, all three tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/daemon/environment-applier-mac.js tests/environment-applier-mac.test.js
git commit -m "feat: capture macos environment state"
```

---

### Task 3: macOS Environment Apply and Restore

**Files:**
- Modify: `src/daemon/environment-applier-mac.js`
- Modify: `tests/environment-applier-mac.test.js`

- [ ] **Step 1: Add failing apply and restore tests**

Append these tests to `tests/environment-applier-mac.test.js`:

```javascript
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
  assert.deepEqual(privileged[0], [['systemsetup', '-settimezone', 'America/Chicago']]);
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
  const applier = new EnvironmentApplierMac({ platform: 'darwin' });
  applier.isBrowserRunning = async () => ['chrome', 'edge'];

  const result = await applier.applyProfile({
    timeZone: 'America/New_York',
    language: 'en-US',
    languages: ['en-US']
  });

  assert.equal(result.ok, false);
  assert.equal(result.steps.preflight.error, 'BROWSER_RUNNING');
  assert.deepEqual(result.steps.preflight.running, ['chrome', 'edge']);
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
  const runner = {
    run: async () => '',
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
  const prefs = JSON.parse(files[chromePrefs]);
  assert.equal(prefs.intl.accept_languages, 'zh-CN,zh');
  assert.equal(prefs.webrtc.ip_handling_policy, undefined);
});
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
node --test tests/environment-applier-mac.test.js
```

Expected: FAIL with `applier.applyProfile is not a function`.

- [ ] **Step 3: Implement apply and restore methods**

Update `src/daemon/environment-applier-mac.js` by adding these methods inside `EnvironmentApplierMac`:

```javascript
  async applyProfile(profile, { keepChineseInput = true } = {}) {
    if (!this.isSupported()) {
      return { ok: false, steps: { platform: stepResult(false, 'UNSUPPORTED_PLATFORM') } };
    }

    const running = await this.isBrowserRunning();
    if (running.length) {
      return {
        ok: false,
        steps: {
          preflight: stepResult(false, 'BROWSER_RUNNING', { running })
        }
      };
    }

    const steps = {};
    steps['mac.timezone'] = await this.applyTimeZone(profile.timeZone);

    if (keepChineseInput) {
      steps['mac.language'] = stepResult(true, null, { skipped: true, reason: 'KEEP_CHINESE_INPUT' });
      steps['chrome.language'] = stepResult(true, null, { skipped: true, reason: 'KEEP_CHINESE_INPUT' });
      steps['edge.language'] = stepResult(true, null, { skipped: true, reason: 'KEEP_CHINESE_INPUT' });
    } else {
      steps['mac.language'] = await this.applyLanguage(profile.language, profile.languages);
      steps['chrome.language'] = await this.applyBrowserLanguage('chrome', profile);
      steps['edge.language'] = await this.applyBrowserLanguage('edge', profile);
    }

    steps['chrome.webrtc'] = await this.applyBrowserWebRtc('chrome');
    steps['edge.webrtc'] = await this.applyBrowserWebRtc('edge');

    return {
      ok: Object.values(steps).every((step) => step.ok),
      keepChineseInput,
      steps
    };
  }

  async restoreFromBackup(backup) {
    if (!this.isSupported()) {
      return { ok: false, steps: { platform: stepResult(false, 'UNSUPPORTED_PLATFORM') } };
    }

    const running = await this.isBrowserRunning();
    if (running.length) {
      return {
        ok: false,
        steps: {
          preflight: stepResult(false, 'BROWSER_RUNNING', { running })
        }
      };
    }

    const steps = {};
    steps['mac.timezone'] = await this.applyTimeZone(backup.mac && backup.mac.timeZone);
    steps['mac.language'] = await this.restoreLanguage(backup.mac || {});
    steps['chrome.language'] = await this.restoreBrowserLanguage('chrome', backup.chrome);
    steps['chrome.webrtc'] = await this.restoreBrowserWebRtc('chrome', backup.chrome);
    steps['edge.language'] = await this.restoreBrowserLanguage('edge', backup.edge);
    steps['edge.webrtc'] = await this.restoreBrowserWebRtc('edge', backup.edge);

    return {
      ok: Object.values(steps).every((step) => step.ok),
      steps
    };
  }

  async applyTimeZone(timeZone) {
    try {
      if (!timeZone) return stepResult(false, 'TIMEZONE_EMPTY');
      await this.runner.runPrivilegedCommands([['systemsetup', '-settimezone', timeZone]]);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async applyLanguage(language, languages = []) {
    try {
      const finalLanguages = languages.length ? languages : [language || 'en-US'];
      await this.runner.run('defaults', ['write', 'NSGlobalDomain', 'AppleLanguages', '-array', ...finalLanguages]);
      await this.runner.run('defaults', ['write', 'NSGlobalDomain', 'AppleLocale', localeFromLanguage(finalLanguages[0])]);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async restoreLanguage(macBackup = {}) {
    try {
      const languages = Array.isArray(macBackup.appleLanguages) ? macBackup.appleLanguages.filter(Boolean) : [];
      if (languages.length) {
        await this.runner.run('defaults', ['write', 'NSGlobalDomain', 'AppleLanguages', '-array', ...languages]);
      }
      if (macBackup.appleLocale) {
        await this.runner.run('defaults', ['write', 'NSGlobalDomain', 'AppleLocale', macBackup.appleLocale]);
      }
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async applyBrowserLanguage(browserId, profile) {
    const preferencesPath = this.getBrowserPreferencesPath(browserId);
    if (!this.fs.existsSync(preferencesPath)) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      const acceptLanguages = (profile.languages && profile.languages.length ? profile.languages : [profile.language]).join(',');
      this.patchBrowserPreferences(preferencesPath, { acceptLanguages });
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async applyBrowserWebRtc(browserId) {
    const preferencesPath = this.getBrowserPreferencesPath(browserId);
    if (!this.fs.existsSync(preferencesPath)) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      this.patchBrowserPreferences(preferencesPath, { webRtcPolicy: WEBRTC_POLICY });
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async restoreBrowserLanguage(browserId, backupSection = {}) {
    if (!backupSection || !backupSection.installed) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      if (backupSection.intlAcceptLanguages !== null && backupSection.intlAcceptLanguages !== undefined) {
        this.patchBrowserPreferences(backupSection.preferencesPath || this.getBrowserPreferencesPath(browserId), {
          acceptLanguages: backupSection.intlAcceptLanguages
        });
      }
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async restoreBrowserWebRtc(browserId, backupSection = {}) {
    if (!backupSection || !backupSection.installed) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      const preferencesPath = backupSection.preferencesPath || this.getBrowserPreferencesPath(browserId);
      if (!this.fs.existsSync(preferencesPath)) {
        return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
      }
      const prefs = this.readPreferences(preferencesPath);
      prefs.webrtc = prefs.webrtc || {};
      if (backupSection.webrtcPreference === null || backupSection.webrtcPreference === undefined) {
        delete prefs.webrtc.ip_handling_policy;
      } else {
        prefs.webrtc.ip_handling_policy = backupSection.webrtcPreference;
      }
      const tempPath = `${preferencesPath}.ng-tmp`;
      this.fs.writeFileSync(tempPath, JSON.stringify(prefs));
      this.fs.renameSync(tempPath, preferencesPath);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }
```

- [ ] **Step 4: Run the macOS applier tests**

Run:

```powershell
node --test tests/environment-applier-mac.test.js
```

Expected: PASS, all seven tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/daemon/environment-applier-mac.js tests/environment-applier-mac.test.js
git commit -m "feat: apply and restore macos environment"
```

---

### Task 4: Platform Selection in Environment Consistency Service

**Files:**
- Modify: `src/daemon/environment-consistency-service.js`
- Modify: `tests/environment-consistency-service.test.js`

- [ ] **Step 1: Add failing macOS service tests**

Append these tests to `tests/environment-consistency-service.test.js`:

```javascript
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
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
node --test tests/environment-consistency-service.test.js
```

Expected: FAIL because `isSupported()` still checks `this.platform === 'win32'`.

- [ ] **Step 3: Update service platform selection**

Replace the top imports in `src/daemon/environment-consistency-service.js` with:

```javascript
const path = require('path');
const { EnvironmentBackupStore } = require('./environment-backup-store');
const { EnvironmentApplierWin } = require('./environment-applier-win');
const { EnvironmentApplierMac } = require('./environment-applier-mac');
const { resolveEnvironmentProfile } = require('./environment-profile-resolver');
```

Add this helper above the class:

```javascript
function createPlatformApplier(platform) {
  if (platform === 'darwin') return new EnvironmentApplierMac({ platform });
  return new EnvironmentApplierWin({ platform });
}
```

Replace the constructor applier assignment with:

```javascript
    this.applier = applier || createPlatformApplier(platform);
```

Replace `isSupported()` with:

```javascript
  isSupported() {
    return (this.platform === 'win32' || this.platform === 'darwin') && this.applier.isSupported();
  }
```

Export the helper for focused tests:

```javascript
module.exports = {
  EnvironmentConsistencyService,
  createPlatformApplier
};
```

- [ ] **Step 4: Run service and existing Windows applier tests**

Run:

```powershell
node --test tests/environment-consistency-service.test.js tests/environment-applier-win.test.js
```

Expected: PASS. Windows service behavior stays unchanged; macOS service is now supported when the applier supports it.

- [ ] **Step 5: Commit**

```bash
git add src/daemon/environment-consistency-service.js tests/environment-consistency-service.test.js
git commit -m "feat: select environment applier by platform"
```

---

### Task 5: macOS pf Rule Rendering and pf.conf Patching

**Files:**
- Modify: `src/daemon/firewall-manager.js`
- Modify: `tests/firewall-manager.test.js`

- [ ] **Step 1: Add failing pf helper tests**

Append these tests to `tests/firewall-manager.test.js`:

```javascript
test('renderPfBlockRule renders IPv4 and IPv6 target set', () => {
  const { renderPfBlockRule } = require('../src/daemon/firewall-manager');
  assert.equal(
    renderPfBlockRule(['203.0.113.10', '2001:db8::10']),
    'block drop out quick to { 203.0.113.10, 2001:db8::10 }'
  );
});

test('renderPfBlockRule rejects invalid IP literals', () => {
  const { renderPfBlockRule } = require('../src/daemon/firewall-manager');
  assert.throws(() => renderPfBlockRule(['api.anthropic.com']), /INVALID_PF_IP/);
});

test('ensurePfAnchorBlock adds one marked anchor block', () => {
  const { ensurePfAnchorBlock, PF_CONF_BLOCK_START, PF_CONF_BLOCK_END } = require('../src/daemon/firewall-manager');
  const once = ensurePfAnchorBlock('set skip on lo0\n');
  const twice = ensurePfAnchorBlock(once);

  assert.match(once, new RegExp(PF_CONF_BLOCK_START));
  assert.match(once, /anchor "com\.local\.claude-network-guard"/);
  assert.match(once, /load anchor "com\.local\.claude-network-guard"/);
  assert.match(once, new RegExp(PF_CONF_BLOCK_END));
  assert.equal(twice, once);
});

test('removePfAnchorBlock removes only the marked block', () => {
  const { ensurePfAnchorBlock, removePfAnchorBlock } = require('../src/daemon/firewall-manager');
  const patched = ensurePfAnchorBlock('set skip on lo0\npass out all\n');

  assert.equal(removePfAnchorBlock(patched), 'set skip on lo0\npass out all\n');
});
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
node --test tests/firewall-manager.test.js
```

Expected: FAIL because the pf helper exports do not exist.

- [ ] **Step 3: Add pf constants and helper functions**

In `src/daemon/firewall-manager.js`, add these constants near the existing constants:

```javascript
const PF_ANCHOR_NAME = 'com.local.claude-network-guard';
const PF_ANCHOR_PATH = `/etc/pf.anchors/${PF_ANCHOR_NAME}`;
const PF_CONF_PATH = '/etc/pf.conf';
const PF_CONF_BLOCK_START = '# ClaudeNetworkGuard START';
const PF_CONF_BLOCK_END = '# ClaudeNetworkGuard END';
```

Add these helper functions after `sanitizeRuleName()`:

```javascript
function isValidIpLiteral(value) {
  const text = String(value || '').trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) {
    return text.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return /^[0-9a-fA-F:]+$/.test(text) && text.includes(':');
}

function renderPfBlockRule(ips = []) {
  const unique = Array.from(new Set(ips.map((ip) => String(ip || '').trim()).filter(Boolean)));
  if (!unique.length) throw new Error('PF_IPS_EMPTY');
  for (const ip of unique) {
    if (!isValidIpLiteral(ip)) throw new Error(`INVALID_PF_IP:${ip}`);
  }
  return `block drop out quick to { ${unique.join(', ')} }`;
}

function removePfAnchorBlock(content = '') {
  const pattern = new RegExp(`${PF_CONF_BLOCK_START}[\\s\\S]*?${PF_CONF_BLOCK_END}\\r?\\n?`, 'g');
  return String(content || '').replace(pattern, '');
}

function ensurePfAnchorBlock(content = '') {
  const cleaned = removePfAnchorBlock(content);
  const block = [
    PF_CONF_BLOCK_START,
    `anchor "${PF_ANCHOR_NAME}"`,
    `load anchor "${PF_ANCHOR_NAME}" from "${PF_ANCHOR_PATH}"`,
    PF_CONF_BLOCK_END
  ].join(os.EOL);
  return `${cleaned.replace(/\s+$/g, '')}${cleaned.trim() ? os.EOL : ''}${block}${os.EOL}`;
}
```

Add the new exports at the bottom:

```javascript
  PF_ANCHOR_NAME,
  PF_ANCHOR_PATH,
  PF_CONF_PATH,
  PF_CONF_BLOCK_START,
  PF_CONF_BLOCK_END,
  renderPfBlockRule,
  ensurePfAnchorBlock,
  removePfAnchorBlock,
  isValidIpLiteral,
```

- [ ] **Step 4: Run the firewall tests**

Run:

```powershell
node --test tests/firewall-manager.test.js
```

Expected: PASS, including existing hosts-block tests.

- [ ] **Step 5: Commit**

```bash
git add src/daemon/firewall-manager.js tests/firewall-manager.test.js
git commit -m "feat: add macos pf rule helpers"
```

---

### Task 6: macOS pf Apply and Clear Backend

**Files:**
- Modify: `src/daemon/firewall-manager.js`
- Modify: `tests/firewall-manager.test.js`

- [ ] **Step 1: Add failing macOS firewall backend tests**

Append these tests to `tests/firewall-manager.test.js`:

```javascript
test('applyMacBlock writes anchor, patches pf.conf, and loads pf', async () => {
  const files = {
    '/etc/pf.conf': 'set skip on lo0\n'
  };
  const privilegedWrites = [];
  const privilegedCommands = [];
  const manager = new FirewallManager({
    hosts: ['api.anthropic.com'],
    platform: 'darwin',
    fsImpl: {
      existsSync: (filePath) => Object.prototype.hasOwnProperty.call(files, filePath),
      readFileSync: (filePath) => files[filePath],
      writeFileSync: (filePath, content) => {
        files[filePath] = content;
      }
    },
    resolveTargetIpsImpl: async () => ({
      ips: ['203.0.113.10'],
      results: [{ host: 'api.anthropic.com', ips: ['203.0.113.10'], errors: [] }]
    }),
    macRunner: {
      writeFilePrivileged: async (filePath, content) => {
        privilegedWrites.push({ filePath, content });
        files[filePath] = content;
      },
      removeFilePrivileged: async (filePath) => {
        delete files[filePath];
      },
      runPrivilegedCommands: async (commands) => {
        privilegedCommands.push(commands);
        return '';
      }
    }
  });

  const result = await manager.applyBlock();

  assert.equal(result.mode, 'PF_BLOCK');
  assert.equal(result.applied, true);
  assert.equal(privilegedWrites[0].filePath, '/etc/pf.anchors/com.local.claude-network-guard');
  assert.match(privilegedWrites[0].content, /block drop out quick to/);
  assert.match(privilegedWrites[1].content, /load anchor/);
  assert.deepEqual(privilegedCommands[0], [
    ['pfctl', '-f', '/etc/pf.conf'],
    ['pfctl', '-e']
  ]);
});

test('clearMacBlock removes anchor block and reloads pf.conf', async () => {
  const files = {
    '/etc/pf.conf': [
      'set skip on lo0',
      '# ClaudeNetworkGuard START',
      'anchor "com.local.claude-network-guard"',
      'load anchor "com.local.claude-network-guard" from "/etc/pf.anchors/com.local.claude-network-guard"',
      '# ClaudeNetworkGuard END',
      ''
    ].join('\n'),
    '/etc/pf.anchors/com.local.claude-network-guard': 'block drop out quick to { 203.0.113.10 }\n'
  };
  const commands = [];
  const manager = new FirewallManager({
    platform: 'darwin',
    fsImpl: {
      existsSync: (filePath) => Object.prototype.hasOwnProperty.call(files, filePath),
      readFileSync: (filePath) => files[filePath],
      writeFileSync: (filePath, content) => {
        files[filePath] = content;
      }
    },
    macRunner: {
      writeFilePrivileged: async (filePath, content) => {
        files[filePath] = content;
      },
      removeFilePrivileged: async (filePath) => {
        delete files[filePath];
      },
      runPrivilegedCommands: async (nextCommands) => {
        commands.push(nextCommands);
        return '';
      }
    }
  });

  const result = await manager.clearBlock();

  assert.equal(result.mode, 'PF_CLEARED');
  assert.equal(result.rules.length, 0);
  assert.doesNotMatch(files['/etc/pf.conf'], /ClaudeNetworkGuard START/);
  assert.equal(files['/etc/pf.anchors/com.local.claude-network-guard'], undefined);
  assert.deepEqual(commands[0], [['pfctl', '-f', '/etc/pf.conf']]);
});

test('applyMacBlock returns partial result when authorization fails', async () => {
  const manager = new FirewallManager({
    hosts: ['api.anthropic.com'],
    platform: 'darwin',
    resolveTargetIpsImpl: async () => ({ ips: ['203.0.113.10'], results: [] }),
    macRunner: {
      writeFilePrivileged: async () => {
        throw new Error('AUTH_DENIED');
      },
      runPrivilegedCommands: async () => ''
    }
  });

  const result = await manager.applyBlock();

  assert.equal(result.mode, 'PARTIAL_BLOCK');
  assert.match(result.lastError, /AUTH_DENIED/);
});
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
node --test tests/firewall-manager.test.js
```

Expected: FAIL because `FirewallManager` does not accept the new injected dependencies and `applyBlock()` still returns `UNSUPPORTED_PLATFORM` on `darwin`.

- [ ] **Step 3: Add dependency injection to FirewallManager**

Update the imports at the top of `src/daemon/firewall-manager.js`:

```javascript
const { execFile } = require('child_process');
const { MacCommandRunner } = require('./macos-command-runner');
```

Replace the `FirewallManager` constructor with:

```javascript
  constructor({
    hosts = FIREWALL_TARGET_HOSTS,
    platform = process.platform,
    fsImpl = fs,
    macRunner = new MacCommandRunner(),
    resolveTargetIpsImpl = resolveTargetIps,
    pfConfPath = PF_CONF_PATH,
    pfAnchorPath = PF_ANCHOR_PATH
  } = {}) {
    this.hosts = hosts;
    this.platform = platform;
    this.fs = fsImpl;
    this.macRunner = macRunner;
    this.resolveTargetIps = resolveTargetIpsImpl;
    this.pfConfPath = pfConfPath;
    this.pfAnchorPath = pfAnchorPath;
  }
```

Replace `applyBlock()` with:

```javascript
  async applyBlock() {
    if (process.env.NETWORK_GUARD_SKIP_FIREWALL === '1') {
      return { applied: false, mode: 'SKIPPED', rules: [], lastError: null };
    }

    if (this.platform === 'win32') return this.applyWindowsBlock();
    if (this.platform === 'darwin') return this.applyMacBlock();

    return { applied: false, mode: 'UNSUPPORTED_PLATFORM', rules: [], lastError: this.platform };
  }
```

Replace `clearBlock()` with:

```javascript
  async clearBlock(existingRules = []) {
    if (process.env.NETWORK_GUARD_SKIP_FIREWALL === '1') {
      return { applied: false, mode: 'SKIPPED', rules: [], lastError: null };
    }

    if (this.platform === 'win32') return this.clearWindowsBlock(existingRules);
    if (this.platform === 'darwin') return this.clearMacBlock();
    return { applied: false, mode: 'UNSUPPORTED_PLATFORM', rules: [], lastError: null };
  }
```

- [ ] **Step 4: Implement macOS apply and clear methods**

Add these methods inside `FirewallManager`:

```javascript
  readPfConf() {
    if (!this.fs.existsSync(this.pfConfPath)) return '';
    return this.fs.readFileSync(this.pfConfPath, 'utf8');
  }

  async applyMacBlock() {
    const resolved = await this.resolveTargetIps(this.hosts);
    const rules = [];
    try {
      if (!resolved.ips.length) {
        return {
          applied: false,
          mode: 'PARTIAL_BLOCK',
          rules: [],
          resolved,
          lastError: 'PF_IPS_EMPTY'
        };
      }

      const ruleText = `${renderPfBlockRule(resolved.ips)}${os.EOL}`;
      rules.push({ anchor: PF_ANCHOR_NAME, ips: resolved.ips });
      const patchedPfConf = ensurePfAnchorBlock(this.readPfConf());

      await this.macRunner.writeFilePrivileged(this.pfAnchorPath, ruleText);
      await this.macRunner.writeFilePrivileged(this.pfConfPath, patchedPfConf);
      await this.macRunner.runPrivilegedCommands([
        ['pfctl', '-f', this.pfConfPath],
        ['pfctl', '-e']
      ]);

      return {
        applied: true,
        mode: 'PF_BLOCK',
        rules,
        resolved,
        lastError: null
      };
    } catch (error) {
      return {
        applied: rules.length > 0,
        mode: 'PARTIAL_BLOCK',
        rules,
        resolved,
        lastError: error.message || 'PF_BLOCK_FAILED'
      };
    }
  }

  async clearMacBlock() {
    try {
      const patchedPfConf = removePfAnchorBlock(this.readPfConf());
      await this.macRunner.writeFilePrivileged(this.pfConfPath, patchedPfConf);
      await this.macRunner.removeFilePrivileged(this.pfAnchorPath);
      await this.macRunner.runPrivilegedCommands([['pfctl', '-f', this.pfConfPath]]);
      return {
        applied: true,
        mode: 'PF_CLEARED',
        rules: [],
        lastError: null
      };
    } catch (error) {
      return {
        applied: false,
        mode: 'PARTIAL_CLEAR',
        rules: [],
        lastError: error.message || 'PF_CLEAR_FAILED'
      };
    }
  }
```

- [ ] **Step 5: Run firewall tests**

Run:

```powershell
node --test tests/firewall-manager.test.js
```

Expected: PASS.

- [ ] **Step 6: Run guard-service smoke tests for firewall integration**

Run:

```powershell
node --test tests/guard-service.test.js
```

Expected: PASS. If failures show the constructor change broke default Windows behavior, keep constructor defaults exactly compatible with `new FirewallManager({ hosts })`.

- [ ] **Step 7: Commit**

```bash
git add src/daemon/firewall-manager.js tests/firewall-manager.test.js
git commit -m "feat: add macos pf firewall fallback"
```

---

### Task 7: Guard Status, Diagnostic Summary, Renderer Copy, and README

**Files:**
- Modify: `src/daemon/guard-service.js`
- Modify: `src/daemon/diagnostic-report.js`
- Modify: `src/renderer/renderer.js`
- Modify: `README.md`
- Modify: `tests/guard-service.test.js`
- Modify: `tests/diagnostic-report.test.js`
- Modify: `tests/renderer-static.test.js`

- [ ] **Step 1: Add failing tests for shared status and diagnostics**

Append this test to `tests/guard-service.test.js`:

```javascript
test('GuardService decorateCheckWithFirewall treats macOS pf modes as successful firewall states', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  store.update({ guardState: GuardState.ENABLED });

  const blocked = service.decorateCheckWithFirewall(
    { verdict: 'BLOCK', reasons: ['DNS_CHECK_FAILED'], checkItems: [] },
    { mode: 'PF_BLOCK', rules: [{ anchor: 'com.local.claude-network-guard' }], lastError: null }
  );
  const cleared = service.decorateCheckWithFirewall(
    { verdict: 'PASS', reasons: [], checkItems: [] },
    { mode: 'PF_CLEARED', rules: [], lastError: null }
  );

  assert.equal(blocked.checkItems.find((item) => item.id === 'firewall').verdict, 'PASS');
  assert.equal(cleared.checkItems.find((item) => item.id === 'firewall').verdict, 'PASS');
});
```

Append this test to `tests/diagnostic-report.test.js`:

```javascript
test('buildDiagnosticReport includes environment consistency supported flag', () => {
  const report = buildDiagnosticReport({
    environmentConsistency: {
      supported: true,
      enabled: true,
      deriveFromExitIp: true,
      backup: { hasBackup: true, createdAt: '2026-05-31T01:00:00.000Z' },
      lastTargetProfile: { timeZone: 'America/Chicago', language: 'en-US' },
      lastApplyResult: { ok: true, at: '2026-05-31T01:01:00.000Z', steps: { secret: { ok: true } } }
    }
  });

  assert.equal(report.environmentConsistency.supported, true);
  assert.equal(report.environmentConsistency.backup.createdAt, '2026-05-31T01:00:00.000Z');
  assert.deepEqual(report.environmentConsistency.lastApplyResult, {
    ok: true,
    at: '2026-05-31T01:01:00.000Z'
  });
  assert.equal(JSON.stringify(report).includes('secret'), false);
});
```

Append this assertion to the existing `renderer exposes environment consistency controls` test in `tests/renderer-static.test.js`:

```javascript
  assert.doesNotMatch(renderer, /注销 Windows/);
```

- [ ] **Step 2: Run focused tests and verify failures**

Run:

```powershell
node --test tests/guard-service.test.js tests/diagnostic-report.test.js tests/renderer-static.test.js
```

Expected: diagnostic test fails because `supported` is not summarized; renderer static test fails while the restart message mentions Windows.

- [ ] **Step 3: Update diagnostic summary**

In `src/daemon/diagnostic-report.js`, replace the start of `summarizeEnvironmentConsistency()` with:

```javascript
function summarizeEnvironmentConsistency(environmentConsistency = {}) {
  const backup = environmentConsistency.backup || {};
  return {
    supported: environmentConsistency.supported === true,
    enabled: Boolean(environmentConsistency.enabled),
```

Keep the existing summary fields after `enabled`.

- [ ] **Step 4: Make renderer restart guidance platform-neutral**

In `src/renderer/renderer.js`, replace this string:

```javascript
'对齐完成，应用约 2 秒后自动重启并重新检测。若仍失败，请注销 Windows 一次。'
```

with:

```javascript
'对齐完成，应用约 2 秒后自动重启并重新检测。若仍失败，请重新登录当前系统账户后再检测。'
```

If the file currently contains mojibake text because of encoding display, replace only the JavaScript string that includes `Windows` in the apply-environment success branch.

- [ ] **Step 5: Confirm GuardService firewall logic already accepts pf success modes**

Open `src/daemon/guard-service.js` and confirm `decorateCheckWithFirewall()` only treats `ERROR`, `PARTIAL_BLOCK`, and `PARTIAL_CLEAR` as failure modes. If it already does, no code change is needed for the guard-service test. If it has an explicit allowlist, replace it with:

```javascript
    let verdict =
      mode === 'ERROR' || mode === 'PARTIAL_BLOCK' || mode === 'PARTIAL_CLEAR'
        ? 'FAIL'
        : mode === 'SKIPPED' || mode === 'UNSUPPORTED_PLATFORM'
          ? 'SKIPPED'
          : 'PASS';
```

- [ ] **Step 6: Update README platform notes**

In `README.md`, replace the macOS platform note:

```markdown
- macOS proxy settings use `networksetup` and default to the `Wi-Fi` service. Set `NETWORK_GUARD_MAC_SERVICE` to target another network service.
```

with:

```markdown
- macOS proxy settings use `networksetup` and default to the `Wi-Fi` service. Set `NETWORK_GUARD_MAC_SERVICE` to target another network service.
- macOS firewall fallback uses an app-owned `pf` anchor at `/etc/pf.anchors/com.local.claude-network-guard` and may request administrator authorization. The app only manages its marked `pf.conf` block and its own anchor file.
```

- [ ] **Step 7: Run focused tests**

Run:

```powershell
node --test tests/guard-service.test.js tests/diagnostic-report.test.js tests/renderer-static.test.js
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/daemon/guard-service.js src/daemon/diagnostic-report.js src/renderer/renderer.js README.md tests/guard-service.test.js tests/diagnostic-report.test.js tests/renderer-static.test.js
git commit -m "chore: surface macos parity status"
```

---

### Task 8: Full Regression and Manual macOS Smoke Checklist

**Files:**
- Modify only if failures from verification require fixes.

- [ ] **Step 1: Run the full automated test suite**

Run:

```powershell
npm.cmd test
```

Expected: all tests PASS.

- [ ] **Step 2: Inspect git status**

Run:

```powershell
git status --short
```

Expected: no uncommitted implementation changes. If verification fixes were needed, commit them with a focused message before continuing.

- [ ] **Step 3: Run a non-mutating macOS dry-run review before using a real Mac**

Review the code paths and confirm these environment variables still work:

```powershell
$env:NETWORK_GUARD_SKIP_FIREWALL='1'
$env:NETWORK_GUARD_SKIP_SYSTEM_PROXY='1'
npm.cmd test
```

Expected: tests still pass, and skip variables do not bypass unit-level helper tests because those tests call helper functions directly.

- [ ] **Step 4: Manual macOS smoke test for pf fallback**

On a macOS machine:

```bash
npm install
npm start
```

Manual checks:

1. Set `NETWORK_GUARD_SKIP_FIREWALL` unset.
2. Configure static IP as `0.0.0.0` for the smoke test.
3. Trigger a blocked guard check.
4. Approve the administrator prompt.
5. Verify `/etc/pf.anchors/com.local.claude-network-guard` exists.
6. Verify `/etc/pf.conf` contains exactly one `ClaudeNetworkGuard START` block.
7. Disable guard or make checks pass.
8. Verify the marked `pf.conf` block is gone and the app anchor file is removed.

Expected: UI firewall item reports `PF_BLOCK` while blocked and `PF_CLEARED` after cleanup.

- [ ] **Step 5: Manual macOS smoke test for environment consistency**

On a macOS machine with Chrome and Edge fully closed:

```bash
npm start
```

Manual checks:

1. Open the app and run a check.
2. Use the environment consistency apply button.
3. Approve administrator authorization for time zone changes.
4. Confirm `environment-backup.json` is created in the app data directory.
5. Confirm the app relaunches and runs a post-apply check.
6. Restore the environment from the UI.
7. Confirm the backed-up time zone and browser preference fields are restored.
8. Repeat restore once more.

Expected: the second restore is safe and reports success or skipped browser steps, not corruption.

- [ ] **Step 6: Commit verification fixes if any were made**

```bash
git add src tests README.md
git commit -m "fix: complete macos parity verification fixes"
```

Only run this commit command if Step 1 through Step 5 required code or documentation changes after the Task 7 commit.

---

## Spec Coverage Self-Review

| Spec Requirement | Plan Task |
|------------------|-----------|
| macOS command authorization with scoped privileged changes | Task 1 |
| macOS environment backup shape and state capture | Task 2 |
| macOS apply/restore for time zone, language, Chrome/Edge, WebRTC | Task 3 |
| Platform applier selection and support status | Task 4 |
| `pf` anchor rule rendering and `pf.conf` patching | Task 5 |
| `pf` apply/clear backend with failure results | Task 6 |
| Shared UI/status/diagnostic/README parity | Task 7 |
| Full automated and manual verification | Task 8 |
| Windows behavior remains unchanged | Tasks 4, 6, 7, 8 regression commands |

No spec requirement is intentionally deferred.
