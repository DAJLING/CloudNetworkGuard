const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');

const WEBRTC_POLICY = 'disable_non_proxied_udp';
const BLOCKED_LANGUAGES = new Set(['zh-CN', 'zh-HK', 'zh-MO']);

const BROWSER_REGISTRY = {
  chrome: {
    processName: 'chrome',
    policyKey: 'Software\\Policies\\Google\\Chrome',
    preferencesPath: path.join(
      process.env.LOCALAPPDATA || '',
      'Google',
      'Chrome',
      'User Data',
      'Default',
      'Preferences'
    )
  },
  edge: {
    processName: 'msedge',
    policyKey: 'Software\\Policies\\Microsoft\\Edge',
    preferencesPath: path.join(
      process.env.LOCALAPPDATA || '',
      'Microsoft',
      'Edge',
      'User Data',
      'Default',
      'Preferences'
    )
  }
};

const POWERSHELL_TIMEOUT_MS = 45000;
const COMMAND_TIMEOUT_MS = 20000;

function execFileWithTimeout(command, args, timeoutMs, execFileImpl = execFile) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const child = execFileImpl(command, args, { windowsHide: true }, (error, stdout, stderr) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(new Error(String(stderr || stdout || error.message).trim() || error.message));
        return;
      }
      resolve(stdout);
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error('COMMAND_TIMEOUT'));
    }, timeoutMs);
  });
}

function stepResult(ok, error = null, extra = {}) {
  return { ok, error, ...extra };
}

class EnvironmentApplierWin {
  constructor({ execFile: customExec = null, fsImpl = fs, platform = process.platform } = {}) {
    this.customExec = customExec;
    this.fs = fsImpl;
    this.platform = platform;
  }

  async runCmd(command, args, timeoutMs = COMMAND_TIMEOUT_MS) {
    if (this.customExec) {
      const output = await this.customExec(command, args);
      return typeof output === 'string' ? output : String(output ?? '');
    }
    return execFileWithTimeout(command, args, timeoutMs, execFile);
  }

  async runPowerShell(script) {
    return this.runCmd(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
      POWERSHELL_TIMEOUT_MS
    );
  }

  isSupported() {
    return this.platform === 'win32';
  }

  async captureCurrentState() {
    if (!this.isSupported()) {
      throw new Error('UNSUPPORTED_PLATFORM');
    }

    const timeZoneId = (await this.runPowerShell('(Get-TimeZone).Id')).trim();
    const languageJson = await this.runPowerShell(
      '(Get-WinUserLanguageList | ConvertTo-Json -Compress -Depth 4)'
    ).catch(() => '[]');

    let userLanguages = [];
    try {
      userLanguages = JSON.parse(languageJson || '[]');
      if (!Array.isArray(userLanguages)) userLanguages = [userLanguages];
    } catch {
      userLanguages = [];
    }

    const chrome = await this.captureBrowserState('chrome');
    const edge = await this.captureBrowserState('edge');

    return {
      version: 1,
      createdAt: new Date().toISOString(),
      platform: 'win32',
      windows: {
        timeZoneId,
        userLanguages
      },
      chrome,
      edge
    };
  }

  async captureBrowserState(browserId) {
    const browser = BROWSER_REGISTRY[browserId];
    const installed = this.fs.existsSync(path.dirname(browser.preferencesPath));
    const snapshot = {
      installed,
      preferencesPath: browser.preferencesPath,
      intlAcceptLanguages: null,
      webrtcPolicy: null,
      webrtcPolicyApplied: false
    };

    if (!installed) return snapshot;

    snapshot.intlAcceptLanguages = this.readAcceptLanguages(browser.preferencesPath);
    snapshot.webrtcPolicy = await this.readWebRtcPolicy(browser.policyKey).catch(() => null);
    snapshot.webrtcPolicyApplied = snapshot.webrtcPolicy === WEBRTC_POLICY;
    return snapshot;
  }

  readAcceptLanguages(preferencesPath) {
    if (!this.fs.existsSync(preferencesPath)) return null;
    const prefs = JSON.parse(this.fs.readFileSync(preferencesPath, 'utf8'));
    return prefs.intl && prefs.intl.accept_languages ? prefs.intl.accept_languages : null;
  }

  async readWebRtcPolicy(policyKey) {
    const stdout = await this.runCmd('reg', ['query', `HKCU\\${policyKey}`, '/v', 'WebRtcIPHandlingPolicy']);
    const match = stdout.match(/WebRtcIPHandlingPolicy\s+REG_\w+\s+(.+)/i);
    return match ? match[1].trim() : null;
  }

  async isBrowserRunning() {
    const running = [];
    for (const [name, browser] of Object.entries(BROWSER_REGISTRY)) {
      try {
        const stdout = await this.runCmd('tasklist', ['/FI', `IMAGENAME eq ${browser.processName}.exe`]);
        if (/No tasks are running/i.test(stdout)) continue;
        if (new RegExp(`${browser.processName}\\.exe`, 'i').test(stdout)) running.push(name);
      } catch {
        // ignore
      }
    }
    return running;
  }

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
    steps['windows.timezone'] = await this.applyWindowsTimeZone(profile.windowsTimeZone);
    if (keepChineseInput) {
      steps['windows.language'] = stepResult(true, null, { skipped: true, reason: 'KEEP_CHINESE_INPUT' });
      steps['chrome.language'] = stepResult(true, null, { skipped: true, reason: 'KEEP_CHINESE_INPUT' });
      steps['edge.language'] = stepResult(true, null, { skipped: true, reason: 'KEEP_CHINESE_INPUT' });
    } else {
      steps['windows.language'] = await this.applyWindowsLanguage(profile.language, profile.languages);
      steps['chrome.language'] = await this.applyBrowserLanguage('chrome', profile);
      steps['edge.language'] = await this.applyBrowserLanguage('edge', profile);
    }
    steps['chrome.webrtc'] = await this.applyBrowserWebRtc('chrome');
    steps['edge.webrtc'] = await this.applyBrowserWebRtc('edge');

    const ok = Object.values(steps).every((step) => step.ok);
    return { ok, steps, keepChineseInput };
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
    if (backup.windows) {
      steps['windows.timezone'] = await this.applyWindowsTimeZone(backup.windows.timeZoneId);
      steps['windows.language'] = await this.restoreWindowsLanguages(backup.windows.userLanguages);
    }

    steps['chrome.language'] = await this.restoreBrowserLanguage('chrome', backup.chrome);
    steps['chrome.webrtc'] = await this.restoreBrowserWebRtc('chrome', backup.chrome);
    steps['edge.language'] = await this.restoreBrowserLanguage('edge', backup.edge);
    steps['edge.webrtc'] = await this.restoreBrowserWebRtc('edge', backup.edge);

    const ok = Object.values(steps).every((step) => step.ok);
    return { ok, steps };
  }

  async applyWindowsTimeZone(windowsTimeZone) {
    try {
      await this.runCmd('tzutil', ['/s', windowsTimeZone]);
      return stepResult(true);
    } catch (error) {
      try {
        await this.runPowerShell(`Set-TimeZone -Id '${windowsTimeZone.replace(/'/g, "''")}'`);
        return stepResult(true);
      } catch (fallbackError) {
        return stepResult(false, fallbackError.message);
      }
    }
  }

  async applyWindowsLanguage(language, languages = []) {
    try {
      const primary = language || 'en-US';
      const list = languages.length ? languages : [primary];
      const filtered = list.filter((item) => !BLOCKED_LANGUAGES.has(item));
      const finalList = filtered.length ? filtered : [primary];
      const script = `
        $list = New-WinUserLanguageList '${primary.replace(/'/g, "''")}';
        ${finalList
          .slice(1)
          .map((lang) => `$list.Add('${lang.replace(/'/g, "''")}');`)
          .join('\n')}
        Set-WinUserLanguageList $list -Force;
      `;
      await this.runPowerShell(script);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  normalizeLanguageId(entry) {
    if (!entry) return null;
    if (typeof entry === 'string') return entry.trim();
    return String(entry.LanguageId || entry.languageId || entry.LanguageTag || entry.languageTag || '').trim() || null;
  }

  async restoreWindowsLanguages(userLanguages) {
    try {
      if (!Array.isArray(userLanguages) || !userLanguages.length) {
        return stepResult(true, null, { skipped: true });
      }

      const languageIds = userLanguages.map((entry) => this.normalizeLanguageId(entry)).filter(Boolean);
      if (!languageIds.length) {
        return stepResult(false, 'BACKUP_LANGUAGE_EMPTY');
      }

      const primary = languageIds[0].replace(/'/g, "''");
      const additional = languageIds.slice(1).map((id) => id.replace(/'/g, "''"));
      const script = `
        $list = New-WinUserLanguageList '${primary}';
        ${additional.map((id) => `$list.Add('${id}');`).join('\n')}
        Set-WinUserLanguageList $list -Force;
      `;
      await this.runPowerShell(script);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async applyBrowserLanguage(browserId, profile) {
    const browser = BROWSER_REGISTRY[browserId];
    if (!this.fs.existsSync(path.dirname(browser.preferencesPath))) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      const acceptLanguages = profile.languages.join(',') || profile.language;
      this.patchBrowserPreferences(browser.preferencesPath, acceptLanguages);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async restoreBrowserLanguage(browserId, backupSection = {}) {
    const browser = BROWSER_REGISTRY[browserId];
    if (!backupSection || !backupSection.installed) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      if (backupSection.intlAcceptLanguages) {
        this.patchBrowserPreferences(browser.preferencesPath, backupSection.intlAcceptLanguages);
      }
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  patchBrowserPreferences(preferencesPath, acceptLanguages) {
    if (!this.fs.existsSync(preferencesPath)) {
      throw new Error('PREFERENCES_NOT_FOUND');
    }
    const prefs = JSON.parse(this.fs.readFileSync(preferencesPath, 'utf8'));
    prefs.intl = prefs.intl || {};
    prefs.intl.accept_languages = acceptLanguages;
    const tempPath = `${preferencesPath}.ng-tmp`;
    this.fs.writeFileSync(tempPath, JSON.stringify(prefs));
    this.fs.renameSync(tempPath, preferencesPath);
  }

  async applyBrowserWebRtc(browserId) {
    const browser = BROWSER_REGISTRY[browserId];
    if (!this.fs.existsSync(path.dirname(browser.preferencesPath))) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      await this.runCmd('reg', [
        'add',
        `HKCU\\${browser.policyKey}`,
        '/v',
        'WebRtcIPHandlingPolicy',
        '/t',
        'REG_SZ',
        '/d',
        WEBRTC_POLICY,
        '/f'
      ]);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async restoreBrowserWebRtc(browserId, backupSection = {}) {
    const browser = BROWSER_REGISTRY[browserId];
    if (!backupSection || !backupSection.installed) {
      return stepResult(true, null, { skipped: true, reason: 'NOT_INSTALLED' });
    }
    try {
      if (backupSection.webrtcPolicy === null || backupSection.webrtcPolicy === undefined) {
        await this.runCmd('reg', ['delete', `HKCU\\${browser.policyKey}`, '/v', 'WebRtcIPHandlingPolicy', '/f']).catch((error) => {
          const message = String(error && error.message ? error.message : error);
          if (!/unable|not found|cannot find|找不到|系统找不到/i.test(message)) throw error;
        });
      } else {
        await this.runCmd('reg', [
          'add',
          `HKCU\\${browser.policyKey}`,
          '/v',
          'WebRtcIPHandlingPolicy',
          '/t',
          'REG_SZ',
          '/d',
          backupSection.webrtcPolicy,
          '/f'
        ]);
      }
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }
}

module.exports = {
  EnvironmentApplierWin,
  BROWSER_REGISTRY,
  WEBRTC_POLICY,
  execFileWithTimeout,
  COMMAND_TIMEOUT_MS,
  POWERSHELL_TIMEOUT_MS
};
