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
const REMOVE_PREFERENCE = Symbol('REMOVE_PREFERENCE');

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
  const normalized = String(language || 'en-US').replace(/-/g, '_');
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

    const ok = Object.values(steps).every((step) => step.ok);
    return { ok, steps, keepChineseInput };
  }

  async restoreFromBackup(backup) {
    if (!this.isSupported() || backup.platform !== 'darwin') {
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
    if (backup.mac) {
      steps['mac.timezone'] = await this.applyTimeZone(backup.mac.timeZone);
      steps['mac.language'] = await this.restoreLanguage(backup.mac);
    }
    steps['chrome.language'] = await this.restoreBrowserLanguage('chrome', backup.chrome);
    steps['chrome.webrtc'] = await this.restoreBrowserWebRtc('chrome', backup.chrome);
    steps['edge.language'] = await this.restoreBrowserLanguage('edge', backup.edge);
    steps['edge.webrtc'] = await this.restoreBrowserWebRtc('edge', backup.edge);

    const ok = Object.values(steps).every((step) => step.ok);
    return { ok, steps };
  }

  async applyTimeZone(timeZone) {
    try {
      await this.runner.runPrivilegedCommands([['systemsetup', '-settimezone', timeZone]]);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async applyLanguage(language, languages = []) {
    try {
      const primary = language || 'en-US';
      const list = languages.length ? languages : [primary];
      await this.runner.run('defaults', ['write', 'NSGlobalDomain', 'AppleLanguages', '-array', ...list]);
      await this.runner.run('defaults', ['write', 'NSGlobalDomain', 'AppleLocale', localeFromLanguage(primary)]);
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  async restoreLanguage(macBackup = {}) {
    try {
      const languages = Array.isArray(macBackup.appleLanguages) ? macBackup.appleLanguages : [];
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
      const languages = Array.isArray(profile.languages) ? profile.languages : [];
      const acceptLanguages = languages.join(',') || profile.language;
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
    const preferencesPath = backupSection.preferencesPath || this.getBrowserPreferencesPath(browserId);
    try {
      if (backupSection.intlAcceptLanguages) {
        this.patchBrowserPreferences(preferencesPath, { acceptLanguages: backupSection.intlAcceptLanguages });
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
    const preferencesPath = backupSection.preferencesPath || this.getBrowserPreferencesPath(browserId);
    try {
      const webRtcPolicy =
        backupSection.webrtcPreference === null || backupSection.webrtcPreference === undefined
          ? REMOVE_PREFERENCE
          : backupSection.webrtcPreference;
      this.patchBrowserPreferences(preferencesPath, { webRtcPolicy });
      return stepResult(true);
    } catch (error) {
      return stepResult(false, error.message);
    }
  }

  patchBrowserPreferences(preferencesPath, { acceptLanguages = null, webRtcPolicy = null }) {
    if (!this.fs.existsSync(preferencesPath)) throw new Error('PREFERENCES_NOT_FOUND');
    const originalMode =
      typeof this.fs.statSync === 'function' && typeof this.fs.chmodSync === 'function'
        ? this.fs.statSync(preferencesPath).mode
        : null;
    const prefs = this.readPreferences(preferencesPath);
    if (acceptLanguages !== null) {
      prefs.intl = prefs.intl || {};
      prefs.intl.accept_languages = acceptLanguages;
    }
    if (webRtcPolicy !== null) {
      if (webRtcPolicy === REMOVE_PREFERENCE) {
        if (prefs.webrtc) delete prefs.webrtc.ip_handling_policy;
      } else {
        prefs.webrtc = prefs.webrtc || {};
        prefs.webrtc.ip_handling_policy = webRtcPolicy;
      }
    }
    const tempPath = `${preferencesPath}.ng-tmp`;
    this.fs.writeFileSync(tempPath, JSON.stringify(prefs));
    if (originalMode !== null) {
      this.fs.chmodSync(tempPath, originalMode);
    }
    this.fs.renameSync(tempPath, preferencesPath);
  }
}

module.exports = {
  EnvironmentApplierMac,
  BROWSER_REGISTRY,
  WEBRTC_POLICY,
  parseSystemsetupTimeZone,
  parseDefaultsArray,
  localeFromLanguage,
  stepResult
};
