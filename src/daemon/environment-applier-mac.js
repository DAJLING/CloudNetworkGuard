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
      prefs.webrtc = prefs.webrtc || {};
      prefs.webrtc.ip_handling_policy = webRtcPolicy;
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
