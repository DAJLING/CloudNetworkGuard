const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { GuardState } = require('../shared/constants');

function defaultDataDir(appName = 'claude-network-guard') {
  if (process.env.NETWORK_GUARD_DATA_DIR) return process.env.NETWORK_GUARD_DATA_DIR;
  if (process.platform === 'win32') {
    return path.join(process.env.APPDATA || os.homedir(), appName);
  }
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', appName);
  }
  return path.join(os.homedir(), '.config', appName);
}

class Store {
  constructor(filePath = path.join(defaultDataDir(), 'state.json')) {
    this.filePath = filePath;
    this.state = this.load();
  }

  load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      return {
        ...this.defaultState(),
        ...parsed
      };
    } catch {
      return this.defaultState();
    }
  }

  defaultState() {
    return {
      guardState: GuardState.DISABLED,
      guardMode: 'AUTO',
      systemProxyApplied: false,
      checkingNetwork: false,
      launchAtLogin: false,
      salt: crypto.randomBytes(24).toString('hex'),
      staticIp: null,
      boundExitIpHash: null,
      clientEnvironment: null,
      environmentConsistency: {
        enabled: false,
        deriveFromExitIp: true,
        keepChineseInput: true,
        profileOverride: { timeZone: '', language: '', languages: [] },
        backup: { createdAt: null, path: null },
        lastTargetProfile: null,
        lastApplyResult: null,
        lastRestoreResult: null,
        pendingPostApplyCheck: false
      },
      claudeRiskAcceptedAt: null,
      actionRequired: null,
      lastCheck: null,
      ping0RiskCache: null,
      recovery: {
        lastResult: null
      },
      monitoring: {
        enabled: false,
        intervalMinutes: 15,
        lastRunAt: null,
        lastResult: null,
        lastError: null
      },
      setup: {
        completed: false,
        completedAt: null,
        staticIpStrategy: null
      },
      firewall: {
        mode: 'IDLE',
        rules: [],
        lastError: null,
        updatedAt: null
      },
      usageEvents: [],
      logs: []
    };
  }

  getState() {
    return this.state;
  }

  update(patch) {
    this.state = {
      ...this.state,
      ...patch
    };
    this.save();
    return this.state;
  }

  appendLog(entry) {
    const logs = [entry, ...this.state.logs].slice(0, 100);
    this.update({ logs });
  }

  save() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(this.state, null, 2));
  }
}

module.exports = {
  Store,
  defaultDataDir
};
