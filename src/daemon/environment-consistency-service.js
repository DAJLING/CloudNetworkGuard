const path = require('path');
const { EnvironmentBackupStore } = require('./environment-backup-store');
const { EnvironmentApplierWin } = require('./environment-applier-win');
const { resolveEnvironmentProfile } = require('./environment-profile-resolver');

class EnvironmentConsistencyService {
  constructor({
    dataDir,
    backupStore = null,
    applier = null,
    resolveProfile = resolveEnvironmentProfile,
    platform = process.platform
  } = {}) {
    this.dataDir = dataDir;
    this.backupStore =
      backupStore || new EnvironmentBackupStore(path.join(dataDir, 'environment-backup.json'));
    this.applier = applier || new EnvironmentApplierWin({ platform });
    this.resolveProfile = resolveProfile;
    this.platform = platform;
  }

  isSupported() {
    return this.platform === 'win32' && this.applier.isSupported();
  }

  getBackupSummary() {
    return this.backupStore.getSummary();
  }

  async ensureBackup() {
    if (this.backupStore.exists()) {
      return this.backupStore.load();
    }
    const snapshot = await this.applier.captureCurrentState();
    return this.backupStore.save(snapshot);
  }

  async backupNow() {
    const snapshot = await this.applier.captureCurrentState();
    return this.backupStore.save(snapshot);
  }

  buildTargetProfile({ exitIp, config }) {
    const deriveFromExitIp = config.deriveFromExitIp !== false;
    const override = config.profileOverride || {};
    const hasOverride =
      Boolean(override.timeZone) || Boolean(override.language) || (override.languages && override.languages.length);

    if (!deriveFromExitIp || hasOverride) {
      const fallbackExit = exitIp && exitIp.countryCode ? exitIp : { countryCode: 'US', regionName: null };
      const derived = this.resolveProfile(fallbackExit, {});
      return this.resolveProfile(fallbackExit, {
        timeZone: override.timeZone || derived.timeZone,
        language: override.language || derived.language,
        languages: override.languages && override.languages.length ? override.languages : derived.languages
      });
    }

    return this.resolveProfile(exitIp || { countryCode: 'US', regionName: null }, {});
  }

  async apply({ exitIp, config = {} }) {
    if (!this.isSupported()) {
      return {
        ok: false,
        restartRequired: false,
        steps: { platform: { ok: false, error: 'UNSUPPORTED_PLATFORM' } }
      };
    }

    const running = await this.applier.isBrowserRunning();
    if (running.length) {
      return {
        ok: false,
        restartRequired: false,
        steps: {
          preflight: { ok: false, error: 'BROWSER_RUNNING', running }
        },
        lastTargetProfile: this.buildTargetProfile({ exitIp, config }),
        backup: this.backupStore.getSummary()
      };
    }

    const targetProfile = this.buildTargetProfile({ exitIp, config });
    await this.ensureBackup();
    const keepChineseInput = config.keepChineseInput !== false;
    const applyResult = await this.applier.applyProfile(targetProfile, { keepChineseInput });

    return {
      ok: applyResult.ok,
      restartRequired: applyResult.ok,
      steps: applyResult.steps,
      keepChineseInput,
      lastTargetProfile: targetProfile,
      backup: this.backupStore.getSummary()
    };
  }

  async restore() {
    if (!this.isSupported()) {
      return {
        ok: false,
        steps: { platform: { ok: false, error: 'UNSUPPORTED_PLATFORM' } }
      };
    }

    if (!this.backupStore.exists()) {
      return {
        ok: false,
        steps: { backup: { ok: false, error: 'BACKUP_NOT_FOUND' } }
      };
    }

    const backup = this.backupStore.load();
    const restoreResult = await this.applier.restoreFromBackup(backup);
    return {
      ok: restoreResult.ok,
      steps: restoreResult.steps,
      backup: this.backupStore.getSummary()
    };
  }
}

module.exports = {
  EnvironmentConsistencyService
};
