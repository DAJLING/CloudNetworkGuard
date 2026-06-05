const http = require('http');
const path = require('path');
const { Store } = require('./store');
const { NetworkChecker } = require('./network-checker');
const { ProxyManager } = require('./proxy-manager');
const { GuardProxy } = require('./guard-proxy');
const { recordTargetUsage } = require('./usage-monitor');
const { FirewallManager } = require('./firewall-manager');
const { TARGET_CONFIG_FILE, TargetConfigManager } = require('./target-config');
const { scoreProviderResults } = require('./scoring');
const { hashIp, maskIp } = require('./static-ip-observer');
const { buildDiagnosticReport } = require('./diagnostic-report');
const { EnvironmentConsistencyService } = require('./environment-consistency-service');
const { GuardMode, GuardState, NetworkVerdict } = require('../shared/constants');
const { getTopReasonGuidance } = require('../shared/reason-catalog');

function defaultEnvironmentConsistencyState() {
  return {
    enabled: false,
    deriveFromExitIp: true,
    keepChineseInput: true,
    profileOverride: { timeZone: '', language: '', languages: [] },
    backup: { createdAt: null, path: null },
    lastTargetProfile: null,
    lastApplyResult: null,
    lastRestoreResult: null,
    pendingPostApplyCheck: false
  };
}

function shouldUseSystemProxy() {
  if (process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY === '1') return false;
  if (process.env.NETWORK_GUARD_USE_SYSTEM_PROXY === '1') return true;
  // System-wide proxy breaks Windows IME / language services for many users.
  if (process.platform === 'win32') return false;
  return true;
}

class GuardService {
  constructor({ store = new Store(), apiPort = 18765, proxyPort = 18089, targetConfigManager = null } = {}) {
    this.store = store;
    this.apiPort = apiPort;
    this.clients = new Set();
    this.targetConfigManager =
      targetConfigManager ||
      new TargetConfigManager({
        filePath: path.join(path.dirname(store.filePath), TARGET_CONFIG_FILE)
      });
    this.targetConfig = this.targetConfigManager.load();
    this.proxyManager = new ProxyManager({ port: proxyPort });
    this.firewallManager = new FirewallManager({ hosts: this.targetConfig.firewallHosts });
    this.checker = new NetworkChecker({ store, getTargetConfig: () => this.targetConfig });
    this.proxy = new GuardProxy({
      port: proxyPort,
      getStatus: () => this.getStatus(),
      getTargetRules: () => this.targetConfig.rules,
      onTargetRequest: (host) => this.recordTargetRequest(host),
      emitEvent: (event) => this.emit(event)
    });
    this.apiServer = http.createServer(this.handleApi.bind(this));
    this.environmentConsistency = new EnvironmentConsistencyService({
      dataDir: path.dirname(store.filePath)
    });
  }

  getEnvironmentConsistencyStatus() {
    const state = this.store.getState();
    const stored = state.environmentConsistency || defaultEnvironmentConsistencyState();
    const backupSummary = this.environmentConsistency.getBackupSummary();
    return {
      ...stored,
      supported: this.environmentConsistency.isSupported(),
      backup: {
        ...stored.backup,
        hasBackup: backupSummary.hasBackup,
        createdAt: backupSummary.createdAt,
        path: backupSummary.path
      }
    };
  }

  async start() {
    if (!shouldUseSystemProxy()) {
      await this.proxyManager.disable().catch(() => {});
      this.store.update({ systemProxyApplied: false });
    }
    await this.clearManagedNetworkBlocks().catch(() => {});
    await this.proxy.start();
    await new Promise((resolve, reject) => {
      this.apiServer.once('error', reject);
      this.apiServer.listen(this.apiPort, '127.0.0.1', () => {
        this.apiServer.off('error', reject);
        resolve();
      });
    });
    return this.getStatus();
  }

  async stop() {
    await this.proxy.stop();
    await new Promise((resolve) => this.apiServer.close(() => resolve()));
  }

  getStatus() {
    const state = this.store.getState();
    const reasons = state.lastCheck && Array.isArray(state.lastCheck.reasons) ? state.lastCheck.reasons : [];
    const latestIp = state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip : {};
    return {
      guardState: state.guardState,
      guardMode: this.normalizeGuardMode(state.guardMode),
      launchAtLogin: state.launchAtLogin,
      setup: state.setup || { completed: false, completedAt: null, staticIpStrategy: null },
      proxy: {
        host: this.proxyManager.host,
        port: this.proxyManager.port,
        systemApplied: state.systemProxyApplied === true,
        mode: state.systemProxyApplied ? 'SYSTEM' : process.platform === 'win32' ? 'FIREWALL_ONLY' : 'LOCAL_ONLY'
      },
      lastCheck: state.lastCheck,
      firewall: state.firewall,
      recovery: state.recovery || { lastResult: null },
      binding: {
        bound: Boolean(state.boundExitIpHash),
        currentMaskedIp: latestIp.maskedIp || (state.staticIp && state.staticIp.maskedIp) || null,
        lastCheckedAt: state.lastCheck ? state.lastCheck.checkedAt : null,
        mismatch: reasons.includes('IP_BINDING_MISMATCH')
      },
      clientEnvironment: state.clientEnvironment,
      environmentConsistency: this.getEnvironmentConsistencyStatus(),
      actionRequired: state.actionRequired || null,
      guidance: getTopReasonGuidance(reasons),
      targetConfig: this.targetConfig,
      logs: state.logs || []
    };
  }

  normalizeGuardMode(mode) {
    if (mode === 'STRICT_BLOCK') return GuardMode.STRICT_VALIDATE;
    if (mode === GuardMode.STRICT_VALIDATE) return GuardMode.STRICT_VALIDATE;
    return GuardMode.AUTO;
  }

  async clearManagedNetworkBlocks() {
    const state = this.store.getState();
    const currentRules = state.firewall && state.firewall.rules ? state.firewall.rules : [];
    this.firewallManager.setHosts(this.targetConfig.firewallHosts || []);
    return this.firewallManager.clearBlock(currentRules);
  }

  async syncFirewallForStatus() {
    const state = this.store.getState();
    const currentRules = state.firewall && state.firewall.rules ? state.firewall.rules : [];
    this.firewallManager.setHosts(this.targetConfig.firewallHosts || []);

    if (state.checkingNetwork) {
      try {
        const result = await this.firewallManager.clearBlock(currentRules);
        return result;
      } catch (error) {
        return {
          mode: 'ERROR',
          rules: currentRules,
          lastError: error.message || 'FIREWALL_CLEAR_FAILED'
        };
      }
    }

    const shouldBlock =
      state.guardState === GuardState.ENABLED &&
      (!state.lastCheck || state.lastCheck.allowTargetTraffic !== true);

    try {
      const result = shouldBlock
        ? await this.firewallManager.applyBlock()
        : await this.firewallManager.clearBlock(currentRules);
      this.store.update({
        firewall: {
          mode: result.mode,
          rules: result.rules || [],
          lastError: result.lastError || null,
          updatedAt: new Date().toISOString()
        }
      });
      return result;
    } catch (error) {
      const firewall = {
        mode: 'ERROR',
        rules: currentRules,
        lastError: error.message || 'FIREWALL_ERROR',
        updatedAt: new Date().toISOString()
      };
      this.store.update({ firewall });
      return firewall;
    }
  }

  recordTargetRequest(host) {
    const state = this.store.getState();
    if (state.guardState !== GuardState.ENABLED) return { block: false, reasons: [] };

    const usage = recordTargetUsage({ state, host });
    const currentCheck = state.lastCheck || {
      checkedAt: new Date().toISOString(),
      verdict: NetworkVerdict.PASS,
      reasons: [],
      allowTargetTraffic: true
    };
    const reasons = Array.from(new Set([...(currentCheck.reasons || []), ...usage.reasons]));
    const lastCheck =
      usage.verdict === NetworkVerdict.BLOCK
        ? {
            ...currentCheck,
            verdict: NetworkVerdict.BLOCK,
            reasons,
            allowTargetTraffic: false,
            usage: {
              count: usage.count,
              windowMs: usage.windowMs,
              maxRequests: usage.maxRequests
            }
          }
        : {
            ...currentCheck,
            usage: {
              count: usage.count,
              windowMs: usage.windowMs,
              maxRequests: usage.maxRequests
            }
          };

    this.store.update({
      usageEvents: usage.nextEvents,
      lastCheck
    });

    if (usage.verdict === NetworkVerdict.BLOCK) {
      this.syncFirewallForStatus().catch(() => {});
      this.emit({ type: 'usage-rate-risk', host, status: this.getStatus() });
      return { block: true, reasons: usage.reasons };
    }

    return { block: false, reasons: [] };
  }

  updateClientEnvironment(environment) {
    this.store.update({ clientEnvironment: environment });
    this.emit({ type: 'environment-updated', status: this.getStatus() });
    return this.getStatus();
  }

  decorateCheckWithFirewall(check, firewallResult) {
    const state = this.store.getState();
    const guardEnabled = state.guardState === GuardState.ENABLED;
    const mode = firewallResult && firewallResult.mode ? firewallResult.mode : 'UNKNOWN';
    let verdict =
      mode === 'ERROR' || mode === 'PARTIAL_BLOCK' || mode === 'PARTIAL_CLEAR'
        ? 'FAIL'
        : mode === 'SKIPPED' || mode === 'UNSUPPORTED_PLATFORM'
          ? 'SKIPPED'
          : 'PASS';

    if (!guardEnabled) {
      verdict = 'SKIPPED';
    }

    const detailParts = [mode];
    if (firewallResult && firewallResult.lastError) detailParts.push(firewallResult.lastError);
    if (!guardEnabled) detailParts.push('守卫关闭时不启用防火墙兜底');

    const firewallItem = {
      id: 'firewall',
      label: '防火墙兜底',
      verdict,
      detail: detailParts.join(' / '),
      reason: guardEnabled && verdict === 'FAIL' ? 'FIREWALL_ERROR' : null
    };
    const existing = Array.isArray(check.checkItems) ? check.checkItems.filter((item) => item.id !== 'firewall') : [];
    return {
      ...check,
      checkItems: [...existing, firewallItem]
    };
  }

  async reloadTargetConfig() {
    const currentState = this.store.getState();
    const previousFirewallRules = currentState.firewall && currentState.firewall.rules ? currentState.firewall.rules : [];
    this.targetConfig = this.targetConfigManager.load();
    this.firewallManager.setHosts(this.targetConfig.firewallHosts || []);
    if (previousFirewallRules.length) {
      const clearResult = await this.firewallManager.clearBlock(previousFirewallRules).catch((error) => ({
        mode: 'PARTIAL_CLEAR',
        rules: previousFirewallRules,
        lastError: error.message || 'FIREWALL_CLEAR_FAILED'
      }));
      this.store.update({
        firewall: {
          mode: clearResult.mode,
          rules: clearResult.rules || [],
          lastError: clearResult.lastError || null,
          updatedAt: new Date().toISOString()
        }
      });
    }
    const firewallResult = await this.syncFirewallForStatus();
    const status = this.getStatus();
    this.emit({
      type: 'rules-reloaded',
      at: new Date().toISOString(),
      targetConfig: this.targetConfig,
      firewallResult,
      status
    });
    return status;
  }

  setStaticResidentialIp(value) {
    this.targetConfig = this.targetConfigManager.setStaticResidentialIp(value);
    this.store.update({ actionRequired: null });
    const status = this.getStatus();
    this.emit({ type: 'static-ip-updated', status });
    return status;
  }

  async saveValidationConfig(validationInput) {
    try {
      this.targetConfig = this.targetConfigManager.saveValidation(validationInput);
    } catch (error) {
      const status = this.getStatus();
      this.emit({ type: 'validation-config-failed', error: error.message || 'VALIDATION_CONFIG_INVALID', status });
      throw error;
    }
    return this.reloadTargetConfig();
  }

  async saveTargetRules(rulesInput) {
    this.targetConfig = this.targetConfigManager.saveRules(rulesInput);
    const status = await this.reloadTargetConfig();
    this.emit({ type: 'target-rules-saved', status });
    return status;
  }

  async resetValidationDefaults() {
    this.targetConfig = this.targetConfigManager.resetValidationToDefaults();
    return this.reloadTargetConfig();
  }

  async resetTargetConfigDefaults() {
    this.targetConfig = this.targetConfigManager.resetToDefaults();
    return this.reloadTargetConfig();
  }

  emit(event) {
    const payload = JSON.stringify(event);
    for (const client of this.clients) {
      client.write(`data: ${payload}\n\n`);
    }
  }

  async setSystemProxyEnabled(shouldEnable) {
    const state = this.store.getState();
    if (!shouldEnable) {
      if (!state.systemProxyApplied) {
        return { applied: false, reason: 'NOT_APPLIED' };
      }
      const result = await this.proxyManager.disable();
      this.store.update({ systemProxyApplied: false });
      return result;
    }

    if (!shouldUseSystemProxy()) {
      this.store.update({ systemProxyApplied: false });
      return {
        applied: false,
        reason: process.platform === 'win32' ? 'WINDOWS_FIREWALL_ONLY' : 'SKIPPED'
      };
    }

    const result = await this.proxyManager.enable();
    this.store.update({ systemProxyApplied: result.applied === true });
    return result;
  }

  async enableGuard(mode = GuardMode.AUTO) {
    const staticPreflight = await this.checker.checkStaticResidentialIpPreflight();
    if (!staticPreflight.ok) {
      const preflightCheck = {
        checkedAt: new Date().toISOString(),
        verdict: NetworkVerdict.BLOCK,
        reasons: [staticPreflight.reason],
        allowTargetTraffic: false,
        checkItems: [staticPreflight.checkItem]
      };
      this.store.update({
        guardState: GuardState.DISABLED,
        actionRequired: {
          type: staticPreflight.reason,
          currentMaskedIp: staticPreflight.currentMaskedIp || null
        },
        lastCheck: preflightCheck
      });
      const firewallResult = await this.syncFirewallForStatus();
      const status = this.getStatus();
      this.emit({ type: 'static-ip-preflight-blocked', firewallResult, status });
      return status;
    }

    await this.clearManagedNetworkBlocks().catch(() => {});
    const check = await this.runNetworkCheck();
    const proxyResult = await this.setSystemProxyEnabled(true);

    if (check.allowTargetTraffic !== true) {
      this.store.update({
        guardState: GuardState.DISABLED,
        guardMode: this.normalizeGuardMode(mode),
        actionRequired: null,
        lastCheck: check
      });
      const firewallResult = await this.syncFirewallForStatus();
      const decoratedCheck = this.decorateCheckWithFirewall(check, firewallResult);
      this.store.update({ lastCheck: decoratedCheck });
      const status = this.getStatus();
      this.emit({ type: 'guard-enable-failed', proxyResult, firewallResult, status, check: decoratedCheck });
      return status;
    }

    this.store.update({
      guardState: GuardState.ENABLED,
      guardMode: this.normalizeGuardMode(mode),
      actionRequired: null,
      lastCheck: check
    });
    const firewallResult = await this.syncFirewallForStatus();
    const decoratedCheck = this.decorateCheckWithFirewall(check, firewallResult);
    this.store.update({ lastCheck: decoratedCheck });
    const status = this.getStatus();
    this.emit({ type: 'guard-enabled', proxyResult, firewallResult, status, check: decoratedCheck });
    return status;
  }

  async disableGuard() {
    const proxyResult = await this.setSystemProxyEnabled(false);
    this.store.update({ guardState: GuardState.DISABLED });
    const firewallResult = await this.syncFirewallForStatus();
    const status = this.getStatus();
    this.emit({ type: 'guard-disabled', proxyResult, firewallResult, status });
    return status;
  }

  async emergencyRestore() {
    const state = this.store.getState();
    const currentRules = state.firewall && state.firewall.rules ? state.firewall.rules : [];
    const result = {
      ok: true,
      at: new Date().toISOString(),
      steps: {
        proxy: { ok: true, result: null, error: null },
        firewall: { ok: true, result: null, error: null }
      }
    };

    this.store.update({ guardState: GuardState.DISABLED, actionRequired: null });

    try {
      result.steps.proxy.result = await this.proxyManager.disable();
      this.store.update({ systemProxyApplied: false });
    } catch (error) {
      result.ok = false;
      result.steps.proxy.ok = false;
      result.steps.proxy.error = error.message || 'PROXY_RESTORE_FAILED';
    }

    try {
      const firewallResult = await this.firewallManager.clearBlock(currentRules);
      result.steps.firewall.result = firewallResult;
      this.store.update({
        firewall: {
          mode: firewallResult.mode,
          rules: firewallResult.rules || [],
          lastError: firewallResult.lastError || null,
          updatedAt: result.at
        }
      });
    } catch (error) {
      result.ok = false;
      result.steps.firewall.ok = false;
      result.steps.firewall.error = error.message || 'FIREWALL_RESTORE_FAILED';
      this.store.update({
        firewall: {
          mode: 'ERROR',
          rules: currentRules,
          lastError: result.steps.firewall.error,
          updatedAt: result.at
        }
      });
    }

    this.store.update({
      recovery: {
        lastResult: result
      }
    });
    this.store.appendLog({
      type: 'emergency-restore',
      at: result.at,
      verdict: result.ok ? 'PASS' : 'WARN',
      reasons: result.ok ? [] : ['RECOVERY_PARTIAL'],
      maskedIp: state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip.maskedIp : null,
      asn: state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip.asn : null
    });

    const status = this.getStatus();
    this.emit({ type: 'emergency-restore', result, status });
    return status;
  }

  async applyEnvironmentConsistency() {
    const state = this.store.getState();
    const stored = state.environmentConsistency || defaultEnvironmentConsistencyState();
    const exitIp =
      state.lastCheck && state.lastCheck.ip
        ? {
            countryCode: state.lastCheck.ip.countryCode,
            regionName: state.lastCheck.ip.regionName
          }
        : { countryCode: 'US', regionName: null };

    const result = await this.environmentConsistency.apply({
      exitIp,
      config: {
        deriveFromExitIp: stored.deriveFromExitIp !== false,
        keepChineseInput: stored.keepChineseInput !== false,
        profileOverride: stored.profileOverride || {}
      }
    });

    const at = new Date().toISOString();
    this.store.update({
      environmentConsistency: {
        ...stored,
        enabled: result.ok,
        keepChineseInput: result.keepChineseInput !== false,
        lastTargetProfile: result.lastTargetProfile || stored.lastTargetProfile,
        lastApplyResult: { ok: result.ok, at, steps: result.steps || {} },
        pendingPostApplyCheck: Boolean(result.restartRequired),
        backup: result.backup || this.environmentConsistency.getBackupSummary()
      }
    });
    this.store.appendLog({
      type: 'environment-consistency-apply',
      at,
      verdict: result.ok ? 'PASS' : 'WARN',
      reasons: result.ok ? [] : ['ENVIRONMENT_CONSISTENCY_PARTIAL'],
      maskedIp: state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip.maskedIp : null,
      asn: state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip.asn : null
    });

    const status = this.getStatus();
    this.emit({ type: 'environment-consistency-applied', result, status });
    return { ...result, status };
  }

  async restoreEnvironmentConsistency() {
    const state = this.store.getState();
    const stored = state.environmentConsistency || defaultEnvironmentConsistencyState();
    const result = await this.environmentConsistency.restore();
    const at = new Date().toISOString();

    this.store.update({
      environmentConsistency: {
        ...stored,
        enabled: false,
        lastRestoreResult: { ok: result.ok, at, steps: result.steps || {} },
        pendingPostApplyCheck: false
      }
    });
    this.store.appendLog({
      type: 'environment-consistency-restore',
      at,
      verdict: result.ok ? 'PASS' : 'WARN',
      reasons: result.ok ? [] : ['ENVIRONMENT_CONSISTENCY_RESTORE_PARTIAL'],
      maskedIp: state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip.maskedIp : null,
      asn: state.lastCheck && state.lastCheck.ip ? state.lastCheck.ip.asn : null
    });

    const status = this.getStatus();
    this.emit({ type: 'environment-consistency-restored', result, status });
    return { ...result, status };
  }

  async backupEnvironmentNow() {
    const snapshot = await this.environmentConsistency.backupNow();
    const summary = this.environmentConsistency.getBackupSummary();
    const state = this.store.getState();
    const stored = state.environmentConsistency || defaultEnvironmentConsistencyState();
    this.store.update({
      environmentConsistency: {
        ...stored,
        backup: summary
      }
    });
    const status = this.getStatus();
    this.emit({ type: 'environment-consistency-backup', snapshot, status });
    return { snapshot, status };
  }

  setEnvironmentConsistencyConfig(patch = {}) {
    const state = this.store.getState();
    const stored = state.environmentConsistency || defaultEnvironmentConsistencyState();
    const next = {
      ...stored,
      deriveFromExitIp: patch.deriveFromExitIp !== undefined ? Boolean(patch.deriveFromExitIp) : stored.deriveFromExitIp,
      keepChineseInput: patch.keepChineseInput !== undefined ? Boolean(patch.keepChineseInput) : stored.keepChineseInput,
      profileOverride: {
        ...stored.profileOverride,
        ...(patch.profileOverride || {})
      }
    };
    if (patch.enabled !== undefined) next.enabled = Boolean(patch.enabled);
    this.store.update({ environmentConsistency: next });
    const status = this.getStatus();
    this.emit({ type: 'environment-consistency-config', status });
    return status;
  }

  resetExitBinding() {
    const at = new Date().toISOString();
    this.store.update({ boundExitIpHash: null });
    this.store.appendLog({
      type: 'exit-binding-reset',
      at,
      verdict: 'WARN',
      reasons: ['EXIT_BINDING_RESET'],
      maskedIp: null,
      asn: null
    });
    const status = this.getStatus();
    this.emit({ type: 'exit-binding-reset', status });
    return status;
  }

  async rebindExitToCurrent() {
    const providerResults = await this.checker.providers();
    const providerScore = scoreProviderResults(providerResults);
    if (!providerScore.ip) {
      throw new Error('PROVIDER_UNAVAILABLE');
    }

    const at = new Date().toISOString();
    const state = this.store.getState();
    const maskedIp = maskIp(providerScore.ip);
    this.store.update({
      boundExitIpHash: hashIp(providerScore.ip, state.salt),
      staticIp: {
        ipHash: hashIp(providerScore.ip, state.salt),
        maskedIp,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now()
      }
    });
    this.store.appendLog({
      type: 'exit-binding-rebound',
      at,
      verdict: 'PASS',
      reasons: [],
      maskedIp,
      asn: providerScore.asn
    });
    const status = this.getStatus();
    this.emit({ type: 'exit-binding-rebound', status });
    return status;
  }

  completeSetup({ staticIpStrategy = 'manual' } = {}) {
    this.store.update({
      setup: {
        completed: true,
        completedAt: new Date().toISOString(),
        staticIpStrategy
      }
    });
    const status = this.getStatus();
    this.emit({ type: 'setup-completed', status });
    return status;
  }

  reopenSetup() {
    const previous = this.store.getState().setup || {};
    this.store.update({
      setup: {
        ...previous,
        completed: false,
        completedAt: null
      }
    });
    const status = this.getStatus();
    this.emit({ type: 'setup-reopened', status });
    return status;
  }

  getDiagnosticReport() {
    return buildDiagnosticReport(this.getStatus());
  }

  async runNetworkCheck() {
    this.store.update({ checkingNetwork: true });
    try {
      await this.clearManagedNetworkBlocks().catch(() => {});
      return await this.checker.checkNow();
    } finally {
      this.store.update({ checkingNetwork: false });
    }
  }

  async checkNow() {
    const check = await this.runNetworkCheck();
    this.store.update({ lastCheck: check });
    const firewallResult = await this.syncFirewallForStatus();
    const decoratedCheck = this.decorateCheckWithFirewall(check, firewallResult);
    this.store.update({ lastCheck: decoratedCheck });
    this.emit({ type: 'check-complete', check: decoratedCheck, firewallResult, status: this.getStatus() });
    return decoratedCheck;
  }

  sendJson(response, statusCode, body) {
    response.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify(body));
  }

  readJsonBody(request) {
    return new Promise((resolve, reject) => {
      let body = '';
      request.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1024 * 1024) {
          reject(new Error('BODY_TOO_LARGE'));
          request.destroy();
        }
      });
      request.on('end', () => {
        if (!body) {
          resolve({});
          return;
        }
        try {
          resolve(JSON.parse(body));
        } catch {
          reject(new Error('INVALID_JSON'));
        }
      });
    });
  }

  async handleApi(request, response) {
    try {
      if (request.method === 'GET' && request.url === '/status') {
        this.sendJson(response, 200, this.getStatus());
        return;
      }

      if (request.method === 'GET' && request.url === '/events') {
        response.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive'
        });
        response.write('\n');
        this.clients.add(response);
        request.on('close', () => this.clients.delete(response));
        return;
      }

      if (request.method === 'POST' && request.url === '/guard/enable') {
        const body = await this.readJsonBody(request);
        this.sendJson(response, 200, await this.enableGuard(body.mode || GuardMode.AUTO));
        return;
      }

      if (request.method === 'POST' && request.url === '/guard/disable') {
        this.sendJson(response, 200, await this.disableGuard());
        return;
      }

      if (request.method === 'POST' && request.url === '/check-now') {
        this.sendJson(response, 200, await this.checkNow());
        return;
      }

      if (request.method === 'POST' && request.url === '/environment') {
        this.sendJson(response, 200, this.updateClientEnvironment(await this.readJsonBody(request)));
        return;
      }

      if (request.method === 'POST' && request.url === '/rules/reload') {
        this.sendJson(response, 200, await this.reloadTargetConfig());
        return;
      }

      if (request.method === 'POST' && request.url === '/config/static-ip') {
        const body = await this.readJsonBody(request);
        this.sendJson(response, 200, this.setStaticResidentialIp(body.staticResidentialIp || ''));
        return;
      }

      this.sendJson(response, 404, { error: 'NOT_FOUND' });
    } catch (error) {
      this.sendJson(response, 500, { error: error.message || 'INTERNAL_ERROR' });
    }
  }
}

module.exports = {
  GuardService,
  shouldUseSystemProxy
};
