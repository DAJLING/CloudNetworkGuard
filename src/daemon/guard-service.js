const http = require('http');
const path = require('path');
const { Store } = require('./store');
const { NetworkChecker } = require('./network-checker');
const { ProxyManager } = require('./proxy-manager');
const { GuardProxy } = require('./guard-proxy');
const { recordTargetUsage } = require('./usage-monitor');
const { FirewallManager } = require('./firewall-manager');
const { TARGET_CONFIG_FILE, TargetConfigManager } = require('./target-config');
const { GuardMode, GuardState, NetworkVerdict } = require('../shared/constants');

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
  }

  async start() {
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
    return {
      guardState: state.guardState,
      guardMode: this.normalizeGuardMode(state.guardMode),
      launchAtLogin: state.launchAtLogin,
      proxy: {
        host: this.proxyManager.host,
        port: this.proxyManager.port
      },
      lastCheck: state.lastCheck,
      firewall: state.firewall,
      clientEnvironment: state.clientEnvironment,
      actionRequired: state.actionRequired || null,
      targetConfig: this.targetConfig,
      logs: state.logs || []
    };
  }

  normalizeGuardMode(mode) {
    if (mode === 'STRICT_BLOCK') return GuardMode.STRICT_VALIDATE;
    if (mode === GuardMode.STRICT_VALIDATE) return GuardMode.STRICT_VALIDATE;
    return GuardMode.AUTO;
  }

  async syncFirewallForStatus() {
    const state = this.store.getState();
    const shouldBlock =
      state.guardState === GuardState.ENABLED &&
      (!state.lastCheck || state.lastCheck.allowTargetTraffic !== true);
    const currentRules = state.firewall && state.firewall.rules ? state.firewall.rules : [];
    this.firewallManager.setHosts(this.targetConfig.firewallHosts || []);

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
    const mode = firewallResult && firewallResult.mode ? firewallResult.mode : 'UNKNOWN';
    const verdict =
      mode === 'ERROR' || mode === 'PARTIAL_BLOCK' || mode === 'PARTIAL_CLEAR'
        ? 'FAIL'
        : mode === 'SKIPPED' || mode === 'UNSUPPORTED_PLATFORM'
          ? 'SKIPPED'
          : 'PASS';
    const firewallItem = {
      id: 'firewall',
      label: '防火墙兜底',
      verdict,
      detail: firewallResult && firewallResult.lastError ? `${mode} / ${firewallResult.lastError}` : mode,
      reason: verdict === 'FAIL' ? 'FIREWALL_ERROR' : null
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

  emit(event) {
    const payload = JSON.stringify(event);
    for (const client of this.clients) {
      client.write(`data: ${payload}\n\n`);
    }
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

    const proxyResult = await this.proxyManager.enable();
    const pendingCheck = {
      checkedAt: new Date().toISOString(),
      verdict: NetworkVerdict.BLOCK,
      reasons: ['CHECK_PENDING'],
      allowTargetTraffic: false,
      checkItems: [
        staticPreflight.checkItem,
        {
          id: 'guard-startup',
          label: '守卫启动',
          verdict: 'PENDING',
          detail: '正在校验网络状态',
          reason: 'CHECK_PENDING'
        }
      ]
    };
    this.store.update({
      guardState: GuardState.ENABLED,
      guardMode: this.normalizeGuardMode(mode),
      actionRequired: null,
      lastCheck: pendingCheck
    });
    await this.syncFirewallForStatus();
    const check = await this.checker.checkNow();
    const firewallResult = await this.syncFirewallForStatus();
    const decoratedCheck = this.decorateCheckWithFirewall(check, firewallResult);
    this.store.update({ lastCheck: decoratedCheck });
    const status = this.getStatus();
    this.emit({ type: 'guard-enabled', proxyResult, firewallResult, status, check: decoratedCheck });
    return status;
  }

  async disableGuard() {
    const proxyResult = await this.proxyManager.disable();
    this.store.update({ guardState: GuardState.DISABLED });
    const firewallResult = await this.syncFirewallForStatus();
    const status = this.getStatus();
    this.emit({ type: 'guard-disabled', proxyResult, firewallResult, status });
    return status;
  }

  async checkNow() {
    const check = await this.checker.checkNow();
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
  GuardService
};
