const { execFile } = require('child_process');

function execFilePromise(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || stdout || error.message));
        return;
      }
      resolve(stdout);
    });
  });
}

function parseMacNetworkServices(output = '') {
  return String(output)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.startsWith('An asterisk'))
    .filter((line) => !line.startsWith('*'));
}

function parseMacProxyState(output = '') {
  const state = {};
  for (const line of String(output).split(/\r?\n/)) {
    const match = line.match(/^\s*([^:]+):\s*(.*?)\s*$/);
    if (!match) continue;
    state[match[1].trim()] = match[2].trim();
  }
  return {
    enabled: /^yes$/i.test(state.Enabled || ''),
    server: state.Server || '',
    port: Number(state.Port) || 0,
    authenticated: state['Authenticated Proxy Enabled'] || '0'
  };
}

function macProxyStateMatches(state, host, port) {
  return Boolean(state && state.enabled && state.server === host && Number(state.port) === Number(port));
}

function proxyStateToUpstream(state, ownHost, ownPort) {
  if (!state || !state.enabled || !state.server || !state.port) return null;
  if (state.server === ownHost && Number(state.port) === Number(ownPort)) return null;
  return {
    protocol: 'http:',
    host: state.server,
    port: Number(state.port)
  };
}

class ProxyManager {
  constructor({ host = '127.0.0.1', port = 18089, execFileImpl = execFilePromise } = {}) {
    this.host = host;
    this.port = port;
    this.execFile = execFileImpl;
  }

  getProxyAddress() {
    return `${this.host}:${this.port}`;
  }

  async enable() {
    if (process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY === '1') {
      return { applied: false, reason: 'SKIPPED_BY_ENV' };
    }

    if (process.platform === 'win32') return this.enableWindows();
    if (process.platform === 'darwin') return this.enableMac();
    return { applied: false, reason: 'UNSUPPORTED_PLATFORM' };
  }

  async disable() {
    if (process.env.NETWORK_GUARD_SKIP_SYSTEM_PROXY === '1') {
      return { applied: false, reason: 'SKIPPED_BY_ENV' };
    }

    if (process.platform === 'win32') return this.disableWindows();
    if (process.platform === 'darwin') return this.disableMac();
    return { applied: false, reason: 'UNSUPPORTED_PLATFORM' };
  }

  async enableWindows() {
    const proxy = `http=${this.getProxyAddress()};https=${this.getProxyAddress()}`;
    await this.execFile('reg', [
      'add',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
      '/v',
      'ProxyEnable',
      '/t',
      'REG_DWORD',
      '/d',
      '1',
      '/f'
    ]);
    await this.execFile('reg', [
      'add',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
      '/v',
      'ProxyServer',
      '/t',
      'REG_SZ',
      '/d',
      proxy,
      '/f'
    ]);
    return { applied: true, platform: 'win32', proxy };
  }

  async disableWindows() {
    await this.execFile('reg', [
      'add',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
      '/v',
      'ProxyEnable',
      '/t',
      'REG_DWORD',
      '/d',
      '0',
      '/f'
    ]);
    return { applied: true, platform: 'win32' };
  }

  async enableMac() {
    const services = await this.getMacServices();
    const upstreamProxy = await this.detectMacUpstreamProxy(services);
    const results = [];
    for (const service of services) {
      try {
        await this.execFile('networksetup', ['-setwebproxy', service, this.host, String(this.port)]);
        await this.execFile('networksetup', ['-setsecurewebproxy', service, this.host, String(this.port)]);
        results.push({ service, applied: true });
      } catch (error) {
        results.push({ service, applied: false, error: error.message || 'PROXY_APPLY_FAILED' });
      }
    }
    const appliedServices = results.filter((result) => result.applied).map((result) => result.service);
    if (!appliedServices.length) {
      throw new Error(results.map((result) => `${result.service}: ${result.error}`).join('; ') || 'NO_MAC_NETWORK_SERVICES');
    }
    const verification = await this.verifyMacProxyApplied(appliedServices);
    if (!verification.ok) {
      throw new Error(
        verification.results
          .filter((result) => !result.ok)
          .map((result) => `${result.service}: ${result.error || `HTTP ${result.http.server}:${result.http.port}, HTTPS ${result.https.server}:${result.https.port}`}`)
          .join('; ') || 'MAC_PROXY_NOT_EFFECTIVE'
      );
    }
    return {
      applied: true,
      platform: 'darwin',
      service: appliedServices[0],
      services: appliedServices,
      results,
      verification,
      upstreamProxy,
      proxy: this.getProxyAddress()
    };
  }

  async disableMac() {
    const services = await this.getMacServices();
    const results = [];
    for (const service of services) {
      try {
        await this.execFile('networksetup', ['-setwebproxystate', service, 'off']);
        await this.execFile('networksetup', ['-setsecurewebproxystate', service, 'off']);
        results.push({ service, applied: true });
      } catch (error) {
        results.push({ service, applied: false, error: error.message || 'PROXY_CLEAR_FAILED' });
      }
    }
    const appliedServices = results.filter((result) => result.applied).map((result) => result.service);
    if (!appliedServices.length) {
      throw new Error(results.map((result) => `${result.service}: ${result.error}`).join('; ') || 'NO_MAC_NETWORK_SERVICES');
    }
    return { applied: true, platform: 'darwin', service: appliedServices[0], services: appliedServices, results };
  }

  async getMacServices() {
    const configured = String(process.env.NETWORK_GUARD_MAC_SERVICE || '').trim();
    if (configured) return [configured];
    const output = await this.execFile('networksetup', ['-listallnetworkservices']);
    const services = parseMacNetworkServices(output);
    if (!services.length) throw new Error('NO_MAC_NETWORK_SERVICES');
    return services;
  }

  async getMacServiceProxyState(service, secure = false) {
    const output = await this.execFile('networksetup', [secure ? '-getsecurewebproxy' : '-getwebproxy', service]);
    return parseMacProxyState(output);
  }

  async verifyMacProxyApplied(services = null) {
    const targetServices = services || (await this.getMacServices());
    const results = [];
    for (const service of targetServices) {
      try {
        const [http, https] = await Promise.all([
          this.getMacServiceProxyState(service, false),
          this.getMacServiceProxyState(service, true)
        ]);
        results.push({
          service,
          ok: macProxyStateMatches(http, this.host, this.port) && macProxyStateMatches(https, this.host, this.port),
          http,
          https,
          error: null
        });
      } catch (error) {
        results.push({ service, ok: false, http: null, https: null, error: error.message || 'MAC_PROXY_VERIFY_FAILED' });
      }
    }
    return {
      ok: results.length > 0 && results.every((result) => result.ok),
      services: targetServices,
      results
    };
  }

  async detectMacUpstreamProxy(services = null) {
    const targetServices = services || (await this.getMacServices());
    for (const service of targetServices) {
      try {
        const https = await this.getMacServiceProxyState(service, true);
        const upstream = proxyStateToUpstream(https, this.host, this.port);
        if (upstream) return { ...upstream, source: service, kind: 'https' };
      } catch {}
      try {
        const http = await this.getMacServiceProxyState(service, false);
        const upstream = proxyStateToUpstream(http, this.host, this.port);
        if (upstream) return { ...upstream, source: service, kind: 'http' };
      } catch {}
    }
    return null;
  }
}

module.exports = {
  parseMacNetworkServices,
  parseMacProxyState,
  ProxyManager
};
