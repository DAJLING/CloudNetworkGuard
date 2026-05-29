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

class ProxyManager {
  constructor({ host = '127.0.0.1', port = 18089 } = {}) {
    this.host = host;
    this.port = port;
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
    await execFilePromise('reg', [
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
    await execFilePromise('reg', [
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
    await execFilePromise('reg', [
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
    const service = process.env.NETWORK_GUARD_MAC_SERVICE || 'Wi-Fi';
    await execFilePromise('networksetup', ['-setwebproxy', service, this.host, String(this.port)]);
    await execFilePromise('networksetup', ['-setsecurewebproxy', service, this.host, String(this.port)]);
    return { applied: true, platform: 'darwin', service, proxy: this.getProxyAddress() };
  }

  async disableMac() {
    const service = process.env.NETWORK_GUARD_MAC_SERVICE || 'Wi-Fi';
    await execFilePromise('networksetup', ['-setwebproxystate', service, 'off']);
    await execFilePromise('networksetup', ['-setsecurewebproxystate', service, 'off']);
    return { applied: true, platform: 'darwin', service };
  }
}

module.exports = {
  ProxyManager
};
