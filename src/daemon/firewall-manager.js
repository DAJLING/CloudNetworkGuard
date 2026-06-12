const dns = require('dns').promises;
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { MacCommandRunner } = require('./macos-command-runner');

const FIREWALL_RULE_PREFIX = 'ClaudeNetworkGuard';
const FIREWALL_TARGET_HOSTS = [
  'claude.ai',
  'api.anthropic.com',
  'anthropic.com'
];
const HOSTS_BLOCK_START = '# ClaudeNetworkGuard START';
const HOSTS_BLOCK_END = '# ClaudeNetworkGuard END';
const PF_ANCHOR_NAME = 'com.local.claude-network-guard';
const PF_ANCHOR_PATH = `/etc/pf.anchors/${PF_ANCHOR_NAME}`;
const PF_CONF_PATH = '/etc/pf.conf';
const PF_CONF_BLOCK_START = '# ClaudeNetworkGuard PF START';
const PF_CONF_BLOCK_END = '# ClaudeNetworkGuard PF END';

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

function sanitizeRuleName(value) {
  return String(value).replace(/[^a-zA-Z0-9_.:-]/g, '_');
}

function isValidIpLiteral(value) {
  const text = String(value || '').trim();
  return net.isIP(text) !== 0;
}

function renderPfBlockRule(ips = []) {
  const normalized = ips.map((ip) => String(ip || '').trim());
  if (!normalized.length) throw new Error('PF_IPS_EMPTY');
  for (const ip of normalized) {
    if (!isValidIpLiteral(ip)) throw new Error(`INVALID_PF_IP:${ip}`);
  }
  const unique = Array.from(new Set(normalized));
  return `block drop out quick to { ${unique.join(', ')} }`;
}

function escapeRegExpLiteral(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function removePfAnchorBlock(content = '') {
  const start = escapeRegExpLiteral(PF_CONF_BLOCK_START);
  const end = escapeRegExpLiteral(PF_CONF_BLOCK_END);
  const pattern = new RegExp(`^[\\t ]*${start}[\\t ]*(?:\\r?\\n|\\r)[\\s\\S]*?^[\\t ]*${end}[\\t ]*(?:\\r?\\n|\\r|$)`, 'gm');
  return String(content || '').replace(pattern, '');
}

function ensurePfAnchorBlock(
  content = '',
  { anchorName = PF_ANCHOR_NAME, anchorPath = PF_ANCHOR_PATH } = {}
) {
  const cleaned = removePfAnchorBlock(content);
  const block = [
    PF_CONF_BLOCK_START,
    `anchor "${anchorName}"`,
    `load anchor "${anchorName}" from "${anchorPath}"`,
    PF_CONF_BLOCK_END
  ].join('\n');
  return `${cleaned.replace(/\s+$/g, '')}${cleaned.trim() ? '\n' : ''}${block}\n`;
}

async function isWindowsElevated(execFileImpl = execFilePromise) {
  if (process.platform !== 'win32') return false;
  try {
    await execFileImpl('net', ['session']);
    return true;
  } catch {
    return false;
  }
}

async function resolveTargetIps(hosts = FIREWALL_TARGET_HOSTS) {
  const ips = new Set();
  const results = [];

  for (const host of hosts) {
    const hostResult = { host, ips: [], errors: [] };
    for (const family of [4, 6]) {
      try {
        const records = family === 4 ? await dns.resolve4(host) : await dns.resolve6(host);
        for (const ip of records) {
          ips.add(ip);
          hostResult.ips.push(ip);
        }
      } catch (error) {
        hostResult.errors.push(error.code || error.message);
      }
    }
    results.push(hostResult);
  }

  return {
    ips: Array.from(ips),
    results
  };
}

class FirewallManager {
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

  setHosts(hosts = []) {
    this.hosts = Array.from(new Set(hosts.filter(Boolean)));
  }

  async applyBlock() {
    if (process.env.NETWORK_GUARD_SKIP_FIREWALL === '1') {
      return { applied: false, mode: 'SKIPPED', rules: [], lastError: null };
    }

    if (this.platform === 'win32') return this.applyWindowsBlock();
    if (this.platform === 'darwin') return this.applyMacBlock();

    return { applied: false, mode: 'UNSUPPORTED_PLATFORM', rules: [], lastError: this.platform };
  }

  async clearBlock(existingRules = []) {
    if (process.env.NETWORK_GUARD_SKIP_FIREWALL === '1') {
      return { applied: false, mode: 'SKIPPED', rules: [], lastError: null };
    }

    if (this.platform === 'win32') return this.clearWindowsBlock(existingRules);
    if (this.platform === 'darwin') return this.clearMacBlock();
    return { applied: false, mode: 'UNSUPPORTED_PLATFORM', rules: [], lastError: null };
  }

  async applyWindowsBlock() {
    if (!(await isWindowsElevated())) {
      return {
        applied: false,
        mode: 'SKIPPED',
        rules: [],
        lastError: '需要管理员权限才能配置 Windows 防火墙规则，请以管理员身份运行本应用。'
      };
    }

    const resolved = await this.resolveTargetIps(this.hosts);
    const rules = [];
    const errors = [];

    for (const ip of resolved.ips) {
      const ruleName = `${FIREWALL_RULE_PREFIX}_${sanitizeRuleName(ip)}`;
      try {
        await execFilePromise('netsh', [
          'advfirewall',
          'firewall',
          'delete',
          'rule',
          `name=${ruleName}`
        ]).catch(() => {});
        await execFilePromise('netsh', [
          'advfirewall',
          'firewall',
          'add',
          'rule',
          `name=${ruleName}`,
          'dir=out',
          'action=block',
          `remoteip=${ip}`,
          'enable=yes'
        ]);
        rules.push({ name: ruleName, remoteIp: ip });
      } catch (error) {
        errors.push(`${ip}: ${error.message}`);
      }
    }

    const useHostsBlock = process.env.NETWORK_GUARD_USE_HOSTS_BLOCK === '1';
    const hostsResult = useHostsBlock
      ? await this.applyHostsBlock().catch((error) => ({
          applied: false,
          error: error.message
        }))
      : { applied: false, skipped: true, reason: 'HOSTS_BLOCK_DISABLED' };

    return {
      applied: rules.length > 0 || hostsResult.applied === true,
      mode: errors.length || hostsResult.error ? 'PARTIAL_BLOCK' : 'BLOCK',
      rules,
      hosts: hostsResult,
      resolved,
      lastError: [...errors, hostsResult.error].filter(Boolean).join('; ') || null
    };
  }

  async clearWindowsBlock(existingRules = []) {
    if (!(await isWindowsElevated())) {
      return {
        applied: false,
        mode: 'SKIPPED',
        rules: [],
        lastError: '未以管理员运行，跳过清理防火墙规则（不影响环境检测）。'
      };
    }

    const rules = existingRules.length
      ? existingRules
      : (await this.resolveTargetIps(this.hosts)).ips.map((ip) => ({
          name: `${FIREWALL_RULE_PREFIX}_${sanitizeRuleName(ip)}`,
          remoteIp: ip
        }));
    const errors = [];

    for (const rule of rules) {
      try {
        await execFilePromise('netsh', [
          'advfirewall',
          'firewall',
          'delete',
          'rule',
          `name=${rule.name}`
        ]);
      } catch (error) {
        errors.push(`${rule.name}: ${error.message}`);
      }
    }

    const hostsResult = await this.clearHostsBlock().catch((error) => ({
      applied: false,
      error: error.message
    }));

    return {
      applied: true,
      mode: hostsResult.error ? 'PARTIAL_CLEAR' : 'CLEARED',
      rules: [],
      hosts: hostsResult,
      lastError: [...errors, hostsResult.error].filter(Boolean).join('; ') || null
    };
  }

  readPfConf() {
    if (!this.fs.existsSync(this.pfConfPath)) return '';
    return this.fs.readFileSync(this.pfConfPath, 'utf8');
  }

  async applyMacBlock() {
    let resolved = { ips: [], results: [] };
    try {
      resolved = await this.resolveTargetIps(this.hosts);
      const ips = Array.isArray(resolved.ips) ? resolved.ips : [];
      if (!ips.length) {
        return {
          applied: false,
          mode: 'PARTIAL_BLOCK',
          rules: [],
          resolved,
          lastError: 'PF_IPS_EMPTY'
        };
      }

      const ruleText = `${renderPfBlockRule(ips)}\n`;
      const patchedPfConf = ensurePfAnchorBlock(this.readPfConf(), {
        anchorName: PF_ANCHOR_NAME,
        anchorPath: this.pfAnchorPath
      });

      await this.macRunner.writeFilePrivileged(this.pfAnchorPath, ruleText);
      await this.macRunner.writeFilePrivileged(this.pfConfPath, patchedPfConf);
      await this.macRunner.runPrivilegedCommands([
        ['pfctl', '-nf', this.pfConfPath],
        ['pfctl', '-f', this.pfConfPath],
        ['pfctl', '-e']
      ]);

      return {
        applied: true,
        mode: 'PF_BLOCK',
        rules: [{ anchor: PF_ANCHOR_NAME, ips }],
        resolved,
        lastError: null
      };
    } catch (error) {
      return {
        applied: false,
        mode: 'PARTIAL_BLOCK',
        rules: [],
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
      await this.macRunner.runPrivilegedCommands([
        ['pfctl', '-nf', this.pfConfPath],
        ['pfctl', '-f', this.pfConfPath]
      ]);
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

  getHostsPath() {
    if (this.platform === 'win32') {
      return path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts');
    }
    return '/etc/hosts';
  }

  renderHostsBlock() {
    const lines = [HOSTS_BLOCK_START];
    for (const host of this.hosts) {
      lines.push(`0.0.0.0 ${host}`);
      lines.push(`:: ${host}`);
    }
    lines.push(HOSTS_BLOCK_END);
    return lines.join(os.EOL);
  }

  removeHostsBlock(content) {
    const pattern = new RegExp(`${HOSTS_BLOCK_START}[\\s\\S]*?${HOSTS_BLOCK_END}\\r?\\n?`, 'g');
    return content.replace(pattern, '').trimEnd();
  }

  async applyHostsBlock() {
    const hostsPath = this.getHostsPath();
    const current = this.fs.existsSync(hostsPath) ? this.fs.readFileSync(hostsPath, 'utf8') : '';
    const cleaned = this.removeHostsBlock(current);
    const next = `${cleaned}${cleaned ? os.EOL : ''}${this.renderHostsBlock()}${os.EOL}`;
    this.fs.writeFileSync(hostsPath, next);
    return { applied: true, hostsPath, hosts: this.hosts };
  }

  async clearHostsBlock() {
    const hostsPath = this.getHostsPath();
    if (!this.fs.existsSync(hostsPath)) return { applied: false, hostsPath };
    const current = this.fs.readFileSync(hostsPath, 'utf8');
    this.fs.writeFileSync(hostsPath, `${this.removeHostsBlock(current)}${os.EOL}`);
    return { applied: true, hostsPath };
  }
}

module.exports = {
  FIREWALL_RULE_PREFIX,
  FIREWALL_TARGET_HOSTS,
  HOSTS_BLOCK_START,
  HOSTS_BLOCK_END,
  PF_ANCHOR_NAME,
  PF_ANCHOR_PATH,
  PF_CONF_PATH,
  PF_CONF_BLOCK_START,
  PF_CONF_BLOCK_END,
  renderPfBlockRule,
  ensurePfAnchorBlock,
  removePfAnchorBlock,
  isValidIpLiteral,
  resolveTargetIps,
  isWindowsElevated,
  FirewallManager
};
