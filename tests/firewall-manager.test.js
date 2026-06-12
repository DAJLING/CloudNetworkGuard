const test = require('node:test');
const assert = require('node:assert/strict');
const { FIREWALL_RULE_PREFIX, FIREWALL_TARGET_HOSTS, HOSTS_BLOCK_START, HOSTS_BLOCK_END, FirewallManager } = require('../src/daemon/firewall-manager');

async function withFirewallEnabled(fn) {
  const previous = process.env.NETWORK_GUARD_SKIP_FIREWALL;
  delete process.env.NETWORK_GUARD_SKIP_FIREWALL;
  try {
    return await fn();
  } finally {
    if (previous === undefined) {
      delete process.env.NETWORK_GUARD_SKIP_FIREWALL;
    } else {
      process.env.NETWORK_GUARD_SKIP_FIREWALL = previous;
    }
  }
}

test('firewall rule prefix is scoped to this app', () => {
  assert.equal(FIREWALL_RULE_PREFIX, 'ClaudeNetworkGuard');
});

test('firewall target hosts include only Claude and Anthropic endpoints', () => {
  assert.equal(FIREWALL_TARGET_HOSTS.includes('claude.ai'), true);
  assert.equal(FIREWALL_TARGET_HOSTS.includes('api.anthropic.com'), true);
  assert.deepEqual(FIREWALL_TARGET_HOSTS, ['claude.ai', 'api.anthropic.com', 'anthropic.com']);
});

test('hosts block renderer includes stable markers and target domains', () => {
  const manager = new FirewallManager({ hosts: ['api.anthropic.com'] });
  const block = manager.renderHostsBlock();
  assert.equal(block.includes(HOSTS_BLOCK_START), true);
  assert.equal(block.includes('0.0.0.0 api.anthropic.com'), true);
  assert.equal(block.includes(HOSTS_BLOCK_END), true);
  assert.equal(manager.removeHostsBlock(`before\n${block}\nafter`), 'before\nafter');
});

test('renderPfBlockRule renders IPv4 and IPv6 target set', () => {
  const { renderPfBlockRule } = require('../src/daemon/firewall-manager');
  assert.equal(
    renderPfBlockRule(['203.0.113.10', '2001:db8::10']),
    'block drop out quick to { 203.0.113.10, 2001:db8::10 }'
  );
});

test('renderPfBlockRule rejects invalid IP literals', () => {
  const { renderPfBlockRule } = require('../src/daemon/firewall-manager');
  for (const value of ['api.anthropic.com', '::::', 'abc:def', '1:2:3:4:5:6:7:8:9']) {
    assert.throws(() => renderPfBlockRule([value]), /INVALID_PF_IP/);
  }
});

test('renderPfBlockRule rejects empty input and blank entries', () => {
  const { renderPfBlockRule } = require('../src/daemon/firewall-manager');

  assert.throws(() => renderPfBlockRule([]), /PF_IPS_EMPTY/);
  assert.throws(() => renderPfBlockRule(['   ']), /INVALID_PF_IP/);
  assert.throws(() => renderPfBlockRule(['203.0.113.10', '']), /INVALID_PF_IP/);
  assert.throws(() => renderPfBlockRule(['203.0.113.10', '   ']), /INVALID_PF_IP/);
});

test('ensurePfAnchorBlock adds one marked anchor block', () => {
  const { ensurePfAnchorBlock, PF_CONF_BLOCK_START, PF_CONF_BLOCK_END } = require('../src/daemon/firewall-manager');
  const once = ensurePfAnchorBlock('set skip on lo0\n');
  const twice = ensurePfAnchorBlock(once);

  assert.equal(PF_CONF_BLOCK_START, '# ClaudeNetworkGuard PF START');
  assert.equal(PF_CONF_BLOCK_END, '# ClaudeNetworkGuard PF END');
  assert.match(once, new RegExp(PF_CONF_BLOCK_START));
  assert.match(once, /anchor "com\.local\.claude-network-guard"/);
  assert.match(once, /load anchor "com\.local\.claude-network-guard"/);
  assert.match(once, new RegExp(PF_CONF_BLOCK_END));
  assert.equal(twice, once);
});

test('removePfAnchorBlock removes only the marked block', () => {
  const { ensurePfAnchorBlock, removePfAnchorBlock } = require('../src/daemon/firewall-manager');
  const patched = ensurePfAnchorBlock('set skip on lo0\npass out all\n');

  assert.equal(removePfAnchorBlock(patched), 'set skip on lo0\npass out all\n');
});

test('removePfAnchorBlock preserves marker text outside whole marker lines', () => {
  const { removePfAnchorBlock } = require('../src/daemon/firewall-manager');
  const content = [
    'set skip on lo0',
    'pass out all # ClaudeNetworkGuard PF START',
    'anchor "other"',
    '# ClaudeNetworkGuard PF END is mentioned here'
  ].join('\n');

  assert.equal(removePfAnchorBlock(content), content);
});

test('removePfAnchorBlock removes marked CRLF anchor block', () => {
  const { removePfAnchorBlock } = require('../src/daemon/firewall-manager');
  const content = [
    'set skip on lo0',
    '# ClaudeNetworkGuard PF START',
    'anchor "com.local.claude-network-guard"',
    'load anchor "com.local.claude-network-guard" from "/etc/pf.anchors/com.local.claude-network-guard"',
    '# ClaudeNetworkGuard PF END',
    'pass out all'
  ].join('\r\n');

  assert.equal(removePfAnchorBlock(`${content}\r\n`), 'set skip on lo0\r\npass out all\r\n');
});

test('applyMacBlock writes anchor, patches pf.conf, and loads pf', async () => {
  await withFirewallEnabled(async () => {
    const { FirewallManager: TestFirewallManager } = require('../src/daemon/firewall-manager');
    const pfConfPath = '/tmp/network-guard-pf.conf';
    const pfAnchorPath = '/tmp/network-guard-anchor';
    const files = {
      [pfConfPath]: 'set skip on lo0\n'
    };
    const privilegedWrites = [];
    const privilegedCommands = [];
    const manager = new TestFirewallManager({
      hosts: ['api.anthropic.com'],
      platform: 'darwin',
      pfConfPath,
      pfAnchorPath,
      fsImpl: {
        existsSync: (filePath) => Object.prototype.hasOwnProperty.call(files, filePath),
        readFileSync: (filePath) => files[filePath],
        writeFileSync: (filePath, content) => {
          files[filePath] = content;
        }
      },
      resolveTargetIpsImpl: async () => ({
        ips: ['203.0.113.10'],
        results: [{ host: 'api.anthropic.com', ips: ['203.0.113.10'], errors: [] }]
      }),
      macRunner: {
        writeFilePrivileged: async (filePath, content) => {
          privilegedWrites.push({ filePath, content });
          files[filePath] = content;
        },
        removeFilePrivileged: async (filePath) => {
          delete files[filePath];
        },
        runPrivilegedCommands: async (commands) => {
          privilegedCommands.push(commands);
          return '';
        }
      }
    });

    const result = await manager.applyBlock();

    assert.equal(result.mode, 'PF_BLOCK');
    assert.equal(result.applied, true);
    assert.equal(privilegedWrites[0].filePath, pfAnchorPath);
    assert.match(privilegedWrites[0].content, /block drop out quick to \{ 203\.0\.113\.10 \}/);
    assert.equal(privilegedWrites[1].filePath, pfConfPath);
    assert.match(privilegedWrites[1].content, new RegExp(`load anchor "com\\.local\\.claude-network-guard" from "${pfAnchorPath}"`));
    assert.deepEqual(privilegedCommands[0], [
      ['pfctl', '-nf', pfConfPath],
      ['pfctl', '-f', pfConfPath],
      ['pfctl', '-e']
    ]);
  });
});

test('clearMacBlock removes anchor block and reloads pf.conf', async () => {
  await withFirewallEnabled(async () => {
    const {
      FirewallManager: TestFirewallManager,
      PF_ANCHOR_PATH
    } = require('../src/daemon/firewall-manager');
    const files = {
      '/etc/pf.conf': [
        'set skip on lo0',
        '# ClaudeNetworkGuard PF START',
        'anchor "com.local.claude-network-guard"',
        'load anchor "com.local.claude-network-guard" from "/etc/pf.anchors/com.local.claude-network-guard"',
        '# ClaudeNetworkGuard PF END',
        ''
      ].join('\n'),
      [PF_ANCHOR_PATH]: 'block drop out quick to { 203.0.113.10 }\n'
    };
    const commands = [];
    const manager = new TestFirewallManager({
      platform: 'darwin',
      fsImpl: {
        existsSync: (filePath) => Object.prototype.hasOwnProperty.call(files, filePath),
        readFileSync: (filePath) => files[filePath],
        writeFileSync: (filePath, content) => {
          files[filePath] = content;
        }
      },
      macRunner: {
        writeFilePrivileged: async (filePath, content) => {
          files[filePath] = content;
        },
        removeFilePrivileged: async (filePath) => {
          delete files[filePath];
        },
        runPrivilegedCommands: async (nextCommands) => {
          commands.push(nextCommands);
          return '';
        }
      }
    });

    const result = await manager.clearBlock();

    assert.equal(result.mode, 'PF_CLEARED');
    assert.equal(result.rules.length, 0);
    assert.doesNotMatch(files['/etc/pf.conf'], /ClaudeNetworkGuard PF START/);
    assert.equal(files[PF_ANCHOR_PATH], undefined);
    assert.deepEqual(commands[0], [
      ['pfctl', '-nf', '/etc/pf.conf'],
      ['pfctl', '-f', '/etc/pf.conf']
    ]);
  });
});

test('applyMacBlock returns partial result when authorization fails', async () => {
  await withFirewallEnabled(async () => {
    const { FirewallManager: TestFirewallManager } = require('../src/daemon/firewall-manager');
    const manager = new TestFirewallManager({
      hosts: ['api.anthropic.com'],
      platform: 'darwin',
      resolveTargetIpsImpl: async () => ({ ips: ['203.0.113.10'], results: [] }),
      macRunner: {
        writeFilePrivileged: async () => {
          throw new Error('AUTH_DENIED');
        },
        removeFilePrivileged: async () => {},
        runPrivilegedCommands: async () => ''
      }
    });

    const result = await manager.applyBlock();

    assert.equal(result.mode, 'PARTIAL_BLOCK');
    assert.equal(result.applied, false);
    assert.match(result.lastError, /AUTH_DENIED/);
  });
});
