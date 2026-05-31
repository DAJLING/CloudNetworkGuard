const test = require('node:test');
const assert = require('node:assert/strict');
const { FIREWALL_RULE_PREFIX, FIREWALL_TARGET_HOSTS, HOSTS_BLOCK_START, HOSTS_BLOCK_END, FirewallManager } = require('../src/daemon/firewall-manager');

test('firewall rule prefix is scoped to this app', () => {
  assert.equal(FIREWALL_RULE_PREFIX, 'ClaudeCodexNetworkGuard');
});

test('firewall target hosts include Claude and Codex/OpenAI endpoints', () => {
  assert.equal(FIREWALL_TARGET_HOSTS.includes('claude.ai'), true);
  assert.equal(FIREWALL_TARGET_HOSTS.includes('api.anthropic.com'), true);
  assert.equal(FIREWALL_TARGET_HOSTS.includes('api.openai.com'), true);
  assert.equal(FIREWALL_TARGET_HOSTS.includes('chatgpt.com'), true);
});

test('hosts block renderer includes stable markers and target domains', () => {
  const manager = new FirewallManager({ hosts: ['api.openai.com'] });
  const block = manager.renderHostsBlock();
  assert.equal(block.includes(HOSTS_BLOCK_START), true);
  assert.equal(block.includes('0.0.0.0 api.openai.com'), true);
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
  for (const value of ['api.openai.com', '::::', 'abc:def', '1:2:3:4:5:6:7:8:9']) {
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

  assert.equal(PF_CONF_BLOCK_START, '# ClaudeCodexNetworkGuard PF START');
  assert.equal(PF_CONF_BLOCK_END, '# ClaudeCodexNetworkGuard PF END');
  assert.match(once, new RegExp(PF_CONF_BLOCK_START));
  assert.match(once, /anchor "com\.local\.claude-codex-network-guard"/);
  assert.match(once, /load anchor "com\.local\.claude-codex-network-guard"/);
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
    'pass out all # ClaudeCodexNetworkGuard PF START',
    'anchor "other"',
    '# ClaudeCodexNetworkGuard PF END is mentioned here'
  ].join('\n');

  assert.equal(removePfAnchorBlock(content), content);
});

test('removePfAnchorBlock removes marked CRLF anchor block', () => {
  const { removePfAnchorBlock } = require('../src/daemon/firewall-manager');
  const content = [
    'set skip on lo0',
    '# ClaudeCodexNetworkGuard PF START',
    'anchor "com.local.claude-codex-network-guard"',
    'load anchor "com.local.claude-codex-network-guard" from "/etc/pf.anchors/com.local.claude-codex-network-guard"',
    '# ClaudeCodexNetworkGuard PF END',
    'pass out all'
  ].join('\r\n');

  assert.equal(removePfAnchorBlock(`${content}\r\n`), 'set skip on lo0\r\npass out all\r\n');
});
