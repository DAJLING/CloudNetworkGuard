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
