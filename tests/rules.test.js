const test = require('node:test');
const assert = require('node:assert/strict');
const { domainMatches, isGuardedTarget } = require('../src/daemon/rules');

test('domainMatches supports exact and wildcard target domains', () => {
  assert.equal(domainMatches('claude.ai', 'claude.ai'), true);
  assert.equal(domainMatches('*.claude.ai', 'api.claude.ai'), true);
  assert.equal(domainMatches('*.claude.ai', 'deep.api.claude.ai'), true);
  assert.equal(domainMatches('*.claude.ai', 'notclaude.ai'), false);
});

test('isGuardedTarget guards only Claude and Anthropic domains by default', () => {
  assert.equal(isGuardedTarget('api.anthropic.com'), true);
  assert.equal(isGuardedTarget('claude.ai'), true);
  assert.equal(isGuardedTarget('example.com'), false);
});

test('isGuardedTarget accepts custom editable rules', () => {
  const rules = [{ id: 'example', domainPattern: '*.example.com', processNames: [], action: 'GUARD' }];

  assert.equal(isGuardedTarget('api.example.com', rules), true);
  assert.equal(isGuardedTarget('claude.ai', rules), false);
});
