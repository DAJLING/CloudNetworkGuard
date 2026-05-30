const test = require('node:test');
const assert = require('node:assert/strict');
const { probeClaudeWeb } = require('../src/daemon/claude-web-probe');
const { CheckReason, NetworkVerdict } = require('../src/shared/constants');

test('probeClaudeWeb passes successful and redirect responses', async () => {
  const result = await probeClaudeWeb(async () => ({
    status: 302,
    headers: { get: () => 'https://claude.ai/login' }
  }));

  assert.equal(result.verdict, NetworkVerdict.PASS);
});

test('probeClaudeWeb blocks forbidden responses', async () => {
  const result = await probeClaudeWeb(async () => ({
    status: 403,
    headers: { get: () => null }
  }));

  assert.equal(result.verdict, NetworkVerdict.BLOCK);
  assert.equal(result.reasons.includes(CheckReason.CLAUDE_WEB_CHECK_FAILED), true);
});

test('probeClaudeWeb treats Cloudflare browser challenges as reachable', async () => {
  const result = await probeClaudeWeb(async () => ({
    status: 403,
    headers: {
      get: (name) => (name.toLowerCase() === 'cf-mitigated' ? 'challenge' : null)
    }
  }));

  assert.equal(result.verdict, NetworkVerdict.PASS);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.status, 403);
  assert.equal(result.challenge, 'cloudflare');
});
