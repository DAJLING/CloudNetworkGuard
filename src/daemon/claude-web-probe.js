const { CheckReason, NetworkVerdict } = require('../shared/constants');

async function probeClaudeWeb(fetchImpl = fetch, url = 'https://claude.ai/') {
  try {
    const response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'user-agent': 'Mozilla/5.0 ClaudeCodexNetworkGuard/0.1',
        accept: 'text/html,application/xhtml+xml'
      }
    });

    const ok = response.status >= 200 && response.status < 400;
    return {
      verdict: ok ? NetworkVerdict.PASS : NetworkVerdict.BLOCK,
      reasons: ok ? [] : [CheckReason.CLAUDE_WEB_CHECK_FAILED],
      status: response.status,
      location: response.headers && response.headers.get ? response.headers.get('location') : null
    };
  } catch (error) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reasons: [CheckReason.CLAUDE_WEB_CHECK_FAILED],
      status: null,
      error: error && error.message ? error.message : 'UNKNOWN_ERROR'
    };
  }
}

module.exports = {
  probeClaudeWeb
};
