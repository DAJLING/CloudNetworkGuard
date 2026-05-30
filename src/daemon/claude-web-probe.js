const { CheckReason, NetworkVerdict } = require('../shared/constants');

function headerValue(headers, name) {
  if (!headers || !headers.get) return null;
  return headers.get(name) || headers.get(name.toLowerCase()) || headers.get(name.toUpperCase());
}

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

    const cfMitigated = headerValue(response.headers, 'cf-mitigated');
    const isBrowserChallenge = response.status === 403 && String(cfMitigated || '').toLowerCase() === 'challenge';
    const ok = (response.status >= 200 && response.status < 400) || isBrowserChallenge;
    return {
      verdict: ok ? NetworkVerdict.PASS : NetworkVerdict.BLOCK,
      reasons: ok ? [] : [CheckReason.CLAUDE_WEB_CHECK_FAILED],
      status: response.status,
      location: headerValue(response.headers, 'location'),
      challenge: isBrowserChallenge ? 'cloudflare' : null
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
  headerValue,
  probeClaudeWeb
};
