function withTimeout(ms) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ms);
  return {
    signal: controller.signal,
    done: () => clearTimeout(timeout)
  };
}

async function fetchJson(url, timeoutMs = 5000) {
  const timeout = withTimeout(timeoutMs);
  try {
    const response = await fetch(url, {
      signal: timeout.signal,
      headers: {
        'user-agent': 'ClaudeCodexNetworkGuard/0.1'
      }
    });
    if (!response.ok) throw new Error(`HTTP_${response.status}`);
    return await response.json();
  } finally {
    timeout.done();
  }
}

function mapIpWhoIs(data) {
  const connection = data.connection || {};
  const security = data.security || {};
  const type = connection.type ? String(connection.type).toLowerCase() : 'unknown';
  const ipType = type.includes('hosting') ? 'hosting' : type.includes('isp') ? 'residential' : type || 'unknown';

  return {
    source: 'ipwho.is',
    ip: data.ip,
    ipType,
    countryCode: data.country_code || 'unknown',
    regionName: data.country || data.region || 'unknown',
    asn: connection.asn ? `AS${connection.asn}` : null,
    isProxy: Boolean(security.proxy),
    isVpn: Boolean(security.vpn),
    isTor: Boolean(security.tor),
    isBlacklisted: false,
    riskScore: security.proxy || security.vpn || security.tor ? 75 : 10,
    confidence: 35
  };
}

function mapIpApi(data) {
  const proxy = Boolean(data.proxy);
  const hosting = Boolean(data.hosting);
  return {
    source: 'ip-api.com',
    ip: data.query,
    ipType: hosting ? 'hosting' : 'unknown',
    countryCode: data.countryCode || 'unknown',
    regionName: data.country || data.regionName || 'unknown',
    asn: data.as || null,
    isProxy: proxy,
    isVpn: false,
    isTor: false,
    isBlacklisted: false,
    riskScore: proxy || hosting ? 70 : 15,
    confidence: 25
  };
}

async function runFreeProviders() {
  const providers = [
    async () => mapIpWhoIs(await fetchJson('https://ipwho.is/')),
    async () => mapIpApi(await fetchJson('http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,as,proxy,hosting'))
  ];

  return Promise.all(
    providers.map(async (provider) => {
      try {
        return await provider();
      } catch (error) {
        return {
          source: 'free-provider',
          error: error && error.message ? error.message : 'UNKNOWN_ERROR'
        };
      }
    })
  );
}

module.exports = {
  fetchJson,
  runFreeProviders,
  mapIpWhoIs,
  mapIpApi
};
