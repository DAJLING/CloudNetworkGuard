function withTimeout(ms) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ms);
  return {
    signal: controller.signal,
    done: () => clearTimeout(timeout)
  };
}

function getFetchImplementation() {
  try {
    const electron = require('electron');
    if (electron && electron.net && typeof electron.net.fetch === 'function') {
      return electron.net.fetch.bind(electron.net);
    }
  } catch {
    // Running in plain Node tests or CLI diagnostics.
  }
  return fetch;
}

async function fetchJson(url, timeoutMs = 5000) {
  const timeout = withTimeout(timeoutMs);
  const fetchImpl = getFetchImplementation();
  try {
    const response = await fetchImpl(url, {
      signal: timeout.signal,
      headers: {
        'user-agent': 'ClaudeNetworkGuard/0.1'
      }
    });
    if (!response.ok) throw new Error(`HTTP_${response.status}`);
    return await response.json();
  } finally {
    timeout.done();
  }
}

function providerError(source, error) {
  const cause = error && error.cause ? error.cause : null;
  const causeCode = cause && (cause.code || cause.name || cause.message);
  const message = error && error.message ? error.message : 'UNKNOWN_ERROR';
  return {
    source,
    error: causeCode && causeCode !== message ? `${message}: ${causeCode}` : message
  };
}

async function fetchText(url, timeoutMs = 5000) {
  const timeout = withTimeout(timeoutMs);
  const fetchImpl = getFetchImplementation();
  try {
    const response = await fetchImpl(url, {
      signal: timeout.signal,
      headers: {
        'user-agent': 'Mozilla/5.0 ClaudeNetworkGuard/0.1'
      }
    });
    if (!response.ok) throw new Error(`HTTP_${response.status}`);
    return await response.text();
  } finally {
    timeout.done();
  }
}

function parseNumber(value) {
  const match = String(value || '').replace(/,/g, '').match(/\d+(?:\.\d+)?/);
  return match ? Number(match[0]) : null;
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== '');
}

function parseSharedUsers(value) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return { label: null, max: null };
  const plus = text.match(/(\d[\d,]*)\s*\+/);
  if (plus) return { label: text, max: Number(plus[1].replace(/,/g, '')) + 1 };
  const range = text.match(/(\d[\d,]*)\s*-\s*(\d[\d,]*)/);
  if (range) return { label: text, max: Number(range[2].replace(/,/g, '')) };
  const single = parseNumber(text);
  return { label: text, max: single };
}

function purityFromRiskScore(riskScore) {
  if (typeof riskScore !== 'number' || !Number.isFinite(riskScore)) return null;
  if (riskScore <= 30) return '低风险';
  if (riskScore <= 60) return '中性';
  return '高风险';
}

function hasPing0Captcha(html) {
  const text = String(html || '').toLowerCase();
  return text.includes('cf-turnstile') || text.includes('aliyuncaptchaconfig') || text.includes('captcha-element');
}

function normalizeCountryCode(countryCode) {
  const code = String(countryCode || '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : null;
}

function countryNameToCode(country) {
  const normalized = String(country || '').trim();
  const map = {
    中国: 'CN',
    香港: 'HK',
    澳门: 'MO',
    美國: 'US',
    美国: 'US',
    英国: 'GB',
    日本: 'JP',
    韩国: 'KR',
    新加坡: 'SG',
    加拿大: 'CA',
    澳大利亚: 'AU',
    德国: 'DE',
    法国: 'FR',
    荷兰: 'NL',
    阿根廷: 'AR'
  };
  return map[normalized] || Object.entries(map).find(([name]) => normalized.startsWith(name))?.[1] || null;
}

function inferIpTypeFromText(...values) {
  const text = values
    .map((value) => String(value || '').toLowerCase())
    .filter(Boolean)
    .join(' ');
  if (!text) return 'unknown';

  const hostingKeywords = [
    'hosting',
    'host',
    'cloud',
    'amazon',
    'aws',
    'google',
    'azure',
    'microsoft',
    'digitalocean',
    'linode',
    'vultr',
    'ovh',
    'hetzner',
    'leaseweb',
    'm247',
    'choopa',
    'colo',
    'colocation',
    'data center',
    'datacenter',
    'server'
  ];
  if (hostingKeywords.some((keyword) => text.includes(keyword))) return 'hosting';

  const residentialKeywords = [
    'rcn',
    'comcast',
    'xfinity',
    'charter',
    'spectrum',
    'time warner',
    'cox',
    'verizon',
    'fios',
    'at&t',
    'bellsouth',
    'frontier',
    'optimum',
    'altice',
    'cablevision',
    'mediacom',
    'windstream',
    'wideopenwest',
    'ziply',
    'sonic telecom',
    'rogers',
    'bell canada',
    'telus',
    'shaw',
    'virgin media',
    'bt broadband',
    'sky broadband',
    'talktalk',
    'deutsche telekom',
    'orange',
    'telefonica',
    'movistar',
    'telstra',
    'singtel',
    'kddi',
    'ntt',
    'softbank'
  ];
  return residentialKeywords.some((keyword) => text.includes(keyword)) ? 'residential' : 'unknown';
}

function normalizePing0IpType(data) {
  const typeText = [
    data.asntype,
    data.asnType,
    data.asn_type,
    data.orgtype,
    data.orgType,
    data.org_type,
    data.iptype,
    data.ipType,
    data.ip_type,
    data.type
  ]
    .map((value) => String(value || '').trim().toLowerCase())
    .filter(Boolean)
    .join(' ');

  if (data.isidc === true || /(?:hosting|host|idc|机房|数据中心|datacenter|data center|server|cloud|云)/i.test(typeText)) {
    return 'hosting';
  }

  if (
    data.isnative === true ||
    /(?:isp|residential|home|broadband|家宽|家庭|住宅|宽带|原生)/i.test(typeText)
  ) {
    return 'residential';
  }

  return inferIpTypeFromText(data.asnname, data.org, data.isp);
}

function ping0IpTypeFromText(text) {
  const normalized = String(text || '').trim();
  if (!normalized) return 'unknown';
  if (/(?:hosting|host|idc|机房|数据中心|datacenter|data center|server|cloud|云)/i.test(normalized)) {
    return 'hosting';
  }
  if (/(?:isp|residential|home|broadband|家宽|家庭|住宅|宽带|原生)/i.test(normalized)) {
    return 'residential';
  }
  return 'unknown';
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
  const inferredType = inferIpTypeFromText(data.as, data.isp, data.org);
  return {
    source: 'ip-api.com',
    ip: data.query,
    ipType: hosting ? 'hosting' : inferredType,
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

function mapPing0Api(data) {
  const asn = data.asn ? String(data.asn).startsWith('AS') ? String(data.asn) : `AS${data.asn}` : null;
  const ipType = normalizePing0IpType(data);
  const shared = parseSharedUsers(
    firstDefined(
      data.usecount,
      data.useCount,
      data.use_count,
      data.usercount,
      data.userCount,
      data.user_count,
      data.sharedUsers,
      data.shared_users,
      data.shareCount,
      data.share_count
    )
  );
  const countryCode = normalizeCountryCode(data.countryCode || data.country_code) || countryNameToCode(data.country);
  const riskValue = firstDefined(data.iprisk, data.ipRisk, data.riskScore, data.risk_score, data.risk);
  const riskScore = typeof riskValue === 'number' ? riskValue : parseNumber(riskValue);
  const purity = firstDefined(data.purity, data.ping0Purity, data.riskLevel, data.risk_level);

  return {
    source: 'ping0.cc',
    ip: data.ip,
    ipType,
    countryCode: countryCode || 'unknown',
    regionName: data.location || [data.country, data.province, data.city].filter(Boolean).join(' ') || 'unknown',
    asn,
    isProxy: false,
    isVpn: false,
    isTor: false,
    isBlacklisted: false,
    riskScore,
    ping0Purity: purity || purityFromRiskScore(riskScore),
    sharedUsers: shared.label,
    sharedUsersMax: shared.max,
    confidence: 45
  };
}

function parsePing0Html(html, ip) {
  const plainText = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  const riskBlockMatch = html.match(/<[^>]+class=["'][^"']*\briskcurrent\b[^"']*["'][^>]*>[\s\S]*?<\/div>/i);
  const riskBlock = riskBlockMatch ? riskBlockMatch[0] : html;
  const riskValueMatch = riskBlock.match(/<span[^>]+class=["'][^"']*\bvalue\b[^"']*["'][^>]*>\s*([\d.]+)\s*%?\s*<\/span>/i)
    || plainText.match(/(?:风控|风险|纯净)[^0-9]{0,12}([\d.]+)\s*%?/);
  const riskLabelMatch = riskBlock.match(/<span[^>]+class=["'][^"']*\blab\b[^"']*["'][^>]*>\s*([^<]+?)\s*<\/span>/i)
    || html.match(/<span[^>]+class=["'][^"']*\blab\b[^"']*["'][^>]*>\s*([^<]+?)\s*<\/span>/i)
    || plainText.match(/(?:纯净度|风险等级|风控等级)[：:\s]*([^\s，,。]+)/);
  const sharedMatch = html.match(/\busecount=["']([^"']+)["']/i)
    || plainText.match(/(?:共享人数|使用人数|use\s*count|usecount)[^0-9]*(\d[\d,]*(?:\s*(?:-|~|至)\s*\d[\d,]*)?(?:\s*\+)?(?:\s*（[^）]+）|\s*\([^)]*\))?)/i);
  const flagMatch = html.match(/\/flags\/([a-z]{2})\.(?:png|svg|webp)/i);
  const asnMatch = html.match(/<title>[^<]*?-(\d{1,10})-/) || plainText.match(/\bAS\s?(\d{1,10})\b/i);
  const ipTypeBlock = html.match(/<div class="line line-iptype">([\s\S]*?)<\/div>\s*<\/div>/);
  const ipTypeLabelMatch = plainText.match(/(?:IP\s*类型|IP类型|类型)[：:\s]*([^，。|｜\n]{1,40})/i);
  const ipTypeText = ipTypeBlock
    ? ipTypeBlock[1].replace(/<[^>]+>/g, ' ')
    : ipTypeLabelMatch
      ? ipTypeLabelMatch[1]
      : '';
  const shared = parseSharedUsers(sharedMatch && sharedMatch[1]);
  const riskScore = riskValueMatch ? Number(riskValueMatch[1]) : null;
  const countryCode = flagMatch ? flagMatch[1].toUpperCase() : 'unknown';
  const ipType = ping0IpTypeFromText(ipTypeText);

  return {
    source: 'ping0.cc',
    ip,
    ipType,
    countryCode,
    regionName: 'unknown',
    asn: asnMatch ? `AS${asnMatch[1]}` : null,
    isProxy: false,
    isVpn: false,
    isTor: false,
    isBlacklisted: false,
    riskScore,
    ping0Purity: riskLabelMatch ? riskLabelMatch[1].trim() : purityFromRiskScore(riskScore),
    sharedUsers: shared.label,
    sharedUsersMax: shared.max,
    confidence: 40
  };
}

async function mapPing0Public() {
  const geo = await fetchText('https://ping0.cc/geo');
  const [ip, location, asnLine, org] = geo.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!ip) throw new Error('PING0_IP_MISSING');
  const html = await fetchText(`https://ping0.cc/ip/${encodeURIComponent(ip)}`);
  if (hasPing0Captcha(html)) throw new Error('PING0_CAPTCHA_REQUIRED');
  const mapped = parsePing0Html(html, ip);
  mapped.regionName = location || mapped.regionName;
  mapped.asn = mapped.asn || asnLine || null;
  mapped.org = org || null;
  if (mapped.countryCode === 'unknown') {
    mapped.countryCode = countryNameToCode(location) || 'unknown';
  }
  if (mapped.ipType === 'unknown') {
    mapped.ipType = inferIpTypeFromText(org, asnLine, location);
  }
  return mapped;
}

async function mapPing0() {
  const apiKey = String(process.env.PING0_API_KEY || '').trim();
  if (!apiKey) return mapPing0Public();
  const ip = (await fetchText('https://ping0.cc')).trim();
  if (!ip) throw new Error('PING0_IP_MISSING');
  const data = await fetchJson(`https://ping0.cc/apiloc/apikey(${encodeURIComponent(apiKey)})/ip(${encodeURIComponent(ip)})`);
  return mapPing0Api(data);
}

async function runFreeProviders() {
  const providers = [
    {
      source: 'ipwho.is',
      run: async () => mapIpWhoIs(await fetchJson('https://ipwho.is/'))
    },
    {
      source: 'ip-api.com',
      run: async () => mapIpApi(await fetchJson('http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,as,isp,org,proxy,hosting'))
    },
    {
      source: 'ping0.cc',
      run: async () => mapPing0()
    }
  ];

  return Promise.all(
    providers.map(async (provider) => {
      try {
        return await provider.run();
      } catch (error) {
        return providerError(provider.source, error);
      }
    })
  );
}

module.exports = {
  getFetchImplementation,
  fetchJson,
  fetchText,
  runFreeProviders,
  providerError,
  inferIpTypeFromText,
  mapIpWhoIs,
  mapIpApi,
  mapPing0Api,
  parsePing0Html
};
