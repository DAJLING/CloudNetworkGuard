const test = require('node:test');
const assert = require('node:assert/strict');
const { mapIpWhoIs, mapIpApi, mapPing0Api, parsePing0Html, providerError, inferIpTypeFromText } = require('../src/daemon/providers');

test('mapIpWhoIs carries region metadata for blocked-region scoring', () => {
  const mapped = mapIpWhoIs({
    ip: '203.0.113.8',
    country_code: 'HK',
    country: 'Hong Kong',
    connection: { type: 'isp', asn: 64500 },
    security: {}
  });

  assert.equal(mapped.countryCode, 'HK');
  assert.equal(mapped.regionName, 'Hong Kong');
  assert.equal(mapped.ipType, 'residential');
});

test('mapIpApi carries region metadata for blocked-region scoring', () => {
  const mapped = mapIpApi({
    query: '203.0.113.9',
    countryCode: 'MO',
    country: 'Macau',
    as: 'AS64501 Example',
    proxy: false,
    hosting: false
  });

  assert.equal(mapped.countryCode, 'MO');
  assert.equal(mapped.regionName, 'Macau');
});

test('mapIpApi infers residential type for known consumer ISPs', () => {
  const mapped = mapIpApi({
    query: '72.245.65.244',
    countryCode: 'US',
    country: 'United States',
    as: 'AS6079 RCN',
    proxy: false,
    hosting: false
  });

  assert.equal(mapped.ipType, 'residential');
});

test('mapPing0Api maps risk, sharing, location, and IP type metadata', () => {
  const mapped = mapPing0Api({
    ip: '198.51.100.10',
    location: '美国 加利福尼亚州 洛杉矶',
    country: '美国',
    asn: '174',
    isidc: false,
    iprisk: 12,
    usecount: '10 - 100 (一般)',
    asntype: 'isp',
    orgtype: 'isp'
  });

  assert.equal(mapped.source, 'ping0.cc');
  assert.equal(mapped.ipType, 'residential');
  assert.equal(mapped.countryCode, 'US');
  assert.equal(mapped.riskScore, 12);
  assert.equal(mapped.sharedUsers, '10 - 100 (一般)');
  assert.equal(mapped.sharedUsersMax, 100);
});

test('mapPing0Api accepts alternate Ping0 risk and sharing field names', () => {
  const mapped = mapPing0Api({
    ip: '198.51.100.11',
    country_code: 'US',
    asn: 6079,
    risk_score: '8%',
    risk_level: '低风险',
    shared_users: '1 - 10',
    asntype: 'isp'
  });

  assert.equal(mapped.countryCode, 'US');
  assert.equal(mapped.asn, 'AS6079');
  assert.equal(mapped.riskScore, 8);
  assert.equal(mapped.ping0Purity, '低风险');
  assert.equal(mapped.sharedUsers, '1 - 10');
  assert.equal(mapped.sharedUsersMax, 10);
});

test('mapPing0Api maps Ping0 native and Chinese broadband labels to residential', () => {
  const nativeMapped = mapPing0Api({
    ip: '198.51.100.12',
    country: '美国',
    asn: '6079',
    iprisk: 6,
    usecount: '1 - 10',
    isnative: true
  });
  const chineseMapped = mapPing0Api({
    ip: '198.51.100.13',
    country: '美国',
    asn: '6079',
    iprisk: 6,
    usecount: '1 - 10',
    asntype: '家宽',
    orgtype: '家庭宽带'
  });

  assert.equal(nativeMapped.ipType, 'residential');
  assert.equal(chineseMapped.ipType, 'residential');
});

test('inferIpTypeFromText prefers hosting keywords over residential hints', () => {
  assert.equal(inferIpTypeFromText('AS16509 Amazon.com, Inc.'), 'hosting');
  assert.equal(inferIpTypeFromText('AS6079 RCN'), 'residential');
  assert.equal(inferIpTypeFromText('Example Transit Backbone'), 'unknown');
});

test('parsePing0Html extracts public page risk and sharing metadata', () => {
  const mapped = parsePing0Html(
    `
      <title>38.150.35.130-174-Cogent Communications</title>
      <div class="line line-iptype"><div class="content"><span>IDC机房 IP</span></div></div>
      <div class="riskitem riskcurrent"><span class="value">31%</span><span class="lab"> 中性</span></div>
      <div class="usecountbar" usecount="100 - 1000 (风险)">100 - 1000 (风险)</div>
      <img src="https://cdn.ping0.cc/images/flags/us.png" alt="">
    `,
    '38.150.35.130'
  );

  assert.equal(mapped.ipType, 'hosting');
  assert.equal(mapped.countryCode, 'US');
  assert.equal(mapped.asn, 'AS174');
  assert.equal(mapped.riskScore, 31);
  assert.equal(mapped.ping0Purity, '中性');
  assert.equal(mapped.sharedUsers, '100 - 1000 (风险)');
  assert.equal(mapped.sharedUsersMax, 1000);
});

test('parsePing0Html extracts risk and sharing from label-oriented public markup', () => {
  const mapped = parsePing0Html(
    `
      <title>72.245.65.244-AS6079-RCN</title>
      <section>IP类型 家庭宽带</section>
      <section>风控值：12% 纯净度：低风险 共享人数：1 - 10 (低)</section>
      <img src="/images/flags/us.webp">
    `,
    '72.245.65.244'
  );

  assert.equal(mapped.ipType, 'residential');
  assert.equal(mapped.countryCode, 'US');
  assert.equal(mapped.asn, 'AS6079');
  assert.equal(mapped.riskScore, 12);
  assert.equal(mapped.ping0Purity, '低风险');
  assert.equal(mapped.sharedUsers, '1 - 10 (低)');
  assert.equal(mapped.sharedUsersMax, 10);
});

test('parsePing0Html ignores unrelated hosting text outside the IP type field', () => {
  const mapped = parsePing0Html(
    `
      <title>72.245.65.244-6079-RCN</title>
      <nav>常见说明：IDC机房、数据中心、家宽如何区分</nav>
      <section>IP类型：家宽</section>
      <section>风控值：10% 纯净度：极度纯净 共享人数：1 - 10 (极好)</section>
      <img src="/images/flags/us.webp">
    `,
    '72.245.65.244'
  );

  assert.equal(mapped.ipType, 'residential');
  assert.equal(mapped.ping0Purity, '极度纯净');
  assert.equal(mapped.sharedUsersMax, 10);
});

test('providerError keeps source and low-level network cause', () => {
  const error = new Error('fetch failed');
  error.cause = { code: 'ECONNRESET' };

  assert.deepEqual(providerError('ping0.cc', error), {
    source: 'ping0.cc',
    error: 'fetch failed: ECONNRESET'
  });
});
