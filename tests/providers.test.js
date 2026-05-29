const test = require('node:test');
const assert = require('node:assert/strict');
const { mapIpWhoIs, mapIpApi } = require('../src/daemon/providers');

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
