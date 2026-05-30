const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('dns').promises;
const { dnsProbe } = require('../src/daemon/network-checker');

test('dnsProbe falls back to system resolver when direct DNS resolve is refused', async () => {
  const originalResolve = dns.resolve;
  const originalLookup = dns.lookup;

  dns.resolve = async () => {
    const error = new Error('query refused');
    error.code = 'ECONNREFUSED';
    throw error;
  };
  dns.lookup = async () => [
    { address: '198.18.0.49', family: 4 },
    { address: '198.18.0.50', family: 4 }
  ];

  try {
    const result = await dnsProbe('claude.ai');

    assert.equal(result.ok, true);
    assert.deepEqual(result.addresses, ['198.18.0.49', '198.18.0.50']);
    assert.equal(result.error, null);
    assert.equal(result.resolver, 'system');
    assert.equal(result.fallbackFrom, 'ECONNREFUSED');
  } finally {
    dns.resolve = originalResolve;
    dns.lookup = originalLookup;
  }
});
