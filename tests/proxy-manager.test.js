const test = require('node:test');
const assert = require('node:assert/strict');
const { ProxyManager, parseMacNetworkServices, parseMacProxyState } = require('../src/daemon/proxy-manager');

test('parseMacNetworkServices ignores header and disabled services', () => {
  const services = parseMacNetworkServices(
    [
      'An asterisk (*) denotes that a network service is disabled.',
      'Wi-Fi',
      '*Bluetooth PAN',
      'USB 10/100/1000 LAN',
      'Thunderbolt Bridge'
    ].join('\n')
  );

  assert.deepEqual(services, ['Wi-Fi', 'USB 10/100/1000 LAN', 'Thunderbolt Bridge']);
});

test('parseMacProxyState reads enabled host and port', () => {
  const state = parseMacProxyState(
    ['Enabled: Yes', 'Server: 127.0.0.1', 'Port: 18089', 'Authenticated Proxy Enabled: 0'].join('\n')
  );

  assert.deepEqual(state, {
    enabled: true,
    server: '127.0.0.1',
    port: 18089,
    authenticated: '0'
  });
});

test('ProxyManager enableMac applies proxy to every enabled network service', async () => {
  const calls = [];
  const manager = new ProxyManager({
    host: '127.0.0.1',
    port: 18089,
    execFileImpl: async (command, args) => {
      calls.push([command, args]);
      if (args[0] === '-listallnetworkservices') {
        return ['An asterisk (*) denotes that a network service is disabled.', 'Wi-Fi', 'USB LAN'].join('\n');
      }
      if (args[0] === '-getwebproxy' || args[0] === '-getsecurewebproxy') {
        return ['Enabled: Yes', 'Server: 127.0.0.1', 'Port: 18089', 'Authenticated Proxy Enabled: 0'].join('\n');
      }
      return '';
    }
  });

  const result = await manager.enableMac();

  assert.deepEqual(result.services, ['Wi-Fi', 'USB LAN']);
  assert.deepEqual(result.upstreamProxy, null);
  assert.deepEqual(
    calls.map(([, args]) => args).filter((args) => args[0].startsWith('-set')),
    [
      ['-setwebproxy', 'Wi-Fi', '127.0.0.1', '18089'],
      ['-setsecurewebproxy', 'Wi-Fi', '127.0.0.1', '18089'],
      ['-setwebproxy', 'USB LAN', '127.0.0.1', '18089'],
      ['-setsecurewebproxy', 'USB LAN', '127.0.0.1', '18089']
    ]
  );
});

test('ProxyManager enableMac fails when another proxy remains effective', async () => {
  const manager = new ProxyManager({
    host: '127.0.0.1',
    port: 18089,
    execFileImpl: async (_command, args) => {
      if (args[0] === '-listallnetworkservices') return 'Wi-Fi\n';
      if (args[0] === '-getwebproxy' || args[0] === '-getsecurewebproxy') {
        return ['Enabled: Yes', 'Server: 127.0.0.1', 'Port: 7897', 'Authenticated Proxy Enabled: 0'].join('\n');
      }
      return '';
    }
  });

  await assert.rejects(() => manager.enableMac(), /Wi-Fi: HTTP 127\.0\.0\.1:7897, HTTPS 127\.0\.0\.1:7897/);
});

test('ProxyManager enableMac preserves previous local proxy as upstream', async () => {
  let setCalls = 0;
  const manager = new ProxyManager({
    host: '127.0.0.1',
    port: 18089,
    execFileImpl: async (_command, args) => {
      if (args[0] === '-listallnetworkservices') return 'Wi-Fi\n';
      if (args[0] === '-setwebproxy' || args[0] === '-setsecurewebproxy') {
        setCalls += 1;
        return '';
      }
      if (args[0] === '-getwebproxy' || args[0] === '-getsecurewebproxy') {
        const port = setCalls >= 2 ? 18089 : 7897;
        return ['Enabled: Yes', 'Server: 127.0.0.1', `Port: ${port}`, 'Authenticated Proxy Enabled: 0'].join('\n');
      }
      return '';
    }
  });

  const result = await manager.enableMac();

  assert.deepEqual(result.upstreamProxy, {
    protocol: 'http:',
    host: '127.0.0.1',
    port: 7897,
    source: 'Wi-Fi',
    kind: 'https'
  });
});

test('ProxyManager disableMac clears proxy from every enabled network service', async () => {
  const calls = [];
  const manager = new ProxyManager({
    execFileImpl: async (command, args) => {
      calls.push([command, args]);
      if (args[0] === '-listallnetworkservices') {
        return ['Wi-Fi', 'USB LAN'].join('\n');
      }
      return '';
    }
  });

  const result = await manager.disableMac();

  assert.deepEqual(result.services, ['Wi-Fi', 'USB LAN']);
  assert.deepEqual(
    calls.slice(1).map(([, args]) => args),
    [
      ['-setwebproxystate', 'Wi-Fi', 'off'],
      ['-setsecurewebproxystate', 'Wi-Fi', 'off'],
      ['-setwebproxystate', 'USB LAN', 'off'],
      ['-setsecurewebproxystate', 'USB LAN', 'off']
    ]
  );
});

test('ProxyManager respects explicit mac service override', async () => {
  const previous = process.env.NETWORK_GUARD_MAC_SERVICE;
  process.env.NETWORK_GUARD_MAC_SERVICE = 'Wi-Fi';
  try {
    const calls = [];
    const manager = new ProxyManager({
      execFileImpl: async (command, args) => {
        calls.push([command, args]);
        if (args[0] === '-getwebproxy' || args[0] === '-getsecurewebproxy') {
          return ['Enabled: Yes', 'Server: 127.0.0.1', 'Port: 18089', 'Authenticated Proxy Enabled: 0'].join('\n');
        }
        return '';
      }
    });

    const result = await manager.enableMac();

    assert.deepEqual(result.services, ['Wi-Fi']);
    assert.equal(calls.some(([, args]) => args[0] === '-listallnetworkservices'), false);
  } finally {
    if (previous === undefined) {
      delete process.env.NETWORK_GUARD_MAC_SERVICE;
    } else {
      process.env.NETWORK_GUARD_MAC_SERVICE = previous;
    }
  }
});
