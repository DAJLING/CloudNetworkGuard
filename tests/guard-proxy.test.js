const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const net = require('net');
const { GuardProxy } = require('../src/daemon/guard-proxy');
const { GuardState } = require('../src/shared/constants');

test('GuardProxy awaits guarded target request decision', async () => {
  const proxy = new GuardProxy({
    getStatus: () => ({ guardState: GuardState.ENABLED }),
    getTargetRules: () => [{ id: 'claude', domainPattern: 'claude.ai', action: 'GUARD' }],
    onTargetRequest: async (host) => ({ block: host === 'claude.ai', reasons: ['BLOCKED_REGION'] })
  });

  const decision = await proxy.evaluateTargetRequest('claude.ai');

  assert.equal(decision.block, true);
  assert.deepEqual(decision.reasons, ['BLOCKED_REGION']);
});

test('GuardProxy bypasses request gate when guard is disabled', async () => {
  let calls = 0;
  const proxy = new GuardProxy({
    getStatus: () => ({ guardState: GuardState.DISABLED }),
    getTargetRules: () => [{ id: 'claude', domainPattern: 'claude.ai', action: 'GUARD' }],
    onTargetRequest: async () => {
      calls += 1;
      return { block: true, reasons: ['BLOCKED_REGION'] };
    }
  });

  const decision = await proxy.evaluateTargetRequest('claude.ai');

  assert.equal(decision.block, false);
  assert.equal(calls, 0);
});

test('GuardProxy forwards allowed HTTP requests through upstream proxy', async () => {
  const upstreamRequests = [];
  const upstream = http.createServer((request, response) => {
    upstreamRequests.push({ method: request.method, url: request.url, host: request.headers.host });
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('via-upstream');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));

  const proxy = new GuardProxy({
    port: 0,
    upstreamProxy: { host: '127.0.0.1', port: upstream.address().port },
    getStatus: () => ({ guardState: GuardState.ENABLED }),
    getTargetRules: () => [{ id: 'claude', domainPattern: 'claude.ai', action: 'GUARD' }],
    onTargetRequest: async () => ({ block: false, reasons: [] })
  });
  await proxy.start();

  const body = await new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: proxy.server.address().port,
        method: 'GET',
        path: 'http://claude.ai/test?q=1',
        headers: { Host: 'claude.ai' }
      },
      (response) => {
        let data = '';
        response.on('data', (chunk) => {
          data += chunk;
        });
        response.on('end', () => resolve(data));
      }
    );
    request.on('error', reject);
    request.end();
  });

  assert.equal(body, 'via-upstream');
  assert.deepEqual(upstreamRequests, [{ method: 'GET', url: 'http://claude.ai/test?q=1', host: 'claude.ai' }]);

  await proxy.stop();
  await new Promise((resolve) => upstream.close(resolve));
});

test('GuardProxy forwards allowed CONNECT tunnels through upstream proxy', async () => {
  let connectLine = null;
  const upstream = net.createServer((socket) => {
    let stage = 'headers';
    let buffered = '';
    socket.on('data', (chunk) => {
      if (stage === 'headers') {
        buffered += chunk.toString('latin1');
        if (!buffered.includes('\r\n\r\n')) return;
        connectLine = buffered.split('\r\n')[0];
        stage = 'tunnel';
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        return;
      }
      socket.write(chunk);
    });
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));

  const proxy = new GuardProxy({
    port: 0,
    upstreamProxy: { host: '127.0.0.1', port: upstream.address().port },
    getStatus: () => ({ guardState: GuardState.ENABLED }),
    getTargetRules: () => [{ id: 'claude', domainPattern: 'claude.ai', action: 'GUARD' }],
    onTargetRequest: async () => ({ block: false, reasons: [] })
  });
  await proxy.start();

  const tunnelResult = await new Promise((resolve, reject) => {
    const socket = net.connect(proxy.server.address().port, '127.0.0.1', () => {
      socket.write('CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n');
    });
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString('latin1');
      if (data.includes('\r\n\r\n') && !data.includes('ping')) {
        socket.write('ping');
      }
      if (data.includes('ping')) {
        socket.destroy();
        resolve(data);
      }
    });
    socket.on('error', reject);
  });

  assert.equal(connectLine, 'CONNECT claude.ai:443 HTTP/1.1');
  assert.match(tunnelResult, /200 Connection Established/);
  assert.match(tunnelResult, /ping/);

  await proxy.stop();
  await new Promise((resolve) => upstream.close(resolve));
});
