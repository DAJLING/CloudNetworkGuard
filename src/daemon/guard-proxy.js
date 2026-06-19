const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');
const { isGuardedTarget } = require('./rules');
const { GuardState } = require('../shared/constants');

function normalizeUpstreamProxy(proxy) {
  if (!proxy || !proxy.host || !proxy.port) return null;
  return {
    protocol: proxy.protocol || 'http:',
    host: String(proxy.host),
    port: Number(proxy.port)
  };
}

class GuardProxy {
  constructor({ port = 18089, host = '127.0.0.1', upstreamProxy = null, getStatus, getTargetRules, onTargetRequest, emitEvent }) {
    this.port = port;
    this.host = host;
    this.upstreamProxy = normalizeUpstreamProxy(upstreamProxy);
    this.getStatus = getStatus;
    this.getTargetRules = getTargetRules || (() => undefined);
    this.onTargetRequest = onTargetRequest || (async () => ({ block: false, reasons: [] }));
    this.emitEvent = emitEvent;
    this.server = http.createServer(this.handleHttp.bind(this));
    this.server.on('connect', this.handleConnect.bind(this));
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.server.off('error', reject);
        resolve(this.server.address());
      });
    });
  }

  stop() {
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }

  setUpstreamProxy(proxy) {
    this.upstreamProxy = normalizeUpstreamProxy(proxy);
  }

  shouldBlock(host) {
    const status = this.getStatus();
    return (
      status.guardState === GuardState.ENABLED &&
      isGuardedTarget(host, this.getTargetRules()) &&
      (!status.lastCheck || status.lastCheck.allowTargetTraffic !== true)
    );
  }

  async evaluateTargetRequest(host) {
    if (!isGuardedTarget(host, this.getTargetRules())) return { block: false, reasons: [] };
    const status = this.getStatus();
    if (status.guardState !== GuardState.ENABLED) return { block: false, reasons: [] };
    return this.onTargetRequest(host);
  }

  emitBlocked(host, protocol) {
    const status = this.getStatus();
    this.emitEvent({
      type: 'request-blocked',
      at: new Date().toISOString(),
      host,
      protocol,
      verdict: status.lastCheck ? status.lastCheck.verdict : 'UNKNOWN',
      reasons: status.lastCheck ? status.lastCheck.reasons : []
    });
  }

  async handleConnect(request, clientSocket, head) {
    const [host, port = '443'] = request.url.split(':');
    const decision = await this.evaluateTargetRequest(host).catch((error) => ({
      block: true,
      reasons: ['PROVIDER_UNAVAILABLE'],
      error: error.message || 'REQUEST_CHECK_FAILED'
    }));
    if (decision.block) {
      this.emitBlocked(host, 'CONNECT');
      clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nClaude Network Guard blocked this request.');
      clientSocket.destroy();
      return;
    }

    if (this.upstreamProxy) {
      this.tunnelViaUpstreamProxy(request.url, clientSocket, head);
      return;
    }

    const upstream = net.connect(Number(port), host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });

    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  }

  tunnelViaUpstreamProxy(authority, clientSocket, head) {
    const upstream = net.connect(this.upstreamProxy.port, this.upstreamProxy.host, () => {
      upstream.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });

    let buffered = Buffer.alloc(0);
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const headerEnd = buffered.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;

      const header = buffered.subarray(0, headerEnd).toString('latin1');
      const rest = buffered.subarray(headerEnd + 4);
      const statusMatch = header.match(/^HTTP\/\d(?:\.\d)?\s+(\d+)/i);
      const statusCode = statusMatch ? Number(statusMatch[1]) : 502;
      upstream.off('data', onData);

      if (statusCode < 200 || statusCode >= 300) {
        clientSocket.write(`HTTP/1.1 ${statusCode} Upstream Proxy Error\r\n\r\n`);
        clientSocket.destroy();
        upstream.destroy();
        return;
      }

      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      if (rest.length) clientSocket.write(rest);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    };

    upstream.on('data', onData);
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  }

  async handleHttp(clientRequest, clientResponse) {
    let targetUrl;
    try {
      targetUrl = new URL(clientRequest.url);
    } catch {
      clientResponse.writeHead(400);
      clientResponse.end('Bad proxy request');
      return;
    }

    const decision = await this.evaluateTargetRequest(targetUrl.hostname).catch((error) => ({
      block: true,
      reasons: ['PROVIDER_UNAVAILABLE'],
      error: error.message || 'REQUEST_CHECK_FAILED'
    }));
    if (decision.block) {
      this.emitBlocked(targetUrl.hostname, targetUrl.protocol);
      clientResponse.writeHead(403, { 'content-type': 'text/plain' });
      clientResponse.end('Claude Network Guard blocked this request.');
      return;
    }

    const useUpstreamProxy = Boolean(this.upstreamProxy);
    const transport = useUpstreamProxy ? http : targetUrl.protocol === 'https:' ? https : http;
    const upstreamRequest = transport.request(
      useUpstreamProxy
        ? {
            protocol: this.upstreamProxy.protocol,
            hostname: this.upstreamProxy.host,
            port: this.upstreamProxy.port,
            path: clientRequest.url,
            method: clientRequest.method,
            headers: clientRequest.headers
          }
        : {
            protocol: targetUrl.protocol,
            hostname: targetUrl.hostname,
            port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
            path: `${targetUrl.pathname}${targetUrl.search}`,
            method: clientRequest.method,
            headers: clientRequest.headers
          },
      (upstreamResponse) => {
        clientResponse.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
        upstreamResponse.pipe(clientResponse);
      }
    );

    upstreamRequest.on('error', () => {
      clientResponse.writeHead(502);
      clientResponse.end('Proxy upstream error');
    });

    clientRequest.pipe(upstreamRequest);
  }
}

module.exports = {
  GuardProxy
};
