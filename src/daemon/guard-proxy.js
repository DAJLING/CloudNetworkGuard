const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');
const { isGuardedTarget } = require('./rules');
const { GuardState } = require('../shared/constants');

class GuardProxy {
  constructor({ port = 18089, host = '127.0.0.1', getStatus, getTargetRules, onTargetRequest, emitEvent }) {
    this.port = port;
    this.host = host;
    this.getStatus = getStatus;
    this.getTargetRules = getTargetRules || (() => undefined);
    this.onTargetRequest = onTargetRequest || (() => ({ block: false, reasons: [] }));
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

  shouldBlock(host) {
    const status = this.getStatus();
    return (
      status.guardState === GuardState.ENABLED &&
      isGuardedTarget(host, this.getTargetRules()) &&
      (!status.lastCheck || status.lastCheck.allowTargetTraffic !== true)
    );
  }

  evaluateTargetRequest(host) {
    if (!isGuardedTarget(host, this.getTargetRules())) return { block: false, reasons: [] };
    if (this.shouldBlock(host)) {
      const status = this.getStatus();
      return {
        block: true,
        reasons: status.lastCheck ? status.lastCheck.reasons : []
      };
    }
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

  handleConnect(request, clientSocket, head) {
    const [host, port = '443'] = request.url.split(':');
    const decision = this.evaluateTargetRequest(host);
    if (decision.block) {
      this.emitBlocked(host, 'CONNECT');
      clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nClaude Network Guard blocked this request.');
      clientSocket.destroy();
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

  handleHttp(clientRequest, clientResponse) {
    let targetUrl;
    try {
      targetUrl = new URL(clientRequest.url);
    } catch {
      clientResponse.writeHead(400);
      clientResponse.end('Bad proxy request');
      return;
    }

    const decision = this.evaluateTargetRequest(targetUrl.hostname);
    if (decision.block) {
      this.emitBlocked(targetUrl.hostname, targetUrl.protocol);
      clientResponse.writeHead(403, { 'content-type': 'text/plain' });
      clientResponse.end('Claude Network Guard blocked this request.');
      return;
    }

    const transport = targetUrl.protocol === 'https:' ? https : http;
    const upstreamRequest = transport.request(
      {
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
