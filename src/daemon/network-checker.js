const dns = require('dns').promises;
const tls = require('tls');
const { runFreeProviders } = require('./providers');
const { scoreProviderResults, combineVerdicts, normalizeEnabledChecks } = require('./scoring');
const { hashIp, maskIp } = require('./static-ip-observer');
const { checkClientEnvironment, buildEnvironmentCheckInput } = require('./environment-checker');
const { probeClaudeWeb } = require('./claude-web-probe');
const { CheckReason, NetworkVerdict } = require('../shared/constants');
const { normalizeHost } = require('./rules');
const { STATIC_IP_SKIP_VALUE } = require('./target-config');

const TARGET_HEALTH_HOSTS = ['claude.ai', 'api.openai.com', 'api.anthropic.com'];
const CLAUDE_CONTROL_HOSTS = ['claude.ai', 'api.anthropic.com'];

async function dnsProbe(host) {
  try {
    const addresses = await dns.resolve(host);
    return { ok: addresses.length > 0, addresses, error: null, resolver: 'dns' };
  } catch (error) {
    const originalError = error.code || error.message;
    try {
      const records = await dns.lookup(host, { all: true });
      const addresses = records.map((record) => record.address).filter(Boolean);
      return {
        ok: addresses.length > 0,
        addresses,
        error: null,
        resolver: 'system',
        fallbackFrom: originalError
      };
    } catch (fallbackError) {
      return {
        ok: false,
        addresses: [],
        error: fallbackError.code || fallbackError.message,
        resolver: 'system',
        fallbackFrom: originalError
      };
    }
  }
}

function pickProbeAddress(dnsResult) {
  const addresses = dnsResult && Array.isArray(dnsResult.addresses) ? dnsResult.addresses : [];
  const ipv4 = addresses.find((address) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address));
  return ipv4 || addresses[0] || null;
}

function tcpProbe(host, port = 443, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = require('net').connect({ host, port, timeout: timeoutMs });

    const finish = (ok, error = null) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve({ ok, error });
    };

    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'TIMEOUT'));
    socket.once('error', (error) => finish(false, error.code || error.message));
  });
}

function tlsProbe(host, servername = host, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port: 443,
      servername,
      timeout: timeoutMs
    });

    const finish = (ok, error = null) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve({ ok, error });
    };

    socket.once('secureConnect', () => finish(true));
    socket.once('timeout', () => finish(false, 'TIMEOUT'));
    socket.once('error', (error) => finish(false, error.code || error.message));
  });
}

function resultPassesLayers(result, layers) {
  return Object.entries(layers).every(([layer, enabled]) => {
    if (!enabled) return true;
    return Boolean(result[layer] && result[layer].ok);
  });
}

function hasAccessChecks(enabledChecks) {
  return Boolean(enabledChecks.dns || enabledChecks.tcp || enabledChecks.tls);
}

function hasTargetChecks(enabledChecks) {
  return Boolean(hasAccessChecks(enabledChecks) || enabledChecks.controlHosts);
}

function hasProviderChecks(enabledChecks) {
  return Boolean(
    enabledChecks.staticResidentialIp ||
      enabledChecks.ipType ||
      enabledChecks.region ||
      enabledChecks.proxyRisk ||
      enabledChecks.exitBinding
  );
}

function enabledChecksFromConfig(targetConfig = {}) {
  const validation = targetConfig.validation || {};
  const checks = normalizeEnabledChecks(validation.checks || {});
  checks.webProbe = validation.webProbe ? validation.webProbe.enabled !== false : Boolean(targetConfig.webProbeUrl);
  return checks;
}

async function checkExternalAccess(hosts = TARGET_HEALTH_HOSTS, controlHosts = CLAUDE_CONTROL_HOSTS, enabledChecks = {}) {
  const checks = normalizeEnabledChecks(enabledChecks);
  const accessChecksEnabled = hasAccessChecks(checks);
  const controlOnly = checks.controlHosts && !accessChecksEnabled;
  const probeLayers = {
    dns: checks.dns || controlOnly,
    tcp: checks.tcp || controlOnly,
    tls: checks.tls || controlOnly
  };
  const targetHosts = accessChecksEnabled ? hosts : controlOnly ? controlHosts : [];

  if (!targetHosts.length || !hasTargetChecks(checks)) {
    return {
      ok: true,
      claudeControlOk: true,
      results: []
    };
  }

  const results = [];
  for (const host of targetHosts) {
    const result = { host };

    if (probeLayers.dns) {
      result.dns = await dnsProbe(host);
    }

    const probeTarget = result.dns ? pickProbeAddress(result.dns) || host : host;

    if (probeLayers.tcp) {
      result.tcp =
        result.dns && !result.dns.ok
          ? { ok: false, error: 'DNS_FAILED' }
          : await tcpProbe(probeTarget);
    }

    if (probeLayers.tls) {
      result.tls =
        result.tcp && !result.tcp.ok
          ? { ok: false, error: 'TCP_FAILED' }
          : await tlsProbe(probeTarget, host);
    }

    result.ok = resultPassesLayers(result, probeLayers);
    results.push(result);
  }

  const requiredControlHosts = new Set(controlHosts.map(normalizeHost).filter(Boolean));
  const claudeResults = results.filter((result) => requiredControlHosts.has(normalizeHost(result.host)));
  const claudeControlOk =
    !checks.controlHosts ||
    requiredControlHosts.size === 0 ||
    (claudeResults.length === requiredControlHosts.size && claudeResults.every((result) => resultPassesLayers(result, probeLayers)));
  const accessOk = !accessChecksEnabled || results.some((result) => resultPassesLayers(result, {
    dns: checks.dns,
    tcp: checks.tcp,
    tls: checks.tls
  }));

  return {
    ok: accessOk && claudeControlOk,
    claudeControlOk,
    results
  };
}

function checkExitBinding({ providerScore, state }) {
  if (!providerScore.ip) {
    return {
      verdict: NetworkVerdict.PASS,
      reasons: [],
      nextBoundExitIpHash: state.boundExitIpHash || null
    };
  }

  const currentHash = hashIp(providerScore.ip, state.salt);
  if (!state.boundExitIpHash) {
    return {
      verdict: NetworkVerdict.PASS,
      reasons: [],
      nextBoundExitIpHash: currentHash
    };
  }

  if (state.boundExitIpHash !== currentHash) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reasons: [CheckReason.IP_BINDING_MISMATCH],
      nextBoundExitIpHash: state.boundExitIpHash
    };
  }

  return {
    verdict: NetworkVerdict.PASS,
    reasons: [],
    nextBoundExitIpHash: state.boundExitIpHash
  };
}

function checkItem(id, label, verdict, detail = '--', reason = null) {
  return { id, label, verdict, detail, reason };
}

function itemVerdict(verdict) {
  if (verdict === NetworkVerdict.PASS) return 'PASS';
  if (verdict === NetworkVerdict.WARN || verdict === NetworkVerdict.OBSERVING) return 'WARN';
  if (verdict === 'SKIPPED') return 'SKIPPED';
  return 'FAIL';
}

function evaluateStaticResidentialIp({ currentIp, configuredIp, now = Date.now(), salt }) {
  const normalized = String(configuredIp || '').trim();

  if (!normalized) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reason: CheckReason.STATIC_RESIDENTIAL_IP_REQUIRED,
      skipped: false,
      configuredIp: '',
      nextState: null
    };
  }

  if (normalized === STATIC_IP_SKIP_VALUE) {
    return {
      verdict: NetworkVerdict.PASS,
      reason: null,
      checkReason: CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED,
      skipped: true,
      configuredIp: normalized,
      nextState: null
    };
  }

  if (!currentIp) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reason: CheckReason.PROVIDER_UNAVAILABLE,
      skipped: false,
      configuredIp: normalized,
      nextState: null
    };
  }

  const nextState = {
    ipHash: hashIp(currentIp, salt),
    maskedIp: maskIp(currentIp),
    firstSeenAt: now,
    lastSeenAt: now
  };

  if (currentIp !== normalized) {
    return {
      verdict: NetworkVerdict.BLOCK,
      reason: CheckReason.STATIC_RESIDENTIAL_IP_MISMATCH,
      skipped: false,
      configuredIp: normalized,
      nextState
    };
  }

  return {
    verdict: NetworkVerdict.PASS,
    reason: null,
    skipped: false,
    configuredIp: normalized,
    nextState
  };
}

function summarizeAccessLayer(externalAccess, layer) {
  const results = externalAccess.results || [];
  if (!results.length) return checkItem(layer, layer.toUpperCase(), 'SKIPPED', '未配置检测目标', null);
  const failures = results.filter((result) => result[layer] && !result[layer].ok);
  if (failures.length) {
    return checkItem(layer, layer.toUpperCase(), 'FAIL', `${failures.length}/${results.length} 个目标失败`, `${layer.toUpperCase()}_CHECK_FAILED`);
  }
  return checkItem(layer, layer.toUpperCase(), 'PASS', `${results.length} 个目标通过`, null);
}

function buildCheckItems({ targetConfig, externalAccess, providerScore, staticObservation, environment, claudeWeb, binding, usage }) {
  const enabledChecks = enabledChecksFromConfig(targetConfig);
  const providerReasons = new Set(providerScore.reasons || []);
  const items = [];

  if (enabledChecks.staticResidentialIp && staticObservation.skipped) {
    items.push(checkItem('static-residential-ip', '静态住宅 IP', 'SKIPPED', '已配置 0.0.0.0，跳过静态 IP 校验', CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED));
  } else if (enabledChecks.staticResidentialIp && staticObservation.reason) {
    const detail =
      staticObservation.reason === CheckReason.STATIC_RESIDENTIAL_IP_REQUIRED
        ? '未填写静态住宅 IP'
        : staticObservation.reason === CheckReason.STATIC_RESIDENTIAL_IP_MISMATCH
          ? `当前出口 ${staticObservation.nextState ? staticObservation.nextState.maskedIp : '未知'} 与配置不一致`
          : '无法确认当前出口 IP';
    items.push(checkItem('static-residential-ip', '静态住宅 IP', 'FAIL', detail, staticObservation.reason));
  } else if (enabledChecks.staticResidentialIp) {
    items.push(checkItem('static-residential-ip', '静态住宅 IP', 'PASS', `匹配 ${targetConfig.staticResidentialIp}`, null));
  }

  if (enabledChecks.ipType) {
    const providerUnavailable = providerReasons.has(CheckReason.PROVIDER_UNAVAILABLE);
    const ipTypeDetail = providerUnavailable ? '检测源不可用' : providerScore.ipType || 'unknown';
    items.push(
      checkItem(
        'ip-type',
        'IP 类型',
        providerUnavailable || providerReasons.has(CheckReason.DATACENTER_IP)
          ? 'FAIL'
          : providerScore.ipType === 'residential'
            ? 'PASS'
            : 'WARN',
        ipTypeDetail,
        providerUnavailable ? CheckReason.PROVIDER_UNAVAILABLE : providerReasons.has(CheckReason.DATACENTER_IP) ? CheckReason.DATACENTER_IP : null
      )
    );
  }

  if (enabledChecks.region) {
    const providerUnavailable = providerReasons.has(CheckReason.PROVIDER_UNAVAILABLE);
    items.push(
      checkItem(
        'region',
        '地区',
        providerUnavailable || providerReasons.has(CheckReason.BLOCKED_REGION) ? 'FAIL' : 'PASS',
        providerUnavailable
          ? '检测源不可用'
          : providerScore.countryCode
            ? `${providerScore.countryCode} / ${providerScore.regionName || 'unknown'}`
            : 'unknown',
        providerUnavailable ? CheckReason.PROVIDER_UNAVAILABLE : providerReasons.has(CheckReason.BLOCKED_REGION) ? CheckReason.BLOCKED_REGION : null
      )
    );
  }

  if (enabledChecks.proxyRisk) {
    const proxyRiskReason = [CheckReason.PROVIDER_UNAVAILABLE, CheckReason.VPN_OR_PROXY_RISK, CheckReason.BLACKLISTED].find((reason) => providerReasons.has(reason));
    items.push(
      checkItem(
        'proxy-risk',
        '代理风险',
        proxyRiskReason ? 'FAIL' : 'PASS',
        proxyRiskReason === CheckReason.PROVIDER_UNAVAILABLE
          ? '检测源不可用'
          : proxyRiskReason
            ? '检测到代理/VPN/Tor 或黑名单风险'
            : '未发现代理风险',
        proxyRiskReason || null
      )
    );
  }

  if (enabledChecks.dns) items.push(summarizeAccessLayer(externalAccess, 'dns'));
  if (enabledChecks.tcp) items.push(summarizeAccessLayer(externalAccess, 'tcp'));
  if (enabledChecks.tls) items.push(summarizeAccessLayer(externalAccess, 'tls'));

  if (enabledChecks.controlHosts) {
    items.push(
      checkItem(
        'control-hosts',
        '强校验目标',
        externalAccess.claudeControlOk === false ? 'FAIL' : 'PASS',
        externalAccess.claudeControlOk === false ? '强校验目标未全部通过' : '强校验目标通过',
        externalAccess.claudeControlOk === false ? CheckReason.CLAUDE_CONTROL_CHECK_FAILED : null
      )
    );
  }

  if (enabledChecks.webProbe && claudeWeb && claudeWeb.skipped) {
    items.push(checkItem('claude-web', 'Claude Web', 'SKIPPED', '未配置网页探测', null));
  } else if (enabledChecks.webProbe) {
    items.push(
      checkItem(
        'claude-web',
        'Claude Web',
        itemVerdict(claudeWeb && claudeWeb.verdict),
        claudeWeb && claudeWeb.status ? `HTTP ${claudeWeb.status}` : claudeWeb && claudeWeb.error ? claudeWeb.error : '--',
        claudeWeb && claudeWeb.reasons && claudeWeb.reasons[0] ? claudeWeb.reasons[0] : null
      )
    );
  }

  if (enabledChecks.environment) {
    items.push(
      checkItem(
        'environment',
        '环境一致性',
        itemVerdict(environment && environment.verdict),
        environment ? `${environment.timeZone || 'unknown'} / ${environment.language || 'unknown'}` : '--',
        environment && environment.reasons && environment.reasons[0] ? environment.reasons[0] : null
      )
    );
  }

  if (enabledChecks.exitBinding) {
    items.push(
      checkItem(
        'exit-binding',
        '出口绑定',
        itemVerdict(binding && binding.verdict),
        binding && binding.bound ? '已绑定出口指纹' : '首次绑定出口指纹',
        binding && binding.reasons && binding.reasons[0] ? binding.reasons[0] : null
      )
    );
  }

  if (enabledChecks.usageRate) {
    items.push(
      checkItem(
        'usage-rate',
        '使用频率',
        usage && usage.verdict === NetworkVerdict.BLOCK ? 'FAIL' : 'PASS',
        usage ? `${usage.count}/${usage.maxRequests}` : '未触发频率风险',
        usage && usage.reasons && usage.reasons[0] ? usage.reasons[0] : null
      )
    );
  }

  return items;
}

class NetworkChecker {
  constructor({
    store,
    providers = runFreeProviders,
    externalAccessCheck = checkExternalAccess,
    claudeWebProbe = probeClaudeWeb,
    environmentCheck = checkClientEnvironment,
    getTargetConfig = () => ({
      healthCheckHosts: TARGET_HEALTH_HOSTS,
      controlHosts: CLAUDE_CONTROL_HOSTS,
      webProbeUrl: 'https://claude.ai/',
      staticResidentialIp: STATIC_IP_SKIP_VALUE
    }),
    now = () => Date.now()
  }) {
    this.store = store;
    this.providers = providers;
    this.externalAccessCheck = externalAccessCheck;
    this.claudeWebProbe = claudeWebProbe;
    this.environmentCheck = environmentCheck;
    this.getTargetConfig = getTargetConfig;
    this.now = now;
  }

  async checkStaticResidentialIpPreflight() {
    const targetConfig = this.getTargetConfig();
    const enabledChecks = enabledChecksFromConfig(targetConfig);
    if (!enabledChecks.staticResidentialIp) {
      return {
        ok: true,
        skipped: true,
        disabled: true,
        reason: CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED,
        checkItem: checkItem('static-residential-ip', '静态住宅 IP', 'SKIPPED', '已关闭静态 IP 校验', CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED)
      };
    }
    const staticResidentialIp = String(targetConfig.staticResidentialIp || '').trim();

    if (!staticResidentialIp) {
      return {
        ok: false,
        reason: CheckReason.STATIC_RESIDENTIAL_IP_REQUIRED,
        checkItem: checkItem('static-residential-ip', '静态住宅 IP', 'FAIL', '未填写静态住宅 IP', CheckReason.STATIC_RESIDENTIAL_IP_REQUIRED)
      };
    }

    if (staticResidentialIp === STATIC_IP_SKIP_VALUE) {
      return {
        ok: true,
        skipped: true,
        reason: CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED,
        checkItem: checkItem('static-residential-ip', '静态住宅 IP', 'SKIPPED', '已配置 0.0.0.0，跳过静态 IP 校验', CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED)
      };
    }

    const providerResults = await this.providers();
    const providerScore = scoreProviderResults(providerResults);
    const state = this.store.getState();
    const staticObservation = evaluateStaticResidentialIp({
      currentIp: providerScore.ip,
      configuredIp: staticResidentialIp,
      now: this.now(),
      salt: state.salt
    });

    return {
      ok: staticObservation.verdict === NetworkVerdict.PASS,
      reason: staticObservation.reason,
      currentMaskedIp: staticObservation.nextState ? staticObservation.nextState.maskedIp : null,
      checkItem: staticObservation.reason
        ? checkItem('static-residential-ip', '静态住宅 IP', 'FAIL', staticObservation.nextState ? `当前出口 ${staticObservation.nextState.maskedIp} 与配置不一致` : '无法确认当前出口 IP', staticObservation.reason)
        : checkItem('static-residential-ip', '静态住宅 IP', 'PASS', `匹配 ${staticResidentialIp}`, null)
    };
  }

  async checkNow() {
    const targetConfig = this.getTargetConfig();
    const enabledChecks = enabledChecksFromConfig(targetConfig);
    const shouldCheckTargets = hasTargetChecks(enabledChecks);
    const shouldCheckProviders = hasProviderChecks(enabledChecks);
    const [externalAccess, providerResults, claudeWeb] = await Promise.all([
      shouldCheckTargets
        ? this.externalAccessCheck(targetConfig.healthCheckHosts || [], targetConfig.controlHosts || [], enabledChecks)
        : Promise.resolve({ ok: true, claudeControlOk: true, results: [], skipped: true }),
      shouldCheckProviders ? this.providers() : Promise.resolve([]),
      enabledChecks.webProbe && targetConfig.webProbeUrl
        ? this.claudeWebProbe(undefined, targetConfig.webProbeUrl)
        : Promise.resolve({ verdict: NetworkVerdict.PASS, reasons: [], skipped: true })
    ]);
    const providerScore = shouldCheckProviders
      ? scoreProviderResults(providerResults)
      : {
          verdict: NetworkVerdict.PASS,
          reasons: [],
          riskScore: 0,
          confidence: 0,
          ip: null,
          ipType: 'not checked',
          asn: null,
          countryCode: 'unknown',
          regionName: 'unknown',
          sources: []
        };
    const state = this.store.getState();
    const consistency = state.environmentConsistency || {};
    const environment = enabledChecks.environment
      ? this.environmentCheck(buildEnvironmentCheckInput(state.clientEnvironment || {}, consistency))
      : { verdict: NetworkVerdict.PASS, reasons: [], disabled: true };
    const binding = enabledChecks.exitBinding
      ? checkExitBinding({ providerScore, state })
      : { verdict: NetworkVerdict.PASS, reasons: [], nextBoundExitIpHash: state.boundExitIpHash || null, disabled: true };
    const staticObservation = enabledChecks.staticResidentialIp
      ? evaluateStaticResidentialIp({
          currentIp: providerScore.ip,
          configuredIp: targetConfig.staticResidentialIp,
          now: this.now(),
          salt: state.salt
        })
      : { verdict: NetworkVerdict.PASS, reason: null, skipped: true, disabled: true, nextState: null };
    const combined = combineVerdicts({
      externalAccess,
      providerScore,
      staticObservation,
      environmentScore: environment,
      claudeWebScore: claudeWeb,
      bindingScore: binding,
      enabledChecks
    });

    const check = {
      checkedAt: new Date(this.now()).toISOString(),
      verdict: combined.verdict,
      reasons: combined.reasons,
      allowTargetTraffic: combined.allowTargetTraffic,
      externalAccess,
      claudeWeb,
      environment,
      binding: {
        verdict: binding.verdict,
        reasons: binding.reasons,
        bound: Boolean(binding.nextBoundExitIpHash)
      },
      ip: {
        maskedIp: staticObservation.nextState ? staticObservation.nextState.maskedIp : maskIp(providerScore.ip),
        ipType: providerScore.ipType,
        countryCode: providerScore.countryCode,
        regionName: providerScore.regionName,
        asn: providerScore.asn,
        riskScore: providerScore.riskScore,
        confidence: providerScore.confidence
      },
      providers: providerResults.map((result) => ({
        source: result.source,
        error: result.error || null,
        ipType: result.ipType || null,
        countryCode: result.countryCode || null,
        regionName: result.regionName || null,
        asn: result.asn || null,
        riskScore: result.riskScore || null,
        confidence: result.confidence || null
      })),
      targets: {
        healthCheckHosts: targetConfig.healthCheckHosts || [],
        controlHosts: targetConfig.controlHosts || [],
        webProbeUrl: targetConfig.webProbeUrl || null,
        staticResidentialIp: targetConfig.staticResidentialIp || '',
        enabledChecks
      },
      checkItems: buildCheckItems({
        targetConfig,
        externalAccess,
        providerScore,
        staticObservation,
        environment,
        claudeWeb,
        binding
      })
    };

    this.store.update({
      boundExitIpHash: binding.nextBoundExitIpHash,
      staticIp: enabledChecks.staticResidentialIp ? staticObservation.nextState : state.staticIp,
      lastCheck: check
    });

    this.store.appendLog({
      at: check.checkedAt,
      verdict: check.verdict,
      reasons: check.reasons,
      maskedIp: check.ip.maskedIp,
      asn: check.ip.asn
    });

    return check;
  }
}

module.exports = {
  TARGET_HEALTH_HOSTS,
  CLAUDE_CONTROL_HOSTS,
  dnsProbe,
  tcpProbe,
  tlsProbe,
  checkExternalAccess,
  checkExitBinding,
  enabledChecksFromConfig,
  evaluateStaticResidentialIp,
  buildCheckItems,
  NetworkChecker
};
