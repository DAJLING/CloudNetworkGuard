const els = {
  summary: document.querySelector('#summary'),
  guardToggle: document.querySelector('#guardToggle'),
  checkNow: document.querySelector('#checkNow'),
  reloadRules: document.querySelector('#reloadRules'),
  saveStaticIp: document.querySelector('#saveStaticIp'),
  emergencyRestore: document.querySelector('#emergencyRestore'),
  recoveryStatus: document.querySelector('#recoveryStatus'),
  bindingStatus: document.querySelector('#bindingStatus'),
  bindingHelp: document.querySelector('#bindingHelp'),
  resetBinding: document.querySelector('#resetBinding'),
  rebindCurrentExit: document.querySelector('#rebindCurrentExit'),
  setupWizard: document.querySelector('#setupWizard'),
  completeSetup: document.querySelector('#completeSetup'),
  reopenSetup: document.querySelector('#reopenSetup'),
  diagnosticReport: document.querySelector('#diagnosticReport'),
  copyReport: document.querySelector('#copyReport'),
  statusBand: document.querySelector('#statusBand'),
  verdict: document.querySelector('#verdict'),
  traffic: document.querySelector('#traffic'),
  ip: document.querySelector('#ip'),
  risk: document.querySelector('#risk'),
  checkedAt: document.querySelector('#checkedAt'),
  region: document.querySelector('#region'),
  staticIpMetric: document.querySelector('#staticIpMetric'),
  staticIpMetricNote: document.querySelector('#staticIpMetricNote'),
  fixTitle: document.querySelector('#fixTitle'),
  fixExplanation: document.querySelector('#fixExplanation'),
  fixActions: document.querySelector('#fixActions'),
  staticResidentialIp: document.querySelector('#staticResidentialIp'),
  staticIpHelp: document.querySelector('#staticIpHelp'),
  launchAtLogin: document.querySelector('#launchAtLogin'),
  proxy: document.querySelector('#proxy'),
  targetCount: document.querySelector('#targetCount'),
  targetConfigPath: document.querySelector('#targetConfigPath'),
  configStatus: document.querySelector('#configStatus'),
  configError: document.querySelector('#configError'),
  targetRules: document.querySelector('#targetRules'),
  addTargetRule: document.querySelector('#addTargetRule'),
  saveTargetRules: document.querySelector('#saveTargetRules'),
  targetRulesStatus: document.querySelector('#targetRulesStatus'),
  healthHosts: document.querySelector('#healthHosts'),
  controlHosts: document.querySelector('#controlHosts'),
  firewallHosts: document.querySelector('#firewallHosts'),
  validationClaude: document.querySelector('#validationClaude'),
  validationStaticResidentialIp: document.querySelector('#validationStaticResidentialIp'),
  validationIpType: document.querySelector('#validationIpType'),
  validationRegion: document.querySelector('#validationRegion'),
  validationProxyRisk: document.querySelector('#validationProxyRisk'),
  validationDns: document.querySelector('#validationDns'),
  validationTcp: document.querySelector('#validationTcp'),
  validationTls: document.querySelector('#validationTls'),
  validationControlHosts: document.querySelector('#validationControlHosts'),
  validationWebProbe: document.querySelector('#validationWebProbe'),
  validationWebProbeUrl: document.querySelector('#validationWebProbeUrl'),
  validationEnvironment: document.querySelector('#validationEnvironment'),
  validationExitBinding: document.querySelector('#validationExitBinding'),
  validationUsageRate: document.querySelector('#validationUsageRate'),
  validationCustomHosts: document.querySelector('#validationCustomHosts'),
  validationCustomFields: document.querySelector('#validationCustomFields'),
  validationHealthHosts: document.querySelector('#validationHealthHosts'),
  validationCustomControlHosts: document.querySelector('#validationCustomControlHosts'),
  validationStatus: document.querySelector('#validationStatus'),
  saveValidation: document.querySelector('#saveValidation'),
  resetValidationDefaults: document.querySelector('#resetValidationDefaults'),
  resetTargetConfigDefaults: document.querySelector('#resetTargetConfigDefaults'),
  checkItems: document.querySelector('#checkItems'),
  logs: document.querySelector('#logs'),
  monitoringEnabled: document.querySelector('#monitoringEnabled'),
  monitoringInterval: document.querySelector('#monitoringInterval'),
  saveMonitoring: document.querySelector('#saveMonitoring'),
  monitoringStatus: document.querySelector('#monitoringStatus'),
  staticIpDialog: document.querySelector('#staticIpDialog'),
  staticIpDialogInput: document.querySelector('#staticIpDialogInput'),
  staticIpDialogError: document.querySelector('#staticIpDialogError'),
  confirmStaticIp: document.querySelector('#confirmStaticIp'),
  skipStaticIp: document.querySelector('#skipStaticIp'),
  cancelStaticIp: document.querySelector('#cancelStaticIp'),
  environmentConsistencySummary: document.querySelector('#environmentConsistencySummary'),
  environmentConsistencyTarget: document.querySelector('#environmentConsistencyTarget'),
  environmentConsistencyToggle: document.querySelector('#environmentConsistencyToggle'),
  deriveFromExitIp: document.querySelector('#deriveFromExitIp'),
  keepChineseInput: document.querySelector('#keepChineseInput'),
  profileOverrideTimeZone: document.querySelector('#profileOverrideTimeZone'),
  profileOverrideLanguage: document.querySelector('#profileOverrideLanguage'),
  applyEnvironmentConsistency: document.querySelector('#applyEnvironmentConsistency'),
  restoreEnvironmentConsistency: document.querySelector('#restoreEnvironmentConsistency'),
  backupEnvironmentNow: document.querySelector('#backupEnvironmentNow'),
  environmentConsistencyStatus: document.querySelector('#environmentConsistencyStatus')
};

let currentStatus = null;
let shouldOpenStaticIpDialogAfterEnable = false;
let appBusy = false;
let networkCheckInFlight = false;

const validationCheckDefaults = {
  staticResidentialIp: true,
  ipType: true,
  region: true,
  proxyRisk: true,
  dns: true,
  tcp: true,
  tls: true,
  controlHosts: true,
  environment: true,
  exitBinding: true,
  usageRate: true
};

const validationCheckElements = {
  staticResidentialIp: () => els.validationStaticResidentialIp,
  ipType: () => els.validationIpType,
  region: () => els.validationRegion,
  proxyRisk: () => els.validationProxyRisk,
  dns: () => els.validationDns,
  tcp: () => els.validationTcp,
  tls: () => els.validationTls,
  controlHosts: () => els.validationControlHosts,
  environment: () => els.validationEnvironment,
  exitBinding: () => els.validationExitBinding,
  usageRate: () => els.validationUsageRate
};

const verdictLabels = {
  PASS: '通过',
  WARN: '警告',
  BLOCK: '阻断',
  OBSERVING: '观察中',
  UNKNOWN: '未知',
  DISABLED: '已关闭',
  FAIL: '失败',
  PENDING: '等待',
  SKIPPED: '跳过'
};

const reasonLabels = {
  CHECK_PENDING: '正在校验，暂不放行',
  DNS_CHECK_FAILED: 'DNS 校验失败',
  TCP_CHECK_FAILED: 'TCP 连接校验失败',
  TLS_CHECK_FAILED: 'TLS 握手校验失败',
  CLAUDE_CONTROL_CHECK_FAILED: '未通过 Claude 强校验',
  CLAUDE_WEB_CHECK_FAILED: 'Claude 网页探测失败',
  ENVIRONMENT_MISMATCH: '浏览器 / 系统环境不一致',
  IP_BINDING_MISMATCH: '出口 IP 与绑定不一致',
  USAGE_RATE_RISK: '请求频率风险',
  NO_EXTERNAL_ACCESS: '无法访问外网目标',
  DATACENTER_IP: '数据中心 IP',
  IP_TYPE_UNCONFIRMED: 'IP 类型未确认',
  VPN_OR_PROXY_RISK: '代理 / VPN / Tor 风险',
  IP_SHARED_USERS_RISK: 'IP 共享人数过高',
  IP_RISK_DATA_UNAVAILABLE: 'Ping0 风控数据不可用',
  BLACKLISTED: '黑名单命中',
  BLOCKED_REGION: '被封锁区域',
  IP_CHANGED: 'IP 已变化',
  STATIC_WINDOW_PENDING: '静态 IP 观察不足 24 小时',
  STATIC_RESIDENTIAL_IP_REQUIRED: '未配置静态住宅 IP',
  STATIC_RESIDENTIAL_IP_MISMATCH: '静态住宅 IP 不匹配',
  STATIC_RESIDENTIAL_IP_SKIPPED: '静态住宅 IP 校验已跳过',
  CLAUDE_ACCOUNT_RISK_ACK_REQUIRED: '需要确认 Claude 账号风险',
  DNS_LEAK_RISK: 'DNS 泄露风险',
  PROVIDER_UNAVAILABLE: '检测源不可用',
  FIREWALL_ERROR: '防火墙兜底失败'
};

const userErrorMessages = {
  BROWSER_RUNNING: '请先完全关闭 Chrome / Edge 后重试。',
  BACKUP_NOT_FOUND: '还没有可还原的环境备份，请先执行一次环境对齐或重新备份。',
  UNSUPPORTED_PLATFORM: '当前平台暂不支持此操作。',
  TIMEZONE_EMPTY: '目标时区为空，请填写目标时区或恢复自动选择。',
  BACKUP_LANGUAGE_EMPTY: '备份中的语言列表为空，无法还原语言设置。',
  COMMAND_TIMEOUT: '系统命令执行超时，请稍后重试。',
  PREFERENCES_NOT_FOUND: '未找到浏览器偏好设置文件，可能尚未启动过该浏览器。',
  NOT_INSTALLED: '未安装对应浏览器，已跳过。',
  PROXY_RESTORE_FAILED: '代理设置恢复失败，请尝试再次恢复网络。',
  FIREWALL_RESTORE_FAILED: '防火墙规则清理失败，请以管理员身份运行后重试。',
  FIREWALL_CLEAR_FAILED: '防火墙规则清理失败，请以管理员身份运行后重试。',
  FIREWALL_ERROR: '防火墙兜底失败，请以管理员身份运行后重试。',
  MONITORING_INTERVAL_INVALID: '监控间隔需在 1 到 1440 分钟之间。',
  MONITORING_FAILED: '周期监控执行失败，请稍后重试。',
  CLAUDE_ACCOUNT_RISK_ACK_REQUIRED: '未绑定静态住宅 IP，开启前需要确认 Claude 账号风险。',
  STATIC_RESIDENTIAL_IP_REQUIRED: '请填写静态住宅 IP，或选择不校验。',
  INVALID_STATIC_RESIDENTIAL_IP: '静态住宅 IP 无效，请重新填写 IPv4 地址。',
  VALIDATION_SERVICE_REQUIRED: '请启用 Claude / Anthropic 校验，或使用自定义 Claude 主机。',
  VALIDATION_CUSTOM_HOSTS_REQUIRED: '自定义模式下请填写至少一个检测目标主机。',
  VALIDATION_CONFIG_INVALID: '校验配置无效，已回退默认配置。',
  TARGET_CONFIG_LOAD_FAILED: '配置文件读取失败，请检查 JSON 格式或恢复默认配置。',
  CLAUDE_TARGET_REQUIRED: '只能添加 claude.ai 或 anthropic.com 及其子域名。',
  TARGET_RULES_REQUIRED: '请至少保留一条目标规则。',
  TARGET_RULE_IDS_DUPLICATE: '目标规则 ID 重复，请删除重复规则后保存。',
  PROVIDER_UNAVAILABLE: '检测源暂不可用，请稍后重试。',
  INTERNAL_ERROR: '内部服务异常，请稍后重试或查看日志。'
};

const stepLabels = {
  preflight: '前置检查',
  platform: '平台检查',
  backup: '环境备份',
  proxy: '代理恢复',
  firewall: '防火墙恢复',
  'windows.timezone': 'Windows 时区',
  'windows.language': 'Windows 语言',
  'mac.timezone': 'macOS 时区',
  'mac.language': 'macOS 语言',
  'chrome.language': 'Chrome 语言',
  'chrome.webrtc': 'Chrome WebRTC',
  'edge.language': 'Edge 语言',
  'edge.webrtc': 'Edge WebRTC'
};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function labelVerdict(verdict) {
  return verdictLabels[verdict] || verdict || '--';
}

function isInternalErrorCode(value) {
  return /^[A-Z0-9_]+$/.test(String(value || ''));
}

function formatUserError(value, fallback = '操作失败，请稍后重试。') {
  const message = value && value.message ? value.message : value;
  const normalized = String(message || '').trim();
  if (!normalized) return fallback;
  if (userErrorMessages[normalized]) return userErrorMessages[normalized];
  return isInternalErrorCode(normalized) ? fallback : normalized;
}

function formatStepFailures(steps = {}, fallback = '操作失败，请稍后重试。') {
  return Object.entries(steps)
    .filter(([, step]) => step && step.ok === false)
    .map(([name, step]) => `${stepLabels[name] || name}：${formatUserError(step.error, fallback)}`);
}

function formatDate(value) {
  if (!value) return '尚未检测';
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'short',
    timeStyle: 'medium'
  }).format(new Date(value));
}

function isValidIpv4(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function validateStaticIpInput(value, allowEmpty = true) {
  const normalized = String(value || '').trim();
  if (!normalized) return allowEmpty ? null : '请填写静态住宅 IP，或选择不校验。';
  if (!isValidIpv4(normalized)) return '请输入有效 IPv4，例如 203.0.113.10。';
  return null;
}

async function collectWebRtcLocalIpCount() {
  if (!window.RTCPeerConnection) return 0;

  return new Promise((resolve) => {
    const ips = new Set();
    const pc = new RTCPeerConnection({
      iceServers: [],
      iceTransportPolicy: 'relay',
      bundlePolicy: 'max-bundle'
    });
    const timeout = setTimeout(() => {
      pc.close();
      resolve(ips.size);
    }, 1200);

    pc.createDataChannel('probe');
    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        clearTimeout(timeout);
        pc.close();
        resolve(ips.size);
        return;
      }
      const candidate = event.candidate.candidate || '';
      const matches = candidate.match(/(\d{1,3}(?:\.\d{1,3}){3})/g) || [];
      for (const ip of matches) {
        if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip)) ips.add(ip);
      }
    };
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => {
        clearTimeout(timeout);
        pc.close();
        resolve(0);
      });
  });
}

async function reportEnvironment() {
  let trustConsistencyWebRtc = false;
  let trustConsistencyLanguage = false;
  let keepChineseInput = true;
  let consistencyActive = false;
  let consistency = {};
  try {
    const status = await window.networkGuard.getStatus();
    consistency = status.environmentConsistency || {};
    consistencyActive =
      consistency.enabled === true && consistency.lastApplyResult && consistency.lastApplyResult.ok === true;
    keepChineseInput = consistency.keepChineseInput !== false;
    trustConsistencyWebRtc = consistencyActive;
    trustConsistencyLanguage = keepChineseInput;
  } catch {
    trustConsistencyWebRtc = false;
    trustConsistencyLanguage = false;
  }

  let language = navigator.language;
  let languages = Array.from(navigator.languages || []);
  if (
    consistencyActive &&
    !keepChineseInput &&
    consistency.lastTargetProfile &&
    consistency.lastTargetProfile.language
  ) {
    language = consistency.lastTargetProfile.language;
    languages =
      consistency.lastTargetProfile.languages && consistency.lastTargetProfile.languages.length
        ? consistency.lastTargetProfile.languages
        : [consistency.lastTargetProfile.language];
  }

  const environment = {
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language,
    languages,
    platform: navigator.platform,
    userAgent: navigator.userAgent,
    webRtcLocalIpCount: await collectWebRtcLocalIpCount(),
    trustConsistencyWebRtc,
    trustConsistencyLanguage,
    keepChineseInput
  };
  await window.networkGuard.reportEnvironment(environment);
}

function setBusy(isBusy) {
  appBusy = isBusy;
  for (const button of [
    els.guardToggle,
    els.checkNow,
    els.reloadRules,
    els.saveStaticIp,
    els.emergencyRestore,
    els.resetBinding,
    els.rebindCurrentExit,
    els.completeSetup,
    els.reopenSetup,
    els.copyReport,
    els.confirmStaticIp,
    els.skipStaticIp,
    els.addTargetRule,
    els.saveTargetRules,
    els.saveMonitoring,
    els.applyEnvironmentConsistency,
    els.restoreEnvironmentConsistency,
    els.backupEnvironmentNow,
    els.environmentConsistencyToggle,
    els.saveValidation,
    els.resetValidationDefaults,
    els.resetTargetConfigDefaults
  ]) {
    if (button) button.disabled = isBusy;
  }
  applyPrimaryActionAvailability();
}

function isNetworkChecking(status = currentStatus) {
  return networkCheckInFlight || Boolean(status && status.checkingNetwork);
}

function setNetworkCheckInFlight(isChecking) {
  networkCheckInFlight = isChecking;
  if (currentStatus) {
    render(currentStatus);
  } else {
    applyPrimaryActionAvailability();
  }
}

function setHelp(message, tone = 'neutral') {
  els.staticIpHelp.textContent = message;
  els.staticIpHelp.className = tone === 'error' ? 'field-message error' : tone === 'success' ? 'field-message success' : 'field-message';
}

function iconSvg(verdict) {
  if (verdict === 'PASS') {
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>';
  }
  if (verdict === 'FAIL') {
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m18 6-12 12M6 6l12 12" /></svg>';
  }
  if (verdict === 'PENDING' || verdict === 'WARN') {
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 7v5l3 2" /><path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" /></svg>';
  }
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14" /></svg>';
}

function renderChipList(element, values = []) {
  if (!element) return;
  if (!values.length) {
    element.innerHTML = '<span class="empty-inline">未配置</span>';
    return;
  }

  element.innerHTML = values.map((value) => `<span class="chip">${escapeHtml(value)}</span>`).join('');
}

function renderTargets(config = {}) {
  const rules = Array.isArray(config.rules) ? config.rules : [];
  const guardedRules = rules.filter((rule) => rule.action === 'GUARD');

  els.targetCount.textContent = String(guardedRules.length);
  els.targetConfigPath.textContent = config.path || '--';
  els.configStatus.textContent = config.error || config.staticResidentialIpError ? '配置需要处理' : '已载入';
  els.configStatus.className = config.error || config.staticResidentialIpError ? 'status-text danger-text' : 'status-text';

  if (config.error || config.staticResidentialIpError) {
    els.configError.hidden = false;
    els.configError.textContent = config.error
      ? `配置读取失败：${formatUserError(config.error, '配置文件无法读取，请检查 JSON 格式或恢复默认配置。')}`
      : formatUserError(config.staticResidentialIpError, '静态住宅 IP 配置无效，请在总览页重新保存。');
  } else {
    els.configError.hidden = true;
    els.configError.textContent = '';
  }

  renderTargetRuleEditor(rules);

  renderChipList(els.healthHosts, config.healthCheckHosts || []);
  renderChipList(els.controlHosts, config.controlHosts || []);
  renderChipList(els.firewallHosts, config.firewallHosts || []);
  renderValidationEditor(config.validation || {}, config);
}

function renderTargetRuleEditor(rules = []) {
  if (!els.targetRules) return;
  if (!rules.length) {
    els.targetRules.innerHTML = '<div class="empty-state">当前没有启用的拦截规则</div>';
    return;
  }

  els.targetRules.innerHTML = rules
    .map((rule, index) => `
      <div class="target-row editable" data-rule-index="${index}" data-rule-id="${escapeHtml(rule.id)}">
        <input class="text-input rule-domain-input" type="text" value="${escapeHtml(rule.domainPattern)}" aria-label="规则域名" />
        <select class="text-input rule-action-input" aria-label="规则动作">
          <option value="GUARD"${rule.action === 'GUARD' ? ' selected' : ''}>拦截</option>
          <option value="ALLOW"${rule.action === 'ALLOW' ? ' selected' : ''}>放行</option>
        </select>
        <button class="button secondary remove-rule" type="button" data-remove-rule="${index}">删除</button>
      </div>
    `)
    .join('');
}

function readTargetRulesFromEditor({ validate = true } = {}) {
  const rows = Array.from(els.targetRules ? els.targetRules.querySelectorAll('.target-row.editable') : []);
  const rules = rows.map((row, index) => {
    const domainInput = row.querySelector('.rule-domain-input');
    const actionInput = row.querySelector('.rule-action-input');
    return {
      id: String(row.dataset.ruleId || `target-${index + 1}`).trim() || `target-${index + 1}`,
      domainPattern: String((domainInput && domainInput.value) || '').trim(),
      action: actionInput && actionInput.value === 'ALLOW' ? 'ALLOW' : 'GUARD'
    };
  });

  if (!validate) return rules;
  if (!rules.length) throw new Error('请至少保留一条目标规则。');

  for (const rule of rules) {
    if (!rule.domainPattern) throw new Error('请填写每条规则的域名或 URL。');
  }
  return rules;
}

function hostsToTextarea(hosts = []) {
  return (hosts || []).join('\n');
}

function parseHostLines(value) {
  return String(value || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function normalizeValidationChecks(checks = {}) {
  return Object.fromEntries(
    Object.keys(validationCheckDefaults).map((checkId) => [checkId, checks[checkId] !== false])
  );
}

function readValidationChecksFromForm() {
  return Object.fromEntries(
    Object.entries(validationCheckElements).map(([checkId, getElement]) => {
      const input = getElement();
      return [checkId, input ? Boolean(input.checked) : validationCheckDefaults[checkId]];
    })
  );
}

function hasTargetValidationChecks(checks = {}) {
  return Boolean(checks.dns || checks.tcp || checks.tls || checks.controlHosts);
}

function hasEnabledValidationChecks(validation = {}) {
  const checks = normalizeValidationChecks(validation.checks || {});
  const webProbe = validation.webProbe || {};
  return Boolean(webProbe.enabled !== false || Object.values(checks).some(Boolean));
}

function countEnabledValidationChecks(validation = {}) {
  const checks = normalizeValidationChecks(validation.checks || {});
  const webProbe = validation.webProbe || {};
  return Object.values(checks).filter(Boolean).length + (webProbe.enabled !== false ? 1 : 0);
}

function hasEnabledValidationFormItems() {
  const checks = readValidationChecksFromForm();
  return Boolean(Object.values(checks).some(Boolean) || (els.validationWebProbe && els.validationWebProbe.checked));
}

function applyPrimaryActionAvailability() {
  const status = currentStatus || {};
  const guardEnabled = status.guardState === 'ENABLED';
  const validation = status.targetConfig && status.targetConfig.validation ? status.targetConfig.validation : {};
  const hasEnabledChecks = hasEnabledValidationChecks(validation);
  const disabledReason = hasEnabledChecks ? '' : '请至少开启并保存一项校验';

  if (els.checkNow) {
    els.checkNow.disabled = appBusy || !hasEnabledChecks;
    els.checkNow.textContent = isNetworkChecking(status) ? '检测中...' : '立即检测';
    els.checkNow.title = disabledReason;
  }
  if (els.guardToggle) {
    els.guardToggle.disabled = appBusy || (!guardEnabled && !hasEnabledChecks);
    els.guardToggle.title = !guardEnabled ? disabledReason : '';
  }
}

function updateValidationEditorState(options = {}) {
  const preserveStatus = options && options.preserveStatus === true;
  if (!els.validationCustomFields) return;
  const custom = Boolean(els.validationCustomHosts && els.validationCustomHosts.checked);
  els.validationCustomFields.hidden = !custom;

  const webProbeEnabled = Boolean(els.validationWebProbe && els.validationWebProbe.checked);
  if (els.validationWebProbeUrl) {
    els.validationWebProbeUrl.disabled = !webProbeEnabled;
  }

  if (els.validationStatus && !hasEnabledValidationFormItems()) {
    els.validationStatus.textContent = '当前表单没有开启任何校验项，保存后立即检测和开启守卫会禁用。';
    els.validationStatus.className = 'field-message';
  } else if (els.validationStatus && !preserveStatus) {
    els.validationStatus.textContent = '校验项已修改，保存后生效。';
    els.validationStatus.className = 'field-message';
  }
}

function renderValidationEditor(validation = {}, config = {}) {
  if (!els.validationClaude) return;

  const services = validation.services || {};
  els.validationClaude.checked = services.claude !== false;

  const checks = normalizeValidationChecks(validation.checks || {});
  for (const [checkId, getElement] of Object.entries(validationCheckElements)) {
    const input = getElement();
    if (input) input.checked = checks[checkId] !== false;
  }

  const webProbe = validation.webProbe || {};
  els.validationWebProbe.checked = webProbe.enabled !== false;
  els.validationWebProbeUrl.value = config.webProbeUrl || webProbe.url || 'https://claude.ai/';

  els.validationCustomHosts.checked = validation.useCustomHosts === true;
  els.validationHealthHosts.value = hostsToTextarea(
    validation.customHealthCheckHosts && validation.customHealthCheckHosts.length
      ? validation.customHealthCheckHosts
      : config.healthCheckHosts
  );
  els.validationCustomControlHosts.value = hostsToTextarea(
    validation.customControlHosts && validation.customControlHosts.length
      ? validation.customControlHosts
      : config.controlHosts
  );

  if (config.validationError) {
    els.validationStatus.textContent = `校验配置无效，已回退默认：${formatUserError(config.validationError)}`;
    els.validationStatus.className = 'field-message error';
  } else if (!hasEnabledValidationChecks(validation)) {
    els.validationStatus.textContent = '当前没有开启的校验项，立即检测和开启守卫已禁用。';
    els.validationStatus.className = 'field-message';
  } else {
    const enabledCount = countEnabledValidationChecks(validation);
    const serviceLabel = services.claude !== false ? 'Claude / Anthropic' : '未选择目标服务';
    els.validationStatus.textContent = validation.useCustomHosts
      ? `当前使用自定义主机列表，已开启 ${enabledCount} 项校验。`
      : `当前预设：${serviceLabel}，已开启 ${enabledCount} 项校验。`;
    els.validationStatus.className = 'field-message';
  }

  updateValidationEditorState({ preserveStatus: true });
}

function readValidationInputFromForm() {
  const claude = Boolean(els.validationClaude && els.validationClaude.checked);
  const checks = readValidationChecksFromForm();
  const targetChecksEnabled = hasTargetValidationChecks(checks);
  if (targetChecksEnabled && !claude && !(els.validationCustomHosts && els.validationCustomHosts.checked)) {
    throw new Error('请启用 Claude / Anthropic 校验，或使用自定义 Claude 主机。');
  }

  const useCustomHosts = Boolean(els.validationCustomHosts && els.validationCustomHosts.checked);
  const customHealthCheckHosts = parseHostLines(els.validationHealthHosts && els.validationHealthHosts.value);
  const customControlHosts = parseHostLines(
    els.validationCustomControlHosts && els.validationCustomControlHosts.value
  );
  if (targetChecksEnabled && useCustomHosts && !customHealthCheckHosts.length) {
    throw new Error('自定义模式下请填写至少一个检测目标主机。');
  }

  return {
    services: { claude },
    checks,
    webProbe: {
      enabled: Boolean(els.validationWebProbe && els.validationWebProbe.checked),
      url: String(els.validationWebProbeUrl && els.validationWebProbeUrl.value || '').trim()
    },
    useCustomHosts,
    customHealthCheckHosts,
    customControlHosts
  };
}

function renderCheckItems(items = []) {
  if (isNetworkChecking()) {
    els.checkItems.innerHTML = `
      <div class="check-row pending check-row-live">
        <span class="status-icon status-icon-loading" aria-label="检测中"></span>
        <span class="check-copy">
          <strong>正在检测网络</strong>
          <small>正在确认 DNS、连接、出口 IP 和浏览器环境。</small>
        </span>
        <span class="check-result">检测中</span>
      </div>
    `;
    return;
  }

  if (!items.length) {
    const validation = currentStatus && currentStatus.targetConfig ? currentStatus.targetConfig.validation : {};
    els.checkItems.innerHTML = hasEnabledValidationChecks(validation)
      ? '<div class="empty-state">尚未生成检测清单。点击“立即检测”或开启守卫后会显示逐项结果。</div>'
      : '<div class="empty-state">当前没有开启的校验项。开启并保存至少一项后才能检测或开启守卫。</div>';
    return;
  }

  els.checkItems.innerHTML = items
    .map((item) => {
      const verdict = item.verdict === 'FAIL' ? 'FAIL' : item.verdict === 'PENDING' ? 'PENDING' : item.verdict === 'WARN' ? 'WARN' : item.verdict === 'SKIPPED' ? 'SKIPPED' : 'PASS';
      const reason = item.reason ? reasonLabels[item.reason] || item.reason : labelVerdict(verdict);
      return `
        <div class="check-row ${verdict.toLowerCase()}">
          <span class="status-icon" aria-label="${escapeHtml(labelVerdict(verdict))}">
            ${iconSvg(verdict)}
          </span>
          <span class="check-copy">
            <strong>${escapeHtml(item.label)}</strong>
            <small>${escapeHtml(item.detail || '--')}</small>
          </span>
          <span class="check-result">${escapeHtml(reason)}</span>
        </div>
      `;
    })
    .join('');
}

function renderLogs(logs = []) {
  if (!logs.length) {
    els.logs.innerHTML = '<div class="empty-state">暂无事件</div>';
    return;
  }

  els.logs.innerHTML = logs
    .slice(0, 20)
    .map((log) => {
      const reasons = log.reasons && log.reasons.length ? log.reasons.map((reason) => reasonLabels[reason] || reason).join(', ') : '--';
      return `
        <div class="log-row">
          <span>${escapeHtml(formatDate(log.at))}</span>
          <strong>${escapeHtml(labelVerdict(log.verdict))}</strong>
          <span>${escapeHtml(reasons)}</span>
        </div>
      `;
    })
    .join('');
}

function renderMonitoring(monitoring = {}) {
  if (!els.monitoringStatus) return;
  if (els.monitoringEnabled) els.monitoringEnabled.checked = false;
  if (els.monitoringInterval) els.monitoringInterval.value = String(monitoring.intervalMinutes || 15);
  const parts = ['定时检测已停用'];
  if (monitoring.lastRunAt) parts.push(`最后一次旧监控 ${formatDate(monitoring.lastRunAt)}`);
  if (monitoring.lastResult && monitoring.lastResult.verdict) parts.push(`旧结果 ${labelVerdict(monitoring.lastResult.verdict)}`);
  els.monitoringStatus.textContent = parts.join(' · ');
  els.monitoringStatus.className = 'field-message';
}

function readMonitoringConfig() {
  const interval = Number(els.monitoringInterval && els.monitoringInterval.value);
  if (!Number.isFinite(interval) || interval < 1 || interval > 1440) {
    throw new Error('监控间隔需在 1 到 1440 分钟之间。');
  }
  return {
    enabled: Boolean(els.monitoringEnabled && els.monitoringEnabled.checked),
    intervalMinutes: Math.round(interval)
  };
}

function renderRecovery(recovery = {}) {
  if (!els.recoveryStatus) return;
  const result = recovery.lastResult;
  if (!result) {
    els.recoveryStatus.textContent = '尚未执行恢复。';
    els.recoveryStatus.className = 'field-message';
    return;
  }

  if (result.ok) {
    els.recoveryStatus.textContent = '网络恢复完成：守卫已关闭，代理和拦截规则已清理。';
    els.recoveryStatus.className = 'field-message success';
    return;
  }

  const failedLayers = formatStepFailures(result.steps || {}, '恢复失败，请稍后重试。');
  els.recoveryStatus.textContent = `部分恢复失败：${failedLayers.join('；') || '请查看日志'}`;
  els.recoveryStatus.className = 'field-message error';
}

function runGuidanceAction(actionId) {
  if (actionId === 'retry-check') {
    els.checkNow.click();
  } else if (actionId === 'restore-network') {
    els.emergencyRestore.click();
  } else if (actionId === 'fix-environment') {
    setActiveView('settings');
    if (els.applyEnvironmentConsistency.disabled) {
      els.environmentConsistencyStatus.textContent = '当前平台暂不支持自动对齐环境。';
      els.environmentConsistencyStatus.className = 'field-message error';
      return;
    }
    els.applyEnvironmentConsistency.click();
  } else if (actionId === 'configure-static-ip' || actionId === 'skip-static-ip') {
    openStaticIpDialog();
  } else if (actionId === 'view-report' || actionId === 'review-binding') {
    setActiveView('report');
  }
}

function formatConsistencySteps(steps = {}) {
  return formatStepFailures(steps, '环境操作失败，请稍后重试。');
}

function formatRunningBrowsers(running = []) {
  const labels = { chrome: 'Chrome', edge: 'Edge' };
  const names = running.map((name) => labels[name] || name).filter(Boolean);
  return names.length ? names.join(' / ') : 'Chrome / Edge';
}

function isBrowserRunningPreflight(steps = {}) {
  return steps.preflight?.error === 'BROWSER_RUNNING';
}

function renderEnvironmentConsistency(consistency = {}) {
  if (!els.environmentConsistencySummary) return;

  const supported = consistency.supported !== false;
  const enabled = Boolean(consistency.enabled);
  const backup = consistency.backup || {};
  const profile = consistency.lastTargetProfile;

  if (!supported) {
    els.environmentConsistencySummary.textContent = '当前平台暂不支持自动对齐。';
    els.environmentConsistencyToggle.disabled = true;
    els.applyEnvironmentConsistency.disabled = true;
    return;
  }

  els.environmentConsistencyToggle.disabled = false;
  els.environmentConsistencyToggle.checked = enabled;
  els.deriveFromExitIp.checked = consistency.deriveFromExitIp !== false;
  if (els.keepChineseInput) els.keepChineseInput.checked = consistency.keepChineseInput !== false;
  els.profileOverrideTimeZone.value = consistency.profileOverride?.timeZone || '';
  els.profileOverrideLanguage.value = consistency.profileOverride?.language || '';

  if (profile) {
    els.environmentConsistencyTarget.textContent = `目标：${profile.timeZone} / ${profile.language}`;
    els.environmentConsistencySummary.textContent = enabled
      ? '已启用环境对齐，与出口姿态一致。'
      : `已计算目标环境：${profile.timeZone} / ${profile.language}`;
  } else if (consistency.deriveFromExitIp !== false) {
    els.environmentConsistencyTarget.textContent = '跟随出口 IP';
    els.environmentConsistencySummary.textContent = enabled ? '已启用环境对齐' : '尚未对齐环境';
  } else {
    els.environmentConsistencyTarget.textContent = '使用手动目标配置';
    els.environmentConsistencySummary.textContent = enabled ? '已启用手动对齐' : '尚未对齐环境';
  }

  if (backup.hasBackup && backup.createdAt) {
    els.environmentConsistencySummary.textContent += ` · 已备份 ${formatDate(backup.createdAt)}`;
  }

  const applyResult = consistency.lastApplyResult;
  const restoreResult = consistency.lastRestoreResult;
  if (!els.environmentConsistencyStatus) return;

  if (restoreResult) {
    if (restoreResult.ok) {
      els.environmentConsistencyStatus.textContent = '原始环境已还原，应用将重启以生效。';
      els.environmentConsistencyStatus.className = 'field-message success';
    } else {
      const failed = formatConsistencySteps(restoreResult.steps);
      els.environmentConsistencyStatus.textContent = isBrowserRunningPreflight(restoreResult.steps)
        ? `请先完全关闭 ${formatRunningBrowsers(restoreResult.steps.preflight.running)}，再重试还原环境。`
        : `还原未完全成功：${failed.join('；') || '请查看日志'}`;
      els.environmentConsistencyStatus.className = 'field-message error';
    }
    return;
  }

  if (applyResult) {
    if (applyResult.ok) {
      els.environmentConsistencyStatus.textContent =
        '环境对齐完成。若重启后检测仍失败，请重新登录当前系统账户，并确认 Chrome/Edge 已关闭后再试。';
      els.environmentConsistencyStatus.className = 'field-message success';
    } else {
      const failed = formatConsistencySteps(applyResult.steps);
      els.environmentConsistencyStatus.textContent = isBrowserRunningPreflight(applyResult.steps)
        ? `请先完全关闭 ${formatRunningBrowsers(applyResult.steps.preflight.running)}，再重试一键对齐。`
        : `对齐未完全成功：${failed.join('；') || '请查看日志'}`;
      els.environmentConsistencyStatus.className = 'field-message error';
    }
    return;
  }

  els.environmentConsistencyStatus.textContent = '尚未执行环境对齐。';
  els.environmentConsistencyStatus.className = 'field-message';
}

async function persistEnvironmentConsistencyConfig() {
  return window.networkGuard.setEnvironmentConsistencyConfig({
    deriveFromExitIp: els.deriveFromExitIp.checked,
    keepChineseInput: els.keepChineseInput ? els.keepChineseInput.checked : true,
    profileOverride: {
      timeZone: els.profileOverrideTimeZone.value.trim(),
      language: els.profileOverrideLanguage.value.trim()
    }
  });
}

async function runPostApplyCheck() {
  setNetworkCheckInFlight(true);
  await reportEnvironment();
  try {
    await window.networkGuard.checkNow();
    await refresh();
  } finally {
    setNetworkCheckInFlight(false);
  }
}

function renderGuidance(guidance = {}) {
  if (!els.fixTitle || !els.fixExplanation || !els.fixActions) return;
  if (isNetworkChecking()) {
    els.fixTitle.textContent = '正在检测网络';
    els.fixExplanation.textContent = '检测完成后会自动更新检测清单和修复建议。';
    els.fixActions.innerHTML = '';
    return;
  }

  els.fixTitle.textContent = guidance.title || '等待检测结果';
  els.fixExplanation.textContent = guidance.explanation || '检测完成后会显示最重要的阻断原因和下一步建议。';
  els.fixActions.innerHTML = '';

  for (const action of guidance.actions || []) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = action.tone === 'primary' ? 'button primary' : 'button secondary';
    button.textContent = action.label;
    button.addEventListener('click', () => runGuidanceAction(action.id));
    els.fixActions.appendChild(button);
  }
}

function renderBinding(binding = {}) {
  if (!els.bindingStatus || !els.bindingHelp) return;
  const maskedIp = binding.currentMaskedIp || '未检测';
  els.bindingStatus.textContent = binding.bound ? `已绑定出口，最近出口：${maskedIp}` : `尚未绑定出口，最近出口：${maskedIp}`;
  if (binding.mismatch) {
    els.bindingHelp.textContent = '当前出口与绑定指纹不一致，请确认网络后重置或重新绑定。';
    els.bindingHelp.className = 'field-message error';
  } else {
    els.bindingHelp.textContent = '只保存出口 IP 指纹，不显示完整 IP。';
    els.bindingHelp.className = 'field-message';
  }
}

function selectedSetupStrategy() {
  const selected = document.querySelector('input[name="setupStaticIpStrategy"]:checked');
  return selected ? selected.value : 'manual';
}

function renderSetup(setup = {}) {
  if (!els.setupWizard) return;
  els.setupWizard.hidden = Boolean(setup.completed);
}

async function renderDiagnosticReport() {
  if (!els.diagnosticReport) return;
  const report = await window.networkGuard.getDiagnosticReport();
  els.diagnosticReport.textContent = JSON.stringify(report, null, 2);
}

function renderStaticIp(config = {}) {
  const value = config.staticResidentialIp || '';
  if (document.activeElement !== els.staticResidentialIp) {
    els.staticResidentialIp.value = value;
  }

  if (!value) {
    els.staticIpMetric.textContent = '未配置';
    els.staticIpMetricNote.textContent = '开启前需要确认';
    if (document.activeElement !== els.staticResidentialIp) {
      setHelp('填写 0.0.0.0 表示跳过静态 IP 校验。');
    }
  } else if (value === '0.0.0.0') {
    els.staticIpMetric.textContent = '已跳过';
    els.staticIpMetricNote.textContent = '不校验静态 IP';
  } else {
    els.staticIpMetric.textContent = value;
    els.staticIpMetricNote.textContent = '开启前会比对出口';
  }
}

function render(status) {
  currentStatus = status;
  const check = status.lastCheck;
  const enabled = status.guardState === 'ENABLED';
  const verdict = check ? check.verdict : 'UNKNOWN';
  const displayVerdict = enabled ? verdict : 'DISABLED';
  const ip = check && check.ip ? check.ip : {};
  const checking = isNetworkChecking(status);

  els.summary.textContent = enabled
    ? '守卫已开启，目标流量会先经过网络状态矩阵，验证通过后放行。'
    : '守卫已关闭。你可以先配置静态住宅 IP，再执行检测或开启守卫。';
  els.guardToggle.textContent = enabled ? '关闭守卫' : '开启守卫';
  els.guardToggle.className = enabled ? 'button danger' : 'button primary';
  els.verdict.textContent = labelVerdict(displayVerdict);
  els.traffic.textContent = enabled ? (check && check.allowTargetTraffic ? '允许' : '阻断') : '放行';
  els.ip.textContent = ip.maskedIp || '未检测';
  els.risk.textContent = typeof ip.riskScore === 'number' ? `风险分 ${ip.riskScore}` : '风险分 --';
  els.checkedAt.textContent = checking ? '检测中...' : check ? formatDate(check.checkedAt) : '尚未检测';
  els.region.textContent = ip.countryCode ? `${ip.countryCode} / ${ip.regionName || 'unknown'}` : '--';
  els.launchAtLogin.checked = Boolean(status.launchAtLogin);
  const proxy = status.proxy || {};
  els.proxy.textContent =
    proxy.systemApplied === true
      ? `${proxy.host}:${proxy.port}（系统代理）`
      : proxy.mode === 'FIREWALL_ONLY'
        ? `${proxy.host}:${proxy.port}（仅防火墙，不改系统代理）`
        : `${proxy.host}:${proxy.port}`;

  els.statusBand.className = `metrics-grid ${String(displayVerdict).toLowerCase()}`;
  renderStaticIp(status.targetConfig || {});
  renderTargets(status.targetConfig || {});
  renderCheckItems(check && Array.isArray(check.checkItems) ? check.checkItems : []);
  renderLogs(status.logs);
  renderRecovery(status.recovery || {});
  renderGuidance(status.guidance || {});
  renderBinding(status.binding || {});
  renderEnvironmentConsistency(status.environmentConsistency || {});
  renderMonitoring(status.monitoring || {});
  renderSetup(status.setup || {});
  applyPrimaryActionAvailability();
}

async function refresh() {
  render(await window.networkGuard.getStatus());
}

function setActiveView(viewName) {
  for (const tab of document.querySelectorAll('[data-view-tab]')) {
    const active = tab.dataset.viewTab === viewName;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  }

  for (const panel of document.querySelectorAll('[data-view-panel]')) {
    const active = panel.dataset.viewPanel === viewName;
    panel.classList.toggle('is-active', active);
    panel.hidden = !active;
  }

  if (viewName === 'report') {
    renderDiagnosticReport().catch(() => {
      els.diagnosticReport.textContent = '无法生成检测报告。';
    });
  }
}

function openStaticIpDialog() {
  els.staticIpDialog.hidden = false;
  els.staticIpDialogInput.value = els.staticResidentialIp.value || '';
  els.staticIpDialogError.textContent = '填写真实静态住宅 IP 后继续，或明确选择不校验。';
  els.staticIpDialogInput.focus();
}

function closeStaticIpDialog() {
  els.staticIpDialog.hidden = true;
}

function hasBoundStaticResidentialIp(config = currentStatus && currentStatus.targetConfig) {
  const value = String((config && config.staticResidentialIp) || '').trim();
  return Boolean(value && value !== '0.0.0.0');
}

function confirmNoStaticIpRisk() {
  return window.confirm(
    [
      '未绑定静态住宅 IP 时继续使用 Claude 存在账号风险。',
      '',
      '守卫会在命中 Claude / Anthropic 请求时校验出口地区；如果出口地区不在 Claude 服务范围内，会阻断请求。',
      '但出口 IP 变化、代理质量或地区误判仍可能触发 Claude 账号限制。',
      '',
      '是否确认风险并开启守卫？'
    ].join('\n')
  );
}

async function saveStaticIp(value, { allowEmpty = true } = {}) {
  const error = validateStaticIpInput(value, allowEmpty);
  if (error) throw new Error(error);
  return window.networkGuard.setStaticResidentialIp(String(value || '').trim());
}

async function enableGuardWithStaticIpHandling() {
  setBusy(true);
  try {
    await reportEnvironment();
    const acceptNoStaticIpRisk = !hasBoundStaticResidentialIp() && confirmNoStaticIpRisk();
    if (!hasBoundStaticResidentialIp() && !acceptNoStaticIpRisk) {
      setHelp('已取消开启守卫。绑定静态住宅 IP 后可减少 Claude 账号风险。');
      return;
    }
    const status = await window.networkGuard.enable('AUTO', { acceptNoStaticIpRisk });
    render(status);
    if (status.actionRequired && status.actionRequired.type === 'CLAUDE_ACCOUNT_RISK_ACK_REQUIRED') {
      setHelp('开启守卫前需要确认 Claude 账号风险。', 'error');
    } else if (status.guardState === 'ENABLED') {
      setHelp('守卫已开启。命中 Claude / Anthropic 请求时会先校验出口 IP。', 'success');
    } else if (status.guardState !== 'ENABLED' && status.lastCheck && status.lastCheck.allowTargetTraffic !== true) {
      setHelp('开启守卫未完成，请查看检测清单里的失败项。', 'error');
    }
    if (status.actionRequired && status.actionRequired.type === 'STATIC_RESIDENTIAL_IP_REQUIRED') {
      shouldOpenStaticIpDialogAfterEnable = true;
      openStaticIpDialog();
    } else if (status.actionRequired && status.actionRequired.type === 'STATIC_RESIDENTIAL_IP_MISMATCH') {
      setHelp('当前出口 IP 与配置不一致，守卫未开启。请确认后重新保存。', 'error');
    }
  } finally {
    shouldOpenStaticIpDialogAfterEnable = false;
    setBusy(false);
  }
}

for (const tab of document.querySelectorAll('[data-view-tab]')) {
  tab.addEventListener('click', () => setActiveView(tab.dataset.viewTab));
}

for (const shortcut of document.querySelectorAll('[data-open-view]')) {
  shortcut.addEventListener('click', () => setActiveView(shortcut.dataset.openView));
}

els.guardToggle.addEventListener('click', async () => {
  if (currentStatus && currentStatus.guardState === 'ENABLED') {
    setBusy(true);
    try {
      render(await window.networkGuard.disable());
    } finally {
      setBusy(false);
    }
    return;
  }

  await enableGuardWithStaticIpHandling();
});

async function invokeWithTimeout(promiseFactory, timeoutMs, timeoutMessage) {
  let timer = null;
  const timeoutPromise = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });
  try {
    return await Promise.race([promiseFactory(), timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

let consistencyActionInFlight = false;

els.applyEnvironmentConsistency.addEventListener('click', async () => {
  if (consistencyActionInFlight) return;
  consistencyActionInFlight = true;
  setBusy(true);
  try {
    els.environmentConsistencyStatus.textContent =
      '正在对齐时区与 WebRTC（保留中文输入法）…';
    els.environmentConsistencyStatus.className = 'field-message';
    await persistEnvironmentConsistencyConfig();
    const result = await invokeWithTimeout(
      () => window.networkGuard.applyEnvironmentConsistency(),
      120000,
      '环境对齐超时，请稍后重试。'
    );
    if (result.status) render(result.status);
    if (result.ok && result.restartRequired) {
      els.environmentConsistencyStatus.textContent =
        '对齐完成，应用约 2 秒后自动重启并重新检测；重新打开 Chrome/Edge 后会应用浏览器策略。';
      els.environmentConsistencyStatus.className = 'field-message success';
      return;
    }
    if (!result.ok) {
      const failed = formatConsistencySteps(result.steps);
      els.environmentConsistencyStatus.textContent = isBrowserRunningPreflight(result.steps)
        ? `请先完全关闭 ${formatRunningBrowsers(result.steps.preflight.running)}，再重试一键对齐。`
        : `对齐未完全成功：${failed.join('；') || '请查看日志'}`;
      els.environmentConsistencyStatus.className = 'field-message error';
      return;
    }
    await runPostApplyCheck();
  } catch (error) {
    els.environmentConsistencyStatus.textContent = formatUserError(error, '环境对齐失败。');
    els.environmentConsistencyStatus.className = 'field-message error';
  } finally {
    consistencyActionInFlight = false;
    setBusy(false);
  }
});

els.restoreEnvironmentConsistency.addEventListener('click', async () => {
  setBusy(true);
  try {
    els.environmentConsistencyStatus.textContent = '正在还原原始环境…';
    const result = await window.networkGuard.restoreEnvironmentConsistency();
    if (result.status) render(result.status);
    if (!result.ok) return;
    if (!result.restartRequired) {
      await runPostApplyCheck();
    }
  } catch (error) {
    els.environmentConsistencyStatus.textContent = formatUserError(error, '环境还原失败。');
    els.environmentConsistencyStatus.className = 'field-message error';
  } finally {
    setBusy(false);
  }
});

els.environmentConsistencyToggle.addEventListener('change', async () => {
  if (consistencyActionInFlight) {
    els.environmentConsistencyToggle.checked = Boolean(currentStatus?.environmentConsistency?.enabled);
    return;
  }
  if (els.environmentConsistencyToggle.checked) {
    els.applyEnvironmentConsistency.click();
    return;
  }
  els.restoreEnvironmentConsistency.click();
});

els.backupEnvironmentNow.addEventListener('click', async () => {
  if (!window.confirm('将用当前系统与浏览器环境覆盖已有备份，是否继续？')) return;
  setBusy(true);
  try {
    const result = await window.networkGuard.backupEnvironmentNow();
    if (result.status) render(result.status);
    els.environmentConsistencyStatus.textContent = '已重新备份当前环境。';
    els.environmentConsistencyStatus.className = 'field-message success';
  } catch (error) {
    els.environmentConsistencyStatus.textContent = formatUserError(error, '备份失败。');
    els.environmentConsistencyStatus.className = 'field-message error';
  } finally {
    setBusy(false);
  }
});

for (const input of [els.deriveFromExitIp, els.keepChineseInput, els.profileOverrideTimeZone, els.profileOverrideLanguage]) {
  input.addEventListener('change', async () => {
    render(await persistEnvironmentConsistencyConfig());
  });
}

els.checkNow.addEventListener('click', async () => {
  if (isNetworkChecking()) return;
  setNetworkCheckInFlight(true);
  setBusy(true);
  try {
    await reportEnvironment();
    const check = await window.networkGuard.checkNow();
    await refresh();
    setHelp(
      check && check.allowTargetTraffic === true
        ? '检测完成，当前网络可放行。'
        : '检测完成，请查看检测清单和修复建议。',
      check && check.allowTargetTraffic === true ? 'success' : 'neutral'
    );
  } catch (error) {
    setHelp(formatUserError(error, '检测失败，请稍后重试。'), 'error');
  } finally {
    setNetworkCheckInFlight(false);
    setBusy(false);
  }
});

els.reloadRules.addEventListener('click', async () => {
  setBusy(true);
  try {
    render(await window.networkGuard.reloadRules());
    setHelp('配置已重新载入。', 'success');
  } finally {
    setBusy(false);
  }
});

if (els.targetRules) {
  els.targetRules.addEventListener('click', (event) => {
    const button = event.target.closest('[data-remove-rule]');
    if (!button) return;
    const rules = readTargetRulesFromEditor({ validate: false });
    rules.splice(Number(button.dataset.removeRule), 1);
    renderTargetRuleEditor(rules);
  });
}

if (els.addTargetRule) {
  els.addTargetRule.addEventListener('click', () => {
    const rules = readTargetRulesFromEditor({ validate: false });
    rules.push({
      id: `custom-${Date.now().toString(36)}`,
      domainPattern: '',
      action: 'GUARD'
    });
    renderTargetRuleEditor(rules);
    if (els.targetRulesStatus) {
      els.targetRulesStatus.textContent = '请填写新规则域名后保存。';
      els.targetRulesStatus.className = 'field-message';
    }
  });
}

if (els.saveTargetRules) {
  els.saveTargetRules.addEventListener('click', async () => {
    setBusy(true);
    try {
      const rules = readTargetRulesFromEditor();
      render(await window.networkGuard.saveTargetRules(rules));
      if (els.targetRulesStatus) {
        els.targetRulesStatus.textContent = '拦截规则已保存。';
        els.targetRulesStatus.className = 'field-message success';
      }
      setHelp('拦截规则已更新。', 'success');
    } catch (error) {
      const message = formatUserError(error, '规则保存失败。');
      if (els.targetRulesStatus) {
        els.targetRulesStatus.textContent = message;
        els.targetRulesStatus.className = 'field-message error';
      }
      setHelp(message, 'error');
    } finally {
      setBusy(false);
    }
  });
}

if (els.saveMonitoring) {
  els.saveMonitoring.addEventListener('click', async () => {
    setBusy(true);
    try {
      render(await window.networkGuard.setMonitoringConfig({ enabled: false }));
      setHelp('后台定时检测已停用；将改为请求时校验。', 'success');
    } catch (error) {
      if (els.monitoringStatus) {
        els.monitoringStatus.textContent = formatUserError(error, '监控设置保存失败。');
        els.monitoringStatus.className = 'field-message error';
      }
      setHelp(formatUserError(error, '监控设置保存失败。'), 'error');
    } finally {
      setBusy(false);
    }
  });
}

for (const input of [
  els.validationClaude,
  els.validationStaticResidentialIp,
  els.validationIpType,
  els.validationRegion,
  els.validationProxyRisk,
  els.validationDns,
  els.validationTcp,
  els.validationTls,
  els.validationControlHosts,
  els.validationWebProbe,
  els.validationEnvironment,
  els.validationExitBinding,
  els.validationUsageRate,
  els.validationCustomHosts
]) {
  if (input) input.addEventListener('change', updateValidationEditorState);
}

if (els.saveValidation) {
  els.saveValidation.addEventListener('click', async () => {
    setBusy(true);
    try {
      const validation = readValidationInputFromForm();
      render(await window.networkGuard.saveValidationConfig(validation));
      els.validationStatus.textContent = hasEnabledValidationChecks(validation)
        ? '校验配置已保存，建议立即检测。'
        : '校验配置已保存。当前没有开启的校验项，立即检测和开启守卫已禁用。';
      els.validationStatus.className = 'field-message success';
      setHelp(hasEnabledValidationChecks(validation) ? '接口校验范围已更新。' : '所有校验项已关闭。', 'success');
    } catch (error) {
      els.validationStatus.textContent = formatUserError(error, '保存失败。');
      els.validationStatus.className = 'field-message error';
      setHelp(formatUserError(error, '保存失败。'), 'error');
    } finally {
      setBusy(false);
    }
  });
}

if (els.resetValidationDefaults) {
  els.resetValidationDefaults.addEventListener('click', async () => {
    setBusy(true);
    try {
      render(await window.networkGuard.resetValidationDefaults());
      els.validationStatus.textContent = '已还原为默认 Claude / Anthropic 校验范围。';
      els.validationStatus.className = 'field-message success';
      setHelp('校验配置已还原默认。', 'success');
    } catch (error) {
      els.validationStatus.textContent = formatUserError(error, '还原失败。');
      els.validationStatus.className = 'field-message error';
    } finally {
      setBusy(false);
    }
  });
}

if (els.resetTargetConfigDefaults) {
  els.resetTargetConfigDefaults.addEventListener('click', async () => {
    if (!window.confirm('将还原拦截规则、校验范围与静态 IP 为出厂默认，是否继续？')) return;
    setBusy(true);
    try {
      render(await window.networkGuard.resetTargetConfigDefaults());
      els.validationStatus.textContent = '全部目标配置已还原默认。';
      els.validationStatus.className = 'field-message success';
      setHelp('全部配置已还原默认。', 'success');
    } catch (error) {
      els.validationStatus.textContent = formatUserError(error, '还原失败。');
      els.validationStatus.className = 'field-message error';
    } finally {
      setBusy(false);
    }
  });
}

els.saveStaticIp.addEventListener('click', async () => {
  setBusy(true);
  try {
    render(await saveStaticIp(els.staticResidentialIp.value));
    setHelp('静态住宅 IP 已保存。', 'success');
  } catch (error) {
    setHelp(formatUserError(error, '保存失败。'), 'error');
  } finally {
    setBusy(false);
  }
});

els.emergencyRestore.addEventListener('click', async () => {
  setBusy(true);
  try {
    render(await window.networkGuard.emergencyRestore());
  } finally {
    setBusy(false);
  }
});

els.resetBinding.addEventListener('click', async () => {
  setBusy(true);
  try {
    render(await window.networkGuard.resetExitBinding());
  } finally {
    setBusy(false);
  }
});

els.rebindCurrentExit.addEventListener('click', async () => {
  setBusy(true);
  try {
    render(await window.networkGuard.rebindExitToCurrent());
  } catch (error) {
    els.bindingHelp.textContent = formatUserError(error, '绑定当前出口失败。');
    els.bindingHelp.className = 'field-message error';
  } finally {
    setBusy(false);
  }
});

els.completeSetup.addEventListener('click', async () => {
  setBusy(true);
  try {
    if (selectedSetupStrategy() === 'skip') {
      render(await saveStaticIp('0.0.0.0', { allowEmpty: false }));
    }
    render(await window.networkGuard.completeSetup({ staticIpStrategy: selectedSetupStrategy() }));
  } finally {
    setBusy(false);
  }
});

els.reopenSetup.addEventListener('click', async () => {
  render(await window.networkGuard.reopenSetup());
});

els.copyReport.addEventListener('click', async () => {
  await renderDiagnosticReport();
  const text = els.diagnosticReport.textContent || '';
  if (navigator.clipboard && text) {
    await navigator.clipboard.writeText(text);
  }
});

els.staticResidentialIp.addEventListener('blur', () => {
  const error = validateStaticIpInput(els.staticResidentialIp.value);
  if (error) setHelp(error, 'error');
});

els.confirmStaticIp.addEventListener('click', async () => {
  setBusy(true);
  try {
    const value = els.staticIpDialogInput.value;
    render(await saveStaticIp(value, { allowEmpty: false }));
    closeStaticIpDialog();
    await enableGuardWithStaticIpHandling();
  } catch (error) {
    els.staticIpDialogError.textContent = formatUserError(error, '保存失败。');
  } finally {
    setBusy(false);
  }
});

els.skipStaticIp.addEventListener('click', async () => {
  setBusy(true);
  try {
    render(await saveStaticIp('0.0.0.0', { allowEmpty: false }));
    closeStaticIpDialog();
    await enableGuardWithStaticIpHandling();
  } finally {
    setBusy(false);
  }
});

els.cancelStaticIp.addEventListener('click', closeStaticIpDialog);

els.staticIpDialog.addEventListener('click', (event) => {
  if (event.target === els.staticIpDialog) closeStaticIpDialog();
});

els.launchAtLogin.addEventListener('change', async () => {
  render(await window.networkGuard.setLaunchAtLogin(els.launchAtLogin.checked));
});

window.networkGuard.onEvent((event) => {
  if (event.type === 'post-apply-check') {
    runPostApplyCheck().catch(() => {});
    return;
  }
  if (event.type === 'guard-enable-failed') {
    setHelp('开启守卫前网络校验未通过，守卫未开启。请查看检测清单中的失败项。', 'error');
  }
  if (event.status) {
    render(event.status);
    if (shouldOpenStaticIpDialogAfterEnable && event.status.actionRequired && event.status.actionRequired.type === 'STATIC_RESIDENTIAL_IP_REQUIRED') {
      openStaticIpDialog();
    }
  } else {
    refresh();
  }
});

reportEnvironment().finally(refresh);
