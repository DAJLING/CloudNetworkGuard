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
  validationCodex: document.querySelector('#validationCodex'),
  validationWebProbe: document.querySelector('#validationWebProbe'),
  validationWebProbeUrl: document.querySelector('#validationWebProbeUrl'),
  validationCustomHosts: document.querySelector('#validationCustomHosts'),
  validationCustomFields: document.querySelector('#validationCustomFields'),
  validationHealthHosts: document.querySelector('#validationHealthHosts'),
  validationControlHosts: document.querySelector('#validationControlHosts'),
  validationStatus: document.querySelector('#validationStatus'),
  saveValidation: document.querySelector('#saveValidation'),
  resetValidationDefaults: document.querySelector('#resetValidationDefaults'),
  resetTargetConfigDefaults: document.querySelector('#resetTargetConfigDefaults'),
  checkItems: document.querySelector('#checkItems'),
  logs: document.querySelector('#logs'),
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
  VPN_OR_PROXY_RISK: '代理 / VPN / Tor 风险',
  BLACKLISTED: '黑名单命中',
  BLOCKED_REGION: '被封锁区域',
  IP_CHANGED: 'IP 已变化',
  STATIC_WINDOW_PENDING: '静态 IP 观察不足 24 小时',
  STATIC_RESIDENTIAL_IP_REQUIRED: '未配置静态住宅 IP',
  STATIC_RESIDENTIAL_IP_MISMATCH: '静态住宅 IP 不匹配',
  STATIC_RESIDENTIAL_IP_SKIPPED: '静态住宅 IP 校验已跳过',
  DNS_LEAK_RISK: 'DNS 泄露风险',
  PROVIDER_UNAVAILABLE: '检测源不可用',
  FIREWALL_ERROR: '防火墙兜底失败'
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
    els.configError.textContent = config.error ? `配置读取失败：${config.error}` : '静态住宅 IP 配置无效，请在总览页重新保存。';
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
      <div class="target-row editable" data-rule-index="${index}">
        <input class="text-input rule-id-input" type="text" value="${escapeHtml(rule.id)}" aria-label="规则 ID" />
        <input class="text-input rule-domain-input" type="text" value="${escapeHtml(rule.domainPattern)}" aria-label="规则域名" />
        <select class="text-input rule-action-input" aria-label="规则动作">
          <option value="GUARD"${rule.action === 'GUARD' ? ' selected' : ''}>GUARD</option>
          <option value="ALLOW"${rule.action === 'ALLOW' ? ' selected' : ''}>ALLOW</option>
        </select>
        <button class="button secondary remove-rule" type="button" data-remove-rule="${index}">删除</button>
      </div>
    `)
    .join('');
}

function readTargetRulesFromEditor({ validate = true } = {}) {
  const rows = Array.from(els.targetRules ? els.targetRules.querySelectorAll('.target-row.editable') : []);
  const rules = rows.map((row, index) => {
    const idInput = row.querySelector('.rule-id-input');
    const domainInput = row.querySelector('.rule-domain-input');
    const actionInput = row.querySelector('.rule-action-input');
    return {
      id: String((idInput && idInput.value) || `target-${index + 1}`).trim() || `target-${index + 1}`,
      domainPattern: String((domainInput && domainInput.value) || '').trim(),
      action: actionInput && actionInput.value === 'ALLOW' ? 'ALLOW' : 'GUARD'
    };
  });

  if (!validate) return rules;
  if (!rules.length) throw new Error('请至少保留一条目标规则。');

  const ids = new Set();
  for (const rule of rules) {
    if (!rule.domainPattern) throw new Error('请填写每条规则的域名或 URL。');
    if (ids.has(rule.id)) throw new Error('规则 ID 不能重复。');
    ids.add(rule.id);
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

function updateValidationEditorState() {
  if (!els.validationCustomFields) return;
  const custom = Boolean(els.validationCustomHosts && els.validationCustomHosts.checked);
  els.validationCustomFields.hidden = !custom;

  const claudeEnabled = Boolean(els.validationClaude && els.validationClaude.checked);
  const webProbeEnabled = Boolean(els.validationWebProbe && els.validationWebProbe.checked);
  if (els.validationWebProbe) {
    els.validationWebProbe.disabled = !claudeEnabled;
    if (!claudeEnabled) els.validationWebProbe.checked = false;
  }
  if (els.validationWebProbeUrl) {
    els.validationWebProbeUrl.disabled = !claudeEnabled || !webProbeEnabled;
  }
}

function renderValidationEditor(validation = {}, config = {}) {
  if (!els.validationClaude) return;

  const services = validation.services || {};
  els.validationClaude.checked = services.claude !== false;
  els.validationCodex.checked = services.codex !== false;

  const webProbe = validation.webProbe || {};
  els.validationWebProbe.checked = webProbe.enabled !== false && Boolean(config.webProbeUrl || webProbe.url);
  els.validationWebProbeUrl.value = config.webProbeUrl || webProbe.url || 'https://claude.ai/';

  els.validationCustomHosts.checked = validation.useCustomHosts === true;
  els.validationHealthHosts.value = hostsToTextarea(
    validation.customHealthCheckHosts && validation.customHealthCheckHosts.length
      ? validation.customHealthCheckHosts
      : config.healthCheckHosts
  );
  els.validationControlHosts.value = hostsToTextarea(
    validation.customControlHosts && validation.customControlHosts.length
      ? validation.customControlHosts
      : config.controlHosts
  );

  if (config.validationError) {
    els.validationStatus.textContent = `校验配置无效，已回退默认：${config.validationError}`;
    els.validationStatus.className = 'field-message error';
  } else {
    els.validationStatus.textContent = validation.useCustomHosts
      ? '当前使用自定义主机列表。'
      : `当前预设：${services.claude !== false ? 'Claude' : ''}${services.claude !== false && services.codex !== false ? ' + ' : ''}${services.codex !== false ? 'Codex' : ''}`;
    els.validationStatus.className = 'field-message';
  }

  updateValidationEditorState();
}

function readValidationInputFromForm() {
  const claude = Boolean(els.validationClaude && els.validationClaude.checked);
  const codex = Boolean(els.validationCodex && els.validationCodex.checked);
  if (!claude && !codex) {
    throw new Error('请至少启用 Claude 或 Codex/OpenAI 其中一项校验。');
  }

  const useCustomHosts = Boolean(els.validationCustomHosts && els.validationCustomHosts.checked);
  const customHealthCheckHosts = parseHostLines(els.validationHealthHosts && els.validationHealthHosts.value);
  const customControlHosts = parseHostLines(els.validationControlHosts && els.validationControlHosts.value);
  if (useCustomHosts && !customHealthCheckHosts.length) {
    throw new Error('自定义模式下请填写至少一个检测目标主机。');
  }

  return {
    services: { claude, codex },
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
  if (!items.length) {
    els.checkItems.innerHTML = '<div class="empty-state">尚未生成检测清单。点击“立即检测”或开启守卫后会显示逐项结果。</div>';
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

  const failedLayers = Object.entries(result.steps || {})
    .filter(([, step]) => step && step.ok === false)
    .map(([name, step]) => `${name}: ${step.error || '失败'}`);
  els.recoveryStatus.textContent = `部分恢复失败：${failedLayers.join('；') || '请查看日志'}`;
  els.recoveryStatus.className = 'field-message error';
}

function runGuidanceAction(actionId) {
  if (actionId === 'retry-check') {
    els.checkNow.click();
  } else if (actionId === 'restore-network') {
    els.emergencyRestore.click();
  } else if (actionId === 'fix-environment') {
    els.applyEnvironmentConsistency.click();
  } else if (actionId === 'configure-static-ip' || actionId === 'skip-static-ip') {
    openStaticIpDialog();
  } else if (actionId === 'view-report' || actionId === 'review-binding') {
    setActiveView('report');
  }
}

function formatConsistencySteps(steps = {}) {
  const failed = Object.entries(steps)
    .filter(([, step]) => step && step.ok === false)
    .map(([name, step]) => `${name}: ${step.error || '失败'}`);
  return failed;
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
      els.environmentConsistencyStatus.textContent = `还原未完全成功：${failed.join('；') || '请查看日志'}`;
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
      const browserRunning = applyResult.steps?.preflight?.error === 'BROWSER_RUNNING';
      els.environmentConsistencyStatus.textContent = browserRunning
        ? '请先完全关闭 Chrome 和 Edge，再重试一键对齐。'
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
  await reportEnvironment();
  await window.networkGuard.checkNow();
  await refresh();
}

function renderGuidance(guidance = {}) {
  if (!els.fixTitle || !els.fixExplanation || !els.fixActions) return;
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

  els.summary.textContent = enabled
    ? '守卫已开启，目标流量会先经过网络状态矩阵，验证通过后放行。'
    : '守卫已关闭。你可以先配置静态住宅 IP，再执行检测或开启守卫。';
  els.guardToggle.textContent = enabled ? '关闭守卫' : '开启守卫';
  els.guardToggle.className = enabled ? 'button danger' : 'button primary';
  els.verdict.textContent = labelVerdict(displayVerdict);
  els.traffic.textContent = enabled ? (check && check.allowTargetTraffic ? '允许' : '阻断') : '放行';
  els.ip.textContent = ip.maskedIp || '未检测';
  els.risk.textContent = typeof ip.riskScore === 'number' ? `风险分 ${ip.riskScore}` : '风险分 --';
  els.checkedAt.textContent = check ? formatDate(check.checkedAt) : '尚未检测';
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
  renderSetup(status.setup || {});
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

async function saveStaticIp(value, { allowEmpty = true } = {}) {
  const error = validateStaticIpInput(value, allowEmpty);
  if (error) throw new Error(error);
  return window.networkGuard.setStaticResidentialIp(String(value || '').trim());
}

async function enableGuardWithStaticIpHandling() {
  setBusy(true);
  try {
    await reportEnvironment();
    const status = await window.networkGuard.enable('AUTO');
    render(status);
    if (status.guardState !== 'ENABLED' && status.lastCheck && status.lastCheck.allowTargetTraffic !== true) {
      setHelp('开启守卫前网络校验未通过，守卫未开启。请先看检测清单里失败项（与「环境对齐」无关时多为 DNS/TCP/Claude 连通性）。', 'error');
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
      '正在对齐时区与 WebRTC（保留中文输入法，请先关闭 Chrome/Edge）…';
    els.environmentConsistencyStatus.className = 'field-message';
    await persistEnvironmentConsistencyConfig();
    const result = await invokeWithTimeout(
      () => window.networkGuard.applyEnvironmentConsistency(),
      120000,
      '环境对齐超时：请完全关闭 Chrome 和 Edge 后重试。'
    );
    if (result.status) render(result.status);
    if (result.ok && result.restartRequired) {
      els.environmentConsistencyStatus.textContent =
        '对齐完成，应用约 2 秒后自动重启并重新检测。若仍失败，请重新登录当前系统账户后再检测。';
      els.environmentConsistencyStatus.className = 'field-message success';
      return;
    }
    if (!result.ok) {
      return;
    }
    await runPostApplyCheck();
  } catch (error) {
    els.environmentConsistencyStatus.textContent = error.message || '环境对齐失败。';
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
    els.environmentConsistencyStatus.textContent = error.message || '环境还原失败。';
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
    els.environmentConsistencyStatus.textContent = error.message || '备份失败。';
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
  setBusy(true);
  try {
    await reportEnvironment();
    await window.networkGuard.checkNow();
    await refresh();
  } finally {
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
      if (els.targetRulesStatus) {
        els.targetRulesStatus.textContent = error.message || '规则保存失败。';
        els.targetRulesStatus.className = 'field-message error';
      }
      setHelp(error.message || '规则保存失败。', 'error');
    } finally {
      setBusy(false);
    }
  });
}

for (const input of [
  els.validationClaude,
  els.validationCodex,
  els.validationWebProbe,
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
      els.validationStatus.textContent = '校验配置已保存，建议立即检测。';
      els.validationStatus.className = 'field-message success';
      setHelp('接口校验范围已更新。', 'success');
    } catch (error) {
      els.validationStatus.textContent = error.message || '保存失败。';
      els.validationStatus.className = 'field-message error';
      setHelp(error.message || '保存失败。', 'error');
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
      els.validationStatus.textContent = '已还原为默认校验范围（Claude + Codex）。';
      els.validationStatus.className = 'field-message success';
      setHelp('校验配置已还原默认。', 'success');
    } catch (error) {
      els.validationStatus.textContent = error.message || '还原失败。';
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
      els.validationStatus.textContent = error.message || '还原失败。';
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
    setHelp(error.message || '保存失败。', 'error');
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
    els.bindingHelp.textContent = error.message || '绑定当前出口失败。';
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
    els.staticIpDialogError.textContent = error.message || '保存失败。';
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
