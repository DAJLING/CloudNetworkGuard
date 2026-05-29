const els = {
  summary: document.querySelector('#summary'),
  guardToggle: document.querySelector('#guardToggle'),
  checkNow: document.querySelector('#checkNow'),
  reloadRules: document.querySelector('#reloadRules'),
  saveStaticIp: document.querySelector('#saveStaticIp'),
  statusBand: document.querySelector('#statusBand'),
  verdict: document.querySelector('#verdict'),
  traffic: document.querySelector('#traffic'),
  ip: document.querySelector('#ip'),
  risk: document.querySelector('#risk'),
  checkedAt: document.querySelector('#checkedAt'),
  region: document.querySelector('#region'),
  staticIpMetric: document.querySelector('#staticIpMetric'),
  staticIpMetricNote: document.querySelector('#staticIpMetricNote'),
  staticResidentialIp: document.querySelector('#staticResidentialIp'),
  staticIpHelp: document.querySelector('#staticIpHelp'),
  launchAtLogin: document.querySelector('#launchAtLogin'),
  proxy: document.querySelector('#proxy'),
  targetCount: document.querySelector('#targetCount'),
  targetConfigPath: document.querySelector('#targetConfigPath'),
  configStatus: document.querySelector('#configStatus'),
  configError: document.querySelector('#configError'),
  targetRules: document.querySelector('#targetRules'),
  healthHosts: document.querySelector('#healthHosts'),
  controlHosts: document.querySelector('#controlHosts'),
  firewallHosts: document.querySelector('#firewallHosts'),
  checkItems: document.querySelector('#checkItems'),
  logs: document.querySelector('#logs'),
  staticIpDialog: document.querySelector('#staticIpDialog'),
  staticIpDialogInput: document.querySelector('#staticIpDialogInput'),
  staticIpDialogError: document.querySelector('#staticIpDialogError'),
  confirmStaticIp: document.querySelector('#confirmStaticIp'),
  skipStaticIp: document.querySelector('#skipStaticIp'),
  cancelStaticIp: document.querySelector('#cancelStaticIp')
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
    const pc = new RTCPeerConnection({ iceServers: [] });
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
  const environment = {
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    languages: Array.from(navigator.languages || []),
    platform: navigator.platform,
    userAgent: navigator.userAgent,
    webRtcLocalIpCount: await collectWebRtcLocalIpCount()
  };
  await window.networkGuard.reportEnvironment(environment);
}

function setBusy(isBusy) {
  for (const button of [els.guardToggle, els.checkNow, els.reloadRules, els.saveStaticIp, els.confirmStaticIp, els.skipStaticIp]) {
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

  if (!rules.length) {
    els.targetRules.innerHTML = '<div class="empty-state">当前没有启用的拦截规则</div>';
  } else {
    els.targetRules.innerHTML = rules
      .map((rule) => {
        const actionClass = rule.action === 'GUARD' ? 'guard' : 'allow';
        return `
          <div class="target-row">
            <span class="rule-action ${actionClass}">${escapeHtml(rule.action)}</span>
            <strong>${escapeHtml(rule.domainPattern)}</strong>
            <span>${escapeHtml(rule.id)}</span>
          </div>
        `;
      })
      .join('');
  }

  renderChipList(els.healthHosts, config.healthCheckHosts || []);
  renderChipList(els.controlHosts, config.controlHosts || []);
  renderChipList(els.firewallHosts, config.firewallHosts || []);
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
  els.proxy.textContent = `${status.proxy.host}:${status.proxy.port}`;

  els.statusBand.className = `metrics-grid ${String(displayVerdict).toLowerCase()}`;
  renderStaticIp(status.targetConfig || {});
  renderTargets(status.targetConfig || {});
  renderCheckItems(check && Array.isArray(check.checkItems) ? check.checkItems : []);
  renderLogs(status.logs);
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
    const status = await window.networkGuard.enable('AUTO');
    render(status);
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

els.checkNow.addEventListener('click', async () => {
  setBusy(true);
  try {
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
