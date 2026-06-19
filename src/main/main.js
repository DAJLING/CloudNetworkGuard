const path = require('path');
const { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage, Notification, dialog, shell } = require('electron');
const { GuardService } = require('../daemon/guard-service');
const { GuardState } = require('../shared/constants');
const { NotificationDeduper } = require('./notification-state');

let mainWindow = null;
let tray = null;
let service = null;
const blockingStatusDeduper = new NotificationDeduper();
const blockedRequestDeduper = new NotificationDeduper();
const appIconPath = path.join(__dirname, '../../assets/app-icon.png');

// Prevent WebRTC from exposing RFC1918 local IPs during environment checks.
app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp');

function scheduleAppRelaunch() {
  app.relaunch();
  app.exit(0);
}

function statusLabel(status) {
  if (status.guardState === GuardState.DISABLED) return '守卫关闭';
  const verdict = status.lastCheck ? status.lastCheck.verdict : '未检测';
  return `守卫开启 · ${verdict}`;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1060,
    height: 760,
    minWidth: 860,
    minHeight: 640,
    title: 'Claude Network Guard',
    backgroundColor: '#f6f7f9',
    icon: appIconPath,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.setMenu(null);
  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray() {
  const icon = nativeImage.createFromPath(appIconPath);
  tray = new Tray(icon);
  tray.setToolTip('Claude Network Guard');
  updateTray();
  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    } else {
      createWindow();
    }
  });
}

function updateTray() {
  if (!tray || !service) return;
  const status = service.getStatus();
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: statusLabel(status), enabled: false },
      { type: 'separator' },
      {
        label: status.guardState === GuardState.ENABLED ? '关闭守卫' : '开启守卫',
        click: async () => {
          if (status.guardState === GuardState.ENABLED) await service.disableGuard();
          else await service.enableGuard();
          updateTray();
          broadcastStatus();
        }
      },
      {
        label: '立即检测',
        click: async () => {
          await service.checkNow();
          updateTray();
          broadcastStatus();
        }
      },
      { type: 'separator' },
      { label: '显示主窗口', click: () => (mainWindow ? mainWindow.show() : createWindow()) },
      { label: '退出', click: () => app.quit() }
    ])
  );
}

function broadcastStatus() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('guard:event', {
      type: 'status',
      status: service.getStatus()
    });
  }
}

function runAfterMainWindowLoad(callback) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.webContents.isLoading()) {
    mainWindow.webContents.once('did-finish-load', callback);
    return;
  }
  callback();
}

function attentionPulse() {
  if (process.platform === 'darwin' && app.dock && typeof app.dock.bounce === 'function') {
    app.dock.bounce('critical');
  } else if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.flashFrame(true);
  }
}

function showSystemNotification({ title, body }) {
  attentionPulse();
  if (!Notification.isSupported()) return;
  new Notification({
    title,
    body,
    silent: false,
    urgency: 'critical'
  }).show();
}

function reasonLabels() {
  return {
    CHECK_PENDING: '正在校验，暂不放行',
    DNS_CHECK_FAILED: 'DNS 校验失败',
    TCP_CHECK_FAILED: 'TCP 连接校验失败',
    TLS_CHECK_FAILED: 'TLS 握手校验失败',
    CLAUDE_CONTROL_CHECK_FAILED: '未通过 Claude 封控验证',
    CLAUDE_WEB_CHECK_FAILED: 'Claude 网页探测失败',
    ENVIRONMENT_MISMATCH: '浏览器/系统环境不一致',
    IP_BINDING_MISMATCH: '出口 IP 与绑定不一致',
    USAGE_RATE_RISK: '请求频率风险',
    STATIC_RESIDENTIAL_IP_REQUIRED: '未配置静态住宅 IP',
    STATIC_RESIDENTIAL_IP_MISMATCH: '静态住宅 IP 不匹配',
    STATIC_RESIDENTIAL_IP_SKIPPED: '静态住宅 IP 校验已跳过',
    CLAUDE_ACCOUNT_RISK_ACK_REQUIRED: '需要确认 Claude 账号风险',
    BLOCKED_REGION: '被封锁区域',
    NO_EXTERNAL_ACCESS: '无法访问外网目标',
    DATACENTER_IP: '数据中心 IP',
    IP_TYPE_UNCONFIRMED: 'IP 类型未确认',
    VPN_OR_PROXY_RISK: '代理/VPN/Tor 风险',
    IP_SHARED_USERS_RISK: 'IP 共享人数过高',
    IP_RISK_DATA_UNAVAILABLE: 'Ping0 风控数据不可用',
    BLACKLISTED: '黑名单命中',
    STATIC_WINDOW_PENDING: '静态 IP 观察不足 24 小时',
    IP_CHANGED: 'IP 已变化',
    PROVIDER_UNAVAILABLE: '检测源不可用',
    SYSTEM_PROXY_NOT_APPLIED: '系统代理未被守卫接管'
  };
}

function formatReasons(reasons = []) {
  const labels = reasonLabels();
  return reasons.length ? reasons.map((reason) => labels[reason] || reason).join(', ') : 'UNKNOWN';
}

function shouldReuseNoStaticIpRiskAcceptance(status = {}) {
  const staticResidentialIp =
    status.targetConfig && status.targetConfig.staticResidentialIp
      ? String(status.targetConfig.staticResidentialIp).trim()
      : '';
  return Boolean(status.claudeRiskAcceptedAt || staticResidentialIp === '0.0.0.0');
}

function shouldShowStartupGuardAlert(status = {}, error = null) {
  if (error) return true;
  if (!status || status.guardState !== GuardState.ENABLED) return true;
  const check = status.lastCheck;
  return !check || check.allowTargetTraffic !== true;
}

function showMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) createWindow();
  if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
  }
}

async function showStartupGuardAlert(status = {}, error = null) {
  showMainWindow();
  attentionPulse();

  const check = status.lastCheck || {};
  const guidance = status.guidance || {};
  const reasonText = error ? error.message || 'STARTUP_GUARD_FAILED' : formatReasons(check.reasons || []);
  const title =
    status.guardState === GuardState.ENABLED
      ? '开机防护已启动，但 Claude 流量暂被阻断'
      : '开机防护未能开启';
  const message =
    guidance.title && status.guardState === GuardState.ENABLED
      ? `${guidance.title}\n\n${reasonText}`
      : `Claude Network Guard 开机后自动检测未通过。\n\n${reasonText}`;

  const result = await dialog.showMessageBox(mainWindow, {
    type: 'warning',
    title,
    message,
    detail: '守卫会保持谨慎保护。请查看检测报告或修复建议后重新检测。',
    buttons: ['查看检测报告', '知道了'],
    defaultId: 0,
    cancelId: 1,
    noLink: true
  });

  if (result.response === 0 && mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('guard:event', { type: 'open-report', status: service.getStatus() });
  }
}

async function runStartupGuardCheck() {
  const initialStatus = service.getStatus();
  const shouldAutoEnable = initialStatus.launchAtLogin === true || initialStatus.guardState === GuardState.ENABLED;
  if (!shouldAutoEnable) return;

  try {
    const status = await service.enableGuard(undefined, {
      acceptNoStaticIpRisk: shouldReuseNoStaticIpRiskAcceptance(initialStatus)
    });
    updateTray();
    broadcastStatus();

    if (initialStatus.launchAtLogin === true && shouldShowStartupGuardAlert(status)) {
      await showStartupGuardAlert(status);
    }
  } catch (error) {
    const status = service.getStatus();
    updateTray();
    broadcastStatus();
    if (initialStatus.launchAtLogin === true) {
      await showStartupGuardAlert(status, error);
    }
  }
}

function notifyBlockedRequest(event) {
  const status = service.getStatus();
  if (!blockedRequestDeduper.shouldNotifyBlocked(status)) return;

  showSystemNotification({
    title: 'Claude 请求已拦截',
    body: `${event.host} 被阻断：${formatReasons(event.reasons)}`
  });
}

function notifyBlockingStatus(event) {
  const status = event.status || service.getStatus();
  if (!blockingStatusDeduper.shouldNotifyBlocked(status)) return;
  const check = status.lastCheck || {};
  const guidance = status.guidance || {};
  const reasonText = formatReasons(check.reasons || []);
  showSystemNotification({
    title: guidance.title ? `守卫已阻断：${guidance.title}` : '守卫已进入阻断保护',
    body: reasonText ? `Claude 目标流量暂不放行：${reasonText}` : 'Claude 目标流量暂不放行。'
  });
}

function wireIpc() {
  ipcMain.handle('guard:get-status', () => service.getStatus());
  ipcMain.handle('guard:enable', async (_event, mode, options) => {
    const status = await service.enableGuard(mode, options || {});
    updateTray();
    return status;
  });
  ipcMain.handle('guard:disable', async () => {
    const status = await service.disableGuard();
    updateTray();
    return status;
  });
  ipcMain.handle('guard:emergency-restore', async () => {
    const status = await service.emergencyRestore();
    updateTray();
    return status;
  });
  ipcMain.handle('guard:reset-exit-binding', () => service.resetExitBinding());
  ipcMain.handle('guard:rebind-exit-current', async () => service.rebindExitToCurrent());
  ipcMain.handle('guard:complete-setup', (_event, setup) => service.completeSetup(setup || {}));
  ipcMain.handle('guard:reopen-setup', () => service.reopenSetup());
  ipcMain.handle('guard:get-diagnostic-report', () => service.getDiagnosticReport());
  ipcMain.handle('guard:check-now', async () => {
    const check = await service.checkNow();
    updateTray();
    return check;
  });
  ipcMain.handle('guard:open-ping0-verify', async () => {
    await shell.openExternal('https://ping0.cc');
    return { ok: true };
  });
  ipcMain.handle('guard:reload-rules', async () => {
    const status = await service.reloadTargetConfig();
    updateTray();
    return status;
  });
  ipcMain.handle('guard:save-validation-config', async (_event, validation) => {
    const status = await service.saveValidationConfig(validation || {});
    updateTray();
    return status;
  });
  ipcMain.handle('guard:save-target-rules', async (_event, rules) => {
    const status = await service.saveTargetRules(rules || []);
    updateTray();
    return status;
  });
  ipcMain.handle('guard:reset-validation-defaults', async () => {
    const status = await service.resetValidationDefaults();
    updateTray();
    return status;
  });
  ipcMain.handle('guard:reset-target-config-defaults', async () => {
    const status = await service.resetTargetConfigDefaults();
    updateTray();
    return status;
  });
  ipcMain.handle('guard:set-static-residential-ip', (_event, staticResidentialIp) => {
    const status = service.setStaticResidentialIp(staticResidentialIp);
    updateTray();
    return status;
  });
  ipcMain.handle('guard:report-environment', (_event, environment) => {
    return service.updateClientEnvironment(environment);
  });
  ipcMain.handle('guard:set-launch-at-login', (_event, enabled) => {
    app.setLoginItemSettings({ openAtLogin: Boolean(enabled) });
    service.store.update({ launchAtLogin: Boolean(enabled) });
    updateTray();
    return service.getStatus();
  });
  ipcMain.handle('guard:environment-consistency-apply', async () => {
    const result = await service.applyEnvironmentConsistency();
    updateTray();
    if (result.ok && result.restartRequired) {
      setTimeout(() => scheduleAppRelaunch(), 1500);
    }
    return result;
  });
  ipcMain.handle('guard:environment-consistency-restore', async () => {
    const result = await service.restoreEnvironmentConsistency();
    updateTray();
    if (result.ok) {
      setTimeout(() => scheduleAppRelaunch(), 1500);
    }
    return result;
  });
  ipcMain.handle('guard:environment-consistency-set-config', (_event, config) => {
    const status = service.setEnvironmentConsistencyConfig(config || {});
    updateTray();
    return status;
  });
  ipcMain.handle('guard:environment-consistency-backup-now', async () => {
    const result = await service.backupEnvironmentNow();
    updateTray();
    return result;
  });
  ipcMain.handle('guard:set-monitoring-config', (_event, config) => {
    const status = service.setMonitoringConfig(config || {});
    updateTray();
    return status;
  });
}

app.whenReady().then(async () => {
  service = new GuardService();
  await service.start();

  const originalEmit = service.emit.bind(service);
  service.emit = (event) => {
    originalEmit(event);
    if (event.type === 'request-blocked') {
      notifyBlockedRequest(event);
    } else if (
      [
        'guard-enabled-blocking',
        'check-complete',
        'usage-rate-risk',
        'system-proxy-lost',
        'guard-enabled'
      ].includes(event.type)
    ) {
      notifyBlockingStatus(event);
    } else {
      const status = service.getStatus();
      blockingStatusDeduper.resetIfReleased(status);
      blockedRequestDeduper.resetIfReleased(status);
    }
    updateTray();
    broadcastStatus();
  };

  wireIpc();
  createWindow();
  createTray();

  const pendingPostApplyCheck = service.getStatus().environmentConsistency?.pendingPostApplyCheck;
  if (pendingPostApplyCheck) {
    const stored = service.store.getState().environmentConsistency || {};
    service.store.update({
      environmentConsistency: {
        ...stored,
        pendingPostApplyCheck: false
      }
    });
    runAfterMainWindowLoad(() => {
      mainWindow.webContents.send('guard:event', { type: 'post-apply-check' });
    });
  }

  runAfterMainWindowLoad(() => {
    runStartupGuardCheck().catch(() => {});
  });
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', async () => {
  if (service) {
    await service.setSystemProxyEnabled(false).catch(() => {});
  }
});
