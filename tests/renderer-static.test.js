const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');

function readProjectFile(relativePath) {
  return fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
}

test('renderer exposes emergency network restore controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="emergencyRestore"/);
  assert.match(html, /id="recoveryStatus"/);
  assert.match(renderer, /networkGuard\.emergencyRestore\(\)/);
  assert.match(preload, /emergencyRestore: \(\) => ipcRenderer\.invoke\('guard:emergency-restore'\)/);
  assert.match(main, /ipcMain\.handle\('guard:emergency-restore'/);
});

test('renderer exposes fix guidance surface', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const service = readProjectFile('src/daemon/guard-service.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="fixTitle"/);
  assert.match(html, /id="fixExplanation"/);
  assert.match(html, /id="fixActions"/);
  assert.match(renderer, /renderGuidance\(status\.guidance/);
  assert.match(renderer, /open-ping0-verify/);
  assert.match(renderer, /networkGuard\.openPing0Verify\(\)/);
  assert.match(preload, /openPing0Verify: \(\) => ipcRenderer\.invoke\('guard:open-ping0-verify'\)/);
  assert.match(main, /shell\.openExternal\('https:\/\/ping0\.cc'\)/);
  assert.match(service, /getTopReasonGuidance/);
});

test('renderer exposes in-flight network check state', () => {
  const renderer = readProjectFile('src/renderer/renderer.js');
  const styles = readProjectFile('src/renderer/styles.css');
  const service = readProjectFile('src/daemon/guard-service.js');

  assert.match(renderer, /networkCheckInFlight/);
  assert.match(renderer, /setNetworkCheckInFlight/);
  assert.match(renderer, /检测中\.\.\./);
  assert.match(renderer, /正在检测网络/);
  assert.match(styles, /status-icon-loading/);
  assert.match(service, /checkingNetwork: state\.checkingNetwork === true/);
});

test('renderer exposes exit binding management controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="bindingStatus"/);
  assert.match(html, /id="resetBinding"/);
  assert.match(html, /id="rebindCurrentExit"/);
  assert.match(renderer, /networkGuard\.resetExitBinding\(\)/);
  assert.match(renderer, /networkGuard\.rebindExitToCurrent\(\)/);
  assert.match(preload, /resetExitBinding: \(\) => ipcRenderer\.invoke\('guard:reset-exit-binding'\)/);
  assert.match(preload, /rebindExitToCurrent: \(\) => ipcRenderer\.invoke\('guard:rebind-exit-current'\)/);
  assert.match(main, /ipcMain\.handle\('guard:reset-exit-binding'/);
  assert.match(main, /ipcMain\.handle\('guard:rebind-exit-current'/);
});

test('renderer exposes first-run setup wizard shell', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="setupWizard"/);
  assert.match(html, /id="completeSetup"/);
  assert.match(html, /id="reopenSetup"/);
  assert.match(renderer, /renderSetup\(status\.setup/);
  assert.match(renderer, /networkGuard\.completeSetup/);
  assert.match(renderer, /networkGuard\.reopenSetup\(\)/);
  assert.match(preload, /completeSetup: \(setup\) => ipcRenderer\.invoke\('guard:complete-setup', setup\)/);
  assert.match(preload, /reopenSetup: \(\) => ipcRenderer\.invoke\('guard:reopen-setup'\)/);
  assert.match(main, /ipcMain\.handle\('guard:complete-setup'/);
  assert.match(main, /ipcMain\.handle\('guard:reopen-setup'/);
});

test('renderer passes no-static-IP risk acknowledgement when enabling guard', () => {
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(renderer, /confirmNoStaticIpRisk/);
  assert.match(renderer, /acceptNoStaticIpRisk/);
  assert.match(preload, /enable: \(mode, options\) => ipcRenderer\.invoke\('guard:enable', mode, options\)/);
  assert.match(main, /ipcMain\.handle\('guard:enable', async \(_event, mode, options\)/);
});

test('renderer exposes environment consistency controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="applyEnvironmentConsistency"/);
  assert.match(html, /id="restoreEnvironmentConsistency"/);
  assert.match(html, /id="environmentConsistencyToggle"/);
  assert.match(html, /id="keepChineseInput"/);
  assert.match(renderer, /networkGuard\.applyEnvironmentConsistency\(\)/);
  assert.match(renderer, /fix-environment/);
  assert.match(preload, /applyEnvironmentConsistency: \(\) => ipcRenderer\.invoke\('guard:environment-consistency-apply'\)/);
  assert.match(main, /ipcMain\.handle\('guard:environment-consistency-apply'/);
  assert.doesNotMatch(main, /appendSwitch\('lang'/);
  assert.doesNotMatch(renderer, /注销 Windows/);
  assert.doesNotMatch(renderer, /仅 Windows/);
});

test('renderer gives actionable restore guidance when browsers are running', () => {
  const renderer = readProjectFile('src/renderer/renderer.js');

  assert.match(renderer, /isBrowserRunningPreflight\(restoreResult\.steps\)/);
  assert.match(renderer, /再重试还原环境/);
  assert.match(renderer, /formatRunningBrowsers/);
});

test('renderer translates internal error codes before showing them', () => {
  const renderer = readProjectFile('src/renderer/renderer.js');

  assert.match(renderer, /const userErrorMessages =/);
  assert.match(renderer, /BACKUP_NOT_FOUND: '还没有可还原的环境备份/);
  assert.match(renderer, /TARGET_RULES_REQUIRED: '请至少保留一条目标规则。'/);
  assert.match(renderer, /PROXY_RESTORE_FAILED: '代理设置恢复失败/);
  assert.match(renderer, /MONITORING_INTERVAL_INVALID: '监控间隔需在 1 到 1440 分钟之间。'/);
  assert.match(renderer, /formatStepFailures\(result\.steps/);
  assert.doesNotMatch(renderer, /\.textContent = error\.message/);
  assert.doesNotMatch(renderer, /setHelp\(error\.message/);
  assert.doesNotMatch(renderer, /配置读取失败：\$\{config\.error\}/);
});

test('renderer exposes configurable validation target controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="validationClaude"/);
  assert.doesNotMatch(html, /validationCodex/);
  assert.match(html, /id="validationStaticResidentialIp"/);
  assert.match(html, /id="validationDns"/);
  assert.match(html, /id="validationUsageRate"/);
  assert.match(html, /id="saveValidation"/);
  assert.match(html, /id="addTargetRule"/);
  assert.match(html, /id="saveTargetRules"/);
  assert.match(html, /id="targetRulesStatus"/);
  assert.match(html, /id="resetValidationDefaults"/);
  assert.match(html, /id="resetTargetConfigDefaults"/);
  assert.match(renderer, /renderTargetRuleEditor/);
  assert.match(renderer, /readTargetRulesFromEditor/);
  assert.match(renderer, /readValidationChecksFromForm/);
  assert.match(renderer, /saveValidationConfig/);
  assert.match(renderer, /networkGuard\.saveTargetRules/);
  assert.match(preload, /saveValidationConfig: \(validation\) => ipcRenderer\.invoke\('guard:save-validation-config', validation\)/);
  assert.match(preload, /saveTargetRules: \(rules\) => ipcRenderer\.invoke\('guard:save-target-rules', rules\)/);
  assert.match(main, /ipcMain\.handle\('guard:save-target-rules'/);
  assert.match(main, /ipcMain\.handle\('guard:reset-validation-defaults'/);
});

test('renderer exposes diagnostic report controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');
  const service = readProjectFile('src/daemon/guard-service.js');

  assert.match(html, /data-view-tab="report"/);
  assert.match(html, /id="diagnosticReport"/);
  assert.match(html, /id="copyReport"/);
  assert.match(renderer, /networkGuard\.getDiagnosticReport\(\)/);
  assert.match(renderer, /renderDiagnosticReport/);
  assert.match(preload, /getDiagnosticReport: \(\) => ipcRenderer\.invoke\('guard:get-diagnostic-report'\)/);
  assert.match(main, /ipcMain\.handle\('guard:get-diagnostic-report'/);
  assert.match(service, /buildDiagnosticReport/);
});

test('renderer explains request-time validation replaces periodic monitoring', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');

  assert.match(html, /请求时校验/);
  assert.doesNotMatch(html, /id="monitoringEnabled"/);
  assert.doesNotMatch(html, /id="monitoringInterval"/);
  assert.match(html, /id="monitoringStatus"/);
  assert.match(renderer, /renderMonitoring/);
  assert.match(renderer, /定时检测已停用/);
});

test('main process auto-checks and strongly alerts on launch-at-login guard failures', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /启动后自动检测并开启守卫/);
  assert.match(main, /runStartupGuardCheck/);
  assert.match(main, /initialStatus\.launchAtLogin === true/);
  assert.match(main, /service\.enableGuard\(undefined, \{/);
  assert.match(main, /acceptNoStaticIpRisk: shouldReuseNoStaticIpRiskAcceptance/);
  assert.match(main, /dialog\.showMessageBox/);
  assert.match(main, /开机防护已启动，但 Claude 流量暂被阻断/);
  assert.match(renderer, /event\.type === 'open-report'/);
  assert.match(renderer, /setActiveView\('report'\)/);
});

test('README documents macOS pf firewall fallback', () => {
  const readme = readProjectFile('README.md');

  assert.match(readme, /macOS firewall fallback/);
  assert.match(readme, /\/etc\/pf\.anchors\/com\.local\.claude-network-guard/);
  assert.match(readme, /administrator authorization/);
  assert.match(readme, /Targets view/);
  assert.match(readme, /Request-time validation/);
});
