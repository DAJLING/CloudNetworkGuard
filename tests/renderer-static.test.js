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

  assert.match(html, /id="fixTitle"/);
  assert.match(html, /id="fixExplanation"/);
  assert.match(html, /id="fixActions"/);
  assert.match(renderer, /renderGuidance\(status\.guidance/);
  assert.match(service, /getTopReasonGuidance/);
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

test('renderer exposes configurable validation target controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="validationClaude"/);
  assert.match(html, /id="validationCodex"/);
  assert.match(html, /id="saveValidation"/);
  assert.match(html, /id="addTargetRule"/);
  assert.match(html, /id="saveTargetRules"/);
  assert.match(html, /id="targetRulesStatus"/);
  assert.match(html, /id="resetValidationDefaults"/);
  assert.match(html, /id="resetTargetConfigDefaults"/);
  assert.match(renderer, /renderTargetRuleEditor/);
  assert.match(renderer, /readTargetRulesFromEditor/);
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

test('renderer exposes periodic monitoring controls', () => {
  const html = readProjectFile('src/renderer/index.html');
  const renderer = readProjectFile('src/renderer/renderer.js');
  const preload = readProjectFile('src/main/preload.js');
  const main = readProjectFile('src/main/main.js');

  assert.match(html, /id="monitoringEnabled"/);
  assert.match(html, /id="monitoringInterval"/);
  assert.match(html, /id="saveMonitoring"/);
  assert.match(html, /id="monitoringStatus"/);
  assert.match(renderer, /renderMonitoring/);
  assert.match(renderer, /readMonitoringConfig/);
  assert.match(renderer, /networkGuard\.setMonitoringConfig/);
  assert.match(preload, /setMonitoringConfig: \(config\) => ipcRenderer\.invoke\('guard:set-monitoring-config', config\)/);
  assert.match(main, /ipcMain\.handle\('guard:set-monitoring-config'/);
});

test('README documents macOS pf firewall fallback', () => {
  const readme = readProjectFile('README.md');

  assert.match(readme, /macOS firewall fallback/);
  assert.match(readme, /\/etc\/pf\.anchors\/com\.local\.claude-codex-network-guard/);
  assert.match(readme, /administrator authorization/);
  assert.match(readme, /Targets view/);
  assert.match(readme, /Periodic monitoring/);
});
