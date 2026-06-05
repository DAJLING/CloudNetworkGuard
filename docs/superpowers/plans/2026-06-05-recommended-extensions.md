# Recommended Guard Extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the recommended extension bundle: editable target rules UI, periodic monitoring, richer diagnostics, and macOS pf permission/recovery visibility.

**Architecture:** Keep configuration normalization in `TargetConfigManager`, orchestration in `GuardService`, IPC in `main/preload`, and view behavior in the existing renderer files. Monitoring is a lightweight local timer owned by `GuardService` and persisted in `Store`, while diagnostics summarize status without exposing sensitive raw data.

**Tech Stack:** Electron 42, Node.js CommonJS, Node test runner, existing renderer HTML/CSS/JS, local JSON store.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/daemon/target-config.js` | Add `saveRules()` and rule-list validation/rederivation. |
| `tests/target-config.test.js` | Cover saving rules, normalized domains, and derived firewall hosts. |
| `src/daemon/store.js` | Persist default monitoring config. |
| `src/daemon/guard-service.js` | Add rule-save orchestration, monitoring config/timer/tick, and status fields. |
| `tests/guard-service.test.js` | Cover rule saving and periodic monitoring behavior. |
| `src/main/preload.js` | Expose rule and monitoring IPC methods to renderer. |
| `src/main/main.js` | Register rule and monitoring IPC handlers. |
| `src/renderer/index.html` | Add rule editor controls and monitoring controls. |
| `src/renderer/renderer.js` | Render/edit/save rules and monitoring config. |
| `src/renderer/styles.css` | Style compact rule editor and monitoring controls. |
| `tests/renderer-static.test.js` | Verify static UI, preload, and IPC exposure. |
| `src/daemon/diagnostic-report.js` | Add monitoring, platform capabilities, rule preview, and macOS notes. |
| `tests/diagnostic-report.test.js` | Verify enhanced diagnostic summary without leaks. |
| `README.md` | Document rule editor, periodic monitoring, and macOS recovery notes. |

## Task 1: Rule Save Backend and IPC

**Files:**
- Modify: `src/daemon/target-config.js`
- Modify: `tests/target-config.test.js`
- Modify: `src/daemon/guard-service.js`
- Modify: `tests/guard-service.test.js`
- Modify: `src/main/preload.js`
- Modify: `src/main/main.js`
- Modify: `tests/renderer-static.test.js`

- [ ] **Step 1: Write failing tests**

Add tests that:

```javascript
// tests/target-config.test.js
test('TargetConfigManager saves editable target rules and derives firewall hosts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const filePath = path.join(tmp, 'target-rules.json');
  const manager = new TargetConfigManager({ filePath });
  manager.load();

  const saved = manager.saveRules([
    { id: 'custom-api', domainPattern: 'https://api.example.com/v1', action: 'GUARD' },
    { id: 'allowed-docs', domainPattern: 'docs.example.com', action: 'ALLOW' },
    { id: 'wildcard', domainPattern: '*.example.org', action: 'GUARD' }
  ]);

  assert.deepEqual(saved.rules.map((rule) => rule.domainPattern), ['api.example.com', 'docs.example.com', '*.example.org']);
  assert.deepEqual(saved.firewallHosts, ['api.example.com', 'example.org']);
  assert.equal(saved.rules[1].action, 'ALLOW');
});

test('TargetConfigManager rejects empty editable target rules', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-targets-'));
  const manager = new TargetConfigManager({ filePath: path.join(tmp, 'target-rules.json') });
  manager.load();

  assert.throws(() => manager.saveRules([]), /TARGET_RULES_REQUIRED/);
});
```

```javascript
// tests/guard-service.test.js
test('GuardService saveTargetRules persists rules and reloads firewall hosts', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  service.firewallManager.clearBlock = async () => ({ mode: 'CLEARED', rules: [] });

  const status = await service.saveTargetRules([
    { id: 'custom-api', domainPattern: 'api.example.com', action: 'GUARD' }
  ]);

  assert.equal(status.targetConfig.rules.length, 1);
  assert.deepEqual(service.firewallManager.hosts, ['api.example.com']);
});
```

Add static assertions for `saveTargetRules` in preload, main IPC, and renderer.

- [ ] **Step 2: Run tests and verify failure**

Run:

```powershell
node --test tests/target-config.test.js tests/guard-service.test.js tests/renderer-static.test.js
```

Expected: FAIL because `saveRules`, `saveTargetRules`, and IPC are missing.

- [ ] **Step 3: Implement backend and IPC**

Add `TargetConfigManager.saveRules(rulesInput)`:

```javascript
saveRules(rulesInput) {
  const normalizedRules = Array.isArray(rulesInput)
    ? rulesInput.map(normalizeRule).filter(Boolean)
    : [];
  if (!normalizedRules.length) throw new Error('TARGET_RULES_REQUIRED');
  const ids = new Set();
  for (const rule of normalizedRules) {
    if (ids.has(rule.id)) throw new Error('TARGET_RULE_IDS_DUPLICATE');
    ids.add(rule.id);
  }
  const raw = this.readRaw();
  raw.rules = normalizedRules;
  raw.firewallHosts = deriveHostsFromRules(normalizedRules);
  this.saveRaw(raw);
  return normalizeTargetConfig(raw, this.filePath);
}
```

Add `GuardService.saveTargetRules(rules)` that calls the manager, emits `target-rules-saved`, then delegates to `reloadTargetConfig()`.

Expose:

```javascript
saveTargetRules: (rules) => ipcRenderer.invoke('guard:save-target-rules', rules)
```

and:

```javascript
ipcMain.handle('guard:save-target-rules', async (_event, rules) => {
  const status = await service.saveTargetRules(rules || []);
  updateTray();
  return status;
});
```

- [ ] **Step 4: Run focused tests**

Run:

```powershell
node --test tests/target-config.test.js tests/guard-service.test.js tests/renderer-static.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/daemon/target-config.js tests/target-config.test.js src/daemon/guard-service.js tests/guard-service.test.js src/main/preload.js src/main/main.js tests/renderer-static.test.js
git commit -m "feat: add target rule save backend"
```

## Task 2: Rule Editor UI

**Files:**
- Modify: `src/renderer/index.html`
- Modify: `src/renderer/renderer.js`
- Modify: `src/renderer/styles.css`
- Modify: `tests/renderer-static.test.js`

- [ ] **Step 1: Write failing static tests**

Extend `renderer exposes configurable validation target controls` to assert:

```javascript
assert.match(html, /id="addTargetRule"/);
assert.match(html, /id="saveTargetRules"/);
assert.match(html, /id="targetRulesStatus"/);
assert.match(renderer, /renderTargetRuleEditor/);
assert.match(renderer, /readTargetRulesFromEditor/);
assert.match(renderer, /networkGuard\.saveTargetRules/);
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```powershell
node --test tests/renderer-static.test.js
```

Expected: FAIL because the editor controls/functions are missing.

- [ ] **Step 3: Implement UI**

Add buttons and a status element to the Rules panel:

```html
<div class="button-row">
  <button id="addTargetRule" class="button secondary" type="button">新增规则</button>
  <button id="saveTargetRules" class="button primary" type="button">保存规则</button>
</div>
<small id="targetRulesStatus" class="field-message" aria-live="polite"></small>
```

Render each rule as editable inputs with stable row layout:

```javascript
function renderTargetRuleEditor(rules = []) {
  els.targetRules.innerHTML = rules.map((rule, index) => `
    <div class="target-row editable" data-rule-index="${index}">
      <input class="text-input rule-id-input" value="${escapeHtml(rule.id)}" aria-label="Rule id" />
      <input class="text-input rule-domain-input" value="${escapeHtml(rule.domainPattern)}" aria-label="Rule domain" />
      <select class="text-input rule-action-input" aria-label="Rule action">
        <option value="GUARD"${rule.action === 'GUARD' ? ' selected' : ''}>GUARD</option>
        <option value="ALLOW"${rule.action === 'ALLOW' ? ' selected' : ''}>ALLOW</option>
      </select>
      <button class="button secondary remove-rule" type="button" data-remove-rule="${index}">删除</button>
    </div>
  `).join('');
}
```

Implement `readTargetRulesFromEditor()` with local validation for blank domains and duplicate IDs. Wire Add, Remove, and Save buttons.

- [ ] **Step 4: Run renderer static tests**

Run:

```powershell
node --test tests/renderer-static.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/renderer/index.html src/renderer/renderer.js src/renderer/styles.css tests/renderer-static.test.js
git commit -m "feat: add target rule editor UI"
```

## Task 3: Periodic Monitoring

**Files:**
- Modify: `src/daemon/store.js`
- Modify: `src/daemon/guard-service.js`
- Modify: `tests/guard-service.test.js`
- Modify: `src/main/preload.js`
- Modify: `src/main/main.js`
- Modify: `src/renderer/index.html`
- Modify: `src/renderer/renderer.js`
- Modify: `src/renderer/styles.css`
- Modify: `tests/renderer-static.test.js`

- [ ] **Step 1: Write failing tests**

Add GuardService tests:

```javascript
test('GuardService setMonitoringConfig persists enabled interval', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });

  const status = service.setMonitoringConfig({ enabled: true, intervalMinutes: 5 });

  assert.equal(status.monitoring.enabled, true);
  assert.equal(status.monitoring.intervalMinutes, 5);
});

test('GuardService runMonitoringTick records compact result and skips overlap', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-'));
  const store = new Store(path.join(tmp, 'state.json'));
  const service = new GuardService({ store, apiPort: 0, proxyPort: 0 });
  let calls = 0;
  service.checkNow = async () => {
    calls += 1;
    return { verdict: 'PASS', reasons: [], checkedAt: '2026-06-05T00:00:00.000Z' };
  };

  await service.runMonitoringTick();
  service.monitoringRunning = true;
  await service.runMonitoringTick();

  const monitoring = store.getState().monitoring;
  assert.equal(calls, 1);
  assert.equal(monitoring.lastResult.verdict, 'PASS');
  assert.equal(monitoring.lastError, 'MONITORING_ALREADY_RUNNING');
});
```

Add static renderer tests for `monitoringEnabled`, `monitoringInterval`, `saveMonitoring`, `renderMonitoring`, and `setMonitoringConfig`.

- [ ] **Step 2: Run tests and verify failure**

Run:

```powershell
node --test tests/guard-service.test.js tests/renderer-static.test.js
```

Expected: FAIL because monitoring state, methods, IPC, and controls are missing.

- [ ] **Step 3: Implement monitoring service**

Add default store state:

```javascript
monitoring: {
  enabled: false,
  intervalMinutes: 15,
  lastRunAt: null,
  lastResult: null,
  lastError: null
}
```

Add methods to `GuardService`:

```javascript
normalizeMonitoringConfig(config = {}) {
  const intervalMinutes = Math.max(1, Math.min(1440, Number(config.intervalMinutes) || 15));
  return { enabled: config.enabled === true, intervalMinutes };
}

getMonitoringStatus() {
  return { ...this.store.getState().monitoring, running: this.monitoringRunning === true };
}

setMonitoringConfig(config = {}) {
  const current = this.store.getState().monitoring || {};
  const normalized = this.normalizeMonitoringConfig(config);
  this.store.update({ monitoring: { ...current, ...normalized, lastError: null } });
  this.rescheduleMonitoring();
  const status = this.getStatus();
  this.emit({ type: 'monitoring-config', status });
  return status;
}

async runMonitoringTick() {
  if (this.monitoringRunning) {
    this.store.update({ monitoring: { ...this.store.getState().monitoring, lastError: 'MONITORING_ALREADY_RUNNING' } });
    return null;
  }
  this.monitoringRunning = true;
  const ranAt = new Date().toISOString();
  try {
    const check = await this.checkNow();
    this.store.update({ monitoring: { ...this.store.getState().monitoring, lastRunAt: ranAt, lastResult: { verdict: check.verdict, reasons: check.reasons || [], checkedAt: check.checkedAt || ranAt }, lastError: null } });
    return check;
  } catch (error) {
    this.store.update({ monitoring: { ...this.store.getState().monitoring, lastRunAt: ranAt, lastError: error.message || 'MONITORING_FAILED' } });
    return null;
  } finally {
    this.monitoringRunning = false;
  }
}
```

Add `rescheduleMonitoring()` and `clearMonitoringTimer()` with `setInterval`.

- [ ] **Step 4: Implement IPC and UI**

Expose `setMonitoringConfig(config)` in preload and main IPC. Add renderer controls and `renderMonitoring(status.monitoring || {})`.

- [ ] **Step 5: Run focused tests**

Run:

```powershell
node --test tests/guard-service.test.js tests/renderer-static.test.js
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/daemon/store.js src/daemon/guard-service.js tests/guard-service.test.js src/main/preload.js src/main/main.js src/renderer/index.html src/renderer/renderer.js src/renderer/styles.css tests/renderer-static.test.js
git commit -m "feat: add periodic monitoring controls"
```

## Task 4: Diagnostic Report Upgrade and Docs

**Files:**
- Modify: `src/daemon/diagnostic-report.js`
- Modify: `tests/diagnostic-report.test.js`
- Modify: `README.md`

- [ ] **Step 1: Write failing tests**

Add a diagnostic test asserting:

```javascript
const report = buildDiagnosticReport({
  platform: { os: 'darwin' },
  monitoring: { enabled: true, intervalMinutes: 5, lastRunAt: '2026-06-05T00:00:00.000Z', lastResult: { verdict: 'PASS', reasons: [] } },
  firewall: { mode: 'PF_BLOCK', lastError: null },
  targetConfig: {
    rules: [
      { id: 'api', domainPattern: 'api.example.com', action: 'GUARD' },
      { id: 'docs', domainPattern: 'docs.example.com', action: 'ALLOW' }
    ],
    staticResidentialIp: '203.0.113.10'
  },
  environmentConsistency: { supported: true }
});

assert.equal(report.monitoring.enabled, true);
assert.equal(report.platformCapabilities.firewallFallback, 'macos-pf');
assert.deepEqual(report.targetConfig.rulePreview.guardedDomains, ['api.example.com']);
assert.equal(JSON.stringify(report).includes('203.0.113.10'), false);
assert.match(report.safetyNotes.join(' '), /Emergency restore/);
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```powershell
node --test tests/diagnostic-report.test.js
```

Expected: FAIL because enhanced fields are missing.

- [ ] **Step 3: Implement diagnostic summary**

Add summarizers for monitoring, platform capabilities, rule preview, and safety notes. Determine macOS pf by `status.platform.os === 'darwin'` or firewall mode starting with `PF_`.

- [ ] **Step 4: Update README**

Document:

- Rules can be edited in the Targets view.
- Periodic monitoring can run checks in the background.
- Diagnostic report includes monitoring/platform/rule summaries.
- Emergency restore is the safe recovery path after partial macOS pf changes.

- [ ] **Step 5: Run diagnostic tests**

Run:

```powershell
node --test tests/diagnostic-report.test.js tests/renderer-static.test.js
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/daemon/diagnostic-report.js tests/diagnostic-report.test.js README.md
git commit -m "feat: expand diagnostic report summary"
```

## Task 5: Final Verification

**Files:**
- Modify only if verification finds defects.

- [ ] **Step 1: Run full regression**

Run:

```powershell
npm.cmd test
```

Expected: all tests PASS.

- [ ] **Step 2: Run dry-run regression**

Run:

```powershell
$env:NETWORK_GUARD_SKIP_FIREWALL='1'; $env:NETWORK_GUARD_SKIP_SYSTEM_PROXY='1'; npm.cmd test
```

Expected: all tests PASS.

- [ ] **Step 3: Inspect git status**

Run:

```powershell
git status --short
```

Expected: no uncommitted implementation changes.

- [ ] **Step 4: Commit verification fixes if needed**

Only if changes were required:

```bash
git add src tests README.md
git commit -m "fix: complete recommended extension verification"
```

## Spec Coverage Self-Review

| Spec Requirement | Plan Task |
|------------------|-----------|
| Add/edit/delete/save target rules in UI | Tasks 1-2 |
| Typed IPC save path for rules | Task 1 |
| Periodic monitoring with persisted config and non-overlap | Task 3 |
| Monitoring controls and last-run summary | Task 3 |
| Diagnostic monitoring summary | Task 4 |
| Diagnostic platform capabilities | Task 4 |
| Diagnostic rule preview without IP leak | Task 4 |
| macOS pf safety/recovery visibility | Task 4 |
| Full regression | Task 5 |

No spec requirement is intentionally deferred.
