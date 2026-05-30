# Environment Consistency One-Click Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship one-click environment alignment (Windows + Chrome + Edge) with backup/restore, toggle, US state-level timezone mapping, immediate app relaunch, and diagnostic report backup summary.

**Architecture:** Four focused daemon modules (`profile-resolver`, `backup-store`, `applier-win`, `consistency-service`) orchestrated by `GuardService`, exposed via IPC like `emergencyRestore`. Renderer adds a consistency control block and wires `fix-environment` guidance action.

**Tech Stack:** Electron 42, Node.js test runner, PowerShell (`powershell.exe -NoProfile`), vanilla renderer.

**Spec:** `docs/superpowers/specs/2026-05-30-environment-consistency-fix-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/daemon/environment-profile-resolver.js` | Map exit IP + override → target profile |
| `src/daemon/environment-backup-store.js` | Read/write `environment-backup.json` |
| `src/daemon/environment-applier-win.js` | Windows + Chrome + Edge mutations |
| `src/daemon/environment-consistency-service.js` | Apply/restore/backup orchestration |
| `src/daemon/guard-service.js` | Wire service, relaunch flag, `getStatus()` |
| `src/daemon/store.js` | Default `environmentConsistency` state |
| `src/daemon/diagnostic-report.js` | Add `environmentConsistency` summary |
| `src/shared/reason-catalog.js` | `fix-environment` action |
| `src/main/main.js` | IPC + `app.relaunch()` helper + `--lang` from store when enabled |
| `src/main/preload.js` | New IPC bridges |
| `src/renderer/index.html` | Consistency UI block |
| `src/renderer/renderer.js` | Toggle, apply, restore, guidance handler |
| `src/renderer/styles.css` | `.consistency-box` styles |
| `tests/environment-profile-resolver.test.js` | Resolver tests |
| `tests/environment-backup-store.test.js` | Backup round-trip |
| `tests/environment-applier-win.test.js` | Mocked exec/patch |
| `tests/environment-consistency-service.test.js` | Apply/restore flow |
| `tests/guard-service.test.js` | Integration hooks |
| `tests/diagnostic-report.test.js` | Report summary fields |
| `tests/reason-catalog.test.js` | `fix-environment` present |
| `tests/renderer-static.test.js` | DOM + IPC wiring |

---

### Task 1: Environment Profile Resolver

**Files:**
- Create: `src/daemon/environment-profile-resolver.js`
- Create: `tests/environment-profile-resolver.test.js`

- [ ] **Step 1: Write failing tests**

```javascript
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveEnvironmentProfile } = require('../src/daemon/environment-profile-resolver');

test('resolveEnvironmentProfile maps US Texas to Central', () => {
  const profile = resolveEnvironmentProfile({
    countryCode: 'US',
    regionName: 'Texas, United States'
  });
  assert.equal(profile.timeZone, 'America/Chicago');
  assert.equal(profile.windowsTimeZone, 'Central Standard Time');
  assert.equal(profile.language, 'en-US');
});

test('resolveEnvironmentProfile prefers user override', () => {
  const profile = resolveEnvironmentProfile(
    { countryCode: 'US', regionName: 'California' },
    { timeZone: 'Europe/London', language: 'en-GB' }
  );
  assert.equal(profile.timeZone, 'Europe/London');
  assert.equal(profile.language, 'en-GB');
});
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `node --test tests/environment-profile-resolver.test.js`  
Expected: module not found

- [ ] **Step 3: Implement resolver**

Export `resolveEnvironmentProfile(exitIp, override = {})` returning:

```javascript
{
  timeZone, windowsTimeZone, language, languages, countryCode, derivedFrom: 'exit-ip' | 'override' | 'fallback'
}
```

Implement US keyword table from spec (Eastern/Central/Mountain/Pacific/Alaska/Hawaii). Country fallback table for GB, CA, AU, DE, JP, unknown→US Eastern.

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/daemon/environment-profile-resolver.js tests/environment-profile-resolver.test.js
git commit -m "feat: add environment profile resolver from exit IP"
```

---

### Task 2: Environment Backup Store

**Files:**
- Create: `src/daemon/environment-backup-store.js`
- Create: `tests/environment-backup-store.test.js`

- [ ] **Step 1: Write failing tests**

```javascript
test('EnvironmentBackupStore saves and loads snapshot', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-backup-'));
  const store = new EnvironmentBackupStore(path.join(tmp, 'environment-backup.json'));
  const snapshot = { version: 1, createdAt: new Date().toISOString(), platform: 'win32', windows: { timeZoneId: 'China Standard Time' } };
  store.save(snapshot);
  assert.deepEqual(store.load(), snapshot);
});
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Implement**

Methods: `exists()`, `load()`, `save(snapshot)`, `getSummary()` → `{ hasBackup, createdAt }`.

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

---

### Task 3: Windows Environment Applier

**Files:**
- Create: `src/daemon/environment-applier-win.js`
- Create: `tests/environment-applier-win.test.js`

- [ ] **Step 1: Write failing tests with injectable deps**

```javascript
test('captureCurrentState returns windows timezone from mock exec', async () => {
  const applier = new EnvironmentApplierWin({
    execFile: async () => ({ stdout: 'China Standard Time\n' })
  });
  const state = await applier.captureCurrentState();
  assert.equal(state.windows.timeZoneId, 'China Standard Time');
});
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Implement applier**

Injectable `execFile`, `fs`, `path`, `process`.

Methods:
- `captureCurrentState()` → backup-shaped object (PowerShell: `(Get-TimeZone).Id`, `Get-WinUserLanguageList`, Chrome/Edge prefs paths under `%LOCALAPPDATA%`)
- `applyProfile(profile)` → `{ ok, steps: { 'windows.timezone': { ok, error } } }`
- `restoreFromBackup(backup)` → same step shape
- `isBrowserRunning()` → tasklist check for `chrome.exe`, `msedge.exe`
- `patchBrowserPreferences(path, { acceptLanguages })` — JSON parse, set `intl.accept_languages`, write atomically (write temp + rename)
- `setWebRtcPolicy(browser, policy)` — HKCU registry keys under `Software\Policies\Google\Chrome` and `Microsoft\Edge`
- `removeWebRtcPolicy(browser)` — delete only keys this app set (track `webrtcPolicyApplied: true` in backup)

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

---

### Task 4: Environment Consistency Service

**Files:**
- Create: `src/daemon/environment-consistency-service.js`
- Create: `tests/environment-consistency-service.test.js`

- [ ] **Step 1: Write failing tests**

```javascript
test('apply creates backup then applies profile', async () => {
  const backupStore = { exists: () => false, save: () => {}, getSummary: () => ({ hasBackup: true, createdAt: 't' }) };
  const applier = { captureCurrentState: async () => ({ version: 1, windows: {} }), applyProfile: async () => ({ ok: true, steps: {} }), isBrowserRunning: () => false };
  const service = new EnvironmentConsistencyService({ backupStore, applier, resolveProfile: () => ({ timeZone: 'America/Chicago', language: 'en-US', languages: ['en-US'] }) });
  const result = await service.apply({ exitIp: { countryCode: 'US', regionName: 'Texas' }, config: { deriveFromExitIp: true, profileOverride: {} } });
  assert.equal(result.ok, true);
  assert.equal(result.restartRequired, true);
});
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Implement service**

Methods:
- `apply({ exitIp, config, storeUpdater })` — preflight browsers, `ensureBackup`, resolve profile, apply, return `{ ok, steps, restartRequired: true, lastTargetProfile }`
- `restore()` — load backup, restore, `enabled: false`
- `backupNow()` — force overwrite backup from current capture
- `setConfig(patch)` — merge derive/override

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

---

### Task 5: Store Defaults & GuardService Integration

**Files:**
- Modify: `src/daemon/store.js`
- Modify: `src/daemon/guard-service.js`
- Modify: `tests/guard-service.test.js`

- [ ] **Step 1: Extend `defaultState()`**

```javascript
environmentConsistency: {
  enabled: false,
  deriveFromExitIp: true,
  profileOverride: { timeZone: '', language: '', languages: [] },
  backup: { createdAt: null, path: null },
  lastTargetProfile: null,
  lastApplyResult: null,
  lastRestoreResult: null,
  pendingPostApplyCheck: false
}
```

- [ ] **Step 2: Write failing guard-service tests**

```javascript
test('applyEnvironmentConsistency sets pendingPostApplyCheck', async () => {
  // mock EnvironmentConsistencyService.apply → { ok: true, restartRequired: true }
  const status = await service.applyEnvironmentConsistency();
  assert.equal(service.store.getState().environmentConsistency.pendingPostApplyCheck, true);
});
```

- [ ] **Step 3: Wire GuardService**

Constructor: `this.environmentConsistency = new EnvironmentConsistencyService({ dataDir: path.dirname(store.filePath), ... })`

Methods:
- `applyEnvironmentConsistency()`
- `restoreEnvironmentConsistency()`
- `backupEnvironmentNow()`
- `setEnvironmentConsistencyConfig(patch)`
- Include `environmentConsistency` in `getStatus()` (merge backup summary from backup store)

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

---

### Task 6: App Relaunch & Electron Lang Flag

**Files:**
- Modify: `src/main/main.js`
- Modify: `src/daemon/guard-service.js`

- [ ] **Step 1: Add launch switches before `app.whenReady`**

Keep existing `force-webrtc-ip-handling-policy`. After store load in `app.whenReady`, if `environmentConsistency.enabled` and profile language set:

```javascript
app.commandLine.appendSwitch('lang', profile.language || 'en-US');
```

(Append before first window only — read store synchronously from default data dir path helper.)

- [ ] **Step 2: IPC handler returns restart flag; relaunch helper**

```javascript
function scheduleAppRelaunch() {
  app.relaunch();
  app.exit(0);
}
```

`guard:environment-consistency-apply` → on success with `restartRequired`, call `scheduleAppRelaunch()` after IPC response sent (use `setImmediate`).

- [ ] **Step 3: Post-restart auto check**

In `app.whenReady` after `createWindow()`:

```javascript
if (service.getStatus().environmentConsistency?.pendingPostApplyCheck) {
  service.store.update({ environmentConsistency: { ...state, pendingPostApplyCheck: false } });
  mainWindow.webContents.once('did-finish-load', () => {
    mainWindow.webContents.send('guard:event', { type: 'post-apply-check' });
  });
}
```

Renderer on `post-apply-check`: `reportEnvironment()` → `checkNow()`.

- [ ] **Step 4: Manual smoke** — apply flow triggers relaunch (document in plan notes)

- [ ] **Step 5: Commit**

---

### Task 7: IPC & Preload

**Files:**
- Modify: `src/main/main.js`
- Modify: `src/main/preload.js`

- [ ] **Step 1: Add IPC handlers**

- `guard:environment-consistency-apply`
- `guard:environment-consistency-restore`
- `guard:environment-consistency-set-config`
- `guard:environment-consistency-backup-now`

- [ ] **Step 2: Expose preload methods**

```javascript
applyEnvironmentConsistency: () => ipcRenderer.invoke('guard:environment-consistency-apply'),
restoreEnvironmentConsistency: () => ipcRenderer.invoke('guard:environment-consistency-restore'),
setEnvironmentConsistencyConfig: (config) => ipcRenderer.invoke('guard:environment-consistency-set-config', config),
backupEnvironmentNow: () => ipcRenderer.invoke('guard:environment-consistency-backup-now'),
```

- [ ] **Step 3: Commit**

---

### Task 8: Diagnostic Report & Reason Catalog

**Files:**
- Modify: `src/daemon/diagnostic-report.js`
- Modify: `src/shared/reason-catalog.js`
- Modify: `tests/diagnostic-report.test.js`
- Modify: `tests/reason-catalog.test.js`

- [ ] **Step 1: Failing diagnostic test**

```javascript
test('buildDiagnosticReport includes environmentConsistency summary', () => {
  const report = buildDiagnosticReport({
    environmentConsistency: {
      enabled: true,
      backup: { hasBackup: true, createdAt: '2026-05-30T01:00:00.000Z' },
      lastTargetProfile: { timeZone: 'America/Chicago', language: 'en-US' }
    }
  });
  assert.equal(report.environmentConsistency.backup.createdAt, '2026-05-30T01:00:00.000Z');
});
```

- [ ] **Step 2: Implement `summarizeEnvironmentConsistency(status)`**

Return masked summary per spec; no raw backup file body.

- [ ] **Step 3: Update ENVIRONMENT_MISMATCH actions**

Primary: `fix-environment` → `一键修复环境`

- [ ] **Step 4: Run tests — PASS**

- [ ] **Step 5: Commit**

---

### Task 9: Renderer UI & Wiring

**Files:**
- Modify: `src/renderer/index.html`
- Modify: `src/renderer/renderer.js`
- Modify: `src/renderer/styles.css`
- Modify: `tests/renderer-static.test.js`

- [ ] **Step 1: Add HTML block in overview `side-stack`**

```html
<div class="consistency-box">
  <div>
    <strong>环境一致性</strong>
    <small id="environmentConsistencySummary">尚未对齐</small>
  </div>
  <label class="switch-row">
    <span><strong>启用对齐</strong><small id="environmentConsistencyTarget">跟随出口 IP</small></span>
    <input id="environmentConsistencyToggle" type="checkbox" />
  </label>
  <label class="field compact">
    <span><input id="deriveFromExitIp" type="checkbox" checked /> 跟随出口 IP 自动选择</span>
  </label>
  <label class="field">
    <span>目标时区 (IANA)</span>
    <input id="profileOverrideTimeZone" type="text" placeholder="留空=自动" />
  </label>
  <label class="field">
    <span>目标语言</span>
    <input id="profileOverrideLanguage" type="text" placeholder="留空=自动" />
  </label>
  <button id="applyEnvironmentConsistency" class="button primary wide" type="button">一键对齐环境</button>
  <button id="restoreEnvironmentConsistency" class="button secondary wide" type="button">还原原始环境</button>
  <button id="backupEnvironmentNow" class="button secondary wide" type="button">重新备份当前环境</button>
  <small id="environmentConsistencyStatus" class="field-message" aria-live="polite"></small>
</div>
```

- [ ] **Step 2: Renderer logic**

- `renderEnvironmentConsistency(status.environmentConsistency)` — backup line uses `backup.createdAt` formatted
- Toggle ON → `applyEnvironmentConsistency()`; OFF → `restoreEnvironmentConsistency()`
- `runGuidanceAction('fix-environment')` → click apply button
- `deriveFromExitIp` / override inputs → debounced `setEnvironmentConsistencyConfig`
- `renderEnvironmentConsistencyResult(lastApplyResult | lastRestoreResult)` — mirror `renderRecovery`
- On `post-apply-check` event → `reportEnvironment` + `checkNow`

- [ ] **Step 3: CSS** — reuse `.binding-box` spacing patterns

- [ ] **Step 4: Static tests** — assert element ids and preload IPC strings exist

- [ ] **Step 5: Commit**

---

### Task 10: Full Verification

- [ ] **Step 1: Run full test suite**

Run: `npm.cmd test`  
Expected: all tests PASS

- [ ] **Step 2: Manual checklist (Windows)**

1. Trigger `ENVIRONMENT_MISMATCH` with zh-CN + US IP
2. Click **一键修复环境** — confirm backup created, browsers closed prompt if running
3. App relaunches; post-restart check runs
4. Report shows `environmentConsistency.backup.createdAt`
5. Toggle OFF / **还原原始环境** — timezone and language revert
6. Override timezone to `America/Los_Angeles` with derive off — apply uses override

- [ ] **Step 3: Final commit if loose changes remain**

```bash
git commit -m "feat: environment consistency one-click fix with backup and toggle"
```

---

## Spec Self-Review

| Requirement | Task |
|-------------|------|
| US state subdivision | Task 1 |
| Immediate app restart | Task 6 |
| Diagnostic backup summary | Task 8 |
| Backup/restore | Tasks 2, 3, 4 |
| Toggle + Chrome/Edge | Tasks 3, 4, 9 |
| User override | Tasks 1, 4, 9 |
| fix-environment action | Task 8, 9 |

No placeholders remain in task steps above.
