# macOS Parity Design

## Goal

Make the macOS build match the existing Windows feature surface for guarded network operation:

- Environment consistency one-click apply, backup, and restore
- Chrome and Edge language/WebRTC alignment
- Direct-client fallback blocking when apps bypass the system proxy
- UI, status, diagnostic, and test coverage parity

The approved approach is native macOS parity using an `EnvironmentApplierMac` and a `pf`-based firewall fallback. Administrator authorization is acceptable for macOS operations that modify protected system settings or packet filter rules.

## Current State

The app already supports both Windows and macOS at the product level, and `ProxyManager` already applies macOS system proxy settings through `networksetup`.

Two important gaps remain:

1. `EnvironmentConsistencyService.isSupported()` only returns true on `win32`, and the default applier is `EnvironmentApplierWin`.
2. `FirewallManager.applyBlock()` returns `UNSUPPORTED_PLATFORM` on macOS, so direct clients that bypass the system proxy are not blocked.

Windows behavior must remain unchanged.

## Product Principles

1. **Native parity**: macOS should expose the same user-facing controls and status semantics as Windows.
2. **Reversible by default**: macOS environment changes require a local backup before mutation and support explicit restore.
3. **Scoped privileged changes**: admin-authorized operations only touch app-owned resources and the specific system settings required for parity.
4. **No silent partial success**: every apply, restore, and firewall operation records per-step status.
5. **Testable without host mutation**: unit tests validate command construction, file patching, rule rendering, and orchestration without invoking real `pfctl` or mutating the host OS.

## Platform Scope

| Capability | Windows | macOS target |
|------------|---------|--------------|
| System proxy | Registry Internet Settings | `networksetup` service proxy |
| Environment consistency support | Full | Full |
| System time zone alignment | `tzutil` / PowerShell | `systemsetup -settimezone` |
| Language/locale alignment | PowerShell language list | `defaults write NSGlobalDomain` |
| Chrome/Edge preference patching | Preferences JSON | Preferences JSON |
| Chrome/Edge WebRTC policy | HKCU policy registry | Managed policy when available; preference fallback |
| Direct-client fallback blocking | `netsh advfirewall` | `pf` anchor |
| Backup/restore | `environment-backup.json` | same file, `platform: "darwin"` |
| Safari/Firefox | Out of scope | Out of scope |

Safari and Firefox are out of scope because the Windows implementation only manages Chrome and Edge. The UI and diagnostic report should avoid implying Safari is protected by environment consistency.

## Architecture

```
GuardService
  |-- EnvironmentConsistencyService
  |     |-- EnvironmentProfileResolver
  |     |-- EnvironmentBackupStore
  |     |-- EnvironmentApplierWin
  |     `-- EnvironmentApplierMac
  |
  |-- FirewallManager
        |-- Windows netsh backend
        `-- macOS pf backend
```

### Platform Applier Selection

`EnvironmentConsistencyService` should select the applier by platform:

- `win32` -> `EnvironmentApplierWin`
- `darwin` -> `EnvironmentApplierMac`
- other -> unsupported result

`isSupported()` should return true for `win32` and `darwin` when the selected applier reports support.

Dependency injection remains available for tests:

```javascript
new EnvironmentConsistencyService({
  dataDir,
  platform: 'darwin',
  applier,
  backupStore,
  resolveProfile
});
```

### Privileged Command Runner

macOS privileged operations need a small internal runner with a narrow API. It should not accept arbitrary shell strings from callers.

Responsibilities:

- Run unprivileged commands through injectable `execFile`
- Run privileged command batches through AppleScript authorization, for example `osascript -e 'do shell script ... with administrator privileges'`
- Quote all file paths and arguments with a deterministic helper
- Return stdout/stderr or clear errors for per-step reporting

The runner should be used for:

- `systemsetup -settimezone`
- writes under `/etc/pf.anchors`
- patching `/etc/pf.conf`
- `pfctl -f /etc/pf.conf`
- `pfctl -e`

Unprivileged reads should stay unprivileged where possible.

## macOS Environment Consistency

### Backup Shape

`EnvironmentApplierMac.captureCurrentState()` writes the same top-level backup file used by Windows:

```javascript
{
  version: 1,
  createdAt: 'ISO-8601',
  platform: 'darwin',
  mac: {
    timeZone: 'Asia/Shanghai',
    appleLanguages: ['zh-Hans-CN', 'en-US'],
    appleLocale: 'zh_CN'
  },
  chrome: {
    installed: true,
    preferencesPath: '...',
    intlAcceptLanguages: 'zh-CN,zh',
    webrtcPolicy: null,
    webrtcPreference: null
  },
  edge: {
    installed: true,
    preferencesPath: '...',
    intlAcceptLanguages: 'zh-CN,zh',
    webrtcPolicy: null,
    webrtcPreference: null
  }
}
```

Backup captures only fields the feature can modify. Full browser profiles are not copied.

### State Capture

Capture commands:

- Time zone: `systemsetup -gettimezone`
- Languages: `defaults read NSGlobalDomain AppleLanguages`
- Locale: `defaults read NSGlobalDomain AppleLocale`
- Browser preferences:
  - Chrome: `~/Library/Application Support/Google/Chrome/Default/Preferences`
  - Edge: `~/Library/Application Support/Microsoft Edge/Default/Preferences`

The applier should parse simple `defaults` output robustly enough for tests and common macOS output. If language or locale reads fail because values do not exist, store empty values and continue.

### Preflight

`EnvironmentApplierMac.isBrowserRunning()` checks for running Chrome and Edge before profile mutation:

- `pgrep -x "Google Chrome"`
- `pgrep -x "Microsoft Edge"`

If either browser is running, apply and restore return a `BROWSER_RUNNING` preflight failure and do not mutate browser preferences.

### Apply Behavior

`applyProfile(profile, { keepChineseInput })` returns:

```javascript
{
  ok,
  keepChineseInput,
  steps: {
    'mac.timezone': { ok, error },
    'mac.language': { ok, error, skipped, reason },
    'chrome.language': { ok, error, skipped, reason },
    'chrome.webrtc': { ok, error, skipped, reason },
    'edge.language': { ok, error, skipped, reason },
    'edge.webrtc': { ok, error, skipped, reason }
  }
}
```

Rules:

- Time zone always applies with `systemsetup -settimezone <profile.timeZone>`.
- If `keepChineseInput !== false`, language and browser language changes are skipped with reason `KEEP_CHINESE_INPUT`, matching the existing Windows-friendly behavior.
- If `keepChineseInput === false`, apply:
  - `defaults write NSGlobalDomain AppleLanguages -array <languages...>`
  - `defaults write NSGlobalDomain AppleLocale <locale derived from language>`
  - Browser `intl.accept_languages` preference patch.
- WebRTC protection applies for installed Chrome and Edge regardless of `keepChineseInput`.
- Missing browser installs are skipped successfully with reason `NOT_INSTALLED`.
- The service keeps the existing `restartRequired` flow so Electron can relaunch and run the post-apply check.

### WebRTC Strategy

The preferred setting is equivalent to Chromium's `disable_non_proxied_udp` behavior.

Implementation order:

1. Use browser managed policy locations when feasible and testable.
2. Fall back to Preferences JSON patching if policy writing is unavailable.

The backup must record which field existed before apply so restore can return the browser to its prior state or remove the app-owned value.

### Restore Behavior

`restoreFromBackup(backup)` restores absolute values from backup:

- `systemsetup -settimezone <backup.mac.timeZone>`
- Restore `AppleLanguages` when available
- Restore `AppleLocale` when available, or delete the app-written value only if it was absent in backup
- Restore browser `intl.accept_languages`
- Restore or remove WebRTC preference/policy fields based on backup

Restore is idempotent. If a browser was not installed in the backup, restore skips that browser successfully.

## macOS pf Firewall Fallback

### Desired Behavior

When the guard is enabled and validation has not released traffic, macOS should block direct outbound connections to guarded target IPs even if a client ignores system proxy settings. When validation passes or the guard is disabled, the app clears its block.

### Anchor Files

Use an app-owned anchor:

- Anchor name: `com.local.claude-codex-network-guard`
- Anchor path: `/etc/pf.anchors/com.local.claude-codex-network-guard`
- `pf.conf` marker start: `# ClaudeCodexNetworkGuard START`
- `pf.conf` marker end: `# ClaudeCodexNetworkGuard END`

The manager should only add or remove the marked block in `/etc/pf.conf`; all other user content must remain untouched.

### Rule Rendering

After resolving target hosts, render one compact outbound block:

```pf
block drop out quick to { 203.0.113.10, 2001:db8::10 }
```

If no IPs resolve, return a partial/failed block result with resolver details and do not install an empty rule.

### Apply Flow

`FirewallManager.applyMacBlock()`:

1. Resolve target hosts using existing `resolveTargetIps()`.
2. Render the anchor rule.
3. Write the anchor file through privileged runner.
4. Ensure `/etc/pf.conf` contains the marked anchor include.
5. Run `pfctl -f /etc/pf.conf`.
6. Run `pfctl -e`, treating "already enabled" as success.
7. Return `{ applied: true, mode: 'PF_BLOCK', rules, resolved, lastError: null }` when successful.

On partial failure, return `PARTIAL_BLOCK` with `lastError` and the rules that were attempted.

### Clear Flow

`FirewallManager.clearMacBlock()`:

1. Remove the marked anchor include from `/etc/pf.conf`.
2. Remove or truncate the app-owned anchor file.
3. Run `pfctl -f /etc/pf.conf`.
4. Return `{ applied: true, mode: 'PF_CLEARED', rules: [], lastError: null }`.

If privileged cleanup fails, return `PARTIAL_CLEAR` with `lastError`.

### Safety Constraints

- Do not shell-interpolate domains, IPs, or paths.
- Validate resolved IP strings before rendering pf rules.
- Manage only the app-owned anchor file and marked `pf.conf` block.
- Preserve existing Windows firewall behavior and public return shapes.
- If admin authorization is denied, report `SKIPPED` or `PARTIAL_BLOCK` with a clear error.

## GuardService and Status

`GuardService.getEnvironmentConsistencyStatus()` should report:

- `supported: true` on macOS
- backup summary as today
- last target profile and step results as today

Proxy mode remains:

- Windows default: `FIREWALL_ONLY`
- macOS: `SYSTEM` when system proxy is applied; firewall status separately reports `PF_BLOCK` or `PF_CLEARED`

`decorateCheckWithFirewall()` should treat `PF_BLOCK` and `PF_CLEARED` like successful firewall states, while `PARTIAL_BLOCK`, `PARTIAL_CLEAR`, and `ERROR` remain failures when the guard is enabled.

## UI

The current environment consistency UI remains shared:

- Do not hide the card on macOS.
- Show macOS step IDs in the result message when present.
- Continue using the existing apply, restore, backup, and override controls.
- Authorization failures appear in the existing status/error area.

Firewall status should display macOS modes without calling them unsupported:

- `PF_BLOCK`
- `PF_CLEARED`
- `PARTIAL_BLOCK`
- `PARTIAL_CLEAR`
- `SKIPPED`

No separate macOS page is required.

## Diagnostic Report

The diagnostic report should include:

- `environmentConsistency.supported: true` on macOS status
- `environmentConsistency.backup.hasBackup`
- `environmentConsistency.backup.createdAt`
- `environmentConsistency.lastTargetProfile`
- `environmentConsistency.lastApplyResult.ok`
- `environmentConsistency.lastRestoreResult.ok`
- `firewall.mode` with macOS pf modes

The report must not include full backup contents, raw browser profile contents, or unmasked IP addresses.

## README and Packaging Notes

README platform notes should state:

- macOS system proxy uses `networksetup`.
- macOS direct-client fallback uses `pf` and may request administrator authorization.
- The app manages only its own `pf` anchor and marked `pf.conf` block.
- `NETWORK_GUARD_SKIP_FIREWALL=1` disables firewall fallback for tests and dry runs.

No packaging change is required for the first implementation pass unless manual macOS smoke testing reveals additional entitlements or signing constraints.

## Testing Strategy

### New Tests

`tests/environment-applier-mac.test.js`

- Captures time zone from mocked `systemsetup -gettimezone`
- Parses mocked `defaults read` language output
- Blocks apply when Chrome or Edge is running
- Applies time zone with privileged runner
- Skips language changes when `keepChineseInput` is true
- Patches browser preferences when `keepChineseInput` is false
- Restores backup values idempotently

### Expanded Tests

`tests/environment-consistency-service.test.js`

- `darwin` platform reports supported with mac applier
- apply on `darwin` creates backup and returns `restartRequired`

`tests/firewall-manager.test.js`

- Renders pf block rule from IPv4 and IPv6 addresses
- Patches `pf.conf` by adding one marked anchor block
- Removes only the marked block
- Builds expected privileged command sequence for apply and clear
- Reports partial failure on authorization or command failure

`tests/guard-service.test.js`

- macOS environment consistency status is supported when injected service supports it
- macOS firewall success modes decorate checks as pass/skipped appropriately

`tests/renderer-static.test.js`

- Existing environment consistency UI and IPC wiring remains present
- No static unsupported macOS copy is introduced

### Full Verification

Run:

```powershell
npm.cmd test
```

Manual macOS smoke checklist:

1. Start app on macOS with `NETWORK_GUARD_SKIP_FIREWALL` unset.
2. Enable guard while checks are blocked; approve admin prompt.
3. Confirm `pf` anchor exists and guarded target IPs are blocked.
4. Run immediate check until pass; confirm pf rules are cleared.
5. Apply environment consistency with Chrome/Edge closed; confirm backup file is created.
6. Relaunch occurs and post-apply check runs.
7. Restore environment consistency; confirm backed-up values are restored.
8. Deny admin authorization once; confirm UI reports failure and app remains recoverable.

## Acceptance Criteria

1. macOS environment consistency apply and restore no longer return `UNSUPPORTED_PLATFORM`.
2. macOS backup captures system time zone, language/locale, and Chrome/Edge fields modified by the feature.
3. macOS restore returns modified fields to backup values and is safe to run multiple times.
4. macOS guard fallback can install and clear an app-owned `pf` block for resolved target IPs.
5. macOS authorization denial produces clear per-step failure without corrupting unrelated settings.
6. Existing Windows behavior and tests continue to pass.
7. UI, status, diagnostic report, and README accurately describe macOS parity.
8. Unit tests cover the macOS applier, `pf` rule management, and service platform selection.

## Out of Scope

- Safari and Firefox environment management
- Network Extension or long-running privileged helper
- Automatic browser restart
- Automatic macOS reboot or logout
- Managing VPN/proxy accounts
- Persistently pinning target domains instead of resolved IPs

## Open Questions Resolved

| Question | Decision |
|----------|----------|
| Include macOS direct-client fallback? | Yes, use `pf`. |
| Can the app request admin authorization? | Yes. |
| Use a privileged helper now? | No, use a scoped AppleScript authorization runner first. |
| Match Windows browser scope? | Yes, Chrome and Edge only. |
| Separate macOS UI? | No, reuse shared controls and status. |
