# Recommended Extensions Design

Date: 2026-06-05

## Context and Decision

The user asked to finish macOS parity and then implement the recommended extensions from the project review without asking follow-up questions. The approved bundle is:

- Rules configuration UI
- Periodic monitoring
- Diagnostic report upgrade
- macOS permission and recovery safety visibility

The implementation should extend existing boundaries instead of introducing a new configuration system or scheduler framework.

## Approach

### Recommended Approach: Small Integrated Controls

Use the existing `TargetConfigManager`, `GuardService`, IPC/preload bridge, and renderer page layout. Add a rule editor for the existing `rules` array, a lightweight monitoring timer inside `GuardService`, and richer diagnostic summaries derived from current status. This is the best fit because the app is already a compact Electron desktop guard and most data already flows through `getStatus()`.

### Alternatives Rejected

- Raw JSON editor only: faster, but error-prone and less useful for normal users.
- Full policy engine with per-process strategy modes: powerful, but larger than the current product surface and better left for a later iteration.
- External scheduler service: unnecessary; the app already owns the guard lifecycle and can run a local timer.

## Requirements

### Rules Configuration UI

- The Targets view must allow adding, editing, deleting, and saving guarded target rules.
- Each editable rule has `id`, `domainPattern`, and `action`.
- `action` is either `GUARD` or `ALLOW`.
- Saving rules uses a typed IPC path, not manual JSON file edits.
- Rule normalization remains in `TargetConfigManager`.
- `firewallHosts` are derived from saved `GUARD` rules unless the raw config explicitly had custom firewall hosts.
- Reset-to-defaults keeps its current behavior and refreshes the editor.
- Invalid or empty rule sets must show a local error and avoid saving.

### Periodic Monitoring

- Add persisted monitoring config under store state:
  - `enabled`
  - `intervalMinutes`
  - `lastRunAt`
  - `lastResult`
  - `lastError`
- Default: disabled, 15 minutes.
- Valid interval range: 1 to 1440 minutes.
- `GuardService.start()` starts the timer only when enabled.
- Updating config starts, stops, or reschedules the timer immediately.
- A monitor tick reuses `checkNow()` so firewall decoration, logging, target config, and diagnostic state stay consistent.
- Ticks must not overlap. If one tick is already running, the next one is skipped with a stored `lastError`.
- Renderer shows a compact monitoring control in the Activity or Report-adjacent surface with toggle, interval input, save button, and last-run summary.

### Diagnostic Report Upgrade

- Diagnostic JSON must include:
  - monitoring summary
  - platform capabilities for environment consistency and firewall fallback
  - target rule preview with rule count and guarded domains without exposing private IPs
  - macOS permission and recovery notes when platform or firewall mode indicates macOS/pf involvement
- Report remains copyable as JSON in the existing Diagnostic view.
- Diagnostic output must not include full raw backup contents, full provider IPs, or full static residential IP.

### macOS Permission and Recovery Safety Visibility

- Status should surface enough information to explain `pf` behavior:
  - `PF_BLOCK`, `PF_CLEARED`, and `PARTIAL_*` modes remain visible in firewall status.
  - README and diagnostic notes describe the app-owned anchor and marked `pf.conf` block.
- Emergency restore remains the recovery path and should be mentioned in diagnostics when macOS `pf` is active or partially failed.

## Data Flow

1. Renderer edits rules and calls `window.networkGuard.saveTargetRules(rules)`.
2. Main process forwards to `GuardService.saveTargetRules()`.
3. `TargetConfigManager.saveRules()` normalizes and persists rules, derives firewall hosts, then `GuardService.reloadTargetConfig()` refreshes runtime state.
4. Renderer edits monitoring config and calls `window.networkGuard.setMonitoringConfig(config)`.
5. `GuardService.setMonitoringConfig()` validates, persists, and reschedules the local timer.
6. Timer calls `checkNow()` and stores a compact monitor result.
7. `buildDiagnosticReport(getStatus())` emits the enhanced summary.

## Error Handling

- Rule editor validation rejects no rules, blank domains, duplicate IDs after trimming, and unsupported actions before IPC.
- Daemon-side normalization still guards against malformed input.
- Monitoring config rejects out-of-range intervals.
- Timer errors are stored in `monitoring.lastError` and emitted to renderer logs without crashing the service.
- Monitoring never runs concurrent checks.

## Testing

- `tests/target-config.test.js`: saving rules normalizes domains and derives firewall hosts.
- `tests/guard-service.test.js`: saving rules reloads firewall hosts; monitoring config persists; monitor tick runs `checkNow()` once and skips overlap.
- `tests/diagnostic-report.test.js`: enhanced diagnostic summary includes monitoring, platform capabilities, rule preview, and macOS notes without leaking IPs/backups.
- `tests/renderer-static.test.js`: IPC/preload/renderer/static HTML expose rule editor and monitoring controls.
- Full `npm.cmd test` must pass before merge.

## Scope Limits

- No per-process policy editor in this bundle.
- No remote telemetry or cloud sync.
- No packaging/signing changes.
- No visual redesign beyond fitting controls into existing panels.
