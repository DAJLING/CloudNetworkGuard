# Configurable Validation Targets Design

## Goal

Let users choose which API surfaces are validated (Claude only, Codex/OpenAI only, or both), with in-app controls and reset-to-default actions. Guard/block rules remain separate from validation scope.

## Model

- `validation.services.claude` / `validation.services.codex` — toggles preset host bundles.
- `validation.webProbe` — optional Claude web probe URL.
- `validation.useCustomHosts` — advanced mode: user-edited health/control host lists.
- Derived fields `healthCheckHosts`, `controlHosts`, `webProbeUrl` persisted in `target-rules.json` for readability.

## Defaults

- Both Claude and Codex enabled; web probe `https://claude.ai/`.
- `还原校验默认` resets validation block only (keeps guard rules and static IP).
- `还原全部默认` rewrites file to factory `defaultTargetConfig()`.

## UI

Targets tab: checkboxes, web probe toggle/URL, optional custom host textareas, Save + two reset buttons.
