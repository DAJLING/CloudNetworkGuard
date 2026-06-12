# Configurable Validation Targets Design

## Goal

Let users configure which Claude and Anthropic API checks are active, with in-app controls and reset-to-default actions. Guard/block rules remain separate from validation scope.

## Model

- `validation.services.claude` — toggles the Claude/Anthropic preset host bundle.
- `validation.webProbe` — optional Claude web probe URL.
- `validation.useCustomHosts` — advanced mode: user-edited health/control host lists.
- Derived fields `healthCheckHosts`, `controlHosts`, `webProbeUrl` persisted in `target-rules.json` for readability.

## Defaults

- Claude/Anthropic enabled; web probe `https://claude.ai/`.
- `还原校验默认` resets validation block only (keeps guard rules and static IP).
- `还原全部默认` rewrites file to factory `defaultTargetConfig()`.

## UI

Targets tab: checkboxes, web probe toggle/URL, optional custom host textareas, Save + two reset buttons.
