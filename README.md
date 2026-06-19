# Claude Network Guard

Windows/macOS desktop guard for Claude and Anthropic API traffic.

The app provides a one-click guard switch. When enabled, target traffic is routed through a local proxy. Matching Claude/Anthropic requests trigger request-time exit IP validation before they are sent upstream:

- If a static residential IP is configured, the current exit IP must exactly match it.
- If no static residential IP is configured, the user must acknowledge Claude account risk before enabling the guard.
- Without a static residential IP, matching requests are blocked when the exit region is unsupported for Claude or cannot be confirmed.
- Manual "立即检测" still runs the broader DNS, TCP, TLS, web probe, provider, environment, and binding checks on demand.
- Browser/system environment consistency checks for blocked time zones, languages, and WebRTC local IP exposure
- Exit IP binding and mismatch alerts
- Target request rate monitoring
- Firewall fallback blocking for direct clients that do not honor system proxy settings
- Minimal local logging with masked IP data only

## Target Configuration

Guarded Claude targets are loaded from an editable JSON file named `target-rules.json` in the app data directory. Set `NETWORK_GUARD_TARGET_CONFIG` to point at another file. The Targets view can add, edit, delete, and save Claude/Anthropic target rules without manually editing JSON.

On first run the app writes the default Claude and Anthropic rules. Rules, custom validation hosts, and the web probe URL are restricted to `claude.ai` and `anthropic.com` domains.

`staticResidentialIp` may be edited in the app or in this file. Leave it empty or set it to `0.0.0.0` to enable request-time region validation after the user acknowledges Claude account risk. Set it to a real static residential IPv4 address to require an exact exit IP match before guarded requests are sent.

```json
{
  "version": 1,
  "rules": [
    { "id": "claude-web", "domainPattern": "claude.ai", "action": "GUARD" },
    { "id": "anthropic-api", "domainPattern": "*.anthropic.com", "action": "GUARD" }
  ],
  "healthCheckHosts": ["claude.ai", "api.anthropic.com"],
  "controlHosts": ["claude.ai", "api.anthropic.com"],
  "firewallHosts": ["claude.ai", "anthropic.com"],
  "webProbeUrl": "https://claude.ai/",
  "staticResidentialIp": ""
}
```

## Commands

Common development:

```bash
pnpm install
pnpm run make-icon
pnpm test
pnpm start
```

macOS packaging (run on macOS):

```bash
pnpm run pack:mac    # unpacked app at dist/mac/
pnpm run dist:mac    # DMG + PKG installers
```

Windows packaging (run on Windows):

```powershell
pnpm run pack:win       # unpacked app at dist/win-unpacked/
pnpm run dist:win       # NSIS installer
pnpm run dist:win:msi   # MSI installer (requires WiX on the build machine)
```

`pnpm run make-icon` creates the local Windows icon asset used by installer builds. macOS and Windows builds are intentionally separate commands so each platform only produces its own artifacts under `dist/`.

## Guard Behavior

- Guard disabled: target traffic is allowed and no block notification is shown.
- Guard enabled: matching Claude/Anthropic requests are held by the local proxy until request-time exit validation allows or blocks them.
- Direct clients: when a request-time verdict blocks traffic, Windows firewall rules or macOS `pf` anchor rules may be added for resolved target IPs so CLI tools that bypass the system proxy are also blocked.
- No static IP: the app prompts for Claude account-risk acknowledgement before enabling the guard.
- Exit IP binding: the first detected exit IP is locally bound by hash; later changes are blocked until state is reset.
- Claude control check: DNS, TCP, TLS, and Claude web probe failures block guarded traffic.
- Usage rate check: unusually high target request volume blocks guarded traffic.
- Request-time validation: background periodic checks are disabled; matching requests trigger the exit IP gate instead.
- Provider outage or offline checks: fail-closed while the guard is enabled.

## Platform Notes

- Windows proxy settings are applied through the current user's Internet Settings registry keys.
- Windows firewall fallback uses `netsh advfirewall` outbound block rules for resolved Claude/Anthropic IPs. It may require elevated permissions.
- macOS proxy settings use `networksetup` and default to the `Wi-Fi` service. Set `NETWORK_GUARD_MAC_SERVICE` to target another network service.
- macOS firewall fallback uses an app-owned `pf` anchor at `/etc/pf.anchors/com.local.claude-network-guard` and may request administrator authorization. The app only manages its marked `pf.conf` block and its own anchor file.
- Set `NETWORK_GUARD_SKIP_SYSTEM_PROXY=1` for tests or dry runs that should not touch system proxy settings.
- Set `NETWORK_GUARD_SKIP_FIREWALL=1` for tests or dry runs that should not touch firewall settings.
- Set `PING0_API_KEY` to enable Ping0 paid API lookup for IP risk, purity, and shared-user metadata. Without an API key, Ping0's free `/geo` endpoint only provides IP, location, ASN, and organization data; its public detail page may require CAPTCHA and cannot reliably provide risk or shared-user fields to the app.

## Current Limitations

- The app does not buy, switch, or manage proxy/VPN accounts.
- Free IP intelligence sources can misclassify residential/static status. The provider layer is intentionally pluggable for paid sources later.
- Account history, payment region, and server-side Claude risk decisions cannot be fully verified locally.
- Firewall fallback resolves current target IPs. If a service rotates to a new IP before the next request-time validation, run "立即检测" or reload target rules.
- The included icon is intentionally simple and should be replaced before public distribution.
