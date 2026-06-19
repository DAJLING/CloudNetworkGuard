# Claude Network Guard

[![English](https://img.shields.io/badge/Language-English-blue)](README.md)
[![简体中文](https://img.shields.io/badge/语言-简体中文-green)](README.zh.md)

Claude Network Guard is a Windows/macOS desktop app for Claude and Anthropic API network detection, request-time blocking, local proxy guarding, firewall fallback, static residential IP checks, and browser environment consistency.

If you are looking for a **Claude network detector**, **Claude request blocker**, **Anthropic API proxy guard**, **Claude Code network guard**, **static residential IP checker**, or **Claude traffic firewall**, this project is built for that workflow.

## What It Does

Claude Network Guard starts a local guard proxy and puts Claude / Anthropic target traffic through a request-time validation flow. When the guard is enabled, matching requests are held by the local proxy. They are forwarded upstream only after exit IP, region, proxy risk, Claude reachability, browser environment, usage rate, and exit binding checks pass.

Use it when you need to:

- Check whether your current network is suitable before using Claude, Claude Web, Claude Code, or the Anthropic API.
- Block Claude target traffic automatically when the exit IP changes, the region is unsupported, provider checks are unavailable, or the IP looks like a VPN, proxy, Tor, datacenter, blacklist, or high-risk shared exit.
- Align browser/system signals with your exit region, including timezone, language, and WebRTC local IP exposure.
- Add Windows Firewall or macOS pf fallback blocking for clients that bypass system proxy settings.
- Generate a local diagnostic report for DNS, TCP, TLS, Claude Web, Ping0/Proxycheck, exit binding, usage rate, and environment issues.

## Highlights

- **One-click guard**: Enable or disable protection from the main window or tray.
- **Request-time gate**: Periodic background checks are disabled; matching Claude / Anthropic requests trigger validation at request time.
- **Claude target rules**: Built-in rules for `claude.ai`, `*.claude.ai`, and `*.anthropic.com`; rules can be added, allowed, edited, and saved in the UI.
- **Local proxy**: The default local proxy is `127.0.0.1:18089`.
- **Firewall fallback**: Windows uses `netsh advfirewall`; macOS uses an app-owned `pf` anchor for target IP blocking when needed.
- **Static residential IP check**: Require an exact fixed residential IPv4 match, or explicitly acknowledge the Claude account risk when skipping it.
- **IP intelligence**: Free provider lookups check IP, region, ASN, residential/hosting hints, proxy risk, blacklists, and shared-user signals; `PING0_API_KEY` unlocks paid Ping0 fields.
- **Environment consistency**: Check and optionally apply timezone, language, and browser WebRTC settings, with app-managed backup and restore.
- **Exit binding**: Store only an exit IP fingerprint and block when the exit changes.
- **Diagnostic report**: Copy a sanitized JSON report for support or issue filing.
- **Emergency restore**: Disable the guard and clean up app-managed proxy, firewall, hosts, and environment changes.
- **Minimal local logs**: Local event logs with masked IP display.

## How It Works

Request-time validation is the core behavior: Claude / Anthropic traffic is checked at the moment a matching request appears, then allowed or blocked.

```text
Claude / Anthropic request
        |
        v
Local guard proxy 127.0.0.1:18089
        |
        v
Target rule match? ---- no ----> allow as normal
        |
       yes
        |
        v
Request-time checks:
DNS / TCP / TLS / Claude Web / IP type / region / proxy risk /
static residential IP / exit binding / usage rate / environment consistency
        |
        v
PASS -> forward upstream
BLOCK -> reject request + optional firewall fallback
```

The guard is intentionally fail-closed while enabled. If provider checks are unavailable, Claude control targets fail, the region cannot be confirmed, risk data is missing, or system proxy ownership is lost, target traffic stays blocked.

## Screens and Controls

The app currently has five primary views:

- **Overview**: Verdict, target traffic status, exit IP, static residential IP, check matrix, fix guidance, and config summary.
- **Targets**: Claude / Anthropic domain rules with `GUARD` and `ALLOW` actions.
- **Settings**: Validation toggles, static residential IP, launch at login, environment consistency, exit binding, emergency restore, and active targets.
- **Diagnostic**: Sanitized report preview and copy action.
- **Activity**: Minimal local event log.

## Quick Start

Requirements:

- Node.js `>=22.12.0`
- pnpm `11.8.0`
- Windows or macOS

```bash
pnpm install
pnpm run make-icon
pnpm test
pnpm start
```

On first launch, the app shows a setup wizard. The recommended path is to configure a real static residential IPv4 address. If you explicitly choose to skip static IP matching, the rest of the Claude network detection and request blocking checks still apply.

## Build

macOS packaging, run on macOS:

```bash
pnpm run pack:mac    # unpacked app at dist/mac/
pnpm run dist:mac    # DMG + PKG installers
```

Windows packaging, run on Windows:

```powershell
pnpm run pack:win       # unpacked app at dist/win-unpacked/
pnpm run dist:win       # NSIS installer
pnpm run dist:win:msi   # MSI installer, requires WiX on the build machine
```

`pnpm run make-icon` creates the Windows icon asset used by installer builds. macOS and Windows builds are intentionally separate so each platform only produces its own artifacts under `dist/`.

## GitHub Releases

This repository includes a GitHub Actions workflow that builds Windows and macOS installers whenever a `v*` tag is pushed.

To publish the first public installer release:

```bash
git tag v0.0.2
git push origin v0.0.2
```

The workflow will:

- install dependencies with pnpm,
- run the test suite,
- build macOS `.dmg` and `.pkg` installers,
- build Windows `.exe` and `.msi` installers,
- create or update the GitHub Release for the tag,
- upload the installer files as release assets.

Current release artifacts are unsigned. macOS Gatekeeper and Windows SmartScreen may warn users until Apple notarization and Windows code signing are configured.

## Target Configuration

Guarded Claude targets are loaded from `target-rules.json` in the app data directory. Set `NETWORK_GUARD_TARGET_CONFIG` to point at another file. The Targets view can add, edit, delete, reload, reset, and save target rules without manually editing JSON.

For safety, custom rules, custom validation hosts, and web probe URLs are restricted to `claude.ai` and `anthropic.com` domains.

Default config:

```json
{
  "version": 1,
  "rules": [
    { "id": "anthropic-api", "domainPattern": "*.anthropic.com", "processNames": [], "action": "GUARD" },
    { "id": "claude-web", "domainPattern": "claude.ai", "processNames": [], "action": "GUARD" },
    { "id": "claude-subdomains", "domainPattern": "*.claude.ai", "processNames": [], "action": "GUARD" }
  ],
  "validation": {
    "services": { "claude": true },
    "checks": {
      "staticResidentialIp": true,
      "ipType": true,
      "region": true,
      "proxyRisk": true,
      "dns": true,
      "tcp": true,
      "tls": true,
      "controlHosts": true,
      "environment": true,
      "exitBinding": true,
      "usageRate": true
    },
    "webProbe": { "enabled": true, "url": "https://claude.ai/" },
    "useCustomHosts": false,
    "customHealthCheckHosts": [],
    "customControlHosts": []
  },
  "healthCheckHosts": ["claude.ai", "api.anthropic.com"],
  "controlHosts": ["claude.ai", "api.anthropic.com"],
  "firewallHosts": ["anthropic.com", "claude.ai"],
  "webProbeUrl": "https://claude.ai/",
  "staticResidentialIp": ""
}
```

`staticResidentialIp` behavior:

- Empty: enabling the guard requires explicit Claude account-risk acknowledgement.
- `0.0.0.0`: skip exact static IP matching after explicit acknowledgement.
- Real IPv4 address: guarded requests are blocked unless the current exit IP exactly matches this value.

## Validation Matrix

| Check | Purpose |
| --- | --- |
| Static residential IP | Require a known fixed exit IP or explicit skip |
| IP type | Detect residential vs hosting/datacenter networks |
| Region | Block unsupported or unconfirmed Claude regions |
| Proxy risk | Detect VPN, proxy, Tor, blacklists, high-risk IPs, and shared-user signals |
| DNS | Verify target host resolution |
| TCP | Verify HTTPS port reachability |
| TLS | Verify secure handshake |
| Control hosts | Require core Claude / Anthropic targets to pass |
| Claude Web probe | Probe `https://claude.ai/` or a configured Claude URL |
| Environment | Check timezone, language, and browser WebRTC exposure |
| Exit binding | Detect exit IP changes through a local hash |
| Usage rate | Block unusually high target request volume |

## Platform Notes

- Windows proxy settings are intentionally not applied by default because system-wide proxying can interfere with language/IME services. The app still runs the local proxy and uses firewall fallback when needed.
- Windows firewall fallback uses `netsh advfirewall` outbound block rules for resolved Claude / Anthropic IPs and may require administrator permissions.
- macOS proxy settings use `networksetup` and default to the `Wi-Fi` service. Set `NETWORK_GUARD_MAC_SERVICE` to another network service if needed.
- macOS firewall fallback uses `/etc/pf.anchors/com.local.claude-network-guard` and a marked `pf.conf` block, and may request administrator authorization. The app only manages its own marked block and anchor file.
- Environment consistency can modify system timezone/language and Chrome/Edge WebRTC preferences after creating an app-managed backup.
- Emergency restore attempts to remove the proxy, firewall, hosts, and environment changes managed by this app.

## Environment Variables

| Variable | Effect |
| --- | --- |
| `NETWORK_GUARD_DATA_DIR` | Use a custom app data directory |
| `NETWORK_GUARD_TARGET_CONFIG` | Use a custom `target-rules.json` path |
| `NETWORK_GUARD_MAC_SERVICE` | Choose the macOS network service for `networksetup` |
| `NETWORK_GUARD_SKIP_SYSTEM_PROXY=1` | Do not touch system proxy settings |
| `NETWORK_GUARD_USE_SYSTEM_PROXY=1` | Force system proxy use where supported |
| `NETWORK_GUARD_SKIP_FIREWALL=1` | Do not touch firewall settings |
| `NETWORK_GUARD_USE_HOSTS_BLOCK=1` | Enable app-managed hosts blocking fallback when supported |
| `NETWORK_GUARD_USE_PROXYCHECK=1` | Enable Proxycheck lookup even without `PROXYCHECK_API_KEY` |
| `PING0_API_KEY` | Enable Ping0 paid API lookup for IP risk, purity, and shared-user metadata |
| `PROXYCHECK_API_KEY` | Enable Proxycheck API lookup |

Without `PING0_API_KEY`, Ping0's free `/geo` endpoint only returns basic IP, location, ASN, and organization data. The public detail page may require CAPTCHA, so risk and shared-user fields are not always available.

## Safety and Privacy

- Claude Network Guard does not buy, switch, or manage proxy/VPN accounts.
- It does not guarantee Claude account safety. Account history, payment region, server-side risk decisions, and Anthropic-side policy enforcement cannot be fully verified locally.
- The app stores only masked IP display data and local IP hashes for binding; diagnostic reports sanitize provider results.
- Firewall fallback resolves current target IPs. If Claude / Anthropic rotates to new IPs before the next request-time validation, run `立即检测` or reload target rules.
- Free IP intelligence sources can misclassify residential/static status. The provider layer is intentionally pluggable for paid or stronger sources later.

## Troubleshooting

**Claude requests are blocked after enabling guard**

Open the Diagnostic view and check `reasons`. Common blockers are `STATIC_RESIDENTIAL_IP_REQUIRED`, `STATIC_RESIDENTIAL_IP_MISMATCH`, `BLOCKED_REGION`, `DATACENTER_IP`, `VPN_OR_PROXY_RISK`, `IP_RISK_DATA_UNAVAILABLE`, `CLAUDE_WEB_CHECK_FAILED`, `ENVIRONMENT_MISMATCH`, and `SYSTEM_PROXY_NOT_APPLIED`.

**A CLI client bypasses the local proxy**

Use the firewall fallback path. On Windows this depends on `netsh advfirewall`; on macOS it depends on the app-owned `pf` anchor. If privileged changes fail, use Emergency Restore and retry as an administrator.

**Ping0 risk data is missing**

Set `PING0_API_KEY`, or open the Ping0 verification action in the app when available. Without paid/API data, the app may block because risk, purity, or shared-user fields cannot be confirmed.

**Environment consistency fails**

Close running browsers, create a fresh backup, then retry environment alignment. Use Restore Environment or Emergency Restore to roll back app-managed changes.

## Development

```bash
pnpm test
pnpm start
```

The test suite uses Node's built-in test runner and covers proxy gating, target rules, provider scoring, network checks, firewall managers, environment consistency, diagnostic reports, and renderer wiring.

## GitHub Discovery Keywords

This project is intentionally described with the phrases people are likely to search for:

- Claude network guard
- Claude network detector
- Claude request blocker
- Claude traffic firewall
- Claude Code proxy guard
- Anthropic API network check
- Anthropic API request blocking
- static residential IP checker
- Claude WebRTC leak check
- Claude environment consistency
- Claude 防封控网络检测
- Claude 网络拦截
- Claude 请求拦截
- Claude 静态住宅 IP 检测
- Claude Code 网络守卫

Recommended GitHub topics for the repository: `claude`, `anthropic`, `claude-code`, `network-guard`, `network-diagnostics`, `request-blocking`, `local-proxy`, `firewall`, `static-residential-ip`, `webrtc`, `electron`.

## Current Limitations

- No official release artifacts are described here yet; build locally with Electron Builder.
- Only Claude / Anthropic domains are accepted by the target config manager.
- Firewall fallback is IP-resolution based and may need a fresh validation when target services rotate addresses.
- Linux is not currently listed as a supported desktop target.
- The included icon is intentionally simple and should be replaced before public distribution.

## License

MIT
