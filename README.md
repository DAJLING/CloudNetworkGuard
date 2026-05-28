# Claude Codex Network Guard

Windows/macOS desktop guard for Claude, Codex, ChatGPT, OpenAI API, and Anthropic API traffic.

The app provides a one-click guard switch. When enabled, target traffic is routed through a local proxy and is blocked unless the current network passes these checks:

- External access to Claude/OpenAI/Anthropic targets
- DNS, TCP:443, and TLS checks for Claude/OpenAI/Anthropic targets
- Claude web reachability probe for `https://claude.ai/`
- Free-source IP classification and proxy/VPN/datacenter risk checks
- Mainland China, Hong Kong, Macau, and unknown-region blocking
- Local 24-hour static IP observation window
- Browser/system environment consistency checks for blocked time zones, languages, and WebRTC local IP exposure
- Exit IP binding and mismatch alerts
- Target request rate monitoring
- Firewall fallback blocking for direct clients that do not honor system proxy settings
- Minimal local logging with masked IP data only

## Commands

```powershell
npm.cmd install
npm.cmd run make-icon
npm.cmd test
npm.cmd start
npm.cmd run pack
npm.cmd run dist
npm.cmd run dist:msi
```

`npm.cmd run make-icon` creates the local Windows icon asset used by installer builds. `npm.cmd run pack` creates an unpacked app at `dist/win-unpacked` on Windows. `npm.cmd run dist` creates the default NSIS installer. `npm.cmd run dist:msi` builds an MSI when Windows Installer/WiX validation is available on the build machine.

## Guard Behavior

- Guard disabled: target traffic is allowed and no block notification is shown.
- Guard enabled: the app temporarily blocks target traffic while checking, then releases firewall/hosts blocks only if validation passes.
- Direct clients: when the verdict blocks traffic, Windows firewall rules are added for resolved target IPs so CLI tools that bypass the system proxy are also blocked.
- First run or IP change: the app enters `OBSERVING` until the same masked IP has remained stable for 24 hours.
- Exit IP binding: the first detected exit IP is locally bound by hash; later changes are blocked until state is reset.
- Claude control check: DNS, TCP, TLS, and Claude web probe failures block guarded traffic.
- Usage rate check: unusually high target request volume blocks guarded traffic.
- Provider outage or offline checks: fail-closed while the guard is enabled.

## Platform Notes

- Windows proxy settings are applied through the current user's Internet Settings registry keys.
- Windows firewall fallback uses `netsh advfirewall` outbound block rules for resolved Claude/OpenAI/ChatGPT IPs. It may require elevated permissions.
- macOS proxy settings use `networksetup` and default to the `Wi-Fi` service. Set `NETWORK_GUARD_MAC_SERVICE` to target another network service.
- Set `NETWORK_GUARD_SKIP_SYSTEM_PROXY=1` for tests or dry runs that should not touch system proxy settings.
- Set `NETWORK_GUARD_SKIP_FIREWALL=1` for tests or dry runs that should not touch firewall settings.

## Current Limitations

- The app does not buy, switch, or manage proxy/VPN accounts.
- Free IP intelligence sources can misclassify residential/static status. The provider layer is intentionally pluggable for paid sources later.
- Account history, payment region, and server-side Claude risk decisions cannot be fully verified locally.
- Firewall fallback resolves current target IPs. If a service rotates to a new IP before the next check, run "立即检测" or keep periodic checks enabled in a later version.
- The included icon is intentionally simple and should be replaced before public distribution.
